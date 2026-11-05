//! EIP-4844 blob transactions: signing, the sidecar network form for
//! `eth_sendRawTransaction`, and blob gas pricing (Prague parameters).
//!
//! Network form (pre-Osaka): `0x03 || rlp([tx_payload_body, blobs, commitments, proofs])`
//! where `tx_payload_body` is the signed transaction list; the block form is just
//! `0x03 || rlp(tx_payload_body)` (the consensus `Envelope` encoding).

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const signature = consensus.signature;
const rlp = @import("../../common/rlp/root.zig");
const kzg = @import("../blobs/kzg.zig");
const root = @import("root.zig");

pub const blob_gas_per_blob: u64 = 1 << 17;
/// Prague `BLOB_BASE_FEE_UPDATE_FRACTION` (EIP-7691).
pub const blob_base_fee_update_fraction: u64 = 5_007_716;
pub const blob_base_fee_min: u128 = 1;
/// geth requires blob transaction replacements to double every fee.
pub const blob_bump_percent: u8 = 100;
pub const blobs_per_tx_max = 6;
const blob_length = @typeInfo(kzg.Blob).array.len;
const point_length = @typeInfo(kzg.Commitment).array.len;

comptime {
    assert(point_length == @typeInfo(kzg.Proof).array.len);
}

pub const Request = struct {
    chain_id: u64,
    nonce: u64,
    fees: root.Fees,
    blob_fee_wei: u128,
    to: root.Address,
    versioned_hashes: []const [32]u8,
};

/// Signs a blob transaction; `hash_buffer` (33 bytes per blob) backs the hash list.
pub fn sign(
    request: Request,
    hash_buffer: []u8,
    private_key: [32]u8,
) signature.SignError!consensus.Envelope {
    assert(request.versioned_hashes.len > 0);
    assert(request.versioned_hashes.len <= blobs_per_tx_max);
    assert(hash_buffer.len >= 33 * request.versioned_hashes.len);
    for (request.versioned_hashes, 0..) |hash, index| {
        assert(hash[0] == kzg.versioned_hash_version);
        hash_buffer[index * 33] = 0xa0;
        hash_buffer[index * 33 + 1 ..][0..32].* = hash;
    }
    var envelope: consensus.Envelope = .{ .eip4844 = .{ .tx = .{
        .chain_id = request.chain_id,
        .nonce = request.nonce,
        .max_priority_fee_per_gas = request.fees.max_priority_fee_per_gas,
        .max_fee_per_gas = request.fees.max_fee_per_gas,
        .gas_limit = 21_000,
        .to = request.to,
        .value = 0,
        .input = &.{},
        .access_list = .empty,
        .max_fee_per_blob_gas = request.blob_fee_wei,
        .blob_versioned_hashes = .{
            .payload = hash_buffer[0 .. 33 * request.versioned_hashes.len],
        },
    }, .signature = .{ .y_parity = false, .r = 1, .s = 1 } } };
    envelope.eip4844.signature = try signature.sign(private_key, envelope.signing_hash().?);
    assert(envelope.eip4844.signature.is_low_s());
    return envelope;
}

pub const Sidecar = struct {
    blobs: []const *const kzg.Blob,
    commitments: []const kzg.Commitment,
    proofs: []const kzg.Proof,

    fn payload_length(sidecar: Sidecar) usize {
        assert(sidecar.blobs.len == sidecar.commitments.len);
        assert(sidecar.blobs.len == sidecar.proofs.len);
        const count = sidecar.blobs.len;
        const blob_item = rlp.header_length(blob_length) + blob_length;
        const point_item = 1 + point_length;
        return rlp.list_length(count * blob_item) + 2 * rlp.list_length(count * point_item);
    }
};

/// Length of the network form of `envelope` with `sidecar`.
pub fn network_length(envelope: consensus.Envelope, sidecar: Sidecar) usize {
    const body_length = envelope.encoded_length() - 1;
    return 1 + rlp.list_length(body_length + sidecar.payload_length());
}

/// Writes the network form into `out` and returns it.
pub fn encode_network(envelope: consensus.Envelope, sidecar: Sidecar, out: []u8) []u8 {
    assert(envelope == .eip4844);
    assert(sidecar.blobs.len == envelope.eip4844.tx.blob_versioned_hashes.count());
    const total = network_length(envelope, sidecar);
    assert(out.len >= total);
    const body_length = envelope.encoded_length() - 1;
    const payload = body_length + sidecar.payload_length();
    const prefix_length = 1 + rlp.header_length(payload);
    // Encode `0x03 || body` so the body lands right after the prefix, then write the
    // prefix (type byte + list header) over the leading bytes.
    const typed = envelope.encode_to(out[prefix_length - 1 ..][0 .. body_length + 1]);
    assert(typed.len == body_length + 1);
    var encoder = rlp.Encoder.init(out[0..prefix_length]);
    encoder.raw(&.{@backingInt(consensus.TxType.eip4844)});
    encoder.list_header(payload);
    assert(encoder.remaining() == 0);
    var tail = rlp.Encoder.init(out[prefix_length + body_length .. total]);
    tail.list_header(sidecar.blobs.len * (rlp.header_length(blob_length) + blob_length));
    for (sidecar.blobs) |blob| tail.bytes(blob);
    tail.list_header(sidecar.commitments.len * (1 + point_length));
    for (sidecar.commitments) |*commitment| tail.bytes(commitment);
    tail.list_header(sidecar.proofs.len * (1 + point_length));
    for (sidecar.proofs) |*proof| tail.bytes(proof);
    assert(tail.remaining() == 0);
    return out[0..total];
}

/// `fake_exponential(MIN_BASE_FEE_PER_BLOB_GAS, excess, BLOB_BASE_FEE_UPDATE_FRACTION)`.
pub fn blob_base_fee(excess_blob_gas: u64) u128 {
    const factor: u256 = blob_base_fee_min;
    const denominator: u256 = blob_base_fee_update_fraction;
    var output: u256 = 0;
    var accumulator: u256 = factor * denominator;
    var index: u256 = 1;
    // Terms shrink geometrically once index exceeds excess / fraction; the bound keeps
    // the loop finite for any u64 excess (the series is exact in far fewer steps).
    while (accumulator > 0 and index < 4096) : (index += 1) {
        output += accumulator;
        accumulator = accumulator * excess_blob_gas / (denominator * index);
    }
    return std.math.cast(u128, output / denominator) orelse std.math.maxInt(u128);
}

const testing = std.testing;
const accounts = @import("../devnet/accounts.zig");

test "blob tx: base fee matches the EIP-4844 reference points" {
    try testing.expectEqual(@as(u128, 1), blob_base_fee(0));
    try testing.expectEqual(@as(u128, 1), blob_base_fee(blob_base_fee_update_fraction / 2));
    // e^1 ~ 2.718 rounds down to 2; e^2 ~ 7.389 to 7.
    try testing.expectEqual(@as(u128, 2), blob_base_fee(blob_base_fee_update_fraction));
    try testing.expectEqual(@as(u128, 7), blob_base_fee(2 * blob_base_fee_update_fraction));
    var previous: u128 = 0;
    var prng = @import("../../testing/prng.zig").Prng.init(0xb10b);
    for (0..64) |_| {
        const fee = blob_base_fee(prng.below(200_000_000));
        try testing.expect(fee >= 1);
        previous = fee;
    }
    try testing.expect(previous >= 1);
}

test "blob tx: network form wraps the signed body and the sidecar" {
    const key = accounts.derive_dev(@backingInt(accounts.Role.batcher)).private_key;
    const blob = try testing.allocator.create(kzg.Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 0);
    blob[100] = 7;
    const commitment: kzg.Commitment = @splat(0xc1);
    const proof: kzg.Proof = @splat(0xc2);
    const hashes = [_][32]u8{kzg.versioned_hash(&commitment)};
    var hash_buffer: [33]u8 = undefined;
    const envelope = try sign(.{
        .chain_id = 900,
        .nonce = 2,
        .fees = root.suggest_fees(10, 1),
        .blob_fee_wei = 5,
        .to = .{ .bytes = @splat(0xff) },
        .versioned_hashes = &hashes,
    }, &hash_buffer, key);
    const blobs = [_]*const kzg.Blob{blob};
    const sidecar: Sidecar = .{
        .blobs = &blobs,
        .commitments = &.{commitment},
        .proofs = &.{proof},
    };
    const out = try testing.allocator.alloc(u8, network_length(envelope, sidecar));
    defer testing.allocator.free(out);
    const network = encode_network(envelope, sidecar, out);
    try testing.expectEqual(@as(u8, 0x03), network[0]);

    var decoder = rlp.Decoder.init(network[1..]);
    var outer = try decoder.list();
    const body = try outer.raw();
    var typed: [512]u8 = undefined;
    typed[0] = 0x03;
    @memcpy(typed[1..][0..body.len], body);
    const decoded = try consensus.Envelope.decode(typed[0 .. body.len + 1]);
    try testing.expect(decoded.hash().eql(envelope.hash()));
    const sender = decoded.recover_sender(signature.recover_address).?;
    try testing.expect(sender.eql(accounts.address_of(key)));
    var blob_list = try outer.list();
    try testing.expectEqualSlices(u8, blob, try blob_list.bytes());
    var commitment_list = try outer.list();
    try testing.expectEqualSlices(u8, &commitment, try commitment_list.bytes());
    var proof_list = try outer.list();
    try testing.expectEqualSlices(u8, &proof, try proof_list.bytes());
    try testing.expect(outer.is_empty());
}

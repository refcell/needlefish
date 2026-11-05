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
/// EIP-7594 (Osaka) cell proofs per blob in a version-1 sidecar.
pub const cell_proofs_per_blob = 128;
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

/// Version 0 (EIP-4844): one blob proof per blob. Version 1 (EIP-7594, Osaka): the
/// network form gains a `wrapper_version` item and carries 128 cell proofs per blob.
pub const Sidecar = struct {
    version: u1 = 0,
    blobs: []const *const kzg.Blob,
    commitments: []const kzg.Commitment,
    proofs: []const kzg.Proof,

    fn proofs_per_blob(sidecar: Sidecar) usize {
        return if (sidecar.version == 1) cell_proofs_per_blob else 1;
    }

    fn payload_length(sidecar: Sidecar) usize {
        assert(sidecar.blobs.len == sidecar.commitments.len);
        assert(sidecar.blobs.len * sidecar.proofs_per_blob() == sidecar.proofs.len);
        const count = sidecar.blobs.len;
        const blob_item = rlp.header_length(blob_length) + blob_length;
        const point_item = 1 + point_length;
        const version_item: usize = sidecar.version; // The byte 0x01, or nothing.
        return version_item + rlp.list_length(count * blob_item) +
            rlp.list_length(count * point_item) + rlp.list_length(sidecar.proofs.len * point_item);
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
    if (sidecar.version == 1) tail.int(@as(u8, 1));
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

test "blob tx: version 1 sidecar carries the wrapper version and 128 cell proofs" {
    const key = accounts.derive_dev(@backingInt(accounts.Role.batcher)).private_key;
    const blob = try testing.allocator.create(kzg.Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 3);
    const commitment: kzg.Commitment = @splat(0xc1);
    var proofs: [cell_proofs_per_blob]kzg.Proof = undefined;
    for (&proofs, 0..) |*proof, index| proof.* = @splat(@intCast(index));
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
        .version = 1,
        .blobs = &blobs,
        .commitments = &.{commitment},
        .proofs = &proofs,
    };
    const out = try testing.allocator.alloc(u8, network_length(envelope, sidecar));
    defer testing.allocator.free(out);
    const network = encode_network(envelope, sidecar, out);
    var decoder = rlp.Decoder.init(network[1..]);
    var outer = try decoder.list();
    _ = try outer.raw();
    try testing.expectEqual(@as(u8, 1), try outer.int(u8));
    var blob_list = try outer.list();
    try testing.expectEqualSlices(u8, blob, try blob_list.bytes());
    try testing.expect(blob_list.is_empty());
    var commitment_list = try outer.list();
    try testing.expectEqualSlices(u8, &commitment, try commitment_list.bytes());
    var proof_list = try outer.list();
    for (&proofs) |*proof| try testing.expectEqualSlices(u8, proof, try proof_list.bytes());
    try testing.expect(proof_list.is_empty());
    try testing.expect(outer.is_empty());
}

test "blob tx: seeded fuzz of sidecar lengths across versions and blob counts" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x7594);
    for (0..32) |_| try check_sidecar_length(&prng);
}

test "blob tx: fuzz sidecar lengths" {
    try testing.fuzz({}, fuzz_sidecar_length, .{});
}

fn fuzz_sidecar_length(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [8]u8 = @splat(0);
    _ = smith.slice(&bytes);
    var prng = @import("../../testing/prng.zig").Prng.init(std.mem.readInt(u64, &bytes, .little));
    try check_sidecar_length(&prng);
}

/// The encoded network form is exactly `network_length` and decodes back into the same
/// number of blobs, commitments and proofs.
fn check_sidecar_length(prng: anytype) !void {
    const key = accounts.derive_dev(@backingInt(accounts.Role.batcher)).private_key;
    const count = prng.range(1, 3);
    const version: u1 = @intCast(prng.below(2));
    const per_blob: usize = if (version == 1) cell_proofs_per_blob else 1;
    const blob = try testing.allocator.create(kzg.Blob);
    defer testing.allocator.destroy(blob);
    prng.fill(blob[0..64]);
    var commitments: [3]kzg.Commitment = undefined;
    var hashes: [3][32]u8 = undefined;
    for (0..count) |index| {
        commitments[index] = @splat(prng.int(u8));
        hashes[index] = kzg.versioned_hash(&commitments[index]);
    }
    var proofs: [3 * cell_proofs_per_blob]kzg.Proof = @splat(@splat(0xab));
    var hash_buffer: [33 * 3]u8 = undefined;
    const envelope = try sign(.{
        .chain_id = 900,
        .nonce = prng.below(1000),
        .fees = root.suggest_fees(10, 1),
        .blob_fee_wei = 5,
        .to = .{ .bytes = @splat(0xff) },
        .versioned_hashes = hashes[0..count],
    }, &hash_buffer, key);
    const blobs = [_]*const kzg.Blob{ blob, blob, blob };
    const sidecar: Sidecar = .{
        .version = version,
        .blobs = blobs[0..count],
        .commitments = commitments[0..count],
        .proofs = proofs[0 .. count * per_blob],
    };
    const out = try testing.allocator.alloc(u8, network_length(envelope, sidecar));
    defer testing.allocator.free(out);
    const network = encode_network(envelope, sidecar, out);
    try testing.expectEqual(out.len, network.len);
    var decoder = rlp.Decoder.init(network[1..]);
    var outer = try decoder.list();
    _ = try outer.raw();
    if (version == 1) try testing.expectEqual(@as(u8, 1), try outer.int(u8));
    const expected = [_]usize{ count, count, count * per_blob };
    for (expected) |items| {
        var list = try outer.list();
        for (0..items) |_| _ = try list.bytes();
        try testing.expect(list.is_empty());
    }
    try testing.expect(outer.is_empty());
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

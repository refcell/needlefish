//! Transaction tests: public vectors, seeded fuzz over every type, coverage fuzz.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const tx_module = @import("tx.zig");
const signature_module = @import("signature.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = tx_module.Envelope;
const hex = primitives.hex;

const recover = signature_module.recover_address;

const eip155_example_hex =
    "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764" ++
    "00008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cb" ++
    "e9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

/// basescan.org/tx/0xc468b38a20375922828c8126912740105125143b9856936085474b2590bbca91
const base_deposit_hex =
    "7ef8f8a0417d134467f4737fcdf2475f0ecdd2a0ed6d87ecffc888ba9f60ee7e3b8ac26a94deadde" ++
    "addeaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080" ++
    "830f424080b8a4440a5e20000008dd00101c1200000000000000040000000066c352bb0000000001" ++
    "39c4f500000000000000000000000000000000000000000000000000000000c0cff1460000000000" ++
    "000000000000000000000000000000000000000000000000000001d4c88f4065ac9671e8b1329b90" ++
    "773e89b5ddff9cf8675b2b5e9c1b28320609930000000000000000000000005050f69a9786f08150" ++
    "9234f1a7f4684b5e5b76c9";

fn expect_canonical(envelope: Envelope, encoded: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    try testing.expectEqual(encoded.len, envelope.encoded_length());
    try testing.expectEqualSlices(u8, encoded, envelope.encode_to(&buffer));
    try testing.expect(envelope.hash().eql(primitives.keccak256(encoded)));
}

test "tx: EIP-155 example vector" {
    var buffer: [256]u8 = undefined;
    const encoded = try hex.decode_into(&buffer, eip155_example_hex);
    const envelope = try Envelope.decode(encoded);
    try testing.expectEqual(tx_module.TxType.legacy, envelope.tx_type());
    try testing.expectEqual(@as(?u64, 1), envelope.chain_id());
    try testing.expectEqual(@as(?u64, 9), envelope.nonce());
    try testing.expectEqual(@as(u256, 1_000_000_000_000_000_000), envelope.value());
    const signing_hash = B256.comptime_hex(
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53",
    );
    try testing.expect(envelope.signing_hash().?.eql(signing_hash));
    const sender = Address.comptime_hex("9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F");
    try testing.expect(envelope.recover_sender(recover).?.eql(sender));
    try expect_canonical(envelope, encoded);

    // Re-signing with the public EIP-155 example key reproduces the signature.
    const key: [32]u8 = @splat(0x46);
    const resigned = try tx_module.sign(envelope.legacy.tx, key);
    try expect_canonical(resigned, encoded);
}

test "tx: Base mainnet deposit vector" {
    var buffer: [512]u8 = undefined;
    const encoded = try hex.decode_into(&buffer, base_deposit_hex);
    const envelope = try Envelope.decode(encoded);
    try testing.expect(envelope.is_deposit());
    try testing.expectEqual(@as(u128, 0), envelope.deposit.mint);
    try testing.expectEqual(@as(u64, 1_000_000), envelope.gas_limit());
    const expected_hash = B256.comptime_hex(
        "c468b38a20375922828c8126912740105125143b9856936085474b2590bbca91",
    );
    try testing.expect(envelope.hash().eql(expected_hash));
    const from = Address.comptime_hex("deaddeaddeaddeaddeaddeaddeaddeaddead0001");
    try testing.expect(envelope.recover_sender(recover).?.eql(from));
    try testing.expect(envelope.signing_hash() == null);
    try expect_canonical(envelope, encoded);
    // A bare deposit body without the type byte is not a valid envelope.
    if (Envelope.decode(encoded[1..])) |_| return error.TestUnexpectedResult else |_| {}
}

fn random_bytes(prng: *Prng, buffer: []u8) []u8 {
    const len = prng.below(buffer.len + 1);
    prng.fill(buffer[0..len]);
    return buffer[0..len];
}

fn random_address(prng: *Prng) Address {
    var address: Address = undefined;
    prng.fill(&address.bytes);
    return address;
}

fn random_kind(prng: *Prng) tx_module.TxKind {
    if (prng.chance(1, 4)) return .create;
    return .{ .call = random_address(prng) };
}

fn random_u256(prng: *Prng) u256 {
    return prng.int(u256) >> @intCast(prng.below(256));
}

const Scratch = struct {
    input: [300]u8 = undefined,
    access_list: [600]u8 = undefined,
    keys: [4]B256 = undefined,
    hashes: [200]u8 = undefined,
    authorizations: [400]u8 = undefined,
};

fn random_access_list(prng: *Prng, scratch: *Scratch) tx_module.AccessList {
    for (&scratch.keys) |*key| prng.fill(&key.bytes);
    var items: [3]tx_module.AccessList.BuildItem = undefined;
    const count = prng.below(items.len + 1);
    for (items[0..count]) |*item| {
        item.* = .{
            .address = random_address(prng),
            .storage_keys = scratch.keys[0..prng.below(scratch.keys.len + 1)],
        };
    }
    return tx_module.AccessList.build(&scratch.access_list, items[0..count]);
}

fn random_authorizations(prng: *Prng, scratch: *Scratch) tx_module.AuthorizationList {
    var items: [3]@import("tx_fields.zig").Authorization = undefined;
    const count = prng.below(items.len + 1);
    for (items[0..count]) |*item| {
        item.* = .{
            .chain_id = random_u256(prng),
            .address = random_address(prng),
            .nonce = prng.int(u64),
            .y_parity = @intCast(prng.below(2)),
            .r = random_u256(prng),
            .s = random_u256(prng),
        };
    }
    return tx_module.AuthorizationList.build(&scratch.authorizations, items[0..count]);
}

const Common = struct {
    input: []const u8,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    fee: u128,
    tip: u128,
};

fn random_common(prng: *Prng, scratch: *Scratch) Common {
    return .{
        .input = random_bytes(prng, &scratch.input),
        .chain_id = prng.int(u64) >> @intCast(prng.below(64)),
        .nonce = prng.int(u64) >> @intCast(prng.below(64)),
        .gas_limit = prng.int(u64) >> @intCast(prng.below(64)),
        .fee = prng.int(u128) >> @intCast(prng.below(128)),
        .tip = prng.int(u128) >> @intCast(prng.below(128)),
    };
}

fn random_legacy_like(prng: *Prng, scratch: *Scratch, c: Common, key: [32]u8) !Envelope {
    if (prng.chance(1, 2)) return tx_module.sign(tx_module.Legacy{
        .chain_id = if (prng.chance(1, 4)) null else c.chain_id,
        .nonce = c.nonce,
        .gas_price = c.fee,
        .gas_limit = c.gas_limit,
        .to = random_kind(prng),
        .value = random_u256(prng),
        .input = c.input,
    }, key);
    return tx_module.sign(tx_module.Eip2930{
        .chain_id = c.chain_id,
        .nonce = c.nonce,
        .gas_price = c.fee,
        .gas_limit = c.gas_limit,
        .to = random_kind(prng),
        .value = random_u256(prng),
        .input = c.input,
        .access_list = random_access_list(prng, scratch),
    }, key);
}

fn random_eip1559(prng: *Prng, scratch: *Scratch, c: Common, key: [32]u8) !Envelope {
    return tx_module.sign(tx_module.Eip1559{
        .chain_id = c.chain_id,
        .nonce = c.nonce,
        .max_priority_fee_per_gas = c.tip,
        .max_fee_per_gas = c.fee,
        .gas_limit = c.gas_limit,
        .to = random_kind(prng),
        .value = random_u256(prng),
        .input = c.input,
        .access_list = random_access_list(prng, scratch),
    }, key);
}

fn random_eip4844(prng: *Prng, scratch: *Scratch, c: Common, key: [32]u8) !Envelope {
    var hashes: [6]B256 = undefined;
    for (&hashes) |*h| prng.fill(&h.bytes);
    const count = prng.below(hashes.len + 1);
    return tx_module.sign(tx_module.Eip4844{
        .chain_id = c.chain_id,
        .nonce = c.nonce,
        .max_priority_fee_per_gas = c.tip,
        .max_fee_per_gas = c.fee,
        .gas_limit = c.gas_limit,
        .to = random_address(prng),
        .value = random_u256(prng),
        .input = c.input,
        .access_list = random_access_list(prng, scratch),
        .max_fee_per_blob_gas = c.fee,
        .blob_versioned_hashes = tx_module.HashList.build(&scratch.hashes, hashes[0..count]),
    }, key);
}

fn random_eip7702(prng: *Prng, scratch: *Scratch, c: Common, key: [32]u8) !Envelope {
    return tx_module.sign(tx_module.Eip7702{
        .chain_id = c.chain_id,
        .nonce = c.nonce,
        .max_priority_fee_per_gas = c.tip,
        .max_fee_per_gas = c.fee,
        .gas_limit = c.gas_limit,
        .to = random_address(prng),
        .value = random_u256(prng),
        .input = c.input,
        .access_list = random_access_list(prng, scratch),
        .authorization_list = random_authorizations(prng, scratch),
    }, key);
}

fn random_deposit(prng: *Prng, c: Common) Envelope {
    var source_hash: B256 = undefined;
    prng.fill(&source_hash.bytes);
    return .{ .deposit = .{
        .source_hash = source_hash,
        .from = random_address(prng),
        .to = random_kind(prng),
        .mint = c.fee,
        .value = random_u256(prng),
        .gas_limit = c.gas_limit,
        .is_system_transaction = prng.chance(1, 2),
        .input = c.input,
    } };
}

fn random_envelope(prng: *Prng, scratch: *Scratch, key: [32]u8) !Envelope {
    const c = random_common(prng, scratch);
    return switch (prng.below(5)) {
        0 => random_legacy_like(prng, scratch, c, key),
        1 => random_eip1559(prng, scratch, c, key),
        2 => random_eip4844(prng, scratch, c, key),
        3 => random_eip7702(prng, scratch, c, key),
        else => random_deposit(prng, c),
    };
}

test "tx: seeded fuzz sign, encode, decode, recover for every type" {
    var prng = Prng.init(0x7e7e);
    const key = try hex.decode_array(
        32,
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    const sender = signature_module.address_from_private(key).?;
    var scratch: Scratch = .{};
    var buffer: [4096]u8 = undefined;
    var network: [4096]u8 = undefined;
    for (0..120) |_| {
        const envelope = try random_envelope(&prng, &scratch, key);
        const encoded = envelope.encode_to(&buffer);
        const decoded = try Envelope.decode(encoded);
        try testing.expectEqual(envelope.tx_type(), decoded.tx_type());
        try expect_canonical(decoded, encoded);
        try testing.expect(decoded.hash().eql(envelope.hash()));
        if (!decoded.is_deposit()) {
            try testing.expect(decoded.recover_sender(recover).?.eql(sender));
        }
        // Block-body (network) form round trip.
        var encoder = rlp.Encoder.init(&network);
        decoded.encode_network(&encoder);
        try testing.expectEqual(decoded.network_length(), encoder.position);
        var decoder = rlp.Decoder.init(encoder.written());
        const again = try Envelope.decode_network(&decoder);
        try decoder.finish();
        try testing.expect(again.hash().eql(envelope.hash()));
    }
}

test "tx: effective gas price" {
    const envelope: Envelope = .{ .eip1559 = .{
        .tx = .{
            .chain_id = 1,
            .nonce = 0,
            .max_priority_fee_per_gas = 2,
            .max_fee_per_gas = 10,
            .gas_limit = 21000,
            .to = .create,
            .value = 0,
            .input = &.{},
            .access_list = .empty,
        },
        .signature = .{ .y_parity = false, .r = 1, .s = 1 },
    } };
    try testing.expectEqual(@as(?u128, 7), envelope.effective_gas_price(5));
    try testing.expectEqual(@as(?u128, 10), envelope.effective_gas_price(9));
    try testing.expectEqual(@as(?u128, null), envelope.effective_gas_price(11));
}

test "tx: decode rejects malformed envelopes" {
    try testing.expectError(error.UnexpectedEnd, Envelope.decode(&.{}));
    try testing.expectError(error.UnknownTxType, Envelope.decode(&.{ 0x05, 0xc0 }));
    try testing.expectError(error.InvalidEnvelope, Envelope.decode(&.{ 0x00, 0xc0 }));
    try testing.expectError(error.UnexpectedEnd, Envelope.decode(&.{ 0x02, 0xc0 }));
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [2048]u8 = undefined;
    const len = smith.slice(&input);
    const envelope = Envelope.decode(input[0..len]) catch return;
    // Strict decoding means a decoded transaction re-encodes byte for byte.
    try expect_canonical(envelope, input[0..len]);
}

test "tx: fuzz decode is canonical" {
    try testing.fuzz({}, fuzz_decode, .{});
}

test "tx: seeded fuzz corrupted encodings" {
    var prng = Prng.init(0xbad7);
    const key: [32]u8 = @splat(0x11);
    var scratch: Scratch = .{};
    var buffer: [4096]u8 = undefined;
    for (0..200) |_| {
        const envelope = try random_envelope(&prng, &scratch, key);
        const encoded = envelope.encode_to(&buffer);
        encoded[prng.below(encoded.len)] = prng.int(u8);
        const decoded = Envelope.decode(encoded) catch continue;
        try expect_canonical(decoded, encoded);
    }
}

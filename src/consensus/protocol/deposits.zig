//! Deposit transactions (EIP-2718 type 0x7E), their source hashes, and user deposits
//! decoded from `TransactionDeposited` logs of the L1 deposit contract (OptimismPortal).
//!
//! A deposit tx encodes as `0x7E ++ rlp([source_hash, from, to, mint, value, gas_limit,
//! is_system_transaction, data])` with an empty `to` string for contract creation.
//! Mirrors base/base `crates/consensus/protocol/src/deposits.rs` and
//! `crates/common/consensus/src/{source.rs,transaction/deposit.rs}`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Log = @import("log.zig").Log;
const Receipt = @import("log.zig").Receipt;

pub const deposit_tx_type: u8 = 0x7e;

/// keccak256("TransactionDeposited(address,address,uint256,bytes)").
pub const transaction_deposited_topic = B256.comptime_hex(
    "b3813568d9991fc951961fcb4c784893574240a28925604d09fc577c55bb7c32",
);

/// Gas allotted to system deposits (L1 info, upgrades) from Regolith on.
pub const regolith_system_tx_gas: u64 = 1_000_000;
pub const depositor_account = Address.comptime_hex(
    "0xDeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001",
);
pub const l1_block_info_address = Address.comptime_hex(
    "0x4200000000000000000000000000000000000015",
);

pub const SourceDomain = enum(u64) {
    user = 0,
    l1_info = 1,
    upgrade = 2,
    base_time = 3,
};

/// `keccak256(domain_word ++ deposit_id_hash)`.
fn domain_hash(domain: SourceDomain, deposit_id_hash: B256) B256 {
    var input: [64]u8 = @splat(0);
    std.mem.writeInt(u64, input[24..32], @backingInt(domain), .big);
    input[32..64].* = deposit_id_hash.bytes;
    return primitives.keccak256(&input);
}

/// Source hash of a user deposit: L1 block hash and log index within the block.
pub fn user_source_hash(l1_block_hash: B256, log_index: u64) B256 {
    var input: [64]u8 = @splat(0);
    input[0..32].* = l1_block_hash.bytes;
    std.mem.writeInt(u64, input[56..64], log_index, .big);
    return domain_hash(.user, primitives.keccak256(&input));
}

/// Source hash of an L1 info deposit: L1 block hash and L2 sequence number.
pub fn l1_info_source_hash(l1_block_hash: B256, sequence_number: u64) B256 {
    var input: [64]u8 = @splat(0);
    input[0..32].* = l1_block_hash.bytes;
    std.mem.writeInt(u64, input[56..64], sequence_number, .big);
    return domain_hash(.l1_info, primitives.keccak256(&input));
}

/// Source hash of a network upgrade transaction identified by its intent string.
pub fn upgrade_source_hash(intent: []const u8) B256 {
    return domain_hash(.upgrade, primitives.keccak256(intent));
}

/// Source hash of a Base time deposit for an L2 block number.
pub fn base_time_source_hash(block_number: u64) B256 {
    var input: [32]u8 = @splat(0);
    std.mem.writeInt(u64, input[24..32], block_number, .big);
    return domain_hash(.base_time, primitives.keccak256(&input));
}

pub const DepositTx = struct {
    source_hash: B256,
    from: Address,
    /// Null means contract creation.
    to: ?Address,
    mint: u128 = 0,
    value: u256 = 0,
    gas_limit: u64,
    is_system_transaction: bool = false,
    /// Borrowed calldata.
    input: []const u8,

    fn payload_length(tx: *const DepositTx) usize {
        const to_length: usize = if (tx.to == null) 1 else 21;
        return 33 + 21 + to_length + rlp.int_length(tx.mint) + rlp.int_length(tx.value) +
            rlp.int_length(tx.gas_limit) + 1 + rlp.bytes_length(tx.input);
    }

    /// Length of the EIP-2718 encoding (type byte included).
    pub fn encoded_length(tx: *const DepositTx) usize {
        return 1 + rlp.list_length(tx.payload_length());
    }

    /// Writes the EIP-2718 encoding into `out`, returning the written prefix.
    pub fn encode(tx: *const DepositTx, out: []u8) []u8 {
        const length = tx.encoded_length();
        assert(out.len >= length);
        out[0] = deposit_tx_type;
        var encoder = rlp.Encoder.init(out[1..length]);
        encoder.list_header(tx.payload_length());
        encoder.bytes(&tx.source_hash.bytes);
        encoder.bytes(&tx.from.bytes);
        if (tx.to) |to| encoder.bytes(&to.bytes) else encoder.bytes(&.{});
        encoder.int(tx.mint);
        encoder.int(tx.value);
        encoder.int(tx.gas_limit);
        encoder.boolean(tx.is_system_transaction);
        encoder.bytes(tx.input);
        assert(encoder.written().len == length - 1);
        return out[0..length];
    }
};

pub const DecodeError = error{
    UnexpectedTopicsLength,
    InvalidSelector,
    IncompleteOpaqueData,
    UnalignedData,
    InvalidFromTopic,
    InvalidToTopic,
    InvalidOpaqueDataOffset,
    OpaqueContentOverflow,
    InvalidOpaqueDataLength,
    InvalidOpaqueDataPadding,
    InvalidVersion,
    UnexpectedOpaqueDataLength,
};

fn word_is_address(word: B256) bool {
    for (word.bytes[0..12]) |byte| if (byte != 0) return false;
    return true;
}

/// Decodes a `TransactionDeposited` log into a deposit tx. `input` borrows `log.data`.
pub fn decode_deposit_log(l1_block_hash: B256, log_index: u64, log: Log) DecodeError!DepositTx {
    if (log.topics.len != 4) return error.UnexpectedTopicsLength;
    if (!log.topics[0].eql(transaction_deposited_topic)) return error.InvalidSelector;
    const data = log.data;
    if (data.len < 64) return error.IncompleteOpaqueData;
    if (data.len % 32 != 0) return error.UnalignedData;
    if (!word_is_address(log.topics[1])) return error.InvalidFromTopic;
    if (!word_is_address(log.topics[2])) return error.InvalidToTopic;

    if (std.mem.readInt(u256, data[0..32], .big) != 32) return error.InvalidOpaqueDataOffset;
    const content_length_word = std.mem.readInt(u256, data[32..64], .big);
    if (content_length_word > std.math.maxInt(u64)) return error.OpaqueContentOverflow;
    const content_length: u64 = @intCast(content_length_word);
    if (content_length > data.len - 64) return error.InvalidOpaqueDataLength;
    const opaque_content = data[64..][0..@intCast(content_length)];
    // Padding up to the next 32-byte boundary must exist and be zero.
    const padded_end: u64 = 64 + std.mem.alignForward(u64, content_length, 32);
    if (content_length % 32 != 0) {
        if (padded_end > data.len) return error.InvalidOpaqueDataPadding;
        const padding = data[@intCast(64 + content_length)..@intCast(padded_end)];
        for (padding) |byte| if (byte != 0) return error.InvalidOpaqueDataPadding;
    }
    if (!log.topics[3].is_zero()) return error.InvalidVersion;
    return unmarshal_v0(
        user_source_hash(l1_block_hash, log_index),
        .init(log.topics[1].bytes[12..32].*),
        .init(log.topics[2].bytes[12..32].*),
        opaque_content,
    );
}

/// Version 0 opaque data: `mint (32) ++ value (32) ++ gas (8) ++ is_creation (1) ++ data`.
fn unmarshal_v0(
    source_hash: B256,
    from: Address,
    to: Address,
    data: []const u8,
) DecodeError!DepositTx {
    if (data.len < 32 + 32 + 8 + 1) return error.UnexpectedOpaqueDataLength;
    const tx: DepositTx = .{
        .source_hash = source_hash,
        .from = from,
        // Only the low 16 bytes of the mint word are read (matches base/base).
        .mint = std.mem.readInt(u128, data[16..32], .big),
        .value = std.mem.readInt(u256, data[32..64], .big),
        .gas_limit = std.mem.readInt(u64, data[64..72], .big),
        .to = if (data[72] == 0) to else null,
        .is_system_transaction = false,
        .input = data[73..],
    };
    assert(tx.input.len == data.len - 73);
    return tx;
}

/// Iterates user deposits in the receipts of one L1 block, in log order. The log index
/// counts every log of successful receipts (base/base `derive_deposits`).
pub const DepositIterator = struct {
    receipts: []const Receipt,
    deposit_contract: Address,
    l1_block_hash: B256,
    receipt_index: usize = 0,
    log_index_in_receipt: usize = 0,
    global_log_index: u64 = 0,

    pub fn next(iterator: *DepositIterator) DecodeError!?DepositTx {
        while (iterator.receipt_index < iterator.receipts.len) {
            const receipt = iterator.receipts[iterator.receipt_index];
            if (!receipt.success or iterator.log_index_in_receipt >= receipt.logs.len) {
                iterator.receipt_index += 1;
                iterator.log_index_in_receipt = 0;
                continue;
            }
            const log = receipt.logs[iterator.log_index_in_receipt];
            const index = iterator.global_log_index;
            iterator.log_index_in_receipt += 1;
            iterator.global_log_index += 1;
            if (log.topics.len == 0 or !log.topics[0].eql(transaction_deposited_topic)) continue;
            if (!log.address.eql(iterator.deposit_contract)) continue;
            return try decode_deposit_log(iterator.l1_block_hash, index, log);
        }
        return null;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn padded(address_hex: []const u8) B256 {
    var word: [32]u8 = @splat(0);
    word[12..32].* = (Address.from_hex(address_hex) catch unreachable).bytes;
    return .init(word);
}

fn make_opaque(buffer: []u8, length: u64) []u8 {
    @memset(buffer, 0);
    buffer[31] = 32;
    std.mem.writeInt(u64, buffer[56..64], length, .big);
    return buffer;
}

const zero_hex_55: *const [110]u8 = &@as([110]u8, @splat('0'));

fn expect_encoding(tx: DepositTx, comptime expected_hex: []const u8) !void {
    const size = expected_hex.len / 2;
    const expected = primitives.hex.decode_array(size, expected_hex) catch unreachable;
    var buffer: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, &expected, tx.encode(&buffer));
}

test "deposits: decode empty deposit (base/base vector)" {
    var buffer: [192]u8 = undefined;
    const data = make_opaque(&buffer, 128);
    const topics = [_]B256{
        transaction_deposited_topic,
        padded("ffffffffffffffffffffffffffffffffffffffff"),
        padded("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        .zero,
    };
    const log: Log = .{ .address = .zero, .topics = &topics, .data = data };
    const tx = try decode_deposit_log(.zero, 0, log);
    try expect_encoding(tx, "7ef887a0ed428e1c45e1d9561b62834e1a2d3015a0caae3bfdc16b4da059" ++
        "ac885b01a1" ++
        "4594ffffffffffffffffffffffffffffffffffffffff94bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ++
        "80808080b7" ++ zero_hex_55);
}

test "deposits: decode full deposit (base/base vector)" {
    var buffer: [192]u8 = undefined;
    const data = make_opaque(&buffer, 128);
    std.mem.writeInt(u128, data[80..96], 10, .big);
    std.mem.writeInt(u256, data[96..128], 100, .big);
    std.mem.writeInt(u64, data[128..136], 1000, .big);
    data[136] = 1;
    const topics = [_]B256{
        transaction_deposited_topic,
        padded("1111111111111111111111111111111111111111"),
        padded("2222222222222222222222222222222222222222"),
        .zero,
    };
    const log: Log = .{ .address = .zero, .topics = &topics, .data = data };
    const tx = try decode_deposit_log(.zero, 0, log);
    try testing.expect(tx.to == null);
    try expect_encoding(tx, "7ef875a0ed428e1c45e1d9561b62834e1a2d3015a0caae3bfdc16b4da059" ++
        "ac885b01a1" ++
        "45941111111111111111111111111111111111111111800a648203e880b7" ++ zero_hex_55);
}

test "deposits: decode errors" {
    var buffer: [192]u8 = undefined;
    var topics = [_]B256{
        transaction_deposited_topic,
        padded("1111111111111111111111111111111111111111"),
        padded("2222222222222222222222222222222222222222"),
        .zero,
    };
    const log: Log = .{ .address = .zero, .topics = &topics, .data = make_opaque(&buffer, 128) };
    _ = try decode_deposit_log(.zero, 0, log);
    try testing.expectError(error.UnexpectedTopicsLength, decode_deposit_log(.zero, 0, .{
        .address = .zero,
        .topics = topics[0..3],
        .data = log.data,
    }));
    try testing.expectError(error.UnalignedData, decode_deposit_log(.zero, 0, .{
        .address = .zero,
        .topics = &topics,
        .data = log.data[0..100],
    }));
    _ = make_opaque(&buffer, 129); // Longer than the data.
    try testing.expectError(error.InvalidOpaqueDataLength, decode_deposit_log(.zero, 0, log));
    _ = make_opaque(&buffer, 72); // Too short for v0.
    try testing.expectError(error.UnexpectedOpaqueDataLength, decode_deposit_log(.zero, 0, log));
    _ = make_opaque(&buffer, 100);
    buffer[64 + 110] = 1; // Nonzero padding.
    try testing.expectError(error.InvalidOpaqueDataPadding, decode_deposit_log(.zero, 0, log));
    _ = make_opaque(&buffer, 128);
    topics[3] = padded("0000000000000000000000000000000000000001");
    try testing.expectError(error.InvalidVersion, decode_deposit_log(.zero, 0, log));
    topics[3] = .zero;
    topics[1].bytes[0] = 1;
    try testing.expectError(error.InvalidFromTopic, decode_deposit_log(.zero, 0, log));
    topics[1].bytes[0] = 0;
    buffer[0] = 1;
    try testing.expectError(error.InvalidOpaqueDataOffset, decode_deposit_log(.zero, 0, log));
}

test "deposits: iterator skips failed receipts and other emitters but counts their logs" {
    var buffer: [192]u8 = undefined;
    const data = make_opaque(&buffer, 128);
    const deposit_topics = [_]B256{ transaction_deposited_topic, .zero, .zero, .zero };
    const other_topics = [_]B256{.zero};
    const portal = Address.comptime_hex("0x49048044D57e1C92A77f79988d21Fa8fAF74E97e");
    const logs_a = [_]Log{
        .{ .address = portal, .topics = &other_topics, .data = &.{} },
        .{ .address = portal, .topics = &deposit_topics, .data = data },
    };
    const logs_b = [_]Log{.{ .address = portal, .topics = &deposit_topics, .data = data }};
    const logs_c = [_]Log{
        .{ .address = .zero, .topics = &deposit_topics, .data = data },
        .{ .address = portal, .topics = &deposit_topics, .data = data },
    };
    const receipts = [_]Receipt{
        .{ .success = true, .logs = &logs_a },
        .{ .success = false, .logs = &logs_b },
        .{ .success = true, .logs = &logs_c },
    };
    const block_hash: B256 = .init(@splat(0xab));
    var iterator: DepositIterator = .{
        .receipts = &receipts,
        .deposit_contract = portal,
        .l1_block_hash = block_hash,
    };
    const first = (try iterator.next()).?;
    try testing.expect(first.source_hash.eql(user_source_hash(block_hash, 1)));
    const second = (try iterator.next()).?;
    try testing.expect(second.source_hash.eql(user_source_hash(block_hash, 3)));
    try testing.expect((try iterator.next()) == null);
}

test "deposits: source hash domains differ" {
    const hash: B256 = .init(@splat(1));
    try testing.expect(!user_source_hash(hash, 0).eql(l1_info_source_hash(hash, 0)));
    try testing.expect(!upgrade_source_hash("x").eql(base_time_source_hash(0)));
}

fn check_decode(data: []const u8, topics: []const B256) !void {
    const log: Log = .{ .address = .zero, .topics = topics, .data = data };
    const tx = decode_deposit_log(.zero, 0, log) catch return;
    var buffer: [4096]u8 = undefined;
    const encoded = tx.encode(&buffer);
    try testing.expectEqual(tx.encoded_length(), encoded.len);
    try testing.expectEqual(deposit_tx_type, encoded[0]);
    const consumed = try rlp.validate(encoded[1..], 2);
    try testing.expectEqual(@as(usize, 9), consumed); // One list plus eight fields.
}

test "deposits: seeded fuzz decode" {
    var prng = Prng.init(0x4445504f);
    var data: [512]u8 = undefined;
    const topics = [_]B256{ transaction_deposited_topic, .zero, .zero, .zero };
    for (0..5_000) |_| {
        const length = prng.below(16) * 32;
        prng.fill(data[0..length]);
        if (length >= 64 and prng.chance(3, 4)) {
            _ = make_opaque(data[0..64], prng.below(length - 63));
            const content = std.mem.readInt(u64, data[56..64], .big);
            const end = @min(length, 64 + std.mem.alignForward(u64, content, 32));
            if (prng.chance(1, 2)) @memset(data[@intCast(64 + content)..@intCast(end)], 0);
        }
        try check_decode(data[0..length], &topics);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var data: [512]u8 = undefined;
    const length = smith.slice(&data);
    const topics = [_]B256{ transaction_deposited_topic, .zero, .zero, .zero };
    try check_decode(data[0..length], &topics);
}

test "deposits: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

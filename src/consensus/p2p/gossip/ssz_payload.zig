//! SSZ codec for the execution payloads carried by OP Stack unsafe-block gossip:
//! `ExecutionPayloadV1` (Bedrock), `V2` (Canyon, + withdrawals), `V3` (Ecotone, + blob gas
//! used and excess blob gas) and the OP Isthmus `V4` (V3 + `withdrawals_root`), matching
//! base/base `BoundedExecutionPayloadV1..V3` and `BaseExecutionPayloadV4`.
//!
//! Container layout: the fixed part holds every fixed-size field in order plus a 4-byte
//! little-endian offset for each variable field (`extra_data`, `transactions`, and from V2
//! `withdrawals`); variable data follows in the same order. Integers are little-endian,
//! including the 256-bit `base_fee_per_gas`.
//!
//! Decoding is zero-copy: `extra_data`, `transactions`, and `withdrawals` are views into
//! the input. Offsets are validated strictly: the first offset equals the fixed size,
//! offsets never decrease, and every offset is in bounds. Limits follow the SSZ types:
//! `extra_data` at most 32 bytes, at most 2^20 transactions of at most 2^30 bytes each,
//! at most 16 withdrawals. (base/base declares an unbounded `extra_data` here and lets
//! `into_block_raw` reject > 32 bytes later, and caps withdrawals at 0; both end in a
//! gossip Reject either way, and `validity.zig` rejects non-empty withdrawals.)

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../../common/primitives/root.zig");
const payload_types = @import("../../../execution/payload/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Bloom = primitives.Bloom;

pub const Withdrawal = payload_types.Withdrawal;

pub const Version = enum(u8) {
    /// Bedrock.
    v1 = 1,
    /// Canyon: withdrawals list.
    v2 = 2,
    /// Ecotone: blob gas used and excess blob gas (the envelope adds the beacon root).
    v3 = 3,
    /// Isthmus: withdrawals root (L2ToL1MessagePasser storage root).
    v4 = 4,
};

pub const offset_size: u32 = 4;
pub const extra_data_size_max: u32 = 32;
pub const transactions_count_max: u32 = 1 << 20;
pub const transaction_size_max: u32 = 1 << 30;
pub const withdrawals_count_max: u32 = 16;
/// index (8) + validator_index (8) + address (20) + amount (8).
pub const withdrawal_size: u32 = 44;

/// Fixed part of V1: six roots/hashes, address, bloom, four u64, u256, two offsets.
const v1_fixed_size: u32 = 32 * 4 + 20 + 256 + 8 * 4 + offset_size + 32 + 32 + offset_size;

comptime {
    assert(v1_fixed_size == 508);
    assert(fixed_size(.v4) == 560);
    assert(withdrawal_size == 8 + 8 + 20 + 8);
}

/// Size of the fixed part (the first offset of a valid encoding) for `version`.
pub fn fixed_size(version: Version) u32 {
    const size: u32 = switch (version) {
        .v1 => v1_fixed_size,
        .v2 => v1_fixed_size + offset_size,
        .v3 => v1_fixed_size + offset_size + 16,
        .v4 => v1_fixed_size + offset_size + 16 + 32,
    };
    assert(size >= v1_fixed_size);
    assert(size % 4 == 0);
    return size;
}

pub const Error = error{
    /// The input is shorter than the fixed part.
    Truncated,
    /// The first variable offset does not equal the fixed size.
    OffsetInvalid,
    /// A later offset is smaller than an earlier one.
    OffsetOrder,
    /// An offset points past the end of the input.
    OffsetOutOfBounds,
    /// `extra_data` is longer than 32 bytes.
    ExtraDataTooLong,
    /// The transaction list's first offset is not a positive multiple of 4.
    TransactionsOffsetInvalid,
    /// More than 2^20 transactions.
    TooManyTransactions,
    /// One transaction is longer than 2^30 bytes.
    TransactionTooLarge,
    /// The withdrawals list is not a whole number of 44-byte items.
    WithdrawalsLengthInvalid,
    /// More than 16 withdrawals.
    TooManyWithdrawals,
};

fn read_u32(bytes: []const u8, position: usize) u32 {
    assert(position + 4 <= bytes.len);
    return std.mem.readInt(u32, bytes[position..][0..4], .little);
}

/// Zero-copy view of an SSZ `List[ByteList[2^30], 2^20]`: `count` offsets, then the
/// concatenated items. `decode` validates every offset, so `get` cannot fail.
pub const Transactions = struct {
    bytes: []const u8 = &.{},
    count: u32 = 0,

    pub fn decode(bytes: []const u8) Error!Transactions {
        if (bytes.len == 0) return .{};
        if (bytes.len < offset_size) return error.OffsetOutOfBounds;
        const first = read_u32(bytes, 0);
        if (first % offset_size != 0 or first < offset_size) {
            return error.TransactionsOffsetInvalid;
        }
        if (first > bytes.len) return error.OffsetOutOfBounds;
        const count = first / offset_size;
        if (count > transactions_count_max) return error.TooManyTransactions;
        var previous = first;
        var index: u32 = 1;
        while (index < count) : (index += 1) {
            const offset = read_u32(bytes, index * offset_size);
            if (offset < previous) return error.OffsetOrder;
            if (offset > bytes.len) return error.OffsetOutOfBounds;
            if (offset - previous > transaction_size_max) return error.TransactionTooLarge;
            previous = offset;
        }
        if (bytes.len - previous > transaction_size_max) return error.TransactionTooLarge;
        assert(count >= 1);
        assert(previous <= bytes.len);
        return .{ .bytes = bytes, .count = count };
    }

    /// Transaction `index` (an EIP-2718 encoding), a slice of the underlying bytes.
    pub fn get(list: Transactions, index: u32) []const u8 {
        assert(index < list.count);
        const start = read_u32(list.bytes, index * offset_size);
        const end: usize = if (index + 1 < list.count)
            read_u32(list.bytes, (index + 1) * offset_size)
        else
            list.bytes.len;
        assert(start <= end);
        assert(end <= list.bytes.len);
        return list.bytes[start..end];
    }

    /// Encoded size of a list holding `items`.
    pub fn list_length(items: []const []const u8) u64 {
        assert(items.len <= transactions_count_max);
        var total: u64 = @as(u64, items.len) * offset_size;
        for (items) |item| total += item.len;
        assert(total >= items.len * offset_size);
        return total;
    }

    /// Encodes `items` into the front of `out` and returns a view of the result.
    pub fn encode(out: []u8, items: []const []const u8) Transactions {
        const length = list_length(items);
        assert(out.len >= length);
        var data_position: usize = items.len * offset_size;
        for (items, 0..) |item, index| {
            assert(item.len <= transaction_size_max);
            const position = index * offset_size;
            std.mem.writeInt(u32, out[position..][0..4], @intCast(data_position), .little);
            @memcpy(out[data_position..][0..item.len], item);
            data_position += item.len;
        }
        assert(data_position == length);
        return .{ .bytes = out[0..data_position], .count = @intCast(items.len) };
    }
};

/// Zero-copy view of an SSZ `List[Withdrawal, 16]` of fixed 44-byte items.
pub const Withdrawals = struct {
    bytes: []const u8 = &.{},
    count: u32 = 0,

    pub fn decode(bytes: []const u8) Error!Withdrawals {
        if (bytes.len % withdrawal_size != 0) return error.WithdrawalsLengthInvalid;
        if (bytes.len / withdrawal_size > withdrawals_count_max) return error.TooManyWithdrawals;
        const count: u32 = @intCast(bytes.len / withdrawal_size);
        assert(count <= withdrawals_count_max);
        assert(count * withdrawal_size == bytes.len);
        return .{ .bytes = bytes, .count = count };
    }

    pub fn get(list: Withdrawals, index: u32) Withdrawal {
        assert(index < list.count);
        const item = list.bytes[index * withdrawal_size ..][0..withdrawal_size];
        assert(item.len == withdrawal_size);
        return .{
            .index = std.mem.readInt(u64, item[0..8], .little),
            .validator_index = std.mem.readInt(u64, item[8..16], .little),
            .address = .{ .bytes = item[16..36].* },
            .amount_gwei = std.mem.readInt(u64, item[36..44], .little),
        };
    }

    /// Encodes `items` into the front of `out` and returns a view of the result.
    pub fn encode(out: []u8, items: []const Withdrawal) Withdrawals {
        assert(items.len <= withdrawals_count_max);
        assert(out.len >= items.len * withdrawal_size);
        for (items, 0..) |item, index| {
            const slot = out[index * withdrawal_size ..][0..withdrawal_size];
            std.mem.writeInt(u64, slot[0..8], item.index, .little);
            std.mem.writeInt(u64, slot[8..16], item.validator_index, .little);
            slot[16..36].* = item.address.bytes;
            std.mem.writeInt(u64, slot[36..44], item.amount_gwei, .little);
        }
        return .{ .bytes = out[0 .. items.len * withdrawal_size], .count = @intCast(items.len) };
    }
};

/// One payload of any version. Fields a version lacks hold zero values: no withdrawals
/// before V2, zero blob gas before V3, a zero withdrawals root before V4.
pub const ExecutionPayload = struct {
    version: Version,
    parent_hash: B256 = .zero,
    fee_recipient: Address = .zero,
    state_root: B256 = .zero,
    receipts_root: B256 = .zero,
    logs_bloom: Bloom = .zero,
    prev_randao: B256 = .zero,
    block_number: u64 = 0,
    gas_limit: u64 = 0,
    gas_used: u64 = 0,
    timestamp: u64 = 0,
    extra_data: []const u8 = &.{},
    base_fee_per_gas: u256 = 0,
    block_hash: B256 = .zero,
    transactions: Transactions = .{},
    withdrawals: Withdrawals = .{},
    blob_gas_used: u64 = 0,
    excess_blob_gas: u64 = 0,
    withdrawals_root: B256 = .zero,

    pub fn has_withdrawals(payload: ExecutionPayload) bool {
        return @backingInt(payload.version) >= @backingInt(Version.v2);
    }

    pub fn has_blob_gas(payload: ExecutionPayload) bool {
        return @backingInt(payload.version) >= @backingInt(Version.v3);
    }
};

/// Sequential reader over the fixed part. Bounds were checked against the fixed size.
const FixedReader = struct {
    bytes: []const u8,
    position: usize = 0,

    fn take(reader: *FixedReader, comptime size: usize) *const [size]u8 {
        assert(reader.position + size <= reader.bytes.len);
        const result = reader.bytes[reader.position..][0..size];
        reader.position += size;
        return result;
    }

    fn int(reader: *FixedReader, comptime T: type) T {
        return std.mem.readInt(T, reader.take(@sizeOf(T)), .little);
    }
};

const Offsets = struct {
    extra_data: u32,
    transactions: u32,
    withdrawals: u32,
};

fn decode_fixed(payload: *ExecutionPayload, bytes: []const u8) Offsets {
    const fixed = fixed_size(payload.version);
    assert(bytes.len >= fixed);
    var reader: FixedReader = .{ .bytes = bytes };
    payload.parent_hash = .{ .bytes = reader.take(32).* };
    payload.fee_recipient = .{ .bytes = reader.take(20).* };
    payload.state_root = .{ .bytes = reader.take(32).* };
    payload.receipts_root = .{ .bytes = reader.take(32).* };
    payload.logs_bloom = .{ .bytes = reader.take(256).* };
    payload.prev_randao = .{ .bytes = reader.take(32).* };
    payload.block_number = reader.int(u64);
    payload.gas_limit = reader.int(u64);
    payload.gas_used = reader.int(u64);
    payload.timestamp = reader.int(u64);
    var offsets: Offsets = .{ .extra_data = reader.int(u32), .transactions = 0, .withdrawals = 0 };
    payload.base_fee_per_gas = reader.int(u256);
    payload.block_hash = .{ .bytes = reader.take(32).* };
    offsets.transactions = reader.int(u32);
    offsets.withdrawals = if (payload.has_withdrawals()) reader.int(u32) else @intCast(bytes.len);
    if (payload.has_blob_gas()) {
        payload.blob_gas_used = reader.int(u64);
        payload.excess_blob_gas = reader.int(u64);
    }
    if (payload.version == .v4) payload.withdrawals_root = .{ .bytes = reader.take(32).* };
    assert(reader.position == fixed);
    return offsets;
}

/// Decodes a payload of `version`. The result borrows `bytes`.
pub fn decode(version: Version, bytes: []const u8) Error!ExecutionPayload {
    const fixed = fixed_size(version);
    if (bytes.len < fixed) return error.Truncated;
    var payload: ExecutionPayload = .{ .version = version };
    const offsets = decode_fixed(&payload, bytes);
    if (offsets.extra_data != fixed) return error.OffsetInvalid;
    if (offsets.transactions < offsets.extra_data) return error.OffsetOrder;
    if (offsets.withdrawals < offsets.transactions) return error.OffsetOrder;
    if (offsets.transactions > bytes.len) return error.OffsetOutOfBounds;
    if (offsets.withdrawals > bytes.len) return error.OffsetOutOfBounds;
    payload.extra_data = bytes[offsets.extra_data..offsets.transactions];
    if (payload.extra_data.len > extra_data_size_max) return error.ExtraDataTooLong;
    payload.transactions =
        try Transactions.decode(bytes[offsets.transactions..offsets.withdrawals]);
    if (payload.has_withdrawals()) {
        payload.withdrawals = try Withdrawals.decode(bytes[offsets.withdrawals..]);
    }
    assert(payload.extra_data.len <= extra_data_size_max);
    assert(payload.has_withdrawals() or payload.withdrawals.count == 0);
    return payload;
}

/// Encoded size of `payload`.
pub fn encoded_length(payload: ExecutionPayload) u64 {
    assert(payload.extra_data.len <= extra_data_size_max);
    assert(payload.has_withdrawals() or payload.withdrawals.count == 0);
    const length = @as(u64, fixed_size(payload.version)) + payload.extra_data.len +
        payload.transactions.bytes.len + payload.withdrawals.bytes.len;
    assert(length >= fixed_size(payload.version));
    return length;
}

const FixedWriter = struct {
    out: []u8,
    position: usize = 0,

    fn put(writer: *FixedWriter, bytes: []const u8) void {
        assert(writer.position + bytes.len <= writer.out.len);
        @memcpy(writer.out[writer.position..][0..bytes.len], bytes);
        writer.position += bytes.len;
    }

    fn int(writer: *FixedWriter, comptime T: type, value: T) void {
        var buffer: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buffer, value, .little);
        writer.put(&buffer);
    }
};

/// Encodes `payload` into the front of `out` (at least `encoded_length` bytes).
pub fn encode(payload: ExecutionPayload, out: []u8) []u8 {
    const length = encoded_length(payload);
    assert(out.len >= length);
    const fixed = fixed_size(payload.version);
    const transactions_offset: u32 = fixed + @as(u32, @intCast(payload.extra_data.len));
    const withdrawals_offset: u32 =
        transactions_offset + @as(u32, @intCast(payload.transactions.bytes.len));
    var writer: FixedWriter = .{ .out = out };
    writer.put(&payload.parent_hash.bytes);
    writer.put(&payload.fee_recipient.bytes);
    writer.put(&payload.state_root.bytes);
    writer.put(&payload.receipts_root.bytes);
    writer.put(&payload.logs_bloom.bytes);
    writer.put(&payload.prev_randao.bytes);
    writer.int(u64, payload.block_number);
    writer.int(u64, payload.gas_limit);
    writer.int(u64, payload.gas_used);
    writer.int(u64, payload.timestamp);
    writer.int(u32, fixed);
    writer.int(u256, payload.base_fee_per_gas);
    writer.put(&payload.block_hash.bytes);
    writer.int(u32, transactions_offset);
    if (payload.has_withdrawals()) writer.int(u32, withdrawals_offset);
    if (payload.has_blob_gas()) {
        writer.int(u64, payload.blob_gas_used);
        writer.int(u64, payload.excess_blob_gas);
    }
    if (payload.version == .v4) writer.put(&payload.withdrawals_root.bytes);
    assert(writer.position == fixed);
    writer.put(payload.extra_data);
    writer.put(payload.transactions.bytes);
    writer.put(payload.withdrawals.bytes);
    assert(writer.position == length);
    return out[0..length];
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");
const vectors = @import("vectors.zig");

/// A payload with every field set from `prng`, storing variable data in `storage`.
pub fn random_payload(prng: *Prng, version: Version, storage: []u8) ExecutionPayload {
    assert(storage.len >= 4096);
    var payload: ExecutionPayload = .{ .version = version };
    prng.fill(&payload.parent_hash.bytes);
    prng.fill(&payload.fee_recipient.bytes);
    prng.fill(&payload.state_root.bytes);
    prng.fill(&payload.receipts_root.bytes);
    prng.fill(&payload.logs_bloom.bytes);
    prng.fill(&payload.prev_randao.bytes);
    payload.block_number = prng.int(u64);
    payload.gas_limit = prng.int(u64);
    payload.gas_used = prng.int(u64);
    payload.timestamp = prng.int(u64);
    payload.base_fee_per_gas = prng.int(u256);
    prng.fill(&payload.block_hash.bytes);
    const extra = storage[0..@intCast(prng.range(0, extra_data_size_max))];
    prng.fill(extra);
    payload.extra_data = extra;
    var items_storage: [8][]const u8 = undefined;
    const items = items_storage[0..@intCast(prng.range(0, items_storage.len))];
    var position: usize = 64;
    for (items) |*item| {
        const item_bytes = storage[position..][0..@intCast(prng.range(0, 200))];
        prng.fill(item_bytes);
        item.* = item_bytes;
        position += item_bytes.len;
    }
    payload.transactions = Transactions.encode(storage[2048..], items);
    if (payload.has_withdrawals()) {
        var withdrawals: [withdrawals_count_max]Withdrawal = undefined;
        const count: usize = @intCast(prng.range(0, 3));
        for (withdrawals[0..count]) |*withdrawal| {
            withdrawal.* = .{
                .index = prng.int(u64),
                .validator_index = prng.int(u64),
                .address = .{ .bytes = @splat(prng.int(u8)) },
                .amount_gwei = prng.int(u64),
            };
        }
        payload.withdrawals = Withdrawals.encode(storage[1600..2048], withdrawals[0..count]);
    }
    if (payload.has_blob_gas()) {
        payload.blob_gas_used = prng.int(u64);
        payload.excess_blob_gas = prng.int(u64);
    }
    if (version == .v4) prng.fill(&payload.withdrawals_root.bytes);
    return payload;
}

fn expect_payload_equal(expected: ExecutionPayload, actual: ExecutionPayload) !void {
    try testing.expectEqual(expected.version, actual.version);
    try testing.expect(expected.parent_hash.eql(actual.parent_hash));
    try testing.expect(expected.fee_recipient.eql(actual.fee_recipient));
    try testing.expectEqualSlices(u8, &expected.logs_bloom.bytes, &actual.logs_bloom.bytes);
    try testing.expectEqual(expected.block_number, actual.block_number);
    try testing.expectEqual(expected.timestamp, actual.timestamp);
    try testing.expectEqual(expected.base_fee_per_gas, actual.base_fee_per_gas);
    try testing.expectEqualSlices(u8, expected.extra_data, actual.extra_data);
    try testing.expectEqual(expected.transactions.count, actual.transactions.count);
    var index: u32 = 0;
    while (index < expected.transactions.count) : (index += 1) {
        const want = expected.transactions.get(index);
        try testing.expectEqualSlices(u8, want, actual.transactions.get(index));
    }
    try testing.expectEqual(expected.withdrawals.count, actual.withdrawals.count);
    index = 0;
    while (index < expected.withdrawals.count) : (index += 1) {
        const want = expected.withdrawals.get(index);
        try testing.expectEqual(want, actual.withdrawals.get(index));
    }
    try testing.expectEqual(expected.blob_gas_used, actual.blob_gas_used);
    try testing.expectEqual(expected.excess_blob_gas, actual.excess_blob_gas);
    try testing.expect(expected.withdrawals_root.eql(actual.withdrawals_root));
}

test "ssz_payload: fixed sizes" {
    try testing.expectEqual(@as(u32, 508), fixed_size(.v1));
    try testing.expectEqual(@as(u32, 512), fixed_size(.v2));
    try testing.expectEqual(@as(u32, 528), fixed_size(.v3));
    try testing.expectEqual(@as(u32, 560), fixed_size(.v4));
}

test "ssz_payload: hand-built v1 layout" {
    var tx_storage: [16]u8 = undefined;
    const txs = Transactions.encode(&tx_storage, &.{ "\x02\xaa", "\x7e" });
    try testing.expectEqualSlices(u8, "\x08\x00\x00\x00\x0a\x00\x00\x00\x02\xaa\x7e", txs.bytes);
    const payload: ExecutionPayload = .{
        .version = .v1,
        .block_number = 0x0102,
        .timestamp = 7,
        .extra_data = "xy",
        .base_fee_per_gas = 0x1_0000_0000_0000_0000,
        .transactions = txs,
    };
    var out: [600]u8 = undefined;
    const encoded = encode(payload, &out);
    try testing.expectEqual(@as(usize, 508 + 2 + 11), encoded.len);
    try testing.expectEqualSlices(u8, "\x02\x01\x00\x00\x00\x00\x00\x00", encoded[404..412]);
    try testing.expectEqualSlices(u8, "\x07\x00\x00\x00\x00\x00\x00\x00", encoded[428..436]);
    try testing.expectEqualSlices(u8, "\xfc\x01\x00\x00", encoded[436..440]); // 508
    try testing.expectEqual(@as(u8, 1), encoded[440 + 8]); // u256 little-endian
    try testing.expectEqualSlices(u8, "\xfe\x01\x00\x00", encoded[504..508]); // 510
    try testing.expectEqualSlices(u8, "xy", encoded[508..510]);
    const decoded = try decode(.v1, encoded);
    try expect_payload_equal(payload, decoded);
    try testing.expectEqualSlices(u8, "\x7e", decoded.transactions.get(1));
}

test "ssz_payload: base/base v4 vector round trips" {
    var buffer: [1024]u8 = undefined;
    const bytes = vectors.decode(&buffer, vectors.payload_v4_ssz);
    try testing.expectEqual(@as(usize, 568), bytes.len);
    const payload = try decode(.v4, bytes);
    try testing.expectEqual(@as(u64, 222), payload.block_number);
    try testing.expectEqual(@as(u64, 555), payload.timestamp);
    try testing.expectEqualSlices(u8, "\x66\x66", payload.extra_data);
    try testing.expectEqual(@as(u32, 1), payload.transactions.count);
    try testing.expectEqualSlices(u8, "\x99\x99", payload.transactions.get(0));
    try testing.expectEqual(@as(u32, 0), payload.withdrawals.count);
    try testing.expectEqual(@as(u8, 0x23), payload.withdrawals_root.bytes[31]);
    var out: [1024]u8 = undefined;
    try testing.expectEqualSlices(u8, bytes, encode(payload, &out));
}

test "ssz_payload: seeded round trip of every version" {
    var prng = Prng.init(0x7373_7a70);
    var storage: [4096]u8 = undefined;
    var out: [8192]u8 = undefined;
    for (0..200) |iteration| {
        const version: Version = @fromBackingInt(@intCast(1 + iteration % 4));
        const payload = random_payload(&prng, version, &storage);
        const encoded = encode(payload, &out);
        try testing.expectEqual(encoded_length(payload), encoded.len);
        try expect_payload_equal(payload, try decode(version, encoded));
        // Other versions see a different fixed size and must not panic.
        for ([_]Version{ .v1, .v2, .v3, .v4 }) |other| _ = decode(other, encoded) catch {};
    }
}

fn put_u32(bytes: []u8, position: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[position..][0..4], value, .little);
}

test "ssz_payload: strict offsets and limits" {
    var buffer: [1024]u8 = @splat(0);
    const empty: ExecutionPayload = .{ .version = .v2 };
    const encoded = encode(empty, &buffer);
    try testing.expectEqual(@as(usize, 512), encoded.len);
    _ = try decode(.v2, encoded);
    try testing.expectError(error.Truncated, decode(.v2, encoded[0..511]));
    put_u32(encoded, 436, 516);
    try testing.expectError(error.OffsetInvalid, decode(.v2, encoded));
    put_u32(encoded, 436, 512);
    put_u32(encoded, 504, 511);
    try testing.expectError(error.OffsetOrder, decode(.v2, encoded));
    put_u32(encoded, 504, 513);
    put_u32(encoded, 508, 513);
    try testing.expectError(error.OffsetOutOfBounds, decode(.v2, encoded));
    put_u32(encoded, 504, 512);
    put_u32(encoded, 508, 600);
    try testing.expectError(error.OffsetOutOfBounds, decode(.v2, encoded));
    put_u32(encoded, 508, 512);
    // 33 bytes of extra data: offsets 512 / 545 / 545 over 545 bytes.
    put_u32(encoded, 504, 545);
    put_u32(encoded, 508, 545);
    try testing.expectError(error.ExtraDataTooLong, decode(.v2, buffer[0..545]));
    put_u32(encoded, 504, 544);
    put_u32(encoded, 508, 544);
    _ = try decode(.v2, buffer[0..544]);
}

test "ssz_payload: transaction and withdrawal list validation" {
    try testing.expectEqual(@as(u32, 0), (try Transactions.decode("")).count);
    const E = error.TransactionsOffsetInvalid;
    try testing.expectError(error.OffsetOutOfBounds, Transactions.decode("\x04\x00"));
    try testing.expectError(E, Transactions.decode("\x00\x00\x00\x00"));
    try testing.expectError(E, Transactions.decode("\x05\x00\x00\x00\x00"));
    try testing.expectError(error.OffsetOutOfBounds, Transactions.decode("\x08\x00\x00\x00"));
    const unordered = "\x08\x00\x00\x00\x07\x00\x00\x00";
    try testing.expectError(error.OffsetOrder, Transactions.decode(unordered));
    const past_end = "\x08\x00\x00\x00\x09\x00\x00\x00";
    try testing.expectError(error.OffsetOutOfBounds, Transactions.decode(past_end));
    // An empty item is valid SSZ (validity rejects it as an undecodable transaction).
    const list = try Transactions.decode("\x04\x00\x00\x00");
    try testing.expectEqual(@as(u32, 1), list.count);
    try testing.expectEqual(@as(usize, 0), list.get(0).len);
    var many: [(transactions_count_max + 1) * 4]u8 = undefined;
    put_u32(&many, 0, @intCast(many.len));
    try testing.expectError(error.TooManyTransactions, Transactions.decode(&many));
    const withdrawal_bytes: [withdrawal_size * 17]u8 = @splat(1);
    const ragged = withdrawal_bytes[1..];
    try testing.expectError(error.WithdrawalsLengthInvalid, Withdrawals.decode(ragged));
    try testing.expectError(error.TooManyWithdrawals, Withdrawals.decode(&withdrawal_bytes));
    const sixteen = try Withdrawals.decode(withdrawal_bytes[withdrawal_size..]);
    try testing.expectEqual(@as(u32, 16), sixteen.count);
    try testing.expectEqual(@as(u64, 0x0101010101010101), sixteen.get(15).amount_gwei);
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    var out: [fuzz.input_size_limit]u8 = undefined;
    for ([_]Version{ .v1, .v2, .v3, .v4 }) |version| {
        const payload = decode(version, input) catch continue;
        // Anything accepted re-encodes byte for byte: the encoding is canonical.
        try testing.expectEqualSlices(u8, input, encode(payload, &out));
        var index: u32 = 0;
        while (index < payload.transactions.count) : (index += 1) {
            _ = payload.transactions.get(index);
        }
    }
}

test "ssz_payload: fuzz decode of random bytes" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 2048 });
}

fn fuzz_mutate(_: void, smith: *std.testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var storage: [4096]u8 = undefined;
    var out: [8192]u8 = undefined;
    const version: Version = @fromBackingInt(@intCast(1 + prng.below(4)));
    const encoded = encode(random_payload(&prng, version, &storage), &out);
    const flips = prng.range(1, 6);
    for (0..flips) |_| {
        const position: usize = @intCast(prng.below(encoded.len));
        // Bias mutations toward the offsets, where the interesting checks are.
        const target = if (prng.chance(1, 2)) 436 + prng.below(4) else position;
        encoded[@intCast(@min(target, encoded.len - 1))] = prng.int(u8);
    }
    const cut: usize = @intCast(prng.range(0, encoded.len));
    try fuzz_decode({}, encoded[0..cut]);
    try fuzz_decode({}, encoded);
}

test "ssz_payload: fuzz decode of mutated valid payloads" {
    try fuzz.run({}, fuzz_mutate, .{});
}

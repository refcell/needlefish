//! Logs and receipts, including the OP deposit receipt fields (Regolith deposit nonce,
//! Canyon receipt version). Mirrors base/base `crates/common/consensus/src/receipts`.
//!
//! Consensus encoding: `type || rlp([status, cumulative_gas_used, bloom, logs, ...])`,
//! with legacy receipts as a bare list. Logs are zero copy (validated RLP payload).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const fields = @import("tx_fields.zig");
const tx_module = @import("tx.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Bloom = primitives.Bloom;
const HashList = fields.HashList;
const TxType = tx_module.TxType;

pub const Log = struct {
    address: Address,
    topics: HashList,
    data: []const u8,

    /// Adds this log's address and topics to `bloom`.
    pub fn accrue(log: Log, bloom: *Bloom) void {
        bloom.accrue(&log.address.bytes);
        for (0..log.topics.count()) |index| bloom.accrue(&log.topics.get(index).bytes);
    }
};

pub const Logs = struct {
    payload: []const u8 = &.{},
    count: u32 = 0,

    pub const empty: Logs = .{};

    pub const Iterator = struct {
        decoder: rlp.Decoder,

        pub fn next(self: *Iterator) ?Log {
            if (self.decoder.is_empty()) return null;
            return rlp.decode(Log, &self.decoder) catch unreachable; // Validated.
        }
    };

    pub fn iterator(logs: Logs) Iterator {
        return .{ .decoder = rlp.Decoder.init(logs.payload) };
    }

    pub fn from_payload(payload: []const u8) rlp.Error!Logs {
        var decoder = rlp.Decoder.init(payload);
        var count: u32 = 0;
        while (!decoder.is_empty()) : (count += 1) _ = try rlp.decode(Log, &decoder);
        return .{ .payload = payload, .count = count };
    }

    pub fn build(buffer: []u8, items: []const Log) Logs {
        var encoder = rlp.Encoder.init(buffer);
        for (items) |item| rlp.encode(&encoder, item);
        return .{ .payload = encoder.written(), .count = @intCast(items.len) };
    }

    pub fn bloom(logs: Logs) Bloom {
        var result = Bloom.zero;
        var it = logs.iterator();
        while (it.next()) |log| log.accrue(&result);
        return result;
    }

    pub fn rlp_length(logs: Logs) usize {
        return rlp.list_length(logs.payload.len);
    }

    pub fn rlp_encode(logs: Logs, encoder: *rlp.Encoder) void {
        encoder.list_header(logs.payload.len);
        encoder.raw(logs.payload);
    }

    pub fn rlp_decode(decoder: *rlp.Decoder) rlp.Error!Logs {
        const items = try decoder.list();
        return from_payload(items.input);
    }
};

pub const DecodeError = rlp.Error || error{ UnknownTxType, InvalidEnvelope };

/// A receipt with its bloom, as stored in the receipts trie.
pub const Receipt = struct {
    tx_type: TxType = .legacy,
    /// EIP-658 status: true on success.
    status: bool,
    cumulative_gas_used: u64,
    logs_bloom: Bloom = .zero,
    logs: Logs = .empty,
    /// Deposits only, from Regolith.
    deposit_nonce: ?u64 = null,
    /// Deposits only, from Canyon (requires `deposit_nonce`).
    deposit_receipt_version: ?u64 = null,
    /// EIP-8130 only (required): how many call phases committed, in order.
    committed_phases: ?u64 = null,

    pub const CommittedPhasesError = error{ ExceedsPhaseCount, StatusMismatch };

    /// base/base: `committed_phases <= phase_count`, and status is success exactly when
    /// every phase committed.
    pub fn validate_committed_phases(
        receipt: Receipt,
        phase_count: u64,
    ) CommittedPhasesError!void {
        assert(receipt.tx_type == .eip8130);
        const committed = receipt.committed_phases.?;
        if (committed > phase_count) return error.ExceedsPhaseCount;
        if (receipt.status != (committed == phase_count)) return error.StatusMismatch;
    }

    pub fn phase_committed(receipt: Receipt, index: u64) bool {
        return index < (receipt.committed_phases orelse 0);
    }

    fn payload_length(receipt: Receipt) usize {
        var total = 1 + rlp.int_length(receipt.cumulative_gas_used) +
            rlp.length(receipt.logs_bloom) + rlp.length(receipt.logs);
        if (receipt.deposit_nonce) |nonce| total += rlp.int_length(nonce);
        if (receipt.deposit_receipt_version) |version| total += rlp.int_length(version);
        if (receipt.committed_phases) |phases| total += rlp.int_length(phases);
        return total;
    }

    fn assert_valid(receipt: Receipt) void {
        if (receipt.tx_type != .deposit) assert(receipt.deposit_nonce == null);
        if (receipt.deposit_receipt_version != null) assert(receipt.deposit_nonce != null);
        assert((receipt.tx_type == .eip8130) == (receipt.committed_phases != null));
    }

    /// Length of the EIP-2718 encoding.
    pub fn encoded_length(receipt: Receipt) usize {
        const type_length: usize = if (receipt.tx_type == .legacy) 0 else 1;
        return type_length + rlp.list_length(receipt.payload_length());
    }

    pub fn encode(receipt: Receipt, encoder: *rlp.Encoder) void {
        receipt.assert_valid();
        const start = encoder.position;
        if (receipt.tx_type != .legacy) encoder.raw(&.{@backingInt(receipt.tx_type)});
        encoder.list_header(receipt.payload_length());
        encoder.boolean(receipt.status);
        encoder.int(receipt.cumulative_gas_used);
        rlp.encode(encoder, receipt.logs_bloom);
        rlp.encode(encoder, receipt.logs);
        if (receipt.deposit_nonce) |nonce| encoder.int(nonce);
        if (receipt.deposit_receipt_version) |version| encoder.int(version);
        if (receipt.committed_phases) |phases| encoder.int(phases);
        assert(encoder.position - start == receipt.encoded_length());
    }

    pub fn encode_to(receipt: Receipt, buffer: []u8) []u8 {
        var encoder = rlp.Encoder.init(buffer);
        receipt.encode(&encoder);
        return encoder.written();
    }

    /// Decodes one EIP-2718 encoded receipt.
    pub fn decode(encoded: []const u8) DecodeError!Receipt {
        if (encoded.len == 0) return error.UnexpectedEnd;
        var tx_type: TxType = .legacy;
        var body = encoded;
        if (encoded[0] < 0xc0) {
            tx_type = std.enums.fromInt(TxType, encoded[0]) orelse return error.UnknownTxType;
            if (tx_type == .legacy) return error.InvalidEnvelope;
            body = encoded[1..];
        }
        var decoder = rlp.Decoder.init(body);
        var items = try decoder.list();
        try decoder.finish();
        var receipt: Receipt = .{
            .tx_type = tx_type,
            .status = try items.boolean(),
            .cumulative_gas_used = try items.int(u64),
            .logs_bloom = try rlp.decode(Bloom, &items),
            .logs = try rlp.decode(Logs, &items),
        };
        if (tx_type == .deposit and !items.is_empty()) {
            receipt.deposit_nonce = try items.int(u64);
            if (!items.is_empty()) receipt.deposit_receipt_version = try items.int(u64);
        }
        if (tx_type == .eip8130) receipt.committed_phases = try items.int(u64);
        try items.finish();
        receipt.assert_valid();
        return receipt;
    }

    /// Network (block body / devp2p) form: typed receipts are wrapped in a string.
    pub fn network_length(receipt: Receipt) usize {
        const length = receipt.encoded_length();
        if (receipt.tx_type == .legacy) return length;
        return rlp.header_length(length) + length;
    }

    pub fn encode_network(receipt: Receipt, encoder: *rlp.Encoder) void {
        if (receipt.tx_type != .legacy) encoder.string_header(receipt.encoded_length());
        receipt.encode(encoder);
    }

    pub fn decode_network(decoder: *rlp.Decoder) DecodeError!Receipt {
        const header = try decoder.peek_header();
        if (header.list) return decode(try decoder.raw());
        const inner = try decoder.bytes();
        if (inner.len == 0 or inner[0] >= 0x80) return error.InvalidEnvelope;
        return decode(inner);
    }
};

const testing = std.testing;
const hex = primitives.hex;
const Prng = @import("../../testing/prng.zig").Prng;

fn zero_bloom_hex() [512]u8 {
    return @splat('0');
}

// EIP-2481 legacy receipt vector (failed status, one log), as used by base/base tests.
test "receipt: EIP-2481 legacy receipt vector" {
    const prefix = "f901668001b90100";
    const suffix = "f85ff85d940000000000000000000000000000000000000011f842a00000000000000000" ++
        "00000000000000000000000000000000000000000000dead" ++
        "a0000000000000000000000000000000000000000000000000000000000000beef830100ff";
    const text = prefix ++ zero_bloom_hex() ++ suffix;
    var buffer: [400]u8 = undefined;
    const encoded = try hex.decode_into(&buffer, text);
    const receipt = try Receipt.decode(encoded);
    try testing.expect(!receipt.status);
    try testing.expectEqual(@as(u64, 1), receipt.cumulative_gas_used);
    try testing.expectEqual(@as(u32, 1), receipt.logs.count);
    var it = receipt.logs.iterator();
    const log = it.next().?;
    try testing.expectEqual(@as(u8, 0x11), log.address.bytes[19]);
    try testing.expectEqual(@as(usize, 2), log.topics.count());
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0xff }, log.data);
    var again: [400]u8 = undefined;
    try testing.expectEqualSlices(u8, encoded, receipt.encode_to(&again));
}

test "receipt: OP deposit receipt vectors (Regolith, Canyon)" {
    const prefix = "f9010c0182b741b90100";
    const regolith = prefix ++ zero_bloom_hex() ++ "c0833d3bbf";
    const canyon = "f9010d0182b741b90100" ++ zero_bloom_hex() ++ "c0833d3bbf01";
    inline for (.{ regolith, canyon }, 0..) |text, index| {
        var buffer: [400]u8 = undefined;
        const body = try hex.decode_into(buffer[1..], text);
        buffer[0] = 0x7e;
        const encoded = buffer[0 .. body.len + 1];
        const receipt = try Receipt.decode(encoded);
        try testing.expect(receipt.status);
        try testing.expectEqual(@as(u64, 46913), receipt.cumulative_gas_used);
        try testing.expectEqual(@as(?u64, 4012991), receipt.deposit_nonce);
        const version: ?u64 = if (index == 0) null else 1;
        try testing.expectEqual(version, receipt.deposit_receipt_version);
        var again: [400]u8 = undefined;
        try testing.expectEqualSlices(u8, encoded, receipt.encode_to(&again));
    }
}

test "receipt: seeded fuzz round trip with bloom" {
    var prng = Prng.init(0x4ec1);
    var log_buffer: [2048]u8 = undefined;
    var buffer: [4096]u8 = undefined;
    var network: [4096]u8 = undefined;
    const types = [_]TxType{
        .legacy, .eip2930, .eip1559, .eip4844, .eip7702, .eip8130, .deposit,
    };
    for (0..200) |_| {
        var topics_buffer: [4 * 33]u8 = undefined;
        var topics: [4]B256 = undefined;
        for (&topics) |*topic| prng.fill(&topic.bytes);
        var data: [64]u8 = undefined;
        var logs: [4]Log = undefined;
        const log_count = prng.below(logs.len + 1);
        for (logs[0..log_count]) |*log| {
            prng.fill(&log.address.bytes);
            log.topics = HashList.build(&topics_buffer, topics[0..prng.below(5)]);
            log.data = data[0..prng.below(data.len + 1)];
        }
        const built = Logs.build(&log_buffer, logs[0..log_count]);
        var receipt: Receipt = .{
            .tx_type = types[prng.below(types.len)],
            .status = prng.chance(1, 2),
            .cumulative_gas_used = prng.int(u64) >> @intCast(prng.below(64)),
            .logs = built,
            .logs_bloom = built.bloom(),
        };
        if (receipt.tx_type == .deposit and prng.chance(1, 2)) {
            receipt.deposit_nonce = prng.int(u64);
            if (prng.chance(1, 2)) receipt.deposit_receipt_version = 1;
        }
        if (receipt.tx_type == .eip8130) receipt.committed_phases = prng.below(4);
        const encoded = receipt.encode_to(&buffer);
        const decoded = try Receipt.decode(encoded);
        try testing.expect(decoded.logs_bloom.eql(decoded.logs.bloom()));
        try testing.expectEqualSlices(u8, encoded, decoded.encode_to(&network));
        var encoder = rlp.Encoder.init(&network);
        decoded.encode_network(&encoder);
        var decoder = rlp.Decoder.init(encoder.written());
        const again = try Receipt.decode_network(&decoder);
        try testing.expectEqual(receipt.cumulative_gas_used, again.cumulative_gas_used);
    }
}

fn fuzz_receipt(_: void, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const len = smith.slice(&input);
    const receipt = Receipt.decode(input[0..len]) catch return;
    var again: [1024]u8 = undefined;
    try testing.expectEqualSlices(u8, input[0..len], receipt.encode_to(&again));
}

test "receipt: fuzz decode is canonical" {
    try testing.fuzz({}, fuzz_receipt, .{});
}

test "receipt: EIP-8130 committed phases" {
    var buffer: [512]u8 = undefined;
    const receipt: Receipt = .{
        .tx_type = .eip8130,
        .status = false,
        .cumulative_gas_used = 21_000,
        .committed_phases = 1,
    };
    const encoded = receipt.encode_to(&buffer);
    try testing.expectEqual(@as(u8, 0x79), encoded[0]);
    // committed_phases is the last list item.
    try testing.expectEqual(@as(u8, 0x01), encoded[encoded.len - 1]);
    const decoded = try Receipt.decode(encoded);
    try testing.expectEqual(@as(?u64, 1), decoded.committed_phases);
    try decoded.validate_committed_phases(2);
    try testing.expect(decoded.phase_committed(0) and !decoded.phase_committed(1));
    try testing.expectError(error.ExceedsPhaseCount, decoded.validate_committed_phases(0));
    try testing.expectError(error.StatusMismatch, decoded.validate_committed_phases(1));
    // The field is required for 0x79 receipts.
    var short: [512]u8 = undefined;
    var encoder = rlp.Encoder.init(&short);
    encoder.raw(&.{0x79});
    const payload_length = 1 + 3 + rlp.length(Bloom.zero) + 1;
    encoder.list_header(payload_length);
    encoder.boolean(true);
    encoder.int(@as(u64, 21_000));
    rlp.encode(&encoder, Bloom.zero);
    encoder.list_header(0);
    try testing.expectError(error.UnexpectedEnd, Receipt.decode(encoder.written()));
}

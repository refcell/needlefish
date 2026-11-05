//! Denim BaseTime metadata deposit: the second transaction of every subsecond block
//! carries the millisecond part of the block timestamp to the `BaseTime` predeploy.
//! Mirrors base/base `crates/common/consensus/src/base_time.rs`. The Denim timestamp
//! schedule itself lives in `consensus/protocol/rollup_config.zig`; callers pass the
//! expected parts.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const tx_module = @import("tx.zig");
const predeploys = @import("predeploys.zig");
const B256 = primitives.B256;
const Deposit = tx_module.Deposit;
const Envelope = tx_module.Envelope;

/// `setTimestampMillisPart(uint16)` selector.
pub const selector = [4]u8{ 0x86, 0xbd, 0xf3, 0x94 };
pub const calldata_length = 4 + 32;
/// Denim block cadence.
pub const block_interval_ms: u16 = 200;
/// Gas limit of system deposits since Regolith.
pub const regolith_system_tx_gas: u64 = 1_000_000;
/// Deposit source domain of BaseTime deposits.
pub const source_domain: u64 = 3;

pub fn is_valid_millis_part(millis_part: u16) bool {
    return millis_part < 1_000 and millis_part % block_interval_ms == 0;
}

pub const DecodeError = error{
    MissingSelector,
    InvalidSelector,
    InvalidLength,
    NonZeroPadding,
    InvalidTimestampMillisPart,
};

pub fn encode_calldata(millis_part: u16) [calldata_length]u8 {
    assert(is_valid_millis_part(millis_part));
    var calldata: [calldata_length]u8 = @splat(0);
    calldata[0..4].* = selector;
    std.mem.writeInt(u16, calldata[34..36], millis_part, .big);
    return calldata;
}

pub fn decode_calldata(calldata: []const u8) DecodeError!u16 {
    if (calldata.len < 4) return error.MissingSelector;
    if (!std.mem.eql(u8, calldata[0..4], &selector)) return error.InvalidSelector;
    if (calldata.len != calldata_length) return error.InvalidLength;
    if (!std.mem.allEqual(u8, calldata[4..34], 0)) return error.NonZeroPadding;
    const millis_part = std.mem.readInt(u16, calldata[34..36], .big);
    if (!is_valid_millis_part(millis_part)) return error.InvalidTimestampMillisPart;
    return millis_part;
}

/// `keccak256(uint256(3) || keccak256(uint256(block_number)))`.
pub fn source_hash(block_number: u64) B256 {
    var inner: [32]u8 = @splat(0);
    std.mem.writeInt(u64, inner[24..32], block_number, .big);
    var outer: [64]u8 = @splat(0);
    std.mem.writeInt(u64, outer[24..32], source_domain, .big);
    outer[32..64].* = primitives.keccak256(&inner).bytes;
    return primitives.keccak256(&outer);
}

/// The metadata deposit for L2 block `block_number`. `calldata` must outlive the result.
pub fn deposit(block_number: u64, calldata: *const [calldata_length]u8) Deposit {
    return .{
        .source_hash = source_hash(block_number),
        .from = predeploys.depositor_account,
        .to = .{ .call = predeploys.base_time },
        .mint = 0,
        .value = 0,
        .gas_limit = regolith_system_tx_gas,
        .is_system_transaction = false,
        .input = calldata,
    };
}

pub const MetadataError = DecodeError || error{
    Missing,
    NotDeposit,
    InvalidSourceHash,
    InvalidSender,
    InvalidRecipient,
    NonZeroMint,
    NonZeroValue,
    InvalidGasLimit,
    SystemTransaction,
};

/// Checks every field of a BaseTime deposit and returns its millisecond part.
pub fn validate_deposit(tx: Deposit, block_number: u64) MetadataError!u16 {
    if (!tx.source_hash.eql(source_hash(block_number))) return error.InvalidSourceHash;
    if (!tx.from.eql(predeploys.depositor_account)) return error.InvalidSender;
    const to = tx.to.to() orelse return error.InvalidRecipient;
    if (!to.eql(predeploys.base_time)) return error.InvalidRecipient;
    if (tx.mint != 0) return error.NonZeroMint;
    if (tx.value != 0) return error.NonZeroValue;
    if (tx.gas_limit != regolith_system_tx_gas) return error.InvalidGasLimit;
    if (tx.is_system_transaction) return error.SystemTransaction;
    return decode_calldata(tx.input);
}

/// The millisecond part from a block's second transaction (index 1, after L1 info).
pub fn extract(second: ?Envelope, block_number: u64) MetadataError!u16 {
    const envelope = second orelse return error.Missing;
    if (envelope != .deposit) return error.NotDeposit;
    return validate_deposit(envelope.deposit, block_number);
}

/// Block timestamp in milliseconds: `timestamp * 1000 + millis_part`.
pub fn timestamp_ms(timestamp: u64, millis_part: u16) u64 {
    assert(millis_part < 1_000);
    return timestamp *| 1_000 +| millis_part;
}

pub const ScheduleError = MetadataError || error{
    InvalidTimestamp,
    InvalidTimestampMillisPart,
};

/// Validates a subsecond block against the schedule's expected timestamp parts.
pub fn validate_block_timestamp(
    second: ?Envelope,
    block_number: u64,
    timestamp: u64,
    expected_timestamp: u64,
    expected_millis_part: u16,
) ScheduleError!void {
    if (timestamp != expected_timestamp) return error.InvalidTimestamp;
    const millis_part = try extract(second, block_number);
    if (millis_part != expected_millis_part) return error.InvalidTimestampMillisPart;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "base time: calldata" {
    const calldata = encode_calldata(600);
    try testing.expectEqualSlices(u8, &selector, calldata[0..4]);
    try testing.expectEqual(@as(u16, 600), try decode_calldata(&calldata));
    try testing.expectError(error.MissingSelector, decode_calldata(calldata[0..3]));
    try testing.expectError(error.InvalidLength, decode_calldata(calldata[0..35]));
    var bad = calldata;
    bad[10] = 1;
    try testing.expectError(error.NonZeroPadding, decode_calldata(&bad));
    bad = calldata;
    bad[0] ^= 1;
    try testing.expectError(error.InvalidSelector, decode_calldata(&bad));
    bad = calldata;
    bad[35] = 100;
    try testing.expectError(error.InvalidTimestampMillisPart, decode_calldata(&bad));
    try testing.expect(!is_valid_millis_part(1_000));
    try testing.expect(is_valid_millis_part(0) and is_valid_millis_part(800));
}

test "base time: deposit round trip and validation" {
    const calldata = encode_calldata(400);
    const tx = deposit(77, &calldata);
    try testing.expectEqual(@as(u16, 400), try validate_deposit(tx, 77));
    try testing.expectError(error.InvalidSourceHash, validate_deposit(tx, 78));
    var bad = tx;
    bad.gas_limit = 1;
    try testing.expectError(error.InvalidGasLimit, validate_deposit(bad, 77));
    bad = tx;
    bad.is_system_transaction = true;
    try testing.expectError(error.SystemTransaction, validate_deposit(bad, 77));
    bad = tx;
    bad.to = .create;
    try testing.expectError(error.InvalidRecipient, validate_deposit(bad, 77));
    const envelope: Envelope = .{ .deposit = tx };
    try validate_block_timestamp(envelope, 77, 1_800_000_000, 1_800_000_000, 400);
    try testing.expectError(
        error.InvalidTimestampMillisPart,
        validate_block_timestamp(envelope, 77, 1_800_000_000, 1_800_000_000, 600),
    );
    try testing.expectError(error.Missing, extract(null, 77));
    try testing.expectEqual(@as(u64, 1_800_000_000_400), timestamp_ms(1_800_000_000, 400));
}

test "base time: source hash matches consensus deposits" {
    const deposits = @import("../../consensus/protocol/deposits.zig");
    for ([_]u64{ 0, 1, 1_000_000, std.math.maxInt(u64) }) |number| {
        try testing.expect(source_hash(number).eql(deposits.base_time_source_hash(number)));
    }
}

test "base time: seeded fuzz decode" {
    var prng = Prng.init(0xba5e);
    var calldata: [calldata_length]u8 = undefined;
    for (0..1000) |_| {
        calldata = encode_calldata(@intCast(prng.below(5) * 200));
        if (prng.chance(1, 2)) calldata[prng.below(calldata.len)] = prng.int(u8);
        const length = prng.range(0, calldata.len);
        const millis_part = decode_calldata(calldata[0..length]) catch continue;
        try testing.expect(is_valid_millis_part(millis_part));
    }
}

//! `DelayedWETH` calls (base/base `crates/proof/contracts/src/delayed_weth.rs`): the
//! withdrawal delay and a claimant's pending withdrawal.

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("abi.zig");

const Address = abi.Address;

pub const delay = abi.selector("delay()");
pub const withdrawals = abi.selector("withdrawals(address,address)");

pub const Withdrawal = struct { amount: u256, timestamp: u64 };

pub fn encode_withdrawals(out: []u8, owner: Address, guy: Address) abi.EncodeError![]u8 {
    return abi.encode_call(out, withdrawals, &.{ .{ .address = owner }, .{ .address = guy } });
}

pub fn decode_delay_seconds(data: []const u8) abi.DecodeError!u64 {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.uint(u64, 0);
}

/// `withdrawals()` returns `(uint256 amount, uint256 timestamp)`.
pub fn decode_withdrawal(data: []const u8) abi.DecodeError!Withdrawal {
    const decoder: abi.Decoder = .{ .data = data };
    const withdrawal: Withdrawal = .{
        .amount = try decoder.uint(u256, 0),
        .timestamp = try decoder.uint(u64, 1),
    };
    assert(data.len >= 64);
    return withdrawal;
}

/// When the withdrawal becomes claimable, or null when nothing is pending.
pub fn claimable_at(withdrawal: Withdrawal, delay_seconds: u64) ?u64 {
    if (withdrawal.timestamp == 0) return null;
    return std.math.add(u64, withdrawal.timestamp, delay_seconds) catch std.math.maxInt(u64);
}

const testing = std.testing;

test "delayed weth: calls and returns" {
    var buffer: [80]u8 = undefined;
    const calldata = try encode_withdrawals(&buffer, @splat(1), @splat(2));
    try testing.expectEqual(@as(usize, 68), calldata.len);
    var data: [64]u8 = @splat(0);
    data[31] = 5;
    data[63] = 100;
    const withdrawal = try decode_withdrawal(&data);
    try testing.expectEqual(@as(u256, 5), withdrawal.amount);
    try testing.expectEqual(@as(?u64, 160), claimable_at(withdrawal, 60));
    try testing.expectEqual(@as(?u64, null), claimable_at(.{ .amount = 0, .timestamp = 0 }, 60));
    try testing.expectEqual(@as(u64, 5), try decode_delay_seconds(&data));
}

test "delayed weth: fuzz the return decoders" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var data: [96]u8 = undefined;
            const length = smith.index(data.len);
            smith.bytes(data[0..length]);
            if (smith.index(2) == 0) @memset(data[0..@min(length, 24)], 0);
            if (decode_delay_seconds(data[0..length])) |_| {
                try testing.expect(length >= 32);
            } else |_| {}
            const withdrawal = decode_withdrawal(data[0..length]) catch return;
            try testing.expect(length >= 64);
            const delay_seconds = smith.value(u64);
            const at = claimable_at(withdrawal, delay_seconds) orelse {
                try testing.expectEqual(@as(u64, 0), withdrawal.timestamp);
                return;
            };
            try testing.expect(at >= withdrawal.timestamp);
        }
    }.one, .{ .iterations = 3000 });
}

//! eth_simulateV1 `traceTransfers`: the ERC-7528 transfer logs Nethermind's
//! `SimulateTxTracer` adds to a call's `logs`. A frame that moves value logs
//! `Transfer(from, to, value)` from 0xeeee…eeee at its start, before its own logs.
//! DELEGATECALL never moves value, and CALLCODE pays the caller itself. A SELFDESTRUCT
//! with a balance logs the payout. A reverted or halted frame drops its transfers along
//! with its logs. The synthetic logs appear only in the response. They are not added to the
//! receipt, the logs bloom or the receipts root.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");

const Address = [20]u8;

/// The transfers one call may log.
pub const items_max = 512;
/// Open frames: the EVM's depth limit, the top frame and a SELFDESTRUCT's pseudo-frame.
const frames_max = 1024 + 2;

/// ERC-7528's address for native ETH.
pub const eth_address: Address = @splat(0xee);
/// keccak256("Transfer(address,address,uint256)").
pub const transfer_topic: [32]u8 = .{
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
};

pub const Transfer = struct {
    from: Address,
    to: Address,
    value: u256,
    /// How many of the call's own logs come before it.
    position: u32,
};

const Start = struct { count: u32, logs: u32 };

pub const Transfers = struct {
    items: []Transfer,
    count: u32 = 0,
    /// The call's own logs so far (a failed frame drops its own, as the EVM does).
    logs: u32 = 0,
    starts: [frames_max]Start = undefined,
    depth: u32 = 0,
    /// More than `items_max` transfers: the call's logs cannot be served.
    full: bool = false,

    pub fn reset(transfers: *Transfers) void {
        transfers.count = 0;
        transfers.logs = 0;
        transfers.depth = 0;
        transfers.full = false;
    }

    pub fn tracer(transfers: *Transfers) evm.evm.Tracer {
        return .{ .context = transfers, .enter = enter, .exit = exit, .log = log };
    }

    fn enter(context: *anyopaque, frame: evm.evm.TraceFrame) void {
        const transfers: *Transfers = @ptrCast(@alignCast(context));
        assert(transfers.depth < frames_max);
        transfers.starts[transfers.depth] = .{ .count = transfers.count, .logs = transfers.logs };
        transfers.depth += 1;
        if (frame.kind == .delegatecall or frame.value == 0) return;
        if (transfers.count == transfers.items.len) {
            transfers.full = true;
            return;
        }
        transfers.items[transfers.count] = .{
            .from = frame.from,
            .to = if (frame.kind == .callcode) frame.from else frame.to,
            .value = frame.value,
            .position = transfers.logs,
        };
        transfers.count += 1;
    }

    fn exit(context: *anyopaque, outcome: evm.evm.Outcome) void {
        const transfers: *Transfers = @ptrCast(@alignCast(context));
        assert(transfers.depth > 0);
        transfers.depth -= 1;
        if (outcome.status == .success) return;
        const start = transfers.starts[transfers.depth];
        transfers.count = start.count;
        transfers.logs = start.logs;
    }

    fn log(
        context: *anyopaque,
        address: Address,
        topics: []const evm.B256,
        data: []const u8,
    ) void {
        _ = address;
        _ = topics;
        _ = data;
        const transfers: *Transfers = @ptrCast(@alignCast(context));
        transfers.logs += 1;
    }
};

/// The 32-byte words of a transfer's topics and data.
pub fn topics_of(transfer: *const Transfer) [3][32]u8 {
    var from: [32]u8 = @splat(0);
    var to: [32]u8 = @splat(0);
    from[12..].* = transfer.from;
    to[12..].* = transfer.to;
    return .{ transfer_topic, from, to };
}

test "simulate_transfers: frames log value, a failed frame drops its transfers" {
    var items: [4]Transfer = undefined;
    var transfers: Transfers = .{ .items = &items };
    const hooks = transfers.tracer();
    const a: Address = @splat(0xaa);
    const b: Address = @splat(0xbb);
    const frame: evm.evm.TraceFrame = .{
        .kind = .call,
        .from = a,
        .to = b,
        .value = 5,
        .gas = 0,
        .input = &.{},
        .depth = 0,
    };
    const success: evm.evm.Outcome = .{
        .status = .success,
        .exit = .stop,
        .gas_remaining = 0,
        .gas_refund = 0,
        .output = &.{},
    };
    var failure = success;
    failure.status = .revert;
    hooks.enter(hooks.context, frame);
    hooks.log(hooks.context, b, &.{}, &.{});
    // A reverted child: its transfer and log go.
    hooks.enter(hooks.context, frame);
    hooks.log(hooks.context, b, &.{}, &.{});
    hooks.exit(hooks.context, failure);
    // DELEGATECALL moves nothing; CALLCODE pays the caller.
    var delegated = frame;
    delegated.kind = .delegatecall;
    hooks.enter(hooks.context, delegated);
    hooks.exit(hooks.context, success);
    var code_call = frame;
    code_call.kind = .callcode;
    hooks.enter(hooks.context, code_call);
    hooks.exit(hooks.context, success);
    hooks.exit(hooks.context, success);
    try std.testing.expectEqual(@as(u32, 2), transfers.count);
    try std.testing.expectEqual(@as(u32, 1), transfers.logs);
    try std.testing.expectEqual(@as(u32, 0), items[0].position);
    try std.testing.expectEqualSlices(u8, &b, &items[0].to);
    try std.testing.expectEqual(@as(u32, 1), items[1].position);
    try std.testing.expectEqualSlices(u8, &a, &items[1].to);
    try std.testing.expectEqual(@as(u32, 0), transfers.depth);
    const words = topics_of(&items[0]);
    try std.testing.expectEqualSlices(u8, &a, words[1][12..]);
}

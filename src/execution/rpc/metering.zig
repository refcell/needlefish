//! `base_meterBlockByHash` / `base_meterBlockByNumber` (base/base `metering` crate):
//! re-executes a canonical block on its parent's state and reports how long sender
//! recovery and each transaction's execution took, in microseconds.
//!
//! The parent state is read through `HistoryDatabase` (the history window bounds which
//! blocks can be metered) and every change is discarded. Times come from the service's
//! monotonic clock (`Api.clock`); without one they are zero. `stateRootTimeUs` is zero:
//! the root is not recomputed over historical reads. `totalTimeUs` is the sum of the parts.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;
const Executor = node.executor.Executor;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "base_meterBlockByHash", .handler = meter_by_hash },
    .{ .name = "base_meterBlockByNumber", .handler = meter_by_number },
};

fn meter_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    try call.params.finish();
    try meter(api, call, hash);
}

fn meter_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    const hash = eth.resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.fail(rpc.code.server_error, "block not found"),
        else => return err,
    };
    try meter(api, call, hash);
}

fn zero_ns(_: *anyopaque) u64 {
    return 0;
}

var zero_context: u8 = 0;
const zero_clock: Executor.Clock = .{ .context = &zero_context, .now_ns = zero_ns };

/// The per-transaction buffers at the head of the scratch (the proofs sit at its tail).
const Buffers = struct { ns: []u64, gas: []u64 };

fn carve(api: *Api, count: usize) ?Buffers {
    const tail = eth.proof_tail_offset(api) orelse return null;
    const bytes = count * 2 * @sizeOf(u64);
    const start = std.mem.alignForward(usize, @intFromPtr(api.scratch.ptr), @alignOf(u64)) -
        @intFromPtr(api.scratch.ptr);
    if (start + bytes > tail) return null;
    const words: [*]u64 = @ptrCast(@alignCast(api.scratch[start..].ptr));
    return .{ .ns = words[0..count], .gas = words[count .. 2 * count] };
}

fn meter(api: *Api, call: *Call, hash: Hash) HandlerError!void {
    const chain = api.chain;
    var stored = chain.record(hash) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
    const header = stored.header;
    if (header.number == 0) return call.fail(rpc.code.invalid_params, "genesis has no parent");
    var count: usize = 0;
    while (!stored.transactions.is_empty()) : (count += 1) {
        assert(count < chain.transactions_buffer.len); // Stored blocks fit the executor.
        chain.transactions_buffer[count] = stored.transactions.bytes() catch unreachable;
    }
    const transactions = chain.transactions_buffer[0..count];
    const buffers = carve(api, count) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const offset = eth.proof_tail_offset(api).?; // Checked by `carve`.
    const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
    var history: node.HistoryDatabase = .{
        .chain = chain,
        .hash = header.parent_hash.bytes,
        .number = header.number - 1,
        .account_proof = &proofs.account,
        .storage_proof = &proofs.storage,
    };
    const executor = chain.executor;
    const session = executor.session_begin(history.database());
    defer executor.session_end(session);
    const env = node.chain.env_of(&header);
    const clock = api.clock orelse zero_clock;
    const ns = buffers.ns;
    const gas = buffers.gas;
    const metered = executor.meter_block(&env, transactions, clock, ns, gas) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return call.fail(rpc.code.server_error, @errorName(err));
    };
    if (metered.gas_used != header.gas_used) {
        return call.fail(rpc.code.internal_error, "re-execution diverged from the block");
    }
    try write(call.writer, hash, header.number, metered, transactions, buffers);
}

fn write(
    w: *json.Writer,
    hash: Hash,
    number: u64,
    metered: Executor.Metered,
    transactions: []const []const u8,
    buffers: Buffers,
) json.Writer.WriteError!void {
    const recovery_us = metered.signer_recovery_ns / std.time.ns_per_us;
    const execution_us = metered.execution_ns / std.time.ns_per_us;
    try w.begin_object();
    try w.key("blockHash");
    try w.data(&hash);
    try w.key("blockNumber");
    try w.integer(number);
    const totals = [_]struct { []const u8, u64 }{
        .{ "signerRecoveryTimeUs", recovery_us },
        .{ "executionTimeUs", execution_us },
        .{ "stateRootTimeUs", 0 },
        .{ "totalTimeUs", recovery_us + execution_us },
    };
    for (totals) |total| {
        try w.key(total[0]);
        try w.integer(total[1]);
    }
    try w.key("transactions");
    try w.begin_array();
    for (transactions, buffers.ns[0..transactions.len], buffers.gas[0..transactions.len]) |
        raw,
        ns,
        gas,
    | {
        try w.begin_object();
        try w.key("txHash");
        try w.data(&primitives.keccak256(raw).bytes);
        try w.key("gasUsed");
        try w.integer(gas);
        try w.key("executionTimeUs");
        try w.integer(ns / std.time.ns_per_us);
        try w.end_object();
    }
    try w.end_array();
    try w.end_object();
}

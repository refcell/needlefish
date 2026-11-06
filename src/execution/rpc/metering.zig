//! `base_meterBlockByHash` / `base_meterBlockByNumber` (base/base `metering` crate):
//! re-executes a canonical block on its parent's state and reports how long sender
//! recovery and each transaction's execution took, in microseconds.
//!
//! The parent state is read through `HistoryDatabase` (the history window bounds which
//! blocks can be metered) and every change is discarded. Times come from the service's
//! monotonic clock (`Api.clock`); without one they are zero. `stateRootTimeUs` is zero:
//! the root is not recomputed over historical reads. `totalTimeUs` is the sum of the parts.
//!
//! `base_meterBundle({txs})` runs raw transactions on the head state in the next block
//! (base fee at most 5 Mwei, each sender starting at its first transaction's nonce) and
//! reports each one's gas, fees (`gasUsed * maxFeePerGas`, all counted as coinbase diff, as
//! base/base) and time. Not ported: opcode gas metering and the BaseTime update before the
//! first transaction.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
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
    .{ .name = "base_meterBundle", .handler = meter_bundle },
};

/// Transactions per metered bundle.
pub const bundle_transactions_max = 256;
/// base/base caps the simulated base fee at 5 Mwei.
pub const bundle_base_fee_max: u64 = 5_000_000;

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

const Bundle = struct {
    transactions: [bundle_transactions_max][]const u8 = undefined,
    count: u32 = 0,
};

/// Parses `{"txs":[raw, ...]}`; the transactions decode into `space`.
fn parse_bundle(raw: []const u8, space: []u8, bundle: *Bundle) HandlerError!void {
    var scanner = json.Scanner.init(raw);
    if ((scanner.next() catch return error.InvalidParams).tag != .object_begin) {
        return error.InvalidParams;
    }
    var used: usize = 0;
    var found = false;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        const value = scanner.next() catch return error.InvalidParams;
        if (!std.mem.eql(u8, name.bytes, "txs")) return error.InvalidParams;
        if (value.tag != .array_begin) return error.InvalidParams;
        found = true;
        while (true) {
            const item = scanner.next() catch return error.InvalidParams;
            if (item.tag == .array_end) break;
            if (item.tag != .string) return error.InvalidParams;
            if (bundle.count == bundle_transactions_max) return error.InvalidParams;
            const tx = json.parse_data(item.bytes, space[used..]) catch return error.InvalidParams;
            if (tx.len == 0 or tx[0] == 0x7e) return error.InvalidParams;
            used += tx.len;
            bundle.transactions[bundle.count] = tx;
            bundle.count += 1;
        }
    }
    if (!found) return error.InvalidParams;
    assert(used <= space.len);
}

fn meter_bundle(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    var bundle: Bundle = .{};
    const half = api.scratch.len / 2;
    try parse_bundle(raw, api.scratch[0..half], &bundle);
    const transactions = bundle.transactions[0..bundle.count];
    var ns: [bundle_transactions_max]u64 = undefined;
    var gas: [bundle_transactions_max]u64 = undefined;
    const chain = api.chain;
    chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const header = eth.head_header(api);
    var env = node.chain.env_of(&header);
    env.number += 1;
    env.timestamp += 1;
    env.parent_hash = header.hash().bytes;
    env.base_fee = @min(env.base_fee, bundle_base_fee_max);
    const executor = chain.executor;
    const session = executor.session_begin(null);
    defer executor.session_end(session);
    const clock = api.clock orelse zero_clock;
    _ = executor.meter_bundle(&env, transactions, clock, &ns, &gas) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    const senders = executor.senders[0..transactions.len];
    try write_bundle(call.writer, header.number, transactions, senders, &ns, &gas);
}

fn field_u256(w: *json.Writer, name: []const u8, value: u256) json.Writer.WriteError!void {
    try w.key(name);
    try w.quantity(value);
}

fn write_bundle(
    w: *json.Writer,
    state_block: u64,
    transactions: []const []const u8,
    senders: []const ?primitives.Address,
    ns: []const u64,
    gas: []const u64,
) json.Writer.WriteError!void {
    var hashes: [bundle_transactions_max * 32]u8 = undefined;
    var total_gas: u64 = 0;
    var total_fees: u256 = 0;
    var total_us: u64 = 0;
    for (transactions, 0..) |raw, index| {
        hashes[index * 32 ..][0..32].* = primitives.keccak256(raw).bytes;
        const envelope = consensus.Envelope.decode(raw) catch unreachable; // Executed.
        total_gas += gas[index];
        total_fees += @as(u256, gas[index]) * envelope.max_fee_per_gas();
        total_us += ns[index] / std.time.ns_per_us;
    }
    try w.begin_object();
    try field_u256(w, "bundleGasPrice", if (total_gas > 0) total_fees / total_gas else 0);
    try w.key("bundleHash");
    try w.data(&primitives.keccak256(hashes[0 .. transactions.len * 32]).bytes);
    try field_u256(w, "coinbaseDiff", total_fees);
    try field_u256(w, "ethSentToCoinbase", 0);
    try field_u256(w, "gasFees", total_fees);
    try w.key("results");
    try w.begin_array();
    for (transactions, senders, ns[0..transactions.len], gas[0..transactions.len]) |
        raw,
        sender,
        time_ns,
        used,
    | {
        try write_result(w, raw, sender, time_ns, used);
    }
    try w.end_array();
    try w.key("stateBlockNumber");
    try w.integer(state_block);
    try w.key("totalGasUsed");
    try w.integer(total_gas);
    try w.key("totalExecutionTimeUs");
    try w.integer(total_us);
    try w.end_object();
}

fn write_result(
    w: *json.Writer,
    raw: []const u8,
    sender: ?primitives.Address,
    time_ns: u64,
    used: u64,
) json.Writer.WriteError!void {
    const envelope = consensus.Envelope.decode(raw) catch unreachable; // Executed.
    const price = envelope.max_fee_per_gas();
    const fees = @as(u256, used) * price;
    try w.begin_object();
    try field_u256(w, "coinbaseDiff", fees);
    try field_u256(w, "ethSentToCoinbase", 0);
    try w.key("fromAddress");
    try w.data(&(sender orelse primitives.Address.zero).bytes);
    try field_u256(w, "gasFees", fees);
    try field_u256(w, "gasPrice", price);
    try w.key("gasUsed");
    try w.integer(used);
    try w.key("toAddress");
    if (envelope.kind().to()) |to| try w.data(&to.bytes) else try w.null_value();
    try w.key("txHash");
    try w.data(&primitives.keccak256(raw).bytes);
    try field_u256(w, "value", envelope.value());
    try w.key("executionTimeUs");
    try w.integer(time_ns / std.time.ns_per_us);
    try w.end_object();
}

//! `eth_simulateV1(options, block?)` (execution-apis): runs `blockStateCalls`, a list of
//! simulated blocks each with optional `blockOverrides`, `stateOverrides` and `calls`, on
//! top of a base block, carrying state across calls and blocks. Nothing is committed.
//!
//! Supported: block overrides `number`, `time`, `gasLimit`, `feeRecipient`, `prevRandao`
//! (numbers and times must increase; defaults are parent + 1 and parent time + 12);
//! state overrides `balance`, `nonce`, `code`, `state` (replaces all storage) and
//! `stateDiff`. Calls run fee-free (gas price and base fee zero, as without
//! `validation`), with the block's remaining gas by default. Each block reports
//! `number`, `timestamp`, `gasLimit`, `gasUsed`, `baseFeePerGas`, `miner` and `calls`
//! (`returnData`, `logs`, `gasUsed`, `status`, `error` for a revert (code 3, with data) or
//! a halt (-32015)). Not supported: `validation: true`, `traceTransfers`,
//! `baseFeePerGas` overrides, `movePrecompileToAddress`; no block hashes or roots.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");
const state_view = @import("state_view.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Executor = node.executor.Executor;
const BlockEnv = node.executor.BlockEnv;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_simulateV1", .handler = simulate_v1 },
};

pub const blocks_max = 16;
pub const calls_max = 256;
pub const overrides_max = 64;
pub const slots_max = 256;
const timestamp_increment = 12;
/// execution-apis error codes.
const code_block_number = -38020;
const code_block_timestamp = -38021;
const code_block_gas = -38015;
const code_vm_error = -32015;

/// Iterates the elements of a JSON array as raw value slices.
const Elements = struct {
    scanner: json.Scanner,
    count: u32 = 0,

    fn init(raw: []const u8) HandlerError!Elements {
        var elements: Elements = .{ .scanner = json.Scanner.init(raw) };
        const first = elements.scanner.next() catch return error.InvalidParams;
        if (first.tag != .array_begin) return error.InvalidParams;
        return elements;
    }

    fn next(elements: *Elements, max: u32) HandlerError!?[]const u8 {
        const before = elements.scanner.offset();
        const token = elements.scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) return null;
        if (elements.count == max) return error.InvalidParams;
        elements.count += 1;
        elements.scanner.skip(token) catch return error.InvalidParams;
        const text = elements.scanner.input[before..elements.scanner.offset()];
        return std.mem.trimStart(u8, text, " \t\r\n,");
    }
};

/// Iterates the members of a JSON object as (key, raw value) pairs.
const Members = struct {
    scanner: json.Scanner,
    count: u32 = 0,

    const Member = struct { key: []const u8, value: []const u8 };

    fn init(raw: []const u8) HandlerError!Members {
        var members: Members = .{ .scanner = json.Scanner.init(raw) };
        const first = members.scanner.next() catch return error.InvalidParams;
        if (first.tag != .object_begin) return error.InvalidParams;
        return members;
    }

    fn next(members: *Members, max: u32) HandlerError!?Member {
        const key = members.scanner.next() catch return error.InvalidParams;
        if (key.tag == .object_end) return null;
        if (members.count == max or key.escaped) return error.InvalidParams;
        members.count += 1;
        const before = members.scanner.offset();
        const token = members.scanner.next() catch return error.InvalidParams;
        members.scanner.skip(token) catch return error.InvalidParams;
        const text = members.scanner.input[before..members.scanner.offset()];
        return .{ .key = key.bytes, .value = std.mem.trim(u8, text, " \t\r\n:") };
    }
};

fn string_of(raw: []const u8) HandlerError![]const u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    return raw[1 .. raw.len - 1];
}

fn quantity_of(comptime T: type, raw: []const u8) HandlerError!T {
    return json.parse_quantity(T, try string_of(raw)) catch error.InvalidParams;
}

fn simulate_v1(api: *Api, call: *Call) HandlerError!void {
    const options = try call.params.raw();
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    try call.params.finish();
    if (try json_true(options, "validation")) {
        return call.fail(rpc.code.invalid_params, "validation is not supported");
    }
    const blocks = (json.find_path(options, &.{"blockStateCalls"}) catch null) orelse
        return error.InvalidParams;
    const space = switch (view) {
        .head => api.scratch,
        .historical => api.scratch[0 .. eth.proof_tail_offset(api) orelse {
            return call.fail(rpc.code.internal_error, "proof scratch too small");
        }],
    };
    const header = eth.view_header(api, view);
    const executor = api.chain.executor;
    var history: node.HistoryDatabase = undefined;
    const database: ?evm.state.Database = switch (view) {
        .head => blk: {
            api.chain.ensure_head_state() catch {
                return call.fail(rpc.code.internal_error, "head state unavailable");
            };
            break :blk null;
        },
        .historical => |block| blk: {
            const offset = eth.proof_tail_offset(api).?; // Checked above.
            const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
            history = .{
                .chain = api.chain,
                .hash = block.hash,
                .number = block.number,
                .account_proof = &proofs.account,
                .storage_proof = &proofs.storage,
            };
            break :blk history.database();
        },
    };
    const session = executor.session_begin(database);
    defer executor.session_end(session);
    var parent = node.chain.env_of(&header);
    parent.base_fee = 0;
    parent.parent_beacon_block_root = parent.parent_beacon_block_root orelse @splat(0);
    var list = try Elements.init(blocks);
    const w = call.writer;
    try w.begin_array();
    while (try list.next(blocks_max)) |block_raw| {
        parent = simulate_block(api, call, space, &parent, block_raw) catch |err| {
            if (database != null) if (history.failure) |failure| {
                return eth_proof.fail_history(call, failure);
            };
            return err;
        };
    }
    try w.end_array();
}

fn json_true(raw: []const u8, name: []const u8) HandlerError!bool {
    const value = (json.find_path(raw, &.{name}) catch return error.InvalidParams) orelse
        return false;
    return std.mem.eql(u8, value, "true");
}

/// Runs one simulated block on top of `parent` and writes it; returns its environment.
fn simulate_block(
    api: *Api,
    call: *Call,
    space: []u8,
    parent: *const BlockEnv,
    raw: []const u8,
) HandlerError!BlockEnv {
    var env = parent.*;
    env.number = parent.number + 1;
    env.timestamp = parent.timestamp + timestamp_increment;
    if (json.find_path(raw, &.{"blockOverrides"}) catch return error.InvalidParams) |o| {
        try apply_block_overrides(call, &env, o);
    }
    if (env.number <= parent.number) {
        return call.fail(code_block_number, "block numbers must increase");
    }
    if (env.timestamp <= parent.timestamp) {
        return call.fail(code_block_timestamp, "block timestamps must increase");
    }
    const executor = api.chain.executor;
    if (json.find_path(raw, &.{"stateOverrides"}) catch return error.InvalidParams) |o| {
        apply_state_overrides(executor.state, space, o) catch |err| switch (err) {
            error.InvalidParams => return error.InvalidParams,
            else => return call.fail(rpc.code.internal_error, @errorName(err)),
        };
    }
    const w = call.writer;
    try w.begin_object();
    try w.key("number");
    try w.quantity(env.number);
    try w.key("timestamp");
    try w.quantity(env.timestamp);
    try w.key("gasLimit");
    try w.quantity(env.gas_limit);
    try w.key("baseFeePerGas");
    try w.quantity(env.base_fee);
    try w.key("miner");
    try w.data(&env.beneficiary);
    try w.key("calls");
    try w.begin_array();
    var gas_used: u64 = 0;
    var log_index: u64 = 0;
    if (json.find_path(raw, &.{"calls"}) catch return error.InvalidParams) |calls| {
        var list = try Elements.init(calls);
        var index: u64 = 0;
        while (try list.next(calls_max)) |call_raw| : (index += 1) {
            const position: Position = .{ .block = env.number, .index = index };
            const used =
                try run_call(api, call, space, &env, gas_used, call_raw, position, &log_index);
            gas_used += used;
            assert(gas_used <= env.gas_limit);
        }
    }
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(gas_used);
    try w.end_object();
    return env;
}

const Position = struct { block: u64, index: u64 };

pub fn apply_block_overrides(call: *Call, env: *BlockEnv, raw: []const u8) HandlerError!void {
    var members = try Members.init(raw);
    while (try members.next(16)) |member| {
        if (std.mem.eql(u8, member.value, "null")) continue;
        if (std.mem.eql(u8, member.key, "number")) {
            env.number = try quantity_of(u64, member.value);
        } else if (std.mem.eql(u8, member.key, "time")) {
            env.timestamp = try quantity_of(u64, member.value);
        } else if (std.mem.eql(u8, member.key, "gasLimit")) {
            env.gas_limit = try quantity_of(u64, member.value);
        } else if (std.mem.eql(u8, member.key, "feeRecipient")) {
            env.beneficiary = json.parse_fixed(20, try string_of(member.value)) catch
                return error.InvalidParams;
        } else if (std.mem.eql(u8, member.key, "prevRandao")) {
            env.prev_randao = json.parse_fixed(32, try string_of(member.value)) catch
                return error.InvalidParams;
        } else {
            return call.fail(rpc.code.invalid_params, "unsupported block override");
        }
    }
}

pub const OverrideError = HandlerError || evm.state.Error;

pub fn apply_state_overrides(state: *evm.State, space: []u8, raw: []const u8) OverrideError!void {
    var accounts = try Members.init(raw);
    while (try accounts.next(overrides_max)) |entry| {
        const text = entry.key;
        if (text.len != 42) return error.InvalidParams;
        const address = json.parse_fixed(20, text) catch return error.InvalidParams;
        const account = try state.load(address);
        var fields = try Members.init(entry.value);
        while (try fields.next(8)) |field| {
            if (std.mem.eql(u8, field.value, "null")) continue;
            try apply_account_field(state, account, space, field);
        }
    }
}

fn apply_account_field(
    state: *evm.State,
    account: *evm.state.Account,
    space: []u8,
    field: Members.Member,
) OverrideError!void {
    if (std.mem.eql(u8, field.key, "balance")) {
        try state.set_balance(account, try quantity_of(u256, field.value));
    } else if (std.mem.eql(u8, field.key, "nonce")) {
        try state.set_nonce(account, try quantity_of(u64, field.value));
    } else if (std.mem.eql(u8, field.key, "code")) {
        const code = json.parse_data(try string_of(field.value), space) catch
            return error.InvalidParams;
        try state.replace_code(account, code);
    } else if (std.mem.eql(u8, field.key, "state")) {
        // Fresh storage incarnation: database slots read as zero (never committed).
        account.storage_epoch += 1;
        try write_slots(state, account, field.value);
    } else if (std.mem.eql(u8, field.key, "stateDiff")) {
        try write_slots(state, account, field.value);
    } else return error.InvalidParams;
}

fn write_slots(state: *evm.State, account: *evm.state.Account, raw: []const u8) OverrideError!void {
    var slots = try Members.init(raw);
    while (try slots.next(slots_max)) |slot| {
        const key = json.parse_fixed(32, slot.key) catch return error.InvalidParams;
        const value = json.parse_fixed(32, try string_of(slot.value)) catch
            return error.InvalidParams;
        const access = try state.storage_access(account, std.mem.readInt(u256, &key, .big));
        try state.storage_write(account, access.slot, std.mem.readInt(u256, &value, .big));
    }
}

/// Runs and writes one call; returns its gas used.
fn run_call(
    api: *Api,
    call: *Call,
    space: []u8,
    env: *const BlockEnv,
    gas_used: u64,
    raw: []const u8,
    position: Position,
    log_index: *u64,
) HandlerError!u64 {
    var message = try eth.parse_call(space, raw);
    const remaining = env.gas_limit - gas_used;
    const w = call.writer;
    if ((message.gas orelse remaining) > remaining or remaining == 0) {
        try write_failed(w, code_block_gas, "block gas limit reached", &.{});
        return 0;
    }
    message.gas = message.gas orelse @min(remaining, api.chain.executor.default_call_gas(env));
    const result = api.chain.executor.session_call(env, message) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    const executed = switch (result) {
        .invalid => |reason| {
            try write_failed(w, rpc.code.server_error, @tagName(reason), &.{});
            return 0;
        },
        .executed => |executed| executed,
    };
    try w.begin_object();
    try w.key("returnData");
    try w.data(executed.output);
    try w.key("logs");
    try w.begin_array();
    for (executed.logs) |item| {
        try write_log(w, item, position, log_index.*);
        log_index.* += 1;
    }
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(executed.gas_used);
    try w.key("status");
    try w.quantity(@as(u64, @intFromBool(executed.status == .success)));
    switch (executed.status) {
        .success => {},
        .revert => try write_error(w, 3, "execution reverted", executed.output),
        .halt => try write_error(w, code_vm_error, "vm execution error", &.{}),
    }
    try w.end_object();
    return executed.gas_used;
}

fn write_failed(
    w: *json.Writer,
    code: i32,
    message: []const u8,
    data: []const u8,
) HandlerError!void {
    try w.begin_object();
    try w.key("returnData");
    try w.data(&.{});
    try w.key("logs");
    try w.begin_array();
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(@as(u64, 0));
    try w.key("status");
    try w.quantity(@as(u64, 0));
    try write_error(w, code, message, data);
    try w.end_object();
}

fn write_error(
    w: *json.Writer,
    code: i32,
    message: []const u8,
    data: []const u8,
) HandlerError!void {
    try w.key("error");
    try w.begin_object();
    try w.key("code");
    try w.integer(code);
    try w.key("message");
    try w.string(message);
    if (data.len > 0) {
        try w.key("data");
        try w.data(data);
    }
    try w.end_object();
}

fn write_log(
    w: *json.Writer,
    item: evm.state.Log,
    position: Position,
    index: u64,
) HandlerError!void {
    try w.begin_object();
    try w.key("address");
    try w.data(&item.address);
    try w.key("topics");
    try w.begin_array();
    for (item.topic_slice()) |topic| try w.data(&topic);
    try w.end_array();
    try w.key("data");
    try w.data(item.data);
    try w.key("blockNumber");
    try w.quantity(position.block);
    try w.key("transactionIndex");
    try w.quantity(position.index);
    try w.key("logIndex");
    try w.quantity(index);
    try w.key("removed");
    try w.boolean(false);
    try w.end_object();
}

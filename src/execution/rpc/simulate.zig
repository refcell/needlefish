//! `eth_simulateV1(options, block?)` (execution-apis): runs `blockStateCalls`, a list of
//! simulated blocks each with optional `blockOverrides`, `stateOverrides` and `calls`, on
//! top of a base block, carrying state across calls and blocks. Nothing is committed.
//!
//! Supported: the block overrides of `apply_block_overrides` (Nethermind's `BlockOverride`
//! fields, any case; an unknown key is refused; overridden numbers and times must
//! increase; defaults are parent + 1 and parent time + 12, saturating; the base fee is
//! zero unless overridden);
//! state overrides `balance`, `nonce`, `code`, `state` (replaces all storage) and
//! `stateDiff`. Calls run fee-free (gas price and base fee zero, as without
//! `validation`), with the block's remaining gas by default. Each block is the full block
//! base/base assembles (`simulate_block.zig`: header, hash, transactions, withdrawals) plus
//! `calls` (`returnData`, `logs`, `gasUsed`, `maxUsedGas`, `status`, `error` for a revert
//! (code 3, reth's "execution reverted: <reason>", with data, "0x" when empty) or a halt
//! (-32015, reth's halt text)); `returnFullTransactions` writes transaction objects;
//! `traceTransfers` adds Nethermind's ERC-7528 transfer logs to the calls' logs
//! (`simulate_transfers.zig`). Not supported: `movePrecompileToAddress`.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");
const state_view = @import("state_view.zig");
const call_error = @import("call_error.zig");
const call_fees = @import("call_fees.zig");
const chainspec = @import("../chainspec/root.zig");
const schedule_module = @import("simulate_schedule.zig");
const assembly = @import("simulate_block.zig");
const transfers_module = @import("simulate_transfers.zig");
const primitives = @import("../../common/primitives/root.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Executor = node.executor.Executor;
const BlockEnv = node.executor.BlockEnv;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_simulateV1", .handler = simulate_v1 },
};

pub const blocks_max = schedule_module.blocks_max;
pub const calls_max = assembly.calls_max;
pub const overrides_max = 64;
pub const slots_max = 256;
/// execution-apis error codes (reth `EthSimulateError::error_code`, `SIMULATE_*_CODE`).
const code_vm_error = -32015;
const code_nonce_too_low = -38010;
const code_nonce_too_high = -38011;
const code_base_fee_too_low = -38012;
const code_intrinsic_gas = -38013;
const code_insufficient_funds = -38014;
const code_block_gas = -38015;
const code_initcode_size = -38025;

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

/// One eth_simulateV1 request: what every block and call of it shares.
const Simulation = struct {
    api: *Api,
    call: *Call,
    /// Call data and override code of the call running; error texts once it ran.
    space: []u8,
    /// The encoded transactions and receipts of the block running.
    block_space: []u8,
    /// `returnFullTransactions`: blocks list transaction objects, not hashes.
    full_transactions: bool,
    /// The base block's beacon root, which every simulated block repeats (base/base
    /// `BaseNextBlockEnvAttributes::build_pending_env` copies the parent's).
    parent_beacon_block_root: ?primitives.B256,
    /// `validation: true`: fees, balances and nonces are checked and fees charged.
    validation: bool,
    /// The base block's extra data (its EIP-1559 parameters, for validated base fees).
    extra_data: []const u8,
    history: ?*node.HistoryDatabase,
    /// What is left of the RPC gas cap, shared by every call of the request (reth
    /// `remaining_call_gas_limit`).
    gas_cap_remaining: u64 = eth.rpc_gas_cap,
    /// `traceTransfers`: the running call's transfer logs.
    transfers: ?*transfers_module.Transfers = null,
};

/// reth `EthSimulateError::GasLimitReached` (-38026, as `TooManyBlocks`).
const code_gas_limit_reached = schedule_module.code_too_many_blocks;
const gas_limit_reached = "Client adjustable limit reached";

/// The simulated block a block builds on.
const Parent = struct {
    env: BlockEnv,
    hash: primitives.B256,
    gas_used: u64,
    blob_gas_used: u64,
};

fn simulate_v1(api: *Api, call: *Call) HandlerError!void {
    const options = try call.params.raw();
    const blocks = (json.find_path(options, &.{"blockStateCalls"}) catch null) orelse
        return error.InvalidParams;
    try check_override_keys(call, blocks);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    try call.params.finish();
    try check_count(call, blocks);
    const scratch = try scratch_of(api, call, view);
    var transfers: transfers_module.Transfers = .{ .items = &.{} };
    const traced: ?*transfers_module.Transfers =
        if (try json_true(options, "traceTransfers")) &transfers else null;
    const space = try call_space(call, scratch, traced);
    const header = eth.view_header(api, view);
    const chain = api.chain;
    var schedule = schedule_module.Schedule.init(
        chain.genesis_number,
        chain.genesis_timestamp,
        api.spec.upgrades[@backingInt(chainspec.Upgrade.denim)],
        header.number,
        header.timestamp,
    );
    try precheck_blocks(call, space, blocks, header.gas_limit, api.spec.chain_id);
    // base/base orders and bounds every block before running any.
    try plan_blocks(call, space, schedule, blocks);
    var history: node.HistoryDatabase = undefined;
    var simulation: Simulation = .{
        .api = api,
        .call = call,
        .space = space,
        .block_space = scratch[scratch.len / 2 ..],
        .full_transactions = try json_true(options, "returnFullTransactions"),
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .validation = try json_true(options, "validation"),
        .extra_data = header.extra_data,
        .history = null,
        .transfers = traced,
    };
    const database: ?evm.state.Database = switch (view) {
        .head => blk: {
            chain.ensure_head_state() catch {
                return call.fail(rpc.code.internal_error, "head state unavailable");
            };
            break :blk null;
        },
        .historical => |block| blk: {
            const offset = eth.proof_tail_offset(api).?; // Checked above.
            const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
            history = .{
                .chain = chain,
                .hash = block.hash,
                .number = block.number,
                .account_proof = &proofs.account,
                .storage_proof = &proofs.storage,
            };
            simulation.history = &history;
            break :blk history.database();
        },
    };
    const session = chain.executor.session_begin(database);
    defer chain.executor.session_end(session);
    var parent: Parent = .{
        .env = node.chain.env_of(&header),
        .hash = header.hash(),
        .gas_used = header.gas_used,
        .blob_gas_used = header.blob_gas_used orelse 0,
    };
    parent.env.parent_beacon_block_root = parent.env.parent_beacon_block_root orelse @splat(0);
    try run_blocks(&simulation, &schedule, &parent, blocks);
}

/// The calls' scratch: the first half (the block being assembled takes the second), less
/// the `traceTransfers` buffer at its tail when `transfers` is given.
fn call_space(
    call: *Call,
    scratch: []u8,
    transfers: ?*transfers_module.Transfers,
) HandlerError![]u8 {
    const half = scratch.len / 2;
    const traced = transfers orelse return scratch[0..half];
    const Transfer = transfers_module.Transfer;
    const items_max = transfers_module.items_max;
    const transfer_bytes = items_max * @sizeOf(Transfer) + @alignOf(Transfer);
    if (half < 2 * transfer_bytes) return call.fail(rpc.code.internal_error, "scratch too small");
    var used: usize = 0;
    const tail = scratch[half - transfer_bytes .. half];
    // Proof: the tail holds `items_max` transfers past any alignment.
    traced.items = @import("trace.zig").carve(Transfer, tail, &used, items_max).?;
    assert(traced.items.len == items_max);
    return scratch[0 .. half - transfer_bytes];
}

/// The scratch a simulation may use: all of it at the head, else what the proofs leave.
fn scratch_of(api: *Api, call: *Call, view: state_view.View) HandlerError![]u8 {
    const scratch = switch (view) {
        .head => api.scratch,
        .historical => api.scratch[0 .. eth.proof_tail_offset(api) orelse {
            return call.fail(rpc.code.internal_error, "proof scratch too small");
        }],
    };
    assert(scratch.len <= api.scratch.len);
    return scratch;
}

fn check_count(call: *Call, blocks: []const u8) HandlerError!void {
    const count = try count_blocks(blocks);
    if (count > blocks_max) {
        return call.fail(schedule_module.code_too_many_blocks, "too many blocks");
    }
    if (count == 0) return call.fail(rpc.code.invalid_params, "calls are empty.");
    assert(count > 0 and count <= blocks_max);
}

fn count_blocks(blocks: []const u8) HandlerError!u64 {
    var list = try Elements.init(blocks);
    var count: u64 = 0;
    while (try list.next(4 * blocks_max)) |_| count += 1;
    return count;
}

/// Nethermind's (OP) checks over every block before it runs any, in block order: a gas
/// limit override above both the base block's limit and the RPC gas cap (base/base's
/// client limit), an account override with both `state` and `stateDiff`, and a call whose
/// priority fee exceeds its fee cap (revm's `validate_env`, a missing cap read as 0).
fn precheck_blocks(
    call: *Call,
    buffer: []u8,
    blocks: []const u8,
    base_gas_limit: u64,
    chain_id: u64,
) HandlerError!void {
    var list = try Elements.init(blocks);
    while (try list.next(blocks_max)) |block_raw| {
        if (try block_overrides(block_raw)) |raw| {
            const gas_limit = json.find_member_ignore_case(raw, "gasLimit") catch
                return error.InvalidParams;
            if (gas_limit) |text| if (!std.mem.eql(u8, text, "null")) {
                const limit = try quantity_of(u64, text);
                if (limit > base_gas_limit and limit > eth.rpc_gas_cap) {
                    return call.fail(code_gas_limit_reached, gas_limit_reached);
                }
            };
        }
        const overrides = json.find_path(block_raw, &.{"stateOverrides"}) catch
            return error.InvalidParams;
        if (overrides) |raw| if (!std.mem.eql(u8, raw, "null")) {
            if (try both_state_and_diff(raw)) |address| {
                return call.fail(rpc.code.invalid_params, both_state_message(buffer, address));
            }
        };
        try precheck_fee_caps(call, block_raw);
        try precheck_chain_ids(call, block_raw, chain_id);
    }
}

/// The calls' chain ids, checked block by block before any block runs: Nethermind refuses
/// a call for another chain (-32000 "invalid chain ID") ahead of a later block's limits.
fn precheck_chain_ids(call: *Call, block_raw: []const u8, chain_id: u64) HandlerError!void {
    const calls = (json.find_path(block_raw, &.{"calls"}) catch return error.InvalidParams) orelse
        return;
    if (std.mem.eql(u8, calls, "null")) return;
    var list = try Elements.init(calls);
    while (try list.next(calls_max)) |call_raw| {
        const found = json.find_path(call_raw, &.{"chainId"}) catch return error.InvalidParams;
        const raw = found orelse continue;
        if (std.mem.eql(u8, raw, "null")) continue;
        if (try quantity_of(u64, raw) != chain_id) {
            return call.fail(call_error.code_invalid_input, "invalid chain ID");
        }
    }
}

/// Nethermind's OP pre-run check of each call's priority fee against its fee cap.
fn precheck_fee_caps(call: *Call, block_raw: []const u8) HandlerError!void {
    const calls = (json.find_path(block_raw, &.{"calls"}) catch return error.InvalidParams) orelse
        return;
    if (std.mem.eql(u8, calls, "null")) return;
    var list = try Elements.init(calls);
    while (try list.next(calls_max)) |call_raw| {
        const fees = try call_fees.parse(call_raw);
        const tip = fees.max_priority_fee orelse continue;
        if (tip > (fees.max_fee orelse 0)) {
            const text = "max priority fee per gas higher than max fee per gas";
            return call.fail(call_error.code_transaction_rejected, text);
        }
    }
}

/// Checks the numbers and timestamps of every block (`sanitize_base_chain`) on a copy of
/// the schedule.
fn plan_blocks(
    call: *Call,
    buffer: []u8,
    schedule_in: schedule_module.Schedule,
    blocks: []const u8,
) HandlerError!void {
    var schedule = schedule_in;
    var list = try Elements.init(blocks);
    while (try list.next(blocks_max)) |block_raw| {
        _ = try schedule.next(call, buffer, try block_overrides(block_raw));
    }
}

fn block_overrides(block_raw: []const u8) HandlerError!?[]const u8 {
    const raw = json.find_path(block_raw, &.{"blockOverrides"}) catch return error.InvalidParams;
    const text = raw orelse return null;
    return if (std.mem.eql(u8, text, "null")) null else text;
}

/// Runs and writes every block, each preceded by the empty fillers of its number gap.
fn run_blocks(
    simulation: *Simulation,
    schedule: *schedule_module.Schedule,
    parent: *Parent,
    blocks: []const u8,
) HandlerError!void {
    const w = simulation.call.writer;
    try w.begin_array();
    var list = try Elements.init(blocks);
    while (try list.next(blocks_max)) |block_raw| {
        var filler = schedule.*;
        const overrides = try block_overrides(block_raw);
        const planned = try schedule.next(simulation.call, simulation.space, overrides);
        var number = filler.prev_number + 1;
        while (number < planned.number) : (number += 1) {
            const prev = filler.prev_timestamp;
            // Proof: `plan_blocks` ran the same schedule without an error.
            filler.prev_timestamp = filler.next_timestamp(number, prev).?;
            const empty: schedule_module.Schedule.Planned = .{
                .number = number,
                .timestamp = filler.prev_timestamp,
            };
            parent.* = try run_block_checked(simulation, parent, "{}", empty);
        }
        parent.* = try run_block_checked(simulation, parent, block_raw, planned);
    }
    try w.end_array();
}

/// `simulate_block`, reporting a historical state read failure as such.
fn run_block_checked(
    simulation: *Simulation,
    parent: *const Parent,
    raw: []const u8,
    planned: schedule_module.Schedule.Planned,
) HandlerError!Parent {
    return simulate_block(simulation, parent, raw, planned) catch |err| {
        if (simulation.history) |history| if (history.failure) |failure| {
            return eth_proof.fail_history(simulation.call, failure);
        };
        return err;
    };
}

/// A boolean option, false when absent. Nethermind's BooleanConverter also reads a string
/// starting with "true" or "false" (any case, as .NET's Utf8Parser does) and refuses
/// anything else, null included.
fn json_true(raw: []const u8, name: []const u8) HandlerError!bool {
    const value = (json.find_path(raw, &.{name}) catch return error.InvalidParams) orelse
        return false;
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    if (value.len < 2 or value[0] != '"') return error.InvalidParams;
    const text = value[1..];
    if (std.ascii.startsWithIgnoreCase(text, "true")) return true;
    if (std.ascii.startsWithIgnoreCase(text, "false")) return false;
    return error.InvalidParams;
}

/// The environment of a simulated block on `parent`: unvalidated blocks run with a zero
/// base fee, validated ones with the chain's next base fee; prevRandao is zero; then the
/// block overrides apply.
fn block_env(
    simulation: *Simulation,
    parent: *const Parent,
    overrides: ?[]const u8,
    planned: schedule_module.Schedule.Planned,
) HandlerError!BlockEnv {
    var env = parent.env;
    env.number = planned.number;
    env.timestamp = planned.timestamp;
    env.prev_randao = @splat(0);
    env.blob_base_fee = null;
    env.base_fee = 0;
    env.base_fee_override = null;
    if (simulation.validation) {
        const spec = simulation.api.spec;
        env.base_fee = spec.next_base_fee(.{
            .timestamp = parent.env.timestamp,
            .gas_used = parent.gas_used,
            .gas_limit = parent.env.gas_limit,
            .base_fee = parent.env.base_fee,
            .blob_gas_used = parent.blob_gas_used,
            .extra_data = simulation.extra_data,
        }, planned.timestamp) catch parent.env.base_fee;
    }
    // `precheck_blocks` refused a gas limit above the client limit.
    if (overrides) |raw| try apply_block_overrides(simulation.call, &env, raw);
    assert(env.number == planned.number and env.timestamp == planned.timestamp);
    return env;
}

/// Runs one simulated block on top of `parent` and writes it. The calls are written as
/// they run, so their logs' `blockHash` is filled in once the block is sealed.
fn simulate_block(
    simulation: *Simulation,
    parent: *const Parent,
    raw: []const u8,
    planned: schedule_module.Schedule.Planned,
) HandlerError!Parent {
    const overrides = try block_overrides(raw);
    const env = try block_env(simulation, parent, overrides, planned);
    try apply_block_state_overrides(simulation, raw);
    var block = assembly.Block.init(simulation.block_space);
    const w = simulation.call.writer;
    try w.begin_object();
    try w.key("calls");
    try w.begin_array();
    const calls_start = w.out.end;
    if (json.find_path(raw, &.{"calls"}) catch return error.InvalidParams) |calls| {
        var list = try Elements.init(calls);
        var log_index: u64 = 0;
        var index: u64 = 0;
        while (try list.next(calls_max)) |call_raw| : (index += 1) {
            try run_call(simulation, &env, &block, call_raw, &log_index);
            assert(block.gas_used <= env.gas_limit);
        }
        assert(index == block.count);
    }
    try w.end_array();
    const calls_end = w.out.end;
    const sealed: assembly.Sealed = .{
        .header = block.header(.{
            .spec = simulation.api.spec,
            .parent_hash = parent.hash,
            .env = &env,
            .difficulty = 0,
            .extra_data = simulation.extra_data,
            .parent_beacon_block_root = simulation.parent_beacon_block_root,
        }),
        .base_fee_override = env.base_fee_override,
    };
    const hash = sealed.hash();
    _ = assembly.patch_block_hashes(w.out.buffer[calls_start..calls_end], hash);
    try block.write(w, &sealed, hash, simulation.full_transactions, simulation.api.spec.chain_id);
    try w.end_object();
    return .{
        .env = env,
        .hash = hash,
        .gas_used = block.gas_used,
        .blob_gas_used = block.da_footprint,
    };
}

fn apply_block_state_overrides(simulation: *Simulation, raw: []const u8) HandlerError!void {
    const call = simulation.call;
    const space = simulation.space;
    const executor = simulation.api.chain.executor;
    // As in geth, overridden precompiles last for their own block: the next block starts
    // from the fork's precompiles (the overridden code stays in the state).
    executor.state.ordinary_count = 0;
    const overrides = (json.find_path(raw, &.{"stateOverrides"}) catch
        return error.InvalidParams) orelse return;
    if (try both_state_and_diff(overrides)) |address| {
        return call.fail(rpc.code.invalid_params, both_state_message(space, address));
    }
    apply_state_overrides(executor.state, space, overrides) catch |err| switch (err) {
        error.InvalidParams => return error.InvalidParams,
        else => return call.fail(rpc.code.internal_error, @errorName(err)),
    };
}

/// Whether the block overrides `raw` set the field `names` (a name and its aliases; a null
/// member sets nothing).
fn overridden(raw: []const u8, names: []const []const u8) HandlerError!bool {
    for (names) |name| {
        const value = json.find_member_ignore_case(raw, name) catch return error.InvalidParams;
        if (value != null and !std.mem.eql(u8, value.?, "null")) return true;
    }
    return false;
}

/// Nethermind's `BlockOverride.ApplyOverrides` over its fields, matched ASCII
/// case-insensitively (`PropertyNameCaseInsensitive`); other members are ignored here
/// (eth_simulateV1 refuses them first, `check_override_keys`). `beaconRoot` never reaches a
/// simulated header (base/base repeats the parent's); `withdrawals` are not applied.
pub fn apply_block_overrides(call: *Call, env: *BlockEnv, raw: []const u8) HandlerError!void {
    _ = call;
    var members = try Members.init(raw);
    while (try members.next(32)) |member| {
        if (std.mem.eql(u8, member.value, "null")) continue;
        const key = member.key;
        if (is(key, "number")) {
            env.number = saturate(u64, try quantity_of(u256, member.value));
        } else if (is(key, "time")) {
            env.timestamp = try quantity_of(u64, member.value);
        } else if (is(key, "gasLimit")) {
            env.gas_limit = try quantity_of(u64, member.value);
        } else if (is(key, "feeRecipient") or is(key, "coinbase")) {
            env.beneficiary = try fixed_of(20, member.value);
        } else if (is(key, "prevRandao")) {
            env.prev_randao = try fixed_of(32, member.value);
        } else if (is(key, "baseFeePerGas")) {
            const base_fee = try quantity_of(u256, member.value);
            env.base_fee = saturate(u64, base_fee);
            env.base_fee_override = if (base_fee > env.base_fee) base_fee else null;
        } else if (is(key, "blobBaseFee")) {
            env.blob_base_fee = saturate(u128, try quantity_of(u256, member.value));
        } else if (is(key, "beaconRoot")) {
            env.parent_beacon_block_root = try fixed_of(32, member.value);
        }
    }
}

fn is(key: []const u8, name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(key, name);
}

/// The fields of Nethermind's `BlockOverride` (`OverrideFields.Of<BlockOverride>`).
const block_override_fields = [_][]const u8{
    "number",   "prevRandao",    "time",        "gasLimit",    "feeRecipient",
    "coinbase", "baseFeePerGas", "blobBaseFee", "withdrawals", "beaconRoot",
};

/// The fields of Nethermind's `AccountOverride` (`AccountOverrideConverter`).
const account_override_fields = [_][]const u8{
    "nonce", "balance", "code", "movePrecompileToAddress", "state", "stateDiff",
};

/// Nethermind's `OverrideFields.Match` over the override object `raw`: every key names a
/// field ASCII case-insensitively, and no field is named by two spellings (the same
/// spelling twice is one key given twice). Not an object: nothing to check here.
fn override_keys_valid(raw: []const u8, fields: []const []const u8) HandlerError!bool {
    assert(fields.len <= 16);
    if (raw.len == 0 or raw[0] != '{') return true;
    var spellings: [16]?[]const u8 = @splat(null);
    var members = try Members.init(raw);
    while (try members.next(64)) |member| {
        const index = for (fields, 0..) |field, index| {
            if (is(member.key, field)) break index;
        } else return false;
        if (spellings[index]) |spelling| {
            if (!std.mem.eql(u8, spelling, member.key)) return false;
        }
        spellings[index] = member.key;
    }
    return true;
}

/// Nethermind's `BlockStateCallConverter` and `AccountOverrideConverter` refuse an unknown
/// block or account override key while reading the payload (argument 0), before the block
/// parameter is read and anything runs.
fn check_override_keys(call: *Call, blocks: []const u8) HandlerError!void {
    var list = try Elements.init(blocks);
    // Every block is read, even past the limit `check_count` refuses next; each element
    // takes at least one byte, so the request's length bounds the loop.
    while (try list.next(std.math.maxInt(u32))) |block_raw| {
        assert(list.count <= blocks.len);
        var valid = true;
        if (try block_overrides(block_raw)) |raw| {
            valid = try override_keys_valid(raw, &block_override_fields);
        }
        const found = json.find_path(block_raw, &.{"stateOverrides"}) catch
            return error.InvalidParams;
        if (found) |accounts| if (valid and accounts.len > 0 and accounts[0] == '{') {
            var members = try Members.init(accounts);
            while (try members.next(overrides_max)) |entry| {
                if (!try override_keys_valid(entry.value, &account_override_fields)) {
                    valid = false;
                    break;
                }
            }
        };
        if (!valid) return call.fail(rpc.code.invalid_params, "invalid argument 0");
    }
}

fn saturate(comptime T: type, value: u256) T {
    return @intCast(@min(value, std.math.maxInt(T)));
}

fn fixed_of(comptime size: usize, raw: []const u8) HandlerError![size]u8 {
    return json.parse_fixed(size, try string_of(raw)) catch error.InvalidParams;
}

/// The first account of the state overrides `raw` that sets both `state` and `stateDiff`
/// (alloy-evm `StateOverrideError::BothStateAndStateDiff`), if any.
pub fn both_state_and_diff(raw: []const u8) HandlerError!?[20]u8 {
    var accounts = try Members.init(raw);
    while (try accounts.next(overrides_max)) |entry| {
        const state = try overridden(entry.value, &.{"state"});
        if (state and try overridden(entry.value, &.{"stateDiff"})) {
            return json.parse_fixed(20, entry.key) catch error.InvalidParams;
        }
    }
    return null;
}

/// reth's `EthApiError::BothStateAndStateDiffInOverride` text (the address `{:?}`-printed:
/// lowercase hex), written into `buffer`.
pub fn both_state_message(buffer: []u8, address: [20]u8) []const u8 {
    assert(buffer.len >= 96);
    const hex = std.fmt.bytesToHex(address, .lower);
    const format = "account 0x{s} has both 'state' and 'stateDiff'";
    return std.fmt.bufPrint(buffer, format, .{&hex}) catch unreachable; // Proof: 96 bytes.
}

pub const OverrideError = HandlerError || evm.state.Error;

pub fn apply_state_overrides(state: *evm.State, space: []u8, raw: []const u8) OverrideError!void {
    comptime assert(overrides_max <= evm.State.ordinary_max);
    var accounts = try Members.init(raw);
    while (try accounts.next(overrides_max)) |entry| {
        const text = entry.key;
        if (text.len != 42) return error.InvalidParams;
        const address = json.parse_fixed(20, text) catch return error.InvalidParams;
        // geth's `Apply` (and Nethermind's `UpdateCode`): any override of a precompile's
        // address turns it into an ordinary account, whose code the EVM runs.
        state.make_ordinary(address);
        const account = try state.load(address);
        if (!try override_keys_valid(entry.value, &account_override_fields)) {
            return error.InvalidParams;
        }
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
    if (is(field.key, "balance")) {
        try state.set_balance(account, try quantity_of(u256, field.value));
    } else if (is(field.key, "nonce")) {
        try state.set_nonce(account, try quantity_of(u64, field.value));
    } else if (is(field.key, "code")) {
        try state.replace_code(account, try parse_code(try string_of(field.value), space));
    } else if (is(field.key, "state")) {
        // Fresh storage incarnation: database slots read as zero (never committed).
        account.storage_epoch += 1;
        try write_slots(state, account, field.value);
    } else if (is(field.key, "stateDiff")) {
        try write_slots(state, account, field.value);
    } else if (is(field.key, "movePrecompileToAddress")) {
        // alloy's `AccountOverride` reads it, but only reth's eth_simulateV1 applies it
        // (`apply_precompile_overrides`); other calls ignore it. Not applied here yet.
        _ = json.parse_fixed(20, try string_of(field.value)) catch return error.InvalidParams;
    } else return error.InvalidParams;
}

/// Override code as Nethermind's `ByteArrayConverter` reads it: an odd digit count decodes
/// with a leading zero nibble (`0x601` is `0x0601`).
fn parse_code(text: []const u8, space: []u8) OverrideError![]const u8 {
    const odd = text.len > 2 and (text.len - 2) % 2 == 1;
    if (!odd) return json.parse_data(text, space) catch error.InvalidParams;
    if (text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) return error.InvalidParams;
    const size = (text.len - 2 + 1) / 2;
    if (size > space.len) return error.InvalidParams;
    space[0] = std.fmt.charToDigit(text[2], 16) catch return error.InvalidParams;
    const rest = std.fmt.hexToBytes(space[1..size], text[3..]) catch return error.InvalidParams;
    assert(rest.len + 1 == size);
    return space[0..size];
}

test "simulate: override code with an odd digit count gets a leading zero nibble" {
    var space: [4]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 0x06, 0x01 }, try parse_code("0x601", &space));
    try std.testing.expectEqualSlices(u8, &.{0x0f}, try parse_code("0xf", &space));
    try std.testing.expectEqualSlices(u8, &.{ 0x60, 0x01 }, try parse_code("0x6001", &space));
    try std.testing.expectError(error.InvalidParams, parse_code("0x60g", &space));
    try std.testing.expectError(error.InvalidParams, parse_code("0x123456789", &space));
}

fn write_slots(state: *evm.State, account: *evm.state.Account, raw: []const u8) OverrideError!void {
    var slots = try Members.init(raw);
    while (try slots.next(slots_max)) |slot| {
        // Nethermind reads a slot key as a `UInt256` (`0x1` is slot one), a value as a hash.
        const key = eth_proof.parse_slot_key(slot.key) orelse return error.InvalidParams;
        const value = json.parse_hash(try string_of(slot.value)) catch
            return error.InvalidParams;
        const access = try state.storage_access(account, std.mem.readInt(u256, &key, .big));
        try state.storage_write(account, access.slot, std.mem.readInt(u256, &value, .big));
    }
}

/// Where a call's logs sit; their block hash is patched in once the block is sealed.
const Position = struct { block: u64, timestamp: u64, index: u64, tx_hash: primitives.B256 };

/// Runs and writes one call, adding its transaction and receipt to `block`. A call the EVM
/// rejects fails the whole request (reth's `execute_transactions`); a revert or halt is the
/// call's `error`.
fn run_call(
    simulation: *Simulation,
    env: *const BlockEnv,
    block: *assembly.Block,
    raw: []const u8,
    log_index: *u64,
) HandlerError!void {
    const call = simulation.call;
    const executor = simulation.api.chain.executor;
    if (try eth.incomplete_deposit(raw)) |refusal| {
        return call.fail(rpc.code.invalid_params, refusal);
    }
    var message = try eth.parse_call(simulation.space, raw, executor.recoverer);
    try set_fees(simulation, &message, raw);
    const remaining = env.gas_limit - block.gas_used;
    if ((message.gas orelse 0) > remaining) {
        return call.fail(code_block_gas, "Block gas limit exceeded by the block's transactions");
    }
    // The RPC gas cap bounds a given gas silently and the default.
    const cap = simulation.gas_cap_remaining;
    message.gas = if (message.gas) |gas| @min(gas, cap) else @min(remaining, cap);
    const caller = executor.state.load(message.from) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    const sender: Sender = .{ .nonce = caller.info.nonce, .balance = caller.info.balance };
    const position: Position = .{
        .block = env.number,
        .timestamp = env.timestamp,
        .index = block.count,
        .tx_hash = try add_transaction(simulation, block, &message, raw, sender.nonce),
    };
    if (simulation.validation) message.envelope = block.transactions[block.count - 1];
    try add_da_footprint(simulation, env, block);
    var hooks: evm.evm.Tracer = undefined;
    if (simulation.transfers) |transfers| {
        transfers.reset();
        hooks = transfers.tracer();
        executor.machine.tracer = &hooks;
    }
    const result = executor.session_call(env, message) catch |err| {
        executor.machine.tracer = null;
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    executor.machine.tracer = null;
    const executed = switch (result) {
        .invalid => |reason| return fail_invalid(simulation, reason, &message, sender),
        .executed => |executed| executed,
    };
    if (executed.gas_used > cap) {
        return call.fail(code_gas_limit_reached, gas_limit_reached);
    }
    simulation.gas_cap_remaining = cap - executed.gas_used;
    const success = executed.status == .success;
    const logs = if (success) executed.logs else &.{};
    block.add_receipt(success, executed.gas_used, logs) catch return scratch_full(call);
    try write_call(simulation, &message, &executed, position, log_index);
}

const Executed = @FieldType(Executor.SessionCall, "executed");

fn write_call(
    simulation: *Simulation,
    message: *const Executor.Call,
    executed: *const Executed,
    position: Position,
    log_index: *u64,
) HandlerError!void {
    const w = simulation.call.writer;
    const space = simulation.space;
    assert(executed.gas_max_used >= executed.gas_used);
    try w.begin_object();
    try w.key("returnData");
    // base/base reports no return data for a failed call (the revert output is `data`).
    try w.data(if (executed.status == .success) executed.output else &.{});
    try w.key("logs");
    try w.begin_array();
    if (executed.status == .success) try write_logs(simulation, executed.logs, position, log_index);
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(executed.gas_used);
    try w.key("maxUsedGas");
    try w.quantity(executed.gas_max_used);
    try w.key("status");
    try w.quantity(@as(u64, @intFromBool(executed.status == .success)));
    // The call data in `space` is done with: the error text goes there.
    switch (executed.status) {
        .success => {},
        .revert => {
            const text = call_error.revert_message(space, executed.output);
            try write_error(w, call_error.code_execution_error, text, executed.output);
        },
        .halt => {
            const failure = call_error.halt(space, executed.exit, message.gas.?);
            try write_error(w, code_vm_error, failure.message, null);
        },
    }
    try w.end_object();
}

fn scratch_full(call: *Call) HandlerError {
    return call.fail(rpc.code.internal_error, "simulation scratch full");
}

/// The call as the transaction base/base builds for it (reth `resolve_transaction`): the
/// state nonce unless given (a given 2^64 - 1 is zero without validation), the call's gas,
/// the chain id unless given, missing prices zero; added to `block`, returning its hash.
fn add_transaction(
    simulation: *const Simulation,
    block: *assembly.Block,
    message: *const Executor.Call,
    raw: []const u8,
    state_nonce: u64,
) HandlerError!primitives.B256 {
    const fees = try call_fees.parse(raw);
    const tx_type = assembly.tx_type_of(
        message.authorization_list != null,
        fees.blob_hashes != null,
        try member_of(raw, "accessList") != null,
        fees.gas_price != null,
    );
    var nonce = state_nonce;
    if (try member_of(raw, "nonce")) |text| nonce = try quantity_of(u64, text);
    if (!simulation.validation and nonce == std.math.maxInt(u64)) nonce = 0;
    var request: assembly.TxRequest = .{
        .tx_type = tx_type,
        .chain_id = message.chain_id orelse simulation.api.spec.chain_id,
        .nonce = nonce,
        .gas_limit = message.gas.?,
        .to = if (message.to) |to| .{ .bytes = to } else null,
        .value = message.value,
        .input = message.data,
        .access_list = message.access_list,
    };
    const price_max = std.math.maxInt(u128);
    switch (tx_type) {
        .legacy, .eip2930 => request.gas_price = @intCast(@min(fees.gas_price orelse 0, price_max)),
        else => {
            request.max_fee_per_gas = @intCast(@min(fees.max_fee orelse 0, price_max));
            const priority = fees.max_priority_fee orelse 0;
            request.max_priority_fee_per_gas = @intCast(@min(priority, price_max));
        },
    }
    if (tx_type == .eip7702) {
        const list = (try member_of(raw, "authorizationList")).?; // Parsed by `parse_call`.
        request.authorizations = assembly.encode_authorizations(block, list) catch |err|
            return switch (err) {
                error.ScratchFull => scratch_full(simulation.call),
                else => |other| other,
            };
    }
    const sender: primitives.Address = .{ .bytes = message.from };
    return block.add_transaction(&request, sender) catch scratch_full(simulation.call);
}

/// Jovian: base/base's block executor counts every transaction's DA footprint, of its empty
/// envelope (`WithEncoded::new(Default::default(), tx)`) at the L1Block's current scalar.
fn add_da_footprint(
    simulation: *const Simulation,
    env: *const BlockEnv,
    block: *assembly.Block,
) HandlerError!void {
    if (!simulation.api.spec.is_upgrade_active(.jovian, env.timestamp)) return;
    const state = simulation.api.chain.executor.state;
    const params = evm.op.load_params(state, .jovian) catch |err| {
        return simulation.call.fail(rpc.code.internal_error, @errorName(err));
    };
    block.da_footprint +|= params.jovian_da_footprint(&.{});
}

/// The raw value of member `name` of the object `raw`; null when absent or null.
fn member_of(raw: []const u8, name: []const u8) HandlerError!?[]const u8 {
    const value = (json.find_path(raw, &.{name}) catch return error.InvalidParams) orelse
        return null;
    return if (std.mem.eql(u8, value, "null")) null else value;
}

const Sender = struct { nonce: u64, balance: u256 };

/// The call's prices and nonce as reth's `resolve_transaction` fills them: missing fee
/// fields are zero; the request's nonce counts only with validation.
fn set_fees(
    simulation: *const Simulation,
    message: *node.executor.Executor.Call,
    raw: []const u8,
) HandlerError!void {
    const fees = try call_fees.parse(raw);
    const eip1559 = fees.max_fee != null or fees.max_priority_fee != null;
    const price = if (eip1559) fees.max_fee orelse 0 else fees.gas_price orelse 0;
    message.gas_price = @min(price, std.math.maxInt(u128));
    message.priority_fee = if (eip1559)
        @min(fees.max_priority_fee orelse 0, std.math.maxInt(u128))
    else
        null;
    message.validate = simulation.validation;
    if (!simulation.validation) return;
    const nonce = json.find_path(raw, &.{"nonce"}) catch return error.InvalidParams;
    if (nonce) |text| if (!std.mem.eql(u8, text, "null")) {
        message.nonce = try quantity_of(u64, text);
    };
}

/// reth's top-level error for a call the EVM rejects (`as_simulate_error`, else the
/// eth_call error).
fn fail_invalid(
    simulation: *const Simulation,
    reason: evm.transaction.Invalid,
    message: *const node.executor.Executor.Call,
    sender: Sender,
) HandlerError {
    const call = simulation.call;
    const buffer = simulation.space;
    // Nethermind buys the gas (the balance check) before it checks the nonce.
    const nonce_wrong = reason == .nonce_too_low or reason == .nonce_too_high;
    const effective: evm.transaction.Invalid = if (nonce_wrong and
        message.validate and sender.balance < cost_of(message)) .insufficient_funds else reason;
    switch (effective) {
        .nonce_too_low => {
            const text = std.fmt.bufPrint(buffer, "nonce too low: next nonce {d}, tx nonce {d}", .{
                sender.nonce, message.nonce orelse sender.nonce,
            }) catch "nonce too low";
            return call.fail(code_nonce_too_low, text);
        },
        .nonce_too_high => return call.fail(code_nonce_too_high, "nonce too high"),
        .nonce_overflow => return call.fail(rpc.code.internal_error, "nonce has max value"),
        .fee_below_base_fee => {
            return call.fail(code_base_fee_too_low, "max fee per gas less than block base fee");
        },
        .intrinsic_gas_too_low, .floor_gas_too_low => {
            return call.fail(code_intrinsic_gas, "intrinsic gas too low");
        },
        // Nethermind's `SimulateErrorMessages.InsufficientFunds`.
        .insufficient_funds => return call.fail(code_insufficient_funds, insufficient_funds),
        .initcode_too_large => return call.fail(code_initcode_size, "max initcode size exceeded"),
        else => return eth.fail_invalid(call, reason),
    }
}

const insufficient_funds = "Insufficient funds to pay for gas fees and value for a transaction";

/// What the sender must hold for the call: its gas at the gas price (the fee cap) plus value.
fn cost_of(message: *const node.executor.Executor.Call) u512 {
    const cost = @as(u512, message.gas.?) * message.gas_price + message.value;
    assert(cost >= message.value);
    return cost;
}

fn write_error(
    w: *json.Writer,
    code: i32,
    message: []const u8,
    data: ?[]const u8,
) HandlerError!void {
    try w.key("error");
    try w.begin_object();
    try w.key("code");
    try w.integer(code);
    try w.key("message");
    try w.string(message);
    // As Nethermind's SimulateTxTracer: a revert carries its data, "0x" when empty; a halt
    // none.
    if (data) |bytes| {
        try w.key("data");
        try w.data(bytes);
    }
    try w.end_object();
}

/// The call's logs, with `traceTransfers`' transfer logs before the logs that follow them.
fn write_logs(
    simulation: *const Simulation,
    logs: []const evm.state.Log,
    position: Position,
    log_index: *u64,
) HandlerError!void {
    const w = simulation.call.writer;
    const empty: []const transfers_module.Transfer = &.{};
    var transfers = empty;
    if (simulation.transfers) |traced| {
        if (traced.full) return simulation.call.fail(rpc.code.internal_error, "too many transfers");
        assert(traced.depth == 0 and traced.logs == logs.len);
        transfers = traced.items[0..traced.count];
    }
    var next: usize = 0;
    for (0..logs.len + 1) |real| {
        while (next < transfers.len and transfers[next].position <= real) : (next += 1) {
            try write_transfer_log(w, &transfers[next], position, log_index.*);
            log_index.* += 1;
        }
        if (real == logs.len) break;
        try write_log(w, logs[real], position, log_index.*);
        log_index.* += 1;
    }
    assert(next == transfers.len);
}

fn write_transfer_log(
    w: *json.Writer,
    transfer: *const transfers_module.Transfer,
    position: Position,
    index: u64,
) HandlerError!void {
    var data: [32]u8 = undefined;
    std.mem.writeInt(u256, &data, transfer.value, .big);
    const words = transfers_module.topics_of(transfer);
    const log: evm.state.Log = .{
        .address = transfers_module.eth_address,
        .topics = .{ words[0], words[1], words[2], @splat(0) },
        .topic_count = words.len,
        .data = &data,
    };
    try write_log(w, log, position, index);
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
    // A placeholder until the block is sealed (`patch_block_hashes`).
    try w.key("blockHash");
    try w.data(&primitives.B256.zero.bytes);
    try w.key("blockNumber");
    try w.quantity(position.block);
    try w.key("blockTimestamp");
    try w.quantity(position.timestamp);
    try w.key("transactionHash");
    try w.data(&position.tx_hash.bytes);
    try w.key("transactionIndex");
    try w.quantity(position.index);
    try w.key("logIndex");
    try w.quantity(index);
    try w.key("removed");
    try w.boolean(false);
    try w.end_object();
}

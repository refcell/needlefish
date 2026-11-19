//! eth_*, net_* and web3_* JSON-RPC methods over the node's chain, state and pool.
//! State queries serve the head state (older blocks: "historical state unavailable",
//! until persistence keeps state history).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const chainspec = @import("../chainspec/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const BlobParams = chainspec.BlobParams;
const txpool = @import("../txpool/root.zig");
const node = @import("../node/root.zig");
const format = @import("format.zig");
const debug = @import("debug.zig");
const native = @import("../evm/native.zig");
const eip8130_call = @import("eip8130_call.zig");

const Hash = [32]u8;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Chain = node.Chain;

pub const estimate_iterations_max = 64;
/// reth's default RPC gas cap (`--rpc.gascap`, `RPC_DEFAULT_GAS_CAP`): the most gas a call
/// (eth_call, eth_estimateGas, eth_createAccessList, debug_traceCall, eth_simulateV1) runs
/// with, whatever it or a block override asks for.
pub const rpc_gas_cap: u64 = 50_000_000;
pub const logs_blocks_max = 10_000;
pub const logs_max = 10_000;
pub const fee_history_blocks_max = 1024;

pub const Api = struct {
    spec: *const chainspec.ChainSpec,
    chain: *Chain,
    pool: ?*txpool.Pool,
    client_version: []const u8 = "needlefish/v0.0.0",
    /// Verifies blob transaction KZG proofs on submission when set.
    kzg: ?consensus.sidecar.KzgVerifier = null,
    /// Decoding space for raw transactions and call data (bounded request size).
    scratch: []u8,
    /// `debug_executionWitness` buffers, bound to the chain's state; null disables it.
    witness: ?*node.witness.Generator = null,
    /// Polling filters (eth_newFilter and friends); null disables them.
    filters: ?*filters_module.Filters = null,
    /// eth_sendRawTransactionSync's hand-off to the transport; null disables the method.
    sync: ?*send_sync.Request = null,
    /// Monotonic clock for `base_meterBlock*` timings; null reports zero times.
    clock: ?node.executor.Executor.Clock = null,
    /// Pool storage and builder enforcement for `base_sendRawTransactionValidity`; null
    /// rejects validity transactions.
    validity_sink: ?@import("validity.zig").Sink = null,
    /// Ordered storage leaves at block boundaries for `debug_storageRangeAt`; null disables it.
    storage_range: ?@import("storage_range.zig").Source = null,
};

pub const methods = core_methods ++ @import("eth_more.zig").methods ++ filters_module.methods ++
    @import("txpool.zig").methods ++ @import("eth_config.zig").methods ++
    @import("access_list.zig").methods ++ @import("simulate.zig").methods ++ send_sync.methods ++
    @import("metering.zig").methods ++ @import("trace.zig").methods ++
    @import("validity.zig").methods ++ @import("account.zig").methods ++
    @import("storage_range.zig").methods ++ @import("insert_validated.zig").methods ++
    @import("sender_nonce.zig").methods ++ fuzz_coverage.methods;
pub const fuzz_coverage = @import("fuzz_coverage.zig");
pub const send_sync = @import("send_sync.zig");
const filters_module = @import("filters.zig");
const state_view = @import("state_view.zig");
const eth_proof = @import("eth_proof.zig");
const simulate_module = @import("simulate.zig");
const evm = @import("../evm/root.zig");
const call_error = @import("call_error.zig");
const call_fees = @import("call_fees.zig");

const core_methods = [_]rpc.Method(*Api){
    .{ .name = "web3_clientVersion", .handler = client_version },
    .{ .name = "net_version", .handler = net_version },
    .{ .name = "net_listening", .handler = net_listening },
    .{ .name = "net_peerCount", .handler = net_peer_count },
    .{ .name = "eth_chainId", .handler = chain_id },
    .{ .name = "eth_syncing", .handler = syncing },
    .{ .name = "eth_blockNumber", .handler = block_number },
    .{ .name = "eth_gasPrice", .handler = gas_price },
    .{ .name = "eth_maxPriorityFeePerGas", .handler = max_priority_fee },
    .{ .name = "eth_blobBaseFee", .handler = blob_base_fee },
    .{ .name = "eth_feeHistory", .handler = fee_history },
    .{ .name = "eth_getBalance", .handler = get_balance },
    .{ .name = "eth_getTransactionCount", .handler = get_transaction_count },
    .{ .name = "eth_getCode", .handler = get_code },
    .{ .name = "eth_getStorageAt", .handler = get_storage_at },
    .{ .name = "eth_getBlockByNumber", .handler = get_block_by_number },
    .{ .name = "eth_getBlockByHash", .handler = get_block_by_hash },
    .{ .name = "eth_getTransactionByHash", .handler = get_transaction_by_hash },
    .{ .name = "eth_getTransactionReceipt", .handler = get_transaction_receipt },
    .{ .name = "eth_getBlockReceipts", .handler = get_block_receipts },
    .{ .name = "eth_sendRawTransaction", .handler = send_raw_transaction },
    .{ .name = "eth_call", .handler = eth_call },
    .{ .name = "eth_estimateGas", .handler = estimate_gas },
    .{ .name = "eth_getLogs", .handler = get_logs },
    .{ .name = "eth_getProof", .handler = @import("eth_proof.zig").get_proof },
    .{ .name = "miner_setMaxDASize", .handler = set_max_da_size },
    .{ .name = "miner_getMaxDASize", .handler = get_max_da_size },
    .{ .name = "miner_setGasLimit", .handler = set_gas_limit },
    .{ .name = "debug_getRawHeader", .handler = debug.get_raw_header },
    .{ .name = "debug_getRawBlock", .handler = debug.get_raw_block },
    .{ .name = "debug_getRawReceipts", .handler = debug.get_raw_receipts },
    .{ .name = "debug_getRawTransaction", .handler = debug.get_raw_transaction },
    .{ .name = "debug_executionWitness", .handler = debug.execution_witness },
    .{ .name = "debug_executePayload", .handler = debug.execute_payload },
    .{ .name = "debug_proofsSyncStatus", .handler = debug.proofs_sync_status },
};

pub const Router = rpc.Router(*Api, &methods);

// ---- Simple values ----------------------------------------------------------------

fn client_version(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.string(api.client_version);
}

fn net_version(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{api.spec.chain_id}) catch unreachable;
    try call.writer.string(text);
}

fn net_listening(_: *Api, call: *Call) HandlerError!void {
    try call.writer.boolean(true);
}

fn net_peer_count(_: *Api, call: *Call) HandlerError!void {
    try call.writer.quantity(@as(u8, 0));
}

fn chain_id(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(api.spec.chain_id);
}

fn syncing(_: *Api, call: *Call) HandlerError!void {
    try call.writer.boolean(false);
}

fn block_number(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(head_header(api).number);
}

/// Base fee of the block after the head.
fn next_base_fee(api: *Api) u64 {
    const head = head_header(api);
    return next_base_fee_after(api, &head, head.timestamp);
}

/// Base fee of a block after `parent`, as base/base derives it (`next_block_base_fee` at the
/// child's `timestamp`; zero when the parent's EIP-1559 extra data does not decode).
fn next_base_fee_after(api: *Api, parent: *const consensus.Header, timestamp: u64) u64 {
    return api.spec.next_base_fee(.{
        .timestamp = parent.timestamp,
        .gas_used = parent.gas_used,
        .gas_limit = parent.gas_limit,
        .base_fee = parent.base_fee_per_gas orelse 0,
        .blob_gas_used = parent.blob_gas_used orelse 0,
        .excess_blob_gas = parent.excess_blob_gas orelse 0,
        .extra_data = parent.extra_data,
    }, timestamp) catch 0;
}

/// Blob base fee of a block after `parent` (null without a blob schedule or blob fields).
fn next_blob_fee_after(api: *Api, parent: *const consensus.Header) ?u128 {
    const params = api.spec.blob_schedule_at(parent.timestamp) orelse return null;
    const excess = parent.excess_blob_gas orelse return null;
    const used = parent.blob_gas_used orelse return null;
    const next = params.next_excess_blob_gas(excess, used, parent.base_fee_per_gas orelse 0);
    return params.base_fee(next);
}

/// base/base's minimum suggested priority fee (0.001 gwei).
pub const min_suggested_priority_fee: u64 = 1_000_000;

/// `eth_gasPrice`: the suggested tip plus the head's base fee (reth `gas_price`).
fn gas_price(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const head = head_header(api);
    try call.writer.quantity(suggested_tip(api) + (head.base_fee_per_gas orelse 0));
}

fn max_priority_fee(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(suggested_tip(api));
}

/// reth's `op_suggest_tip_cap`: the minimum suggested priority fee, or 10% above the
/// head's median effective tip when the head has no room for its largest transaction.
fn suggested_tip(api: *Api) u128 {
    var record = api.chain.record(api.chain.head_hash()).?;
    var receipts = record.receipts;
    var tx_gas_max: u64 = 0;
    var previous: u64 = 0;
    while (!receipts.is_empty()) {
        const encoded = receipts.bytes() catch unreachable; // Stored by the chain.
        const receipt = consensus.Receipt.decode(encoded) catch unreachable; // Stored.
        tx_gas_max = @max(tx_gas_max, receipt.cumulative_gas_used - previous);
        previous = receipt.cumulative_gas_used;
    }
    const header = record.header;
    if (header.gas_used +| tx_gas_max <= header.gas_limit) return min_suggested_priority_fee;
    const base_fee = header.base_fee_per_gas orelse 0;
    const tips_max = api.scratch.len / @sizeOf(u128);
    const tips: [*]u128 = @ptrCast(@alignCast(api.scratch.ptr));
    var count: usize = 0;
    while (!record.transactions.is_empty() and count < tips_max) {
        const raw = record.transactions.bytes() catch unreachable; // Stored by the chain.
        const envelope = consensus.Envelope.decode(raw) catch unreachable; // Stored.
        const price = envelope.effective_gas_price(base_fee) orelse 0;
        if (price < base_fee) continue; // No effective tip (a deposit, or fee below base).
        tips[count] = price - base_fee;
        count += 1;
    }
    if (count == 0) return min_suggested_priority_fee;
    const sorted = tips[0..count];
    std.mem.sort(u128, sorted, {}, std.sort.asc(u128));
    const median = if (count % 2 == 1)
        sorted[count / 2]
    else
        (sorted[count / 2 - 1] + sorted[count / 2]) / 2;
    return @max(min_suggested_priority_fee, median + median / 10);
}

/// `miner_setMaxDASize(maxTxSize, maxBlockSize)`: the batcher's DA throttle; 0 lifts a
/// limit. Takes effect from the next payload build.
fn set_max_da_size(api: *Api, call: *Call) HandlerError!void {
    const tx_bytes_max = try call.params.quantity(u64);
    const block_bytes_max = try call.params.quantity(u64);
    try call.params.finish();
    api.chain.da_limits = .{ .tx_bytes_max = tx_bytes_max, .block_bytes_max = block_bytes_max };
    assert(api.chain.da_limits.block_bytes_max == block_bytes_max);
    try call.writer.boolean(true);
}

/// `miner_getMaxDASize`: `[maxTxSize, maxBlockSize]` (0 when unset), as base/base.
fn get_max_da_size(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const limits = api.chain.da_limits;
    try call.writer.begin_array();
    try call.writer.quantity(limits.tx_bytes_max);
    try call.writer.quantity(limits.block_bytes_max);
    try call.writer.end_array();
}

/// `miner_setGasLimit(gasLimit)`: gas the builder fills with pool transactions (capped
/// by the block gas limit; the header keeps the block's limit); 0 lifts it.
fn set_gas_limit(api: *Api, call: *Call) HandlerError!void {
    const gas_limit = try call.params.quantity(u64);
    try call.params.finish();
    api.chain.gas_limit_target = gas_limit;
    assert(api.chain.gas_limit_target == gas_limit);
    try call.writer.boolean(true);
}

fn blob_base_fee(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const fee = next_blob_fee_after(api, &head_header(api)) orelse
        return call.fail(rpc.code.server_error, "excess blob gas not set");
    try call.writer.quantity(fee);
}

/// Percentiles `eth_feeHistory` accepts per request (reth's `max_reward_percentile_count`).
const reward_percentiles_max = 100;

/// `eth_feeHistory(blockCount, newestBlock, rewardPercentiles?)` as base/base (reth) answers:
/// a count above 1024 is truncated, a range reaching below genesis is an invalid range, the
/// next block's base and blob fees close the fee lists, and rewards are the effective tips at
/// each gas-weighted percentile.
/// The block count as alloy's `U64` reads it: a hex quantity or a plain JSON number.
fn block_count(call: *Call) HandlerError!u64 {
    const raw = try call.params.raw();
    if (raw.len > 0 and raw[0] != '"') {
        for (raw) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidParams;
        return std.fmt.parseInt(u64, raw, 10) catch error.InvalidParams;
    }
    if (raw.len < 2 or raw[raw.len - 1] != '"') return error.InvalidParams;
    return json.parse_quantity(u64, raw[1 .. raw.len - 1]) catch error.InvalidParams;
}

fn fee_history(api: *Api, call: *Call) HandlerError!void {
    var count = @min(try block_count(call), fee_history_blocks_max);
    const newest_raw = try call.params.raw();
    const percentiles_raw = try call.params.optional_raw();
    try call.params.finish();
    const w = call.writer;
    if (count == 0) {
        try w.begin_object();
        try w.key("gasUsedRatio");
        try w.begin_array();
        try w.end_array();
        try format.field_quantity(w, "oldestBlock", @as(u64, 0));
        return w.end_object();
    }
    var percentiles_buffer: [reward_percentiles_max]f64 = undefined;
    const percentiles = try parse_percentiles(call, percentiles_raw, &percentiles_buffer);
    // Nethermind takes any block parameter here (a hash, an EIP-1898 object).
    const newest_hash = try resolve_block(api, call, newest_raw);
    const newest = (api.chain.header(newest_hash) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    }).number;
    count = @min(count, newest + 1);
    const oldest = newest + 1 - count;
    if (oldest < api.chain.genesis_number) {
        return call.fail(rpc.code.invalid_params, "invalid block range");
    }
    for (oldest..newest + 1) |number| {
        if (canonical_header(api, number) == null) {
            return call.fail(rpc.code.invalid_params, "invalid block range");
        }
    }
    try w.begin_object();
    try write_fee_lists(api, w, oldest, newest);
    try format.field_quantity(w, "oldestBlock", oldest);
    if (percentiles) |list| try fee_rewards(api, w, oldest, newest, list);
    try w.end_object();
}

/// `null` without percentiles; an invalid list is reth's "invalid reward percentiles".
fn parse_percentiles(
    call: *Call,
    raw: ?[]const u8,
    buffer: *[reward_percentiles_max]f64,
) HandlerError!?[]const f64 {
    const text = raw orelse return null;
    if (std.mem.eql(u8, text, "null")) return null;
    var scanner = json.Scanner.init(text);
    if ((try scanner_next(&scanner)).tag != .array_begin) return error.InvalidParams;
    var count: usize = 0;
    while (true) {
        const token = try scanner_next(&scanner);
        if (token.tag == .array_end) break;
        if (token.tag != .number) return error.InvalidParams;
        if (count == buffer.len) {
            return call.fail(rpc.code.invalid_params, "invalid reward percentiles");
        }
        buffer[count] = std.fmt.parseFloat(f64, token.bytes) catch return error.InvalidParams;
        count += 1;
    }
    const list = buffer[0..count];
    for (list, 0..) |percentile, index| {
        const descending = index > 0 and list[index - 1] > percentile;
        if (percentile < 0 or percentile > 100 or descending) {
            return call.fail(rpc.code.invalid_params, "invalid reward percentiles");
        }
    }
    return list;
}

/// `baseFeePerGas`, `gasUsedRatio`, `baseFeePerBlobGas` and `blobGasUsedRatio`.
fn write_fee_lists(api: *Api, w: *json.Writer, oldest: u64, newest: u64) !void {
    const last = canonical_header(api, newest).?;
    try w.key("baseFeePerGas");
    try w.begin_array();
    for (oldest..newest + 1) |number| {
        try w.quantity(canonical_header(api, number).?.base_fee_per_gas orelse 0);
    }
    try w.quantity(next_base_fee_after(api, &last, last.timestamp));
    try w.end_array();
    try w.key("gasUsedRatio");
    try w.begin_array();
    for (oldest..newest + 1) |number| {
        const header = canonical_header(api, number).?;
        try write_ratio(w, header.gas_used, header.gas_limit);
    }
    try w.end_array();
    try w.key("baseFeePerBlobGas");
    try w.begin_array();
    for (oldest..newest + 1) |number| {
        const header = canonical_header(api, number).?;
        const params = api.spec.blob_schedule_at(header.timestamp) orelse BlobParams.cancun;
        const fee = if (header.excess_blob_gas) |excess| params.base_fee(excess) else 0;
        try w.quantity(fee);
    }
    try w.quantity(next_blob_fee_after(api, &last) orelse 0);
    try w.end_array();
    try w.key("blobGasUsedRatio");
    try w.begin_array();
    for (oldest..newest + 1) |number| {
        const header = canonical_header(api, number).?;
        const params = api.spec.blob_schedule_at(header.timestamp) orelse BlobParams.cancun;
        try write_ratio(w, header.blob_gas_used orelse 0, params.max_blob_gas());
    }
    try w.end_array();
}

/// `used / limit` as a JSON number (0 for a zero limit).
fn write_ratio(w: *json.Writer, used: u64, limit: u64) !void {
    const ratio = if (limit == 0)
        0
    else
        @as(f64, @floatFromInt(used)) / @as(f64, @floatFromInt(limit));
    var text: [32]u8 = undefined;
    try w.raw(std.fmt.bufPrint(&text, "{d}", .{ratio}) catch "0");
}

const Tip = struct { gas_used: u64, reward: u128 };

fn tip_less(_: void, a: Tip, b: Tip) bool {
    return a.reward < b.reward;
}

/// Per block, each percentile's effective tip: transactions sorted by tip, the first whose
/// cumulative gas reaches the percentile of the block's gas (reth
/// `calculate_reward_percentiles_for_block`); zeros for an empty block.
fn fee_rewards(
    api: *Api,
    w: *json.Writer,
    oldest: u64,
    newest: u64,
    percentiles: []const f64,
) !void {
    const tips_max = api.scratch.len / @sizeOf(Tip);
    const tips: [*]Tip = @ptrCast(@alignCast(api.scratch.ptr));
    try w.key("reward");
    try w.begin_array();
    if (percentiles.len > 0) for (oldest..newest + 1) |number| {
        const hash = api.chain.store.canonical_hash(number).?;
        var record = api.chain.record(hash).?;
        const base_fee = record.header.base_fee_per_gas orelse 0;
        var count: usize = 0;
        var previous_gas: u64 = 0;
        while (!record.transactions.is_empty()) : (count += 1) {
            const raw = record.transactions.bytes() catch unreachable; // Stored.
            const encoded = record.receipts.bytes() catch unreachable; // Stored.
            const receipt = consensus.Receipt.decode(encoded) catch unreachable; // Stored.
            if (count == tips_max) return error.InvalidParams;
            const envelope = consensus.Envelope.decode(raw) catch unreachable; // Stored.
            const price = envelope.effective_gas_price(base_fee) orelse 0;
            tips[count] = .{
                .gas_used = receipt.cumulative_gas_used - previous_gas,
                .reward = price -| base_fee,
            };
            previous_gas = receipt.cumulative_gas_used;
        }
        try write_block_rewards(w, tips[0..count], previous_gas, percentiles);
    };
    try w.end_array();
}

fn write_block_rewards(
    w: *json.Writer,
    tips: []Tip,
    gas_total: u64,
    percentiles: []const f64,
) !void {
    std.mem.sort(Tip, tips, {}, tip_less);
    try w.begin_array();
    var index: usize = 0;
    var cumulative: u64 = if (tips.len > 0) tips[0].gas_used else 0;
    for (percentiles) |percentile| {
        if (tips.len == 0) {
            try w.quantity(@as(u8, 0));
            continue;
        }
        const gas: f64 = @floatFromInt(gas_total);
        const threshold: u64 = @intFromFloat(gas * percentile / 100);
        while (cumulative < threshold and index < tips.len - 1) {
            index += 1;
            cumulative += tips[index].gas_used;
        }
        try w.quantity(tips[index].reward);
    }
    try w.end_array();
}

fn scanner_next(scanner: *json.Scanner) HandlerError!json.Token {
    return scanner.next() catch error.InvalidParams;
}

// ---- State ------------------------------------------------------------------------

/// Requires the block param to name the head (or a pending/latest tag).
pub fn require_head_state(api: *Api, call: *Call, raw: ?[]const u8) HandlerError!void {
    if (raw) |text| {
        const hash = try resolve_block(api, call, text);
        if (!std.mem.eql(u8, &hash, &api.chain.head_hash())) {
            return call.fail(rpc.code.server_error, "historical state unavailable");
        }
    }
    api.chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
}

fn get_balance(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    const account = try state_view.account(api, call, view, address);
    try call.writer.quantity(if (account) |a| a.balance else 0);
}

fn get_transaction_count(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const tag = try call.params.optional_raw();
    const pending = if (tag) |t| std.mem.eql(u8, t, "\"pending\"") else false;
    // Base EIP-8130: a non-zero `nonce_key` reads the 2D channel nonce from the Nonce
    // Manager (canonical state only, no pending delta); `nonce_key_max` is not a channel.
    const nonce_key = try call.params.optional_quantity(u256) orelse 0;
    try call.params.finish();
    if (nonce_key == consensus.eip8130.nonce_key_max) return error.InvalidParams;
    const view = try state_view.resolve(api, call, if (pending) null else tag);
    if (nonce_key != 0) {
        const manager = native.nonce_manager_address;
        const slot = native.nonce_slot(address, nonce_key);
        const channel = try state_view.storage(api, call, view, manager, slot);
        return call.writer.quantity(@as(u64, @truncate(channel)));
    }
    const account = try state_view.account(api, call, view, address);
    var nonce = if (account) |a| a.nonce else 0;
    if (pending) if (api.pool) |pool| {
        nonce = pool.next_nonce(.{ .bytes = address }, nonce);
    };
    try call.writer.quantity(nonce);
}

fn get_code(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    const account = try state_view.account(api, call, view, address) orelse
        return call.writer.data(&.{});
    try call.writer.data(state_view.code(api, account.code_hash));
}

fn get_storage_at(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    // The slot is a `JsonStorageKey` (full-width hex is common), not a quantity.
    const slot_key = eth_proof.parse_key(try call.params.string()) orelse
        return error.InvalidParams;
    const slot = std.mem.readInt(u256, &slot_key, .big);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    var value: [32]u8 = undefined;
    std.mem.writeInt(u256, &value, try state_view.storage(api, call, view, address, slot), .big);
    try call.writer.data(&value);
}

// ---- Blocks -----------------------------------------------------------------------

pub fn head_header(api: *Api) consensus.Header {
    return api.chain.header(api.chain.head_hash()).?;
}

fn canonical_header(api: *Api, number: u64) ?consensus.Header {
    const hash = api.chain.store.canonical_hash(number) orelse return null;
    return api.chain.header(hash);
}

/// Resolves a block parameter (tag, number, bare hash, or `{"blockHash": ...}`) to a
/// hash. Nethermind's `BlockParameterConverter` reads every block parameter this way, the
/// block-number ones included.
pub fn resolve_block(api: *Api, call: *Call, raw: []const u8) HandlerError!Hash {
    if (raw.len == 2 + 2 + 64 and raw[0] == '"') {
        const hash = json.parse_hash(raw[1 .. raw.len - 1]) catch return error.InvalidParams;
        if (api.chain.store.ref(hash) == null) {
            return call.fail(rpc.code.server_error, "block not found");
        }
        return hash;
    }
    if (raw.len > 0 and raw[0] == '{') {
        return resolve_block_object(api, call, raw);
    }
    const number = try resolve_number(api, call, raw);
    return api.chain.store.canonical_hash(number) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
}

/// An EIP-1898 block object, read as Nethermind's `BlockParameterConverter` does: `blockHash`
/// (a null one counts as absent; `requireCanonical` must be a boolean) or `blockNumber`, any
/// block parameter but an object (a null one is latest). Both, or neither, are refused;
/// other members are ignored.
fn resolve_block_object(api: *Api, call: *Call, raw: []const u8) HandlerError!Hash {
    assert(raw[0] == '{');
    const canonical = json.find_path(raw, &.{"requireCanonical"}) catch
        return error.InvalidParams;
    if (canonical) |flag| {
        const boolean = std.mem.eql(u8, flag, "true") or std.mem.eql(u8, flag, "false");
        if (!boolean) return error.InvalidParams;
    }
    const hash_raw = json.find_path(raw, &.{"blockHash"}) catch return error.InvalidParams;
    const number_raw = json.find_path(raw, &.{"blockNumber"}) catch return error.InvalidParams;
    const hash_given = hash_raw != null and !std.mem.eql(u8, hash_raw.?, "null");
    if (hash_given and number_raw != null) return error.InvalidParams;
    if (number_raw) |number| {
        if (number.len == 0 or number[0] == '{') return error.InvalidParams;
        return resolve_block(api, call, number);
    }
    if (!hash_given) return error.InvalidParams;
    const text = hash_raw.?;
    if (text.len < 2 or text[0] != '"') return error.InvalidParams;
    const found = json.parse_hash(text[1 .. text.len - 1]) catch return error.InvalidParams;
    if (api.chain.store.ref(found) == null) {
        return call.fail(rpc.code.server_error, "block not found");
    }
    return found;
}

fn resolve_number(api: *Api, call: *Call, raw: []const u8) HandlerError!u64 {
    // Nethermind reads a null block parameter as latest.
    if (std.mem.eql(u8, raw, "null")) return head_header(api).number;
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    return resolve_number_text(api, call, raw[1 .. raw.len - 1]);
}

/// A block tag or hex number, without quotes.
fn resolve_number_text(api: *Api, call: *Call, text: []const u8) HandlerError!u64 {
    const number = try number_of_tag(api, text);
    if (number > head_header(api).number) {
        return call.fail(rpc.code.server_error, "block not found");
    }
    return number;
}

/// A block tag or hex number, without quotes; a number may lie beyond the head. The empty
/// string is latest, as Nethermind reads it.
fn number_of_tag(api: *Api, text: []const u8) HandlerError!u64 {
    const head = head_header(api).number;
    if (text.len == 0) return head;
    if (std.mem.eql(u8, text, "latest") or std.mem.eql(u8, text, "pending")) return head;
    if (std.mem.eql(u8, text, "earliest")) return api.chain.genesis_number;
    if (std.mem.eql(u8, text, "safe") or std.mem.eql(u8, text, "finalized")) {
        const fc = api.chain.forkchoice;
        const safe = std.mem.eql(u8, text, "safe");
        const hash = if (safe) fc.safe_block_hash else fc.finalized_block_hash;
        const stored = api.chain.store.ref(hash.bytes) orelse return api.chain.genesis_number;
        return stored.number;
    }
    return json.parse_quantity(u64, text) catch return error.InvalidParams;
}

fn write_block(api: *Api, call: *Call, hash: Hash, full: bool) HandlerError!void {
    const bytes = api.chain.store.record(hash) orelse return call.writer.null_value();
    const record = node.chain.Record.decode(bytes) catch unreachable; // Stored by the chain.
    const size = block_size(record);
    try format.block(call.writer, record, hash, size, full, api.chain.executor.recoverer);
}

/// The block's RLP length, `rlp([header, transactions, ommers, withdrawals?])`, as a block
/// object's `size` reports it. A legacy transaction is a list in the body; a typed one is a
/// byte string.
fn block_size(record: node.chain.Record) usize {
    var transactions = record.transactions;
    var transactions_payload: usize = 0;
    while (!transactions.is_empty()) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        assert(raw.len > 0);
        transactions_payload += if (raw[0] >= 0xc0) raw.len else rlp.bytes_length(raw);
    }
    var payload = rlp.length(record.header) + rlp.list_length(transactions_payload) +
        rlp.list_length(0);
    if (record.withdrawals) |withdrawals| payload += withdrawals.rlp_length();
    return rlp.list_length(payload);
}

fn get_block_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    const full = try call.params.absent_or_boolean() orelse false;
    const hash = resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.writer.null_value(),
        else => return err,
    };
    try write_block(api, call, hash, full);
}

fn get_block_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.hash();
    const full = try call.params.absent_or_boolean() orelse false;
    try write_block(api, call, hash, full);
}

// ---- Transactions and receipts ----------------------------------------------------

fn get_transaction_by_hash(api: *Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.hash();
    try call.params.finish();
    const recoverer = api.chain.executor.recoverer;
    if (api.chain.find_transaction(tx_hash)) |location| {
        const record = api.chain.record(location.block_hash).?;
        const raw = nth_transaction(record, location.index);
        return format.transaction(call.writer, raw, .{
            .block_hash = location.block_hash,
            .block_number = record.header.number,
            .index = location.index,
            .base_fee = record.header.base_fee_per_gas,
            .timestamp_ms = format.timestamp_ms(record),
            .timestamp = record.header.timestamp,
            .deposit = format.deposit_receipt(record, location.index),
        }, recoverer);
    }
    const pool = api.pool orelse return call.writer.null_value();
    const tx = pool.get(.{ .bytes = tx_hash }) orelse return call.writer.null_value();
    try format.transaction(call.writer, node.chain.canonical_form(tx.raw, api.scratch) catch {
        return call.fail(rpc.code.internal_error, "transaction too large");
    }, null, recoverer);
}

fn nth_transaction(record: node.chain.Record, index: u32) []const u8 {
    var transactions = record.transactions;
    for (0..index) |_| _ = transactions.bytes() catch unreachable;
    return transactions.bytes() catch unreachable;
}

fn get_transaction_receipt(api: *Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.hash();
    try call.params.finish();
    if (!try write_receipt(api, call.writer, tx_hash)) try call.writer.null_value();
}

/// Writes the receipt of canonical transaction `tx_hash`; false (nothing written) if unknown.
pub fn write_receipt(api: *Api, w: *json.Writer, tx_hash: Hash) HandlerError!bool {
    const location = api.chain.find_transaction(tx_hash) orelse return false;
    try block_receipts(api, w, location.block_hash, location.index);
    return true;
}

fn get_block_receipts(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    const hash = resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.writer.null_value(),
        else => return err,
    };
    try call.writer.begin_array();
    try block_receipts(api, call.writer, hash, null);
    try call.writer.end_array();
}

/// Writes the receipt at `only` (or every receipt) of the block `hash`.
fn block_receipts(api: *Api, w: *json.Writer, hash: Hash, only: ?u32) HandlerError!void {
    const record = api.chain.record(hash).?;
    const recoverer = api.chain.executor.recoverer;
    try format.block_receipts(w, api.spec, recoverer, record, hash, only);
}

fn send_raw_transaction(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.data(api.scratch[0 .. api.scratch.len / 2]);
    try call.params.finish();
    const hash = try add_raw(api, call, raw);
    try call.writer.data(&hash);
}

/// Validates `raw` (decoded into the first half of the scratch) and adds it to the pool.
pub fn add_raw(api: *Api, call: *Call, raw: []const u8) HandlerError!Hash {
    return switch (add_raw_checked(api, raw, null)) {
        .added => |hash| hash,
        .failed => |failure| call.fail(failure.code, failure.message),
    };
}

pub const AddFailure = struct {
    code: i32,
    /// What failed (a static error name or message).
    message: []const u8,
    /// Set when the pool refused the transaction (as opposed to validation).
    pool_error: ?anyerror = null,
};

pub const AddResult = union(enum) { added: Hash, failed: AddFailure };

/// `add_raw` reporting its failure instead of answering the call; `known_sender` skips
/// signature recovery for a caller that already recovered it.
pub fn add_raw_checked(api: *Api, raw: []const u8, known_sender: ?primitives.Address) AddResult {
    const half = api.scratch.len / 2;
    assert(raw.len <= half);
    const pool = api.pool orelse {
        return fail_add(rpc.code.server_error, "transaction pool disabled");
    };
    const head = head_header(api);
    const validated = txpool.validate.validate_known(
        raw,
        api.scratch[half..],
        api.spec,
        head.timestamp + 1,
        api.chain.executor.recoverer,
        known_sender,
    ) catch |err| return fail_add(rpc.code.server_error, @errorName(err));
    if (validated.sidecar != null) {
        if (api.kzg) |verifier| txpool.validate.verify_blob_proofs(raw, verifier) catch |err| {
            return fail_add(rpc.code.server_error, @errorName(err));
        };
    }
    api.chain.ensure_head_state() catch {
        return fail_add(rpc.code.internal_error, "head state unavailable");
    };
    const account: txpool.Account = if (validated.lane) |lane|
        api.chain.lane_account(lane)
    else if (api.chain.db.get_account(validated.tx.sender.bytes)) |a|
        .{ .nonce = a.nonce, .balance = a.balance }
    else
        .{ .nonce = 0, .balance = 0 };
    _ = pool.add(validated.tx, account) catch |err| {
        var failure = fail_add(rpc.code.server_error, @errorName(err)).failed;
        failure.pool_error = err;
        return .{ .failed = failure };
    };
    if (api.filters) |filters| filters.note_pending(validated.tx.hash.bytes);
    return .{ .added = validated.tx.hash.bytes };
}

fn fail_add(code: i32, message: []const u8) AddResult {
    assert(message.len > 0);
    return .{ .failed = .{ .code = code, .message = message } };
}

// ---- Calls ------------------------------------------------------------------------

pub fn parse_call(
    space: []u8,
    raw: []const u8,
    recoverer: consensus.Recoverer,
) HandlerError!node.executor.Executor.Call {
    var result: node.executor.Executor.Call = .{};
    var scanner = json.Scanner.init(raw);
    var used: usize = 0;
    if ((try scanner_next(&scanner)).tag != .object_begin) return error.InvalidParams;
    while (true) {
        const name = try scanner_next(&scanner);
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = try scanner_next(&scanner);
        if (value.tag == .null) continue;
        const text = value.bytes;
        if (std.mem.eql(u8, name.bytes, "accessList")) {
            result.access_list = try parse_access_list(&scanner, value, space, &used);
        } else if (std.mem.eql(u8, name.bytes, "authorizationList")) {
            const list = try parse_authorizations(&scanner, value, space, &used, recoverer);
            result.authorization_list = list;
        } else if (std.mem.eql(u8, name.bytes, "from")) {
            result.from = json.parse_fixed(20, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "to")) {
            result.to = json.parse_fixed(20, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "gas")) {
            result.gas = json.parse_quantity(u64, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "value")) {
            result.value = json.parse_quantity(u256, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "data") or std.mem.eql(u8, name.bytes, "input")) {
            if (value.tag != .string) return error.InvalidParams;
            // alloy's `Bytes`, like geth's hexutil.Bytes, reads "" as empty.
            if (text.len == 0) {
                result.data = &.{};
                continue;
            }
            const data = json.parse_data(text, space[used..]) catch return error.InvalidParams;
            result.data = data;
            used += data.len;
        } else if (std.mem.eql(u8, name.bytes, "blobVersionedHashes")) {
            result.blob_hashes = try parse_blob_hashes(&scanner, value, space, &used);
        } else if (std.mem.eql(u8, name.bytes, "maxFeePerBlobGas")) {
            if (value.tag != .string) return error.InvalidParams;
            result.max_fee_per_blob_gas = json.parse_quantity(u256, text) catch
                return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "chainId")) {
            // Checked against the chain's by the EVM (revm `InvalidChainId`).
            if (value.tag != .string) return error.InvalidParams;
            result.chain_id = json.parse_quantity(u64, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "type")) {
            // alloy reads `type` as a u8 quantity; the request's fields pick the type.
            if (value.tag != .string) return error.InvalidParams;
            _ = json.parse_quantity(u8, text) catch return error.InvalidParams;
        } else {
            if (!typed_field_valid(name.bytes, value)) return error.InvalidParams;
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
    return result;
}

/// Nethermind binds a call object as a `TransactionForRpc`, typing members the call does
/// not use: a nonce (`ulong`), `v`, `r`, `s` (`UInt256`), `hash` and `blockHash`
/// (`Hash256`), `blockNumber`, `blockTimestamp` (`ulong`) and `transactionIndex` (`long`).
/// A value of the wrong type (a block tag as a nonce) refuses the request. Other members are
/// not checked here.
fn typed_field_valid(name: []const u8, value: json.Token) bool {
    const Field = struct { name: []const u8, bits: u16 };
    const quantities = [_]Field{
        .{ .name = "nonce", .bits = 64 },
        .{ .name = "v", .bits = 256 },
        .{ .name = "r", .bits = 256 },
        .{ .name = "s", .bits = 256 },
        .{ .name = "blockNumber", .bits = 64 },
        .{ .name = "blockTimestamp", .bits = 64 },
        .{ .name = "transactionIndex", .bits = 63 },
    };
    for (quantities) |field| {
        if (std.ascii.eqlIgnoreCase(name, field.name)) {
            return lenient_quantity_valid(value, field.bits);
        }
    }
    if (std.ascii.eqlIgnoreCase(name, "hash") or std.ascii.eqlIgnoreCase(name, "blockHash")) {
        if (value.tag != .string) return false;
        _ = json.parse_hash(value.bytes) catch return false;
    }
    return true;
}

/// A number as Nethermind's `ULongConverter` and `UInt256Converter` read one: a JSON
/// number, or a string of `0x` and hex digits (leading zeros allowed) or of decimal digits,
/// fitting `bits` bits.
fn lenient_quantity_valid(value: json.Token, bits: u16) bool {
    assert(bits > 0 and bits <= 256);
    const text = value.bytes;
    if (value.tag != .string and value.tag != .number) return false;
    const hex = value.tag == .string and text.len >= 2 and text[0] == '0' and text[1] == 'x';
    const digits = if (hex) text[2..] else text;
    if (digits.len == 0) return hex;
    const radix: u8 = if (hex) 16 else 10;
    // `parseUnsigned` also takes `_` separators; .NET does not.
    for (digits) |digit| _ = std.fmt.charToDigit(digit, radix) catch return false;
    const parsed = std.fmt.parseUnsigned(u256, digits, radix) catch return false;
    if (bits == 256) return true;
    return parsed >> @intCast(bits) == 0;
}

/// A request's `blobVersionedHashes` (each a `B256`), stored in `space` after `used`.
fn parse_blob_hashes(
    scanner: *json.Scanner,
    first: json.Token,
    space: []u8,
    used: *usize,
) HandlerError![]const [32]u8 {
    if (first.tag != .array_begin) return error.InvalidParams;
    const start = used.*;
    var count: usize = 0;
    while (true) : (count += 1) {
        const token = try scanner_next(scanner);
        if (token.tag == .array_end) break;
        if (token.tag != .string) return error.InvalidParams;
        if (start + (count + 1) * 32 > space.len) return error.InvalidParams;
        space[start + count * 32 ..][0..32].* = json.parse_hash(token.bytes) catch
            return error.InvalidParams;
    }
    used.* = start + count * 32;
    assert(used.* <= space.len);
    return std.mem.bytesAsSlice([32]u8, space[start..used.*]);
}

const Authorization = evm.transaction.Authorization;

/// A request's EIP-7702 authorizations (`chainId`, `address`, `nonce` and `yParity` (alias
/// `v`) required; `r` and `s` zero when absent, as Nethermind's `RpcAuthTuple` defaults
/// them), with each authority recovered as a transaction's are (none for a zero
/// signature); stored in `space` after `used`.
fn parse_authorizations(
    scanner: *json.Scanner,
    first: json.Token,
    space: []u8,
    used: *usize,
    recoverer: consensus.Recoverer,
) HandlerError![]const Authorization {
    if (first.tag != .array_begin) return error.InvalidParams;
    var probe = scanner.*;
    var count: usize = 0;
    while (try signed_authorization(&probe)) |_| count += 1;
    const start = std.mem.alignForward(usize, used.*, @alignOf(Authorization));
    const bytes = count * @sizeOf(Authorization);
    if (start + bytes > space.len) return error.InvalidParams;
    const list: []Authorization = @alignCast(std.mem.bytesAsSlice(
        Authorization,
        space[start..][0..bytes],
    ));
    for (list) |*out| {
        const signed = (try signed_authorization(scanner)).?;
        const authority = signed.recover_authority(recoverer);
        out.* = .{
            .chain_id = signed.chain_id,
            .address = signed.address.bytes,
            .nonce = signed.nonce,
            .authority = if (authority) |a| a.bytes else null,
        };
    }
    if ((try scanner_next(scanner)).tag != .array_end) return error.InvalidParams;
    used.* = start + bytes;
    return list;
}

/// One signed authorization object, or null at the list's end.
pub fn signed_authorization(
    scanner: *json.Scanner,
) HandlerError!?consensus.tx_fields.Authorization {
    const open = try scanner_next(scanner);
    if (open.tag == .array_end) return null;
    if (open.tag != .object_begin) return error.InvalidParams;
    var fields: [6]?[]const u8 = @splat(null);
    const names = [_][]const u8{ "chainId", "address", "nonce", "yParity", "r", "s" };
    while (true) {
        const name = try scanner_next(scanner);
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = try scanner_next(scanner);
        const key = if (std.mem.eql(u8, name.bytes, "v")) "yParity" else name.bytes;
        for (names, 0..) |known, index| {
            if (!std.mem.eql(u8, key, known)) continue;
            if (value.tag != .string or fields[index] != null) return error.InvalidParams;
            fields[index] = value.bytes;
            break;
        } else scanner.skip(value) catch return error.InvalidParams;
    }
    for (fields[0..4]) |field| if (field == null) return error.InvalidParams;
    const quantity = json.parse_quantity;
    const r = if (fields[4]) |text| quantity(u256, text) catch return error.InvalidParams else 0;
    const s = if (fields[5]) |text| quantity(u256, text) catch return error.InvalidParams else 0;
    assert(fields[4] != null or r == 0);
    return .{
        .chain_id = quantity(u256, fields[0].?) catch return error.InvalidParams,
        .address = .{ .bytes = json.parse_fixed(20, fields[1].?) catch return error.InvalidParams },
        .nonce = quantity(u64, fields[2].?) catch return error.InvalidParams,
        .y_parity = quantity(u8, fields[3].?) catch return error.InvalidParams,
        .r = r,
        .s = s,
    };
}

const AccessListItem = evm.transaction.AccessListItem;

/// A request's EIP-2930 access list (Nethermind's `AccessListForRpc`: every item needs
/// `address`; `storageKeys` may be absent or null, and each key is `0x` and 1 to 64 hex
/// digits), stored in `space` after `used`. Counted on a copy of the scanner first.
fn parse_access_list(
    scanner: *json.Scanner,
    first: json.Token,
    space: []u8,
    used: *usize,
) HandlerError![]const AccessListItem {
    if (first.tag != .array_begin) return error.InvalidParams;
    var probe = scanner.*;
    var items_count: usize = 0;
    var keys_count: usize = 0;
    while (try access_list_item(&probe, null, null)) |keys| {
        items_count += 1;
        keys_count += keys;
    }
    const start = std.mem.alignForward(usize, used.*, @alignOf(AccessListItem));
    const items_bytes = items_count * @sizeOf(AccessListItem);
    const keys_bytes = keys_count * @sizeOf([32]u8);
    if (start + items_bytes + keys_bytes > space.len) return error.InvalidParams;
    const items: []AccessListItem = @alignCast(std.mem.bytesAsSlice(
        AccessListItem,
        space[start..][0..items_bytes],
    ));
    const keys: [][32]u8 = @alignCast(std.mem.bytesAsSlice(
        [32]u8,
        space[start + items_bytes ..][0..keys_bytes],
    ));
    var keys_used: usize = 0;
    for (items) |*item| {
        const count = (try access_list_item(scanner, item, keys[keys_used..])).?;
        keys_used += count;
    }
    assert(keys_used == keys_count);
    if ((try scanner_next(scanner)).tag != .array_end) return error.InvalidParams;
    used.* = start + items_bytes + keys_bytes;
    return items;
}

/// Reads one access list item (null at the list's end) and returns its key count; with
/// `item`, fills it, its keys in `keys`.
fn access_list_item(
    scanner: *json.Scanner,
    item: ?*AccessListItem,
    keys: ?[][32]u8,
) HandlerError!?usize {
    const open = try scanner_next(scanner);
    if (open.tag == .array_end) return null;
    if (open.tag != .object_begin) return error.InvalidParams;
    var address: ?[20]u8 = null;
    var count: usize = 0;
    while (true) {
        const name = try scanner_next(scanner);
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = try scanner_next(scanner);
        if (std.mem.eql(u8, name.bytes, "address")) {
            if (value.tag != .string) return error.InvalidParams;
            address = json.parse_fixed(20, value.bytes) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "storageKeys")) {
            if (value.tag == .null) continue;
            if (value.tag != .array_begin) return error.InvalidParams;
            var index: usize = 0;
            while (true) : (index += 1) {
                const key = try scanner_next(scanner);
                if (key.tag == .array_end) break;
                if (key.tag != .string) return error.InvalidParams;
                const bytes = eth_proof.parse_slot_key(key.bytes) orelse
                    return error.InvalidParams;
                if (keys) |out| out[index] = bytes;
            }
            count = index;
        } else scanner.skip(value) catch return error.InvalidParams;
    }
    const keys_count = count;
    if (item) |out| out.* = .{
        .address = address orelse return error.InvalidParams,
        .storage_keys = keys.?[0..keys_count],
    };
    if (address == null) return error.InvalidParams;
    return keys_count;
}

/// A call request with the state it runs against. The block is resolved before the
/// call object is parsed, so call data of a historical call stays clear of the proof
/// buffers at the scratch tail.
pub const CallRequest = struct {
    message: node.executor.Executor.Call,
    view: state_view.View,
    /// The block tag was "pending": the call runs in a block after the head.
    pending: bool = false,
    /// eth_call and eth_estimateGas: a "pending" call runs at the Denim schedule's time for
    /// the block after the head, with that block's BaseTime millisecond part (base/base
    /// `BasePendingForecast`); other methods keep reth's head + 12 seconds.
    forecast: bool = false,
    /// The request's fee fields (`call_fees`), applied when the call runs.
    fees: call_fees.Fees = .{},
    /// Raw geth `stateOverrides` / `blockOverrides` objects (see `set_overrides`).
    state_overrides: ?[]const u8 = null,
    block_overrides: ?[]const u8 = null,
    /// Scratch after the call data for override code (hex decodes to half its text).
    override_space: []u8 = &.{},
};

fn present(raw: ?[]const u8) ?[]const u8 {
    const text = raw orelse return null;
    return if (std.mem.eql(u8, text, "null")) null else text;
}

/// The scratch end usable by a call request (the proof buffers sit past it in a
/// historical view).
fn request_scratch_end(api: *Api, view: state_view.View) usize {
    return switch (view) {
        .head => api.scratch.len,
        .historical => proof_tail_offset(api).?, // Checked when the request was parsed.
    };
}

/// Scratch bytes a parsed request occupies (call data, then override code space).
pub fn scratch_used(api: *Api, request: *const CallRequest) usize {
    const base = @intFromPtr(api.scratch.ptr);
    const space = request.override_space;
    if (space.len > 0) return @intFromPtr(space.ptr) - base + space.len;
    // The call data and access list `parse_call` stored, in either order.
    const message = &request.message;
    var end: usize = 0;
    if (message.data.len > 0) end = @intFromPtr(message.data.ptr) + message.data.len;
    if (message.access_list.len > 0) {
        const items = std.mem.sliceAsBytes(message.access_list);
        end = @max(end, @intFromPtr(items.ptr) + items.len);
    }
    for (message.access_list) |item| {
        const keys = std.mem.sliceAsBytes(item.storage_keys);
        if (keys.len > 0) end = @max(end, @intFromPtr(keys.ptr) + keys.len);
    }
    if (message.authorization_list) |list| {
        const bytes = std.mem.sliceAsBytes(list);
        if (bytes.len > 0) end = @max(end, @intFromPtr(bytes.ptr) + bytes.len);
    }
    const blobs = std.mem.sliceAsBytes(message.blob_hashes);
    if (blobs.len > 0) end = @max(end, @intFromPtr(blobs.ptr) + blobs.len);
    return if (end == 0) 0 else end - base;
}

/// Attaches state and block overrides (raw JSON, "null" or absent for none).
pub fn set_overrides(
    api: *Api,
    call: *Call,
    request: *CallRequest,
    state_overrides: ?[]const u8,
    block_overrides: ?[]const u8,
) HandlerError!void {
    request.block_overrides = present(block_overrides);
    request.state_overrides = present(state_overrides);
    const state = request.state_overrides orelse return;
    const start = scratch_used(api, request);
    const end = request_scratch_end(api, request.view);
    const size = state.len / 2 + 32;
    if (start + size > end) return call.fail(rpc.code.invalid_params, "overrides too large");
    request.override_space = api.scratch[start..][0..size];
    if (try simulate_module.both_state_and_diff(state)) |address| {
        // reth `EthApiError::BothStateAndStateDiffInOverride`; the call data is done with.
        const message = simulate_module.both_state_message(api.scratch, address);
        return call.fail(rpc.code.invalid_params, message);
    }
}

/// The executor's `prepare` hook of an RPC call: applies the state overrides, then for a
/// priced call reads the caller's gas allowance and caps the gas with it (reth
/// `caller_gas_allowance` in `prepare_call_env` and the estimate).
pub const Prepared = struct {
    raw: []const u8 = "",
    space: []u8 = &.{},
    failure: ?simulate_module.OverrideError = null,
    gas_price: u256 = 0,
    cap: Cap = .none,
    /// Records whether the callee has code (eth_estimateGas's transfer test).
    check_callee: bool = false,
    callee_code: bool = false,
    /// The caller's balance, read when `cap` is set.
    balance: u256 = 0,
    /// What the caller can afford; null when the balance does not cover `value`.
    allowance: ?u64 = null,
    /// A forecast call's BaseTime millisecond part, written beneath the state overrides.
    millis_part: ?u16 = null,

    pub const Cap = enum {
        none,
        /// Caps the gas the call was given (an eth_call that named none).
        allowance,
    };

    fn run(context: *anyopaque, state: *evm.State, message: *node.executor.Executor.Call) void {
        const prepared: *Prepared = @ptrCast(@alignCast(context));
        prepared.apply(state, message) catch |err| {
            prepared.failure = err;
        };
    }

    fn apply(
        prepared: *Prepared,
        state: *evm.State,
        message: *node.executor.Executor.Call,
    ) simulate_module.OverrideError!void {
        if (prepared.millis_part) |part| try forecast_base_time(state, part);
        if (prepared.raw.len > 0) {
            try simulate_module.apply_state_overrides(state, prepared.space, prepared.raw);
        }
        if (prepared.check_callee) if (message.to) |to| {
            prepared.callee_code = (try state.load(to)).info.has_code();
        };
        if (prepared.cap == .none) return;
        assert(prepared.gas_price > 0);
        const caller = try state.load(message.from);
        prepared.balance = caller.info.balance;
        const balance = caller.info.balance;
        prepared.allowance = call_fees.allowance(balance, message.value, prepared.gas_price);
        message.gas = @min(message.gas.?, prepared.allowance orelse 0);
    }

    fn hooked(prepared: *const Prepared) bool {
        return prepared.raw.len > 0 or prepared.check_callee or prepared.cap != .none or
            prepared.millis_part != null;
    }
};

/// Installs BaseTime and stores `millis_part` in the low 16 bits of its packed slot, as the
/// synthetic override base/base puts beneath a forecast call's own overrides (which then
/// win per slot, or wholesale for a `state` override).
fn forecast_base_time(state: *evm.State, millis_part: u16) simulate_module.OverrideError!void {
    const base_time = node.base_time;
    base_time.ensure_predeploy(state) catch |err| switch (err) {
        // A Denim chain installed BaseTime at activation; its proxy cannot be missing.
        error.BaseTimeMissingProxy,
        error.BaseTimeCodelessProxy,
        error.BaseTimeUnexpectedProxyAdmin,
        => return error.InvalidParams,
        else => |e| return e,
    };
    const proxy = try state.load(base_time.proxy_address);
    const access = try state.storage_access(proxy, base_time.millis_part_slot);
    const word = access.slot.present & ~@as(u256, std.math.maxInt(u16));
    try state.storage_write(proxy, access.slot, word | millis_part);
}

pub fn parse_call_request(api: *Api, call: *Call) HandlerError!CallRequest {
    const call_raw = try call.params.raw();
    const block_raw = try call.params.optional_raw();
    const view = try state_view.resolve(api, call, block_raw);
    const space = switch (view) {
        .head => api.scratch,
        .historical => api.scratch[0 .. proof_tail_offset(api) orelse {
            return call.fail(rpc.code.internal_error, "proof scratch too small");
        }],
    };
    const message = try parse_call(space, call_raw, api.chain.executor.recoverer);
    return .{
        .message = message,
        .view = view,
        .pending = if (block_raw) |raw| std.mem.eql(u8, raw, "\"pending\"") else false,
        .fees = try call_fees.parse(call_raw),
    };
}

/// Where the proof buffers of a historical call start (aligned, at the scratch tail).
pub fn proof_tail_offset(api: *Api) ?usize {
    const size = @sizeOf(eth_proof.Scratch);
    if (api.scratch.len < size + @alignOf(eth_proof.Scratch)) return null;
    const base = @intFromPtr(api.scratch.ptr);
    const alignment = @alignOf(eth_proof.Scratch);
    const start = std.mem.alignBackward(usize, base + api.scratch.len - size, alignment);
    assert(start >= base);
    return start - base;
}

pub fn view_header(api: *Api, view: state_view.View) consensus.Header {
    return switch (view) {
        .head => head_header(api),
        .historical => |block| api.chain.header(block.hash).?, // Resolved, so stored.
    };
}

/// The block a call request runs in, with block overrides. As reth's `evm_env_at`: a block's
/// own environment on its post-state, or for "pending" (base/base has no pending block) the
/// next block derived from the head (`BaseNextBlockEnvAttributes::build_pending_env`).
pub fn request_env(
    api: *Api,
    call: *Call,
    request: *const CallRequest,
) HandlerError!node.executor.BlockEnv {
    const header = view_header(api, request.view);
    var env = node.chain.env_of(&header);
    if (request.pending) {
        assert(request.view == .head);
        env.number = header.number + 1;
        env.timestamp = if (pending_forecast(api, request)) |parts|
            parts.seconds
        else
            header.timestamp +| 12;
        env.parent_hash = header.hash().bytes;
        env.base_fee = next_base_fee_after(api, &header, @max(env.timestamp, header.timestamp));
        env.prev_randao = @splat(0); // base/base draws it at random.
        // The beacon root stays the parent's, as build_pending_env copies it.
    }
    if (request.block_overrides) |raw| try simulate_module.apply_block_overrides(call, &env, raw);
    return env;
}

/// base/base `BasePendingForecast::successor`: the scheduled time of the block after the
/// head, for a "pending" eth_call or eth_estimateGas on a chain with a Denim schedule.
pub fn pending_forecast(api: *Api, request: *const CallRequest) ?node.base_time.Schedule.Parts {
    if (!request.pending or !request.forecast) return null;
    const schedule = api.chain.denim_schedule() orelse return null;
    return schedule.parts(view_header(api, request.view).number + 1);
}

/// The BaseTime millisecond part a forecast call sees, once Denim is active at its time
/// (base/base `BasePendingForecast::state_overrides`).
pub fn forecast_millis_part(api: *Api, request: *const CallRequest) ?u16 {
    const parts = pending_forecast(api, request) orelse return null;
    if (!api.spec.is_upgrade_active(.denim, parts.seconds)) return null;
    return parts.millis_part;
}

/// The prices of a call under `base_fee` (reth `CallFees::ensure_fees`).
pub fn call_prices(call: *Call, fees: call_fees.Fees, base_fee: u64) HandlerError!call_fees.Prices {
    return switch (call_fees.ensure(fees, base_fee)) {
        .prices => |prices| prices,
        .failure => |failure| call.fail(failure.code, failure.message),
    };
}

/// Runs a call request as reth's `prepare_call_env` sets it up: priced by its fee fields
/// (an unpriced call runs with a zero base fee), and when priced without a gas limit
/// capped at what the caller can afford.
pub fn simulate(
    api: *Api,
    call: *Call,
    request: CallRequest,
) HandlerError!node.executor.Executor.Simulated {
    const env = try request_env(api, call, &request);
    const prices = try call_prices(call, request.fees, env.base_fee);
    var message = request.message;
    message.gas_price = prices.gas_price;
    message.priority_fee = prices.priority_fee;
    message.keep_base_fee = prices.gas_price != 0;
    var prepared: Prepared = .{
        .raw = request.state_overrides orelse "",
        .space = request.override_space,
        .gas_price = prices.gas_price,
        .millis_part = forecast_millis_part(api, &request),
    };
    // The gas cap bounds a given gas silently and is the default; the block's gas limit
    // does not bound it (reth `prepare_call_env`) unless the allowance caps the default.
    message.gas = @min(request.message.gas orelse rpc_gas_cap, rpc_gas_cap);
    if (request.message.gas == null and prices.gas_price > 0) {
        message.gas = @min(rpc_gas_cap, env.gas_limit);
        prepared.cap = .allowance;
    }
    return run_prepared(api, call, request.view, &env, message, &prepared);
}

/// Runs `message` with the `prepare` hook `prepared`, failing on its override or funds error.
pub fn run_prepared(
    api: *Api,
    call: *Call,
    view: state_view.View,
    env: *const node.executor.BlockEnv,
    message_in: node.executor.Executor.Call,
    prepared: *Prepared,
) HandlerError!node.executor.Executor.Simulated {
    var message = message_in;
    assert(message.prepare == null);
    if (prepared.hooked()) message.prepare = .{ .context = prepared, .run = Prepared.run };
    const simulated = try simulate_in(api, call, view, env, message);
    if (prepared.failure) |failure| switch (failure) {
        error.InvalidParams => return error.InvalidParams,
        else => return call.fail(rpc.code.invalid_params, "invalid state override"),
    };
    if (prepared.cap != .none and prepared.allowance == null) {
        // reth `InsufficientFunds` from `caller_gas_allowance`; the call data is done with.
        const message_text = std.fmt.bufPrint(
            api.scratch,
            "insufficient funds for gas * price + value: have {d} want {d}",
            .{ prepared.balance, message.value },
        ) catch "insufficient funds for gas * price + value";
        return call.fail(call_error.code_transaction_rejected, message_text);
    }
    return simulated;
}

/// Fails with reth's error for a call the EVM rejected.
pub fn fail_invalid(call: *Call, reason: evm.transaction.Invalid) HandlerError {
    const failure = call_error.invalid(reason);
    return call.fail(failure.code, failure.message);
}

/// How an endpoint wraps a transaction error (Nethermind `ErrorWrapper`, as geth).
pub const Wrap = enum { call, estimate, trace };

/// Fails a call that names a tip but no fee cap with geth's `ErrTipAboveFeeCap` (the cap
/// stays zero, see `call_fees.tip_without_cap`), wrapped as `wrap` does with `gas`, the
/// gas the call was given (estimate: its highest run). The text goes to the scratch.
pub fn fail_tip_above_cap(
    api: *Api,
    call: *Call,
    from: [20]u8,
    tip: u256,
    wrap: Wrap,
    gas: u64,
) HandlerError {
    var inner_buffer: [256]u8 = undefined;
    const address = primitives.checksum(.{ .bytes = from }, null);
    const inner = std.fmt.bufPrint(&inner_buffer, "max priority fee per gas higher than max " ++
        "fee per gas: address {s}, maxPriorityFeePerGas: {d}, maxFeePerGas: 0", .{
        &address,
        tip,
    }) catch unreachable; // Proof: 120 bytes of text and a 78-digit u256.
    const text = switch (wrap) {
        .call => std.fmt.bufPrint(api.scratch, "err: {s} (supplied gas {d})", .{ inner, gas }),
        .estimate => std.fmt.bufPrint(api.scratch, "failed with {d} gas: {s}", .{ gas, inner }),
        .trace => std.fmt.bufPrint(api.scratch, "tracing failed: {s}", .{inner}),
    } catch inner;
    return call.fail(rpc.code.server_error, text);
}

/// Fails with reth's error for a call that reverted (code 3, the output as data) or halted
/// with `gas_limit`. The text goes to the scratch, whose call data is done with.
pub fn fail_executed(
    api: *Api,
    call: *Call,
    output: []const u8,
    exit: evm.evm.Exit,
    gas_limit: u64,
) HandlerError {
    assert(exit.status() != .success);
    if (exit.status() == .revert) {
        const message = call_error.revert_message(api.scratch, output);
        return call.fail_data(call_error.code_execution_error, message, output);
    }
    const failure = call_error.halt(api.scratch, exit, gas_limit);
    return call.fail(failure.code, failure.message);
}

fn simulate_in(
    api: *Api,
    call: *Call,
    view: state_view.View,
    env: *const node.executor.BlockEnv,
    message: node.executor.Executor.Call,
) HandlerError!node.executor.Executor.Simulated {
    const executor = api.chain.executor;
    const block = switch (view) {
        .head => {
            api.chain.ensure_head_state() catch {
                return call.fail(rpc.code.internal_error, "head state unavailable");
            };
            return executor.simulate(env, message) catch |err| {
                return call.fail(rpc.code.internal_error, @errorName(err));
            };
        },
        .historical => |block| block,
    };
    const offset = proof_tail_offset(api).?; // Checked when the request was parsed.
    const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
    var history: node.HistoryDatabase = .{
        .chain = api.chain,
        .hash = block.hash,
        .number = block.number,
        .account_proof = &proofs.account,
        .storage_proof = &proofs.storage,
    };
    return executor.simulate_on(env, message, history.database()) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
}

fn eth_call(api: *Api, call: *Call) HandlerError!void {
    try refuse_deposit(call);
    if (try eip8130_request(api, call, .call)) return;
    var request = try parse_call_request(api, call);
    request.forecast = true;
    const state_overrides = try call.params.optional_raw();
    const block_overrides = try call.params.optional_raw();
    try call.params.finish();
    try set_overrides(api, call, &request, state_overrides, block_overrides);
    if (call_fees.tip_without_cap(request.fees)) |tip| {
        const gas = @min(request.message.gas orelse rpc_gas_cap, rpc_gas_cap);
        return fail_tip_above_cap(api, call, request.message.from, tip, .call, gas);
    }
    switch (try simulate(api, call, request)) {
        .invalid => |reason| return fail_invalid(call, reason),
        .executed => |executed| {
            if (!executed.success) {
                return fail_executed(api, call, executed.output, executed.exit, executed.gas_used);
            }
            try call.writer.data(executed.output);
        },
    }
}

/// Nethermind binds the request of eth_call, eth_estimateGas and eth_createAccessList as a
/// `SignableTransactionForRpc`, which refuses a deposit (`type` 0x7e) before the call runs
/// (-32602 "invalid argument 0"). Params are left untouched.
pub fn refuse_deposit(call: *Call) HandlerError!void {
    var peek = call.params;
    if (try is_deposit(try peek.raw())) {
        return call.fail(rpc.code.invalid_params, "invalid argument 0");
    }
}

/// debug_traceCall and eth_simulateV1 take a deposit, but Nethermind's
/// `DepositTransactionForRpc` needs its `sourceHash`, `from`, `value` and `input` (no `data`
/// alias): the first one missing or null is refused with .NET's `ArgumentNullException`.
pub fn refuse_incomplete_deposit(call: *Call) HandlerError!void {
    var peek = call.params;
    if (try incomplete_deposit(try peek.raw())) |message| {
        return call.fail(rpc.code.invalid_params, message);
    }
}

/// The refusal of a deposit call object missing a field Nethermind requires, else null.
pub fn incomplete_deposit(call_raw: []const u8) HandlerError!?[]const u8 {
    if (!try is_deposit(call_raw)) return null;
    const required = [_][]const u8{ "sourceHash", "from", "value", "input" };
    const messages = [_][]const u8{
        "Value cannot be null. (Parameter 'SourceHash')",
        "Value cannot be null. (Parameter 'From')",
        "Value cannot be null. (Parameter 'Value')",
        "Value cannot be null. (Parameter 'Input')",
    };
    comptime assert(required.len == messages.len);
    for (required, messages) |field, message| {
        const value = json.find_path(call_raw, &.{field}) catch return error.InvalidParams;
        if (value == null or std.mem.eql(u8, value.?, "null")) return message;
    }
    return null;
}

fn is_deposit(call_raw: []const u8) HandlerError!bool {
    const value = (json.find_path(call_raw, &.{"type"}) catch return error.InvalidParams) orelse
        return false;
    // Any other malformed `type` is refused by `parse_call`.
    if (value.len < 2 or value[0] != '"' or value[value.len - 1] != '"') return false;
    const tx_type = json.parse_quantity(u8, value[1 .. value.len - 1]) catch return false;
    return tx_type == deposit_tx_type;
}

const deposit_tx_type: u8 = 0x7e;

/// Serves an EIP-8130 request (`eip8130_call`); false (params untouched) for a plain one.
fn eip8130_request(
    api: *Api,
    call: *Call,
    mode: eip8130_call.Mode,
) HandlerError!bool {
    var peek = call.params;
    const call_raw = try peek.raw();
    if (!eip8130_call.is_request(call_raw)) return false;
    const view = try state_view.resolve(api, call, try peek.optional_raw());
    try eip8130_call.handle(api, call, call_raw, view, mode);
    return true;
}

/// reth's estimate (`estimate.zig`).
fn estimate_gas(api: *Api, call: *Call) HandlerError!void {
    try refuse_deposit(call);
    if (try eip8130_request(api, call, .estimate)) return;
    var request = try parse_call_request(api, call);
    request.forecast = true;
    const state_overrides = try call.params.optional_raw();
    const block_overrides = try call.params.optional_raw();
    try call.params.finish();
    try set_overrides(api, call, &request, state_overrides, block_overrides);
    try call.writer.quantity(try @import("estimate.zig").estimate(api, call, &request));
}

// ---- Logs -------------------------------------------------------------------------

pub const Filter = struct {
    from: u64,
    to: u64,
    /// `toBlock` was a concrete number (not omitted or a tag): a polled filter stops there.
    to_given: bool = false,
    block_hash: ?Hash = null,
    /// `fromBlock` and `toBlock` named the same block by hash: that block alone, canonical or
    /// not (Nethermind's `LogFinder`).
    range_block: ?Hash = null,
    /// `fromBlock` or `toBlock` named an unknown block hash.
    missing_block: bool = false,
    addresses: [16][20]u8 = undefined,
    address_count: u32 = 0,
    /// Per position: allowed topics (empty = any).
    topics: [4][8]Hash = undefined,
    topic_counts: [4]u32 = @splat(0),

    pub fn matches(filter: *const Filter, item: consensus.Log) bool {
        if (filter.address_count > 0) {
            const ok = for (filter.addresses[0..filter.address_count]) |a| {
                if (std.mem.eql(u8, &a, &item.address.bytes)) break true;
            } else false;
            if (!ok) return false;
        }
        for (0..4) |position| {
            const count = filter.topic_counts[position];
            if (count == 0) continue;
            if (position >= item.topics.count()) return false;
            const topic = item.topics.get(position).bytes;
            const ok = for (filter.topics[position][0..count]) |t| {
                if (std.mem.eql(u8, &t, &topic)) break true;
            } else false;
            if (!ok) return false;
        }
        return true;
    }
};

fn parse_hashes(scanner: *json.Scanner, first: json.Token, out: [][32]u8) HandlerError!u32 {
    if (first.tag == .null) return 0;
    if (first.tag == .string) {
        out[0] = json.parse_hash(first.bytes) catch return error.InvalidParams;
        return 1;
    }
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (true) {
        const token = try scanner_next(scanner);
        if (token.tag == .array_end) return count;
        if (count == out.len or token.tag != .string) return error.InvalidParams;
        out[count] = json.parse_hash(token.bytes) catch return error.InvalidParams;
        count += 1;
    }
}

pub fn parse_filter(api: *Api, raw: []const u8) HandlerError!Filter {
    const head = head_header(api).number;
    var filter: Filter = .{ .from = head, .to = head };
    var scanner = json.Scanner.init(raw);
    if ((try scanner_next(&scanner)).tag != .object_begin) return error.InvalidParams;
    // alloy's `Filter`: null reads as absent, and a block hash excludes a range.
    var range_given = false;
    // The hashes `toBlock` (0) and `fromBlock` (1) named, if any.
    var bound_hashes: [2]?Hash = .{ null, null };
    while (true) {
        const name = try scanner_next(&scanner);
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = try scanner_next(&scanner);
        const block_field = std.mem.eql(u8, name.bytes, "fromBlock") or
            std.mem.eql(u8, name.bytes, "toBlock") or std.mem.eql(u8, name.bytes, "blockHash");
        if (block_field and value.tag == .null) continue;
        if (std.mem.eql(u8, name.bytes, "fromBlock") or std.mem.eql(u8, name.bytes, "toBlock")) {
            if (value.tag != .string) return error.InvalidParams;
            range_given = true;
            const from = name.bytes[0] == 'f';
            const bound = &bound_hashes[@intFromBool(from)];
            const number = try filter_bound(api, &filter, value.bytes, bound);
            if (from) filter.from = number else filter.to = number;
            if (!from) filter.to_given = std.mem.startsWith(u8, value.bytes, "0x");
        } else if (std.mem.eql(u8, name.bytes, "blockHash")) {
            filter.block_hash = json.parse_hash(value.bytes) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "address")) {
            filter.address_count = try parse_addresses(&scanner, value, &filter.addresses);
        } else if (std.mem.eql(u8, name.bytes, "topics")) {
            if (value.tag != .array_begin) return error.InvalidParams;
            var position: usize = 0;
            while (true) : (position += 1) {
                const entry = try scanner_next(&scanner);
                if (entry.tag == .array_end) break;
                if (position == 4) return error.InvalidParams;
                const allowed = &filter.topics[position];
                filter.topic_counts[position] = try parse_hashes(&scanner, entry, allowed);
            }
        } else scanner.skip(value) catch return error.InvalidParams;
    }
    if (range_given and filter.block_hash != null) return error.InvalidParams;
    if (bound_hashes[0]) |to_hash| if (bound_hashes[1]) |from_hash| {
        if (std.mem.eql(u8, &to_hash, &from_hash)) filter.range_block = to_hash;
    };
    return filter;
}

/// A `fromBlock` or `toBlock`: a tag, a number, or (Nethermind) a 32-byte block hash, read as
/// that block's number; `hash` keeps the hash.
fn filter_bound(api: *Api, filter: *Filter, text: []const u8, hash: *?Hash) HandlerError!u64 {
    if (text.len != 2 + 64) return number_of_tag(api, text);
    const named = json.parse_hash(text) catch return error.InvalidParams;
    hash.* = named;
    const header = api.chain.header(named) orelse {
        filter.missing_block = true;
        return 0;
    };
    return header.number;
}

fn parse_addresses(scanner: *json.Scanner, first: json.Token, out: *[16][20]u8) HandlerError!u32 {
    if (first.tag == .string) {
        out[0] = json.parse_fixed(20, first.bytes) catch return error.InvalidParams;
        return 1;
    }
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (true) {
        const token = try scanner_next(scanner);
        if (token.tag == .array_end) return count;
        if (count == out.len or token.tag != .string) return error.InvalidParams;
        out[count] = json.parse_fixed(20, token.bytes) catch return error.InvalidParams;
        count += 1;
    }
}

fn get_logs(api: *Api, call: *Call) HandlerError!void {
    const filter = try parse_filter(api, try call.params.raw());
    try call.params.finish();
    if (filter.missing_block) return call.fail(rpc.code.server_error, "block not found");
    const single = filter.block_hash orelse filter.range_block;
    if (single == null) {
        // reth's checks and texts, in its order.
        const head = head_header(api).number;
        var text: [128]u8 = undefined;
        if (filter.to > head) {
            const message = std.fmt.bufPrint(&text, "block range extends beyond current " ++
                "head block: requested {d}, head {d}", .{ filter.to, head }) catch unreachable;
            return call.fail(rpc.code.invalid_params, message);
        }
        if (filter.to < filter.from) {
            return call.fail(rpc.code.invalid_params, "invalid block range params");
        }
        // Numbers below genesis are unpruned history with no blocks (base/base answers []).
        if (filter.to - filter.from >= logs_blocks_max) {
            return call.fail(rpc.code.server_error, "block range too large");
        }
    }
    try call.writer.begin_array();
    var written: u32 = 0;
    if (single) |hash| {
        try block_logs(api, call, hash, &filter, &written);
    } else {
        var number = filter.from;
        while (number <= filter.to) : (number += 1) {
            const hash = api.chain.store.canonical_hash(number) orelse continue;
            try block_logs(api, call, hash, &filter, &written);
        }
    }
    try call.writer.end_array();
}

pub fn block_logs(
    api: *Api,
    call: *Call,
    hash: Hash,
    filter: *const Filter,
    written: *u32,
) HandlerError!void {
    const record = api.chain.record(hash) orelse return;
    if (record.header.logs_bloom.eql(.zero)) return; // No logs in the block.
    const block_ms = format.timestamp_ms(record);
    var transactions = record.transactions;
    var receipts = record.receipts;
    var index: u32 = 0;
    var log_index: u64 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable;
        const encoded = receipts.bytes() catch unreachable; // Stored by the chain.
        const value = consensus.Receipt.decode(encoded) catch unreachable;
        const at: format.Inclusion = .{
            .block_hash = hash,
            .block_number = record.header.number,
            .index = index,
            .base_fee = null,
            .timestamp_ms = block_ms,
            .timestamp = record.header.timestamp,
        };
        const tx_hash = primitives.keccak256(raw).bytes;
        var it = value.logs.iterator();
        while (it.next()) |item| : (log_index += 1) {
            if (!filter.matches(item)) continue;
            if (written.* == logs_max) return call.fail(rpc.code.server_error, "too many logs");
            try format.log(call.writer, item, at, tx_hash, log_index);
            written.* += 1;
        }
    }
}

test {
    _ = @import("call_error.zig");
    _ = @import("call_fees.zig");
    _ = @import("simulate_schedule.zig");
    _ = @import("eth_config.zig");
    _ = @import("access_list.zig");
    _ = @import("simulate.zig");
    _ = @import("simulate_block.zig");
    _ = @import("simulate_transfers.zig");
    _ = @import("eth_test.zig");
    _ = @import("send_sync.zig");
    _ = @import("debug_test.zig");
    _ = @import("debug_http_test.zig");
    _ = @import("debug_large_test.zig");
    _ = @import("eth_proof_test.zig");
}

test "eth: call object numbers read as Nethermind's converters read them" {
    const t = std.testing;
    const string = struct {
        fn of(text: []const u8) json.Token {
            return .{ .tag = .string, .bytes = text };
        }
    }.of;
    try t.expect(lenient_quantity_valid(string("0x01"), 64));
    try t.expect(lenient_quantity_valid(string("0x"), 64));
    try t.expect(lenient_quantity_valid(string("12"), 64));
    try t.expect(lenient_quantity_valid(.{ .tag = .number, .bytes = "7" }, 64));
    try t.expect(lenient_quantity_valid(string("0xffffffffffffffff"), 64));
    try t.expect(!lenient_quantity_valid(string("0x10000000000000000"), 64));
    try t.expect(!lenient_quantity_valid(string("0x8000000000000000"), 63));
    try t.expect(!lenient_quantity_valid(string("finalized"), 64));
    try t.expect(!lenient_quantity_valid(string("1_0"), 64));
    try t.expect(!lenient_quantity_valid(.{ .tag = .true }, 64));
    try t.expect(typed_field_valid("other", string("finalized")));
    try t.expect(!typed_field_valid("Nonce", string("finalized")));
    try t.expect(!typed_field_valid("blockHash", string("0x12")));
}

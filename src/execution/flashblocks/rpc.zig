//! Flashblocks JSON-RPC: pending-tag overrides of the eth namespace. Mirrors base/base
//! `rpc/eth.rs` (`EthApiExt`): with flashblocks state present, `"pending"` reads come from
//! the pending blocks and the executor-backed pending state; everything else falls through
//! to the node's eth handlers unchanged.
//!
//! - `eth_getBlockByNumber("pending")`: the latest pending block (header from its index-0
//!   base and latest delta, hash = the latest delta's block hash).
//! - `eth_getTransactionReceipt`: canonical first (base/base avoids the race after a
//!   canonical commit), then the pending receipts.
//! - `eth_getBalance` / `eth_getTransactionCount` / `eth_call` with `"pending"`: the
//!   pending state (the nonce is the pending account nonce, base/base's canonical count
//!   plus the flashblocks' count for that sender).
//! - `eth_subscribe` / `eth_unsubscribe`: flashblocks pubsub (`pubsub.zig`).
//!
//! The router is the node's eth method table with these entries replaced, over an `Api`
//! that wraps the node's `eth.Api`, so the eth lane stays untouched.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const eth = @import("../rpc/eth.zig");
const format = @import("../rpc/format.zig");
const ordered = @import("../trie/ordered.zig");
const pending_module = @import("pending.zig");
const state_executor = @import("state_executor.zig");
pub const pubsub = @import("pubsub.zig");

const Hash = [32]u8;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const WriteError = json.Writer.WriteError;
const ExecutorState = state_executor.ExecutorState;
const BlockRecord = state_executor.BlockRecord;

pub const Api = struct {
    eth: *eth.Api,
    pending: *const pending_module.PendingBlocks,
    state: *ExecutorState,
    /// Transaction slices for the pending block's transactions root (one per transaction
    /// a pending block can hold).
    items: [][]const u8,
    /// The connection's subscriptions (set by a WebSocket transport); null over HTTP.
    subscriptions: ?*pubsub.Subscriptions = null,
};

/// The latest pending block and its execution, when both exist and agree.
pub const View = struct {
    block: *const pending_module.Block,
    record: *const BlockRecord,
};

pub fn pending_view(api: *const Api) ?View {
    const block = api.pending.latest() orelse return null;
    const record = api.state.block_by_number(block.block_number) orelse return null;
    if (record.transaction_count != block.transaction_count) return null;
    assert(record.number == block.block_number);
    return .{ .block = block, .record = record };
}

const overrides = [_]rpc.Method(*Api){
    .{ .name = "eth_getBlockByNumber", .handler = get_block_by_number },
    .{ .name = "eth_getTransactionReceipt", .handler = get_transaction_receipt },
    .{ .name = "eth_getBalance", .handler = get_balance },
    .{ .name = "eth_getTransactionCount", .handler = get_transaction_count },
    .{ .name = "eth_call", .handler = eth_call },
    .{ .name = "eth_subscribe", .handler = pubsub.subscribe },
    .{ .name = "eth_unsubscribe", .handler = pubsub.unsubscribe },
};

pub const methods = build_methods();
pub const Router = rpc.Router(*Api, &methods);

fn build_methods() [eth.methods.len + extra_count()]rpc.Method(*Api) {
    @setEvalBranchQuota(64 * (eth.methods.len + overrides.len) * overrides.len + 1000);
    var list: [eth.methods.len + extra_count()]rpc.Method(*Api) = undefined;
    for (eth.methods, 0..) |method, index| {
        list[index] = override_of(method.name) orelse .{
            .name = method.name,
            .handler = delegate(method.handler),
        };
    }
    var count = eth.methods.len;
    for (overrides) |method| {
        if (in_eth(method.name)) continue;
        list[count] = method;
        count += 1;
    }
    assert(count == list.len);
    return list;
}

fn extra_count() usize {
    var count: usize = 0;
    for (overrides) |method| {
        if (!in_eth(method.name)) count += 1;
    }
    return count;
}

fn in_eth(comptime name: []const u8) bool {
    @setEvalBranchQuota(64 * eth.methods.len + 1000);
    for (eth.methods) |method| {
        if (std.mem.eql(u8, method.name, name)) return true;
    }
    return false;
}

fn override_of(comptime name: []const u8) ?rpc.Method(*Api) {
    for (overrides) |method| {
        if (std.mem.eql(u8, method.name, name)) return method;
    }
    return null;
}

fn eth_handler(comptime name: []const u8) *const fn (*eth.Api, *Call) HandlerError!void {
    @setEvalBranchQuota(64 * eth.methods.len + 1000);
    inline for (eth.methods) |method| {
        if (comptime std.mem.eql(u8, method.name, name)) return method.handler;
    }
    @compileError("no eth method " ++ name);
}

fn delegate(
    comptime handler: *const fn (*eth.Api, *Call) HandlerError!void,
) *const fn (*Api, *Call) HandlerError!void {
    return struct {
        fn run(api: *Api, call: *Call) HandlerError!void {
            return handler(api.eth, call);
        }
    }.run;
}

fn is_pending_tag(raw: ?[]const u8) bool {
    const text = raw orelse return false;
    return std.mem.eql(u8, text, "\"pending\"");
}

// ---- Handlers ---------------------------------------------------------------------

fn get_block_by_number(api: *Api, call: *Call) HandlerError!void {
    const saved = call.params;
    const tag = try call.params.raw();
    const full = try call.params.optional_boolean() orelse false;
    if (is_pending_tag(tag)) {
        if (pending_view(api)) |view| return write_block(api, call.writer, view, full);
    }
    call.params = saved;
    return (comptime eth_handler("eth_getBlockByNumber"))(api.eth, call);
}

fn get_transaction_receipt(api: *Api, call: *Call) HandlerError!void {
    const saved = call.params;
    const tx_hash = try call.params.fixed(32);
    try call.params.finish();
    if (api.eth.chain.find_transaction(tx_hash) == null) {
        if (api.state.find_transaction(.{ .bytes = tx_hash })) |position| {
            return write_receipt(api, call.writer, position);
        }
    }
    call.params = saved;
    return (comptime eth_handler("eth_getTransactionReceipt"))(api.eth, call);
}

fn get_balance(api: *Api, call: *Call) HandlerError!void {
    const saved = call.params;
    const address = try call.params.fixed(20);
    const tag = try call.params.optional_raw();
    if (is_pending_tag(tag) and pending_view(api) != null) {
        const account = api.state.account(address);
        return call.writer.quantity(if (account) |found| found.balance else 0);
    }
    call.params = saved;
    return (comptime eth_handler("eth_getBalance"))(api.eth, call);
}

fn get_transaction_count(api: *Api, call: *Call) HandlerError!void {
    const saved = call.params;
    const address = try call.params.fixed(20);
    const tag = try call.params.optional_raw();
    if (is_pending_tag(tag) and pending_view(api) != null) {
        const account = api.state.account(address);
        return call.writer.quantity(if (account) |found| found.nonce else 0);
    }
    call.params = saved;
    return (comptime eth_handler("eth_getTransactionCount"))(api.eth, call);
}

fn eth_call(api: *Api, call: *Call) HandlerError!void {
    const saved = call.params;
    _ = try call.params.raw();
    const tag = try call.params.optional_raw();
    call.params = saved;
    if (!is_pending_tag(tag) or pending_view(api) == null) {
        return (comptime eth_handler("eth_call"))(api.eth, call);
    }
    // "pending" resolves to the head for parsing; the call runs on the pending state.
    const request = try eth.parse_call_request(api.eth, call);
    const result = api.state.call(request.message) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    switch (result.?) {
        .invalid => |reason| return call.fail(rpc.code.server_error, @tagName(reason)),
        .executed => |executed| {
            if (!executed.success) return call.fail(3, "execution reverted");
            try call.writer.data(executed.output);
        },
    }
}

// ---- Pending block, transactions, receipts ----------------------------------------

/// The pending block's header: base fields from index 0, roots and gas from the latest
/// delta (base/base `block_assembler.rs`).
pub fn pending_header(api: *const Api, view: View) consensus.Header {
    const block = view.block;
    const base = &block.base;
    const spec = api.eth.spec;
    var header: consensus.Header = .{
        .parent_hash = base.parent_hash,
        .beneficiary = base.fee_recipient,
        .state_root = block.header.state_root,
        .transactions_root = transactions_root(api, block),
        .receipts_root = block.header.receipts_root,
        .logs_bloom = block.header.logs_bloom,
        .number = block.block_number,
        .gas_limit = base.gas_limit,
        .gas_used = block.header.gas_used,
        .timestamp = base.timestamp,
        .extra_data = base.extra_data(),
        .mix_hash = base.prev_randao,
        .base_fee_per_gas = view.record.env.base_fee,
        .withdrawals_root = block.header.withdrawals_root,
        .blob_gas_used = block.header.blob_gas_used orelse 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = base.parent_beacon_block_root,
    };
    if (spec.is_ethereum_fork_active(.prague, base.timestamp)) {
        header.requests_hash = consensus.block.empty_requests_hash;
    }
    assert(header.number == view.record.number);
    return header;
}

fn transactions_root(api: *const Api, block: *const pending_module.Block) primitives.B256 {
    assert(block.transaction_count <= api.items.len);
    const items = api.items[0..block.transaction_count];
    for (items, 0..) |*item, index| item.* = block.transaction(@intCast(index));
    return .{ .bytes = ordered.ordered_trie_root(items) };
}

/// The RLP size of the block (header, transactions, no ommers, withdrawals).
fn block_size(header: *const consensus.Header, block: *const pending_module.Block) usize {
    var transactions: usize = 0;
    for (0..block.transaction_count) |index| {
        transactions += rlp.bytes_length(block.transaction(@intCast(index)));
    }
    const withdrawal_size = 1 + 9 + 9 + 21 + 9;
    const withdrawals = block.withdrawal_count * rlp.list_length(withdrawal_size);
    const payload = header.rlp_length() + rlp.list_length(transactions) + rlp.list_length(0) +
        rlp.list_length(withdrawals);
    assert(payload > transactions);
    return rlp.list_length(payload);
}

pub fn inclusion(view: View, index: u32) format.Inclusion {
    assert(index < view.block.transaction_count);
    return .{
        .block_hash = view.record.hash.bytes,
        .block_number = view.block.block_number,
        .index = index,
        .base_fee = view.record.env.base_fee,
    };
}

/// The latest pending block object (transactions as objects with `full`).
pub fn write_block(api: *const Api, w: *json.Writer, view: View, full: bool) WriteError!void {
    const block = view.block;
    const header = pending_header(api, view);
    const recoverer = api.eth.chain.executor.recoverer;
    try w.begin_object();
    try format.header_fields(w, &header, view.record.hash.bytes, block_size(&header, block));
    try w.key("uncles");
    try w.begin_array();
    try w.end_array();
    try w.key("transactions");
    try w.begin_array();
    for (0..block.transaction_count) |index| {
        const position: u32 = @intCast(index);
        if (full) {
            const raw = block.transaction(position);
            try format.transaction(w, raw, inclusion(view, position), recoverer);
        } else {
            try w.data(&block.transaction_hashes[index].bytes);
        }
    }
    try w.end_array();
    try w.key("withdrawals");
    try w.begin_array();
    for (block.withdrawal_list()) |item| {
        try w.begin_object();
        try format.field_quantity(w, "index", item.index);
        try format.field_quantity(w, "validatorIndex", item.validator_index);
        try format.field_data(w, "address", &item.address.bytes);
        try format.field_quantity(w, "amount", item.amount_gwei);
        try w.end_object();
    }
    try w.end_array();
    try w.end_object();
}

/// The receipt context of the executed pending transaction at `position`.
pub fn receipt_context(api: *const Api, position: u32) ?format.ReceiptContext {
    const executed = api.state.transaction_at(position);
    const block = api.pending.get(executed.block_number) orelse return null;
    const record = api.state.block_by_number(executed.block_number) orelse return null;
    if (executed.index >= block.transaction_count) return null;
    const raw = block.transaction(executed.index);
    const envelope = consensus.Envelope.decode(raw) catch return null;
    const sender = envelope.recover_sender(api.eth.chain.executor.recoverer) orelse
        primitives.Address.zero;
    const to = envelope.kind().to();
    const base_fee = record.env.base_fee;
    const view: View = .{ .block = block, .record = record };
    assert(executed.hash.eql(block.transaction_hashes[executed.index]));
    return .{
        .inclusion = inclusion(view, executed.index),
        .tx_hash = executed.hash.bytes,
        .from = sender,
        .to = to,
        .contract_address = if (to == null)
            format.contract_address(sender, envelope.nonce() orelse 0)
        else
            null,
        .gas_used = executed.gas_used,
        .effective_gas_price = if (envelope == .deposit)
            0
        else
            envelope.effective_gas_price(base_fee) orelse 0,
        .first_log_index = executed.log_index,
        .blob_gas_used = 0,
        .blob_gas_price = null,
    };
}

fn write_receipt(api: *const Api, w: *json.Writer, position: u32) HandlerError!void {
    const context = receipt_context(api, position) orelse return w.null_value();
    try format.receipt(w, api.state.receipt_at(position).*, context);
}

comptime {
    assert(methods.len == eth.methods.len + 2);
    assert(override_of("eth_call") != null);
}

test {
    _ = @import("rpc_test.zig");
}

//! Flashblocks pubsub. Mirrors base/base `rpc/pubsub.rs` and `rpc/types.rs`: per-connection
//! `eth_subscribe` subscriptions to the pending state, notified after every flashblock.
//!
//! - `newFlashblocks`: the latest pending block with full transactions.
//! - `pendingLogs` (optional log filter): each matching log of the latest flashblock, one
//!   log per message.
//! - `newFlashblockTransactions`: each transaction hash of the latest flashblock; with
//!   `true`, full transactions with their logs and receipt fields (`TransactionWithLogs`);
//!   with a log filter, only full transactions with at least one matching log.
//!
//! Standard kinds (`newHeads`, `logs`, ...) are not served by the node, so they fail with
//! invalid params. A `Subscriptions` table is fixed-size and owned by the WebSocket
//! transport (one per connection); `notify` renders every message into a caller buffer
//! and hands it to a sink, skipping (and counting) messages that do not fit.

const std = @import("std");
const assert = std.debug.assert;

const consensus = @import("../../common/consensus/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const eth = @import("../rpc/eth.zig");
const format = @import("../rpc/format.zig");
const flashblocks_rpc = @import("rpc.zig");

const Api = flashblocks_rpc.Api;
const View = flashblocks_rpc.View;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const subscriptions_max = 16;

pub const Kind = enum {
    new_flashblocks,
    pending_logs,
    transaction_hashes,
    transactions_full,
    transactions_filtered,
};

pub const Subscription = struct {
    id: u64,
    kind: Kind,
    filter: ?eth.Filter,
};

pub const Subscriptions = struct {
    entries: [subscriptions_max]Subscription = undefined,
    count: u32 = 0,
    next_id: u64 = 1,
    /// Notifications that did not fit the message buffer.
    dropped: u64 = 0,

    /// Registers a subscription; null when the table is full.
    pub fn add(subscriptions: *Subscriptions, kind: Kind, filter: ?eth.Filter) ?u64 {
        if (subscriptions.count == subscriptions_max) return null;
        const id = subscriptions.next_id;
        subscriptions.next_id += 1;
        subscriptions.entries[subscriptions.count] = .{ .id = id, .kind = kind, .filter = filter };
        subscriptions.count += 1;
        assert(subscriptions.count <= subscriptions_max);
        return id;
    }

    /// Removes subscription `id`; false when unknown.
    pub fn remove(subscriptions: *Subscriptions, id: u64) bool {
        for (subscriptions.entries[0..subscriptions.count], 0..) |entry, index| {
            if (entry.id != id) continue;
            subscriptions.count -= 1;
            subscriptions.entries[index] = subscriptions.entries[subscriptions.count];
            assert(subscriptions.count < subscriptions_max);
            return true;
        }
        return false;
    }

    pub fn list(subscriptions: *const Subscriptions) []const Subscription {
        assert(subscriptions.count <= subscriptions_max);
        return subscriptions.entries[0..subscriptions.count];
    }
};

/// Parses the `eth_subscribe` kind and parameter.
fn parse_kind(
    api: *Api,
    call: *Call,
    name: []const u8,
    raw: ?[]const u8,
) HandlerError!Subscription {
    var subscription: Subscription = .{ .id = 0, .kind = .new_flashblocks, .filter = null };
    if (std.mem.eql(u8, name, "newFlashblocks")) {
        if (raw != null) return error.InvalidParams;
        return subscription;
    }
    if (std.mem.eql(u8, name, "pendingLogs")) {
        subscription.kind = .pending_logs;
        if (raw) |text| subscription.filter = try eth.parse_filter(api.eth, call, text);
        return subscription;
    }
    if (!std.mem.eql(u8, name, "newFlashblockTransactions")) {
        return call.fail(rpc.code.invalid_params, "unsupported subscription");
    }
    subscription.kind = .transaction_hashes;
    const text = raw orelse return subscription;
    if (std.mem.eql(u8, text, "true")) {
        subscription.kind = .transactions_full;
    } else if (text.len > 0 and text[0] == '{') {
        subscription.kind = .transactions_filtered;
        subscription.filter = try eth.parse_filter(api.eth, call, text);
    } else if (!std.mem.eql(u8, text, "false")) return error.InvalidParams;
    return subscription;
}

pub fn subscribe(api: *Api, call: *Call) HandlerError!void {
    const name = try call.params.string();
    const raw = try call.params.optional_raw();
    try call.params.finish();
    const subscriptions = api.subscriptions orelse {
        return call.fail(rpc.code.server_error, "subscriptions need a WebSocket connection");
    };
    const parsed = try parse_kind(api, call, name, raw);
    const id = subscriptions.add(parsed.kind, parsed.filter) orelse {
        return call.fail(rpc.code.server_error, "too many subscriptions");
    };
    assert(id > 0);
    try call.writer.quantity(id);
}

pub fn unsubscribe(api: *Api, call: *Call) HandlerError!void {
    const id = try call.params.quantity(u64);
    try call.params.finish();
    const subscriptions = api.subscriptions orelse {
        return call.fail(rpc.code.server_error, "subscriptions need a WebSocket connection");
    };
    try call.writer.boolean(subscriptions.remove(id));
}

// ---- Notifications ----------------------------------------------------------------

/// Renders the notifications of the latest flashblock for every subscription into
/// `buffer`, calling `sink.send(message)` for each (the message borrows `buffer`).
/// Returns how many were sent.
pub fn notify(
    api: *const Api,
    subscriptions: *Subscriptions,
    buffer: []u8,
    sink: anytype,
) !u32 {
    const view = flashblocks_rpc.pending_view(api) orelse return 0;
    const range = view.block.flashblock_transactions(@intCast(view.block.latest_index()));
    var sent: u32 = 0;
    for (subscriptions.list()) |*subscription| {
        if (subscription.kind == .new_flashblocks) {
            sent += try emit(api, subscriptions, subscription, view, .block, buffer, sink);
            continue;
        }
        var index = range[0];
        while (index < range[1]) : (index += 1) {
            sent += try notify_transaction(
                api,
                subscriptions,
                subscription,
                view,
                index,
                buffer,
                sink,
            );
        }
    }
    return sent;
}

fn notify_transaction(
    api: *const Api,
    subscriptions: *Subscriptions,
    subscription: *const Subscription,
    view: View,
    index: u32,
    buffer: []u8,
    sink: anytype,
) !u32 {
    assert(index < view.block.transaction_count);
    const position = view.record.transaction_start + index;
    const receipt = api.state.receipt_at(position);
    switch (subscription.kind) {
        .new_flashblocks => unreachable,
        .transaction_hashes, .transactions_full => {
            const item: Item = if (subscription.kind == .transaction_hashes)
                .{ .hash = index }
            else
                .{ .transaction = index };
            return emit(api, subscriptions, subscription, view, item, buffer, sink);
        },
        .transactions_filtered => {
            if (!any_log_matches(receipt, &subscription.filter.?)) return 0;
            const item: Item = .{ .transaction = index };
            return emit(api, subscriptions, subscription, view, item, buffer, sink);
        },
        .pending_logs => {
            var sent: u32 = 0;
            var logs = receipt.logs.iterator();
            var offset: u32 = 0;
            while (logs.next()) |item| : (offset += 1) {
                if (subscription.filter) |*filter| if (!filter.matches(item)) continue;
                const log_item: Item = .{ .log = .{ .index = index, .offset = offset } };
                sent += try emit(api, subscriptions, subscription, view, log_item, buffer, sink);
            }
            return sent;
        },
    }
}

fn any_log_matches(receipt: *const consensus.Receipt, filter: *const eth.Filter) bool {
    var logs = receipt.logs.iterator();
    var bound: u32 = receipt.logs.count;
    while (logs.next()) |item| {
        assert(bound > 0);
        bound -= 1;
        if (filter.matches(item)) return true;
    }
    return false;
}

const Item = union(enum) {
    block,
    hash: u32,
    transaction: u32,
    log: struct { index: u32, offset: u32 },
};

/// Renders one `eth_subscription` message and sends it; 0 when it did not fit.
fn emit(
    api: *const Api,
    subscriptions: *Subscriptions,
    subscription: *const Subscription,
    view: View,
    item: Item,
    buffer: []u8,
    sink: anytype,
) !u32 {
    var out: std.Io.Writer = .fixed(buffer);
    render(api, &out, subscription.id, view, item) catch {
        subscriptions.dropped += 1;
        return 0;
    };
    try sink.send(out.buffered());
    return 1;
}

fn render(
    api: *const Api,
    out: *std.Io.Writer,
    id: u64,
    view: View,
    item: Item,
) json.Writer.WriteError!void {
    var w = json.Writer.init(out);
    try w.begin_object();
    try w.key("jsonrpc");
    try w.string("2.0");
    try w.key("method");
    try w.string("eth_subscription");
    try w.key("params");
    try w.begin_object();
    try format.field_quantity(&w, "subscription", id);
    try w.key("result");
    switch (item) {
        .block => try flashblocks_rpc.write_block(api, &w, view, true),
        .hash => |index| try w.data(&view.block.transaction_hashes[index].bytes),
        .transaction => |index| try write_transaction_with_logs(api, &w, view, index),
        .log => |at| try write_log(api, &w, view, at.index, at.offset),
    }
    try w.end_object();
    try w.end_object();
    assert(w.depth == 0);
}

fn write_log(
    api: *const Api,
    w: *json.Writer,
    view: View,
    index: u32,
    offset: u32,
) json.Writer.WriteError!void {
    const position = view.record.transaction_start + index;
    const executed = api.state.transaction_at(position);
    var logs = api.state.receipt_at(position).logs.iterator();
    var skipped: u32 = 0;
    while (skipped < offset) : (skipped += 1) _ = logs.next();
    const item = logs.next().?;
    const at = flashblocks_rpc.inclusion(view, index);
    try format.log(w, item, at, executed.hash.bytes, executed.log_index + offset);
}

/// base/base `TransactionWithLogs`: the transaction object flattened with its logs,
/// gas used, status, cumulative gas, contract address, and logs bloom.
fn write_transaction_with_logs(
    api: *const Api,
    w: *json.Writer,
    view: View,
    index: u32,
) json.Writer.WriteError!void {
    const position = view.record.transaction_start + index;
    const context = flashblocks_rpc.receipt_context(api, position) orelse return w.null_value();
    const receipt = api.state.receipt_at(position);
    var transaction_buffer: [1 << 14]u8 = undefined;
    var transaction_out: std.Io.Writer = .fixed(&transaction_buffer);
    var transaction_writer = json.Writer.init(&transaction_out);
    const raw = view.block.transaction(index);
    const recoverer = api.eth.chain.executor.recoverer;
    try format.transaction(&transaction_writer, raw, context.inclusion, recoverer);
    const transaction_json = transaction_out.buffered();
    assert(transaction_json.len >= 2 and transaction_json[transaction_json.len - 1] == '}');
    // Re-open the transaction object and append the receipt fields.
    try w.raw(transaction_json[0 .. transaction_json.len - 1]);
    const out = w.out;
    var fields = json.Writer.init(out);
    fields.depth = 1;
    fields.has_element[1] = true;
    try fields.key("logs");
    try fields.begin_array();
    var logs = receipt.logs.iterator();
    var log_index = context.first_log_index;
    while (logs.next()) |item| : (log_index += 1) {
        try format.log(&fields, item, context.inclusion, context.tx_hash, log_index);
    }
    try fields.end_array();
    try format.field_quantity(&fields, "gasUsed", context.gas_used);
    try format.field_quantity(&fields, "status", @as(u8, @intFromBool(receipt.status)));
    try format.field_quantity(&fields, "cumulativeGasUsed", receipt.cumulative_gas_used);
    try fields.key("contractAddress");
    if (context.contract_address) |address| try fields.data(&address.bytes) else {
        try fields.null_value();
    }
    try format.field_data(&fields, "logsBloom", &receipt.logs_bloom.bytes);
    try out.writeByte('}');
}

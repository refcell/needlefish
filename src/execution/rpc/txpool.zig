//! Pool listing and control beyond `txpool_status`: `base_transactionStatus`, the admin
//! drop methods, and `txpool_content`, `txpool_contentFrom` and `txpool_inspect`, shaped
//! like reth (base/base). Listings use `pending` and `queued` maps keyed
//! by the sender's EIP-55 address, then by the decimal nonce. Content values are pending
//! transaction objects (as `eth_getTransactionByHash`); inspect values are one-line
//! summaries, `"<to>: <value> wei + <gas> gas × <gas price> wei"` with `contract creation`
//! for creations and the fee cap as the gas price of dynamic-fee transactions.
//!
//! Senders are listed by ascending address (reth uses ordered maps) from an index list
//! carved from the tail of the API scratch; the head of the scratch decodes network-form
//! blob transactions to their canonical form.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const txpool = @import("../txpool/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const format = @import("format.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Pool = txpool.Pool;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "txpool_content", .handler = content },
    .{ .name = "txpool_contentFrom", .handler = content_from },
    .{ .name = "txpool_inspect", .handler = inspect },
    .{ .name = "base_transactionStatus", .handler = transaction_status },
    .{ .name = "admin_dropTransaction", .handler = drop_transaction },
    .{ .name = "admin_dropSenderTransactions", .handler = drop_sender_transactions },
};

/// `base_transactionStatus(hash)`: `{"status":"Known"}` while the transaction is in the
/// pool, else `"Unknown"` (base/base without a sequencer client to forward to).
fn transaction_status(api: *Api, call: *Call) HandlerError!void {
    const hash: primitives.B256 = .{ .bytes = try call.params.fixed(32) };
    try call.params.finish();
    const known = if (api.pool) |pool| pool.get(hash) != null else false;
    try call.writer.begin_object();
    try call.writer.key("status");
    try call.writer.string(if (known) "Known" else "Unknown");
    try call.writer.end_object();
}

/// `admin_dropTransaction(hash)`: removes one pool transaction; true when it was there.
fn drop_transaction(api: *Api, call: *Call) HandlerError!void {
    const hash: primitives.B256 = .{ .bytes = try call.params.fixed(32) };
    try call.params.finish();
    const removed = if (api.pool) |pool| pool.remove(hash) else false;
    assert(api.pool == null or api.pool.?.get(hash) == null);
    try call.writer.boolean(removed);
}

/// `admin_dropSenderTransactions(address)`: removes every pool transaction of the
/// sender and returns their hashes, lowest nonce first.
fn drop_sender_transactions(api: *Api, call: *Call) HandlerError!void {
    const address: primitives.Address = .{ .bytes = try call.params.fixed(20) };
    try call.params.finish();
    const w = call.writer;
    try w.begin_array();
    if (api.pool) |pool| {
        // One removal per transaction: bounded by the per-sender slot limit.
        var removals: u32 = 0;
        while (pool.sender_of(address)) |sender| : (removals += 1) {
            assert(removals < pool.config.account_slots_max);
            var iterator = pool.sender_transactions(sender);
            const hash = iterator.next().?.tx.hash;
            const removed = pool.remove(hash);
            assert(removed);
            try w.data(&hash.bytes);
        }
    }
    try w.end_array();
}

const Mode = enum { content, inspect };

fn content(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try write_pool(api, call, .content);
}

fn inspect(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try write_pool(api, call, .inspect);
}

/// `{"pending": {nonce: tx}, "queued": {nonce: tx}}` for one sender.
fn content_from(api: *Api, call: *Call) HandlerError!void {
    const address: primitives.Address = .{ .bytes = try call.params.fixed(20) };
    try call.params.finish();
    const w = call.writer;
    const pool = api.pool orelse return write_empty(w);
    const split = try split_scratch(api, call, pool);
    const count = pool.sorted_senders(split.senders);
    var found: ?u32 = null;
    for (split.senders[0..count]) |sender| {
        if (std.mem.eql(u8, &pool.sender_address(sender).bytes, &address.bytes)) found = sender;
    }
    const sender = found orelse return write_empty(w);
    try w.begin_object();
    inline for (.{ true, false }, .{ "pending", "queued" }) |pending, name| {
        try w.key(name);
        try w.begin_object();
        try write_sender(api, call, split.decode, pool, sender, pending, .content);
        try w.end_object();
    }
    try w.end_object();
}

fn write_empty(w: *json.Writer) HandlerError!void {
    try w.begin_object();
    try w.key("pending");
    try w.begin_object();
    try w.end_object();
    try w.key("queued");
    try w.begin_object();
    try w.end_object();
    try w.end_object();
}

fn write_pool(api: *Api, call: *Call, mode: Mode) HandlerError!void {
    const w = call.writer;
    const pool = api.pool orelse return write_empty(w);
    const split = try split_scratch(api, call, pool);
    const count = pool.sorted_senders(split.senders);
    const senders = split.senders[0..count];
    try w.begin_object();
    inline for (.{ true, false }, .{ "pending", "queued" }) |pending, name| {
        try w.key(name);
        try w.begin_object();
        for (senders) |sender| {
            if (!has_any(pool, sender, pending)) continue;
            const text = primitives.checksum(pool.sender_address(sender), null);
            try w.key(&text);
            try w.begin_object();
            try write_sender(api, call, split.decode, pool, sender, pending, mode);
            try w.end_object();
        }
        try w.end_object();
    }
    try w.end_object();
}

fn has_any(pool: *const Pool, sender: u32, pending: bool) bool {
    var iterator = pool.sender_transactions(sender);
    while (iterator.next()) |item| if (item.pending == pending) return true;
    return false;
}

/// One sender's transactions of one subpool, keyed by decimal nonce.
fn write_sender(
    api: *Api,
    call: *Call,
    decode: []u8,
    pool: *const Pool,
    sender: u32,
    pending: bool,
    mode: Mode,
) HandlerError!void {
    const w = call.writer;
    var iterator = pool.sender_transactions(sender);
    var previous_nonce: ?u64 = null;
    while (iterator.next()) |item| {
        assert(previous_nonce == null or previous_nonce.? < item.tx.nonce);
        previous_nonce = item.tx.nonce;
        if (item.pending != pending) continue;
        var nonce_text: [20]u8 = undefined;
        const nonce_key = std.fmt.bufPrint(&nonce_text, "{d}", .{item.tx.nonce}) catch
            unreachable; // A u64 has at most 20 digits.
        try w.key(nonce_key);
        const raw = node.chain.canonical_form(item.tx.raw, decode) catch {
            return call.fail(rpc.code.internal_error, "transaction too large");
        };
        switch (mode) {
            .content => try format.transaction(w, raw, null, api.chain.executor.recoverer),
            .inspect => try write_summary(w, item.tx, raw),
        }
    }
}

/// Longest summary: "0x" + 40 + ": " + 78 digits + " wei + " + 20 + " gas × " + 39 + " wei".
const summary_bytes_max = 256;

fn write_summary(w: *json.Writer, tx: *const txpool.Tx, raw: []const u8) HandlerError!void {
    var buffer: [summary_bytes_max]u8 = undefined;
    const text = summary(&buffer, tx, raw);
    assert(text.len > 0);
    try w.string(text);
}

/// The inspect line of a pool transaction; `raw` is its canonical encoding.
pub fn summary(buffer: *[summary_bytes_max]u8, tx: *const txpool.Tx, raw: []const u8) []const u8 {
    var to_text: [42]u8 = undefined;
    const envelope = consensus.Envelope.decode(raw) catch null;
    const to: []const u8 = if (envelope) |e| if (e.kind().to()) |address| blk: {
        to_text = primitives.checksum(address, null);
        break :blk &to_text;
    } else "contract creation" else "contract creation";
    const line = "{s}: {d} wei + {d} gas \u{00d7} {d} wei";
    const args = .{ to, tx.value, tx.gas_limit, tx.max_fee_per_gas };
    return std.fmt.bufPrint(buffer, line, args) catch unreachable; // Sized for maxima.
}

const Split = struct { decode: []u8, senders: []u32 };

/// The sender index list at the (aligned) tail of the scratch, decoding space before it.
fn split_scratch(api: *Api, call: *Call, pool: *const Pool) HandlerError!Split {
    const capacity = pool.sender_capacity();
    const list_bytes = @as(usize, capacity) * @sizeOf(u32);
    const scratch = api.scratch;
    if (scratch.len < list_bytes + @alignOf(u32)) {
        return call.fail(rpc.code.internal_error, "scratch too small");
    }
    const end = @intFromPtr(scratch.ptr) + scratch.len;
    const start = std.mem.alignBackward(usize, end - list_bytes, @alignOf(u32));
    const offset = start - @intFromPtr(scratch.ptr);
    const words: [*]u32 = @ptrCast(@alignCast(scratch[offset..].ptr));
    const result: Split = .{ .decode = scratch[0..offset], .senders = words[0..capacity] };
    assert(@intFromPtr(result.senders.ptr) >= @intFromPtr(result.decode.ptr + result.decode.len));
    return result;
}

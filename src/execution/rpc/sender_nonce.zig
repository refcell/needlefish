//! reth's `eth_getTransactionBySenderAndNonce(sender, nonce)`: the transaction a sender
//! sent with `nonce`, as `eth_getTransactionByHash`, or null. The pool is checked first.
//! A mined transaction is found by binary search over the history window on the sender's
//! account nonce (the first block whose post-state nonce exceeds `nonce` holds it); without
//! history, or for a transaction older than the window, the newest `scan_blocks_max` blocks
//! below the window are scanned. Deposits carry no nonce field and are never matched.

const std = @import("std");
const assert = std.debug.assert;

const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const eth = @import("eth.zig");
const state_view = @import("state_view.zig");
const format = @import("format.zig");
const node = @import("../node/root.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;
const Address = [20]u8;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_getTransactionBySenderAndNonce", .handler = by_sender_and_nonce },
};

/// Most blocks scanned backwards when the history window cannot narrow the search.
pub const scan_blocks_max: u64 = 1024;
/// A binary search over u64 block numbers ends within 64 halvings.
const search_steps_max: u32 = 64;

fn by_sender_and_nonce(api: *Api, call: *Call) HandlerError!void {
    const sender = try call.params.fixed(20);
    const nonce = try call.params.quantity(u64);
    try call.params.finish();
    if (api.pool) |pool| {
        if (pool.find_by_sender_nonce(.{ .bytes = sender }, nonce)) |tx| {
            const raw = node.chain.canonical_form(tx.raw, api.scratch) catch {
                return call.fail(rpc.code.internal_error, "transaction too large");
            };
            return format.transaction(call.writer, raw, null, api.chain.executor.recoverer);
        }
    }
    const head = api.chain.record(api.chain.head_hash()).?.header.number;
    const head_nonce = if (api.chain.db.get_account(sender)) |account| account.nonce else 0;
    if (nonce >= head_nonce) return call.writer.null_value(); // Not mined yet.
    const scan_from = try search_window(api, call, sender, nonce, head);
    var number = scan_from;
    var scanned: u64 = 0;
    while (scanned < scan_blocks_max) : (scanned += 1) {
        if (try write_in_block(api, call, number, sender, nonce)) return;
        if (number == 0) break;
        number -= 1;
    }
    try call.writer.null_value();
}

/// The block to start the backward scan at: the block holding the transaction when the
/// history window brackets it, else the window's oldest block (or the head without history).
fn search_window(api: *Api, call: *Call, sender: Address, nonce: u64, head: u64) !u64 {
    const window = api.chain.history_window() orelse return head;
    assert(window.oldest <= window.head);
    if (window.head != head) return head; // History lags the head: scan.
    if (try nonce_at(api, call, sender, window.oldest) > nonce) return window.oldest;
    // Invariant: nonce_at(low) <= nonce < nonce_at(high).
    var low = window.oldest;
    var high = head;
    var steps: u32 = 0;
    while (high - low > 1) : (steps += 1) {
        assert(steps < search_steps_max);
        const middle = low + (high - low) / 2;
        if (try nonce_at(api, call, sender, middle) > nonce) high = middle else low = middle;
    }
    assert(high > low);
    return high;
}

fn nonce_at(api: *Api, call: *Call, sender: Address, number: u64) !u64 {
    const hash = api.chain.store.canonical_hash(number).?; // Inside the history window.
    const view: state_view.View = if (std.mem.eql(u8, &hash, &api.chain.head_hash()))
        .head
    else
        .{ .historical = .{ .hash = hash, .number = number } };
    const account = try state_view.account(api, call, view, sender);
    return if (account) |found| found.nonce else 0;
}

/// Writes the transaction and returns true when canonical block `number` holds it.
fn write_in_block(api: *Api, call: *Call, number: u64, sender: Address, nonce: u64) !bool {
    const hash = api.chain.store.canonical_hash(number) orelse return false;
    const record = api.chain.record(hash) orelse return false;
    const recoverer = api.chain.executor.recoverer;
    var transactions = record.transactions;
    var index: u32 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        const envelope = consensus.Envelope.decode(raw) catch continue;
        if (envelope.nonce() != nonce) continue;
        const recovered = envelope.recover_sender(recoverer) orelse continue;
        if (!std.mem.eql(u8, &recovered.bytes, &sender)) continue;
        try format.transaction(call.writer, raw, .{
            .block_hash = hash,
            .block_number = number,
            .index = index,
            .base_fee = record.header.base_fee_per_gas,
            .timestamp_ms = format.timestamp_ms(record),
        }, recoverer);
        return true;
    }
    return false;
}

comptime {
    assert(scan_blocks_max > 0);
    _ = primitives;
}

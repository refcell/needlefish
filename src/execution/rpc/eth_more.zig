//! Smaller eth_* / web3_* / txpool_* methods that wallets and tooling (ethers, viem,
//! cast) call: block transaction counts, transactions by block and index, uncle stubs
//! (post-merge blocks have none), `eth_accounts` (the node holds no keys), `web3_sha3`
//! and `txpool_status`. Shapes follow reth (base/base).

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const format = @import("format.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_getBlockTransactionCountByHash", .handler = count_by_hash },
    .{ .name = "eth_getBlockTransactionCountByNumber", .handler = count_by_number },
    .{ .name = "eth_getUncleCountByBlockHash", .handler = uncle_count_by_hash },
    .{ .name = "eth_getUncleCountByBlockNumber", .handler = uncle_count_by_number },
    .{ .name = "eth_getUncleByBlockHashAndIndex", .handler = uncle_by_index },
    .{ .name = "eth_getUncleByBlockNumberAndIndex", .handler = uncle_by_index },
    .{ .name = "eth_getTransactionByBlockHashAndIndex", .handler = transaction_by_hash_index },
    .{ .name = "eth_getTransactionByBlockNumberAndIndex", .handler = transaction_by_number_index },
    .{ .name = "eth_accounts", .handler = accounts },
    .{ .name = "web3_sha3", .handler = sha3 },
    .{ .name = "txpool_status", .handler = txpool_status },
};

/// The block named by a number/tag parameter, or null (answered with JSON null).
fn block_by_number(api: *Api, call: *Call) HandlerError!?Hash {
    const raw = try call.params.raw();
    return eth.resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return null,
        else => return err,
    };
}

fn block_by_hash(api: *Api, call: *Call) HandlerError!?Hash {
    const hash = try call.params.fixed(32);
    return if (api.chain.store.ref(hash) != null) hash else null;
}

fn transaction_count(record: node.chain.Record) u64 {
    var transactions = record.transactions;
    var count: u64 = 0;
    while (!transactions.is_empty()) : (count += 1) {
        _ = transactions.bytes() catch unreachable; // Stored by the chain.
    }
    assert(transactions.is_empty());
    return count;
}

fn write_count(api: *Api, call: *Call, hash: ?Hash) HandlerError!void {
    try call.params.finish();
    const found = hash orelse return call.writer.null_value();
    const record = api.chain.record(found) orelse return call.writer.null_value();
    try call.writer.quantity(transaction_count(record));
}

fn count_by_hash(api: *Api, call: *Call) HandlerError!void {
    try write_count(api, call, try block_by_hash(api, call));
}

fn count_by_number(api: *Api, call: *Call) HandlerError!void {
    try write_count(api, call, try block_by_number(api, call));
}

fn write_uncle_count(call: *Call, hash: ?Hash) HandlerError!void {
    try call.params.finish();
    if (hash == null) return call.writer.null_value();
    try call.writer.quantity(@as(u64, 0));
}

fn uncle_count_by_hash(api: *Api, call: *Call) HandlerError!void {
    try write_uncle_count(call, try block_by_hash(api, call));
}

fn uncle_count_by_number(api: *Api, call: *Call) HandlerError!void {
    try write_uncle_count(call, try block_by_number(api, call));
}

fn uncle_by_index(api: *Api, call: *Call) HandlerError!void {
    _ = api;
    _ = try call.params.raw();
    _ = try call.params.quantity(u64);
    try call.params.finish();
    try call.writer.null_value();
}

fn write_transaction_at(api: *Api, call: *Call, hash: ?Hash) HandlerError!void {
    const index = try call.params.quantity(u64);
    try call.params.finish();
    const found = hash orelse return call.writer.null_value();
    const record = api.chain.record(found) orelse return call.writer.null_value();
    if (index >= transaction_count(record)) return call.writer.null_value();
    var transactions = record.transactions;
    for (0..index) |_| _ = transactions.bytes() catch unreachable;
    const raw = transactions.bytes() catch unreachable;
    try format.transaction(call.writer, raw, .{
        .block_hash = found,
        .block_number = record.header.number,
        .index = @intCast(index),
        .base_fee = record.header.base_fee_per_gas,
    }, api.chain.executor.recoverer);
}

fn transaction_by_hash_index(api: *Api, call: *Call) HandlerError!void {
    try write_transaction_at(api, call, try block_by_hash(api, call));
}

fn transaction_by_number_index(api: *Api, call: *Call) HandlerError!void {
    try write_transaction_at(api, call, try block_by_number(api, call));
}

fn accounts(api: *Api, call: *Call) HandlerError!void {
    _ = api;
    try call.params.finish();
    try call.writer.begin_array();
    try call.writer.end_array();
}

fn sha3(api: *Api, call: *Call) HandlerError!void {
    const input = try call.params.data(api.scratch);
    try call.params.finish();
    const digest = primitives.keccak256(input);
    try call.writer.data(&digest.bytes);
}

fn txpool_status(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    var pending: u64 = 0;
    var queued: u64 = 0;
    if (api.pool) |pool| {
        pending = pool.pending_count;
        queued = pool.queued_count;
        assert(pending + queued == pool.count());
    }
    try call.writer.begin_object();
    try call.writer.key("pending");
    try call.writer.quantity(pending);
    try call.writer.key("queued");
    try call.writer.quantity(queued);
    try call.writer.end_object();
}

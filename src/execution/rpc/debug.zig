//! `debug_getRaw*` (geth): consensus encodings of stored headers, blocks, receipts and
//! transactions. Blocks are rebuilt from the stored record: legacy transactions are
//! embedded as lists and typed ones as byte strings, ommers are always empty, and the
//! withdrawals list is present from Shanghai on. Encodings go through the API's bounded
//! scratch.
//!
//! `debug_executionWitness(block)` (base/base, alloy `ExecutionWitness`): the pre-state trie
//! nodes, codes, touched keys, and ancestor headers a stateless client needs to re-execute
//! the block, as `{state, codes, keys, headers}` hex arrays (`node/witness.zig`). A witness
//! whose JSON exceeds the generator's `response_bytes_max`, or that the response writer
//! cannot make room for, fails with -32000 "witness too large" (as does one that overflowed
//! the generator's output buffers) instead of an overflowing response. The exact length is
//! computed first and room for it requested from the writer (`ensureUnusedCapacity`): over
//! HTTP that moves a response larger than the connection's send buffer into one of the
//! server's shared, lazily committed large send buffers (`http.server` "Large responses").

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../common/rlp/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const json = @import("../../utilities/json/root.zig");
const witness_module = @import("../db/witness.zig");
const ByteList = witness_module.ByteList;
const witness_json = @import("../db/witness_json.zig");
const engine_json = @import("engine_json.zig");
const payload = @import("../payload/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Hash = [32]u8;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

fn resolve_record(api: *eth.Api, call: *Call) HandlerError!node.chain.Record {
    const hash = try eth.resolve_block(api, call, try call.params.raw());
    try call.params.finish();
    return api.chain.record(hash) orelse call.fail(rpc.code.server_error, "block not found");
}

pub fn get_raw_header(api: *eth.Api, call: *Call) HandlerError!void {
    const record = try resolve_record(api, call);
    const length = rlp.length(record.header);
    if (length > api.scratch.len) return call.fail(rpc.code.internal_error, "scratch too small");
    var encoder = rlp.Encoder.init(api.scratch[0..length]);
    rlp.encode(&encoder, record.header);
    assert(encoder.position == length);
    try call.writer.data(encoder.written());
}

/// Length of one transaction inside a block body.
fn body_tx_length(raw: []const u8) usize {
    assert(raw.len > 0);
    return if (raw[0] >= 0xc0) raw.len else rlp.bytes_length(raw);
}

pub fn get_raw_block(api: *eth.Api, call: *Call) HandlerError!void {
    const record = try resolve_record(api, call);
    var transactions_length: usize = 0;
    var transactions = record.transactions;
    while (!transactions.is_empty()) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        transactions_length += body_tx_length(raw);
    }
    const ommers_length = rlp.list_length(0);
    var payload_length = rlp.length(record.header) + rlp.list_length(transactions_length) +
        ommers_length;
    if (record.withdrawals) |withdrawals| payload_length += withdrawals.rlp_length();
    const length = rlp.list_length(payload_length);
    if (length > api.scratch.len) return call.fail(rpc.code.internal_error, "scratch too small");
    var encoder = rlp.Encoder.init(api.scratch[0..length]);
    encoder.list_header(payload_length);
    rlp.encode(&encoder, record.header);
    encoder.list_header(transactions_length);
    transactions = record.transactions;
    while (!transactions.is_empty()) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        if (raw[0] >= 0xc0) encoder.raw(raw) else encoder.bytes(raw);
    }
    encoder.list_header(0); // Ommers.
    if (record.withdrawals) |withdrawals| withdrawals.rlp_encode(&encoder);
    assert(encoder.position == length);
    try call.writer.data(encoder.written());
}

/// Each receipt's EIP-2718 consensus encoding, as stored.
pub fn get_raw_receipts(api: *eth.Api, call: *Call) HandlerError!void {
    const record = try resolve_record(api, call);
    const w = call.writer;
    try w.begin_array();
    var receipts = record.receipts;
    while (!receipts.is_empty()) {
        try w.data(receipts.bytes() catch unreachable); // Stored by the chain.
    }
    try w.end_array();
}

pub fn get_raw_transaction(api: *eth.Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.fixed(32);
    try call.params.finish();
    const location = api.chain.find_transaction(tx_hash) orelse return call.writer.data(&.{});
    const record = api.chain.record(location.block_hash).?;
    var transactions = record.transactions;
    var index: u32 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable; // Stored by the chain.
        if (index == location.index) return call.writer.data(raw);
    }
    unreachable; // The index points into the canonical block.
}

pub fn execution_witness(api: *eth.Api, call: *Call) HandlerError!void {
    const hash = try eth.resolve_block(api, call, try call.params.raw());
    try call.params.finish();
    const generator = api.witness orelse
        return call.fail(rpc.code.server_error, "execution witness unavailable");
    node.witness.execution_witness(api.chain, generator, hash) catch |err| switch (err) {
        error.WitnessFull => return call.fail(rpc.code.server_error, witness_too_large),
        else => return call.fail(rpc.code.server_error, @errorName(err)),
    };
    try write_built(call, generator);
}

/// Writes the generator's filled witness as the result, bounded by `response_bytes_max`.
fn write_built(call: *Call, generator: *node.witness.Generator) HandlerError!void {
    const built = &generator.witness;
    const w = call.writer;
    const length = witness_json_length(built);
    if (length > generator.response_bytes_max) {
        return call.fail(rpc.code.server_error, witness_too_large);
    }
    // The response's closing `}` follows, and a full buffer reads as overflow: keep one more.
    w.out.ensureUnusedCapacity(@intCast(length + 2)) catch {
        return call.fail(rpc.code.server_error, witness_too_large);
    };
    assert(w.out.buffer.len - w.out.end >= length + 2);
    const start = w.out.end;
    try w.begin_object();
    try write_list(w, "state", &built.state);
    try write_list(w, "codes", &built.codes);
    try write_list(w, "keys", &built.keys);
    try write_list(w, "headers", &built.headers);
    try w.end_object();
    assert(w.out.end - start == length);
}

pub const witness_too_large = "witness too large";

/// Bounds of the attributes `debug_executePayload` decodes (the engine's limits).
const execute_transactions_max = 4096;
const execute_withdrawals_max = 16;
const execute_hashes_max = 16;

/// `debug_executePayload(parentHash, attributes)` (base/base): builds the block the
/// payload attributes describe on the parent, as `engine_forkchoiceUpdated` would but
/// without a payload id or forkchoice change, and returns its execution witness. The
/// block is stored as a side block; the attributes decode into the API's scratch.
pub fn execute_payload(api: *eth.Api, call: *Call) HandlerError!void {
    const parent = try call.params.fixed(32);
    const raw = try call.params.raw();
    try call.params.finish();
    const generator = api.witness orelse
        return call.fail(rpc.code.server_error, "execution witness unavailable");
    var space = attribute_space(api.scratch) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    const attributes = engine_json.parse_attributes(raw, &space) catch
        return call.fail(rpc.code.invalid_params, "invalid payload attributes");
    if (api.chain.header(parent) == null) {
        return call.fail(rpc.code.server_error, "parent block not found");
    }
    const hash = api.chain.build_block(parent, &attributes) catch |err| switch (err) {
        error.InvalidAttributes, error.InvalidTransaction => {
            return call.fail(rpc.code.invalid_params, @errorName(err));
        },
        else => return call.fail(rpc.code.server_error, @errorName(err)),
    };
    // The state sits at the built block; serve later reads from the head again.
    defer api.chain.ensure_head_state() catch |err| {
        std.log.scoped(.rpc).warn("debug_executePayload: head state: {s}", .{@errorName(err)});
    };
    node.witness.built_witness(api.chain, generator, hash) catch |err| switch (err) {
        error.WitnessFull => return call.fail(rpc.code.server_error, witness_too_large),
        else => return call.fail(rpc.code.server_error, @errorName(err)),
    };
    try write_built(call, generator);
}

/// Carves the attribute decoding space out of `scratch`; null when it does not fit.
fn attribute_space(scratch: []u8) ?engine_json.Space {
    var offset: usize = 0;
    const transactions = carve([]const u8, scratch, &offset, execute_transactions_max) orelse
        return null;
    const withdrawals = carve(payload.Withdrawal, scratch, &offset, execute_withdrawals_max) orelse
        return null;
    const hashes = carve(primitives.B256, scratch, &offset, execute_hashes_max) orelse
        return null;
    if (offset >= scratch.len) return null;
    assert(transactions.len == execute_transactions_max);
    return .{
        .bytes = scratch[offset..],
        .transactions = transactions,
        .withdrawals = withdrawals,
        .hashes = hashes,
    };
}

fn carve(comptime T: type, scratch: []u8, offset: *usize, count: usize) ?[]T {
    const base = @intFromPtr(scratch.ptr);
    const start = std.mem.alignForward(usize, base + offset.*, @alignOf(T)) - base;
    const end = start + count * @sizeOf(T);
    if (end > scratch.len) return null;
    offset.* = end;
    const typed: [*]T = @ptrCast(@alignCast(scratch[start..end].ptr));
    return typed[0..count];
}

/// `debug_proofsSyncStatus` (base/base): `{earliest, latest}` block numbers the
/// history serves, both null without history.
pub fn proofs_sync_status(api: *eth.Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const window = api.chain.history_window();
    const w = call.writer;
    try w.begin_object();
    try w.key("earliest");
    if (window) |range| try w.integer(range.oldest) else try w.null_value();
    try w.key("latest");
    if (window) |range| try w.integer(range.head) else try w.null_value();
    try w.end_object();
}

/// Exact length of the `{state, codes, keys, headers}` object `execution_witness` writes
/// (`db.witness_json.length`: O(1) per list).
pub fn witness_json_length(built: *const witness_module.Witness) u64 {
    return witness_json.length(built);
}

fn write_list(w: *json.Writer, name: []const u8, list: *const ByteList) HandlerError!void {
    assert(list.count <= list.ends.len);
    try w.key(name);
    try w.begin_array();
    var index: u32 = 0;
    while (index < list.count) : (index += 1) try w.data(list.get(index));
    try w.end_array();
}

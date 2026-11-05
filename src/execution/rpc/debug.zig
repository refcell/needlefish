//! `debug_getRaw*` (geth): consensus encodings of stored headers, blocks, receipts and
//! transactions. Blocks are rebuilt from the stored record: legacy transactions are
//! embedded as lists and typed ones as byte strings, ommers are always empty, and the
//! withdrawals list is present from Shanghai on. Encodings go through the API's bounded
//! scratch.
//!
//! `debug_executionWitness(block)` (base/base, alloy `ExecutionWitness`): the pre-state trie
//! nodes, codes, touched keys, and ancestor headers a stateless client needs to re-execute
//! the block, as `{state, codes, keys, headers}` hex arrays (`node/witness.zig`).

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../common/rlp/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const json = @import("../../utilities/json/root.zig");
const ByteList = @import("../db/witness.zig").ByteList;

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
    node.witness.execution_witness(api.chain, generator, hash) catch |err| {
        return call.fail(rpc.code.server_error, @errorName(err));
    };
    const built = &generator.witness;
    const w = call.writer;
    try w.begin_object();
    try write_list(w, "state", &built.state);
    try write_list(w, "codes", &built.codes);
    try write_list(w, "keys", &built.keys);
    try write_list(w, "headers", &built.headers);
    try w.end_object();
}

fn write_list(w: *json.Writer, name: []const u8, list: *const ByteList) HandlerError!void {
    assert(list.count <= list.ends.len);
    try w.key(name);
    try w.begin_array();
    var index: u32 = 0;
    while (index < list.count) : (index += 1) try w.data(list.get(index));
    try w.end_array();
}

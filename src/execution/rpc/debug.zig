//! `debug_getRaw*` (geth): consensus encodings of stored headers, blocks, receipts and
//! transactions. Blocks are rebuilt from the stored record: legacy transactions are
//! embedded as lists and typed ones as byte strings, ommers are always empty, and the
//! withdrawals list is present from Shanghai on. Encodings go through the API's bounded
//! scratch.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../common/rlp/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");

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

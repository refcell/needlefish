//! `debug_storageRangeAt(blockHash, txIndex, address, keyStart, maxResult)` (geth): an
//! account's storage leaves in hashed-key order from `keyStart` (inclusive), plus the next
//! hashed key. Leaves come from `Api.storage_range`, a block-boundary state source, so only
//! the state before the block's first transaction (`txIndex` 0: the parent's) and after its
//! last (`txIndex` >= its transaction count) are served; states between transactions would
//! need re-execution and are rejected.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const eth = @import("eth.zig");
const db = @import("../db/root.zig");
const node = @import("../node/root.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

/// Most leaves returned by one call.
pub const results_max: u32 = 1024;

/// A slot by hashed key; preimages are not kept, so `key` is reported null (as geth
/// without preimages).
pub const Leaf = db.history.StorageEntry;
/// `count` leaves copied, and the hashed key after them (null at the end).
pub const Range = db.history.StorageRange;

/// Storage leaves of the state after block `number` (head or within the history window).
pub const Source = struct {
    context: *anyopaque,
    range: *const fn (
        context: *anyopaque,
        hash: [32]u8,
        number: u64,
        address_hash: [32]u8,
        start: [32]u8,
        max: u32,
        out: []Leaf,
    ) anyerror!Range,

    /// The node's chain: head from the live trie, older blocks from the history window.
    pub fn of_chain(chain: *node.chain.Chain) Source {
        return .{ .context = chain, .range = chain_range };
    }
};

fn chain_range(
    context: *anyopaque,
    hash: [32]u8,
    number: u64,
    address_hash: [32]u8,
    start: [32]u8,
    max: u32,
    out: []Leaf,
) anyerror!Range {
    const chain: *node.chain.Chain = @ptrCast(@alignCast(context));
    const range = chain.storage_range_at(hash, number, address_hash, start, max, out) catch |err|
        switch (err) {
            // An absent account has no storage (geth answers an empty range).
            error.UnknownAccount => return .{ .count = 0, .next = null },
            else => return err,
        };
    assert(range.count <= @min(max, out.len));
    return range;
}

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "debug_storageRangeAt", .handler = storage_range_at },
};

/// Left-pads `keyStart` (up to 32 bytes, as geth's `BytesToHash`).
pub fn start_key(bytes: []const u8) ?[32]u8 {
    if (bytes.len > 32) return null;
    var key: [32]u8 = @splat(0);
    @memcpy(key[32 - bytes.len ..], bytes);
    assert(std.mem.eql(u8, key[32 - bytes.len ..], bytes));
    return key;
}

fn storage_range_at(api: *Api, call: *Call) HandlerError!void {
    const block_hash = try call.params.fixed(32);
    const transaction_index = try call.params.quantity(u64);
    const address = try call.params.fixed(20);
    var start_bytes: [64]u8 = undefined;
    const start_raw = call.params.data(&start_bytes) catch
        return call.fail(rpc.code.invalid_params, "keyStart is at most 32 bytes");
    const max_result = max_result_of(try call.params.raw()) orelse
        return call.fail(rpc.code.invalid_params, "invalid maxResult");
    try call.params.finish();
    const start = start_key(start_raw) orelse
        return call.fail(rpc.code.invalid_params, "keyStart is at most 32 bytes");
    const source = api.storage_range orelse
        return call.fail(rpc.code.server_error, "storage ranges are unavailable");
    var record = api.chain.record(block_hash) orelse
        return call.fail(rpc.code.server_error, "block not found");
    const count = transactions_in(&record.transactions);
    const number = record.header.number;
    var state_number = number;
    var state_hash = block_hash;
    if (transaction_index == 0 and count > 0) {
        if (number == 0) return call.fail(rpc.code.invalid_params, "genesis has no parent");
        state_number = number - 1;
        state_hash = record.header.parent_hash.bytes;
    } else if (transaction_index < count) {
        return call.fail(rpc.code.invalid_params, "state between transactions is unsupported");
    }
    const out = leaves_in(api.scratch, @min(max_result, results_max));
    const address_hash = primitives.keccak256(&address).bytes;
    api.chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const max: u32 = @intCast(out.len);
    const range = source.range(
        source.context,
        state_hash,
        state_number,
        address_hash,
        start,
        max,
        out,
    ) catch |err| return call.fail(rpc.code.server_error, @errorName(err));
    if (range.count > out.len) return call.fail(rpc.code.internal_error, "range overflow");
    try write_range(call.writer, out[0..range.count], range.next);
}

/// `maxResult`: a JSON integer (geth) or a hex quantity string.
pub fn max_result_of(raw: []const u8) ?u64 {
    if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
        const text = raw[1 .. raw.len - 1];
        if (!std.mem.startsWith(u8, text, "0x") or text.len == 2) return null;
        return std.fmt.parseInt(u64, text[2..], 16) catch null;
    }
    if (raw.len == 0 or raw.len > 20) return null;
    for (raw) |byte| if (!std.ascii.isDigit(byte)) return null;
    return std.fmt.parseInt(u64, raw, 10) catch null;
}

fn transactions_in(list: anytype) u64 {
    var count: u64 = 0;
    // Stored blocks hold at most the executor's transaction limit; bound the walk anyway.
    while (!list.is_empty() and count < 1 << 20) : (count += 1) {
        _ = list.raw() catch break;
    }
    return count;
}

fn leaves_in(scratch: []u8, max: u64) []Leaf {
    const aligned = std.mem.alignInSlice(scratch, @alignOf(Leaf)) orelse return &.{};
    const capacity = aligned.len / @sizeOf(Leaf);
    const leaves: [*]Leaf = @ptrCast(@alignCast(aligned.ptr));
    return leaves[0..@min(capacity, max)];
}

pub fn write_range(writer: *json.Writer, leaves: []const Leaf, next: ?[32]u8) HandlerError!void {
    try writer.begin_object();
    try writer.key("storage");
    try writer.begin_object();
    for (leaves) |leaf| {
        var name: [66]u8 = undefined;
        name[0..2].* = "0x".*;
        json.hex_encode(name[2..], &leaf.key_hash);
        try writer.key(&name);
        try writer.begin_object();
        try writer.key("key");
        try writer.null_value();
        try writer.key("value");
        var value: [32]u8 = undefined;
        std.mem.writeInt(u256, &value, leaf.value, .big);
        try writer.data(&value);
        try writer.end_object();
    }
    try writer.end_object();
    try writer.key("nextKey");
    if (next) |key| try writer.data(&key) else try writer.null_value();
    try writer.end_object();
}

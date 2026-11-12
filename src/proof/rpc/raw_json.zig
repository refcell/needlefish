//! Raw headers, block transactions and receipts for the proof tools. They prefer the
//! `debug_getRaw*` methods; where a node answers those with "method not found" (public L1
//! endpoints do), the same bytes are rebuilt from `eth_getBlockBy*` and
//! `eth_getBlockReceipts` JSON. The rebuilt header must hash to the block hash, and the
//! transactions and receipts must match the roots of that header, so the fallback returns
//! exactly the bytes the debug methods would.

const std = @import("std");
const assert = std.debug.assert;

const endpoint_module = @import("endpoint.zig");
const rlp = @import("../../common/rlp/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const sources = @import("../../consensus/sources/root.zig");

const header_json = sources.header_json;
const transaction_json = sources.transaction_json;
const receipt_json = sources.receipt_json;

const Error = endpoint_module.Error;
const Param = endpoint_module.Param;
const Hash = endpoint_module.Hash;

/// JSON-RPC "method not found".
const method_not_found: i64 = -32601;

/// The RLP header of `block` (a hash, number or tag), valid until the endpoint's next call.
pub fn header(endpoint: anytype, block: Param) Error![]const u8 {
    if (try debug_call(endpoint, "debug_getRawHeader", block)) |raw| return endpoint.hex(raw);
    const decoded = try block_header(endpoint, block, "false");
    const size = rlp.length(decoded.header);
    const out = endpoint.arena.allocator().alloc(u8, size) catch return error.CallFailed;
    const encoded = rlp.encode_to(out, decoded.header);
    assert(primitives.keccak256(encoded).eql(decoded.hash));
    return encoded;
}

/// The EIP-2718 transactions of block `hash` rebuilt from `eth_getBlockByHash` (for when
/// `debug_call` reported `debug_getRawBlock` missing), valid until the endpoint's next call.
pub fn transactions(endpoint: anytype, hash: Hash, items_max: u32) Error![]const []const u8 {
    const block: Param = .{ .hash = hash };
    const raw = try endpoint.call("eth_getBlockByHash", &.{ block, .{ .raw_json = "true" } });
    const decoded = try decode_header(endpoint, raw, hash);
    const list = (header_json.transactions_raw(raw) catch return error.CallFailed) orelse
        return error.CallFailed;
    const limits: transaction_json.Limits = .{ .transactions_max = items_max };
    const root = decoded.header.transactions_root;
    const allocator = endpoint.arena.allocator();
    return transaction_json.encode_block(allocator, list, root, limits) catch error.CallFailed;
}

/// The EIP-2718 receipts of block `hash`, valid until the endpoint's next call.
pub fn receipts(endpoint: anytype, hash: Hash, items_max: u32) Error![]const []const u8 {
    if (try debug_call(endpoint, "debug_getRawReceipts", .{ .hash = hash })) |raw| {
        return endpoint.hex_list(raw, items_max);
    }
    const decoded = try block_header(endpoint, .{ .hash = hash }, "false");
    const raw = try endpoint.call("eth_getBlockReceipts", &.{.{ .hash = hash }});
    const limits: receipt_json.Limits = .{ .receipts_max = items_max };
    const allocator = endpoint.arena.allocator();
    return receipt_json.encode_block(allocator, raw, decoded.header.receipts_root, limits) catch
        error.CallFailed;
}

/// The debug method's result, or null when the node reports it missing (remembered on the
/// endpoint, so later calls go straight to the JSON methods).
pub fn debug_call(endpoint: anytype, method: []const u8, param: Param) Error!?[]const u8 {
    if (endpoint.debug_raw_missing) return null;
    return endpoint.call(method, &.{param}) catch |err| {
        const failure = endpoint.last_error orelse return err;
        if (err != error.NotFound or failure.code != method_not_found) return err;
        endpoint.debug_raw_missing = true;
        return null;
    };
}

fn block_header(endpoint: anytype, block: Param, full: []const u8) Error!header_json.Decoded {
    const method = if (block == .hash) "eth_getBlockByHash" else "eth_getBlockByNumber";
    const raw = try endpoint.call(method, &.{ block, .{ .raw_json = full } });
    return decode_header(endpoint, raw, if (block == .hash) block.hash else null);
}

/// A hash-verified header; `expected` also pins the hash that was asked for.
fn decode_header(endpoint: anytype, raw: []const u8, expected: ?Hash) Error!header_json.Decoded {
    const allocator = endpoint.arena.allocator();
    const extra = allocator.create([header_json.extra_data_size_max]u8) catch
        return error.CallFailed;
    const decoded = header_json.decode(raw, extra) catch return error.CallFailed;
    if (expected) |hash| {
        if (!std.mem.eql(u8, &hash, &decoded.hash.bytes)) return error.CallFailed;
    }
    return decoded;
}

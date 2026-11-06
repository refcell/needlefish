//! Trie nodes and codes from untrusted JSON-RPC results (`eth_getProof`, `eth_getCode`).
//!
//! Nothing here is verified: the follower's node store is keyed by keccak256, so a node only
//! ever serves the trie reference that names its hash, and a code only the account whose
//! code hash it matches. A malformed result is an error the driver retries.

const std = @import("std");
const assert = std.debug.assert;

const Value = std.json.Value;

pub const Error = error{ OutOfMemory, Malformed };

/// Bytes of one hex string (`0x` prefix, even length).
pub fn decode_hex(arena: std.mem.Allocator, value: Value) Error![]u8 {
    if (value != .string) return error.Malformed;
    const text = value.string;
    if (text.len < 2 or text.len % 2 != 0) return error.Malformed;
    if (text[0] != '0' or text[1] != 'x') return error.Malformed;
    const out = try arena.alloc(u8, (text.len - 2) / 2);
    _ = std.fmt.hexToBytes(out, text[2..]) catch return error.Malformed;
    assert(out.len * 2 + 2 == text.len);
    return out;
}

fn field(value: Value, name: []const u8) Error!Value {
    if (value != .object) return error.Malformed;
    return value.object.get(name) orelse error.Malformed;
}

fn append_list(arena: std.mem.Allocator, list: Value, out: *std.ArrayList([]const u8)) Error!void {
    if (list != .array) return error.Malformed;
    for (list.array.items) |item| try out.append(arena, try decode_hex(arena, item));
}

/// Appends every node of one `eth_getProof` result: the account proof and each storage
/// proof, in order.
pub fn collect_nodes(
    arena: std.mem.Allocator,
    result: Value,
    out: *std.ArrayList([]const u8),
) Error!void {
    const before = out.items.len;
    try append_list(arena, try field(result, "accountProof"), out);
    const storage = try field(result, "storageProof");
    if (storage != .array) return error.Malformed;
    for (storage.array.items) |entry| try append_list(arena, try field(entry, "proof"), out);
    assert(out.items.len >= before);
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "proofs: collect_nodes walks account and storage proofs in order" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text =
        \\{"accountProof":["0x01","0x0203"],"storageProof":[{"key":"0x0","proof":["0x04"]},
        \\{"key":"0x1","proof":[]},{"key":"0x2","proof":["0x0506","0x"]}]}
    ;
    const value = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    var nodes: std.ArrayList([]const u8) = .empty;
    try collect_nodes(arena, value, &nodes);
    const expected = [_][]const u8{ &.{1}, &.{ 2, 3 }, &.{4}, &.{ 5, 6 }, &.{} };
    try testing.expectEqual(expected.len, nodes.items.len);
    for (expected, nodes.items) |want, got| try testing.expectEqualSlices(u8, want, got);
    const rejected = [_][]const u8{
        "{\"accountProof\":[\"0x1\"],\"storageProof\":[]}",
        "{\"accountProof\":[\"01\"],\"storageProof\":[]}",
        "{\"accountProof\":[\"0xzz\"],\"storageProof\":[]}",
        "{\"accountProof\":[],\"storageProof\":[{\"proof\":7}]}",
        "{\"accountProof\":[]}",
        "[]",
    };
    for (rejected) |bad| {
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, bad, .{});
        try testing.expectError(error.Malformed, collect_nodes(arena, parsed, &nodes));
    }
}

fn fuzz_collect(_: void, input: []const u8) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const value = std.json.parseFromSliceLeaky(Value, arena, input, .{}) catch return;
    var nodes: std.ArrayList([]const u8) = .empty;
    // Any server bytes: never crash; every accepted node is the bytes of a hex string.
    collect_nodes(arena, value, &nodes) catch |err| {
        try testing.expect(err == error.Malformed);
        return;
    };
    for (nodes.items) |node| try testing.expect(node.len <= input.len);
}

test "proofs: fuzz collect_nodes" {
    const corpus = [_][]const u8{
        "{\"accountProof\":[\"0xf851\"],\"storageProof\":[{\"proof\":[\"0x80\"]}]}",
        "{\"accountProof\":[],\"storageProof\":[{\"proof\":[\"0x\",\"0x00ff\"]},{}]}",
    };
    try fuzz.run_bytes({}, fuzz_collect, .{ .iterations = 512, .corpus = &corpus });
}

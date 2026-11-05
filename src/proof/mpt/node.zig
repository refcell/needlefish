//! Generic trie node decoding. Port of the `Decodable` half of base/base
//! `crates/proof/mpt/src/node.rs`.
//!
//! `execution/trie/sparse.zig` decodes state-trie nodes strictly (32-byte keys, bounded
//! account values). Transaction and receipt tries have short `rlp(index)` keys and values
//! of any size, so this decoder only checks the node shape: canonical RLP, a 2-item leaf
//! or extension with a hex-prefix path, or a 17-item branch whose children are empty,
//! 32-byte hashes, or embedded nodes shorter than 32 bytes.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../../execution/trie/root.zig");
const rlp = trie.rlp;
const nibbles = trie.nibbles;
const Nibbles = trie.Nibbles;
const RlpNode = trie.RlpNode;

pub const Error = error{InvalidNode};

pub const Kind = enum { leaf, extension, branch };

/// One decoded node. Slices point into the input.
pub const Decoded = struct {
    kind: Kind,
    path: Nibbles = .{},
    /// Leaf value, or the branch value (empty in every Ethereum list or state trie).
    value: []const u8 = &.{},
    /// Child references by nibble; `len == 0` means empty. An extension uses slot 0.
    children: [16]RlpNode = @splat(.{}),

    pub fn child_count(decoded: *const Decoded) u32 {
        var count: u32 = 0;
        for (decoded.children) |child| count += @intFromBool(child.len > 0);
        return count;
    }
};

fn decode_child(item: rlp.Item) Error!RlpNode {
    switch (item.kind) {
        .string => {
            if (item.payload.len == 0) return .{};
            if (item.payload.len != 32) return error.InvalidNode;
            return RlpNode.from_hash(item.payload[0..32].*);
        },
        .list => {
            if (item.raw.len >= 32) return error.InvalidNode;
            return RlpNode.from_rlp(item.raw);
        },
    }
}

pub fn decode(bytes: []const u8) Error!Decoded {
    const outer = rlp.decode_item(bytes) catch return error.InvalidNode;
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string) return error.InvalidNode;
        var result: Decoded = .{ .kind = .branch, .value = items[16].payload };
        for (items[0..16], &result.children) |item, *child| child.* = try decode_child(item);
        assert(result.child_count() <= 16);
        return result;
    }
    if (count != 2) return error.InvalidNode;
    if (items[0].kind != .string) return error.InvalidNode;
    const prefix = nibbles.hex_prefix_decode(items[0].payload) catch return error.InvalidNode;
    if (prefix.leaf) {
        if (items[1].kind != .string) return error.InvalidNode;
        return .{ .kind = .leaf, .path = prefix.path, .value = items[1].payload };
    }
    if (prefix.path.len == 0) return error.InvalidNode;
    var result: Decoded = .{ .kind = .extension, .path = prefix.path };
    result.children[0] = try decode_child(items[1]);
    if (result.children[0].len == 0) return error.InvalidNode;
    assert(result.child_count() == 1);
    return result;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Comptime-known valid hex.
    return out;
}

test "node: decode branch vector" {
    const branch = hex("f851a0eb08a66a94882454bec899d3e82952dcc918ba4b35a09a84acd98019aef4345080" ++
        "808080808080a05d87a81d9bbf5aee61a6bfeab3a5643347e2c751b36789d988a5b6b163d49651" ++
        "8080808080808080");
    const decoded = try decode(&branch);
    try testing.expectEqual(Kind.branch, decoded.kind);
    try testing.expectEqual(@as(u32, 2), decoded.child_count());
    try testing.expect(decoded.children[0].is_hash());
    try testing.expect(decoded.children[8].is_hash());
    try testing.expectEqual(@as(u8, 0xeb), decoded.children[0].bytes[1]);
    try testing.expectEqual(@as(u8, 0x5d), decoded.children[8].bytes[1]);
    try testing.expectEqual(@as(usize, 0), decoded.value.len);
}

test "node: decode extension with an embedded leaf" {
    const extension = hex("d28300646fcd308b8a74657374207468726565");
    const decoded = try decode(&extension);
    try testing.expectEqual(Kind.extension, decoded.kind);
    try testing.expectEqualSlices(u8, &.{ 6, 4, 6, 15 }, decoded.path.slice());
    try testing.expect(!decoded.children[0].is_hash());
    const leaf = try decode(decoded.children[0].slice());
    try testing.expectEqual(Kind.leaf, leaf.kind);
    try testing.expectEqualSlices(u8, &.{0}, leaf.path.slice());
    try testing.expectEqualSlices(u8, &hex("8a74657374207468726565"), leaf.value);
}

test "node: rejects bad shapes" {
    try testing.expectError(error.InvalidNode, decode(&.{0x80}));
    try testing.expectError(error.InvalidNode, decode(&.{ 0xc3, 0x80, 0x80, 0x80 }));
    // Extension with an empty path.
    try testing.expectError(error.InvalidNode, decode(&.{ 0xc2, 0x00, 0x01 }));
    // Leaf with a bad hex-prefix flag.
    try testing.expectError(error.InvalidNode, decode(&.{ 0xc2, 0x40, 0x01 }));
    // Trailing bytes.
    try testing.expectError(error.InvalidNode, decode(&.{ 0xc2, 0x20, 0x01, 0x00 }));
}

fn fuzz_decode(_: void, bytes: []const u8) anyerror!void {
    const decoded = decode(bytes) catch return;
    switch (decoded.kind) {
        .leaf => try testing.expectEqual(@as(u32, 0), decoded.child_count()),
        .extension => try testing.expectEqual(@as(u32, 1), decoded.child_count()),
        .branch => try testing.expect(decoded.path.len == 0),
    }
    for (decoded.children) |child| {
        if (child.len == 0 or child.is_hash()) continue;
        try testing.expect(child.len < 32);
    }
}

test "node: fuzz decode" {
    try fuzz.run_bytes({}, fuzz_decode, .{});
}

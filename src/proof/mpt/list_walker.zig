//! Ordered list walker. Port of base/base `crates/proof/mpt/src/list_walker.rs`.
//!
//! Reads every value of an ordered trie (transactions, receipts, withdrawals: key
//! `rlp(index)`) from its root through a `Resolver`. The Rust walker relies on DFS order
//! and moves the leaf for index 0 to the front; here every leaf key is decoded back to
//! its index and checked to be canonical, unique and in range, and the indices must form
//! `0..count` exactly, so a malformed trie is an error, never a reordered list.
//! Iterative DFS with an explicit, bounded stack.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../../execution/trie/root.zig");
const node = @import("node.zig");
const Hash = trie.Hash;
const RlpNode = trie.RlpNode;
const Nibbles = trie.Nibbles;
const Resolver = trie.sparse.Resolver;

pub const Error = error{
    /// A node on the walk has no preimage.
    WitnessIncomplete,
    /// A node does not decode, or the trie is not a well-formed ordered list.
    InvalidList,
    /// More leaves than the output slice holds.
    ListTooLong,
};

/// Longest `rlp(index)` key in nibbles: one prefix byte and eight index bytes.
pub const key_nibbles_max = 18;
/// Pending nodes: at most 16 per level on one path of `key_nibbles_max` branches.
const stack_max = 16 * (key_nibbles_max + 1);

const Pending = struct {
    ref: RlpNode,
    path: Nibbles,
};

/// Decodes `rlp(index)` from the packed key; null if not a canonical index encoding.
fn decode_index(key: []const u8) ?u64 {
    if (key.len == 0 or key.len > 9) return null;
    var index: u64 = 0;
    if (key.len == 1) {
        if (key[0] == 0x80) return 0;
        if (key[0] == 0 or key[0] > 0x7f) return null;
        index = key[0];
    } else {
        if (key[0] != 0x80 + key.len - 1) return null;
        for (key[1..]) |byte| index = (index << 8) | byte;
        if (index < 0x80) return null;
    }
    var expected: [9]u8 = undefined;
    const encoded = trie.ordered.encode_index(index, &expected);
    return if (std.mem.eql(u8, encoded, key)) index else null;
}

fn node_bytes(resolver: Resolver, ref: *const RlpNode) Error![]const u8 {
    if (!ref.is_hash()) return ref.slice();
    const hash: Hash = ref.bytes[1..33].*;
    const bytes = resolver.resolve(resolver.context, &hash) orelse return error.WitnessIncomplete;
    return bytes;
}

/// Places one leaf's value at its index in `values`.
fn place_leaf(
    path: *const Nibbles,
    value: []const u8,
    values: [][]const u8,
    seen: []bool,
) Error!void {
    if (path.len % 2 != 0 or path.len > key_nibbles_max) return error.InvalidList;
    var key_buffer: [key_nibbles_max / 2]u8 = undefined;
    const key = path.pack(&key_buffer);
    const index = decode_index(key) orelse return error.InvalidList;
    if (index >= values.len) return error.ListTooLong;
    if (seen[@intCast(index)]) return error.InvalidList;
    seen[@intCast(index)] = true;
    values[@intCast(index)] = value;
}

/// Fills `values[0..count]` with the list stored under `root` and returns `count`.
/// Values point into resolver-owned preimages (or into `root`'s embedded node copies,
/// which live in `scratch`), so they stay valid while those do. `seen` must be at least
/// as long as `values`.
pub fn walk(
    resolver: Resolver,
    root: Hash,
    values: [][]const u8,
    seen: []bool,
    scratch: *Scratch,
) Error!u32 {
    assert(seen.len >= values.len);
    if (std.mem.eql(u8, &root, &trie.empty_root)) return 0;
    @memset(seen[0..values.len], false);
    scratch.used = 0;
    var stack: [stack_max]Pending = undefined;
    var stack_len: u32 = 1;
    stack[0] = .{ .ref = RlpNode.from_hash(root), .path = .{} };
    var leaves: u32 = 0;
    while (stack_len > 0) {
        stack_len -= 1;
        const pending = stack[stack_len];
        const bytes = try scratch.keep(try node_bytes(resolver, &pending.ref), pending.ref);
        const decoded = node.decode(bytes) catch return error.InvalidList;
        if (pending.path.len + decoded.path.len > key_nibbles_max) return error.InvalidList;
        var path = pending.path;
        path.append(decoded.path.slice());
        switch (decoded.kind) {
            .leaf => {
                try place_leaf(&path, decoded.value, values, seen);
                leaves += 1;
            },
            .extension => {
                stack[stack_len] = .{ .ref = decoded.children[0], .path = path };
                stack_len += 1;
            },
            .branch => {
                if (decoded.value.len != 0) return error.InvalidList;
                if (decoded.child_count() < 2) return error.InvalidList;
                if (path.len + 1 > key_nibbles_max) return error.InvalidList;
                stack_len = try push_children(&stack, stack_len, &decoded, &path);
            },
        }
    }
    for (seen[0..leaves]) |present| if (!present) return error.InvalidList;
    return leaves;
}

fn push_children(
    stack: *[stack_max]Pending,
    stack_len: u32,
    decoded: *const node.Decoded,
    path: *const Nibbles,
) Error!u32 {
    var len = stack_len;
    var nibble: u8 = 16;
    while (nibble > 0) {
        nibble -= 1;
        const child = decoded.children[nibble];
        if (child.len == 0) continue;
        if (len == stack_max) return error.InvalidList;
        var child_path = path.*;
        child_path.push(nibble);
        stack[len] = .{ .ref = child, .path = child_path };
        len += 1;
    }
    assert(len > stack_len);
    return len;
}

/// Copies of embedded nodes, so values inside them outlive the walk's stack.
pub const Scratch = struct {
    bytes: [scratch_bytes]u8 = undefined,
    used: u32 = 0,

    pub const scratch_bytes = 64 * 1024;

    fn keep(scratch: *Scratch, bytes: []const u8, ref: RlpNode) Error![]const u8 {
        if (ref.is_hash()) return bytes;
        assert(bytes.len < 32);
        if (scratch.used + bytes.len > scratch.bytes.len) return error.ListTooLong;
        const copy = scratch.bytes[scratch.used..][0..bytes.len];
        @memcpy(copy, bytes);
        scratch.used += @intCast(bytes.len);
        return copy;
    }
};

const testing = std.testing;

test "list_walker: decode_index" {
    try testing.expectEqual(@as(?u64, 0), decode_index(&.{0x80}));
    try testing.expectEqual(@as(?u64, 1), decode_index(&.{0x01}));
    try testing.expectEqual(@as(?u64, 0x7f), decode_index(&.{0x7f}));
    try testing.expectEqual(@as(?u64, 0x80), decode_index(&.{ 0x81, 0x80 }));
    try testing.expectEqual(@as(?u64, 0x1234), decode_index(&.{ 0x82, 0x12, 0x34 }));
    try testing.expectEqual(@as(?u64, null), decode_index(&.{0x00}));
    try testing.expectEqual(@as(?u64, null), decode_index(&.{ 0x81, 0x7f }));
    try testing.expectEqual(@as(?u64, null), decode_index(&.{ 0x82, 0x00, 0x80 }));
    try testing.expectEqual(@as(?u64, null), decode_index(&.{0x81}));
}

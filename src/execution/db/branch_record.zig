//! Branch records: the branch nodes of the account and storage tries, stored by path so a
//! disk-backed state can rebuild any node preimage with one point lookup and compute
//! per-block roots incrementally (docs: disk-state import plan, Q3).
//!
//! A record is keyed by its hang path H: the path of its parent branch plus this child's
//! nibble, empty for the root. Its node is `extension(E) -> branch`, or just a branch; the
//! extension above a branch is folded into the branch's record.
//!
//! Key: H packed two nibbles per byte into 32 bytes, padded with 0xF nibbles, then one
//! byte `63 - len(H)`. Byte order of keys is then post-order: every descendant sorts before
//! its ancestor, and siblings sort by nibble. (Proof: a descendant D of A agrees with A on
//! A's nibbles and is <= 0xF at A's first padding nibble; if D continues with only 0xF
//! nibbles, the length byte breaks the tie, smaller for the longer path.) This is the order
//! `HashBuilder` finishes branches in, so its records come out sorted and bulk load without
//! a reorder buffer. Storage-trie keys prefix the 32-byte owner (keccak of the address).
//!
//! Value, `value_bytes_max` (1 077) bytes at most:
//!
//! ```
//! extension_len    u8           0..63
//! extension        ceil(extension_len / 2) bytes, nibbles packed high first, a spare low
//!                               nibble zero
//! state_mask       u16 big-endian, >= 2 bits
//! tree_mask        u16 big-endian, subset of state_mask (children that are records)
//! children         per state_mask bit, nibble order: len u8, then len bytes. len 32: the
//!                  child's keccak hash; len 3..31: the child's inline RLP list.
//! leaf_keys        per state_mask & ~tree_mask bit, nibble order: the leaf's 32-byte key
//! ```
//!
//! Values come from disk, so `decode` checks every field and never asserts on input.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const node = trie.node;
const Hash = node.Hash;
const Nibbles = trie.Nibbles;
const RlpNode = node.RlpNode;

pub const Record = trie.hash_builder.BranchNode;

/// Longest hang path: a branch at depth 63 of a 64-nibble trie hangs at length <= 63.
pub const hang_nibbles_max = 63;
pub const path_key_bytes = 33;
pub const storage_key_bytes = 32 + path_key_bytes;

const extension_bytes_max = (Record.extension_nibbles_max + 1) / 2;
pub const value_bytes_max = 1 + extension_bytes_max + 2 + 2 + 16 * 33 + 16 * 32;

/// Largest branch encoding: 16 hashed children and the empty value, with a 3-byte header.
pub const branch_bytes_max = 3 + 16 * 33 + 1;
/// Largest extension encoding: the 63-nibble hex-prefix string (33 bytes) and a hash child.
pub const extension_encoding_bytes_max = 2 + 33 + 33;

/// The shortest inline child: a leaf `[hp, value]` of two one-byte strings.
const inline_child_bytes_min = 3;

comptime {
    assert(value_bytes_max == 1077);
    assert(extension_bytes_max == 32);
    assert(hang_nibbles_max <= std.math.maxInt(u8));
    assert(Record.extension_nibbles_max == hang_nibbles_max);
}

pub const Error = error{Corrupt};

/// The account-trie key of the record hanging at `hang`.
pub fn path_key(hang: []const u8) [path_key_bytes]u8 {
    assert(hang.len <= hang_nibbles_max);
    var key: [path_key_bytes]u8 = @splat(0xff);
    for (hang, 0..) |nibble, index| {
        assert(nibble < 16);
        const byte = &key[index / 2];
        if (index % 2 == 0) {
            byte.* = nibble << 4 | 0x0f;
        } else {
            byte.* = (byte.* & 0xf0) | nibble;
        }
    }
    key[32] = @intCast(hang_nibbles_max - hang.len);
    assert(key[32] <= hang_nibbles_max);
    return key;
}

/// The storage-trie key: owner (keccak of the address) then the path key.
pub fn storage_key(owner: *const Hash, hang: []const u8) [storage_key_bytes]u8 {
    var key: [storage_key_bytes]u8 = undefined;
    key[0..32].* = owner.*;
    key[32..].* = path_key(hang);
    assert(std.mem.eql(u8, key[0..32], owner));
    return key;
}

/// The hang path of a path key; rejects a bad length byte or non-0xF padding.
pub fn decode_path_key(key: *const [path_key_bytes]u8) Error!Nibbles {
    if (key[32] > hang_nibbles_max) return error.Corrupt;
    const len: u32 = hang_nibbles_max - key[32];
    var result: Nibbles = .{};
    for (0..64) |index| {
        const byte = key[index / 2];
        const nibble = if (index % 2 == 0) byte >> 4 else byte & 0x0f;
        if (index < len) {
            result.push(nibble);
        } else if (nibble != 0x0f) {
            return error.Corrupt;
        }
    }
    assert(result.len == len);
    assert(result.len <= hang_nibbles_max);
    return result;
}

/// Asserts the record invariants `decode` checks; for records built in memory.
fn assert_valid(record: *const Record) void {
    assert(record.extension_len <= Record.extension_nibbles_max);
    assert(record.child_count() >= 2);
    assert(record.tree_mask & ~record.state_mask == 0);
    for (record.extension_slice()) |nibble| assert(nibble < 16);
    for (record.children[0..record.child_count()]) |*child| {
        assert(child.is_hash() or child.len >= inline_child_bytes_min);
        assert(child.is_hash() or child.bytes[0] == 0xc0 + child.len - 1);
    }
}

pub fn encode(record: *const Record, out: *[value_bytes_max]u8) []u8 {
    assert_valid(record);
    out[0] = record.extension_len;
    var offset: usize = 1;
    const extension = record.extension_slice();
    const packed_bytes = (extension.len + 1) / 2;
    @memset(out[offset..][0..packed_bytes], 0);
    for (extension, 0..) |nibble, index| {
        const shift: u3 = if (index % 2 == 0) 4 else 0;
        out[offset + index / 2] |= nibble << shift;
    }
    offset += packed_bytes;
    std.mem.writeInt(u16, out[offset..][0..2], record.state_mask, .big);
    std.mem.writeInt(u16, out[offset + 2 ..][0..2], record.tree_mask, .big);
    offset += 4;
    for (record.children[0..record.child_count()]) |*child| {
        const bytes = if (child.is_hash()) child.bytes[1..33] else child.slice();
        assert(bytes.len <= 32);
        out[offset] = @intCast(bytes.len);
        @memcpy(out[offset + 1 ..][0..bytes.len], bytes);
        offset += 1 + bytes.len;
    }
    for (record.leaf_keys[0..record.leaf_count()]) |*key| {
        out[offset..][0..32].* = key.*;
        offset += 32;
    }
    assert(offset <= value_bytes_max);
    return out[0..offset];
}

/// Decodes and validates `value` into `out`. The encoding is canonical: a value that
/// decodes re-encodes to the same bytes.
pub fn decode(value: []const u8, out: *Record) Error!void {
    if (value.len < 1) return error.Corrupt;
    const extension_len = value[0];
    if (extension_len > Record.extension_nibbles_max) return error.Corrupt;
    const packed_bytes: usize = (@as(usize, extension_len) + 1) / 2;
    if (value.len < 1 + packed_bytes + 4) return error.Corrupt;
    out.extension_len = extension_len;
    for (out.extension[0..extension_len], 0..) |*nibble, index| {
        const byte = value[1 + index / 2];
        nibble.* = if (index % 2 == 0) byte >> 4 else byte & 0x0f;
    }
    if (extension_len % 2 == 1 and value[packed_bytes] & 0x0f != 0) return error.Corrupt;
    var offset: usize = 1 + packed_bytes;
    out.state_mask = std.mem.readInt(u16, value[offset..][0..2], .big);
    out.tree_mask = std.mem.readInt(u16, value[offset + 2 ..][0..2], .big);
    offset += 4;
    if (@popCount(out.state_mask) < 2) return error.Corrupt;
    if (out.tree_mask & ~out.state_mask != 0) return error.Corrupt;
    for (out.children[0..out.child_count()]) |*child| {
        if (offset >= value.len) return error.Corrupt;
        const len = value[offset];
        offset += 1;
        if (len > 32 or len < inline_child_bytes_min) return error.Corrupt;
        if (value.len - offset < len) return error.Corrupt;
        const bytes = value[offset..][0..len];
        offset += len;
        if (len == 32) {
            child.* = RlpNode.from_hash(bytes[0..32].*);
            continue;
        }
        // An inline child is a short RLP list exactly `len` bytes long.
        if (bytes[0] != 0xc0 + len - 1) return error.Corrupt;
        child.* = RlpNode.from_rlp(bytes);
    }
    const leaf_count = out.leaf_count();
    if (value.len - offset != @as(usize, leaf_count) * 32) return error.Corrupt;
    for (out.leaf_keys[0..leaf_count]) |*key| {
        key.* = value[offset..][0..32].*;
        offset += 32;
    }
    assert(offset == value.len);
    assert_valid(out);
}

/// Checks a decoded record against the hang path it was stored under: the branch fits in
/// a 64-nibble trie and every leaf key runs through hang ++ extension ++ its nibble.
pub fn validate_path(hang: []const u8, record: *const Record) Error!void {
    assert(hang.len <= hang_nibbles_max);
    const branch_depth = hang.len + record.extension_len;
    if (branch_depth > hang_nibbles_max) return error.Corrupt;
    const extension = record.extension_slice();
    var leaf: u32 = 0;
    var nibble: u8 = 0;
    while (nibble < 16) : (nibble += 1) {
        if (record.leaf_mask() & (@as(u16, 1) << @intCast(nibble)) == 0) continue;
        const key = Nibbles.from_bytes(&record.leaf_keys[leaf]);
        leaf += 1;
        const path = key.slice();
        if (!std.mem.eql(u8, path[0..hang.len], hang)) return error.Corrupt;
        if (!std.mem.eql(u8, path[hang.len..][0..extension.len], extension)) {
            return error.Corrupt;
        }
        if (path[branch_depth] != nibble) return error.Corrupt;
    }
    assert(leaf == record.leaf_count());
}

/// The branch node's RLP encoding: its keccak (or itself, when shorter than 32 bytes) is
/// the reference its extension, or else its parent, holds.
pub fn branch_encoding(record: *const Record, out: *[branch_bytes_max]u8) []const u8 {
    assert_valid(record);
    var sink: node.BufferSink = .{ .buffer = out };
    const children = record.children[0..record.child_count()];
    node.encode_branch(&sink, record.state_mask, children, &.{});
    assert(sink.written == node.branch_length(record.state_mask, children, &.{}));
    return sink.result();
}

/// The extension node's RLP encoding over the branch reference `branch`.
pub fn extension_encoding(
    record: *const Record,
    branch: *const RlpNode,
    out: *[extension_encoding_bytes_max]u8,
) []const u8 {
    assert(record.extension_len > 0);
    var sink: node.BufferSink = .{ .buffer = out };
    node.encode_extension(&sink, record.extension_slice(), branch);
    assert(sink.written == node.extension_length(record.extension_slice(), branch));
    return sink.result();
}

pub fn branch_reference(record: *const Record) RlpNode {
    assert_valid(record);
    return node.branch_ref(record.state_mask, record.children[0..record.child_count()], &.{});
}

/// The reference the parent branch holds for this record's top node (extension or branch).
pub fn reference(record: *const Record) RlpNode {
    const branch = branch_reference(record);
    if (record.extension_len == 0) return branch;
    return node.extension_ref(record.extension_slice(), &branch);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// A random path; a small alphabet often, so paths share prefixes and 0xF nibbles.
fn random_path(prng: *Prng, out: *[hang_nibbles_max]u8) []u8 {
    const len = prng.below(hang_nibbles_max + 1);
    const narrow = prng.chance(1, 2);
    const alphabet = [_]u8{ 0, 1, 0xe, 0xf };
    for (out[0..len]) |*nibble| {
        nibble.* = if (narrow) alphabet[prng.below(4)] else @intCast(prng.below(16));
    }
    return out[0..len];
}

const PathList = struct {
    paths: [256][hang_nibbles_max]u8 = undefined,
    lens: [256]u8 = undefined,
    count: u32 = 0,

    fn get(self: *const PathList, index: u32) []const u8 {
        return self.paths[index][0..self.lens[index]];
    }

    fn add(self: *PathList, path: []const u8) void {
        for (0..self.count) |index| {
            if (std.mem.eql(u8, self.get(@intCast(index)), path)) return;
        }
        @memcpy(self.paths[self.count][0..path.len], path);
        self.lens[self.count] = @intCast(path.len);
        self.count += 1;
    }

    fn sort(self: *PathList, order: []u32, less: anytype) void {
        for (order, 0..) |*slot, index| slot.* = @intCast(index);
        std.mem.sort(u32, order, self, less);
    }

    fn lexicographic_less(self: *PathList, a: u32, b: u32) bool {
        return std.mem.order(u8, self.get(a), self.get(b)) == .lt;
    }

    fn key_less(self: *PathList, a: u32, b: u32) bool {
        return std.mem.order(u8, &path_key(self.get(a)), &path_key(self.get(b))) == .lt;
    }
};

fn is_prefix(prefix: []const u8, path: []const u8) bool {
    return prefix.len <= path.len and std.mem.eql(u8, prefix, path[0..prefix.len]);
}

/// The reference post-order of the paths: walk them in pre-order (lexicographic), keeping
/// the chain of open ancestors on an explicit stack, and emit a path once the walk leaves
/// its subtree. Descendants come out before ancestors, sibling subtrees in nibble order.
fn post_order_walk(list: *PathList, pre: []const u32, out: []u32) void {
    var stack: [hang_nibbles_max + 1]u32 = undefined;
    var stack_len: u32 = 0;
    var written: u32 = 0;
    for (pre) |index| {
        while (stack_len > 0 and !is_prefix(list.get(stack[stack_len - 1]), list.get(index))) {
            stack_len -= 1;
            out[written] = stack[stack_len];
            written += 1;
        }
        assert(stack_len <= hang_nibbles_max);
        stack[stack_len] = index;
        stack_len += 1;
    }
    while (stack_len > 0) {
        stack_len -= 1;
        out[written] = stack[stack_len];
        written += 1;
    }
    assert(written == pre.len);
}

test "branch record: key order is the post-order of a reference walk" {
    var prng = Prng.init(0xb4a2_c0de);
    var list: PathList = .{};
    var pre: [256]u32 = undefined;
    var walk: [256]u32 = undefined;
    var by_key: [256]u32 = undefined;
    var scratch: [hang_nibbles_max]u8 = undefined;
    for (0..200) |_| {
        list.count = 0;
        const count = prng.range(1, 64);
        for (0..count) |_| {
            const path = random_path(&prng, &scratch);
            list.add(path);
            // Ancestors and siblings too, so most pairs are related.
            if (path.len > 0) list.add(path[0..prng.below(path.len)]);
            if (path.len > 0) {
                path[path.len - 1] = @intCast(prng.below(16));
                list.add(path);
            }
        }
        const n = list.count;
        list.sort(pre[0..n], PathList.lexicographic_less);
        post_order_walk(&list, pre[0..n], walk[0..n]);
        list.sort(by_key[0..n], PathList.key_less);
        try testing.expectEqualSlices(u32, walk[0..n], by_key[0..n]);
        for (by_key[0..n], 0..) |a, position| {
            const key = path_key(list.get(a));
            try testing.expectEqualSlices(u8, list.get(a), (try decode_path_key(&key)).slice());
            for (by_key[position + 1 .. n]) |b| {
                // A later key is never a descendant of an earlier one.
                try testing.expect(!is_prefix(list.get(a), list.get(b)));
            }
        }
    }
}

test "branch record: path key layout" {
    const root = path_key(&.{});
    try testing.expect(std.mem.allEqual(u8, root[0..32], 0xff));
    try testing.expectEqual(@as(u8, 63), root[32]);
    const key = path_key(&.{ 0x1, 0x2, 0x3 });
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x3f, 0xff }, key[0..3]);
    try testing.expectEqual(@as(u8, 60), key[32]);
    var bad = key;
    bad[1] = 0x30; // Zero padding is rejected.
    try testing.expectError(error.Corrupt, decode_path_key(&bad));
    bad = key;
    bad[32] = 64;
    try testing.expectError(error.Corrupt, decode_path_key(&bad));
    const owner: Hash = @splat(0xab);
    const storage = storage_key(&owner, &.{ 0x1, 0x2, 0x3 });
    try testing.expectEqualSlices(u8, &owner, storage[0..32]);
    try testing.expectEqualSlices(u8, &key, storage[32..]);
}

/// A random record that satisfies every invariant.
fn random_record(prng: *Prng, out: *Record) void {
    out.extension_len = @intCast(prng.below(Record.extension_nibbles_max + 1));
    for (out.extension[0..out.extension_len]) |*nibble| nibble.* = @intCast(prng.below(16));
    out.state_mask = 0;
    while (@popCount(out.state_mask) < 2) out.state_mask = prng.int(u16);
    out.tree_mask = out.state_mask & prng.int(u16);
    for (out.children[0..out.child_count()]) |*child| {
        if (prng.chance(3, 4)) {
            var hash: Hash = undefined;
            prng.fill(&hash);
            child.* = RlpNode.from_hash(hash);
            continue;
        }
        var bytes: [31]u8 = undefined;
        const len = prng.range(inline_child_bytes_min, 31);
        prng.fill(bytes[1..len]);
        bytes[0] = @intCast(0xc0 + len - 1);
        child.* = RlpNode.from_rlp(bytes[0..len]);
    }
    for (out.leaf_keys[0..out.leaf_count()]) |*key| prng.fill(key);
}

fn expect_canonical(value: []const u8) !void {
    var record: Record = undefined;
    decode(value, &record) catch return;
    var again: [value_bytes_max]u8 = undefined;
    try testing.expectEqualSlices(u8, value, encode(&record, &again));
}

test "branch record: seeded fuzz: round trip, mutations rejected or canonical" {
    var prng = Prng.init(0xb4a2_f022);
    var buffer: [value_bytes_max]u8 = undefined;
    var mutated: [value_bytes_max + 8]u8 = undefined;
    var record: Record = undefined;
    var decoded: Record = undefined;
    var again: [value_bytes_max]u8 = undefined;
    for (0..3000) |_| {
        random_record(&prng, &record);
        const value = encode(&record, &buffer);
        try decode(value, &decoded);
        try testing.expectEqualSlices(u8, value, encode(&decoded, &again));
        try testing.expectEqualSlices(u8, record.extension_slice(), decoded.extension_slice());
        const want = reference(&record);
        try testing.expectEqualSlices(u8, want.slice(), reference(&decoded).slice());
        // Truncations always fail; extensions always fail; byte flips fail or stay canonical.
        try testing.expectError(error.Corrupt, decode(value[0..prng.below(value.len)], &decoded));
        @memcpy(mutated[0..value.len], value);
        mutated[value.len] = @truncate(prng.int(u8));
        try testing.expectError(error.Corrupt, decode(mutated[0 .. value.len + 1], &decoded));
        for (0..4) |_| {
            @memcpy(mutated[0..value.len], value);
            mutated[prng.below(value.len)] ^= @as(u8, 1) << @intCast(prng.below(8));
            try expect_canonical(mutated[0..value.len]);
        }
    }
}

test "branch record: decode rejects inconsistent masks and refs" {
    var prng = Prng.init(0xb4a2_0bad);
    var record: Record = undefined;
    var buffer: [value_bytes_max]u8 = undefined;
    var decoded: Record = undefined;
    random_record(&prng, &record);
    record.extension_len = 0;
    const value = encode(&record, &buffer);
    var bad: [value_bytes_max]u8 = undefined;
    @memcpy(bad[0..value.len], value);
    bad[0] = 64; // Extension too long.
    try testing.expectError(error.Corrupt, decode(bad[0..value.len], &decoded));
    @memcpy(bad[0..value.len], value);
    std.mem.writeInt(u16, bad[3..5], record.tree_mask | ~record.state_mask, .big);
    try testing.expectError(error.Corrupt, decode(bad[0..value.len], &decoded));
    @memcpy(bad[0..value.len], value);
    std.mem.writeInt(u16, bad[1..3], 0x0010, .big); // One child.
    try testing.expectError(error.Corrupt, decode(bad[0..value.len], &decoded));
    @memcpy(bad[0..value.len], value);
    bad[5] = 33; // Reference too long.
    try testing.expectError(error.Corrupt, decode(bad[0..value.len], &decoded));
    try testing.expectError(error.Corrupt, decode(&.{ 1, 0x10 }, &decoded));
    try testing.expectError(error.Corrupt, decode(&.{}, &decoded));
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [value_bytes_max + 16]u8 = undefined;
    const length = smith.slice(&input);
    // A plausible header makes the fuzzer reach the children more often.
    if (length >= 5 and smith.value(bool)) {
        input[0] = 0;
        std.mem.writeInt(u16, input[1..3], smith.value(u16) | 0x0101, .big);
    }
    try expect_canonical(input[0..length]);
    var record: Record = undefined;
    decode(input[0..length], &record) catch return;
    const hang: [hang_nibbles_max]u8 = @splat(0);
    const hang_len = @min(length % 64, hang_nibbles_max - record.extension_len);
    validate_path(hang[0..hang_len], &record) catch |err| assert(err == error.Corrupt);
    var out: [branch_bytes_max]u8 = undefined;
    _ = branch_encoding(&record, &out);
    _ = reference(&record);
}

test "branch record: std.testing.fuzz decoder" {
    try testing.fuzz({}, fuzz_decode, .{});
}

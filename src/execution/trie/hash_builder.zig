//! Streaming trie root from sorted entries.
//!
//! `HashBuilder` computes a Merkle Patricia Trie root from leaves fed in strictly increasing key
//! order, using a bounded stack of child references and no recursion. It follows the algorithm
//! of alloy-trie's `HashBuilder`, which reth and base/base use for state, storage, transaction,
//! receipt, and withdrawal roots. Besides leaves, it accepts precomputed subtrie hashes
//! (`add_branch`), so an incremental state root can reuse the hashes of unchanged subtries.
//!
//! Each leaf is encoded only once the next key is known, because the next key decides how much
//! of the path the leaf keeps. The builder therefore borrows the most recent leaf value: it must
//! stay valid until the next `add_leaf`, `add_branch`, or `root` call.

const std = @import("std");
const assert = std.debug.assert;

const node = @import("node.zig");
const nibbles_module = @import("nibbles.zig");
const Nibbles = nibbles_module.Nibbles;
const RlpNode = node.RlpNode;
const Hash = node.Hash;

/// A builder for keys of at most `depth_max` nibbles.
/// Receives the encoding of every node the builder hashes (encodings of at least 32
/// bytes, plus the root), streamed as `write` chunks closed by one `end`. Lets callers
/// store trie nodes as keccak preimages (the fault-proof host serves list tries this way).
pub const NodeSink = struct {
    context: *anyopaque,
    write: *const fn (context: *anyopaque, bytes: []const u8) void,
    end: *const fn (context: *anyopaque) void,

    const Writer = struct {
        sink: NodeSink,
        pub fn write(writer: *Writer, bytes: []const u8) void {
            writer.sink.write(writer.sink.context, bytes);
        }
    };
};

/// One branch of a 32-byte-key trie (state or storage) together with the extension above it,
/// if any: the unit stored as a branch record (`db/branch_record.zig`). The branch's
/// value slot is always empty in these tries.
pub const BranchNode = struct {
    /// A branch sits at depth <= 63 of a 64-nibble trie, so its extension has <= 63 nibbles.
    pub const extension_nibbles_max = 63;

    extension_len: u8 = 0,
    /// Nibbles of the extension above the branch, `extension_len` of them.
    extension: [extension_nibbles_max]u8 = undefined,
    /// One bit per present child (bit n = nibble n). At least two bits, or none for the
    /// leaf-root record of a single-leaf trie (its key in `leaf_keys[0]`, nothing else set).
    state_mask: u16 = 0,
    /// Children that are branch records themselves (subset of `state_mask`); the other
    /// present children are leaves.
    tree_mask: u16 = 0,
    /// The present children's references in nibble order, `@popCount(state_mask)` of them.
    children: [16]RlpNode = undefined,
    /// The full key of each leaf child in nibble order, `leaf_count()` of them.
    leaf_keys: [16]Hash = undefined,

    pub fn extension_slice(self: *const BranchNode) []const u8 {
        assert(self.extension_len <= extension_nibbles_max);
        return self.extension[0..self.extension_len];
    }

    pub fn child_count(self: *const BranchNode) u32 {
        return @popCount(self.state_mask);
    }

    pub fn leaf_mask(self: *const BranchNode) u16 {
        assert(self.tree_mask & ~self.state_mask == 0);
        return self.state_mask & ~self.tree_mask;
    }

    pub fn leaf_count(self: *const BranchNode) u32 {
        return @popCount(self.leaf_mask());
    }
};

/// Receives every branch of a 32-byte-key trie as a `BranchNode` (with the extension above it
/// folded in), keyed by its hang path: the parent branch's path plus this child's nibble,
/// empty for the root. Branches arrive in post-order (descendants first, siblings by
/// nibble), the order the builder finishes them, so no reordering is needed. A trie that is
/// one leaf emits a leaf-root record instead (empty hang, `state_mask` 0). Kept apart
/// from the hash-keyed `NodeSink`: this one is path-aware and needs per-entry state, which
/// lives here so a builder without a sink stays as small as before.
pub const BranchSink = struct {
    /// The stack capacity of a 64-nibble builder.
    pub const entries_max = 64 * 16 + 1;

    context: *anyopaque,
    emit: *const fn (context: *anyopaque, hang: []const u8, branch: *const BranchNode) void,
    /// Builder scratch, parallel to its stack: whether each entry is a leaf, and its key.
    leaf: [entries_max]bool = undefined,
    leaf_keys: [entries_max]Hash = undefined,
    /// The branch built last, waiting for its extension (known one fold later).
    pending: BranchNode = .{},
    pending_set: bool = false,
};

pub fn HashBuilderType(comptime depth_max: u32) type {
    comptime assert(depth_max > 0 and depth_max <= nibbles_module.nibbles_max);
    return struct {
        const Self = @This();

        /// Each pending branch level holds at most 16 children on the stack, plus the node
        /// being built.
        pub const stack_capacity = depth_max * 16 + 1;

        const Value = union(enum) {
            none,
            leaf: []const u8,
            hash: Hash,
        };

        key: Nibbles = .{},
        value: Value = .none,
        groups: [depth_max]u16 = undefined,
        groups_len: u32 = 0,
        stack: [stack_capacity]RlpNode = undefined,
        stack_len: u32 = 0,
        /// Optional: receives every hashed node's encoding.
        node_sink: ?NodeSink = null,
        /// Optional: receives every branch as a path-keyed record (64-nibble keys only, no
        /// `add_branch`). Must outlive the builder's use; `reset` clears it.
        branch_sink: ?*BranchSink = null,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.* = .{};
        }

        /// Adds a leaf. Keys must strictly increase and no key may prefix another.
        pub fn add_leaf(self: *Self, key: []const u8, value: []const u8) void {
            assert(key.len > 0 and key.len <= depth_max);
            assert(value.len > 0);
            assert(self.branch_sink == null or (depth_max == 64 and key.len == 64));
            self.advance(key);
            self.value = .{ .leaf = value };
        }

        /// Adds the hash of a whole subtrie rooted at path `key`. The hash must belong to a
        /// node whose encoding is at least 32 bytes, as every stored branch node's is.
        pub fn add_branch(self: *Self, key: []const u8, hash: Hash) void {
            assert(key.len <= depth_max);
            // A precomputed subtrie has no records to emit.
            assert(self.branch_sink == null);
            self.advance(key);
            self.value = .{ .hash = hash };
        }

        fn advance(self: *Self, key: []const u8) void {
            if (self.value != .none) {
                assert(nibbles_module.order(self.key.slice(), key) == .lt);
                self.update(key);
            }
            self.key = Nibbles.from_nibbles(key);
        }

        /// Finishes the trie and returns its root. The builder is spent; call `reset` to reuse.
        pub fn root(self: *Self) Hash {
            if (self.value != .none) {
                self.update(&.{});
                self.value = .none;
                self.key = .{};
            }
            assert(self.stack_len <= 1);
            if (self.stack_len == 0) return node.empty_root;
            if (self.branch_sink) |sink| if (sink.leaf[0]) {
                // A single-leaf trie has no branch: its root gets a leaf-root record.
                var record: BranchNode = .{};
                record.leaf_keys[0] = sink.leaf_keys[0];
                assert(record.state_mask == 0 and !sink.pending_set);
                sink.emit(sink.context, &.{}, &record);
            };
            // An inline root is still hashed: its encoding is a preimage too.
            if (self.node_sink) |sink| if (!self.stack[0].is_hash()) {
                sink.write(sink.context, self.stack[0].slice());
                sink.end(sink.context);
            };
            return self.stack[0].root_hash();
        }

        fn emit_leaf(self: *Self, path: []const u8, value: []const u8) void {
            const sink = self.node_sink orelse return;
            var hp: [nibbles_module.hex_prefix_bytes_max]u8 = undefined;
            const compact = hp[0..nibbles_module.hex_prefix_encode(path, true, &hp)];
            if (node.leaf_length_compact(compact, value) < 32) return;
            var writer: NodeSink.Writer = .{ .sink = sink };
            node.encode_leaf_compact(&writer, compact, value);
            sink.end(sink.context);
        }

        fn push(self: *Self, reference: RlpNode) void {
            assert(self.stack_len < stack_capacity);
            self.stack[self.stack_len] = reference;
            self.stack_len += 1;
        }

        fn pop(self: *Self) RlpNode {
            assert(self.stack_len > 0);
            self.stack_len -= 1;
            return self.stack[self.stack_len];
        }

        fn set_group_bit(self: *Self, level: u32, nibble: u8) void {
            assert(level < depth_max);
            assert(nibble < 16);
            while (self.groups_len <= level) : (self.groups_len += 1) {
                self.groups[self.groups_len] = 0;
            }
            self.groups[level] |= @as(u16, 1) << @intCast(nibble);
        }

        /// Folds the current entry into the stack given the key that follows it (empty at the
        /// end). Every iteration moves up at least one level, so the loop is bounded.
        fn update(self: *Self, succeeding: []const u8) void {
            if (self.branch_sink) |sink| assert(!sink.pending_set);
            var current = self.key;
            var build_extensions = false;
            var iterations: u32 = 0;
            while (true) : (iterations += 1) {
                assert(iterations <= depth_max);
                const preceding_exists = self.groups_len > 0;
                const preceding_len: u32 = if (preceding_exists) self.groups_len - 1 else 0;
                const common = nibbles_module.common_prefix_length(succeeding, current.slice());
                const len = @max(preceding_len, common);
                assert(len < current.len);
                self.set_group_bit(len, current.data[len]);

                const len_from = len + @intFromBool(succeeding.len > 0 or preceding_exists);
                const short_key = current.slice()[len_from..];
                if (!build_extensions) {
                    switch (self.value) {
                        .none => unreachable, // update() runs only with a pending entry.
                        .leaf => |value| {
                            self.emit_leaf(short_key, value);
                            self.push(node.leaf_ref(short_key, value));
                            if (self.branch_sink) |sink| self.track_leaf(sink);
                        },
                        .hash => |hash| {
                            self.push(RlpNode.from_hash(hash));
                            build_extensions = true;
                        },
                    }
                }
                if (build_extensions and short_key.len > 0) {
                    const child = self.pop();
                    if (self.node_sink) |sink| {
                        if (node.extension_length(short_key, &child) >= 32) {
                            var writer: NodeSink.Writer = .{ .sink = sink };
                            node.encode_extension(&writer, short_key, &child);
                            sink.end(sink.context);
                        }
                    }
                    self.push(node.extension_ref(short_key, &child));
                }
                // The branch folded last now has its extension and hang path.
                if (self.branch_sink) |sink| if (sink.pending_set) {
                    assert(build_extensions);
                    emit_branch(sink, current.slice()[0..len_from], short_key);
                };
                if (preceding_len <= common and succeeding.len > 0) return;
                if (succeeding.len > 0 or preceding_exists) self.push_branch(len);
                self.groups_len = len;
                if (preceding_len == 0) {
                    // Only the root branch returns before its fold: no extension, no hang.
                    if (self.branch_sink) |sink| if (sink.pending_set) {
                        assert(succeeding.len == 0 and len == 0);
                        emit_branch(sink, &.{}, &.{});
                    };
                    return;
                }
                current.truncate(preceding_len);
                while (self.groups_len > 0 and self.groups[self.groups_len - 1] == 0) {
                    self.groups_len -= 1;
                }
                build_extensions = true;
            }
        }

        fn push_branch(self: *Self, level: u32) void {
            const mask = self.groups[level];
            const count = @popCount(mask);
            assert(count >= 2);
            assert(self.stack_len >= count);
            const first = self.stack_len - count;
            if (self.node_sink) |sink| {
                const children = self.stack[first..self.stack_len];
                if (node.branch_length(mask, children, &.{}) >= 32) {
                    var writer: NodeSink.Writer = .{ .sink = sink };
                    node.encode_branch(&writer, mask, children, &.{});
                    sink.end(sink.context);
                }
            }
            if (self.branch_sink) |sink| self.track_branch(sink, mask, first);
            const reference = node.branch_ref(mask, self.stack[first..self.stack_len], &.{});
            self.stack_len = first;
            self.push(reference);
            if (self.branch_sink) |sink| sink.leaf[first] = false;
        }

        fn track_leaf(self: *Self, sink: *BranchSink) void {
            assert(self.stack_len > 0 and self.stack_len <= BranchSink.entries_max);
            assert(self.key.len == 64);
            const index = self.stack_len - 1;
            sink.leaf[index] = true;
            _ = self.key.pack(&sink.leaf_keys[index]);
        }

        /// Records the branch about to replace `stack[first..]`; emitted once its extension
        /// (or lack of one) is known.
        fn track_branch(self: *Self, sink: *BranchSink, mask: u16, first: u32) void {
            assert(!sink.pending_set);
            assert(self.stack_len - first == @popCount(mask));
            const branch = &sink.pending;
            branch.* = .{ .state_mask = mask };
            var leaves: u32 = 0;
            var child: u32 = 0;
            var nibble: u8 = 0;
            while (nibble < 16) : (nibble += 1) {
                const bit = @as(u16, 1) << @intCast(nibble);
                if (mask & bit == 0) continue;
                const index = first + child;
                branch.children[child] = self.stack[index];
                child += 1;
                if (sink.leaf[index]) {
                    branch.leaf_keys[leaves] = sink.leaf_keys[index];
                    leaves += 1;
                } else {
                    branch.tree_mask |= bit;
                }
            }
            assert(child == branch.child_count());
            assert(leaves == branch.leaf_count());
            sink.pending_set = true;
        }

        fn emit_branch(sink: *BranchSink, hang: []const u8, extension: []const u8) void {
            assert(sink.pending_set);
            assert(hang.len + extension.len < 64);
            const branch = &sink.pending;
            branch.extension_len = @intCast(extension.len);
            @memcpy(branch.extension[0..extension.len], extension);
            sink.pending_set = false;
            sink.emit(sink.context, hang, branch);
        }
    };
}

/// Builder for 32-byte keys: state and storage tries.
pub const HashBuilder = HashBuilderType(64);

const testing = std.testing;

test "hash builder: empty trie" {
    var builder = HashBuilder.init();
    try testing.expectEqual(node.empty_root, builder.root());
}

test "hash builder: trie test vector 'hex'" {
    var builder = HashBuilderType(8).init();
    builder.add_leaf(&.{ 0, 0, 4, 5 }, &.{ 0x01, 0x23, 0x45, 0x67, 0x89 });
    builder.add_leaf(&.{ 4, 5, 0, 0 }, &.{ 0x98, 0x76, 0x54, 0x32, 0x10 });
    const expected = node.hex_to_hash(
        "285505fcabe84badc8aa310e2aae17eddc7d120aabec8a476902c8184b3a3503",
    );
    try testing.expectEqual(expected, builder.root());
}

test "hash builder: trie test vector 'singleItem'" {
    var builder = HashBuilderType(2).init();
    builder.add_leaf(&.{ 4, 1 }, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const expected = node.hex_to_hash(
        "d23786fb4a010da3ce639d66d5e904a11dbc02746d1ce25029e53290cabf28ab",
    );
    try testing.expectEqual(expected, builder.root());
}

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
            self.advance(key);
            self.value = .{ .leaf = value };
        }

        /// Adds the hash of a whole subtrie rooted at path `key`. The hash must belong to a
        /// node whose encoding is at least 32 bytes, as every stored branch node's is.
        pub fn add_branch(self: *Self, key: []const u8, hash: Hash) void {
            assert(key.len <= depth_max);
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
            return self.stack[0].root_hash();
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
                        .leaf => |value| self.push(node.leaf_ref(short_key, value)),
                        .hash => |hash| {
                            self.push(RlpNode.from_hash(hash));
                            build_extensions = true;
                        },
                    }
                }
                if (build_extensions and short_key.len > 0) {
                    const child = self.pop();
                    self.push(node.extension_ref(short_key, &child));
                }
                if (preceding_len <= common and succeeding.len > 0) return;
                if (succeeding.len > 0 or preceding_exists) self.push_branch(len);
                self.groups_len = len;
                if (preceding_len == 0) return;
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
            const reference = node.branch_ref(mask, self.stack[first..self.stack_len], &.{});
            self.stack_len = first;
            self.push(reference);
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

//! Mutable in-memory Merkle Patricia Trie with cached node hashes.
//!
//! Nodes live in a fixed pool allocated once at `init`; inserts and deletes never allocate.
//! A node holds only what its kind needs (packed path and inline value for a leaf, 17 child
//! indices for a branch, the 17th being its value leaf). Every node caches its child reference
//! (`RlpNode`) in a parallel array, apart from the traversal data. A write clears the cache
//! only on the nodes along the written path, so `root_hash` rehashes just the dirty paths: the
//! cost of a root after `k` updates is about `k * depth` node hashes instead of the whole trie.
//!
//! All walks are iterative with explicit, bounded stacks. Keys of any length up to the
//! configured maximum are allowed, and a key may prefix another (the branch then carries a
//! value), so the public `trietest` vectors run unmodified.

const std = @import("std");
const assert = std.debug.assert;

const node = @import("node.zig");
const rlp = @import("rlp.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const nibbles_module = @import("nibbles.zig");
const Nibbles = nibbles_module.Nibbles;
const RlpNode = node.RlpNode;
const Hash = node.Hash;

pub const Config = struct {
    key_bytes_max: u32 = 32,
    value_size_max: u32 = 128,
    /// Rehash dirty nodes level by level with `keccak256_batch` (deepest level first). When
    /// false, a post-order walk hashes one node at a time; that path is the reference the
    /// batched one is fuzzed against.
    hash_batched: bool = true,
};

pub const Error = error{TrieFull};

pub fn TrieType(comptime config: Config) type {
    comptime assert(config.key_bytes_max > 0);
    comptime assert(config.key_bytes_max <= nibbles_module.key_bytes_max);
    comptime assert(config.value_size_max > 0 and config.value_size_max < (1 << 16));
    return struct {
        const Self = @This();

        pub const NodeIndex = u32;
        pub const none: NodeIndex = std.math.maxInt(NodeIndex);
        pub const path_max = config.key_bytes_max * 2;
        /// Every node on a path consumes a nibble, except that an extension and its branch
        /// together consume at least two; leaves end the path.
        pub const depth_max = path_max * 2 + 2;
        /// One insert creates at most a branch, a leaf, and an extension.
        pub const nodes_per_insert_max = 3;
        /// Largest full node encoding: a branch with 16 hashed children and a maximal value.
        pub const node_bytes_max = 3 + 16 * 33 + 3 + config.value_size_max;

        fn key_nibble(key: []const u8, at: u32) u8 {
            assert(at < key.len * 2);
            const byte = key[at >> 1];
            return if (at & 1 == 0) byte >> 4 else byte & 0x0f;
        }

        /// Bytes of a packed path: the hex-prefix layout without the flag nibble.
        pub const path_bytes_max = config.key_bytes_max + 1;
        /// A branch keeps its value as a leaf with an empty path in this extra child slot.
        pub const value_slot = 16;

        pub const Kind = enum(u8) { free, leaf, extension, branch };

        const Leaf = extern struct {
            path: [path_bytes_max]u8,
            value: [config.value_size_max]u8,
        };

        const Extension = extern struct {
            path: [path_bytes_max]u8,
            /// The child, or the next free node while on the free list.
            child: NodeIndex,
        };

        /// One layout per kind: a leaf never needs children, a branch never needs a path.
        const Body = extern union {
            leaf: Leaf,
            extension: Extension,
            /// Children by nibble, then the value leaf at `value_slot`.
            branch: [17]NodeIndex,
        };

        /// Hot traversal data only; the cached child reference of node `i` is `cache[i]`.
        pub const Node = extern struct {
            kind: Kind,
            /// Path length in nibbles (leaf and extension).
            path_len: u8,
            /// Value length in bytes (leaf).
            value_len: u16,
            body: Body,

            /// The packed path: nibble `i` sits at nibble position `i + 2 - path_len % 2`, so
            /// the bytes are the hex-prefix encoding once the flag nibble is set.
            fn path_packed(self: *const Node) []const u8 {
                assert(self.kind == .leaf or self.kind == .extension);
                return self.body.leaf.path[0 .. self.path_len / 2 + 1];
            }

            fn path_nibble(self: *const Node, index: u32) u8 {
                assert(index < self.path_len);
                const position = index + 2 - (self.path_len & 1);
                const byte = self.body.leaf.path[position >> 1];
                return if (position & 1 == 0) byte >> 4 else byte & 0x0f;
            }

            fn path_unpack(self: *const Node, out: *[path_max]u8) []u8 {
                assert(self.kind == .leaf or self.kind == .extension);
                for (out[0..self.path_len], 0..) |*nibble, index| {
                    nibble.* = self.path_nibble(@intCast(index));
                }
                return out[0..self.path_len];
            }

            /// Writes the hex-prefix encoding of the path, with the leaf or extension flag.
            fn hex_prefix(self: *const Node, out: *[path_bytes_max]u8) []const u8 {
                assert(self.kind == .leaf or self.kind == .extension);
                const path = self.path_packed();
                @memcpy(out[0..path.len], path);
                const leaf: u8 = @intFromBool(self.kind == .leaf);
                assert(out[0] >> 4 == 0);
                out[0] |= (leaf * 2 + (self.path_len & 1)) << 4;
                return out[0..path.len];
            }

            /// Length of the common prefix of the path and `rest`.
            fn common_prefix(self: *const Node, rest: []const u8) u32 {
                const limit: u32 = @intCast(@min(self.path_len, rest.len));
                var index: u32 = 0;
                while (index < limit and self.path_nibble(index) == rest[index]) index += 1;
                assert(index <= self.path_len);
                return index;
            }

            /// Whether the path equals the key nibbles from `at` to the end, compared packed:
            /// equal lengths force `at` and the stored path onto the same nibble parity.
            fn path_equals_key_tail(self: *const Node, key: []const u8, at: u32) bool {
                assert(at <= key.len * 2);
                if (key.len * 2 - at != self.path_len) return false;
                assert(at & 1 == self.path_len & 1);
                const half = self.path_len / 2;
                const stored = self.body.leaf.path[1..][0..half];
                if (!std.mem.eql(u8, stored, key[(at + 1) / 2 ..][0..half])) return false;
                if (self.path_len & 1 == 0) return true;
                return self.body.leaf.path[0] & 0x0f == key[at / 2] & 0x0f;
            }

            /// Whether the path is a prefix of the key nibbles from `at`.
            fn path_prefixes_key(self: *const Node, key: []const u8, at: u32) bool {
                assert(at <= key.len * 2);
                if (key.len * 2 - at < self.path_len) return false;
                var index: u32 = 0;
                while (index < self.path_len) : (index += 1) {
                    if (self.path_nibble(index) != key_nibble(key, at + index)) return false;
                }
                return true;
            }

            fn path_equals(self: *const Node, rest: []const u8) bool {
                return rest.len == self.path_len and self.common_prefix(rest) == self.path_len;
            }

            fn path_prefixes(self: *const Node, rest: []const u8) bool {
                return rest.len >= self.path_len and self.common_prefix(rest) == self.path_len;
            }

            fn set_path(self: *Node, path: []const u8) void {
                assert(self.kind == .leaf or self.kind == .extension);
                assert(path.len <= path_max);
                const offset = 2 - (path.len & 1);
                const out = &self.body.leaf.path;
                @memset(out[0 .. path.len / 2 + 1], 0);
                for (path, 0..) |nibble, index| {
                    assert(nibble < 16);
                    const position = index + offset;
                    const shift: u3 = if (position & 1 == 0) 4 else 0;
                    out[position >> 1] |= nibble << shift;
                }
                self.path_len = @intCast(path.len);
                assert(self.path_packed().len == path.len / 2 + 1);
            }

            fn prepend_path(self: *Node, prefix: []const u8) void {
                const len = self.path_len + prefix.len;
                assert(len <= path_max);
                var buffer: [path_max]u8 = undefined;
                var suffix: [path_max]u8 = undefined;
                @memcpy(buffer[0..prefix.len], prefix);
                @memcpy(buffer[prefix.len..len], self.path_unpack(&suffix));
                self.set_path(buffer[0..len]);
            }

            fn append_path(self: *Node, suffix: []const u8) void {
                const len = self.path_len + suffix.len;
                assert(len <= path_max);
                var buffer: [path_max]u8 = undefined;
                _ = self.path_unpack(buffer[0..path_max]);
                @memcpy(buffer[self.path_len..len], suffix);
                self.set_path(buffer[0..len]);
            }

            fn value_slice(self: *const Node) []const u8 {
                assert(self.kind == .leaf);
                assert(self.value_len > 0);
                return self.body.leaf.value[0..self.value_len];
            }

            fn set_value(self: *Node, value: []const u8) void {
                assert(self.kind == .leaf);
                assert(value.len > 0 and value.len <= config.value_size_max);
                @memcpy(self.body.leaf.value[0..value.len], value);
                self.value_len = @intCast(value.len);
            }

            fn child_count(self: *const Node) u32 {
                assert(self.kind == .branch);
                var count: u32 = 0;
                for (self.body.branch[0..16]) |child| count += @intFromBool(child != none);
                return count;
            }
        };

        comptime {
            assert(@offsetOf(Leaf, "path") == @offsetOf(Extension, "path"));
            assert(@offsetOf(Node, "body") == 4);
            const body_bytes = @max(@sizeOf(Leaf), @sizeOf(Extension), 17 * @sizeOf(NodeIndex));
            assert(@sizeOf(Node) == 4 + std.mem.alignForward(usize, body_bytes, 4));
            assert(@sizeOf(RlpNode) == 34);
        }

        nodes: []Node,
        /// Child reference of each node; `len == 0` marks it dirty. Kept apart from `nodes`
        /// so lookups stream through hot traversal data only.
        cache: []RlpNode,
        free_head: NodeIndex,
        free_count: u32,
        root: NodeIndex = none,
        /// Scratch for the batched rehash: one `key << 32 | index` entry per dirty node, keyed
        /// first by depth, then by encoding length. Empty when hashing is not batched.
        order: []u64,

        pub fn init(allocator: std.mem.Allocator, node_count_max: u32) !Self {
            assert(node_count_max >= nodes_per_insert_max);
            assert(node_count_max < none);
            const nodes = try allocator.alloc(Node, node_count_max);
            errdefer allocator.free(nodes);
            const cache = try allocator.alloc(RlpNode, node_count_max);
            errdefer allocator.free(cache);
            const order_len: u32 = if (config.hash_batched) node_count_max else 0;
            const order = try allocator.alloc(u64, order_len);
            var self: Self = .{
                .nodes = nodes,
                .cache = cache,
                .free_head = none,
                .free_count = 0,
                .order = order,
            };
            self.clear();
            return self;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.order);
            allocator.free(self.cache);
            allocator.free(self.nodes);
            self.* = undefined;
        }

        /// Removes every entry. The pool is kept.
        pub fn clear(self: *Self) void {
            self.free_head = none;
            var index: u32 = @intCast(self.nodes.len);
            while (index > 0) {
                index -= 1;
                self.nodes[index].kind = .free;
                self.nodes[index].body.extension.child = self.free_head;
                self.free_head = index;
            }
            self.free_count = @intCast(self.nodes.len);
            self.root = none;
        }

        pub fn node_count(self: *const Self) u32 {
            return @as(u32, @intCast(self.nodes.len)) - self.free_count;
        }

        fn allocate(self: *Self, kind: Kind) NodeIndex {
            assert(kind != .free);
            assert(self.free_count > 0);
            const index = self.free_head;
            const result = &self.nodes[index];
            assert(result.kind == .free);
            self.free_head = result.body.extension.child;
            self.free_count -= 1;
            result.kind = kind;
            result.path_len = 0;
            result.value_len = 0;
            switch (kind) {
                .free => unreachable, // Asserted above.
                .leaf => {},
                .extension => result.body.extension.child = none,
                .branch => result.body.branch = @splat(none),
            }
            self.cache[index] = .{};
            return index;
        }

        fn release(self: *Self, index: NodeIndex) void {
            assert(self.nodes[index].kind != .free);
            self.nodes[index].kind = .free;
            self.nodes[index].body.extension.child = self.free_head;
            self.free_head = index;
            self.free_count += 1;
            assert(self.free_count <= self.nodes.len);
        }

        fn new_leaf(self: *Self, path: []const u8, value: []const u8) NodeIndex {
            const index = self.allocate(.leaf);
            self.nodes[index].set_path(path);
            self.nodes[index].set_value(value);
            return index;
        }

        fn new_extension(self: *Self, path: []const u8, child: NodeIndex) NodeIndex {
            assert(path.len > 0);
            assert(child != none);
            const index = self.allocate(.extension);
            self.nodes[index].set_path(path);
            self.nodes[index].body.extension.child = child;
            return index;
        }

        /// The value of a branch, empty when it has none.
        fn branch_value(self: *const Self, current: *const Node) []const u8 {
            assert(current.kind == .branch);
            const value_index = current.body.branch[value_slot];
            if (value_index == none) return &.{};
            const value_leaf = &self.nodes[value_index];
            assert(value_leaf.kind == .leaf and value_leaf.path_len == 0);
            return value_leaf.value_slice();
        }

        fn set_branch_value(self: *Self, branch: NodeIndex, value: []const u8) void {
            assert(self.nodes[branch].kind == .branch);
            const value_index = self.nodes[branch].body.branch[value_slot];
            if (value_index == none) {
                const leaf = self.new_leaf(&.{}, value);
                self.nodes[branch].body.branch[value_slot] = leaf;
            } else {
                assert(self.nodes[value_index].path_len == 0);
                self.nodes[value_index].set_value(value);
            }
        }

        pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
            return self.get_in(self.root, key);
        }

        /// Looks up `key` in the trie rooted at `root`, one of many roots sharing this pool.
        /// Walks the packed key directly; `at` is the next key nibble.
        pub fn get_in(self: *const Self, root: NodeIndex, key: []const u8) ?[]const u8 {
            assert(key.len <= config.key_bytes_max);
            const key_nibbles: u32 = @intCast(key.len * 2);
            var at: u32 = 0;
            var index = root;
            var depth: u32 = 0;
            while (index != none) : (depth += 1) {
                assert(depth <= depth_max);
                assert(at <= key_nibbles);
                const current = &self.nodes[index];
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => {
                        if (!current.path_equals_key_tail(key, at)) return null;
                        return current.value_slice();
                    },
                    .extension => {
                        if (!current.path_prefixes_key(key, at)) return null;
                        at += current.path_len;
                        index = current.body.extension.child;
                    },
                    .branch => {
                        if (at == key_nibbles) {
                            const value_index = current.body.branch[value_slot];
                            if (value_index == none) return null;
                            return self.nodes[value_index].value_slice();
                        }
                        index = current.body.branch[key_nibble(key, at)];
                        at += 1;
                    },
                }
            }
            return null;
        }

        /// Inserts or replaces `key`. Fails without changing the trie if the pool is too full.
        pub fn put(self: *Self, key: []const u8, value: []const u8) Error!void {
            return self.put_in(&self.root, key, value);
        }

        pub fn put_in(
            self: *Self,
            root: *NodeIndex,
            key: []const u8,
            value: []const u8,
        ) Error!void {
            assert(key.len <= config.key_bytes_max);
            assert(value.len > 0 and value.len <= config.value_size_max);
            if (self.free_count < nodes_per_insert_max) return error.TrieFull;
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var slot: *NodeIndex = root;
            var depth: u32 = 0;
            while (true) : (depth += 1) {
                assert(depth <= depth_max);
                if (slot.* == none) {
                    slot.* = self.new_leaf(rest, value);
                    return;
                }
                const current = &self.nodes[slot.*];
                self.cache[slot.*] = .{};
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => return self.split_leaf(slot, rest, value),
                    .extension => {
                        const common = current.common_prefix(rest);
                        if (common < current.path_len) {
                            return self.split_extension(slot, common, rest, value);
                        }
                        rest = rest[common..];
                        slot = &current.body.extension.child;
                    },
                    .branch => {
                        if (rest.len == 0) return self.set_branch_value(slot.*, value);
                        slot = &current.body.branch[rest[0]];
                        rest = rest[1..];
                    },
                }
            }
        }

        /// Places `value` at `rest` below the fresh branch `branch`, `common` nibbles in.
        fn place_value(
            self: *Self,
            branch: NodeIndex,
            common: u32,
            rest: []const u8,
            value: []const u8,
        ) void {
            assert(self.nodes[branch].kind == .branch);
            if (rest.len == common) {
                self.set_branch_value(branch, value);
            } else {
                const leaf = self.new_leaf(rest[common + 1 ..], value);
                assert(self.nodes[branch].body.branch[rest[common]] == none);
                self.nodes[branch].body.branch[rest[common]] = leaf;
            }
        }

        fn split_leaf(self: *Self, slot: *NodeIndex, rest: []const u8, value: []const u8) void {
            const leaf_index = slot.*;
            const leaf = &self.nodes[leaf_index];
            assert(leaf.kind == .leaf);
            const common = leaf.common_prefix(rest);
            if (common == leaf.path_len and common == rest.len) return leaf.set_value(value);

            var buffer: [path_max]u8 = undefined;
            const leaf_path = leaf.path_unpack(&buffer);
            const branch = self.allocate(.branch);
            if (leaf_path.len == common) {
                // The old leaf becomes the branch value: a leaf with an empty path.
                leaf.set_path(&.{});
                self.nodes[branch].body.branch[value_slot] = leaf_index;
            } else {
                const nibble = leaf_path[common];
                leaf.set_path(leaf_path[common + 1 ..]);
                self.nodes[branch].body.branch[nibble] = leaf_index;
            }
            self.cache[leaf_index] = .{};
            self.place_value(branch, common, rest, value);
            slot.* = if (common > 0) self.new_extension(rest[0..common], branch) else branch;
        }

        fn split_extension(
            self: *Self,
            slot: *NodeIndex,
            common: u32,
            rest: []const u8,
            value: []const u8,
        ) void {
            const extension_index = slot.*;
            const extension = &self.nodes[extension_index];
            assert(extension.kind == .extension);
            assert(common < extension.path_len);
            var buffer: [path_max]u8 = undefined;
            const path = extension.path_unpack(&buffer);
            const branch = self.allocate(.branch);
            const nibble = path[common];
            var reused = false;
            if (path.len - common - 1 == 0) {
                self.nodes[branch].body.branch[nibble] = extension.body.extension.child;
            } else {
                extension.set_path(path[common + 1 ..]);
                self.nodes[branch].body.branch[nibble] = extension_index;
                reused = true;
            }
            self.place_value(branch, common, rest, value);
            if (common == 0) {
                if (!reused) self.release(extension_index);
                slot.* = branch;
            } else if (reused) {
                slot.* = self.new_extension(path[0..common], branch);
            } else {
                extension.set_path(path[0..common]);
                extension.body.extension.child = branch;
            }
        }

        /// Removes `key`. Returns whether it was present.
        pub fn delete(self: *Self, key: []const u8) bool {
            return self.delete_in(&self.root, key);
        }

        pub fn delete_in(self: *Self, root: *NodeIndex, key: []const u8) bool {
            assert(key.len <= config.key_bytes_max);
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var stack: [depth_max]*NodeIndex = undefined;
            var stack_len: u32 = 0;
            var slot: *NodeIndex = root;
            while (true) {
                assert(stack_len < depth_max);
                if (slot.* == none) return false;
                const current = &self.nodes[slot.*];
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => {
                        if (!current.path_equals(rest)) return false;
                        self.release(slot.*);
                        slot.* = none;
                        break;
                    },
                    .extension => {
                        if (!current.path_prefixes(rest)) return false;
                        stack[stack_len] = slot;
                        stack_len += 1;
                        rest = rest[current.path_len..];
                        slot = &current.body.extension.child;
                    },
                    .branch => {
                        if (rest.len == 0) {
                            const value_index = current.body.branch[value_slot];
                            if (value_index == none) return false;
                            stack[stack_len] = slot;
                            stack_len += 1;
                            self.release(value_index);
                            current.body.branch[value_slot] = none;
                            break;
                        }
                        stack[stack_len] = slot;
                        stack_len += 1;
                        slot = &current.body.branch[rest[0]];
                        rest = rest[1..];
                    },
                }
            }
            while (stack_len > 0) {
                stack_len -= 1;
                self.normalize(stack[stack_len]);
            }
            return true;
        }

        /// Restores the canonical shape of the node at `slot` after a delete below it.
        fn normalize(self: *Self, slot: *NodeIndex) void {
            const index = slot.*;
            assert(index != none);
            const current = &self.nodes[index];
            self.cache[index] = .{};
            switch (current.kind) {
                .free, .leaf => unreachable, // Only branches and extensions are on the path.
                .extension => {
                    const child_index = current.body.extension.child;
                    const child = &self.nodes[child_index];
                    var buffer: [path_max]u8 = undefined;
                    switch (child.kind) {
                        .free => unreachable, // Reachable nodes are never on the free list.
                        .branch => {},
                        .leaf => {
                            child.prepend_path(current.path_unpack(&buffer));
                            self.cache[child_index] = .{};
                            slot.* = child_index;
                            self.release(index);
                        },
                        .extension => {
                            const grandchild = child.body.extension.child;
                            current.append_path(child.path_unpack(&buffer));
                            self.release(child_index);
                            current.body.extension.child = grandchild;
                        },
                    }
                },
                .branch => self.normalize_branch(slot),
            }
        }

        fn normalize_branch(self: *Self, slot: *NodeIndex) void {
            const index = slot.*;
            const current = &self.nodes[index];
            assert(current.kind == .branch);
            const count = current.child_count();
            const value_index = current.body.branch[value_slot];
            if (count + @intFromBool(value_index != none) >= 2) return;
            if (count == 0) {
                // Only the value is left: its leaf (empty path) replaces the branch.
                assert(value_index != none);
                assert(self.nodes[value_index].path_len == 0);
                self.cache[value_index] = .{};
                slot.* = value_index;
                self.release(index);
                return;
            }
            assert(count == 1 and value_index == none);
            var nibble: u8 = 0;
            while (current.body.branch[nibble] == none) nibble += 1;
            const child_index = current.body.branch[nibble];
            const child = &self.nodes[child_index];
            switch (child.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf, .extension => {
                    child.prepend_path(&.{nibble});
                    self.cache[child_index] = .{};
                    slot.* = child_index;
                    self.release(index);
                },
                .branch => {
                    // The body is shared: `child_index` is read before the path overwrites it.
                    current.kind = .extension;
                    current.set_path(&.{nibble});
                    current.body.extension.child = child_index;
                },
            }
        }

        /// Root hash of the trie. Rehashes only nodes changed since the previous call.
        pub fn root_hash(self: *Self) Hash {
            return self.root_hash_of(self.root);
        }

        pub fn root_hash_of(self: *Self, root: NodeIndex) Hash {
            if (root == none) return node.empty_root;
            self.update_caches(&.{root});
            return self.cache[root].root_hash();
        }

        /// Fills every dirty cache below `roots`, distinct roots of tries in this pool, so
        /// their dirty nodes share hash batches. Later `root_hash_of` calls are then free.
        pub fn update_caches(self: *Self, roots: []const NodeIndex) void {
            if (config.hash_batched) {
                self.update_caches_batched(roots);
            } else {
                for (roots) |root| {
                    if (root != none) self.update_cache(root);
                }
            }
            for (roots) |root| assert(root == none or self.cache[root].len > 0);
        }

        /// Frees every node of the trie rooted at `root` and empties it.
        pub fn free_tree(self: *Self, root: *NodeIndex) void {
            if (root.* == none) return;
            // Each branch pops one entry and pushes up to 17 (its value leaf included).
            var stack: [depth_max * 17]NodeIndex = undefined;
            stack[0] = root.*;
            var stack_len: u32 = 1;
            var freed: u64 = 0;
            while (stack_len > 0) : (freed += 1) {
                assert(freed < self.nodes.len);
                stack_len -= 1;
                const index = stack[stack_len];
                const current = &self.nodes[index];
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => {},
                    .extension => {
                        stack[stack_len] = current.body.extension.child;
                        stack_len += 1;
                    },
                    .branch => for (current.body.branch) |child| {
                        if (child == none) continue;
                        assert(stack_len < stack.len);
                        stack[stack_len] = child;
                        stack_len += 1;
                    },
                }
                self.release(index);
            }
            root.* = none;
        }

        const Frame = struct { index: NodeIndex, next_child: u8 };

        /// Post-order walk that fills in every dirty cache below `start`.
        fn update_cache(self: *Self, start: NodeIndex) void {
            var stack: [depth_max]Frame = undefined;
            stack[0] = .{ .index = start, .next_child = 0 };
            var stack_len: u32 = 1;
            var steps: u64 = 0;
            while (stack_len > 0) : (steps += 1) {
                assert(steps <= @as(u64, self.nodes.len) * 17 + 1);
                const frame = &stack[stack_len - 1];
                const current = &self.nodes[frame.index];
                if (self.cache[frame.index].len > 0) {
                    stack_len -= 1;
                    continue;
                }
                const pending = self.next_dirty_child(frame);
                if (pending != none) {
                    assert(stack_len < depth_max);
                    stack[stack_len] = .{ .index = pending, .next_child = 0 };
                    stack_len += 1;
                    continue;
                }
                self.cache[frame.index] = self.encode_ref(current);
                assert(self.cache[frame.index].len > 0);
                stack_len -= 1;
            }
        }

        /// Rehashes every dirty node below `roots`, deepest level first: a node depends only
        /// on its children, which sit one level deeper, so a level's nodes are independent.
        fn update_caches_batched(self: *Self, roots: []const NodeIndex) void {
            const count = self.collect_dirty(roots);
            const order = self.order[0..count];
            std.sort.pdq(u64, order, {}, std.sort.asc(u64));
            var end: usize = count;
            var levels: u32 = 0;
            while (end > 0) : (levels += 1) {
                assert(levels <= depth_max);
                const depth = order[end - 1] >> 32;
                var start = end - 1;
                while (start > 0 and order[start - 1] >> 32 == depth) start -= 1;
                self.hash_level(order[start..end]);
                end = start;
            }
        }

        /// Writes `depth << 32 | index` into `order` for every dirty node below `roots`.
        fn collect_dirty(self: *Self, roots: []const NodeIndex) u32 {
            var stack: [depth_max * 16]u64 = undefined;
            var count: u32 = 0;
            for (roots) |root| {
                if (root == none or self.cache[root].len > 0) continue;
                stack[0] = root;
                var stack_len: u32 = 1;
                while (stack_len > 0) {
                    stack_len -= 1;
                    const entry = stack[stack_len];
                    const index: NodeIndex = @truncate(entry);
                    const child_depth = (entry >> 32) + 1;
                    assert(child_depth <= depth_max);
                    assert(count < self.order.len);
                    self.order[count] = entry;
                    count += 1;
                    const current = &self.nodes[index];
                    assert(self.cache[index].len == 0);
                    const children: []const NodeIndex = switch (current.kind) {
                        .free => unreachable, // Reachable nodes are never on the free list.
                        .leaf => &.{},
                        .extension => (&current.body.extension.child)[0..1],
                        .branch => current.body.branch[0..16],
                    };
                    for (children) |child| {
                        if (child == none or self.cache[child].len > 0) continue;
                        assert(stack_len < stack.len);
                        stack[stack_len] = child_depth << 32 | child;
                        stack_len += 1;
                    }
                }
            }
            assert(count <= self.nodes.len);
            return count;
        }

        /// Hashes one level. Sorting by encoding length puts equal-length encodings next to
        /// each other, the input shape `keccak256_batch` requires.
        fn hash_level(self: *Self, level: []u64) void {
            assert(level.len > 0);
            for (level) |*entry| {
                const index: NodeIndex = @truncate(entry.*);
                const length = self.encoded_length(&self.nodes[index]);
                assert(length > 0 and length <= node_bytes_max);
                entry.* = length << 32 | index;
            }
            std.sort.pdq(u64, level, {}, std.sort.asc(u64));
            var start: usize = 0;
            while (start < level.len) {
                const length = level[start] >> 32;
                var end = start + 1;
                while (end < level.len and level[end] >> 32 == length) end += 1;
                self.hash_run(level[start..end], length);
                start = end;
            }
        }

        /// Hashes nodes whose encodings are all `length` bytes, `batch_width` at a time.
        fn hash_run(self: *Self, run: []const u64, length: u64) void {
            assert(run.len > 0);
            var start: usize = 0;
            if (length >= 32) {
                var buffers: [keccak.batch_width][node_bytes_max]u8 = undefined;
                var inputs: [keccak.batch_width][]const u8 = undefined;
                var digests: [keccak.batch_width]keccak.Digest = undefined;
                while (run.len - start >= keccak.batch_width) : (start += keccak.batch_width) {
                    for (&inputs, &buffers, run[start..][0..keccak.batch_width]) |*input, *b, e| {
                        const index: NodeIndex = @truncate(e);
                        input.* = self.encode_full(&self.nodes[index], b);
                        assert(input.len == length);
                    }
                    keccak.keccak256_batch(&inputs, &digests);
                    for (digests, run[start..][0..keccak.batch_width]) |digest, entry| {
                        const index: NodeIndex = @truncate(entry);
                        self.cache[index] = RlpNode.from_hash(digest);
                    }
                }
            }
            for (run[start..]) |entry| {
                const index: NodeIndex = @truncate(entry);
                self.cache[index] = self.encode_ref(&self.nodes[index]);
                assert(self.cache[index].len > 0);
                assert(self.cache[index].is_hash() == (length >= 32));
            }
        }

        /// Length of the full encoding of a node whose children are all clean.
        fn encoded_length(self: *const Self, current: *const Node) u64 {
            var hp: [path_bytes_max]u8 = undefined;
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => return node.leaf_length_compact(
                    current.hex_prefix(&hp),
                    current.value_slice(),
                ),
                .extension => {
                    const child = &self.cache[current.body.extension.child];
                    assert(child.len > 0);
                    return node.extension_length_compact(current.hex_prefix(&hp), child);
                },
                .branch => {
                    var payload: u64 = rlp.string_encoded_length(self.branch_value(current));
                    for (current.body.branch[0..16]) |child| {
                        if (child == none) {
                            payload += 1;
                        } else {
                            assert(self.cache[child].len > 0);
                            payload += self.cache[child].len;
                        }
                    }
                    return rlp.header_length(payload) + payload;
                },
            }
        }

        fn next_dirty_child(self: *Self, frame: *Frame) NodeIndex {
            const current = &self.nodes[frame.index];
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => return none,
                .extension => {
                    const child = current.body.extension.child;
                    if (self.cache[child].len > 0) return none;
                    return child;
                },
                .branch => {
                    while (frame.next_child < 16) {
                        const child = current.body.branch[frame.next_child];
                        frame.next_child += 1;
                        if (child != none and self.cache[child].len == 0) return child;
                    }
                    return none;
                },
            }
        }

        fn gather_children(self: *const Self, current: *const Node, out: *[16]RlpNode) u16 {
            var mask: u16 = 0;
            var count: u32 = 0;
            for (current.body.branch[0..16], 0..) |child, nibble| {
                if (child == none) continue;
                assert(self.cache[child].len > 0);
                mask |= @as(u16, 1) << @intCast(nibble);
                out[count] = self.cache[child];
                count += 1;
            }
            assert(@popCount(mask) == count);
            return mask;
        }

        fn encode_ref(self: *const Self, current: *const Node) RlpNode {
            var hp: [path_bytes_max]u8 = undefined;
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => {
                    return node.leaf_ref_compact(current.hex_prefix(&hp), current.value_slice());
                },
                .extension => {
                    const child = &self.cache[current.body.extension.child];
                    return node.extension_ref_compact(current.hex_prefix(&hp), child);
                },
                .branch => {
                    var children: [16]RlpNode = undefined;
                    const mask = self.gather_children(current, &children);
                    const count = @popCount(mask);
                    const value = self.branch_value(current);
                    return node.branch_ref(mask, children[0..count], value);
                },
            }
        }

        /// Writes the full encoding of a clean node into `out`.
        fn encode_full(self: *const Self, current: *const Node, out: []u8) []u8 {
            assert(out.len >= node_bytes_max);
            var sink: node.BufferSink = .{ .buffer = out };
            var hp: [path_bytes_max]u8 = undefined;
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => node.encode_leaf_compact(
                    &sink,
                    current.hex_prefix(&hp),
                    current.value_slice(),
                ),
                .extension => {
                    const child = &self.cache[current.body.extension.child];
                    node.encode_extension_compact(&sink, current.hex_prefix(&hp), child);
                },
                .branch => {
                    var children: [16]RlpNode = undefined;
                    const mask = self.gather_children(current, &children);
                    const count = @popCount(mask);
                    const value = self.branch_value(current);
                    node.encode_branch(&sink, mask, children[0..count], value);
                },
            }
            return sink.result();
        }

        /// Merkle proof for `key`, in the format of `eth_getProof`: the root node, then every
        /// node on the key's path whose reference is a hash. Embedded nodes travel inside
        /// their parent.
        pub const Proof = struct {
            buffer: [depth_max * node_bytes_max]u8 = undefined,
            ends: [depth_max]u32 = undefined,
            count: u32 = 0,

            pub fn node_at(self: *const Proof, index: u32) []const u8 {
                assert(index < self.count);
                const start = if (index == 0) 0 else self.ends[index - 1];
                return self.buffer[start..self.ends[index]];
            }

            fn append(self: *Proof, trie: *const Self, current: *const Node) void {
                assert(self.count < depth_max);
                const start = if (self.count == 0) 0 else self.ends[self.count - 1];
                const encoded = trie.encode_full(current, self.buffer[start..]);
                self.ends[self.count] = start + @as(u32, @intCast(encoded.len));
                self.count += 1;
            }
        };

        /// Fills `proof` for `key`, which may be absent (an exclusion proof).
        pub fn prove(self: *Self, key: []const u8, proof: *Proof) void {
            self.prove_in(self.root, key, proof);
        }

        pub fn prove_in(self: *Self, root: NodeIndex, key: []const u8, proof: *Proof) void {
            assert(key.len <= config.key_bytes_max);
            proof.count = 0;
            _ = self.root_hash_of(root);
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var index = root;
            var depth: u32 = 0;
            while (index != none) : (depth += 1) {
                assert(depth <= depth_max);
                const current = &self.nodes[index];
                if (depth == 0 or self.cache[index].is_hash()) proof.append(self, current);
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => return,
                    .extension => {
                        if (!current.path_prefixes(rest)) return;
                        rest = rest[current.path_len..];
                        index = current.body.extension.child;
                    },
                    .branch => {
                        if (rest.len == 0) return;
                        index = current.body.branch[rest[0]];
                        rest = rest[1..];
                    },
                }
            }
        }
    };
}

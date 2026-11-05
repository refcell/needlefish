//! Mutable in-memory Merkle Patricia Trie with cached node hashes.
//!
//! Nodes live in a fixed pool allocated once at `init`; inserts and deletes never allocate.
//! Every node caches its child reference (`RlpNode`). A write clears the cache only on the
//! nodes along the written path, so `root_hash` rehashes just the dirty paths: the cost of a
//! root after `k` updates is about `k * depth` node hashes instead of the whole trie.
//!
//! All walks are iterative with explicit, bounded stacks. Keys of any length up to the
//! configured maximum are allowed, and a key may prefix another (the branch then carries a
//! value), so the public `trietest` vectors run unmodified.

const std = @import("std");
const assert = std.debug.assert;

const node = @import("node.zig");
const nibbles_module = @import("nibbles.zig");
const Nibbles = nibbles_module.Nibbles;
const RlpNode = node.RlpNode;
const Hash = node.Hash;

pub const Config = struct {
    key_bytes_max: u32 = 32,
    value_size_max: u32 = 128,
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

        pub const Kind = enum(u8) { free, leaf, extension, branch };

        pub const Node = struct {
            kind: Kind,
            path_len: u8,
            value_len: u16,
            /// Child reference of this node; `len == 0` marks it dirty.
            cached: RlpNode,
            /// Extension child, or the next free node while on the free list.
            child: NodeIndex,
            path: [path_max]u8,
            children: [16]NodeIndex,
            value: [config.value_size_max]u8,

            fn path_slice(self: *const Node) []const u8 {
                return self.path[0..self.path_len];
            }

            fn value_slice(self: *const Node) []const u8 {
                return self.value[0..self.value_len];
            }

            fn set_path(self: *Node, path: []const u8) void {
                assert(path.len <= path_max);
                std.mem.copyForwards(u8, self.path[0..path.len], path);
                self.path_len = @intCast(path.len);
            }

            fn prepend_path(self: *Node, prefix: []const u8) void {
                const len = self.path_len + prefix.len;
                assert(len <= path_max);
                std.mem.copyBackwards(u8, self.path[prefix.len..len], self.path_slice());
                @memcpy(self.path[0..prefix.len], prefix);
                self.path_len = @intCast(len);
            }

            fn append_path(self: *Node, suffix: []const u8) void {
                const len = self.path_len + suffix.len;
                assert(len <= path_max);
                @memcpy(self.path[self.path_len..len], suffix);
                self.path_len = @intCast(len);
            }

            fn set_value(self: *Node, value: []const u8) void {
                assert(value.len <= config.value_size_max);
                @memcpy(self.value[0..value.len], value);
                self.value_len = @intCast(value.len);
            }

            fn child_count(self: *const Node) u32 {
                assert(self.kind == .branch);
                var count: u32 = 0;
                for (self.children) |child| count += @intFromBool(child != none);
                return count;
            }
        };

        nodes: []Node,
        free_head: NodeIndex,
        free_count: u32,
        root: NodeIndex = none,

        pub fn init(allocator: std.mem.Allocator, node_count_max: u32) !Self {
            assert(node_count_max >= nodes_per_insert_max);
            assert(node_count_max < none);
            const nodes = try allocator.alloc(Node, node_count_max);
            var self: Self = .{ .nodes = nodes, .free_head = none, .free_count = 0 };
            self.clear();
            return self;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
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
                self.nodes[index].child = self.free_head;
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
            self.free_head = result.child;
            self.free_count -= 1;
            result.* = .{
                .kind = kind,
                .path_len = 0,
                .value_len = 0,
                .cached = .{},
                .child = none,
                .path = undefined,
                .children = @splat(none),
                .value = undefined,
            };
            return index;
        }

        fn release(self: *Self, index: NodeIndex) void {
            assert(self.nodes[index].kind != .free);
            self.nodes[index].kind = .free;
            self.nodes[index].child = self.free_head;
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
            self.nodes[index].child = child;
            return index;
        }

        pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
            assert(key.len <= config.key_bytes_max);
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var index = self.root;
            var depth: u32 = 0;
            while (index != none) : (depth += 1) {
                assert(depth <= depth_max);
                const current = &self.nodes[index];
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => {
                        if (!std.mem.eql(u8, current.path_slice(), rest)) return null;
                        return current.value_slice();
                    },
                    .extension => {
                        if (!std.mem.startsWith(u8, rest, current.path_slice())) return null;
                        rest = rest[current.path_len..];
                        index = current.child;
                    },
                    .branch => {
                        if (rest.len == 0) {
                            if (current.value_len == 0) return null;
                            return current.value_slice();
                        }
                        index = current.children[rest[0]];
                        rest = rest[1..];
                    },
                }
            }
            return null;
        }

        /// Inserts or replaces `key`. Fails without changing the trie if the pool is too full.
        pub fn put(self: *Self, key: []const u8, value: []const u8) Error!void {
            assert(key.len <= config.key_bytes_max);
            assert(value.len > 0 and value.len <= config.value_size_max);
            if (self.free_count < nodes_per_insert_max) return error.TrieFull;
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var slot: *NodeIndex = &self.root;
            var depth: u32 = 0;
            while (true) : (depth += 1) {
                assert(depth <= depth_max);
                if (slot.* == none) {
                    slot.* = self.new_leaf(rest, value);
                    return;
                }
                const current = &self.nodes[slot.*];
                current.cached = .{};
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => return self.split_leaf(slot, rest, value),
                    .extension => {
                        const common = nibbles_module.common_prefix_length(
                            current.path_slice(),
                            rest,
                        );
                        if (common < current.path_len) {
                            return self.split_extension(slot, common, rest, value);
                        }
                        rest = rest[common..];
                        slot = &current.child;
                    },
                    .branch => {
                        if (rest.len == 0) return current.set_value(value);
                        slot = &current.children[rest[0]];
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
                self.nodes[branch].set_value(value);
            } else {
                const leaf = self.new_leaf(rest[common + 1 ..], value);
                assert(self.nodes[branch].children[rest[common]] == none);
                self.nodes[branch].children[rest[common]] = leaf;
            }
        }

        fn split_leaf(self: *Self, slot: *NodeIndex, rest: []const u8, value: []const u8) void {
            const leaf_index = slot.*;
            const leaf = &self.nodes[leaf_index];
            assert(leaf.kind == .leaf);
            const common = nibbles_module.common_prefix_length(leaf.path_slice(), rest);
            if (common == leaf.path_len and common == rest.len) return leaf.set_value(value);

            const branch = self.allocate(.branch);
            if (leaf.path_len == common) {
                self.nodes[branch].set_value(leaf.value_slice());
                self.release(leaf_index);
            } else {
                const nibble = leaf.path[common];
                leaf.set_path(leaf.path_slice()[common + 1 ..]);
                self.nodes[branch].children[nibble] = leaf_index;
            }
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
            const path = Nibbles.from_nibbles(extension.path_slice());
            const branch = self.allocate(.branch);
            const nibble = path.data[common];
            var reused = false;
            if (path.len - common - 1 == 0) {
                self.nodes[branch].children[nibble] = extension.child;
            } else {
                extension.set_path(path.slice()[common + 1 ..]);
                self.nodes[branch].children[nibble] = extension_index;
                reused = true;
            }
            self.place_value(branch, common, rest, value);
            if (common == 0) {
                if (!reused) self.release(extension_index);
                slot.* = branch;
            } else if (reused) {
                slot.* = self.new_extension(path.slice()[0..common], branch);
            } else {
                extension.set_path(path.slice()[0..common]);
                extension.child = branch;
            }
        }

        /// Removes `key`. Returns whether it was present.
        pub fn delete(self: *Self, key: []const u8) bool {
            assert(key.len <= config.key_bytes_max);
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var stack: [depth_max]*NodeIndex = undefined;
            var stack_len: u32 = 0;
            var slot: *NodeIndex = &self.root;
            while (true) {
                assert(stack_len < depth_max);
                if (slot.* == none) return false;
                const current = &self.nodes[slot.*];
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => {
                        if (!std.mem.eql(u8, current.path_slice(), rest)) return false;
                        self.release(slot.*);
                        slot.* = none;
                        break;
                    },
                    .extension => {
                        if (!std.mem.startsWith(u8, rest, current.path_slice())) return false;
                        stack[stack_len] = slot;
                        stack_len += 1;
                        rest = rest[current.path_len..];
                        slot = &current.child;
                    },
                    .branch => {
                        stack[stack_len] = slot;
                        stack_len += 1;
                        if (rest.len == 0) {
                            if (current.value_len == 0) return false;
                            current.value_len = 0;
                            break;
                        }
                        slot = &current.children[rest[0]];
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
            current.cached = .{};
            switch (current.kind) {
                .free, .leaf => unreachable, // Only branches and extensions are on the path.
                .extension => {
                    const child = &self.nodes[current.child];
                    switch (child.kind) {
                        .free => unreachable, // Reachable nodes are never on the free list.
                        .branch => {},
                        .leaf => {
                            child.prepend_path(current.path_slice());
                            child.cached = .{};
                            slot.* = current.child;
                            self.release(index);
                        },
                        .extension => {
                            const grandchild = child.child;
                            current.append_path(child.path_slice());
                            self.release(current.child);
                            current.child = grandchild;
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
            if (count + @intFromBool(current.value_len > 0) >= 2) return;
            if (count == 0) {
                assert(current.value_len > 0);
                current.kind = .leaf;
                current.path_len = 0;
                return;
            }
            assert(count == 1 and current.value_len == 0);
            var nibble: u8 = 0;
            while (current.children[nibble] == none) nibble += 1;
            const child_index = current.children[nibble];
            const child = &self.nodes[child_index];
            switch (child.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf, .extension => {
                    child.prepend_path(&.{nibble});
                    child.cached = .{};
                    slot.* = child_index;
                    self.release(index);
                },
                .branch => {
                    current.kind = .extension;
                    current.set_path(&.{nibble});
                    current.child = child_index;
                },
            }
        }

        /// Root hash of the trie. Rehashes only nodes changed since the previous call.
        pub fn root_hash(self: *Self) Hash {
            if (self.root == none) return node.empty_root;
            self.update_cache(self.root);
            return self.nodes[self.root].cached.root_hash();
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
                if (current.cached.len > 0) {
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
                current.cached = self.encode_ref(current);
                assert(current.cached.len > 0);
                stack_len -= 1;
            }
        }

        fn next_dirty_child(self: *Self, frame: *Frame) NodeIndex {
            const current = &self.nodes[frame.index];
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => return none,
                .extension => {
                    if (self.nodes[current.child].cached.len > 0) return none;
                    return current.child;
                },
                .branch => {
                    while (frame.next_child < 16) {
                        const child = current.children[frame.next_child];
                        frame.next_child += 1;
                        if (child != none and self.nodes[child].cached.len == 0) return child;
                    }
                    return none;
                },
            }
        }

        fn gather_children(self: *const Self, current: *const Node, out: *[16]RlpNode) u16 {
            var mask: u16 = 0;
            var count: u32 = 0;
            for (current.children, 0..) |child, nibble| {
                if (child == none) continue;
                assert(self.nodes[child].cached.len > 0);
                mask |= @as(u16, 1) << @intCast(nibble);
                out[count] = self.nodes[child].cached;
                count += 1;
            }
            assert(@popCount(mask) == count);
            return mask;
        }

        fn encode_ref(self: *const Self, current: *const Node) RlpNode {
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => return node.leaf_ref(current.path_slice(), current.value_slice()),
                .extension => {
                    const child = &self.nodes[current.child].cached;
                    return node.extension_ref(current.path_slice(), child);
                },
                .branch => {
                    var children: [16]RlpNode = undefined;
                    const mask = self.gather_children(current, &children);
                    const count = @popCount(mask);
                    return node.branch_ref(mask, children[0..count], current.value_slice());
                },
            }
        }

        /// Writes the full encoding of a clean node into `out`.
        fn encode_full(self: *const Self, current: *const Node, out: []u8) []u8 {
            assert(out.len >= node_bytes_max);
            var sink: node.BufferSink = .{ .buffer = out };
            switch (current.kind) {
                .free => unreachable, // Reachable nodes are never on the free list.
                .leaf => node.encode_leaf(&sink, current.path_slice(), current.value_slice()),
                .extension => {
                    const child = &self.nodes[current.child].cached;
                    node.encode_extension(&sink, current.path_slice(), child);
                },
                .branch => {
                    var children: [16]RlpNode = undefined;
                    const mask = self.gather_children(current, &children);
                    const count = @popCount(mask);
                    node.encode_branch(&sink, mask, children[0..count], current.value_slice());
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
            assert(key.len <= config.key_bytes_max);
            proof.count = 0;
            _ = self.root_hash();
            const path = Nibbles.from_bytes(key);
            var rest: []const u8 = path.slice();
            var index = self.root;
            var depth: u32 = 0;
            while (index != none) : (depth += 1) {
                assert(depth <= depth_max);
                const current = &self.nodes[index];
                if (depth == 0 or current.cached.is_hash()) proof.append(self, current);
                switch (current.kind) {
                    .free => unreachable, // Reachable nodes are never on the free list.
                    .leaf => return,
                    .extension => {
                        if (!std.mem.startsWith(u8, rest, current.path_slice())) return;
                        rest = rest[current.path_len..];
                        index = current.child;
                    },
                    .branch => {
                        if (rest.len == 0) return;
                        index = current.children[rest[0]];
                        rest = rest[1..];
                    },
                }
            }
        }
    };
}

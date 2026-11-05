//! Sparse Merkle Patricia Trie: a trie that knows only some of its nodes.
//!
//! Stateless execution gets a witness: the RLP preimages of the trie nodes a block touches.
//! A sparse trie starts as one unresolved reference (the root hash) and decodes nodes on
//! demand through a `Resolver` (hash -> preimage). Subtries the block never enters stay as
//! their references, so the root after an update is exact without the rest of the state. A
//! missing preimage on a needed path is `error.WitnessIncomplete`; this includes the sibling
//! a delete must merge into its parent when a branch collapses.
//!
//! Keys are fixed-length (32 bytes, hashed state keys), so branches never carry values and
//! every leaf ends exactly at the key's last nibble. Nodes that break these rules are
//! `error.InvalidWitness`. Many tries share one fixed node pool (`*_in` style roots), sized
//! at init. Children of a node decoded from the witness are materialized lazily from its
//! preimage, so an untouched branch costs one pool node, not seventeen. No recursion.

const std = @import("std");
const assert = std.debug.assert;

const rlp = @import("rlp.zig");
const node = @import("node.zig");
const nibbles_module = @import("nibbles.zig");
const Hash = node.Hash;
const RlpNode = node.RlpNode;
const Nibbles = nibbles_module.Nibbles;

/// Nibbles in a key: keys are 32-byte hashes.
pub const key_nibbles = 64;
/// Largest leaf value: an account `rlp([nonce, balance, storage_root, code_hash])`.
pub const value_bytes_max = 112;
/// Nodes on one path: at most one branch and one extension per nibble, then a leaf.
pub const depth_max = key_nibbles * 2 + 2;

pub const Error = error{ WitnessIncomplete, InvalidWitness, SparseFull };
pub const DecodeError = error{InvalidNode};

pub const NodeIndex = u32;
pub const none: NodeIndex = std.math.maxInt(NodeIndex);
/// A child present in the parent's preimage but not yet given a pool node.
const unloaded: NodeIndex = none - 1;

pub const DecodedKind = enum { leaf, extension, branch };

/// One node as decoded from its RLP; slices point into the input.
pub const Decoded = struct {
    kind: DecodedKind,
    path: Nibbles = .{},
    /// Leaf value.
    value: []const u8 = &.{},
    /// Child references by nibble; `len == 0` means empty. An extension uses slot 0.
    children: [16]RlpNode = @splat(.{}),
};

fn decode_child(item: rlp.Item) DecodeError!RlpNode {
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

/// Decodes one state-trie node strictly: canonical RLP, no branch values, a branch has at
/// least two children, paths fit a 32-byte key, leaf values are non-empty and bounded.
pub fn decode_node(bytes: []const u8) DecodeError!Decoded {
    const outer = rlp.decode_item(bytes) catch return error.InvalidNode;
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string or items[16].payload.len != 0) return error.InvalidNode;
        var result: Decoded = .{ .kind = .branch };
        var children: u32 = 0;
        for (items[0..16], &result.children) |item, *child| {
            child.* = try decode_child(item);
            children += @intFromBool(child.len > 0);
        }
        if (children < 2) return error.InvalidNode;
        return result;
    }
    if (count != 2 or items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch {
        return error.InvalidNode;
    };
    if (decoded.path.len > key_nibbles) return error.InvalidNode;
    if (decoded.leaf) {
        const value = items[1];
        if (value.kind != .string) return error.InvalidNode;
        if (value.payload.len == 0 or value.payload.len > value_bytes_max) {
            return error.InvalidNode;
        }
        return .{ .kind = .leaf, .path = decoded.path, .value = value.payload };
    }
    if (decoded.path.len == 0) return error.InvalidNode;
    var result: Decoded = .{ .kind = .extension, .path = decoded.path };
    result.children[0] = try decode_child(items[1]);
    if (result.children[0].len == 0) return error.InvalidNode;
    return result;
}

/// Maps a node hash to its preimage (whose keccak256 must be that hash), or null.
pub const Resolver = struct {
    context: *anyopaque,
    resolve: *const fn (context: *anyopaque, hash: *const Hash) ?[]const u8,
};

const Kind = enum(u8) { free, unresolved, leaf, extension, branch };

const Body = union { value: [value_bytes_max]u8, children: [16]NodeIndex };

const Node = struct {
    kind: Kind,
    path_len: u8 = 0,
    value_len: u8 = 0,
    /// The node's reference while clean; `len == 0` once it or a descendant changed.
    ref: RlpNode = .{},
    /// The witness preimage of a decoded extension or branch, for its `unloaded` children.
    source: []const u8 = &.{},
    path: [key_nibbles]u8 = undefined,
    body: Body = .{ .children = undefined },
};

pub const SparseTrie = struct {
    nodes: []Node,
    free_head: NodeIndex = none,
    free_count: u32 = 0,
    resolver: Resolver,

    pub fn init(
        allocator: std.mem.Allocator,
        nodes_max: u32,
        resolver: Resolver,
    ) !SparseTrie {
        assert(nodes_max > 0 and nodes_max < unloaded);
        const nodes = try allocator.alloc(Node, nodes_max);
        var result: SparseTrie = .{ .nodes = nodes, .resolver = resolver };
        result.clear();
        return result;
    }

    pub fn deinit(self: *SparseTrie, allocator: std.mem.Allocator) void {
        allocator.free(self.nodes);
        self.* = undefined;
    }

    /// Frees every node of every trie.
    pub fn clear(self: *SparseTrie) void {
        self.free_head = none;
        var index: usize = self.nodes.len;
        while (index > 0) {
            index -= 1;
            self.nodes[index] = .{ .kind = .free };
            self.nodes[index].body = .{ .children = @splat(self.free_head) };
            self.free_head = @intCast(index);
        }
        self.free_count = @intCast(self.nodes.len);
        assert(self.free_head == 0);
    }

    fn alloc(self: *SparseTrie, kind: Kind) Error!NodeIndex {
        if (self.free_count == 0) return error.SparseFull;
        const index = self.free_head;
        assert(index < self.nodes.len);
        assert(self.nodes[index].kind == .free);
        self.free_head = self.nodes[index].body.children[0];
        self.free_count -= 1;
        self.nodes[index] = .{ .kind = kind };
        return index;
    }

    fn free(self: *SparseTrie, index: NodeIndex) void {
        assert(self.nodes[index].kind != .free);
        self.nodes[index] = .{ .kind = .free };
        self.nodes[index].body = .{ .children = @splat(self.free_head) };
        self.free_head = index;
        self.free_count += 1;
        assert(self.free_count <= self.nodes.len);
    }

    fn alloc_unresolved(self: *SparseTrie, ref: RlpNode) Error!NodeIndex {
        assert(ref.len > 0);
        const index = try self.alloc(.unresolved);
        self.nodes[index].ref = ref;
        return index;
    }

    /// A trie root from its hash: `none` for the empty trie, else an unresolved node.
    pub fn root_from_hash(self: *SparseTrie, root: Hash) Error!NodeIndex {
        if (std.mem.eql(u8, &root, &node.empty_root)) return none;
        const index = try self.alloc_unresolved(RlpNode.from_hash(root));
        assert(self.nodes[index].ref.is_hash());
        return index;
    }

    /// Decodes an unresolved node in place. Embedded nodes (inside their parent's ref) get
    /// their children materialized at once, since their bytes live in the node itself.
    fn resolve(self: *SparseTrie, index: NodeIndex) Error!void {
        const current = &self.nodes[index];
        if (current.kind != .unresolved) return;
        assert(current.ref.len > 0);
        var embedded: [32]u8 = undefined;
        const from_witness = current.ref.is_hash();
        const bytes: []const u8 = if (from_witness)
            self.resolver.resolve(self.resolver.context, current.ref.bytes[1..33]) orelse
                return error.WitnessIncomplete
        else blk: {
            @memcpy(embedded[0..current.ref.len], current.ref.slice());
            break :blk embedded[0..current.ref.len];
        };
        const decoded = decode_node(bytes) catch return error.InvalidWitness;
        var children: u32 = 0;
        for (decoded.children) |ref| children += @intFromBool(ref.len > 0);
        if (!from_witness and self.free_count < children) return error.SparseFull;
        current.path_len = decoded.path.len;
        @memcpy(current.path[0..decoded.path.len], decoded.path.slice());
        if (decoded.kind == .leaf) {
            current.kind = .leaf;
            current.body = .{ .value = undefined };
            current.value_len = @intCast(decoded.value.len);
            @memcpy(current.body.value[0..decoded.value.len], decoded.value);
            return;
        }
        current.kind = if (decoded.kind == .branch) .branch else .extension;
        current.body = .{ .children = @splat(none) };
        for (decoded.children, 0..) |ref, nibble| {
            if (ref.len == 0) continue;
            current.body.children[nibble] = unloaded;
            if (!from_witness) {
                // Capacity checked above, before the node changed.
                current.body.children[nibble] = self.alloc_unresolved(ref) catch unreachable;
            }
        }
        current.source = if (from_witness) bytes else &.{};
        assert(current.kind != .unresolved);
    }

    /// The pool node of child `nibble` (slot 0 for an extension), materialized if needed.
    fn child_at(self: *SparseTrie, parent: NodeIndex, nibble: u8) Error!NodeIndex {
        const current = &self.nodes[parent];
        assert(current.kind == .branch or current.kind == .extension);
        const index = current.body.children[nibble];
        if (index != unloaded) return index;
        // The source decoded when the node was resolved, and decoding is deterministic.
        const decoded = decode_node(current.source) catch unreachable;
        assert(decoded.children[nibble].len > 0);
        const created = try self.alloc_unresolved(decoded.children[nibble]);
        current.body.children[nibble] = created;
        return created;
    }

    /// Checks the fixed-key-length shape of a resolved node `rest_len` nibbles above the end.
    fn check_shape(self: *const SparseTrie, index: NodeIndex, rest_len: usize) Error!void {
        const current = &self.nodes[index];
        switch (current.kind) {
            .leaf => if (current.path_len != rest_len) return error.InvalidWitness,
            .extension => if (current.path_len >= rest_len) return error.InvalidWitness,
            .branch => if (rest_len == 0) return error.InvalidWitness,
            .free, .unresolved => unreachable, // Callers resolve first.
        }
    }

    /// The value under `key`, or null. The slice is valid until the next update.
    pub fn get(self: *SparseTrie, root: NodeIndex, key: *const [32]u8) Error!?[]const u8 {
        const path = Nibbles.from_bytes(key);
        var rest: []const u8 = path.slice();
        var index = root;
        var depth: u32 = 0;
        while (index != none) : (depth += 1) {
            assert(depth <= depth_max);
            try self.resolve(index);
            try self.check_shape(index, rest.len);
            const current = &self.nodes[index];
            switch (current.kind) {
                .leaf => {
                    if (!std.mem.eql(u8, current.path[0..current.path_len], rest)) return null;
                    return current.body.value[0..current.value_len];
                },
                .extension => {
                    const node_path = current.path[0..current.path_len];
                    if (!std.mem.startsWith(u8, rest, node_path)) return null;
                    rest = rest[node_path.len..];
                    index = try self.child_at(index, 0);
                },
                .branch => {
                    const nibble = rest[0];
                    rest = rest[1..];
                    if (current.body.children[nibble] == none) return null;
                    index = try self.child_at(index, nibble);
                },
                .free, .unresolved => unreachable,
            }
        }
        return null;
    }

    fn new_leaf(self: *SparseTrie, path: []const u8, value: []const u8) Error!NodeIndex {
        assert(value.len > 0 and value.len <= value_bytes_max);
        const index = try self.alloc(.leaf);
        const leaf = &self.nodes[index];
        leaf.path_len = @intCast(path.len);
        @memcpy(leaf.path[0..path.len], path);
        leaf.body = .{ .value = undefined };
        leaf.value_len = @intCast(value.len);
        @memcpy(leaf.body.value[0..value.len], value);
        return index;
    }

    fn new_branch(self: *SparseTrie) Error!NodeIndex {
        const index = try self.alloc(.branch);
        self.nodes[index].body = .{ .children = @splat(none) };
        return index;
    }

    fn new_extension(self: *SparseTrie, path: []const u8, target: NodeIndex) Error!NodeIndex {
        assert(path.len > 0 and target != none and target != unloaded);
        const index = try self.alloc(.extension);
        const extension = &self.nodes[index];
        extension.path_len = @intCast(path.len);
        @memcpy(extension.path[0..path.len], path);
        extension.body = .{ .children = @splat(none) };
        extension.body.children[0] = target;
        return index;
    }

    /// Drops the first `count` nibbles of a leaf or extension path; the node becomes dirty.
    fn drop_path_prefix(self: *SparseTrie, index: NodeIndex, count: u32) void {
        const current = &self.nodes[index];
        assert(current.kind == .leaf or current.kind == .extension);
        assert(count <= current.path_len);
        const len = current.path_len - count;
        std.mem.copyForwards(u8, current.path[0..len], current.path[count..current.path_len]);
        current.path_len = @intCast(len);
        current.ref = .{};
    }

    /// Prepends `prefix` to a leaf or extension path; the node becomes dirty.
    fn add_path_prefix(self: *SparseTrie, index: NodeIndex, prefix: []const u8) void {
        const current = &self.nodes[index];
        assert(current.kind == .leaf or current.kind == .extension);
        const len = current.path_len + prefix.len;
        assert(len <= key_nibbles);
        std.mem.copyBackwards(u8, current.path[prefix.len..len], current.path[0..current.path_len]);
        @memcpy(current.path[0..prefix.len], prefix);
        current.path_len = @intCast(len);
        current.ref = .{};
    }

    /// Puts a branch where leaf or extension `index` diverges from `rest` after `common`
    /// shared nibbles; returns the new subtree top (a branch, or an extension over it).
    fn split(
        self: *SparseTrie,
        index: NodeIndex,
        rest: []const u8,
        common: u32,
        value: []const u8,
    ) Error!NodeIndex {
        if (self.free_count < 4) return error.SparseFull;
        const current = &self.nodes[index];
        assert(common < current.path_len and common < rest.len);
        const old_nibble = current.path[common];
        assert(old_nibble != rest[common]);
        const branch = try self.new_branch();
        if (current.kind == .extension and common + 1 == current.path_len) {
            // The extension would become empty: its child hangs off the branch directly.
            self.nodes[branch].body.children[old_nibble] = try self.child_at(index, 0);
            self.free(index);
        } else {
            // An extension keeps its child: its source still describes slot 0.
            self.drop_path_prefix(index, common + 1);
            self.nodes[branch].body.children[old_nibble] = index;
        }
        const leaf = try self.new_leaf(rest[common + 1 ..], value);
        self.nodes[branch].body.children[rest[common]] = leaf;
        if (common == 0) return branch;
        return self.new_extension(rest[0..common], branch);
    }

    /// Inserts or replaces `key`'s value.
    pub fn put(
        self: *SparseTrie,
        root: *NodeIndex,
        key: *const [32]u8,
        value: []const u8,
    ) Error!void {
        assert(value.len > 0 and value.len <= value_bytes_max);
        const path = Nibbles.from_bytes(key);
        var rest: []const u8 = path.slice();
        var slots: [depth_max]*NodeIndex = undefined;
        var slots_len: u32 = 0;
        var slot = root;
        while (true) {
            assert(slots_len < depth_max);
            slots[slots_len] = slot;
            slots_len += 1;
            const index = slot.*;
            if (index == none) {
                slot.* = try self.new_leaf(rest, value);
                break;
            }
            try self.resolve(index);
            try self.check_shape(index, rest.len);
            const current = &self.nodes[index];
            if (current.kind == .branch) {
                const nibble = rest[0];
                rest = rest[1..];
                if (current.body.children[nibble] != none) _ = try self.child_at(index, nibble);
                slot = &current.body.children[nibble];
                continue;
            }
            const node_path = current.path[0..current.path_len];
            const common = nibbles_module.common_prefix_length(node_path, rest);
            if (current.kind == .leaf and common == rest.len) {
                current.value_len = @intCast(value.len);
                @memcpy(current.body.value[0..value.len], value);
                break;
            }
            if (common < node_path.len) {
                slot.* = try self.split(index, rest, common, value);
                break;
            }
            assert(current.kind == .extension);
            rest = rest[node_path.len..];
            _ = try self.child_at(index, 0);
            slot = &current.body.children[0];
        }
        self.mark_dirty(slots[0..slots_len]);
    }

    fn mark_dirty(self: *SparseTrie, slots: []const *NodeIndex) void {
        for (slots) |slot| {
            if (slot.* == none) continue;
            assert(self.nodes[slot.*].kind != .free and self.nodes[slot.*].kind != .unresolved);
            self.nodes[slot.*].ref = .{};
        }
    }

    fn children_count(self: *const SparseTrie, index: NodeIndex) u32 {
        const current = &self.nodes[index];
        assert(current.kind == .branch);
        var count: u32 = 0;
        for (current.body.children) |child_index| count += @intFromBool(child_index != none);
        return count;
    }

    /// The only other child of the leaf's parent branch, when removing the leaf collapses
    /// it: materialized, resolved, and shape-checked before anything changes.
    fn collapse_sibling(
        self: *SparseTrie,
        parent: NodeIndex,
        leaf_nibble: u8,
        rest_len: usize,
    ) Error!?struct { nibble: u8, index: NodeIndex } {
        if (self.children_count(parent) > 2) return null;
        assert(self.children_count(parent) == 2);
        for (self.nodes[parent].body.children, 0..) |child_index, nibble| {
            if (child_index == none or nibble == leaf_nibble) continue;
            const sibling = try self.child_at(parent, @intCast(nibble));
            try self.resolve(sibling);
            try self.check_shape(sibling, rest_len);
            return .{ .nibble = @intCast(nibble), .index = sibling };
        }
        unreachable; // Two children, one of them the leaf.
    }

    /// Descends to `key`'s leaf, filling `slots` with the slot of every node on the path.
    /// Returns the path length, or 0 when the key is absent.
    fn find_leaf(
        self: *SparseTrie,
        root: *NodeIndex,
        key: *const [32]u8,
        slots: *[depth_max]*NodeIndex,
        rest_lens: *[depth_max]u8,
    ) Error!u32 {
        const path = Nibbles.from_bytes(key);
        var rest: []const u8 = path.slice();
        var slot = root;
        var len: u32 = 0;
        while (slot.* != none) {
            assert(len < depth_max);
            const index = slot.*;
            try self.resolve(index);
            try self.check_shape(index, rest.len);
            slots[len] = slot;
            rest_lens[len] = @intCast(rest.len);
            len += 1;
            const current = &self.nodes[index];
            const node_path = current.path[0..current.path_len];
            switch (current.kind) {
                .leaf => return if (std.mem.eql(u8, node_path, rest)) len else 0,
                .extension => {
                    if (!std.mem.startsWith(u8, rest, node_path)) return 0;
                    rest = rest[node_path.len..];
                    _ = try self.child_at(index, 0);
                    slot = &current.body.children[0];
                },
                .branch => {
                    const nibble = rest[0];
                    rest = rest[1..];
                    if (current.body.children[nibble] == none) return 0;
                    _ = try self.child_at(index, nibble);
                    slot = &current.body.children[nibble];
                },
                .free, .unresolved => unreachable,
            }
        }
        return 0;
    }

    /// Removes `key` if present. A branch left with one child collapses into it (merging
    /// paths with a parent extension); that child must resolve, else `WitnessIncomplete`
    /// and the trie is unchanged.
    pub fn delete(self: *SparseTrie, root: *NodeIndex, key: *const [32]u8) Error!void {
        var slots: [depth_max]*NodeIndex = undefined;
        // Nibbles left below each node on the path, for shape checks.
        var rest_lens: [depth_max]u8 = undefined;
        var len = try self.find_leaf(root, key, &slots, &rest_lens);
        if (len == 0) return;
        const leaf_slot = slots[len - 1];
        if (len == 1) {
            self.free(leaf_slot.*);
            leaf_slot.* = none;
            return;
        }
        const parent_slot = slots[len - 2];
        const parent = parent_slot.*;
        if (self.nodes[parent].kind != .branch) return error.InvalidWitness;
        const path = Nibbles.from_bytes(key);
        const leaf_nibble = path.data[key_nibbles - rest_lens[len - 2]];
        assert(self.nodes[parent].body.children[leaf_nibble] == leaf_slot.*);
        const sibling = try self.collapse_sibling(parent, leaf_nibble, rest_lens[len - 2] - 1);
        self.free(leaf_slot.*);
        leaf_slot.* = none;
        len -= 1;
        if (sibling) |kept| {
            const replacement = self.collapse(parent, kept.nibble, kept.index);
            parent_slot.* = replacement;
            // `merge_extension` frees the grandparent, which holds `parent_slot`.
            if (len >= 2) {
                const grand_slot = slots[len - 2];
                if (self.merge_extension(grand_slot.*, replacement)) {
                    grand_slot.* = replacement;
                    len -= 1;
                }
            }
        }
        self.mark_dirty(slots[0..len]);
    }

    /// Replaces a one-child branch: a leaf or extension child takes the nibble as a path
    /// prefix; a branch child gets a one-nibble extension (the old branch node, reused).
    fn collapse(self: *SparseTrie, branch: NodeIndex, nibble: u8, kept: NodeIndex) NodeIndex {
        assert(self.children_count(branch) == 1);
        switch (self.nodes[kept].kind) {
            .leaf, .extension => {
                // An extension keeps its child: its source still describes slot 0.
                self.add_path_prefix(kept, &.{nibble});
                self.free(branch);
                return kept;
            },
            .branch => {
                const current = &self.nodes[branch];
                current.kind = .extension;
                current.path_len = 1;
                current.path[0] = nibble;
                current.body = .{ .children = @splat(none) };
                current.body.children[0] = kept;
                current.source = &.{};
                current.ref = .{};
                return branch;
            },
            .free, .unresolved => unreachable, // `collapse_sibling` resolved it.
        }
    }

    /// Folds extension `upper` into its only child `lower` when that is a leaf or an
    /// extension. Returns whether it did (and freed `upper`).
    fn merge_extension(self: *SparseTrie, upper: NodeIndex, lower: NodeIndex) bool {
        if (self.nodes[upper].kind != .extension) return false;
        assert(self.nodes[upper].body.children[0] == lower);
        if (self.nodes[lower].kind != .leaf and self.nodes[lower].kind != .extension) {
            return false;
        }
        const upper_node = &self.nodes[upper];
        self.add_path_prefix(lower, upper_node.path[0..upper_node.path_len]);
        self.free(upper);
        return true;
    }

    fn child_ref(self: *const SparseTrie, index: NodeIndex) RlpNode {
        const ref = self.nodes[index].ref;
        assert(ref.len > 0);
        return ref;
    }

    fn compute_ref(self: *SparseTrie, index: NodeIndex) void {
        const current = &self.nodes[index];
        assert(current.ref.len == 0);
        const node_path = current.path[0..current.path_len];
        switch (current.kind) {
            .leaf => {
                const value = current.body.value[0..current.value_len];
                current.ref = node.leaf_ref(node_path, value);
            },
            .extension => {
                const target = current.body.children[0];
                assert(target != none and target != unloaded);
                current.ref = node.extension_ref(node_path, &self.child_ref(target));
            },
            .branch => {
                var decoded: ?Decoded = null;
                var refs: [16]RlpNode = undefined;
                var mask: u16 = 0;
                var count: u32 = 0;
                for (current.body.children, 0..) |child_index, nibble| {
                    if (child_index == none) continue;
                    mask |= @as(u16, 1) << @intCast(nibble);
                    if (child_index == unloaded) {
                        // Validated when the node was resolved; decoding is deterministic.
                        if (decoded == null) {
                            decoded = decode_node(current.source) catch unreachable;
                        }
                        refs[count] = decoded.?.children[nibble];
                    } else {
                        refs[count] = self.child_ref(child_index);
                    }
                    count += 1;
                }
                assert(count >= 1);
                current.ref = node.branch_ref(mask, refs[0..count], &.{});
            },
            .free, .unresolved => unreachable, // Unresolved nodes are never dirty.
        }
        assert(current.ref.len > 0);
    }

    /// Recomputes the references of every dirty node below `root`, children first.
    fn update_refs(self: *SparseTrie, root: NodeIndex) void {
        const Frame = struct { index: NodeIndex, expanded: bool };
        var stack: [depth_max * 16]Frame = undefined;
        var stack_len: u32 = 0;
        if (self.nodes[root].ref.len > 0) return;
        stack[0] = .{ .index = root, .expanded = false };
        stack_len = 1;
        var steps: u64 = 0;
        while (stack_len > 0) : (steps += 1) {
            assert(steps <= 2 * @as(u64, self.nodes.len));
            const frame = &stack[stack_len - 1];
            const current = &self.nodes[frame.index];
            if (frame.expanded) {
                self.compute_ref(frame.index);
                stack_len -= 1;
                continue;
            }
            frame.expanded = true;
            if (current.kind == .leaf) continue;
            const children: []const NodeIndex = if (current.kind == .extension)
                current.body.children[0..1]
            else
                current.body.children[0..];
            for (children) |child_index| {
                if (child_index == none or child_index == unloaded) continue;
                if (self.nodes[child_index].ref.len > 0) continue;
                assert(stack_len < stack.len);
                stack[stack_len] = .{ .index = child_index, .expanded = false };
                stack_len += 1;
            }
        }
    }

    /// The root hash of the trie at `root` after all updates.
    pub fn root_hash(self: *SparseTrie, root: NodeIndex) Hash {
        if (root == none) return node.empty_root;
        self.update_refs(root);
        assert(self.nodes[root].ref.len > 0);
        return self.nodes[root].ref.root_hash();
    }

    pub fn free_nodes(self: *const SparseTrie) u32 {
        return self.free_count;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn check_decode(bytes: []const u8) !void {
    const decoded = decode_node(bytes) catch return;
    switch (decoded.kind) {
        .leaf => try testing.expect(decoded.value.len > 0 and decoded.value.len <= value_bytes_max),
        .extension => try testing.expect(decoded.path.len > 0 and decoded.children[0].len > 0),
        .branch => {
            var count: u32 = 0;
            for (decoded.children) |child| count += @intFromBool(child.len > 0);
            try testing.expect(count >= 2);
        },
    }
    try testing.expect(decoded.path.len <= key_nibbles);
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(input[0..length]);
}

test "sparse: fuzz node decoder" {
    try testing.fuzz({}, fuzz_decode, .{});
}

test "sparse: seeded node decoder fuzz" {
    var prng = Prng.init(0x5ba25e);
    var buffer: [600]u8 = undefined;
    var refs: [16]RlpNode = undefined;
    for (0..2000) |_| {
        // Valid-ish nodes from the encoders, then random corruption.
        var sink: node.BufferSink = .{ .buffer = &buffer };
        var path: [key_nibbles]u8 = undefined;
        const path_len = prng.range(1, key_nibbles);
        for (path[0..path_len]) |*nibble| nibble.* = @intCast(prng.below(16));
        var value: [40]u8 = undefined;
        prng.fill(&value);
        const value_len = prng.range(1, value.len);
        switch (prng.below(3)) {
            0 => node.encode_leaf(&sink, path[0..path_len], value[0..value_len]),
            1 => {
                const ref = RlpNode.from_hash(node.keccak256(&value));
                node.encode_extension(&sink, path[0..path_len], &ref);
            },
            else => {
                const mask: u16 = @intCast(prng.range(1, 0xffff));
                for (&refs) |*ref| ref.* = RlpNode.from_hash(node.keccak256(&value));
                node.encode_branch(&sink, mask, refs[0..@popCount(mask)], &.{});
            },
        }
        const encoded = sink.result();
        try check_decode(encoded);
        if (prng.chance(1, 2)) encoded[prng.below(encoded.len)] = prng.int(u8);
        try check_decode(encoded[0..prng.range(1, encoded.len)]);
    }
}

const TestStore = struct {
    preimages: std.AutoHashMapUnmanaged(Hash, []const u8) = .empty,

    fn resolve(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *TestStore = @ptrCast(@alignCast(context));
        return self.preimages.get(hash.*);
    }
};

test "sparse: updates from an unknown root keep untouched subtries as references" {
    const Trie = @import("trie.zig").TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });
    var full = try Trie.init(testing.allocator, 4096);
    defer full.deinit(testing.allocator);
    var prng = Prng.init(7);
    var keys: [64][32]u8 = undefined;
    for (&keys) |*key| {
        prng.fill(key);
        try full.put(key, &.{ 1, 2, 3 });
    }
    const pre_root = full.root_hash();
    // Every node is known: hash every node of the full trie into the store.
    var store: TestStore = .{};
    defer store.preimages.deinit(testing.allocator);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const Collect = struct {
        store: *TestStore,
        arena: std.mem.Allocator,
        pub fn visit(self: @This(), visit_info: @import("trie.zig").Visit) !void {
            if (visit_info.encoding.len < 32 and visit_info.path.len > 0) return;
            const copy = try self.arena.dupe(u8, visit_info.encoding);
            try self.store.preimages.put(testing.allocator, node.keccak256(copy), copy);
        }
    };
    try full.track_changes(testing.allocator);
    const collect: Collect = .{ .store = &store, .arena = arena_state.allocator() };
    try full.visit_nodes(full.root, .all, collect);
    var sparse = try SparseTrie.init(testing.allocator, 4096, .{
        .context = &store,
        .resolve = TestStore.resolve,
    });
    defer sparse.deinit(testing.allocator);
    var root = try sparse.root_from_hash(pre_root);
    try testing.expectEqual(pre_root, sparse.root_hash(root));
    for (keys[0..32]) |*key| {
        try sparse.delete(&root, key);
        _ = full.delete(key);
    }
    var fresh: [32]u8 = undefined;
    prng.fill(&fresh);
    try sparse.put(&root, &fresh, &.{9});
    try full.put(&fresh, &.{9});
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, (try sparse.get(root, &keys[40])).?);
    try testing.expectEqual(full.root_hash(), sparse.root_hash(root));
    // Deleting everything empties the trie.
    for (keys[32..]) |*key| try sparse.delete(&root, key);
    try sparse.delete(&root, &fresh);
    try testing.expectEqual(none, root);
    try testing.expectEqual(node.empty_root, sparse.root_hash(root));
}

test "sparse: missing preimage is WitnessIncomplete" {
    var store: TestStore = .{};
    var sparse = try SparseTrie.init(testing.allocator, 16, .{
        .context = &store,
        .resolve = TestStore.resolve,
    });
    defer sparse.deinit(testing.allocator);
    const root = try sparse.root_from_hash(node.keccak256("unknown"));
    const key: [32]u8 = @splat(1);
    try testing.expectError(error.WitnessIncomplete, sparse.get(root, &key));
}

fn clustered_key(prng: *Prng) [32]u8 {
    // Few distinct leading nibbles: long shared prefixes force extensions and their splits.
    var key: [32]u8 = undefined;
    prng.fill(&key);
    key[0] = @intCast(prng.below(2) * 0x11);
    key[1] = @intCast(prng.below(3));
    key[2] = if (prng.chance(1, 2)) 0 else key[2];
    return key;
}

test "sparse: seeded differential against the full trie with shared prefixes" {
    const trie_module = @import("trie.zig");
    const Trie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const Collect = struct {
        store: *TestStore,
        arena: std.mem.Allocator,
        pub fn visit(self: @This(), visit_info: trie_module.Visit) !void {
            if (visit_info.encoding.len < 32 and visit_info.path.len > 0) return;
            const copy = try self.arena.dupe(u8, visit_info.encoding);
            try self.store.preimages.put(self.arena, node.keccak256(copy), copy);
        }
    };
    for (0..12) |seed| {
        var prng = Prng.init(0xd1ff + seed);
        var full = try Trie.init(testing.allocator, 2048);
        defer full.deinit(testing.allocator);
        try full.track_changes(testing.allocator);
        var keys: [48][32]u8 = undefined;
        for (&keys) |*key| {
            key.* = clustered_key(&prng);
            try full.put(key, &.{ 0x82, 1, 2 });
        }
        var store: TestStore = .{};
        const collect: Collect = .{ .store = &store, .arena = arena_state.allocator() };
        const pre_root = full.root_hash();
        try full.visit_nodes(full.root, .all, collect);
        var sparse = try SparseTrie.init(testing.allocator, 2048, .{
            .context = &store,
            .resolve = TestStore.resolve,
        });
        defer sparse.deinit(testing.allocator);
        var root = try sparse.root_from_hash(pre_root);
        for (0..96) |_| {
            const key = if (prng.chance(1, 2)) keys[prng.below(keys.len)] else clustered_key(&prng);
            if (prng.chance(1, 2)) {
                _ = full.delete(&key);
                try sparse.delete(&root, &key);
            } else {
                const value: [2]u8 = .{ 0x81, @intCast(prng.range(0x80, 0xff)) };
                try full.put(&key, &value);
                try sparse.put(&root, &key, &value);
            }
            try testing.expectEqual(full.root_hash(), sparse.root_hash(root));
            const probe = keys[prng.below(keys.len)];
            const expected = full.get(&probe);
            const actual = try sparse.get(root, &probe);
            try testing.expectEqual(expected == null, actual == null);
            if (expected) |bytes| try testing.expectEqualSlices(u8, bytes, actual.?);
        }
    }
}

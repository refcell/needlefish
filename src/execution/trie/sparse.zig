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
//! preimage, so an untouched branch costs one pool node, not seventeen: each child slot holds
//! the byte offset of the child's item in that preimage until then, so neither materializing
//! a child nor rehashing a dirty branch over unloaded children decodes the preimage again.
//! No recursion.
//!
//! Root computation rehashes dirty nodes level by level, deepest first, across any number
//! of tries at once (`update_root_refs`), batching equal-length encodings through
//! `keccak256_batch`; `root_hash_serial` (the post-order reference) is fuzzed against it.

const std = @import("std");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
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
/// Longest node encoding: a branch of sixteen hashed children and no value.
const encoding_bytes_max = 3 + 16 * 33 + 1;
const batch_width = keccak.batch_width;
/// Encodings waiting for a batch partner: `batch_width - 1` per encoding length.
const pending_bytes = (encoding_bytes_max + 1) * (batch_width - 1) * encoding_bytes_max;

comptime {
    assert(batch_width >= 2);
    assert(encoding_bytes_max == 532);
    // A leaf (hex-prefixed path and the largest value) and an extension fit too.
    assert(3 + 34 + 2 + value_bytes_max <= encoding_bytes_max);
}

/// keccak256 of each of `inputs` (all of one length) into `out`, `batch_width` at a time.
pub fn keccak256_many(inputs: []const []const u8, out: []Hash) void {
    assert(inputs.len == out.len);
    var start: usize = 0;
    while (inputs.len - start >= batch_width) : (start += batch_width) {
        keccak.keccak256_batch(inputs[start..][0..batch_width], out[start..][0..batch_width]);
    }
    for (inputs[start..], out[start..]) |input, *digest| digest.* = node.keccak256(input);
    assert(inputs.len - start < batch_width);
}

pub const Error = error{ WitnessIncomplete, InvalidWitness, SparseFull };
pub const DecodeError = error{InvalidNode};

pub const NodeIndex = u32;
pub const none: NodeIndex = std.math.maxInt(NodeIndex);
/// Bound on a decoded node's preimage, so a child's item offset fits an `unloaded` slot.
const source_bytes_max = 1024;
/// A child present in the parent's preimage but not yet given a pool node is
/// `unloaded_first + offset`, where `offset` locates its RLP item in the parent's `source`:
/// materializing or re-referencing it never decodes the parent again.
const unloaded_first: NodeIndex = none - source_bytes_max;

comptime {
    // Every preimage `decode_layout` accepts is at most a full branch.
    assert(encoding_bytes_max < source_bytes_max);
    assert(unloaded_first > std.math.maxInt(u16));
}

fn unloaded_at(offset: u32) NodeIndex {
    assert(offset > 0 and offset < source_bytes_max);
    const index = unloaded_first + offset;
    assert(index != none);
    return index;
}

fn is_unloaded(index: NodeIndex) bool {
    return index >= unloaded_first and index != none;
}

fn unloaded_offset(index: NodeIndex) u32 {
    assert(is_unloaded(index));
    const offset = index - unloaded_first;
    assert(offset > 0);
    return offset;
}

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

/// One node as decoded from its RLP with child references left in the input: each is
/// located by the byte offset of its RLP item, 0 when empty (offset 0 is the list header).
pub const Layout = struct {
    kind: DecodedKind,
    path: Nibbles = .{},
    /// Leaf value.
    value: []const u8 = &.{},
    /// Child item offsets by nibble; an extension uses slot 0.
    child_offsets: [16]u16 = @splat(0),
};

/// Whether a branch or extension child item is present; rejects malformed references.
fn check_child(item: rlp.Item) DecodeError!bool {
    switch (item.kind) {
        .string => {
            if (item.payload.len == 0) return false;
            if (item.payload.len != 32) return error.InvalidNode;
            return true;
        },
        .list => {
            if (item.raw.len >= 32) return error.InvalidNode;
            return true;
        },
    }
}

fn item_offset(bytes: []const u8, item: rlp.Item) u16 {
    const offset = @intFromPtr(item.raw.ptr) - @intFromPtr(bytes.ptr);
    assert(offset > 0 and offset + item.raw.len <= bytes.len);
    assert(offset < source_bytes_max);
    return @intCast(offset);
}

/// The reference whose RLP item starts at `offset` of `bytes`, a preimage `decode_layout`
/// accepted with that child offset: a 32-byte hash string or an embedded list under 32 bytes.
/// Either way the item's bytes are the reference itself.
pub fn child_ref_at(bytes: []const u8, offset: u32) RlpNode {
    const item = child_item_at(bytes, offset);
    var result: RlpNode = .{ .len = @intCast(item.len) };
    @memcpy(result.bytes[0..item.len], item);
    assert(result.len > 0);
    return result;
}

/// The bytes of the reference `child_ref_at` returns, in place.
pub fn child_item_at(bytes: []const u8, offset: u32) []const u8 {
    assert(offset > 0 and offset < bytes.len);
    const prefix = bytes[offset];
    const length: u32 = if (prefix == 0xa0) 33 else 1 + @as(u32, prefix - 0xc0);
    assert(prefix == 0xa0 or (prefix >= 0xc0 and length < 32));
    assert(offset + length <= bytes.len);
    return bytes[offset..][0..length];
}

/// The byte length of a branch child item in the forms a valid branch child takes: the
/// empty string, a 32-byte hash string, or a short list under 32 bytes. Null for any other
/// item (an invalid child, or not a branch at all), or one running past `rest`.
fn branch_child_length(rest: []const u8) ?u32 {
    if (rest.len == 0) return null;
    const prefix = rest[0];
    const length: u32 = switch (prefix) {
        0x80 => 1,
        0xa0 => 33,
        0xc0...0xf7 => 1 + @as(u32, prefix - 0xc0),
        else => return null,
    };
    if (length >= 32 and prefix != 0xa0) return null;
    if (length > rest.len) return null;
    assert(length >= 1 and length <= 33);
    return length;
}

/// `decode_layout` of a list payload that is a well-formed branch, in one pass without
/// building items; null when it is anything else (the strict decoder then decides). Accepts
/// exactly the branches `decode_layout_items` accepts, with the same offsets.
fn decode_branch_fast(bytes: []const u8, payload: []const u8) ?Layout {
    const payload_start = @intFromPtr(payload.ptr) - @intFromPtr(bytes.ptr);
    assert(payload_start > 0 and payload_start + payload.len == bytes.len);
    var result: Layout = .{ .kind = .branch };
    var position: u32 = 0;
    var children: u32 = 0;
    for (&result.child_offsets) |*offset| {
        const length = branch_child_length(payload[position..]) orelse return null;
        // Only the empty string is an empty slot (`0xc0`, the empty list, is a child).
        if (payload[position] != 0x80) {
            offset.* = @intCast(payload_start + position);
            children += 1;
        }
        position += length;
    }
    // The value slot: the empty string, ending the list.
    if (position + 1 != payload.len or payload[position] != 0x80) return null;
    if (children < 2) return null;
    assert(children <= 16);
    return result;
}

/// Decodes one state-trie node strictly: canonical RLP, no branch values, a branch has at
/// least two children, paths fit a 32-byte key, leaf values are non-empty and bounded.
pub fn decode_layout(bytes: []const u8) DecodeError!Layout {
    const outer = rlp.decode_item(bytes) catch return error.InvalidNode;
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    if (decode_branch_fast(bytes, outer.payload)) |layout| return layout;
    return decode_layout_items(bytes, outer.payload);
}

/// The reference decoder behind `decode_layout`: splits the list into items first.
fn decode_layout_items(bytes: []const u8, payload: []const u8) DecodeError!Layout {
    assert(payload.len < bytes.len);
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string or items[16].payload.len != 0) return error.InvalidNode;
        var result: Layout = .{ .kind = .branch };
        var children: u32 = 0;
        for (items[0..16], &result.child_offsets) |item, *offset| {
            if (!try check_child(item)) continue;
            offset.* = item_offset(bytes, item);
            children += 1;
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
    if (!try check_child(items[1])) return error.InvalidNode;
    var result: Layout = .{ .kind = .extension, .path = decoded.path };
    result.child_offsets[0] = item_offset(bytes, items[1]);
    return result;
}

/// `decode_layout` with the child references copied out.
pub fn decode_node(bytes: []const u8) DecodeError!Decoded {
    const layout = try decode_layout(bytes);
    var result: Decoded = .{ .kind = layout.kind, .path = layout.path, .value = layout.value };
    for (layout.child_offsets, &result.children) |offset, *child| {
        if (offset > 0) child.* = child_ref_at(bytes, offset);
    }
    assert(layout.kind != .leaf or result.children[0].len == 0);
    return result;
}

/// Maps a node hash to its preimage (whose keccak256 must be that hash), or null.
/// Receives the encoding of every node a root computation hashes (32 bytes or more), with its
/// hash: a verifier that keeps the trie's new nodes can resolve them again after `clear`.
pub const Sink = struct {
    context: *anyopaque,
    add: *const fn (context: *anyopaque, hash: *const Hash, bytes: []const u8) void,
};

pub const Resolver = struct {
    context: *anyopaque,
    resolve: *const fn (context: *anyopaque, hash: *const Hash) ?[]const u8,
};

/// What `visit_records` knows about a branch child: a loaded leaf, a loaded extension or
/// branch (a record of its own), or a reference only (not loaded, or not yet decoded).
pub const ChildKind = enum(u8) { leaf, record, unknown };

pub const VisitChild = struct {
    ref: RlpNode = .{},
    kind: ChildKind = .unknown,
    /// A loaded leaf's path: the key's nibbles after the branch's path and this nibble.
    leaf_path: []const u8 = &.{},
};

/// One record position of a trie as `visit_records` reports it: a branch together with the
/// extension above it, hanging below its parent branch's path and nibble (empty at the root),
/// or the leaf of a trie that is one leaf. Slices are valid during the callback only.
pub const RecordVisit = struct {
    hang: []const u8,
    /// The extension above the branch; empty when the branch is the top node.
    extension: []const u8 = &.{},
    /// Set for a single-leaf trie: the leaf's whole path (64 nibbles); no branch then.
    root_leaf_path: ?[]const u8 = null,
    /// The top node, or the branch below it, was built or changed since `clear`.
    changed: bool,
    /// The parent branch was built or changed: the record may hang elsewhere than before.
    parent_changed: bool,
    /// The reference the parent (or the root hash) holds for the top node.
    top_ref: RlpNode,
    /// The preimages the top node and the branch were decoded from; empty when built here
    /// or embedded in their parent.
    top_source: []const u8 = &.{},
    branch_source: []const u8 = &.{},
    branch_ref: RlpNode = .{},
    /// False when the branch below a loaded extension is not loaded: children unknown.
    branch_loaded: bool = false,
    state_mask: u16 = 0,
    /// By nibble; set where `state_mask` has a bit.
    children: [16]VisitChild = @splat(.{}),
};

const Kind = enum(u8) { free, unresolved, leaf, extension, branch };

const Body = union { value: [value_bytes_max]u8, children: [16]NodeIndex };

const Node = struct {
    kind: Kind,
    path_len: u8 = 0,
    value_len: u8 = 0,
    /// The node's reference while clean; `len == 0` once it or a descendant changed.
    ref: RlpNode = .{},
    /// Set when the node is built or changed (its `ref` cleared) since `clear`; unlike a
    /// cleared `ref` it survives the root computation, for `visit_records`.
    changed: bool = false,
    /// The witness preimage of a decoded extension or branch: its unloaded children
    /// (`unloaded_at`) are item offsets into it.
    source: []const u8 = &.{},
    path: [key_nibbles]u8 = undefined,
    body: Body = .{ .children = undefined },
};

/// Node pool: freed nodes form a LIFO list, and `nodes[fresh..]` were never handed out since
/// the last `clear`. So `clear` is O(1) and the pool (reserved at init, committed on first
/// touch through `lazy_alloc`) only becomes resident as far as a block actually used it.
pub const SparseTrie = struct {
    nodes: []Node,
    free_head: NodeIndex = none,
    free_count: u32 = 0,
    /// Nodes at and above this index are untouched since `clear`.
    fresh: u32 = 0,
    resolver: Resolver,
    /// Optional: told about every node `update_root_refs` hashes.
    sink: ?Sink = null,
    /// Root computation scratch (one entry per pool node): `depth << 32 | index` of every
    /// dirty node, then the same nodes ordered deepest level first.
    dirty: []u64,
    levels: []NodeIndex,
    /// Encodings waiting for equal-length partners within one level (`pending_bytes`).
    pending: []u8,

    pub fn init(
        allocator: std.mem.Allocator,
        nodes_max: u32,
        resolver: Resolver,
    ) !SparseTrie {
        assert(nodes_max > 0 and nodes_max < unloaded_first);
        const nodes = try lazy.alloc(allocator, Node, nodes_max);
        errdefer lazy.free(allocator, nodes);
        const dirty = try lazy.alloc(allocator, u64, nodes_max);
        errdefer lazy.free(allocator, dirty);
        const levels = try lazy.alloc(allocator, NodeIndex, nodes_max);
        errdefer lazy.free(allocator, levels);
        const pending = try lazy.alloc(allocator, u8, pending_bytes);
        var result: SparseTrie = .{
            .nodes = nodes,
            .resolver = resolver,
            .dirty = dirty,
            .levels = levels,
            .pending = pending,
        };
        result.clear();
        assert(result.dirty.len == result.nodes.len and result.levels.len == result.nodes.len);
        return result;
    }

    pub fn deinit(self: *SparseTrie, allocator: std.mem.Allocator) void {
        lazy.free(allocator, self.pending);
        lazy.free(allocator, self.levels);
        lazy.free(allocator, self.dirty);
        lazy.free(allocator, self.nodes);
        self.* = undefined;
    }

    /// Frees every node of every trie.
    pub fn clear(self: *SparseTrie) void {
        self.free_head = none;
        self.fresh = 0;
        self.free_count = @intCast(self.nodes.len);
        assert(self.free_count > 0);
    }

    /// Reuses the newest freed node first, then the lowest untouched one: the same order
    /// as a free list threaded through the whole pool.
    fn alloc(self: *SparseTrie, kind: Kind) Error!NodeIndex {
        if (self.free_count == 0) return error.SparseFull;
        const index = if (self.free_head != none) blk: {
            const head = self.free_head;
            assert(head < self.fresh);
            assert(self.nodes[head].kind == .free);
            self.free_head = self.nodes[head].body.children[0];
            break :blk head;
        } else blk: {
            assert(self.fresh < self.nodes.len);
            self.fresh += 1;
            break :blk self.fresh - 1;
        };
        self.free_count -= 1;
        assert(self.free_count >= self.nodes.len - self.fresh);
        self.nodes[index] = .{ .kind = kind };
        return @intCast(index);
    }

    fn free(self: *SparseTrie, index: NodeIndex) void {
        assert(index < self.fresh);
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
        const decoded = decode_layout(bytes) catch return error.InvalidWitness;
        var children: u32 = 0;
        for (decoded.child_offsets) |offset| children += @intFromBool(offset > 0);
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
        for (decoded.child_offsets, 0..) |offset, nibble| {
            if (offset == 0) continue;
            if (from_witness) {
                current.body.children[nibble] = unloaded_at(offset);
            } else {
                // Capacity checked above, before the node changed.
                current.body.children[nibble] =
                    self.alloc_unresolved(child_ref_at(bytes, offset)) catch unreachable;
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
        assert(index != none);
        if (!is_unloaded(index)) return index;
        const ref = child_ref_at(current.source, unloaded_offset(index));
        const created = try self.alloc_unresolved(ref);
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
        leaf.changed = true;
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
        self.nodes[index].changed = true;
        return index;
    }

    fn new_extension(self: *SparseTrie, path: []const u8, target: NodeIndex) Error!NodeIndex {
        assert(path.len > 0 and target != none and !is_unloaded(target));
        const index = try self.alloc(.extension);
        const extension = &self.nodes[index];
        extension.changed = true;
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
        current.changed = true;
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
        current.changed = true;
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
            self.nodes[slot.*].changed = true;
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
                current.changed = true;
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

    /// The child reference of a dirty extension. A witness extension that only changed its
    /// path (a parent branch collapsed into it) keeps its child unloaded: the reference then
    /// comes from its source.
    fn extension_target_ref(self: *const SparseTrie, index: NodeIndex) RlpNode {
        const current = &self.nodes[index];
        assert(current.kind == .extension);
        const target = current.body.children[0];
        assert(target != none);
        const target_ref = if (is_unloaded(target))
            child_ref_at(current.source, unloaded_offset(target))
        else
            self.child_ref(target);
        assert(target_ref.len > 0);
        return target_ref;
    }

    /// The child references of a dirty branch, in nibble order, and their mask.
    fn branch_refs(
        self: *const SparseTrie,
        index: NodeIndex,
        refs: *[16]RlpNode,
        mask: *u16,
    ) u32 {
        const current = &self.nodes[index];
        assert(current.kind == .branch);
        var count: u32 = 0;
        mask.* = 0;
        for (current.body.children, 0..) |child_index, nibble| {
            if (child_index == none) continue;
            mask.* |= @as(u16, 1) << @intCast(nibble);
            if (is_unloaded(child_index)) {
                refs[count] = child_ref_at(current.source, unloaded_offset(child_index));
            } else {
                refs[count] = self.child_ref(child_index);
            }
            count += 1;
        }
        assert(count >= 1 and count == @popCount(mask.*));
        return count;
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
                const target_ref = self.extension_target_ref(index);
                current.ref = node.extension_ref(node_path, &target_ref);
            },
            .branch => {
                var refs: [16]RlpNode = undefined;
                var mask: u16 = 0;
                const count = self.branch_refs(index, &refs, &mask);
                current.ref = node.branch_ref(mask, refs[0..count], &.{});
            },
            .free, .unresolved => unreachable, // Unresolved nodes are never dirty.
        }
        assert(current.ref.len > 0);
    }

    /// The full encoding of a dirty node whose children are all clean.
    fn encode_dirty(
        self: *const SparseTrie,
        index: NodeIndex,
        buffer: *[encoding_bytes_max]u8,
    ) []const u8 {
        const current = &self.nodes[index];
        assert(current.ref.len == 0);
        var sink: node.BufferSink = .{ .buffer = buffer };
        const node_path = current.path[0..current.path_len];
        switch (current.kind) {
            .leaf => node.encode_leaf(&sink, node_path, current.body.value[0..current.value_len]),
            .extension => {
                const target_ref = self.extension_target_ref(index);
                node.encode_extension(&sink, node_path, &target_ref);
            },
            .branch => return self.encode_dirty_branch(index, buffer),
            .free, .unresolved => unreachable, // Unresolved nodes are never dirty.
        }
        const encoded = sink.result();
        assert(encoded.len > 0);
        return encoded;
    }

    /// `node.encode_branch` of a dirty branch without a value, writing each child reference
    /// straight from its pool node or its parent's preimage (no `RlpNode` copies).
    fn encode_dirty_branch(
        self: *const SparseTrie,
        index: NodeIndex,
        buffer: *[encoding_bytes_max]u8,
    ) []const u8 {
        const current = &self.nodes[index];
        assert(current.kind == .branch and current.ref.len == 0);
        var items: [16][]const u8 = undefined;
        // One byte per empty slot and one for the empty value.
        var payload_length: u32 = 1;
        var children: u32 = 0;
        for (current.body.children, &items) |child_index, *item| {
            item.* = if (child_index == none)
                &.{0x80}
            else if (is_unloaded(child_index))
                child_item_at(current.source, unloaded_offset(child_index))
            else
                self.nodes[child_index].ref.slice();
            payload_length += @intCast(item.len);
            children += @intFromBool(child_index != none);
        }
        assert(children >= 1);
        var written = rlp.write_list_header(buffer, payload_length);
        for (items) |item| {
            // Fixed-size copies for the two common shapes instead of a memcpy call each.
            switch (item.len) {
                1 => buffer[written] = item[0],
                33 => buffer[written..][0..33].* = item[0..33].*,
                else => @memcpy(buffer[written..][0..item.len], item),
            }
            written += @intCast(item.len);
        }
        buffer[written] = 0x80;
        written += 1;
        assert(written == rlp.header_length(payload_length) + payload_length);
        return buffer[0..written];
    }

    /// Recomputes the references of every dirty node below `root`, children first, one
    /// keccak at a time (the reference for the batched `update_root_refs`).
    fn update_refs_serial(self: *SparseTrie, root: NodeIndex) void {
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
                if (child_index == none or is_unloaded(child_index)) continue;
                if (self.nodes[child_index].ref.len > 0) continue;
                assert(stack_len < stack.len);
                stack[stack_len] = .{ .index = child_index, .expanded = false };
                stack_len += 1;
            }
        }
    }

    /// Recomputes the references of every dirty node below `roots` (distinct tries of this
    /// pool, `none` allowed), deepest level first: a node depends only on its children, one
    /// level deeper, so the nodes of a level are independent and share hash batches. Later
    /// `root_hash` calls on these roots are then free.
    pub fn update_root_refs(self: *SparseTrie, roots: []const NodeIndex) void {
        var depth_counts: [depth_max + 1]u32 = @splat(0);
        const count = self.collect_dirty(roots, &depth_counts);
        // Counting sort by depth, deepest first.
        var depth_starts: [depth_max + 1]u32 = undefined;
        var offset: u32 = 0;
        var depth: u32 = depth_max + 1;
        while (depth > 0) {
            depth -= 1;
            depth_starts[depth] = offset;
            offset += depth_counts[depth];
        }
        assert(offset == count);
        var next = depth_starts;
        for (self.dirty[0..count]) |entry| {
            const entry_depth: u32 = @intCast(entry >> 32);
            self.levels[next[entry_depth]] = @truncate(entry);
            next[entry_depth] += 1;
        }
        depth = depth_max + 1;
        while (depth > 0) {
            depth -= 1;
            if (depth_counts[depth] == 0) continue;
            const start = depth_starts[depth];
            self.hash_level(self.levels[start..][0..depth_counts[depth]]);
        }
        for (roots) |root| assert(root == none or self.nodes[root].ref.len > 0);
    }

    /// Writes `depth << 32 | index` into `dirty` for every dirty node below `roots` and
    /// counts the nodes of each depth. Returns the number of dirty nodes.
    fn collect_dirty(
        self: *SparseTrie,
        roots: []const NodeIndex,
        depth_counts: *[depth_max + 1]u32,
    ) u32 {
        // Each pop pushes at most sixteen children, one level deeper.
        var stack: [depth_max * 16]u64 = undefined;
        var count: u32 = 0;
        for (roots) |root| {
            if (root == none or self.nodes[root].ref.len > 0) continue;
            stack[0] = root;
            var stack_len: u32 = 1;
            while (stack_len > 0) {
                stack_len -= 1;
                const entry = stack[stack_len];
                const index: NodeIndex = @truncate(entry);
                const depth: u32 = @intCast(entry >> 32);
                assert(depth <= depth_max);
                assert(count < self.dirty.len);
                self.dirty[count] = entry;
                count += 1;
                depth_counts[depth] += 1;
                const current = &self.nodes[index];
                assert(current.ref.len == 0);
                const children: []const NodeIndex = switch (current.kind) {
                    .leaf => &.{},
                    .extension => current.body.children[0..1],
                    .branch => current.body.children[0..],
                    .free, .unresolved => unreachable, // Unresolved nodes are never dirty.
                };
                for (children) |child_index| {
                    if (child_index == none or is_unloaded(child_index)) continue;
                    if (self.nodes[child_index].ref.len > 0) continue;
                    assert(stack_len < stack.len);
                    stack[stack_len] = @as(u64, depth + 1) << 32 | child_index;
                    stack_len += 1;
                }
            }
        }
        return count;
    }

    fn pending_slot(self: *SparseTrie, length: usize, slot: usize) []u8 {
        assert(length <= encoding_bytes_max and slot < batch_width - 1);
        const start = (length * (batch_width - 1) + slot) * encoding_bytes_max;
        return self.pending[start..][0..length];
    }

    /// References of one level's nodes. An encoding of 32 bytes or more waits in `pending`
    /// until `batch_width` encodings of its length are there, then they hash together;
    /// leftovers hash one by one at the end of the level.
    fn hash_level(self: *SparseTrie, level: []const NodeIndex) void {
        assert(level.len > 0);
        var waiting: [encoding_bytes_max + 1]u8 = @splat(0);
        var waiting_index: [encoding_bytes_max + 1][batch_width - 1]NodeIndex = undefined;
        var buffer: [encoding_bytes_max]u8 = undefined;
        for (level) |index| {
            const encoded = self.encode_dirty(index, &buffer);
            const length = encoded.len;
            if (length < 32) {
                self.nodes[index].ref = RlpNode.from_rlp(encoded);
                continue;
            }
            if (waiting[length] + 1 < batch_width) {
                @memcpy(self.pending_slot(length, waiting[length]), encoded);
                waiting_index[length][waiting[length]] = index;
                waiting[length] += 1;
                continue;
            }
            var inputs: [batch_width][]const u8 = undefined;
            for (inputs[0 .. batch_width - 1], 0..) |*input, slot| {
                input.* = self.pending_slot(length, slot);
            }
            inputs[batch_width - 1] = encoded;
            var digests: [batch_width]Hash = undefined;
            keccak.keccak256_batch(&inputs, &digests);
            for (waiting_index[length], digests[0 .. batch_width - 1]) |waiting_node, digest| {
                self.nodes[waiting_node].ref = RlpNode.from_hash(digest);
            }
            self.nodes[index].ref = RlpNode.from_hash(digests[batch_width - 1]);
            if (self.sink) |sink| {
                for (inputs, &digests) |input, *digest| sink.add(sink.context, digest, input);
            }
            waiting[length] = 0;
        }
        for (waiting, 0..) |waiting_count, length| {
            for (waiting_index[length][0..waiting_count], 0..) |waiting_node, slot| {
                const encoded = self.pending_slot(length, slot);
                const digest = node.keccak256(encoded);
                self.nodes[waiting_node].ref = RlpNode.from_hash(digest);
                if (self.sink) |sink| sink.add(sink.context, &digest, encoded);
            }
        }
        for (level) |index| assert(self.nodes[index].ref.len > 0);
    }

    /// The root hash of the trie at `root` after all updates.
    pub fn root_hash(self: *SparseTrie, root: NodeIndex) Hash {
        if (root == none) return node.empty_root;
        self.update_root_refs(&.{root});
        assert(self.nodes[root].ref.len > 0);
        return self.nodes[root].ref.root_hash();
    }

    /// `root_hash` through the serial post-order rehash.
    fn root_hash_serial(self: *SparseTrie, root: NodeIndex) Hash {
        if (root == none) return node.empty_root;
        self.update_refs_serial(root);
        assert(self.nodes[root].ref.len > 0);
        return self.nodes[root].ref.root_hash();
    }

    /// Reports every record position reachable through loaded nodes of the trie at `root` to
    /// `visitor.record(*const RecordVisit)`, in pre-order: each loaded extension-and-branch or
    /// bare branch, and the leaf of a single-leaf trie. Children that are not loaded are
    /// reported by reference only (`ChildKind.unknown`); loaded extension and branch children
    /// are visited in turn. Call after the root computation (every loaded node has its
    /// reference). Clean subtries are walked too, as far as they are loaded. No recursion.
    pub fn visit_records(self: *const SparseTrie, root: NodeIndex, visitor: anytype) !void {
        if (root == none) return;
        const top = &self.nodes[root];
        if (top.kind == .unresolved) return;
        assert(top.ref.len > 0);
        if (top.kind == .leaf) {
            assert(top.path_len == key_nibbles);
            return visitor.record(&RecordVisit{
                .hang = &.{},
                .root_leaf_path = top.path[0..top.path_len],
                .changed = top.changed,
                .parent_changed = false,
                .top_ref = top.ref,
            });
        }
        const Frame = struct { index: NodeIndex, hang_len: u8, nibble: u8, parent_changed: bool };
        // Each pop pushes at most sixteen frames, one branch deeper.
        var stack: [depth_max * 16]Frame = undefined;
        stack[0] = .{ .index = root, .hang_len = 0, .nibble = 0, .parent_changed = false };
        var stack_len: u32 = 1;
        // The path to the frame being visited; ancestors' nibbles stay in place below it.
        var path: [key_nibbles]u8 = undefined;
        var steps: u64 = 0;
        while (stack_len > 0) : (steps += 1) {
            assert(steps < self.nodes.len);
            stack_len -= 1;
            const frame = stack[stack_len];
            if (frame.hang_len > 0) path[frame.hang_len - 1] = frame.nibble;
            var visit: RecordVisit = undefined;
            const hang = path[0..frame.hang_len];
            const branch = self.record_at(frame.index, hang, frame.parent_changed, &path, &visit);
            try visitor.record(&visit);
            if (branch == none) continue;
            const branch_len = frame.hang_len + visit.extension.len;
            assert(branch_len < key_nibbles);
            var nibble: u8 = 16;
            while (nibble > 0) {
                nibble -= 1;
                const child = self.nodes[branch].body.children[nibble];
                if (child == none or is_unloaded(child)) continue;
                const kind = self.nodes[child].kind;
                if (kind != .branch and kind != .extension) continue;
                assert(stack_len < stack.len);
                stack[stack_len] = .{
                    .index = child,
                    .hang_len = @intCast(branch_len + 1),
                    .nibble = nibble,
                    .parent_changed = self.nodes[branch].changed,
                };
                stack_len += 1;
            }
        }
    }

    /// Fills `visit` for the record whose top node is the loaded extension or branch `index`
    /// (an extension's nibbles go into `path` after `hang`). Returns the branch's pool node
    /// when it is loaded, else `none`.
    fn record_at(
        self: *const SparseTrie,
        index: NodeIndex,
        hang: []const u8,
        parent_changed: bool,
        path: *[key_nibbles]u8,
        visit: *RecordVisit,
    ) NodeIndex {
        const top = &self.nodes[index];
        assert(top.kind == .extension or top.kind == .branch);
        assert(top.ref.len > 0);
        visit.* = .{
            .hang = hang,
            .changed = top.changed,
            .parent_changed = parent_changed,
            .top_ref = top.ref,
            .top_source = top.source,
        };
        var branch = index;
        if (top.kind == .extension) {
            visit.extension = top.path[0..top.path_len];
            assert(hang.len + visit.extension.len < key_nibbles);
            @memcpy(path[hang.len..][0..top.path_len], visit.extension);
            const target = top.body.children[0];
            assert(target != none);
            if (is_unloaded(target)) {
                visit.branch_ref = child_ref_at(top.source, unloaded_offset(target));
                return none;
            }
            if (self.nodes[target].kind == .unresolved) {
                visit.branch_ref = self.nodes[target].ref;
                return none;
            }
            // An extension's child is a branch (a leaf below would have merged into it).
            assert(self.nodes[target].kind == .branch);
            branch = target;
        }
        const current = &self.nodes[branch];
        visit.changed = visit.changed or current.changed;
        visit.branch_ref = current.ref;
        visit.branch_source = current.source;
        visit.branch_loaded = true;
        self.visit_children(branch, visit);
        assert(visit.branch_ref.len > 0);
        return branch;
    }

    fn visit_children(self: *const SparseTrie, branch: NodeIndex, visit: *RecordVisit) void {
        const current = &self.nodes[branch];
        assert(current.kind == .branch);
        for (current.body.children, &visit.children, 0..) |child_index, *child, nibble| {
            if (child_index == none) continue;
            visit.state_mask |= @as(u16, 1) << @intCast(nibble);
            if (is_unloaded(child_index)) {
                child.* = .{ .ref = child_ref_at(current.source, unloaded_offset(child_index)) };
                continue;
            }
            const loaded = &self.nodes[child_index];
            assert(loaded.ref.len > 0);
            child.* = .{
                .ref = loaded.ref,
                .kind = switch (loaded.kind) {
                    .leaf => .leaf,
                    .extension, .branch => .record,
                    .unresolved => .unknown,
                    .free => unreachable, // A branch never points at a freed node.
                },
            };
            if (loaded.kind == .leaf) child.leaf_path = loaded.path[0..loaded.path_len];
        }
        // Deletes collapse a branch left with one child.
        assert(@popCount(visit.state_mask) >= 2);
    }

    /// Turns every clean node decoded from the preimage `source` (compared by address) back
    /// into an unresolved node under its reference, so the next read resolves it again.
    /// For a verifier that resolved a node to a stand-in it must not keep serving. Children
    /// the stand-in materialized stay allocated until `clear`. Returns the nodes reset.
    pub fn unresolve_source(self: *SparseTrie, source: []const u8) Error!u32 {
        assert(source.len > 0);
        var count: u32 = 0;
        for (self.nodes[0..self.fresh]) |*current| {
            if (current.kind != .branch and current.kind != .extension) continue;
            if (current.source.ptr != source.ptr) continue;
            // A changed stand-in has no reference to resolve again.
            if (!current.ref.is_hash()) return error.InvalidWitness;
            current.kind = .unresolved;
            current.source = &.{};
            count += 1;
        }
        assert(count <= self.fresh);
        return count;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// The one-pass branch decoder accepts exactly what the item decoder accepts as a branch.
fn check_branch_fast(bytes: []const u8) !void {
    const outer = rlp.decode_item(bytes) catch return;
    if (outer.kind != .list or outer.encoded_length != bytes.len) return;
    const fast = decode_branch_fast(bytes, outer.payload);
    const reference = decode_layout_items(bytes, outer.payload) catch {
        try testing.expect(fast == null);
        return;
    };
    const layout = fast orelse {
        try testing.expect(reference.kind != .branch);
        return;
    };
    try testing.expectEqual(DecodedKind.branch, reference.kind);
    try testing.expectEqualSlices(u16, &reference.child_offsets, &layout.child_offsets);
}

fn check_decode(bytes: []const u8) !void {
    try check_branch_fast(bytes);
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
                for (&refs) |*ref| {
                    // Some children embedded: a short leaf encodes in under 32 bytes.
                    const short_path = path[0..prng.range(0, @min(8, path_len))];
                    ref.* = if (prng.chance(1, 3))
                        node.leaf_ref(short_path, value[0..prng.range(1, 8)])
                    else
                        RlpNode.from_hash(node.keccak256(&value));
                }
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

test "sparse: collapse into a witness extension with an unloaded child" {
    const Trie = @import("trie.zig").TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });
    var full = try Trie.init(testing.allocator, 64);
    defer full.deinit(testing.allocator);
    // Root branch: a leaf under nibble 0, and under nibble 1 a long hashed extension
    // over a branch of two leaves.
    const lone: [32]u8 = @splat(0x00);
    var deep_a: [32]u8 = @splat(0x11);
    var deep_b: [32]u8 = @splat(0x11);
    deep_a[20] = 0x00;
    deep_b[20] = 0xff;
    try full.put(&lone, &.{ 0x82, 1, 2 });
    try full.put(&deep_a, &.{ 0x82, 3, 4 });
    try full.put(&deep_b, &.{ 0x82, 5, 6 });
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
    const pre_root = full.root_hash();
    try full.visit_nodes(full.root, .all, collect);
    var sparse = try SparseTrie.init(testing.allocator, 64, .{
        .context = &store,
        .resolve = TestStore.resolve,
    });
    defer sparse.deinit(testing.allocator);
    var root = try sparse.root_from_hash(pre_root);
    // The delete collapses the root branch into the extension without loading its child.
    try sparse.delete(&root, &lone);
    _ = full.delete(&lone);
    try testing.expectEqual(full.root_hash(), sparse.root_hash(root));
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

test "sparse: seeded differential of the batched root against the serial root" {
    const trie_module = @import("trie.zig");
    const Trie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 64 });
    const tries_count = 3;
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
    for (0..8) |seed| {
        var prng = Prng.init(0xba7c4ed + seed);
        var full = try Trie.init(testing.allocator, 2048);
        defer full.deinit(testing.allocator);
        try full.track_changes(testing.allocator);
        var keys: [64][32]u8 = undefined;
        for (&keys) |*key| {
            key.* = clustered_key(&prng);
            try full.put(key, &.{ 0x82, 1, 2 });
        }
        var store: TestStore = .{};
        const collect: Collect = .{ .store = &store, .arena = arena_state.allocator() };
        const pre_root = full.root_hash();
        try full.visit_nodes(full.root, .all, collect);
        const resolver: Resolver = .{ .context = &store, .resolve = TestStore.resolve };
        // The same updates on every trie of two pools: `batched` rehashes all its tries in
        // one `update_root_refs`, `serial` one post-order walk per trie.
        var batched = try SparseTrie.init(testing.allocator, 8192, resolver);
        defer batched.deinit(testing.allocator);
        var serial = try SparseTrie.init(testing.allocator, 8192, resolver);
        defer serial.deinit(testing.allocator);
        var batched_roots: [tries_count]NodeIndex = undefined;
        var serial_roots: [tries_count]NodeIndex = undefined;
        for (&batched_roots, &serial_roots) |*a, *b| {
            a.* = try batched.root_from_hash(pre_root);
            b.* = try serial.root_from_hash(pre_root);
        }
        for (0..24) |_| {
            for (&batched_roots, &serial_roots, 0..) |*a, *b, trie_index| {
                for (0..prng.range(0, 6)) |_| {
                    const key = if (prng.chance(1, 2))
                        keys[prng.below(keys.len)]
                    else
                        clustered_key(&prng);
                    if (prng.chance(1, 3)) {
                        try batched.delete(a, &key);
                        try serial.delete(b, &key);
                        if (trie_index == 0) _ = full.delete(&key);
                        continue;
                    }
                    var value: [64]u8 = undefined;
                    prng.fill(&value);
                    const length = prng.range(1, value.len);
                    try batched.put(a, &key, value[0..length]);
                    try serial.put(b, &key, value[0..length]);
                    if (trie_index == 0) try full.put(&key, value[0..length]);
                }
            }
            batched.update_root_refs(&batched_roots);
            for (batched_roots, serial_roots) |a, b| {
                try testing.expectEqual(serial.root_hash_serial(b), batched.root_hash(a));
            }
            try testing.expectEqual(full.root_hash(), batched.root_hash(batched_roots[0]));
        }
    }
}

const hash_builder = @import("hash_builder.zig");

/// Records keyed by hang path, from `HashBuilder`'s branch sink or from `visit_records`.
const RecordList = struct {
    const capacity = 64;

    hangs: [capacity]Nibbles = undefined,
    records: [capacity]hash_builder.BranchNode = undefined,
    /// Whether the visit saw every child (no `unknown` kinds).
    complete: [capacity]bool = undefined,
    changed: [capacity]bool = undefined,
    count: u32 = 0,

    fn emit(context: *anyopaque, hang: []const u8, branch: *const hash_builder.BranchNode) void {
        const self: *RecordList = @ptrCast(@alignCast(context));
        assert(self.count < capacity);
        self.hangs[self.count] = Nibbles.from_nibbles(hang);
        self.records[self.count] = branch.*;
        self.complete[self.count] = true;
        self.changed[self.count] = true;
        self.count += 1;
    }

    fn find(self: *const RecordList, hang: []const u8) ?u32 {
        for (self.hangs[0..self.count], 0..) |*entry, index| {
            if (std.mem.eql(u8, entry.slice(), hang)) return @intCast(index);
        }
        return null;
    }

    /// `visit_records` callback: the record as the trie holds it (leaf keys rebuilt from
    /// the loaded leaves' paths).
    pub fn record(self: *RecordList, visit: *const RecordVisit) !void {
        assert(self.count < capacity);
        var branch: hash_builder.BranchNode = .{};
        var complete = true;
        if (visit.root_leaf_path) |leaf_path| {
            _ = Nibbles.from_nibbles(leaf_path).pack(&branch.leaf_keys[0]);
        } else if (visit.branch_loaded) {
            branch.extension_len = @intCast(visit.extension.len);
            @memcpy(branch.extension[0..visit.extension.len], visit.extension);
            branch.state_mask = visit.state_mask;
            var children: u32 = 0;
            var leaves: u32 = 0;
            for (&visit.children, 0..) |*child, nibble| {
                if (visit.state_mask & (@as(u16, 1) << @intCast(nibble)) == 0) continue;
                branch.children[children] = child.ref;
                children += 1;
                switch (child.kind) {
                    .record => branch.tree_mask |= @as(u16, 1) << @intCast(nibble),
                    .unknown => complete = false,
                    .leaf => {
                        var key = Nibbles.from_nibbles(visit.hang);
                        key.append(visit.extension);
                        key.push(@intCast(nibble));
                        key.append(child.leaf_path);
                        try testing.expectEqual(@as(usize, key_nibbles), @as(usize, key.len));
                        _ = key.pack(&branch.leaf_keys[leaves]);
                        leaves += 1;
                    },
                }
            }
        } else {
            complete = false;
        }
        self.hangs[self.count] = Nibbles.from_nibbles(visit.hang);
        self.records[self.count] = branch;
        self.complete[self.count] = complete;
        self.changed[self.count] = visit.changed;
        self.count += 1;
    }
};

fn expect_same_record(
    want: *const hash_builder.BranchNode,
    got: *const hash_builder.BranchNode,
) !void {
    try testing.expectEqualSlices(u8, want.extension_slice(), got.extension_slice());
    try testing.expectEqual(want.state_mask, got.state_mask);
    try testing.expectEqual(want.tree_mask, got.tree_mask);
    for (want.children[0..want.child_count()], got.children[0..got.child_count()]) |a, b| {
        try testing.expectEqualSlices(u8, a.slice(), b.slice());
    }
    const leaves: u32 = if (want.state_mask == 0) 1 else want.leaf_count();
    for (want.leaf_keys[0..leaves], got.leaf_keys[0..leaves]) |a, b| {
        try testing.expectEqualSlices(u8, &a, &b);
    }
}

/// The records `HashBuilder` emits for the sorted `keys` (values `value_of`); the root.
fn build_records(keys: []const [32]u8, out: *RecordList) Hash {
    var sink: hash_builder.BranchSink = .{ .context = out, .emit = RecordList.emit };
    var builder = hash_builder.HashBuilder.init();
    builder.branch_sink = &sink;
    var values: [2][3]u8 = undefined;
    for (keys, 0..) |*key, index| {
        // The builder borrows the previous value until the next leaf.
        values[index % 2] = value_of(key);
        const path = Nibbles.from_bytes(key);
        builder.add_leaf(path.slice(), &values[index % 2]);
    }
    return builder.root();
}

fn value_of(key: *const [32]u8) [3]u8 {
    return .{ 0x82, key[31], key[30] | 1 };
}

fn sort_unique(keys: [][32]u8) [][32]u8 {
    const Less = struct {
        fn less(_: void, a: [32]u8, b: [32]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    };
    std.mem.sort([32]u8, keys, {}, Less.less);
    var count: usize = 0;
    for (keys) |key| {
        if (count > 0 and std.mem.eql(u8, &keys[count - 1], &key)) continue;
        keys[count] = key;
        count += 1;
    }
    return keys[0..count];
}

/// A sparse sink that keeps every hashed node in a `TestStore` (arena-owned copies).
const KeepStore = struct {
    store: TestStore = .{},
    arena: std.mem.Allocator,

    fn add(context: *anyopaque, hash: *const Hash, bytes: []const u8) void {
        const self: *KeepStore = @ptrCast(@alignCast(context));
        const copy = self.arena.dupe(u8, bytes) catch @panic("test arena");
        self.store.preimages.put(self.arena, hash.*, copy) catch @panic("test arena");
    }
};

test "sparse: visit_records reports the records HashBuilder emits, changed ones after updates" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    for (0..16) |seed| {
        var prng = Prng.init(0x7e5c + seed);
        var keep: KeepStore = .{ .arena = arena_state.allocator() };
        var keys_buffer: [40][32]u8 = undefined;
        for (&keys_buffer) |*key| key.* = clustered_key(&prng);
        const keys = sort_unique(keys_buffer[0..prng.range(1, keys_buffer.len)]);
        var sparse = try SparseTrie.init(testing.allocator, 1024, .{
            .context = &keep.store,
            .resolve = TestStore.resolve,
        });
        defer sparse.deinit(testing.allocator);
        sparse.sink = .{ .context = &keep, .add = KeepStore.add };
        // A trie built here: every node is new and loaded, so the visit sees all records.
        var root = try sparse.root_from_hash(node.empty_root);
        for (keys) |*key| try sparse.put(&root, key, &value_of(key));
        var want: RecordList = .{};
        try testing.expectEqual(build_records(keys, &want), sparse.root_hash(root));
        var got: RecordList = .{};
        try sparse.visit_records(root, &got);
        try testing.expectEqual(want.count, got.count);
        for (0..got.count) |index| {
            const at = want.find(got.hangs[index].slice()) orelse
                return error.TestUnexpectedResult;
            try testing.expect(got.complete[index] and got.changed[index]);
            try expect_same_record(&want.records[at], &got.records[index]);
        }
        // From the root hash: delete and add a few keys; every record the visit reports
        // completely is the fresh build's record at that hang, and every changed one exists.
        const pre_root = sparse.root_hash(root);
        sparse.clear();
        root = try sparse.root_from_hash(pre_root);
        var after_buffer: [48][32]u8 = undefined;
        var after_len: usize = 0;
        for (keys) |key| {
            if (prng.chance(1, 3)) {
                try sparse.delete(&root, &key);
            } else {
                after_buffer[after_len] = key;
                after_len += 1;
            }
        }
        for (0..prng.below(8)) |_| {
            const key = clustered_key(&prng);
            try sparse.put(&root, &key, &value_of(&key));
            after_buffer[after_len] = key;
            after_len += 1;
        }
        const after = sort_unique(after_buffer[0..after_len]);
        var fresh: RecordList = .{};
        try testing.expectEqual(build_records(after, &fresh), sparse.root_hash(root));
        var visited: RecordList = .{};
        try sparse.visit_records(root, &visited);
        for (0..visited.count) |index| {
            const at = fresh.find(visited.hangs[index].slice()) orelse
                return error.TestUnexpectedResult;
            if (!visited.complete[index]) continue;
            try expect_same_record(&fresh.records[at], &visited.records[index]);
        }
    }
}

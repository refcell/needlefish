//! Multi-key historical storage proofs (`history.Store.get_proofs`): the base/base
//! `cursor_cache.rs` analogue. `eth_getProof(address, [k1..kn], block)` at an older block
//! hashes the n slots, sorts the unique hashes (`trie.path_targets`), and walks the storage
//! trie once (`Store.walk_frames`): each node on a shared prefix is looked up, hash-checked,
//! and decoded once, then referenced by every key whose path enters it.
//!
//! A `ProofSet` holds, per unique key, the proof nodes as slices into the history store and
//! the value; `fill` copies one requested key's proof into a `TrieType.Proof`, byte for byte
//! the proof `Store.get_proof` builds for that slot alone. The slices are valid until the
//! store next changes (commit, unwind, reset, prune), so read the set right after the walk.
//! All memory is caller-provided: `init` (allocator) or a fixed `Storage(keys_max)`.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");

const Hash = [32]u8;
const PathTarget = trie.PathTarget;

/// Upper bound on the nodes of one proof of a 32-byte key: the root plus one per nibble.
pub const nodes_max = trie.path_targets.path_nibbles + 1;

/// The proof of one unique key: nodes in `eth_getProof` order (root first) and the value
/// (0 when absent).
pub const KeyProof = struct {
    nodes: [nodes_max][]const u8 = undefined,
    count: u32 = 0,
    value: u256 = 0,

    pub fn append(self: *KeyProof, bytes: []const u8) void {
        assert(self.count < nodes_max);
        assert(bytes.len > 0);
        self.nodes[self.count] = bytes;
        self.count += 1;
    }
};

/// Fixed-capacity backing arrays for a `ProofSet` (for bounded scratch carving).
pub fn Storage(comptime keys_max: u32) type {
    comptime assert(keys_max > 0);
    return struct {
        hashes: [keys_max]Hash,
        targets: [keys_max]PathTarget,
        keys: [keys_max]KeyProof,

        pub fn set(self: *@This()) ProofSet {
            return .{ .hashes = &self.hashes, .targets = &self.targets, .keys = &self.keys };
        }
    };
}

pub const ProofSet = struct {
    /// Per requested slot (input order): the hashed slot.
    hashes: []Hash,
    /// Unique hashed slots, sorted (the first `unique`).
    targets: []PathTarget,
    /// Per unique target: its proof.
    keys: []KeyProof,
    slots_count: u32 = 0,
    unique: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, keys_max: u32) !ProofSet {
        assert(keys_max > 0);
        const hashes = try allocator.alloc(Hash, keys_max);
        errdefer allocator.free(hashes);
        const targets = try allocator.alloc(PathTarget, keys_max);
        errdefer allocator.free(targets);
        const keys = try allocator.alloc(KeyProof, keys_max);
        return .{ .hashes = hashes, .targets = targets, .keys = keys };
    }

    /// A set for `keys_max` keys carved from `buffer` (bounded scratch); null when it does
    /// not fit.
    pub fn carve(buffer: []u8, keys_max: u32) ?ProofSet {
        assert(keys_max > 0);
        var offset: usize = 0;
        const keys = carve_slice(KeyProof, buffer, &offset, keys_max) orelse return null;
        const hashes = carve_slice(Hash, buffer, &offset, keys_max) orelse return null;
        const targets = carve_slice(PathTarget, buffer, &offset, keys_max) orelse return null;
        assert(offset <= buffer.len);
        return .{ .hashes = hashes, .targets = targets, .keys = keys };
    }

    pub fn deinit(self: *ProofSet, allocator: std.mem.Allocator) void {
        allocator.free(self.keys);
        allocator.free(self.targets);
        allocator.free(self.hashes);
        self.* = undefined;
    }

    pub fn capacity(self: *const ProofSet) u32 {
        assert(self.hashes.len == self.targets.len and self.hashes.len == self.keys.len);
        return @intCast(self.hashes.len);
    }

    /// Hashes `slots`, sorts the unique hashes into the targets, and clears their proofs.
    pub fn prepare(self: *ProofSet, slots: []const u256) void {
        assert(slots.len <= self.capacity());
        for (slots, self.hashes[0..slots.len], self.targets[0..slots.len]) |slot, *h, *t| {
            var slot_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &slot_bytes, slot, .big);
            h.* = trie.node.keccak256(&slot_bytes);
            t.* = .{ .path = h.* };
        }
        self.slots_count = @intCast(slots.len);
        self.unique = trie.path_targets.sort_unique(self.targets[0..slots.len]);
        assert(self.unique <= self.slots_count);
        for (self.keys[0..self.unique]) |*key| key.* = .{};
    }

    /// The unique hashed slots, sorted (walk targets).
    pub fn targets_unique(self: *const ProofSet) []const PathTarget {
        assert(self.unique <= self.slots_count);
        return self.targets[0..self.unique];
    }

    /// The proofs of `targets_unique`, in the same order.
    pub fn keys_unique(self: *ProofSet) []KeyProof {
        assert(self.unique <= self.slots_count);
        return self.keys[0..self.unique];
    }

    /// The proof of requested slot `slot_index` (input order; duplicates share one).
    pub fn proof(self: *const ProofSet, slot_index: u32) *const KeyProof {
        assert(slot_index < self.slots_count);
        const hash = &self.hashes[slot_index];
        var low: u32 = 0;
        var high: u32 = self.unique;
        // Binary search: the hash is one of the unique targets.
        while (low < high) {
            const middle = low + (high - low) / 2;
            switch (std.mem.order(u8, &self.targets[middle].path, hash)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return &self.keys[middle],
            }
        }
        unreachable; // `prepare` put every requested hash into the targets.
    }

    pub fn value(self: *const ProofSet, slot_index: u32) u256 {
        return self.proof(slot_index).value;
    }

    /// Copies the proof of requested slot `slot_index` into `out` (a `TrieType.Proof`).
    pub fn fill(self: *const ProofSet, slot_index: u32, out: anytype) void {
        const key = self.proof(slot_index);
        assert(key.count <= out.ends.len);
        var end: u32 = 0;
        for (key.nodes[0..key.count], out.ends[0..key.count]) |bytes, *node_end| {
            assert(end + bytes.len <= out.buffer.len);
            @memcpy(out.buffer[end..][0..bytes.len], bytes);
            end += @intCast(bytes.len);
            node_end.* = end;
        }
        out.count = key.count;
    }
};

fn carve_slice(comptime T: type, buffer: []u8, offset: *usize, count: u32) ?[]T {
    const base = @intFromPtr(buffer.ptr);
    const start = std.mem.alignForward(usize, base + offset.*, @alignOf(T)) - base;
    const end = start + @as(usize, count) * @sizeOf(T);
    if (end > buffer.len) return null;
    offset.* = end;
    const items: [*]T = @ptrCast(@alignCast(buffer[start..].ptr));
    return items[0..count];
}

test "proof set: duplicates share one unique target and find their proof" {
    var storage: Storage(4) = undefined;
    var set = storage.set();
    const slots = [_]u256{ 7, 3, 7, 1 };
    set.prepare(&slots);
    try std.testing.expectEqual(@as(u32, 3), set.unique);
    try std.testing.expect(trie.path_targets.sorted(set.targets_unique()));
    set.keys_unique()[0].value = 11;
    set.keys_unique()[1].value = 12;
    set.keys_unique()[2].value = 13;
    try std.testing.expectEqual(set.value(0), set.value(2));
    try std.testing.expect(set.value(0) != set.value(1));
    try std.testing.expect(set.proof(0) == set.proof(2));
}

test "proof set: carve fits the keys or refuses" {
    var buffer: [8 * @sizeOf(KeyProof)]u8 = undefined;
    try std.testing.expect(ProofSet.carve(&buffer, 64) == null);
    var set = ProofSet.carve(&buffer, 4).?;
    try std.testing.expectEqual(@as(u32, 4), set.capacity());
    set.prepare(&.{ 2, 2 });
    try std.testing.expectEqual(@as(u32, 1), set.unique);
}

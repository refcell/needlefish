//! Historical proofs store: `eth_getProof` at any block of a retention window, without
//! re-execution. Mirrors base/base `crates/execution/trie` (`BaseProofsStore`): trie node
//! preimages are versioned by (trie, path, block), and a proof at block N walks the trie from
//! the state root of N, taking at each path the newest version written at or before N.
//!
//! Why paths and not hashes: a path has one node per block, so the newest version at or before
//! N is exactly the node of N whenever N's parent node points at that path, and pruning is
//! per path (a version is dropped once a newer one is at or before the window start). The
//! store is fed by `StateTrie.visit_nodes`: every node rehashed in a block is written at its
//! path. A node a block removes gets a tombstone (an empty version) at its path, found by
//! diffing each rewritten node against its previous version; tombstones let the pruner free
//! paths of deleted subtries. Every node of a proof is checked against its parent's reference.
//!
//! Leaf values are the leaves themselves (accounts and slots decode from leaf nodes), so no
//! separate leaf history is kept. All memory is sized at init from `Config`.
//!
//! The store is in memory only and is not journaled: after a restart it is rebuilt with
//! `reset` at the recovered head, and proofs for older blocks are unavailable until the
//! window refills.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const changeset_module = @import("changeset.zig");
const rlp = trie.rlp;
const nibbles_module = trie.nibbles;
const StateTrie = trie.StateTrie;

pub const Address = changeset_module.Address;
pub const Hash = changeset_module.Hash;

pub const Config = struct {
    /// Proofs work for blocks `[head - window_blocks + 1, head]`.
    window_blocks: u32,
    /// Distinct (trie, path) keys stored at once (see "Sizing" on `Store`).
    paths_max: u32,
    /// Node versions with encodings of at most `small_bytes` bytes (leaves, extensions,
    /// sparse branches) and tombstones, across the window plus one base version per path.
    small_versions_max: u32,
    /// Node versions with longer encodings (dense branches).
    large_versions_max: u32,
    /// Queued versions `commit_block` prunes before writing a block (see "Sizing").
    prune_per_commit: u32,
};

pub const Error = error{
    /// The block is not in `[oldest, head]`.
    BlockOutOfWindow,
    /// `commit_block` takes `head + 1` only.
    NotNextBlock,
    /// Not enough paths or versions for the block; the store keeps its previous head.
    HistoryFull,
    /// `reset` has not run (or failed).
    NotInitialized,
    /// A stored node does not decode or does not match its parent's reference.
    HistoryCorrupt,
} || trie.state_trie.Error;

/// Largest encoding kept in a small version: an account leaf (148 bytes) fits.
pub const small_bytes = 160;
pub const large_bytes = @max(StateTrie.account_node_bytes_max, StateTrie.storage_node_bytes_max);
const path_nibbles_max = 64;

comptime {
    assert(2 + 34 + 2 + trie.state_trie.account_rlp_bytes_max <= small_bytes);
    assert(small_bytes < large_bytes);
    assert(large_bytes < std.math.maxInt(u16));
}

/// Owner (32 bytes), storage flag, path length, packed path nibbles.
const Key = [32 + 1 + 1 + path_nibbles_max / 2]u8;

fn make_key(owner: ?Hash, path: []const u8) Key {
    assert(path.len <= path_nibbles_max);
    var key: Key = @splat(0);
    if (owner) |hash| {
        key[0..32].* = hash;
        key[32] = 1;
    }
    key[33] = @intCast(path.len);
    for (path, 0..) |nibble, index| {
        assert(nibble < 16);
        key[34 + index / 2] |= if (index % 2 == 0) nibble << 4 else nibble;
    }
    return key;
}

fn key_owner(key: *const Key) ?Hash {
    assert(key[32] <= 1);
    if (key[32] == 0) return null;
    return key[0..32].*;
}

fn key_path(key: *const Key, out: *[path_nibbles_max]u8) []const u8 {
    const length = key[33];
    assert(length <= path_nibbles_max);
    for (out[0..length], 0..) |*nibble, index| {
        const byte = key[34 + index / 2];
        nibble.* = if (index % 2 == 0) byte >> 4 else byte & 0x0f;
    }
    return out[0..length];
}

const none: u32 = std.math.maxInt(u32);
const large_bit: u32 = 1 << 31;

const Version = struct {
    block: u64,
    /// The next older version of the same path, or `none`.
    prev: u32,
    /// The next newer version of the same path, or `none`.
    newer: u32,
    /// The next version written in the same block (unwind), then the next version of the
    /// prune queue once the block became the oldest; `none` at the end.
    block_next: u32,
    path: u32,
    /// Encoding length; 0 is a tombstone (no node at the path from this block on).
    len: u16,
};

const Path = struct { key: Key, head: u32 };

const BlockEntry = struct {
    number: u64,
    state_root: Hash,
    /// Versions written in this block, newest first; `none` for the oldest block (its
    /// versions moved to the prune queue or are base versions).
    versions: u32,
    /// The first version written in this block (the end of `versions`).
    versions_tail: u32,
    versions_count: u32,
};

/// The account fields of an account leaf.
pub const AccountState = struct {
    nonce: u64,
    balance: u256,
    storage_root: Hash,
    code_hash: Hash,
};

/// Occupancy, for capacity monitoring and tests.
pub const Usage = struct {
    paths: u32,
    small_versions: u32,
    large_versions: u32,
    /// Versions at or before the oldest block that `prune_step` has not examined yet.
    prune_queue: u32,
};

/// A free list of version slots of one size class.
fn Pool(comptime bytes: u32) type {
    return struct {
        const Self = @This();
        versions: []Version,
        data: [][bytes]u8,
        free: []u32,
        free_len: u32,

        fn init(allocator: std.mem.Allocator, count: u32) !Self {
            const versions = try allocator.alloc(Version, count);
            errdefer allocator.free(versions);
            const data = try allocator.alloc([bytes]u8, count);
            errdefer allocator.free(data);
            const free = try allocator.alloc(u32, count);
            var self: Self = .{ .versions = versions, .data = data, .free = free, .free_len = 0 };
            self.clear();
            return self;
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.free);
            allocator.free(self.data);
            allocator.free(self.versions);
            self.* = undefined;
        }

        fn clear(self: *Self) void {
            for (self.free, 0..) |*slot, index| slot.* = @intCast(self.free.len - 1 - index);
            self.free_len = @intCast(self.free.len);
        }

        fn take(self: *Self) u32 {
            assert(self.free_len > 0);
            self.free_len -= 1;
            const index = self.free[self.free_len];
            assert(index < self.versions.len);
            return index;
        }

        fn give(self: *Self, index: u32) void {
            assert(index < self.versions.len);
            assert(self.free_len < self.free.len);
            self.free[self.free_len] = index;
            self.free_len += 1;
        }

        fn used(self: *const Self) u32 {
            assert(self.free_len <= self.free.len);
            return @as(u32, @intCast(self.free.len)) - self.free_len;
        }
    };
}

/// A pending subtrie root to bury (tombstone) while diffing a block.
const BuryFrame = struct {
    owner: Hash,
    has_owner: bool,
    /// Only tombstone paths the new trie does not reach (a diff candidate may share paths
    /// with the new trie); unchecked frames come from a whole trie that is gone.
    checked: bool,
    len: u8,
    nibbles: [path_nibbles_max]u8,
};

/// Depth-first, a node pops itself and pushes at most 16 children: at most 15 per level
/// stay behind, for one account-trie walk plus one storage-trie walk stacked on it.
const bury_frames_max = 2 * 16 * (path_nibbles_max + 1);

/// The shape of a stored node: kind, child slots or path, leaf value.
const Shape = struct {
    kind: enum { leaf, extension, branch },
    /// Branch: non-empty child slots.
    mask: u16 = 0,
    /// Leaf or extension path.
    path: nibbles_module.Nibbles = .{},
    /// Leaf value.
    value: []const u8 = &.{},
};

fn node_shape(bytes: []const u8) StepError!Shape {
    const outer = try rlp.decode_item(bytes);
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        var shape: Shape = .{ .kind = .branch };
        for (items[0..16], 0..) |item, nibble| {
            const present = item.kind == .list or item.payload.len > 0;
            if (present) shape.mask |= @as(u16, 1) << @intCast(nibble);
        }
        return shape;
    }
    if (count != 2 or items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch {
        return error.InvalidNode;
    };
    if (decoded.leaf) return .{ .kind = .leaf, .path = decoded.path, .value = items[1].payload };
    if (decoded.path.len == 0) return error.InvalidNode;
    return .{ .kind = .extension, .path = decoded.path };
}

const Drain = struct {
    pub fn visit(_: *Drain, _: StateTrie.NodeVisit) error{}!void {}
};

/// Pruning and sizing. `commit_block` only moves the window: the block that becomes the
/// oldest hands its versions to a FIFO prune queue. `prune_step(budget)` examines up to
/// `budget` queued versions; for each it frees the older version it shadows (in FIFO order
/// at most one is left), and a queued tombstone is freed too, with its path when nothing
/// newer exists. After the queue drains, every live path holds exactly one version at or
/// before the oldest block: the node the oldest block reaches there.
///
/// Sizing: let N be the most trie nodes a state holds (account plus storage pool nodes) and
/// B the most versions one block writes (rehashed nodes whose encoding changed plus one
/// tombstone per removed node; a wiped storage trie tombstones all its nodes). With
/// `prune_per_commit >= B` the queue is empty whenever a block is written, so the store
/// never holds more than N + window_blocks * B versions or paths. Size `paths_max` and each
/// version class to that bound and `commit_block` never fails with `HistoryFull`. As a
/// fallback, a block that does not fit drains the whole queue (bounded by the version
/// capacity) and is tried once more.
pub const Store = struct {
    config: Config,
    path_index: std.AutoHashMapUnmanaged(Key, u32),
    paths: []Path,
    path_free: []u32,
    path_free_len: u32,
    /// Paths removed from `path_index` since its last rehash (tombstone cleanup).
    paths_removed: u32,
    small: Pool(small_bytes),
    large: Pool(large_bytes),
    /// Ring of retained blocks, oldest first; one spare slot for the block being written.
    blocks: []BlockEntry,
    blocks_start: u32,
    blocks_len: u32,
    prune_head: u32,
    prune_tail: u32,
    prune_count: u32,
    bury_stack: []BuryFrame,
    bury_len: u32,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Store {
        assert(config.window_blocks > 0);
        assert(config.small_versions_max < large_bit and config.large_versions_max < large_bit);
        var path_index: std.AutoHashMapUnmanaged(Key, u32) = .empty;
        try path_index.ensureTotalCapacity(allocator, config.paths_max);
        errdefer path_index.deinit(allocator);
        const paths = try allocator.alloc(Path, config.paths_max);
        errdefer allocator.free(paths);
        const path_free = try allocator.alloc(u32, config.paths_max);
        errdefer allocator.free(path_free);
        var small = try Pool(small_bytes).init(allocator, config.small_versions_max);
        errdefer small.deinit(allocator);
        var large = try Pool(large_bytes).init(allocator, config.large_versions_max);
        errdefer large.deinit(allocator);
        const blocks = try allocator.alloc(BlockEntry, config.window_blocks + 1);
        errdefer allocator.free(blocks);
        const bury_stack = try allocator.alloc(BuryFrame, bury_frames_max);
        var self: Store = .{
            .config = config,
            .path_index = path_index,
            .paths = paths,
            .path_free = path_free,
            .path_free_len = 0,
            .paths_removed = 0,
            .small = small,
            .large = large,
            .blocks = blocks,
            .blocks_start = 0,
            .blocks_len = 0,
            .prune_head = none,
            .prune_tail = none,
            .prune_count = 0,
            .bury_stack = bury_stack,
            .bury_len = 0,
        };
        self.clear();
        return self;
    }

    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        allocator.free(self.bury_stack);
        allocator.free(self.blocks);
        self.large.deinit(allocator);
        self.small.deinit(allocator);
        allocator.free(self.path_free);
        allocator.free(self.paths);
        self.path_index.deinit(allocator);
        self.* = undefined;
    }

    fn clear(self: *Store) void {
        self.path_index.clearRetainingCapacity();
        for (self.path_free, 0..) |*slot, index| slot.* = @intCast(self.path_free.len - 1 - index);
        self.path_free_len = @intCast(self.path_free.len);
        self.paths_removed = 0;
        self.small.clear();
        self.large.clear();
        self.blocks_start = 0;
        self.blocks_len = 0;
        self.prune_head = none;
        self.prune_tail = none;
        self.prune_count = 0;
        self.bury_len = 0;
    }

    /// Oldest and newest retained block, or null before `reset`.
    pub fn window(self: *const Store) ?struct { oldest: u64, head: u64 } {
        if (self.blocks_len == 0) return null;
        assert(self.blocks_len <= self.config.window_blocks);
        const oldest = self.block_at(0).number;
        const head = self.block_at(self.blocks_len - 1).number;
        assert(head - oldest + 1 == self.blocks_len);
        return .{ .oldest = oldest, .head = head };
    }

    pub fn usage(self: *const Store) Usage {
        assert(self.path_free_len <= self.paths.len);
        return .{
            .paths = @as(u32, @intCast(self.paths.len)) - self.path_free_len,
            .small_versions = self.small.used(),
            .large_versions = self.large.used(),
            .prune_queue = self.prune_count,
        };
    }

    /// Whether the store holds any version at the path (freed paths are gone).
    pub fn contains_path(self: *const Store, owner: ?Hash, path: []const u8) bool {
        return self.path_index.contains(make_key(owner, path));
    }

    /// Versions written by the head block (for sizing `B`, see `Store`).
    pub fn head_block_versions(self: *const Store) u32 {
        assert(self.blocks_len > 0);
        return self.block_at(self.blocks_len - 1).versions_count;
    }

    /// Node versions at or before the oldest block (tests: after the queue drains this is
    /// the node count of the oldest block's trie). O(paths).
    pub fn base_node_count(self: *const Store) u32 {
        const oldest = self.window().?.oldest;
        var count: u32 = 0;
        var iterator = self.path_index.valueIterator();
        while (iterator.next()) |path_id| {
            var id = self.paths[path_id.*].head;
            var steps: u64 = 0;
            while (id != none) : (steps += 1) {
                assert(steps <= self.versions_total());
                const current = self.version(id);
                if (current.block <= oldest) {
                    if (current.len > 0) count += 1;
                    break;
                }
                id = current.prev;
            }
        }
        return count;
    }

    fn versions_total(self: *const Store) u64 {
        return self.small.versions.len + self.large.versions.len;
    }

    fn block_at(self: *const Store, offset: u32) *BlockEntry {
        assert(offset < self.blocks_len);
        return &self.blocks[(self.blocks_start + offset) % self.blocks.len];
    }

    fn version(self: *const Store, id: u32) *Version {
        if (id & large_bit != 0) return &self.large.versions[id & ~large_bit];
        return &self.small.versions[id];
    }

    fn encoding(self: *const Store, id: u32) []const u8 {
        const length = self.version(id).len;
        if (id & large_bit != 0) return self.large.data[id & ~large_bit][0..length];
        return self.small.data[id][0..length];
    }

    fn release(self: *Store, id: u32) void {
        if (id & large_bit != 0) self.large.give(id & ~large_bit) else self.small.give(id);
    }

    fn new_path(self: *Store, key: *const Key) u32 {
        assert(self.path_free_len > 0);
        self.path_free_len -= 1;
        const id = self.path_free[self.path_free_len];
        self.paths[id] = .{ .key = key.*, .head = none };
        self.path_index.putAssumeCapacityNoClobber(key.*, id);
        return id;
    }

    fn free_path(self: *Store, id: u32) void {
        assert(self.paths[id].head == none);
        assert(self.path_free_len < self.path_free.len);
        const removed = self.path_index.remove(self.paths[id].key);
        assert(removed);
        self.path_free[self.path_free_len] = id;
        self.path_free_len += 1;
        self.paths_removed += 1;
    }

    /// Drops all history and stores every node of `state_trie` as block `number`, the new
    /// oldest block and head. `state_trie` must have change tracking enabled; after this, only
    /// nodes rehashed later are fed by `commit_block`.
    pub fn reset(self: *Store, state_trie: *StateTrie, number: u64) Error!void {
        self.clear();
        self.blocks_len = 1;
        const root = try state_trie.root();
        self.blocks[0] = .{
            .number = number,
            .state_root = root,
            .versions = none,
            .versions_tail = none,
            .versions_count = 0,
        };
        var writer: Writer = .{ .store = self, .number = number };
        state_trie.visit_nodes(.all, &writer) catch |err| {
            self.blocks_len = 0;
            return err;
        };
        // The snapshot block is the oldest: its versions are base versions.
        self.blocks[0].versions = none;
        self.blocks[0].versions_tail = none;
        assert(self.window().?.head == number);
    }

    /// Records block `number` (`head + 1`) from the nodes `state_trie` rehashed since the
    /// previous `commit_block`, `reset`, or `unwind_to`, then moves the oldest block forward
    /// once the window is full. Atomic: on any error (`HistoryFull`) the store keeps its
    /// window and the trie keeps its change marks, so the call can be retried.
    pub fn commit_block(self: *Store, state_trie: *StateTrie, number: u64) Error!void {
        const current = self.window() orelse return error.NotInitialized;
        if (number != current.head + 1) return error.NotNextBlock;
        const root = try state_trie.root();
        _ = self.prune_step(self.config.prune_per_commit);
        self.write_block(state_trie, number, root) catch |err| {
            if (err != error.HistoryFull or self.prune_count == 0) return err;
            _ = self.prune_step(self.prune_count);
            try self.write_block(state_trie, number, root);
        };
        var drain: Drain = .{};
        try state_trie.visit_nodes(.drain, &drain);
        if (self.blocks_len > self.config.window_blocks) self.advance_oldest();
        assert(self.window().?.head == number);
    }

    /// Writes block `number` as the new head, or nothing on error.
    fn write_block(self: *Store, state_trie: *StateTrie, number: u64, root: Hash) Error!void {
        assert(self.blocks_len <= self.config.window_blocks);
        assert(self.bury_len == 0);
        self.blocks_len += 1;
        self.block_at(self.blocks_len - 1).* = .{
            .number = number,
            .state_root = root,
            .versions = none,
            .versions_tail = none,
            .versions_count = 0,
        };
        errdefer {
            self.bury_len = 0;
            self.pop_head_block();
        }
        var writer: Writer = .{ .store = self, .number = number };
        try state_trie.visit_nodes(.count, &writer);
        try self.bury_removed(state_trie, number);
        assert(self.bury_len == 0);
    }

    /// The oldest block leaves; the next one becomes the oldest and queues its versions.
    fn advance_oldest(self: *Store) void {
        assert(self.blocks_len == self.config.window_blocks + 1);
        assert(self.block_at(0).versions == none);
        self.blocks_start = @intCast((self.blocks_start + 1) % self.blocks.len);
        self.blocks_len -= 1;
        const entry = self.block_at(0);
        if (entry.versions == none) return;
        assert(self.version(entry.versions_tail).block_next == none);
        if (self.prune_tail == none) {
            self.prune_head = entry.versions;
        } else {
            self.version(self.prune_tail).block_next = entry.versions;
        }
        self.prune_tail = entry.versions_tail;
        self.prune_count += entry.versions_count;
        entry.versions = none;
        entry.versions_tail = none;
    }

    /// Examines up to `budget` queued versions (oldest blocks first) and frees what they
    /// shadow: older versions of the same path, and tombstoned paths. Returns the number of
    /// versions examined; less than `budget` only when the queue is empty. Proofs at every
    /// block of the window are unchanged.
    pub fn prune_step(self: *Store, budget: u32) u32 {
        var examined: u32 = 0;
        while (examined < budget and self.prune_head != none) : (examined += 1) {
            assert(self.prune_count > 0);
            const id = self.prune_head;
            const current = self.version(id);
            self.prune_head = current.block_next;
            if (self.prune_head == none) self.prune_tail = none;
            self.prune_count -= 1;
            current.block_next = none;
            self.prune_version(id);
        }
        assert((self.prune_head == none) == (self.prune_count == 0));
        // Removed keys leave hash map tombstones that lengthen probes; one O(paths) rehash
        // per paths_max / 2 removals keeps the amortized cost per removal constant.
        if (self.paths_removed > 0 and self.paths_removed >= self.paths.len / 2) {
            self.path_index.rehash(std.hash_map.AutoContext(Key){});
            self.paths_removed = 0;
        }
        return examined;
    }

    fn prune_version(self: *Store, id: u32) void {
        const current = self.version(id);
        assert(current.block <= self.block_at(0).number);
        if (current.prev != none) {
            const older = self.version(current.prev);
            assert(older.block < current.block);
            // FIFO order: everything older was examined, so one version is left below.
            assert(older.prev == none);
            assert(older.newer == id);
            self.release(current.prev);
            current.prev = none;
        }
        if (current.len > 0) return;
        // A tombstone at or before the oldest block: no block of the window reaches the path
        // until a newer version, so the tombstone itself goes too.
        if (current.newer == none) {
            const path_id = current.path;
            assert(self.paths[path_id].head == id);
            self.paths[path_id].head = none;
            self.release(id);
            self.free_path(path_id);
        } else {
            const newer = self.version(current.newer);
            assert(newer.prev == id and newer.block > current.block);
            newer.prev = none;
            self.release(id);
        }
    }

    /// Reorg: forgets every block above `number`, which must be in the window. The state
    /// trie must be moved back to `number` too (`State.unwind`); the nodes that move rehashes
    /// are written again (unchanged encodings are skipped) by the next `commit_block`.
    pub fn unwind_to(self: *Store, number: u64) Error!void {
        const current = self.window() orelse return error.NotInitialized;
        if (number < current.oldest or number > current.head) return error.BlockOutOfWindow;
        while (self.block_at(self.blocks_len - 1).number > number) self.pop_head_block();
        assert(self.window().?.head == number);
    }

    /// Drops the head block's versions; paths left without a version are freed.
    fn pop_head_block(self: *Store) void {
        assert(self.blocks_len > 1);
        const entry = self.block_at(self.blocks_len - 1);
        var id = entry.versions;
        var count: u32 = 0;
        while (id != none) : (count += 1) {
            assert(count < entry.versions_count);
            const removed = self.version(id);
            const path_id = removed.path;
            const path = &self.paths[path_id];
            assert(path.head == id);
            assert(removed.block == entry.number and removed.newer == none);
            path.head = removed.prev;
            if (removed.prev != none) self.version(removed.prev).newer = none;
            const next = removed.block_next;
            self.release(id);
            if (path.head == none) self.free_path(path_id);
            id = next;
        }
        assert(count == entry.versions_count);
        self.blocks_len -= 1;
    }

    /// The newest version of the path at or before `number`; null when there is none or it
    /// is a tombstone.
    fn lookup(self: *const Store, owner: ?Hash, path: []const u8, number: u64) ?u32 {
        const path_id = self.path_index.get(make_key(owner, path)) orelse return null;
        var id = self.paths[path_id].head;
        var steps: u64 = 0;
        while (id != none) : (steps += 1) {
            assert(steps <= self.versions_total());
            const current = self.version(id);
            assert(current.path == path_id);
            if (current.block <= number) return if (current.len == 0) null else id;
            id = current.prev;
        }
        return null;
    }

    /// Whether `visit` needs a new version, and whether its path is new.
    fn needs_version(self: *const Store, key: *const Key, visit_encoding: []const u8) struct {
        version: bool,
        path_id: ?u32,
    } {
        assert(visit_encoding.len > 0);
        const path_id = self.path_index.get(key.*) orelse
            return .{ .version = true, .path_id = null };
        const head = self.paths[path_id].head;
        assert(head != none);
        const same = std.mem.eql(u8, self.encoding(head), visit_encoding);
        return .{ .version = !same, .path_id = path_id };
    }

    const Writer = struct {
        store: *Store,
        number: u64,

        pub fn visit(self: *Writer, visit_info: StateTrie.NodeVisit) error{HistoryFull}!void {
            try self.store.put_version(self.number, &visit_info);
        }
    };

    fn put_version(
        self: *Store,
        number: u64,
        visit: *const StateTrie.NodeVisit,
    ) error{HistoryFull}!void {
        const length = visit.encoding.len;
        assert(length > 0 and length <= large_bytes);
        const key = make_key(visit.owner, visit.path);
        const needed = self.needs_version(&key, visit.encoding);
        if (!needed.version) return;
        // Check every resource before taking any, so a failure leaves nothing behind.
        if (needed.path_id == null and self.path_free_len == 0) return error.HistoryFull;
        if (length <= small_bytes and self.small.free_len == 0) return error.HistoryFull;
        if (length > small_bytes and self.large.free_len == 0) return error.HistoryFull;
        const path_id = needed.path_id orelse self.new_path(&key);
        var id: u32 = undefined;
        if (length <= small_bytes) {
            id = self.small.take();
            @memcpy(self.small.data[id][0..length], visit.encoding);
        } else {
            const index = self.large.take();
            @memcpy(self.large.data[index][0..length], visit.encoding);
            id = index | large_bit;
        }
        self.link_version(path_id, id, number, @intCast(length));
    }

    /// Makes `id` the newest version of the path and of the head block.
    fn link_version(self: *Store, path_id: u32, id: u32, number: u64, length: u16) void {
        const path = &self.paths[path_id];
        if (path.head != none) {
            assert(self.version(path.head).block < number);
            assert(self.version(path.head).newer == none);
            self.version(path.head).newer = id;
        }
        const entry = self.block_at(self.blocks_len - 1);
        assert(entry.number == number);
        self.version(id).* = .{
            .block = number,
            .prev = path.head,
            .newer = none,
            .block_next = entry.versions,
            .path = path_id,
            .len = length,
        };
        if (entry.versions == none) entry.versions_tail = id;
        path.head = id;
        entry.versions = id;
        entry.versions_count += 1;
    }

    /// Tombstones the path at `number`; false when it already is one (buried twice).
    fn put_tombstone(
        self: *Store,
        owner: ?Hash,
        path: []const u8,
        number: u64,
    ) error{HistoryFull}!bool {
        const path_id = self.path_index.get(make_key(owner, path)).?;
        const head = self.version(self.paths[path_id].head);
        if (head.len == 0) {
            assert(head.block == number);
            return false;
        }
        // An unreachable node is never visited, so it has no version in this block.
        assert(head.block < number);
        if (self.small.free_len == 0) return error.HistoryFull;
        self.link_version(path_id, self.small.take(), number, 0);
        return true;
    }

    /// Tombstones every node the head block removed: subtries dropped by a rewritten node,
    /// storage tries of accounts left without storage, and the whole account trie when the
    /// state became empty. Runs after the block's nodes are written, so reachability in the
    /// new trie is a walk at `number`, while the old trie is a walk at `number - 1`.
    fn bury_removed(self: *Store, state_trie: *StateTrie, number: u64) Error!void {
        assert(number > 0);
        const entry = self.block_at(self.blocks_len - 1);
        if (std.mem.eql(u8, &entry.state_root, &trie.empty_root)) {
            if (self.lookup(null, &.{}, number - 1) != null) {
                self.push_bury(null, &.{}, &.{}, false);
                try self.bury_frames(state_trie, number);
            }
        }
        // Tombstones are prepended, so walking from here sees only the written nodes.
        var id = entry.versions;
        var count: u32 = 0;
        const written = entry.versions_count;
        while (id != none) : (count += 1) {
            assert(count < written);
            const current = self.version(id);
            const next = current.block_next;
            if (current.len > 0 and current.prev != none and self.version(current.prev).len > 0) {
                try self.bury_dropped_children(state_trie, id, number);
            }
            id = next;
        }
    }

    /// Queues the children of `id`'s previous version that `id` no longer has, then buries.
    fn bury_dropped_children(
        self: *Store,
        state_trie: *StateTrie,
        id: u32,
        number: u64,
    ) Error!void {
        const current = self.version(id);
        const key = &self.paths[current.path].key;
        const owner = key_owner(key);
        var path_buffer: [path_nibbles_max]u8 = undefined;
        const path = key_path(key, &path_buffer);
        const old = node_shape(self.encoding(current.prev)) catch return error.HistoryCorrupt;
        const new = node_shape(self.encoding(id)) catch return error.HistoryCorrupt;
        switch (old.kind) {
            .leaf => if (owner == null) try self.bury_storage_if_gone(state_trie, path, &old),
            .extension => {
                const kept = new.kind == .extension and
                    std.mem.eql(u8, new.path.slice(), old.path.slice());
                if (!kept) self.push_bury(owner, path, old.path.slice(), true);
            },
            .branch => {
                const kept: u16 = if (new.kind == .branch) new.mask else 0;
                self.push_branch_children(owner, path, old.mask & ~kept, true);
            },
        }
        try self.bury_frames(state_trie, number);
    }

    /// An account leaf left the trie or changed: if the account had storage and has none
    /// now, its whole storage trie is gone.
    fn bury_storage_if_gone(
        self: *Store,
        state_trie: *StateTrie,
        prefix: []const u8,
        leaf: *const Shape,
    ) Error!void {
        assert(leaf.kind == .leaf);
        const leaf_path = leaf.path.slice();
        if (prefix.len + leaf_path.len != path_nibbles_max) return error.HistoryCorrupt;
        var full: [path_nibbles_max]u8 = undefined;
        @memcpy(full[0..prefix.len], prefix);
        @memcpy(full[prefix.len..], leaf_path);
        var address_hash: Hash = undefined;
        for (&address_hash, 0..) |*byte, index| byte.* = full[2 * index] << 4 | full[2 * index + 1];
        const account = decode_account(leaf.value) catch return error.HistoryCorrupt;
        if (std.mem.eql(u8, &account.storage_root, &trie.empty_root)) return;
        const storage_root = state_trie.storage_root(address_hash);
        if (!std.mem.eql(u8, &storage_root, &trie.empty_root)) return;
        self.push_bury(address_hash, &.{}, &.{}, false);
    }

    fn push_branch_children(
        self: *Store,
        owner: ?Hash,
        path: []const u8,
        mask: u16,
        checked: bool,
    ) void {
        for (0..16) |nibble| {
            if (mask & (@as(u16, 1) << @intCast(nibble)) == 0) continue;
            const suffix = [1]u8{@intCast(nibble)};
            self.push_bury(owner, path, &suffix, checked);
        }
    }

    fn push_bury(
        self: *Store,
        owner: ?Hash,
        prefix: []const u8,
        suffix: []const u8,
        checked: bool,
    ) void {
        assert(prefix.len + suffix.len <= path_nibbles_max);
        assert(self.bury_len < self.bury_stack.len);
        const frame = &self.bury_stack[self.bury_len];
        frame.* = .{
            .owner = owner orelse @splat(0),
            .has_owner = owner != null,
            .checked = checked,
            .len = @intCast(prefix.len + suffix.len),
            .nibbles = undefined,
        };
        @memcpy(frame.nibbles[0..prefix.len], prefix);
        @memcpy(frame.nibbles[prefix.len..][0..suffix.len], suffix);
        self.bury_len += 1;
    }

    /// Tombstones the queued subtries of the old trie, depth first, stopping at paths the
    /// new trie still reaches (checked frames): a reached node is either rewritten (and
    /// diffed itself) or unchanged, and then so is its whole subtrie.
    fn bury_frames(self: *Store, state_trie: *StateTrie, number: u64) Error!void {
        var steps: u64 = 0;
        while (self.bury_len > 0) : (steps += 1) {
            assert(steps <= 17 * self.versions_total() + bury_frames_max);
            self.bury_len -= 1;
            const frame = self.bury_stack[self.bury_len];
            const owner: ?Hash = if (frame.has_owner) frame.owner else null;
            const path = frame.nibbles[0..frame.len];
            const old_id = self.lookup(owner, path, number - 1) orelse
                return error.HistoryCorrupt;
            if (frame.checked and self.reachable(owner, path, number)) continue;
            if (!try self.put_tombstone(owner, path, number)) continue;
            const old = node_shape(self.encoding(old_id)) catch return error.HistoryCorrupt;
            switch (old.kind) {
                .leaf => if (owner == null) try self.bury_storage_if_gone(state_trie, path, &old),
                .extension => self.push_bury(owner, path, old.path.slice(), frame.checked),
                .branch => self.push_branch_children(owner, path, old.mask, frame.checked),
            }
        }
    }

    /// Whether the trie of `owner` at block `number` has a node at `path`.
    fn reachable(self: *const Store, owner: ?Hash, path: []const u8, number: u64) bool {
        var id = self.lookup(owner, &.{}, number) orelse return false;
        var consumed: u32 = 0;
        var depth: u32 = 0;
        while (depth <= path_nibbles_max + 1) : (depth += 1) {
            if (consumed == path.len) return true;
            const step = step_node(self.encoding(id), path[consumed..]) catch return false;
            switch (step) {
                .found, .absent => return false,
                .next => |next| {
                    consumed += next.consumed;
                    assert(consumed <= path.len);
                    id = self.lookup(owner, path[0..consumed], number) orelse return false;
                },
            }
        }
        return false;
    }

    /// The state root of block `number`.
    pub fn state_root_at(self: *const Store, number: u64) Error!Hash {
        const current = self.window() orelse return error.NotInitialized;
        if (number < current.oldest or number > current.head) return error.BlockOutOfWindow;
        const entry = self.block_at(@intCast(number - current.oldest));
        assert(entry.number == number);
        return entry.state_root;
    }

    /// `eth_getProof(address, slots, number)`: fills the account proof, one storage proof and
    /// value per slot, and returns the account (null when absent at `number`). Proofs have the
    /// format of `StateTrie.prove_account`/`prove_storage` on the state of block `number`.
    pub fn get_proof(
        self: *const Store,
        number: u64,
        address: Address,
        slots: []const u256,
        account_proof: *StateTrie.AccountProof,
        storage_proofs: []StateTrie.StorageProof,
        values: []u256,
    ) Error!?AccountState {
        assert(slots.len == storage_proofs.len and slots.len == values.len);
        const account = try self.prove_account(number, address, account_proof);
        const storage_root = if (account) |found| found.storage_root else trie.empty_root;
        const address_hash = trie.node.keccak256(&address);
        for (slots, storage_proofs, values) |slot, *proof, *value| {
            value.* = try self.prove_storage(number, address_hash, storage_root, slot, proof);
        }
        return account;
    }

    /// The account proof at block `number`; returns the account or null when absent.
    pub fn prove_account(
        self: *const Store,
        number: u64,
        address: Address,
        proof: *StateTrie.AccountProof,
    ) Error!?AccountState {
        const root = try self.state_root_at(number);
        const address_hash = trie.node.keccak256(&address);
        const value = try self.prove_path(null, root, &address_hash, number, proof) orelse
            return null;
        return decode_account(value) catch return error.HistoryCorrupt;
    }

    /// The storage proof of `slot` at block `number` in the storage trie of `address_hash`,
    /// whose root at that block is `storage_root` (from the account); returns the value.
    pub fn prove_storage(
        self: *const Store,
        number: u64,
        address_hash: Hash,
        storage_root: Hash,
        slot: u256,
        proof: *StateTrie.StorageProof,
    ) Error!u256 {
        _ = try self.state_root_at(number);
        var slot_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_bytes, slot, .big);
        const slot_hash = trie.node.keccak256(&slot_bytes);
        const owner: ?Hash = address_hash;
        const value = try self.prove_path(owner, storage_root, &slot_hash, number, proof) orelse
            return 0;
        return decode_storage_value(value) catch return error.HistoryCorrupt;
    }

    /// Walks the trie of `owner` at block `number` from `root` along `key`, appending every
    /// hashed node (and the root) to `proof`, like `TrieType.prove_in`. Returns the leaf value
    /// (pointing into the store) or null for an exclusion proof.
    fn prove_path(
        self: *const Store,
        owner: ?Hash,
        root: Hash,
        key: *const Hash,
        number: u64,
        proof: anytype,
    ) Error!?[]const u8 {
        proof.count = 0;
        const sink: ProofSink(@TypeOf(proof)) = .{ .proof = proof };
        return self.walk_path(owner, root, key, number, sink);
    }

    /// Walks the trie of `owner` at block `number` from `root` along `key`, calling
    /// `sink.visit(bytes)` for the root and every node referenced by hash (the nodes of an
    /// `eth_getProof` proof). Returns the leaf value or null when `key` is absent.
    fn walk_path(
        self: *const Store,
        owner: ?Hash,
        root: Hash,
        key: *const Hash,
        number: u64,
        sink: anytype,
    ) !?[]const u8 {
        if (std.mem.eql(u8, &root, &trie.empty_root)) return null;
        const path = trie.Nibbles.from_bytes(key);
        const nibbles = path.slice();
        assert(nibbles.len == path_nibbles_max);
        var consumed: u32 = 0;
        var reference: Reference = .{ .hash = root };
        var depth: u32 = 0;
        while (depth <= path_nibbles_max + 1) : (depth += 1) {
            const bytes = try self.checked_node(owner, nibbles[0..consumed], number, reference);
            if (depth == 0 or bytes.len >= 32) try sink.visit(bytes);
            const step = step_node(bytes, nibbles[consumed..]) catch return error.HistoryCorrupt;
            switch (step) {
                .found => |value| return value,
                .absent => return null,
                .next => |next| {
                    consumed += next.consumed;
                    assert(consumed <= path_nibbles_max);
                    reference = next.reference;
                },
            }
        }
        return error.HistoryCorrupt;
    }

    /// Like `TrieType.visit_siblings_in` on the trie of block `number`: calls
    /// `sink.visit(bytes)` for every child referenced by hash, off `key`'s path, of each
    /// branch on `key`'s path (a delete of `key` may collapse such a branch into it).
    fn walk_siblings(
        self: *const Store,
        owner: ?Hash,
        root: Hash,
        key: *const Hash,
        number: u64,
        sink: anytype,
    ) !void {
        if (std.mem.eql(u8, &root, &trie.empty_root)) return;
        const path = trie.Nibbles.from_bytes(key);
        const nibbles = path.slice();
        assert(nibbles.len == path_nibbles_max);
        var consumed: u32 = 0;
        var reference: Reference = .{ .hash = root };
        var depth: u32 = 0;
        while (depth <= path_nibbles_max + 1) : (depth += 1) {
            const bytes = try self.checked_node(owner, nibbles[0..consumed], number, reference);
            if (consumed < path_nibbles_max) {
                const walked = nibbles[0 .. consumed + 1];
                try self.visit_hashed_children(owner, walked, number, bytes, sink);
            }
            const step = step_node(bytes, nibbles[consumed..]) catch return error.HistoryCorrupt;
            switch (step) {
                .found, .absent => return,
                .next => |next| {
                    consumed += next.consumed;
                    assert(consumed <= path_nibbles_max);
                    reference = next.reference;
                },
            }
        }
        return error.HistoryCorrupt;
    }

    /// If `bytes` is a branch, visits its hashed children except the one at `path`'s last
    /// nibble (the walked one); `path` is the branch path plus that nibble.
    fn visit_hashed_children(
        self: *const Store,
        owner: ?Hash,
        path: []const u8,
        number: u64,
        bytes: []const u8,
        sink: anytype,
    ) !void {
        assert(path.len > 0 and path.len <= path_nibbles_max);
        const outer = rlp.decode_item(bytes) catch return error.HistoryCorrupt;
        if (outer.kind != .list) return error.HistoryCorrupt;
        var items: [17]rlp.Item = undefined;
        const count = rlp.decode_list(outer.payload, &items) catch return error.HistoryCorrupt;
        if (count != 17) return;
        var child_path: [path_nibbles_max]u8 = undefined;
        @memcpy(child_path[0..path.len], path);
        const walked = path[path.len - 1];
        for (items[0..16], 0..) |item, nibble| {
            if (nibble == walked) continue;
            const reference = child_reference(item) catch return error.HistoryCorrupt;
            const child = reference orelse continue;
            if (child != .hash) continue;
            child_path[path.len - 1] = @intCast(nibble);
            const child_path_slice = child_path[0..path.len];
            const child_bytes = try self.checked_node(owner, child_path_slice, number, child);
            assert(child_bytes.len >= 32);
            try sink.visit(child_bytes);
        }
    }

    /// The node of the trie of `owner` at `path` at block `number`, checked against the
    /// parent's `reference` (hash or inline bytes).
    fn checked_node(
        self: *const Store,
        owner: ?Hash,
        path: []const u8,
        number: u64,
        reference: Reference,
    ) Error![]const u8 {
        const id = self.lookup(owner, path, number) orelse return error.HistoryCorrupt;
        const bytes = self.encoding(id);
        assert(bytes.len > 0);
        const matches = switch (reference) {
            .hash => |hash| std.mem.eql(u8, &trie.node.keccak256(bytes), &hash),
            .embedded => |inline_bytes| std.mem.eql(u8, inline_bytes, bytes),
        };
        if (!matches) return error.HistoryCorrupt;
        return bytes;
    }

    /// The account of `address_hash` at block `number` (null when absent), without a proof.
    pub fn account_at(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
    ) Error!?AccountState {
        const root = try self.state_root_at(number);
        const value = try self.walk_path(null, root, address_hash, number, NullSink{}) orelse
            return null;
        return decode_account(value) catch return error.HistoryCorrupt;
    }

    /// The value of `slot_hash` at block `number` in the storage trie of `address_hash`,
    /// whose root at that block is `storage_root`; 0 when absent.
    pub fn storage_at(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
        storage_root: Hash,
        slot_hash: *const Hash,
    ) Error!u256 {
        _ = try self.state_root_at(number);
        const owner: ?Hash = address_hash.*;
        const value = try self.walk_path(owner, storage_root, slot_hash, number, NullSink{}) orelse
            return 0;
        return decode_storage_value(value) catch return error.HistoryCorrupt;
    }

    /// Visits the nodes of the account proof of `address_hash` at block `number`
    /// (`StateTrie.prove_account` order).
    pub fn visit_account_proof(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
        sink: anytype,
    ) !void {
        const root = try self.state_root_at(number);
        _ = try self.walk_path(null, root, address_hash, number, sink);
    }

    /// Visits the nodes of the storage proof of `slot_hash` at block `number`; nothing when
    /// the account is absent or has no storage (as `StateTrie.prove_storage`).
    pub fn visit_storage_proof(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
        slot_hash: *const Hash,
        sink: anytype,
    ) !void {
        const account = try self.account_at(number, address_hash) orelse return;
        const owner: ?Hash = address_hash.*;
        _ = try self.walk_path(owner, account.storage_root, slot_hash, number, sink);
    }

    /// Visits the hashed siblings along `address_hash`'s path in the account trie at
    /// block `number` (`StateTrie.visit_account_siblings`).
    pub fn visit_account_siblings(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
        sink: anytype,
    ) !void {
        const root = try self.state_root_at(number);
        try self.walk_siblings(null, root, address_hash, number, sink);
    }

    /// Visits the hashed siblings along `slot_hash`'s path in the account's storage trie at
    /// block `number` (`StateTrie.visit_storage_siblings`).
    pub fn visit_storage_siblings(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
        slot_hash: *const Hash,
        sink: anytype,
    ) !void {
        const account = try self.account_at(number, address_hash) orelse return;
        const owner: ?Hash = address_hash.*;
        try self.walk_siblings(owner, account.storage_root, slot_hash, number, sink);
    }
};

fn append_node(proof: anytype, bytes: []const u8) void {
    assert(proof.count < proof.ends.len);
    const start = if (proof.count == 0) 0 else proof.ends[proof.count - 1];
    assert(start + bytes.len <= proof.buffer.len);
    @memcpy(proof.buffer[start..][0..bytes.len], bytes);
    proof.ends[proof.count] = start + @as(u32, @intCast(bytes.len));
    proof.count += 1;
}

/// Appends walked proof nodes to a `TrieType.Proof`.
fn ProofSink(comptime ProofPointer: type) type {
    return struct {
        proof: ProofPointer,

        pub fn visit(self: @This(), bytes: []const u8) error{}!void {
            append_node(self.proof, bytes);
        }
    };
}

/// Ignores walked nodes (value lookups).
const NullSink = struct {
    pub fn visit(_: NullSink, _: []const u8) error{}!void {}
};

const Reference = union(enum) {
    hash: Hash,
    embedded: []const u8,
};

pub const StepError = error{InvalidNode} || rlp.DecodeError;

pub const Step = union(enum) {
    found: []const u8,
    absent,
    next: struct { consumed: u32, reference: Reference },
};

/// Decodes one node and returns where the walk along `rest` goes next.
pub fn step_node(bytes: []const u8, rest: []const u8) StepError!Step {
    const outer = try rlp.decode_item(bytes);
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string) return error.InvalidNode;
        if (rest.len == 0) {
            if (items[16].payload.len == 0) return .absent;
            return .{ .found = items[16].payload };
        }
        const reference = try child_reference(items[rest[0]]) orelse return .absent;
        return .{ .next = .{ .consumed = 1, .reference = reference } };
    }
    if (count != 2 or items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch {
        return error.InvalidNode;
    };
    const node_path = decoded.path.slice();
    if (decoded.leaf) {
        if (items[1].kind != .string or items[1].payload.len == 0) return error.InvalidNode;
        if (!std.mem.eql(u8, node_path, rest)) return .absent;
        return .{ .found = items[1].payload };
    }
    if (node_path.len == 0) return error.InvalidNode;
    if (!std.mem.startsWith(u8, rest, node_path)) return .absent;
    const reference = try child_reference(items[1]) orelse return error.InvalidNode;
    return .{ .next = .{ .consumed = @intCast(node_path.len), .reference = reference } };
}

fn child_reference(item: rlp.Item) StepError!?Reference {
    switch (item.kind) {
        .string => {
            if (item.payload.len == 0) return null;
            if (item.payload.len != 32) return error.InvalidNode;
            return .{ .hash = item.payload[0..32].* };
        },
        .list => {
            if (item.raw.len >= 32) return error.InvalidNode;
            return .{ .embedded = item.raw };
        },
    }
}

pub const ValueError = error{InvalidValue} || rlp.DecodeError;

fn decode_integer(comptime T: type, item: rlp.Item) ValueError!T {
    if (item.kind != .string) return error.InvalidValue;
    if (item.payload.len > @sizeOf(T)) return error.InvalidValue;
    if (item.payload.len > 0 and item.payload[0] == 0) return error.InvalidValue;
    var result: T = 0;
    for (item.payload) |byte| result = (result << 8) | byte;
    return result;
}

fn decode_hash(item: rlp.Item) ValueError!Hash {
    if (item.kind != .string or item.payload.len != 32) return error.InvalidValue;
    return item.payload[0..32].*;
}

/// Decodes an account leaf value `rlp([nonce, balance, storage_root, code_hash])`.
pub fn decode_account(value: []const u8) ValueError!AccountState {
    const outer = try rlp.decode_item(value);
    if (outer.kind != .list or outer.encoded_length != value.len) return error.InvalidValue;
    var items: [4]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidValue;
    if (count != 4) return error.InvalidValue;
    return .{
        .nonce = try decode_integer(u64, items[0]),
        .balance = try decode_integer(u256, items[1]),
        .storage_root = try decode_hash(items[2]),
        .code_hash = try decode_hash(items[3]),
    };
}

/// Decodes a storage leaf value `rlp(value)`; stored values are never zero.
pub fn decode_storage_value(value: []const u8) ValueError!u256 {
    const item = try rlp.decode_item(value);
    if (item.encoded_length != value.len) return error.InvalidValue;
    const result = try decode_integer(u256, item);
    if (result == 0) return error.InvalidValue;
    return result;
}

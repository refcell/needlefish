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
//! The store is in memory only and is not journaled: after a restart the durable database
//! rebuilds it (`reset` at the oldest block it can unwind to, then `commit_block` for each
//! retained block up to the recovered head).

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const changeset_module = @import("changeset.zig");
const lazy_alloc = @import("../../utilities/lazy_alloc/root.zig");
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
    /// Byte budget of retained history (`Store.bytes_used`); null = only the capacities
    /// above bound it. A commit that leaves the store above the budget prunes the oldest
    /// blocks until it fits, so the effective window shrinks below `window_blocks` instead
    /// of history being dropped (see "Byte budget" on `Store`).
    bytes_max: ?u64 = null,
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

/// Bytes one occupied slot holds, as `Store.bytes_used` counts them: a version record, its
/// encoding slot, and its free-stack entry; a path record, its free-stack entry, and its
/// `path_index` entry (key, value, one metadata byte; the index's load-factor slack is
/// static capacity, not counted).
pub const small_version_bytes: u64 = @sizeOf(Version) + small_bytes + @sizeOf(u32);
pub const large_version_bytes: u64 = @sizeOf(Version) + large_bytes + @sizeOf(u32);
pub const path_bytes: u64 = @sizeOf(Path) + @sizeOf(u32) + @sizeOf(Key) + @sizeOf(u32) + 1;

comptime {
    assert(small_version_bytes < large_version_bytes);
    assert(path_bytes > @sizeOf(Key));
}

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
    /// `Store.bytes_used`: what `Config.bytes_max` bounds.
    bytes: u64,
};

/// Version slots of one size class: slots are handed out from a never-used tail (`fresh`)
/// and recycled through a LIFO free stack, so only slots ever used are touched. The arrays
/// are lazily committed (`lazy_alloc`): resident memory follows the peak occupancy, not the
/// capacity, which lets `Config.bytes_max` bound memory below the configured capacity.
fn Pool(comptime bytes: u32) type {
    return struct {
        const Self = @This();
        versions: []Version,
        data: [][bytes]u8,
        free: []u32,
        free_len: u32,
        /// Slots `[fresh, len)` were never handed out since the last `clear`.
        fresh: u32,

        fn init(allocator: std.mem.Allocator, count: u32) !Self {
            const versions = try lazy_alloc.alloc(allocator, Version, count);
            errdefer lazy_alloc.free(allocator, versions);
            const data = try lazy_alloc.alloc(allocator, [bytes]u8, count);
            errdefer lazy_alloc.free(allocator, data);
            const free = try lazy_alloc.alloc(allocator, u32, count);
            var self: Self = .{
                .versions = versions,
                .data = data,
                .free = free,
                .free_len = 0,
                .fresh = 0,
            };
            self.clear();
            return self;
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            lazy_alloc.free(allocator, self.free);
            lazy_alloc.free(allocator, self.data);
            lazy_alloc.free(allocator, self.versions);
            self.* = undefined;
        }

        fn clear(self: *Self) void {
            self.free_len = 0;
            self.fresh = 0;
        }

        /// Slots `take` can still hand out.
        fn available(self: *const Self) u32 {
            assert(self.fresh <= self.versions.len);
            return self.free_len + (@as(u32, @intCast(self.versions.len)) - self.fresh);
        }

        fn take(self: *Self) u32 {
            assert(self.available() > 0);
            if (self.free_len > 0) {
                self.free_len -= 1;
                const index = self.free[self.free_len];
                assert(index < self.fresh);
                return index;
            }
            const index = self.fresh;
            self.fresh += 1;
            assert(index < self.versions.len);
            return index;
        }

        fn give(self: *Self, index: u32) void {
            assert(index < self.fresh);
            assert(self.free_len < self.fresh);
            self.free[self.free_len] = index;
            self.free_len += 1;
        }

        fn used(self: *const Self) u32 {
            assert(self.free_len <= self.fresh);
            return self.fresh - self.free_len;
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
///
/// Byte budget: `Config.bytes_max` bounds `bytes_used` (occupied paths and versions at their
/// `*_bytes` unit sizes). The arrays are lazily committed and slots are recycled LIFO, so
/// resident memory follows peak occupancy; size the capacities above the budget (plus one
/// block of B) and the budget binds first. A commit that ends above the budget prunes the
/// oldest blocks (`fit_budget`): the effective window (`window`) shrinks, proofs at blocks
/// that left it return `BlockOutOfWindow`, and history is only dropped when the head state
/// alone is above the budget.
pub const Store = struct {
    config: Config,
    path_index: std.AutoHashMapUnmanaged(Key, u32),
    paths: []Path,
    path_free: []u32,
    path_free_len: u32,
    /// Path slots `[paths_fresh, paths_max)` were never used since the last `clear` (as
    /// `Pool.fresh`: only used slots are touched, the arrays are lazily committed).
    paths_fresh: u32,
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
    /// Blocks that left the window early to fit `Config.bytes_max` (since `init`).
    window_shrinks: u64,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Store {
        assert(config.window_blocks > 0);
        assert(config.small_versions_max < large_bit and config.large_versions_max < large_bit);
        var path_index: std.AutoHashMapUnmanaged(Key, u32) = .empty;
        try path_index.ensureTotalCapacity(allocator, config.paths_max);
        errdefer path_index.deinit(allocator);
        const paths = try lazy_alloc.alloc(allocator, Path, config.paths_max);
        errdefer lazy_alloc.free(allocator, paths);
        const path_free = try lazy_alloc.alloc(allocator, u32, config.paths_max);
        errdefer lazy_alloc.free(allocator, path_free);
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
            .paths_fresh = 0,
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
            .window_shrinks = 0,
        };
        self.clear();
        return self;
    }

    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        allocator.free(self.bury_stack);
        allocator.free(self.blocks);
        self.large.deinit(allocator);
        self.small.deinit(allocator);
        lazy_alloc.free(allocator, self.path_free);
        lazy_alloc.free(allocator, self.paths);
        self.path_index.deinit(allocator);
        self.* = undefined;
    }

    fn clear(self: *Store) void {
        self.path_index.clearRetainingCapacity();
        self.path_free_len = 0;
        self.paths_fresh = 0;
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

    /// Bytes held by occupied paths and versions (see `small_version_bytes`).
    pub fn bytes_used(self: *const Store) u64 {
        const paths: u64 = self.paths_fresh - self.path_free_len;
        const bytes = paths * path_bytes + @as(u64, self.small.used()) * small_version_bytes +
            @as(u64, self.large.used()) * large_version_bytes;
        assert(bytes <= self.bytes_capacity());
        return bytes;
    }

    /// `bytes_used` with every slot occupied.
    pub fn bytes_capacity(self: *const Store) u64 {
        return self.paths.len * path_bytes + self.small.versions.len * small_version_bytes +
            self.large.versions.len * large_version_bytes;
    }

    pub fn usage(self: *const Store) Usage {
        assert(self.path_free_len <= self.paths_fresh);
        return .{
            .paths = self.paths_fresh - self.path_free_len,
            .small_versions = self.small.used(),
            .large_versions = self.large.used(),
            .prune_queue = self.prune_count,
            .bytes = self.bytes_used(),
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

    fn paths_available(self: *const Store) u32 {
        assert(self.paths_fresh <= self.paths.len);
        return self.path_free_len + (@as(u32, @intCast(self.paths.len)) - self.paths_fresh);
    }

    fn new_path(self: *Store, key: *const Key) u32 {
        assert(self.paths_available() > 0);
        var id: u32 = undefined;
        if (self.path_free_len > 0) {
            self.path_free_len -= 1;
            id = self.path_free[self.path_free_len];
            assert(id < self.paths_fresh);
        } else {
            id = self.paths_fresh;
            self.paths_fresh += 1;
        }
        self.paths[id] = .{ .key = key.*, .head = none };
        self.path_index.putAssumeCapacityNoClobber(key.*, id);
        return id;
    }

    fn free_path(self: *Store, id: u32) void {
        assert(self.paths[id].head == none);
        assert(self.path_free_len < self.paths_fresh);
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
        // One state alone above the budget: nothing to shrink, no history.
        if (self.over_budget()) {
            self.blocks_len = 0;
            return error.HistoryFull;
        }
        assert(self.window().?.head == number);
    }

    fn over_budget(self: *const Store) bool {
        const bytes_max = self.config.bytes_max orelse return false;
        return self.bytes_used() > bytes_max;
    }

    /// Records block `number` (`head + 1`) from the nodes `state_trie` rehashed since the
    /// previous `commit_block`, `reset`, or `unwind_to`, then moves the oldest block forward
    /// once the window is full, then fits the byte budget (`fit_budget`). Atomic when the
    /// block does not fit the capacities (`HistoryFull`): the store keeps its window and the
    /// trie keeps its change marks, so the call can be retried. A budget the head block's
    /// state alone exceeds also returns `HistoryFull`, after the block is written and the
    /// window shrank to that one block (callers drop history then, see `fit_budget`).
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
        try self.fit_budget();
        assert(self.window().?.head == number);
    }

    /// Byte budget: while the store is above `Config.bytes_max`, drains the prune queue
    /// (garbage first), then moves the oldest block forward one at a time and prunes what it
    /// shadowed. The window stays contiguous and ends at the head; it grows back by one block
    /// per commit while there is room. `HistoryFull` when even the head block alone (its
    /// state's nodes) is above the budget. Bounded: one drain plus one shrink per block.
    fn fit_budget(self: *Store) error{HistoryFull}!void {
        if (!self.over_budget()) return;
        var steps: u32 = 0;
        while (self.over_budget()) : (steps += 1) {
            assert(steps <= 2 * self.config.window_blocks + 1);
            if (self.prune_count > 0) {
                _ = self.prune_step(self.prune_count);
                assert(self.prune_count == 0);
                continue;
            }
            if (self.blocks_len == 1) return error.HistoryFull;
            self.advance_oldest();
            self.window_shrinks += 1;
        }
        assert(self.blocks_len >= 1 and !self.over_budget());
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
    /// Runs when the window overflows by one block, or earlier to fit the byte budget.
    fn advance_oldest(self: *Store) void {
        assert(self.blocks_len > 1 and self.blocks_len <= self.config.window_blocks + 1);
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
        if (needed.path_id == null and self.paths_available() == 0) return error.HistoryFull;
        if (length <= small_bytes and self.small.available() == 0) return error.HistoryFull;
        if (length > small_bytes and self.large.available() == 0) return error.HistoryFull;
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
        if (self.small.available() == 0) return error.HistoryFull;
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

    /// The account trie nodes at block `number` of many keys in one walk
    /// (`StateTrie.visit_account_paths`).
    pub fn visit_account_paths(
        self: *const Store,
        number: u64,
        targets: []const trie.PathTarget,
        sink: anytype,
    ) !void {
        const root = try self.state_root_at(number);
        try self.walk_paths(null, root, targets, number, sink);
    }

    /// The storage trie nodes at block `number` of many slots of one account in one walk;
    /// nothing when the account is absent (`StateTrie.visit_storage_paths`).
    pub fn visit_storage_paths(
        self: *const Store,
        number: u64,
        address_hash: *const Hash,
        targets: []const trie.PathTarget,
        sink: anytype,
    ) !void {
        const account = try self.account_at(number, address_hash) orelse return;
        const owner: ?Hash = address_hash.*;
        try self.walk_paths(owner, account.storage_root, targets, number, sink);
    }

    /// `TrieType.visit_paths_in` on the trie of `owner` at block `number`: one depth-first
    /// walk visiting each proof node of every target (and siblings of `siblings` targets)
    /// once, as `sink.visit(hash, bytes, marked)`. Hashes are the parents' references, which
    /// `checked_node` verified.
    fn walk_paths(
        self: *const Store,
        owner: ?Hash,
        root: Hash,
        targets: []const trie.PathTarget,
        number: u64,
        sink: anytype,
    ) !void {
        assert(trie.path_targets.sorted(targets));
        if (std.mem.eql(u8, &root, &trie.empty_root) or targets.len == 0) return;
        var stack: [trie.path_targets.stack_frames_max]PathFrame = undefined;
        const end: u32 = @intCast(targets.len);
        stack[0] = .{ .reference = .{ .hash = root }, .start = 0, .end = end, .consumed = 0 };
        var stack_len: u32 = 1;
        var visited: u64 = 0;
        while (stack_len > 0) : (visited += 1) {
            // At most one frame per path node of each target.
            assert(visited <= targets.len * (path_nibbles_max + 1));
            stack_len -= 1;
            const frame = stack[stack_len];
            const range = targets[frame.start..frame.end];
            assert(range.len > 0 and frame.consumed <= path_nibbles_max);
            const prefix = trie.Nibbles.from_bytes(&range[0].path);
            const path = prefix.slice()[0..frame.consumed];
            const bytes = try self.checked_node(owner, path, number, frame.reference);
            if (frame.consumed == 0 or bytes.len >= 32) {
                assert(frame.reference == .hash);
                const marked = trie.path_targets.any_mark(range);
                try sink.visit(&frame.reference.hash, bytes, marked);
            }
            const view = node_view(bytes) catch return error.HistoryCorrupt;
            const off_path = view == .branch and frame.consumed < path_nibbles_max and
                trie.path_targets.any_siblings(range);
            if (off_path) try self.visit_off_path(owner, number, &view.branch, frame, range, sink);
            stack_len = push_children(&view, frame, targets, &stack, stack_len);
        }
    }

    /// Pushes the frames of `view`'s children that targets enter (branch children last
    /// nibble first, so they pop in nibble order). Returns the new stack length.
    fn push_children(
        view: *const NodeView,
        frame: PathFrame,
        targets: []const trie.PathTarget,
        stack: *[trie.path_targets.stack_frames_max]PathFrame,
        stack_len: u32,
    ) u32 {
        switch (view.*) {
            .leaf => return stack_len,
            .extension => |*extension| {
                const path = &extension.path;
                var start = frame.start;
                while (start < frame.end and
                    !extends(&targets[start], frame.consumed, path)) start += 1;
                var end = start;
                while (end < frame.end and extends(&targets[end], frame.consumed, path)) end += 1;
                if (start == end) return stack_len;
                assert(stack_len < stack.len);
                const length: u32 = @intCast(path.slice().len);
                stack[stack_len] = .{
                    .reference = extension.child,
                    .start = start,
                    .end = end,
                    .consumed = frame.consumed + length,
                };
                return stack_len + 1;
            },
            .branch => |*children| {
                if (frame.consumed == path_nibbles_max) return stack_len;
                const range = targets[frame.start..frame.end];
                var length = stack_len;
                var end: u32 = @intCast(range.len);
                while (end > 0) {
                    const start = trie.path_targets.group_start(range, end, frame.consumed);
                    const nibble = trie.path_targets.nibble(&range[start], frame.consumed);
                    if (children[nibble]) |child| {
                        assert(length < stack.len);
                        stack[length] = .{
                            .reference = child,
                            .start = frame.start + start,
                            .end = frame.start + end,
                            .consumed = frame.consumed + 1,
                        };
                        length += 1;
                    }
                    end = start;
                }
                assert(length <= stack_len + 16);
                return length;
            },
        }
    }

    /// Visits the hashed children of a branch that no target of `range` takes.
    fn visit_off_path(
        self: *const Store,
        owner: ?Hash,
        number: u64,
        children: *const [16]?Reference,
        frame: PathFrame,
        range: []const trie.PathTarget,
        sink: anytype,
    ) !void {
        assert(frame.consumed < path_nibbles_max);
        const taken = trie.path_targets.taken_mask(range, frame.consumed);
        const prefix = trie.Nibbles.from_bytes(&range[0].path);
        var child_path: [path_nibbles_max]u8 = undefined;
        @memcpy(child_path[0..frame.consumed], prefix.slice()[0..frame.consumed]);
        for (children, 0..) |reference, nibble| {
            if (taken & (@as(u16, 1) << @intCast(nibble)) != 0) continue;
            const child = reference orelse continue;
            if (child != .hash) continue;
            child_path[frame.consumed] = @intCast(nibble);
            const path = child_path[0 .. frame.consumed + 1];
            const bytes = try self.checked_node(owner, path, number, child);
            assert(bytes.len >= 32);
            try sink.visit(&child.hash, bytes, false);
        }
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

/// A node of `Store.walk_paths` (by its parent's reference) and the targets entering it.
const PathFrame = struct { reference: Reference, start: u32, end: u32, consumed: u32 };

/// The children of one decoded trie node (`Store.walk_paths`).
const NodeView = union(enum) {
    leaf,
    extension: struct { path: trie.Nibbles, child: Reference },
    branch: [16]?Reference,
};

/// Decodes a node strictly enough to walk it (`step_node`'s rules, all children at once).
fn node_view(bytes: []const u8) StepError!NodeView {
    const outer = try rlp.decode_item(bytes);
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string) return error.InvalidNode;
        var children: [16]?Reference = undefined;
        for (items[0..16], &children) |item, *child| child.* = try child_reference(item);
        return .{ .branch = children };
    }
    if (count != 2 or items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch {
        return error.InvalidNode;
    };
    if (decoded.leaf) {
        if (items[1].kind != .string or items[1].payload.len == 0) return error.InvalidNode;
        return .leaf;
    }
    if (decoded.path.slice().len == 0) return error.InvalidNode;
    const child = try child_reference(items[1]) orelse return error.InvalidNode;
    return .{ .extension = .{ .path = decoded.path, .child = child } };
}

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

/// Whether `target`'s path continues with `path` after its first `consumed` nibbles.
fn extends(target: *const trie.PathTarget, consumed: u32, path: *const trie.Nibbles) bool {
    const nibbles = path.slice();
    if (consumed + nibbles.len > path_nibbles_max) return false;
    for (nibbles, 0..) |value, offset| {
        const at: u32 = consumed + @as(u32, @intCast(offset));
        if (trie.path_targets.nibble(target, at) != value) return false;
    }
    return true;
}

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

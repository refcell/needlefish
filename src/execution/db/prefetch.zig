//! Prefetch: reads the table blocks a set of upcoming point reads will need, many at once,
//! into the flat trees' block cache, so the synchronous reads that follow (`Tree.get`, one
//! blocking grid read per missed block) find them there.
//!
//! The owner names keys (`add_*`: account records, slots, branch records), then `start`s and
//! ticks its storage until `running` is false. Each round walks every key's `get` search over
//! the cached blocks (`Tree.prefetch_need`: the memtables, then the tables, filters first)
//! and collects the first block each search lacks, once per block; those reads go to the grid
//! with up to `reads_max` in flight (asynchronous: io_uring on the OS backend), and every
//! block that verifies (the grid's checksum and header checks, then `Tree.prefetch_store`'s
//! table checks) is cached. The next round starts when the last read of a round lands, so a
//! key moves one block per round (index block, then data block, level by level) until its
//! search ends in cached blocks. At most `rounds_max` rounds. A path key (`add_path`) walks a
//! trie path instead, as a root update over the key resolves it: the record at the root's
//! hang, then, while the record found has the key's next child as a record (`tree_mask`,
//! past any extension the key matches), that child's record; so it names only records that
//! exist on the path.
//!
//! Correctness never depends on it: the cache is keyed by block address and checksum, a
//! block is cached only after it verifies, and a later `get` searches exactly as it would
//! have. A wrong, partial, or stale key set, a failed read, or an install that retires a
//! table mid-prefetch only costs reads. Reads target blocks the manifest named when the round
//! walked it; such a block is reused only after two more checkpoints are durable
//! (`free_set.zig`), so no prefetch read can overlap its rewrite while the owner holds
//! checkpoints (`Database.hold_checkpoints`), as the runner does.
//!
//! Static memory: `keys_max` keys, the round's needs (at most one per key) and their
//! dedupe set, and `reads_max` grid reads with one block buffer each.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage/storage.zig");
const grid_module = @import("storage/grid.zig");
const branch_record = @import("branch_record.zig");

const Hash = [32]u8;

/// Rounds one `start` runs at most: a key's search reads two blocks (index, data) per
/// table, and a lookup visits at most four level-0 tables and eight levels; a path key's
/// records, one hang at a time, are mostly in the last level.
pub const rounds_max: u32 = 2 * (4 + 8);

/// The deepest hang a path key walks to (a trie of 16^16 random keys is shallower).
pub const path_depth_max: u8 = 16;

pub const Config = struct {
    keys_max: u32,
    reads_max: u32,
};

pub const Stats = struct {
    /// `start` calls, rounds, keys named, and keys a round dropped (the set was full).
    runs: u64 = 0,
    rounds: u64 = 0,
    keys: u64 = 0,
    keys_dropped: u64 = 0,
    /// Blocks read and cached, reads that failed to verify, and the sum and peak of the
    /// reads in flight at each submission (sum / reads: the mean depth).
    reads: u64 = 0,
    failed: u64 = 0,
    depth_sum: u64 = 0,
    depth_max: u32 = 0,
};

/// Which tree a key belongs to.
pub const TreeName = enum(u8) { accounts, storage, account_branches, storage_branches };

const key_bytes_max = branch_record.storage_key_bytes;

const Key = struct {
    tree: TreeName,
    /// The search ended in cached blocks (this start).
    done: bool = false,
    /// A path key: `bytes` holds the owner (storage trie) then the key hash, and `depth` is
    /// the hang length the walk is at.
    path: bool = false,
    depth: u8 = 0,
    bytes: [key_bytes_max]u8,
};

const Step = union(enum) { absent, found: []const u8, missing: Need };

/// A table block a search lacks (the trees' `Need`s are all this shape).
const Need = struct {
    reference: grid_module.Reference,
    kind: grid_module.BlockKind,
};

pub fn PrefetchType(comptime FlatTrees: type) type {
    return struct {
        const Self = @This();
        const Grid = FlatTrees.Grid;

        const Pending = struct { tree: TreeName, need: Need };

        /// One read in flight: `read` must not move (the grid points at it).
        const Slot = struct {
            read: Grid.Read = .{},
            owner: *Self = undefined,
            pending: Pending = undefined,
            buffer: []align(storage.sector_size) u8 = &.{},
        };

        config: Config,
        /// The trees of the running prefetch (set by `start`: the owner may move between).
        trees: ?*FlatTrees = null,
        keys: []Key,
        keys_len: u32 = 0,
        needs: []Pending,
        needs_len: u32 = 0,
        needs_next: u32 = 0,
        seen: std.AutoHashMapUnmanaged(u64, void) = .empty,
        slots: []Slot,
        buffers: []align(storage.sector_size) u8,
        /// Indices of idle slots (a stack).
        free: []u32,
        free_len: u32,
        round: u32 = 0,
        running: bool = false,
        stats: Stats = .{},

        /// Boxed: the grid reads point into it.
        pub fn create(allocator: std.mem.Allocator, config: Config, block_size: u32) !*Self {
            assert(config.keys_max > 0 and config.reads_max > 0);
            assert(block_size % storage.sector_size == 0);
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            const keys = try allocator.alloc(Key, config.keys_max);
            errdefer allocator.free(keys);
            const needs = try allocator.alloc(Pending, config.keys_max);
            errdefer allocator.free(needs);
            var seen: std.AutoHashMapUnmanaged(u64, void) = .empty;
            try seen.ensureTotalCapacity(allocator, config.keys_max);
            errdefer seen.deinit(allocator);
            const slots = try allocator.alloc(Slot, config.reads_max);
            errdefer allocator.free(slots);
            const alignment = comptime std.mem.Alignment.fromByteUnits(storage.sector_size);
            const buffers = try allocator.alignedAlloc(
                u8,
                alignment,
                @as(usize, config.reads_max) * block_size,
            );
            errdefer allocator.free(buffers);
            const free = try allocator.alloc(u32, config.reads_max);
            @memset(buffers, 0);
            for (slots, free, 0..) |*slot, *index, position| {
                slot.* = .{
                    .owner = self,
                    .buffer = @alignCast(buffers[position * block_size ..][0..block_size]),
                };
                index.* = @intCast(position);
            }
            self.* = .{
                .config = config,
                .keys = keys,
                .needs = needs,
                .seen = seen,
                .slots = slots,
                .buffers = buffers,
                .free = free,
                .free_len = config.reads_max,
            };
            return self;
        }

        /// Reads may be in flight only if the storage dropped them (a crash).
        pub fn destroy(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.free);
            allocator.free(self.buffers);
            allocator.free(self.slots);
            self.seen.deinit(allocator);
            allocator.free(self.needs);
            allocator.free(self.keys);
            allocator.destroy(self);
        }

        /// No read in flight.
        pub fn idle(self: *const Self) bool {
            assert(self.free_len <= self.slots.len);
            return self.free_len == self.slots.len;
        }

        /// Forgets the keys of the last prefetch (none may be running).
        pub fn clear(self: *Self) void {
            assert(!self.running);
            assert(self.idle());
            self.keys_len = 0;
        }

        fn add(self: *Self, tree: TreeName, bytes: []const u8) void {
            assert(!self.running);
            assert(bytes.len <= key_bytes_max);
            if (self.keys_len == self.keys.len) {
                self.stats.keys_dropped += 1;
                return;
            }
            const key = &self.keys[self.keys_len];
            key.* = .{ .tree = tree, .bytes = undefined };
            @memcpy(key.bytes[0..bytes.len], bytes);
            self.keys_len += 1;
        }

        /// The account record of `address_hash`.
        pub fn add_account(self: *Self, address_hash: *const Hash) void {
            self.add(.accounts, address_hash);
        }

        /// The slot `slot_hash` of `address_hash`.
        pub fn add_slot(self: *Self, address_hash: *const Hash, slot_hash: *const Hash) void {
            var key: [64]u8 = undefined;
            key[0..32].* = address_hash.*;
            key[32..64].* = slot_hash.*;
            self.add(.storage, &key);
        }

        /// The branch record hanging at `hang` in the account trie (`owner` null) or in
        /// `owner`'s storage trie.
        pub fn add_branch(self: *Self, owner: ?*const Hash, hang: []const u8) void {
            if (owner) |hash| {
                self.add(.storage_branches, &branch_record.storage_key(hash, hang));
            } else {
                self.add(.account_branches, &branch_record.path_key(hang));
            }
        }

        /// The branch records a root update over `key_hash` resolves: those along its path,
        /// in the account trie (`owner` null) or in `owner`'s storage trie (see the file
        /// comment).
        pub fn add_path(self: *Self, owner: ?*const Hash, key_hash: *const Hash) void {
            var bytes: [64]u8 = undefined;
            if (owner) |hash| {
                bytes[0..32].* = hash.*;
                bytes[32..64].* = key_hash.*;
                self.add(.storage_branches, &bytes);
            } else {
                self.add(.account_branches, key_hash);
            }
            if (self.keys_len > 0) self.keys[self.keys_len - 1].path = true;
        }

        /// Starts reading the blocks the named keys need; the owner ticks its storage until
        /// `running` is false. Nothing to read: done at once.
        pub fn start(self: *Self, trees: *FlatTrees) void {
            assert(!self.running);
            assert(self.idle());
            assert(trees.bulk == null);
            self.trees = trees;
            self.running = true;
            self.round = 0;
            self.stats.runs += 1;
            self.stats.keys += self.keys_len;
            for (self.keys[0..self.keys_len]) |*key| {
                key.done = false;
                key.depth = 0;
            }
            self.round_start();
        }

        /// Collects each unfinished key's next missing block (once per block) and reads
        /// them; ends the prefetch when none is missing or the rounds are spent.
        fn round_start(self: *Self) void {
            assert(self.running and self.idle());
            const trees = self.trees.?;
            self.needs_len = 0;
            self.needs_next = 0;
            self.seen.clearRetainingCapacity();
            for (self.keys[0..self.keys_len]) |*key| {
                if (key.done) continue;
                const need = need_of(trees, key) orelse {
                    key.done = true;
                    continue;
                };
                const address = need.reference.address;
                if (self.seen.contains(address)) continue;
                self.seen.putAssumeCapacityNoClobber(address, {});
                self.needs[self.needs_len] = .{ .tree = key.tree, .need = need };
                self.needs_len += 1;
            }
            assert(self.needs_len <= self.keys_len);
            if (self.needs_len == 0 or self.round == rounds_max) {
                self.running = false;
                return;
            }
            self.round += 1;
            self.stats.rounds += 1;
            self.issue();
        }

        /// The first block `key`'s search lacks, or null once it ends in cached blocks. A
        /// path key moves down its path past every record found.
        fn need_of(trees: *FlatTrees, key: *Key) ?Need {
            if (!key.path) {
                return switch (step_of(trees, key.tree, &key.bytes)) {
                    .absent, .found => null,
                    .missing => |need| need,
                };
            }
            // Bounded: each record found moves the walk at least one nibble deeper.
            while (key.depth <= path_depth_max) {
                var bytes: [key_bytes_max]u8 = undefined;
                path_key(key, &bytes);
                switch (step_of(trees, key.tree, &bytes)) {
                    .absent => return null,
                    .found => |value| key.depth = path_next(key, value) orelse return null,
                    .missing => |need| return need,
                }
            }
            assert(key.depth > path_depth_max);
            return null;
        }

        /// The hang depth of the record below `value` (the record at `key`'s current hang)
        /// on `key`'s path, or null if there is none (a leaf child, a diverging extension,
        /// or a record that does not decode: the walk ends).
        fn path_next(key: *const Key, value: []const u8) ?u8 {
            assert(key.path);
            var record: branch_record.Record = undefined;
            branch_record.decode(value, &record) catch return null;
            const branch_depth = @as(u32, key.depth) + record.extension_len;
            if (branch_depth >= path_depth_max) return null;
            const hash = path_hash(key);
            for (record.extension_slice(), key.depth..) |nibble, index| {
                if (nibble_of(hash, @intCast(index)) != nibble) return null;
            }
            const child = nibble_of(hash, branch_depth);
            if (record.tree_mask >> @intCast(child) & 1 == 0) return null;
            assert(branch_depth + 1 <= path_depth_max);
            return @intCast(branch_depth + 1);
        }

        fn path_hash(key: *const Key) *const Hash {
            assert(key.path);
            const offset: u32 = if (key.tree == .storage_branches) 32 else 0;
            return key.bytes[offset..][0..32];
        }

        fn nibble_of(hash: *const Hash, index: u32) u8 {
            assert(index < 64);
            const byte = hash[index / 2];
            return if (index % 2 == 0) byte >> 4 else byte & 0x0f;
        }

        fn step_of(trees: *FlatTrees, name: TreeName, bytes: *const [key_bytes_max]u8) Step {
            return switch (name) {
                inline else => |tree| {
                    const Tree = @FieldType(FlatTrees, @tagName(tree));
                    const key = bytes[0..Tree.key_bytes];
                    return switch (@field(trees, @tagName(tree)).prefetch_step(key)) {
                        .absent => .absent,
                        .found => |value| .{ .found = value },
                        .missing => |need| .{
                            .missing = .{ .reference = need.reference, .kind = need.kind },
                        },
                    };
                },
            };
        }

        /// The branch-record key at path key `key`'s hang.
        fn path_key(key: *const Key, out: *[key_bytes_max]u8) void {
            assert(key.path);
            assert(key.depth <= path_depth_max);
            const storage_trie = key.tree == .storage_branches;
            assert(storage_trie or key.tree == .account_branches);
            const hash = path_hash(key);
            var nibbles: [path_depth_max]u8 = undefined;
            for (nibbles[0..key.depth], 0..) |*nibble, index| {
                nibble.* = nibble_of(hash, @intCast(index));
            }
            const hang = nibbles[0..key.depth];
            if (storage_trie) {
                out[0..branch_record.storage_key_bytes].* =
                    branch_record.storage_key(key.bytes[0..32], hang);
            } else {
                out[0..branch_record.path_key_bytes].* = branch_record.path_key(hang);
            }
        }

        /// Submits the round's next reads while slots are free.
        fn issue(self: *Self) void {
            const grid = self.trees.?.accounts.grid;
            while (self.needs_next < self.needs_len and self.free_len > 0) {
                const pending = self.needs[self.needs_next];
                self.needs_next += 1;
                self.free_len -= 1;
                const slot = &self.slots[self.free[self.free_len]];
                slot.pending = pending;
                const depth: u32 = @intCast(self.slots.len - self.free_len);
                self.stats.depth_sum += depth;
                self.stats.depth_max = @max(self.stats.depth_max, depth);
                grid.read_block(
                    on_read,
                    &slot.read,
                    slot.buffer,
                    pending.need.reference,
                    pending.need.kind,
                );
            }
            assert(self.needs_next <= self.needs_len);
        }

        fn on_read(read: *Grid.Read) void {
            const slot: *Slot = @alignCast(@fieldParentPtr("read", read));
            const self = slot.owner;
            assert(self.running);
            assert(self.free_len < self.slots.len);
            const trees = self.trees.?;
            const stored = if (read.payload) |payload| stored: {
                const length = grid_module.block_header_size + payload.len;
                const block = slot.buffer[0..length];
                const need = slot.pending.need;
                break :stored switch (slot.pending.tree) {
                    inline else => |tree| @field(trees, @tagName(tree))
                        .prefetch_store(need.reference, need.kind, block),
                };
            } else false;
            if (stored) self.stats.reads += 1 else self.stats.failed += 1;
            self.free[self.free_len] = @intCast(slot - self.slots.ptr);
            self.free_len += 1;
            self.issue();
            if (self.idle() and self.needs_next == self.needs_len) self.round_start();
        }
    };
}

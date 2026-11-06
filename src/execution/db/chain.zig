//! Chain store: recent blocks, the canonical chain index, transaction lookup, and reorgs.
//!
//! Block contents are opaque encoded bytes (header, body, receipts, and the block's state
//! changeset), so this store does not depend on the consensus types. Blocks live in a fixed
//! byte ring: inserting past capacity evicts the oldest-inserted blocks, which bounds memory
//! for a node that runs forever. Persistence of older blocks is the storage engine's job.
//!
//! The canonical index maps numbers to hashes in a ring of `canonical_max` entries. Moving the
//! head computes a `ReorgPlan`: the canonical blocks to unwind (newest first) and the new
//! branch to apply (oldest first). The caller unwinds and applies state with the blocks'
//! changesets, then calls `set_head` with the plan.

const std = @import("std");
const assert = std.debug.assert;

pub const Hash = [32]u8;

pub const Config = struct {
    blocks_max: u32,
    bytes_max: u32,
    transactions_max: u32,
    canonical_max: u32,
    /// Deepest reorg (and longest ancestry walk) accepted.
    reorg_depth_max: u32 = 64,
};

pub const Error = error{
    BlockTooLarge,
    UnknownBlock,
    UnknownParent,
    ReorgTooDeep,
    TransactionIndexFull,
};

pub const BlockInput = struct {
    hash: Hash,
    parent_hash: Hash,
    number: u64,
    timestamp: u64,
    header: []const u8,
    body: []const u8,
    receipts: []const u8,
    transaction_hashes: []const Hash,
    changeset: []const u8,
};

pub const BlockMeta = struct {
    hash: Hash,
    parent_hash: Hash,
    number: u64,
    timestamp: u64,
};

pub const BlockView = struct {
    meta: BlockMeta,
    header: []const u8,
    body: []const u8,
    receipts: []const u8,
    changeset: []const u8,
    transaction_count: u32,
};

pub const TransactionLocation = struct { block_hash: Hash, index: u32 };

const Slot = struct {
    meta: BlockMeta,
    offset: u32,
    header_len: u32,
    body_len: u32,
    receipts_len: u32,
    transactions_len: u32,
    changeset_len: u32,

    fn total_len(self: *const Slot) u32 {
        return self.header_len + self.body_len + self.receipts_len +
            self.transactions_len * 32 + self.changeset_len;
    }
};

const CanonicalEntry = struct { number: u64, hash: Hash, valid: bool };

pub const ReorgPlan = struct {
    /// Last block shared by the old and new canonical chains.
    ancestor: BlockMeta,
    /// Old canonical blocks above the ancestor, newest first.
    unwind: []Hash,
    unwind_len: u32 = 0,
    /// New canonical blocks above the ancestor, oldest first, ending at the new head.
    apply: []Hash,
    apply_len: u32 = 0,

    pub fn unwind_hashes(self: *const ReorgPlan) []const Hash {
        return self.unwind[0..self.unwind_len];
    }

    pub fn apply_hashes(self: *const ReorgPlan) []const Hash {
        return self.apply[0..self.apply_len];
    }
};

pub const ChainStore = struct {
    slots: []Slot,
    /// FIFO of slots in insertion order: `slot_head` is the oldest.
    slot_head: u32 = 0,
    slot_count: u32 = 0,
    bytes: []u8,
    by_hash: std.AutoHashMapUnmanaged(Hash, u32),
    transactions: std.AutoHashMapUnmanaged(Hash, TransactionLocation),
    canonical: []CanonicalEntry,
    head_meta: ?BlockMeta = null,
    config: Config,

    pub fn init(allocator: std.mem.Allocator, config: Config) !ChainStore {
        assert(config.blocks_max > 0 and config.bytes_max > 0);
        assert(config.canonical_max >= config.reorg_depth_max);
        const slots = try allocator.alloc(Slot, config.blocks_max);
        errdefer allocator.free(slots);
        const bytes = try allocator.alloc(u8, config.bytes_max);
        errdefer allocator.free(bytes);
        var by_hash: std.AutoHashMapUnmanaged(Hash, u32) = .empty;
        try by_hash.ensureTotalCapacity(allocator, config.blocks_max);
        errdefer by_hash.deinit(allocator);
        var transactions: std.AutoHashMapUnmanaged(Hash, TransactionLocation) = .empty;
        try transactions.ensureTotalCapacity(allocator, config.transactions_max);
        errdefer transactions.deinit(allocator);
        const canonical = try allocator.alloc(CanonicalEntry, config.canonical_max);
        @memset(canonical, .{ .number = 0, .hash = @splat(0), .valid = false });
        return .{
            .slots = slots,
            .bytes = bytes,
            .by_hash = by_hash,
            .transactions = transactions,
            .canonical = canonical,
            .config = config,
        };
    }

    pub fn deinit(self: *ChainStore, allocator: std.mem.Allocator) void {
        allocator.free(self.canonical);
        self.transactions.deinit(allocator);
        self.by_hash.deinit(allocator);
        allocator.free(self.bytes);
        allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn plan_init(allocator: std.mem.Allocator, config: Config) !ReorgPlan {
        const unwind = try allocator.alloc(Hash, config.reorg_depth_max);
        errdefer allocator.free(unwind);
        const apply = try allocator.alloc(Hash, config.reorg_depth_max);
        return .{ .ancestor = undefined, .unwind = unwind, .apply = apply };
    }

    pub fn plan_deinit(allocator: std.mem.Allocator, plan: *ReorgPlan) void {
        allocator.free(plan.apply);
        allocator.free(plan.unwind);
        plan.* = undefined;
    }

    pub fn block_count(self: *const ChainStore) u32 {
        return self.slot_count;
    }

    fn slot_at(self: *const ChainStore, position: u32) u32 {
        assert(position < self.slot_count);
        return (self.slot_head + position) % @as(u32, @intCast(self.slots.len));
    }

    /// Byte offset where the next record of `length` bytes goes, or null if eviction is needed.
    fn next_offset(self: *const ChainStore, length: u32) ?u32 {
        const capacity: u32 = @intCast(self.bytes.len);
        if (self.slot_count == 0) return if (length <= capacity) 0 else null;
        const oldest = &self.slots[self.slot_head];
        const newest = &self.slots[self.slot_at(self.slot_count - 1)];
        const write = newest.offset + newest.total_len();
        const read = oldest.offset;
        if (write > read) {
            if (capacity - write >= length) return write;
            if (read >= length) return 0;
            return null;
        }
        // Records are never empty, so `write == read` means the ring is full.
        if (write < read and read - write >= length) return write;
        return null;
    }

    /// Drops the oldest-inserted block. Callers that need deterministic retention evict
    /// explicitly before `insert` so the ring never evicts on its own.
    pub fn evict_oldest(self: *ChainStore) void {
        assert(self.slot_count > 0);
        const slot = &self.slots[self.slot_head];
        const hashes = self.bytes[slot.offset + slot.header_len + slot.body_len +
            slot.receipts_len ..][0 .. slot.transactions_len * 32];
        for (0..slot.transactions_len) |index| {
            const transaction_hash = hashes[index * 32 ..][0..32].*;
            if (self.transactions.get(transaction_hash)) |location| {
                if (std.mem.eql(u8, &location.block_hash, &slot.meta.hash)) {
                    _ = self.transactions.remove(transaction_hash);
                }
            }
        }
        assert(self.by_hash.remove(slot.meta.hash));
        self.slot_head = (self.slot_head + 1) % @as(u32, @intCast(self.slots.len));
        self.slot_count -= 1;
    }

    fn record_length(input: *const BlockInput) u64 {
        return @as(u64, input.header.len) + input.body.len + input.receipts.len +
            @as(u64, input.transaction_hashes.len) * 32 + input.changeset.len;
    }

    /// Stores a block. A known hash is a no-op. Evicts the oldest blocks to make room.
    pub fn insert(self: *ChainStore, input: *const BlockInput) Error!void {
        if (self.by_hash.contains(input.hash)) return;
        assert(input.header.len > 0);
        const length_wide = record_length(input);
        if (length_wide > self.bytes.len) return error.BlockTooLarge;
        if (input.transaction_hashes.len > self.config.transactions_max) {
            return error.TransactionIndexFull;
        }
        const length: u32 = @intCast(length_wide);
        var evictions: u32 = 0;
        while (self.slot_count == self.slots.len or
            self.next_offset(length) == null or
            self.transactions.count() + input.transaction_hashes.len >
                self.config.transactions_max)
        {
            assert(evictions <= self.slots.len);
            self.evict_oldest();
            evictions += 1;
        }
        const offset = self.next_offset(length).?;
        self.write_record(offset, input);
        const index = (self.slot_head + self.slot_count) % @as(u32, @intCast(self.slots.len));
        self.slots[index] = .{
            .meta = .{
                .hash = input.hash,
                .parent_hash = input.parent_hash,
                .number = input.number,
                .timestamp = input.timestamp,
            },
            .offset = offset,
            .header_len = @intCast(input.header.len),
            .body_len = @intCast(input.body.len),
            .receipts_len = @intCast(input.receipts.len),
            .transactions_len = @intCast(input.transaction_hashes.len),
            .changeset_len = @intCast(input.changeset.len),
        };
        assert(self.slots[index].total_len() == length);
        self.slot_count += 1;
        self.by_hash.putAssumeCapacityNoClobber(input.hash, index);
        for (input.transaction_hashes, 0..) |transaction_hash, position| {
            self.transactions.putAssumeCapacity(transaction_hash, .{
                .block_hash = input.hash,
                .index = @intCast(position),
            });
        }
    }

    fn write_record(self: *ChainStore, offset: u32, input: *const BlockInput) void {
        var position: usize = offset;
        const parts = [_][]const u8{ input.header, input.body, input.receipts };
        for (parts) |part| {
            @memcpy(self.bytes[position..][0..part.len], part);
            position += part.len;
        }
        for (input.transaction_hashes) |*transaction_hash| {
            @memcpy(self.bytes[position..][0..32], transaction_hash);
            position += 32;
        }
        @memcpy(self.bytes[position..][0..input.changeset.len], input.changeset);
        position += input.changeset.len;
        assert(position - offset == record_length(input));
    }

    pub fn meta(self: *const ChainStore, hash: Hash) ?BlockMeta {
        const index = self.by_hash.get(hash) orelse return null;
        return self.slots[index].meta;
    }

    pub fn block(self: *const ChainStore, hash: Hash) ?BlockView {
        const index = self.by_hash.get(hash) orelse return null;
        const slot = &self.slots[index];
        var position: usize = slot.offset;
        const header = self.bytes[position..][0..slot.header_len];
        position += slot.header_len;
        const body = self.bytes[position..][0..slot.body_len];
        position += slot.body_len;
        const receipts = self.bytes[position..][0..slot.receipts_len];
        position += slot.receipts_len + slot.transactions_len * 32;
        const changeset = self.bytes[position..][0..slot.changeset_len];
        return .{
            .meta = slot.meta,
            .header = header,
            .body = body,
            .receipts = receipts,
            .changeset = changeset,
            .transaction_count = slot.transactions_len,
        };
    }

    pub fn transaction(self: *const ChainStore, transaction_hash: Hash) ?TransactionLocation {
        const location = self.transactions.get(transaction_hash) orelse return null;
        if (!self.is_canonical(location.block_hash)) return null;
        return location;
    }

    pub fn head(self: *const ChainStore) ?BlockMeta {
        return self.head_meta;
    }

    pub fn canonical_hash(self: *const ChainStore, number: u64) ?Hash {
        const head_meta = self.head_meta orelse return null;
        if (number > head_meta.number) return null;
        const entry = &self.canonical[number % self.canonical.len];
        if (!entry.valid or entry.number != number) return null;
        return entry.hash;
    }

    pub fn is_canonical(self: *const ChainStore, hash: Hash) bool {
        const block_meta = self.meta(hash) orelse return false;
        const canonical = self.canonical_hash(block_meta.number) orelse return false;
        return std.mem.eql(u8, &canonical, &hash);
    }

    /// Whether `ancestor` is `descendant` or one of its ancestors, within the reorg depth.
    pub fn is_ancestor(self: *const ChainStore, ancestor: Hash, descendant: Hash) bool {
        const target = self.meta(ancestor) orelse return false;
        var current = self.meta(descendant) orelse return false;
        var steps: u32 = 0;
        while (current.number > target.number) : (steps += 1) {
            if (steps == self.config.reorg_depth_max) return false;
            current = self.meta(current.parent_hash) orelse return false;
        }
        return std.mem.eql(u8, &current.hash, &target.hash);
    }

    /// Computes how to move the canonical head to `new_head`.
    pub fn plan_reorg(self: *const ChainStore, new_head: Hash, plan: *ReorgPlan) Error!void {
        plan.unwind_len = 0;
        plan.apply_len = 0;
        var current = self.meta(new_head) orelse return error.UnknownBlock;
        // Walk the new branch down until it meets the canonical chain. Before the first head
        // exists, the walk ends at the block whose parent is unknown (genesis).
        while (!self.is_canonical(current.hash)) {
            if (self.head_meta == null and self.meta(current.parent_hash) == null) break;
            if (plan.apply_len == plan.apply.len) return error.ReorgTooDeep;
            plan.apply[plan.apply_len] = current.hash;
            plan.apply_len += 1;
            current = self.meta(current.parent_hash) orelse return error.UnknownParent;
        }
        std.mem.reverse(Hash, plan.apply[0..plan.apply_len]);
        plan.ancestor = current;
        const old_head = self.head_meta orelse {
            // First head: the whole walked branch becomes canonical, ancestor included.
            return;
        };
        var number = old_head.number;
        while (number > current.number) : (number -= 1) {
            if (plan.unwind_len == plan.unwind.len) return error.ReorgTooDeep;
            const hash = self.canonical_hash(number) orelse return error.UnknownBlock;
            // Unwinding needs the block's changeset, so the block must still be stored.
            if (self.meta(hash) == null) return error.UnknownBlock;
            plan.unwind[plan.unwind_len] = hash;
            plan.unwind_len += 1;
        }
    }

    /// Makes the plan's branch canonical. The caller has moved state already.
    pub fn set_head(self: *ChainStore, plan: *const ReorgPlan) void {
        if (self.head_meta == null) self.set_canonical_root(plan.ancestor);
        for (0..plan.unwind_len) |index| {
            const number = plan.ancestor.number + 1 + index;
            self.canonical[number % self.canonical.len].valid = false;
        }
        var new_head = plan.ancestor;
        for (plan.apply_hashes(), 0..) |hash, index| {
            new_head = self.meta(hash).?;
            assert(new_head.number == plan.ancestor.number + 1 + index);
            self.set_canonical(new_head);
        }
        self.head_meta = new_head;
        assert(self.is_canonical(new_head.hash));
    }

    /// First head whose block was evicted (a checkpoint keeps its metadata only): the head
    /// and its parent become canonical, as `set_head` does for the oldest walked block.
    pub fn restore_evicted_head(self: *ChainStore, head_meta: BlockMeta) void {
        assert(self.head_meta == null);
        assert(self.meta(head_meta.hash) == null);
        self.set_canonical_root(head_meta);
        self.head_meta = head_meta;
        assert(self.canonical_hash(head_meta.number) != null);
    }

    /// The first head's oldest canonical block and its parent: the parent of a canonical
    /// block is canonical even when evicted. A reopen rebuilds the index from the retained
    /// blocks, and the history window reaches the state below the oldest retained one (its
    /// parent), so without this entry a reopen forgets a window block the live index held.
    fn set_canonical_root(self: *ChainStore, root: BlockMeta) void {
        assert(self.head_meta == null);
        self.set_canonical(root);
        if (root.number == 0) return;
        self.set_canonical(.{
            .hash = root.parent_hash,
            .parent_hash = @splat(0),
            .number = root.number - 1,
            .timestamp = 0,
        });
        assert(self.canonical[(root.number - 1) % self.canonical.len].number == root.number - 1);
    }

    fn set_canonical(self: *ChainStore, block_meta: BlockMeta) void {
        self.canonical[block_meta.number % self.canonical.len] = .{
            .number = block_meta.number,
            .hash = block_meta.hash,
            .valid = true,
        };
    }
};

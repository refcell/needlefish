//! Pending blocks assembled from flashblocks. Mirrors the data side of base/base
//! `pending_blocks.rs` (`PendingBlocks`, `PendingBlocksBuilder`) and `block_assembler.rs`:
//! a run of consecutive blocks `earliest..latest`, each the concatenation of its
//! flashblocks' deltas (transactions and withdrawals appended, header fields taken from the
//! latest delta, base fields from index 0).
//!
//! Memory is fixed at `init` from `Limits`: a ring of `blocks_max` block slots, each with
//! its own transaction byte arena, hash list, withdrawal list, and per-flashblock
//! transaction offsets. Appends check every capacity before mutating, so a rejected
//! flashblock leaves the view unchanged. When a new block arrives with every slot in use
//! the earliest block is evicted (base/base grows until a canonical block trims it).
//!
//! Execution results (receipts, balances, nonces, state) are the state builder's; this view
//! holds what the flashblocks themselves carry.

const std = @import("std");
const assert = std.debug.assert;

const flashblocks = @import("../../common/flashblocks/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const keccak256 = @import("../../common/crypto/keccak.zig").keccak256;
const validation = @import("validation.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Bloom = primitives.Bloom;
const Flashblock = flashblocks.Flashblock;
pub const Withdrawal = flashblocks.Withdrawal;

pub const Limits = struct {
    /// Blocks held at once (base/base `max_pending_blocks_depth` bounds the same run).
    blocks_max: u32 = 8,
    flashblocks_per_block_max: u32 = 64,
    transactions_per_block_max: u32 = 8192,
    transaction_bytes_per_block_max: u32 = 2 << 20,
    withdrawals_per_block_max: u32 = 16,

    pub fn validate(limits: Limits) error{InvalidLimits}!void {
        if (limits.blocks_max == 0 or limits.flashblocks_per_block_max == 0) {
            return error.InvalidLimits;
        }
        if (limits.transactions_per_block_max == 0) return error.InvalidLimits;
        if (limits.transaction_bytes_per_block_max == 0) return error.InvalidLimits;
    }
};

pub const AppendError = error{
    TooManyFlashblocks,
    TooManyTransactions,
    TransactionBytesFull,
    TooManyWithdrawals,
};

/// The index-0 fields of a block (base/base `ExecutionPayloadBaseV1`), owned.
pub const Base = struct {
    parent_beacon_block_root: B256,
    parent_hash: B256,
    fee_recipient: Address,
    prev_randao: B256,
    gas_limit: u64,
    timestamp: u64,
    base_fee_per_gas: u256,
    extra_data_buffer: [validation.extra_data_size_max]u8,
    extra_data_size: u8,

    fn init(base: flashblocks.PayloadBase) Base {
        assert(base.extra_data.len <= validation.extra_data_size_max);
        var result: Base = .{
            .parent_beacon_block_root = base.parent_beacon_block_root,
            .parent_hash = base.parent_hash,
            .fee_recipient = base.fee_recipient,
            .prev_randao = base.prev_randao,
            .gas_limit = base.gas_limit,
            .timestamp = base.timestamp,
            .base_fee_per_gas = base.base_fee_per_gas,
            .extra_data_buffer = @splat(0),
            .extra_data_size = @intCast(base.extra_data.len),
        };
        @memcpy(result.extra_data_buffer[0..base.extra_data.len], base.extra_data);
        assert(result.extra_data_size == base.extra_data.len);
        return result;
    }

    pub fn extra_data(base: *const Base) []const u8 {
        return base.extra_data_buffer[0..base.extra_data_size];
    }
};

/// The latest delta's header fields (base/base `refresh_same_block_header`).
pub const Header = struct {
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    gas_used: u64,
    block_hash: B256,
    withdrawals_root: B256,
    blob_gas_used: ?u64,

    fn init(delta: flashblocks.Delta) Header {
        return .{
            .state_root = delta.state_root,
            .receipts_root = delta.receipts_root,
            .logs_bloom = delta.logs_bloom,
            .gas_used = delta.gas_used,
            .block_hash = delta.block_hash,
            .withdrawals_root = delta.withdrawals_root,
            .blob_gas_used = delta.blob_gas_used,
        };
    }
};

pub const Block = struct {
    block_number: u64 = 0,
    payload_id: [8]u8 = @splat(0),
    base: Base = undefined,
    header: Header = undefined,
    flashblock_count: u32 = 0,
    transaction_count: u32 = 0,
    withdrawal_count: u32 = 0,
    transaction_bytes_size: u32 = 0,
    /// `transaction_ends[i]` is the end of transaction `i` in `transaction_bytes`.
    transaction_ends: []u32,
    transaction_hashes: []B256,
    transaction_bytes: []u8,
    withdrawals: []Withdrawal,
    /// Transaction index where each flashblock's transactions start.
    flashblock_transaction_starts: []u32,

    pub fn latest_index(block: *const Block) u64 {
        assert(block.flashblock_count > 0);
        return block.flashblock_count - 1;
    }

    pub fn transaction(block: *const Block, index: u32) []const u8 {
        assert(index < block.transaction_count);
        const start = if (index == 0) 0 else block.transaction_ends[index - 1];
        return block.transaction_bytes[start..block.transaction_ends[index]];
    }

    pub fn hashes(block: *const Block) []const B256 {
        return block.transaction_hashes[0..block.transaction_count];
    }

    pub fn withdrawal_list(block: *const Block) []const Withdrawal {
        return block.withdrawals[0..block.withdrawal_count];
    }

    /// Transactions of flashblock `index` (base/base `latest_flashblock_tx_start`).
    pub fn flashblock_transactions(block: *const Block, index: u32) [2]u32 {
        assert(index < block.flashblock_count);
        const start = block.flashblock_transaction_starts[index];
        const end = if (index + 1 == block.flashblock_count)
            block.transaction_count
        else
            block.flashblock_transaction_starts[index + 1];
        assert(start <= end);
        return .{ start, end };
    }

    pub fn find_transaction(block: *const Block, hash: B256) ?u32 {
        for (block.hashes(), 0..) |candidate, index| {
            if (candidate.eql(hash)) return @intCast(index);
        }
        return null;
    }

    fn check_capacity(block: *const Block, flashblock: *const Flashblock) AppendError!void {
        if (block.flashblock_count >= block.flashblock_transaction_starts.len) {
            return error.TooManyFlashblocks;
        }
        const transactions = flashblock.diff.transactions;
        if (transactions.len > block.transaction_ends.len - block.transaction_count) {
            return error.TooManyTransactions;
        }
        var bytes: u64 = 0;
        for (transactions) |bytes_one| bytes += bytes_one.len;
        if (bytes > block.transaction_bytes.len - block.transaction_bytes_size) {
            return error.TransactionBytesFull;
        }
        const withdrawals = flashblock.diff.withdrawals;
        if (withdrawals.len > block.withdrawals.len - block.withdrawal_count) {
            return error.TooManyWithdrawals;
        }
    }

    /// Appends a delta; `check_capacity` passed.
    fn append(block: *Block, flashblock: *const Flashblock) void {
        assert(flashblock.index == block.flashblock_count);
        block.flashblock_transaction_starts[block.flashblock_count] = block.transaction_count;
        block.flashblock_count += 1;
        for (flashblock.diff.transactions) |bytes| {
            const start = block.transaction_bytes_size;
            const end = start + @as(u32, @intCast(bytes.len));
            @memcpy(block.transaction_bytes[start..end], bytes);
            block.transaction_ends[block.transaction_count] = end;
            block.transaction_hashes[block.transaction_count] = .{ .bytes = keccak256(bytes) };
            block.transaction_count += 1;
            block.transaction_bytes_size = end;
        }
        for (flashblock.diff.withdrawals) |withdrawal| {
            block.withdrawals[block.withdrawal_count] = withdrawal;
            block.withdrawal_count += 1;
        }
        block.header = .init(flashblock.diff);
        assert(block.transaction_bytes_size <= block.transaction_bytes.len);
    }

    fn reset(block: *Block, flashblock: *const Flashblock) void {
        assert(flashblock.index == 0);
        block.block_number = flashblock.metadata.block_number;
        block.payload_id = flashblock.payload_id;
        block.base = .init(flashblock.base.?);
        block.flashblock_count = 0;
        block.transaction_count = 0;
        block.withdrawal_count = 0;
        block.transaction_bytes_size = 0;
    }
};

pub const PendingBlocks = struct {
    limits: Limits,
    slots: []Block,
    /// Slot of the earliest block.
    head: u32 = 0,
    count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !PendingBlocks {
        try limits.validate();
        const slots = try allocator.alloc(Block, limits.blocks_max);
        var initialized: u32 = 0;
        errdefer {
            for (slots[0..initialized]) |*slot| free_slot(allocator, slot);
            allocator.free(slots);
        }
        for (slots) |*slot| {
            slot.* = try alloc_slot(allocator, limits);
            initialized += 1;
        }
        assert(initialized == limits.blocks_max);
        return .{ .limits = limits, .slots = slots };
    }

    pub fn deinit(pending: *PendingBlocks, allocator: std.mem.Allocator) void {
        for (pending.slots) |*slot| free_slot(allocator, slot);
        allocator.free(pending.slots);
        pending.* = undefined;
    }

    fn alloc_slot(allocator: std.mem.Allocator, limits: Limits) !Block {
        const ends = try allocator.alloc(u32, limits.transactions_per_block_max);
        errdefer allocator.free(ends);
        const hashes = try allocator.alloc(B256, limits.transactions_per_block_max);
        errdefer allocator.free(hashes);
        const bytes = try allocator.alloc(u8, limits.transaction_bytes_per_block_max);
        errdefer allocator.free(bytes);
        const withdrawals = try allocator.alloc(Withdrawal, limits.withdrawals_per_block_max);
        errdefer allocator.free(withdrawals);
        const starts = try allocator.alloc(u32, limits.flashblocks_per_block_max);
        return .{
            .transaction_ends = ends,
            .transaction_hashes = hashes,
            .transaction_bytes = bytes,
            .withdrawals = withdrawals,
            .flashblock_transaction_starts = starts,
        };
    }

    fn free_slot(allocator: std.mem.Allocator, slot: *Block) void {
        allocator.free(slot.flashblock_transaction_starts);
        allocator.free(slot.withdrawals);
        allocator.free(slot.transaction_bytes);
        allocator.free(slot.transaction_hashes);
        allocator.free(slot.transaction_ends);
    }

    pub fn is_empty(pending: *const PendingBlocks) bool {
        return pending.count == 0;
    }

    pub fn earliest(pending: *const PendingBlocks) ?*const Block {
        if (pending.count == 0) return null;
        return &pending.slots[pending.head];
    }

    pub fn latest(pending: *const PendingBlocks) ?*const Block {
        if (pending.count == 0) return null;
        return pending.slot_at(pending.count - 1);
    }

    pub fn earliest_block_number(pending: *const PendingBlocks) ?u64 {
        const block = pending.earliest() orelse return null;
        return block.block_number;
    }

    pub fn latest_block_number(pending: *const PendingBlocks) ?u64 {
        const block = pending.latest() orelse return null;
        return block.block_number;
    }

    /// The pending block numbered `block_number`, if held.
    pub fn get(pending: *const PendingBlocks, block_number: u64) ?*const Block {
        const first = pending.earliest_block_number() orelse return null;
        if (block_number < first) return null;
        const offset = block_number - first;
        if (offset >= pending.count) return null;
        const block = pending.slot_at(@intCast(offset));
        assert(block.block_number == block_number);
        return block;
    }

    /// The `position`th held block, earliest first.
    pub fn at(pending: *const PendingBlocks, position: u32) *const Block {
        assert(position < pending.count);
        return pending.slot_at(position);
    }

    pub fn transaction_count(pending: *const PendingBlocks) u64 {
        var total: u64 = 0;
        for (0..pending.count) |position| {
            total += pending.slot_at(@intCast(position)).transaction_count;
        }
        return total;
    }

    fn slot_at(pending: *const PendingBlocks, position: u32) *Block {
        assert(position < pending.slots.len);
        const index = (pending.head + position) % @as(u32, @intCast(pending.slots.len));
        return &pending.slots[index];
    }

    pub fn clear(pending: *PendingBlocks) void {
        pending.head = 0;
        pending.count = 0;
        assert(pending.is_empty());
    }

    /// Drops every block numbered at most `block_number` (base/base retains flashblocks
    /// above the canonical number before rebuilding).
    pub fn drop_through(pending: *PendingBlocks, block_number: u64) void {
        const slots: u32 = @intCast(pending.slots.len);
        var bound: u32 = slots;
        while (pending.count > 0 and bound > 0) : (bound -= 1) {
            if (pending.slots[pending.head].block_number > block_number) break;
            pending.head = (pending.head + 1) % slots;
            pending.count -= 1;
        }
        if (pending.earliest_block_number()) |first| assert(first > block_number);
    }

    /// Starts block `flashblock.metadata.block_number` from its index-0 flashblock. It must
    /// be the block after the latest (or the view empty). Evicts the earliest block when
    /// every slot is in use; returns whether it did.
    pub fn begin_block(pending: *PendingBlocks, flashblock: *const Flashblock) AppendError!bool {
        assert(flashblock.index == 0 and flashblock.base != null);
        if (pending.latest_block_number()) |number| {
            assert(flashblock.metadata.block_number == number + 1);
        }
        // Every slot has the same capacity: check the delta against an empty block.
        if (flashblock.diff.transactions.len > pending.limits.transactions_per_block_max) {
            return error.TooManyTransactions;
        }
        var bytes: u64 = 0;
        for (flashblock.diff.transactions) |transaction| bytes += transaction.len;
        if (bytes > pending.limits.transaction_bytes_per_block_max) {
            return error.TransactionBytesFull;
        }
        if (flashblock.diff.withdrawals.len > pending.limits.withdrawals_per_block_max) {
            return error.TooManyWithdrawals;
        }
        const evicted = pending.count == pending.slots.len;
        if (evicted) {
            pending.head = (pending.head + 1) % @as(u32, @intCast(pending.slots.len));
            pending.count -= 1;
        }
        const block = pending.slot_at(pending.count);
        pending.count += 1;
        block.reset(flashblock);
        block.check_capacity(flashblock) catch unreachable; // Checked against the limits.
        block.append(flashblock);
        return evicted;
    }

    /// Appends the next flashblock of the latest block.
    pub fn append(pending: *PendingBlocks, flashblock: *const Flashblock) AppendError!void {
        assert(pending.count > 0);
        const block = pending.slot_at(pending.count - 1);
        assert(block.block_number == flashblock.metadata.block_number);
        assert(flashblock.index == block.flashblock_count);
        try block.check_capacity(flashblock);
        block.append(flashblock);
    }
};

test {
    _ = @import("pending_test.zig");
}

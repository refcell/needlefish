//! The executor-backed pending state builder. Mirrors base/base `state_builder.rs`
//! (`PendingStateBuilder`) and the data side of `receipt_builder.rs`: every pending
//! transaction is re-executed by the node's block `Executor` on top of the canonical state,
//! so pending-tag RPC calls can read receipts, balances, nonces, storage, code, and run
//! `eth_call` against the pending state.
//!
//! The pending writes never reach the canonical `StateDb`. The executor runs over a
//! `Backend` whose reads go through a `db.Overlay` on the canonical tables and whose
//! commits fold the evm block state into that overlay (the overlay is never committed).
//! Contract code created by pending transactions lives in a builder-owned store, so the
//! canonical code table and the durable journal see only canonical code.
//!
//! A block opens with `Executor.begin_block` at its first flashblock (pre-block system
//! calls and transitions), and later flashblocks resume it: the open block's counters are
//! kept here, the evm block context is restored with `Executor.set_block_env`, and every
//! flashblock's changes are folded into the overlay when it finishes. A block's
//! withdrawals (and L1 requests) are applied by `Executor.finish_block` when the next
//! block starts. Receipts are copied out of the executor's scratch arena after every
//! transaction (their log payloads into a fixed byte arena), because `eth_call` reuses it.
//!
//! Memory is fixed at `create` from `Options`. Execution results accumulate since the
//! last `reset` (the processor resets on every rebuild), bounded by `transactions_max`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const keccak256 = @import("../../common/crypto/keccak.zig").keccak256;
const evm = @import("../evm/root.zig");
const db = @import("../db/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const node = @import("../node/root.zig");
const ordered = @import("../trie/ordered.zig");
const pending = @import("pending.zig");
const state = @import("state.zig");

const Address = [20]u8;
const Hash = [32]u8;
const B256 = primitives.B256;
const Receipt = consensus.Receipt;
const Executor = node.Executor;
const BlockEnv = node.executor.BlockEnv;
const Building = Executor.Building;
pub const AccountInfo = db.state.AccountInfo;
pub const Call = Executor.Call;
pub const Simulated = Executor.Simulated;

pub const Options = struct {
    /// Transactions executed since the last reset, over every pending block.
    transactions_max: u32 = 1 << 14,
    /// RLP log payload bytes of those transactions' receipts.
    log_bytes_max: u32 = 4 << 20,
    /// Pending blocks tracked at once (match `pending.Limits.blocks_max`).
    blocks_max: u32 = 8,
    withdrawals_per_block_max: u32 = 16,
    /// Contract code created by pending transactions.
    codes_max: u32 = 1 << 10,
    code_bytes_max: u32 = 4 << 20,
    /// Accounts and slots the pending blocks may change in total.
    accounts_max: u32 = 1 << 14,
    slots_max: u32 = 1 << 16,
    executor: node.executor.Config = .{},

    pub fn validate(options: Options) error{InvalidOptions}!void {
        if (options.transactions_max == 0 or options.blocks_max == 0) {
            return error.InvalidOptions;
        }
        if (options.codes_max == 0 or options.code_bytes_max == 0) return error.InvalidOptions;
        if (options.accounts_max == 0 or options.slots_max == 0) return error.InvalidOptions;
    }
};

pub const Error = node.executor.Error || error{
    UnexpectedBlock,
    LogBytesFull,
    TooManyWithdrawals,
    BaseFeeTooLarge,
};

/// One executed pending transaction; its receipt is `receipt(position)`.
pub const Transaction = struct {
    hash: B256,
    block_number: u64,
    /// Index in its block.
    index: u32,
    /// Gas this transaction used (its receipt carries the cumulative gas).
    gas_used: u64,
    /// Block-level index of its first log.
    log_index: u32,
};

/// One pending block's execution so far (the open block's `Building` counters).
pub const BlockRecord = struct {
    number: u64,
    /// The latest delta's block hash (BLOCKHASH of later pending blocks).
    hash: B256,
    env: BlockEnv,
    fork: evm.Fork,
    /// Position of its first transaction in `transactions`.
    transaction_start: u32,
    transaction_count: u32 = 0,
    gas_used: u64 = 0,
    blob_gas_used: u64 = 0,
    logs_bloom: primitives.Bloom = .zero,
    fees: u256 = 0,
    log_count: u32 = 0,
    withdrawals: []payload.Withdrawal,
    withdrawal_count: u32 = 0,
    finished: bool = false,

    fn save(record: *BlockRecord, building: *const Building) void {
        assert(building.count >= record.transaction_count);
        assert(building.gas_used >= record.gas_used);
        record.transaction_count = building.count;
        record.gas_used = building.gas_used;
        record.blob_gas_used = building.blob_gas_used;
        record.logs_bloom = building.logs_bloom;
        record.fees = building.fees;
    }

    pub fn withdrawal_list(record: *const BlockRecord) []const payload.Withdrawal {
        assert(record.withdrawal_count <= record.withdrawals.len);
        return record.withdrawals[0..record.withdrawal_count];
    }
};

const CodeEntry = struct { offset: u32, size: u32 };

pub const Stats = struct {
    resets: u64 = 0,
    executed: u64 = 0,
    failures: u64 = 0,
};

pub const ExecutorState = struct {
    spec: *const chainspec.ChainSpec,
    canonical: *node.StateDb,
    executor: Executor,
    overlay: db.Overlay,
    codes: std.AutoHashMapUnmanaged(Hash, CodeEntry),
    code_bytes: []u8,
    code_bytes_size: u32 = 0,
    codes_max: u32,
    transactions: []Transaction,
    receipts: []Receipt,
    transaction_count: u32 = 0,
    log_bytes: []u8,
    log_bytes_size: u32 = 0,
    /// Ring of block records: `[block_head, block_head + block_count)`.
    blocks: []BlockRecord,
    block_head: u32 = 0,
    block_count: u32 = 0,
    withdrawal_storage: []payload.Withdrawal,
    stats: Stats = .{},

    /// Heap-pinned: the executor's backend points at the builder.
    pub fn create(
        allocator: std.mem.Allocator,
        spec: *const chainspec.ChainSpec,
        canonical: *node.StateDb,
        options: Options,
    ) !*ExecutorState {
        try options.validate();
        const builder = try allocator.create(ExecutorState);
        errdefer allocator.destroy(builder);
        builder.* = .{
            .spec = spec,
            .canonical = canonical,
            .executor = undefined,
            .overlay = try db.Overlay.init(allocator, canonical.state, .{
                .accounts_max = options.accounts_max,
                .slots_max = options.slots_max,
                .codes_max = 1,
            }),
            .codes = .empty,
            .code_bytes = &.{},
            .codes_max = options.codes_max,
            .transactions = &.{},
            .receipts = &.{},
            .log_bytes = &.{},
            .blocks = &.{},
            .withdrawal_storage = &.{},
        };
        errdefer builder.overlay.deinit(allocator);
        try builder.alloc_buffers(allocator, options);
        errdefer builder.free_buffers(allocator);
        builder.executor = try Executor.init_backend(allocator, spec, .{
            .context = builder,
            .database = .{ .context = builder, .vtable = &database_vtable },
            .commit = backend_commit,
            .root = backend_root,
        }, options.executor);
        assert(builder.blocks.len == options.blocks_max);
        assert(builder.transaction_count == 0);
        return builder;
    }

    pub fn destroy(builder: *ExecutorState, allocator: std.mem.Allocator) void {
        builder.executor.deinit(allocator);
        builder.free_buffers(allocator);
        builder.overlay.deinit(allocator);
        allocator.destroy(builder);
    }

    fn alloc_buffers(
        builder: *ExecutorState,
        allocator: std.mem.Allocator,
        options: Options,
    ) !void {
        try builder.codes.ensureTotalCapacity(allocator, options.codes_max);
        errdefer builder.codes.deinit(allocator);
        builder.code_bytes = try allocator.alloc(u8, options.code_bytes_max);
        errdefer allocator.free(builder.code_bytes);
        builder.transactions = try allocator.alloc(Transaction, options.transactions_max);
        errdefer allocator.free(builder.transactions);
        builder.receipts = try allocator.alloc(Receipt, options.transactions_max);
        errdefer allocator.free(builder.receipts);
        builder.log_bytes = try allocator.alloc(u8, options.log_bytes_max);
        errdefer allocator.free(builder.log_bytes);
        builder.blocks = try allocator.alloc(BlockRecord, options.blocks_max);
        errdefer allocator.free(builder.blocks);
        const withdrawals = @as(usize, options.blocks_max) * options.withdrawals_per_block_max;
        builder.withdrawal_storage = try allocator.alloc(payload.Withdrawal, withdrawals);
        assert(builder.receipts.len == builder.transactions.len);
    }

    fn free_buffers(builder: *ExecutorState, allocator: std.mem.Allocator) void {
        allocator.free(builder.withdrawal_storage);
        allocator.free(builder.blocks);
        allocator.free(builder.log_bytes);
        allocator.free(builder.receipts);
        allocator.free(builder.transactions);
        allocator.free(builder.code_bytes);
        builder.codes.deinit(allocator);
    }

    // ---- state.zig interface ---------------------------------------------------------

    /// Drops every pending result; reads fall through to the canonical state again.
    pub fn reset(builder: *ExecutorState) void {
        builder.executor.abort_block();
        builder.overlay.discard();
        builder.codes.clearRetainingCapacity();
        builder.code_bytes_size = 0;
        builder.transaction_count = 0;
        builder.log_bytes_size = 0;
        builder.block_head = 0;
        builder.block_count = 0;
        builder.stats.resets += 1;
        assert(builder.latest_block() == null);
        assert(builder.overlay.accounts.count() == 0);
    }

    /// Executes transactions `start..end` of `block`. Any failure is `ExecutionFailed`;
    /// the processor then resets the builder (base/base drops the pending state).
    pub fn execute(
        builder: *ExecutorState,
        block: *const pending.Block,
        start: u32,
        end: u32,
    ) state.Error!void {
        assert(start <= end);
        assert(end <= block.transaction_count);
        builder.execute_range(block, start, end) catch {
            builder.executor.abort_block();
            builder.stats.failures += 1;
            return error.ExecutionFailed;
        };
        builder.stats.executed += end - start;
    }

    fn execute_range(
        builder: *ExecutorState,
        block: *const pending.Block,
        start: u32,
        end: u32,
    ) Error!void {
        builder.executor.abort_block();
        var building = try builder.open(block, start);
        const record = builder.latest_record().?;
        assert(record.number == block.block_number);
        var index = start;
        while (index < end) : (index += 1) {
            try builder.apply_one(record, &building, block, index);
        }
        try copy_withdrawals(record, block);
        record.hash = block.header.block_hash;
        try backend_commit(builder, builder.executor.state);
        assert(record.transaction_count == end);
    }

    /// The building block for `block` at transaction `start`: the open block resumed when
    /// it is the same block, else a fresh block (after finishing the previous one). A
    /// block's first flashblocks may carry no transactions, so `start == 0` can resume.
    fn open(builder: *ExecutorState, block: *const pending.Block, start: u32) Error!Building {
        const latest = builder.latest_record();
        const same = if (latest) |record| record.number == block.block_number else false;
        if (!same) {
            if (start != 0) return error.UnexpectedBlock;
            try builder.finish_latest(block.block_number);
            const record = try builder.push_record(block);
            var building = try builder.executor.begin_block(&record.env);
            record.fork = building.fork;
            building.receipts = builder.receipts[record.transaction_start..];
            return building;
        }
        const record = latest.?;
        assert(record.number == block.block_number);
        if (record.transaction_count != start or record.finished) return error.UnexpectedBlock;
        builder.executor.arena.reset();
        builder.executor.set_block_env(&record.env);
        assert(record.transaction_start + record.transaction_count == builder.transaction_count);
        return builder.resume_building(record);
    }

    fn resume_building(builder: *ExecutorState, record: *BlockRecord) Building {
        assert(record.transaction_start <= builder.transaction_count);
        assert(!record.finished);
        return .{
            .block = &record.env,
            .fork = record.fork,
            .receipts = builder.receipts[record.transaction_start..],
            .count = record.transaction_count,
            .gas_used = record.gas_used,
            .blob_gas_used = record.blob_gas_used,
            .logs_bloom = record.logs_bloom,
            .fees = record.fees,
        };
    }

    fn apply_one(
        builder: *ExecutorState,
        record: *BlockRecord,
        building: *Building,
        block: *const pending.Block,
        index: u32,
    ) Error!void {
        assert(index == building.count);
        const position = builder.transaction_count;
        if (position == builder.transactions.len) return error.TooManyTransactions;
        const gas_before = building.gas_used;
        try builder.executor.apply(building, block.transaction(index));
        const receipt = &builder.receipts[position];
        assert(receipt == &building.receipts[building.count - 1]);
        const logs = receipt.logs.payload;
        if (logs.len > builder.log_bytes.len - builder.log_bytes_size) {
            return error.LogBytesFull;
        }
        const copy = builder.log_bytes[builder.log_bytes_size..][0..logs.len];
        @memcpy(copy, logs);
        receipt.logs.payload = copy;
        builder.log_bytes_size += @intCast(logs.len);
        builder.transactions[position] = .{
            .hash = block.transaction_hashes[index],
            .block_number = block.block_number,
            .index = index,
            .gas_used = building.gas_used - gas_before,
            .log_index = record.log_count,
        };
        record.log_count += receipt.logs.count;
        builder.transaction_count = position + 1;
        record.save(building);
    }

    /// Applies the latest block's withdrawals and post-block changes before block
    /// `next_number` starts.
    fn finish_latest(builder: *ExecutorState, next_number: u64) Error!void {
        const record = builder.latest_record() orelse return;
        assert(!record.finished);
        if (next_number != record.number + 1) return error.UnexpectedBlock;
        builder.executor.arena.reset();
        builder.executor.set_block_env(&record.env);
        const building = builder.resume_building(record);
        _ = try builder.executor.finish_block(&building, record.withdrawal_list());
        record.finished = true;
        assert(builder.executor.state.accounts.count() == 0);
    }

    fn push_record(builder: *ExecutorState, block: *const pending.Block) Error!*BlockRecord {
        const env = try env_of(block);
        const slots: u32 = @intCast(builder.blocks.len);
        if (builder.block_count == slots) {
            assert(builder.blocks[builder.block_head].finished);
            builder.block_head = (builder.block_head + 1) % slots;
            builder.block_count -= 1;
        }
        const slot = (builder.block_head + builder.block_count) % slots;
        const per_block = builder.withdrawal_storage.len / builder.blocks.len;
        builder.blocks[slot] = .{
            .number = block.block_number,
            .hash = block.header.block_hash,
            .env = env,
            .fork = .merge,
            .transaction_start = builder.transaction_count,
            .withdrawals = builder.withdrawal_storage[slot * per_block ..][0..per_block],
        };
        builder.block_count += 1;
        assert(builder.block_count <= slots);
        return &builder.blocks[slot];
    }

    fn copy_withdrawals(record: *BlockRecord, block: *const pending.Block) Error!void {
        const list = block.withdrawal_list();
        if (list.len > record.withdrawals.len) return error.TooManyWithdrawals;
        for (list, record.withdrawals[0..list.len]) |source, *into| {
            into.* = .{
                .index = source.index,
                .validator_index = source.validator_index,
                .address = source.address,
                .amount_gwei = source.amount_gwei,
            };
        }
        record.withdrawal_count = @intCast(list.len);
        assert(record.withdrawal_list().len == list.len);
    }

    fn latest_record(builder: *ExecutorState) ?*BlockRecord {
        if (builder.block_count == 0) return null;
        const slots: u32 = @intCast(builder.blocks.len);
        return &builder.blocks[(builder.block_head + builder.block_count - 1) % slots];
    }

    // ---- Pending reads ---------------------------------------------------------------

    /// The newest pending block executed since the last reset.
    pub fn latest_block(builder: *const ExecutorState) ?*const BlockRecord {
        if (builder.block_count == 0) return null;
        return builder.block_at(builder.block_count - 1);
    }

    /// The executed pending block numbered `number`, if tracked.
    pub fn block_by_number(builder: *const ExecutorState, number: u64) ?*const BlockRecord {
        var position: u32 = 0;
        while (position < builder.block_count) : (position += 1) {
            const record = builder.block_at(position);
            if (record.number == number) return record;
        }
        return null;
    }

    fn block_at(builder: *const ExecutorState, position: u32) *const BlockRecord {
        assert(position < builder.block_count);
        const slots: u32 = @intCast(builder.blocks.len);
        return &builder.blocks[(builder.block_head + position) % slots];
    }

    /// Position of the executed transaction `hash` (newest first), if any.
    pub fn find_transaction(builder: *const ExecutorState, hash: B256) ?u32 {
        var position = builder.transaction_count;
        while (position > 0) {
            position -= 1;
            if (builder.transactions[position].hash.eql(hash)) return position;
        }
        return null;
    }

    pub fn transaction_at(builder: *const ExecutorState, position: u32) *const Transaction {
        assert(position < builder.transaction_count);
        return &builder.transactions[position];
    }

    /// The receipt of the transaction at `position` (logs valid until the next reset).
    pub fn receipt_at(builder: *const ExecutorState, position: u32) *const Receipt {
        assert(position < builder.transaction_count);
        return &builder.receipts[position];
    }

    /// The receipts of a tracked block, in order.
    pub fn block_receipts(
        builder: *const ExecutorState,
        record: *const BlockRecord,
    ) []const Receipt {
        assert(record.transaction_start + record.transaction_count <= builder.transaction_count);
        return builder.receipts[record.transaction_start..][0..record.transaction_count];
    }

    /// The account in the pending state (null: absent).
    pub fn account(builder: *const ExecutorState, address: Address) ?AccountInfo {
        const info = builder.overlay.basic(address);
        if (info) |found| assert(found.nonce < std.math.maxInt(u64));
        return info;
    }

    pub fn storage(builder: *const ExecutorState, address: Address, slot: u256) u256 {
        return builder.overlay.storage(address, slot);
    }

    pub fn code_by_hash(builder: *const ExecutorState, code_hash: Hash) ?[]const u8 {
        if (builder.codes.get(code_hash)) |entry| {
            return builder.code_bytes[entry.offset..][0..entry.size];
        }
        return builder.overlay.code_by_hash(code_hash);
    }

    /// `eth_call` on the pending state in the latest pending block's context; null when
    /// nothing is pending. The output borrows the executor's scratch until the next call.
    pub fn call(builder: *ExecutorState, request: Call) Error!?Simulated {
        const record = builder.latest_record() orelse return null;
        assert(builder.executor.state.accounts.count() == 0);
        const simulated = try builder.executor.simulate(&record.env, request);
        assert(builder.executor.state.accounts.count() == 0);
        return simulated;
    }

    /// The receipts root of a tracked block's executed transactions (checks a delta).
    pub fn receipts_root(builder: *ExecutorState, record: *const BlockRecord) Error!Hash {
        const receipts = builder.block_receipts(record);
        builder.executor.arena.reset();
        const allocator = builder.executor.arena.allocator();
        const items = allocator.alloc([]const u8, receipts.len) catch return error.ScratchFull;
        for (receipts, items) |item, *encoded| {
            const buffer = allocator.alloc(u8, item.encoded_length()) catch
                return error.ScratchFull;
            encoded.* = item.encode_to(buffer);
        }
        assert(items.len == record.transaction_count);
        return ordered.ordered_trie_root(items);
    }

    // ---- Executor backend ------------------------------------------------------------

    fn store_code(builder: *ExecutorState, code_hash: Hash, bytes: []const u8) Error!void {
        if (builder.codes.count() == builder.codes_max) return error.CodeStoreFull;
        if (bytes.len > builder.code_bytes.len - builder.code_bytes_size) {
            return error.CodeStoreFull;
        }
        const offset = builder.code_bytes_size;
        @memcpy(builder.code_bytes[offset..][0..bytes.len], bytes);
        builder.code_bytes_size += @intCast(bytes.len);
        const entry: CodeEntry = .{ .offset = offset, .size = @intCast(bytes.len) };
        builder.codes.putAssumeCapacity(code_hash, entry);
        assert(builder.code_by_hash(code_hash).?.len == bytes.len);
    }

    /// Folds the evm block state into the overlay (the `commit_evm` rules, code kept
    /// here), then empties the evm cache like `StateDb.commit`.
    fn fold(builder: *ExecutorState, evm_state: *evm.State) Error!void {
        var accounts = evm_state.accounts.valueIterator();
        while (accounts.next()) |entry| {
            if (!entry.dirty) continue;
            if (!entry.in_database) {
                try builder.overlay.set_account(entry.address, null);
                continue;
            }
            const code_hash = entry.info.code_hash;
            if (entry.info.has_code() and builder.code_by_hash(code_hash) == null) {
                try builder.store_code(code_hash, entry.info.code.?);
            }
            try builder.overlay.set_account(entry.address, .{
                .nonce = entry.info.nonce,
                .balance = entry.info.balance,
                .code_hash = code_hash,
            });
            if (entry.storage_cleared) try builder.overlay.wipe_storage(entry.address);
        }
        var slots = evm_state.slots.iterator();
        while (slots.next()) |entry| {
            if (!entry.value_ptr.dirty) continue;
            const owner = evm_state.accounts.getPtr(entry.key_ptr.address) orelse continue;
            if (!owner.in_database) continue;
            if (entry.value_ptr.epoch != owner.storage_epoch) continue;
            const key = entry.key_ptr;
            try builder.overlay.set_storage(key.address, key.slot, entry.value_ptr.present);
        }
        evm_state.accounts.clearRetainingCapacity();
        evm_state.slots.clearRetainingCapacity();
        evm_state.code_store_len = 0;
        assert(evm_state.accounts.count() == 0);
    }

    fn backend_commit(context: *anyopaque, evm_state: *evm.State) node.executor.BackendError!void {
        const builder: *ExecutorState = @ptrCast(@alignCast(context));
        builder.fold(evm_state) catch |err| return switch (err) {
            error.CodeStoreFull => error.CodeStoreFull,
            error.OverlayFull => error.OverlayFull,
            else => error.StateUnavailable,
        };
    }

    /// The pending state has no trie; flashblock deltas carry the roots.
    fn backend_root(context: *anyopaque) node.executor.BackendError!Hash {
        const builder: *ExecutorState = @ptrCast(@alignCast(context));
        assert(builder.executor.state.accounts.count() == 0);
        return @splat(0);
    }

    const database_vtable: evm.state.Database.VTable = .{
        .basic = database_basic,
        .code_by_hash = database_code,
        .storage = database_storage,
        .block_hash = database_block_hash,
    };

    fn from(context: *anyopaque) *ExecutorState {
        return @ptrCast(@alignCast(context));
    }

    /// `has_storage` (EIP-7610 create collisions) reads the canonical trie unless the
    /// pending blocks wiped the account; storage first written by a pending block does
    /// not set it (such an account has code or a nonce, which already collide).
    fn database_basic(
        context: *anyopaque,
        address: Address,
    ) evm.state.Error!?evm.state.AccountInfo {
        const builder = from(context);
        const info = builder.overlay.basic(address) orelse return null;
        const wiped = if (builder.overlay.accounts.get(address)) |entry| entry.wiped else false;
        const trie = &builder.canonical.state.state_trie;
        return .{
            .balance = info.balance,
            .nonce = info.nonce,
            .code_hash = info.code_hash,
            .has_storage = !wiped and trie.has_storage(keccak256(&address)),
        };
    }

    fn database_code(context: *anyopaque, code_hash: Hash) evm.state.Error![]const u8 {
        return from(context).code_by_hash(code_hash) orelse error.DatabaseFailure;
    }

    fn database_storage(context: *anyopaque, address: Address, slot: u256) evm.state.Error!u256 {
        return from(context).overlay.storage(address, slot);
    }

    /// Pending blocks answer with their latest delta hash; older blocks come from the
    /// canonical ring (unknown numbers read zero, as BLOCKHASH outside the window).
    fn database_block_hash(context: *anyopaque, number: u64) evm.state.Error!Hash {
        const builder = from(context);
        if (builder.block_by_number(number)) |record| {
            if (record.number < builder.latest_block().?.number) return record.hash.bytes;
        }
        return builder.overlay.block_hash(number) orelse @splat(0);
    }
};

/// The block context of a pending block from its index-0 base. L2 blocks carry no
/// excess blob gas (`Chain.child_header` sets 0).
fn env_of(block: *const pending.Block) Error!BlockEnv {
    const base = &block.base;
    if (base.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeTooLarge;
    assert(block.flashblock_count > 0);
    return .{
        .number = block.block_number,
        .timestamp = base.timestamp,
        .beneficiary = base.fee_recipient.bytes,
        .gas_limit = base.gas_limit,
        .base_fee = @intCast(base.base_fee_per_gas),
        .prev_randao = base.prev_randao.bytes,
        .parent_hash = base.parent_hash.bytes,
        .parent_beacon_block_root = base.parent_beacon_block_root.bytes,
        .excess_blob_gas = 0,
    };
}

comptime {
    state.assert_interface(ExecutorState);
}

test {
    _ = @import("state_executor_test.zig");
}

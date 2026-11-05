//! The flashblock generator: builds one payload job as a sequence of flashblocks. Mirrors
//! base/base `crates/builder/core/src/flashblocks/{generator,payload,context}.rs`.
//!
//! Flashblock 0 carries the `PayloadBase` (fields fixed for the block) and the sequencer's
//! attribute transactions (deposits, forced transactions). Flashblocks `1..=count` each add
//! best-pool transactions under a cumulative budget: base/base splits the block gas limit
//! (and the batcher's DA block limit, when set) evenly, `per_batch = limit / count`, and
//! flashblock `j` may fill the block up to `j * per_batch`.
//!
//! Every delta carries the block state as if the block ended after it: state root,
//! receipts root, logs bloom, gas used, blob gas used, withdrawals root and the hash of the
//! block sealed there. To get those roots mid-block without changing the executor, each
//! flashblock re-executes the block's accepted transactions from the parent state, adds
//! its new ones, commits (one undo record), seals, and rolls the commit back. The state
//! database is therefore at the parent state between flashblocks and after the job, and
//! the last flashblock's sealed header is exactly what `Chain` builds from the same list.
//! Re-execution makes a block cost O(count) executions of its prefix; see the lane file.
//!
//! The generator is pinned (headers point into its extra-data buffer) and allocates only
//! at `init`; the attributes passed to `start` must outlive the job.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const flashblocks = @import("../../common/flashblocks/root.zig");
const flz = @import("../../common/flz/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const txpool = @import("../../execution/txpool/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const executor_module = @import("../../execution/node/executor.zig");
const best_txs = @import("best_txs.zig");

const Chain = chain_module.Chain;
const Header = consensus.Header;
const Hash = [32]u8;
const Building = executor_module.Executor.Building;

pub const Flashblock = flashblocks.Flashblock;
pub const FlashblockId = flashblocks.FlashblockId;

pub const Error = chain_module.Error || error{
    MissingParentBeaconBlockRoot,
    TransactionBytesFull,
    JobInactive,
};

pub const Config = struct {
    /// Most regular flashblocks (indices `1..=count`) in one block.
    flashblocks_max: u32 = 64,
    /// Most transactions in one block (attribute and pool transactions).
    transactions_max: u32 = 1 << 14,
    /// Bytes for the block's transactions (each accepted transaction is copied).
    transaction_bytes_max: u32 = 16 << 20,
    /// Pool snapshot size per flashblock.
    select_max: u32 = 1 << 14,
};

/// One payload job: the parent block and the attributes the block is built from.
pub const Job = struct {
    payload_id: [8]u8,
    parent_hash: Hash,
    attributes: *const payload.PayloadAttributes,
    /// Regular flashblocks for this block (base/base `calculate_flashblocks`).
    flashblock_count: u32,
};

pub const Generator = struct {
    config: Config,
    best: best_txs.BestFlashblocksTxs,
    transactions: [][]const u8,
    senders: []?primitives.Address,
    bytes: []u8,
    select_buffer: []*const txpool.Tx,
    extra_data: [chainspec.basefee.jovian_extra_data_size]u8 = undefined,
    withdrawals: [chain_module.withdrawals_max]flashblocks.Withdrawal = undefined,
    /// The last flashblock produced for publication (base/base `last_emitted_flashblock_id`).
    last_emitted: FlashblockId = .{},

    // Job state, valid while `active`.
    active: bool = false,
    chain: *Chain = undefined,
    job: Job = undefined,
    template: Header = undefined,
    sealed: Header = undefined,
    env: executor_module.BlockEnv = undefined,
    withdrawals_len: u32 = 0,
    /// Next flashblock index to build.
    index: u32 = 0,
    count: u32 = 0,
    bytes_len: u32 = 0,
    gas_per_batch: u64 = 0,
    da_per_batch: ?u64 = null,
    da_used_bytes: u64 = 0,
    fees: u256 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        rejection_cache: *const best_txs.RejectionCache,
        config: Config,
    ) !Generator {
        assert(config.flashblocks_max > 0 and config.transactions_max > 0);
        assert(config.transaction_bytes_max > 0 and config.select_max > 0);
        var best = try best_txs.BestFlashblocksTxs.init(allocator, rejection_cache, .{
            .committed_max = config.transactions_max,
        });
        errdefer best.deinit(allocator);
        const transactions = try allocator.alloc([]const u8, config.transactions_max);
        errdefer allocator.free(transactions);
        const senders = try allocator.alloc(?primitives.Address, config.transactions_max);
        errdefer allocator.free(senders);
        const bytes = try allocator.alloc(u8, config.transaction_bytes_max);
        errdefer allocator.free(bytes);
        const select_buffer = try allocator.alloc(*const txpool.Tx, config.select_max);
        return .{
            .config = config,
            .best = best,
            .transactions = transactions,
            .senders = senders,
            .bytes = bytes,
            .select_buffer = select_buffer,
        };
    }

    pub fn deinit(generator: *Generator, allocator: std.mem.Allocator) void {
        allocator.free(generator.select_buffer);
        allocator.free(generator.bytes);
        allocator.free(generator.senders);
        allocator.free(generator.transactions);
        generator.best.deinit(allocator);
        generator.* = undefined;
    }

    /// Starts a job and builds flashblock 0. The chain's state must be the parent's.
    pub fn start(generator: *Generator, chain: *Chain, job: Job) Error!Flashblock {
        assert(job.flashblock_count <= generator.config.flashblocks_max);
        generator.active = false;
        const parent = chain.header(job.parent_hash) orelse return error.StateUnavailable;
        if (!std.mem.eql(u8, &chain.state_hash, &job.parent_hash)) return error.StateUnavailable;
        if (job.attributes.parent_beacon_block_root == null) {
            return error.MissingParentBeaconBlockRoot;
        }
        var template = try chain.child_header(&parent, job.parent_hash, job.attributes);
        // The chain's staging tail holds the extra data only until its next build.
        assert(template.extra_data.len <= generator.extra_data.len);
        const extra_data = generator.extra_data[0..template.extra_data.len];
        @memcpy(extra_data, template.extra_data);
        template.extra_data = extra_data;
        generator.chain = chain;
        generator.job = job;
        generator.template = template;
        generator.env = chain_module.env_of(&generator.template);
        generator.set_withdrawals(job.attributes.withdrawals orelse &.{});
        generator.reset_counters();
        const count = job.flashblock_count;
        generator.gas_per_batch = if (count > 0) template.gas_limit / count else 0;
        const da_block_bytes_max = chain.da_limits.block_bytes_max;
        generator.da_per_batch = null;
        if (count > 0 and da_block_bytes_max != 0) {
            generator.da_per_batch = da_block_bytes_max / count;
        }
        generator.best.reset_block();
        generator.active = true;
        const flashblock = try generator.build(0, 0);
        assert(flashblock.index == 0 and flashblock.base != null);
        return flashblock;
    }

    /// Builds the next regular flashblock, or null when the job has built all of them
    /// (or takes no pool transactions). `now_ns` ages the rejection cache.
    pub fn next(generator: *Generator, now_ns: u64) Error!?Flashblock {
        if (!generator.active) return error.JobInactive;
        assert(generator.index >= 1);
        if (generator.job.attributes.no_tx_pool orelse false) return null;
        if (generator.index > generator.job.flashblock_count) return null;
        const flashblock = try generator.build(generator.index, now_ns);
        assert(flashblock.index == generator.index - 1 and flashblock.base == null);
        return flashblock;
    }

    /// Every transaction of the block so far, in order.
    pub fn block_transactions(generator: *const Generator) []const []const u8 {
        assert(generator.active);
        assert(generator.count <= generator.transactions.len);
        return generator.transactions[0..generator.count];
    }

    /// The block sealed after the last flashblock (what `getPayload` returns).
    pub fn sealed_header(generator: *const Generator) *const Header {
        assert(generator.active);
        assert(generator.index >= 1);
        return &generator.sealed;
    }

    /// Priority fees paid to the fee recipient by the block so far.
    pub fn block_value(generator: *const Generator) u256 {
        assert(generator.active);
        return generator.fees;
    }

    fn reset_counters(generator: *Generator) void {
        generator.index = 0;
        generator.count = 0;
        generator.bytes_len = 0;
        generator.da_used_bytes = 0;
        generator.fees = 0;
        assert(generator.block_bytes_free() == generator.bytes.len);
    }

    fn set_withdrawals(generator: *Generator, list: []const payload.Withdrawal) void {
        assert(list.len <= generator.withdrawals.len);
        for (list, generator.withdrawals[0..list.len]) |w, *out| {
            out.* = .{
                .index = w.index,
                .validator_index = w.validator_index,
                .address = w.address,
                .amount_gwei = w.amount_gwei,
            };
        }
        generator.withdrawals_len = @intCast(list.len);
    }

    fn block_bytes_free(generator: *const Generator) usize {
        assert(generator.bytes_len <= generator.bytes.len);
        return generator.bytes.len - generator.bytes_len;
    }

    /// Re-executes the accepted prefix, adds flashblock `index`'s transactions, commits,
    /// seals, and rolls the commit back. A failed build ends the job.
    fn build(generator: *Generator, index: u32, now_ns: u64) Error!Flashblock {
        assert(generator.active and index == generator.index);
        errdefer generator.active = false;
        const chain = generator.chain;
        const executor = chain.executor;
        const start_count = generator.count;
        var building = try executor.begin_block(&generator.env);
        errdefer executor.abort_block();
        try generator.replay(&building);
        if (index == 0) {
            try generator.apply_attributes(&building);
        } else {
            try generator.apply_best(&building, index, now_ns);
        }
        assert(building.count == generator.count);
        const withdrawals = generator.job.attributes.withdrawals;
        const executed = try executor.finish_block(&building, withdrawals);
        generator.sealed = generator.template;
        const transactions = generator.transactions[0..generator.count];
        chain.seal(&generator.sealed, transactions, withdrawals, &executed);
        try chain.db.rollback();
        assert(std.mem.eql(u8, &chain.state_hash, &generator.job.parent_hash));
        generator.fees = executed.fees;
        generator.index = index + 1;
        return generator.flashblock_of(index, start_count);
    }

    fn replay(generator: *Generator, building: *Building) Error!void {
        const executor = generator.chain.executor;
        defer executor.known_sender = null;
        for (generator.transactions[0..generator.count], 0..) |raw, position| {
            executor.known_sender = generator.senders[position];
            try executor.apply(building, raw);
        }
        assert(building.count == generator.count);
    }

    /// The sequencer's transactions must all execute (as in a non-flashblocks build).
    fn apply_attributes(generator: *Generator, building: *Building) Error!void {
        assert(generator.count == 0);
        const list = generator.job.attributes.transactions orelse &.{};
        for (list) |raw| {
            if (raw.len > generator.block_bytes_free()) return error.TransactionBytesFull;
            try generator.chain.executor.apply(building, raw);
            generator.append(raw, null);
            generator.best.mark_committed(&.{primitives.keccak256(raw)});
        }
        assert(generator.count == list.len);
    }

    /// Adds best-pool transactions up to flashblock `index`'s cumulative gas and DA budget.
    /// Transactions over a budget or failing execution are skipped with their sender's
    /// later nonces (base/base `skip_current` / `mark_invalid`).
    fn apply_best(generator: *Generator, building: *Building, index: u32, now_ns: u64) Error!void {
        assert(index >= 1 and index <= generator.job.flashblock_count);
        const chain = generator.chain;
        const pool = chain.pool orelse return;
        const gas_target = @min(generator.gas_per_batch * index, generator.env.gas_limit);
        const selected = pool.select(generator.env.base_fee, generator.select_buffer);
        generator.best.refresh(generator.select_buffer[0..selected]);
        // Bounded by the snapshot: `next` advances its cursor on every call.
        while (generator.best.next(now_ns)) |tx| {
            if (generator.count == generator.transactions.len) break;
            if (building.gas_used +| tx.gas_limit > gas_target) {
                generator.best.mark_invalid(tx.sender, tx.nonce);
                continue;
            }
            const scratch = generator.bytes[generator.bytes_len..];
            const raw = chain_module.canonical_form(tx.raw, scratch) catch break;
            if (raw.len > scratch.len) break;
            const da_bytes = if (chain.spec.mode == .l2) flz.estimated_size_bytes(raw) else 0;
            if (!generator.da_admits(index, da_bytes)) {
                generator.best.mark_invalid(tx.sender, tx.nonce);
                continue;
            }
            if (!try generator.try_apply(building, tx, raw)) continue;
            generator.append(raw, tx.sender);
            generator.best.mark_current_committed();
            generator.da_used_bytes += da_bytes;
        }
        assert(generator.count == building.count);
    }

    fn da_admits(generator: *const Generator, index: u32, da_bytes: u64) bool {
        assert(index >= 1);
        const tx_bytes_max = generator.chain.da_limits.tx_bytes_max;
        if (tx_bytes_max != 0 and da_bytes > tx_bytes_max) return false;
        const per_batch = generator.da_per_batch orelse return true;
        return generator.da_used_bytes +| da_bytes <= per_batch * index;
    }

    /// Applies a pool transaction; false (sender skipped) when it cannot execute.
    fn try_apply(
        generator: *Generator,
        building: *Building,
        tx: *const txpool.Tx,
        raw: []const u8,
    ) Error!bool {
        const executor = generator.chain.executor;
        const count_before = building.count;
        // The pool recovered the sender at admission; skip a second ecrecover.
        executor.known_sender = tx.sender;
        defer executor.known_sender = null;
        executor.apply(building, raw) catch |err| switch (err) {
            error.InvalidTransaction,
            error.BlockGasExceeded,
            error.BlobGasExceeded,
            error.TxTypeNotSupported,
            => {
                assert(building.count == count_before);
                generator.best.mark_invalid(tx.sender, tx.nonce);
                return false;
            },
            else => return err,
        };
        assert(building.count == count_before + 1);
        return true;
    }

    /// Records an applied transaction, copying it into the block's byte buffer unless it
    /// is already there (a canonical-form copy). The caller checked the space.
    fn append(generator: *Generator, raw: []const u8, sender: ?primitives.Address) void {
        assert(generator.count < generator.transactions.len);
        const target = generator.bytes[generator.bytes_len..][0..raw.len];
        if (raw.ptr != target.ptr) @memcpy(target, raw);
        generator.transactions[generator.count] = target;
        generator.senders[generator.count] = sender;
        generator.count += 1;
        generator.bytes_len += @intCast(raw.len);
        assert(generator.bytes_len <= generator.bytes.len);
    }

    fn flashblock_of(generator: *Generator, index: u32, start_count: u32) Flashblock {
        assert(start_count <= generator.count);
        const sealed = &generator.sealed;
        const flashblock: Flashblock = .{
            .payload_id = generator.job.payload_id,
            .index = index,
            .base = if (index == 0) generator.payload_base() else null,
            .diff = .{
                .state_root = sealed.state_root,
                .receipts_root = sealed.receipts_root,
                .logs_bloom = sealed.logs_bloom,
                .gas_used = sealed.gas_used,
                .block_hash = sealed.hash(),
                .transactions = generator.transactions[start_count..generator.count],
                .withdrawals = generator.withdrawals[0..generator.withdrawals_len],
                .withdrawals_root = sealed.withdrawals_root orelse .zero,
                .blob_gas_used = sealed.blob_gas_used,
            },
            .metadata = .{
                .block_number = sealed.number,
                .prev_flashblock_id = generator.last_emitted,
            },
        };
        // A no-tx-pool job (syncing) publishes nothing (base/base `build_payload`).
        if (!(generator.job.attributes.no_tx_pool orelse false)) {
            generator.last_emitted = .{ .block_number = sealed.number, .index = index };
        }
        return flashblock;
    }

    fn payload_base(generator: *const Generator) flashblocks.PayloadBase {
        const template = &generator.template;
        assert(template.parent_beacon_block_root != null);
        return .{
            .parent_beacon_block_root = template.parent_beacon_block_root.?,
            .parent_hash = template.parent_hash,
            .fee_recipient = template.beneficiary,
            .prev_randao = template.mix_hash,
            .block_number = template.number,
            .gas_limit = template.gas_limit,
            .timestamp = template.timestamp,
            .extra_data = template.extra_data,
            .base_fee_per_gas = template.base_fee_per_gas orelse 0,
        };
    }
};

test {
    _ = @import("generator_test.zig");
}

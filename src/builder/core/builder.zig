//! The single-shot block builder: builds one payload job as one full block. Mirrors the
//! one-shot (post-Denim) path of base/base `crates/execution/payload/src/builder.rs`
//! (`BasePayloadBuilder::build`, `execute_best_transactions`).
//!
//! A job runs in two calls. `start` derives the block template from the parent and the
//! payload attributes and copies the attribute transactions (L1 info deposit, `BaseTime`
//! update, user deposits, forced transactions). `build` then executes, from the parent
//! state, the attribute transactions (all must succeed), then best pool transactions in
//! priority order through the `best_txs` view until the pool snapshot is exhausted, the
//! injected clock reaches the transaction cutoff (the seal offset into the slot), or the
//! block runs out of room (the gas budget is the `miner_setGasLimit` target when
//! smaller than the block gas limit). Transactions over the remaining gas or DA budget, or
//! failing execution, are skipped with their sender's later nonces (base/base `skip_current`).
//! The block is sealed once: commit, roots, header, then the commit is rolled back so the
//! chain's state stays at the parent and the node imports the block like any other.
//! The sealed header is exactly what `Chain` builds from the same transaction list.
//!
//! Resource metering (base/base `ResourceMeteringConfig` in `execute_best_transactions`) is
//! optional: with a `resource` driver installed and active, attribute transactions are
//! accounted unthrottled, each pool candidate is checked against its simulated sample before
//! the gas/DA budget checks (an enforced overrun skips it with its sender's later nonces),
//! included candidates add their executed usage, and transaction-scope excludes are evicted
//! after the scan (rejection cache, metering store, pool). Without it, or inactive, the build
//! is exactly the unmetered one.
//!
//! The builder is pinned (headers point into its extra-data buffer) and allocates only at
//! `init`; the attributes passed to `start` must outlive the job except their transaction
//! list, which is copied.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const flz = @import("../../common/flz/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const txpool = @import("../../execution/txpool/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const executor_module = @import("../../execution/node/executor.zig");
const best_txs = @import("best_txs.zig");
const resource_module = @import("../metering/resource.zig");

pub const ResourceMetering = resource_module.ResourceMetering;

const Chain = chain_module.Chain;
const Header = consensus.Header;
const Hash = [32]u8;
const Building = executor_module.Executor.Building;
const consensus_deposit_type: u8 = @backingInt(consensus.tx.TxType.deposit);
const B256 = primitives.B256;

pub const Error = chain_module.Error || error{
    MissingParentBeaconBlockRoot,
    TransactionBytesFull,
    TransactionsFull,
};

pub const Config = struct {
    /// Most transactions in one block (attribute and pool transactions).
    transactions_max: u32 = 1 << 14,
    /// Bytes for the block's transactions (each accepted transaction is copied).
    transaction_bytes_max: u32 = 16 << 20,
    /// Pool snapshot size per build.
    select_max: u32 = 1 << 14,
};

/// One payload job: the parent block and the attributes the block is built from.
pub const Job = struct {
    payload_id: [8]u8,
    parent_hash: Hash,
    attributes: *const payload.PayloadAttributes,
};

/// The injected clock `build` reads between pool transactions to honour the cutoff.
pub const Clock = struct {
    context: *anyopaque,
    read_ns: *const fn (context: *anyopaque) u64,

    pub fn now_ns(clock: Clock) u64 {
        return clock.read_ns(clock.context);
    }

    /// A clock over any `*T` with `fn now_ns(*T) u64`.
    pub fn of(comptime T: type, source: *T) Clock {
        const Adapter = struct {
            fn read(context: *anyopaque) u64 {
                const typed: *T = @ptrCast(@alignCast(context));
                return typed.now_ns();
            }
        };
        return .{ .context = source, .read_ns = Adapter.read };
    }
};

/// Why a build stopped adding pool transactions.
pub const Stop = enum {
    /// The attributes forbid pool transactions (`no_tx_pool`).
    no_tx_pool,
    /// Every transaction of the pool snapshot was offered.
    pool_exhausted,
    /// The clock reached the transaction cutoff.
    cutoff,
    /// The block holds `transactions_max` transactions.
    transactions_full,
    /// The block's transaction byte buffer is full.
    bytes_full,
};

pub const State = enum { idle, started, sealed };

pub const BlockBuilder = struct {
    config: Config,
    best: best_txs.BestTxs,
    transactions: [][]const u8,
    /// The sender of each transaction in `transactions` (zero for deposits), handed to the
    /// sequencer's import so it skips ecrecover. Valid while `senders_known`.
    senders: []primitives.Address,
    bytes: []u8,
    select_buffer: []*const txpool.Tx,
    cache: *best_txs.RejectionCache,
    /// Transaction-scope resource-metering excludes of the current build (pool evictions).
    rejected: []B256,
    rejected_count: u32 = 0,
    /// Resource metering in transaction selection; null builds unmetered.
    resource: ?*ResourceMetering = null,
    extra_data: [chainspec.basefee.jovian_extra_data_size]u8 = undefined,
    state: State = .idle,

    // Job state, valid unless `idle`.
    chain: *Chain = undefined,
    job: Job = undefined,
    template: Header = undefined,
    sealed: Header = undefined,
    env: executor_module.BlockEnv = undefined,
    /// Attribute transactions at the front of `transactions`.
    forced_count: u32 = 0,
    count: u32 = 0,
    /// False when a forced transaction is not a deposit: its sender is not recovered here,
    /// so the import recovers every sender itself.
    senders_known: bool = true,
    bytes_len: u32 = 0,
    da_used_bytes: u64 = 0,
    fees: u256 = 0,
    stop: Stop = .pool_exhausted,
    /// The last clock reading of the build.
    now_ns: u64 = 0,
    /// The attribute transactions' resource usage is in the cumulative usage.
    forced_accounted: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        rejection_cache: *best_txs.RejectionCache,
        config: Config,
    ) !BlockBuilder {
        assert(config.transactions_max > 0);
        assert(config.transaction_bytes_max > 0 and config.select_max > 0);
        var best = try best_txs.BestTxs.init(allocator, rejection_cache, .{
            .committed_max = config.transactions_max,
        });
        errdefer best.deinit(allocator);
        const transactions = try allocator.alloc([]const u8, config.transactions_max);
        errdefer allocator.free(transactions);
        const senders = try allocator.alloc(primitives.Address, config.transactions_max);
        errdefer allocator.free(senders);
        const bytes = try allocator.alloc(u8, config.transaction_bytes_max);
        errdefer allocator.free(bytes);
        const select_buffer = try allocator.alloc(*const txpool.Tx, config.select_max);
        errdefer allocator.free(select_buffer);
        const rejected = try allocator.alloc(B256, config.select_max);
        return .{
            .config = config,
            .best = best,
            .transactions = transactions,
            .senders = senders,
            .bytes = bytes,
            .select_buffer = select_buffer,
            .cache = rejection_cache,
            .rejected = rejected,
        };
    }

    pub fn deinit(builder: *BlockBuilder, allocator: std.mem.Allocator) void {
        allocator.free(builder.rejected);
        allocator.free(builder.select_buffer);
        allocator.free(builder.bytes);
        allocator.free(builder.senders);
        allocator.free(builder.transactions);
        builder.best.deinit(allocator);
        builder.* = undefined;
    }

    /// Starts a job: derives the template and copies the attribute transactions. Executes
    /// nothing. The chain's state must be the parent's. Ends any previous job.
    pub fn start(builder: *BlockBuilder, chain: *Chain, job: Job) Error!void {
        builder.state = .idle;
        const parent = chain.header(job.parent_hash) orelse return error.StateUnavailable;
        if (!std.mem.eql(u8, &chain.state_hash, &job.parent_hash)) return error.StateUnavailable;
        if (job.attributes.parent_beacon_block_root == null) {
            return error.MissingParentBeaconBlockRoot;
        }
        var template = try chain.child_header(&parent, job.parent_hash, job.attributes);
        // The chain's staging tail holds the extra data only until its next build.
        assert(template.extra_data.len <= builder.extra_data.len);
        const extra_data = builder.extra_data[0..template.extra_data.len];
        @memcpy(extra_data, template.extra_data);
        template.extra_data = extra_data;
        builder.chain = chain;
        builder.job = job;
        builder.template = template;
        builder.env = chain_module.env_of(&builder.template);
        builder.count = 0;
        builder.bytes_len = 0;
        builder.da_used_bytes = 0;
        builder.fees = 0;
        const list = job.attributes.transactions orelse &.{};
        if (list.len > builder.transactions.len) return error.TransactionsFull;
        for (list) |raw| {
            if (raw.len > builder.block_bytes_free()) return error.TransactionBytesFull;
            builder.append(raw);
        }
        builder.forced_count = builder.count;
        builder.state = .started;
        assert(builder.forced_count == list.len);
    }

    /// Builds and seals the block: attribute transactions, then pool transactions until
    /// `clock` reaches `cutoff_ns` (or the pool or block runs out). A failed build ends the
    /// job; the chain's state is back at the parent either way.
    pub fn build(builder: *BlockBuilder, clock: Clock, cutoff_ns: u64) Error!Stop {
        assert(builder.state == .started);
        assert(builder.count == builder.forced_count);
        errdefer builder.state = .idle;
        const chain = builder.chain;
        const executor = chain.executor;
        var building = try executor.begin_block(&builder.env);
        errdefer executor.abort_block();
        builder.best.reset_block();
        builder.rejected_count = 0;
        builder.forced_accounted = false;
        if (builder.resource) |resource| resource.begin_build();
        try builder.apply_forced(&building);
        builder.stop = try builder.apply_best(&building, clock, cutoff_ns);
        if (!builder.forced_accounted and builder.active_resource() != null) {
            builder.now_ns = clock.now_ns();
            builder.account_forced(&building);
        }
        builder.evict_rejected();
        assert(building.count == builder.count);
        const withdrawals = builder.job.attributes.withdrawals;
        const executed = try executor.finish_block(&building, withdrawals);
        builder.sealed = builder.template;
        const transactions = builder.transactions[0..builder.count];
        chain.seal(&builder.sealed, transactions, withdrawals, &executed);
        try chain.db.rollback();
        assert(std.mem.eql(u8, &chain.state_hash, &builder.job.parent_hash));
        builder.fees = executed.fees;
        builder.state = .sealed;
        return builder.stop;
    }

    /// Every transaction of the sealed block, in order.
    pub fn block_transactions(builder: *const BlockBuilder) []const []const u8 {
        assert(builder.state == .sealed);
        assert(builder.count <= builder.transactions.len);
        return builder.transactions[0..builder.count];
    }

    /// The sender of every transaction of the sealed block, in order (zero for deposits), or
    /// empty when not all are known (the import then recovers them).
    pub fn block_senders(builder: *const BlockBuilder) []const primitives.Address {
        assert(builder.state == .sealed);
        assert(builder.count <= builder.senders.len);
        if (!builder.senders_known) return &.{};
        return builder.senders[0..builder.count];
    }

    /// The sealed block's header (what `getPayload` returns).
    pub fn sealed_header(builder: *const BlockBuilder) *const Header {
        assert(builder.state == .sealed);
        assert(builder.sealed.number == builder.template.number);
        return &builder.sealed;
    }

    /// Priority fees paid to the fee recipient by the sealed block.
    pub fn block_value(builder: *const BlockBuilder) u256 {
        assert(builder.state == .sealed);
        return builder.fees;
    }

    fn block_bytes_free(builder: *const BlockBuilder) usize {
        assert(builder.bytes_len <= builder.bytes.len);
        return builder.bytes.len - builder.bytes_len;
    }

    /// The sequencer's transactions must all execute (as in a `Chain` build).
    fn apply_forced(builder: *BlockBuilder, building: *Building) Error!void {
        assert(building.count == 0);
        const executor = builder.chain.executor;
        builder.senders_known = true;
        const forced = builder.transactions[0..builder.forced_count];
        for (forced, builder.senders[0..builder.forced_count]) |raw, *sender| {
            assert(raw.len > 0);
            sender.* = primitives.Address.zero;
            if (raw[0] != consensus_deposit_type) builder.senders_known = false;
            try executor.apply(building, raw);
            builder.best.mark_committed(&.{primitives.keccak256(raw)});
        }
        assert(building.count == builder.forced_count);
    }

    /// Adds best-pool transactions until the cutoff or the snapshot ends. Transactions over
    /// the gas or DA budget are skipped with their sender's later nonces.
    fn apply_best(
        builder: *BlockBuilder,
        building: *Building,
        clock: Clock,
        cutoff_ns: u64,
    ) Error!Stop {
        if (builder.job.attributes.no_tx_pool orelse false) return .no_tx_pool;
        const chain = builder.chain;
        const pool = chain.pool orelse return .pool_exhausted;
        const selected = pool.select(builder.env.base_fee, builder.select_buffer);
        builder.best.refresh(builder.select_buffer[0..selected]);
        const gas_budget = builder.pool_gas_budget();
        // Bounded by the snapshot: `next` advances its cursor on every call.
        var offered: usize = 0;
        while (offered <= selected) : (offered += 1) {
            const now_ns = clock.now_ns();
            builder.now_ns = now_ns;
            if (!builder.forced_accounted) builder.account_forced(building);
            if (now_ns >= cutoff_ns) return .cutoff;
            const tx = builder.best.next(now_ns) orelse return .pool_exhausted;
            if (builder.count == builder.transactions.len) return .transactions_full;
            const admission = builder.check_resources(tx, now_ns) orelse continue;
            if (building.gas_used +| tx.gas_limit > gas_budget) {
                builder.best.mark_invalid(tx.sender, tx.nonce);
                continue;
            }
            const scratch = builder.bytes[builder.bytes_len..];
            const raw = chain_module.canonical_form(tx.raw, scratch) catch return .bytes_full;
            if (raw.len > scratch.len) return .bytes_full;
            const da_bytes = if (chain.spec.mode == .l2) flz.estimated_size_bytes(raw) else 0;
            if (!chain.da_limits.admits(builder.da_used_bytes, da_bytes)) {
                builder.best.mark_invalid(tx.sender, tx.nonce);
                continue;
            }
            const gas_before = building.gas_used;
            if (!try builder.try_apply(building, tx, raw)) continue;
            if (builder.active_resource()) |resource| {
                _ = resource.account_executed(building.gas_used - gas_before, admission.sample);
            }
            builder.senders[builder.count] = tx.sender;
            builder.append(raw);
            builder.best.mark_current_committed();
            builder.da_used_bytes += da_bytes;
        }
        // Each pass consumed one of at most `selected` snapshot entries or returned.
        unreachable;
    }

    /// Accounts the attribute transactions unthrottled (base/base
    /// `execute_sequencer_transactions`), at the build's first clock reading so an unmetered
    /// build reads the clock exactly as before. Each one's gas comes from its receipt.
    fn account_forced(builder: *BlockBuilder, building: *const Building) void {
        assert(!builder.forced_accounted);
        assert(building.count >= builder.forced_count);
        builder.forced_accounted = true;
        const resource = builder.active_resource() orelse return;
        var gas_before: u64 = 0;
        for (builder.transactions[0..builder.forced_count], 0..) |raw, index| {
            const gas_after = building.receipts[index].cumulative_gas_used;
            const hash = primitives.keccak256(raw);
            resource.account_unthrottled(hash, gas_after - gas_before, builder.now_ns);
            gas_before = gas_after;
        }
    }

    /// The resource-metering driver when installed and active.
    fn active_resource(builder: *const BlockBuilder) ?*ResourceMetering {
        const resource = builder.resource orelse return null;
        if (!resource.is_active()) return null;
        assert(resource.cumulative_usage().len > 0);
        return resource;
    }

    /// The simulated resource check (base/base `check_simulated_usage`): null when an
    /// enforced overrun excludes `tx` (skipped with its sender's later nonces; recorded for
    /// eviction when transaction-scope).
    fn check_resources(
        builder: *BlockBuilder,
        tx: *const txpool.Tx,
        now_ns: u64,
    ) ?resource_module.Admission {
        const resource = builder.active_resource() orelse
            return .{ .decision = .allow, .sample = null };
        const admission = resource.check_simulated(tx.hash, now_ns);
        if (!admission.should_exclude()) return admission;
        builder.best.mark_invalid(tx.sender, tx.nonce);
        if (admission.is_permanent()) {
            // Each snapshot entry is offered at most once and `rejected` holds `select_max`.
            assert(builder.rejected_count < builder.rejected.len);
            builder.rejected[builder.rejected_count] = tx.hash;
            builder.rejected_count += 1;
        }
        return null;
    }

    /// Evicts the build's transaction-scope excludes: no block can hold them (base/base
    /// marks them in the rejection cache, drops their metering, and removes them from the
    /// pool after the scan).
    fn evict_rejected(builder: *BlockBuilder) void {
        const rejected = builder.rejected[0..builder.rejected_count];
        if (rejected.len == 0) return;
        assert(builder.resource != null);
        builder.cache.mark_rejected(rejected, builder.now_ns);
        if (builder.resource.?.store) |store| store.remove(rejected, builder.now_ns);
        const pool = builder.chain.pool orelse return;
        for (rejected) |hash| _ = pool.remove(hash);
    }

    /// Gas the block may fill with pool transactions: the `miner_setGasLimit` target when
    /// set and smaller, else the block gas limit (base/base `execute_best_transactions`,
    /// `GasLimitConfig`). The attribute transactions count against it, as in base/base.
    fn pool_gas_budget(builder: *const BlockBuilder) u64 {
        const target = builder.chain.gas_limit_target;
        const gas_limit = builder.env.gas_limit;
        const budget = if (target == 0) gas_limit else @min(target, gas_limit);
        assert(budget <= builder.env.gas_limit);
        assert(target == 0 or budget <= target);
        return budget;
    }

    /// Applies a pool transaction; false (sender skipped) when it cannot execute.
    fn try_apply(
        builder: *BlockBuilder,
        building: *Building,
        tx: *const txpool.Tx,
        raw: []const u8,
    ) Error!bool {
        const executor = builder.chain.executor;
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
                builder.best.mark_invalid(tx.sender, tx.nonce);
                return false;
            },
            else => return err,
        };
        assert(building.count == count_before + 1);
        return true;
    }

    /// Records a transaction, copying it into the block's byte buffer unless it is already
    /// there (a canonical-form copy). The caller checked the space.
    fn append(builder: *BlockBuilder, raw: []const u8) void {
        assert(builder.count < builder.transactions.len);
        const target = builder.bytes[builder.bytes_len..][0..raw.len];
        if (raw.ptr != target.ptr) @memcpy(target, raw);
        builder.transactions[builder.count] = target;
        builder.count += 1;
        builder.bytes_len += @intCast(raw.len);
        assert(builder.bytes_len <= builder.bytes.len);
    }
};

test {
    _ = @import("builder_test.zig");
}

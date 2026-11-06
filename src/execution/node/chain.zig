//! The chain: the `engine.Engine` backend. Imports payloads (header checks against the
//! parent, execution, root checks), keeps the canonical chain from forkchoice updates,
//! moves the single in-memory state between branches (undo-journal rollback plus
//! re-execution of stored blocks), and builds payloads from attributes and the txpool.
//!
//! Each stored block record is `rlp([header, [tx...], withdrawals | "", [receipt...],
//! [request...]])` with transactions and receipts as EIP-2718 byte strings.

const std = @import("std");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const flz = @import("../../common/flz/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const evm = @import("../evm/root.zig");
const engine = @import("../engine/root.zig");
const ordered = @import("../trie/ordered.zig");
const executor_module = @import("executor.zig");
const block_store = @import("block_store.zig");
const base_time = @import("base_time.zig");
const StateDb = @import("state_db.zig").StateDb;
const witness_block = @import("../db/witness_block.zig");
const db_database = @import("../db/database.zig");
const db_history = @import("../db/history.zig");
const history_module = db_history;
const StateTrie = @import("../trie/state_trie.zig").StateTrie;

const Hash = [32]u8;
const B256 = primitives.B256;
const Header = consensus.Header;
const Executor = executor_module.Executor;

pub const builds_max = 8;
pub const withdrawals_max = engine.block.withdrawals_per_payload_max;
/// Longest chain of stored blocks re-executed to reach a state (reorg depth bound).
pub const reexecute_max = 256;
const l2_to_l1_message_passer: [20]u8 =
    primitives.hex.decode_array(20, "4200000000000000000000000000000000000016") catch unreachable;

pub const Config = struct {
    /// The state db holds a restored head's state, not genesis (durable restart): skip
    /// the genesis root check; `restore` re-adds the retained blocks.
    restoring: bool = false,
    store: block_store.Config = .{},
    staging_bytes: u32 = 32 << 20,
    select_max: u32 = 4096,
    /// Transactions findable by hash (most recent stored blocks).
    tx_index_max: u32 = 1 << 16,
    /// Block-body copies of pooled blob transactions during one build.
    build_bytes: u32 = 4 << 20,
};

pub const BuiltPayload = struct {
    id: payload.PayloadId,
    timestamp: u64,
    block_hash: B256,
    /// Priority fees paid to the fee recipient (wei).
    block_value: u256,
};

/// A block sealed by an external payload builder (`builder/core`), resolved by getPayload.
/// Slices borrow the builder until its next job.
pub const SealedPayload = struct {
    header: Header,
    block_hash: B256,
    block_value: u256,
    transactions: []const []const u8,
    withdrawals: ?[]const payload.Withdrawal,
};

pub const Resolved = union(enum) {
    /// `id` is not the builder's active job.
    unknown,
    /// The job's build failed.
    failed,
    sealed: SealedPayload,
};

/// An external payload builder in front of the synchronous `Chain` build: an FCU with
/// attributes starts its job and returns at once; getPayload resolves the sealed block,
/// which the chain then imports like any other block (`builder/core` `NodeBuilder`).
pub const PayloadBuilder = struct {
    context: *anyopaque,
    start: *const fn (
        context: *anyopaque,
        id: payload.PayloadId,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) engine.EngineError!void,
    resolve: *const fn (context: *anyopaque, id: payload.PayloadId) Resolved,
};

pub const Error = executor_module.Error || block_store.Error || error{
    StagingFull,
    InvalidRecord,
    StateUnavailable,
    InvalidAttributes,
};

pub const Record = struct {
    header: Header,
    transactions: rlp.Decoder,
    withdrawals: ?consensus.block.Withdrawals,
    receipts: rlp.Decoder,
    requests: rlp.Decoder,

    pub fn decode(bytes: []const u8) Error!Record {
        return decode_fields(bytes) catch error.InvalidRecord;
    }

    fn decode_fields(bytes: []const u8) !Record {
        var outer = rlp.Decoder.init(bytes);
        var items = try outer.list();
        try outer.finish();
        const header = try Header.rlp_decode(&items);
        const transactions = try items.list();
        var withdrawals: ?consensus.block.Withdrawals = null;
        if ((try items.peek_header()).list) {
            withdrawals = try consensus.block.Withdrawals.decode_list(&items);
        } else if ((try items.bytes()).len != 0) return error.InvalidRecord;
        const receipts = try items.list();
        const requests = try items.list();
        try items.finish();
        return .{
            .header = header,
            .transactions = transactions,
            .withdrawals = withdrawals,
            .receipts = receipts,
            .requests = requests,
        };
    }
};

pub const TxLocation = struct { block_hash: Hash, index: u32 };

/// A stored block as the durable journal records it: the record bytes (header, body,
/// receipts, requests) and the changeset `StateDb` just applied for it.
pub const JournalBlock = struct {
    hash: Hash,
    parent_hash: Hash,
    number: u64,
    timestamp: u64,
    header: []const u8,
    record: []const u8,
    changeset: []const u8,
};

pub const JournalError = error{ JournalBusy, JournalFailed };

/// Durable journal of executed blocks (`durable.zig`). Every stored block is committed
/// right after execution (state already applied, journal head moves to it), and every
/// other state move is a journal head move that unwinds/applies stored changesets on the
/// shared state instead of re-executing.
pub const Journal = struct {
    context: *anyopaque,
    commit_block: *const fn (context: *anyopaque, block: *const JournalBlock) JournalError!void,
    move_head: *const fn (context: *anyopaque, hash: Hash) JournalError!void,
    /// Execution witness of a stored canonical block, with the state moved in memory only
    /// (`node/witness.zig`); null when the journal cannot produce one.
    witness: ?*const fn (
        context: *anyopaque,
        generator: *witness_block.Generator,
        hash: Hash,
        execute: witness_block.Execute,
    ) witness_block.Error!Hash = null,
    /// `eth_getProof` at block `number` (hash `hash`, which must be canonical in the
    /// journal) of the journal's history window (`Database.proof_at`); null when the
    /// journal keeps no history.
    proof: ?*const fn (
        context: *anyopaque,
        hash: Hash,
        number: u64,
        address: [20]u8,
        slots: []const u256,
        account_proof: *StateTrie.AccountProof,
        storage_proofs: []StateTrie.StorageProof,
        values: []u256,
    ) db_database.ProofError!?db_history.AccountState = null,
    /// `proof` for many slots in one storage walk (`Database.proofs_at`): the slots'
    /// proofs and values land in `set`, valid until the journal's next head move; null
    /// when the journal keeps no history.
    proofs: ?*const fn (
        context: *anyopaque,
        hash: Hash,
        number: u64,
        address: [20]u8,
        slots: []const u256,
        account_proof: *StateTrie.AccountProof,
        set: *db_history.ProofSet,
    ) db_database.ProofError!?db_history.AccountState = null,
    /// The journal's history window (oldest and newest block); null when it keeps none.
    history_window: ?*const fn (context: *anyopaque) ?HistoryWindow = null,
};

/// Builder DA limits set by the batcher (`miner_setMaxDASize`); 0 means no limit. Sizes
/// are FastLZ-estimated compressed bytes of the EIP-2718 encoding (base/base
/// `estimated_da_size`). Applied to pool transactions on L2 only.
pub const DaLimits = struct {
    tx_bytes_max: u64 = 0,
    block_bytes_max: u64 = 0,

    /// Whether a transaction of `size_bytes` fits after `used_bytes` of the block.
    pub fn admits(limits: DaLimits, used_bytes: u64, size_bytes: u64) bool {
        if (limits.tx_bytes_max != 0 and size_bytes > limits.tx_bytes_max) return false;
        const total = used_bytes +| size_bytes;
        return limits.block_bytes_max == 0 or total <= limits.block_bytes_max;
    }
};

/// Blocks whose state the history serves (`debug_proofsSyncStatus`).
pub const HistoryWindow = struct { oldest: u64, head: u64 };

/// The senders of the last few executed blocks, by block hash: pool pruning on
/// forkchoice reuses them instead of recovering every included transaction again.
const RecentSenders = struct {
    const blocks_max = 4;

    hashes: [blocks_max]Hash = @splat(@splat(0)),
    lengths: [blocks_max]u32 = @splat(0),
    valid: [blocks_max]bool = @splat(false),
    buffer: []primitives.Address = &.{},
    per_block: u32 = 0,
    next: u32 = 0,

    fn init(allocator: std.mem.Allocator, per_block: u32) !RecentSenders {
        assert(per_block > 0);
        const buffer = try lazy.alloc(allocator, primitives.Address, blocks_max * per_block);
        return .{ .buffer = buffer, .per_block = per_block };
    }

    fn deinit(recent: *RecentSenders, allocator: std.mem.Allocator) void {
        if (recent.buffer.len > 0) lazy.free(allocator, recent.buffer);
        recent.* = .{};
    }

    fn put(recent: *RecentSenders, hash: Hash, senders: []const primitives.Address) void {
        if (recent.per_block == 0 or senders.len > recent.per_block) return;
        const slot = recent.next;
        recent.next = (recent.next + 1) % blocks_max;
        const start = slot * recent.per_block;
        @memcpy(recent.buffer[start..][0..senders.len], senders);
        recent.hashes[slot] = hash;
        recent.lengths[slot] = @intCast(senders.len);
        recent.valid[slot] = true;
        assert(recent.next < blocks_max);
    }

    fn get(recent: *const RecentSenders, hash: Hash) ?[]const primitives.Address {
        for (0..blocks_max) |slot| {
            if (!recent.valid[slot]) continue;
            if (!std.mem.eql(u8, &recent.hashes[slot], &hash)) continue;
            const start = slot * recent.per_block;
            return recent.buffer[start..][0..recent.lengths[slot]];
        }
        return null;
    }
};

pub const Chain = struct {
    pub const Built = BuiltPayload;

    spec: *const chainspec.ChainSpec,
    db: *StateDb,
    executor: *Executor,
    store: block_store.BlockStore,
    pool: ?*txpool.Pool = null,
    journal: ?Journal = null,
    /// Historical proofs window following the executed state (`attach_history`).
    history: ?*history_module.Store = null,
    /// Times the window was rebuilt from scratch (reorgs, moves, full store).
    history_resets: u64 = 0,
    da_limits: DaLimits = .{},
    /// `miner_setGasLimit`: gas the builder fills with pool transactions, capped by the
    /// block gas limit; 0 fills the whole block (base/base `GasLimitConfig`).
    gas_limit_target: u64 = 0,
    staging: []u8,
    select_buffer: []*const txpool.Tx,
    transactions_buffer: [][]const u8,
    recent_senders: RecentSenders = .{},
    build_bytes: []u8,
    build_len: usize = 0,
    tx_index: std.AutoHashMapUnmanaged(Hash, TxLocation),
    /// Insertion-ordered ring of indexed hashes; the oldest is dropped when full.
    tx_ring: []Hash,
    tx_ring_head: u64 = 0,
    /// Block whose post-state `db` holds.
    state_hash: Hash,
    genesis_hash: Hash,
    /// Genesis time: forks at or before it are not part of the EIP-2124 fork id.
    genesis_timestamp: u64,
    genesis_number: u64,
    forkchoice: engine.ForkchoiceState,
    builds: [builds_max]Built = undefined,
    builds_len: u32 = 0,
    builds_next: u32 = 0,
    /// When set, payload jobs go to this builder instead of the synchronous `build`.
    payload_builder: ?PayloadBuilder = null,

    /// `db` must already hold the genesis state, whose root `genesis` commits to.
    pub fn init(
        allocator: std.mem.Allocator,
        spec: *const chainspec.ChainSpec,
        db: *StateDb,
        executor: *Executor,
        genesis: *const Header,
        config: Config,
    ) !Chain {
        assert(genesis.number == 0);
        if (!config.restoring) {
            assert(std.mem.eql(u8, &genesis.state_root.bytes, &(try db.root())));
        }
        var store = try block_store.BlockStore.init(allocator, config.store);
        errdefer store.deinit(allocator);
        const staging = try lazy.alloc(allocator, u8, config.staging_bytes);
        errdefer lazy.free(allocator, staging);
        const select_buffer = try allocator.alloc(*const txpool.Tx, config.select_max);
        errdefer allocator.free(select_buffer);
        const transactions_buffer = try allocator.alloc([]const u8, executor.transactions_max);
        errdefer allocator.free(transactions_buffer);
        const build_bytes = try lazy.alloc(allocator, u8, config.build_bytes);
        errdefer lazy.free(allocator, build_bytes);
        assert(config.tx_index_max > 0);
        var tx_index: std.AutoHashMapUnmanaged(Hash, TxLocation) = .empty;
        try tx_index.ensureTotalCapacity(allocator, config.tx_index_max);
        errdefer tx_index.deinit(allocator);
        const tx_ring = try allocator.alloc(Hash, config.tx_index_max);
        const hash = genesis.hash().bytes;
        var chain: Chain = .{
            .spec = spec,
            .db = db,
            .executor = executor,
            .store = store,
            .staging = staging,
            .select_buffer = select_buffer,
            .transactions_buffer = transactions_buffer,
            .build_bytes = build_bytes,
            .tx_index = tx_index,
            .tx_ring = tx_ring,
            .state_hash = hash,
            .genesis_hash = hash,
            .genesis_timestamp = genesis.timestamp,
            .genesis_number = genesis.number,
            .forkchoice = .{
                .head_block_hash = .{ .bytes = hash },
                .safe_block_hash = .zero,
                .finalized_block_hash = .zero,
            },
        };
        chain.recent_senders = try RecentSenders.init(allocator, executor.transactions_max);
        errdefer chain.recent_senders.deinit(allocator);
        const genesis_record = try chain.encode_record(genesis, &.{}, null, &.{}, &.{});
        try chain.store.put(ref_of(genesis, hash), genesis_record);
        chain.store.set_canonical(0, hash);
        db.set_block_hash(0, hash);
        return chain;
    }

    pub fn deinit(chain: *Chain, allocator: std.mem.Allocator) void {
        allocator.free(chain.tx_ring);
        chain.recent_senders.deinit(allocator);
        chain.tx_index.deinit(allocator);
        lazy.free(allocator, chain.build_bytes);
        allocator.free(chain.transactions_buffer);
        allocator.free(chain.select_buffer);
        lazy.free(allocator, chain.staging);
        chain.store.deinit(allocator);
        chain.* = undefined;
    }

    // ---- Engine backend -------------------------------------------------------------

    pub fn block(chain: *Chain, hash: B256) ?engine.BlockRef {
        const stored = chain.store.ref(hash.bytes) orelse return null;
        return .{
            .hash = .{ .bytes = stored.hash },
            .parent_hash = .{ .bytes = stored.parent_hash },
            .number = stored.number,
            .timestamp = stored.timestamp,
        };
    }

    pub fn is_ancestor(chain: *Chain, ancestor: B256, descendant: B256) bool {
        const target = chain.store.ref(ancestor.bytes) orelse return false;
        var cursor = chain.store.ref(descendant.bytes) orelse return false;
        while (cursor.number > target.number) {
            cursor = chain.store.ref(cursor.parent_hash) orelse return false;
        }
        return std.mem.eql(u8, &cursor.hash, &target.hash);
    }

    pub fn insert(
        chain: *Chain,
        p: *const engine.ExecutionPayload,
        params: *const engine.NewPayloadParams,
    ) engine.InsertResult {
        const imported = engine.block.ensure_well_formed(chain.spec, p, params) catch |err| {
            return .{ .invalid = @errorName(err) };
        };
        const parent = chain.header(p.parent_hash.bytes) orelse return .syncing;
        if (chain.check_header(&parent, &imported)) |reason| return .{ .invalid = reason };
        if (chain.check_subsecond(&imported, p.transactions)) |reason| {
            return .{ .invalid = reason };
        }
        chain.move_state(p.parent_hash.bytes) catch return .syncing;
        const withdrawals = p.withdrawals;
        const env = env_of(&imported);
        const executor = chain.executor;
        const executed = executor.execute_block(&env, p.transactions, withdrawals) catch |err| {
            return .{ .invalid = @errorName(err) };
        };
        if (chain.check_executed(&imported, &executed)) |reason| {
            chain.db.rollback() catch unreachable; // The commit just recorded its undo.
            return .{ .invalid = reason };
        }
        chain.store_block(&imported, p.transactions, withdrawals, &executed) catch |err| {
            chain.db.rollback() catch unreachable;
            return .{ .invalid = @errorName(err) };
        };
        chain.settle_head();
        return .valid;
    }

    pub fn set_forkchoice(
        chain: *Chain,
        state: engine.ForkchoiceState,
    ) engine.EngineError!engine.ForkchoiceApplied {
        const head = state.head_block_hash.bytes;
        chain.move_state(head) catch return .syncing;
        chain.mark_canonical(head);
        chain.forkchoice = state;
        return .applied;
    }

    pub fn start_build(
        chain: *Chain,
        id: payload.PayloadId,
        parent: engine.BlockRef,
        attributes: *const payload.PayloadAttributes,
    ) engine.EngineError!void {
        if (chain.payload_builder) |builder| {
            return builder.start(builder.context, id, parent.hash.bytes, attributes);
        }
        const entry = chain.build(id, parent.hash.bytes, attributes) catch |err| switch (err) {
            error.InvalidAttributes, error.InvalidTransaction => {
                return error.InvalidPayloadAttributes;
            },
            else => return error.InternalError,
        };
        chain.remember_build(entry);
        chain.settle_head();
    }

    fn remember_build(chain: *Chain, entry: Built) void {
        assert(chain.builds_next < builds_max);
        chain.builds[chain.builds_next] = entry;
        chain.builds_next = (chain.builds_next + 1) % builds_max;
        chain.builds_len = @min(chain.builds_len + 1, builds_max);
        assert(chain.builds_len <= builds_max);
    }

    /// The payload `id`: the external builder's active job (sealed and imported now), else
    /// a build already done.
    pub fn built(chain: *Chain, id: payload.PayloadId) ?Built {
        if (chain.payload_builder) |builder| switch (builder.resolve(builder.context, id)) {
            .unknown => {},
            .failed => return null,
            .sealed => |*sealed| return chain.import_sealed(id, sealed),
        };
        for (chain.builds[0..chain.builds_len]) |entry| {
            if (std.mem.eql(u8, &entry.id, &id)) return entry;
        }
        return null;
    }

    /// Imports an externally sealed block through the regular `insert` path (re-executing
    /// it, which also checks the builder's roots) and records it as payload `id`.
    fn import_sealed(chain: *Chain, id: payload.PayloadId, sealed: *const SealedPayload) ?Built {
        assert(sealed.header.hash().eql(sealed.block_hash));
        var execution_payload = engine.block.payload_of(
            &sealed.header,
            sealed.block_hash,
            sealed.transactions,
            sealed.withdrawals,
        );
        if (chain.spec.mode == .l2) {
            execution_payload.withdrawals_root = sealed.header.withdrawals_root;
        }
        const requests: []const []const u8 = &.{};
        const params: engine.NewPayloadParams = .{
            .parent_beacon_block_root = sealed.header.parent_beacon_block_root,
            .execution_requests = if (sealed.header.requests_hash != null) requests else null,
        };
        const known = chain.store.ref(sealed.block_hash.bytes) != null;
        if (!known and chain.insert(&execution_payload, &params) != .valid) return null;
        const entry: Built = .{
            .id = id,
            .timestamp = sealed.header.timestamp,
            .block_hash = sealed.block_hash,
            .block_value = sealed.block_value,
        };
        chain.remember_build(entry);
        assert(chain.store.ref(sealed.block_hash.bytes) != null);
        return entry;
    }

    // ---- Queries --------------------------------------------------------------------

    pub fn header(chain: *const Chain, hash: Hash) ?Header {
        const bytes = chain.store.record(hash) orelse return null;
        const decoded = Record.decode(bytes) catch unreachable; // Written by this chain.
        return decoded.header;
    }

    pub fn record(chain: *const Chain, hash: Hash) ?Record {
        const bytes = chain.store.record(hash) orelse return null;
        return Record.decode(bytes) catch unreachable; // Written by this chain.
    }

    pub fn head_hash(chain: *const Chain) Hash {
        return chain.forkchoice.head_block_hash.bytes;
    }

    /// The execution payload of a stored block (for `engine_getPayload`). Transactions
    /// borrow the store; `transactions` must hold the block's transaction count.
    pub fn payload_of(
        chain: *const Chain,
        hash: Hash,
        transactions: [][]const u8,
        withdrawals: *[withdrawals_max]payload.Withdrawal,
    ) ?engine.ExecutionPayload {
        var stored = chain.record(hash) orelse return null;
        var count: usize = 0;
        while (!stored.transactions.is_empty()) : (count += 1) {
            transactions[count] = stored.transactions.bytes() catch unreachable;
        }
        const list = if (stored.withdrawals) |w| convert_withdrawals(w, withdrawals) else null;
        const block_hash: B256 = .{ .bytes = hash };
        const used = transactions[0..count];
        var result = engine.block.payload_of(&stored.header, block_hash, used, list);
        if (chain.spec.mode == .l2) result.withdrawals_root = stored.header.withdrawals_root;
        return result;
    }

    // ---- Import ---------------------------------------------------------------------

    /// The chain's Denim timestamp schedule, when Denim is scheduled on an L2.
    pub fn denim_schedule(chain: *const Chain) ?base_time.Schedule {
        if (chain.spec.mode != .l2) return null;
        const activation = chain.spec.upgrades[@backingInt(chainspec.Upgrade.denim)] orelse
            return null;
        assert(chain.spec.block_time_seconds > 0);
        return .{
            .genesis_block_number = chain.genesis_number,
            .genesis_timestamp = chain.genesis_timestamp,
            .legacy_interval_seconds = chain.spec.block_time_seconds,
            .denim_activation_timestamp = activation,
        };
    }

    /// Denim subsecond blocks: the header timestamp is the schedule's (selected by block
    /// number, so a block cannot dodge it by claiming an earlier time), and the BaseTime
    /// deposit at index 1 carries the schedule's millisecond part. base/base checks the
    /// millisecond part as a 200 ms step from the parent's stored part after execution;
    /// with every ancestor on the schedule the two agree.
    pub fn check_subsecond(
        chain: *const Chain,
        child: *const Header,
        transactions: []const []const u8,
    ) ?[]const u8 {
        const schedule = chain.denim_schedule() orelse return null;
        if (child.number == schedule.genesis_block_number) return null;
        if (!schedule.subsecond_at(child.number)) return null;
        const expected = schedule.parts(child.number);
        if (child.timestamp != expected.seconds) return "timestamp off the subsecond schedule";
        const second: ?consensus.Envelope = if (transactions.len > 1)
            consensus.Envelope.decode(transactions[1]) catch return "invalid BaseTime deposit"
        else
            null;
        const millis_part = consensus.base_time.extract(second, child.number) catch
            return "invalid BaseTime deposit";
        if (millis_part != expected.millis_part) return "BaseTime millisecond part off schedule";
        return null;
    }

    /// Consensus checks of `child` against `parent` that do not need execution.
    fn check_header(chain: *const Chain, parent: *const Header, child: *const Header) ?[]const u8 {
        if (child.gas_used > child.gas_limit) return "gas used above gas limit";
        const expected_base_fee = chain.spec.next_base_fee(.{
            .timestamp = parent.timestamp,
            .gas_used = parent.gas_used,
            .gas_limit = parent.gas_limit,
            .base_fee = parent.base_fee_per_gas orelse 0,
            .blob_gas_used = parent.blob_gas_used orelse 0,
            .excess_blob_gas = parent.excess_blob_gas orelse 0,
            .extra_data = parent.extra_data,
        }, child.timestamp) catch return "invalid parent extra data";
        if (child.base_fee_per_gas != expected_base_fee) return "invalid base fee";
        if (chain.spec.mode == .l1) {
            const limit = parent.gas_limit / 1024;
            const high = @max(child.gas_limit, parent.gas_limit);
            const delta = high - @min(child.gas_limit, parent.gas_limit);
            if (delta >= limit or child.gas_limit < 5000) return "invalid gas limit";
        } else if (chain.spec.is_upgrade_active(.holocene, child.timestamp)) {
            const jovian = chain.spec.is_upgrade_active(.jovian, child.timestamp);
            const valid = if (jovian)
                chainspec.basefee.decode_jovian(child.extra_data)
            else
                chainspec.basefee.decode_holocene(child.extra_data);
            _ = valid catch return "invalid extra data";
        }
        if (chain.spec.blob_params_at(child.timestamp)) |params| {
            const expected = params.next_excess_blob_gas(
                parent.excess_blob_gas orelse 0,
                parent.blob_gas_used orelse 0,
                parent.base_fee_per_gas orelse 0,
            );
            if (child.excess_blob_gas != expected) return "invalid excess blob gas";
        }
        return null;
    }

    fn check_executed(
        chain: *Chain,
        child: *const Header,
        executed: *const executor_module.Executed,
    ) ?[]const u8 {
        if (child.gas_used != executed.gas_used) return "gas used mismatch";
        if (!child.logs_bloom.eql(executed.logs_bloom)) return "logs bloom mismatch";
        if (!std.mem.eql(u8, &child.receipts_root.bytes, &executed.receipts_root)) {
            return "receipts root mismatch";
        }
        if (!std.mem.eql(u8, &child.state_root.bytes, &executed.state_root)) {
            return "state root mismatch";
        }
        if (child.blob_gas_used) |used| if (used != executed.blob_gas_used) {
            return "blob gas used mismatch";
        };
        if (chain.spec.mode == .l1) {
            if (child.requests_hash) |hash| {
                if (!hash.eql(consensus.block.requests_hash(executed.requests))) {
                    return "requests hash mismatch";
                }
            }
        } else if (chain.spec.is_upgrade_active(.isthmus, child.timestamp)) {
            const key = primitives.keccak256(&l2_to_l1_message_passer).bytes;
            const root = chain.db.trie().storage_root(key);
            if (!std.mem.eql(u8, &child.withdrawals_root.?.bytes, &root)) {
                return "withdrawals root mismatch";
            }
        }
        return null;
    }

    fn store_block(
        chain: *Chain,
        child: *const Header,
        transactions: []const []const u8,
        withdrawals: ?[]const payload.Withdrawal,
        executed: *const executor_module.Executed,
    ) Error!void {
        const hash = child.hash().bytes;
        chain.recent_senders.put(hash, executed.senders);
        const receipts = executed.receipts;
        const bytes =
            try chain.encode_record(child, transactions, withdrawals, receipts, executed.requests);
        try chain.store.put(ref_of(child, hash), bytes);
        if (chain.journal) |journal| {
            // A failure leaves the record stored but unexecuted; the caller rolls back.
            const entry = journal_block(child, hash, chain.store.record(hash).?, chain.db);
            journal.commit_block(journal.context, &entry) catch return error.StateUnavailable;
        }
        for (transactions, 0..) |raw, index| chain.index_transaction(raw, hash, @intCast(index));
        chain.state_hash = hash;
        chain.db.set_block_hash(child.number, hash);
        chain.sync_history();
    }

    fn journal_block(
        child: *const Header,
        hash: Hash,
        record_bytes: []const u8,
        db: *StateDb,
    ) JournalBlock {
        var outer = rlp.Decoder.init(record_bytes);
        var items = outer.list() catch unreachable; // Encoded by this chain.
        return .{
            .hash = hash,
            .parent_hash = child.parent_hash.bytes,
            .number = child.number,
            .timestamp = child.timestamp,
            .header = items.raw() catch unreachable,
            .record = record_bytes,
            .changeset = db.last_changeset().?, // The commit of this very block.
        };
    }

    /// Re-adds a block retained by the durable journal (oldest first, after `init` with
    /// `restoring`); the last one restored is the head and the state's block.
    pub fn restore(chain: *Chain, record_bytes: []const u8) Error!void {
        const stored = Record.decode(record_bytes) catch return error.StateUnavailable;
        const hash = stored.header.hash().bytes;
        if (chain.store.ref(hash) == null) {
            try chain.store.put(ref_of(&stored.header, hash), record_bytes);
        }
        var transactions = stored.transactions;
        var index: u32 = 0;
        while (!transactions.is_empty()) : (index += 1) {
            chain.index_transaction(transactions.bytes() catch unreachable, hash, index);
        }
        chain.store.set_canonical(stored.header.number, hash);
        chain.state_hash = hash;
        chain.forkchoice.head_block_hash = .{ .bytes = hash };
        assert(std.mem.eql(u8, &chain.head_hash(), &hash));
    }

    fn index_transaction(chain: *Chain, raw: []const u8, block_hash: Hash, index: u32) void {
        const tx_hash = primitives.keccak256(raw).bytes;
        const location: TxLocation = .{ .block_hash = block_hash, .index = index };
        if (chain.tx_index.getPtr(tx_hash)) |existing| {
            existing.* = location; // Re-included on another branch: point at the newest.
            return;
        }
        const slot = chain.tx_ring_head % chain.tx_ring.len;
        if (chain.tx_ring_head >= chain.tx_ring.len) {
            _ = chain.tx_index.remove(chain.tx_ring[slot]);
        }
        chain.tx_ring[slot] = tx_hash;
        chain.tx_ring_head += 1;
        chain.tx_index.putAssumeCapacityNoClobber(tx_hash, location);
    }

    /// Where a transaction was included, if its block is canonical and still stored.
    pub fn find_transaction(chain: *const Chain, tx_hash: Hash) ?TxLocation {
        const location = chain.tx_index.get(tx_hash) orelse return null;
        const stored = chain.store.ref(location.block_hash) orelse return null;
        const canonical = chain.store.canonical_hash(stored.number) orelse return null;
        if (!std.mem.eql(u8, &canonical, &location.block_hash)) return null;
        return location;
    }

    /// Makes the head's post-state current (after a build left a newer block's state).
    /// Starts a historical proofs window at the current state. The state trie must track
    /// changes (`StateTrie.track_changes`) from here on.
    pub fn attach_history(chain: *Chain, store: *history_module.Store) Error!void {
        chain.history = store;
        const number = chain.store.ref(chain.state_hash).?.number;
        store.reset(chain.db.trie(), number) catch return error.StateUnavailable;
        assert(store.window().?.head == number);
    }

    /// The block range the history serves, null without history.
    pub fn history_window(chain: *const Chain) ?HistoryWindow {
        if (chain.journal) |journal| {
            const window = journal.history_window orelse return null;
            return window(journal.context);
        }
        const store = chain.history orelse return null;
        const window = store.window() orelse return null;
        assert(window.oldest <= window.head);
        return .{ .oldest = window.oldest, .head = window.head };
    }

    /// Builds and stores the block `attributes` describe on `parent_hash` without
    /// registering a payload or touching the forkchoice; returns its hash
    /// (`debug_executePayload`). The state is left at the new block.
    pub fn build_block(
        chain: *Chain,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) Error!Hash {
        const id: payload.PayloadId = @splat(0);
        const entry = try chain.build(id, parent_hash, attributes);
        assert(std.mem.eql(u8, &chain.state_hash, &entry.block_hash.bytes));
        return entry.block_hash.bytes;
    }

    /// True when older blocks can be served: from the journal's history (durable node)
    /// or from the in-memory window (`attach_history`).
    pub fn serves_history(chain: *const Chain) bool {
        if (chain.journal) |journal| return journal.proof != null;
        return chain.history != null;
    }

    /// `eth_getProof` at the canonical block `hash` (number `number`) from whichever
    /// history the chain keeps; `HistoryUnavailable` for a side block or no history.
    pub fn proof_at(
        chain: *Chain,
        hash: Hash,
        number: u64,
        address: [20]u8,
        slots: []const u256,
        account_proof: *StateTrie.AccountProof,
        storage_proofs: []StateTrie.StorageProof,
        values: []u256,
    ) db_database.ProofError!?db_history.AccountState {
        assert(slots.len == storage_proofs.len and slots.len == values.len);
        if (chain.journal) |journal| {
            const proof = journal.proof orelse return error.HistoryUnavailable;
            const context = journal.context;
            const proofs = storage_proofs;
            return proof(context, hash, number, address, slots, account_proof, proofs, values);
        }
        const store = chain.history orelse return error.HistoryUnavailable;
        const canonical = chain.store.canonical_hash(number) orelse
            return error.HistoryUnavailable;
        if (!std.mem.eql(u8, &canonical, &hash)) return error.HistoryUnavailable;
        const header_at = chain.header(hash) orelse return error.HistoryUnavailable;
        if (!chain.history_has(number, header_at.state_root.bytes)) {
            return error.HistoryUnavailable; // The window holds another branch there.
        }
        return store.get_proof(number, address, slots, account_proof, storage_proofs, values);
    }

    /// `proof_at` for many slots in one storage walk (`history.Store.get_proofs`): each
    /// slot's proof and value land in `set` (byte for byte `proof_at`'s), valid until the
    /// next block or head move.
    pub fn proofs_at(
        chain: *Chain,
        hash: Hash,
        number: u64,
        address: [20]u8,
        slots: []const u256,
        account_proof: *StateTrie.AccountProof,
        set: *db_history.ProofSet,
    ) db_database.ProofError!?db_history.AccountState {
        assert(slots.len <= set.capacity());
        if (chain.journal) |journal| {
            const proofs = journal.proofs orelse return error.HistoryUnavailable;
            return proofs(journal.context, hash, number, address, slots, account_proof, set);
        }
        const store = chain.history orelse return error.HistoryUnavailable;
        const canonical = chain.store.canonical_hash(number) orelse
            return error.HistoryUnavailable;
        if (!std.mem.eql(u8, &canonical, &hash)) return error.HistoryUnavailable;
        const header_at = chain.header(hash) orelse return error.HistoryUnavailable;
        if (!chain.history_has(number, header_at.state_root.bytes)) {
            return error.HistoryUnavailable; // The window holds another branch there.
        }
        return store.get_proofs(number, address, slots, account_proof, set);
    }

    /// The block number `number` is served from the window when the window holds that
    /// number with the state root of the canonical block there.
    pub fn history_has(chain: *const Chain, number: u64, state_root: Hash) bool {
        const store = chain.history orelse return false;
        const root = store.state_root_at(number) catch return false;
        return std.mem.eql(u8, &root, &state_root);
    }

    /// Keeps the window in step with the executed state: the next block is committed, a
    /// move back to a block in the window unwinds, and anything else (a move across
    /// branches, a full store) restarts the window at the current state.
    fn sync_history(chain: *Chain) void {
        const store = chain.history orelse return;
        const header_now = chain.header(chain.state_hash).?;
        const number = header_now.number;
        const root = header_now.state_root.bytes;
        if (store.window()) |window| {
            if (number == window.head + 1 and chain.history_extends(header_now)) {
                if (store.commit_block(chain.db.trie(), number)) |_| return else |_| {}
            } else if (number <= window.head and chain.history_has(number, root)) {
                if (store.unwind_to(number)) |_| return else |_| {}
            }
        }
        chain.history_resets += 1;
        store.reset(chain.db.trie(), number) catch {
            chain.history = null; // Out of capacity even for one state: stop serving.
        };
    }

    fn history_extends(chain: *const Chain, child: Header) bool {
        const parent = chain.header(child.parent_hash.bytes) orelse return false;
        return chain.history_has(parent.number, parent.state_root.bytes);
    }

    pub fn ensure_head_state(chain: *Chain) Error!void {
        try chain.move_state(chain.head_hash());
    }

    // ---- State movement -------------------------------------------------------------

    /// Brings `db` to the post-state of `target`: roll back to the common ancestor with
    /// the current state, then re-execute stored blocks up to `target`. Checks first, so
    /// a failure leaves the state where it was.
    /// Durable mode: the database head is the forkchoice head at rest, so a restart
    /// resumes there (as reth restores its persisted canonical head) and never on a block
    /// that was built or imported but not made canonical. A stored non-head block's
    /// changeset is unwound now and re-applied when a forkchoice update adopts it. A failed
    /// move keeps the state where it is (best effort; the next state move retries).
    fn settle_head(chain: *Chain) void {
        if (chain.journal == null) return;
        const head = chain.forkchoice.head_block_hash.bytes;
        if (std.mem.eql(u8, &chain.state_hash, &head)) return;
        chain.move_state(head) catch return;
        assert(std.mem.eql(u8, &chain.state_hash, &head));
    }

    pub fn move_state(chain: *Chain, target: Hash) Error!void {
        if (std.mem.eql(u8, &target, &chain.state_hash)) return;
        if (chain.journal) |journal| {
            // The journal unwinds/applies stored changesets on the shared state.
            journal.move_head(journal.context, target) catch return error.StateUnavailable;
            chain.db.clear_undo();
            chain.state_hash = target;
            chain.sync_history();
            return;
        }
        var path: [reexecute_max]Hash = undefined;
        var path_len: u32 = 0;
        var rollbacks: u32 = 0;
        var a = chain.store.ref(chain.state_hash) orelse return error.StateUnavailable;
        var b = chain.store.ref(target) orelse return error.StateUnavailable;
        while (!std.mem.eql(u8, &a.hash, &b.hash)) {
            if (a.number >= b.number and a.number > 0) {
                rollbacks += 1;
                a = chain.store.ref(a.parent_hash) orelse return error.StateUnavailable;
            } else {
                if (path_len == reexecute_max or b.number == 0) return error.StateUnavailable;
                path[path_len] = b.hash;
                path_len += 1;
                b = chain.store.ref(b.parent_hash) orelse return error.StateUnavailable;
            }
        }
        if (rollbacks > chain.db.undo_depth()) return error.StateUnavailable;
        for (0..rollbacks) |_| try chain.db.rollback();
        chain.state_hash = a.hash;
        if (rollbacks > 0) chain.sync_history();
        while (path_len > 0) {
            path_len -= 1;
            try chain.reexecute(path[path_len]);
        }
        assert(std.mem.eql(u8, &chain.state_hash, &target));
    }

    fn reexecute(chain: *Chain, hash: Hash) Error!void {
        var stored = chain.record(hash) orelse return error.StateUnavailable;
        assert(std.mem.eql(u8, &stored.header.parent_hash.bytes, &chain.state_hash));
        var count: usize = 0;
        while (!stored.transactions.is_empty()) : (count += 1) {
            if (count == chain.transactions_buffer.len) return error.TooManyTransactions;
            chain.transactions_buffer[count] = stored.transactions.bytes() catch unreachable;
        }
        var withdrawals_buffer: [withdrawals_max]payload.Withdrawal = undefined;
        const withdrawals = if (stored.withdrawals) |w|
            convert_withdrawals(w, &withdrawals_buffer)
        else
            null;
        const env = env_of(&stored.header);
        const transactions = chain.transactions_buffer[0..count];
        const executed = try chain.executor.execute_block(&env, transactions, withdrawals);
        // A stored block was valid when imported; the same inputs give the same root.
        assert(std.mem.eql(u8, &executed.state_root, &stored.header.state_root.bytes));
        chain.state_hash = hash;
        chain.db.set_block_hash(stored.header.number, hash);
        chain.sync_history();
    }

    /// Points the canonical index at `head`'s ancestry and refreshes the txpool for the
    /// newly canonical blocks.
    /// Points the number index at `head`'s branch: entries above the head are dropped
    /// (a reorg to a lower head), then the branch is written down to the first number
    /// that already maps to it. Entries below that point are consistent, since every
    /// earlier call wrote its branch down to such a point too.
    fn mark_canonical(chain: *Chain, head: Hash) void {
        var cursor = chain.store.ref(head) orelse return;
        chain.store.clear_canonical_above(cursor.number);
        var steps: u32 = 0;
        while (steps < chain.store.entries.len) : (steps += 1) {
            if (chain.store.canonical_hash(cursor.number)) |existing| {
                if (std.mem.eql(u8, &existing, &cursor.hash)) break;
            }
            chain.store.set_canonical(cursor.number, cursor.hash);
            chain.prune_pool(cursor.hash);
            if (cursor.number == 0) break;
            cursor = chain.store.ref(cursor.parent_hash) orelse break;
        }
    }

    /// The pool account of an EIP-8130 lane at the state's block: the channel nonce
    /// (account nonce for key 0, nonce manager storage for 2D keys, 0 when nonce-free)
    /// and the payer's balance.
    pub fn lane_account(chain: *const Chain, lane: txpool.eip8130.Lane) txpool.Account {
        const payer = chain.db.get_account(lane.payer.bytes);
        const balance = if (payer) |account| account.balance else 0;
        if (lane.nonce_free()) return .{ .nonce = 0, .balance = balance };
        if (lane.nonce_key == 0) {
            const sender = chain.db.get_account(lane.sender.bytes);
            return .{ .nonce = if (sender) |account| account.nonce else 0, .balance = balance };
        }
        const slot = evm.native.nonce_slot(lane.sender.bytes, lane.nonce_key);
        const channel = chain.db.get_storage(evm.native.nonce_manager_address, slot);
        return .{ .nonce = @truncate(channel), .balance = balance };
    }

    /// Refreshes the lane of an included EIP-8130 transaction.
    fn prune_lane(chain: *Chain, pool: *txpool.Pool, raw: []const u8, tx_hash: B256) void {
        const envelope = consensus.Envelope.decode(raw) catch return;
        assert(envelope == .eip8130);
        const lane = txpool.eip8130.resolve(
            envelope.eip8130,
            tx_hash.bytes,
            chain.executor.recoverer,
        ) orelse return;
        _ = pool.remove(tx_hash);
        pool.update_account(lane.address, chain.lane_account(lane));
    }

    /// Drops `hash`'s transactions from the pool and refreshes their senders' accounts.
    fn prune_pool(chain: *Chain, hash: Hash) void {
        const pool = chain.pool orelse return;
        var stored = chain.record(hash) orelse return;
        // Senders recorded at execution save an ecrecover per transaction.
        const known = chain.recent_senders.get(hash);
        var index: usize = 0;
        while (!stored.transactions.is_empty()) : (index += 1) {
            const raw = stored.transactions.bytes() catch unreachable;
            const tx_hash = primitives.keccak256(raw);
            if (raw.len > 0 and raw[0] == consensus.tx.eip8130.tx_type) {
                chain.prune_lane(pool, raw, tx_hash);
                continue;
            }
            const sender = if (pool.get(tx_hash)) |tx| tx.sender else if (known) |senders|
                senders[index]
            else blk: {
                const envelope = consensus.Envelope.decode(raw) catch continue;
                break :blk envelope.recover_sender(chain.executor.recoverer) orelse continue;
            };
            _ = pool.remove(tx_hash);
            const account = chain.db.get_account(sender.bytes) orelse continue;
            pool.update_account(sender, .{ .nonce = account.nonce, .balance = account.balance });
        }
    }

    // ---- Building -------------------------------------------------------------------

    fn build(
        chain: *Chain,
        id: payload.PayloadId,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) Error!Built {
        const parent = chain.header(parent_hash) orelse return error.StateUnavailable;
        try chain.move_state(parent_hash);
        var child = try chain.child_header(&parent, parent_hash, attributes);
        const env = env_of(&child);
        chain.build_len = 0;
        var building = try chain.executor.begin_block(&env);
        errdefer chain.executor.abort_block();
        const forced = attributes.transactions orelse &.{};
        try chain.executor.apply_list(&building, forced);
        @memcpy(chain.transactions_buffer[0..forced.len], forced);
        var count: u32 = @intCast(forced.len);
        if (!(attributes.no_tx_pool orelse false)) {
            count = try chain.apply_pool(&building, &env, count);
        }
        const executed = try chain.executor.finish_block(&building, attributes.withdrawals);
        errdefer chain.db.rollback() catch unreachable;
        const transactions = chain.transactions_buffer[0..count];
        chain.seal(&child, transactions, attributes.withdrawals, &executed);
        try chain.store_block(&child, transactions, attributes.withdrawals, &executed);
        const block_hash = child.hash();
        return .{
            .id = id,
            .timestamp = attributes.timestamp,
            .block_hash = block_hash,
            .block_value = executed.fees,
        };
    }

    /// Adds pool transactions (best tip first) while they fit; skips invalid ones.
    fn apply_pool(
        chain: *Chain,
        building: *Executor.Building,
        env: *const executor_module.BlockEnv,
        start: u32,
    ) Error!u32 {
        const pool = chain.pool orelse return start;
        var count = start;
        var da_used_bytes: u64 = 0;
        const limit_da = chain.spec.mode == .l2;
        const selected = pool.select(env.base_fee, chain.select_buffer);
        const target = chain.gas_limit_target;
        const gas_limit = if (target == 0) env.gas_limit else @min(target, env.gas_limit);
        assert(gas_limit <= env.gas_limit);
        for (chain.select_buffer[0..selected]) |tx| {
            if (count == chain.transactions_buffer.len) break;
            if (building.gas_used + tx.gas_limit > gas_limit) continue;
            const raw = try canonical_form(tx.raw, chain.build_bytes[chain.build_len..]);
            const da_bytes = if (limit_da) flz.estimated_size_bytes(raw) else 0;
            if (!chain.da_limits.admits(da_used_bytes, da_bytes)) continue;
            if (raw.ptr != tx.raw.ptr) chain.build_len += raw.len;
            // The pool recovered the sender at admission; skip a second ecrecover.
            chain.executor.known_sender = tx.sender;
            defer chain.executor.known_sender = null;
            chain.executor.apply(building, raw) catch |err| switch (err) {
                error.InvalidTransaction,
                error.BlockGasExceeded,
                error.BlobGasExceeded,
                error.TxTypeNotSupported,
                => continue,
                else => return err,
            };
            chain.transactions_buffer[count] = raw;
            count += 1;
            da_used_bytes += da_bytes;
        }
        return count;
    }

    /// Header fields known before execution.
    pub fn child_header(
        chain: *Chain,
        parent: *const Header,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) Error!Header {
        var extra_buffer: [chainspec.basefee.jovian_extra_data_size]u8 = undefined;
        const extra = if (chain.spec.mode == .l2)
            attributes.extra_data(chain.spec, &extra_buffer)
        else
            &.{};
        // The record copy owns the bytes once stored; keep them in the staging tail.
        const extra_data = chain.staging[chain.staging.len - extra.len ..];
        @memcpy(extra_data, extra);
        var child: Header = .{
            .parent_hash = .{ .bytes = parent_hash },
            .beneficiary = attributes.suggested_fee_recipient,
            .number = parent.number + 1,
            .gas_limit = attributes.gas_limit orelse parent.gas_limit,
            .timestamp = attributes.timestamp,
            .extra_data = extra_data,
            .mix_hash = attributes.prev_randao,
            .base_fee_per_gas = chain.spec.next_base_fee(.{
                .timestamp = parent.timestamp,
                .gas_used = parent.gas_used,
                .gas_limit = parent.gas_limit,
                .base_fee = parent.base_fee_per_gas orelse 0,
                .blob_gas_used = parent.blob_gas_used orelse 0,
                .excess_blob_gas = parent.excess_blob_gas orelse 0,
                .extra_data = parent.extra_data,
            }, attributes.timestamp) catch return error.InvalidAttributes,
            .parent_beacon_block_root = attributes.parent_beacon_block_root,
        };
        if (chain.spec.blob_params_at(attributes.timestamp)) |params| {
            child.excess_blob_gas = params.next_excess_blob_gas(
                parent.excess_blob_gas orelse 0,
                parent.blob_gas_used orelse 0,
                parent.base_fee_per_gas orelse 0,
            );
        } else if (chain.spec.mode == .l2 and attributes.parent_beacon_block_root != null) {
            child.excess_blob_gas = 0;
        }
        return child;
    }

    /// Fills the execution results into `child`.
    pub fn seal(
        chain: *Chain,
        child: *Header,
        transactions: []const []const u8,
        withdrawals: ?[]const payload.Withdrawal,
        executed: *const executor_module.Executed,
    ) void {
        child.state_root = .{ .bytes = executed.state_root };
        child.transactions_root = .{ .bytes = ordered.ordered_trie_root(transactions) };
        child.receipts_root = .{ .bytes = executed.receipts_root };
        child.logs_bloom = executed.logs_bloom;
        child.gas_used = executed.gas_used;
        if (child.parent_beacon_block_root != null) child.blob_gas_used = executed.blob_gas_used;
        if (withdrawals) |list| {
            child.withdrawals_root = withdrawals_root(list);
        }
        const prague = chain.spec.is_ethereum_fork_active(.prague, child.timestamp);
        if (prague) {
            if (chain.spec.mode == .l1) {
                child.requests_hash = consensus.block.requests_hash(executed.requests);
            } else {
                child.requests_hash = consensus.block.empty_requests_hash;
                const key = primitives.keccak256(&l2_to_l1_message_passer).bytes;
                child.withdrawals_root = .{ .bytes = chain.db.trie().storage_root(key) };
            }
        }
        assert(child.optionals_contiguous());
    }

    // ---- Records --------------------------------------------------------------------

    fn encode_record(
        chain: *Chain,
        child: *const Header,
        transactions: []const []const u8,
        withdrawals: ?[]const payload.Withdrawal,
        receipts: []const consensus.Receipt,
        requests: []const []const u8,
    ) Error![]const u8 {
        var transactions_length: usize = 0;
        for (transactions) |raw| transactions_length += rlp.bytes_length(raw);
        var withdrawals_length: usize = 0;
        if (withdrawals) |list| for (list) |w| {
            withdrawals_length += rlp.length(consensus_withdrawal(w));
        };
        var receipts_length: usize = 0;
        for (receipts) |receipt| {
            const length = receipt.encoded_length();
            receipts_length += rlp.header_length(length) + length;
        }
        var requests_length: usize = 0;
        for (requests) |request| requests_length += rlp.bytes_length(request);
        const payload_length = rlp.length(child.*) + rlp.list_length(transactions_length) +
            (if (withdrawals == null) 1 else rlp.list_length(withdrawals_length)) +
            rlp.list_length(receipts_length) + rlp.list_length(requests_length);
        const total = rlp.list_length(payload_length);
        // The staging tail may hold the header's extra data (see `child_header`).
        if (total + child.extra_data.len > chain.staging.len) return error.StagingFull;
        var encoder = rlp.Encoder.init(chain.staging[0..total]);
        encoder.list_header(payload_length);
        rlp.encode(&encoder, child.*);
        encoder.list_header(transactions_length);
        for (transactions) |raw| encoder.bytes(raw);
        if (withdrawals) |list| {
            encoder.list_header(withdrawals_length);
            for (list) |w| rlp.encode(&encoder, consensus_withdrawal(w));
        } else encoder.bytes(&.{});
        encoder.list_header(receipts_length);
        for (receipts) |receipt| {
            encoder.string_header(receipt.encoded_length());
            receipt.encode(&encoder);
        }
        encoder.list_header(requests_length);
        for (requests) |request| encoder.bytes(request);
        assert(encoder.written().len == total);
        return encoder.written();
    }
};

fn ref_of(child: *const Header, hash: Hash) block_store.Ref {
    return .{
        .hash = hash,
        .parent_hash = child.parent_hash.bytes,
        .number = child.number,
        .timestamp = child.timestamp,
    };
}

pub fn env_of(child: *const Header) executor_module.BlockEnv {
    return .{
        .number = child.number,
        .timestamp = child.timestamp,
        .beneficiary = child.beneficiary.bytes,
        .gas_limit = child.gas_limit,
        .base_fee = child.base_fee_per_gas orelse 0,
        .prev_randao = child.mix_hash.bytes,
        .parent_hash = child.parent_hash.bytes,
        .parent_beacon_block_root = if (child.parent_beacon_block_root) |r| r.bytes else null,
        .excess_blob_gas = child.excess_blob_gas,
    };
}

fn consensus_withdrawal(w: payload.Withdrawal) consensus.Withdrawal {
    return .{
        .index = w.index,
        .validator_index = w.validator_index,
        .address = w.address,
        .amount = w.amount_gwei,
    };
}

pub fn convert_withdrawals(
    list: consensus.block.Withdrawals,
    out: *[withdrawals_max]payload.Withdrawal,
) []const payload.Withdrawal {
    var it = list.iterator();
    var count: usize = 0;
    while (it.next()) |w| : (count += 1) {
        out[count] = .{
            .index = w.index,
            .validator_index = w.validator_index,
            .address = w.address,
            .amount_gwei = w.amount,
        };
    }
    return out[0..count];
}

fn withdrawals_root(list: []const payload.Withdrawal) B256 {
    assert(list.len <= withdrawals_max);
    var bytes: [withdrawals_max * 64]u8 = undefined;
    var items: [withdrawals_max][]const u8 = undefined;
    var position: usize = 0;
    for (list, 0..) |w, index| {
        items[index] = rlp.encode_to(bytes[position..], consensus_withdrawal(w));
        position += items[index].len;
    }
    return .{ .bytes = ordered.ordered_trie_root(items[0..list.len]) };
}

/// The block-body form of a pooled transaction: blob transactions
/// (`0x03 || rlp([body, (version,) blobs, commitments, proofs])`) become `0x03 || body`,
/// copied into `out`; everything else is returned as is.
pub fn canonical_form(raw: []const u8, out: []u8) error{StagingFull}![]const u8 {
    if (raw.len == 0 or raw[0] != @backingInt(consensus.TxType.eip4844)) return raw;
    var outer = rlp.Decoder.init(raw[1..]);
    var items = outer.list() catch return raw;
    const header = items.peek_header() catch return raw;
    if (!header.list) return raw;
    const body = items.raw() catch return raw;
    if (out.len < body.len + 1) return error.StagingFull;
    out[0] = raw[0];
    @memcpy(out[1..][0..body.len], body);
    return out[0 .. body.len + 1];
}

test {
    _ = @import("chain_test.zig");
}

test "chain: recent senders ring keeps the last blocks and skips oversized ones" {
    var recent = try RecentSenders.init(std.testing.allocator, 3);
    defer recent.deinit(std.testing.allocator);
    const a: primitives.Address = .{ .bytes = @splat(0xaa) };
    const b: primitives.Address = .{ .bytes = @splat(0xbb) };
    recent.put(@splat(1), &.{ a, b });
    try std.testing.expectEqualSlices(primitives.Address, &.{ a, b }, recent.get(@splat(1)).?);
    recent.put(@splat(9), &.{ a, b, a, b });
    try std.testing.expect(recent.get(@splat(9)) == null);
    for (2..2 + RecentSenders.blocks_max) |n| recent.put(@splat(@intCast(n)), &.{b});
    try std.testing.expect(recent.get(@splat(1)) == null);
    const last: Hash = @splat(@intCast(1 + RecentSenders.blocks_max));
    try std.testing.expectEqualSlices(primitives.Address, &.{b}, recent.get(last).?);
    var prng = @import("../../testing/prng.zig").Prng.init(7);
    for (0..256) |_| {
        const count = prng.below(5);
        var list: [4]primitives.Address = undefined;
        for (list[0..@min(count, 4)]) |*item| {
            item.* = .{ .bytes = @splat(@truncate(prng.int(u8))) };
        }
        const hash: Hash = @splat(@truncate(prng.int(u8)));
        recent.put(hash, list[0..@min(count, 4)]);
        if (count <= 3) {
            const got = recent.get(hash).?;
            try std.testing.expectEqualSlices(primitives.Address, list[0..count], got);
        }
    }
}

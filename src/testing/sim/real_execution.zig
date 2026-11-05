//! The execution lane's real engine inside the simulator (`Config.real_execution`): world
//! state, EVM, payload builder, block store and Engine API handlers
//! (`execution/node/chain.zig` behind `execution/engine.Engine`), called in-process by the
//! consensus driver's polling engine client: no sockets, no JSON.
//!
//! - Chain: `spec` is the sim rollup's L2 (Granite from genesis, which implies Regolith
//!   through Fjord; Holocene and later off) and the genesis allocation is empty with a zero
//!   base fee that stays zero (blocks use far less gas than the target). Payload
//!   transactions are real signatures (`codec.TxFormat.signed`): each payload's own key
//!   sends one zero-fee transaction at nonce 0, so every block executes the L1 info deposit
//!   and a signed user transaction, and its hash and state root are real.
//! - Durability: blocks and state live in the trie-db lane's durable database
//!   (`node/durable.zig`) over the simulated sector storage (`db/storage/sim_storage.zig`).
//!   The storage advances one tick per simulator step (`tick`); engine writes wait while the
//!   database queue is busy or a checkpoint is due (`Client` answers `NotAvailable`), as a
//!   slow disk would. A crash without a disk fault lets submitted writes land (the OS keeps
//!   them); a disk fault is power loss: `SimStorage.crash` loses, keeps, or tears every
//!   unsynced write, the node reopens from what is durable (journal replay over the last
//!   checkpoint, `Chain.restore`), and startup discovery must recover from that.
//! - Forkchoice labels (safe, finalized) are kept as the EL persists them: a disk fault loses
//!   the last label update, and a label whose block did not survive falls back to an older
//!   label that is an ancestor of the recovered head (`recover_labels`).
//! - A sequencer engine (`create` with `pool`) refills its txpool with one signed payload
//!   transaction (random payload) before each build, so the payload builder includes it.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const genesis_module = @import("../../common/genesis/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload_module = @import("../../execution/payload/root.zig");
const txpool = @import("../../execution/txpool/root.zig");
const engine_module = @import("../../execution/engine/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const executor_module = @import("../../execution/node/executor.zig");
const state_db = @import("../../execution/node/state_db.zig");
const durable_module = @import("../../execution/node/durable.zig");
const db_module = @import("../../execution/db/root.zig");
const SimStorage = @import("../../execution/db/storage/sim_storage.zig").SimStorage;
const protocol = @import("../../consensus/protocol/root.zig");
const task = @import("../../consensus/engine/task.zig");
const sync_start = @import("../../consensus/engine/sync_start.zig");
const derive = @import("../../consensus/derive/root.zig");
const Prng = @import("../prng.zig").Prng;
const codec = @import("codec.zig");

const B256 = primitives.B256;
const Header = consensus.Header;
const L2BlockInfo = protocol.block.L2BlockInfo;
const SafeBlock = protocol.span_batch.SafeBlock;
const SystemConfig = protocol.SystemConfig;
const ProviderError = derive.errors.ProviderError;
const ClientError = task.ClientError;
const Chain = chain_module.Chain;
const Engine = engine_module.Engine(Chain);
const StateDb = state_db.StateDb;
pub const Durable = durable_module.Durable(SimStorage);

/// Engine polls answered with `NotAvailable`, in percent (as `real_verifier`'s).
const not_available_percent = 10;
/// Transactions one block may hold that this harness reads back (deposit, user, pool).
pub const block_transactions_max = 8;
/// Retained blocks: every block of the longest run (`Config.block_count_max`) fits.
pub const blocks_retained_max = 512;
const ticks_open_max = 1_000_000;
/// Storage operations take up to this many simulator steps (10 ms each): a slow disk, so
/// a power loss often finds the newest blocks unsynced.
const storage_latency_ticks_max = 8;
const sector = db_module.storage.storage.sector_size;

/// The sim rollup's L2 (`codec.rollup`): Granite from genesis, Holocene and later off.
pub const spec: chainspec.ChainSpec = spec: {
    var result: chainspec.ChainSpec = .{
        .chain_id = codec.l2_chain_id,
        .mode = .l2,
        .base_fee_params = .{ .max_change_denominator = 50, .elasticity_multiplier = 6 },
        .base_fee_params_canyon = .{ .max_change_denominator = 250, .elasticity_multiplier = 6 },
        .gas_limit = codec.gas_limit,
        .genesis_base_fee = 0,
    };
    const active = [_]chainspec.Upgrade{ .regolith, .canyon, .delta, .ecotone, .fjord, .granite };
    for (active) |upgrade| result.upgrades[@backingInt(upgrade)] = 0;
    break :spec result;
};

comptime {
    assert(codec.rollup.is_active(.granite, 0));
    assert(!codec.rollup.is_active(.holocene, 0));
    assert(codec.rollup.genesis.l2_time == 0);
}

const state_config: state_db.Config = .{
    .trie = .{ .accounts_max = 4096, .account_nodes_max = 16384, .storage_nodes_max = 1024 },
    .storage_slots_max = 256,
    .code_bytes_max = 1 << 12,
    .codes_max = 16,
    .block_accounts_max = 64,
    .block_slots_max = 64,
    .block_codes_max = 8,
    .block_code_bytes_max = 1 << 12,
    .undo_bytes_max = 1 << 20,
    .undo_blocks_max = 256,
};

const executor_config: executor_module.Config = .{
    .scratch_bytes = 1 << 20,
    .transactions_max = 64,
    .evm = .{ .memory_bytes_max = 1 << 20, .code_arena_bytes = 1 << 20 },
    .limits = .{
        .accounts_max = 256,
        .slots_max = 1024,
        .transient_slots_max = 64,
        .journal_entries_max = 4096,
        .logs_max = 64,
        .log_data_bytes_max = 4096,
        .code_bytes_max = 1 << 16,
    },
};

pub const database_config: db_module.database.Config = .{
    .engine = .{
        .journal_size_bytes = 256 * sector,
        .checkpoint_zone_size_bytes = 512 * sector,
        .entry_body_size_max = 16 * sector,
        .checkpoint_block_size = 4 * sector,
    },
    .state = StateDb.state_config(state_config),
    .chain = .{
        .blocks_max = blocks_retained_max,
        .bytes_max = 1 << 20,
        .transactions_max = 4 * blocks_retained_max,
        .canonical_max = 2 * blocks_retained_max,
        .reorg_depth_max = 64,
    },
    .changeset = .{
        .accounts_max = 64,
        .storage_max = 64,
        .codes_max = 8,
        .code_bytes_max = 1 << 12,
    },
    .queue_entries_max = 8,
    .checkpoint_staging_bytes = 1 << 20,
};

/// Engine calls start only with this many free queue entries (one call writes at most a
/// head move and a block).
const queue_entries_reserved = 3;

fn chain_config(restoring: bool) chain_module.Config {
    return .{
        .restoring = restoring,
        .store = .{ .blocks_max = 2 * blocks_retained_max, .bytes_max = 2 << 20 },
        .staging_bytes = 1 << 18,
        .select_max = 16,
        .tx_index_max = 4096,
        .build_bytes = 1 << 16,
    };
}

/// Genesis: empty allocation, zero base fee, Canyon withdrawals root, Ecotone blob fields.
pub fn genesis_header() Header {
    return .{
        .state_root = primitives.empty_root_hash,
        .gas_limit = codec.gas_limit,
        .timestamp = codec.rollup.genesis.l2_time,
        .base_fee_per_gas = 0,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .zero,
    };
}

/// The sim rollup config with the real L2 genesis hash (the driver checks it).
pub fn rollup_config(genesis_hash: B256) protocol.RollupConfig {
    var result = codec.rollup;
    result.genesis.l2.hash = genesis_hash;
    assert(result.genesis.l2.number == 0);
    return result;
}

/// Which engine drives a real node: the simulator's model engine or this file's.
pub const Execution = enum { sim, real };

/// A sequencer engine refills its pool before builds; a follower only executes.
pub const Role = enum { follower, sequencer };

const Labels = struct {
    safe: B256 = .zero,
    finalized: B256 = .zero,

    fn eql(a: Labels, b: Labels) bool {
        return a.safe.eql(b.safe) and a.finalized.eql(b.finalized);
    }
};

/// The execution node proper, rebuilt over the durable state on every restart.
const Node = struct {
    db: StateDb,
    executor: executor_module.Executor,
    pool: txpool.Pool,
    chain: Chain,
    engine: Engine,
};

pub const ExecEngine = struct {
    allocator: std.mem.Allocator,
    genesis: Header,
    genesis_hash: B256,
    rollup_genesis: protocol.rollup_config.ChainGenesis,
    storage: SimStorage,
    durable: *Durable,
    node: *Node,
    labels: Labels = .{},
    /// Labels before the last label update: what a disk fault leaves.
    labels_previous: Labels = .{},
    /// Sequencer engines draw one payload per pool refill; followers have none.
    pool_prng: ?Prng,
    pool_tx: [codec.payload_tx_length_max]u8 = undefined,
    restarts: u64 = 0,
    disk_faults: u64 = 0,
    /// Disk faults that lost at least one block (the recovered head went back).
    blocks_lost: u64 = 0,
    builds: u64 = 0,
    inserts: u64 = 0,
    /// Separate scratch per caller: results borrow it until that caller's next call.
    client_transactions: [block_transactions_max][]const u8 = undefined,
    provider_transactions: [block_transactions_max][]const u8 = undefined,
    info_transactions: [block_transactions_max][]const u8 = undefined,
    withdrawals: [chain_module.withdrawals_max]payload_module.Withdrawal = undefined,

    /// Heap-pinned: the chain, the engine and storage callbacks keep pointers into it.
    pub fn create(allocator: std.mem.Allocator, seed: u64, role: Role) !*ExecEngine {
        const engine = try allocator.create(ExecEngine);
        errdefer allocator.destroy(engine);
        const genesis = genesis_header();
        engine.* = .{
            .allocator = allocator,
            .genesis = genesis,
            .genesis_hash = genesis.hash(),
            .rollup_genesis = undefined,
            .storage = try SimStorage.init(allocator, .{
                .size_bytes = database_config.engine.size_bytes(),
                .seed = seed ^ 0x6469_736b,
                .latency_ticks_max = storage_latency_ticks_max,
            }),
            .durable = undefined,
            .node = undefined,
            .pool_prng = if (role == .sequencer) Prng.init(seed ^ 0x706f_6f6c) else null,
        };
        errdefer engine.storage.deinit(allocator);
        engine.rollup_genesis = rollup_config(engine.genesis_hash).genesis;
        try engine.open();
        errdefer engine.durable.destroy(allocator);
        assert(!engine.durable.has_head());
        const parsed: genesis_module.Genesis = .{};
        const hash = try engine.durable.bootstrap(allocator, &parsed, &genesis);
        assert(std.mem.eql(u8, &hash, &engine.genesis_hash.bytes));
        try engine.create_node(false);
        try engine.settle();
        return engine;
    }

    pub fn destroy(engine: *ExecEngine) void {
        const allocator = engine.allocator;
        engine.destroy_node();
        engine.durable.destroy(allocator);
        engine.storage.deinit(allocator);
        allocator.destroy(engine);
    }

    fn open(engine: *ExecEngine) !void {
        const durable = try Durable.create(
            engine.allocator,
            &engine.storage,
            database_config,
            engine.genesis_hash.bytes,
            codec.l2_chain_id,
        );
        errdefer durable.destroy(engine.allocator);
        durable.start();
        for (0..ticks_open_max) |_| {
            if (durable.phase == .ready or durable.phase == .failed) break;
            engine.storage.tick();
            durable.poll();
        }
        if (durable.phase != .ready) return error.OpenFailed;
        engine.durable = durable;
    }

    /// Ticks until every submitted write is durable (startup, clean shutdown).
    fn settle(engine: *ExecEngine) !void {
        for (0..ticks_open_max) |_| {
            if (engine.durable.database.idle()) return;
            engine.storage.tick();
            engine.durable.poll();
        }
        return error.Timeout;
    }

    fn create_node(engine: *ExecEngine, restoring: bool) !void {
        const allocator = engine.allocator;
        const node = try allocator.create(Node);
        errdefer allocator.destroy(node);
        node.db = try StateDb.init_shared(allocator, state_config, engine.durable.state());
        errdefer node.db.deinit(allocator);
        node.executor = try .init(allocator, &spec, &node.db, executor_config);
        errdefer node.executor.deinit(allocator);
        node.pool = try txpool.Pool.init(allocator, .{ .tx_capacity = 64 });
        errdefer node.pool.deinit(allocator);
        const config = chain_config(restoring);
        const genesis = &engine.genesis;
        node.chain = try Chain.init(allocator, &spec, &node.db, &node.executor, genesis, config);
        errdefer node.chain.deinit(allocator);
        if (engine.pool_prng != null) node.chain.pool = &node.pool;
        node.engine = Engine.init(&spec, &node.chain);
        if (restoring) {
            var records: [blocks_retained_max][]const u8 = undefined;
            for (engine.durable.retained(&records)) |record| try node.chain.restore(record);
        }
        node.chain.journal = engine.durable.journal();
        engine.node = node;
        assert(engine.node.chain.store.ref(engine.genesis_hash.bytes) != null);
    }

    fn destroy_node(engine: *ExecEngine) void {
        const allocator = engine.allocator;
        const node = engine.node;
        node.chain.deinit(allocator);
        node.pool.deinit(allocator);
        node.executor.deinit(allocator);
        node.db.deinit(allocator);
        allocator.destroy(node);
        engine.node = undefined;
    }

    /// One storage tick per simulator step: submitted reads and writes complete.
    pub fn tick(engine: *ExecEngine) void {
        engine.storage.tick();
        engine.durable.poll();
    }

    /// Engine writes wait (the client answers `NotAvailable`) while the database queue is
    /// nearly full or the journal needs a checkpoint, so a commit never meets `Busy`.
    pub fn accepting(engine: *const ExecEngine) bool {
        const database = &engine.durable.database;
        if (engine.durable.phase != .ready or database.phase != .ready) return false;
        if (database.checkpoint_wanted) return false;
        const queue_max = database_config.queue_entries_max;
        if (database.queue_count + queue_entries_reserved > queue_max) return false;
        const ring = &database.engine.journal;
        const used = ring.head - ring.tail + database.journal_bytes_pending;
        return used * 2 <= ring.config.zone_size_bytes;
    }

    /// What a crash-restart of the EL loses: nothing (`none`: every submitted write lands,
    /// the OS keeps them), the last label update (`labels`: the writes land but the label
    /// file did not), or power (`power`: unsynced writes are lost, kept or torn, and the
    /// last label update is lost). The node reopens from what is durable.
    pub const Fault = enum { none, labels, power };

    pub fn restart(engine: *ExecEngine, fault: Fault) !void {
        const head = engine.head_number();
        if (fault == .power) engine.storage.crash() else try engine.settle();
        if (fault != .none) {
            engine.labels = engine.labels_previous;
            engine.disk_faults += 1;
        }
        engine.destroy_node();
        engine.durable.destroy(engine.allocator);
        try engine.open();
        try engine.create_node(true);
        engine.recover_labels();
        engine.restarts += 1;
        engine.blocks_lost += @intFromBool(engine.head_number() < head);
        // The durable head is the last executed block: a payload built but not yet chosen
        // by forkchoiceUpdated becomes the head after a restart.
        assert(fault == .power or engine.head_number() >= head);
    }

    /// Each label must be an ancestor of the recovered head: else the next older label
    /// that is, else genesis; finalized never above safe.
    fn recover_labels(engine: *ExecEngine) void {
        const labels = engine.labels;
        const previous = engine.labels_previous;
        const safe = engine.first_ancestor(
            &.{ labels.safe, previous.safe, labels.finalized, previous.finalized },
            engine.head_hash(),
        );
        var finalized = engine.first_ancestor(&.{ labels.finalized, previous.finalized }, safe);
        if (safe.is_zero()) finalized = .zero;
        engine.labels = .{ .safe = safe, .finalized = finalized };
        engine.labels_previous = engine.labels;
        assert(engine.label_number(.finalized) <= engine.label_number(.safe));
    }

    fn first_ancestor(engine: *ExecEngine, candidates: []const B256, head: B256) B256 {
        const chain = &engine.node.chain;
        for (candidates) |hash| {
            if (hash.is_zero()) continue;
            if (chain.is_ancestor(hash, head)) return hash;
        }
        return .zero;
    }

    // ------------------------------------------------------------ reads

    pub fn head_hash(engine: *const ExecEngine) B256 {
        return .{ .bytes = engine.node.chain.head_hash() };
    }

    pub fn head_number(engine: *const ExecEngine) u64 {
        return engine.node.chain.store.ref(engine.node.chain.head_hash()).?.number;
    }

    pub fn canonical_hash(engine: *const ExecEngine, number: u64) ?B256 {
        if (number > engine.head_number()) return null;
        const hash = engine.node.chain.store.canonical_hash(number) orelse return null;
        return .{ .bytes = hash };
    }

    pub fn header(engine: *const ExecEngine, hash: B256) ?Header {
        return engine.node.chain.header(hash.bytes);
    }

    pub fn label_hash(engine: *const ExecEngine, label: sync_start.Label) B256 {
        const hash = switch (label) {
            .latest => return engine.head_hash(),
            .safe => engine.labels.safe,
            .finalized => engine.labels.finalized,
        };
        return if (hash.is_zero()) engine.genesis_hash else hash;
    }

    pub fn label_number(engine: *const ExecEngine, label: sync_start.Label) u64 {
        const hash = engine.label_hash(label);
        return engine.node.chain.store.ref(hash.bytes).?.number;
    }

    /// The stored block as an execution payload (transactions borrow the store). The
    /// Canyon withdrawals root stays out: it is a V4 (Isthmus) payload field.
    pub fn payload_of(
        engine: *ExecEngine,
        hash: B256,
        transactions: *[block_transactions_max][]const u8,
    ) ?task.ExecutionPayload {
        const chain = &engine.node.chain;
        const record = chain.record(hash.bytes) orelse return null;
        var counter = record.transactions;
        var count: usize = 0;
        while (!counter.is_empty()) : (count += 1) {
            _ = counter.bytes() catch unreachable; // Proof: written by this chain.
        }
        assert(count <= block_transactions_max);
        var result = chain.payload_of(hash.bytes, transactions, &engine.withdrawals).?;
        result.withdrawals_root = null;
        assert(result.block_hash.eql(hash));
        return result;
    }

    fn info_of(engine: *ExecEngine, hash: B256) ProviderError!L2BlockInfo {
        const payload = engine.payload_of(hash, &engine.info_transactions) orelse
            return error.NotFound;
        return task.block_info_from_payload(&payload, &engine.rollup_genesis) catch
            error.NotFound;
    }

    /// The `L2BlockInfo` of canonical block `number` (its L1 origin from the deposit).
    pub fn block_info(engine: *ExecEngine, number: u64) ?L2BlockInfo {
        const hash = engine.canonical_hash(number) orelse return null;
        return engine.info_of(hash) catch null;
    }

    // ------------------------------------------------------------ L2 provider

    pub fn l2_block_info_by_label(
        engine: *ExecEngine,
        label: sync_start.Label,
    ) ProviderError!L2BlockInfo {
        return engine.info_of(engine.label_hash(label));
    }

    pub fn l2_block_info_by_number(engine: *ExecEngine, number: u64) ProviderError!L2BlockInfo {
        const hash = engine.canonical_hash(number) orelse return error.NotFound;
        return engine.info_of(hash);
    }

    pub fn l2_block_info_by_hash(engine: *ExecEngine, hash: B256) ProviderError!L2BlockInfo {
        const info = try engine.info_of(hash);
        const canonical = engine.canonical_hash(info.block_info.number) orelse
            return error.NotFound;
        if (!canonical.eql(hash)) return error.NotFound;
        return info;
    }

    /// The model never updates the system config: every block has the genesis one.
    pub fn system_config_by_l2_hash(engine: *ExecEngine, hash: B256) ProviderError!SystemConfig {
        if (engine.node.chain.store.ref(hash.bytes) == null) return error.NotFound;
        return codec.rollup.genesis.system_config.?;
    }

    pub fn l2_block_by_number(engine: *ExecEngine, number: u64) ProviderError!SafeBlock {
        const hash = engine.canonical_hash(number) orelse return error.NotFound;
        const info = try engine.info_of(hash);
        const payload = engine.payload_of(hash, &engine.provider_transactions).?;
        return .{
            .transactions = payload.transactions,
            .l1_origin_number = info.l1_origin.number,
        };
    }

    // ------------------------------------------------------------ Engine API

    pub fn forkchoice_updated(
        engine: *ExecEngine,
        version: task.Version,
        state: *const task.EngineForkchoiceState,
        attributes: ?*const task.EngineAttributes,
    ) ClientError!task.ForkchoiceUpdated {
        if (attributes) |built| engine.fill_pool(built);
        const node = engine.node;
        const result = node.engine.forkchoice_updated(version, state.*, attributes);
        // The forkchoice stands even when the attributes are rejected.
        if (node.engine.forkchoice) |applied| {
            if (applied.head_block_hash.eql(state.head_block_hash)) engine.set_labels(state);
        }
        const updated = result catch |err| return switch (err) {
            error.InvalidForkchoiceState => error.InvalidForkchoiceState,
            else => error.RpcFailed,
        };
        engine.builds += @intFromBool(updated.payload_id != null);
        return updated;
    }

    fn set_labels(engine: *ExecEngine, state: *const task.EngineForkchoiceState) void {
        const labels: Labels = .{
            .safe = state.safe_block_hash,
            .finalized = state.finalized_block_hash,
        };
        if (labels.eql(engine.labels)) return;
        engine.labels_previous = engine.labels;
        engine.labels = labels;
    }

    /// Sequencer engines: one signed payload transaction waits in the pool for the build.
    fn fill_pool(engine: *ExecEngine, attributes: *const task.EngineAttributes) void {
        const prng = &(engine.pool_prng orelse return);
        if (attributes.no_tx_pool == true) return;
        const pool = &engine.node.pool;
        if (pool.count() > 0) return;
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, prng.int(u64), .big);
        const envelope = codec.payload_envelope_signed(&payload);
        const tx = envelope.eip1559.tx;
        const sender = consensus.signature.address_from_private(codec.payload_key(&payload)).?;
        _ = pool.add(.{
            .hash = envelope.hash(),
            .sender = sender,
            .nonce = tx.nonce,
            .tx_type = 2,
            .gas_limit = tx.gas_limit,
            .max_fee_per_gas = tx.max_fee_per_gas,
            .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
            .raw = envelope.encode_to(&engine.pool_tx),
        }, .{ .nonce = 0, .balance = 0 }) catch unreachable; // Proof: empty pool, fresh sender.
        assert(pool.count() == 1);
    }

    pub fn new_payload(
        engine: *ExecEngine,
        version: task.Version,
        payload: *const task.ExecutionPayload,
        params: *const task.NewPayloadParams,
    ) ClientError!task.PayloadStatus {
        const status = engine.node.engine.new_payload(version, payload, params) catch
            return error.RpcFailed;
        engine.inserts += @intFromBool(status.status == .valid);
        return status;
    }

    pub fn get_payload(
        engine: *ExecEngine,
        version: task.Version,
        id: task.PayloadId,
    ) ClientError!task.PayloadEnvelope {
        const built = engine.node.engine.get_payload(version, id) catch return error.RpcFailed;
        const payload = engine.payload_of(built.block_hash, &engine.client_transactions) orelse
            return error.RpcFailed;
        const stored = engine.header(built.block_hash).?;
        return .{
            .payload = payload,
            .block_value = built.block_value,
            .parent_beacon_block_root = stored.parent_beacon_block_root,
        };
    }

    pub fn l2_block(engine: *ExecEngine, number: u64) ClientError!?task.L2Block {
        const hash = engine.canonical_hash(number) orelse return null;
        const stored = engine.header(hash).?;
        const payload = engine.payload_of(hash, &engine.client_transactions).?;
        const info = task.block_info_from_payload(&payload, &engine.rollup_genesis) catch
            return error.InvalidBlock;
        return .{
            .info = info,
            .prev_randao = stored.mix_hash,
            .gas_limit = stored.gas_limit,
            .fee_recipient = stored.beneficiary,
            .extra_data = stored.extra_data,
            .withdrawals_root = stored.withdrawals_root,
            .parent_beacon_block_root = stored.parent_beacon_block_root,
            .withdrawals = &.{},
            .transactions = payload.transactions,
        };
    }
};

/// The polling engine client (`engine/task.zig`) over the real engine.
pub const Client = struct {
    engine: *ExecEngine,
    prng: Prng,
    calls: u64 = 0,

    fn poll(client: *Client, writes: bool) ClientError!void {
        client.calls += 1;
        if (client.prng.below(100) < not_available_percent) return error.NotAvailable;
        if (writes and !client.engine.accepting()) return error.NotAvailable;
    }

    pub fn forkchoice_updated(
        client: *Client,
        version: task.Version,
        state: *const task.EngineForkchoiceState,
        attributes: ?*const task.EngineAttributes,
    ) ClientError!task.ForkchoiceUpdated {
        assert(version == .v3); // Ecotone is active from genesis.
        try client.poll(true);
        return client.engine.forkchoice_updated(version, state, attributes);
    }

    pub fn new_payload(
        client: *Client,
        version: task.Version,
        payload: *const task.ExecutionPayload,
        params: *const task.NewPayloadParams,
    ) ClientError!task.PayloadStatus {
        assert(version == .v3);
        try client.poll(true);
        // As on the wire: `engine_newPayloadV3` has no execution requests parameter.
        var sent = params.*;
        sent.execution_requests = null;
        return client.engine.new_payload(version, payload, &sent);
    }

    pub fn get_payload(
        client: *Client,
        version: task.Version,
        payload_id: task.PayloadId,
    ) ClientError!task.PayloadEnvelope {
        assert(version == .v3);
        try client.poll(false);
        return client.engine.get_payload(version, payload_id);
    }

    pub fn l2_block_by_number(client: *Client, number: u64) ClientError!?task.L2Block {
        try client.poll(false);
        return client.engine.l2_block(number);
    }

    pub fn l2_block_info_by_number(client: *Client, number: u64) ClientError!?L2BlockInfo {
        const block = try client.l2_block_by_number(number) orelse return null;
        assert(block.info.block_info.number == number);
        return block.info;
    }
};

const testing = std.testing;

test "real execution: genesis opens, survives a clean restart and a disk fault" {
    const engine = try ExecEngine.create(testing.allocator, 1, .follower);
    defer engine.destroy();
    try testing.expectEqual(@as(u64, 0), engine.head_number());
    const info = try engine.l2_block_info_by_label(.safe);
    try testing.expect(info.block_info.hash.eql(engine.genesis_hash));
    try engine.restart(.none);
    try engine.restart(.labels);
    try engine.restart(.power);
    try testing.expectEqual(@as(u64, 0), engine.head_number());
    try testing.expect(engine.head_hash().eql(engine.genesis_hash));
}

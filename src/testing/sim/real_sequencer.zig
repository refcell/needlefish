//! The consensus lane's real node driver in sequencer mode (`Driver` with
//! `.sequencer = true`, which builds through `sequencer/{origin,build}.zig` and the engine
//! task queue) producing the L2 chain inside the simulator. It replaces the model
//! sequencer's block production; the model sequencer keeps serving gossip sync requests
//! from the reference chain, which this file fills from the real sequencer's engine.
//!
//! - Its engine is a `real_verifier.SimEngine` with a transaction pool: every build whose
//!   attributes allow the pool gets one model payload transaction with a random payload,
//!   so a block's hash is the model's `nodes.block_hash` and the batchers, model
//!   verifiers, and real verifier all work on it unchanged.
//! - Its L1 view has a confirmation depth of `nodes.l1_reorg_depth_max`: L1 origin
//!   selection (and its own derivation) only sees blocks no L1 reorg can change, as the
//!   model sequencer's origin rule and `codec.Origin` require.
//! - New engine blocks are appended to the reference chain (`record`) after the checks
//!   below, and the driver's sealed payloads are gossiped to every verifier in the model's
//!   `unsafe_block` format (`take_gossip`).
//! - A crash loses all driver state; the engine's chain is durable (a sequencer EL that
//!   loses gossiped blocks equivocates by construction), but a disk fault loses its last
//!   forkchoice label update. Startup discovery recovers the unsafe head from the engine.
//!
//! Invariants on every recorded block (the model sequencer's guarantees):
//! - exactly the L1 info deposit followed by one payload transaction;
//! - timestamp is the parent's plus the block time;
//! - L1 origin is the parent's (sequence number + 1) or the next L1 block (sequence
//!   number 0), canonical and final on L1, not newer than the block, and within the
//!   maximum sequencer drift;
//! - no equivocation: a recorded block is never replaced and the head never goes back;
//! - the sealed payload gossiped is the block recorded at its number.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../../consensus/protocol/root.zig");
const driver_module = @import("../../consensus/service/driver.zig");
const SafeDB = @import("../../consensus/safedb/root.zig").SafeDB;
const Prng = @import("../prng.zig").Prng;
const codec = @import("codec.zig");
const nodes = @import("nodes.zig");
const real_verifier = @import("real_verifier.zig");
const real_execution = @import("real_execution.zig");

const B256 = protocol.block.Hash;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Driver = driver_module.Driver;
const SimEngine = real_verifier.SimEngine;
const EngineClient = real_verifier.EngineClient;
const L1View = real_verifier.L1View;
const View = real_verifier.View;
const low_word = real_verifier.low_word;

const safe_db_capacity = 64;
const deposit_tx_type: u8 = 0x7e;

/// One gossiped block in the model sequencer's `unsafe_block` format.
pub const Gossip = struct { number: u64, payload: u64, hash: u64 };

pub const RealSequencer = struct {
    allocator: std.mem.Allocator,
    rollup: protocol.RollupConfig,
    blob_schedule: protocol.l1_info.L1BlobSchedule = .{},
    engine: SimEngine,
    client: EngineClient,
    l1_view: L1View = undefined,
    safe_db: SafeDB,
    driver: Driver,
    restarts: u32 = 0,
    gossiped: u64 = 0,
    block_count_max: u64,
    /// Real execution: the execution lane's engine (with a txpool) replaces `engine`.
    exec: ?*real_execution.ExecEngine = null,
    exec_client: real_execution.Client = undefined,

    /// Heap-allocated: the driver keeps pointers to the rollup config and safe db.
    pub fn create(
        allocator: std.mem.Allocator,
        block_count_max: u64,
        seed: u64,
        execution: real_execution.Execution,
    ) !*RealSequencer {
        const sequencer = try allocator.create(RealSequencer);
        errdefer allocator.destroy(sequencer);
        sequencer.* = .{
            .allocator = allocator,
            .rollup = codec.rollup,
            .engine = try SimEngine.init(allocator, block_count_max),
            .client = undefined,
            .safe_db = undefined,
            .driver = undefined,
            .block_count_max = block_count_max,
        };
        errdefer sequencer.engine.deinit(allocator);
        sequencer.engine.pool = Prng.init(seed ^ 0x706f_6f6c);
        const client_prng = Prng.init(seed ^ 0x7365_7175_656e_6365);
        sequencer.client = .{ .engine = &sequencer.engine, .prng = client_prng };
        if (execution == .real) {
            const exec = try real_execution.ExecEngine.create(allocator, seed, .sequencer);
            sequencer.exec = exec;
            sequencer.exec_client = .{ .engine = exec, .prng = client_prng };
            sequencer.rollup = real_execution.rollup_config(exec.genesis_hash);
        }
        errdefer if (sequencer.exec) |exec| exec.destroy();
        try sequencer.start();
        assert(sequencer.driver.phase == .starting);
        assert(sequencer.driver.sequencer_active);
        return sequencer;
    }

    pub fn destroy(sequencer: *RealSequencer) void {
        const allocator = sequencer.allocator;
        sequencer.stop();
        sequencer.engine.deinit(allocator);
        if (sequencer.exec) |exec| exec.destroy();
        allocator.destroy(sequencer);
    }

    fn start(sequencer: *RealSequencer) !void {
        sequencer.safe_db = try SafeDB.init(sequencer.allocator, safe_db_capacity);
        errdefer sequencer.safe_db.deinit(sequencer.allocator);
        try sequencer.driver.init(
            sequencer.allocator,
            &sequencer.rollup,
            &sequencer.blob_schedule,
            &sequencer.safe_db,
            .{ .sequencer = true },
        );
    }

    fn stop(sequencer: *RealSequencer) void {
        sequencer.driver.deinit();
        sequencer.safe_db.deinit(sequencer.allocator);
    }

    /// Crash-restart: driver state is lost; the engine keeps its chain, and on a disk
    /// fault loses its last label update (`lose_unflushed` with no blocks lost).
    /// With real execution, the execution db keeps every block (its writes land) and a disk
    /// fault loses the last label update only.
    pub fn restart(sequencer: *RealSequencer, disk_fault: bool) !void {
        const head = sequencer.engine_head();
        sequencer.stop();
        if (sequencer.exec) |exec| {
            try exec.restart(if (disk_fault) .labels else .none);
        } else if (disk_fault) sequencer.engine.lose_unflushed(0);
        try sequencer.start();
        sequencer.restarts += 1;
        // Real execution may recover a built, never gossiped payload as its head.
        assert(sequencer.engine_head() == head or
            (sequencer.exec != null and sequencer.engine_head() == head + 1));
        assert(sequencer.driver.phase == .starting);
    }

    /// One driver step. `producing` false stops the sequencer (admin_stopSequencer), as
    /// at the end of the production phase. The clock is clamped so the driver never
    /// builds past `block_count_max` blocks (the reference chain's capacity).
    pub fn tick(sequencer: *RealSequencer, view: View, producing: bool) void {
        if (!producing and sequencer.driver.sequencer_active) {
            _ = sequencer.driver.stop_sequencer() catch unreachable; // Proof: active.
        }
        assert(producing or !sequencer.driver.sequencer_active);
        sequencer.l1_view = .{
            .l1 = view.l1,
            .pool = view.pool,
            .reachable = view.l1_reachable,
            .confirmations = nodes.l1_reorg_depth_max,
        };
        const l1 = &sequencer.l1_view;
        const confirmed = view.l1.head -| nodes.l1_reorg_depth_max;
        const providers: real_verifier.Providers = .{
            .l1 = l1,
            .blobs = l1,
            .l2 = &sequencer.engine,
            .engine = &sequencer.client,
            .l1_head = if (view.l1_reachable) l1.info(confirmed) else null,
            .l1_finalized = if (view.l1_reachable) l1.info(confirmed) else null,
        };
        const now_ms_max = codec.rollup.l2_block_timestamp_ms(sequencer.block_count_max);
        const now_ms = @min(view.now_ns / std.time.ns_per_ms, now_ms_max);
        if (sequencer.exec) |exec| {
            exec.tick();
            const exec_providers: real_verifier.ExecProviders = .{
                .l1 = l1,
                .blobs = l1,
                .l2 = exec,
                .engine = &sequencer.exec_client,
                .l1_head = providers.l1_head,
                .l1_finalized = providers.l1_finalized,
            };
            return sequencer.driver.tick(exec_providers, now_ms);
        }
        sequencer.driver.tick(providers, now_ms);
    }

    pub fn engine_head(sequencer: *const RealSequencer) u64 {
        if (sequencer.exec) |exec| return exec.head_number();
        return sequencer.engine.head();
    }

    pub fn safe_number(sequencer: *const RealSequencer) u64 {
        if (sequencer.driver.phase == .starting) return 0;
        return sequencer.driver.sync_state().safe_head.block_info.number;
    }

    /// Checks the engine's blocks against the reference chain and appends new ones to it.
    /// Returns the violated invariant, or null.
    pub fn record(
        sequencer: *RealSequencer,
        chain: *nodes.Sequencer,
        l1: *const nodes.L1,
    ) ?[]const u8 {
        if (sequencer.driver.stats.critical_errors != 0) return "real sequencer critical error";
        if (sequencer.exec) |exec| return record_executed(exec, chain, l1);
        const engine = &sequencer.engine;
        // Rewritten blocks at or below the recorded head must be the recorded ones.
        var number = engine.written_low;
        while (number <= @min(chain.head, engine.head())) : (number += 1) {
            const hash = engine.blocks[number].info.block_info.hash;
            if (!hash.eql(codec.word_hash(chain.chain.hashes[number]))) {
                return "real sequencer equivocated";
            }
        }
        engine.written_low = std.math.maxInt(u64);
        if (engine.head() < chain.head) return "real sequencer unsafe head went back";
        while (chain.head < engine.head()) {
            number = chain.head + 1;
            assert(number <= chain.chain.capacity());
            const block = &engine.blocks[number];
            const transactions = SimEngine.slices(block, &engine.read_slices);
            if (check_block(block.info, transactions, chain, l1)) |reason| return reason;
            const payload = codec.payload_from_tx(block.transaction(1)).?;
            const hash = chain.chain.put(number, payload);
            if (!block.info.block_info.hash.eql(codec.word_hash(hash))) {
                return "real sequencer block hash differs from the model's";
            }
            const origin = block.info.l1_origin;
            chain.chain.origins[number] = .{
                .number = origin.number,
                .hash = low_word(origin.hash).?,
                .sequence_number = block.info.sequence_number,
            };
            chain.head = number;
        }
        assert(chain.head == engine.head());
        return null;
    }

    /// Real execution: the engine's canonical blocks above the recorded head are checked
    /// like the sim engine's and recorded with their real hash and state root.
    fn record_executed(
        exec: *real_execution.ExecEngine,
        chain: *nodes.Sequencer,
        l1: *const nodes.L1,
    ) ?[]const u8 {
        assert(chain.chain.real);
        // The recorded head still canonical implies its whole prefix is (parent hashes).
        const recorded = exec.canonical_hash(chain.head) orelse
            return "real sequencer unsafe head went back";
        if (!recorded.eql(chain.chain.real_hashes[chain.head])) return "real sequencer equivocated";
        while (chain.head < exec.head_number()) {
            const number = chain.head + 1;
            assert(number <= chain.chain.capacity());
            const hash = exec.canonical_hash(number).?;
            var transactions: [real_execution.block_transactions_max][]const u8 = undefined;
            const payload = exec.payload_of(hash, &transactions).?;
            const info = exec.block_info(number) orelse
                return "real sequencer block without an L1 info deposit";
            if (check_block(info, payload.transactions, chain, l1)) |reason| return reason;
            _ = chain.chain.put(number, codec.payload_from_tx(payload.transactions[1]).?);
            chain.chain.real_hashes[number] = hash;
            chain.chain.real_state_roots[number] = payload.state_root;
            const origin = info.l1_origin;
            chain.chain.origins[number] = .{
                .number = origin.number,
                .hash = low_word(origin.hash).?,
                .sequence_number = info.sequence_number,
            };
            chain.head = number;
        }
        assert(chain.head == exec.head_number());
        return null;
    }

    /// The model sequencer's guarantees for block `chain.head + 1`.
    fn check_block(
        info: L2BlockInfo,
        transactions: []const []const u8,
        chain: *const nodes.Sequencer,
        l1: *const nodes.L1,
    ) ?[]const u8 {
        const number = info.block_info.number;
        assert(number == chain.head + 1);
        if (transactions.len != 2) return "real sequencer block without one user tx";
        const deposit = transactions[0];
        if (deposit.len == 0 or deposit[0] != deposit_tx_type) {
            return "real sequencer block does not start with the L1 info deposit";
        }
        if (codec.payload_from_tx(transactions[1]) == null) {
            return "real sequencer block without one user tx";
        }
        const parent_time = codec.rollup.l2_block_timestamp(number - 1);
        if (info.block_info.timestamp != parent_time + codec.rollup.block_time) {
            return "real sequencer block time spacing";
        }
        return check_origin(info, chain.chain.origins[number - 1], l1);
    }

    fn check_origin(info: L2BlockInfo, parent: codec.Origin, l1: *const nodes.L1) ?[]const u8 {
        const origin = info.l1_origin;
        const same = origin.number == parent.number and
            low_word(origin.hash) == parent.hash and
            info.sequence_number == parent.sequence_number + 1;
        const next = origin.number == parent.number + 1 and info.sequence_number == 0;
        if (!same and !next) return "real sequencer L1 origin not monotone";
        // Genesis is final from the start; any other origin must be deeper than a reorg.
        if (origin.number > l1.head -| nodes.l1_reorg_depth_max or
            low_word(origin.hash) != l1.blocks[origin.number].hash)
        {
            return "real sequencer L1 origin not final";
        }
        const origin_time = origin.number * codec.l1_block_time_s;
        const time = info.block_info.timestamp;
        if (origin_time > time) return "real sequencer L1 origin newer than block";
        if (time > origin_time + codec.rollup.max_sequencer_drift_at(origin_time)) {
            return "real sequencer L1 origin beyond drift";
        }
        assert(origin.number <= l1.head);
        return null;
    }

    /// The driver's last sealed payload as model gossip, once; it must be the recorded
    /// block at its number (call after `record`).
    pub fn take_gossip(
        sequencer: *RealSequencer,
        chain: *const nodes.Sequencer,
    ) error{GossipDiverged}!?Gossip {
        const envelope = sequencer.driver.queue.take_sealed() orelse return null;
        const payload = &envelope.payload;
        const number = payload.block_number;
        if (number == 0 or number > chain.head) return error.GossipDiverged;
        if (payload.transactions.len != 2) return error.GossipDiverged;
        if (chain.chain.real) {
            if (!payload.block_hash.eql(chain.chain.real_hashes[number])) {
                return error.GossipDiverged;
            }
        } else if (low_word(payload.block_hash) != chain.chain.hashes[number]) {
            return error.GossipDiverged;
        }
        const hash = chain.chain.hashes[number];
        const user = codec.payload_from_tx(payload.transactions[1]) orelse
            return error.GossipDiverged;
        if (user != chain.chain.payloads[number]) return error.GossipDiverged;
        sequencer.gossiped += 1;
        return .{ .number = number, .payload = user, .hash = hash };
    }
};

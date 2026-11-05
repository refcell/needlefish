//! Proof collection and game submission (base/base `crates/proof/proposer/src/
//! {proof_collector,proof_submitter,output_proposer}.rs`).
//!
//! In order from its cursor the collector polls the next target's proof, re-checks it
//! against fresh canonical roots, and creates the game with `createWithInitData`. The L1
//! transaction is asynchronous here: one submission is in flight at a time and is polled
//! on later ticks until mined (then the game is looked up by key) or failed. Outcomes that
//! cannot safely advance the cursor ask the pipeline to restart from a fresh recovery.

const std = @import("std");
const assert = std.debug.assert;

const factory = @import("../contracts/dispute_game_factory.zig");
const interfaces = @import("interfaces.zig");
const target = @import("target.zig");
const recovery_module = @import("recovery.zig");
const dispatcher_module = @import("dispatcher.zig");

const Chain = interfaces.Chain;
const Prover = interfaces.Prover;
const Submitter = interfaces.Submitter;
const Hash = interfaces.Hash;
const Intervals = interfaces.Intervals;
const Proof = interfaces.Proof;
const SubmitFailure = interfaces.SubmitFailure;
const TxId = interfaces.TxId;
const RecoveredState = target.RecoveredState;
const Dispatcher = dispatcher_module.Dispatcher;

/// Largest game `initData` (proof bytes) the collector forwards: a TEE proof is 130 bytes,
/// the native prover's witness archive is hundreds of KiB (`base proposer` sizes its
/// submitter to match).
pub const init_data_bytes_max = 4 << 20;
/// `createWithInitData(uint32,bytes32,bytes,bytes)` calldata upper bound.
pub const calldata_bytes_max = 4 + 6 * 32 + 64 +
    recovery_module.extra_data_bytes_max + init_data_bytes_max;

pub const Config = struct {
    game_type: u32,
    /// Abandon tracking of an unmined game creation after this long; 0 disables.
    submit_timeout_ns: u64 = 0,
    /// Lookups of a just-created game before assuming it raced (base/base retries 3x).
    game_lookup_attempts_max: u32 = 3,
    /// Most targets one tick collects.
    steps_max: u32 = 16,
};

pub const Outcome = enum { idle, restart };

/// What the submission of one target is waiting for.
const InFlight = struct {
    phase: enum { pending, lookup },
    tx: TxId,
    /// The state the game chains from; the cursor advances only if it still matches.
    start: RecoveredState,
    target_block: u64,
    root_claim: Hash,
    session: Hash,
    extra_data_len: u32,
    sent_ns: u64,
    lookups: u32,
};

const Step = enum { wait, advanced, restart };

pub const Collector = struct {
    config: Config,
    chain: Chain,
    prover: Prover,
    submitter: Submitter,
    cursor: ?RecoveredState = null,
    in_flight: ?InFlight = null,
    scratch: recovery_module.KeyScratch = .{},
    proof_roots: [recovery_module.roots_max]Hash = undefined,
    extra_data: [recovery_module.extra_data_bytes_max]u8 = undefined,
    calldata: [calldata_bytes_max]u8 = undefined,
    stats: Stats = .{},

    pub const Stats = struct {
        proofs_ready: u64 = 0,
        proofs_failed: u64 = 0,
        root_mismatches: u64 = 0,
        games_created: u64 = 0,
        games_adopted: u64 = 0,
        submit_failures: u64 = 0,
        discards: u64 = 0,
        timeouts: u64 = 0,
    };

    pub fn init(config: Config, chain: Chain, prover: Prover, submitter: Submitter) Collector {
        assert(config.game_lookup_attempts_max > 0);
        assert(config.steps_max > 0);
        return .{ .config = config, .chain = chain, .prover = prover, .submitter = submitter };
    }

    /// Collects and submits ready proofs in order up to `finalized_head`.
    pub fn tick(
        collector: *Collector,
        dispatcher: *Dispatcher,
        finalized_head: u64,
        now_ns: u64,
    ) Outcome {
        var steps: u32 = 0;
        while (steps < collector.config.steps_max) : (steps += 1) {
            const step = if (collector.in_flight != null)
                collector.poll_in_flight(now_ns)
            else
                collector.collect_next(dispatcher, finalized_head, now_ns);
            switch (step) {
                .wait => return .idle,
                .restart => return .restart,
                .advanced => if (collector.cursor) |cursor| {
                    dispatcher.pop_before(cursor.l2_block_number);
                },
            }
        }
        assert(steps == collector.config.steps_max);
        return .idle;
    }

    fn collect_next(
        collector: *Collector,
        dispatcher: *const Dispatcher,
        finalized_head: u64,
        now_ns: u64,
    ) Step {
        assert(collector.in_flight == null);
        const cursor = collector.cursor orelse return .wait;
        const intervals = collector.chain.intervals_for(cursor.l2_block_number) catch return .wait;
        const block = cursor.l2_block_number;
        const target_block = target.next_block(block, intervals.block_interval) orelse return .wait;
        if (target_block > finalized_head) return .wait;
        const claimed = collector.chain.output_at_block(target_block) catch return .wait;
        const session = claimed.output_root;
        const dispatched = dispatcher.find(cursor.l2_block_number) != null;
        const status = collector.prover.poll(session) catch |err| switch (err) {
            error.Unavailable => return .wait,
            // Missing before dispatch is normal; after dispatch the prover lost it.
            error.NotFound => if (dispatched) return collector.delete(session) else return .wait,
        };
        switch (status) {
            .pending => return .wait,
            .failed => {
                collector.stats.proofs_failed += 1;
                return collector.delete(session);
            },
            .succeeded => |proof| {
                collector.stats.proofs_ready += 1;
                return collector.submit(cursor, intervals, target_block, session, proof, now_ns);
            },
        }
    }

    /// Validates a completed proof just in time and creates (or adopts) its game.
    fn submit(
        collector: *Collector,
        cursor: RecoveredState,
        intervals: Intervals,
        target_block: u64,
        session: Hash,
        proof: Proof,
        now_ns: u64,
    ) Step {
        assert(target_block == cursor.l2_block_number + intervals.block_interval);
        const key = switch (collector.validate(cursor, intervals, session, proof)) {
            .key => |key| key,
            .step => |step| return step,
        };
        assert(key.target_block == target_block);
        const extra_data = collector.extra_data[0..key.extra_data.len];
        const game_type = collector.config.game_type;
        const existing = collector.chain.game_lookup(game_type, key.root_claim, extra_data) catch {
            collector.stats.submit_failures += 1;
            return .restart;
        };
        if (existing) |game| {
            // base/base attaches its proof to the existing game; the game is the same
            // either way, so it becomes the parent.
            collector.stats.games_adopted += 1;
            collector.cursor = .{
                .parent = game,
                .output_root = key.root_claim,
                .l2_block_number = target_block,
            };
            return .advanced;
        }
        const calldata = factory.encode_create(
            &collector.calldata,
            game_type,
            key.root_claim,
            extra_data,
            proof.init_data,
        ) catch unreachable; // The buffer fits the largest extra data and init data.
        collector.in_flight = .{
            .phase = .pending,
            .tx = 0,
            .start = cursor,
            .target_block = target_block,
            .root_claim = key.root_claim,
            .session = session,
            .extra_data_len = @intCast(extra_data.len),
            .sent_ns = now_ns,
            .lookups = 0,
        };
        switch (collector.submitter.send(calldata)) {
            .pending => |tx| collector.in_flight.?.tx = tx,
            .failed => |failure| return collector.on_failure(failure),
        }
        return .wait;
    }

    const Validated = union(enum) { key: factory.LookupKey, step: Step };

    /// Checks the proof's claim and intermediate roots against fresh canonical roots
    /// (base/base JIT validation); the key's extra data lands in `collector.extra_data`.
    fn validate(
        collector: *Collector,
        cursor: RecoveredState,
        intervals: Intervals,
        session: Hash,
        proof: Proof,
    ) Validated {
        const root_count = intervals.root_count();
        // A proof the game cannot take as is (wrong root count, oversized) is re-proved.
        if (proof.intermediate_roots.len != root_count or
            proof.init_data.len > init_data_bytes_max)
        {
            return .{ .step = collector.discard(session) };
        }
        const roots = collector.proof_roots[0..root_count];
        @memcpy(roots, proof.intermediate_roots);
        const scratch = &collector.scratch;
        const chain = collector.chain;
        const key = recovery_module.canonical_key(chain, scratch, cursor, intervals) catch {
            collector.stats.submit_failures += 1;
            return .{ .step = .restart };
        };
        const canonical = scratch.roots[0..root_count];
        if (!std.mem.eql(u8, &proof.output_root, &key.root_claim) or
            !std.mem.eql(u8, std.mem.sliceAsBytes(roots), std.mem.sliceAsBytes(canonical)))
        {
            collector.stats.root_mismatches += 1;
            _ = collector.delete(session);
            return .{ .step = .restart };
        }
        assert(key.extra_data.len <= collector.extra_data.len);
        @memcpy(collector.extra_data[0..key.extra_data.len], key.extra_data);
        return .{ .key = .{
            .target_block = key.target_block,
            .root_claim = key.root_claim,
            .extra_data = collector.extra_data[0..key.extra_data.len],
        } };
    }

    fn poll_in_flight(collector: *Collector, now_ns: u64) Step {
        const flight = &collector.in_flight.?;
        switch (flight.phase) {
            .pending => {
                const timeout = collector.config.submit_timeout_ns;
                if (timeout > 0 and now_ns -| flight.sent_ns >= timeout) {
                    // The transaction may still land; the next recovery walk finds it.
                    collector.stats.timeouts += 1;
                    collector.in_flight = null;
                    return .restart;
                }
                switch (collector.submitter.status(flight.tx)) {
                    .pending => return .wait,
                    .mined => {
                        collector.stats.games_created += 1;
                        flight.phase = .lookup;
                        return collector.lookup_game();
                    },
                    .failed => |failure| return collector.on_failure(failure),
                }
            },
            .lookup => return collector.lookup_game(),
        }
    }

    /// Finds the game the in-flight submission created (or raced against) by its key.
    fn lookup_game(collector: *Collector) Step {
        const flight = &collector.in_flight.?;
        assert(flight.phase == .lookup);
        flight.lookups += 1;
        const extra_data = collector.extra_data[0..flight.extra_data_len];
        const game_type = collector.config.game_type;
        const found = collector.chain.game_lookup(game_type, flight.root_claim, extra_data) catch
            null;
        const game = found orelse {
            if (flight.lookups < collector.config.game_lookup_attempts_max) return .wait;
            collector.in_flight = null;
            return .restart;
        };
        const done = flight.*;
        collector.in_flight = null;
        if (collector.cursor) |cursor| {
            if (cursor.eql(done.start)) {
                collector.cursor = .{
                    .parent = game,
                    .output_root = done.root_claim,
                    .l2_block_number = done.target_block,
                };
            }
        }
        return .advanced;
    }

    /// base/base `submission_error_action` plus the collector's reaction to it.
    fn on_failure(collector: *Collector, failure: SubmitFailure) Step {
        const flight = &collector.in_flight.?;
        switch (failure) {
            .game_already_exists => {
                flight.phase = .lookup;
                return collector.lookup_game();
            },
            .invalid_parent_game, .l1_origin_too_old, .invalid_signer => {
                const session = flight.session;
                collector.in_flight = null;
                return collector.discard(session);
            },
            .unavailable, .reverted, .dropped => {
                // Keep the proof: transient L1 issues retry the same completed proof.
                collector.stats.submit_failures += 1;
                collector.in_flight = null;
                return .restart;
            },
        }
    }

    /// The proof cannot be submitted with current chain state: delete it to re-prove.
    fn discard(collector: *Collector, session: Hash) Step {
        assert(collector.in_flight == null);
        collector.stats.discards += 1;
        return collector.delete(session);
    }

    /// Deletes a session; a restart re-dispatches it. A failed delete idles and retries.
    fn delete(collector: *Collector, session: Hash) Step {
        collector.prover.delete(session) catch |err| switch (err) {
            error.NotFound => return .restart,
            error.Unavailable => return .wait,
        };
        return .restart;
    }
};

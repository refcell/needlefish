//! The proving pipeline (base/base `crates/proof/proposer/src/{pipeline,driver}.rs`) as a
//! deterministic state machine.
//!
//! Each `tick(now_ns)` (at most once per poll interval) recovers onchain state, moves the
//! dispatcher and collector cursors to it when it changed, dispatches proof requests ahead
//! of the collector, then collects and submits ready proofs in order. base/base runs the
//! dispatcher and collector as two concurrent loops with one recovery cache each and
//! restarts both when the collector needs fresh state; here they share one cache and a
//! restart clears it, both cursors and the dispatched ring.

const std = @import("std");
const assert = std.debug.assert;

const interfaces = @import("interfaces.zig");
const target = @import("target.zig");
const recovery_module = @import("recovery.zig");
const dispatcher_module = @import("dispatcher.zig");
const collector_module = @import("collector.zig");

const Address = interfaces.Address;
const RecoveredState = target.RecoveredState;

pub const Config = struct {
    game_type: u32,
    /// Game creator, bound into proof requests.
    proposer: Address,
    /// The "no parent" sentinel of the first game after an anchor without a game.
    anchor_state_registry: Address,
    poll_interval_ns: u64,
    /// 0 disables the submit timeout.
    submit_timeout_ns: u64 = 0,
    proofs_in_flight_max: u32 = 8,
    walk_steps_max: u32 = 256,
    game_lookup_attempts_max: u32 = 3,
};

pub const Pipeline = struct {
    config: Config,
    recovery: recovery_module.Recovery,
    dispatcher: dispatcher_module.Dispatcher,
    collector: collector_module.Collector,
    cache: ?recovery_module.Cache = null,
    /// The recovered state the cursors were last moved to.
    cursor_source: ?RecoveredState = null,
    next_tick_ns: u64 = 0,
    now_ns_last: u64 = 0,
    stats: Stats = .{},

    pub const Stats = struct {
        ticks: u64 = 0,
        skipped: u64 = 0,
        restarts: u64 = 0,
    };

    /// Initializes in place: the pipeline holds its scratch buffers (~140 KiB) inline.
    pub fn init(
        pipeline: *Pipeline,
        config: Config,
        chain: interfaces.Chain,
        prover: interfaces.Prover,
        submitter: interfaces.Submitter,
    ) void {
        assert(config.poll_interval_ns > 0);
        assert(config.proofs_in_flight_max > 0);
        assert(config.proofs_in_flight_max <= dispatcher_module.in_flight_limit);
        pipeline.* = .{
            .config = config,
            .recovery = .init(.{
                .game_type = config.game_type,
                .anchor_state_registry = config.anchor_state_registry,
                .walk_steps_max = config.walk_steps_max,
            }, chain),
            .dispatcher = .init(.{
                .proposer = config.proposer,
                .in_flight_max = config.proofs_in_flight_max,
            }, chain, prover),
            .collector = .init(.{
                .game_type = config.game_type,
                .submit_timeout_ns = config.submit_timeout_ns,
                .game_lookup_attempts_max = config.game_lookup_attempts_max,
                .steps_max = config.proofs_in_flight_max + 1,
            }, chain, prover, submitter),
        };
    }

    /// Runs one pipeline step if a poll interval has passed since the last one.
    pub fn tick(pipeline: *Pipeline, now_ns: u64) void {
        assert(now_ns >= pipeline.now_ns_last);
        pipeline.now_ns_last = now_ns;
        if (now_ns < pipeline.next_tick_ns) return;
        pipeline.next_tick_ns = now_ns + pipeline.config.poll_interval_ns;
        pipeline.stats.ticks += 1;

        const plan = pipeline.recovery.try_recover_and_plan(&pipeline.cache) orelse {
            pipeline.stats.skipped += 1;
            return;
        };
        pipeline.move_cursors(plan.state);
        pipeline.dispatcher.tick(plan.finalized_head, plan.sync_status);
        const outcome = pipeline.collector.tick(&pipeline.dispatcher, plan.finalized_head, now_ns);
        if (outcome == .restart) pipeline.restart();
        assert(pipeline.dispatcher.in_flight() <= pipeline.config.proofs_in_flight_max);
    }

    /// Moves both cursors to recovered state when it differs from the last one. While
    /// it is unchanged they keep their in-memory progress (base/base `cursor_source`).
    fn move_cursors(pipeline: *Pipeline, state: RecoveredState) void {
        if (pipeline.cursor_source) |source| {
            if (source.eql(state) and pipeline.collector.cursor != null) return;
        }
        pipeline.cursor_source = state;
        pipeline.collector.cursor = state;
        pipeline.dispatcher.rebase(state);
        assert(pipeline.dispatcher.cursor != null);
    }

    /// Drops every cache and cursor; the next tick recovers from chain state.
    fn restart(pipeline: *Pipeline) void {
        pipeline.stats.restarts += 1;
        pipeline.cache = null;
        pipeline.cursor_source = null;
        pipeline.collector.cursor = null;
        pipeline.collector.in_flight = null;
        pipeline.dispatcher.clear();
        // Retry on the next call rather than a poll interval later, as base/base restarts
        // its session immediately.
        pipeline.next_tick_ns = pipeline.now_ns_last;
        assert(pipeline.dispatcher.in_flight() == 0);
    }
};

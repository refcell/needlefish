//! The payload service: drives one single-shot payload job per `forkchoiceUpdated` with
//! attributes and serves `getPayload`. Mirrors the job lifecycle of base/base
//! `crates/builder/core` (`BlockPayloadJobGenerator`, `BlockPayloadJob`) on the one-shot
//! (post-Denim) path, where a payload is built once and frozen.
//!
//! base/base runs the job on a reth `PayloadBuilderService` with tokio timers. Here the
//! service is a synchronous state machine over injected time:
//! - `send_new_payload` (FCU with attributes) cancels any previous job
//!   (`ensure_only_one_payload`) and starts a new one whose slot begins at the last tick's
//!   time; the builder derives the template and copies the attribute transactions.
//! - `tick(now_ns)` builds a pending job: attribute transactions, then pool transactions
//!   until the injected clock reaches the slot's cutoff (the seal offset, 150 ms into the
//!   200 ms slot by default), then seals once. A sealed job stays resolvable until its slot
//!   end plus leeway, then expires.
//! - `resolve` (getPayload) returns the sealed block and ends the job. Called before the job
//!   was built, it seals immediately with the cutoff moved to now: it never waits, so it
//!   never runs past the slot end.
//!
//! A resolved `Payload` borrows the builder's buffers (transactions, extra data) and is
//! valid until the next job starts.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const payload = @import("../../execution/payload/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const builder_module = @import("builder.zig");
const timing = @import("timing.zig");

const Chain = chain_module.Chain;
const BlockBuilder = builder_module.BlockBuilder;
const B256 = primitives.B256;

pub const Clock = builder_module.Clock;
pub const Stop = builder_module.Stop;
pub const PayloadId = payload.PayloadId;
pub const PayloadAttributes = payload.PayloadAttributes;
pub const Error = error{BuildFailed};

/// The sealed block of a job (what `getPayload` returns).
pub const Payload = struct {
    id: PayloadId,
    header: consensus.Header,
    block_hash: B256,
    /// Priority fees paid to the fee recipient (wei).
    block_value: u256,
    /// Every transaction of the block, in order; borrows the builder.
    transactions: []const []const u8,
    /// The attributes' withdrawals; borrows the service until its next job.
    withdrawals: ?[]const payload.Withdrawal,
    /// Why the build stopped adding pool transactions.
    stop: Stop,
};

pub const Metrics = struct {
    jobs_started: metrics.Counter = .{},
    /// A job ended by a newer FCU before it was resolved.
    jobs_cancelled: metrics.Counter = .{},
    jobs_resolved: metrics.Counter = .{},
    /// A job that reached its expiry unresolved.
    jobs_expired: metrics.Counter = .{},
    job_start_failed: metrics.Counter = .{},
    blocks_sealed: metrics.Counter = .{},
    /// A build sealed by `resolve` before `tick` built it.
    blocks_sealed_early: metrics.Counter = .{},
    /// A build that stopped at its cutoff with pool transactions left.
    builds_cut_off: metrics.Counter = .{},
    build_failed: metrics.Counter = .{},
};

/// Why a started job ended without a sealed block reaching getPayload.
pub const EndReason = enum {
    /// A newer FCU replaced it (`ensure_only_one_payload`).
    cancelled,
    /// It reached its expiry unresolved.
    expired,
    /// Its build failed; getPayload answered `BuildFailed`.
    failed,
};

/// A job lifecycle event, for an external auditor (the DST slot invariants).
pub const Event = union(enum) {
    started: struct { id: PayloadId, number: u64, slot: timing.Slot },
    /// FCU with attributes that could not start a job (nothing is active afterwards).
    start_failed: struct { id: PayloadId },
    sealed: struct { id: PayloadId, number: u64, block_hash: B256, cutoff_ns: u64, stop: Stop },
    /// getPayload returned the sealed block; `now_ns` is when it arrived (it never waits).
    resolved: struct { id: PayloadId, number: u64, now_ns: u64 },
    ended: struct { id: PayloadId, number: u64, reason: EndReason },
};

pub const Observer = struct {
    context: *anyopaque,
    on_event: *const fn (context: *anyopaque, event: *const Event) void,

    /// An observer over any `*T` with `fn on_event(*T, *const Event) void`.
    pub fn of(comptime T: type, target: *T) Observer {
        const Adapter = struct {
            fn call(context: *anyopaque, event: *const Event) void {
                const typed: *T = @ptrCast(@alignCast(context));
                typed.on_event(event);
            }
        };
        return .{ .context = target, .on_event = Adapter.call };
    }
};

pub const Service = struct {
    const JobState = enum { pending, sealed, failed };

    const Job = struct {
        id: PayloadId,
        timestamp: u64,
        slot: timing.Slot,
        state: JobState,
        number: u64,
        /// Valid once `sealed`.
        best: Payload,
    };

    builder: *BlockBuilder,
    chain: *Chain,
    clock: Clock,
    config: timing.Config,
    now_ns: u64 = 0,
    job: ?Job = null,
    /// The active job's attributes (the builder borrows them for the whole job).
    attributes: PayloadAttributes = undefined,
    withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined,
    metrics: Metrics = .{},
    /// Receives every job event when set (simulation and tests).
    observer: ?Observer = null,

    /// The service must not move while a job is active (the builder points into it).
    /// `clock` is read during a build to stop at the cutoff; `tick` supplies the time
    /// between builds. Both must be the same time base.
    pub fn init(
        builder: *BlockBuilder,
        chain: *Chain,
        clock: Clock,
        config: timing.Config,
    ) timing.ConfigError!Service {
        try config.validate();
        assert(builder.state == .idle);
        assert(builder.config.transactions_max > 0);
        return .{ .builder = builder, .chain = chain, .clock = clock, .config = config };
    }

    /// FCU with attributes: starts a payload job whose slot begins at the last tick's time.
    pub fn send_new_payload(
        service: *Service,
        id: PayloadId,
        parent: [32]u8,
        attributes: *const PayloadAttributes,
    ) Error!void {
        service.cancel();
        const withdrawals = attributes.withdrawals orelse &.{};
        if (withdrawals.len > service.withdrawals.len) return service.start_failed(id);
        // base/base: a zero parent hash builds on the latest block.
        const zero: [32]u8 = @splat(0);
        const parent_hash = if (std.mem.eql(u8, &parent, &zero))
            service.chain.head_hash()
        else
            parent;
        service.attributes = attributes.*;
        const copy = service.withdrawals[0..withdrawals.len];
        @memcpy(copy, withdrawals);
        if (attributes.withdrawals != null) service.attributes.withdrawals = copy;
        service.builder.start(service.chain, .{
            .payload_id = id,
            .parent_hash = parent_hash,
            .attributes = &service.attributes,
        }) catch return service.start_failed(id);
        // The builder copied the attribute transactions; drop the caller's slices so the
        // job holds no borrowed memory.
        service.attributes.transactions = null;
        service.job = .{
            .id = id,
            .timestamp = attributes.timestamp,
            .slot = timing.Slot.init(service.config, service.now_ns),
            .state = .pending,
            .number = service.builder.template.number,
            .best = undefined,
        };
        service.metrics.jobs_started.increment();
        assert(service.builder.state == .started);
        const job = &service.job.?;
        service.emit(.{ .started = .{ .id = id, .number = job.number, .slot = job.slot } });
    }

    fn emit(service: *const Service, event: Event) void {
        const observer = service.observer orelse return;
        assert(event != .started or service.job != null);
        observer.on_event(observer.context, &event);
    }

    fn start_failed(service: *Service, id: PayloadId) Error {
        assert(service.job == null);
        service.metrics.job_start_failed.increment();
        service.emit(.{ .start_failed = .{ .id = id } });
        return error.BuildFailed;
    }

    /// Ends the active job unresolved (a newer FCU replaces it).
    fn cancel(service: *Service) void {
        const job = service.job orelse return;
        service.job = null;
        service.metrics.jobs_cancelled.increment();
        service.emit(.{ .ended = .{ .id = job.id, .number = job.number, .reason = .cancelled } });
        assert(service.job == null);
    }

    /// Advances time: builds and seals a pending job (stopping at its cutoff), then drops
    /// a job whose expiry has passed.
    pub fn tick(service: *Service, now_ns: u64) void {
        assert(now_ns >= service.now_ns);
        assert(now_ns <= timing.time_ns_max);
        service.now_ns = now_ns;
        const job = &(service.job orelse return);
        if (job.state == .pending) service.seal(job, job.slot.cutoff_ns);
        assert(job.state != .pending);
        if (now_ns >= job.slot.expires_ns) {
            const ended: Event = .{ .ended = .{
                .id = job.id,
                .number = job.number,
                .reason = .expired,
            } };
            service.job = null;
            service.metrics.jobs_expired.increment();
            service.emit(ended);
        }
    }

    /// Advances time without building or expiring anything (an FCU or getPayload arriving
    /// between ticks): the next job's slot starts here, an early resolve cuts off here.
    pub fn set_now(service: *Service, now_ns: u64) void {
        assert(now_ns <= timing.time_ns_max);
        service.now_ns = @max(service.now_ns, now_ns);
        assert(service.now_ns >= now_ns);
    }

    /// Runs the job's one build with `cutoff_ns` and records the sealed block. The chain's
    /// state may have moved since the job started (a block imported in between): it is
    /// brought back to the parent first.
    fn seal(service: *Service, job: *Job, cutoff_ns: u64) void {
        assert(job.state == .pending);
        assert(cutoff_ns <= job.slot.cutoff_ns);
        const builder = service.builder;
        service.chain.move_state(builder.job.parent_hash) catch {
            job.state = .failed;
            service.metrics.build_failed.increment();
            return;
        };
        const stop = builder.build(service.clock, cutoff_ns) catch {
            job.state = .failed;
            service.metrics.build_failed.increment();
            return;
        };
        const header = builder.sealed_header();
        job.best = .{
            .id = job.id,
            .header = header.*,
            .block_hash = header.hash(),
            .block_value = builder.block_value(),
            .transactions = builder.block_transactions(),
            .withdrawals = service.attributes.withdrawals,
            .stop = stop,
        };
        job.state = .sealed;
        service.metrics.blocks_sealed.increment();
        if (stop == .cutoff) service.metrics.builds_cut_off.increment();
        assert(job.best.header.timestamp == job.timestamp);
        assert(job.best.header.number == job.number);
        service.emit(.{ .sealed = .{
            .id = job.id,
            .number = job.number,
            .block_hash = job.best.block_hash,
            .cutoff_ns = cutoff_ns,
            .stop = stop,
        } });
    }

    /// When `tick` must run next: now for a pending job, its expiry for a built one; null
    /// without an active job.
    pub fn next_deadline_ns(service: *const Service) ?u64 {
        const job = service.job orelse return null;
        assert(job.slot.expires_ns > service.now_ns or job.state == .pending);
        if (job.state == .pending) return service.now_ns;
        return job.slot.expires_ns;
    }

    /// The active job's id, if any.
    pub fn active_id(service: *const Service) ?PayloadId {
        const job = service.job orelse return null;
        return job.id;
    }

    fn job_for(service: *Service, id: PayloadId) ?*Job {
        const job = &(service.job orelse return null);
        if (!std.mem.eql(u8, &job.id, &id)) return null;
        return job;
    }

    pub fn payload_timestamp(service: *Service, id: PayloadId) ?u64 {
        const job = service.job_for(id) orelse return null;
        assert(job.state != .sealed or job.timestamp == job.best.header.timestamp);
        return job.timestamp;
    }

    /// getPayload: the sealed block, sealing now if the job was not built yet; ends the job.
    /// Null when `id` is not the active job.
    pub fn resolve(service: *Service, id: PayloadId) ?(Error!Payload) {
        const job = service.job_for(id) orelse return null;
        if (job.state == .pending) {
            service.metrics.blocks_sealed_early.increment();
            service.seal(job, job.slot.cutoff_at(service.now_ns));
        }
        assert(job.state != .pending);
        const state = job.state;
        const best = job.best;
        const number = job.number;
        service.job = null;
        service.metrics.jobs_resolved.increment();
        if (state == .failed) {
            service.emit(.{ .ended = .{ .id = id, .number = number, .reason = .failed } });
            return error.BuildFailed;
        }
        assert(std.mem.eql(u8, &best.id, &id));
        const now_ns = service.now_ns;
        service.emit(.{ .resolved = .{ .id = id, .number = number, .now_ns = now_ns } });
        return best;
    }
};

test {
    _ = @import("service_test.zig");
    _ = @import("cadence_test.zig");
}

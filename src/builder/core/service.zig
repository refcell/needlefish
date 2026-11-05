//! The flashblocks payload service: drives one payload job per `forkchoiceUpdated` with
//! attributes and serves `getPayload`. Mirrors base/base
//! `crates/builder/core/src/flashblocks/{service,handler,resting}.rs` and the job lifecycle
//! of `generator.rs` (`BlockPayloadJobGenerator`, `BlockPayloadJob`).
//!
//! base/base runs the job on a reth `PayloadBuilderService` with tokio timers. Here the
//! service is a synchronous state machine over injected time:
//! - `send_new_payload` (FCU with attributes) cancels any previous job
//!   (`ensure_only_one_payload`), starts the generator, and publishes flashblock 0.
//! - `tick(now_ns)` builds and publishes every regular flashblock whose deadline has passed
//!   (the interval timer, burst on missed ticks), then ends the job at its
//!   `PayloadJobDeadline` (timestamp plus leeway): an expired job is gone, as in reth.
//! - `resolve` (getPayload) returns the best sealed payload so far and ends the job
//!   (`resolve_kind` cancels it; `KeepPayloadJobAlive::No`).
//! - `next_deadline_ns` tells the IO loop when to call `tick` next.
//!
//! `handler.rs` only forwards built payloads to reth's event stream; the service keeps the
//! best payload itself. `resting.rs` holds no transactions back by default (resting is off
//! in base/base), so every job's resting carry is zero.
//!
//! The service satisfies the comptime `Builder` interface of `builder/multiplex`.
//! `send_new_payload` uses the time of the last `tick`. A resolved `Payload` borrows the
//! generator's buffers (transactions, extra data) and is valid until the next job starts.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const payload = @import("../../execution/payload/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const metrics = @import("../../utilities/metrics/root.zig");
const multiplex = @import("../multiplex/root.zig");
const generator_module = @import("generator.zig");
const timing = @import("timing.zig");

const Chain = chain_module.Chain;
const Generator = generator_module.Generator;
const Flashblock = generator_module.Flashblock;
const B256 = primitives.B256;

pub const PayloadId = payload.PayloadId;
pub const PayloadAttributes = payload.PayloadAttributes;
pub const BuilderError = multiplex.BuilderError;

/// The best sealed block of a job (what `getPayload` returns).
pub const Payload = struct {
    id: PayloadId,
    /// Index of the last flashblock folded into this block (0 = fallback block).
    flashblock_index: u32,
    header: consensus.Header,
    block_hash: B256,
    /// Priority fees paid to the fee recipient (wei).
    block_value: u256,
    /// Every transaction of the block, in order; borrows the generator.
    transactions: []const []const u8,
};

pub const Metrics = struct {
    jobs_started: metrics.Counter = .{},
    /// A job ended by a newer FCU before it was resolved.
    jobs_cancelled: metrics.Counter = .{},
    jobs_resolved: metrics.Counter = .{},
    /// A job that reached its payload deadline unresolved.
    jobs_expired: metrics.Counter = .{},
    job_start_failed: metrics.Counter = .{},
    flashblocks_built: metrics.Counter = .{},
    flashblock_build_failed: metrics.Counter = .{},
    publish_failed: metrics.Counter = .{},
};

/// `Sink` must provide `publish(*Sink, Flashblock) E!u32` for some error set `E`
/// (`builder/publish.Publisher(IO)` does).
pub fn Service(comptime Sink: type) type {
    return struct {
        const Self = @This();

        const Job = struct {
            id: PayloadId,
            timestamp: u64,
            schedule: timing.Schedule,
            /// Regular flashblocks this job builds: `min(schedule.count, flashblocks_max)`.
            count: u32,
            /// Next regular flashblock to build (1..=count + 1).
            index_next: u32,
            /// False once the generator finished, failed, or takes no pool transactions.
            building: bool,
            /// `PayloadJobDeadline`: the job is dropped at this time.
            expires_ns: u64,
            best: Payload,
        };

        generator: *Generator,
        chain: *Chain,
        sink: *Sink,
        config: timing.Config,
        now_ns: u64 = 0,
        job: ?Job = null,
        /// The active job's attributes (the generator borrows them for the whole job).
        attributes: PayloadAttributes = undefined,
        withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined,
        metrics: Metrics = .{},

        /// The service must not move while a job is active (the generator points into it).
        pub fn init(
            generator: *Generator,
            chain: *Chain,
            sink: *Sink,
            config: timing.Config,
        ) timing.ConfigError!Self {
            try config.validate();
            assert(generator.config.flashblocks_max > 0);
            assert(!generator.active);
            return .{ .generator = generator, .chain = chain, .sink = sink, .config = config };
        }

        /// Starts a payload job at the last tick's time (multiplex `Builder` interface).
        pub fn send_new_payload(
            service: *Self,
            id: PayloadId,
            parent: [32]u8,
            attributes: *const PayloadAttributes,
        ) BuilderError!void {
            service.cancel();
            const withdrawals = attributes.withdrawals orelse &.{};
            if (withdrawals.len > service.withdrawals.len) return service.start_failed();
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
            const now_ns = service.now_ns;
            const schedule = timing.Schedule.init(service.config, attributes.timestamp, now_ns, 0);
            const count: u32 = @intCast(@min(
                schedule.count,
                service.generator.config.flashblocks_max,
            ));
            const flashblock = service.generator.start(service.chain, .{
                .payload_id = id,
                .parent_hash = parent_hash,
                .attributes = &service.attributes,
                .flashblock_count = count,
            }) catch return service.start_failed();
            // The generator reads attribute transactions only for flashblock 0 (it copied
            // them); dropping the caller's slices keeps the job free of borrowed memory.
            service.attributes.transactions = null;
            const duration_ns = timing.payload_job_duration_ns(
                service.config,
                attributes.timestamp,
                now_ns,
            );
            service.job = .{
                .id = id,
                .timestamp = attributes.timestamp,
                .schedule = schedule,
                .count = count,
                .index_next = 1,
                .building = !(attributes.no_tx_pool orelse false),
                .expires_ns = now_ns +| duration_ns,
                .best = undefined,
            };
            service.metrics.jobs_started.increment();
            service.accept(flashblock);
            assert(service.job.?.best.flashblock_index == 0);
        }

        fn start_failed(service: *Self) BuilderError {
            assert(service.job == null);
            service.metrics.job_start_failed.increment();
            return error.BuildFailed;
        }

        /// Ends the active job unresolved (a newer FCU replaces it).
        fn cancel(service: *Self) void {
            if (service.job == null) return;
            service.job = null;
            service.metrics.jobs_cancelled.increment();
            assert(service.job == null);
        }

        /// Advances time: builds every flashblock whose deadline is at or before `now_ns`,
        /// then drops the job once its payload deadline has passed.
        pub fn tick(service: *Self, now_ns: u64) void {
            assert(now_ns >= service.now_ns);
            assert(now_ns <= timing.time_ns_max);
            service.now_ns = now_ns;
            const job = &(service.job orelse return);
            // Bounded: each pass builds one flashblock or stops building.
            while (job.building and job.index_next <= job.count) {
                if (job.schedule.deadline_ns(job.index_next) > now_ns) break;
                service.build_next(job);
            }
            if (job.index_next > job.count) job.building = false;
            if (now_ns >= job.expires_ns) {
                service.job = null;
                service.metrics.jobs_expired.increment();
            }
        }

        fn build_next(service: *Self, job: *Job) void {
            assert(job.building);
            assert(job.index_next <= job.count);
            const flashblock = service.generator.next(service.now_ns) catch {
                // The last sealed payload stays resolvable (base/base's watch channel).
                job.building = false;
                service.metrics.flashblock_build_failed.increment();
                return;
            } orelse {
                job.building = false;
                return;
            };
            assert(flashblock.index == job.index_next);
            service.accept(flashblock);
        }

        /// Records a freshly built flashblock as the job's best payload and publishes it.
        fn accept(service: *Self, flashblock: Flashblock) void {
            const job = &service.job.?;
            const generator = service.generator;
            const header = generator.sealed_header();
            const transactions = generator.block_transactions();
            assert(std.mem.eql(u8, &header.hash().bytes, &flashblock.diff.block_hash.bytes));
            job.best = .{
                .id = job.id,
                .flashblock_index = @intCast(flashblock.index),
                .header = header.*,
                .block_hash = flashblock.diff.block_hash,
                .block_value = generator.block_value(),
                .transactions = transactions,
            };
            if (flashblock.index > 0) job.index_next = @intCast(flashblock.index + 1);
            service.metrics.flashblocks_built.increment();
            // A no-tx-pool (shadow or syncing) job publishes nothing.
            if (service.attributes.no_tx_pool orelse false) return;
            if (service.sink.publish(flashblock)) |_| {} else |_| {
                service.metrics.publish_failed.increment();
            }
        }

        /// When `tick` must run next: the next flashblock deadline or the job's payload
        /// deadline; null without an active job.
        pub fn next_deadline_ns(service: *const Self) ?u64 {
            const job = service.job orelse return null;
            assert(job.expires_ns > service.now_ns);
            if (job.building and job.index_next <= job.count) {
                const deadline_ns = job.schedule.deadline_ns(job.index_next);
                assert(deadline_ns > service.now_ns);
                return @min(deadline_ns, job.expires_ns);
            }
            return job.expires_ns;
        }

        /// The active job's id, if any.
        pub fn active_id(service: *const Self) ?PayloadId {
            const job = service.job orelse return null;
            return job.id;
        }

        fn job_for(service: *Self, id: PayloadId) ?*Job {
            const job = &(service.job orelse return null);
            if (!std.mem.eql(u8, &job.id, &id)) return null;
            return job;
        }

        /// base/base `BlockPayloadJob::best_payload` is unsupported (use `resolve`).
        pub fn best_payload(service: *Self, id: PayloadId) ?(BuilderError!Payload) {
            _ = service.job_for(id) orelse return null;
            return error.BuildFailed;
        }

        pub fn payload_timestamp(service: *Self, id: PayloadId) ?(BuilderError!u64) {
            const job = service.job_for(id) orelse return null;
            assert(job.timestamp == job.best.header.timestamp);
            return job.timestamp;
        }

        /// getPayload: the best sealed payload so far; ends the job.
        pub fn resolve(service: *Self, id: PayloadId) ?(BuilderError!Payload) {
            const job = service.job_for(id) orelse return null;
            const best = job.best;
            service.job = null;
            service.metrics.jobs_resolved.increment();
            assert(std.mem.eql(u8, &best.id, &id));
            return best;
        }
    };
}

test {
    _ = @import("service_test.zig");
}

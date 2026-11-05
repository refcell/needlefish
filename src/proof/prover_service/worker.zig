//! The prover worker (base/base `crates/proof/worker/src/{job_discovery,claimed_job,
//! heartbeat,proof_submitter,task}.rs`) as a `tick`-driven state machine over an injected
//! proving `Backend`:
//!
//!   idle --getNextProof--> proving --backend result--> submitting --submitProof--> idle
//!                            |  \--backend error--> abandoning --abandonProof--> idle
//!                            \--heartbeat rejected (lease lost, cancelled) or the lease
//!                               deadline passed--> idle (backend cancelled)
//!
//! While proving, the worker heartbeats every `heartbeat_interval_ns`, or at half the time
//! left when the lease is closer than that (base/base `WorkerHeartbeat::until_failure`),
//! and gives the job up after `heartbeat_failures_max` consecutive transport failures.
//! Submissions and abandons are retried on later ticks until the service answers (base/base
//! `submit_until_delivered_or_cancelled`). One job at a time (base/base's default
//! `max_concurrent_jobs = 1`). Every RPC is one blocking `Client` call.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("protocol.zig");
const client_module = @import("client.zig");
const Clock = @import("service.zig").Clock;

pub const BackendError = error{
    /// The backend cannot prove this kind of request.
    Unsupported,
    /// Proving failed (missing data, the claim does not hold, the proof is too large).
    Failed,
};

/// A proving backend (base/base's TEE, SP1 cluster/network backends). `start` begins a job;
/// `poll` returns null while it runs, then its result, whose slices stay valid until the
/// next `start`; `cancel` drops the running job.
pub const Backend = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        start: *const fn (context: *anyopaque, job: *const protocol.ProofJob) BackendError!void,
        poll: *const fn (context: *anyopaque) BackendError!?protocol.ProofResult,
        cancel: *const fn (context: *anyopaque) void,
    };

    pub fn start(backend: Backend, job: *const protocol.ProofJob) BackendError!void {
        assert(job.status == .claimed);
        return backend.vtable.start(backend.context, job);
    }

    pub fn poll(backend: Backend) BackendError!?protocol.ProofResult {
        return backend.vtable.poll(backend.context);
    }

    pub fn cancel(backend: Backend) void {
        backend.vtable.cancel(backend.context);
    }
};

pub const Config = struct {
    worker_id: protocol.WorkerId,
    proof_type: protocol.ProofType,
    tee_kinds: []const protocol.TeeKind = &.{},
    zk_vms: []const protocol.ZkVm = &.{},
    zk_backends: []const protocol.ZkBackend = &.{},
    /// 0: the service default.
    lock_duration_seconds: u32 = 0,
    poll_interval_ns: u64 = 5 * std.time.ns_per_s,
    heartbeat_interval_ns: u64 = 30 * std.time.ns_per_s,
    heartbeat_failures_max: u32 = 5,
};

/// base/base `ASSUMED_DEFAULT_WORKER_LOCK_DURATION_SECONDS`.
const assumed_lock_seconds = 300;

pub const State = enum { idle, proving, submitting, abandoning };

pub const Stats = struct {
    claimed: u64 = 0,
    submitted: u64 = 0,
    abandoned: u64 = 0,
    /// Jobs given up because the lease was lost, expired or cancelled.
    lost: u64 = 0,
    heartbeats: u64 = 0,
};

pub fn Worker(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Client = client_module.Client(IO);

        client: *Client,
        backend: Backend,
        clock: Clock,
        config: Config,
        state: State = .idle,
        job: protocol.ProofJob = undefined,
        result: protocol.ProofResult = undefined,
        abandon_message: protocol.ErrorMessage = .{},
        poll_next_ns: u64 = 0,
        heartbeat_next_ns: u64 = 0,
        lease_deadline_ns: u64 = 0,
        heartbeat_failures: u32 = 0,
        stats: Stats = .{},

        pub fn init(client: *Client, backend: Backend, clock: Clock, config: Config) Self {
            assert(config.worker_id.len > 0);
            assert(config.heartbeat_interval_ns > 0 and config.poll_interval_ns > 0);
            return .{ .client = client, .backend = backend, .clock = clock, .config = config };
        }

        /// Advances the worker by one step at the current time.
        pub fn tick(worker: *Self) void {
            const now_ns = worker.clock.read();
            switch (worker.state) {
                .idle => worker.discover(now_ns),
                .proving => worker.prove(now_ns),
                .submitting => worker.submit(),
                .abandoning => worker.abandon(),
            }
        }

        /// base/base `JobDiscovery`: claims the next job matching the worker's filter.
        fn discover(worker: *Self, now_ns: u64) void {
            assert(worker.state == .idle);
            if (now_ns < worker.poll_next_ns) return;
            worker.poll_next_ns = now_ns + worker.config.poll_interval_ns;
            const config = &worker.config;
            const response = worker.client.get_next_proof(&.{
                .worker_id = config.worker_id,
                .proof_type = config.proof_type,
                .tee_kinds = config.tee_kinds,
                .zk_vms = config.zk_vms,
                .zk_backends = config.zk_backends,
                .lock_duration_seconds = config.lock_duration_seconds,
            }) catch return;
            const job = response.job orelse return;
            if (job.status != .claimed or job.lock_id == null) return;
            worker.job = job;
            worker.stats.claimed += 1;
            worker.heartbeat_failures = 0;
            worker.lease_deadline_ns = worker.deadline_of(&job, now_ns);
            worker.heartbeat_next_ns = worker.heartbeat_due(now_ns);
            worker.backend.start(&worker.job) catch |err| {
                worker.give_up_to_abandon(err);
                return;
            };
            worker.state = .proving;
        }

        fn deadline_of(worker: *const Self, job: *const protocol.ProofJob, now_ns: u64) u64 {
            if (job.lock_expires_at) |expiry| return expiry.seconds * std.time.ns_per_s;
            const seconds = if (worker.config.lock_duration_seconds == 0)
                assumed_lock_seconds
            else
                worker.config.lock_duration_seconds;
            return now_ns + @as(u64, seconds) * std.time.ns_per_s;
        }

        /// The next heartbeat: the interval, or half the time left on a short lease.
        fn heartbeat_due(worker: *const Self, now_ns: u64) u64 {
            const remaining = worker.lease_deadline_ns -| now_ns;
            const delay = @max(@min(worker.config.heartbeat_interval_ns, remaining / 2), 1);
            assert(delay <= worker.config.heartbeat_interval_ns);
            return now_ns + delay;
        }

        fn prove(worker: *Self, now_ns: u64) void {
            assert(worker.state == .proving);
            if (now_ns >= worker.heartbeat_next_ns) {
                if (!worker.heartbeat(now_ns)) return;
            }
            const result = worker.backend.poll() catch |err| {
                worker.give_up_to_abandon(err);
                return;
            } orelse return;
            worker.result = result;
            worker.state = .submitting;
            worker.submit();
        }

        /// Extends the lease; false when the job was given up.
        fn heartbeat(worker: *Self, now_ns: u64) bool {
            const job = &worker.job;
            worker.stats.heartbeats += 1;
            const response = worker.client.heartbeat(&.{
                .session_id = job.session_id,
                .lock_id = job.lock_id.?,
                .worker_id = worker.config.worker_id,
                .lock_duration_seconds = worker.config.lock_duration_seconds,
            }) catch |err| {
                const lost = switch (err) {
                    error.Rejected, error.NotFound => true,
                    error.Unavailable => blk: {
                        worker.heartbeat_failures += 1;
                        const failures_max = worker.config.heartbeat_failures_max;
                        break :blk worker.heartbeat_failures >= failures_max or
                            now_ns >= worker.lease_deadline_ns;
                    },
                };
                if (!lost) {
                    worker.heartbeat_next_ns = worker.heartbeat_due(now_ns);
                    return true;
                }
                worker.backend.cancel();
                worker.stats.lost += 1;
                worker.state = .idle;
                return false;
            };
            worker.heartbeat_failures = 0;
            worker.lease_deadline_ns = worker.deadline_of(&response.job, now_ns);
            worker.heartbeat_next_ns = worker.heartbeat_due(now_ns);
            return true;
        }

        fn give_up_to_abandon(worker: *Self, err: BackendError) void {
            worker.abandon_message = protocol.ErrorMessage.from(switch (err) {
                error.Unsupported => "worker backend does not support this proof request",
                error.Failed => "worker backend failed to generate the proof",
            });
            worker.state = .abandoning;
        }

        /// base/base `ProofSubmitter`: delivers the result; transport failures retry later.
        fn submit(worker: *Self) void {
            assert(worker.state == .submitting);
            const job = &worker.job;
            _ = worker.client.submit_proof(&.{
                .session_id = job.session_id,
                .lock_id = job.lock_id.?,
                .worker_id = worker.config.worker_id,
                .result = worker.result,
            }) catch |err| switch (err) {
                error.Unavailable => return,
                error.Rejected, error.NotFound => {
                    worker.stats.lost += 1;
                    worker.state = .idle;
                    return;
                },
            };
            worker.stats.submitted += 1;
            worker.state = .idle;
        }

        fn abandon(worker: *Self) void {
            assert(worker.state == .abandoning);
            const job = &worker.job;
            _ = worker.client.abandon_proof(&.{
                .session_id = job.session_id,
                .lock_id = job.lock_id.?,
                .worker_id = worker.config.worker_id,
                .error_message = worker.abandon_message,
            }) catch |err| switch (err) {
                error.Unavailable => return,
                error.Rejected, error.NotFound => {},
            };
            worker.stats.abandoned += 1;
            worker.state = .idle;
        }
    };
}

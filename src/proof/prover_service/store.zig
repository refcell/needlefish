//! The prover service job store: a fixed-capacity, in-memory replacement for base/base's
//! Postgres `ProofRequestRepo` (`prover-service/db/src/repo.rs`) and its status poller's
//! reaper (`src/worker/status_poller.rs`). Every operation takes the current time, so the
//! store is a pure state machine the simulator can drive.
//!
//! A job is keyed by its canonical session id (base/base's unique session index):
//!
//!   pending --claim--> claimed --submit--> succeeded
//!      ^                 |  |
//!      +--abandon/expiry-+  +--abandon/expiry with the reclaim budget spent--> failed
//!   pending/claimed --cancel--> cancelled (reported as failed with the cancel message)
//!
//! A claim is a lease: a fresh lock id, the worker id and a deadline that heartbeats push
//! out. Only the lease holder may heartbeat, abandon, record a backend session or submit,
//! and only before the deadline. An expired lease is claimable again (and `expire` requeues
//! it) while attempts remain. Requests are idempotent: the same session and request replay
//! the existing job, a different request under the same session is a collision, and a
//! failed job is requeued only when the requester allows it and retries remain.
//!
//! Memory is allocated once in `init` (job slots, proof bytes and roots per slot); lookups
//! scan the slots, which `jobs_max` bounds.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("protocol.zig");

const Hash = protocol.Hash;
const ProofRequest = protocol.ProofRequest;
const ProofResult = protocol.ProofResult;
const SessionId = protocol.SessionId;
const LockId = protocol.LockId;
const WorkerId = protocol.WorkerId;

pub const Config = struct {
    jobs_max: u32 = 64,
    /// Largest proof a worker may submit.
    proof_bytes_max: u32 = 1 << 20,
    roots_max: u32 = protocol.intermediate_root_count_max,
    /// base/base `max_proof_retries`: requester retries of a failed session.
    max_proof_retries: u32 = 3,
    /// base/base `WorkerQueueConfig::reclaim_attempts`: claims per (re)queued job.
    reclaim_attempts: u32 = 5,
    default_lock_duration_seconds: u32 = 300,
    max_lock_duration_seconds: u32 = 3600,
    /// Seeds lock ids, so a run is reproducible.
    seed: u64 = 0,
};

pub const State = enum { free, pending, claimed, succeeded, failed, cancelled };

pub const Job = struct {
    state: State = .free,
    /// Creation order, for listing and claim tie-breaks.
    sequence: u64 = 0,
    request: ProofRequest = undefined,
    attempt: u32 = 0,
    retry_count: u32 = 0,
    lock_id: LockId = .{},
    worker_id: WorkerId = .{},
    lock_expires_ns: u64 = 0,
    created_ns: u64 = 0,
    updated_ns: u64 = 0,
    completed_ns: u64 = 0,
    error_message: protocol.ErrorMessage = .{},
    result: ?ProofResult = null,
    /// The backend session per `SessionType`.
    sessions: [2]?protocol.BackendSession = .{ null, null },
    proof_memory: []u8,
    roots_memory: []Hash,
    signature_memory: [protocol.signature_bytes_max]u8 = undefined,

    pub fn terminal(job: *const Job) bool {
        return switch (job.state) {
            .succeeded, .failed, .cancelled => true,
            .free, .pending, .claimed => false,
        };
    }

    pub fn session_id(job: *const Job) []const u8 {
        assert(job.state != .free);
        return job.request.session_id.slice();
    }

    pub fn expired(job: *const Job, now_ns: u64) bool {
        assert(job.state == .claimed);
        return job.lock_expires_ns <= now_ns;
    }

    pub fn proof_status(job: *const Job) protocol.ProofStatus {
        return switch (job.state) {
            .free => unreachable,
            .pending => .queued,
            .claimed => .running,
            .succeeded => .succeeded,
            .failed, .cancelled => .failed,
        };
    }

    pub fn job_status(job: *const Job) protocol.ProofJobStatus {
        return switch (job.state) {
            .free => unreachable,
            .pending => .pending,
            .claimed => .claimed,
            .succeeded => .succeeded,
            .failed, .cancelled => .failed,
        };
    }

    /// The first block the job proves, which orders claims like base/base's
    /// `start_block_number`.
    fn start_block(job: *const Job) u64 {
        return switch (job.request.request) {
            .compressed => |zk| zk.start_block_number,
            .snark_plonk => |snark| snark.proof.start_block_number,
            .tee => |tee| tee.proof.claimed_l2_block_number,
        };
    }

    fn clear_lease(job: *Job) void {
        job.lock_id = .{};
        job.worker_id = .{};
        job.lock_expires_ns = 0;
    }
};

/// base/base `ClaimAuth::classify`.
pub const Auth = enum {
    authorized,
    not_found,
    not_claimed,
    stale_lock,
    expired,
    terminal,
    cancelled,
};

pub const CreateOutcome = enum {
    created,
    replayed,
    requeued,
    retry_not_allowed,
    retry_exhausted,
    cancelled,
};

pub const CreateError = error{ IdCollision, Full, InvalidRange };

pub const Filter = struct {
    proof_type: protocol.ProofType,
    tee_kinds: []const protocol.TeeKind = &.{},
    zk_vms: []const protocol.ZkVm = &.{},
    zk_backends: []const protocol.ZkBackend = &.{},
};

pub const Lease = struct {
    session_id: []const u8,
    lock_id: []const u8,
    worker_id: []const u8,
};

pub const Answer = struct { auth: Auth, job: ?*const Job };

pub const AbandonOutcome = enum { requeued, failed };

pub const SubmitOutcome = enum {
    completed,
    already_completed,
    /// The result does not fit the request (kind, VM, claimed root), or is oversized.
    result_mismatch,
    /// The job already succeeded with a different result.
    result_conflict,
};

pub const CancelOutcome = enum {
    cancelled,
    already_cancelled,
    not_found,
    unsupported_backend,
    already_terminal,
};

pub const DeleteOutcome = enum { deleted, not_found, not_completed };

/// Job outcomes since startup (base/base `prover_service.*` metrics).
pub const Stats = struct {
    created: u64 = 0,
    /// Failed requests requeued by a retrying `create`.
    retried: u64 = 0,
    succeeded: u64 = 0,
    failed: u64 = 0,
    cancelled: u64 = 0,
    abandoned: u64 = 0,
    /// Expired leases reaped (stuck requests).
    expired: u64 = 0,
};

pub const Store = struct {
    config: Config,
    stats: Stats = .{},
    jobs: []Job,
    /// Slot indexes, for sorting a listing.
    order: []u32,
    proof_memory: []u8,
    roots_memory: []Hash,
    sequence_next: u64 = 1,
    lock_sequence: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Store {
        assert(config.jobs_max > 0);
        assert(config.default_lock_duration_seconds <= config.max_lock_duration_seconds);
        assert(config.reclaim_attempts > 0);
        const jobs = try allocator.alloc(Job, config.jobs_max);
        errdefer allocator.free(jobs);
        const order = try allocator.alloc(u32, config.jobs_max);
        errdefer allocator.free(order);
        const proof_bytes = @as(usize, config.jobs_max) * config.proof_bytes_max;
        const proof_memory = try allocator.alloc(u8, proof_bytes);
        errdefer allocator.free(proof_memory);
        const roots_count = @as(usize, config.jobs_max) * config.roots_max;
        const roots_memory = try allocator.alloc(Hash, roots_count);
        const proof_size = config.proof_bytes_max;
        for (jobs, 0..) |*job, index| {
            job.* = .{
                .proof_memory = proof_memory[index * proof_size ..][0..proof_size],
                .roots_memory = roots_memory[index * config.roots_max ..][0..config.roots_max],
            };
        }
        return .{
            .config = config,
            .jobs = jobs,
            .order = order,
            .proof_memory = proof_memory,
            .roots_memory = roots_memory,
        };
    }

    pub fn deinit(store: *Store, allocator: std.mem.Allocator) void {
        allocator.free(store.roots_memory);
        allocator.free(store.proof_memory);
        allocator.free(store.order);
        allocator.free(store.jobs);
        store.* = undefined;
    }

    /// Jobs in use.
    pub fn count(store: *const Store) u32 {
        var used: u32 = 0;
        for (store.jobs) |*job| used += @intFromBool(job.state != .free);
        assert(used <= store.config.jobs_max);
        return used;
    }

    pub fn get(store: *const Store, session_id: []const u8) ?*const Job {
        return store.find(session_id);
    }

    fn find(store: *const Store, session_id: []const u8) ?*Job {
        assert(session_id.len > 0);
        for (store.jobs) |*job| {
            if (job.state != .free and std.mem.eql(u8, job.session_id(), session_id)) return job;
        }
        return null;
    }

    /// base/base `create_for_worker_queue`. `request.session_id` must be canonical.
    pub fn create(
        store: *Store,
        request: *const ProofRequest,
        retry_failed: bool,
        now_ns: u64,
    ) CreateError!CreateOutcome {
        assert(request.session_id.len > 0);
        try validate_request(request);
        const job = store.find(request.session_id.slice()) orelse {
            const slot = store.free_slot() orelse return error.Full;
            slot.* = .{ .proof_memory = slot.proof_memory, .roots_memory = slot.roots_memory };
            slot.state = .pending;
            slot.sequence = store.sequence_next;
            store.sequence_next += 1;
            slot.request = request.*;
            slot.created_ns = now_ns;
            slot.updated_ns = now_ns;
            store.stats.created += 1;
            return .created;
        };
        if (job.state != .failed and job.state != .cancelled) {
            if (!std.meta.eql(job.request.request, request.request)) return error.IdCollision;
            return .replayed;
        }
        // A failed request may come back with a newer L1 head.
        var normalized = request.request;
        replace_l1_head(&normalized, &job.request.request);
        if (!std.meta.eql(job.request.request, normalized)) return error.IdCollision;
        if (job.state == .cancelled) return .cancelled;
        if (!retry_failed) return .retry_not_allowed;
        if (job.retry_count >= store.config.max_proof_retries) return .retry_exhausted;
        job.retry_count += 1;
        job.state = .pending;
        job.request = request.*;
        job.attempt = 0;
        job.clear_lease();
        job.error_message = .{};
        job.result = null;
        job.completed_ns = 0;
        job.updated_ns = now_ns;
        job.sessions = .{ null, null };
        store.stats.retried += 1;
        assert(job.state == .pending);
        return .requeued;
    }

    fn free_slot(store: *Store) ?*Job {
        for (store.jobs) |*job| if (job.state == .free) return job;
        return null;
    }

    /// base/base `resolve_lock_duration`: 0 means the default, capped at the maximum.
    pub fn lock_duration_seconds(store: *const Store, requested: u32) u32 {
        const default = store.config.default_lock_duration_seconds;
        const duration = if (requested == 0) default else requested;
        const resolved = @min(duration, store.config.max_lock_duration_seconds);
        assert(resolved > 0 or store.config.max_lock_duration_seconds == 0);
        return resolved;
    }

    /// base/base `claim_next_proof_job`: the lowest-start eligible job matching `filter`,
    /// pending or with an expired lease and attempts left, under a fresh lock.
    pub fn claim(
        store: *Store,
        filter: *const Filter,
        worker_id: []const u8,
        requested_lock_seconds: u32,
        now_ns: u64,
    ) ?*const Job {
        assert(worker_id.len > 0 and worker_id.len <= protocol.worker_id_bytes_max);
        var best: ?*Job = null;
        for (store.jobs) |*job| {
            const eligible = switch (job.state) {
                .pending => true,
                .claimed => job.expired(now_ns) and job.attempt < store.config.reclaim_attempts,
                else => false,
            };
            if (!eligible or !matches(filter, &job.request.request)) continue;
            if (best) |current| {
                const start = job.start_block();
                const current_start = current.start_block();
                const earlier = start < current_start or
                    (start == current_start and job.sequence < current.sequence);
                if (!earlier) continue;
            }
            best = job;
        }
        const job = best orelse return null;
        const seconds = store.lock_duration_seconds(requested_lock_seconds);
        job.state = .claimed;
        job.attempt += 1;
        job.lock_id = store.next_lock_id();
        job.worker_id = WorkerId.from(worker_id);
        job.lock_expires_ns = now_ns + @as(u64, seconds) * std.time.ns_per_s;
        job.updated_ns = now_ns;
        assert(!job.expired(now_ns) or seconds == 0);
        return job;
    }

    /// A UUIDv4-shaped lock id, deterministic in the seed and the claim count.
    fn next_lock_id(store: *Store) LockId {
        store.lock_sequence += 1;
        var uuid: [16]u8 = undefined;
        for (0..2) |half| {
            var hasher = std.hash.Wyhash.init(store.config.seed);
            hasher.update(std.mem.asBytes(&store.lock_sequence));
            hasher.update(std.mem.asBytes(&half));
            std.mem.writeInt(u64, uuid[half * 8 ..][0..8], hasher.final(), .little);
        }
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        const text = protocol.format_uuid(uuid);
        return LockId.from(text.slice());
    }

    /// base/base `ClaimAuth::classify` of `lease` against the job at `now_ns`.
    pub fn authorize(store: *const Store, lease: *const Lease, now_ns: u64) Answer {
        const job = store.find(lease.session_id) orelse return .{ .auth = .not_found, .job = null };
        const auth: Auth = switch (job.state) {
            .free => unreachable,
            .cancelled => .cancelled,
            .succeeded, .failed => .terminal,
            .pending => .not_claimed,
            .claimed => if (!job.lock_id.eql(lease.lock_id) or !job.worker_id.eql(lease.worker_id))
                .stale_lock
            else if (job.expired(now_ns))
                .expired
            else
                .authorized,
        };
        return .{ .auth = auth, .job = job };
    }

    /// base/base `heartbeat_proof_job`: extends the lease of its holder.
    pub fn heartbeat(
        store: *Store,
        lease: *const Lease,
        requested_lock_seconds: u32,
        now_ns: u64,
    ) Answer {
        const answer = store.authorize(lease, now_ns);
        if (answer.auth != .authorized) return answer;
        const job = store.find(lease.session_id).?;
        const seconds = store.lock_duration_seconds(requested_lock_seconds);
        job.lock_expires_ns = now_ns + @as(u64, seconds) * std.time.ns_per_s;
        job.updated_ns = now_ns;
        assert(job.state == .claimed);
        return answer;
    }

    /// base/base `abandon_proof_job`: requeues while attempts remain, else fails the job.
    pub fn abandon(
        store: *Store,
        lease: *const Lease,
        message: []const u8,
        now_ns: u64,
    ) struct { Answer, ?AbandonOutcome } {
        const answer = store.authorize(lease, now_ns);
        if (answer.auth != .authorized) return .{ answer, null };
        const job = store.find(lease.session_id).?;
        job.error_message = protocol.ErrorMessage.init(message) catch
            protocol.ErrorMessage.from(message[0..protocol.error_message_bytes_max]);
        job.clear_lease();
        job.updated_ns = now_ns;
        store.stats.abandoned += 1;
        if (job.attempt >= store.config.reclaim_attempts) {
            fail_sessions(job);
            job.state = .failed;
            job.completed_ns = now_ns;
            store.stats.failed += 1;
            return .{ answer, .failed };
        }
        job.state = .pending;
        return .{ answer, .requeued };
    }

    /// base/base `complete_claimed_proof_job`.
    pub fn submit(
        store: *Store,
        lease: *const Lease,
        result: *const ProofResult,
        now_ns: u64,
    ) struct { Answer, ?SubmitOutcome } {
        if (store.find(lease.session_id)) |job| {
            if (job.state == .succeeded) {
                const same = results_equal(&job.result.?, result);
                const answer: Answer = .{ .auth = .authorized, .job = job };
                return .{ answer, if (same) .already_completed else .result_conflict };
            }
        }
        const answer = store.authorize(lease, now_ns);
        if (answer.auth != .authorized) return .{ answer, null };
        const job = store.find(lease.session_id).?;
        if (!result_fits(&job.request, result)) return .{ answer, .result_mismatch };
        job.result = copy_result(job, result) orelse return .{ answer, .result_mismatch };
        job.state = .succeeded;
        job.completed_ns = now_ns;
        job.updated_ns = now_ns;
        store.stats.succeeded += 1;
        for (&job.sessions) |*maybe| if (maybe.*) |*session| {
            const active = session.state == .submitting or session.state == .running;
            if (active) session.state = .completed;
        };
        return .{ answer, .completed };
    }

    /// base/base `cancel_proof_request_by_session_id`: only cluster and network ZK
    /// requests can be cancelled; the lease holder learns it on its next heartbeat.
    pub fn cancel(store: *Store, session_id: []const u8, now_ns: u64) CancelOutcome {
        const job = store.find(session_id) orelse return .not_found;
        const backend: ?protocol.ZkBackend = switch (job.request.request) {
            .compressed => |zk| zk.zk_backend,
            .snark_plonk => |snark| snark.proof.zk_backend,
            .tee => null,
        };
        if (backend != .cluster and backend != .network) return .unsupported_backend;
        if (job.state == .cancelled) return .already_cancelled;
        if (job.terminal()) return .already_terminal;
        fail_sessions(job);
        job.state = .cancelled;
        job.error_message = protocol.ErrorMessage.from(protocol.proof_request_cancelled_message);
        job.completed_ns = now_ns;
        job.updated_ns = now_ns;
        job.clear_lease();
        store.stats.cancelled += 1;
        assert(job.terminal());
        return .cancelled;
    }

    /// base/base `delete_proof_request_by_session_id`: frees a terminal job's slot.
    pub fn delete(store: *Store, session_id: []const u8) DeleteOutcome {
        const job = store.find(session_id) orelse return .not_found;
        if (!job.terminal()) return .not_completed;
        job.state = .free;
        job.result = null;
        assert(store.find(session_id) == null);
        return .deleted;
    }

    /// The status poller's reaper: an expired lease is requeued while attempts remain,
    /// otherwise the job fails. Returns the jobs changed.
    pub fn expire(store: *Store, now_ns: u64) u32 {
        var changed: u32 = 0;
        for (store.jobs) |*job| {
            if (job.state != .claimed or !job.expired(now_ns)) continue;
            changed += 1;
            store.stats.expired += 1;
            job.clear_lease();
            job.updated_ns = now_ns;
            if (job.attempt < store.config.reclaim_attempts) {
                job.state = .pending;
                continue;
            }
            fail_sessions(job);
            job.state = .failed;
            job.completed_ns = now_ns;
            store.stats.failed += 1;
            job.error_message = .{};
            const text = std.fmt.bufPrint(
                &job.error_message.buffer,
                "Worker claim expired after exhausting {d} attempts",
                .{store.config.reclaim_attempts},
            ) catch unreachable; // The message is far below the buffer size.
            job.error_message.len = @intCast(text.len);
        }
        assert(changed <= store.jobs.len);
        return changed;
    }

    /// base/base `record_worker_proof_session` (insert or update by session type).
    pub fn record_session(
        store: *Store,
        lease: *const Lease,
        session_type: protocol.SessionType,
        session: protocol.BackendSession,
        now_ns: u64,
    ) struct { Answer, ?protocol.BackendSession } {
        const answer = store.authorize(lease, now_ns);
        if (answer.auth != .authorized) return .{ answer, null };
        const job = store.find(lease.session_id).?;
        const slot = &job.sessions[@backingInt(session_type)];
        if (slot.*) |existing| {
            const done = existing.state == .completed or existing.state == .failed;
            if (done) return .{ answer, existing };
        }
        if (session.state == .completed or session.state == .failed) return .{ answer, null };
        slot.* = session;
        job.updated_ns = now_ns;
        return .{ answer, session };
    }

    /// base/base `get_active_session`: a session still submitting or running.
    pub fn active_session(
        store: *const Store,
        session_id: []const u8,
        session_type: protocol.SessionType,
    ) ?protocol.BackendSession {
        const job = store.find(session_id) orelse return null;
        const session = job.sessions[@backingInt(session_type)] orelse return null;
        if (session.state != .submitting and session.state != .running) return null;
        return session;
    }

    /// base/base `list_with_offset`: newest first. Fills `out` with at most `out.len` jobs
    /// after skipping `offset`; returns the total matching count.
    pub fn list(
        store: *Store,
        offset: u64,
        status_filter: ?protocol.ProofStatus,
        out: []*const Job,
    ) struct { total: u64, page: []*const Job } {
        var total: u32 = 0;
        for (store.jobs, 0..) |*job, index| {
            if (job.state == .free) continue;
            if (status_filter) |status| if (job.proof_status() != status) continue;
            store.order[total] = @intCast(index);
            total += 1;
        }
        const matching = store.order[0..total];
        std.mem.sort(u32, matching, store, newer_first);
        const start = @min(offset, total);
        const size = @min(out.len, total - start);
        for (out[0..size], matching[start..][0..size]) |*slot, index| slot.* = &store.jobs[index];
        return .{ .total = total, .page = out[0..size] };
    }

    fn newer_first(store: *Store, a: u32, b: u32) bool {
        return store.jobs[a].sequence > store.jobs[b].sequence;
    }
};

fn validate_request(request: *const ProofRequest) CreateError!void {
    switch (request.request) {
        .compressed => |zk| _ = zk.validate_range() catch return error.InvalidRange,
        .snark_plonk => |snark| _ = snark.proof.validate_range() catch return error.InvalidRange,
        .tee => |tee| {
            if (tee.proof.intermediate_block_interval == 0) return error.InvalidRange;
            if (tee.proof.claimed_l2_block_number == 0) return error.InvalidRange;
        },
    }
}

/// Copies the L1 head of `from` into `kind` (same variant), for failed-request retries.
fn replace_l1_head(kind: *protocol.ProofRequestKind, from: *const protocol.ProofRequestKind) void {
    switch (kind.*) {
        .compressed => |*zk| if (from.* == .compressed) {
            zk.l1_head = from.compressed.l1_head;
        },
        .snark_plonk => |*snark| if (from.* == .snark_plonk) {
            snark.proof.l1_head = from.snark_plonk.proof.l1_head;
        },
        .tee => |*tee| if (from.* == .tee) {
            tee.proof.l1_head = from.tee.proof.l1_head;
            tee.proof.l1_head_number = from.tee.proof.l1_head_number;
        },
    }
}

fn contains(comptime T: type, items: []const T, item: T) bool {
    for (items) |candidate| if (candidate == item) return true;
    return false;
}

fn matches(filter: *const Filter, kind: *const protocol.ProofRequestKind) bool {
    if (filter.proof_type != std.meta.activeTag(kind.*)) return false;
    const zk: protocol.ZkProofRequest = switch (kind.*) {
        .tee => |tee| return contains(protocol.TeeKind, filter.tee_kinds, tee.tee_kind),
        .compressed => |zk| zk,
        .snark_plonk => |snark| snark.proof,
    };
    if (!contains(protocol.ZkVm, filter.zk_vms, zk.zk_vm)) return false;
    // base/base: no backend filter means cluster only.
    if (filter.zk_backends.len == 0) return zk.zk_backend == .cluster;
    return contains(protocol.ZkBackend, filter.zk_backends, zk.zk_backend);
}

/// Whether `result` answers `request`: same proof type and VM or TEE kind, and a TEE
/// proposal for the claimed root and block.
pub fn result_fits(request: *const ProofRequest, result: *const ProofResult) bool {
    if (std.meta.activeTag(request.request) != std.meta.activeTag(result.*)) return false;
    return switch (request.request) {
        .compressed => |zk| zk.zk_vm == result.compressed.zk_vm,
        .snark_plonk => |snark| snark.proof.zk_vm == result.snark_plonk.proof.zk_vm,
        .tee => |tee| tee.tee_kind == result.tee.tee_kind and std.mem.eql(
            u8,
            &tee.proof.claimed_l2_output_root,
            &result.tee.aggregate_proposal.output_root,
        ) and tee.proof.claimed_l2_block_number == result.tee.aggregate_proposal.l2_block_number,
    };
}

pub fn results_equal(a: *const ProofResult, b: *const ProofResult) bool {
    if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
    return switch (a.*) {
        .compressed => |zk| zk.zk_vm == b.compressed.zk_vm and
            std.mem.eql(u8, zk.proof, b.compressed.proof),
        .snark_plonk => |snark| snark.proof.zk_vm == b.snark_plonk.proof.zk_vm and
            std.mem.eql(u8, snark.proof.proof, b.snark_plonk.proof.proof),
        .tee => |tee| tee_equal(&tee, &b.tee),
    };
}

fn tee_equal(a: *const protocol.TeeProofResult, b: *const protocol.TeeProofResult) bool {
    var proposal_a = a.aggregate_proposal;
    var proposal_b = b.aggregate_proposal;
    if (!std.mem.eql(u8, proposal_a.signature, proposal_b.signature)) return false;
    proposal_a.signature = "";
    proposal_b.signature = "";
    return std.meta.eql(proposal_a, proposal_b) and a.tee_kind == b.tee_kind and
        std.mem.eql(u8, &a.tee_signer, &b.tee_signer) and
        std.mem.eql(
            u8,
            std.mem.sliceAsBytes(a.intermediate_roots),
            std.mem.sliceAsBytes(b.intermediate_roots),
        );
}

/// `result` with its slices copied into the job's memory; null when they do not fit.
fn copy_result(job: *Job, result: *const ProofResult) ?ProofResult {
    switch (result.*) {
        .compressed => |zk| {
            if (zk.proof.len > job.proof_memory.len) return null;
            @memcpy(job.proof_memory[0..zk.proof.len], zk.proof);
            const proof = job.proof_memory[0..zk.proof.len];
            return .{ .compressed = .{ .zk_vm = zk.zk_vm, .proof = proof } };
        },
        .snark_plonk => |snark| {
            const proof = snark.proof.proof;
            if (proof.len > job.proof_memory.len) return null;
            @memcpy(job.proof_memory[0..proof.len], proof);
            return .{ .snark_plonk = .{ .proof = .{
                .zk_vm = snark.proof.zk_vm,
                .proof = job.proof_memory[0..proof.len],
            } } };
        },
        .tee => |tee| {
            const roots = tee.intermediate_roots;
            const signature = tee.aggregate_proposal.signature;
            if (roots.len > job.roots_memory.len) return null;
            if (signature.len > job.signature_memory.len) return null;
            @memcpy(job.roots_memory[0..roots.len], roots);
            @memcpy(job.signature_memory[0..signature.len], signature);
            var copy = tee;
            copy.intermediate_roots = job.roots_memory[0..roots.len];
            copy.aggregate_proposal.signature = job.signature_memory[0..signature.len];
            return .{ .tee = copy };
        },
    }
}

fn fail_sessions(job: *Job) void {
    for (&job.sessions) |*maybe| if (maybe.*) |*session| {
        if (session.state == .submitting or session.state == .running) session.state = .failed;
    };
}

fn timestamp(ns: u64) protocol.Timestamp {
    return protocol.Timestamp.from_ns(ns);
}

/// The worker-facing view of a job.
pub fn to_proof_job(job: *const Job) protocol.ProofJob {
    assert(job.state != .free);
    const claimed = job.state == .claimed;
    return .{
        .session_id = job.request.session_id,
        .status = job.job_status(),
        .request = job.request,
        .attempt = job.attempt,
        .lock_id = if (claimed) job.lock_id else null,
        .worker_id = if (claimed) job.worker_id else null,
        .lock_expires_at = if (claimed) timestamp(job.lock_expires_ns) else null,
        .created_at = timestamp(job.created_ns),
        .updated_at = timestamp(job.updated_ns),
        .completed_at = if (job.terminal()) timestamp(job.completed_ns) else null,
        .error_message = if (job.error_message.len > 0) job.error_message else null,
    };
}

/// The requester-facing summary of a job (`listProofs`).
pub fn to_summary(job: *const Job) protocol.ProofSummary {
    assert(job.state != .free);
    const kind = job.request.request;
    return .{
        .session_id = job.request.session_id,
        .proof_type = std.meta.activeTag(kind),
        .status = job.proof_status(),
        .created_at = timestamp(job.created_ns),
        .updated_at = timestamp(job.updated_ns),
        .completed_at = if (job.terminal()) timestamp(job.completed_ns) else null,
        .error_message = if (job.terminal() and job.error_message.len > 0)
            job.error_message
        else
            null,
        .tee_kind = if (kind == .tee) kind.tee.tee_kind else null,
        .zk_vm = switch (kind) {
            .compressed => |zk| zk.zk_vm,
            .snark_plonk => |snark| snark.proof.zk_vm,
            .tee => null,
        },
    };
}

/// base/base `get_proof`: status, the failure message, and the stored result.
pub fn to_get_proof(job: *const Job) protocol.GetProofResponse {
    assert(job.state != .free);
    const status = job.proof_status();
    return .{
        .status = status,
        .error_message = if (status == .failed) job.error_message else null,
        .result = if (status == .succeeded) job.result.? else null,
    };
}

test {
    _ = @import("store_test.zig");
}

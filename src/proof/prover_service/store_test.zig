//! Job store tests: the base/base repository outcomes (create/replay/requeue, lease
//! ownership, abandon, submit, cancel, delete, reaper) and a seeded state-machine fuzz that
//! checks the lease invariants against a model of the workers.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const fuzz = @import("../../testing/fuzz.zig");
const protocol = @import("protocol.zig");
const store_module = @import("store.zig");

const Store = store_module.Store;
const s_ns = std.time.ns_per_s;

fn zk_request(session: []const u8, start: u64) protocol.ProofRequest {
    return .{
        .session_id = .from(session),
        .request = .{ .compressed = .{
            .start_block_number = start,
            .number_of_blocks_to_prove = 10,
            .intermediate_block_interval = 5,
            .zk_vm = .sp1,
        } },
    };
}

const zk_filter: store_module.Filter = .{ .proof_type = .compressed, .zk_vms = &.{.sp1} };

fn lease_of(job: *const store_module.Job) store_module.Lease {
    return .{
        .session_id = job.session_id(),
        .lock_id = job.lock_id.slice(),
        .worker_id = job.worker_id.slice(),
    };
}

fn zk_result(proof: []const u8) protocol.ProofResult {
    return .{ .compressed = .{ .zk_vm = .sp1, .proof = proof } };
}

test "prover service store: idempotent create, collision, retry of failed" {
    var store: Store = try .init(testing.allocator, .{ .jobs_max = 2, .proof_bytes_max = 16 });
    defer store.deinit(testing.allocator);
    const request = zk_request("a", 0);
    try testing.expectEqual(.created, try store.create(&request, true, 0));
    try testing.expectEqual(.replayed, try store.create(&request, true, 1));
    try testing.expectEqual(@as(u32, 1), store.count());
    try testing.expectError(error.IdCollision, store.create(&zk_request("a", 10), true, 1));
    var bad = zk_request("b", 0);
    bad.request.compressed.number_of_blocks_to_prove = 7;
    try testing.expectError(error.InvalidRange, store.create(&bad, true, 1));
    try testing.expectEqual(.created, try store.create(&zk_request("b", 5), true, 1));
    try testing.expectError(error.Full, store.create(&zk_request("c", 5), true, 1));
    // Fail "a" by abandoning every attempt.
    var attempt: u32 = 0;
    while (attempt < store.config.reclaim_attempts) : (attempt += 1) {
        const job = store.claim(&zk_filter, "w", 10, 2).?;
        try testing.expectEqualStrings("a", job.session_id());
        const answer, const outcome = store.abandon(&lease_of(job), "boom", 2);
        try testing.expectEqual(.authorized, answer.auth);
        const last = attempt + 1 == store.config.reclaim_attempts;
        const expected: store_module.AbandonOutcome = if (last) .failed else .requeued;
        try testing.expectEqual(expected, outcome.?);
    }
    try testing.expectEqual(protocol.ProofStatus.failed, store.get("a").?.proof_status());
    try testing.expectEqual(.retry_not_allowed, try store.create(&request, false, 3));
    // A newer L1 head is allowed when retrying a failed request.
    var newer = request;
    newer.request.compressed.l1_head = @splat(9);
    try testing.expectEqual(.requeued, try store.create(&newer, true, 3));
    try testing.expectEqual(protocol.ProofStatus.queued, store.get("a").?.proof_status());
    try testing.expectEqual(@as(u32, 0), store.get("a").?.attempt);
}

test "prover service store: lease ownership, expiry and submit" {
    var store: Store = try .init(testing.allocator, .{ .jobs_max = 4, .proof_bytes_max = 16 });
    defer store.deinit(testing.allocator);
    _ = try store.create(&zk_request("late", 20), true, 0);
    _ = try store.create(&zk_request("early", 10), true, 0);
    const tee_filter: store_module.Filter = .{ .proof_type = .tee, .tee_kinds = &.{.aws_nitro} };
    try testing.expect(store.claim(&tee_filter, "w", 1, 0) == null);
    const job = store.claim(&zk_filter, "one", 10, 0).?;
    try testing.expectEqualStrings("early", job.session_id());
    // Copies: the job's own fields change when it is reclaimed.
    const lock = job.lock_id;
    const lease: store_module.Lease = .{
        .session_id = "early",
        .lock_id = lock.slice(),
        .worker_id = "one",
    };
    var stale = lease;
    stale.worker_id = "two";
    try testing.expectEqual(.stale_lock, store.heartbeat(&stale, 10, 1).auth);
    try testing.expectEqual(.authorized, store.heartbeat(&lease, 10, 5 * s_ns).auth);
    // The heartbeat moved the deadline to 15 s; at 16 s the lease has expired.
    try testing.expectEqual(.expired, store.heartbeat(&lease, 10, 16 * s_ns).auth);
    const reclaimed = store.claim(&zk_filter, "two", 10, 16 * s_ns).?;
    try testing.expectEqualStrings("early", reclaimed.session_id());
    try testing.expectEqual(@as(u32, 2), reclaimed.attempt);
    try testing.expect(!std.mem.eql(u8, lease.lock_id, reclaimed.lock_id.slice()));
    try testing.expectEqual(.stale_lock, store.heartbeat(&lease, 10, 16 * s_ns).auth);
    const result = zk_result("proof");
    const old_answer, _ = store.submit(&lease, &result, 17 * s_ns);
    try testing.expectEqual(.stale_lock, old_answer.auth);
    const new_lease = lease_of(reclaimed);
    const wrong: protocol.ProofResult = .{ .tee = undefined };
    _, const mismatch = store.submit(&new_lease, &wrong, 17 * s_ns);
    try testing.expectEqual(.result_mismatch, mismatch.?);
    _, const done = store.submit(&new_lease, &result, 17 * s_ns);
    try testing.expectEqual(.completed, done.?);
    _, const replay = store.submit(&new_lease, &result, 18 * s_ns);
    try testing.expectEqual(.already_completed, replay.?);
    const other = zk_result("other");
    _, const conflict = store.submit(&new_lease, &other, 18 * s_ns);
    try testing.expectEqual(.result_conflict, conflict.?);
    const response = store_module.to_get_proof(store.get("early").?);
    try testing.expectEqualStrings("proof", response.result.?.compressed.proof);
    try testing.expectEqual(.terminal, store.heartbeat(&new_lease, 10, 18 * s_ns).auth);
    try testing.expectEqual(store_module.Stats{ .created = 2, .succeeded = 1 }, store.stats);
}

test "prover service store: cancel, delete, reaper and listing" {
    var store: Store = try .init(testing.allocator, .{
        .jobs_max = 4,
        .proof_bytes_max = 16,
        .reclaim_attempts = 1,
    });
    defer store.deinit(testing.allocator);
    _ = try store.create(&zk_request("a", 0), true, 0);
    _ = try store.create(&zk_request("b", 10), true, 1);
    var tee = zk_request("t", 0);
    tee.request = .{ .tee = .{ .proof = .{
        .l1_head = @splat(1),
        .agreed_l2_head_hash = @splat(2),
        .agreed_l2_output_root = @splat(3),
        .claimed_l2_output_root = @splat(4),
        .claimed_l2_block_number = 5,
        .intermediate_block_interval = 5,
    }, .tee_kind = .aws_nitro } };
    _ = try store.create(&tee, true, 2);
    try testing.expectEqual(.unsupported_backend, store.cancel("t", 3));
    try testing.expectEqual(.not_found, store.cancel("x", 3));
    const job = store.claim(&zk_filter, "w", 10, 3).?;
    const lease = lease_of(job);
    try testing.expectEqual(.not_completed, store.delete("a"));
    try testing.expectEqual(.cancelled, store.cancel("a", 4));
    try testing.expectEqual(.already_cancelled, store.cancel("a", 4));
    try testing.expectEqual(.cancelled, store.heartbeat(&lease, 10, 5).auth);
    try testing.expectEqual(.cancelled, try store.create(&zk_request("a", 0), true, 5));
    try testing.expectEqual(.deleted, store.delete("a"));
    try testing.expectEqual(.not_found, store.delete("a"));
    // With one reclaim attempt an expired lease fails the job.
    const second = store.claim(&zk_filter, "w", 10, 6).?;
    try testing.expectEqualStrings("b", second.session_id());
    try testing.expectEqual(@as(u32, 0), store.expire(10 * s_ns));
    try testing.expectEqual(@as(u32, 1), store.expire(17 * s_ns));
    const failed = store.get("b").?;
    try testing.expectEqual(protocol.ProofStatus.failed, failed.proof_status());
    const message = failed.error_message.slice();
    try testing.expect(std.mem.startsWith(u8, message, "Worker claim expired"));
    var out: [4]*const store_module.Job = undefined;
    const all = store.list(0, null, &out);
    try testing.expectEqual(@as(u64, 2), all.total);
    try testing.expectEqualStrings("t", all.page[0].session_id());
    const failed_only = store.list(0, .failed, &out);
    try testing.expectEqual(@as(u64, 1), failed_only.total);
    try testing.expectEqual(@as(usize, 0), store.list(5, null, &out).page.len);
    const stats: store_module.Stats = .{ .created = 3, .cancelled = 1, .expired = 1, .failed = 1 };
    try testing.expectEqual(stats, store.stats);
}

test "prover service store: backend sessions" {
    var store: Store = try .init(testing.allocator, .{ .jobs_max = 1, .proof_bytes_max = 16 });
    defer store.deinit(testing.allocator);
    _ = try store.create(&zk_request("a", 0), true, 0);
    const lease = lease_of(store.claim(&zk_filter, "w", 10, 0).?);
    const running: protocol.BackendSession = .{
        .backend_session_id = .from("b-1"),
        .state = .running,
    };
    _, const recorded = store.record_session(&lease, .stark, running, 1);
    try testing.expectEqualStrings("b-1", recorded.?.backend_session_id.slice());
    try testing.expect(store.active_session("a", .stark) != null);
    try testing.expect(store.active_session("a", .snark) == null);
    var finished = running;
    finished.state = .completed;
    _, const rejected = store.record_session(&lease, .stark, finished, 1);
    try testing.expect(rejected == null);
}

/// The model of one worker: the lease it believes it holds.
const ModelWorker = struct {
    name: []const u8,
    lease: ?struct { session: protocol.SessionId, lock: protocol.LockId } = null,

    fn view(worker: *const ModelWorker) ?store_module.Lease {
        const held = &(worker.lease orelse return null);
        return .{
            .session_id = held.session.slice(),
            .lock_id = held.lock.slice(),
            .worker_id = worker.name,
        };
    }
};

const sessions = [_][]const u8{ "s0", "s1", "s2", "s3", "s4" };

fn fuzz_store(_: void, smith: *std.testing.Smith) anyerror!void {
    var store: Store = try .init(testing.allocator, .{
        .jobs_max = 4,
        .proof_bytes_max = 8,
        .reclaim_attempts = 3,
        .max_proof_retries = 2,
        .seed = smith.value(u64),
    });
    defer store.deinit(testing.allocator);
    var workers = [_]ModelWorker{ .{ .name = "w0" }, .{ .name = "w1" }, .{ .name = "w2" } };
    var now_ns: u64 = 0;
    var steps: u32 = 0;
    while (steps < 128 and !smith.eos()) : (steps += 1) {
        const worker = &workers[smith.index(workers.len)];
        const session = sessions[smith.index(sessions.len)];
        switch (smith.valueRangeAtMost(u8, 0, 8)) {
            0 => try fuzz_create(&store, session, smith, now_ns),
            1 => fuzz_claim(&store, worker, now_ns),
            2 => if (worker.view()) |lease| {
                const seconds = smith.valueRangeAtMost(u32, 1, 20);
                const answer = store.heartbeat(&lease, seconds, now_ns);
                if (answer.auth != .authorized) worker.lease = null;
            },
            3 => if (worker.view()) |lease| {
                _ = store.abandon(&lease, "boom", now_ns);
                worker.lease = null;
            },
            4 => if (worker.view()) |lease| {
                const result = zk_result("p");
                const answer, const outcome = store.submit(&lease, &result, now_ns);
                if (outcome == .completed) assert(answer.auth == .authorized);
                if (outcome != null) worker.lease = null;
            },
            5 => _ = store.cancel(session, now_ns),
            6 => _ = store.delete(session),
            7 => _ = store.expire(now_ns),
            8 => now_ns += smith.valueRangeAtMost(u64, 0, 30) * s_ns,
            else => unreachable,
        }
        try check_invariants(&store, &workers, now_ns);
    }
}

fn fuzz_create(store: *Store, session: []const u8, smith: *std.testing.Smith, now_ns: u64) !void {
    const before = store.count();
    const exists = store.get(session) != null;
    const start: u64 = if (smith.value(bool)) 0 else 10;
    const retry_failed = smith.value(bool);
    const outcome = store.create(&zk_request(session, start), retry_failed, now_ns) catch |err| {
        try testing.expect(err == error.IdCollision or err == error.Full);
        try testing.expectEqual(before, store.count());
        return;
    };
    // An idempotent request never adds a job for a known session.
    try testing.expectEqual(before + @intFromBool(!exists), store.count());
    try testing.expectEqual(outcome == .created, !exists);
}

fn fuzz_claim(store: *Store, worker: *ModelWorker, now_ns: u64) void {
    if (worker.lease != null) return;
    // Every job matches the filter: a claim succeeds exactly when some job is pending or
    // has an expired lease with attempts left.
    var eligible = false;
    for (store.jobs) |*job| {
        if (job.state == .pending) eligible = true;
        if (job.state == .claimed and job.expired(now_ns) and
            job.attempt < store.config.reclaim_attempts) eligible = true;
    }
    const claimed = store.claim(&zk_filter, worker.name, 10, now_ns);
    assert(eligible == (claimed != null));
    const job = claimed orelse return;
    assert(job.state == .claimed);
    assert(job.worker_id.eql(worker.name));
    worker.lease = .{ .session = job.request.session_id, .lock = job.lock_id };
}

fn check_invariants(store: *Store, workers: []ModelWorker, now_ns: u64) !void {
    for (store.jobs, 0..) |*job, index| {
        if (job.state == .free) continue;
        // One job per session.
        for (store.jobs[index + 1 ..]) |*other| {
            if (other.state == .free) continue;
            try testing.expect(!std.mem.eql(u8, job.session_id(), other.session_id()));
        }
        try testing.expect(job.attempt <= store.config.reclaim_attempts);
        try testing.expect(job.retry_count <= store.config.max_proof_retries);
        if (job.state != .claimed) continue;
        try testing.expect(job.lock_id.len > 0 and job.worker_id.len > 0);
        // A live lease is authorized for exactly one worker.
        var holders: u32 = 0;
        for (workers) |*worker| {
            const lease = worker.view() orelse continue;
            if (store.authorize(&lease, now_ns).auth == .authorized) holders += 1;
        }
        try testing.expect(holders <= 1);
        if (!job.expired(now_ns)) try testing.expectEqual(@as(u32, 1), holders);
    }
}

test "prover service store: fuzz state machine" {
    try fuzz.run({}, fuzz_store, .{ .iterations = 512, .input_size_max = 512 });
}

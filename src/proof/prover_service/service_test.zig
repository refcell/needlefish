//! Prover service server tests through the JSON-RPC router: the requester and worker flows,
//! base/base error codes, and idempotent re-requests.

const std = @import("std");
const testing = std.testing;

const json = @import("../../utilities/json/root.zig");
const protocol = @import("protocol.zig");
const codec = @import("codec.zig");
const store_module = @import("store.zig");
const service_module = @import("service.zig");

const Service = service_module.Service;

const TestClock = struct {
    now_ns: u64 = 1_793_880_000 * std.time.ns_per_s,

    fn read(context: *anyopaque) u64 {
        const test_clock: *TestClock = @ptrCast(@alignCast(context));
        return test_clock.now_ns;
    }

    fn clock(test_clock: *TestClock) service_module.Clock {
        return .{ .context = test_clock, .now_ns = read };
    }
};

const Fixture = struct {
    clock: TestClock = .{},
    store: store_module.Store,
    service: Service,
    out: [16 * 1024]u8 = undefined,
    body: [8 * 1024]u8 = undefined,

    fn init(fixture: *Fixture) !void {
        fixture.* = .{ .store = undefined, .service = undefined };
        fixture.store = try .init(testing.allocator, .{ .jobs_max = 4, .proof_bytes_max = 64 });
        errdefer fixture.store.deinit(testing.allocator);
        fixture.service = try .init(testing.allocator, &fixture.store, fixture.clock.clock(), .{
            .request_arena_bytes = 64 * 1024,
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.service.deinit(testing.allocator);
        fixture.store.deinit(testing.allocator);
    }

    /// Calls `method` with `param` (already JSON); returns the response body.
    fn call(fixture: *Fixture, method: []const u8, param: []const u8) ![]const u8 {
        const body = try std.fmt.bufPrint(
            &fixture.body,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":[{s}]}}",
            .{ method, param },
        );
        var out: std.Io.Writer = .fixed(&fixture.out);
        _ = Service.Router.handle(&fixture.service, body, &out);
        return out.buffered();
    }

    fn call_value(fixture: *Fixture, method: []const u8, comptime T: type, value: *const T) ![]const u8 {
        var buffer: [4096]u8 = undefined;
        return fixture.call(method, try codec.encode_to(T, &buffer, value));
    }

    fn result_of(fixture: *Fixture, comptime T: type, response: []const u8) !T {
        _ = fixture;
        const raw = (try json.find_path(response, &.{"result"})) orelse {
            std.debug.print("unexpected response: {s}\n", .{response});
            return error.TestUnexpectedResult;
        };
        const static = struct {
            var memory: [32 * 1024]u8 = undefined;
        };
        var arena: std.heap.FixedBufferAllocator = .init(&static.memory);
        return codec.decode(T, arena.allocator(), raw);
    }
};

fn error_code(response: []const u8) !i64 {
    const raw = (try json.find_path(response, &.{ "error", "code" })) orelse return error.NoError;
    return std.fmt.parseInt(i64, raw, 10);
}

const session = "9DCD3BF1-DA72-502D-A430-77A6F3474685";
const canonical = "9dcd3bf1-da72-502d-a430-77a6f3474685";

fn prove_request(start: u64) protocol.ProveBlockRangeRequest {
    return .{ .proof = .{
        .session_id = .from(session),
        .request = .{ .compressed = .{
            .start_block_number = start,
            .number_of_blocks_to_prove = 4,
            .intermediate_block_interval = 2,
            .zk_vm = .sp1,
        } },
    } };
}

const next_request: protocol.GetNextProofRequest = .{
    .worker_id = .from("worker-1"),
    .proof_type = .compressed,
    .zk_vms = &.{.sp1},
    .lock_duration_seconds = 60,
};

test "prover service server: request, claim, heartbeat, submit, get" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const method = protocol.method;
    const prove = prove_request(100);
    const created = try fixture.call_value(method.prove_block_range, protocol.ProveBlockRangeRequest, &prove);
    const response = try fixture.result_of(protocol.ProveBlockRangeResponse, created);
    try testing.expectEqualStrings(canonical, response.session_id.slice());
    // The same request again replays; a different one under the session collides.
    _ = try fixture.result_of(protocol.ProveBlockRangeResponse, try fixture.call_value(
        method.prove_block_range,
        protocol.ProveBlockRangeRequest,
        &prove,
    ));
    try testing.expectEqual(@as(u32, 1), fixture.store.count());
    const other = prove_request(104);
    const collision = try fixture.call_value(method.prove_block_range, protocol.ProveBlockRangeRequest, &other);
    try testing.expectEqual(@as(i64, protocol.code.failed_precondition), try error_code(collision));
    const queued = try fixture.call(method.get_proof, "{\"session_id\":\"" ++ session ++ "\"}");
    try testing.expectEqual(.queued, (try fixture.result_of(protocol.GetProofResponse, queued)).status);

    const next = try fixture.call_value(method.get_next_proof, protocol.GetNextProofRequest, &next_request);
    const job = (try fixture.result_of(protocol.GetNextProofResponse, next)).job.?;
    try testing.expectEqual(protocol.ProofJobStatus.claimed, job.status);
    try testing.expectEqual(@as(u32, 1), job.attempt);
    const beat: protocol.HeartbeatRequest = .{
        .session_id = job.session_id,
        .lock_id = job.lock_id.?,
        .worker_id = job.worker_id.?,
        .lock_duration_seconds = 0,
    };
    fixture.clock.now_ns += 30 * std.time.ns_per_s;
    const extended = try fixture.call_value(method.heartbeat, protocol.HeartbeatRequest, &beat);
    const beat_job = (try fixture.result_of(protocol.HeartbeatResponse, extended)).job;
    // Lock duration 0 is the default 300 s.
    const expected = fixture.clock.now_ns / std.time.ns_per_s + 300;
    try testing.expectEqual(expected, beat_job.lock_expires_at.?.seconds);
    var bad_lock = beat;
    bad_lock.lock_id = .from("not-a-uuid");
    const bad = try fixture.call_value(method.heartbeat, protocol.HeartbeatRequest, &bad_lock);
    try testing.expectEqual(@as(i64, protocol.code.failed_precondition), try error_code(bad));

    const submit: protocol.WorkerSubmitProofRequest = .{
        .session_id = job.session_id,
        .lock_id = job.lock_id.?,
        .worker_id = job.worker_id.?,
        .result = .{ .compressed = .{ .zk_vm = .sp1, .proof = "zk" } },
    };
    const submitted = try fixture.call_value(method.submit_proof, protocol.WorkerSubmitProofRequest, &submit);
    const done = (try fixture.result_of(protocol.WorkerSubmitProofResponse, submitted)).job;
    try testing.expectEqual(protocol.ProofJobStatus.succeeded, done.status);
    const proof = try fixture.call(method.get_proof, "{\"session_id\":\"" ++ canonical ++ "\"}");
    const finished = try fixture.result_of(protocol.GetProofResponse, proof);
    try testing.expectEqual(.succeeded, finished.status);
    try testing.expectEqualStrings("zk", finished.result.?.compressed.proof);
    const listed = try fixture.call(method.list_proofs, "{\"offset\":0,\"limit\":0}");
    const list = try fixture.result_of(protocol.ListProofsResponse, listed);
    try testing.expectEqual(@as(u64, 1), list.total_count);
    try testing.expectEqual(protocol.ProofType.compressed, list.proofs[0].proof_type);
    const deleted = try fixture.call(method.delete_proof_request, "{\"session_id\":\"" ++ session ++ "\"}");
    try testing.expect(std.mem.indexOf(u8, deleted, "\"result\":null") != null);
    const gone = try fixture.call(method.get_proof, "{\"session_id\":\"" ++ session ++ "\"}");
    try testing.expectEqual(@as(i64, protocol.code.not_found), try error_code(gone));
}

test "prover service server: cancel reaches the worker, lease expiry, bad params" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const method = protocol.method;
    const prove = prove_request(0);
    _ = try fixture.call_value(method.prove_block_range, protocol.ProveBlockRangeRequest, &prove);
    const next = try fixture.call_value(method.get_next_proof, protocol.GetNextProofRequest, &next_request);
    const job = (try fixture.result_of(protocol.GetNextProofResponse, next)).job.?;
    // The lease (60 s) expires; another worker reclaims the job.
    fixture.clock.now_ns += 61 * std.time.ns_per_s;
    var second = next_request;
    second.worker_id = .from("worker-2");
    const reclaimed = try fixture.call_value(method.get_next_proof, protocol.GetNextProofRequest, &second);
    const job_two = (try fixture.result_of(protocol.GetNextProofResponse, reclaimed)).job.?;
    try testing.expectEqual(@as(u32, 2), job_two.attempt);
    const stale: protocol.HeartbeatRequest = .{
        .session_id = job.session_id,
        .lock_id = job.lock_id.?,
        .worker_id = job.worker_id.?,
        .lock_duration_seconds = 60,
    };
    const rejected = try fixture.call_value(method.heartbeat, protocol.HeartbeatRequest, &stale);
    try testing.expectEqual(@as(i64, protocol.code.failed_precondition), try error_code(rejected));
    try testing.expect(std.mem.indexOf(u8, rejected, "rotated") != null);
    const cancelled = try fixture.call(method.cancel_proof_request, "{\"session_id\":\"" ++ session ++ "\"}");
    try testing.expect(std.mem.indexOf(u8, cancelled, "\"result\":null") != null);
    var current = stale;
    current.lock_id = job_two.lock_id.?;
    current.worker_id = job_two.worker_id.?;
    const told = try fixture.call_value(method.heartbeat, protocol.HeartbeatRequest, &current);
    try testing.expectEqual(@as(i64, protocol.code.proof_cancelled), try error_code(told));
    const again = try fixture.call_value(method.prove_block_range, protocol.ProveBlockRangeRequest, &prove);
    try testing.expectEqual(@as(i64, protocol.code.failed_precondition), try error_code(again));
    const invalid = try fixture.call(method.get_proof, "{\"session\":\"x\"}");
    try testing.expectEqual(@as(i64, protocol.code.invalid_params), try error_code(invalid));
    const too_many = try fixture.call(method.list_proofs, "{\"offset\":0,\"limit\":1001}");
    try testing.expectEqual(@as(i64, protocol.code.invalid_params), try error_code(too_many));
    const empty = try fixture.call(method.get_next_proof, "{\"worker_id\":\"w\",\"proof_type\":\"tee\"," ++
        "\"tee_kinds\":[\"aws_nitro\"],\"lock_duration_seconds\":5}");
    try testing.expect(std.mem.indexOf(u8, empty, "\"result\":{}") != null);
}

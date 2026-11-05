//! The prover service JSON-RPC server (base/base `prover-service/src/server/*.rs`): the
//! requester methods (`prover_proveBlockRange`, `getProof`, `cancelProofRequest`,
//! `deleteProofRequest`, `listProofs`) and the worker methods (`getNextProof`, `heartbeat`,
//! `abandonProof`, `submitProof`, `getProofSession`, `recordProofSession`) over the job
//! store, served by the shared `utilities/rpc` router on `utilities/http`.
//!
//! Each method takes its request object as the single positional param (or as the named
//! param `request`), like jsonrpsee. Errors keep base/base's codes and messages. Time comes
//! from an injected `Clock`. The status poller's reaper (`Store.expire`) runs at the start
//! of every request instead of on a timer, so expired leases are visible without one.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const http = @import("../../utilities/http/root.zig");
const protocol = @import("protocol.zig");
const codec = @import("codec.zig");
const store_module = @import("store.zig");

const Store = store_module.Store;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const code = protocol.code;

/// Realtime nanoseconds from an injected source (`utilities.io` or a test clock).
pub const Clock = struct {
    context: *anyopaque,
    now_ns: *const fn (context: *anyopaque) u64,

    pub fn of(comptime IO: type, io: *IO) Clock {
        const Adapter = struct {
            fn now_ns(context: *anyopaque) u64 {
                const typed: *IO = @ptrCast(@alignCast(context));
                return typed.now_realtime_ns();
            }
        };
        return .{ .context = io, .now_ns = Adapter.now_ns };
    }

    pub fn read(clock: Clock) u64 {
        return clock.now_ns(clock.context);
    }
};

pub const Options = struct {
    /// Decode arena per request: bounds byte strings and lists in requests.
    request_arena_bytes: u32 = 2 << 20,
};

pub const Service = struct {
    store: *Store,
    clock: Clock,
    arena_memory: []u8,
    arena: std.heap.FixedBufferAllocator,
    message: [512]u8 = undefined,
    page: []*const store_module.Job,
    summaries: []protocol.ProofSummary,

    pub fn init(
        allocator: std.mem.Allocator,
        store: *Store,
        clock: Clock,
        options: Options,
    ) !Service {
        assert(options.request_arena_bytes > 0);
        const arena_memory = try allocator.alloc(u8, options.request_arena_bytes);
        errdefer allocator.free(arena_memory);
        const page = try allocator.alloc(*const store_module.Job, store.config.jobs_max);
        errdefer allocator.free(page);
        const summaries = try allocator.alloc(protocol.ProofSummary, store.config.jobs_max);
        return .{
            .store = store,
            .clock = clock,
            .arena_memory = arena_memory,
            .arena = .init(arena_memory),
            .page = page,
            .summaries = summaries,
        };
    }

    pub fn deinit(service: *Service, allocator: std.mem.Allocator) void {
        allocator.free(service.summaries);
        allocator.free(service.page);
        allocator.free(service.arena_memory);
        service.* = undefined;
    }

    pub const methods = [_]rpc.Method(*Service){
        .{ .name = protocol.method.prove_block_range, .handler = prove_block_range },
        .{ .name = protocol.method.get_proof, .handler = get_proof },
        .{ .name = protocol.method.cancel_proof_request, .handler = cancel_proof_request },
        .{ .name = protocol.method.delete_proof_request, .handler = delete_proof_request },
        .{ .name = protocol.method.list_proofs, .handler = list_proofs },
        .{ .name = protocol.method.get_next_proof, .handler = get_next_proof },
        .{ .name = protocol.method.heartbeat, .handler = heartbeat },
        .{ .name = protocol.method.abandon_proof, .handler = abandon_proof },
        .{ .name = protocol.method.submit_proof, .handler = submit_proof },
        .{ .name = protocol.method.get_proof_session, .handler = get_proof_session },
        .{ .name = protocol.method.record_proof_session, .handler = record_proof_session },
    };
    pub const Router = rpc.Router(*Service, &methods);

    /// The HTTP handler (`http.Server(IO, *Service, Service.handle_http)`).
    pub fn handle_http(
        service: *Service,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        _ = Router.handle(service, request.body, response.writer());
    }

    /// The current time, after reaping expired leases.
    fn begin(service: *Service) u64 {
        const now_ns = service.clock.read();
        _ = service.store.expire(now_ns);
        service.arena.reset();
        return now_ns;
    }

    fn params(service: *Service, comptime T: type, call: *Call) HandlerError!T {
        const raw = if (call.params.named)
            (json.find_path(call.params.scanner.input, &.{"request"}) catch null) orelse
                return error.InvalidParams
        else
            try call.params.raw();
        try call.params.finish();
        assert(raw.len > 0);
        return codec.decode(T, service.arena.allocator(), raw) catch |err|
            service.fail(call, code.invalid_params, "invalid request: {t}", .{err});
    }

    fn reply(service: *Service, comptime T: type, call: *Call, value: *const T) HandlerError!void {
        _ = service;
        codec.encode(T, call.writer, value) catch return error.WriteFailed;
    }

    /// Fails `call` with a formatted message (kept in `service.message`).
    fn fail(
        service: *Service,
        call: *Call,
        error_code: i32,
        comptime format: []const u8,
        arguments: anytype,
    ) HandlerError {
        const text = std.fmt.bufPrint(&service.message, format, arguments) catch
            service.message[0..];
        assert(text.len <= service.message.len);
        return call.fail(error_code, text);
    }

    fn canonical(
        service: *Service,
        call: *Call,
        session_id: *const protocol.SessionId,
    ) HandlerError!protocol.SessionId {
        return protocol.canonical_session_id(session_id) catch
            service.fail(call, code.invalid_params, "session_id must not be empty", .{});
    }

    /// A worker lease from request fields; the lock id must be a UUID (a fencing token).
    fn lease(
        service: *Service,
        call: *Call,
        session_id: *protocol.SessionId,
        lock_id: *protocol.LockId,
        worker_id: *const protocol.WorkerId,
    ) HandlerError!store_module.Lease {
        session_id.* = try service.canonical(call, session_id);
        const uuid = protocol.parse_uuid(lock_id.slice()) orelse return service.fail(
            call,
            code.failed_precondition,
            "lock_id {s} is not a valid fencing token",
            .{lock_id.slice()},
        );
        lock_id.* = protocol.LockId.from(protocol.format_uuid(uuid).slice());
        return .{
            .session_id = session_id.slice(),
            .lock_id = lock_id.slice(),
            .worker_id = worker_id.slice(),
        };
    }

    /// base/base `reject_ownership` and the not-found / cancelled cases.
    fn reject(
        service: *Service,
        call: *Call,
        method_name: []const u8,
        session_id: []const u8,
        auth: store_module.Auth,
    ) HandlerError {
        const reason = switch (auth) {
            .authorized => unreachable,
            .not_found => return service.fail(call, code.not_found, "proof job not found for " ++
                "session_id {s}", .{session_id}),
            .cancelled => if (std.mem.eql(u8, method_name, "heartbeat") or
                std.mem.eql(u8, method_name, "record_proof_session"))
                return call.fail(code.proof_cancelled, protocol.proof_request_cancelled_message)
            else
                "job has already reached a terminal state",
            .not_claimed => "job is not currently claimed",
            .stale_lock => "lock is held by another worker or has been rotated",
            .expired => "lock has expired",
            .terminal => "job has already reached a terminal state",
        };
        const format = "{s} rejected for session_id {s}: {s}";
        const arguments = .{ method_name, session_id, reason };
        return service.fail(call, code.failed_precondition, format, arguments);
    }
};

fn prove_block_range(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    const request = try service.params(protocol.ProveBlockRangeRequest, call);
    var proof = request.proof;
    proof.session_id = try service.canonical(call, &proof.session_id);
    const id = proof.session_id.slice();
    const created = service.store.create(&proof, request.retry_failed, now_ns);
    const outcome = created catch |err| return switch (err) {
        error.IdCollision => service.fail(
            call,
            code.failed_precondition,
            "session_id {s} already exists with a different request",
            .{id},
        ),
        error.Full => call.fail(code.resource_exhausted, "proof job store is full"),
        error.InvalidRange => call.fail(code.invalid_params, "invalid proof block range"),
    };
    switch (outcome) {
        .created, .replayed, .requeued => {},
        .retry_not_allowed => return service.fail(
            call,
            code.failed_precondition,
            "session_id {s} already failed; set retry_failed to true to requeue it",
            .{id},
        ),
        .retry_exhausted => return service.fail(call, code.resource_exhausted, "session_id {s}: " ++
            "proof request retry budget exhausted; " ++
            "use get_proof for the stored terminal result", .{id}),
        .cancelled => return service.fail(call, code.failed_precondition, "session_id {s} was " ++
            "cancelled; delete it with deleteProofRequest before proving it again", .{id}),
    }
    try service.reply(protocol.ProveBlockRangeResponse, call, &.{ .session_id = proof.session_id });
}

fn get_proof(service: *Service, call: *Call) HandlerError!void {
    _ = service.begin();
    const request = try service.params(protocol.GetProofRequest, call);
    const session_id = try service.canonical(call, &request.session_id);
    const job = service.store.get(session_id.slice()) orelse
        return call.fail(code.not_found, protocol.proof_request_not_found_message);
    const response = store_module.to_get_proof(job);
    try service.reply(protocol.GetProofResponse, call, &response);
}

fn cancel_proof_request(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    const request = try service.params(protocol.CancelProofRequest, call);
    const session_id = try service.canonical(call, &request.session_id);
    const id = session_id.slice();
    switch (service.store.cancel(id, now_ns)) {
        .cancelled, .already_cancelled => {},
        .not_found => return call.fail(code.not_found, protocol.proof_request_not_found_message),
        .unsupported_backend => return call.fail(
            code.failed_precondition,
            "cancellation is not available for this proof backend",
        ),
        .already_terminal => return service.fail(call, code.failed_precondition, "session_id " ++
            "{s}: proof request is terminal, expected a queued or running request", .{id}),
    }
    try call.writer.null_value();
}

fn delete_proof_request(service: *Service, call: *Call) HandlerError!void {
    _ = service.begin();
    const request = try service.params(protocol.DeleteProofRequest, call);
    const session_id = try service.canonical(call, &request.session_id);
    switch (service.store.delete(session_id.slice())) {
        .deleted, .not_found => {},
        .not_completed => return service.fail(call, code.failed_precondition, "session_id {s}: " ++
            "proof request is not completed, expected SUCCEEDED or FAILED", .{session_id.slice()}),
    }
    try call.writer.null_value();
}

fn list_proofs(service: *Service, call: *Call) HandlerError!void {
    _ = service.begin();
    const request = try service.params(protocol.ListProofsRequest, call);
    const limit: u32 = switch (request.limit) {
        0 => protocol.list_limit_default,
        1...protocol.list_limit_max => request.limit,
        else => return service.fail(call, code.invalid_params, "limit must be less than or " ++
            "equal to {d}", .{protocol.list_limit_max}),
    };
    const page_size = @min(limit, service.page.len);
    const page = service.page[0..page_size];
    const listed = service.store.list(request.offset, request.status_filter, page);
    const summaries = service.summaries[0..listed.page.len];
    for (summaries, listed.page) |*summary, job| summary.* = store_module.to_summary(job);
    const response: protocol.ListProofsResponse = .{
        .proofs = summaries,
        .total_count = listed.total,
    };
    try service.reply(protocol.ListProofsResponse, call, &response);
}

fn get_next_proof(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    const request = try service.params(protocol.GetNextProofRequest, call);
    if (request.worker_id.len == 0) {
        return call.fail(code.invalid_params, "worker_id must not be empty");
    }
    const filter: store_module.Filter = .{
        .proof_type = request.proof_type,
        .tee_kinds = request.tee_kinds,
        .zk_vms = request.zk_vms,
        .zk_backends = request.zk_backends,
    };
    const worker_id = request.worker_id.slice();
    const claimed = service.store.claim(&filter, worker_id, request.lock_duration_seconds, now_ns);
    const response: protocol.GetNextProofResponse = .{
        .job = if (claimed) |job| store_module.to_proof_job(job) else null,
    };
    try service.reply(protocol.GetNextProofResponse, call, &response);
}

fn heartbeat(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    var request = try service.params(protocol.HeartbeatRequest, call);
    const held = try service.lease(call, &request.session_id, &request.lock_id, &request.worker_id);
    const answer = service.store.heartbeat(&held, request.lock_duration_seconds, now_ns);
    if (answer.auth != .authorized) {
        return service.reject(call, "heartbeat", held.session_id, answer.auth);
    }
    const job = store_module.to_proof_job(answer.job.?);
    const response: protocol.HeartbeatResponse = .{ .job = job };
    try service.reply(protocol.HeartbeatResponse, call, &response);
}

fn abandon_proof(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    var request = try service.params(protocol.AbandonProofRequest, call);
    const held = try service.lease(call, &request.session_id, &request.lock_id, &request.worker_id);
    const message = request.error_message.slice();
    const answer, const outcome = service.store.abandon(&held, message, now_ns);
    if (answer.auth != .authorized) {
        return service.reject(call, "abandon_proof", held.session_id, answer.auth);
    }
    assert(outcome != null);
    const job = store_module.to_proof_job(answer.job.?);
    const response: protocol.AbandonProofResponse = .{ .job = job };
    try service.reply(protocol.AbandonProofResponse, call, &response);
}

fn submit_proof(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    var request = try service.params(protocol.WorkerSubmitProofRequest, call);
    const held = try service.lease(call, &request.session_id, &request.lock_id, &request.worker_id);
    const id = held.session_id;
    const answer, const outcome = service.store.submit(&held, &request.result, now_ns);
    if (answer.auth != .authorized) return service.reject(call, "submit_proof", id, answer.auth);
    switch (outcome.?) {
        .completed, .already_completed => {},
        .result_mismatch => return service.fail(call, code.invalid_params, "submit_proof " ++
            "rejected " ++
            "for session_id {s}: result does not match the claimed job", .{id}),
        .result_conflict => return service.fail(call, code.failed_precondition, "submit_" ++
            "proof rejected for session_id {s}: job already completed with a different " ++
            "result", .{id}),
    }
    const response: protocol.WorkerSubmitProofResponse = .{
        .job = store_module.to_proof_job(answer.job.?),
    };
    try service.reply(protocol.WorkerSubmitProofResponse, call, &response);
}

fn get_proof_session(service: *Service, call: *Call) HandlerError!void {
    _ = service.begin();
    const request = try service.params(protocol.GetProofSessionRequest, call);
    const session_id = try service.canonical(call, &request.session_id);
    const response: protocol.GetProofSessionResponse = .{
        .session = service.store.active_session(session_id.slice(), request.session_type),
    };
    try service.reply(protocol.GetProofSessionResponse, call, &response);
}

fn record_proof_session(service: *Service, call: *Call) HandlerError!void {
    const now_ns = service.begin();
    var request = try service.params(protocol.RecordProofSessionRequest, call);
    const held = try service.lease(call, &request.session_id, &request.lock_id, &request.worker_id);
    const session: protocol.BackendSession = .{
        .backend_session_id = request.backend_session_id,
        .state = request.state,
    };
    const session_type = request.session_type;
    const answer, const recorded =
        service.store.record_session(&held, session_type, session, now_ns);
    if (answer.auth != .authorized) {
        return service.reject(call, "record_proof_session", held.session_id, answer.auth);
    }
    const stored = recorded orelse return service.fail(
        call,
        code.failed_precondition,
        "record_proof_session rejected for session_id {s}: backend session status is terminal",
        .{held.session_id},
    );
    try service.reply(protocol.RecordProofSessionResponse, call, &.{ .session = stored });
}

test {
    _ = @import("service_test.zig");
}

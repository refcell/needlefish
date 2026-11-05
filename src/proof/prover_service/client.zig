//! Prover service clients (base/base `prover-service/client/src/{requester,worker}.rs`):
//! typed blocking calls over the proof tools' `Endpoint` (one JSON-RPC call per method,
//! IO advanced by the caller's pump), and the proposer's `Prover` over the requester API.
//!
//! The requester and worker APIs share one transport, so one `Client` type serves both;
//! base/base's retry with backoff is the caller's loop (the proposer retries on its next
//! tick, the worker on its next `tick`). Decoded responses live in the client's arena until
//! its next call.

const std = @import("std");
const assert = std.debug.assert;

const endpoint_module = @import("../rpc/endpoint.zig");
const interfaces = @import("../proposer/interfaces.zig");
const protocol = @import("protocol.zig");
const codec = @import("codec.zig");

pub const Error = error{
    /// The service answered `not found` (-32004).
    NotFound,
    /// The service refused the call with another JSON-RPC error (`last_code`).
    Rejected,
    /// Transport failure, timeout, or a malformed response.
    Unavailable,
};

pub const Options = struct {
    /// Largest encoded request (a submitted proof is hex: twice its size).
    request_bytes_max: u32 = 4 << 20,
    /// Decode arena for responses (proof bytes, roots, listings).
    response_arena_bytes: u32 = 4 << 20,
};

pub fn Client(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Endpoint = endpoint_module.Endpoint(IO);

        endpoint: *Endpoint,
        request_buffer: []u8,
        arena_memory: []u8,
        arena: std.heap.FixedBufferAllocator,
        /// The JSON-RPC error code of the last `Rejected` or `NotFound` call.
        last_code: i64 = 0,

        pub fn init(allocator: std.mem.Allocator, endpoint: *Endpoint, options: Options) !Self {
            assert(options.request_bytes_max > 0);
            assert(options.response_arena_bytes > 0);
            const request_buffer = try allocator.alloc(u8, options.request_bytes_max);
            errdefer allocator.free(request_buffer);
            const arena_memory = try allocator.alloc(u8, options.response_arena_bytes);
            return .{
                .endpoint = endpoint,
                .request_buffer = request_buffer,
                .arena_memory = arena_memory,
                .arena = .init(arena_memory),
            };
        }

        pub fn deinit(client: *Self, allocator: std.mem.Allocator) void {
            allocator.free(client.arena_memory);
            allocator.free(client.request_buffer);
            client.* = undefined;
        }

        /// One call of `method` with `request` as its only param. A `void` response is a
        /// JSON `null` result.
        pub fn call(
            client: *Self,
            comptime Response: type,
            method: []const u8,
            comptime Request: type,
            request: *const Request,
        ) Error!Response {
            const encoded = codec.encode_to(Request, client.request_buffer, request) catch
                return error.Unavailable;
            assert(encoded.len > 0);
            client.endpoint.reset();
            client.arena.reset();
            client.last_code = 0;
            const raw = client.endpoint.call(method, &.{.{ .raw_json = encoded }}) catch |err| {
                if (err == error.CallFailed) return error.Unavailable;
                const failure = client.endpoint.last_error orelse {
                    // A `null` result: success for unit methods.
                    if (Response == void) return;
                    return error.Unavailable;
                };
                client.last_code = failure.code;
                if (failure.code == protocol.code.not_found) return error.NotFound;
                return error.Rejected;
            };
            if (Response == void) return error.Unavailable;
            return codec.decode(Response, client.arena.allocator(), raw) catch error.Unavailable;
        }

        pub fn prove_block_range(
            client: *Self,
            request: *const protocol.ProveBlockRangeRequest,
        ) Error!protocol.ProveBlockRangeResponse {
            const Response = protocol.ProveBlockRangeResponse;
            const method = protocol.method.prove_block_range;
            return client.call(Response, method, protocol.ProveBlockRangeRequest, request);
        }

        pub fn get_proof(
            client: *Self,
            request: *const protocol.GetProofRequest,
        ) Error!protocol.GetProofResponse {
            const method = protocol.method.get_proof;
            return client.call(protocol.GetProofResponse, method, protocol.GetProofRequest, request);
        }

        pub fn cancel_proof_request(client: *Self, request: *const protocol.CancelProofRequest) Error!void {
            const method = protocol.method.cancel_proof_request;
            return client.call(void, method, protocol.CancelProofRequest, request);
        }

        pub fn delete_proof_request(client: *Self, request: *const protocol.DeleteProofRequest) Error!void {
            const method = protocol.method.delete_proof_request;
            return client.call(void, method, protocol.DeleteProofRequest, request);
        }

        pub fn list_proofs(
            client: *Self,
            request: *const protocol.ListProofsRequest,
        ) Error!protocol.ListProofsResponse {
            const method = protocol.method.list_proofs;
            return client.call(protocol.ListProofsResponse, method, protocol.ListProofsRequest, request);
        }

        pub fn get_next_proof(
            client: *Self,
            request: *const protocol.GetNextProofRequest,
        ) Error!protocol.GetNextProofResponse {
            const Response = protocol.GetNextProofResponse;
            const method = protocol.method.get_next_proof;
            return client.call(Response, method, protocol.GetNextProofRequest, request);
        }

        pub fn heartbeat(
            client: *Self,
            request: *const protocol.HeartbeatRequest,
        ) Error!protocol.HeartbeatResponse {
            const method = protocol.method.heartbeat;
            return client.call(protocol.HeartbeatResponse, method, protocol.HeartbeatRequest, request);
        }

        pub fn abandon_proof(
            client: *Self,
            request: *const protocol.AbandonProofRequest,
        ) Error!protocol.AbandonProofResponse {
            const Response = protocol.AbandonProofResponse;
            const method = protocol.method.abandon_proof;
            return client.call(Response, method, protocol.AbandonProofRequest, request);
        }

        pub fn submit_proof(
            client: *Self,
            request: *const protocol.WorkerSubmitProofRequest,
        ) Error!protocol.WorkerSubmitProofResponse {
            const Response = protocol.WorkerSubmitProofResponse;
            const method = protocol.method.submit_proof;
            return client.call(Response, method, protocol.WorkerSubmitProofRequest, request);
        }

        pub fn get_proof_session(
            client: *Self,
            request: *const protocol.GetProofSessionRequest,
        ) Error!protocol.GetProofSessionResponse {
            const Response = protocol.GetProofSessionResponse;
            const method = protocol.method.get_proof_session;
            return client.call(Response, method, protocol.GetProofSessionRequest, request);
        }

        pub fn record_proof_session(
            client: *Self,
            request: *const protocol.RecordProofSessionRequest,
        ) Error!protocol.RecordProofSessionResponse {
            const Response = protocol.RecordProofSessionResponse;
            const method = protocol.method.record_proof_session;
            return client.call(Response, method, protocol.RecordProofSessionRequest, request);
        }
    };
}

/// The proposer's `Prover` over the requester API (base/base `ProposerProofAdapter` with
/// `ProofRequesterClient`): TEE requests whose session id derives from the claimed root.
pub fn ProposerProver(comptime IO: type) type {
    return struct {
        const Self = @This();

        client: *Client(IO),
        /// The `initData` of the last succeeded poll.
        init_data: [130]u8 = undefined,

        pub fn prover(adapter: *Self) interfaces.Prover {
            return .{ .context = adapter, .vtable = &vtable };
        }

        const vtable: interfaces.Prover.VTable = .{
            .request = request,
            .poll = poll,
            .delete = delete,
        };

        fn of(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn request(context: *anyopaque, proof_request: *const interfaces.ProofRequest) interfaces.ProverError!void {
            const adapter = of(context);
            assert(proof_request.intermediate_block_interval > 0);
            const primitive: protocol.PrimitiveProofRequest = .{
                .l1_head = proof_request.l1_head.hash,
                .agreed_l2_head_hash = proof_request.agreed_l2_head_hash,
                .agreed_l2_output_root = proof_request.agreed_l2_output_root,
                .claimed_l2_output_root = proof_request.claimed_l2_output_root,
                .claimed_l2_block_number = proof_request.claimed_l2_block_number,
                .proposer = proof_request.proposer,
                .l1_head_number = proof_request.l1_head.number,
                .intermediate_block_interval = proof_request.intermediate_block_interval,
            };
            const session_id = protocol.tee_session_id_for_root(proof_request.session());
            const body = protocol.tee_prove_block_range_request(primitive, session_id);
            _ = adapter.client.prove_block_range(&body) catch return error.Unavailable;
        }

        fn poll(context: *anyopaque, session: interfaces.Hash) interfaces.ProverError!interfaces.ProofStatus {
            const adapter = of(context);
            const session_id = protocol.tee_session_id_for_root(session);
            const response = adapter.client.get_proof(&.{ .session_id = session_id }) catch |err|
                return switch (err) {
                    error.NotFound => error.NotFound,
                    error.Rejected, error.Unavailable => error.Unavailable,
                };
            switch (response.status) {
                .queued, .running => return .pending,
                .failed => return .failed,
                .succeeded => {},
            }
            const result = response.result orelse return error.Unavailable;
            // base/base `tee_proof_result`: anything but an AWS Nitro TEE result is unusable.
            if (result != .tee or result.tee.tee_kind != .aws_nitro) return .failed;
            const proposal = result.tee.aggregate_proposal;
            protocol.encode_tee_proof_bytes(
                &adapter.init_data,
                proposal.signature,
                proposal.l1_origin_hash,
                proposal.l1_origin_number,
            ) catch return .failed;
            return .{ .succeeded = .{
                .output_root = proposal.output_root,
                .intermediate_roots = result.tee.intermediate_roots,
                .init_data = &adapter.init_data,
            } };
        }

        fn delete(context: *anyopaque, session: interfaces.Hash) interfaces.ProverError!void {
            const adapter = of(context);
            const session_id = protocol.tee_session_id_for_root(session);
            adapter.client.delete_proof_request(&.{ .session_id = session_id }) catch |err|
                return switch (err) {
                    error.NotFound => error.NotFound,
                    error.Rejected, error.Unavailable => error.Unavailable,
                };
        }
    };
}

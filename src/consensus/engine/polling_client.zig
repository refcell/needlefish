//! Polling engine client: adapts the callback-based `sources.EngineClient` to the
//! non-blocking client contract of `task.zig`, so the engine task queue drives a real
//! execution layer over HTTP.
//!
//! The engine client runs one request at a time. Each call names its request with a `Key`
//! (method, version, and a digest of the identifying arguments). The first call starts the
//! request and returns `error.NotAvailable`; calls return `NotAvailable` while any request is
//! in flight. Once the result arrives, the next call with the same key takes it (once); a
//! call with a different key discards it and starts its own request. A task that keeps
//! calling with the same arguments therefore gets exactly the result of its own request,
//! and a task abandoned mid-request (reset, queue clear) cannot hand its result to another.
//! Results borrow the engine client's arena until the next result arrives.
//!
//! Errors map onto `task.ClientError`: -38002 is `InvalidForkchoiceState`; blocks that do
//! not decode, verify, or anchor at genesis are `InvalidBlock`; transport failures and other
//! RPC errors are `RpcFailed`; a missing block is null.
//! Plays the role of base/base's `EngineClient` trait object in the task queue
//! (`crates/consensus/engine/src/client.rs`), whose calls are async futures.

const std = @import("std");
const assert = std.debug.assert;

const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const engine_client = @import("../sources/engine_client.zig");
const l2_block_full = @import("../sources/l2_block_full.zig");

const ClientError = task.ClientError;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Wyhash = std.hash.Wyhash;

pub const Method = enum(u8) {
    forkchoice_updated,
    new_payload,
    get_payload,
    l2_block,
    l2_block_info,
};

/// Identifies a request. Digests are 64-bit Wyhash values over the arguments; the method
/// and version are compared exactly.
pub const Key = struct {
    method: Method,
    version: u8 = 0,
    digest: u64,

    pub fn eql(a: Key, b: Key) bool {
        return a.method == b.method and a.version == b.version and a.digest == b.digest;
    }

    pub fn forkchoice(
        version: task.Version,
        state: *const task.EngineForkchoiceState,
        attributes: ?*const task.EngineAttributes,
    ) Key {
        assert(version == .v2 or version == .v3);
        var hasher = Wyhash.init(0);
        hasher.update(&state.head_block_hash.bytes);
        hasher.update(&state.safe_block_hash.bytes);
        hasher.update(&state.finalized_block_hash.bytes);
        if (attributes) |value| hash_attributes(&hasher, value);
        hash_int(&hasher, @intFromBool(attributes != null));
        const key: Key = .{
            .method = .forkchoice_updated,
            .version = @backingInt(version),
            .digest = hasher.final(),
        };
        assert(key.version >= 2);
        return key;
    }

    pub fn new_payload(
        version: task.Version,
        payload: *const task.ExecutionPayload,
        params: *const task.NewPayloadParams,
    ) Key {
        assert(@backingInt(version) >= 2 and @backingInt(version) <= 4);
        var hasher = Wyhash.init(0);
        // The block hash commits to every payload field.
        hasher.update(&payload.block_hash.bytes);
        if (params.parent_beacon_block_root) |root| hasher.update(&root.bytes);
        hash_int(&hasher, if (params.versioned_hashes) |list| list.len + 1 else 0);
        hash_int(&hasher, if (params.execution_requests) |list| list.len + 1 else 0);
        const key: Key = .{
            .method = .new_payload,
            .version = @backingInt(version),
            .digest = hasher.final(),
        };
        assert(key.method == .new_payload);
        return key;
    }

    pub fn get_payload(version: task.Version, payload_id: task.PayloadId) Key {
        assert(@backingInt(version) >= 2 and @backingInt(version) <= 5);
        const key: Key = .{
            .method = .get_payload,
            .version = @backingInt(version),
            .digest = std.mem.readInt(u64, &payload_id, .big),
        };
        assert(key.method == .get_payload);
        return key;
    }

    pub fn block(method: Method, number: u64) Key {
        assert(method == .l2_block or method == .l2_block_info);
        const key: Key = .{ .method = method, .digest = number };
        assert(key.version == 0);
        return key;
    }
};

fn hash_int(hasher: *Wyhash, value: u64) void {
    hasher.update(std.mem.asBytes(&value));
}

fn hash_attributes(hasher: *Wyhash, attributes: *const task.EngineAttributes) void {
    hash_int(hasher, attributes.timestamp);
    hasher.update(&attributes.prev_randao.bytes);
    hasher.update(&attributes.suggested_fee_recipient.bytes);
    if (attributes.parent_beacon_block_root) |root| hasher.update(&root.bytes);
    hash_int(hasher, if (attributes.withdrawals) |list| list.len + 1 else 0);
    hash_int(hasher, attributes.gas_limit orelse 0);
    hash_int(hasher, if (attributes.no_tx_pool) |flag| @as(u64, @intFromBool(flag)) + 1 else 0);
    if (attributes.eip1559_params) |params| hasher.update(&params);
    hash_int(hasher, attributes.min_base_fee orelse 0);
    const transactions = attributes.transactions orelse &.{};
    hash_int(hasher, transactions.len);
    for (transactions) |transaction| {
        hash_int(hasher, transaction.len);
        hasher.update(transaction);
    }
}

pub fn PollingClient(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Engine = engine_client.EngineClient(IO);
        const Result = engine_client.Error!engine_client.Response;
        const Outcome = struct { result: Result };

        const Request = union(Method) {
            forkchoice_updated: struct {
                version: task.Version,
                state: *const task.EngineForkchoiceState,
                attributes: ?*const task.EngineAttributes,
            },
            new_payload: struct {
                version: task.Version,
                payload: *const task.ExecutionPayload,
                params: *const task.NewPayloadParams,
            },
            get_payload: struct { version: task.Version, payload_id: task.PayloadId },
            l2_block: u64,
            l2_block_info: u64,
        };

        engine: *Engine,
        /// The request in flight.
        pending: ?Key = null,
        /// The arrived result nobody has taken yet, and the key of its request.
        stored_key: ?Key = null,
        stored: Result = undefined,
        requests_started: u64 = 0,
        results_discarded: u64 = 0,

        /// The client must not move while a request is in flight.
        pub fn init(engine: *Engine) Self {
            assert(!engine.busy());
            const client: Self = .{ .engine = engine };
            assert(client.pending == null and client.stored_key == null);
            return client;
        }

        /// Drives the request timeout; call periodically.
        pub fn tick(client: *Self) void {
            assert(client.pending == null or client.engine.busy());
            client.engine.tick();
        }

        pub fn busy(client: *const Self) bool {
            assert(client.pending == null or client.stored_key == null);
            return client.pending != null;
        }

        pub fn forkchoice_updated(
            client: *Self,
            version: task.Version,
            state: *const task.EngineForkchoiceState,
            attributes: ?*const task.EngineAttributes,
        ) ClientError!task.ForkchoiceUpdated {
            const key = Key.forkchoice(version, state, attributes);
            const outcome = try client.poll(key, .{ .forkchoice_updated = .{
                .version = version,
                .state = state,
                .attributes = attributes,
            } });
            const response = outcome.result catch |err| return engine_error(err);
            return response.forkchoice_updated;
        }

        pub fn new_payload(
            client: *Self,
            version: task.Version,
            payload: *const task.ExecutionPayload,
            params: *const task.NewPayloadParams,
        ) ClientError!task.PayloadStatus {
            const key = Key.new_payload(version, payload, params);
            const outcome = try client.poll(key, .{ .new_payload = .{
                .version = version,
                .payload = payload,
                .params = params,
            } });
            const response = outcome.result catch |err| return engine_error(err);
            return response.payload_status;
        }

        pub fn get_payload(
            client: *Self,
            version: task.Version,
            payload_id: task.PayloadId,
        ) ClientError!task.PayloadEnvelope {
            const key = Key.get_payload(version, payload_id);
            const outcome = try client.poll(key, .{ .get_payload = .{
                .version = version,
                .payload_id = payload_id,
            } });
            const response = outcome.result catch |err| return engine_error(err);
            return response.payload;
        }

        /// The full block at `number` (`eth_getBlockByNumber(n, true)`), or null.
        pub fn l2_block_by_number(client: *Self, number: u64) ClientError!?task.L2Block {
            const outcome = try client.poll(Key.block(.l2_block, number), .{ .l2_block = number });
            const response = outcome.result catch |err| {
                if (err == error.BlockNotFound) return null;
                return block_error(err);
            };
            const block = response.l2_block_full;
            if (block.info.block_info.number != number) return error.InvalidBlock;
            return block;
        }

        pub fn l2_block_info_by_number(client: *Self, number: u64) ClientError!?L2BlockInfo {
            const key = Key.block(.l2_block_info, number);
            const outcome = try client.poll(key, .{ .l2_block_info = number });
            const response = outcome.result catch |err| {
                if (err == error.BlockNotFound) return null;
                return block_error(err);
            };
            const info = response.l2_block;
            if (info.block_info.number != number) return error.InvalidBlock;
            return info;
        }

        /// Takes the stored result for `key`, or starts `request` when idle.
        fn poll(client: *Self, key: Key, request: Request) ClientError!Outcome {
            assert(@as(Method, request) == key.method);
            if (client.stored_key) |stored_key| {
                client.stored_key = null;
                if (stored_key.eql(key)) return .{ .result = client.stored };
                client.results_discarded += 1; // Its caller moved on.
            }
            assert(client.stored_key == null);
            if (client.pending != null) return error.NotAvailable;
            client.start(key, request) catch return error.RpcFailed;
            return error.NotAvailable;
        }

        fn start(client: *Self, key: Key, request: Request) !void {
            assert(client.pending == null);
            assert(!client.engine.busy());
            client.pending = key;
            errdefer client.pending = null;
            const engine = client.engine;
            switch (request) {
                .forkchoice_updated => |call| try engine.forkchoice_updated(
                    call.version,
                    call.state,
                    call.attributes,
                    *Self,
                    client,
                    on_response,
                ),
                .new_payload => |call| try engine.new_payload(
                    call.version,
                    call.payload,
                    call.params,
                    *Self,
                    client,
                    on_response,
                ),
                .get_payload => |call| try engine.get_payload(
                    call.version,
                    call.payload_id,
                    *Self,
                    client,
                    on_response,
                ),
                .l2_block => |number| {
                    try engine.l2_full_block(.{ .number = number }, *Self, client, on_response);
                },
                .l2_block_info => |number| {
                    try engine.l2_block_info(.{ .number = number }, *Self, client, on_response);
                },
            }
            client.requests_started += 1;
        }

        fn on_response(client: *Self, engine: *Engine, result: Result) void {
            assert(engine == client.engine);
            assert(client.stored_key == null);
            const key = client.pending.?;
            client.pending = null;
            client.stored_key = key;
            client.stored = result;
        }
    };
}

/// Engine API calls: -38002 keeps its meaning, everything else is an RPC failure.
fn engine_error(err: engine_client.Error) ClientError {
    const result: ClientError = switch (err) {
        error.InvalidForkchoiceState => error.InvalidForkchoiceState,
        else => error.RpcFailed,
    };
    assert(result != error.NotAvailable);
    return result;
}

/// Block lookups: a block that fails decoding or verification is invalid; transport and
/// RPC errors (and running out of arena memory) are RPC failures.
fn block_error(err: engine_client.Error) ClientError {
    assert(err != error.BlockNotFound);
    if (err == error.OutOfMemory) return error.RpcFailed;
    if (in_error_set(l2_block_full.Error, err)) {
        assert(!in_error_set(rpc.client.Error, err));
        return error.InvalidBlock;
    }
    return error.RpcFailed;
}

fn in_error_set(comptime Set: type, err: anyerror) bool {
    inline for (@typeInfo(Set).error_set.error_names.?) |name| {
        if (err == @field(anyerror, name)) return true;
    }
    return false;
}

comptime {
    // Transport errors and block decoding errors must not overlap, or a transport failure
    // would be reported as an invalid block.
    @setEvalBranchQuota(100_000);
    for (@typeInfo(rpc.client.Error).error_set.error_names.?) |name| {
        assert(!in_error_set(l2_block_full.Error, @field(anyerror, name)));
    }
}

//! L2 Engine API client: `engine_forkchoiceUpdatedV2/V3`, `engine_newPayloadV2/V3/V4`,
//! `engine_getPayloadV2..V5` (the versions base/base selects per fork in
//! `crates/consensus/engine/src/versions.rs`), and `eth_getBlockByNumber` on the same
//! authenticated endpoint to build `L2BlockInfo`s or full, verified `L2Block`s. Every
//! request carries a fresh `Authorization: Bearer <jwt>` with `iat` from the injected IO's
//! wall clock.
//!
//! One request in flight. Results are delivered to the caller's callback as a `Response`
//! whose slices stay valid until the next response arrives. Engine API error codes map to
//! errors (`UnknownPayload`, `InvalidForkchoiceState`, ...); others become `RpcError`
//! with the code kept in `last_rpc_error_code`.
//! Mirrors base/base `crates/consensus/engine/src/client.rs` (`BaseEngineClient`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const protocol = @import("../protocol/root.zig");
const engine_json = @import("engine_json.zig");
const l2_block = @import("l2_block.zig");
const l2_block_full = @import("l2_block_full.zig");

const L2BlockInfo = protocol.block.L2BlockInfo;
const ChainGenesis = protocol.rollup_config.ChainGenesis;
const Version = engine_json.Version;

pub const ForkchoiceState = engine_json.ForkchoiceState;
pub const ForkchoiceUpdated = engine_json.ForkchoiceUpdated;
pub const PayloadAttributes = engine_json.PayloadAttributes;
pub const PayloadStatus = engine_json.PayloadStatus;
pub const ExecutionPayload = engine_json.ExecutionPayload;
pub const NewPayloadParams = engine_json.NewPayloadParams;
pub const PayloadEnvelope = engine_json.PayloadEnvelope;
pub const PayloadId = engine_json.PayloadId;

pub const BlockTag = union(enum) { number: u64, latest, safe, finalized };

pub const Response = union(enum) {
    forkchoice_updated: ForkchoiceUpdated,
    payload_status: PayloadStatus,
    payload: PayloadEnvelope,
    l2_block: L2BlockInfo,
    /// Borrows the client's arena until the next response.
    l2_block_full: l2_block_full.L2Block,
};

pub const Error = rpc.client.Error || l2_block_full.Error || error{
    UnknownPayload,
    InvalidForkchoiceState,
    InvalidPayloadAttributes,
    TooLargeRequest,
    UnsupportedFork,
    RpcError,
    /// `eth_getBlockByNumber` returned null.
    BlockNotFound,
};

pub const Options = struct {
    /// Anchors `L2BlockInfo` for the genesis block, which has no L1 info deposit.
    genesis: ChainGenesis,
    limits: engine_json.Limits = .{},
    block_limits: l2_block_full.Limits = .{},
    /// Largest request body (a `newPayload` with every transaction).
    request_size_max: u32 = 8 * 1024 * 1024,
    retain_bytes: usize = 4 * 1024 * 1024,
};

const Method = enum { forkchoice_updated, new_payload, get_payload, block, block_full };

/// Maps an Engine API error code (execution-apis `common.md`).
pub fn error_from_code(code: i64) Error {
    return switch (code) {
        -38001 => error.UnknownPayload,
        -38002 => error.InvalidForkchoiceState,
        -38003 => error.InvalidPayloadAttributes,
        -38004 => error.TooLargeRequest,
        -38005 => error.UnsupportedFork,
        else => error.RpcError,
    };
}

pub fn EngineClient(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);
        const Callback = *const fn (?*anyopaque, *Self, Error!Response) void;

        io: *IO,
        client: Rpc,
        secret: jwt.Secret,
        options: Options,
        arena: std.heap.ArenaAllocator,
        pending: ?Method = null,
        callback: Callback = undefined,
        context: ?*anyopaque = null,
        last_rpc_error_code: i64 = 0,

        /// `engine` must not move afterwards while a request is in flight.
        pub fn init(
            engine: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
            secret: jwt.Secret,
            options: Options,
        ) !void {
            assert(options.request_size_max <= http_options.send_buffer_size);
            const request_size_max = options.request_size_max;
            var client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            errdefer client.deinit();
            engine.* = .{
                .io = io,
                .client = client,
                .secret = secret,
                .options = options,
                .arena = .init(allocator),
            };
            assert(engine.pending == null);
        }

        pub fn deinit(engine: *Self) void {
            assert(engine.pending == null);
            engine.arena.deinit();
            engine.client.deinit();
            engine.* = undefined;
        }

        pub fn busy(engine: *const Self) bool {
            return engine.pending != null;
        }

        /// Drives the request timeout; call periodically.
        pub fn tick(engine: *Self) void {
            engine.client.http.tick();
        }

        pub fn forkchoice_updated(
            engine: *Self,
            version: Version,
            state: *const ForkchoiceState,
            attributes: ?*const PayloadAttributes,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Response) void,
        ) !void {
            assert(version == .v2 or version == .v3);
            const params: ForkchoiceParams = .{ .state = state, .attributes = attributes };
            var name: [32]u8 = undefined;
            const method = versioned(&name, "engine_forkchoiceUpdated", version);
            try engine.start(.forkchoice_updated, Context, context, callback);
            errdefer engine.pending = null;
            try engine.client.call(*Self, engine, on_result, method, &params, write_forkchoice);
        }

        pub fn new_payload(
            engine: *Self,
            version: Version,
            payload: *const ExecutionPayload,
            params: *const NewPayloadParams,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Response) void,
        ) !void {
            assert(@backingInt(version) >= 2 and @backingInt(version) <= 4);
            const call_params: NewPayloadCall = .{
                .version = version,
                .payload = payload,
                .params = params,
            };
            var name: [32]u8 = undefined;
            const method = versioned(&name, "engine_newPayload", version);
            try engine.start(.new_payload, Context, context, callback);
            errdefer engine.pending = null;
            const client = &engine.client;
            try client.call(*Self, engine, on_result, method, &call_params, write_new_payload);
        }

        pub fn get_payload(
            engine: *Self,
            version: Version,
            payload_id: PayloadId,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Response) void,
        ) !void {
            assert(@backingInt(version) >= 2 and @backingInt(version) <= 5);
            var name: [32]u8 = undefined;
            const method = versioned(&name, "engine_getPayload", version);
            try engine.start(.get_payload, Context, context, callback);
            errdefer engine.pending = null;
            try engine.client.call(*Self, engine, on_result, method, &payload_id, write_payload_id);
        }

        /// `eth_getBlockByNumber(tag, true)` decoded into an `L2BlockInfo`.
        pub fn l2_block_info(
            engine: *Self,
            tag: BlockTag,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Response) void,
        ) !void {
            const method = "eth_getBlockByNumber";
            try engine.start(.block, Context, context, callback);
            errdefer engine.pending = null;
            try engine.client.call(*Self, engine, on_result, method, &tag, write_block_tag);
        }

        /// `eth_getBlockByNumber(tag, true)` decoded into a full, verified `L2Block`.
        pub fn l2_full_block(
            engine: *Self,
            tag: BlockTag,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Response) void,
        ) !void {
            const method = "eth_getBlockByNumber";
            try engine.start(.block_full, Context, context, callback);
            errdefer engine.pending = null;
            try engine.client.call(*Self, engine, on_result, method, &tag, write_block_tag);
        }

        fn start(
            engine: *Self,
            method: Method,
            comptime Context: type,
            context: Context,
            comptime callback: fn (Context, *Self, Error!Response) void,
        ) error{Busy}!void {
            if (engine.pending != null) return error.Busy;
            assert(!engine.client.http.busy());
            var token_buffer: [jwt.token_size_max]u8 = undefined;
            const now_s = engine.io.now_realtime_ns() / std.time.ns_per_s;
            engine.client.set_bearer(jwt.create(engine.secret, now_s, &token_buffer));
            engine.pending = method;
            engine.context = if (Context == void) null else @ptrCast(@constCast(context));
            engine.callback = &struct {
                fn erased(opaque_context: ?*anyopaque, self: *Self, result: Error!Response) void {
                    callback(typed(Context, opaque_context), self, result);
                }
            }.erased;
        }

        fn on_result(
            engine: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &engine.client);
            const method = engine.pending.?;
            engine.pending = null;
            _ = engine.arena.reset(.{ .retain_with_limit = engine.options.retain_bytes });
            const response = engine.decode(method, result);
            engine.callback(engine.context, engine, response);
        }

        fn decode(
            engine: *Self,
            method: Method,
            result: rpc.client.Error!rpc.client.Result,
        ) Error!Response {
            const raw = switch (try result) {
                .ok => |raw| raw,
                .rpc_error => |rpc_error| {
                    engine.last_rpc_error_code = rpc_error.code;
                    return error_from_code(rpc_error.code);
                },
            };
            const allocator = engine.arena.allocator();
            const limits = engine.options.limits;
            return switch (method) {
                .forkchoice_updated => .{ .forkchoice_updated = try engine_json
                    .decode_forkchoice_updated(allocator, raw, limits) },
                .new_payload => .{
                    .payload_status = try engine_json.decode_payload_status(allocator, raw, limits),
                },
                .get_payload => .{
                    .payload = try engine_json.decode_payload_envelope(allocator, raw, limits),
                },
                .block => {
                    if (std.mem.eql(u8, raw, "null")) return error.BlockNotFound;
                    return .{ .l2_block = try l2_block.decode(raw, &engine.options.genesis) };
                },
                .block_full => {
                    if (std.mem.eql(u8, raw, "null")) return error.BlockNotFound;
                    const genesis = &engine.options.genesis;
                    const block_limits = engine.options.block_limits;
                    const block = try l2_block_full.decode(allocator, raw, genesis, block_limits);
                    return .{ .l2_block_full = block };
                },
            };
        }
    };
}

fn typed(comptime Context: type, opaque_context: ?*anyopaque) Context {
    if (Context == void) return {};
    assert(opaque_context != null);
    return @ptrCast(@alignCast(opaque_context));
}

fn versioned(buffer: *[32]u8, prefix: []const u8, version: Version) []const u8 {
    const name = std.fmt.bufPrint(buffer, "{s}V{d}", .{ prefix, @backingInt(version) }) catch
        unreachable; // The longest name is 28 bytes.
    assert(name.len > prefix.len);
    return name;
}

const ForkchoiceParams = struct {
    state: *const ForkchoiceState,
    attributes: ?*const PayloadAttributes,
};

fn write_forkchoice(
    params: *const ForkchoiceParams,
    writer: *json.Writer,
) json.Writer.WriteError!void {
    try engine_json.write_forkchoice_params(writer, params.state, params.attributes);
}

const NewPayloadCall = struct {
    version: Version,
    payload: *const ExecutionPayload,
    params: *const NewPayloadParams,
};

fn write_new_payload(
    call: *const NewPayloadCall,
    writer: *json.Writer,
) json.Writer.WriteError!void {
    try engine_json.write_new_payload_params(writer, call.version, call.payload, call.params);
}

fn write_payload_id(id: *const PayloadId, writer: *json.Writer) json.Writer.WriteError!void {
    try writer.data(id);
}

fn write_block_tag(tag: *const BlockTag, writer: *json.Writer) json.Writer.WriteError!void {
    switch (tag.*) {
        .number => |number| try writer.quantity(number),
        .latest => try writer.string("latest"),
        .safe => try writer.string("safe"),
        .finalized => try writer.string("finalized"),
    }
    try writer.boolean(true);
}

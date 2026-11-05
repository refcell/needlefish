//! Engine API JSON-RPC methods (served on the JWT-authenticated authrpc port) over
//! `Engine(Chain)`. The authrpc router also answers every eth_* method, since rollup
//! consensus clients query the execution client through the engine endpoint.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const engine_module = @import("../engine/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const codec = @import("engine_json.zig");

const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Version = payload.Version;
const types = engine_module.types;
const B256 = primitives.B256;

pub const Engine = engine_module.Engine(node.Chain);

pub const Limits = struct {
    bytes: u32 = 8 << 20,
    transactions_max: u32 = 4096,
    withdrawals_max: u32 = 16,
    hashes_max: u32 = 64,
};

pub const EngineApi = struct {
    spec: *const chainspec.ChainSpec,
    engine: *Engine,
    chain: *node.Chain,
    eth: *eth.Api,
    space: codec.Space,
    client_version: []const u8 = "v0.0.0",

    pub fn init(
        allocator: std.mem.Allocator,
        engine: *Engine,
        eth_api: *eth.Api,
        limits: Limits,
    ) !EngineApi {
        assert(limits.transactions_max > 0);
        const bytes = try allocator.alloc(u8, limits.bytes);
        errdefer allocator.free(bytes);
        const transactions = try allocator.alloc([]const u8, limits.transactions_max);
        errdefer allocator.free(transactions);
        const withdrawals = try allocator.alloc(payload.Withdrawal, limits.withdrawals_max);
        errdefer allocator.free(withdrawals);
        const hashes = try allocator.alloc(B256, limits.hashes_max);
        return .{
            .spec = engine.spec,
            .engine = engine,
            .chain = eth_api.chain,
            .eth = eth_api,
            .space = .{
                .bytes = bytes,
                .transactions = transactions,
                .withdrawals = withdrawals,
                .hashes = hashes,
            },
        };
    }

    pub fn deinit(api: *EngineApi, allocator: std.mem.Allocator) void {
        allocator.free(api.space.hashes);
        allocator.free(api.space.withdrawals);
        allocator.free(api.space.transactions);
        allocator.free(api.space.bytes);
        api.* = undefined;
    }
};

const engine_methods = [_]rpc.Method(*EngineApi){
    .{ .name = "engine_exchangeCapabilities", .handler = exchange_capabilities },
    .{ .name = "engine_getClientVersionV1", .handler = client_version },
    .{ .name = "engine_forkchoiceUpdatedV1", .handler = forkchoice_updated(.v1) },
    .{ .name = "engine_forkchoiceUpdatedV2", .handler = forkchoice_updated(.v2) },
    .{ .name = "engine_forkchoiceUpdatedV3", .handler = forkchoice_updated(.v3) },
    .{ .name = "engine_newPayloadV1", .handler = new_payload(.v1) },
    .{ .name = "engine_newPayloadV2", .handler = new_payload(.v2) },
    .{ .name = "engine_newPayloadV3", .handler = new_payload(.v3) },
    .{ .name = "engine_newPayloadV4", .handler = new_payload(.v4) },
    .{ .name = "engine_getPayloadV1", .handler = get_payload(.v1) },
    .{ .name = "engine_getPayloadV2", .handler = get_payload(.v2) },
    .{ .name = "engine_getPayloadV3", .handler = get_payload(.v3) },
    .{ .name = "engine_getPayloadV4", .handler = get_payload(.v4) },
};

fn wrap_eth(comptime handler: *const fn (*eth.Api, *Call) HandlerError!void) fn (
    *EngineApi,
    *Call,
) HandlerError!void {
    return struct {
        fn call_eth(api: *EngineApi, call: *Call) HandlerError!void {
            return handler(api.eth, call);
        }
    }.call_eth;
}

const eth_methods = wrapped: {
    var out: [eth.methods.len]rpc.Method(*EngineApi) = undefined;
    for (eth.methods, 0..) |method, index| {
        out[index] = .{ .name = method.name, .handler = wrap_eth(method.handler) };
    }
    break :wrapped out;
};

pub const methods = engine_methods ++ eth_methods;
pub const Router = rpc.Router(*EngineApi, &methods);

fn fail_engine(call: *Call, err: types.EngineError) HandlerError {
    return call.fail(@backingInt(types.error_code(err)), @errorName(err));
}

fn exchange_capabilities(api: *EngineApi, call: *Call) HandlerError!void {
    _ = api;
    _ = try call.params.raw(); // The consensus client's list; ours does not depend on it.
    try call.params.finish();
    try call.writer.begin_array();
    for (engine_methods) |method| try call.writer.string(method.name);
    try call.writer.end_array();
}

fn client_version(api: *EngineApi, call: *Call) HandlerError!void {
    _ = try call.params.optional_raw();
    try call.params.finish();
    const w = call.writer;
    try w.begin_array();
    try w.begin_object();
    try w.key("code");
    try w.string("NF");
    try w.key("name");
    try w.string("needlefish");
    try w.key("version");
    try w.string(api.client_version);
    try w.key("commit");
    try w.string("0x00000000");
    try w.end_object();
    try w.end_array();
}

fn invalid_params(err: codec.Error) HandlerError {
    return switch (err) {
        error.InvalidParams => error.InvalidParams,
    };
}

fn non_null(raw: ?[]const u8) ?[]const u8 {
    const text = raw orelse return null;
    return if (std.mem.eql(u8, text, "null")) null else text;
}

fn forkchoice_updated(comptime version: Version) fn (*EngineApi, *Call) HandlerError!void {
    return struct {
        fn handle(api: *EngineApi, call: *Call) HandlerError!void {
            const state = codec.parse_forkchoice(try call.params.raw()) catch |e| {
                return invalid_params(e);
            };
            const attributes_raw = non_null(try call.params.optional_raw());
            try call.params.finish();
            api.space.reset();
            var attributes: payload.PayloadAttributes = undefined;
            if (attributes_raw) |raw| {
                attributes = codec.parse_attributes(raw, &api.space) catch |e| {
                    return invalid_params(e);
                };
            }
            const pointer: ?*const payload.PayloadAttributes =
                if (attributes_raw != null) &attributes else null;
            const updated = api.engine.forkchoice_updated(version, state, pointer) catch |err| {
                return fail_engine(call, err);
            };
            try codec.write_forkchoice_updated(call.writer, updated);
        }
    }.handle;
}

fn new_payload(comptime version: Version) fn (*EngineApi, *Call) HandlerError!void {
    return struct {
        fn handle(api: *EngineApi, call: *Call) HandlerError!void {
            api.space.reset();
            const raw = try call.params.raw();
            const execution_payload = codec.parse_payload(raw, &api.space) catch |e| {
                return invalid_params(e);
            };
            var params: types.NewPayloadParams = .{};
            if (@backingInt(version) >= 3) {
                const hashes = try call.params.raw();
                params.versioned_hashes = codec.parse_hashes(hashes, &api.space) catch |e| {
                    return invalid_params(e);
                };
                params.parent_beacon_block_root = .{ .bytes = try call.params.fixed(32) };
            }
            if (@backingInt(version) >= 4) {
                const requests = try call.params.raw();
                params.execution_requests = codec.parse_data_array(requests, &api.space) catch |e| {
                    return invalid_params(e);
                };
            }
            try call.params.finish();
            const engine = api.engine;
            const status = engine.new_payload(version, &execution_payload, &params) catch |err| {
                return fail_engine(call, err);
            };
            try codec.write_status(call.writer, status);
        }
    }.handle;
}

fn get_payload(comptime version: Version) fn (*EngineApi, *Call) HandlerError!void {
    return struct {
        fn handle(api: *EngineApi, call: *Call) HandlerError!void {
            const id = try call.params.fixed(8);
            try call.params.finish();
            const built = api.engine.get_payload(version, id) catch |err| {
                return fail_engine(call, err);
            };
            var withdrawals: [node.chain.withdrawals_max]payload.Withdrawal = undefined;
            const hash = built.block_hash.bytes;
            const transactions = api.space.transactions;
            const chain = api.chain;
            const execution_payload = chain.payload_of(hash, transactions, &withdrawals) orelse {
                return fail_engine(call, error.UnknownPayload);
            };
            if (version == .v1) return codec.write_payload(call.writer, &execution_payload);
            try write_envelope(api, call.writer, version, &execution_payload, built.block_value);
        }
    }.handle;
}

fn write_envelope(
    api: *EngineApi,
    w: *json.Writer,
    version: Version,
    execution_payload: *const types.ExecutionPayload,
    block_value: u256,
) json.Writer.WriteError!void {
    assert(version != .v1);
    try w.begin_object();
    try w.key("executionPayload");
    try codec.write_payload(w, execution_payload);
    try codec.write_quantity(w, "blockValue", block_value);
    if (@backingInt(version) >= 3) {
        try w.key("blobsBundle");
        try w.raw("{\"commitments\":[],\"proofs\":[],\"blobs\":[]}");
        try w.key("shouldOverrideBuilder");
        try w.boolean(false);
        const stored = api.chain.record(execution_payload.block_hash.bytes).?;
        if (api.spec.mode == .l2) {
            try w.key("parentBeaconBlockRoot");
            const root = stored.header.parent_beacon_block_root orelse B256.zero;
            try w.data(&root.bytes);
        }
        if (@backingInt(version) >= 4) {
            try w.key("executionRequests");
            try w.begin_array();
            var requests = stored.requests;
            while (!requests.is_empty()) {
                try w.data(requests.bytes() catch unreachable); // Stored by the chain.
            }
            try w.end_array();
        }
    }
    try w.end_object();
}

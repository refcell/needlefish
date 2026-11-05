//! The `optimism_*` rollup node JSON-RPC API (base/base `crates/consensus/rpc/src/rollup.rs`,
//! `jsonrpsee.rs` `RollupNodeApi`) for `utilities/rpc.Router`.
//!
//! Handlers read node state through a `Backend` vtable so the API is independent of the node
//! service and testable in isolation. JSON shapes follow base/base: `BlockInfo` and
//! `L2BlockInfo` are camelCase with plain integer numbers (`l1origin`, `sequenceNumber`),
//! `SyncStatus` is snake_case, `OutputResponse` and `SafeHeadResponse` are camelCase.
//!
//! Difference: handlers never block. `outputAtBlock` needs an execution-layer proof; a
//! backend that has not fetched it yet returns `error.NotAvailable`, which is reported as a
//! retryable server error (-32000) instead of waiting.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const keccak256 = @import("../../common/primitives/root.zig").keccak256;
const block = @import("../protocol/block.zig");
const safedb = @import("../safedb/root.zig");
const rollup_json = @import("../protocol/rollup_json.zig");
const RollupConfig = @import("../protocol/rollup_config.zig").RollupConfig;

const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const BlockId = block.BlockId;
const BlockInfo = block.BlockInfo;
const L2BlockInfo = block.L2BlockInfo;
const Hash = block.Hash;

pub const SyncStatus = struct {
    current_l1: BlockInfo = .{},
    current_l1_finalized: BlockInfo = .{},
    head_l1: BlockInfo = .{},
    safe_l1: BlockInfo = .{},
    finalized_l1: BlockInfo = .{},
    unsafe_l2: L2BlockInfo = .{},
    local_safe_l2: L2BlockInfo = .{},
    safe_l2: L2BlockInfo = .{},
    finalized_l2: L2BlockInfo = .{},
};

/// Version-0 output root preimage (base/base `OutputRoot`).
pub const OutputRoot = struct {
    state_root: Hash,
    bridge_storage_root: Hash,
    block_hash: Hash,

    pub const encoded_size_bytes = 128;

    pub fn encode(output: OutputRoot) [encoded_size_bytes]u8 {
        var encoded: [encoded_size_bytes]u8 = @splat(0);
        @memcpy(encoded[32..64], &output.state_root.bytes);
        @memcpy(encoded[64..96], &output.bridge_storage_root.bytes);
        @memcpy(encoded[96..128], &output.block_hash.bytes);
        assert(std.mem.allEqual(u8, encoded[0..32], 0));
        return encoded;
    }

    pub fn hash(output: OutputRoot) Hash {
        const encoded = output.encode();
        const digest = keccak256(&encoded);
        assert(digest.bytes.len == 32);
        return digest;
    }
};

pub const BlockTag = union(enum) { number: u64, latest, safe, finalized, earliest, pending };

pub const OutputAtBlock = struct {
    block_ref: L2BlockInfo,
    output: OutputRoot,
};

pub const Backend = struct {
    context: *anyopaque,
    vtable: *const VTable,
    version: []const u8,
    rollup: *const RollupConfig,

    pub const VTable = struct {
        sync_status: *const fn (context: *anyopaque) SyncStatus,
        output_at_block: *const fn (
            context: *anyopaque,
            tag: BlockTag,
        ) error{ NotAvailable, NotFound }!OutputAtBlock,
        /// Null when safe head tracking is disabled.
        safe_db: *const fn (context: *anyopaque) ?*const safedb.SafeDB,
    };
};

pub const methods = [_]rpc.Method(*const Backend){
    .{ .name = "optimism_outputAtBlock", .handler = output_at_block },
    .{ .name = "optimism_safeHeadAtL1Block", .handler = safe_head_at_l1_block },
    .{ .name = "optimism_syncStatus", .handler = sync_status },
    .{ .name = "optimism_rollupConfig", .handler = rollup_config },
    .{ .name = "optimism_version", .handler = version },
};

pub const Router = rpc.Router(*const Backend, &methods);

const safe_head_unavailable_code: i32 = -32000;

fn parse_block_tag(call: *Call) HandlerError!BlockTag {
    const text = try call.params.string();
    const tags = [_]struct { []const u8, BlockTag }{
        .{ "latest", .latest },     .{ "safe", .safe },       .{ "finalized", .finalized },
        .{ "earliest", .earliest }, .{ "pending", .pending },
    };
    for (tags) |entry| if (std.mem.eql(u8, text, entry[0])) return entry[1];
    const number = json.parse_quantity(u64, text) catch return error.InvalidParams;
    return .{ .number = number };
}

fn output_at_block(backend: *const Backend, call: *Call) HandlerError!void {
    const tag = try parse_block_tag(call);
    try call.params.finish();
    const result = backend.vtable.output_at_block(backend.context, tag) catch |err| {
        return switch (err) {
            error.NotAvailable => call.fail(rpc.code.server_error, "output not available yet"),
            error.NotFound => call.fail(rpc.code.server_error, "block not found"),
        };
    };
    const status = backend.vtable.sync_status(backend.context);
    const writer = call.writer;
    try writer.begin_object();
    try writer.key("version");
    try writer.data(&(@as([32]u8, @splat(0))));
    try writer.key("outputRoot");
    try writer.data(&result.output.hash().bytes);
    try writer.key("blockRef");
    try write_l2_block_info(writer, result.block_ref);
    try writer.key("withdrawalStorageRoot");
    try writer.data(&result.output.bridge_storage_root.bytes);
    try writer.key("stateRoot");
    try writer.data(&result.output.state_root.bytes);
    try writer.key("syncStatus");
    try write_sync_status(writer, status);
    try writer.end_object();
}

fn safe_head_at_l1_block(backend: *const Backend, call: *Call) HandlerError!void {
    const tag = try parse_block_tag(call);
    try call.params.finish();
    const number = switch (tag) {
        .number => |number| number,
        else => return call.fail(
            rpc.code.invalid_params,
            "optimism_safeHeadAtL1Block requires an explicit block number, " ++
                "not latest/earliest/pending",
        ),
    };
    const db = backend.vtable.safe_db(backend.context) orelse return call.fail(
        safe_head_unavailable_code,
        "safe head tracking is disabled on this node",
    );
    const entry = db.safe_head_at_l1(number) catch |err| switch (err) {
        error.NotFound => return call.fail(safe_head_unavailable_code, "safe head not found"),
        error.OutOfMemory => return call.fail(rpc.code.internal_error, "internal error"),
    };
    assert(entry.l1_block.number <= number);
    const writer = call.writer;
    try writer.begin_object();
    try writer.key("l1Block");
    try write_block_id(writer, entry.l1_block);
    try writer.key("safeHead");
    try write_block_id(writer, entry.safe_head);
    try writer.end_object();
}

fn sync_status(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const status = backend.vtable.sync_status(backend.context);
    assert(status.finalized_l2.block_info.number <= status.unsafe_l2.block_info.number or
        status.unsafe_l2.block_info.hash.is_zero());
    try write_sync_status(call.writer, status);
}

fn rollup_config(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    assert(backend.rollup.block_time > 0 or backend.rollup.l2_chain_id == 0);
    try rollup_json.write(call.writer, backend.rollup);
}

fn version(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    assert(backend.version.len > 0);
    try call.writer.string(backend.version);
}

pub fn write_block_id(writer: *json.Writer, id: BlockId) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("hash");
    try writer.data(&id.hash.bytes);
    try writer.key("number");
    try writer.integer(id.number);
    try writer.end_object();
}

fn write_block_info_fields(writer: *json.Writer, info: BlockInfo) json.Writer.WriteError!void {
    try writer.key("hash");
    try writer.data(&info.hash.bytes);
    try writer.key("number");
    try writer.integer(info.number);
    try writer.key("parentHash");
    try writer.data(&info.parent_hash.bytes);
    try writer.key("timestamp");
    try writer.integer(info.timestamp);
}

pub fn write_block_info(writer: *json.Writer, info: BlockInfo) json.Writer.WriteError!void {
    try writer.begin_object();
    try write_block_info_fields(writer, info);
    try writer.end_object();
}

pub fn write_l2_block_info(writer: *json.Writer, info: L2BlockInfo) json.Writer.WriteError!void {
    try writer.begin_object();
    try write_block_info_fields(writer, info.block_info);
    try writer.key("l1origin");
    try write_block_id(writer, info.l1_origin);
    try writer.key("sequenceNumber");
    try writer.integer(info.sequence_number);
    try writer.end_object();
}

pub fn write_sync_status(writer: *json.Writer, status: SyncStatus) json.Writer.WriteError!void {
    try writer.begin_object();
    inline for (.{ "current_l1", "current_l1_finalized", "head_l1", "safe_l1", "finalized_l1" }) |
        name,
    | {
        try writer.key(name);
        try write_block_info(writer, @field(status, name));
    }
    inline for (.{ "unsafe_l2", "safe_l2", "finalized_l2", "local_safe_l2" }) |name| {
        try writer.key(name);
        try write_l2_block_info(writer, @field(status, name));
    }
    try writer.end_object();
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const TestNode = struct {
    status: SyncStatus = .{},
    output: ?OutputAtBlock = null,
    db: ?*const safedb.SafeDB = null,
    last_tag: ?BlockTag = null,
    rollup: RollupConfig = .{ .block_time = 2, .l2_chain_id = 8453 },

    const vtable: Backend.VTable = .{
        .sync_status = status_of,
        .output_at_block = output_of,
        .safe_db = db_of,
    };

    fn node(context: *anyopaque) *TestNode {
        return @ptrCast(@alignCast(context));
    }
    fn status_of(context: *anyopaque) SyncStatus {
        return node(context).status;
    }
    fn output_of(context: *anyopaque, tag: BlockTag) error{ NotAvailable, NotFound }!OutputAtBlock {
        node(context).last_tag = tag;
        return node(context).output orelse error.NotAvailable;
    }
    fn db_of(context: *anyopaque) ?*const safedb.SafeDB {
        return node(context).db;
    }

    fn call(test_node: *TestNode, body: []const u8, buffer: []u8) []const u8 {
        const backend: Backend = .{
            .context = test_node,
            .vtable = &vtable,
            .version = "v0.1.0",
            .rollup = &test_node.rollup,
        };
        var out: std.Io.Writer = .fixed(buffer);
        _ = Router.handle(&backend, body, &out);
        return out.buffered();
    }
};

fn filled(byte: u8) Hash {
    return .{ .bytes = @splat(byte) };
}

test "rollup rpc: output root matches the version-0 hash" {
    const output: OutputRoot = .{
        .state_root = filled(1),
        .bridge_storage_root = filled(2),
        .block_hash = filled(3),
    };
    var preimage: [128]u8 = @splat(0);
    @memset(preimage[32..64], 1);
    @memset(preimage[64..96], 2);
    @memset(preimage[96..128], 3);
    try testing.expectEqualSlices(u8, &preimage, &output.encode());
    try testing.expect(output.hash().eql(keccak256(&preimage)));
}

test "rollup rpc: syncStatus and version JSON" {
    var test_node: TestNode = .{};
    test_node.status.head_l1 = .{ .hash = filled(1), .number = 7, .timestamp = 9 };
    test_node.status.unsafe_l2 = .{
        .block_info = .{ .hash = filled(2), .number = 3, .parent_hash = filled(4) },
        .l1_origin = .{ .number = 5, .hash = filled(6) },
        .sequence_number = 1,
    };
    var buffer: [8192]u8 = undefined;
    const reply = test_node.call(
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_syncStatus","params":[]}
    , &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "\"head_l1\":{\"hash\":\"0x0101") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"number\":7,\"parentHash\":\"0x0000") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"l1origin\":{\"hash\":\"0x0606") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"sequenceNumber\":1}") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"local_safe_l2\":{") != null);
    const version_reply = test_node.call(
        \\{"jsonrpc":"2.0","id":2,"method":"optimism_version"}
    , &buffer);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":2,"result":"v0.1.0"}
    , version_reply);
    const config_reply = test_node.call(
        \\{"jsonrpc":"2.0","id":3,"method":"optimism_rollupConfig"}
    , &buffer);
    const start = std.mem.indexOf(u8, config_reply, "\"result\":").? + 9;
    const config = try rollup_json.parse(config_reply[start .. config_reply.len - 1]);
    try testing.expectEqualDeep(test_node.rollup, config);
}

test "rollup rpc: outputAtBlock tags, availability, and response" {
    var test_node: TestNode = .{};
    var buffer: [8192]u8 = undefined;
    var reply = test_node.call(
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_outputAtBlock","params":["0x10"]}
    , &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "\"code\":-32000") != null);
    try testing.expectEqual(@as(u64, 16), test_node.last_tag.?.number);
    test_node.output = .{
        .block_ref = .{ .block_info = .{ .number = 16, .hash = filled(9) } },
        .output = .{
            .state_root = filled(1),
            .bridge_storage_root = filled(2),
            .block_hash = filled(9),
        },
    };
    reply = test_node.call(
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_outputAtBlock","params":["finalized"]}
    , &buffer);
    try testing.expectEqual(BlockTag.finalized, test_node.last_tag.?);
    var root_hex: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&root_hex, "0x{x}", .{&test_node.output.?.output.hash().bytes});
    try testing.expect(std.mem.indexOf(u8, reply, &root_hex) != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"withdrawalStorageRoot\":\"0x0202") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"syncStatus\":{\"current_l1\"") != null);
    reply = test_node.call(
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_outputAtBlock","params":["bogus"]}
    , &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "\"code\":-32602") != null);
}

test "rollup rpc: safeHeadAtL1Block" {
    var test_node: TestNode = .{};
    var buffer: [4096]u8 = undefined;
    const body =
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_safeHeadAtL1Block","params":["0x5"]}
    ;
    var reply = test_node.call(body, &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "tracking is disabled") != null);
    var db = try safedb.SafeDB.init(testing.allocator, 8);
    defer db.deinit(testing.allocator);
    test_node.db = &db;
    reply = test_node.call(body, &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "safe head not found") != null);
    db.safe_head_updated(
        .{ .block_info = .{ .number = 11, .hash = filled(0xbb) } },
        .{ .number = 4, .hash = filled(0xaa) },
    );
    reply = test_node.call(body, &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "\"l1Block\":{\"hash\":\"0xaaaa") != null);
    try testing.expect(std.mem.indexOf(u8, reply, "\"number\":11}") != null);
    reply = test_node.call(
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_safeHeadAtL1Block","params":["latest"]}
    , &buffer);
    try testing.expect(std.mem.indexOf(u8, reply, "explicit block number") != null);
}

fn fuzz_body(test_node: *TestNode, body: []const u8) !void {
    var buffer: [16384]u8 = undefined;
    const reply = test_node.call(body, &buffer);
    if (reply.len > 0) try json.validate(reply);
}

test "rollup rpc: seeded fuzz, replies are always valid JSON" {
    var prng = Prng.init(0x524f4c4c);
    var test_node: TestNode = .{};
    const names = [_][]const u8{
        "outputAtBlock", "safeHeadAtL1Block", "syncStatus", "version", "rollupConfig",
    };
    const params = [_][]const u8{ "[]", "[\"0x1\"]", "[\"safe\"]", "[1]", "{}", "[\"0x\"]", "x" };
    var body: [256]u8 = undefined;
    for (0..2000) |_| {
        if (prng.chance(1, 2)) {
            test_node.output = .{ .block_ref = .{}, .output = .{
                .state_root = filled(1),
                .bridge_storage_root = filled(2),
                .block_hash = filled(3),
            } };
        } else test_node.output = null;
        const text = try std.fmt.bufPrint(&body, "{{\"jsonrpc\":\"2.0\",\"id\":{d}," ++
            "\"method\":\"optimism_{s}\",\"params\":{s}}}", .{
            prng.below(100),
            names[prng.below(names.len)],
            params[prng.below(params.len)],
        });
        const cut = if (prng.chance(1, 8)) prng.below(text.len) else text.len;
        try fuzz_body(&test_node, text[0..cut]);
    }
}

test "rollup rpc: fuzz request bodies" {
    try testing.fuzz({}, fuzz_target, .{});
}

fn fuzz_target(_: void, smith: *testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const length = smith.slice(&input);
    var test_node: TestNode = .{};
    try fuzz_body(&test_node, input[0..length]);
}

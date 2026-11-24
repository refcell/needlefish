//! Differential protocol `systemConfig` mode: applies one L1 block's receipts to a system
//! config on derivation's path (`SystemConfig.update_with_receipts`, with Ecotone decided
//! from the L1 timestamp under the Base mainnet rollup config) and reports the resulting
//! config and what happened to every log.
//!
//! Each log runs alone through `update_with_receipts`, in a receipt with the original
//! status, so every outcome comes from the derivation code itself. needlefish's derivation
//! skips every malformed update, so no log halts it.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const chains = @import("../../common/chains/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const request = @import("request.zig");
const response = @import("response.zig");

const SystemConfig = protocol.system_config.SystemConfig;
const Log = protocol.system_config.Log;
const Receipt = protocol.system_config.Receipt;
const Address = primitives.Address;
const B256 = primitives.B256;
const Writer = std.Io.Writer;
const Error = request.Error;

pub const RawConfig = struct {
    batcherAddress: ?[]const u8 = null,
    overhead: ?[]const u8 = null,
    scalar: ?[]const u8 = null,
    gasLimit: ?[]const u8 = null,
    eip1559Denominator: ?[]const u8 = null,
    eip1559Elasticity: ?[]const u8 = null,
    operatorFeeScalar: ?[]const u8 = null,
    operatorFeeConstant: ?[]const u8 = null,
    minBaseFee: ?[]const u8 = null,
    daFootprintGasScalar: ?[]const u8 = null,
};

pub const RawLog = struct {
    address: []const u8 = "",
    topics: []const []const u8 = &.{},
    data: []const u8 = "0x",
};

pub const RawReceipt = struct {
    status: []const u8 = "",
    logs: []const RawLog = &.{},
};

/// The request's `systemConfig` object. `forks` is informational: Ecotone comes from
/// `l1Timestamp`.
pub const RawSystemConfig = struct {
    l1Timestamp: ?[]const u8 = null,
    forks: []const []const u8 = &.{},
    config: RawConfig = .{},
    receipts: []const RawReceipt = &.{},
};

pub const Outcome = union(enum) {
    applied: u64,
    rejected: protocol.system_config.UpdateError,
    ignored,
};

pub const Result = struct {
    config: SystemConfig,
    outcomes: []const Outcome,
};

/// The rollup config fields derivation reads here, from needlefish's Base mainnet config.
const rollup: protocol.RollupConfig = .{
    .upgrades = .base_mainnet,
    .l1_system_config_address = chains.mainnet.system_config_address,
};

/// Decodes the request, applies its receipts, and writes the response line.
pub fn handle(
    arena: std.mem.Allocator,
    id: ?[]const u8,
    raw: ?RawSystemConfig,
    out: *Writer,
) Writer.Error!void {
    const result = run(arena, raw orelse return response.write_error(
        out,
        id,
        "invalid request: MissingField systemConfig",
        null,
    )) catch |err| {
        const text = std.fmt.allocPrint(arena, "invalid request: {t}", .{err}) catch
            "invalid request";
        return response.write_error(out, id, text, null);
    };
    try write(out, id, &result);
}

pub fn run(arena: std.mem.Allocator, raw: RawSystemConfig) Error!Result {
    const timestamp = try request.quantity(u64, required(raw.l1Timestamp));
    var config = try decode_config(&raw.config);
    const ecotone = rollup.is_feature_active(.blob_aware_l1_fees, timestamp);
    var count: usize = 0;
    for (raw.receipts) |receipt| count += receipt.logs.len;
    const outcomes = try arena.alloc(Outcome, count);
    var index: usize = 0;
    for (raw.receipts) |raw_receipt| {
        const success = try decode_status(raw_receipt.status);
        for (raw_receipt.logs) |raw_log| {
            const log = try decode_log(arena, &raw_log);
            outcomes[index] = apply(&config, success, log, ecotone);
            index += 1;
        }
    }
    assert(index == count);
    return .{ .config = config, .outcomes = outcomes };
}

/// One log through `update_with_receipts`; a skipped config update is replayed through
/// `apply_log` on a copy for its error.
fn apply(config: *SystemConfig, success: bool, log: Log, ecotone: bool) Outcome {
    const receipts = [_]Receipt{.{ .success = success, .logs = &.{log} }};
    const address = rollup.l1_system_config_address;
    const applied = config.update_with_receipts(&receipts, address, ecotone);
    assert(applied <= 1);
    // Derivation reads the kind from the low 8 bytes of topics[2].
    if (applied == 1) {
        return .{ .applied = std.mem.readInt(u64, log.topics[2].bytes[24..32], .big) };
    }
    const update = success and log.address.eql(address) and log.topics.len > 0 and
        log.topics[0].eql(protocol.system_config.config_update_topic);
    if (!update) return .ignored;
    var scratch = config.*;
    _ = scratch.apply_log(log, ecotone) catch |err| return .{ .rejected = err };
    unreachable; // update_with_receipts applies every log apply_log accepts.
}

fn decode_config(raw: *const RawConfig) Error!SystemConfig {
    return .{
        .batcher_address = .init(try request.fixed(20, required(raw.batcherAddress))),
        .overhead = std.mem.readInt(u256, &try request.fixed(32, required(raw.overhead)), .big),
        .scalar = std.mem.readInt(u256, &try request.fixed(32, required(raw.scalar)), .big),
        .gas_limit = try request.quantity(u64, required(raw.gasLimit)),
        .eip1559_denominator = try request.quantity(u32, required(raw.eip1559Denominator)),
        .eip1559_elasticity = try request.quantity(u32, required(raw.eip1559Elasticity)),
        .operator_fee_scalar = try request.quantity(u32, required(raw.operatorFeeScalar)),
        .operator_fee_constant = try request.quantity(u64, required(raw.operatorFeeConstant)),
        .min_base_fee = try request.quantity(u64, required(raw.minBaseFee)),
        .da_footprint_gas_scalar = try request.quantity(u16, required(raw.daFootprintGasScalar)),
    };
}

fn decode_status(text: []const u8) Error!bool {
    if (std.mem.eql(u8, text, "0x1")) return true;
    if (std.mem.eql(u8, text, "0x0")) return false;
    return error.InvalidField;
}

fn decode_log(arena: std.mem.Allocator, raw: *const RawLog) Error!Log {
    const topics = try arena.alloc(B256, raw.topics.len);
    for (raw.topics, topics) |text, *topic| topic.* = .{ .bytes = try request.fixed(32, text) };
    return .{
        .address = .init(try request.fixed(20, raw.address)),
        .topics = topics,
        .data = try request.bytes(arena, raw.data),
    };
}

fn required(field: ?[]const u8) Error![]const u8 {
    return field orelse error.MissingField;
}

pub fn write(out: *Writer, id: ?[]const u8, result: *const Result) Writer.Error!void {
    try out.writeAll("{\"id\":");
    try response.write_string_or_null(out, id);
    try out.writeAll(",\"ok\":true,\"valid\":true,\"rejected\":[],\"receipts\":[],\"post\":{}," ++
        "\"systemConfig\":{\"config\":");
    try write_config(out, &result.config);
    try out.writeAll(",\"logs\":[");
    for (result.outcomes, 0..) |outcome, index| {
        if (index > 0) try out.writeAll(",");
        switch (outcome) {
            .applied => |kind| {
                try out.writeAll("{\"outcome\":\"applied\",\"kind\":");
                try response.quantity(out, kind);
                try out.writeAll("}");
            },
            .rejected => |err| {
                try out.print("{{\"outcome\":\"rejected\",\"error\":\"{t}\"}}", .{err});
            },
            .ignored => try out.writeAll("{\"outcome\":\"ignored\"}"),
        }
    }
    try out.writeAll("]}}");
}

fn write_config(out: *Writer, config: *const SystemConfig) Writer.Error!void {
    var overhead: [32]u8 = undefined;
    var scalar: [32]u8 = undefined;
    std.mem.writeInt(u256, &overhead, config.overhead, .big);
    std.mem.writeInt(u256, &scalar, config.scalar, .big);
    try out.writeAll("{\"batcherAddress\":");
    try response.data(out, &config.batcher_address.bytes);
    try out.writeAll(",\"overhead\":");
    try response.data(out, &overhead);
    try out.writeAll(",\"scalar\":");
    try response.data(out, &scalar);
    const quantities = [_]struct { []const u8, u64 }{
        .{ "gasLimit", config.gas_limit },
        .{ "eip1559Denominator", config.eip1559_denominator.? },
        .{ "eip1559Elasticity", config.eip1559_elasticity.? },
        .{ "operatorFeeScalar", config.operator_fee_scalar.? },
        .{ "operatorFeeConstant", config.operator_fee_constant.? },
        .{ "minBaseFee", config.min_base_fee.? },
        .{ "daFootprintGasScalar", config.da_footprint_gas_scalar.? },
    };
    for (quantities) |entry| {
        try out.print(",\"{s}\":", .{entry[0]});
        try response.quantity(out, entry[1]);
    }
    try out.writeAll("}");
}

const testing = std.testing;

fn hex_repeat(comptime byte: *const [2]u8, comptime count: usize) *const [2 * count]u8 {
    const pairs: [count][2]u8 = @splat(byte.*);
    const flat: [2 * count]u8 = @bitCast(pairs);
    return &flat;
}

test "diff system config: per-log outcomes follow derivation's update path" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const topic0 = "\"0x1d2b0bda21d56b8bd12d4f94ebacffdfb35f5e226f84b461103bb8beab6353be\"";
    const zero = "\"0x" ++ hex_repeat("00", 32) ++ "\"";
    const head = hex_repeat("00", 31) ++ "20";
    // Gas limit kind (2) with dirty high topic bytes: derivation reads the low 8 bytes.
    const kind = "\"0x" ++ hex_repeat("ff", 24) ++ hex_repeat("00", 7) ++ "02\"";
    const gas = "\"0x" ++ head ++ head ++ hex_repeat("00", 28) ++ "01c9c380\"";
    const config_address = "\"0x73a79fab69143498ed3712e519a88a918e1f4072\"";
    const update = "{\"address\":" ++ config_address ++ ",\"topics\":[" ++ topic0 ++ "," ++
        zero ++ "," ++ kind ++ "," ++ zero ++ "],\"data\":" ++ gas ++ "}";
    const bad_pointer = "{\"address\":" ++ config_address ++ ",\"topics\":[" ++ topic0 ++ "," ++
        zero ++ "," ++ kind ++ "],\"data\":\"0x" ++ hex_repeat("00", 96) ++ "\"}";
    const other = "{\"address\":\"0x" ++ hex_repeat("11", 20) ++ "\",\"topics\":[" ++
        topic0 ++ "," ++ zero ++ "," ++ kind ++ "],\"data\":" ++ gas ++ "}";
    const line = "{\"id\":\"sc\",\"chain\":\"base-mainnet\",\"mode\":\"systemConfig\"," ++
        "\"systemConfig\":{\"l1Timestamp\":\"0x6b49d200\",\"config\":{\"batcherAddress\":\"0x" ++
        hex_repeat("50", 20) ++ "\",\"overhead\":\"0x" ++ hex_repeat("00", 31) ++
        "bc\",\"scalar\":\"0x" ++
        hex_repeat("00", 32) ++ "\",\"gasLimit\":\"0x1\",\"eip1559Denominator\":\"0xfa\"," ++
        "\"eip1559Elasticity\":\"0x6\",\"operatorFeeScalar\":\"0x0\"," ++
        "\"operatorFeeConstant\":\"0x0\",\"minBaseFee\":\"0x0\"," ++
        "\"daFootprintGasScalar\":\"0x190\"},\"receipts\":[{\"status\":\"0x0\",\"logs\":[" ++
        update ++ "]},{\"status\":\"0x1\",\"logs\":[" ++ bad_pointer ++ "," ++ other ++ "," ++
        update ++ "]}]}}";
    const raw = try request.parse(arena, line);
    const result = try run(arena, raw.systemConfig.?);
    try testing.expectEqual(@as(u64, 30_000_000), result.config.gas_limit);
    try testing.expectEqual(@as(usize, 4), result.outcomes.len);
    try testing.expectEqual(Outcome.ignored, result.outcomes[0]); // Failed receipt.
    try testing.expectEqual(
        Outcome{ .rejected = error.InvalidDataPointer },
        result.outcomes[1],
    );
    try testing.expectEqual(Outcome.ignored, result.outcomes[2]); // Another emitter.
    try testing.expectEqual(Outcome{ .applied = 2 }, result.outcomes[3]); // Four topics.
}

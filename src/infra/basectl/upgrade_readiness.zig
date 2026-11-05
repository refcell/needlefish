//! `basectl upgrade-readiness`: whether the consensus node supports the contract-backed
//! upgrades scheduled on L1 (`base_upgradeReadiness`, base/base
//! `commands/upgrade_readiness.rs`). Not ready is a failing outcome so rollouts can gate
//! on the exit code.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;
const Text = types.Text;

pub const upgrades_max = 16;

pub const Upgrade = struct {
    upgrade_id: Text(64),
    required_protocol_version: Text(64),
    activation_timestamp: u64,
    supported: bool,
    malformed: bool,
    would_halt: bool,
};

pub const Readiness = struct {
    ready: bool,
    node_protocol_version: Text(64),
    mode: Text(32),
    reason: ?Text(256) = null,
    l1_block_number: ?u64 = null,
    upgrades: types.List(Upgrade, upgrades_max) = .{},
};

pub const Report = struct {
    network: []const u8,
    readiness: Readiness,
};

pub fn decode_readiness(value: json.Value) DecodeError!Readiness {
    var readiness: Readiness = .{
        .ready = try types.decode_bool(try rpc.field(value, "ready")),
        .node_protocol_version = try types.decode_string(
            64,
            try rpc.field(value, "node_protocol_version"),
        ),
        .mode = try types.decode_string(32, try rpc.field(value, "mode")),
    };
    if (try types.optional_field(value, "reason")) |reason| {
        readiness.reason = try types.decode_string(256, reason);
    }
    if (try types.optional_field(value, "l1_block_number")) |number| {
        readiness.l1_block_number = try rpc.number(number);
    }
    const upgrades = try rpc.field(value, "upgrades");
    if (upgrades != .array) return error.MalformedResponse;
    for (upgrades.array.items) |item| {
        if (!readiness.upgrades.push(try decode_upgrade(item))) return error.MalformedResponse;
    }
    assert(readiness.upgrades.count <= upgrades_max);
    return readiness;
}

fn decode_upgrade(value: json.Value) DecodeError!Upgrade {
    const upgrade: Upgrade = .{
        .upgrade_id = try types.decode_string(64, try rpc.field(value, "upgrade_id")),
        .required_protocol_version = try types.decode_string(
            64,
            try rpc.field(value, "required_protocol_version"),
        ),
        .activation_timestamp = try rpc.number(try rpc.field(value, "activation_timestamp")),
        .supported = try types.decode_bool(try rpc.field(value, "supported")),
        .malformed = try types.decode_bool(try rpc.field(value, "malformed")),
        .would_halt = try types.decode_bool(try rpc.field(value, "would_halt")),
    };
    assert(value == .object);
    return upgrade;
}

/// `target_version`, when set, must be plain `major.minor.patch[-rc.N]` (validated by the
/// server); it is passed through as the single param.
pub fn fetch(context: *const types.Context, target_version: ?[]const u8) types.Fetched(Report) {
    assert(context.network.len > 0);
    var buffer: [96]u8 = undefined;
    const params = if (target_version) |version| blk: {
        if (version.len > 64 or std.mem.indexOfAny(u8, version, "\"\\") != null) {
            return .{ .failed = .{ .what = "target version", .failure = .malformed } };
        }
        break :blk std.fmt.bufPrint(&buffer, "[\"{s}\"]", .{version}) catch unreachable;
    } else "[]";
    const readiness = types.probe(
        Readiness,
        context.rollup.client,
        "base_upgradeReadiness",
        params,
        decode_readiness,
    );
    return switch (readiness) {
        .failed => |failure| .{ .failed = .{ .what = "rollup rpc", .failure = failure } },
        .ok => |value| .{ .ok = .{ .network = context.network, .readiness = value } },
    };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    const readiness = &report.readiness;
    assert(readiness.upgrades.count <= upgrades_max);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "ready", "{}", .{readiness.ready});
    try types.row(writer, "mode", "{s}", .{readiness.mode.slice()});
    try types.row(writer, "node_protocol_version", "{s}", .{
        readiness.node_protocol_version.slice(),
    });
    if (readiness.l1_block_number) |number| {
        try types.row(writer, "l1_block_number", "{d}", .{number});
    } else {
        try types.row(writer, "l1_block_number", "none (no schedule on L1)", .{});
    }
    if (readiness.reason) |*reason| try types.row(writer, "reason", "{s}", .{reason.slice()});
    if (readiness.upgrades.count == 0) try types.row(writer, "scheduled_upgrades", "none", .{});
    for (readiness.upgrades.slice()) |*upgrade| {
        var key_buffer: [80]u8 = undefined;
        const id = upgrade.upgrade_id.slice();
        // Proof: ids are at most 64 bytes.
        const key = std.fmt.bufPrint(&key_buffer, "upgrade[{s}]", .{id}) catch unreachable;
        try types.row(
            writer,
            key,
            "required={s} activation={d} supported={} malformed={} would_halt={}",
            .{
                upgrade.required_protocol_version.slice(), upgrade.activation_timestamp,
                upgrade.supported,                         upgrade.malformed,
                upgrade.would_halt,
            },
        );
    }
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

pub const sample_readiness =
    \\{"ready":false,"node_protocol_version":"1.2.3","mode":"runtime-admin",
    \\"reason":"upgrade jovian requires 1.3.0","l1_block_number":77,
    \\"upgrades":[{"upgrade_id":"jovian","required_protocol_version":"1.3.0",
    \\"activation_timestamp":1800000000,"supported":false,"malformed":false,"would_halt":true}]}
;

test "basectl upgrade-readiness: decode and render" {
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "base_upgradeReadiness", .result = sample_readiness },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{ .rollup = .{ .client = &client } };
    const report = fetch(&context, "1.3.0").ok;
    try testing.expect(!report.readiness.ready);
    var buffer: [1024]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "upgrade[jovian]       required=1.3.0 " ++
        "activation=1800000000 supported=false malformed=false would_halt=true\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "l1_block_number       77\n") != null);
    try testing.expectEqual(types.Failure.malformed, fetch(&context, "1\"").failed.failure);
}

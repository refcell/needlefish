//! `basectl batcher`: the batcher's runtime state from its admin RPC
//! (`admin_getBatcherStatus`, base/base `commands/batcher.rs` status path). The
//! start/stop/flush actions are not ported.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;

pub const Status = struct {
    stopped: bool,
    in_flight: u64,
    da_backlog_bytes: u64,
};

pub const Report = struct {
    network: []const u8,
    rpc: []const u8,
    status: Status,
};

pub fn decode_status(value: json.Value) DecodeError!Status {
    const status: Status = .{
        .stopped = try types.decode_bool(try rpc.field(value, "stopped")),
        .in_flight = try rpc.number(try rpc.field(value, "in_flight")),
        .da_backlog_bytes = try rpc.number(try rpc.field(value, "da_backlog_bytes")),
    };
    assert(value == .object);
    return status;
}

pub fn fetch(context: *const types.Context) types.Fetched(Report) {
    assert(context.network.len > 0);
    const status = types.probe(
        Status,
        context.batcher.client,
        "admin_getBatcherStatus",
        "[]",
        decode_status,
    );
    return switch (status) {
        .failed => |failure| .{ .failed = .{ .what = "batcher rpc", .failure = failure } },
        .ok => |value| .{ .ok = .{
            .network = context.network,
            .rpc = context.batcher.url,
            .status = value,
        } },
    };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.network.len > 0);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "rpc", "{s}", .{report.rpc});
    try types.row(writer, "stopped", "{}", .{report.status.stopped});
    try types.row(writer, "in flight", "{d}", .{report.status.in_flight});
    try types.row(writer, "da backlog bytes", "{d}", .{report.status.da_backlog_bytes});
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

test "basectl batcher: decode and render status" {
    var fake: FakeTransport = .{ .answers = &.{.{
        .method = "admin_getBatcherStatus",
        .result = "{\"stopped\":false,\"in_flight\":2,\"da_backlog_bytes\":4096}",
    }} };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    var context: types.Context = .{ .batcher = .{ .client = &client, .url = "http://b" } };
    const report = fetch(&context).ok;
    try testing.expectEqual(@as(u64, 4096), report.status.da_backlog_bytes);
    var buffer: [512]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    try testing.expectEqualStrings(
        "network               devnet\n" ++
            "rpc                   http://b\n" ++
            "stopped               false\n" ++
            "in flight             2\n" ++
            "da backlog bytes      4096\n",
        writer.buffered(),
    );
    context.batcher.client = null;
    try testing.expectEqual(types.Failure.not_configured, fetch(&context).failed.failure);
}

//! `basectl txpool`: pending and queued transaction counts of the execution node's pool
//! (base/base `commands/txpool.rs`, read path). The whole pool is read with
//! `txpool_status`, falling back to counting `txpool_content`; one sender's transactions
//! with `txpool_contentFrom`. Pool mutation (`admin_clearTxpool`) is not ported.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;

/// Transactions per sender map and senders per pool are bounded when counting content.
pub const entries_max: u32 = 1 << 20;

pub const Counts = struct {
    pending: u64,
    queued: u64,
};

pub const Report = struct {
    network: []const u8,
    rpc: []const u8,
    sender: ?types.Address,
    counts: Counts,
};

/// `txpool_status`: `{"pending":"0x..","queued":"0x.."}`.
pub fn decode_status(value: json.Value) DecodeError!Counts {
    const counts: Counts = .{
        .pending = try rpc.number(try rpc.field(value, "pending")),
        .queued = try rpc.number(try rpc.field(value, "queued")),
    };
    assert(value == .object);
    return counts;
}

/// `txpool_content`: `{"pending":{sender:{nonce:tx}},"queued":{...}}`.
pub fn decode_content(value: json.Value) DecodeError!Counts {
    const counts: Counts = .{
        .pending = try count_nested(try rpc.field(value, "pending")),
        .queued = try count_nested(try rpc.field(value, "queued")),
    };
    assert(value == .object);
    return counts;
}

/// `txpool_contentFrom`: `{"pending":{nonce:tx},"queued":{nonce:tx}}`.
pub fn decode_content_from(value: json.Value) DecodeError!Counts {
    const counts: Counts = .{
        .pending = try count_object(try rpc.field(value, "pending")),
        .queued = try count_object(try rpc.field(value, "queued")),
    };
    assert(value == .object);
    return counts;
}

fn count_object(value: json.Value) DecodeError!u64 {
    if (value != .object) return error.MalformedResponse;
    const count = value.object.count();
    if (count > entries_max) return error.MalformedResponse;
    return count;
}

fn count_nested(value: json.Value) DecodeError!u64 {
    if (value != .object) return error.MalformedResponse;
    if (value.object.count() > entries_max) return error.MalformedResponse;
    var total: u64 = 0;
    for (value.object.values()) |by_nonce| total += try count_object(by_nonce);
    assert(total <= @as(u64, entries_max) * entries_max);
    return total;
}

pub fn fetch(context: *const types.Context, sender: ?types.Address) types.Fetched(Report) {
    assert(context.network.len > 0);
    const client = context.l2.client;
    const counts: types.Probe(Counts) = if (sender) |address| blk: {
        var buffer: [48]u8 = undefined;
        const params = std.fmt.bufPrint(&buffer, "[\"{f}\"]", .{address}) catch unreachable;
        break :blk types.probe(Counts, client, "txpool_contentFrom", params, decode_content_from);
    } else blk: {
        const status = types.probe(Counts, client, "txpool_status", "[]", decode_status);
        if (status == .failed and status.failed == .unavailable) {
            break :blk types.probe(Counts, client, "txpool_content", "[]", decode_content);
        }
        break :blk status;
    };
    return switch (counts) {
        .failed => |failure| .{ .failed = .{ .what = "l2 rpc", .failure = failure } },
        .ok => |value| .{ .ok = .{
            .network = context.network,
            .rpc = context.l2.url,
            .sender = sender,
            .counts = value,
        } },
    };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.network.len > 0);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "rpc", "{s}", .{report.rpc});
    try types.row(writer, "scope", "{s}", .{if (report.sender == null) "all" else "sender"});
    try types.row(writer, "pending", "{d}", .{report.counts.pending});
    try types.row(writer, "queued", "{d}", .{report.counts.queued});
    try types.row(writer, "total", "{d}", .{report.counts.pending + report.counts.queued});
    if (report.sender) |sender| try types.row(writer, "sender", "{f}", .{sender});
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

test "basectl txpool: status, content fallback, sender" {
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "txpool_status", .result = "{\"pending\":\"0x3\",\"queued\":\"0x1\"}" },
        .{
            .method = "txpool_contentFrom",
            .result = "{\"pending\":{\"0\":{},\"1\":{}},\"queued\":{}}",
        },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{ .l2 = .{ .client = &client, .url = "http://l2" } };
    const all = fetch(&context, null).ok;
    try testing.expectEqual(@as(u64, 3), all.counts.pending);
    const one = fetch(&context, .{ .bytes = @splat(0x11) }).ok;
    try testing.expectEqual(@as(u64, 2), one.counts.pending);
    var buffer: [1024]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&all, &writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "total                 4\n") != null);

    var fallback: FakeTransport = .{ .answers = &.{.{
        .method = "txpool_content",
        .result = "{\"pending\":{\"0xa\":{\"0\":{},\"1\":{}},\"0xb\":{\"5\":{}}},\"queued\":{}}",
    }} };
    var fallback_client = try fallback.client(testing.allocator);
    defer fallback_client.deinit(testing.allocator);
    const fallback_context: types.Context = .{ .l2 = .{ .client = &fallback_client } };
    try testing.expectEqual(@as(u64, 3), fetch(&fallback_context, null).ok.counts.pending);
}

//! `basectl sync-status`: the consensus node's `optimism_syncStatus` combined with the
//! execution node's `eth_syncing` (base/base `commands/sync_status.rs`).

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Hash = types.Hash;
const Writer = types.Writer;
const DecodeError = types.DecodeError;

/// A block reference from `optimism_syncStatus` (L1 `BlockInfo` or flattened `L2BlockRef`).
pub const BlockRef = struct {
    number: u64 = 0,
    timestamp: u64 = 0,
    hash: Hash = .{},
};

pub const SyncStatus = struct {
    current_l1: BlockRef = .{},
    head_l1: BlockRef = .{},
    safe_l1: BlockRef = .{},
    finalized_l1: BlockRef = .{},
    unsafe_l2: BlockRef = .{},
    safe_l2: BlockRef = .{},
    finalized_l2: BlockRef = .{},

    /// Seconds the safe head trails the unsafe head.
    pub fn safe_lag_seconds(status: *const SyncStatus) u64 {
        return status.unsafe_l2.timestamp -| status.safe_l2.timestamp;
    }

    pub fn safe_lag_blocks(status: *const SyncStatus) u64 {
        return status.unsafe_l2.number -| status.safe_l2.number;
    }

    pub fn finalized_lag_blocks(status: *const SyncStatus) u64 {
        return status.unsafe_l2.number -| status.finalized_l2.number;
    }
};

/// `eth_syncing`: `false`, or the staged-sync progress object.
pub const ElSync = union(enum) {
    not_syncing,
    syncing: Progress,

    pub const Progress = struct {
        starting_block: u64,
        current_block: u64,
        highest_block: u64,
    };
};

pub const Report = struct {
    network: []const u8,
    el: types.Probe(ElSync),
    cl: SyncStatus,
};

pub fn decode_block_ref(value: json.Value) DecodeError!BlockRef {
    const ref: BlockRef = .{
        .number = try rpc.number(try rpc.field(value, "number")),
        .timestamp = try rpc.number(try rpc.field(value, "timestamp")),
        .hash = try types.decode_hash(try rpc.field(value, "hash")),
    };
    assert(value == .object);
    return ref;
}

pub fn decode_sync_status(value: json.Value) DecodeError!SyncStatus {
    if (value != .object) return error.MalformedResponse;
    var status: SyncStatus = .{};
    inline for (.{
        "current_l1", "head_l1", "safe_l1",      "finalized_l1",
        "unsafe_l2",  "safe_l2", "finalized_l2",
    }) |name| {
        @field(status, name) = try decode_block_ref(try rpc.field(value, name));
    }
    assert(status.head_l1.number >= 0);
    return status;
}

pub fn decode_el_sync(value: json.Value) DecodeError!ElSync {
    if (value == .bool) {
        if (value.bool) return error.MalformedResponse;
        return .not_syncing;
    }
    if (value != .object) return error.MalformedResponse;
    const progress: ElSync.Progress = .{
        .starting_block = try rpc.number(try rpc.field(value, "startingBlock")),
        .current_block = try rpc.number(try rpc.field(value, "currentBlock")),
        .highest_block = try rpc.number(try rpc.field(value, "highestBlock")),
    };
    return .{ .syncing = progress };
}

pub fn fetch(context: *const types.Context) types.Fetched(Report) {
    assert(context.network.len > 0);
    const cl = types.probe(
        SyncStatus,
        context.rollup.client,
        "optimism_syncStatus",
        "[]",
        decode_sync_status,
    );
    const status = switch (cl) {
        .ok => |status| status,
        .failed => |failure| return .{ .failed = .{ .what = "rollup rpc", .failure = failure } },
    };
    const el = types.probe(ElSync, context.l2.client, "eth_syncing", "[]", decode_el_sync);
    return .{ .ok = .{ .network = context.network, .el = el, .cl = status } };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.network.len > 0);
    const cl = &report.cl;
    try types.row(writer, "network", "{s}", .{report.network});
    switch (report.el) {
        .failed => |failure| try types.row(writer, "el_syncing", "{s}", .{failure.text()}),
        .ok => |el| switch (el) {
            .not_syncing => try types.row(writer, "el_syncing", "false", .{}),
            .syncing => |progress| try types.row(
                writer,
                "el_syncing",
                "true (catching up: {d} blocks remaining, {d} done; current={d} highest={d})",
                .{
                    progress.highest_block -| progress.current_block,
                    progress.current_block -| progress.starting_block,
                    progress.current_block,
                    progress.highest_block,
                },
            ),
        },
    }
    try block_row(writer, "unsafe_l2", cl.unsafe_l2);
    try block_row(writer, "safe_l2", cl.safe_l2);
    try block_row(writer, "finalized_l2", cl.finalized_l2);
    try types.row(writer, "safe_lag", "{f} ({d} blocks behind unsafe)", .{
        types.Duration{ .seconds = cl.safe_lag_seconds() },
        cl.safe_lag_blocks(),
    });
    try block_row(writer, "l1_head", cl.head_l1);
    try block_row(writer, "l1_safe", cl.safe_l1);
    try block_row(writer, "l1_finalized", cl.finalized_l1);
    const tip = "unavailable (no independent public RPC configured)";
    try types.row(writer, "tip_reference", tip, .{});
}

fn block_row(writer: *Writer, key: []const u8, ref: BlockRef) !void {
    assert(key.len > 0);
    try types.row(writer, key, "#{d} ts={d} ({f})", .{
        ref.number,
        ref.timestamp,
        types.UnixTime{ .seconds = ref.timestamp },
    });
}

const testing = std.testing;
const hex_11 = "1111111111111111111111111111111111111111111111111111111111111111";
const FakeTransport = @import("fake.zig").FakeTransport;

/// An `optimism_syncStatus` result with unsafe/safe/finalized L2 heads and an L1 head.
pub fn sample_sync_status(
    buffer: []u8,
    unsafe: u64,
    safe: u64,
    finalized: u64,
    l1_head: u64,
) []const u8 {
    assert(unsafe >= safe and safe >= finalized);
    const hash = "\"0x" ++ hex_11 ++ "\"";
    const ref = "{{\"hash\":" ++ hash ++ ",\"number\":{d},\"timestamp\":{d}}}";
    const body = "{{\"current_l1\":" ++ ref ++ ",\"head_l1\":" ++ ref ++ ",\"safe_l1\":" ++ ref ++
        ",\"finalized_l1\":" ++ ref ++ ",\"unsafe_l2\":" ++ ref ++ ",\"safe_l2\":" ++ ref ++
        ",\"finalized_l2\":" ++ ref ++ "}}";
    const base_time: u64 = 1_700_000_000;
    return std.fmt.bufPrint(buffer, body, .{
        l1_head,   base_time + l1_head * 2,
        l1_head,   base_time + l1_head * 2,
        l1_head,   base_time + l1_head * 2,
        l1_head,   base_time + l1_head * 2,
        unsafe,    base_time + unsafe,
        safe,      base_time + safe,
        finalized, base_time + finalized,
    }) catch unreachable; // Proof: callers pass a buffer sized for seven references.
}

test "basectl sync-status: decode and render" {
    var text: [2048]u8 = undefined;
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "optimism_syncStatus", .result = sample_sync_status(&text, 120, 100, 40, 9) },
        .{
            .method = "eth_syncing",
            .result = "{\"startingBlock\":\"0x0\",\"currentBlock\":\"0x64\"," ++
                "\"highestBlock\":\"0x78\"}",
        },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .rollup = .{ .client = &client },
        .l2 = .{ .client = &client },
    };
    const report = fetch(&context).ok;
    try testing.expectEqual(@as(u64, 20), report.cl.safe_lag_blocks());
    try testing.expectEqual(@as(u64, 80), report.cl.finalized_lag_blocks());
    var buffer: [4096]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "el_syncing            true (catching up: " ++
        "20 blocks remaining, 100 done; current=100 highest=120)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "unsafe_l2             #120 ts=1700000120") !=
        null);
    try testing.expect(std.mem.indexOf(u8, out, "safe_lag              20s (20 blocks") != null);
    try testing.expect(std.mem.indexOf(u8, out, "l1_head               #9 ") != null);
}

test "basectl sync-status: required and optional failures" {
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "eth_syncing", .result = "false" },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    var context: types.Context = .{ .l2 = .{ .client = &client } };
    try testing.expectEqual(types.Failure.not_configured, fetch(&context).failed.failure);
    context.rollup.client = &client;
    try testing.expectEqual(types.Failure.unavailable, fetch(&context).failed.failure);
    try testing.expectError(error.MalformedResponse, decode_el_sync(.{ .bool = true }));
    try testing.expectEqual(ElSync.not_syncing, try decode_el_sync(.{ .bool = false }));
}

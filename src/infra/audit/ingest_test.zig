//! Ingest tests: batch shape errors, idempotence across retries, mixed batches, retention
//! admission, and the journal contract.

const std = @import("std");
const testing = std.testing;

const ingest_module = @import("ingest.zig");
const store_module = @import("store.zig");
const time = @import("time.zig");
const segment = @import("segment.zig");

const s = std.time.ns_per_s;
const day_ns = 86_400 * s;
const limits: ingest_module.Limits = .{
    .batch_max = 4,
    .request_bytes_max = 16 * 1024,
    .event = .{ .event_bytes_max = 2048, .data_bytes_max = 512 },
};

const tx_digits = "1111111111111111111111111111111111111111111111111111111111111111";

pub fn line(buffer: []u8, id: []const u8, event_time: []const u8, extra: []const u8) []const u8 {
    return std.fmt.bufPrint(buffer,
        \\{{"schema_version":"transaction-event/v1","event_id":"{s}","event_time":"{s}",
    ++
        \\"producer":"base-builder","event_type":"BUILDER_ACCEPTED","tx_hash":"0x{s}",
    ++
        \\"data":{{"position":1}}{s}}}
    , .{ id, event_time, tx_digits, extra }) catch unreachable;
}

const Harness = struct {
    store: store_module.Store,
    ingest: ingest_module.Ingest,
    now_ns: u64,
    out: [8192]u8 = undefined,
    response: []const u8 = "",
    journal_ok: bool = true,
    journal: [16 * 1024]u8 = undefined,
    journal_size: usize = 0,

    fn init(harness: *Harness) !void {
        harness.* = .{
            .store = try store_module.Store.init(testing.allocator, .{
                .events_max = 16,
                .arena_bytes = 8192,
                .retention_ns = .init(.{
                    .hot = 3 * day_ns,
                    .warm = 7 * day_ns,
                    .cold = 30 * day_ns,
                }),
            }),
            .ingest = undefined,
            .now_ns = try time.parse("2026-11-05T12:00:00Z"),
        };
        harness.ingest = try ingest_module.Ingest.init(testing.allocator, limits);
    }

    fn deinit(harness: *Harness) void {
        harness.ingest.deinit(testing.allocator);
        harness.store.deinit(testing.allocator);
    }

    fn persist(context: *anyopaque, bytes: []const u8) bool {
        const harness: *Harness = @ptrCast(@alignCast(context));
        if (!harness.journal_ok) return false;
        @memcpy(harness.journal[harness.journal_size..][0..bytes.len], bytes);
        harness.journal_size += bytes.len;
        return true;
    }

    fn post(harness: *Harness, body: []const u8) u16 {
        var writer: std.Io.Writer = .fixed(&harness.out);
        const journal: ingest_module.Journal = .{ .context = harness, .persist = persist };
        const outcome = harness.ingest.run(&harness.store, journal, body, harness.now_ns, &writer);
        harness.response = writer.buffered();
        return outcome.http_status;
    }

    fn expect_body(harness: *const Harness, expected: []const u8) !void {
        try testing.expectEqualStrings(expected, harness.response);
    }

    fn expect_contains(harness: *const Harness, needle: []const u8) !void {
        if (std.mem.indexOf(u8, harness.response, needle) == null) {
            std.debug.print("missing {s} in {s}\n", .{ needle, harness.response });
            return error.TestUnexpectedResult;
        }
    }
};

const now_text = "2026-11-05T12:00:00Z";

test "ingest: accepts a valid batch, then reports duplicates on retry" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var a: [512]u8 = undefined;
    var b: [512]u8 = undefined;
    var body: [1200]u8 = undefined;
    const text = try std.fmt.bufPrint(&body, "{s}\n\n{s}\r\n", .{
        line(&a, "event-1", now_text, ""),
        line(&b, "event-2", now_text, ""),
    });
    try testing.expectEqual(@as(u16, 200), harness.post(text));
    try harness.expect_body(
        \\{"status":"accepted","accepted":2,"duplicate":0,"rejected":0,"results":[
    ++
        \\{"event_id":"event-1","status":"accepted"},{"event_id":"event-2","status":"accepted"}]}
    );
    try testing.expectEqual(@as(u32, 2), harness.store.count);
    try testing.expectEqual(@as(u64, 2), harness.ingest.counts.persisted);
    try testing.expectEqual(@as(u16, 200), harness.post(text));
    try harness.expect_body(
        \\{"status":"duplicate","accepted":0,"duplicate":2,"rejected":0,"results":[
    ++
        \\{"event_id":"event-1","status":"duplicate","reason":"duplicate event_id"},
    ++
        \\{"event_id":"event-2","status":"duplicate","reason":"duplicate event_id"}]}
    );
    try testing.expectEqual(@as(u32, 2), harness.store.count);
    // The journal holds exactly the two accepted records.
    var replayed = try store_module.Store.init(testing.allocator, harness.store.options);
    defer replayed.deinit(testing.allocator);
    const result = segment.replay(&replayed, harness.journal[0..harness.journal_size], 1 << 20, 0);
    try testing.expectEqual(@as(u32, 2), result.inserted);
    try testing.expectEqual(@as(u64, harness.journal_size), result.consumed);
}

test "ingest: mixed batch with in-request duplicate and invalid event" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var lines: [4][512]u8 = undefined;
    var body: [2400]u8 = undefined;
    var bad: [512]u8 = undefined;
    const bad_line = line(&bad, "bad-event", now_text, "");
    const index = std.mem.indexOf(u8, bad_line, "0x111").?;
    @memcpy(bad[index + 2 .. index + 5], "zzz");
    const text = try std.fmt.bufPrint(&body, "{s}\n{s}\n{s}", .{
        line(&lines[0], "event-1", now_text, ""),
        line(&lines[1], "event-1", now_text, ""),
        bad_line,
    });
    try testing.expectEqual(@as(u16, 200), harness.post(text));
    try harness.expect_contains("\"status\":\"partial\",\"accepted\":1,\"duplicate\":1,");
    try harness.expect_contains("\"duplicate\":1,\"rejected\":1,");
    try harness.expect_contains("\"reason\":\"duplicate event_id within request\"");
    try harness.expect_contains(
        \\{"event_id":"bad-event","status":"rejected","reason":"invalid transaction event envelope: invalid value for `tx_hash`"}
    );
    try testing.expectEqual(@as(u32, 1), harness.store.count);
}

test "ingest: only invalid events is 422, a journal failure is 503 and stores nothing" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try testing.expectEqual(@as(u16, 422), harness.post("{\"schema_version\":\"x\"}"));
    try harness.expect_contains("\"status\":\"rejected\",\"accepted\":0,\"duplicate\":0,");
    try harness.expect_contains("\"duplicate\":0,\"rejected\":1,");
    try harness.expect_contains("\"event_id\":null");
    harness.journal_ok = false;
    var a: [512]u8 = undefined;
    try testing.expectEqual(@as(u16, 503), harness.post(line(&a, "event-1", now_text, "")));
    try harness.expect_contains("journal unavailable; retry batch");
    try testing.expectEqual(@as(u32, 0), harness.store.count);
    try testing.expectEqual(@as(u64, 1), harness.ingest.counts.journal_failures);
}

test "ingest: batch-level rejections" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try testing.expectEqual(@as(u16, 422), harness.post(" \n\n"));
    try harness.expect_contains("batch must contain at least one event");
    try testing.expectEqual(@as(u16, 400), harness.post("{\"events\":[]}"));
    try harness.expect_contains("unsupported transaction event batch wrapper on line 1");
    try testing.expectEqual(@as(u16, 400), harness.post("{}\n[1]"));
    try harness.expect_contains("invalid NDJSON transaction event on line 2: expected JSON object");
    try testing.expectEqual(@as(u16, 400), harness.post("{}\n{"));
    try harness.expect_contains("on line 2: invalid JSON");
    try testing.expectEqual(@as(u16, 400), harness.post("{}\n{}\n{}\n{}\n{}"));
    try harness.expect_contains("batch size exceeds maximum 4");
    try testing.expectEqual(@as(u16, 400), harness.post("{\"a\":\"\xff\"}"));
    try harness.expect_contains("request body is not UTF-8");
    try testing.expectEqual(@as(u64, 6), harness.ingest.counts.rejected);
    // Exactly the maximum is fine (each `{}` is then rejected individually).
    try testing.expectEqual(@as(u16, 422), harness.post("{}\n{}\n{}\n{}"));
}

test "ingest: retention window and future skew" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var lines: [3][512]u8 = undefined;
    var body: [2000]u8 = undefined;
    const text = try std.fmt.bufPrint(&body, "{s}\n{s}\n{s}", .{
        line(&lines[0], "fresh", now_text, ""),
        // BUILDER_ACCEPTED is hot: 3 days.
        line(&lines[1], "expired", "2026-11-01T12:00:00Z", ""),
        line(&lines[2], "future", "2026-11-05T13:00:00Z", ""),
    });
    try testing.expectEqual(@as(u16, 200), harness.post(text));
    try harness.expect_contains("\"accepted\":1,\"duplicate\":0,\"rejected\":2");
    try harness.expect_contains("event_time is older than the hot retention window");
    try harness.expect_contains("event_time is more than 3600 seconds in the future");
    try testing.expectEqual(@as(u64, 1), harness.ingest.counts.expired);
    try testing.expectEqual(@as(u64, 1), harness.ingest.counts.future);
}

test "ingest: batch status table" {
    const batch_status = ingest_module.batch_status;
    try testing.expectEqual(ingest_module.BatchStatus.accepted, batch_status(2, 0, 0, 2));
    try testing.expectEqual(ingest_module.BatchStatus.duplicate, batch_status(0, 2, 0, 2));
    try testing.expectEqual(ingest_module.BatchStatus.rejected, batch_status(0, 0, 2, 2));
    try testing.expectEqual(ingest_module.BatchStatus.partial, batch_status(1, 1, 0, 2));
    try testing.expectEqual(ingest_module.BatchStatus.partial, batch_status(0, 1, 1, 2));
}

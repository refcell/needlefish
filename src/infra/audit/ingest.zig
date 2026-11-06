//! Vector NDJSON batch ingest (base/base `ingest_transaction_event_batch`), sans IO.
//!
//! One request body holds one `transaction-event/v1` object per line. The batch is checked
//! as a whole first (UTF-8, every non-empty line a JSON object, no `{"events": ...}`
//! wrapper, at most `batch_max` events): any failure rejects the batch with HTTP 400, an
//! empty batch gets 422. Each event is then decoded and validated, admitted against its
//! retention class's window and the future-skew bound, and deduplicated by `event_id`
//! within the request and against the store. New events are encoded as segment records
//! into one batch buffer, handed to the journal (if any) in a single write, and only then
//! inserted into the store, so a journal failure (503) changes nothing.
//!
//! All buffers are allocated in `init` from the configured limits.

const std = @import("std");
const assert = std.debug.assert;

const event_module = @import("event.zig");
const store_module = @import("store.zig");
const segment = @import("segment.zig");
const json = @import("../../utilities/json/root.zig");

/// base/base `DEFAULT_TRANSACTION_EVENT_BATCH_PATH`.
pub const default_path = "/v1/transaction-events/batch";
/// base/base `MAX_TRANSACTION_EVENT_FUTURE_SKEW_SECS`.
pub const future_skew_s: u64 = 3_600;
const reason_size_max = 512;
const message_size_max = 256;
const none: u32 = std.math.maxInt(u32);

pub const Limits = struct {
    /// base/base `DEFAULT_TRANSACTION_EVENT_MAX_BATCH_SIZE` (Vector's `max_events`).
    batch_max: u32 = 1000,
    /// base/base `DEFAULT_TRANSACTION_EVENT_MAX_REQUEST_BYTES`.
    request_bytes_max: u32 = 8 * 1024 * 1024,
    event: event_module.Limits = .{},
};

/// Durable append of whole segment records; returns false if they may not be durable.
pub const Journal = struct {
    context: *anyopaque,
    persist: *const fn (context: *anyopaque, bytes: []const u8) bool,
};

pub const ItemStatus = enum { accepted, duplicate, rejected };
pub const BatchStatus = enum { accepted, partial, duplicate, rejected };

const Item = struct {
    status: ItemStatus,
    has_id: bool,
    id_length: u16,
    reason_length: u16,
};

pub const Counts = struct {
    received: u64 = 0,
    persisted: u64 = 0,
    duplicate: u64 = 0,
    /// Events and whole batches rejected (base/base `transaction_events_rejected`).
    rejected: u64 = 0,
    validation_failures: u64 = 0,
    journal_failures: u64 = 0,
    expired: u64 = 0,
    future: u64 = 0,
};

pub const Outcome = struct {
    http_status: u16,
    /// Number of events in the batch (0 when rejected as a whole).
    events: u32,
};

pub const Ingest = struct {
    limits: Limits,
    scratch: []u8,
    items: []Item,
    ids: []u8,
    reasons: []u8,
    dedupe: []u32,
    batch: []u8,
    batch_size: usize = 0,
    item_count: u32 = 0,
    message: [message_size_max]u8 = undefined,
    message_length: u32 = 0,
    counts: Counts = .{},

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Ingest {
        assert(limits.batch_max > 0 and limits.batch_max < none / 4);
        assert(limits.event.data_bytes_max <= limits.event.event_bytes_max);
        const dedupe_size = std.math.ceilPowerOfTwoAssert(u32, 2 * limits.batch_max);
        const scratch = try allocator.alloc(u8, event_module.scratch_size(limits.event));
        errdefer allocator.free(scratch);
        const items = try allocator.alloc(Item, limits.batch_max);
        errdefer allocator.free(items);
        const id_bytes = @as(usize, limits.batch_max) * event_module.event_id_size_max;
        const ids = try allocator.alloc(u8, id_bytes);
        errdefer allocator.free(ids);
        const reasons = try allocator.alloc(u8, @as(usize, limits.batch_max) * reason_size_max);
        errdefer allocator.free(reasons);
        const dedupe = try allocator.alloc(u32, dedupe_size);
        errdefer allocator.free(dedupe);
        const batch = try allocator.alloc(u8, batch_bytes_max(limits));
        return .{
            .limits = limits,
            .scratch = scratch,
            .items = items,
            .ids = ids,
            .reasons = reasons,
            .dedupe = dedupe,
            .batch = batch,
        };
    }

    pub fn deinit(ingest: *Ingest, allocator: std.mem.Allocator) void {
        allocator.free(ingest.batch);
        allocator.free(ingest.dedupe);
        allocator.free(ingest.reasons);
        allocator.free(ingest.ids);
        allocator.free(ingest.items);
        allocator.free(ingest.scratch);
        ingest.* = undefined;
    }

    /// Encoded bytes of the largest batch: line bytes plus per-record overhead.
    pub fn batch_bytes_max(limits: Limits) usize {
        const overhead = segment.header_size + segment.payload_size_max(0) +
            store_module.record_overhead_bytes;
        return limits.request_bytes_max + @as(usize, limits.batch_max) * overhead;
    }

    /// Processes one request body and writes the JSON response into `out`.
    pub fn run(
        ingest: *Ingest,
        store: *store_module.Store,
        journal: ?Journal,
        body: []const u8,
        now_ns: u64,
        out: *std.Io.Writer,
    ) Outcome {
        assert(body.len <= ingest.limits.request_bytes_max);
        ingest.item_count = 0;
        ingest.batch_size = 0;
        const count = ingest.check_batch(body) orelse {
            ingest.counts.rejected += 1;
            return ingest.write_batch_error(out, 400, 1);
        };
        ingest.counts.received += count;
        if (count == 0) {
            ingest.counts.rejected += 1;
            ingest.set_message("batch must contain at least one event", .{});
            return ingest.write_batch_error(out, 422, 1);
        }
        @memset(ingest.dedupe, none);
        var valid: u32 = 0;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |raw_line| {
            const line = trim_line(raw_line);
            if (line.len == 0) continue;
            valid += @intFromBool(ingest.process(store, line, now_ns));
        }
        assert(ingest.item_count == count);
        if (valid == 0) return ingest.write_results(out, 422, count);
        if (ingest.batch_size > 0) {
            if (journal) |sink| {
                if (!sink.persist(sink.context, ingest.batch[0..ingest.batch_size])) {
                    ingest.counts.journal_failures += 1;
                    ingest.set_message("journal unavailable; retry batch", .{});
                    return ingest.write_batch_error(out, 503, 0);
                }
            }
            const replayed = segment.replay(store, ingest.batch[0..ingest.batch_size], none, 0);
            assert(replayed.consumed == ingest.batch_size and replayed.stop == .incomplete);
            ingest.counts.persisted += replayed.inserted;
        }
        return ingest.write_results(out, 200, count);
    }

    /// The batch-level checks; returns the event count, or null with `message` set.
    fn check_batch(ingest: *Ingest, body: []const u8) ?u32 {
        if (!std.unicode.utf8ValidateSlice(body)) {
            ingest.set_message("request body is not UTF-8", .{});
            return null;
        }
        var count: u32 = 0;
        var line_number: u32 = 0;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |raw_line| {
            line_number += 1;
            const line = trim_line(raw_line);
            if (line.len == 0) continue;
            if (count >= ingest.limits.batch_max) {
                ingest.set_message("batch size exceeds maximum {d}", .{ingest.limits.batch_max});
                return null;
            }
            const problem = line_problem(line) orelse {
                count += 1;
                continue;
            };
            ingest.set_message("{s} on line {d}{s}", .{ problem[0], line_number, problem[1] });
            return null;
        }
        assert(count <= ingest.limits.batch_max);
        return count;
    }

    fn line_problem(line: []const u8) ?struct { []const u8, []const u8 } {
        assert(line.len > 0);
        const invalid = "invalid NDJSON transaction event";
        json.validate(line) catch return .{ invalid, ": invalid JSON" };
        if (line[0] != '{') return .{ invalid, ": expected JSON object" };
        const events = json.find_path(line, &.{"events"}) catch unreachable; // Validated.
        const version = json.find_path(line, &.{"schema_version"}) catch unreachable;
        if (events != null and version == null) {
            return .{
                "unsupported transaction event batch wrapper",
                "; send one event JSON object per line",
            };
        }
        return null;
    }

    fn set_message(ingest: *Ingest, comptime format: []const u8, args: anytype) void {
        const text = std.fmt.bufPrint(&ingest.message, format, args) catch
            ingest.message[0..message_size_max];
        ingest.message_length = @intCast(text.len);
        assert(ingest.message_length <= message_size_max);
    }

    /// Decodes, admits, and deduplicates one line; returns whether it is valid (new or a
    /// store duplicate), as base/base's `valid_events`.
    fn process(ingest: *Ingest, store: *store_module.Store, line: []const u8, now_ns: u64) bool {
        const index = ingest.item_count;
        assert(index < ingest.items.len);
        ingest.item_count += 1;
        const decoded = event_module.decode(line, ingest.limits.event, ingest.scratch);
        const value = switch (decoded) {
            .rejected => |rejection| {
                const id = event_module.find_event_id(line, ingest.id_slot(index));
                ingest.reject(index, id, rejection);
                return false;
            },
            .event => |value| value,
        };
        if (admit(value, store, now_ns)) |rejection| {
            if (rejection.reason == .expired) ingest.counts.expired += 1;
            if (rejection.reason == .future) ingest.counts.future += 1;
            ingest.reject(index, value.event_id, rejection);
            return false;
        }
        ingest.set_item(index, .duplicate, value.event_id);
        if (ingest.seen_in_request(index)) {
            ingest.counts.duplicate += 1;
            ingest.items[index].reason_length = ingest.write_reason(index, "{s}", .{
                "duplicate event_id within request",
            });
            return false;
        }
        if (store.find_event_id(value.event_id) != null) {
            ingest.counts.duplicate += 1;
            const reason = ingest.write_reason(index, "duplicate event_id", .{});
            ingest.items[index].reason_length = reason;
            return true;
        }
        const record: store_module.Record = .{ .event = value, .ingested_at_ns = now_ns };
        assert(store_module.Store.record_size(&record) <= store.arena.len);
        const encoded = segment.encode(&record, ingest.batch[ingest.batch_size..]);
        ingest.batch_size += encoded.len;
        ingest.items[index].status = .accepted;
        return true;
    }

    fn admit(
        value: event_module.Event,
        store: *const store_module.Store,
        now_ns: u64,
    ) ?event_module.Rejection {
        const class = value.event_type.retention_class();
        const window_ns = store.options.retention_ns.get(class);
        if (value.event_time_ns < now_ns -| window_ns) {
            return .{ .reason = .expired, .text = @tagName(class) };
        }
        if (value.event_time_ns >= now_ns +| future_skew_s * std.time.ns_per_s) {
            return .{ .reason = .future, .limit = future_skew_s };
        }
        return null;
    }

    fn reject(
        ingest: *Ingest,
        index: u32,
        id: ?[]const u8,
        rejection: event_module.Rejection,
    ) void {
        ingest.counts.rejected += 1;
        ingest.counts.validation_failures += 1;
        const fits = if (id) |text| text.len <= event_module.event_id_size_max else false;
        ingest.set_item(index, .rejected, if (fits) id else null);
        var writer: std.Io.Writer = .fixed(ingest.reason_slot(index));
        rejection.write(&writer) catch {}; // Truncated messages are still useful.
        ingest.items[index].reason_length = @intCast(writer.end);
        assert(ingest.items[index].status == .rejected);
    }

    fn set_item(ingest: *Ingest, index: u32, status: ItemStatus, id: ?[]const u8) void {
        assert(index < ingest.item_count);
        const slot = ingest.id_slot(index);
        var length: u16 = 0;
        if (id) |text| {
            assert(text.len <= slot.len);
            // `text` may already live in this slot (rejected ids are unescaped into it).
            if (text.ptr != slot.ptr) std.mem.copyForwards(u8, slot[0..text.len], text);
            length = @intCast(text.len);
        }
        ingest.items[index] = .{
            .status = status,
            .has_id = id != null,
            .id_length = length,
            .reason_length = 0,
        };
    }

    fn id_slot(ingest: *Ingest, index: u32) []u8 {
        const size = event_module.event_id_size_max;
        return ingest.ids[@as(usize, index) * size ..][0..size];
    }

    fn reason_slot(ingest: *Ingest, index: u32) []u8 {
        return ingest.reasons[@as(usize, index) * reason_size_max ..][0..reason_size_max];
    }

    fn write_reason(ingest: *Ingest, index: u32, comptime format: []const u8, args: anytype) u16 {
        const text = std.fmt.bufPrint(ingest.reason_slot(index), format, args) catch unreachable;
        assert(text.len <= reason_size_max);
        return @intCast(text.len);
    }

    /// Inserts item `index`'s event id into the request table; true if already there.
    fn seen_in_request(ingest: *Ingest, index: u32) bool {
        const id = ingest.id_slot(index)[0..ingest.items[index].id_length];
        const mask: u32 = @intCast(ingest.dedupe.len - 1);
        var position: u32 = @truncate(std.hash.Wyhash.hash(0, id) & mask);
        var probes: u32 = 0;
        while (probes < ingest.dedupe.len) : (probes += 1) {
            const other = ingest.dedupe[position];
            if (other == none) {
                ingest.dedupe[position] = index;
                return false;
            }
            const other_id = ingest.id_slot(other)[0..ingest.items[other].id_length];
            if (std.mem.eql(u8, other_id, id)) return true;
            position = (position + 1) & mask;
        }
        unreachable; // The table has at least twice as many entries as a batch has events.
    }

    fn write_batch_error(ingest: *Ingest, out: *std.Io.Writer, status: u16, rejected: u32) Outcome {
        assert(status >= 400);
        assert(rejected <= 1);
        var writer = json.Writer.init(out);
        write_batch_error_body(&writer, ingest.message[0..ingest.message_length], rejected) catch
            return .{ .http_status = 500, .events = 0 };
        return .{ .http_status = status, .events = 0 };
    }

    fn write_results(ingest: *Ingest, out: *std.Io.Writer, status: u16, count: u32) Outcome {
        assert(count == ingest.item_count);
        var tally: [3]u32 = @splat(0);
        for (ingest.items[0..count]) |item| tally[@backingInt(item.status)] += 1;
        const accepted = tally[@backingInt(ItemStatus.accepted)];
        const duplicate = tally[@backingInt(ItemStatus.duplicate)];
        const rejected = tally[@backingInt(ItemStatus.rejected)];
        var writer = json.Writer.init(out);
        ingest.write_results_body(&writer, accepted, duplicate, rejected) catch
            return .{ .http_status = 500, .events = count };
        return .{ .http_status = status, .events = count };
    }

    fn write_results_body(
        ingest: *Ingest,
        writer: *json.Writer,
        accepted: u32,
        duplicate: u32,
        rejected: u32,
    ) json.Writer.WriteError!void {
        try write_counts(writer, batch_status(accepted, duplicate, rejected, ingest.item_count), .{
            accepted, duplicate, rejected,
        });
        try writer.key("results");
        try writer.begin_array();
        for (ingest.items[0..ingest.item_count], 0..) |item, index| {
            const id = ingest.id_slot(@intCast(index))[0..item.id_length];
            const reason = ingest.reason_slot(@intCast(index))[0..item.reason_length];
            try write_item(writer, if (item.has_id) id else null, item.status, reason);
        }
        try writer.end_array();
        try writer.end_object();
    }
};

/// base/base `response_from_results`.
pub fn batch_status(accepted: u32, duplicate: u32, rejected: u32, total: u32) BatchStatus {
    assert(accepted + duplicate + rejected <= total);
    if (accepted == 0 and duplicate == 0) return .rejected;
    if (accepted == 0 and rejected == 0) return .duplicate;
    if (duplicate == 0 and rejected == 0 and accepted == total) return .accepted;
    return .partial;
}

fn write_counts(
    writer: *json.Writer,
    status: BatchStatus,
    counts: [3]u32,
) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("status");
    try writer.string(@tagName(status));
    for ([_][]const u8{ "accepted", "duplicate", "rejected" }, counts) |name, value| {
        try writer.key(name);
        try writer.integer(value);
    }
}

fn write_item(
    writer: *json.Writer,
    id: ?[]const u8,
    status: ItemStatus,
    reason: []const u8,
) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("event_id");
    if (id) |text| try writer.string(text) else try writer.null_value();
    try writer.key("status");
    try writer.string(@tagName(status));
    if (reason.len > 0) {
        try writer.key("reason");
        try writer.string(reason);
    }
    try writer.end_object();
}

fn write_batch_error_body(
    writer: *json.Writer,
    message: []const u8,
    rejected: u32,
) json.Writer.WriteError!void {
    assert(message.len > 0);
    try write_counts(writer, .rejected, .{ 0, 0, rejected });
    try writer.key("results");
    try writer.begin_array();
    try write_item(writer, null, .rejected, message);
    try writer.end_array();
    try writer.end_object();
}

/// Rust's `str::lines` drops a trailing `\r`; base/base then trims whitespace.
fn trim_line(line: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, line, " \t\r\n\x0b\x0c");
    assert(trimmed.len <= line.len);
    return trimmed;
}

test {
    _ = @import("ingest_test.zig");
}

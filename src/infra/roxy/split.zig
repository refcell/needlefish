//! Batch splitting for roxy (proxyd `rpc_method_mappings` with batches): a batch whose
//! methods are routed to upstreams with no upstream in common is split into one sub-batch
//! ("part") per group of entries that can share an upstream. Each part is proxied as its own
//! request (the proxy's slots, pool, and retries); when every part has completed, the parts'
//! responses are matched to the entries by `id` and written back as one JSON array in the
//! original order. A part that fails yields a JSON-RPC error per entry, keeping its id.
//!
//! A `Split` owns fixed buffers sized at startup: the part request bodies (at most the
//! original body plus brackets, commas, and tag rewrites) and an arena for the part
//! responses (their sum is bounded by one upstream response). No allocation after `init`.

const std = @import("std");
const assert = std.debug.assert;

const http = @import("../../utilities/http/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const methods = @import("methods.zig");
const pool = @import("pool.zig");
const routes = @import("routes.zig");
const tags = @import("tags.zig");

pub const Mask = pool.Mask;
pub const batch_max = methods.batch_max;
/// Every part is created by an entry whose route mask no earlier part intersects; there are
/// at most `rules_max` route masks plus "any upstream".
pub const parts_max = routes.rules_max + 1;

/// Bytes the part bodies may add to the original body.
pub const request_overhead_max = 2 * parts_max + batch_max * tags.replacement_size_max;
/// Upper bound of one error entry written for a failed part, id excluded.
const error_size_max = 160;

/// Groups entries first-fit: an entry joins the first part whose (narrowed) mask intersects
/// its own. Returns the number of parts; one part means no split is needed.
pub fn assign(entry_masks: []const Mask, entry_part: []u8, part_masks: *[parts_max]Mask) u32 {
    assert(entry_masks.len > 0 and entry_masks.len <= batch_max);
    assert(entry_part.len >= entry_masks.len);
    var count: u32 = 0;
    for (entry_masks, 0..) |mask, entry| {
        assert(mask != 0);
        const part = for (part_masks[0..count], 0..) |part_mask, index| {
            if (part_mask & mask != 0) break index;
        } else part: {
            assert(count < parts_max); // See `parts_max`.
            part_masks[count] = mask;
            count += 1;
            break :part count - 1;
        };
        part_masks[part] &= mask;
        entry_part[entry] = @intCast(part);
    }
    assert(count >= 1 and count <= parts_max);
    return count;
}

pub const Outcome = enum {
    pending,
    ok,
    /// Every attempt failed in transport (or no upstream could be selected).
    unavailable,
    request_too_large,
    response_too_large,
    /// The upstream answered with a non-200 status (`Part.status`).
    http_status,
};

pub const Part = struct {
    mask: Mask = 0,
    outcome: Outcome = .pending,
    status: u16 = 0,
    /// The part's request body in `request_buffer`.
    body_start: u32 = 0,
    body_end: u32 = 0,
    /// The part's response body in `arena`.
    response_start: u32 = 0,
    response_end: u32 = 0,
    /// Highest block height any of its entries needs (consensus tags).
    height: u64 = 0,
};

pub const Split = struct {
    active: bool = false,
    token: http.Deferred = undefined,
    entries_count: u32 = 0,
    parts_count: u32 = 0,
    /// Parts whose slot has not been released yet.
    parts_open: u32 = 0,
    entry_part: [batch_max]u8 = undefined,
    /// Raw ids; point into the server's receive buffer (valid while `token` is).
    entry_id: [batch_max][]const u8 = undefined,
    entry_response: [batch_max]?[]const u8 = undefined,
    parts: [parts_max]Part = undefined,
    request_buffer: []u8,
    arena: []u8,
    arena_used: u32 = 0,

    pub fn part_body(split: *const Split, part: u32) []const u8 {
        assert(split.active and part < split.parts_count);
        const entry = &split.parts[part];
        return split.request_buffer[entry.body_start..entry.body_end];
    }

    /// Fills the split from a body already grouped by `assign`: builds one sub-batch body per
    /// part (applying `plans` with `head`), and remembers ids for reassembly.
    pub fn begin(
        split: *Split,
        token: http.Deferred,
        body: []const u8,
        entries: []const methods.Entry,
        plans: []const tags.Plan,
        head: u64,
        part_masks: []const Mask,
    ) error{WriteFailed}!void {
        assert(!split.active and entries.len == plans.len);
        assert(part_masks.len >= 2 and part_masks.len <= parts_max);
        split.active = true;
        split.token = token;
        split.entries_count = @intCast(entries.len);
        split.parts_count = @intCast(part_masks.len);
        split.parts_open = split.parts_count;
        split.arena_used = 0;
        for (entries, 0..) |*entry, index| {
            split.entry_id[index] = entry.id;
            split.entry_response[index] = null;
        }
        var writer: std.Io.Writer = .fixed(split.request_buffer);
        for (part_masks, 0..) |mask, part| {
            const start: u32 = @intCast(writer.end);
            var height: u64 = 0;
            try writer.writeByte('[');
            var written: u32 = 0;
            for (entries, plans, 0..) |*entry, plan, index| {
                if (split.entry_part[index] != part) continue;
                if (written > 0) try writer.writeByte(',');
                try tags.copy(&writer, body, entry.start, entry.end, plan, head);
                height = @max(height, plan.height);
                written += 1;
            }
            try writer.writeByte(']');
            assert(written > 0);
            split.parts[part] = .{
                .mask = mask,
                .body_start = start,
                .body_end = @intCast(writer.end),
                .height = height,
            };
        }
    }

    /// Records a part's upstream response (copied: the client reuses its buffer).
    pub fn record_response(split: *Split, part: u32, status: u16, body: []const u8) void {
        assert(split.active and part < split.parts_count);
        const entry = &split.parts[part];
        assert(entry.outcome == .pending);
        if (status != 200) {
            entry.outcome = .http_status;
            entry.status = status;
            return;
        }
        if (body.len > split.arena.len - split.arena_used) {
            entry.outcome = .response_too_large;
            return;
        }
        entry.response_start = split.arena_used;
        @memcpy(split.arena[split.arena_used..][0..body.len], body);
        split.arena_used += @intCast(body.len);
        entry.response_end = split.arena_used;
        entry.outcome = .ok;
        assert(split.arena_used <= split.arena.len);
    }

    pub fn record_failure(split: *Split, part: u32, outcome: Outcome) void {
        assert(split.active and part < split.parts_count);
        assert(outcome != .ok and outcome != .pending and outcome != .http_status);
        assert(split.parts[part].outcome == .pending);
        split.parts[part].outcome = outcome;
    }

    /// Releases one part; returns true when it was the last one.
    pub fn close_part(split: *Split) bool {
        assert(split.active and split.parts_open > 0);
        split.parts_open -= 1;
        return split.parts_open == 0;
    }

    pub fn release(split: *Split) void {
        assert(split.active and split.parts_open == 0);
        split.active = false;
    }

    /// `http.Server.resume_deferred` writer: the reassembled batch response.
    pub fn write(split: *Split, builder: *http.ResponseBuilder) void {
        assert(split.active and split.parts_open == 0);
        for (0..split.parts_count) |part| {
            if (split.parts[part].outcome == .ok) split.match(@intCast(part));
        }
        builder.status = 200;
        const out = builder.writer();
        const estimate = split.arena_used + split.entries_count * error_size_max + 2;
        out.ensureUnusedCapacity(estimate) catch return builder.fail(502);
        split.write_entries(out) catch return builder.fail(502);
    }

    fn write_entries(split: *const Split, out: *std.Io.Writer) std.Io.Writer.Error!void {
        assert(split.entries_count > 0);
        try out.writeByte('[');
        for (0..split.entries_count) |index| {
            if (index > 0) try out.writeByte(',');
            if (split.entry_response[index]) |response| {
                try out.writeAll(response);
                continue;
            }
            const part = &split.parts[split.entry_part[index]];
            var buffer: [48]u8 = undefined;
            const message = switch (part.outcome) {
                .pending, .unavailable => "no upstream available",
                .request_too_large => "request too large",
                .response_too_large => "upstream response too large",
                .http_status => std.fmt.bufPrint(&buffer, "upstream answered HTTP {d}", .{
                    part.status,
                }) catch unreachable, // At most 28 bytes.
                .ok => "upstream response has no entry with this id",
            };
            const code = rpc.code.internal_error;
            try methods.write_error(out, split.entry_id[index], code, message);
        }
        try out.writeByte(']');
    }

    /// Matches the elements of a part's response array to its entries by raw id text, each
    /// element to the first unmatched entry with that id. A response that is not an array
    /// matches nothing (every entry then gets an error).
    fn match(split: *Split, part: u32) void {
        const entry = &split.parts[part];
        assert(entry.outcome == .ok);
        const response = split.arena[entry.response_start..entry.response_end];
        var scanner = json.Scanner.init(response);
        const first = scanner.next() catch return;
        if (first.tag != .array_begin) return;
        var elements: u32 = 0;
        while (elements <= response.len) : (elements += 1) {
            const token = scanner.next() catch return;
            if (token.tag == .array_end) return;
            const start = scanner.index - 1;
            scanner.skip(token) catch return;
            if (token.tag != .object_begin) continue;
            const element = response[start..scanner.index];
            assert(element[0] == '{' and element[element.len - 1] == '}');
            const found = json.find_path(element, &.{"id"}) catch continue;
            split.match_id(part, found orelse continue, element);
        }
    }

    fn match_id(split: *Split, part: u32, id: []const u8, element: []const u8) void {
        assert(id.len > 0 and element.len > 0);
        for (0..split.entries_count) |index| {
            if (split.entry_part[index] != part) continue;
            if (split.entry_response[index] != null) continue;
            if (!std.mem.eql(u8, split.entry_id[index], id)) continue;
            split.entry_response[index] = element;
            return;
        }
    }
};

const testing = std.testing;

test "split: first-fit assignment narrows masks" {
    var entry_part: [batch_max]u8 = undefined;
    var part_masks: [parts_max]Mask = undefined;
    const masks = [_]Mask{ 0b100, 0b001, 0b111, 0b100, 0b011 };
    const count = assign(&masks, &entry_part, &part_masks);
    try testing.expectEqual(@as(u32, 2), count);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 0, 0, 1 }, entry_part[0..5]);
    try testing.expectEqualSlices(Mask, &.{ 0b100, 0b001 }, part_masks[0..2]);
    const shared = [_]Mask{ 0b011, 0b110, 0b111 };
    try testing.expectEqual(@as(u32, 1), assign(&shared, &entry_part, &part_masks));
    try testing.expectEqual(@as(Mask, 0b010), part_masks[0]);
}

fn test_split(request_buffer: []u8, arena: []u8, body: []const u8) !Split {
    var entries: [batch_max]methods.Entry = undefined;
    const summary = try methods.extract(body, &entries);
    var split: Split = .{ .request_buffer = request_buffer, .arena = arena };
    const masks = [_]Mask{ 0b01, 0b10, 0b01 };
    var part_masks: [parts_max]Mask = undefined;
    const count = assign(masks[0..summary.count], &split.entry_part, &part_masks);
    var plans: [batch_max]tags.Plan = @splat(.{});
    const token: http.Deferred = .{ .index = 0, .generation = 0 };
    const entries_used = entries[0..summary.count];
    try split.begin(token, body, entries_used, plans[0..summary.count], 0, part_masks[0..count]);
    return split;
}

test "split: parts, ordered reassembly by id, and per-entry errors" {
    var request_buffer: [512]u8 = undefined;
    var arena: [512]u8 = undefined;
    const body = "[{\"id\":1,\"method\":\"a\"}, {\"id\":\"x\",\"method\":\"b\"}," ++
        "{\"id\":3,\"method\":\"a\"}]";
    var split = try test_split(&request_buffer, &arena, body);
    try testing.expectEqual(@as(u32, 2), split.parts_count);
    try testing.expectEqualStrings(
        "[{\"id\":1,\"method\":\"a\"},{\"id\":3,\"method\":\"a\"}]",
        split.part_body(0),
    );
    try testing.expectEqualStrings("[{\"id\":\"x\",\"method\":\"b\"}]", split.part_body(1));
    // Part 0 answers out of order; part 1 fails.
    split.record_response(0, 200, "[{\"id\":3,\"result\":\"c\"}, {\"id\":1,\"result\":\"a\"}]");
    split.record_response(1, 503, "busy");
    try testing.expect(!split.close_part());
    try testing.expect(split.close_part());
    var buffer: [4096]u8 = undefined;
    var builder = http.ResponseBuilder.init(&buffer);
    split.write(&builder);
    try testing.expectEqualStrings(
        "[{\"id\":1,\"result\":\"a\"},{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":" ++
            "-32603,\"message\":\"upstream answered HTTP 503\"}},{\"id\":3,\"result\":\"c\"}]",
        builder.body.buffered(),
    );
    split.release();
    try testing.expect(!split.active);
}

test "split: a missing id and an oversized response become errors" {
    var request_buffer: [512]u8 = undefined;
    var arena: [40]u8 = undefined;
    const body = "[{\"id\":1,\"method\":\"a\"},{\"id\":2,\"method\":\"b\"}," ++
        "{\"id\":3,\"method\":\"a\"}]";
    var split = try test_split(&request_buffer, &arena, body);
    split.record_response(0, 200, "[{\"id\":1,\"result\":\"a\"}]");
    split.record_response(1, 200, "[{\"id\":2,\"result\":\"this does not fit the arena\"}]");
    try testing.expectEqual(Outcome.response_too_large, split.parts[1].outcome);
    _ = split.close_part();
    _ = split.close_part();
    var buffer: [4096]u8 = undefined;
    var builder = http.ResponseBuilder.init(&buffer);
    split.write(&builder);
    const text = builder.body.buffered();
    try testing.expect(std.mem.startsWith(u8, text, "[{\"id\":1,\"result\":\"a\"},"));
    try testing.expect(std.mem.indexOf(u8, text, "upstream response too large") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"id\":3,\"error\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no entry with this id") != null);
    try json.validate(text);
}

/// Never crashes on arbitrary part responses; the output is a valid JSON array.
fn check_responses(first: []const u8, second: []const u8) !void {
    var request_buffer: [512]u8 = undefined;
    var arena: [2048]u8 = undefined;
    const body = "[{\"id\":1,\"method\":\"a\"},{\"id\":2,\"method\":\"b\"}," ++
        "{\"id\":1,\"method\":\"a\"}]";
    var split = try test_split(&request_buffer, &arena, body);
    split.record_response(0, 200, first);
    split.record_response(1, 200, second);
    _ = split.close_part();
    _ = split.close_part();
    var buffer: [16384]u8 = undefined;
    var builder = http.ResponseBuilder.init(&buffer);
    split.write(&builder);
    if (builder.status != 200) return;
    const text = builder.body.buffered();
    try testing.expect(text[0] == '[' and text[text.len - 1] == ']');
}

test "split: seeded fuzz of part responses" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x5917);
    const pieces = [_][]const u8{
        "[", "]", "{", "}", ",", ":", "\"id\"", "1", "2", "\"result\"", "null", " ",
    };
    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    for (0..3000) |_| {
        var a: std.Io.Writer = .fixed(&first);
        var b: std.Io.Writer = .fixed(&second);
        for (0..prng.below(30)) |_| a.writeAll(pieces[prng.below(pieces.len)]) catch break;
        for (0..prng.below(30)) |_| b.writeAll(pieces[prng.below(pieces.len)]) catch break;
        try check_responses(a.buffered(), b.buffered());
    }
}

fn fuzz_responses(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [1024]u8 = undefined;
    const size = smith.slice(&input);
    try check_responses(input[0..size], input[0 .. size / 2]);
}

test "split: fuzz part responses" {
    try testing.fuzz({}, fuzz_responses, .{});
}

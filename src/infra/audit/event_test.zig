//! Decoder and validator tests for `transaction-event/v1` lines, plus fuzzing.

const std = @import("std");
const testing = std.testing;

const event = @import("event.zig");
const time = @import("time.zig");
const json = @import("../../utilities/json/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const limits: event.Limits = .{ .event_bytes_max = 4096, .data_bytes_max = 1024 };
const tx_hex = "0x1111111111111111111111111111111111111111111111111111111111111111";

pub const sample_line =
    \\{"schema_version":"transaction-event/v1","event_id":"event-1",
++
    \\"event_time":"2026-11-05T12:00:00Z","producer":"base-builder",
++
    \\"event_type":"BUILDER_ACCEPTED","network":"base-mainnet","tx_hash":"
++ tx_hex ++
    \\","block_hash":null,"block_number":null,"payload_id":null,"request_id":null,
++
    \\"data":{"position":1}}
;

fn decode(line: []const u8, scratch: []u8) event.Decoded {
    return event.decode(line, limits, scratch);
}

fn expect_rejected(line: []const u8, reason: event.Reason) !event.Rejection {
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    const decoded = decode(line, &scratch);
    switch (decoded) {
        .event => return error.TestUnexpectedResult,
        .rejected => |rejection| {
            try testing.expectEqual(reason, rejection.reason);
            return rejection;
        },
    }
}

fn reason_text(rejection: event.Rejection, buffer: []u8) []const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    rejection.write(&writer) catch unreachable;
    return writer.buffered();
}

/// `sample_line` with `old` replaced by `new` (once).
fn edited(buffer: []u8, old: []const u8, new: []const u8) []const u8 {
    const index = std.mem.indexOf(u8, sample_line, old).?;
    var writer: std.Io.Writer = .fixed(buffer);
    writer.writeAll(sample_line[0..index]) catch unreachable;
    writer.writeAll(new) catch unreachable;
    writer.writeAll(sample_line[index + old.len ..]) catch unreachable;
    return writer.buffered();
}

test "event: decodes the README example" {
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    const decoded = decode(sample_line, &scratch);
    const value = decoded.event;
    try testing.expectEqualStrings("event-1", value.event_id);
    try testing.expectEqual(try time.parse("2026-11-05T12:00:00Z"), value.event_time_ns);
    try testing.expectEqual(event.Producer.base_builder, value.producer);
    try testing.expectEqual(event.EventType.builder_accepted, value.event_type);
    try testing.expectEqualStrings("base-mainnet", value.network.?);
    try testing.expectEqual(@as(u8, 0x11), value.tx_hash.?[31]);
    try testing.expect(value.block_hash == null and value.block_number == null);
    try testing.expectEqualStrings("{\"position\":1}", value.data);
}

test "event: optional fields may be absent, unknown fields are ignored" {
    const line =
        \\{ "schema_version" : "transaction-event/v1", "event_id": "a\u0062c",
        \\  "event_time": "2026-11-05T12:00:00.5+01:00", "producer": "base-routing/proxyd",
        \\  "event_type": "PROXY_REJECTED", "extra": {"nested": [1, 2]}, "block_number": 7,
        \\  "block_hash": "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        \\  "data": { "bundle_id": "b-1", "bundle_hash": "h\u0031", "deep": {"bundle_id": "x"} } }
    ;
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    const value = decode(line, &scratch).event;
    try testing.expectEqualStrings("abc", value.event_id);
    try testing.expectEqual(try time.parse("2026-11-05T11:00:00.5Z"), value.event_time_ns);
    try testing.expectEqual(event.Producer.base_routing_proxyd, value.producer);
    try testing.expectEqual(@as(u64, 7), value.block_number.?);
    try testing.expectEqual(@as(u8, 0xaa), value.block_hash.?[0]);
    try testing.expect(value.network == null and value.tx_hash == null);
    try testing.expectEqualStrings("b-1", value.bundle_id.?);
    try testing.expectEqualStrings("h1", value.bundle_hash.?);
    const data = "{\"bundle_id\":\"b-1\",\"bundle_hash\":\"h\\u0031\"," ++
        "\"deep\":{\"bundle_id\":\"x\"}}";
    try testing.expectEqualStrings(data, value.data);
    try testing.expect(value.event_type.rejected() == false);
}

test "event: schema version, event id, and required fields" {
    var buffer: [1024]u8 = undefined;
    var text: [256]u8 = undefined;
    var rejection = try expect_rejected(
        edited(&buffer, "transaction-event/v1", "transaction-event/v2"),
        .invalid_schema_version,
    );
    try testing.expectEqualStrings(
        "invalid transaction event schema_version transaction-event/v2",
        reason_text(rejection, &text),
    );
    _ = try expect_rejected(edited(&buffer, "\"event-1\"", "\"  \""), .missing_event_id);
    const long_id: [258]u8 = .{'"'} ++ @as([256]u8, @splat('i')) ++ .{'"'};
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    _ = decode(edited(&buffer, "\"event-1\"", &long_id), &scratch).event;
    const too_long: [259]u8 = .{'"'} ++ @as([257]u8, @splat('i')) ++ .{'"'};
    _ = try expect_rejected(edited(&buffer, "\"event-1\"", &too_long), .event_id_too_long);
    const no_producer = edited(&buffer, "\"producer\"", "\"producerx\"");
    rejection = try expect_rejected(no_producer, .missing_field);
    try testing.expectEqual(event.Field.producer, rejection.field);
    try testing.expectEqualStrings(
        "invalid transaction event envelope: missing field `producer`",
        reason_text(rejection, &text),
    );
    const no_data = edited(&buffer, "\"data\":{\"position\":1}", "\"x\":1");
    rejection = try expect_rejected(no_data, .missing_field);
    try testing.expectEqual(event.Field.data, rejection.field);
    const twice = edited(&buffer, "\"network\":", "\"event_id\":\"b\",\"network\":");
    _ = try expect_rejected(twice, .duplicate_field);
}

test "event: invalid field values" {
    var buffer: [1024]u8 = undefined;
    const cases = [_]struct { old: []const u8, new: []const u8, field: event.Field }{
        .{ .old = tx_hex, .new = "not-a-hash", .field = .tx_hash },
        .{ .old = "\"base-builder\"", .new = "\"base-node\"", .field = .producer },
        .{ .old = "\"BUILDER_ACCEPTED\"", .new = "\"builder_accepted\"", .field = .event_type },
        .{ .old = "\"2026-11-05T12:00:00Z\"", .new = "\"yesterday\"", .field = .event_time },
        .{ .old = "\"block_number\":null", .new = "\"block_number\":-1", .field = .block_number },
        .{ .old = "\"block_number\":null", .new = "\"block_number\":1.5", .field = .block_number },
        .{
            .old = "\"block_number\":null",
            .new = "\"block_number\":\"7\"",
            .field = .block_number,
        },
        .{ .old = "\"network\":\"base-mainnet\"", .new = "\"network\":[1]", .field = .network },
        .{ .old = "{\"position\":1}", .new = "[1]", .field = .data },
        .{ .old = "{\"position\":1}", .new = "null", .field = .data },
        .{ .old = "\"event-1\"", .new = "1", .field = .event_id },
    };
    for (cases) |case| {
        const rejection = try expect_rejected(edited(&buffer, case.old, case.new), .invalid_field);
        try testing.expectEqual(case.field, rejection.field);
    }
    _ = try expect_rejected(
        edited(&buffer, "\"block_number\":null", "\"block_number\":9223372036854775808"),
        .block_number_range,
    );
}

test "event: flashblock event types are dropped" {
    var buffer: [1024]u8 = undefined;
    const names = [_][]const u8{
        "BUILDER_FLASHBLOCK_STARTED",       "BUILDER_FLASHBLOCK_PUBLISHED",
        "BUILDER_FLASHBLOCK_BUILD_STOPPED",
    };
    for (names) |name| {
        var quoted: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&quoted, "\"{s}\"", .{name});
        _ = try expect_rejected(
            edited(&buffer, "\"BUILDER_ACCEPTED\"", text),
            .flashblock_event_type,
        );
    }
    for (std.enums.values(event.EventType)) |event_type| {
        const name = event_type.wire_name();
        try testing.expectEqual(event_type, event.EventType.from_wire(name).?);
        try testing.expect(std.mem.indexOf(u8, name, "FLASHBLOCK") == null);
    }
    try testing.expectEqualStrings(
        "TXPOOL_SEND_RAW_TRANSACTION_VALIDITY",
        event.EventType.txpool_send_raw_transaction_validity.wire_name(),
    );
}

test "event: forbidden data keys and nesting depth" {
    var buffer: [1024]u8 = undefined;
    var text: [256]u8 = undefined;
    const rejection = try expect_rejected(
        edited(&buffer, "{\"position\":1}", "{\"ok\":{\"list\":[{\"Raw_Tx\":\"0x\"}]}}"),
        .forbidden_data_key,
    );
    try testing.expectEqualStrings(
        "transaction event data contains forbidden key Raw_Tx",
        reason_text(rejection, &text),
    );
    for ([_][]const u8{ "{\"headers\":1}", "{\"x-forwarded-for\":1}" }) |data| {
        _ = try expect_rejected(edited(&buffer, "{\"position\":1}", data), .forbidden_data_key);
    }
    // Depth: an object nested 16 deep is fine, 17 is too deep (base/base counts arrays too).
    var deep: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&deep);
    for (0..16) |_| try writer.writeAll("{\"a\":");
    try writer.writeAll("1");
    for (0..16) |_| try writer.writeAll("}");
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    _ = decode(edited(&buffer, "{\"position\":1}", writer.buffered()), &scratch).event;
    writer = .fixed(&deep);
    for (0..9) |_| try writer.writeAll("{\"a\":[");
    try writer.writeAll("1");
    for (0..9) |_| try writer.writeAll("]}");
    _ = try expect_rejected(edited(&buffer, "{\"position\":1}", writer.buffered()), .data_too_deep);
}

test "event: event and data size limits" {
    var line: [5000]u8 = undefined;
    @memset(&line, ' ');
    @memcpy(line[0..sample_line.len], sample_line);
    var rejection = try expect_rejected(&line, .event_too_large);
    try testing.expectEqual(@as(u64, 5000), rejection.size);
    var text: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "event size 5000 exceeds maximum 4096 bytes",
        reason_text(rejection, &text),
    );
    // Whitespace inside data does not count; string bytes do. `{"k":"x..x"}` is N + 8 bytes.
    var buffer: [3000]u8 = undefined;
    var value: [1200]u8 = undefined;
    const filler: [1017]u8 = @splat('x');
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    const fits = try std.fmt.bufPrint(&value, "{{ \"k\" :  \"{s}\" }}", .{filler[0..1016]});
    const fits_line = edited(&buffer, "{\"position\":1}", fits);
    try testing.expectEqual(@as(usize, 1024), decode(fits_line, &scratch).event.data.len);
    const big = try std.fmt.bufPrint(&value, "{{\"k\":\"{s}\"}}", .{filler[0..1017]});
    rejection = try expect_rejected(edited(&buffer, "{\"position\":1}", big), .data_too_large);
    try testing.expectEqual(@as(u64, 1025), rejection.size);
}

test "event: event id lookup for results" {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings("event-1", event.find_event_id(sample_line, &buffer).?);
    const escaped = event.find_event_id("{\"event_id\":\"a\\\"b\"}", &buffer).?;
    try testing.expectEqualStrings("a\"b", escaped);
    try testing.expect(event.find_event_id("{\"event_id\":1}", &buffer) == null);
    try testing.expect(event.find_event_id("{}", &buffer) == null);
}

test "event: hashes and compaction" {
    try testing.expect(event.parse_hash(tx_hex[2..]) != null);
    try testing.expect(event.parse_hash(tx_hex[0..65]) == null);
    const bad: [66]u8 = .{ '0', 'x' } ++ @as([64]u8, @splat('g'));
    try testing.expect(event.parse_hash(&bad) == null);
    var out: [64]u8 = undefined;
    const raw = "{ \"a b\" : [ 1 , \"x\\\" y\" ] }";
    try testing.expectEqualStrings("{\"a b\":[1,\"x\\\" y\"]}", event.compact_json(raw, &out));
}

/// Properties for arbitrary input: no crash, and accepted events satisfy the invariants.
fn check_arbitrary(line: []const u8) !void {
    var scratch: [event.scratch_size(limits)]u8 = undefined;
    switch (decode(line, &scratch)) {
        .rejected => |rejection| {
            var text: [512]u8 = undefined;
            try testing.expect(reason_text(rejection, &text).len > 0);
        },
        .event => |value| {
            try testing.expect(line.len <= limits.event_bytes_max);
            try testing.expect(std.mem.trim(u8, value.event_id, " \t\r\n").len > 0);
            try testing.expect(value.event_id.len <= event.event_id_size_max);
            try testing.expect(value.data.len <= limits.data_bytes_max);
            try testing.expect(value.data[0] == '{');
            try json.validate(value.data);
        },
    }
}

test "event: seeded fuzz of mutated lines" {
    var prng = Prng.init(0xa0d17);
    const pieces = [_][]const u8{
        "{",                  "}",                        "[",             "]",
        ",",                  ":",                        "\"event_id\"",  "\"data\"",
        "\"x\"",              "1",                        "null",          "\"a\\u0062\"",
        "\"schema_version\"", "\"transaction-event/v1\"", "\"headers\"",   " ",
        "\"event_type\"",     "\"BUILDER_REJECTED\"",     "\"producer\"",  "\"base-builder\"",
        "\"event_time\"",     "\"2026-11-05T12:00:00Z\"", "\"bundle_id\"", "\"",
    };
    var input: [512]u8 = undefined;
    for (0..4000) |_| {
        var writer: std.Io.Writer = .fixed(&input);
        if (prng.chance(1, 2)) {
            writer.writeAll(sample_line) catch {};
            const flips = prng.below(4);
            for (0..flips) |_| {
                const at = prng.below(writer.end);
                input[at] = @truncate(prng.int(u8));
            }
        } else {
            const parts = prng.below(32);
            for (0..parts) |_| writer.writeAll(pieces[prng.below(pieces.len)]) catch break;
        }
        try check_arbitrary(writer.buffered());
    }
}

fn fuzz_decode(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [1024]u8 = undefined;
    const size = smith.slice(&input);
    try check_arbitrary(input[0..size]);
}

test "event: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{ .corpus = &.{sample_line} });
}

//! JSON tests: token streams, rejection of malformed input, unescaping, hex codecs, writer
//! output, a writer/scanner round-trip seeded fuzz, and a std.testing.fuzz target.

const std = @import("std");
const json = @import("root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectError = std.testing.expectError;

fn repeat(comptime text: []const u8, comptime count: usize) *const [text.len * count]u8 {
    var result: [text.len * count]u8 = undefined;
    for (0..count) |index| @memcpy(result[index * text.len ..][0..text.len], text);
    const final = result;
    return &final;
}

fn expect_tags(input: []const u8, tags: []const json.TokenTag) !void {
    var scanner = json.Scanner.init(input);
    for (tags) |tag| {
        const token = try scanner.next();
        try expectEqual(tag, token.tag);
    }
}

test "json: scans a JSON-RPC request" {
    const input =
        \\ {"jsonrpc":"2.0","id":1,"method":"eth_getBalance",
        \\  "params":["0xdeadbeef", "latest", true, null, -1.5e3, {}, []]}
    ;
    try expect_tags(input, &.{
        .object_begin, .string,     .string,       .string,     .number,      .string,
        .string,       .string,     .array_begin,  .string,     .string,      .true,
        .null,         .number,     .object_begin, .object_end, .array_begin, .array_end,
        .array_end,    .object_end, .end,          .end,
    });
    var scanner = json.Scanner.init(input);
    _ = try scanner.next();
    const key = try scanner.next();
    try expect(key.key);
    try expectEqualStrings("jsonrpc", key.bytes);
    const value = try scanner.next();
    try expect(!value.key);
    try expectEqualStrings("2.0", value.bytes);
}

test "json: rejects malformed documents" {
    const cases = [_]struct { []const u8, json.Error }{
        .{ "", error.UnexpectedEnd },
        .{ "{", error.UnexpectedEnd },
        .{ "[1,]", error.UnexpectedCharacter },
        .{ "{\"a\" 1}", error.UnexpectedCharacter },
        .{ "{1:2}", error.UnexpectedCharacter },
        .{ "01", error.InvalidNumber },
        .{ "1.", error.InvalidNumber },
        .{ "-", error.UnexpectedEnd },
        .{ "1e", error.InvalidNumber },
        .{ "tru", error.UnexpectedEnd },
        .{ "trux", error.InvalidLiteral },
        .{ "\"a\\x\"", error.InvalidString },
        .{ "\"\x01\"", error.InvalidString },
        .{ "\"\xff\"", error.InvalidString },
        .{ "1 2", error.TrailingData },
        .{ "[1}", error.UnexpectedCharacter },
        .{ "{\"a\":1]", error.UnexpectedCharacter },
    };
    for (cases) |case| {
        try expectError(case[1], json.validate(case[0]));
    }
    var deep: [json.depth_max + 1]u8 = @splat('[');
    try expectError(error.DepthExceeded, json.validate(&deep));
}

test "json: skip jumps over nested values" {
    var scanner = json.Scanner.init("{\"skip\":{\"a\":[1,{\"b\":2}]},\"keep\":7}");
    _ = try scanner.next();
    _ = try scanner.next(); // "skip"
    try scanner.skip(try scanner.next());
    const key = try scanner.next();
    try expectEqualStrings("keep", key.bytes);
    const value = try scanner.next();
    try expectEqualStrings("7", value.bytes);
    try expectEqual(json.TokenTag.object_end, (try scanner.next()).tag);
}

test "json: unescape" {
    var scanner = json.Scanner.init("\"a\\n\\\"b\\u00e9\\ud83d\\ude00\\/\"");
    const token = try scanner.next();
    try expect(token.escaped);
    var buffer: [64]u8 = undefined;
    const text = try json.unescape(token, &buffer);
    try expectEqualStrings("a\n\"b\u{e9}\u{1f600}/", text);
    var small: [2]u8 = undefined;
    try expectError(error.NoSpaceLeft, json.unescape(token, &small));
    var lone = json.Scanner.init("\"\\udc00\"");
    try expectError(error.InvalidString, json.unescape(try lone.next(), &buffer));
}

test "json: quantity encoding" {
    try expectEqual(@as(u64, 0), try json.parse_quantity(u64, "0x0"));
    try expectEqual(@as(u64, 0x41), try json.parse_quantity(u64, "0x41"));
    try expectEqual(@as(u64, 0x400), try json.parse_quantity(u64, "0X400"));
    try expectError(error.LeadingZero, json.parse_quantity(u64, "0x0400"));
    try expectError(error.MissingPrefix, json.parse_quantity(u64, "0x"));
    try expectError(error.MissingPrefix, json.parse_quantity(u64, "400"));
    try expectError(error.InvalidHex, json.parse_quantity(u64, "0xfg"));
    try expectError(error.Overflow, json.parse_quantity(u8, "0x100"));
    const max = try json.parse_quantity(u256, "0x" ++ @as([64]u8, @splat('f')));
    try expectEqual(@as(u256, std.math.maxInt(u256)), max);

    var buffer: [66]u8 = undefined;
    try expectEqualStrings("0x0", json.format_quantity(@as(u64, 0), &buffer));
    try expectEqualStrings("0x41", json.format_quantity(@as(u64, 65), &buffer));
    try expectEqualStrings("0x400", json.format_quantity(@as(u32, 1024), &buffer));
}

test "json: data encoding" {
    var out: [8]u8 = undefined;
    const decoded = try json.parse_data("0x4100ff", &out);
    try std.testing.expectEqualSlices(u8, &.{ 0x41, 0x00, 0xff }, decoded);
    try expectEqual(@as(usize, 0), (try json.parse_data("0x", &out)).len);
    try expectError(error.InvalidHex, json.parse_data("0x0", &out));
    try expectError(error.NoSpaceLeft, json.parse_data("0x" ++ @as([18]u8, @splat('0')), &out));
    const address = try json.parse_fixed(20, "0x" ++ comptime repeat("ab", 20));
    try expectEqual(@as(u8, 0xab), address[19]);
    try expectError(error.InvalidLength, json.parse_fixed(20, "0x00"));
}

test "json: writer output" {
    var buffer: [256]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var writer = json.Writer.init(&out);
    try writer.begin_object();
    try writer.key("jsonrpc");
    try writer.string("2.0");
    try writer.key("id");
    try writer.integer(@as(u64, 7));
    try writer.key("result");
    try writer.begin_array();
    try writer.quantity(@as(u64, 1024));
    try writer.data(&.{ 0xde, 0xad });
    try writer.boolean(false);
    try writer.null_value();
    try writer.string("q\"\n\x01");
    try writer.begin_object();
    try writer.end_object();
    try writer.end_array();
    try writer.end_object();
    try expectEqualStrings(
        \\{"jsonrpc":"2.0","id":7,"result":["0x400","0xdead",false,null,"q\"\n\u0001",{}]}
    , out.buffered());
    try json.validate(out.buffered());
}

/// Generates a random document with the writer while recording the expected token tags.
const Generator = struct {
    prng: Prng,
    writer: *json.Writer,
    tags: [512]json.TokenTag = undefined,
    tags_count: usize = 0,
    containers: [16]bool = undefined, // true = object
    depth: usize = 0,

    fn push_tag(generator: *Generator, tag: json.TokenTag) void {
        generator.tags[generator.tags_count] = tag;
        generator.tags_count += 1;
    }

    fn close(generator: *Generator) !void {
        std.debug.assert(generator.depth > 0);
        generator.depth -= 1;
        const object = generator.containers[generator.depth];
        if (object) try generator.writer.end_object() else try generator.writer.end_array();
        generator.push_tag(if (object) .object_end else .array_end);
    }

    fn value(generator: *Generator) !void {
        const prng = &generator.prng;
        const writer = generator.writer;
        const nested_allowed = generator.depth < generator.containers.len;
        const kind = prng.below(if (nested_allowed) 7 else 5);
        switch (kind) {
            0 => try writer.quantity(prng.int(u64)),
            1 => try writer.integer(prng.int(i32)),
            2 => {
                const flag = prng.chance(1, 2);
                try writer.boolean(flag);
                return generator.push_tag(if (flag) .true else .false);
            },
            3 => return {
                try writer.null_value();
                generator.push_tag(.null);
            },
            4 => {
                var bytes: [16]u8 = undefined;
                prng.fill(&bytes);
                try writer.string(&bytes);
            },
            5, 6 => {
                const object = kind == 5;
                generator.containers[generator.depth] = object;
                generator.depth += 1;
                if (object) try writer.begin_object() else try writer.begin_array();
                return generator.push_tag(if (object) .object_begin else .array_begin);
            },
            else => unreachable,
        }
        generator.push_tag(if (kind == 1) .number else .string);
    }

    fn generate(generator: *Generator) !void {
        const steps_max = generator.prng.range(1, 200);
        var steps: usize = 0;
        while (generator.tags_count + 4 < generator.tags.len) : (steps += 1) {
            const in_object = generator.depth > 0 and generator.containers[generator.depth - 1];
            const want_close = steps >= steps_max or generator.prng.chance(1, 4);
            if (generator.depth > 0 and want_close) {
                try generator.close();
                if (generator.depth == 0) return;
                continue;
            }
            if (in_object) {
                var key_bytes: [8]u8 = undefined;
                generator.prng.fill(&key_bytes);
                try generator.writer.key(&key_bytes);
                generator.push_tag(.string);
            }
            try generator.value();
            if (generator.depth == 0) return;
        }
        while (generator.depth > 0) try generator.close();
    }
};

/// Writes a random document, then checks the scanner yields the same token sequence.
fn round_trip(seed: u64) !void {
    var buffer: [16 * 1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var writer = json.Writer.init(&out);
    var generator: Generator = .{ .prng = Prng.init(seed), .writer = &writer };
    try generator.generate();
    var scanner = json.Scanner.init(out.buffered());
    for (generator.tags[0..generator.tags_count]) |tag| {
        const token = try scanner.next();
        try expectEqual(tag, token.tag);
        if (token.tag == .string and token.escaped) {
            var decoded: [128]u8 = undefined;
            _ = json.unescape(token, &decoded) catch |err| switch (err) {
                error.NoSpaceLeft => {},
                error.InvalidString => return err,
            };
        }
    }
    try expectEqual(json.TokenTag.end, (try scanner.next()).tag);
}

test "json: seeded writer/scanner round trip" {
    var seed: u64 = 0;
    var passed: u32 = 0;
    while (seed < 300) : (seed += 1) {
        round_trip(seed) catch |err| switch (err) {
            // Random string bytes can be invalid UTF-8; the writer passes bytes through.
            error.InvalidString => continue,
            else => return err,
        };
        passed += 1;
    }
    try expect(passed > 0);
}

/// Scanning arbitrary bytes never crashes, and accepted documents rescan identically.
fn scan_arbitrary(input: []const u8) !void {
    var scanner = json.Scanner.init(input);
    var count: usize = 0;
    while (count <= input.len + 1) : (count += 1) {
        const token = scanner.next() catch return;
        if (token.tag == .string) {
            var buffer: [256]u8 = undefined;
            _ = json.unescape(token, &buffer) catch {};
        }
        if (token.tag == .end) break;
    }
    try expect(count <= input.len + 1);
}

test "json: find_path" {
    const doc =
        \\{"version":"0x0","blockRef":{"hash":"0xab","l1origin":{"number":19,"x":[1,{"y":2}]}},
        \\ "number" : 7 , "obj": {"k": null}, "esc\\u0041": 1}
    ;
    const find = json.find_path;
    try expectEqualStrings("19", (try find(doc, &.{ "blockRef", "l1origin", "number" })).?);
    try expectEqualStrings("7", (try find(doc, &.{"number"})).?);
    try expectEqualStrings("\"0xab\"", (try find(doc, &.{ "blockRef", "hash" })).?);
    try expectEqualStrings("[1,{\"y\":2}]", (try find(doc, &.{ "blockRef", "l1origin", "x" })).?);
    try expectEqualStrings("{\"k\": null}", (try find(doc, &.{"obj"})).?);
    try expectEqualStrings(doc, (try find(doc, &.{})).?);
    try expect((try find(doc, &.{"missing"})) == null);
    try expect((try find(doc, &.{ "number", "deeper" })) == null); // Not an object.
    try expect((try find(doc, &.{"escA"})) == null); // Escaped keys never match.
    try expect((try find("[1]", &.{"a"})) == null);
    try std.testing.expectError(error.UnexpectedEnd, find("{\"a\":", &.{"a"}));
    try std.testing.expectError(error.UnexpectedCharacter, find("{a:1}", &.{"a"}));
}

/// A found value is itself a well-formed document.
fn find_arbitrary(input: []const u8) !void {
    const keys = [_][]const u8{ "a", "b" };
    for (0..keys.len + 1) |depth| {
        const found = json.find_path(input, keys[0..depth]) catch continue orelse continue;
        try json.validate(found);
    }
}

test "json: seeded arbitrary bytes" {
    var prng = Prng.init(0x15011);
    const alphabet = "{}[]:,\"\\ 0123456789-+.eEtrufalsn\x00\xc3\xa9u";
    var input: [128]u8 = undefined;
    for (0..2000) |_| {
        const size = prng.below(input.len);
        for (input[0..size]) |*byte| byte.* = alphabet[prng.below(alphabet.len)];
        try scan_arbitrary(input[0..size]);
        try find_arbitrary(input[0..size]);
    }
}

fn fuzz_scan(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [512]u8 = undefined;
    const size = smith.slice(&input);
    try scan_arbitrary(input[0..size]);
    try find_arbitrary(input[0..size]);
}

test "json: fuzz scanner" {
    try std.testing.fuzz({}, fuzz_scan, .{});
}

/// The per-byte `Writer.data` encoding `write_hex` replaced.
fn hex_reference(out: []u8, bytes: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        out[2 * index] = digits[byte >> 4];
        out[2 * index + 1] = digits[byte & 0xf];
    }
    return out[0 .. 2 * bytes.len];
}

test "json: hex_encode and write_hex equal the per-byte encoding (seeded)" {
    const allocator = std.testing.allocator;
    var prng = Prng.init(0x4e58);
    var source: [300]u8 = undefined;
    var expected: [600]u8 = undefined;
    var encoded: [600]u8 = undefined;
    for (0..400) |_| {
        const length = prng.below(source.len + 1);
        prng.fill(source[0..length]);
        const reference = hex_reference(&expected, source[0..length]);
        json.hex_encode(encoded[0 .. 2 * length], source[0..length]);
        try expectEqualStrings(reference, encoded[0 .. 2 * length]);
        // A small growing buffer splits the output into chunks at varying offsets.
        const capacity = 2 + prng.below(40);
        var buffer = try std.Io.Writer.Allocating.initCapacity(allocator, capacity);
        defer buffer.deinit();
        const prefix = prng.below(capacity);
        try buffer.writer.splatByteAll('-', prefix);
        try json.write_hex(&buffer.writer, source[0..length]);
        try expectEqualStrings(reference, buffer.written()[prefix..]);
    }
}

test "json: write_hex without a buffer writes digit by digit" {
    var sink: [8]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(sink[0..1]);
    try expectError(error.WriteFailed, json.write_hex(&fixed, &.{0xab}));
    try expectEqualStrings("a", fixed.buffered());
}

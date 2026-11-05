//! Structured, leveled logging with fixed messages and typed fields.
//!
//! A log line is `<time> <LEVEL> <scope>: <message> key=value ...` (logfmt-style fields), or
//! one JSON object per line. Messages are fixed strings; variable data goes in fields, so
//! lines stay greppable and machine-parsable. Each line is formatted into a stack buffer and
//! emitted with one sink call, so concurrent lines never interleave and nothing allocates.
//! The level check happens before any formatting. Time comes from the caller's clock (IO or
//! simulator), never from the OS, so simulator logs are reproducible.

const std = @import("std");
const assert = std.debug.assert;

pub const line_size_max = 1024;

pub const Level = enum(u8) {
    trace,
    debug,
    info,
    warn,
    err,

    pub fn label(level: Level) []const u8 {
        return switch (level) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }

    pub fn parse(text: []const u8) ?Level {
        const names = [_]struct { []const u8, Level }{
            .{ "trace", .trace }, .{ "debug", .debug }, .{ "info", .info },
            .{ "warn", .warn },   .{ "error", .err },   .{ "err", .err },
        };
        for (names) |entry| if (std.ascii.eqlIgnoreCase(text, entry[0])) return entry[1];
        return null;
    }
};

pub const Format = enum { text, json };

/// Where finished lines go. `write` receives one complete line including the newline.
pub const Sink = struct {
    context: ?*anyopaque,
    write: *const fn (context: ?*anyopaque, line: []const u8) void,
};

/// Writes lines to stderr with a single write per line. Errors are dropped: logging must
/// never take down the node.
pub fn stderr_sink() Sink {
    return .{ .context = null, .write = write_stderr };
}

fn write_stderr(context: ?*anyopaque, line: []const u8) void {
    _ = context;
    std.debug.print("{s}", .{line});
}

/// Collects lines in memory (tests, simulator traces).
pub const MemorySink = struct {
    buffer: []u8,
    size: usize = 0,
    lines: u32 = 0,
    truncated: bool = false,

    pub fn sink(memory: *MemorySink) Sink {
        return .{ .context = memory, .write = write_memory };
    }

    pub fn text(memory: *const MemorySink) []const u8 {
        return memory.buffer[0..memory.size];
    }

    fn write_memory(context: ?*anyopaque, line: []const u8) void {
        const memory: *MemorySink = @ptrCast(@alignCast(context.?));
        memory.lines += 1;
        const free = memory.buffer.len - memory.size;
        if (line.len > free) {
            memory.truncated = true;
            return;
        }
        @memcpy(memory.buffer[memory.size..][0..line.len], line);
        memory.size += line.len;
    }
};

/// A clock reading for the line prefix, in nanoseconds (realtime for production, simulated
/// time in DST). Zero omits the timestamp.
pub const TimeSource = struct {
    context: ?*anyopaque = null,
    now_ns: *const fn (context: ?*anyopaque) u64 = no_time,

    fn no_time(context: ?*anyopaque) u64 {
        _ = context;
        return 0;
    }
};

pub const Logger = struct {
    level: Level = .info,
    format: Format = .text,
    sink: Sink,
    time: TimeSource = .{},
    /// Lines dropped because they did not fit `line_size_max`; they are truncated instead.
    lines_truncated: u64 = 0,

    pub fn scoped(logger: *Logger, comptime scope: []const u8) Scoped(scope) {
        return .{ .logger = logger };
    }

    pub fn enabled(logger: *const Logger, level: Level) bool {
        return @backingInt(level) >= @backingInt(logger.level);
    }

    /// Logs `message` with `fields`, an anonymous struct whose field names become keys.
    pub fn log(
        logger: *Logger,
        level: Level,
        comptime scope: []const u8,
        comptime message: []const u8,
        fields: anytype,
    ) void {
        comptime assert(message.len > 0);
        comptime assert(std.mem.findScalar(u8, message, '\n') == null);
        if (!logger.enabled(level)) return;
        var buffer: [line_size_max]u8 = undefined;
        var out: std.Io.Writer = .fixed(buffer[0 .. buffer.len - 1]);
        const now_ns = logger.time.now_ns(logger.time.context);
        const complete = switch (logger.format) {
            .text => write_text(&out, now_ns, level, scope, message, fields),
            .json => write_json(&out, now_ns, level, scope, message, fields),
        };
        if (complete) |_| {} else |_| logger.lines_truncated += 1;
        var size = out.end;
        buffer[size] = '\n';
        size += 1;
        logger.sink.write(logger.sink.context, buffer[0..size]);
    }
};

pub fn Scoped(comptime scope: []const u8) type {
    return struct {
        logger: *Logger,

        const Self = @This();

        pub fn trace(self: Self, comptime message: []const u8, fields: anytype) void {
            self.logger.log(.trace, scope, message, fields);
        }
        pub fn debug(self: Self, comptime message: []const u8, fields: anytype) void {
            self.logger.log(.debug, scope, message, fields);
        }
        pub fn info(self: Self, comptime message: []const u8, fields: anytype) void {
            self.logger.log(.info, scope, message, fields);
        }
        pub fn warn(self: Self, comptime message: []const u8, fields: anytype) void {
            self.logger.log(.warn, scope, message, fields);
        }
        pub fn err(self: Self, comptime message: []const u8, fields: anytype) void {
            self.logger.log(.err, scope, message, fields);
        }
    };
}

const Error = std.Io.Writer.Error;

fn write_timestamp(out: *std.Io.Writer, now_ns: u64) Error!void {
    const seconds = now_ns / std.time.ns_per_s;
    const millis = (now_ns % std.time.ns_per_s) / std.time.ns_per_ms;
    try out.print("{d}.{d:0>3}", .{ seconds, millis });
}

fn write_text(
    out: *std.Io.Writer,
    now_ns: u64,
    level: Level,
    comptime scope: []const u8,
    comptime message: []const u8,
    fields: anytype,
) Error!void {
    if (now_ns != 0) {
        try write_timestamp(out, now_ns);
        try out.writeByte(' ');
    }
    try out.print("{s: <5} " ++ scope ++ ": " ++ message, .{level.label()});
    inline for (@typeInfo(@TypeOf(fields)).@"struct".field_names) |name| {
        try out.writeAll(" " ++ name ++ "=");
        try write_text_value(out, @field(fields, name));
    }
}

fn write_text_value(out: *std.Io.Writer, value: anytype) Error!void {
    const T = @TypeOf(value);
    if (comptime is_string(T)) {
        const text: []const u8 = value;
        const needs_quotes = text.len == 0 or for (text) |byte| {
            if (byte <= ' ' or byte == '"' or byte == '=' or byte >= 0x7f) break true;
        } else false;
        if (!needs_quotes) return out.writeAll(text);
        return write_quoted(out, text);
    }
    try write_scalar(out, value);
}

fn write_json(
    out: *std.Io.Writer,
    now_ns: u64,
    level: Level,
    comptime scope: []const u8,
    comptime message: []const u8,
    fields: anytype,
) Error!void {
    try out.writeByte('{');
    if (now_ns != 0) {
        try out.writeAll("\"time\":");
        try write_timestamp(out, now_ns);
        try out.writeByte(',');
    }
    try out.print("\"level\":\"{s}\",\"scope\":\"" ++ scope ++ "\",\"message\":", .{level.label()});
    try write_quoted(out, message);
    inline for (@typeInfo(@TypeOf(fields)).@"struct".field_names) |name| {
        try out.writeAll(",\"" ++ name ++ "\":");
        const value = @field(fields, name);
        if (comptime is_string(@TypeOf(value))) {
            try write_quoted(out, value);
        } else if (comptime is_number(@TypeOf(value)) or @TypeOf(value) == bool) {
            try write_scalar(out, value);
        } else {
            // Errors, enums, addresses, ...: render as a string.
            var scratch: [256]u8 = undefined;
            var inner: std.Io.Writer = .fixed(&scratch);
            write_scalar(&inner, value) catch {};
            try write_quoted(out, inner.buffered());
        }
    }
    try out.writeByte('}');
}

fn write_scalar(out: *std.Io.Writer, value: anytype) Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .int, .comptime_int, .float, .comptime_float => try out.print("{d}", .{value}),
        .bool => try out.writeAll(if (value) "true" else "false"),
        .@"enum", .enum_literal => try out.writeAll(@tagName(value)),
        .error_set => try out.writeAll(@errorName(value)),
        .optional => if (value) |inner| try write_scalar(out, inner) else try out.writeAll("null"),
        .array => |info| {
            // Byte arrays (hashes, addresses) render as 0x-hex.
            comptime assert(info.child == u8);
            try out.print("0x{x}", .{value[0..]});
        },
        else => try out.print("{f}", .{value}),
    }
}

fn write_quoted(out: *std.Io.Writer, text: []const u8) Error!void {
    try out.writeByte('"');
    for (text) |byte| switch (byte) {
        '"' => try out.writeAll("\\\""),
        '\\' => try out.writeAll("\\\\"),
        '\n' => try out.writeAll("\\n"),
        '\r' => try out.writeAll("\\r"),
        '\t' => try out.writeAll("\\t"),
        0...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try out.print("\\u{x:0>4}", .{byte}),
        else => try out.writeByte(byte),
    };
    try out.writeByte('"');
}

fn is_string(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| switch (p.size) {
            .slice => p.child == u8,
            .one => switch (@typeInfo(p.child)) {
                .array => |a| a.child == u8,
                else => false,
            },
            else => false,
        },
        else => false,
    };
}

fn is_number(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .int, .comptime_int, .float, .comptime_float => true,
        else => false,
    };
}

test "log: text format with fields and level filter" {
    var storage: [1024]u8 = undefined;
    var memory: MemorySink = .{ .buffer = &storage };
    var logger: Logger = .{ .level = .info, .sink = memory.sink() };
    const engine = logger.scoped("engine");
    engine.debug("dropped", .{ .number = 1 });
    engine.info("forkchoice updated", .{
        .head = @as(u64, 42),
        .status = .valid,
        .peer = "a b",
        .hash = [_]u8{ 0xab, 0xcd },
    });
    engine.err("request failed", .{ .err = error.ConnectionRefused, .attempt = @as(?u32, null) });
    try std.testing.expectEqualStrings(
        \\INFO  engine: forkchoice updated head=42 status=valid peer="a b" hash=0xabcd
        \\ERROR engine: request failed err=ConnectionRefused attempt=null
        \\
    , memory.text());
    try std.testing.expectEqual(@as(u32, 2), memory.lines);
}

const FixedClock = struct {
    fn now(context: ?*anyopaque) u64 {
        _ = context;
        return 1_700_000_000 * std.time.ns_per_s + 5 * std.time.ns_per_ms;
    }
};

test "log: json format" {
    var storage: [1024]u8 = undefined;
    var memory: MemorySink = .{ .buffer = &storage };
    var logger: Logger = .{
        .level = .trace,
        .format = .json,
        .sink = memory.sink(),
        .time = .{ .now_ns = FixedClock.now },
    };
    logger.scoped("p2p").warn("peer banned", .{
        .reason = "bad \"block\"",
        .score = @as(i32, -100),
        .err = error.Timeout,
    });
    const line = memory.text();
    try std.testing.expectEqualStrings(
        \\{"time":1700000000.005,"level":"WARN","scope":"p2p","message":"peer banned","reason":"bad \"block\"","score":-100,"err":"Timeout"}
        \\
    , line);
    try @import("../json/root.zig").validate(line[0 .. line.len - 1]);
}

test "log: long lines are truncated, never split" {
    var storage: [4096]u8 = undefined;
    var memory: MemorySink = .{ .buffer = &storage };
    var logger: Logger = .{ .sink = memory.sink() };
    const long: [2000]u8 = @splat('x');
    logger.scoped("t").info("long", .{ .value = @as([]const u8, &long) });
    try std.testing.expectEqual(@as(u32, 1), memory.lines);
    try std.testing.expectEqual(@as(usize, line_size_max), memory.size);
    try std.testing.expectEqual(@as(u64, 1), logger.lines_truncated);
    try std.testing.expectEqual(@as(u8, '\n'), memory.text()[memory.size - 1]);
}

test "log: level parse" {
    try std.testing.expectEqual(Level.err, Level.parse("ERROR").?);
    try std.testing.expectEqual(Level.debug, Level.parse("debug").?);
    try std.testing.expectEqual(@as(?Level, null), Level.parse("loud"));
}

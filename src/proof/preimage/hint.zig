//! Hint channel. Port of base/base `crates/proof/preimage/src/hint.rs`, plus the generic
//! `<type> 0x<hex>` text encoding from `crates/proof/proof/src/hint.rs`.
//!
//! Wire format: the client writes a big-endian `u32` length and the hint text; the host
//! routes the hint and answers with one acknowledgement byte. The host always
//! acknowledges, even when the hint is invalid or routing fails, so the client never
//! deadlocks; the error is reported on the host side only.

const std = @import("std");
const assert = std.debug.assert;
const channel_module = @import("channel.zig");

const Channel = channel_module.Channel;

/// Largest hint text the host accepts. Longer hints are drained and rejected.
pub const hint_size_max: u32 = 64 * 1024;

pub const HintWriter = struct {
    channel: Channel,

    pub fn init(channel: Channel) HintWriter {
        return .{ .channel = channel };
    }

    pub fn write(writer: HintWriter, hint: []const u8) channel_module.Error!void {
        assert(hint.len <= std.math.maxInt(u32));
        var length_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &length_bytes, @intCast(hint.len), .big);
        try writer.channel.write(&.{ &length_bytes, hint });
        var ack: [1]u8 = undefined;
        try writer.channel.read_exact(&ack);
    }
};

pub const RouteError = error{
    /// The router does not understand the hint (unknown type, bad data).
    HintRejected,
    /// The router understood the hint but could not act on it.
    HintFailed,
};

/// Host-side consumer of hints. The text is only valid during the call.
pub const Router = struct {
    context: *anyopaque,
    route_hint: *const fn (context: *anyopaque, hint: []const u8) RouteError!void,
};

pub const ServeError = channel_module.Error || RouteError || error{
    HintTooLarge,
    InvalidUtf8,
};

pub const HintReader = struct {
    channel: Channel,
    /// Hint text storage, at most `hint_size_max` bytes.
    buffer: []u8,

    pub fn init(channel: Channel, buffer: []u8) HintReader {
        assert(buffer.len > 0);
        assert(buffer.len <= hint_size_max);
        return .{ .channel = channel, .buffer = buffer };
    }

    /// Reads, routes and acknowledges one hint.
    pub fn next_hint(reader: HintReader, router: Router) ServeError!void {
        var length_bytes: [4]u8 = undefined;
        try reader.channel.read_exact(&length_bytes);
        const length = std.mem.readInt(u32, &length_bytes, .big);
        if (length > reader.buffer.len) {
            try reader.drain(length);
            try reader.acknowledge();
            return error.HintTooLarge;
        }
        const hint = reader.buffer[0..length];
        if (length > 0) try reader.channel.read_exact(hint);
        if (!std.unicode.utf8ValidateSlice(hint)) {
            try reader.acknowledge();
            return error.InvalidUtf8;
        }
        const routed = router.route_hint(router.context, hint);
        try reader.acknowledge();
        return routed;
    }

    fn acknowledge(reader: HintReader) channel_module.Error!void {
        try reader.channel.write(&.{&[_]u8{0}});
    }

    fn drain(reader: HintReader, length: u32) channel_module.Error!void {
        assert(length > reader.buffer.len);
        var remaining = length;
        const rounds_max = length / reader.buffer.len + 1;
        var round: u32 = 0;
        while (remaining > 0) : (round += 1) {
            assert(round < rounds_max);
            const chunk: u32 = @intCast(@min(remaining, reader.buffer.len));
            try reader.channel.read_exact(reader.buffer[0..chunk]);
            remaining -= chunk;
        }
    }
};

/// A parsed `<type> 0x<hex>` hint. `type_name` points into the hint text.
pub const Hint = struct {
    type_name: []const u8,
    data: []const u8,

    pub const ParseError = error{InvalidHintFormat};

    /// Parses `text`, decoding the hex data into `data_buffer`. Mirrors the Rust
    /// parser: exactly one space, and the `0x` prefix is optional.
    pub fn parse(text: []const u8, data_buffer: []u8) ParseError!Hint {
        const space = std.mem.indexOfScalar(u8, text, ' ') orelse return error.InvalidHintFormat;
        const type_name = text[0..space];
        var hex = text[space + 1 ..];
        if (std.mem.indexOfScalar(u8, hex, ' ') != null) return error.InvalidHintFormat;
        if (std.mem.startsWith(u8, hex, "0x")) hex = hex[2..];
        if (hex.len % 2 != 0) return error.InvalidHintFormat;
        if (hex.len / 2 > data_buffer.len) return error.InvalidHintFormat;
        const data = std.fmt.hexToBytes(data_buffer[0 .. hex.len / 2], hex) catch {
            return error.InvalidHintFormat;
        };
        assert(data.len * 2 == hex.len);
        return .{ .type_name = type_name, .data = data };
    }

    /// Writes `<type_name> 0x<hex data>` into `out` and returns the text.
    pub fn encode(type_name: []const u8, data: []const u8, out: []u8) error{NoSpaceLeft}![]u8 {
        assert(std.mem.indexOfScalar(u8, type_name, ' ') == null);
        const text = try std.fmt.bufPrint(out, "{s} 0x{x}", .{ type_name, data });
        assert(text.len == type_name.len + 3 + data.len * 2);
        return text;
    }
};

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");
const Duplex = channel_module.Duplex;

const Harness = struct {
    duplex: Duplex = undefined,
    buffer: [64]u8 = undefined,
    hints: [8][64]u8 = undefined,
    hint_lengths: [8]u32 = undefined,
    hint_count: u32 = 0,
    reject: bool = false,
    last_error: ?ServeError = null,

    fn init(harness: *Harness) !void {
        try harness.duplex.init(testing.allocator, 1024);
        harness.duplex.client_endpoint.pump = .{ .context = harness, .step = step };
    }

    fn deinit(harness: *Harness) void {
        harness.duplex.deinit(testing.allocator);
    }

    fn route(context: *anyopaque, hint: []const u8) RouteError!void {
        const harness: *Harness = @ptrCast(@alignCast(context));
        if (harness.reject) return error.HintFailed;
        if (harness.hint_count == harness.hints.len) return error.HintFailed;
        @memcpy(harness.hints[harness.hint_count][0..hint.len], hint);
        harness.hint_lengths[harness.hint_count] = @intCast(hint.len);
        harness.hint_count += 1;
    }

    fn step(context: *anyopaque) bool {
        const harness: *Harness = @ptrCast(@alignCast(context));
        const reader = HintReader.init(harness.duplex.host(), &harness.buffer);
        harness.last_error = null;
        reader.next_hint(.{ .context = harness, .route_hint = route }) catch |err| {
            harness.last_error = err;
            // An acknowledged failure still made progress.
            return err != error.WouldBlock and err != error.ChannelClosed;
        };
        return true;
    }

    fn writer(harness: *Harness) HintWriter {
        return .init(harness.duplex.client());
    }
};

test "hint: client and host" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    try harness.writer().write("test-hint 0xfacade");
    try testing.expectEqual(@as(u32, 1), harness.hint_count);
    const routed = harness.hints[0][0..harness.hint_lengths[0]];
    try testing.expectEqualStrings("test-hint 0xfacade", routed);
}

test "hint: host acknowledges bad utf8, routing failure and oversize hints" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    try harness.writer().write(&.{ 0xf0, 0x90, 0x28, 0xbc });
    try testing.expectEqual(@as(?ServeError, error.InvalidUtf8), harness.last_error);
    harness.reject = true;
    try harness.writer().write("test-hint 0xfacade");
    try testing.expectEqual(@as(?ServeError, error.HintFailed), harness.last_error);
    harness.reject = false;
    try harness.writer().write(&@as([200]u8, @splat('a')));
    try testing.expectEqual(@as(?ServeError, error.HintTooLarge), harness.last_error);
    try harness.writer().write("after 0x00");
    try testing.expectEqual(@as(u32, 1), harness.hint_count);
    try testing.expectEqual(@as(?ServeError, null), harness.last_error);
}

test "hint: parse and encode" {
    var data: [8]u8 = undefined;
    const hint = try Hint.parse("l1-block-header 0xdeadbeef", &data);
    try testing.expectEqualStrings("l1-block-header", hint.type_name);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, hint.data);
    const bare = try Hint.parse("t abcd", &data);
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd }, bare.data);
    const empty = try Hint.parse("t 0x", &data);
    try testing.expectEqual(@as(usize, 0), empty.data.len);
    try testing.expectError(error.InvalidHintFormat, Hint.parse("no-space", &data));
    try testing.expectError(error.InvalidHintFormat, Hint.parse("a 0x00 b", &data));
    try testing.expectError(error.InvalidHintFormat, Hint.parse("a 0x0", &data));
    try testing.expectError(error.InvalidHintFormat, Hint.parse("a 0xzz", &data));
    var out: [64]u8 = undefined;
    const text = try Hint.encode("l2-code", &.{ 0x01, 0xab }, &out);
    try testing.expectEqualStrings("l2-code 0x01ab", text);
}

/// Encode then parse returns the same type and data; parse never accepts garbage that
/// fails to re-encode to an equivalent hint.
fn fuzz_hint_text(_: void, smith: *std.testing.Smith) anyerror!void {
    var type_name: [16]u8 = undefined;
    const letters: []const std.testing.Smith.Weight = &.{.{ .min = 'a', .max = 'z', .weight = 1 }};
    const type_len = smith.sliceWeightedBytes(&type_name, letters);
    var data: [64]u8 = undefined;
    const data_len = smith.slice(&data);
    var out: [256]u8 = undefined;
    const text = try Hint.encode(type_name[0..type_len], data[0..data_len], &out);
    var decoded: [64]u8 = undefined;
    const hint = try Hint.parse(text, &decoded);
    try testing.expectEqualStrings(type_name[0..type_len], hint.type_name);
    try testing.expectEqualSlices(u8, data[0..data_len], hint.data);

    var garbage: [128]u8 = undefined;
    const garbage_len = smith.slice(&garbage);
    const parsed = Hint.parse(garbage[0..garbage_len], &decoded) catch return;
    try testing.expect(parsed.type_name.len < garbage_len);
}

test "hint: fuzz text round trip" {
    try fuzz.run({}, fuzz_hint_text, .{});
}

/// Random hint frames through the channel: valid ones arrive intact, every one is
/// acknowledged, and both pipes end empty.
fn fuzz_frames(_: void, smith: *std.testing.Smith) anyerror!void {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var sent: u32 = 0;
    var frames: u32 = 0;
    while (frames < 16 and !smith.eos()) : (frames += 1) {
        var hint: [96]u8 = undefined;
        const len = smith.slice(&hint);
        try harness.writer().write(hint[0..len]);
        const valid = len <= harness.buffer.len and std.unicode.utf8ValidateSlice(hint[0..len]);
        if (valid and sent < harness.hints.len) {
            try testing.expectEqualSlices(u8, hint[0..len], harness.hints[sent][0..len]);
            sent += 1;
        }
        try testing.expectEqual(sent, harness.hint_count);
    }
    try testing.expectEqual(@as(u32, 0), harness.duplex.to_host.count);
    try testing.expectEqual(@as(u32, 0), harness.duplex.to_client.count);
}

test "hint: fuzz frames" {
    try fuzz.run({}, fuzz_frames, .{});
}

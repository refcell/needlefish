const std = @import("std");
const frame = @import("frame.zig");
const Prng = @import("../../testing/prng.zig").Prng;

test "ws: handshake accept key (RFC 6455 section 1.3)" {
    const accept = frame.accept_key("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
    const key = frame.client_key(@splat(0));
    try std.testing.expectEqualStrings("AAAAAAAAAAAAAAAAAAAAAA==", &key);
}

test "ws: RFC examples decode" {
    // Unmasked "Hello" from server.
    var unmasked = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    const a = (try frame.decode_frame(&unmasked, .client, .{})).frame;
    try std.testing.expectEqualStrings("Hello", a.payload);
    try std.testing.expect(a.header.fin and a.header.opcode == .text);
    // Masked "Hello" from client.
    var masked = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    const b = (try frame.decode_frame(&masked, .server, .{})).frame;
    try std.testing.expectEqualStrings("Hello", b.payload);
    try std.testing.expectEqual(@as(usize, masked.len), b.size);
    // Fragmented text: "Hel" then "lo".
    var first = [_]u8{ 0x01, 0x03, 0x48, 0x65, 0x6c };
    const c = (try frame.decode_frame(&first, .client, .{})).frame;
    try std.testing.expect(!c.header.fin and c.header.opcode == .text);
}

test "ws: protocol violations" {
    const Case = struct { bytes: []const u8, role: frame.Role, err: frame.DecodeError };
    const cases = [_]Case{
        .{ .bytes = &.{ 0xc1, 0x00 }, .role = .client, .err = error.ReservedBitsSet },
        .{ .bytes = &.{ 0x83, 0x00 }, .role = .client, .err = error.UnknownOpcode },
        .{ .bytes = &.{ 0x09, 0x00 }, .role = .client, .err = error.ControlFrameFragmented },
        .{ .bytes = &.{ 0x89, 0x7e }, .role = .client, .err = error.ControlFrameTooLarge },
        .{ .bytes = &.{ 0x82, 0x7e, 0x00, 0x05 }, .role = .client, .err = error.NonMinimalLength },
        .{ .bytes = &.{ 0x81, 0x00 }, .role = .server, .err = error.MaskMismatch },
        .{ .bytes = &.{ 0x81, 0x80, 0, 0, 0, 0 }, .role = .client, .err = error.MaskMismatch },
        .{
            .bytes = &.{ 0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff },
            .role = .client,
            .err = error.NonMinimalLength,
        },
        .{
            .bytes = &.{ 0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 },
            .role = .client,
            .err = error.PayloadTooLarge,
        },
    };
    for (cases) |case| {
        var buffer: [16]u8 = undefined;
        @memcpy(buffer[0..case.bytes.len], case.bytes);
        const result = frame.decode_frame(buffer[0..case.bytes.len], case.role, .{});
        try std.testing.expectError(case.err, result);
    }
}

test "ws: close payloads" {
    try std.testing.expectEqual(null, try frame.parse_close(""));
    const close = (try frame.parse_close(&.{ 0x03, 0xe8, 'b', 'y', 'e' })).?;
    try std.testing.expectEqual(@as(u16, 1000), close.code);
    try std.testing.expectEqualStrings("bye", close.reason);
    try std.testing.expectError(error.InvalidClose, frame.parse_close(&.{0x03}));
    try std.testing.expectError(error.InvalidClose, frame.parse_close(&.{ 0x03, 0xed })); // 1005
    try std.testing.expectError(error.InvalidClose, frame.parse_close(&.{ 0x03, 0xe8, 0xff }));
}

fn round_trip(prng: *Prng, size: usize, role: frame.Role) !void {
    var buffer: [70000 + frame.header_size_max]u8 = undefined;
    var payload: [70000]u8 = undefined;
    prng.fill(payload[0..size]);
    const mask: ?[4]u8 = if (role == .server) .{ 1, 2, 3, 4 } else null;
    var header: [frame.header_size_max]u8 = undefined;
    const fin = prng.chance(1, 2);
    const header_size = frame.encode_header(&header, fin, .binary, size, mask);
    @memcpy(buffer[0..header_size], header[0..header_size]);
    @memcpy(buffer[header_size..][0..size], payload[0..size]);
    if (mask) |key| frame.apply_mask(key, buffer[header_size..][0..size], 0);
    const total = header_size + size;
    // Every strict prefix is incomplete.
    const cut = prng.below(total);
    const partial = try frame.decode_frame(buffer[0..cut], role, .{});
    try std.testing.expect(partial == .incomplete);
    const decoded = (try frame.decode_frame(buffer[0..total], role, .{})).frame;
    try std.testing.expectEqual(total, decoded.size);
    try std.testing.expectEqual(fin, decoded.header.fin);
    try std.testing.expectEqualSlices(u8, payload[0..size], decoded.payload);
}

test "ws: seeded round trip across length encodings" {
    var prng = Prng.init(0x5eb);
    const sizes = [_]usize{ 0, 1, 125, 126, 127, 0xffff, 0x10000, 70000 };
    for (sizes) |size| {
        try round_trip(&prng, size, .server);
        try round_trip(&prng, size, .client);
    }
    for (0..300) |_| {
        const role: frame.Role = if (prng.chance(1, 2)) .server else .client;
        try round_trip(&prng, prng.below(300), role);
    }
}

fn decode_arbitrary(input: []u8) !void {
    const roles = [_]frame.Role{ .server, .client };
    for (roles) |role| {
        var copy: [4096]u8 = undefined;
        @memcpy(copy[0..input.len], input);
        const limits: frame.Limits = .{ .payload_size_max = 1024 };
        const result = frame.decode_frame(copy[0..input.len], role, limits);
        const decoded = result catch continue;
        switch (decoded) {
            .incomplete => {},
            .frame => |f| {
                try std.testing.expect(f.size <= input.len);
                try std.testing.expectEqual(f.header.payload_size, f.payload.len);
                if (f.header.opcode.is_control()) try std.testing.expect(f.payload.len <= 125);
            },
        }
    }
}

test "ws: seeded fuzz decode" {
    var prng = Prng.init(0xf00d);
    var input: [64]u8 = undefined;
    for (0..20000) |_| {
        const size = prng.below(input.len);
        prng.fill(input[0..size]);
        try decode_arbitrary(input[0..size]);
    }
}

fn fuzz_decode(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [4096]u8 = undefined;
    const size = smith.slice(&input);
    try decode_arbitrary(input[0..size]);
}

test "ws: fuzz decode" {
    try std.testing.fuzz({}, fuzz_decode, .{});
}

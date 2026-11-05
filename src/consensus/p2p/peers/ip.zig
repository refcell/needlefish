//! IPv4 / IPv6 address text parsing and formatting into caller buffers. IPv6 output
//! follows RFC 5952 (lowercase, longest zero run compressed, no IPv4 suffix). Used by
//! multiaddr text form and enode URLs.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{InvalidAddress};

/// Longest IPv6 text: eight groups of four digits and seven colons.
pub const text_length_max = 39;

pub const Address = union(enum) {
    ip4: [4]u8,
    ip6: [16]u8,
};

pub fn parse4(text: []const u8) Error![4]u8 {
    var result: [4]u8 = undefined;
    var iterator = std.mem.splitScalar(u8, text, '.');
    var index: usize = 0;
    while (iterator.next()) |part| : (index += 1) {
        if (index == 4) return error.InvalidAddress;
        if (part.len == 0 or part.len > 3) return error.InvalidAddress;
        if (part.len > 1 and part[0] == '0') return error.InvalidAddress;
        var value: u16 = 0;
        for (part) |character| {
            if (character < '0' or character > '9') return error.InvalidAddress;
            value = value * 10 + (character - '0');
        }
        if (value > 255) return error.InvalidAddress;
        result[index] = @intCast(value);
    }
    if (index != 4) return error.InvalidAddress;
    return result;
}

pub fn parse6(text: []const u8) Error![16]u8 {
    if (text.len < 2 or text.len > text_length_max) return error.InvalidAddress;
    var groups: [8]u16 = @splat(0);
    var head = text;
    var tail: []const u8 = "";
    if (std.mem.indexOf(u8, text, "::")) |gap| {
        head = text[0..gap];
        tail = text[gap + 2 ..];
        if (std.mem.indexOf(u8, tail, "::") != null) return error.InvalidAddress;
        const head_count = try parse_groups(head, groups[0..]);
        var tail_groups: [8]u16 = undefined;
        const tail_count = try parse_groups(tail, tail_groups[0..]);
        if (head_count + tail_count > 7) return error.InvalidAddress;
        @memcpy(groups[8 - tail_count ..], tail_groups[0..tail_count]);
    } else {
        if (try parse_groups(text, groups[0..]) != 8) return error.InvalidAddress;
    }
    var result: [16]u8 = undefined;
    for (groups, 0..) |group, index| std.mem.writeInt(u16, result[index * 2 ..][0..2], group, .big);
    return result;
}

/// Parses `a:b:c` hex groups (possibly empty text) into `output`, returning the count.
fn parse_groups(text: []const u8, output: []u16) Error!usize {
    if (text.len == 0) return 0;
    var count: usize = 0;
    var iterator = std.mem.splitScalar(u8, text, ':');
    while (iterator.next()) |part| : (count += 1) {
        if (count == output.len) return error.InvalidAddress;
        if (part.len == 0 or part.len > 4) return error.InvalidAddress;
        output[count] = std.fmt.parseUnsigned(u16, part, 16) catch return error.InvalidAddress;
    }
    assert(count <= output.len);
    return count;
}

pub fn parse(text: []const u8) Error!Address {
    if (std.mem.indexOfScalar(u8, text, ':') != null) return .{ .ip6 = try parse6(text) };
    return .{ .ip4 = try parse4(text) };
}

pub fn format4(output: []u8, address: [4]u8) []const u8 {
    assert(output.len >= 15);
    const text = std.fmt.bufPrint(output, "{d}.{d}.{d}.{d}", .{
        address[0], address[1], address[2], address[3],
    }) catch unreachable; // 15 bytes always suffice, asserted above.
    return text;
}

pub fn format6(output: []u8, address: [16]u8) []const u8 {
    assert(output.len >= text_length_max);
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*group, index| {
        group.* = std.mem.readInt(u16, address[index * 2 ..][0..2], .big);
    }
    // Longest run of zero groups of length >= 2, first one on ties (RFC 5952 4.2).
    var best_start: usize = 8;
    var best_length: usize = 1;
    var index: usize = 0;
    while (index < 8) {
        if (groups[index] != 0) {
            index += 1;
            continue;
        }
        const start = index;
        while (index < 8 and groups[index] == 0) index += 1;
        if (index - start > best_length) {
            best_start = start;
            best_length = index - start;
        }
    }
    var writer = std.Io.Writer.fixed(output);
    index = 0;
    while (index < 8) {
        if (index == best_start) {
            writer.writeAll("::") catch unreachable;
            index += best_length;
            continue;
        }
        const after_gap = index == best_start + best_length;
        if (index > 0 and !after_gap) writer.writeByte(':') catch unreachable;
        writer.print("{x}", .{groups[index]}) catch unreachable;
        index += 1;
    }
    assert(writer.end <= text_length_max);
    return writer.buffered();
}

pub fn format(output: []u8, address: Address) []const u8 {
    return switch (address) {
        .ip4 => |value| format4(output, value),
        .ip6 => |value| format6(output, value),
    };
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "ip: ipv4 parse and format" {
    try std.testing.expectEqual([4]u8{ 34, 65, 205, 244 }, try parse4("34.65.205.244"));
    var buffer: [text_length_max]u8 = undefined;
    try std.testing.expectEqualStrings("10.0.0.1", format4(&buffer, .{ 10, 0, 0, 1 }));
    const invalid = [_][]const u8{
        "", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.1.1.1", "1..1.1", "a.b.c.d",
    };
    for (invalid) |bad| {
        try std.testing.expectError(error.InvalidAddress, parse4(bad));
    }
}

test "ip: ipv6 parse and format" {
    var buffer: [text_length_max]u8 = undefined;
    const cases = [_][2][]const u8{
        .{ "::1", "::1" },
        .{ "::", "::" },
        .{ "2001:db8::1", "2001:db8::1" },
        .{ "2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:db8::ff00:42:8329" },
        .{ "fe80::", "fe80::" },
        .{ "1:0:0:2:0:0:0:3", "1:0:0:2::3" },
        .{ "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8" },
        .{ "1:0:2:3:4:5:6:7", "1:0:2:3:4:5:6:7" },
    };
    for (cases) |case| {
        const address = try parse6(case[0]);
        try std.testing.expectEqualStrings(case[1], format6(&buffer, address));
    }
    for ([_][]const u8{ ":", "1:2", "1::2::3", "12345::", "1:2:3:4:5:6:7:8:9", "g::" }) |bad| {
        try std.testing.expectError(error.InvalidAddress, parse6(bad));
    }
}

test "ip: seeded ipv6 round trip" {
    var prng = Prng.init(0x6970);
    var buffer: [text_length_max]u8 = undefined;
    for (0..512) |_| {
        var address: [16]u8 = undefined;
        prng.fill(&address);
        // Zero random groups to exercise compression.
        for (0..8) |group| {
            if (prng.chance(1, 2)) @memset(address[group * 2 ..][0..2], 0);
        }
        try std.testing.expectEqual(address, try parse6(format6(&buffer, address)));
    }
}

fn fuzz_parse(_: void, input: []const u8) anyerror!void {
    const address = parse(input) catch return;
    var buffer: [text_length_max]u8 = undefined;
    const text = format(&buffer, address);
    try std.testing.expectEqual(address, try parse(text));
}

test "ip: fuzz parse" {
    try fuzz.run_bytes({}, fuzz_parse, .{ .input_size_max = 48 });
}

//! Packed protocol versions (base/base `upgrade-signal` `PackedProtocolVersion`).
//!
//! Layout of the 256-bit word, big-endian: byte 0 is the version type (0 = semver), then
//! reserved bytes, then `major:u32 minor:u32 patch:u32 prerelease:u32` in the low 128 bits.
//! Ordering is by `(type, major, minor, patch, prerelease)` where a release (prerelease 0)
//! sorts above every `-rc.N` of the same version; equality uses the same key, so reserved
//! bytes are ignored.

const std = @import("std");
const assert = std.debug.assert;

pub const Version = struct {
    packed_value: u256,

    pub fn pack(major_part: u32, minor_part: u32, patch_part: u32, rc_part: u32) Version {
        const value = (@as(u256, major_part) << 96) | (@as(u256, minor_part) << 64) |
            (@as(u256, patch_part) << 32) | @as(u256, rc_part);
        return .{ .packed_value = value };
    }

    pub fn major(version: Version) u32 {
        return @truncate(version.packed_value >> 96);
    }

    pub fn minor(version: Version) u32 {
        return @truncate(version.packed_value >> 64);
    }

    pub fn patch(version: Version) u32 {
        return @truncate(version.packed_value >> 32);
    }

    pub fn prerelease(version: Version) u32 {
        return @truncate(version.packed_value);
    }

    pub fn version_type(version: Version) u8 {
        return @truncate(version.packed_value >> 248);
    }

    fn ordering_key(version: Version) [5]u64 {
        const rank: u64 = if (version.prerelease() == 0)
            std.math.maxInt(u64)
        else
            version.prerelease();
        return .{ version.version_type(), version.major(), version.minor(), version.patch(), rank };
    }

    pub fn order(a: Version, b: Version) std.math.Order {
        const key_a = a.ordering_key();
        const key_b = b.ordering_key();
        for (key_a, key_b) |x, y| {
            if (x != y) return std.math.order(x, y);
        }
        return .eq;
    }

    pub fn eql(a: Version, b: Version) bool {
        return a.order(b) == .eq;
    }

    /// Parses `major.minor.patch` with an optional `-rc.N` (N > 0).
    pub fn parse(text: []const u8) error{InvalidVersion}!Version {
        var core = text;
        var rc: u32 = 0;
        if (std.mem.find(u8, text, "-rc.")) |dash| {
            core = text[0..dash];
            rc = parse_part(text[dash + "-rc.".len ..]) catch return error.InvalidVersion;
            if (rc == 0) return error.InvalidVersion;
        }
        var parts = std.mem.splitScalar(u8, core, '.');
        var numbers: [3]u32 = undefined;
        for (&numbers) |*number| {
            const part = parts.next() orelse return error.InvalidVersion;
            number.* = parse_part(part) catch return error.InvalidVersion;
        }
        if (parts.next() != null) return error.InvalidVersion;
        return pack(numbers[0], numbers[1], numbers[2], rc);
    }

    fn parse_part(part: []const u8) !u32 {
        if (part.len == 0) return error.InvalidVersion;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidVersion;
        return std.fmt.parseInt(u32, part, 10);
    }

    pub fn format(version: Version, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (version.version_type() != 0) {
            return writer.print("unknown-version-type-{d}", .{version.version_type()});
        }
        try writer.print("{d}.{d}.{d}", .{ version.major(), version.minor(), version.patch() });
        if (version.prerelease() != 0) try writer.print("-rc.{d}", .{version.prerelease()});
    }
};

fn expect_text(expected: []const u8, version: Version) !void {
    var buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{version});
    try std.testing.expectEqualStrings(expected, text);
}

test "upgrade_signal: version fields, format, and parse" {
    const version = Version.pack(1, 2, 3, 4);
    try std.testing.expectEqual(@as(u32, 1), version.major());
    try std.testing.expectEqual(@as(u32, 2), version.minor());
    try std.testing.expectEqual(@as(u32, 3), version.patch());
    try std.testing.expectEqual(@as(u32, 4), version.prerelease());
    try expect_text("1.2.3", Version.pack(1, 2, 3, 0));
    try expect_text("1.2.3-rc.4", version);
    try expect_text("unknown-version-type-2", .{ .packed_value = @as(u256, 2) << 248 });
    try std.testing.expect(Version.pack(1, 2, 3, 4).eql(try Version.parse("1.2.3-rc.4")));
    try expect_text("10.0.7", try Version.parse("10.0.7"));
    const bad = [_][]const u8{
        "",           "1",          "1.2",    "1.2.3.4", "1.2.x",           "1.2.3-rc.",
        "1.2.3-rc.x", "1.2.3-rc.0", "v1.2.3", "+1.2.3",  "1.2.99999999999",
    };
    for (bad) |text| try std.testing.expectError(error.InvalidVersion, Version.parse(text));
}

test "upgrade_signal: release sorts above its prerelease" {
    const release = Version.pack(1, 2, 3, 0);
    const candidate = Version.pack(1, 2, 3, 1);
    try std.testing.expect(candidate.packed_value > release.packed_value);
    try std.testing.expectEqual(std.math.Order.lt, candidate.order(release));
    try std.testing.expectEqual(std.math.Order.lt, release.order(Version.pack(1, 2, 4, 1)));
    // Reserved bytes do not affect equality.
    const reserved: Version = .{ .packed_value = release.packed_value | (@as(u256, 1) << 200) };
    try std.testing.expect(reserved.eql(release));
}

test "upgrade_signal: seeded version round trip" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x5e3);
    for (0..2000) |_| {
        const version = Version.pack(
            @truncate(prng.int(u64)),
            @truncate(prng.below(1000)),
            @truncate(prng.int(u64)),
            if (prng.chance(1, 2)) 0 else @truncate(prng.range(1, 99)),
        );
        var buffer: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "{f}", .{version});
        try std.testing.expect(version.eql(try Version.parse(text)));
    }
}

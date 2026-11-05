//! Method allowlist: a comma-separated list of JSON-RPC method names, copied into fixed
//! storage at startup. An empty list allows every method.

const std = @import("std");
const assert = std.debug.assert;

pub const methods_max = 128;
pub const name_size_max = 64;

pub const Error = error{ TooManyMethods, InvalidMethodName };

pub const Allowlist = struct {
    names: [methods_max][name_size_max]u8 = undefined,
    sizes: [methods_max]u8 = @splat(0),
    count: u32 = 0,

    /// Parses `a,b,c`; entries are trimmed of spaces, empty entries are skipped.
    pub fn parse(text: []const u8) Error!Allowlist {
        var allowlist: Allowlist = .{};
        var entries = std.mem.splitScalar(u8, text, ',');
        // Each entry consumes at least its separator, so input length bounds the loop.
        var iterations: u32 = 0;
        while (entries.next()) |entry| : (iterations += 1) {
            assert(iterations <= text.len);
            const name = std.mem.trim(u8, entry, " \t");
            if (name.len == 0) continue;
            if (!valid_name(name)) return error.InvalidMethodName;
            if (allowlist.contains(name)) continue;
            if (allowlist.count == methods_max) return error.TooManyMethods;
            @memcpy(allowlist.names[allowlist.count][0..name.len], name);
            allowlist.sizes[allowlist.count] = @intCast(name.len);
            allowlist.count += 1;
        }
        assert(allowlist.count <= methods_max);
        return allowlist;
    }

    /// True when the list is empty (no filtering).
    pub fn allows_all(allowlist: *const Allowlist) bool {
        assert(allowlist.count <= methods_max);
        return allowlist.count == 0;
    }

    pub fn allows(allowlist: *const Allowlist, name: []const u8) bool {
        if (allowlist.allows_all()) return true;
        return allowlist.contains(name);
    }

    fn contains(allowlist: *const Allowlist, name: []const u8) bool {
        assert(allowlist.count <= methods_max);
        if (name.len > name_size_max) return false;
        for (0..allowlist.count) |index| {
            if (std.mem.eql(u8, allowlist.entry_name(@intCast(index)), name)) return true;
        }
        return false;
    }

    pub fn entry_name(allowlist: *const Allowlist, index: u32) []const u8 {
        assert(index < allowlist.count);
        const size = allowlist.sizes[index];
        assert(size > 0);
        return allowlist.names[index][0..size];
    }
};

/// Method names: 1..64 bytes of `[A-Za-z0-9_]`.
pub fn valid_name(name: []const u8) bool {
    if (name.len == 0 or name.len > name_size_max) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    return true;
}

const testing = std.testing;

test "allowlist: parse, trim, dedupe, empty allows all" {
    const allowlist = try Allowlist.parse(" eth_chainId, eth_call,,eth_call ,net_version");
    try testing.expectEqual(@as(u32, 3), allowlist.count);
    try testing.expect(allowlist.allows("eth_call"));
    try testing.expect(allowlist.allows("net_version"));
    try testing.expect(!allowlist.allows("eth_sendRawTransaction"));
    try testing.expect(!allowlist.allows("eth_cal"));
    try testing.expect(!allowlist.allows(""));
    const empty = try Allowlist.parse("");
    try testing.expect(empty.allows_all());
    try testing.expect(empty.allows("anything"));
    const blank = try Allowlist.parse(" , ,");
    try testing.expect(blank.allows_all());
}

test "allowlist: rejects bad names and too many entries" {
    try testing.expectError(error.InvalidMethodName, Allowlist.parse("eth_call,eth-call"));
    try testing.expectError(error.InvalidMethodName, Allowlist.parse("a b"));
    const long: [name_size_max + 1]u8 = @splat('a');
    try testing.expectError(error.InvalidMethodName, Allowlist.parse(&long));
    var buffer: [(methods_max + 1) * 6]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    for (0..methods_max + 1) |index| try writer.print("m{d},", .{index});
    try testing.expectError(error.TooManyMethods, Allowlist.parse(writer.buffered()));
}

/// Parsing never crashes; every accepted name is valid and allowed.
fn check_arbitrary(text: []const u8) !void {
    const allowlist = Allowlist.parse(text) catch return;
    for (0..allowlist.count) |index| {
        const entry = allowlist.entry_name(@intCast(index));
        try testing.expect(valid_name(entry));
        try testing.expect(allowlist.allows(entry));
        try testing.expect(std.mem.indexOf(u8, text, entry) != null);
    }
}

test "allowlist: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xa110);
    const alphabet = "abc_,, \t-1";
    var input: [256]u8 = undefined;
    for (0..2000) |_| {
        const size = prng.below(input.len);
        for (input[0..size]) |*byte| byte.* = alphabet[prng.below(alphabet.len)];
        try check_arbitrary(input[0..size]);
    }
}

fn fuzz_parse(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [1024]u8 = undefined;
    const size = smith.slice(&input);
    try check_arbitrary(input[0..size]);
}

test "allowlist: fuzz parse" {
    try testing.fuzz({}, fuzz_parse, .{});
}

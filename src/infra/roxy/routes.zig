//! Method routing for roxy (proxyd `rpc_method_mappings`): a JSON-RPC method may be pinned
//! to a subset of the upstreams, e.g. `eth_sendRawTransaction` to the sequencer only while
//! reads spread over every upstream. Unlisted methods may go to any upstream.
//!
//! Text form: `;`-separated rules, each `METHOD[,METHOD...]=INDEX[|INDEX...]`, where an index
//! is the upstream's position in `--upstreams` (0-based). Example:
//! `eth_sendRawTransaction,eth_sendRawTransactionConditional=0;debug_traceTransaction=2`.
//! Fixed capacity; no allocation.

const std = @import("std");
const assert = std.debug.assert;

const allowlist = @import("allowlist.zig");
const pool = @import("pool.zig");

pub const Mask = pool.Mask;
pub const rules_max = 32;
pub const name_size_max = allowlist.name_size_max;

pub const Error = error{
    InvalidRoute,
    InvalidMethodName,
    TooManyRoutes,
    DuplicateMethod,
    UpstreamIndexTooLarge,
};

pub const Routes = struct {
    names: [rules_max][name_size_max]u8 = undefined,
    name_sizes: [rules_max]u8 = undefined,
    masks: [rules_max]Mask = undefined,
    count: u32 = 0,

    /// Parses the text form; indices must be below `upstream_count`.
    pub fn parse(text: []const u8, upstream_count: u32) Error!Routes {
        assert(upstream_count > 0 and upstream_count <= pool.upstreams_max);
        var routes: Routes = .{};
        var rules = std.mem.splitScalar(u8, text, ';');
        while (rules.next()) |raw_rule| {
            const rule = std.mem.trim(u8, raw_rule, " \t");
            if (rule.len == 0) continue;
            const equals = std.mem.indexOfScalar(u8, rule, '=') orelse return error.InvalidRoute;
            const mask = try parse_mask(rule[equals + 1 ..], upstream_count);
            var names = std.mem.splitScalar(u8, rule[0..equals], ',');
            while (names.next()) |raw_name| {
                const name = std.mem.trim(u8, raw_name, " \t");
                try routes.add(name, mask);
            }
        }
        assert(routes.count <= rules_max);
        return routes;
    }

    fn add(routes: *Routes, name: []const u8, mask: Mask) Error!void {
        assert(mask != 0);
        if (!allowlist.valid_name(name)) return error.InvalidMethodName;
        if (routes.mask_for(name) != null) return error.DuplicateMethod;
        if (routes.count == rules_max) return error.TooManyRoutes;
        const index = routes.count;
        @memcpy(routes.names[index][0..name.len], name);
        routes.name_sizes[index] = @intCast(name.len);
        routes.masks[index] = mask;
        routes.count += 1;
        assert(routes.mask_for(name).? == mask);
    }

    /// The upstreams `name` is pinned to, or null when any upstream may serve it.
    pub fn mask_for(routes: *const Routes, name: []const u8) ?Mask {
        assert(routes.count <= rules_max);
        for (0..routes.count) |index| {
            const stored = routes.names[index][0..routes.name_sizes[index]];
            if (std.mem.eql(u8, stored, name)) return routes.masks[index];
        }
        return null;
    }

    pub fn empty(routes: *const Routes) bool {
        return routes.count == 0;
    }
};

fn parse_mask(text: []const u8, upstream_count: u32) Error!Mask {
    assert(upstream_count <= pool.upstreams_max);
    var mask: Mask = 0;
    var parts = std.mem.splitScalar(u8, text, '|');
    while (parts.next()) |raw| {
        const part = std.mem.trim(u8, raw, " \t");
        const index = std.fmt.parseInt(u32, part, 10) catch return error.InvalidRoute;
        if (index >= upstream_count) return error.UpstreamIndexTooLarge;
        mask |= pool.bit(index);
    }
    if (mask == 0) return error.InvalidRoute;
    return mask;
}

const testing = std.testing;

test "routes: parse and look up" {
    const text = "eth_sendRawTransaction, eth_sendRawTransactionConditional=0; debug_trace=1|2";
    const routes = try Routes.parse(text, 3);
    try testing.expectEqual(@as(u32, 3), routes.count);
    try testing.expectEqual(@as(?Mask, 0b001), routes.mask_for("eth_sendRawTransaction"));
    try testing.expectEqual(@as(?Mask, 0b110), routes.mask_for("debug_trace"));
    try testing.expectEqual(@as(?Mask, null), routes.mask_for("eth_call"));
    try testing.expect((try Routes.parse("", 1)).empty());
}

test "routes: invalid text is rejected" {
    try testing.expectError(error.InvalidRoute, Routes.parse("eth_call", 2));
    try testing.expectError(error.InvalidRoute, Routes.parse("eth_call=", 2));
    try testing.expectError(error.InvalidRoute, Routes.parse("eth_call=x", 2));
    try testing.expectError(error.UpstreamIndexTooLarge, Routes.parse("eth_call=2", 2));
    try testing.expectError(error.InvalidMethodName, Routes.parse("eth-call=0", 2));
    try testing.expectError(error.DuplicateMethod, Routes.parse("a=0;a=1", 2));
}

fn check_parse(text: []const u8) !void {
    const routes = Routes.parse(text, 4) catch return;
    try testing.expect(routes.count <= rules_max);
    for (0..routes.count) |index| {
        const mask = routes.masks[index];
        try testing.expect(mask != 0 and mask & ~pool.mask_all(4) == 0);
    }
}

test "routes: seeded fuzz of the text form" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x2077e5);
    const random = prng.random();
    const alphabet = "ab_=;,|0123 x";
    var buffer: [96]u8 = undefined;
    for (0..2000) |_| {
        const length = random.uintAtMost(usize, buffer.len);
        for (buffer[0..length]) |*byte| byte.* = alphabet[random.uintLessThan(usize, alphabet.len)];
        try check_parse(buffer[0..length]);
    }
}

test "routes: fuzz the text form" {
    try testing.fuzz({}, fuzz_parse, .{});
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [256]u8 = undefined;
    const length = smith.slice(&buffer);
    try check_parse(buffer[0..length]);
}

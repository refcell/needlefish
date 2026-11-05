//! Shadow mode (base/base `--shadow.*`): the batcher posts to a shadow inbox that only a
//! parity validator derives from, follows that validator's derivation instead of the
//! leader's, and compares the validator's derived blocks with the leader's unsafe blocks
//! (`batcher.parity`). Throttling must be off, so a shadow batcher never pushes DA limits
//! to the real sequencers.
//!
//! The batcher reads its rollup config from a file, so that file must be the validator's:
//! its batch inbox must equal `--shadow.inbox` (base/base checks the validator's rollup
//! config the same way).

const std = @import("std");
const base = @import("base");
const batcher = base.batcher;
const HttpTransport = @import("http_transport.zig").HttpTransport;

const assert = std.debug.assert;

pub const Settings = struct {
    enabled: bool = false,
    inbox: ?[20]u8 = null,
    validator_rollup: ?[]const u8 = null,
    validator_l2: ?[]const u8 = null,

    fn any_set(settings: Settings) bool {
        return settings.enabled or settings.inbox != null or settings.validator_rollup != null or
            settings.validator_l2 != null;
    }

    fn all_set(settings: Settings) bool {
        return settings.enabled and settings.inbox != null and settings.validator_rollup != null and
            settings.validator_l2 != null;
    }
};

/// The value flags; `--shadow.enabled` is a switch handled by the caller.
pub fn apply_flag(settings: *Settings, arg: []const u8, value: []const u8) !bool {
    const eql = std.mem.eql;
    if (eql(u8, arg, "--shadow.inbox")) {
        settings.inbox = base.common.primitives.hex.decode_array(20, value) catch
            return error.InvalidShadowInbox;
    } else if (eql(u8, arg, "--shadow.validator-rollup-rpc")) {
        settings.validator_rollup = try checked_url(value);
    } else if (eql(u8, arg, "--shadow.validator-l2-rpc")) {
        settings.validator_l2 = try checked_url(value);
    } else return false;
    return true;
}

fn checked_url(value: []const u8) ![]const u8 {
    const http = std.mem.startsWith(u8, value, "http://");
    if (!http and !std.mem.startsWith(u8, value, "https://")) return error.InvalidShadowUrl;
    return value;
}

/// All four flags together or none; shadow mode needs throttling off.
pub fn validate(settings: Settings, throttle_off: bool) !void {
    if (!settings.any_set()) return;
    if (!settings.all_set()) return error.ShadowFlagsIncomplete;
    if (!throttle_off) return error.ShadowRequiresNoThrottle;
    assert(settings.inbox != null);
}

/// The rollup config's batch inbox must be the shadow inbox.
pub fn check_inbox(settings: Settings, batch_inbox: [20]u8) !void {
    if (!settings.enabled) return;
    if (!std.mem.eql(u8, &settings.inbox.?, &batch_inbox)) return error.ShadowInboxMismatch;
}

/// Validator clients and the parity monitor; heap-allocated (clients hold self pointers).
/// Parity summaries are logged once per this many compared blocks.
const summary_blocks = 100;

pub const Shadow = struct {
    rollup_http: HttpTransport,
    l2_http: HttpTransport,
    rollup: batcher.rpc.Client,
    l2: batcher.rpc.Client,
    monitor: batcher.parity.Monitor = .{},
    mismatches_logged: u32 = 0,
    checked_logged: u32 = 0,

    pub fn init(
        shadow: *Shadow,
        allocator: std.mem.Allocator,
        io: std.Io,
        settings: Settings,
        timeout_ms: u64,
    ) !void {
        assert(settings.all_set());
        shadow.* = .{
            .rollup_http = HttpTransport.init(allocator, io, settings.validator_rollup.?),
            .l2_http = HttpTransport.init(allocator, io, settings.validator_l2.?),
            .rollup = undefined,
            .l2 = undefined,
        };
        errdefer shadow.l2_http.deinit();
        errdefer shadow.rollup_http.deinit();
        shadow.rollup_http.timeout_ms = timeout_ms;
        shadow.l2_http.timeout_ms = timeout_ms;
        shadow.rollup = try .init(allocator, shadow.rollup_http.transport(), .{});
        errdefer shadow.rollup.deinit(allocator);
        shadow.l2 = try .init(allocator, shadow.l2_http.transport(), .{});
    }

    pub fn deinit(shadow: *Shadow, allocator: std.mem.Allocator) void {
        shadow.l2.deinit(allocator);
        shadow.rollup.deinit(allocator);
        shadow.l2_http.deinit();
        shadow.rollup_http.deinit();
    }

    /// One parity pass against the leader's L2 RPC; logs new mismatches only.
    pub fn check(shadow: *Shadow, leader_l2: *batcher.rpc.Client) void {
        const stats = shadow.monitor.step(leader_l2, &shadow.l2) catch |err| {
            std.debug.print("batcher: parity pass failed: {t}\n", .{err});
            return;
        };
        const totals = shadow.monitor.totals;
        if (totals.checked / summary_blocks != shadow.checked_logged / summary_blocks) {
            shadow.checked_logged = totals.checked;
            std.debug.print("batcher: parity: {d} blocks compared, {d} match, next {d}\n", .{
                totals.checked, totals.matches, shadow.monitor.next_block.?,
            });
        }
        if (stats.missing > 0) {
            std.debug.print("batcher: parity: {d} blocks missing on one side\n", .{stats.missing});
        }
        if (shadow.monitor.totals.mismatches == shadow.mismatches_logged) return;
        shadow.mismatches_logged = shadow.monitor.totals.mismatches;
        const mismatch = shadow.monitor.last_mismatch.?;
        std.debug.print("batcher: PARITY MISMATCH at L2 block {d}: leader 0x{x} validator 0x{x}" ++
            " ({d} total)\n", .{
            mismatch.number,
            &mismatch.sequencer,
            &mismatch.validator,
            shadow.monitor.totals.mismatches,
        });
    }
};

const testing = std.testing;

test "shadow: flags together or not at all, and only without throttling" {
    var settings: Settings = .{};
    try validate(settings, false);
    const inbox = "0x" ++ "abababababababababababababababababababab";
    try testing.expect(try apply_flag(&settings, "--shadow.inbox", inbox));
    try testing.expectError(error.ShadowFlagsIncomplete, validate(settings, true));
    settings.enabled = true;
    _ = try apply_flag(&settings, "--shadow.validator-rollup-rpc", "http://v:7545");
    _ = try apply_flag(&settings, "--shadow.validator-l2-rpc", "http://v:8545");
    try testing.expectError(error.ShadowRequiresNoThrottle, validate(settings, false));
    try validate(settings, true);
    try check_inbox(settings, @splat(0xab));
    try testing.expectError(error.ShadowInboxMismatch, check_inbox(settings, @splat(0xff)));
    try testing.expect(!try apply_flag(&settings, "--l1", "x"));
    const bad_inbox = apply_flag(&settings, "--shadow.inbox", "0x12");
    try testing.expectError(error.InvalidShadowInbox, bad_inbox);
    const bad_url = apply_flag(&settings, "--shadow.validator-l2-rpc", "v:8545");
    try testing.expectError(error.InvalidShadowUrl, bad_url);
}

test "shadow: seeded fuzz of flag combinations" {
    var prng = base.testing.Prng.init(0x5ad0);
    const inbox = "0x" ++ "1111111111111111111111111111111111111111";
    const values = [_][]const u8{ inbox, "http://v:1", "https://v:2", "x", "" };
    const names = [_][]const u8{
        "--shadow.inbox", "--shadow.validator-rollup-rpc", "--shadow.validator-l2-rpc",
    };
    for (0..2000) |_| {
        var settings: Settings = .{ .enabled = prng.chance(1, 2) };
        for (0..prng.below(4)) |_| {
            const name = names[prng.below(names.len)];
            _ = apply_flag(&settings, name, values[prng.below(values.len)]) catch {};
        }
        const throttle_off = prng.chance(1, 2);
        if (validate(settings, throttle_off)) {
            try testing.expect(!settings.any_set() or (settings.all_set() and throttle_off));
        } else |_| try testing.expect(settings.any_set());
    }
}

test "shadow: fuzz flag values" {
    try testing.fuzz({}, fuzz_flag_value, .{});
}

fn fuzz_flag_value(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [64]u8 = undefined;
    const value = buffer[0..smith.slice(&buffer)];
    var settings: Settings = .{};
    if (apply_flag(&settings, "--shadow.inbox", value)) |_| {
        try testing.expect(settings.inbox != null);
    } else |_| try testing.expect(settings.inbox == null);
    if (apply_flag(&settings, "--shadow.validator-l2-rpc", value)) |_| {
        try testing.expect(std.mem.startsWith(u8, settings.validator_l2.?, "http"));
    } else |_| try testing.expect(settings.validator_l2 == null);
}

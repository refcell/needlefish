//! Proposer configuration from command-line flags (base/base
//! `crates/proof/proposer/src/{cli,config}.rs`): the flag names, defaults and validation
//! rules of `ProposerConfig::from_cli`, without logging, metrics, health and admin
//! settings, and with a raw private key instead of a remote signer.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");

pub const Address = [20]u8;

pub const Error = error{
    UnknownFlag,
    MissingValue,
    MissingFlag,
    InvalidValue,
    /// `--anchor-state-registry-addr` / `--dispute-game-factory-addr` of zero.
    ZeroAddress,
    /// `--poll-interval 0`.
    ZeroPollInterval,
    /// Neither `--private-key` nor `--dry-run`.
    MissingSigner,
};

pub const Config = struct {
    dry_run: bool = false,
    prover_rpc: []const u8 = "",
    l1_eth_rpc: []const u8 = "",
    l2_eth_rpc: []const u8 = "",
    rollup_rpc: []const u8 = "",
    anchor_state_registry: Address = @splat(0),
    dispute_game_factory: Address = @splat(0),
    game_type: ?u32 = null,
    poll_interval_ms: u64 = 12_000,
    rpc_timeout_ms: u64 = 30_000,
    private_key: ?[32]u8 = null,
};

/// Durations up to one day: `500ms`, `12s`, `2m`, `1h`, or bare seconds.
pub fn parse_duration_ms(text: []const u8) Error!u64 {
    const units = [_]struct { suffix: []const u8, ms: u64 }{
        .{ .suffix = "ms", .ms = 1 },
        .{ .suffix = "s", .ms = std.time.ms_per_s },
        .{ .suffix = "m", .ms = std.time.ms_per_min },
        .{ .suffix = "h", .ms = std.time.ms_per_hour },
    };
    var number = text;
    var unit_ms: u64 = std.time.ms_per_s;
    for (units) |unit| {
        if (std.mem.endsWith(u8, text, unit.suffix)) {
            number = text[0 .. text.len - unit.suffix.len];
            unit_ms = unit.ms;
            break;
        }
    }
    const value = std.fmt.parseUnsigned(u64, number, 10) catch return error.InvalidValue;
    const ms = std.math.mul(u64, value, unit_ms) catch return error.InvalidValue;
    if (ms > std.time.ms_per_day) return error.InvalidValue;
    assert(ms <= std.time.ms_per_day);
    return ms;
}

const Flag = enum {
    dry_run,
    prover_rpc,
    l1_eth_rpc,
    l2_eth_rpc,
    rollup_rpc,
    anchor_state_registry_addr,
    dispute_game_factory_addr,
    game_type,
    poll_interval,
    rpc_timeout,
    private_key,
};

fn flag_of(name: []const u8) Error!Flag {
    if (!std.mem.startsWith(u8, name, "--")) return error.UnknownFlag;
    var buffer: [64]u8 = undefined;
    if (name.len - 2 > buffer.len) return error.UnknownFlag;
    const field = buffer[0 .. name.len - 2];
    for (name[2..], field) |char, *out| out.* = if (char == '-') '_' else char;
    return std.meta.stringToEnum(Flag, field) orelse error.UnknownFlag;
}

/// Parses and validates `args` (flag/value pairs; `--dry-run` takes no value).
pub fn parse(args: []const []const u8) Error!Config {
    var config: Config = .{};
    var index: usize = 0;
    while (index < args.len) {
        const flag = try flag_of(args[index]);
        if (flag == .dry_run) {
            config.dry_run = true;
            index += 1;
            continue;
        }
        if (index + 1 == args.len) return error.MissingValue;
        try set(&config, flag, args[index + 1]);
        index += 2;
    }
    assert(index == args.len);
    try validate(&config);
    return config;
}

fn set(config: *Config, flag: Flag, value: []const u8) Error!void {
    assert(flag != .dry_run);
    switch (flag) {
        .dry_run => unreachable,
        .prover_rpc => config.prover_rpc = value,
        .l1_eth_rpc => config.l1_eth_rpc = value,
        .l2_eth_rpc => config.l2_eth_rpc = value,
        .rollup_rpc => config.rollup_rpc = value,
        .anchor_state_registry_addr => config.anchor_state_registry = try parse_fixed(20, value),
        .dispute_game_factory_addr => config.dispute_game_factory = try parse_fixed(20, value),
        .game_type => config.game_type = std.fmt.parseUnsigned(u32, value, 10) catch
            return error.InvalidValue,
        .poll_interval => config.poll_interval_ms = try parse_duration_ms(value),
        .rpc_timeout => config.rpc_timeout_ms = try parse_duration_ms(value),
        .private_key => config.private_key = try parse_fixed(32, value),
    }
}

fn parse_fixed(comptime size: usize, text: []const u8) Error![size]u8 {
    return json.parse_fixed(size, text) catch error.InvalidValue;
}

/// base/base `ProposerConfig::from_cli` checks.
fn validate(config: *const Config) Error!void {
    const urls = [_][]const u8{
        config.prover_rpc, config.l1_eth_rpc, config.l2_eth_rpc, config.rollup_rpc,
    };
    for (urls) |url| if (url.len == 0) return error.MissingFlag;
    if (config.game_type == null) return error.MissingFlag;
    // Zero is the "no parent" sentinel of the first game after the anchor.
    if (std.mem.allEqual(u8, &config.anchor_state_registry, 0)) return error.ZeroAddress;
    if (std.mem.allEqual(u8, &config.dispute_game_factory, 0)) return error.ZeroAddress;
    if (config.poll_interval_ms == 0) return error.ZeroPollInterval;
    if (config.rpc_timeout_ms == 0) return error.InvalidValue;
    if (!config.dry_run and config.private_key == null) return error.MissingSigner;
}

const testing = std.testing;

const registry_hex = "0x00000000000000000000000000000000000000a5";
const factory_hex = "0x00000000000000000000000000000000000000fa";

const required = [_][]const u8{
    "--prover-rpc",                 "http://127.0.0.1:7300",
    "--l1-eth-rpc",                 "http://127.0.0.1:8545",
    "--l2-eth-rpc",                 "http://127.0.0.1:9545",
    "--rollup-rpc",                 "http://127.0.0.1:8547",
    "--anchor-state-registry-addr", registry_hex,
    "--dispute-game-factory-addr",  factory_hex,
    "--game-type",                  "621",
};

test "proposer config: flags, defaults and validation" {
    const dry = try parse(&(required ++ [_][]const u8{"--dry-run"}));
    try testing.expect(dry.dry_run);
    try testing.expectEqual(@as(u64, 12_000), dry.poll_interval_ms);
    try testing.expectEqual(@as(?u32, 621), dry.game_type);
    try testing.expectEqual(@as(u8, 0xa5), dry.anchor_state_registry[19]);
    try testing.expectError(error.MissingSigner, parse(&required));
    const key = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const signed = try parse(&(required ++ [_][]const u8{
        "--private-key", key, "--poll-interval", "500ms", "--rpc-timeout", "2m",
    }));
    try testing.expectEqual(@as(u8, 0x11), signed.private_key.?[31]);
    try testing.expectEqual(@as(u64, 500), signed.poll_interval_ms);
    try testing.expectEqual(@as(u64, 120_000), signed.rpc_timeout_ms);
    try testing.expectError(error.MissingFlag, parse(&.{"--dry-run"}));
    try testing.expectError(error.UnknownFlag, parse(&.{"--nope"}));
    try testing.expectError(error.MissingValue, parse(&.{"--game-type"}));
    try testing.expectError(error.ZeroPollInterval, parse(&(required ++ [_][]const u8{
        "--dry-run", "--poll-interval", "0s",
    })));
    const zero = "0x0000000000000000000000000000000000000000";
    try testing.expectError(error.ZeroAddress, parse(&(required ++ [_][]const u8{
        "--dry-run", "--anchor-state-registry-addr", zero,
    })));
}

test "proposer config: durations" {
    try testing.expectEqual(@as(u64, 12_000), try parse_duration_ms("12s"));
    try testing.expectEqual(@as(u64, 12_000), try parse_duration_ms("12"));
    try testing.expectEqual(@as(u64, std.time.ms_per_hour), try parse_duration_ms("1h"));
    for ([_][]const u8{ "", "s", "-1s", "25h", "1.5s", "99999999999999999999ms" }) |bad| {
        try testing.expectError(error.InvalidValue, parse_duration_ms(bad));
    }
}

test "proposer config: fuzz flag parsing" {
    const fuzz = @import("../../testing/fuzz.zig");
    const names = [_][]const u8{
        "--dry-run",
        "--game-type",
        "--poll-interval",
        "--rpc-timeout",
        "--private-key",
        "--prover-rpc",
        "--anchor-state-registry-addr",
        "--bogus",
    };
    const values = [_][]const u8{ "0", "621", "12s", "0x11", registry_hex, "", "http://x:1" };
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var args: [12][]const u8 = undefined;
            const count = smith.index(args.len + 1);
            for (args[0..count], 0..) |*arg, position| {
                const is_name = position % 2 == 0;
                const name = names[smith.index(names.len)];
                arg.* = if (is_name) name else values[smith.index(values.len)];
            }
            const config = parse(args[0..count]) catch return;
            // Whatever parses is valid.
            try testing.expect(config.poll_interval_ms > 0);
            try testing.expect(config.dry_run or config.private_key != null);
            try testing.expect(!std.mem.allEqual(u8, &config.anchor_state_registry, 0));
        }
    }.one, .{ .iterations = 3000 });
}

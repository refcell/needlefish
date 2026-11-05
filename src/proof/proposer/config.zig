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

pub const ProofType = enum { tee, compressed };

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
    /// `--prover-rpc native` proves in-process (`native_prover.zig`) over the L1/L2
    /// endpoints, booting with this rollup config file (required then).
    rollup_config: []const u8 = "",
    /// Custom L1 chains only, with the native prover: the L1 genesis JSON file.
    l1_genesis: []const u8 = "",
    /// With the native prover: the L1 beacon API for blob batches (without it blob reads
    /// fail).
    l1_beacon: []const u8 = "",
    /// What a prover service is asked for: `tee` (base/base, AWS Nitro) or `compressed`
    /// (range jobs that `base prover-worker` proves natively).
    prover_proof_type: ProofType = .tee,
    /// Stop after this many poll intervals (smoke tests); runs forever when null.
    ticks_max: ?u64 = null,
    /// Liveness, readiness and metrics (`exporter.zig`) on `--health.addr`/`--health.port`
    /// (base/base defaults; port 0 disables), and on the metrics port when
    /// `--metrics.enabled`; both serve the same endpoints.
    health_addr: [4]u8 = @splat(0),
    health_port: u16 = 8080,
    metrics_enabled: bool = false,
    metrics_addr: [4]u8 = @splat(0),
    metrics_port: u16 = 7300,
    /// The admin JSON-RPC (`admin.zig`) when `--rpc.enable-admin`, on `--rpc.addr`
    /// `--rpc.port` (base/base defaults).
    rpc_enable_admin: bool = false,
    rpc_addr: [4]u8 = .{ 127, 0, 0, 1 },
    rpc_port: u16 = 8545,

    pub fn native_prover(config: *const Config) bool {
        return std.mem.eql(u8, config.prover_rpc, "native");
    }
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
    rollup_config,
    l1_genesis,
    l1_beacon,
    prover_proof_type,
    ticks_max,
    health_addr,
    health_port,
    metrics_enabled,
    metrics_addr,
    metrics_port,
    rpc_enable_admin,
    rpc_addr,
    rpc_port,
};

fn flag_of(name: []const u8) Error!Flag {
    if (!std.mem.startsWith(u8, name, "--")) return error.UnknownFlag;
    var buffer: [64]u8 = undefined;
    if (name.len - 2 > buffer.len) return error.UnknownFlag;
    const field = buffer[0 .. name.len - 2];
    for (name[2..], field) |char, *out| out.* = if (char == '-' or char == '.') '_' else char;
    return std.meta.stringToEnum(Flag, field) orelse error.UnknownFlag;
}

/// Flags without a value.
fn is_switch(flag: Flag) bool {
    return flag == .dry_run or flag == .metrics_enabled or flag == .rpc_enable_admin;
}

/// Parses and validates `args` (flag/value pairs; `is_switch` flags take no value).
pub fn parse(args: []const []const u8) Error!Config {
    var config: Config = .{};
    var index: usize = 0;
    while (index < args.len) {
        const flag = try flag_of(args[index]);
        if (is_switch(flag)) {
            switch (flag) {
                .dry_run => config.dry_run = true,
                .metrics_enabled => config.metrics_enabled = true,
                .rpc_enable_admin => config.rpc_enable_admin = true,
                else => unreachable,
            }
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
    assert(!is_switch(flag));
    switch (flag) {
        .dry_run, .metrics_enabled, .rpc_enable_admin => unreachable,
        .rpc_addr => config.rpc_addr = try parse_ip4(value),
        .rpc_port => config.rpc_port = std.fmt.parseUnsigned(u16, value, 10) catch
            return error.InvalidValue,
        .health_addr => config.health_addr = try parse_ip4(value),
        .metrics_addr => config.metrics_addr = try parse_ip4(value),
        .health_port => config.health_port = std.fmt.parseUnsigned(u16, value, 10) catch
            return error.InvalidValue,
        .metrics_port => config.metrics_port = std.fmt.parseUnsigned(u16, value, 10) catch
            return error.InvalidValue,
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
        .rollup_config => config.rollup_config = value,
        .l1_genesis => config.l1_genesis = value,
        .l1_beacon => config.l1_beacon = value,
        .prover_proof_type => config.prover_proof_type =
            std.meta.stringToEnum(ProofType, value) orelse return error.InvalidValue,
        .ticks_max => config.ticks_max = std.fmt.parseUnsigned(u64, value, 10) catch
            return error.InvalidValue,
    }
}

fn parse_ip4(text: []const u8) Error![4]u8 {
    var bytes: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&bytes) |*byte| {
        byte.* = std.fmt.parseUnsigned(u8, parts.next() orelse "", 10) catch
            return error.InvalidValue;
    }
    if (parts.next() != null) return error.InvalidValue;
    assert(text.len >= 7);
    return bytes;
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
    if (config.native_prover() and config.rollup_config.len == 0) return error.MissingFlag;
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
    const native_args = [_][]const u8{ "--dry-run", "--prover-rpc", "native" };
    try testing.expectError(error.MissingFlag, parse(&(required ++ native_args)));
    const native = try parse(&(required ++ native_args ++ [_][]const u8{
        "--rollup-config", "rollup.json", "--ticks-max", "3", "--l1-beacon", "http://b:1",
    }));
    try testing.expectEqualStrings("http://b:1", native.l1_beacon);
    try testing.expectEqual(ProofType.tee, native.prover_proof_type);
    const compressed = try parse(&(required ++ [_][]const u8{
        "--dry-run", "--prover-proof-type", "compressed",
    }));
    try testing.expectEqual(ProofType.compressed, compressed.prover_proof_type);
    try testing.expectError(error.InvalidValue, parse(&(required ++ [_][]const u8{
        "--dry-run", "--prover-proof-type", "snark",
    })));
    try testing.expect(native.native_prover());
    try testing.expectEqual(@as(?u64, 3), native.ticks_max);
    try testing.expectError(error.UnknownFlag, parse(&.{"--nope"}));
    try testing.expectEqual(@as(u16, 8080), dry.health_port);
    try testing.expect(!dry.metrics_enabled);
    const served = try parse(&(required ++ [_][]const u8{
        "--dry-run",     "--metrics.enabled", "--metrics.port", "9300",
        "--health.addr", "127.0.0.1",         "--health.port",  "0",
    }));
    try testing.expect(served.metrics_enabled);
    try testing.expect(!served.rpc_enable_admin);
    const admin = try parse(&(required ++ [_][]const u8{
        "--dry-run", "--rpc.enable-admin", "--rpc.port", "18545",
    }));
    try testing.expect(admin.rpc_enable_admin);
    try testing.expectEqual(@as(u16, 18545), admin.rpc_port);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, admin.rpc_addr);
    try testing.expectEqual(@as(u16, 9300), served.metrics_port);
    try testing.expectEqual(@as(u16, 0), served.health_port);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, served.health_addr);
    try testing.expectError(error.InvalidValue, parse(&(required ++ [_][]const u8{
        "--dry-run", "--health.addr", "127.0.0",
    })));
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

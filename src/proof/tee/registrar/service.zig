//! Registrar configuration (base/base `bin/prover-registrar/src/cli.rs` and
//! `registrar/src/service.rs` `RegistrarConfig`): flag names and defaults, validation, and
//! the signer-manager and driver configurations derived from them.
//!
//! Differences from base/base: `--prover-endpoints url1,url2` replaces AWS discovery
//! (`--target-group-arn`, `--aws-region`, `--prover-port`); the signer is a raw
//! `--private-key` or, for devnets, `--dev-key-index N` of the public dev mnemonic,
//! instead of a remote signer; `--max-concurrency` is accepted for compatibility and
//! unused, since registrations run one at a time. Environment variables are not read.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../../utilities/json/root.zig");
const proposer_config = @import("../../proposer/config.zig");
const types = @import("types.zig");
const driver_module = @import("driver.zig");
const discovery_module = @import("discovery.zig");
const signer_manager = @import("signer_manager.zig");

const Address = types.Address;

pub const Error = error{
    UnknownFlag,
    MissingValue,
    MissingFlag,
    InvalidValue,
    ZeroAddress,
    ConflictingSigner,
} || discovery_module.ParseError;

pub const RegistrarConfig = struct {
    l1_rpc_url: []const u8 = "",
    tee_prover_registry_address: Address = @splat(0),
    prover_endpoints: []const u8 = "",
    max_attestation_age_s: u64 = 3300,
    poll_interval_s: u64 = 30,
    prover_timeout_s: u64 = 30,
    max_concurrency: u32 = 4,
    instance_cache_ttl_cycles: u32 = driver_module.default_instance_cache_ttl_cycles,
    max_tx_retries: u32 = signer_manager.default_max_tx_retries,
    tx_retry_delay_s: u64 = signer_manager.default_tx_retry_delay_ms / std.time.ms_per_s,
    /// Enables CRL checks in base/base.
    crl_nitro_verifier_address: ?Address = null,
    private_key: ?[32]u8 = null,
    dev_key_index: ?u32 = null,
    /// Stop after this many poll intervals (smoke tests); runs forever when null.
    ticks_max: ?u64 = null,
    health_addr: [4]u8 = @splat(0),
    health_port: u16 = 8080,
    metrics_enabled: bool = false,
    metrics_addr: [4]u8 = @splat(0),
    metrics_port: u16 = 7300,

    pub fn driver_config(config: *const RegistrarConfig) driver_module.Config {
        assert(config.poll_interval_s > 0);
        return .{
            .poll_interval_ms = config.poll_interval_s * std.time.ms_per_s,
            .instance_cache_ttl_cycles = config.instance_cache_ttl_cycles,
        };
    }

    /// The signer-manager configuration for the resolved `CertManager`.
    pub fn signer_manager_config(
        config: *const RegistrarConfig,
        cert_manager: Address,
    ) signer_manager.Config {
        assert(!std.mem.allEqual(u8, &cert_manager, 0));
        assert(config.tx_retry_delay_s > 0);
        return .{
            .registry_address = config.tee_prover_registry_address,
            .cert_manager_address = cert_manager,
            .max_tx_retries = config.max_tx_retries,
            .tx_retry_delay_ms = config.tx_retry_delay_s * std.time.ms_per_s,
            .max_attestation_age_s = config.max_attestation_age_s,
        };
    }
};

const Flag = enum {
    l1_rpc_url,
    tee_prover_registry_address,
    prover_endpoints,
    max_attestation_age_secs,
    poll_interval_secs,
    prover_timeout_secs,
    max_concurrency,
    instance_cache_ttl_cycles,
    max_tx_retries,
    tx_retry_delay_secs,
    crl_nitro_verifier_address,
    private_key,
    dev_key_index,
    ticks_max,
    health_addr,
    health_port,
    metrics_enabled,
    metrics_addr,
    metrics_port,
};

fn flag_of(name: []const u8) Error!Flag {
    if (!std.mem.startsWith(u8, name, "--")) return error.UnknownFlag;
    var buffer: [64]u8 = undefined;
    if (name.len - 2 > buffer.len) return error.UnknownFlag;
    const field = buffer[0 .. name.len - 2];
    for (name[2..], field) |char, *out| out.* = if (char == '-' or char == '.') '_' else char;
    return std.meta.stringToEnum(Flag, field) orelse error.UnknownFlag;
}

/// Parses flag/value pairs (`--metrics.enabled` takes no value) and validates them.
pub fn parse(args: []const []const u8) Error!RegistrarConfig {
    var config: RegistrarConfig = .{};
    var index: usize = 0;
    while (index < args.len) {
        const flag = try flag_of(args[index]);
        if (flag == .metrics_enabled) {
            config.metrics_enabled = true;
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

fn set(config: *RegistrarConfig, flag: Flag, value: []const u8) Error!void {
    assert(flag != .metrics_enabled);
    switch (flag) {
        .metrics_enabled => unreachable,
        .l1_rpc_url => config.l1_rpc_url = value,
        .tee_prover_registry_address => config.tee_prover_registry_address = try fixed(20, value),
        .prover_endpoints => config.prover_endpoints = value,
        .max_attestation_age_secs => config.max_attestation_age_s = try unsigned(u64, value),
        .poll_interval_secs => config.poll_interval_s = try unsigned(u64, value),
        .prover_timeout_secs => config.prover_timeout_s = try unsigned(u64, value),
        .max_concurrency => config.max_concurrency = try unsigned(u32, value),
        .instance_cache_ttl_cycles => config.instance_cache_ttl_cycles = try unsigned(u32, value),
        .max_tx_retries => config.max_tx_retries = try unsigned(u32, value),
        .tx_retry_delay_secs => config.tx_retry_delay_s = try unsigned(u64, value),
        .crl_nitro_verifier_address => config.crl_nitro_verifier_address = try fixed(20, value),
        .private_key => config.private_key = try fixed(32, value),
        .dev_key_index => config.dev_key_index = try unsigned(u32, value),
        .ticks_max => config.ticks_max = try unsigned(u64, value),
        .health_addr => config.health_addr = try ip4(value),
        .metrics_addr => config.metrics_addr = try ip4(value),
        .health_port => config.health_port = try unsigned(u16, value),
        .metrics_port => config.metrics_port = try unsigned(u16, value),
    }
}

fn ip4(value: []const u8) Error![4]u8 {
    return proposer_config.parse_ip4(value) catch error.InvalidValue;
}

fn unsigned(comptime T: type, value: []const u8) Error!T {
    return std.fmt.parseUnsigned(T, value, 10) catch error.InvalidValue;
}

fn fixed(comptime size: usize, text: []const u8) Error![size]u8 {
    return json.parse_fixed(size, text) catch error.InvalidValue;
}

fn validate(config: *const RegistrarConfig) Error!void {
    if (config.l1_rpc_url.len == 0 or config.prover_endpoints.len == 0) {
        return error.MissingFlag;
    }
    if (std.mem.allEqual(u8, &config.tee_prover_registry_address, 0)) return error.MissingFlag;
    if (config.private_key == null and config.dev_key_index == null) return error.MissingFlag;
    if (config.private_key != null and config.dev_key_index != null) {
        return error.ConflictingSigner;
    }
    if (config.crl_nitro_verifier_address) |address| {
        if (std.mem.allEqual(u8, &address, 0)) return error.ZeroAddress;
    }
    if (config.max_attestation_age_s == 0 or config.poll_interval_s == 0) {
        return error.InvalidValue;
    }
    if (config.prover_timeout_s == 0 or config.tx_retry_delay_s == 0) return error.InvalidValue;
    if (config.max_concurrency == 0) return error.InvalidValue;
    _ = try discovery_module.StaticDiscovery.parse(config.prover_endpoints);
}

const testing = std.testing;

const registry_text = "0x" ++ "1111111111" ++ "1111111111" ++ "1111111111" ++ "1111111111";
const key_text = "0x" ++ ("2222222222222222" ++ "2222222222222222") ++
    ("2222222222222222" ++ "2222222222222222");

const base_args = [_][]const u8{
    "--l1-rpc-url",                  "http://127.0.0.1:8545",
    "--tee-prover-registry-address", registry_text,
    "--prover-endpoints",            "http://10.0.0.5:8000,http://10.0.0.6:8000",
    "--dev-key-index",               "3",
};

test "registrar config: base/base flag names and defaults" {
    const config = try parse(&base_args);
    try testing.expectEqual(@as(u64, 3300), config.max_attestation_age_s);
    try testing.expectEqual(@as(u64, 30_000), config.driver_config().poll_interval_ms);
    try testing.expectEqual(@as(u32, 5), config.instance_cache_ttl_cycles);
    try testing.expectEqual(@as(u32, 3), config.dev_key_index.?);
    const manager = config.signer_manager_config(@splat(0x22));
    try testing.expectEqual(@as(u64, 5000), manager.tx_retry_delay_ms);
    try testing.expectEqual(@as(Address, @splat(0x11)), manager.registry_address);
    const tuned = base_args ++ [_][]const u8{
        "--poll-interval-secs", "6",              "--max-tx-retries", "1",
        "--metrics.enabled",    "--metrics.port", "9301",
    };
    const changed = try parse(&tuned);
    try testing.expectEqual(@as(u64, 6), changed.poll_interval_s);
    try testing.expectEqual(@as(u32, 1), changed.max_tx_retries);
    try testing.expect(changed.metrics_enabled);
    try testing.expectEqual(@as(u16, 9301), changed.metrics_port);
}

test "registrar config: rejects missing and conflicting settings" {
    try testing.expectError(error.MissingFlag, parse(base_args[0..6]));
    try testing.expectError(error.UnknownFlag, parse(&.{ "--target-group-arn", "arn" }));
    try testing.expectError(error.MissingValue, parse(&.{"--l1-rpc-url"}));
    const both = base_args ++ [_][]const u8{ "--private-key", key_text };
    try testing.expectError(error.ConflictingSigner, parse(&both));
    const zero_age = base_args ++ [_][]const u8{ "--max-attestation-age-secs", "0" };
    try testing.expectError(error.InvalidValue, parse(&zero_age));
    var bad_endpoints = base_args;
    bad_endpoints[5] = "ftp://10.0.0.5";
    try testing.expectError(error.InvalidEndpoint, parse(&bad_endpoints));
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    const words = [_][]const u8{
        "--l1-rpc-url",      "--prover-endpoints", "--dev-key-index",  "--poll-interval-secs",
        "--metrics.enabled", "http://10.0.0.1:1",  "3",                "0",
        "--private-key",     "0x11",               "--max-tx-retries", "",
    };
    var args: [8][]const u8 = undefined;
    const count = smith.index(args.len);
    for (args[0..count]) |*arg| arg.* = words[smith.index(words.len)];
    const config = parse(args[0..count]) catch return;
    try testing.expect(config.poll_interval_s > 0);
    try testing.expect(config.l1_rpc_url.len > 0);
}

test "registrar config: fuzz parse" {
    const fuzz = @import("../../../testing/fuzz.zig");
    try fuzz.run({}, fuzz_parse, .{ .iterations = 2000 });
}

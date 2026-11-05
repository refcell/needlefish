//! Challenger command-line flags (base/base `crates/proof/challenge/src/cli.rs`): names,
//! defaults and the `ChallengerConfig::from_cli` checks, with a raw private key instead of
//! a remote signer and without metrics/health settings.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const proposer_config = @import("../proposer/config.zig");
const bond = @import("bond.zig");
const chain = @import("chain.zig");
const config_module = @import("config.zig");

const Address = chain.Address;

pub const Error = error{
    UnknownFlag,
    MissingValue,
    MissingFlag,
    InvalidValue,
    ZeroAddress,
    TooManyClaimAddresses,
} || config_module.Config.Error;

pub const Flags = struct {
    l1_eth_rpc: []const u8 = "",
    l2_eth_rpc: []const u8 = "",
    /// The prover service (base/base `--zk-rpc-url`); disputes need it.
    zk_rpc_url: []const u8 = "",
    dispute_game_factory: Address = @splat(0),
    anchor_state_registry: Address = @splat(0),
    game_type: ?u32 = null,
    poll_interval_ms: u64 = 12_000,
    zk_request_timeout_ms: u64 = 30_000,
    max_proof_duration_ms: u64 = 4 * std.time.ms_per_hour,
    tee_submit_retry_limit: u32 = 3,
    bond_lookback_games: u64 = 1000,
    bond_discovery_interval_ms: u64 = 300_000,
    bond_claim_addresses: [bond.claim_addresses_max]Address = undefined,
    bond_claim_count: u32 = 0,
    private_key: ?[32]u8 = null,
    /// Stop after this many poll intervals (smoke tests); runs forever when null.
    ticks_max: ?u64 = null,

    pub fn claim_addresses(flags: *const Flags) []const Address {
        assert(flags.bond_claim_count <= bond.claim_addresses_max);
        return flags.bond_claim_addresses[0..flags.bond_claim_count];
    }

    /// The driver configuration; `sender` is the private key's address.
    pub fn driver_config(flags: *const Flags, sender: Address) config_module.Config {
        assert(flags.game_type != null);
        return .{
            .game_type = flags.game_type.?,
            .sender = sender,
            .anchor_state_registry = flags.anchor_state_registry,
            .poll_interval_ns = flags.poll_interval_ms * std.time.ns_per_ms,
            .max_proof_duration_ns = flags.max_proof_duration_ms * std.time.ns_per_ms,
            .tee_submit_retry_limit = flags.tee_submit_retry_limit,
            .bond_claim_addresses = flags.claim_addresses(),
            .bond_lookback_games = flags.bond_lookback_games,
            .bond_discovery_interval_ns = flags.bond_discovery_interval_ms * std.time.ns_per_ms,
        };
    }
};

const Flag = enum {
    l1_eth_rpc,
    l2_eth_rpc,
    zk_rpc_url,
    dispute_game_factory_addr,
    anchor_state_registry_addr,
    game_type,
    poll_interval,
    zk_request_timeout,
    max_proof_duration,
    tee_submit_retry_limit,
    bond_discovery_lookback_games,
    bond_discovery_interval,
    bond_claim_addresses,
    private_key,
    ticks_max,
};

fn flag_of(name: []const u8) Error!Flag {
    if (!std.mem.startsWith(u8, name, "--")) return error.UnknownFlag;
    var buffer: [64]u8 = undefined;
    if (name.len - 2 > buffer.len) return error.UnknownFlag;
    const field = buffer[0 .. name.len - 2];
    for (name[2..], field) |char, *out| out.* = if (char == '-') '_' else char;
    return std.meta.stringToEnum(Flag, field) orelse error.UnknownFlag;
}

/// Parses flag/value pairs and validates them as base/base does.
pub fn parse(args: []const []const u8) Error!Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        const flag = try flag_of(args[index]);
        if (index + 1 == args.len) return error.MissingValue;
        try set(&flags, flag, args[index + 1]);
    }
    assert(index >= args.len);
    try validate(&flags);
    return flags;
}

fn set(flags: *Flags, flag: Flag, value: []const u8) Error!void {
    const duration = proposer_config.parse_duration_ms;
    switch (flag) {
        .l1_eth_rpc => flags.l1_eth_rpc = value,
        .l2_eth_rpc => flags.l2_eth_rpc = value,
        .zk_rpc_url => flags.zk_rpc_url = value,
        .dispute_game_factory_addr => flags.dispute_game_factory = try fixed(20, value),
        .anchor_state_registry_addr => flags.anchor_state_registry = try fixed(20, value),
        .game_type => flags.game_type = try unsigned(u32, value),
        .poll_interval => flags.poll_interval_ms = duration(value) catch
            return error.InvalidValue,
        .zk_request_timeout => flags.zk_request_timeout_ms = duration(value) catch
            return error.InvalidValue,
        .max_proof_duration => flags.max_proof_duration_ms = duration(value) catch
            return error.InvalidValue,
        .tee_submit_retry_limit => flags.tee_submit_retry_limit = try unsigned(u32, value),
        .bond_discovery_lookback_games => flags.bond_lookback_games = try unsigned(u64, value),
        .bond_discovery_interval => flags.bond_discovery_interval_ms = duration(value) catch
            return error.InvalidValue,
        .bond_claim_addresses => try set_claim_addresses(flags, value),
        .private_key => flags.private_key = try fixed(32, value),
        .ticks_max => flags.ticks_max = try unsigned(u64, value),
    }
}

/// A comma-separated address list (clap `value_delimiter = ','`).
fn set_claim_addresses(flags: *Flags, value: []const u8) Error!void {
    flags.bond_claim_count = 0;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (flags.bond_claim_count == bond.claim_addresses_max) {
            return error.TooManyClaimAddresses;
        }
        flags.bond_claim_addresses[flags.bond_claim_count] = try fixed(20, part);
        flags.bond_claim_count += 1;
    }
    assert(flags.bond_claim_count > 0);
}

fn unsigned(comptime T: type, value: []const u8) Error!T {
    return std.fmt.parseUnsigned(T, value, 10) catch error.InvalidValue;
}

fn fixed(comptime size: usize, text: []const u8) Error![size]u8 {
    return json.parse_fixed(size, text) catch error.InvalidValue;
}

fn validate(flags: *const Flags) Error!void {
    if (flags.l1_eth_rpc.len == 0 or flags.l2_eth_rpc.len == 0) return error.MissingFlag;
    if (flags.game_type == null or flags.private_key == null) return error.MissingFlag;
    if (chain.is_zero(flags.dispute_game_factory)) return error.ZeroAddress;
    if (flags.zk_request_timeout_ms == 0) return error.InvalidValue;
    // The sender is only known with the key; any non-zero stand-in validates the rest.
    const stand_in: Address = @splat(1);
    try flags.driver_config(stand_in).validate();
}

const testing = std.testing;

const test_key = "0x" ++ "11111111111111111111111111111111" ++
    "11111111111111111111111111111111";

const base_args = [_][]const u8{
    "--l1-eth-rpc",                 "http://127.0.0.1:8545",
    "--l2-eth-rpc",                 "http://127.0.0.1:9545",
    "--dispute-game-factory-addr",  "0x00000000000000000000000000000000000000fa",
    "--anchor-state-registry-addr", "0x00000000000000000000000000000000000000a5",
    "--game-type",                  "621",
    "--private-key",                test_key,
};

test "challenger flags: defaults, lists and validation" {
    const flags = try parse(&base_args);
    try testing.expectEqual(@as(u64, 4 * std.time.ms_per_hour), flags.max_proof_duration_ms);
    try testing.expectEqual(@as(usize, 0), flags.claim_addresses().len);
    const config = flags.driver_config(@splat(2));
    try testing.expectEqual(@as(u64, 12 * std.time.ns_per_s), config.poll_interval_ns);
    const listed = try parse(&(base_args ++ [_][]const u8{
        "--bond-claim-addresses",
        "0x0000000000000000000000000000000000000001,0x0000000000000000000000000000000000000002",
        "--poll-interval",
        "2s",
    }));
    try testing.expectEqual(@as(usize, 2), listed.claim_addresses().len);
    try testing.expectEqual(@as(u8, 2), listed.claim_addresses()[1][19]);
    try testing.expectError(error.MissingFlag, parse(base_args[0..10]));
    try testing.expectError(error.UnknownFlag, parse(&.{ "--nope", "1" }));
    try testing.expectError(error.ZeroPollInterval, parse(&(base_args ++ [_][]const u8{
        "--poll-interval", "0s",
    })));
    try testing.expectError(error.ZeroBondLookback, parse(&(base_args ++ [_][]const u8{
        "--bond-discovery-lookback-games", "0",
    })));
}

test "challenger flags: fuzz" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            const names = [_][]const u8{
                "--poll-interval",
                "--bond-claim-addresses",
                "--bond-discovery-lookback-games",
                "--max-proof-duration",
                "--game-type",
                "--bogus",
            };
            const values = [_][]const u8{
                "0",                                          "5000",
                "3s",                                         "",
                "0x0000000000000000000000000000000000000001", ",",
            };
            var args: [base_args.len + 6][]const u8 = undefined;
            @memcpy(args[0..base_args.len], &base_args);
            const extra = smith.index(4) * 2;
            for (0..extra) |position| {
                const is_name = position % 2 == 0;
                const name = names[smith.index(names.len)];
                args[base_args.len + position] = if (is_name) name else values[smith.index(6)];
            }
            const flags = parse(args[0 .. base_args.len + extra]) catch return;
            try testing.expect(flags.poll_interval_ms > 0);
            try testing.expect(flags.bond_lookback_games <= bond.lookback_games_max);
        }
    }.one, .{ .iterations = 3000 });
}

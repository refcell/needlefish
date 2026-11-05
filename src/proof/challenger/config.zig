//! Challenger configuration (base/base `crates/proof/challenge/src/config.rs`): the values
//! the state machines need, validated the way `ChallengerConfig::from_cli` does. RPC URLs,
//! signer, transaction manager, health and metrics settings belong to the binary and
//! network adapters and are not part of this config.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const bond = @import("bond.zig");

const Address = chain.Address;

pub const Config = struct {
    /// Game type of the `AggregateVerifier` games (anchor lookups).
    game_type: u32,
    /// The transaction sender; also the prover address in proof requests.
    sender: Address,
    anchor_state_registry: Address,
    poll_interval_ns: u64,
    /// How long a prover session may run before it counts as failed.
    max_proof_duration_ns: u64,
    /// Retryable TEE submission failures tolerated before the ZK fallback.
    tee_submit_retry_limit: u32,
    bond_claim_addresses: []const Address,
    bond_lookback_games: u64,
    bond_discovery_interval_ns: u64,
    /// Most games the scanner evaluates per tick (base/base: unbounded).
    games_per_scan_max: u64 = 4096,

    pub const Error = error{
        ZeroAnchorStateRegistry,
        ZeroPollInterval,
        ZeroMaxProofDuration,
        ZeroBondDiscoveryInterval,
        ZeroBondLookback,
        BondLookbackTooLarge,
        TooManyClaimAddresses,
        ZeroGamesPerScan,
    };

    pub fn validate(config: *const Config) Error!void {
        if (chain.is_zero(config.anchor_state_registry)) return error.ZeroAnchorStateRegistry;
        if (config.poll_interval_ns == 0) return error.ZeroPollInterval;
        if (config.max_proof_duration_ns == 0) return error.ZeroMaxProofDuration;
        if (config.bond_discovery_interval_ns == 0) return error.ZeroBondDiscoveryInterval;
        if (config.bond_lookback_games == 0) return error.ZeroBondLookback;
        if (config.bond_lookback_games > bond.lookback_games_max) return error.BondLookbackTooLarge;
        if (config.bond_claim_addresses.len > bond.claim_addresses_max) {
            return error.TooManyClaimAddresses;
        }
        if (config.games_per_scan_max == 0) return error.ZeroGamesPerScan;
        assert(config.poll_interval_ns > 0 and config.bond_lookback_games > 0);
    }
};

const testing = std.testing;

fn minimal() Config {
    return .{
        .game_type = 1,
        .sender = @splat(0xcc),
        .anchor_state_registry = @splat(0x22),
        .poll_interval_ns = 12 * std.time.ns_per_s,
        .max_proof_duration_ns = 3600 * std.time.ns_per_s,
        .tee_submit_retry_limit = 3,
        .bond_claim_addresses = &.{},
        .bond_lookback_games = 1000,
        .bond_discovery_interval_ns = 300 * std.time.ns_per_s,
    };
}

test "challenger config: valid and rejected configs" {
    try minimal().validate();
    const Case = struct { *const fn (*Config) void, Config.Error };
    const cases = [_]Case{
        .{ struct {
            fn f(c: *Config) void {
                c.poll_interval_ns = 0;
            }
        }.f, error.ZeroPollInterval },
        .{ struct {
            fn f(c: *Config) void {
                c.bond_lookback_games = 0;
            }
        }.f, error.ZeroBondLookback },
        .{ struct {
            fn f(c: *Config) void {
                c.bond_discovery_interval_ns = 0;
            }
        }.f, error.ZeroBondDiscoveryInterval },
        .{ struct {
            fn f(c: *Config) void {
                c.max_proof_duration_ns = 0;
            }
        }.f, error.ZeroMaxProofDuration },
        .{ struct {
            fn f(c: *Config) void {
                c.anchor_state_registry = @splat(0);
            }
        }.f, error.ZeroAnchorStateRegistry },
        .{ struct {
            fn f(c: *Config) void {
                c.bond_lookback_games = bond.lookback_games_max + 1;
            }
        }.f, error.BondLookbackTooLarge },
    };
    for (cases) |case| {
        var config = minimal();
        case[0](&config);
        try testing.expectError(case[1], config.validate());
    }
}

//! EIP-1559 base fee arithmetic plus the OP Stack Holocene and Jovian extra-data
//! encodings that let the sequencer override the EIP-1559 parameters per block.
//!
//! Mirrors alloy `calc_next_block_base_fee` and base/base
//! `crates/common/consensus/src/extra` + `crates/execution/chainspec/src/basefee.rs`.

const std = @import("std");
const assert = std.debug.assert;

/// EIP-1559 parameters. Both fields are always non-zero.
pub const BaseFeeParams = struct {
    max_change_denominator: u64,
    elasticity_multiplier: u64,

    /// Ethereum mainnet (EIP-1559 defaults).
    pub const ethereum: BaseFeeParams = .{
        .max_change_denominator = 8,
        .elasticity_multiplier = 2,
    };

    pub fn init(max_change_denominator: u64, elasticity_multiplier: u64) BaseFeeParams {
        assert(max_change_denominator > 0);
        assert(elasticity_multiplier > 0);
        return .{
            .max_change_denominator = max_change_denominator,
            .elasticity_multiplier = elasticity_multiplier,
        };
    }
};

/// Next block base fee per EIP-1559. Computed in u128 so no input can overflow.
pub fn next_base_fee(gas_used: u64, gas_limit: u64, base_fee: u64, params: BaseFeeParams) u64 {
    assert(params.max_change_denominator > 0);
    assert(params.elasticity_multiplier > 0);
    const gas_target: u128 = gas_limit / params.elasticity_multiplier;
    if (gas_target == 0) return base_fee; // Degenerate limit: nothing to compare against.
    const used: u128 = gas_used;
    const fee: u128 = base_fee;
    const denominator: u128 = gas_target * params.max_change_denominator;
    if (used == gas_target) return base_fee;
    if (used > gas_target) {
        const delta = @max(1, fee * (used - gas_target) / denominator);
        const result = fee + delta;
        assert(result > fee);
        return @intCast(@min(result, std.math.maxInt(u64)));
    }
    const delta = fee * (gas_target - used) / denominator;
    assert(delta <= fee);
    return @intCast(fee - delta);
}

pub const ExtraDataError = error{
    InvalidExtraDataLength,
    InvalidExtraDataVersion,
    /// Exactly one of elasticity/denominator is zero.
    InvalidEip1559Params,
};

pub const holocene_extra_data_size = 9;
pub const jovian_extra_data_size = 17;
const holocene_version: u8 = 0;
const jovian_version: u8 = 1;

/// Decoded Holocene/Jovian EIP-1559 parameters. Zero/zero means "use chain defaults".
pub const ExtraParams = struct {
    denominator: u32,
    elasticity: u32,
    /// Jovian only; zero before Jovian.
    min_base_fee: u64 = 0,

    /// Resolve against the chain defaults; rejects a half-zero pair.
    pub fn resolve(extra: ExtraParams, defaults: BaseFeeParams) ExtraDataError!BaseFeeParams {
        if (extra.denominator == 0 and extra.elasticity == 0) return defaults;
        if (extra.denominator == 0 or extra.elasticity == 0) return error.InvalidEip1559Params;
        return BaseFeeParams.init(extra.denominator, extra.elasticity);
    }
};

pub fn decode_holocene(extra_data: []const u8) ExtraDataError!ExtraParams {
    if (extra_data.len != holocene_extra_data_size) return error.InvalidExtraDataLength;
    if (extra_data[0] != holocene_version) return error.InvalidExtraDataVersion;
    return .{
        .denominator = std.mem.readInt(u32, extra_data[1..5], .big),
        .elasticity = std.mem.readInt(u32, extra_data[5..9], .big),
    };
}

pub fn decode_jovian(extra_data: []const u8) ExtraDataError!ExtraParams {
    if (extra_data.len != jovian_extra_data_size) return error.InvalidExtraDataLength;
    if (extra_data[0] != jovian_version) return error.InvalidExtraDataVersion;
    return .{
        .denominator = std.mem.readInt(u32, extra_data[1..5], .big),
        .elasticity = std.mem.readInt(u32, extra_data[5..9], .big),
        .min_base_fee = std.mem.readInt(u64, extra_data[9..17], .big),
    };
}

/// `eip1559_params` from payload attributes: 8 bytes, denominator then elasticity (big
/// endian). All zero selects `defaults`.
pub fn encode_params(eip1559_params: [8]u8, defaults: BaseFeeParams, out: *[8]u8) void {
    if (std.mem.allEqual(u8, &eip1559_params, 0)) {
        assert(defaults.max_change_denominator <= std.math.maxInt(u32));
        assert(defaults.elasticity_multiplier <= std.math.maxInt(u32));
        std.mem.writeInt(u32, out[0..4], @intCast(defaults.max_change_denominator), .big);
        std.mem.writeInt(u32, out[4..8], @intCast(defaults.elasticity_multiplier), .big);
    } else {
        out.* = eip1559_params;
    }
}

pub fn encode_holocene(eip1559_params: [8]u8, defaults: BaseFeeParams) [9]u8 {
    var out: [holocene_extra_data_size]u8 = undefined;
    out[0] = holocene_version;
    encode_params(eip1559_params, defaults, out[1..9]);
    return out;
}

pub fn encode_jovian(eip1559_params: [8]u8, defaults: BaseFeeParams, min_base_fee: u64) [17]u8 {
    var out: [jovian_extra_data_size]u8 = undefined;
    out[0] = jovian_version;
    encode_params(eip1559_params, defaults, out[1..9]);
    std.mem.writeInt(u64, out[9..17], min_base_fee, .big);
    return out;
}

const testing = std.testing;

test "basefee: eip1559 vectors" {
    const p = BaseFeeParams.ethereum;
    // At target: unchanged.
    try testing.expectEqual(@as(u64, 1_000_000_000), next_base_fee(15_000_000, 30_000_000, 1e9, p));
    // Full block: +12.5%.
    try testing.expectEqual(@as(u64, 1_125_000_000), next_base_fee(30_000_000, 30_000_000, 1e9, p));
    // Empty block: -12.5%.
    try testing.expectEqual(@as(u64, 875_000_000), next_base_fee(0, 30_000_000, 1e9, p));
    // Minimum increase of 1 wei.
    try testing.expectEqual(@as(u64, 8), next_base_fee(15_000_001, 30_000_000, 7, p));
    // Alloy test vector (base_fee 1e9, gas_used 10_000_000, limit 10_000_000).
    try testing.expectEqual(@as(u64, 1_125_000_000), next_base_fee(10_000_000, 10_000_000, 1e9, p));
}

test "basefee: base sepolia params (250, 10)" {
    const p = BaseFeeParams.init(250, 10);
    // gas_target = 3_000_000; used 6_000_000 => +1e9 * 3e6 / (3e6 * 250) = +4e6.
    try testing.expectEqual(@as(u64, 1_004_000_000), next_base_fee(6_000_000, 30_000_000, 1e9, p));
}

test "basefee: holocene encode/decode" {
    const defaults = BaseFeeParams.init(80, 60);
    const zero = @as([8]u8, @splat(0));
    const encoded = encode_holocene(zero, defaults);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 80, 0, 0, 0, 60 }, &encoded);
    const explicit = encode_holocene(.{ 0, 0, 0, 8, 0, 0, 0, 8 }, defaults);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 8, 0, 0, 0, 8 }, &explicit);
    const decoded = try decode_holocene(&encoded);
    try testing.expectEqual(@as(u32, 80), decoded.denominator);
    try testing.expectEqual(@as(u32, 60), decoded.elasticity);
    try testing.expectError(error.InvalidExtraDataLength, decode_holocene(encoded[0..8]));
    const jovian = encode_jovian(zero, defaults, 7);
    try testing.expectError(error.InvalidExtraDataLength, decode_holocene(&jovian));
    var bad = encoded;
    bad[0] = 1;
    try testing.expectError(error.InvalidExtraDataVersion, decode_holocene(&bad));
}

test "basefee: jovian encode/decode and half-zero rejection" {
    const defaults = BaseFeeParams.init(250, 6);
    const encoded = encode_jovian(@as([8]u8, @splat(0)), defaults, 100_000_000);
    const decoded = try decode_jovian(&encoded);
    try testing.expectEqual(@as(u64, 100_000_000), decoded.min_base_fee);
    const resolved = try decoded.resolve(BaseFeeParams.ethereum);
    try testing.expectEqual(@as(u64, 250), resolved.max_change_denominator);
    const half_zero = [_]u8{ 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const half = try decode_jovian(&half_zero);
    try testing.expectError(error.InvalidEip1559Params, half.resolve(defaults));
    const all_zero = (ExtraParams{ .denominator = 0, .elasticity = 0 });
    try testing.expectEqual(defaults, try all_zero.resolve(defaults));
}

fn check_base_fee_bounds(
    gas_used: u64,
    gas_limit: u64,
    base_fee: u64,
    params: BaseFeeParams,
) !void {
    const next = next_base_fee(gas_used, gas_limit, base_fee, params);
    const target = gas_limit / params.elasticity_multiplier;
    if (target == 0 or gas_used == target) {
        try testing.expectEqual(base_fee, next);
    } else if (gas_used > target) {
        try testing.expect(next > base_fee or base_fee == std.math.maxInt(u64));
    } else {
        try testing.expect(next <= base_fee);
    }
}

fn fuzz_extra_data(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [32]u8 = undefined;
    const len = smith.slice(&buffer);
    const data = buffer[0..len];
    if (decode_holocene(data)) |params| {
        try testing.expectEqual(@as(usize, 9), data.len);
        if (params.denominator != 0 or params.elasticity != 0) {
            const round = encode_holocene(data[1..9].*, BaseFeeParams.ethereum);
            try testing.expectEqualSlices(u8, data, &round);
        }
    } else |_| {}
    if (decode_jovian(data)) |params| {
        try testing.expectEqual(@as(usize, 17), data.len);
        _ = params.resolve(BaseFeeParams.ethereum) catch {};
    } else |_| {}
    const params = BaseFeeParams.init(
        smith.valueRangeAtMost(u64, 1, 1 << 32),
        smith.valueRangeAtMost(u64, 1, 1 << 32),
    );
    try check_base_fee_bounds(smith.value(u64), smith.value(u64), smith.value(u64), params);
}

test "basefee: fuzz" {
    try testing.fuzz({}, fuzz_extra_data, .{});
}

test "basefee: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x1559);
    for (0..10_000) |_| {
        const params = BaseFeeParams.init(prng.range(1, 1 << 32), prng.range(1, 1 << 32));
        const limit = prng.int(u64) >> @intCast(prng.below(64));
        const used = if (limit == 0) 0 else prng.below(limit);
        try check_base_fee_bounds(used, limit, prng.int(u64), params);
        var extra: [17]u8 = undefined;
        prng.fill(&extra);
        extra[0] = @intCast(prng.below(3));
        if (decode_jovian(&extra)) |decoded| {
            const re = encode_jovian(
                extra[1..9].*,
                BaseFeeParams.ethereum,
                decoded.min_base_fee,
            );
            if (!std.mem.allEqual(u8, extra[1..9], 0)) {
                try testing.expectEqualSlices(u8, &extra, &re);
            }
        } else |_| {}
    }
}

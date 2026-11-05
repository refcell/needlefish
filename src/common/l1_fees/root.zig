//! OP Stack L1 data fee and operator fee math (Bedrock, Regolith, Ecotone, Fjord,
//! Isthmus, Jovian). Mirrors base/base `crates/common/l1-fees`.
//!
//! All arithmetic is on `u256` with the same saturating/wrapping choices as the
//! reference so results match bit for bit. The fork gate is a local `Rules` enum;
//! callers map their upgrade schedule onto it with `Rules.at`.

const std = @import("std");
const assert = std.debug.assert;
const flz = @import("../flz/root.zig");

/// EIP-2028 gas per calldata token.
pub const standard_token_cost: u64 = 4;
/// A non-zero calldata byte counts as this many tokens (Istanbul).
pub const non_zero_byte_multiplier: u64 = 4;
/// Operator fee scalar has 6 decimals before Jovian.
pub const operator_fee_scalar_decimal: u64 = 1_000_000;
/// Jovian multiplies the operator fee scalar component by 100 instead.
pub const operator_fee_jovian_multiplier: u64 = 100;

const deposit_tx_type: u8 = 0x7e;
const pre_regolith_signature_bytes: u64 = 68;

/// L1 fee rule sets, in activation order. Each enables the features of earlier ones.
pub const Rules = enum(u8) {
    bedrock,
    /// Actual L1 signature bytes (no 68-byte padding).
    regolith,
    /// Blob-aware L1 fees.
    ecotone,
    /// FastLZ-based L1 fees.
    fjord,
    /// Operator fee.
    isthmus,
    /// Scaled operator fee, DA footprint.
    jovian,

    pub fn at_least(rules: Rules, other: Rules) bool {
        return @backingInt(rules) >= @backingInt(other);
    }

    pub const Schedule = struct {
        regolith: ?u64,
        ecotone: ?u64,
        fjord: ?u64,
        isthmus: ?u64,
        jovian: ?u64,
    };

    /// The rules active at `timestamp` for a schedule of activation timestamps.
    pub fn at(schedule: Schedule, timestamp: u64) Rules {
        const ordered = [_]struct { ?u64, Rules }{
            .{ schedule.jovian, .jovian },
            .{ schedule.isthmus, .isthmus },
            .{ schedule.fjord, .fjord },
            .{ schedule.ecotone, .ecotone },
            .{ schedule.regolith, .regolith },
        };
        for (ordered) |entry| {
            if (entry[0]) |activation| {
                if (timestamp >= activation) return entry[1];
            }
        }
        return .bedrock;
    }
};

/// Per-block L1 fee parameters, as posted by the L1 attributes deposit.
pub const L1FeeParams = struct {
    l1_base_fee: u256 = 0,
    /// Null once Ecotone is active.
    l1_fee_overhead: ?u256 = null,
    l1_base_fee_scalar: u256 = 0,
    /// Null before Ecotone.
    l1_blob_base_fee: ?u256 = null,
    l1_blob_base_fee_scalar: ?u256 = null,
    /// Null before Isthmus.
    operator_fee_scalar: ?u256 = null,
    operator_fee_constant: ?u256 = null,
    /// Ecotone is active but its scalars are not yet set (first Ecotone block).
    empty_ecotone_scalars: bool = false,
    /// Null before Jovian (or when unset).
    da_footprint_gas_scalar: ?u256 = null,

    fn is_fee_exempt(input: []const u8) bool {
        return input.len == 0 or input[0] == deposit_tx_type;
    }

    /// L1 calldata gas for posting `input` (an EIP-2718 encoded transaction).
    pub fn data_gas(input: []const u8, rules: Rules) u256 {
        if (rules.at_least(.fjord)) {
            const size: u256 = flz.estimated_size(input);
            return (size *| flz.non_zero_byte_cost) / 1_000_000;
        }
        var tokens: u64 = 0;
        for (input) |byte| tokens += if (byte == 0) 1 else non_zero_byte_multiplier;
        if (!rules.at_least(.regolith)) {
            tokens += pre_regolith_signature_bytes * non_zero_byte_multiplier;
        }
        return tokens *| standard_token_cost;
    }

    /// Jovian DA-footprint gas: estimated compressed bytes times the scalar.
    pub fn jovian_da_footprint(params: L1FeeParams, input: []const u8) u64 {
        const scalar = params.da_footprint_gas_scalar orelse return 0;
        const bytes: u256 = flz.estimated_size(input) / 1_000_000;
        const footprint = bytes *| scalar;
        return std.math.cast(u64, footprint) orelse std.math.maxInt(u64);
    }

    /// L1 data cost of `input` under `rules`. Deposits and empty input are exempt.
    pub fn tx_l1_cost(params: L1FeeParams, input: []const u8, rules: Rules) u256 {
        if (is_fee_exempt(input)) return 0;
        if (rules.at_least(.fjord)) {
            return params.tx_l1_cost_fjord(input, flz.compress_length(input));
        }
        if (rules.at_least(.ecotone)) return params.tx_l1_cost_ecotone(input, rules);
        return params.tx_l1_cost_bedrock(input, rules);
    }

    pub fn tx_l1_cost_bedrock(params: L1FeeParams, input: []const u8, rules: Rules) u256 {
        if (is_fee_exempt(input)) return 0;
        const gas = data_gas(input, rules) +| (params.l1_fee_overhead orelse 0);
        return ((gas *| params.l1_base_fee) *| params.l1_base_fee_scalar) / 1_000_000;
    }

    /// `data_gas * (l1_base_fee * 16 * base_scalar + blob_base_fee * blob_scalar) / 16e6`.
    pub fn tx_l1_cost_ecotone(params: L1FeeParams, input: []const u8, rules: Rules) u256 {
        if (is_fee_exempt(input)) return 0;
        // The first Ecotone block (unless at genesis) still prices with Bedrock rules.
        if (params.empty_ecotone_scalars) return params.tx_l1_cost_bedrock(input, rules);
        const gas = data_gas(input, rules);
        return (params.l1_fee_scaled() *| gas) / (1_000_000 * flz.non_zero_byte_cost);
    }

    /// `estimated_size * (base_scalar * l1_base_fee * 16 + blob_scalar * blob_fee) / 1e12`,
    /// given the input's precomputed FastLZ length.
    pub fn tx_l1_cost_fjord(params: L1FeeParams, input: []const u8, fastlz_size: u32) u256 {
        if (is_fee_exempt(input)) return 0;
        const scaled = params.l1_fee_scaled();
        if (scaled == 0) return 0;
        const size: u256 = flz.estimated_size_from_fastlz_size(fastlz_size);
        return (size *| scaled) / 1_000_000_000_000;
    }

    fn l1_fee_scaled(params: L1FeeParams) u256 {
        const per_byte = params.l1_base_fee *| flz.non_zero_byte_cost;
        const calldata = per_byte *| params.l1_base_fee_scalar;
        const blob_fee = params.l1_blob_base_fee orelse 0;
        const blob = blob_fee *| (params.l1_blob_base_fee_scalar orelse 0);
        return calldata +| blob;
    }

    /// Operator fee for `input` with gas budget `gas_limit`. Callers gate on Isthmus.
    pub fn operator_fee_charge(
        params: L1FeeParams,
        input: []const u8,
        gas_limit: u256,
        rules: Rules,
    ) u256 {
        if (is_fee_exempt(input)) return 0;
        return params.operator_fee_for_gas(gas_limit, rules);
    }

    /// Operator fee for `gas`; missing parameters count as zero.
    pub fn operator_fee_for_gas(params: L1FeeParams, gas: u256, rules: Rules) u256 {
        const scalar = params.operator_fee_scalar orelse 0;
        const constant = params.operator_fee_constant orelse 0;
        const product = if (rules.at_least(.jovian))
            (gas *| scalar) *| operator_fee_jovian_multiplier
        else
            (gas *| scalar) / operator_fee_scalar_decimal;
        return product +| constant;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn reference_params() L1FeeParams {
    return .{
        .l1_base_fee = 1_000_000,
        .l1_fee_overhead = 1_000_000,
        .l1_base_fee_scalar = 1_000_000,
    };
}

test "l1 fees: data gas matches reference" {
    const facade = [_]u8{ 0xfa, 0xca, 0xde };
    try testing.expectEqual(@as(u256, 1136), L1FeeParams.data_gas(&facade, .bedrock));
    try testing.expectEqual(@as(u256, 48), L1FeeParams.data_gas(&facade, .regolith));
    try testing.expectEqual(@as(u256, 1600), L1FeeParams.data_gas(&facade, .fjord));
    const zeros = [_]u8{ 0xfa, 0x00, 0xca, 0x00, 0xde };
    try testing.expectEqual(@as(u256, 1144), L1FeeParams.data_gas(&zeros, .bedrock));
}

test "l1 fees: DA footprint" {
    try testing.expectEqual(@as(u64, 0), reference_params().jovian_da_footprint(&.{ 2, 0xab }));
    const params: L1FeeParams = .{ .da_footprint_gas_scalar = 7 };
    try testing.expectEqual(@as(u64, 700), params.jovian_da_footprint(&.{ 0x02, 0xab, 0xcd }));
}

test "l1 fees: exemptions and operator fee" {
    const params = reference_params();
    try testing.expectEqual(@as(u256, 0), params.tx_l1_cost(&.{}, .ecotone));
    try testing.expectEqual(@as(u256, 0), params.tx_l1_cost(&.{ 0x7e, 1, 2 }, .ecotone));
    try testing.expectEqual(@as(u256, 0), params.operator_fee_for_gas(21_000, .isthmus));
    const operator: L1FeeParams = .{ .operator_fee_scalar = 2_000_000, .operator_fee_constant = 5 };
    try testing.expectEqual(@as(u256, 42_005), operator.operator_fee_for_gas(21_000, .isthmus));
    try testing.expectEqual(
        @as(u256, 21_000 * 2_000_000 * 100 + 5),
        operator.operator_fee_for_gas(21_000, .jovian),
    );
}

test "l1 fees: bedrock and ecotone formulas" {
    const params = reference_params();
    const input = [_]u8{ 0xfa, 0xca, 0xde };
    // (48 + 1e6) * 1e6 * 1e6 / 1e6.
    const bedrock: u256 = (48 + 1_000_000) * 1_000_000;
    try testing.expectEqual(bedrock, params.tx_l1_cost(&input, .regolith));
    var ecotone = params;
    ecotone.l1_fee_overhead = null;
    ecotone.l1_base_fee_scalar = 1000;
    ecotone.l1_blob_base_fee = 10;
    ecotone.l1_blob_base_fee_scalar = 1_000_000;
    const scaled: u256 = 1_000_000 * 16 * 1000 + 10 * 1_000_000;
    try testing.expectEqual(scaled * 48 / 16_000_000, ecotone.tx_l1_cost(&input, .ecotone));
    ecotone.empty_ecotone_scalars = true;
    try testing.expectEqual(
        ecotone.tx_l1_cost_bedrock(&input, .ecotone),
        ecotone.tx_l1_cost(&input, .ecotone),
    );
}

test "l1 fees: rules from schedule" {
    const schedule: Rules.Schedule = .{
        .regolith = 10,
        .ecotone = 20,
        .fjord = 30,
        .isthmus = null,
        .jovian = null,
    };
    try testing.expectEqual(Rules.bedrock, Rules.at(schedule, 9));
    try testing.expectEqual(Rules.regolith, Rules.at(schedule, 10));
    try testing.expectEqual(Rules.fjord, Rules.at(schedule, 1000));
}

test "l1 fees: seeded fuzz monotonic in base fee" {
    var prng = Prng.init(0x11fe);
    var input: [512]u8 = undefined;
    for (0..200) |_| {
        const len = prng.range(1, input.len);
        prng.fill(input[0..len]);
        input[0] = 0x02;
        const rules: Rules = @fromBackingInt(@intCast(prng.below(6)));
        var params: L1FeeParams = .{
            .l1_base_fee = prng.int(u64),
            .l1_fee_overhead = prng.int(u16),
            .l1_base_fee_scalar = prng.int(u32),
            .l1_blob_base_fee = prng.int(u64),
            .l1_blob_base_fee_scalar = prng.int(u32),
        };
        const low = params.tx_l1_cost(input[0..len], rules);
        params.l1_base_fee +|= prng.int(u32);
        try testing.expect(params.tx_l1_cost(input[0..len], rules) >= low);
    }
}

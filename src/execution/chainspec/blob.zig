//! EIP-4844 blob gas accounting: per-fork blob parameters (Cancun, Prague/EIP-7691,
//! Osaka/EIP-7918 and the BPO forks), `fake_exponential`, excess blob gas and the blob
//! base fee. Mirrors alloy `BlobParams`.

const std = @import("std");
const assert = std.debug.assert;

pub const gas_per_blob: u64 = 1 << 17;
pub const min_blob_base_fee: u64 = 1;
/// EIP-7918 reserve price multiplier.
pub const blob_base_cost: u64 = 1 << 13;

pub const BlobParams = struct {
    target_blob_count: u64,
    max_blob_count: u64,
    update_fraction: u64,
    /// EIP-7918 (Osaka+): blob base fee is bounded below by the execution base fee.
    reserve_price: bool,

    pub const cancun: BlobParams = .{
        .target_blob_count = 3,
        .max_blob_count = 6,
        .update_fraction = 3_338_477,
        .reserve_price = false,
    };
    pub const prague: BlobParams = .{
        .target_blob_count = 6,
        .max_blob_count = 9,
        .update_fraction = 5_007_716,
        .reserve_price = false,
    };
    pub const osaka: BlobParams = .{
        .target_blob_count = 6,
        .max_blob_count = 9,
        .update_fraction = 5_007_716,
        .reserve_price = true,
    };
    pub const bpo1: BlobParams = .{
        .target_blob_count = 10,
        .max_blob_count = 15,
        .update_fraction = 8_346_193,
        .reserve_price = true,
    };
    pub const bpo2: BlobParams = .{
        .target_blob_count = 14,
        .max_blob_count = 21,
        .update_fraction = 11_684_671,
        .reserve_price = true,
    };

    pub fn target_blob_gas(params: BlobParams) u64 {
        return params.target_blob_count * gas_per_blob;
    }

    pub fn max_blob_gas(params: BlobParams) u64 {
        return params.max_blob_count * gas_per_blob;
    }

    /// Blob base fee for a block with `excess_blob_gas`.
    pub fn base_fee(params: BlobParams, excess_blob_gas: u64) u128 {
        assert(params.update_fraction > 0);
        return fake_exponential(min_blob_base_fee, excess_blob_gas, params.update_fraction);
    }

    /// Excess blob gas of a child block, from its parent's header fields.
    pub fn next_excess_blob_gas(
        params: BlobParams,
        parent_excess_blob_gas: u64,
        parent_blob_gas_used: u64,
        parent_base_fee: u64,
    ) u64 {
        assert(params.max_blob_count >= params.target_blob_count);
        const total = parent_excess_blob_gas +| parent_blob_gas_used;
        const target = params.target_blob_gas();
        if (total < target) return 0;
        if (params.reserve_price) {
            const reserve: u128 = @as(u128, blob_base_cost) * parent_base_fee;
            const parent_blob_fee = params.base_fee(parent_excess_blob_gas);
            const blob_fee: u128 = @as(u128, gas_per_blob) *| parent_blob_fee;
            if (reserve > blob_fee) {
                assert(params.max_blob_count > 0);
                const spread = params.max_blob_count - params.target_blob_count;
                const scaled: u128 =
                    @as(u128, parent_blob_gas_used) * spread / params.max_blob_count;
                return parent_excess_blob_gas +| @as(u64, @intCast(scaled));
            }
        }
        return total - target;
    }
};

/// `factor * e ** (numerator / denominator)` by Taylor expansion (EIP-4844). Saturates
/// rather than overflowing; iteration is bounded because each term shrinks once
/// `i > numerator / denominator`, and is hard-capped at `iterations_max`.
pub fn fake_exponential(factor: u64, numerator: u64, denominator: u64) u128 {
    assert(denominator > 0);
    const iterations_max = 1 << 16;
    const d: u128 = denominator;
    var i: u128 = 1;
    var output: u128 = 0;
    var accumulator: u128 = @as(u128, factor) * d;
    while (accumulator > 0) : (i += 1) {
        if (i > iterations_max) return std.math.maxInt(u128);
        output +|= accumulator;
        const product = std.math.mul(u128, accumulator, numerator) catch {
            return std.math.maxInt(u128);
        };
        accumulator = product / (d * i);
    }
    return output / d;
}

const testing = std.testing;

test "blob: fake_exponential vectors (EIP-4844)" {
    const vectors = [_][4]u64{
        .{ 1, 0, 1, 1 },    .{ 38493, 0, 1000, 38493 }, .{ 0, 1234, 2345, 0 },
        .{ 1, 2, 1, 6 },    .{ 1, 4, 2, 6 },            .{ 1, 3, 1, 16 },
        .{ 1, 6, 2, 18 },   .{ 1, 4, 1, 49 },           .{ 1, 8, 2, 50 },
        .{ 10, 8, 2, 542 }, .{ 11, 8, 2, 596 },         .{ 1, 5, 1, 136 },
        .{ 1, 5, 2, 11 },   .{ 2, 5, 2, 23 },           .{ 1, 50000000, 2225652, 5709098764 },
    };
    for (vectors) |v| {
        try testing.expectEqual(@as(u128, v[3]), fake_exponential(v[0], v[1], v[2]));
    }
}

test "blob: excess blob gas" {
    const p = BlobParams.cancun;
    try testing.expectEqual(@as(u64, 0), p.next_excess_blob_gas(0, 0, 7));
    try testing.expectEqual(@as(u64, 0), p.next_excess_blob_gas(0, p.target_blob_gas() - 1, 7));
    const over = p.next_excess_blob_gas(gas_per_blob, p.max_blob_gas(), 7);
    try testing.expectEqual(gas_per_blob * 4, over);
    try testing.expectEqual(@as(u128, 1), p.base_fee(0));
}

test "blob: eip-7918 reserve price" {
    const p = BlobParams.osaka;
    // Huge execution base fee: reserve dominates, excess grows by used * 3 / 9.
    const used = p.max_blob_gas();
    const next = p.next_excess_blob_gas(p.target_blob_gas(), used, 1_000_000_000_000);
    try testing.expectEqual(p.target_blob_gas() + used * 3 / 9, next);
    // Tiny base fee: plain EIP-4844 rule.
    const plain = p.next_excess_blob_gas(p.target_blob_gas(), used, 0);
    try testing.expectEqual(used, plain);
}

fn fuzz_blob(_: void, smith: *testing.Smith) anyerror!void {
    const all = [_]BlobParams{ .cancun, .prague, .osaka, .bpo1, .bpo2 };
    const p = all[smith.valueRangeLessThan(u8, 0, all.len)];
    const excess = smith.value(u64);
    const used = smith.value(u64);
    const next = p.next_excess_blob_gas(excess, used, smith.value(u64));
    if (excess +| used < p.target_blob_gas()) try testing.expectEqual(@as(u64, 0), next);
    try testing.expect(p.base_fee(excess) >= 1);
}

test "blob: fuzz" {
    try testing.fuzz({}, fuzz_blob, .{});
}

test "blob: seeded fuzz monotone base fee" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x4844);
    for (0..2_000) |_| {
        const a = prng.below(1 << 30);
        const b = a + prng.below(1 << 20);
        try testing.expect(BlobParams.prague.base_fee(a) <= BlobParams.prague.base_fee(b));
    }
}

//! Deterministic pseudo random number generator for simulation and fuzzing.
//!
//! Every source of randomness in tests and the simulator flows from one seed
//! through this type, so any failure reproduces from its seed alone.

const std = @import("std");
const assert = std.debug.assert;

pub const Prng = struct {
    state: std.Random.Xoshiro256,

    pub fn init(seed: u64) Prng {
        return .{ .state = std.Random.Xoshiro256.init(seed) };
    }

    pub fn random(prng: *Prng) std.Random {
        return prng.state.random();
    }

    pub fn int(prng: *Prng, comptime T: type) T {
        return prng.random().int(T);
    }

    /// Uniform in [0, bound).
    pub fn below(prng: *Prng, bound: u64) u64 {
        assert(bound > 0);
        return prng.random().uintLessThan(u64, bound);
    }

    /// Uniform in [min, max].
    pub fn range(prng: *Prng, min: u64, max: u64) u64 {
        assert(min <= max);
        return prng.random().intRangeAtMost(u64, min, max);
    }

    /// True with probability numerator / denominator.
    pub fn chance(prng: *Prng, numerator: u64, denominator: u64) bool {
        assert(denominator > 0);
        assert(numerator <= denominator);
        return prng.below(denominator) < numerator;
    }

    pub fn fill(prng: *Prng, buffer: []u8) void {
        prng.random().bytes(buffer);
    }
};

test "prng: same seed, same sequence" {
    var a = Prng.init(42);
    var b = Prng.init(42);
    for (0..1000) |_| {
        try std.testing.expectEqual(a.int(u64), b.int(u64));
    }
}

test "prng: bounds" {
    var p = Prng.init(7);
    for (0..10_000) |_| {
        const v = p.range(3, 9);
        try std.testing.expect(v >= 3 and v <= 9);
        try std.testing.expect(p.below(5) < 5);
    }
}

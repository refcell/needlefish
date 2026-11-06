//! Differential fuzz of the MODEXP precompile (0x05) against a square-and-multiply model.
//!
//! Random base and exponent of 0..64 bytes and a modulus of 0..32 bytes, with random
//! leading zeros, zero lengths, and zero or one moduli. The model reduces with the builtin
//! u512 remainder, independent of the crypto lane's Montgomery code. The output must be the
//! result left-padded to the modulus length, and a gas limit below the charged cost must
//! fail with all gas consumed. Gas formulas themselves are covered by the crypto lane's
//! vectors and the EEST state tests.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const precompiles = @import("precompiles.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Fork = @import("fork.zig").Fork;

const operand_bytes_max = 64;
const modulus_bytes_max = 32;
const input_bytes_max = 96 + 2 * operand_bytes_max + modulus_bytes_max;

fn random_operand(prng: *Prng, buffer: []u8, len_max: usize) []u8 {
    const len: usize = @intCast(prng.below(len_max + 1));
    const operand = buffer[0..len];
    for (operand) |*byte| byte.* = @truncate(prng.int(u64));
    // Leading zeros are common in real inputs and must not change the value.
    const zeros: usize = @intCast(prng.below(len + 1));
    if (prng.below(3) == 0) @memset(operand[0..zeros], 0);
    return operand;
}

fn value_of(bytes: []const u8) u512 {
    assert(bytes.len <= 64);
    var value: u512 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

/// base^exponent mod modulus by left-to-right square-and-multiply; 0 for modulus 0.
fn model(base: []const u8, exponent: []const u8, modulus: u256) u256 {
    if (modulus == 0) return 0;
    const m: u512 = modulus;
    const b = value_of(base) % m;
    var result: u512 = 1 % m;
    for (exponent) |byte| {
        var bit: u4 = 8;
        while (bit > 0) {
            bit -= 1;
            result = (result * result) % m;
            if ((byte >> @intCast(bit)) & 1 == 1) result = (result * b) % m;
        }
    }
    assert(result < m);
    return @intCast(result);
}

fn run_case(prng: *Prng) !void {
    var base_buffer: [operand_bytes_max]u8 = undefined;
    var exponent_buffer: [operand_bytes_max]u8 = undefined;
    var modulus_buffer: [modulus_bytes_max]u8 = undefined;
    const base = random_operand(prng, &base_buffer, operand_bytes_max);
    const exponent = random_operand(prng, &exponent_buffer, operand_bytes_max);
    const modulus = random_operand(prng, &modulus_buffer, modulus_bytes_max);
    if (modulus.len > 0 and prng.below(8) == 0) {
        @memset(modulus, 0);
        modulus[modulus.len - 1] = @intCast(prng.below(2)); // A zero or one modulus.
    }
    var input: [input_bytes_max]u8 = @splat(0);
    std.mem.writeInt(u256, input[0..32], base.len, .big);
    std.mem.writeInt(u256, input[32..64], exponent.len, .big);
    std.mem.writeInt(u256, input[64..96], modulus.len, .big);
    var length: usize = 96;
    for ([_][]const u8{ base, exponent, modulus }) |operand| {
        @memcpy(input[length..][0..operand.len], operand);
        length += operand.len;
    }
    const forks = [_]Fork{ .byzantium, .berlin, .osaka };
    const fork = forks[@intCast(prng.below(forks.len))];
    try check(fork, input[0..length], base, exponent, modulus);
}

fn check(
    fork: Fork,
    input: []const u8,
    base: []const u8,
    exponent: []const u8,
    modulus: []const u8,
) !void {
    const address = primitives.address_from_int(5);
    var out: [modulus_bytes_max]u8 = undefined;
    const buffers = precompiles.Buffers{ .out = &out, .scratch = &.{} };
    const run = switch (fork) {
        inline else => |comptime_fork| precompiles.lookup(comptime_fork, null, address).?,
    };
    const result = run(input, 1 << 40, buffers);
    try std.testing.expectEqual(precompiles.Status.success, result.status);
    try std.testing.expectEqual(@as(u32, @intCast(modulus.len)), result.output_len);
    var expected: [32]u8 = undefined;
    std.mem.writeInt(u256, &expected, model(base, exponent, @intCast(value_of(modulus))), .big);
    try std.testing.expectEqualSlices(u8, expected[32 - modulus.len ..], out[0..modulus.len]);
    // One gas short of the charge fails and consumes the whole limit (pre-Berlin MODEXP
    // can cost nothing).
    if (result.gas_used == 0) return;
    const short = run(input, result.gas_used - 1, buffers);
    try std.testing.expectEqual(precompiles.Status.out_of_gas, short.status);
    try std.testing.expectEqual(result.gas_used - 1, short.gas_used);
}

fn fuzz_modexp(_: void, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    @memcpy(seed[0..@min(bytes.len, 8)], bytes[0..@min(bytes.len, 8)]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    try run_case(&prng);
}

test "modexp fuzz: precompile output against a square-and-multiply model" {
    try fuzz.run_bytes({}, fuzz_modexp, .{ .seed = 0x0de5_0001, .iterations = 200 });
}

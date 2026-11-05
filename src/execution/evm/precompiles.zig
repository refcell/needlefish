//! Precompiled contracts: per-fork address sets, gas, and dispatch.
//!
//! Each precompile writes its output into the EVM return buffer and reports gas
//! used. Cryptography lives in `common.crypto`; this file owns addresses, fork gates,
//! gas, and the Base (OP Stack) input caps.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const Fork = @import("fork.zig").Fork;
const crypto = @import("../../common/crypto/root.zig");
const op = @import("op.zig");
const Address = primitives.Address;

pub const Status = enum { success, failure, out_of_gas };

pub const Result = struct {
    status: Status,
    gas_used: u64,
    output_len: u32 = 0,
};

pub const Precompile = *const fn (input: []const u8, gas_limit: u64, out: []u8) Result;

/// Highest precompile address number per fork (Osaka adds P256VERIFY at 0x100).
fn last_address(comptime fork: Fork) u64 {
    if (fork.at_least(.prague)) return 0x11;
    if (fork.at_least(.cancun)) return 0x0a;
    if (fork.at_least(.istanbul)) return 0x09;
    if (fork.at_least(.byzantium)) return 0x08;
    return 0x04;
}

/// `op_upgrade` is the Base upgrade (null on Ethereum): Fjord adds RIP-7212 P256VERIFY,
/// Granite/Isthmus/Jovian cap pairing and MSM input sizes.
pub fn lookup(comptime fork: Fork, op_upgrade: ?op.Upgrade, address: Address) ?Precompile {
    for (address[0..18]) |b| {
        if (b != 0) return null;
    }
    const number = std.mem.readInt(u16, address[18..20], .big);
    if (number == 0x100) {
        if (fork.at_least(.osaka)) return p256verify(6900);
        const upgrade = op_upgrade orelse return null;
        return if (upgrade.at_least(.fjord)) p256verify(3450) else null;
    }
    if (number == 0 or number > last_address(fork)) return null;
    return switch (number) {
        0x01 => ecrecover,
        0x02 => sha256,
        0x03 => ripemd160,
        0x04 => identity,
        0x05 => modexp(modexp_rules(fork)),
        0x06 => bn254_add(fork.at_least(.istanbul)),
        0x07 => bn254_mul(fork.at_least(.istanbul)),
        0x08 => bn254_pairing_capped(fork, op_upgrade),
        0x09 => blake2f,
        0x0a => point_evaluation,
        0x0b...0x11 => switch (@as(Bls, @fromBackingInt(@intCast(@as(u8, @intCast(number)))))) {
            inline else => |bls_address| bls_capped(bls_address, op_upgrade),
        },
        else => unreachable, // Proof: number <= last_address(fork) <= 0x11.
    };
}

/// Base caps on pairing / MSM input bytes (base/base `bn254_pair.rs`, `bls12_381.rs`).
pub const Caps = struct {
    pub const bn254_pairing_granite: usize = 112_687;
    pub const bn254_pairing_jovian: usize = 81_984;
    pub const g1_msm_isthmus: usize = 513_760;
    pub const g2_msm_isthmus: usize = 488_448;
    pub const pairing_isthmus: usize = 235_008;
    pub const g1_msm_jovian: usize = 288_960;
    pub const g2_msm_jovian: usize = 278_784;
    pub const pairing_jovian: usize = 156_672;
};

fn bn254_pairing_capped(comptime fork: Fork, op_upgrade: ?op.Upgrade) Precompile {
    const istanbul = comptime fork.at_least(.istanbul);
    const upgrade = op_upgrade orelse return bn254_pairing(istanbul, null);
    if (upgrade.at_least(.jovian)) return bn254_pairing(istanbul, Caps.bn254_pairing_jovian);
    if (upgrade.at_least(.granite)) return bn254_pairing(istanbul, Caps.bn254_pairing_granite);
    return bn254_pairing(istanbul, null);
}

fn bls_capped(comptime address: Bls, op_upgrade: ?op.Upgrade) Precompile {
    const upgrade = op_upgrade orelse return bls(address, null);
    const jovian = upgrade.at_least(.jovian);
    return switch (address) {
        .g1_msm => if (jovian)
            bls(.g1_msm, Caps.g1_msm_jovian)
        else
            bls(.g1_msm, Caps.g1_msm_isthmus),
        .g2_msm => if (jovian)
            bls(.g2_msm, Caps.g2_msm_jovian)
        else
            bls(.g2_msm, Caps.g2_msm_isthmus),
        .pairing_check => if (jovian)
            bls(.pairing_check, Caps.pairing_jovian)
        else
            bls(.pairing_check, Caps.pairing_isthmus),
        else => bls(address, null),
    };
}

pub fn is_precompile(comptime fork: Fork, op_upgrade: ?op.Upgrade, address: Address) bool {
    return lookup(fork, op_upgrade, address) != null;
}

const bn254 = crypto.bn254;
const bls_precompile = crypto.bls12_381.precompile;
const Bls = bls_precompile.Address;

fn fail(gas_limit: u64) Result {
    return .{ .status = .failure, .gas_used = gas_limit };
}

/// EIP-196 / EIP-1108 (Istanbul repricing).
fn bn254_add(comptime istanbul: bool) Precompile {
    return struct {
        fn run(input: []const u8, gas_limit: u64, out: []u8) Result {
            const cost: u64 = if (istanbul) 150 else 500;
            if (charge(gas_limit, cost)) |failure| return failure;
            out[0..64].* = bn254.precompile_bn254_add(input) catch return fail(gas_limit);
            return .{ .status = .success, .gas_used = cost, .output_len = 64 };
        }
    }.run;
}

fn bn254_mul(comptime istanbul: bool) Precompile {
    return struct {
        fn run(input: []const u8, gas_limit: u64, out: []u8) Result {
            const cost: u64 = if (istanbul) 6_000 else 40_000;
            if (charge(gas_limit, cost)) |failure| return failure;
            out[0..64].* = bn254.precompile_bn254_mul(input) catch return fail(gas_limit);
            return .{ .status = .success, .gas_used = cost, .output_len = 64 };
        }
    }.run;
}

/// EIP-197 pairing check; `cap` is the Base input byte limit (inclusive).
fn bn254_pairing(comptime istanbul: bool, comptime cap: ?usize) Precompile {
    return struct {
        fn run(input: []const u8, gas_limit: u64, out: []u8) Result {
            if (cap) |limit| {
                if (input.len > limit) return fail(gas_limit);
            }
            const pairs: u64 = input.len / 192;
            const cost: u64 = if (istanbul) 45_000 + 34_000 * pairs else 100_000 + 80_000 * pairs;
            if (charge(gas_limit, cost)) |failure| return failure;
            out[0..32].* = bn254.precompile_bn254_pairing(input) catch return fail(gas_limit);
            return .{ .status = .success, .gas_used = cost, .output_len = 32 };
        }
    }.run;
}

/// EIP-4844 point evaluation (0x0a).
fn point_evaluation(input: []const u8, gas_limit: u64, out: []u8) Result {
    const cost = 50_000;
    if (charge(gas_limit, cost)) |failure| return failure;
    out[0..64].* = crypto.kzg.precompile_point_evaluation(input) catch return fail(gas_limit);
    return .{ .status = .success, .gas_used = cost, .output_len = 64 };
}

/// EIP-2537 BLS12-381 (0x0b-0x11); `cap` is the Base input byte limit (inclusive).
fn bls(comptime address: Bls, comptime cap: ?usize) Precompile {
    return struct {
        fn run(input: []const u8, gas_limit: u64, out: []u8) Result {
            if (cap) |limit| {
                if (input.len > limit) return fail(gas_limit);
            }
            const cost = bls_precompile.gas(address, input.len);
            if (charge(gas_limit, cost)) |failure| return failure;
            assert(out.len >= bls_precompile.output_length_max);
            const length = bls_execute(address, input, out) catch return fail(gas_limit);
            return .{ .status = .success, .gas_used = cost, .output_len = length };
        }
    }.run;
}

fn bls_execute(comptime address: Bls, input: []const u8, out: []u8) bls_precompile.Error!u32 {
    const g1_length = bls_precompile.g1_length;
    const g2_length = bls_precompile.g2_length;
    switch (address) {
        .g1_add => try bls_precompile.g1_add(input, out[0..g1_length]),
        .g1_msm => try bls_precompile.g1_msm(input, out[0..g1_length]),
        .g2_add => try bls_precompile.g2_add(input, out[0..g2_length]),
        .g2_msm => try bls_precompile.g2_msm(input, out[0..g2_length]),
        .pairing_check => try bls_precompile.pairing_check(input, out[0..32]),
        .map_fp_to_g1 => try bls_precompile.map_fp_to_g1(input, out[0..g1_length]),
        .map_fp2_to_g2 => try bls_precompile.map_fp2_to_g2(input, out[0..g2_length]),
    }
    return switch (address) {
        .g1_add, .g1_msm, .map_fp_to_g1 => g1_length,
        .g2_add, .g2_msm, .map_fp2_to_g2 => g2_length,
        .pairing_check => 32,
    };
}

fn charge(gas_limit: u64, cost: u64) ?Result {
    if (cost > gas_limit) return .{ .status = .out_of_gas, .gas_used = gas_limit };
    return null;
}

fn words(len: usize) u64 {
    return (@as(u64, len) + 31) / 32;
}

fn identity(input: []const u8, gas_limit: u64, out: []u8) Result {
    const cost = 15 + 3 * words(input.len);
    if (charge(gas_limit, cost)) |failure| return failure;
    assert(out.len >= input.len);
    std.mem.copyForwards(u8, out[0..input.len], input);
    return .{ .status = .success, .gas_used = cost, .output_len = @intCast(input.len) };
}

fn sha256(input: []const u8, gas_limit: u64, out: []u8) Result {
    const cost = 60 + 12 * words(input.len);
    if (charge(gas_limit, cost)) |failure| return failure;
    assert(out.len >= 32);
    out[0..32].* = crypto.sha256.sha256(input);
    return .{ .status = .success, .gas_used = cost, .output_len = 32 };
}

fn ecrecover(input: []const u8, gas_limit: u64, out: []u8) Result {
    const cost = 3000;
    if (charge(gas_limit, cost)) |failure| return failure;
    // An unrecoverable signature succeeds with empty output.
    const word = crypto.secp256k1.precompile_ecrecover(input) orelse {
        return .{ .status = .success, .gas_used = cost };
    };
    out[0..32].* = word;
    return .{ .status = .success, .gas_used = cost, .output_len = 32 };
}

fn ripemd160(input: []const u8, gas_limit: u64, out: []u8) Result {
    const cost = 600 + 120 * words(input.len);
    if (charge(gas_limit, cost)) |failure| return failure;
    out[0..32].* = crypto.ripemd160.precompile_ripemd160(input);
    return .{ .status = .success, .gas_used = cost, .output_len = 32 };
}

fn blake2f(input: []const u8, gas_limit: u64, out: []u8) Result {
    const rounds = crypto.blake2f.input_rounds(input) orelse {
        return .{ .status = .failure, .gas_used = gas_limit };
    };
    if (charge(gas_limit, rounds)) |failure| return failure;
    crypto.blake2f.precompile_blake2f(input, out[0..64]) catch {
        return .{ .status = .failure, .gas_used = gas_limit };
    };
    return .{ .status = .success, .gas_used = rounds, .output_len = 64 };
}

/// P256VERIFY: RIP-7212 (3450 gas, OP Fjord) and EIP-7951 (6900 gas, Osaka). Invalid
/// signatures succeed with empty output.
fn p256verify(comptime cost: u64) Precompile {
    comptime assert(cost == 3450 or cost == 6900);
    return struct {
        fn run(input: []const u8, gas_limit: u64, out: []u8) Result {
            if (charge(gas_limit, cost)) |failure| return failure;
            const word = crypto.precompile_p256verify(input) orelse {
                return .{ .status = .success, .gas_used = cost };
            };
            out[0..32].* = word;
            return .{ .status = .success, .gas_used = cost, .output_len = 32 };
        }
    }.run;
}

const ModexpRules = crypto.modexp.Rules;

fn modexp_rules(comptime fork: Fork) ModexpRules {
    if (fork.at_least(.osaka)) return .osaka;
    if (fork.at_least(.berlin)) return .berlin;
    return .byzantium;
}

/// EIP-198 / EIP-2565 / EIP-7883 gas; EIP-7823 operand limits from Osaka.
fn modexp(comptime rules: ModexpRules) Precompile {
    return struct {
        fn run(input: []const u8, gas_limit: u64, out: []u8) Result {
            const parsed = crypto.modexp.precompile_modexp_parse(input) catch {
                return .{ .status = .out_of_gas, .gas_used = gas_limit };
            };
            if (rules == .osaka) {
                parsed.check_osaka_limits() catch {
                    return .{ .status = .failure, .gas_used = gas_limit };
                };
            }
            const cost = parsed.gas(rules);
            if (charge(gas_limit, cost)) |failure| return failure;
            const modulus_len = parsed.modulus.len;
            if (modulus_len > out.len) return .{ .status = .failure, .gas_used = gas_limit };
            const output = out[0..@intCast(modulus_len)];
            // Moduli wider than 8192 bits cost far more gas than any block holds.
            crypto.modexp.precompile_modexp_run(parsed, output) catch {
                return .{ .status = .failure, .gas_used = gas_limit };
            };
            return .{ .status = .success, .gas_used = cost, .output_len = @intCast(modulus_len) };
        }
    }.run;
}

test "precompiles: sets by fork" {
    const one = primitives.address_from_int(1);
    const nine = primitives.address_from_int(9);
    try std.testing.expect(is_precompile(.frontier, null, one));
    try std.testing.expect(!is_precompile(.byzantium, null, nine));
    try std.testing.expect(is_precompile(.istanbul, null, nine));
    try std.testing.expect(!is_precompile(.osaka, null, primitives.address_from_int(0x12)));
    try std.testing.expect(is_precompile(.osaka, null, primitives.address_from_int(0x100)));
    try std.testing.expect(!is_precompile(.prague, null, primitives.address_from_int(0x100)));
    const p256_address = primitives.address_from_int(0x100);
    try std.testing.expect(!is_precompile(.cancun, .ecotone, p256_address));
    try std.testing.expect(is_precompile(.cancun, .fjord, p256_address));
    const rip7212 = lookup(.cancun, .fjord, p256_address).?;
    var out: [32]u8 = undefined;
    const result = rip7212(&.{}, 10_000, &out);
    try std.testing.expectEqual(@as(u64, 3450), result.gas_used);
    try std.testing.expectEqual(@as(u32, 0), result.output_len);
    const eip7951 = lookup(.osaka, .jovian, p256_address).?;
    try std.testing.expectEqual(@as(u64, 6900), eip7951(&.{}, 10_000, &out).gas_used);
}

test "precompiles: identity and sha256" {
    var out: [64]u8 = undefined;
    const result = identity("abc", 100, &out);
    try std.testing.expectEqual(Status.success, result.status);
    try std.testing.expectEqual(@as(u64, 18), result.gas_used);
    try std.testing.expectEqualStrings("abc", out[0..3]);
    try std.testing.expectEqual(Status.out_of_gas, identity("abc", 17, &out).status);
    const digest = sha256("", 100, &out);
    try std.testing.expectEqual(@as(u64, 60), digest.gas_used);
    try std.testing.expectEqual(@as(u8, 0xe3), out[0]);
}

test "precompiles: bn254 gas by fork and Base pairing caps" {
    const pairing = primitives.address_from_int(0x08);
    var out: [256]u8 = undefined;
    // Empty pairing input is a successful check.
    const byzantium = lookup(.byzantium, null, pairing).?(&.{}, 200_000, &out);
    try std.testing.expectEqual(@as(u64, 100_000), byzantium.gas_used);
    try std.testing.expectEqual(@as(u8, 1), out[31]);
    const istanbul = lookup(.istanbul, null, pairing).?(&.{}, 200_000, &out);
    try std.testing.expectEqual(@as(u64, 45_000), istanbul.gas_used);
    const add = primitives.address_from_int(0x06);
    const add_result = lookup(.cancun, null, add).?(&.{}, 1_000, &out);
    try std.testing.expectEqual(@as(u64, 150), add_result.gas_used);

    // Over the Jovian cap fails before any pairing work; Granite still accepts it.
    var input: [Caps.bn254_pairing_jovian + 192]u8 = @splat(0);
    const jovian = lookup(.prague, .jovian, pairing).?(&input, 1 << 30, &out);
    try std.testing.expectEqual(Status.failure, jovian.status);
    const granite = lookup(.cancun, .granite, pairing).?(&input, 1 << 30, &out);
    try std.testing.expectEqual(Status.success, granite.status);
}

test "precompiles: BLS caps under Base and failures consume all gas" {
    const g1_msm = primitives.address_from_int(0x0c);
    var out: [256]u8 = undefined;
    var input: [Caps.g1_msm_jovian + 160]u8 = @splat(0);
    const capped = lookup(.prague, .jovian, g1_msm).?(&input, 1 << 40, &out);
    try std.testing.expectEqual(Status.failure, capped.status);
    try std.testing.expectEqual(@as(u64, 1 << 40), capped.gas_used);
    const empty = lookup(.prague, null, g1_msm).?(&.{}, 100_000, &out);
    try std.testing.expectEqual(Status.failure, empty.status);
    try std.testing.expectEqual(@as(u64, 100_000), empty.gas_used);
}

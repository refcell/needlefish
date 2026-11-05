//! Precompiled contracts: per-fork address sets, gas, and dispatch.
//!
//! Each precompile writes its output into the EVM return buffer and reports gas
//! used. Contracts whose cryptography has not landed yet (in `common.crypto`) are
//! dispatched to `unimplemented`, which fails the call; see docs/lanes/evm.md.

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

/// `op_rules` is the OP Stack rule set (null on Ethereum): Fjord adds RIP-7212 P256VERIFY.
pub fn lookup(comptime fork: Fork, op_rules: ?op.Rules, address: Address) ?Precompile {
    for (address[0..18]) |b| {
        if (b != 0) return null;
    }
    const number = std.mem.readInt(u16, address[18..20], .big);
    if (number == 0x100) {
        if (fork.at_least(.osaka)) return p256verify(6900);
        const rules = op_rules orelse return null;
        return if (rules.at_least(.fjord)) p256verify(3450) else null;
    }
    if (number == 0 or number > last_address(fork)) return null;
    return switch (number) {
        0x01 => ecrecover,
        0x02 => sha256,
        0x03 => ripemd160,
        0x04 => identity,
        0x05 => modexp(modexp_rules(fork)),
        0x09 => blake2f,
        else => unimplemented,
    };
}

pub fn is_precompile(comptime fork: Fork, op_rules: ?op.Rules, address: Address) bool {
    return lookup(fork, op_rules, address) != null;
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

fn unimplemented(input: []const u8, gas_limit: u64, out: []u8) Result {
    _ = input;
    _ = out;
    return .{ .status = .failure, .gas_used = gas_limit };
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

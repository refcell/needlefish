//! Precompiled contracts: per-fork address sets, gas, and dispatch.
//!
//! Each precompile writes its output into the EVM return buffer and reports gas
//! used. Contracts whose cryptography has not landed yet (in `common.crypto`) are
//! dispatched to `unimplemented`, which fails the call; see docs/lanes/evm.md.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const Fork = @import("fork.zig").Fork;
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

pub fn lookup(comptime fork: Fork, address: Address) ?Precompile {
    for (address[0..18]) |b| {
        if (b != 0) return null;
    }
    const number = std.mem.readInt(u16, address[18..20], .big);
    if (fork.at_least(.osaka) and number == 0x100) return unimplemented;
    if (number == 0 or number > last_address(fork)) return null;
    return switch (number) {
        0x02 => sha256,
        0x04 => identity,
        else => unimplemented,
    };
}

pub fn is_precompile(comptime fork: Fork, address: Address) bool {
    return lookup(fork, address) != null;
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
    std.crypto.hash.sha2.Sha256.hash(input, out[0..32], .{});
    return .{ .status = .success, .gas_used = cost, .output_len = 32 };
}

fn unimplemented(input: []const u8, gas_limit: u64, out: []u8) Result {
    _ = input;
    _ = out;
    return .{ .status = .failure, .gas_used = gas_limit };
}

test "precompiles: sets by fork" {
    const one = primitives.address_from_int(1);
    const nine = primitives.address_from_int(9);
    try std.testing.expect(is_precompile(.frontier, one));
    try std.testing.expect(!is_precompile(.byzantium, nine));
    try std.testing.expect(is_precompile(.istanbul, nine));
    try std.testing.expect(!is_precompile(.osaka, primitives.address_from_int(0x12)));
    try std.testing.expect(is_precompile(.osaka, primitives.address_from_int(0x100)));
    try std.testing.expect(!is_precompile(.prague, primitives.address_from_int(0x100)));
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

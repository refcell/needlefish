//! Interpreter fuzzing: random bytecode run as a transaction on every fork.
//!
//! The oracles are the interpreter's own assertions plus cross-run invariants:
//!   - determinism: the same code, fork, and pre-state give the same result twice,
//!   - gas: intrinsic <= gas used <= gas limit,
//!   - value: no execution creates ether (the balance sum never grows),
//!   - atomicity: a reverted or halted top frame leaves the target's storage untouched.
//! Seeded on every `zig build test`; coverage guided with `zig build test --fuzz`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Smith = testing.Smith;
const primitives = @import("primitives.zig");
const transaction = @import("transaction.zig");
const Fork = @import("fork.zig").Fork;
const Harness = @import("evm_test.zig").Harness;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Address = primitives.Address;

const code_size_max = 512;
/// Keeps every run below the harness limits (logs, journal, memory) so `StateFull`
/// never masks a real result: 59k execution gas buys at most 157 LOG0s.
const gas_limit: u64 = 80_000;
const sender_balance: u256 = 1 << 64;
const forks = std.enums.values(Fork);

const sender = primitives.address_from_int(0xf022);
const target = primitives.address_from_int(0x7a26e7);
const coinbase = primitives.address_from_int(0xc0ba5e);

/// Mostly small PUSH1 operands so jumps, memory offsets, and slots hit useful values.
/// Structure comes from a `Prng` seeded by the fuzz input: fuzz inputs are often constant
/// fills, which would otherwise collapse every program to one instruction.
fn generate_code(seed: u64, buffer: *[code_size_max]u8) []const u8 {
    var prng = Prng.init(seed);
    const instructions = prng.range(1, code_size_max / 2);
    var length: usize = 0;
    var count: u64 = 0;
    while (count < instructions) : (count += 1) {
        assert(length + 2 <= buffer.len);
        if (prng.chance(2, 3)) {
            buffer[length] = prng.int(u8);
            length += 1;
        } else {
            buffer[length] = 0x60; // PUSH1
            buffer[length + 1] = @intCast(prng.below(65));
            length += 2;
        }
    }
    assert(length <= buffer.len);
    return buffer[0..length];
}

const Observed = struct {
    status: @import("evm.zig").Status,
    gas_used: u64,
    output_hash: u64,
    logs: usize,
};

fn balance_sum(h: *Harness) u512 {
    var sum: u512 = 0;
    var iterator = h.state.accounts.valueIterator();
    while (iterator.next()) |account| sum += account.info.balance;
    return sum;
}

fn run_once(h: *Harness, fork: Fork, code: []const u8) !Observed {
    try h.database.put_account(target, 0, 1, code);
    try h.database.put_account(sender, sender_balance, 0, &.{});
    h.state.reset(h.database.interface());
    h.evm.block = .{ .coinbase = coinbase, .gas_limit = gas_limit, .number = 1, .timestamp = 1 };
    const tx = transaction.TxEnv{
        .caller = sender,
        .gas_limit = gas_limit,
        .gas_price = 1,
        .to = target,
        .value = 7,
        .data = &.{ 0x01, 0x02, 0x03 },
    };
    const result = try transaction.transact(&h.evm, fork, &tx);
    const executed = result.executed;
    // Refunds (up to half before London) may take gas used below the intrinsic cost.
    try testing.expect(executed.gas_used + executed.gas_refunded >= 21_000);
    try testing.expect(executed.gas_refunded <= executed.gas_used);
    try testing.expect(executed.gas_used <= gas_limit);
    try testing.expect(balance_sum(h) <= sender_balance);
    if (executed.status != .success) {
        try testing.expectEqual(@as(usize, 0), executed.logs.len);
        try testing.expectEqual(@as(u256, 0), try h.storage(target, 0));
        try testing.expectEqual(@as(u256, 0), try h.storage(target, 1));
    }
    return .{
        .status = executed.status,
        .gas_used = executed.gas_used,
        .output_hash = std.hash.Wyhash.hash(0, executed.output),
        .logs = executed.logs.len,
    };
}

fn fuzz_transact(h: *Harness, smith: *Smith) anyerror!void {
    const seed = smith.value(u64);
    const fork = forks[seed % forks.len];
    var buffer: [code_size_max]u8 = undefined;
    const code = generate_code(seed, &buffer);
    const first = run_once(h, fork, code) catch |err| {
        std.debug.print("evm fuzz: failure fork={s} code={x}\n", .{ @tagName(fork), code });
        return err;
    };
    const second = try run_once(h, fork, code);
    try testing.expectEqual(first, second);
}

test "evm fuzz: random bytecode transactions keep invariants on every fork" {
    const h = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(h);
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try fuzz.run(h, fuzz_transact, .{
        .seed = 0x65766d_66757a7a,
        .iterations = 512,
        .corpus = &.{
            // SSTORE then INVALID; CREATE of a reverting child; SELFDESTRUCT to self.
            &.{ 0x60, 0x01, 0x60, 0x00, 0x55, 0xfe },
            &.{ 0x60, 0xfd, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0x60, 0x00, 0xf0 },
            &.{ 0x30, 0xff },
        },
    });
}

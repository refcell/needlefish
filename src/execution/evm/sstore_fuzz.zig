//! Differential fuzz of SSTORE gas and refunds against the EIP-2200/2929/3529 rules.
//!
//! A random sequence of SSTORE and SLOAD over three slots (values 0, 1, 2; random original
//! values) runs as real bytecode. A table-free reference model tracks each slot's original
//! value, current value, and warmth, and predicts the exact gas used and the raw refund
//! counter (before the 1/5 cap), which the top frame's outcome reports.

const std = @import("std");
const assert = std.debug.assert;
const op = @import("opcode.zig");
const evm_module = @import("evm.zig");
const primitives = @import("primitives.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Harness = @import("evm_test.zig").Harness;

const contract = primitives.address_from_int(0x5503);
const gas_limit: u64 = 1_000_000;
const slots = 3;
const operations_max = 24;

const cold_sload: u64 = 2100;
const warm_read: u64 = 100;
const sstore_set: u64 = 20_000;
const sstore_reset: u64 = 2900;
const clear_refund: i64 = 4800;

const Model = struct {
    original: [slots]u8,
    current: [slots]u8,
    warm: [slots]bool = @splat(false),
    gas: u64 = 0,
    refund: i64 = 0,

    /// SSTORE's cold surcharge (EIP-2929) on top of the EIP-2200 cost.
    fn access(model: *Model, slot: usize) void {
        if (!model.warm[slot]) model.gas += cold_sload;
        model.warm[slot] = true;
    }

    /// SLOAD (EIP-2929): 2100 cold, 100 warm, plus PUSH1 and POP.
    fn sload(model: *Model, slot: usize) void {
        model.gas += 3 + 2 + (if (model.warm[slot]) warm_read else cold_sload);
        model.warm[slot] = true;
    }

    /// EIP-2200 with EIP-2929 costs and EIP-3529 refunds (London and later).
    fn sstore(model: *Model, slot: usize, new: u8) void {
        model.gas += 3 + 3; // Two PUSH1.
        model.access(slot);
        const original = model.original[slot];
        const current = model.current[slot];
        defer model.current[slot] = new;
        if (new == current) {
            model.gas += warm_read;
            return;
        }
        if (current == original) {
            model.gas += if (original == 0) sstore_set else sstore_reset;
            if (original != 0 and new == 0) model.refund += clear_refund;
            return;
        }
        model.gas += warm_read;
        if (original != 0) {
            if (current == 0) model.refund -= clear_refund;
            if (new == 0) model.refund += clear_refund;
        }
        if (original == new) {
            const restored: i64 = if (original == 0) sstore_set else sstore_reset;
            model.refund += restored - @as(i64, warm_read);
        }
    }
};

fn run_case(h: *Harness, prng: *Prng) !void {
    var model = Model{ .original = undefined, .current = undefined };
    try h.database.put_account(contract, 0, 1, &.{});
    for (0..slots) |slot| {
        const value: u8 = @intCast(prng.below(3));
        model.original[slot] = value;
        model.current[slot] = value;
        try h.database.put_storage(contract, slot, value);
    }
    var code: [operations_max * 5 + 1]u8 = undefined;
    var length: usize = 0;
    const count: usize = @intCast(prng.range(1, operations_max));
    for (0..count) |_| {
        const slot: u8 = @intCast(prng.below(slots));
        if (prng.below(4) == 0) {
            code[length..][0..4].* = .{ op.PUSH1, slot, op.SLOAD, op.POP };
            length += 4;
            model.sload(slot);
        } else {
            const value: u8 = @intCast(prng.below(3));
            code[length..][0..5].* = .{ op.PUSH1, value, op.PUSH1, slot, op.SSTORE };
            length += 5;
            model.sstore(slot, value);
        }
    }
    code[length] = op.STOP;
    length += 1;
    try h.database.put_account(contract, 0, 1, code[0..length]);
    h.state.reset(h.database.interface());
    const outcome = try h.call(.osaka, contract, &.{}, gas_limit);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(model.gas, gas_limit - outcome.gas_remaining);
    try std.testing.expectEqual(model.refund, outcome.gas_refund);
}

fn fuzz_sstore(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    @memcpy(seed[0..@min(bytes.len, 8)], bytes[0..@min(bytes.len, 8)]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    try run_case(h, &prng);
}

test "sstore fuzz: gas and refunds against the EIP-2200/2929/3529 model" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_sstore, .{ .seed = 0x5503_0001, .iterations = 500 });
}

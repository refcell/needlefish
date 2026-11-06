//! Differential fuzz of the journaled `State` against a snapshot-stack model.
//!
//! Random operations on four accounts and four slots each: nested checkpoints, reverts,
//! and discards (a call returning successfully), balance and nonce writes, SSTORE, TSTORE,
//! address and slot warming, logs, and account re-creation (a storage incarnation), across
//! several transactions. The model copies itself on every checkpoint and restores the copy
//! on revert. After every step every observable is compared: balances, nonces, storage,
//! transient storage, warm addresses, and the log count.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Harness = @import("evm_test.zig").Harness;
const State = state_module.State;
const Address = primitives.Address;

const accounts = 4;
const slots = 4;
const depth_max = 8;
const operations_max = 48;
const transactions_max = 4;

const Model = struct {
    balance: [accounts]u256,
    nonce: [accounts]u64,
    storage: [accounts][slots]u256,
    transient: [accounts][slots]u256 = std.mem.zeroes([accounts][slots]u256),
    warm_account: [accounts]bool = @splat(false),
    warm_slot: [accounts][slots]bool = std.mem.zeroes([accounts][slots]bool),
    logs: u32 = 0,
};

const Fuzzer = struct {
    h: *Harness,
    prng: *Prng,
    model: Model,
    snapshots: [depth_max]Model = undefined,
    checkpoints: [depth_max]state_module.Checkpoint = undefined,
    depth: u32 = 0,

    fn address(index: usize) Address {
        return primitives.address_from_int(0xa110 + index);
    }

    fn state(fuzzer: *Fuzzer) *State {
        return &fuzzer.h.state;
    }

    fn step(fuzzer: *Fuzzer) !void {
        const account_index: usize = @intCast(fuzzer.prng.below(accounts));
        const slot: usize = @intCast(fuzzer.prng.below(slots));
        const value: u256 = fuzzer.prng.below(4);
        const account = try fuzzer.state().load(address(account_index));
        const model = &fuzzer.model;
        switch (fuzzer.prng.below(11)) {
            0 => if (fuzzer.depth < depth_max) {
                fuzzer.snapshots[fuzzer.depth] = model.*;
                fuzzer.checkpoints[fuzzer.depth] = fuzzer.state().checkpoint();
                fuzzer.depth += 1;
            },
            1 => if (fuzzer.depth > 0) {
                fuzzer.depth -= 1;
                fuzzer.state().revert(fuzzer.checkpoints[fuzzer.depth]);
                model.* = fuzzer.snapshots[fuzzer.depth];
            },
            2 => if (fuzzer.depth > 0) {
                fuzzer.depth -= 1; // The call returned: its changes join the parent's.
            },
            3 => {
                try fuzzer.state().set_balance(account, value);
                model.balance[account_index] = value;
            },
            4 => {
                const nonce = 1 + fuzzer.prng.below(3);
                try fuzzer.state().set_nonce(account, nonce);
                model.nonce[account_index] = nonce;
            },
            5, 6 => try fuzzer.sstore(account, account_index, slot, value),
            7 => {
                try fuzzer.state().transient_store(address(account_index), slot, value);
                model.transient[account_index][slot] = value;
            },
            8 => {
                const access = try fuzzer.state().access(address(account_index));
                try std.testing.expectEqual(!model.warm_account[account_index], access.is_cold);
                model.warm_account[account_index] = true;
            },
            9 => {
                try fuzzer.state().log(address(account_index), &.{}, &.{});
                model.logs += 1;
            },
            10 => if (!account.info.has_code()) {
                try fuzzer.state().create_account(account, .cancun);
                model.storage[account_index] = @splat(0);
                model.nonce[account_index] = 1;
            },
            else => unreachable,
        }
        try fuzzer.check();
    }

    fn sstore(
        fuzzer: *Fuzzer,
        account: *state_module.Account,
        account_index: usize,
        slot: usize,
        value: u256,
    ) !void {
        const access = try fuzzer.state().storage_access(account, slot);
        const model = &fuzzer.model;
        try std.testing.expectEqual(!model.warm_slot[account_index][slot], access.is_cold);
        try std.testing.expectEqual(model.storage[account_index][slot], access.slot.present);
        model.warm_slot[account_index][slot] = true;
        try fuzzer.state().storage_write(account, access.slot, value);
        model.storage[account_index][slot] = value;
    }

    fn check(fuzzer: *Fuzzer) !void {
        const model = &fuzzer.model;
        for (0..accounts) |index| {
            const account = try fuzzer.state().load(address(index));
            try std.testing.expectEqual(model.balance[index], account.info.balance);
            try std.testing.expectEqual(model.nonce[index], account.info.nonce);
            const warm = fuzzer.state().is_warm(address(index));
            try std.testing.expectEqual(model.warm_account[index], warm);
            for (0..slots) |slot| {
                const stored = try fuzzer.state().storage_value(address(index), slot);
                try std.testing.expectEqual(model.storage[index][slot], stored);
                const transient = fuzzer.state().transient_load(address(index), slot);
                try std.testing.expectEqual(model.transient[index][slot], transient);
            }
        }
        const logs: u32 = @intCast(fuzzer.state().transaction_logs().len);
        try std.testing.expectEqual(model.logs, logs);
    }

    /// Finish the transaction: discard open checkpoints (the top frame succeeded), then
    /// clear what EIP-1153/2929 scope to one transaction.
    fn next_transaction(fuzzer: *Fuzzer) void {
        fuzzer.depth = 0;
        fuzzer.state().finalize_transaction(.cancun);
        fuzzer.state().begin_transaction();
        fuzzer.model.transient = std.mem.zeroes([accounts][slots]u256);
        fuzzer.model.warm_account = @splat(false);
        fuzzer.model.warm_slot = std.mem.zeroes([accounts][slots]bool);
        fuzzer.model.logs = 0;
    }
};

fn run_case(h: *Harness, prng: *Prng) !void {
    var model = Model{ .balance = undefined, .nonce = undefined, .storage = undefined };
    for (0..accounts) |index| {
        model.balance[index] = prng.below(4);
        model.nonce[index] = 1; // Non-empty, so EIP-161 never deletes an account mid-case.
        try h.database.put_account(Fuzzer.address(index), model.balance[index], 1, &.{});
        for (0..slots) |slot| {
            model.storage[index][slot] = prng.below(3);
            try h.database.put_storage(Fuzzer.address(index), slot, model.storage[index][slot]);
        }
    }
    h.state.reset(h.database.interface());
    h.state.begin_transaction();
    var fuzzer = Fuzzer{ .h = h, .prng = prng, .model = model };
    try fuzzer.check();
    const transactions: u32 = @intCast(prng.range(1, transactions_max));
    for (0..transactions) |_| {
        const operations: u32 = @intCast(prng.range(1, operations_max));
        for (0..operations) |_| try fuzzer.step();
        fuzzer.next_transaction();
        try fuzzer.check();
    }
    assert(fuzzer.depth == 0);
}

fn fuzz_journal(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    @memcpy(seed[0..@min(bytes.len, 8)], bytes[0..@min(bytes.len, 8)]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    try run_case(h, &prng);
}

test "journal fuzz: nested checkpoints and reverts match a snapshot model" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_journal, .{ .seed = 0x10a7_0001, .iterations = 300 });
}

//! Differential fuzz of EIP-7702 authorization processing against a model.
//!
//! One type-4 transaction carries 1..6 authorizations over three authorities that start
//! absent, empty-but-present, funded, already delegated, or holding real code; sometimes
//! the sender is an authority (its nonce is bumped before authorizations apply). Tuples
//! use the right chain, chain 0, or a wrong chain, right or wrong nonces, the 2^64 - 1
//! nonce, a missing signer, and the zero address (clearing). The model applies the
//! EIP-7702 rules in order and predicts every authority's code and nonce and the gas used:
//! intrinsic gas minus the existing-account refunds, capped at a fifth (EIP-3529).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const bytecode = @import("bytecode.zig");
const transaction = @import("transaction.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Harness = @import("evm_test.zig").Harness;
const Address = primitives.Address;

const authorities = 3;
const authorizations_max = 6;
const sender = primitives.address_from_int(0x5e4d);
const recipient = primitives.address_from_int(0x2ec1);
const contract_code = [_]u8{ 0x60, 0x00, 0x00 };

const Code = enum { none, delegated, contract };

const Account = struct {
    exists: bool,
    nonce: u64,
    code: Code,
    target: Address = primitives.address_zero,
};

fn authority_address(index: usize) Address {
    return primitives.address_from_int(0xa070 + index);
}

fn delegate_address(prng: *Prng) Address {
    return primitives.address_from_int(0xde1e + prng.below(3));
}

fn designator(target: Address) [bytecode.delegation_len]u8 {
    var code: [bytecode.delegation_len]u8 = undefined;
    code[0..3].* = bytecode.delegation_prefix;
    code[3..23].* = target;
    return code;
}

fn setup_authority(h: *Harness, prng: *Prng, address: Address) !Account {
    var account = Account{ .exists = false, .nonce = 0, .code = .none };
    switch (prng.below(5)) {
        0 => return account, // Absent from the database.
        1 => account.exists = true, // Present but empty.
        2 => {
            account.exists = true;
            account.nonce = prng.below(3);
        },
        3 => {
            account = .{ .exists = true, .nonce = 1, .code = .delegated };
            account.target = delegate_address(prng);
        },
        4 => account = .{ .exists = true, .nonce = 1, .code = .contract },
        else => unreachable,
    }
    const code: []const u8 = switch (account.code) {
        .none => &.{},
        .delegated => &designator(account.target),
        .contract => &contract_code,
    };
    const balance: u256 = prng.below(2);
    try h.database.put_account(address, balance, account.nonce, code);
    return account;
}

/// EIP-7702 processing of one tuple; returns the refund it earns.
fn model_apply(account: *Account, auth: transaction.Authorization, chain_id: u64) u64 {
    if (auth.chain_id != 0 and auth.chain_id != chain_id) return 0;
    if (auth.nonce == std.math.maxInt(u64)) return 0;
    if (auth.authority == null) return 0;
    if (account.code == .contract) return 0;
    if (account.nonce != auth.nonce) return 0;
    const refund: u64 = if (account.exists) 25_000 - 12_500 else 0;
    const clear = std.mem.eql(u8, &auth.address, &primitives.address_zero);
    account.code = if (clear) .none else .delegated;
    account.target = auth.address;
    account.nonce += 1;
    account.exists = true;
    return refund;
}

fn random_authorization(
    prng: *Prng,
    chain_id: u64,
    index: usize,
    nonce: u64,
) transaction.Authorization {
    const chains = [_]u256{ chain_id, chain_id, 0, chain_id + 1 };
    const nonces = [_]u64{ nonce, nonce, nonce + 1, std.math.maxInt(u64) };
    const address = if (prng.below(5) == 0) primitives.address_zero else delegate_address(prng);
    return .{
        .chain_id = chains[@intCast(prng.below(chains.len))],
        .address = address,
        .nonce = nonces[@intCast(prng.below(nonces.len))],
        .authority = if (prng.below(10) == 0) null else authority_address(index),
    };
}

fn run_case(h: *Harness, prng: *Prng) !void {
    const chain_id = h.evm.config.chain_id;
    const sender_nonce = prng.below(3);
    const self_sponsored = prng.below(3) == 0;
    var model: [authorities]Account = undefined;
    for (&model, 0..) |*account, index| {
        // Accounts persist in the database across cases; "absent" must mean absent.
        _ = h.database.accounts.remove(authority_address(index));
        account.* = try setup_authority(h, prng, authority_address(index));
    }
    try h.database.put_account(sender, 1 << 60, sender_nonce, &.{});
    if (self_sponsored) {
        // Authority 0 is the sender: present, nonce already bumped for the transaction.
        model[0] = .{ .exists = true, .nonce = sender_nonce + 1, .code = .none };
    }
    var list: [authorizations_max]transaction.Authorization = undefined;
    const count: usize = @intCast(prng.range(1, authorizations_max));
    var refund: u64 = 0;
    for (list[0..count]) |*auth| {
        const index: usize = @intCast(prng.below(authorities));
        auth.* = random_authorization(prng, chain_id, index, model[index].nonce);
        if (self_sponsored and index == 0 and auth.authority != null) auth.authority = sender;
        refund += model_apply(&model[index], auth.*, chain_id);
    }
    h.state.reset(h.database.interface());
    const tx = transaction.TxEnv{
        .tx_type = .eip7702,
        .caller = sender,
        .nonce = sender_nonce,
        .chain_id = chain_id,
        .gas_limit = 1_000_000,
        .gas_price = 0,
        .gas_priority_fee = 0,
        .to = recipient,
        .authorization_list = list[0..count],
    };
    const result = try transaction.transact(&h.evm, .prague, &tx);
    const intrinsic: u64 = 21_000 + 25_000 * @as(u64, count);
    try std.testing.expectEqual(intrinsic - @min(refund, intrinsic / 5), result.executed.gas_used);
    for (model, 0..) |expected, index| {
        const address = if (self_sponsored and index == 0) sender else authority_address(index);
        try check_account(h, address, expected, self_sponsored and index == 0, sender_nonce);
    }
}

fn check_account(
    h: *Harness,
    address: Address,
    expected: Account,
    is_sender: bool,
    sender_nonce: u64,
) !void {
    const account = try h.state.load(address);
    // The sender's nonce is bumped by the transaction itself on top of any authorization.
    const nonce = if (is_sender) @max(expected.nonce, sender_nonce + 1) else expected.nonce;
    try std.testing.expectEqual(nonce, account.info.nonce);
    const code = try h.state.code(account);
    switch (expected.code) {
        .none => try std.testing.expectEqual(@as(usize, 0), code.len),
        .contract => try std.testing.expectEqualSlices(u8, &contract_code, code),
        .delegated => try std.testing.expectEqualSlices(u8, &designator(expected.target), code),
    }
}

fn fuzz_delegation(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    @memcpy(seed[0..@min(bytes.len, 8)], bytes[0..@min(bytes.len, 8)]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    try run_case(h, &prng);
}

test "delegation fuzz: EIP-7702 authorizations against a model" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_delegation, .{ .seed = 0x7702_0001, .iterations = 400 });
}

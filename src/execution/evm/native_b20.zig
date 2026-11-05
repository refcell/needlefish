//! B-20 token core shared by the Asset and Stablecoin variants: storage layout, accounting,
//! roles, pause flags, policy guards, and the ERC-20 movements.
//! base/base `crates/common/precompiles/src/common` (core_storage, token_accounting, ops).
//!
//! Storage (ERC-7201 `base.b20` at the token address): name 0, symbol 1, contract URI 2,
//! total supply 3, balances 4, allowances 5, roles 6, role admins 7, admin count 8, transfer
//! sender/receiver/executor policy ids packed in slot 9 (u64 lanes from the low end), mint
//! receiver policy 10, paused bit set 11, supply cap 12, permit nonces 13, seize exempt /
//! receiver policy ids packed in slot 14.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");
const policy = @import("native_policy.zig");
const primitives = @import("primitives.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Context = native.Context;
const Error = native.Error;

pub const root: u256 = 0xc78b71fee795ddd74aff64ea9b2474194c938c3196430e10bb5f01ed48434000;
pub const slot_name: u256 = root;
pub const slot_symbol: u256 = root + 1;
pub const slot_contract_uri: u256 = root + 2;
pub const slot_total_supply: u256 = root + 3;
const base_balances: u256 = root + 4;
const base_allowances: u256 = root + 5;
const base_roles: u256 = root + 6;
const base_role_admins: u256 = root + 7;
const slot_admin_count: u256 = root + 8;
const slot_transfer_policies: u256 = root + 9;
const slot_mint_policy: u256 = root + 10;
const slot_paused: u256 = root + 11;
pub const slot_supply_cap: u256 = root + 12;
const base_nonces: u256 = root + 13;
const slot_seize_policies: u256 = root + 14;

/// Largest supply cap: 2^128 - 1.
pub const supply_cap_max: u256 = std.math.maxInt(u128);

pub const role_default_admin: u256 = 0;
pub const role_mint: u256 = 0x154c00819833dac601ee5ddded6fda79d9d8b506b911b3dbd54cdb95fe6c3686;
pub const role_burn: u256 = 0xe97b137254058bd94f28d2f3eb79e2d34074ffb488d042e3bc958e0a57d2fa22;
pub const role_burn_blocked: u256 =
    0x7408fdc0d31c7bcb349eab611f5d1168acd4303574993f8cdc98b1cd18c41cae;
pub const role_seize: u256 = 0x3469b8b0d89e9604f8510ed143f74a8336d22955d4f83e23bf53d9414e27f432;
pub const role_pause: u256 = 0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d;
pub const role_unpause: u256 =
    0x265b220c5a8891efdd9e1b1b7fa72f257bd5169f8d87e319cf3dad6ff52b94ae;
pub const role_metadata: u256 =
    0x6bd6b5318a46e5fff572d5e4258a20774aab40cc35ac7680654b9081fcc82f80;

const scope_transfer_sender: u256 =
    0xb81736c875ab819dd97f59f2a6542cfb731ad52b4ae15a6f24df2fb02b0327f5;
const scope_transfer_receiver: u256 =
    0x8a4b3fa2d8b921852bc0089c6ef0958aa6961897be36fd731330fe2cd23f8363;
const scope_transfer_executor: u256 =
    0x10be5173aff2a44e748bd9acd8b19fe34689581398a9db7ba2fb671e786ff7d8;
const scope_mint_receiver: u256 =
    0xa0d5ae037e66a09119acf080a1d807abb9b6d03b6b9130eb19f7c1e6bdb8ffc8;
const scope_seize_exempt: u256 =
    0xedb5da348cfb67af08746d3afd1be81034b50d5c8576f31aff688f39dfd540ed;
const scope_seize_receiver: u256 =
    0xbf15b19caf5c77422c038bc25f26b8b815c3a14f6d04c6616076b81bcfe07b3d;

pub const PolicyScope = enum {
    transfer_sender,
    transfer_receiver,
    transfer_executor,
    mint_receiver,
    seize_exempt,
    seize_receiver,

    pub fn id(scope: PolicyScope) u256 {
        return switch (scope) {
            .transfer_sender => scope_transfer_sender,
            .transfer_receiver => scope_transfer_receiver,
            .transfer_executor => scope_transfer_executor,
            .mint_receiver => scope_mint_receiver,
            .seize_exempt => scope_seize_exempt,
            .seize_receiver => scope_seize_receiver,
        };
    }

    pub fn from_id(value: u256) ?PolicyScope {
        const scopes = [_]PolicyScope{
            .transfer_sender,
            .transfer_receiver,
            .transfer_executor,
            .mint_receiver,
            .seize_exempt,
            .seize_receiver,
        };
        for (scopes) |scope| {
            if (scope.id() == value) return scope;
        }
        return null;
    }

    /// Storage slot and byte offset (from the low end) of the scope's u64 lane.
    fn lane(scope: PolicyScope) struct { slot: u256, shift: u8 } {
        return switch (scope) {
            .transfer_sender => .{ .slot = slot_transfer_policies, .shift = 0 },
            .transfer_receiver => .{ .slot = slot_transfer_policies, .shift = 64 },
            .transfer_executor => .{ .slot = slot_transfer_policies, .shift = 128 },
            .mint_receiver => .{ .slot = slot_mint_policy, .shift = 0 },
            .seize_exempt => .{ .slot = slot_seize_policies, .shift = 0 },
            .seize_receiver => .{ .slot = slot_seize_policies, .shift = 64 },
        };
    }
};

/// SEIZE exists from V2 (Cobalt).
pub const PausableFeature = enum(u8) { transfer = 0, mint = 1, burn = 2, seize = 3 };

pub const error_unauthorized_account = [4]u8{ 0xe2, 0x51, 0x7d, 0x3f };
pub const error_contract_paused = [4]u8{ 0xfd, 0x8c, 0x42, 0x45 };
pub const error_insufficient_allowance = [4]u8{ 0x19, 0x2b, 0x9e, 0x4e };
pub const error_insufficient_balance = [4]u8{ 0xdb, 0x42, 0x14, 0x4d };
pub const error_invalid_sender = [4]u8{ 0x4c, 0x14, 0xf6, 0x4c };
pub const error_invalid_receiver = [4]u8{ 0x9c, 0xfe, 0xa5, 0x83 };
pub const error_invalid_approver = [4]u8{ 0x8b, 0xc1, 0x46, 0xc4 };
pub const error_invalid_spender = [4]u8{ 0x4e, 0x15, 0xef, 0xda };
pub const error_policy_forbids = [4]u8{ 0xa4, 0x3f, 0xec, 0x12 };
pub const error_account_not_blocked = [4]u8{ 0x64, 0xa5, 0xcb, 0x46 };
pub const error_account_not_seizable = [4]u8{ 0x91, 0xdb, 0xbc, 0x8d };

pub const event_transfer: B256 = primitives.hex_to_b256(
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
);
pub const event_approval: B256 = primitives.hex_to_b256(
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
);
pub const event_role_granted: B256 = primitives.hex_to_b256(
    "2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",
);
pub const event_role_revoked: B256 = primitives.hex_to_b256(
    "f6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b",
);

const word = native.u256_word;
const address_word = native.address_word;
const panic_overflow: u256 = 0x11;

pub fn overflow(context: *Context) error{Revert} {
    return context.revert_word(native.error_panic, word(panic_overflow));
}

fn same(a: Address, b: Address) bool {
    return std.mem.eql(u8, &a, &b);
}

pub fn is_zero(account: Address) bool {
    return same(account, primitives.address_zero);
}

/// Revert with `selector` and the given ABI words.
pub fn revert_words(context: *Context, selector: [4]u8, words: []const [32]u8) error{Revert} {
    assert(words.len <= 3);
    var buffer: [4 + 32 * 3]u8 = undefined;
    buffer[0..4].* = selector;
    for (words, 0..) |item, index| buffer[4 + 32 * index ..][0..32].* = item;
    return context.revert(buffer[0 .. 4 + 32 * words.len]);
}

// ------------------------------------------------------------------ accounting

pub fn balance_slot(account: Address) u256 {
    return native.mapping_slot(address_word(account), base_balances);
}

pub fn allowance_slot(owner: Address, spender: Address) u256 {
    const inner = native.mapping_slot(address_word(owner), base_allowances);
    return native.mapping_slot(address_word(spender), inner);
}

fn role_slot(role: u256, account: Address) u256 {
    const inner = native.mapping_slot(word(role), base_roles);
    return native.mapping_slot(address_word(account), inner);
}

fn role_admin_slot(role: u256) u256 {
    return native.mapping_slot(word(role), base_role_admins);
}

pub fn nonce_slot(owner: Address) u256 {
    return native.mapping_slot(address_word(owner), base_nonces);
}

pub fn balance_of(context: *Context, account: Address) Error!u256 {
    return context.sload(balance_slot(account));
}

pub fn has_role(context: *Context, role: u256, account: Address) Error!bool {
    return try context.sload(role_slot(role, account)) != 0;
}

pub fn role_admin(context: *Context, role: u256) Error!u256 {
    return context.sload(role_admin_slot(role));
}

pub fn set_role_admin(context: *Context, role: u256, admin: u256) Error!void {
    try context.sstore(role_admin_slot(role), admin);
}

/// Member count; only DEFAULT_ADMIN_ROLE is counted.
pub fn role_member_count(context: *Context, role: u256) Error!u256 {
    if (role != role_default_admin) return 0;
    return context.sload(slot_admin_count);
}

pub fn policy_id(context: *Context, scope: PolicyScope) Error!u64 {
    const lane = scope.lane();
    return @truncate(try context.sload(lane.slot) >> lane.shift);
}

pub fn set_policy_id(context: *Context, scope: PolicyScope, id: u64) Error!void {
    const lane = scope.lane();
    const current = try context.sload(lane.slot);
    const mask = @as(u256, std.math.maxInt(u64)) << lane.shift;
    try context.sstore(lane.slot, (current & ~mask) | (@as(u256, id) << lane.shift));
}

pub fn paused(context: *Context) Error!u256 {
    return context.sload(slot_paused);
}

pub fn set_paused(context: *Context, flags: u256) Error!void {
    try context.sstore(slot_paused, flags);
}

pub fn feature_mask(feature: PausableFeature) u256 {
    return @as(u256, 1) << @backingInt(feature);
}

// ------------------------------------------------------------------ guards

pub fn ensure_role(context: *Context, account: Address, role: u256) Error!void {
    if (try has_role(context, role, account)) return;
    return revert_words(context, error_unauthorized_account, &.{
        address_word(account),
        word(role),
    });
}

pub fn ensure_not_paused(context: *Context, feature: PausableFeature) Error!void {
    if (try paused(context) & feature_mask(feature) == 0) return;
    return context.revert_word(error_contract_paused, word(@backingInt(feature)));
}

pub fn ensure_policy(context: *Context, scope: PolicyScope, account: Address) Error!void {
    const id = try policy_id(context, scope);
    if (try policy.is_authorized(context, id, account)) return;
    return revert_words(context, error_policy_forbids, &.{ word(scope.id()), word(id) });
}

/// seizeWithMemo: the account must fail the seize-exempt policy.
pub fn ensure_seizable(context: *Context, account: Address) Error!void {
    const id = try policy_id(context, .seize_exempt);
    if (!try policy.is_authorized(context, id, account)) return;
    return context.revert_word(error_account_not_seizable, address_word(account));
}

/// Authorization against an already-read policy id.
fn ensure_policy_id(context: *Context, scope: PolicyScope, id: u64, account: Address) Error!void {
    if (try policy.is_authorized(context, id, account)) return;
    return revert_words(context, error_policy_forbids, &.{ word(scope.id()), word(id) });
}

pub const TransferPolicies = struct { sender: u64, receiver: u64, executor: u64 };

/// V2: the three transfer policy ids from one read of the packed slot.
pub fn transfer_policies(context: *Context) Error!TransferPolicies {
    const packed_ids = try context.sload(slot_transfer_policies);
    return .{
        .sender = @truncate(packed_ids),
        .receiver = @truncate(packed_ids >> 64),
        .executor = @truncate(packed_ids >> 128),
    };
}

/// burnBlocked: the account must fail the transfer-sender policy.
pub fn ensure_blocked(context: *Context, account: Address) Error!void {
    const id = try policy_id(context, .transfer_sender);
    if (!try policy.is_authorized(context, id, account)) return;
    return context.revert_word(error_account_not_blocked, address_word(account));
}

// ------------------------------------------------------------------ movements

fn emit_transfer(context: *Context, from: Address, to: Address, amount: u256) Error!void {
    const topics = [3]B256{ event_transfer, address_word(from), address_word(to) };
    try context.emit(&topics, &word(amount));
}

fn revert_insufficient_balance(
    context: *Context,
    account: Address,
    balance: u256,
    needed: u256,
) error{Revert} {
    return revert_words(context, error_insufficient_balance, &.{
        address_word(account),
        word(balance),
        word(needed),
    });
}

/// Balance movement with receiver/sender checks and (unless privileged) transfer policies.
pub fn transfer_inner(
    context: *Context,
    from: Address,
    to: Address,
    amount: u256,
    privileged: bool,
) Error!void {
    if (is_zero(to)) return context.revert_word(error_invalid_receiver, address_word(to));
    if (is_zero(from)) return context.revert_word(error_invalid_sender, address_word(from));
    if (!privileged) {
        try ensure_policy(context, .transfer_sender, from);
        try ensure_policy(context, .transfer_receiver, to);
    }
    try move_balance(context, from, to, amount);
}

/// Debit `from`, credit `to`, emit Transfer.
pub fn move_balance(context: *Context, from: Address, to: Address, amount: u256) Error!void {
    const from_balance = try balance_of(context, from);
    if (from_balance < amount) {
        return revert_insufficient_balance(context, from, from_balance, amount);
    }
    try context.sstore(balance_slot(from), from_balance - amount);
    const to_balance = try balance_of(context, to);
    const sum = @addWithOverflow(to_balance, amount);
    if (sum[1] != 0) return overflow(context);
    try context.sstore(balance_slot(to), sum[0]);
    try emit_transfer(context, from, to, amount);
}

/// V2 transfer: pause, zero checks, then one policy read (skipped when privileged).
pub fn transfer_v2(context: *Context, to: Address, amount: u256, privileged: bool) Error!void {
    try ensure_not_paused(context, .transfer);
    const from = context.caller;
    if (is_zero(to)) return context.revert_word(error_invalid_receiver, address_word(to));
    if (is_zero(from)) return context.revert_word(error_invalid_sender, address_word(from));
    if (!privileged) {
        const policies = try transfer_policies(context);
        try ensure_policy_id(context, .transfer_sender, policies.sender, from);
        try ensure_policy_id(context, .transfer_receiver, policies.receiver, to);
    }
    try move_balance(context, from, to, amount);
}

/// V2 transferFrom: zero checks, allowance, one policy read, executor, sender, receiver.
pub fn transfer_from_v2(
    context: *Context,
    from: Address,
    to: Address,
    amount: u256,
    privileged: bool,
) Error!void {
    try ensure_not_paused(context, .transfer);
    if (is_zero(to)) return context.revert_word(error_invalid_receiver, address_word(to));
    if (is_zero(from)) return context.revert_word(error_invalid_sender, address_word(from));
    const caller = context.caller;
    const allowance = try context.sload(allowance_slot(from, caller));
    const is_infinite = allowance == std.math.maxInt(u256);
    if (!is_infinite and allowance < amount) {
        return revert_words(context, error_insufficient_allowance, &.{
            address_word(caller),
            word(allowance),
            word(amount),
        });
    }
    if (!privileged) {
        const policies = try transfer_policies(context);
        if (!same(caller, from)) {
            try ensure_policy_id(context, .transfer_executor, policies.executor, caller);
        }
        try ensure_policy_id(context, .transfer_sender, policies.sender, from);
        try ensure_policy_id(context, .transfer_receiver, policies.receiver, to);
    }
    try move_balance(context, from, to, amount);
    if (!is_infinite) try context.sstore(allowance_slot(from, caller), allowance - amount);
}

/// ERC-20 transferFrom: allowance (unlimited at 2^256-1), executor policy, movement.
pub fn transfer_from(
    context: *Context,
    from: Address,
    to: Address,
    amount: u256,
    privileged: bool,
) Error!void {
    try ensure_not_paused(context, .transfer);
    if (is_zero(to)) return context.revert_word(error_invalid_receiver, address_word(to));
    if (is_zero(from)) return context.revert_word(error_invalid_sender, address_word(from));
    const caller = context.caller;
    const allowance = try context.sload(allowance_slot(from, caller));
    const is_infinite = allowance == std.math.maxInt(u256);
    if (!is_infinite and allowance < amount) {
        return revert_words(context, error_insufficient_allowance, &.{
            address_word(caller),
            word(allowance),
            word(amount),
        });
    }
    if (!privileged and !same(caller, from)) {
        try ensure_policy(context, .transfer_executor, caller);
    }
    try transfer_inner(context, from, to, amount, privileged);
    if (!is_infinite) try context.sstore(allowance_slot(from, caller), allowance - amount);
}

pub fn approve(context: *Context, owner: Address, spender: Address, amount: u256) Error!void {
    if (is_zero(owner)) return context.revert_word(error_invalid_approver, address_word(owner));
    if (is_zero(spender)) {
        return context.revert_word(error_invalid_spender, address_word(spender));
    }
    try context.sstore(allowance_slot(owner, spender), amount);
    const topics = [3]B256{ event_approval, address_word(owner), address_word(spender) };
    try context.emit(&topics, &word(amount));
}

pub fn burn_inner(context: *Context, from: Address, amount: u256) Error!void {
    const balance = try balance_of(context, from);
    if (balance < amount) return revert_insufficient_balance(context, from, balance, amount);
    try context.sstore(balance_slot(from), balance - amount);
    const supply = try context.sload(slot_total_supply);
    if (supply < amount) return overflow(context);
    try context.sstore(slot_total_supply, supply - amount);
    try emit_transfer(context, from, primitives.address_zero, amount);
}

/// Grant without authorization checks; counts DEFAULT_ADMIN_ROLE members.
pub fn grant_role_unchecked(
    context: *Context,
    role: u256,
    account: Address,
    sender: Address,
) Error!void {
    if (try has_role(context, role, account)) return;
    try context.sstore(role_slot(role, account), 1);
    if (role == role_default_admin) {
        const count = try context.sload(slot_admin_count);
        if (count == std.math.maxInt(u256)) return overflow(context);
        try context.sstore(slot_admin_count, count + 1);
    }
    const topics = [4]B256{
        event_role_granted,
        word(role),
        address_word(account),
        address_word(sender),
    };
    try context.emit(&topics, &.{});
}

pub fn revoke_role_unchecked(
    context: *Context,
    role: u256,
    account: Address,
    sender: Address,
) Error!void {
    if (!try has_role(context, role, account)) return;
    try context.sstore(role_slot(role, account), 0);
    if (role == role_default_admin) {
        const count = try context.sload(slot_admin_count);
        if (count == 0) return overflow(context);
        try context.sstore(slot_admin_count, count - 1);
    }
    const topics = [4]B256{
        event_role_revoked,
        word(role),
        address_word(account),
        address_word(sender),
    };
    try context.emit(&topics, &.{});
}

const testing = std.testing;
const keccak256 = @import("../../common/crypto/root.zig").keccak256;

test "b20: roots, roles, scopes, errors, and events match their definitions" {
    const roots = .{.{ "base.b20", root }};
    inline for (roots) |entry| {
        const id = std.mem.readInt(u256, &keccak256(entry[0]), .big);
        const outer = keccak256(&word(id - 1));
        const derived = std.mem.readInt(u256, &outer, .big) & ~@as(u256, 0xff);
        try testing.expectEqual(entry[1], derived);
    }
    const hashes = .{
        .{ "MINT_ROLE", role_mint },
        .{ "BURN_ROLE", role_burn },
        .{ "BURN_BLOCKED_ROLE", role_burn_blocked },
        .{ "SEIZE_ROLE", role_seize },
        .{ "PAUSE_ROLE", role_pause },
        .{ "UNPAUSE_ROLE", role_unpause },
        .{ "METADATA_ROLE", role_metadata },
        .{ "TRANSFER_SENDER_POLICY", PolicyScope.transfer_sender.id() },
        .{ "TRANSFER_RECEIVER_POLICY", PolicyScope.transfer_receiver.id() },
        .{ "TRANSFER_EXECUTOR_POLICY", PolicyScope.transfer_executor.id() },
        .{ "MINT_RECEIVER_POLICY", PolicyScope.mint_receiver.id() },
    };
    inline for (hashes) |entry| {
        try testing.expectEqual(entry[1], std.mem.readInt(u256, &keccak256(entry[0]), .big));
    }
    const selectors = .{
        .{ "AccessControlUnauthorizedAccount(address,bytes32)", &error_unauthorized_account },
        .{ "ContractPaused(uint8)", &error_contract_paused },
        .{ "InsufficientAllowance(address,uint256,uint256)", &error_insufficient_allowance },
        .{ "InsufficientBalance(address,uint256,uint256)", &error_insufficient_balance },
        .{ "InvalidSender(address)", &error_invalid_sender },
        .{ "InvalidReceiver(address)", &error_invalid_receiver },
        .{ "InvalidApprover(address)", &error_invalid_approver },
        .{ "InvalidSpender(address)", &error_invalid_spender },
        .{ "PolicyForbids(bytes32,uint64)", &error_policy_forbids },
        .{ "AccountNotBlocked(address)", &error_account_not_blocked },
        .{ "Transfer(address,address,uint256)", &event_transfer },
        .{ "Approval(address,address,uint256)", &event_approval },
        .{ "RoleGranted(bytes32,address,address)", &event_role_granted },
        .{ "RoleRevoked(bytes32,address,address)", &event_role_revoked },
    };
    inline for (selectors) |entry| {
        const expected: []const u8 = entry[1];
        try testing.expectEqualSlices(u8, keccak256(entry[0])[0..expected.len], expected);
    }
    const scope = PolicyScope.from_id(PolicyScope.mint_receiver.id()).?;
    try testing.expect(scope == .mint_receiver);
}

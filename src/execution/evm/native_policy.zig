//! PolicyRegistry (Beryl), allowlist/blocklist policies for the B-20 tokens.
//! base/base `crates/common/precompiles/src/policy` (V1 logic and wire surface).
//!
//! Storage (ERC-7201 `base.policy_registry`): `policies` mapping(uint64 => packed word) at the
//! root (bit 255 exists, low 160 bits admin), `members` mapping(uint64 => mapping(address =>
//! bool)) at root + 1, `pending_admins` at root + 2, `next_counter` at root + 3, composite
//! `children` at root + 4. A policy id is `type << 56 | counter`; ids 0 (always allow) and
//! `1 << 56 | 1` (always block) are built in. Mutations require the activation registry's
//! PolicyRegistry feature; views do not.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");
const abi = @import("native_abi.zig");
const activation = @import("native_activation.zig");
const primitives = @import("primitives.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Context = native.Context;
const Error = native.Error;
const Arguments = abi.Arguments;
const AddressArray = abi.AddressArray;

pub const address = primitives.hex_to_address("8453000000000000000000000000000000000002");
pub const root: u256 = 0x00503aeb06982fa1fe3151dc68f90b3946c55c449dfd447e49dcaece71ba4a00;
const members_base: u256 = root + 1;
const pending_admins_base: u256 = root + 2;
const next_counter_slot: u256 = root + 3;

pub const type_blocklist: u8 = 0;
pub const type_allowlist: u8 = 1;
pub const always_allow_id: u64 = 0;
pub const always_block_id: u64 = (1 << 56) | 1;
const builtin_policy_count: u64 = 2;
const counter_mask: u64 = (1 << 56) - 1;
pub const accounts_per_batch_max: u32 = 64;
const exists_bit: u256 = 1 << 255;

pub const Tag = enum {
    create_policy,
    create_policy_with_accounts,
    stage_update_admin,
    finalize_update_admin,
    renounce_admin,
    update_allowlist,
    update_blocklist,
    is_authorized,
    policy_exists,
    policy_admin,
    pending_policy_admin,
};

const Function = struct {
    tag: Tag,
    selector: [4]u8,
    parameters: []const u8,
    kinds: []const abi.Kind,
    mutating: bool,
};

pub const functions = [_]Function{
    .{
        .tag = .create_policy,
        .selector = .{ 0xca, 0x5d, 0x55, 0xf6 },
        .parameters = "(address,uint8)",
        .kinds = &.{ .address, .policy_type },
        .mutating = true,
    },
    .{
        .tag = .create_policy_with_accounts,
        .selector = .{ 0xa2, 0xd3, 0x04, 0x4f },
        .parameters = "(address,uint8,address[])",
        .kinds = &.{ .address, .policy_type, .address_array },
        .mutating = true,
    },
    .{
        .tag = .stage_update_admin,
        .selector = .{ 0x1d, 0x7a, 0xe6, 0x95 },
        .parameters = "(uint64,address)",
        .kinds = &.{ .uint64, .address },
        .mutating = true,
    },
    .{
        .tag = .finalize_update_admin,
        .selector = .{ 0x33, 0x03, 0x1a, 0x9c },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = true,
    },
    .{
        .tag = .renounce_admin,
        .selector = .{ 0xef, 0xdb, 0x7f, 0xa3 },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = true,
    },
    .{
        .tag = .update_allowlist,
        .selector = .{ 0x33, 0x88, 0xfb, 0x5b },
        .parameters = "(uint64,bool,address[])",
        .kinds = &.{ .uint64, .bool, .address_array },
        .mutating = true,
    },
    .{
        .tag = .update_blocklist,
        .selector = .{ 0x5c, 0x4e, 0x51, 0xb8 },
        .parameters = "(uint64,bool,address[])",
        .kinds = &.{ .uint64, .bool, .address_array },
        .mutating = true,
    },
    .{
        .tag = .is_authorized,
        .selector = .{ 0x55, 0xa1, 0x17, 0x9e },
        .parameters = "(uint64,address)",
        .kinds = &.{ .uint64, .address },
        .mutating = false,
    },
    .{
        .tag = .policy_exists,
        .selector = .{ 0x33, 0x0f, 0x56, 0x37 },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = false,
    },
    .{
        .tag = .policy_admin,
        .selector = .{ 0x09, 0xdd, 0x0a, 0x47 },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = false,
    },
    .{
        .tag = .pending_policy_admin,
        .selector = .{ 0x01, 0x75, 0x48, 0xb7 },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = false,
    },
};

pub const error_unauthorized = [4]u8{ 0x82, 0xb4, 0x29, 0x00 };
pub const error_policy_not_found = [4]u8{ 0x72, 0x0c, 0xaa, 0x4f };
pub const error_incompatible_policy_type = [4]u8{ 0xf1, 0x01, 0x1e, 0xf5 };
pub const error_zero_address = [4]u8{ 0xd9, 0x2e, 0x23, 0x3d };
pub const error_batch_size_too_large = [4]u8{ 0x08, 0x3e, 0x2f, 0x67 };
pub const error_no_pending_admin = [4]u8{ 0xb4, 0x53, 0x9a, 0xfa };
pub const error_panic = [4]u8{ 0x4e, 0x48, 0x7b, 0x71 };
const panic_overflow: u256 = 0x11;

pub const event_policy_created: B256 = primitives.hex_to_b256(
    "718d87917f0c4cfd1263707ef0e77c656ed8d8bfaca06152bdb0b8094142ec27",
);
pub const event_policy_admin_staged: B256 = primitives.hex_to_b256(
    "dbf3b34a4c956c56ca05cd4b8f9293a4347ad61994445a4b89817d4a19561136",
);
pub const event_policy_admin_updated: B256 = primitives.hex_to_b256(
    "98925cfb1bc09c5b43dd0dd56d3d95aa04fb3300927580cc588c3f5dd58c15e1",
);
pub const event_allowlist_updated: B256 = primitives.hex_to_b256(
    "18c46532f90187ba11e436e21da087b684801d7f0787f2043f26f079c91e9ef0",
);
pub const event_blocklist_updated: B256 = primitives.hex_to_b256(
    "2ff63c102b1b9fd7f5d39f83039c5d6aaf50a414a4f2def2704e41be2628f1e3",
);

fn find(selector: [4]u8) ?*const Function {
    for (&functions) |*function| {
        if (std.mem.eql(u8, &function.selector, &selector)) return function;
    }
    return null;
}

pub fn dispatch(context: *Context, input: []const u8) Error![]const u8 {
    if (context.value != 0) return context.revert_selector(native.selector_non_payable);
    try context.charge_calldata(input);
    const selector = native.selector_of(input);
    const function = find(selector) orelse return context.revert_selector(selector);
    assert(input.len >= 4);
    var failure: native.DecodeFailure = .overrun;
    const arguments = abi.decode_arguments(input[4..], function.kinds, &failure) orelse
        return context.revert_decode(selector, function.parameters, failure);
    if (function.mutating) try ensure_activated(context);
    return route(context, function.tag, &arguments);
}

fn ensure_activated(context: *Context) Error!void {
    const feature = native.u256_word(activation.feature_policy_registry);
    const slot = activation.feature_slot(feature);
    if (try context.sload_at(activation.address, slot) != 0) return;
    return context.revert_word(activation.error_feature_not_activated, feature);
}

fn route(context: *Context, tag: Tag, arguments: *const Arguments) Error![]const u8 {
    const id = arguments.uint64(0);
    switch (tag) {
        .create_policy => {
            const created = try create_policy(context, arguments, false);
            return native.write_word(context, native.u256_word(created));
        },
        .create_policy_with_accounts => {
            const created = try create_policy(context, arguments, true);
            return native.write_word(context, native.u256_word(created));
        },
        .stage_update_admin => try stage_update_admin(context, id, arguments.address(1)),
        .finalize_update_admin => try finalize_update_admin(context, id),
        .renounce_admin => try renounce_admin(context, id),
        .update_allowlist => try update_membership(context, id, type_allowlist, arguments),
        .update_blocklist => try update_membership(context, id, type_blocklist, arguments),
        .is_authorized => {
            const authorized = try is_authorized(context, id, arguments.address(1));
            return native.write_word(context, native.u256_word(@intFromBool(authorized)));
        },
        .policy_exists => {
            const exists = try policy_exists(context, id);
            return native.write_word(context, native.u256_word(@intFromBool(exists)));
        },
        .policy_admin => {
            const admin = try policy_admin(context, id);
            return native.write_word(context, native.address_word(admin));
        },
        .pending_policy_admin => {
            const pending = try pending_policy_admin(context, id);
            return native.write_word(context, native.address_word(pending));
        },
    }
    return context.out[0..0];
}

// ------------------------------------------------------------------ storage

fn id_word(id: u64) [32]u8 {
    return native.u256_word(id);
}

fn policy_slot(id: u64) u256 {
    return native.mapping_slot(id_word(id), root);
}

pub fn member_slot(id: u64, account: Address) u256 {
    const inner = native.mapping_slot(id_word(id), members_base);
    return native.mapping_slot(native.address_word(account), inner);
}

fn pending_slot(id: u64) u256 {
    return native.mapping_slot(id_word(id), pending_admins_base);
}

fn pack_policy(admin: Address) u256 {
    return exists_bit | std.mem.readInt(u160, &admin, .big);
}

fn packed_admin(word: u256) Address {
    return to_address(@truncate(word));
}

fn to_address(value: u160) Address {
    var result: Address = undefined;
    std.mem.writeInt(u160, &result, value, .big);
    return result;
}

fn id_type(id: u64) u8 {
    return @intCast(id >> 56);
}

fn is_builtin(id: u64) bool {
    return id == always_allow_id or id == always_block_id;
}

fn same(a: Address, b: Address) bool {
    return std.mem.eql(u8, &a, &b);
}

fn is_zero(account: Address) bool {
    return same(account, primitives.address_zero);
}

/// The packed word of an existing policy, or a PolicyNotFound revert.
fn require_custom(context: *Context, id: u64) Error!u256 {
    const word = try context.sload(policy_slot(id));
    if (word & exists_bit == 0) return context.revert_selector(error_policy_not_found);
    return word;
}

fn require_admin(context: *Context, id: u64) Error!u256 {
    const word = try require_custom(context, id);
    if (!same(packed_admin(word), context.caller)) {
        return context.revert_selector(error_unauthorized);
    }
    return word;
}

fn require_batch(context: *Context, accounts: AddressArray) Error!void {
    if (accounts.count() <= accounts_per_batch_max) return;
    return context.revert_word(error_batch_size_too_large, native.u256_word(64));
}

// ------------------------------------------------------------------ logic

fn ensure_initialized(context: *Context) Error!u64 {
    const counter: u64 = @truncate(try context.sload(next_counter_slot));
    if (counter >= builtin_policy_count) return counter;
    try context.install_marker();
    try context.sstore(policy_slot(always_allow_id), exists_bit);
    try context.sstore(policy_slot(always_block_id), exists_bit);
    try context.sstore(next_counter_slot, builtin_policy_count);
    return builtin_policy_count;
}

fn create_policy(context: *Context, arguments: *const Arguments, with_accounts: bool) Error!u64 {
    const admin = arguments.address(0);
    const policy_type = arguments.small(1);
    assert(policy_type <= type_allowlist);
    if (is_zero(admin)) return context.revert_selector(error_zero_address);
    if (with_accounts) try require_batch(context, arguments.array);
    const counter = try ensure_initialized(context);
    if (counter >= counter_mask) {
        return context.revert_word(error_panic, native.u256_word(panic_overflow));
    }
    try context.sstore(next_counter_slot, counter + 1);
    const id = (@as(u64, policy_type) << 56) | (counter & counter_mask);
    try context.sstore(policy_slot(id), pack_policy(admin));
    const caller_word = native.address_word(context.caller);
    const created = [3]B256{ event_policy_created, id_word(id), caller_word };
    try context.emit(&created, &native.u256_word(policy_type));
    const updated = [4]B256{
        event_policy_admin_updated,
        id_word(id),
        native.address_word(primitives.address_zero),
        native.address_word(admin),
    };
    try context.emit(&updated, &.{});
    if (!with_accounts) return id;
    for (0..arguments.array.count()) |index| {
        const account = arguments.array.word(@intCast(index))[12..32].*;
        try context.sstore(member_slot(id, account), 1);
    }
    try emit_membership(context, id, policy_type, true, arguments.array);
    return id;
}

fn emit_membership(
    context: *Context,
    id: u64,
    policy_type: u8,
    flag: bool,
    accounts: AddressArray,
) Error!void {
    assert(accounts.count() <= accounts_per_batch_max);
    const signature = if (policy_type == type_allowlist)
        event_allowlist_updated
    else
        event_blocklist_updated;
    const topics = [3]B256{ signature, id_word(id), native.address_word(context.caller) };
    // abi.encode(bool, address[]): flag, offset 0x40, length, elements.
    var data: [96 + 32 * accounts_per_batch_max]u8 = undefined;
    data[0..32].* = native.u256_word(@intFromBool(flag));
    data[32..64].* = native.u256_word(0x40);
    data[64..96].* = native.u256_word(accounts.count());
    @memcpy(data[96..][0..accounts.words.len], accounts.words);
    try context.emit(&topics, data[0 .. 96 + accounts.words.len]);
}

fn stage_update_admin(context: *Context, id: u64, new_admin: Address) Error!void {
    _ = try require_admin(context, id);
    try context.sstore(pending_slot(id), std.mem.readInt(u160, &new_admin, .big));
    const topics = [4]B256{
        event_policy_admin_staged,
        id_word(id),
        native.address_word(context.caller),
        native.address_word(new_admin),
    };
    try context.emit(&topics, &.{});
}

fn finalize_update_admin(context: *Context, id: u64) Error!void {
    const word = try require_custom(context, id);
    const pending = to_address(@truncate(try context.sload(pending_slot(id))));
    if (is_zero(pending)) return context.revert_selector(error_no_pending_admin);
    if (!same(pending, context.caller)) return context.revert_selector(error_unauthorized);
    try context.sstore(policy_slot(id), pack_policy(context.caller));
    try context.sstore(pending_slot(id), 0);
    const topics = [4]B256{
        event_policy_admin_updated,
        id_word(id),
        native.address_word(packed_admin(word)),
        native.address_word(context.caller),
    };
    try context.emit(&topics, &.{});
}

fn renounce_admin(context: *Context, id: u64) Error!void {
    _ = try require_admin(context, id);
    try context.sstore(policy_slot(id), pack_policy(primitives.address_zero));
    try context.sstore(pending_slot(id), 0);
    const topics = [4]B256{
        event_policy_admin_updated,
        id_word(id),
        native.address_word(context.caller),
        native.address_word(primitives.address_zero),
    };
    try context.emit(&topics, &.{});
}

/// Check order matches the Solidity reference: existence, type, admin, batch size.
fn update_membership(
    context: *Context,
    id: u64,
    expected_type: u8,
    arguments: *const Arguments,
) Error!void {
    const word = try require_custom(context, id);
    if (id_type(id) != expected_type) {
        return context.revert_selector(error_incompatible_policy_type);
    }
    if (!same(packed_admin(word), context.caller)) {
        return context.revert_selector(error_unauthorized);
    }
    const accounts = arguments.array;
    try require_batch(context, accounts);
    const add = arguments.flag(1);
    for (0..accounts.count()) |index| {
        const account = accounts.word(@intCast(index))[12..32].*;
        try context.sstore(member_slot(id, account), @intFromBool(add));
    }
    try emit_membership(context, id, expected_type, add, accounts);
}

fn is_authorized(context: *Context, id: u64, account: Address) Error!bool {
    if (id_type(id) > type_allowlist) return false;
    if (id == always_allow_id) return true;
    if (id == always_block_id) return false;
    const member = try context.sload(member_slot(id, account)) != 0;
    return if (id_type(id) == type_allowlist) member else !member;
}

fn policy_exists(context: *Context, id: u64) Error!bool {
    if (id_type(id) > type_allowlist) return false;
    if (is_builtin(id)) return true;
    return try context.sload(policy_slot(id)) & exists_bit != 0;
}

fn policy_admin(context: *Context, id: u64) Error!Address {
    if (id_type(id) > type_allowlist) return primitives.address_zero;
    const word = try context.sload(policy_slot(id));
    if (word & exists_bit == 0) return primitives.address_zero;
    return packed_admin(word);
}

fn pending_policy_admin(context: *Context, id: u64) Error!Address {
    if (id_type(id) > type_allowlist or is_builtin(id)) return primitives.address_zero;
    return to_address(@truncate(try context.sload(pending_slot(id))));
}

const testing = std.testing;
const keccak256 = @import("../../common/crypto/root.zig").keccak256;

test "policy: selectors, events, and root match their definitions" {
    const names = [_][]const u8{
        "createPolicy(address,uint8)",
        "createPolicyWithAccounts(address,uint8,address[])",
        "stageUpdateAdmin(uint64,address)",
        "finalizeUpdateAdmin(uint64)",
        "renounceAdmin(uint64)",
        "updateAllowlist(uint64,bool,address[])",
        "updateBlocklist(uint64,bool,address[])",
        "isAuthorized(uint64,address)",
        "policyExists(uint64)",
        "policyAdmin(uint64)",
        "pendingPolicyAdmin(uint64)",
    };
    for (names, functions) |name, function| {
        try testing.expectEqualSlices(u8, keccak256(name)[0..4], &function.selector);
    }
    const checks = .{
        .{ "Unauthorized()", &error_unauthorized },
        .{ "PolicyNotFound()", &error_policy_not_found },
        .{ "IncompatiblePolicyType()", &error_incompatible_policy_type },
        .{ "ZeroAddress()", &error_zero_address },
        .{ "BatchSizeTooLarge(uint256)", &error_batch_size_too_large },
        .{ "NoPendingAdmin()", &error_no_pending_admin },
        .{ "Panic(uint256)", &error_panic },
        .{ "PolicyCreated(uint64,address,uint8)", &event_policy_created },
        .{ "PolicyAdminStaged(uint64,address,address)", &event_policy_admin_staged },
        .{ "PolicyAdminUpdated(uint64,address,address)", &event_policy_admin_updated },
        .{ "AllowlistUpdated(uint64,address,bool,address[])", &event_allowlist_updated },
        .{ "BlocklistUpdated(uint64,address,bool,address[])", &event_blocklist_updated },
    };
    inline for (checks) |check| {
        const expected: []const u8 = check[1];
        try testing.expectEqualSlices(u8, keccak256(check[0])[0..expected.len], expected);
    }
    const id = std.mem.readInt(u256, &keccak256("base.policy_registry"), .big);
    const outer = keccak256(&native.u256_word(id - 1));
    try testing.expectEqual(root, std.mem.readInt(u256, &outer, .big) & ~@as(u256, 0xff));
}

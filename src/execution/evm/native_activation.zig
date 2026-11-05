//! ActivationRegistry (Beryl), the feature gate for the Base token precompiles.
//! base/base `crates/common/precompiles/src/activation`.
//!
//! Storage (ERC-7201 `base.activation_registry`): `features` mapping(bytes32 => bool) at the
//! root, `admin` address at root + 1. The admin is the chain-configured address; from
//! Cobalt a non-zero stored admin overrides it and `setAdmin` is callable. From Cobalt every
//! selector rejects attached value.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");
const primitives = @import("primitives.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Context = native.Context;
const Error = native.Error;

pub const address = primitives.hex_to_address("8453000000000000000000000000000000000001");
pub const root: u256 = 0x43ee1bbe25e988521cccd8b2c8fbd38c8287ebff8e074e825a70dfd3885cce00;
const admin_slot: u256 = root + 1;

/// Feature ids checked by the factory and token precompiles.
pub const feature_policy_registry: u256 =
    0xb582ebae03f16fee49a6763f78df482fb11ae73f103ed0d330bbe556aa90a43f;
pub const feature_b20_stablecoin: u256 =
    0xecfa0def2c10020caaf65e6155aa69c84b24892aaef76eeac52e0e2b3a0b8601;
pub const feature_b20_asset: u256 =
    0xcdcc772fe4cbdb1029f822861176d09e646db96723d4c1e82ddfdeb8163ef54c;

pub const selector_is_activated = [4]u8{ 0xba, 0x87, 0xaf, 0x80 };
pub const selector_check_activated = [4]u8{ 0xde, 0x5b, 0xfd, 0x9b };
pub const selector_admin = [4]u8{ 0xf8, 0x51, 0xa4, 0x40 };
pub const selector_set_admin = [4]u8{ 0x70, 0x4b, 0x6c, 0x02 };
pub const selector_activate = [4]u8{ 0x59, 0xdb, 0x6e, 0x85 };
pub const selector_deactivate = [4]u8{ 0x22, 0xee, 0xe8, 0x4c };

pub const error_unauthorized = [4]u8{ 0x8e, 0x4a, 0x23, 0xd6 };
pub const error_already_activated = [4]u8{ 0x86, 0x6b, 0x00, 0x41 };
pub const error_feature_not_activated = [4]u8{ 0xb9, 0xb2, 0xa4, 0x25 };
pub const error_static_call_not_allowed = [4]u8{ 0xbe, 0xab, 0xa5, 0xb7 };
pub const error_admin_storage_not_enabled = [4]u8{ 0xec, 0xcf, 0x51, 0x25 };
pub const error_zero_admin_address = [4]u8{ 0x3e, 0xf3, 0x9b, 0x81 };

pub const event_feature_activated: B256 = primitives.hex_to_b256(
    "8c7a0ecdbb8d96e867e43ec1aef80027976ee493c18bef399fa799ed19752451",
);
pub const event_feature_deactivated: B256 = primitives.hex_to_b256(
    "15bf65a782c3258c63268ba9d7aed710cf9f9315d3687d9a4632ccdad7926c84",
);
pub const event_admin_changed: B256 = primitives.hex_to_b256(
    "4eb572e99196bed0270fbd5b17a948e19c3f50a97838cb0d2a75a823ff8e6c50",
);

fn is_zero(account: Address) bool {
    return std.mem.eql(u8, &account, &primitives.address_zero);
}

fn address_from_u160(value: u160) Address {
    var result: Address = undefined;
    std.mem.writeInt(u160, &result, value, .big);
    return result;
}

fn state_admin_enabled(context: *const Context) bool {
    return context.is_cobalt();
}

pub fn feature_slot(feature: [32]u8) u256 {
    return native.mapping_slot(feature, root);
}

pub fn dispatch(context: *Context, input: []const u8) Error![]const u8 {
    if (context.is_cobalt() and context.value != 0) {
        return context.revert_selector(native.selector_non_payable);
    }
    try context.charge_calldata(input);
    const selector = native.selector_of(input);
    const eql = std.mem.eql;
    if (!state_admin_enabled(context) and eql(u8, &selector, &selector_set_admin)) {
        return context.revert_selector(selector);
    }
    if (eql(u8, &selector, &selector_admin)) {
        return native.write_word(context, native.address_word(try admin(context)));
    }
    if (eql(u8, &selector, &selector_set_admin)) {
        const word = native.argument(input, 0) orelse
            return context.revert_decode(selector, "(address)", .overrun);
        const new_admin = native.argument_address(word) orelse
            return context.revert_decode(selector, "(address)", .type_check);
        try set_admin(context, new_admin);
        return context.out[0..0];
    }
    const is_known = eql(u8, &selector, &selector_is_activated) or
        eql(u8, &selector, &selector_check_activated) or
        eql(u8, &selector, &selector_activate) or
        eql(u8, &selector, &selector_deactivate);
    if (!is_known) return context.revert_selector(selector);
    const feature = (native.argument(input, 0) orelse
        return context.revert_decode(selector, "(bytes32)", .overrun)).*;
    if (eql(u8, &selector, &selector_activate)) return set_activated(context, feature, true);
    if (eql(u8, &selector, &selector_deactivate)) return set_activated(context, feature, false);
    const activated = try context.sload(feature_slot(feature)) != 0;
    if (eql(u8, &selector, &selector_is_activated)) {
        return native.write_word(context, native.u256_word(@intFromBool(activated)));
    }
    assert(eql(u8, &selector, &selector_check_activated));
    if (!activated) return context.revert_word(error_feature_not_activated, feature);
    return context.out[0..0];
}

fn admin(context: *Context) Error!Address {
    if (state_admin_enabled(context)) {
        const stored: u160 = @truncate(try context.sload(admin_slot));
        if (stored != 0) return address_from_u160(stored);
    }
    return context.activation_admin orelse primitives.address_zero;
}

/// The caller, which must be the non-zero admin.
fn require_admin_caller(context: *Context) Error!Address {
    const caller = context.caller;
    const unauthorized = native.address_word(caller);
    if (is_zero(caller)) {
        return context.revert_word(error_unauthorized, unauthorized);
    }
    const current = try admin(context);
    if (is_zero(current) or !std.mem.eql(u8, &current, &caller)) {
        return context.revert_word(error_unauthorized, unauthorized);
    }
    return caller;
}

fn set_activated(context: *Context, feature: [32]u8, activated: bool) Error![]const u8 {
    if (context.is_static) return context.revert_selector(error_static_call_not_allowed);
    const caller = try require_admin_caller(context);
    const slot = feature_slot(feature);
    const current = try context.sload(slot) != 0;
    if (activated and current) return context.revert_word(error_already_activated, feature);
    if (!activated and !current) return context.revert_word(error_feature_not_activated, feature);
    const topics = [3]B256{
        if (activated) event_feature_activated else event_feature_deactivated,
        feature,
        native.address_word(caller),
    };
    if (activated) try context.install_marker();
    try context.sstore(slot, @intFromBool(activated));
    try context.emit(&topics, &.{});
    return context.out[0..0];
}

fn set_admin(context: *Context, new_admin: Address) Error!void {
    if (context.is_static) return context.revert_selector(error_static_call_not_allowed);
    assert(state_admin_enabled(context));
    if (is_zero(new_admin)) {
        return context.revert_selector(error_zero_admin_address);
    }
    const caller = try require_admin_caller(context);
    try context.install_marker();
    try context.sstore(admin_slot, std.mem.readInt(u160, &new_admin, .big));
    const caller_word = native.address_word(caller);
    const topics = [4]B256{
        event_admin_changed,
        caller_word,
        native.address_word(new_admin),
        caller_word,
    };
    try context.emit(&topics, &.{});
}

const testing = std.testing;
const keccak256 = @import("../../common/crypto/root.zig").keccak256;

fn expect_hash(comptime signature: []const u8, expected: []const u8) !void {
    try testing.expectEqualSlices(u8, keccak256(signature)[0..expected.len], expected);
}

test "activation: selectors, events, and root match their definitions" {
    try expect_hash("isActivated(bytes32)", &selector_is_activated);
    try expect_hash("checkActivated(bytes32)", &selector_check_activated);
    try expect_hash("admin()", &selector_admin);
    try expect_hash("setAdmin(address)", &selector_set_admin);
    try expect_hash("activate(bytes32)", &selector_activate);
    try expect_hash("deactivate(bytes32)", &selector_deactivate);
    try expect_hash("Unauthorized(address)", &error_unauthorized);
    try expect_hash("AlreadyActivated(bytes32)", &error_already_activated);
    try expect_hash("FeatureNotActivated(bytes32)", &error_feature_not_activated);
    try expect_hash("StaticCallNotAllowed()", &error_static_call_not_allowed);
    try expect_hash("AdminStorageNotEnabled()", &error_admin_storage_not_enabled);
    try expect_hash("ZeroAdminAddress()", &error_zero_admin_address);
    try expect_hash("FeatureActivated(bytes32,address)", &event_feature_activated);
    try expect_hash("FeatureDeactivated(bytes32,address)", &event_feature_deactivated);
    try expect_hash("AdminChanged(address,address,address)", &event_admin_changed);
    const id = std.mem.readInt(u256, &keccak256("base.activation_registry"), .big);
    const outer = keccak256(&native.u256_word(id - 1));
    try testing.expectEqual(root, std.mem.readInt(u256, &outer, .big) & ~@as(u256, 0xff));
}

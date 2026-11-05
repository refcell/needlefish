//! PolicyRegistry, allowlist/blocklist policies for the B-20 tokens.
//! base/base `crates/common/precompiles/src/policy`: V1 at Beryl, V2 at Cobalt (composite
//! UNION/INTERSECT policies over 2-4 children), V3 from Denim (inverted policy ids: bit 63
//! negates a policy in views and composite children).
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
const keccak256 = @import("../../common/crypto/root.zig").keccak256;
const Arguments = abi.Arguments;
const Array = abi.Array;

pub const address = primitives.hex_to_address("8453000000000000000000000000000000000002");
pub const root: u256 = 0x00503aeb06982fa1fe3151dc68f90b3946c55c449dfd447e49dcaece71ba4a00;
const members_base: u256 = root + 1;
const pending_admins_base: u256 = root + 2;
const next_counter_slot: u256 = root + 3;

const children_base: u256 = root + 4;

pub const Version = enum(u8) { v1, v2, v3 };

pub fn version_of(context: *const Context) Version {
    if (context.upgrade.at_least(.denim)) return .v3;
    if (context.upgrade.at_least(.cobalt)) return .v2;
    return .v1;
}

pub const type_blocklist: u8 = 0;
pub const type_allowlist: u8 = 1;
pub const type_union: u8 = 2;
pub const type_intersect: u8 = 3;
pub const children_min: u32 = 2;
pub const children_max: u32 = 4;
const inverted_bit: u64 = 1 << 63;
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
    create_composite_policy,
    update_composite,
    min_composite_child_policies,
    max_composite_child_policies,
    composite_policy_child_ids,
    inverted_policy_id,
};

const Function = struct {
    tag: Tag,
    selector: [4]u8,
    parameters: []const u8,
    kinds: []const abi.Kind,
    mutating: bool,
    since: Version = .v1,
};

pub const functions = [_]Function{
    .{
        .tag = .create_policy,
        .selector = .{ 0xca, 0x5d, 0x55, 0xf6 },
        .parameters = "(address,uint8)",
        .kinds = &.{ .address, .enumeration },
        .mutating = true,
    },
    .{
        .tag = .create_policy_with_accounts,
        .selector = .{ 0xa2, 0xd3, 0x04, 0x4f },
        .parameters = "(address,uint8,address[])",
        .kinds = &.{ .address, .enumeration, .address_array },
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
    .{
        .tag = .create_composite_policy,
        .selector = .{ 0x6f, 0xdd, 0x14, 0x91 },
        .parameters = "(address,uint8,uint64[])",
        .kinds = &.{ .address, .enumeration, .uint64_array },
        .mutating = true,
        .since = .v2,
    },
    .{
        .tag = .update_composite,
        .selector = .{ 0xbf, 0xe1, 0x42, 0xc0 },
        .parameters = "(uint64,uint64[])",
        .kinds = &.{ .uint64, .uint64_array },
        .mutating = true,
        .since = .v2,
    },
    .{
        .tag = .min_composite_child_policies,
        .selector = .{ 0xb3, 0xae, 0x29, 0xf7 },
        .parameters = "()",
        .kinds = &.{},
        .mutating = false,
        .since = .v2,
    },
    .{
        .tag = .max_composite_child_policies,
        .selector = .{ 0x54, 0x30, 0x98, 0x70 },
        .parameters = "()",
        .kinds = &.{},
        .mutating = false,
        .since = .v2,
    },
    .{
        .tag = .composite_policy_child_ids,
        .selector = .{ 0x7c, 0x40, 0xdf, 0x74 },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = false,
        .since = .v2,
    },
    .{
        .tag = .inverted_policy_id,
        .selector = .{ 0x6b, 0x46, 0x89, 0x33 },
        .parameters = "(uint64)",
        .kinds = &.{.uint64},
        .mutating = false,
        .since = .v3,
    },
};

pub const error_unauthorized = [4]u8{ 0x82, 0xb4, 0x29, 0x00 };
pub const error_policy_not_found = [4]u8{ 0x72, 0x0c, 0xaa, 0x4f };
pub const error_incompatible_policy_type = [4]u8{ 0xf1, 0x01, 0x1e, 0xf5 };
pub const error_zero_address = [4]u8{ 0xd9, 0x2e, 0x23, 0x3d };
pub const error_batch_size_too_large = [4]u8{ 0x08, 0x3e, 0x2f, 0x67 };
pub const error_no_pending_admin = [4]u8{ 0xb4, 0x53, 0x9a, 0xfa };
pub const error_panic = [4]u8{ 0x4e, 0x48, 0x7b, 0x71 };
pub const error_child_policies_outside_of_range = [4]u8{ 0x69, 0x7e, 0xc8, 0x68 };
pub const error_invalid_child_policy = [4]u8{ 0x46, 0x50, 0x8e, 0xf6 };
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
pub const event_composite_policy_updated: B256 = primitives.hex_to_b256(
    "4ff6adaab31b0df87aa7b8b7320c52b8b3b5eede3bf28a6baaaa8b8b7e1d6363",
);

fn find(selector: [4]u8, version: Version) ?*const Function {
    for (&functions) |*function| {
        if (@backingInt(function.since) > @backingInt(version)) continue;
        if (std.mem.eql(u8, &function.selector, &selector)) return function;
    }
    return null;
}

pub fn dispatch(context: *Context, input: []const u8) Error![]const u8 {
    if (context.value != 0) return context.revert_selector(native.selector_non_payable);
    try context.charge_calldata(input);
    const selector = native.selector_of(input);
    const version = version_of(context);
    const function = find(selector, version) orelse return context.revert_selector(selector);
    assert(input.len >= 4);
    var failure: native.DecodeFailure = .overrun;
    const enumeration_max = if (version == .v1) type_allowlist else type_intersect;
    const kinds = function.kinds;
    const arguments = abi.decode_arguments(input[4..], kinds, enumeration_max, &failure) orelse
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
    const version = version_of(context);
    switch (tag) {
        .create_policy, .create_policy_with_accounts, .create_composite_policy => {
            const created = try create_policy(context, tag, arguments);
            return native.write_word(context, native.u256_word(created));
        },
        .stage_update_admin => try stage_update_admin(context, id, arguments.address(1)),
        .finalize_update_admin => try finalize_update_admin(context, id),
        .renounce_admin => try renounce_admin(context, id),
        .update_allowlist => try update_membership(context, id, type_allowlist, arguments),
        .update_blocklist => try update_membership(context, id, type_blocklist, arguments),
        .update_composite => try update_composite(context, id, arguments.array),
        .is_authorized => {
            const authorized = try is_authorized(context, id, arguments.address(1));
            return native.write_word(context, native.u256_word(@intFromBool(authorized)));
        },
        .policy_exists => {
            const exists = try policy_exists(context, version, id);
            return native.write_word(context, native.u256_word(@intFromBool(exists)));
        },
        .policy_admin => {
            const admin = try policy_admin(context, version, id);
            return native.write_word(context, native.address_word(admin));
        },
        .pending_policy_admin => {
            const pending = try pending_policy_admin(context, version, id);
            return native.write_word(context, native.address_word(pending));
        },
        .min_composite_child_policies => {
            return native.write_word(context, native.u256_word(children_min));
        },
        .max_composite_child_policies => {
            return native.write_word(context, native.u256_word(children_max));
        },
        .composite_policy_child_ids => return composite_policy_child_ids(context, version, id),
        .inverted_policy_id => {
            return native.write_word(context, native.u256_word(id ^ inverted_bit));
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

/// The policy id with the V3 inversion bit cleared (V1 and V2 keep ids as given).
fn base_id(version: Version, id: u64) u64 {
    return if (version == .v3) id & ~inverted_bit else id;
}

fn is_well_formed(version: Version, id: u64) bool {
    const type_max = if (version == .v1) type_allowlist else type_intersect;
    return id_type(id) <= type_max;
}

fn is_composite(id: u64) bool {
    return id_type(id) == type_union or id_type(id) == type_intersect;
}

fn children_length_slot(id: u64) u256 {
    return native.mapping_slot(id_word(id), children_base);
}

/// Children of a composite: a packed `uint64[]` (four per slot, lowest lane first).
const Children = struct {
    ids: [children_max]u64 = @splat(0),
    count: u32 = 0,
};

fn read_children(context: *Context, id: u64) Error!Children {
    const length_slot = children_length_slot(id);
    const length = try context.sload_at(address, length_slot);
    if (length > std.math.maxInt(u32)) {
        return context.revert_word(error_panic, native.u256_word(panic_overflow));
    }
    var children = Children{ .count = @intCast(length) };
    if (children.count == 0) return children;
    // Stored lists come from `write_children`, which bounds them to `children_max`.
    assert(children.count <= children_max);
    const data_slot = std.mem.readInt(u256, &keccak256(&native.u256_word(length_slot)), .big);
    const word = try context.sload_at(address, data_slot);
    for (0..children.count) |index| children.ids[index] = @truncate(word >> @intCast(64 * index));
    return children;
}

/// Cobalt `Vec` write: read the old length (tail cleanup), store the length, then the packed
/// data slot. Lists hold 2-4 ids, so they never retire a whole slot.
fn write_children(context: *Context, id: u64, children: Array) Error!void {
    assert(children.count() >= children_min and children.count() <= children_max);
    if (context.is_static) return context.revert(&.{});
    const length_slot = children_length_slot(id);
    const old_length = try context.sload_at(address, length_slot);
    if (old_length > std.math.maxInt(u32)) {
        return context.revert_word(error_panic, native.u256_word(panic_overflow));
    }
    try context.sstore(length_slot, children.count());
    var word: u256 = 0;
    for (0..children.count()) |index| {
        word |= @as(u256, children.uint64(@intCast(index))) << @intCast(64 * index);
    }
    const data_slot = std.mem.readInt(u256, &keccak256(&native.u256_word(length_slot)), .big);
    try context.sstore(data_slot, word);
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
    const word = try context.sload_at(address, policy_slot(id));
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

fn require_batch(context: *Context, accounts: Array) Error!void {
    if (accounts.count() <= accounts_per_batch_max) return;
    return context.revert_word(error_batch_size_too_large, native.u256_word(64));
}

// ------------------------------------------------------------------ logic

fn ensure_initialized(context: *Context) Error!u64 {
    const counter: u64 = @truncate(try context.sload_at(address, next_counter_slot));
    if (counter >= builtin_policy_count) return counter;
    try context.install_marker();
    try context.sstore(policy_slot(always_allow_id), exists_bit);
    try context.sstore(policy_slot(always_block_id), exists_bit);
    try context.sstore(next_counter_slot, builtin_policy_count);
    return builtin_policy_count;
}

fn create_policy(context: *Context, tag: Tag, arguments: *const Arguments) Error!u64 {
    const admin = arguments.address(0);
    const policy_type = arguments.small(1);
    const version = version_of(context);
    assert(policy_type <= type_intersect);
    if (is_zero(admin)) return context.revert_selector(error_zero_address);
    const composite = tag == .create_composite_policy;
    const type_valid = if (composite) policy_type >= type_union else policy_type <= type_allowlist;
    if (!type_valid) return context.revert_selector(error_incompatible_policy_type);
    if (composite) try validate_children(context, version, arguments.array);
    if (tag == .create_policy_with_accounts) try require_batch(context, arguments.array);
    const id = try create_policy_inner(context, admin, policy_type);
    switch (tag) {
        .create_policy => {},
        .create_policy_with_accounts => {
            for (0..arguments.array.count()) |index| {
                const account = arguments.array.word(@intCast(index))[12..32].*;
                try context.sstore(member_slot(id, account), 1);
            }
            try emit_membership(context, id, policy_type, true, arguments.array);
        },
        .create_composite_policy => {
            try write_children(context, id, arguments.array);
            try emit_children(context, id, arguments.array);
        },
        else => unreachable, // `route` only passes the three create tags.
    }
    return id;
}

fn create_policy_inner(context: *Context, admin: Address, policy_type: u8) Error!u64 {
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
    return id;
}

/// Children must number 2-4 and name existing plain lists (V3: possibly inverted).
fn validate_children(context: *Context, version: Version, children: Array) Error!void {
    const count = children.count();
    if (count < children_min or count > children_max) {
        return context.revert_selector(error_child_policies_outside_of_range);
    }
    for (0..count) |index| {
        _ = try require_custom(context, base_id(version, children.uint64(@intCast(index))));
    }
    for (0..count) |index| {
        const child = children.uint64(@intCast(index));
        const base = base_id(version, child);
        if (is_builtin(base) or is_composite(base)) {
            return context.revert_word(error_invalid_child_policy, id_word(child));
        }
    }
}

fn update_composite(context: *Context, id: u64, children: Array) Error!void {
    const word = try require_custom(context, id);
    if (!is_composite(id)) return context.revert_selector(error_incompatible_policy_type);
    if (!same(packed_admin(word), context.caller)) {
        return context.revert_selector(error_unauthorized);
    }
    try validate_children(context, version_of(context), children);
    try write_children(context, id, children);
    try emit_children(context, id, children);
}

/// CompositePolicyUpdated(id, updater, uint64[] children).
fn emit_children(context: *Context, id: u64, children: Array) Error!void {
    assert(children.count() <= children_max);
    const topics = [3]B256{
        event_composite_policy_updated,
        id_word(id),
        native.address_word(context.caller),
    };
    var data: [64 + 32 * children_max]u8 = undefined;
    data[0..32].* = native.u256_word(0x20);
    data[32..64].* = native.u256_word(children.count());
    for (0..children.count()) |index| {
        data[64 + 32 * index ..][0..32].* = id_word(children.uint64(@intCast(index)));
    }
    try context.emit(&topics, data[0 .. 64 + 32 * children.count()]);
}

fn emit_membership(
    context: *Context,
    id: u64,
    policy_type: u8,
    flag: bool,
    accounts: Array,
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
    const pending = to_address(@truncate(try context.sload_at(address, pending_slot(id))));
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

/// Policy evaluation for the registry and for B-20 tokens (reads target the registry).
pub fn is_authorized(context: *Context, id: u64, account: Address) Error!bool {
    const version = version_of(context);
    if (version == .v1) {
        // V1 rejects malformed ids before the built-in fast paths; the result is the same.
        if (id_type(id) > type_allowlist) return false;
    }
    if (id == always_allow_id) return true;
    if (id == always_block_id) return false;
    if (version == .v3 and id & inverted_bit != 0) {
        const base = base_id(version, id);
        if (!try policy_exists(context, version, base)) return false;
        return !try authorized_plain(context, version, base, account);
    }
    return authorized_plain(context, version, id, account);
}

/// A non-inverted id: built-ins, lists, and composites over leaf children.
fn authorized_plain(context: *Context, version: Version, id: u64, account: Address) Error!bool {
    assert(id & inverted_bit == 0 or version != .v3);
    if (!is_composite(id) or !is_well_formed(version, id)) {
        return authorized_leaf(context, version, id, account);
    }
    const children = try read_children(context, id);
    const is_union = id_type(id) == type_union;
    for (children.ids[0..children.count]) |child| {
        const authorized = try authorized_leaf(context, version, child, account);
        if (is_union and authorized) return true;
        if (!is_union and !authorized) return false;
    }
    return !is_union;
}

/// Composite children: built-ins and (possibly inverted) lists. Validation at write time
/// rejects composite children, so evaluation stops here without recursion.
fn authorized_leaf(context: *Context, version: Version, id: u64, account: Address) Error!bool {
    if (id == always_allow_id) return true;
    if (id == always_block_id) return false;
    var base = id;
    var inverted = false;
    if (version == .v3 and id & inverted_bit != 0) {
        base = base_id(version, id);
        if (!try policy_exists(context, version, base)) return false;
        if (base == always_allow_id) return false;
        if (base == always_block_id) return true;
        inverted = true;
    }
    if (!is_well_formed(version, base) or is_composite(base)) return inverted;
    const member = try context.sload_at(address, member_slot(base, account)) != 0;
    const authorized = if (id_type(base) == type_allowlist) member else !member;
    return authorized != inverted;
}

pub fn policy_exists(context: *Context, version: Version, policy_id: u64) Error!bool {
    const id = base_id(version, policy_id);
    if (version == .v1 and id_type(id) > type_allowlist) return false;
    if (is_builtin(id)) return true;
    if (!is_well_formed(version, id)) return false;
    return try context.sload_at(address, policy_slot(id)) & exists_bit != 0;
}

fn policy_admin(context: *Context, version: Version, policy_id: u64) Error!Address {
    const id = base_id(version, policy_id);
    if (!is_well_formed(version, id)) return primitives.address_zero;
    const word = try context.sload_at(address, policy_slot(id));
    if (word & exists_bit == 0) return primitives.address_zero;
    return packed_admin(word);
}

fn pending_policy_admin(context: *Context, version: Version, policy_id: u64) Error!Address {
    const id = base_id(version, policy_id);
    if (!is_well_formed(version, id) or is_builtin(id)) return primitives.address_zero;
    return to_address(@truncate(try context.sload_at(address, pending_slot(id))));
}

fn composite_policy_child_ids(
    context: *Context,
    version: Version,
    policy_id: u64,
) Error![]const u8 {
    const id = base_id(version, policy_id);
    var children = Children{};
    if (is_well_formed(version, id) and is_composite(id)) children = try read_children(context, id);
    const out = context.out;
    out[0..32].* = native.u256_word(0x20);
    out[32..64].* = native.u256_word(children.count);
    for (children.ids[0..children.count], 0..) |child, index| {
        out[64 + 32 * index ..][0..32].* = id_word(child);
    }
    return out[0 .. 64 + 32 * @as(usize, children.count)];
}

const testing = std.testing;

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
        "createCompositePolicy(address,uint8,uint64[])",
        "updateComposite(uint64,uint64[])",
        "MIN_COMPOSITE_CHILD_POLICIES()",
        "MAX_COMPOSITE_CHILD_POLICIES()",
        "compositePolicyChildIds(uint64)",
        "invertedPolicyId(uint64)",
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
        .{ "ChildPoliciesOutsideOfRange()", &error_child_policies_outside_of_range },
        .{ "InvalidChildPolicy(uint64)", &error_invalid_child_policy },
        .{ "CompositePolicyUpdated(uint64,address,uint64[])", &event_composite_policy_updated },
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

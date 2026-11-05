//! B-20 tokens (Beryl V1), Asset and Stablecoin variants: ERC-20 with memos, roles, pause
//! flags, supply cap, transfer policies, metadata, permit; the asset extension (multiplier,
//! extra metadata, batch mint, announce) and the stablecoin `currency()`. The variant comes
//! from the token address. base/base `crates/common/precompiles/src/b20_{asset,stablecoin}`.
//!
//! Stablecoin extension storage (ERC-7201 `base.b20.stablecoin`): currency string 0;
//! decimals are fixed at 6.
//!
//! Extension storage (ERC-7201 `base.b20.asset`): decimals 0 (low byte; 0 reads as 6),
//! multiplier 1, used announcement ids 2, extra metadata 3, pending multiplier 4.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");
const abi = @import("native_abi.zig");
const b20 = @import("native_b20.zig");
const policy = @import("native_policy.zig");
const storage = @import("native_storage.zig");
const primitives = @import("primitives.zig");
const secp256k1 = @import("../../common/crypto/root.zig").secp256k1;
const Address = primitives.Address;
const B256 = primitives.B256;
const Context = native.Context;
const Error = native.Error;
const Arguments = abi.Arguments;

const word = native.u256_word;
const address_word = native.address_word;

pub const asset_root: u256 = 0xfdc6d4552d1286ade4d9facdbf0fb50d2ec9b89a90e104f26fd277585e374b00;
const slot_decimals: u256 = asset_root;
const slot_multiplier: u256 = asset_root + 1;
const base_announcement_ids: u256 = asset_root + 2;
const base_extra_metadata: u256 = asset_root + 3;

pub const stablecoin_root: u256 =
    0x35827975a06ca0e9367ea3129b19441d45d0ca58e30b7693f09e73d0943d6200;

pub const role_operator: u256 =
    0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
pub const wad: u256 = 1_000_000_000_000_000_000;
pub const decimals_min: u8 = 6;
pub const decimals_max: u8 = 18;
/// V1 surfaces end at Beryl; V2 (Cobalt) adds seize, the UI multiplier, and metering. V3
/// (Denim) keeps the V2 ABI; its logic changes are gated on the upgrade in `native_b20`.
pub const Version = enum(u8) { v1 = 1, v2 = 2 };

pub fn version_of(context: *const Context) Version {
    return if (context.upgrade.at_least(.cobalt)) .v2 else .v1;
}

fn enumeration_max(version: Version) u8 {
    const last: b20.PausableFeature = if (version == .v1) .burn else .seize;
    return @backingInt(last);
}

const slot_pending: u256 = asset_root + 4;
pub const ui_multiplier_max: u256 = std.math.maxInt(u128);
const interface_erc165 = [4]u8{ 0x01, 0xff, 0xc9, 0xa7 };
const interfaces_erc8056 = [4][4]u8{
    .{ 0xa6, 0x0b, 0xf1, 0x3d },
    .{ 0x4b, 0xd2, 0x76, 0x48 },
    .{ 0xd8, 0x90, 0xfd, 0x71 },
    .{ 0x57, 0x85, 0x4f, 0xc3 },
};
const error_effective_at_in_past = [4]u8{ 0x14, 0x11, 0x9c, 0xf6 };
const error_effective_at_too_far = [4]u8{ 0x1c, 0xe2, 0x14, 0xfa };
const error_update_does_not_exist = [4]u8{ 0xa7, 0xd6, 0xa5, 0xca };
const error_update_exists = [4]u8{ 0x44, 0x81, 0xa6, 0x8e };

const error_empty_feature_set = [4]u8{ 0x48, 0x61, 0xff, 0x45 };
const error_invalid_supply_cap = [4]u8{ 0x0a, 0x37, 0x80, 0xce };
const error_supply_cap_exceeded = [4]u8{ 0x4b, 0x34, 0x4b, 0x11 };
const error_policy_not_found = [4]u8{ 0xcc, 0xca, 0xd5, 0x23 };
const error_unsupported_policy_type = [4]u8{ 0xcd, 0xd9, 0x8a, 0x4a };
const error_last_admin_cannot_renounce = [4]u8{ 0x36, 0x15, 0x13, 0xe7 };
const error_not_sole_admin = [4]u8{ 0x2a, 0x98, 0xe7, 0x3b };
const error_bad_confirmation = [4]u8{ 0x66, 0x97, 0xb2, 0x32 };
const error_invalid_multiplier = [4]u8{ 0x6f, 0x12, 0xf3, 0xdc };
const error_length_mismatch = [4]u8{ 0xab, 0x8b, 0x67, 0xc6 };
const error_empty_batch = [4]u8{ 0xc2, 0xe5, 0x34, 0x7d };
const error_invalid_metadata_key = [4]u8{ 0x86, 0xea, 0x3a, 0xbb };
const error_announcement_id_used = [4]u8{ 0xd1, 0x0b, 0x3c, 0x9e };
const error_announcement_in_progress = [4]u8{ 0x5c, 0x5f, 0x08, 0x29 };
const error_internal_call_malformed = [4]u8{ 0x4e, 0x2f, 0x14, 0x3e };
const error_internal_call_failed = [4]u8{ 0xb2, 0x88, 0xa1, 0x27 };

fn topic(comptime hex: []const u8) B256 {
    return comptime primitives.hex_to_b256(hex);
}

const event_seized = topic("a9aec5d8b86e2fa2fd6ac3af62f2622e3dfdab1967d4cbbb56a5df7d74cb887c");
const event_ui_multiplier_update_cancelled =
    topic("883856335ba5f60c18b9817c4505d3c7d3f6223dcf39516b30c508c46a5e1cad");
const event_ui_multiplier_updated =
    topic("2205df4534432b2f60654a3fdb48737ffdaf3e9edb1a498bd985bc026b15b055");
const event_memo = topic("6989f5818dcfd11f8cd53b27c94cec33dae1589735f03e639cba54553a1825e8");
const event_burned_blocked =
    topic("0b552e96653fd6842da37c477005d3b5c08a8c7d3631b1f43787b2dc9a1006a3");
const event_role_admin_changed =
    topic("bd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff");
const event_last_admin_renounced =
    topic("e8d3a9872e7ca325571ff1e4c51ddd69090a0345240cc605ccde365ec867cc67");
const event_paused = topic("3e849708b13f20dd0b87a503523c305e7604cd7e8f855e7a5ebe21397dfd7146");
const event_unpaused =
    topic("086a815e5123cf1af5cb7a82f8b052bf96c622204c98b2f4f9782bf77f753c57");
const event_policy_updated =
    topic("8b4790f7ff717fc8f60f07ae099e47ef318dc04b37ae98056b50a22b79056626");
const event_supply_cap_updated =
    topic("6d14f44808ce024f263432bc38d019a9951fbe674e9898b54844dbc8dc09c23a");
const event_contract_uri_updated =
    topic("a5d4097edda6d87cb9329af83fb3712ef77eeb13738ffe43cc35a4ce305ad962");
const event_name_updated =
    topic("74321da206c1b9fa34367f7ece59ca49371dcd13820b9a5c3767ae1ecceed51a");
const event_symbol_updated =
    topic("64e8b5c6dcea43dd79766bb3b8af7c45968d12b68c960cf2da23856f34d598d4");
const event_domain_changed =
    topic("0a6387c9ea3628b88a633bb4f3b151770f70085117a15f9bf3787cda53f13d31");
const event_multiplier_updated =
    topic("4dbe4840d7465bd162f67814cea0b519567a2e0e578bcde61e7f4ced361e5a3d");
const event_announcement =
    topic("ccebf8218a62875909564adef86a6f4df81503cb617221e793357d62f8e813f7");
const event_end_announcement =
    topic("96d64dafe2c790596430196b982ad1da3221cb3b0f4e6e2df77f2e4f71a90037");
const event_extra_metadata_updated =
    topic("d7bb345be29e78d635203d40fe0567e7ef19d5cd5cc5fcd25f768b8063e82aa1");

const Function = struct {
    tag: Tag,
    selector: [4]u8,
    parameters: []const u8,
    kinds: []const abi.Kind,
    since: Version = .v1,
};

pub fn selector_of(tag: Tag) [4]u8 {
    for (&functions) |*function| {
        if (function.tag == tag) return function.selector;
    }
    unreachable; // Every tag has a table entry.
}

fn find(selector: [4]u8, variant: native.B20Variant, version: Version) ?*const Function {
    for (&functions) |*function| {
        if (@backingInt(function.since) > @backingInt(version)) continue;
        if (!available(function.tag, variant)) continue;
        if (std.mem.eql(u8, &function.selector, &selector)) return function;
    }
    return null;
}

fn variant_of(context: *const Context) native.B20Variant {
    return native.b20_variant(context.address).?;
}

/// The asset extension exists only on assets, `currency()` only on stablecoins.
fn available(tag: Tag, variant: native.B20Variant) bool {
    return switch (tag) {
        .operator_role,
        .wad_precision,
        .is_announcement_id_used,
        .multiplier,
        .to_scaled_balance,
        .to_raw_balance,
        .scaled_balance_of,
        .update_multiplier,
        .batch_mint,
        .extra_metadata,
        .update_extra_metadata,
        .announce,
        .max_ui_multiplier,
        .ui_multiplier,
        .new_ui_multiplier,
        .effective_at,
        .balance_of_ui,
        .total_supply_ui,
        .to_ui_amount,
        .from_ui_amount,
        .update_ui_multiplier,
        .cancel_ui_multiplier_update,
        .supports_interface,
        => variant == .asset,
        .currency => variant == .stablecoin,
        else => true,
    };
}

/// Entry point for a token address; `privileged` is false for external calls.
pub fn dispatch(context: *Context, input: []const u8) Error![]const u8 {
    if (context.value != 0) return context.revert_selector(native.selector_non_payable);
    try context.charge_calldata(input);
    if (!try context.account_has_code(context.address)) return context.revert(&.{});
    return route(context, input, false);
}

/// Decode and run one call; factory init calls use `privileged = true`.
pub fn route(context: *Context, input: []const u8, privileged: bool) Error![]const u8 {
    const selector = native.selector_of(input);
    const function = find(selector, variant_of(context), version_of(context)) orelse
        return context.revert_unknown(selector);
    if (function.tag != .announce) return execute(context, function, input, privileged);
    const arguments = try decode(context, function, input);
    try announce(context, &arguments, privileged);
    return &.{};
}

fn decode(context: *Context, function: *const Function, input: []const u8) Error!Arguments {
    assert(input.len >= 4);
    assert(std.mem.eql(u8, input[0..4], &function.selector));
    var failure: native.DecodeFailure = .overrun;
    const kinds = function.kinds;
    const maximum = enumeration_max(version_of(context));
    return abi.decode_arguments(input[4..], kinds, maximum, &failure) orelse
        return context.revert_decode(function.selector, function.parameters, failure);
}

/// Every call except `announce` (which runs its internal calls through here).
fn execute(
    context: *Context,
    function: *const Function,
    input: []const u8,
    privileged: bool,
) Error![]const u8 {
    assert(function.tag != .announce);
    const arguments = try decode(context, function, input);
    if (try view(context, function.tag, &arguments)) |output| return output;
    if (try movement(context, function.tag, &arguments, privileged)) |output| return output;
    try administration(context, function.tag, &arguments, privileged);
    return &.{};
}

/// announce(internalCalls, id, description, uri): mark the id, emit, run each internal call
/// with the outer privilege (any revert becomes InternalCallFailed), then EndAnnouncement.
fn announce(context: *Context, arguments: *const Arguments, privileged: bool) Error!void {
    if (!privileged) try b20.ensure_role(context, context.caller, role_operator);
    const id = arguments.bytes(1);
    const id_slot = string_slot(id, base_announcement_ids);
    if (try context.sload(id_slot) != 0) {
        const length = encode_dynamic(context.out[4..], &.{}, &.{id});
        context.out[0..4].* = error_announcement_id_used;
        return context.revert(context.out[0 .. 4 + length]);
    }
    try context.sstore(id_slot, 1);
    const fields = [3][]const u8{ id, arguments.bytes(2), arguments.bytes(3) };
    const length = encode_dynamic(context.out, &.{}, &fields);
    const topics = [2]B256{ event_announcement, address_word(context.caller) };
    try context.emit(&topics, context.out[0..length]);
    var item: u32 = 0;
    while (item < arguments.bytes_count(0)) : (item += 1) {
        try internal_call(context, arguments.bytes_item(0, item), privileged);
    }
    const end_length = encode_dynamic(context.out, &.{}, &.{id});
    try context.emit(&.{event_end_announcement}, context.out[0..end_length]);
}

fn internal_call(context: *Context, call: []const u8, privileged: bool) Error!void {
    if (call.len < 4) return revert_with_bytes(context, error_internal_call_malformed, call);
    const function = find(call[0..4].*, .asset, version_of(context)) orelse
        return revert_with_bytes(context, error_internal_call_failed, call);
    if (function.tag == .announce) return context.revert_selector(error_announcement_in_progress);
    _ = execute(context, function, call, privileged) catch |err| switch (err) {
        error.Revert => return revert_with_bytes(context, error_internal_call_failed, call),
        else => |other| return other,
    };
}

fn revert_with_bytes(context: *Context, selector: [4]u8, bytes: []const u8) error{Revert} {
    const length = encode_dynamic(context.out[4..], &.{}, &.{bytes});
    context.out[0..4].* = selector;
    return context.revert(context.out[0 .. 4 + length]);
}

// ------------------------------------------------------------------ output encoding

fn write_u256(context: *Context, value: u256) []const u8 {
    return native.write_word(context, word(value));
}

fn write_bool(context: *Context, value: bool) []const u8 {
    return write_u256(context, @intFromBool(value));
}

/// ABI-encode `values` (one dynamic `bytes`/`string` each) after `heads` static words into
/// `buffer`; returns the encoding length.
fn encode_dynamic(buffer: []u8, heads: []const [32]u8, values: []const []const u8) usize {
    const head_count = heads.len + values.len;
    assert(head_count <= 8);
    var length: usize = 32 * head_count;
    for (heads, 0..) |head, index| buffer[32 * index ..][0..32].* = head;
    for (values, 0..) |value, index| {
        buffer[32 * (heads.len + index) ..][0..32].* = word(length);
        buffer[length..][0..32].* = word(value.len);
        @memcpy(buffer[length + 32 ..][0..value.len], value);
        const padded = std.mem.alignForward(usize, value.len, 32);
        @memset(buffer[length + 32 + value.len ..][0 .. padded - value.len], 0);
        length += 32 + padded;
    }
    assert(length % 32 == 0);
    return length;
}

fn write_string(context: *Context, value: []const u8) []const u8 {
    const length = encode_dynamic(context.out, &.{}, &.{value});
    return context.out[0..length];
}

fn load_string(context: *Context, slot: u256) Error![]const u8 {
    // The upper half of the return buffer (the EVM memory cap) holds the loaded value; the
    // ABI encoding goes to the lower half, so strings up to half the cap round-trip.
    assert(context.out.len >= 4 * storage.bytes_length_max);
    const buffer = context.out[context.out.len / 2 ..];
    return storage.load(context, slot, buffer);
}

// ------------------------------------------------------------------ views

fn constant(tag: Tag) ?u256 {
    return switch (tag) {
        .default_admin_role => b20.role_default_admin,
        .mint_role => b20.role_mint,
        .burn_role => b20.role_burn,
        .burn_blocked_role => b20.role_burn_blocked,
        .pause_role => b20.role_pause,
        .unpause_role => b20.role_unpause,
        .metadata_role => b20.role_metadata,
        .operator_role => role_operator,
        .transfer_sender_policy => b20.PolicyScope.transfer_sender.id(),
        .transfer_receiver_policy => b20.PolicyScope.transfer_receiver.id(),
        .transfer_executor_policy => b20.PolicyScope.transfer_executor.id(),
        .mint_receiver_policy => b20.PolicyScope.mint_receiver.id(),
        .wad_precision => wad,
        .seize_role => b20.role_seize,
        .seize_exempt_policy => b20.PolicyScope.seize_exempt.id(),
        .seize_receiver_policy => b20.PolicyScope.seize_receiver.id(),
        .max_ui_multiplier => ui_multiplier_max,
        else => null,
    };
}

fn view(context: *Context, tag: Tag, arguments: *const Arguments) Error!?[]const u8 {
    if (constant(tag)) |value| return write_u256(context, value);
    switch (tag) {
        .name, .symbol, .contract_uri => {
            const slot = switch (tag) {
                .name => b20.slot_name,
                .symbol => b20.slot_symbol,
                else => b20.slot_contract_uri,
            };
            const value = try load_string(context, slot);
            return write_string(context, value);
        },
        .decimals => return write_u256(context, try decimals(context)),
        .total_supply => return write_u256(context, try context.sload(b20.slot_total_supply)),
        .supply_cap => return write_u256(context, try context.sload(b20.slot_supply_cap)),
        .balance_of => {
            return write_u256(context, try b20.balance_of(context, arguments.address(0)));
        },
        .allowance => {
            const slot = b20.allowance_slot(arguments.address(0), arguments.address(1));
            return write_u256(context, try context.sload(slot));
        },
        .nonces => {
            const slot = b20.nonce_slot(arguments.address(0));
            return write_u256(context, try context.sload(slot));
        },
        .has_role => {
            const role = arguments.uint256(0);
            return write_bool(context, try b20.has_role(context, role, arguments.address(1)));
        },
        .get_role_admin => {
            return write_u256(context, try b20.role_admin(context, arguments.uint256(0)));
        },
        else => return view_extension(context, tag, arguments),
    }
}

fn view_extension(context: *Context, tag: Tag, arguments: *const Arguments) Error!?[]const u8 {
    switch (tag) {
        .paused_features => return try paused_features(context),
        .is_paused => {
            const mask = @as(u256, 1) << @intCast(arguments.small(0));
            return write_bool(context, try b20.paused(context) & mask != 0);
        },
        .policy_id => {
            const scope = try supported_scope(context, arguments.uint256(0));
            return write_u256(context, try b20.policy_id(context, scope));
        },
        .multiplier => return write_u256(context, try multiplier(context)),
        .currency => return write_string(context, try load_string(context, stablecoin_root)),
        .domain_separator => return native.write_word(context, try domain_separator(context)),
        .eip712_domain => return try eip712_domain(context),
        .to_scaled_balance, .to_ui_amount => {
            return write_u256(context, try to_scaled(context, arguments.uint256(0)));
        },
        .ui_multiplier => return write_u256(context, try multiplier(context)),
        .new_ui_multiplier => return write_u256(context, try new_ui_multiplier(context)),
        .effective_at => return write_u256(context, (try pending(context)).effective_at),
        .total_supply_ui => {
            const supply = try context.sload(b20.slot_total_supply);
            return write_u256(context, try to_scaled(context, supply));
        },
        .supports_interface => {
            const id = arguments.words[0][0..4].*;
            var supported = std.mem.eql(u8, &id, &interface_erc165);
            for (interfaces_erc8056) |known| supported = supported or std.mem.eql(u8, &id, &known);
            return write_bool(context, supported);
        },
        .to_raw_balance, .from_ui_amount => {
            const product = std.math.mul(u256, arguments.uint256(0), wad) catch
                return b20.overflow(context);
            return write_u256(context, product / try multiplier(context));
        },
        .scaled_balance_of, .balance_of_ui => {
            const balance = try b20.balance_of(context, arguments.address(0));
            return write_u256(context, try to_scaled(context, balance));
        },
        .extra_metadata => {
            const slot = string_slot(arguments.bytes(0), base_extra_metadata);
            return write_string(context, try load_string(context, slot));
        },
        .is_announcement_id_used => {
            const slot = string_slot(arguments.bytes(0), base_announcement_ids);
            return write_bool(context, try context.sload(slot) != 0);
        },
        else => return null,
    }
}

/// Solidity `mapping(string => ...)` slot: keccak256(key ++ base), unmetered.
fn string_slot(key: []const u8, base: u256) u256 {
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(key);
    hasher.update(&word(base));
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.mem.readInt(u256, &digest, .big);
}

fn decimals(context: *Context) Error!u8 {
    if (variant_of(context) == .stablecoin) return decimals_min;
    const value: u8 = @truncate(try context.sload(slot_decimals));
    return if (value == 0) decimals_min else value;
}

/// The stored multiplier; an unset (zero) slot reads as WAD.
fn stored_multiplier(context: *Context) Error!u256 {
    const value = try context.sload(slot_multiplier);
    return if (value == 0) wad else value;
}

const Pending = struct { multiplier: u128, effective_at: u64 };

/// The scheduled UI multiplier (slot 4: u128 multiplier, u64 effective-at at byte 16).
fn pending(context: *Context) Error!Pending {
    const value = try context.sload(slot_pending);
    return .{ .multiplier = @truncate(value), .effective_at = @truncate(value >> 128) };
}

/// V2: a matured pending multiplier wins over the stored one (base reads the slot twice).
fn multiplier(context: *Context) Error!u256 {
    if (version_of(context) == .v1) return stored_multiplier(context);
    const effective_at = (try pending(context)).effective_at;
    if (effective_at != 0 and context.timestamp >= effective_at) {
        const matured = (try pending(context)).multiplier;
        assert(matured != 0);
        return matured;
    }
    return stored_multiplier(context);
}

fn new_ui_multiplier(context: *Context) Error!u256 {
    const scheduled = try pending(context);
    if (scheduled.effective_at > context.timestamp) {
        return (try pending(context)).multiplier;
    }
    return multiplier(context);
}

fn to_scaled(context: *Context, balance: u256) Error!u256 {
    const product = std.math.mul(u256, balance, try multiplier(context)) catch
        return b20.overflow(context);
    return product / wad;
}

fn paused_features(context: *Context) Error![]const u8 {
    const flags = try b20.paused(context);
    var count: u8 = 0;
    const out = context.out;
    const count_max: u8 = if (version_of(context) == .v1) 3 else 4;
    for (0..count_max) |feature| {
        if (flags & (@as(u256, 1) << @intCast(feature)) == 0) continue;
        out[64 + 32 * @as(usize, count) ..][0..32].* = word(feature);
        count += 1;
    }
    out[0..32].* = word(32);
    out[32..64].* = word(count);
    return out[0 .. 64 + 32 * @as(usize, count)];
}

fn supported_scope(context: *Context, id: u256) Error!b20.PolicyScope {
    const scope = b20.PolicyScope.from_id(id) orelse
        return context.revert_word(error_unsupported_policy_type, word(id));
    if (version_of(context) == .v2) return scope;
    return switch (scope) {
        .seize_exempt, .seize_receiver => {
            return context.revert_word(error_unsupported_policy_type, word(id));
        },
        else => scope,
    };
}

// ------------------------------------------------------------------ movements

fn emit_memo(context: *Context, memo: *const [32]u8) Error!void {
    const topics = [3]B256{ event_memo, address_word(context.caller), memo.* };
    try context.emit(&topics, &.{});
}

fn movement(
    context: *Context,
    tag: Tag,
    arguments: *const Arguments,
    privileged: bool,
) Error!?[]const u8 {
    const caller = context.caller;
    switch (tag) {
        .transfer, .transfer_with_memo => {
            const to = arguments.address(0);
            const amount = arguments.uint256(1);
            if (version_of(context) == .v1) {
                try b20.ensure_not_paused(context, .transfer);
                try b20.transfer_inner(context, caller, to, amount, privileged);
            } else {
                try b20.transfer_v2(context, to, amount, privileged);
            }
            if (tag == .transfer_with_memo) try emit_memo(context, arguments.words[2]);
            return write_bool(context, true);
        },
        .transfer_from, .transfer_from_with_memo => {
            const from = arguments.address(0);
            const to = arguments.address(1);
            const amount = arguments.uint256(2);
            if (version_of(context) == .v1) {
                try b20.transfer_from(context, from, to, amount, privileged);
            } else {
                try b20.transfer_from_v2(context, from, to, amount, privileged);
            }
            if (tag == .transfer_from_with_memo) try emit_memo(context, arguments.words[3]);
            return write_bool(context, true);
        },
        .approve => {
            try b20.approve(context, caller, arguments.address(0), arguments.uint256(1));
            return write_bool(context, true);
        },
        .mint, .mint_with_memo => {
            try mint_guarded(context, arguments.address(0), arguments.uint256(1), privileged);
            if (tag == .mint_with_memo) try emit_memo(context, arguments.words[2]);
        },
        .burn, .burn_with_memo => {
            try b20.ensure_not_paused(context, .burn);
            try b20.ensure_role(context, caller, b20.role_burn);
            try b20.burn_inner(context, caller, arguments.uint256(0));
            if (tag == .burn_with_memo) try emit_memo(context, arguments.words[1]);
        },
        .burn_blocked => {
            const from = arguments.address(0);
            try burn_blocked(context, from, arguments.uint256(1), privileged);
        },
        .batch_mint => try batch_mint(context, arguments, privileged),
        .seize_with_memo => try seize(context, arguments),
        else => return null,
    }
    return &.{};
}

/// seizeWithMemo(from, to, amount, memo): SEIZE_ROLE moves funds off a non-exempt account.
fn seize(context: *Context, arguments: *const Arguments) Error!void {
    try b20.ensure_not_paused(context, .seize);
    try b20.ensure_role(context, context.caller, b20.role_seize);
    const from = arguments.address(0);
    const to = arguments.address(1);
    const amount = arguments.uint256(2);
    const invalid_receiver = b20.is_zero(to) or std.mem.eql(u8, &from, &to);
    if (b20.receiver_rejected(context, to)) {
        return context.revert_word(b20.error_invalid_receiver, address_word(to));
    }
    if (b20.is_zero(from)) return context.revert_word(b20.error_invalid_sender, address_word(from));
    if (invalid_receiver) return context.revert_word(b20.error_invalid_receiver, address_word(to));
    try b20.ensure_seizable(context, from);
    try b20.ensure_policy(context, .seize_receiver, to);
    try b20.move_balance(context, from, to, amount);
    try emit_memo(context, arguments.words[3]);
    const caller = address_word(context.caller);
    const topics = [4]B256{ event_seized, caller, address_word(from), address_word(to) };
    try context.emit(&topics, &word(amount));
}

fn mint_guarded(context: *Context, to: Address, amount: u256, privileged: bool) Error!void {
    try b20.ensure_not_paused(context, .mint);
    if (!privileged) try b20.ensure_role(context, context.caller, b20.role_mint);
    try mint(context, to, amount);
}

/// Mint after pause/role checks: receiver, mint policy, supply cap, balance.
fn mint(context: *Context, to: Address, amount: u256) Error!void {
    if (b20.receiver_rejected(context, to)) {
        return context.revert_word(b20.error_invalid_receiver, address_word(to));
    }
    try b20.ensure_policy(context, .mint_receiver, to);
    const supply = try context.sload(b20.slot_total_supply);
    const cap = try context.sload(b20.slot_supply_cap);
    const attempted = std.math.add(u256, supply, amount) catch return b20.overflow(context);
    if (attempted > cap) {
        const words = [2][32]u8{ word(cap), word(attempted) };
        return b20.revert_words(context, error_supply_cap_exceeded, &words);
    }
    try context.sstore(b20.slot_total_supply, attempted);
    const balance = try b20.balance_of(context, to);
    const updated = std.math.add(u256, balance, amount) catch return b20.overflow(context);
    try context.sstore(b20.balance_slot(to), updated);
    const zero = address_word(primitives.address_zero);
    const topics = [3]B256{ b20.event_transfer, zero, address_word(to) };
    try context.emit(&topics, &word(amount));
}

fn burn_blocked(context: *Context, from: Address, amount: u256, privileged: bool) Error!void {
    try b20.ensure_not_paused(context, .burn);
    if (!privileged) try b20.ensure_role(context, context.caller, b20.role_burn_blocked);
    try b20.ensure_blocked(context, from);
    try b20.burn_inner(context, from, amount);
    const caller = address_word(context.caller);
    const topics = [3]B256{ event_burned_blocked, caller, address_word(from) };
    try context.emit(&topics, &word(amount));
}

fn batch_mint(context: *Context, arguments: *const Arguments, privileged: bool) Error!void {
    try b20.ensure_not_paused(context, .mint);
    if (!privileged) try b20.ensure_role(context, context.caller, b20.role_mint);
    const recipients = arguments.list(0);
    const amounts = arguments.list(1);
    if (recipients.count() != amounts.count()) {
        return b20.revert_words(context, error_length_mismatch, &.{
            word(recipients.count()),
            word(amounts.count()),
        });
    }
    if (recipients.count() == 0) return context.revert_selector(error_empty_batch);
    for (0..recipients.count()) |index| {
        const recipient = recipients.word(@intCast(index))[12..32].*;
        const amount = std.mem.readInt(u256, amounts.word(@intCast(index)), .big);
        try b20.ensure_not_paused(context, .mint);
        try mint(context, recipient, amount);
    }
}

// ------------------------------------------------------------------ administration

fn administration(
    context: *Context,
    tag: Tag,
    arguments: *const Arguments,
    privileged: bool,
) Error!void {
    const caller = context.caller;
    switch (tag) {
        .pause, .unpause => try set_pause(context, tag == .pause, arguments.list(0), privileged),
        .update_supply_cap => try update_supply_cap(context, arguments.uint256(0), privileged),
        .update_name, .update_symbol, .update_contract_uri => {
            if (!privileged) try b20.ensure_role(context, caller, b20.role_metadata);
            try update_metadata(context, tag, arguments.bytes(0));
        },
        .grant_role => {
            try grant_role(context, arguments.uint256(0), arguments.address(1), privileged);
        },
        .revoke_role => {
            try revoke_role(context, arguments.uint256(0), arguments.address(1), privileged);
        },
        .renounce_role => {
            const role = arguments.uint256(0);
            if (!std.mem.eql(u8, &arguments.address(1), &caller)) {
                return context.revert_selector(error_bad_confirmation);
            }
            try ensure_not_last_admin(context, role, caller);
            try b20.revoke_role_unchecked(context, role, caller, caller);
        },
        .renounce_last_admin => try renounce_last_admin(context),
        .set_role_admin => {
            const admin = arguments.uint256(1);
            try set_role_admin(context, arguments.uint256(0), admin, privileged);
        },
        .update_policy => {
            try update_policy(context, arguments.uint256(0), arguments.uint64(1), privileged);
        },
        .permit => try permit(context, arguments),
        .update_multiplier => try update_multiplier(context, arguments.uint256(0), privileged),
        .update_ui_multiplier => {
            const value = arguments.uint256(0);
            try update_ui_multiplier(context, value, arguments.uint256(1), privileged);
        },
        .cancel_ui_multiplier_update => try cancel_ui_multiplier_update(context, privileged),
        .update_extra_metadata => {
            if (!privileged) try b20.ensure_role(context, caller, b20.role_metadata);
            try update_extra_metadata(context, arguments.bytes(0), arguments.bytes(1));
        },
        else => unreachable, // Views and movements returned earlier; the table is closed.
    }
}

fn set_pause(context: *Context, pause: bool, features: abi.Array, privileged: bool) Error!void {
    const role = if (pause) b20.role_pause else b20.role_unpause;
    if (!privileged) try b20.ensure_role(context, context.caller, role);
    if (features.count() == 0) return context.revert_selector(error_empty_feature_set);
    var flags = try b20.paused(context);
    for (0..features.count()) |index| {
        const mask = @as(u256, 1) << @intCast(features.word(@intCast(index))[31]);
        flags = if (pause) flags | mask else flags & ~mask;
    }
    try b20.set_paused(context, flags);
    // Event data: the features array as passed (offset, length, elements).
    const out = context.out;
    const length = 64 + features.words.len;
    out[0..32].* = word(32);
    out[32..64].* = word(features.count());
    @memcpy(out[64..length], features.words);
    const event = if (pause) event_paused else event_unpaused;
    const topics = [2]B256{ event, address_word(context.caller) };
    try context.emit(&topics, out[0..length]);
}

fn update_supply_cap(context: *Context, cap: u256, privileged: bool) Error!void {
    if (!privileged) try b20.ensure_role(context, context.caller, b20.role_default_admin);
    const supply = try context.sload(b20.slot_total_supply);
    if (cap < supply or cap > b20.supply_cap_max) {
        return b20.revert_words(context, error_invalid_supply_cap, &.{ word(supply), word(cap) });
    }
    const old = try context.sload(b20.slot_supply_cap);
    try context.sstore(b20.slot_supply_cap, cap);
    var data: [64]u8 = undefined;
    data[0..32].* = word(old);
    data[32..64].* = word(cap);
    const topics = [2]B256{ event_supply_cap_updated, address_word(context.caller) };
    try context.emit(&topics, &data);
}

fn update_metadata(context: *Context, tag: Tag, value: []const u8) Error!void {
    const slot = switch (tag) {
        .update_name => b20.slot_name,
        .update_symbol => b20.slot_symbol,
        else => b20.slot_contract_uri,
    };
    try storage.store(context, slot, value);
    if (tag == .update_contract_uri) {
        try context.emit(&.{event_contract_uri_updated}, &.{});
        return;
    }
    const length = encode_dynamic(context.out, &.{}, &.{value});
    const event = if (tag == .update_name) event_name_updated else event_symbol_updated;
    const topics = [2]B256{ event, address_word(context.caller) };
    try context.emit(&topics, context.out[0..length]);
    if (tag == .update_name) try context.emit(&.{event_domain_changed}, &.{});
}

fn ensure_admin_mutations_available(context: *Context) Error!void {
    if (try b20.role_member_count(context, b20.role_default_admin) != 0) return;
    return b20.revert_words(context, b20.error_unauthorized_account, &.{
        address_word(context.caller),
        word(b20.role_default_admin),
    });
}

fn grant_role(context: *Context, role: u256, account: Address, privileged: bool) Error!void {
    if (role == b20.role_default_admin or !privileged) {
        try ensure_admin_mutations_available(context);
    }
    if (!privileged) {
        try b20.ensure_role(context, context.caller, try b20.role_admin(context, role));
    }
    try b20.grant_role_unchecked(context, role, account, context.caller);
}

fn ensure_not_last_admin(context: *Context, role: u256, account: Address) Error!void {
    if (role != b20.role_default_admin) return;
    if (!try b20.has_role(context, role, account)) return;
    if (try b20.role_member_count(context, role) != 1) return;
    return context.revert_selector(error_last_admin_cannot_renounce);
}

fn revoke_role(context: *Context, role: u256, account: Address, privileged: bool) Error!void {
    if (!privileged) {
        try ensure_admin_mutations_available(context);
        try b20.ensure_role(context, context.caller, try b20.role_admin(context, role));
    }
    try ensure_not_last_admin(context, role, account);
    try b20.revoke_role_unchecked(context, role, account, context.caller);
}

fn renounce_last_admin(context: *Context) Error!void {
    const caller = context.caller;
    try b20.ensure_role(context, caller, b20.role_default_admin);
    if (try b20.role_member_count(context, b20.role_default_admin) != 1) {
        return context.revert_selector(error_not_sole_admin);
    }
    try b20.revoke_role_unchecked(context, b20.role_default_admin, caller, caller);
    const topics = [2]B256{ event_last_admin_renounced, address_word(caller) };
    try context.emit(&topics, &.{});
}

fn set_role_admin(context: *Context, role: u256, admin: u256, privileged: bool) Error!void {
    const previous = try b20.role_admin(context, role);
    if (!privileged) {
        try ensure_admin_mutations_available(context);
        try b20.ensure_role(context, context.caller, previous);
    }
    try b20.set_role_admin(context, role, admin);
    const topics = [4]B256{ event_role_admin_changed, word(role), word(previous), word(admin) };
    try context.emit(&topics, &.{});
}

fn update_policy(context: *Context, scope_id: u256, id: u64, privileged: bool) Error!void {
    if (!privileged) try b20.ensure_role(context, context.caller, b20.role_default_admin);
    const scope = try supported_scope(context, scope_id);
    const version = policy.version_of(context);
    // Stablecoins read the old id before the existence check (gas on the revert path).
    const stablecoin = variant_of(context) == .stablecoin and version_of(context) == .v1;
    const old_first = if (stablecoin) try b20.policy_id(context, scope) else 0;
    if (!try policy.policy_exists(context, version, id)) {
        return context.revert_word(error_policy_not_found, word(id));
    }
    const old = if (stablecoin) old_first else try b20.policy_id(context, scope);
    try b20.set_policy_id(context, scope, id);
    var data: [64]u8 = undefined;
    data[0..32].* = word(old);
    data[32..64].* = word(id);
    const topics = [2]B256{ event_policy_updated, word(scope_id) };
    try context.emit(&topics, &data);
}

fn update_multiplier(context: *Context, value: u256, privileged: bool) Error!void {
    if (!privileged) try b20.ensure_role(context, context.caller, role_operator);
    if (version_of(context) == .v2) return update_multiplier_v2(context, value);
    if (value == 0) return context.revert_selector(error_invalid_multiplier);
    try context.sstore(slot_multiplier, value);
    try context.emit(&.{event_multiplier_updated}, &word(value));
}

/// V2: set now, dropping any schedule (a live one is reported cancelled).
fn update_multiplier_v2(context: *Context, value: u256) Error!void {
    if (value == 0 or value > ui_multiplier_max) {
        return context.revert_selector(error_invalid_multiplier);
    }
    const scheduled_multiplier = (try pending(context)).multiplier;
    const scheduled = try pending(context);
    const live = scheduled.effective_at > context.timestamp;
    const old = try multiplier(context);
    try context.sstore(slot_multiplier, value);
    if (scheduled.effective_at != 0) try clear_pending(context);
    if (live) try emit_cancelled(context, scheduled_multiplier, scheduled.effective_at);
    try context.emit(&.{event_multiplier_updated}, &word(value));
    try emit_ui_updated(context, old, value, context.timestamp);
}

fn clear_pending(context: *Context) Error!void {
    const value = try context.sload(slot_pending);
    const lanes_mask = (@as(u256, 1) << 192) - 1;
    try context.sstore(slot_pending, value & ~lanes_mask);
}

fn emit_cancelled(context: *Context, value: u128, effective_at: u64) Error!void {
    var data: [64]u8 = undefined;
    data[0..32].* = word(value);
    data[32..64].* = word(effective_at);
    try context.emit(&.{event_ui_multiplier_update_cancelled}, &data);
}

fn emit_ui_updated(context: *Context, old: u256, new: u256, effective_at: u256) Error!void {
    var data: [96]u8 = undefined;
    data[0..32].* = word(old);
    data[32..64].* = word(new);
    data[64..96].* = word(effective_at);
    try context.emit(&.{event_ui_multiplier_updated}, &data);
}

/// updateUIMultiplier(newMultiplier, effectiveAt): schedule a future multiplier.
fn update_ui_multiplier(
    context: *Context,
    value: u256,
    effective_at: u256,
    privileged: bool,
) Error!void {
    if (!privileged) try b20.ensure_role(context, context.caller, role_operator);
    if (value == 0 or value > ui_multiplier_max) {
        return context.revert_selector(error_invalid_multiplier);
    }
    if (effective_at <= context.timestamp) {
        return context.revert_word(error_effective_at_in_past, word(effective_at));
    }
    if (effective_at > std.math.maxInt(u64)) {
        return context.revert_word(error_effective_at_too_far, word(effective_at));
    }
    const scheduled_at = (try pending(context)).effective_at;
    if (scheduled_at > context.timestamp) {
        return context.revert_word(error_update_exists, word(scheduled_at));
    }
    if (scheduled_at != 0) {
        const matured = (try pending(context)).multiplier;
        try context.sstore(slot_multiplier, matured);
    }
    const old = try stored_multiplier(context);
    const current = try context.sload(slot_pending);
    const lanes_mask = (@as(u256, 1) << 192) - 1;
    const lanes = value | (effective_at << 128);
    try context.sstore(slot_pending, (current & ~lanes_mask) | lanes);
    try emit_ui_updated(context, old, value, effective_at);
}

fn cancel_ui_multiplier_update(context: *Context, privileged: bool) Error!void {
    if (!privileged) try b20.ensure_role(context, context.caller, role_operator);
    const scheduled_multiplier = (try pending(context)).multiplier;
    const scheduled = try pending(context);
    if (scheduled.effective_at <= context.timestamp) {
        return context.revert_selector(error_update_does_not_exist);
    }
    try clear_pending(context);
    try emit_cancelled(context, scheduled_multiplier, scheduled.effective_at);
}

fn update_extra_metadata(context: *Context, key: []const u8, value: []const u8) Error!void {
    if (key.len == 0) return context.revert_selector(error_invalid_metadata_key);
    try storage.store(context, string_slot(key, base_extra_metadata), value);
    const length = encode_dynamic(context.out, &.{}, &.{ key, value });
    try context.emit(&.{event_extra_metadata_updated}, context.out[0..length]);
}

// ------------------------------------------------------------------ EIP-712 and permit

const domain_typehash: u256 =
    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
const permit_typehash: u256 =
    0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
const error_expired_signature = [4]u8{ 0xbd, 0x2a, 0x91, 0x3c };
const error_invalid_signer = [4]u8{ 0x7b, 0xa5, 0xff, 0xb5 };

fn keccak_words(words: []const [32]u8) [32]u8 {
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    for (words) |item| hasher.update(&item);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn keccak(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(bytes, &digest, .{});
    return digest;
}

/// keccak256(abi.encode(DOMAIN_TYPEHASH, keccak(name), keccak("1"), chainId, address)).
/// V2 meters each keccak (30 + 6 per word), V1 hashes for free.
fn metered_keccak(context: *Context, bytes: []const u8) Error![32]u8 {
    if (version_of(context) == .v2) {
        const words: u64 = @intCast(std.math.divCeil(usize, bytes.len, 32) catch unreachable);
        try context.charge(30 + 6 * words);
    }
    return keccak(bytes);
}

fn domain_separator(context: *Context) Error![32]u8 {
    const name = try load_string(context, b20.slot_name);
    const name_hash = try metered_keccak(context, name);
    const version_hash = try metered_keccak(context, "1");
    var encoded: [5 * 32]u8 = undefined;
    encoded[0..32].* = word(domain_typehash);
    encoded[32..64].* = name_hash;
    encoded[64..96].* = version_hash;
    encoded[96..128].* = word(context.chain_id);
    encoded[128..160].* = address_word(context.address);
    return metered_keccak(context, &encoded);
}

fn eip712_domain(context: *Context) Error![]const u8 {
    const name = try load_string(context, b20.slot_name);
    var fields: [32]u8 = @splat(0);
    fields[0] = 0x0f;
    const out = context.out;
    // Heads: fields, name, version, chainId, verifyingContract, salt, extensions.
    out[0..32].* = fields;
    out[96..128].* = word(context.chain_id);
    out[128..160].* = address_word(context.address);
    out[160..192].* = @splat(0);
    var length: usize = 7 * 32;
    const tails = [2][]const u8{ name, "1" };
    for (tails, 0..) |tail, index| {
        out[32 * (index + 1) ..][0..32].* = word(length);
        out[length..][0..32].* = word(tail.len);
        const padded = std.mem.alignForward(usize, tail.len, 32);
        @memset(out[length + 32 ..][0..padded], 0);
        @memcpy(out[length + 32 ..][0..tail.len], tail);
        length += 32 + padded;
    }
    out[192..224].* = word(length);
    out[length..][0..32].* = word(0);
    return out[0 .. length + 32];
}

const recover_gas: u64 = 3000;

fn permit(context: *Context, arguments: *const Arguments) Error!void {
    const owner = arguments.address(0);
    const deadline = arguments.uint256(3);
    if (context.timestamp > deadline) {
        return context.revert_word(error_expired_signature, word(deadline));
    }
    const separator = try domain_separator(context);
    const nonce_slot = b20.nonce_slot(owner);
    const nonce = try context.sload(nonce_slot);
    var encoded: [6 * 32]u8 = undefined;
    encoded[0..32].* = word(permit_typehash);
    encoded[32..64].* = arguments.words[0].*;
    encoded[64..96].* = arguments.words[1].*;
    encoded[96..128].* = arguments.words[2].*;
    encoded[128..160].* = word(nonce);
    encoded[160..192].* = arguments.words[3].*;
    const struct_hash = try metered_keccak(context, &encoded);
    var message: [66]u8 = undefined;
    message[0..2].* = .{ 0x19, 0x01 };
    message[2..34].* = separator;
    message[34..66].* = struct_hash;
    const signing_hash = try metered_keccak(context, &message);
    if (version_of(context) == .v2) try context.charge(recover_gas);
    const recovered = recover(signing_hash, arguments) orelse primitives.address_zero;
    if (b20.is_zero(recovered) or !std.mem.eql(u8, &recovered, &owner)) {
        return b20.revert_words(context, error_invalid_signer, &.{
            address_word(recovered),
            address_word(owner),
        });
    }
    if (nonce == std.math.maxInt(u256)) return b20.overflow(context);
    try context.sstore(nonce_slot, nonce + 1);
    try b20.approve(context, owner, arguments.address(1), arguments.uint256(2));
}

/// k256 recovery: v must be 27 or 28, and high s is rejected.
fn recover(hash: [32]u8, arguments: *const Arguments) ?Address {
    const v = arguments.small(4);
    if (v != 27 and v != 28) return null;
    const parity: u1 = @intCast(v - 27);
    return secp256k1.recover_tx_address(hash, parity, arguments.words[5].*, arguments.words[6].*);
}

pub const Tag = enum {
    default_admin_role,
    mint_role,
    burn_role,
    burn_blocked_role,
    pause_role,
    unpause_role,
    metadata_role,
    transfer_sender_policy,
    transfer_receiver_policy,
    transfer_executor_policy,
    mint_receiver_policy,
    name,
    symbol,
    decimals,
    total_supply,
    balance_of,
    allowance,
    transfer,
    transfer_from,
    approve,
    update_name,
    update_symbol,
    transfer_with_memo,
    transfer_from_with_memo,
    mint,
    mint_with_memo,
    burn,
    burn_with_memo,
    burn_blocked,
    has_role,
    get_role_admin,
    grant_role,
    revoke_role,
    renounce_role,
    renounce_last_admin,
    set_role_admin,
    paused_features,
    is_paused,
    pause,
    unpause,
    policy_id,
    update_policy,
    supply_cap,
    update_supply_cap,
    domain_separator,
    nonces,
    permit,
    eip712_domain,
    contract_uri,
    update_contract_uri,
    operator_role,
    wad_precision,
    is_announcement_id_used,
    multiplier,
    to_scaled_balance,
    to_raw_balance,
    scaled_balance_of,
    update_multiplier,
    batch_mint,
    extra_metadata,
    update_extra_metadata,
    announce,
    currency,
    seize_role,
    seize_exempt_policy,
    seize_receiver_policy,
    seize_with_memo,
    max_ui_multiplier,
    ui_multiplier,
    new_ui_multiplier,
    effective_at,
    balance_of_ui,
    total_supply_ui,
    to_ui_amount,
    from_ui_amount,
    update_ui_multiplier,
    cancel_ui_multiplier_update,
    supports_interface,
};

pub const functions = [_]Function{
    .{
        .tag = .default_admin_role,
        .selector = .{ 0xa2, 0x17, 0xfd, 0xdf },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .mint_role,
        .selector = .{ 0xe9, 0xa9, 0xc8, 0x50 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .burn_role,
        .selector = .{ 0xb9, 0x30, 0x90, 0x8f },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .burn_blocked_role,
        .selector = .{ 0x32, 0xad, 0x9b, 0xe8 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .pause_role,
        .selector = .{ 0x38, 0x9e, 0xd2, 0x67 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .unpause_role,
        .selector = .{ 0x30, 0x97, 0x56, 0xfb },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .metadata_role,
        .selector = .{ 0x38, 0x84, 0x17, 0x82 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .transfer_sender_policy,
        .selector = .{ 0xd1, 0x16, 0xfc, 0x21 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .transfer_receiver_policy,
        .selector = .{ 0x21, 0x0f, 0x52, 0x1b },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .transfer_executor_policy,
        .selector = .{ 0x72, 0x4e, 0x9c, 0x53 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .mint_receiver_policy,
        .selector = .{ 0x6e, 0x5b, 0x01, 0x3d },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .name,
        .selector = .{ 0x06, 0xfd, 0xde, 0x03 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .symbol,
        .selector = .{ 0x95, 0xd8, 0x9b, 0x41 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .decimals,
        .selector = .{ 0x31, 0x3c, 0xe5, 0x67 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .total_supply,
        .selector = .{ 0x18, 0x16, 0x0d, 0xdd },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .balance_of,
        .selector = .{ 0x70, 0xa0, 0x82, 0x31 },
        .parameters = "(address)",
        .kinds = &.{.address},
    },
    .{
        .tag = .allowance,
        .selector = .{ 0xdd, 0x62, 0xed, 0x3e },
        .parameters = "(address,address)",
        .kinds = &.{ .address, .address },
    },
    .{
        .tag = .transfer,
        .selector = .{ 0xa9, 0x05, 0x9c, 0xbb },
        .parameters = "(address,uint256)",
        .kinds = &.{ .address, .uint256 },
    },
    .{
        .tag = .transfer_from,
        .selector = .{ 0x23, 0xb8, 0x72, 0xdd },
        .parameters = "(address,address,uint256)",
        .kinds = &.{ .address, .address, .uint256 },
    },
    .{
        .tag = .approve,
        .selector = .{ 0x09, 0x5e, 0xa7, 0xb3 },
        .parameters = "(address,uint256)",
        .kinds = &.{ .address, .uint256 },
    },
    .{
        .tag = .update_name,
        .selector = .{ 0x84, 0xda, 0x92, 0xa7 },
        .parameters = "(string)",
        .kinds = &.{.string},
    },
    .{
        .tag = .update_symbol,
        .selector = .{ 0x53, 0x7f, 0x53, 0x12 },
        .parameters = "(string)",
        .kinds = &.{.string},
    },
    .{
        .tag = .transfer_with_memo,
        .selector = .{ 0x95, 0x77, 0x7d, 0x59 },
        .parameters = "(address,uint256,bytes32)",
        .kinds = &.{ .address, .uint256, .bytes32 },
    },
    .{
        .tag = .transfer_from_with_memo,
        .selector = .{ 0x92, 0x9c, 0x25, 0x39 },
        .parameters = "(address,address,uint256,bytes32)",
        .kinds = &.{ .address, .address, .uint256, .bytes32 },
    },
    .{
        .tag = .mint,
        .selector = .{ 0x40, 0xc1, 0x0f, 0x19 },
        .parameters = "(address,uint256)",
        .kinds = &.{ .address, .uint256 },
    },
    .{
        .tag = .mint_with_memo,
        .selector = .{ 0xe4, 0x4f, 0x0b, 0x12 },
        .parameters = "(address,uint256,bytes32)",
        .kinds = &.{ .address, .uint256, .bytes32 },
    },
    .{
        .tag = .burn,
        .selector = .{ 0x42, 0x96, 0x6c, 0x68 },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
    },
    .{
        .tag = .burn_with_memo,
        .selector = .{ 0x38, 0xf2, 0x3b, 0x0b },
        .parameters = "(uint256,bytes32)",
        .kinds = &.{ .uint256, .bytes32 },
    },
    .{
        .tag = .burn_blocked,
        .selector = .{ 0xec, 0x0c, 0xf3, 0xdc },
        .parameters = "(address,uint256)",
        .kinds = &.{ .address, .uint256 },
    },
    .{
        .tag = .has_role,
        .selector = .{ 0x91, 0xd1, 0x48, 0x54 },
        .parameters = "(bytes32,address)",
        .kinds = &.{ .bytes32, .address },
    },
    .{
        .tag = .get_role_admin,
        .selector = .{ 0x24, 0x8a, 0x9c, 0xa3 },
        .parameters = "(bytes32)",
        .kinds = &.{.bytes32},
    },
    .{
        .tag = .grant_role,
        .selector = .{ 0x2f, 0x2f, 0xf1, 0x5d },
        .parameters = "(bytes32,address)",
        .kinds = &.{ .bytes32, .address },
    },
    .{
        .tag = .revoke_role,
        .selector = .{ 0xd5, 0x47, 0x74, 0x1f },
        .parameters = "(bytes32,address)",
        .kinds = &.{ .bytes32, .address },
    },
    .{
        .tag = .renounce_role,
        .selector = .{ 0x36, 0x56, 0x8a, 0xbe },
        .parameters = "(bytes32,address)",
        .kinds = &.{ .bytes32, .address },
    },
    .{
        .tag = .renounce_last_admin,
        .selector = .{ 0x6f, 0x79, 0xe3, 0xd7 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .set_role_admin,
        .selector = .{ 0x1e, 0x4e, 0x00, 0x91 },
        .parameters = "(bytes32,bytes32)",
        .kinds = &.{ .bytes32, .bytes32 },
    },
    .{
        .tag = .paused_features,
        .selector = .{ 0xde, 0x99, 0x97, 0xe3 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .is_paused,
        .selector = .{ 0xbc, 0x61, 0xe7, 0x33 },
        .parameters = "(PausableFeature)",
        .kinds = &.{.enumeration},
    },
    .{
        .tag = .pause,
        .selector = .{ 0xa2, 0x90, 0x24, 0x9c },
        .parameters = "(PausableFeature[])",
        .kinds = &.{.enumeration_array},
    },
    .{
        .tag = .unpause,
        .selector = .{ 0x8b, 0x93, 0xdd, 0x63 },
        .parameters = "(PausableFeature[])",
        .kinds = &.{.enumeration_array},
    },
    .{
        .tag = .policy_id,
        .selector = .{ 0xdb, 0x3d, 0xe6, 0x24 },
        .parameters = "(bytes32)",
        .kinds = &.{.bytes32},
    },
    .{
        .tag = .update_policy,
        .selector = .{ 0xad, 0xf9, 0xc4, 0xea },
        .parameters = "(bytes32,uint64)",
        .kinds = &.{ .bytes32, .uint64 },
    },
    .{
        .tag = .supply_cap,
        .selector = .{ 0x8f, 0x77, 0x0a, 0xd0 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .update_supply_cap,
        .selector = .{ 0xe5, 0xa9, 0x7f, 0x07 },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
    },
    .{
        .tag = .domain_separator,
        .selector = .{ 0x36, 0x44, 0xe5, 0x15 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .nonces,
        .selector = .{ 0x7e, 0xce, 0xbe, 0x00 },
        .parameters = "(address)",
        .kinds = &.{.address},
    },
    .{
        .tag = .permit,
        .selector = .{ 0xd5, 0x05, 0xac, 0xcf },
        .parameters = "(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        .kinds = &.{ .address, .address, .uint256, .uint256, .uint8, .bytes32, .bytes32 },
    },
    .{
        .tag = .eip712_domain,
        .selector = .{ 0x84, 0xb0, 0x19, 0x6e },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .contract_uri,
        .selector = .{ 0xe8, 0xa3, 0xd4, 0x85 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .update_contract_uri,
        .selector = .{ 0x7e, 0x5b, 0x1e, 0x24 },
        .parameters = "(string)",
        .kinds = &.{.string},
    },
    .{
        .tag = .operator_role,
        .selector = .{ 0xf5, 0xb5, 0x41, 0xa6 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .wad_precision,
        .selector = .{ 0x66, 0x48, 0x08, 0xa8 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .is_announcement_id_used,
        .selector = .{ 0xc0, 0xda, 0x47, 0x4e },
        .parameters = "(string)",
        .kinds = &.{.string},
    },
    .{
        .tag = .multiplier,
        .selector = .{ 0x1b, 0x3e, 0xd7, 0x22 },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .to_scaled_balance,
        .selector = .{ 0x04, 0xf0, 0x4c, 0x99 },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
    },
    .{
        .tag = .to_raw_balance,
        .selector = .{ 0x0c, 0xa0, 0x6c, 0x44 },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
    },
    .{
        .tag = .scaled_balance_of,
        .selector = .{ 0x1d, 0xa2, 0x4f, 0x3e },
        .parameters = "(address)",
        .kinds = &.{.address},
    },
    .{
        .tag = .update_multiplier,
        .selector = .{ 0x5f, 0xfe, 0x61, 0x46 },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
    },
    .{
        .tag = .batch_mint,
        .selector = .{ 0x68, 0x57, 0x31, 0x07 },
        .parameters = "(address[],uint256[])",
        .kinds = &.{ .address_array, .uint256_array },
    },
    .{
        .tag = .extra_metadata,
        .selector = .{ 0x4d, 0xdf, 0x9d, 0xa0 },
        .parameters = "(string)",
        .kinds = &.{.string},
    },
    .{
        .tag = .update_extra_metadata,
        .selector = .{ 0xb2, 0x85, 0x1e, 0xf5 },
        .parameters = "(string,string)",
        .kinds = &.{ .string, .string },
    },
    .{
        .tag = .announce,
        .selector = .{ 0x59, 0x51, 0x35, 0xdd },
        .parameters = "(bytes[],string,string,string)",
        .kinds = &.{ .bytes_array, .string, .string, .string },
    },
    .{
        .tag = .currency,
        .selector = .{ 0xe5, 0xa6, 0xb1, 0x0f },
        .parameters = "()",
        .kinds = &.{},
    },
    .{
        .tag = .seize_role,
        .selector = .{ 0x3c, 0x7e, 0x9b, 0xa5 },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .seize_exempt_policy,
        .selector = .{ 0xfe, 0xb3, 0x46, 0xec },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .seize_receiver_policy,
        .selector = .{ 0xb3, 0x1d, 0xa2, 0x7f },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .seize_with_memo,
        .selector = .{ 0xf9, 0x16, 0xd8, 0x1b },
        .parameters = "(address,address,uint256,bytes32)",
        .kinds = &.{ .address, .address, .uint256, .bytes32 },
        .since = .v2,
    },
    .{
        .tag = .max_ui_multiplier,
        .selector = .{ 0x78, 0x5c, 0x0c, 0xf0 },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .ui_multiplier,
        .selector = .{ 0xa6, 0x0b, 0xf1, 0x3d },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .new_ui_multiplier,
        .selector = .{ 0xdc, 0x76, 0x70, 0x07 },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .effective_at,
        .selector = .{ 0x97, 0xa4, 0x06, 0x4f },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .balance_of_ui,
        .selector = .{ 0x43, 0x7a, 0x99, 0x58 },
        .parameters = "(address)",
        .kinds = &.{.address},
        .since = .v2,
    },
    .{
        .tag = .total_supply_ui,
        .selector = .{ 0x9b, 0xea, 0x64, 0x29 },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .to_ui_amount,
        .selector = .{ 0x32, 0x48, 0xd4, 0xff },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
        .since = .v2,
    },
    .{
        .tag = .from_ui_amount,
        .selector = .{ 0x65, 0xcd, 0x9b, 0x3c },
        .parameters = "(uint256)",
        .kinds = &.{.uint256},
        .since = .v2,
    },
    .{
        .tag = .update_ui_multiplier,
        .selector = .{ 0x62, 0x8e, 0x60, 0x0f },
        .parameters = "(uint256,uint256)",
        .kinds = &.{ .uint256, .uint256 },
        .since = .v2,
    },
    .{
        .tag = .cancel_ui_multiplier_update,
        .selector = .{ 0x2c, 0x97, 0xa0, 0xf0 },
        .parameters = "()",
        .kinds = &.{},
        .since = .v2,
    },
    .{
        .tag = .supports_interface,
        .selector = .{ 0x01, 0xff, 0xc9, 0xa7 },
        .parameters = "(bytes4)",
        .kinds = &.{.bytes4},
        .since = .v2,
    },
};

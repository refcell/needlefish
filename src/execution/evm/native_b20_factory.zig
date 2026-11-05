//! B-20 token factory (Beryl) at 0xB20F00..00: deterministic token addresses, creation with
//! privileged init calls, and B-20 address queries.
//! base/base `crates/common/precompiles/src/b20_factory` (dispatch.rs, logic/v1.rs).
//!
//! A token address is 0xb2, nine zero bytes, the variant discriminant, then the first nine
//! bytes of keccak256(abi.encode(creator, salt)).

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");
const abi = @import("native_abi.zig");
const activation = @import("native_activation.zig");
const b20 = @import("native_b20.zig");
const asset = @import("native_b20_token.zig");
const storage = @import("native_storage.zig");
const primitives = @import("primitives.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Context = native.Context;
const Error = native.Error;
const Arguments = abi.Arguments;

const word = native.u256_word;
const address_word = native.address_word;

pub const address = primitives.hex_to_address("b20f000000000000000000000000000000000000");
const variant_max: u8 = @backingInt(native.B20Variant.stablecoin);
const params_version: u8 = 1;
/// keccak256 of a 64-byte preimage: 30 + 2 words * 6.
const address_hash_gas: u64 = 42;

const error_token_already_exists = [4]u8{ 0x15, 0xef, 0x3a, 0x57 };
const error_unsupported_version = [4]u8{ 0xc0, 0xd8, 0xb4, 0xe0 };
const error_invalid_decimals = [4]u8{ 0xca, 0x95, 0x03, 0x91 };
const error_init_call_failed = [4]u8{ 0x4e, 0xae, 0x08, 0x60 };
const event_b20_created: B256 = primitives.hex_to_b256(
    "fd9bf2730513a1709722ff379a0844dfd8f997d600693c2bcc659e188bbdba0d",
);

pub const Tag = enum { create_b20, get_b20_address, is_b20, is_b20_initialized };

const Function = struct {
    tag: Tag,
    selector: [4]u8,
    parameters: []const u8,
    kinds: []const abi.Kind,
};

pub const functions = [_]Function{
    .{
        .tag = .create_b20,
        .selector = .{ 0x62, 0x97, 0x5e, 0x6a },
        .parameters = "(uint8,bytes32,bytes,bytes[])",
        .kinds = &.{ .enumeration, .bytes32, .bytes, .bytes_array },
    },
    .{
        .tag = .get_b20_address,
        .selector = .{ 0x8c, 0x30, 0x26, 0x0f },
        .parameters = "(uint8,address,bytes32)",
        .kinds = &.{ .enumeration, .address, .bytes32 },
    },
    .{
        .tag = .is_b20,
        .selector = .{ 0xfa, 0x19, 0xb9, 0x27 },
        .parameters = "(address)",
        .kinds = &.{.address},
    },
    .{
        .tag = .is_b20_initialized,
        .selector = .{ 0x6a, 0x45, 0xba, 0x98 },
        .parameters = "(address)",
        .kinds = &.{.address},
    },
};

pub fn selector_of(tag: Tag) [4]u8 {
    return functions[@backingInt(tag)].selector;
}

pub fn dispatch(context: *Context, input: []const u8) Error![]const u8 {
    if (context.value != 0) return context.revert_selector(native.selector_non_payable);
    try context.charge_calldata(input);
    const selector = native.selector_of(input);
    const function = for (&functions) |*function| {
        if (std.mem.eql(u8, &function.selector, &selector)) break function;
    } else return context.revert_unknown(selector);
    assert(input.len >= 4);
    var failure: native.DecodeFailure = .overrun;
    const kinds = function.kinds;
    const arguments = abi.decode_arguments(input[4..], kinds, variant_max, &failure) orelse
        return context.revert_decode(selector, function.parameters, failure);
    switch (function.tag) {
        .create_b20 => {
            const token = try create(context, &arguments);
            return native.write_word(context, address_word(token));
        },
        .get_b20_address => {
            try context.charge(address_hash_gas);
            const variant: native.B20Variant = @fromBackingInt(@intCast(arguments.small(0)));
            const token = token_address(variant, arguments.address(1), arguments.words[2]);
            return native.write_word(context, address_word(token));
        },
        .is_b20 => {
            const is_b20 = prefixed(arguments.address(0));
            return native.write_word(context, word(@intFromBool(is_b20)));
        },
        .is_b20_initialized => {
            const token = arguments.address(0);
            const initialized = prefixed(token) and try marker_installed(context, token);
            return native.write_word(context, word(@intFromBool(initialized)));
        },
    }
}

/// 0xb2 followed by nine zero bytes (any discriminant).
fn prefixed(account: Address) bool {
    if (account[0] != 0xb2) return false;
    for (account[1..10]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// Metered account read: the code is exactly the `0xef` marker.
fn marker_installed(context: *Context, token: Address) Error!bool {
    if (!try context.account_has_code(token)) return false;
    const account = try context.state.load(token);
    const code = try context.state.code(account);
    return std.mem.eql(u8, code, &native.marker_code);
}

pub fn token_address(variant: native.B20Variant, creator: Address, salt: *const [32]u8) Address {
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update(&address_word(creator));
    hasher.update(salt);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var token: Address = @splat(0);
    token[0] = 0xb2;
    token[10] = @backingInt(variant);
    token[11..20].* = digest[0..9].*;
    assert(native.b20_variant(token).? == variant);
    return token;
}

const Params = struct {
    variant: native.B20Variant,
    version: u8,
    name: []const u8,
    symbol: []const u8,
    initial_admin: Address,
    /// Asset decimals (stablecoins are fixed at 6).
    decimals: u8,
    /// Stablecoin currency code.
    currency: []const u8,
};

/// abi_decode_validate of `B20AssetCreateParams` / `B20StablecoinCreateParams` (a dynamic
/// struct behind one offset word); failures report the createB20 selector.
fn decode_params(
    context: *Context,
    variant: native.B20Variant,
    params: []const u8,
) Error!Params {
    const selector = selector_of(.create_b20);
    const name = switch (variant) {
        .asset => "B20AssetCreateParams",
        .stablecoin => "B20StablecoinCreateParams",
    };
    const last: abi.Kind = if (variant == .asset) .uint8 else .string;
    const kinds = [_]abi.Kind{ .uint8, .string, .string, .address, last };
    var failure: native.DecodeFailure = .overrun;
    if (params.len < 32) return context.revert_decode(selector, name, failure);
    const head = params[0..32];
    const offset = for (head[0..24]) |byte| {
        if (byte != 0) return context.revert_decode(selector, name, .{ .offset = head.* });
    } else std.mem.readInt(u64, head[24..32], .big);
    if (offset > params.len) return context.revert_decode(selector, name, failure);
    const tuple = params[@intCast(offset)..];
    const arguments = abi.decode_arguments(tuple, &kinds, 0, &failure) orelse
        return context.revert_decode(selector, name, failure);
    const is_asset = variant == .asset;
    return .{
        .variant = variant,
        .version = arguments.small(0),
        .name = arguments.bytes(1),
        .symbol = arguments.bytes(2),
        .initial_admin = arguments.address(3),
        .decimals = if (is_asset) arguments.small(4) else asset.decimals_min,
        .currency = if (is_asset) &.{} else arguments.bytes(4),
    };
}

fn ensure_activated(context: *Context, feature: u256) Error!void {
    const slot = activation.feature_slot(word(feature));
    if (try context.sload_at(activation.address, slot) != 0) return;
    return context.revert_word(activation.error_feature_not_activated, word(feature));
}

fn create(context: *Context, arguments: *const Arguments) Error!Address {
    try context.charge(address_hash_gas);
    const variant: native.B20Variant = @fromBackingInt(@intCast(arguments.small(0)));
    const feature = switch (variant) {
        .asset => activation.feature_b20_asset,
        .stablecoin => activation.feature_b20_stablecoin,
    };
    try ensure_activated(context, feature);
    const params = try decode_params(context, variant, arguments.bytes(2));
    if (params.version != params_version) {
        return b20.revert_words(context, error_unsupported_version, &.{
            word(params.version),
            word(@backingInt(variant)),
        });
    }
    if (params.decimals < asset.decimals_min or params.decimals > asset.decimals_max) {
        return context.revert_word(error_invalid_decimals, word(params.decimals));
    }
    const token = token_address(variant, context.caller, arguments.words[1]);
    if (try context.account_has_code(token)) {
        return context.revert_word(error_token_already_exists, address_word(token));
    }
    try context.install_marker_at(token);
    try initialize(context, token, &params);
    try emit_created(context, token, variant, &params);
    try run_init_calls(context, token, &params, arguments);
    return token;
}

/// Runs `body` against the token's storage and logs with the factory as caller.
const TokenScope = struct {
    address: Address,
    caller: Address,

    fn enter(context: *Context, token: Address) TokenScope {
        const saved = TokenScope{ .address = context.address, .caller = context.caller };
        context.address = token;
        context.caller = address;
        return saved;
    }

    fn leave(saved: TokenScope, context: *Context) void {
        context.address = saved.address;
        context.caller = saved.caller;
    }
};

fn initialize(context: *Context, token: Address, params: *const Params) Error!void {
    const scope = TokenScope.enter(context, token);
    defer scope.leave(context);
    if (params.variant == .stablecoin) try validate_currency(context, params.currency);
    try storage.store(context, b20.slot_name, params.name);
    try storage.store(context, b20.slot_symbol, params.symbol);
    try context.sstore(b20.slot_supply_cap, b20.supply_cap_max);
    if (params.variant == .stablecoin) {
        try storage.store(context, asset.stablecoin_root, params.currency);
        return;
    }
    const decimals_word = try context.sload(asset.asset_root);
    try context.sstore(asset.asset_root, (decimals_word & ~@as(u256, 0xff)) | params.decimals);
    try context.sstore(asset.asset_root + 1, 0); // Initial multiplier 0 (reads as WAD).
}

const error_missing_required_field = [4]u8{ 0x4a, 0x43, 0xae, 0x87 };
const error_invalid_currency = [4]u8{ 0x99, 0x7c, 0x1d, 0xe8 };

/// Non-empty, uppercase ASCII letters only.
fn validate_currency(context: *Context, currency: []const u8) Error!void {
    if (currency.len == 0) {
        return revert_string(context, error_missing_required_field, "currency");
    }
    for (currency) |byte| {
        if (byte < 'A' or byte > 'Z') {
            return revert_string(context, error_invalid_currency, currency);
        }
    }
}

fn revert_string(context: *Context, selector: [4]u8, text: []const u8) error{Revert} {
    const out = context.out;
    out[0..4].* = selector;
    out[4..36].* = word(0x20);
    out[36..68].* = word(text.len);
    const padded = std.mem.alignForward(usize, text.len, 32);
    @memset(out[68..][0..padded], 0);
    @memcpy(out[68..][0..text.len], text);
    return context.revert(out[0 .. 68 + padded]);
}

/// B20Created(token indexed, variant indexed, name, symbol, decimals, variantParams);
/// stablecoin variantParams = abi.encode(B20StablecoinEventParams{version: 1, currency}).
fn emit_created(
    context: *Context,
    token: Address,
    variant: native.B20Variant,
    params: *const Params,
) Error!void {
    const out = context.out;
    out[64..96].* = word(params.decimals);
    var length: usize = 4 * 32;
    length = append_bytes(out, 0, length, params.name);
    length = append_bytes(out, 1, length, params.symbol);
    out[96..128].* = word(length);
    if (variant == .asset) {
        out[length..][0..32].* = word(0);
        length += 32;
    } else {
        const currency = params.currency;
        const padded = std.mem.alignForward(usize, currency.len, 32);
        out[length..][0..32].* = word(4 * 32 + padded);
        out[length + 32 ..][0..32].* = word(0x20);
        out[length + 64 ..][0..32].* = word(1);
        out[length + 96 ..][0..32].* = word(0x40);
        length = append_tail(out, length + 128, currency);
    }
    const topics = [3]B256{ event_b20_created, address_word(token), word(@backingInt(variant)) };
    try context.emit(&topics, out[0..length]);
}

/// Write head `head` as an offset to a length-prefixed tail at `length`.
fn append_bytes(out: []u8, head: usize, length: usize, bytes: []const u8) usize {
    out[32 * head ..][0..32].* = word(length);
    return append_tail(out, length, bytes);
}

fn append_tail(out: []u8, length: usize, bytes: []const u8) usize {
    out[length..][0..32].* = word(bytes.len);
    const padded = std.mem.alignForward(usize, bytes.len, 32);
    @memset(out[length + 32 ..][0..padded], 0);
    @memcpy(out[length + 32 ..][0..bytes.len], bytes);
    assert(padded % 32 == 0);
    return length + 32 + padded;
}

fn run_init_calls(
    context: *Context,
    token: Address,
    params: *const Params,
    arguments: *const Arguments,
) Error!void {
    const scope = TokenScope.enter(context, token);
    defer scope.leave(context);
    if (!b20.is_zero(params.initial_admin)) {
        const admin = params.initial_admin;
        try b20.grant_role_unchecked(context, b20.role_default_admin, admin, address);
    }
    var index: u32 = 0;
    while (index < arguments.bytes_count(3)) : (index += 1) {
        const call = arguments.bytes_item(3, index);
        _ = asset.route(context, call, true) catch |err| switch (err) {
            error.Revert => {
                if (context.revert_len != 0 and context.revert_custom) return error.Revert;
                return context.revert_word(error_init_call_failed, word(index));
            },
            else => |other| return other,
        };
    }
}

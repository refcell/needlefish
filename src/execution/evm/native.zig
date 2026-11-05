//! Base native (stateful) precompiles: Solidity-ABI contracts implemented in the client
//! that read and write EVM state through the transaction journal.
//!
//! Mirrors base/base `crates/common/precompile-storage` (metering, result mapping) and
//! `crates/common/precompiles` (contracts). The framework rules:
//!   - only direct calls (CALL, STATICCALL); DELEGATECALL and CALLCODE revert with
//!     `DelegateCallNotAllowed()` and use no gas,
//!   - storage, transient storage, and logs go through the EVM journal, so the calling
//!     frame's revert rolls them back; warmth is the transaction access list,
//!   - gas is charged on top of the CALL with the Osaka schedule (base/base passes
//!     `GasParams::default()`): SLOAD 100/2100, SSTORE per EIP-2200/2929/3529,
//!     TLOAD/TSTORE 100, LOG 375 + 375 per topic + 8 per byte,
//!   - out of gas halts (the frame loses all its gas); contract errors revert with their
//!     ABI encoding and keep the unused gas; writes in a static call revert empty.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const gas = @import("gas.zig");
const state_module = @import("state.zig");
const op = @import("op.zig");
const keccak256 = @import("../../common/crypto/root.zig").keccak256;
const activation = @import("native_activation.zig");
const policy = @import("native_policy.zig");
const native_abi = @import("native_abi.zig");
pub const Address = primitives.Address;
const B256 = primitives.B256;
const State = state_module.State;

pub const Status = enum { success, revert, halt };

pub const Outcome = struct {
    status: Status,
    gas_used: u64,
    /// SSTORE refund counter delta; only meaningful on success.
    refund: i64,
    output: []const u8,
};

pub const Error = error{ OutOfGas, Revert } || state_module.Error;

/// The call context and host operations one native precompile invocation sees.
pub const Context = struct {
    state: *State,
    upgrade: op.Upgrade,
    /// Chain-configured activation admin (`beryl_activation_admin_address`).
    activation_admin: ?Address = null,
    address: Address,
    caller: Address,
    origin: Address,
    value: u256,
    is_static: bool,
    gas_limit: u64,
    gas_used: u64 = 0,
    refund: i64 = 0,
    /// Output (or revert data) buffer, the EVM return buffer.
    out: []u8,
    revert_len: u32 = 0,

    pub fn charge(context: *Context, cost: u64) error{OutOfGas}!void {
        assert(context.gas_used <= context.gas_limit);
        if (cost > context.gas_limit - context.gas_used) return error.OutOfGas;
        context.gas_used += cost;
    }

    /// Revert with `data` (an ABI-encoded error, a bare selector, or empty).
    pub fn revert(context: *Context, data: []const u8) error{Revert} {
        assert(data.len <= context.out.len);
        @memcpy(context.out[0..data.len], data);
        context.revert_len = @intCast(data.len);
        return error.Revert;
    }

    pub fn revert_selector(context: *Context, selector: [4]u8) error{Revert} {
        return context.revert(&selector);
    }

    /// Calldata ingestion charge of the common dispatchers: 6 gas per 32-byte word.
    pub fn charge_calldata(context: *Context, input: []const u8) error{OutOfGas}!void {
        const words = (@as(u64, input.len) + 31) / 32;
        try context.charge(words * calldata_word_gas);
    }

    pub fn sload(context: *Context, slot: u256) Error!u256 {
        return context.sload_at(context.address, slot);
    }

    pub fn sstore(context: *Context, slot: u256, value: u256) Error!void {
        if (context.is_static) return context.revert(&.{});
        if (context.gas_limit - context.gas_used <= gas.call_stipend) return error.OutOfGas;
        const account = try context.state.load(context.address);
        const access = try context.state.storage_access(account, slot);
        const stored = access.slot;
        const cost = gas.sstore(.osaka, stored.original, stored.present, value, access.is_cold);
        try context.charge(cost.cost);
        context.refund += cost.refund;
        try context.state.storage_write(account, stored, value);
    }

    /// `__initialize`: install the one-byte `0xef` marker code (G_codedeposit, plus G_create
    /// and the code-hash cost when the account had no code). Existing code is kept.
    pub fn install_marker(context: *Context) Error!void {
        if (context.is_static) return context.revert(&.{});
        try context.charge(gas.code_deposit_byte);
        const account = try context.state.load(context.address);
        if (account.info.has_code()) return;
        try context.charge(gas.create + keccak256_gas + gas.keccak256_word);
        try context.state.set_code(account, &marker_code);
    }

    pub fn is_cobalt(context: *const Context) bool {
        return context.upgrade.at_least(.cobalt);
    }

    /// A known selector with malformed arguments: the bare selector from Cobalt, the
    /// selector followed by the ABI decoder's message before.
    pub fn revert_decode(
        context: *Context,
        selector: [4]u8,
        parameters: []const u8,
        failure: DecodeFailure,
    ) error{Revert} {
        assert(parameters.len <= parameters_length_max);
        if (context.is_cobalt()) return context.revert_selector(selector);
        var buffer: [4 + 160]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        writer.writeAll(&selector) catch unreachable; // 4 bytes fit.
        // Messages are at most 26 + parameters_length_max or 51 + 64 bytes.
        switch (failure) {
            .overrun => writer.writeAll(
                "ABI decoding failed: buffer overrun while deserializing",
            ) catch unreachable,
            .type_check => writer.print("type check failed for \"{s}\"", .{
                parameters,
            }) catch unreachable,
            .offset => |word| writer.print(
                "type check failed for \"offset (usize)\" with data: {x}",
                .{&word},
            ) catch unreachable,
        }
        return context.revert(writer.buffered());
    }

    pub fn sload_at(context: *Context, address: Address, slot: u256) Error!u256 {
        const account = try context.state.load(address);
        const access = try context.state.storage_access(account, slot);
        const cost: u64 = if (access.is_cold) gas.cold_sload else gas.warm_storage_read;
        try context.charge(cost);
        return access.slot.present;
    }

    /// Revert with `selector` followed by one ABI word.
    pub fn revert_word(context: *Context, selector: [4]u8, word: [32]u8) error{Revert} {
        var buffer: [36]u8 = undefined;
        buffer[0..4].* = selector;
        buffer[4..36].* = word;
        return context.revert(&buffer);
    }

    pub fn tload_unmetered(context: *Context, slot: u256) u256 {
        return context.state.transient_load(context.address, slot);
    }

    pub fn tstore(context: *Context, slot: u256, value: u256) Error!void {
        if (context.is_static) return context.revert(&.{});
        try context.charge(gas.warm_storage_read);
        try context.state.transient_store(context.address, slot, value);
    }

    pub fn emit(context: *Context, topics: []const B256, data: []const u8) Error!void {
        assert(topics.len <= 4);
        if (context.is_static) return context.revert(&.{});
        const cost = gas.log + gas.log_topic * @as(u64, topics.len) +
            gas.log_data_byte * @as(u64, data.len);
        try context.charge(cost);
        try context.state.log(context.address, topics, data);
    }
};

pub const calldata_word_gas: u64 = 6;
pub const marker_code = [_]u8{0xef};
/// G_sha3, the static KECCAK256 cost.
const keccak256_gas: u64 = 30;

pub const DecodeFailure = union(enum) { overrun, type_check, offset: [32]u8 };
/// Longest parameter tuple signature in a type-check message.
pub const parameters_length_max = 96;

/// Returns the output slice (inside `context.out`) on success.
pub const Native = *const fn (context: *Context, input: []const u8) Error![]const u8;

pub const tx_context_address =
    primitives.hex_to_address("813000000000000000000000000000000000aa02");
pub const nonce_manager_address = op.nonce_manager;

pub const selector_delegate_call_not_allowed = [4]u8{ 0x0d, 0x89, 0x43, 0x8e };
pub const selector_non_payable = [4]u8{ 0x6f, 0xb1, 0xb0, 0xe9 };

/// The native precompile at `address` under `upgrade`, if any.
pub fn lookup(upgrade: ?op.Upgrade, address: Address) ?Native {
    const active = upgrade orelse return null;
    if (!active.at_least(.beryl)) return null;
    if (std.mem.eql(u8, &address, &activation.address)) return activation.dispatch;
    // PolicyRegistry V2 (Cobalt) and V3 (Denim) are not implemented yet.
    if (!active.at_least(.cobalt) and std.mem.eql(u8, &address, &policy.address)) {
        return policy.dispatch;
    }
    if (!active.at_least(.cobalt)) return null;
    if (std.mem.eql(u8, &address, &tx_context_address)) return tx_context;
    if (std.mem.eql(u8, &address, &nonce_manager_address)) return nonce_manager;
    return null;
}

/// Singletons warmed at transaction start (they are in the precompile set).
pub fn warm_addresses(upgrade: ?op.Upgrade) []const Address {
    const active = upgrade orelse return &.{};
    if (!active.at_least(.beryl)) return &.{};
    if (!active.at_least(.cobalt)) return &.{ activation.address, policy.address };
    return &.{ activation.address, nonce_manager_address, tx_context_address };
}

/// Run `native` and map its result. `is_direct` is false for DELEGATECALL / CALLCODE.
pub fn run(
    native: Native,
    context: *Context,
    input: []const u8,
    is_direct: bool,
) state_module.Error!Outcome {
    if (!is_direct) {
        @memcpy(context.out[0..4], &selector_delegate_call_not_allowed);
        return .{ .status = .revert, .gas_used = 0, .refund = 0, .output = context.out[0..4] };
    }
    const output = native(context, input) catch |err| switch (err) {
        error.OutOfGas => return .{
            .status = .halt,
            .gas_used = context.gas_limit,
            .refund = 0,
            .output = &.{},
        },
        error.Revert => return .{
            .status = .revert,
            .gas_used = context.gas_used,
            .refund = 0,
            .output = context.out[0..context.revert_len],
        },
        else => |fatal| return fatal,
    };
    assert(context.gas_used <= context.gas_limit);
    return .{
        .status = .success,
        .gas_used = context.gas_used,
        .refund = context.refund,
        .output = output,
    };
}

// ------------------------------------------------------------------ ABI helpers

/// The 4-byte selector; calls shorter than 4 bytes use zeros (an unknown selector).
pub fn selector_of(input: []const u8) [4]u8 {
    if (input.len < 4) return @splat(0);
    return input[0..4].*;
}

/// Argument word `index` after the selector, or null when the calldata is too short.
pub fn argument(input: []const u8, index: usize) ?*const [32]u8 {
    const start = 4 + 32 * index;
    if (input.len < start + 32) return null;
    return input[start..][0..32];
}

/// ABI `address` validation: the 12 high bytes must be zero.
pub fn argument_address(word: *const [32]u8) ?Address {
    for (word[0..12]) |byte| {
        if (byte != 0) return null;
    }
    return word[12..32].*;
}

pub fn write_word(context: *Context, word: [32]u8) []const u8 {
    context.out[0..32].* = word;
    return context.out[0..32];
}

pub fn address_word(address: Address) [32]u8 {
    var word: [32]u8 = @splat(0);
    word[12..32].* = address;
    return word;
}

// ------------------------------------------------------------------ TxContext

pub const selector_get_transaction_sender = [4]u8{ 0xbe, 0xad, 0x3f, 0x50 };
pub const selector_get_transaction_payer = [4]u8{ 0x69, 0x0b, 0x3a, 0x9d };
pub const selector_get_transaction_sender_actor_id = [4]u8{ 0xe1, 0x4f, 0xe3, 0xf3 };

/// EIP-8130 transaction context (Cobalt): sender, payer, and sender actor id from
/// transient slots 0-2, falling back to tx.origin. Getters cost 3 gas per output word.
fn tx_context(context: *Context, input: []const u8) Error![]const u8 {
    if (context.value != 0) return context.revert_selector(selector_non_payable);
    const selector = selector_of(input);
    const slot: u256 = if (std.mem.eql(u8, &selector, &selector_get_transaction_sender))
        0
    else if (std.mem.eql(u8, &selector, &selector_get_transaction_payer))
        1
    else if (std.mem.eql(u8, &selector, &selector_get_transaction_sender_actor_id))
        2
    else
        return context.revert_selector(selector);
    const raw = context.tload_unmetered(slot);
    var word: [32]u8 = undefined;
    if (raw == 0) {
        word = address_word(context.origin);
    } else if (slot == 2) {
        std.mem.writeInt(u256, &word, raw, .big);
    } else {
        // An address word: the low 20 bytes of the stored value.
        std.mem.writeInt(u256, &word, raw & std.math.maxInt(u160), .big);
    }
    try context.charge(3);
    return write_word(context, word);
}

// ------------------------------------------------------------------ NonceManager

/// ERC-7201 root of `base.nonce_manager`; field 0 is `nonces`.
pub const nonce_manager_root: u256 =
    0x9d3ea32ad25774a46482ebbae019e8da4242109d164d324a59aa787515b9fe00;
pub const selector_get_nonce = [4]u8{ 0x89, 0x53, 0x58, 0x03 };
pub const selector_protocol_nonce_not_supported = [4]u8{ 0x1b, 0xc8, 0x1c, 0xa9 };

/// Solidity mapping slot: keccak256(key word ++ be32(base)).
pub fn mapping_slot(key: [32]u8, base: u256) u256 {
    var buffer: [64]u8 = undefined;
    buffer[0..32].* = key;
    std.mem.writeInt(u256, buffer[32..64], base, .big);
    return std.mem.readInt(u256, &keccak256(&buffer), .big);
}

pub fn u256_word(value: u256) [32]u8 {
    var word: [32]u8 = undefined;
    std.mem.writeInt(u256, &word, value, .big);
    return word;
}

/// `nonces[account][key]`: keccak256(be32(key) ++ keccak256(pad32(account) ++ be32(root))).
pub fn nonce_slot(account: Address, key: u256) u256 {
    const inner = mapping_slot(address_word(account), nonce_manager_root);
    return mapping_slot(u256_word(key), inner);
}

/// EIP-8130 2D nonce manager (Cobalt). Only `getNonce(address,uint256)` is callable;
/// increments are driven by the EIP-8130 transaction executor.
fn nonce_manager(context: *Context, input: []const u8) Error![]const u8 {
    if (context.value != 0) return context.revert_selector(selector_non_payable);
    try context.charge_calldata(input);
    const selector = selector_of(input);
    if (!std.mem.eql(u8, &selector, &selector_get_nonce)) return context.revert_selector(selector);
    // Cobalt+: a malformed call to a known selector reverts with the bare selector.
    const account_word = argument(input, 0) orelse return context.revert_selector(selector);
    const key_word = argument(input, 1) orelse return context.revert_selector(selector);
    const account = argument_address(account_word) orelse return context.revert_selector(selector);
    const key = std.mem.readInt(u256, key_word, .big);
    if (key == 0) return context.revert_selector(selector_protocol_nonce_not_supported);
    const stored = try context.sload(nonce_slot(account, key));
    var word: [32]u8 = @splat(0);
    std.mem.writeInt(u64, word[24..32], @truncate(stored), .big);
    return write_word(context, word);
}

const testing = std.testing;

fn expect_selector(comptime signature: []const u8, selector: [4]u8) !void {
    try testing.expectEqualSlices(u8, keccak256(signature)[0..4], &selector);
}

test "native: selectors match their Solidity signatures" {
    try expect_selector("DelegateCallNotAllowed()", selector_delegate_call_not_allowed);
    try expect_selector("NonPayable()", selector_non_payable);
    try expect_selector("getTransactionSender()", selector_get_transaction_sender);
    try expect_selector("getTransactionPayer()", selector_get_transaction_payer);
    try expect_selector("getTransactionSenderActorId()", selector_get_transaction_sender_actor_id);
    try expect_selector("getNonce(address,uint256)", selector_get_nonce);
    try expect_selector("ProtocolNonceNotSupported()", selector_protocol_nonce_not_supported);
}

test {
    _ = activation;
    _ = policy;
    _ = native_abi;
}

test "native: nonce manager root is the ERC-7201 slot of base.nonce_manager" {
    const id = std.mem.readInt(u256, &keccak256("base.nonce_manager"), .big);
    var buffer: [32]u8 = undefined;
    std.mem.writeInt(u256, &buffer, id - 1, .big);
    const root = std.mem.readInt(u256, &keccak256(&buffer), .big) & ~@as(u256, 0xff);
    try testing.expectEqual(nonce_manager_root, root);
}

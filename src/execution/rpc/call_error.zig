//! reth's errors for a failed RPC call (eth_call, eth_estimateGas, eth_createAccessList,
//! debug_traceCall, eth_simulateV1): base/reth 2b20e42
//! `crates/rpc/rpc-eth-types/src/error/mod.rs` (`RevertError`, `RpcInvalidTransactionError`
//! and its `halt`, `out_of_gas` and `From<InvalidTransaction>`). A revert is code 3 with
//! the output as `data`; a halt and an invalid call are -32000 or -32003 by kind.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");

const Exit = evm.evm.Exit;
const Invalid = evm.transaction.Invalid;

/// `EthRpcErrorCode::ExecutionError`: a revert.
pub const code_execution_error: i32 = 3;
/// `EthRpcErrorCode::InvalidInput`.
pub const code_invalid_input: i32 = -32000;
/// `EthRpcErrorCode::TransactionRejected`.
pub const code_transaction_rejected: i32 = -32003;

pub const Failure = struct { code: i32, message: []const u8 };

const selector_error = [4]u8{ 0x08, 0xc3, 0x79, 0xa0 };
const selector_panic = [4]u8{ 0x4e, 0x48, 0x7b, 0x71 };
const prefix_reverted = "execution reverted";

/// `RevertError`'s text: "execution reverted", then ": " and the reason alloy's
/// `RevertReason::decode` finds (an `Error(string)` reason, a `Panic(uint256)`, or the
/// whole output when it is UTF-8). Written into `buffer` (cut short when it does not fit).
pub fn revert_message(buffer: []u8, output: []const u8) []const u8 {
    assert(buffer.len >= prefix_reverted.len + 64);
    var out: Out = .{ .buffer = buffer };
    out.append(prefix_reverted);
    if (output.len == 0) return out.slice();
    if (output.len >= 4 and std.mem.eql(u8, output[0..4], &selector_error)) {
        if (error_reason(output[4..])) |reason| {
            out.append(": ");
            append_reason(&out, reason);
            return out.slice();
        }
    }
    if (output.len >= 4 + 32 and std.mem.eql(u8, output[0..4], &selector_panic)) {
        out.append(": ");
        append_panic(&out, std.mem.readInt(u256, output[4..36], .big));
        return out.slice();
    }
    if (std.unicode.utf8ValidateSlice(output)) {
        out.append(": ");
        out.append(output);
    }
    assert(out.length <= buffer.len);
    return out.slice();
}

/// The string of a non-validating `Error(string)` decode (alloy-sol-types): an offset word,
/// then at that offset a length word and the bytes; trailing data is ignored.
fn error_reason(body: []const u8) ?[]const u8 {
    const offset = offset_word(body, 0) orelse return null;
    if (offset > body.len) return null;
    const length = offset_word(body, offset) orelse return null;
    const start = offset + 32;
    if (length > body.len - start) return null;
    assert(start + length <= body.len);
    return body[start..][0..length];
}

/// A word read as a `usize` offset (its top 24 bytes zero), or null when out of range.
fn offset_word(body: []const u8, at: usize) ?usize {
    if (at > body.len or body.len - at < 32) return null;
    const word = body[at..][0..32];
    if (!std.mem.allEqual(u8, word[0..24], 0)) return null;
    const value = std.mem.readInt(u64, word[24..32], .big);
    return std.math.cast(usize, value);
}

/// `Revert`'s `Display` ("revert: " + reason, "<empty>" for none) with every leading
/// "revert: " trimmed, as reth's `trim_start_matches`. Invalid UTF-8 decodes lossily.
fn append_reason(out: *Out, reason: []const u8) void {
    const prefix = "revert: ";
    if (reason.len == 0) return out.append("<empty>");
    var text = reason;
    var iterations: usize = 0;
    while (std.mem.startsWith(u8, text, prefix)) : (iterations += 1) {
        assert(iterations < reason.len);
        text = text[prefix.len..];
    }
    if (std.unicode.utf8ValidateSlice(text)) return out.append(text);
    // A lossy decode never adds a "revert: " the valid prefix lacked: the prefix is ASCII.
    append_lossy(out, text);
}

/// `String::from_utf8_lossy`: each maximal invalid subsequence becomes U+FFFD.
fn append_lossy(out: *Out, bytes: []const u8) void {
    var index: usize = 0;
    while (index < bytes.len) {
        const length = std.unicode.utf8ByteSequenceLength(bytes[index]) catch {
            out.append("\u{fffd}");
            index += 1;
            continue;
        };
        var valid: usize = 1;
        while (valid < length and index + valid < bytes.len) : (valid += 1) {
            if (!continuation_valid(bytes[index], valid, bytes[index + valid])) break;
        }
        if (valid == length) {
            out.append(bytes[index..][0..length]);
        } else {
            out.append("\u{fffd}");
        }
        index += valid;
    }
    assert(index == bytes.len);
}

/// Whether `byte` may follow the lead byte `lead` at `position` (1-based) in UTF-8.
fn continuation_valid(lead: u8, position: usize, byte: u8) bool {
    assert(position >= 1 and position <= 3);
    if (position > 1) return byte >= 0x80 and byte <= 0xbf;
    return switch (lead) {
        0xe0 => byte >= 0xa0 and byte <= 0xbf,
        0xed => byte >= 0x80 and byte <= 0x9f,
        0xf0 => byte >= 0x90 and byte <= 0xbf,
        0xf4 => byte >= 0x80 and byte <= 0x8f,
        else => byte >= 0x80 and byte <= 0xbf,
    };
}

/// `Panic`'s `Display`: "panic: <kind> (0x<code>)".
fn append_panic(out: *Out, code: u256) void {
    out.append("panic: ");
    const kind: ?[]const u8 = switch (code) {
        0x00 => "generic/unspecified error",
        0x01 => "assertion failed",
        0x11 => "arithmetic underflow or overflow",
        0x12 => "division or modulo by zero",
        0x21 => "failed to convert value into enum type",
        0x22 => "storage byte array incorrectly encoded",
        0x31 => "called `.pop()` on an empty array",
        0x32 => "array out-of-bounds access",
        0x41 => "memory allocation error",
        0x51 => "called an invalid internal function",
        else => null,
    };
    var text: [80]u8 = undefined;
    const formatted = if (kind) |name|
        std.fmt.bufPrint(&text, "{s} (0x{x:0>2})", .{ name, code })
    else
        std.fmt.bufPrint(&text, "unknown code (0x{x})", .{code});
    out.append(formatted catch unreachable); // Proof: 80 bytes fit any kind and code.
}

/// The error of a call that halted (`RpcInvalidTransactionError::halt`, code -32003):
/// out of gas carries the gas limit, other halts print revm's `HaltReason` name.
pub fn halt(buffer: []u8, exit: Exit, gas_limit: u64) Failure {
    assert(buffer.len >= 96);
    assert(exit.status() == .halt);
    const name: []const u8 = switch (exit) {
        .out_of_gas => return gas_failure(buffer, "out of gas: gas required exceeds: ", gas_limit),
        .precompile_out_of_gas => return gas_failure(
            buffer,
            "out of gas: gas exhausted during precompiled contract execution: ",
            gas_limit,
        ),
        .invalid_opcode => "OpcodeNotFound",
        .invalid_fe_opcode => "InvalidFEOpcode",
        .stack_underflow => "StackUnderflow",
        .stack_overflow => "StackOverflow",
        .invalid_jump => "InvalidJump",
        .static_violation => "StateChangeDuringStaticCall",
        .return_data_out_of_bounds => "OutOfOffset",
        .code_size_limit => "CreateContractSizeLimit",
        .invalid_code_prefix => "CreateContractStartingWithEF",
        .create_collision => "CreateCollision",
        .precompile_failure => "PrecompileError",
        .out_of_funds => "OutOfFunds",
        .deposit_system_tx, .deposit_intrinsic_gas => "FailedDeposit",
        .stop, .return_, .self_destruct, .revert, .call, .create, .fatal => unreachable,
    };
    const message = std.fmt.bufPrint(buffer, "EVM error: {s}", .{name}) catch unreachable;
    return .{ .code = code_transaction_rejected, .message = message };
}

fn gas_failure(buffer: []u8, text: []const u8, gas_limit: u64) Failure {
    // Proof: `halt` asserts room for the longest text and a u64.
    const message = std.fmt.bufPrint(buffer, "{s}{d}", .{ text, gas_limit }) catch unreachable;
    return .{ .code = code_transaction_rejected, .message = message };
}

/// The error of a call the EVM rejects before execution (`From<InvalidTransaction>`).
pub fn invalid(reason: Invalid) Failure {
    return switch (reason) {
        .type_not_supported => rejected("transaction type not supported"),
        .gas_limit_too_high, .gas_cap_exceeded => input("intrinsic gas too high"),
        .chain_id_mismatch => input("invalid chain ID"),
        .fee_below_base_fee => input("max fee per gas less than block base fee"),
        .priority_fee_above_max_fee => rejected(
            "max priority fee per gas higher than max fee per gas",
        ),
        .initcode_too_large => rejected("max initcode size exceeded"),
        .intrinsic_gas_too_low, .floor_gas_too_low => input("intrinsic gas too low"),
        .sender_has_code => rejected("sender is not an EOA"),
        .nonce_too_low => input("nonce too low"),
        .nonce_too_high => input("nonce too high"),
        .nonce_overflow => rejected("nonce has max value"),
        .insufficient_funds => rejected("insufficient funds for gas * price + value"),
        .blob_create => rejected("blob transaction is a create transaction"),
        .blob_empty => rejected("blob transaction missing blob hashes"),
        .blob_too_many => rejected("blob transaction exceeds max blobs per block"),
        .blob_version => rejected("blob hash version mismatch"),
        .blob_fee_too_low => rejected("max fee per blob gas less than block blob gas fee"),
        .authorization_empty, .authorization_create => rejected(
            "EIP-7702 authorization list has invalid fields",
        ),
        .eip8130_rejected => rejected("EIP-8130 transaction rejected"),
    };
}

fn rejected(message: []const u8) Failure {
    return .{ .code = code_transaction_rejected, .message = message };
}

fn input(message: []const u8) Failure {
    return .{ .code = code_invalid_input, .message = message };
}

/// Whether reth's estimate treats `reason` as `GasTooHigh` / `GasTooLow` (`is_gas_too_high`,
/// `is_gas_too_low`).
pub fn gas_too_high(reason: Invalid) bool {
    return reason == .gas_limit_too_high or reason == .gas_cap_exceeded;
}

pub fn gas_too_low(reason: Invalid) bool {
    return reason == .intrinsic_gas_too_low or reason == .floor_gas_too_low;
}

/// Appends into a fixed buffer, dropping what does not fit.
const Out = struct {
    buffer: []u8,
    length: usize = 0,

    fn append(out: *Out, bytes: []const u8) void {
        const count = @min(bytes.len, out.buffer.len - out.length);
        @memcpy(out.buffer[out.length..][0..count], bytes[0..count]);
        out.length += count;
        assert(out.length <= out.buffer.len);
    }

    fn slice(out: *const Out) []const u8 {
        return out.buffer[0..out.length];
    }
};

fn encode_error_string(buffer: []u8, reason: []const u8) []const u8 {
    @memset(buffer, 0);
    buffer[0..4].* = selector_error;
    buffer[4 + 31] = 0x20;
    std.mem.writeInt(u256, buffer[4 + 32 ..][0..32], reason.len, .big);
    @memcpy(buffer[4 + 64 ..][0..reason.len], reason);
    return buffer[0 .. 4 + 64 + std.mem.alignForward(usize, reason.len, 32)];
}

test "call_error: revert messages follow alloy's RevertReason" {
    var buffer: [256]u8 = undefined;
    var encoded: [160]u8 = undefined;
    const t = std.testing;
    try t.expectEqualStrings("execution reverted", revert_message(&buffer, &.{}));
    // A custom error that is not UTF-8 has no reason.
    const custom = [_]u8{ 0x3c, 0xc5, 0x0b, 0x45 };
    try t.expectEqualStrings("execution reverted", revert_message(&buffer, &custom));
    const reason = encode_error_string(&encoded, "nope");
    try t.expectEqualStrings("execution reverted: nope", revert_message(&buffer, reason));
    const empty = encode_error_string(&encoded, "");
    try t.expectEqualStrings("execution reverted: <empty>", revert_message(&buffer, empty));
    const nested = encode_error_string(&encoded, "revert: revert: x");
    try t.expectEqualStrings("execution reverted: x", revert_message(&buffer, nested));
    const lossy = encode_error_string(&encoded, "a\xffb\xe2\x82");
    try t.expectEqualStrings(
        "execution reverted: a\u{fffd}b\u{fffd}",
        revert_message(&buffer, lossy),
    );
    var panic: [36]u8 = @splat(0);
    panic[0..4].* = selector_panic;
    panic[35] = 0x11;
    try t.expectEqualStrings(
        "execution reverted: panic: arithmetic underflow or overflow (0x11)",
        revert_message(&buffer, &panic),
    );
    panic[35] = 0x99;
    try t.expectEqualStrings(
        "execution reverted: panic: unknown code (0x99)",
        revert_message(&buffer, &panic),
    );
    try t.expectEqualStrings("execution reverted: hi", revert_message(&buffer, "hi"));
    // A truncated Error(string) falls back to the UTF-8 test of the whole output.
    try t.expectEqualStrings("execution reverted", revert_message(&buffer, reason[0..40]));
}

test "call_error: halts and invalid calls carry reth's codes" {
    var buffer: [128]u8 = undefined;
    const t = std.testing;
    const oog = halt(&buffer, .out_of_gas, 21000);
    try t.expectEqual(code_transaction_rejected, oog.code);
    try t.expectEqualStrings("out of gas: gas required exceeds: 21000", oog.message);
    const fe = halt(&buffer, .invalid_fe_opcode, 1).message;
    try t.expectEqualStrings("EVM error: InvalidFEOpcode", fe);
    const undefined_opcode = halt(&buffer, .invalid_opcode, 1).message;
    try t.expectEqualStrings("EVM error: OpcodeNotFound", undefined_opcode);
    const low = invalid(.fee_below_base_fee);
    try t.expectEqual(code_invalid_input, low.code);
    try t.expectEqualStrings("max fee per gas less than block base fee", low.message);
    try t.expect(gas_too_low(.intrinsic_gas_too_low) and !gas_too_low(.gas_cap_exceeded));
    try t.expect(gas_too_high(.gas_cap_exceeded) and !gas_too_high(.nonce_too_high));
}

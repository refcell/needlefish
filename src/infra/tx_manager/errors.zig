//! Publish-error classification (base/base `tx-manager/src/error.rs`
//! `RpcErrorClassifier`).
//!
//! Execution clients report mempool rejections only as free-form messages. The manager
//! needs a small closed set to decide whether to retry, bump, or abort, so messages are
//! matched case-insensitively against geth/reth substrings in base/base's order (the
//! "replacement transaction underpriced" check must precede "transaction underpriced").

const std = @import("std");
const assert = std.debug.assert;

pub const PublishError = enum {
    replacement_underpriced,
    underpriced,
    nonce_too_low,
    nonce_too_high,
    insufficient_funds,
    intrinsic_gas_too_low,
    execution_reverted,
    fee_too_low,
    max_fee_per_gas_too_low,
    already_known,
    /// Transport failure, timeout, or an unrecognized RPC error message.
    rpc,

    /// Errors that a later attempt (after a delay or a fee bump) may clear.
    pub fn is_retryable(publish_error: PublishError) bool {
        return switch (publish_error) {
            .nonce_too_high,
            .underpriced,
            .replacement_underpriced,
            .fee_too_low,
            .max_fee_per_gas_too_low,
            .already_known,
            .rpc,
            => true,
            .nonce_too_low,
            .insufficient_funds,
            .intrinsic_gas_too_low,
            .execution_reverted,
            => false,
        };
    }
};

const Pattern = struct { needle: []const u8, kind: PublishError };

/// Order matters: first match wins.
const patterns = [_]Pattern{
    .{ .needle = "replacement transaction underpriced", .kind = .replacement_underpriced },
    .{ .needle = "transaction underpriced", .kind = .underpriced },
    .{ .needle = "nonce too low", .kind = .nonce_too_low },
    .{ .needle = "nonce too high", .kind = .nonce_too_high },
    .{ .needle = "insufficient funds", .kind = .insufficient_funds },
    .{ .needle = "intrinsic gas too low", .kind = .intrinsic_gas_too_low },
    .{ .needle = "execution reverted", .kind = .execution_reverted },
    .{ .needle = "fee too low", .kind = .fee_too_low },
    .{ .needle = "max fee per gas less than block base fee", .kind = .max_fee_per_gas_too_low },
    .{ .needle = "already known", .kind = .already_known },
    .{ .needle = "transaction already in pool", .kind = .already_known },
};

comptime {
    for (patterns) |pattern| assert(pattern.needle.len > 0);
}

/// Classifies a JSON-RPC error message. Unknown messages are `.rpc`.
pub fn classify(message: []const u8) PublishError {
    for (patterns) |pattern| {
        if (contains_ignore_case(message, pattern.needle)) return pattern.kind;
    }
    return .rpc;
}

fn contains_ignore_case(haystack: []const u8, needle: []const u8) bool {
    assert(needle.len > 0);
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |start| {
        if (std.ascii.eqlIgnoreCase(haystack[start..][0..needle.len], needle)) return true;
    }
    return false;
}

const testing = std.testing;

test "errors: classify matches base/base cases" {
    const Case = struct { message: []const u8, kind: PublishError };
    const cases = [_]Case{
        .{ .message = "replacement transaction underpriced", .kind = .replacement_underpriced },
        .{ .message = "transaction underpriced", .kind = .underpriced },
        .{ .message = "nonce too low", .kind = .nonce_too_low },
        .{ .message = "NONCE TOO LOW", .kind = .nonce_too_low },
        .{ .message = "Nonce Too Low", .kind = .nonce_too_low },
        .{ .message = "nonce too high", .kind = .nonce_too_high },
        .{ .message = "insufficient funds for gas * price + value", .kind = .insufficient_funds },
        .{ .message = "intrinsic gas too low", .kind = .intrinsic_gas_too_low },
        .{ .message = "execution reverted: nope", .kind = .execution_reverted },
        .{ .message = "fee too low", .kind = .fee_too_low },
        .{
            .message = "max fee per gas less than block base fee",
            .kind = .max_fee_per_gas_too_low,
        },
        .{ .message = "already known", .kind = .already_known },
        .{ .message = "transaction already in pool", .kind = .already_known },
        .{ .message = "something else", .kind = .rpc },
        .{ .message = "", .kind = .rpc },
    };
    for (cases) |case| try testing.expectEqual(case.kind, classify(case.message));
}

test "errors: retryability" {
    try testing.expect(PublishError.nonce_too_high.is_retryable());
    try testing.expect(PublishError.already_known.is_retryable());
    try testing.expect(PublishError.rpc.is_retryable());
    try testing.expect(!PublishError.nonce_too_low.is_retryable());
    try testing.expect(!PublishError.execution_reverted.is_retryable());
    try testing.expect(!PublishError.insufficient_funds.is_retryable());
}

test "errors: fuzz classify is total and stable" {
    try testing.fuzz({}, fuzz_classify, .{});
}

fn fuzz_classify(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [256]u8 = undefined;
    const length = smith.slice(&buffer);
    const message = buffer[0..length];
    const kind = classify(message);
    // Deterministic and case-insensitive.
    try testing.expectEqual(kind, classify(message));
    var upper: [256]u8 = undefined;
    _ = std.ascii.upperString(upper[0..length], message);
    try testing.expectEqual(kind, classify(upper[0..length]));
}

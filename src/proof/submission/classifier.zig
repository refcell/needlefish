//! Known-revert classification of a JSON-RPC error (base/base
//! `crates/proof/submission/src/classifier.rs`): the revert data's selector goes through
//! `aggregate_verifier.classify_revert`; failing that, the message is searched for a known
//! selector in hex or a known error name (the name itself, not a longer identifier).

const std = @import("std");
const assert = std.debug.assert;

const aggregate_verifier = @import("../contracts/aggregate_verifier.zig");
const factory = @import("../contracts/dispute_game_factory.zig");

pub const KnownRevert = aggregate_verifier.KnownRevert;

const Named = struct { name: []const u8, selector: [4]u8, revert: KnownRevert };

const named = [_]Named{
    .{
        .name = "GameAlreadyExists",
        .selector = factory.game_already_exists,
        .revert = .game_already_exists,
    },
    .{
        .name = "AlreadyProven",
        .selector = aggregate_verifier.error_already_proven,
        .revert = .proof_already_verified,
    },
    .{
        .name = "L1OriginTooOld",
        .selector = aggregate_verifier.error_l1_origin_too_old,
        .revert = .l1_origin_too_old,
    },
    .{
        .name = "InvalidParentGame",
        .selector = aggregate_verifier.error_invalid_parent_game,
        .revert = .invalid_parent_game,
    },
    .{
        .name = "InvalidSigner",
        .selector = aggregate_verifier.error_invalid_signer,
        .revert = .invalid_signer,
    },
    .{
        .name = "InvalidProof",
        .selector = aggregate_verifier.error_invalid_proof,
        .revert = .invalid_proof,
    },
};

/// Classifies a JSON-RPC error from its `message` and hex `data` (`0x`-prefixed revert
/// payload, possibly empty); null for an unknown revert.
pub fn classify(message: []const u8, data: []const u8) ?KnownRevert {
    if (data_selector(data)) |selector| {
        if (aggregate_verifier.classify_revert(&selector)) |known| return known;
    }
    var hex_buffer: [8]u8 = undefined;
    for (named) |entry| {
        // Four bytes always format into eight hex digits.
        const hex = std.fmt.bufPrint(&hex_buffer, "{x}", .{&entry.selector}) catch unreachable;
        assert(hex.len == hex_buffer.len);
        if (std.ascii.findIgnoreCase(message, hex) != null) return entry.revert;
        if (names_error(message, entry.name)) return entry.revert;
    }
    return null;
}

/// The first four bytes of `0x`-prefixed hex revert data, if it holds that many.
fn data_selector(data: []const u8) ?[4]u8 {
    if (data.len < 10) return null;
    if (data[0] != '0' or (data[1] != 'x' and data[1] != 'X')) return null;
    var selector: [4]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&selector, data[2..10]) catch return null;
    assert(decoded.len == 4);
    return selector;
}

/// Whether `text` names `name` itself, not a longer identifier starting with it.
pub fn names_error(text: []const u8, name: []const u8) bool {
    assert(name.len > 0);
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, text, start, name)) |index| {
        const end = index + name.len;
        if (end == text.len) return true;
        const next = text[end];
        if (!std.ascii.isAlphanumeric(next) and next != '_') return true;
        start = index + 1;
    }
    assert(start <= text.len);
    return false;
}

const testing = std.testing;

test "submission classifier: data selector, selector text and error name" {
    var hex: [10]u8 = undefined;
    const exists = try std.fmt.bufPrint(&hex, "0x{x}", .{&factory.game_already_exists});
    try testing.expectEqual(KnownRevert.game_already_exists, classify("reverted", exists).?);
    const proven = try std.fmt.bufPrint(&hex, "0X{X}", .{&aggregate_verifier.error_already_proven});
    try testing.expectEqual(KnownRevert.proof_already_verified, classify("", proven).?);
    try testing.expectEqual(KnownRevert.invalid_proof, classify("InvalidProof()", "").?);
    try testing.expectEqual(null, classify("InvalidProofType()", ""));
    try testing.expectEqual(null, classify("execution reverted", "0x12345678"));
    try testing.expectEqual(null, classify("execution reverted", "0xzz"));
    var message: [64]u8 = undefined;
    const selector = aggregate_verifier.error_l1_origin_too_old;
    const text = try std.fmt.bufPrint(&message, "custom error {x}", .{&selector});
    try testing.expectEqual(KnownRevert.l1_origin_too_old, classify(text, "").?);
}

test "submission classifier: fuzz" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var message: [96]u8 = undefined;
            var data: [24]u8 = undefined;
            const message_length = smith.slice(&message);
            const data_length = smith.slice(&data);
            const result = classify(message[0..message_length], data[0..data_length]);
            // Without a selector or name in either string, nothing is known.
            if (message_length == 0 and data_length < 10) try testing.expectEqual(null, result);
        }
    }.one, .{ .iterations = 2000 });
}

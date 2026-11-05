//! `AggregateVerifier` (dispute game) calls (base/base
//! `crates/proof/contracts/src/aggregate_verifier.rs`): getter selectors and strict return
//! decoders, the `nullify`/`challenge` dispute calldata, `resolve`/`claimCredit`, the
//! interval ABI version gate, and the classification of known revert selectors (base/base
//! `crates/proof/submission/src/classifier.rs`).

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("abi.zig");
const dispute_game_factory = @import("dispute_game_factory.zig");

const Address = abi.Address;
const Hash = [32]u8;

pub const root_claim = abi.selector("rootClaim()");
pub const l2_sequence_number = abi.selector("l2SequenceNumber()");
pub const status = abi.selector("status()");
pub const tee_prover = abi.selector("teeProver()");
pub const zk_prover = abi.selector("zkProver()");
pub const parent_address = abi.selector("parentAddress()");
pub const version = abi.selector("version()");
pub const block_interval = abi.selector("BLOCK_INTERVAL()");
pub const intermediate_block_interval = abi.selector("INTERMEDIATE_BLOCK_INTERVAL()");
pub const intervals_for_starting_block = abi.selector("intervalsForStartingBlock(uint256)");
pub const game_type = abi.selector("gameType()");
pub const starting_block_number = abi.selector("startingBlockNumber()");
pub const l1_head = abi.selector("l1Head()");
pub const intermediate_output_roots = abi.selector("intermediateOutputRoots()");
pub const intermediate_output_root = abi.selector("intermediateOutputRoot(uint256)");
pub const countered_index = abi.selector("counteredByIntermediateRootIndexPlusOne()");
pub const nullify = abi.selector("nullify(bytes,uint256,bytes32)");
pub const challenge = abi.selector("challenge(bytes,uint256,bytes32)");
pub const verify_proposal_proof = abi.selector("verifyProposalProof(bytes)");
pub const resolve = abi.selector("resolve()");
pub const claim_credit = abi.selector("claimCredit()");
pub const game_over = abi.selector("gameOver()");
pub const resolved_at = abi.selector("resolvedAt()");
pub const bond_recipient = abi.selector("bondRecipient()");
pub const bond_unlocked = abi.selector("bondUnlocked()");
pub const bond_claimed = abi.selector("bondClaimed()");
pub const expected_resolution = abi.selector("expectedResolution()");
pub const proof_count = abi.selector("proofCount()");
pub const created_at = abi.selector("createdAt()");
pub const delayed_weth = abi.selector("DELAYED_WETH()");
pub const anchor_state_registry = abi.selector("anchorStateRegistry()");
/// `IVerifier.nullified()` on the TEE or ZK verifier.
pub const nullified = abi.selector("nullified()");

pub const error_l1_origin_too_old = abi.selector("L1OriginTooOld(uint256,uint256)");
pub const error_invalid_parent_game = abi.selector("InvalidParentGame()");
pub const error_invalid_signer = abi.selector("InvalidSigner(address)");
pub const error_already_proven = abi.selector("AlreadyProven(uint8)");
pub const error_invalid_proof = abi.selector("InvalidProof()");

/// Proof type byte that prefixes dispute proof bytes.
pub const proof_type_tee: u8 = 0;
pub const proof_type_zk: u8 = 1;

/// `AggregateVerifier.status()`.
pub const GameStatus = enum(u8) {
    in_progress = 0,
    challenger_wins = 1,
    defender_wins = 2,
};

/// Contract reverts the challenger reacts to (base/base `KnownRevert`).
pub const KnownRevert = enum {
    game_already_exists,
    proof_already_verified,
    l1_origin_too_old,
    invalid_parent_game,
    invalid_signer,
    invalid_proof,
};

/// The known revert a revert payload starts with, if any (the selector half of
/// `KnownRevert::from_tx_manager_error`; reason strings are a transport concern).
pub fn classify_revert(data: []const u8) ?KnownRevert {
    if (data.len < 4) return null;
    const head = data[0..4];
    const table = [_]struct { [4]u8, KnownRevert }{
        .{ dispute_game_factory.game_already_exists, .game_already_exists },
        .{ error_already_proven, .proof_already_verified },
        .{ error_l1_origin_too_old, .l1_origin_too_old },
        .{ error_invalid_parent_game, .invalid_parent_game },
        .{ error_invalid_signer, .invalid_signer },
        .{ error_invalid_proof, .invalid_proof },
    };
    for (table) |entry| {
        if (std.mem.eql(u8, head, &entry[0])) return entry[1];
    }
    assert(data.len >= 4);
    return null;
}

/// Calldata of a getter without arguments (or `resolve()` / `claimCredit()`).
pub fn encode_getter(out: []u8, function: [4]u8) abi.EncodeError![]u8 {
    assert(!std.mem.eql(u8, &function, &nullify));
    assert(!std.mem.eql(u8, &function, &challenge));
    return abi.encode_call(out, function, &.{});
}

pub fn encode_intervals_for_starting_block(out: []u8, starting_block: u64) abi.EncodeError![]u8 {
    return abi.encode_call(out, intervals_for_starting_block, &.{.{ .uint = starting_block }});
}

pub fn encode_intermediate_output_root(out: []u8, index: u64) abi.EncodeError![]u8 {
    return abi.encode_call(out, intermediate_output_root, &.{.{ .uint = index }});
}

pub fn decode_status(data: []const u8) abi.DecodeError!GameStatus {
    const decoder: abi.Decoder = .{ .data = data };
    const raw = try decoder.uint(u8, 0);
    return std.enums.fromInt(GameStatus, raw) orelse error.TypeCheck;
}

pub fn decode_hash(data: []const u8) abi.DecodeError!Hash {
    const decoder: abi.Decoder = .{ .data = data };
    return (try decoder.word(0)).*;
}

pub fn decode_address(data: []const u8) abi.DecodeError!Address {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.address(0);
}

pub fn decode_uint(comptime T: type, data: []const u8) abi.DecodeError!T {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.uint(T, 0);
}

pub fn decode_boolean(data: []const u8) abi.DecodeError!bool {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.boolean(0);
}

/// `version()` returns a `string`, encoded like `bytes`.
pub fn decode_version(data: []const u8) abi.DecodeError![]const u8 {
    const decoder: abi.Decoder = .{ .data = data };
    return decoder.bytes(0);
}

/// `intermediateOutputRoots()` returns `bytes`: concatenated 32-byte roots.
pub fn decode_intermediate_roots(data: []const u8, out: []Hash) abi.DecodeError![]Hash {
    const decoder: abi.Decoder = .{ .data = data };
    const raw = try decoder.bytes(0);
    if (raw.len % 32 != 0) return error.TypeCheck;
    const count = raw.len / 32;
    if (count > out.len) return error.Overrun;
    for (out[0..count], 0..) |*root, index| root.* = raw[index * 32 ..][0..32].*;
    assert(count * 32 == raw.len);
    return out[0..count];
}

pub const Intervals = struct { block: u64, intermediate_block: u64 };

/// Checks an interval pair as `read_intervals_for_starting_block` does: proposals span at
/// least two blocks and divide into whole intermediate checkpoints.
pub fn check_intervals(intervals: Intervals) error{InvalidInterval}!Intervals {
    if (intervals.block < 2) return error.InvalidInterval;
    if (intervals.intermediate_block == 0) return error.InvalidInterval;
    if (intervals.block % intervals.intermediate_block != 0) return error.InvalidInterval;
    assert(intervals.block >= intervals.intermediate_block);
    return intervals;
}

/// `intervalsForStartingBlock()` returns `(uint256 blockInterval, uint256 intermediate)`.
pub fn decode_intervals(data: []const u8) (abi.DecodeError || error{InvalidInterval})!Intervals {
    const decoder: abi.Decoder = .{ .data = data };
    return check_intervals(.{
        .block = try decoder.uint(u64, 0),
        .intermediate_block = try decoder.uint(u64, 1),
    });
}

/// Whether a verifier reporting `text` speaks the fork-aware interval ABI (0.3.0+). Anything
/// that is not exactly `MAJOR.MINOR.PATCH` (after stripping `-pre`/`+build`) counts as new.
pub fn supports_fork_aware_intervals(text: []const u8) bool {
    const core_end = std.mem.indexOfAny(u8, text, "-+") orelse text.len;
    var parts = std.mem.splitScalar(u8, text[0..core_end], '.');
    var numbers: [3]u64 = undefined;
    for (&numbers) |*number| {
        const part = parts.next() orelse return true;
        const trimmed = std.mem.trim(u8, part, " \t");
        number.* = std.fmt.parseInt(u64, trimmed, 10) catch return true;
    }
    if (parts.next() != null) return true;
    if (numbers[0] != 0) return true;
    return numbers[1] >= 3;
}

pub const DisputeKind = enum { nullify, challenge };

pub const DisputeCall = struct {
    kind: DisputeKind,
    /// Borrows the calldata.
    proof_bytes: []const u8,
    intermediate_root_index: u64,
    intermediate_root_to_prove: Hash,
};

/// `nullify(bytes,uint256,bytes32)` or `challenge(bytes,uint256,bytes32)` calldata.
pub fn encode_dispute(
    out: []u8,
    kind: DisputeKind,
    proof_bytes: []const u8,
    intermediate_root_index: u64,
    intermediate_root_to_prove: Hash,
) abi.EncodeError![]u8 {
    const function = switch (kind) {
        .nullify => nullify,
        .challenge => challenge,
    };
    const calldata = try abi.encode_call(out, function, &.{
        .{ .bytes = proof_bytes },
        .{ .uint = intermediate_root_index },
        .{ .word = intermediate_root_to_prove },
    });
    assert(calldata.len >= 4 + 4 * abi.word_bytes);
    return calldata;
}

/// Decodes dispute calldata; null for any other call or malformed arguments.
pub fn decode_dispute(calldata: []const u8) ?DisputeCall {
    if (calldata.len < 4) return null;
    const kind: DisputeKind = if (std.mem.eql(u8, calldata[0..4], &nullify))
        .nullify
    else if (std.mem.eql(u8, calldata[0..4], &challenge))
        .challenge
    else
        return null;
    const decoder: abi.Decoder = .{ .data = calldata[4..] };
    const call: DisputeCall = .{
        .kind = kind,
        .proof_bytes = decoder.bytes(0) catch return null,
        .intermediate_root_index = decoder.uint(u64, 1) catch return null,
        .intermediate_root_to_prove = (decoder.word(2) catch return null).*,
    };
    return call;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "aggregate verifier: fork-aware interval ABI gates on 0.3.0" {
    const legacy = [_][]const u8{
        "0.1.0",
        "0.1.99",
        "0.2.0",
        "0.2.99",
        "0.2.0-beta.1",
        "0.1.0-rc.1",
    };
    for (legacy) |text| try testing.expect(!supports_fork_aware_intervals(text));
    const fork_aware = [_][]const u8{
        "0.3.0", "0.10.0", "1.0.0", "0.3.0+deadbeef", "",     "unversioned",
        "3",     "0.1",    "0.1.x", "0.1.0.1",        "0.1.",
    };
    for (fork_aware) |text| try testing.expect(supports_fork_aware_intervals(text));
}

test "aggregate verifier: dispute calldata round trips both disputes" {
    var buffer: [256]u8 = undefined;
    const root: Hash = @splat(0x7a);
    const nullify_data = try encode_dispute(&buffer, .nullify, &.{ 1, 2, 3 }, 19, root);
    try testing.expectEqualSlices(u8, &nullify, nullify_data[0..4]);
    const nullify_call = decode_dispute(nullify_data).?;
    try testing.expectEqual(DisputeKind.nullify, nullify_call.kind);
    try testing.expectEqual(@as(u64, 19), nullify_call.intermediate_root_index);
    try testing.expectEqual(root, nullify_call.intermediate_root_to_prove);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, nullify_call.proof_bytes);
    var other: [256]u8 = undefined;
    const challenge_data = try encode_dispute(&other, .challenge, &.{}, 4, @splat(0));
    const challenge_call = decode_dispute(challenge_data).?;
    try testing.expectEqual(DisputeKind.challenge, challenge_call.kind);
    try testing.expectEqual(@as(usize, 0), challenge_call.proof_bytes.len);
    try testing.expect(!std.mem.eql(u8, &nullify, &challenge));
    var small: [8]u8 = undefined;
    const resolve_data = try encode_getter(&small, resolve);
    try testing.expectEqual(@as(usize, 4), resolve_data.len);
    try testing.expectEqual(@as(?DisputeCall, null), decode_dispute(resolve_data));
    try testing.expect(!std.mem.eql(u8, &resolve, &claim_credit));
}

test "aggregate verifier: getters decode strictly" {
    var data: [128]u8 = @splat(0);
    data[31] = 2;
    try testing.expectEqual(GameStatus.defender_wins, try decode_status(data[0..32]));
    data[31] = 3;
    try testing.expectError(error.TypeCheck, decode_status(data[0..32]));
    data[31] = 4;
    data[63] = 2;
    const intervals = try decode_intervals(data[0..64]);
    try testing.expectEqual(@as(u64, 2), intervals.intermediate_block);
    data[63] = 3;
    try testing.expectError(error.InvalidInterval, decode_intervals(data[0..64]));
    data[31] = 1;
    data[63] = 1;
    try testing.expectError(error.InvalidInterval, decode_intervals(data[0..64]));
    try testing.expectError(error.Overrun, decode_boolean(data[0..16]));
    var buffer: [64]u8 = undefined;
    const call = try encode_intermediate_output_root(&buffer, 5);
    try testing.expectEqual(@as(u8, 5), call[35]);
}

test "aggregate verifier: intermediate roots and known reverts" {
    var buffer: [256]u8 = undefined;
    var roots_bytes: [64]u8 = undefined;
    @memset(roots_bytes[0..32], 0x11);
    @memset(roots_bytes[32..], 0x22);
    // Return data has the same layout as calldata after the selector.
    const encoded = try abi.encode_call(&buffer, @splat(0), &.{.{ .bytes = &roots_bytes }});
    var out: [4]Hash = undefined;
    const roots = try decode_intermediate_roots(encoded[4..], &out);
    try testing.expectEqual(@as(usize, 2), roots.len);
    try testing.expectEqual(@as(Hash, @splat(0x22)), roots[1]);
    try testing.expectError(error.Overrun, decode_intermediate_roots(encoded[4..], out[0..1]));
    const odd = try abi.encode_call(&buffer, @splat(0), &.{.{ .bytes = roots_bytes[0..33] }});
    try testing.expectError(error.TypeCheck, decode_intermediate_roots(odd[4..], &out));
    try testing.expectEqual(KnownRevert.invalid_proof, classify_revert(&error_invalid_proof).?);
    const exists = dispute_game_factory.game_already_exists;
    try testing.expectEqual(KnownRevert.game_already_exists, classify_revert(&exists).?);
    try testing.expectEqual(@as(?KnownRevert, null), classify_revert(&.{ 0xde, 0xad, 0xbe, 0xef }));
    try testing.expectEqual(@as(?KnownRevert, null), classify_revert(&.{0x09}));
}

fn fuzz_dispute(_: void, smith: *std.testing.Smith) anyerror!void {
    var buffer: [512]u8 = undefined;
    var proof: [200]u8 = undefined;
    const proof_length = smith.slice(&proof);
    const kind: DisputeKind = if (smith.value(bool)) .nullify else .challenge;
    const index = smith.value(u64);
    const root: Hash = @splat(smith.value(u8));
    const calldata = try encode_dispute(&buffer, kind, proof[0..proof_length], index, root);
    const call = decode_dispute(calldata).?;
    try testing.expectEqual(kind, call.kind);
    try testing.expectEqual(index, call.intermediate_root_index);
    try testing.expectEqualSlices(u8, proof[0..proof_length], call.proof_bytes);
    // Truncations and arbitrary bytes decode or are rejected, never crash.
    const cut = smith.valueRangeAtMost(u32, 0, @intCast(calldata.len));
    if (decode_dispute(calldata[0..cut])) |again| {
        try testing.expect(again.proof_bytes.len <= proof_length);
    }
    var junk: [128]u8 = undefined;
    const junk_length = smith.slice(&junk);
    _ = decode_dispute(junk[0..junk_length]);
    var roots: [4]Hash = undefined;
    _ = decode_intermediate_roots(junk[0..junk_length], &roots) catch {};
    _ = classify_revert(junk[0..junk_length]);
}

test "aggregate verifier: fuzz dispute calldata and roots" {
    try fuzz.run({}, fuzz_dispute, .{ .iterations = 1024 });
}

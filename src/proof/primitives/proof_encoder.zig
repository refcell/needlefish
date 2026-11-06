//! Proof bytes for the `AggregateVerifier` contract (base/base
//! `crates/proof/primitives/src/proof_encoder.rs`).
//!
//! A TEE proof is the proof type byte, the L1 origin, and the enclave's ECDSA signature
//! with v as 27/28: 130 bytes for `initializeWithInitData`, 66 bytes (no L1 origin, which
//! the contract already stores) for `nullify`, `challenge` and `verifyProposalProof`. A ZK
//! dispute proof is the proof type byte and the raw proof.

const std = @import("std");
const assert = std.debug.assert;

pub const Hash = [32]u8;

/// ECDSA signature length in bytes (r: 32, s: 32, v: 1).
pub const ecdsa_signature_length = 65;
/// Matches `AggregateVerifier.ProofType.TEE`.
pub const proof_type_tee: u8 = 0;
/// Matches `AggregateVerifier.ProofType.ZK`.
pub const proof_type_zk: u8 = 1;

/// `proofType(1) + l1OriginHash(32) + l1OriginNumber(32) + signature(65)`.
pub const tee_proof_bytes = 1 + 32 + 32 + ecdsa_signature_length;
/// `proofType(1) + signature(65)`.
pub const tee_dispute_proof_bytes = 1 + ecdsa_signature_length;

const ecdsa_v_offset: u8 = 27;

comptime {
    assert(tee_proof_bytes == 130);
    assert(tee_dispute_proof_bytes == 66);
}

pub const Error = error{
    /// The signature is not 65 bytes.
    InvalidSignatureLength,
    /// The v byte is not 0, 1, 27, or 28 (base/base `InvalidVValue`).
    InvalidV,
};

/// 0/1 become 27/28; 27/28 stay.
pub fn normalize_v(v: u8) Error!u8 {
    const result: u8 = switch (v) {
        0, 1 => v + ecdsa_v_offset,
        27, 28 => v,
        else => return error.InvalidV,
    };
    assert(result == 27 or result == 28);
    return result;
}

/// The 130-byte TEE proof for `AggregateVerifier.initializeWithInitData()`.
pub fn encode_proof_bytes(
    out: *[tee_proof_bytes]u8,
    signature: []const u8,
    l1_origin_hash: Hash,
    l1_origin_number: u64,
) Error!void {
    if (signature.len != ecdsa_signature_length) return error.InvalidSignatureLength;
    const v = try normalize_v(signature[ecdsa_signature_length - 1]);
    out.* = @splat(0);
    out[0] = proof_type_tee;
    @memcpy(out[1..33], &l1_origin_hash);
    std.mem.writeInt(u256, out[33..65], l1_origin_number, .big);
    @memcpy(out[65..130], signature);
    out[129] = v;
    assert(out[0] == proof_type_tee);
    assert(std.mem.allEqual(u8, out[33..57], 0));
}

/// The 66-byte TEE proof for `nullify()`, `challenge()` and `verifyProposalProof()`.
pub fn encode_dispute_proof_bytes(
    out: *[tee_dispute_proof_bytes]u8,
    signature: []const u8,
) Error!void {
    if (signature.len != ecdsa_signature_length) return error.InvalidSignatureLength;
    const v = try normalize_v(signature[ecdsa_signature_length - 1]);
    out[0] = proof_type_tee;
    @memcpy(out[1..66], signature);
    out[65] = v;
    assert(out[0] == proof_type_tee);
    assert(std.mem.eql(u8, out[1..65], signature[0..64]));
}

/// `proofType(ZK) + rawZkProof` into `out`; returns the written prefix.
pub fn encode_zk_dispute_proof_bytes(out: []u8, proof: []const u8) error{NoSpaceLeft}![]u8 {
    if (out.len < proof.len + 1) return error.NoSpaceLeft;
    out[0] = proof_type_zk;
    @memcpy(out[1..][0..proof.len], proof);
    const written = out[0 .. proof.len + 1];
    assert(written[0] == proof_type_zk);
    assert(written.len == proof.len + 1);
    return written;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

fn test_signature(v: u8) [ecdsa_signature_length]u8 {
    var signature: [ecdsa_signature_length]u8 = @splat(0xab);
    signature[64] = v;
    return signature;
}

test "proof encoder: tee proof bytes format" {
    var out: [tee_proof_bytes]u8 = undefined;
    try encode_proof_bytes(&out, &test_signature(0), @splat(0xdd), 12345);
    try testing.expectEqual(proof_type_tee, out[0]);
    try testing.expectEqualSlices(u8, &@as(Hash, @splat(0xdd)), out[1..33]);
    var number: [32]u8 = @splat(0);
    std.mem.writeInt(u64, number[24..32], 12345, .big);
    try testing.expectEqualSlices(u8, &number, out[33..65]);
    try testing.expectEqualSlices(u8, test_signature(0)[0..64], out[65..129]);
}

test "proof encoder: v values are normalized" {
    const cases = [_][2]u8{ .{ 0, 27 }, .{ 1, 28 }, .{ 27, 27 }, .{ 28, 28 } };
    for (cases) |case| {
        var out: [tee_proof_bytes]u8 = undefined;
        try encode_proof_bytes(&out, &test_signature(case[0]), @splat(0), 0);
        try testing.expectEqual(case[1], out[129]);
        var dispute: [tee_dispute_proof_bytes]u8 = undefined;
        try encode_dispute_proof_bytes(&dispute, &test_signature(case[0]));
        try testing.expectEqual(case[1], dispute[65]);
        try testing.expectEqual(proof_type_tee, dispute[0]);
    }
}

test "proof encoder: errors" {
    var out: [tee_proof_bytes]u8 = undefined;
    var dispute: [tee_dispute_proof_bytes]u8 = undefined;
    const invalid_v = test_signature(5);
    try testing.expectError(error.InvalidV, encode_proof_bytes(&out, &invalid_v, @splat(0), 0));
    try testing.expectError(error.InvalidV, encode_dispute_proof_bytes(&dispute, &invalid_v));
    const short: [32]u8 = @splat(0);
    const long: [70]u8 = @splat(0);
    for ([_][]const u8{ &short, &long }) |signature| {
        const result = encode_proof_bytes(&out, signature, @splat(0), 0);
        try testing.expectError(error.InvalidSignatureLength, result);
        const dispute_result = encode_dispute_proof_bytes(&dispute, signature);
        try testing.expectError(error.InvalidSignatureLength, dispute_result);
    }
}

test "proof encoder: zk dispute proof prefixes the zk type" {
    var out: [8]u8 = undefined;
    const written = try encode_zk_dispute_proof_bytes(&out, &.{ 0xab, 0xcd });
    try testing.expectEqualSlices(u8, &.{ proof_type_zk, 0xab, 0xcd }, written);
    try testing.expectError(error.NoSpaceLeft, encode_zk_dispute_proof_bytes(out[0..2], "ab"));
}

fn fuzz_encode(_: void, smith: *std.testing.Smith) anyerror!void {
    var signature: [80]u8 = undefined;
    const len = smith.slice(&signature);
    const origin_number = smith.value(u64);
    var out: [tee_proof_bytes]u8 = undefined;
    encode_proof_bytes(&out, signature[0..len], @splat(0x5a), origin_number) catch |err| {
        const v_ok = len == ecdsa_signature_length and
            (normalize_v(signature[64]) catch null) != null;
        try testing.expect(!v_ok);
        try testing.expect(err == error.InvalidV or len != ecdsa_signature_length);
        return;
    };
    try testing.expectEqual(@as(usize, ecdsa_signature_length), len);
    try testing.expectEqual(origin_number, std.mem.readInt(u64, out[57..65], .big));
    try testing.expectEqualSlices(u8, signature[0..64], out[65..129]);
    try testing.expect(out[129] == 27 or out[129] == 28);
}

test "proof encoder: seeded fuzz" {
    try fuzz.run({}, fuzz_encode, .{ .iterations = 512 });
}

//! Offline check of a TEE proof receipt, the host-side analog of base/base `snark-e2e`'s
//! receipt verification: rebuild the journal `AggregateVerifier` reconstructs from the game
//! and recover the address that signed it. The caller compares that address with the
//! signer registered in `TEEProverRegistry`.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../prover_service/protocol.zig");
const primitives = @import("../primitives/root.zig");
const crypto = @import("enclave/crypto.zig");

const Address = [20]u8;
const Hash = [32]u8;

pub const Error = error{
    /// The proposal is not for the expected claim (block, output root, or previous root).
    ClaimMismatch,
    /// No roots, too many, or the last root is not the claimed output root.
    InvalidIntermediateRoots,
    /// The proposal's signature is not a 65-byte recoverable signature.
    InvalidSignature,
    /// The recovered address is not the result's `tee_signer`.
    SignerMismatch,
};

/// What the game commits to besides the proposal itself.
pub const Expected = struct {
    proposer: Address,
    starting_l2_block: u64,
    prev_output_root: Hash,
    claimed_output_root: Hash,
    claimed_l2_block_number: u64,
    /// keccak256(PCR0); zero for a local-mode enclave.
    tee_image_hash: Hash,
};

/// Returns the signer of `result` once it proves `expected`; it equals `result.tee_signer`.
pub fn recover_signer(
    result: *const protocol.TeeProofResult,
    expected: *const Expected,
) Error!Address {
    const proposal = &result.aggregate_proposal;
    if (proposal.l2_block_number != expected.claimed_l2_block_number) return error.ClaimMismatch;
    if (expected.starting_l2_block >= expected.claimed_l2_block_number) {
        return error.ClaimMismatch;
    }
    if (!std.mem.eql(u8, &proposal.output_root, &expected.claimed_output_root)) {
        return error.ClaimMismatch;
    }
    if (!std.mem.eql(u8, &proposal.prev_output_root, &expected.prev_output_root)) {
        return error.ClaimMismatch;
    }
    const roots = result.intermediate_roots;
    if (roots.len == 0 or roots.len > primitives.proposal.intermediate_roots_max) {
        return error.InvalidIntermediateRoots;
    }
    if (!std.mem.eql(u8, &roots[roots.len - 1], &proposal.output_root)) {
        return error.InvalidIntermediateRoots;
    }
    if (proposal.signature.len != crypto.signature_length) return error.InvalidSignature;
    const journal: primitives.ProofJournal = .{
        .proposer = expected.proposer,
        .l1_origin_hash = proposal.l1_origin_hash,
        .prev_output_root = proposal.prev_output_root,
        .starting_l2_block = expected.starting_l2_block,
        .output_root = proposal.output_root,
        .ending_l2_block = proposal.l2_block_number,
        .intermediate_roots = roots,
        .config_hash = proposal.config_hash,
        .tee_image_hash = expected.tee_image_hash,
        .schedule_id = proposal.schedule_id,
    };
    var buffer: [primitives.proposal.proof_journal_length_max]u8 = undefined;
    const encoded = journal.encode(&buffer);
    assert(encoded.len == journal.encoded_length());
    const signature = proposal.signature[0..crypto.signature_length];
    const signer = crypto.recover_address(encoded, signature) orelse return error.InvalidSignature;
    if (!std.mem.eql(u8, &signer, &result.tee_signer)) return error.SignerMismatch;
    return signer;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

const Fixture = struct {
    roots: [2]Hash,
    signature: crypto.Signature,
    result: protocol.TeeProofResult,
    expected: Expected,

    fn init(fixture: *Fixture, signer: *const crypto.Signer) void {
        fixture.roots = .{ @splat(0x0a), @splat(0x0b) };
        fixture.expected = .{
            .proposer = @splat(0x77),
            .starting_l2_block = 10,
            .prev_output_root = @splat(0x01),
            .claimed_output_root = fixture.roots[1],
            .claimed_l2_block_number = 14,
            .tee_image_hash = @splat(0),
        };
        fixture.result = .{
            .aggregate_proposal = .{
                .output_root = fixture.roots[1],
                .signature = &fixture.signature,
                .l1_origin_hash = @splat(0x03),
                .l1_origin_number = 9,
                .l2_block_number = 14,
                .prev_output_root = @splat(0x01),
                .config_hash = @splat(0x04),
                .schedule_id = @splat(0x05),
            },
            .intermediate_roots = &fixture.roots,
            .tee_kind = .aws_nitro,
            .tee_signer = signer.address,
        };
        const proposal = &fixture.result.aggregate_proposal;
        const journal: primitives.ProofJournal = .{
            .proposer = fixture.expected.proposer,
            .l1_origin_hash = proposal.l1_origin_hash,
            .prev_output_root = proposal.prev_output_root,
            .starting_l2_block = 10,
            .output_root = proposal.output_root,
            .ending_l2_block = 14,
            .intermediate_roots = &fixture.roots,
            .config_hash = proposal.config_hash,
            .tee_image_hash = @splat(0),
            .schedule_id = proposal.schedule_id,
        };
        var buffer: [primitives.proposal.proof_journal_length_max]u8 = undefined;
        fixture.signature = signer.sign(journal.encode(&buffer));
    }
};

test "tee verify: a signed receipt recovers its signer" {
    const signer = try crypto.Signer.from_bytes(&@as([32]u8, @splat(0x21)));
    var fixture: Fixture = undefined;
    fixture.init(&signer);
    try testing.expectEqual(signer.address, try recover_signer(&fixture.result, &fixture.expected));
    // Any journal field the signature does not cover changes the recovered address.
    var wrong = fixture.expected;
    wrong.proposer[0] ^= 1;
    try testing.expectError(error.SignerMismatch, recover_signer(&fixture.result, &wrong));
    wrong = fixture.expected;
    wrong.tee_image_hash[0] ^= 1;
    try testing.expectError(error.SignerMismatch, recover_signer(&fixture.result, &wrong));
    wrong = fixture.expected;
    wrong.claimed_output_root[0] ^= 1;
    try testing.expectError(error.ClaimMismatch, recover_signer(&fixture.result, &wrong));
    wrong = fixture.expected;
    wrong.starting_l2_block = 14;
    try testing.expectError(error.ClaimMismatch, recover_signer(&fixture.result, &wrong));
    var result = fixture.result;
    result.intermediate_roots = fixture.roots[0..1];
    const short = recover_signer(&result, &fixture.expected);
    try testing.expectError(error.InvalidIntermediateRoots, short);
    result = fixture.result;
    result.aggregate_proposal.signature = fixture.signature[0..64];
    try testing.expectError(error.InvalidSignature, recover_signer(&result, &fixture.expected));
}

test "tee verify: fuzz tampered receipts never verify" {
    const Context = struct {
        signer: crypto.Signer,
        fn run(context: *const @This(), smith: *std.testing.Smith) anyerror!void {
            var fixture: Fixture = undefined;
            fixture.init(&context.signer);
            var signature = fixture.signature;
            const index = smith.index(crypto.signature_length);
            signature[index] ^= smith.valueRangeAtMost(u8, 1, 255);
            fixture.result.aggregate_proposal.signature = &signature;
            const recovered = recover_signer(&fixture.result, &fixture.expected);
            try testing.expect(std.meta.isError(recovered));
        }
    };
    const key: [32]u8 = @splat(0x33);
    const context: Context = .{ .signer = try crypto.Signer.from_bytes(&key) };
    try fuzz.run(&context, Context.run, .{ .iterations = 64 });
}

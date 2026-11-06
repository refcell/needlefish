//! The TEE proof journal and the proposal proof data (base/base
//! `crates/proof/primitives/src/proposal.rs`).
//!
//! The journal is what the enclave signs and what `AggregateVerifier` rebuilds on chain:
//!
//! ```text
//! prover(20) || l1OriginHash(32) || prevOutputRoot(32) || startingL2Block(8)
//!   || outputRoot(32) || endingL2Block(8) || intermediateRoots(32*N) || configHash(32)
//!   || imageHash(32) || scheduleId(32)
//! ```
//!
//! The proposal type itself is the prover service's (`prover_service/protocol.zig`).

const std = @import("std");
const assert = std.debug.assert;

const proof_encoder = @import("proof_encoder.zig");
const service_protocol = @import("../prover_service/protocol.zig");

pub const Hash = [32]u8;
pub const Address = [20]u8;
pub const Proposal = service_protocol.Proposal;

/// address(20) + 6 x bytes32(32) + 2 x uint64(8).
pub const proof_journal_base_length = 228;
/// The dispute game factory's bound on intermediate roots.
pub const intermediate_roots_max = service_protocol.intermediate_root_count_max;
/// Largest encoded journal.
pub const proof_journal_length_max = proof_journal_base_length + 32 * intermediate_roots_max;

comptime {
    assert(proof_journal_base_length == 20 + 6 * 32 + 2 * 8);
}

pub const ProofJournal = struct {
    proposer: Address,
    l1_origin_hash: Hash,
    prev_output_root: Hash,
    starting_l2_block: u64,
    output_root: Hash,
    ending_l2_block: u64,
    intermediate_roots: []const Hash,
    config_hash: Hash,
    tee_image_hash: Hash,
    schedule_id: Hash,

    pub fn encoded_length(journal: *const ProofJournal) u32 {
        assert(journal.intermediate_roots.len <= intermediate_roots_max);
        const roots: u32 = @intCast(journal.intermediate_roots.len);
        return proof_journal_base_length + 32 * roots;
    }

    /// The ABI-packed journal into `out` (at least `encoded_length` bytes).
    pub fn encode(journal: *const ProofJournal, out: []u8) []u8 {
        const length = journal.encoded_length();
        assert(out.len >= length);
        var offset: usize = 0;
        put(out, &offset, &journal.proposer);
        put(out, &offset, &journal.l1_origin_hash);
        put(out, &offset, &journal.prev_output_root);
        put_u64(out, &offset, journal.starting_l2_block);
        put(out, &offset, &journal.output_root);
        put_u64(out, &offset, journal.ending_l2_block);
        for (journal.intermediate_roots) |*root| put(out, &offset, root);
        put(out, &offset, &journal.config_hash);
        put(out, &offset, &journal.tee_image_hash);
        put(out, &offset, &journal.schedule_id);
        assert(offset == length);
        return out[0..length];
    }
};

/// The 130-byte proof data for `AggregateVerifier.initialize()`:
/// `proofType(1) + l1OriginHash(32) + l1OriginNumber(32) + signature(65)`.
pub fn build_proof_data(
    proposal: *const Proposal,
    out: *[proof_encoder.tee_proof_bytes]u8,
) proof_encoder.Error!void {
    try proof_encoder.encode_proof_bytes(
        out,
        proposal.signature,
        proposal.l1_origin_hash,
        proposal.l1_origin_number,
    );
    assert(out[0] == proof_encoder.proof_type_tee);
}

fn put(out: []u8, offset: *usize, bytes: []const u8) void {
    assert(offset.* + bytes.len <= out.len);
    @memcpy(out[offset.*..][0..bytes.len], bytes);
    offset.* += bytes.len;
}

fn put_u64(out: []u8, offset: *usize, value: u64) void {
    assert(offset.* + 8 <= out.len);
    std.mem.writeInt(u64, out[offset.*..][0..8], value, .big);
    offset.* += 8;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");
const primitives = @import("../../common/primitives/root.zig");

const proof_data_v_index = 1 + 32 + 32 + proof_encoder.ecdsa_signature_length - 1;

const anvil_address = primitives.Address.comptime_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

pub fn test_journal() ProofJournal {
    return .{
        .proposer = anvil_address.bytes,
        .l1_origin_hash = @splat(0x22),
        .prev_output_root = @splat(0x33),
        .starting_l2_block = 999,
        .output_root = @splat(0x44),
        .ending_l2_block = 1000,
        .intermediate_roots = &.{},
        .config_hash = @splat(0x11),
        .tee_image_hash = @splat(0x55),
        .schedule_id = @splat(0x66),
    };
}

test "proposal: journal encode length" {
    var out: [proof_journal_base_length]u8 = undefined;
    const journal = test_journal();
    try testing.expectEqual(@as(usize, 228), journal.encode(&out).len);
}

test "proposal: journal encode components" {
    const journal = test_journal();
    var out: [proof_journal_base_length]u8 = undefined;
    const data = journal.encode(&out);
    try testing.expectEqualSlices(u8, &journal.proposer, data[0..20]);
    try testing.expectEqualSlices(u8, &journal.l1_origin_hash, data[20..52]);
    try testing.expectEqualSlices(u8, &journal.prev_output_root, data[52..84]);
    try testing.expectEqual(@as(u64, 999), std.mem.readInt(u64, data[84..92], .big));
    try testing.expectEqualSlices(u8, &journal.output_root, data[92..124]);
    try testing.expectEqual(@as(u64, 1000), std.mem.readInt(u64, data[124..132], .big));
    try testing.expectEqualSlices(u8, &journal.config_hash, data[132..164]);
    try testing.expectEqualSlices(u8, &journal.tee_image_hash, data[164..196]);
    try testing.expectEqualSlices(u8, &journal.schedule_id, data[196..228]);
}

test "proposal: journal encode with intermediate roots" {
    const roots = [_]Hash{ @splat(0xaa), @splat(0xbb) };
    var journal = test_journal();
    journal.intermediate_roots = &roots;
    var out: [proof_journal_base_length + 64]u8 = undefined;
    const data = journal.encode(&out);
    try testing.expectEqual(@as(usize, proof_journal_base_length + 64), data.len);
    const offset = 20 + 32 + 32 + 8 + 32 + 8;
    try testing.expectEqualSlices(u8, &roots[0], data[offset..][0..32]);
    try testing.expectEqualSlices(u8, &roots[1], data[offset + 32 ..][0..32]);
    try testing.expectEqualSlices(u8, &journal.config_hash, data[offset + 64 ..][0..32]);
}

fn sample_proposal(signature: []const u8) Proposal {
    return .{
        .output_root = hash_low(1),
        .signature = signature,
        .l1_origin_hash = hash_low(2),
        .l1_origin_number = 100,
        .l2_block_number = 12345,
        .prev_output_root = hash_low(3),
        .config_hash = hash_low(4),
        .schedule_id = hash_low(5),
    };
}

fn hash_low(byte: u8) Hash {
    var hash: Hash = @splat(0);
    hash[31] = byte;
    return hash;
}

test "proposal: build proof data normalizes v" {
    const cases = [_]struct { u8, ?u8 }{
        .{ 0, 27 }, .{ 1, 28 }, .{ 27, 27 }, .{ 28, 28 }, .{ 5, null },
    };
    for (cases) |case| {
        var signature: [proof_encoder.ecdsa_signature_length]u8 = @splat(0xab);
        signature[64] = case[0];
        const proposal = sample_proposal(&signature);
        var out: [proof_encoder.tee_proof_bytes]u8 = undefined;
        if (case[1]) |expected| {
            try build_proof_data(&proposal, &out);
            try testing.expectEqual(expected, out[proof_data_v_index]);
            try testing.expectEqualSlices(u8, &proposal.l1_origin_hash, out[1..33]);
        } else {
            try testing.expectError(error.InvalidV, build_proof_data(&proposal, &out));
        }
    }
}

fn fuzz_journal(_: void, smith: *std.testing.Smith) anyerror!void {
    var roots: [8]Hash = undefined;
    const count = smith.valueRangeAtMost(u8, 0, roots.len);
    for (roots[0..count], 0..) |*root, index| root.* = @splat(@intCast(index + 1));
    var journal = test_journal();
    journal.starting_l2_block = smith.value(u64);
    journal.ending_l2_block = smith.value(u64);
    journal.intermediate_roots = roots[0..count];
    var out: [proof_journal_base_length + 8 * 32]u8 = undefined;
    const data = journal.encode(&out);
    try testing.expectEqual(proof_journal_base_length + 32 * @as(usize, count), data.len);
    try testing.expectEqual(journal.starting_l2_block, std.mem.readInt(u64, data[84..92], .big));
    try testing.expectEqual(journal.ending_l2_block, std.mem.readInt(u64, data[124..132], .big));
    try testing.expectEqualSlices(u8, &journal.schedule_id, data[data.len - 32 ..]);
}

test "proposal: seeded fuzz journal encoding" {
    try fuzz.run({}, fuzz_journal, .{ .iterations = 256 });
}

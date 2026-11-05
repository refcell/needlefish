//! Output root validation (base/base `crates/proof/challenge/src/validator.rs`): recompute
//! the output root of each checkpoint block from its L2 header and compare it with the
//! game's claim. The first mismatch is the index the dispute targets.
//!
//! base/base proves the `L2ToL1MessagePasser` storage root with an `eth_getProof` account
//! proof; since Isthmus the header's withdrawals root is that storage root, so the root is
//! computed from the raw header alone (`host/native.zig` `output_root_of`), and the block
//! hash is the keccak of the bytes the root commits to (no separate hash check needed).

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const native = @import("../host/native.zig");
const crypto = @import("../../common/crypto/root.zig");

const Hash = chain.Hash;

/// Largest raw L2 header the validator reads.
pub const header_bytes_max = 2048;

pub const Error = chain.HeaderError || error{
    InvalidHeader,
    InvalidBlockRange,
    CheckpointCountMismatch,
    ArithmeticOverflow,
};

pub const ValidationResult = struct {
    is_valid: bool,
    /// The recomputed root of the first mismatching checkpoint, else the claim.
    expected_root: Hash,
    invalid_intermediate_index: ?u64,
};

pub const IntermediateParams = struct {
    starting_block_number: u64,
    l2_block_number: u64,
    intermediate_block_interval: u64,
    claimed_root: Hash,
    intermediate_roots: []const Hash,
};

pub const OutputWithHash = struct { block_hash: Hash, output_root: Hash };

/// The block hash and output root of an L2 block.
pub fn compute_output_root_with_hash(view: chain.ChainView, block: u64) Error!OutputWithHash {
    var buffer: [header_bytes_max]u8 = undefined;
    const raw = try view.l2_header(block, &buffer);
    const output = native.output_of(raw) catch return error.InvalidHeader;
    const encoded = output.encode();
    const result: OutputWithHash = .{
        .block_hash = output.block_hash,
        .output_root = crypto.keccak256(&encoded),
    };
    assert(raw.len > 0);
    assert(!std.mem.eql(u8, &result.block_hash, &result.output_root));
    return result;
}

pub fn compute_output_root(view: chain.ChainView, block: u64) Error!Hash {
    const result = try compute_output_root_with_hash(view, block);
    return result.output_root;
}

/// Checks one claimed root at one block.
pub fn validate_claimed_root_at_block(
    view: chain.ChainView,
    block: u64,
    claimed_root: Hash,
) Error!ValidationResult {
    const expected = try compute_output_root(view, block);
    const is_valid = std.mem.eql(u8, &expected, &claimed_root);
    return .{ .is_valid = is_valid, .expected_root = expected, .invalid_intermediate_index = null };
}

/// Checks every intermediate root of a game, in order, stopping at the first mismatch.
/// The count must be exactly `(end - start) / interval`; the last root is the claim.
pub fn validate_intermediate_roots(
    view: chain.ChainView,
    params: IntermediateParams,
) Error!ValidationResult {
    assert(params.intermediate_block_interval > 0);
    if (params.starting_block_number >= params.l2_block_number) return error.InvalidBlockRange;
    const span = params.l2_block_number - params.starting_block_number;
    const expected_count = span / params.intermediate_block_interval;
    if (params.intermediate_roots.len != expected_count) return error.CheckpointCountMismatch;
    var block = params.starting_block_number;
    for (params.intermediate_roots, 0..) |claimed, index| {
        block = std.math.add(u64, block, params.intermediate_block_interval) catch
            return error.ArithmeticOverflow;
        const expected = try compute_output_root(view, block);
        if (!std.mem.eql(u8, &expected, &claimed)) {
            return .{
                .is_valid = false,
                .expected_root = expected,
                .invalid_intermediate_index = index,
            };
        }
    }
    assert(block <= params.l2_block_number);
    return .{
        .is_valid = true,
        .expected_root = params.claimed_root,
        .invalid_intermediate_index = null,
    };
}

test {
    _ = @import("validator_test.zig");
}

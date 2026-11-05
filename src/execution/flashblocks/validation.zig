//! Flashblock ordering and canonical reconciliation rules. Mirrors base/base
//! `crates/execution/flashblocks/src/validation.rs`:
//!
//! - `validate_sequence` classifies an incoming flashblock against the latest pending one
//!   (next in sequence, first of the next block, duplicate, gap, bad new-block index, or a
//!   broken `prev_flashblock_id` link).
//! - `detect_reorg` compares the transaction hashes tracked for a block with the canonical
//!   block's.
//! - `reconcile` picks what to do with the pending blocks when a canonical block lands.
//!
//! needlefish adds `validate_shape` (base present exactly at index 0, base block number
//! equals the metadata block number, bounded extra data) and `validate_continuity`
//! (payload id stable within a block, the next block's parent hash equals the previous
//! block's latest hash); base/base enforces the shape inside `BlockAssembler` and does not
//! check the other two.

const std = @import("std");
const assert = std.debug.assert;

const flashblocks = @import("../../common/flashblocks/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const B256 = primitives.B256;
const FlashblockId = flashblocks.FlashblockId;
const Flashblock = flashblocks.Flashblock;

/// Header extra data is at most 32 bytes (yellow paper; OP Holocene/Jovian use 9/17).
pub const extra_data_size_max = 32;

pub const SequenceResult = union(enum) {
    next_in_sequence,
    first_of_next_block,
    duplicate,
    non_sequential_gap: struct { expected: u64, actual: u64 },
    invalid_new_block_index: struct { block_number: u64, index: u64 },
    non_sequential_predecessor: struct { expected: FlashblockId, actual: FlashblockId },
};

/// base/base `FlashblockSequenceValidator::validate`, rule for rule and in the same order.
pub fn validate_sequence(
    latest_block_number: u64,
    latest_index: u64,
    incoming_block_number: u64,
    incoming_index: u64,
    incoming_prev: FlashblockId,
) SequenceResult {
    const latest: FlashblockId = .{ .block_number = latest_block_number, .index = latest_index };
    if (incoming_block_number == latest_block_number and incoming_index == latest_index) {
        return .duplicate;
    }
    const prev_set = incoming_prev.block_number != 0 or incoming_prev.index != 0;
    if (prev_set and !std.meta.eql(incoming_prev, latest)) {
        return .{ .non_sequential_predecessor = .{ .expected = latest, .actual = incoming_prev } };
    }
    const next_index = latest_index +| 1;
    if (incoming_block_number == latest_block_number and incoming_index == next_index) {
        return .next_in_sequence;
    }
    // Rust `latest_block_number + 1` would overflow-panic at u64 max; saturate instead.
    if (incoming_block_number == latest_block_number +| 1 and incoming_index == 0 and
        latest_block_number != std.math.maxInt(u64))
    {
        return .first_of_next_block;
    }
    if (incoming_block_number == latest_block_number) {
        assert(incoming_index != next_index);
        return .{ .non_sequential_gap = .{ .expected = next_index, .actual = incoming_index } };
    }
    return .{ .invalid_new_block_index = .{
        .block_number = incoming_block_number,
        .index = incoming_index,
    } };
}

pub const ShapeError = error{
    /// Index 0 without a base (base/base `ProtocolError::MissingBase`).
    MissingBase,
    /// A base on a non-zero index.
    UnexpectedBase,
    /// `base.block_number` differs from `metadata.block_number`.
    BlockNumberMismatch,
    /// Block 0 cannot be a flashblock (base/base `ProtocolError::GenesisFlashblock`).
    GenesisFlashblock,
    ExtraDataTooLong,
};

/// Structural checks that need no pending state.
pub fn validate_shape(flashblock: *const Flashblock) ShapeError!void {
    const block_number = flashblock.metadata.block_number;
    if (block_number == 0) return error.GenesisFlashblock;
    if (flashblock.index == 0) {
        const base = flashblock.base orelse return error.MissingBase;
        if (base.block_number != block_number) return error.BlockNumberMismatch;
        if (base.extra_data.len > extra_data_size_max) return error.ExtraDataTooLong;
    } else {
        if (flashblock.base != null) return error.UnexpectedBase;
    }
    assert(block_number > 0);
    assert((flashblock.index == 0) == (flashblock.base != null));
}

pub const ContinuityError = error{
    /// A next-in-sequence flashblock carries another payload id than its block's first.
    PayloadIdMismatch,
    /// The first flashblock of the next block does not build on the previous block's
    /// latest hash.
    ParentHashMismatch,
};

/// Checks a flashblock that `validate_sequence` accepted against the latest pending block.
/// `latest_block_hash` is the previous block's latest delta hash; a zero hash (a builder
/// that leaves it unset) skips the parent check.
pub fn validate_continuity(
    result: SequenceResult,
    flashblock: *const Flashblock,
    latest_payload_id: [8]u8,
    latest_block_hash: B256,
) ContinuityError!void {
    switch (result) {
        .next_in_sequence => {
            assert(flashblock.base == null);
            const same = std.mem.eql(u8, &flashblock.payload_id, &latest_payload_id);
            if (!same) return error.PayloadIdMismatch;
        },
        .first_of_next_block => {
            const base = flashblock.base.?;
            if (latest_block_hash.is_zero()) return;
            if (!base.parent_hash.eql(latest_block_hash)) return error.ParentHashMismatch;
        },
        else => unreachable, // Callers only check accepted flashblocks.
    }
}

pub const ReorgResult = union(enum) {
    no_reorg,
    reorg_detected: struct { tracked_count: u64, canonical_count: u64 },

    pub fn is_reorg(result: ReorgResult) bool {
        return result == .reorg_detected;
    }
};

/// base/base `ReorgDetector::detect`: nothing tracked means no reorg; otherwise the
/// tracked and canonical hash lists must be identical, in order.
pub fn detect_reorg(tracked: []const B256, canonical: []const B256) ReorgResult {
    if (tracked.len == 0) return .no_reorg;
    const same = tracked.len == canonical.len and for (tracked, canonical) |a, b| {
        if (!a.eql(b)) break false;
    } else true;
    if (same) return .no_reorg;
    assert(tracked.len > 0);
    return .{ .reorg_detected = .{
        .tracked_count = tracked.len,
        .canonical_count = canonical.len,
    } };
}

pub const Strategy = union(enum) {
    catch_up,
    handle_reorg,
    depth_limit_exceeded: struct { depth: u64, max_depth: u64 },
    @"continue",
    no_pending_state,
};

/// base/base `CanonicalBlockReconciler::reconcile`.
pub fn reconcile(
    pending_earliest_block: ?u64,
    pending_latest_block: ?u64,
    canonical_block_number: u64,
    max_depth: u64,
    reorg_detected: bool,
) Strategy {
    const earliest = pending_earliest_block orelse return .no_pending_state;
    const latest = pending_latest_block orelse return .no_pending_state;
    assert(earliest <= latest);
    if (latest <= canonical_block_number) return .catch_up;
    if (reorg_detected) return .handle_reorg;
    const depth = canonical_block_number -| earliest;
    if (depth > max_depth) {
        return .{ .depth_limit_exceeded = .{ .depth = depth, .max_depth = max_depth } };
    }
    assert(latest > canonical_block_number);
    return .@"continue";
}

test {
    _ = @import("validation_test.zig");
}

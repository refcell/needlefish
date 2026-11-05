//! Per-send blob storage for the transaction-manager driver: the blobs of each pending
//! blob send plus their KZG commitments and proofs, computed once at submit (as base/base
//! tx-manager builds the sidecar once and re-signs only the fees on every bump).
//!
//! Sidecar version 0 (EIP-4844) carries one blob proof per blob; version 1 (EIP-7594,
//! required by L1 mempools since Osaka) carries 128 cell proofs per blob. Everything is
//! allocated at init for `sends_max` sends of up to `blobs_per_send_max` blobs.

const std = @import("std");
const assert = std.debug.assert;

const kzg = @import("../../batcher/blobs/kzg.zig");
const blob_tx = @import("../../batcher/txdata/blob.zig");

pub const Blob = kzg.Blob;
pub const blobs_per_send_limit = blob_tx.blobs_per_tx_max;

/// Upper bound of one blob's share of the network encoding (blob, commitment, proofs).
pub fn network_bytes_per_blob(version: u1) usize {
    const proofs: usize = if (version == 1) kzg.cell_proofs_per_blob else 1;
    return @sizeOf(Blob) + 8 + (1 + 48) * (1 + proofs);
}

pub const StoreError = kzg.Error || kzg.CellError || error{TooManyBlobs};

pub const BlobStore = struct {
    sends_max: u32,
    blobs_per_send_max: u8,
    version: u1,
    blobs: []Blob,
    commitments: []kzg.Commitment,
    proofs: []kzg.Proof,
    counts: []u8,
    prover: kzg.Prover,
    cell_prover: ?kzg.CellProver,
    /// Scratch for `sidecar` and `versioned_hashes` (single-threaded use).
    pointers: [blobs_per_send_limit]*const Blob = undefined,
    hashes: [blobs_per_send_limit][32]u8 = undefined,

    pub fn init(
        allocator: std.mem.Allocator,
        sends_max: u32,
        blobs_per_send_max: u8,
        version: u1,
    ) !BlobStore {
        assert(sends_max > 0);
        assert(blobs_per_send_max > 0 and blobs_per_send_max <= blobs_per_send_limit);
        const blob_count = @as(usize, sends_max) * blobs_per_send_max;
        const blobs = try allocator.alloc(Blob, blob_count);
        errdefer allocator.free(blobs);
        const commitments = try allocator.alloc(kzg.Commitment, blob_count);
        errdefer allocator.free(commitments);
        const proofs = try allocator.alloc(kzg.Proof, blob_count * proofs_per_blob(version));
        errdefer allocator.free(proofs);
        const counts = try allocator.alloc(u8, sends_max);
        errdefer allocator.free(counts);
        @memset(counts, 0);
        var prover = try kzg.Prover.init(allocator);
        errdefer prover.deinit(allocator);
        const cell_prover = if (version == 1) try kzg.CellProver.init(allocator) else null;
        return .{
            .sends_max = sends_max,
            .blobs_per_send_max = blobs_per_send_max,
            .version = version,
            .blobs = blobs,
            .commitments = commitments,
            .proofs = proofs,
            .counts = counts,
            .prover = prover,
            .cell_prover = cell_prover,
        };
    }

    pub fn deinit(slots: *BlobStore, allocator: std.mem.Allocator) void {
        if (slots.cell_prover) |*cell_prover| cell_prover.deinit(allocator);
        slots.prover.deinit(allocator);
        allocator.free(slots.counts);
        allocator.free(slots.proofs);
        allocator.free(slots.commitments);
        allocator.free(slots.blobs);
        slots.* = undefined;
    }

    fn proofs_per_blob(version: u1) usize {
        return if (version == 1) kzg.cell_proofs_per_blob else 1;
    }

    /// Copies `blobs` into `slot` and computes their commitments and proofs.
    pub fn store(slots: *BlobStore, slot: u32, blobs: []const *const Blob) StoreError!void {
        assert(slot < slots.sends_max);
        assert(blobs.len > 0);
        if (blobs.len > slots.blobs_per_send_max) return error.TooManyBlobs;
        const first = @as(usize, slot) * slots.blobs_per_send_max;
        const per_blob = proofs_per_blob(slots.version);
        slots.counts[slot] = 0;
        for (blobs, 0..) |blob, offset| {
            const index = first + offset;
            slots.blobs[index] = blob.*;
            const stored = &slots.blobs[index];
            slots.commitments[index] = try slots.prover.commitment(stored);
            const proofs = slots.proofs[index * per_blob ..][0..per_blob];
            if (slots.cell_prover) |*cell_prover| {
                try cell_prover.cell_proofs(stored, proofs[0..kzg.cell_proofs_per_blob]);
            } else {
                proofs[0] = try slots.prover.blob_proof(stored, &slots.commitments[index]);
            }
        }
        slots.counts[slot] = @intCast(blobs.len);
        assert(slots.counts[slot] == blobs.len);
    }

    pub fn clear(slots: *BlobStore, slot: u32) void {
        assert(slot < slots.sends_max);
        slots.counts[slot] = 0;
    }

    pub fn count(slots: *const BlobStore, slot: u32) u8 {
        assert(slot < slots.sends_max);
        return slots.counts[slot];
    }

    /// Versioned hashes of `slot`; valid until the next call.
    pub fn versioned_hashes(slots: *BlobStore, slot: u32) []const [32]u8 {
        const blob_count = slots.count(slot);
        assert(blob_count > 0);
        const first = @as(usize, slot) * slots.blobs_per_send_max;
        for (0..blob_count) |offset| {
            slots.hashes[offset] = kzg.versioned_hash(&slots.commitments[first + offset]);
        }
        return slots.hashes[0..blob_count];
    }

    /// The sidecar of `slot`; valid until the next call.
    pub fn sidecar(slots: *BlobStore, slot: u32) blob_tx.Sidecar {
        const blob_count = slots.count(slot);
        assert(blob_count > 0);
        const first = @as(usize, slot) * slots.blobs_per_send_max;
        for (0..blob_count) |offset| slots.pointers[offset] = &slots.blobs[first + offset];
        const per_blob = proofs_per_blob(slots.version);
        return .{
            .version = slots.version,
            .blobs = slots.pointers[0..blob_count],
            .commitments = slots.commitments[first..][0..blob_count],
            .proofs = slots.proofs[first * per_blob ..][0 .. blob_count * per_blob],
        };
    }
};

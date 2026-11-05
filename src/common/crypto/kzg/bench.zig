//! KZG blob API benchmark bodies, registered in `src/common/crypto/bench.zig`.
//!
//! The decoded setup and a random blob live in file-level state initialised on the first
//! call (benchmarks only; the library itself has no global state). The harness reports
//! the fastest sample, so the one-time setup decode does not skew the numbers.

const std = @import("std");
const assert = std.debug.assert;
const blob = @import("blob.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const batch_size = 6;

const State = struct {
    storage: blob.Settings.Storage,
    settings: blob.Settings,
    workspace: blob.Workspace,
    batch_storage: blob.BatchStorage(batch_size),
    blobs: [batch_size]blob.Blob,
    commitments: [batch_size]blob.Commitment,
    proofs: [batch_size]blob.Proof,
};

var state: State = undefined;
var state_ready = false;

fn prepare() *State {
    if (state_ready) return &state;
    state.settings = blob.Settings.init(&state.storage) catch unreachable; // Embedded setup.
    var prng = Prng.init(0x4844);
    for (0..batch_size) |index| {
        for (0..blob.field_elements) |element| {
            const bytes = state.blobs[index][element * 32 ..][0..32];
            prng.fill(bytes);
            bytes[0] &= 0x3f; // Below the modulus.
        }
        const commitment = blob.blob_to_kzg_commitment(
            &state.settings,
            &state.workspace,
            &state.blobs[index],
        ) catch unreachable; // Canonical elements.
        state.commitments[index] = commitment;
        state.proofs[index] = blob.compute_blob_kzg_proof(
            &state.settings,
            &state.workspace,
            &state.blobs[index],
            &state.commitments[index],
        ) catch unreachable; // Valid commitment.
    }
    state_ready = true;
    return &state;
}

pub fn blob_to_kzg_commitment(iterations: u32) u64 {
    const context = prepare();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const commitment = blob.blob_to_kzg_commitment(
            &context.settings,
            &context.workspace,
            &context.blobs[0],
        ) catch unreachable; // Canonical elements.
        accumulator +%= commitment[1];
    }
    return accumulator;
}

pub fn compute_blob_kzg_proof(iterations: u32) u64 {
    const context = prepare();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const proof = blob.compute_blob_kzg_proof(
            &context.settings,
            &context.workspace,
            &context.blobs[0],
            &context.commitments[0],
        ) catch unreachable; // Valid commitment.
        accumulator +%= proof[1];
    }
    return accumulator;
}

pub fn verify_blob_kzg_proof(iterations: u32) u64 {
    const context = prepare();
    var valid: u64 = 0;
    for (0..iterations) |_| {
        valid += @intFromBool(blob.verify_blob_kzg_proof(
            &context.settings,
            &context.workspace,
            &context.blobs[0],
            &context.commitments[0],
            &context.proofs[0],
        ) catch unreachable); // Valid inputs.
    }
    assert(valid == iterations);
    return valid;
}

pub fn verify_blob_kzg_proof_batch_6(iterations: u32) u64 {
    const context = prepare();
    var pointers: [batch_size]*const blob.Blob = undefined;
    for (&pointers, &context.blobs) |*pointer, *data| pointer.* = data;
    var valid: u64 = 0;
    for (0..iterations) |_| {
        valid += @intFromBool(blob.verify_blob_kzg_proof_batch(
            &context.settings,
            &context.workspace,
            context.batch_storage.scratch(),
            &pointers,
            &context.commitments,
            &context.proofs,
        ) catch unreachable); // Valid inputs and enough scratch.
    }
    assert(valid == iterations);
    return valid;
}

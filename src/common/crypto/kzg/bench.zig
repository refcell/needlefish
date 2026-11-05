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

const cells = @import("cells.zig");

/// Cell benchmark state: full settings (FK20 tables), one blob's cells and proofs.
const CellState = struct {
    storage: cells.Settings.Storage,
    settings: cells.Settings,
    workspace: cells.Workspace,
    verify_storage: cells.VerifyStorage(cells.cells_per_ext_blob),
    cells: cells.Cells,
    proofs: cells.Proofs,
    commitments: [cells.cells_per_ext_blob]blob.Commitment,
    indices: [cells.cells_per_ext_blob]u64,
};

var cell_state: CellState = undefined;
var cell_state_ready = false;

fn prepare_cells() *CellState {
    if (cell_state_ready) return &cell_state;
    const context = prepare();
    const settings = cells.Settings.init(&cell_state.storage) catch unreachable; // Embedded.
    cell_state.settings = settings;
    cells.compute_cells_and_kzg_proofs(
        &cell_state.settings,
        &cell_state.workspace,
        &context.blobs[0],
        &cell_state.cells,
        &cell_state.proofs,
    ) catch unreachable; // Canonical blob.
    for (&cell_state.commitments, &cell_state.indices, 0..) |*commitment, *index, value| {
        commitment.* = context.commitments[0];
        index.* = value;
    }
    cell_state_ready = true;
    return &cell_state;
}

pub fn compute_cells(iterations: u32) u64 {
    const context = prepare();
    const state_cells = prepare_cells();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        cells.compute_cells(
            &state_cells.settings,
            &state_cells.workspace,
            &context.blobs[1],
            &state_cells.cells,
        ) catch unreachable; // Canonical blob.
        accumulator +%= state_cells.cells[100][7];
    }
    return accumulator;
}

pub fn compute_cells_and_kzg_proofs(iterations: u32) u64 {
    const context = prepare();
    const state_cells = prepare_cells();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        cells.compute_cells_and_kzg_proofs(
            &state_cells.settings,
            &state_cells.workspace,
            &context.blobs[0],
            &state_cells.cells,
            &state_cells.proofs,
        ) catch unreachable; // Canonical blob.
        accumulator +%= state_cells.proofs[5][1];
    }
    return accumulator;
}

fn verify_cells(count: u32, iterations: u32) u64 {
    const state_cells = prepare_cells();
    assert(count <= cells.cells_per_ext_blob);
    var valid: u64 = 0;
    for (0..iterations) |_| {
        valid += @intFromBool(cells.verify_cell_kzg_proof_batch(
            &state_cells.settings,
            &state_cells.workspace,
            state_cells.verify_storage.scratch(),
            state_cells.commitments[0..count],
            state_cells.indices[0..count],
            state_cells.cells[0..count],
            state_cells.proofs[0..count],
        ) catch unreachable); // Valid inputs.
    }
    assert(valid == iterations);
    return valid;
}

pub fn verify_cell_kzg_proof_batch_1(iterations: u32) u64 {
    return verify_cells(1, iterations);
}

pub fn verify_cell_kzg_proof_batch_128(iterations: u32) u64 {
    return verify_cells(cells.cells_per_ext_blob, iterations);
}

pub fn recover_cells_and_kzg_proofs(iterations: u32) u64 {
    const state_cells = prepare_cells();
    // Every other cell: the worst case for recovery (64 cells present).
    var indices: [cells.cells_per_ext_blob / 2]u64 = undefined;
    var present: [cells.cells_per_ext_blob / 2]cells.Cell = undefined;
    for (&indices, &present, 0..) |*index, *cell, slot| {
        index.* = 2 * slot;
        cell.* = state_cells.cells[2 * slot];
    }
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        cells.recover_cells_and_kzg_proofs(
            &state_cells.settings,
            &state_cells.workspace,
            &indices,
            &present,
            &state_cells.cells,
            &state_cells.proofs,
        ) catch unreachable; // Valid cells.
        accumulator +%= state_cells.proofs[9][3];
    }
    return accumulator;
}

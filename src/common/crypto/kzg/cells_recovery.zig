//! `recover_cells_and_kzg_proofs`: erasure recovery of an extended blob from at least
//! half of its cells (consensus-specs fulu `recover_polynomialcoeff`, c-kzg-4844
//! `recovery.c`).
//!
//! With E the extended evaluations (zero where cells are missing) and Z the polynomial
//! vanishing on the missing cosets, (E * Z) agrees with (P * Z) over the domain; P is
//! recovered by dividing (P * Z) by Z over a shifted coset (shift 7) where Z has no zero.
//! Z over the missing cosets is Z_short(X^64) with Z_short over 128th roots of unity.

const std = @import("std");
const assert = std.debug.assert;
const bls = @import("../bls12_381/root.zig");
const fft = @import("fft.zig");
const cells = @import("cells.zig");
const blob_api = @import("blob.zig");

const Fr = bls.Fr;
const Cell = cells.Cell;
const Cells = cells.Cells;
const Proofs = cells.Proofs;
const Error = cells.Error;
const Settings = cells.Settings;
const Workspace = cells.Workspace;

const field_elements_per_cell = cells.field_elements_per_cell;
const cells_per_ext_blob = cells.cells_per_ext_blob;
const ext_size = fft.ext_size;

/// The coset shift of the division step (the spec's `PRIMITIVE_ROOT_OF_UNITY`).
const recovery_shift = fft.primitive_root;

/// Checks the recovery inputs per spec: matching lengths, 64..128 cells, indices
/// strictly ascending (so unique) and below 128.
fn check_inputs(cell_indices: []const u64, cell_values: []const Cell) Error!void {
    if (cell_indices.len != cell_values.len) return error.InvalidLength;
    if (cell_indices.len < cells_per_ext_blob / 2) return error.InvalidLength;
    if (cell_indices.len > cells_per_ext_blob) return error.InvalidLength;
    for (cell_indices, 0..) |cell_index, position| {
        if (cell_index >= cells_per_ext_blob) return error.InvalidCellIndex;
        if (position > 0 and cell_index <= cell_indices[position - 1]) {
            return error.InvalidCellIndex;
        }
    }
    assert(cell_indices.len >= 64 and cell_indices.len <= 128);
}

/// Writes the known cells into `extended` (bit-reversed order, zeros where missing).
fn load_cells(
    extended: *[ext_size]Fr,
    cell_indices: []const u64,
    cell_values: []const Cell,
) Error!void {
    assert(cell_indices.len == cell_values.len);
    @memset(extended, Fr.zero);
    for (cell_indices, cell_values) |cell_index, *cell| {
        const start: usize = @intCast(cell_index * field_elements_per_cell);
        for (extended[start..][0..field_elements_per_cell], 0..) |*slot, index| {
            const bytes = cell[index * 32 ..][0..32];
            slot.* = Fr.from_bytes_be(bytes) orelse return error.InvalidFieldElement;
        }
    }
}

/// Z(X) = prod over missing cells k of (X^64 - h_k^64), in monomial form in `out`.
/// `missing` marks absent cells (natural cell order); at least one is missing.
fn vanishing_polynomial(
    settings: *const Settings,
    missing: *const [cells_per_ext_blob]bool,
    out: *[ext_size]Fr,
) void {
    // Short polynomial over Y = X^64 built root by root (degree <= 64, bounded loops).
    var short: [cells_per_ext_blob / 2 + 1]Fr = @splat(Fr.zero);
    var degree: usize = 0;
    short[0] = Fr.one;
    for (missing, 0..) |is_missing, cell_index| {
        if (!is_missing) continue;
        // h_k^64 = w^(64 * reverse_bits_7(k)): a 128th root of unity.
        const reversed = fft.reverse_bits(@intCast(cell_index), 7);
        const root = settings.roots[reversed * field_elements_per_cell];
        assert(degree < short.len - 1);
        degree += 1;
        // short *= (Y - root), from the top coefficient down.
        var index = degree;
        while (index > 0) : (index -= 1) {
            short[index] = short[index - 1].sub(short[index].mul(root));
        }
        short[0] = short[0].mul(root).neg();
    }
    assert(degree > 0 and short[degree].eql(Fr.one));
    @memset(out, Fr.zero);
    for (short[0 .. degree + 1], 0..) |coefficient, index| {
        out[index * field_elements_per_cell] = coefficient;
    }
}

/// Multiplies coefficient i by shift^i.
fn shift_polynomial(values: []Fr, shift: Fr) void {
    assert(values.len > 0);
    var factor = Fr.one;
    for (values) |*value| {
        value.* = value.mul(factor);
        factor = factor.mul(shift);
    }
    assert(!factor.is_zero());
}

/// Recovers the blob polynomial: on return `workspace.extended[0..4096]` holds its
/// monomial coefficients. Inputs are already loaded and checked.
fn recover_polynomial(
    settings: *const Settings,
    workspace: *Workspace,
    missing: *const [cells_per_ext_blob]bool,
) void {
    const roots = settings.roots;
    const extended = &workspace.extended;
    const vanishing = &workspace.vanishing;
    vanishing_polynomial(settings, missing, vanishing);
    // (E * Z) in evaluation form, natural order, then to coefficients.
    fft.bit_reverse_permute(Fr, extended);
    const vanishing_values = &workspace.scratch;
    @memcpy(vanishing_values, vanishing);
    fft.fft_fr(roots, vanishing_values);
    for (extended, vanishing_values) |*value, z| value.* = value.mul(z);
    fft.ifft_fr(roots, extended);
    // Divide by Z over the coset 7 * <w>, where Z has no zero.
    const shift = Fr.from_int_comptime(recovery_shift);
    shift_polynomial(extended, shift);
    fft.fft_fr(roots, extended);
    shift_polynomial(vanishing, shift);
    fft.fft_fr(roots, vanishing);
    blob_api.batch_inverse(vanishing, vanishing_values);
    for (extended, vanishing) |*value, inverse| {
        assert(!inverse.is_zero());
        value.* = value.mul(inverse);
    }
    fft.ifft_fr(roots, extended);
    shift_polynomial(extended, shift.inverse());
}

/// `recover_cells`: all 128 cells from at least 64 (no proofs; needs no FK20 tables).
/// Leaves the recovered polynomial's 4096 monomial coefficients in
/// `workspace.scratch[0..4096]`. As in the spec, the polynomial is truncated to degree
/// < 4096 and every cell is recomputed from it, also when all 128 cells are given.
pub fn recover_cells(
    settings: *const Settings,
    workspace: *Workspace,
    cell_indices: []const u64,
    cell_values: []const Cell,
    recovered: *Cells,
) Error!void {
    try check_inputs(cell_indices, cell_values);
    try load_cells(&workspace.extended, cell_indices, cell_values);
    if (cell_indices.len == cells_per_ext_blob) {
        // Z = 1: the polynomial is the inverse FFT of the cells.
        cells.evaluations_brp_to_monomial(settings.roots, &workspace.extended);
    } else {
        var missing: [cells_per_ext_blob]bool = @splat(true);
        for (cell_indices) |cell_index| missing[@intCast(cell_index)] = false;
        recover_polynomial(settings, workspace, &missing);
    }
    const coefficients = workspace.scratch[0..cells.field_elements_per_blob];
    @memcpy(coefficients, workspace.extended[0..cells.field_elements_per_blob]);
    cells.monomial_to_cells(settings, &workspace.extended, recovered);
    assert(recovered.len == cells_per_ext_blob);
}

/// `recover_cells_and_kzg_proofs`: all cells and proofs from at least half of the cells.
/// Requires full `Settings` (FK20 tables).
pub fn recover_cells_and_kzg_proofs(
    settings: *const Settings,
    workspace: *Workspace,
    cell_indices: []const u64,
    cell_values: []const Cell,
    recovered_cells: *Cells,
    recovered_proofs: *Proofs,
) Error!void {
    assert(settings.columns != null);
    try recover_cells(settings, workspace, cell_indices, cell_values, recovered_cells);
    const coefficients = workspace.scratch[0..cells.field_elements_per_blob];
    cells.monomial_to_proofs(settings, workspace, coefficients, recovered_proofs);
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

var test_cells: Cells = undefined;
var test_recovered: Cells = undefined;

fn random_blob(prng: *Prng, blob: *cells.Blob) void {
    for (0..cells.field_elements_per_blob) |index| {
        prng.fill(blob[index * 32 ..][0..32]);
        blob[index * 32] &= 0x3f;
    }
}

test "cells recovery: recovers random erasures of half the cells (seeded)" {
    const settings = try cells.shared_settings();
    const workspace = cells.shared_workspace();
    var prng = Prng.init(0x7ec0);
    var blob: cells.Blob = undefined;
    random_blob(&prng, &blob);
    try cells.compute_cells(settings, workspace, &blob, &test_cells);
    var kept_indices: [cells_per_ext_blob]u64 = undefined;
    var kept_cells: [cells_per_ext_blob]Cell = undefined;
    const rounds = if (cells.heavy_tests) 4 else 1;
    for (0..rounds) |_| {
        const keep: usize = @intCast(prng.range(64, 127));
        // Choose `keep` distinct indices in ascending order (selection sampling).
        var count: usize = 0;
        for (0..cells_per_ext_blob) |index| {
            const remaining = cells_per_ext_blob - index;
            if (prng.below(remaining) < keep - count) {
                kept_indices[count] = index;
                kept_cells[count] = test_cells[index];
                count += 1;
            }
        }
        try testing.expectEqual(keep, count);
        try recover_for_test(kept_indices[0..count], kept_cells[0..count]);
        const expected = std.mem.asBytes(&test_cells);
        try testing.expectEqualSlices(u8, expected, std.mem.asBytes(&test_recovered));
    }
}

fn recover_for_test(indices: []const u64, cell_values: []const Cell) !void {
    const settings = try cells.shared_settings();
    const workspace = cells.shared_workspace();
    return recover_cells(settings, workspace, indices, cell_values, &test_recovered);
}

test "cells recovery: input checks" {
    var indices: [cells_per_ext_blob]u64 = undefined;
    for (&indices, 0..) |*index, value| index.* = value;
    const zero_cells: [cells_per_ext_blob]Cell = @splat(@splat(0));
    const zeros = zero_cells[0..64];
    const too_few = recover_for_test(indices[0..63], zero_cells[0..63]);
    try testing.expectError(error.InvalidLength, too_few);
    const mismatched = recover_for_test(indices[0..64], zero_cells[0..65]);
    try testing.expectError(error.InvalidLength, mismatched);
    var shuffled = indices;
    std.mem.swap(u64, &shuffled[3], &shuffled[4]);
    try testing.expectError(error.InvalidCellIndex, recover_for_test(shuffled[0..64], zeros));
    shuffled = indices;
    shuffled[63] = 128;
    try testing.expectError(error.InvalidCellIndex, recover_for_test(shuffled[0..64], zeros));
    var bad = zero_cells;
    std.mem.writeInt(u256, bad[9][0..32], @import("root.zig").bls_modulus, .big);
    const non_canonical = recover_for_test(indices[0..64], bad[0..64]);
    try testing.expectError(error.InvalidFieldElement, non_canonical);
    // All-zero cells recover to the zero extended blob.
    try recover_for_test(indices[0..64], zeros);
    const expected = std.mem.asBytes(&zero_cells);
    try testing.expectEqualSlices(u8, expected, std.mem.asBytes(&test_recovered));
}

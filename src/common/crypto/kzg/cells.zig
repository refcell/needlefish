//! EIP-7594 (PeerDAS) cells and cell proofs (consensus-specs fulu
//! `polynomial-commitments-sampling.md`, mirrored by c-kzg-4844's `eip7594`).
//!
//! A blob polynomial (degree < 4096) is evaluated over the 8192-point extended domain in
//! bit-reversal order and cut into 128 cells of 64 field elements; cell k holds the
//! evaluations over the coset h_k * <w^128> with h_k = w^reverse_bits_7(k). Each cell has
//! a KZG multi-proof; all 128 are computed together with FK20 (`fk20.zig`).
//!
//! No hidden state and no allocation: `Settings.init` fills caller-provided `Storage`
//! (about 1.15 MiB: 256 KiB of roots, 832 KiB of FK20 tables), operations take a
//! caller-provided `Workspace` (about 1.1 MiB). `Settings.init_verifier` skips the FK20
//! tables (64 G1 FFTs of size 128, about 0.8 s in ReleaseFast) for nodes that only verify
//! cells and recover cells without proofs. Everything handles public data, so the code is
//! variable time.

const std = @import("std");
const assert = std.debug.assert;
const bls = @import("../bls12_381/root.zig");
const kzg = @import("root.zig");
const fft = @import("fft.zig");
const fk20 = @import("fk20.zig");
const blob_api = @import("blob.zig");

pub const verify = @import("cells_verify.zig");
pub const recovery = @import("cells_recovery.zig");
pub const verify_cell_kzg_proof_batch = verify.verify_cell_kzg_proof_batch;
pub const VerifyScratch = verify.VerifyScratch;
pub const VerifyStorage = verify.VerifyStorage;
pub const recover_cells_and_kzg_proofs = recovery.recover_cells_and_kzg_proofs;
pub const recover_cells = recovery.recover_cells;

const Fr = bls.Fr;
const G1Affine = bls.G1Affine;

pub const field_elements_per_blob = kzg.field_elements_per_blob;
pub const field_elements_per_ext_blob = fft.ext_size;
pub const field_elements_per_cell = fk20.field_elements_per_cell;
pub const cells_per_ext_blob = fk20.cells_per_ext_blob;
pub const bytes_per_cell = field_elements_per_cell * kzg.bytes_per_field_element;

pub const Blob = blob_api.Blob;
pub const Commitment = blob_api.Commitment;
pub const Proof = blob_api.Proof;
pub const Cell = [bytes_per_cell]u8;
pub const Cells = [cells_per_ext_blob]Cell;
pub const Proofs = [cells_per_ext_blob]Proof;

pub const Error = error{
    /// A blob or cell element is not a canonical field element (>= BLS_MODULUS).
    InvalidFieldElement,
    /// A commitment or proof is not a valid compressed G1 point in the subgroup.
    InvalidPoint,
    /// A cell index is >= 128, or recovery indices are not strictly ascending.
    InvalidCellIndex,
    /// Input slices disagree in length, or recovery has fewer than 64 or more than 128 cells.
    InvalidLength,
    /// The caller-provided batch scratch is smaller than the batch.
    ScratchTooSmall,
};

comptime {
    assert(bytes_per_cell == 2048);
    assert(field_elements_per_ext_blob == cells_per_ext_blob * field_elements_per_cell);
}

pub const Settings = struct {
    /// w^0 .. w^8192 for the order-8192 root of unity w, natural order.
    roots: *const fft.Roots,
    /// [tau^i]G1 for i < 64: commits to the interpolation polynomial of a cell.
    g1_monomial: *const [field_elements_per_cell]G1Affine,
    /// Miller loop lines of [tau^64]G2, the right side of the cell pairing check.
    tau_cell_g2: *const bls.pairing.PreparedG2,
    /// FK20 tables; null for a verifier-only `Settings` (no proof computation).
    columns: ?*const fk20.Columns,

    pub const Storage = struct {
        roots: fft.Roots,
        g1_monomial: [field_elements_per_cell]G1Affine,
        tau_cell_g2: bls.pairing.PreparedG2,
        columns: fk20.Columns,
    };

    pub const InitError = error{InvalidSetup};

    /// Full settings: verification, recovery, and proof computation.
    pub fn init(storage: *Storage) InitError!Settings {
        var settings = try init_verifier(storage);
        try fk20.init_columns(&storage.roots, &storage.columns);
        settings.columns = &storage.columns;
        assert(settings.columns != null);
        return settings;
    }

    /// Settings for `compute_cells`, `verify_cell_kzg_proof_batch`, and `recover_cells`
    /// only; `storage.columns` is left untouched.
    pub fn init_verifier(storage: *Storage) InitError!Settings {
        fft.fill_roots(&storage.roots);
        for (&storage.g1_monomial, 0..) |*point, index| {
            const bytes = kzg.setup_g1_monomial(@intCast(index));
            point.* = bls.g1.decompress_unchecked(bytes) catch return error.InvalidSetup;
            if (point.infinity) return error.InvalidSetup;
        }
        const tau_bytes = kzg.setup_g2_monomial(field_elements_per_cell);
        const tau = bls.g2.decompress_unchecked(tau_bytes) catch return error.InvalidSetup;
        if (tau.infinity) return error.InvalidSetup;
        storage.tau_cell_g2 = bls.pairing.prepare(tau);
        assert(storage.roots[0].eql(Fr.one));
        return .{
            .roots = &storage.roots,
            .g1_monomial = &storage.g1_monomial,
            .tau_cell_g2 = &storage.tau_cell_g2,
            .columns = null,
        };
    }
};

/// Scratch memory (about 1.1 MiB); contents are meaningless between calls.
pub const Workspace = struct {
    extended: [field_elements_per_ext_blob]Fr,
    vanishing: [field_elements_per_ext_blob]Fr,
    scratch: [field_elements_per_ext_blob]Fr,
    fk20: fk20.Workspace,
};

/// Parses a blob into its 4096 evaluations (bit-reversed domain order).
fn blob_to_polynomial(blob: *const Blob, out: []Fr) Error!void {
    assert(out.len == field_elements_per_blob);
    for (out, 0..) |*element, index| {
        const bytes = blob[index * 32 ..][0..32];
        element.* = Fr.from_bytes_be(bytes) orelse return error.InvalidFieldElement;
    }
}

/// Evaluations in bit-reversed order over a domain of `values.len` to monomial
/// coefficients, in place.
pub fn evaluations_brp_to_monomial(roots: *const fft.Roots, values: []Fr) void {
    assert(values.len >= 2);
    fft.bit_reverse_permute(Fr, values);
    fft.ifft_fr(roots, values);
}

/// Loads the blob as 4096 monomial coefficients into `polynomial[0..4096]`.
fn blob_to_monomial(settings: *const Settings, blob: *const Blob, polynomial: []Fr) Error!void {
    assert(polynomial.len >= field_elements_per_blob);
    const coefficients = polynomial[0..field_elements_per_blob];
    try blob_to_polynomial(blob, coefficients);
    evaluations_brp_to_monomial(settings.roots, coefficients);
}

/// Writes the cells of a polynomial given by its first 4096 monomial coefficients in
/// `extended` (overwritten with the extended evaluations in bit-reversed order).
pub fn monomial_to_cells(
    settings: *const Settings,
    extended: *[field_elements_per_ext_blob]Fr,
    cells: *Cells,
) void {
    @memset(extended[field_elements_per_blob..], Fr.zero);
    fft.fft_fr(settings.roots, extended);
    fft.bit_reverse_permute(Fr, extended);
    for (cells, 0..) |*cell, cell_index| {
        const start = cell_index * field_elements_per_cell;
        const values = extended[start..][0..field_elements_per_cell];
        for (values, 0..) |value, index| cell[index * 32 ..][0..32].* = value.to_bytes_be();
    }
    assert(cells.len == cells_per_ext_blob);
}

/// `compute_cells`: the 128 cells of the extended blob (no proofs; needs no FK20 tables).
pub fn compute_cells(
    settings: *const Settings,
    workspace: *Workspace,
    blob: *const Blob,
    cells: *Cells,
) Error!void {
    try blob_to_monomial(settings, blob, &workspace.extended);
    monomial_to_cells(settings, &workspace.extended, cells);
}

/// The 128 cell proofs of the polynomial whose 4096 monomial coefficients are in
/// `coefficients`. Requires full `Settings` (FK20 tables).
pub fn monomial_to_proofs(
    settings: *const Settings,
    workspace: *Workspace,
    coefficients: *const [field_elements_per_blob]Fr,
    proofs: *Proofs,
) void {
    const columns = settings.columns orelse unreachable; // Documented precondition.
    fk20.compute_cell_proofs(settings.roots, columns, coefficients, &workspace.fk20, proofs);
}

/// `compute_cells_and_kzg_proofs`: the cells of the extended blob and their proofs.
/// Requires `Settings.init` (not `init_verifier`).
pub fn compute_cells_and_kzg_proofs(
    settings: *const Settings,
    workspace: *Workspace,
    blob: *const Blob,
    cells: *Cells,
    proofs: *Proofs,
) Error!void {
    assert(settings.columns != null);
    try blob_to_monomial(settings, blob, &workspace.extended);
    const coefficients = workspace.scratch[0..field_elements_per_blob];
    @memcpy(coefficients, workspace.extended[0..field_elements_per_blob]);
    monomial_to_cells(settings, &workspace.extended, cells);
    monomial_to_proofs(settings, workspace, coefficients, proofs);
}

/// h_k: the shift of the coset of cell `cell_index` (w^reverse_bits_7(k)).
pub fn coset_shift(settings: *const Settings, cell_index: u32) Fr {
    assert(cell_index < cells_per_ext_blob);
    return settings.roots[fft.reverse_bits(cell_index, 7)];
}

const testing = std.testing;
const builtin = @import("builtin");
const Prng = @import("../../../testing/prng.zig").Prng;

/// Proof computation and the FK20 setup take minutes unoptimised; Debug covers cells,
/// recovery of cells, and the cheap verification paths only.
pub const heavy_tests = builtin.mode != .debug;

// Tests share one decoded setup and workspace (too big for the stack).
var test_storage: Settings.Storage = undefined;
var test_workspace: Workspace = undefined;
var test_settings: ?Settings = null;
var test_full = false;

/// Verifier settings, or full settings when `heavy_tests` (FK20 init is slow in Debug).
pub fn shared_settings() !*const Settings {
    if (test_settings == null) {
        test_settings = if (heavy_tests)
            try Settings.init(&test_storage)
        else
            try Settings.init_verifier(&test_storage);
    }
    return &test_settings.?;
}

pub fn shared_workspace() *Workspace {
    return &test_workspace;
}

/// Evaluates the polynomial with 4096 monomial coefficients at `z` (Horner).
fn evaluate_monomial(coefficients: []const Fr, z: Fr) Fr {
    var result = Fr.zero;
    var index = coefficients.len;
    while (index > 0) {
        index -= 1;
        result = result.mul(z).add(coefficients[index]);
    }
    return result;
}

test "cells: cell k holds evaluations over its coset in bit-reversed order" {
    const settings = try shared_settings();
    var prng = Prng.init(0xce11);
    var blob: Blob = undefined;
    for (0..field_elements_per_blob) |index| {
        prng.fill(blob[index * 32 ..][0..32]);
        blob[index * 32] &= 0x3f;
    }
    const cells = &test_cells;
    try compute_cells(settings, &test_workspace, &blob, cells);
    // Coefficients of the blob polynomial, for direct evaluation.
    var coefficients: [field_elements_per_blob]Fr = undefined;
    try blob_to_polynomial(&blob, &coefficients);
    evaluations_brp_to_monomial(settings.roots, &coefficients);
    for ([_]u32{ 0, 1, 77, 127 }) |cell_index| {
        const h = coset_shift(settings, cell_index);
        for ([_]u32{ 0, 1, 40, 63 }) |index| {
            // Coset point j in bit-reversed order: h * (w^128)^reverse_bits_6(j).
            const exponent = 128 * fft.reverse_bits(index, 6);
            const z = h.mul(settings.roots[exponent]);
            const expected = evaluate_monomial(&coefficients, z).to_bytes_be();
            try testing.expectEqualSlices(u8, &expected, cells[cell_index][index * 32 ..][0..32]);
        }
    }
    // The first half of the extended blob is the blob itself (systematic code).
    const systematic = std.mem.asBytes(cells[0..64]);
    try testing.expectEqualSlices(u8, blob[0 .. 64 * bytes_per_cell], systematic);
}

var test_cells: Cells = undefined;

test "cells: non-canonical blob elements are rejected" {
    const settings = try shared_settings();
    var blob: Blob = @splat(0);
    std.mem.writeInt(u256, blob[100 * 32 ..][0..32], kzg.bls_modulus, .big);
    try testing.expectError(
        error.InvalidFieldElement,
        compute_cells(settings, &test_workspace, &blob, &test_cells),
    );
    if (!heavy_tests) return;
    var proofs: Proofs = undefined;
    try testing.expectError(
        error.InvalidFieldElement,
        compute_cells_and_kzg_proofs(settings, &test_workspace, &blob, &test_cells, &proofs),
    );
}

test {
    testing.refAllDecls(@This());
    _ = @import("cells_vectors.zig");
}

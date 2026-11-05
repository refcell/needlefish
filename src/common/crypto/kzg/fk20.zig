//! FK20 multi-proofs for EIP-7594 cells (Feist-Khovratovich, "Fast amortized KZG proofs",
//! eprint 2023/033), following c-kzg-4844's `fk20.c`.
//!
//! All 128 cell proofs of a blob polynomial f (4096 monomial coefficients) are the
//! commitments to the quotients of f by X^64 - h^64 over the 128 cosets. Their
//! commitments form a Toeplitz matrix-vector product with the G1 monomial setup, which
//! becomes 64 circulant products of size 128 evaluated through FFTs:
//!
//! - setup (once): for each offset i < 64, the G1 FFT of the setup points
//!   [tau^(4095 - 64 - i - 64 j)] for j < 63, zero padded to 128; stored transposed as
//!   `Columns` (128 rows of 64 affine points, about 832 KiB);
//! - per blob: 64 Fr FFTs of the circulant coefficient vectors, 128 MSMs of 64 points
//!   (one per row), an inverse G1 FFT, and a G1 FFT of size 128 that evaluates the
//!   resulting degree < 64 polynomial at the 128 cosets.

const std = @import("std");
const assert = std.debug.assert;
const bls = @import("../bls12_381/root.zig");
const kzg = @import("root.zig");
const fft = @import("fft.zig");

const Fr = bls.Fr;
const Fp = bls.Fp;
const G1 = bls.G1;
const G1Affine = bls.G1Affine;

pub const field_elements_per_cell = 64;
pub const cells_per_blob = kzg.field_elements_per_blob / field_elements_per_cell;
pub const cells_per_ext_blob = 2 * cells_per_blob;
/// Size of the circulant embedding of the 64 x 64 Toeplitz blocks (eprint 2023/033 §3).
pub const circulant_size = 2 * cells_per_blob;

/// Transposed FFTs of the setup slices: `columns[row][offset]`.
pub const Columns = [circulant_size][field_elements_per_cell]G1Affine;

comptime {
    assert(cells_per_blob == 64 and cells_per_ext_blob == 128);
    assert(circulant_size == cells_per_ext_blob);
}

/// Window width of the optional fixed-base prover tables (9 measured fastest: 7, 8, 10
/// were 15-18% slower).
pub const table_window_bits = 9;
pub const table_windows = bls.msm.precomputed_window_count(table_window_bits);
/// Optional prover tables: `tables[row]` holds, for each offset, the shifts
/// [2^(9 w)] columns[row][offset] for w < 29 (about 25 MiB). With them each of the 128
/// row MSMs is one bucket pass without doublings (`bls.msm.msm_precomputed`).
pub const Tables = [circulant_size][field_elements_per_cell * table_windows]G1Affine;

/// Fills `tables` from `columns` (about 2M doublings; once at startup).
pub fn init_tables(columns: *const Columns, tables: *Tables) void {
    for (tables, columns) |*table_row, *column_row| {
        for (column_row, 0..) |point, offset| {
            const out = table_row[offset * table_windows ..][0..table_windows];
            bls.msm.precompute_shifts(G1, table_window_bits, point, out);
        }
    }
    assert(tables[0][0].eql(columns[0][0]));
    assert(tables[0][table_windows].eql(columns[0][1]));
}

/// Scratch for one proof computation (about 300 KiB).
pub const Workspace = struct {
    scalars: [circulant_size][field_elements_per_cell]u256,
    circulant: [circulant_size]Fr,
    points: [circulant_size]G1,
    affine: [circulant_size]G1Affine,
    inverses: [circulant_size]Fp,
};

/// Decodes the monomial setup slices and fills `columns`. Points are decoded without
/// subgroup checks: the setup is public and its hash is asserted in tests.
pub fn init_columns(roots: *const fft.Roots, columns: *Columns) error{InvalidSetup}!void {
    var points: [circulant_size]G1 = undefined;
    var affine: [circulant_size]G1Affine = undefined;
    var inverses: [circulant_size]Fp = undefined;
    for (0..field_elements_per_cell) |offset| {
        const start = kzg.field_elements_per_blob - field_elements_per_cell - 1 - offset;
        for (points[0 .. cells_per_blob - 1], 0..) |*point, index| {
            const setup_index: u32 = @intCast(start - index * field_elements_per_cell);
            const bytes = kzg.setup_g1_monomial(setup_index);
            const decoded = bls.g1.decompress_unchecked(bytes) catch return error.InvalidSetup;
            if (decoded.infinity) return error.InvalidSetup;
            point.* = decoded.to_jacobian();
        }
        @memset(points[cells_per_blob - 1 ..], G1.identity);
        fft.fft_g1(roots, &points);
        G1.batch_to_affine(&points, &affine, &inverses);
        for (columns, affine) |*row, point| row[offset] = point;
    }
    assert(!columns[0][0].infinity);
    assert(columns[0][0].is_on_curve());
}

/// The first column of the `offset`-th circulant matrix: c[0] = f[d - i],
/// c[128 - j] = f[d - i - 64 j] for j in 1..63, zero elsewhere (d = 4095).
fn circulant_coefficients(
    out: *[circulant_size]Fr,
    polynomial: *const [kzg.field_elements_per_blob]Fr,
    offset: usize,
) void {
    assert(offset < field_elements_per_cell);
    const last = kzg.field_elements_per_blob - 1 - offset;
    @memset(out, Fr.zero);
    out[0] = polynomial[last];
    for (1..cells_per_blob - 1) |j| {
        out[circulant_size - j] = polynomial[last - j * field_elements_per_cell];
    }
    assert(out[1].is_zero() and out[cells_per_blob].is_zero());
}

/// The 128 cell proofs of `polynomial` (monomial form) in cell order (bit-reversed
/// coset order), as Jacobian points in `workspace.points`, then compressed to `out`.
pub fn compute_cell_proofs(
    roots: *const fft.Roots,
    columns: *const Columns,
    tables: ?*const Tables,
    polynomial: *const [kzg.field_elements_per_blob]Fr,
    workspace: *Workspace,
    out: *[cells_per_ext_blob][kzg.bytes_per_proof]u8,
) void {
    // The 1/128 of the inverse G1 FFT is folded into the scalars (cheap field products).
    const inverse_size = Fr.from_int(circulant_size).inverse();
    assert(inverse_size.mul(Fr.from_int(circulant_size)).eql(Fr.one));
    for (0..field_elements_per_cell) |offset| {
        circulant_coefficients(&workspace.circulant, polynomial, offset);
        fft.fft_fr(roots, &workspace.circulant);
        for (&workspace.scalars, workspace.circulant) |*row, value| {
            row[offset] = value.mul(inverse_size).to_int();
        }
    }
    if (tables) |table_rows| {
        for (&workspace.points, table_rows, &workspace.scalars) |*point, *row, *scalars| {
            point.* = bls.msm.msm_precomputed(G1, table_window_bits, row, scalars);
        }
    } else {
        for (&workspace.points, columns, &workspace.scalars) |*point, *row, *scalars| {
            point.* = bls.msm.msm(G1, row, scalars);
        }
    }
    fft.ifft_g1_unscaled(roots, &workspace.points);
    // The polynomial of proofs has degree < 64; its upper half is zero by construction.
    @memset(workspace.points[cells_per_blob..], G1.identity);
    fft.fft_g1(roots, &workspace.points);
    fft.bit_reverse_permute(G1, &workspace.points);
    G1.batch_to_affine(&workspace.points, &workspace.affine, &workspace.inverses);
    for (out, workspace.affine) |*bytes, point| bytes.* = bls.g1.compress(point);
    assert(out[0][0] & 0x80 != 0);
}

const testing = std.testing;

test "fk20: circulant coefficient layout" {
    var polynomial: [kzg.field_elements_per_blob]Fr = undefined;
    for (&polynomial, 0..) |*value, index| value.* = Fr.from_int(index);
    var out: [circulant_size]Fr = undefined;
    circulant_coefficients(&out, &polynomial, 5);
    try testing.expect(out[0].eql(Fr.from_int(4090)));
    try testing.expect(out[127].eql(Fr.from_int(4090 - 64)));
    try testing.expect(out[66].eql(Fr.from_int(4090 - 62 * 64)));
    for (out[1..66]) |value| try testing.expect(value.is_zero());
}

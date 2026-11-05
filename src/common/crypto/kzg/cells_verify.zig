//! `verify_cell_kzg_proof_batch`: the universal verification equation for EIP-7594
//! cells (consensus-specs fulu `verify_cell_kzg_proof_batch_impl`).
//!
//! With r from the Fiat-Shamir hash of every input and k ranging over the cells:
//!   e(sum_k r^k proof_k, [tau^64]G2) == e(RLC - RLI + RLP, G2)
//! where RLC = sum_i weight_i commitment_i (weights sum the r^k of the cells of each
//! deduplicated commitment), RLI commits to sum_k r^k I_k(X) (I_k interpolates cell k
//! over its coset, computed per column with a size-64 inverse FFT), and
//! RLP = sum_k r^k h_k^64 proof_k.

const std = @import("std");
const assert = std.debug.assert;
const bls = @import("../bls12_381/root.zig");
const sha256 = @import("../sha256.zig");
const kzg = @import("root.zig");
const fft = @import("fft.zig");
const cells = @import("cells.zig");
const verify_4844 = @import("verify.zig");

const Fr = bls.Fr;
const G1 = bls.G1;
const G1Affine = bls.G1Affine;
const Cell = cells.Cell;
const Commitment = cells.Commitment;
const Proof = cells.Proof;
const Error = cells.Error;
const Settings = cells.Settings;
const Workspace = cells.Workspace;

const field_elements_per_cell = cells.field_elements_per_cell;
const cells_per_ext_blob = cells.cells_per_ext_blob;

/// Domain separation tag (consensus-specs `RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN`).
const challenge_domain = "RCKZGCBATCH__V1_";

comptime {
    assert(challenge_domain.len == 16);
}

/// Caller-provided memory for a batch of up to n cells: `points.len`, `scalars.len >=
/// 2n`, and `powers.len`, `weights.len`, `commitment_indices.len >= n`.
pub const VerifyScratch = struct {
    points: []G1Affine,
    scalars: []u256,
    powers: []Fr,
    weights: []Fr,
    commitment_indices: []u32,

    fn capacity(scratch: VerifyScratch) usize {
        const pairs = @min(scratch.points.len, scratch.scalars.len) / 2;
        const singles = @min(scratch.powers.len, scratch.weights.len);
        return @min(pairs, singles, scratch.commitment_indices.len);
    }
};

/// Fixed-capacity storage for batches of up to `capacity` cells (about 240 bytes/cell).
pub fn VerifyStorage(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        points: [2 * capacity]G1Affine = undefined,
        scalars: [2 * capacity]u256 = undefined,
        powers: [capacity]Fr = undefined,
        weights: [capacity]Fr = undefined,
        commitment_indices: [capacity]u32 = undefined,

        pub fn scratch(self: *Self) VerifyScratch {
            return .{
                .points = &self.points,
                .scalars = &self.scalars,
                .powers = &self.powers,
                .weights = &self.weights,
                .commitment_indices = &self.commitment_indices,
            };
        }
    };
}

/// Input of a batch: one (commitment, cell index, cell, proof) tuple per position.
pub const Batch = struct {
    commitments: []const Commitment,
    cell_indices: []const u64,
    cells: []const Cell,
    proofs: []const Proof,
};

/// `verify_cell_kzg_proof_batch`: true when every cell is the evaluation of its
/// commitment's polynomial over the coset of its index. Errors for malformed input
/// (length mismatch, index >= 128, non-canonical element, invalid point). An empty
/// batch is valid.
pub fn verify_cell_kzg_proof_batch(
    settings: *const Settings,
    workspace: *Workspace,
    scratch: VerifyScratch,
    commitments: []const Commitment,
    cell_indices: []const u64,
    cell_values: []const Cell,
    proofs: []const Proof,
) Error!bool {
    const count = cell_indices.len;
    if (commitments.len != count or cell_values.len != count or proofs.len != count) {
        return error.InvalidLength;
    }
    if (count == 0) return true;
    if (scratch.capacity() < count) return error.ScratchTooSmall;
    for (cell_indices) |cell_index| {
        if (cell_index >= cells_per_ext_blob) return error.InvalidCellIndex;
    }
    const batch: Batch = .{
        .commitments = commitments,
        .cell_indices = cell_indices,
        .cells = cell_values,
        .proofs = proofs,
    };
    // Decoding (subgroup checks) and the field check of every cell come before any
    // hashing, so malformed input is always an error, never `false`.
    for (proofs, scratch.points[0..count]) |*bytes, *point| point.* = try decode_g1(bytes);
    try aggregate_columns(workspace, batch, null);
    const unique_count = deduplicate(commitments, scratch.commitment_indices[0..count]);
    const unique_points = scratch.points[count..][0..unique_count];
    for (unique_points, 0..) |*point, unique_index| {
        point.* = try decode_g1(&commitments[first_index_of(scratch, unique_index, count)]);
    }
    const r = compute_challenge_deduplicated(batch, scratch, unique_count);
    var power = Fr.one;
    for (scratch.powers[0..count]) |*slot| {
        slot.* = power;
        power = power.mul(r);
    }
    return check(settings, workspace, batch, scratch, unique_count);
}

fn decode_g1(bytes: *const [48]u8) Error!G1Affine {
    return bls.g1.decompress(bytes) catch error.InvalidPoint;
}

fn read_element(cell: *const Cell, index: usize) Error!Fr {
    assert(index < field_elements_per_cell);
    return Fr.from_bytes_be(cell[index * 32 ..][0..32]) orelse error.InvalidFieldElement;
}

/// Maps each commitment to the index of its first occurrence among the distinct
/// commitments (in order of first appearance); returns the number of distinct ones.
fn deduplicate(commitments: []const Commitment, indices: []u32) u32 {
    assert(commitments.len == indices.len);
    var unique_count: u32 = 0;
    for (commitments, 0..) |*commitment, position| {
        var found: ?u32 = null;
        for (commitments[0..position], indices[0..position]) |*earlier, earlier_index| {
            if (std.mem.eql(u8, earlier, commitment)) {
                found = earlier_index;
                break;
            }
        }
        indices[position] = found orelse blk: {
            unique_count += 1;
            break :blk unique_count - 1;
        };
    }
    assert(unique_count >= 1 or commitments.len == 0);
    return unique_count;
}

/// Position in the batch of the first commitment with deduplicated index `unique_index`.
fn first_index_of(scratch: VerifyScratch, unique_index: usize, count: usize) usize {
    for (scratch.commitment_indices[0..count], 0..) |index, position| {
        if (index == unique_index) return position;
    }
    unreachable; // Every deduplicated index has a first occurrence by construction.
}

fn hash_u64(hasher: *sha256.Hasher, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    hasher.update(&bytes);
}

fn compute_challenge_deduplicated(batch: Batch, scratch: VerifyScratch, unique_count: u32) Fr {
    var hasher = challenge_header(unique_count, batch.cell_indices.len);
    for (0..unique_count) |unique_index| {
        const position = first_index_of(scratch, unique_index, batch.cell_indices.len);
        hasher.update(&batch.commitments[position]);
    }
    const indices = scratch.commitment_indices[0..batch.cell_indices.len];
    return challenge_body(&hasher, batch, indices);
}

fn challenge_header(commitment_count: u64, cell_count: u64) sha256.Hasher {
    var hasher = sha256.Hasher.init();
    hasher.update(challenge_domain);
    hash_u64(&hasher, kzg.field_elements_per_blob);
    hash_u64(&hasher, field_elements_per_cell);
    hash_u64(&hasher, commitment_count);
    hash_u64(&hasher, cell_count);
    return hasher;
}

fn challenge_body(hasher: *sha256.Hasher, batch: Batch, commitment_indices: []const u32) Fr {
    assert(commitment_indices.len == batch.cell_indices.len);
    assert(batch.cells.len == batch.cell_indices.len);
    for (commitment_indices, batch.cell_indices, batch.cells, batch.proofs) |
        commitment_index,
        cell_index,
        *cell,
        *proof,
    | {
        hash_u64(hasher, commitment_index);
        hash_u64(hasher, cell_index);
        hasher.update(cell); // Cells are canonical here, so bytes = bls_field_to_bytes.
        hasher.update(proof);
    }
    const digest = hasher.final();
    return Fr.from_int(std.mem.readInt(u256, &digest, .big));
}

/// `compute_verify_cell_kzg_proof_batch_challenge` over already deduplicated
/// commitments (`batch.commitments` holds the distinct ones; `commitment_indices` maps
/// each cell to one). Cells must be canonical.
pub fn compute_challenge(batch: Batch, commitment_indices: []const u32) Fr {
    assert(batch.proofs.len == batch.cell_indices.len);
    var hasher = challenge_header(batch.commitments.len, batch.cell_indices.len);
    for (batch.commitments) |*commitment| hasher.update(commitment);
    return challenge_body(&hasher, batch, commitment_indices);
}

/// Adds r^k * cell_k into the cell's column of `workspace.extended` (one column of 64
/// elements per cell index). With `powers == null` it only validates the cells.
fn aggregate_columns(workspace: *Workspace, batch: Batch, powers: ?[]const Fr) Error!void {
    assert(powers == null or powers.?.len == batch.cells.len);
    @memset(&workspace.extended, Fr.zero);
    for (batch.cell_indices, batch.cells, 0..) |cell_index, *cell, position| {
        assert(cell_index < cells_per_ext_blob);
        const start: usize = @intCast(cell_index * field_elements_per_cell);
        const column = workspace.extended[start..][0..field_elements_per_cell];
        for (column, 0..) |*slot, index| {
            const value = try read_element(cell, index);
            if (powers) |weights| slot.* = slot.add(value.mul(weights[position]));
        }
    }
}

/// sum_k r^k I_k(X) in monomial form: per used column, the inverse FFT of its
/// aggregated values (put in natural coset order), unshifted by h^-j.
fn aggregated_interpolation(
    settings: *const Settings,
    workspace: *Workspace,
    batch: Batch,
    out: *[field_elements_per_cell]Fr,
) void {
    var used: [cells_per_ext_blob]bool = @splat(false);
    for (batch.cell_indices) |cell_index| used[@intCast(cell_index)] = true;
    @memset(out, Fr.zero);
    for (used, 0..) |is_used, cell_index| {
        if (!is_used) continue;
        const start = cell_index * field_elements_per_cell;
        const column = workspace.extended[start..][0..field_elements_per_cell];
        cells.evaluations_brp_to_monomial(settings.roots, column);
        const reversed = fft.reverse_bits(@intCast(cell_index), 7);
        const inverse_shift = settings.roots[fft.ext_size - reversed];
        var factor = Fr.one;
        for (out, column) |*sum, coefficient| {
            sum.* = sum.add(coefficient.mul(factor));
            factor = factor.mul(inverse_shift);
        }
    }
    assert(used[@intCast(batch.cell_indices[0])]);
}

fn check(
    settings: *const Settings,
    workspace: *Workspace,
    batch: Batch,
    scratch: VerifyScratch,
    unique_count: u32,
) Error!bool {
    const count = batch.cell_indices.len;
    const powers = scratch.powers[0..count];
    const proof_points = scratch.points[0..count];
    // LL = sum_k r^k proof_k.
    for (scratch.scalars[0..count], powers) |*scalar, power| scalar.* = power.to_int();
    const left = bls.msm.msm(G1, proof_points, scratch.scalars[0..count]);
    // RLC weights and RLP scalars r^k h_k^64 share one MSM over proofs then commitments.
    const weights = scratch.weights[0..unique_count];
    @memset(weights, Fr.zero);
    for (scratch.commitment_indices[0..count], powers) |index, power| {
        weights[index] = weights[index].add(power);
    }
    for (scratch.scalars[0..count], powers, batch.cell_indices) |*scalar, power, cell_index| {
        const reversed = fft.reverse_bits(@intCast(cell_index), 7);
        scalar.* = power.mul(settings.roots[reversed * field_elements_per_cell]).to_int();
    }
    for (scratch.scalars[count..][0..unique_count], weights) |*scalar, weight| {
        scalar.* = weight.to_int();
    }
    const total = count + unique_count;
    const rlc_plus_rlp = bls.msm.msm(G1, scratch.points[0..total], scratch.scalars[0..total]);
    // RLI: commitment to the aggregated interpolation polynomial.
    try aggregate_columns(workspace, batch, powers);
    var interpolation: [field_elements_per_cell]Fr = undefined;
    aggregated_interpolation(settings, workspace, batch, &interpolation);
    var interpolation_scalars: [field_elements_per_cell]u256 = undefined;
    for (&interpolation_scalars, interpolation) |*scalar, value| scalar.* = value.to_int();
    const rli = bls.msm.msm(G1, settings.g1_monomial, &interpolation_scalars);
    const right = rlc_plus_rlp.sub(rli);
    // e(LL, [tau^64]G2) * e(-RL, G2) == 1.
    const pairs = [2]bls.pairing.PreparedPair{
        .{ .g1 = left.to_affine(), .g2 = settings.tau_cell_g2 },
        .{ .g1 = right.neg().to_affine(), .g2 = &verify_4844.prepared_generator },
    };
    return bls.pairing.pairing_check_prepared(&pairs);
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const blob_api = @import("blob.zig");

test "cells verify: deduplication keeps first-appearance order" {
    var commitments: [5]Commitment = undefined;
    for (&commitments, [_]u8{ 7, 3, 7, 9, 3 }) |*commitment, tag| commitment.* = @splat(tag);
    var indices: [5]u32 = undefined;
    try testing.expectEqual(@as(u32, 3), deduplicate(&commitments, &indices));
    try testing.expectEqualSlices(u32, &.{ 0, 1, 0, 2, 1 }, &indices);
}

fn verify_for_test(
    commitments: []const Commitment,
    indices: []const u64,
    cell_values: []const Cell,
    proofs: []const Proof,
) Error!bool {
    var storage: VerifyStorage(2) = .{};
    const settings = cells.shared_settings() catch unreachable; // Embedded setup.
    const workspace = cells.shared_workspace();
    const scratch = storage.scratch();
    return verify_cell_kzg_proof_batch(
        settings,
        workspace,
        scratch,
        commitments,
        indices,
        cell_values,
        proofs,
    );
}

test "cells verify: malformed batches are errors" {
    const identity: Commitment = bls.g1.compress(G1Affine.identity);
    const one = [1]Commitment{identity};
    const zero_cell: Cell = @splat(0);
    const zero_cells = [1]Cell{zero_cell};
    const index_zero = [1]u64{0};
    // Empty batch is valid; mismatched lengths are not.
    try testing.expect(try verify_for_test(&.{}, &.{}, &.{}, &.{}));
    try testing.expectError(error.InvalidLength, verify_for_test(&one, &.{}, &zero_cells, &one));
    const index_high = [1]u64{128};
    try testing.expectError(
        error.InvalidCellIndex,
        verify_for_test(&one, &index_high, &zero_cells, &one),
    );
    var bad_cell = zero_cell;
    std.mem.writeInt(u256, bad_cell[32..64], kzg.bls_modulus, .big);
    try testing.expectError(
        error.InvalidFieldElement,
        verify_for_test(&one, &index_zero, &.{bad_cell}, &one),
    );
    const garbage = [1]Proof{@splat(0xff)};
    try testing.expectError(
        error.InvalidPoint,
        verify_for_test(&one, &index_zero, &zero_cells, &garbage),
    );
    try testing.expectError(
        error.InvalidPoint,
        verify_for_test(&garbage, &index_zero, &zero_cells, &one),
    );
    const three = [3]u64{ 0, 1, 2 };
    const commitments3 = [3]Commitment{ identity, identity, identity };
    const cells3 = [3]Cell{ zero_cell, zero_cell, zero_cell };
    try testing.expectError(
        error.ScratchTooSmall,
        verify_for_test(&commitments3, &three, &cells3, &commitments3),
    );
}

test "cells verify: zero cells with identity commitment and proofs verify" {
    const settings = try cells.shared_settings();
    var storage: VerifyStorage(2) = .{};
    const identity: Commitment = bls.g1.compress(G1Affine.identity);
    const zero_cell: Cell = @splat(0);
    try testing.expect(try verify_cell_kzg_proof_batch(
        settings,
        cells.shared_workspace(),
        storage.scratch(),
        &.{ identity, identity },
        &.{ 5, 99 },
        &.{ zero_cell, zero_cell },
        &.{ identity, identity },
    ));
    var one_cell = zero_cell;
    one_cell[31] = 1;
    try testing.expect(!try verify_cell_kzg_proof_batch(
        settings,
        cells.shared_workspace(),
        storage.scratch(),
        &.{identity},
        &.{5},
        &.{one_cell},
        &.{identity},
    ));
}

var seeded_cells: cells.Cells = undefined;
var seeded_proofs: cells.Proofs = undefined;

test "cells verify: random subsets verify, corruptions fail (seeded)" {
    if (!cells.heavy_tests) return error.SkipZigTest; // FK20 proofs are slow in Debug.
    const settings = try cells.shared_settings();
    const workspace = cells.shared_workspace();
    const blob_settings_storage = &seeded_blob_storage;
    const blob_settings = try blob_api.Settings.init(blob_settings_storage);
    var prng = Prng.init(0xce11_0e21);
    var blob: cells.Blob = undefined;
    for (0..kzg.field_elements_per_blob) |index| {
        prng.fill(blob[index * 32 ..][0..32]);
        blob[index * 32] &= 0x3f;
    }
    const blob_workspace = &seeded_blob_workspace;
    const commitment = try blob_api.blob_to_kzg_commitment(&blob_settings, blob_workspace, &blob);
    const inputs = .{ settings, workspace, &blob };
    const outputs = .{ &seeded_cells, &seeded_proofs };
    try @call(.auto, cells.compute_cells_and_kzg_proofs, inputs ++ outputs);
    var storage: VerifyStorage(8) = .{};
    var commitments: [8]Commitment = @splat(commitment);
    var indices: [8]u64 = undefined;
    var picked_cells: [8]Cell = undefined;
    var picked_proofs: [8]Proof = undefined;
    for (0..6) |_| {
        const count: usize = @intCast(prng.range(1, 8));
        for (0..count) |slot| {
            const cell_index = prng.below(cells_per_ext_blob);
            indices[slot] = cell_index;
            picked_cells[slot] = seeded_cells[cell_index];
            picked_proofs[slot] = seeded_proofs[cell_index];
        }
        const args = .{ settings, workspace, storage.scratch(), commitments[0..count] };
        const tail = .{ indices[0..count], picked_cells[0..count], picked_proofs[0..count] };
        try testing.expect(try @call(.auto, verify_cell_kzg_proof_batch, args ++ tail));
        // A wrong index, a changed element, or a swapped proof breaks the batch.
        const victim = prng.below(count);
        indices[victim] = (indices[victim] + 1) % cells_per_ext_blob;
        try testing.expect(!try @call(.auto, verify_cell_kzg_proof_batch, args ++ tail));
        indices[victim] = (indices[victim] + cells_per_ext_blob - 1) % cells_per_ext_blob;
        picked_cells[victim][31 + 32 * prng.below(field_elements_per_cell)] ^= 1;
        try testing.expect(!try @call(.auto, verify_cell_kzg_proof_batch, args ++ tail));
        picked_cells[victim] = seeded_cells[indices[victim]];
        picked_proofs[victim] = seeded_proofs[(indices[victim] + 3) % cells_per_ext_blob];
        try testing.expect(!try @call(.auto, verify_cell_kzg_proof_batch, args ++ tail));
    }
    commitments[0][0] ^= 0x20; // Negated commitment: valid point, wrong polynomial.
    try testing.expect(!try verify_cell_kzg_proof_batch(
        settings,
        workspace,
        storage.scratch(),
        commitments[0..1],
        &.{0},
        seeded_cells[0..1],
        seeded_proofs[0..1],
    ));
}

var seeded_blob_storage: blob_api.Settings.Storage = undefined;
var seeded_blob_workspace: blob_api.Workspace = undefined;

test "cells verify: random inputs never crash (seeded)" {
    var prng = Prng.init(0xf022);
    var commitments: [2]Commitment = undefined;
    var proofs: [2]Proof = undefined;
    var cell_values: [2]Cell = @splat(@splat(0));
    var indices: [2]u64 = undefined;
    for (0..8) |_| {
        for (0..2) |slot| {
            prng.fill(&commitments[slot]);
            prng.fill(&proofs[slot]);
            // Valid-looking flags half the time, so decoding reaches the curve checks.
            if (prng.chance(1, 2)) commitments[slot][0] = 0x80 | (commitments[slot][0] & 0x1f);
            if (prng.chance(1, 2)) proofs[slot] = bls.g1.compress(G1Affine.identity);
            prng.fill(cell_values[slot][0..64]);
            indices[slot] = prng.below(140);
        }
        const count: usize = @intCast(prng.below(3));
        const result = verify_for_test(
            commitments[0..count],
            indices[0..count],
            cell_values[0..count],
            proofs[0..count],
        );
        if (count == 0) try testing.expect(try result);
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    const settings = try cells.shared_settings();
    var storage: VerifyStorage(2) = .{};
    var commitments: [2]Commitment = undefined;
    var proofs: [2]Proof = undefined;
    var cell_values: [2]Cell = @splat(@splat(0));
    var indices: [2]u64 = undefined;
    for (0..2) |slot| {
        smith.bytes(&commitments[slot]);
        smith.bytes(&proofs[slot]);
        // Sparse cells keep the fuzz fast; the head reaches non-canonical elements.
        _ = smith.slice(cell_values[slot][0..96]);
        indices[slot] = smith.value(u8);
    }
    const count: usize = smith.value(u8) % 3;
    _ = verify_cell_kzg_proof_batch(
        settings,
        cells.shared_workspace(),
        storage.scratch(),
        commitments[0..count],
        indices[0..count],
        cell_values[0..count],
        proofs[0..count],
    ) catch {};
}

test "cells verify: coverage-guided fuzz (never crashes)" {
    try testing.fuzz({}, fuzz_one, .{});
}

//! KZG prover for EIP-4844 blobs: `blob_to_kzg_commitment` and `compute_blob_kzg_proof`
//! from `common.crypto.kzg.blob` (c-kzg vector tested), with the decoded setup and the
//! scratch workspace allocated once in `Prover.init` (static allocation).

const std = @import("std");
const assert = std.debug.assert;
const kzg = @import("../../common/crypto/kzg/root.zig");
const blob_kzg = kzg.blob;

pub const Blob = blob_kzg.Blob;
pub const Commitment = blob_kzg.Commitment;
pub const Proof = blob_kzg.Proof;

pub const versioned_hash = kzg.versioned_hash;
pub const versioned_hash_version = kzg.versioned_hash_version_kzg;

pub const Error = blob_kzg.Error;

const cells = kzg.cells;
pub const cell_proofs_per_blob = cells.cells_per_ext_blob;
pub const CellProofs = cells.Proofs;
pub const CellError = cells.Error;

/// EIP-7594 (Osaka) cell proofs for version-1 sidecars, with the fixed-base FK20 tables
/// (about 25 MiB, built once in `init`): 93 ms per blob instead of 202 ms in release
/// builds, same proofs. Setup takes about a second in release and minutes in Debug, so
/// only a batcher that sends version-1 sidecars builds one.
pub const CellProver = struct {
    storage: *cells.Settings.Storage,
    workspace: *cells.Workspace,
    tables: *kzg.fk20.Tables,
    cells_out: *cells.Cells,
    settings: cells.Settings,

    pub fn init(allocator: std.mem.Allocator) !CellProver {
        const storage = try allocator.create(cells.Settings.Storage);
        errdefer allocator.destroy(storage);
        const workspace = try allocator.create(cells.Workspace);
        errdefer allocator.destroy(workspace);
        const tables = try allocator.create(kzg.fk20.Tables);
        errdefer allocator.destroy(tables);
        const cells_out = try allocator.create(cells.Cells);
        errdefer allocator.destroy(cells_out);
        var settings = try cells.Settings.init(storage);
        settings.attach_prover_tables(tables);
        assert(settings.tables != null and settings.columns != null);
        return .{
            .storage = storage,
            .workspace = workspace,
            .tables = tables,
            .cells_out = cells_out,
            .settings = settings,
        };
    }

    pub fn deinit(prover: *CellProver, allocator: std.mem.Allocator) void {
        allocator.destroy(prover.storage);
        allocator.destroy(prover.workspace);
        allocator.destroy(prover.tables);
        allocator.destroy(prover.cells_out);
        prover.* = undefined;
    }

    /// The 128 cell proofs of `blob` (the cells themselves stay in `cells_out`).
    pub fn cell_proofs(prover: *CellProver, blob: *const Blob, out: *CellProofs) CellError!void {
        assert(prover.settings.tables == prover.tables);
        try cells.compute_cells_and_kzg_proofs(
            &prover.settings,
            prover.workspace,
            blob,
            prover.cells_out,
            out,
        );
        assert(out[0][0] & 0x80 != 0); // Compressed point flag.
    }
};

pub const Prover = struct {
    storage: *blob_kzg.Settings.Storage,
    workspace: *blob_kzg.Workspace,
    settings: blob_kzg.Settings,

    pub fn init(allocator: std.mem.Allocator) !Prover {
        const storage = try allocator.create(blob_kzg.Settings.Storage);
        errdefer allocator.destroy(storage);
        const workspace = try allocator.create(blob_kzg.Workspace);
        errdefer allocator.destroy(workspace);
        const settings = try blob_kzg.Settings.init(storage);
        return .{ .storage = storage, .workspace = workspace, .settings = settings };
    }

    pub fn deinit(prover: *Prover, allocator: std.mem.Allocator) void {
        allocator.destroy(prover.storage);
        allocator.destroy(prover.workspace);
        prover.* = undefined;
    }

    /// `settings` points into `storage`, which is heap-allocated, so `Prover` may move.
    pub fn commitment(prover: *Prover, blob: *const Blob) Error!Commitment {
        assert(prover.settings.g1_lagrange == &prover.storage.g1_lagrange);
        const settings = &prover.settings;
        const result = try blob_kzg.blob_to_kzg_commitment(settings, prover.workspace, blob);
        assert(result[0] & 0x80 != 0); // Compressed point flag.
        return result;
    }

    /// `compute_blob_kzg_proof(blob, commitment)`.
    pub fn blob_proof(
        prover: *Prover,
        blob: *const Blob,
        commitment_bytes: *const Commitment,
    ) Error!Proof {
        const proof = try blob_kzg.compute_blob_kzg_proof(
            &prover.settings,
            prover.workspace,
            blob,
            commitment_bytes,
        );
        assert(proof[0] & 0x80 != 0);
        return proof;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "kzg prover: proofs verify with verify_blob_kzg_proof; tampering fails" {
    var prover = try Prover.init(testing.allocator);
    defer prover.deinit(testing.allocator);
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 0);
    var prng = Prng.init(0x4844);
    for (0..blob_kzg.field_elements) |index| {
        // Random canonical field elements: top byte zero keeps them below r.
        prng.fill(blob[index * 32 + 1 ..][0..31]);
    }
    const commitment_bytes = try prover.commitment(blob);
    const proof = try prover.blob_proof(blob, &commitment_bytes);
    const settings = &prover.settings;
    const workspace = prover.workspace;
    try testing.expect(try blob_kzg.verify_blob_kzg_proof(
        settings,
        workspace,
        blob,
        &commitment_bytes,
        &proof,
    ));
    blob[100] ^= 1;
    try testing.expect(!try blob_kzg.verify_blob_kzg_proof(
        settings,
        workspace,
        blob,
        &commitment_bytes,
        &proof,
    ));
}

test "kzg prover: zero blob commits to infinity; non-canonical words rejected" {
    var prover = try Prover.init(testing.allocator);
    defer prover.deinit(testing.allocator);
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 0);
    const commitment_bytes = try prover.commitment(blob);
    try testing.expectEqual(@as(u8, 0xc0), commitment_bytes[0]);
    for (commitment_bytes[1..]) |byte| try testing.expectEqual(@as(u8, 0), byte);
    @memset(blob[0..32], 0xff);
    try testing.expectError(error.InvalidFieldElement, prover.commitment(blob));
}

test "kzg cell prover: proofs verify with verify_cell_kzg_proof_batch" {
    if (!cells.heavy_tests) return error.SkipZigTest; // FK20 setup takes minutes in Debug.
    var prover = try CellProver.init(testing.allocator);
    defer prover.deinit(testing.allocator);
    var blob_prover = try Prover.init(testing.allocator);
    defer blob_prover.deinit(testing.allocator);
    const blob = try testing.allocator.create(Blob);
    defer testing.allocator.destroy(blob);
    @memset(blob, 0);
    var prng = Prng.init(0x7594);
    for (0..blob_kzg.field_elements) |index| prng.fill(blob[index * 32 + 1 ..][0..31]);
    const proofs = try testing.allocator.create(CellProofs);
    defer testing.allocator.destroy(proofs);
    try prover.cell_proofs(blob, proofs);
    const commitment_bytes = try blob_prover.commitment(blob);
    const storage = try testing.allocator.create(cells.VerifyStorage(cell_proofs_per_blob));
    defer testing.allocator.destroy(storage);
    var commitments: [cell_proofs_per_blob]Commitment = @splat(commitment_bytes);
    var indices: [cell_proofs_per_blob]u64 = undefined;
    for (&indices, 0..) |*index, position| index.* = position;
    const scratch = storage.scratch();
    const settings = &prover.settings;
    const workspace = prover.workspace;
    try testing.expect(try cells.verify_cell_kzg_proof_batch(
        settings,
        workspace,
        scratch,
        &commitments,
        &indices,
        prover.cells_out,
        proofs,
    ));
    commitments[5][47] ^= 1;
    const tampered = cells.verify_cell_kzg_proof_batch(
        settings,
        workspace,
        scratch,
        &commitments,
        &indices,
        prover.cells_out,
        proofs,
    ) catch false;
    try testing.expect(!tampered);
}

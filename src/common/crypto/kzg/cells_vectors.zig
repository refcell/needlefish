//! c-kzg-4844 public EIP-7594 test vectors (`tests/*/kzg-mainnet/*/data.yaml`), curated
//! into `cell_vectors.txt` to stay small. Cells are written as `blob.cell` references
//! into the cells of the seven c-kzg blobs already stored in `blob_vectors.bin` (each
//! checked against the sha256 of the vector's full cell output), `=` repeats the previous
//! item, and `-` is an empty list. Line kinds:
//!   K blob cells_sha256 proofs_hex           compute_cells(_and_kzg_proofs), valid
//!   C synthetic_blob                         compute_cells(_and_kzg_proofs), invalid blob
//!   V verdict commitments indices cells proofs   verify_cell_kzg_proof_batch
//!   R blob|E indices cells                   recover_cells_and_kzg_proofs
//!   H challenge commitments commitment_indices cell_indices cells proofs
//!                                            compute_verify_cell_kzg_proof_batch_challenge
//! Dropped: wrong-length blobs (impossible with a fixed-size blob type) and the two
//! largest challenge cases (all cells / many cells, ~1 MB; the 128-cell verify cases
//! cover the same hash path).

const std = @import("std");
const assert = std.debug.assert;
const kzg = @import("root.zig");
const cells = @import("cells.zig");
const cells_verify = @import("cells_verify.zig");
const sha256 = @import("../sha256.zig");

const testing = std.testing;
const Cell = cells.Cell;
const Cells = cells.Cells;
const Commitment = cells.Commitment;
const Proof = cells.Proof;

const vector_lines = @embedFile("cell_vectors.txt");
const vector_blobs = @embedFile("blob_vectors.bin");
const stored_blob_count = 7;
const items_max = cells.cells_per_ext_blob + 1;

comptime {
    assert(vector_blobs.len == stored_blob_count * kzg.bytes_per_blob);
}

fn stored_blob(index: usize) *const cells.Blob {
    assert(index < stored_blob_count);
    return vector_blobs[index * kzg.bytes_per_blob ..][0..kzg.bytes_per_blob];
}

/// Cells of the stored blobs, computed on first use and checked against `K` lines.
var blob_cells: [stored_blob_count]Cells = undefined;
var blob_cells_ready: [stored_blob_count]bool = @splat(false);
var synthetic_blob: cells.Blob = undefined;
var output_cells: Cells = undefined;
var output_proofs: cells.Proofs = undefined;

fn cells_of(index: usize) !*const Cells {
    if (index >= stored_blob_count) return error.BadVector;
    if (!blob_cells_ready[index]) {
        const settings = try cells.shared_settings();
        const workspace = cells.shared_workspace();
        try cells.compute_cells(settings, workspace, stored_blob(index), &blob_cells[index]);
        blob_cells_ready[index] = true;
    }
    return &blob_cells[index];
}

const Fields = std.mem.TokenIterator(u8, .scalar);

fn next_field(fields: *Fields) ![]const u8 {
    return fields.next() orelse error.BadVector;
}

/// A comma-separated list; `-` is empty, `=` repeats the previous item.
const List = struct {
    items: [items_max][]const u8 = undefined,
    count: usize = 0,

    fn parse(text: []const u8) !List {
        var list: List = .{};
        if (std.mem.eql(u8, text, "-")) return list;
        var parts = std.mem.tokenizeScalar(u8, text, ',');
        while (parts.next()) |part| {
            if (list.count == items_max) return error.BadVector;
            const item = if (std.mem.eql(u8, part, "=")) blk: {
                if (list.count == 0) return error.BadVector;
                break :blk list.items[list.count - 1];
            } else part;
            list.items[list.count] = item;
            list.count += 1;
        }
        return list;
    }
};

fn parse_hex(comptime length: usize, hex: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    if (hex.len != 2 * length) return error.BadVector;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

/// A cell item: `blob.cell` reference or 4096 hex digits.
fn parse_cell(item: []const u8) !Cell {
    if (std.mem.indexOfScalar(u8, item, '.')) |dot| {
        const blob_index = try std.fmt.parseInt(usize, item[0..dot], 10);
        const cell_index = try std.fmt.parseInt(usize, item[dot + 1 ..], 10);
        if (cell_index >= cells.cells_per_ext_blob) return error.BadVector;
        return (try cells_of(blob_index))[cell_index];
    }
    return parse_hex(cells.bytes_per_cell, item);
}

/// Wrong-length hex cells become a non-canonical cell (all 0xff), an error verdict.
fn parse_cell_or_invalid(item: []const u8) !Cell {
    if (std.mem.indexOfScalar(u8, item, '.') != null) return parse_cell(item);
    if (item.len != 2 * cells.bytes_per_cell) return @splat(0xff);
    return parse_cell(item);
}

/// Proof items are `blob.cell` references into `K` proofs or hex.
fn parse_proof(item: []const u8) !Proof {
    if (std.mem.indexOfScalar(u8, item, '.')) |dot| {
        const blob_index = try std.fmt.parseInt(usize, item[0..dot], 10);
        const cell_index = try std.fmt.parseInt(usize, item[dot + 1 ..], 10);
        if (blob_index >= stored_blob_count or cell_index >= cells.cells_per_ext_blob) {
            return error.BadVector;
        }
        return stored_proofs[blob_index][cell_index];
    }
    return parse_hex(48, item);
}

/// Proofs of the stored blobs, filled from `K` lines (which come first in the file).
var stored_proofs: [stored_blob_count]cells.Proofs = undefined;

const Batch = struct {
    commitments: [items_max]Commitment = undefined,
    indices: [items_max]u64 = undefined,
    cells: [items_max]Cell = undefined,
    proofs: [items_max]Proof = undefined,
    commitment_count: usize = 0,
    index_count: usize = 0,
    cell_count: usize = 0,
    proof_count: usize = 0,
};

var batch: Batch = .{};

fn parse_indices(text: []const u8, out: []u64) !usize {
    const list = try List.parse(text);
    for (list.items[0..list.count], out[0..list.count]) |item, *slot| {
        slot.* = try std.fmt.parseInt(u64, item, 10);
    }
    return list.count;
}

fn parse_batch(fields: *Fields) !void {
    const commitments = try List.parse(try next_field(fields));
    for (commitments.items[0..commitments.count], 0..) |item, slot| {
        // Wrong-length encodings become an undecodable point (an error verdict).
        batch.commitments[slot] = parse_hex(48, item) catch @splat(0xff);
    }
    batch.commitment_count = commitments.count;
    batch.index_count = try parse_indices(try next_field(fields), &batch.indices);
    const cell_list = try List.parse(try next_field(fields));
    for (cell_list.items[0..cell_list.count], 0..) |item, slot| {
        batch.cells[slot] = try parse_cell_or_invalid(item);
    }
    batch.cell_count = cell_list.count;
    const proofs = try List.parse(try next_field(fields));
    for (proofs.items[0..proofs.count], 0..) |item, slot| {
        // Malformed proofs (wrong length) map to an error verdict before verification.
        batch.proofs[slot] = parse_proof(item) catch @splat(0xff);
    }
    batch.proof_count = proofs.count;
}

fn digest_of_cells(value: *const Cells) [32]u8 {
    return sha256.sha256(std.mem.asBytes(value));
}

fn run_compute(fields: *Fields) !void {
    const blob_index = try std.fmt.parseInt(usize, try next_field(fields), 10);
    const expected_digest = try parse_hex(32, try next_field(fields));
    const proofs_hex = try next_field(fields);
    if (proofs_hex.len != 2 * 48 * cells.cells_per_ext_blob) return error.BadVector;
    _ = try std.fmt.hexToBytes(std.mem.asBytes(&stored_proofs[blob_index]), proofs_hex);
    const computed = try cells_of(blob_index);
    try testing.expectEqual(expected_digest, digest_of_cells(computed));
    if (!cells.heavy_tests) return;
    const settings = try cells.shared_settings();
    try cells.compute_cells_and_kzg_proofs(
        settings,
        cells.shared_workspace(),
        stored_blob(blob_index),
        &output_cells,
        &output_proofs,
    );
    try testing.expectEqual(expected_digest, digest_of_cells(&output_cells));
    const expected_proofs = std.mem.asBytes(&stored_proofs[blob_index]);
    try testing.expectEqualSlices(u8, expected_proofs, std.mem.asBytes(&output_proofs));
    // The fixed-base prover tables must give the same proofs.
    try cells.compute_cells_and_kzg_proofs(
        try cells.shared_settings_with_tables(),
        cells.shared_workspace(),
        stored_blob(blob_index),
        &output_cells,
        &output_proofs,
    );
    try testing.expectEqualSlices(u8, expected_proofs, std.mem.asBytes(&output_proofs));
}

/// Synthetic invalid blobs of blob.zig's vectors: 7 = all 0xff, 8 = zeros with one
/// element equal to the modulus.
fn run_invalid_blob(fields: *Fields) !void {
    const which = try std.fmt.parseInt(u32, try next_field(fields), 10);
    switch (which) {
        7 => synthetic_blob = @splat(0xff),
        8 => {
            synthetic_blob = @splat(0);
            std.mem.writeInt(u256, synthetic_blob[2111 * 32 ..][0..32], kzg.bls_modulus, .big);
        },
        else => return error.BadVector,
    }
    const settings = try cells.shared_settings();
    const workspace = cells.shared_workspace();
    const result = cells.compute_cells(settings, workspace, &synthetic_blob, &output_cells);
    try testing.expectError(error.InvalidFieldElement, result);
    if (!cells.heavy_tests) return;
    try testing.expectError(error.InvalidFieldElement, cells.compute_cells_and_kzg_proofs(
        settings,
        workspace,
        &synthetic_blob,
        &output_cells,
        &output_proofs,
    ));
}

var verify_storage: cells_verify.VerifyStorage(items_max) = .{};

fn run_verify(fields: *Fields) !void {
    const verdict = (try next_field(fields))[0];
    try parse_batch(fields);
    // Debug: subgroup checks and MSMs are slow unoptimised, so only small batches run.
    if (!cells.heavy_tests and batch.index_count > 4) return;
    const settings = try cells.shared_settings();
    const result = cells_verify.verify_cell_kzg_proof_batch(
        settings,
        cells.shared_workspace(),
        verify_storage.scratch(),
        batch.commitments[0..batch.commitment_count],
        batch.indices[0..batch.index_count],
        batch.cells[0..batch.cell_count],
        batch.proofs[0..batch.proof_count],
    );
    switch (verdict) {
        '1' => try testing.expect(try result),
        '0' => try testing.expect(!(try result)),
        'E' => try testing.expect(std.meta.isError(result)),
        else => return error.BadVector,
    }
}

fn run_recover(fields: *Fields) !void {
    const expected = try next_field(fields);
    batch.index_count = try parse_indices(try next_field(fields), &batch.indices);
    const cell_list = try List.parse(try next_field(fields));
    for (cell_list.items[0..cell_list.count], 0..) |item, slot| {
        batch.cells[slot] = try parse_cell_or_invalid(item);
    }
    batch.cell_count = cell_list.count;
    const settings = try cells.shared_settings();
    const workspace = cells.shared_workspace();
    const indices = batch.indices[0..batch.index_count];
    const cell_values = batch.cells[0..batch.cell_count];
    if (expected[0] == 'E') {
        const result =
            cells.recover_cells(settings, workspace, indices, cell_values, &output_cells);
        return testing.expect(std.meta.isError(result));
    }
    const blob_index = try std.fmt.parseInt(usize, expected, 10);
    if (!cells.heavy_tests) {
        try cells.recover_cells(settings, workspace, indices, cell_values, &output_cells);
    } else {
        try cells.recover_cells_and_kzg_proofs(
            settings,
            workspace,
            indices,
            cell_values,
            &output_cells,
            &output_proofs,
        );
        const expected_proofs = std.mem.asBytes(&stored_proofs[blob_index]);
        try testing.expectEqualSlices(u8, expected_proofs, std.mem.asBytes(&output_proofs));
    }
    const expected_cells = try cells_of(blob_index);
    const got = std.mem.asBytes(&output_cells);
    try testing.expectEqualSlices(u8, std.mem.asBytes(expected_cells), got);
}

fn run_challenge(fields: *Fields) !void {
    const expected = try parse_hex(32, try next_field(fields));
    const commitments = try List.parse(try next_field(fields));
    for (commitments.items[0..commitments.count], 0..) |item, slot| {
        batch.commitments[slot] = try parse_hex(48, item);
    }
    var commitment_indices64: [items_max]u64 = undefined;
    const count = try parse_indices(try next_field(fields), &commitment_indices64);
    var commitment_indices: [items_max]u32 = undefined;
    for (commitment_indices[0..count], commitment_indices64[0..count]) |*out, value| {
        out.* = @intCast(value);
    }
    batch.index_count = try parse_indices(try next_field(fields), &batch.indices);
    const cell_list = try List.parse(try next_field(fields));
    for (cell_list.items[0..cell_list.count], 0..) |item, slot| {
        batch.cells[slot] = try parse_cell(item);
    }
    const proofs = try List.parse(try next_field(fields));
    for (proofs.items[0..proofs.count], 0..) |item, slot| {
        batch.proofs[slot] = try parse_proof(item);
    }
    if (count != batch.index_count or cell_list.count != count) return error.BadVector;
    const challenge = cells_verify.compute_challenge(.{
        .commitments = batch.commitments[0..commitments.count],
        .cell_indices = batch.indices[0..count],
        .cells = batch.cells[0..count],
        .proofs = batch.proofs[0..count],
    }, commitment_indices[0..count]);
    try testing.expectEqual(expected, challenge.to_bytes_be());
}

test "cells: c-kzg-4844 EIP-7594 vectors" {
    var lines = std.mem.tokenizeScalar(u8, vector_lines, '\n');
    var counts: [5]u32 = @splat(0);
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = (try next_field(&fields))[0];
        switch (kind) {
            'K' => try run_compute(&fields),
            'C' => try run_invalid_blob(&fields),
            'V' => try run_verify(&fields),
            'R' => try run_recover(&fields),
            'H' => try run_challenge(&fields),
            else => return error.BadVector,
        }
        counts[std.mem.indexOfScalar(u8, "KCVRH", kind).?] += 1;
    }
    // 7 valid blobs, 4 invalid blobs, 32 verify, 18 recover, 8 challenge cases.
    try testing.expectEqualSlices(u32, &.{ 7, 4, 32, 18, 8 }, &counts);
}

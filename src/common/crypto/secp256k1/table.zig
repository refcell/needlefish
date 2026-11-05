//! Compile-time precomputed multiples of the generator G.
//!
//! Computed with exact `comptime_int` affine arithmetic, so the tables never depend
//! on the runtime field code they are used to accelerate (and act as an independent
//! check of it in tests).
//!
//! - `g_odd[i] = (2i + 1) G` and `g_lambda_odd[i] = lambda (2i + 1) G = (beta x, y)`
//!   for the variable-time wNAF double-scalar multiplication.
//! - `gen_rows[i][j] = (j + 1) 16^i G` for the constant-time signed 4-bit window
//!   multiplication used by signing and public key derivation.

const std = @import("std");
const assert = std.debug.assert;
const field = @import("field.zig");
const Fe = field.Fe;

pub const Affine = struct { x: Fe, y: Fe };

pub const g_x_int: u256 = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
pub const g_y_int: u256 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
/// Cube root of unity mod p: lambda (x, y) = (beta x, y).
pub const beta_int: u256 = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE;

/// wNAF window for the generator: 2^(window - 2) odd multiples per table.
pub const g_window = 10;
pub const g_table_size = 1 << (g_window - 2);

/// Constant-time generator multiplication: 65 rows (64 signed nibbles plus the final
/// carry) of 8 multiples each.
pub const gen_row_count = 65;
pub const gen_row_size = 8;

const p: comptime_int = field.p_int;

const PointInt = struct { x: comptime_int, y: comptime_int };

comptime {
    @setEvalBranchQuota(10_000);
    const x: comptime_int = g_x_int;
    const y: comptime_int = g_y_int;
    assert(@mod(y * y - x * x * x - 7, p) == 0);
    const beta: comptime_int = beta_int;
    assert((beta * beta * beta) % p == 1);
}

fn modulo(comptime value: comptime_int) comptime_int {
    const reduced = @mod(value, p);
    assert(reduced >= 0 and reduced < p);
    return reduced;
}

/// Modular inverse by the extended Euclidean algorithm (bounded iteration).
fn inverse(comptime value: comptime_int) comptime_int {
    assert(@mod(value, p) != 0);
    var old_r: comptime_int = modulo(value);
    var r: comptime_int = p;
    var old_s: comptime_int = 1;
    var s: comptime_int = 0;
    var iterations: u32 = 0;
    while (r != 0) : (iterations += 1) {
        assert(iterations < 1024);
        const quotient = @divFloor(old_r, r);
        const next_r = old_r - quotient * r;
        old_r = r;
        r = next_r;
        const next_s = old_s - quotient * s;
        old_s = s;
        s = next_s;
    }
    assert(old_r == 1);
    return modulo(old_s);
}

fn point_add(comptime a: PointInt, comptime b: PointInt) PointInt {
    assert(a.x != b.x);
    const slope = modulo((b.y - a.y) * inverse(b.x - a.x));
    const x = modulo(slope * slope - a.x - b.x);
    return .{ .x = x, .y = modulo(slope * (a.x - x) - a.y) };
}

fn point_double(comptime a: PointInt) PointInt {
    assert(a.y != 0);
    const slope = modulo(3 * a.x * a.x * inverse(2 * a.y));
    const x = modulo(slope * slope - 2 * a.x);
    return .{ .x = x, .y = modulo(slope * (a.x - x) - a.y) };
}

fn to_affine(comptime point: PointInt) Affine {
    return .{ .x = Fe.from_int(point.x), .y = Fe.from_int(point.y) };
}

const generator: PointInt = .{ .x = g_x_int, .y = g_y_int };

pub const g_odd: [g_table_size]Affine = blk: {
    @setEvalBranchQuota(10_000_000);
    var table: [g_table_size]Affine = undefined;
    const twice = point_double(generator);
    var current = generator;
    for (0..g_table_size) |index| {
        table[index] = to_affine(current);
        if (index + 1 < g_table_size) current = point_add(current, twice);
    }
    break :blk table;
};

pub const g_lambda_odd: [g_table_size]Affine = blk: {
    @setEvalBranchQuota(1_000_000);
    var table: [g_table_size]Affine = undefined;
    const beta = Fe.from_int(beta_int);
    for (&table, g_odd) |*entry, base| {
        const x: comptime_int = base.x.to_int();
        const b: comptime_int = beta.to_int();
        entry.* = .{ .x = Fe.from_int(modulo(x * b)), .y = base.y };
    }
    break :blk table;
};

pub const gen_rows: [gen_row_count][gen_row_size]Affine = blk: {
    @setEvalBranchQuota(100_000_000);
    var rows: [gen_row_count][gen_row_size]Affine = undefined;
    var base = generator;
    for (&rows, 0..) |*row, row_index| {
        var current = base;
        row[0] = to_affine(current);
        const twice = point_double(base);
        row[1] = to_affine(twice);
        current = twice;
        for (2..gen_row_size) |entry| {
            current = point_add(current, base);
            row[entry] = to_affine(current);
        }
        if (row_index + 1 < gen_row_count) {
            // 16 * base = 2 * (8 * base).
            base = point_double(current);
        }
    }
    break :blk rows;
};

test "table: entries are on the curve" {
    const seven = Fe.from_int(7);
    for (g_odd ++ g_lambda_odd) |point| {
        try std.testing.expect(point.y.sqr().equal(point.x.sqr().mul(point.x).add(seven)));
    }
    for (gen_rows) |row| {
        for (row) |point| {
            try std.testing.expect(point.y.sqr().equal(point.x.sqr().mul(point.x).add(seven)));
        }
    }
}

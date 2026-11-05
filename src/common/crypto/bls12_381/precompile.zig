//! EIP-2537 BLS12-381 precompiles (Prague): G1ADD 0x0b, G1MSM 0x0c, G2ADD 0x0d,
//! G2MSM 0x0e, PAIRING_CHECK 0x0f, MAP_FP_TO_G1 0x10, MAP_FP2_TO_G2 0x11.
//!
//! Field elements are 64 bytes big-endian whose top 16 bytes must be zero and whose
//! value must be below p. Points are x || y (G2: x.c0 || x.c1 || y.c0 || y.c1);
//! all zeros encodes infinity. ADD only checks that points are on the curve; MSM
//! and PAIRING also check subgroup membership. Every error burns all call gas, so
//! callers only need to know that an error happened; the error kind is kept for
//! tests and tracing. Input-length caps (e.g. Base's Jovian limits) are applied
//! by the caller before calling in; work here is chunked with static bounds.

const std = @import("std");
const assert = std.debug.assert;
const fields = @import("fields.zig");
const g1 = @import("g1.zig");
const g2 = @import("g2.zig");
const msm = @import("msm.zig");
const pairing = @import("pairing.zig");
const map = @import("map.zig");

const Fp = fields.Fp;
const Fp2 = fields.Fp2;

pub const Address = enum(u8) {
    g1_add = 0x0b,
    g1_msm = 0x0c,
    g2_add = 0x0d,
    g2_msm = 0x0e,
    pairing_check = 0x0f,
    map_fp_to_g1 = 0x10,
    map_fp2_to_g2 = 0x11,
};

pub const Error = error{
    InvalidInputLength,
    InvalidFieldElement,
    PointNotOnCurve,
    PointNotInSubgroup,
};

pub const fp_length = 64;
pub const fp2_length = 2 * fp_length;
pub const g1_length = 2 * fp_length;
pub const g2_length = 2 * fp2_length;
pub const scalar_length = 32;
pub const g1_msm_pair_length = g1_length + scalar_length;
pub const g2_msm_pair_length = g2_length + scalar_length;
pub const pairing_pair_length = g1_length + g2_length;
pub const output_length_max = g2_length;

comptime {
    assert(g1_msm_pair_length == 160);
    assert(g2_msm_pair_length == 288);
    assert(pairing_pair_length == 384);
}

// Gas schedule (EIP-2537 final).
pub const g1_add_gas: u64 = 375;
pub const g2_add_gas: u64 = 600;
pub const g1_mul_gas: u64 = 12000;
pub const g2_mul_gas: u64 = 22500;
pub const map_fp_to_g1_gas: u64 = 5500;
pub const map_fp2_to_g2_gas: u64 = 23800;
pub const pairing_per_pair_gas: u64 = 32600;
pub const pairing_base_gas: u64 = 37700;
const msm_multiplier: u64 = 1000;

/// G1 MSM discounts for k = 1..128; k > 128 uses the last entry (max_discount).
const g1_discounts = [128]u16{
    1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677,
    673,  669, 665, 661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627,
    625,  623, 621, 619, 617, 615, 613, 611, 609, 608, 606, 604, 603, 601, 599, 598,
    596,  595, 593, 592, 591, 589, 588, 586, 585, 584, 582, 581, 580, 579, 577, 576,
    575,  574, 573, 572, 570, 569, 568, 567, 566, 565, 564, 563, 562, 561, 560, 559,
    558,  557, 556, 555, 554, 553, 552, 551, 550, 549, 548, 547, 547, 546, 545, 544,
    543,  542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534, 533, 532, 532, 531,
    530,  529, 528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520, 520, 519,
};

/// G2 MSM discounts for k = 1..128; k > 128 uses the last entry (max_discount).
const g2_discounts = [128]u16{
    1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717,
    711,  704,  699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646,
    643,  640,  637, 634, 632, 629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607,
    606,  604,  602, 600, 598, 597, 595, 593, 592, 590, 589, 587, 586, 584, 583, 582,
    580,  579,  578, 576, 575, 574, 573, 571, 570, 569, 568, 567, 566, 565, 563, 562,
    561,  560,  559, 558, 557, 556, 555, 554, 553, 552, 552, 551, 550, 549, 548, 547,
    546,  545,  545, 544, 543, 542, 541, 541, 540, 539, 538, 537, 537, 536, 535, 535,
    534,  533,  532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525, 524, 524,
};

fn msm_gas(input_length: usize, pair_length: usize, mul_gas: u64, discounts: []const u16) u64 {
    assert(pair_length > 0);
    assert(discounts.len == 128);
    const k: u64 = input_length / pair_length;
    if (k == 0) return 0;
    const discount: u64 = discounts[@min(k, discounts.len) - 1];
    return k * mul_gas * discount / msm_multiplier;
}

pub fn g1_msm_gas(input_length: usize) u64 {
    return msm_gas(input_length, g1_msm_pair_length, g1_mul_gas, &g1_discounts);
}

pub fn g2_msm_gas(input_length: usize) u64 {
    return msm_gas(input_length, g2_msm_pair_length, g2_mul_gas, &g2_discounts);
}

pub fn pairing_gas(input_length: usize) u64 {
    const k: u64 = input_length / pairing_pair_length;
    return pairing_per_pair_gas * k + pairing_base_gas;
}

/// Gas for a call to `address` with `input_length` bytes of input.
pub fn gas(address: Address, input_length: usize) u64 {
    return switch (address) {
        .g1_add => g1_add_gas,
        .g1_msm => g1_msm_gas(input_length),
        .g2_add => g2_add_gas,
        .g2_msm => g2_msm_gas(input_length),
        .pairing_check => pairing_gas(input_length),
        .map_fp_to_g1 => map_fp_to_g1_gas,
        .map_fp2_to_g2 => map_fp2_to_g2_gas,
    };
}

fn decode_fp(bytes: *const [fp_length]u8) Error!Fp {
    for (bytes[0..16]) |byte| if (byte != 0) return error.InvalidFieldElement;
    return Fp.from_bytes_be(bytes[16..64]) orelse error.InvalidFieldElement;
}

fn decode_fp2(bytes: *const [fp2_length]u8) Error!Fp2 {
    return .{ .c0 = try decode_fp(bytes[0..64]), .c1 = try decode_fp(bytes[64..128]) };
}

fn encode_fp(element: Fp, out: *[fp_length]u8) void {
    @memset(out[0..16], 0);
    out[16..64].* = element.to_bytes_be();
}

fn encode_fp2(element: Fp2, out: *[fp2_length]u8) void {
    encode_fp(element.c0, out[0..64]);
    encode_fp(element.c1, out[64..128]);
}

/// Decodes a G1 point and checks it is on the curve (not the subgroup).
pub fn decode_g1(bytes: *const [g1_length]u8) Error!g1.Affine {
    const x = try decode_fp(bytes[0..64]);
    const y = try decode_fp(bytes[64..128]);
    if (x.is_zero() and y.is_zero()) return g1.Affine.identity;
    const point: g1.Affine = .{ .x = x, .y = y, .infinity = false };
    if (!point.is_on_curve()) return error.PointNotOnCurve;
    return point;
}

/// Decodes a G2 point and checks it is on the curve (not the subgroup).
pub fn decode_g2(bytes: *const [g2_length]u8) Error!g2.Affine {
    const x = try decode_fp2(bytes[0..128]);
    const y = try decode_fp2(bytes[128..256]);
    if (x.is_zero() and y.is_zero()) return g2.Affine.identity;
    const point: g2.Affine = .{ .x = x, .y = y, .infinity = false };
    if (!point.is_on_curve()) return error.PointNotOnCurve;
    return point;
}

fn decode_g1_in_subgroup(bytes: *const [g1_length]u8) Error!g1.Affine {
    const point = try decode_g1(bytes);
    if (!g1.is_in_subgroup(point)) return error.PointNotInSubgroup;
    return point;
}

fn decode_g2_in_subgroup(bytes: *const [g2_length]u8) Error!g2.Affine {
    const point = try decode_g2(bytes);
    if (!g2.is_in_subgroup(point)) return error.PointNotInSubgroup;
    return point;
}

pub fn encode_g1(point: g1.Affine, out: *[g1_length]u8) void {
    if (point.infinity) return @memset(out, 0);
    encode_fp(point.x, out[0..64]);
    encode_fp(point.y, out[64..128]);
}

pub fn encode_g2(point: g2.Affine, out: *[g2_length]u8) void {
    if (point.infinity) return @memset(out, 0);
    encode_fp2(point.x, out[0..128]);
    encode_fp2(point.y, out[128..256]);
}

pub fn g1_add(input: []const u8, out: *[g1_length]u8) Error!void {
    if (input.len != 2 * g1_length) return error.InvalidInputLength;
    const a = try decode_g1(input[0..g1_length]);
    const b = try decode_g1(input[g1_length..][0..g1_length]);
    encode_g1(a.to_jacobian().add_affine(b).to_affine(), out);
}

pub fn g2_add(input: []const u8, out: *[g2_length]u8) Error!void {
    if (input.len != 2 * g2_length) return error.InvalidInputLength;
    const a = try decode_g2(input[0..g2_length]);
    const b = try decode_g2(input[g2_length..][0..g2_length]);
    encode_g2(a.to_jacobian().add_affine(b).to_affine(), out);
}

pub fn g1_msm(input: []const u8, out: *[g1_length]u8) Error!void {
    if (input.len == 0 or input.len % g1_msm_pair_length != 0) return error.InvalidInputLength;
    var points: [msm.chunk_points_max]g1.Affine = undefined;
    var scalars: [msm.chunk_points_max]u256 = undefined;
    var result = g1.G1.identity;
    var offset: usize = 0;
    while (offset < input.len) {
        var count: usize = 0;
        while (count < msm.chunk_points_max and offset < input.len) : (count += 1) {
            const pair = input[offset..][0..g1_msm_pair_length];
            points[count] = try decode_g1_in_subgroup(pair[0..g1_length]);
            scalars[count] = std.mem.readInt(u256, pair[g1_length..][0..scalar_length], .big);
            offset += g1_msm_pair_length;
        }
        result = result.add(msm.msm(g1.G1, points[0..count], scalars[0..count]));
    }
    assert(offset == input.len);
    encode_g1(result.to_affine(), out);
}

pub fn g2_msm(input: []const u8, out: *[g2_length]u8) Error!void {
    if (input.len == 0 or input.len % g2_msm_pair_length != 0) return error.InvalidInputLength;
    var points: [msm.chunk_points_max]g2.Affine = undefined;
    var scalars: [msm.chunk_points_max]u256 = undefined;
    var result = g2.G2.identity;
    var offset: usize = 0;
    while (offset < input.len) {
        var count: usize = 0;
        while (count < msm.chunk_points_max and offset < input.len) : (count += 1) {
            const pair = input[offset..][0..g2_msm_pair_length];
            points[count] = try decode_g2_in_subgroup(pair[0..g2_length]);
            scalars[count] = std.mem.readInt(u256, pair[g2_length..][0..scalar_length], .big);
            offset += g2_msm_pair_length;
        }
        result = result.add(msm.msm(g2.G2, points[0..count], scalars[0..count]));
    }
    assert(offset == input.len);
    encode_g2(result.to_affine(), out);
}

/// Writes 32 bytes: 31 zeros then 1 when the pairing product is 1, else 0.
pub fn pairing_check(input: []const u8, out: *[32]u8) Error!void {
    if (input.len == 0 or input.len % pairing_pair_length != 0) return error.InvalidInputLength;
    var pairs: [pairing.pairs_per_loop_max]pairing.Pair = undefined;
    var f = fields.Fp12.one;
    var offset: usize = 0;
    while (offset < input.len) {
        var count: usize = 0;
        while (count < pairing.pairs_per_loop_max and offset < input.len) : (count += 1) {
            const pair = input[offset..][0..pairing_pair_length];
            pairs[count] = .{
                .g1 = try decode_g1_in_subgroup(pair[0..g1_length]),
                .g2 = try decode_g2_in_subgroup(pair[g1_length..][0..g2_length]),
            };
            offset += pairing_pair_length;
        }
        f = f.mul(pairing.miller_loop(pairs[0..count]));
    }
    assert(offset == input.len);
    @memset(out, 0);
    out[31] = @intFromBool(pairing.final_exponentiation(f).eql(fields.Fp12.one));
}

pub fn map_fp_to_g1(input: []const u8, out: *[g1_length]u8) Error!void {
    if (input.len != fp_length) return error.InvalidInputLength;
    const u = try decode_fp(input[0..fp_length]);
    encode_g1(map.map_fp_to_g1(u), out);
}

pub fn map_fp2_to_g2(input: []const u8, out: *[g2_length]u8) Error!void {
    if (input.len != fp2_length) return error.InvalidInputLength;
    const u = try decode_fp2(input[0..fp2_length]);
    encode_g2(map.map_fp2_to_g2(u), out);
}

/// Runs the precompile at `address`; returns the output prefix of `out`.
pub fn run(address: Address, input: []const u8, out: *[output_length_max]u8) Error![]const u8 {
    switch (address) {
        .g1_add => try g1_add(input, out[0..g1_length]),
        .g1_msm => try g1_msm(input, out[0..g1_length]),
        .g2_add => try g2_add(input, out[0..g2_length]),
        .g2_msm => try g2_msm(input, out[0..g2_length]),
        .pairing_check => try pairing_check(input, out[0..32]),
        .map_fp_to_g1 => try map_fp_to_g1(input, out[0..g1_length]),
        .map_fp2_to_g2 => try map_fp2_to_g2(input, out[0..g2_length]),
    }
    const length: usize = switch (address) {
        .g1_add, .g1_msm, .map_fp_to_g1 => g1_length,
        .g2_add, .g2_msm, .map_fp2_to_g2 => g2_length,
        .pairing_check => 32,
    };
    assert(length <= out.len);
    return out[0..length];
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;

const Vector = struct {
    address: Address,
    input: []const u8,
    /// Null when the call must fail.
    output: ?[]const u8,
    gas: u64,
    error_code: u8,
};

/// Iterates `vectors/eip2537.bin`: a curated subset of the public go-ethereum
/// EIP-2537 vectors. Record: address u8, input length u32 BE, input, status u8
/// (0 ok; 1 length, 2 field element, 3 not on curve, 4 not in subgroup), then on
/// success output length u16 BE, output, gas u32 BE.
const VectorIterator = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(iterator: *VectorIterator, length: usize) []const u8 {
        const slice = iterator.bytes[iterator.offset..][0..length];
        iterator.offset += length;
        return slice;
    }

    fn next(iterator: *VectorIterator) ?Vector {
        if (iterator.offset == iterator.bytes.len) return null;
        const address: Address = @fromBackingInt(@intCast(iterator.take(1)[0]));
        const input_length = std.mem.readInt(u32, iterator.take(4)[0..4], .big);
        const input = iterator.take(input_length);
        const status = iterator.take(1)[0];
        if (status != 0) {
            return .{
                .address = address,
                .input = input,
                .output = null,
                .gas = 0,
                .error_code = status,
            };
        }
        const output_length = std.mem.readInt(u16, iterator.take(2)[0..2], .big);
        const output = iterator.take(output_length);
        const gas_value = std.mem.readInt(u32, iterator.take(4)[0..4], .big);
        return .{
            .address = address,
            .input = input,
            .output = output,
            .gas = gas_value,
            .error_code = 0,
        };
    }
};

const vector_bytes = @embedFile("vectors/eip2537.bin");

fn expected_error(code: u8) Error {
    return switch (code) {
        1 => error.InvalidInputLength,
        2 => error.InvalidFieldElement,
        3 => error.PointNotOnCurve,
        else => error.PointNotInSubgroup,
    };
}

test "precompile: official EIP-2537 vectors (curated go-ethereum subset)" {
    var iterator: VectorIterator = .{ .bytes = vector_bytes };
    var seen: [7]u32 = @splat(0);
    var out: [output_length_max]u8 = undefined;
    while (iterator.next()) |vector| {
        seen[@backingInt(vector.address) - 0x0b] += 1;
        const result = run(vector.address, vector.input, &out);
        if (vector.output) |expected| {
            try testing.expectEqualSlices(u8, expected, try result);
            try testing.expectEqual(vector.gas, gas(vector.address, vector.input.len));
        } else {
            try testing.expectError(expected_error(vector.error_code), result);
        }
    }
    for (seen) |count| try testing.expect(count >= 8);
}

test "precompile: seeded mutation fuzz never crashes" {
    var prng = Prng.init(0x2537);
    var iterator: VectorIterator = .{ .bytes = vector_bytes };
    var buffer: [4096]u8 = undefined;
    var out: [output_length_max]u8 = undefined;
    var index: u32 = 0;
    while (iterator.next()) |vector| : (index += 1) {
        // Keep Debug test time low: the expensive precompiles get fewer rounds.
        if (vector.input.len > buffer.len or index % 3 != 0) continue;
        const input = buffer[0..vector.input.len];
        @memcpy(input, vector.input);
        if (input.len > 0) {
            const position = prng.below(input.len);
            input[position] ^= @as(u8, 1) << @intCast(prng.below(8));
        }
        const cut = if (prng.chance(1, 4)) prng.below(input.len + 1) else input.len;
        _ = run(vector.address, input[0..cut], &out) catch {};
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    if (length == 0) return;
    const address: Address = @fromBackingInt(@intCast(0x0b + buffer[0] % 7));
    var out: [output_length_max]u8 = undefined;
    _ = run(address, buffer[1..length], &out) catch {};
}

test "bls12-381 precompile: coverage-guided fuzz never crashes" {
    try testing.fuzz({}, fuzz_one, .{});
}

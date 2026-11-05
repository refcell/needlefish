//! secp256r1 (NIST P-256) ECDSA verification for the P256VERIFY precompile
//! (RIP-7212, EIP-7951, address 0x100).
//!
//! Semantics follow EIP-7951 exactly: the input is `hash || r || s || qx || qy`
//! (5 x 32 bytes, big-endian, exactly 160 bytes); `r` and `s` must be in [1, n - 1];
//! `qx` and `qy` must be below p, satisfy y^2 = x^3 - 3x + b, and not be the (0, 0)
//! point-at-infinity encoding. Success yields the 32-byte big-endian integer 1,
//! every failure yields empty output (`null` here). The hash is used as an integer
//! reduced modulo n (no truncation, it is already 256 bits), and the final check is
//! `x(R) mod n == r` for R = (h/s) * G + (r/s) * Q with R not the identity.
//!
//! Arithmetic is variable time: every input to verification is public. Points are
//! Jacobian with the a = -3 doubling formulas; u1*G + u2*Q is one interleaved wNAF
//! pass using a static 32-entry affine table of odd multiples of G (window 7) and
//! a runtime 8-entry Jacobian table of odd multiples of Q (window 5). The final
//! comparison is done projectively, so only one field inversion (for 1/s mod n) is
//! needed. `std.crypto.sign.ecdsa` is used only as a test oracle.

const std = @import("std");
const assert = std.debug.assert;
const montgomery = @import("montgomery.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const p_int: u256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
const n_int: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const b_int: u256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
const gx_int: u256 = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
const gy_int: u256 = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;

/// Base field GF(p) and scalar field GF(n), both in Montgomery form.
pub const Fp = montgomery.Field(4, p_int);
pub const Fn = montgomery.Field(4, n_int);

/// Input length of the P256VERIFY precompile.
pub const input_length = 160;
/// Window widths of the wNAF recoding for the generator and the public key.
const g_window = 7;
const q_window = 5;
const g_table_len = 1 << (g_window - 2);
const q_table_len = 1 << (q_window - 2);
const digits_max = 257;

comptime {
    assert(Fp.modulus == p_int and Fn.modulus == n_int);
    assert(n_int < p_int and p_int - n_int < (1 << 129));
    assert(g_table_len == 32 and q_table_len == 8);
}

const Affine = struct { x: Fp, y: Fp };

/// Jacobian point (X : Y : Z) = (X/Z^2, Y/Z^3); Z = 0 is the identity.
const Point = struct {
    x: Fp,
    y: Fp,
    z: Fp,

    const identity: Point = .{ .x = Fp.one, .y = Fp.one, .z = Fp.zero };

    fn from_affine(a: Affine) Point {
        return .{ .x = a.x, .y = a.y, .z = Fp.one };
    }

    fn is_identity(p: Point) bool {
        return p.z.is_zero();
    }
};

/// Odd multiples G, 3G, 5G, ..., 63G as affine (x, y), generated offline from the
/// public curve parameters and checked against `add` in the tests below.
const g_odd_multiples = [g_table_len][2]u256{
    .{
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    },
    .{
        0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c,
        0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032,
    },
    .{
        0x51590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed,
        0xe0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4,
    },
    .{
        0x8e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3,
        0x73eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4,
    },
    .{
        0xea68d7b6fedf0b71878938d51d71f8729e0acb8c2c6df8b3d79e8a4b90949ee0,
        0x2a2744c972c9fce787014a964a8ea0c84d714feaa4de823fe85a224a4dd048fa,
    },
    .{
        0x3ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d1,
        0x9099209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740,
    },
    .{
        0x177c837ae0ac495a61805df2d85ee2fc792e284b65ead58a98e15d9d46072c01,
        0x63bb58cd4ebea558a24091adb40f4e7226ee14c3a1fb4df39c43bbe2efc7bfd8,
    },
    .{
        0xf0454dc6971abae7adfb378999888265ae03af92de3a0ef163668c63e59b9d5f,
        0xb5b93ee3592e2d1f4e6594e51f9643e62a3b21ce75b5fa3f47e59cde0d034f36,
    },
    .{
        0x47776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73e,
        0xaa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc,
    },
    .{
        0xcb6d2861102c0c25ce39b7c17108c507782c452257884895c1fc7b74ab03ed83,
        0x58d7614b24d9ef515c35e7100d6d6ce4a496716e30fa3e03e39150752bcecdaa,
    },
    .{
        0x3250fcf686637c7b2e4ac86eb473bca53a582139f42b1523fd76364e67399e83,
        0x42e7c342667d359397b3090d1d7eb88c897cd3c33b566a8215de24a071d48c09,
    },
    .{
        0x0e91c7239c2640d7d28a3e39d4583fa63c0bc0a5df64a4fe672e573045ca7896,
        0x5df65c3b550dba221a22733bb8e0bd6d7e68833575e7a5ae138046543140ad55,
    },
    .{
        0x3a67e2554b0c0bb685f4f52d8c07fa8441652fc5b76f1b2484a4dc45f200d687,
        0x27d0f1872f1fcf4326daf267163afb0d8c188af735a7618aa9ed16b302f79324,
    },
    .{
        0x184ffa5819d80d51deba2fac4611f378576355bd683e54abf2e201173b0883d1,
        0xc0a66e276688f359a4c6d90826cb999545bdeccc63f0491620d242c260906e6f,
    },
    .{
        0xd6d33adefa195b07a7c36da090853b8cfd8cd1c688b58a41dedd693d1c784def,
        0x84aaba16ee195d7e3f78245f558a5dcb09a166ab4b95eded550c124593d1bca6,
    },
    .{
        0x301d9e502dc7e05da85da026a7ae9aa0fac9db7d52a95b3e3e3f9aa0a1b45b8b,
        0x6551b6f6b3061223e0d23c026b017d72298d9ae46887ca61d58db6aea17ee267,
    },
    .{
        0x9807d699fcd81356fa9aa25b89d9d34ea03b0a533aa872fd65c100f3cb2cd793,
        0xc2a59cdccab11bf286a01a4d1d091b2fffe630b96c5878532f6bf92479634af4,
    },
    .{
        0xd58d4a589ed27d168ffa3ad7326c48ca94e8e1fe92af9700a12d389033bb291a,
        0xd45514d102726b8576ea92632dc7fef667271c163b034979a5b0c9c6f586b9d5,
    },
    .{
        0x419a6a646ddb817dd6b0978611a826aae0d21379246bfd4473a92894502b3348,
        0x332544cf1102f584545c9fb1954c2fd513c6d072f3dee1e2db1d6c81b09214b2,
    },
    .{
        0x22a682f7c3996d4d42014976a179046e547b942dd2d138d4a0c199ddfb2776c4,
        0x4f4606b0102223eeb918c9835a54356c979dcc310265b0685347f649cbaa285d,
    },
    .{
        0x67a6bec240dee0651cf258d2e6cfe8aa6067c5c3d4175a593a7de694995d2fa2,
        0xde692b7022d131586c249b49464d44991542c7ee209aca6c49c24ce1441feed5,
    },
    .{
        0x986ae2506f1ff104d04230861d8f4b498f4bc4c6d009b30f7544dc129b82d28d,
        0x003cccc0a6460e0ae328a4d97d3c7b61d86fc6289c189f2525110c441bb07e97,
    },
    .{
        0xa891d06670bde99b3ecd0f5ddff0672e0f5f609edd29d6d979c78080fae0ba03,
        0xb596cd922cbfa1c1419a88c4033c1ce71c6b38f0feb0f2ccefc3edc8166934ae,
    },
    .{
        0x42c315cc48958708595361ea83071bbcdd5b31583e19066d51d689227b1c0d7c,
        0x649a61ce571b95852914d1dfbb7a799074f1a1e1eb87f164d6c4a72bb2f9b1b9,
    },
    .{
        0xf785b0e098068875bb22b146866e6c0528fb7ea9758fd4fd7d228ce6a5674455,
        0x73fdb0bf6080da6ee15c767f0d9f5b414b04b6fd5f3aa60ae7bc490c10d62408,
    },
    .{
        0x672c4a514d9de43eaadee6863c1d68bc95f7eb56e81008ff044360f0018e22b1,
        0x548c7e9196a25bfe611de5a4ace203f7136246589704d9419935399191f37104,
    },
    .{
        0x6f01bd49c9d952455a47802254b88039982b1ca78de9b983f126ec9f7449d036,
        0x1562080ff1d5deab11a0f21a608776cea78551bfc3749b08360233dd989e17db,
    },
    .{
        0x079dba7ba068c9267571a109fe7fea2cc2a595b762c1eadadec1dff7df6e60a0,
        0xdc1e19b743d4d1811d223f9d2a9588ab83eb2df35751a397fb0da5aeb4824dea,
    },
    .{
        0xc116e30ebb4d2865126d45a8ea907f86289d406e2d6c6bd88abd97b1d0f56077,
        0xe9478823c35b30c2b8b16d9bb13b87657d5bd5e89e59c8c5313fd7fda410c206,
    },
    .{
        0x665f1a6ffe0c6437765b2784fca9bdf7e50941119e8dc8eca2b6ea0e0faa4b45,
        0x490e2ca49ffd18c26e8cca29f7eac37f7dede5bf81e215bc6e25a6602b7f4ccf,
    },
    .{
        0x059ccb19edd3da9a2d3a6b3d8d9900013e7910a08b724fd55939ac380d32af0e,
        0xbb6ad7eccad49159da65281b9345638e1621f7a33956cecd928e1e3c97fe91d1,
    },
    .{
        0x6a9501d85bf5dc802a1f28a08acc7d8fdf53c8af01a7cd3832a290825d8bdac1,
        0xca640ad19347374381c6c6e44a3c56a3f8461b5c697a6f3530aff53d5f1ef1a3,
    },
};

const g_table: [g_table_len]Affine = blk: {
    var table: [g_table_len]Affine = undefined;
    for (g_odd_multiples, 0..) |entry, index| {
        table[index] = .{
            .x = Fp.from_int_comptime(entry[0]),
            .y = Fp.from_int_comptime(entry[1]),
        };
    }
    break :blk table;
};

const curve_b = Fp.from_int_comptime(b_int);

/// True when (x, y) satisfies y^2 = x^3 - 3x + b.
fn is_on_curve(x: Fp, y: Fp) bool {
    assert(Fp.modulus % 4 == 3 and Fp.limbs == 4);
    const x_squared = x.square();
    const rhs = x_squared.sub(Fp.from_int_comptime(3)).mul(x).add(curve_b);
    return y.square().eql(rhs);
}

/// Point doubling for a = -3 (dbl-2001-b); the identity doubles to the identity.
fn double(p: Point) Point {
    assert(p.z.is_zero() == p.is_identity());
    const delta = p.z.square();
    const gamma = p.y.square();
    const beta = p.x.mul(gamma);
    const alpha_half = p.x.sub(delta).mul(p.x.add(delta));
    const alpha = alpha_half.add(alpha_half).add(alpha_half);
    const beta4 = beta.double().double();
    const x3 = alpha.square().sub(beta4.double());
    const z3 = p.y.add(p.z).square().sub(gamma).sub(delta);
    const gamma_squared = gamma.square().double().double().double();
    const y3 = alpha.mul(beta4.sub(x3)).sub(gamma_squared);
    return .{ .x = x3, .y = y3, .z = z3 };
}

/// Mixed addition P + Q for affine Q (madd-2007-bl) with the exceptional cases
/// (P = identity, P = Q, P = -Q) handled explicitly: inputs are public.
fn add_mixed(p: Point, q: Affine) Point {
    assert(!q.x.is_zero() or !q.y.is_zero());
    if (p.is_identity()) return Point.from_affine(q);
    const z1z1 = p.z.square();
    const h = q.x.mul(z1z1).sub(p.x);
    const s2 = q.y.mul(p.z).mul(z1z1);
    const r = s2.sub(p.y).double();
    if (h.is_zero()) {
        if (r.is_zero()) return double(p);
        return Point.identity;
    }
    const hh = h.square();
    const i = hh.double().double();
    const j = h.mul(i);
    const v = p.x.mul(i);
    const x3 = r.square().sub(j).sub(v.double());
    const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).double());
    const z3 = p.z.add(h).square().sub(z1z1).sub(hh);
    return .{ .x = x3, .y = y3, .z = z3 };
}

/// General addition (add-2007-bl) with the same exceptional-case handling.
fn add(p: Point, q: Point) Point {
    assert(p.z.is_zero() == p.is_identity() and q.z.is_zero() == q.is_identity());
    if (p.is_identity()) return q;
    if (q.is_identity()) return p;
    const z1z1 = p.z.square();
    const z2z2 = q.z.square();
    const x1_scaled = p.x.mul(z2z2);
    const h = q.x.mul(z1z1).sub(x1_scaled);
    const s1 = p.y.mul(q.z).mul(z2z2);
    const r = q.y.mul(p.z).mul(z1z1).sub(s1).double();
    if (h.is_zero()) {
        if (r.is_zero()) return double(p);
        return Point.identity;
    }
    const i = h.double().square();
    const j = h.mul(i);
    const v = x1_scaled.mul(i);
    const x3 = r.square().sub(j).sub(v.double());
    const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).double());
    const z_sum = p.z.add(q.z).square().sub(z1z1).sub(z2z2);
    return .{ .x = x3, .y = y3, .z = z_sum.mul(h) };
}

fn negate_affine(q: Affine) Affine {
    assert(is_on_curve(q.x, q.y));
    return .{ .x = q.x, .y = q.y.neg() };
}

fn negate(p: Point) Point {
    assert(p.z.is_zero() == p.is_identity());
    return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
}

/// Width-`window` non-adjacent form: odd digits in (-2^(w-1), 2^(w-1)), at most one
/// non-zero digit in any `window` consecutive positions. Returns the digit count.
fn wnaf(comptime window: u32, scalar: u256, digits: *[digits_max]i8) u32 {
    comptime assert(window >= 2 and window <= 7);
    assert(scalar < n_int);
    const window_size: i16 = 1 << window;
    var remaining = scalar;
    var count: u32 = 0;
    digits.* = @splat(0);
    while (remaining != 0) {
        const trailing: u32 = @intCast(@ctz(remaining));
        remaining >>= @intCast(trailing);
        count += trailing;
        var digit: i16 = @intCast(remaining & (window_size - 1));
        if (digit >= window_size / 2) digit -= window_size;
        // Subtracting a negative digit adds at most 2^(w-1): no overflow below n.
        if (digit > 0) remaining -= @intCast(digit) else remaining += @intCast(-digit);
        assert(remaining & 1 == 0);
        digits[count] = @intCast(digit);
        count += 1;
        remaining >>= 1;
    }
    assert(count <= digits_max);
    return count;
}

fn fp_from_u256(value: u256) Fp {
    assert(value < p_int);
    return Fp.from_int(value);
}

/// u1 * G + u2 * Q in one interleaved wNAF pass (variable time).
/// Q, 3Q, ..., 15Q in affine form with one shared inversion (Montgomery's trick).
/// The group has prime order, so no multiple below n is the identity.
fn odd_multiples_affine(q: Affine) [q_table_len]Affine {
    var jacobian: [q_table_len]Point = undefined;
    jacobian[0] = Point.from_affine(q);
    const q_double = double(jacobian[0]);
    for (1..q_table_len) |index| jacobian[index] = add(jacobian[index - 1], q_double);
    var prefix: [q_table_len]Fp = undefined;
    prefix[0] = jacobian[0].z;
    for (1..q_table_len) |index| prefix[index] = prefix[index - 1].mul(jacobian[index].z);
    assert(!prefix[q_table_len - 1].is_zero());
    var inverse = prefix[q_table_len - 1].inverse();
    var table: [q_table_len]Affine = undefined;
    var index: usize = q_table_len;
    while (index > 0) {
        index -= 1;
        const z_inverse = if (index > 0) inverse.mul(prefix[index - 1]) else inverse;
        inverse = inverse.mul(jacobian[index].z);
        const z_inverse_squared = z_inverse.square();
        table[index] = .{
            .x = jacobian[index].x.mul(z_inverse_squared),
            .y = jacobian[index].y.mul(z_inverse_squared).mul(z_inverse),
        };
    }
    assert(is_on_curve(table[q_table_len - 1].x, table[q_table_len - 1].y));
    return table;
}

fn double_scalar_mul(u1_int: u256, u2_int: u256, q: Affine) Point {
    assert(u1_int < n_int and u2_int < n_int);
    assert(is_on_curve(q.x, q.y));
    var g_digits: [digits_max]i8 = undefined;
    var q_digits: [digits_max]i8 = undefined;
    const g_count = wnaf(g_window, u1_int, &g_digits);
    const q_count = wnaf(q_window, u2_int, &q_digits);

    const q_table = odd_multiples_affine(q);

    var acc = Point.identity;
    var position = @max(g_count, q_count);
    while (position > 0) {
        position -= 1;
        acc = double(acc);
        const g_digit = g_digits[position];
        if (g_digit > 0) {
            acc = add_mixed(acc, g_table[@intCast(g_digit >> 1)]);
        } else if (g_digit < 0) {
            acc = add_mixed(acc, negate_affine(g_table[@intCast((-g_digit) >> 1)]));
        }
        const q_digit = q_digits[position];
        if (q_digit > 0) {
            acc = add_mixed(acc, q_table[@intCast(q_digit >> 1)]);
        } else if (q_digit < 0) {
            acc = add_mixed(acc, negate_affine(q_table[@intCast((-q_digit) >> 1)]));
        }
    }
    return acc;
}

fn read_int(bytes: *const [32]u8) u256 {
    return std.mem.readInt(u256, bytes, .big);
}

/// ECDSA verification over P-256 with EIP-7951 semantics (see the file header).
pub fn verify(
    hash: [32]u8,
    r: [32]u8,
    s: [32]u8,
    qx: [32]u8,
    qy: [32]u8,
) bool {
    const r_int = read_int(&r);
    const s_int = read_int(&s);
    if (r_int == 0 or r_int >= n_int or s_int == 0 or s_int >= n_int) return false;
    const x = Fp.from_bytes_be(&qx) orelse return false;
    const y = Fp.from_bytes_be(&qy) orelse return false;
    if (x.is_zero() and y.is_zero()) return false;
    if (!is_on_curve(x, y)) return false;

    const s_inverse = Fn.from_int(s_int).inverse();
    const u1_int = Fn.from_int(read_int(&hash)).mul(s_inverse).to_int();
    const u2_int = Fn.from_int(r_int).mul(s_inverse).to_int();
    const result = double_scalar_mul(u1_int, u2_int, .{ .x = x, .y = y });
    if (result.is_identity()) return false;

    // x(R) mod n == r, compared projectively: x(R) is r or r + n (when r + n < p).
    const z_squared = result.z.square();
    if (result.x.eql(fp_from_u256(r_int).mul(z_squared))) return true;
    if (r_int < p_int - n_int) {
        return result.x.eql(fp_from_u256(r_int + n_int).mul(z_squared));
    }
    return false;
}

/// P256VERIFY (0x100): 160-byte input, 32-byte big-endian 1 on success, else null
/// (empty output). Gas is charged by the EVM (6900 since Osaka, 3450 under RIP-7212).
pub fn precompile_p256verify(input: []const u8) ?[32]u8 {
    if (input.len != input_length) return null;
    const valid = verify(
        input[0..32].*,
        input[32..64].*,
        input[64..96].*,
        input[96..128].*,
        input[128..160].*,
    );
    if (!valid) return null;
    var output: [32]u8 = @splat(0);
    output[31] = 1;
    return output;
}

// ---------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------

const testing = std.testing;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

fn to_affine(p: Point) Affine {
    assert(!p.is_identity());
    const z_inverse = p.z.inverse();
    const z_inverse_squared = z_inverse.square();
    return .{ .x = p.x.mul(z_inverse_squared), .y = p.y.mul(z_inverse_squared).mul(z_inverse) };
}

fn affine_eql(a: Affine, b: Affine) bool {
    return a.x.eql(b.x) and a.y.eql(b.y);
}

test "p256: generator is on the curve and has order n" {
    const g: Affine = .{ .x = Fp.from_int_comptime(gx_int), .y = Fp.from_int_comptime(gy_int) };
    try testing.expect(is_on_curve(g.x, g.y));
    // (n - 1) * G = -G, so (n-1)G + G is the identity.
    const minus_g = double_scalar_mul(n_int - 1, 0, g);
    try testing.expect(affine_eql(to_affine(minus_g), negate_affine(g)));
    try testing.expect(add_mixed(minus_g, g).is_identity());
    try testing.expect(!is_on_curve(g.x, g.y.add(Fp.one)));
}

test "p256: static generator table holds odd multiples of G" {
    const g = Point.from_affine(g_table[0]);
    const g_double = double(g);
    var running = g;
    for (g_table, 0..) |entry, index| {
        try testing.expect(is_on_curve(entry.x, entry.y));
        try testing.expect(affine_eql(to_affine(running), entry));
        // Cross-check against scalar multiplication through the other path.
        const odd: u256 = 2 * index + 1;
        const by_scalar = double_scalar_mul(0, odd, g_table[0]);
        try testing.expect(affine_eql(to_affine(by_scalar), entry));
        running = add(running, g_double);
    }
}

test "p256: add, double and add_mixed agree and handle exceptional cases" {
    const g = Point.from_affine(g_table[0]);
    const two_g = double(g);
    const three_g = add(two_g, g);
    try testing.expect(affine_eql(to_affine(three_g), g_table[1]));
    try testing.expect(affine_eql(to_affine(add_mixed(two_g, g_table[0])), g_table[1]));
    // P + P through the addition formulas falls back to doubling.
    try testing.expect(affine_eql(to_affine(add(g, g)), to_affine(two_g)));
    try testing.expect(affine_eql(to_affine(add_mixed(g, g_table[0])), to_affine(two_g)));
    // P + (-P) is the identity; identity is neutral.
    try testing.expect(add(g, negate(g)).is_identity());
    try testing.expect(add_mixed(g, negate_affine(g_table[0])).is_identity());
    try testing.expect(affine_eql(to_affine(add(Point.identity, g)), g_table[0]));
    try testing.expect(affine_eql(to_affine(add(g, Point.identity)), g_table[0]));
    try testing.expect(double(Point.identity).is_identity());
}

test "p256: wnaf reconstructs the scalar and respects the digit rules" {
    var prng = Prng.init(0x7212);
    var digits: [digits_max]i8 = undefined;
    for (0..300) |round| {
        var scalar: u256 = prng.int(u256) % n_int;
        if (round == 0) scalar = 0;
        if (round == 1) scalar = n_int - 1;
        if (round == 2) scalar = 1;
        const count = wnaf(g_window, scalar, &digits);
        var accumulator: i512 = 0;
        var index: u32 = count;
        var last_nonzero: i32 = -100;
        while (index > 0) {
            index -= 1;
            accumulator = accumulator * 2 + digits[index];
        }
        for (digits[0..count], 0..) |digit, position| {
            if (digit == 0) continue;
            try testing.expect(@mod(digit, 2) == 1);
            try testing.expect(digit > -64 and digit < 64);
            try testing.expect(@as(i32, @intCast(position)) - last_nonzero >= g_window);
            last_nonzero = @intCast(position);
        }
        try testing.expectEqual(@as(i512, scalar), accumulator);
    }
}

fn hex_to_bytes(comptime length: usize, text: []const u8) [length]u8 {
    var out: [length]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, text) catch unreachable;
    assert(decoded.len == length);
    return out;
}

test "p256: public vectors (RIP-7212 / EIP-7951 / Wycheproof)" {
    const vectors = @embedFile("testdata/p256_verify_vectors.txt");
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    var count: u32 = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, ' ');
        const input = hex_to_bytes(input_length, fields.next().?);
        const expected_valid = std.mem.eql(u8, fields.next().?, "1");
        const output = precompile_p256verify(&input);
        try testing.expectEqual(expected_valid, output != null);
        if (output) |bytes| {
            try testing.expectEqual(@as(u256, 1), std.mem.readInt(u256, &bytes, .big));
        }
        count += 1;
    }
    try testing.expectEqual(@as(u32, 54), count);
}

test "p256: precompile rejects wrong lengths and malformed fields" {
    const input = first_vector_input();
    try testing.expect(precompile_p256verify(&input) != null);
    try testing.expect(precompile_p256verify(input[0..159]) == null);
    try testing.expect(precompile_p256verify(&(input ++ [1]u8{0})) == null);
    try testing.expect(precompile_p256verify(&.{}) == null);

    // Each 32-byte field forced to zero or 0xff..ff must fail.
    for (1..5) |field| {
        var zeroed = input;
        @memset(zeroed[field * 32 ..][0..32], 0);
        try testing.expect(precompile_p256verify(&zeroed) == null);
        var ones = input;
        @memset(ones[field * 32 ..][0..32], 0xff);
        try testing.expect(precompile_p256verify(&ones) == null);
    }
    // qx + p (non-canonical but < 2^256) must fail even though it is congruent.
    var shifted = input;
    const qx = std.mem.readInt(u256, input[96..128], .big);
    if (@addWithOverflow(qx, p_int)[1] == 0) {
        std.mem.writeInt(u256, shifted[96..128], qx + p_int, .big);
        try testing.expect(precompile_p256verify(&shifted) == null);
    }
    // r = n and s = n are out of range; r + n would otherwise equal r.
    var r_is_n = input;
    std.mem.writeInt(u256, r_is_n[32..64], n_int, .big);
    try testing.expect(precompile_p256verify(&r_is_n) == null);
    var s_is_n = input;
    std.mem.writeInt(u256, s_is_n[64..96], n_int, .big);
    try testing.expect(precompile_p256verify(&s_is_n) == null);
}

fn first_vector_input() [input_length]u8 {
    const vectors = @embedFile("testdata/p256_verify_vectors.txt");
    const end = std.mem.indexOfScalar(u8, vectors, ' ').?;
    return hex_to_bytes(input_length, vectors[0..end]);
}

fn oracle_verify(hash: [32]u8, r: [32]u8, s: [32]u8, qx: [32]u8, qy: [32]u8) bool {
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    sec1[1..33].* = qx;
    sec1[33..65].* = qy;
    const public_key = Ecdsa.PublicKey.fromSec1(&sec1) catch return false;
    const signature = Ecdsa.Signature{ .r = r, .s = s };
    signature.verifyPrehashed(hash, public_key) catch return false;
    return true;
}

fn corrupt(prng: *Prng, bytes: *[32]u8) void {
    switch (prng.below(3)) {
        0 => bytes[prng.below(32)] ^= @as(u8, 1) << @intCast(prng.below(8)),
        1 => bytes.* = @bitCast(@as(u256, @bitCast(bytes.*)) +% 1),
        else => prng.fill(bytes),
    }
}

test "p256: seeded differential fuzz vs std ecdsa" {
    var prng = Prng.init(0x5ec9256);
    for (0..24) |round| {
        var seed: [Ecdsa.KeyPair.seed_length]u8 = undefined;
        prng.fill(&seed);
        const key_pair = try Ecdsa.KeyPair.generateDeterministic(seed);
        var hash: [32]u8 = undefined;
        prng.fill(&hash);
        if (round == 0) hash = @splat(0);
        if (round == 1) hash = @splat(0xff);
        const signature = try key_pair.signPrehashed(hash, null);
        const sec1 = key_pair.public_key.toUncompressedSec1();
        const qx = sec1[1..33].*;
        const qy = sec1[33..65].*;
        try testing.expect(verify(hash, signature.r, signature.s, qx, qy));
        for (0..6) |_| {
            var fields = [5][32]u8{ hash, signature.r, signature.s, qx, qy };
            corrupt(&prng, &fields[prng.below(5)]);
            const ours = verify(fields[0], fields[1], fields[2], fields[3], fields[4]);
            const theirs = oracle_verify(fields[0], fields[1], fields[2], fields[3], fields[4]);
            try testing.expectEqual(theirs, ours);
        }
    }
}

fn fuzz_one(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [input_length + 8]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    const output = precompile_p256verify(input);
    if (length != input_length) {
        try testing.expect(output == null);
        return;
    }
    const expected = oracle_verify(
        input[0..32].*,
        input[32..64].*,
        input[64..96].*,
        input[96..128].*,
        input[128..160].*,
    );
    try testing.expectEqual(expected, output != null);
}

test "p256: coverage-guided fuzz over precompile input" {
    try testing.fuzz({}, fuzz_one, .{});
}

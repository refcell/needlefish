//! Public Wycheproof vectors (C2SP/wycheproof, Apache-2.0) for secp256k1 ECDSA verify,
//! P-256 ECDSA verify (EIP-7951 semantics: high s valid, like Wycheproof's P1363 suites),
//! and secp256k1 ECDH. Converted by `etc/scripts/crypto-wycheproof.py`; see its header for
//! the line formats and which cases are kept.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const secp256k1 = @import("secp256k1/root.zig");
const p256 = @import("p256.zig");

const ecdsa_secp256k1 = @embedFile("vectors/wycheproof_ecdsa_secp256k1.txt");
const ecdsa_secp256r1 = @embedFile("vectors/wycheproof_ecdsa_secp256r1.txt");
const ecdh_secp256k1 = @embedFile("vectors/wycheproof_ecdh_secp256k1.txt");

const Curve = enum { secp256k1, secp256r1 };

fn hex(comptime length: usize, text: []const u8) ![length]u8 {
    var out: [length]u8 = undefined;
    if (text.len != 2 * length) return error.BadVector;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}

fn verdict(text: []const u8) !bool {
    if (std.mem.eql(u8, text, "1")) return true;
    if (std.mem.eql(u8, text, "0")) return false;
    return error.BadVector;
}

fn verify_on(curve: Curve, key: *const [64]u8, hash: [32]u8, r: [32]u8, s: [32]u8) bool {
    return switch (curve) {
        .secp256k1 => secp256k1.verify(hash, r, s, key),
        .secp256r1 => p256.verify(hash, r, s, key[0..32].*, key[32..64].*),
    };
}

/// Runs every `T` line against the preceding `K` key; returns the number of tests.
fn run_ecdsa(curve: Curve, text: []const u8) !u32 {
    var key: ?[64]u8 = null;
    var count: u32 = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const tag = fields.next() orelse return error.BadVector;
        if (std.mem.eql(u8, tag, "K")) {
            key = try hex(64, fields.next() orelse return error.BadVector);
            continue;
        }
        if (!std.mem.eql(u8, tag, "T")) return error.BadVector;
        const hash = try hex(32, fields.next() orelse return error.BadVector);
        const r = try hex(32, fields.next() orelse return error.BadVector);
        const s = try hex(32, fields.next() orelse return error.BadVector);
        const expected = try verdict(fields.next() orelse return error.BadVector);
        const actual = verify_on(curve, &(key orelse return error.BadVector), hash, r, s);
        if (actual != expected) {
            std.debug.print("{s} mismatch at line: {s}\n", .{ @tagName(curve), line });
            return error.TestUnexpectedResult;
        }
        count += 1;
    }
    return count;
}

test "wycheproof: secp256k1 ECDSA (P1363, SHA-256)" {
    const count = try run_ecdsa(.secp256k1, ecdsa_secp256k1);
    try testing.expect(count >= 230);
}

test "wycheproof: secp256r1 ECDSA (P1363, SHA-256)" {
    const count = try run_ecdsa(.secp256r1, ecdsa_secp256r1);
    try testing.expect(count >= 230);
}

/// The shared x coordinate, or null when the public key is rejected.
fn ecdh_shared(private: [32]u8, public_text: []const u8) !?[32]u8 {
    const public: secp256k1.PublicKey = switch (public_text.len) {
        130 => blk: {
            const sec1 = try hex(65, public_text);
            if (sec1[0] != 0x04) return error.BadVector;
            break :blk sec1[1..65].*;
        },
        66 => blk: {
            const compressed = try hex(33, public_text);
            break :blk secp256k1.decompress_public_key(&compressed) orelse return null;
        },
        else => return error.BadVector,
    };
    const shared = secp256k1.ecdh(private, &public) catch |err| switch (err) {
        error.InvalidPublicKey => return null,
        error.InvalidPrivateKey => return error.BadVector, // Vectors use valid scalars.
    };
    assert(shared[0] == 0x02 or shared[0] == 0x03);
    return shared[1..33].*;
}

test "wycheproof: secp256k1 ECDH (raw points)" {
    var count: u32 = 0;
    var invalid: u32 = 0;
    var lines = std.mem.tokenizeScalar(u8, ecdh_secp256k1, '\n');
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, fields.next() orelse return error.BadVector, "E")) {
            return error.BadVector;
        }
        const private = try hex(32, fields.next() orelse return error.BadVector);
        const public_text = fields.next() orelse return error.BadVector;
        const shared_text = fields.next() orelse return error.BadVector;
        const expected = try verdict(fields.next() orelse return error.BadVector);
        const actual = try ecdh_shared(private, public_text);
        if (expected) {
            const shared = try hex(32, shared_text);
            if (actual == null or !std.mem.eql(u8, &actual.?, &shared)) {
                std.debug.print("ecdh mismatch at line: {s}\n", .{line});
                return error.TestUnexpectedResult;
            }
        } else {
            invalid += 1;
            if (actual != null) {
                std.debug.print("ecdh accepted invalid key: {s}\n", .{line});
                return error.TestUnexpectedResult;
            }
        }
        count += 1;
    }
    try testing.expect(count >= 450);
    try testing.expect(invalid > 0);
}

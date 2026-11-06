//! `CertManager` calls (base/base `crates/proof/contracts/src/cert_manager.rs`): the hinted
//! CA and client certificate verification the registrar caches certificates with, the raw
//! cache reads, and revocation.

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("abi.zig");

const Address = abi.Address;
const Hash = [32]u8;

pub const owner = abi.selector("owner()");
pub const revoker = abi.selector("revoker()");
pub const verify_ca_cert_with_hints = abi.selector("verifyCACertWithHints(bytes,bytes32,bytes)");
pub const verify_client_cert_with_hints =
    abi.selector("verifyClientCertWithHints(bytes,bytes32,bytes)");
pub const load_verified = abi.selector("loadVerified(bytes32)");
pub const is_revoked = abi.selector("isRevoked(bytes32)");
pub const compute_cert_id = abi.selector("computeCertId(bytes)");
pub const revoke_cert = abi.selector("revokeCert(bytes32)");

/// `CertManagerVerifiedCert`: raw cached metadata, possibly expired or revoked.
pub const VerifiedCert = struct {
    ca: bool,
    not_after: u64,
    max_path_len: i64,
    subject_hash: Hash,
    /// Points into the return data.
    public_key: []const u8,

    /// An empty entry (`notAfter == 0`) means the certificate was never cached.
    pub fn is_cached(cert: *const VerifiedCert) bool {
        return cert.not_after != 0;
    }
};

/// `verifyCACertWithHints` or `verifyClientCertWithHints`.
pub fn encode_verify(
    out: []u8,
    function: [4]u8,
    cert: []const u8,
    parent_cert_hash: Hash,
    signature_hints: []const u8,
) abi.EncodeError![]u8 {
    assert(std.mem.eql(u8, &function, &verify_ca_cert_with_hints) or
        std.mem.eql(u8, &function, &verify_client_cert_with_hints));
    assert(cert.len > 0);
    return abi.encode_call(out, function, &.{
        .{ .bytes = cert }, .{ .word = parent_cert_hash }, .{ .bytes = signature_hints },
    });
}

/// `loadVerified`, `isRevoked` and `revokeCert`, which take one `bytes32`.
pub fn encode_hash_call(out: []u8, function: [4]u8, hash: Hash) abi.EncodeError![]u8 {
    assert(std.mem.eql(u8, &function, &load_verified) or
        std.mem.eql(u8, &function, &is_revoked) or std.mem.eql(u8, &function, &revoke_cert));
    return abi.encode_call(out, function, &.{.{ .word = hash }});
}

pub fn encode_compute_cert_id(out: []u8, cert: []const u8) abi.EncodeError![]u8 {
    assert(cert.len > 0);
    return abi.encode_call(out, compute_cert_id, &.{.{ .bytes = cert }});
}

/// The `CertManagerVerifiedCert memory` returned by `loadVerified` and
/// `verifyClientCertWithHints`: an offset to the struct, then its fields.
pub fn decode_verified_cert(data: []const u8) abi.DecodeError!VerifiedCert {
    const outer: abi.Decoder = .{ .data = data };
    const offset = try outer.uint(u32, 0);
    if (offset % 32 != 0 or offset > data.len) return error.TypeCheck;
    const fields: abi.Decoder = .{ .data = data[offset..] };
    const cert: VerifiedCert = .{
        .ca = try fields.boolean(0),
        .not_after = try fields.uint(u64, 1),
        .max_path_len = try int64(fields, 2),
        .subject_hash = (try fields.word(3)).*,
        .public_key = try fields.bytes(4),
    };
    assert(data.len >= offset + 5 * 32);
    return cert;
}

/// A sign-extended `int64` word.
fn int64(decoder: abi.Decoder, index: usize) abi.DecodeError!i64 {
    const raw = try decoder.word(index);
    const value: i256 = @bitCast(std.mem.readInt(u256, raw, .big));
    const result = std.math.cast(i64, value) orelse return error.TypeCheck;
    assert(@as(i256, result) == value);
    return result;
}

const testing = std.testing;

test "cert manager: calls and the verified-cert return" {
    var buffer: [512]u8 = undefined;
    const cert: [70]u8 = @splat(0x30);
    const parent: Hash = @splat(7);
    const call = try encode_verify(&buffer, verify_ca_cert_with_hints, &cert, parent, "hint");
    const args = try abi.Decoder.call(call, verify_ca_cert_with_hints);
    try testing.expectEqualSlices(u8, &cert, try args.bytes(0));
    try testing.expectEqual(parent, (try args.word(1)).*);
    try testing.expectEqualStrings("hint", try args.bytes(2));
    const load = try encode_hash_call(&buffer, load_verified, parent);
    try testing.expectEqual(@as(usize, 36), load.len);
    _ = try encode_compute_cert_id(&buffer, &cert);

    // offset | ca | notAfter | maxPathLen (-1) | subjectHash | pubKey offset | len | key
    var data: [32 * 9]u8 = @splat(0);
    data[31] = 32;
    data[63] = 1;
    std.mem.writeInt(u64, data[88..96], 1_700_000_000, .big);
    @memset(data[96..128], 0xff);
    data[128..160].* = @splat(9);
    data[191] = 5 * 32;
    data[223] = 3;
    data[224..227].* = .{ 4, 5, 6 };
    const verified = try decode_verified_cert(&data);
    try testing.expect(verified.ca and verified.is_cached());
    try testing.expectEqual(@as(i64, -1), verified.max_path_len);
    try testing.expectEqual(@as(u64, 1_700_000_000), verified.not_after);
    try testing.expectEqualSlices(u8, &.{ 4, 5, 6 }, verified.public_key);
    data[96] = 0x7f;
    try testing.expectError(error.TypeCheck, decode_verified_cert(&data));
}

test "cert manager: fuzz the verified-cert decoder" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var data: [288]u8 = undefined;
            const length = smith.index(data.len);
            smith.bytes(data[0..length]);
            if (smith.index(2) == 0 and length >= 32) {
                @memset(data[0..31], 0);
                data[31] = 32;
            }
            const verified = decode_verified_cert(data[0..length]) catch return;
            try testing.expect(verified.public_key.len <= length);
        }
    }.one, .{ .iterations = 3000 });
}

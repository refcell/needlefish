//! HS256 JSON Web Tokens for Engine API authentication.
//!
//! Per the execution-apis authentication spec: the consensus client signs a token with a
//! shared 32-byte secret (hex in a file, optional `0x` prefix), the header is
//! `{"alg":"HS256","typ":"JWT"}`, the claims carry `iat` (seconds), and the execution client
//! rejects tokens whose `iat` is more than 60 seconds away from its own clock. Only HS256 is
//! accepted; `alg: none` and every other algorithm are rejected before any signature work.
//! Token creation and verification use fixed buffers and constant-time comparison.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const base64 = std.base64.url_safe_no_pad;

pub const secret_size = 32;
pub const iat_window_s: u64 = 60;
/// Long enough for the header, `iat`, and a few optional claims.
pub const token_size_max = 512;

const header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";

pub const Secret = struct {
    bytes: [secret_size]u8,

    /// Parses a hex secret, as stored in `jwt.hex`. Surrounding whitespace and an optional
    /// `0x` prefix are accepted.
    pub fn parse_hex(text: []const u8) error{InvalidSecret}!Secret {
        var hex = std.mem.trim(u8, text, " \t\r\n");
        if (hex.len >= 2 and hex[0] == '0' and (hex[1] == 'x' or hex[1] == 'X')) hex = hex[2..];
        if (hex.len != secret_size * 2) return error.InvalidSecret;
        var secret: Secret = .{ .bytes = undefined };
        _ = std.fmt.hexToBytes(&secret.bytes, hex) catch return error.InvalidSecret;
        return secret;
    }

    /// Hex encoding (no prefix) for writing a fresh `jwt.hex`.
    pub fn to_hex(secret: Secret) [secret_size * 2]u8 {
        return std.fmt.bytesToHex(secret.bytes, .lower);
    }
};

/// Creates a token with `iat = now_s` into `buffer`. Returns the token slice.
pub fn create(secret: Secret, now_s: u64, buffer: *[token_size_max]u8) []const u8 {
    var claims_buffer: [64]u8 = undefined;
    const claims = std.fmt.bufPrint(&claims_buffer, "{{\"iat\":{d}}}", .{now_s}) catch
        unreachable; // A u64 always fits.
    var length: usize = 0;
    length += base64.Encoder.encode(buffer[length..], header_json).len;
    buffer[length] = '.';
    length += 1;
    length += base64.Encoder.encode(buffer[length..], claims).len;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, buffer[0..length], &secret.bytes);
    buffer[length] = '.';
    length += 1;
    length += base64.Encoder.encode(buffer[length..], &mac).len;
    assert(length <= token_size_max);
    return buffer[0..length];
}

pub const VerifyError = error{
    Malformed,
    UnsupportedAlgorithm,
    InvalidSignature,
    MissingIssuedAt,
    IssuedAtOutOfWindow,
};

/// Verifies `token` against `secret` and checks that `iat` is within `iat_window_s` of
/// `now_s`. Returns the `iat` claim on success.
pub fn verify(secret: Secret, token: []const u8, now_s: u64) VerifyError!u64 {
    if (token.len == 0 or token.len > token_size_max) return error.Malformed;
    const first_dot = std.mem.findScalar(u8, token, '.') orelse return error.Malformed;
    const second_dot = std.mem.findScalarPos(u8, token, first_dot + 1, '.') orelse
        return error.Malformed;
    if (std.mem.findScalarPos(u8, token, second_dot + 1, '.') != null) return error.Malformed;

    var header_buffer: [token_size_max]u8 = undefined;
    const header = try decode_part(token[0..first_dot], &header_buffer);
    try check_header(header);

    var signature: [HmacSha256.mac_length]u8 = undefined;
    const signature_text = token[second_dot + 1 ..];
    const signature_size = base64.Decoder.calcSizeForSlice(signature_text) catch
        return error.Malformed;
    if (signature_size != signature.len) return error.InvalidSignature;
    base64.Decoder.decode(&signature, signature_text) catch return error.Malformed;
    var expected: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected, token[0..second_dot], &secret.bytes);
    if (!std.crypto.timing_safe.eql([HmacSha256.mac_length]u8, signature, expected)) {
        return error.InvalidSignature;
    }

    var claims_buffer: [token_size_max]u8 = undefined;
    const claims = try decode_part(token[first_dot + 1 .. second_dot], &claims_buffer);
    const iat = try claim_iat(claims);
    const distance = if (iat > now_s) iat - now_s else now_s - iat;
    if (distance > iat_window_s) return error.IssuedAtOutOfWindow;
    return iat;
}

/// Extracts the token from an `Authorization: Bearer <token>` header value.
pub fn bearer_token(authorization: []const u8) ?[]const u8 {
    const prefix = "Bearer ";
    if (authorization.len <= prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(authorization[0..prefix.len], prefix)) return null;
    return std.mem.trim(u8, authorization[prefix.len..], " ");
}

fn decode_part(text: []const u8, buffer: []u8) VerifyError![]const u8 {
    const size = base64.Decoder.calcSizeForSlice(text) catch return error.Malformed;
    if (size > buffer.len) return error.Malformed;
    base64.Decoder.decode(buffer[0..size], text) catch return error.Malformed;
    return buffer[0..size];
}

fn check_header(header: []const u8) VerifyError!void {
    var scanner = json.Scanner.init(header);
    json.validate(header) catch return error.Malformed;
    const first = scanner.next() catch unreachable;
    if (first.tag != .object_begin) return error.Malformed;
    var algorithm_ok = false;
    var iterations: usize = 0;
    while (iterations < header.len) : (iterations += 1) {
        const key = scanner.next() catch unreachable;
        if (key.tag == .object_end) break;
        const value = scanner.next() catch unreachable;
        if (std.mem.eql(u8, key.bytes, "alg")) {
            // Exact match: "none", "hs256", or escaped variants are all rejected.
            if (value.tag != .string or value.escaped) return error.UnsupportedAlgorithm;
            if (!std.mem.eql(u8, value.bytes, "HS256")) return error.UnsupportedAlgorithm;
            algorithm_ok = true;
        }
        scanner.skip(value) catch unreachable;
    }
    if (!algorithm_ok) return error.UnsupportedAlgorithm;
}

fn claim_iat(claims: []const u8) VerifyError!u64 {
    var scanner = json.Scanner.init(claims);
    json.validate(claims) catch return error.Malformed;
    const first = scanner.next() catch unreachable;
    if (first.tag != .object_begin) return error.Malformed;
    var iat: ?u64 = null;
    var iterations: usize = 0;
    while (iterations < claims.len) : (iterations += 1) {
        const key = scanner.next() catch unreachable;
        if (key.tag == .object_end) break;
        const value = scanner.next() catch unreachable;
        if (std.mem.eql(u8, key.bytes, "iat")) {
            if (value.tag != .number) return error.MissingIssuedAt;
            iat = std.fmt.parseInt(u64, value.bytes, 10) catch return error.MissingIssuedAt;
        }
        scanner.skip(value) catch unreachable;
    }
    return iat orelse error.MissingIssuedAt;
}

const test_secret_hex = "0x" ++ "0123456789abcdef" ++ "0123456789abcdef" ++
    "0123456789abcdef" ++ "0123456789abcdef";

test "jwt: create and verify round trip" {
    const secret = try Secret.parse_hex(test_secret_hex ++ "\n");
    var buffer: [token_size_max]u8 = undefined;
    const token = create(secret, 1_700_000_000, &buffer);
    try std.testing.expectEqual(@as(u64, 1_700_000_000), try verify(secret, token, 1_700_000_030));
    try std.testing.expectEqual(@as(u64, 1_700_000_000), try verify(secret, token, 1_699_999_940));
    try std.testing.expectError(error.IssuedAtOutOfWindow, verify(secret, token, 1_700_000_061));
    try std.testing.expectError(error.IssuedAtOutOfWindow, verify(secret, token, 1_699_999_939));
    try std.testing.expectEqualStrings(test_secret_hex[2..], &secret.to_hex());
}

test "jwt: rejects tampering and wrong secrets" {
    const secret = try Secret.parse_hex(test_secret_hex);
    var other = secret;
    other.bytes[0] ^= 1;
    var buffer: [token_size_max]u8 = undefined;
    const token = create(secret, 100, &buffer);
    try std.testing.expectError(error.InvalidSignature, verify(other, token, 100));
    var tampered: [token_size_max]u8 = undefined;
    @memcpy(tampered[0..token.len], token);
    const dot = std.mem.findScalarLast(u8, token, '.').?;
    tampered[dot - 1] ^= 1; // Flip a claims byte.
    try std.testing.expect(std.meta.isError(verify(secret, tampered[0..token.len], 100)));
    try std.testing.expectError(error.Malformed, verify(secret, "a.b", 100));
    try std.testing.expectError(error.Malformed, verify(secret, "a.b.c.d", 100));
    try std.testing.expectError(error.InvalidSecret, Secret.parse_hex("0x1234"));
}

test "jwt: rejects alg none and other algorithms" {
    const secret = try Secret.parse_hex(test_secret_hex);
    var buffer: [token_size_max]u8 = undefined;
    const valid = create(secret, 100, &buffer);
    const rest = valid[std.mem.findScalar(u8, valid, '.').?..];
    const headers = [_][]const u8{
        "{\"alg\":\"none\",\"typ\":\"JWT\"}",
        "{\"alg\":\"HS512\"}",
        "{\"alg\":\"hs256\"}",
        "{\"typ\":\"JWT\"}",
    };
    for (headers) |header| {
        var forged: [token_size_max]u8 = undefined;
        const encoded = base64.Encoder.encode(&forged, header);
        @memcpy(forged[encoded.len..][0..rest.len], rest);
        const token = forged[0 .. encoded.len + rest.len];
        try std.testing.expectError(error.UnsupportedAlgorithm, verify(secret, token, 100));
    }
}

test "jwt: bearer header" {
    try std.testing.expectEqualStrings("abc", bearer_token("Bearer abc").?);
    try std.testing.expectEqualStrings("abc", bearer_token("bearer  abc").?);
    try std.testing.expectEqual(@as(?[]const u8, null), bearer_token("Basic abc"));
    try std.testing.expectEqual(@as(?[]const u8, null), bearer_token("Bearer "));
}

fn verify_arbitrary(token: []const u8) !void {
    const secret: Secret = .{ .bytes = @splat(7) };
    if (verify(secret, token, 1000)) |iat| {
        // Accepting means the signature matched: only possible for a token we created.
        var buffer: [token_size_max]u8 = undefined;
        try std.testing.expectEqualStrings(create(secret, iat, &buffer), token);
    } else |_| {}
}

test "jwt: seeded fuzz of mutated tokens" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x3a7);
    const secret: Secret = .{ .bytes = @splat(7) };
    var buffer: [token_size_max]u8 = undefined;
    for (0..2000) |_| {
        const token = create(secret, prng.range(900, 1100), &buffer);
        var mutated: [token_size_max]u8 = undefined;
        @memcpy(mutated[0..token.len], token);
        var size = token.len;
        switch (prng.below(3)) {
            0 => mutated[prng.below(size)] = prng.int(u8),
            1 => size = prng.below(size),
            2 => {},
            else => unreachable,
        }
        try verify_arbitrary(mutated[0..size]);
    }
}

fn fuzz_verify(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var token: [token_size_max]u8 = undefined;
    const size = smith.slice(&token);
    try verify_arbitrary(token[0..size]);
}

test "jwt: fuzz verify" {
    try std.testing.fuzz({}, fuzz_verify, .{});
}

//! libp2p peer ids (libp2p `peer-ids` spec). A peer id is a multihash of the protobuf
//! `PublicKey { Type type = 1; bytes Data = 2; }`. Keys that serialize to <= 42 bytes use
//! the identity multihash, so a secp256k1 peer id is
//! `0x00 0x25 | 0x08 0x02 0x12 0x21 | <33-byte compressed key>` (39 bytes), whose base58
//! text starts with `16Uiu2`. OP Stack nodes always use secp256k1 identities.

const std = @import("std");
const assert = std.debug.assert;
const base58 = @import("base58.zig");
const secp256k1 = @import("secp256k1.zig");
const varint = @import("varint.zig");

/// Longest multihash we store: sha256 (2 + 32) or an identity key up to 42 bytes.
pub const length_max = 2 + 42;
pub const text_length_max = 64;

const multihash_identity = 0x00;
const multihash_sha256 = 0x12;
const key_type_secp256k1 = 2;
const secp256k1_protobuf_prefix = [_]u8{ 0x08, key_type_secp256k1, 0x12, 33 };
pub const secp256k1_length = 2 + secp256k1_protobuf_prefix.len + secp256k1.compressed_length;

pub const Error = error{ InvalidPeerId, InvalidText };

pub const PeerId = struct {
    /// Bytes past `length` are always zero so `std.meta.eql` agrees with `eql`.
    bytes: [length_max]u8,
    length: u8,

    pub fn slice(peer: *const PeerId) []const u8 {
        assert(peer.length <= length_max);
        return peer.bytes[0..peer.length];
    }

    pub fn eql(a: *const PeerId, b: *const PeerId) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }

    /// The embedded secp256k1 key, or null for other key types or hashed ids.
    pub fn secp256k1_public_key(peer: *const PeerId) ?secp256k1.PublicKey {
        if (peer.length != secp256k1_length) return null;
        const body = peer.bytes[2..secp256k1_length];
        if (peer.bytes[0] != multihash_identity) return null;
        if (!std.mem.eql(u8, body[0..4], &secp256k1_protobuf_prefix)) return null;
        return body[4..][0..secp256k1.compressed_length].*;
    }

    pub fn format(peer: *const PeerId, output: []u8) []const u8 {
        assert(output.len >= text_length_max);
        // A validated multihash is at most `length_max` bytes, well within base58 bounds.
        return base58.encode(output, peer.slice()) catch unreachable;
    }
};

pub fn from_public_key(key: secp256k1.PublicKey) PeerId {
    assert(key[0] == 0x02 or key[0] == 0x03);
    var peer: PeerId = .{ .bytes = @splat(0), .length = secp256k1_length };
    peer.bytes[0] = multihash_identity;
    peer.bytes[1] = secp256k1_protobuf_prefix.len + secp256k1.compressed_length;
    @memcpy(peer.bytes[2..6], &secp256k1_protobuf_prefix);
    @memcpy(peer.bytes[6..secp256k1_length], &key);
    assert(peer.secp256k1_public_key() != null);
    return peer;
}

/// Validates multihash structure (identity or sha256) and copies it.
pub fn from_bytes(bytes: []const u8) Error!PeerId {
    if (bytes.len > length_max) return error.InvalidPeerId;
    const code = varint.decode(bytes) catch return error.InvalidPeerId;
    const size = varint.decode(bytes[code.length..]) catch return error.InvalidPeerId;
    const header_length = code.length + size.length;
    if (bytes.len - header_length != size.value) return error.InvalidPeerId;
    switch (code.value) {
        multihash_identity => if (size.value > 42) return error.InvalidPeerId,
        multihash_sha256 => if (size.value != 32) return error.InvalidPeerId,
        else => return error.InvalidPeerId,
    }
    var peer: PeerId = .{ .bytes = @splat(0), .length = @intCast(bytes.len) };
    @memcpy(peer.bytes[0..bytes.len], bytes);
    return peer;
}

pub fn parse(text: []const u8) Error!PeerId {
    if (text.len == 0 or text.len > text_length_max) return error.InvalidText;
    var bytes: [base58.input_length_max]u8 = undefined;
    const decoded = base58.decode(&bytes, text) catch return error.InvalidText;
    const peer = try from_bytes(decoded);
    if (peer.secp256k1_public_key()) |key| {
        _ = secp256k1.compress(&key) catch return error.InvalidPeerId;
    }
    return peer;
}

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "peer_id: secp256k1 round trip and text prefix" {
    var prng = Prng.init(0x7065_6572);
    var text: [text_length_max]u8 = undefined;
    for (0..16) |_| {
        var secret: secp256k1.SecretKey = undefined;
        prng.fill(&secret);
        const key = secp256k1.public_key(secret) catch continue;
        const peer = from_public_key(key);
        const formatted = peer.format(&text);
        try std.testing.expect(std.mem.startsWith(u8, formatted, "16Uiu2HA"));
        const parsed = try parse(formatted);
        try std.testing.expect(peer.eql(&parsed));
        try std.testing.expectEqual(key, parsed.secp256k1_public_key().?);
    }
}

test "peer_id: rejects malformed" {
    try std.testing.expectError(error.InvalidText, parse(""));
    try std.testing.expectError(error.InvalidText, parse("0OIl"));
    try std.testing.expectError(error.InvalidPeerId, from_bytes(&.{ 0x12, 0x20, 0x00 }));
    try std.testing.expectError(error.InvalidPeerId, from_bytes(&.{ 0x99, 0x00 }));
}

fn fuzz_parse(_: void, input: []const u8) anyerror!void {
    const peer = parse(input) catch return;
    var text: [text_length_max]u8 = undefined;
    const again = try parse(peer.format(&text));
    try std.testing.expect(peer.eql(&again));
}

test "peer_id: fuzz parse" {
    try fuzz.run_bytes({}, fuzz_parse, .{ .input_size_max = 64 });
}

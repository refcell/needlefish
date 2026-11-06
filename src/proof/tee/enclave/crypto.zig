//! The enclave's secp256k1 signer (base/base `crates/proof/tee/nitro-enclave/src/crypto.rs`).
//!
//! The enclave signs keccak256 of the proof journal; the signature is `r || s || v` with v
//! the recovery parity (0 or 1, alloy `as_rsy`), and `AggregateVerifier` recovers the
//! signer address from it. Public keys are 65-byte uncompressed SEC1 points (Go's
//! `crypto.FromECDSAPub`). Verification follows k256 `verify_prehash`: only r and s
//! count, and a high s is rejected.

const std = @import("std");
const assert = std.debug.assert;

const secp256k1 = @import("../../../common/crypto/secp256k1/root.zig");
const keccak = @import("../../../common/crypto/keccak.zig");

pub const Address = [20]u8;
pub const Hash = [32]u8;
pub const signature_length = 65;
pub const public_key_length = 65;
pub const PublicKey = [public_key_length]u8;
pub const Signature = [signature_length]u8;

/// Fresh 32-byte candidates drawn before giving up on a valid private key; each draw
/// fails with probability below 2^-127.
pub const generate_attempts_max = 16;

pub const Error = error{
    InvalidPrivateKey,
    InvalidHex,
    InvalidSignatureLength,
    InvalidPublicKey,
    InvalidSignature,
};

pub const Signer = struct {
    private_key: [32]u8,
    /// Uncompressed SEC1: 0x04 || x || y.
    public_key: PublicKey,
    address: Address,

    /// A signer from a 32-byte private key in [1, n - 1].
    pub fn from_bytes(bytes: []const u8) Error!Signer {
        if (bytes.len != 32) return error.InvalidPrivateKey;
        const private_key = bytes[0..32].*;
        const public = secp256k1.public_key(private_key) catch return error.InvalidPrivateKey;
        var signer: Signer = .{
            .private_key = private_key,
            .public_key = undefined,
            .address = secp256k1.public_key_to_address(&public),
        };
        signer.public_key[0] = 0x04;
        signer.public_key[1..].* = public;
        assert(signer.public_key[0] == 0x04);
        assert(!std.mem.allEqual(u8, &signer.address, 0));
        return signer;
    }

    /// A signer from a hex private key, optionally `0x`-prefixed.
    pub fn from_hex(text: []const u8) Error!Signer {
        const digits = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
        if (digits.len != 64) return error.InvalidHex;
        var bytes: [32]u8 = undefined;
        const decoded = std.fmt.hexToBytes(&bytes, digits) catch return error.InvalidHex;
        assert(decoded.len == 32);
        return from_bytes(&bytes);
    }

    /// A signer from random bytes drawn through `context.fill(buffer) !void` (the NSM's
    /// hardware RNG in an enclave).
    pub fn generate(context: anytype) !Signer {
        var attempt: u32 = 0;
        while (attempt < generate_attempts_max) : (attempt += 1) {
            var candidate: [32]u8 = undefined;
            try context.fill(&candidate);
            return from_bytes(&candidate) catch continue;
        }
        return error.InvalidPrivateKey;
    }

    /// keccak256(data) signed: `r || s || v`, v in {0, 1}.
    pub fn sign(signer: *const Signer, data: []const u8) Signature {
        const digest = keccak.keccak256(data);
        // The private key was validated at construction.
        const signature = secp256k1.sign(signer.private_key, digest) catch unreachable;
        var out: Signature = undefined;
        out[0..32].* = signature.r;
        out[32..64].* = signature.s;
        out[64] = @as(u8, signature.recovery_id) & 1;
        assert(secp256k1.is_low_s(signature.s));
        assert(out[64] <= 1);
        return out;
    }
};

/// Verifies `signature` (65 bytes; v ignored) over keccak256(`data`) against a SEC1
/// public key (65-byte uncompressed or 33-byte compressed).
pub fn verify(public_key: []const u8, data: []const u8, signature: []const u8) Error!bool {
    if (signature.len != signature_length) return error.InvalidSignatureLength;
    const point = try decode_public_key(public_key);
    const r = signature[0..32].*;
    const s = signature[32..64].*;
    if (std.mem.allEqual(u8, &r, 0) or std.mem.allEqual(u8, &s, 0)) {
        return error.InvalidSignature;
    }
    const digest = keccak.keccak256(data);
    if (!secp256k1.is_low_s(s)) return false;
    const valid = secp256k1.verify(digest, r, s, &point);
    assert(signature.len == signature_length);
    return valid;
}

/// The address that signed keccak256(`data`), or null.
pub fn recover_address(data: []const u8, signature: *const Signature) ?Address {
    const digest = keccak.keccak256(data);
    const v = signature[64];
    const parity: u1 = switch (v) {
        0, 27 => 0,
        1, 28 => 1,
        else => return null,
    };
    assert(v <= 28);
    return secp256k1.ecrecover_address(digest, parity, signature[0..32].*, signature[32..64].*);
}

fn decode_public_key(bytes: []const u8) Error!secp256k1.PublicKey {
    if (bytes.len == public_key_length and bytes[0] == 0x04) {
        const point = bytes[1..65].*;
        if (secp256k1.decode_public_key(&point) == null) return error.InvalidPublicKey;
        return point;
    }
    if (bytes.len == 33 and (bytes[0] == 0x02 or bytes[0] == 0x03)) {
        const compressed = bytes[0..33].*;
        return secp256k1.decompress_public_key(&compressed) orelse error.InvalidPublicKey;
    }
    return error.InvalidPublicKey;
}

const testing = std.testing;
const proposal = @import("../../primitives/proposal.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const anvil_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const PrngSource = struct {
    prng: Prng,
    pub fn fill(source: *PrngSource, out: []u8) !void {
        source.prng.fill(out);
    }
};

fn journal_bytes(buffer: *[proposal.proof_journal_base_length]u8) []u8 {
    const journal = proposal.test_journal();
    return journal.encode(buffer);
}

test "enclave crypto: generated signers have uncompressed public keys" {
    var source: PrngSource = .{ .prng = .init(1) };
    const signer = try Signer.generate(&source);
    try testing.expectEqual(@as(u8, 0x04), signer.public_key[0]);
    try testing.expectEqual(@as(usize, 65), signer.public_key.len);
}

test "enclave crypto: signer from hex, with and without prefix, has the anvil address" {
    const expected = [20]u8{
        0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce,
        0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf, 0xfF, 0xb9, 0x22, 0x66,
    };
    try testing.expectEqual(expected, (try Signer.from_hex(anvil_key)).address);
    try testing.expectEqual(expected, (try Signer.from_hex(anvil_key[2..])).address);
}

test "enclave crypto: invalid private keys" {
    const short: [31]u8 = @splat(0);
    try testing.expectError(error.InvalidPrivateKey, Signer.from_bytes(&short));
    const zero: [32]u8 = @splat(0);
    try testing.expectError(error.InvalidPrivateKey, Signer.from_bytes(&zero));
    try testing.expectError(error.InvalidHex, Signer.from_hex("0xzz"));
}

test "enclave crypto: sign and verify round trip, recover the address" {
    var source: PrngSource = .{ .prng = .init(2) };
    const signer = try Signer.generate(&source);
    var buffer: [proposal.proof_journal_base_length]u8 = undefined;
    const data = journal_bytes(&buffer);
    const signature = signer.sign(data);
    try testing.expect(signature[64] <= 1);
    try testing.expect(try verify(&signer.public_key, data, &signature));
    try testing.expectEqual(signer.address, recover_address(data, &signature).?);
}

test "enclave crypto: a wrong key or wrong data fails verification" {
    var source: PrngSource = .{ .prng = .init(3) };
    const signer = try Signer.generate(&source);
    const other = try Signer.generate(&source);
    var buffer: [proposal.proof_journal_base_length]u8 = undefined;
    const data = journal_bytes(&buffer);
    const signature = signer.sign(data);
    try testing.expect(!try verify(&other.public_key, data, &signature));
    var journal = proposal.test_journal();
    journal.proposer = @splat(0);
    journal.proposer[19] = 1;
    var other_buffer: [proposal.proof_journal_base_length]u8 = undefined;
    const other_data = journal.encode(&other_buffer);
    try testing.expect(!try verify(&signer.public_key, other_data, &signature));
}

test "enclave crypto: invalid signature length" {
    const public_key: [65]u8 = @splat(0x04);
    const data: [proposal.proof_journal_base_length]u8 = @splat(0);
    const short: [64]u8 = @splat(0);
    try testing.expectError(error.InvalidSignatureLength, verify(&public_key, &data, &short));
}

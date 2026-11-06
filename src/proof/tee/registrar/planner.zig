//! Nitro attestation registration-plan construction (base/base
//! `registrar/src/planner.rs`).
//!
//! Strictly parses `COSE_Sign1` (raw protected/payload TLVs for the TBS) and builds
//! the `CertManager`-oriented plan fields hinted registration needs.

const std = @import("std");
const assert = std.debug.assert;
const cbor = @import("cbor.zig");
const types = @import("types.zig");
const nitro_attestation = @import("../nitro/attestation.zig");
const nitro_errors = @import("../nitro/errors.zig");
const nitro_types = @import("../nitro/types.zig");
const verify = @import("../nitro/verify.zig");
const x509 = @import("../nitro/x509.zig");
const keccak256 = @import("../../../common/crypto/keccak.zig").keccak256;

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const NitroCose = cbor.NitroCose;
const CertKind = types.CertKind;
const CertPlan = types.CertPlan;
const Hash = types.Hash;
const RegistrationPlan = types.RegistrationPlan;

const uncompressed_secp256k1_size: u32 = 65;

/// Largest attestation the planner accepts; the nitro decoder's input limit.
pub const attestation_size_max: u32 = nitro_attestation.limits.input_size_max;
/// TBS buffer size that fits any accepted attestation.
pub const tbs_size_max: u32 = attestation_size_max + cbor.tbs_prefix_size;

/// Full-DER keccak of the pinned AWS Nitro root certificate.
pub const pinned_root_cert_hash: Hash = hex32(
    "311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185",
);

pub const PlannerError = error{
    PlanBufferTooSmall,
    AttestationPublicKeyMissing,
    AttestationPcr0Missing,
    AttestationCabundleTooShort,
    AttestationRootNotPinned,
    PlanMismatch,
    LeafPublicKeyInvalid,
    AttestationSignatureRejected,
    PublicKeyFormat,
    PublicKeyInvalid,
    CertificateVersionMissing,
    CertificateVersionTrailingData,
    CertificateVersionNotV3,
    DerTooShort,
    DerLengthInvalid,
    DerLengthMismatch,
};

pub const Error = PlannerError || cbor.Error || nitro_errors.Error;

/// Scratch for `authenticate_registration_plan`: a rebuilt envelope and its TBS.
/// About 128 KiB; allocate once.
pub const AuthenticateScratch = struct {
    envelope: [tbs_size_max]u8,
    tbs: [tbs_size_max]u8,
};

/// Parses AWS Nitro `COSE_Sign1` attestations into certificate registration plans.
pub const AttestationPlanner = struct {
    /// Authenticate every plan field against the pinned-root chain and the signed
    /// payload.
    pub fn authenticate_registration_plan(
        plan: *const RegistrationPlan,
        scratch: *AuthenticateScratch,
    ) Error!void {
        assert(plan.cert_count <= types.cert_plan_count_max);
        const envelope = try NitroCose.sign1_from_tbs(
            plan.attestation_tbs,
            &plan.signature,
            &scratch.envelope,
        );
        const canonical = try prepare_registration_plan(envelope, &scratch.tbs);
        if (!canonical.eql(plan)) return error.PlanMismatch;
        var certs: [types.chain_length_max][]const u8 = undefined;
        certs[0] = plan.root_cert;
        for (plan.cert_plans(), 1..) |*cert, index| certs[index] = cert.cert;
        const chain = try x509.CertChain.from_der(certs[0 .. plan.cert_count + 1]);
        // Attribution must not depend on CertManager's cache or revocation state.
        var chain_result: x509.ChainResult = undefined;
        try chain.verify_chain(0, plan.timestamp_ms, &chain_result);
        const key = Ecdsa.PublicKey.fromSec1(chain.leaf_public_key()) catch
            return error.LeafPublicKeyInvalid;
        const signature = Ecdsa.Signature.fromBytes(plan.signature);
        signature.verify(plan.attestation_tbs, key) catch
            return error.AttestationSignatureRejected;
    }

    /// Parse a raw `COSE_Sign1` Nitro attestation and build a registration plan.
    ///
    /// Does not generate P-384 hints or submit transactions. The signer comes from
    /// the attestation `public_key` (Base semantics), never from `user_data`. The
    /// plan borrows `attestation` and `tbs_buffer`.
    pub fn prepare_registration_plan(
        attestation: []const u8,
        tbs_buffer: []u8,
    ) Error!RegistrationPlan {
        if (tbs_buffer.len < attestation.len + cbor.tbs_prefix_size) {
            return error.PlanBufferTooSmall;
        }
        const cose = try NitroCose.parse_sign1(attestation, tbs_buffer);
        // Intentional overlap with `validate_attestation_content` below: the raw walk
        // rejects duplicates and trailing bytes a decoder could collapse or miss.
        try NitroCose.validate_payload_structure(cose.payload);
        const document = try nitro_attestation.AttestationDocument.parse(cose.payload);
        try verify.AttestationVerifier.validate_attestation_content(&document);

        const public_key = document.public_key orelse return error.AttestationPublicKeyMissing;
        var plan: RegistrationPlan = undefined;
        plan.signer = try signer_from_public_key(public_key);
        plan.pcr0 = (find_pcr(&document, 0) orelse return error.AttestationPcr0Missing).*;
        if (document.cabundle_count < 2) return error.AttestationCabundleTooShort;
        plan.root_cert = document.cabundle[0];
        plan.root_cert_hash = keccak256(plan.root_cert);
        if (!std.mem.eql(u8, &plan.root_cert_hash, &pinned_root_cert_hash)) {
            return error.AttestationRootNotPinned;
        }
        plan.timestamp_ms = document.timestamp_ms;
        plan.nonce = document.nonce;
        plan.attestation_tbs = cose.attestation_tbs;
        plan.signature = cose.signature.*;
        try fill_cert_plans(&plan, &document);
        assert(plan.cert_count == document.cabundle_count);
        return plan;
    }

    fn fill_cert_plans(
        plan: *RegistrationPlan,
        document: *const nitro_attestation.AttestationDocument,
    ) Error!void {
        assert(document.cabundle_count >= 2);
        var parent_hash = plan.root_cert_hash;
        plan.cert_count = 0;
        for (document.cabundle[1..document.cabundle_count], 1..) |cert, index| {
            const keys = try CertManagerKeys.keys(cert);
            plan.certs[plan.cert_count] = .{
                .kind = .ca,
                .label = ca_label(@intCast(index)),
                .cert = cert,
                .cert_hash = keys.cache_key,
                .parent_cert_hash = parent_hash,
                .revocation_id = keys.revocation_id,
            };
            plan.cert_count += 1;
            parent_hash = keys.cache_key;
        }
        const leaf_keys = try CertManagerKeys.keys(document.certificate);
        plan.certs[plan.cert_count] = .{
            .kind = .leaf,
            .label = types.Label.init("client / leaf cert") catch unreachable, // 18 bytes.
            .cert = document.certificate,
            .cert_hash = leaf_keys.cache_key,
            .parent_cert_hash = parent_hash,
            .revocation_id = leaf_keys.revocation_id,
        };
        plan.cert_count += 1;
        plan.leaf_cert_hash = leaf_keys.cache_key;
        assert(plan.cert_count <= types.cert_plan_count_max);
    }

    fn find_pcr(
        document: *const nitro_attestation.AttestationDocument,
        index: u64,
    ) ?*const [nitro_types.pcr_size_bytes]u8 {
        assert(document.pcr_count <= nitro_types.pcr_count_max);
        for (document.pcrs[0..document.pcr_count]) |*pcr| {
            if (pcr.index == index) return &pcr.value;
        }
        return null;
    }

    /// Human-readable role label for a non-root CA index in the cabundle.
    pub fn ca_label(index: u32) types.Label {
        assert(index >= 1 and index <= types.cert_plan_count_max);
        const text = switch (index) {
            1 => "regional CA",
            2 => "zonal CA",
            3 => "issuer / instance CA",
            else => {
                var label: types.Label = .{};
                const written = std.fmt.bufPrint(&label.bytes, "non-root CA {d}", .{index}) catch
                    unreachable; // At most "non-root CA 32", 14 bytes.
                label.length = @intCast(written.len);
                return label;
            },
        };
        return types.Label.init(text) catch unreachable; // Static labels fit.
    }

    /// Derive the Base signer address from an uncompressed secp256k1 `public_key`:
    /// keccak of the key without the `0x04` prefix, last 20 bytes.
    pub fn signer_from_public_key(public_key: []const u8) Error!types.Address {
        if (public_key.len != uncompressed_secp256k1_size or public_key[0] != 0x04) {
            return error.PublicKeyFormat;
        }
        _ = Secp256k1.fromSec1(public_key) catch return error.PublicKeyInvalid;
        const digest = keccak256(public_key[1..]);
        const address: types.Address = digest[12..32].*;
        assert(address.len == 20);
        return address;
    }
};

/// Certificate hash and revocation helpers aligned with onchain `CertManager`.
pub const CertManagerKeys = struct {
    pub const Keys = struct {
        cache_key: Hash,
        revocation_id: Hash,
    };

    /// `(cache_key, revocation_id)` for `cert` from one X.509 parse.
    ///
    /// The pinned root uses `keccak256(full DER)` as the cache key; every non-root
    /// certificate uses `keccak256(TBSCertificate TLV)`. `revocation_id` is always
    /// `keccak256(issuerHash || serialHash)`. Rejects trailing DER bytes and
    /// requires the version-present v3 TBS layout `CertManager` expects.
    pub fn keys(cert: []const u8) Error!Keys {
        const full_hash = keccak256(cert);
        const parsed = try x509.ParsedCert.parse(cert);
        try require_v3_layout(parsed.tbs, parsed.version);
        const cache_key = if (std.mem.eql(u8, &full_hash, &pinned_root_cert_hash))
            full_hash
        else
            keccak256(parsed.tbs);
        // INTEGER content octets including any DER sign padding, as
        // `CertManager._certIdentity` hashes them.
        const serial_hash = keccak256(parsed.serial);
        const issuer_hash = keccak256(try der_content_octets(parsed.issuer));
        var material: [64]u8 = undefined;
        material[0..32].* = issuer_hash;
        material[32..64].* = serial_hash;
        const result: Keys = .{ .cache_key = cache_key, .revocation_id = keccak256(&material) };
        assert(parsed.tbs.len < cert.len);
        return result;
    }

    /// Require an explicit context-tagged version with value 2 (X.509 v3) whose
    /// INTEGER consumes the whole `[0] EXPLICIT` wrapper (`CertManager._parseTbs`).
    pub fn require_v3_layout(tbs_tlv: []const u8, version: u8) Error!void {
        const tbs_content = try der_content_octets(tbs_tlv);
        if (tbs_content.len == 0 or tbs_content[0] != 0xa0) {
            return error.CertificateVersionMissing;
        }
        const wrapper = try der_tlv_at(tbs_content, 0);
        const version_child = try der_tlv_at(wrapper.content, 0);
        if (version_child.end != wrapper.content.len) {
            return error.CertificateVersionTrailingData;
        }
        if (version != 2) return error.CertificateVersionNotV3;
        assert(wrapper.end <= tbs_content.len);
    }

    /// Strip the tag and length from an exact-fit TLV, returning content octets.
    pub fn der_content_octets(tlv: []const u8) Error![]const u8 {
        const parsed = try der_tlv_at(tlv, 0);
        if (parsed.end != tlv.len) return error.DerLengthMismatch;
        assert(parsed.content.len < tlv.len);
        return parsed.content;
    }

    pub const DerTlv = struct {
        content: []const u8,
        /// End offset; may leave siblings.
        end: usize,
    };

    /// Parse one DER TLV at `start`.
    pub fn der_tlv_at(bytes: []const u8, start: usize) Error!DerTlv {
        if (start > bytes.len or bytes.len - start < 2) return error.DerTooShort;
        const first = bytes[start + 1];
        var header_size: usize = 2;
        var content_size: u64 = first;
        if (first & 0x80 != 0) {
            const width: usize = first & 0x7f;
            if (width == 0 or width > 4 or bytes.len < start + 2 + width) {
                return error.DerLengthInvalid;
            }
            content_size = 0;
            for (bytes[start + 2 ..][0..width]) |byte| content_size = (content_size << 8) | byte;
            header_size = 2 + width;
        }
        const content_start = start + header_size;
        if (content_size > bytes.len - content_start) return error.DerLengthMismatch;
        const end = content_start + @as(usize, @intCast(content_size));
        assert(end <= bytes.len);
        return .{ .content = bytes[content_start..end], .end = end };
    }
};

fn hex32(comptime text: *const [64]u8) Hash {
    var out: Hash = undefined;
    // 64 hex digits always decode to 32 bytes; a bad literal fails at comptime.
    const decoded = std.fmt.hexToBytes(&out, text) catch unreachable;
    assert(decoded.len == out.len);
    return out;
}

test {
    _ = @import("planner_test.zig");
}

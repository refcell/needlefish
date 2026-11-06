//! End-to-end Nitro attestation verification (base/base `verify.rs`): COSE parsing,
//! M-02 content validation, X.509 chain validation (M-01), COSE signature
//! verification against the leaf key, and journal construction. Deterministic and
//! free of side effects: time comes from the attestation document, never a clock.
//!
//! Additions over base/base, both fail-closed:
//!   - the COSE protected header must name ES384;
//!   - `cabundle[0]` must equal `Options.trusted_root_der`, the public AWS Nitro
//!     Enclaves root G1 by default. Set it to null for base/base behavior, where
//!     trust in the root is decided on-chain from the journal's path digests.

const std = @import("std");
const assert = std.debug.assert;
const attestation = @import("attestation.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");
const x509 = @import("x509.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const AttestationDocument = attestation.AttestationDocument;
const AttestationReport = attestation.AttestationReport;

pub const Error = errors.Error;

/// The public AWS Nitro Enclaves root certificate (G1), DER. SHA-256 fingerprint
/// 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b, as published by
/// AWS for verifying attestation documents.
pub const aws_nitro_root_der = @embedFile("aws_nitro_root_g1.der");

/// Size limits from `NitroValidator.sol`, enforced by base/base content validation.
pub const certificate_size_max: u32 = 1024;
pub const public_key_size_max: u32 = 1024;
pub const user_data_size_max: u32 = 512;
pub const nonce_size_max: u32 = 512;
pub const pcr_index_max: u64 = 31;

pub const Options = struct {
    /// Leading certificates already trusted (on-chain cache); they are not re-verified.
    trusted_certs_prefix_len: u8 = 0,
    /// Required DER of `cabundle[0]`; null disables the check.
    trusted_root_der: ?[]const u8 = aws_nitro_root_der,
};

pub const AttestationVerifier = struct {
    /// Verify a raw `COSE_Sign1` attestation report. The journal borrows byte
    /// fields from `report_bytes`.
    pub fn verify(report_bytes: []const u8, options: Options) Error!types.VerifierJournal {
        const report = try AttestationReport.parse(report_bytes);
        try report.cose.check_algorithm();
        const document = &report.document;
        try validate_attestation_content(document);
        if (options.trusted_root_der) |root_der| {
            assert(root_der.len > 0);
            if (!std.mem.eql(u8, document.cabundle[0], root_der)) {
                return error.RootCertNotTrusted;
            }
        }
        var chain_der: [types.chain_length_max][]const u8 = undefined;
        const chain = try x509.CertChain.from_der(document.cert_chain(&chain_der));
        var chain_result: x509.ChainResult = undefined;
        try chain.verify_chain(
            options.trusted_certs_prefix_len,
            document.timestamp_ms,
            &chain_result,
        );
        try verify_cose_signature(chain.leaf_public_key(), &report.cose);
        const journal = build_journal(document, &chain_result, options.trusted_certs_prefix_len);
        assert(journal.cert_count == chain.count);
        return journal;
    }

    /// Verify a `VerifierInput`, as base/base's `verify` does.
    pub fn verify_input(
        input: *const types.VerifierInput,
        trusted_root_der: ?[]const u8,
    ) Error!types.VerifierJournal {
        assert(input.attestation_report.len <= std.math.maxInt(u32));
        return verify(input.attestation_report, .{
            .trusted_certs_prefix_len = input.trusted_certs_prefix_len,
            .trusted_root_der = trusted_root_der,
        });
    }

    /// M-02 / `NitroValidator` content checks.
    pub fn validate_attestation_content(document: *const AttestationDocument) Error!void {
        assert(document.cabundle_count <= types.cabundle_count_max);
        assert(document.pcr_count <= types.pcr_count_max);
        if (document.module_id.len == 0) return error.ModuleIdEmpty;
        if (document.timestamp_ms == 0) return error.TimestampZero;
        if (!std.mem.eql(u8, document.digest, "SHA384")) return error.DigestUnsupported;
        if (document.cabundle_count == 0) return error.CabundleCount;
        for (document.cabundle[0..document.cabundle_count]) |cert| {
            if (cert.len == 0 or cert.len > certificate_size_max) {
                return error.CabundleCertificateLength;
            }
        }
        if (document.certificate.len == 0 or document.certificate.len > certificate_size_max) {
            return error.CertificateLength;
        }
        try validate_pcrs(document.pcrs[0..document.pcr_count]);
        if (document.public_key) |key| {
            // Present-but-empty is rejected: Solidity reads length 0 as absent.
            if (key.len == 0 or key.len > public_key_size_max) return error.PublicKeyLength;
        }
        if (document.user_data) |data| {
            if (data.len > user_data_size_max) return error.UserDataLength;
        }
        if (document.nonce) |nonce| {
            if (nonce.len > nonce_size_max) return error.NonceLength;
        }
    }

    /// 1-32 PCRs, indices 0-31, not all zero (all-zero PCRs mean Nitro debug mode).
    fn validate_pcrs(pcrs: []const types.Pcr) Error!void {
        if (pcrs.len == 0 or pcrs.len > types.pcr_count_max) return error.PcrCount;
        var all_zero = true;
        for (pcrs) |*pcr| {
            if (pcr.index > pcr_index_max) return error.PcrIndex;
            for (pcr.value) |byte| all_zero = all_zero and byte == 0;
        }
        if (all_zero) return error.PcrsAllZero;
        assert(!all_zero and pcrs.len > 0);
    }

    /// The COSE signature is raw `r || s` (96 bytes) over the `Sig_structure`.
    fn verify_cose_signature(
        leaf_public_key: []const u8,
        cose: *const attestation.CoseSign1,
    ) Error!void {
        assert(cose.payload.len > 0);
        const public_key = Ecdsa.PublicKey.fromSec1(leaf_public_key) catch
            return error.CertificatePublicKeyInvalid;
        if (cose.signature.len != Ecdsa.Signature.encoded_length) {
            return error.CoseSignatureLength;
        }
        const signature = Ecdsa.Signature.fromBytes(cose.signature[0..96].*);
        var verifier = signature.verifier(public_key) catch return error.CoseSignatureInvalid;
        cose.sig_structure_emit(&verifier);
        verifier.verify() catch return error.CoseSignatureInvalid;
    }

    fn build_journal(
        document: *const AttestationDocument,
        chain_result: *const x509.ChainResult,
        trusted_certs_prefix_len: u8,
    ) types.VerifierJournal {
        assert(chain_result.count >= 1 and chain_result.count <= types.chain_length_max);
        var journal: types.VerifierJournal = .{
            .result = .success,
            .trusted_certs_prefix_len = trusted_certs_prefix_len,
            .timestamp_ms = document.timestamp_ms,
            .certs = undefined,
            .cert_expiries = undefined,
            .cert_count = chain_result.count,
            .user_data = document.user_data orelse &.{},
            .nonce = document.nonce orelse &.{},
            .public_key = document.public_key orelse &.{},
            .pcrs = undefined,
            .pcr_count = document.pcr_count,
            .module_id = document.module_id,
        };
        const count = chain_result.count;
        @memcpy(journal.certs[0..count], chain_result.digests[0..count]);
        @memcpy(journal.cert_expiries[0..count], chain_result.expiries[0..count]);
        @memcpy(journal.pcrs[0..document.pcr_count], document.pcrs[0..document.pcr_count]);
        assert(journal.pcr_count <= types.pcr_count_max);
        return journal;
    }
};

test {
    _ = @import("verify_test.zig");
}

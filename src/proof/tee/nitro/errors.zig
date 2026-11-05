//! Error set for Nitro attestation verification (base/base `error.rs`).
//!
//! base/base has seven coarse `VerifierError` variants carrying a message string.
//! Zig errors carry no payload, so each failure gets its own error name, and
//! `category` maps it back to the base/base variant.

const std = @import("std");
const assert = std.debug.assert;
const cbor = @import("cbor.zig");

pub const CoseError = error{
    CoseNotArray,
    CoseWrongLength,
    CoseWrongTag,
    CoseFieldType,
    CoseAlgorithmMissing,
    CoseAlgorithmUnsupported,
};

pub const AttestationFormatError = error{
    DocumentNotMap,
    DocumentFieldType,
    DocumentFieldMissing,
    DocumentFieldDuplicate,
    PcrLength,
    PcrDuplicate,
};

pub const X509ParseError = error{
    ChainEmpty,
    ChainTooLong,
    CertificateMalformed,
    CertificateTrailingData,
    CertificateTimeInvalid,
};

pub const CertificateVerificationError = error{
    TrustedPrefixTooLong,
    SelfIssuedNotAnchor,
    CertificateNotYetValid,
    CertificateExpired,
    IssuerMismatch,
    PathLengthExceeded,
    SignatureAlgorithmUnsupported,
    PublicKeyAlgorithmUnsupported,
    CurveUnsupported,
    LeafIsCa,
    LeafKeyUsage,
    CaMissingBasicConstraints,
    CaNotCa,
    CaMissingKeyUsage,
    CaKeyUsage,
    /// Not in base/base: `cabundle[0]` differs from the configured trusted root.
    RootCertNotTrusted,
};

pub const SignatureVerificationError = error{
    CertificatePublicKeyInvalid,
    CertificateSignatureEncoding,
    CertificateSignatureInvalid,
    CoseSignatureLength,
    CoseSignatureInvalid,
};

pub const ContentValidationError = error{
    ModuleIdEmpty,
    TimestampZero,
    DigestUnsupported,
    CabundleCount,
    CabundleCertificateLength,
    CertificateLength,
    PcrCount,
    PcrIndex,
    PcrsAllZero,
    PublicKeyLength,
    UserDataLength,
    NonceLength,
};

pub const Error = cbor.Error || CoseError || AttestationFormatError || X509ParseError ||
    CertificateVerificationError || SignatureVerificationError || ContentValidationError;

/// base/base `VerifierError` variants.
pub const Category = enum {
    cbor,
    cose_format,
    attestation_format,
    x509_parse,
    certificate_verification,
    signature_verification,
    content_validation,
};

/// Map an error to its base/base `VerifierError` variant.
pub fn category(err: Error) Category {
    const result: Category = if (in_set(cbor.Error, err))
        .cbor
    else if (in_set(CoseError, err))
        .cose_format
    else if (in_set(AttestationFormatError, err))
        .attestation_format
    else if (in_set(X509ParseError, err))
        .x509_parse
    else if (in_set(CertificateVerificationError, err))
        .certificate_verification
    else if (in_set(SignatureVerificationError, err))
        .signature_verification
    else if (in_set(ContentValidationError, err))
        .content_validation
    else
        unreachable;
    assert(@backingInt(result) < @typeInfo(Category).@"enum".field_names.len);
    return result;
}

fn in_set(comptime Set: type, err: Error) bool {
    const names = comptime std.meta.fieldNames(Set);
    assert(names.len > 0);
    inline for (names) |name| {
        if (err == @field(Set, name)) return true;
    }
    return false;
}

test "nitro errors: categories match base/base variants" {
    const testing = std.testing;
    try testing.expectEqual(Category.cbor, category(error.Truncated));
    try testing.expectEqual(Category.cose_format, category(error.CoseWrongLength));
    try testing.expectEqual(Category.attestation_format, category(error.PcrLength));
    try testing.expectEqual(Category.x509_parse, category(error.CertificateTrailingData));
    try testing.expectEqual(Category.certificate_verification, category(error.CertificateExpired));
    try testing.expectEqual(Category.signature_verification, category(error.CoseSignatureInvalid));
    try testing.expectEqual(Category.content_validation, category(error.PcrsAllZero));
}

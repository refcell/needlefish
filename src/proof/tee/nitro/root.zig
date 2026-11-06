//! AWS Nitro Enclave attestation verification (base/base
//! `crates/proof/tee/nitro-verifier`): COSE_Sign1 parsing, attestation document
//! extraction, X.509 chain validation, and the Solidity-aligned verifier journal.

const std = @import("std");

pub const cbor = @import("cbor.zig");
pub const errors = @import("errors.zig");
pub const types = @import("types.zig");
pub const attestation = @import("attestation.zig");
pub const x509 = @import("x509.zig");
pub const verify = @import("verify.zig");

pub const AttestationVerifier = verify.AttestationVerifier;
pub const Options = verify.Options;
pub const VerifierJournal = types.VerifierJournal;
pub const VerificationResult = types.VerificationResult;
pub const Error = errors.Error;

test {
    std.testing.refAllDecls(@This());
}

//! TEE prover registrar (base/base `crates/proof/tee/registrar`): strict Nitro
//! `COSE_Sign1` parsing, registration planning against the onchain `CertManager`,
//! P-384 inverse hints for the onchain verifier, CRL checks, and signer
//! reconciliation across discovery cycles.

const std = @import("std");

pub const cbor = @import("cbor.zig");

test {
    std.testing.refAllDecls(@This());
}

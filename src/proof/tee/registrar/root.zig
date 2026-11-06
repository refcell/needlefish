//! TEE prover registrar (base/base `crates/proof/tee/registrar`): strict Nitro
//! `COSE_Sign1` parsing, registration planning against the onchain `CertManager`,
//! P-384 inverse hints for the onchain verifier, CRL checks, and signer
//! reconciliation across discovery cycles.

const std = @import("std");

pub const cbor = @import("cbor.zig");
pub const types = @import("types.zig");
pub const hints = @import("hints.zig");
pub const planner = @import("planner.zig");

pub const P384Hints = hints.P384Hints;
pub const AttestationPlanner = planner.AttestationPlanner;
pub const CertManagerKeys = planner.CertManagerKeys;
pub const pinned_root_cert_hash = planner.pinned_root_cert_hash;

test {
    std.testing.refAllDecls(@This());
}

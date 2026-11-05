//! AWS Nitro Enclave attestation verification (base/base
//! `crates/proof/tee/nitro-verifier`): COSE_Sign1 parsing, attestation document
//! extraction, X.509 chain validation, and the Solidity-aligned verifier journal.

const std = @import("std");

pub const cbor = @import("cbor.zig");
pub const errors = @import("errors.zig");
pub const types = @import("types.zig");

test {
    std.testing.refAllDecls(@This());
}

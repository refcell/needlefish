//! The AWS Nitro enclave prover (base/base `crates/proof/tee/nitro-enclave`): a
//! secp256k1 signer whose key never leaves the enclave, attested by the Nitro Secure
//! Module, that proves a claim by running the fault-proof client over a witness and
//! signs the proof journal `AggregateVerifier` checks on chain.
//!
//! The host talks to it over the Enclave link: length-prefixed bincode frames, one
//! request per connection. Real vsock and the real `/dev/nsm` driver are outside the
//! standard library; the link runs over any `std.Io` stream and the NSM sits behind an
//! interface with a deterministic fake (see `nsm.zig`).

const std = @import("std");

pub const bincode = @import("bincode.zig");
pub const crypto = @import("crypto.zig");
pub const protocol = @import("protocol.zig");
pub const transport = @import("transport.zig");
pub const nsm = @import("nsm.zig");
pub const oracle = @import("oracle.zig");

pub const Signer = crypto.Signer;
pub const Nsm = nsm.Nsm;

/// The enclave's vsock port (base/base `VSOCK_PORT`).
pub const vsock_port: u32 = 8000;

test {
    std.testing.refAllDecls(@This());
}

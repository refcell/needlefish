//! TEE prover registrar (base/base `crates/proof/tee/registrar`): strict Nitro
//! `COSE_Sign1` parsing, registration planning against the onchain `CertManager`,
//! P-384 inverse hints for the onchain verifier, CRL checks, and signer
//! reconciliation across discovery cycles.

const std = @import("std");

pub const cbor = @import("cbor.zig");
pub const types = @import("types.zig");
pub const hints = @import("hints.zig");
pub const planner = @import("planner.zig");
pub const crl = @import("crl.zig");
pub const registration_tasks = @import("registration_tasks.zig");
pub const reconciler = @import("reconciler.zig");
pub const prover = @import("prover.zig");
pub const l1 = @import("l1.zig");
pub const metrics = @import("metrics.zig");
pub const signer_manager = @import("signer_manager.zig");
pub const fakes = @import("fakes.zig");
pub const rpc_l1 = @import("rpc_l1.zig");
pub const discovery = @import("discovery.zig");
pub const driver = @import("driver.zig");
pub const service = @import("service.zig");

pub const P384Hints = hints.P384Hints;
pub const AttestationPlanner = planner.AttestationPlanner;
pub const CertManagerKeys = planner.CertManagerKeys;
pub const pinned_root_cert_hash = planner.pinned_root_cert_hash;
pub const SignerReconciler = reconciler.SignerReconciler;
pub const RegistrationTaskSet = registration_tasks.RegistrationTaskSet;
pub const SignerManager = signer_manager.SignerManager;
pub const RegistrationDriver = driver.Driver;
pub const StaticDiscovery = discovery.StaticDiscovery;
pub const RegistrarConfig = service.RegistrarConfig;

test {
    std.testing.refAllDecls(@This());
}

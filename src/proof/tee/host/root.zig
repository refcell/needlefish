//! The TEE prover host (base/base `crates/proof/tee/nitro-host`): fronts one or more
//! enclaves for the prover service.
//!
//! A prover worker (`prover_service/worker.zig`) claims AWS Nitro TEE jobs; the
//! `proof_generator.Generator` backend records each request's witness on the host with the
//! proof host's handler and store (`backend.zig`), proves it on a free enclave whose signer
//! is valid onchain (`pool.zig`, `registration.zig`), and returns the enclave's signed
//! aggregate proposal. `server.zig` exposes the signer keys, attestations, and health
//! (`health.zig`) to the registrar. Enclaves are reached over an Enclave link transport
//! (`link.zig`): vsock on a Nitro instance, or an enclave in this process in local mode.

const std = @import("std");

pub const config = @import("config.zig");
pub const link = @import("link.zig");
pub const backend = @import("backend.zig");
pub const registration = @import("registration.zig");
pub const rpc_registry = @import("rpc_registry.zig");
pub const pool = @import("pool.zig");
pub const health = @import("health.zig");
pub const proof_generator = @import("proof_generator.zig");
pub const server = @import("server.zig");

pub const Link = link.Link;
pub const LocalEnclave = link.LocalEnclave;
pub const Pool = pool.Pool;
pub const Checker = registration.Checker;
pub const Generator = proof_generator.Generator;
pub const Server = server.Server;

test {
    std.testing.refAllDecls(@This());
}

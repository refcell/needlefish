//! The challenger (base/base `crates/proof/challenge`): scans dispute games, recomputes
//! their output roots, disputes invalid ones with TEE or ZK proofs, keeps the anchor
//! moving, and claims its bonds. Pure state machines over injected `chain` vtables; the
//! driver's `tick(now)` is the only entry point a runtime needs.

pub const chain = @import("chain.zig");
pub const config = @import("config.zig");
pub const scanner = @import("scanner.zig");
pub const validator = @import("validator.zig");
pub const dispute_attempt = @import("dispute_attempt.zig");
pub const proof_manager = @import("proof_manager.zig");
pub const bond = @import("bond.zig");
pub const anchor = @import("anchor.zig");
pub const driver = @import("driver.zig");

pub const Config = config.Config;
pub const Driver = driver.Driver;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("sim_test.zig");
}

//! basectl: plain-text operator commands over the node, consensus, batcher, and conductor
//! JSON-RPCs (base/base `crates/infra/basectl`, CLI commands only; the TUI is out of scope).
//!
//! Each command is fetch (through the injected `batcher/rpc` client), decode (pure, into a
//! fixed-size report), and render (pure, to a `*std.Io.Writer`, as text or JSON). Reads of
//! methods a server does not implement report "unavailable" instead of failing.

const std = @import("std");

pub const types = @import("types.zig");
pub const sync_status = @import("sync_status.zig");
pub const block = @import("block.zig");
pub const txpool = @import("txpool.zig");
pub const batcher = @import("batcher.zig");
pub const p2p = @import("p2p.zig");
pub const conductor = @import("conductor.zig");
pub const sequencer = @import("sequencer.zig");
pub const proofs = @import("proofs.zig");
pub const upgrade_readiness = @import("upgrade_readiness.zig");
pub const doctor = @import("doctor.zig");
pub const fake = @import("fake.zig");

pub const Context = types.Context;
pub const Endpoint = types.Endpoint;

test {
    std.testing.refAllDecls(@This());
    _ = @import("doctor_test.zig");
    _ = @import("fuzz_test.zig");
}

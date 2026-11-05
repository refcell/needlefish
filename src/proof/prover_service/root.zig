//! `proof/prover_service`: the proof request service and its workers. Port of base/base
//! `crates/proof/prover-service` (protocol, server, status poller, clients) and
//! `crates/proof/worker` (job discovery, heartbeat, submission), with a bounded in-memory
//! job store in place of Postgres.

const std = @import("std");

pub const protocol = @import("protocol.zig");
pub const codec = @import("codec.zig");
pub const store = @import("store.zig");
pub const service = @import("service.zig");
pub const client = @import("client.zig");
pub const challenger_prover = @import("challenger_prover.zig");
pub const proposer_native = @import("proposer_native.zig");
pub const worker = @import("worker.zig");
pub const exporter = @import("exporter.zig");
pub const native_backend = @import("native_backend.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("e2e_test.zig");
}

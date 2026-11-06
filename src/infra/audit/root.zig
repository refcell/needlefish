//! Transaction-event audit archiver (base/base `crates/infra/audit` + `bin/audit-archiver`).
//!
//! Accepts Vector `transaction-event/v1` NDJSON batches over HTTP, stores them
//! idempotently by `event_id`, and serves the `base_getTransactionEvents*` JSON-RPC
//! queries. base/base stores events in Postgres; needlefish has no dependencies, so the
//! store is a bounded, statically allocated ring with hash indexes and an optional
//! append-only segment file for durability (see `store.zig` and `segment.zig`).

const std = @import("std");

pub const time = @import("time.zig");
pub const event = @import("event.zig");
pub const store = @import("store.zig");
pub const segment = @import("segment.zig");
pub const ingest = @import("ingest.zig");
pub const rpc = @import("rpc.zig");
pub const archiver = @import("archiver.zig");

pub const Archiver = archiver.Archiver;

test {
    std.testing.refAllDecls(@This());
}

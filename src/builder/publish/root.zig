//! Flashblocks WebSocket publishing: a replay ring of encoded flashblocks and a publisher
//! that fans them out to subscribers. Mirrors base/base `crates/builder/publish`.

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}

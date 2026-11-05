//! `proof/host`: serves the fault-proof program's preimages. Port of base/base
//! `crates/proof/host`.

const std = @import("std");

pub const store = @import("store.zig");
pub const handler = @import("handler.zig");
pub const archive = @import("archive.zig");
pub const offline = @import("offline.zig");
pub const rpc_source = @import("rpc_source.zig");
pub const beacon_blobs = @import("beacon_blobs.zig");
pub const native = @import("native.zig");
pub const recording = @import("recording.zig");
pub const Recording = recording.Recording;

pub const Store = store.Store;
pub const BootValues = store.BootValues;
pub const Handler = handler.Handler;
pub const Source = handler.Source;

test {
    std.testing.refAllDecls(@This());
    _ = @import("host_test.zig");
    _ = @import("beacon_blobs_test.zig");
    _ = @import("rpc_source_test.zig");
}

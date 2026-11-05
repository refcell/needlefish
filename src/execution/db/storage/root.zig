//! Crash-safe storage engine over an injected sector storage.
//!
//! Layout on disk: four superblock copies, two checkpoint zones (A/B), and a write-ahead
//! journal ring. The engine stores opaque bytes; callers define what a checkpoint or a
//! journal entry means. See `engine.zig` for the protocol and its crash-safety argument.

const std = @import("std");

pub const storage = @import("storage.zig");
pub const checksum = @import("checksum.zig");
pub const sim_storage = @import("sim_storage.zig");

pub const sector_size = storage.sector_size;
pub const SimStorage = sim_storage.SimStorage;

test {
    std.testing.refAllDecls(@This());
}

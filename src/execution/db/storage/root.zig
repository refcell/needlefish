//! Crash-safe storage engine over an injected sector storage.
//!
//! Layout on disk: four superblock copies, two checkpoint zones (A/B), and a write-ahead
//! journal ring. The engine stores opaque bytes; callers define what a checkpoint or a
//! journal entry means. See `engine.zig` for the protocol and its crash-safety argument.

const std = @import("std");

pub const storage = @import("storage.zig");
pub const checksum = @import("checksum.zig");
pub const sim_storage = @import("sim_storage.zig");
pub const superblock = @import("superblock.zig");
pub const journal = @import("journal.zig");
pub const checkpoint = @import("checkpoint.zig");
pub const engine = @import("engine.zig");

pub const sector_size = storage.sector_size;
pub const SimStorage = sim_storage.SimStorage;
pub const EngineType = engine.EngineType;
pub const Config = engine.Config;
pub const Consumer = engine.Consumer;
pub const Producer = engine.Producer;
pub const OpenResult = engine.OpenResult;
pub const tick_until_idle = engine.tick_until_idle;

test {
    std.testing.refAllDecls(@This());
    _ = @import("journal_test.zig");
    _ = @import("engine_test.zig");
}

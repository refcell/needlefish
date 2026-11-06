//! Replay real Base blocks offline and check needlefish reproduces every canonical header
//! field (`base replay`, docs/REPLAY.md).
//!
//! - `archive`: the checksummed, compressed witness archive (`NFRP`).
//! - `replayer`: chained stateless replay of an archive through the node's executor.

const std = @import("std");

pub const archive = @import("archive.zig");
pub const replayer = @import("replayer.zig");
pub const Archive = archive.Archive;
pub const Replayer = replayer.Replayer;

test {
    std.testing.refAllDecls(@This());
    _ = @import("archive_test.zig");
}

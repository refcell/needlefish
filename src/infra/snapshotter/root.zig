//! Node datadir snapshots (base/base `crates/infra/snapshotter`): a tip check, then the
//! node database split into content-addressed BLAKE3 chunks plus a manifest, written to a
//! local snapshot store; restore verifies every chunk before the database is replaced.
//! Docker control and S3 upload are out of scope (zero dependencies): the binary runs
//! operator-supplied stop/start commands and writes to a directory.

const std = @import("std");

pub const manifest = @import("manifest.zig");
pub const tip = @import("tip.zig");

test {
    std.testing.refAllDecls(@This());
}

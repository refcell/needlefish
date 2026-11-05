//! Proof transaction submission (base/base `crates/proof/submission`): the generic
//! JSON-RPC transaction sender and the known-revert classifier shared by the proposer and
//! the challenger.

const std = @import("std");

pub const classifier = @import("classifier.zig");
pub const sender = @import("sender.zig");

pub const KnownRevert = classifier.KnownRevert;
pub const classify = classifier.classify;
pub const Sender = sender.Sender;

test {
    std.testing.refAllDecls(@This());
}

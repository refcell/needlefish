//! Payload building: Engine API payload attributes and payload IDs, and (as the
//! executor lands) the builder that turns attributes plus pool transactions into a
//! sealed block. Mirrors base/base `crates/execution/payload`.

const std = @import("std");

pub const attributes = @import("attributes.zig");
pub const PayloadAttributes = attributes.PayloadAttributes;
pub const PayloadId = attributes.PayloadId;
pub const Version = attributes.Version;
pub const Withdrawal = attributes.Withdrawal;

test {
    std.testing.refAllDecls(@This());
}

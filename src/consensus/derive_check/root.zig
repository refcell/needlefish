//! Derivation check (docs/SYNC_PLAN.md M5): derive a real chain's safe blocks from L1 and
//! compare every payload attributes with the canonical block of a reference node, the way
//! a verifier's consolidation does. The network glue lives in `bin/base/derive_check.zig`;
//! this module holds the comparison, the start-point rules, and the cadence tracker.

const std = @import("std");

pub const compare = @import("compare.zig");
pub const start = @import("start.zig");
pub const cadence = @import("cadence.zig");

test {
    std.testing.refAllDecls(@This());
}

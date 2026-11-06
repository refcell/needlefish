//! L2 to L1 withdrawer (base/base `crates/infra/withdrawer`): initiate a withdrawal on L2,
//! prove it on L1 against a dispute game's output root, and finalize it after the proof
//! maturity delay. The core is pure: log and proof decoding (`withdrawal`), portal calldata
//! and read decoders (`calldata`), the next-step decision (`status`), and the broadcast
//! journal codec (`journal`) that lets a restarted run resume without double-sending.

const std = @import("std");

pub const withdrawal = @import("withdrawal.zig");
pub const calldata = @import("calldata.zig");
pub const status = @import("status.zig");
pub const journal = @import("journal.zig");
pub const reader = @import("reader.zig");
pub const flow = @import("flow.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("withdrawal_test.zig");
    _ = @import("status_test.zig");
    _ = @import("flow_test.zig");
    _ = @import("fake_chain.zig");
}

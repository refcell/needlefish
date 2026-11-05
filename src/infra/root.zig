//! Infrastructure tools (base/base `crates/infra/*` and the tool-side utilities):
//! transaction manager, websocket proxy, RPC proxy, load tester, withdrawer, basectl.

const std = @import("std");

pub const tx_manager = @import("tx_manager/root.zig");

test {
    std.testing.refAllDecls(@This());
}

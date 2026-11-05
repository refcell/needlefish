//! Minimal L1 log and receipt views used by derivation. The primitives lane will own the
//! full receipt types; these borrow their data and are cheap to construct from RPC results.

const primitives = @import("../../common/primitives/root.zig");

pub const Log = struct {
    address: primitives.Address,
    topics: []const primitives.B256,
    data: []const u8,
};

pub const Receipt = struct {
    success: bool,
    logs: []const Log,
};

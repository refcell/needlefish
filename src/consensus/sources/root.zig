//! Online data sources for the consensus node: a non-blocking caching L1 chain provider
//! over JSON-RPC, a beacon blob provider, and an L2 engine API client.
//! Mirrors base/base `crates/consensus/providers` (`AlloyChainProvider`,
//! `OnlineBeaconClient`, `OnlineBlobProvider`) and `crates/consensus/engine/src/client.rs`.

const std = @import("std");

pub const json_object = @import("json_object.zig");
pub const header_json = @import("header_json.zig");
pub const transaction_json = @import("transaction_json.zig");
pub const receipt_json = @import("receipt_json.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("l1_json_test.zig");
}

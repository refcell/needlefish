//! Online data sources for the consensus node: a non-blocking caching L1 chain provider
//! over JSON-RPC, a beacon blob provider, and an L2 engine API client.
//! Mirrors base/base `crates/consensus/providers` (`AlloyChainProvider`,
//! `OnlineBeaconClient`, `OnlineBlobProvider`) and `crates/consensus/engine/src/client.rs`.

const std = @import("std");

pub const json_object = @import("json_object.zig");
pub const header_json = @import("header_json.zig");
pub const transaction_json = @import("transaction_json.zig");
pub const receipt_json = @import("receipt_json.zig");
pub const l1_provider = @import("l1_provider.zig");
pub const L1Provider = l1_provider.L1Provider;

test {
    std.testing.refAllDecls(@This());
    _ = @import("l1_json_test.zig");
    _ = @import("l1_provider_test.zig");
}

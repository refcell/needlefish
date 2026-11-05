//! Blocking JSON-RPC clients for the proof tools: the shared endpoint (pump-driven calls
//! over `rpc.Client`) and typed execution and rollup node calls.

pub const endpoint = @import("endpoint.zig");
pub const clients = @import("clients.zig");
pub const Endpoint = endpoint.Endpoint;
pub const Pump = endpoint.Pump;
pub const Block = endpoint.Block;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("rpc_test.zig");
}

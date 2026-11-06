//! roxy: JSON-RPC reverse proxy (base/base `crates/infra/roxy`, which replaces a ProxyD
//! fork). base/base ships only the scaffold (listen address, `/healthz`, `/readyz`); this
//! module extends it toward that intent: load balancing over N upstreams, passive health
//! with bounded exponential ejection backoff and fail-open, retries on another upstream, and
//! a method allowlist, and per-client rate limits (client IPs via `utilities/trusted_proxy`).

const std = @import("std");

pub const allowlist = @import("allowlist.zig");
pub const methods = @import("methods.zig");
pub const pool = @import("pool.zig");
pub const proxy = @import("proxy.zig");
pub const rate_limit = @import("rate_limit.zig");
pub const routes = @import("routes.zig");
pub const split = @import("split.zig");
pub const Routes = routes.Routes;
pub const Mask = pool.Mask;

pub const Allowlist = allowlist.Allowlist;
pub const Pool = pool.Pool;
pub const Proxy = proxy.Proxy;
pub const Options = proxy.Options;

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}

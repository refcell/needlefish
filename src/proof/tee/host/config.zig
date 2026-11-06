//! TEE prover worker configuration (base/base `crates/proof/tee/nitro-host/src/
//! {config,host}.rs`): the prover-service endpoint the worker claims jobs from, and the
//! worker filter that claims only AWS Nitro TEE jobs.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../../prover_service/protocol.zig");
const worker_module = @import("../../prover_service/worker.zig");

pub const Error = error{
    /// The endpoint is not an http:// or https:// URL (base/base `InvalidEndpointScheme`).
    InvalidEndpointScheme,
    /// The endpoint has no host (base/base `MissingEndpointHost`).
    MissingEndpointHost,
    InvalidWorkerId,
    InvalidInterval,
};

/// The TEE kinds this host proves (base/base `NitroHost::new`).
pub const tee_kinds = [_]protocol.TeeKind{.aws_nitro};

pub const Config = struct {
    prover_service_url: []const u8,
    worker_id: []const u8,
    /// 0: the service default.
    lock_duration_seconds: u32 = 0,
    poll_interval_ns: u64 = 5 * std.time.ns_per_s,
    heartbeat_interval_ns: u64 = 30 * std.time.ns_per_s,
    heartbeat_failures_max: u32 = 5,

    /// base/base `NitroWorkerConfig::validate`.
    pub fn validate(config: *const Config) Error!void {
        const url = config.prover_service_url;
        const rest = if (std.mem.startsWith(u8, url, "http://"))
            url["http://".len..]
        else if (std.mem.startsWith(u8, url, "https://"))
            url["https://".len..]
        else
            return error.InvalidEndpointScheme;
        const host_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
        const authority = rest[0..host_end];
        const at = std.mem.lastIndexOfScalar(u8, authority, '@');
        const host = authority[(if (at) |index| index + 1 else 0)..];
        if (host.len == 0 or host[0] == ':') return error.MissingEndpointHost;
        const id = config.worker_id;
        if (id.len == 0 or id.len > protocol.worker_id_bytes_max) return error.InvalidWorkerId;
        if (config.poll_interval_ns == 0 or config.heartbeat_interval_ns == 0) {
            return error.InvalidInterval;
        }
        assert(rest.len < url.len);
    }

    /// The prover worker filter: claim only AWS Nitro TEE jobs.
    pub fn worker_config(config: *const Config) worker_module.Config {
        assert(config.worker_id.len > 0);
        assert(config.worker_id.len <= protocol.worker_id_bytes_max);
        return .{
            .worker_id = .from(config.worker_id),
            .proof_type = .tee,
            .tee_kinds = &tee_kinds,
            .lock_duration_seconds = config.lock_duration_seconds,
            .poll_interval_ns = config.poll_interval_ns,
            .heartbeat_interval_ns = config.heartbeat_interval_ns,
            .heartbeat_failures_max = config.heartbeat_failures_max,
        };
    }
};

const testing = std.testing;

test "tee host config: endpoint validation" {
    var config: Config = .{ .prover_service_url = "http://localhost:8545", .worker_id = "tee-1" };
    try config.validate();
    config.prover_service_url = "https://user@prover.example/rpc";
    try config.validate();
    config.prover_service_url = "file:///tmp/prover-service.sock";
    try testing.expectError(error.InvalidEndpointScheme, config.validate());
    config.prover_service_url = "http:///rpc";
    try testing.expectError(error.MissingEndpointHost, config.validate());
    config.prover_service_url = "http://:80";
    try testing.expectError(error.MissingEndpointHost, config.validate());
    config.prover_service_url = "http://a";
    config.worker_id = "";
    try testing.expectError(error.InvalidWorkerId, config.validate());
}

test "tee host config: the worker claims only Nitro TEE jobs" {
    const config: Config = .{ .prover_service_url = "http://a:1", .worker_id = "tee-1" };
    const worker = config.worker_config();
    try testing.expectEqual(protocol.ProofType.tee, worker.proof_type);
    try testing.expectEqualSlices(protocol.TeeKind, &.{.aws_nitro}, worker.tee_kinds);
    try testing.expect(worker.worker_id.eql("tee-1"));
}

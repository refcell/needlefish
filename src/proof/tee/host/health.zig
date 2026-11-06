//! Registration-gated health of the TEE prover host (base/base
//! `crates/proof/tee/nitro-host/src/health.rs`).
//!
//! Without a registration checker the host is healthy whenever it answers (base/base
//! `HealthzRpc`). With one, `healthz` is healthy once any enclave signer is valid onchain
//! or carries the pending image hash, and then stays healthy (the checker latches), so a
//! transient L1 failure does not get the instance replaced. The proving guard and enclave
//! routing still require current onchain validity.

const std = @import("std");
const assert = std.debug.assert;

const registration = @import("registration.zig");

/// base/base's JSON-RPC server error code for an unhealthy host.
pub const unhealthy_code: i32 = -32000;
pub const not_valid_message = "signer is not a valid signer in TEEProverRegistry";

pub const Status = union(enum) {
    healthy,
    /// The reason, for the JSON-RPC error message.
    unhealthy: []const u8,
};

pub const Health = struct {
    version: []const u8,
    checker: ?*registration.Checker = null,
    checks: u64 = 0,

    pub fn check(health: *Health) Status {
        assert(health.version.len > 0);
        health.checks += 1;
        const checker = health.checker orelse return .healthy;
        const healthy = checker.check_health() catch |err| return .{ .unhealthy = message_of(err) };
        if (!healthy) return .{ .unhealthy = not_valid_message };
        assert(checker.healthy);
        return .healthy;
    }
};

pub fn message_of(err: registration.Error) []const u8 {
    return switch (err) {
        error.RegistryUnavailable => "TEEProverRegistry L1 call failed",
        error.InvalidSetup => "signer setup failed",
        error.SignerUnavailable => "signer setup failed: enclave signer key unavailable",
        error.NotValid, error.NoValidSigner => not_valid_message,
    };
}

const testing = std.testing;
const link_module = @import("link.zig");

test "tee health: healthy without a checker, gated and latched with one" {
    var plain: Health = .{ .version = "0.0.0" };
    try testing.expect(plain.check() == .healthy);
    const local = try link_module.test_local_enclave(0x71);
    defer local.destroy();
    const links = [_]*link_module.Link{&local.link};
    var fake: registration.FakeRegistry = .{};
    var checker: registration.Checker = try .init(&links, fake.registry());
    var gated: Health = .{ .version = "0.0.0", .checker = &checker };
    try testing.expectEqualStrings(not_valid_message, gated.check().unhealthy);
    fake.unavailable = true;
    try testing.expectEqualStrings("TEEProverRegistry L1 call failed", gated.check().unhealthy);
    fake.unavailable = false;
    fake.allow(local.server.signer_address());
    try testing.expect(gated.check() == .healthy);
    fake.valid_count = 0;
    fake.unavailable = true;
    try testing.expect(gated.check() == .healthy);
    try testing.expectEqual(@as(u64, 4), gated.checks);
}

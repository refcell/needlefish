//! libp2p ping (`/ipfs/ping/1.0.0`): the dialer writes 32 random bytes, the listener
//! echoes them, and the dialer measures the round trip. libp2p's default behaviour
//! (used by base/base) pings every 15 s and fails the connection after a 20 s timeout.

const std = @import("std");
const assert = std.debug.assert;

const ns_per_s = std.time.ns_per_s;

pub const protocol_id = "/ipfs/ping/1.0.0";
pub const payload_length = 32;
pub const interval_ns: u64 = 15 * ns_per_s;
pub const timeout_ns: u64 = 20 * ns_per_s;

pub const Error = error{ Mismatch, Unexpected };

/// Dialer side of one ping stream.
pub const Pinger = struct {
    payload: [payload_length]u8 = undefined,
    sent_ns: u64 = 0,
    outstanding: bool = false,
    next_ns: u64 = 0,

    /// Returns the payload to write when a ping is due, else null.
    pub fn poll(pinger: *Pinger, random: std.Random, now_ns: u64) ?*const [payload_length]u8 {
        if (pinger.outstanding or now_ns < pinger.next_ns) return null;
        random.bytes(&pinger.payload);
        pinger.sent_ns = now_ns;
        pinger.outstanding = true;
        assert(pinger.outstanding);
        return &pinger.payload;
    }

    /// Handles the echo; returns the round-trip time.
    pub fn on_echo(pinger: *Pinger, echo: []const u8, now_ns: u64) Error!u64 {
        if (!pinger.outstanding) return error.Unexpected;
        if (!std.mem.eql(u8, echo, &pinger.payload)) return error.Mismatch;
        pinger.outstanding = false;
        pinger.next_ns = now_ns + interval_ns;
        assert(now_ns >= pinger.sent_ns);
        return now_ns - pinger.sent_ns;
    }

    pub fn timed_out(pinger: *const Pinger, now_ns: u64) bool {
        return pinger.outstanding and now_ns - pinger.sent_ns >= timeout_ns;
    }
};

const Prng = @import("../../../testing/prng.zig").Prng;

test "ping: round trip, mismatch, timeout" {
    var prng = Prng.init(1);
    var pinger: Pinger = .{};
    const payload = pinger.poll(prng.random(), 0).?.*;
    try std.testing.expect(pinger.poll(prng.random(), 1) == null);
    var wrong = payload;
    wrong[0] ^= 1;
    try std.testing.expectError(error.Mismatch, pinger.on_echo(&wrong, 5));
    try std.testing.expectEqual(@as(u64, 7), try pinger.on_echo(&payload, 7));
    try std.testing.expectError(error.Unexpected, pinger.on_echo(&payload, 8));
    try std.testing.expect(pinger.poll(prng.random(), 8) == null);
    _ = pinger.poll(prng.random(), 7 + interval_ns).?;
    try std.testing.expect(!pinger.timed_out(7 + interval_ns + 1));
    try std.testing.expect(pinger.timed_out(7 + interval_ns + timeout_ns));
}

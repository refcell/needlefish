//! End-to-end fuzz target for the proof lane's preimage protocols
//! (`proof/preimage/{channel,hint,oracle}.zig`): one client and one host over two
//! duplex channels (hints and preimages), interleaved on one thread through pumps, as
//! the fault-proof program runs against its host.
//!
//! The host routes `fetch 0x<value>` hints by storing `value` under its keccak key, the
//! way the real host prefetches what a hint names. The client issues a fuzzed mix of:
//!   - a hint followed by a get of the hinted value's key: the answer is the value, and
//!     its keccak digest matches the key (the check the client program does);
//!   - a get of a key never hinted: the host fails the request, the client sees it
//!     starve, and both channels are left empty (still framed);
//!   - malformed hints (bad format, invalid UTF-8): still acknowledged, so the client
//!     never deadlocks, and later traffic is unaffected;
//!   - gets into a too-small buffer: `BufferTooSmall`, and the channel stays framed.
//! Every step ends with both duplexes drained.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const preimage = @import("../proof/preimage/root.zig");
const keccak = @import("../common/crypto/keccak.zig");

const Key = preimage.Key;
const Duplex = preimage.Duplex;

const values_max = 16;
const value_bytes_max = 96;
const operations_max = 48;
const hint_bytes_max = 2 * value_bytes_max + 16;

const Host = struct {
    hints: Duplex = undefined,
    oracle: Duplex = undefined,
    store: preimage.MemoryStore(values_max * 2, values_max * 2 * value_bytes_max) = .{},
    hint_buffer: [hint_bytes_max]u8 = undefined,
    hint_errors: u32 = 0,
    oracle_errors: u32 = 0,

    fn init(host: *Host) !void {
        try host.hints.init(std.testing.allocator, 1024);
        errdefer host.hints.deinit(std.testing.allocator);
        try host.oracle.init(std.testing.allocator, 1024);
        host.hints.client_endpoint.pump = .{ .context = host, .step = step_hint };
        host.oracle.client_endpoint.pump = .{ .context = host, .step = step_oracle };
    }

    fn deinit(host: *Host) void {
        host.hints.deinit(std.testing.allocator);
        host.oracle.deinit(std.testing.allocator);
    }

    fn step_hint(context: *anyopaque) bool {
        const host: *Host = @ptrCast(@alignCast(context));
        const reader = preimage.HintReader.init(host.hints.host(), &host.hint_buffer);
        const router: preimage.Router = .{ .context = host, .route_hint = route };
        reader.next_hint(router) catch |err| switch (err) {
            error.WouldBlock, error.ChannelClosed => return false,
            else => host.hint_errors += 1, // Acknowledged anyway.
        };
        return true;
    }

    fn step_oracle(context: *anyopaque) bool {
        const host: *Host = @ptrCast(@alignCast(context));
        const server = preimage.OracleServer.init(host.oracle.host());
        server.next_preimage_request(host.store.fetcher()) catch {
            host.oracle_errors += 1;
            return false;
        };
        return true;
    }

    fn route(context: *anyopaque, text: []const u8) preimage.hint.RouteError!void {
        const host: *Host = @ptrCast(@alignCast(context));
        var data: [value_bytes_max]u8 = undefined;
        const hint = preimage.Hint.parse(text, &data) catch return error.HintRejected;
        if (!std.mem.eql(u8, hint.type_name, "fetch")) return error.HintRejected;
        const key = Key.keccak256(keccak.keccak256(hint.data));
        if (host.store.get(key) != null) return;
        host.store.put(key, hint.data) catch return error.HintFailed;
    }

    fn drained(host: *const Host) bool {
        return host.hints.to_host.count == 0 and host.hints.to_client.count == 0 and
            host.oracle.to_host.count == 0 and host.oracle.to_client.count == 0;
    }
};

const Client = struct {
    host: *Host,
    values: [values_max][value_bytes_max]u8 = undefined,
    lengths: [values_max]u8 = undefined,
    hinted: [values_max]bool = @splat(false),

    fn value(client: *const Client, index: usize) []const u8 {
        return client.values[index][0..client.lengths[index]];
    }

    fn key(client: *const Client, index: usize) Key {
        return Key.keccak256(keccak.keccak256(client.value(index)));
    }

    fn hint(client: *Client, index: usize) !void {
        var text: [hint_bytes_max]u8 = undefined;
        const encoded = try preimage.Hint.encode("fetch", client.value(index), &text);
        try preimage.HintWriter.init(client.host.hints.client()).write(encoded);
        client.hinted[index] = true;
    }

    fn get(client: *Client, index: usize, capacity: usize) !void {
        const reader = preimage.OracleReader.init(client.host.oracle.client());
        var buffer: [value_bytes_max]u8 = undefined;
        const expected = client.value(index);
        const result = reader.get(client.key(index), buffer[0..capacity]);
        // Distinct indexes may hold equal values: the store is keyed by content.
        const known = client.host.store.get(client.key(index)) != null;
        if (!known) {
            try std.testing.expect(!client.hinted[index]);
            try std.testing.expectError(error.WouldBlock, result);
            return;
        }
        const data = result catch |err| {
            try std.testing.expectEqual(error.BufferTooSmall, err);
            try std.testing.expect(expected.len > capacity);
            return;
        };
        try std.testing.expectEqualSlices(u8, expected, data);
        const digest = keccak.keccak256(data);
        try std.testing.expect(client.key(index).eql(Key.keccak256(digest)));
    }

    fn bad_hint(client: *Client, prng: *Prng) !void {
        const texts = [_][]const u8{ "fetch", "fetch 0xzz", "fetch 0x1", "a b c", "", "\xff\xfe" };
        const errors_before = client.host.hint_errors;
        const text = texts[@intCast(prng.below(texts.len))];
        try preimage.HintWriter.init(client.host.hints.client()).write(text);
        try std.testing.expectEqual(errors_before + 1, client.host.hint_errors);
    }
};

fn fuzz_session(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var host: Host = .{};
    try host.init();
    defer host.deinit();
    var client: Client = .{ .host = &host };
    for (&client.values, &client.lengths) |*bytes, *length| {
        length.* = @intCast(prng.below(value_bytes_max + 1));
        prng.fill(bytes[0..length.*]);
    }
    for (0..operations_max) |_| {
        const index: usize = @intCast(prng.below(values_max));
        switch (prng.below(5)) {
            0, 1 => try client.hint(index),
            2 => try client.get(index, value_bytes_max),
            3 => try client.get(index, @intCast(prng.below(value_bytes_max + 1))),
            else => try client.bad_hint(&prng),
        }
        try std.testing.expect(host.drained());
    }
}

test "fuzz_targets_proof: preimage client and host stay framed and correct" {
    try fuzz.run({}, fuzz_session, .{ .iterations = 256 });
}

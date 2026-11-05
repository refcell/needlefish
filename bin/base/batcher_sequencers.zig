//! `base batcher --sequencer-urls`: HTTP clients for every sequencer endpoint.
//!
//! Each comma-separated entry is `URL` (one endpoint serving both the L2 EL and rollup
//! node APIs, as in base/base) or `L2_URL=ROLLUP_URL` (needlefish runs the EL and CL as
//! separate processes). The legacy `--l2 [--rollup-rpc]` pair is one entry.

const std = @import("std");
const base = @import("base");

const assert = std.debug.assert;
const rpc = base.batcher.rpc;
const sequencers = base.batcher.sequencers;
const HttpTransport = @import("http_transport.zig").HttpTransport;

pub const Entry = struct {
    l2: []const u8,
    rollup: ?[]const u8,
};

/// Parses `--sequencer-urls` into `entries`; returns the entry count.
pub fn parse_entries(text: []const u8, entries: *[sequencers.sequencers_max]Entry) !u8 {
    var count: u8 = 0;
    var parts = std.mem.splitScalar(u8, text, ',');
    while (parts.next()) |part| {
        if (part.len == 0) return error.EmptySequencerUrl;
        if (count == sequencers.sequencers_max) return error.TooManySequencers;
        const split = std.mem.indexOfScalar(u8, part, '=');
        entries[count] = if (split) |index| .{
            .l2 = part[0..index],
            .rollup = part[index + 1 ..],
        } else .{ .l2 = part, .rollup = part };
        const entry = entries[count];
        if (entry.l2.len == 0 or entry.rollup.?.len == 0) return error.EmptySequencerUrl;
        count += 1;
    }
    assert(count > 0);
    return count;
}

/// Owns the transports and clients; heap-allocate it, clients point into it.
pub const SequencerClients = struct {
    l2_http: [sequencers.sequencers_max]HttpTransport = undefined,
    rollup_http: [sequencers.sequencers_max]HttpTransport = undefined,
    l2: [sequencers.sequencers_max]rpc.Client = undefined,
    rollup: [sequencers.sequencers_max]rpc.Client = undefined,
    count: u8 = 0,
    /// False for the legacy `--l2` without `--rollup-rpc`: no rollup node to ask.
    has_rollup: bool = true,

    pub fn init(
        clients: *SequencerClients,
        allocator: std.mem.Allocator,
        io: std.Io,
        entries: []const Entry,
    ) !void {
        assert(entries.len > 0 and entries.len <= sequencers.sequencers_max);
        clients.* = .{ .has_rollup = entries[0].rollup != null };
        errdefer clients.deinit(allocator);
        for (entries) |entry| {
            assert((entry.rollup != null) == clients.has_rollup);
            try clients.init_entry(allocator, io, entry);
        }
        assert(clients.count == entries.len);
    }

    fn init_entry(
        clients: *SequencerClients,
        allocator: std.mem.Allocator,
        io: std.Io,
        entry: Entry,
    ) !void {
        const index = clients.count;
        assert(index < sequencers.sequencers_max);
        clients.l2_http[index] = HttpTransport.init(allocator, io, entry.l2);
        errdefer clients.l2_http[index].deinit();
        const rollup_url = entry.rollup orelse entry.l2;
        clients.rollup_http[index] = HttpTransport.init(allocator, io, rollup_url);
        errdefer clients.rollup_http[index].deinit();
        const l2_transport = clients.l2_http[index].transport();
        clients.l2[index] = try rpc.Client.init(allocator, l2_transport, .{});
        errdefer clients.l2[index].deinit(allocator);
        const rollup_transport = clients.rollup_http[index].transport();
        clients.rollup[index] = try rpc.Client.init(allocator, rollup_transport, .{});
        clients.count += 1;
    }

    pub fn deinit(clients: *SequencerClients, allocator: std.mem.Allocator) void {
        for (0..clients.count) |index| {
            clients.rollup[index].deinit(allocator);
            clients.l2[index].deinit(allocator);
            clients.rollup_http[index].deinit();
            clients.l2_http[index].deinit();
        }
        clients.count = 0;
    }

    pub fn tracker(clients: *SequencerClients) sequencers.Sequencers {
        assert(clients.count > 0);
        var endpoints: [sequencers.sequencers_max]sequencers.Endpoint = undefined;
        for (0..clients.count) |index| {
            endpoints[index] = .{ .l2 = &clients.l2[index], .rollup = &clients.rollup[index] };
        }
        return sequencers.Sequencers.init(endpoints[0..clients.count]);
    }
};

test "batcher sequencers: parse entries" {
    var entries: [sequencers.sequencers_max]Entry = undefined;
    const count = try parse_entries("http://a:9545=http://a:7545,http://b:8545", &entries);
    try std.testing.expectEqual(@as(u8, 2), count);
    try std.testing.expectEqualStrings("http://a:7545", entries[0].rollup.?);
    try std.testing.expectEqualStrings("http://b:8545", entries[1].rollup.?);
    try std.testing.expectError(error.EmptySequencerUrl, parse_entries("a,,b", &entries));
    try std.testing.expectError(error.EmptySequencerUrl, parse_entries("a=", &entries));
    const nine = "a,a,a,a,a,a,a,a,a";
    try std.testing.expectError(error.TooManySequencers, parse_entries(nine, &entries));
}

test "batcher sequencers: seeded fuzz of entry parsing" {
    var prng = base.testing.Prng.init(0x5e1);
    var entries: [sequencers.sequencers_max]Entry = undefined;
    const alphabet = "ab=,";
    for (0..1000) |_| {
        var text: [24]u8 = undefined;
        const length = prng.range(1, text.len);
        for (text[0..length]) |*byte| byte.* = alphabet[prng.below(alphabet.len)];
        const count = parse_entries(text[0..length], &entries) catch continue;
        for (entries[0..count]) |entry| {
            try std.testing.expect(entry.l2.len > 0 and entry.rollup.?.len > 0);
            try std.testing.expect(std.mem.indexOfScalar(u8, entry.l2, ',') == null);
        }
    }
}

test "batcher sequencers: fuzz entry parsing" {
    try std.testing.fuzz({}, fuzz_entries, .{});
}

fn fuzz_entries(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [64]u8 = undefined;
    const length = smith.slice(&bytes);
    var entries: [sequencers.sequencers_max]Entry = undefined;
    const count = parse_entries(bytes[0..length], &entries) catch return;
    try std.testing.expect(count > 0 and count <= sequencers.sequencers_max);
}

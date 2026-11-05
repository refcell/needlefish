//! Preimage oracle client and server. Port of base/base
//! `crates/proof/preimage/src/oracle.rs`.
//!
//! Wire format: the client writes a 32-byte key; the server answers with a big-endian
//! `u64` length followed by that many bytes.
//!
//! Unlike the Rust reader, a length mismatch drains the payload before returning the
//! error, so the channel stays framed and the next request still works.

const std = @import("std");
const assert = std.debug.assert;
const channel_module = @import("channel.zig");
const key_module = @import("key.zig");

const Channel = channel_module.Channel;
const Key = key_module.Key;

/// Largest preimage either side accepts. Bigger lengths mean a broken peer.
pub const preimage_size_max: u64 = 16 * 1024 * 1024;

pub const ReadError = channel_module.Error || error{
    /// `get_exact` buffer size differs from the preimage (payload was drained).
    BufferLengthMismatch,
    /// `get` buffer is smaller than the preimage (payload was drained).
    BufferTooSmall,
    /// Length header above `preimage_size_max`; the channel is no longer framed.
    PreimageTooLarge,
};

pub const OracleReader = struct {
    channel: Channel,

    pub fn init(channel: Channel) OracleReader {
        return .{ .channel = channel };
    }

    fn request(reader: OracleReader, key: Key) ReadError!u64 {
        const raw = key.to_bytes();
        try reader.channel.write(&.{&raw});
        var length_bytes: [8]u8 = undefined;
        try reader.channel.read_exact(&length_bytes);
        const length = std.mem.readInt(u64, &length_bytes, .big);
        if (length > preimage_size_max) return error.PreimageTooLarge;
        return length;
    }

    /// Reads and discards `length` bytes in bounded chunks.
    fn drain(reader: OracleReader, length: u64) channel_module.Error!void {
        assert(length <= preimage_size_max);
        var scratch: [512]u8 = undefined;
        var remaining = length;
        const rounds_max = length / scratch.len + 1;
        var round: u64 = 0;
        while (remaining > 0) : (round += 1) {
            assert(round < rounds_max);
            const chunk: usize = @intCast(@min(remaining, scratch.len));
            try reader.channel.read_exact(scratch[0..chunk]);
            remaining -= chunk;
        }
    }

    /// Fetches the preimage for `key` into `buffer` and returns the filled prefix.
    pub fn get(reader: OracleReader, key: Key, buffer: []u8) ReadError![]u8 {
        const length = try reader.request(key);
        if (length > buffer.len) {
            try reader.drain(length);
            return error.BufferTooSmall;
        }
        const data = buffer[0..@intCast(length)];
        if (data.len > 0) try reader.channel.read_exact(data);
        assert(data.len == length);
        return data;
    }

    /// Fetches the preimage for `key`, which must be exactly `buffer.len` bytes.
    pub fn get_exact(reader: OracleReader, key: Key, buffer: []u8) ReadError!void {
        const length = try reader.request(key);
        if (length != buffer.len) {
            try reader.drain(length);
            return error.BufferLengthMismatch;
        }
        if (buffer.len > 0) try reader.channel.read_exact(buffer);
    }
};

pub const FetchError = error{
    KeyNotFound,
    /// The backend could not produce the preimage (network, disk, decode).
    FetchFailed,
};

/// Host-side source of preimages. The returned slice stays valid until the next call.
pub const Fetcher = struct {
    context: *anyopaque,
    get_preimage: *const fn (context: *anyopaque, key: Key) FetchError![]const u8,
};

pub const ServeError = channel_module.Error || FetchError || error{
    InvalidPreimageKey,
    PreimageTooLarge,
};

pub const OracleServer = struct {
    channel: Channel,

    pub fn init(channel: Channel) OracleServer {
        return .{ .channel = channel };
    }

    /// Serves one request: read key, fetch, write length and payload.
    pub fn next_preimage_request(server: OracleServer, fetcher: Fetcher) ServeError!void {
        var raw: [key_module.key_size]u8 = undefined;
        try server.channel.read_exact(&raw);
        const key = try Key.from_bytes(raw);
        const value = try fetcher.get_preimage(fetcher.context, key);
        if (value.len > preimage_size_max) return error.PreimageTooLarge;
        var length_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &length_bytes, value.len, .big);
        try server.channel.write(&.{ &length_bytes, value });
    }
};

/// Fixed-capacity in-memory preimage table for tests and the offline host.
pub fn MemoryStore(comptime entries_max: u32, comptime bytes_max: u32) type {
    return struct {
        const Store = @This();

        keys: [entries_max]Key = undefined,
        offsets: [entries_max + 1]u32 = @splat(0),
        bytes: [bytes_max]u8 = undefined,
        count: u32 = 0,

        pub fn put(store: *Store, key: Key, value: []const u8) error{StoreFull}!void {
            if (store.count == entries_max) return error.StoreFull;
            const start = store.offsets[store.count];
            if (value.len > bytes_max - start) return error.StoreFull;
            @memcpy(store.bytes[start..][0..value.len], value);
            store.keys[store.count] = key;
            store.offsets[store.count + 1] = start + @as(u32, @intCast(value.len));
            store.count += 1;
            assert(store.offsets[store.count] <= bytes_max);
        }

        pub fn get(store: *const Store, key: Key) ?[]const u8 {
            assert(store.count <= entries_max);
            for (store.keys[0..store.count], 0..) |candidate, index| {
                if (candidate.eql(key)) {
                    return store.bytes[store.offsets[index]..store.offsets[index + 1]];
                }
            }
            return null;
        }

        fn get_preimage(context: *anyopaque, key: Key) FetchError![]const u8 {
            const store: *Store = @ptrCast(@alignCast(context));
            return store.get(key) orelse error.KeyNotFound;
        }

        pub fn fetcher(store: *Store) Fetcher {
            return .{ .context = store, .get_preimage = get_preimage };
        }
    };
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const Duplex = channel_module.Duplex;

/// Runs one server step when the client starves, recording the last error.
const Harness = struct {
    duplex: Duplex = undefined,
    store: MemoryStore(32, 4096) = .{},
    last_error: ?ServeError = null,

    fn init(harness: *Harness) !void {
        try harness.duplex.init(testing.allocator, 2048);
        harness.duplex.client_endpoint.pump = .{ .context = harness, .step = step };
    }

    fn deinit(harness: *Harness) void {
        harness.duplex.deinit(testing.allocator);
    }

    fn step(context: *anyopaque) bool {
        const harness: *Harness = @ptrCast(@alignCast(context));
        const server = OracleServer.init(harness.duplex.host());
        server.next_preimage_request(harness.store.fetcher()) catch |err| {
            harness.last_error = err;
            return false;
        };
        return true;
    }

    fn reader(harness: *Harness) OracleReader {
        return .init(harness.duplex.client());
    }
};

test "oracle: client and host" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    const data_a = "1234567890";
    const data_b = "FACADE";
    const key_a = Key.keccak256(keccak.keccak256(data_a));
    const key_b = Key.keccak256(keccak.keccak256(data_b));
    try harness.store.put(key_a, data_a);
    try harness.store.put(key_b, data_b);

    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(data_a, try harness.reader().get(key_a, &buffer));
    try testing.expectEqualStrings(data_b, try harness.reader().get(key_b, &buffer));
    var exact_a: [10]u8 = undefined;
    var exact_b: [6]u8 = undefined;
    try harness.reader().get_exact(key_a, &exact_a);
    try harness.reader().get_exact(key_b, &exact_b);
    try testing.expectEqualStrings(data_a, &exact_a);
    try testing.expectEqualStrings(data_b, &exact_b);
}

test "oracle: mismatches drain and keep the channel framed" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    const key = Key.local(1);
    try harness.store.put(key, "abcdef");
    var small: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, harness.reader().get(key, &small));
    try testing.expectError(error.BufferLengthMismatch, harness.reader().get_exact(key, &small));
    var exact: [6]u8 = undefined;
    try harness.reader().get_exact(key, &exact);
    try testing.expectEqualStrings("abcdef", &exact);
}

test "oracle: empty preimage and missing key" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    try harness.store.put(Key.local(2), "");
    var buffer: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), (try harness.reader().get(Key.local(2), &buffer)).len);
    try testing.expectError(error.WouldBlock, harness.reader().get(Key.local(3), &buffer));
    try testing.expectEqual(@as(?ServeError, error.KeyNotFound), harness.last_error);
}

test "oracle: server rejects an invalid key type" {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    var raw: [32]u8 = @splat(0);
    raw[0] = 9;
    try harness.duplex.client().write(&.{&raw});
    const server = OracleServer.init(harness.duplex.host());
    const result = server.next_preimage_request(harness.store.fetcher());
    try testing.expectError(error.InvalidPreimageKey, result);
}

/// Random stores and request sequences: every answer matches the store, and every
/// error leaves the channel usable for the next request.
fn fuzz_requests(_: void, smith: *std.testing.Smith) anyerror!void {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    const entries = smith.valueRangeAtMost(u32, 1, 16);
    var value: [96]u8 = undefined;
    for (0..entries) |index| {
        const len = smith.slice(&value);
        harness.store.put(Key.local(index), value[0..len]) catch break;
    }
    var requests: u32 = 0;
    while (requests < 32 and !smith.eos()) : (requests += 1) {
        const index = smith.valueRangeAtMost(u32, 0, harness.store.count - 1);
        const key = Key.local(index);
        const expected = harness.store.get(key).?;
        var buffer: [96]u8 = undefined;
        const capacity = smith.valueRangeAtMost(u32, 0, 96);
        const got = harness.reader().get(key, buffer[0..capacity]) catch |err| {
            try testing.expectEqual(error.BufferTooSmall, err);
            try testing.expect(expected.len > capacity);
            continue;
        };
        try testing.expectEqualSlices(u8, expected, got);
    }
    try testing.expectEqual(@as(u32, 0), harness.duplex.to_host.count);
    try testing.expectEqual(@as(u32, 0), harness.duplex.to_client.count);
}

test "oracle: fuzz request sequences" {
    try fuzz.run({}, fuzz_requests, .{});
}

/// Arbitrary bytes from a hostile client never crash the server.
fn fuzz_server_input(_: void, bytes: []const u8) anyerror!void {
    var harness: Harness = .{};
    try harness.init();
    defer harness.deinit();
    try harness.store.put(Key.local(0), "zero");
    const len = @min(bytes.len, 2048);
    harness.duplex.client().write(&.{bytes[0..len]}) catch unreachable; // len <= capacity.
    harness.duplex.to_host.closed = true;
    const server = OracleServer.init(harness.duplex.host());
    var requests: u32 = 0;
    while (requests < 128) : (requests += 1) {
        server.next_preimage_request(harness.store.fetcher()) catch |err| switch (err) {
            error.ChannelClosed => break,
            error.KeyNotFound, error.InvalidPreimageKey => continue,
            else => return err,
        };
    }
}

test "oracle: fuzz server input" {
    try fuzz.run_bytes({}, fuzz_server_input, .{});
}

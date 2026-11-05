//! Byte channel between the fault-proof client and the host. Port of the `Channel` trait
//! in base/base `crates/proof/preimage/src/traits.rs` and the in-process pipe pair in
//! `native_channel.rs`.
//!
//! The Rust version is async and runs client and host on separate tasks. Here the
//! client is synchronous: when an in-memory endpoint would block on a read it runs a
//! `Pump` (normally one host server step) and retries, so client and host interleave
//! deterministically on one thread. Writes are atomic: either every part fits in the
//! pipe or nothing is written, so a full pipe never leaves a torn frame behind.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The peer closed the channel (or the read hit EOF mid-frame).
    ChannelClosed,
    /// No data or no space and the pump made no progress.
    WouldBlock,
};

/// Upper bound on pump calls per read, so a stuck host cannot spin the client forever.
pub const pump_rounds_max: u32 = 64;
/// Upper bound on parts per write (header + payload in every frame of the protocol).
pub const write_parts_max: u32 = 4;

pub const Channel = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        read_exact: *const fn (context: *anyopaque, buffer: []u8) Error!void,
        /// Writes the concatenation of `parts`, all or nothing.
        write: *const fn (context: *anyopaque, parts: []const []const u8) Error!void,
    };

    pub fn read_exact(channel: Channel, buffer: []u8) Error!void {
        return channel.vtable.read_exact(channel.context, buffer);
    }

    pub fn write(channel: Channel, parts: []const []const u8) Error!void {
        assert(parts.len > 0);
        assert(parts.len <= write_parts_max);
        return channel.vtable.write(channel.context, parts);
    }
};

/// Runs one step of the peer. Returns true when it made progress.
pub const Pump = struct {
    context: *anyopaque,
    step: *const fn (context: *anyopaque) bool,
};

/// Bounded single-direction byte ring buffer.
pub const Pipe = struct {
    buffer: []u8,
    head: u32 = 0,
    count: u32 = 0,
    closed: bool = false,

    pub fn init(buffer: []u8) Pipe {
        assert(buffer.len > 0);
        assert(buffer.len <= std.math.maxInt(u32));
        return .{ .buffer = buffer };
    }

    pub fn free_bytes(pipe: *const Pipe) u32 {
        assert(pipe.count <= pipe.buffer.len);
        return @as(u32, @intCast(pipe.buffer.len)) - pipe.count;
    }

    pub fn push(pipe: *Pipe, parts: []const []const u8) Error!void {
        if (pipe.closed) return error.ChannelClosed;
        var total: u64 = 0;
        for (parts) |part| total += part.len;
        if (total > pipe.free_bytes()) return error.WouldBlock;
        const count_before = pipe.count;
        const capacity: u32 = @intCast(pipe.buffer.len);
        for (parts) |part| {
            for (part) |byte| {
                pipe.buffer[(pipe.head + pipe.count) % capacity] = byte;
                pipe.count += 1;
            }
        }
        assert(pipe.count == count_before + total);
    }

    /// Pops exactly `out.len` bytes, or nothing.
    pub fn pop(pipe: *Pipe, out: []u8) Error!void {
        if (pipe.count < out.len) {
            return if (pipe.closed) error.ChannelClosed else error.WouldBlock;
        }
        const capacity: u32 = @intCast(pipe.buffer.len);
        const count_before = pipe.count;
        for (out) |*byte| {
            byte.* = pipe.buffer[pipe.head];
            pipe.head = (pipe.head + 1) % capacity;
            pipe.count -= 1;
        }
        assert(pipe.count + out.len == count_before);
    }
};

pub const Side = enum { client, host };

/// Two pipes and two endpoints over one allocation, made at startup.
pub const Duplex = struct {
    memory: []u8,
    to_host: Pipe,
    to_client: Pipe,
    client_endpoint: Endpoint,
    host_endpoint: Endpoint,

    pub const Endpoint = struct {
        duplex: *Duplex,
        side: Side,
        pump: ?Pump = null,

        fn inbox(endpoint: *Endpoint) *Pipe {
            return switch (endpoint.side) {
                .client => &endpoint.duplex.to_client,
                .host => &endpoint.duplex.to_host,
            };
        }

        fn outbox(endpoint: *Endpoint) *Pipe {
            return switch (endpoint.side) {
                .client => &endpoint.duplex.to_host,
                .host => &endpoint.duplex.to_client,
            };
        }

        fn read_exact(context: *anyopaque, buffer: []u8) Error!void {
            const endpoint: *Endpoint = @ptrCast(@alignCast(context));
            var round: u32 = 0;
            while (round <= pump_rounds_max) : (round += 1) {
                endpoint.inbox().pop(buffer) catch |err| switch (err) {
                    error.ChannelClosed => return err,
                    error.WouldBlock => {
                        const pump = endpoint.pump orelse return err;
                        if (!pump.step(pump.context)) return err;
                        continue;
                    },
                };
                return;
            }
            return error.WouldBlock;
        }

        fn write(context: *anyopaque, parts: []const []const u8) Error!void {
            const endpoint: *Endpoint = @ptrCast(@alignCast(context));
            return endpoint.outbox().push(parts);
        }

        const vtable: Channel.VTable = .{ .read_exact = read_exact, .write = write };

        pub fn channel(endpoint: *Endpoint) Channel {
            return .{ .context = endpoint, .vtable = &vtable };
        }
    };

    /// `capacity_bytes` per direction. The duplex must not move after `init`.
    pub fn init(duplex: *Duplex, allocator: std.mem.Allocator, capacity_bytes: u32) !void {
        assert(capacity_bytes > 0);
        const memory = try allocator.alloc(u8, @as(usize, capacity_bytes) * 2);
        duplex.* = .{
            .memory = memory,
            .to_host = .init(memory[0..capacity_bytes]),
            .to_client = .init(memory[capacity_bytes..]),
            .client_endpoint = .{ .duplex = duplex, .side = .client },
            .host_endpoint = .{ .duplex = duplex, .side = .host },
        };
        assert(duplex.to_host.buffer.len == duplex.to_client.buffer.len);
    }

    pub fn deinit(duplex: *Duplex, allocator: std.mem.Allocator) void {
        allocator.free(duplex.memory);
        duplex.* = undefined;
    }

    pub fn client(duplex: *Duplex) Channel {
        return duplex.client_endpoint.channel();
    }

    pub fn host(duplex: *Duplex) Channel {
        return duplex.host_endpoint.channel();
    }

    /// Closes both directions: pending bytes stay readable, then reads fail.
    pub fn close(duplex: *Duplex) void {
        duplex.to_host.closed = true;
        duplex.to_client.closed = true;
    }
};

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "pipe: atomic write and exact read" {
    var storage: [8]u8 = undefined;
    var pipe: Pipe = .init(&storage);
    try pipe.push(&.{ "abc", "de" });
    try testing.expectError(error.WouldBlock, pipe.push(&.{"xyzw"}));
    try testing.expectEqual(@as(u32, 5), pipe.count);
    var out: [4]u8 = undefined;
    try pipe.pop(&out);
    try testing.expectEqualStrings("abcd", &out);
    try testing.expectError(error.WouldBlock, pipe.pop(&out));
    pipe.closed = true;
    try testing.expectError(error.ChannelClosed, pipe.pop(&out));
    try pipe.pop(out[0..1]);
    try testing.expectEqual(@as(u8, 'e'), out[0]);
}

test "duplex: endpoints cross" {
    var duplex: Duplex = undefined;
    try duplex.init(testing.allocator, 16);
    defer duplex.deinit(testing.allocator);
    try duplex.client().write(&.{"ping"});
    var buffer: [4]u8 = undefined;
    try duplex.host().read_exact(&buffer);
    try testing.expectEqualStrings("ping", &buffer);
    try testing.expectError(error.WouldBlock, duplex.client().read_exact(&buffer));
    duplex.close();
    try testing.expectError(error.ChannelClosed, duplex.client().read_exact(&buffer));
}

/// Mirrors a pipe against a plain FIFO model under random pushes and pops.
fn fuzz_pipe(_: void, smith: *std.testing.Smith) anyerror!void {
    var storage: [64]u8 = undefined;
    var pipe: Pipe = .init(storage[0..smith.valueRangeAtMost(u32, 1, 64)]);
    var model: [4096]u8 = undefined;
    var model_head: u32 = 0;
    var model_tail: u32 = 0;
    var steps: u32 = 0;
    while (steps < 256 and !smith.eos()) : (steps += 1) {
        var chunk: [80]u8 = undefined;
        const len = smith.valueRangeAtMost(u32, 0, 80);
        if (smith.value(bool)) {
            smith.bytes(chunk[0..len]);
            pipe.push(&.{chunk[0..len]}) catch {
                try testing.expect(len > pipe.free_bytes());
                continue;
            };
            if (model_tail + len > model.len) return;
            @memcpy(model[model_tail..][0..len], chunk[0..len]);
            model_tail += len;
        } else {
            pipe.pop(chunk[0..len]) catch {
                try testing.expect(model_tail - model_head < len);
                continue;
            };
            try testing.expectEqualSlices(u8, model[model_head..][0..len], chunk[0..len]);
            model_head += len;
        }
        try testing.expectEqual(model_tail - model_head, pipe.count);
    }
}

test "pipe: fuzz against fifo model" {
    try fuzz.run({}, fuzz_pipe, .{});
}

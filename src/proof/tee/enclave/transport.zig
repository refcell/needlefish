//! Length-prefixed frames of the Enclave link (base/base
//! `crates/proof/tee/nitro-enclave/src/transport.rs`): an 8-byte big-endian payload length,
//! then the bincode payload.
//!
//! Writes go out in segments of at most 28 KiB: Linux `virtio_vsock` allocates nonlinear
//! socket buffers above about 32 KiB and some hypervisors corrupt those
//! (cloud-hypervisor issue 7672). Frames run over any `std.Io.Reader`/`Writer`, so the
//! stream behind them (vsock, a socket from `utilities/io`, or memory) is the caller's.
//! base/base accepts any length up to `u64::MAX`; here a frame longer than the caller's
//! buffer is refused before any payload byte is read.

const std = @import("std");
const assert = std.debug.assert;

pub const segment_bytes_max = 28 * 1024;
pub const header_bytes = 8;

pub const ReadError = std.Io.Reader.Error || error{FrameTooLarge};

/// Writes one frame: the length, the payload in segments, then a flush.
pub fn write(writer: *std.Io.Writer, payload: []const u8) std.Io.Writer.Error!void {
    var header: [header_bytes]u8 = undefined;
    std.mem.writeInt(u64, &header, payload.len, .big);
    try writer.writeAll(&header);
    var offset: usize = 0;
    while (offset < payload.len) {
        const end = @min(offset + segment_bytes_max, payload.len);
        try writer.writeAll(payload[offset..end]);
        offset = end;
    }
    assert(offset == payload.len);
    try writer.flush();
}

/// Reads one frame's payload into `buffer`.
pub fn read(reader: *std.Io.Reader, buffer: []u8) ReadError![]u8 {
    var header: [header_bytes]u8 = undefined;
    try reader.readSliceAll(&header);
    const length = std.mem.readInt(u64, &header, .big);
    if (length > buffer.len) return error.FrameTooLarge;
    const payload = buffer[0..@intCast(length)];
    try reader.readSliceAll(payload);
    assert(payload.len == length);
    return payload;
}

const testing = std.testing;
const fuzz = @import("../../../testing/fuzz.zig");

test "enclave transport: a multi-segment frame round trips with a u64 length prefix" {
    const value_len = 3 * segment_bytes_max + 7;
    const value = try testing.allocator.alloc(u8, value_len);
    defer testing.allocator.free(value);
    @memset(value, 0xab);
    const wire = try testing.allocator.alloc(u8, value_len + header_bytes);
    defer testing.allocator.free(wire);
    var writer: std.Io.Writer = .fixed(wire);
    try write(&writer, value);
    try testing.expectEqual(@as(u64, value_len), std.mem.readInt(u64, wire[0..8], .big));
    var reader: std.Io.Reader = .fixed(wire);
    const back = try testing.allocator.alloc(u8, value_len);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, value, try read(&reader, back));
}

test "enclave transport: oversized and truncated frames are refused" {
    var buffer: [4]u8 = undefined;
    var oversized: std.Io.Reader = .fixed(&.{ 0, 0, 0, 0, 0, 0, 0, 5, 1, 2, 3, 4, 5 });
    try testing.expectError(error.FrameTooLarge, read(&oversized, &buffer));
    var truncated: std.Io.Reader = .fixed(&.{ 0, 0, 0, 0, 0, 0, 0, 3, 1 });
    try testing.expectError(error.EndOfStream, read(&truncated, &buffer));
    var short_header: std.Io.Reader = .fixed(&.{ 0, 0 });
    try testing.expectError(error.EndOfStream, read(&short_header, &buffer));
}

fn fuzz_read(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [128]u8 = undefined;
    const len = smith.slice(&input);
    var reader: std.Io.Reader = .fixed(input[0..len]);
    var buffer: [64]u8 = undefined;
    const payload = read(&reader, &buffer) catch return;
    try testing.expect(payload.len + header_bytes <= len);
    try testing.expectEqualSlices(u8, input[header_bytes..][0..payload.len], payload);
}

test "enclave transport: seeded fuzz frame reads" {
    try fuzz.run({}, fuzz_read, .{ .iterations = 512, .input_size_max = 128 });
}

//! RFC 6455 WebSocket handshake helpers and frame codec.
//!
//! Decoding is incremental over a caller buffer: `decode_frame` returns `.incomplete` until a
//! whole frame is buffered, then the header plus a payload slice that is unmasked in place.
//! All protocol violations are distinct errors so the connection can close with 1002.
//! Limits: payloads above `Limits.payload_size_max` are rejected before buffering.

const std = @import("std");
const assert = std.debug.assert;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,

    pub fn is_control(opcode: Opcode) bool {
        return @backingInt(opcode) & 0x8 != 0;
    }
};

pub const Header = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_size: u64,
    mask: [4]u8,
};

pub const Limits = struct {
    payload_size_max: u64 = 1 << 20,
};

pub const DecodeError = error{
    ReservedBitsSet,
    UnknownOpcode,
    ControlFrameFragmented,
    ControlFrameTooLarge,
    NonMinimalLength,
    PayloadTooLarge,
    /// Client-to-server frames must be masked; server-to-client frames must not be.
    MaskMismatch,
};

pub const Decoded = union(enum) {
    incomplete,
    frame: struct { header: Header, payload: []u8, size: usize },
};

pub const Role = enum {
    /// We are the server: incoming frames must be masked.
    server,
    /// We are the client: incoming frames must be unmasked.
    client,
};

/// Decodes one frame from the front of `input`. On `.frame`, `size` bytes were consumed and
/// `payload` (inside `input`) is already unmasked.
pub fn decode_frame(input: []u8, role: Role, limits: Limits) DecodeError!Decoded {
    if (input.len < 2) return .incomplete;
    const first = input[0];
    const second = input[1];
    if (first & 0x70 != 0) return error.ReservedBitsSet;
    const opcode: Opcode = @fromBackingInt(@intCast(@as(u4, @truncate(first))));
    switch (opcode) {
        .continuation, .text, .binary, .close, .ping, .pong => {},
        _ => return error.UnknownOpcode,
    }
    const fin = first & 0x80 != 0;
    const masked = second & 0x80 != 0;
    if (masked != (role == .server)) return error.MaskMismatch;
    var offset: usize = 2;
    var payload_size: u64 = second & 0x7f;
    if (opcode.is_control()) {
        if (!fin) return error.ControlFrameFragmented;
        if (payload_size > 125) return error.ControlFrameTooLarge;
    }
    if (payload_size == 126) {
        if (input.len < 4) return .incomplete;
        payload_size = std.mem.readInt(u16, input[2..4], .big);
        if (payload_size < 126) return error.NonMinimalLength;
        offset = 4;
    } else if (payload_size == 127) {
        if (input.len < 10) return .incomplete;
        payload_size = std.mem.readInt(u64, input[2..10], .big);
        if (payload_size <= 0xffff or payload_size >> 63 != 0) return error.NonMinimalLength;
        offset = 10;
    }
    if (payload_size > limits.payload_size_max) return error.PayloadTooLarge;
    var mask: [4]u8 = @splat(0);
    if (masked) {
        if (input.len < offset + 4) return .incomplete;
        mask = input[offset..][0..4].*;
        offset += 4;
    }
    if (input.len - offset < payload_size) return .incomplete;
    const payload = input[offset..][0..@intCast(payload_size)];
    if (masked) apply_mask(mask, payload, 0);
    const header: Header = .{
        .fin = fin,
        .opcode = opcode,
        .masked = masked,
        .payload_size = payload_size,
        .mask = mask,
    };
    return .{ .frame = .{ .header = header, .payload = payload, .size = offset + payload.len } };
}

/// XORs `bytes` with `mask`, starting at mask phase `phase` (the payload offset).
pub fn apply_mask(mask: [4]u8, bytes: []u8, phase: usize) void {
    for (bytes, 0..) |*byte, index| byte.* ^= mask[(index + phase) % 4];
}

pub const header_size_max = 14;

/// Writes a frame header into `out`; returns its length. The caller writes the payload after
/// it (masked with `mask` when non-null, e.g. via `apply_mask`).
pub fn encode_header(
    out: *[header_size_max]u8,
    fin: bool,
    opcode: Opcode,
    payload_size: u64,
    mask: ?[4]u8,
) usize {
    assert(!opcode.is_control() or (fin and payload_size <= 125));
    assert(payload_size >> 63 == 0);
    out[0] = (if (fin) @as(u8, 0x80) else 0) | @backingInt(opcode);
    const mask_bit: u8 = if (mask != null) 0x80 else 0;
    var size: usize = 2;
    if (payload_size < 126) {
        out[1] = mask_bit | @as(u8, @intCast(payload_size));
    } else if (payload_size <= 0xffff) {
        out[1] = mask_bit | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(payload_size), .big);
        size = 4;
    } else {
        out[1] = mask_bit | 127;
        std.mem.writeInt(u64, out[2..10], payload_size, .big);
        size = 10;
    }
    if (mask) |key| {
        out[size..][0..4].* = key;
        size += 4;
    }
    assert(size <= header_size_max);
    return size;
}

const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub const accept_size = 28;
pub const key_size = 24;

/// `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub fn accept_key(key: []const u8) [accept_size]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update(handshake_guid);
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var out: [accept_size]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&out, &digest);
    assert(encoded.len == accept_size);
    return out;
}

/// A `Sec-WebSocket-Key` from 16 caller-provided random bytes.
pub fn client_key(nonce: [16]u8) [key_size]u8 {
    var out: [key_size]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&out, &nonce);
    assert(encoded.len == key_size);
    return out;
}

pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    internal_error = 1011,
    _,
};

/// Parses a close frame payload. An empty payload means no status (treated as 1005 by
/// callers); a 1-byte payload or a reserved code is a protocol error.
pub const Close = struct { code: u16, reason: []const u8 };

pub fn parse_close(payload: []const u8) error{InvalidClose}!?Close {
    if (payload.len == 0) return null;
    if (payload.len == 1) return error.InvalidClose;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    const valid = (code >= 1000 and code <= 1003) or (code >= 1007 and code <= 1011) or
        (code >= 3000 and code <= 4999);
    if (!valid) return error.InvalidClose;
    const reason = payload[2..];
    if (!std.unicode.utf8ValidateSlice(reason)) return error.InvalidClose;
    return .{ .code = code, .reason = reason };
}

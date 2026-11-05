//! discv5.1 packet codec (devp2p `discv5-wire.md`): masked header, ordinary message,
//! WHOAREYOU, and handshake packets.
//!
//!     packet        = masking-iv || masked-header || message
//!     masked-header = aesctr_encrypt(dest-id[:16], masking-iv, header)
//!     header        = "discv5" || version || flag || nonce || authdata-size || authdata
//!     message       = aesgcm_encrypt(key, nonce, message-pt, masking-iv || header)
//!
//! Decoding unmasks into a caller-owned `Decoded` value (fixed-size, no allocation) and
//! leaves the message ciphertext for the session layer to open.

const std = @import("std");
const assert = std.debug.assert;
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const modes = std.crypto.core.modes;
const secp256k1 = @import("../peers/secp256k1.zig");
const enr = @import("../peers/enr.zig");

pub const size_min = 63;
pub const size_max = 1280;
pub const masking_iv_length = 16;
pub const nonce_length = 12;
pub const tag_length = Aes128Gcm.tag_length;
pub const key_length = 16;
pub const protocol_id = "discv5";
pub const version: u16 = 1;
pub const static_header_length = protocol_id.len + 2 + 1 + nonce_length + 2;
pub const whoareyou_authdata_length = 24;
pub const message_authdata_length = 32;
/// `src-id || sig-size || eph-key-size`.
pub const handshake_authdata_head_length = 34;
pub const header_length_max = size_max - masking_iv_length;

pub const NodeId = enr.NodeId;
pub const Nonce = [nonce_length]u8;
pub const MaskingIv = [masking_iv_length]u8;
pub const Key = [key_length]u8;

pub const Flag = enum(u8) { message = 0, whoareyou = 1, handshake = 2 };

pub const Error = error{
    TooSmall,
    TooLarge,
    WrongProtocol,
    UnsupportedVersion,
    UnknownFlag,
    InvalidAuthdata,
    UnexpectedMessage,
};

pub const Whoareyou = struct {
    id_nonce: [16]u8,
    enr_seq: u64,
};

pub const Handshake = struct {
    src_id: NodeId,
    signature: secp256k1.Signature,
    ephemeral_public_key: secp256k1.PublicKey,
    /// Raw ENR bytes, empty when the record was omitted.
    record: []const u8,
};

pub const Authdata = union(Flag) {
    message: NodeId,
    whoareyou: Whoareyou,
    handshake: Handshake,
};

/// An unmasked packet. Slices point into `header_bytes` or the input packet.
pub const Decoded = struct {
    masking_iv: MaskingIv,
    nonce: Nonce,
    authdata: Authdata,
    /// Unmasked `static-header || authdata`.
    header_bytes: [header_length_max]u8,
    header_length: u16,
    /// Message ciphertext plus tag; empty for WHOAREYOU.
    message: []const u8,

    pub fn header(decoded: *const Decoded) []const u8 {
        assert(decoded.header_length >= static_header_length);
        return decoded.header_bytes[0..decoded.header_length];
    }

    /// `challenge-data` (WHOAREYOU) and message AD share the form `masking-iv || header`.
    pub fn authenticated_data(decoded: *const Decoded, output: []u8) []const u8 {
        const length = masking_iv_length + decoded.header_length;
        assert(output.len >= length);
        @memcpy(output[0..masking_iv_length], &decoded.masking_iv);
        @memcpy(output[masking_iv_length..length], decoded.header());
        return output[0..length];
    }
};

fn mask(dest_id: NodeId, masking_iv: MaskingIv, output: []u8, input: []const u8) void {
    assert(output.len == input.len);
    assert(input.len <= header_length_max);
    const cipher = Aes128.initEnc(dest_id[0..key_length].*);
    modes.ctr(@TypeOf(cipher), cipher, output, input, masking_iv, .big);
}

/// Unmasks and parses a packet addressed to `local_id`. `decoded` must outlive the
/// returned slices into `packet`; record slices point into `decoded.header_bytes`.
pub fn decode(decoded: *Decoded, local_id: NodeId, packet: []const u8) Error!void {
    if (packet.len < size_min) return error.TooSmall;
    if (packet.len > size_max) return error.TooLarge;
    decoded.masking_iv = packet[0..masking_iv_length].*;
    const masked = packet[masking_iv_length..];
    // CTR is a stream cipher: unmask everything that could be header, then cut.
    mask(local_id, decoded.masking_iv, decoded.header_bytes[0..masked.len], masked);
    const static = decoded.header_bytes[0..static_header_length];
    if (!std.mem.eql(u8, static[0..protocol_id.len], protocol_id)) return error.WrongProtocol;
    if (std.mem.readInt(u16, static[6..8], .big) != version) return error.UnsupportedVersion;
    const flag = std.enums.fromInt(Flag, static[8]) orelse return error.UnknownFlag;
    decoded.nonce = static[9..][0..nonce_length].*;
    const authdata_length = std.mem.readInt(u16, static[21..23], .big);
    if (authdata_length > masked.len - static_header_length) return error.InvalidAuthdata;
    const header_length = static_header_length + authdata_length;
    decoded.header_length = @intCast(header_length);
    const authdata = decoded.header_bytes[static_header_length..header_length];
    decoded.message = masked[header_length..];
    decoded.authdata = try parse_authdata(flag, authdata);
    switch (flag) {
        .whoareyou => if (decoded.message.len != 0) return error.UnexpectedMessage,
        .message, .handshake => if (decoded.message.len < tag_length) return error.TooSmall,
    }
    assert(decoded.header_length <= header_length_max);
}

fn parse_authdata(flag: Flag, authdata: []const u8) Error!Authdata {
    switch (flag) {
        .message => {
            if (authdata.len != message_authdata_length) return error.InvalidAuthdata;
            return .{ .message = authdata[0..32].* };
        },
        .whoareyou => {
            if (authdata.len != whoareyou_authdata_length) return error.InvalidAuthdata;
            return .{ .whoareyou = .{
                .id_nonce = authdata[0..16].*,
                .enr_seq = std.mem.readInt(u64, authdata[16..24], .big),
            } };
        },
        .handshake => {
            if (authdata.len < handshake_authdata_head_length) return error.InvalidAuthdata;
            const signature_size = authdata[32];
            const key_size = authdata[33];
            if (signature_size != secp256k1.signature_length) return error.InvalidAuthdata;
            if (key_size != secp256k1.compressed_length) return error.InvalidAuthdata;
            const fixed = handshake_authdata_head_length + signature_size + key_size;
            if (authdata.len < fixed) return error.InvalidAuthdata;
            const body = authdata[handshake_authdata_head_length..];
            return .{ .handshake = .{
                .src_id = authdata[0..32].*,
                .signature = body[0..64].*,
                .ephemeral_public_key = body[64..97].*,
                .record = authdata[fixed..],
            } };
        },
    }
}

/// Everything needed to write one packet.
pub const Outgoing = struct {
    dest_id: NodeId,
    masking_iv: MaskingIv,
    nonce: Nonce,
    authdata: Authdata,
    /// Message plaintext (`message-type || rlp`) and its key; ignored for WHOAREYOU.
    plaintext: []const u8 = "",
    key: Key = @splat(0),
};

/// Writes a packet into `output`, returning the written prefix.
pub fn encode(output: *[size_max]u8, outgoing: *const Outgoing) Error![]const u8 {
    var header_buffer: [header_length_max]u8 = undefined;
    const header = try write_header(&header_buffer, outgoing);
    const is_whoareyou = outgoing.authdata == .whoareyou;
    const message_length = if (is_whoareyou) 0 else outgoing.plaintext.len + tag_length;
    const total = masking_iv_length + header.len + message_length;
    if (total > size_max) return error.TooLarge;
    if (total < size_min) return error.TooSmall;

    @memcpy(output[0..masking_iv_length], &outgoing.masking_iv);
    const masked = output[masking_iv_length..][0..header.len];
    mask(outgoing.dest_id, outgoing.masking_iv, masked, header);
    if (!is_whoareyou) {
        var ad: [size_max]u8 = undefined;
        @memcpy(ad[0..masking_iv_length], &outgoing.masking_iv);
        @memcpy(ad[masking_iv_length..][0..header.len], header);
        const message = output[masking_iv_length + header.len ..][0..outgoing.plaintext.len];
        var tag: [tag_length]u8 = undefined;
        const ad_length = masking_iv_length + header.len;
        const plaintext = outgoing.plaintext;
        Aes128Gcm.encrypt(message, &tag, plaintext, ad[0..ad_length], outgoing.nonce, outgoing.key);
        @memcpy(output[total - tag_length .. total], &tag);
    }
    assert(total >= size_min and total <= size_max);
    return output[0..total];
}

fn write_header(output: *[header_length_max]u8, outgoing: *const Outgoing) Error![]const u8 {
    var authdata_length: usize = 0;
    const authdata = output[static_header_length..];
    switch (outgoing.authdata) {
        .message => |src_id| {
            @memcpy(authdata[0..32], &src_id);
            authdata_length = 32;
        },
        .whoareyou => |value| {
            @memcpy(authdata[0..16], &value.id_nonce);
            std.mem.writeInt(u64, authdata[16..24], value.enr_seq, .big);
            authdata_length = 24;
        },
        .handshake => |value| {
            const fixed = handshake_authdata_head_length + 64 + 33;
            if (value.record.len > enr.size_max) return error.InvalidAuthdata;
            @memcpy(authdata[0..32], &value.src_id);
            authdata[32] = secp256k1.signature_length;
            authdata[33] = secp256k1.compressed_length;
            @memcpy(authdata[34..98], &value.signature);
            @memcpy(authdata[98..131], &value.ephemeral_public_key);
            @memcpy(authdata[fixed..][0..value.record.len], value.record);
            authdata_length = fixed + value.record.len;
        },
    }
    @memcpy(output[0..protocol_id.len], protocol_id);
    std.mem.writeInt(u16, output[6..8], version, .big);
    output[8] = @backingInt(outgoing.authdata);
    @memcpy(output[9..21], &outgoing.nonce);
    std.mem.writeInt(u16, output[21..23], @intCast(authdata_length), .big);
    assert(authdata_length <= header_length_max - static_header_length);
    return output[0 .. static_header_length + authdata_length];
}

/// Opens a message (ordinary or handshake) with `key`, writing plaintext into `output`.
pub fn open_message(decoded: *const Decoded, key: Key, output: []u8) error{
    TooSmall,
    AuthenticationFailed,
}![]const u8 {
    if (decoded.message.len < tag_length) return error.TooSmall;
    const ciphertext_length = decoded.message.len - tag_length;
    assert(output.len >= ciphertext_length);
    var ad_buffer: [size_max]u8 = undefined;
    const ad = decoded.authenticated_data(&ad_buffer);
    const tag = decoded.message[ciphertext_length..][0..tag_length].*;
    const plaintext = output[0..ciphertext_length];
    const ciphertext = decoded.message[0..ciphertext_length];
    Aes128Gcm.decrypt(plaintext, ciphertext, tag, ad, decoded.nonce, key) catch
        return error.AuthenticationFailed;
    return plaintext;
}

test {
    _ = @import("packet_test.zig");
}

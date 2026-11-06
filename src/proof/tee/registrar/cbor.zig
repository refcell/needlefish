//! Minimal CBOR walker matching `NitroValidator` (`decodeAttestationTbs` /
//! `_parseAttestation`), base/base `registrar/src/cbor.rs`.
//!
//! Preserves the raw protected and payload byte-string TLVs for attestation TBS
//! construction. The COSE envelope accepts only the compact `0xD2` tag (optional) and
//! compact `0x84` array; any valid unprotected map is skipped. Nested `pcrs` and
//! `cabundle` may be definite or indefinite.
//!
//! base/base skips nested items recursively; this walker uses an explicit bounded
//! stack with the same depth limit and accept/reject behavior.

const std = @import("std");
const assert = std.debug.assert;

pub const nesting_depth_max: u32 = 64;
pub const pcr_count_max: u32 = 32;
pub const cabundle_count_max: u32 = 32;
pub const cabundle_cert_size_max: u32 = 1024;
pub const p384_signature_size: u32 = 96;

pub const major_uint: u3 = 0;
pub const major_negative_int: u3 = 1;
pub const major_byte_string: u3 = 2;
pub const major_text_string: u3 = 3;
pub const major_array: u3 = 4;
pub const major_map: u3 = 5;
pub const major_tag: u3 = 6;
pub const major_simple: u3 = 7;
const cbor_break: u8 = 0xff;

const cose_sign1_tag_byte: u8 = 0xd2;
const cose_sign1_array_byte: u8 = 0x84;
const cbor_empty_byte_string: u8 = 0x40;

/// Encoded Nitro protected header selecting ES384 (`{1: -35}`) as a CBOR bstr TLV.
pub const nitro_protected_header_tlv = [_]u8{ 0x44, 0xa1, 0x01, 0x38, 0x22 };

/// `Sig_structure` array header + `"Signature1"` context string.
pub const cose_sig_structure_prefix = [_]u8{ 0x84, 0x6a } ++ "Signature1".*;

/// Bytes of TBS framing before the payload TLV: prefix, protected TLV, empty bstr.
pub const tbs_prefix_size: u32 = cose_sig_structure_prefix.len +
    nitro_protected_header_tlv.len + 1;

/// Top-level Nitro fields that `NitroValidator` treats as single-assignment.
const known_attestation_keys = [_][]const u8{
    "module_id", "digest",    "certificate", "public_key", "user_data",
    "nonce",     "timestamp", "cabundle",    "pcrs",
};

comptime {
    assert(cose_sig_structure_prefix.len == 12);
    assert(tbs_prefix_size == 18);
    assert(known_attestation_keys.len <= 16);
}

pub const Error = error{
    CoseNestingTooDeep,
    CoseOutOfBounds,
    CoseIndefiniteString,
    CoseIndefiniteScalar,
    CoseUnexpectedBreak,
    CoseMissingBreak,
    CoseContainerCount,
    CoseAdditionalInfo,
    CoseMajorType,
    CoseEnvelopeHeader,
    CoseSignatureLength,
    CoseTrailingData,
    CoseProtectedHeader,
    CoseInvalidTbs,
    CoseKeyNotUtf8,
    CoseDuplicateKey,
    CoseCertificateLength,
    CosePcrCount,
    CosePcrIndex,
    CosePcrDuplicate,
    CoseCabundleCount,
    CoseCabundleCertificateLength,
    CoseMapLength,
    CoseBufferTooSmall,
};

/// Low-level CBOR item cursor used by `NitroCose`.
pub const CborItem = struct {
    major: u3,
    /// Decoded additional-information value (length, tag, integer, ...).
    value: u64,
    indefinite: bool,
    /// Offset of the item's content, after the header.
    content_start: usize,
    /// End offset (exclusive) of the complete item.
    end: usize,

    /// Decode the complete CBOR item at `start`.
    pub fn read(bytes: []const u8, start: usize) Error!CborItem {
        return read_at(bytes, start, 0);
    }

    /// Decode an item with `depth` enclosing containers already entered.
    pub fn read_at(bytes: []const u8, start: usize, depth: u32) Error!CborItem {
        if (depth > nesting_depth_max) return error.CoseNestingTooDeep;
        const root = try read_header(bytes, start);
        var stack: [nesting_depth_max + 1]Frame = undefined;
        var stack_len: u32 = 0;
        try push_children(bytes, &stack, &stack_len, root);
        var position = root.end;
        var iterations: usize = 0;
        while (true) : (iterations += 1) {
            // Every child consumes at least one byte.
            assert(iterations <= bytes.len);
            position = try pop_finished(bytes, &stack, &stack_len, position);
            if (stack_len == 0) break;
            if (depth + stack_len > nesting_depth_max) return error.CoseNestingTooDeep;
            stack[stack_len - 1].consume();
            const child = try read_header(bytes, position);
            try push_children(bytes, &stack, &stack_len, child);
            position = child.end;
        }
        assert(position <= bytes.len and position > start);
        return .{
            .major = root.major,
            .value = root.value,
            .indefinite = root.indefinite,
            .content_start = root.content_start,
            .end = position,
        };
    }

    /// Ensure this item has the expected CBOR major type.
    pub fn require_major(item: CborItem, major: u3) Error!CborItem {
        assert(item.end > item.content_start or item.end == item.content_start);
        if (item.major != major) return error.CoseMajorType;
        return item;
    }

    pub fn content(item: CborItem, bytes: []const u8) []const u8 {
        assert(item.end <= bytes.len);
        assert(item.content_start <= item.end);
        return bytes[item.content_start..item.end];
    }
};

const AdditionalInfo = struct {
    value: u64,
    /// Header length including the initial byte.
    header_size: u32,
    indefinite: bool,
};

/// Decode the additional-information portion of a CBOR header at `offset`.
pub fn read_additional_info(bytes: []const u8, offset: usize, ai: u5) Error!AdditionalInfo {
    assert(offset >= 1);
    const width: u32 = switch (ai) {
        0...23 => return .{ .value = ai, .header_size = 1, .indefinite = false },
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        31 => return .{ .value = 0, .header_size = 1, .indefinite = true },
        else => return error.CoseAdditionalInfo,
    };
    if (offset > bytes.len or bytes.len - offset < width) return error.CoseOutOfBounds;
    var value: u64 = 0;
    for (bytes[offset..][0..width]) |byte| value = (value << 8) | byte;
    assert(width <= 8);
    return .{ .value = value, .header_size = 1 + width, .indefinite = false };
}

/// One item header; `end` is the item end for scalars and strings, else content start.
const Header = struct {
    major: u3,
    value: u64,
    indefinite: bool,
    content_start: usize,
    end: usize,
};

fn read_header(bytes: []const u8, start: usize) Error!Header {
    if (start >= bytes.len) return error.CoseOutOfBounds;
    const initial = bytes[start];
    const major: u3 = @intCast(initial >> 5);
    const info = try read_additional_info(bytes, start + 1, @truncate(initial));
    const content_start = start + info.header_size;
    assert(content_start <= bytes.len);
    var end = content_start;
    switch (major) {
        major_byte_string, major_text_string => {
            if (info.indefinite) return error.CoseIndefiniteString;
            if (info.value > bytes.len - content_start) return error.CoseOutOfBounds;
            end = content_start + @as(usize, @intCast(info.value));
        },
        major_uint, major_negative_int => {
            if (info.indefinite) return error.CoseIndefiniteScalar;
        },
        major_simple => {
            if (info.indefinite) return error.CoseUnexpectedBreak;
        },
        major_tag => {
            if (info.indefinite) return error.CoseIndefiniteScalar;
        },
        major_array, major_map => {},
    }
    assert(end <= bytes.len);
    return .{
        .major = major,
        .value = info.value,
        .indefinite = info.indefinite,
        .content_start = content_start,
        .end = end,
    };
}

/// Children still owed by an open container.
const Frame = struct {
    /// Definite containers: children left (map entries count twice).
    remaining: u64,
    indefinite: bool,
    /// Indefinite maps: the next child is a value, so no break may appear.
    value_pending: bool,
    is_map: bool,

    fn consume(frame: *Frame) void {
        if (frame.indefinite) {
            if (frame.is_map) frame.value_pending = !frame.value_pending;
        } else {
            assert(frame.remaining > 0);
            frame.remaining -= 1;
        }
    }
};

fn push_children(
    bytes: []const u8,
    stack: *[nesting_depth_max + 1]Frame,
    stack_len: *u32,
    header: Header,
) Error!void {
    assert(header.content_start <= bytes.len);
    const available: u64 = bytes.len - header.content_start;
    const frame: Frame = switch (header.major) {
        major_array => blk: {
            if (!header.indefinite and header.value > available) {
                return error.CoseContainerCount;
            }
            break :blk .{
                .remaining = header.value,
                .indefinite = header.indefinite,
                .value_pending = false,
                .is_map = false,
            };
        },
        major_map => blk: {
            if (!header.indefinite and header.value > available / 2) {
                return error.CoseContainerCount;
            }
            break :blk .{
                .remaining = header.value * 2,
                .indefinite = header.indefinite,
                .value_pending = false,
                .is_map = true,
            };
        },
        major_tag => .{ .remaining = 1, .indefinite = false, .value_pending = false, .is_map = false },
        else => return,
    };
    // The depth check before every child read keeps the stack within bounds.
    assert(stack_len.* < stack.len);
    stack[stack_len.*] = frame;
    stack_len.* += 1;
}

fn pop_finished(
    bytes: []const u8,
    stack: *[nesting_depth_max + 1]Frame,
    stack_len: *u32,
    position_start: usize,
) Error!usize {
    var position = position_start;
    while (stack_len.* > 0) {
        const top = stack[stack_len.* - 1];
        if (top.indefinite) {
            if (top.value_pending) break;
            if (position >= bytes.len) return error.CoseMissingBreak;
            if (bytes[position] != cbor_break) break;
            position += 1;
        } else if (top.remaining != 0) {
            break;
        }
        stack_len.* -= 1;
    }
    assert(position <= bytes.len);
    return position;
}

/// Strictly parsed `COSE_Sign1` fields needed to build a registration plan.
pub const ParsedCoseSign1 = struct {
    /// Attestation TBS built from the raw protected/payload TLVs (no reserialization).
    attestation_tbs: []const u8,
    /// Raw attestation document payload bytes (CBOR map), borrowed from the input.
    payload: []const u8,
    /// 96-byte P-384 signature (`r || s`), borrowed from the input.
    signature: *const [p384_signature_size]u8,
};

/// `NitroValidator`-aligned `COSE_Sign1` / payload structure parser.
pub const NitroCose = struct {
    /// Reconstruct a `COSE_Sign1` envelope without changing the signed TBS bytes.
    pub fn sign1_from_tbs(tbs: []const u8, signature: []const u8, out: []u8) Error![]u8 {
        const prefix = cose_sig_structure_prefix ++ nitro_protected_header_tlv ++
            [_]u8{cbor_empty_byte_string};
        comptime assert(prefix.len == tbs_prefix_size);
        if (!std.mem.startsWith(u8, tbs, &prefix) or signature.len != p384_signature_size) {
            return error.CoseInvalidTbs;
        }
        const payload = try (try CborItem.read(tbs, prefix.len)).require_major(major_byte_string);
        if (payload.end != tbs.len) return error.CoseTrailingData;
        const payload_tlv = tbs[prefix.len..];
        const size = 1 + nitro_protected_header_tlv.len + 1 + payload_tlv.len + 2 +
            p384_signature_size;
        if (out.len < size) return error.CoseBufferTooSmall;
        var writer: Writer = .{ .buffer = out };
        writer.byte(cose_sign1_array_byte);
        writer.raw(&nitro_protected_header_tlv);
        writer.byte(0xa0);
        writer.raw(payload_tlv);
        writer.raw(&.{ 0x58, p384_signature_size });
        writer.raw(signature);
        assert(writer.position == size);
        return out[0..size];
    }

    /// Parse a `COSE_Sign1` attestation with `decodeAttestationTbs` envelope checks.
    /// The TBS is written to `tbs_out`; payload and signature borrow `attestation`.
    pub fn parse_sign1(attestation: []const u8, tbs_out: []u8) Error!ParsedCoseSign1 {
        if (attestation.len == 0) return error.CoseOutOfBounds;
        var offset: usize = 0;
        if (attestation[0] == cose_sign1_tag_byte) offset = 1;
        if (offset >= attestation.len or attestation[offset] != cose_sign1_array_byte) {
            return error.CoseEnvelopeHeader;
        }
        offset += 1;
        const protected = try (try CborItem.read(attestation, offset))
            .require_major(major_byte_string);
        const unprotected = try (try CborItem.read(attestation, protected.end))
            .require_major(major_map);
        const payload = try (try CborItem.read(attestation, unprotected.end))
            .require_major(major_byte_string);
        const signature = try (try CborItem.read(attestation, payload.end))
            .require_major(major_byte_string);
        if (signature.end - signature.content_start != p384_signature_size) {
            return error.CoseSignatureLength;
        }
        if (signature.end != attestation.len) return error.CoseTrailingData;
        const raw_protected = attestation[offset..protected.end];
        if (!std.mem.eql(u8, raw_protected, &nitro_protected_header_tlv)) {
            return error.CoseProtectedHeader;
        }
        const raw_payload_tlv = attestation[unprotected.end..payload.end];
        const tbs_size = tbs_prefix_size + raw_payload_tlv.len;
        if (tbs_out.len < tbs_size) return error.CoseBufferTooSmall;
        var writer: Writer = .{ .buffer = tbs_out };
        writer.raw(&cose_sig_structure_prefix);
        writer.raw(raw_protected);
        writer.byte(cbor_empty_byte_string);
        writer.raw(raw_payload_tlv);
        assert(writer.position == tbs_size);
        return .{
            .attestation_tbs = tbs_out[0..tbs_size],
            .payload = payload.content(attestation),
            .signature = attestation[signature.content_start..][0..p384_signature_size],
        };
    }

    /// Validate payload CBOR structure: no trailing bytes, single-assignment known
    /// keys, PCR index rules, certificate and cabundle limits.
    pub fn validate_payload_structure(payload: []const u8) Error!void {
        const root = try (try CborItem.read(payload, 0)).require_major(major_map);
        if (root.end != payload.len) return error.CoseTrailingData;
        var offset = root.content_start;
        var item_count: u64 = 0;
        var seen_keys: u16 = 0;
        while (true) : (item_count += 1) {
            // Each entry is at least a one-byte key and a one-byte value.
            assert(item_count <= payload.len);
            if (try container_done(payload, root, offset, item_count)) break;
            const key = try (try CborItem.read(payload, offset)).require_major(major_text_string);
            const value = try CborItem.read(payload, key.end);
            const key_text = key.content(payload);
            if (!std.unicode.utf8ValidateSlice(key_text)) return error.CoseKeyNotUtf8;
            if (known_key_index(key_text)) |index| {
                const bit = @as(u16, 1) << @intCast(index);
                if (seen_keys & bit != 0) return error.CoseDuplicateKey;
                seen_keys |= bit;
            }
            try validate_field(payload, key_text, value);
            offset = value.end;
        }
        if (root.indefinite) {
            assert(payload[offset] == cbor_break);
        } else if (offset != root.end) {
            return error.CoseMapLength;
        }
    }

    fn validate_field(payload: []const u8, key_text: []const u8, value: CborItem) Error!void {
        assert(value.end <= payload.len);
        if (std.mem.eql(u8, key_text, "pcrs")) return validate_pcrs(payload, value);
        if (std.mem.eql(u8, key_text, "cabundle")) return validate_cabundle(payload, value);
        if (std.mem.eql(u8, key_text, "certificate")) {
            const certificate = try value.require_major(major_byte_string);
            const length = certificate.end - certificate.content_start;
            if (length == 0 or length > cabundle_cert_size_max) {
                return error.CoseCertificateLength;
            }
        }
    }

    /// `pcrs`: unique keys below 32, definite or indefinite. Matches
    /// `NitroValidator._parsePcrs` (32-slot bank, sparse indices allowed).
    fn validate_pcrs(payload: []const u8, item: CborItem) Error!void {
        const pcrs = try item.require_major(major_map);
        if (!pcrs.indefinite and pcrs.value > pcr_count_max) return error.CosePcrCount;
        var seen: u32 = 0;
        var offset = pcrs.content_start;
        var count: u64 = 0;
        while (true) : (count += 1) {
            assert(count <= pcr_count_max);
            if (try container_done(payload, pcrs, offset, count)) break;
            if (count >= pcr_count_max) return error.CosePcrCount;
            const key = try (try CborItem.read(payload, offset)).require_major(major_uint);
            if (key.value >= pcr_count_max) return error.CosePcrIndex;
            const bit = @as(u32, 1) << @intCast(key.value);
            if (seen & bit != 0) return error.CosePcrDuplicate;
            seen |= bit;
            const value = try (try CborItem.read(payload, key.end))
                .require_major(major_byte_string);
            offset = value.end;
        }
    }

    /// Validate cabundle length and per-certificate size limits.
    fn validate_cabundle(payload: []const u8, item: CborItem) Error!void {
        const cabundle = try item.require_major(major_array);
        if (!cabundle.indefinite and cabundle.value > cabundle_count_max) {
            return error.CoseCabundleCount;
        }
        var offset = cabundle.content_start;
        var count: u64 = 0;
        while (true) : (count += 1) {
            assert(count <= cabundle_count_max);
            if (try container_done(payload, cabundle, offset, count)) break;
            if (count >= cabundle_count_max) return error.CoseCabundleCount;
            const cert = try (try CborItem.read(payload, offset)).require_major(major_byte_string);
            const length = cert.end - cert.content_start;
            if (length == 0 or length > cabundle_cert_size_max) {
                return error.CoseCabundleCertificateLength;
            }
            offset = cert.end;
        }
        if (count == 0) return error.CoseCabundleCount;
    }

    fn known_key_index(key: []const u8) ?u32 {
        for (known_attestation_keys, 0..) |known, index| {
            if (std.mem.eql(u8, key, known)) return @intCast(index);
        }
        return null;
    }

    fn container_done(
        bytes: []const u8,
        container: CborItem,
        offset: usize,
        item_count: u64,
    ) Error!bool {
        assert(container.major == major_map or container.major == major_array);
        if (!container.indefinite) return item_count == container.value;
        if (offset >= bytes.len) return error.CoseMissingBreak;
        return bytes[offset] == cbor_break;
    }
};

/// Bounded byte writer; callers check capacity first.
const Writer = struct {
    buffer: []u8,
    position: usize = 0,

    fn raw(writer: *Writer, bytes: []const u8) void {
        assert(writer.position + bytes.len <= writer.buffer.len);
        @memcpy(writer.buffer[writer.position..][0..bytes.len], bytes);
        writer.position += bytes.len;
    }

    fn byte(writer: *Writer, value: u8) void {
        assert(writer.position < writer.buffer.len);
        writer.buffer[writer.position] = value;
        writer.position += 1;
    }
};

test {
    _ = @import("cbor_test.zig");
}

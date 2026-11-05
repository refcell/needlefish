//! `COSE_Sign1` parsing and Nitro attestation document extraction (base/base
//! `attestation.rs`).
//!
//! Everything borrows from the input bytes; nothing allocates. The envelope is
//! `[protected, unprotected, payload, signature]`, optionally wrapped in CBOR tag 18.
//! Unlike base/base, the protected header is decoded and its algorithm must be ES384
//! (COSE algorithm -35): Nitro always signs with ES384, and checking it keeps a
//! malformed envelope from reaching signature verification.

const std = @import("std");
const assert = std.debug.assert;
const cbor = @import("cbor.zig");
const errors = @import("errors.zig");
const types = @import("types.zig");

pub const Error = errors.Error;

/// COSE algorithm identifier for ECDSA P-384 with SHA-384.
pub const algorithm_es384: i64 = -35;
pub const cose_sign1_tag: u64 = 18;

/// Decoder limits for envelopes and documents. A maximal valid document holds 32
/// CA certificates and a leaf of at most 1024 bytes each plus small fields, well
/// under 64 KiB and a few hundred items.
pub const limits: cbor.Limits = .{
    .depth_max = 8,
    .items_max = 1024,
    .input_size_max = 64 * 1024,
};

pub const CoseSign1 = struct {
    /// CBOR-encoded protected header bytes.
    protected: []const u8,
    /// CBOR-encoded attestation document.
    payload: []const u8,
    signature: []const u8,

    pub fn parse(bytes: []const u8) Error!CoseSign1 {
        try cbor.validate(bytes, limits);
        var reader = cbor.Reader.init(bytes);
        var head = try reader.next();
        if (head == .tag) {
            if (head.tag != cose_sign1_tag) return error.CoseWrongTag;
            head = try reader.next();
            if (head != .array) return error.CoseNotArray;
        }
        if (head != .array) return error.CoseNotArray;
        if (head.array != 4) return error.CoseWrongLength;
        const protected = try expect_cose_bytes(&reader);
        try reader.skip(limits); // Unprotected header: unused, as in base/base.
        const payload = try expect_cose_bytes(&reader);
        const signature = try expect_cose_bytes(&reader);
        assert(reader.at_end());
        return .{ .protected = protected, .payload = payload, .signature = signature };
    }

    fn expect_cose_bytes(reader: *cbor.Reader) Error![]const u8 {
        const item = try reader.next();
        if (item != .bytes) return error.CoseFieldType;
        assert(item.bytes.len <= reader.bytes.len);
        return item.bytes;
    }

    /// Require the protected header to be a map whose `alg` (label 1) is ES384.
    pub fn check_algorithm(cose: *const CoseSign1) Error!void {
        if (cose.protected.len == 0) return error.CoseAlgorithmMissing;
        try cbor.validate(cose.protected, limits);
        var reader = cbor.Reader.init(cose.protected);
        const head = try reader.next();
        if (head != .map) return error.CoseFieldType;
        var algorithm: ?i64 = null;
        var pair: u64 = 0;
        while (pair < head.map) : (pair += 1) {
            const key = try reader.peek();
            if (key != .unsigned or key.unsigned != 1) {
                try reader.skip(limits);
                try reader.skip(limits);
                continue;
            }
            _ = try reader.next();
            if (algorithm != null) return error.CoseFieldType;
            algorithm = try algorithm_value(try reader.next());
        }
        assert(reader.at_end());
        const value = algorithm orelse return error.CoseAlgorithmMissing;
        if (value != algorithm_es384) return error.CoseAlgorithmUnsupported;
    }

    /// COSE algorithm identifiers are integers; values outside `i64` are unsupported.
    fn algorithm_value(item: cbor.Item) Error!i64 {
        const limit: u64 = std.math.maxInt(i64);
        const value: i64 = switch (item) {
            .negative => |argument| if (argument < limit) -1 - @as(i64, @intCast(argument)) else 0,
            .unsigned => |argument| if (argument <= limit) @intCast(argument) else 0,
            else => return error.CoseAlgorithmUnsupported,
        };
        assert(value != 0 or item == .unsigned or item == .negative);
        return value;
    }

    /// Feed the RFC 8152 section 4.4 `Sig_structure`
    /// `["Signature1", protected, h'', payload]` to `sink.update(bytes)`.
    pub fn sig_structure_emit(cose: *const CoseSign1, sink: anytype) void {
        var head: [9]u8 = undefined;
        sink.update(&.{ 0x84, 0x6a });
        sink.update("Signature1");
        sink.update(cbor.head_encode(&head, .bytes, cose.protected.len));
        sink.update(cose.protected);
        sink.update(&.{0x40});
        sink.update(cbor.head_encode(&head, .bytes, cose.payload.len));
        sink.update(cose.payload);
    }

    pub fn sig_structure_size(cose: *const CoseSign1) u64 {
        const size: u64 = 2 + 10 + cbor.head_size(cose.protected.len) + cose.protected.len +
            1 + cbor.head_size(cose.payload.len) + cose.payload.len;
        assert(size > cose.protected.len + cose.payload.len);
        return size;
    }
};

/// A parsed Nitro attestation document. Byte fields borrow from the payload.
pub const AttestationDocument = struct {
    module_id: []const u8,
    /// Unix milliseconds.
    timestamp_ms: u64,
    digest: []const u8,
    /// Sorted by ascending index, like base/base's `BTreeMap`.
    pcrs: [types.pcr_count_max]types.Pcr,
    pcr_count: u8,
    certificate: []const u8,
    /// Root first, then intermediates.
    cabundle: [types.cabundle_count_max][]const u8,
    cabundle_count: u8,
    public_key: ?[]const u8,
    user_data: ?[]const u8,
    nonce: ?[]const u8,

    pub fn parse(payload: []const u8) Error!AttestationDocument {
        try cbor.validate(payload, limits);
        var reader = cbor.Reader.init(payload);
        const head = try reader.next();
        if (head != .map) return error.DocumentNotMap;
        var document: AttestationDocument = undefined;
        document.public_key = null;
        document.user_data = null;
        document.nonce = null;
        var seen: u9 = 0;
        var pair: u64 = 0;
        while (pair < head.map) : (pair += 1) {
            const key = try reader.next();
            if (key != .text) return error.DocumentFieldType;
            const field = std.meta.stringToEnum(Field, key.text) orelse {
                try reader.skip(limits); // Unknown fields are ignored, as serde does.
                continue;
            };
            const bit = @as(u9, 1) << @backingInt(field);
            if (seen & bit != 0) return error.DocumentFieldDuplicate;
            seen |= bit;
            try document.parse_field(&reader, field);
        }
        assert(reader.at_end());
        if (seen & Field.required_mask != Field.required_mask) {
            return error.DocumentFieldMissing;
        }
        return document;
    }

    const Field = enum(u4) {
        module_id,
        timestamp,
        digest,
        pcrs,
        certificate,
        cabundle,
        public_key,
        user_data,
        nonce,

        const required_mask: u9 = 0b0_0011_1111;
    };

    fn parse_field(document: *AttestationDocument, reader: *cbor.Reader, field: Field) Error!void {
        assert(reader.position < reader.bytes.len);
        switch (field) {
            .module_id => document.module_id = try expect_text(reader),
            .digest => document.digest = try expect_text(reader),
            .timestamp => {
                const item = try reader.next();
                if (item != .unsigned) return error.DocumentFieldType;
                document.timestamp_ms = item.unsigned;
            },
            .pcrs => try document.parse_pcrs(reader),
            .certificate => document.certificate = try expect_bytes(reader),
            .cabundle => try document.parse_cabundle(reader),
            .public_key => document.public_key = try optional_bytes(reader),
            .user_data => document.user_data = try optional_bytes(reader),
            .nonce => document.nonce = try optional_bytes(reader),
        }
    }

    fn parse_pcrs(document: *AttestationDocument, reader: *cbor.Reader) Error!void {
        const head = try reader.next();
        if (head != .map) return error.DocumentFieldType;
        if (head.map > types.pcr_count_max) return error.PcrCount;
        document.pcr_count = 0;
        var pair: u64 = 0;
        while (pair < head.map) : (pair += 1) {
            const key = try reader.next();
            if (key != .unsigned) return error.DocumentFieldType;
            const value = try expect_bytes(reader);
            if (value.len != types.pcr_size_bytes) return error.PcrLength;
            try document.insert_pcr(key.unsigned, value[0..types.pcr_size_bytes]);
        }
        assert(document.pcr_count == head.map);
    }

    /// Sorted insert. base/base's map would silently keep the last duplicate; a
    /// duplicate PCR index is rejected here instead.
    fn insert_pcr(document: *AttestationDocument, index: u64, value: *const [48]u8) Error!void {
        assert(document.pcr_count < types.pcr_count_max);
        var position: u32 = document.pcr_count;
        while (position > 0) : (position -= 1) {
            const previous = document.pcrs[position - 1];
            if (previous.index == index) return error.PcrDuplicate;
            if (previous.index < index) break;
            document.pcrs[position] = previous;
        }
        document.pcrs[position] = .{ .index = index, .value = value.* };
        document.pcr_count += 1;
    }

    fn parse_cabundle(document: *AttestationDocument, reader: *cbor.Reader) Error!void {
        const head = try reader.next();
        if (head != .array) return error.DocumentFieldType;
        if (head.array > types.cabundle_count_max) return error.CabundleCount;
        var index: u32 = 0;
        while (index < head.array) : (index += 1) {
            document.cabundle[index] = try expect_bytes(reader);
        }
        document.cabundle_count = @intCast(index);
        assert(document.cabundle_count == head.array);
    }

    /// Certificates in chain order: root, intermediates, leaf.
    pub fn cert_chain(
        document: *const AttestationDocument,
        out: *[types.chain_length_max][]const u8,
    ) []const []const u8 {
        assert(document.cabundle_count <= types.cabundle_count_max);
        const count = document.cabundle_count;
        @memcpy(out[0..count], document.cabundle[0..count]);
        out[count] = document.certificate;
        assert(out[count].ptr == document.certificate.ptr);
        return out[0 .. count + 1];
    }
};

fn expect_text(reader: *cbor.Reader) Error![]const u8 {
    const item = try reader.next();
    if (item != .text) return error.DocumentFieldType;
    assert(item.text.len <= reader.bytes.len);
    return item.text;
}

fn expect_bytes(reader: *cbor.Reader) Error![]const u8 {
    const item = try reader.next();
    if (item != .bytes) return error.DocumentFieldType;
    assert(item.bytes.len <= reader.bytes.len);
    return item.bytes;
}

fn optional_bytes(reader: *cbor.Reader) Error!?[]const u8 {
    const item = try reader.next();
    return switch (item) {
        .null => null,
        .bytes => |bytes| bytes,
        else => error.DocumentFieldType,
    };
}

/// A parsed attestation report: envelope plus document.
pub const AttestationReport = struct {
    cose: CoseSign1,
    document: AttestationDocument,

    pub fn parse(bytes: []const u8) Error!AttestationReport {
        const cose = try CoseSign1.parse(bytes);
        const document = try AttestationDocument.parse(cose.payload);
        assert(document.cabundle_count <= types.cabundle_count_max);
        assert(document.pcr_count <= types.pcr_count_max);
        return .{ .cose = cose, .document = document };
    }
};

const testing = std.testing;

test "nitro attestation: COSE rejects empty and non-array input" {
    try testing.expectError(error.Truncated, CoseSign1.parse(&.{}));
    try testing.expectError(error.CoseNotArray, CoseSign1.parse(&.{ 0x18, 0x2a }));
}

test "nitro attestation: COSE rejects wrong length array" {
    try testing.expectError(error.CoseWrongLength, CoseSign1.parse(&.{ 0x83, 0x40, 0x40, 0x40 }));
}

test "nitro attestation: COSE parses a valid four element array" {
    const bytes = [_]u8{ 0x84, 0x41, 0x01, 0xa0, 0x42, 0x02, 0x03, 0x41, 0x04 };
    const cose = try CoseSign1.parse(&bytes);
    try testing.expectEqualSlices(u8, &.{0x01}, cose.protected);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x03 }, cose.payload);
    try testing.expectEqualSlices(u8, &.{0x04}, cose.signature);
}

test "nitro attestation: COSE handles tag 18 and rejects other tags" {
    const tagged = [_]u8{ 0xd2, 0x84, 0x41, 0x01, 0xa0, 0x41, 0x02, 0x41, 0x03 };
    const cose = try CoseSign1.parse(&tagged);
    try testing.expectEqualSlices(u8, &.{0x01}, cose.protected);
    const wrong = [_]u8{ 0xd8, 0x63, 0x84, 0x40, 0xa0, 0x40, 0x40 };
    try testing.expectError(error.CoseWrongTag, CoseSign1.parse(&wrong));
    const tagged_int = [_]u8{ 0xd2, 0x01 };
    try testing.expectError(error.CoseNotArray, CoseSign1.parse(&tagged_int));
    const field = [_]u8{ 0x84, 0x01, 0xa0, 0x40, 0x40 };
    try testing.expectError(error.CoseFieldType, CoseSign1.parse(&field));
}

test "nitro attestation: protected header must name ES384" {
    var cose: CoseSign1 = .{
        .protected = &.{ 0xa1, 0x01, 0x38, 0x22 },
        .payload = &.{},
        .signature = &.{},
    };
    try cose.check_algorithm();
    cose.protected = &.{ 0xa1, 0x01, 0x26 }; // ES256 (-7).
    try testing.expectError(error.CoseAlgorithmUnsupported, cose.check_algorithm());
    cose.protected = &.{ 0xa1, 0x04, 0x41, 0x00 }; // kid only.
    try testing.expectError(error.CoseAlgorithmMissing, cose.check_algorithm());
    cose.protected = &.{};
    try testing.expectError(error.CoseAlgorithmMissing, cose.check_algorithm());
    cose.protected = &.{ 0xa2, 0x01, 0x38, 0x22, 0x01, 0x38, 0x22 };
    try testing.expectError(error.CoseFieldType, cose.check_algorithm());
    cose.protected = &.{ 0x81, 0x01 };
    try testing.expectError(error.CoseFieldType, cose.check_algorithm());
}

const SliceSink = struct {
    writer: cbor.Writer,
    fn update(sink: *SliceSink, bytes: []const u8) void {
        sink.writer.raw(bytes) catch unreachable; // Test buffer is sized generously.
    }
};

test "nitro attestation: sig structure is a four element CBOR array" {
    const cose: CoseSign1 = .{
        .protected = &.{ 0xa1, 0x01, 0x38, 0x22 },
        .payload = &.{ 0x01, 0x02 },
        .signature = &.{0x03},
    };
    var buffer: [64]u8 = undefined;
    var sink: SliceSink = .{ .writer = .{ .buffer = &buffer } };
    cose.sig_structure_emit(&sink);
    const expected = [_]u8{0x84} ++ [_]u8{0x6a} ++ "Signature1".* ++
        [_]u8{ 0x44, 0xa1, 0x01, 0x38, 0x22, 0x40, 0x42, 0x01, 0x02 };
    try testing.expectEqualSlices(u8, &expected, sink.writer.written());
    try testing.expectEqual(@as(u64, expected.len), cose.sig_structure_size());
    try cbor.validate(sink.writer.written(), .{});
}

test "nitro attestation: parses the real Nitro attestation document" {
    const report = try AttestationReport.parse(@embedFile("testdata/attestation.bin"));
    const document = &report.document;
    try testing.expectEqualStrings("i-0de38b2b6853cc9e8-enc0193685e7fee7d85", document.module_id);
    try testing.expectEqualStrings("SHA384", document.digest);
    try testing.expectEqual(@as(u64, 0x000001937de1c543), document.timestamp_ms);
    try testing.expectEqual(@as(u8, 16), document.pcr_count);
    try testing.expectEqual(@as(u8, 4), document.cabundle_count);
    try testing.expect(document.public_key != null);
    try testing.expect(document.user_data == null);
    try testing.expect(document.nonce == null);
    for (document.pcrs[0..document.pcr_count], 0..) |pcr, index| {
        try testing.expectEqual(@as(u64, index), pcr.index);
    }
    try testing.expectEqualSlices(
        u8,
        @embedFile("testdata/aws_nitro_root_g1.der"),
        document.cabundle[0],
    );
    try testing.expectEqualSlices(u8, @embedFile("testdata/leaf.der"), document.certificate);
    try report.cose.check_algorithm();
    try testing.expectEqual(@as(usize, 96), report.cose.signature.len);
}

/// Builds a document map with `entries` raw key/value CBOR snippets.
fn build_document(buffer: []u8, pcr_bytes: []const u8, extra: []const u8) ![]const u8 {
    var writer: cbor.Writer = .{ .buffer = buffer };
    try writer.head(.map, if (extra.len > 0) 7 else 6);
    try writer.text_string("module_id");
    try writer.text_string("m");
    try writer.text_string("timestamp");
    try writer.integer(1);
    try writer.text_string("digest");
    try writer.text_string("SHA384");
    try writer.text_string("pcrs");
    try writer.raw(pcr_bytes);
    try writer.text_string("certificate");
    try writer.byte_string(&.{0x30});
    try writer.text_string("cabundle");
    try writer.head(.array, 1);
    try writer.byte_string(&.{0x30});
    try writer.raw(extra);
    return writer.written();
}

test "nitro attestation: document field validation" {
    var buffer: [512]u8 = undefined;
    var pcr_buffer: [128]u8 = undefined;
    var pcrs: cbor.Writer = .{ .buffer = &pcr_buffer };
    try pcrs.head(.map, 2);
    try pcrs.integer(5);
    try pcrs.byte_string(&@as([48]u8, @splat(5)));
    try pcrs.integer(1);
    try pcrs.byte_string(&@as([48]u8, @splat(1)));
    const sorted = try AttestationDocument.parse(try build_document(&buffer, pcrs.written(), ""));
    try testing.expectEqual(@as(u64, 1), sorted.pcrs[0].index);
    try testing.expectEqual(@as(u64, 5), sorted.pcrs[1].index);
    try testing.expect(sorted.public_key == null);

    const unknown = [_]u8{ 0x61, 'z', 0x82, 0x01, 0x02 };
    _ = try AttestationDocument.parse(try build_document(&buffer, pcrs.written(), &unknown));
    const duplicate = [_]u8{ 0x66, 'd', 'i', 'g', 'e', 's', 't', 0x61, 'x' };
    try testing.expectError(error.DocumentFieldDuplicate, AttestationDocument.parse(
        try build_document(&buffer, pcrs.written(), &duplicate),
    ));
    const nonce_type = [_]u8{ 0x65, 'n', 'o', 'n', 'c', 'e', 0x01 };
    try testing.expectError(error.DocumentFieldType, AttestationDocument.parse(
        try build_document(&buffer, pcrs.written(), &nonce_type),
    ));

    const short_pcr = [_]u8{ 0xa1, 0x00, 0x43, 1, 2, 3 };
    try testing.expectError(error.PcrLength, AttestationDocument.parse(
        try build_document(&buffer, &short_pcr, ""),
    ));
    var dup_buffer: [128]u8 = undefined;
    var dup: cbor.Writer = .{ .buffer = &dup_buffer };
    try dup.head(.map, 2);
    for (0..2) |_| {
        try dup.integer(3);
        try dup.byte_string(&@as([48]u8, @splat(3)));
    }
    try testing.expectError(error.PcrDuplicate, AttestationDocument.parse(
        try build_document(&buffer, dup.written(), ""),
    ));
    try testing.expectError(error.DocumentNotMap, AttestationDocument.parse(&.{0x80}));
    try testing.expectError(error.DocumentFieldMissing, AttestationDocument.parse(&.{0xa0}));
}

const fuzz = @import("../../../testing/fuzz.zig");

/// Property: arbitrary bytes never crash the envelope or document parsers.
fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    if (CoseSign1.parse(input)) |cose| {
        try testing.expect(cose.payload.len < input.len);
        cose.check_algorithm() catch {};
    } else |_| {}
    if (AttestationDocument.parse(input)) |document| {
        try testing.expect(document.pcr_count <= types.pcr_count_max);
        try testing.expect(document.cabundle_count <= types.cabundle_count_max);
    } else |_| {}
}

/// Property: single-byte corruptions of a real report are parsed or rejected cleanly.
fn fuzz_mutate(_: void, smith: *testing.Smith) anyerror!void {
    const original = @embedFile("testdata/attestation.bin");
    var buffer: [original.len]u8 = original.*;
    var flips: u32 = 0;
    while (flips < 4 and !smith.eosWeightedSimple(1, 1)) : (flips += 1) {
        const index = smith.valueRangeLessThan(u32, 0, original.len);
        buffer[index] = smith.value(u8);
    }
    const cut = smith.valueRangeAtMost(u32, 0, 64);
    _ = AttestationReport.parse(buffer[0 .. original.len - cut]) catch return;
}

test "nitro attestation: fuzz parse" {
    try fuzz.run({}, fuzz_parse, .{ .iterations = 1024 });
}

test "nitro attestation: fuzz mutated real report" {
    try fuzz.run({}, fuzz_mutate, .{ .iterations = 512 });
}

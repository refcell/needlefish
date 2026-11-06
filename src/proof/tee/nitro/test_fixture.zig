//! Test-only builder for synthetic Nitro attestations: a deterministic P-384 root
//! and leaf certificate (hand-built DER), an attestation document, and a signed
//! `COSE_Sign1` envelope. Lets tests cover accept and reject paths the single real
//! fixture cannot (expired leaf, populated optional fields, tag 18, wrong keys).

const std = @import("std");
const assert = std.debug.assert;
const cbor = @import("cbor.zig");
const x509 = @import("x509.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;

/// Bounded DER writer. `begin` reserves room for a three-byte length; `end` moves
/// the content back so every length uses the minimal DER form.
const Der = struct {
    buffer: []u8,
    position: usize = 0,

    const reserved: usize = 4;

    fn begin(der: *Der, tag: u8) usize {
        assert(der.position + reserved <= der.buffer.len);
        const start = der.position;
        der.buffer[start] = tag;
        der.position += reserved;
        return start;
    }

    fn end(der: *Der, start: usize) void {
        const content_start = start + reserved;
        const length = der.position - content_start;
        assert(length <= 0xffff);
        const length_bytes: usize = if (length < 0x80) 1 else if (length <= 0xff) 2 else 3;
        const header = der.buffer[start + 1 ..][0..3];
        switch (length_bytes) {
            1 => header[0] = @intCast(length),
            2 => header[0..2].* = .{ 0x81, @intCast(length) },
            else => header.* = .{ 0x82, @intCast(length >> 8), @truncate(length) },
        }
        const target = start + 1 + length_bytes;
        std.mem.copyForwards(
            u8,
            der.buffer[target..][0..length],
            der.buffer[content_start..][0..length],
        );
        der.position = target + length;
        assert(der.position <= content_start + length);
    }

    fn raw(der: *Der, bytes: []const u8) void {
        assert(der.position + bytes.len <= der.buffer.len);
        @memcpy(der.buffer[der.position..][0..bytes.len], bytes);
        der.position += bytes.len;
    }

    fn tlv(der: *Der, tag: u8, content: []const u8) void {
        const start = der.begin(tag);
        der.raw(content);
        der.end(start);
    }

    fn name(der: *Der, common_name: []const u8) void {
        const sequence = der.begin(0x30);
        const set = der.begin(0x31);
        const attribute = der.begin(0x30);
        der.tlv(0x06, &.{ 0x55, 0x04, 0x03 });
        der.tlv(0x0c, common_name);
        der.end(attribute);
        der.end(set);
        der.end(sequence);
    }
};

pub const CertSpec = struct {
    issuer: []const u8,
    subject: []const u8,
    /// UTCTime strings, `YYMMDDHHMMSSZ`.
    not_before: *const [13]u8 = "200101000000Z",
    not_after: *const [13]u8 = "400101000000Z",
    ca: bool,
};

/// Build a certificate for `subject_key`, signed by `issuer_key`.
pub fn build_cert(
    out: []u8,
    spec: CertSpec,
    subject_key: *const Ecdsa.KeyPair,
    issuer_key: *const Ecdsa.KeyPair,
) ![]const u8 {
    var tbs_buffer: [1024]u8 = undefined;
    var tbs: Der = .{ .buffer = &tbs_buffer };
    const tbs_start = tbs.begin(0x30);
    tbs.tlv(0xa0, &.{ 0x02, 0x01, 0x02 });
    tbs.tlv(0x02, &.{0x01});
    tbs.tlv(0x30, &[_]u8{ 0x06, 0x08 } ++ x509.oid_ecdsa_with_sha384);
    tbs.name(spec.issuer);
    const validity = tbs.begin(0x30);
    tbs.tlv(0x17, spec.not_before);
    tbs.tlv(0x17, spec.not_after);
    tbs.end(validity);
    tbs.name(spec.subject);
    const spki = tbs.begin(0x30);
    tbs.tlv(0x30, &[_]u8{ 0x06, 0x07 } ++ x509.oid_ec_public_key ++
        [_]u8{ 0x06, 0x05 } ++ x509.oid_secp384r1);
    const point = subject_key.public_key.toUncompressedSec1();
    tbs.tlv(0x03, &[_]u8{0x00} ++ point);
    tbs.end(spki);
    write_extensions(&tbs, spec.ca);
    tbs.end(tbs_start);
    const tbs_bytes = tbs.buffer[0..tbs.position];

    const signature = try issuer_key.sign(tbs_bytes, null);
    var signature_der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const signature_bytes = signature.toDer(&signature_der);
    var cert: Der = .{ .buffer = out };
    const cert_start = cert.begin(0x30);
    cert.raw(tbs_bytes);
    cert.tlv(0x30, &[_]u8{ 0x06, 0x08 } ++ x509.oid_ecdsa_with_sha384);
    const bit_string = cert.begin(0x03);
    cert.raw(&.{0x00});
    cert.raw(signature_bytes);
    cert.end(bit_string);
    cert.end(cert_start);
    return cert.buffer[0..cert.position];
}

fn write_extensions(der: *Der, ca: bool) void {
    const wrapper = der.begin(0xa3);
    const extensions = der.begin(0x30);
    const basic = der.begin(0x30);
    der.tlv(0x06, &.{ 0x55, 0x1d, 0x13 });
    der.tlv(0x01, &.{0xff});
    if (ca) {
        der.tlv(0x04, &.{ 0x30, 0x03, 0x01, 0x01, 0xff });
    } else {
        der.tlv(0x04, &.{ 0x30, 0x00 });
    }
    der.end(basic);
    const usage = der.begin(0x30);
    der.tlv(0x06, &.{ 0x55, 0x1d, 0x0f });
    der.tlv(0x01, &.{0xff});
    // keyCertSign + cRLSign + digitalSignature for CAs; digitalSignature for leaves.
    if (ca) {
        der.tlv(0x04, &.{ 0x03, 0x02, 0x01, 0x86 });
    } else {
        der.tlv(0x04, &.{ 0x03, 0x02, 0x07, 0x80 });
    }
    der.end(usage);
    der.end(extensions);
    der.end(wrapper);
}

pub fn key_pair(seed_byte: u8) !Ecdsa.KeyPair {
    const seed: [Ecdsa.KeyPair.seed_length]u8 = @splat(seed_byte);
    return Ecdsa.KeyPair.generateDeterministic(seed);
}

pub const DocumentSpec = struct {
    timestamp_ms: u64 = 1_700_000_000_000,
    certificate: []const u8,
    cabundle: []const []const u8,
    nonce: ?[]const u8 = null,
    user_data: ?[]const u8 = null,
    public_key: ?[]const u8 = null,
    pcr_fill: u8 = 0x01,
};

pub fn build_document(out: []u8, spec: DocumentSpec) ![]const u8 {
    var writer: cbor.Writer = .{ .buffer = out };
    try writer.head(.map, 9);
    try writer.text_string("module_id");
    try writer.text_string("i-synthetic-enc0");
    try writer.text_string("digest");
    try writer.text_string("SHA384");
    try writer.text_string("timestamp");
    try writer.head(.unsigned, spec.timestamp_ms);
    try writer.text_string("pcrs");
    try writer.head(.map, 3);
    for (0..3) |index| {
        try writer.integer(@intCast(index));
        try writer.byte_string(&@as([48]u8, @splat(spec.pcr_fill)));
    }
    try writer.text_string("certificate");
    try writer.byte_string(spec.certificate);
    try writer.text_string("cabundle");
    try writer.head(.array, spec.cabundle.len);
    for (spec.cabundle) |cert| try writer.byte_string(cert);
    const optional = [_]struct { []const u8, ?[]const u8 }{
        .{ "public_key", spec.public_key },
        .{ "user_data", spec.user_data },
        .{ "nonce", spec.nonce },
    };
    for (optional) |field| {
        try writer.text_string(field[0]);
        if (field[1]) |bytes| try writer.byte_string(bytes) else try writer.simple_null();
    }
    return writer.written();
}

const Sink = struct {
    writer: cbor.Writer,
    pub fn update(sink: *Sink, bytes: []const u8) void {
        sink.writer.raw(bytes) catch unreachable; // Callers size buffers for the document.
    }
};

pub const CoseSpec = struct {
    protected: []const u8 = &.{ 0xa1, 0x01, 0x38, 0x22 },
    tagged: bool = false,
};

/// Sign `payload` with `signer` into a `COSE_Sign1` envelope.
pub fn build_cose(
    out: []u8,
    payload: []const u8,
    signer: *const Ecdsa.KeyPair,
    spec: CoseSpec,
) ![]const u8 {
    const attestation = @import("attestation.zig");
    const cose: attestation.CoseSign1 = .{
        .protected = spec.protected,
        .payload = payload,
        .signature = &.{},
    };
    var structure_buffer: [8192]u8 = undefined;
    var sink: Sink = .{ .writer = .{ .buffer = &structure_buffer } };
    cose.sig_structure_emit(&sink);
    const signature = try signer.sign(sink.writer.written(), null);
    var writer: cbor.Writer = .{ .buffer = out };
    if (spec.tagged) try writer.head(.tag, attestation.cose_sign1_tag);
    try writer.head(.array, 4);
    try writer.byte_string(spec.protected);
    try writer.head(.map, 0);
    try writer.byte_string(payload);
    try writer.byte_string(&signature.toBytes());
    return writer.written();
}

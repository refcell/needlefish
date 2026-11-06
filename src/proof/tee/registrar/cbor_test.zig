//! Tests for the strict `NitroValidator` CBOR walker (base/base `cbor.rs` tests).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const cbor = @import("cbor.zig");
const fuzz = @import("../../../testing/fuzz.zig");

const CborItem = cbor.CborItem;
const NitroCose = cbor.NitroCose;

pub const fixture_attestation = @embedFile("../nitro/testdata/attestation.bin");
const protected_tlv = cbor.nitro_protected_header_tlv;

/// Fixed-capacity byte builder for test envelopes.
const Bytes = struct {
    buffer: [256]u8 = undefined,
    length: usize = 0,

    fn add(bytes: *Bytes, data: []const u8) void {
        assert(bytes.length + data.len <= bytes.buffer.len);
        @memcpy(bytes.buffer[bytes.length..][0..data.len], data);
        bytes.length += data.len;
    }

    fn slice(bytes: *const Bytes) []const u8 {
        assert(bytes.length <= bytes.buffer.len);
        return bytes.buffer[0..bytes.length];
    }
};

/// Minimal definite `COSE_Sign1`: ES384 protected, empty unprotected, short payload.
fn minimal_cose(payload: []const u8, signature: *const [96]u8) Bytes {
    assert(payload.len < 24);
    var out: Bytes = .{};
    out.add(&.{0x84});
    out.add(&protected_tlv);
    out.add(&.{ 0xa0, 0x40 | @as(u8, @intCast(payload.len)) });
    out.add(payload);
    out.add(&.{ 0x58, 96 });
    out.add(signature);
    return out;
}

fn parses(attestation: []const u8) bool {
    var tbs: [512]u8 = undefined;
    _ = NitroCose.parse_sign1(attestation, &tbs) catch return false;
    return true;
}

test "registrar cbor: parse_sign1 accepts fixture and rejects trailing" {
    var tbs: [fixture_attestation.len + 32]u8 = undefined;
    _ = try NitroCose.parse_sign1(fixture_attestation, &tbs);
    var trailing: [fixture_attestation.len + 1]u8 = undefined;
    @memcpy(trailing[0..fixture_attestation.len], fixture_attestation);
    trailing[fixture_attestation.len] = 0;
    try testing.expectError(error.CoseTrailingData, NitroCose.parse_sign1(&trailing, &tbs));
}

test "registrar cbor: parse_sign1 matches NitroValidator envelope" {
    const sig: [96]u8 = @splat(0);
    const good = minimal_cose(&.{0xa0}, &sig);
    try testing.expect(parses(good.slice()));

    // Compact tag 0xD2 is accepted; long-form tag(18) is not.
    var tagged: Bytes = .{};
    tagged.add(&.{0xd2});
    tagged.add(good.slice());
    try testing.expect(parses(tagged.slice()));
    var long_tag: Bytes = .{};
    long_tag.add(&.{ 0xd8, 0x12 });
    long_tag.add(good.slice());
    try testing.expect(!parses(long_tag.slice()));

    // Long-form array(4) header is rejected.
    var long_array: Bytes = .{};
    long_array.add(&.{ 0x98, 0x04 });
    long_array.add(good.slice()[1..]);
    try testing.expect(!parses(long_array.slice()));

    // Non-empty and indefinite unprotected maps are skipped.
    for ([_][]const u8{ &.{ 0xa1, 0x01, 0x01 }, &.{ 0xbf, 0xff } }) |unprotected| {
        var envelope: Bytes = .{};
        envelope.add(&.{0x84});
        envelope.add(&protected_tlv);
        envelope.add(unprotected);
        envelope.add(&.{ 0x41, 0xa0, 0x58, 96 });
        envelope.add(&sig);
        try testing.expect(parses(envelope.slice()));
    }

    // Wrong array length.
    var wrong_len: Bytes = .{};
    wrong_len.add(&.{0x83});
    wrong_len.add(&protected_tlv);
    wrong_len.add(&.{ 0xa0, 0x41, 0xa0 });
    try testing.expect(!parses(wrong_len.slice()));

    // Non-ES384 protected header content.
    var bad_protected: Bytes = .{};
    bad_protected.add(&.{ 0x84, 0x41, 0x00, 0xa0, 0x41, 0xa0, 0x58, 96 });
    bad_protected.add(&sig);
    try testing.expect(!parses(bad_protected.slice()));

    // Unexpected CBOR tag.
    var tagged_wrong: Bytes = .{};
    tagged_wrong.add(&.{ 0xd8, 0x63 });
    tagged_wrong.add(good.slice());
    try testing.expect(!parses(tagged_wrong.slice()));

    // Indefinite-length array is rejected.
    try testing.expect(!parses(&.{ 0x9f, 0xff }));

    // Wrong signature length (1 byte instead of 96).
    var short_sig: Bytes = .{};
    short_sig.add(&.{0x84});
    short_sig.add(&protected_tlv);
    short_sig.add(&.{ 0xa0, 0x41, 0xa0, 0x41, 0x00 });
    try testing.expect(!parses(short_sig.slice()));
}

test "registrar cbor: item rejects truncated header, oversize, deep nesting" {
    try testing.expectError(error.CoseOutOfBounds, CborItem.read(&.{0x18}, 0));
    try testing.expectError(error.CoseOutOfBounds, CborItem.read(&.{ 0x45, 0x00, 0x00 }, 0));

    // Nest array(1) deeper than the depth limit.
    var nested: [cbor.nesting_depth_max + 3]u8 = @splat(0x81);
    nested[nested.len - 1] = 0x00;
    try testing.expectError(error.CoseNestingTooDeep, CborItem.read(&nested, 0));

    // Exactly at the limit is accepted: 64 arrays enclose a uint at depth 64.
    var at_limit: [cbor.nesting_depth_max + 1]u8 = @splat(0x81);
    at_limit[at_limit.len - 1] = 0x00;
    const item = try CborItem.read(&at_limit, 0);
    try testing.expectEqual(at_limit.len, item.end);
}

test "registrar cbor: item rejects impossible container counts" {
    try testing.expectError(error.CoseContainerCount, CborItem.read(&.{0x82}, 0));
    try testing.expectError(error.CoseContainerCount, CborItem.read(&.{ 0xa2, 0x00 }, 0));
}

test "registrar cbor: indefinite map requires a value before break" {
    // {_ 0: BREAK} — the break sits where a value must be.
    try testing.expectError(error.CoseUnexpectedBreak, CborItem.read(&.{ 0xbf, 0x00, 0xff }, 0));
    const item = try CborItem.read(&.{ 0xbf, 0x00, 0x00, 0xff }, 0);
    try testing.expectEqual(@as(usize, 4), item.end);
    try testing.expect(item.indefinite);
}

test "registrar cbor: payload structure rejects pcr and cabundle faults" {
    const validate = NitroCose.validate_payload_structure;
    try testing.expectError(error.CoseTrailingData, validate(&.{ 0xa0, 0x00 }));
    // {"pcrs": {0: h'00', 0: h'00'}}
    try testing.expectError(error.CosePcrDuplicate, validate(&.{
        0xa1, 0x64, 'p', 'c', 'r', 's', 0xa2, 0x00, 0x41, 0x00, 0x00, 0x41, 0x00,
    }));
    // {"pcrs": {0: h'00'}, "pcrs": {0: h'00'}}
    try testing.expectError(error.CoseDuplicateKey, validate(&.{
        0xa2, 0x64, 'p', 'c', 'r', 's',  0xa1, 0x00, 0x41, 0x00,
        0x64, 'p',  'c', 'r', 's', 0xa1, 0x00, 0x41, 0x00,
    }));
    // Repeated unknown keys stay forward-compatible: {"x": null, "x": null}.
    try validate(&.{ 0xa2, 0x61, 'x', 0xf6, 0x61, 'x', 0xf6 });
    // Sparse PCR keys are valid: {"pcrs": {1: h'00'}}.
    try validate(&.{ 0xa1, 0x64, 'p', 'c', 'r', 's', 0xa1, 0x01, 0x41, 0x00 });
    // Indefinite pcrs map with sparse key 8.
    try validate(&.{
        0xa1, 0x64, 'p', 'c', 'r', 's', 0xbf, 0x00, 0x41, 0x00, 0x08, 0x41, 0x00, 0xff,
    });
    // {"cabundle": [h'']}
    try testing.expectError(error.CoseCabundleCertificateLength, validate(&.{
        0xa1, 0x68, 'c', 'a', 'b', 'u', 'n', 'd', 'l', 'e', 0x81, 0x40,
    }));
    // {"cabundle": []}
    try testing.expectError(error.CoseCabundleCount, validate(&.{
        0xa1, 0x68, 'c', 'a', 'b', 'u', 'n', 'd', 'l', 'e', 0x80,
    }));
    // {"cabundle": [_ h'30' ]}
    try validate(&.{ 0xa1, 0x68, 'c', 'a', 'b', 'u', 'n', 'd', 'l', 'e', 0x9f, 0x41, 0x30, 0xff });
}

test "registrar cbor: payload structure accepts fixture payload" {
    var tbs: [fixture_attestation.len + 32]u8 = undefined;
    const cose = try NitroCose.parse_sign1(fixture_attestation, &tbs);
    try NitroCose.validate_payload_structure(cose.payload);
}

test "registrar cbor: sign1_from_tbs round-trips the fixture" {
    var tbs: [fixture_attestation.len + 32]u8 = undefined;
    const cose = try NitroCose.parse_sign1(fixture_attestation, &tbs);
    var envelope: [fixture_attestation.len + 32]u8 = undefined;
    const rebuilt = try NitroCose.sign1_from_tbs(cose.attestation_tbs, cose.signature, &envelope);
    var tbs_again: [fixture_attestation.len + 32]u8 = undefined;
    const again = try NitroCose.parse_sign1(rebuilt, &tbs_again);
    try testing.expectEqualSlices(u8, cose.attestation_tbs, again.attestation_tbs);
    try testing.expectEqualSlices(u8, cose.signature, again.signature);
    try testing.expectError(
        error.CoseInvalidTbs,
        NitroCose.sign1_from_tbs(cose.attestation_tbs[1..], cose.signature, &envelope),
    );
}

/// Property: the walker never panics, every accepted item ends inside the input,
/// and an accepted envelope's TBS holds the payload TLV after the fixed prefix.
fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    const length = smith.slice(&buffer);
    const input = buffer[0..length];
    if (CborItem.read(input, 0)) |item| {
        try testing.expect(item.end <= input.len and item.end > 0);
    } else |_| {}
    NitroCose.validate_payload_structure(input) catch {};
    var tbs: [1024 + cbor.tbs_prefix_size]u8 = undefined;
    const cose = NitroCose.parse_sign1(input, &tbs) catch return;
    try testing.expectEqual(@as(usize, 96), cose.signature.len);
    try testing.expect(cose.attestation_tbs.len > cbor.tbs_prefix_size);
}

test "registrar cbor: fuzz parse" {
    try fuzz.run({}, fuzz_parse, .{ .iterations = 1024 });
}

/// Property: corrupting the real fixture never crashes the strict parsers.
fn fuzz_mutate(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [fixture_attestation.len]u8 = fixture_attestation.*;
    var flips: u32 = 0;
    while (flips < 4 and !smith.eosWeightedSimple(1, 1)) : (flips += 1) {
        const index = smith.valueRangeLessThan(u32, 0, buffer.len);
        buffer[index] ^= smith.valueRangeAtMost(u8, 1, 255);
    }
    var tbs: [fixture_attestation.len + 32]u8 = undefined;
    const cose = NitroCose.parse_sign1(&buffer, &tbs) catch return;
    NitroCose.validate_payload_structure(cose.payload) catch return;
    try testing.expect(cose.payload.len < buffer.len);
}

test "registrar cbor: fuzz mutated fixture" {
    try fuzz.run({}, fuzz_mutate, .{ .iterations = 256 });
}

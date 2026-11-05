//! Ethereum Node Records (EIP-778) with the `v4` identity scheme, plus the OP Stack
//! `opstack` key (base/base `peers/src/enr.rs`).
//!
//! A record is `rlp([signature, seq, k1, v1, k2, v2, ...])`, at most 300 bytes, keys
//! sorted and unique. The `v4` signature is a secp256k1 `r || s` over
//! `keccak256(rlp([seq, k1, v1, ...]))`; the node id is `keccak256(x || y)` of the
//! uncompressed public key. `Record` keeps the raw bytes plus offsets of every pair, so
//! a decoded record is a fixed-size value with no allocation and no pointers.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../../common/rlp/root.zig");
const secp256k1 = @import("secp256k1.zig");
const varint = @import("varint.zig");

pub const size_max = 300;
/// Pairs per record. 300 bytes fit at most ~100 one-byte pairs; real records carry < 12.
pub const pairs_max = 32;
pub const text_prefix = "enr:";
pub const text_length_max = text_prefix.len + (size_max * 4 + 2) / 3;
pub const opstack_key = "opstack";

pub const NodeId = [32]u8;

pub const Error = error{
    TooLarge,
    TooManyPairs,
    Malformed,
    KeysNotSorted,
    UnsupportedIdentityScheme,
    MissingPublicKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidText,
};

/// Offsets of one key/value pair inside `Record.bytes`. The value is a raw RLP item.
pub const Pair = struct {
    key_offset: u16,
    key_length: u16,
    value_offset: u16,
    value_length: u16,
};

/// The `opstack` ENR value: chain id and version as two unsigned varints.
pub const OpStack = struct {
    chain_id: u64,
    version: u64 = 0,
};

pub const Record = struct {
    bytes: [size_max]u8,
    length: u16,
    sequence: u64,
    signature: secp256k1.Signature,
    public_key: secp256k1.PublicKey,
    pairs: [pairs_max]Pair,
    pairs_count: u8,

    pub fn raw(record: *const Record) []const u8 {
        assert(record.length <= size_max);
        return record.bytes[0..record.length];
    }

    /// Raw RLP value item for `key`, or null.
    pub fn get(record: *const Record, key: []const u8) ?[]const u8 {
        assert(record.pairs_count <= pairs_max);
        for (record.pairs[0..record.pairs_count]) |pair| {
            const pair_key = record.bytes[pair.key_offset..][0..pair.key_length];
            if (std.mem.eql(u8, pair_key, key)) {
                return record.bytes[pair.value_offset..][0..pair.value_length];
            }
        }
        return null;
    }

    pub fn node_id(record: *const Record) NodeId {
        return node_id_from_public_key(record.public_key);
    }

    pub fn ip4(record: *const Record) ?[4]u8 {
        return record.get_fixed(4, "ip");
    }

    pub fn ip6(record: *const Record) ?[16]u8 {
        return record.get_fixed(16, "ip6");
    }

    pub fn tcp(record: *const Record) ?u16 {
        return record.get_port("tcp");
    }

    pub fn udp(record: *const Record) ?u16 {
        return record.get_port("udp");
    }

    pub fn tcp6(record: *const Record) ?u16 {
        return record.get_port("tcp6");
    }

    pub fn udp6(record: *const Record) ?u16 {
        return record.get_port("udp6");
    }

    /// The `opstack` value, or null when absent or malformed.
    pub fn opstack(record: *const Record) ?OpStack {
        const item = record.get(opstack_key) orelse return null;
        return decode_opstack(item) catch null;
    }

    fn get_fixed(record: *const Record, comptime size: usize, key: []const u8) ?[size]u8 {
        const item = record.get(key) orelse return null;
        var decoder = rlp.Decoder.init(item);
        const value = decoder.fixed(size) catch return null;
        decoder.finish() catch return null;
        return value;
    }

    fn get_port(record: *const Record, key: []const u8) ?u16 {
        const item = record.get(key) orelse return null;
        var decoder = rlp.Decoder.init(item);
        const value = decoder.int(u16) catch return null;
        decoder.finish() catch return null;
        return value;
    }
};

pub fn node_id_from_public_key(key: secp256k1.PublicKey) NodeId {
    // Records only hold keys that decompressed during decode or came from a secret key.
    const uncompressed = secp256k1.decompress(key) catch unreachable;
    return secp256k1.keccak256(&.{uncompressed[1..]});
}

/// Decodes the RLP value item of an `opstack` key. Trailing bytes after the version are
/// ignored, matching base/base.
pub fn decode_opstack(item: []const u8) Error!OpStack {
    var decoder = rlp.Decoder.init(item);
    const payload = decoder.bytes() catch return error.Malformed;
    decoder.finish() catch return error.Malformed;
    const chain_id = varint.decode(payload) catch return error.Malformed;
    const version = varint.decode(payload[chain_id.length..]) catch return error.Malformed;
    return .{ .chain_id = chain_id.value, .version = version.value };
}

/// Encodes an `opstack` value as an RLP string item into `output`.
pub fn encode_opstack(output: []u8, value: OpStack) []u8 {
    var payload: [2 * varint.length_max]u8 = undefined;
    const chain_id = varint.encode(&payload, value.chain_id);
    const version = varint.encode(payload[chain_id.len..], value.version);
    var encoder = rlp.Encoder.init(output);
    encoder.bytes(payload[0 .. chain_id.len + version.len]);
    return encoder.written();
}

/// Decodes and verifies a binary record.
pub fn decode(bytes: []const u8) Error!Record {
    if (bytes.len > size_max) return error.TooLarge;
    var record: Record = undefined;
    @memcpy(record.bytes[0..bytes.len], bytes);
    record.length = @intCast(bytes.len);
    const owned = record.bytes[0..bytes.len];

    var outer = rlp.Decoder.init(owned);
    var items = outer.list() catch return error.Malformed;
    outer.finish() catch return error.Malformed;
    const signature = items.bytes() catch return error.Malformed;
    const content_offset = owned.len - items.rest().len;
    record.sequence = items.int(u64) catch return error.Malformed;
    try decode_pairs(&record, owned, &items);

    const scheme = record.get("id") orelse return error.UnsupportedIdentityScheme;
    if (!std.mem.eql(u8, scheme, "\x82v4")) return error.UnsupportedIdentityScheme;
    if (signature.len != secp256k1.signature_length) return error.InvalidSignature;
    record.signature = signature[0..secp256k1.signature_length].*;
    const key_item = record.get("secp256k1") orelse return error.MissingPublicKey;
    var key_decoder = rlp.Decoder.init(key_item);
    const key = key_decoder.fixed(secp256k1.compressed_length) catch
        return error.InvalidPublicKey;
    record.public_key = secp256k1.compress(&key) catch return error.InvalidPublicKey;

    const digest = content_digest(owned[content_offset..]);
    if (!secp256k1.verify_digest(record.public_key, digest, record.signature)) {
        return error.InvalidSignature;
    }
    assert(record.pairs_count >= 2);
    return record;
}

fn decode_pairs(record: *Record, owned: []const u8, items: *rlp.Decoder) Error!void {
    record.pairs_count = 0;
    var previous_key: []const u8 = "";
    while (!items.is_empty()) {
        if (record.pairs_count == pairs_max) return error.TooManyPairs;
        const key = items.bytes() catch return error.Malformed;
        const value = items.raw() catch return error.Malformed;
        if (record.pairs_count > 0 and !std.mem.lessThan(u8, previous_key, key)) {
            return error.KeysNotSorted;
        }
        previous_key = key;
        record.pairs[record.pairs_count] = .{
            .key_offset = @intCast(key.ptr - owned.ptr),
            .key_length = @intCast(key.len),
            .value_offset = @intCast(value.ptr - owned.ptr),
            .value_length = @intCast(value.len),
        };
        record.pairs_count += 1;
    }
    assert(record.pairs_count <= pairs_max);
}

/// `keccak256(rlp([seq, k, v, ...]))` given the concatenated content items.
fn content_digest(content_items: []const u8) secp256k1.Digest {
    var header_buffer: [9]u8 = undefined;
    var header = rlp.Encoder.init(&header_buffer);
    header.list_header(content_items.len);
    return secp256k1.keccak256(&.{ header.written(), content_items });
}

/// Decodes `enr:<base64url>` text.
pub fn decode_text(text: []const u8) Error!Record {
    if (!std.mem.startsWith(u8, text, text_prefix)) return error.InvalidText;
    const body = text[text_prefix.len..];
    const codec = std.base64.url_safe_no_pad.Decoder;
    const length = codec.calcSizeForSlice(body) catch return error.InvalidText;
    if (length > size_max) return error.TooLarge;
    var bytes: [size_max]u8 = undefined;
    codec.decode(bytes[0..length], body) catch return error.InvalidText;
    return decode(bytes[0..length]);
}

/// Writes `enr:<base64url>` text into `output` (at least `text_length_max` bytes).
pub fn encode_text(output: []u8, record: *const Record) []const u8 {
    assert(output.len >= text_length_max);
    @memcpy(output[0..text_prefix.len], text_prefix);
    const codec = std.base64.url_safe_no_pad.Encoder;
    const body = codec.encode(output[text_prefix.len..], record.raw());
    return output[0 .. text_prefix.len + body.len];
}

/// Fields of a locally built record. Keys are emitted in sorted order.
pub const Fields = struct {
    sequence: u64 = 1,
    ip4: ?[4]u8 = null,
    ip6: ?[16]u8 = null,
    opstack: ?OpStack = null,
    tcp: ?u16 = null,
    tcp6: ?u16 = null,
    udp: ?u16 = null,
    udp6: ?u16 = null,
};

/// Builds and signs a `v4` record.
pub fn build(secret: secp256k1.SecretKey, fields: Fields) (Error || secp256k1.Error)!Record {
    const public_key = try secp256k1.public_key(secret);
    var content_buffer: [size_max]u8 = undefined;
    const content = encode_content(&content_buffer, public_key, fields);
    const signature = try secp256k1.sign_digest(secret, content_digest(content));

    const payload_length = rlp.bytes_length(&signature) + content.len;
    if (rlp.list_length(payload_length) > size_max) return error.TooLarge;
    var record_buffer: [size_max]u8 = undefined;
    var encoder = rlp.Encoder.init(&record_buffer);
    encoder.list_header(payload_length);
    encoder.bytes(&signature);
    encoder.raw(content);
    const record = try decode(encoder.written());
    assert(record.sequence == fields.sequence);
    assert(std.mem.eql(u8, &record.public_key, &public_key));
    return record;
}

/// Writes the content items (without the list header). The largest possible content
/// (all fields set, u64 values) is ~150 bytes, so `size_max` always fits.
fn encode_content(
    output: *[size_max]u8,
    public_key: secp256k1.PublicKey,
    fields: Fields,
) []const u8 {
    var encoder = rlp.Encoder.init(output);
    encoder.int(fields.sequence);
    encoder.bytes("id");
    encoder.bytes("v4");
    if (fields.ip4) |value| encode_pair(&encoder, "ip", &value);
    if (fields.ip6) |value| encode_pair(&encoder, "ip6", &value);
    if (fields.opstack) |value| {
        encoder.bytes(opstack_key);
        var item: [2 * varint.length_max + 1]u8 = undefined;
        encoder.raw(encode_opstack(&item, value));
    }
    encode_pair(&encoder, "secp256k1", &public_key);
    if (fields.tcp) |value| encode_port(&encoder, "tcp", value);
    if (fields.tcp6) |value| encode_port(&encoder, "tcp6", value);
    if (fields.udp) |value| encode_port(&encoder, "udp", value);
    if (fields.udp6) |value| encode_port(&encoder, "udp6", value);
    assert(encoder.written().len <= 160);
    return encoder.written();
}

fn encode_pair(encoder: *rlp.Encoder, key: []const u8, value: []const u8) void {
    encoder.bytes(key);
    encoder.bytes(value);
}

fn encode_port(encoder: *rlp.Encoder, key: []const u8, value: u16) void {
    encoder.bytes(key);
    encoder.int(value);
}

/// Result of checking a discovered record against the local chain (base/base
/// `EnrValidation`).
pub const Validation = enum { valid, missing_key, malformed, invalid_version, invalid_chain_id };

pub fn validate_chain(record: *const Record, chain_id: u64) Validation {
    const item = record.get(opstack_key) orelse return .missing_key;
    const value = decode_opstack(item) catch return .malformed;
    if (value.version != 0) return .invalid_version;
    if (value.chain_id != chain_id) return .invalid_chain_id;
    return .valid;
}

const hex = @import("../../../common/primitives/hex.zig");
const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

/// EIP-778 example record.
const eip778_text = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOon" ++
    "rkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_ox" ++
    "Vtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";

test "enr: EIP-778 vector" {
    const record = try decode_text(eip778_text);
    try std.testing.expectEqual(@as(u64, 1), record.sequence);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, record.ip4().?);
    try std.testing.expectEqual(@as(u16, 30303), record.udp().?);
    try std.testing.expectEqual(@as(?u16, null), record.tcp());
    try std.testing.expectEqual(
        try hex.decode_array(33, "03ca634cae0d49acb401d8a4c6b6fe8c55" ++
            "b70d115bf400769cc1400f3258cd3138"),
        record.public_key,
    );
    try std.testing.expectEqual(
        try hex.decode_array(32, "a448f24c6d18e575453db13171562b71" ++
            "999873db5b286df957af199ec94617f7"),
        record.node_id(),
    );
    var text: [text_length_max]u8 = undefined;
    try std.testing.expectEqualStrings(eip778_text, encode_text(&text, &record));
}

test "enr: tampered record fails verification" {
    const valid = try decode_text(eip778_text);
    var bytes = valid.bytes;
    // Flip the udp port's last byte.
    bytes[valid.length - 1] ^= 1;
    try std.testing.expectError(error.InvalidSignature, decode(bytes[0..valid.length]));
}

test "enr: opstack value encoding" {
    var buffer: [32]u8 = undefined;
    const mainnet = encode_opstack(&buffer, .{ .chain_id = 8453 });
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0x85, 0x42, 0x00 }, mainnet);
    const decoded = try decode_opstack(mainnet);
    try std.testing.expectEqual(@as(u64, 8453), decoded.chain_id);
    try std.testing.expectEqual(@as(u64, 0), decoded.version);
}

test "enr: build, sign, decode, validate chain" {
    var secret: secp256k1.SecretKey = @splat(0x42);
    secret[0] = 0x01;
    const record = try build(secret, .{
        .sequence = 7,
        .ip4 = .{ 10, 0, 0, 1 },
        .tcp = 9222,
        .udp = 9223,
        .opstack = .{ .chain_id = 8453 },
    });
    try std.testing.expectEqual(@as(u64, 7), record.sequence);
    try std.testing.expectEqual(@as(u16, 9222), record.tcp().?);
    try std.testing.expectEqual(@as(u16, 9223), record.udp().?);
    try std.testing.expectEqual(Validation.valid, validate_chain(&record, 8453));
    try std.testing.expectEqual(Validation.invalid_chain_id, validate_chain(&record, 84532));
    var text: [text_length_max]u8 = undefined;
    const round = try decode_text(encode_text(&text, &record));
    try std.testing.expectEqualSlices(u8, record.raw(), round.raw());

    const versioned = try build(secret, .{ .opstack = .{ .chain_id = 8453, .version = 1 } });
    try std.testing.expectEqual(Validation.invalid_version, validate_chain(&versioned, 8453));
    const bare = try build(secret, .{});
    try std.testing.expectEqual(Validation.missing_key, validate_chain(&bare, 8453));
}

test "enr: rejects malformed structure" {
    try std.testing.expectError(error.Malformed, decode(&.{}));
    try std.testing.expectError(error.Malformed, decode(&.{0xc0}));
    const oversized: [size_max + 1]u8 = @splat(0);
    try std.testing.expectError(error.TooLarge, decode(&oversized));
    try std.testing.expectError(error.InvalidText, decode_text("enx:abc"));
    try std.testing.expectError(error.InvalidText, decode_text("enr:***"));
}

test "enr: seeded build round trip" {
    var prng = Prng.init(0x656e72);
    for (0..32) |_| {
        var secret: secp256k1.SecretKey = undefined;
        prng.fill(&secret);
        secp256k1.validate_secret_key(secret) catch continue;
        var fields: Fields = .{ .sequence = prng.int(u64) };
        if (prng.chance(1, 2)) fields.ip4 = @bitCast(prng.int(u32));
        if (prng.chance(1, 2)) fields.ip6 = @bitCast(prng.int(u128));
        if (prng.chance(1, 2)) fields.tcp = prng.int(u16);
        if (prng.chance(1, 2)) fields.udp6 = prng.int(u16);
        if (prng.chance(1, 2)) fields.opstack = .{ .chain_id = prng.int(u64) };
        const record = try build(secret, fields);
        try std.testing.expectEqual(fields.tcp, record.tcp());
        try std.testing.expectEqual(fields.udp6, record.udp6());
        try std.testing.expectEqual(fields.ip6, record.ip6());
        if (fields.opstack) |value| {
            try std.testing.expectEqual(value.chain_id, record.opstack().?.chain_id);
        }
    }
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    const record = decode(input) catch return;
    try std.testing.expectEqualSlices(u8, input, record.raw());
    var text: [text_length_max]u8 = undefined;
    const round = try decode_text(encode_text(&text, &record));
    try std.testing.expectEqualSlices(u8, input, round.raw());
}

fn fuzz_mutate(_: void, smith: *std.testing.Smith) anyerror!void {
    const valid = try decode_text(eip778_text);
    var bytes = valid.bytes;
    const length = valid.length;
    const flips = smith.value(u8) % 4 + 1;
    for (0..flips) |_| {
        const index = smith.value(u16) % length;
        bytes[index] ^= smith.value(u8) | 1;
    }
    // Any accepted mutation must still be a valid, self-consistent record.
    const record = decode(bytes[0..length]) catch return;
    try std.testing.expectEqualSlices(u8, bytes[0..length], record.raw());
}

test "enr: fuzz decode" {
    const valid = try decode_text(eip778_text);
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 320, .corpus = &.{valid.raw()} });
}

test "enr: fuzz mutated vector" {
    try fuzz.run({}, fuzz_mutate, .{ .iterations = 128 });
}

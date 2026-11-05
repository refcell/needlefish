//! OP Stack unsafe-block gossip messages: topics, gossipsub message ids, the signed
//! envelope codec, and the unsafe-block-signer signature. Mirrors base/base
//! `crates/consensus/gossip` (`handler.rs`, `config.rs`) and `NetworkPayloadEnvelope`.
//!
//!   topic        `/optimism/<chain_id>/<version - 1>/blocks`
//!   message      snappy(signature(65) || payload_bytes)
//!   payload      v1/v2: `ExecutionPayload` SSZ; v3/v4: `parent_beacon_block_root(32) || SSZ`
//!   signature    `r(32) || s(32) || v(1)`; v is the y parity, written as 0/1
//!   signing hash keccak256(domain(32 zero bytes) || chain_id(32 BE) || keccak256(payload_bytes))
//!   message id   sha256(domain(4) || len(topic) as u64 LE || topic || data)[0..20]
//!
//! The message id binds the topic like base/base and op-node (the older spec text omits
//! it). `domain = 01000000` with the decompressed message when the snappy preamble
//! declares at most 10 MiB and decompression succeeds, else `00000000` with the raw bytes.
//!
//! Signature parsing mirrors alloy `Signature::from_raw`: v may be 0/1, 27/28, or any
//! EIP-155 style value >= 35. Recovery accepts high-s signatures (alloy normalizes s and
//! flips the parity, which recovers the same key); r and s must lie in [1, n).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../../common/primitives/root.zig");
const keccak = @import("../../../common/crypto/keccak.zig");
const sha256 = @import("../../../common/crypto/sha256.zig");
const secp256k1 = @import("../../../common/crypto/secp256k1/root.zig");
const rollup_config = @import("../../protocol/rollup_config.zig");
const snappy = @import("snappy.zig");
const ssz = @import("ssz_payload.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const RollupConfig = rollup_config.RollupConfig;

pub const Version = ssz.Version;
pub const ExecutionPayload = ssz.ExecutionPayload;

pub const signature_length = 65;
pub const message_id_length = 20;
pub const MessageId = [message_id_length]u8;

/// Longest topic: `/optimism/` + 20 decimal digits of a u64 + `/0/blocks`.
pub const topic_length_max = "/optimism/".len + 20 + "/0/blocks".len;

/// Maximum gossip block age in seconds; also the topic retirement grace period.
pub const block_age_max_seconds: u64 = 60;

pub const domain_valid_snappy = [4]u8{ 1, 0, 0, 0 };
pub const domain_invalid_snappy = [4]u8{ 0, 0, 0, 0 };

/// Smallest decompressed message: signature plus at least one payload byte (v1/v2), or
/// signature, beacon root, and one payload byte (v3/v4). Matches base/base.
pub fn decompressed_length_min(version: Version) u32 {
    const length: u32 = if (has_parent_beacon_root(version)) 98 else 66;
    assert(length > signature_length);
    return length;
}

pub fn has_parent_beacon_root(version: Version) bool {
    return @backingInt(version) >= @backingInt(Version.v3);
}

/// Writes the topic for `version` on `chain_id` into `buffer`.
pub fn topic(buffer: *[topic_length_max]u8, chain_id: u64, version: Version) []const u8 {
    const index = @backingInt(version) - 1;
    assert(index <= 3);
    const text = std.fmt.bufPrint(buffer, "/optimism/{d}/{d}/blocks", .{ chain_id, index }) catch
        unreachable; // Proof: topic_length_max covers the longest u64.
    assert(text.len <= topic_length_max);
    return text;
}

/// The block version a topic carries on `chain_id`, or null for any other topic.
pub fn topic_version(chain_id: u64, topic_text: []const u8) ?Version {
    if (topic_text.len > topic_length_max) return null;
    for ([_]Version{ .v1, .v2, .v3, .v4 }) |version| {
        var buffer: [topic_length_max]u8 = undefined;
        if (std.mem.eql(u8, topic(&buffer, chain_id, version), topic_text)) return version;
    }
    return null;
}

/// The topic version to publish a block with `timestamp` on (base/base `topic`).
pub fn version_at(config: *const RollupConfig, timestamp: u64) Version {
    const version: Version = if (config.is_feature_active(.gossip_payload_v4, timestamp))
        .v4
    else if (config.is_feature_active(.gossip_payload_v3, timestamp))
        .v3
    else if (config.is_feature_active(.gossip_payload_v2, timestamp))
        .v2
    else
        .v1;
    assert(@backingInt(version) >= 1);
    return version;
}

/// True once `version` can no longer carry a block inside the accepted timestamp window at
/// local time `now_seconds` (base/base `topics_at`). Future topics are never retired.
pub fn is_topic_retired(config: *const RollupConfig, version: Version, now_seconds: u64) bool {
    const oldest = version_at(config, now_seconds -| block_age_max_seconds);
    assert(@backingInt(oldest) <= @backingInt(version_at(config, now_seconds)));
    return @backingInt(version) < @backingInt(oldest);
}

fn message_id_hash(domain: *const [4]u8, topic_text: []const u8, data: []const u8) MessageId {
    var hasher = sha256.Hasher.init();
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, topic_text.len, .little);
    hasher.update(domain);
    hasher.update(&length);
    hasher.update(topic_text);
    hasher.update(data);
    const digest = hasher.final();
    assert(digest.len >= message_id_length);
    return digest[0..message_id_length].*;
}

/// Gossipsub message id of `data` received on `topic_text`. `scratch` holds the
/// decompressed message and must fit the 10 MiB gossip cap.
pub fn message_id(topic_text: []const u8, data: []const u8, scratch: []u8) MessageId {
    assert(scratch.len >= snappy.gossip_size_max);
    const header = snappy.decode_header(data) catch
        return message_id_hash(&domain_invalid_snappy, topic_text, data);
    if (header.decoded_length > snappy.gossip_size_max) {
        return message_id_hash(&domain_invalid_snappy, topic_text, data);
    }
    const decoded = snappy.decompress(data, scratch, snappy.gossip_size_max) catch
        return message_id_hash(&domain_invalid_snappy, topic_text, data);
    assert(decoded.len == header.decoded_length);
    return message_id_hash(&domain_valid_snappy, topic_text, decoded);
}

/// y parity of a raw signature `v` byte, or null when alloy would reject it.
pub fn parse_v(v: u8) ?u1 {
    const parity: u1 = switch (v) {
        0, 1 => @intCast(v),
        27, 28 => @intCast(v - 27),
        35...255 => @intFromBool(v % 2 == 0),
        else => return null,
    };
    assert(v != 2 and v != 34);
    return parity;
}

/// A decoded gossip message. Slices borrow the decompression buffer.
pub const Envelope = struct {
    version: Version,
    signature: [signature_length]u8,
    y_parity: u1,
    /// Present exactly for v3 and v4.
    parent_beacon_block_root: ?B256,
    payload: ExecutionPayload,
    /// keccak256 of the signed payload bytes (beacon root included for v3/v4).
    payload_hash: B256,
};

pub const DecodeError = snappy.Error || ssz.Error || error{
    /// The decompressed message is shorter than `decompressed_length_min`.
    InvalidLength,
    /// The signature `v` byte is not a recognized parity encoding.
    InvalidSignature,
};

/// Decodes a gossip message for `version`, decompressing into `scratch`.
pub fn decode(version: Version, data: []const u8, scratch: []u8) DecodeError!Envelope {
    assert(scratch.len > 0);
    const decompressed = try snappy.decompress(data, scratch, snappy.gossip_size_max);
    assert(decompressed.len <= snappy.gossip_size_max);
    return decode_decompressed(version, decompressed);
}

/// Decodes an already decompressed message. The result borrows `bytes`.
pub fn decode_decompressed(version: Version, bytes: []const u8) DecodeError!Envelope {
    if (bytes.len < decompressed_length_min(version)) return error.InvalidLength;
    const y_parity = parse_v(bytes[64]) orelse return error.InvalidSignature;
    const signed = bytes[signature_length..];
    var parent_beacon_block_root: ?B256 = null;
    var ssz_bytes = signed;
    if (has_parent_beacon_root(version)) {
        parent_beacon_block_root = .{ .bytes = signed[0..32].* };
        ssz_bytes = signed[32..];
    }
    const payload = try ssz.decode(version, ssz_bytes);
    assert(payload.version == version);
    assert(ssz_bytes.len > 0);
    return .{
        .version = version,
        .signature = bytes[0..signature_length].*,
        .y_parity = y_parity,
        .parent_beacon_block_root = parent_beacon_block_root,
        .payload = payload,
        .payload_hash = .{ .bytes = keccak.keccak256(signed) },
    };
}

/// keccak256(32 zero bytes || chain_id as 32 BE bytes || payload_hash).
pub fn signing_hash(chain_id: u64, payload_hash: B256) B256 {
    var preimage: [96]u8 = @splat(0);
    std.mem.writeInt(u64, preimage[56..64], chain_id, .big);
    preimage[64..96].* = payload_hash.bytes;
    assert(std.mem.allEqual(u8, preimage[0..56], 0));
    const digest = keccak.keccak256(&preimage);
    assert(digest.len == 32);
    return .{ .bytes = digest };
}

/// Address that signed `envelope` for `chain_id`, or null when recovery fails.
pub fn recover_signer(envelope: *const Envelope, chain_id: u64) ?Address {
    const hash = signing_hash(chain_id, envelope.payload_hash);
    const r = envelope.signature[0..32].*;
    const s = envelope.signature[32..64].*;
    assert(parse_v(envelope.signature[64]) == envelope.y_parity);
    const signer = secp256k1.ecrecover_address(hash.bytes, envelope.y_parity, r, s) orelse
        return null;
    return .{ .bytes = signer };
}

pub const EncodeError = error{
    /// v3/v4 need a parent beacon block root; v1/v2 must not carry one.
    ParentBeaconRootMismatch,
    /// The secret key is zero or not below the group order.
    InvalidSecretKey,
    /// The nonce point's x overflowed the group order (probability below 2^-127): the
    /// signature cannot be expressed with a parity-only `v`.
    UnrecoverableSignature,
};

/// Bytes `encode_signed` needs in `scratch` for `payload`.
pub fn signed_length(payload: ExecutionPayload) u64 {
    const root_length: u64 = if (has_parent_beacon_root(payload.version)) 32 else 0;
    const length = signature_length + root_length + ssz.encoded_length(payload);
    assert(length >= decompressed_length_min(payload.version));
    return length;
}

/// Builds `signature || payload_bytes` for `payload` in `scratch`, signed for `chain_id`
/// with `secret_key`, and snappy-compresses it into `out` (at least
/// `snappy.max_compressed_length(signed_length(payload))` bytes).
pub fn encode_signed(
    chain_id: u64,
    secret_key: [32]u8,
    parent_beacon_block_root: ?B256,
    payload: ExecutionPayload,
    scratch: []u8,
    compressor: *snappy.Compressor,
    out: []u8,
) EncodeError![]u8 {
    if (has_parent_beacon_root(payload.version) != (parent_beacon_block_root != null)) {
        return error.ParentBeaconRootMismatch;
    }
    const length: usize = @intCast(signed_length(payload));
    assert(scratch.len >= length);
    var position: usize = signature_length;
    if (parent_beacon_block_root) |root| {
        scratch[position..][0..32].* = root.bytes;
        position += 32;
    }
    position += ssz.encode(payload, scratch[position..]).len;
    assert(position == length);
    const payload_hash: B256 = .{ .bytes = keccak.keccak256(scratch[signature_length..length]) };
    const hash = signing_hash(chain_id, payload_hash);
    const signature = secp256k1.sign(secret_key, hash.bytes) catch return error.InvalidSecretKey;
    if (signature.recovery_id & 2 != 0) return error.UnrecoverableSignature;
    scratch[0..32].* = signature.r;
    scratch[32..64].* = signature.s;
    scratch[64] = @intCast(signature.recovery_id & 1);
    return compressor.compress(scratch[0..length], out);
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");
const vectors = @import("vectors.zig");
const peers_secp256k1 = @import("../peers/secp256k1.zig");

/// Shared decompression buffer at the full gossip cap, for `message_id` in tests.
var test_scratch: [snappy.gossip_size_max]u8 = undefined;

test "block: topics per version and chain" {
    var buffer: [topic_length_max]u8 = undefined;
    try testing.expectEqualStrings("/optimism/8453/0/blocks", topic(&buffer, 8453, .v1));
    try testing.expectEqualStrings("/optimism/8453/3/blocks", topic(&buffer, 8453, .v4));
    const longest = topic(&buffer, std.math.maxInt(u64), .v2);
    try testing.expectEqual(topic_length_max, longest.len);
    try testing.expectEqual(Version.v3, topic_version(84532, "/optimism/84532/2/blocks").?);
    try testing.expectEqual(@as(?Version, null), topic_version(8453, "/optimism/84532/2/blocks"));
    try testing.expectEqual(@as(?Version, null), topic_version(8453, "/optimism/8453/4/blocks"));
    try testing.expectEqual(@as(?Version, null), topic_version(8453, ""));
}

test "block: topic version follows forks and retires after the age window" {
    var config: RollupConfig = .{};
    config.upgrades.set(.canyon, 100);
    config.upgrades.set(.ecotone, 200);
    config.upgrades.set(.isthmus, 300);
    try testing.expectEqual(Version.v1, version_at(&config, 99));
    try testing.expectEqual(Version.v2, version_at(&config, 100));
    try testing.expectEqual(Version.v3, version_at(&config, 299));
    try testing.expectEqual(Version.v4, version_at(&config, 300));
    // At fork + 59 a block from just before the fork is still acceptable.
    try testing.expect(!is_topic_retired(&config, .v1, 159));
    try testing.expect(is_topic_retired(&config, .v1, 160));
    try testing.expect(!is_topic_retired(&config, .v2, 259));
    try testing.expect(is_topic_retired(&config, .v2, 260));
    try testing.expect(is_topic_retired(&config, .v3, 360));
    // Future topics stay subscribed.
    try testing.expect(!is_topic_retired(&config, .v4, 0));
}

test "block: message id matches the base/base golden vector" {
    var compressor: snappy.Compressor = .{};
    var compressed: [64]u8 = undefined;
    const data = compressor.compress(&.{ 1, 2, 3, 4, 5 }, &compressed);
    const expected = [_]u8{
        0xad, 0xbe, 0x54, 0x7b, 0x27, 0xf4, 0x12, 0x94, 0xa0, 0x8a,
        0x09, 0x21, 0x0a, 0x5e, 0x85, 0x31, 0xe8, 0x3c, 0xdc, 0x16,
    };
    try testing.expectEqualSlices(u8, &expected, &message_id("test", data, &test_scratch));
    const v3 = message_id("/optimism/8453/2/blocks", data, &test_scratch);
    const v4 = message_id("/optimism/8453/3/blocks", data, &test_scratch);
    try testing.expect(!std.mem.eql(u8, &v3, &v4));
}

test "block: message id of invalid snappy hashes the raw bytes" {
    const raw = [_]u8{ 1, 2, 3, 4, 5 };
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    sha.update(&domain_invalid_snappy);
    sha.update(&[_]u8{ 4, 0, 0, 0, 0, 0, 0, 0 });
    sha.update("test");
    sha.update(&raw);
    const digest = sha.finalResult();
    try testing.expectEqualSlices(u8, digest[0..20], &message_id("test", &raw, &test_scratch));
    // A preamble declaring more than 10 MiB is never decompressed.
    const bomb = [_]u8{ 0x81, 0x80, 0x80, 0x05, 0x00 };
    const expected = message_id_hash(&domain_invalid_snappy, "t", &bomb);
    try testing.expectEqualSlices(u8, &expected, &message_id("t", &bomb, &test_scratch));
}

test "block: signing hash matches the base/base vector" {
    const inner: [32]u8 = @splat(0x99);
    const payload_hash: B256 = .{ .bytes = keccak.keccak256(&inner) };
    const expected = B256.comptime_hex(
        "44a0e2b1aba1aae1771eddae1dcd2ad18a8cdac8891517153f03253e49d3f206",
    );
    try testing.expect(signing_hash(10, payload_hash).eql(expected));
}

test "block: v byte normalization matches alloy" {
    try testing.expectEqual(@as(?u1, 0), parse_v(0));
    try testing.expectEqual(@as(?u1, 1), parse_v(1));
    try testing.expectEqual(@as(?u1, 0), parse_v(27));
    try testing.expectEqual(@as(?u1, 1), parse_v(28));
    try testing.expectEqual(@as(?u1, 0), parse_v(35));
    try testing.expectEqual(@as(?u1, 1), parse_v(36));
    try testing.expectEqual(@as(?u1, 0), parse_v(255));
    for ([_]u8{ 2, 3, 26, 29, 34 }) |v| try testing.expectEqual(@as(?u1, null), parse_v(v));
}

test "block: decodes the base/base golden messages" {
    const cases = [_]struct { Version, []const u8, u64 }{
        .{ .v1, vectors.message_v1, 1725271882 },
        .{ .v2, vectors.message_v2, 1708427627 },
        .{ .v3, vectors.message_v3, 1708427461 },
        .{ .v4, vectors.message_v4, 1741842007 },
    };
    var compressor: snappy.Compressor = .{};
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        const data = vectors.decode(&buffer, case[1]);
        var scratch: [4096]u8 = undefined;
        const envelope = try decode(case[0], data, &scratch);
        try testing.expectEqual(case[2], envelope.payload.timestamp);
        const has_root = envelope.parent_beacon_block_root != null;
        try testing.expectEqual(has_parent_beacon_root(case[0]), has_root);
        // Our compressor may pick different copies than `snap`; the content must match.
        const decompressed = try snappy.decompress(data, &scratch, snappy.gossip_size_max);
        var again: [8192]u8 = undefined;
        var round: [4096]u8 = undefined;
        const recompressed = compressor.compress(decompressed, &again);
        const decoded = try snappy.decompress(recompressed, &round, snappy.gossip_size_max);
        try testing.expectEqualSlices(u8, decompressed, decoded);
        // Every version rejects a message cut below its minimum.
        const short = decompressed[0 .. decompressed_length_min(case[0]) - 1];
        try testing.expectError(error.InvalidLength, decode_decompressed(case[0], short));
    }
}

fn random_secret(prng: *Prng) [32]u8 {
    for (0..64) |_| {
        var secret: [32]u8 = undefined;
        prng.fill(&secret);
        if (secp256k1.address(secret)) |_| return secret else |_| continue;
    }
    unreachable; // Proof: a random scalar is invalid with probability below 2^-127.
}

test "block: encode_signed round trips and recovers the signer for every version" {
    var prng = Prng.init(0x626c_6f63);
    var compressor: snappy.Compressor = .{};
    var storage: [4096]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    var out: [snappy.max_compressed_length(8192)]u8 = undefined;
    var decoded_scratch: [8192]u8 = undefined;
    for (0..24) |iteration| {
        const version: Version = @fromBackingInt(@intCast(1 + iteration % 4));
        const payload = ssz.random_payload(&prng, version, &storage);
        const secret = random_secret(&prng);
        const chain_id = prng.int(u64);
        var root: ?B256 = null;
        if (has_parent_beacon_root(version)) root = .{ .bytes = @splat(prng.int(u8)) };
        const message = try encode_signed(
            chain_id,
            secret,
            root,
            payload,
            &scratch,
            &compressor,
            &out,
        );
        const envelope = try decode(version, message, &decoded_scratch);
        try testing.expectEqual(payload.block_number, envelope.payload.block_number);
        if (root) |value| try testing.expect(value.eql(envelope.parent_beacon_block_root.?));
        const signer = recover_signer(&envelope, chain_id).?;
        try testing.expectEqual(try secp256k1.address(secret), signer.bytes);
        try testing.expect(envelope.signature[64] <= 1);
        // A different chain id recovers a different address.
        const other = recover_signer(&envelope, chain_id +% 1);
        if (other) |address| try testing.expect(!address.eql(signer));
        const missing = encode_signed(1, secret, null, payload, &scratch, &compressor, &out);
        if (root != null) try testing.expectError(error.ParentBeaconRootMismatch, missing);
    }
}

test "block: recovery matches the public EIP-155 example signature" {
    // Signing hash, r, s and sender from the EIP-155 specification (public values).
    const hash = B256.comptime_hex(
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53",
    );
    const r = primitives.u256_to_bytes(
        18515461264373351373200002665853028612451056578545711640558177340181847433846,
    );
    const s_value: u256 =
        46948507304638947509940763649030358759909902576025900602547168820602576006531;
    const sender = Address.comptime_hex("9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
    const s = primitives.u256_to_bytes(s_value);
    try testing.expectEqual(sender.bytes, secp256k1.ecrecover_address(hash.bytes, 0, r, s).?);
    // The high-s twin with flipped parity recovers the same key, as alloy normalizes it.
    const twin = primitives.u256_to_bytes(secp256k1_order - s_value);
    try testing.expectEqual(sender.bytes, secp256k1.ecrecover_address(hash.bytes, 1, r, twin).?);
    // r or s outside [1, n) never recovers.
    const zero: [32]u8 = @splat(0);
    const none: ?[20]u8 = null;
    try testing.expectEqual(none, secp256k1.ecrecover_address(hash.bytes, 0, zero, twin));
    const order = primitives.u256_to_bytes(secp256k1_order);
    try testing.expectEqual(none, secp256k1.ecrecover_address(hash.bytes, 0, r, order));
}

const secp256k1_order: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

test "block: recovery agrees with the p2p signer" {
    var prng = Prng.init(0x7032_7073);
    for (0..16) |_| {
        const secret = random_secret(&prng);
        const compressed = try peers_secp256k1.public_key(secret);
        const uncompressed = try peers_secp256k1.decompress(compressed);
        const address = keccak.keccak256(uncompressed[1..])[12..32].*;
        var digest: [32]u8 = undefined;
        prng.fill(&digest);
        const signature = try peers_secp256k1.sign_digest(secret, digest);
        const r = signature[0..32].*;
        const s = signature[32..64].*;
        const even = secp256k1.ecrecover_address(digest, 0, r, s);
        const odd = secp256k1.ecrecover_address(digest, 1, r, s);
        const matches = @intFromBool(std.meta.eql(even, address)) +
            @intFromBool(std.meta.eql(odd, address));
        try testing.expectEqual(@as(u32, 1), matches);
    }
}

fn fuzz_decode_decompressed(_: void, input: []const u8) anyerror!void {
    for ([_]Version{ .v1, .v2, .v3, .v4 }) |version| {
        const envelope = decode_decompressed(version, input) catch continue;
        try testing.expect(input.len >= decompressed_length_min(version));
        _ = recover_signer(&envelope, 8453);
    }
}

test "block: fuzz decode of decompressed bytes" {
    try fuzz.run_bytes({}, fuzz_decode_decompressed, .{ .input_size_max = 2048 });
}

fn fuzz_message(_: void, input: []const u8) anyerror!void {
    var scratch: [fuzz.input_size_limit * 4]u8 = undefined;
    for ([_]Version{ .v1, .v2, .v3, .v4 }) |version| {
        _ = decode(version, input, &scratch) catch continue;
    }
    const first = message_id("/optimism/8453/2/blocks", input, &test_scratch);
    const second = message_id("/optimism/8453/2/blocks", input, &test_scratch);
    try testing.expectEqualSlices(u8, &first, &second);
}

test "block: fuzz message decode and message id" {
    try fuzz.run_bytes({}, fuzz_message, .{});
}

fn fuzz_mutated_message(_: void, smith: *std.testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var storage: [4096]u8 = undefined;
    var scratch: [8192]u8 = undefined;
    var out: [snappy.max_compressed_length(8192)]u8 = undefined;
    var compressor: snappy.Compressor = .{};
    const version: Version = @fromBackingInt(@intCast(1 + prng.below(4)));
    const payload = ssz.random_payload(&prng, version, &storage);
    const root: ?B256 = if (has_parent_beacon_root(version)) B256.zero else null;
    var secret: [32]u8 = @splat(0);
    secret[31] = 3;
    const message = try encode_signed(8453, secret, root, payload, &scratch, &compressor, &out);
    for (0..prng.range(1, 4)) |_| {
        message[@intCast(prng.below(message.len))] = prng.int(u8);
    }
    var decoded: [8192 * 2]u8 = undefined;
    const envelope = decode(version, message, &decoded) catch return;
    _ = recover_signer(&envelope, 8453);
}

test "block: fuzz decode of mutated signed messages" {
    try fuzz.run({}, fuzz_mutated_message, .{});
}

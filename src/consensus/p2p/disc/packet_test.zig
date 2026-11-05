//! Packet codec tests against devp2p `discv5-wire-test-vectors.md`. The spec's private
//! keys are not committed (AGENTS rule 3): every check uses public values only — the
//! destination node id unmasks, the published read keys open messages, offline-derived
//! public keys verify signatures, and the ECDH outputs were computed offline.

const std = @import("std");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");
const messages = @import("messages.zig");
const enr = @import("../peers/enr.zig");
const hex = @import("../../../common/primitives/hex.zig");
const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const node_id_a = "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb";
const node_id_b = "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9";
/// Public key of the vectors' node A, derived offline from `node-a-key`.
const node_a_public = "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9";
/// ecdh(node B public key, ephemeral-key 0288ef00...), derived offline.
const handshake_shared = "03a3817f091ce7b59d9407fd83146054ce18c174318efebd1bb683ada2c2369c18";
const ping_plaintext = [_]u8{ 0x01, 0xc6, 0x84, 0x00, 0x00, 0x00, 0x01, 0x02 };

const ping_packet = "00000000000000000000000000000000088b3d4342774649325f313964a39e55" ++
    "ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
    "4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc";
const whoareyou_packet = "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad" ++
    "1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d";
const handshake_packet = "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
    "ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
    "4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef" ++
    "268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb" ++
    "a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
    "f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83" ++
    "9cf8";
const handshake_enr_packet = "00000000000000000000000000000000088b3d4342774649305f313964a39e55" ++
    "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3" ++
    "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856" ++
    "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2" ++
    "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1" ++
    "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6" ++
    "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1" ++
    "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a" ++
    "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e" ++
    "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394" ++
    "71";
const challenge_prefix = "000000000000000000000000000000006469736376350001010102030405060708" ++
    "090a0b0c00180102030405060708090a0b0c0d0e0f10";

fn bytes_of(comptime text: []const u8) [text.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    return hex.decode_array(text.len / 2, text) catch unreachable;
}

fn reencode(decoded: *const packet.Decoded, key: packet.Key, plaintext: []const u8) ![]const u8 {
    const State = struct {
        var output: [packet.size_max]u8 = undefined;
    };
    const outgoing: packet.Outgoing = .{
        .dest_id = bytes_of(node_id_b),
        .masking_iv = decoded.masking_iv,
        .nonce = decoded.nonce,
        .authdata = decoded.authdata,
        .plaintext = plaintext,
        .key = key,
    };
    return packet.encode(&State.output, &outgoing);
}

test "disc packet: ordinary ping vector" {
    const raw = bytes_of(ping_packet);
    var decoded: packet.Decoded = undefined;
    try packet.decode(&decoded, bytes_of(node_id_b), &raw);
    try std.testing.expectEqual(bytes_of(node_id_a), decoded.authdata.message);
    const nonce: packet.Nonce = @splat(0xff);
    try std.testing.expectEqual(nonce, decoded.nonce);
    var plaintext: [packet.size_max]u8 = undefined;
    const key: packet.Key = @splat(0);
    const opened = try packet.open_message(&decoded, key, &plaintext);
    try std.testing.expectEqualSlices(u8, &ping_plaintext, opened);
    try std.testing.expectEqualSlices(u8, &raw, try reencode(&decoded, key, opened));
    const wrong: packet.Key = @splat(1);
    const result = packet.open_message(&decoded, wrong, &plaintext);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "disc packet: whoareyou vector" {
    const raw = bytes_of(whoareyou_packet);
    var decoded: packet.Decoded = undefined;
    try packet.decode(&decoded, bytes_of(node_id_b), &raw);
    const challenge = decoded.authdata.whoareyou;
    try std.testing.expectEqual(bytes_of("0102030405060708090a0b0c0d0e0f10"), challenge.id_nonce);
    try std.testing.expectEqual(@as(u64, 0), challenge.enr_seq);
    try std.testing.expectEqual(bytes_of("0102030405060708090a0b0c"), decoded.nonce);
    var buffer: [packet.size_max]u8 = undefined;
    const challenge_data = decoded.authenticated_data(&buffer);
    const expected = bytes_of(challenge_prefix ++ "0000000000000000");
    try std.testing.expectEqualSlices(u8, &expected, challenge_data);
    try std.testing.expectEqualSlices(u8, &raw, try reencode(&decoded, @splat(0), ""));
}

fn check_handshake(
    comptime text: []const u8,
    comptime enr_seq: []const u8,
    read_key: []const u8,
) !void {
    const raw = bytes_of(text);
    var decoded: packet.Decoded = undefined;
    try packet.decode(&decoded, bytes_of(node_id_b), &raw);
    const handshake = decoded.authdata.handshake;
    try std.testing.expectEqual(bytes_of(node_id_a), handshake.src_id);
    const challenge = bytes_of(challenge_prefix ++ enr_seq);
    try std.testing.expect(crypto.id_verify(
        bytes_of(node_a_public),
        handshake.signature,
        &challenge,
        handshake.ephemeral_public_key,
        bytes_of(node_id_b),
    ));
    const keys = crypto.derive_keys_from_secret(
        bytes_of(handshake_shared),
        bytes_of(node_id_a),
        bytes_of(node_id_b),
        &challenge,
    );
    try std.testing.expectEqualSlices(u8, read_key, &keys.initiator_key);
    var plaintext: [packet.size_max]u8 = undefined;
    const opened = try packet.open_message(&decoded, keys.initiator_key, &plaintext);
    const message = try messages.decode(opened);
    try std.testing.expectEqual(@as(u64, 1), message.ping.enr_seq);
    try std.testing.expectEqualSlices(u8, &raw, try reencode(&decoded, keys.initiator_key, opened));
    if (handshake.record.len > 0) {
        const record = try enr.decode(handshake.record);
        try std.testing.expectEqual(bytes_of(node_a_public), record.public_key);
        try std.testing.expectEqual(bytes_of(node_id_a), record.node_id());
    }
}

test "disc packet: handshake vector without record" {
    const read_key = bytes_of("4f9fac6de7567d1e3b1241dffe90f662");
    try check_handshake(handshake_packet, "0000000000000001", &read_key);
}

test "disc packet: handshake vector with record" {
    const read_key = bytes_of("53b1c075f41876423154e157470c2f48");
    try check_handshake(handshake_enr_packet, "0000000000000000", &read_key);
}

test "disc packet: rejects malformed" {
    var decoded: packet.Decoded = undefined;
    const local = bytes_of(node_id_b);
    const short: [62]u8 = @splat(0);
    try std.testing.expectError(error.TooSmall, packet.decode(&decoded, local, &short));
    const long: [packet.size_max + 1]u8 = @splat(0);
    try std.testing.expectError(error.TooLarge, packet.decode(&decoded, local, &long));
    var raw = bytes_of(ping_packet);
    const other = bytes_of(node_id_a);
    try std.testing.expectError(error.WrongProtocol, packet.decode(&decoded, other, &raw));
    raw[16] ^= 1; // First masked protocol-id byte.
    try std.testing.expectError(error.WrongProtocol, packet.decode(&decoded, local, &raw));
}

test "disc packet: seeded encode/decode round trip" {
    var prng = Prng.init(0x6469_7363);
    var output: [packet.size_max]u8 = undefined;
    var plaintext_buffer: [256]u8 = undefined;
    var opened: [packet.size_max]u8 = undefined;
    for (0..64) |_| {
        var outgoing: packet.Outgoing = .{
            .dest_id = undefined,
            .masking_iv = undefined,
            .nonce = undefined,
            .authdata = .{ .message = undefined },
        };
        prng.fill(&outgoing.dest_id);
        prng.fill(&outgoing.masking_iv);
        prng.fill(&outgoing.nonce);
        prng.fill(&outgoing.key);
        prng.fill(&outgoing.authdata.message);
        const length: usize = @intCast(prng.range(1, plaintext_buffer.len));
        prng.fill(plaintext_buffer[0..length]);
        outgoing.plaintext = plaintext_buffer[0..length];
        const encoded = try packet.encode(&output, &outgoing);
        var decoded: packet.Decoded = undefined;
        try packet.decode(&decoded, outgoing.dest_id, encoded);
        try std.testing.expectEqual(outgoing.authdata.message, decoded.authdata.message);
        const plain = try packet.open_message(&decoded, outgoing.key, &opened);
        try std.testing.expectEqualSlices(u8, outgoing.plaintext, plain);
    }
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    var decoded: packet.Decoded = undefined;
    packet.decode(&decoded, bytes_of(node_id_b), input) catch return;
    try std.testing.expect(decoded.header_length >= packet.static_header_length);
    var plaintext: [packet.size_max]u8 = undefined;
    _ = packet.open_message(&decoded, @splat(0), &plaintext) catch {};
}

fn fuzz_mutate(_: void, smith: *std.testing.Smith) anyerror!void {
    var raw = bytes_of(handshake_enr_packet);
    const flips = smith.value(u8) % 4 + 1;
    for (0..flips) |_| raw[smith.index(raw.len)] ^= smith.value(u8) | 1;
    var decoded: packet.Decoded = undefined;
    packet.decode(&decoded, bytes_of(node_id_b), &raw) catch return;
    if (decoded.authdata == .handshake and decoded.authdata.handshake.record.len > 0) {
        _ = enr.decode(decoded.authdata.handshake.record) catch {};
    }
}

test "disc packet: fuzz decode" {
    const corpus: []const []const u8 = &.{ &bytes_of(ping_packet), &bytes_of(whoareyou_packet) };
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 1300, .corpus = corpus });
}

test "disc packet: fuzz mutated handshake" {
    try fuzz.run({}, fuzz_mutate, .{ .iterations = 128 });
}

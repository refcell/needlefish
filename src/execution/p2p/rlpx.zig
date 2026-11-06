//! RLPx transport (devp2p `rlpx.md`, EIP-8 handshake), IO-free.
//!
//! Handshake (initiator side shown; the recipient mirrors it):
//!
//!   auth = size_be16 || ecies(remote, rlp([sig, pubkey, nonce, 4]) || padding, size_be16)
//!   ack  = size_be16 || ecies(local, rlp([ephemeral_pubkey, nonce, 4]) || padding, size_be16)
//!
//! where `sig` signs `x(static ECDH) ^ initiator_nonce` with the initiator's ephemeral key.
//! Secrets: `ephemeral = x(ephemeral ECDH)`, `shared = keccak(ephemeral || keccak(recipient_nonce
//! || initiator_nonce))`, `aes = keccak(ephemeral || shared)`, `mac = keccak(ephemeral || aes)`.
//! The initiator's egress MAC starts as `keccak((mac ^ recipient_nonce) || auth)` and its
//! ingress MAC as `keccak((mac ^ initiator_nonce) || ack)`; the recipient swaps them.
//!
//! Frames: `header(16) || header_mac(16) || body(padded to 16) || body_mac(16)`, AES-256-CTR
//! keyed with `aes` (zero IV, one continuous stream per direction), header =
//! `size_be24 || rlp([0, 0]) || zero padding`. MACs update a running Keccak-256 with seeds
//! `AES-256-ECB(mac, digest[0..16]) ^ x` as the spec defines. Randomness comes from the caller.

const std = @import("std");
const assert = std.debug.assert;
const curve = @import("../../common/crypto/secp256k1/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const rlp = @import("../../common/rlp/root.zig");
const ecies = @import("ecies.zig");

const Aes256 = std.crypto.core.aes.Aes256;
const Context = @TypeOf(Aes256.initEnc(@as([32]u8, @splat(0))));

pub const PublicKey = curve.PublicKey;
pub const nonce_length = 32;
/// Largest auth or ack packet accepted (EIP-8 allows padding; geth caps reads at 2 KiB).
pub const handshake_size_max = 2048;
pub const frame_header_length = 32;
/// devp2p caps a frame at 2^24 - 1 bytes; we cap bodies at 16 MiB as well.
pub const frame_size_max: u32 = (1 << 24) - 1;
const auth_version = 4;

pub const Error = ecies.Error || rlp.Error || error{
    InvalidHandshake,
    InvalidSignature,
    HeaderMac,
    BodyMac,
    FrameTooLarge,
    BufferTooSmall,
};

/// Per-direction cipher and MAC state after a completed handshake.
pub const Session = struct {
    egress_counter: u128 = 0,
    ingress_counter: u128 = 0,
    egress_cipher: Context,
    ingress_cipher: Context,
    mac_cipher: Context,
    egress_mac: keccak.Hasher,
    ingress_mac: keccak.Hasher,
    /// Body length of the frame whose header `open_header` just accepted.
    ingress_pending: ?u32 = null,

    /// Bytes `seal` writes for `data_length` bytes of frame data.
    pub fn sealed_length(data_length: usize) usize {
        return frame_header_length + padded(data_length) + 16;
    }

    /// Writes one frame carrying `data` (message id RLP || message data) into `output`.
    pub fn seal(session: *Session, data: []const u8, output: []u8) Error![]u8 {
        if (data.len > frame_size_max) return error.FrameTooLarge;
        const length = sealed_length(data.len);
        if (output.len < length) return error.BufferTooSmall;
        var header: [16]u8 = @splat(0);
        std.mem.writeInt(u24, header[0..3], @intCast(data.len), .big);
        header[3..6].* = .{ 0xc2, 0x80, 0x80 };
        ctr(session.egress_cipher, &session.egress_counter, output[0..16], &header);
        const header_mac = header_mac_update(
            &session.egress_mac,
            session.mac_cipher,
            output[0..16],
        );
        output[16..32].* = header_mac;
        const body = output[32..][0..padded(data.len)];
        @memcpy(body[0..data.len], data);
        @memset(body[data.len..], 0);
        ctr(session.egress_cipher, &session.egress_counter, body, body);
        output[32 + body.len ..][0..16].* = body_mac_update(
            &session.egress_mac,
            session.mac_cipher,
            body,
        );
        assert(length == 48 + body.len);
        return output[0..length];
    }

    /// Checks and decrypts a 32-byte frame header. Returns the bytes the rest of the frame
    /// occupies (padded body plus MAC); call `open_body` with exactly those bytes next.
    pub fn open_header(session: *Session, bytes: *const [frame_header_length]u8) Error!usize {
        assert(session.ingress_pending == null);
        const expected = header_mac_update(&session.ingress_mac, session.mac_cipher, bytes[0..16]);
        if (!std.crypto.timing_safe.eql([16]u8, expected, bytes[16..32].*)) {
            return error.HeaderMac;
        }
        var header: [16]u8 = undefined;
        ctr(session.ingress_cipher, &session.ingress_counter, &header, bytes[0..16]);
        const size = std.mem.readInt(u24, header[0..3], .big);
        session.ingress_pending = size;
        return padded(size) + 16;
    }

    /// Checks and decrypts the frame body in place. Returns the frame data.
    pub fn open_body(session: *Session, bytes: []u8) Error![]u8 {
        const size = session.ingress_pending.?;
        session.ingress_pending = null;
        assert(bytes.len == padded(size) + 16);
        const body = bytes[0 .. bytes.len - 16];
        const expected = body_mac_update(&session.ingress_mac, session.mac_cipher, body);
        if (!std.crypto.timing_safe.eql([16]u8, expected, bytes[body.len..][0..16].*)) {
            return error.BodyMac;
        }
        ctr(session.ingress_cipher, &session.ingress_counter, body, body);
        return body[0..size];
    }
};

fn padded(length: usize) usize {
    return std.mem.alignForward(usize, length, 16);
}

/// AES-256-CTR over whole blocks with a big-endian 128-bit counter that persists.
fn ctr(context: Context, counter: *u128, destination: []u8, source: []const u8) void {
    assert(destination.len == source.len and source.len % 16 == 0);
    var offset: usize = 0;
    while (offset < source.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        std.mem.writeInt(u128, &block, counter.*, .big);
        context.encrypt(&block, &block);
        counter.* +%= 1;
        for (destination[offset..][0..16], source[offset..][0..16], block) |*out, in, key| {
            out.* = in ^ key;
        }
    }
}

fn digest16(mac: *const keccak.Hasher) [16]u8 {
    var copy = mac.*;
    return copy.final()[0..16].*;
}

fn header_mac_update(mac: *keccak.Hasher, cipher: Context, ciphertext: *const [16]u8) [16]u8 {
    var seed = digest16(mac);
    cipher.encrypt(&seed, &seed);
    for (&seed, ciphertext) |*byte, other| byte.* ^= other;
    mac.update(&seed);
    return digest16(mac);
}

fn body_mac_update(mac: *keccak.Hasher, cipher: Context, ciphertext: []const u8) [16]u8 {
    mac.update(ciphertext);
    const previous = digest16(mac);
    var seed = previous;
    cipher.encrypt(&seed, &seed);
    for (&seed, previous) |*byte, other| byte.* ^= other;
    mac.update(&seed);
    return digest16(mac);
}

/// Key material the handshake fixes before secrets are derived.
const Agreed = struct {
    ephemeral_shared: [32]u8,
    initiator_nonce: [32]u8,
    recipient_nonce: [32]u8,
    auth: []const u8,
    ack: []const u8,
};

fn derive(agreed: Agreed, initiator: bool) Session {
    var nonces: [64]u8 = undefined;
    nonces[0..32].* = agreed.recipient_nonce;
    nonces[32..64].* = agreed.initiator_nonce;
    var joined: [64]u8 = undefined;
    joined[0..32].* = agreed.ephemeral_shared;
    joined[32..64].* = keccak.keccak256(&nonces);
    const shared = keccak.keccak256(&joined);
    joined[32..64].* = shared;
    const aes = keccak.keccak256(&joined);
    joined[32..64].* = aes;
    const mac = keccak.keccak256(&joined);
    var to_recipient = keccak.Hasher.init();
    var to_initiator = keccak.Hasher.init();
    var seed: [32]u8 = undefined;
    for (&seed, mac, agreed.recipient_nonce) |*byte, m, n| byte.* = m ^ n;
    to_recipient.update(&seed);
    to_recipient.update(agreed.auth);
    for (&seed, mac, agreed.initiator_nonce) |*byte, m, n| byte.* = m ^ n;
    to_initiator.update(&seed);
    to_initiator.update(agreed.ack);
    return .{
        .egress_cipher = Aes256.initEnc(aes),
        .ingress_cipher = Aes256.initEnc(aes),
        .mac_cipher = Aes256.initEnc(mac),
        .egress_mac = if (initiator) to_recipient else to_initiator,
        .ingress_mac = if (initiator) to_initiator else to_recipient,
    };
}

/// Randomness one side of a handshake consumes.
pub const Random = struct {
    ephemeral_secret: [32]u8,
    nonce: [32]u8,
    iv: [16]u8,
    /// EIP-8 padding length (geth sends 100..300 random bytes).
    padding: u16 = 100,
};

/// Seals `body` (RLP) plus zero padding as an EIP-8 handshake packet to `remote`.
fn seal_packet(
    remote: *const PublicKey,
    body: []const u8,
    random: Random,
    output: []u8,
) Error![]u8 {
    const plain_length = body.len + random.padding;
    const size = plain_length + ecies.overhead;
    if (size > handshake_size_max or output.len < size + 2) return error.BufferTooSmall;
    var plain: [handshake_size_max]u8 = undefined;
    @memcpy(plain[0..body.len], body);
    @memset(plain[body.len..plain_length], 0);
    std.mem.writeInt(u16, output[0..2], @intCast(size), .big);
    const sealed = try ecies.encrypt(
        remote,
        plain[0..plain_length],
        output[0..2],
        random.ephemeral_secret,
        random.iv,
        output[2..],
    );
    assert(sealed.len == size);
    return output[0 .. size + 2];
}

/// The total length of the handshake packet starting `bytes`, once its 2-byte prefix is in.
pub fn packet_length(prefix: *const [2]u8) Error!usize {
    const size = std.mem.readInt(u16, prefix, .big);
    if (size < ecies.overhead or size > handshake_size_max) return error.InvalidHandshake;
    return @as(usize, size) + 2;
}

fn open_packet(secret: [32]u8, packet: []const u8, output: []u8) Error![]u8 {
    if (packet.len < 2 or (try packet_length(packet[0..2])) != packet.len) {
        return error.InvalidHandshake;
    }
    return ecies.decrypt(secret, packet[2..], packet[0..2], output);
}

pub const Initiator = struct {
    static_secret: [32]u8,
    remote: PublicKey,
    random: Random,
    auth: [handshake_size_max + 2]u8 = undefined,
    auth_length: usize = 0,

    /// Builds the auth packet; send `initiator.auth[0..auth_length]`.
    pub fn start(initiator: *Initiator) Error![]const u8 {
        const static_shared = try ecies.shared_x(initiator.static_secret, &initiator.remote);
        var signed: [32]u8 = undefined;
        for (&signed, static_shared, initiator.random.nonce) |*byte, a, b| byte.* = a ^ b;
        const signature = curve.sign(initiator.random.ephemeral_secret, signed) catch
            return error.InvalidPrivateKey;
        var sig: [65]u8 = undefined;
        sig[0..32].* = signature.r;
        sig[32..64].* = signature.s;
        sig[64] = @intCast(signature.recovery_id & 1);
        const public = curve.public_key(initiator.static_secret) catch
            return error.InvalidPrivateKey;
        var body: [256]u8 = undefined;
        const payload = rlp.bytes_length(&sig) + rlp.bytes_length(&public) +
            rlp.bytes_length(&initiator.random.nonce) + rlp.int_length(@as(u8, auth_version));
        var encoder = rlp.Encoder.init(&body);
        encoder.list_header(payload);
        encoder.bytes(&sig);
        encoder.bytes(&public);
        encoder.bytes(&initiator.random.nonce);
        encoder.int(@as(u8, auth_version));
        const body_rlp = encoder.written();
        const output = &initiator.auth;
        const packet = try seal_packet(&initiator.remote, body_rlp, initiator.random, output);
        initiator.auth_length = packet.len;
        return packet;
    }

    /// Opens the recipient's ack and derives the session.
    pub fn finish(initiator: *const Initiator, ack: []const u8) Error!Session {
        assert(initiator.auth_length > 0);
        var plain: [handshake_size_max]u8 = undefined;
        const opened = try open_packet(initiator.static_secret, ack, &plain);
        var outer = rlp.Decoder.init(opened);
        var fields = try outer.list();
        const remote_ephemeral = try fields.fixed(64);
        const recipient_nonce = try fields.fixed(32);
        const ephemeral_secret = initiator.random.ephemeral_secret;
        const ephemeral_shared = try ecies.shared_x(ephemeral_secret, &remote_ephemeral);
        return derive(.{
            .ephemeral_shared = ephemeral_shared,
            .initiator_nonce = initiator.random.nonce,
            .recipient_nonce = recipient_nonce,
            .auth = initiator.auth[0..initiator.auth_length],
            .ack = ack,
        }, true);
    }
};

/// Recipient side, for tests and a future listener: opens auth, returns ack and session.
pub fn respond(
    static_secret: [32]u8,
    auth: []const u8,
    random: Random,
    ack_output: []u8,
    remote_out: *PublicKey,
) Error!struct { ack: []u8, session: Session } {
    var plain: [handshake_size_max]u8 = undefined;
    const opened = try open_packet(static_secret, auth, &plain);
    var outer = rlp.Decoder.init(opened);
    var fields = try outer.list();
    const sig = try fields.fixed(65);
    const initiator_public = try fields.fixed(64);
    const initiator_nonce = try fields.fixed(32);
    const static_shared = try ecies.shared_x(static_secret, &initiator_public);
    var signed: [32]u8 = undefined;
    for (&signed, static_shared, initiator_nonce) |*byte, a, b| byte.* = a ^ b;
    if (sig[64] > 1) return error.InvalidSignature;
    const parity: u1 = @intCast(sig[64]);
    const remote_ephemeral = curve.ecrecover(signed, parity, sig[0..32].*, sig[32..64].*) orelse
        return error.InvalidSignature;
    const ephemeral = curve.public_key(random.ephemeral_secret) catch
        return error.InvalidPrivateKey;
    var body: [128]u8 = undefined;
    const payload = rlp.bytes_length(&ephemeral) + rlp.bytes_length(&random.nonce) +
        rlp.int_length(@as(u8, auth_version));
    var encoder = rlp.Encoder.init(&body);
    encoder.list_header(payload);
    encoder.bytes(&ephemeral);
    encoder.bytes(&random.nonce);
    encoder.int(@as(u8, auth_version));
    const ack = try seal_packet(&initiator_public, encoder.written(), random, ack_output);
    remote_out.* = initiator_public;
    const session = derive(.{
        .ephemeral_shared = try ecies.shared_x(random.ephemeral_secret, &remote_ephemeral),
        .initiator_nonce = initiator_nonce,
        .recipient_nonce = random.nonce,
        .auth = auth,
        .ack = ack,
    }, false);
    return .{ .ack = ack, .session = session };
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const fuzz = @import("../../testing/fuzz.zig");

fn random_for(prng: *Prng) Random {
    var random: Random = undefined;
    while (true) {
        prng.fill(&random.ephemeral_secret);
        _ = curve.public_key(random.ephemeral_secret) catch continue;
        break;
    }
    prng.fill(&random.nonce);
    prng.fill(&random.iv);
    random.padding = @intCast(prng.range(0, 300));
    return random;
}

fn secret_for(prng: *Prng) [32]u8 {
    return random_for(prng).ephemeral_secret;
}

fn exchange(from: *Session, to: *Session, data: []const u8) ![]u8 {
    var wire: [4096]u8 = undefined;
    const frame = try from.seal(data, &wire);
    try testing.expectEqual(Session.sealed_length(data.len), frame.len);
    const rest = try to.open_header(frame[0..32]);
    try testing.expectEqual(frame.len - 32, rest);
    const opened = try to.open_body(frame[32..]);
    try testing.expectEqualSlices(u8, data, opened);
    return opened;
}

test "rlpx: handshake both ways and frames in sequence; tampering fails the MAC" {
    var prng = Prng.init(3);
    for (0..8) |_| {
        const initiator_secret = secret_for(&prng);
        const recipient_secret = secret_for(&prng);
        var initiator: Initiator = .{
            .static_secret = initiator_secret,
            .remote = try curve.public_key(recipient_secret),
            .random = random_for(&prng),
        };
        const auth = try initiator.start();
        try testing.expectEqual(auth.len, try packet_length(auth[0..2]));
        var ack_buffer: [handshake_size_max + 2]u8 = undefined;
        var seen: PublicKey = undefined;
        const response = try respond(recipient_secret, auth, random_for(&prng), &ack_buffer, &seen);
        try testing.expectEqualSlices(u8, &(try curve.public_key(initiator_secret)), &seen);
        var a = try initiator.finish(response.ack);
        var b = response.session;
        // Several frames each way: the CTR streams and MACs must stay in step.
        for (0..6) |round| {
            var data: [700]u8 = undefined;
            const length: usize = @intCast(prng.range(1, data.len));
            prng.fill(data[0..length]);
            if (round % 2 == 0) {
                _ = try exchange(&a, &b, data[0..length]);
            } else {
                _ = try exchange(&b, &a, data[0..length]);
            }
        }
        var wire: [256]u8 = undefined;
        const frame = try a.seal("hello", &wire);
        frame[40] ^= 1;
        _ = try b.open_header(frame[0..32]);
        try testing.expectError(error.BodyMac, b.open_body(frame[32..]));
        // A wrong static key cannot open the auth.
        var plain: [handshake_size_max]u8 = undefined;
        try testing.expectError(error.BadMac, open_packet(initiator_secret, auth, &plain));
    }
}

/// Hostile handshake packets and frames: every input either opens to what was sealed or
/// fails with an error; nothing panics. The fuzz input seeds the keys and mutations.
fn fuzz_rlpx(_: void, smith: *std.testing.Smith) anyerror!void {
    var prng_state = Prng.init(smith.value(u64));
    const prng = &prng_state;
    const recipient_secret = secret_for(prng);
    const recipient = try curve.public_key(recipient_secret);
    var initiator: Initiator = .{
        .static_secret = secret_for(prng),
        .remote = recipient,
        .random = random_for(prng),
    };
    const auth = try initiator.start();
    var ack_buffer: [handshake_size_max + 2]u8 = undefined;
    var seen: PublicKey = undefined;
    // Arbitrary plaintext under a valid MAC reaches the RLP and signature checks.
    var body: [400]u8 = undefined;
    const body_length: usize = @intCast(prng.range(0, body.len));
    prng.fill(body[0..body_length]);
    var packet: [handshake_size_max + 2]u8 = undefined;
    const sealed = try seal_packet(&recipient, body[0..body_length], random_for(prng), &packet);
    if (respond(recipient_secret, sealed, random_for(prng), &ack_buffer, &seen)) |_| {} else |_| {}
    const sealed_ack = try seal_packet(&recipient, body[0..body_length], random_for(prng), &packet);
    var wrong: Initiator = initiator;
    wrong.static_secret = recipient_secret;
    if (wrong.finish(sealed_ack)) |_| {} else |_| {}
    // A flipped byte in a real auth never opens.
    var mutated: [handshake_size_max + 2]u8 = undefined;
    @memcpy(mutated[0..auth.len], auth);
    mutated[@intCast(prng.below(auth.len))] ^= @as(u8, 1) << @intCast(prng.below(8));
    const tampered = mutated[0..auth.len];
    const opened = respond(recipient_secret, tampered, random_for(prng), &ack_buffer, &seen);
    try testing.expect(std.meta.isError(opened));
    const response = try respond(recipient_secret, auth, random_for(prng), &ack_buffer, &seen);
    var a = try initiator.finish(response.ack);
    var b = response.session;
    for (0..8) |_| {
        var data: [300]u8 = undefined;
        const length: usize = @intCast(prng.range(1, data.len));
        prng.fill(data[0..length]);
        var wire: [512]u8 = undefined;
        const frame = try a.seal(data[0..length], &wire);
        const flip = prng.chance(1, 3);
        if (flip) frame[@intCast(prng.below(frame.len))] ^= 0x80;
        const rest = b.open_header(frame[0..frame_header_length]) catch |err| {
            try testing.expect(flip and err == error.HeaderMac);
            return;
        };
        try testing.expectEqual(frame.len - frame_header_length, rest);
        const plain = b.open_body(frame[frame_header_length..]) catch |err| {
            try testing.expect(flip and err == error.BodyMac);
            return;
        };
        try testing.expect(!flip);
        try testing.expectEqualSlices(u8, data[0..length], plain);
    }
}

test "rlpx: fuzz handshake packets and frames" {
    // Each input costs several ECDH operations; keep the per-commit budget small.
    try fuzz.run({}, fuzz_rlpx, .{ .iterations = 24, .input_size_max = 64 });
}

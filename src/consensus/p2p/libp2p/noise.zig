//! Noise secure channel for libp2p (libp2p `noise` spec): `Noise_XX_25519_ChaChaPoly_SHA256`
//! with an empty prologue and the libp2p handshake payload that binds the Noise static key
//! to the peer's libp2p identity key.
//!
//!   -> e                      (payload empty)
//!   <- e, ee, s, es           (payload: responder identity)
//!   -> s, se                  (payload: initiator identity)
//!
//! Every handshake and transport message is framed by a 2-byte big-endian length. The
//! payload is the protobuf `NoiseHandshakePayload { identity_key = 1; identity_sig = 2;
//! extensions = 4; }`, where `identity_sig` signs `"noise-libp2p-static-key:" || s.pub`.
//!
//! `Handshake` is an IO-free state machine: key material (identity key and the X25519 static
//! and ephemeral seeds) is injected, so the simulator reproduces every byte from a seed.
//! After completion `finish` yields a `Transport` holding the split cipher pair and the
//! remote `PeerId`.

const std = @import("std");
const assert = std.debug.assert;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const identity = @import("identity.zig");
const protobuf = @import("protobuf.zig");
const peer_id = @import("../peers/peer_id.zig");
const secp256k1 = @import("../peers/secp256k1.zig");
const PeerId = peer_id.PeerId;

pub const protocol_id = "/noise";
pub const protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const signature_prefix = "noise-libp2p-static-key:";
pub const key_length = 32;
pub const hash_length = 32;
pub const tag_length = Aead.tag_length;
pub const prefix_length = 2;
/// Noise caps every message at 65535 bytes, tag included.
pub const message_length_max = 65535;
pub const plaintext_length_max = message_length_max - tag_length;
/// Remote handshake messages are much smaller than a full Noise message: an identity key,
/// a signature, and optional extensions. Larger ones are rejected.
pub const handshake_message_length_max = 2048;
/// Our own encoded payload: protobuf key (2 + 37) plus DER signature (2 + 72).
pub const local_payload_length_max = 2 + identity.public_key_protobuf_length + 2 +
    identity.signature_length_max;
/// Output buffer `start` and `receive` need: message 2 is the largest we send.
pub const handshake_output_length_max = prefix_length + key_length + key_length + tag_length +
    local_payload_length_max + tag_length;

comptime {
    assert(protocol_name.len == hash_length);
    assert(local_payload_length_max == 113);
    assert(handshake_output_length_max <= 256);
}

pub const Error = error{
    /// Short, oversized, or otherwise malformed message.
    InvalidMessage,
    /// AEAD authentication failed (tampering or wrong keys).
    DecryptFailed,
    /// The handshake payload is not a valid `NoiseHandshakePayload`.
    InvalidPayload,
    /// The identity signature does not cover the remote static key.
    InvalidSignature,
    /// Remote identity key is not secp256k1.
    UnsupportedKeyType,
    /// A Diffie-Hellman input is a low-order point.
    InvalidPublicKey,
    /// The 64-bit nonce space is used up; the connection must be closed.
    NonceExhausted,
};

/// Noise `CipherState`: a ChaCha20-Poly1305 key and a 64-bit counter nonce.
pub const CipherState = struct {
    key: [key_length]u8 = @splat(0),
    nonce: u64 = 0,
    has_key: bool = false,

    fn nonce_bytes(cipher: *const CipherState) [Aead.nonce_length]u8 {
        var bytes: [Aead.nonce_length]u8 = @splat(0);
        std.mem.writeInt(u64, bytes[4..12], cipher.nonce, .little);
        return bytes;
    }

    /// Encrypts into `output` (plaintext + tag); passes plaintext through without a key.
    pub fn encrypt(
        cipher: *CipherState,
        ad: []const u8,
        plaintext: []const u8,
        output: []u8,
    ) Error![]u8 {
        assert(plaintext.len <= plaintext_length_max);
        if (!cipher.has_key) {
            assert(output.len >= plaintext.len);
            @memcpy(output[0..plaintext.len], plaintext);
            return output[0..plaintext.len];
        }
        if (cipher.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        assert(output.len >= plaintext.len + tag_length);
        const tag = output[plaintext.len..][0..tag_length];
        const nonce = cipher.nonce_bytes();
        Aead.encrypt(output[0..plaintext.len], tag, plaintext, ad, nonce, cipher.key);
        cipher.nonce += 1;
        return output[0 .. plaintext.len + tag_length];
    }

    /// Decrypts into `output`; the nonce advances only on success.
    pub fn decrypt(
        cipher: *CipherState,
        ad: []const u8,
        ciphertext: []const u8,
        output: []u8,
    ) Error![]u8 {
        if (!cipher.has_key) {
            assert(output.len >= ciphertext.len);
            @memcpy(output[0..ciphertext.len], ciphertext);
            return output[0..ciphertext.len];
        }
        if (cipher.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
        if (ciphertext.len < tag_length) return error.InvalidMessage;
        const length = ciphertext.len - tag_length;
        assert(output.len >= length);
        const tag = ciphertext[length..][0..tag_length].*;
        const nonce = cipher.nonce_bytes();
        Aead.decrypt(output[0..length], ciphertext[0..length], tag, ad, nonce, cipher.key) catch
            return error.DecryptFailed;
        cipher.nonce += 1;
        return output[0..length];
    }
};

/// Noise `SymmetricState`: chaining key, handshake hash, and the current cipher.
pub const SymmetricState = struct {
    chaining_key: [hash_length]u8,
    hash: [hash_length]u8,
    cipher: CipherState = .{},

    /// `InitializeSymmetric(protocol_name)` then `MixHash(prologue)` with an empty prologue.
    pub fn init() SymmetricState {
        var state: SymmetricState = .{ .chaining_key = protocol_name.*, .hash = protocol_name.* };
        state.mix_hash("");
        assert(!state.cipher.has_key);
        return state;
    }

    pub fn mix_hash(state: *SymmetricState, data: []const u8) void {
        var hasher = Sha256.init(.{});
        hasher.update(&state.hash);
        hasher.update(data);
        hasher.final(&state.hash);
    }

    /// HKDF(ck, ikm) -> (ck, k): the Noise HKDF is HMAC-based extract then expand.
    pub fn mix_key(state: *SymmetricState, input_key_material: []const u8) void {
        var output: [2 * hash_length]u8 = undefined;
        hkdf2(&output, state.chaining_key, input_key_material);
        state.chaining_key = output[0..hash_length].*;
        state.cipher = .{ .key = output[hash_length..].*, .nonce = 0, .has_key = true };
        assert(state.cipher.has_key);
    }

    pub fn encrypt_and_hash(
        state: *SymmetricState,
        plaintext: []const u8,
        output: []u8,
    ) Error![]u8 {
        const ciphertext = try state.cipher.encrypt(&state.hash, plaintext, output);
        state.mix_hash(ciphertext);
        return ciphertext;
    }

    pub fn decrypt_and_hash(
        state: *SymmetricState,
        ciphertext: []const u8,
        output: []u8,
    ) Error![]u8 {
        const plaintext = try state.cipher.decrypt(&state.hash, ciphertext, output);
        state.mix_hash(ciphertext);
        return plaintext;
    }

    /// `Split()`: the initiator sends with the first key, the responder with the second.
    pub fn split(state: *const SymmetricState) [2]CipherState {
        assert(state.cipher.has_key);
        var output: [2 * hash_length]u8 = undefined;
        hkdf2(&output, state.chaining_key, "");
        return .{
            .{ .key = output[0..hash_length].*, .has_key = true },
            .{ .key = output[hash_length..].*, .has_key = true },
        };
    }
};

fn hkdf2(output: *[2 * hash_length]u8, chaining_key: [hash_length]u8, ikm: []const u8) void {
    const prk = Hkdf.extract(&chaining_key, ikm);
    Hkdf.expand(output, "", prk);
    assert(!std.mem.eql(u8, output[0..hash_length], output[hash_length..]));
}

fn dh(secret: [key_length]u8, public: [key_length]u8) Error![key_length]u8 {
    const shared = X25519.scalarmult(secret, public) catch return error.InvalidPublicKey;
    assert(shared.len == key_length);
    return shared;
}

pub const Role = enum { initiator, responder };

pub const Config = struct {
    /// libp2p identity (secp256k1) secret key.
    identity_secret: identity.SecretKey,
    /// Seed of the X25519 static key; libp2p peers usually make one per connection.
    static_seed: [X25519.seed_length]u8,
    /// Seed of the X25519 ephemeral key. Must be fresh randomness per handshake.
    ephemeral_seed: [X25519.seed_length]u8,
};

pub const Step = struct {
    consumed: usize,
    /// Bytes to send to the peer (a prefix of the caller's output buffer).
    output: []const u8,
    done: bool,
};

const State = enum { idle, await_message_1, await_message_2, await_message_3, done, failed };

/// Reassembles one length-prefixed handshake message from fragmented input.
const Inbox = struct {
    buffer: [prefix_length + handshake_message_length_max]u8 = undefined,
    fill: u16 = 0,

    fn push(inbox: *Inbox, input: []const u8) Error!struct { consumed: usize, body: ?[]u8 } {
        assert(inbox.fill < inbox.buffer.len);
        var consumed: usize = 0;
        if (inbox.fill < prefix_length) {
            const take = @min(prefix_length - inbox.fill, input.len);
            @memcpy(inbox.buffer[inbox.fill..][0..take], input[0..take]);
            inbox.fill += @intCast(take);
            consumed = take;
            if (inbox.fill < prefix_length) return .{ .consumed = consumed, .body = null };
        }
        const length: usize = std.mem.readInt(u16, inbox.buffer[0..prefix_length], .big);
        if (length > handshake_message_length_max) return error.InvalidMessage;
        const total = prefix_length + length;
        const take = @min(total - inbox.fill, input.len - consumed);
        @memcpy(inbox.buffer[inbox.fill..][0..take], input[consumed..][0..take]);
        inbox.fill += @intCast(take);
        consumed += take;
        assert(inbox.fill <= total);
        if (inbox.fill < total) return .{ .consumed = consumed, .body = null };
        inbox.fill = 0;
        return .{ .consumed = consumed, .body = inbox.buffer[prefix_length..total] };
    }
};

pub const Handshake = struct {
    role: Role,
    state: State = .idle,
    symmetric: SymmetricState,
    ephemeral: X25519.KeyPair,
    static: X25519.KeyPair,
    remote_ephemeral: [key_length]u8 = @splat(0),
    remote_static: [key_length]u8 = @splat(0),
    payload: [local_payload_length_max]u8 = undefined,
    payload_length: u8 = 0,
    remote_peer: ?PeerId = null,
    inbox: Inbox = .{},

    pub fn init(role: Role, config: Config) identity.Error!Handshake {
        var handshake: Handshake = .{
            .role = role,
            .symmetric = SymmetricState.init(),
            .ephemeral = X25519.KeyPair.generateDeterministic(config.ephemeral_seed),
            .static = X25519.KeyPair.generateDeterministic(config.static_seed),
        };
        try handshake.build_payload(config.identity_secret);
        assert(handshake.payload_length > 0);
        assert(handshake.state == .idle);
        return handshake;
    }

    fn build_payload(handshake: *Handshake, secret: identity.SecretKey) identity.Error!void {
        const public = secp256k1.public_key(secret) catch
            return error.InvalidSecretKey;
        var key_buffer: [identity.public_key_protobuf_length]u8 = undefined;
        const key = identity.encode_public_key(&key_buffer, public);
        const signature = try identity.sign(secret, &signed_message(handshake.static.public_key));
        var writer = protobuf.Writer.init(&handshake.payload);
        writer.write_bytes_field(1, key);
        writer.write_bytes_field(2, signature.slice());
        handshake.payload_length = @intCast(writer.length);
        assert(handshake.payload_length <= local_payload_length_max);
    }

    /// Initiator: writes message 1. Responder: writes nothing and waits for message 1.
    pub fn start(handshake: *Handshake, output: []u8) Error![]const u8 {
        assert(handshake.state == .idle);
        assert(output.len >= handshake_output_length_max);
        if (handshake.role == .responder) {
            handshake.state = .await_message_1;
            return output[0..0];
        }
        const body = output[prefix_length..];
        @memcpy(body[0..key_length], &handshake.ephemeral.public_key);
        handshake.symmetric.mix_hash(&handshake.ephemeral.public_key);
        const payload = try handshake.symmetric.encrypt_and_hash("", body[key_length..]);
        assert(payload.len == 0);
        handshake.state = .await_message_2;
        return frame(output, key_length);
    }

    pub fn receive(handshake: *Handshake, input: []const u8, output: []u8) Error!Step {
        assert(output.len >= handshake_output_length_max);
        assert(handshake.state == .await_message_1 or handshake.state == .await_message_2 or
            handshake.state == .await_message_3);
        const pushed = handshake.inbox.push(input) catch |err| return handshake.fail(err);
        var step: Step = .{ .consumed = pushed.consumed, .output = &.{}, .done = false };
        const body = pushed.body orelse return step;
        const result = switch (handshake.state) {
            .await_message_1 => handshake.read_message_1(body, output),
            .await_message_2 => handshake.read_message_2(body, output),
            .await_message_3 => handshake.read_message_3(body),
            else => unreachable,
        };
        step.output = result catch |err| return handshake.fail(err);
        step.done = handshake.state == .done;
        return step;
    }

    /// The transport cipher pair and remote identity. Only valid after `done`.
    pub fn finish(handshake: *const Handshake) Transport {
        assert(handshake.state == .done);
        const ciphers = handshake.symmetric.split();
        const initiator = handshake.role == .initiator;
        return .{
            .sender = if (initiator) ciphers[0] else ciphers[1],
            .receiver = if (initiator) ciphers[1] else ciphers[0],
            .remote_peer = handshake.remote_peer.?,
            .handshake_hash = handshake.symmetric.hash,
        };
    }

    fn fail(handshake: *Handshake, err: Error) Error {
        assert(handshake.state != .done);
        handshake.state = .failed;
        return err;
    }

    /// Responder: `-> e`, then writes `<- e, ee, s, es` with our payload.
    fn read_message_1(handshake: *Handshake, body: []const u8, output: []u8) Error![]const u8 {
        assert(handshake.role == .responder);
        if (body.len < key_length) return error.InvalidMessage;
        handshake.remote_ephemeral = body[0..key_length].*;
        handshake.symmetric.mix_hash(&handshake.remote_ephemeral);
        // Message 1 carries no payload in libp2p; any bytes are hashed and ignored.
        var scratch: [handshake_message_length_max]u8 = undefined;
        _ = try handshake.symmetric.decrypt_and_hash(body[key_length..], &scratch);

        const out = output[prefix_length..];
        @memcpy(out[0..key_length], &handshake.ephemeral.public_key);
        handshake.symmetric.mix_hash(&handshake.ephemeral.public_key);
        const ee = try dh(handshake.ephemeral.secret_key, handshake.remote_ephemeral);
        handshake.symmetric.mix_key(&ee);
        const length = try handshake.write_static_and_payload(out[key_length..]);
        handshake.state = .await_message_3;
        return frame(output, key_length + length);
    }

    /// Initiator: `<- e, ee, s, es`, then writes `-> s, se` with our payload.
    fn read_message_2(handshake: *Handshake, body: []const u8, output: []u8) Error![]const u8 {
        assert(handshake.role == .initiator);
        if (body.len < key_length + key_length + tag_length + tag_length) {
            return error.InvalidMessage;
        }
        handshake.remote_ephemeral = body[0..key_length].*;
        handshake.symmetric.mix_hash(&handshake.remote_ephemeral);
        const ee = try dh(handshake.ephemeral.secret_key, handshake.remote_ephemeral);
        handshake.symmetric.mix_key(&ee);
        try handshake.read_static_and_payload(body[key_length..]);

        const out = output[prefix_length..];
        const length = try handshake.write_static_and_payload(out);
        handshake.state = .done;
        return frame(output, length);
    }

    /// Responder: `-> s, se` with the initiator's payload.
    fn read_message_3(handshake: *Handshake, body: []const u8) Error![]const u8 {
        assert(handshake.role == .responder);
        if (body.len < key_length + tag_length + tag_length) return error.InvalidMessage;
        try handshake.read_static_and_payload(body);
        handshake.state = .done;
        return &.{};
    }

    /// Writes `s` (encrypted static key), the `es`/`se` DH, and our encrypted payload.
    fn write_static_and_payload(handshake: *Handshake, output: []u8) Error!usize {
        assert(handshake.symmetric.cipher.has_key);
        const sealed_static = try handshake.symmetric.encrypt_and_hash(
            &handshake.static.public_key,
            output,
        );
        assert(sealed_static.len == key_length + tag_length);
        // Responder `es` and initiator `se` are both DH(own static, remote ephemeral).
        const shared = try dh(handshake.static.secret_key, handshake.remote_ephemeral);
        handshake.symmetric.mix_key(&shared);
        const payload = try handshake.symmetric.encrypt_and_hash(
            handshake.payload[0..handshake.payload_length],
            output[sealed_static.len..],
        );
        return sealed_static.len + payload.len;
    }

    /// Reads `s`, mixes DH(own ephemeral, remote static), then verifies the payload.
    fn read_static_and_payload(handshake: *Handshake, body: []const u8) Error!void {
        const sealed_length = key_length + tag_length;
        assert(body.len >= sealed_length + tag_length);
        var remote_static: [key_length]u8 = undefined;
        _ = try handshake.symmetric.decrypt_and_hash(body[0..sealed_length], &remote_static);
        handshake.remote_static = remote_static;
        handshake.symmetric.mix_key(&try dh(handshake.ephemeral.secret_key, remote_static));
        var scratch: [handshake_message_length_max]u8 = undefined;
        const payload = try handshake.symmetric.decrypt_and_hash(body[sealed_length..], &scratch);
        handshake.remote_peer = try verify_payload(payload, remote_static);
    }
};

fn frame(output: []u8, body_length: usize) []const u8 {
    assert(body_length <= message_length_max);
    assert(output.len >= prefix_length + body_length);
    std.mem.writeInt(u16, output[0..prefix_length], @intCast(body_length), .big);
    return output[0 .. prefix_length + body_length];
}

fn signed_message(static_public: [key_length]u8) [signature_prefix.len + key_length]u8 {
    var message: [signature_prefix.len + key_length]u8 = undefined;
    @memcpy(message[0..signature_prefix.len], signature_prefix);
    @memcpy(message[signature_prefix.len..], &static_public);
    assert(message.len == 56);
    return message;
}

/// Parses `NoiseHandshakePayload` and checks the identity signature over `remote_static`.
pub fn verify_payload(payload: []const u8, remote_static: [key_length]u8) Error!PeerId {
    var reader = protobuf.Reader.init(payload);
    var key_bytes: ?[]const u8 = null;
    var signature: ?[]const u8 = null;
    // Each field consumes at least two bytes, so this loop ends.
    while (reader.next() catch return error.InvalidPayload) |field| {
        if (field.number != 1 and field.number != 2) continue; // Extensions are optional.
        if (field.wire_type != .bytes) return error.InvalidPayload;
        if (field.number == 1) key_bytes = field.bytes else signature = field.bytes;
    }
    const key = identity.decode_public_key(key_bytes orelse return error.InvalidPayload) catch |err|
        return switch (err) {
            error.UnsupportedKeyType => error.UnsupportedKeyType,
            else => error.InvalidPayload,
        };
    const message = signed_message(remote_static);
    const sig = signature orelse return error.InvalidPayload;
    if (!identity.verify(key, &message, sig)) return error.InvalidSignature;
    const remote = peer_id.from_public_key(key);
    assert(remote.secp256k1_public_key() != null);
    return remote;
}

pub const Opened = struct {
    /// Input bytes consumed (prefix + ciphertext).
    consumed: usize,
    plaintext: []u8,
};

/// Post-handshake secure channel: each frame is a 2-byte length then ciphertext + tag.
pub const Transport = struct {
    sender: CipherState,
    receiver: CipherState,
    remote_peer: PeerId,
    handshake_hash: [hash_length]u8,

    /// Seals `plaintext` (at most `plaintext_length_max`) as one frame into `output`.
    pub fn encrypt_frame(transport: *Transport, plaintext: []const u8, output: []u8) Error![]u8 {
        assert(plaintext.len <= plaintext_length_max);
        assert(output.len >= prefix_length + plaintext.len + tag_length);
        assert(transport.sender.has_key);
        const sealed = try transport.sender.encrypt(&.{}, plaintext, output[prefix_length..]);
        assert(sealed.len == plaintext.len + tag_length);
        std.mem.writeInt(u16, output[0..prefix_length], @intCast(sealed.len), .big);
        return output[0 .. prefix_length + sealed.len];
    }

    /// Opens the frame at the front of `input`, or returns null if it is incomplete.
    /// `output` must hold `plaintext_length_max` bytes or at least the frame's plaintext.
    pub fn decrypt_frame(transport: *Transport, input: []const u8, output: []u8) Error!?Opened {
        assert(transport.receiver.has_key);
        if (input.len < prefix_length) return null;
        const length: usize = std.mem.readInt(u16, input[0..prefix_length], .big);
        if (length < tag_length) return error.InvalidMessage;
        if (input.len < prefix_length + length) return null;
        if (output.len < length - tag_length) return error.InvalidMessage;
        const ciphertext = input[prefix_length..][0..length];
        const plaintext = try transport.receiver.decrypt(&.{}, ciphertext, output);
        assert(plaintext.len + tag_length == length);
        return .{ .consumed = prefix_length + length, .plaintext = plaintext };
    }
};

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

fn test_config(prng: *Prng) Config {
    var config: Config = undefined;
    while (true) {
        prng.fill(&config.identity_secret);
        secp256k1.validate_secret_key(config.identity_secret) catch continue;
        break;
    }
    prng.fill(&config.static_seed);
    prng.fill(&config.ephemeral_seed);
    return config;
}

fn expected_peer(config: Config) !PeerId {
    return peer_id.from_public_key(try secp256k1.public_key(config.identity_secret));
}

/// Shuttles handshake bytes in chunks of at most `chunk`; `tamper` flips one byte of the
/// message with that index (1-based) before delivery.
fn run_handshake(initiator: *Handshake, responder: *Handshake, chunk: usize, tamper: u8) !void {
    var to_responder: [1024]u8 = undefined;
    var to_initiator: [1024]u8 = undefined;
    var output: [handshake_output_length_max]u8 = undefined;
    var message: u8 = 1;
    _ = try responder.start(&output);
    const first = try initiator.start(&output);
    @memcpy(to_responder[0..first.len], first);
    var pending: []u8 = to_responder[0..first.len];
    while (pending.len > 0) : (message += 1) {
        if (tamper == message) pending[pending.len - 1] ^= 0x01;
        const receiver = if (message % 2 == 1) responder else initiator;
        const next_buffer = if (message % 2 == 1) &to_initiator else &to_responder;
        var offset: usize = 0;
        var produced: usize = 0;
        while (offset < pending.len) {
            const take = @min(chunk, pending.len - offset);
            const step = try receiver.receive(pending[offset..][0..take], &output);
            offset += step.consumed;
            @memcpy(next_buffer[produced..][0..step.output.len], step.output);
            produced += step.output.len;
        }
        pending = next_buffer[0..produced];
        if (message > 3) return error.TestUnexpectedResult;
    }
}

test "noise: full handshake and transport round trip" {
    var prng = Prng.init(0x6e6f_6973);
    for ([_]usize{ 1, 3, 64, 1024 }) |chunk| {
        const initiator_config = test_config(&prng);
        const responder_config = test_config(&prng);
        var initiator = try Handshake.init(.initiator, initiator_config);
        var responder = try Handshake.init(.responder, responder_config);
        try run_handshake(&initiator, &responder, chunk, 0);
        try std.testing.expectEqual(State.done, initiator.state);
        try std.testing.expectEqual(State.done, responder.state);
        var a = initiator.finish();
        var b = responder.finish();
        try std.testing.expect(a.remote_peer.eql(&try expected_peer(responder_config)));
        try std.testing.expect(b.remote_peer.eql(&try expected_peer(initiator_config)));
        try std.testing.expectEqualSlices(u8, &a.handshake_hash, &b.handshake_hash);
        try expect_round_trip(&a, &b, "hello from the initiator");
        try expect_round_trip(&b, &a, "hello from the responder");
        try expect_round_trip(&a, &b, "");
    }
}

fn expect_round_trip(sender: *Transport, receiver: *Transport, message: []const u8) !void {
    var sealed: [prefix_length + 64 + tag_length]u8 = undefined;
    var opened: [64]u8 = undefined;
    const frame_bytes = try sender.encrypt_frame(message, &sealed);
    try std.testing.expectEqual(message.len + tag_length + prefix_length, frame_bytes.len);
    const short = try receiver.decrypt_frame(frame_bytes[0..1], &opened);
    try std.testing.expectEqual(@as(?Opened, null), short);
    const partial = try receiver.decrypt_frame(frame_bytes[0 .. frame_bytes.len - 1], &opened);
    try std.testing.expectEqual(@as(?Opened, null), partial);
    const result = (try receiver.decrypt_frame(frame_bytes, &opened)).?;
    try std.testing.expectEqual(frame_bytes.len, result.consumed);
    try std.testing.expectEqualSlices(u8, message, result.plaintext);
}

test "noise: tampered handshake messages are rejected" {
    var prng = Prng.init(0x7461_6d70);
    // Message 1 is unauthenticated: tampering it surfaces as a failure on message 2.
    for ([_]u8{ 1, 2, 3 }) |tamper| {
        var initiator = try Handshake.init(.initiator, test_config(&prng));
        var responder = try Handshake.init(.responder, test_config(&prng));
        const result = run_handshake(&initiator, &responder, 7, tamper);
        try std.testing.expectError(error.DecryptFailed, result);
        try std.testing.expect(initiator.state == .failed or responder.state == .failed);
    }
}

test "noise: identity signature over another static key is rejected" {
    var prng = Prng.init(0x7369_676e);
    var initiator = try Handshake.init(.initiator, test_config(&prng));
    var responder = try Handshake.init(.responder, test_config(&prng));
    // The payload still signs the original static key.
    var other_seed: [X25519.seed_length]u8 = undefined;
    prng.fill(&other_seed);
    responder.static = X25519.KeyPair.generateDeterministic(other_seed);
    const result = run_handshake(&initiator, &responder, 1024, 0);
    try std.testing.expectError(error.InvalidSignature, result);
    try std.testing.expectEqual(State.failed, initiator.state);
}

test "noise: verify_payload rejects malformed payloads" {
    const static: [key_length]u8 = @splat(7);
    try std.testing.expectError(error.InvalidPayload, verify_payload(&.{}, static));
    try std.testing.expectError(error.InvalidPayload, verify_payload(&.{ 0x0a, 0x05 }, static));
    var buffer: [128]u8 = undefined;
    var writer = protobuf.Writer.init(&buffer);
    writer.write_bytes_field(1, &.{ 0x08, 0x01, 0x12, 0x01, 0x00 });
    writer.write_bytes_field(2, &.{0x30});
    try std.testing.expectError(error.UnsupportedKeyType, verify_payload(writer.written(), static));
}

test "noise: transport rejects tampering, replays, and short frames" {
    var prng = Prng.init(0x7472_616e);
    var initiator = try Handshake.init(.initiator, test_config(&prng));
    var responder = try Handshake.init(.responder, test_config(&prng));
    try run_handshake(&initiator, &responder, 1024, 0);
    var a = initiator.finish();
    var b = responder.finish();
    var sealed: [prefix_length + 32 + tag_length]u8 = undefined;
    var opened: [32]u8 = undefined;
    const frame_bytes = try a.encrypt_frame("needlefish", &sealed);
    frame_bytes[3] ^= 0x80;
    try std.testing.expectError(error.DecryptFailed, b.decrypt_frame(frame_bytes, &opened));
    frame_bytes[3] ^= 0x80;
    _ = (try b.decrypt_frame(frame_bytes, &opened)).?;
    try std.testing.expectError(error.DecryptFailed, b.decrypt_frame(frame_bytes, &opened));
    try std.testing.expectError(error.InvalidMessage, b.decrypt_frame(&.{ 0, 15 }, &opened));
    a.sender.nonce = std.math.maxInt(u64);
    try std.testing.expectError(error.NonceExhausted, a.encrypt_frame("x", &sealed));
}

test "noise: largest transport frame" {
    var prng = Prng.init(0x6269_6766);
    var initiator = try Handshake.init(.initiator, test_config(&prng));
    var responder = try Handshake.init(.responder, test_config(&prng));
    try run_handshake(&initiator, &responder, 1024, 0);
    var a = initiator.finish();
    var b = responder.finish();
    const State_ = struct {
        var plaintext: [plaintext_length_max]u8 = undefined;
        var sealed: [prefix_length + message_length_max]u8 = undefined;
        var opened: [plaintext_length_max]u8 = undefined;
    };
    prng.fill(&State_.plaintext);
    const frame_bytes = try a.encrypt_frame(&State_.plaintext, &State_.sealed);
    try std.testing.expectEqualSlices(u8, &.{ 0xff, 0xff }, frame_bytes[0..2]);
    const result = (try b.decrypt_frame(frame_bytes, &State_.opened)).?;
    try std.testing.expectEqualSlices(u8, &State_.plaintext, result.plaintext);
}

test "noise: initial symmetric state" {
    const state = SymmetricState.init();
    var expected: [hash_length]u8 = undefined;
    Sha256.hash(protocol_name, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &state.hash);
    try std.testing.expectEqualSlices(u8, protocol_name, &state.chaining_key);
}

fn fuzz_responder(_: void, input: []const u8) anyerror!void {
    var prng = Prng.init(input.len);
    var responder = try Handshake.init(.responder, test_config(&prng));
    var output: [handshake_output_length_max]u8 = undefined;
    _ = try responder.start(&output);
    var offset: usize = 0;
    while (offset < input.len) {
        const step = responder.receive(input[offset..], &output) catch return;
        try std.testing.expect(!step.done);
        try std.testing.expect(step.consumed > 0);
        offset += step.consumed;
    }
}

test "noise: fuzz responder" {
    const message_1 = [_]u8{ 0x00, 0x20 } ++ @as([32]u8, @splat(9)) ++ [_]u8{ 0x00, 0x40 };
    const corpus = [_][]const u8{&message_1};
    try fuzz.run_bytes({}, fuzz_responder, .{
        .input_size_max = 512,
        .iterations = 128,
        .corpus = &corpus,
    });
}

//! Typed request and response messages of the Enclave link (base/base
//! `crates/proof/tee/nitro-enclave/src/protocol.rs`), with their bincode wire encoding.
//!
//! Variant order is the wire format (serde variant indices): requests are `Prove`,
//! `SignerPublicKey`, `SignerAttestation`; responses `Prove`, `SignerPublicKey`,
//! `SignerAttestation`, `Error` (images that predate `Failure`), `Failure`. A preimage key
//! is serde's `PreimageKey { data: [u8; 31], key_type }`, where the key type is the
//! variant index (local = 0 ... precompile = 5), not the wire type byte. The proof result
//! is base/base's `ProofResult` (`Tee { aggregate_proposal, intermediate_roots,
//! tee_signer }` or `Zk { proof_bytes }`).
//!
//! Decoding is zero-copy: byte strings point into the frame; the preimage and root lists
//! are allocated from the caller's (arena) allocator, bounded by `Limits`.

const std = @import("std");
const assert = std.debug.assert;

const bincode = @import("bincode.zig");
const preimage = @import("../../preimage/root.zig");
const service_protocol = @import("../../prover_service/protocol.zig");

pub const Hash = [32]u8;
pub const TeeProofResult = service_protocol.TeeProofResult;
pub const Proposal = service_protocol.Proposal;

/// NSM attestation API limits on `user_data` and `nonce`.
pub const user_data_bytes_max = 512;
pub const nonce_bytes_max = 512;

pub const Limits = struct {
    preimages_max: u32 = 1 << 20,
    /// Longest failure message decoded.
    message_bytes_max: u32 = 64 * 1024,
    /// Longest public key, attestation document, signature or ZK proof decoded.
    blob_bytes_max: u32 = 1 << 30,
};

pub const Preimage = struct {
    key: preimage.Key,
    value: []const u8,
};

pub const AttestationRequest = struct {
    user_data: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
};

pub const Request = union(enum) {
    /// Run the proof pipeline over these witness preimages.
    prove: []const Preimage,
    /// The enclave's 65-byte uncompressed ECDSA public key.
    signer_public_key,
    /// The raw Nitro attestation document (`COSE_Sign1` bytes).
    signer_attestation: AttestationRequest,

    pub fn operation(request: *const Request) []const u8 {
        return switch (request.*) {
            .prove => "prove",
            .signer_public_key => "signer_public_key",
            .signer_attestation => "signer_attestation",
        };
    }

    /// The limits the enclave enforces before running a request.
    pub fn validate(request: *const Request) ?Failure {
        const attestation = switch (request.*) {
            .signer_attestation => |attestation| attestation,
            .prove, .signer_public_key => return null,
        };
        if (attestation.user_data) |data| if (data.len > user_data_bytes_max) {
            return .{ .kind = .invalid_request, .message = "user_data exceeds 512-byte limit" };
        };
        if (attestation.nonce) |nonce| if (nonce.len > nonce_bytes_max) {
            return .{ .kind = .invalid_request, .message = "nonce exceeds 512-byte limit" };
        };
        return null;
    }
};

pub const FailureKind = enum(u8) { invalid_request, proof, attestation };

/// The enclave refused or failed a request.
pub const Failure = struct {
    kind: FailureKind,
    message: []const u8,
};

pub const ProofResult = union(enum) {
    tee: TeeProofResult,
    zk: []const u8,
};

pub const Response = union(enum) {
    prove: ProofResult,
    signer_public_key: []const u8,
    signer_attestation: []const u8,
    /// Untyped failure from enclave images that predate `failure`.
    error_text: []const u8,
    failure: Failure,
};

const key_type_variants = [_]preimage.KeyType{
    .local, .keccak256, .global_generic, .sha256, .blob, .precompile,
};

comptime {
    for (key_type_variants, 1..) |key_type, wire| assert(@backingInt(key_type) == wire);
}

pub const EncodeError = std.Io.Writer.Error;
pub const DecodeError = bincode.DecodeError || std.mem.Allocator.Error;

pub fn encode_request(writer: *std.Io.Writer, request: *const Request) EncodeError!void {
    const encoder: bincode.Encoder = .{ .writer = writer };
    assert(request.* != .prove or request.prove.len <= std.math.maxInt(u64));
    switch (request.*) {
        .prove => |preimages| {
            try encoder.variant(0);
            try encoder.varint(preimages.len);
            for (preimages) |*entry| {
                assert(@backingInt(entry.key.key_type) >= 1);
                try encoder.raw(&entry.key.data);
                try encoder.variant(@backingInt(entry.key.key_type) - 1);
                try encoder.bytes(entry.value);
            }
        },
        .signer_public_key => try encoder.variant(1),
        .signer_attestation => |attestation| {
            try encoder.variant(2);
            try encoder.option_bytes(attestation.user_data);
            try encoder.option_bytes(attestation.nonce);
        },
    }
}

pub fn decode_request(
    arena: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) DecodeError!Request {
    var decoder: bincode.Decoder = .{ .bytes = bytes };
    const request: Request = switch (try decoder.variant()) {
        0 => .{ .prove = try decode_preimages(arena, &decoder, limits) },
        1 => .signer_public_key,
        2 => .{ .signer_attestation = .{
            .user_data = try decoder.option_bytes(limits.blob_bytes_max),
            .nonce = try decoder.option_bytes(limits.blob_bytes_max),
        } },
        else => return error.InvalidTag,
    };
    assert(decoder.offset <= bytes.len);
    return request;
}

fn decode_preimages(
    arena: std.mem.Allocator,
    decoder: *bincode.Decoder,
    limits: Limits,
) DecodeError![]const Preimage {
    // data(31) + key type(1) + value length(1).
    const count = try decoder.sequence(limits.preimages_max, preimage.key.data_size + 2);
    const preimages = try arena.alloc(Preimage, @intCast(count));
    for (preimages) |*entry| {
        const data = try decoder.take(preimage.key.data_size);
        const variant = try decoder.variant();
        if (variant >= key_type_variants.len) return error.InvalidTag;
        entry.key = .{
            .data = data[0..preimage.key.data_size].*,
            .key_type = key_type_variants[variant],
        };
        entry.value = try decoder.bytes_max(limits.blob_bytes_max);
    }
    assert(preimages.len == count);
    return preimages;
}

pub fn encode_response(writer: *std.Io.Writer, response: *const Response) EncodeError!void {
    const encoder: bincode.Encoder = .{ .writer = writer };
    switch (response.*) {
        .prove => |result| {
            try encoder.variant(0);
            try encode_proof_result(encoder, &result);
        },
        .signer_public_key => |key| {
            try encoder.variant(1);
            try encoder.bytes(key);
        },
        .signer_attestation => |document| {
            try encoder.variant(2);
            try encoder.bytes(document);
        },
        .error_text => |text| {
            try encoder.variant(3);
            try encoder.bytes(text);
        },
        .failure => |failure| {
            try encoder.variant(4);
            try encoder.variant(@backingInt(failure.kind));
            try encoder.bytes(failure.message);
        },
    }
}

fn encode_proof_result(encoder: bincode.Encoder, result: *const ProofResult) EncodeError!void {
    switch (result.*) {
        .tee => |tee| {
            assert(tee.intermediate_roots.len <= TeeProofResult.intermediate_roots_max);
            assert(tee.aggregate_proposal.signature.len <= Proposal.signature_max);
            try encoder.variant(0);
            const proposal = &tee.aggregate_proposal;
            try encoder.bytes(&proposal.output_root);
            try encoder.bytes(proposal.signature);
            try encoder.bytes(&proposal.l1_origin_hash);
            try encoder.varint(proposal.l1_origin_number);
            try encoder.varint(proposal.l2_block_number);
            try encoder.bytes(&proposal.prev_output_root);
            try encoder.bytes(&proposal.config_hash);
            try encoder.bytes(&proposal.schedule_id);
            try encoder.varint(tee.intermediate_roots.len);
            for (tee.intermediate_roots) |*root| try encoder.bytes(root);
            try encoder.bytes(&tee.tee_signer);
        },
        .zk => |proof| {
            try encoder.variant(1);
            try encoder.bytes(proof);
        },
    }
}

pub fn decode_response(
    arena: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) DecodeError!Response {
    var decoder: bincode.Decoder = .{ .bytes = bytes };
    const response: Response = switch (try decoder.variant()) {
        0 => .{ .prove = try decode_proof_result(arena, &decoder, limits) },
        1 => .{ .signer_public_key = try decoder.bytes_max(limits.blob_bytes_max) },
        2 => .{ .signer_attestation = try decoder.bytes_max(limits.blob_bytes_max) },
        3 => .{ .error_text = try decoder.string_max(limits.message_bytes_max) },
        4 => .{ .failure = try decode_failure(&decoder, limits) },
        else => return error.InvalidTag,
    };
    assert(decoder.offset <= bytes.len);
    return response;
}

fn decode_failure(decoder: *bincode.Decoder, limits: Limits) DecodeError!Failure {
    const variant = try decoder.variant();
    if (variant > @backingInt(FailureKind.attestation)) return error.InvalidTag;
    const failure: Failure = .{
        .kind = @fromBackingInt(@intCast(variant)),
        .message = try decoder.string_max(limits.message_bytes_max),
    };
    assert(failure.message.len <= limits.message_bytes_max);
    return failure;
}

fn decode_proof_result(
    arena: std.mem.Allocator,
    decoder: *bincode.Decoder,
    limits: Limits,
) DecodeError!ProofResult {
    switch (try decoder.variant()) {
        0 => {},
        1 => return .{ .zk = try decoder.bytes_max(limits.blob_bytes_max) },
        else => return error.InvalidTag,
    }
    var proposal: Proposal = undefined;
    proposal.output_root = try decoder.fixed(32);
    proposal.signature = try decoder.bytes_max(Proposal.signature_max);
    proposal.l1_origin_hash = try decoder.fixed(32);
    proposal.l1_origin_number = try decoder.varint();
    proposal.l2_block_number = try decoder.varint();
    proposal.prev_output_root = try decoder.fixed(32);
    proposal.config_hash = try decoder.fixed(32);
    proposal.schedule_id = try decoder.fixed(32);
    const count = try decoder.sequence(TeeProofResult.intermediate_roots_max, 33);
    const roots = try arena.alloc(Hash, @intCast(count));
    for (roots) |*root| root.* = try decoder.fixed(32);
    const result: TeeProofResult = .{
        .aggregate_proposal = proposal,
        .intermediate_roots = roots,
        .tee_kind = .aws_nitro,
        .tee_signer = try decoder.fixed(20),
    };
    assert(result.intermediate_roots.len == count);
    return .{ .tee = result };
}

const testing = std.testing;
const fuzz = @import("../../../testing/fuzz.zig");

fn encode_to(buffer: []u8, value: anytype) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    switch (@TypeOf(value)) {
        *const Request => try encode_request(&writer, value),
        *const Response => try encode_response(&writer, value),
        else => comptime unreachable,
    }
    return writer.buffered();
}

test "enclave protocol: request wire bytes match bincode serde" {
    var buffer: [256]u8 = undefined;
    const public_key: Request = .signer_public_key;
    try testing.expectEqualSlices(u8, &.{1}, try encode_to(&buffer, &public_key));
    const attestation: Request = .{ .signer_attestation = .{ .nonce = &.{ 0xaa, 0xbb } } };
    const expected_attestation = [_]u8{ 2, 0, 1, 2, 0xaa, 0xbb };
    try testing.expectEqualSlices(u8, &expected_attestation, try encode_to(&buffer, &attestation));
    const key: preimage.Key = .local(1);
    const prove: Request = .{ .prove = &.{.{ .key = key, .value = &.{ 7, 8 } }} };
    const encoded = try encode_to(&buffer, &prove);
    // Variant 0, one entry, 31 data bytes, key type variant 0 (local), value length 2.
    try testing.expectEqual(@as(usize, 1 + 1 + 31 + 1 + 1 + 2), encoded.len);
    try testing.expectEqualSlices(u8, &.{ 0, 1 }, encoded[0..2]);
    try testing.expectEqual(@as(u8, 1), encoded[32]);
    try testing.expectEqualSlices(u8, &.{ 0, 2, 7, 8 }, encoded[33..]);
}

test "enclave protocol: requests round trip" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buffer: [512]u8 = undefined;
    const hash_key: preimage.Key = .keccak256(@splat(0x42));
    const entries = [_]Preimage{
        .{ .key = hash_key, .value = "abc" },
        .{ .key = .local(9), .value = "" },
    };
    const prove: Request = .{ .prove = &entries };
    const decoded = try decode_request(arena.allocator(), try encode_to(&buffer, &prove), .{});
    try testing.expectEqual(@as(usize, 2), decoded.prove.len);
    try testing.expect(decoded.prove[0].key.eql(hash_key));
    try testing.expectEqualStrings("abc", decoded.prove[0].value);
    try testing.expect(decoded.prove[1].key.eql(.local(9)));
    const attestation: Request = .{ .signer_attestation = .{ .user_data = "u" } };
    const back = try decode_request(arena.allocator(), try encode_to(&buffer, &attestation), .{});
    try testing.expectEqualStrings("u", back.signer_attestation.user_data.?);
    try testing.expect(back.signer_attestation.nonce == null);
}

test "enclave protocol: validation limits" {
    const at_limit: [512]u8 = @splat(0);
    const over: [513]u8 = @splat(0);
    const ok: Request = .{ .signer_attestation = .{ .user_data = &at_limit, .nonce = &at_limit } };
    try testing.expect(ok.validate() == null);
    const bad_nonce: Request = .{ .signer_attestation = .{ .nonce = &over } };
    try testing.expectEqual(FailureKind.invalid_request, bad_nonce.validate().?.kind);
    const bad_data: Request = .{ .signer_attestation = .{ .user_data = &over } };
    try testing.expectEqual(FailureKind.invalid_request, bad_data.validate().?.kind);
    try testing.expectEqualStrings("prove", (Request{ .prove = &.{} }).operation());
}

test "enclave protocol: responses round trip" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var buffer: [1024]u8 = undefined;
    const signature: [65]u8 = @splat(0x01);
    const roots = [_]Hash{ @splat(0xaa), @splat(0xbb) };
    const tee: Response = .{ .prove = .{ .tee = .{
        .aggregate_proposal = .{
            .output_root = @splat(1),
            .signature = &signature,
            .l1_origin_hash = @splat(2),
            .l1_origin_number = 300,
            .l2_block_number = 70000,
            .prev_output_root = @splat(3),
            .config_hash = @splat(4),
            .schedule_id = @splat(5),
        },
        .intermediate_roots = &roots,
        .tee_kind = .aws_nitro,
        .tee_signer = @splat(6),
    } } };
    const encoded = try encode_to(&buffer, &tee);
    // Variant 0, Tee 0, output root as a serde byte string.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 32 }, encoded[0..3]);
    const decoded = try decode_response(arena.allocator(), encoded, .{});
    const result = decoded.prove.tee;
    try testing.expectEqual(@as(u64, 70000), result.aggregate_proposal.l2_block_number);
    try testing.expectEqualSlices(u8, &signature, result.aggregate_proposal.signature);
    try testing.expectEqualSlices(Hash, &roots, result.intermediate_roots);
    try testing.expectEqual(@as([20]u8, @splat(6)), result.tee_signer);
    const failure: Response = .{ .failure = .{ .kind = .attestation, .message = "no nsm" } };
    const failed = try decode_response(arena.allocator(), try encode_to(&buffer, &failure), .{});
    try testing.expectEqual(FailureKind.attestation, failed.failure.kind);
    try testing.expectEqualStrings("no nsm", failed.failure.message);
    const zk: Response = .{ .prove = .{ .zk = "proof" } };
    const zk_back = try decode_response(arena.allocator(), try encode_to(&buffer, &zk), .{});
    try testing.expectEqualStrings("proof", zk_back.prove.zk);
}

test "enclave protocol: malformed messages are refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    try testing.expectError(error.InvalidTag, decode_request(allocator, &.{3}, .{}));
    try testing.expectError(error.UnexpectedEnd, decode_request(allocator, &.{}, .{}));
    try testing.expectError(error.InvalidTag, decode_request(allocator, &.{ 2, 2 }, .{}));
    // A preimage count larger than the bytes behind it.
    try testing.expectError(error.UnexpectedEnd, decode_request(allocator, &.{ 0, 200 }, .{}));
    try testing.expectError(error.TooMany, decode_request(allocator, &.{ 0, 2 }, .{
        .preimages_max = 1,
    }));
    try testing.expectError(error.InvalidTag, decode_response(allocator, &.{5}, .{}));
    try testing.expectError(error.InvalidUtf8, decode_response(allocator, &.{ 3, 1, 0xff }, .{}));
    try testing.expectError(error.InvalidTag, decode_response(allocator, &.{ 4, 3, 0 }, .{}));
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const len = smith.slice(&input);
    var buffer: [4096]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&buffer);
    const limits: Limits = .{ .preimages_max = 16, .message_bytes_max = 128 };
    if (decode_request(fixed.allocator(), input[0..len], limits)) |request| {
        // What decodes re-encodes to a prefix of the input (trailing bytes are ignored).
        var out: [1024]u8 = undefined;
        const encoded = try encode_to(&out, &request);
        try testing.expect(encoded.len <= len);
    } else |_| {}
    fixed.reset();
    if (decode_response(fixed.allocator(), input[0..len], limits)) |response| {
        var out: [1024]u8 = undefined;
        const encoded = try encode_to(&out, &response);
        try testing.expect(encoded.len <= len);
    } else |_| {}
}

test "enclave protocol: seeded fuzz decoders" {
    try fuzz.run({}, fuzz_decode, .{ .iterations = 1024, .input_size_max = 512 });
}

//! EIP-4844 blob sidecars and the pooled (network) form of blob transactions, as gossiped
//! over devp2p and accepted by `eth_sendRawTransaction`:
//!
//!   v0 (EIP-4844): 0x03 || rlp([tx_payload_body, blobs, commitments, proofs])
//!   v1 (EIP-7594): 0x03 || rlp([tx_payload_body, 1, blobs, commitments, cell_proofs])
//!
//! `tx_payload_body` is the signed list `[fields..., y_parity, r, s]`. Like the other
//! list fields, blobs/commitments/proofs keep their validated RLP payload and are read
//! by index, so decoding a 6-blob transaction (768 KiB) copies nothing.
//!
//! KZG proof verification is not done here (the crypto lane exposes point evaluation
//! only so far); `Sidecar.validate` checks counts and commitment -> versioned hash.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const tx_module = @import("tx.zig");
const kzg = @import("../crypto/kzg/root.zig");
const kzg_blob = kzg.blob;
const B256 = primitives.B256;
const Encoder = rlp.Encoder;
const Decoder = rlp.Decoder;
const HashList = tx_module.HashList;
const Eip4844 = tx_module.Eip4844;
const SignedBlobTx = tx_module.Signed(Eip4844);

pub const bytes_per_blob = kzg.bytes_per_blob;
pub const bytes_per_commitment = kzg.bytes_per_commitment;
pub const bytes_per_proof = kzg.bytes_per_proof;
/// EIP-7594: one KZG proof per cell of the extended blob.
pub const cells_per_ext_blob = 128;
/// Upper bound on blobs in one transaction (EIP-7594 / Osaka per-tx limit is 6; leave
/// headroom for blob-parameter-only forks but keep every loop bounded).
pub const blobs_per_tx_max = 64;

/// A list of fixed-size byte strings, stored as its validated RLP payload.
pub fn FixedList(comptime size: usize) type {
    return struct {
        const Self = @This();
        pub const item_size = size;
        const header_size = rlp.header_length(size);
        const stride = header_size + size;

        payload: []const u8 = &.{},

        pub fn count(list: Self) usize {
            assert(list.payload.len % stride == 0);
            return list.payload.len / stride;
        }

        pub fn get(list: Self, index: usize) *const [size]u8 {
            assert(index < list.count());
            return list.payload[index * stride + header_size ..][0..size];
        }

        pub fn from_payload(payload: []const u8) rlp.Error!Self {
            if (payload.len % stride != 0) return error.Overflow;
            var decoder = Decoder.init(payload);
            // Bounded: one item per stride.
            while (!decoder.is_empty()) {
                const item = try decoder.bytes();
                if (item.len != size) return error.Overflow;
            }
            return .{ .payload = payload };
        }

        /// Writes `items` as a payload into `buffer` (`stride` bytes each).
        pub fn build(buffer: []u8, items: []const [size]u8) Self {
            assert(buffer.len >= items.len * stride);
            var encoder = Encoder.init(buffer);
            for (items) |*item| encoder.bytes(item);
            assert(encoder.position == items.len * stride);
            return .{ .payload = encoder.written() };
        }

        pub fn rlp_length(list: Self) usize {
            return rlp.list_length(list.payload.len);
        }

        pub fn rlp_encode(list: Self, encoder: *Encoder) void {
            encoder.list_header(list.payload.len);
            encoder.raw(list.payload);
        }

        pub fn rlp_decode(decoder: *Decoder) rlp.Error!Self {
            const items = try decoder.list();
            return from_payload(items.input);
        }
    };
}

pub const BlobList = FixedList(bytes_per_blob);
pub const CommitmentList = FixedList(bytes_per_commitment);
pub const ProofList = FixedList(bytes_per_proof);

pub const WrapperVersion = enum(u8) {
    /// EIP-4844: one blob proof per blob.
    eip4844 = 0,
    /// EIP-7594 (PeerDAS): `cells_per_ext_blob` cell proofs per blob.
    eip7594 = 1,

    pub fn proofs_per_blob(version: WrapperVersion) usize {
        return switch (version) {
            .eip4844 => 1,
            .eip7594 => cells_per_ext_blob,
        };
    }
};

pub const ValidateError = error{
    NoBlobs,
    TooManyBlobs,
    BlobCountMismatch,
    ProofCountMismatch,
    VersionedHashMismatch,
};

pub const KzgError = error{
    /// EIP-7594 cell proofs: verification lands with the crypto lane's cell API.
    CellProofsUnsupported,
    /// A blob element is not canonical, or a commitment or proof is not a valid point.
    InvalidKzgInput,
    /// The proofs do not open the commitments to the blobs.
    KzgProofMismatch,
};

/// Long-lived KZG state: the decoded trusted setup plus scratch (about 1.1 MiB in all;
/// keep it in static memory or on the heap). One verifier serves one call at a time.
pub const KzgVerifier = struct {
    settings: *const kzg_blob.Settings,
    workspace: *kzg_blob.Workspace,
    batch: *kzg_blob.BatchStorage(blobs_per_tx_max),
};

pub const Sidecar = struct {
    version: WrapperVersion = .eip4844,
    blobs: BlobList = .{},
    commitments: CommitmentList = .{},
    proofs: ProofList = .{},

    /// Structure against the transaction's versioned hashes (no KZG verification).
    pub fn validate(sidecar: Sidecar, hashes: HashList) ValidateError!void {
        const blob_count = sidecar.blobs.count();
        if (blob_count == 0) return error.NoBlobs;
        if (blob_count > blobs_per_tx_max) return error.TooManyBlobs;
        if (hashes.count() != blob_count) return error.BlobCountMismatch;
        if (sidecar.commitments.count() != blob_count) return error.BlobCountMismatch;
        const proofs_expected = blob_count * sidecar.version.proofs_per_blob();
        if (sidecar.proofs.count() != proofs_expected) return error.ProofCountMismatch;
        for (0..blob_count) |index| {
            const expected = kzg.versioned_hash(sidecar.commitments.get(index));
            if (!std.mem.eql(u8, &expected, &hashes.get(index).bytes)) {
                return error.VersionedHashMismatch;
            }
        }
    }

    /// Verifies every blob proof in one batched pairing check. Call after `validate`.
    pub fn verify_kzg(sidecar: Sidecar, verifier: KzgVerifier) KzgError!void {
        if (sidecar.version != .eip4844) return error.CellProofsUnsupported;
        const count = sidecar.blobs.count();
        assert(count <= blobs_per_tx_max);
        assert(sidecar.commitments.count() == count and sidecar.proofs.count() == count);
        var blobs: [blobs_per_tx_max]*const kzg_blob.Blob = undefined;
        var commitments: [blobs_per_tx_max]kzg_blob.Commitment = undefined;
        var proofs: [blobs_per_tx_max]kzg_blob.Proof = undefined;
        for (0..count) |index| {
            blobs[index] = sidecar.blobs.get(index);
            commitments[index] = sidecar.commitments.get(index).*;
            proofs[index] = sidecar.proofs.get(index).*;
        }
        const valid = kzg_blob.verify_blob_kzg_proof_batch(
            verifier.settings,
            verifier.workspace,
            verifier.batch.scratch(),
            blobs[0..count],
            commitments[0..count],
            proofs[0..count],
        ) catch |err| return switch (err) {
            error.InvalidFieldElement, error.InvalidPoint => error.InvalidKzgInput,
            error.ScratchTooSmall => unreachable, // Storage holds blobs_per_tx_max blobs.
            error.InvalidInputLength => unreachable, // All three slices hold `count` items.
        };
        if (!valid) return error.KzgProofMismatch;
    }

    fn version_length(sidecar: Sidecar) usize {
        return if (sidecar.version == .eip4844) 0 else 1;
    }

    /// Length of the sidecar items that follow `tx_payload_body` in the outer list.
    pub fn fields_length(sidecar: Sidecar) usize {
        return sidecar.version_length() + sidecar.blobs.rlp_length() +
            sidecar.commitments.rlp_length() + sidecar.proofs.rlp_length();
    }

    pub fn encode_fields(sidecar: Sidecar, encoder: *Encoder) void {
        if (sidecar.version != .eip4844) encoder.int(@backingInt(sidecar.version));
        sidecar.blobs.rlp_encode(encoder);
        sidecar.commitments.rlp_encode(encoder);
        sidecar.proofs.rlp_encode(encoder);
    }

    /// Decodes the items after `tx_payload_body`; v1 starts with the version integer.
    pub fn decode_fields(items: *Decoder) tx_module.DecodeError!Sidecar {
        var sidecar: Sidecar = .{};
        const header = try items.peek_header();
        if (!header.list) {
            const version = try items.int(u8);
            if (version != @backingInt(WrapperVersion.eip7594)) return error.InvalidEnvelope;
            sidecar.version = .eip7594;
        }
        sidecar.blobs = try BlobList.rlp_decode(items);
        sidecar.commitments = try CommitmentList.rlp_decode(items);
        sidecar.proofs = try ProofList.rlp_decode(items);
        return sidecar;
    }
};

/// A blob transaction with its sidecar, in the pooled network encoding.
pub const PooledBlobTx = struct {
    signed: SignedBlobTx,
    sidecar: Sidecar,

    fn payload_length(pooled: PooledBlobTx) usize {
        const body = tx_module.signed_payload_length(Eip4844, pooled.signed);
        return rlp.list_length(body) + pooled.sidecar.fields_length();
    }

    /// Length of `0x03 || rlp([...])`.
    pub fn encoded_length(pooled: PooledBlobTx) usize {
        return 1 + rlp.list_length(pooled.payload_length());
    }

    pub fn encode(pooled: PooledBlobTx, encoder: *Encoder) void {
        const start = encoder.position;
        encoder.raw(&.{@backingInt(tx_module.TxType.eip4844)});
        encoder.list_header(pooled.payload_length());
        tx_module.encode_signed_list(Eip4844, encoder, pooled.signed);
        pooled.sidecar.encode_fields(encoder);
        assert(encoder.position - start == pooled.encoded_length());
    }

    pub fn encode_to(pooled: PooledBlobTx, buffer: []u8) []u8 {
        var encoder = Encoder.init(buffer);
        pooled.encode(&encoder);
        return encoder.written();
    }

    /// Decodes exactly one pooled blob transaction (structure only; see `validate`).
    pub fn decode(encoded: []const u8) tx_module.DecodeError!PooledBlobTx {
        if (encoded.len == 0) return error.UnexpectedEnd;
        if (encoded[0] != @backingInt(tx_module.TxType.eip4844)) return error.InvalidEnvelope;
        var decoder = Decoder.init(encoded[1..]);
        var items = try decoder.list();
        try decoder.finish();
        const body_header = try items.peek_header();
        if (!body_header.list) return error.InvalidEnvelope;
        const signed = try tx_module.decode_signed_list(Eip4844, try items.raw());
        const sidecar = try Sidecar.decode_fields(&items);
        try items.finish();
        return .{ .signed = signed, .sidecar = sidecar };
    }

    pub fn validate(pooled: PooledBlobTx) ValidateError!void {
        try pooled.sidecar.validate(pooled.signed.tx.blob_versioned_hashes);
    }

    /// The canonical (block) transaction, without the sidecar.
    pub fn envelope(pooled: PooledBlobTx) tx_module.Envelope {
        return .{ .eip4844 = pooled.signed };
    }

    /// The transaction hash: the sidecar is not part of it.
    pub fn hash(pooled: PooledBlobTx) B256 {
        return pooled.envelope().hash();
    }
};

/// Any transaction as submitted to the pool: blob txs must carry their sidecar.
pub const PooledTx = union(enum) {
    plain: tx_module.Envelope,
    blob: PooledBlobTx,

    pub const DecodeError = tx_module.DecodeError || error{NotPoolable};

    pub fn decode(encoded: []const u8) PooledTx.DecodeError!PooledTx {
        if (encoded.len > 0 and encoded[0] == @backingInt(tx_module.TxType.eip4844)) {
            return .{ .blob = try PooledBlobTx.decode(encoded) };
        }
        const envelope = try tx_module.Envelope.decode(encoded);
        if (envelope == .deposit) return error.NotPoolable;
        return .{ .plain = envelope };
    }

    pub fn hash(pooled: PooledTx) B256 {
        return switch (pooled) {
            .plain => |envelope| envelope.hash(),
            .blob => |blob| blob.hash(),
        };
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const dev_key = [32]u8{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};

/// Builds a pooled tx with `blob_count` blobs into `arena` (structure, not real KZG).
const Fixture = struct {
    pooled: PooledBlobTx,

    fn init(
        allocator: std.mem.Allocator,
        prng: *Prng,
        blob_count: usize,
        version: WrapperVersion,
    ) !Fixture {
        const blobs = try allocator.alloc([bytes_per_blob]u8, blob_count);
        const commitments = try allocator.alloc([bytes_per_commitment]u8, blob_count);
        const proof_count = blob_count * version.proofs_per_blob();
        const proofs = try allocator.alloc([bytes_per_proof]u8, proof_count);
        const hashes = try allocator.alloc(B256, blob_count);
        for (blobs) |*blob| prng.fill(blob[0..256]);
        for (blobs) |*blob| @memset(blob[256..], 0);
        for (commitments, hashes) |*commitment, *hash| {
            prng.fill(commitment);
            hash.bytes = kzg.versioned_hash(commitment);
        }
        for (proofs) |*proof| prng.fill(proof);
        const stride_blob = BlobList.stride;
        const stride_small = CommitmentList.stride;
        const hash_buffer = try allocator.alloc(u8, blob_count * 33);
        const tx: Eip4844 = .{
            .chain_id = 8453,
            .nonce = prng.int(u32),
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 1_000_000_000,
            .gas_limit = 21_000,
            .to = primitives.Address.comptime_hex("00000000000000000000000000000000000000aa"),
            .value = prng.int(u64),
            .input = &.{},
            .access_list = .{},
            .max_fee_per_blob_gas = 7,
            .blob_versioned_hashes = HashList.build(hash_buffer, hashes),
        };
        const envelope = try tx_module.sign(tx, dev_key);
        return .{ .pooled = .{ .signed = envelope.eip4844, .sidecar = .{
            .version = version,
            .blobs = BlobList.build(try allocator.alloc(u8, blob_count * stride_blob), blobs),
            .commitments = CommitmentList.build(
                try allocator.alloc(u8, blob_count * stride_small),
                commitments,
            ),
            .proofs = ProofList.build(try allocator.alloc(u8, proof_count * stride_small), proofs),
        } } };
    }
};

fn round_trip(allocator: std.mem.Allocator, pooled: PooledBlobTx) ![]u8 {
    const buffer = try allocator.alloc(u8, pooled.encoded_length());
    const encoded = pooled.encode_to(buffer);
    try testing.expectEqual(buffer.len, encoded.len);
    const decoded = try PooledBlobTx.decode(encoded);
    try testing.expectEqual(pooled.sidecar.version, decoded.sidecar.version);
    try testing.expectEqualSlices(u8, pooled.sidecar.blobs.payload, decoded.sidecar.blobs.payload);
    try testing.expect(decoded.hash().eql(pooled.hash()));
    try decoded.validate();
    const reencoded = try allocator.alloc(u8, decoded.encoded_length());
    try testing.expectEqualSlices(u8, encoded, decoded.encode_to(reencoded));
    return encoded;
}

test "sidecar: v0 and v1 round trip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var prng = Prng.init(0x4844);
    for ([_]WrapperVersion{ .eip4844, .eip7594 }) |version| {
        const fixture = try Fixture.init(allocator, &prng, 2, version);
        const encoded = try round_trip(allocator, fixture.pooled);
        // The sidecar is not part of the transaction hash.
        const canonical = try allocator.alloc(u8, fixture.pooled.envelope().encoded_length());
        _ = fixture.pooled.envelope().encode_to(canonical);
        try testing.expect(fixture.pooled.hash().eql(primitives.keccak256(canonical)));
        const pool = try PooledTx.decode(encoded);
        try testing.expect(pool == .blob);
        try testing.expect(pool.hash().eql(fixture.pooled.hash()));
        // The canonical form is not a pooled blob transaction.
        try testing.expectError(error.InvalidEnvelope, PooledBlobTx.decode(canonical));
    }
}

test "sidecar: validation failures" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var prng = Prng.init(0x7594);
    const fixture = try Fixture.init(allocator, &prng, 3, .eip4844);
    const hashes = fixture.pooled.signed.tx.blob_versioned_hashes;
    var sidecar = fixture.pooled.sidecar;
    try sidecar.validate(hashes);
    sidecar.version = .eip7594;
    try testing.expectError(error.ProofCountMismatch, sidecar.validate(hashes));
    sidecar = fixture.pooled.sidecar;
    sidecar.commitments.payload = sidecar.commitments.payload[0 .. 2 * CommitmentList.stride];
    try testing.expectError(error.BlobCountMismatch, sidecar.validate(hashes));
    sidecar = fixture.pooled.sidecar;
    try testing.expectError(error.NoBlobs, (Sidecar{}).validate(hashes));
    const reordered = try allocator.dupe(u8, hashes.payload);
    std.mem.swap([33]u8, reordered[0..33], reordered[33..66]);
    const bad: HashList = .{ .payload = reordered };
    try testing.expectError(error.VersionedHashMismatch, sidecar.validate(bad));
}

test "sidecar: pooled plain and deposit" {
    var buffer: [256]u8 = undefined;
    const tx: tx_module.Eip1559 = .{
        .chain_id = 8453,
        .nonce = 1,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 2,
        .gas_limit = 21_000,
        .to = .create,
        .value = 0,
        .input = &.{},
        .access_list = .{},
    };
    const envelope = try tx_module.sign(tx, dev_key);
    const pool = try PooledTx.decode(envelope.encode_to(&buffer));
    try testing.expect(pool.hash().eql(envelope.hash()));
    const deposit: tx_module.Envelope = .{ .deposit = .{
        .source_hash = .zero,
        .from = .zero,
        .to = .create,
        .mint = 0,
        .value = 0,
        .gas_limit = 1,
        .is_system_transaction = false,
        .input = &.{},
    } };
    try testing.expectError(error.NotPoolable, PooledTx.decode(deposit.encode_to(&buffer)));
}

fn decode_any(input: []const u8) !void {
    const pooled = PooledTx.decode(input) catch return;
    if (pooled == .blob) {
        pooled.blob.validate() catch {};
        var buffer: [8192]u8 = undefined;
        if (pooled.blob.encoded_length() > buffer.len) return;
        try testing.expectEqualSlices(u8, input, pooled.blob.encode_to(&buffer));
    }
}

test "sidecar: seeded fuzz mutations" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var prng = Prng.init(0xb10b);
    const fixture = try Fixture.init(arena.allocator(), &prng, 1, .eip7594);
    const encoded = try round_trip(arena.allocator(), fixture.pooled);
    const mutated = try arena.allocator().alloc(u8, encoded.len);
    for (0..32) |_| {
        @memcpy(mutated, encoded);
        // Mutate the header region, where structure lives.
        for (0..prng.range(1, 4)) |_| mutated[prng.below(256)] = prng.int(u8);
        decode_any(mutated[0..prng.range(1, mutated.len)]) catch |err| return err;
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    try decode_any(input[0..smith.slice(&input)]);
}

test "sidecar: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

// KZG tests decode the 4096-point setup and run pairings: too slow for debug builds,
// matching the crypto lane's `heavy_tests` gate.
const heavy_tests = @import("builtin").mode != .debug;
var test_kzg_storage: kzg_blob.Settings.Storage = undefined;
var test_kzg_workspace: kzg_blob.Workspace = undefined;
var test_kzg_batch: kzg_blob.BatchStorage(blobs_per_tx_max) = .{};
var test_kzg_settings: ?kzg_blob.Settings = null;

fn test_verifier() !KzgVerifier {
    if (test_kzg_settings == null) {
        test_kzg_settings = try kzg_blob.Settings.init(&test_kzg_storage);
    }
    return .{
        .settings = &test_kzg_settings.?,
        .workspace = &test_kzg_workspace,
        .batch = &test_kzg_batch,
    };
}

var test_blobs: [2]kzg_blob.Blob = undefined;
var test_blob_list: [2 * (bytes_per_blob + 4)]u8 = undefined;

test "sidecar: KZG verification" {
    const v1: Sidecar = .{ .version = .eip7594 };
    const no_verifier: KzgVerifier = undefined;
    try testing.expectError(error.CellProofsUnsupported, v1.verify_kzg(no_verifier));
    if (!heavy_tests) return error.SkipZigTest;
    const verifier = try test_verifier();
    var prng = Prng.init(0x4844);
    var commitments: [2]kzg_blob.Commitment = undefined;
    var proofs: [2]kzg_blob.Proof = undefined;
    for (&test_blobs, &commitments, &proofs) |*blob, *commitment, *proof| {
        // Small field elements are always canonical.
        @memset(blob, 0);
        for (0..kzg_blob.field_elements) |element| blob[element * 32 + 31] = prng.int(u8);
        commitment.* = try kzg_blob.blob_to_kzg_commitment(
            verifier.settings,
            verifier.workspace,
            blob,
        );
        proof.* = try kzg_blob.compute_blob_kzg_proof(
            verifier.settings,
            verifier.workspace,
            blob,
            commitment,
        );
    }
    var commitment_buffer: [128]u8 = undefined;
    var proof_buffer: [128]u8 = undefined;
    var sidecar: Sidecar = .{
        .blobs = BlobList.build(&test_blob_list, &test_blobs),
        .commitments = CommitmentList.build(&commitment_buffer, &commitments),
        .proofs = ProofList.build(&proof_buffer, &proofs),
    };
    try sidecar.verify_kzg(verifier);
    const swapped = [_]kzg_blob.Proof{ proofs[1], proofs[0] };
    sidecar.proofs = ProofList.build(&proof_buffer, &swapped);
    try testing.expectError(error.KzgProofMismatch, sidecar.verify_kzg(verifier));
    var bad_point: kzg_blob.Proof = @splat(0xff);
    bad_point[0] = 0x9f;
    sidecar.proofs = ProofList.build(&proof_buffer, &.{ proofs[0], bad_point });
    try testing.expectError(error.InvalidKzgInput, sidecar.verify_kzg(verifier));
}

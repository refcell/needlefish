//! Stateless validation of raw transactions submitted to the pool
//! (`eth_sendRawTransaction`): decode the pooled encoding (blob transactions carry a
//! sidecar), check chain ID, fork-allowed types, EIP-2 low-s, intrinsic gas and the
//! EIP-7623 calldata floor, init code size and blob sidecar shape, then recover the
//! sender. Produces the `Tx` descriptor the pool stores. Stateful checks (nonce,
//! balance) happen in `Pool.add` against the caller-supplied account.
//!
//! Commitments are checked against the versioned hashes here; `verify_blob_proofs`
//! adds the (expensive) batched KZG proof check with a long-lived verifier.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const txpool = @import("root.zig");

const B256 = primitives.B256;
const Envelope = consensus.Envelope;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const bytes_per_blob = 131_072;
pub const bytes_per_commitment = 48;
pub const bytes_per_proof = 48;
/// EIP-7594 (Osaka) cell proofs per blob.
pub const cell_proofs_per_blob = 128;
pub const init_code_size_max = 49_152;

pub const ValidateError = consensus.tx.DecodeError || error{
    WrongChainId,
    UnprotectedTx,
    TxTypeNotSupported,
    BlobSidecarMissing,
    BlobSidecarInvalid,
    NoBlobs,
    TooManyBlobs,
    EmptyAuthorizationList,
    InvalidSignature,
    IntrinsicGasTooLow,
    InitCodeTooLarge,
    GasLimitExceeded,
    ScratchTooSmall,
    BlobProofInvalid,
};

pub const Sidecar = struct {
    /// Concatenated blobs / commitments / proofs (each an RLP string list payload).
    blob_count: u32,
    commitments: rlp.Decoder,
    /// 1 = EIP-7594 cell proofs, 0 = EIP-4844 blob proofs.
    wrapper_version: u8,
};

pub const Validated = struct {
    tx: txpool.Tx,
    envelope: Envelope,
    sidecar: ?Sidecar,
};

/// Validates `raw` for inclusion at `timestamp` (the next block's time). `scratch`
/// must hold `raw.len` bytes; the returned envelope borrows from `raw` or `scratch`.
pub fn validate(
    raw: []const u8,
    scratch: []u8,
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
    recoverer: consensus.Recoverer,
) ValidateError!Validated {
    const pooled = try decode_pooled(raw, scratch);
    const envelope = pooled.envelope;
    try check_type(envelope, spec, timestamp);
    const chain_id = envelope.chain_id() orelse return error.UnprotectedTx;
    if (chain_id != spec.chain_id) return error.WrongChainId;
    if (envelope.gas_limit() > spec.gas_limit) return error.GasLimitExceeded;
    try check_gas(envelope, spec.spec_at(timestamp));
    if (envelope == .eip4844) try check_sidecar(envelope, pooled.sidecar, spec, timestamp);
    const signature = envelope.signature().?;
    if (!signature.is_in_range() or !signature.is_low_s()) return error.InvalidSignature;
    const sender = envelope.recover_sender(recoverer) orelse return error.InvalidSignature;
    return .{
        .tx = .{
            .hash = envelope.hash(),
            .sender = sender,
            .nonce = envelope.nonce().?,
            .tx_type = @backingInt(envelope.tx_type()),
            .gas_limit = envelope.gas_limit(),
            .max_fee_per_gas = envelope.max_fee_per_gas(),
            .max_priority_fee_per_gas = envelope.max_priority_fee_per_gas(),
            .max_fee_per_blob_gas = blob_fee_cap(envelope),
            .blob_count = @intCast(envelope.blob_versioned_hashes().count()),
            .value = envelope.value(),
            .raw = raw,
        },
        .envelope = envelope,
        .sidecar = pooled.sidecar,
    };
}

fn blob_fee_cap(envelope: Envelope) u128 {
    return if (envelope == .eip4844) envelope.eip4844.tx.max_fee_per_blob_gas else 0;
}

const Pooled = struct { envelope: Envelope, sidecar: ?Sidecar };

/// Pooled encoding: plain EIP-2718 bytes, or for blob transactions
/// `0x03 || rlp([tx_body, (wrapper_version,) blobs, commitments, proofs])`.
pub fn decode_pooled(raw: []const u8, scratch: []u8) ValidateError!Pooled {
    if (raw.len == 0 or raw[0] != @backingInt(consensus.TxType.eip4844)) {
        return .{ .envelope = try Envelope.decode(raw), .sidecar = null };
    }
    var outer = rlp.Decoder.init(raw[1..]);
    var items = try outer.list();
    try outer.finish();
    // Without a nested tx body this is the plain (block-body) form: no sidecar.
    if (!(try items.peek_header()).list) {
        return .{ .envelope = try Envelope.decode(raw), .sidecar = null };
    }
    const body = try items.raw();
    var wrapper_version: u8 = 0;
    if (!(try items.peek_header()).list) {
        wrapper_version = try items.int(u8);
        if (wrapper_version != 1) return error.BlobSidecarInvalid;
    }
    var blobs = try items.list();
    const commitments = try items.list();
    _ = try items.list(); // Proofs: counted in check_sidecar.
    try items.finish();
    var blob_count: u32 = 0;
    while (!blobs.is_empty()) : (blob_count += 1) {
        if ((try blobs.bytes()).len != bytes_per_blob) return error.BlobSidecarInvalid;
    }
    if (scratch.len < body.len + 1) return error.ScratchTooSmall;
    scratch[0] = raw[0];
    @memcpy(scratch[1..][0..body.len], body);
    const envelope = try Envelope.decode(scratch[0 .. body.len + 1]);
    const sidecar: Sidecar = .{
        .blob_count = blob_count,
        .commitments = commitments,
        .wrapper_version = wrapper_version,
    };
    return .{ .envelope = envelope, .sidecar = sidecar };
}

fn check_type(
    envelope: Envelope,
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
) ValidateError!void {
    switch (envelope) {
        // EIP-8130 needs AA execution and Everest gating; not supported yet.
        .deposit, .eip8130 => return error.TxTypeNotSupported,
        .eip4844 => if (spec.blob_params_at(timestamp) == null) return error.TxTypeNotSupported,
        .eip7702 => |signed| {
            if (!spec.is_ethereum_fork_active(.prague, timestamp)) return error.TxTypeNotSupported;
            if (signed.tx.authorization_list.count == 0) return error.EmptyAuthorizationList;
        },
        .legacy, .eip2930, .eip1559 => {},
    }
}

fn check_gas(envelope: Envelope, rules: chainspec.Spec) ValidateError!void {
    const gas = intrinsic_gas(envelope, rules);
    if (envelope.gas_limit() < gas.intrinsic) return error.IntrinsicGasTooLow;
    if (envelope.gas_limit() < gas.floor) return error.IntrinsicGasTooLow;
    const is_create = envelope.kind() == .create;
    const shanghai = @backingInt(rules) >= @backingInt(chainspec.Spec.shanghai);
    if (is_create and shanghai and envelope.input().len > init_code_size_max) {
        return error.InitCodeTooLarge;
    }
}

fn check_sidecar(
    envelope: Envelope,
    sidecar: ?Sidecar,
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
) ValidateError!void {
    const car = sidecar orelse return error.BlobSidecarMissing;
    const hashes = envelope.blob_versioned_hashes();
    if (hashes.count() == 0) return error.NoBlobs;
    const params = spec.blob_params_at(timestamp).?;
    if (hashes.count() > params.max_blob_count) return error.TooManyBlobs;
    if (car.blob_count != hashes.count()) return error.BlobSidecarInvalid;
    // Osaka requires EIP-7594 cell proofs; before it, plain blob proofs.
    const osaka = spec.is_ethereum_fork_active(.osaka, timestamp);
    if (osaka != (car.wrapper_version == 1)) return error.BlobSidecarInvalid;
    var commitments = car.commitments;
    var index: usize = 0;
    while (!commitments.is_empty()) : (index += 1) {
        const commitment = try commitments.bytes();
        if (commitment.len != bytes_per_commitment) return error.BlobSidecarInvalid;
        if (index >= hashes.count()) return error.BlobSidecarInvalid;
        if (!kzg_to_versioned_hash(commitment).eql(hashes.get(index))) {
            return error.BlobSidecarInvalid;
        }
    }
    if (index != hashes.count()) return error.BlobSidecarInvalid;
}

/// Verifies the EIP-4844 blob proofs of a pooled blob transaction that passed
/// `validate`. EIP-7594 cell proofs cannot be verified yet and are accepted (the dev
/// chain keeps Osaka off).
pub fn verify_blob_proofs(
    raw: []const u8,
    verifier: consensus.sidecar.KzgVerifier,
) ValidateError!void {
    assert(raw.len > 0 and raw[0] == @backingInt(consensus.TxType.eip4844));
    var outer = rlp.Decoder.init(raw[1..]);
    var items = try outer.list();
    _ = try items.raw(); // The transaction body.
    const sidecar = consensus.Sidecar.decode_fields(&items) catch {
        return error.BlobSidecarInvalid;
    };
    sidecar.verify_kzg(verifier) catch |err| switch (err) {
        error.CellProofsUnsupported => return,
        error.InvalidKzgInput, error.KzgProofMismatch => return error.BlobProofInvalid,
    };
}

pub fn kzg_to_versioned_hash(commitment: []const u8) B256 {
    assert(commitment.len == bytes_per_commitment);
    var out: B256 = undefined;
    Sha256.hash(commitment, &out.bytes, .{});
    out.bytes[0] = 0x01;
    return out;
}

pub const IntrinsicGas = struct { intrinsic: u64, floor: u64 };

/// Intrinsic gas (Frontier → Prague) and the EIP-7623 calldata floor (Prague+).
pub fn intrinsic_gas(envelope: Envelope, rules: chainspec.Spec) IntrinsicGas {
    const input = envelope.input();
    const zeros: u64 = std.mem.count(u8, input, &.{0});
    const non_zeros: u64 = input.len - zeros;
    var gas: u64 = 21_000 + zeros * 4 + non_zeros * 16;
    if (envelope.kind() == .create) {
        gas += 32_000;
        if (@backingInt(rules) >= @backingInt(chainspec.Spec.shanghai)) {
            gas += 2 * ((input.len + 31) / 32); // EIP-3860 init code words.
        }
    }
    const access_list = envelope.access_list();
    gas += @as(u64, access_list.address_count) * 2_400;
    gas += @as(u64, access_list.storage_key_count) * 1_900;
    if (envelope == .eip7702) {
        gas += @as(u64, envelope.eip7702.tx.authorization_list.count) * 25_000;
    }
    const prague = @backingInt(rules) >= @backingInt(chainspec.Spec.prague);
    const floor: u64 = if (prague) 21_000 + 10 * (zeros + 4 * non_zeros) else 0;
    assert(gas >= 21_000);
    return .{ .intrinsic = gas, .floor = floor };
}

const testing = std.testing;
/// Trivial test scalar (not a real account key).
const test_key: [32]u8 = blk: {
    var key: [32]u8 = @splat(0);
    key[31] = 7;
    break :blk key;
};

fn run(raw: []const u8, scratch: []u8, spec: *const chainspec.ChainSpec) !Validated {
    return validate(raw, scratch, spec, 1, consensus.recover_address);
}

fn signed_1559(buffer: []u8, chain_id: u64, gas_limit: u64, input: []const u8) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = chain_id,
        .nonce = 3,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 10,
        .gas_limit = gas_limit,
        .to = .{ .call = primitives.Address.zero },
        .value = 5,
        .input = input,
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, test_key);
    return envelope.encode_to(buffer);
}

test "validate: eip1559 happy path and descriptor" {
    var buffer: [256]u8 = undefined;
    var scratch: [256]u8 = undefined;
    const spec = &chainspec.ChainSpec.presets.base_devnet;
    const raw = try signed_1559(&buffer, spec.chain_id, 21_000, &.{});
    const v = try run(raw, &scratch, spec);
    try testing.expectEqual(@as(u64, 3), v.tx.nonce);
    try testing.expectEqual(@as(u8, 2), v.tx.tx_type);
    try testing.expectEqual(@as(u256, 5), v.tx.value);
    try testing.expect(v.tx.hash.eql(primitives.keccak256(raw)));
    try testing.expect(!v.tx.sender.is_zero());
}

test "validate: chain id, intrinsic gas, floor" {
    var buffer: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    const spec = &chainspec.ChainSpec.presets.base_devnet;
    const wrong = try signed_1559(&buffer, 1, 21_000, &.{});
    try testing.expectError(error.WrongChainId, run(wrong, &scratch, spec));
    const low = try signed_1559(&buffer, spec.chain_id, 20_999, &.{});
    try testing.expectError(error.IntrinsicGasTooLow, run(low, &scratch, spec));
    // 100 non-zero bytes: intrinsic 22_600, Prague floor 25_000.
    const data: [100]u8 = @splat(1);
    const floor = try signed_1559(&buffer, spec.chain_id, 24_999, &data);
    try testing.expectError(error.IntrinsicGasTooLow, run(floor, &scratch, spec));
    const ok = try signed_1559(&buffer, spec.chain_id, 25_000, &data);
    _ = try run(ok, &scratch, spec);
    const big = try signed_1559(&buffer, spec.chain_id, spec.gas_limit + 1, &.{});
    try testing.expectError(error.GasLimitExceeded, run(big, &scratch, spec));
}

test "validate: blob tx rejected on L2, sidecar required on L1" {
    var buffer: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    var hash_buffer: [64]u8 = undefined;
    const tx: consensus.Eip4844 = .{
        .chain_id = 1337,
        .nonce = 0,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 10,
        .gas_limit = 21_000,
        .to = primitives.Address.zero,
        .value = 0,
        .input = &.{},
        .access_list = .empty,
        .max_fee_per_blob_gas = 1,
        .blob_versioned_hashes = consensus.HashList.build(&hash_buffer, &.{B256.zero}),
    };
    const envelope = try consensus.tx.sign(tx, test_key);
    const raw = envelope.encode_to(&buffer);
    const l1 = &chainspec.ChainSpec.presets.l1_dev;
    try testing.expectError(error.BlobSidecarMissing, run(raw, &scratch, l1));
    const l2 = &chainspec.ChainSpec.presets.base_devnet;
    try testing.expectError(error.TxTypeNotSupported, run(raw, &scratch, l2));
}

test "validate: versioned hash" {
    const commitment: [48]u8 = @splat(0xc0);
    const h = kzg_to_versioned_hash(&commitment);
    try testing.expectEqual(@as(u8, 1), h.bytes[0]);
}

fn fuzz_validate(_: void, smith: *testing.Smith) anyerror!void {
    var raw: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;
    const len = smith.slice(&raw);
    const spec = &chainspec.ChainSpec.presets.l1_dev;
    _ = validate(raw[0..len], &scratch, spec, 1, consensus.recover_address) catch {};
}

test "validate: fuzz" {
    try testing.fuzz({}, fuzz_validate, .{});
}

test "validate: seeded fuzz mutations of a valid tx" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x7a11d);
    var buffer: [256]u8 = undefined;
    var scratch: [256]u8 = undefined;
    const spec = &chainspec.ChainSpec.presets.base_devnet;
    const raw = try signed_1559(&buffer, spec.chain_id, 30_000, "hello");
    var mutated: [256]u8 = undefined;
    for (0..300) |_| {
        @memcpy(mutated[0..raw.len], raw);
        const flips = prng.range(1, 4);
        for (0..flips) |_| mutated[prng.below(raw.len)] ^= @intCast(prng.range(1, 255));
        const len = raw.len - prng.below(3);
        _ = run(mutated[0..len], &scratch, spec) catch {};
    }
}

const kzg_blob = @import("../../common/crypto/kzg/root.zig").blob;
var test_kzg_storage: kzg_blob.Settings.Storage = undefined;
var test_kzg_workspace: kzg_blob.Workspace = undefined;
var test_kzg_batch: kzg_blob.BatchStorage(consensus.sidecar.blobs_per_tx_max) = .{};
var test_blob: kzg_blob.Blob = undefined;
var test_blob_list: [bytes_per_blob + 8]u8 = undefined;
var test_pooled: [bytes_per_blob + 1024]u8 = undefined;
var test_scratch: [1024]u8 = undefined;

test "validate: blob proofs verified with KZG" {
    // Decoding the setup and proving take seconds in Debug builds.
    if (@import("builtin").mode == .debug) return error.SkipZigTest;
    const settings = try kzg_blob.Settings.init(&test_kzg_storage);
    const verifier: consensus.sidecar.KzgVerifier = .{
        .settings = &settings,
        .workspace = &test_kzg_workspace,
        .batch = &test_kzg_batch,
    };
    @memset(&test_blob, 0);
    for (0..kzg_blob.field_elements) |element| test_blob[element * 32 + 31] = @truncate(element);
    const workspace = &test_kzg_workspace;
    const commitment = try kzg_blob.blob_to_kzg_commitment(&settings, workspace, &test_blob);
    var proof = try kzg_blob.compute_blob_kzg_proof(
        &settings,
        &test_kzg_workspace,
        &test_blob,
        &commitment,
    );
    for (0..2) |round| {
        if (round == 1) proof[47] ^= 1; // A wrong proof (or an invalid point).
        var hash_buffer: [64]u8 = undefined;
        const tx: consensus.Eip4844 = .{
            .chain_id = 1337,
            .nonce = 0,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 10,
            .gas_limit = 21_000,
            .to = primitives.Address.zero,
            .value = 0,
            .input = &.{},
            .access_list = .empty,
            .max_fee_per_blob_gas = 1,
            .blob_versioned_hashes = consensus.HashList.build(
                &hash_buffer,
                &.{kzg_to_versioned_hash(&commitment)},
            ),
        };
        const envelope = try consensus.tx.sign(tx, test_key);
        var commitment_list: [64]u8 = undefined;
        var proof_list: [64]u8 = undefined;
        const pooled: consensus.PooledBlobTx = .{ .signed = envelope.eip4844, .sidecar = .{
            .blobs = consensus.sidecar.BlobList.build(&test_blob_list, &.{test_blob}),
            .commitments = consensus.sidecar.CommitmentList.build(&commitment_list, &.{commitment}),
            .proofs = consensus.sidecar.ProofList.build(&proof_list, &.{proof}),
        } };
        const raw = pooled.encode_to(&test_pooled);
        const l1 = &chainspec.ChainSpec.presets.l1_dev;
        _ = try validate(raw, &test_scratch, l1, 1, consensus.recover_address);
        const result = verify_blob_proofs(raw, verifier);
        if (round == 0) try result else try testing.expectError(error.BlobProofInvalid, result);
    }
}

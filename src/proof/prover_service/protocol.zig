//! The prover service protocol (base/base `crates/proof/prover-service/protocol/src/
//! {api,types,session}.rs`): the `prover_*` JSON-RPC method names, the request and response
//! types, the error codes and messages, and the proof session id derivation.
//!
//! Types mirror the serde structs field for field and in the same order, so `codec.zig`
//! writes the same JSON as base/base. Strings are bounded `Text` values (zero-padded, so
//! `std.meta.eql` compares them); byte strings and lists are slices into the decoder's
//! arena. Left out: `deleteProofsByTeeSigner` and `ExecutionStats` (see the lane file).

const std = @import("std");
const assert = std.debug.assert;

pub const Hash = [32]u8;
pub const Address = [20]u8;

/// JSON-RPC method names (`namespace = "prover"`).
pub const method = struct {
    pub const prove_block_range = "prover_proveBlockRange";
    pub const get_proof = "prover_getProof";
    pub const cancel_proof_request = "prover_cancelProofRequest";
    pub const delete_proof_request = "prover_deleteProofRequest";
    pub const list_proofs = "prover_listProofs";
    pub const get_next_proof = "prover_getNextProof";
    pub const heartbeat = "prover_heartbeat";
    pub const abandon_proof = "prover_abandonProof";
    pub const submit_proof = "prover_submitProof";
    pub const get_proof_session = "prover_getProofSession";
    pub const record_proof_session = "prover_recordProofSession";
};

/// base/base `server/mod.rs` error codes.
pub const code = struct {
    pub const invalid_params: i32 = -32602;
    pub const internal: i32 = -32603;
    pub const not_found: i32 = -32004;
    pub const unavailable: i32 = -32014;
    pub const resource_exhausted: i32 = -32016;
    pub const failed_precondition: i32 = -32017;
    pub const proof_cancelled: i32 = -32018;
};

pub const proof_request_not_found_message = "Proof request not found";
pub const proof_request_cancelled_message = "Proof request cancelled by requester";

pub const session_id_bytes_max = 64;
pub const worker_id_bytes_max = 64;
pub const lock_id_bytes_max = 64;
pub const error_message_bytes_max = 256;
pub const backend_session_id_bytes_max = 128;
/// The dispute game factory's bound on intermediate roots.
pub const intermediate_root_count_max = 512;
pub const signature_bytes_max = 128;
pub const list_limit_max = 1000;
pub const list_limit_default = 50;

/// A bounded UTF-8 string. Unused bytes stay zero, so equal texts are bytewise equal.
pub fn Text(comptime capacity: u16) type {
    return struct {
        const Self = @This();
        pub const is_text = true;
        pub const bytes_max = capacity;

        buffer: [capacity]u8 = @splat(0),
        len: u16 = 0,

        pub fn init(bytes: []const u8) error{TooLong}!Self {
            if (bytes.len > capacity) return error.TooLong;
            var text: Self = .{};
            @memcpy(text.buffer[0..bytes.len], bytes);
            text.len = @intCast(bytes.len);
            assert(std.mem.eql(u8, text.slice(), bytes));
            return text;
        }

        /// For literals and inputs known to fit.
        pub fn from(bytes: []const u8) Self {
            assert(bytes.len <= capacity);
            return init(bytes) catch unreachable; // Checked above.
        }

        pub fn slice(text: *const Self) []const u8 {
            assert(text.len <= capacity);
            return text.buffer[0..text.len];
        }

        pub fn eql(text: *const Self, other: []const u8) bool {
            return std.mem.eql(u8, text.slice(), other);
        }
    };
}

pub const SessionId = Text(session_id_bytes_max);
pub const WorkerId = Text(worker_id_bytes_max);
pub const LockId = Text(lock_id_bytes_max);
pub const ErrorMessage = Text(error_message_bytes_max);
pub const BackendSessionId = Text(backend_session_id_bytes_max);

/// A UTC instant, serialized as RFC 3339 (`2026-11-05T12:00:00Z`) like chrono.
pub const Timestamp = struct {
    pub const is_timestamp = true;
    seconds: u64,

    pub fn from_ns(ns: u64) Timestamp {
        return .{ .seconds = ns / std.time.ns_per_s };
    }
};

pub const ProofType = enum { compressed, snark_plonk, tee };
pub const TeeKind = enum { aws_nitro };
pub const ZkVm = enum { sp1 };
pub const ZkBackend = enum { dry_run, cluster, network };
pub const ProofStatus = enum { queued, running, succeeded, failed };
pub const ProofJobStatus = enum { pending, claimed, succeeded, failed };
pub const SessionType = enum { stark, snark };
pub const BackendSessionState = enum { submitting, running, completed, failed };

pub const ZkProofRequest = struct {
    start_block_number: u64,
    number_of_blocks_to_prove: u64,
    sequence_window: ?u64 = null,
    l1_head: ?Hash = null,
    schedule_l2_block_number: ?u64 = null,
    intermediate_block_interval: u64,
    zk_vm: ZkVm,
    zk_backend: ZkBackend = .cluster,

    pub const RangeError = error{ EmptyRange, EndBlockOverflow, MisalignedRange };

    /// base/base `validate_range`: the exclusive end block.
    pub fn validate_range(request: *const ZkProofRequest) RangeError!u64 {
        assert(request.intermediate_block_interval > 0);
        if (request.number_of_blocks_to_prove == 0) return error.EmptyRange;
        if (request.number_of_blocks_to_prove % request.intermediate_block_interval != 0) {
            return error.MisalignedRange;
        }
        const count = request.number_of_blocks_to_prove;
        return std.math.add(u64, request.start_block_number, count) catch error.EndBlockOverflow;
    }

    pub fn validate(request: *const ZkProofRequest) error{InvalidField}!void {
        if (request.intermediate_block_interval == 0) return error.InvalidField;
    }
};

pub const SnarkPlonkProofRequest = struct {
    proof: ZkProofRequest,
    prover_address: Address,
};

/// base/base `base_proof_primitives::ProofRequest`.
pub const PrimitiveProofRequest = struct {
    l1_head: Hash,
    agreed_l2_head_hash: Hash,
    agreed_l2_output_root: Hash,
    claimed_l2_output_root: Hash,
    claimed_l2_block_number: u64,
    proposer: Address = @splat(0),
    l1_head_number: u64 = 0,
    schedule_l2_block_number: ?u64 = null,
    intermediate_block_interval: u64,

    pub fn validate(request: *const PrimitiveProofRequest) error{InvalidField}!void {
        if (request.intermediate_block_interval == 0) return error.InvalidField;
    }
};

pub const TeeProofRequest = struct {
    proof: PrimitiveProofRequest,
    tee_kind: TeeKind,
};

/// Adjacently tagged: `{"proof_type": .., "payload": ..}`.
pub const ProofRequestKind = union(ProofType) {
    compressed: ZkProofRequest,
    snark_plonk: SnarkPlonkProofRequest,
    tee: TeeProofRequest,
};

pub const ProofRequest = struct {
    session_id: SessionId,
    request: ProofRequestKind,
};

pub const ProveBlockRangeRequest = struct {
    proof: ProofRequest,
    retry_failed: bool = true,
};

pub const ProveBlockRangeResponse = struct { session_id: SessionId };
pub const CancelProofRequest = struct { session_id: SessionId };
pub const DeleteProofRequest = struct { session_id: SessionId };
pub const GetProofRequest = struct { session_id: SessionId };

pub const ZkProofResult = struct {
    pub const proof_max = std.math.maxInt(u32);
    zk_vm: ZkVm,
    proof: []const u8,
};

pub const SnarkPlonkProofResult = struct { proof: ZkProofResult };

/// base/base `base_proof_primitives::Proposal`.
pub const Proposal = struct {
    pub const signature_max = signature_bytes_max;
    output_root: Hash,
    signature: []const u8,
    l1_origin_hash: Hash,
    l1_origin_number: u64,
    l2_block_number: u64,
    prev_output_root: Hash,
    config_hash: Hash,
    schedule_id: Hash = @splat(0),
};

pub const TeeProofResult = struct {
    pub const intermediate_roots_max = intermediate_root_count_max;
    aggregate_proposal: Proposal,
    intermediate_roots: []const Hash,
    tee_kind: TeeKind,
    tee_signer: Address,
};

pub const ProofResult = union(ProofType) {
    compressed: ZkProofResult,
    snark_plonk: SnarkPlonkProofResult,
    tee: TeeProofResult,
};

pub const GetProofResponse = struct {
    status: ProofStatus,
    error_message: ?ErrorMessage = null,
    result: ?ProofResult = null,
};

pub const ListProofsRequest = struct {
    offset: u64,
    limit: u32,
    status_filter: ?ProofStatus = null,
};

pub const ProofSummary = struct {
    session_id: SessionId,
    proof_type: ProofType,
    status: ProofStatus,
    created_at: Timestamp,
    updated_at: Timestamp,
    completed_at: ?Timestamp = null,
    error_message: ?ErrorMessage = null,
    tee_kind: ?TeeKind = null,
    zk_vm: ?ZkVm = null,
};

pub const ListProofsResponse = struct {
    pub const proofs_max = list_limit_max;
    proofs: []const ProofSummary,
    total_count: u64,
};

pub const ProofJob = struct {
    session_id: SessionId,
    status: ProofJobStatus,
    request: ProofRequest,
    attempt: u32,
    lock_id: ?LockId = null,
    worker_id: ?WorkerId = null,
    lock_expires_at: ?Timestamp = null,
    created_at: Timestamp,
    updated_at: Timestamp,
    completed_at: ?Timestamp = null,
    error_message: ?ErrorMessage = null,
};

pub const GetNextProofRequest = struct {
    pub const tee_kinds_max = 8;
    pub const zk_vms_max = 8;
    pub const zk_backends_max = 8;
    worker_id: WorkerId,
    proof_type: ProofType,
    tee_kinds: []const TeeKind = &.{},
    zk_vms: []const ZkVm = &.{},
    zk_backends: []const ZkBackend = &.{},
    lock_duration_seconds: u32,
};

pub const GetNextProofResponse = struct { job: ?ProofJob = null };

pub const HeartbeatRequest = struct {
    session_id: SessionId,
    lock_id: LockId,
    worker_id: WorkerId,
    lock_duration_seconds: u32,
};

pub const HeartbeatResponse = struct { job: ProofJob };

pub const AbandonProofRequest = struct {
    session_id: SessionId,
    lock_id: LockId,
    worker_id: WorkerId,
    error_message: ErrorMessage,
};

pub const AbandonProofResponse = struct { job: ProofJob };

pub const WorkerSubmitProofRequest = struct {
    session_id: SessionId,
    lock_id: LockId,
    worker_id: WorkerId,
    result: ProofResult,
};

pub const WorkerSubmitProofResponse = struct { job: ProofJob };

pub const BackendSession = struct {
    backend_session_id: BackendSessionId,
    state: BackendSessionState,
};

pub const GetProofSessionRequest = struct {
    session_id: SessionId,
    session_type: SessionType,
};

pub const GetProofSessionResponse = struct { session: ?BackendSession = null };

pub const RecordProofSessionRequest = struct {
    session_id: SessionId,
    lock_id: LockId,
    worker_id: WorkerId,
    session_type: SessionType,
    backend_session_id: BackendSessionId,
    state: BackendSessionState,
};

pub const RecordProofSessionResponse = struct { session: BackendSession };

/// RFC 4122 `NAMESPACE_OID`.
const namespace_oid: [16]u8 = .{
    0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1,
    0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8,
};

/// The proposer's session namespace and TEE label (base/base `ProposerProofAdapter`).
pub const proposer_session_namespace = "base/proposer/proof-session/v2";
pub const tee_session_label = "tee/aws_nitro";

/// base/base `ProofSessionId::derive`: UUIDv5 (OID namespace) of
/// `namespace ":" proof_subtype ":" root`.
pub fn derive_session_id(namespace: []const u8, proof_subtype: []const u8, root: Hash) SessionId {
    assert(namespace.len > 0);
    assert(proof_subtype.len > 0);
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(&namespace_oid);
    hasher.update(namespace);
    hasher.update(":");
    hasher.update(proof_subtype);
    hasher.update(":");
    hasher.update(&root);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    var uuid: [16]u8 = digest[0..16].*;
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    return format_uuid(uuid);
}

/// The proposer's session id for a claimed output root.
pub fn tee_session_id_for_root(root: Hash) SessionId {
    return derive_session_id(proposer_session_namespace, tee_session_label, root);
}

/// Lowercase hyphenated form of a UUID.
pub fn format_uuid(uuid: [16]u8) SessionId {
    var text: [36]u8 = undefined;
    var out: usize = 0;
    for (uuid, 0..) |byte, index| {
        if (index == 4 or index == 6 or index == 8 or index == 10) {
            text[out] = '-';
            out += 1;
        }
        text[out] = std.fmt.hex_charset[byte >> 4];
        text[out + 1] = std.fmt.hex_charset[byte & 0xf];
        out += 2;
    }
    assert(out == text.len);
    return SessionId.from(&text);
}

/// Parses a hyphenated or simple (32 hex digits) UUID, any case.
pub fn parse_uuid(text: []const u8) ?[16]u8 {
    const hyphenated = text.len == 36;
    if (!hyphenated and text.len != 32) return null;
    var uuid: [16]u8 = undefined;
    var read: usize = 0;
    for (&uuid, 0..) |*byte, index| {
        if (hyphenated and (index == 4 or index == 6 or index == 8 or index == 10)) {
            if (text[read] != '-') return null;
            read += 1;
        }
        const high = std.fmt.charToDigit(text[read], 16) catch return null;
        const low = std.fmt.charToDigit(text[read + 1], 16) catch return null;
        byte.* = (high << 4) | low;
        read += 2;
    }
    assert(read == text.len);
    return uuid;
}

/// base/base `canonical_session_id`: a UUID is normalized to lowercase hyphenated form,
/// anything else is kept as is; empty ids are invalid.
pub fn canonical_session_id(session_id: *const SessionId) error{EmptySessionId}!SessionId {
    if (session_id.len == 0) return error.EmptySessionId;
    const uuid = parse_uuid(session_id.slice()) orelse return session_id.*;
    const canonical = format_uuid(uuid);
    assert(canonical.len == 36);
    return canonical;
}

/// base/base `ProposerProofAdapter::tee_prove_block_range_request_with_session_id`.
pub fn tee_prove_block_range_request(
    request: PrimitiveProofRequest,
    session_id: SessionId,
) ProveBlockRangeRequest {
    assert(request.intermediate_block_interval > 0);
    assert(session_id.len > 0);
    return .{
        .proof = .{
            .session_id = session_id,
            .request = .{ .tee = .{ .proof = request, .tee_kind = .aws_nitro } },
        },
        .retry_failed = true,
    };
}

/// base/base `ProofEncoder::encode_proof_bytes`: the 130-byte TEE `initData`,
/// `proofType(0) | l1OriginHash | l1OriginNumber (uint256) | signature (v as 27/28)`.
pub fn encode_tee_proof_bytes(
    out: *[130]u8,
    signature: []const u8,
    l1_origin_hash: Hash,
    l1_origin_number: u64,
) error{ InvalidSignatureLength, InvalidV }!void {
    if (signature.len != 65) return error.InvalidSignatureLength;
    out.* = @splat(0);
    @memcpy(out[1..33], &l1_origin_hash);
    std.mem.writeInt(u64, out[57..65], l1_origin_number, .big);
    @memcpy(out[65..130], signature);
    out[129] = switch (out[129]) {
        0, 1 => out[129] + 27,
        27, 28 => out[129],
        else => return error.InvalidV,
    };
    assert(out[0] == 0);
}

const testing = std.testing;

test "prover service protocol: session id derivation matches base/base" {
    // Python: uuid5(NAMESPACE_OID, "base/proposer/proof-session/v2:tee/aws_nitro:" + 0x11*32).
    const session = tee_session_id_for_root(@splat(0x11));
    try testing.expectEqualStrings("9dcd3bf1-da72-502d-a430-77a6f3474685", session.slice());
    const other = tee_session_id_for_root(@splat(0x12));
    try testing.expect(!std.mem.eql(u8, session.slice(), other.slice()));
}

test "prover service protocol: canonical session ids" {
    const upper = SessionId.from("9DCD3BF1DA72502DA43077A6F3474685");
    const canonical = try canonical_session_id(&upper);
    try testing.expectEqualStrings("9dcd3bf1-da72-502d-a430-77a6f3474685", canonical.slice());
    const free_form = SessionId.from("proof-session");
    try testing.expectEqualStrings("proof-session", (try canonical_session_id(&free_form)).slice());
    try testing.expectError(error.EmptySessionId, canonical_session_id(&SessionId{}));
    try testing.expect(parse_uuid("9dcd3bf1-da72-502d-a430-77a6f347468g") == null);
}

test "prover service protocol: zk range validation" {
    var request: ZkProofRequest = .{
        .start_block_number = 10,
        .number_of_blocks_to_prove = 20,
        .intermediate_block_interval = 10,
        .zk_vm = .sp1,
    };
    try testing.expectEqual(@as(u64, 30), try request.validate_range());
    request.number_of_blocks_to_prove = 15;
    try testing.expectError(error.MisalignedRange, request.validate_range());
    request.number_of_blocks_to_prove = 0;
    try testing.expectError(error.EmptyRange, request.validate_range());
    request.number_of_blocks_to_prove = 10;
    request.start_block_number = std.math.maxInt(u64);
    try testing.expectError(error.EndBlockOverflow, request.validate_range());
}

test "prover service protocol: tee proof bytes" {
    var out: [130]u8 = undefined;
    var signature: [65]u8 = @splat(0xab);
    signature[64] = 1;
    try encode_tee_proof_bytes(&out, &signature, @splat(0xcd), 0x1234);
    try testing.expectEqual(@as(u8, 0), out[0]);
    try testing.expectEqual(@as(u8, 0xcd), out[1]);
    try testing.expectEqual(@as(u8, 0x12), out[63]);
    try testing.expectEqual(@as(u8, 0x34), out[64]);
    try testing.expectEqual(@as(u8, 28), out[129]);
    signature[64] = 5;
    try testing.expectError(error.InvalidV, encode_tee_proof_bytes(&out, &signature, @splat(0), 0));
    const empty = encode_tee_proof_bytes(&out, "", @splat(0), 0);
    try testing.expectError(error.InvalidSignatureLength, empty);
}

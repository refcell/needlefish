//! TEE proof generation for claimed prover-service jobs (base/base
//! `crates/proof/tee/nitro-host/src/{proof_generator,proof_submitter,host}.rs`), as a
//! prover worker `Backend`.
//!
//! The worker (`prover_service/worker.zig`) already owns what base/base's generator wraps
//! around a proof: job discovery, lease heartbeats, abandoning a failed job, and submitting
//! the result. This backend is the part in between: it takes an AWS Nitro TEE request,
//! records its witness on the host (`backend.zig`), proves it on a free valid enclave
//! (`pool.zig`), and returns the enclave's signed aggregate proposal as the job's
//! `TeeProofResult`, with the enclave signer as `tee_signer` (base/base
//! `ProofSubmitterRequest::from_tee_proof`). Before discovery the worker asks `ready`,
//! which is false while no enclave signer is valid onchain (base/base `ready_to_claim`).
//!
//! Proving runs to completion inside `start`, like the native backend; `poll` then hands
//! out the result, copied into the generator so it outlives later enclave calls.

const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.tee_host);

const host = @import("../../host/root.zig");
const protocol = @import("../../prover_service/protocol.zig");
const worker_module = @import("../../prover_service/worker.zig");
const backend_module = @import("backend.zig");
const pool_module = @import("pool.zig");

const BackendError = worker_module.BackendError;
const Hash = [32]u8;

pub const Stats = struct {
    proved: u64 = 0,
    /// Claims the host's run refuted (never sent to an enclave).
    refuted: u64 = 0,
    /// Witness generation failures (source, store, or program errors).
    witness_failed: u64 = 0,
    /// Enclave failures: busy, no valid signer, link errors, refused proofs.
    enclave_failed: u64 = 0,
};

/// The TEE request of a claimed job (base/base `ProofGeneratorRequest::try_from`).
pub fn request_of(job: *const protocol.ProofJob) BackendError!protocol.PrimitiveProofRequest {
    if (job.lock_id == null) return error.Unsupported;
    const tee = switch (job.request.request) {
        .tee => |tee| tee,
        .compressed, .snark_plonk => return error.Unsupported,
    };
    assert(tee.tee_kind == .aws_nitro);
    tee.proof.validate() catch return error.Unsupported;
    return tee.proof;
}

pub const Generator = struct {
    allocator: std.mem.Allocator,
    source: host.Source,
    config: backend_module.Config,
    pool: *pool_module.Pool,
    outcome: ?(BackendError!protocol.ProofResult) = null,
    signature: [protocol.signature_bytes_max]u8 = undefined,
    roots: *[protocol.intermediate_root_count_max]Hash,
    stats: Stats = .{},
    /// The last failure, for diagnostics.
    last_error: ?anyerror = null,

    pub fn init(
        allocator: std.mem.Allocator,
        source: host.Source,
        config: backend_module.Config,
        pool: *pool_module.Pool,
    ) std.mem.Allocator.Error!Generator {
        assert(config.rollup_config_json.len > 0);
        assert(config.preimages_max > 0);
        return .{
            .allocator = allocator,
            .source = source,
            .config = config,
            .pool = pool,
            .roots = try allocator.create([protocol.intermediate_root_count_max]Hash),
        };
    }

    pub fn deinit(generator: *Generator) void {
        generator.allocator.destroy(generator.roots);
        generator.* = undefined;
    }

    pub fn backend(generator: *Generator) worker_module.Backend {
        return .{ .context = generator, .vtable = &vtable };
    }

    const vtable: worker_module.Backend.VTable = .{
        .start = start,
        .poll = poll,
        .cancel = cancel,
        .ready = ready,
    };

    fn of(context: *anyopaque) *Generator {
        return @ptrCast(@alignCast(context));
    }

    fn start(context: *anyopaque, job: *const protocol.ProofJob) BackendError!void {
        const generator = of(context);
        const request = try request_of(job);
        generator.outcome = generator.generate(&request);
    }

    fn poll(context: *anyopaque) BackendError!?protocol.ProofResult {
        const generator = of(context);
        const outcome = generator.outcome orelse return null;
        generator.outcome = null;
        return try outcome;
    }

    fn cancel(context: *anyopaque) void {
        of(context).outcome = null;
    }

    fn ready(context: *anyopaque) bool {
        return of(context).pool.ready_to_claim();
    }

    /// Records the witness, proves it on an enclave, and keeps a copy of the result.
    pub fn generate(
        generator: *Generator,
        request: *const protocol.PrimitiveProofRequest,
    ) BackendError!protocol.ProofResult {
        const allocator = generator.allocator;
        var witness: host.Store = .init(allocator, generator.config.store_limits);
        defer witness.deinit();
        backend_module.record_witness(
            allocator,
            generator.source,
            &generator.config,
            request,
            &witness,
        ) catch |err| return generator.fail_witness(err);
        const preimages = backend_module.preimages_of(
            allocator,
            &witness,
            generator.config.preimages_max,
        ) catch |err| return generator.fail_witness(err);
        defer allocator.free(preimages);
        const proved = generator.pool.prove(preimages) catch |err| {
            generator.stats.enclave_failed += 1;
            generator.last_error = err;
            log.info("block {d}: enclave failed: {t}", .{ request.claimed_l2_block_number, err });
            return error.Failed;
        };
        const result = try generator.keep(&proved.result);
        generator.stats.proved += 1;
        assert(result.tee.aggregate_proposal.l2_block_number == request.claimed_l2_block_number);
        return result;
    }

    fn fail_witness(generator: *Generator, err: backend_module.Error) BackendError {
        if (err == error.ClaimDoesNotHold) {
            generator.stats.refuted += 1;
        } else {
            generator.stats.witness_failed += 1;
        }
        generator.last_error = err;
        log.info("witness failed: {t}", .{err});
        return error.Failed;
    }

    /// Copies the enclave's byte strings, which live in its link, into the generator.
    fn keep(
        generator: *Generator,
        result: *const protocol.TeeProofResult,
    ) BackendError!protocol.ProofResult {
        const signature = result.aggregate_proposal.signature;
        const roots = result.intermediate_roots;
        if (signature.len > generator.signature.len) return error.Failed;
        if (roots.len > generator.roots.len) return error.Failed;
        @memcpy(generator.signature[0..signature.len], signature);
        @memcpy(generator.roots[0..roots.len], roots);
        var kept = result.*;
        kept.aggregate_proposal.signature = generator.signature[0..signature.len];
        kept.intermediate_roots = generator.roots[0..roots.len];
        assert(kept.tee_kind == .aws_nitro);
        return .{ .tee = kept };
    }
};

const testing = std.testing;
const link_module = @import("link.zig");
const registration = @import("registration.zig");

fn tee_job(lock: ?[]const u8) protocol.ProofJob {
    return .{
        .session_id = .from("tee-1"),
        .status = .claimed,
        .request = .{ .session_id = .from("tee-1"), .request = .{ .tee = .{
            .proof = .{
                .l1_head = @splat(1),
                .agreed_l2_head_hash = @splat(2),
                .agreed_l2_output_root = @splat(3),
                .claimed_l2_output_root = @splat(4),
                .claimed_l2_block_number = 10,
                .intermediate_block_interval = 5,
            },
            .tee_kind = .aws_nitro,
        } } },
        .attempt = 1,
        .lock_id = if (lock) |text| .from(text) else null,
        .created_at = .{ .seconds = 0 },
        .updated_at = .{ .seconds = 0 },
    };
}

test "tee proof generator: only claimed TEE jobs are supported" {
    var job = tee_job("lock-1");
    const request = try request_of(&job);
    try testing.expectEqual(@as(u64, 10), request.claimed_l2_block_number);
    const unclaimed = tee_job(null);
    try testing.expectError(error.Unsupported, request_of(&unclaimed));
    job.request.request.tee.proof.intermediate_block_interval = 0;
    try testing.expectError(error.Unsupported, request_of(&job));
    job.request.request = .{ .compressed = .{
        .start_block_number = 0,
        .number_of_blocks_to_prove = 2,
        .intermediate_block_interval = 1,
        .zk_vm = .sp1,
    } };
    try testing.expectError(error.Unsupported, request_of(&job));
}

/// A source where every lookup is not found.
const Empty = struct {
    fn source() host.Source {
        return .{ .context = undefined, .vtable = &.{
            .raw_header = raw_header,
            .transactions = transactions,
            .receipts = receipts,
            .blob = blob,
            .preimage = preimage,
            .payload_witness = payload_witness,
        } };
    }
    const SourceError = host.handler.SourceError;
    fn raw_header(_: *anyopaque, _: host.handler.Chain, _: Hash) SourceError![]const u8 {
        return error.NotFound;
    }
    fn transactions(_: *anyopaque, _: host.handler.Chain, _: Hash) SourceError![]const []const u8 {
        return error.NotFound;
    }
    fn receipts(_: *anyopaque, _: Hash) SourceError![]const []const u8 {
        return error.NotFound;
    }
    fn blob(_: *anyopaque, _: Hash, _: u64) SourceError!host.handler.Blob {
        return error.NotFound;
    }
    fn preimage(_: *anyopaque, _: Hash) SourceError![]const u8 {
        return error.NotFound;
    }
    fn payload_witness(_: *anyopaque, _: Hash, _: []const u8) SourceError![]const []const u8 {
        return error.NotFound;
    }
};

test "tee proof generator: a witness failure fails the job; readiness follows the registry" {
    const local = try link_module.test_local_enclave(0x61);
    defer local.destroy();
    const links = [_]*link_module.Link{&local.link};
    var pool: pool_module.Pool = try .init(&links);
    var generator: Generator = try .init(testing.allocator, Empty.source(), .{
        .rollup_config_json = "{}",
        .chain_id = 8453,
        .client_options = link_module.unused_client_options,
    }, &pool);
    defer generator.deinit();
    const backend = generator.backend();
    const job = tee_job("lock-1");
    try backend.start(&job);
    try testing.expectError(error.Failed, backend.poll());
    try testing.expect(try backend.poll() == null);
    try testing.expectEqual(@as(u64, 1), generator.stats.witness_failed);
    try testing.expectEqual(@as(?anyerror, error.NotFound), generator.last_error);
    try testing.expect(backend.ready());
    var fake: registration.FakeRegistry = .{};
    var checker: registration.Checker = try .init(&links, fake.registry());
    try pool.set_checker(&checker);
    try testing.expect(!backend.ready());
    fake.allow(local.server.signer_address());
    try testing.expect(backend.ready());
}

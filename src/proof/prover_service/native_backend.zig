//! A worker `Backend` that proves `compressed` range requests by running the fault-proof
//! program natively (`host/native.zig`) against an `RpcSource`, and returns the recorded
//! witness archive (`host/archive.zig`) as the proof bytes.
//!
//! This stands in for base/base's SP1 and TEE backends, whose proof formats (SP1 STARK and
//! SNARK receipts, Nitro enclave signatures) are out of scope: the archive is not succinct,
//! but anyone can re-check the claim by replaying it offline (`base proof replay`). The
//! boot values follow `base proof run`: the agreed output is block `start`, the claim is
//! block `start + count`, and the L1 head is the request's or the latest L1 block. A claim
//! that does not hold fails the job (the worker abandons it).
//!
//! Proving runs to completion inside `start`; `poll` then hands out the result.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("protocol.zig");
const worker_module = @import("worker.zig");
const host = @import("../host/root.zig");
const proof_client = @import("../client/root.zig");
const crypto = @import("../../common/crypto/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");

const BackendError = worker_module.BackendError;

pub const Config = struct {
    rollup_config_json: []const u8,
    l1_config_json: []const u8 = "",
    chain_id: u64,
    client_options: proof_client.client.Options,
    roots_brp: ?*const [kzg.field_elements_per_blob][32]u8 = null,
    /// Largest archive the backend returns (and the service accepts).
    proof_bytes_max: u32,
};

/// The backend over the node's JSON-RPC (`host.rpc_source`).
pub fn Native(comptime IO: type) type {
    return NativeOver(host.rpc_source.RpcSource(IO));
}

/// The backend over any source with `header_by_number(chain, ?number) ![]const u8` (the
/// raw header; null is the latest) and `as_source() host.handler.Source`.
pub fn NativeOver(comptime SourceType: type) type {
    return struct {
        const Self = @This();
        pub const Source = SourceType;

        allocator: std.mem.Allocator,
        source: *Source,
        config: Config,
        archive_buffer: []u8,
        outcome: ?(BackendError!protocol.ProofResult) = null,
        /// Proofs produced and claims that did not hold, for diagnostics.
        proved: u64 = 0,
        refuted: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, source: *Source, config: Config) !Self {
            assert(config.proof_bytes_max >= host.archive.header_bytes);
            assert(config.rollup_config_json.len > 0);
            return .{
                .allocator = allocator,
                .source = source,
                .config = config,
                .archive_buffer = try allocator.alloc(u8, config.proof_bytes_max),
            };
        }

        pub fn deinit(native: *Self) void {
            native.allocator.free(native.archive_buffer);
            native.* = undefined;
        }

        pub fn backend(native: *Self) worker_module.Backend {
            return .{ .context = native, .vtable = &vtable };
        }

        const vtable: worker_module.Backend.VTable = .{
            .start = start,
            .poll = poll,
            .cancel = cancel,
        };

        fn of(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn start(context: *anyopaque, job: *const protocol.ProofJob) BackendError!void {
            const native = of(context);
            const range = switch (job.request.request) {
                .compressed => |zk| zk,
                .snark_plonk, .tee => return error.Unsupported,
            };
            native.outcome = native.prove(&range);
        }

        fn poll(context: *anyopaque) BackendError!?protocol.ProofResult {
            const native = of(context);
            const outcome = native.outcome orelse return null;
            native.outcome = null;
            return try outcome;
        }

        fn cancel(context: *anyopaque) void {
            of(context).outcome = null;
        }

        fn prove(
            native: *Self,
            range: *const protocol.ZkProofRequest,
        ) BackendError!protocol.ProofResult {
            const claimed_block = range.validate_range() catch return error.Failed;
            var store: host.Store = .init(native.allocator, .{});
            defer store.deinit();
            native.boot(&store, range, claimed_block) catch return error.Failed;
            var witness: host.Store = .init(native.allocator, .{});
            defer witness.deinit();
            const verdict = host.native.run(
                native.allocator,
                &store,
                native.source.as_source(),
                native.config.roots_brp,
                native.config.client_options,
                &witness,
            ) catch return error.Failed;
            if (!verdict.holds) {
                native.refuted += 1;
                return error.Failed;
            }
            const archive = try native.encode_archive(&witness);
            native.proved += 1;
            assert(archive.len >= host.archive.header_bytes);
            return .{ .compressed = .{ .zk_vm = range.zk_vm, .proof = archive } };
        }

        /// The boot values and the agreed output root preimage (`base proof run`'s `boot`).
        fn boot(
            native: *Self,
            store: *host.Store,
            range: *const protocol.ZkProofRequest,
            claimed_block: u64,
        ) !void {
            assert(claimed_block > range.start_block_number);
            const source = native.source;
            const agreed = try host.native.output_of(
                try source.header_by_number(.l2, range.start_block_number),
            );
            const agreed_root = try store.put_keccak(&agreed.encode());
            const claimed_root = try host.native.output_root_of(
                try source.header_by_number(.l2, claimed_block),
            );
            const l1_head = range.l1_head orelse
                crypto.keccak256(try source.header_by_number(.l1, null));
            try store.put_boot(&.{
                .l1_head = l1_head,
                .agreed_l2_output_root = agreed_root,
                .claimed_l2_output_root = claimed_root,
                .claimed_l2_block_number = claimed_block,
                .chain_id = native.config.chain_id,
                .rollup_config_json = native.config.rollup_config_json,
                .l1_config_json = native.config.l1_config_json,
                .intermediate_block_interval = range.intermediate_block_interval,
                .schedule_block_number = range.schedule_l2_block_number,
            });
        }

        fn encode_archive(native: *Self, witness: *const host.Store) BackendError![]const u8 {
            const size = host.archive.encoded_bytes(witness);
            if (size > native.archive_buffer.len) return error.Failed;
            const keys = native.allocator.alloc([32]u8, witness.count()) catch return error.Failed;
            defer native.allocator.free(keys);
            var writer: std.Io.Writer = .fixed(native.archive_buffer);
            host.archive.encode(witness, keys, &writer) catch return error.Failed;
            return writer.buffered();
        }
    };
}

const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");

test "prover service native backend: unsupported kinds and unreachable sources fail cleanly" {
    const allocator = testing.allocator;
    var world = try io.SimWorld.init(allocator, .{ .seed = 3 });
    defer world.deinit();
    var sim_io: io.SimIo = undefined;
    try io.SimIo.init(&sim_io, allocator, &world, .{ .host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0) });
    defer sim_io.deinit();
    const Backend = Native(io.SimIo);
    const nowhere = io.Address.ip4(.{ 10, 0, 0, 9 }, 8545);
    const http_options: http.client.Options = .{
        .send_buffer_size = 4096,
        .recv_buffer_size = 16384,
        .limits = .{ .head_size_max = 1024, .body_size_max = 8192 },
    };
    var l1: Backend.Source.Client = try .init(allocator, &sim_io, nowhere, http_options, 4096);
    defer l1.deinit();
    var l2: Backend.Source.Client = try .init(allocator, &sim_io, nowhere, http_options, 4096);
    defer l2.deinit();
    const Pump = struct {
        fn step(context: *anyopaque) anyerror!void {
            const sim_world: *io.SimWorld = @ptrCast(@alignCast(context));
            sim_world.run_for_ns(std.time.ns_per_ms);
        }
    };
    const pump: host.rpc_source.Pump = .{ .context = &world, .step = Pump.step };
    var source: Backend.Source = .init(allocator, &l1, &l2, pump, .{ .steps_max = 1000 });
    defer source.deinit();
    var native: Backend = try .init(allocator, &source, .{
        .rollup_config_json = "{}",
        .chain_id = 8453,
        // Never reached: the source fails before the client runs.
        .client_options = undefined,
        .proof_bytes_max = 1024,
    });
    defer native.deinit();
    const backend = native.backend();
    var job: protocol.ProofJob = .{
        .session_id = .from("s"),
        .status = .claimed,
        .request = .{ .session_id = .from("s"), .request = .{ .compressed = .{
            .start_block_number = 10,
            .number_of_blocks_to_prove = 2,
            .intermediate_block_interval = 1,
            .zk_vm = .sp1,
        } } },
        .attempt = 1,
        .created_at = .{ .seconds = 0 },
        .updated_at = .{ .seconds = 0 },
    };
    try backend.start(&job);
    try testing.expectError(error.Failed, backend.poll());
    try testing.expect(try backend.poll() == null);
    job.request.request = .{ .tee = undefined };
    try testing.expectError(error.Unsupported, backend.start(&job));
}

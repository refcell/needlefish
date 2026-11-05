//! An in-process `Prover`: runs the fault-proof program natively (`host.native.run`) over
//! a preimage source for each request and returns the recorded witness archive as the
//! game's `initData`, with the intermediate roots the client sampled. It stands in for
//! base/base's prover service (TEE/ZK backends) so the proposer runs end to end; a request
//! is proven synchronously inside `request`.

const std = @import("std");
const assert = std.debug.assert;

const client = @import("../client/root.zig");
const host = @import("../host/root.zig");
const program = @import("../program/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const interfaces = @import("interfaces.zig");

const Hash = interfaces.Hash;

const log = std.log.scoped(.proposer);

/// At most this many sessions are kept (the pipeline's default `proofs_in_flight_max`).
pub const sessions_max = 8;

pub const Config = struct {
    /// The rollup config JSON and L2 chain id written into every boot.
    rollup_config_json: []const u8,
    chain_id: u64,
    /// Custom L1 chains only: the geth chain config JSON object.
    l1_config_json: []const u8 = "",
    /// Client options (builder, KZG); `intermediate` is set per session.
    options: client.client.Options,
    roots_brp: ?*const [kzg.field_elements_per_blob][32]u8 = null,
};

const Session = struct {
    id: Hash,
    status: enum { failed, succeeded },
    output_root: Hash,
    roots: []const Hash,
    /// The encoded witness archive; owned.
    init_data: []u8,
};

pub const NativeProver = struct {
    allocator: std.mem.Allocator,
    source: host.handler.Source,
    config: Config,
    samplers: *[sessions_max]program.IntermediateRootSampler,
    sessions: [sessions_max]?Session = @splat(null),
    proofs_total: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        source: host.handler.Source,
        config: Config,
    ) error{OutOfMemory}!NativeProver {
        assert(config.rollup_config_json.len > 0);
        assert(config.options.intermediate == null);
        return .{
            .allocator = allocator,
            .source = source,
            .config = config,
            .samplers = try allocator.create([sessions_max]program.IntermediateRootSampler),
        };
    }

    pub fn deinit(prover: *NativeProver) void {
        for (&prover.sessions) |*slot| prover.free(slot);
        prover.allocator.destroy(prover.samplers);
        prover.* = undefined;
    }

    pub fn prover_interface(prover: *NativeProver) interfaces.Prover {
        return .{ .context = prover, .vtable = &vtable };
    }

    const vtable: interfaces.Prover.VTable = .{
        .request = request,
        .poll = poll,
        .delete = delete,
    };

    fn from(context: *anyopaque) *NativeProver {
        return @ptrCast(@alignCast(context));
    }

    fn find(prover: *NativeProver, id: Hash) ?usize {
        for (prover.sessions, 0..) |slot, index| {
            const session = slot orelse continue;
            if (std.mem.eql(u8, &session.id, &id)) return index;
        }
        return null;
    }

    fn free(prover: *NativeProver, slot: *?Session) void {
        const session = slot.* orelse return;
        prover.allocator.free(session.init_data);
        slot.* = null;
        assert(slot.* == null);
    }

    fn request(
        context: *anyopaque,
        proof_request: *const interfaces.ProofRequest,
    ) interfaces.ProverError!void {
        const prover = from(context);
        const id = proof_request.session();
        if (prover.find(id) != null) return;
        const index = for (prover.sessions, 0..) |slot, index| {
            if (slot == null) break index;
        } else return error.Unavailable;
        prover.sessions[index] = prover.prove(proof_request, index) catch |err| failed: {
            log.info("native prover: block {d} failed: {t}", .{
                proof_request.claimed_l2_block_number,
                err,
            });
            break :failed .{
                .id = id,
                .status = .failed,
                .output_root = @splat(0),
                .roots = &.{},
                .init_data = &.{},
            };
        };
        assert(prover.find(id) == index);
    }

    fn poll(context: *anyopaque, id: Hash) interfaces.ProverError!interfaces.ProofStatus {
        const prover = from(context);
        const index = prover.find(id) orelse return error.NotFound;
        const session = prover.sessions[index].?;
        return switch (session.status) {
            .failed => .failed,
            .succeeded => .{ .succeeded = .{
                .output_root = session.output_root,
                .intermediate_roots = session.roots,
                .init_data = session.init_data,
            } },
        };
    }

    fn delete(context: *anyopaque, id: Hash) interfaces.ProverError!void {
        const prover = from(context);
        const index = prover.find(id) orelse return error.NotFound;
        prover.free(&prover.sessions[index]);
        assert(prover.find(id) == null);
    }

    const ProveError = host.native.Error || host.handler.SourceError || error{
        ClaimDoesNotHold,
        AgreedRootMismatch,
        WriteFailed,
    } || program.intermediate_roots.Error;

    /// Boots, runs and archives one request into session slot `index`.
    fn prove(
        prover: *NativeProver,
        proof_request: *const interfaces.ProofRequest,
        index: usize,
    ) ProveError!Session {
        assert(index < sessions_max);
        assert(prover.sessions[index] == null);
        var store: host.Store = .init(prover.allocator, .{});
        defer store.deinit();
        try prover.boot(&store, proof_request);
        var witness: host.Store = .init(prover.allocator, .{});
        defer witness.deinit();
        const sampler = &prover.samplers[index];
        var options = prover.config.options;
        options.intermediate = sampler;
        const verdict = try host.native.run(
            prover.allocator,
            &store,
            prover.source,
            prover.config.roots_brp,
            options,
            &witness,
        );
        if (!verdict.holds) return error.ClaimDoesNotHold;
        assert(verdict.outcome.block_number == proof_request.claimed_l2_block_number);
        const roots = try sampler.finish();
        const init_data = try archive(prover.allocator, &witness);
        prover.proofs_total += 1;
        return .{
            .id = proof_request.session(),
            .status = .succeeded,
            .output_root = verdict.outcome.output_root,
            .roots = roots,
            .init_data = init_data,
        };
    }

    fn boot(
        prover: *NativeProver,
        store: *host.Store,
        proof_request: *const interfaces.ProofRequest,
    ) ProveError!void {
        const source = prover.source;
        const hash = proof_request.agreed_l2_head_hash;
        const agreed_header = try source.vtable.raw_header(source.context, .l2, hash);
        const agreed = try host.native.output_of(agreed_header);
        const agreed_root = try store.put_keccak(&agreed.encode());
        // The proposer's agreed root is the parent game's claim: a different canonical
        // root means the request is stale.
        if (!std.mem.eql(u8, &agreed_root, &proof_request.agreed_l2_output_root)) {
            return error.AgreedRootMismatch;
        }
        try store.put_boot(&.{
            .l1_head = proof_request.l1_head.hash,
            .agreed_l2_output_root = agreed_root,
            .claimed_l2_output_root = proof_request.claimed_l2_output_root,
            .claimed_l2_block_number = proof_request.claimed_l2_block_number,
            .chain_id = prover.config.chain_id,
            .rollup_config_json = prover.config.rollup_config_json,
            .l1_config_json = prover.config.l1_config_json,
            .proposer = proof_request.proposer,
            .intermediate_block_interval = proof_request.intermediate_block_interval,
        });
        assert(store.count() > 1);
    }
};

/// The witness as one canonical archive (`base proof replay` checks it offline).
fn archive(allocator: std.mem.Allocator, witness: *const host.Store) ![]u8 {
    const keys = try allocator.alloc([32]u8, witness.count());
    defer allocator.free(keys);
    const bytes = try allocator.alloc(u8, @intCast(host.archive.encoded_bytes(witness)));
    errdefer allocator.free(bytes);
    var writer: std.Io.Writer = .fixed(bytes);
    try host.archive.encode(witness, keys, &writer);
    assert(writer.end == bytes.len);
    return bytes;
}

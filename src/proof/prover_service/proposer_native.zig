//! The proposer's `Prover` over the prover service with native workers: requests go out
//! as `compressed` range jobs (what `native_backend` proves), the proof bytes are the
//! witness archive, and the intermediate roots come from the proposer's own chain view
//! (the collector re-checks every one against canonical roots before submitting). The
//! TEE path of base/base is `client.ProposerProver`.

const std = @import("std");
const assert = std.debug.assert;

const interfaces = @import("../proposer/interfaces.zig");
const protocol = @import("protocol.zig");
const client_module = @import("client.zig");

const Hash = interfaces.Hash;

pub const compressed_session_label = "zk/sp1/compressed";
/// Requests tracked at once (the pipeline's default `proofs_in_flight_max`).
pub const sessions_max = 8;
pub const roots_max = protocol.intermediate_root_count_max;

/// The session id of a claimed output root (proposer namespace, compressed label).
pub fn session_id_for_root(root: Hash) protocol.SessionId {
    const namespace = protocol.proposer_session_namespace;
    return protocol.derive_session_id(namespace, compressed_session_label, root);
}

/// The compressed range job for a proposer request.
pub fn range_request(request: *const interfaces.ProofRequest) protocol.ProveBlockRangeRequest {
    assert(request.claimed_l2_block_number > request.agreed_l2_block_number);
    assert(request.intermediate_block_interval > 0);
    return .{ .proof = .{
        .session_id = session_id_for_root(request.session()),
        .request = .{ .compressed = .{
            .start_block_number = request.agreed_l2_block_number,
            .number_of_blocks_to_prove = request.claimed_l2_block_number -
                request.agreed_l2_block_number,
            .l1_head = request.l1_head.hash,
            .intermediate_block_interval = request.intermediate_block_interval,
            .zk_vm = .sp1,
        } },
    } };
}

pub fn NativeProposerProver(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Client = client_module.Client(IO);

        const Session = struct {
            root: Hash,
            agreed_block: u64,
            claimed_block: u64,
            interval: u64,
        };

        client: *Client,
        /// Reads the intermediate output roots of a proved range.
        chain: interfaces.Chain,
        sessions: [sessions_max]?Session = @splat(null),
        roots: [roots_max]Hash = undefined,

        pub fn prover(adapter: *Self) interfaces.Prover {
            return .{ .context = adapter, .vtable = &vtable };
        }

        const vtable: interfaces.Prover.VTable = .{
            .request = request,
            .poll = poll,
            .delete = delete,
        };

        fn of(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn find(adapter: *const Self, root: Hash) ?usize {
            for (adapter.sessions, 0..) |slot, index| {
                const session = slot orelse continue;
                if (std.mem.eql(u8, &session.root, &root)) return index;
            }
            return null;
        }

        fn request(
            context: *anyopaque,
            proof_request: *const interfaces.ProofRequest,
        ) interfaces.ProverError!void {
            const adapter = of(context);
            const root = proof_request.session();
            const index = adapter.find(root) orelse for (adapter.sessions, 0..) |slot, free| {
                if (slot == null) break free;
            } else return error.Unavailable;
            const body = range_request(proof_request);
            _ = adapter.client.prove_block_range(&body) catch return error.Unavailable;
            adapter.sessions[index] = .{
                .root = root,
                .agreed_block = proof_request.agreed_l2_block_number,
                .claimed_block = proof_request.claimed_l2_block_number,
                .interval = proof_request.intermediate_block_interval,
            };
            assert(adapter.find(root) == index);
        }

        fn poll(context: *anyopaque, root: Hash) interfaces.ProverError!interfaces.ProofStatus {
            const adapter = of(context);
            const index = adapter.find(root) orelse return error.NotFound;
            const session = adapter.sessions[index].?;
            const id = session_id_for_root(root);
            const response = adapter.client.get_proof(&.{ .session_id = id }) catch |err|
                return switch (err) {
                    error.NotFound => error.NotFound,
                    error.Rejected, error.Unavailable => error.Unavailable,
                };
            switch (response.status) {
                .queued, .running => return .pending,
                .failed => return .failed,
                .succeeded => {},
            }
            const result = response.result orelse return error.Unavailable;
            if (result != .compressed) return .failed;
            const roots = adapter.fill_roots(&session) catch return error.Unavailable;
            return .{ .succeeded = .{
                .output_root = root,
                .intermediate_roots = roots,
                .init_data = result.compressed.proof,
            } };
        }

        /// The output root at every `interval` block of the range, the claim last.
        fn fill_roots(adapter: *Self, session: *const Session) ![]const Hash {
            const span = session.claimed_block - session.agreed_block;
            assert(span % session.interval == 0);
            const count = span / session.interval;
            if (count > roots_max) return error.TooManyRoots;
            for (adapter.roots[0..count], 1..) |*out, step| {
                const block = session.agreed_block + step * session.interval;
                out.* = (try adapter.chain.output_at_block(block)).output_root;
            }
            if (!std.mem.eql(u8, &adapter.roots[count - 1], &session.root)) {
                return error.ClaimDiverged;
            }
            return adapter.roots[0..count];
        }

        fn delete(context: *anyopaque, root: Hash) interfaces.ProverError!void {
            const adapter = of(context);
            const index = adapter.find(root) orelse return error.NotFound;
            adapter.sessions[index] = null;
            const id = session_id_for_root(root);
            adapter.client.delete_proof_request(&.{ .session_id = id }) catch |err|
                return switch (err) {
                    error.NotFound => error.NotFound,
                    error.Rejected, error.Unavailable => error.Unavailable,
                };
        }
    };
}

test "proposer native: compressed range request and session id" {
    const request: interfaces.ProofRequest = .{
        .l1_head = .{ .number = 40, .hash = @splat(0x40) },
        .agreed_l2_head_hash = @splat(0x0a),
        .agreed_l2_output_root = @splat(0x0b),
        .agreed_l2_block_number = 100,
        .claimed_l2_output_root = @splat(0x0c),
        .claimed_l2_block_number = 110,
        .intermediate_block_interval = 5,
        .proposer = @splat(0x0d),
    };
    const body = range_request(&request);
    const range = body.proof.request.compressed;
    try std.testing.expectEqual(@as(u64, 100), range.start_block_number);
    try std.testing.expectEqual(@as(u64, 10), range.number_of_blocks_to_prove);
    try std.testing.expectEqual(@as(u64, 110), try range.validate_range());
    const tee = protocol.tee_session_id_for_root(request.session());
    try std.testing.expect(!std.mem.eql(u8, tee.slice(), body.proof.session_id.slice()));
}

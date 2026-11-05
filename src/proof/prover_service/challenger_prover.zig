//! The challenger's `Prover` over the prover service (base/base `ChallengerProofAdapter`):
//! idempotent session ids per (game, invalid index, proof kind) in the
//! `base/challenger/proof-session/v2` namespace, TEE requests as AWS Nitro proofs and ZK
//! requests as SP1 PLONK proofs. The challenger's numeric session handles index a fixed
//! table of the service's string session ids.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("../challenger/chain.zig");
const protocol = @import("protocol.zig");
const client_module = @import("client.zig");

pub const session_namespace = "base/challenger/proof-session/v2";
pub const zk_session_label = "zk/sp1/snark_plonk";

/// Sessions kept; the challenger's proof manager runs at most 64 attempts.
pub const slots_max = 64;

const Kind = std.meta.Tag(chain.ProofRequest);

/// base/base `ChallengerProofAdapter::{tee,snark_plonk}_session_id`.
pub fn session_id(kind: Kind, game: chain.Address, index: u64) protocol.SessionId {
    var index_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &index_bytes, index, .big);
    const label = switch (kind) {
        .tee => protocol.tee_session_label,
        .zk => zk_session_label,
    };
    const components: []const []const u8 = &.{ &game, &index_bytes };
    return protocol.derive_session_id_components(session_namespace, label, components);
}

/// The service request for one challenger proof request.
pub fn prove_request(
    id: protocol.SessionId,
    request: chain.ProofRequest,
) protocol.ProveBlockRangeRequest {
    return switch (request) {
        .tee => |tee| protocol.tee_prove_block_range_request(.{
            .l1_head = tee.l1_head,
            .agreed_l2_head_hash = tee.agreed_l2_head_hash,
            .agreed_l2_output_root = tee.agreed_l2_output_root,
            .claimed_l2_output_root = tee.claimed_l2_output_root,
            .claimed_l2_block_number = tee.claimed_l2_block_number,
            .proposer = tee.proposer,
            .l1_head_number = tee.l1_head_number,
            .schedule_l2_block_number = tee.schedule_l2_block_number,
            .intermediate_block_interval = tee.intermediate_block_interval,
        }, id),
        .zk => |zk| .{ .proof = .{ .session_id = id, .request = .{ .snark_plonk = .{
            .proof = .{
                .start_block_number = zk.start_block_number,
                .number_of_blocks_to_prove = zk.number_of_blocks_to_prove,
                .l1_head = zk.l1_head,
                .schedule_l2_block_number = zk.schedule_l2_block_number,
                .intermediate_block_interval = zk.intermediate_block_interval,
                .zk_vm = .sp1,
            },
            .prover_address = zk.prover_address,
        } } } },
    };
}

/// Maps a finished service result onto the challenger's (slices borrow the response).
pub fn proof_result(kind: Kind, result: protocol.ProofResult) ?chain.ProofResult {
    switch (kind) {
        .tee => {
            if (result != .tee or result.tee.tee_kind != .aws_nitro) return null;
            const proposal = result.tee.aggregate_proposal;
            return .{ .tee = .{
                .output_root = proposal.output_root,
                .signature = proposal.signature,
            } };
        },
        // The SP1 receipt-to-seal encoding (base/base `SnarkReceiptEncoder`) has no SP1 to
        // run against here: the service's proof bytes are the on-chain body as is.
        .zk => {
            if (result != .snark_plonk) return null;
            return .{ .zk = result.snark_plonk.proof.proof };
        },
    }
}

pub fn ChallengerProver(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Client = client_module.Client(IO);

        const Slot = struct {
            handle: chain.SessionId,
            kind: Kind,
            id: protocol.SessionId,
        };

        client: *Client,
        slots: [slots_max]?Slot = @splat(null),
        /// Handles count up from 1; a handle's slot is `handle % slots_max`, so a reused
        /// slot makes older handles stale (reported unavailable).
        handle_next: chain.SessionId = 1,

        pub fn prover(adapter: *Self) chain.Prover {
            return .{ .context = adapter, .vtable = &vtable };
        }

        const vtable: chain.Prover.VTable = .{ .request = request, .poll = poll };

        fn of(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn request(
            context: *anyopaque,
            game: chain.Address,
            index: u64,
            proof_request: chain.ProofRequest,
        ) chain.ProverError!chain.SessionId {
            const adapter = of(context);
            const kind = std.meta.activeTag(proof_request);
            const id = session_id(kind, game, index);
            const body = prove_request(id, proof_request);
            _ = adapter.client.prove_block_range(&body) catch return error.ProverUnavailable;
            const handle = adapter.handle_next;
            adapter.handle_next += 1;
            adapter.slots[handle % slots_max] = .{ .handle = handle, .kind = kind, .id = id };
            assert(handle > 0);
            return handle;
        }

        fn poll(context: *anyopaque, handle: chain.SessionId) chain.ProverError!chain.ProverStatus {
            const adapter = of(context);
            assert(handle > 0);
            const slot = adapter.slots[handle % slots_max] orelse return error.ProverUnavailable;
            if (slot.handle != handle) return error.ProverUnavailable;
            const response = adapter.client.get_proof(&.{ .session_id = slot.id }) catch
                return error.ProverUnavailable;
            return switch (response.status) {
                .queued => .queued,
                .running => .running,
                .failed => .failed,
                .succeeded => .{ .succeeded = if (response.result) |result|
                    proof_result(slot.kind, result)
                else
                    null },
            };
        }
    };
}

const testing = std.testing;

test "challenger prover: session ids are stable and separated" {
    const game: chain.Address = @splat(0xaa);
    const tee = session_id(.tee, game, 1);
    try testing.expectEqualStrings(tee.slice(), session_id(.tee, game, 1).slice());
    try testing.expect(!std.mem.eql(u8, tee.slice(), session_id(.zk, game, 1).slice()));
    try testing.expect(!std.mem.eql(u8, tee.slice(), session_id(.tee, game, 2).slice()));
    const other: chain.Address = @splat(0xbb);
    try testing.expect(!std.mem.eql(u8, tee.slice(), session_id(.tee, other, 1).slice()));
    try testing.expectEqual(@as(usize, 36), tee.slice().len);
    try testing.expectEqual(@as(u8, '5'), tee.slice()[14]);
}

test "challenger prover: requests and results map by kind" {
    const zk: chain.ProofRequest = .{ .zk = .{
        .start_block_number = 10,
        .number_of_blocks_to_prove = 4,
        .l1_head = @splat(1),
        .schedule_l2_block_number = 14,
        .intermediate_block_interval = 2,
        .prover_address = @splat(2),
    } };
    const body = prove_request(session_id(.zk, @splat(3), 0), zk);
    const plonk = body.proof.request.snark_plonk;
    try testing.expectEqual(@as(u64, 4), plonk.proof.number_of_blocks_to_prove);
    try testing.expectEqual(@as(u8, 2), plonk.prover_address[0]);
    const signature: [65]u8 = @splat(7);
    const tee_result: protocol.ProofResult = .{ .tee = .{
        .aggregate_proposal = .{
            .output_root = @splat(9),
            .signature = &signature,
            .l1_origin_hash = @splat(0),
            .l1_origin_number = 0,
            .l2_block_number = 14,
            .prev_output_root = @splat(0),
            .config_hash = @splat(0),
        },
        .intermediate_roots = &.{},
        .tee_kind = .aws_nitro,
        .tee_signer = @splat(0),
    } };
    const mapped = proof_result(.tee, tee_result).?;
    try testing.expectEqual(@as(u8, 9), mapped.tee.output_root[0]);
    try testing.expect(proof_result(.zk, tee_result) == null);
    const zk_result: protocol.ProofResult = .{ .snark_plonk = .{ .proof = .{
        .zk_vm = .sp1,
        .proof = "seal",
    } } };
    try testing.expectEqualStrings("seal", proof_result(.zk, zk_result).?.zk);
}

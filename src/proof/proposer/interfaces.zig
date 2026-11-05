//! Injected interfaces of the proposer, so the pipeline runs unchanged against network
//! adapters, in-memory fakes, and the deterministic simulator.
//!
//! - `Chain`: the rollup node (sync status, canonical output roots) and the L1 contracts
//!   (`AnchorStateRegistry` snapshot, `DisputeGameFactory` game count and lookups, the
//!   verifier's interval pair for a starting block). base/base `RollupProvider`,
//!   `AnchorStateRegistryClient`, `DisputeGameFactoryClient`, `IntervalResolver`.
//! - `Prover`: a proving service with sessions keyed by the claimed output root (base/base
//!   `ProofRequesterProvider` with `tee_session_id_for_root`).
//! - `Submitter`: L1 transaction submission of `createWithInitData` calldata, which is
//!   asynchronous: send returns a pending id, later polled to mined or failed (base/base
//!   `OutputProposer` over the `TxManager`).
//!
//! Every call is synchronous and must not block for long; data returned by reference is
//! valid until the next call on the same interface.

const std = @import("std");
const assert = std.debug.assert;

const clients = @import("../rpc/clients.zig");
const intervals_module = @import("intervals.zig");
const anchor_state_registry = @import("../contracts/anchor_state_registry.zig");

pub const Hash = [32]u8;
pub const Address = [20]u8;
pub const SyncStatus = clients.SyncStatus;
pub const OutputAtBlock = clients.OutputAtBlock;
pub const BlockRef = clients.BlockRef;
pub const AnchorRoot = anchor_state_registry.AnchorRoot;
pub const Intervals = intervals_module.Intervals;

pub const ChainError = error{
    /// The rollup node does not have the block yet (end of a recovery walk).
    BlockNotFound,
    /// Any transient RPC or contract failure; retried on the next tick.
    Unavailable,
};

/// The anchor root and anchor game, read from one L1 snapshot so recovery never combines
/// an old root with a newer game. A zero `game` means the anchor has no game.
pub const AnchorSnapshot = struct { root: AnchorRoot, game: Address };

pub const Chain = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        sync_status: *const fn (context: *anyopaque) ChainError!SyncStatus,
        /// Canonical output at `block`; adapters must not serve it from a cache, since
        /// submission re-checks proved roots against it just in time.
        output_at_block: *const fn (context: *anyopaque, block: u64) ChainError!OutputAtBlock,
        anchor_snapshot: *const fn (context: *anyopaque) ChainError!AnchorSnapshot,
        game_count: *const fn (context: *anyopaque) ChainError!u64,
        /// `DisputeGameFactory.games(gameType, rootClaim, extraData)`; null when no game.
        game_lookup: *const fn (
            context: *anyopaque,
            game_type: u32,
            root_claim: Hash,
            extra_data: []const u8,
        ) ChainError!?Address,
        /// The raw `(BLOCK_INTERVAL, INTERMEDIATE_BLOCK_INTERVAL)` pair the factory's current
        /// implementation applies to a game starting at `starting_block`.
        intervals: *const fn (context: *anyopaque, starting_block: u64) ChainError!Intervals,
    };

    pub fn sync_status(chain: Chain) ChainError!SyncStatus {
        return chain.vtable.sync_status(chain.context);
    }

    pub fn output_at_block(chain: Chain, block: u64) ChainError!OutputAtBlock {
        const output = try chain.vtable.output_at_block(chain.context, block);
        if (output.block.number != block) return error.Unavailable;
        return output;
    }

    pub fn anchor_snapshot(chain: Chain) ChainError!AnchorSnapshot {
        return chain.vtable.anchor_snapshot(chain.context);
    }

    pub fn game_count(chain: Chain) ChainError!u64 {
        return chain.vtable.game_count(chain.context);
    }

    pub fn game_lookup(
        chain: Chain,
        game_type: u32,
        root_claim: Hash,
        extra_data: []const u8,
    ) ChainError!?Address {
        assert(extra_data.len >= 52);
        const game = try chain.vtable.game_lookup(chain.context, game_type, root_claim, extra_data);
        if (game) |address| assert(!std.mem.allEqual(u8, &address, 0));
        return game;
    }

    /// The validated interval pair for a game starting at `starting_block`. A pair the
    /// verifier would reject is reported as `Unavailable` (the tick is skipped).
    pub fn intervals_for(chain: Chain, starting_block: u64) ChainError!Intervals {
        const raw = try chain.vtable.intervals(chain.context, starting_block);
        const valid = intervals_module.validate(
            raw.block_interval,
            raw.intermediate_block_interval,
        ) catch return error.Unavailable;
        assert(valid.intermediate_block_interval > 0);
        return valid;
    }
};

/// A proof request for one game range. The session id is the claimed output root.
pub const ProofRequest = struct {
    /// Finalized L1 head the prover derives from.
    l1_head: BlockRef,
    agreed_l2_head_hash: Hash,
    agreed_l2_output_root: Hash,
    agreed_l2_block_number: u64,
    claimed_l2_output_root: Hash,
    claimed_l2_block_number: u64,
    intermediate_block_interval: u64,
    /// The `msg.sender` of the game creation, bound into the proof journal.
    proposer: Address,

    pub fn session(request: *const ProofRequest) Hash {
        assert(request.claimed_l2_block_number > request.agreed_l2_block_number);
        return request.claimed_l2_output_root;
    }
};

/// A completed proof; slices borrow the prover's memory until its next call.
pub const Proof = struct {
    /// The proved claim, re-checked against the canonical root before submission.
    output_root: Hash,
    /// One proved root per intermediate checkpoint, the last being the claim.
    intermediate_roots: []const Hash,
    /// The game's `initData` (proof bytes) for `createWithInitData`.
    init_data: []const u8,
};

pub const ProofStatus = union(enum) {
    pending,
    failed,
    succeeded: Proof,
};

pub const ProverError = error{
    /// No session with that id (never dispatched, or deleted).
    NotFound,
    /// The prover refused the request or is unreachable; retried on a later tick.
    Unavailable,
};

pub const Prover = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Idempotent: requesting an existing session succeeds without new work.
        request: *const fn (context: *anyopaque, request: *const ProofRequest) ProverError!void,
        poll: *const fn (context: *anyopaque, session: Hash) ProverError!ProofStatus,
        delete: *const fn (context: *anyopaque, session: Hash) ProverError!void,
    };

    pub fn request(prover: Prover, proof_request: *const ProofRequest) ProverError!void {
        assert(proof_request.intermediate_block_interval > 0);
        return prover.vtable.request(prover.context, proof_request);
    }

    pub fn poll(prover: Prover, session: Hash) ProverError!ProofStatus {
        return prover.vtable.poll(prover.context, session);
    }

    pub fn delete(prover: Prover, session: Hash) ProverError!void {
        return prover.vtable.delete(prover.context, session);
    }
};

pub const TxId = u64;

/// Why a game creation did not land. The adapter maps revert selectors (gas estimation or
/// receipt) to these; base/base `ProofSubmissionError`.
pub const SubmitFailure = enum {
    /// RPC, nonce or fee failure before or while broadcasting.
    unavailable,
    /// `GameAlreadyExists(bytes32)`: someone created the same game first.
    game_already_exists,
    /// The parent game is unknown, blacklisted, retired or lost (e.g. reorged out).
    invalid_parent_game,
    /// The proof's L1 head fell out of the verifier's history window.
    l1_origin_too_old,
    /// The proof's signer is not registered with the verifier.
    invalid_signer,
    /// Any other revert.
    reverted,
    /// Dropped from the mempool or never mined.
    dropped,
};

pub const SendResult = union(enum) {
    pending: TxId,
    failed: SubmitFailure,
};

pub const TxStatus = union(enum) {
    pending,
    mined,
    failed: SubmitFailure,
};

pub const Submitter = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Sends `createWithInitData` calldata to the factory with the game's init bond.
        send: *const fn (context: *anyopaque, calldata: []const u8) SendResult,
        status: *const fn (context: *anyopaque, tx: TxId) TxStatus,
    };

    pub fn send(submitter: Submitter, calldata: []const u8) SendResult {
        assert(calldata.len >= 4 + 32 * 4);
        return submitter.vtable.send(submitter.context, calldata);
    }

    pub fn status(submitter: Submitter, tx: TxId) TxStatus {
        return submitter.vtable.status(submitter.context, tx);
    }
};

test "proposer interfaces: request session is the claimed root" {
    const request: ProofRequest = .{
        .l1_head = .{ .number = 1, .hash = @splat(1) },
        .agreed_l2_head_hash = @splat(2),
        .agreed_l2_output_root = @splat(3),
        .agreed_l2_block_number = 10,
        .claimed_l2_output_root = @splat(4),
        .claimed_l2_block_number = 20,
        .intermediate_block_interval = 5,
        .proposer = @splat(5),
    };
    try std.testing.expectEqual(@as(Hash, @splat(4)), request.session());
}

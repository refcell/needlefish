//! The challenger's injected world (base/base `crates/proof/challenge/src` talks to it
//! through `DisputeGameFactoryClient`, `AggregateVerifierClient`, `AnchorStateRegistryClient`,
//! `L1Provider`/`L2Provider`, `ProofRequesterProvider` and `TxManager`). Three vtables keep
//! the challenger a deterministic state machine: the simulator and tests use in-memory fakes;
//! network adapters over `proof/rpc` and the contract codecs come later.
//!
//! - `ChainView`: synchronous reads of L1 contract state and L2 headers.
//! - `Prover`: starts a proof job (returns at once) and is polled for its outcome.
//! - `Submitter`: queues a transaction (returns a ticket) and is polled until it is mined.

const std = @import("std");
const assert = std.debug.assert;

const contracts = @import("../contracts/root.zig");

pub const Address = contracts.abi.Address;
pub const Hash = [32]u8;
pub const zero_address: Address = @splat(0);
pub const GameStatus = contracts.aggregate_verifier.GameStatus;
pub const KnownRevert = contracts.aggregate_verifier.KnownRevert;
pub const GameAtIndex = contracts.dispute_game_factory.GameAtIndex;
pub const AnchorRoot = contracts.anchor_state_registry.AnchorRoot;
pub const Preflight = contracts.anchor_state_registry.Preflight;
pub const Withdrawal = contracts.delayed_weth.Withdrawal;
pub const Intervals = contracts.aggregate_verifier.Intervals;

pub fn is_zero(address: Address) bool {
    return std.mem.allEqual(u8, &address, 0);
}

/// A read failed (transport, decode, missing contract). The caller skips and retries later.
pub const ReadError = error{ChainUnavailable};
/// An L2 header read: the block may simply not exist yet.
pub const HeaderError = ReadError || error{BlockNotAvailable};

/// The prover-relevant fields of a game (`status`, `teeProver`, `zkProver`,
/// `counteredByIntermediateRootIndexPlusOne`).
pub const GameState = struct {
    status: GameStatus,
    tee_prover: Address,
    zk_prover: Address,
    /// 1-based challenged index; 0 when unchallenged.
    countered_index: u64,
};

/// The immutable fields of a game, read through its own proxy so the intervals are the
/// ones it was created with.
pub const GameInfo = struct {
    root_claim: Hash,
    l2_block_number: u64,
    parent: Address,
    starting_block_number: u64,
    l1_head: Hash,
    intervals: Intervals,
};

/// The bond fields of a game.
pub const BondState = struct {
    bond_recipient: Address,
    zk_prover: Address,
    resolved_at: u64,
    game_over: bool,
    bond_unlocked: bool,
    bond_claimed: bool,
    delayed_weth: Address,
};

pub const AnchorSnapshot = struct {
    anchor_game: Address,
    anchor_root: AnchorRoot,

    pub fn eql(a: AnchorSnapshot, b: AnchorSnapshot) bool {
        return std.mem.eql(u8, &a.anchor_game, &b.anchor_game) and
            std.mem.eql(u8, &a.anchor_root.root, &b.anchor_root.root) and
            a.anchor_root.l2_block_number == b.anchor_root.l2_block_number;
    }
};

pub const ChainView = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        game_count: *const fn (*anyopaque) ReadError!u64,
        game_at_index: *const fn (*anyopaque, u64) ReadError!GameAtIndex,
        game_state: *const fn (*anyopaque, Address) ReadError!GameState,
        game_info: *const fn (*anyopaque, Address) ReadError!GameInfo,
        /// Fills `out` with the game's intermediate roots.
        intermediate_roots: *const fn (*anyopaque, Address, []Hash) ReadError![]Hash,
        intermediate_root: *const fn (*anyopaque, Address, u64) ReadError!Hash,
        anchor_snapshot: *const fn (*anyopaque) ReadError!AnchorSnapshot,
        /// The factory implementation's intervals for a game starting at `starting_block`.
        implementation_intervals: *const fn (*anyopaque, u32, u64) ReadError!Intervals,
        /// `factory.games(gameType, rootClaim, extraData)`; null when absent.
        factory_game: *const fn (*anyopaque, u32, Hash, []const u8) ReadError!?Address,
        anchor_registry_of: *const fn (*anyopaque, Address) ReadError!Address,
        is_game_finalized: *const fn (*anyopaque, Address, Address) ReadError!bool,
        anchor_preflight: *const fn (*anyopaque, Address, Address) ReadError!Preflight,
        bond_state: *const fn (*anyopaque, Address) ReadError!BondState,
        weth_delay_seconds: *const fn (*anyopaque, Address) ReadError!u64,
        /// `DelayedWETH.withdrawals(owner, guy)` at the given WETH contract.
        withdrawal: *const fn (*anyopaque, Address, Address, Address) ReadError!Withdrawal,
        l1_block_number: *const fn (*anyopaque, Hash) ReadError!u64,
        /// The raw RLP header of an L2 block, written into `out`.
        l2_header: *const fn (*anyopaque, u64, []u8) HeaderError![]const u8,
    };

    pub fn game_count(view: ChainView) ReadError!u64 {
        return view.vtable.game_count(view.context);
    }
    pub fn game_at_index(view: ChainView, index: u64) ReadError!GameAtIndex {
        return view.vtable.game_at_index(view.context, index);
    }
    pub fn game_state(view: ChainView, game: Address) ReadError!GameState {
        return view.vtable.game_state(view.context, game);
    }
    pub fn game_info(view: ChainView, game: Address) ReadError!GameInfo {
        return view.vtable.game_info(view.context, game);
    }
    pub fn intermediate_roots(view: ChainView, game: Address, out: []Hash) ReadError![]Hash {
        const roots = try view.vtable.intermediate_roots(view.context, game, out);
        assert(roots.len <= out.len);
        return roots;
    }
    pub fn intermediate_root(view: ChainView, game: Address, index: u64) ReadError!Hash {
        return view.vtable.intermediate_root(view.context, game, index);
    }
    pub fn anchor_snapshot(view: ChainView) ReadError!AnchorSnapshot {
        return view.vtable.anchor_snapshot(view.context);
    }
    pub fn implementation_intervals(view: ChainView, kind: u32, start: u64) ReadError!Intervals {
        return view.vtable.implementation_intervals(view.context, kind, start);
    }
    pub fn factory_game(
        view: ChainView,
        kind: u32,
        claim: Hash,
        extra_data: []const u8,
    ) ReadError!?Address {
        return view.vtable.factory_game(view.context, kind, claim, extra_data);
    }
    pub fn anchor_registry_of(view: ChainView, game: Address) ReadError!Address {
        return view.vtable.anchor_registry_of(view.context, game);
    }
    pub fn is_game_finalized(view: ChainView, registry: Address, game: Address) ReadError!bool {
        return view.vtable.is_game_finalized(view.context, registry, game);
    }
    pub fn anchor_preflight(view: ChainView, registry: Address, game: Address) ReadError!Preflight {
        return view.vtable.anchor_preflight(view.context, registry, game);
    }
    pub fn bond_state(view: ChainView, game: Address) ReadError!BondState {
        return view.vtable.bond_state(view.context, game);
    }
    pub fn weth_delay_seconds(view: ChainView, weth: Address) ReadError!u64 {
        return view.vtable.weth_delay_seconds(view.context, weth);
    }
    pub fn withdrawal(view: ChainView, weth: Address, owner: Address, guy: Address) ReadError!Withdrawal {
        return view.vtable.withdrawal(view.context, weth, owner, guy);
    }
    pub fn l1_block_number(view: ChainView, hash: Hash) ReadError!u64 {
        return view.vtable.l1_block_number(view.context, hash);
    }
    pub fn l2_header(view: ChainView, number: u64, out: []u8) HeaderError![]const u8 {
        const raw = try view.vtable.l2_header(view.context, number, out);
        assert(raw.len <= out.len);
        return raw;
    }
};

pub const SessionId = u64;

/// A ZK (SP1 PLONK) range proof request (base/base `SnarkPlonkProofRequest`).
pub const ZkRequest = struct {
    start_block_number: u64,
    number_of_blocks_to_prove: u64,
    l1_head: Hash,
    schedule_l2_block_number: u64,
    intermediate_block_interval: u64,
    prover_address: Address,
};

/// A TEE proof request (base/base `base_proof_primitives::ProofRequest`).
pub const TeeRequest = struct {
    l1_head: Hash,
    l1_head_number: u64,
    agreed_l2_head_hash: Hash,
    agreed_l2_output_root: Hash,
    claimed_l2_output_root: Hash,
    claimed_l2_block_number: u64,
    proposer: Address,
    schedule_l2_block_number: u64,
    intermediate_block_interval: u64,
};

pub const ProofRequest = union(enum) { tee: TeeRequest, zk: ZkRequest };

/// A finished proof as the prover service returns it. Slices borrow the prover's memory
/// until the next prover call.
pub const ProofResult = union(enum) {
    /// The aggregate proposal's output root and its 65-byte ECDSA signature.
    tee: struct { output_root: Hash, signature: []const u8 },
    /// The on-chain SP1 proof body: verifier key prefix (4 bytes) then the PLONK proof.
    zk: []const u8,
};

pub const ProverStatus = union(enum) {
    queued,
    running,
    failed,
    /// Null when the service reported success without a result (malformed).
    succeeded: ?ProofResult,
};

pub const ProverError = error{ProverUnavailable};

pub const Prover = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Starts a session proving the checkpoint `invalid_index` of `game`.
        request: *const fn (*anyopaque, Address, u64, ProofRequest) ProverError!SessionId,
        poll: *const fn (*anyopaque, SessionId) ProverError!ProverStatus,
    };

    pub fn request(prover: Prover, game: Address, index: u64, proof: ProofRequest) ProverError!SessionId {
        return prover.vtable.request(prover.context, game, index, proof);
    }
    pub fn poll(prover: Prover, session: SessionId) ProverError!ProverStatus {
        return prover.vtable.poll(prover.context, session);
    }
};

/// Why a transaction failed (base/base `ChallengeSubmitError`).
pub const SubmitError = union(enum) {
    known_revert: KnownRevert,
    /// Mined with a failed status.
    tx_reverted,
    /// The node rejected it during gas estimation with an unknown revert.
    execution_reverted,
    /// Anything else from the transaction manager (nonce, fees, transport, timeout).
    other,
};

pub const Tx = struct {
    to: Address,
    /// Borrowed for the duration of `send` only.
    calldata: []const u8,
};

pub const Ticket = u64;

/// `send` either queues the transaction or rejects it at once (estimation, nonce, fees).
pub const SendResult = union(enum) {
    queued: Ticket,
    rejected: SubmitError,
};

pub const TxStatus = union(enum) {
    pending,
    mined,
    failed: SubmitError,
};

pub const Submitter = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, Tx) SendResult,
        status: *const fn (*anyopaque, Ticket) TxStatus,
    };

    pub fn send(submitter: Submitter, tx: Tx) SendResult {
        assert(tx.calldata.len >= 4);
        return submitter.vtable.send(submitter.context, tx);
    }
    pub fn status(submitter: Submitter, ticket: Ticket) TxStatus {
        return submitter.vtable.status(submitter.context, ticket);
    }
};

/// Everything the challenger reads from and acts on.
pub const World = struct {
    chain: ChainView,
    prover: Prover,
    submitter: Submitter,
};

//! Dispute proof manager (base/base `crates/proof/challenge/src/proof_manager.rs`): starts a
//! dispute attempt per invalid game (TEE first when the game has a TEE proof, with a ZK
//! fallback), and every tick drives each attempt through its needs: prover polls, chain
//! reads, dispute transactions and reproves. Attempts live in a fixed slot table; games
//! that can never be disputed go to a bounded FIFO ignore list.
//!
//! base/base awaits each dispute transaction inline. Here the submitter is polled: while a
//! slot's transaction is pending the attempt is not asked for needs, so it never
//! re-submits; the outcome is applied as the `submitted` event once it lands.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const contracts = @import("../contracts/root.zig");
const dispute_attempt = @import("dispute_attempt.zig");
const scanner = @import("scanner.zig");
const validator = @import("validator.zig");

const Address = chain.Address;
const Hash = chain.Hash;
const DisputeAttempt = dispute_attempt.DisputeAttempt;
const DisputeIntent = dispute_attempt.DisputeIntent;
const Action = dispute_attempt.Action;
const CandidateGame = scanner.CandidateGame;

/// Concurrent dispute attempts.
pub const attempts_max = 64;
/// Ignored games remembered (base/base `MAX_IGNORED_GAMES` is 10 000).
pub const ignored_games_max = 1024;
/// Proof retries per source before an attempt is dropped (base/base `MAX_PROOF_RETRIES`).
pub const proof_retries_max: u32 = 3;
/// Needs (and actions per need) driven per attempt per tick.
pub const steps_per_tick_max = 8;
const calldata_bytes_max = dispute_attempt.proof_bytes_max + 4 + 5 * 32;

pub const InitiateError = error{ AttemptsFull, Overflow, ProverUnavailable };

pub const Stats = struct {
    tee_requests: u64 = 0,
    zk_requests: u64 = 0,
    tee_fallbacks: u64 = 0,
    reproves: u64 = 0,
    submissions: u64 = 0,
    submit_rejections: u64 = 0,
    disputed: u64 = 0,
    dropped: u64 = 0,
    ignored: u64 = 0,
    read_errors: u64 = 0,
};

const Slot = struct {
    game: Address,
    attempt: DisputeAttempt,
    /// The dispute transaction in flight, if any.
    submission: ?chain.Ticket,
};

pub const ProofManager = struct {
    limits: dispute_attempt.AttemptLimits,
    slots: [attempts_max]Slot,
    used: [attempts_max]bool,
    used_count: u32,
    ignored: [ignored_games_max]Address,
    ignored_oldest: u32,
    ignored_count: u32,
    stats: Stats,
    calldata: [calldata_bytes_max]u8,

    /// Initializes in place: the slot table is large.
    pub fn init(
        manager: *ProofManager,
        max_proof_duration_ns: u64,
        tee_submit_retry_limit: u32,
    ) void {
        assert(max_proof_duration_ns > 0);
        manager.limits = .{
            .max_proof_duration_ns = max_proof_duration_ns,
            .tee_submit_retry_limit = tee_submit_retry_limit,
            .max_proof_retries = proof_retries_max,
        };
        manager.used = @splat(false);
        manager.used_count = 0;
        manager.ignored_oldest = 0;
        manager.ignored_count = 0;
        manager.stats = .{};
        assert(manager.pending_count() == 0);
    }

    pub fn pending_count(manager: *const ProofManager) u32 {
        assert(manager.used_count <= attempts_max);
        return manager.used_count;
    }

    pub fn has_pending_proof(manager: *const ProofManager, game: Address) bool {
        return manager.find(game) != null;
    }

    pub fn is_ignored(manager: *const ProofManager, game: Address) bool {
        assert(manager.ignored_count <= ignored_games_max);
        for (0..manager.ignored_count) |offset| {
            const position = (manager.ignored_oldest + offset) % ignored_games_max;
            if (std.mem.eql(u8, &manager.ignored[position], &game)) return true;
        }
        return false;
    }

    /// Starts an attempt: a TEE proof (with a ZK fallback) when the game has a TEE prover
    /// and `try_tee_first`, else a ZK proof. TEE request failures fall back to ZK at once.
    pub fn initiate_proof(
        manager: *ProofManager,
        world: chain.World,
        sender: Address,
        candidate: *const CandidateGame,
        target: dispute_attempt.DisputeTarget,
        intent: DisputeIntent,
        try_tee_first: bool,
        now_ns: u64,
    ) InitiateError!void {
        assert(!manager.has_pending_proof(candidate.proxy));
        if (manager.used_count == attempts_max) return error.AttemptsFull;
        if (!chain.is_zero(candidate.tee_prover) and try_tee_first) {
            if (manager.initiate_tee(world, sender, candidate, target, intent, now_ns)) return;
            manager.stats.tee_fallbacks += 1;
        }
        return manager.initiate_zk_proof(world, sender, candidate, target, intent, now_ns);
    }

    fn initiate_tee(
        manager: *ProofManager,
        world: chain.World,
        sender: Address,
        candidate: *const CandidateGame,
        target: dispute_attempt.DisputeTarget,
        intent: DisputeIntent,
        now_ns: u64,
    ) bool {
        manager.stats.tee_requests += 1;
        const request = build_tee_request(world.chain, sender, candidate, target) catch
            return false;
        const zk_fallback: ?dispute_attempt.ZkFallback = if (build_zk_request(
            sender,
            candidate,
            target.invalid_index,
        )) |zk| .{ .request = zk, .intent = intent } else |_| null;
        const session = world.prover.request(candidate.proxy, target.invalid_index, .{
            .tee = request,
        }) catch return false;
        const attempt: DisputeAttempt = .awaiting_tee(
            session,
            target,
            zk_fallback,
            manager.limits,
            now_ns,
        );
        manager.insert(candidate.proxy, &attempt);
        assert(manager.has_pending_proof(candidate.proxy));
        return true;
    }

    pub fn initiate_zk_proof(
        manager: *ProofManager,
        world: chain.World,
        sender: Address,
        candidate: *const CandidateGame,
        target: dispute_attempt.DisputeTarget,
        intent: DisputeIntent,
        now_ns: u64,
    ) InitiateError!void {
        if (manager.used_count == attempts_max) return error.AttemptsFull;
        const request = try build_zk_request(sender, candidate, target.invalid_index);
        manager.stats.zk_requests += 1;
        const session = try world.prover.request(candidate.proxy, target.invalid_index, .{
            .zk = request,
        });
        const attempt: DisputeAttempt = .awaiting_zk(
            session,
            target,
            request,
            intent,
            manager.limits,
            now_ns,
        );
        manager.insert(candidate.proxy, &attempt);
        assert(manager.has_pending_proof(candidate.proxy));
    }

    /// Drives every attempt once for this tick.
    pub fn poll(manager: *ProofManager, world: chain.World, now_ns: u64) void {
        for (0..attempts_max) |index| {
            if (manager.used[index]) manager.poll_slot(index, world, now_ns);
        }
        assert(manager.used_count <= attempts_max);
    }

    fn poll_slot(manager: *ProofManager, index: usize, world: chain.World, now_ns: u64) void {
        const slot = &manager.slots[index];
        if (slot.submission) |ticket| {
            const result: ?chain.SubmitError = switch (world.submitter.status(ticket)) {
                .pending => return,
                .mined => null,
                .failed => |err| err,
            };
            slot.submission = null;
            const action = slot.attempt.apply(.{ .submitted = result }, now_ns);
            if (!manager.run_actions(index, world, action, now_ns)) return;
        }
        for (0..steps_per_tick_max) |_| {
            const event: dispute_attempt.Event = switch (slot.attempt.need(now_ns)) {
                .idle => return,
                .poll_prover => |session| .{ .prover_status = world.prover.poll(session) catch {
                    manager.stats.read_errors += 1;
                    return;
                } },
                .check_chain => .{ .chain_state = chain_state(world.chain, slot.game) catch {
                    manager.stats.read_errors += 1;
                    return;
                } },
            };
            const action = slot.attempt.apply(event, now_ns);
            if (!manager.run_actions(index, world, action, now_ns)) return;
        }
    }

    /// Carries out actions until the attempt waits. False when the slot was freed or a
    /// transaction is now in flight.
    fn run_actions(
        manager: *ProofManager,
        index: usize,
        world: chain.World,
        first: Action,
        now_ns: u64,
    ) bool {
        const slot = &manager.slots[index];
        assert(manager.used[index]);
        var action = first;
        for (0..steps_per_tick_max) |_| {
            switch (action) {
                .wait => return true,
                .submit => |submit_action| {
                    const result = manager.send_dispute(world.submitter, slot.game, submit_action);
                    const err = switch (result) {
                        .queued => |ticket| {
                            slot.submission = ticket;
                            return false;
                        },
                        .rejected => |err| err,
                    };
                    action = slot.attempt.apply(.{ .submitted = err }, now_ns);
                },
                .reprove => |reprove| {
                    manager.stats.reproves += 1;
                    const session: ?chain.SessionId = world.prover.request(
                        slot.game,
                        reprove.invalid_index,
                        .{ .zk = reprove.request },
                    ) catch null;
                    action = slot.attempt.apply(.{ .reprove_started = session }, now_ns);
                },
                .drop => |reason| {
                    if (reason == .disputed) manager.stats.disputed += 1;
                    manager.stats.dropped += 1;
                    manager.free(index);
                    return false;
                },
                .ignore => {
                    manager.ignore(slot.game);
                    manager.free(index);
                    return false;
                },
            }
        }
        return false;
    }

    fn send_dispute(
        manager: *ProofManager,
        submitter: chain.Submitter,
        game: Address,
        submit_action: dispute_attempt.Submit,
    ) chain.SendResult {
        const kind: contracts.aggregate_verifier.DisputeKind = switch (submit_action.intent) {
            .nullify => .nullify,
            .challenge => .challenge,
        };
        // The buffer fits the largest proof: encoding cannot run out of space.
        const calldata = contracts.aggregate_verifier.encode_dispute(
            &manager.calldata,
            kind,
            submit_action.proof_bytes,
            submit_action.target.invalid_index,
            submit_action.target.expected_root,
        ) catch unreachable;
        manager.stats.submissions += 1;
        const result = submitter.send(.{ .to = game, .calldata = calldata });
        if (result == .rejected) manager.stats.submit_rejections += 1;
        return result;
    }

    fn find(manager: *const ProofManager, game: Address) ?usize {
        for (0..attempts_max) |index| {
            if (!manager.used[index]) continue;
            if (std.mem.eql(u8, &manager.slots[index].game, &game)) return index;
        }
        return null;
    }

    fn insert(manager: *ProofManager, game: Address, attempt: *const DisputeAttempt) void {
        assert(manager.find(game) == null);
        const index = std.mem.indexOfScalar(bool, &manager.used, false).?;
        manager.slots[index] = .{ .game = game, .attempt = attempt.*, .submission = null };
        manager.used[index] = true;
        manager.used_count += 1;
        assert(manager.used_count <= attempts_max);
    }

    fn free(manager: *ProofManager, index: usize) void {
        assert(manager.used[index]);
        assert(manager.used_count > 0);
        manager.used[index] = false;
        manager.used_count -= 1;
    }

    fn ignore(manager: *ProofManager, game: Address) void {
        manager.stats.ignored += 1;
        if (manager.is_ignored(game)) return;
        if (manager.ignored_count == ignored_games_max) {
            manager.ignored_oldest = (manager.ignored_oldest + 1) % ignored_games_max;
            manager.ignored_count -= 1;
        }
        const position = (manager.ignored_oldest + manager.ignored_count) % ignored_games_max;
        manager.ignored[position] = game;
        manager.ignored_count += 1;
        assert(manager.is_ignored(game));
    }
};

fn chain_state(view: chain.ChainView, game: Address) chain.ReadError!dispute_attempt.ChainState {
    const state = try view.game_state(game);
    return .{
        .status = state.status,
        .tee_prover = state.tee_prover,
        .zk_prover = state.zk_prover,
    };
}

/// The ZK request proving checkpoint `invalid_index` of a game.
pub fn build_zk_request(
    sender: Address,
    candidate: *const CandidateGame,
    invalid_index: u64,
) error{Overflow}!chain.ZkRequest {
    const start = try candidate.checkpoint_start_block(invalid_index);
    assert(candidate.intermediate_block_interval > 0);
    return .{
        .start_block_number = start,
        .number_of_blocks_to_prove = candidate.intermediate_block_interval,
        .l1_head = candidate.l1_head,
        .schedule_l2_block_number = candidate.l2_block_number,
        .intermediate_block_interval = candidate.intermediate_block_interval,
        .prover_address = sender,
    };
}

/// The TEE request: the agreed output at the checkpoint start (from the L2 header) and the
/// root the challenger expects at its end.
pub fn build_tee_request(
    view: chain.ChainView,
    sender: Address,
    candidate: *const CandidateGame,
    target: dispute_attempt.DisputeTarget,
) (validator.Error || error{Overflow})!chain.TeeRequest {
    const start = try candidate.checkpoint_start_block(target.invalid_index);
    const claimed_block = try std.math.add(u64, start, candidate.intermediate_block_interval);
    const l1_head_number = try view.l1_block_number(candidate.l1_head);
    const agreed = try validator.compute_output_root_with_hash(view, start);
    assert(claimed_block > start);
    return .{
        .l1_head = candidate.l1_head,
        .l1_head_number = l1_head_number,
        .agreed_l2_head_hash = agreed.block_hash,
        .agreed_l2_output_root = agreed.output_root,
        .claimed_l2_output_root = target.expected_root,
        .claimed_l2_block_number = claimed_block,
        .proposer = sender,
        .schedule_l2_block_number = candidate.l2_block_number,
        .intermediate_block_interval = candidate.intermediate_block_interval,
    };
}

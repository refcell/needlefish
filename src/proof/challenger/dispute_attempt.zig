//! One game's dispute attempt (base/base `crates/proof/challenge/src/dispute_attempt.rs`):
//! the proof and dispute lifecycle across TEE and ZK proof sources, including the ZK
//! fallback, without IO. The proof manager asks `need(now)` what to read next, feeds the
//! answer back as an `Event` through `apply`, and carries out the returned `Action`.
//!
//! A TEE attempt always nullifies the TEE proof; when it fails (proof, validation, or a
//! rejected or repeatedly failing dispute transaction) it falls back to the ZK request it
//! was created with, which then challenges or nullifies with a fresh retry budget. ZK
//! submissions retry without bound; every new proof (timeout, failure, reprove error)
//! spends one retry until `max_proof_retries` is exceeded.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const contracts = @import("../contracts/root.zig");

const Address = chain.Address;
const Hash = chain.Hash;
const SessionId = chain.SessionId;
const GameStatus = chain.GameStatus;
const KnownRevert = chain.KnownRevert;
const SubmitError = chain.SubmitError;
const ZkRequest = chain.ZkRequest;

/// Largest dispute proof (type byte + SP1 PLONK proof with its verifier key prefix).
pub const proof_bytes_max = 2048;
const ecdsa_signature_bytes = 65;

pub const DisputeIntent = enum {
    /// `challenge()`: refute a TEE proof with a ZK proof.
    challenge,
    /// `nullify()`: remove a proof (or a ZK challenge) with a proof of the same kind.
    nullify,
};

pub const AttemptLimits = struct {
    max_proof_duration_ns: u64,
    tee_submit_retry_limit: u32,
    max_proof_retries: u32,
};

pub const DisputeTarget = struct { invalid_index: u64, expected_root: Hash };

pub const ZkFallback = struct { request: ZkRequest, intent: DisputeIntent };

pub const ProofSource = enum { tee, zk };

pub const TeeProofError = error{ WrongKind, UnexpectedOutputRoot, EncodingFailed };
pub const ZkProofError = error{ WrongKind, MockProof, TooLarge };

pub const RetryReason = union(enum) {
    timeout: struct { elapsed_ns: u64, limit_ns: u64 },
    /// The prover reported success without a result.
    malformed,
    tee_validation: TeeProofError,
    prover_failed,
};

pub const Need = union(enum) {
    idle,
    poll_prover: SessionId,
    /// Read the game's status and provers; carries the timeout that forced the read.
    check_chain: ?RetryReason,
};

pub const ChainState = struct {
    status: GameStatus,
    tee_prover: Address,
    zk_prover: Address,
};

pub const Event = union(enum) {
    prover_status: chain.ProverStatus,
    chain_state: ChainState,
    /// The dispute transaction's outcome; null when it was mined successfully.
    submitted: ?SubmitError,
    /// The new prover session of a reprove; null when the request failed.
    reprove_started: ?SessionId,
};

pub const AttemptUpdate = union(enum) {
    pending,
    ready: ProofSource,
    needs_retry: RetryReason,
    zk_decode_error: ZkProofError,
    tee_submit_retry: struct { count: u32, limit: u32, has_zk_fallback: bool, err: SubmitError },
    zk_submit_retry: SubmitError,
    reprove_started: struct { session: SessionId, retry_count: u32 },
    reprove_failed: struct { retry_count: u32 },
};

pub const TeeSubmissionFailure = union(enum) {
    rejected: SubmitError,
    retry_limit: struct { count: u32, limit: u32, has_zk_fallback: bool, err: SubmitError },
};

pub const DropReason = union(enum) {
    disputed,
    game_not_in_progress: GameStatus,
    already_resolved: struct { intent: DisputeIntent, tee_prover: Address, zk_prover: Address },
    already_resolved_revert: KnownRevert,
    retries_exhausted: struct { retry_count: u32, submission_failure: ?TeeSubmissionFailure },
    no_zk_fallback: ?TeeSubmissionFailure,
    zk_invalid_signer,
};

pub const IgnoreReason = union(enum) {
    invalid_parent_game,
    l1_origin_too_old,
    zk_invalid_proof: u64,
};

pub const AttemptReprove = struct {
    request: ZkRequest,
    invalid_index: u64,
    retry_count: u32,
    /// True when this reprove is the switch from TEE to ZK.
    fallback: bool,
    submission_failure: ?TeeSubmissionFailure,
};

pub const Submit = struct {
    /// Borrows the attempt until its next `apply`.
    proof_bytes: []const u8,
    target: DisputeTarget,
    intent: DisputeIntent,
    source: ProofSource,
    just_obtained: bool,
};

pub const Action = union(enum) {
    wait: AttemptUpdate,
    submit: Submit,
    reprove: AttemptReprove,
    drop: DropReason,
    ignore: IgnoreReason,
};

pub const Source = union(enum) {
    tee: struct { zk_fallback: ?ZkFallback, retry_count: u32, submit_retry_count: u32 },
    zk: struct { request: ZkRequest, intent: DisputeIntent, retry_count: u32 },
};

pub const Phase = union(enum) {
    awaiting: struct { session: SessionId, started_at_ns: u64 },
    ready: struct { just_obtained: bool },
    needs_retry,
    reproving: u32,
    done,
};

/// `0x00 ++ signature` with `v` normalized to 27/28 (base/base `ProofEncoder`), after
/// checking the TEE computed the root the challenger expects.
pub fn tee_dispute_proof_bytes(
    out: []u8,
    result: chain.ProofResult,
    expected_root: Hash,
) TeeProofError![]u8 {
    assert(out.len >= 1 + ecdsa_signature_bytes);
    const tee = switch (result) {
        .tee => |tee| tee,
        .zk => return error.WrongKind,
    };
    if (!std.mem.eql(u8, &tee.output_root, &expected_root)) return error.UnexpectedOutputRoot;
    if (tee.signature.len != ecdsa_signature_bytes) return error.EncodingFailed;
    const proof = out[0 .. 1 + ecdsa_signature_bytes];
    proof[0] = contracts.aggregate_verifier.proof_type_tee;
    @memcpy(proof[1..], tee.signature);
    proof[65] = switch (proof[65]) {
        0, 1 => proof[65] + 27,
        27, 28 => proof[65],
        else => return error.EncodingFailed,
    };
    assert(proof[65] == 27 or proof[65] == 28);
    return proof;
}

/// `0x01 ++ vkey_prefix ++ plonk_proof` (base/base `SnarkReceiptEncoder`).
pub fn zk_dispute_proof_bytes(out: []u8, result: chain.ProofResult) ZkProofError![]u8 {
    const body = switch (result) {
        .zk => |body| body,
        .tee => return error.WrongKind,
    };
    if (body.len == 0) return error.MockProof;
    if (body.len + 1 > out.len) return error.TooLarge;
    out[0] = contracts.aggregate_verifier.proof_type_zk;
    @memcpy(out[1..][0..body.len], body);
    assert(out[0] == 1);
    return out[0 .. body.len + 1];
}

pub const DisputeAttempt = struct {
    target: DisputeTarget,
    limits: AttemptLimits,
    source: Source,
    phase: Phase,
    tick: ?u64 = null,
    polled: bool = false,
    checked_chain: bool = false,
    proof_length: u32 = 0,
    proof_bytes: [proof_bytes_max]u8 = undefined,

    pub fn awaiting_tee(
        session: SessionId,
        target: DisputeTarget,
        zk_fallback: ?ZkFallback,
        limits: AttemptLimits,
        now_ns: u64,
    ) DisputeAttempt {
        assert(limits.max_proof_duration_ns > 0);
        return .{
            .target = target,
            .limits = limits,
            .source = .{ .tee = .{
                .zk_fallback = zk_fallback,
                .retry_count = 0,
                .submit_retry_count = 0,
            } },
            .phase = .{ .awaiting = .{ .session = session, .started_at_ns = now_ns } },
        };
    }

    pub fn awaiting_zk(
        session: SessionId,
        target: DisputeTarget,
        request: ZkRequest,
        intent: DisputeIntent,
        limits: AttemptLimits,
        now_ns: u64,
    ) DisputeAttempt {
        assert(limits.max_proof_duration_ns > 0);
        return .{
            .target = target,
            .limits = limits,
            .source = .{ .zk = .{ .request = request, .intent = intent, .retry_count = 0 } },
            .phase = .{ .awaiting = .{ .session = session, .started_at_ns = now_ns } },
        };
    }

    /// What the attempt needs read this tick. Each read is requested at most once per
    /// `now`; a new `now` starts a new tick.
    pub fn need(attempt: *DisputeAttempt, now_ns: u64) Need {
        if (attempt.tick != now_ns) {
            // A reprove that never got its result back is retried after a chain check.
            if (attempt.tick != null and attempt.phase == .reproving) attempt.phase = .needs_retry;
            attempt.tick = now_ns;
            attempt.polled = false;
            attempt.checked_chain = false;
            if (attempt.phase == .ready) attempt.phase.ready.just_obtained = false;
        }
        assert(attempt.tick.? == now_ns);
        if (attempt.checked_chain) return .idle;
        if (attempt.phase == .awaiting) {
            if (attempt.polled) return .idle;
            const elapsed_ns = now_ns -| attempt.phase.awaiting.started_at_ns;
            if (elapsed_ns > attempt.limits.max_proof_duration_ns) {
                attempt.increment_retry();
                attempt.phase = .needs_retry;
                attempt.checked_chain = true;
                return .{ .check_chain = .{ .timeout = .{
                    .elapsed_ns = elapsed_ns,
                    .limit_ns = attempt.limits.max_proof_duration_ns,
                } } };
            }
        }
        switch (attempt.phase) {
            .awaiting => |awaiting| {
                attempt.polled = true;
                return .{ .poll_prover = awaiting.session };
            },
            .ready, .needs_retry => {
                attempt.checked_chain = true;
                return .{ .check_chain = null };
            },
            .reproving, .done => return .idle,
        }
    }

    /// Applies one read or effect result. Events that do not fit the phase are ignored.
    pub fn apply(attempt: *DisputeAttempt, event: Event, now_ns: u64) Action {
        switch (event) {
            .prover_status => |status| if (attempt.phase == .awaiting) {
                return attempt.apply_prover_status(status);
            },
            .chain_state => |state| if (attempt.phase == .needs_retry or attempt.phase == .ready) {
                return attempt.apply_chain_state(state);
            },
            .submitted => |result| if (attempt.phase == .ready) {
                return attempt.apply_submitted(result);
            },
            .reprove_started => |result| if (attempt.phase == .reproving) {
                return attempt.apply_reprove_started(result, now_ns);
            },
        }
        return .{ .wait = .pending };
    }

    pub fn is_done(attempt: *const DisputeAttempt) bool {
        return attempt.phase == .done;
    }

    pub fn proof_source(attempt: *const DisputeAttempt) struct { ProofSource, DisputeIntent } {
        return switch (attempt.source) {
            .tee => .{ .tee, .nullify },
            .zk => |zk| .{ .zk, zk.intent },
        };
    }

    pub fn retry_count(attempt: *const DisputeAttempt) u32 {
        return switch (attempt.source) {
            .tee => |tee| tee.retry_count,
            .zk => |zk| zk.retry_count,
        };
    }

    fn apply_prover_status(attempt: *DisputeAttempt, status: chain.ProverStatus) Action {
        assert(attempt.phase == .awaiting);
        const reason: RetryReason = switch (status) {
            .queued, .running => return .{ .wait = .pending },
            .failed => .prover_failed,
            .succeeded => |maybe_result| reason: {
                const result = maybe_result orelse break :reason .malformed;
                const source, _ = attempt.proof_source();
                switch (source) {
                    .tee => {
                        const proof = tee_dispute_proof_bytes(
                            &attempt.proof_bytes,
                            result,
                            attempt.target.expected_root,
                        ) catch |err| break :reason .{ .tee_validation = err };
                        attempt.proof_length = @intCast(proof.len);
                    },
                    .zk => {
                        const proof = zk_dispute_proof_bytes(&attempt.proof_bytes, result) catch |err|
                            return .{ .wait = .{ .zk_decode_error = err } };
                        attempt.proof_length = @intCast(proof.len);
                    },
                }
                attempt.phase = .{ .ready = .{ .just_obtained = true } };
                assert(attempt.proof_length > 0);
                return .{ .wait = .{ .ready = source } };
            },
        };
        attempt.increment_retry();
        attempt.phase = .needs_retry;
        return .{ .wait = .{ .needs_retry = reason } };
    }

    fn apply_chain_state(attempt: *DisputeAttempt, state: ChainState) Action {
        assert(attempt.phase == .needs_retry or attempt.phase == .ready);
        const source, const intent = attempt.proof_source();
        if (state.status != .in_progress) {
            attempt.phase = .done;
            return .{ .drop = .{ .game_not_in_progress = state.status } };
        }
        const already_resolved = switch (intent) {
            .challenge => !chain.is_zero(state.zk_prover) or chain.is_zero(state.tee_prover),
            .nullify => switch (source) {
                .tee => chain.is_zero(state.tee_prover),
                .zk => chain.is_zero(state.zk_prover),
            },
        };
        if (already_resolved) {
            attempt.phase = .done;
            return .{ .drop = .{ .already_resolved = .{
                .intent = intent,
                .tee_prover = state.tee_prover,
                .zk_prover = state.zk_prover,
            } } };
        }
        return switch (attempt.phase) {
            .ready => |ready| .{ .submit = .{
                .proof_bytes = attempt.proof_bytes[0..attempt.proof_length],
                .target = attempt.target,
                .intent = intent,
                .source = source,
                .just_obtained = ready.just_obtained,
            } },
            else => attempt.reprove(null),
        };
    }

    fn apply_submitted(attempt: *DisputeAttempt, result: ?SubmitError) Action {
        assert(attempt.phase == .ready);
        const err = result orelse {
            attempt.phase = .done;
            return .{ .drop = .disputed };
        };
        const is_tee = attempt.source == .tee;
        if (attempt.terminal_submit_action(err, is_tee)) |action| {
            attempt.phase = .done;
            return action;
        }
        if (!is_tee) return .{ .wait = .{ .zk_submit_retry = err } };
        const rejected = switch (err) {
            .known_revert => |revert| revert == .invalid_signer or revert == .invalid_proof,
            .tx_reverted, .execution_reverted => true,
            .other => false,
        };
        if (rejected) return attempt.reprove(.{ .rejected = err });
        const tee = &attempt.source.tee;
        const count = tee.submit_retry_count;
        const limit = attempt.limits.tee_submit_retry_limit;
        const has_zk_fallback = tee.zk_fallback != null;
        if (count >= limit) {
            return attempt.reprove(.{ .retry_limit = .{
                .count = count,
                .limit = limit,
                .has_zk_fallback = has_zk_fallback,
                .err = err,
            } });
        }
        tee.submit_retry_count = count +| 1;
        return .{ .wait = .{ .tee_submit_retry = .{
            .count = tee.submit_retry_count,
            .limit = limit,
            .has_zk_fallback = has_zk_fallback,
            .err = err,
        } } };
    }

    fn terminal_submit_action(attempt: *const DisputeAttempt, err: SubmitError, is_tee: bool) ?Action {
        assert(attempt.phase == .ready);
        const revert = switch (err) {
            .known_revert => |revert| revert,
            else => return null,
        };
        return switch (revert) {
            .game_already_exists, .proof_already_verified => .{
                .drop = .{ .already_resolved_revert = revert },
            },
            .invalid_parent_game => .{ .ignore = .invalid_parent_game },
            .l1_origin_too_old => .{ .ignore = .l1_origin_too_old },
            .invalid_proof => if (is_tee)
                null
            else
                .{ .ignore = .{ .zk_invalid_proof = attempt.target.invalid_index } },
            .invalid_signer => if (is_tee) null else .{ .drop = .zk_invalid_signer },
        };
    }

    fn apply_reprove_started(attempt: *DisputeAttempt, result: ?SessionId, now_ns: u64) Action {
        const count = attempt.phase.reproving;
        if (result) |session| {
            attempt.phase = .{ .awaiting = .{ .session = session, .started_at_ns = now_ns } };
            return .{ .wait = .{ .reprove_started = .{ .session = session, .retry_count = count } } };
        }
        attempt.increment_retry();
        attempt.phase = .needs_retry;
        assert(attempt.retry_count() > 0);
        return .{ .wait = .{ .reprove_failed = .{ .retry_count = count } } };
    }

    fn increment_retry(attempt: *DisputeAttempt) void {
        switch (attempt.source) {
            .tee => |*tee| tee.retry_count +|= 1,
            .zk => |*zk| zk.retry_count +|= 1,
        }
        assert(attempt.retry_count() > 0);
    }

    fn reprove(attempt: *DisputeAttempt, submission_failure: ?TeeSubmissionFailure) Action {
        const count = attempt.retry_count();
        if (count > attempt.limits.max_proof_retries) {
            attempt.phase = .done;
            return .{ .drop = .{ .retries_exhausted = .{
                .retry_count = count,
                .submission_failure = submission_failure,
            } } };
        }
        const fallback = attempt.source == .tee;
        const request = switch (attempt.source) {
            .tee => |tee| request: {
                const zk_fallback = tee.zk_fallback orelse {
                    attempt.phase = .done;
                    return .{ .drop = .{ .no_zk_fallback = submission_failure } };
                };
                attempt.source = .{ .zk = .{
                    .request = zk_fallback.request,
                    .intent = zk_fallback.intent,
                    .retry_count = 0,
                } };
                break :request zk_fallback.request;
            },
            .zk => |zk| zk.request,
        };
        assert(attempt.source == .zk);
        attempt.phase = .{ .reproving = count };
        return .{ .reprove = .{
            .request = request,
            .invalid_index = attempt.target.invalid_index,
            .retry_count = count,
            .fallback = fallback,
            .submission_failure = submission_failure,
        } };
    }
};

test {
    _ = @import("dispute_attempt_test.zig");
}

//! Tests of the dispute attempt state machine, ported from the unit tests of base/base
//! `crates/proof/challenge/src/dispute_attempt.rs`.

const std = @import("std");
const testing = std.testing;

const chain = @import("chain.zig");
const attempt_module = @import("dispute_attempt.zig");

const DisputeAttempt = attempt_module.DisputeAttempt;
const Event = attempt_module.Event;
const Action = attempt_module.Action;
const Need = attempt_module.Need;
const SubmitError = chain.SubmitError;

const second = std.time.ns_per_s;
const start: u64 = 1_000 * second;

const session_first: chain.SessionId = 1;
const session_tee: chain.SessionId = 2;
const session_next: chain.SessionId = 3;

const zk_body = [_]u8{ 0x5a, 0x09, 0x3a, 0x2f, 0xab, 0xcd };
const zk_proof = [_]u8{ 1, 0x5a, 0x09, 0x3a, 0x2f, 0xab, 0xcd };
const zero_signature: [65]u8 = @splat(0);

fn request() chain.ZkRequest {
    return .{
        .start_block_number = 0,
        .number_of_blocks_to_prove = 1,
        .l1_head = @splat(0),
        .schedule_l2_block_number = 0,
        .intermediate_block_interval = 1,
        .prover_address = @splat(0),
    };
}

fn limits() attempt_module.AttemptLimits {
    return .{
        .max_proof_duration_ns = 10 * second,
        .tee_submit_retry_limit = 1,
        .max_proof_retries = 2,
    };
}

fn target() attempt_module.DisputeTarget {
    return .{ .invalid_index = 3, .expected_root = @splat(0xaa) };
}

fn zk(now: u64) DisputeAttempt {
    return .awaiting_zk(session_first, target(), request(), .challenge, limits(), now);
}

fn zk_with(now: u64, intent: attempt_module.DisputeIntent) DisputeAttempt {
    return .awaiting_zk(session_first, target(), request(), intent, limits(), now);
}

fn tee(now: u64, fallback: bool) DisputeAttempt {
    const zk_fallback: ?attempt_module.ZkFallback =
        if (fallback) .{ .request = request(), .intent = .challenge } else null;
    return .awaiting_tee(session_tee, target(), zk_fallback, limits(), now);
}

fn success(is_tee: bool) Event {
    const result: chain.ProofResult = if (is_tee)
        .{ .tee = .{ .output_root = target().expected_root, .signature = &zero_signature } }
    else
        .{ .zk = &zk_body };
    return .{ .prover_status = .{ .succeeded = result } };
}

fn response(status: chain.ProverStatus) Event {
    return .{ .prover_status = status };
}

fn chain_state() Event {
    return chain_event(.in_progress, @splat(1), @splat(0));
}

fn chain_event(
    status: chain.GameStatus,
    tee_prover: chain.Address,
    zk_prover: chain.Address,
) Event {
    return .{ .chain_state = .{
        .status = status,
        .tee_prover = tee_prover,
        .zk_prover = zk_prover,
    } };
}

const submit_failure: Event = .{ .submitted = .other };
const reprove_next: Event = .{ .reprove_started = session_next };
const reprove_error: Event = .{ .reprove_started = null };

const Step = enum { idle, poll, chain, timeout, submit, reprove, remove, transport_error };

const Trace = struct {
    steps: [16]Step = undefined,
    len: usize = 0,

    fn push(trace: *Trace, step: Step) void {
        trace.steps[trace.len] = step;
        trace.len += 1;
    }

    fn expect(trace: *const Trace, expected: []const Step) !void {
        try testing.expectEqualSlices(Step, expected, trace.steps[0..trace.len]);
    }
};

/// Drives one tick the way the proof manager does, answering each need from `events`.
fn drive_tick(attempt: *DisputeAttempt, now: u64, events: []const Event) !Trace {
    var trace: Trace = .{};
    var next: usize = 0;
    for (0..8) |_| {
        const need = attempt.need(now);
        trace.push(switch (need) {
            .idle => .idle,
            .poll_prover => .poll,
            .check_chain => |timeout| if (timeout == null) .chain else .timeout,
        });
        if (need == .idle) {
            try testing.expectEqual(events.len, next); // No unused scripted response.
            return trace;
        }
        if (next == events.len) {
            trace.push(.transport_error);
            return trace;
        }
        var action = attempt.apply(events[next], now);
        next += 1;
        while (true) {
            switch (action) {
                .wait => break,
                .submit => trace.push(.submit),
                .reprove => trace.push(.reprove),
                .drop, .ignore => {
                    trace.push(.remove);
                    return trace;
                },
            }
            action = attempt.apply(events[next], now);
            next += 1;
        }
    }
    return trace;
}

test "challenger dispute attempt: tick sequences follow needs without inspecting updates" {
    const Case = struct { DisputeAttempt, u64, []const Event, []const Step };
    var ready = tee(start, true);
    _ = ready.apply(success(true), start);
    var retry = zk(start);
    _ = retry.apply(response(.failed), start);
    const cases = [_]Case{
        .{ zk(start), start, &.{response(.running)}, &.{ .poll, .idle } },
        .{ zk(start), start, &.{success(true)}, &.{ .poll, .idle } },
        .{
            tee(start, true),
            start,
            &.{ success(true), chain_state(), submit_failure },
            &.{ .poll, .chain, .submit, .idle },
        },
        .{
            zk(start),
            start,
            &.{ success(false), chain_state(), submit_failure },
            &.{ .poll, .chain, .submit, .idle },
        },
        .{
            zk(start),
            start,
            &.{ response(.failed), chain_state(), reprove_next },
            &.{ .poll, .chain, .reprove, .idle },
        },
        .{
            tee(start, true),
            start,
            &.{ response(.failed), chain_state(), reprove_next },
            &.{ .poll, .chain, .reprove, .idle },
        },
        .{ retry, start, &.{ chain_state(), reprove_next }, &.{ .chain, .reprove, .idle } },
        .{
            zk(start),
            start,
            &.{ response(.failed), chain_state(), reprove_error },
            &.{ .poll, .chain, .reprove, .idle },
        },
        .{ ready, start, &.{ chain_state(), submit_failure }, &.{ .chain, .submit, .idle } },
        .{
            zk(start),
            start + 11 * second,
            &.{ chain_state(), reprove_next },
            &.{ .timeout, .reprove, .idle },
        },
        .{
            tee(start, true),
            start,
            &.{
                success(true),
                chain_state(),
                .{ .submitted = .{ .known_revert = .invalid_proof } },
                reprove_next,
            },
            &.{ .poll, .chain, .submit, .reprove, .idle },
        },
    };
    for (cases) |case| {
        var attempt = case[0];
        const trace = try drive_tick(&attempt, case[1], case[2]);
        try trace.expect(case[3]);
    }
}

test "challenger dispute attempt: reprove timeout starts at completion" {
    var attempt = zk(start);
    try testing.expect(attempt.need(start) == .poll_prover);
    _ = attempt.apply(response(.failed), start);
    try testing.expect(attempt.need(start).check_chain == null);
    try testing.expect(attempt.apply(chain_state(), start) == .reprove);
    const completed_at = start + 20 * second;
    _ = attempt.apply(reprove_next, completed_at);
    try testing.expect(attempt.need(start) == .idle);
    const deadline = completed_at + 10 * second;
    try testing.expectEqual(session_next, attempt.need(deadline).poll_prover);
    const timeout = attempt.need(deadline + second).check_chain.?.timeout;
    try testing.expectEqual(11 * second, timeout.elapsed_ns);
    try testing.expectEqual(10 * second, timeout.limit_ns);
}

test "challenger dispute attempt: idle ticks resume only with a new now" {
    const Case = struct { DisputeAttempt, []const Event, Step };
    const cases = [_]Case{
        .{ zk(start), &.{response(.running)}, .poll },
        .{ zk(start), &.{success(true)}, .poll },
        .{ tee(start, true), &.{ success(true), chain_state(), submit_failure }, .chain },
        .{ zk(start), &.{ success(false), chain_state(), submit_failure }, .chain },
        .{ zk(start), &.{ response(.failed), chain_state(), reprove_next }, .poll },
        .{ zk(start), &.{ response(.failed), chain_state(), reprove_error }, .chain },
        .{ zk(start), &.{ success(false), chain_state(), .{ .submitted = null } }, .idle },
    };
    for (cases) |case| {
        var attempt = case[0];
        _ = try drive_tick(&attempt, start, case[1]);
        for (0..2) |_| try (try drive_tick(&attempt, start, &.{})).expect(&.{.idle});
        const trace = try drive_tick(&attempt, start + second, &.{});
        if (case[2] == .idle) {
            try trace.expect(&.{.idle});
        } else {
            try trace.expect(&.{ case[2], .transport_error });
        }
    }
}

fn expect_unapplied_reprove_recovers(initial: DisputeAttempt, fallback: bool) !void {
    var attempt = initial;
    try testing.expect(attempt.need(start) == .poll_prover);
    _ = attempt.apply(response(.failed), start);
    try testing.expect(attempt.need(start).check_chain == null);
    const first = attempt.apply(chain_state(), start).reprove;
    try testing.expectEqual(@as(u32, 1), first.retry_count);
    try testing.expectEqual(fallback, first.fallback);
    try testing.expect(attempt.need(start) == .idle);
    const next = start + second;
    try testing.expect(attempt.need(next).check_chain == null);
    const retry = attempt.apply(chain_state(), next).reprove;
    try testing.expectEqual(first.request, retry.request);
    try testing.expectEqual(@as(u32, if (fallback) 0 else 1), retry.retry_count);
    try testing.expect(!retry.fallback);
    try testing.expect(attempt.need(next) == .idle);
    _ = attempt.apply(reprove_next, next);
    const proof_tick = next + second;
    try testing.expectEqual(session_next, attempt.need(proof_tick).poll_prover);
    _ = attempt.apply(success(false), proof_tick);
    try testing.expect(attempt.need(proof_tick).check_chain == null);
    const submit = attempt.apply(chain_state(), proof_tick).submit;
    try testing.expectEqual(attempt_module.ProofSource.zk, submit.source);
    try testing.expectEqual(attempt_module.DisputeIntent.challenge, submit.intent);
}

test "challenger dispute attempt: unapplied reprove retries next tick" {
    try expect_unapplied_reprove_recovers(zk(start), false);
    try expect_unapplied_reprove_recovers(tee(start, true), true);
}

test "challenger dispute attempt: TEE proof is just obtained only in its poll tick" {
    for ([_]bool{ false, true }) |chain_read_fails| {
        var attempt = tee(start, true);
        try testing.expect(attempt.need(start) == .poll_prover);
        _ = attempt.apply(success(true), start);
        try testing.expect(attempt.need(start) == .check_chain);
        var tick = start;
        if (chain_read_fails) {
            tick = start + second;
            try testing.expect(attempt.need(tick) == .check_chain);
        }
        const submit = attempt.apply(chain_state(), tick).submit;
        try testing.expectEqual(!chain_read_fails, submit.just_obtained);
        _ = attempt.apply(submit_failure, tick);
        try testing.expect(attempt.need(tick) == .idle);
    }
}

test "challenger dispute attempt: proof results validate each field" {
    for ([_]bool{ false, true }) |is_tee| {
        var attempt = if (is_tee) tee(start, true) else zk(start);
        var tick = start;
        for ([_]chain.ProverStatus{ .queued, .running }) |status| {
            try testing.expect(attempt.need(tick) == .poll_prover);
            try testing.expect(attempt.apply(response(status), tick).wait == .pending);
            try testing.expect(attempt.need(tick) == .idle);
            tick += second;
        }
        try testing.expect(attempt.need(tick) == .poll_prover);
        try testing.expect(attempt.apply(success(is_tee), tick).wait == .ready);
        try testing.expect(attempt.need(tick) == .check_chain);
        const proof = attempt.apply(chain_state(), tick).submit.proof_bytes;
        if (is_tee) {
            var expected: [66]u8 = @splat(0);
            expected[65] = 27;
            try testing.expectEqualSlices(u8, &expected, proof);
        } else {
            try testing.expectEqualSlices(u8, &zk_proof, proof);
        }
    }
    for ([_]bool{ true, false }) |bad_root| {
        const result: chain.ProofResult = if (bad_root)
            .{ .tee = .{ .output_root = @splat(0), .signature = &zero_signature } }
        else
            .{ .tee = .{ .output_root = target().expected_root, .signature = &.{} } };
        var attempt = tee(start, true);
        const action = attempt.apply(.{ .prover_status = .{ .succeeded = result } }, start);
        const expected = if (bad_root) error.UnexpectedOutputRoot else error.EncodingFailed;
        try testing.expectEqual(expected, action.wait.needs_retry.tee_validation);
    }
    var attempt = zk(start);
    const empty: Event = .{ .prover_status = .{ .succeeded = .{ .zk = &.{} } } };
    try testing.expectEqual(error.MockProof, attempt.apply(empty, start).wait.zk_decode_error);
    try testing.expect(attempt.need(start + 11 * second).check_chain.? == .timeout);
    try testing.expectEqual(@as(u32, 1), attempt.apply(chain_state(), start).reprove.retry_count);
}

test "challenger dispute attempt: decode outcomes and fallback reset the budget" {
    var attempt = zk(start);
    try testing.expect(attempt.apply(success(true), start).wait == .zk_decode_error);
    try testing.expect(attempt.need(start) == .poll_prover);
    _ = attempt.apply(response(.failed), start);
    try testing.expectEqual(@as(u32, 1), attempt.apply(chain_state(), start).reprove.retry_count);
    for ([_]bool{ false, true }) |fallback| {
        var tee_attempt = tee(start, fallback);
        const update = tee_attempt.apply(success(false), start).wait;
        try testing.expectEqual(error.WrongKind, update.needs_retry.tee_validation);
        const action = tee_attempt.apply(chain_state(), start);
        if (!fallback) {
            try testing.expect(action.drop == .no_zk_fallback);
            continue;
        }
        try testing.expectEqual(@as(u32, 1), action.reprove.retry_count);
        try testing.expect(action.reprove.fallback);
        _ = tee_attempt.apply(reprove_next, start);
        for ([_]u32{ 1, 2 }) |count| {
            _ = tee_attempt.apply(response(.failed), start);
            const reprove = tee_attempt.apply(chain_state(), start).reprove;
            try testing.expectEqual(count, reprove.retry_count);
            try testing.expect(!reprove.fallback);
            _ = tee_attempt.apply(reprove_next, start);
        }
        _ = tee_attempt.apply(response(.failed), start);
        const exhausted = tee_attempt.apply(chain_state(), start).drop.retries_exhausted;
        try testing.expectEqual(@as(u32, 3), exhausted.retry_count);
    }
}

fn expect_chain_gate(
    is_tee: bool,
    intent: attempt_module.DisputeIntent,
    resolved: bool,
    state: attempt_module.ChainState,
    ready: bool,
) !void {
    var attempt = if (is_tee) tee(start, true) else zk_with(start, intent);
    _ = attempt.need(start);
    _ = attempt.apply(if (ready) success(is_tee) else response(.failed), start);
    const action = attempt.apply(.{ .chain_state = state }, start);
    if (state.status != .in_progress) {
        try testing.expectEqual(state.status, action.drop.game_not_in_progress);
    } else if (resolved) {
        const already = action.drop.already_resolved;
        try testing.expectEqual(intent, already.intent);
        try testing.expectEqual(state.tee_prover, already.tee_prover);
        try testing.expectEqual(state.zk_prover, already.zk_prover);
    } else if (ready) {
        try testing.expectEqual(intent, action.submit.intent);
        try testing.expectEqual(target(), action.submit.target);
        try testing.expect(action.submit.just_obtained);
        _ = attempt.apply(submit_failure, start);
        _ = attempt.need(start + second);
        const again = attempt.apply(.{ .chain_state = state }, start + second);
        try testing.expect(!again.submit.just_obtained);
    } else {
        try testing.expect(action == .reprove);
    }
}

test "challenger dispute attempt: chain state gates ready and retry for each source and intent" {
    const Case = struct { bool, attempt_module.DisputeIntent, [4]bool };
    const cases = [_]Case{
        .{ true, .nullify, .{ true, false, true, false } },
        .{ false, .challenge, .{ true, false, true, true } },
        .{ false, .nullify, .{ true, true, false, false } },
    };
    const zero: chain.Address = @splat(0);
    const provers = [_][2]chain.Address{
        .{ zero, zero }, .{ @splat(1), zero }, .{ zero, @splat(2) }, .{ @splat(1), @splat(2) },
    };
    for (cases) |case| {
        for (provers, 0..) |pair, index| {
            for ([_]bool{ false, true }) |ready| {
                for (std.enums.values(chain.GameStatus)) |status| {
                    const state: attempt_module.ChainState =
                        .{ .status = status, .tee_prover = pair[0], .zk_prover = pair[1] };
                    try expect_chain_gate(case[0], case[1], case[2][index], state, ready);
                }
            }
        }
    }
}

test "challenger dispute attempt: TEE nullification completes without further effects" {
    var attempt = tee(start, false);
    _ = attempt.need(start);
    _ = attempt.apply(success(true), start);
    const submit = attempt.apply(chain_state(), start).submit;
    try testing.expectEqual(attempt_module.DisputeIntent.nullify, submit.intent);
    try testing.expectEqual(attempt_module.ProofSource.tee, submit.source);
    try testing.expect(attempt.apply(.{ .submitted = null }, start).drop == .disputed);
    try testing.expect(attempt.need(start + second) == .idle);
}

const Expected = enum { resolved, parent, origin, proof, signer, revert, generic };

fn expect_submit_policy(is_tee: bool, fallback: bool, err: SubmitError, expected: Expected) !void {
    var attempt = if (is_tee) tee(start, fallback) else zk(start);
    try testing.expect(attempt.apply(success(is_tee), start).wait == .ready);
    const action = attempt.apply(.{ .submitted = err }, start);
    switch (expected) {
        .resolved => return testing.expect(action.drop == .already_resolved_revert),
        .parent => return testing.expect(action.ignore == .invalid_parent_game),
        .origin => return testing.expect(action.ignore == .l1_origin_too_old),
        else => {},
    }
    if (!is_tee) {
        switch (expected) {
            .proof => try testing.expect(action.ignore == .zk_invalid_proof),
            .signer => try testing.expect(action.drop == .zk_invalid_signer),
            else => try testing.expect(action.wait == .zk_submit_retry),
        }
        return;
    }
    if (expected == .generic) {
        const retry = action.wait.tee_submit_retry;
        try testing.expectEqual(@as(u32, 1), retry.count);
        try testing.expectEqual(@as(u32, 1), retry.limit);
        try testing.expectEqual(fallback, retry.has_zk_fallback);
    } else if (fallback) {
        try testing.expect(action.reprove.fallback);
        try testing.expect(action.reprove.submission_failure.? == .rejected);
    } else {
        try testing.expect(action.drop.no_zk_fallback.? == .rejected);
    }
}

test "challenger dispute attempt: submit errors follow source specific policy" {
    const Case = struct { SubmitError, Expected };
    const cases = [_]Case{
        .{ .{ .known_revert = .game_already_exists }, .resolved },
        .{ .{ .known_revert = .proof_already_verified }, .resolved },
        .{ .{ .known_revert = .invalid_parent_game }, .parent },
        .{ .{ .known_revert = .l1_origin_too_old }, .origin },
        .{ .{ .known_revert = .invalid_proof }, .proof },
        .{ .{ .known_revert = .invalid_signer }, .signer },
        .{ .tx_reverted, .revert },
        .{ .execution_reverted, .revert },
        .{ .other, .generic },
    };
    for ([_]bool{ false, true }) |is_tee| {
        for ([_]bool{ false, true }) |fallback| {
            for (cases) |case| try expect_submit_policy(is_tee, fallback, case[0], case[1]);
        }
    }
}

fn expect_tee_limit(fallback: bool, limit: u32) !void {
    var now = start;
    var attempt_limits = limits();
    attempt_limits.tee_submit_retry_limit = limit;
    const zk_fallback: ?attempt_module.ZkFallback =
        if (fallback) .{ .request = request(), .intent = .challenge } else null;
    var attempt: DisputeAttempt = .awaiting_tee(
        session_tee,
        target(),
        zk_fallback,
        attempt_limits,
        now,
    );
    _ = attempt.apply(success(true), now);
    var count: u32 = 1;
    while (count <= limit) : (count += 1) {
        const retry = attempt.apply(submit_failure, now).wait.tee_submit_retry;
        try testing.expectEqual(count, retry.count);
        try testing.expectEqual(limit, retry.limit);
        try testing.expectEqual(fallback, retry.has_zk_fallback);
        now += second;
        _ = attempt.need(now);
        const submit = attempt.apply(chain_state(), now).submit;
        try testing.expectEqual(attempt_module.ProofSource.tee, submit.source);
        try testing.expect(!submit.just_obtained);
    }
    const action = attempt.apply(submit_failure, now);
    if (!fallback) {
        try testing.expect(action.drop.no_zk_fallback.? == .retry_limit);
        return;
    }
    try testing.expect(action.reprove.fallback);
    try testing.expectEqual(@as(u32, 0), action.reprove.retry_count);
    try testing.expectEqual(limit, action.reprove.submission_failure.?.retry_limit.count);
    _ = attempt.apply(reprove_next, now);
    _ = attempt.apply(success(false), now);
    for (0..100) |_| {
        try testing.expect(attempt.apply(submit_failure, now).wait == .zk_submit_retry);
        now += second;
        _ = attempt.need(now);
        const submit = attempt.apply(chain_state(), now).submit;
        try testing.expectEqual(attempt_module.DisputeIntent.challenge, submit.intent);
        try testing.expectEqual(attempt_module.ProofSource.zk, submit.source);
    }
    try testing.expect(attempt.apply(.{ .submitted = null }, now).drop == .disputed);
    try testing.expect(attempt.apply(chain_state(), now).wait == .pending);
}

test "challenger dispute attempt: TEE submit limit falls back but ZK resubmits without bound" {
    for ([_]bool{ false, true }) |fallback| {
        for ([_]u32{ 0, 1, 3 }) |limit| try expect_tee_limit(fallback, limit);
    }
}

test "challenger dispute attempt: retry budget includes reprove transport errors" {
    const statuses = [_]chain.ProverStatus{ .failed, .{ .succeeded = null } };
    for (statuses) |status| {
        var attempt = zk(start);
        try testing.expect(attempt.apply(response(status), start).wait == .needs_retry);
        for ([_]u32{ 1, 2 }) |count| {
            const reprove = attempt.apply(chain_state(), start).reprove;
            try testing.expectEqual(count, reprove.retry_count);
            try testing.expect(!reprove.fallback);
            const failed = attempt.apply(reprove_error, start).wait.reprove_failed;
            try testing.expectEqual(count, failed.retry_count);
        }
        const exhausted = attempt.apply(chain_state(), start).drop.retries_exhausted;
        try testing.expectEqual(@as(u32, 3), exhausted.retry_count);
    }
}

const PhaseKind = enum { awaiting, ready, needs_retry, reproving, done };
const EventKind = enum { prover, chain, submitted, reprove_started };

fn expect_out_of_order(phase: PhaseKind, event_kind: EventKind) !void {
    var attempt = zk(start);
    switch (phase) {
        .ready, .done => {
            _ = attempt.apply(success(false), start);
            if (phase == .done) _ = attempt.apply(.{ .submitted = null }, start);
        },
        .needs_retry, .reproving => {
            _ = attempt.apply(response(.failed), start);
            if (phase == .reproving) _ = attempt.apply(chain_state(), start);
        },
        .awaiting => {},
    }
    const event: Event = switch (event_kind) {
        .prover => response(.failed),
        .chain => chain_state(),
        .submitted => .{ .submitted = null },
        .reprove_started => .{ .reprove_started = 99 },
    };
    try testing.expect(attempt.apply(event, start).wait == .pending);
    const need = attempt.need(start);
    switch (phase) {
        .awaiting => {
            try testing.expectEqual(session_first, need.poll_prover);
            try testing.expect(attempt.apply(success(false), start).wait.ready == .zk);
        },
        .reproving, .done => try testing.expect(need == .idle),
        .ready, .needs_retry => try testing.expect(need.check_chain == null),
    }
    switch (phase) {
        .awaiting, .ready => {
            const submit = attempt.apply(chain_state(), start).submit;
            try testing.expectEqualSlices(u8, &zk_proof, submit.proof_bytes);
        },
        .needs_retry => {
            try testing.expectEqual(
                @as(u32, 1),
                attempt.apply(chain_state(), start).reprove.retry_count,
            );
        },
        .reproving, .done => {},
    }
}

test "challenger dispute attempt: out of order events preserve the next need and action" {
    for (std.enums.values(PhaseKind)) |phase| {
        for (std.enums.values(EventKind)) |event_kind| {
            const expected = switch (phase) {
                .awaiting => event_kind == .prover,
                .ready => event_kind == .chain or event_kind == .submitted,
                .needs_retry => event_kind == .chain,
                .reproving => event_kind == .reprove_started,
                .done => false,
            };
            if (expected) continue;
            try expect_out_of_order(phase, event_kind);
        }
    }
}

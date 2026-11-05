//! The withdrawal's next step, decided from chain reads (base/base
//! `crates/infra/withdrawer/src/operation.rs`: `status`, `game_eligible`, `proving_output`).
//!
//! Sans-IO: `Decider` and `GameSearch` emit one `Read` at a time and consume its `Answer`; a
//! driver performs the reads (`eth_call`, a block lookup, a proof fetch) and the simulator or
//! tests answer them directly. Semantics follow base/base's fault-proof path:
//!
//! - finalized on the portal: nothing to do;
//! - the anchor state registry paused: wait, never replace an existing proof;
//! - no proof by this submitter, or its game blacklisted, retired, improper, unrespected or
//!   resolved for the challenger: prove (again);
//! - otherwise ready once the proof is older than the maturity delay, the game resolved and
//!   past the finality delay, the registry reports it finalized, and the portal's own
//!   `checkWithdrawal` passes (it stays authoritative).
//!
//! `GameSearch` picks the game to prove against: the newest finalized covering game, else
//! the oldest pending one, skipping games whose proof does not verify. No covering game means
//! waiting for a proposal.

const std = @import("std");
const assert = std.debug.assert;

const calldata = @import("calldata.zig");
const withdrawal_module = @import("withdrawal.zig");

const Address = withdrawal_module.Address;
const Hash = withdrawal_module.Hash;
pub const GameStatus = calldata.GameStatus;
pub const ProvenWithdrawal = calldata.ProvenWithdrawal;

pub const Status = union(enum) {
    /// No further action is needed.
    finalized,
    /// The withdrawal needs a new inclusion proof.
    prove,
    /// The withdrawal can be executed.
    finalize,
    /// The registry must be unpaused before proving or finalizing.
    paused,
    /// Earliest known L1 ready time; an unresolved game can delay it further.
    not_ready: NotReady,

    pub const NotReady = struct {
        ready_at: u64,
        l1_timestamp: u64,
        waiting_for_game: bool,
    };
};

/// One chain read. Game reads carry the game's address.
pub const Read = union(enum) {
    /// `portal.finalizedWithdrawals(hash)` -> boolean.
    finalized_withdrawal,
    /// `registry.paused()` -> boolean.
    registry_paused,
    /// `portal.provenWithdrawals(hash, submitter)` -> proven.
    proven_withdrawal,
    /// `registry.isGameBlacklisted(game)` -> boolean.
    game_blacklisted: Address,
    /// `registry.isGameRetired(game)` -> boolean.
    game_retired: Address,
    /// `registry.isGameProper(game)` -> boolean.
    game_proper: Address,
    /// `registry.isGameRespected(game)` -> boolean.
    game_respected: Address,
    /// `game.status()` -> game_status.
    game_status: Address,
    /// `portal.proofMaturityDelaySeconds()` -> uint.
    proof_maturity_delay,
    /// `game.resolvedAt()` -> uint.
    game_resolved_at: Address,
    /// `registry.disputeGameFinalityDelaySeconds()` -> uint.
    finality_delay,
    /// `registry.isGameFinalized(game)` -> boolean.
    game_finalized: Address,
    /// Latest L1 block timestamp -> uint.
    l1_timestamp,
    /// `portal.checkWithdrawal(hash, submitter)` -> boolean (false: it reverted).
    check_withdrawal,
    /// `factory.gameCount()` -> uint.
    game_count,
    /// Timestamp of the withdrawal's L2 block -> uint.
    withdrawal_timestamp,
    /// `factory.gameAtIndex(index)` -> game.
    game_at_index: u64,
    /// `game.extraData()` claimed block -> claimed_block (null when unusable).
    game_extra_data: Address,
    /// `game.rootClaim()` -> root.
    game_root_claim: Address,
    /// Fetch the claimed block's header and message passer proof, verify them against the
    /// root -> verify.
    verify: Candidate,
};

pub const Game = struct { timestamp: u64, proxy: Address };

pub const Verify = enum { ok, unusable, rpc_error };

pub const Answer = union(enum) {
    boolean: bool,
    uint: u64,
    proven: ProvenWithdrawal,
    game_status: GameStatus,
    game: Game,
    claimed_block: ?u64,
    root: Hash,
    verify: Verify,
};

pub const Error = error{ UnexpectedAnswer, ValueOverflow, WithdrawalCheckFailed, RpcFailed };

/// First L1 timestamp at which `timestamp + delay` has strictly elapsed.
pub fn ready_time(timestamp: u64, delay: u64) Error!u64 {
    const sum = std.math.add(u64, timestamp, delay) catch return error.ValueOverflow;
    const result = std.math.add(u64, sum, 1) catch return error.ValueOverflow;
    assert(result > timestamp);
    return result;
}

fn expect_boolean(answer: Answer) Error!bool {
    return switch (answer) {
        .boolean => |value| value,
        else => error.UnexpectedAnswer,
    };
}

fn expect_uint(answer: Answer) Error!u64 {
    return switch (answer) {
        .uint => |value| value,
        else => error.UnexpectedAnswer,
    };
}

/// Whether a game can support a current or replacement proof (base/base `game_eligible`).
pub const Eligibility = struct {
    game: Address,
    step: u8 = 0,

    const steps = 5;

    pub fn read(eligibility: *const Eligibility) Read {
        assert(eligibility.step < steps);
        const game = eligibility.game;
        return switch (eligibility.step) {
            0 => .{ .game_blacklisted = game },
            1 => .{ .game_retired = game },
            2 => .{ .game_proper = game },
            3 => .{ .game_respected = game },
            4 => .{ .game_status = game },
            else => unreachable,
        };
    }

    /// The verdict, or null when another read is needed.
    pub fn on_answer(eligibility: *Eligibility, answer: Answer) Error!?bool {
        assert(eligibility.step < steps);
        const step = eligibility.step;
        eligibility.step += 1;
        if (step == 4) {
            const status = switch (answer) {
                .game_status => |value| value,
                else => return error.UnexpectedAnswer,
            };
            return status != .challenger_wins;
        }
        const value = try expect_boolean(answer);
        // Blacklisted or retired (true) and improper or unrespected (false) disqualify.
        const disqualified = if (step < 2) value else !value;
        if (disqualified) return false;
        assert(eligibility.step < steps);
        return null;
    }
};

/// Decides the next step for one withdrawal and submitter.
pub const Decider = struct {
    phase: Phase = .finalized_withdrawal,
    proven: ProvenWithdrawal = .{ .game = @splat(0), .timestamp = 0 },
    eligibility: Eligibility = .{ .game = @splat(0) },
    maturity_delay_s: u64 = 0,
    ready_at: u64 = 0,
    resolved_at: u64 = 0,
    game_finalized: bool = false,
    l1_timestamp: u64 = 0,
    outcome: ?Status = null,

    const Phase = enum {
        finalized_withdrawal,
        registry_paused,
        proven_withdrawal,
        eligibility,
        proof_maturity_delay,
        game_resolved_at,
        finality_delay,
        game_finalized,
        l1_timestamp,
        check_withdrawal,
        done,
    };

    /// The next read, or null once `outcome` is set.
    pub fn next(decider: *const Decider) ?Read {
        assert((decider.phase == .done) == (decider.outcome != null));
        const game = decider.proven.game;
        return switch (decider.phase) {
            .finalized_withdrawal => .finalized_withdrawal,
            .registry_paused => .registry_paused,
            .proven_withdrawal => .proven_withdrawal,
            .eligibility => decider.eligibility.read(),
            .proof_maturity_delay => .proof_maturity_delay,
            .game_resolved_at => .{ .game_resolved_at = game },
            .finality_delay => .finality_delay,
            .game_finalized => .{ .game_finalized = game },
            .l1_timestamp => .l1_timestamp,
            .check_withdrawal => .check_withdrawal,
            .done => null,
        };
    }

    pub fn on_answer(decider: *Decider, answer: Answer) Error!void {
        assert(decider.outcome == null);
        switch (decider.phase) {
            .finalized_withdrawal => {
                if (try expect_boolean(answer)) return decider.finish(.finalized);
                decider.phase = .registry_paused;
            },
            .registry_paused => {
                if (try expect_boolean(answer)) return decider.finish(.paused);
                decider.phase = .proven_withdrawal;
            },
            .proven_withdrawal => try decider.on_proven(answer),
            .eligibility => {
                const eligible = try decider.eligibility.on_answer(answer) orelse return;
                if (!eligible) return decider.finish(.prove);
                decider.phase = .proof_maturity_delay;
            },
            .proof_maturity_delay => {
                const delay_s = try expect_uint(answer);
                decider.ready_at = try ready_time(decider.proven.timestamp, delay_s);
                decider.phase = .game_resolved_at;
            },
            .game_resolved_at => {
                decider.resolved_at = try expect_uint(answer);
                decider.phase = if (decider.resolved_at == 0) .game_finalized else .finality_delay;
            },
            .finality_delay => {
                const resolved_ready = try ready_time(decider.resolved_at, try expect_uint(answer));
                decider.ready_at = @max(decider.ready_at, resolved_ready);
                decider.phase = .game_finalized;
            },
            .game_finalized => {
                decider.game_finalized = try expect_boolean(answer);
                decider.phase = .l1_timestamp;
            },
            .l1_timestamp => try decider.on_l1_timestamp(try expect_uint(answer)),
            .check_withdrawal => {
                if (!try expect_boolean(answer)) return error.WithdrawalCheckFailed;
                decider.finish(.finalize);
            },
            .done => unreachable,
        }
    }

    fn on_proven(decider: *Decider, answer: Answer) Error!void {
        assert(decider.phase == .proven_withdrawal);
        decider.proven = switch (answer) {
            .proven => |value| value,
            else => return error.UnexpectedAnswer,
        };
        if (decider.proven.timestamp == 0) return decider.finish(.prove);
        decider.eligibility = .{ .game = decider.proven.game };
        decider.phase = .eligibility;
    }

    fn on_l1_timestamp(decider: *Decider, l1_timestamp: u64) Error!void {
        assert(decider.phase == .l1_timestamp);
        decider.l1_timestamp = l1_timestamp;
        const waiting_for_game = decider.resolved_at == 0;
        if (l1_timestamp < decider.ready_at or waiting_for_game or !decider.game_finalized) {
            return decider.finish(.{ .not_ready = .{
                .ready_at = decider.ready_at,
                .l1_timestamp = l1_timestamp,
                .waiting_for_game = waiting_for_game,
            } });
        }
        decider.phase = .check_withdrawal;
    }

    fn finish(decider: *Decider, status: Status) void {
        assert(decider.outcome == null);
        decider.outcome = status;
        decider.phase = .done;
        assert(decider.next() == null);
    }
};

/// A covering game: factory index, proxy, claimed L2 block, and (once read) its root claim.
pub const Candidate = struct {
    index: u64,
    game: Address,
    block_number: u64,
    root: Hash = @splat(0),
};

pub const SearchOutcome = union(enum) {
    found: Candidate,
    /// No eligible covering game whose proof verifies: wait for a proposal.
    no_coverage,
};

pub const SearchLimits = struct {
    /// Pending covering games remembered; past it the newest are dropped (the oldest
    /// pending game is preferred, so the newest matter least).
    candidates_max: u32 = 128,
    /// Games inspected walking back from the newest; base/base stops only at games older
    /// than the withdrawal.
    games_scanned_max: u64 = 100_000,
};

/// Chooses the game to prove against (base/base `proving_output`, fault proofs).
pub fn GameSearch(comptime limits: SearchLimits) type {
    comptime assert(limits.candidates_max > 0);
    comptime assert(limits.games_scanned_max > 0);
    return struct {
        const Self = @This();

        withdrawal_block: u64,
        phase: Phase = .game_count,
        remaining: u64 = 0,
        scanned: u64 = 0,
        withdrawal_timestamp: u64 = 0,
        walk_game: Game = .{ .timestamp = 0, .proxy = @splat(0) },
        walk_block: u64 = 0,
        candidates: [limits.candidates_max]Candidate = undefined,
        candidates_start: u32 = 0,
        candidates_count: u32 = 0,
        current: Candidate = .{ .index = 0, .game = @splat(0), .block_number = 0 },
        eligibility: Eligibility = .{ .game = @splat(0) },
        rpc_failed: bool = false,
        outcome: ?SearchOutcome = null,

        const Phase = enum {
            game_count,
            withdrawal_timestamp,
            game_at_index,
            game_extra_data,
            game_finalized,
            eligibility,
            game_root_claim,
            verify,
            done,
        };

        pub fn init(withdrawal_block: u64) Self {
            return .{ .withdrawal_block = withdrawal_block };
        }

        pub fn next(search: *const Self) ?Read {
            assert((search.phase == .done) == (search.outcome != null));
            return switch (search.phase) {
                .game_count => .game_count,
                .withdrawal_timestamp => .withdrawal_timestamp,
                .game_at_index => .{ .game_at_index = search.remaining },
                .game_extra_data => .{ .game_extra_data = search.walk_game.proxy },
                .game_finalized => .{ .game_finalized = search.walk_game.proxy },
                .eligibility => search.eligibility.read(),
                .game_root_claim => .{ .game_root_claim = search.current.game },
                .verify => .{ .verify = search.current },
                .done => null,
            };
        }

        pub fn on_answer(search: *Self, answer: Answer) Error!void {
            assert(search.outcome == null);
            switch (search.phase) {
                .game_count => {
                    search.remaining = try expect_uint(answer);
                    search.phase = .withdrawal_timestamp;
                },
                .withdrawal_timestamp => {
                    search.withdrawal_timestamp = try expect_uint(answer);
                    try search.walk_or_select();
                },
                .game_at_index => try search.on_game(answer),
                .game_extra_data => try search.on_claimed_block(answer),
                .game_finalized => try search.on_finalized(try expect_boolean(answer)),
                .eligibility => {
                    const eligible = try search.eligibility.on_answer(answer) orelse return;
                    if (!eligible) return search.walk_or_select();
                    search.phase = .game_root_claim;
                },
                .game_root_claim => {
                    search.current.root = switch (answer) {
                        .root => |root| root,
                        else => return error.UnexpectedAnswer,
                    };
                    search.phase = .verify;
                },
                .verify => try search.on_verify(answer),
                .done => unreachable,
            }
        }

        /// Steps the walk to the next older game, or selects once it is over.
        fn walk_or_select(search: *Self) Error!void {
            if (search.walk_over()) return search.select(null);
            assert(search.remaining > 0);
            search.remaining -= 1;
            search.scanned += 1;
            search.phase = .game_at_index;
        }

        fn on_game(search: *Self, answer: Answer) Error!void {
            assert(search.phase == .game_at_index);
            search.walk_game = switch (answer) {
                .game => |game| game,
                else => return error.UnexpectedAnswer,
            };
            // A game created before the withdrawal cannot honestly cover it, nor older ones.
            if (search.walk_game.timestamp < search.withdrawal_timestamp) {
                search.remaining = 0;
                return search.select(null);
            }
            search.phase = .game_extra_data;
        }

        fn on_claimed_block(search: *Self, answer: Answer) Error!void {
            assert(search.phase == .game_extra_data);
            const claimed = switch (answer) {
                .claimed_block => |block| block,
                else => return error.UnexpectedAnswer,
            };
            const block = claimed orelse return search.walk_or_select();
            if (block < search.withdrawal_block) return search.walk_or_select();
            search.walk_block = block;
            search.phase = .game_finalized;
        }

        fn on_finalized(search: *Self, finalized: bool) Error!void {
            assert(search.phase == .game_finalized);
            const candidate: Candidate = .{
                .index = search.remaining,
                .game = search.walk_game.proxy,
                .block_number = search.walk_block,
            };
            // A finalized game needs only proof maturity: prefer the newest that verifies.
            if (finalized) return search.select(candidate);
            search.push_back(candidate);
            return search.walk_or_select();
        }

        fn on_verify(search: *Self, answer: Answer) Error!void {
            assert(search.phase == .verify);
            const result = switch (answer) {
                .verify => |value| value,
                else => return error.UnexpectedAnswer,
            };
            switch (result) {
                .ok => return search.finish(.{ .found = search.current }),
                .unusable => {},
                .rpc_error => {
                    // Some RPCs only serve recent state: stop the walk, try the newest saved
                    // candidates, and give up on a second failure.
                    if (search.rpc_failed) return error.RpcFailed;
                    search.rpc_failed = true;
                },
            }
            return search.walk_or_select();
        }

        /// Starts verifying `finalized`, else the next saved candidate once the walk is
        /// over, else finishes. After an RPC failure, running out of candidates is an error.
        fn select(search: *Self, finalized: ?Candidate) Error!void {
            assert(search.outcome == null);
            const chosen = finalized orelse blk: {
                assert(search.walk_over());
                break :blk if (search.rpc_failed) search.pop_front() else search.pop_back();
            };
            const candidate = chosen orelse {
                if (search.rpc_failed) return error.RpcFailed;
                return search.finish(.no_coverage);
            };
            search.current = candidate;
            search.eligibility = .{ .game = candidate.game };
            search.phase = .eligibility;
        }

        fn walk_over(search: *const Self) bool {
            return search.rpc_failed or search.remaining == 0 or
                search.scanned >= limits.games_scanned_max;
        }

        fn push_back(search: *Self, candidate: Candidate) void {
            if (search.candidates_count == limits.candidates_max) _ = search.pop_front();
            const slot = search.slot_of(search.candidates_count);
            search.candidates[slot] = candidate;
            search.candidates_count += 1;
            assert(search.candidates_count <= limits.candidates_max);
        }

        fn slot_of(search: *const Self, offset: u32) u32 {
            assert(offset < limits.candidates_max);
            return (search.candidates_start + offset) % limits.candidates_max;
        }

        /// The newest saved candidate.
        fn pop_front(search: *Self) ?Candidate {
            if (search.candidates_count == 0) return null;
            const candidate = search.candidates[search.candidates_start];
            search.candidates_start = (search.candidates_start + 1) % limits.candidates_max;
            search.candidates_count -= 1;
            return candidate;
        }

        /// The oldest saved candidate.
        fn pop_back(search: *Self) ?Candidate {
            if (search.candidates_count == 0) return null;
            search.candidates_count -= 1;
            const slot = search.slot_of(search.candidates_count);
            return search.candidates[slot];
        }

        fn finish(search: *Self, outcome: SearchOutcome) void {
            assert(search.outcome == null);
            search.outcome = outcome;
            search.phase = .done;
            assert(search.next() == null);
        }
    };
}

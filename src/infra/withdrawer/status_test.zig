//! Status and game-search transitions over a scripted chain, mirroring base/base's
//! `operation.rs` scenarios (proven at 100 s, maturity 100 s, game resolved at 700 s,
//! finality delay 200 s, L1 time 1000 s), plus a seeded fuzz of answer streams.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const status_module = @import("status.zig");
const fuzz = @import("../../testing/fuzz.zig");

const Address = [20]u8;
const Status = status_module.Status;
const Read = status_module.Read;
const Answer = status_module.Answer;

const old_game: Address = @splat(8);

const Scenario = struct {
    proven: u64 = 0,
    finalized: bool = false,
    paused: bool = false,
    blacklisted: bool = false,
    retired: bool = false,
    proper: bool = true,
    respected: bool = true,
    game_status: status_module.GameStatus = .defender_wins,
    game_finalized: bool = true,
    reject_check: bool = false,
    now: u64 = 1000,

    fn answer(scenario: *const Scenario, read: Read) Answer {
        return switch (read) {
            .finalized_withdrawal => .{ .boolean = scenario.finalized },
            .registry_paused => .{ .boolean = scenario.paused },
            .proven_withdrawal => .{
                .proven = .{ .game = old_game, .timestamp = scenario.proven },
            },
            .game_blacklisted => .{ .boolean = scenario.blacklisted },
            .game_retired => .{ .boolean = scenario.retired },
            .game_proper => .{ .boolean = scenario.proper },
            .game_respected => .{ .boolean = scenario.respected },
            .game_status => .{ .game_status = scenario.game_status },
            .proof_maturity_delay => .{ .uint = 100 },
            .game_resolved_at => .{ .uint = if (scenario.game_status == .in_progress) 0 else 700 },
            .finality_delay => .{ .uint = 200 },
            .game_finalized => .{ .boolean = scenario.game_finalized },
            .l1_timestamp => .{ .uint = scenario.now },
            .check_withdrawal => .{ .boolean = !scenario.reject_check },
            else => unreachable, // Search reads are not part of the decision.
        };
    }

    fn decide(scenario: Scenario) !Status {
        var decider: status_module.Decider = .{};
        var reads: u32 = 0;
        while (decider.next()) |read| : (reads += 1) {
            assert(reads < 32);
            try decider.on_answer(scenario.answer(read));
        }
        return decider.outcome.?;
    }
};

test "status: unproven withdrawals prove, proven ones finalize" {
    try testing.expectEqual(Status.prove, try Scenario.decide(.{}));
    try testing.expectEqual(Status.finalize, try Scenario.decide(.{ .proven = 100 }));
    try testing.expectEqual(Status.finalized, try Scenario.decide(.{ .finalized = true }));
}

test "status: invalidated fault proofs are proven again" {
    const cases = [_]Scenario{
        .{ .proven = 100, .blacklisted = true },
        .{ .proven = 100, .retired = true },
        .{ .proven = 100, .proper = false },
        .{ .proven = 100, .respected = false },
        .{ .proven = 100, .game_status = .challenger_wins },
    };
    for (cases) |scenario| try testing.expectEqual(Status.prove, try scenario.decide());
}

test "status: paused contracts wait without replacing proofs" {
    for ([_]u64{ 0, 100 }) |proven| {
        const status = try Scenario.decide(.{ .paused = true, .proven = proven });
        try testing.expectEqual(Status.paused, status);
    }
}

test "status: finalization waits for L1 time and game finality" {
    const Case = struct { scenario: Scenario, ready_at: u64, waiting: bool };
    const cases = [_]Case{
        .{
            .scenario = .{ .proven = 100, .now = 200, .game_finalized = false },
            .ready_at = 901,
            .waiting = false,
        },
        .{
            .scenario = .{ .proven = 100, .game_status = .in_progress, .game_finalized = false },
            .ready_at = 201,
            .waiting = true,
        },
        .{ .scenario = .{ .proven = 950 }, .ready_at = 1051, .waiting = false },
        .{ .scenario = .{ .proven = 100, .now = 900 }, .ready_at = 901, .waiting = false },
    };
    for (cases) |case| {
        const status = try case.scenario.decide();
        try testing.expectEqual(Status{ .not_ready = .{
            .ready_at = case.ready_at,
            .l1_timestamp = case.scenario.now,
            .waiting_for_game = case.waiting,
        } }, status);
    }
    // The first allowed timestamp is exactly the ready time.
    try testing.expectEqual(Status.finalize, try Scenario.decide(.{ .proven = 100, .now = 901 }));
}

test "status: the portal check stays authoritative" {
    const result = Scenario.decide(.{ .proven = 100, .reject_check = true });
    try testing.expectError(error.WithdrawalCheckFailed, result);
}

test "status: ready time overflow and mismatched answers are errors" {
    try testing.expectEqual(@as(u64, 201), try status_module.ready_time(100, 100));
    const max = std.math.maxInt(u64);
    try testing.expectError(error.ValueOverflow, status_module.ready_time(max, 0));
    var decider: status_module.Decider = .{};
    try testing.expectError(error.UnexpectedAnswer, decider.on_answer(.{ .uint = 1 }));
}

const Search = status_module.GameSearch(.{ .candidates_max = 8 });

const Chain = struct {
    /// Per game index: claimed block (null: unusable extra data), finalized, eligible,
    /// verify result, created-at timestamp.
    games: []const GameSpec,
    withdrawal_timestamp: u64 = 50,
    reads: u32 = 0,
    verifies: u32 = 0,

    const GameSpec = struct {
        block: ?u64 = 100,
        finalized: bool = true,
        eligible: bool = true,
        verify: status_module.Verify = .ok,
        timestamp: u64 = 60,
    };

    fn proxy(index: u64) Address {
        var address: Address = @splat(0);
        std.mem.writeInt(u64, address[12..20], index + 1, .big);
        return address;
    }

    fn index_of(address: Address) usize {
        return @intCast(std.mem.readInt(u64, address[12..20], .big) - 1);
    }

    fn answer(chain: *Chain, read: Read) Answer {
        chain.reads += 1;
        return switch (read) {
            .game_count => .{ .uint = chain.games.len },
            .withdrawal_timestamp => .{ .uint = chain.withdrawal_timestamp },
            .game_at_index => |index| .{ .game = .{
                .timestamp = chain.games[@intCast(index)].timestamp,
                .proxy = proxy(index),
            } },
            .game_extra_data => |game| .{ .claimed_block = chain.games[index_of(game)].block },
            .game_finalized => |game| .{ .boolean = chain.games[index_of(game)].finalized },
            .game_blacklisted => |game| .{ .boolean = !chain.games[index_of(game)].eligible },
            .game_retired, .game_respected, .game_proper => .{
                .boolean = read != .game_retired,
            },
            .game_status => .{ .game_status = .defender_wins },
            .game_root_claim => .{ .root = @splat(0x77) },
            .verify => |candidate| blk: {
                chain.verifies += 1;
                break :blk .{ .verify = chain.games[@intCast(candidate.index)].verify };
            },
            else => unreachable, // Decision reads are not part of the search.
        };
    }

    fn search(chain: *Chain, withdrawal_block: u64) !status_module.SearchOutcome {
        var game_search = Search.init(withdrawal_block);
        var steps: u32 = 0;
        while (game_search.next()) |read| : (steps += 1) {
            assert(steps < 1024);
            try game_search.on_answer(chain.answer(read));
        }
        return game_search.outcome.?;
    }
};

fn expect_found(outcome: status_module.SearchOutcome, index: u64) !void {
    try testing.expectEqual(index, outcome.found.index);
    try testing.expectEqual(Chain.proxy(index), outcome.found.game);
    try testing.expectEqual(@as(u8, 0x77), outcome.found.root[0]);
}

test "game search: prefers the newest finalized covering game" {
    var chain: Chain = .{ .games = &.{ .{ .finalized = false }, .{}, .{ .finalized = false } } };
    try expect_found(try chain.search(100), 1);
}

test "game search: otherwise the oldest pending covering game" {
    var chain: Chain = .{ .games = &.{
        .{ .finalized = false }, .{ .finalized = false }, .{ .finalized = false },
    } };
    try expect_found(try chain.search(100), 0);
    try testing.expectEqual(@as(u32, 1), chain.verifies);
}

test "game search: skips unusable, non-covering, blacklisted and unverifiable games" {
    var chain: Chain = .{ .games = &.{ .{}, .{ .eligible = false }, .{ .block = null } } };
    try expect_found(try chain.search(100), 0);
    chain = .{ .games = &.{ .{}, .{ .block = 99 } } };
    try expect_found(try chain.search(100), 0);
    chain = .{ .games = &.{ .{}, .{ .verify = .unusable } } };
    try expect_found(try chain.search(100), 0);
}

test "game search: no covering game waits for a proposal" {
    var chain: Chain = .{ .games = &.{ .{ .block = 1 }, .{ .block = 2 } } };
    try testing.expectEqual(status_module.SearchOutcome.no_coverage, try chain.search(100));
    chain = .{ .games = &.{} };
    try testing.expectEqual(status_module.SearchOutcome.no_coverage, try chain.search(100));
}

test "game search: stops at games older than the withdrawal" {
    var specs: [40]Chain.GameSpec = @splat(.{ .block = 1 });
    for (specs[0..30]) |*spec| spec.timestamp = 10;
    var chain: Chain = .{ .games = &specs };
    try testing.expectEqual(status_module.SearchOutcome.no_coverage, try chain.search(100));
    // Two setup reads, two per non-covering game (39..30), one for the old game 29.
    try testing.expectEqual(@as(u32, 2 + 10 * 2 + 1), chain.reads);
}

test "game search: one proof RPC failure switches to the newest saved candidates" {
    var chain: Chain = .{ .games = &.{
        .{ .finalized = false },
        .{ .finalized = false, .verify = .rpc_error },
        .{ .finalized = false },
    } };
    // The oldest pending game verifies before the failing one is ever tried.
    try expect_found(try chain.search(100), 0);
    chain = .{ .games = &.{
        .{ .finalized = false, .verify = .rpc_error },
        .{ .finalized = false },
        .{ .finalized = false },
    } };
    try expect_found(try chain.search(100), 2);
    chain = .{ .games = &.{
        .{ .finalized = false, .verify = .rpc_error },
        .{ .finalized = false, .verify = .rpc_error },
        .{ .finalized = false, .verify = .rpc_error },
    } };
    try testing.expectError(error.RpcFailed, chain.search(100));
    try testing.expectEqual(@as(u32, 2), chain.verifies);
}

fn fuzz_decider(_: void, smith: *std.testing.Smith) anyerror!void {
    var decider: status_module.Decider = .{};
    var reads: u32 = 0;
    // Arbitrary answers either decide, or fail with a typed error, within a bounded walk.
    while (decider.next()) |_| : (reads += 1) {
        try testing.expect(reads < 32);
        const answer: Answer = switch (smith.valueRangeAtMost(u8, 0, 3)) {
            0 => .{ .boolean = smith.value(bool) },
            1 => .{ .uint = smith.value(u64) },
            2 => .{ .proven = .{ .game = smith.value(Address), .timestamp = smith.value(u64) } },
            else => .{ .game_status = smith.value(status_module.GameStatus) },
        };
        decider.on_answer(answer) catch return;
    }
    try testing.expect(decider.outcome != null);
}

test "status: fuzz decider answers" {
    try fuzz.run({}, fuzz_decider, .{ .iterations = 1024 });
}

fn fuzz_search(_: void, smith: *std.testing.Smith) anyerror!void {
    var specs: [12]Chain.GameSpec = undefined;
    const count = smith.valueRangeAtMost(u8, 0, specs.len);
    for (specs[0..count]) |*spec| spec.* = .{
        .block = if (smith.value(bool)) smith.valueRangeAtMost(u64, 90, 110) else null,
        .finalized = smith.value(bool),
        .eligible = smith.value(bool),
        .verify = smith.value(status_module.Verify),
        .timestamp = smith.valueRangeAtMost(u64, 40, 60),
    };
    var chain: Chain = .{ .games = specs[0..count] };
    const outcome = chain.search(100) catch |err| {
        try testing.expectEqual(error.RpcFailed, err);
        return;
    };
    // A found game always covers the withdrawal, is eligible, and verified.
    switch (outcome) {
        .found => |candidate| {
            const spec = specs[@intCast(candidate.index)];
            try testing.expect(candidate.block_number >= 100);
            try testing.expect(spec.eligible and spec.verify == .ok);
        },
        .no_coverage => {},
    }
}

test "game search: fuzz chains" {
    try fuzz.run({}, fuzz_search, .{ .iterations = 1024 });
}

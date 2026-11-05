//! Proposal checkpoint intervals (base/base `crates/proof/proposer/src/proposal_intervals.rs`
//! and the interval checks of `crates/proof/contracts/src/aggregate_verifier.rs`).
//!
//! The `AggregateVerifier` switches to a shorter cadence at the Denim activation block, so
//! `BLOCK_INTERVAL` / `INTERMEDIATE_BLOCK_INTERVAL` are a function of the block a game's
//! range starts at. Every consumer resolves them from the starting block of the game it is
//! about to create, reconstruct, or look up; nothing caches them at startup.

const std = @import("std");
const assert = std.debug.assert;

const factory = @import("../contracts/dispute_game_factory.zig");

/// The checkpoint intervals a game starting at a given block is created with.
pub const Intervals = struct {
    /// L2 blocks covered by one proposal.
    block_interval: u64,
    /// L2 blocks between intermediate output root checkpoints (never zero once validated).
    intermediate_block_interval: u64,

    /// The intermediate checkpoint blocks of a game starting at `starting_block`, the
    /// last being the target block.
    pub fn intermediate_block_numbers(
        intervals: Intervals,
        out: []u64,
        starting_block: u64,
    ) factory.LookupError![]u64 {
        assert(intervals.intermediate_block_interval > 0);
        const blocks = try factory.lookup_blocks(
            out,
            starting_block,
            intervals.block_interval,
            intervals.intermediate_block_interval,
        );
        assert(blocks.len > 0);
        assert(blocks[blocks.len - 1] == starting_block + intervals.block_interval);
        return blocks;
    }

    /// Number of intermediate roots one game carries.
    pub fn root_count(intervals: Intervals) u32 {
        const count = factory.lookup_count(
            intervals.block_interval,
            intervals.intermediate_block_interval,
        ) catch unreachable; // Validated intervals always have a count (see `validate`).
        assert(count > 0);
        return count;
    }
};

pub const ValidateError = error{InvalidIntervals};

/// The checks base/base applies to an onchain interval pair before using it: a proposal
/// spans at least 2 blocks, the intermediate interval is non-zero and divides the block
/// interval, and the root count fits one game's `extraData`.
pub fn validate(block_interval: u64, intermediate_block_interval: u64) ValidateError!Intervals {
    if (block_interval < 2) return error.InvalidIntervals;
    if (intermediate_block_interval == 0) return error.InvalidIntervals;
    const count = factory.lookup_count(block_interval, intermediate_block_interval) catch
        return error.InvalidIntervals;
    assert(count >= 1);
    assert(block_interval % intermediate_block_interval == 0);
    return .{
        .block_interval = block_interval,
        .intermediate_block_interval = intermediate_block_interval,
    };
}

/// The fork-aware interval schedule of an `AggregateVerifier` (>= 0.3.0): one pair before
/// the fast-cadence (Denim) activation block and another from it on. Used to model the
/// contract's `intervalsForStartingBlock` in tests and simulation.
pub const Schedule = struct {
    slow: Intervals,
    fast: Intervals,
    /// First starting block that uses `fast`; `maxInt(u64)` when unscheduled.
    fast_activation_block: u64 = std.math.maxInt(u64),

    pub fn fixed(intervals: Intervals) Schedule {
        assert(intervals.intermediate_block_interval > 0);
        assert(intervals.block_interval % intervals.intermediate_block_interval == 0);
        return .{ .slow = intervals, .fast = intervals };
    }

    pub fn for_starting_block(schedule: Schedule, starting_block: u64) Intervals {
        assert(schedule.slow.intermediate_block_interval > 0);
        assert(schedule.fast.intermediate_block_interval > 0);
        if (starting_block < schedule.fast_activation_block) return schedule.slow;
        return schedule.fast;
    }
};

/// The first `AggregateVerifier` version that exposes `intervalsForStartingBlock`.
const fork_aware_version_major: u64 = 0;
const fork_aware_version_minor: u64 = 3;

/// Whether a verifier reporting `version` speaks the fork-aware interval ABI. The ABIs are
/// disjoint: 0.3.0 added `intervalsForStartingBlock` and removed `BLOCK_INTERVAL()` /
/// `INTERMEDIATE_BLOCK_INTERVAL()`. Anything that is not exactly three numeric components
/// (before a `-` or `+` suffix) is treated as fork-aware, so malformed strings never reach
/// the legacy getters.
pub fn supports_fork_aware_intervals(version: []const u8) bool {
    const core_end = std.mem.indexOfAny(u8, version, "-+") orelse version.len;
    const core = version[0..core_end];
    var parts = std.mem.splitScalar(u8, core, '.');
    var numbers: [3]u64 = undefined;
    var count: u32 = 0;
    while (parts.next()) |part| : (count += 1) {
        if (count == 3) return true;
        const trimmed = std.mem.trim(u8, part, " \t");
        numbers[count] = std.fmt.parseUnsigned(u64, trimmed, 10) catch return true;
    }
    assert(count <= 3);
    if (count != 3) return true;
    if (numbers[0] != fork_aware_version_major) return numbers[0] > fork_aware_version_major;
    return numbers[1] >= fork_aware_version_minor;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "proposer intervals: validation mirrors the verifier checks" {
    const ok = try validate(100, 50);
    try testing.expectEqual(@as(u64, 100), ok.block_interval);
    try testing.expectEqual(@as(u32, 2), ok.root_count());
    try testing.expectError(error.InvalidIntervals, validate(1, 1));
    try testing.expectError(error.InvalidIntervals, validate(0, 1));
    try testing.expectError(error.InvalidIntervals, validate(100, 0));
    try testing.expectError(error.InvalidIntervals, validate(100, 30));
    try testing.expectError(error.InvalidIntervals, validate(1024, 1));
    var blocks: [4]u64 = undefined;
    const numbers = try ok.intermediate_block_numbers(&blocks, 200);
    try testing.expectEqualSlices(u64, &.{ 250, 300 }, numbers);
}

test "proposer intervals: schedule switches cadence at the activation block" {
    const schedule: Schedule = .{
        .slow = try validate(100, 50),
        .fast = try validate(200, 100),
        .fast_activation_block = 300,
    };
    try testing.expectEqual(@as(u64, 100), schedule.for_starting_block(299).block_interval);
    try testing.expectEqual(@as(u64, 200), schedule.for_starting_block(300).block_interval);
    const fixed = Schedule.fixed(try validate(8, 4));
    const last = fixed.for_starting_block(std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, 8), last.block_interval);
}

test "proposer intervals: fork-aware version gate at 0.3.0" {
    // Ported from `test_supports_fork_aware_intervals_gates_on_0_3_0`.
    const legacy = [_][]const u8{
        "0.1.0", "0.1.99", "0.2.0", "0.2.99", "0.2.0-beta.1", "0.1.0-rc.1",
    };
    for (legacy) |version| try testing.expect(!supports_fork_aware_intervals(version));
    const fork_aware = [_][]const u8{
        "0.3.0", "0.10.0", "1.0.0", "0.3.0+deadbeef", "",     "unversioned",
        "3",     "0.1",    "0.1.x", "0.1.0.1",        "0.1.",
    };
    for (fork_aware) |version| try testing.expect(supports_fork_aware_intervals(version));
}

fn fuzz_intervals(_: void, smith: *std.testing.Smith) anyerror!void {
    const block_interval = smith.valueRangeAtMost(u64, 0, 4096);
    const intermediate = smith.valueRangeAtMost(u64, 0, 4096);
    const starting_block = smith.value(u64) >> 1;
    var version_bytes: [12]u8 = undefined;
    _ = supports_fork_aware_intervals(version_bytes[0..smith.slice(&version_bytes)]);
    const intervals = validate(block_interval, intermediate) catch return;
    var blocks: [factory.intermediate_roots_max]u64 = undefined;
    const numbers = try intervals.intermediate_block_numbers(&blocks, starting_block);
    try testing.expectEqual(@as(usize, intervals.root_count()), numbers.len);
    var previous = starting_block;
    for (numbers) |block| {
        try testing.expectEqual(previous + intermediate, block);
        previous = block;
    }
}

test "proposer intervals: fuzz validation and checkpoints" {
    try fuzz.run({}, fuzz_intervals, .{ .iterations = 512 });
}

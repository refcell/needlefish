//! Flashblocks timing schedule: how many flashblocks a payload job builds and when each one's
//! build window closes. Pure arithmetic over injected time (callers pass `now_ns`); nothing
//! here reads a clock. Ports base/base `crates/builder/core/src/flashblocks/deadline.rs`
//! (`PayloadJobDeadline`), the flashblocks timing fields of `config.rs` (`BuilderConfig`), and
//! the schedule arithmetic in `payload.rs` (`calculate_flashblocks`, `first_flashblock_delay`).
//!
//! Indexing follows base/base: index 0 is the fallback block, built and published immediately
//! when the job starts (no deadline of its own). Regular flashblocks are indices `1..=count`;
//! flashblock `j` builds until `first_deadline_ns + (j - 1) * interval`, which is when the
//! interval timer ticks and starts flashblock `j + 1`. After the tick that closes flashblock
//! `count`, the job finalizes the block.

const std = @import("std");
const assert = std.debug.assert;

pub const ns_per_ms: u64 = std.time.ns_per_ms;
pub const ns_per_s: u64 = std.time.ns_per_s;

/// Upper bound on any configured duration. Keeps every sum below in u64 range; base/base has
/// no explicit bound, but a one-hour block or interval is far outside any real config.
pub const duration_ms_max: u64 = 60 * 60 * 1000;

/// Upper bound on injected time. 2^62 ns is year ~2116; leaves headroom for adding durations.
pub const time_ns_max: u64 = 1 << 62;

comptime {
    assert(duration_ms_max * ns_per_ms * 4 < std.math.maxInt(u64) - time_ns_max);
    assert(ns_per_s == 1000 * ns_per_ms);
}

pub const ConfigError = error{
    FlashblocksIntervalZero,
    FlashblocksLeewayExceedsInterval,
    BlockTimeBelowInterval,
    DurationTooLarge,
};

/// The flashblocks timing knobs of base/base `BuilderConfig`.
pub const Config = struct {
    /// Chain block time; also the FCU cadence from the sequencer (`block_time`).
    block_time_ms: u64 = 2000,
    /// Extra time a payload job stays queryable past its timestamp (`block_time_leeway`,
    /// the `PayloadJobDeadline` leeway; CLI `extra_block_deadline_secs`).
    block_time_leeway_ms: u64 = 500,
    /// How often a flashblock is produced (`flashblocks_interval`).
    flashblocks_interval_ms: u64 = 250,
    /// Time deducted from the block build time to absorb latency; comes out of the first
    /// flashblock and should not exceed the interval (`flashblocks_leeway_time`).
    flashblocks_leeway_time_ms: u64 = 50,

    /// base/base `BuilderConfig::for_tests` timing values.
    pub const for_tests: Config = .{
        .block_time_ms = 1000,
        .block_time_leeway_ms = 500,
        .flashblocks_interval_ms = 200,
        .flashblocks_leeway_time_ms = 100,
    };

    /// Rejects combinations base/base either panics on (zero interval divides by zero) or
    /// documents as invalid (leeway longer than one interval), plus block times that can
    /// never hold one full flashblock.
    pub fn validate(config: Config) ConfigError!void {
        if (config.block_time_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.block_time_leeway_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.flashblocks_interval_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.flashblocks_leeway_time_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.flashblocks_interval_ms == 0) return error.FlashblocksIntervalZero;
        if (config.flashblocks_leeway_time_ms > config.flashblocks_interval_ms) {
            return error.FlashblocksLeewayExceedsInterval;
        }
        if (config.block_time_ms < config.flashblocks_interval_ms) {
            return error.BlockTimeBelowInterval;
        }
        assert(config.flashblocks_per_block() >= 1);
    }

    /// Nominal flashblocks per block, ignoring drift (`flashblocks_per_block`).
    pub fn flashblocks_per_block(config: Config) u64 {
        if (config.block_time_ms == 0) return 0;
        assert(config.flashblocks_interval_ms > 0);
        const count = config.block_time_ms / config.flashblocks_interval_ms;
        assert(count * config.flashblocks_interval_ms <= config.block_time_ms);
        return count;
    }
};

/// Time a payload job stays available, measured from `now_ns` (`PayloadJobDeadline::calculate`).
/// Works in whole seconds like base/base: `max(timestamp - floor(now_s), 1s) + leeway`.
/// Deviation: the Rust branch for a clock before the Unix epoch cannot occur with u64 time.
pub fn payload_job_duration_ns(config: Config, attributes_timestamp_s: u64, now_ns: u64) u64 {
    assert(config.block_time_leeway_ms <= duration_ms_max);
    assert(now_ns <= time_ns_max);
    const now_s = now_ns / ns_per_s;
    const until_s = attributes_timestamp_s -| now_s;
    const leeway_ns = config.block_time_leeway_ms * ns_per_ms;
    // Saturate far-future timestamps instead of overflowing; base/base Duration holds them.
    const until_ns = if (until_s == 0) ns_per_s else std.math.mul(u64, until_s, ns_per_s) catch
        return std.math.maxInt(u64);
    const duration_ns = until_ns +| leeway_ns;
    assert(duration_ns >= ns_per_s);
    return duration_ns;
}

/// Flashblock count and first-flashblock offset (`calculate_flashblocks`).
pub const Derivation = struct {
    /// Regular flashblocks to build (indices `1..=count`); 0 means the FCU arrived too late.
    count: u64,
    /// Time from schedule start to the first interval tick; 0 only when `count` is 0.
    first_offset_ms: u64,
};

/// base/base arithmetic exactly: `drift = (timestamp - flashblocks_leeway) - now`, zero
/// flashblocks unless `drift >= 1ms`, `drift = min(drift, block_time)` in whole ms, then
/// `drift % interval` becomes the first offset (or a full interval on exact division).
pub fn derive(config: Config, timestamp_s: u64, now_ns: u64) Derivation {
    assert(config.flashblocks_interval_ms > 0);
    assert(now_ns <= time_ns_max);
    // u128 so any u64 second timestamp converts; SystemTime in Rust has the same range.
    const timestamp_ns: u128 = @as(u128, timestamp_s) * ns_per_s;
    const leeway_ns: u128 = @as(u128, config.flashblocks_leeway_time_ms) * ns_per_ms;
    const target_ns: u128 = timestamp_ns -| leeway_ns;
    if (target_ns <= now_ns) return .{ .count = 0, .first_offset_ms = 0 };
    const drift_ms_raw: u128 = (target_ns - now_ns) / ns_per_ms;
    if (drift_ms_raw == 0) return .{ .count = 0, .first_offset_ms = 0 };
    const drift_ms: u64 = @intCast(@min(drift_ms_raw, config.block_time_ms));
    const interval_ms = config.flashblocks_interval_ms;
    const remainder_ms = drift_ms % interval_ms;
    const result: Derivation = if (remainder_ms == 0)
        .{ .count = drift_ms / interval_ms, .first_offset_ms = interval_ms }
    else
        .{ .count = drift_ms / interval_ms + 1, .first_offset_ms = remainder_ms };
    assert(result.first_offset_ms > 0 or result.count == 0);
    assert(result.first_offset_ms <= interval_ms);
    return result;
}

/// The resting carry comes out of the first flashblock and never pushes the first tick into
/// the past (`first_flashblock_delay`).
pub fn first_flashblock_delay_ns(first_offset_ns: u64, resting_carry_ns: u64) u64 {
    const delay_ns = first_offset_ns -| resting_carry_ns;
    assert(delay_ns <= first_offset_ns);
    assert(delay_ns == 0 or delay_ns + resting_carry_ns == first_offset_ns);
    return delay_ns;
}

/// The per-block deadline schedule of one payload job.
pub const Schedule = struct {
    count: u64,
    first_offset_ms: u64,
    interval_ns: u64,
    /// When the schedule was derived (base/base reads `SystemTime::now` in
    /// `calculate_flashblocks`).
    start_ns: u64,
    /// First interval tick: closes flashblock 1. In base/base the timer is anchored at
    /// `Instant::now()` after the resting carry, plus `first_flashblock_delay`, so it equals
    /// `start + max(first_offset, resting_carry)` on one time base. Deviation: base/base uses
    /// two clock reads (SystemTime then Instant); here a single injected time base is used.
    first_deadline_ns: u64,

    pub fn init(config: Config, timestamp_s: u64, now_ns: u64, resting_carry_ns: u64) Schedule {
        assert(config.flashblocks_interval_ms > 0);
        assert(config.flashblocks_interval_ms <= duration_ms_max);
        assert(now_ns <= time_ns_max);
        assert(resting_carry_ns <= duration_ms_max * ns_per_ms);
        const derivation = derive(config, timestamp_s, now_ns);
        const first_offset_ns = derivation.first_offset_ms * ns_per_ms;
        const delay_ns = first_flashblock_delay_ns(first_offset_ns, resting_carry_ns);
        const schedule: Schedule = .{
            .count = derivation.count,
            .first_offset_ms = derivation.first_offset_ms,
            .interval_ns = config.flashblocks_interval_ms * ns_per_ms,
            .start_ns = now_ns,
            .first_deadline_ns = now_ns + resting_carry_ns + delay_ns,
        };
        assert(schedule.first_deadline_ns >= now_ns + first_offset_ns);
        return schedule;
    }

    /// Time at which flashblock `index` (1..=count) stops building.
    pub fn deadline_ns(schedule: Schedule, index: u64) u64 {
        assert(index >= 1);
        assert(index <= schedule.count);
        const deadline = schedule.first_deadline_ns + (index - 1) * schedule.interval_ns;
        assert(deadline >= schedule.first_deadline_ns);
        return deadline;
    }

    /// Deadline of the last flashblock, after which the job finalizes; null when count is 0.
    pub fn final_deadline_ns(schedule: Schedule) ?u64 {
        if (schedule.count == 0) return null;
        return schedule.deadline_ns(schedule.count);
    }

    /// Flashblock index being built at `now_ns`: 1 before the first tick, `j` while
    /// `deadline(j - 1) <= now < deadline(j)`, and `count + 1` (finalize) once every deadline
    /// has passed. With zero flashblocks it is always 1 = `count + 1`.
    pub fn index_due(schedule: Schedule, now_ns: u64) u64 {
        assert(schedule.interval_ns > 0);
        if (schedule.count == 0 or now_ns < schedule.first_deadline_ns) return 1;
        const ticks = (now_ns - schedule.first_deadline_ns) / schedule.interval_ns + 1;
        const index = @min(ticks, schedule.count) + 1;
        assert(index >= 2);
        assert(index <= schedule.count + 1);
        return index;
    }

    /// Earliest deadline strictly after `now_ns`, or null once the schedule is done.
    pub fn next_deadline_ns(schedule: Schedule, now_ns: u64) ?u64 {
        const index = schedule.index_due(now_ns);
        if (index > schedule.count) return null;
        const deadline = schedule.deadline_ns(index);
        assert(deadline > now_ns);
        return deadline;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "flashblocks_per_block matches config.rs" {
    try testing.expectEqual(@as(u64, 8), (Config{}).flashblocks_per_block());
    try testing.expectEqual(@as(u64, 5), Config.for_tests.flashblocks_per_block());
    var zero_block = Config{};
    zero_block.block_time_ms = 0;
    try testing.expectEqual(@as(u64, 0), zero_block.flashblocks_per_block());
}

test "validate rejects invalid combinations" {
    try (Config{}).validate();
    try Config.for_tests.validate();
    var config = Config{};
    config.flashblocks_interval_ms = 0;
    try testing.expectError(error.FlashblocksIntervalZero, config.validate());
    config = .{ .flashblocks_leeway_time_ms = 251 };
    try testing.expectError(error.FlashblocksLeewayExceedsInterval, config.validate());
    config = .{ .flashblocks_leeway_time_ms = 250 };
    try config.validate();
    config = .{ .block_time_ms = 249 };
    try testing.expectError(error.BlockTimeBelowInterval, config.validate());
    config = .{ .block_time_leeway_ms = duration_ms_max + 1 };
    try testing.expectError(error.DurationTooLarge, config.validate());
}

test "payload job deadline: minimum duration and leeway (deadline.rs)" {
    const cases = [_][2]u64{ .{ 0, 1000 }, .{ 5000, 6000 } };
    for (cases) |case| {
        const config = Config{ .block_time_leeway_ms = case[0] };
        const now_ns: u64 = 1_700_000_000 * ns_per_s + 123;
        try testing.expectEqual(case[1] * ns_per_ms, payload_job_duration_ns(config, 0, now_ns));
    }
}

test "payload job deadline: uses attributes timestamp (deadline.rs)" {
    for ([_]u64{ 0, 5000 }) |leeway_ms| {
        const config = Config{ .block_time_leeway_ms = leeway_ms };
        const now_s: u64 = 1_700_000_000;
        const now_ns = now_s * ns_per_s + 999_999_999;
        const duration_ns = payload_job_duration_ns(config, now_s + 60, now_ns);
        try testing.expect(duration_ns >= (59 * 1000 + leeway_ms) * ns_per_ms);
        try testing.expect(duration_ns <= (60 * 1000 + leeway_ms) * ns_per_ms);
    }
}

test "derive: on-time, partial, late, and exact division" {
    const config = Config{ .block_time_ms = 1000, .flashblocks_interval_ms = 200 };
    const timestamp_s: u64 = 1_000;
    const target_ns = timestamp_s * ns_per_s - 50 * ns_per_ms;
    // FCU exactly one block time before target: drift clamps to block time, exact division.
    var result = derive(config, timestamp_s, target_ns - 1000 * ns_per_ms);
    try testing.expectEqual(Derivation{ .count = 5, .first_offset_ms = 200 }, result);
    // Early FCU is clamped to block time too.
    result = derive(config, timestamp_s, target_ns - 3000 * ns_per_ms);
    try testing.expectEqual(Derivation{ .count = 5, .first_offset_ms = 200 }, result);
    // Late by 130ms: first flashblock shrinks to 70ms.
    result = derive(config, timestamp_s, target_ns - 870 * ns_per_ms);
    try testing.expectEqual(Derivation{ .count = 5, .first_offset_ms = 70 }, result);
    // Late beyond one interval: fewer flashblocks.
    result = derive(config, timestamp_s, target_ns - 450 * ns_per_ms);
    try testing.expectEqual(Derivation{ .count = 3, .first_offset_ms = 50 }, result);
    // Sub-millisecond drift truncates to 0ms: no flashblocks.
    result = derive(config, timestamp_s, target_ns - 999_999);
    try testing.expectEqual(Derivation{ .count = 0, .first_offset_ms = 0 }, result);
    // Exactly 1ms of drift: one 1ms flashblock.
    result = derive(config, timestamp_s, target_ns - ns_per_ms);
    try testing.expectEqual(Derivation{ .count = 1, .first_offset_ms = 1 }, result);
    // Past target, and leeway larger than the timestamp: no flashblocks.
    result = derive(config, timestamp_s, target_ns + 1);
    try testing.expectEqual(Derivation{ .count = 0, .first_offset_ms = 0 }, result);
    try testing.expectEqual(Derivation{ .count = 0, .first_offset_ms = 0 }, derive(config, 0, 0));
}

test "first flashblock delay subtracts resting carry (payload.rs)" {
    const offset_ns = 120 * ns_per_ms;
    try testing.expectEqual(offset_ns, first_flashblock_delay_ns(offset_ns, 0));
    try testing.expectEqual(100 * ns_per_ms, first_flashblock_delay_ns(offset_ns, 20 * ns_per_ms));
    const short_ns = 5 * ns_per_ms;
    try testing.expectEqual(@as(u64, 0), first_flashblock_delay_ns(short_ns, short_ns));
    try testing.expectEqual(@as(u64, 0), first_flashblock_delay_ns(short_ns, 300 * ns_per_ms));
}

test "schedule deadlines, index_due and next_deadline" {
    const config = Config{ .block_time_ms = 1000, .flashblocks_interval_ms = 200 };
    const target_ns = 1_000 * ns_per_s - 50 * ns_per_ms;
    const start_ns = target_ns - 870 * ns_per_ms;
    const schedule = Schedule.init(config, 1_000, start_ns, 0);
    try testing.expectEqual(@as(u64, 5), schedule.count);
    try testing.expectEqual(start_ns + 70 * ns_per_ms, schedule.deadline_ns(1));
    try testing.expectEqual(target_ns, schedule.final_deadline_ns().?);
    try testing.expectEqual(@as(u64, 1), schedule.index_due(start_ns));
    try testing.expectEqual(@as(u64, 2), schedule.index_due(schedule.deadline_ns(1)));
    try testing.expectEqual(@as(u64, 6), schedule.index_due(target_ns));
    const after_first_ns = schedule.deadline_ns(1);
    try testing.expectEqual(schedule.deadline_ns(2), schedule.next_deadline_ns(after_first_ns).?);
    try testing.expectEqual(@as(?u64, null), schedule.next_deadline_ns(target_ns));
    // A resting carry longer than the first offset delays the whole schedule by the excess.
    const carried = Schedule.init(config, 1_000, start_ns, 100 * ns_per_ms);
    try testing.expectEqual(start_ns + 100 * ns_per_ms, carried.deadline_ns(1));
    // Late FCU: zero flashblocks, the job finalizes straight away.
    const late = Schedule.init(config, 1_000, target_ns, 0);
    try testing.expectEqual(@as(u64, 0), late.count);
    try testing.expectEqual(@as(u64, 1), late.index_due(target_ns));
    try testing.expectEqual(@as(?u64, null), late.next_deadline_ns(0));
}

/// Checks every schedule invariant; shared by the exhaustive, seeded, and coverage fuzz tests.
fn check_schedule(config: Config, timestamp_s: u64, now_ns: u64, carry_ns: u64) !void {
    const schedule = Schedule.init(config, timestamp_s, now_ns, carry_ns);
    const nominal = config.block_time_ms / config.flashblocks_interval_ms;
    try testing.expect(schedule.count <= nominal + 1);
    if (schedule.count == 0) {
        try testing.expectEqual(@as(?u64, null), schedule.next_deadline_ns(now_ns));
        return;
    }
    const offset_ns = schedule.first_offset_ms * ns_per_ms;
    try testing.expect(offset_ns > 0 and offset_ns <= schedule.interval_ns);
    try testing.expectEqual(now_ns + @max(offset_ns, carry_ns), schedule.deadline_ns(1));
    // Without carry the schedule ends at the target, capped at one block time.
    const target_ns = @as(u128, timestamp_s) * ns_per_s -
        @as(u128, config.flashblocks_leeway_time_ms) * ns_per_ms;
    const span_ns = schedule.final_deadline_ns().? - schedule.first_deadline_ns + offset_ns;
    try testing.expect(span_ns <= config.block_time_ms * ns_per_ms);
    if (carry_ns <= offset_ns) try testing.expect(schedule.final_deadline_ns().? <= target_ns);
    var previous_ns = now_ns;
    var index: u64 = 1;
    while (index <= schedule.count) : (index += 1) {
        const deadline = schedule.deadline_ns(index);
        try testing.expect(deadline > previous_ns);
        try testing.expectEqual(index, schedule.index_due(deadline - 1));
        try testing.expectEqual(index + 1, schedule.index_due(deadline));
        try testing.expectEqual(deadline, schedule.next_deadline_ns(previous_ns).?);
        previous_ns = deadline;
    }
    try testing.expectEqual(@as(?u64, null), schedule.next_deadline_ns(previous_ns));
}

test "exhaustive schedule invariants over a small grid" {
    const timestamp_s: u64 = 10;
    for ([_]u64{ 1, 2, 3, 7, 10 }) |interval_ms| {
        for ([_]u64{ 0, 1, 2, 3, 7, 10, 23 }) |block_extra_ms| {
            var leeway_ms: u64 = 0;
            while (leeway_ms <= interval_ms) : (leeway_ms += 1) {
                const config = Config{
                    .block_time_ms = interval_ms + block_extra_ms,
                    .flashblocks_interval_ms = interval_ms,
                    .flashblocks_leeway_time_ms = leeway_ms,
                };
                try config.validate();
                const deadline_ns = timestamp_s * ns_per_s;
                var back_us: u64 = 0;
                while (back_us <= 40_000) : (back_us += 250) {
                    const now_ns = deadline_ns - back_us * 1000;
                    try check_schedule(config, timestamp_s, now_ns, 0);
                    try check_schedule(config, timestamp_s, now_ns, back_us * 100);
                }
            }
        }
    }
}

fn random_config(prng: *Prng) Config {
    const interval_ms = prng.range(1, 1000);
    return .{
        .block_time_ms = interval_ms + prng.below(5000),
        .block_time_leeway_ms = prng.below(duration_ms_max + 1),
        .flashblocks_interval_ms = interval_ms,
        .flashblocks_leeway_time_ms = prng.range(0, interval_ms),
    };
}

test "seeded fuzz: schedule invariants" {
    var prng = Prng.init(0x7131_6e67);
    var iteration: u32 = 0;
    while (iteration < 2000) : (iteration += 1) {
        const config = random_config(&prng);
        try config.validate();
        const timestamp_s = prng.range(0, time_ns_max / ns_per_s);
        const window_ns = 3 * config.block_time_ms * ns_per_ms;
        const base_ns = timestamp_s * ns_per_s;
        const now_ns = @min(time_ns_max, (base_ns -| window_ns) + prng.below(2 * window_ns));
        const carry_ns = if (prng.chance(1, 4)) prng.below(2 * config.flashblocks_interval_ms *
            ns_per_ms) else 0;
        try check_schedule(config, timestamp_s, now_ns, carry_ns);
        const job_ns = payload_job_duration_ns(config, timestamp_s, now_ns);
        try testing.expect(job_ns >= ns_per_s + config.block_time_leeway_ms * ns_per_ms);
    }
}

test "fuzz: schedule invariants" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var prng = Prng.init(smith.value(u64));
            const config = random_config(&prng);
            const timestamp_s = smith.value(u64);
            const now_ns = smith.value(u64) % (time_ns_max + 1);
            const carry_ns = smith.value(u64) % (duration_ms_max * ns_per_ms + 1);
            try check_schedule(config, timestamp_s, now_ns, carry_ns);
            _ = payload_job_duration_ns(config, timestamp_s, now_ns);
        }
    }.run, .{});
}

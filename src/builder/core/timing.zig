//! Block-building timing at Base's native subsecond cadence. Pure arithmetic over injected
//! time (callers pass `now_ns`); nothing here reads a clock.
//!
//! From Denim (`SubsecondBlocks`) every L2 block owns a 200 ms slot
//! (base/base `RollupConfig::NATIVE_SUBSECOND_BLOCK_INTERVAL_MILLIS`). The sequencer seals at a
//! fixed offset into the slot, `DEFAULT_SEAL_OFFSET = 150 ms`
//! (`crates/consensus/protocol/src/timing.rs`), and the builder stops adding pool
//! transactions at the same offset (its wall-clock transaction cutoff): both knobs default
//! from that one constant, so a mismatch shows up as every `getPayload` waiting on an
//! unfinished build.
//!
//! `block_seal_target_ms` ports the sequencer's `block_seal_target`
//! (`crates/consensus/service/src/actors/sequencer/actor.rs`) and its tests. `Slot` is the
//! builder's view of one job: the slot starts when the job starts, pool transactions stop at
//! `start + seal_offset`, and the job never waits past `start + interval`.

const std = @import("std");
const assert = std.debug.assert;

pub const ns_per_ms: u64 = std.time.ns_per_ms;
pub const ns_per_s: u64 = std.time.ns_per_s;

/// base/base `RollupConfig::NATIVE_SUBSECOND_BLOCK_INTERVAL_MILLIS`.
pub const native_subsecond_block_interval_ms: u64 = 200;
/// base/base `DEFAULT_SEAL_OFFSET`.
pub const default_seal_offset_ms: u64 = 150;

/// Upper bound on any configured duration; keeps every sum below in u64 range.
pub const duration_ms_max: u64 = 60 * 60 * 1000;

/// Upper bound on injected time. 2^62 ns is year ~2116; leaves headroom for adding durations.
pub const time_ns_max: u64 = 1 << 62;

comptime {
    assert(duration_ms_max * ns_per_ms * 4 < std.math.maxInt(u64) - time_ns_max);
    assert(default_seal_offset_ms < native_subsecond_block_interval_ms);
    assert(1000 % native_subsecond_block_interval_ms == 0);
}

pub const ConfigError = error{
    IntervalZero,
    SealOffsetExceedsInterval,
    DurationTooLarge,
};

pub const Config = struct {
    /// Slot length: one block per slot.
    block_interval_ms: u64 = native_subsecond_block_interval_ms,
    /// Offset into the slot at which pool transactions stop and the block seals.
    seal_offset_ms: u64 = default_seal_offset_ms,
    /// How long a sealed, unresolved job stays queryable past its slot end (base/base
    /// `block_time_leeway`, the `PayloadJobDeadline` leeway).
    job_leeway_ms: u64 = 500,

    pub fn validate(config: Config) ConfigError!void {
        if (config.block_interval_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.seal_offset_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.job_leeway_ms > duration_ms_max) return error.DurationTooLarge;
        if (config.block_interval_ms == 0) return error.IntervalZero;
        if (config.seal_offset_ms > config.block_interval_ms) {
            return error.SealOffsetExceedsInterval;
        }
        assert(config.seal_offset_ms <= config.block_interval_ms);
    }
};

/// Whether a block is built at the native subsecond cadence (`SubsecondBlocks` active at its
/// timestamp) or at the legacy whole-second block time.
pub const Cadence = enum { legacy, subsecond };

/// Inputs of the sequencer's seal target for one block.
pub const SealTarget = struct {
    cadence: Cadence,
    /// The block's scheduled timestamp `T_N` in milliseconds (`l2_block_timestamp_millis`).
    block_timestamp_ms: u64,
    seal_offset_ms: u64 = default_seal_offset_ms,
    /// Legacy block time in seconds (`RollupConfig::block_time`).
    block_time_s: u64 = 2,
    /// How long the previous seal took (legacy compensation only).
    last_seal_duration_ms: u64 = 0,
};

/// base/base `block_seal_target`: subsecond blocks seal at `T_N - (interval - seal_offset)`,
/// a fixed offset into their 200 ms slot that ignores how long the previous seal took
/// (lateness shrinks the build window instead of shifting the schedule), and the first
/// subsecond block still seals relative to its own timestamp. Legacy blocks lead their
/// timestamp by the previous seal duration, capped at half the block time.
pub fn block_seal_target_ms(target: SealTarget) u64 {
    assert(target.seal_offset_ms <= duration_ms_max);
    assert(target.block_time_s <= duration_ms_max / 1000);
    const result = switch (target.cadence) {
        .subsecond => target.block_timestamp_ms -|
            (native_subsecond_block_interval_ms -| target.seal_offset_ms),
        .legacy => target.block_timestamp_ms -|
            @min(target.last_seal_duration_ms, target.block_time_s * 1000 / 2),
    };
    assert(result <= target.block_timestamp_ms);
    return result;
}

/// Phase of a job's slot at some instant.
pub const Phase = enum {
    /// Before the cutoff: pool transactions may still be added.
    building,
    /// Past the cutoff, inside the slot: seal now.
    sealing,
    /// The slot has ended: a `getPayload` must already have its block.
    over,
};

/// One job's slot on the injected time base.
pub const Slot = struct {
    start_ns: u64,
    /// Pool transactions stop here (`start + seal_offset`).
    cutoff_ns: u64,
    /// The slot ends here (`start + interval`); nothing waits past it.
    end_ns: u64,
    /// The sealed job is dropped here (`end + job_leeway`).
    expires_ns: u64,

    pub fn init(config: Config, start_ns: u64) Slot {
        assert(start_ns <= time_ns_max);
        assert(config.seal_offset_ms <= config.block_interval_ms);
        assert(config.block_interval_ms <= duration_ms_max);
        assert(config.job_leeway_ms <= duration_ms_max);
        const end_ns = start_ns + config.block_interval_ms * ns_per_ms;
        const slot: Slot = .{
            .start_ns = start_ns,
            .cutoff_ns = start_ns + config.seal_offset_ms * ns_per_ms,
            .end_ns = end_ns,
            .expires_ns = end_ns + config.job_leeway_ms * ns_per_ms,
        };
        assert(slot.start_ns <= slot.cutoff_ns and slot.cutoff_ns <= slot.end_ns);
        assert(slot.end_ns <= slot.expires_ns);
        return slot;
    }

    pub fn phase(slot: Slot, now_ns: u64) Phase {
        assert(slot.cutoff_ns <= slot.end_ns);
        const result: Phase = if (now_ns < slot.cutoff_ns)
            .building
        else if (now_ns < slot.end_ns)
            .sealing
        else
            .over;
        assert((result == .building) == (now_ns < slot.cutoff_ns));
        return result;
    }

    /// The cutoff for a build that must seal at `now_ns` (an early `getPayload`): never later
    /// than the slot's own cutoff.
    pub fn cutoff_at(slot: Slot, now_ns: u64) u64 {
        const cutoff_ns = @min(slot.cutoff_ns, now_ns);
        assert(cutoff_ns <= slot.cutoff_ns);
        return cutoff_ns;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "timing: defaults match base/base" {
    const config: Config = .{};
    try config.validate();
    try testing.expectEqual(@as(u64, 200), config.block_interval_ms);
    try testing.expectEqual(@as(u64, 150), config.seal_offset_ms);
}

test "timing: validate rejects invalid combinations" {
    try testing.expectError(error.IntervalZero, (Config{ .block_interval_ms = 0 }).validate());
    const late: Config = .{ .seal_offset_ms = 201 };
    try testing.expectError(error.SealOffsetExceedsInterval, late.validate());
    try (Config{ .seal_offset_ms = 200 }).validate();
    try (Config{ .seal_offset_ms = 0 }).validate();
    const long: Config = .{ .job_leeway_ms = duration_ms_max + 1 };
    try testing.expectError(error.DurationTooLarge, long.validate());
}

// The five tests below port base/base `actor_test.rs` (`denim_seal_target_*`,
// `first_denim_block_*`, `pre_denim_*`): genesis at 100 s, 2 s legacy blocks, Denim at 102 s.

test "timing: denim seal target is a fixed offset into the slot" {
    // Block 2's slot starts at T_1 = 102_000 ms; the target is T_1 + 150 ms (T_2 - 50 ms).
    const target = block_seal_target_ms(.{ .cadence = .subsecond, .block_timestamp_ms = 102_200 });
    try testing.expectEqual(@as(u64, 102_150), target);
}

test "timing: denim seal target ignores the last seal duration" {
    for ([_]u64{ 5000, 1 }) |last_ms| {
        const target = block_seal_target_ms(.{
            .cadence = .subsecond,
            .block_timestamp_ms = 102_200,
            .last_seal_duration_ms = last_ms,
        });
        try testing.expectEqual(@as(u64, 102_150), target);
    }
}

test "timing: first denim block seal target is relative to its own timestamp" {
    // Block 1 (T_1 = 102 s) follows a full legacy slot: T_1 - 50 ms, not T_0 + 150 ms.
    const target = block_seal_target_ms(.{ .cadence = .subsecond, .block_timestamp_ms = 102_000 });
    try testing.expectEqual(@as(u64, 101_950), target);
}

test "timing: denim seal target uses the configured offset" {
    const target = block_seal_target_ms(.{
        .cadence = .subsecond,
        .block_timestamp_ms = 102_200,
        .seal_offset_ms = 100,
    });
    try testing.expectEqual(@as(u64, 102_100), target);
}

test "timing: pre-denim seal target keeps adaptive compensation" {
    // Block 5's timestamp is 110 s; the target leads it by the previous seal duration,
    // capped at half the block interval.
    const legacy: SealTarget = .{ .cadence = .legacy, .block_timestamp_ms = 110_000 };
    var target = legacy;
    target.last_seal_duration_ms = 300;
    try testing.expectEqual(@as(u64, 109_700), block_seal_target_ms(target));
    target.last_seal_duration_ms = 5000;
    try testing.expectEqual(@as(u64, 109_000), block_seal_target_ms(target));
}

test "timing: slot phases and early cutoff" {
    const start_ns: u64 = 7 * ns_per_s;
    const slot = Slot.init(.{}, start_ns);
    try testing.expectEqual(start_ns + 150 * ns_per_ms, slot.cutoff_ns);
    try testing.expectEqual(start_ns + 200 * ns_per_ms, slot.end_ns);
    try testing.expectEqual(start_ns + 700 * ns_per_ms, slot.expires_ns);
    try testing.expectEqual(Phase.building, slot.phase(start_ns));
    try testing.expectEqual(Phase.building, slot.phase(slot.cutoff_ns - 1));
    try testing.expectEqual(Phase.sealing, slot.phase(slot.cutoff_ns));
    try testing.expectEqual(Phase.sealing, slot.phase(slot.end_ns - 1));
    try testing.expectEqual(Phase.over, slot.phase(slot.end_ns));
    try testing.expectEqual(start_ns + 10, slot.cutoff_at(start_ns + 10));
    try testing.expectEqual(slot.cutoff_ns, slot.cutoff_at(slot.end_ns));
}

/// Invariants of one config, seal target and slot; shared by the seeded and coverage fuzz.
fn check_timing(prng: *Prng) !void {
    const interval_ms = prng.range(1, 1000);
    const config: Config = .{
        .block_interval_ms = interval_ms,
        .seal_offset_ms = prng.range(0, interval_ms),
        .job_leeway_ms = prng.below(duration_ms_max + 1),
    };
    try config.validate();
    const start_ns = prng.below(time_ns_max + 1);
    const slot = Slot.init(config, start_ns);
    const now_ns = prng.below(time_ns_max + 1);
    const phase = slot.phase(now_ns);
    try testing.expectEqual(now_ns >= slot.end_ns, phase == .over);
    try testing.expect(slot.cutoff_at(now_ns) <= slot.cutoff_ns);
    try testing.expect(slot.cutoff_at(now_ns) <= now_ns);
    const offset_ms = prng.range(0, native_subsecond_block_interval_ms);
    const timestamp_ms = prng.below(time_ns_max / ns_per_ms);
    const subsecond = block_seal_target_ms(.{
        .cadence = .subsecond,
        .block_timestamp_ms = timestamp_ms,
        .seal_offset_ms = offset_ms,
        .last_seal_duration_ms = prng.int(u64),
    });
    // The target lies inside the block's slot `[T_N - interval, T_N]`, offset from its start.
    if (timestamp_ms >= native_subsecond_block_interval_ms) {
        const slot_start_ms = timestamp_ms - native_subsecond_block_interval_ms;
        try testing.expectEqual(slot_start_ms + offset_ms, subsecond);
    }
    const legacy = block_seal_target_ms(.{
        .cadence = .legacy,
        .block_timestamp_ms = timestamp_ms,
        .block_time_s = prng.range(1, 10),
        .last_seal_duration_ms = prng.int(u64),
    });
    try testing.expect(legacy <= timestamp_ms and legacy + 5000 >= timestamp_ms);
}

test "timing: seeded fuzz of slot and seal target invariants" {
    var prng = Prng.init(0x7131_6e67);
    for (0..4000) |_| try check_timing(&prng);
}

test "timing: fuzz" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var prng = Prng.init(smith.value(u64));
            try check_timing(&prng);
        }
    }.run, .{});
}

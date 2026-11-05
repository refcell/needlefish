//! DA throttling (base/base `batcher/core/src/throttle.rs` + `service/src/throttle.rs`):
//! when the batcher's DA backlog grows, lower the block builder's per-tx and per-block DA
//! limits through `miner_setMaxDASize` so the sequencer produces less data to batch.
//!
//! Intensity rises from 0 at `start_threshold_bytes` to `max_intensity` at
//! `full_threshold_bytes` (step, linear, or quadratic). Limits interpolate from the upper
//! limit (intensity 0) to the lower limit (full intensity). Math is integer, in parts per
//! million, instead of base/base's f64; results match up to rounding at exact halves.
//!
//! The limits are pushed when they change and refreshed every `refresh_ms` (base/base
//! `REFRESH_INTERVAL`), so a restarted builder picks them up again.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../rpc/root.zig");

const ppm = 1_000_000;

pub const Strategy = enum { off, step, linear, quadratic };

pub const Config = struct {
    strategy: Strategy = .quadratic,
    start_threshold_bytes: u64 = 120_000_000,
    full_threshold_bytes: u64 = 360_000_000,
    max_intensity_ppm: u32 = ppm,
    block_size_lower_limit: u64 = 42_000,
    block_size_upper_limit: u64 = 1_900_000,
    tx_size_lower_limit: u64 = 3_500,
    tx_size_upper_limit: u64 = 390_000,
    refresh_ms: u64 = 10_000,

    pub fn validate(config: Config) void {
        assert(config.full_threshold_bytes > config.start_threshold_bytes);
        assert(config.max_intensity_ppm <= ppm);
        assert(config.block_size_lower_limit > 0);
        assert(config.block_size_lower_limit <= config.block_size_upper_limit);
        assert(config.tx_size_lower_limit > 0);
        assert(config.tx_size_lower_limit <= config.tx_size_upper_limit);
        assert(config.refresh_ms > 0);
    }

    /// Throttle intensity in ppm for a backlog; 0 below the start threshold.
    pub fn intensity_ppm(config: Config, backlog_bytes: u64) u32 {
        if (backlog_bytes < config.start_threshold_bytes) return 0;
        const excess: u128 = backlog_bytes - config.start_threshold_bytes;
        const range: u128 = config.full_threshold_bytes - config.start_threshold_bytes;
        const linear: u128 = @min(ppm, excess * ppm / range);
        const factor: u128 = switch (config.strategy) {
            .off => 0,
            .step => ppm,
            .linear => linear,
            .quadratic => linear * linear / ppm,
        };
        const intensity = factor * config.max_intensity_ppm / ppm;
        assert(intensity <= ppm);
        return @intCast(intensity);
    }

    pub fn limits(config: Config, backlog_bytes: u64) DaLimits {
        const intensity = config.intensity_ppm(backlog_bytes);
        const result: DaLimits = .{
            .max_tx_size = interpolate(
                config.tx_size_lower_limit,
                config.tx_size_upper_limit,
                intensity,
            ),
            .max_block_size = interpolate(
                config.block_size_lower_limit,
                config.block_size_upper_limit,
                intensity,
            ),
        };
        assert(result.max_tx_size >= config.tx_size_lower_limit);
        assert(result.max_block_size <= config.block_size_upper_limit);
        return result;
    }
};

pub const DaLimits = struct { max_tx_size: u64, max_block_size: u64 };

/// upper - intensity * (upper - lower), rounded to nearest.
fn interpolate(lower: u64, upper: u64, intensity: u32) u64 {
    assert(lower <= upper and intensity <= ppm);
    const reduction = (@as(u128, upper - lower) * intensity + ppm / 2) / ppm;
    return upper - @as(u64, @intCast(reduction));
}

pub const Outcome = enum {
    /// Nothing to send (limits unchanged and the refresh is not due), or disabled.
    idle,
    pushed,
    /// The builder answered `false`.
    refused,
    /// The builder does not serve `miner_setMaxDASize`; the throttle disables itself.
    unsupported,
    /// Transport or other RPC failure; retried on the next update.
    failed,
};

/// JSON-RPC "method not found".
const method_not_found_code = -32601;

pub const Throttle = struct {
    config: Config,
    pushed: ?DaLimits = null,
    pushed_at_ms: u64 = 0,
    disabled: bool = false,

    pub fn init(config: Config) Throttle {
        config.validate();
        return .{ .config = config, .disabled = config.strategy == .off };
    }

    /// Recomputes the limits for `backlog_bytes` and pushes them to `builder` when they
    /// changed or the refresh is due.
    pub fn update(
        throttle: *Throttle,
        builder: *rpc.Client,
        backlog_bytes: u64,
        now_ms: u64,
    ) Outcome {
        if (throttle.disabled) return .idle;
        const limits = throttle.config.limits(backlog_bytes);
        const changed = if (throttle.pushed) |previous|
            !std.meta.eql(previous, limits)
        else
            true;
        const refresh_due = now_ms -| throttle.pushed_at_ms >= throttle.config.refresh_ms;
        if (!changed and !refresh_due) return .idle;
        var params: [64]u8 = undefined;
        const params_json = std.fmt.bufPrint(&params, "[\"0x{x}\",\"0x{x}\"]", .{
            limits.max_tx_size,
            limits.max_block_size,
        }) catch unreachable; // Two u64 quantities fit in 64 bytes.
        const result = builder.call("miner_setMaxDASize", params_json) catch |err| {
            if (err == error.RpcError and builder.last_error_code == method_not_found_code) {
                throttle.disabled = true;
                return .unsupported;
            }
            return .failed;
        };
        throttle.pushed_at_ms = now_ms;
        if (result != .bool or !result.bool) return .refused;
        throttle.pushed = limits;
        return .pushed;
    }
};

/// Running estimate of the DA backlog: (unsafe - safe) blocks times an exponential
/// moving average of the estimated DA bytes per loaded block. The batcher does not
/// fetch blocks it has not loaded yet, so their size is extrapolated.
pub const BacklogEstimate = struct {
    /// Per-block estimate in bytes, scaled by 16 (EMA with weight 1/16).
    average_scaled: u64 = block_overhead_bytes * 16,

    /// base/base `BufferedBlock::BATCH_OVERHEAD_BYTES`.
    pub const block_overhead_bytes: u64 = 70;

    pub fn observe_block(estimate: *BacklogEstimate, estimated_da_bytes: u64) void {
        assert(estimated_da_bytes >= block_overhead_bytes);
        const sample = @min(estimated_da_bytes, 1 << 40) * 16;
        const average = estimate.average_scaled;
        estimate.average_scaled = average - average / 16 + sample / 16;
        assert(estimate.average_scaled > 0);
    }

    pub fn backlog_bytes(estimate: *const BacklogEstimate, unsafe_l2: u64, safe_l2: u64) u64 {
        const blocks = unsafe_l2 -| safe_l2;
        return blocks *| (estimate.average_scaled / 16);
    }
};

const flz = @import("../../common/flz/root.zig");

/// Estimated DA bytes of a block (base/base `BufferedBlock::new`): batch overhead plus
/// the Fjord FastLZ size estimate of each non-deposit transaction.
pub fn block_da_bytes(transactions: []const []const u8) u64 {
    var total: u64 = BacklogEstimate.block_overhead_bytes;
    for (transactions) |tx| {
        assert(tx.len > 0 and tx[0] != 0x7e); // Deposits are filtered by the source.
        total +|= flz.estimated_size_bytes(tx);
    }
    assert(total >= BacklogEstimate.block_overhead_bytes);
    return total;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "throttle: limits follow base/base's controller" {
    const quadratic: Config = .{};
    const at_rest = quadratic.limits(0);
    try testing.expectEqual(@as(u64, 390_000), at_rest.max_tx_size);
    try testing.expectEqual(@as(u64, 1_900_000), at_rest.max_block_size);
    const full = quadratic.limits(400_000_000);
    try testing.expectEqual(DaLimits{ .max_tx_size = 3_500, .max_block_size = 42_000 }, full);
    // Midway: linear factor 0.5, quadratic intensity 0.25.
    const mid = quadratic.limits(240_000_000);
    try testing.expectEqual(DaLimits{ .max_tx_size = 293_375, .max_block_size = 1_435_500 }, mid);
    const linear: Config = .{ .strategy = .linear };
    const linear_mid = linear.limits(240_000_000);
    try testing.expectEqual(@as(u64, 196_750), linear_mid.max_tx_size);
    try testing.expectEqual(@as(u64, 971_000), linear_mid.max_block_size);
    const step: Config = .{ .strategy = .step, .max_intensity_ppm = 500_000 };
    try testing.expectEqual(@as(u32, 500_000), step.intensity_ppm(120_000_000));
    try testing.expectEqual(@as(u32, 0), step.intensity_ppm(119_999_999));
}

test "throttle: pushes on change and on refresh; disables without the miner API" {
    var canned: rpc.CannedTransport = .{ .answers = &.{
        .{ .method = "miner_setMaxDASize", .result = "true" },
    } };
    var client = try rpc.Client.init(testing.allocator, canned.transport(), .{});
    defer client.deinit(testing.allocator);
    var throttle: Throttle = .init(.{});
    try testing.expectEqual(Outcome.pushed, throttle.update(&client, 0, 1_000));
    try testing.expectEqual(Outcome.idle, throttle.update(&client, 0, 2_000));
    try testing.expectEqual(Outcome.pushed, throttle.update(&client, 300_000_000, 3_000));
    try testing.expectEqual(Outcome.idle, throttle.update(&client, 300_000_000, 12_999));
    try testing.expectEqual(Outcome.pushed, throttle.update(&client, 300_000_000, 13_000));
    try testing.expectEqual(@as(u32, 3), canned.calls);

    var missing: rpc.CannedTransport = .{ .answers = &.{} };
    var bare = try rpc.Client.init(testing.allocator, missing.transport(), .{});
    defer bare.deinit(testing.allocator);
    var unsupported: Throttle = .init(.{});
    try testing.expectEqual(Outcome.unsupported, unsupported.update(&bare, 0, 0));
    try testing.expectEqual(Outcome.idle, unsupported.update(&bare, 0, 20_000));
    try testing.expectEqual(@as(u32, 1), missing.calls);
    var off: Throttle = .init(.{ .strategy = .off });
    try testing.expectEqual(Outcome.idle, off.update(&bare, 1 << 40, 0));
}

test "throttle: seeded fuzz keeps limits monotonic in the backlog and within bounds" {
    var prng = Prng.init(0xda);
    for (0..500) |_| {
        const lower_tx = prng.range(1, 10_000);
        const lower_block = prng.range(1, 100_000);
        const start = prng.range(0, 1 << 32);
        const config: Config = .{
            .strategy = @fromBackingInt(@intCast(prng.below(4))),
            .start_threshold_bytes = start,
            .full_threshold_bytes = start + prng.range(1, 1 << 32),
            .max_intensity_ppm = @intCast(prng.below(ppm + 1)),
            .tx_size_lower_limit = lower_tx,
            .tx_size_upper_limit = lower_tx + prng.below(1 << 20),
            .block_size_lower_limit = lower_block,
            .block_size_upper_limit = lower_block + prng.below(1 << 24),
        };
        config.validate();
        const small = prng.int(u64);
        const large = small +| prng.int(u32);
        const a = config.limits(small);
        const b = config.limits(large);
        try testing.expect(b.max_tx_size <= a.max_tx_size);
        try testing.expect(b.max_block_size <= a.max_block_size);
        try testing.expect(a.max_tx_size <= config.tx_size_upper_limit);
        try testing.expect(b.max_block_size >= config.block_size_lower_limit);
    }
}

test "throttle: backlog estimate tracks the average block size" {
    var estimate: BacklogEstimate = .{};
    try testing.expectEqual(@as(u64, 700), estimate.backlog_bytes(15, 5));
    for (0..200) |_| estimate.observe_block(1070);
    const backlog = estimate.backlog_bytes(1010, 10);
    try testing.expect(backlog > 1_000_000 and backlog <= 1_070_000);
    try testing.expectEqual(@as(u64, 0), estimate.backlog_bytes(3, 9));
    var transfer: [121]u8 = @splat(0x55);
    transfer[0] = 0x02;
    try testing.expect(block_da_bytes(&.{&transfer}) > BacklogEstimate.block_overhead_bytes);
}

test "throttle: fuzz limits" {
    try testing.fuzz({}, fuzz_limits, .{});
}

fn fuzz_limits(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [16]u8 = @splat(0);
    _ = smith.slice(&bytes);
    const backlog = std.mem.readInt(u64, bytes[0..8], .little);
    const config: Config = .{ .strategy = @fromBackingInt(@intCast(bytes[8] % 4)) };
    const limits = config.limits(backlog);
    try testing.expect(limits.max_tx_size >= config.tx_size_lower_limit);
    try testing.expect(limits.max_block_size <= config.block_size_upper_limit);
}

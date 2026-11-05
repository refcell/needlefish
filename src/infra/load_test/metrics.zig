//! Load test results (base/base `load-tests/src/metrics/{collector,aggregator,types}.rs`):
//! inclusion latency percentiles, throughput, success rate, and failure reasons, written as
//! a plain-text report. Samples live in a fixed array; past capacity, latencies are kept by
//! reservoir sampling so percentiles stay representative for long runs.

const std = @import("std");
const assert = std.debug.assert;

const manager = @import("../tx_manager/manager.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const failure_count = std.enums.values(manager.Failure).len;

pub const Summary = struct {
    submitted: u64,
    confirmed: u64,
    failed: u64,
    send_errors: u64,
    bumps: u64,
    latency_p50_ms: u64,
    latency_p90_ms: u64,
    latency_p99_ms: u64,
    latency_max_ms: u64,
    /// Confirmed transactions per second over the measured window, times 1000.
    throughput_milli_tps: u64,
};

pub fn Recorder(comptime samples_max: u32) type {
    comptime assert(samples_max > 0);
    return struct {
        const Self = @This();

        samples: [samples_max]u32 = undefined,
        sample_count: u32 = 0,
        /// Latencies observed, including ones not kept by the reservoir.
        observed: u64 = 0,
        scratch: [samples_max]u32 = undefined,
        prng: Prng = Prng.init(0x10ad),
        submitted: u64 = 0,
        confirmed: u64 = 0,
        failed: u64 = 0,
        failures: [failure_count]u64 = @splat(0),
        send_errors: u64 = 0,
        bumps: u64 = 0,
        latency_max_ms: u64 = 0,
        first_submit_ms: ?u64 = null,
        last_confirm_ms: u64 = 0,

        pub fn record_submit(recorder: *Self, now_ms: u64) void {
            recorder.submitted += 1;
            if (recorder.first_submit_ms == null) recorder.first_submit_ms = now_ms;
        }

        pub fn record_send_error(recorder: *Self) void {
            recorder.send_errors += 1;
        }

        pub fn record_completion(
            recorder: *Self,
            outcome: manager.Outcome,
            bumps: u64,
            latency_ms: u64,
            now_ms: u64,
        ) void {
            recorder.bumps += bumps;
            switch (outcome) {
                .failed => |failure| {
                    recorder.failed += 1;
                    recorder.failures[@backingInt(failure)] += 1;
                },
                .confirmed => {
                    recorder.confirmed += 1;
                    recorder.last_confirm_ms = @max(recorder.last_confirm_ms, now_ms);
                    recorder.record_latency(latency_ms);
                },
            }
            assert(recorder.confirmed + recorder.failed <= recorder.submitted);
        }

        fn record_latency(recorder: *Self, latency_ms: u64) void {
            const value: u32 = @intCast(@min(latency_ms, std.math.maxInt(u32)));
            recorder.latency_max_ms = @max(recorder.latency_max_ms, latency_ms);
            recorder.observed += 1;
            if (recorder.sample_count < samples_max) {
                recorder.samples[recorder.sample_count] = value;
                recorder.sample_count += 1;
                return;
            }
            // Algorithm R: keep each observation with probability samples_max / observed.
            const slot = recorder.prng.below(recorder.observed);
            if (slot < samples_max) recorder.samples[@intCast(slot)] = value;
        }

        pub fn summary(recorder: *Self) Summary {
            const sorted = recorder.scratch[0..recorder.sample_count];
            @memcpy(sorted, recorder.samples[0..recorder.sample_count]);
            std.mem.sort(u32, sorted, {}, std.sort.asc(u32));
            const window_ms = recorder.last_confirm_ms -| (recorder.first_submit_ms orelse 0);
            return .{
                .submitted = recorder.submitted,
                .confirmed = recorder.confirmed,
                .failed = recorder.failed,
                .send_errors = recorder.send_errors,
                .bumps = recorder.bumps,
                .latency_p50_ms = percentile(sorted, 50),
                .latency_p90_ms = percentile(sorted, 90),
                .latency_p99_ms = percentile(sorted, 99),
                .latency_max_ms = recorder.latency_max_ms,
                .throughput_milli_tps = if (window_ms == 0)
                    0
                else
                    recorder.confirmed * 1_000_000 / window_ms,
            };
        }

        pub fn write_report(recorder: *Self, out: *std.Io.Writer) std.Io.Writer.Error!void {
            const s = recorder.summary();
            try out.print("submitted      {d}\nconfirmed      {d}\nfailed         {d}\n", .{
                s.submitted, s.confirmed, s.failed,
            });
            try out.print("send errors    {d}\nfee bumps      {d}\n", .{ s.send_errors, s.bumps });
            try out.print("throughput     {d}.{d:0>3} tx/s\n", .{
                s.throughput_milli_tps / 1000, s.throughput_milli_tps % 1000,
            });
            try out.print("latency ms     p50 {d}  p90 {d}  p99 {d}  max {d}\n", .{
                s.latency_p50_ms, s.latency_p90_ms, s.latency_p99_ms, s.latency_max_ms,
            });
            for (recorder.failures, 0..) |count, index| {
                if (count == 0) continue;
                const failure: manager.Failure = @fromBackingInt(@intCast(index));
                try out.print("failure        {t}: {d}\n", .{ failure, count });
            }
        }
    };
}

/// Writes the summary as JSON object members (no surrounding braces), for embedding.
pub fn write_json_members(
    s: Summary,
    failures: []const u64,
    out: *std.Io.Writer,
) std.Io.Writer.Error!void {
    assert(failures.len == failure_count);
    try out.print("\"submitted\":{d},\"confirmed\":{d},\"failed\":{d},", .{
        s.submitted, s.confirmed, s.failed,
    });
    try out.print("\"send_errors\":{d},\"fee_bumps\":{d},\"throughput_milli_tps\":{d},", .{
        s.send_errors, s.bumps, s.throughput_milli_tps,
    });
    try out.print("\"latency_ms\":{{\"p50\":{d},\"p90\":{d},\"p99\":{d},\"max\":{d}}},", .{
        s.latency_p50_ms, s.latency_p90_ms, s.latency_p99_ms, s.latency_max_ms,
    });
    try out.writeAll("\"failures\":{");
    var first = true;
    for (failures, 0..) |count, index| {
        if (count == 0) continue;
        const failure: manager.Failure = @fromBackingInt(@intCast(index));
        try out.print("{s}\"{t}\":{d}", .{ if (first) "" else ",", failure, count });
        first = false;
    }
    try out.writeAll("}");
}

/// Nearest-rank percentile of an ascending slice; 0 when empty.
fn percentile(sorted: []const u32, rank: u32) u64 {
    assert(rank > 0 and rank <= 100);
    if (sorted.len == 0) return 0;
    const index = (sorted.len * rank + 99) / 100 - 1;
    assert(index < sorted.len);
    return sorted[index];
}

const testing = std.testing;
const confirmed_outcome: manager.Outcome = .{
    .confirmed = .{ .hash = @splat(0), .block_number = 1 },
};

test "metrics: percentiles and throughput" {
    var recorder: Recorder(1000) = .{};
    for (0..100) |index| recorder.record_submit(index * 10);
    for (1..101) |latency| {
        const outcome = confirmed_outcome;
        recorder.record_completion(outcome, 0, latency, 10_000);
    }
    const s = recorder.summary();
    try testing.expectEqual(@as(u64, 50), s.latency_p50_ms);
    try testing.expectEqual(@as(u64, 90), s.latency_p90_ms);
    try testing.expectEqual(@as(u64, 99), s.latency_p99_ms);
    try testing.expectEqual(@as(u64, 100), s.latency_max_ms);
    try testing.expectEqual(@as(u64, 10_000), s.throughput_milli_tps); // 100 tx in 10 s.
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try recorder.write_report(&writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "10.000 tx/s") != null);
}

test "metrics: reservoir keeps percentiles representative" {
    var recorder: Recorder(64) = .{};
    var prng = Prng.init(3);
    for (0..10_000) |_| {
        recorder.record_submit(0);
        const outcome = confirmed_outcome;
        recorder.record_completion(outcome, 0, prng.below(1000), 1);
    }
    const s = recorder.summary();
    try testing.expect(s.latency_p50_ms > 300 and s.latency_p50_ms < 700);
    recorder.record_submit(0);
    recorder.record_completion(.{ .failed = .send_timeout }, 2, 0, 1);
    const index = @backingInt(manager.Failure.send_timeout);
    try testing.expectEqual(@as(u64, 1), recorder.failures[index]);
}

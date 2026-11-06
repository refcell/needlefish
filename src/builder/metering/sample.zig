//! One transaction's simulated resource observations (base/base `ResourceSample` built by
//! `ResourceSample::from_meter` from the matching `meterBundle` transaction result): the
//! simulated gas used and the opcode, precompile and pseudo-opcode rows (`OpcodeGas`).
//!
//! A sample is fixed-size so the metering store holds it inline (static allocation): at
//! most `observations_max` rows whose trimmed names share `name_bytes_max` bytes. Rows with
//! a trimmed name over `schedule.operation_name_length_max` are dropped, since no schedule
//! rule can price them (the evaluator ignores them too). A result that does not fit is
//! rejected (`SampleFull`) and the caller stores no sample, so the builder fails open, as
//! base/base does for a transaction without metering data. The contract address of a row is
//! not kept: the evaluator never reads it.

const std = @import("std");
const assert = std.debug.assert;

const schedule = @import("schedule.zig");

pub const Observation = schedule.Observation;

pub const observations_max = 32;
pub const name_bytes_max = 512;

comptime {
    assert(observations_max <= std.math.maxInt(u8));
    assert(name_bytes_max <= std.math.maxInt(u16));
    assert(schedule.operation_name_length_max <= name_bytes_max);
}

pub const Sample = struct {
    /// The transaction's simulated gas used (`TransactionResult::gas_used`).
    gas_used: u64 = 0,
    row_count: u8 = 0,
    name_bytes_used: u16 = 0,
    rows: [observations_max]Row = undefined,
    name_bytes: [name_bytes_max]u8 = undefined,

    const Row = struct {
        count: u64,
        gas_used: u64,
        name_start: u16,
        name_length: u8,
    };

    pub fn init(gas_used: u64) Sample {
        const sample: Sample = .{ .gas_used = gas_used };
        assert(sample.row_count == 0 and sample.name_bytes_used == 0);
        return sample;
    }

    /// Adds one `OpcodeGas` row. Nothing is written on `SampleFull`.
    pub fn append(
        sample: *Sample,
        name: []const u8,
        count: u64,
        gas_used: u64,
    ) error{SampleFull}!void {
        assert(sample.row_count <= observations_max);
        const trimmed = schedule.trim(name);
        if (trimmed.len > schedule.operation_name_length_max) return;
        if (sample.row_count == observations_max) return error.SampleFull;
        if (trimmed.len > name_bytes_max - sample.name_bytes_used) return error.SampleFull;
        const start = sample.name_bytes_used;
        @memcpy(sample.name_bytes[start..][0..trimmed.len], trimmed);
        sample.rows[sample.row_count] = .{
            .count = count,
            .gas_used = gas_used,
            .name_start = start,
            .name_length = @intCast(trimmed.len),
        };
        sample.row_count += 1;
        sample.name_bytes_used += @intCast(trimmed.len);
        assert(sample.name_bytes_used <= name_bytes_max);
    }

    /// The rows as evaluator observations in `out` (names borrow the sample).
    pub fn observations(
        sample: *const Sample,
        out: *[observations_max]Observation,
    ) []const Observation {
        assert(sample.row_count <= observations_max);
        for (sample.rows[0..sample.row_count], 0..) |row, index| {
            assert(row.name_start + row.name_length <= sample.name_bytes_used);
            out[index] = .{
                .name = sample.name_bytes[row.name_start..][0..row.name_length],
                .count = row.count,
                .gas_used = row.gas_used,
            };
        }
        return out[0..sample.row_count];
    }
};

test "sample: rows round-trip, trimmed; unpriceable names dropped; full is atomic" {
    var sample = Sample.init(21_000);
    try sample.append(" SSTORE ", 2, 40_000);
    const too_long: [schedule.operation_name_length_max + 1]u8 = @splat('x');
    try sample.append(&too_long, 1, 1);
    try sample.append("keccak256", 3, 90);
    var out: [observations_max]Observation = undefined;
    const rows = sample.observations(&out);
    try std.testing.expectEqual(@as(usize, 2), rows.len);
    try std.testing.expectEqualStrings("SSTORE", rows[0].name);
    try std.testing.expectEqual(@as(u64, 40_000), rows[0].gas_used);
    try std.testing.expectEqualStrings("keccak256", rows[1].name);
    try std.testing.expectEqual(@as(u64, 3), rows[1].count);
    var full = Sample.init(0);
    for (0..observations_max) |_| try full.append("ADD", 1, 3);
    try std.testing.expectError(error.SampleFull, full.append("MUL", 1, 5));
    try std.testing.expectEqual(@as(u8, observations_max), full.row_count);
    var bytes = Sample.init(0);
    const long: [schedule.operation_name_length_max]u8 = @splat('y');
    for (0..name_bytes_max / long.len) |_| try bytes.append(&long, 1, 1);
    const used = bytes.name_bytes_used;
    try std.testing.expectError(error.SampleFull, bytes.append(&long, 1, 1));
    try std.testing.expectEqual(used, bytes.name_bytes_used);
}

//! RFC 3339 timestamps for `transaction-event/v1` (`event_time`, `ingested_at`).
//!
//! Parsing accepts what chrono's `DateTime<Utc>` deserializer accepts in practice:
//! `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, `T`/`t`/space as the separator, `z` as
//! UTC, and any number of fraction digits (beyond nanoseconds they are truncated). Times are
//! nanoseconds since the Unix epoch in a `u64`, so 1970-01-01 through year `year_max` are
//! representable; earlier or later instants are rejected. Formatting matches chrono's
//! `SecondsFormat::AutoSi` with `Z`: no fraction, or 3, 6, or 9 digits.

const std = @import("std");
const assert = std.debug.assert;

pub const ns_per_s: u64 = std.time.ns_per_s;
pub const s_per_day: u64 = 24 * 60 * 60;
/// Latest representable year (2^64 ns is about 584 years after 1970).
pub const year_max: u32 = 2500;
/// `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`.
pub const formatted_size_max = 30;

pub const ParseError = error{InvalidTime};

pub const Civil = struct { year: u32, month: u32, day: u32 };

/// Parses an RFC 3339 timestamp into nanoseconds since the Unix epoch.
pub fn parse(text: []const u8) ParseError!u64 {
    if (text.len < 20 or text.len > 64) return error.InvalidTime;
    const year = try digits(text[0..4]);
    const month = try digits(text[5..7]);
    const day = try digits(text[8..10]);
    const hour = try digits(text[11..13]);
    const minute = try digits(text[14..16]);
    const second = try digits(text[17..19]);
    const separators_ok = text[4] == '-' and text[7] == '-' and text[13] == ':' and
        text[16] == ':' and (text[10] == 'T' or text[10] == 't' or text[10] == ' ');
    if (!separators_ok) return error.InvalidTime;
    if (year < 1970 or year > year_max or month < 1 or month > 12) return error.InvalidTime;
    if (day < 1 or day > days_in_month(year, month)) return error.InvalidTime;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTime;
    var index: usize = 19;
    const fraction_ns = try parse_fraction(text, &index);
    const offset_s = try parse_offset(text[index..]);
    const days: u64 = days_from_civil(.{ .year = year, .month = month, .day = day });
    const local_s = days * s_per_day + hour * 3600 + minute * 60 + second;
    const utc_s: i64 = @as(i64, @intCast(local_s)) - offset_s;
    if (utc_s < 0) return error.InvalidTime;
    const result = @as(u64, @intCast(utc_s)) * ns_per_s + fraction_ns;
    assert(fraction_ns < ns_per_s);
    return result;
}

fn digits(text: []const u8) ParseError!u32 {
    assert(text.len > 0 and text.len <= 4);
    var value: u32 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidTime;
        value = value * 10 + (byte - '0');
    }
    return value;
}

/// Parses `.digits` at `index.*` (if present), advancing past it.
fn parse_fraction(text: []const u8, index: *usize) ParseError!u64 {
    assert(index.* <= text.len);
    if (index.* == text.len or text[index.*] != '.') return 0;
    index.* += 1;
    const start = index.*;
    var fraction_ns: u64 = 0;
    var scale: u64 = ns_per_s / 10;
    while (index.* < text.len and std.ascii.isDigit(text[index.*])) : (index.* += 1) {
        fraction_ns += (text[index.*] - '0') * scale;
        scale /= 10;
    }
    if (index.* == start) return error.InvalidTime;
    assert(fraction_ns < ns_per_s);
    return fraction_ns;
}

/// The UTC offset in seconds (`Z` is 0); `rest` must be exactly the offset.
fn parse_offset(rest: []const u8) ParseError!i64 {
    if (rest.len == 1 and (rest[0] == 'Z' or rest[0] == 'z')) return 0;
    if (rest.len != 6 or rest[3] != ':') return error.InvalidTime;
    const sign: i64 = switch (rest[0]) {
        '+' => 1,
        '-' => -1,
        else => return error.InvalidTime,
    };
    const hours = try digits(rest[1..3]);
    const minutes = try digits(rest[4..6]);
    if (hours > 23 or minutes > 59) return error.InvalidTime;
    const offset_s = sign * (@as(i64, hours) * 3600 + minutes * 60);
    assert(offset_s > -86_400 and offset_s < 86_400);
    return offset_s;
}

pub fn days_in_month(year: u32, month: u32) u32 {
    assert(month >= 1 and month <= 12);
    const leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0;
    const table = [12]u32{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    const days = if (month == 2 and leap) 29 else table[month - 1];
    assert(days >= 28);
    return days;
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`, non-negative years only).
pub fn days_from_civil(civil: Civil) u32 {
    assert(civil.year >= 1970 and civil.month >= 1 and civil.month <= 12);
    const year = if (civil.month <= 2) civil.year - 1 else civil.year;
    const era = year / 400;
    const year_of_era = year - era * 400;
    const month_shifted = if (civil.month > 2) civil.month - 3 else civil.month + 9;
    const day_of_year = (153 * month_shifted + 2) / 5 + civil.day - 1;
    const day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    const days = era * 146_097 + day_of_era - 719_468;
    assert(day_of_era < 146_097);
    return days;
}

/// Inverse of `days_from_civil`.
pub fn civil_from_days(days: u64) Civil {
    const shifted = days + 719_468;
    const era = shifted / 146_097;
    const day_of_era = shifted - era * 146_097;
    const year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 -
        day_of_era / 146_096) / 365;
    const day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    const month_shifted = (5 * day_of_year + 2) / 153;
    const day = day_of_year - (153 * month_shifted + 2) / 5 + 1;
    const month = if (month_shifted < 10) month_shifted + 3 else month_shifted - 9;
    const year = year_of_era + era * 400 + @intFromBool(month <= 2);
    assert(month >= 1 and month <= 12);
    assert(day >= 1 and day <= 31);
    return .{ .year = @intCast(year), .month = @intCast(month), .day = @intCast(day) };
}

/// Formats `time_ns` as RFC 3339 UTC with an AutoSi fraction.
pub fn format(time_ns: u64, buffer: *[formatted_size_max]u8) []const u8 {
    const seconds = time_ns / ns_per_s;
    const fraction_ns = time_ns % ns_per_s;
    const civil = civil_from_days(seconds / s_per_day);
    const second_of_day = seconds % s_per_day;
    var writer: std.Io.Writer = .fixed(buffer);
    writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{
        civil.year,
        civil.month,
        civil.day,
        second_of_day / 3600,
        second_of_day % 3600 / 60,
        second_of_day % 60,
    }) catch unreachable; // 19 bytes always fit.
    if (fraction_ns == 0) {
        // No fraction.
    } else if (fraction_ns % 1_000_000 == 0) {
        writer.print(".{d:0>3}", .{fraction_ns / 1_000_000}) catch unreachable;
    } else if (fraction_ns % 1_000 == 0) {
        writer.print(".{d:0>6}", .{fraction_ns / 1_000}) catch unreachable;
    } else {
        writer.print(".{d:0>9}", .{fraction_ns}) catch unreachable;
    }
    writer.writeByte('Z') catch unreachable; // At most 30 bytes, the buffer size.
    assert(writer.end >= 20);
    return writer.buffered();
}

const testing = std.testing;

test "time: parse and format round trip" {
    var buffer: [formatted_size_max]u8 = undefined;
    const cases = [_][]const u8{
        "1970-01-01T00:00:00Z",
        "2026-11-05T12:34:56Z",
        "2024-02-29T23:59:59.123Z",
        "2026-01-01T00:00:00.000001Z",
        "2026-01-01T00:00:00.123456789Z",
    };
    for (cases) |text| {
        const time_ns = try parse(text);
        try testing.expectEqualStrings(text, format(time_ns, &buffer));
    }
    try testing.expectEqual(@as(u64, 0), try parse("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(u64, 86_400 * ns_per_s), try parse("1970-01-02t00:00:00z"));
}

test "time: offsets, fractions, and rejections" {
    const utc = try parse("2026-11-05T10:00:00Z");
    try testing.expectEqual(utc, try parse("2026-11-05T12:00:00+02:00"));
    try testing.expectEqual(utc, try parse("2026-11-05T07:30:00-02:30"));
    try testing.expectEqual(utc + 5, try parse("2026-11-05T10:00:00.0000000059Z"));
    const invalid = [_][]const u8{
        "",                          "2026-11-05",                "2026-13-01T00:00:00Z",
        "2026-02-29T00:00:00Z",      "2026-11-05T24:00:00Z",      "2026-11-05T10:00:60Z",
        "2026-11-05T10:00:00",       "2026-11-05T10:00:00.Z",     "1969-12-31T23:59:59Z",
        "1970-01-01T00:00:00+00:01", "2026-11-05T10:00:00+2:00",  "2026/11/05T10:00:00Z",
        "2501-01-01T00:00:00Z",      "2026-11-05T10:00:00+24:00", "2026-11-05X10:00:00Z",
    };
    for (invalid) |text| try testing.expectError(error.InvalidTime, parse(text));
}

test "time: civil conversion agrees with std over many days" {
    var day: u64 = 0;
    while (day < 200_000) : (day += 37) {
        const civil = civil_from_days(day);
        try testing.expectEqual(day, days_from_civil(civil));
        const epoch_day: std.time.epoch.EpochDay = .{ .day = @intCast(day) };
        const year_day = epoch_day.calculateYearDay();
        try testing.expectEqual(@as(u32, year_day.year), civil.year);
        const month_day = year_day.calculateMonthDay();
        try testing.expectEqual(@as(u32, month_day.month.numeric()), civil.month);
        try testing.expectEqual(@as(u32, month_day.day_index) + 1, civil.day);
    }
}

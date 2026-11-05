//! Append-only broadcast journal (base/base `crates/infra/withdrawer/src/journal.rs`), as a
//! pure codec over bytes so a crashed run resumes without double-sending. The binary appends
//! a `broadcast` record (with the signed transaction's hash) before every
//! `eth_sendRawTransaction`, and `confirmed` or `failed` once the step settles; on restart it
//! replays the file and checks the receipts of pending hashes before sending anything new.
//!
//! Records are fixed-size with a CRC32, so a write torn by a crash is detected: a short or
//! corrupt final record is dropped (`Replay.valid_length` tells the binary where to
//! truncate), while corruption before the tail is an error. File IO stays in the binary.

const std = @import("std");
const assert = std.debug.assert;

const Hash = [32]u8;

pub const magic: u32 = 0x4e46_574a; // "NFWJ"
pub const version: u8 = 1;
pub const record_bytes = 92;
/// Broadcast hashes remembered per step (each fee bump re-signs and adds one).
pub const hashes_max = 32;

pub const Step = enum(u8) { initiate = 1, prove = 2, finalize = 3 };
pub const Event = enum(u8) { broadcast = 1, confirmed = 2, failed = 3 };

pub const Record = struct {
    step: Step,
    event: Event,
    /// The L2 initiating transaction (initiate) or the withdrawal hash (prove, finalize).
    subject: Hash,
    /// The broadcast or confirmed transaction.
    transaction: Hash,
    nonce: u64 = 0,
    /// The inclusion block of a confirmed transaction, else 0.
    block_number: u64 = 0,
};

comptime {
    assert(record_bytes == 4 + 4 + 8 + 8 + 32 + 32 + 4);
    assert(hashes_max >= 2);
}

pub fn encode(record: Record, out: *[record_bytes]u8) void {
    std.mem.writeInt(u32, out[0..4], magic, .little);
    out[4] = version;
    out[5] = @backingInt(record.step);
    out[6] = @backingInt(record.event);
    out[7] = 0;
    std.mem.writeInt(u64, out[8..16], record.nonce, .little);
    std.mem.writeInt(u64, out[16..24], record.block_number, .little);
    out[24..56].* = record.subject;
    out[56..88].* = record.transaction;
    std.mem.writeInt(u32, out[88..92], std.hash.Crc32.hash(out[0..88]), .little);
    assert(std.meta.eql(decode(out) catch unreachable, record)); // Just encoded.
}

pub const DecodeError = error{ Corrupt, UnknownVersion };

pub fn decode(bytes: *const [record_bytes]u8) DecodeError!Record {
    const checksum = std.mem.readInt(u32, bytes[88..92], .little);
    if (checksum != std.hash.Crc32.hash(bytes[0..88])) return error.Corrupt;
    if (std.mem.readInt(u32, bytes[0..4], .little) != magic) return error.Corrupt;
    if (bytes[4] != version) return error.UnknownVersion;
    if (bytes[7] != 0) return error.Corrupt;
    const step = std.enums.fromInt(Step, bytes[5]) orelse return error.Corrupt;
    const event = std.enums.fromInt(Event, bytes[6]) orelse return error.Corrupt;
    const record: Record = .{
        .step = step,
        .event = event,
        .nonce = std.mem.readInt(u64, bytes[8..16], .little),
        .block_number = std.mem.readInt(u64, bytes[16..24], .little),
        .subject = bytes[24..56].*,
        .transaction = bytes[56..88].*,
    };
    assert(@backingInt(record.step) == bytes[5]);
    return record;
}

/// What the journal says about one step.
pub const StepState = struct {
    subject: Hash = @splat(0),
    /// Distinct broadcast hashes since the step last settled, in broadcast order.
    hashes: [hashes_max]Hash = undefined,
    hash_count: u32 = 0,
    confirmed: ?struct { transaction: Hash, block_number: u64 } = null,
    failed: bool = false,

    /// Broadcast hashes not yet settled: check their receipts before sending again.
    pub fn pending(state: *const StepState) []const Hash {
        assert(state.hash_count <= hashes_max);
        if (state.confirmed != null) return &.{};
        return state.hashes[0..state.hash_count];
    }

    fn add(state: *StepState, hash: Hash) void {
        for (state.hashes[0..state.hash_count]) |known| {
            if (std.mem.eql(u8, &known, &hash)) return;
        }
        if (state.hash_count == hashes_max) {
            // Keep the newest: older versions were replaced by fee bumps.
            std.mem.copyForwards(Hash, state.hashes[0 .. hashes_max - 1], state.hashes[1..]);
            state.hash_count -= 1;
        }
        state.hashes[state.hash_count] = hash;
        state.hash_count += 1;
        assert(state.hash_count <= hashes_max);
    }
};

pub const Replay = struct {
    steps: [3]StepState = @splat(.{}),
    records: u64 = 0,
    /// Bytes of whole, valid records; the binary truncates the file here.
    valid_length: u64 = 0,
    torn_tail: bool = false,

    pub fn step(state: *const Replay, which: Step) *const StepState {
        return &state.steps[@backingInt(which) - 1];
    }

    /// Applies one record. A new subject for a step starts that step over.
    pub fn apply(journal: *Replay, record: Record) void {
        const state = &journal.steps[@backingInt(record.step) - 1];
        if (!std.mem.eql(u8, &state.subject, &record.subject)) {
            state.* = .{ .subject = record.subject };
        }
        switch (record.event) {
            .broadcast => {
                // A new broadcast after a failure is a retry of the same step.
                if (state.failed or state.confirmed != null) {
                    state.* = .{ .subject = record.subject };
                }
                state.add(record.transaction);
            },
            .confirmed => {
                state.confirmed = .{
                    .transaction = record.transaction,
                    .block_number = record.block_number,
                };
                state.failed = false;
            },
            .failed => {
                state.failed = true;
                state.hash_count = 0;
            },
        }
        journal.records += 1;
        assert(std.mem.eql(u8, &state.subject, &record.subject));
    }
};

/// Replays a whole journal file.
pub fn replay(bytes: []const u8) DecodeError!Replay {
    var result: Replay = .{};
    const whole = bytes.len / record_bytes;
    for (0..whole) |index| {
        const chunk = bytes[index * record_bytes ..][0..record_bytes];
        const record = decode(chunk) catch |err| {
            // Only the last record may be torn by a crash mid-write.
            if (err == error.Corrupt and index + 1 == whole) {
                result.torn_tail = true;
                break;
            }
            return err;
        };
        result.apply(record);
        result.valid_length += record_bytes;
    }
    if (bytes.len % record_bytes != 0) result.torn_tail = true;
    assert(result.valid_length <= bytes.len);
    assert(result.valid_length % record_bytes == 0);
    return result;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

fn sample(step: Step, event: Event, transaction: u8) Record {
    return .{
        .step = step,
        .event = event,
        .subject = @splat(0xaa),
        .transaction = @splat(transaction),
        .nonce = 7,
        .block_number = if (event == .confirmed) 99 else 0,
    };
}

test "journal: records round trip and resume pending broadcasts" {
    var file: [6 * record_bytes]u8 = undefined;
    const records = [_]Record{
        sample(.prove, .broadcast, 1),
        sample(.prove, .broadcast, 2),
        sample(.prove, .broadcast, 2),
        sample(.prove, .confirmed, 2),
        sample(.finalize, .broadcast, 3),
        sample(.finalize, .broadcast, 4),
    };
    for (records, 0..) |record, index| {
        encode(record, file[index * record_bytes ..][0..record_bytes]);
    }
    const result = try replay(&file);
    try testing.expectEqual(@as(u64, 6), result.records);
    try testing.expect(!result.torn_tail);
    const prove = result.step(.prove);
    try testing.expectEqual(@as(usize, 0), prove.pending().len);
    try testing.expectEqual(@as(u64, 99), prove.confirmed.?.block_number);
    const finalize = result.step(.finalize);
    try testing.expectEqual(@as(usize, 2), finalize.pending().len);
    try testing.expectEqual(@as(u8, 4), finalize.pending()[1][0]);
    try testing.expectEqual(@as(usize, 0), result.step(.initiate).pending().len);
}

test "journal: a torn tail is dropped, earlier corruption is an error" {
    var file: [3 * record_bytes]u8 = undefined;
    for (0..3) |index| {
        const record = sample(.prove, .broadcast, @intCast(index));
        encode(record, file[index * record_bytes ..][0..record_bytes]);
    }
    const partial = try replay(file[0 .. 2 * record_bytes + 40]);
    try testing.expect(partial.torn_tail);
    try testing.expectEqual(@as(u64, 2 * record_bytes), partial.valid_length);
    var torn = file;
    torn[2 * record_bytes + 50] ^= 1;
    const last = try replay(&torn);
    try testing.expect(last.torn_tail);
    try testing.expectEqual(@as(usize, 2), last.step(.prove).pending().len);
    var corrupt = file;
    corrupt[10] ^= 1;
    try testing.expectError(error.Corrupt, replay(&corrupt));
    var future = file;
    future[4] = 2;
    std.mem.writeInt(u32, future[88..92], std.hash.Crc32.hash(future[0..88]), .little);
    try testing.expectError(error.UnknownVersion, replay(&future));
}

test "journal: failures and new subjects start a step over" {
    var result: Replay = .{};
    result.apply(sample(.prove, .broadcast, 1));
    result.apply(sample(.prove, .failed, 1));
    try testing.expectEqual(@as(usize, 0), result.step(.prove).pending().len);
    try testing.expect(result.step(.prove).failed);
    result.apply(sample(.prove, .broadcast, 2));
    try testing.expect(!result.step(.prove).failed);
    try testing.expectEqual(@as(usize, 1), result.step(.prove).pending().len);
    var other = sample(.prove, .broadcast, 3);
    other.subject = @splat(0xbb);
    result.apply(other);
    try testing.expectEqual(@as(u8, 3), result.step(.prove).pending()[0][0]);
    try testing.expectEqual(@as(usize, 1), result.step(.prove).pending().len);
}

test "journal: seeded bumps keep the newest hashes" {
    var prng = Prng.init(0x10_7e);
    var result: Replay = .{};
    const total = hashes_max + prng.range(1, 40);
    for (0..total) |index| {
        var record = sample(.finalize, .broadcast, 0);
        std.mem.writeInt(u64, record.transaction[0..8], index, .little);
        result.apply(record);
    }
    const pending = result.step(.finalize).pending();
    try testing.expectEqual(@as(usize, hashes_max), pending.len);
    const newest = std.mem.readInt(u64, pending[hashes_max - 1][0..8], .little);
    try testing.expectEqual(total - 1, newest);
}

fn fuzz_replay(_: void, bytes: []const u8) anyerror!void {
    // Arbitrary files replay or fail cleanly; replays never claim more than they read.
    const result = replay(bytes) catch return;
    try testing.expect(result.valid_length <= bytes.len);
    try testing.expectEqual(result.records * record_bytes, result.valid_length);
}

test "journal: fuzz replay" {
    try fuzz.run_bytes({}, fuzz_replay, .{ .iterations = 1024 });
}

fn fuzz_round_trip(_: void, smith: *std.testing.Smith) anyerror!void {
    const record: Record = .{
        .step = smith.value(Step),
        .event = smith.value(Event),
        .subject = smith.value(Hash),
        .transaction = smith.value(Hash),
        .nonce = smith.value(u64),
        .block_number = smith.value(u64),
    };
    var bytes: [record_bytes]u8 = undefined;
    encode(record, &bytes);
    try testing.expectEqual(record, try decode(&bytes));
    bytes[smith.valueRangeAtMost(u8, 0, record_bytes - 1)] ^= smith.valueRangeAtMost(u8, 1, 255);
    // Any single corrupted byte is detected.
    if (decode(&bytes)) |_| return error.TestUnexpectedResult else |_| {}
}

test "journal: fuzz record round trip" {
    try fuzz.run({}, fuzz_round_trip, .{ .iterations = 1024 });
}

//! Superblock: the root of all durable state, stored in four copies at sectors 0..3.
//!
//! The superblock names the latest checkpoint (zone, size, checksum) and the journal position
//! where replay starts. It also names the previous checkpoint and its journal start: the
//! journal keeps every entry from that older start, so if the newest checkpoint rots, open
//! falls back to the previous checkpoint and replays the longer journal.
//!
//! Updating the superblock is the engine's only atomic commit point for checkpoints: copies
//! are written one at a time with a sync after each, so a crash or torn write damages at
//! most the copy in flight. Open reads all copies and picks the highest sequence with a
//! valid checksum; copies sharing a sequence must agree byte for byte.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const checksum_module = @import("checksum.zig");

const sector_size = storage.sector_size;

/// "nfsuperb" read as a little-endian u64.
pub const magic: u64 = 0x6272_6570_7573_666e;
pub const version: u32 = 2;
pub const copy_count: u32 = 4;
pub const commit_metadata_size: u32 = 128;
pub const zone_size_bytes: u64 = copy_count * sector_size;

/// Where journal replay starts: the first entry not covered by the checkpoint.
pub const JournalStart = extern struct {
    /// Header checksum of the entry before `sequence` (the hash chain anchor).
    previous_checksum: u128,
    /// Offset of the entry within the journal zone. The entry may instead sit at the zone
    /// start if it did not fit before the zone end.
    offset: u64,
    sequence: u64,
};

/// The latest complete checkpoint. `sequence == 0` means there is none yet.
pub const Checkpoint = extern struct {
    checksum: u128 = 0,
    size_bytes: u64 = 0,
    sequence: u64 = 0,
    zone: u8 = 0,
    reserved: [15]u8 = @splat(0),
};

/// The on-disk layout, checked at open so a misconfigured engine cannot misread a file.
pub const Layout = extern struct {
    checkpoint_zone_size_bytes: u64,
    journal_size_bytes: u64,
    checkpoint_block_size: u32,
    entry_body_size_max: u32,
    reserved: u64 = 0,
};

const header_size = 16 + 16 + 8 + 4 + 4 + 8 + 8 + 2 * @sizeOf(JournalStart) +
    2 * @sizeOf(Checkpoint) + @sizeOf(Layout) + 2 * commit_metadata_size;

pub const SuperBlock = extern struct {
    /// Checksum of every byte after this field.
    checksum: u128,
    /// Chosen at format; journal entries and checkpoint blocks carry it, so leftovers from a
    /// previous format of the same file are never mistaken for live data.
    format_id: u128,
    magic: u64,
    version: u32,
    reserved_a: u32,
    sequence: u64,
    reserved_b: u64,
    journal_start: JournalStart,
    checkpoint: Checkpoint,
    /// The fallback: the checkpoint before `checkpoint` and the journal start that goes with
    /// it. Equal to `journal_start`/`checkpoint` (byte for byte) when there is no distinct
    /// fallback, for example right after format or after open fell back. A previous
    /// checkpoint with `sequence == 0` is the empty state at format.
    journal_start_previous: JournalStart,
    checkpoint_previous: Checkpoint,
    layout: Layout,
    /// Opaque to the engine: the caller's description of the checkpointed state (for example
    /// block number, block hash, state root).
    commit_metadata: [commit_metadata_size]u8,
    /// The caller's description of the state of `checkpoint_previous`.
    commit_metadata_previous: [commit_metadata_size]u8,
    reserved: [sector_size - header_size]u8,

    pub fn compute_checksum(superblock: *const SuperBlock) u128 {
        return checksum_module.checksum(std.mem.asBytes(superblock)[@sizeOf(u128)..]);
    }

    pub fn seal(superblock: *SuperBlock) void {
        superblock.seal_unchecked();
        assert(superblock.valid());
    }

    /// Seals without asserting validity (for tests that build invalid superblocks).
    pub fn seal_unchecked(superblock: *SuperBlock) void {
        superblock.magic = magic;
        superblock.version = version;
        superblock.checksum = superblock.compute_checksum();
        assert(superblock.checksum == superblock.compute_checksum());
    }

    /// Checksum, constants, reserved bytes, and field ranges. Never trusts an unverified byte.
    pub fn valid(superblock: *const SuperBlock) bool {
        if (superblock.checksum != superblock.compute_checksum()) return false;
        if (superblock.magic != magic or superblock.version != version) return false;
        if (superblock.reserved_a != 0 or superblock.reserved_b != 0) return false;
        if (!all_zero(&superblock.reserved)) return false;
        if (!all_zero(&superblock.checkpoint.reserved)) return false;
        if (superblock.layout.reserved != 0) return false;
        if (superblock.sequence == 0) return false;
        if (superblock.journal_start.sequence == 0) return false;
        if (superblock.journal_start.offset % sector_size != 0) return false;
        if (superblock.journal_start.offset >= superblock.layout.journal_size_bytes) return false;
        if (superblock.checkpoint.zone > 1) return false;
        if (superblock.checkpoint.sequence == 0 and superblock.checkpoint.size_bytes != 0) {
            return false;
        }
        return superblock.previous_valid();
    }

    /// True when a distinct, older checkpoint is named as the fallback.
    pub fn has_fallback(superblock: *const SuperBlock) bool {
        assert(superblock.checkpoint_previous.sequence <= superblock.checkpoint.sequence);
        return superblock.checkpoint_previous.sequence < superblock.checkpoint.sequence;
    }

    fn previous_valid(superblock: *const SuperBlock) bool {
        const current = &superblock.checkpoint;
        const previous = &superblock.checkpoint_previous;
        const start = &superblock.journal_start;
        const start_previous = &superblock.journal_start_previous;
        if (!all_zero(&previous.reserved)) return false;
        if (previous.zone > 1) return false;
        if (previous.sequence == 0 and previous.size_bytes != 0) return false;
        if (previous.sequence > current.sequence) return false;
        if (start_previous.sequence == 0) return false;
        if (start_previous.offset % sector_size != 0) return false;
        if (start_previous.offset >= superblock.layout.journal_size_bytes) return false;
        if (start_previous.sequence > start.sequence) return false;
        if (start_previous.sequence == start.sequence) {
            // No entries between the two starts: the same journal position.
            if (start_previous.offset != start.offset) return false;
            if (start_previous.previous_checksum != start.previous_checksum) return false;
        }
        if (previous.sequence == current.sequence) {
            // No distinct fallback: both references name the same checkpoint.
            if (!std.mem.eql(u8, std.mem.asBytes(previous), std.mem.asBytes(current))) {
                return false;
            }
            if (start_previous.sequence != start.sequence) return false;
            const metadata_equal = std.mem.eql(
                u8,
                &superblock.commit_metadata,
                &superblock.commit_metadata_previous,
            );
            return metadata_equal;
        }
        // A real previous checkpoint lives in the other zone (the empty one has no zone).
        if (previous.sequence > 0 and previous.zone == current.zone) return false;
        return true;
    }
};

comptime {
    assert(@sizeOf(SuperBlock) == sector_size);
    assert(@sizeOf(JournalStart) == 32);
    assert(@sizeOf(Checkpoint) == 48);
    assert(@sizeOf(Layout) == 32);
    assert(header_size == 512);
    assert(header_size % 16 == 0);
    assert(@offsetOf(SuperBlock, "reserved") == header_size);
}

fn all_zero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// A zeroed superblock, the starting point for building one.
pub fn zero() SuperBlock {
    return std.mem.zeroes(SuperBlock);
}

/// Decodes one sector; null unless every check passes.
pub fn decode(sector: []const u8) ?SuperBlock {
    assert(sector.len == sector_size);
    var superblock: SuperBlock = undefined;
    @memcpy(std.mem.asBytes(&superblock), sector);
    if (!superblock.valid()) return null;
    assert(superblock.sequence > 0);
    return superblock;
}

pub const Selection = struct {
    pub const Status = enum { ok, missing, conflict };

    status: Status,
    superblock: ?SuperBlock,
    copies_valid: u32,
    /// Copies byte-identical to the chosen one. Fewer than `copy_count` calls for repair.
    copies_current: u32,
};

/// Picks the newest valid copy out of `copy_count` consecutive sectors.
pub fn select(copies: []const u8) Selection {
    assert(copies.len == copy_count * sector_size);
    var chosen: ?u32 = null;
    var chosen_sequence: u64 = 0;
    var copies_valid: u32 = 0;
    for (0..copy_count) |index| {
        const candidate = decode(copy_sector(copies, @intCast(index))) orelse continue;
        copies_valid += 1;
        if (candidate.sequence > chosen_sequence) {
            chosen = @intCast(index);
            chosen_sequence = candidate.sequence;
        }
    }
    const index = chosen orelse return .{
        .status = .missing,
        .superblock = null,
        .copies_valid = 0,
        .copies_current = 0,
    };
    assert(copies_valid > 0);
    const chosen_bytes = copy_sector(copies, index);
    var copies_current: u32 = 0;
    for (0..copy_count) |other| {
        const bytes = copy_sector(copies, @intCast(other));
        if (std.mem.eql(u8, bytes, chosen_bytes)) {
            copies_current += 1;
            continue;
        }
        const candidate = decode(bytes) orelse continue;
        // Two different valid copies with the same sequence: the file is not ours to fix.
        if (candidate.sequence == chosen_sequence) {
            return .{
                .status = .conflict,
                .superblock = null,
                .copies_valid = copies_valid,
                .copies_current = 0,
            };
        }
    }
    assert(copies_current >= 1);
    return .{
        .status = .ok,
        .superblock = decode(chosen_bytes).?,
        .copies_valid = copies_valid,
        .copies_current = copies_current,
    };
}

fn copy_sector(copies: []const u8, index: u32) []const u8 {
    assert(index < copy_count);
    return copies[@as(usize, index) * sector_size ..][0..sector_size];
}

/// Asynchronous reader and writer of the four copies.
pub fn SuperBlockType(comptime Storage: type) type {
    storage.assert_interface(Storage);
    return struct {
        const Self = @This();

        pub const Callback = *const fn (*Self) void;
        /// Reads that do not show four identical valid copies are retried, so a transient read
        /// fault neither hides the newest copy nor triggers a needless repair.
        pub const read_attempts_max: u32 = 4;
        pub const State = enum { idle, reading, writing, syncing };

        storage: *Storage,
        buffer: []align(sector_size) u8,
        /// The newest superblock known durable (chosen at open, or last fully written).
        working: SuperBlock,
        /// The superblock being written.
        staging: SuperBlock,
        selection: Selection,
        state: State = .idle,
        callback: ?Callback = null,
        copy: u32 = 0,
        read_attempts: u32 = 0,
        read: storage.Read = .{},
        write: storage.Write = .{},
        sync: storage.Sync = .{},

        pub fn init(allocator: std.mem.Allocator, storage_: *Storage) !Self {
            assert(storage_.size_bytes() >= zone_size_bytes);
            const buffer = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                copy_count * sector_size,
            );
            @memset(buffer, 0);
            return .{
                .storage = storage_,
                .buffer = buffer,
                .working = zero(),
                .staging = zero(),
                .selection = .{
                    .status = .missing,
                    .superblock = null,
                    .copies_valid = 0,
                    .copies_current = 0,
                },
            };
        }

        /// May run with an operation in flight: after a simulated crash the storage has
        /// dropped it and will never call back.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(self.buffer.len > 0);
            allocator.free(self.buffer);
            self.* = undefined;
        }

        /// Reads every copy; on completion `selection` holds the result and, if it is `ok`,
        /// `working` holds the chosen superblock.
        pub fn open(self: *Self, callback: Callback) void {
            assert(self.state == .idle);
            assert(self.callback == null);
            self.state = .reading;
            self.callback = callback;
            self.read_attempts = 0;
            self.read_copies();
        }

        /// Durably replaces the superblock with `superblock` at sequence `working.sequence + 1`.
        /// `checksum`, `magic`, `version`, and `sequence` are filled in here.
        pub fn write_superblock(self: *Self, superblock: SuperBlock, callback: Callback) void {
            assert(self.state == .idle);
            assert(self.callback == null);
            self.staging = superblock;
            self.staging.sequence = self.working.sequence + 1;
            self.staging.seal();
            @memcpy(self.buffer[0..sector_size], std.mem.asBytes(&self.staging));
            self.state = .writing;
            self.callback = callback;
            self.copy = 0;
            self.write_copy();
        }

        fn read_copies(self: *Self) void {
            assert(self.state == .reading);
            self.read_attempts += 1;
            self.storage.read_sectors(on_read, &self.read, self.buffer, 0);
        }

        fn on_read(read: *storage.Read) void {
            const self: *Self = @alignCast(@fieldParentPtr("read", read));
            assert(self.state == .reading);
            self.selection = select(self.buffer);
            const retry = self.selection.copies_current < copy_count and
                self.read_attempts < read_attempts_max;
            if (retry) return self.read_copies();
            if (self.selection.status == .ok) self.working = self.selection.superblock.?;
            self.finish();
        }

        fn write_copy(self: *Self) void {
            assert(self.state == .writing);
            assert(self.copy < copy_count);
            self.storage.write_sectors(
                on_write,
                &self.write,
                self.buffer[0..sector_size],
                @as(u64, self.copy) * sector_size,
            );
        }

        fn on_write(write: *storage.Write) void {
            const self: *Self = @alignCast(@fieldParentPtr("write", write));
            assert(self.state == .writing);
            self.state = .syncing;
            self.storage.sync(on_sync, &self.sync);
        }

        fn on_sync(sync: *storage.Sync) void {
            const self: *Self = @alignCast(@fieldParentPtr("sync", sync));
            assert(self.state == .syncing);
            self.copy += 1;
            self.state = .writing;
            if (self.copy < copy_count) return self.write_copy();
            self.working = self.staging;
            self.finish();
        }

        fn finish(self: *Self) void {
            assert(self.state != .idle);
            const callback = self.callback.?;
            self.state = .idle;
            self.callback = null;
            callback(self);
        }
    };
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

fn sample(prng: *Prng, sequence: u64) SuperBlock {
    var superblock = zero();
    superblock.format_id = prng.int(u128);
    superblock.sequence = sequence;
    superblock.journal_start = .{ .previous_checksum = prng.int(u128), .offset = 0, .sequence = 1 };
    superblock.checkpoint = .{
        .checksum = prng.int(u128),
        .size_bytes = 7,
        .sequence = 3,
        .zone = 1,
    };
    superblock.journal_start_previous = superblock.journal_start;
    superblock.checkpoint_previous = .{
        .checksum = prng.int(u128),
        .size_bytes = 5,
        .sequence = 2,
        .zone = 0,
    };
    prng.fill(&superblock.commit_metadata_previous);
    superblock.layout = .{
        .checkpoint_zone_size_bytes = 1 << 20,
        .journal_size_bytes = 1 << 20,
        .checkpoint_block_size = 1 << 16,
        .entry_body_size_max = 1 << 12,
    };
    prng.fill(&superblock.commit_metadata);
    superblock.seal();
    return superblock;
}

test "superblock: seal, decode, reject every single bit flip in a sample" {
    var prng = Prng.init(1);
    const superblock = sample(&prng, 5);
    const decoded = decode(std.mem.asBytes(&superblock)).?;
    try testing.expectEqualSlices(u8, std.mem.asBytes(&superblock), std.mem.asBytes(&decoded));
    for (0..512) |_| {
        var bytes = std.mem.toBytes(superblock);
        const bit = prng.below(sector_size * 8);
        bytes[@intCast(bit / 8)] ^= @as(u8, 1) << @intCast(bit % 8);
        try testing.expect(decode(&bytes) == null);
    }
    const zeroes: [sector_size]u8 = @splat(0);
    try testing.expect(decode(&zeroes) == null);
}

test "superblock: select newest, count current copies, detect conflict" {
    var prng = Prng.init(2);
    var copies: [copy_count * sector_size]u8 = @splat(0);
    try testing.expectEqual(Selection.Status.missing, select(&copies).status);
    const old = sample(&prng, 4);
    const new = sample(&prng, 5);
    for (0..copy_count) |index| {
        const source = if (index == 0) &new else &old;
        @memcpy(copies[index * sector_size ..][0..sector_size], std.mem.asBytes(source));
    }
    var selection = select(&copies);
    try testing.expectEqual(Selection.Status.ok, selection.status);
    try testing.expectEqual(@as(u64, 5), selection.superblock.?.sequence);
    try testing.expectEqual(@as(u32, 1), selection.copies_current);
    try testing.expectEqual(@as(u32, 4), selection.copies_valid);

    copies[10] ^= 1; // the newest copy rots: fall back to the older ones
    selection = select(&copies);
    try testing.expectEqual(@as(u64, 4), selection.superblock.?.sequence);
    try testing.expectEqual(@as(u32, 3), selection.copies_current);

    const rival = sample(&prng, 4);
    @memcpy(copies[sector_size..][0..sector_size], std.mem.asBytes(&rival));
    try testing.expectEqual(Selection.Status.conflict, select(&copies).status);
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    var sector: [sector_size]u8 = @splat(0);
    @memcpy(sector[0..@min(input.len, sector_size)], input[0..@min(input.len, sector_size)]);
    // Arbitrary bytes never pass: forging a 128-bit checksum is out of reach.
    try testing.expect(decode(&sector) == null);
    var copies: [copy_count * sector_size]u8 = @splat(0);
    @memcpy(copies[0..sector_size], &sector);
    try testing.expectEqual(Selection.Status.missing, select(&copies).status);
}

test "superblock: fuzz decode arbitrary bytes" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .iterations = 128, .input_size_max = sector_size });
}

test "superblock: seeded mutations of valid copies are rejected or decode to the original" {
    var prng = Prng.init(3);
    for (0..256) |_| {
        const superblock = sample(&prng, prng.range(1, 100));
        var bytes = std.mem.toBytes(superblock);
        const flips = prng.range(0, 3);
        for (0..flips) |_| bytes[@intCast(prng.below(sector_size))] ^= prng.int(u8) | 1;
        if (decode(&bytes)) |decoded| {
            const original = std.mem.asBytes(&superblock);
            try testing.expectEqualSlices(u8, original, std.mem.asBytes(&decoded));
        }
    }
}

/// Draws a value from a few boundary cases or at random.
fn pick(prng: *Prng, comptime T: type, cases: []const T) T {
    if (prng.chance(1, 4)) return prng.int(T);
    return cases[@intCast(prng.below(cases.len))];
}

/// Random fallback fields around the current ones, valid or not.
fn sample_previous(prng: *Prng, superblock: *SuperBlock) void {
    const current = superblock.checkpoint;
    const start = superblock.journal_start;
    const journal_size = superblock.layout.journal_size_bytes;
    if (prng.chance(1, 4)) {
        superblock.checkpoint_previous = current;
        superblock.journal_start_previous = start;
        superblock.commit_metadata_previous = superblock.commit_metadata;
    } else {
        superblock.checkpoint_previous = .{
            .checksum = prng.int(u128),
            .size_bytes = pick(prng, u64, &.{ 0, 1, current.size_bytes }),
            .sequence = pick(prng, u64, &.{ 0, 1, current.sequence - 1, current.sequence }),
            .zone = pick(prng, u8, &.{ 0, 1, 2 }),
        };
        superblock.journal_start_previous = .{
            .previous_checksum = pick(prng, u128, &.{start.previous_checksum}),
            .offset = pick(prng, u64, &.{ 0, sector_size, start.offset, journal_size, 1 }),
            .sequence = pick(prng, u64, &.{ 0, 1, start.sequence, start.sequence + 1 }),
        };
    }
    if (prng.chance(1, 8)) superblock.checkpoint_previous.reserved[prng.below(15)] = 1;
    if (prng.chance(1, 8)) superblock.commit_metadata_previous[0] ^= 1;
}

/// The fallback rules, restated: a decoded superblock must satisfy every one.
fn expect_previous_consistent(superblock: *const SuperBlock) !void {
    const current = superblock.checkpoint;
    const previous = superblock.checkpoint_previous;
    const start = superblock.journal_start;
    const start_previous = superblock.journal_start_previous;
    try testing.expect(previous.sequence <= current.sequence);
    try testing.expect(previous.zone <= 1);
    try testing.expect(previous.sequence > 0 or previous.size_bytes == 0);
    try testing.expect(start_previous.sequence >= 1);
    try testing.expect(start_previous.sequence <= start.sequence);
    try testing.expect(start_previous.offset < superblock.layout.journal_size_bytes);
    try testing.expectEqual(@as(u64, 0), start_previous.offset % sector_size);
    if (start_previous.sequence == start.sequence) {
        try testing.expectEqual(start.offset, start_previous.offset);
        try testing.expectEqual(start.previous_checksum, start_previous.previous_checksum);
    }
    if (superblock.has_fallback()) {
        try testing.expect(previous.sequence == 0 or previous.zone != current.zone);
    } else {
        try testing.expectEqualSlices(u8, std.mem.asBytes(&current), std.mem.asBytes(&previous));
        try testing.expectEqual(start.sequence, start_previous.sequence);
        try testing.expectEqualSlices(
            u8,
            &superblock.commit_metadata,
            &superblock.commit_metadata_previous,
        );
    }
}

test "superblock: seeded fuzz of the fallback fields" {
    var prng = Prng.init(5);
    var accepted: u32 = 0;
    var rejected: u32 = 0;
    for (0..4096) |_| {
        var superblock = sample(&prng, prng.range(1, 100));
        superblock.journal_start.sequence = prng.range(1, 4);
        superblock.journal_start.offset = sector_size * prng.range(0, 3);
        sample_previous(&prng, &superblock);
        superblock.seal_unchecked();
        if (decode(std.mem.asBytes(&superblock))) |decoded| {
            accepted += 1;
            try expect_previous_consistent(&decoded);
        } else rejected += 1;
    }
    // Both outcomes are exercised.
    try testing.expect(accepted > 256);
    try testing.expect(rejected > 256);
}

const SimStorage = @import("sim_storage.zig").SimStorage;

const TestSuperBlock = struct {
    superblock: SuperBlockType(SimStorage),
    done: bool = false,

    fn on_done(superblock: *SuperBlockType(SimStorage)) void {
        const self: *TestSuperBlock = @alignCast(@fieldParentPtr("superblock", superblock));
        assert(!self.done);
        self.done = true;
    }

    fn run(self: *TestSuperBlock, sim: *SimStorage, ticks_max: u32) bool {
        var ticks: u32 = 0;
        while (!self.done and ticks < ticks_max) : (ticks += 1) sim.tick();
        return self.done;
    }
};

test "superblock: crash during write leaves the old or the new superblock" {
    var prng = Prng.init(4);
    for (0..64) |seed| {
        var sim = try SimStorage.init(testing.allocator, .{
            .size_bytes = zone_size_bytes,
            .seed = seed,
        });
        defer sim.deinit(testing.allocator);
        var harness: TestSuperBlock = .{ .superblock = try .init(testing.allocator, &sim) };
        defer harness.superblock.deinit(testing.allocator);
        const first = sample(&prng, 1);
        harness.superblock.write_superblock(first, TestSuperBlock.on_done);
        try testing.expect(harness.run(&sim, 1000));

        harness.done = false;
        const second = sample(&prng, 1);
        harness.superblock.write_superblock(second, TestSuperBlock.on_done);
        const finished = harness.run(&sim, @intCast(prng.range(1, 40)));
        sim.crash();
        if (!finished) harness.superblock.state = .idle; // the crash dropped the operation
        harness.superblock.callback = null;

        harness.done = false;
        harness.superblock.open(TestSuperBlock.on_done);
        try testing.expect(harness.run(&sim, 1000));
        const selection = harness.superblock.selection;
        try testing.expectEqual(Selection.Status.ok, selection.status);
        const sequence = selection.superblock.?.sequence;
        try testing.expect(sequence == 1 or sequence == 2);
        if (finished) try testing.expectEqual(@as(u64, 2), sequence);
        const expected = if (sequence == 1) first.format_id else second.format_id;
        try testing.expectEqual(expected, selection.superblock.?.format_id);
    }
}

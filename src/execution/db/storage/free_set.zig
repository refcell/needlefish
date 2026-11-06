//! Free set: which grid blocks are in use, and when a released block may be reused.
//!
//! One bit per grid block in each of four bitsets, allocated once from the block count:
//! - `acquired`: the block holds data some state may reference (live or awaiting reuse).
//! - `released_new`: released since the last checkpoint snapshot. The newest durable
//!   checkpoint may reference it.
//! - `released_old`: released between the two latest snapshots. The newest checkpoint no
//!   longer references it, but the fallback checkpoint may.
//! - `released_freeing`: released before the snapshot of the checkpoint being written. Once
//!   that checkpoint is durable, neither the newest nor the fallback references it.
//!
//! Lifecycle, driven by the engine's checkpoint protocol:
//! - `checkpoint_begin` (the snapshot point of checkpoint K) encodes the image K records
//!   (`acquired` minus `released_old`, plus `released_new` as K's pending releases) and
//!   shifts: freeing <- old, old <- new, new <- {}.
//! - `checkpoint_durable` (K's superblock is on every copy) frees `released_freeing`.
//! - `checkpoint_abort` (K failed) undoes the shift, merging the sets later, never earlier.
//! - `decode` (open from K's image) restores `acquired` and puts K's pending releases in
//!   `released_old`, so they free when the next checkpoint is durable.
//!
//! So a block released after checkpoint N's snapshot is reusable only after two more
//! checkpoints are durable, the first point at which neither the newest nor the fallback
//! checkpoint can reference it. Reuse is the lowest free address (deterministic).
//!
//! Reservations: `reserve(count)` sets aside free blocks so a multi-block write (a table
//! flush) never runs out halfway; `acquire` hands them out in address order and `forfeit`
//! returns the unused ones. One reservation at a time.
//!
//! Addresses are 1-based (block index + 1) so 0 means "no block".

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{ NoSpace, InvalidFreeSet };

pub const Reservation = struct {
    /// First address of the reserved run, and how many free blocks it holds.
    address_first: u64,
    count: u64,
    /// Blocks handed out so far.
    acquired: u64 = 0,
};

const Set = enum { acquired, released_new, released_old, released_freeing };
const set_count = 4;

comptime {
    assert(@backingInt(Set.released_freeing) == set_count - 1);
}

pub const FreeSet = struct {
    block_count: u64,
    word_count: usize,
    /// `set_count` bitsets of `word_count` words, one allocation.
    words: []u64,
    /// The reservation in progress: blocks at or above `reservation_cursor` and below
    /// `reservation_end` may be acquired from it.
    reservation_cursor: u64 = 0,
    reservation_end: u64 = 0,
    reservation_left: u64 = 0,
    reserved: bool = false,
    /// A checkpoint began and is neither durable nor aborted.
    checkpointing: bool = false,

    pub fn init(allocator: std.mem.Allocator, block_count: u64) !FreeSet {
        assert(block_count > 0);
        const word_count: usize = @intCast(std.math.divCeil(u64, block_count, 64) catch
            unreachable); // Divisor is non-zero.
        const words = try allocator.alloc(u64, word_count * set_count);
        @memset(words, 0);
        var free_set: FreeSet = .{
            .block_count = block_count,
            .word_count = word_count,
            .words = words,
        };
        free_set.assert_invariants();
        return free_set;
    }

    pub fn deinit(self: *FreeSet, allocator: std.mem.Allocator) void {
        assert(self.words.len == self.word_count * set_count);
        allocator.free(self.words);
        self.* = undefined;
    }

    /// Every block free, nothing pending (an empty grid).
    pub fn reset(self: *FreeSet) void {
        @memset(self.words, 0);
        self.reserved = false;
        self.checkpointing = false;
        self.reservation_left = 0;
        self.assert_invariants();
    }

    fn set(self: *const FreeSet, comptime which: Set) []u64 {
        const index = @backingInt(which);
        return self.words[index * self.word_count ..][0..self.word_count];
    }

    fn bit(words: []const u64, address: u64) bool {
        const index = address - 1;
        return words[@intCast(index / 64)] & (@as(u64, 1) << @intCast(index % 64)) != 0;
    }

    fn bit_set(words: []u64, address: u64, value: bool) void {
        const index = address - 1;
        const mask = @as(u64, 1) << @intCast(index % 64);
        if (value) words[@intCast(index / 64)] |= mask else words[@intCast(index / 64)] &= ~mask;
    }

    pub fn is_acquired(self: *const FreeSet, address: u64) bool {
        assert(address >= 1 and address <= self.block_count);
        return bit(self.set(.acquired), address);
    }

    /// True while the block is released but not yet reusable.
    pub fn is_released(self: *const FreeSet, address: u64) bool {
        assert(address >= 1 and address <= self.block_count);
        return bit(self.set(.released_new), address) or bit(self.set(.released_old), address) or
            bit(self.set(.released_freeing), address);
    }

    pub fn count_free(self: *const FreeSet) u64 {
        var acquired: u64 = 0;
        for (self.set(.acquired)) |word| acquired += @popCount(word);
        assert(acquired <= self.block_count);
        return self.block_count - acquired;
    }

    /// The lowest free address at or above `start`, or null.
    fn find_free(self: *const FreeSet, start: u64) ?u64 {
        assert(start >= 1);
        if (start > self.block_count) return null;
        const acquired = self.set(.acquired);
        var index = start - 1;
        var word_index: usize = @intCast(index / 64);
        // Bounded: one pass over the words from `start`.
        while (word_index < self.word_count) : (word_index += 1) {
            const shift: u6 = @intCast(if (word_index == index / 64) index % 64 else 0);
            const free_bits = ~acquired[word_index] & (~@as(u64, 0) << shift);
            if (free_bits != 0) {
                index = @as(u64, word_index) * 64 + @ctz(free_bits);
                if (index >= self.block_count) return null;
                return index + 1;
            }
        }
        return null;
    }

    /// Sets aside `count` free blocks; `acquire` hands them out.
    pub fn reserve(self: *FreeSet, count: u64) Error!Reservation {
        assert(!self.reserved);
        assert(count > 0);
        if (count > self.count_free()) return error.NoSpace;
        const first = self.find_free(1).?;
        // The run ends after the count-th free block.
        var end = first;
        var found: u64 = 0;
        while (found < count) : (found += 1) {
            const address = self.find_free(end).?;
            end = address + 1;
        }
        self.reserved = true;
        self.reservation_cursor = first;
        self.reservation_end = end;
        self.reservation_left = count;
        assert(end <= self.block_count + 1);
        return .{ .address_first = first, .count = count };
    }

    /// The next block of `reservation`, now acquired.
    pub fn acquire(self: *FreeSet, reservation: *Reservation) u64 {
        assert(self.reserved);
        assert(reservation.acquired < reservation.count);
        assert(self.reservation_left > 0);
        const address = self.find_free(self.reservation_cursor).?;
        assert(address < self.reservation_end);
        bit_set(self.set(.acquired), address, true);
        self.reservation_cursor = address + 1;
        self.reservation_left -= 1;
        reservation.acquired += 1;
        assert(self.is_acquired(address) and !self.is_released(address));
        return address;
    }

    /// Ends `reservation`; unacquired blocks stay free.
    pub fn forfeit(self: *FreeSet, reservation: *Reservation) void {
        assert(self.reserved);
        assert(reservation.acquired + self.reservation_left == reservation.count);
        self.reserved = false;
        self.reservation_left = 0;
        reservation.* = undefined;
    }

    /// Marks an acquired block as no longer referenced by the live state. It stays acquired
    /// until no retained checkpoint can reference it.
    pub fn release(self: *FreeSet, address: u64) void {
        assert(address >= 1 and address <= self.block_count);
        assert(self.is_acquired(address));
        assert(!self.is_released(address));
        bit_set(self.set(.released_new), address, true);
        assert(self.is_released(address));
    }

    /// Size of the checkpoint image: `acquired` then the pending releases, each a bitset.
    pub fn encoded_size(self: *const FreeSet) u64 {
        return 2 * self.bitset_size();
    }

    fn bitset_size(self: *const FreeSet) u64 {
        return std.math.divCeil(u64, self.block_count, 8) catch unreachable; // Non-zero.
    }

    /// The snapshot point of a checkpoint: writes its image into `out` and shifts the
    /// release stages.
    pub fn checkpoint_begin(self: *FreeSet, out: []u8) void {
        assert(!self.checkpointing);
        assert(out.len == self.encoded_size());
        const acquired = self.set(.acquired);
        const new = self.set(.released_new);
        const old = self.set(.released_old);
        const freeing = self.set(.released_freeing);
        // The previous checkpoint finished (or aborted), so nothing is mid-free.
        for (freeing) |word| assert(word == 0);
        const size: usize = @intCast(self.bitset_size());
        for (0..self.word_count) |index| {
            const image = acquired[index] & ~old[index];
            write_word(out[0..size], index, image);
            write_word(out[size..], index, new[index]);
            freeing[index] = old[index];
            old[index] = new[index];
            new[index] = 0;
        }
        self.checkpointing = true;
        self.assert_invariants();
    }

    /// The checkpoint is durable on every superblock copy: free what no retained checkpoint
    /// references.
    pub fn checkpoint_durable(self: *FreeSet) void {
        assert(self.checkpointing);
        const acquired = self.set(.acquired);
        const freeing = self.set(.released_freeing);
        for (acquired, freeing) |*word, *free_word| {
            assert(word.* & free_word.* == free_word.*);
            word.* &= ~free_word.*;
            free_word.* = 0;
        }
        self.checkpointing = false;
        self.assert_invariants();
    }

    /// The checkpoint failed: the old checkpoints stay newest and fallback.
    pub fn checkpoint_abort(self: *FreeSet) void {
        assert(self.checkpointing);
        const new = self.set(.released_new);
        const old = self.set(.released_old);
        const freeing = self.set(.released_freeing);
        for (new, old, freeing) |*new_word, *old_word, *free_word| {
            new_word.* |= old_word.*;
            old_word.* = free_word.*;
            free_word.* = 0;
        }
        self.checkpointing = false;
        self.assert_invariants();
    }

    /// Loads a checkpoint image. Rejects bits past the block count and releases of blocks
    /// that are not acquired.
    pub fn decode(self: *FreeSet, bytes: []const u8) Error!void {
        assert(!self.reserved);
        if (bytes.len != self.encoded_size()) return error.InvalidFreeSet;
        const size: usize = @intCast(self.bitset_size());
        @memset(self.words, 0);
        self.checkpointing = false;
        const acquired = self.set(.acquired);
        const old = self.set(.released_old);
        for (0..self.word_count) |index| {
            acquired[index] = read_word(bytes[0..size], index);
            old[index] = read_word(bytes[size..], index);
            if (old[index] & ~acquired[index] != 0) return error.InvalidFreeSet;
        }
        const tail_bits = self.block_count % 64;
        if (tail_bits != 0) {
            const mask = ~@as(u64, 0) << @intCast(tail_bits);
            if (acquired[self.word_count - 1] & mask != 0) return error.InvalidFreeSet;
        }
        // Bits in the last byte past the block count read as acquired above; re-check bytes.
        const byte_bits = self.block_count % 8;
        if (byte_bits != 0) {
            const mask: u8 = @truncate(@as(u16, 0xff) << @intCast(byte_bits));
            if (bytes[size - 1] & mask != 0 or bytes[2 * size - 1] & mask != 0) {
                return error.InvalidFreeSet;
            }
        }
        self.assert_invariants();
    }

    /// Releases are acquired blocks; the stages are disjoint; no bit past the block count.
    pub fn assert_invariants(self: *const FreeSet) void {
        const acquired = self.set(.acquired);
        const new = self.set(.released_new);
        const old = self.set(.released_old);
        const freeing = self.set(.released_freeing);
        for (0..self.word_count) |index| {
            const released = new[index] | old[index] | freeing[index];
            assert(released & ~acquired[index] == 0);
            assert(new[index] & old[index] == 0);
            assert(new[index] & freeing[index] == 0);
            assert(old[index] & freeing[index] == 0);
        }
        const tail_bits = self.block_count % 64;
        if (tail_bits != 0) {
            const mask = ~@as(u64, 0) << @intCast(tail_bits);
            assert(acquired[self.word_count - 1] & mask == 0);
        }
    }
};

/// Little-endian bytes of word `index`, truncated at the end of `out`.
fn write_word(out: []u8, index: usize, word: u64) void {
    const start = index * 8;
    assert(start < out.len);
    const length = @min(8, out.len - start);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, word, .little);
    @memcpy(out[start..][0..length], bytes[0..length]);
}

fn read_word(bytes: []const u8, index: usize) u64 {
    const start = index * 8;
    assert(start < bytes.len);
    const length = @min(8, bytes.len - start);
    var word: [8]u8 = @splat(0);
    @memcpy(word[0..length], bytes[start..][0..length]);
    return std.mem.readInt(u64, &word, .little);
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");

test "free set: acquire lowest, release waits for two durable checkpoints" {
    var free_set = try FreeSet.init(testing.allocator, 70);
    defer free_set.deinit(testing.allocator);
    var image: [18]u8 = undefined;
    var reservation = try free_set.reserve(3);
    try testing.expectEqual(@as(u64, 1), free_set.acquire(&reservation));
    try testing.expectEqual(@as(u64, 2), free_set.acquire(&reservation));
    free_set.forfeit(&reservation);
    try testing.expectEqual(@as(u64, 68), free_set.count_free());

    free_set.release(1); // Checkpoint 0 (the newest) references it.
    free_set.checkpoint_begin(&image);
    try testing.expect(free_set.is_acquired(1));
    free_set.checkpoint_durable();
    try testing.expect(free_set.is_acquired(1)); // Checkpoint 0 is now the fallback.
    free_set.checkpoint_begin(&image);
    try testing.expect(free_set.is_acquired(1)); // Not until the superblock is durable.
    free_set.checkpoint_durable();
    try testing.expect(!free_set.is_acquired(1));
    reservation = try free_set.reserve(1);
    try testing.expectEqual(@as(u64, 1), free_set.acquire(&reservation));
    free_set.forfeit(&reservation);
    try testing.expectError(error.NoSpace, free_set.reserve(69));
}

/// A reference model: per block, the checkpoints that may reference it.
const Model = struct {
    const blocks_max = 200;
    /// Live: referenced by the current state.
    live: [blocks_max]bool = @splat(false),
    /// Referenced by the newest / fallback durable checkpoint, and by the in-flight one.
    newest: [blocks_max]bool = @splat(false),
    fallback: [blocks_max]bool = @splat(false),
    pending: [blocks_max]bool = @splat(false),
    checkpointing: bool = false,

    fn referenced(model: *const Model, index: usize) bool {
        return model.live[index] or model.newest[index] or model.fallback[index] or
            (model.checkpointing and model.pending[index]);
    }
};

/// The free set and the model, driven one operation at a time.
const Harness = struct {
    free_set: FreeSet,
    model: Model = .{},
    image: [2 * Model.blocks_max / 8 + 2]u8 = undefined,
    durable_image: [2 * Model.blocks_max / 8 + 2]u8 = @splat(0),

    fn init(block_count: u64) !Harness {
        return .{ .free_set = try FreeSet.init(testing.allocator, block_count) };
    }

    fn deinit(harness: *Harness) void {
        harness.free_set.deinit(testing.allocator);
    }

    fn step(harness: *Harness, operation: u8, argument: u64) !void {
        const free_set = &harness.free_set;
        const model = &harness.model;
        const image = harness.image[0..@intCast(free_set.encoded_size())];
        switch (operation) {
            0 => try fuzz_acquire(free_set, model, argument % 8 + 1),
            1 => fuzz_release(free_set, model, argument % free_set.block_count),
            2 => if (!model.checkpointing) {
                free_set.checkpoint_begin(image);
                model.pending = model.live;
                model.checkpointing = true;
            },
            3 => if (model.checkpointing) {
                free_set.checkpoint_durable();
                model.fallback = model.newest;
                model.newest = model.pending;
                model.checkpointing = false;
                @memcpy(harness.durable_image[0..image.len], image);
            },
            4 => if (model.checkpointing) {
                free_set.checkpoint_abort();
                model.checkpointing = false;
            },
            5 => {
                // Crash and open from the newest durable image; the superblock still names
                // the same fallback.
                try free_set.decode(harness.durable_image[0..image.len]);
                model.live = model.newest;
                model.checkpointing = false;
            },
            else => unreachable,
        }
        try fuzz_check(free_set, model);
    }
};

fn fuzz_state_machine(_: void, smith: *std.testing.Smith) anyerror!void {
    var harness = try Harness.init(smith.valueRangeAtMost(u64, 1, Model.blocks_max));
    defer harness.deinit();
    var steps: u32 = 0;
    while (!smith.eos() and steps < 512) : (steps += 1) {
        try harness.step(smith.valueRangeAtMost(u8, 0, 5), smith.value(u64));
    }
}

test "free set: seeded state machine against a reference model" {
    var prng = Prng.init(11);
    for (0..64) |_| {
        var harness = try Harness.init(prng.range(1, Model.blocks_max));
        defer harness.deinit();
        for (0..2000) |_| {
            // Acquire and release more often than checkpoints, crashes rarely.
            const operation: u8 = switch (prng.below(16)) {
                0...5 => 0,
                6...10 => 1,
                11, 12 => 2,
                13 => 3,
                14 => if (prng.chance(1, 4)) 4 else 3,
                15 => if (prng.chance(1, 4)) 5 else 2,
                else => unreachable,
            };
            try harness.step(operation, prng.int(u64));
        }
    }
}

fn fuzz_acquire(free_set: *FreeSet, model: *Model, count: u64) !void {
    var reservation = free_set.reserve(count) catch return;
    var index: u64 = 0;
    while (index < count) : (index += 1) {
        const address = free_set.acquire(&reservation);
        const block: usize = @intCast(address - 1);
        // The core property: never hand out a block any retained checkpoint references.
        try testing.expect(!model.referenced(block));
        model.live[block] = true;
    }
    free_set.forfeit(&reservation);
}

fn fuzz_release(free_set: *FreeSet, model: *Model, index: u64) void {
    const block: usize = @intCast(index);
    if (!model.live[block]) return;
    free_set.release(index + 1);
    model.live[block] = false;
}

fn fuzz_check(free_set: *const FreeSet, model: *const Model) !void {
    free_set.assert_invariants();
    for (0..@intCast(free_set.block_count)) |block| {
        if (model.referenced(block)) try testing.expect(free_set.is_acquired(block + 1));
        if (model.live[block]) try testing.expect(!free_set.is_released(block + 1));
    }
}

test "free set: fuzz the reservation state machine against a reference model" {
    try fuzz.run({}, fuzz_state_machine, .{ .iterations = 512, .input_size_max = 4096 });
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    var free_set = try FreeSet.init(testing.allocator, 77);
    defer free_set.deinit(testing.allocator);
    const size: usize = @intCast(free_set.encoded_size());
    var bytes: [32]u8 = @splat(0);
    @memcpy(bytes[0..@min(input.len, size)], input[0..@min(input.len, size)]);
    free_set.decode(bytes[0..size]) catch return;
    // Accepted images round trip through a checkpoint image.
    var image: [32]u8 = undefined;
    free_set.checkpoint_begin(image[0..size]);
    for (0..size / 2) |index| {
        try testing.expectEqual(bytes[index] & ~bytes[size / 2 + index], image[index]);
    }
}

test "free set: fuzz decode" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .iterations = 256, .input_size_max = 40 });
}

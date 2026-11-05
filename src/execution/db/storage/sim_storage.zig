//! Deterministic simulated disk with fault injection.
//!
//! The disk keeps two images: `durable` (what survives a crash) and `memory` (what reads see:
//! durable plus completed-but-unsynced writes). Every operation completes after a random
//! latency in ticks, so completions reorder. `crash()` drops pending operations, then for
//! every unsynced sector randomly loses it, keeps it, or tears it at a 512-byte boundary.
//! Pending writes at crash time may land first, since a real disk may have started them.
//! `corrupt_sector` models bit rot, and reads can return flipped bits (transient faults).
//!
//! Everything is drawn from one `Prng` seed, so a failing run reproduces from its seed.
//! Memory is allocated once at `init`; no operation allocates.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

const sector_size = storage.sector_size;
const Completion = storage.Completion;
const Read = storage.Read;
const Write = storage.Write;
const Sync = storage.Sync;

/// Physical sectors tear at this granularity.
pub const tear_chunk_size: u32 = 512;

pub const Options = struct {
    size_bytes: u64,
    seed: u64,
    latency_ticks_min: u32 = 1,
    latency_ticks_max: u32 = 4,
    /// Probability that a completed read returns one flipped bit (transient fault).
    read_fault_numerator: u32 = 0,
    read_fault_denominator: u32 = 1000,
    /// Probability that a pending write lands (fully) at crash time.
    crash_pending_write_numerator: u32 = 1,
    crash_pending_write_denominator: u32 = 2,
};

pub const SimStorage = struct {
    options: Options,
    prng: Prng,
    durable: []u8,
    memory: []u8,
    /// One flag per sector: written since the last sync.
    dirty: []bool,
    dirty_list: []u32,
    dirty_count: u32 = 0,
    pending_head: ?*Completion = null,
    pending_count: u32 = 0,
    tick_count: u64 = 0,
    stats: Stats = .{},

    pub const Stats = struct {
        reads: u64 = 0,
        writes: u64 = 0,
        syncs: u64 = 0,
        read_faults: u64 = 0,
        crashes: u64 = 0,
        sectors_torn: u64 = 0,
        sectors_lost: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, options: Options) !SimStorage {
        assert(options.size_bytes > 0);
        assert(options.size_bytes % sector_size == 0);
        assert(options.latency_ticks_min >= 1);
        assert(options.latency_ticks_min <= options.latency_ticks_max);
        assert(options.read_fault_numerator <= options.read_fault_denominator);
        const sectors = options.size_bytes / sector_size;
        assert(sectors <= std.math.maxInt(u32));

        const durable = try allocator.alloc(u8, options.size_bytes);
        errdefer allocator.free(durable);
        const memory = try allocator.alloc(u8, options.size_bytes);
        errdefer allocator.free(memory);
        const dirty = try allocator.alloc(bool, sectors);
        errdefer allocator.free(dirty);
        const dirty_list = try allocator.alloc(u32, sectors);
        @memset(durable, 0);
        @memset(memory, 0);
        @memset(dirty, false);
        return .{
            .options = options,
            .prng = Prng.init(options.seed),
            .durable = durable,
            .memory = memory,
            .dirty = dirty,
            .dirty_list = dirty_list,
        };
    }

    pub fn deinit(self: *SimStorage, allocator: std.mem.Allocator) void {
        assert(self.durable.len == self.memory.len);
        allocator.free(self.durable);
        allocator.free(self.memory);
        allocator.free(self.dirty);
        allocator.free(self.dirty_list);
        self.* = undefined;
    }

    pub fn size_bytes(self: *const SimStorage) u64 {
        return self.durable.len;
    }

    pub fn sector_count(self: *const SimStorage) u32 {
        return @intCast(self.durable.len / sector_size);
    }

    pub fn read_sectors(
        self: *SimStorage,
        callback: *const fn (*Read) void,
        read: *Read,
        buffer: []u8,
        offset: u64,
    ) void {
        self.assert_range(offset, buffer.len);
        self.assert_no_pending_write_overlap(offset, buffer.len);
        read.* = .{ .callback = callback, .buffer = buffer, .offset = offset };
        self.submit(&read.completion, .read);
    }

    pub fn write_sectors(
        self: *SimStorage,
        callback: *const fn (*Write) void,
        write: *Write,
        buffer: []const u8,
        offset: u64,
    ) void {
        self.assert_range(offset, buffer.len);
        self.assert_no_pending_write_overlap(offset, buffer.len);
        write.* = .{ .callback = callback, .buffer = buffer, .offset = offset };
        self.submit(&write.completion, .write);
    }

    pub fn sync(self: *SimStorage, callback: *const fn (*Sync) void, sync_: *Sync) void {
        sync_.* = .{ .callback = callback };
        self.submit(&sync_.completion, .sync);
    }

    /// Completes every operation whose latency has elapsed, in random order.
    pub fn tick(self: *SimStorage) void {
        self.tick_count += 1;
        // Detach ready operations first: callbacks may submit, and new submissions always
        // complete in a later tick (latency >= 1).
        var ready_head: ?*Completion = null;
        var ready_count: u32 = 0;
        var link: *?*Completion = &self.pending_head;
        var scanned: u32 = 0;
        const pending_count = self.pending_count;
        while (link.*) |completion| : (scanned += 1) {
            assert(scanned < pending_count);
            if (completion.tick_ready <= self.tick_count) {
                link.* = completion.next;
                completion.next = ready_head;
                ready_head = completion;
                ready_count += 1;
            } else {
                link = &completion.next;
            }
        }
        assert(ready_count <= self.pending_count);
        self.pending_count -= ready_count;

        while (ready_count > 0) : (ready_count -= 1) {
            const completion = unlink_at(&ready_head, @intCast(self.prng.below(ready_count)));
            self.complete(completion);
        }
        assert(ready_head == null);
    }

    /// True when no operation is pending.
    pub fn idle(self: *const SimStorage) bool {
        return self.pending_count == 0;
    }

    /// Power loss. Pending operations are dropped (their callbacks never fire), and every
    /// unsynced sector is randomly lost, kept, or torn. Afterwards reads see the durable image.
    pub fn crash(self: *SimStorage) void {
        var count: u32 = 0;
        while (self.pending_head) |completion| : (count += 1) {
            assert(count < self.pending_count);
            self.pending_head = completion.next;
            completion.next = null;
            if (completion.operation != .write) continue;
            const write: *Write = @fieldParentPtr("completion", completion);
            const lands = self.prng.chance(
                self.options.crash_pending_write_numerator,
                self.options.crash_pending_write_denominator,
            );
            if (lands) self.apply_write(write);
        }
        self.pending_count = 0;

        for (self.dirty_list[0..self.dirty_count]) |sector| {
            assert(self.dirty[sector]);
            self.dirty[sector] = false;
            const durable = self.sector_slice(self.durable, sector);
            const memory = self.sector_slice(self.memory, sector);
            switch (self.prng.below(3)) {
                0 => self.stats.sectors_lost += 1,
                1 => @memcpy(durable, memory),
                2 => self.tear(durable, memory),
                else => unreachable,
            }
            @memcpy(memory, durable);
        }
        self.dirty_count = 0;
        self.stats.crashes += 1;
        assert(std.mem.eql(u8, self.durable, self.memory));
    }

    /// Bit rot: flips 1 to 8 random bits of one sector, durably.
    pub fn corrupt_sector(self: *SimStorage, sector: u32) void {
        assert(sector < self.sector_count());
        const flips = self.prng.range(1, 8);
        var flip: u64 = 0;
        while (flip < flips) : (flip += 1) {
            const bit = self.prng.below(sector_size * 8);
            const index = @as(u64, sector) * sector_size + bit / 8;
            const mask = @as(u8, 1) << @intCast(bit % 8);
            self.durable[index] ^= mask;
            self.memory[index] ^= mask;
        }
    }

    /// The bytes a crash right now would certainly preserve (for test inspection).
    pub fn durable_sector(self: *const SimStorage, sector: u32) []const u8 {
        return self.sector_slice(self.durable, sector);
    }

    /// The bytes a read right now would return, barring read faults.
    pub fn memory_sector(self: *const SimStorage, sector: u32) []const u8 {
        return self.sector_slice(self.memory, sector);
    }

    pub fn unsynced_sector_count(self: *const SimStorage) u32 {
        return self.dirty_count;
    }

    fn submit(self: *SimStorage, completion: *Completion, operation: Operation) void {
        assert(completion.next == null);
        assert(self.pending_count < std.math.maxInt(u32));
        const latency = self.prng.range(
            self.options.latency_ticks_min,
            self.options.latency_ticks_max,
        );
        completion.operation = operation;
        completion.tick_ready = self.tick_count + latency;
        completion.next = self.pending_head;
        self.pending_head = completion;
        self.pending_count += 1;
        switch (operation) {
            .read => self.stats.reads += 1,
            .write => self.stats.writes += 1,
            .sync => self.stats.syncs += 1,
        }
    }

    fn complete(self: *SimStorage, completion: *Completion) void {
        assert(completion.tick_ready <= self.tick_count);
        completion.next = null;
        switch (completion.operation) {
            .read => {
                const read: *Read = @fieldParentPtr("completion", completion);
                const offset: usize = @intCast(read.offset);
                @memcpy(read.buffer, self.memory[offset..][0..read.buffer.len]);
                self.maybe_read_fault(read.buffer);
                read.callback(read);
            },
            .write => {
                const write: *Write = @fieldParentPtr("completion", completion);
                self.apply_write(write);
                write.callback(write);
            },
            .sync => {
                const sync_: *Sync = @fieldParentPtr("completion", completion);
                self.persist();
                sync_.callback(sync_);
            },
        }
    }

    fn apply_write(self: *SimStorage, write: *const Write) void {
        const offset: usize = @intCast(write.offset);
        @memcpy(self.memory[offset..][0..write.buffer.len], write.buffer);
        const first: u32 = @intCast(write.offset / sector_size);
        const count: u32 = @intCast(write.buffer.len / sector_size);
        for (first..first + count) |sector| {
            if (self.dirty[sector]) continue;
            self.dirty[sector] = true;
            self.dirty_list[self.dirty_count] = @intCast(sector);
            self.dirty_count += 1;
        }
        assert(self.dirty_count <= self.dirty.len);
    }

    /// Makes every completed write durable. Stronger than the interface promises (writes
    /// completed after the sync was submitted also persist); the engine must not rely on it.
    fn persist(self: *SimStorage) void {
        for (self.dirty_list[0..self.dirty_count]) |sector| {
            assert(self.dirty[sector]);
            self.dirty[sector] = false;
            @memcpy(
                self.sector_slice(self.durable, sector),
                self.sector_slice(self.memory, sector),
            );
        }
        self.dirty_count = 0;
    }

    fn tear(self: *SimStorage, durable: []u8, memory: []const u8) void {
        const chunks = sector_size / tear_chunk_size;
        const boundary: usize = @intCast(self.prng.range(1, chunks - 1) * tear_chunk_size);
        if (self.prng.chance(1, 2)) {
            @memcpy(durable[0..boundary], memory[0..boundary]);
        } else {
            @memcpy(durable[boundary..], memory[boundary..]);
        }
        self.stats.sectors_torn += 1;
    }

    fn maybe_read_fault(self: *SimStorage, buffer: []u8) void {
        if (self.options.read_fault_numerator == 0) return;
        const fault = self.prng.chance(
            self.options.read_fault_numerator,
            self.options.read_fault_denominator,
        );
        if (!fault) return;
        const bit = self.prng.below(buffer.len * 8);
        buffer[@intCast(bit / 8)] ^= @as(u8, 1) << @intCast(bit % 8);
        self.stats.read_faults += 1;
    }

    fn sector_slice(self: *const SimStorage, image: []u8, sector: u32) []u8 {
        assert(sector < self.sector_count());
        return image[@as(usize, sector) * sector_size ..][0..sector_size];
    }

    fn assert_range(self: *const SimStorage, offset: u64, length: usize) void {
        storage.assert_aligned(offset, length);
        assert(offset + length <= self.durable.len);
    }

    /// Overlapping a pending write is a data race in the caller.
    fn assert_no_pending_write_overlap(self: *const SimStorage, offset: u64, length: usize) void {
        var iterator = self.pending_head;
        var count: u32 = 0;
        while (iterator) |completion| : (count += 1) {
            assert(count < self.pending_count);
            iterator = completion.next;
            if (completion.operation != .write) continue;
            const write: *const Write = @fieldParentPtr("completion", completion);
            const disjoint = write.offset + write.buffer.len <= offset or
                offset + length <= write.offset;
            assert(disjoint);
        }
    }
};

const Operation = storage.Operation;

/// Removes and returns the `index`-th element of a singly linked list.
fn unlink_at(head: *?*Completion, index: u32) *Completion {
    var link: *?*Completion = head;
    var position: u32 = 0;
    while (position < index) : (position += 1) {
        link = &link.*.?.next;
    }
    const completion = link.*.?;
    link.* = completion.next;
    completion.next = null;
    return completion;
}

comptime {
    storage.assert_interface(SimStorage);
}

const testing = std.testing;

const TestOps = struct {
    read: Read = .{},
    write: Write = .{},
    sync: Sync = .{},
    reads_done: u32 = 0,
    writes_done: u32 = 0,
    syncs_done: u32 = 0,

    fn on_read(read: *Read) void {
        const ops: *TestOps = @fieldParentPtr("read", read);
        ops.reads_done += 1;
    }
    fn on_write(write: *Write) void {
        const ops: *TestOps = @fieldParentPtr("write", write);
        ops.writes_done += 1;
    }
    fn on_sync(sync_: *Sync) void {
        const ops: *TestOps = @fieldParentPtr("sync", sync_);
        ops.syncs_done += 1;
    }
};

fn drain(sim: *SimStorage) void {
    var ticks: u32 = 0;
    while (!sim.idle()) : (ticks += 1) {
        assert(ticks < 1000);
        sim.tick();
    }
}

test "sim storage: write, read back, sync makes durable" {
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 8 * sector_size, .seed = 1 });
    defer sim.deinit(testing.allocator);
    var ops: TestOps = .{};
    var data: [2 * sector_size]u8 = undefined;
    @memset(&data, 0xab);
    sim.write_sectors(TestOps.on_write, &ops.write, &data, sector_size);
    try testing.expectEqual(@as(u32, 0), ops.writes_done); // never re-entrant
    drain(&sim);
    try testing.expectEqual(@as(u32, 1), ops.writes_done);
    try testing.expectEqual(@as(u32, 2), sim.unsynced_sector_count());

    var buffer: [2 * sector_size]u8 = undefined;
    sim.read_sectors(TestOps.on_read, &ops.read, &buffer, sector_size);
    drain(&sim);
    try testing.expectEqualSlices(u8, &data, &buffer);
    try testing.expectEqual(@as(u8, 0), sim.durable_sector(1)[0]);

    sim.sync(TestOps.on_sync, &ops.sync);
    drain(&sim);
    try testing.expectEqual(@as(u32, 0), sim.unsynced_sector_count());
    try testing.expectEqual(@as(u8, 0xab), sim.durable_sector(2)[sector_size - 1]);
    sim.crash();
    try testing.expectEqual(@as(u8, 0xab), sim.memory_sector(1)[0]);
}

test "sim storage: crash loses, keeps, or tears unsynced sectors" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = 64 * sector_size,
        .seed = 9,
    });
    defer sim.deinit(testing.allocator);
    var ops: TestOps = .{};
    var data: [64 * sector_size]u8 = undefined;
    @memset(&data, 0xff);
    sim.write_sectors(TestOps.on_write, &ops.write, &data, 0);
    drain(&sim);
    sim.crash();
    var kept: u32 = 0;
    var lost: u32 = 0;
    var torn: u32 = 0;
    for (0..64) |sector| {
        const bytes = sim.durable_sector(@intCast(sector));
        const ones = std.mem.count(u8, bytes, &.{0xff});
        if (ones == sector_size) kept += 1 else if (ones == 0) lost += 1 else {
            torn += 1;
            try testing.expect(ones % tear_chunk_size == 0);
        }
    }
    try testing.expect(kept > 0 and lost > 0 and torn > 0);
    try testing.expectEqual(@as(u64, torn), sim.stats.sectors_torn);
}

test "sim storage: deterministic from seed, completions reorder" {
    var orders: [2][8]u32 = undefined;
    for (&orders) |*order| {
        var sim = try SimStorage.init(testing.allocator, .{
            .size_bytes = 8 * sector_size,
            .seed = 3,
            .latency_ticks_max = 10,
        });
        defer sim.deinit(testing.allocator);
        var ops: [8]TestOps = @splat(.{});
        var buffers: [8][sector_size]u8 = undefined;
        for (&ops, 0..) |*op, index| {
            sim.read_sectors(TestOps.on_read, &op.read, &buffers[index], index * sector_size);
        }
        var done: u32 = 0;
        var ticks: u32 = 0;
        while (done < 8) : (ticks += 1) {
            try testing.expect(ticks < 100);
            sim.tick();
            for (&ops, 0..) |*op, index| {
                if (op.reads_done == 1) {
                    op.reads_done = 2;
                    order[done] = @intCast(index);
                    done += 1;
                }
            }
        }
    }
    try testing.expectEqualSlices(u32, &orders[0], &orders[1]);
    var sorted = true;
    for (1..8) |index| sorted = sorted and orders[0][index - 1] < orders[0][index];
    try testing.expect(!sorted);
}

test "sim storage: corrupt_sector and read faults flip bits" {
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = 4 * sector_size,
        .seed = 5,
        .read_fault_numerator = 1,
        .read_fault_denominator = 1,
    });
    defer sim.deinit(testing.allocator);
    sim.corrupt_sector(2);
    try testing.expect(std.mem.count(u8, sim.durable_sector(2), &.{0}) < sector_size);
    try testing.expect(std.mem.count(u8, sim.durable_sector(1), &.{0}) == sector_size);
    var ops: TestOps = .{};
    var buffer: [sector_size]u8 = undefined;
    sim.read_sectors(TestOps.on_read, &ops.read, &buffer, 0);
    drain(&sim);
    try testing.expect(std.mem.count(u8, &buffer, &.{0}) == sector_size - 1);
    try testing.expectEqual(@as(u64, 1), sim.stats.read_faults);
}

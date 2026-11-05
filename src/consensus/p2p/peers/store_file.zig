//! File sync for small JSON stores (the base/base bootstore file), through `utilities.io`
//! so the simulator can crash it. `start` reads the whole file once and hands it to
//! `hooks.loaded`; then every `interval_ns` (base/base: 60 s) and on `stop`, `hooks.produce`
//! fills the buffer, which is written at offset 0 and fsynced.
//!
//! The io layer has no truncate or rename, so a shorter image is padded with spaces up to
//! the longest image written so far (JSON allows trailing whitespace). A crash before the
//! fsync keeps the previous durable image; a torn write on a real disk yields invalid JSON,
//! which the owner treats as an empty store (base/base `unwrap_or_default`).
//!
//! One operation is in flight at a time. A save that finds the file busy is skipped (and
//! counted); the next interval retries.

const std = @import("std");
const assert = std.debug.assert;
const io_module = @import("../../../utilities/io/root.zig");

pub const Stats = struct {
    open_errors: u64 = 0,
    loads: u64 = 0,
    load_errors: u64 = 0,
    saves: u64 = 0,
    save_errors: u64 = 0,
    saves_skipped: u64 = 0,
};

/// `loaded` receives the file contents once (they stay valid until `deinit`); `produce`
/// writes an image into the buffer it is given and returns the used prefix. Without
/// `produce` the file is read-only: no timer, no writes. `loaded` also runs, with empty
/// contents, when the file cannot be opened or read, so the owner can fall back.
pub fn Hooks(comptime Owner: type) type {
    return struct {
        loaded: fn (*Owner, []const u8) void,
        produce: ?fn (*Owner, []u8) []const u8 = null,
    };
}

pub fn StoreFile(comptime IO: type, comptime Owner: type, comptime hooks: Hooks(Owner)) type {
    return struct {
        const Self = @This();
        const Phase = enum { closed, reading, idle, writing, syncing };

        io: *IO,
        owner: *Owner,
        path: []const u8,
        interval_ns: u64,
        buffer: []u8,
        fd: IO.Fd = undefined,
        phase: Phase = .closed,
        /// Bytes read so far, or bytes of the current image written so far.
        offset: usize = 0,
        /// Bytes of the image being written (payload plus padding).
        image_length: usize = 0,
        /// The longest image on disk: shorter images are padded up to it.
        file_length: usize = 0,
        timer_armed: bool = false,
        stopping: bool = false,
        completion: IO.Completion = .{},
        timer_completion: IO.Completion = .{},
        stats: Stats = .{},

        /// `capacity_bytes` bounds both the file read and every produced image.
        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            owner: *Owner,
            path: []const u8,
            capacity_bytes: usize,
            interval_ns: u64,
        ) !void {
            assert(path.len > 0);
            assert(capacity_bytes > 0);
            assert(interval_ns > 0);
            self.* = .{
                .io = io,
                .owner = owner,
                .path = path,
                .interval_ns = interval_ns,
                .buffer = try allocator.alloc(u8, capacity_bytes),
            };
        }

        /// Call once the IO loop has drained (`busy` is false).
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(!self.busy());
            if (self.phase != .closed) self.io.close_now(self.fd);
            allocator.free(self.buffer);
            self.* = undefined;
        }

        /// After a simulated process crash: the descriptor is closed and pending operations
        /// (timer included) vanished without callbacks, so `deinit` must not wait or close.
        pub fn forget_after_crash(self: *Self) void {
            self.phase = .closed;
            self.timer_armed = false;
            self.stopping = true;
            assert(!self.busy());
        }

        /// Opens (or creates) the file and starts reading it. An open failure is counted
        /// and leaves the store memory-only.
        pub fn start(self: *Self) void {
            assert(self.phase == .closed);
            assert(!self.stopping);
            const mode: io_module.OpenMode = if (hooks.produce == null) .read_only else .create;
            self.fd = self.io.open_file(self.path, mode) catch {
                self.stats.open_errors += 1;
                hooks.loaded(self.owner, self.buffer[0..0]);
                return;
            };
            self.phase = .reading;
            self.offset = 0;
            self.submit_read();
        }

        /// Writes a final image and stops the timer. Drain the IO loop before `deinit`.
        pub fn stop(self: *Self) void {
            if (self.stopping) return;
            self.stopping = true;
            if (self.phase == .idle) self.save();
            if (self.timer_armed) self.io.cancel(&self.timer_completion);
            assert(self.stopping);
        }

        /// True while an operation or the timer is outstanding.
        pub fn busy(self: *const Self) bool {
            const in_flight = switch (self.phase) {
                .reading, .writing, .syncing => true,
                .closed, .idle => false,
            };
            return in_flight or self.timer_armed;
        }

        /// Writes the current image now unless an operation is in flight.
        pub fn save(self: *Self) void {
            const produce = hooks.produce orelse return;
            if (self.phase != .idle) {
                self.stats.saves_skipped += 1;
                return;
            }
            const image = produce(self.owner, self.buffer);
            assert(image.ptr == self.buffer.ptr);
            assert(image.len <= self.buffer.len);
            assert(self.file_length <= self.buffer.len);
            if (image.len < self.file_length) {
                @memset(self.buffer[image.len..self.file_length], ' ');
            }
            self.image_length = @max(image.len, self.file_length);
            if (self.image_length == 0) return;
            self.phase = .writing;
            self.offset = 0;
            self.submit_write();
        }

        fn submit_read(self: *Self) void {
            assert(self.phase == .reading);
            assert(self.offset < self.buffer.len);
            const target = self.buffer[self.offset..];
            self.io.read(*Self, self, on_read, &self.completion, self.fd, target, self.offset);
        }

        fn on_read(
            self: *Self,
            completion: *IO.Completion,
            result: io_module.ReadError!usize,
        ) void {
            assert(completion == &self.completion);
            assert(self.phase == .reading);
            const count = result catch {
                self.stats.load_errors += 1;
                hooks.loaded(self.owner, self.buffer[0..0]);
                self.become_idle();
                return;
            };
            self.offset += count;
            assert(self.offset <= self.buffer.len);
            if (count > 0 and self.offset < self.buffer.len) return self.submit_read();
            self.file_length = self.offset;
            self.stats.loads += 1;
            hooks.loaded(self.owner, self.buffer[0..self.offset]);
            self.become_idle();
        }

        fn become_idle(self: *Self) void {
            assert(self.phase != .closed);
            self.phase = .idle;
            if (self.stopping or hooks.produce == null) return;
            if (!self.timer_armed) self.submit_timer();
        }

        fn submit_write(self: *Self) void {
            assert(self.phase == .writing);
            assert(self.offset < self.image_length);
            const source = self.buffer[self.offset..self.image_length];
            self.io.write(*Self, self, on_write, &self.completion, self.fd, source, self.offset);
        }

        fn on_write(
            self: *Self,
            completion: *IO.Completion,
            result: io_module.WriteError!usize,
        ) void {
            assert(completion == &self.completion);
            assert(self.phase == .writing);
            const count = result catch {
                self.stats.save_errors += 1;
                self.phase = .idle;
                return;
            };
            if (count == 0) {
                self.stats.save_errors += 1;
                self.phase = .idle;
                return;
            }
            self.offset += count;
            assert(self.offset <= self.image_length);
            self.file_length = @max(self.file_length, self.offset);
            if (self.offset < self.image_length) return self.submit_write();
            self.phase = .syncing;
            self.io.fsync(*Self, self, on_fsync, &self.completion, self.fd);
        }

        fn on_fsync(
            self: *Self,
            completion: *IO.Completion,
            result: io_module.FsyncError!void,
        ) void {
            assert(completion == &self.completion);
            assert(self.phase == .syncing);
            self.phase = .idle;
            if (result) |_| {
                self.stats.saves += 1;
            } else |_| {
                self.stats.save_errors += 1;
            }
        }

        fn submit_timer(self: *Self) void {
            assert(!self.timer_armed);
            assert(!self.stopping);
            self.timer_armed = true;
            const completion = &self.timer_completion;
            self.io.timeout(*Self, self, on_timer, completion, self.interval_ns);
        }

        fn on_timer(
            self: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            assert(completion == &self.timer_completion);
            assert(self.timer_armed);
            self.timer_armed = false;
            result catch {};
            if (self.stopping) return;
            self.save();
            self.submit_timer();
        }
    };
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const SimIo = io_module.SimIo;
const ns_per_ms = std.time.ns_per_ms;

/// A store whose image is a byte string; `loaded` keeps the last load (trailing padding
/// trimmed, as a JSON parser would ignore it).
const TestOwner = struct {
    image: []const u8 = "",
    loaded_storage: [256]u8 = undefined,
    loaded: ?[]const u8 = null,

    fn on_loaded(owner: *TestOwner, contents: []const u8) void {
        const trimmed = std.mem.trimEnd(u8, contents, " ");
        @memcpy(owner.loaded_storage[0..trimmed.len], trimmed);
        owner.loaded = owner.loaded_storage[0..trimmed.len];
    }

    fn produce(owner: *TestOwner, output: []u8) []const u8 {
        @memcpy(output[0..owner.image.len], owner.image);
        return output[0..owner.image.len];
    }
};

const TestFile = StoreFile(SimIo, TestOwner, .{
    .loaded = TestOwner.on_loaded,
    .produce = TestOwner.produce,
});

const Harness = struct {
    world: io_module.SimWorld,
    io: SimIo,

    fn init(harness: *Harness, seed: u64, write_fault_ppm: u32) !void {
        harness.world = try io_module.SimWorld.init(testing.allocator, .{ .seed = seed });
        errdefer harness.world.deinit();
        try harness.io.init(testing.allocator, &harness.world, .{
            .host = io_module.Address.ip4(.{ 10, 0, 0, 1 }, 0),
            .disk = .{ .files_max = 1, .file_size_max = 256, .write_fault_ppm = write_fault_ppm },
        });
    }

    fn deinit(harness: *Harness) void {
        harness.io.deinit();
        harness.world.deinit();
    }

    /// Opens the file and runs until the initial read finished.
    fn open(harness: *Harness, file: *TestFile, owner: *TestOwner) !void {
        owner.loaded = null;
        const interval_ns = 60_000 * ns_per_ms;
        try file.init(testing.allocator, &harness.io, owner, "bootstore.json", 256, interval_ns);
        file.start();
        var rounds: u32 = 0;
        while (file.phase == .reading) : (rounds += 1) {
            if (rounds == 1000) return error.ReadStuck;
            harness.world.run_for_ns(ns_per_ms);
        }
    }

    fn close(harness: *Harness, file: *TestFile) void {
        file.stop();
        while (file.busy()) harness.world.run_for_ns(ns_per_ms);
        file.deinit(testing.allocator);
    }
};

test "store file: empty first load, periodic save, reload, shorter image padded" {
    var harness: Harness = undefined;
    try harness.init(1, 0);
    defer harness.deinit();
    var owner: TestOwner = .{};
    var file: TestFile = undefined;
    try harness.open(&file, &owner);
    try testing.expectEqualStrings("", owner.loaded.?);
    owner.image = "[\"enr:long-record\"]";
    harness.world.run_for_ns(61_000 * ns_per_ms);
    try testing.expectEqual(@as(u64, 1), file.stats.saves);
    // Stop writes a final, shorter image.
    owner.image = "[]";
    harness.close(&file);
    try harness.open(&file, &owner);
    try testing.expectEqualStrings("[]", owner.loaded.?);
    try testing.expectEqual(@as(usize, "[\"enr:long-record\"]".len), file.file_length);
    harness.close(&file);
}

test "store file: a crash before fsync keeps the previous durable image" {
    var harness: Harness = undefined;
    try harness.init(2, 0);
    defer harness.deinit();
    var owner: TestOwner = .{ .image = "[\"a\"]" };
    var file: TestFile = undefined;
    try harness.open(&file, &owner);
    file.save();
    while (file.phase != .idle) harness.world.run_for_ns(ns_per_ms);
    owner.image = "[\"b\",\"c\"]";
    file.save();
    harness.io.crash(); // The write vanishes with the process.
    testing.allocator.free(file.buffer);
    try harness.open(&file, &owner);
    try testing.expectEqualStrings("[\"a\"]", owner.loaded.?);
    harness.close(&file);
}

test "store file: seeded fuzz, reload equals the last fsynced image across crashes" {
    var seed: u64 = 0;
    while (seed < 32) : (seed += 1) {
        fuzz_seed(seed) catch |err| {
            std.debug.print("store file fuzz: failing seed={d}\n", .{seed});
            return err;
        };
    }
}

fn fuzz_seed(seed: u64) !void {
    var prng = Prng.init(seed);
    const random = prng.random();
    var harness: Harness = undefined;
    try harness.init(seed, if (random.boolean()) 100_000 else 0);
    defer harness.deinit();
    var image: [200]u8 = undefined;
    var durable_storage: [200]u8 = undefined;
    var durable: []const u8 = durable_storage[0..0];
    var owner: TestOwner = .{};
    var file: TestFile = undefined;
    try harness.open(&file, &owner);
    for (0..24) |_| {
        const length = random.uintAtMost(usize, image.len);
        for (image[0..length]) |*byte| byte.* = 'a' + random.uintLessThan(u8, 26);
        owner.image = image[0..length];
        const saves = file.stats.saves;
        file.save();
        harness.world.run_for_ns(random.uintAtMost(u64, 3) * ns_per_ms);
        if (file.stats.saves > saves) durable = copy(&durable_storage, owner.image);
        if (random.uintLessThan(u8, 4) == 0) {
            harness.io.crash();
            testing.allocator.free(file.buffer);
            try harness.open(&file, &owner);
            try testing.expectEqualStrings(durable, owner.loaded.?);
        } else {
            while (file.phase != .idle) harness.world.run_for_ns(ns_per_ms);
            if (file.stats.saves > saves) durable = copy(&durable_storage, owner.image);
        }
    }
    harness.close(&file);
}

fn copy(storage: []u8, source: []const u8) []const u8 {
    @memcpy(storage[0..source.len], source);
    return storage[0..source.len];
}

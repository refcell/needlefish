//! Sector storage over `utilities.io` (io_uring, kqueue, or the IO simulator).
//!
//! `IoStorageType(IO)` implements the `Storage` interface from `storage.zig` on one file
//! descriptor that the caller has already opened (and owns). It does positional reads and
//! writes plus a full `fsync` barrier through the completion-based IO backend.
//!
//! Design:
//! - In-flight operations are bounded by `Options.operations_max`. Each one borrows an IO
//!   completion from a pool allocated at `init`. When the pool is empty, the caller's
//!   storage completion waits in an intrusive FIFO, so submission never fails or allocates.
//! - Short reads and writes resubmit the remainder on the same IO completion. A read that
//!   returns 0 hit the end of the file: the rest of the buffer is zero-filled, because bytes
//!   past the end were never written (the file may be sparse or shorter than `size_bytes`).
//! - IO callbacks only record the outcome and queue the storage completion. Storage callbacks
//!   run only from `tick()`, never from a submit call or from another component's IO tick.
//! - Read errors are retried `read_retries_max` times, then the remainder is zero-filled.
//!   Every engine structure is checksummed, so a failed read surfaces as a corrupt sector
//!   that the engine already handles (other superblock copy, journal stop).
//! - Write errors are retried `write_retries_max` times and then panic. Fsync errors panic
//!   at once: after a failed fsync the kernel may have dropped dirty pages, so a retry could
//!   report success for lost data. A crashed node is better than a corrupted one.
//! - `sync` is a full fsync (data and file size), which on Darwin is `F_FULLFSYNC`. It is
//!   submitted only after every write whose storage callback already fired has completed in
//!   the kernel, so it covers all of them, as `storage.zig` requires.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const io_common = @import("../../../utilities/io/common.zig");

const sector_size = storage.sector_size;
const Completion = storage.Completion;
const Read = storage.Read;
const Write = storage.Write;
const Sync = storage.Sync;

pub const Options = struct {
    /// Bytes addressable through this storage. The file may be shorter (reads past its end
    /// return zeros, writes extend it) but must never be longer in use.
    size_bytes: u64,
    /// Upper bound on operations submitted to the IO backend at once.
    operations_max: u32 = 64,
    read_retries_max: u32 = 4,
    write_retries_max: u32 = 4,
};

/// An intrusive FIFO of storage completions linked through `Completion.next`.
const Queue = struct {
    head: ?*Completion = null,
    tail: ?*Completion = null,
    count: u32 = 0,

    fn push(queue: *Queue, completion: *Completion) void {
        assert(completion.next == null);
        assert((queue.head == null) == (queue.count == 0));
        if (queue.tail) |tail| tail.next = completion else queue.head = completion;
        queue.tail = completion;
        queue.count += 1;
    }

    fn pop(queue: *Queue) ?*Completion {
        const completion = queue.head orelse return null;
        assert(queue.count > 0);
        queue.head = completion.next;
        if (queue.head == null) queue.tail = null;
        completion.next = null;
        queue.count -= 1;
        return completion;
    }
};

pub fn IoStorageType(comptime IO: type) type {
    return struct {
        const Self = @This();

        pub const Fd = IO.Fd;

        pub const Stats = struct {
            reads: u64 = 0,
            writes: u64 = 0,
            syncs: u64 = 0,
            /// Resubmissions after a short (partial) read or write.
            short_resubmits: u64 = 0,
            read_retries: u64 = 0,
            write_retries: u64 = 0,
            /// Bytes zero-filled because of end of file or exhausted read retries.
            read_zero_filled_bytes: u64 = 0,
        };

        /// One borrowed IO operation: the IO completion plus progress on the storage op.
        const Iop = struct {
            io_completion: IO.Completion = .{},
            self: *Self = undefined,
            completion: ?*Completion = null,
            /// Bytes of the storage buffer already transferred.
            done_bytes: u64 = 0,
            retries: u32 = 0,
        };

        io: *IO,
        fd: Fd,
        options: Options,
        iops: []Iop,
        /// Indexes of free entries in `iops`, used as a stack.
        iops_free: []u32,
        iops_free_count: u32,
        waiting: Queue = .{},
        ready: Queue = .{},
        stats: Stats = .{},

        /// Allocates the operation pool. `io` and `fd` must outlive the storage; the caller
        /// keeps ownership of `fd`. `self` must not move once an operation is submitted.
        pub fn init(allocator: std.mem.Allocator, io: *IO, fd: Fd, options: Options) !Self {
            assert(options.size_bytes > 0);
            assert(options.size_bytes % sector_size == 0);
            assert(options.operations_max > 0);
            const iops = try allocator.alloc(Iop, options.operations_max);
            errdefer allocator.free(iops);
            const iops_free = try allocator.alloc(u32, options.operations_max);
            for (iops, iops_free, 0..) |*iop, *free, index| {
                iop.* = .{};
                free.* = @intCast(index);
            }
            return .{
                .io = io,
                .fd = fd,
                .options = options,
                .iops = iops,
                .iops_free = iops_free,
                .iops_free_count = options.operations_max,
            };
        }

        /// Frees the pool. Operations may be in flight only if the IO backend dropped them
        /// (a simulated crash); their callbacks never fire.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(self.iops.len == self.iops_free.len);
            allocator.free(self.iops);
            allocator.free(self.iops_free);
            self.* = undefined;
        }

        pub fn size_bytes(self: *const Self) u64 {
            return self.options.size_bytes;
        }

        /// True when no operation is in flight, waiting, or awaiting its callback.
        pub fn idle(self: *const Self) bool {
            const in_flight = self.options.operations_max - self.iops_free_count;
            return in_flight == 0 and self.waiting.count == 0 and self.ready.count == 0;
        }

        pub fn read_sectors(
            self: *Self,
            callback: *const fn (*Read) void,
            read: *Read,
            buffer: []u8,
            offset: u64,
        ) void {
            self.assert_range(offset, buffer.len);
            self.assert_no_write_overlap(offset, buffer.len);
            read.* = .{ .callback = callback, .buffer = buffer, .offset = offset };
            read.completion.operation = .read;
            self.stats.reads += 1;
            self.submit(&read.completion);
        }

        /// Reads at once with blocking positional reads (`IO.read_now`): short reads continue,
        /// errors retry `read_retries_max` times, then `error.ReadFailed`. Past the end of the
        /// file reads as zeros, as `read_sectors` does.
        pub fn read_sectors_sync(self: *Self, buffer: []u8, offset: u64) error{ReadFailed}!void {
            self.assert_range(offset, buffer.len);
            self.assert_no_write_overlap(offset, buffer.len);
            self.stats.reads += 1;
            var done: usize = 0;
            var retries: u32 = 0;
            var calls: u64 = 0;
            // Bounded: each call reads at least one byte, or retries, or ends the read.
            while (done < buffer.len) : (calls += 1) {
                assert(calls <= buffer.len + self.options.read_retries_max);
                const rest = buffer[done..];
                const size = self.io.read_now(self.fd, rest, offset + done) catch {
                    if (retries == self.options.read_retries_max) return error.ReadFailed;
                    retries += 1;
                    self.stats.read_retries += 1;
                    continue;
                };
                assert(size <= rest.len);
                if (size == 0) {
                    @memset(rest, 0);
                    self.stats.read_zero_filled_bytes += rest.len;
                    break;
                }
                if (done + size < buffer.len) self.stats.short_resubmits += 1;
                done += size;
            }
        }

        pub fn write_sectors(
            self: *Self,
            callback: *const fn (*Write) void,
            write: *Write,
            buffer: []const u8,
            offset: u64,
        ) void {
            self.assert_range(offset, buffer.len);
            self.assert_no_write_overlap(offset, buffer.len);
            write.* = .{ .callback = callback, .buffer = buffer, .offset = offset };
            write.completion.operation = .write;
            self.stats.writes += 1;
            self.submit(&write.completion);
        }

        pub fn sync(self: *Self, callback: *const fn (*Sync) void, sync_: *Sync) void {
            sync_.* = .{ .callback = callback };
            sync_.completion.operation = .sync;
            self.stats.syncs += 1;
            self.submit(&sync_.completion);
        }

        /// Drives the IO backend without blocking, starts waiting operations, then runs the
        /// callbacks of every operation that had finished when the tick began delivering.
        pub fn tick(self: *Self) void {
            self.io.tick() catch |err| std.debug.panic("io_storage: io tick: {t}", .{err});
            self.process();
        }

        /// The part of `tick` that does not run the IO loop: submits waiting operations
        /// and delivers finished ones. Safe to call from inside an IO callback (where a
        /// re-entrant `io.tick` is not).
        pub fn process(self: *Self) void {
            self.dispatch_waiting();
            // Detach first: callbacks may submit, and those complete in a later tick.
            var ready = self.ready;
            self.ready = .{};
            const count = ready.count;
            var delivered: u32 = 0;
            while (ready.pop()) |completion| : (delivered += 1) {
                assert(delivered < count);
                deliver(completion);
            }
            assert(delivered == count);
            assert(ready.count == 0);
        }

        fn deliver(completion: *Completion) void {
            assert(completion.next == null);
            switch (completion.operation) {
                .read => {
                    const read: *Read = @fieldParentPtr("completion", completion);
                    read.callback(read);
                },
                .write => {
                    const write: *Write = @fieldParentPtr("completion", completion);
                    write.callback(write);
                },
                .sync => {
                    const sync_: *Sync = @fieldParentPtr("completion", completion);
                    sync_.callback(sync_);
                },
            }
        }

        fn submit(self: *Self, completion: *Completion) void {
            assert(completion.next == null);
            // FIFO: never overtake an operation already waiting for an IO completion.
            if (self.waiting.count > 0 or self.iops_free_count == 0) {
                self.waiting.push(completion);
                return;
            }
            self.start(completion);
        }

        fn dispatch_waiting(self: *Self) void {
            const count = self.waiting.count;
            var started: u32 = 0;
            while (self.iops_free_count > 0) : (started += 1) {
                assert(started <= count);
                const completion = self.waiting.pop() orelse break;
                self.start(completion);
            }
        }

        fn start(self: *Self, completion: *Completion) void {
            assert(self.iops_free_count > 0);
            self.iops_free_count -= 1;
            const iop = &self.iops[self.iops_free[self.iops_free_count]];
            assert(iop.completion == null);
            iop.* = .{ .self = self, .completion = completion };
            self.issue(iop);
        }

        /// Submits the remaining part of the operation on `iop` to the IO backend.
        fn issue(self: *Self, iop: *Iop) void {
            const completion = iop.completion.?;
            switch (completion.operation) {
                .read => {
                    const read: *Read = @fieldParentPtr("completion", completion);
                    assert(iop.done_bytes < read.buffer.len);
                    const rest = read.buffer[@intCast(iop.done_bytes)..];
                    const offset = read.offset + iop.done_bytes;
                    self.io.read(*Iop, iop, on_read, &iop.io_completion, self.fd, rest, offset);
                },
                .write => {
                    const write: *Write = @fieldParentPtr("completion", completion);
                    assert(iop.done_bytes < write.buffer.len);
                    const rest = write.buffer[@intCast(iop.done_bytes)..];
                    const offset = write.offset + iop.done_bytes;
                    self.io.write(*Iop, iop, on_write, &iop.io_completion, self.fd, rest, offset);
                },
                .sync => {
                    assert(iop.done_bytes == 0);
                    self.io.fsync(*Iop, iop, on_fsync, &iop.io_completion, self.fd);
                },
            }
        }

        fn on_read(
            iop: *Iop,
            io_completion: *IO.Completion,
            result: io_common.ResultType(Fd, .read),
        ) void {
            assert(io_completion == &iop.io_completion);
            const self = iop.self;
            const read: *Read = @fieldParentPtr("completion", iop.completion.?);
            const remaining = read.buffer.len - iop.done_bytes;
            assert(remaining > 0);
            const size = result catch {
                if (iop.retries < self.options.read_retries_max) {
                    iop.retries += 1;
                    self.stats.read_retries += 1;
                    return self.issue(iop);
                }
                return self.read_zero_fill(iop, read);
            };
            assert(size <= remaining);
            if (size == 0) return self.read_zero_fill(iop, read);
            iop.done_bytes += size;
            if (iop.done_bytes == read.buffer.len) return self.finish(iop);
            self.stats.short_resubmits += 1;
            self.issue(iop);
        }

        /// Zeros the unread rest of the buffer: past the end of file, or unreadable.
        fn read_zero_fill(self: *Self, iop: *Iop, read: *Read) void {
            assert(iop.done_bytes < read.buffer.len);
            const rest = read.buffer[@intCast(iop.done_bytes)..];
            @memset(rest, 0);
            self.stats.read_zero_filled_bytes += rest.len;
            iop.done_bytes = read.buffer.len;
            self.finish(iop);
        }

        fn on_write(
            iop: *Iop,
            io_completion: *IO.Completion,
            result: io_common.ResultType(Fd, .write),
        ) void {
            assert(io_completion == &iop.io_completion);
            const self = iop.self;
            const write: *Write = @fieldParentPtr("completion", iop.completion.?);
            const remaining = write.buffer.len - iop.done_bytes;
            assert(remaining > 0);
            // A zero-byte write makes no progress: treat it like an error so it is bounded.
            const size = result catch 0;
            assert(size <= remaining);
            if (size == 0) {
                if (iop.retries >= self.options.write_retries_max) {
                    const err: anyerror = if (result) |_| error.WriteZero else |err| err;
                    std.debug.panic("io_storage: write at {d}: {t}", .{ write.offset, err });
                }
                iop.retries += 1;
                self.stats.write_retries += 1;
                return self.issue(iop);
            }
            iop.done_bytes += size;
            if (iop.done_bytes == write.buffer.len) return self.finish(iop);
            self.stats.short_resubmits += 1;
            self.issue(iop);
        }

        fn on_fsync(
            iop: *Iop,
            io_completion: *IO.Completion,
            result: io_common.ResultType(Fd, .fsync),
        ) void {
            assert(io_completion == &iop.io_completion);
            assert(iop.completion.?.operation == .sync);
            result catch |err| std.debug.panic("io_storage: fsync: {t}", .{err});
            iop.self.finish(iop);
        }

        /// Returns the IO completion to the pool and queues the storage callback for `tick`.
        fn finish(self: *Self, iop: *Iop) void {
            const completion = iop.completion.?;
            iop.completion = null;
            assert(self.iops_free_count < self.options.operations_max);
            const index: u32 = @intCast(iop - self.iops.ptr);
            self.iops_free[self.iops_free_count] = index;
            self.iops_free_count += 1;
            self.ready.push(completion);
        }

        fn assert_range(self: *const Self, offset: u64, length: u64) void {
            storage.assert_aligned(offset, length);
            assert(offset + length <= self.options.size_bytes);
        }

        /// The interface forbids overlapping a pending write: checks every submitted
        /// operation (bounded by the pool) and every waiting one (bounded by its count).
        fn assert_no_write_overlap(self: *const Self, offset: u64, length: u64) void {
            for (self.iops) |*iop| {
                if (iop.completion) |completion| assert_disjoint(completion, offset, length);
            }
            var cursor = self.waiting.head;
            var scanned: u32 = 0;
            while (cursor) |completion| : (scanned += 1) {
                assert(scanned < self.waiting.count);
                assert_disjoint(completion, offset, length);
                cursor = completion.next;
            }
        }

        fn assert_disjoint(completion: *Completion, offset: u64, length: u64) void {
            assert(length > 0);
            if (completion.operation != .write) return;
            const write: *const Write = @fieldParentPtr("completion", completion);
            const disjoint = offset + length <= write.offset or
                write.offset + write.buffer.len <= offset;
            assert(disjoint);
        }

        comptime {
            storage.assert_interface(Self);
        }
    };
}

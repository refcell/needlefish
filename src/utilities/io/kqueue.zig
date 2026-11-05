//! kqueue IO backend (macOS and BSDs).
//!
//! Operations are attempted immediately with non-blocking syscalls. When one would block,
//! its completion is parked and a one-shot kevent registers interest in the descriptor;
//! when kevent reports readiness the operation is retried. Disk operations run
//! synchronously (kqueue has no async file IO), which is acceptable for the dev platform.
//! Timeouts live in an intrusive list scanned on each tick; the earliest expiry bounds the
//! kevent wait. Completions finish only from `tick`/`run_for_ns`, never inline.

const std = @import("std");
const assert = std.debug.assert;

const common = @import("common.zig");
const os = @import("os.zig");

pub const Address = common.Address;

const events_max = 256;
const loop_iterations_max = 1 << 20;

const supported = os.is_darwin or switch (@import("builtin").os.tag) {
    .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

pub const Kqueue = if (supported) KqueueImpl else struct {
    pub const Fd = i32;
    pub const unsupported = true;
};

/// A FIFO of completions threaded through `Completion.next`.
fn Queue(comptime Completion: type) type {
    return struct {
        head: ?*Completion = null,
        tail: ?*Completion = null,
        count: u32 = 0,

        const Self = @This();

        fn push(queue: *Self, completion: *Completion) void {
            assert(completion.next == null);
            if (queue.tail) |tail| tail.next = completion else queue.head = completion;
            queue.tail = completion;
            queue.count += 1;
        }

        fn pop(queue: *Self) ?*Completion {
            const completion = queue.head orelse return null;
            queue.head = completion.next;
            if (queue.head == null) queue.tail = null;
            completion.next = null;
            queue.count -= 1;
            return completion;
        }
    };
}

const KqueueImpl = struct {
    pub const Fd = os.fd_t;
    pub const Completion = struct {
        pub const Fd = os.fd_t;
        operation: common.Operation(os.fd_t) = .none,
        result: common.Result(os.fd_t) = .none,
        context: ?*anyopaque = null,
        callback: *const fn (?*anyopaque, *Completion) void = undefined,
        next: ?*Completion = null,
    };

    const methods = common.Methods(KqueueImpl);
    pub const accept = methods.accept;
    pub const connect = methods.connect;
    pub const recv = methods.recv;
    pub const send = methods.send;
    pub const read = methods.read;
    pub const write = methods.write;
    pub const fsync = methods.fsync;
    pub const timeout = methods.timeout;
    pub const close = methods.close;

    kq: Fd,
    /// Operations ready to attempt (new or woken by readiness).
    unqueued: Queue(Completion) = .{},
    /// Operations finished, waiting for their callback.
    completed: Queue(Completion) = .{},
    /// Pending timeouts.
    timeouts: Queue(Completion) = .{},
    /// Operations parked on a kevent; the kernel holds pointers to them.
    parked_count: u32 = 0,
    /// Kevents to register on the next kevent call.
    changes: [events_max]os.system.Kevent = undefined,
    changes_count: u32 = 0,

    pub fn init() !KqueueImpl {
        const rc = os.system.kqueue();
        if (os.errno(rc) != .SUCCESS) return error.SystemResources;
        assert(rc >= 0);
        return .{ .kq = rc };
    }

    pub fn deinit(io: *KqueueImpl) void {
        assert(io.kq >= 0);
        os.close(io.kq);
        io.* = undefined;
    }

    pub fn now_monotonic_ns(io: *const KqueueImpl) u64 {
        _ = io;
        return os.monotonic_ns();
    }

    pub fn now_realtime_ns(io: *const KqueueImpl) u64 {
        _ = io;
        return os.realtime_ns();
    }

    pub fn open_socket_tcp(io: *KqueueImpl, family: Address.Family) common.SetupError!Fd {
        _ = io;
        return os.socket_tcp(family, .nonblocking);
    }

    pub fn listen(
        io: *KqueueImpl,
        fd: Fd,
        address: Address,
        backlog: u31,
    ) common.SetupError!Address {
        _ = io;
        return os.listen(fd, address, backlog);
    }

    pub fn open_file(
        io: *KqueueImpl,
        path: []const u8,
        mode: common.OpenMode,
    ) common.SetupError!Fd {
        _ = io;
        return os.open_file(path, mode);
    }

    /// Shuts down both directions; pending recvs complete with 0. Close with `close_now`
    /// once in-flight operations on `fd` have completed.
    pub fn shutdown_now(io: *KqueueImpl, fd: Fd) void {
        _ = io;
        os.shutdown(fd);
    }

    pub fn close_now(io: *KqueueImpl, fd: Fd) void {
        _ = io;
        os.close(fd);
    }

    pub fn enqueue(io: *KqueueImpl, completion: *Completion) void {
        assert(completion.operation != .none);
        if (completion.operation == .timeout) {
            io.timeouts.push(completion);
        } else {
            io.unqueued.push(completion);
        }
    }

    /// Runs ready work without blocking.
    pub fn tick(io: *KqueueImpl) !void {
        try io.flush(.nonblocking, null);
    }

    /// Runs the event loop until `duration_ns` of monotonic time has passed.
    pub fn run_for_ns(io: *KqueueImpl, duration_ns: u64) !void {
        const deadline_ns = os.monotonic_ns() +| duration_ns;
        var iterations: u32 = 0;
        while (iterations < loop_iterations_max) : (iterations += 1) {
            const now_ns = os.monotonic_ns();
            if (now_ns >= deadline_ns) break;
            try io.flush(.blocking, deadline_ns);
        }
        try io.flush(.nonblocking, null);
    }

    const Wait = enum { blocking, nonblocking };

    fn flush(io: *KqueueImpl, wait: Wait, deadline_ns: ?u64) !void {
        io.attempt_unqueued();
        io.expire_timeouts();
        const must_wait = wait == .blocking and io.completed.count == 0;
        try io.poll(if (must_wait) io.wait_ns(deadline_ns) else 0);
        io.attempt_unqueued();
        io.expire_timeouts();
        io.run_completed();
    }

    fn wait_ns(io: *KqueueImpl, deadline_ns: ?u64) u64 {
        const now_ns = os.monotonic_ns();
        var wake_ns: u64 = deadline_ns orelse now_ns;
        var cursor = io.timeouts.head;
        while (cursor) |completion| : (cursor = completion.next) {
            wake_ns = @min(wake_ns, completion.operation.timeout.expires_ns);
        }
        return if (wake_ns > now_ns) wake_ns - now_ns else 0;
    }

    fn poll(io: *KqueueImpl, timeout_ns: u64) !void {
        var events: [events_max]os.system.Kevent = undefined;
        const ts: std.posix.timespec = .{
            .sec = @intCast(timeout_ns / std.time.ns_per_s),
            .nsec = @intCast(timeout_ns % std.time.ns_per_s),
        };
        const rc = os.system.kevent(
            io.kq,
            &io.changes,
            @intCast(io.changes_count),
            &events,
            events.len,
            &ts,
        );
        switch (os.errno(rc)) {
            .SUCCESS => {},
            .INTR => return,
            else => return error.Unexpected,
        }
        io.changes_count = 0;
        const count: usize = @intCast(rc);
        assert(count <= events.len);
        for (events[0..count]) |event| {
            const completion: *Completion = @ptrFromInt(event.udata);
            assert(io.parked_count > 0);
            io.parked_count -= 1;
            io.unqueued.push(completion);
        }
    }

    fn attempt_unqueued(io: *KqueueImpl) void {
        // Bounded by the count at entry: retries that park again are not re-examined.
        var budget = io.unqueued.count;
        while (budget > 0) : (budget -= 1) {
            const completion = io.unqueued.pop().?;
            if (io.attempt(completion)) {
                io.completed.push(completion);
            } else {
                io.park(completion);
            }
        }
    }

    fn park(io: *KqueueImpl, completion: *Completion) void {
        const read_filter: i16 = os.system.EVFILT.READ;
        const write_filter: i16 = os.system.EVFILT.WRITE;
        const fd: Fd, const filter: i16 = switch (completion.operation) {
            .accept => |op| .{ op.socket, read_filter },
            .recv => |op| .{ op.socket, read_filter },
            .connect => |op| .{ op.socket, write_filter },
            .send => |op| .{ op.socket, write_filter },
            else => unreachable, // Only socket operations can block.
        };
        if (io.changes_count == io.changes.len) {
            // Change list full: retry next tick instead of dropping the operation.
            io.unqueued.push(completion);
            return;
        }
        io.changes[io.changes_count] = .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = os.system.EV.ADD | os.system.EV.ENABLE | os.system.EV.ONESHOT,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(completion),
        };
        io.changes_count += 1;
        io.parked_count += 1;
    }

    fn expire_timeouts(io: *KqueueImpl) void {
        const now_ns = os.monotonic_ns();
        var budget = io.timeouts.count;
        while (budget > 0) : (budget -= 1) {
            const completion = io.timeouts.pop().?;
            if (completion.operation.timeout.expires_ns <= now_ns) {
                completion.result = .{ .timeout = {} };
                io.completed.push(completion);
            } else {
                io.timeouts.push(completion);
            }
        }
    }

    fn run_completed(io: *KqueueImpl) void {
        // Callbacks may enqueue new work; only those completed at entry run now.
        var budget = io.completed.count;
        while (budget > 0) : (budget -= 1) {
            const completion = io.completed.pop().?;
            common.complete(Completion, completion);
        }
    }

    /// Attempts an operation. Returns true when it finished (result stored).
    fn attempt(io: *KqueueImpl, completion: *Completion) bool {
        _ = io;
        switch (completion.operation) {
            .none, .timeout => unreachable,
            .accept => |op| return attempt_accept(completion, op.socket),
            .connect => |*op| return attempt_connect(completion, op),
            .recv => |op| {
                const rc = os.system.recv(op.socket, op.buffer.ptr, op.buffer.len, 0);
                const err = os.errno(rc);
                if (err == .AGAIN or err == .INTR) return false;
                completion.result = .{ .recv = if (err == .SUCCESS)
                    @intCast(rc)
                else
                    os.recv_error(err) };
            },
            .send => |op| {
                const rc = os.system.send(op.socket, op.buffer.ptr, op.buffer.len, 0);
                const err = os.errno(rc);
                if (err == .AGAIN or err == .INTR) return false;
                completion.result = .{ .send = if (err == .SUCCESS)
                    @intCast(rc)
                else
                    os.send_error(err) };
            },
            .read => |op| completion.result = .{ .read = do_read(op.fd, op.buffer, op.offset) },
            .write => |op| completion.result = .{ .write = do_write(op.fd, op.buffer, op.offset) },
            .fsync => |op| completion.result = .{ .fsync = do_fsync(op.fd) },
            .close => |op| {
                os.close(op.fd);
                completion.result = .{ .close = {} };
            },
        }
        return true;
    }

    fn attempt_accept(completion: *Completion, socket: Fd) bool {
        const rc = os.system.accept(socket, null, null);
        const err = os.errno(rc);
        if (err == .AGAIN or err == .INTR) return false;
        if (err != .SUCCESS) {
            completion.result = .{ .accept = os.accept_error(err) };
            return true;
        }
        const fd: Fd = rc;
        completion.result = .{ .accept = configure_accepted(fd) };
        return true;
    }

    fn configure_accepted(fd: Fd) common.AcceptError!Fd {
        errdefer os.close(fd);
        // Accepted sockets do not inherit O_NONBLOCK reliably across platforms; set it.
        const flags = os.system.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
        if (flags < 0) return error.Unexpected;
        const nonblock: c_int = @bitCast(std.posix.O{ .NONBLOCK = true });
        if (os.system.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0) return error.Unexpected;
        if (os.system.fcntl(fd, std.posix.F.SETFD, @as(c_int, std.posix.FD_CLOEXEC)) < 0) {
            return error.Unexpected;
        }
        if (os.is_darwin) {
            os.setsockopt_int(fd, std.posix.SOL.SOCKET, std.posix.SO.NOSIGPIPE, 1) catch
                return error.SystemResources;
        }
        os.setsockopt_int(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, 1) catch
            return error.SystemResources;
        return fd;
    }

    fn attempt_connect(completion: *Completion, op: anytype) bool {
        if (op.initiated) {
            // Woken by EVFILT_WRITE: read the outcome from SO_ERROR.
            var value: c_int = 0;
            var len: os.socklen_t = @sizeOf(c_int);
            const rc = os.system.getsockopt(
                op.socket,
                std.posix.SOL.SOCKET,
                std.posix.SO.ERROR,
                &value,
                &len,
            );
            if (os.errno(rc) != .SUCCESS) {
                completion.result = .{ .connect = error.Unexpected };
                return true;
            }
            const err: os.E = @fromBackingInt(@intCast(value));
            completion.result = .{ .connect = if (err == .SUCCESS) {} else os.connect_error(err) };
            return true;
        }
        var sock_addr = os.SockAddr.from(op.address);
        const rc = os.system.connect(op.socket, &sock_addr.any, os.SockAddr.len(op.address));
        const err = os.errno(rc);
        if (err == .INPROGRESS or err == .AGAIN or err == .INTR) {
            op.initiated = true;
            return false;
        }
        completion.result = .{ .connect = if (err == .SUCCESS) {} else os.connect_error(err) };
        return true;
    }

    fn do_read(fd: Fd, buffer: []u8, offset: u64) common.ReadError!usize {
        var iterations: u32 = 0;
        while (iterations < 64) : (iterations += 1) {
            const rc = os.system.pread(fd, buffer.ptr, buffer.len, @intCast(offset));
            const err = os.errno(rc);
            if (err == .INTR) continue;
            if (err != .SUCCESS) return os.read_error(err);
            return @intCast(rc);
        }
        return error.Unexpected;
    }

    fn do_write(fd: Fd, buffer: []const u8, offset: u64) common.WriteError!usize {
        var iterations: u32 = 0;
        while (iterations < 64) : (iterations += 1) {
            const rc = os.system.pwrite(fd, buffer.ptr, buffer.len, @intCast(offset));
            const err = os.errno(rc);
            if (err == .INTR) continue;
            if (err != .SUCCESS) return os.write_error(err);
            return @intCast(rc);
        }
        return error.Unexpected;
    }

    fn do_fsync(fd: Fd) common.FsyncError!void {
        // F_FULLFSYNC flushes the drive cache on Darwin; plain fsync does not.
        if (os.is_darwin) {
            const rc = os.system.fcntl(fd, std.posix.F.FULLFSYNC, @as(c_int, 0));
            if (os.errno(rc) == .SUCCESS) return;
        }
        const rc = os.system.fsync(fd);
        const err = os.errno(rc);
        if (err != .SUCCESS) return os.fsync_error(err);
    }
};

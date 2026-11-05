//! io_uring IO backend (Linux).
//!
//! One ring per `IoUring`. Operations become SQEs and are submitted in batches on each
//! `tick`/`run_for_ns`, so a burst of operations costs one `io_uring_enter`. If the SQ is
//! full, completions wait in an overflow queue and are retried after the next submit.
//! Timeouts use absolute `IORING_OP_TIMEOUT` on CLOCK_MONOTONIC, matching
//! `now_monotonic_ns`. Callbacks run only after their CQE is reaped, from `tick` or
//! `run_for_ns`. Each completion stores the kernel-visible arguments (timespec, sockaddr)
//! inline so they stay valid while the kernel holds the SQE.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const common = @import("common.zig");
const os = @import("os.zig");

pub const Address = common.Address;

pub const IoUring = if (builtin.os.tag == .linux) LinuxIoUring else struct {
    pub const Fd = i32;
    pub const unsupported = true;
};

const linux = std.os.linux;
const entries_default = 256;
const cqes_batch_max = 256;
const loop_iterations_max = 1 << 20;

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

const LinuxIoUring = struct {
    pub const Fd = os.fd_t;
    pub const Completion = struct {
        pub const Fd = os.fd_t;
        operation: common.Operation(os.fd_t) = .none,
        result: common.Result(os.fd_t) = .none,
        context: ?*anyopaque = null,
        callback: *const fn (?*anyopaque, *Completion) void = undefined,
        next: ?*Completion = null,
        timespec: linux.kernel_timespec = undefined,
        sock_addr: os.SockAddr = undefined,
    };

    const methods = common.Methods(LinuxIoUring);
    pub const accept = methods.accept;
    pub const connect = methods.connect;
    pub const recv = methods.recv;
    pub const send = methods.send;
    pub const read = methods.read;
    pub const write = methods.write;
    pub const fsync = methods.fsync;
    pub const timeout = methods.timeout;
    pub const close = methods.close;

    ring: linux.IoUring,
    /// Operations that did not fit in the SQ.
    unqueued: Queue(Completion) = .{},
    /// Reaped completions waiting for their callback.
    completed: Queue(Completion) = .{},
    /// SQEs submitted to the kernel whose CQE has not been reaped.
    in_kernel: u32 = 0,

    pub const Options = struct { entries: u16 = entries_default };

    pub fn init(options: Options) !LinuxIoUring {
        assert(std.math.isPowerOfTwo(options.entries));
        const flags = linux.IORING_SETUP_CLAMP;
        const ring = linux.IoUring.init(options.entries, flags) catch |err| switch (err) {
            // Disabled by sysctl, seccomp, or an LSM (EPERM/EACCES), or a pre-5.1 kernel.
            error.PermissionDenied, error.SystemOutdated, error.Unexpected => {
                return error.IoUringUnavailable;
            },
            else => return err,
        };
        assert(ring.fd >= 0);
        return .{ .ring = ring };
    }

    pub fn deinit(io: *LinuxIoUring) void {
        io.ring.deinit();
        io.* = undefined;
    }

    pub fn now_monotonic_ns(io: *const LinuxIoUring) u64 {
        _ = io;
        return os.monotonic_ns();
    }

    pub fn now_realtime_ns(io: *const LinuxIoUring) u64 {
        _ = io;
        return os.realtime_ns();
    }

    pub fn open_socket_tcp(io: *LinuxIoUring, family: Address.Family) common.SetupError!Fd {
        _ = io;
        // io_uring drives blocking sockets asynchronously; no O_NONBLOCK needed.
        return os.socket_tcp(family, .blocking);
    }

    pub fn listen(
        io: *LinuxIoUring,
        fd: Fd,
        address: Address,
        backlog: u31,
    ) common.SetupError!Address {
        _ = io;
        return os.listen(fd, address, backlog);
    }

    pub fn open_file(
        io: *LinuxIoUring,
        path: []const u8,
        mode: common.OpenMode,
    ) common.SetupError!Fd {
        _ = io;
        return os.open_file(path, mode);
    }

    /// Shuts down both directions; pending recvs complete with 0. Close with `close_now`
    /// once in-flight operations on `fd` have completed.
    pub fn shutdown_now(io: *LinuxIoUring, fd: Fd) void {
        _ = io;
        os.shutdown(fd);
    }

    pub fn close_now(io: *LinuxIoUring, fd: Fd) void {
        _ = io;
        os.close(fd);
    }

    pub fn enqueue(io: *LinuxIoUring, completion: *Completion) void {
        assert(completion.operation != .none);
        io.prepare(completion) catch |err| switch (err) {
            error.SubmissionQueueFull => io.unqueued.push(completion),
        };
    }

    /// Submits queued SQEs and runs callbacks for whatever has completed, without waiting.
    pub fn tick(io: *LinuxIoUring) !void {
        try io.flush(0);
        io.run_completed();
    }

    /// Runs the loop until `duration_ns` of monotonic time has passed.
    pub fn run_for_ns(io: *LinuxIoUring, duration_ns: u64) !void {
        var done = false;
        var deadline: Completion = .{};
        io.timeout(*bool, &done, on_deadline, &deadline, duration_ns);
        var iterations: u32 = 0;
        while (!done and iterations < loop_iterations_max) : (iterations += 1) {
            try io.flush(if (io.completed.count == 0) 1 else 0);
            io.run_completed();
        }
        assert(done);
    }

    fn on_deadline(done: *bool, completion: *Completion, result: common.TimeoutError!void) void {
        _ = completion;
        result catch unreachable; // The deadline timeout is never canceled.
        done.* = true;
    }

    fn flush(io: *LinuxIoUring, wait_nr: u32) !void {
        const submitted = io.ring.submit_and_wait(wait_nr) catch |err| switch (err) {
            error.SignalInterrupt => 0,
            error.CompletionQueueOvercommitted, error.SystemResources => 0,
            else => return err,
        };
        io.in_kernel += submitted;
        io.reap();
        // Retry overflowed operations now that SQ space has been freed.
        var budget = io.unqueued.count;
        while (budget > 0) : (budget -= 1) {
            const completion = io.unqueued.pop().?;
            io.prepare(completion) catch {
                io.unqueued.push(completion);
                break;
            };
        }
    }

    fn reap(io: *LinuxIoUring) void {
        var cqes: [cqes_batch_max]linux.io_uring_cqe = undefined;
        var rounds: u32 = 0;
        while (rounds < loop_iterations_max) : (rounds += 1) {
            const count = io.ring.copy_cqes(&cqes, 0) catch return;
            if (count == 0) return;
            for (cqes[0..count]) |cqe| {
                const completion: *Completion = @ptrFromInt(cqe.user_data);
                assert(io.in_kernel > 0);
                io.in_kernel -= 1;
                io.store_result(completion, cqe);
            }
        }
    }

    fn run_completed(io: *LinuxIoUring) void {
        var budget = io.completed.count;
        while (budget > 0) : (budget -= 1) {
            common.complete(Completion, io.completed.pop().?);
        }
    }

    fn prepare(io: *LinuxIoUring, completion: *Completion) error{SubmissionQueueFull}!void {
        const user_data = @intFromPtr(completion);
        const ring = &io.ring;
        _ = switch (completion.operation) {
            .none => unreachable,
            .accept => |op| try ring.accept(user_data, op.socket, null, null, linux.SOCK.CLOEXEC),
            .connect => |op| blk: {
                completion.sock_addr = os.SockAddr.from(op.address);
                const len = os.SockAddr.len(op.address);
                break :blk try ring.connect(user_data, op.socket, &completion.sock_addr.any, len);
            },
            .recv => |op| try ring.recv(user_data, op.socket, .{ .buffer = op.buffer }, 0),
            .send => |op| try ring.send(user_data, op.socket, op.buffer, linux.MSG.NOSIGNAL),
            .read => |op| try ring.read(user_data, op.fd, .{ .buffer = op.buffer }, op.offset),
            .write => |op| try ring.write(user_data, op.fd, op.buffer, op.offset),
            .fsync => |op| try ring.fsync(user_data, op.fd, 0),
            .timeout => |op| blk: {
                completion.timespec = .{
                    .sec = @intCast(op.expires_ns / std.time.ns_per_s),
                    .nsec = @intCast(op.expires_ns % std.time.ns_per_s),
                };
                const flags = linux.IORING_TIMEOUT_ABS;
                break :blk try ring.timeout(user_data, &completion.timespec, 0, flags);
            },
            .close => |op| try ring.close(user_data, op.fd),
        };
    }

    fn store_result(io: *LinuxIoUring, completion: *Completion, cqe: linux.io_uring_cqe) void {
        const err = cqe.err();
        if (err == .INTR or (err == .AGAIN and completion.operation != .timeout)) {
            // Interrupted or spuriously not ready: resubmit the same operation.
            io.enqueue(completion);
            return;
        }
        const size: usize = if (cqe.res >= 0) @intCast(cqe.res) else 0;
        completion.result = switch (completion.operation) {
            .none => unreachable,
            .accept => .{ .accept = if (err == .SUCCESS) cqe.res else os.accept_error(err) },
            .connect => .{ .connect = if (err == .SUCCESS) {} else os.connect_error(err) },
            .recv => .{ .recv = if (err == .SUCCESS) size else os.recv_error(err) },
            .send => .{ .send = if (err == .SUCCESS) size else os.send_error(err) },
            .read => .{ .read = if (err == .SUCCESS) size else os.read_error(err) },
            .write => .{ .write = if (err == .SUCCESS) size else os.write_error(err) },
            .fsync => .{ .fsync = if (err == .SUCCESS) {} else os.fsync_error(err) },
            // ETIME is the normal expiry of a timeout SQE.
            .timeout => .{ .timeout = switch (err) {
                .SUCCESS, .TIME => {},
                .CANCELED => error.Canceled,
                else => error.Unexpected,
            } },
            // close(2) releases the descriptor even when it reports an error.
            .close => .{ .close = {} },
        };
        io.completed.push(completion);
    }
};

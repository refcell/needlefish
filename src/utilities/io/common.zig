//! Types shared by every IO backend: addresses, operations, results, error sets, and the
//! type-erased callback adapter.
//!
//! Every backend (io_uring, kqueue, simulator) exposes the same completion-based API:
//! the caller owns a `Completion`, submits one operation on it with a typed callback and a
//! context pointer, and the callback runs from `tick()` / `run_for_ns()` once the
//! operation finishes. A completion must stay alive and untouched until its callback runs;
//! the callback may immediately reuse it for the next operation.
//!
//! `cancel(target)` asks for an in-flight operation to finish early. The target's callback
//! still runs exactly once, from a later `tick`: with `error.Canceled` if it had not finished,
//! or with its real result if it had. Canceling an idle completion or a `close` does nothing.

const std = @import("std");
const assert = std.debug.assert;

pub const AcceptError = error{
    ConnectionAborted,
    SocketNotListening,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const ConnectError = error{
    AddressInUse,
    AddressNotAvailable,
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkUnreachable,
    TimedOut,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const RecvError = error{
    ConnectionRefused,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    SocketNotConnected,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const SendError = error{
    BrokenPipe,
    ConnectionResetByPeer,
    MessageTooBig,
    SocketNotConnected,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const ReadError = error{
    InputOutput,
    IsDir,
    NotOpenForReading,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const WriteError = error{
    InputOutput,
    NoSpaceLeft,
    DiskQuota,
    FileTooBig,
    NotOpenForWriting,
    SystemResources,
    Canceled,
    Unexpected,
};

pub const FsyncError = error{
    InputOutput,
    NoSpaceLeft,
    DiskQuota,
    Canceled,
    Unexpected,
};

pub const TimeoutError = error{
    Canceled,
    Unexpected,
};

pub const CloseError = error{
    InputOutput,
    Unexpected,
};

/// Errors from synchronous, cold-path setup calls (open, bind, listen).
pub const SetupError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    FileNotFound,
    NameTooLong,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    NoSpaceLeft,
    /// A writable open found the file locked by another open descriptor (another process,
    /// or this one): one writer per file.
    FileLocked,
    Unexpected,
};

pub const OpenMode = enum { read_only, read_write, create };

/// An IPv4 or IPv6 socket address. Bytes are in network order, the port in native order.
pub const Address = struct {
    family: Family,
    bytes: [16]u8,
    port: u16,

    pub const Family = enum(u8) { ip4, ip6 };

    pub fn ip4(bytes: [4]u8, port: u16) Address {
        var address: Address = .{ .family = .ip4, .bytes = @splat(0), .port = port };
        address.bytes[0..4].* = bytes;
        return address;
    }

    pub fn ip6(bytes: [16]u8, port: u16) Address {
        return .{ .family = .ip6, .bytes = bytes, .port = port };
    }

    pub fn loopback(port: u16) Address {
        return ip4(.{ 127, 0, 0, 1 }, port);
    }

    /// Parses `a.b.c.d:port`, `[v6]:port`, or a bare address (port 0).
    pub fn parse(text: []const u8) error{InvalidAddress}!Address {
        const parsed = std.Io.net.IpAddress.parseLiteral(text) catch return error.InvalidAddress;
        return switch (parsed) {
            .ip4 => |v4| ip4(v4.bytes, v4.port),
            .ip6 => |v6| ip6(v6.bytes, v6.port),
        };
    }

    pub fn eql(a: Address, b: Address) bool {
        return a.family == b.family and a.port == b.port and
            std.mem.eql(u8, a.host_bytes(), b.host_bytes());
    }

    /// True when both addresses name the same host, ignoring the port.
    pub fn same_host(a: Address, b: Address) bool {
        return a.family == b.family and std.mem.eql(u8, a.host_bytes(), b.host_bytes());
    }

    pub fn host_bytes(address: *const Address) []const u8 {
        return switch (address.family) {
            .ip4 => address.bytes[0..4],
            .ip6 => address.bytes[0..16],
        };
    }

    pub fn with_port(address: Address, port: u16) Address {
        var result = address;
        result.port = port;
        return result;
    }

    pub fn format(address: Address, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (address.family) {
            .ip4 => {
                const b = address.bytes;
                try writer.print("{d}.{d}.{d}.{d}:{d}", .{ b[0], b[1], b[2], b[3], address.port });
            },
            .ip6 => {
                try writer.writeAll("[");
                var index: usize = 0;
                while (index < 16) : (index += 2) {
                    if (index != 0) try writer.writeAll(":");
                    const group = @as(u16, address.bytes[index]) << 8 | address.bytes[index + 1];
                    try writer.print("{x}", .{group});
                }
                try writer.print("]:{d}", .{address.port});
            },
        }
    }
};

/// A received datagram: its length in the caller's buffer and its sender.
pub const Datagram = struct {
    length: u32,
    from: Address,
};

/// Largest datagram the UDP path carries (discv5 packets are at most 1280 bytes).
pub const datagram_size_max = 1280;

/// The kind of operation on a completion. Shared by `Operation` and `Result` for every `Fd`.
pub const Tag = enum(u8) {
    none,
    accept,
    connect,
    recv,
    send,
    recvfrom,
    sendto,
    read,
    write,
    fsync,
    timeout,
    close,
};

/// The operation submitted on a completion, with the arguments a backend needs to (re)try it.
pub fn Operation(comptime Fd: type) type {
    return union(Tag) {
        none,
        accept: struct { socket: Fd },
        connect: struct { socket: Fd, address: Address, initiated: bool = false },
        recv: struct { socket: Fd, buffer: []u8 },
        send: struct { socket: Fd, buffer: []const u8 },
        recvfrom: struct { socket: Fd, buffer: []u8 },
        sendto: struct { socket: Fd, buffer: []const u8, address: Address },
        read: struct { fd: Fd, buffer: []u8, offset: u64 },
        write: struct { fd: Fd, buffer: []const u8, offset: u64 },
        fsync: struct { fd: Fd },
        timeout: struct { expires_ns: u64 },
        close: struct { fd: Fd },
    };
}

/// The result of a finished operation. The active tag always matches the operation tag.
pub fn Result(comptime Fd: type) type {
    return union(Tag) {
        none,
        accept: AcceptError!Fd,
        connect: ConnectError!void,
        recv: RecvError!usize,
        send: SendError!usize,
        recvfrom: RecvError!Datagram,
        sendto: SendError!usize,
        read: ReadError!usize,
        write: WriteError!usize,
        fsync: FsyncError!void,
        timeout: TimeoutError!void,
        close: CloseError!void,
    };
}

/// The result a canceled operation reports. `close` cannot be canceled.
pub fn canceled_result(comptime Fd: type, operation: Operation(Fd)) Result(Fd) {
    return switch (operation) {
        .none, .close => unreachable,
        .accept => .{ .accept = error.Canceled },
        .connect => .{ .connect = error.Canceled },
        .recv => .{ .recv = error.Canceled },
        .send => .{ .send = error.Canceled },
        .recvfrom => .{ .recvfrom = error.Canceled },
        .sendto => .{ .sendto = error.Canceled },
        .read => .{ .read = error.Canceled },
        .write => .{ .write = error.Canceled },
        .fsync => .{ .fsync = error.Canceled },
        .timeout => .{ .timeout = error.Canceled },
    };
}

/// Whether `cancel` applies to a completion in this state: in flight and not a close.
pub fn cancelable(comptime Fd: type, operation: Operation(Fd)) bool {
    return switch (operation) {
        .none, .close => false,
        else => true,
    };
}

/// The payload type a callback receives for `tag`, for a backend with descriptor type `Fd`.
pub fn ResultType(comptime Fd: type, comptime tag: Tag) type {
    return @FieldType(Result(Fd), @tagName(tag));
}

/// The typed callback signature for operation `tag` on backend `IO`.
pub fn Callback(comptime IO: type, comptime Context: type, comptime tag: Tag) type {
    return fn (context: Context, completion: *IO.Completion, result: ResultType(IO.Fd, tag)) void;
}

/// The typed operation API, shared by every backend. A backend `IO` provides `Fd`,
/// `Completion` (with the fields `operation`, `result`, `context`, `callback`), and
/// `enqueue(io, completion)`, and re-exports these functions as its own declarations.
/// Completions must be initialized with `.{}` before first use.
pub fn Methods(comptime IO: type) type {
    return struct {
        const Fd = IO.Fd;

        pub fn accept(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .accept),
            completion: *IO.Completion,
            socket: Fd,
        ) void {
            submit(io, Context, context, .accept, callback, completion, .{
                .accept = .{ .socket = socket },
            });
        }

        pub fn connect(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .connect),
            completion: *IO.Completion,
            socket: Fd,
            address: Address,
        ) void {
            submit(io, Context, context, .connect, callback, completion, .{
                .connect = .{ .socket = socket, .address = address },
            });
        }

        pub fn recv(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .recv),
            completion: *IO.Completion,
            socket: Fd,
            buffer: []u8,
        ) void {
            assert(buffer.len > 0);
            submit(io, Context, context, .recv, callback, completion, .{
                .recv = .{ .socket = socket, .buffer = buffer },
            });
        }

        pub fn send(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .send),
            completion: *IO.Completion,
            socket: Fd,
            buffer: []const u8,
        ) void {
            assert(buffer.len > 0);
            submit(io, Context, context, .send, callback, completion, .{
                .send = .{ .socket = socket, .buffer = buffer },
            });
        }

        /// Receives one datagram on a UDP socket (see `Datagram`).
        pub fn recvfrom(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .recvfrom),
            completion: *IO.Completion,
            socket: Fd,
            buffer: []u8,
        ) void {
            assert(buffer.len > 0);
            submit(io, Context, context, .recvfrom, callback, completion, .{
                .recvfrom = .{ .socket = socket, .buffer = buffer },
            });
        }

        /// Sends `buffer` as one datagram to `address`; `buffer` and `address` must stay valid
        /// until the callback. A datagram is sent whole or not at all.
        pub fn sendto(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .sendto),
            completion: *IO.Completion,
            socket: Fd,
            buffer: []const u8,
            address: Address,
        ) void {
            assert(buffer.len > 0);
            submit(io, Context, context, .sendto, callback, completion, .{
                .sendto = .{ .socket = socket, .buffer = buffer, .address = address },
            });
        }

        pub fn read(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .read),
            completion: *IO.Completion,
            fd: Fd,
            buffer: []u8,
            offset: u64,
        ) void {
            assert(buffer.len > 0);
            submit(io, Context, context, .read, callback, completion, .{
                .read = .{ .fd = fd, .buffer = buffer, .offset = offset },
            });
        }

        pub fn write(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .write),
            completion: *IO.Completion,
            fd: Fd,
            buffer: []const u8,
            offset: u64,
        ) void {
            assert(buffer.len > 0);
            submit(io, Context, context, .write, callback, completion, .{
                .write = .{ .fd = fd, .buffer = buffer, .offset = offset },
            });
        }

        pub fn fsync(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .fsync),
            completion: *IO.Completion,
            fd: Fd,
        ) void {
            submit(io, Context, context, .fsync, callback, completion, .{
                .fsync = .{ .fd = fd },
            });
        }

        /// Completes after `duration_ns` of monotonic time.
        pub fn timeout(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .timeout),
            completion: *IO.Completion,
            duration_ns: u64,
        ) void {
            const expires_ns = io.now_monotonic_ns() +| duration_ns;
            submit(io, Context, context, .timeout, callback, completion, .{
                .timeout = .{ .expires_ns = expires_ns },
            });
        }

        pub fn close(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime callback: Callback(IO, Context, .close),
            completion: *IO.Completion,
            fd: Fd,
        ) void {
            submit(io, Context, context, .close, callback, completion, .{
                .close = .{ .fd = fd },
            });
        }

        fn submit(
            io: *IO,
            comptime Context: type,
            context: Context,
            comptime tag: Tag,
            comptime callback: Callback(IO, Context, tag),
            completion: *IO.Completion,
            operation: Operation(Fd),
        ) void {
            assert(operation == tag);
            assert(completion.operation == .none); // Completion still in flight.
            completion.operation = operation;
            completion.result = .none;
            completion.context = opaque_context(Context, context);
            completion.callback = erase(IO.Completion, Context, tag, callback);
            io.enqueue(completion);
        }
    };
}

/// Runs the callback of a finished completion. Backends call this exactly once per
/// operation after storing the result. The completion is reset first so the callback may
/// submit a new operation on it.
pub fn complete(comptime Completion: type, completion: *Completion) void {
    assert(completion.operation != .none);
    assert(std.meta.activeTag(completion.result) == std.meta.activeTag(completion.operation));
    completion.operation = .none;
    completion.callback(completion.context, completion);
}

/// Builds the type-erased callback stored in a completion. `Context` must be a pointer type
/// (or `void`); the typed `callback` receives the context, the completion, and the result.
pub fn erase(
    comptime Completion: type,
    comptime Context: type,
    comptime tag: Tag,
    comptime callback: fn (
        context: Context,
        completion: *Completion,
        result: ResultType(Completion.Fd, tag),
    ) void,
) *const fn (?*anyopaque, *Completion) void {
    comptime assert(Context == void or @typeInfo(Context) == .pointer);
    return &struct {
        fn wrapper(context: ?*anyopaque, completion: *Completion) void {
            assert(completion.result == tag);
            const result = @field(completion.result, @tagName(tag));
            completion.result = .none;
            const typed: Context = if (Context == void) {} else @ptrCast(@alignCast(context));
            callback(typed, completion, result);
        }
    }.wrapper;
}

/// Converts a typed context to the opaque pointer stored in the completion.
pub fn opaque_context(comptime Context: type, context: Context) ?*anyopaque {
    comptime assert(Context == void or @typeInfo(Context) == .pointer);
    if (Context == void) return null;
    return @ptrCast(@constCast(context));
}

test "address: parse and format" {
    const a = try Address.parse("127.0.0.1:8545");
    try std.testing.expect(a.eql(Address.loopback(8545)));
    var buffer: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{a});
    try std.testing.expectEqualStrings("127.0.0.1:8545", text);

    const b = try Address.parse("[::1]:30303");
    try std.testing.expectEqual(Address.Family.ip6, b.family);
    try std.testing.expectEqual(@as(u16, 30303), b.port);
    try std.testing.expect(!a.eql(b));
    try std.testing.expectError(error.InvalidAddress, Address.parse("nope"));
    try std.testing.expect(a.same_host(a.with_port(1)));
}

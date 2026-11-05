//! Tests for the production backend on this target (kqueue on macOS, io_uring on Linux):
//! a loopback TCP echo, timeouts, and file write/fsync/read through real syscalls.

const std = @import("std");
const builtin = @import("builtin");

const root = @import("root.zig");
const common = @import("common.zig");

const IO = root.IO;
const Completion = IO.Completion;
const Address = common.Address;

fn init_io() !IO {
    if (builtin.os.tag != .linux) return IO.init();
    // CI sandboxes may forbid io_uring; the SimIo suite still covers the API there.
    return IO.init(.{}) catch |err| switch (err) {
        error.IoUringUnavailable => error.SkipZigTest,
        else => err,
    };
}

const Loopback = struct {
    io: *IO,
    listener: IO.Fd,
    server_fd: IO.Fd = -1,
    client_fd: IO.Fd,
    server_completion: Completion = .{},
    client_completion: Completion = .{},
    message: []const u8,
    server_buffer: [256]u8 = undefined,
    server_received: usize = 0,
    client_buffer: [256]u8 = undefined,
    client_received: usize = 0,
    failed: bool = false,

    fn on_accept(state: *Loopback, completion: *Completion, result: common.AcceptError!IO.Fd) void {
        state.server_fd = result catch return state.fail();
        state.io.recv(
            *Loopback,
            state,
            on_server_recv,
            completion,
            state.server_fd,
            &state.server_buffer,
        );
    }

    fn on_server_recv(
        state: *Loopback,
        completion: *Completion,
        result: common.RecvError!usize,
    ) void {
        const size = result catch return state.fail();
        if (size == 0) return state.fail();
        state.server_received += size;
        if (state.server_received < state.message.len) {
            const rest = state.server_buffer[state.server_received..];
            state.io.recv(*Loopback, state, on_server_recv, completion, state.server_fd, rest);
            return;
        }
        const reply = state.server_buffer[0..state.server_received];
        state.io.send(*Loopback, state, on_server_send, completion, state.server_fd, reply);
    }

    fn on_server_send(
        state: *Loopback,
        completion: *Completion,
        result: common.SendError!usize,
    ) void {
        _ = completion;
        const size = result catch return state.fail();
        if (size != state.message.len) state.fail();
    }

    fn on_connect(
        state: *Loopback,
        completion: *Completion,
        result: common.ConnectError!void,
    ) void {
        result catch return state.fail();
        state.io.send(*Loopback, state, on_client_send, completion, state.client_fd, state.message);
    }

    fn on_client_send(
        state: *Loopback,
        completion: *Completion,
        result: common.SendError!usize,
    ) void {
        const size = result catch return state.fail();
        if (size != state.message.len) return state.fail();
        state.io.recv(
            *Loopback,
            state,
            on_client_recv,
            completion,
            state.client_fd,
            &state.client_buffer,
        );
    }

    fn on_client_recv(
        state: *Loopback,
        completion: *Completion,
        result: common.RecvError!usize,
    ) void {
        const size = result catch return state.fail();
        if (size == 0) return state.fail();
        state.client_received += size;
        if (state.client_received < state.message.len) {
            const rest = state.client_buffer[state.client_received..];
            state.io.recv(*Loopback, state, on_client_recv, completion, state.client_fd, rest);
        }
    }

    fn fail(state: *Loopback) void {
        state.failed = true;
    }

    fn done(state: *const Loopback) bool {
        return state.failed or state.client_received == state.message.len;
    }
};

test "os io: loopback tcp echo" {
    var io = try init_io();
    defer io.deinit();
    const listener = try io.open_socket_tcp(.ip4);
    defer io.close_now(listener);
    const bound = try io.listen(listener, Address.loopback(0), 16);
    try std.testing.expect(bound.port != 0);

    var state: Loopback = .{
        .io = &io,
        .listener = listener,
        .client_fd = try io.open_socket_tcp(.ip4),
        .message = "engine_forkchoiceUpdatedV3",
    };
    defer io.close_now(state.client_fd);
    io.accept(*Loopback, &state, Loopback.on_accept, &state.server_completion, listener);
    io.connect(
        *Loopback,
        &state,
        Loopback.on_connect,
        &state.client_completion,
        state.client_fd,
        bound,
    );
    var rounds: u32 = 0;
    while (!state.done() and rounds < 500) : (rounds += 1) {
        try io.run_for_ns(10 * std.time.ns_per_ms);
    }
    if (state.server_fd >= 0) io.close_now(state.server_fd);
    try std.testing.expect(!state.failed);
    try std.testing.expectEqualStrings(
        state.message,
        state.client_buffer[0..state.client_received],
    );
}

const Fired = struct {
    count: u32 = 0,
    fn on_timeout(fired: *Fired, completion: *Completion, result: common.TimeoutError!void) void {
        _ = completion;
        result catch unreachable;
        fired.count += 1;
    }
};

test "os io: timeout fires after its duration" {
    var io = try init_io();
    defer io.deinit();
    var fired: Fired = .{};
    var completion: Completion = .{};
    const start_ns = io.now_monotonic_ns();
    io.timeout(*Fired, &fired, Fired.on_timeout, &completion, 2 * std.time.ns_per_ms);
    var rounds: u32 = 0;
    while (fired.count == 0 and rounds < 100) : (rounds += 1) {
        try io.run_for_ns(5 * std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(u32, 1), fired.count);
    try std.testing.expect(io.now_monotonic_ns() - start_ns >= 2 * std.time.ns_per_ms);
}

const FileState = struct {
    /// Callbacks run so far; each step waits for its own callback instead of a fixed time,
    /// because disk latency under a loaded CI host can exceed any small fixed budget.
    completed: u32 = 0,
    written: usize = 0,
    synced: bool = false,
    read: usize = 0,
    failed: bool = false,

    fn on_write(state: *FileState, completion: *Completion, result: common.WriteError!usize) void {
        _ = completion;
        state.completed += 1;
        state.written = result catch blk: {
            state.failed = true;
            break :blk 0;
        };
    }
    fn on_fsync(state: *FileState, completion: *Completion, result: common.FsyncError!void) void {
        _ = completion;
        state.completed += 1;
        result catch {
            state.failed = true;
            return;
        };
        state.synced = true;
    }
    fn on_read(state: *FileState, completion: *Completion, result: common.ReadError!usize) void {
        _ = completion;
        state.completed += 1;
        state.read = result catch blk: {
            state.failed = true;
            break :blk 0;
        };
    }
};

fn run_until_completed(io: *IO, state: *const FileState, count: u32) !void {
    var rounds: u32 = 0;
    while (state.completed < count and rounds < 5000) : (rounds += 1) {
        try io.run_for_ns(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(count, state.completed);
}

test "os io: file write fsync read" {
    var io = try init_io();
    defer io.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.posix.PATH_MAX]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, ".zig-cache/tmp/{s}/data.bin", .{tmp.sub_path});
    const fd = try io.open_file(path, .create);
    defer io.close_now(fd);

    var state: FileState = .{};
    var completion: Completion = .{};
    io.write(*FileState, &state, FileState.on_write, &completion, fd, "needlefish", 4);
    try run_until_completed(&io, &state, 1);
    io.fsync(*FileState, &state, FileState.on_fsync, &completion, fd);
    try run_until_completed(&io, &state, 2);
    var buffer: [32]u8 = undefined;
    io.read(*FileState, &state, FileState.on_read, &completion, fd, &buffer, 0);
    try run_until_completed(&io, &state, 3);
    try std.testing.expect(!state.failed);
    try std.testing.expect(state.synced);
    try std.testing.expectEqual(@as(usize, 10), state.written);
    try std.testing.expectEqual(@as(usize, 14), state.read);
    try std.testing.expectEqualStrings("needlefish", buffer[4..14]);
}

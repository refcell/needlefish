//! Takes a process's log writes off its hot path. When stderr is a regular file (a unit's
//! `>> follow.log 2>&1`), `start` points stderr at a pipe of `pipe_bytes` that a child
//! `base log-relay` copies into that file. A log write then blocks only while the pipe is
//! full, not while the disk is busy; lines keep their order and their exact text.
//!
//! The relay ignores SIGINT, SIGTERM, and SIGHUP and exits at the end of its input, once
//! every holder of the pipe's write end has exited: lines written just before a crash, a
//! panic, or a stop still reach the file.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const linux = std.os.linux;
const assert = std.debug.assert;

/// About 6,000 block lines: minutes of logging while the disk stalls.
pub const pipe_bytes: u32 = 1 << 20;
const chunk_bytes: u32 = 64 * 1024;

/// Points stderr at a relay when it is a regular file. Best effort: on any failure stderr
/// stays as it was, with a note.
pub fn start(io: Io) void {
    if (builtin.os.tag != .linux) return;
    const stderr = Io.File.stderr();
    const stat = stderr.stat(io) catch return;
    if (stat.kind != .file) return;
    var child = std.process.spawn(io, .{
        .argv = &.{ "/proc/self/exe", "log-relay" },
        .stdin = .pipe,
        .stdout = .{ .file = stderr },
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("log-relay: cannot start ({t}); logging directly\n", .{err});
        return;
    };
    child.id = null; // Never waited for: it outlives this process to drain the pipe.
    const pipe = child.stdin.?;
    assert(pipe.handle != linux.STDERR_FILENO);
    // A smaller pipe (the 64 KiB default) still works, so a refused resize is not an error.
    _ = linux.fcntl(pipe.handle, linux.F.SETPIPE_SZ, pipe_bytes);
    // The relay has its own descriptor for stderr's file; ours becomes the pipe.
    const rc = linux.dup2(pipe.handle, linux.STDERR_FILENO);
    pipe.close(io);
    if (linux.errno(rc) != .SUCCESS) {
        std.debug.print("log-relay: cannot redirect stderr; logging directly\n", .{});
    }
}

/// `base log-relay`: copies standard input to standard output until the end of input.
pub fn main() u8 {
    if (builtin.os.tag != .linux) return 2;
    const ignore: std.posix.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &ignore, null);
    std.posix.sigaction(.TERM, &ignore, null);
    std.posix.sigaction(.HUP, &ignore, null);
    pump(linux.STDIN_FILENO, linux.STDOUT_FILENO) catch return 1;
    return 0;
}

/// Copies `input` to `output` until the end of `input`.
fn pump(input: linux.fd_t, output: linux.fd_t) error{ ReadFailed, WriteFailed }!void {
    assert(input != output);
    var buffer: [chunk_bytes]u8 = undefined;
    while (true) {
        const rc = linux.read(input, &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (rc == 0) return;
        assert(rc <= buffer.len);
        try write_all(output, buffer[0..rc]);
    }
}

fn write_all(output: linux.fd_t, bytes: []const u8) error{WriteFailed}!void {
    assert(bytes.len > 0);
    var written: usize = 0;
    while (written < bytes.len) {
        const rc = linux.write(output, bytes[written..].ptr, bytes.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.WriteFailed,
        }
        assert(rc > 0);
        written += rc;
    }
    assert(written == bytes.len);
}

test "pump copies every byte in order to the end of input" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var source: [2]linux.fd_t = undefined;
    var sink: [2]linux.fd_t = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&source, .{ .CLOEXEC = true })));
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&sink, .{ .CLOEXEC = true })));
    defer _ = linux.close(sink[0]);
    // More than one chunk, and not a multiple of it, so a lost or reordered tail shows.
    var expected: [chunk_bytes + 1234]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x5eed);
    prng.random().bytes(&expected);
    _ = linux.fcntl(source[1], linux.F.SETPIPE_SZ, pipe_bytes);
    _ = linux.fcntl(sink[1], linux.F.SETPIPE_SZ, pipe_bytes);
    try write_all(source[1], &expected);
    _ = linux.close(source[1]);
    try pump(source[0], sink[1]);
    _ = linux.close(source[0]);
    _ = linux.close(sink[1]);
    var actual: [expected.len + 1]u8 = undefined;
    var length: usize = 0;
    while (true) {
        const rc = linux.read(sink[0], actual[length..].ptr, actual.len - length);
        try std.testing.expectEqual(.SUCCESS, linux.errno(rc));
        if (rc == 0) break;
        length += rc;
    }
    try std.testing.expectEqualSlices(u8, &expected, actual[0..length]);
}

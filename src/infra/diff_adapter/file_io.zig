//! A blocking file IO backend for the trie mode's on-disk databases (`IoStorageType`'s IO):
//! reads, writes and fsyncs are queued by `enqueue` and performed with blocking positional
//! calls (`utilities.io.os`) on the next `tick`, in submission order, on the calling thread.
//!
//! The node runs the same storage over io_uring; this backend differs only below the
//! storage interface. It makes every completion's timing a function of the request alone
//! (no kernel completion order, no threads), so the storage engine takes the same code paths
//! on every run of a request, and it needs no io_uring (often forbidden in containers).
//!
//! Torn writes (`tear_arm`): a power loss while writes are in flight. The armed tear lets
//! writes land until the chosen one (in a byte range, after `skip` others there), lands a
//! prefix of its sectors, leaves the next sector garbage (a torn sector: whole-sector
//! damage, the bitwise complement of what was being written), and drops it and everything
//! still queued, as the power loss drops every later in-flight write. Nothing completes after
//! that (`crashed`): the owner goes away with the process.

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../../utilities/io/common.zig");
const os = @import("../../utilities/io/os.zig");

pub const FileIo = struct {
    pub const Fd = os.fd_t;
    pub const Completion = struct {
        pub const Fd = os.fd_t;
        operation: io_common.Operation(os.fd_t) = .none,
        result: io_common.Result(os.fd_t) = .none,
        context: ?*anyopaque = null,
        callback: *const fn (?*anyopaque, *Completion) void = undefined,
        next: ?*Completion = null,
    };
    const methods = io_common.Methods(FileIo);
    pub const read = methods.read;
    pub const write = methods.write;
    pub const fsync = methods.fsync;

    queue: io_common.Queue(Completion) = .{},
    tear: ?Tear = null,
    crashed: bool = false,

    pub const sector_size: u32 = 4096;

    /// The write a power loss tears: the first in `[offset_min, offset_max)` after `skip`
    /// others there land whole; of it, `prefix_sectors` land (at most all but one) and the
    /// next is garbage.
    pub const Tear = struct {
        offset_min: u64,
        offset_max: u64,
        skip: u32 = 0,
        prefix_sectors: u32 = 0,
    };

    pub fn tear_arm(io: *FileIo, tear: Tear) void {
        assert(io.tear == null and !io.crashed);
        assert(tear.offset_min < tear.offset_max);
        io.tear = tear;
    }

    pub fn enqueue(io: *FileIo, completion: *Completion) void {
        assert(completion.next == null);
        assert(completion.operation != .none);
        io.queue.push(completion);
    }

    /// Performs and completes every operation queued at entry (callbacks may queue more:
    /// those wait for the next tick).
    pub fn tick(io: *FileIo) error{}!void {
        var pending = io.queue;
        io.queue = .{};
        if (io.crashed) return; // Gone with the power.
        const count = pending.count;
        var completed: u32 = 0;
        while (pending.pop()) |completion| : (completed += 1) {
            assert(completed < count);
            if (io.torn(completion)) {
                io.queue = .{};
                return;
            }
            perform(completion);
            io_common.complete(Completion, completion);
        }
        assert(completed == count);
    }

    /// Whether `completion` is the armed tear's write: then its prefix and a garbage sector
    /// land, and the power is gone (`crashed`).
    fn torn(io: *FileIo, completion: *Completion) bool {
        const tear = &(io.tear orelse return false);
        const op = switch (completion.operation) {
            .write => |op| op,
            else => return false,
        };
        if (op.offset < tear.offset_min or op.offset >= tear.offset_max) return false;
        if (tear.skip > 0) {
            tear.skip -= 1;
            return false;
        }
        assert(op.buffer.len % sector_size == 0 and op.buffer.len > 0);
        const sectors: u32 = @intCast(op.buffer.len / sector_size);
        const prefix = @min(tear.prefix_sectors, sectors - 1);
        // A write the device fails while the power goes did not land: nothing to report.
        const landed = op.buffer[0 .. prefix * sector_size];
        if (prefix > 0) _ = os.pwrite(op.fd, landed, op.offset) catch 0;
        var garbage: [sector_size]u8 = undefined;
        for (&garbage, op.buffer[prefix * sector_size ..][0..sector_size]) |*out, byte| {
            out.* = ~byte;
        }
        _ = os.pwrite(op.fd, &garbage, op.offset + prefix * sector_size) catch 0;
        io.tear = null;
        io.crashed = true;
        assert(prefix < sectors);
        return true;
    }

    pub fn read_now(io: *FileIo, fd: Fd, buffer: []u8, offset: u64) io_common.ReadError!usize {
        _ = io;
        return os.pread(fd, buffer, offset);
    }

    pub fn open_file(io: *FileIo, path: []const u8, mode: io_common.OpenMode) !Fd {
        _ = io;
        return os.open_file(path, mode);
    }

    /// Operations still queued (a database dropped mid-checkpoint, or after a failure) are
    /// forgotten: their owner is going away with the file.
    pub fn close_now(io: *FileIo, fd: Fd) void {
        assert(fd >= 0);
        io.queue = .{};
        os.close(fd);
    }

    fn perform(completion: *Completion) void {
        completion.result = switch (completion.operation) {
            .read => |op| .{ .read = os.pread(op.fd, op.buffer, op.offset) },
            .write => |op| .{ .write = os.pwrite(op.fd, op.buffer, op.offset) },
            .fsync => |op| .{ .fsync = os.fsync(op.fd) },
            // The storage submits only reads, writes and fsyncs.
            else => unreachable,
        };
        assert(std.meta.activeTag(completion.result) == std.meta.activeTag(completion.operation));
    }
};

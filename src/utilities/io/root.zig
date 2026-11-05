//! Completion-based IO, TigerBeetle style.
//!
//! Every backend has the same API: a caller-owned `Completion`, one operation per completion
//! (`accept`, `connect`, `recv`, `send`, `read`, `write`, `fsync`, `timeout`, `close`), a
//! typed callback with a context pointer, and `tick()` / `run_for_ns()` to drive progress.
//! Callbacks run only from `tick`/`run_for_ns`, never from the submitting call.
//!
//! Backends:
//! - `IoUring` (Linux): one ring, batched submissions, no syscalls per operation beyond
//!   `io_uring_enter`.
//! - `Kqueue` (macOS/BSD): readiness via kqueue, operations retried non-blocking.
//! - `SimIo`: deterministic simulation (time, network, disk, faults) driven by one seed.
//!
//! `IO` is the production backend for the build target. Components take the IO type as a
//! comptime parameter (`fn Server(comptime IO: type) type`) so DST can pass `SimIo`.
//!
//! Example:
//! ```
//! fn on_timeout(context: *State, completion: *IO.Completion, result: io.TimeoutError!void)
//!     void { ... }
//! io.timeout(*State, &state, on_timeout, &completion, 10 * std.time.ns_per_ms);
//! try io.run_for_ns(std.time.ns_per_s);
//! ```

const std = @import("std");
const builtin = @import("builtin");

pub const common = @import("common.zig");
pub const sim = @import("sim.zig");
pub const kqueue = @import("kqueue.zig");
pub const io_uring = @import("io_uring.zig");

pub const Address = common.Address;
pub const OpenMode = common.OpenMode;
pub const Tag = common.Tag;
pub const ResultType = common.ResultType;
pub const AcceptError = common.AcceptError;
pub const ConnectError = common.ConnectError;
pub const RecvError = common.RecvError;
pub const SendError = common.SendError;
pub const ReadError = common.ReadError;
pub const WriteError = common.WriteError;
pub const FsyncError = common.FsyncError;
pub const TimeoutError = common.TimeoutError;
pub const CloseError = common.CloseError;
pub const SetupError = common.SetupError;

pub const SimIo = sim.SimIo;
pub const SimWorld = sim.World;
pub const Kqueue = kqueue.Kqueue;
pub const IoUring = io_uring.IoUring;

/// The production backend for this target.
pub const IO = switch (builtin.os.tag) {
    .linux => IoUring,
    .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => Kqueue,
    else => @compileError("needlefish IO: unsupported OS"),
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("sim_test.zig");
    _ = @import("os_test.zig");
}

//! Thin portable layer over raw OS syscalls for the production IO backends.
//!
//! `std.posix.system` is libc on macOS/BSD and raw Linux syscalls on Linux; both report
//! errors through `std.posix.errno`. This file converts addresses, opens sockets and files,
//! reads clocks, and maps errno values onto the IO error sets in `common.zig`. It is the
//! only place outside the backends that touches the OS directly.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const common = @import("common.zig");
const Address = common.Address;

pub const system = std.posix.system;
pub const E = std.posix.E;
pub const fd_t = std.posix.fd_t;
pub const sockaddr = std.posix.sockaddr;
pub const socklen_t = std.posix.socklen_t;

pub const is_darwin = builtin.os.tag.isDarwin();
pub const is_linux = builtin.os.tag == .linux;

pub fn errno(rc: anytype) E {
    return std.posix.errno(rc);
}

pub const Blocking = enum { blocking, nonblocking };

/// A socket address in OS layout, large enough for IPv4 and IPv6.
pub const SockAddr = extern union {
    any: sockaddr,
    in: sockaddr.in,
    in6: sockaddr.in6,

    pub fn from(address: Address) SockAddr {
        const port = std.mem.nativeToBig(u16, address.port);
        return switch (address.family) {
            .ip4 => .{ .in = .{
                .port = port,
                .addr = @bitCast(address.bytes[0..4].*),
            } },
            .ip6 => .{ .in6 = .{
                .port = port,
                .flowinfo = 0,
                .addr = address.bytes,
                .scope_id = 0,
            } },
        };
    }

    pub fn to_address(sock_addr: *const SockAddr) ?Address {
        const family = sock_addr.any.family;
        if (family == std.posix.AF.INET) {
            const bytes: [4]u8 = @bitCast(sock_addr.in.addr);
            return Address.ip4(bytes, std.mem.bigToNative(u16, sock_addr.in.port));
        }
        if (family == std.posix.AF.INET6) {
            return Address.ip6(sock_addr.in6.addr, std.mem.bigToNative(u16, sock_addr.in6.port));
        }
        return null;
    }

    pub fn len(address: Address) socklen_t {
        return switch (address.family) {
            .ip4 => @sizeOf(sockaddr.in),
            .ip6 => @sizeOf(sockaddr.in6),
        };
    }
};

comptime {
    assert(@sizeOf(SockAddr) >= @sizeOf(sockaddr.in6));
}

fn family_of(family: Address.Family) u32 {
    return switch (family) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };
}

/// Opens a TCP socket with close-on-exec, TCP_NODELAY, and (on Darwin) no SIGPIPE.
pub fn socket_tcp(family: Address.Family, blocking: Blocking) common.SetupError!fd_t {
    var socket_type: u32 = std.posix.SOCK.STREAM;
    if (is_linux) {
        socket_type |= std.posix.SOCK.CLOEXEC;
        if (blocking == .nonblocking) socket_type |= std.posix.SOCK.NONBLOCK;
    }
    const rc = system.socket(family_of(family), socket_type, std.posix.IPPROTO.TCP);
    switch (errno(rc)) {
        .SUCCESS => {},
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        else => return error.Unexpected,
    }
    const fd: fd_t = @intCast(rc);
    errdefer close(fd);
    if (is_darwin) {
        try fcntl_set(fd, std.posix.F.SETFD, std.posix.FD_CLOEXEC);
        if (blocking == .nonblocking) {
            const flags = system.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
            if (flags < 0) return error.Unexpected;
            const nonblock: c_int = @bitCast(std.posix.O{ .NONBLOCK = true });
            try fcntl_set(fd, std.posix.F.SETFL, flags | nonblock);
        }
        try setsockopt_int(fd, std.posix.SOL.SOCKET, std.posix.SO.NOSIGPIPE, 1);
    }
    try setsockopt_int(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, 1);
    return fd;
}

fn fcntl_set(fd: fd_t, command: i32, value: anytype) common.SetupError!void {
    const rc = system.fcntl(fd, command, @as(c_int, @intCast(value)));
    if (errno(rc) != .SUCCESS) return error.Unexpected;
}

pub fn setsockopt_int(fd: fd_t, level: i32, option: u32, value: c_int) common.SetupError!void {
    const bytes = std.mem.asBytes(&value);
    const rc = system.setsockopt(fd, level, option, bytes.ptr, @intCast(bytes.len));
    switch (errno(rc)) {
        .SUCCESS => {},
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    }
}

/// Binds with SO_REUSEADDR and listens. Returns the bound address (ephemeral port filled).
pub fn listen(fd: fd_t, address: Address, backlog: u31) common.SetupError!Address {
    assert(backlog > 0);
    try setsockopt_int(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, 1);
    var sock_addr = SockAddr.from(address);
    switch (errno(system.bind(fd, &sock_addr.any, SockAddr.len(address)))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .ACCES, .PERM => return error.AccessDenied,
        .NOMEM, .NOBUFS => return error.SystemResources,
        else => return error.Unexpected,
    }
    switch (errno(system.listen(fd, backlog))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => return error.Unexpected,
    }
    var bound: SockAddr = undefined;
    var bound_len: socklen_t = @sizeOf(SockAddr);
    switch (errno(system.getsockname(fd, &bound.any, &bound_len))) {
        .SUCCESS => {},
        .NOBUFS => return error.SystemResources,
        else => return error.Unexpected,
    }
    return bound.to_address() orelse error.Unexpected;
}

/// Opens a non-blocking UDP socket with close-on-exec.
pub fn socket_udp(family: Address.Family) common.SetupError!fd_t {
    var socket_type: u32 = std.posix.SOCK.DGRAM;
    if (is_linux) socket_type |= std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK;
    const rc = system.socket(family_of(family), socket_type, std.posix.IPPROTO.UDP);
    switch (errno(rc)) {
        .SUCCESS => {},
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        else => return error.Unexpected,
    }
    const fd: fd_t = @intCast(rc);
    errdefer close(fd);
    if (is_darwin) {
        try fcntl_set(fd, std.posix.F.SETFD, std.posix.FD_CLOEXEC);
        const flags = system.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
        if (flags < 0) return error.Unexpected;
        const nonblock: c_int = @bitCast(std.posix.O{ .NONBLOCK = true });
        try fcntl_set(fd, std.posix.F.SETFL, flags | nonblock);
    }
    return fd;
}

/// Binds a datagram socket. Returns the bound address (ephemeral port filled).
pub fn bind(fd: fd_t, address: Address) common.SetupError!Address {
    var sock_addr = SockAddr.from(address);
    switch (errno(system.bind(fd, &sock_addr.any, SockAddr.len(address)))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .ACCES, .PERM => return error.AccessDenied,
        .NOMEM, .NOBUFS => return error.SystemResources,
        else => return error.Unexpected,
    }
    var bound: SockAddr = undefined;
    var bound_len: socklen_t = @sizeOf(SockAddr);
    switch (errno(system.getsockname(fd, &bound.any, &bound_len))) {
        .SUCCESS => {},
        .NOBUFS => return error.SystemResources,
        else => return error.Unexpected,
    }
    return bound.to_address() orelse error.Unexpected;
}

/// One datagram received without blocking, or null when none is queued (or on error;
/// datagram transports tolerate loss). Longer datagrams are truncated to `buffer`.
pub fn recvfrom(fd: fd_t, buffer: []u8) ?common.Datagram {
    assert(buffer.len > 0);
    var from: SockAddr = undefined;
    var from_len: socklen_t = @sizeOf(SockAddr);
    const flags = std.posix.MSG.DONTWAIT;
    const rc = system.recvfrom(fd, buffer.ptr, buffer.len, flags, &from.any, &from_len);
    if (errno(rc) != .SUCCESS) return null;
    const length: usize = @intCast(rc);
    const address = from.to_address() orelse return null;
    return .{ .length = @intCast(@min(length, buffer.len)), .from = address };
}

/// Sends one datagram without blocking. False if the kernel refused it (dropped).
pub fn sendto(fd: fd_t, buffer: []const u8, address: Address) bool {
    assert(buffer.len > 0);
    var to = SockAddr.from(address);
    const flags = std.posix.MSG.DONTWAIT;
    const rc = system.sendto(fd, buffer.ptr, buffer.len, flags, &to.any, SockAddr.len(address));
    return errno(rc) == .SUCCESS;
}

/// The remote address of a connected socket, or null if unavailable (e.g. reset).
pub fn peer_address(fd: fd_t) ?Address {
    var peer: SockAddr = undefined;
    var peer_len: socklen_t = @sizeOf(SockAddr);
    if (errno(system.getpeername(fd, &peer.any, &peer_len)) != .SUCCESS) return null;
    return peer.to_address();
}

pub fn open_file(path: []const u8, mode: common.OpenMode) common.SetupError!fd_t {
    var path_buffer: [std.posix.PATH_MAX]u8 = undefined;
    if (path.len == 0 or path.len >= path_buffer.len) return error.NameTooLong;
    @memcpy(path_buffer[0..path.len], path);
    path_buffer[path.len] = 0;
    const path_z: [*:0]const u8 = path_buffer[0..path.len :0];
    var flags: std.posix.O = .{ .CLOEXEC = true };
    flags.ACCMODE = if (mode == .read_only) .RDONLY else .RDWR;
    if (mode == .create) flags.CREAT = true;
    const permissions: std.posix.mode_t = 0o644;
    const rc = system.openat(std.posix.AT.FDCWD, path_z, flags, permissions);
    return switch (errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.AccessDenied,
        .NOENT => error.FileNotFound,
        .NAMETOOLONG => error.NameTooLong,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOSPC => error.NoSpaceLeft,
        .NOMEM => error.SystemResources,
        else => error.Unexpected,
    };
}

pub fn close(fd: fd_t) void {
    // close(2) always releases the descriptor, even on EINTR/EIO; nothing to retry.
    _ = system.close(fd);
}

/// shutdown(2) both directions. Errors (ENOTCONN after a peer reset) are ignored: the
/// socket is being torn down either way.
pub fn shutdown(fd: fd_t) void {
    _ = system.shutdown(fd, system.SHUT.RDWR);
}

pub fn clock_ns(clock: std.posix.clockid_t) u64 {
    var ts: std.posix.timespec = undefined;
    const rc = system.clock_gettime(clock, &ts);
    // A valid clock id and pointer cannot fail.
    assert(errno(rc) == .SUCCESS);
    assert(ts.sec >= 0);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn monotonic_ns() u64 {
    return clock_ns(if (is_darwin) .UPTIME_RAW else .MONOTONIC);
}

pub fn realtime_ns() u64 {
    return clock_ns(.REALTIME);
}

// Errno mapping onto the operation error sets.

pub fn accept_error(err: E) common.AcceptError {
    return switch (err) {
        .CONNABORTED, .PROTO => error.ConnectionAborted,
        .INVAL, .NOTSOCK, .OPNOTSUPP => error.SocketNotListening,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

pub fn connect_error(err: E) common.ConnectError {
    return switch (err) {
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .NETUNREACH, .HOSTUNREACH => error.NetworkUnreachable,
        .TIMEDOUT => error.TimedOut,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

pub fn recv_error(err: E) common.RecvError {
    return switch (err) {
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .TIMEDOUT => error.ConnectionTimedOut,
        .NOTCONN => error.SocketNotConnected,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

pub fn send_error(err: E) common.SendError {
    return switch (err) {
        .PIPE => error.BrokenPipe,
        .CONNRESET => error.ConnectionResetByPeer,
        .MSGSIZE => error.MessageTooBig,
        .NOTCONN, .DESTADDRREQ => error.SocketNotConnected,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

pub fn read_error(err: E) common.ReadError {
    return switch (err) {
        .IO => error.InputOutput,
        .ISDIR => error.IsDir,
        .BADF => error.NotOpenForReading,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

pub fn write_error(err: E) common.WriteError {
    return switch (err) {
        .IO => error.InputOutput,
        .NOSPC => error.NoSpaceLeft,
        .DQUOT => error.DiskQuota,
        .FBIG => error.FileTooBig,
        .BADF => error.NotOpenForWriting,
        .NOBUFS, .NOMEM => error.SystemResources,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

pub fn fsync_error(err: E) common.FsyncError {
    return switch (err) {
        .IO => error.InputOutput,
        .NOSPC => error.NoSpaceLeft,
        .DQUOT => error.DiskQuota,
        .CANCELED => error.Canceled,
        else => error.Unexpected,
    };
}

test "os: sockaddr round trip" {
    const v4 = Address.loopback(8545);
    const sa4 = SockAddr.from(v4);
    try std.testing.expect(sa4.to_address().?.eql(v4));
    const v6 = try Address.parse("[::1]:9000");
    const sa6 = SockAddr.from(v6);
    try std.testing.expect(sa6.to_address().?.eql(v6));
    try std.testing.expect(SockAddr.len(v4) < SockAddr.len(v6));
}

test "os: clocks advance" {
    const a = monotonic_ns();
    const b = monotonic_ns();
    try std.testing.expect(b >= a);
    try std.testing.expect(realtime_ns() > 1_600_000_000 * std.time.ns_per_s);
}

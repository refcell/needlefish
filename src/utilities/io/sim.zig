//! Deterministic simulated IO backend for DST.
//!
//! A `World` owns simulated time, the seeded PRNG, the network (listeners and TCP-like
//! connections), and fault settings. Each simulated process gets a `SimIo` bound to the
//! world with its own host address, descriptor table, and in-memory disk. `SimIo` exposes the
//! same completion API as the io_uring and kqueue backends, so component code runs unchanged.
//!
//! Network model: a connection is two pipes. A send copies bytes into the peer's receive
//! ring (flow control = ring space) tagged with an arrival time (`now + latency`), keeping
//! per-direction order like TCP. Bytes become visible to `recv` once they have arrived and
//! the two hosts are not partitioned. Faults: latency range, partitions, random connection
//! resets, refused connects. Disk model: files hold a current and a durable image; `fsync`
//! makes the current image durable, `crash` reverts to it. Reads and writes fail with a
//! configurable probability. Every decision draws from the world PRNG, so a seed replays.

const std = @import("std");
const assert = std.debug.assert;

const common = @import("common.zig");
const Prng = @import("../../testing/prng.zig").Prng;

pub const Address = common.Address;
const FdSim = u32;

const ppm_scale = 1_000_000;
const marks_max = 64;
const file_name_size_max = 64;
const loop_iterations_max = 1 << 24;

pub const Options = struct {
    seed: u64,
    nodes_max: u32 = 8,
    connections_max: u32 = 64,
    listeners_max: u32 = 16,
    backlog_max: u32 = 16,
    pipe_size_bytes: u32 = 16 * 1024,
    segment_size_max: u32 = 4 * 1024,
    latency_min_ns: u64 = 100 * std.time.ns_per_us,
    latency_max_ns: u64 = 5 * std.time.ns_per_ms,
    /// Chance, in parts per million, that a send resets its connection.
    reset_ppm: u32 = 0,
    /// Chance, in parts per million, that a connect is refused even with a listener.
    refuse_ppm: u32 = 0,
    realtime_start_ns: u64 = 1_700_000_000 * std.time.ns_per_s,
    /// Datagrams in flight across the world; sends beyond this are dropped.
    datagrams_max: u32 = 256,
    /// Chance, in parts per million, that a datagram is lost.
    datagram_loss_ppm: u32 = 0,
};

/// Datagram accounting across the world: every send is received or counted as dropped.
pub const DatagramStats = struct {
    sent: u64 = 0,
    received: u64 = 0,
    dropped_unbound: u64 = 0,
    dropped_partition: u64 = 0,
    dropped_loss: u64 = 0,
    /// Discarded in flight because the destination socket closed.
    dropped_closed: u64 = 0,
};

/// A datagram in flight: delivered to `to` once `arrive_ns` passes.
const InFlight = struct {
    used: bool = false,
    from: Address = undefined,
    to: Address = undefined,
    arrive_ns: u64 = 0,
    length: u16 = 0,
    bytes: [common.datagram_size_max]u8 = undefined,
};

pub const DiskOptions = struct {
    files_max: u32 = 8,
    file_size_max: u32 = 64 * 1024,
    latency_min_ns: u64 = 10 * std.time.ns_per_us,
    latency_max_ns: u64 = 1 * std.time.ns_per_ms,
    read_fault_ppm: u32 = 0,
    write_fault_ppm: u32 = 0,
};

pub const NodeOptions = struct {
    host: Address,
    fds_max: u32 = 64,
    disk: DiskOptions = .{},
    /// Offset added to world time for this node's realtime clock (clock skew).
    realtime_offset_ns: i64 = 0,
};

/// One direction of a connection: bytes destined to one side, in a bounded ring.
const Pipe = struct {
    storage: []u8,
    head: u32 = 0,
    count: u32 = 0,
    /// Arrival marks: bytes before `end` (relative to `head` origin) arrive at `arrive_ns`.
    marks_end: [marks_max]u64 = undefined,
    marks_arrive_ns: [marks_max]u64 = undefined,
    marks_count: u32 = 0,
    /// Total bytes ever pushed and consumed, used to place marks.
    pushed_total: u64 = 0,
    consumed_total: u64 = 0,
    fin: bool = false,
    fin_arrive_ns: u64 = 0,
    last_arrive_ns: u64 = 0,

    fn free_bytes(pipe: *const Pipe) u32 {
        assert(pipe.count <= pipe.storage.len);
        return @intCast(pipe.storage.len - pipe.count);
    }

    fn push(pipe: *Pipe, bytes: []const u8, arrive_ns: u64) void {
        assert(bytes.len > 0);
        assert(bytes.len <= pipe.free_bytes());
        assert(!pipe.fin);
        const capacity: u32 = @intCast(pipe.storage.len);
        for (bytes, 0..) |byte, index| {
            const position = (pipe.head + pipe.count + @as(u32, @intCast(index))) % capacity;
            pipe.storage[position] = byte;
        }
        pipe.count += @intCast(bytes.len);
        pipe.pushed_total += bytes.len;
        // Arrival is monotonic per direction so bytes never overtake earlier bytes.
        const arrive = @max(arrive_ns, pipe.last_arrive_ns);
        pipe.last_arrive_ns = arrive;
        if (pipe.marks_count == marks_max) {
            // Merge into the newest mark: delays earlier bytes slightly, preserves order.
            pipe.marks_end[marks_max - 1] = pipe.pushed_total;
            pipe.marks_arrive_ns[marks_max - 1] = arrive;
        } else {
            pipe.marks_end[pipe.marks_count] = pipe.pushed_total;
            pipe.marks_arrive_ns[pipe.marks_count] = arrive;
            pipe.marks_count += 1;
        }
        assert(pipe.count <= capacity);
    }

    fn close_write(pipe: *Pipe, arrive_ns: u64) void {
        assert(!pipe.fin);
        pipe.fin = true;
        pipe.fin_arrive_ns = @max(arrive_ns, pipe.last_arrive_ns);
        pipe.last_arrive_ns = pipe.fin_arrive_ns;
    }

    /// Bytes that have arrived by `now_ns` and are ready to read.
    fn visible_bytes(pipe: *const Pipe, now_ns: u64) u64 {
        var end: u64 = pipe.consumed_total;
        for (pipe.marks_end[0..pipe.marks_count], pipe.marks_arrive_ns[0..pipe.marks_count]) |
            mark_end,
            arrive_ns,
        | {
            if (arrive_ns > now_ns) break;
            end = mark_end;
        }
        assert(end >= pipe.consumed_total);
        return end - pipe.consumed_total;
    }

    fn pop(pipe: *Pipe, buffer: []u8, now_ns: u64) u32 {
        const visible = pipe.visible_bytes(now_ns);
        const take: u32 = @intCast(@min(visible, buffer.len));
        assert(take <= pipe.count);
        const capacity: u32 = @intCast(pipe.storage.len);
        for (buffer[0..take], 0..) |*byte, index| {
            byte.* = pipe.storage[(pipe.head + @as(u32, @intCast(index))) % capacity];
        }
        pipe.head = (pipe.head + take) % capacity;
        pipe.count -= take;
        pipe.consumed_total += take;
        // Drop fully consumed marks.
        var drop: u32 = 0;
        while (drop < pipe.marks_count and pipe.marks_end[drop] <= pipe.consumed_total) drop += 1;
        if (drop > 0) {
            const remaining = pipe.marks_count - drop;
            std.mem.copyForwards(
                u64,
                pipe.marks_end[0..remaining],
                pipe.marks_end[drop..][0..remaining],
            );
            std.mem.copyForwards(
                u64,
                pipe.marks_arrive_ns[0..remaining],
                pipe.marks_arrive_ns[drop..][0..remaining],
            );
            pipe.marks_count = remaining;
        }
        return take;
    }

    fn eof(pipe: *const Pipe, now_ns: u64) bool {
        return pipe.fin and pipe.count == 0 and pipe.fin_arrive_ns <= now_ns;
    }

    /// The next time something new becomes visible, or null.
    fn next_arrival_ns(pipe: *const Pipe, now_ns: u64) ?u64 {
        for (pipe.marks_arrive_ns[0..pipe.marks_count]) |arrive_ns| {
            if (arrive_ns > now_ns) return arrive_ns;
        }
        if (pipe.fin and pipe.fin_arrive_ns > now_ns) return pipe.fin_arrive_ns;
        return null;
    }

    fn reset(pipe: *Pipe) void {
        const storage = pipe.storage;
        pipe.* = .{ .storage = storage };
    }
};

const Side = struct {
    node: u32 = 0,
    fd: FdSim = 0,
    open: bool = false,
    /// `shutdown_now` was called: recv returns 0, send fails, and the peer has seen FIN.
    shut: bool = false,
    /// This side's socket address (client: host plus ephemeral port; server: listener).
    address: Address = undefined,
    /// Bytes flowing to this side.
    inbound: Pipe,
};

const Connection = struct {
    used: bool = false,
    reset: bool = false,
    /// Connected by the client but not yet accepted: side 1 is still in a listener backlog.
    pending_accept: bool = false,
    sides: [2]Side,

    fn hosts_partitioned(connection: *const Connection, world: *const World) bool {
        return world.partitioned(connection.sides[0].node, connection.sides[1].node);
    }
};

fn connection_release_if_unused(connection: *Connection) void {
    assert(connection.used);
    const sides_closed = !connection.sides[0].open and !connection.sides[1].open;
    if (sides_closed and !connection.pending_accept) connection.used = false;
}

const Listener = struct {
    used: bool = false,
    node: u32 = 0,
    fd: FdSim = 0,
    address: Address = undefined,
    backlog: []u32,
    backlog_head: u32 = 0,
    backlog_count: u32 = 0,
};

pub const World = struct {
    allocator: std.mem.Allocator,
    options: Options,
    prng: Prng,
    now_ns: u64 = 0,
    nodes: []?*SimIo,
    nodes_count: u32 = 0,
    connections: []Connection,
    listeners: []Listener,
    /// Symmetric partition matrix, nodes_max * nodes_max.
    partitions: []bool,
    port_next: u16 = 40_000,
    pipe_memory: []u8,
    backlog_memory: []u32,
    datagrams: []InFlight,
    datagram_stats: DatagramStats = .{},

    pub fn init(allocator: std.mem.Allocator, options: Options) !World {
        assert(options.latency_min_ns <= options.latency_max_ns);
        assert(options.segment_size_max > 0 and options.pipe_size_bytes > 0);
        assert(options.reset_ppm <= ppm_scale and options.refuse_ppm <= ppm_scale);
        const pipes_count = @as(usize, options.connections_max) * 2;
        const pipe_memory = try allocator.alloc(u8, pipes_count * options.pipe_size_bytes);
        errdefer allocator.free(pipe_memory);
        const backlog_size = @as(usize, options.listeners_max) * options.backlog_max;
        const backlog_memory = try allocator.alloc(u32, backlog_size);
        errdefer allocator.free(backlog_memory);
        const nodes = try allocator.alloc(?*SimIo, options.nodes_max);
        errdefer allocator.free(nodes);
        @memset(nodes, null);
        const nodes_squared = @as(usize, options.nodes_max) * options.nodes_max;
        const partitions = try allocator.alloc(bool, nodes_squared);
        errdefer allocator.free(partitions);
        @memset(partitions, false);
        const connections = try allocator.alloc(Connection, options.connections_max);
        errdefer allocator.free(connections);
        for (connections, 0..) |*connection, index| {
            const size = options.pipe_size_bytes;
            connection.* = .{ .sides = .{
                .{ .inbound = .{ .storage = pipe_memory[(index * 2) * size ..][0..size] } },
                .{ .inbound = .{ .storage = pipe_memory[(index * 2 + 1) * size ..][0..size] } },
            } };
        }
        const datagrams = try allocator.alloc(InFlight, options.datagrams_max);
        errdefer allocator.free(datagrams);
        @memset(datagrams, .{});
        const listeners = try allocator.alloc(Listener, options.listeners_max);
        for (listeners, 0..) |*listener, index| {
            const size = options.backlog_max;
            listener.* = .{ .backlog = backlog_memory[index * size ..][0..size] };
        }
        return .{
            .allocator = allocator,
            .options = options,
            .prng = Prng.init(options.seed),
            .nodes = nodes,
            .connections = connections,
            .listeners = listeners,
            .partitions = partitions,
            .pipe_memory = pipe_memory,
            .backlog_memory = backlog_memory,
            .datagrams = datagrams,
        };
    }

    pub fn deinit(world: *World) void {
        world.allocator.free(world.datagrams);
        world.allocator.free(world.listeners);
        world.allocator.free(world.connections);
        world.allocator.free(world.partitions);
        world.allocator.free(world.nodes);
        world.allocator.free(world.backlog_memory);
        world.allocator.free(world.pipe_memory);
        world.* = undefined;
    }

    fn register(world: *World, io: *SimIo) u32 {
        assert(world.nodes_count < world.nodes.len); // Raise Options.nodes_max.
        const index = world.nodes_count;
        world.nodes[index] = io;
        world.nodes_count += 1;
        return index;
    }

    fn node(world: *World, index: u32) *SimIo {
        assert(index < world.nodes_count);
        return world.nodes[index].?;
    }

    pub fn partition(world: *World, a: u32, b: u32) void {
        world.set_partition(a, b, true);
    }

    pub fn heal(world: *World, a: u32, b: u32) void {
        world.set_partition(a, b, false);
    }

    pub fn heal_all(world: *World) void {
        @memset(world.partitions, false);
    }

    fn set_partition(world: *World, a: u32, b: u32, value: bool) void {
        assert(a < world.nodes_count and b < world.nodes_count);
        assert(a != b);
        const n = world.nodes.len;
        world.partitions[a * n + b] = value;
        world.partitions[b * n + a] = value;
    }

    pub fn partitioned(world: *const World, a: u32, b: u32) bool {
        const n = world.nodes.len;
        assert(a < n and b < n);
        return world.partitions[a * n + b];
    }

    fn latency_ns(world: *World) u64 {
        return world.prng.range(world.options.latency_min_ns, world.options.latency_max_ns);
    }

    fn roll(world: *World, ppm: u32) bool {
        if (ppm == 0) return false;
        return world.prng.chance(ppm, ppm_scale);
    }

    /// Runs every node until `duration_ns` of simulated time passes, jumping between events.
    pub fn run_for_ns(world: *World, duration_ns: u64) void {
        const deadline_ns = world.now_ns +| duration_ns;
        var iterations: u32 = 0;
        while (iterations < loop_iterations_max) : (iterations += 1) {
            const progressed = world.tick();
            if (progressed) continue;
            if (world.now_ns >= deadline_ns) return;
            const next_ns = world.next_event_ns() orelse deadline_ns;
            assert(next_ns > world.now_ns);
            world.now_ns = @min(next_ns, deadline_ns);
        } else unreachable; // A callback loop never yields: a livelock in component code.
    }

    /// Completes every ready operation on every node at the current time. Returns true if
    /// any callback ran.
    pub fn tick(world: *World) bool {
        var progressed = false;
        for (world.nodes[0..world.nodes_count]) |maybe_io| {
            if (maybe_io.?.tick_ready()) progressed = true;
        }
        return progressed;
    }

    fn next_event_ns(world: *World) ?u64 {
        var next: ?u64 = null;
        for (world.nodes[0..world.nodes_count]) |maybe_io| {
            if (maybe_io.?.next_event_ns()) |event_ns| {
                next = if (next) |n| @min(n, event_ns) else event_ns;
            }
        }
        return next;
    }

    fn connection_allocate(world: *World) ?u32 {
        for (world.connections, 0..) |*connection, index| {
            if (connection.used) continue;
            connection.used = true;
            connection.reset = false;
            connection.pending_accept = false;
            for (&connection.sides) |*side| {
                side.open = false;
                side.shut = false;
                side.inbound.reset();
            }
            return @intCast(index);
        }
        return null;
    }

    fn connection_release_side(world: *World, index: u32, side: u1) void {
        const connection = &world.connections[index];
        assert(connection.used);
        assert(connection.sides[side].open);
        connection.sides[side].open = false;
        const peer = &connection.sides[side ^ 1];
        const peer_alive = peer.open or connection.pending_accept;
        const fin_sent = connection.sides[side].shut;
        if (peer_alive and !connection.reset and !fin_sent) {
            peer.inbound.close_write(world.now_ns + world.latency_ns());
        }
        connection_release_if_unused(connection);
    }

    /// The node and descriptor bound to UDP `address`, if any.
    fn udp_find(world: *World, address: Address) ?struct { node: u32, fd: FdSim } {
        for (world.nodes[0..world.nodes_count], 0..) |maybe_io, node_index| {
            const io = maybe_io.?;
            for (io.descriptors, 0..) |descriptor, fd| {
                if (descriptor != .udp) continue;
                if (!descriptor.udp.eql(address)) continue;
                return .{ .node = @intCast(node_index), .fd = @intCast(fd) };
            }
        }
        return null;
    }

    fn datagrams_purge(world: *World, address: Address) void {
        for (world.datagrams) |*datagram| {
            if (datagram.used and datagram.to.eql(address)) {
                datagram.used = false;
                world.datagram_stats.dropped_closed += 1;
            }
        }
    }

    fn listener_find(world: *World, address: Address) ?*Listener {
        for (world.listeners) |*listener| {
            if (listener.used and listener.address.eql(address)) return listener;
        }
        return null;
    }
};

const File = struct {
    used: bool = false,
    name: [file_name_size_max]u8 = undefined,
    name_len: u8 = 0,
    current: []u8,
    durable: []u8,
    size_current: u64 = 0,
    size_durable: u64 = 0,

    fn name_slice(file: *const File) []const u8 {
        return file.name[0..file.name_len];
    }
};

const Descriptor = union(enum) {
    free,
    socket: Address.Family,
    listener: u32,
    stream: struct { connection: u32, side: u1 },
    file: u32,
    /// A UDP socket, unbound until `bind_udp`.
    udp_unbound: Address.Family,
    /// A bound UDP socket.
    udp: Address,
};

pub const SimIo = struct {
    pub const Completion = struct {
        pub const Fd = FdSim;
        operation: common.Operation(FdSim) = .none,
        result: common.Result(FdSim) = .none,
        context: ?*anyopaque = null,
        callback: *const fn (?*anyopaque, *Completion) void = undefined,
        next: ?*Completion = null,
        ready_ns: u64 = 0,
        canceled: bool = false,
    };
    pub const Fd = FdSim;

    const methods = common.Methods(SimIo);
    pub const accept = methods.accept;
    pub const connect = methods.connect;
    pub const recv = methods.recv;
    pub const send = methods.send;
    pub const recvfrom = methods.recvfrom;
    pub const sendto = methods.sendto;
    pub const read = methods.read;
    pub const write = methods.write;
    pub const fsync = methods.fsync;
    pub const timeout = methods.timeout;
    pub const close = methods.close;

    world: *World,
    allocator: std.mem.Allocator,
    index: u32,
    options: NodeOptions,
    descriptors: []Descriptor,
    files: []File,
    file_memory: []u8,
    pending_head: ?*Completion = null,
    pending_tail: ?*Completion = null,
    pending_count: u32 = 0,

    /// Creates a node. `io` must not move afterwards: the world keeps a pointer to it.
    pub fn init(
        io: *SimIo,
        allocator: std.mem.Allocator,
        world: *World,
        options: NodeOptions,
    ) !void {
        assert(options.host.port == 0);
        assert(options.fds_max > 0);
        const disk = options.disk;
        assert(disk.latency_min_ns <= disk.latency_max_ns);
        const descriptors = try allocator.alloc(Descriptor, options.fds_max);
        errdefer allocator.free(descriptors);
        @memset(descriptors, .free);
        const file_bytes = @as(usize, disk.files_max) * disk.file_size_max * 2;
        const file_memory = try allocator.alloc(u8, file_bytes);
        errdefer allocator.free(file_memory);
        @memset(file_memory, 0);
        const files = try allocator.alloc(File, disk.files_max);
        for (files, 0..) |*file, index| {
            const size = disk.file_size_max;
            file.* = .{
                .current = file_memory[(index * 2) * size ..][0..size],
                .durable = file_memory[(index * 2 + 1) * size ..][0..size],
            };
        }
        io.* = .{
            .world = world,
            .allocator = allocator,
            .index = undefined,
            .options = options,
            .descriptors = descriptors,
            .files = files,
            .file_memory = file_memory,
        };
        io.index = world.register(io);
    }

    pub fn deinit(io: *SimIo) void {
        io.allocator.free(io.files);
        io.allocator.free(io.file_memory);
        io.allocator.free(io.descriptors);
        io.* = undefined;
    }

    pub fn now_monotonic_ns(io: *const SimIo) u64 {
        return io.world.now_ns;
    }

    pub fn now_realtime_ns(io: *const SimIo) u64 {
        const base_ns: i128 = io.world.options.realtime_start_ns + io.world.now_ns;
        const skewed = base_ns + io.options.realtime_offset_ns;
        assert(skewed >= 0);
        return @intCast(skewed);
    }

    /// Runs the whole world (all nodes) for `duration_ns` of simulated time.
    pub fn run_for_ns(io: *SimIo, duration_ns: u64) !void {
        io.world.run_for_ns(duration_ns);
    }

    /// Completes ready operations across the world without advancing time.
    pub fn tick(io: *SimIo) !void {
        _ = io.world.tick();
    }

    // Synchronous, cold-path setup calls.

    pub fn open_socket_tcp(io: *SimIo, family: Address.Family) common.SetupError!Fd {
        return io.descriptor_allocate(.{ .socket = family });
    }

    /// Binds and listens. Port 0 picks an ephemeral port. Returns the bound address.
    pub fn listen(
        io: *SimIo,
        fd: Fd,
        address: Address,
        backlog: u31,
    ) common.SetupError!Address {
        assert(backlog > 0);
        assert(io.descriptors[fd] == .socket);
        var bound = address;
        if (bound.same_host(Address.ip4(.{ 0, 0, 0, 0 }, 0))) bound = io.options.host.with_port(0);
        if (!bound.same_host(io.options.host)) return error.AddressNotAvailable;
        if (bound.port == 0) bound.port = io.port_ephemeral();
        if (io.world.listener_find(bound) != null) return error.AddressInUse;
        for (io.world.listeners, 0..) |*listener, index| {
            if (listener.used) continue;
            listener.used = true;
            listener.node = io.index;
            listener.fd = fd;
            listener.address = bound;
            listener.backlog_head = 0;
            listener.backlog_count = 0;
            io.descriptors[fd] = .{ .listener = @intCast(index) };
            return bound;
        }
        return error.SystemResources;
    }

    pub fn open_socket_udp(io: *SimIo, family: Address.Family) common.SetupError!Fd {
        return io.descriptor_allocate(.{ .udp_unbound = family });
    }

    /// Binds a UDP socket on this node's host. Port 0 picks an ephemeral port.
    pub fn bind_udp(io: *SimIo, fd: Fd, address: Address) common.SetupError!Address {
        assert(io.descriptors[fd] == .udp_unbound);
        var bound = address;
        if (bound.same_host(Address.ip4(.{ 0, 0, 0, 0 }, 0))) {
            bound = io.options.host.with_port(address.port); // Keep the requested port.
        }
        if (!bound.same_host(io.options.host)) return error.AddressNotAvailable;
        if (bound.port == 0) bound.port = io.port_ephemeral();
        if (io.world.udp_find(bound) != null) return error.AddressInUse;
        io.descriptors[fd] = .{ .udp = bound };
        return bound;
    }

    /// The oldest arrived datagram for this socket, or null. Never blocks.
    pub fn recvfrom_now(io: *SimIo, fd: Fd, buffer: []u8) ?common.Datagram {
        assert(buffer.len > 0);
        const descriptor = io.descriptors[fd];
        if (descriptor != .udp) return null;
        const world = io.world;
        var best: ?*InFlight = null;
        for (world.datagrams) |*datagram| {
            if (!datagram.used or !datagram.to.eql(descriptor.udp)) continue;
            if (datagram.arrive_ns > world.now_ns) continue;
            if (best == null or datagram.arrive_ns < best.?.arrive_ns) best = datagram;
        }
        const datagram = best orelse return null;
        datagram.used = false;
        world.datagram_stats.received += 1;
        const length = @min(datagram.length, buffer.len);
        @memcpy(buffer[0..length], datagram.bytes[0..length]);
        return .{ .length = @intCast(length), .from = datagram.from };
    }

    /// Queues one datagram with latency; dropped when the target is unbound or
    /// partitioned, or the loss roll fails. Returns false when refused locally (unbound
    /// socket, oversized, or every in-flight slot used), like a kernel refusing the send.
    pub fn sendto_now(io: *SimIo, fd: Fd, buffer: []const u8, address: Address) bool {
        io.datagram_send(fd, buffer, address) catch return false;
        return true;
    }

    fn datagram_send(
        io: *SimIo,
        fd: Fd,
        buffer: []const u8,
        address: Address,
    ) common.SendError!void {
        assert(buffer.len > 0);
        const descriptor = io.descriptors[fd];
        if (descriptor != .udp) return error.SocketNotConnected;
        if (buffer.len > common.datagram_size_max) return error.MessageTooBig;
        const world = io.world;
        const slot = for (world.datagrams) |*datagram| {
            if (!datagram.used) break datagram;
        } else return error.SystemResources;
        const stats = &world.datagram_stats;
        stats.sent += 1;
        const target = world.udp_find(address) orelse {
            stats.dropped_unbound += 1;
            return;
        };
        if (target.node != io.index and world.partitioned(io.index, target.node)) {
            stats.dropped_partition += 1;
            return;
        }
        if (world.roll(world.options.datagram_loss_ppm)) {
            stats.dropped_loss += 1;
            return;
        }
        slot.* = .{
            .used = true,
            .from = descriptor.udp,
            .to = address,
            .arrive_ns = world.now_ns + world.latency_ns(),
            .length = @intCast(buffer.len),
        };
        @memcpy(slot.bytes[0..buffer.len], buffer);
    }

    pub fn open_file(io: *SimIo, path: []const u8, mode: common.OpenMode) common.SetupError!Fd {
        if (path.len == 0 or path.len > file_name_size_max) return error.NameTooLong;
        const file_index = io.file_find(path) orelse blk: {
            if (mode != .create) return error.FileNotFound;
            break :blk try io.file_create(path);
        };
        return io.descriptor_allocate(.{ .file = file_index });
    }

    /// Synchronous close for cleanup paths. Prefer `close` on hot paths.
    pub fn close_now(io: *SimIo, fd: Fd) void {
        io.descriptor_close(fd);
    }

    /// Simulates a process crash: pending operations vanish without callbacks, every
    /// descriptor closes (peers see resets), and unsynced file data is lost.
    pub fn crash(io: *SimIo) void {
        io.pending_head = null;
        io.pending_tail = null;
        io.pending_count = 0;
        for (io.descriptors, 0..) |descriptor, fd| {
            if (descriptor == .stream) {
                io.world.connections[descriptor.stream.connection].reset = true;
            }
            if (descriptor != .free) io.descriptor_close(@intCast(fd));
        }
        for (io.files) |*file| {
            if (!file.used) continue;
            @memcpy(file.current, file.durable);
            file.size_current = file.size_durable;
        }
    }

    /// Resets the connection behind `fd`; both sides observe ConnectionResetByPeer.
    /// Shuts down both directions of a stream: pending and future recvs on `fd` return 0,
    /// sends fail with `BrokenPipe`, and the peer sees end of stream. The descriptor stays
    /// allocated until `close_now`, so in-flight operations complete before it is reused.
    pub fn shutdown_now(io: *SimIo, fd: Fd) void {
        const descriptor = io.descriptors[fd];
        if (descriptor != .stream) return;
        const connection = &io.world.connections[descriptor.stream.connection];
        const side = &connection.sides[descriptor.stream.side];
        assert(side.open);
        if (side.shut) return;
        side.shut = true;
        const peer = &connection.sides[descriptor.stream.side ^ 1];
        if ((peer.open or connection.pending_accept) and !connection.reset) {
            const world = io.world;
            peer.inbound.close_write(world.now_ns + world.latency_ns());
        }
    }

    /// See `common` for the contract. The operation completes with `error.Canceled` on the
    /// next tick unless it is already finished.
    pub fn cancel(io: *SimIo, target: *Completion) void {
        _ = io;
        if (!common.cancelable(FdSim, target.operation)) return;
        target.canceled = true;
    }

    /// The remote address of a connected stream, or null for other descriptors.
    pub fn peer_address(io: *SimIo, fd: Fd) ?Address {
        const descriptor = io.descriptors[fd];
        if (descriptor != .stream) return null;
        const connection = &io.world.connections[descriptor.stream.connection];
        return connection.sides[descriptor.stream.side ^ 1].address;
    }

    pub fn reset_connection(io: *SimIo, fd: Fd) void {
        const descriptor = io.descriptors[fd];
        assert(descriptor == .stream);
        io.world.connections[descriptor.stream.connection].reset = true;
    }

    pub fn enqueue(io: *SimIo, completion: *Completion) void {
        assert(completion.next == null);
        completion.canceled = false;
        const world = io.world;
        completion.ready_ns = switch (completion.operation) {
            .none => unreachable,
            .connect => world.now_ns + 2 * world.latency_ns(),
            .read, .write, .fsync => world.now_ns + world.prng.range(
                io.options.disk.latency_min_ns,
                io.options.disk.latency_max_ns,
            ),
            .timeout => |t| t.expires_ns,
            else => world.now_ns,
        };
        if (io.pending_tail) |tail| tail.next = completion else io.pending_head = completion;
        io.pending_tail = completion;
        io.pending_count += 1;
    }

    /// Completes every ready pending operation. Returns true if any callback ran.
    fn tick_ready(io: *SimIo) bool {
        // Only operations pending at entry are examined; callbacks may enqueue more.
        var budget = io.pending_count;
        var done_head: ?*Completion = null;
        var done_tail: ?*Completion = null;
        while (budget > 0) : (budget -= 1) {
            const completion = io.pending_pop();
            if (io.try_complete(completion)) {
                if (done_tail) |tail| tail.next = completion else done_head = completion;
                done_tail = completion;
            } else {
                io.pending_push(completion);
            }
        }
        var progressed = false;
        var iterations: u32 = 0;
        while (done_head) |completion| : (iterations += 1) {
            assert(iterations < loop_iterations_max);
            done_head = completion.next;
            completion.next = null;
            progressed = true;
            common.complete(Completion, completion);
        }
        return progressed;
    }

    fn pending_pop(io: *SimIo) *Completion {
        const completion = io.pending_head.?;
        io.pending_head = completion.next;
        if (io.pending_head == null) io.pending_tail = null;
        completion.next = null;
        io.pending_count -= 1;
        return completion;
    }

    fn pending_push(io: *SimIo, completion: *Completion) void {
        assert(completion.next == null);
        if (io.pending_tail) |tail| tail.next = completion else io.pending_head = completion;
        io.pending_tail = completion;
        io.pending_count += 1;
    }

    /// The earliest time a pending operation may become ready, or null if none is timed.
    fn next_event_ns(io: *SimIo) ?u64 {
        const now_ns = io.world.now_ns;
        var next: ?u64 = null;
        var cursor = io.pending_head;
        while (cursor) |completion| : (cursor = completion.next) {
            const event_ns: ?u64 = if (completion.canceled)
                now_ns
            else switch (completion.operation) {
                .recv => |op| io.recv_next_ns(op.socket),
                .recvfrom => |op| io.recvfrom_next_ns(op.socket),
                .accept, .send => null,
                else => completion.ready_ns,
            };
            if (event_ns) |e| {
                const clamped = @max(e, now_ns + 1);
                next = if (next) |n| @min(n, clamped) else clamped;
            }
        }
        return next;
    }

    fn recv_next_ns(io: *SimIo, fd: Fd) ?u64 {
        const descriptor = io.descriptors[fd];
        if (descriptor != .stream) return null;
        const connection = &io.world.connections[descriptor.stream.connection];
        if (connection.sides[descriptor.stream.side].shut) return io.world.now_ns;
        if (connection.hosts_partitioned(io.world)) return null;
        return connection.sides[descriptor.stream.side].inbound.next_arrival_ns(io.world.now_ns);
    }

    fn try_complete(io: *SimIo, completion: *Completion) bool {
        if (completion.canceled) {
            completion.result = common.canceled_result(FdSim, completion.operation);
            return true;
        }
        const now_ns = io.world.now_ns;
        switch (completion.operation) {
            .none => unreachable,
            .accept => |op| return io.try_accept(completion, op.socket),
            .connect => |op| {
                if (now_ns < completion.ready_ns) return false;
                completion.result = .{ .connect = io.do_connect(op.socket, op.address) };
            },
            .recv => |op| return io.try_recv(completion, op.socket, op.buffer),
            .send => |op| return io.try_send(completion, op.socket, op.buffer),
            .recvfrom => |op| {
                if (io.descriptors[op.socket] != .udp) {
                    completion.result = .{ .recvfrom = error.SocketNotConnected };
                } else {
                    const datagram = io.recvfrom_now(op.socket, op.buffer) orelse return false;
                    completion.result = .{ .recvfrom = datagram };
                }
            },
            .sendto => |op| {
                const sent = io.datagram_send(op.socket, op.buffer, op.address);
                completion.result = .{ .sendto = if (sent) op.buffer.len else |err| err };
            },
            .read => |op| {
                if (now_ns < completion.ready_ns) return false;
                completion.result = .{ .read = io.do_read(op.fd, op.buffer, op.offset) };
            },
            .write => |op| {
                if (now_ns < completion.ready_ns) return false;
                completion.result = .{ .write = io.do_write(op.fd, op.buffer, op.offset) };
            },
            .fsync => |op| {
                if (now_ns < completion.ready_ns) return false;
                completion.result = .{ .fsync = io.do_fsync(op.fd) };
            },
            .timeout => |op| {
                if (now_ns < op.expires_ns) return false;
                completion.result = .{ .timeout = {} };
            },
            .close => |op| {
                io.descriptor_close(op.fd);
                completion.result = .{ .close = {} };
            },
        }
        return true;
    }

    /// Earliest arrival of a datagram for `fd`; now for a non-UDP descriptor (it fails).
    fn recvfrom_next_ns(io: *SimIo, fd: Fd) ?u64 {
        const descriptor = io.descriptors[fd];
        if (descriptor != .udp) return io.world.now_ns;
        var next: ?u64 = null;
        for (io.world.datagrams) |*datagram| {
            if (!datagram.used or !datagram.to.eql(descriptor.udp)) continue;
            next = if (next) |n| @min(n, datagram.arrive_ns) else datagram.arrive_ns;
        }
        return next;
    }

    fn try_accept(io: *SimIo, completion: *Completion, fd: Fd) bool {
        const descriptor = io.descriptors[fd];
        if (descriptor != .listener) {
            completion.result = .{ .accept = error.SocketNotListening };
            return true;
        }
        const listener = &io.world.listeners[descriptor.listener];
        assert(listener.used and listener.node == io.index);
        if (listener.backlog_count == 0) return false;
        // Reserve the descriptor; it becomes a stream below once the connection is known.
        const new_fd = io.descriptor_allocate(.{ .socket = .ip4 }) catch {
            completion.result = .{ .accept = error.ProcessFdQuotaExceeded };
            return true;
        };
        const connection_index = listener.backlog[listener.backlog_head];
        const backlog_capacity: u32 = @intCast(listener.backlog.len);
        listener.backlog_head = (listener.backlog_head + 1) % backlog_capacity;
        listener.backlog_count -= 1;
        const connection = &io.world.connections[connection_index];
        assert(connection.used and connection.pending_accept);
        assert(!connection.sides[1].open);
        connection.pending_accept = false;
        connection.sides[1].node = io.index;
        connection.sides[1].fd = new_fd;
        connection.sides[1].open = true;
        io.descriptors[new_fd] = .{ .stream = .{ .connection = connection_index, .side = 1 } };
        completion.result = .{ .accept = new_fd };
        return true;
    }

    fn do_connect(io: *SimIo, fd: Fd, address: Address) common.ConnectError!void {
        const world = io.world;
        assert(io.descriptors[fd] == .socket);
        const listener = world.listener_find(address) orelse return error.ConnectionRefused;
        if (world.partitioned(io.index, listener.node)) return error.TimedOut;
        if (world.roll(world.options.refuse_ppm)) return error.ConnectionRefused;
        if (listener.backlog_count == listener.backlog.len) return error.ConnectionRefused;
        const connection_index = world.connection_allocate() orelse return error.SystemResources;
        const connection = &world.connections[connection_index];
        connection.sides[0].node = io.index;
        connection.sides[0].fd = fd;
        connection.sides[0].open = true;
        connection.sides[0].address = io.options.host.with_port(io.port_ephemeral());
        connection.sides[1].address = listener.address;
        // The server side opens on accept; until then its inbound pipe buffers bytes.
        connection.sides[1].node = listener.node;
        connection.pending_accept = true;
        const capacity: u32 = @intCast(listener.backlog.len);
        const tail = (listener.backlog_head + listener.backlog_count) % capacity;
        listener.backlog[tail] = connection_index;
        listener.backlog_count += 1;
        io.descriptors[fd] = .{ .stream = .{ .connection = connection_index, .side = 0 } };
    }

    fn try_recv(io: *SimIo, completion: *Completion, fd: Fd, buffer: []u8) bool {
        const descriptor = io.descriptors[fd];
        if (descriptor != .stream) {
            completion.result = .{ .recv = error.SocketNotConnected };
            return true;
        }
        const connection = &io.world.connections[descriptor.stream.connection];
        if (connection.reset) {
            completion.result = .{ .recv = error.ConnectionResetByPeer };
            return true;
        }
        if (connection.sides[descriptor.stream.side].shut) {
            completion.result = .{ .recv = 0 };
            return true;
        }
        if (connection.hosts_partitioned(io.world)) return false;
        const pipe = &connection.sides[descriptor.stream.side].inbound;
        const now_ns = io.world.now_ns;
        if (pipe.visible_bytes(now_ns) > 0) {
            completion.result = .{ .recv = pipe.pop(buffer, now_ns) };
            return true;
        }
        if (pipe.eof(now_ns)) {
            completion.result = .{ .recv = 0 };
            return true;
        }
        return false;
    }

    fn try_send(io: *SimIo, completion: *Completion, fd: Fd, buffer: []const u8) bool {
        const world = io.world;
        const descriptor = io.descriptors[fd];
        if (descriptor != .stream) {
            completion.result = .{ .send = error.SocketNotConnected };
            return true;
        }
        const connection = &world.connections[descriptor.stream.connection];
        if (!connection.reset and world.roll(world.options.reset_ppm)) connection.reset = true;
        if (connection.reset) {
            completion.result = .{ .send = error.ConnectionResetByPeer };
            return true;
        }
        const peer_side: u1 = descriptor.stream.side ^ 1;
        const peer = &connection.sides[peer_side];
        const own_shut = connection.sides[descriptor.stream.side].shut;
        if (own_shut or (!peer.open and !connection.pending_accept)) {
            completion.result = .{ .send = error.BrokenPipe };
            return true;
        }
        const free = peer.inbound.free_bytes();
        if (free == 0) return false;
        const size = @min(buffer.len, free, world.options.segment_size_max);
        peer.inbound.push(buffer[0..size], world.now_ns + world.latency_ns());
        completion.result = .{ .send = size };
        return true;
    }

    fn do_read(io: *SimIo, fd: Fd, buffer: []u8, offset: u64) common.ReadError!usize {
        const file = io.file_of(fd) orelse return error.NotOpenForReading;
        if (io.world.roll(io.options.disk.read_fault_ppm)) return error.InputOutput;
        if (offset >= file.size_current) return 0;
        const size: usize = @intCast(@min(buffer.len, file.size_current - offset));
        @memcpy(buffer[0..size], file.current[@intCast(offset)..][0..size]);
        return size;
    }

    fn do_write(io: *SimIo, fd: Fd, buffer: []const u8, offset: u64) common.WriteError!usize {
        const file = io.file_of(fd) orelse return error.NotOpenForWriting;
        if (io.world.roll(io.options.disk.write_fault_ppm)) return error.InputOutput;
        if (offset + buffer.len > file.current.len) return error.NoSpaceLeft;
        const start: usize = @intCast(offset);
        // Zero-fill any hole between the old end and the write offset.
        if (start > file.size_current) @memset(file.current[@intCast(file.size_current)..start], 0);
        @memcpy(file.current[start..][0..buffer.len], buffer);
        file.size_current = @max(file.size_current, offset + buffer.len);
        return buffer.len;
    }

    fn do_fsync(io: *SimIo, fd: Fd) common.FsyncError!void {
        const file = io.file_of(fd) orelse return error.Unexpected;
        if (io.world.roll(io.options.disk.write_fault_ppm)) return error.InputOutput;
        @memcpy(file.durable, file.current);
        file.size_durable = file.size_current;
    }

    fn file_of(io: *SimIo, fd: Fd) ?*File {
        const descriptor = io.descriptors[fd];
        if (descriptor != .file) return null;
        const file = &io.files[descriptor.file];
        assert(file.used);
        return file;
    }

    fn file_find(io: *SimIo, path: []const u8) ?u32 {
        for (io.files, 0..) |*file, index| {
            if (file.used and std.mem.eql(u8, file.name_slice(), path)) return @intCast(index);
        }
        return null;
    }

    fn file_create(io: *SimIo, path: []const u8) common.SetupError!u32 {
        assert(path.len <= file_name_size_max);
        for (io.files, 0..) |*file, index| {
            if (file.used) continue;
            file.used = true;
            @memcpy(file.name[0..path.len], path);
            file.name_len = @intCast(path.len);
            file.size_current = 0;
            file.size_durable = 0;
            return @intCast(index);
        }
        return error.NoSpaceLeft;
    }

    fn descriptor_allocate(io: *SimIo, descriptor: Descriptor) common.SetupError!Fd {
        for (io.descriptors, 0..) |*slot, fd| {
            if (slot.* != .free) continue;
            assert(descriptor != .free);
            slot.* = descriptor;
            return @intCast(fd);
        }
        return error.ProcessFdQuotaExceeded;
    }

    fn descriptor_close(io: *SimIo, fd: Fd) void {
        const descriptor = io.descriptors[fd];
        assert(descriptor != .free);
        switch (descriptor) {
            .free => unreachable,
            .socket, .file, .udp_unbound => {},
            .udp => |address| io.world.datagrams_purge(address),
            .listener => |index| io.listener_close(index),
            .stream => |s| io.world.connection_release_side(s.connection, s.side),
        }
        io.descriptors[fd] = .free;
    }

    fn listener_close(io: *SimIo, index: u32) void {
        const listener = &io.world.listeners[index];
        assert(listener.used and listener.node == io.index);
        // Connections still in the backlog were never accepted: reset them.
        var remaining = listener.backlog_count;
        var position = listener.backlog_head;
        while (remaining > 0) : (remaining -= 1) {
            const connection = &io.world.connections[listener.backlog[position]];
            assert(connection.pending_accept);
            connection.reset = true;
            connection.pending_accept = false;
            connection_release_if_unused(connection);
            position = (position + 1) % @as(u32, @intCast(listener.backlog.len));
        }
        listener.used = false;
    }

    fn port_ephemeral(io: *SimIo) u16 {
        const world = io.world;
        const port = world.port_next;
        world.port_next = if (port == std.math.maxInt(u16)) 40_000 else port + 1;
        return port;
    }
};

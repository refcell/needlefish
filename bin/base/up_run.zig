//! The run stage of `base up`: the node's processes, supervised, and its live view.
//!
//! Children (this binary's own subcommands, each logging to `logs/<name>.log`):
//! - `peers`: `base el-peers` crawling discv4 for the chain's execution peers (the current
//!   fork hash) into `peers.txt`, restarted whenever a crawl ends; el-run re-reads the file.
//! - `el`: `base el-run` on the database: blocks over devp2p (outbound connections only, so
//!   it works behind NAT), every block executed and checked, JSON-RPC and the Engine API.
//! - `bridge`: `base https-bridge` from loopback ports to the L1 RPC and beacon (consensus
//!   speaks plain HTTP).
//! - `consensus`: `base consensus` deriving safe and finalized from L1 against el-run. It
//!   starts once el-run's engine ring is warm (until then el-run's `finalized` says "warming
//!   up") and L1 answers, and restarts with el-run (a new ring is cold).
//!
//! A child that exits is restarted with exponential backoff; a known failure in its log tail
//! prints its cause and fix. Ten quick failures in a row of el-run stop the node with that
//! message. SIGINT/SIGTERM stop every child (SIGTERM, then SIGKILL after a grace period).
//!
//! The view (`Table`) reads el-run's log, never its database: one row per executed block
//! once it follows the tip, a progress bar while it catches up, and the safe and finalized
//! heads from consensus. `watch` runs the same view over a node that is already running.

const std = @import("std");
const builtin = @import("builtin");
const base = @import("base");
const up_check = @import("up_check.zig");
const up_view = @import("up_view.zig");

const Io = std.Io;
const View = up_view.View;
const Line = up_view.Line;
const jwt = base.utilities.jwt;
const assert = std.debug.assert;

pub const Role = enum { peers, el, bridge, consensus };
const roles = std.enums.values(Role);

pub const Ports = struct {
    rpc: u16,
    engine: u16,
    consensus: u16,
    l1: u16,
    beacon: u16,
};

pub const Settings = struct {
    exe: []const u8,
    datadir: []const u8,
    db: []const u8,
    chain: *const up_check.Chain,
    ports: Ports,
    jwt_path: []const u8,
    jwt_secret: jwt.Secret,
    /// The L1 endpoints consensus uses; null until one answers (`l1_candidates` are retried).
    l1: ?up_check.L1,
    l1_candidates: struct { rpcs: []const []const u8, beacons: []const []const u8 },
    peers_path: []const u8,
    consensus: bool,
    stop: *const std.atomic.Value(bool),
};

const restart_backoff_s_max: u64 = 300;
/// A child that ran this long had a healthy run: its backoff starts over.
const healthy_ms: i64 = 600_000;
const quick_failures_max: u32 = 10;
const warm_poll_ms: i64 = 20_000;
const l1_retry_ms: i64 = 300_000;
const stop_grace_ms: i64 = 60_000;
const tick_ms = 200;
const tail_bytes = 4096;

// ---- The live view -------------------------------------------------------------------

/// Where a node's view reads from: all read-only.
pub const Watch = struct {
    /// el-run's output (one line per block); null: no rows.
    log_path: ?[]const u8,
    /// el-run's JSON-RPC (`http://127.0.0.1:8545`).
    rpc_url: ?[]const u8,
    /// The consensus node's RPC (`optimism_syncStatus`).
    consensus_url: ?[]const u8,
    /// A public node of the chain, for the tip el-run is compared with.
    reference_rpc: []const u8,
    stop: *const std.atomic.Value(bool),
};

/// Rows from el-run's log, a catch-up bar, safe and finalized from consensus.
pub const Table = struct {
    gpa: std.mem.Allocator,
    io: Io,
    view: *View,
    watch: Watch,
    tail: ?*up_view.Tail = null,
    following: bool = false,
    /// Attached to a running node: the rows start without a phase line.
    quiet_start: bool = false,
    first: ?u64 = null,
    head: ?u64 = null,
    behind: ?u64 = null,
    safe: ?u64 = null,
    finalized: ?u64 = null,
    rows: u64 = 0,
    lag_sum_ms: u64 = 0,
    reference_tip: ?u64 = null,
    last_consensus_ms: i64 = 0,
    last_reference_ms: i64 = 0,
    /// A short note for the ticker (consensus waiting on the ring, peers, ...).
    ticker_note: [96]u8 = undefined,
    ticker_note_len: usize = 0,

    pub fn init(
        gpa: std.mem.Allocator,
        io: Io,
        view: *View,
        sources: Watch,
        from_end: bool,
    ) !Table {
        var table: Table = .{ .gpa = gpa, .io = io, .view = view, .watch = sources };
        if (sources.log_path) |path| {
            const tail = try gpa.create(up_view.Tail);
            tail.* = .init(io, path, from_end);
            table.tail = tail;
        }
        return table;
    }

    pub fn deinit(table: *Table) void {
        if (table.tail) |tail| table.gpa.destroy(tail);
        table.tail = null;
    }

    pub fn note(table: *Table, comptime format: []const u8, args: anytype) void {
        const text = std.fmt.bufPrint(
            &table.ticker_note,
            format,
            args,
        ) catch table.ticker_note[0..0];
        table.ticker_note_len = text.len;
    }

    fn now_ms(table: *const Table) i64 {
        return Io.Clock.awake.now(table.io).toMilliseconds();
    }

    /// Shows what el-run logged since the last tick, and the heads of consensus.
    pub fn tick(table: *Table) void {
        const now = table.now_ms();
        if (table.watch.consensus_url) |url| if (now - table.last_consensus_ms >= 2_000) {
            table.last_consensus_ms = now;
            table.safe = rpc_number(table.gpa, table.io, url, "optimism_syncStatus", "\"safe_l2\"");
            table.finalized = rpc_number(
                table.gpa,
                table.io,
                url,
                "optimism_syncStatus",
                "\"finalized_l2\"",
            );
        };
        if (table.tail) |tail| {
            var lines = std.mem.tokenizeScalar(u8, tail.read(table.io), '\n');
            while (lines.next()) |text| if (Line.parse(text)) |line| table.on_line(&line);
        }
        if (table.tail == null) table.poll_head(now);
        table.draw_live(now);
    }

    fn on_line(table: *Table, line: *const Line) void {
        switch (line.kind) {
            .executing => {
                table.first = line.number;
                table.view.ok(
                    "el-run",
                    "executing from block {d}, blocks over devp2p",
                    .{line.number},
                );
            },
            .summary => {
                table.head = line.number;
                table.behind = line.behind;
            },
            .at_tip => table.start_rows(line.number),
            .mismatch => table.view.refused(
                line.number,
                "el-run kept its head on the parent; see its log",
            ),
            .block => {
                table.head = line.number;
                if (table.first == null) table.first = line.number;
                // At the tip a block lands within a few seconds of its slot.
                if (!table.following and line.lag_ms < 10_000) table.start_rows(line.number);
                if (!table.following) return;
                table.rows += 1;
                table.lag_sum_ms += line.lag_ms;
                table.view.row(line, table.safe, table.finalized);
            },
        }
    }

    fn start_rows(table: *Table, number: u64) void {
        if (table.following) return;
        table.following = true;
        table.behind = 0;
        if (!table.quiet_start) table.view.ok(
            "follow",
            "at the tip, block {d}: every block executed and checked",
            .{number},
        );
        table.view.table();
    }

    /// Without a log: the head from el-run's JSON-RPC, for the ticker.
    fn poll_head(table: *Table, now: i64) void {
        const url = table.watch.rpc_url orelse return;
        if (now - table.last_reference_ms < 2_000) return;
        table.head = rpc_number(
            table.gpa,
            table.io,
            url,
            "eth_blockNumber",
            null,
        ) orelse table.head;
    }

    /// The live line: the catch-up bar, or the ticker under the rows.
    fn draw_live(table: *Table, now: i64) void {
        if (now - table.last_reference_ms >= 10_000) {
            table.last_reference_ms = now;
            table.reference_tip = rpc_number(
                table.gpa,
                table.io,
                table.watch.reference_rpc,
                "eth_blockNumber",
                null,
            );
        }
        const note_text = table.ticker_note[0..table.ticker_note_len];
        const head = table.head orelse {
            table.view.ticker("waiting for el-run's first block  {s}", .{note_text});
            return;
        };
        if (!table.following) {
            const first = table.first orelse head;
            const behind = table.behind orelse return;
            const done: f64 = @floatFromInt(head -| first);
            const fraction = done / @max(done + @as(f64, @floatFromInt(behind)), 1);
            const format = "block {d}, {d} behind the peers  {s}";
            table.view.progress(now, "catch-up", fraction, format, .{
                head, behind, note_text,
            });
            return;
        }
        const lag_avg_ms = if (table.rows == 0) 0 else table.lag_sum_ms / table.rows;
        const behind = if (table.reference_tip) |tip| tip -| head else 0;
        const format = "head {d}  {d} behind the public tip  lag avg {d} ms  {d} blocks shown  {s}";
        table.view.ticker(format, .{
            head, behind, lag_avg_ms, table.rows, note_text,
        });
    }
};

/// Shows a running node read-only until Ctrl-C: rows from its log, safe and finalized from
/// its consensus RPC. Opens no database, takes no lock, signals nothing.
pub fn watch(gpa: std.mem.Allocator, io: Io, view: *View, config: Watch) !u8 {
    var table: Table = try .init(gpa, io, view, config, true);
    defer table.deinit();
    table.quiet_start = true;
    if (config.log_path == null) view.note(
        "no el-run log given (--el.log): the head only, no rows",
        .{},
    );
    while (!config.stop.load(.acquire)) {
        table.tick();
        try Io.sleep(io, .fromMilliseconds(tick_ms), .awake);
    }
    view.ok("watch", "stopped watching; the node keeps running", .{});
    return 0;
}

/// A block number from a JSON-RPC server: the result, or the `number` inside the result's
/// `object` field.
pub fn rpc_number(
    gpa: std.mem.Allocator,
    io: Io,
    url: []const u8,
    method: []const u8,
    object: ?[]const u8,
) ?u64 {
    var request_buffer: [160]u8 = undefined;
    const request = std.fmt.bufPrint(&request_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
        "\"method\":\"{s}\",\"params\":[]}}", .{method}) catch unreachable;
    var response: [16 * 1024]u8 = undefined;
    const answer = up_check.fetch(
        gpa,
        io,
        .{ .url = url, .payload = request },
        &response,
        5_000,
    ) catch
        return null;
    if (answer.status != .ok) return null;
    return number_in(answer.body, object);
}

const Process = struct {
    role: Role,
    pid: ?std.posix.pid_t = null,
    started_ms: i64 = 0,
    /// Earliest restart time while stopped.
    restart_ms: i64 = 0,
    failures: u32 = 0,
    starts: u32 = 0,
};

pub const Node = struct {
    gpa: std.mem.Allocator,
    io: Io,
    view: *View,
    settings: *const Settings,
    processes: [roles.len]Process,
    table: Table = undefined,
    warm: bool = false,
    l1: ?up_check.L1,
    peers_seen: bool = false,
    last_l1_probe_ms: i64 = 0,
    last_warm_poll_ms: i64 = 0,
    /// Set when the node cannot go on (repeated el-run failures): the reason.
    fatal: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, io: Io, view: *View, settings: *const Settings) Node {
        var node: Node = .{
            .gpa = gpa,
            .io = io,
            .view = view,
            .settings = settings,
            .processes = undefined,
            .l1 = settings.l1,
        };
        for (roles, 0..) |role, index| node.processes[index] = .{ .role = role };
        assert(node.processes[@backingInt(Role.el)].role == .el);
        return node;
    }

    fn process(node: *Node, role: Role) *Process {
        return &node.processes[@backingInt(role)];
    }

    fn now_ms(node: *const Node) i64 {
        return Io.Clock.awake.now(node.io).toMilliseconds();
    }

    /// Runs until a stop is requested or the node cannot go on; then stops every child.
    pub fn run(node: *Node) !u8 {
        var arena_state: std.heap.ArenaAllocator = .init(node.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const settings = node.settings;
        const ports = settings.ports;
        node.table = try .init(node.gpa, node.io, node.view, .{
            .log_path = try node.log_path(arena, .el),
            .rpc_url = try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{ports.rpc}),
            .consensus_url = if (settings.consensus)
                try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{ports.consensus})
            else
                null,
            .reference_rpc = settings.chain.run.rpc,
            .stop = settings.stop,
        }, true);
        defer node.table.deinit();
        node.last_l1_probe_ms = node.now_ms();
        try node.write_state();
        while (!settings.stop.load(.acquire) and node.fatal == null) {
            try node.tick();
            try Io.sleep(node.io, .fromMilliseconds(tick_ms), .awake);
        }
        node.stop_all();
        if (node.fatal) |reason| {
            node.view.fail("node", "stopped: {s}", .{reason});
            return 1;
        }
        node.view.ok("stopped", "run `base up` again to continue where it left off", .{});
        return 0;
    }

    fn tick(node: *Node) !void {
        for (&node.processes) |*child| node.reap(child);
        try node.ensure(.peers);
        const peers = count_peers(node.io, node.settings.peers_path);
        if (peers > 0 and !node.peers_seen) {
            node.peers_seen = true;
            node.view.ok(
                "peers",
                "{s} execution peers found over discv4",
                .{node.settings.chain.name},
            );
        }
        if (peers > 0 or node.process(.el).pid != null) try node.ensure(.el);
        if (node.settings.consensus) try node.tick_consensus(node.now_ms());
        node.set_note(peers);
        node.table.tick();
    }

    fn tick_consensus(node: *Node, now: i64) !void {
        assert(node.settings.consensus);
        if (node.l1 == null and now - node.last_l1_probe_ms >= l1_retry_ms) {
            node.last_l1_probe_ms = now;
            node.probe_l1();
        }
        if (node.l1 == null) return;
        try node.ensure(.bridge);
        const el_running = node.process(.el).pid != null;
        if (el_running and !node.warm and now - node.last_warm_poll_ms >= warm_poll_ms) {
            node.last_warm_poll_ms = now;
            node.warm = node.engine_warm();
        }
        if (node.warm and node.process(.bridge).pid != null) try node.ensure(.consensus);
    }

    fn set_note(node: *Node, peers: u32) void {
        const consensus = node.settings.consensus;
        if (peers == 0) return node.table.note("finding execution peers over discv4", .{});
        if (consensus and node.l1 == null) return node.table.note("consensus waits for L1", .{});
        if (consensus and !node.warm) {
            return node.table.note("consensus starts when el-run's engine ring is warm", .{});
        }
        node.table.note("", .{});
    }

    /// Starts `role` unless it runs or waits out its backoff.
    fn ensure(node: *Node, role: Role) !void {
        const child = node.process(role);
        if (child.pid != null or node.now_ms() < child.restart_ms) return;
        var arena: std.heap.ArenaAllocator = .init(node.gpa);
        defer arena.deinit();
        const argv = try node.arguments(arena.allocator(), role);
        const log = try open_log(try node.log_path(arena.allocator(), role));
        defer log.close(node.io);
        var spawned = std.process.spawn(node.io, .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .{ .file = log },
            .stderr = .{ .file = log },
        }) catch |err| {
            node.view.warn("cannot start {t}: {t}; retrying in 30 s", .{ role, err });
            child.restart_ms = node.now_ms() + 30_000;
            return;
        };
        child.pid = spawned.id.?;
        spawned.id = null; // Reaped by `reap`, not by `std.process.Child`.
        child.started_ms = node.now_ms();
        child.starts += 1;
        if (role == .el) node.warm = false;
        if (role == .consensus) node.view.ok("consensus", "started: safe and finalized from " ++
            "L1 ({s})", .{host_of(node.l1.?.rpc)});
        try node.write_state();
    }

    /// Notices a child's exit: shows why, schedules the restart, stops what depends on it.
    fn reap(node: *Node, child: *Process) void {
        const pid = child.pid orelse return;
        const status = try_wait(pid) orelse return;
        child.pid = null;
        const now = node.now_ms();
        const ran_ms = now - child.started_ms;
        child.failures = if (ran_ms >= healthy_ms) 1 else child.failures + 1;
        const shift: u6 = @intCast(@min(child.failures, 16));
        const backoff_s = @min(restart_backoff_s_max, @as(u64, 1) << shift);
        child.restart_ms = now + @as(i64, @intCast(backoff_s)) * 1000;
        if (child.role == .peers and status == 0) {
            child.failures = 0;
            child.restart_ms = now; // A crawl ended: start the next.
            return;
        }
        var tail_buffer: [tail_bytes]u8 = undefined;
        const tail = node.log_tail(child.role, &tail_buffer);
        node.view.warn("{t} exited (status {d}) after {d} s; restarting in {d} s", .{
            child.role, status, @divTrunc(ran_ms, 1000), backoff_s,
        });
        show_last_lines(node.view, tail, 3);
        if (diagnose(child.role, tail)) |hint| node.view.fix("{s}", .{hint});
        if (child.role == .el) {
            node.warm = false;
            node.stop_child(.consensus);
            if (child.failures >= quick_failures_max) {
                node.fatal = "el-run keeps failing; its log has the cause";
            }
        }
    }

    fn stop_child(node: *Node, role: Role) void {
        const child = node.process(role);
        const pid = child.pid orelse return;
        terminate(node.io, pid, stop_grace_ms);
        child.pid = null;
        child.restart_ms = 0;
        node.write_state() catch {};
    }

    /// Stops consensus first (it drives el-run), then the bridge, el-run, the crawler.
    fn stop_all(node: *Node) void {
        node.view.note("stopping the node", .{});
        const order = [_]Role{ .consensus, .bridge, .el, .peers };
        for (order) |role| node.stop_child(role);
    }

    fn log_path(node: *const Node, arena: std.mem.Allocator, role: Role) ![]const u8 {
        return std.fmt.allocPrint(arena, "{s}/logs/{t}.log", .{ node.settings.datadir, role });
    }

    /// The last `buffer.len` bytes of a child's log.
    fn log_tail(node: *const Node, role: Role, buffer: []u8) []const u8 {
        var arena: std.heap.ArenaAllocator = .init(node.gpa);
        defer arena.deinit();
        const path = node.log_path(arena.allocator(), role) catch return "";
        return read_tail(node.io, path, buffer);
    }

    fn arguments(node: *const Node, arena: std.mem.Allocator, role: Role) ![]const []const u8 {
        const settings = node.settings;
        const ports = settings.ports;
        const chain = settings.chain.name;
        var list: std.ArrayList([]const u8) = .empty;
        try list.append(arena, settings.exe);
        switch (role) {
            .peers => {
                const hash = up_check.fork_hash(settings.chain, node.unix_s());
                try list.appendSlice(arena, &.{
                    "el-peers",          "--chain",                                      chain,
                    "--fork-hash",       try std.fmt.allocPrint(arena, "{x}", .{&hash}), "--peers",
                    settings.peers_path, "--duration",                                   "3600",
                });
            },
            .el => try list.appendSlice(arena, &.{
                "el-run",                      "--db",             settings.db,
                "--chain",                     chain,              "--peers",
                settings.peers_path,           "--rpc",            "--rpc.addr",
                try address(arena, ports.rpc), "--engine.addr",    try address(arena, ports.engine),
                "--engine.jwt",                settings.jwt_path,  "--engine.ring-blocks",
                "65536",                       "--engine.ring-mb", "2048",
            }),
            .bridge => try list.appendSlice(arena, &.{
                "https-bridge", "--routes",
                try std.fmt.allocPrint(arena, "{d}={s},{d}={s}", .{
                    ports.l1, node.l1.?.rpc, ports.beacon, node.l1.?.beacon,
                }),
            }),
            .consensus => try node.consensus_arguments(arena, &list),
        }
        return list.items;
    }

    fn consensus_arguments(
        node: *const Node,
        arena: std.mem.Allocator,
        list: *std.ArrayList([]const u8),
    ) !void {
        const settings = node.settings;
        const ports = settings.ports;
        const datadir = settings.datadir;
        try list.appendSlice(arena, &.{
            "consensus",
            "--rollup-config",
            try std.fmt.allocPrint(arena, "{s}/consensus/rollup.json", .{datadir}),
            "--l1",
            try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{ports.l1}),
            "--l1-beacon",
            try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{ports.beacon}),
            "--l2",
            try std.fmt.allocPrint(arena, "http://127.0.0.1:{d}", .{ports.engine}),
            "--l2-jwt",
            settings.jwt_path,
            "--p2p.disabled",
            "--rpc.port",
            try std.fmt.allocPrint(arena, "{d}", .{ports.consensus}),
            "--safedb.path",
            try std.fmt.allocPrint(arena, "{s}/consensus/safedb.bin", .{datadir}),
            "--checkpoint.path",
            try std.fmt.allocPrint(arena, "{s}/consensus/checkpoint.bin", .{datadir}),
        });
    }

    /// Retries the L1 candidates while none answered.
    fn probe_l1(node: *Node) void {
        assert(node.l1 == null);
        const candidates = node.settings.l1_candidates;
        var report: up_check.L1Report = .{};
        const chain = node.settings.chain;
        const choice = up_check.choose_l1(
            node.gpa,
            node.io,
            chain,
            candidates.rpcs,
            candidates.beacons,
            false,
            &report,
        );
        if (choice != .ok) return;
        node.l1 = choice.ok;
        node.view.ok(
            "L1",
            "{s}, beacon {s}",
            .{ host_of(choice.ok.rpc), host_of(choice.ok.beacon) },
        );
    }

    fn unix_s(node: *const Node) u64 {
        const now = Io.Clock.real.now(node.io);
        return @intCast(@max(0, now.toSeconds()));
    }

    /// Whether el-run's engine ring answers `finalized` (it says "warming up" until it holds
    /// enough blocks below the tip for the consensus node's startup walk).
    fn engine_warm(node: *Node) bool {
        var token_buffer: [jwt.token_size_max]u8 = undefined;
        const token = jwt.create(node.settings.jwt_secret, node.unix_s(), &token_buffer);
        var url_buffer: [64]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}", .{
            node.settings.ports.engine,
        }) catch unreachable;
        const request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\"," ++
            "\"params\":[\"finalized\",false]}";
        var response: [64 * 1024]u8 = undefined;
        const answer = up_check.fetch(node.gpa, node.io, .{
            .url = url,
            .payload = request,
            .bearer = token,
        }, &response, 10_000) catch return false;
        if (answer.status != .ok) return false;
        const warm = std.mem.indexOf(u8, answer.body, "\"result\":{") != null;
        return warm;
    }

    /// Writes `node.json`: where the node answers and its children's pids, for a later
    /// `base up` (which then shows this node, or stops what a killed run left behind).
    fn write_state(node: *const Node) !void {
        const settings = node.settings;
        const ports = settings.ports;
        var buffer: [4096]u8 = undefined;
        var writer: Io.Writer = .fixed(&buffer);
        var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const log = try std.fmt.bufPrint(&path_buffer, "{s}/logs/el.log", .{settings.datadir});
        try writer.print("{{\"chain\": \"{s}\", \"el.log\": {f}, " ++
            "\"el.rpc\": \"http://127.0.0.1:{d}\"", .{
            settings.chain.name, std.json.fmt(log, .{}), ports.rpc,
        });
        if (settings.consensus) {
            try writer.print(", \"cl.rpc\": \"http://127.0.0.1:{d}\"", .{ports.consensus});
        }
        try writer.writeAll(", \"pids\": {");
        var first = true;
        for (node.processes) |child| {
            const pid = child.pid orelse continue;
            try writer.print("{s}\"{t}\": {d}", .{ if (first) "" else ", ", child.role, pid });
            first = false;
        }
        try writer.writeAll("}}\n");
        const path = try std.fmt.bufPrint(&path_buffer, "{s}/node.json", .{settings.datadir});
        try Io.Dir.cwd().writeFile(node.io, .{ .sub_path = path, .data = writer.buffered() });
    }
};

pub fn host_of(url: []const u8) []const u8 {
    const scheme_end = (std.mem.indexOf(u8, url, "://") orelse return url) + 3;
    const rest = url[scheme_end..];
    return rest[0 .. std.mem.indexOfScalar(u8, rest, '/') orelse rest.len];
}

/// A log file children append to (`O_APPEND`: restarts and several writers never overwrite).
pub fn open_log(path: []const u8) !Io.File {
    assert(path.len > 0);
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o644);
    assert(fd >= 0);
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
}

fn address(arena: std.mem.Allocator, port: u16) ![]const u8 {
    assert(port != 0);
    return std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{port});
}

/// The number after `"number":` in `object` (or the `"result"` value when null): a JSON
/// integer or a quantity string.
pub fn number_in(body: []const u8, object: ?[]const u8) ?u64 {
    const key = object orelse return up_check.json_quantity(body, "\"result\"");
    const at = std.mem.indexOf(u8, body, key) orelse return null;
    const rest = body[at + key.len ..];
    const field = "\"number\":";
    const number_at = std.mem.indexOf(u8, rest, field) orelse return null;
    const value = std.mem.trimStart(u8, rest[number_at + field.len ..], " ");
    if (value.len > 0 and value[0] == '"') return up_check.json_quantity(rest[number_at..], field);
    const end = std.mem.indexOfNone(u8, value, "0123456789") orelse value.len;
    return std.fmt.parseInt(u64, value[0..end], 10) catch null;
}

/// Lines of `peers.txt` that hold an enode.
pub fn count_peers(io: Io, path: []const u8) u32 {
    var buffer: [64 * 1024]u8 = undefined;
    const text = Io.Dir.cwd().readFile(io, path, &buffer) catch return 0;
    var count: u32 = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, std.mem.trim(u8, line, " \r\t"), "enode://")) count += 1;
    }
    return count;
}

fn read_tail(io: Io, path: []const u8, buffer: []u8) []const u8 {
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch return "";
    defer file.close(io);
    const length = file.length(io) catch return "";
    const start = length -| buffer.len;
    const got = file.readPositionalAll(io, buffer, start) catch return "";
    return buffer[0..got];
}

fn show_last_lines(view: *View, text: []const u8, count: u32) void {
    var start = text.len;
    var lines: u32 = 0;
    const trimmed = std.mem.trimEnd(u8, text, "\n");
    start = trimmed.len;
    while (start > 0 and lines < count) {
        start = if (std.mem.lastIndexOfScalar(u8, trimmed[0..start], '\n')) |at| at else 0;
        lines += 1;
    }
    const shown = std.mem.trimStart(u8, trimmed[start..], "\n");
    var iterator = std.mem.splitScalar(u8, shown, '\n');
    while (iterator.next()) |line| view.note("| {s}", .{line});
}

/// The cause and fix of a known failure in a child's log tail.
pub fn diagnose(role: Role, tail: []const u8) ?[]const u8 {
    const Known = struct { role: ?Role, needle: []const u8, hint: []const u8 };
    const known = [_]Known{
        .{ .role = .el, .needle = "FileLocked", .hint = "another process holds the database " ++
            "(a node still shutting down, or a second node on the same file); retrying. If it " ++
            "persists, stop the other process (fuser -v <database>)." },
        .{ .role = .el, .needle = "StateFull", .hint = "this block needs more room than the " ++
            "database's layout has (an older layout, v1). Re-import with `base up --reimport`." },
        .{ .role = .el, .needle = "no usable peers", .hint = "no execution peers yet; the " ++
            "crawler keeps looking." },
        .{ .role = .el, .needle = "MISMATCH", .hint = "a block did not reproduce: this is a " ++
            "needlefish bug, please report the log above; the database head is unchanged." },
        .{ .role = null, .needle = "AddressInUse", .hint = "a port was taken after the checks " ++
            "ran; choose free ones with --rpc.port, --engine.port, --consensus.port." },
        .{ .role = null, .needle = "NoSpaceLeft", .hint = "the disk is full; free space on " ++
            "the datadir's disk, then run the command again." },
        .{ .role = .consensus, .needle = "ReorgDetected", .hint = "an L1 reorg; consensus " ++
            "resets and continues on its own." },
    };
    for (known) |entry| {
        if (entry.role != null and entry.role.? != role) continue;
        if (std.mem.indexOf(u8, tail, entry.needle) != null) return entry.hint;
    }
    return null;
}

// ---- Processes -----------------------------------------------------------------------

/// The exit status of `pid` when it has exited (reaping it), else null.
pub fn try_wait(pid: std.posix.pid_t) ?u32 {
    assert(pid > 0);
    var status: if (builtin.os.tag == .linux) i32 else c_int = 0;
    const result = if (builtin.os.tag == .linux)
        std.os.linux.waitpid(pid, &status, std.posix.W.NOHANG)
    else
        std.c.waitpid(pid, &status, std.posix.W.NOHANG);
    const reaped: i64 = if (builtin.os.tag == .linux)
        @bitCast(@as(u64, result))
    else
        result;
    if (reaped <= 0) return null; // Running (0), or already reaped (-ECHILD).
    const word: u32 = @bitCast(status);
    if (std.posix.W.IFEXITED(word)) return std.posix.W.EXITSTATUS(word);
    return 128 + @as(u32, @backingInt(std.posix.W.TERMSIG(word)));
}

/// SIGTERM, then SIGKILL once `grace_ms` passes; reaps the child.
pub fn terminate(io: Io, pid: std.posix.pid_t, grace_ms: i64) void {
    assert(pid > 0 and grace_ms > 0);
    std.posix.kill(pid, .TERM) catch return;
    const start = Io.Clock.awake.now(io).toMilliseconds();
    while (Io.Clock.awake.now(io).toMilliseconds() - start < grace_ms) {
        if (try_wait(pid) != null) return;
        Io.sleep(io, .fromMilliseconds(200), .awake) catch {};
    }
    std.posix.kill(pid, .KILL) catch {};
    for (0..50) |_| {
        if (try_wait(pid) != null) return;
        Io.sleep(io, .fromMilliseconds(200), .awake) catch {};
    }
}

/// Stops a process that is not our child (no exit status to reap): SIGTERM, then SIGKILL
/// once `grace_ms` passes; returns when it is gone.
pub fn stop_foreign(io: Io, pid: std.posix.pid_t, grace_ms: i64) void {
    assert(pid > 1 and grace_ms > 0);
    std.posix.kill(pid, .TERM) catch return;
    const start = Io.Clock.awake.now(io).toMilliseconds();
    var signal: std.posix.SIG = .TERM;
    for (0..1000) |_| {
        // Signal 0 checks existence; ESRCH once it is gone.
        std.posix.kill(pid, @fromBackingInt(@intCast(0))) catch return;
        if (signal == .TERM and Io.Clock.awake.now(io).toMilliseconds() - start >= grace_ms) {
            signal = .KILL;
            std.posix.kill(pid, .KILL) catch return;
        }
        Io.sleep(io, .fromMilliseconds(200), .awake) catch return;
    }
}

// ---- Tests ---------------------------------------------------------------------------

const testing = std.testing;

test "up run: numbers from JSON-RPC answers" {
    try testing.expectEqual(@as(?u64, 0x3577f1c), number_in("{\"result\":\"0x3577f1c\"}", null));
    const sync =
        \\{"jsonrpc":"2.0","id":1,"result":{"current_l1":{"number":24000000},
        \\"safe_l2":{"hash":"0xab","number":56139134,"timestamp":1},
        \\"finalized_l2":{"hash":"0xcd","number": 56134227}}}
    ;
    try testing.expectEqual(@as(?u64, 56_139_134), number_in(sync, "\"safe_l2\""));
    try testing.expectEqual(@as(?u64, 56_134_227), number_in(sync, "\"finalized_l2\""));
    try testing.expectEqual(@as(?u64, null), number_in(sync, "\"unsafe_l2\""));
    try testing.expectEqual(@as(?u64, null), number_in("{\"error\":{}}", null));
}

test "up run: known failures name their fix" {
    const locked = "cannot open /d/node.nf: FileLocked\n";
    try testing.expect(std.mem.indexOf(u8, diagnose(.el, locked).?, "another process") != null);
    try testing.expect(diagnose(.consensus, locked) == null); // Not a consensus failure.
    const full = "el-run: block 5 hash 0x..: refused: StateFull; database head 4\n";
    try testing.expect(std.mem.indexOf(u8, diagnose(.el, full).?, "--reimport") != null);
    const port = "consensus: listen failed: AddressInUse\n";
    try testing.expect(std.mem.indexOf(u8, diagnose(.consensus, port).?, "--rpc.port") != null);
    try testing.expect(diagnose(.el, "block 1 checks ok\n") == null);
}

test "up run: peers are the enode lines" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "peers.txt", .data = "enode://a@1.2.3.4:30303\n" ++
        "\n# comment\n  enode://b@5.6.7.8:30303\r\njunk\n" });
    var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPathFile(io, "peers.txt", &path_buffer);
    try testing.expectEqual(@as(u32, 2), count_peers(io, path_buffer[0..length]));
    try testing.expectEqual(@as(u32, 0), count_peers(io, "/nonexistent/peers.txt"));
}

test "up run: a child's exit status is reaped once" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    var child = try std.process.spawn(io, .{ .argv = &.{ "sh", "-c", "exit 7" } });
    const pid = child.id.?;
    child.id = null;
    var status: ?u32 = null;
    for (0..100) |_| {
        status = try_wait(pid);
        if (status != null) break;
        try Io.sleep(io, .fromMilliseconds(20), .awake);
    }
    try testing.expectEqual(@as(?u32, 7), status);
    try testing.expectEqual(@as(?u32, null), try_wait(pid)); // Already reaped.
    var sleeper = try std.process.spawn(io, .{ .argv = &.{ "sleep", "30" } });
    const sleeper_pid = sleeper.id.?;
    sleeper.id = null;
    try testing.expectEqual(@as(?u32, null), try_wait(sleeper_pid));
    terminate(io, sleeper_pid, 5_000);
    try testing.expectEqual(@as(?u32, null), try_wait(sleeper_pid));
}

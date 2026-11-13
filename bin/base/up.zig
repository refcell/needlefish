//! `base up`: one command from nothing to a Base node that follows the tip.
//!
//!     base up [--chain base-mainnet|base-sepolia] [--datadir <dir>] [--db <file>]
//!             [--l1 <url>] [--l1-beacon <url>] [--no-consensus]
//!             [--rpc.port <n>] [--engine.port <n>] [--consensus.port <n>]
//!             [--download.connections <n>] [--download.rate <MB/s>]
//!             [--gossip [--gossip.port <n>]] [--reimport] [--dry-run] [--plain]
//!
//! Every run checks the setup first, then does only what is missing, in order:
//! 1. Snapshot (`up_snapshot.zig`): the chain's latest public snapshot, downloaded and
//!    extracted in one resumable pass, every member checked against the manifest's blake3.
//! 2. Import: `base snapshot-import --out` into `import/`, which recomputes the state root and
//!    requires it to equal the snapshot block's header. Only then is the database renamed to
//!    `db/node.nf`, so that path only ever names a verified database, and a run that finds
//!    it never imports again (`--reimport` is the only way to replace it).
//! 3. Run (`up_run.zig`): peer crawl, el-run (devp2p, JSON-RPC, Engine API), the L1 bridge,
//!    and consensus once el-run's engine ring is warm; supervised until Ctrl-C.
//!
//! Checks (`up_check.zig`), each with its fix: the chain name (missing: base-mainnet; a typo
//! names the nearest chain) and the datadir's chain; another `base up` on the datadir (its
//! endpoints are printed instead), children a killed run left behind (stopped); a database
//! another process holds (its pid), or one of an unknown or older layout; free disk against
//! the remaining stages' peak; ports (unnamed ones move to free ones); the L1 RPC and beacon
//! (their chain must be the chain's L1; unreachable ones defer consensus, not the node).
//! `--dry-run` runs every check and prints the plan without writing or starting anything.

const std = @import("std");
const builtin = @import("builtin");
const base = @import("base");
const up_check = @import("up_check.zig");
const up_snapshot = @import("up_snapshot.zig");
const up_tar = @import("up_tar.zig");
const up_run = @import("up_run.zig");
const up_view = @import("up_view.zig");
const el_engine = @import("el_engine.zig");

const Io = std.Io;
const Chain = up_check.Chain;
const Snapshot = up_snapshot.Snapshot;
const jwt = base.utilities.jwt;
const View = up_view.View;
const assert = std.debug.assert;

const usage =
    \\usage: base up [--chain base-mainnet|base-sepolia] [--datadir <dir>] [--db <file>]
    \\               [--l1 <url>] [--l1-beacon <url>] [--no-consensus]
    \\               [--rpc.port <n>] [--engine.port <n>] [--consensus.port <n>]
    \\               [--download.connections <n>] [--download.rate <MB/s>]
    \\               [--gossip [--gossip.port <n>]] [--reimport] [--dry-run] [--plain]
    \\
    \\Runs a Base node that follows the tip, from nothing: downloads and verifies the latest
    \\public snapshot, imports it, then runs the execution node (blocks over devp2p) and the
    \\consensus node (safe and finalized from L1). Run it again to resume or restart; it never
    \\re-imports over a verified database.
    \\
    \\  --chain       base-mainnet (default) or base-sepolia
    \\  --datadir     where everything lives (default: $HOME/.needlefish/<chain>)
    \\  --db          run an existing imported database (base snapshot-import --out) instead
    \\  --l1          L1 (Ethereum) JSON-RPC for consensus (default: public endpoints)
    \\  --l1-beacon   L1 beacon API for blobs (default: a public endpoint)
    \\  --no-consensus  execution only: no L1 needed, no safe or finalized heads
    \\  --rpc.port    JSON-RPC port on 127.0.0.1 (default 8545)
    \\  --engine.port Engine API port on 127.0.0.1 (default 8551)
    \\  --consensus.port  consensus RPC port on 127.0.0.1 (default 7545)
    \\  --download.connections  parallel snapshot downloads (default 8)
    \\  --download.rate  cap the snapshot download, in MB/s (default: none); leave room on the
    \\               link when a node on it fetches blocks over the same connection
    \\  --gossip     also join Base's consensus gossip and execute the sequencer-signed block
    \\               at the tip as it arrives (devp2p stays the fallback)
    \\  --gossip.port   gossip TCP port on all interfaces, UDP one above (default 9222)
    \\  --reimport    delete the datadir's database and import the latest snapshot again
    \\  --dry-run     check everything and print the plan; change nothing
    \\  --plain       no color and no redrawn lines (the default without a terminal)
    \\
    \\A node is already running in the datadir (its node.json answers): base up shows it,
    \\read-only, and starts nothing. --el.log, --el.rpc and --cl.rpc name one directly.
    \\
;

const Flags = struct {
    chain: ?[]const u8 = null,
    datadir: ?[]const u8 = null,
    db: ?[]const u8 = null,
    l1: ?[]const u8 = null,
    l1_beacon: ?[]const u8 = null,
    consensus: bool = true,
    gossip: bool = false,
    gossip_port: ?u16 = null,
    rpc_port: ?u16 = null,
    engine_port: ?u16 = null,
    consensus_port: ?u16 = null,
    connections: u32 = 8,
    /// MB/s; 0: no cap.
    rate_mb_per_s: u32 = 0,
    reimport: bool = false,
    dry_run: bool = false,
    /// No color and no redraws (also without a TTY).
    plain: bool = false,
    /// Watch a running node through these instead of the datadir's `node.json`.
    el_log: ?[]const u8 = null,
    el_rpc: ?[]const u8 = null,
    cl_rpc: ?[]const u8 = null,
    /// Test hook: another snapshot listing (a local server).
    listing: []const u8 = up_snapshot.listing_url,
};

const connections_max = 64;
const rate_mb_per_s_max = 100_000;

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const name = args[index];
        if (std.mem.eql(u8, name, "--reimport")) {
            flags.reimport = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--dry-run")) {
            flags.dry_run = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--no-consensus")) {
            flags.consensus = false;
            continue;
        }
        if (std.mem.eql(u8, name, "--plain")) {
            flags.plain = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--gossip")) {
            flags.gossip = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--help") or std.mem.eql(u8, name, "-h")) return error.Help;
        if (index + 1 == args.len) return fail_flag("{s} needs a value", .{name});
        index += 1;
        try parse_valued(&flags, name, args[index]);
    }
    if (flags.reimport and flags.db != null) {
        return fail_flag("--reimport replaces the datadir's own database, not a --db file", .{});
    }
    if (flags.gossip_port != null and !flags.gossip) {
        return fail_flag("--gossip.port needs --gossip", .{});
    }
    if (!flags.consensus and (flags.l1 != null or flags.l1_beacon != null)) {
        return fail_flag("--no-consensus runs without L1; drop --l1 and --l1-beacon", .{});
    }
    return flags;
}

fn parse_valued(flags: *Flags, name: []const u8, value: []const u8) !void {
    const eql = std.mem.eql;
    if (eql(u8, name, "--chain")) {
        flags.chain = value;
    } else if (eql(u8, name, "--datadir")) {
        flags.datadir = value;
    } else if (eql(u8, name, "--db")) {
        flags.db = value;
    } else if (eql(u8, name, "--l1")) {
        flags.l1 = try url_flag(name, value);
    } else if (eql(u8, name, "--l1-beacon")) {
        flags.l1_beacon = try url_flag(name, value);
    } else if (eql(u8, name, "--rpc.port")) {
        flags.rpc_port = try port_flag(name, value);
    } else if (eql(u8, name, "--engine.port")) {
        flags.engine_port = try port_flag(name, value);
    } else if (eql(u8, name, "--consensus.port")) {
        flags.consensus_port = try port_flag(name, value);
    } else if (eql(u8, name, "--gossip.port")) {
        flags.gossip_port = try port_flag(name, value);
        if (flags.gossip_port.? == std.math.maxInt(u16)) {
            return fail_flag("--gossip.port takes up to 65534 (UDP uses the port above)", .{});
        }
    } else if (eql(u8, name, "--download.rate")) {
        flags.rate_mb_per_s = std.fmt.parseInt(u32, value, 10) catch 0;
        if (flags.rate_mb_per_s == 0 or flags.rate_mb_per_s > rate_mb_per_s_max) {
            return fail_flag("--download.rate takes 1 to {d} (MB/s)", .{rate_mb_per_s_max});
        }
    } else if (eql(u8, name, "--download.connections")) {
        flags.connections = std.fmt.parseInt(u32, value, 10) catch 0;
        if (flags.connections == 0 or flags.connections > connections_max) {
            return fail_flag("--download.connections takes 1 to {d}", .{connections_max});
        }
    } else if (eql(u8, name, "--el.log")) {
        flags.el_log = value;
    } else if (eql(u8, name, "--el.rpc")) {
        flags.el_rpc = try url_flag(name, value);
    } else if (eql(u8, name, "--cl.rpc")) {
        flags.cl_rpc = try url_flag(name, value);
    } else if (eql(u8, name, "--snapshot.listing")) {
        flags.listing = try url_flag(name, value);
    } else return fail_flag("unknown flag {s}", .{name});
}

fn url_flag(name: []const u8, value: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, value, "http://") or std.mem.startsWith(u8, value, "https://")) {
        return std.mem.trimEnd(u8, value, "/");
    }
    return fail_flag("{s} takes an http:// or https:// URL, not '{s}'", .{ name, value });
}

fn port_flag(name: []const u8, value: []const u8) !u16 {
    const port = std.fmt.parseInt(u16, value, 10) catch 0;
    if (port == 0) return fail_flag(
        "{s} takes a port from 1 to 65535, not '{s}'",
        .{ name, value },
    );
    return port;
}

fn fail_flag(comptime format: []const u8, args: anytype) error{InvalidArguments} {
    if (!builtin.is_test) std.debug.print("base up: " ++ format ++ "\n", args);
    return error.InvalidArguments;
}

var stop_requested: std.atomic.Value(bool) = .init(false);

fn on_signal(_: std.posix.SIG) callconv(.c) void {
    // A second Ctrl-C while the node stops: leave at once.
    if (stop_requested.swap(true, .acq_rel)) std.process.exit(130);
}

fn install_signals() void {
    if (std.posix.Sigaction == void) return;
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = on_signal },
        .mask = std.posix.sigemptyset(),
        // Interrupted system calls restart: the threads' blocking reads must not see EINTR.
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
    std.posix.sigaction(.HUP, &action, null);
}

/// Everything a run works from, resolved from the flags.
const Up = struct {
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    view: *View,
    flags: Flags,
    chain: *const Chain,
    /// Absolute.
    datadir: []const u8,
    exe: []const u8,
    db: []const u8,
    /// The database is the datadir's own (`db/node.nf`), not a `--db` file.
    managed: bool,
    home: ?[]const u8,

    fn path(up: *const Up, comptime format: []const u8, args: anytype) []const u8 {
        return std.fmt.allocPrint(up.arena, "{s}/" ++ format, .{up.datadir} ++ args) catch
            @panic("out of memory");
    }

    fn exists(up: *const Up, file_path: []const u8) bool {
        Io.Dir.cwd().access(up.io, file_path, .{}) catch return false;
        return true;
    }

    fn now_ms(up: *const Up) i64 {
        return Io.Clock.awake.now(up.io).toMilliseconds();
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch |err| {
        std.debug.print("{s}", .{usage});
        return if (err == error.Help) 0 else 2;
    };
    var view_buffer: [16 * 1024]u8 = undefined;
    var view: View = .init(init.io, &view_buffer, flags.plain);
    defer view.finish();
    var up = (try resolve(init, flags, &view)) orelse return 2;
    install_signals();
    // A running node is only ever watched: nothing below writes, locks, or signals.
    if (flags.el_log != null or flags.el_rpc != null or flags.cl_rpc != null) {
        return watch_node(
            &up,
            .{ .el_log = flags.el_log, .el_rpc = flags.el_rpc, .cl_rpc = flags.cl_rpc },
        );
    }
    const described = try read_node_file(&up);
    if (try lock_held(&up)) {
        if (described) |node| return watch_node(&up, node);
        view.header(up.chain.name, up.chain.config.chain_id, shown_path(&up, up.datadir));
        view.ok("node", "another `base up` is preparing this datadir (snapshot or import); " ++
            "its terminal and {s}/logs show its progress", .{up.datadir});
        return 0;
    }
    if (described) |node| if (!owns_orphans(&up, &node)) {
        if (try node_answers(&up, &node)) return watch_node(&up, node);
        // A node.json that `base up` did not leave behind names someone else's node: never
        // set up (lock, download, import) over it because it did not answer once.
        if (!left_by_base_up(&up, &node)) return refuse_silent_node(&up, &node);
    };
    view.header(up.chain.name, up.chain.config.chain_id, shown_path(&up, up.datadir));
    if (!try prepare_datadir(&up)) return 1;
    // One `base up` per datadir; the lock lasts as long as this process.
    const lock = take_lock(&up) catch |err| switch (err) {
        error.WouldBlock => {
            view.fail("node", "another `base up` took this datadir just now", .{});
            return 1;
        },
        else => return err,
    };
    defer if (lock) |file| file.close(up.io);
    if (!up.flags.dry_run) if (described) |node| stop_orphans(&up, &node);
    return run_stages(&up);
}

/// Whether another process holds the datadir's `up.lock` (tested without creating it).
fn lock_held(up: *const Up) !bool {
    const file = Io.Dir.cwd().openFile(up.io, up.path("up.lock", .{}), .{
        .lock = .exclusive,
        .lock_nonblocking = true,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        error.WouldBlock => return true,
        else => return err,
    };
    file.close(up.io);
    return false;
}

/// The datadir's `up.lock`, held exclusively; a dry run only tests an existing one.
fn take_lock(up: *const Up) !?Io.File {
    const path = up.path("up.lock", .{});
    if (up.flags.dry_run) {
        const file = Io.Dir.cwd().openFile(up.io, path, .{
            .lock = .exclusive,
            .lock_nonblocking = true,
        }) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        return file;
    }
    return try Io.Dir.cwd().createFile(up.io, path, .{
        .truncate = false,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });
}

fn resolve(init: std.process.Init, flags: Flags, view: *View) !?Up {
    const arena = init.arena.allocator();
    const chain = if (flags.chain) |name| switch (up_check.resolve_chain(name)) {
        .chain => |chain| chain,
        .unknown => |nearest| {
            view.fail("chain", "unknown chain '{s}'", .{name});
            if (nearest) |chain| view.fix("did you mean --chain {s}?", .{chain.name});
            view.note("chains: base-mainnet (the default), base-sepolia", .{});
            return null;
        },
    } else up_check.default_chain;
    const datadir_flag = flags.datadir orelse default: {
        const home = init.environ_map.get("HOME") orelse {
            view.fail("datadir", "HOME is not set, so there is no default datadir", .{});
            view.fix("pass --datadir <dir>", .{});
            return null;
        };
        break :default try std.fmt.allocPrint(arena, "{s}/.needlefish/{s}", .{ home, chain.name });
    };
    var up: Up = .{
        .gpa = init.gpa,
        .arena = arena,
        .io = init.io,
        .view = view,
        .flags = flags,
        .chain = chain,
        .datadir = try absolute_path(init.io, arena, datadir_flag),
        .exe = try std.process.executablePathAlloc(init.io, arena),
        .db = undefined,
        .managed = flags.db == null,
        .home = init.environ_map.get("HOME"),
    };
    up.db = if (flags.db) |db| try absolute_path(
        init.io,
        arena,
        db,
    ) else up.path("db/node.nf", .{});
    return up;
}

/// `path` made absolute (children run with other working directories); it need not exist.
fn absolute_path(io: Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    assert(path.len > 0);
    if (Io.Dir.cwd().realPathFileAlloc(io, path, arena)) |real| return real else |_| {}
    if (std.fs.path.isAbsolute(path)) return path;
    const cwd = try Io.Dir.cwd().realPathFileAlloc(io, ".", arena);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ cwd, path });
}

/// Creates the datadir's directories and binds the datadir to its chain.
fn prepare_datadir(up: *Up) !bool {
    if (!up.flags.dry_run) Io.Dir.cwd().createDirPath(up.io, up.datadir) catch |err| {
        up.view.fail("datadir", "cannot create {s}: {t}", .{ up.datadir, err });
        up.view.fix("pass --datadir with a directory you can write", .{});
        return false;
    };
    const dirs = [_][]const u8{ "logs", "db", "consensus", "snapshot", "import" };
    if (!up.flags.dry_run) for (dirs) |name| {
        try Io.Dir.cwd().createDirPath(up.io, up.path("{s}", .{name}));
    };
    const marker = up.path("chain", .{});
    var buffer: [64]u8 = undefined;
    if (Io.Dir.cwd().readFile(up.io, marker, &buffer)) |text| {
        const recorded = std.mem.trim(u8, text, " \n");
        if (!std.mem.eql(u8, recorded, up.chain.name)) {
            up.view.fail("chain", "{s} holds a {s} node, not {s}", .{
                up.datadir, recorded, up.chain.name,
            });
            up.view.fix("run `base up --chain {s}`, or pass another --datadir for {s}", .{
                recorded, up.chain.name,
            });
            return false;
        }
    } else |err| switch (err) {
        error.FileNotFound => if (!up.flags.dry_run) try Io.Dir.cwd().writeFile(up.io, .{
            .sub_path = marker,
            .data = try std.fmt.allocPrint(up.arena, "{s}\n", .{up.chain.name}),
        }),
        else => return err,
    }
    const default_note = if (up.flags.chain == null) " (the default; --chain to change)" else "";
    up.view.ok("chain", "{s}{s}", .{ up.chain.name, default_note });
    return true;
}

/// `node.json`: where a running node answers. `base up` writes it while its node runs; an
/// operator can write it by hand for a node started otherwise, so `base up` shows that one.
///
///     {"chain": "base-mainnet", "el.log": "/path/el.log", "el.rpc": "http://127.0.0.1:8545",
///      "cl.rpc": "http://127.0.0.1:7545", "pids": {"el": 4242}}
///
/// Every field is optional (`pids` only matter to `base up` itself); `~/` expands to $HOME.
pub const NodeFile = struct {
    chain: ?[]const u8 = null,
    el_log: ?[]const u8 = null,
    el_rpc: ?[]const u8 = null,
    cl_rpc: ?[]const u8 = null,
    pids: []const Pid = &.{},

    pub const Pid = struct { role: []const u8, pid: std.posix.pid_t };

    pub fn parse(arena: std.mem.Allocator, text: []const u8, home: ?[]const u8) !NodeFile {
        const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
        if (root != .object) return error.BadNodeFile;
        var node: NodeFile = .{
            .chain = try string(root, "chain"),
            .el_log = try expand(arena, try string(root, "el.log"), home),
            .el_rpc = try string(root, "el.rpc"),
            .cl_rpc = try string(root, "cl.rpc"),
        };
        if (root.object.get("pids")) |pids| {
            if (pids != .object) return error.BadNodeFile;
            var list: std.ArrayList(Pid) = .empty;
            var iterator = pids.object.iterator();
            while (iterator.next()) |entry| {
                const value = entry.value_ptr.*;
                const in_range = value == .integer and value.integer > 1 and
                    value.integer <= std.math.maxInt(i32);
                if (!in_range) {
                    return error.BadNodeFile;
                }
                try list.append(
                    arena,
                    .{ .role = entry.key_ptr.*, .pid = @intCast(value.integer) },
                );
            }
            node.pids = list.items;
        }
        if (node.el_log == null and node.el_rpc == null) return error.BadNodeFile;
        return node;
    }

    fn string(root: std.json.Value, key: []const u8) !?[]const u8 {
        const value = root.object.get(key) orelse return null;
        if (value != .string or value.string.len == 0) return error.BadNodeFile;
        return value.string;
    }

    fn expand(arena: std.mem.Allocator, path: ?[]const u8, home: ?[]const u8) !?[]const u8 {
        const text = path orelse return null;
        if (!std.mem.startsWith(u8, text, "~/")) return text;
        const dir = home orelse return error.BadNodeFile;
        return try std.fmt.allocPrint(arena, "{s}{s}", .{ dir, text[1..] });
    }
};

fn read_node_file(up: *const Up) !?NodeFile {
    const path = up.path("node.json", .{});
    const text = Io.Dir.cwd().readFileAlloc(
        up.io,
        path,
        up.arena,
        .limited(64 * 1024),
    ) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return null,
        else => return err,
    };
    return NodeFile.parse(up.arena, text, up.home) catch {
        up.view.fail("node", "{s} is not a node description", .{path});
        up.view.fix("delete it, or write it as {{\"el.log\": \"<el-run log>\", \"el.rpc\": " ++
            "\"http://127.0.0.1:8545\", \"cl.rpc\": \"http://127.0.0.1:7545\"}}", .{});
        return error.BadNodeFile;
    };
}

/// Whether the described node runs: its el-run answers `eth_chainId` (for the right chain),
/// or, with no RPC named, its log exists.
fn node_answers(up: *const Up, node: *const NodeFile) !bool {
    const url = node.el_rpc orelse return up.exists(node.el_log.?);
    const id = up_run.rpc_number(up.gpa, up.io, url, "eth_chainId", null) orelse return false;
    if (id == up.chain.config.chain_id) return true;
    up.view.fail("node", "the node in {s} (el.rpc {s}) is chain {d}, not {s}", .{
        up.datadir, url, id, up.chain.name,
    });
    up.view.fix("pass the --chain it runs, or another --datadir", .{});
    return error.WrongChain;
}

/// `path` as the header shows it: under $HOME as `~/...`, so a screen never names the user.
fn shown_path(up: *const Up, path: []const u8) []const u8 {
    const home = up.home orelse return path;
    assert(path.len > 0);
    if (home.len == 0 or home.len >= path.len) return path;
    if (!std.mem.startsWith(u8, path, home) or path[home.len] != '/') return path;
    const shown = std.fmt.allocPrint(up.arena, "~{s}", .{path[home.len..]}) catch return path;
    assert(shown[0] == '~');
    return shown;
}

/// Shows a running node, read-only, until Ctrl-C.
fn watch_node(up: *Up, node: NodeFile) !u8 {
    if (node.chain) |name| switch (up_check.resolve_chain(name)) {
        .chain => |chain| up.chain = chain,
        .unknown => {},
    };
    const detail = try std.fmt.allocPrint(up.arena, "{s}  read-only view, Ctrl-C leaves it " ++
        "running", .{
        shown_path(up, up.datadir),
    });
    up.view.header(up.chain.name, up.chain.config.chain_id, detail);
    return up_run.watch(up.gpa, up.io, up.view, .{
        .log_path = node.el_log,
        .rpc_url = node.el_rpc,
        .consensus_url = node.cl_rpc,
        .reference_rpc = up.chain.run.rpc,
        .stop = &stop_requested,
    });
}

/// Whether `node.json` names children a killed `base up` left running on this datadir.
fn owns_orphans(up: *const Up, node: *const NodeFile) bool {
    for (node.pids) |entry| if (runs_this_node(up, entry.pid)) return true;
    return false;
}

/// Whether `node.json` is a stale one a killed `base up` wrote: it names children (a
/// hand-written description names none) and none of them runs any more.
fn left_by_base_up(up: *const Up, node: *const NodeFile) bool {
    if (node.pids.len == 0) return false;
    for (node.pids) |entry| {
        assert(entry.pid > 1);
        if (up_check.process_running(up.io, @intCast(entry.pid))) return false;
    }
    return true;
}

/// Fails closed on a described node that does not answer: nothing is set up or touched.
fn refuse_silent_node(up: *const Up, node: *const NodeFile) u8 {
    assert(node.el_rpc != null or node.el_log != null);
    const datadir = shown_path(up, up.datadir);
    up.view.header(up.chain.name, up.chain.config.chain_id, datadir);
    if (node.el_rpc) |url| {
        up.view.fail("node", "{s}/node.json describes a node at {s} that does not answer", .{
            datadir, url,
        });
    } else {
        up.view.fail("node", "{s}/node.json describes a node whose log {s} does not exist", .{
            datadir, node.el_log.?,
        });
    }
    up.view.fix("start that node, or delete {s}/node.json to set up a new node here", .{
        datadir,
    });
    return 1;
}

/// Stops children a killed `base up` left running (named in `node.json`, still running this
/// binary on this datadir), so they release the database and the ports.
fn stop_orphans(up: *const Up, node: *const NodeFile) void {
    for (node.pids) |entry| {
        if (!runs_this_node(up, entry.pid)) continue;
        up.view.warn("stopping {s} (pid {d}), left running by an earlier `base up`", .{
            entry.role, entry.pid,
        });
        up_run.stop_foreign(up.io, entry.pid, 60_000);
    }
    Io.Dir.cwd().deleteFile(up.io, up.path("node.json", .{})) catch {};
}

/// Whether `pid` runs this binary on this datadir or database (Linux; elsewhere no process
/// is touched).
fn runs_this_node(up: *const Up, pid: std.posix.pid_t) bool {
    var buffer: [4096]u8 = undefined;
    const cmdline = up_check.process_cmdline(up.io, pid, &buffer) orelse return false;
    const exe_end = std.mem.indexOfScalar(u8, cmdline, 0) orelse return false;
    if (!std.mem.eql(u8, cmdline[0..exe_end], up.exe)) return false;
    return std.mem.indexOf(u8, cmdline, up.datadir) != null or
        std.mem.indexOf(u8, cmdline, up.db) != null;
}

fn run_stages(up: *Up) !u8 {
    const dry_run = up.flags.dry_run;
    if (up.flags.reimport and !dry_run) try delete_database(up);
    const database = try check_database(up);
    switch (database) {
        .unusable => return 1,
        .in_use => |pid| {
            up.view.fail("database", "{s} is in use by another process", .{up.db});
            if (pid) |holder| up.view.note("held by pid {d}", .{holder});
            up.view.fix("stop that node (one writer per database); to watch it instead, " ++
                "describe it in {s}/node.json (see base up --help)", .{up.datadir});
            return 1;
        },
        .ready, .missing => {},
    }
    const ready = database == .ready and !(dry_run and up.flags.reimport);
    // A dry run reports every failed check; a run stops at the first.
    var problems: u32 = 0;
    var ports = try pick_ports(up) orelse return 1;
    const l1 = try choose_l1(up) orelse if (dry_run) blk: {
        problems += 1;
        break :blk L1Plan.disabled;
    } else return 1;
    check_memory(up);
    var snapshot: ?Snapshot = null;
    const disk_ok = if (!ready) disk: {
        snapshot = try plan_snapshot(up) orelse return 1;
        break :disk try check_disk_snapshot(up, &snapshot.?);
    } else try check_disk_running(up);
    if (!disk_ok) {
        if (!dry_run) return 1;
        problems += 1;
    }
    if (dry_run) {
        print_plan(up, ready, ports, l1, if (snapshot) |*value| value else null);
        if (problems > 0) {
            up.view.fail("dry run", "{d} check{s} failed (above); nothing was changed", .{
                problems, if (problems == 1) "" else "s",
            });
            return 1;
        }
        up.view.ok("dry run", "nothing was changed", .{});
        return 0;
    }
    if (!ready) {
        const stage = try fetch_snapshot(up, &snapshot.?);
        if (stage != 0 or stop_requested.load(.acquire)) return stage;
        const imported = try import_snapshot(up, &snapshot.?);
        if (imported != 0 or stop_requested.load(.acquire)) return imported;
        // Hours went by: a port free at the start (a neighbour node restarting then) may be
        // taken now, so the node's ports are picked again right before it binds them.
        ports = try pick_ports(up) orelse return 1;
    }
    return start_node(up, ports, l1);
}

fn delete_database(up: *Up) !void {
    assert(up.managed);
    if (!up.exists(up.db)) return;
    if (try up_check.database_locked(up.io, up.db)) {
        up.view.fail("reimport", "the database is in use", .{});
        up.view.fix("stop its node first, then run `base up --reimport` again", .{});
        return error.DatabaseInUse;
    }
    try Io.Dir.cwd().deleteFile(up.io, up.db);
    Io.Dir.cwd().deleteFile(up.io, up.path("db/node.nf.counts", .{})) catch {};
    up.view.ok("reimport", "deleted {s}; importing the latest snapshot", .{up.db});
}

const Database = union(enum) {
    ready,
    missing,
    unusable,
    /// Locked by a running node (its pid when known): shown, never touched.
    in_use: ?u32,
};

/// The database's state: ready to run, missing (import it), in use, or unusable.
fn check_database(up: *const Up) !Database {
    if (!up.exists(up.db)) {
        if (!up.managed) {
            up.view.fail("database", "--db {s} does not exist", .{up.db});
            up.view.fix("pass the path of a database `base snapshot-import --out` wrote", .{});
            return .unusable;
        }
        if (up.flags.reimport and up.flags.dry_run) up.view.note(
            "--reimport would delete {s}",
            .{up.db},
        );
        return .missing;
    }
    if (up.flags.reimport and up.flags.dry_run) {
        up.view.note("--reimport would delete {s}", .{up.db});
        return .missing;
    }
    if (!check_layout(up)) return .unusable;
    if (try up_check.database_locked(up.io, up.db)) {
        // A killed node may still be exiting: its lock goes with it.
        if (try wait_unlocked(up)) return .ready;
        return .{ .in_use = lock_holder(up) };
    }
    up.view.ok("database", "{s}", .{up.db});
    return .ready;
}

/// The database's sizing record (`<db>.counts`): present, known, and its layout's limits.
fn check_layout(up: *const Up) bool {
    const counts_path = std.fmt.allocPrint(up.arena, "{s}.counts", .{up.db}) catch return false;
    var buffer: [64]u8 = undefined;
    const bytes = Io.Dir.cwd().readFile(up.io, counts_path, &buffer) catch {
        up.view.fail("database", "{s} has no {s}: not a needlefish database, or its import " ++
            "never finished", .{ up.db, std.fs.path.basename(counts_path) });
        if (up.managed) up.view.fix("`base up --reimport`", .{}) else up.view.fix("pass a " ++
            "database `base snapshot-import --out` wrote", .{});
        return false;
    };
    const counts = base.execution.import.to_disk.Counts.decode(bytes) catch {
        up.view.fail("database", "{s} has a layout this needlefish does not know", .{up.db});
        up.view.fix("update needlefish (git pull && just release), or `base up --reimport`", .{});
        return false;
    };
    if (counts.shape == .v1) {
        up.view.warn("{s} has the older layout v1: it refuses blocks with more than 16,384 " ++
            "trie writes (StateFull); if el-run stops on one, run `base up --reimport`", .{up.db});
    }
    return true;
}

/// Waits up to two minutes for a held database lock to go (a node still exiting).
fn wait_unlocked(up: *const Up) !bool {
    const wait_s = 120;
    var waited_s: u32 = 0;
    while (try up_check.database_locked(up.io, up.db)) : (waited_s += 2) {
        // A running node answers its JSON-RPC: no need to wait for it.
        if (lock_holder(up)) |pid| if (up_check.process_running(up.io, pid) and waited_s >= 10) {
            return false;
        };
        if (waited_s >= wait_s or stop_requested.load(.acquire)) return false;
        up.view.progress(
            up.now_ms(),
            "database",
            @as(f64, @floatFromInt(waited_s)) / wait_s,
            "locked; waiting for its holder to exit",
            .{},
        );
        try Io.sleep(up.io, .fromSeconds(2), .awake);
    }
    return true;
}

fn lock_holder(up: *const Up) ?u32 {
    if (builtin.os.tag != .linux) return null;
    const stat = Io.Dir.cwd().statFile(up.io, up.db, .{}) catch return null;
    const text = Io.Dir.cwd().readFileAlloc(up.io, "/proc/locks", up.arena, .limited(1 << 20)) catch
        return null;
    return up_check.lock_holder(text, stat.inode);
}

fn pick_ports(up: *const Up) !?up_run.Ports {
    const Want = struct { flag: []const u8, default: u16, named: ?u16, udp_next: bool = false };
    const wants = [_]Want{
        .{ .flag = "--rpc.port", .default = 8545, .named = up.flags.rpc_port },
        .{ .flag = "--engine.port", .default = 8551, .named = up.flags.engine_port },
        .{ .flag = "--consensus.port", .default = 7545, .named = up.flags.consensus_port },
        .{ .flag = "", .default = 28545, .named = null }, // The bridge's L1 RPC route.
        .{ .flag = "", .default = 25052, .named = null }, // The bridge's L1 beacon route.
        // Gossip: libp2p on TCP, discv5 on UDP one above (only used with --gossip).
        .{
            .flag = "--gossip.port",
            .default = 9222,
            .named = up.flags.gossip_port,
            .udp_next = true,
        },
    };
    var chosen: [wants.len]u16 = undefined;
    for (wants, 0..) |want, index| {
        if (want.udp_next and !up.flags.gossip) {
            chosen[index] = want.default;
            continue;
        }
        const wanted = want.named orelse want.default;
        const taken = chosen[0..index];
        const named = want.named != null;
        chosen[index] = up_check.pick_port(up.io, wanted, named, taken, want.udp_next) catch {
            if (want.udp_next) {
                up.view.fail("ports", "TCP {d} or UDP {d} ({s}) is in use by another " ++
                    "program", .{ wanted, wanted +% 1, want.flag });
            } else up.view.fail("ports", "port {d} ({s}) is in use by another program", .{
                wanted, want.flag,
            });
            up.view.fix("pick a free one with {s} <port>, or stop the program on it " ++
                "(ss -lntup 'sport = :{d}')", .{ want.flag, wanted });
            return null;
        };
        if (chosen[index] != wanted and want.flag.len > 0) {
            up.view.warn(
                "port {d} is in use; {s} {d} instead",
                .{ wanted, want.flag, chosen[index] },
            );
        }
    }
    up.view.ok("ports", "JSON-RPC {d}, Engine API {d}, consensus {d} (127.0.0.1)", .{
        chosen[0], chosen[1], chosen[2],
    });
    if (up.flags.gossip) up.view.ok("gossip", "TCP {d}, UDP {d} (all interfaces)", .{
        chosen[5], chosen[5] + 1,
    });
    return .{
        .rpc = chosen[0],
        .engine = chosen[1],
        .consensus = chosen[2],
        .l1 = chosen[3],
        .beacon = chosen[4],
        .gossip = chosen[5],
    };
}

const L1Plan = union(enum) {
    disabled,
    chosen: struct { l1: up_check.L1, rpcs: []const []const u8, beacons: []const []const u8 },
    waiting: struct { rpcs: []const []const u8, beacons: []const []const u8 },
};

/// The L1 endpoints for consensus; `.waiting` when none answers (consensus waits, the node
/// runs), null when a named endpoint serves another chain.
fn choose_l1(up: *const Up) !?L1Plan {
    if (!up.flags.consensus) {
        up.view.ok("L1", "none (--no-consensus: execution only)", .{});
        return .disabled;
    }
    const rpcs: []const []const u8 = if (up.flags.l1) |url|
        try up.arena.dupe([]const u8, &.{url})
    else
        up.chain.l1_rpcs;
    const beacons: []const []const u8 = if (up.flags.l1_beacon) |url|
        try up.arena.dupe([]const u8, &.{url})
    else
        up.chain.l1_beacons;
    const named = up.flags.l1 != null or up.flags.l1_beacon != null;
    var report: up_check.L1Report = .{};
    return switch (up_check.choose_l1(up.gpa, up.io, up.chain, rpcs, beacons, named, &report)) {
        .ok => |l1| chosen: {
            up.view.ok("L1", "{s}, beacon {s}", .{ host_of(l1.rpc), host_of(l1.beacon) });
            break :chosen .{ .chosen = .{ .l1 = l1, .rpcs = rpcs, .beacons = beacons } };
        },
        .wrong_chain => wrong: {
            up.view.fail("L1", "{s}", .{report.text()});
            up.view.fix("pass --l1 and --l1-beacon endpoints of chain id {d} ({s}'s L1)", .{
                up.chain.config.l1_chain_id, up.chain.name,
            });
            break :wrong null;
        },
        .unreachable_endpoints => none: {
            up.view.warn("L1: {s}", .{report.text()});
            up.view.note("the execution node runs without L1; consensus starts once one " ++
                "answers (retried every 5 minutes)", .{});
            if (named) up.view.fix("check that the --l1 and --l1-beacon you named are up, or " ++
                "pass others; --no-consensus runs without L1", .{}) else up.view.fix("pass " ++
                "--l1 <Ethereum JSON-RPC> and --l1-beacon <beacon API>, or --no-consensus", .{});
            break :none .{ .waiting = .{ .rpcs = rpcs, .beacons = beacons } };
        },
    };
}

fn host_of(url: []const u8) []const u8 {
    const scheme_end = (std.mem.indexOf(u8, url, "://") orelse return url) + 3;
    const rest = url[scheme_end..];
    return rest[0 .. std.mem.indexOfScalar(u8, rest, '/') orelse rest.len];
}

/// Warns when the host has less memory than the chain's node used where it was measured.
fn check_memory(up: *const Up) void {
    if (builtin.os.tag != .linux) return;
    var buffer: [4096]u8 = undefined;
    const text = Io.Dir.cwd().readFile(up.io, "/proc/meminfo", &buffer) catch return;
    const key = "MemTotal:";
    const at = std.mem.indexOf(u8, text, key) orelse return;
    var fields = std.mem.tokenizeScalar(u8, text[at + key.len ..], ' ');
    const kib = std.fmt.parseInt(u64, fields.next() orelse return, 10) catch return;
    const needed_gib: u64 = if (up.chain.config.chain_id == 8453) 16 else 12;
    if (kib >> 20 >= needed_gib) return;
    up.view.warn("{d} GiB of memory; el-run on {s} used about {d} GiB where it was measured, " ++
        "so the kernel may stop it (OOM)", .{ kib >> 20, up.chain.name, needed_gib - 4 });
}

// ---- Snapshot ------------------------------------------------------------------------

/// The snapshot to import: the saved one while it is still published (or extracted), else
/// the listing's latest (saved for the next run).
fn plan_snapshot(up: *const Up) !?Snapshot {
    if (try load_saved(up)) |saved| {
        if (up.exists(up.path("snapshot/extracted.ok", .{}))) return saved;
        if (up_snapshot.archive_published(up.gpa, up.io, saved.archive_url)) |published| {
            if (published) return saved;
            up.view.warn("snapshot at block {d} is no longer published; switching to the " ++
                "latest (its partial download is deleted)", .{saved.block});
            if (!up.flags.dry_run) try clear_snapshot(up);
        } else |err| {
            up.view.warn("cannot reach the snapshot server ({t}); resuming block {d}", .{
                err, saved.block,
            });
            return saved;
        }
    }
    const chain_id = up.chain.config.chain_id;
    const latest = up_snapshot.fetch_latest(
        up.arena,
        up.io,
        up.flags.listing,
        chain_id,
    ) catch |err| {
        up.view.fail("snapshot", "cannot read the snapshot listing {s}: {t}", .{
            up.flags.listing, err,
        });
        up.view.fix("check the network connection, then run the command again", .{});
        return null;
    };
    const snapshot = up_snapshot.parse_manifest(up.arena, latest.text, latest.url) catch |err| {
        up.view.fail("snapshot", "the manifest {s} is not usable: {t}", .{ latest.url, err });
        return null;
    };
    if (!up.flags.dry_run) {
        const cwd = Io.Dir.cwd();
        try cwd.writeFile(
            up.io,
            .{ .sub_path = up.path("snapshot/manifest.json", .{}), .data = latest.text },
        );
        try cwd.writeFile(
            up.io,
            .{ .sub_path = up.path("snapshot/manifest.url", .{}), .data = latest.url },
        );
    }
    return snapshot;
}

fn load_saved(up: *const Up) !?Snapshot {
    const cwd = Io.Dir.cwd();
    const limit: Io.Limit = .limited(16 << 20);
    const text = cwd.readFileAlloc(
        up.io,
        up.path("snapshot/manifest.json", .{}),
        up.arena,
        limit,
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const url = cwd.readFileAlloc(
        up.io,
        up.path("snapshot/manifest.url", .{}),
        up.arena,
        .limited(4096),
    ) catch
        return null;
    return up_snapshot.parse_manifest(up.arena, text, url) catch null;
}

fn clear_snapshot(up: *const Up) !void {
    try Io.Dir.cwd().deleteTree(up.io, up.path("snapshot", .{}));
    try Io.Dir.cwd().createDirPath(up.io, up.path("snapshot", .{}));
}

fn file_size(up: *const Up, path: []const u8) u64 {
    const stat = Io.Dir.cwd().statFile(up.io, path, .{}) catch return 0;
    return stat.size;
}

/// Bytes the snapshot stages already hold on disk (archive chunks, extraction, import).
fn snapshot_held(up: *const Up, snapshot: *const Snapshot) !u64 {
    var held: u64 = 0;
    for (snapshot.member_slice()) |member| {
        held += file_size(up, up.path("snapshot/extracted/{s}", .{member.path}));
    }
    held += file_size(up, up.path("import/node.nf", .{}));
    const archive_path = up.path("snapshot/archive", .{});
    var dir = Io.Dir.cwd().openDir(up.io, archive_path, .{ .iterate = true }) catch return held;
    defer dir.close(up.io);
    var iterator = dir.iterate();
    while (try iterator.next(up.io)) |entry| {
        const stat = dir.statFile(up.io, entry.name, .{}) catch continue;
        held += stat.size;
    }
    return held;
}

fn check_disk_snapshot(up: *const Up, snapshot: *const Snapshot) !bool {
    const archive = snapshot.archive_bytes;
    const mdbx = snapshot.mdbx_bytes();
    const database = up_check.database_bytes_estimate(mdbx);
    const peak = up_check.snapshot_peak_bytes(archive, mdbx);
    var b: [5][32]u8 = undefined;
    const free = try free_bytes_at(up, up.datadir) orelse {
        up.view.warn("cannot read free disk space here; make sure {s} are free", .{
            up_check.format_bytes(&b[0], peak),
        });
        return true;
    };
    const needed = peak -| try snapshot_held(up, snapshot);
    if (free >= needed) {
        up.view.ok("disk", "{s} free; the snapshot path needs {s} more at its peak", .{
            up_check.format_bytes(&b[0], free), up_check.format_bytes(&b[1], needed),
        });
        return true;
    }
    up.view.fail("disk", "{s} free in {s}, {s} more needed", .{
        up_check.format_bytes(&b[0], free), up.datadir, up_check.format_bytes(&b[1], needed),
    });
    up.view.note("peak {s}: the {s} archive beside its {s} extraction, then the extraction " ++
        "beside the ~{s} database (the node keeps ~{s})", .{
        up_check.format_bytes(&b[2], peak),     up_check.format_bytes(&b[3], archive),
        up_check.format_bytes(&b[4], mdbx),     up_check.format_bytes(&b[1], database),
        up_check.format_bytes(&b[1], database),
    });
    up.view.fix("free space on that disk, or pass --datadir <dir> on a disk with {s} free", .{
        up_check.format_bytes(&b[2], peak),
    });
    return false;
}

/// Free bytes on the file system that holds `path` (or will: its nearest existing parent).
fn free_bytes_at(up: *const Up, path: []const u8) !?u64 {
    var existing = path;
    while (!up.exists(existing)) existing = std.fs.path.dirname(existing) orelse "/";
    return up_check.free_bytes(try up.arena.dupeSentinel(u8, existing, 0));
}

fn check_disk_running(up: *const Up) !bool {
    const directory = std.fs.path.dirname(up.db) orelse up.datadir;
    const free = try free_bytes_at(up, directory) orelse return true;
    var buffer: [32]u8 = undefined;
    if (free < 5 << 30) {
        up.view.fail("disk", "only {s} free on the database's disk", .{
            up_check.format_bytes(&buffer, free),
        });
        up.view.fix("free space on that disk; the node needs room to grow", .{});
        return false;
    }
    if (free < 50 << 30) {
        up.view.warn(
            "only {s} free on the database's disk",
            .{up_check.format_bytes(&buffer, free)},
        );
    } else up.view.ok("disk", "{s} free", .{up_check.format_bytes(&buffer, free)});
    return true;
}

fn print_plan(
    up: *const Up,
    ready: bool,
    ports: up_run.Ports,
    l1: L1Plan,
    snapshot: ?*const Snapshot,
) void {
    const view = up.view;
    if (ready) {
        view.note("plan: run the database as it is (no snapshot, no import)", .{});
    } else {
        var b: [2][32]u8 = undefined;
        view.note("plan: download and extract snapshot block {d} ({s} archive, {s} extracted)", .{
            snapshot.?.block,
            up_check.format_bytes(&b[0], snapshot.?.archive_bytes),
            up_check.format_bytes(&b[1], snapshot.?.mdbx_bytes()),
        });
        view.note(
            "plan: import it into {s}, its state root checked against the block header",
            .{up.db},
        );
    }
    view.note(
        "plan: el-run on JSON-RPC 127.0.0.1:{d}, Engine API 127.0.0.1:{d}",
        .{ ports.rpc, ports.engine },
    );
    if (up.flags.gossip) view.note("plan: el-run joins gossip on TCP {d} and UDP {d}; it " ++
        "executes the sequencer-signed block at the tip, devp2p as the fallback", .{
        ports.gossip, ports.gossip + 1,
    });
    switch (l1) {
        .disabled => view.note("plan: no consensus (--no-consensus)", .{}),
        .chosen => view.note("plan: consensus on 127.0.0.1:{d} once el-run's engine ring is " ++
            "warm", .{
            ports.consensus,
        }),
        .waiting => view.note("plan: consensus once an L1 endpoint answers", .{}),
    }
}

/// Downloads and extracts the snapshot (rounds: a round that loses chunks to a decode error
/// or a hash mismatch fetches them again). 0 when extracted, else the exit status.
fn fetch_snapshot(up: *const Up, snapshot: *const Snapshot) !u8 {
    var b: [2][32]u8 = undefined;
    if (up.exists(up.path("snapshot/extracted.ok", .{}))) {
        up.view.ok("snapshot", "block {d}, extracted and verified", .{snapshot.block});
        return 0;
    }
    try Io.Dir.cwd().createDirPath(up.io, up.path("snapshot/archive", .{}));
    up.view.note("snapshot block {d}: {s} archive, {s} extracted, {d} connections, resumable", .{
        snapshot.block,
        up_check.format_bytes(&b[0], snapshot.archive_bytes),
        up_check.format_bytes(&b[1], snapshot.mdbx_bytes()),
        up.flags.connections,
    });
    if (up.flags.rate_mb_per_s > 0) {
        up.view.note("download capped at {d} MB/s (--download.rate)", .{up.flags.rate_mb_per_s});
    }
    const rounds_max = 6;
    for (0..rounds_max) |_| {
        switch (try snapshot_round(up, snapshot)) {
            .extracted => {
                const ok_path = up.path("snapshot/extracted.ok", .{});
                try Io.Dir.cwd().writeFile(up.io, .{ .sub_path = ok_path, .data = snapshot.file });
                try Io.Dir.cwd().deleteTree(up.io, up.path("snapshot/archive", .{}));
                up.view.ok("snapshot", "block {d}: {s} downloaded, extracted, blake3 of every " ++
                    "file verified", .{
                    snapshot.block,
                    up_check.format_bytes(&b[0], snapshot.archive_bytes),
                });
                return 0;
            },
            .stopped => {
                up.view.note("stopped; the downloaded chunks are kept: run the same command " ++
                    "again to resume", .{});
                return 0;
            },
            .retry => continue,
            .failed => |reason| {
                up.view.fail("snapshot", "{s}", .{reason});
                up.view.fix("{s}", .{"run the command again once fixed; it resumes"});
                return 1;
            },
        }
    }
    up.view.fail("snapshot", "failed to verify {d} times", .{rounds_max});
    up.view.fix("check the disk and the network, then run the command again", .{});
    return 1;
}

const RoundOutcome = union(enum) { extracted, stopped, retry, failed: []const u8 };

const Round = struct {
    halt: std.atomic.Value(bool) = .init(false),
    download: up_snapshot.Download,
    extraction: up_snapshot.Extraction,
};

fn snapshot_round(up: *const Up, snapshot: *const Snapshot) !RoundOutcome {
    const cwd = Io.Dir.cwd();
    const archive = try cwd.openDir(up.io, up.path("snapshot/archive", .{}), .{});
    defer archive.close(up.io);
    const extracted = try cwd.createDirPathOpen(up.io, up.path("snapshot/extracted", .{}), .{});
    defer extracted.close(up.io);
    const sink_buffer = try up.gpa.alloc(u8, up_snapshot.sink_buffer_bytes);
    defer up.gpa.free(sink_buffer);
    const input_buffer = try up.gpa.alloc(u8, up_snapshot.input_buffer_bytes);
    defer up.gpa.free(input_buffer);
    const round = try up.gpa.create(Round);
    defer up.gpa.destroy(round);
    round.* = .{ .download = .{
        .gpa = up.gpa,
        .io = up.io,
        .dir = archive,
        .url = snapshot.archive_url,
        .archive_bytes = snapshot.archive_bytes,
        .chunks = snapshot.chunk_count(),
        .stop = undefined,
    }, .extraction = undefined };
    round.download.stop = &round.halt;
    round.download.rate_bytes_per_s = @as(u64, up.flags.rate_mb_per_s) * 1_000_000;
    round.download.started_ms = up.now_ms();
    try round.download.count_existing();
    round.extraction = .{
        .sink = undefined,
        .chunk_reader = .init(&round.download, input_buffer),
        .directory = .{ .io = up.io, .dir = extracted },
    };
    const output = round.extraction.directory.output();
    round.extraction.sink = .init(sink_buffer, snapshot.member_slice(), output);
    defer round.extraction.chunk_reader.deinit();
    var group: Io.Group = .init;
    for (0..up.flags.connections) |_| {
        try group.concurrent(up.io, up_snapshot.Download.worker, .{&round.download});
    }
    try group.concurrent(up.io, up_snapshot.Extraction.run, .{ &round.extraction, up.gpa });
    watch_round(up, snapshot, round);
    round.halt.store(true, .release);
    group.cancel(up.io);
    return judge_round(up, round);
}

/// Redraws the snapshot bar until the extraction ends, the download fails, or a stop.
fn watch_round(up: *const Up, snapshot: *const Snapshot, round: *Round) void {
    const started_ms = up.now_ms();
    const started_bytes = round.download.bytes.load(.acquire);
    while (!round.extraction.done.load(.acquire)) {
        if (stop_requested.load(.acquire) or round.download.failed() != .none) return;
        Io.sleep(up.io, .fromMilliseconds(500), .awake) catch return;
        const now = up.now_ms();
        const bytes = round.download.bytes.load(.acquire);
        const extracted = round.extraction.sink.written.load(.acquire);
        const elapsed_s = @as(f64, @floatFromInt(@max(now - started_ms, 1))) / 1000;
        const rate = @as(f64, @floatFromInt(bytes -| started_bytes)) / elapsed_s;
        const total: f64 = @floatFromInt(snapshot.archive_bytes);
        const left_s = (total - @as(f64, @floatFromInt(bytes))) / @max(rate, 1);
        var b: [4][32]u8 = undefined;
        var eta: [32]u8 = undefined;
        // The extraction trails the download: the bar is the slower of the two.
        const extracted_fraction = @as(f64, @floatFromInt(extracted)) /
            @as(f64, @floatFromInt(snapshot.mdbx_bytes()));
        const fraction = @min(@as(f64, @floatFromInt(bytes)) / total, extracted_fraction);
        up.view.progress(now, "snapshot", fraction, "{s} / {s} downloaded  {d:.1} MB/s  " ++
            "{s} extracted  {s}", .{
            up_check.format_bytes(&b[0], bytes),
            up_check.format_bytes(&b[1], snapshot.archive_bytes),
            rate / 1e6,
            up_check.format_bytes(&b[2], extracted),
            format_eta(&eta, if (rate > 0) left_s else null),
        });
    }
}

/// `ETA 3h 12m` (or `ETA 42s`), empty while unknown.
pub fn format_eta(buffer: []u8, seconds: ?f64) []const u8 {
    const value = seconds orelse return "";
    if (!std.math.isFinite(value) or value < 0) return "";
    const total: u64 = @intFromFloat(@min(value, 1e9));
    if (total >= 3600) return std.fmt.bufPrint(buffer, "ETA {d}h {d}m", .{
        total / 3600, total % 3600 / 60,
    }) catch "";
    if (total >= 60) return std.fmt.bufPrint(
        buffer,
        "ETA {d}m {d}s",
        .{ total / 60, total % 60 },
    ) catch "";
    return std.fmt.bufPrint(buffer, "ETA {d}s", .{total}) catch "";
}

fn judge_round(up: *const Up, round: *Round) !RoundOutcome {
    if (stop_requested.load(.acquire)) return .stopped;
    switch (round.download.failed()) {
        .none => {},
        .gone => {
            try clear_snapshot(up);
            return .{ .failed = "the snapshot was withdrawn while downloading; run the " ++
                "command again to start the latest one" };
        },
        .no_space => return .{ .failed = no_space_message },
        .changed => {
            try clear_snapshot(up);
            return .{ .failed = "the snapshot archive changed on the server; run the command " ++
                "again to start over" };
        },
        .write_failed, .gave_up => return .{ .failed = "the download keeps failing; check " ++
            "the network and the disk" },
    }
    const result = round.extraction.result orelse return .retry;
    return judge_extraction(up, round, result);
}

const no_space_message = "the disk is full; free space on the datadir's disk (or move the " ++
    "datadir to a bigger one with --datadir)";

fn judge_extraction(up: *const Up, round: *Round, result: anyerror!void) !RoundOutcome {
    result catch |err| switch (err) {
        error.HashMismatch => {
            up.view.warn("an extracted file does not match the manifest's blake3; fetching " ++
                "the archive again", .{});
            try Io.Dir.cwd().deleteTree(up.io, up.path("snapshot/archive", .{}));
            try Io.Dir.cwd().createDirPath(up.io, up.path("snapshot/archive", .{}));
            return .retry;
        },
        error.OutputFailed => {
            const cause = round.extraction.sink.output_error orelse error.Unexpected;
            if (cause == error.NoSpaceLeft) return .{ .failed = no_space_message };
            up.view.warn("cannot write the extraction: {t}", .{cause});
            return .{ .failed = "the datadir's disk refused a write" };
        },
        error.Halted => return .retry,
        else => {
            // A decode error: the chunks around the failing offset are damaged.
            const index = round.extraction.chunk_reader.index;
            up.view.warn("the archive does not decode near chunk {d} ({t}); fetching chunks " ++
                "{d} and {d} again", .{ index, err, index -| 1, index });
            try delete_chunk(up, index -| 1);
            try delete_chunk(up, index);
            return .retry;
        },
    };
    return .extracted;
}

fn delete_chunk(up: *const Up, index: u32) !void {
    for ([_][]const u8{ "", ".part" }) |suffix| {
        const path = up.path("snapshot/archive/{d:0>7}{s}", .{ index, suffix });
        Io.Dir.cwd().deleteFile(up.io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
}

// ---- Import --------------------------------------------------------------------------

/// Imports the extracted snapshot into `import/node.nf` (`base snapshot-import --out`, which
/// requires the computed state root to equal the block header's), then renames it to the
/// database path: the only way a database appears there. 0 when imported.
fn import_snapshot(up: *const Up, snapshot: *const Snapshot) !u8 {
    assert(up.managed);
    const attempts_max = 5;
    for (0..attempts_max) |attempt| {
        // A killed import leaves a partial file: never resumed, always started over.
        try Io.Dir.cwd().deleteTree(up.io, up.path("import", .{}));
        try Io.Dir.cwd().createDirPath(up.io, up.path("import", .{}));
        const started_ms = up.now_ms();
        const status = try run_import(up, snapshot);
        if (stop_requested.load(.acquire)) {
            up.view.note("stopped; the import is not resumable: the next run imports from the " ++
                "extracted snapshot again (it is kept)", .{});
            return 0;
        }
        if (status == 0) return finish_import(up, snapshot);
        var buffer: [4096]u8 = undefined;
        const tail = read_tail(up.io, up.path("logs/import.log", .{}), &buffer);
        up.view.fail("import", "exited with status {d}: {s}", .{ status, last_lines(tail, 1) });
        if (std.mem.indexOf(u8, tail, "StateRootMismatch") != null) {
            up.view.note("the snapshot's state does not hash to its block's state root", .{});
            up.view.fix("report it with {s}/logs/import.log; `base up --reimport` retries " ++
                "with the next snapshot", .{up.datadir});
            return 1;
        }
        if (std.mem.indexOf(u8, tail, "NoSpaceLeft") != null) {
            up.view.fix("{s}", .{no_space_message});
            return 1;
        }
        // Only an early failure (fetching the block headers) is worth another try.
        if (up.now_ms() - started_ms > 10 * 60_000 or attempt + 1 == attempts_max) {
            up.view.fix("see {s}/logs/import.log", .{up.datadir});
            return 1;
        }
        up.view.note("retrying in 30 s (attempt {d} of {d})", .{ attempt + 2, attempts_max });
        try Io.sleep(up.io, .fromSeconds(30), .awake);
    }
    unreachable; // Every attempt returns above.
}

fn run_import(up: *const Up, snapshot: *const Snapshot) !u32 {
    var mdbx: []const u8 = "";
    for (snapshot.member_slice()) |member| {
        if (std.mem.endsWith(u8, member.path, "mdbx.dat")) {
            mdbx = up.path("snapshot/extracted/{s}", .{member.path});
        }
    }
    assert(mdbx.len > 0);
    const out = up.path("import/node.nf", .{});
    const argv = [_][]const u8{
        up.exe, "snapshot-import", "--db", mdbx, "--chain", up.chain.name, "--out", out,
    };
    const log_path = up.path("logs/import.log", .{});
    const log = try up_run.open_log(log_path);
    defer log.close(up.io);
    var child = try std.process.spawn(up.io, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    const pid = child.id.?;
    child.id = null;
    var tail: up_view.Tail = .init(up.io, log_path, true);
    var progress: ImportProgress = .{ .started_ms = up.now_ms() };
    while (true) {
        if (up_run.try_wait(pid)) |status| return status;
        if (stop_requested.load(.acquire)) {
            up_run.terminate(up.io, pid, 30_000);
            return 1;
        }
        progress.update(tail.read(up.io));
        progress.show(up, snapshot.block);
        try Io.sleep(up.io, .fromMilliseconds(500), .awake);
    }
}

/// The import's progress from its log: its `sizing:` line names the accounts and slots, its
/// progress lines count them as they stream.
const ImportProgress = struct {
    started_ms: i64,
    accounts_total: u64 = 0,
    slots_total: u64 = 0,
    accounts: u64 = 0,
    slots: u64 = 0,
    phase: []const u8 = "reading the snapshot",

    fn update(progress: *ImportProgress, lines: []const u8) void {
        var iterator = std.mem.tokenizeScalar(u8, lines, '\n');
        while (iterator.next()) |line| {
            if (std.mem.startsWith(u8, line, "sizing: node shape")) {
                progress.accounts_total = count_before(line, " accounts") orelse 0;
                progress.slots_total = count_before(line, " slots") orelse 0;
                progress.phase = "hashing the state";
            } else if (std.mem.indexOf(u8, line, " accounts (") != null) {
                progress.accounts = count_before(line, " accounts (") orelse progress.accounts;
                progress.slots = count_before(line, " slots (") orelse progress.slots;
            } else if (std.mem.startsWith(u8, line, "imported block")) {
                progress.phase = "state root matches; self-check";
            }
        }
    }

    fn show(progress: *const ImportProgress, up: *const Up, block: u64) void {
        const total = progress.accounts_total + progress.slots_total;
        const done = @min(progress.accounts + progress.slots, total);
        const fraction = if (total == 0) 0 else @as(f64, @floatFromInt(done)) / @as(
            f64,
            @floatFromInt(total),
        );
        const elapsed_s: u64 = @intCast(@divTrunc(up.now_ms() - progress.started_ms, 1000));
        up.view.progress(up.now_ms(), "import", fraction, "block {d}: {s}, {d}h {d:0>2}m", .{
            block, progress.phase, elapsed_s / 3600, elapsed_s % 3600 / 60,
        });
    }
};

/// The integer just before `suffix` in `line` (`... 14200000 accounts ...`).
fn count_before(line: []const u8, suffix: []const u8) ?u64 {
    const end = std.mem.indexOf(u8, line, suffix) orelse return null;
    const start = (std.mem.lastIndexOfScalar(u8, line[0..end], ' ') orelse return null) + 1;
    return std.fmt.parseInt(u64, line[start..end], 10) catch null;
}

fn finish_import(up: *const Up, snapshot: *const Snapshot) !u8 {
    const cwd = Io.Dir.cwd();
    try cwd.rename(
        up.path("import/node.nf.counts", .{}),
        cwd,
        up.path("db/node.nf.counts", .{}),
        up.io,
    );
    // Last: the database's name appears only for a verified import.
    try cwd.rename(up.path("import/node.nf", .{}), cwd, up.db, up.io);
    up.view.ok("import", "block {d}: state root matches the block header", .{snapshot.block});
    try cwd.deleteTree(up.io, up.path("snapshot", .{}));
    try cwd.createDirPath(up.io, up.path("snapshot", .{}));
    return 0;
}

fn read_tail(io: Io, path: []const u8, buffer: []u8) []const u8 {
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch return "";
    defer file.close(io);
    const length = file.length(io) catch return "";
    const got = file.readPositionalAll(io, buffer, length -| buffer.len) catch return "";
    return buffer[0..got];
}

fn last_lines(text: []const u8, count: u32) []const u8 {
    assert(count > 0);
    const trimmed = std.mem.trimEnd(u8, text, "\n");
    var start = trimmed.len;
    for (0..count) |_| {
        start = std.mem.lastIndexOfScalar(u8, trimmed[0..start], '\n') orelse return trimmed;
    }
    return trimmed[start + 1 ..];
}

// ---- Run -----------------------------------------------------------------------------

fn start_node(up: *const Up, ports: up_run.Ports, l1: L1Plan) !u8 {
    const secret = try jwt_secret(up);
    var rollup_buffer: [16 * 1024]u8 = undefined;
    const rollup = try el_engine.rollup_text(&rollup_buffer, up.chain.config);
    const rollup_path = up.path("consensus/rollup.json", .{});
    try Io.Dir.cwd().writeFile(up.io, .{ .sub_path = rollup_path, .data = rollup });
    // Written by the node while it runs (`Node.write_state`); gone when it stops.
    defer Io.Dir.cwd().deleteFile(up.io, up.path("node.json", .{})) catch {};
    const settings: up_run.Settings = .{
        .exe = up.exe,
        .datadir = up.datadir,
        .db = up.db,
        .chain = up.chain,
        .ports = ports,
        .jwt_path = up.path("jwt.hex", .{}),
        .jwt_secret = secret,
        .peers_path = up.path("peers.txt", .{}),
        .consensus = l1 != .disabled,
        .gossip = up.flags.gossip,
        .l1 = if (l1 == .chosen) l1.chosen.l1 else null,
        .l1_candidates = switch (l1) {
            .disabled => .{ .rpcs = &.{}, .beacons = &.{} },
            .chosen => |chosen| .{ .rpcs = chosen.rpcs, .beacons = chosen.beacons },
            .waiting => |waiting| .{ .rpcs = waiting.rpcs, .beacons = waiting.beacons },
        },
        .stop = &stop_requested,
    };
    var node: up_run.Node = .init(up.gpa, up.io, up.view, &settings);
    return node.run();
}

/// The Engine API secret in `jwt.hex` (created once, owner-only).
fn jwt_secret(up: *const Up) !jwt.Secret {
    const path = up.path("jwt.hex", .{});
    var buffer: [128]u8 = undefined;
    if (Io.Dir.cwd().readFile(up.io, path, &buffer)) |text| {
        if (jwt.Secret.parse_hex(text)) |secret| return secret else |_| {}
        up.view.warn("{s} is not a JWT secret; writing a new one", .{path});
    } else |err| if (err != error.FileNotFound) return err;
    var bytes: [32]u8 = undefined;
    try up.io.randomSecure(&bytes);
    const secret: jwt.Secret = .{ .bytes = bytes };
    const hex = secret.to_hex();
    try Io.Dir.cwd().writeFile(up.io, .{
        .sub_path = path,
        .data = &hex,
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    return secret;
}

// ---- Tests ---------------------------------------------------------------------------

const testing = std.testing;

test "up: flags" {
    const defaults = try parse_flags(&.{});
    try testing.expect(defaults.chain == null and defaults.consensus and !defaults.dry_run);
    try testing.expectEqual(@as(u32, 8), defaults.connections);
    const full = try parse_flags(&.{
        "--chain", "base-sepolia", "--l1", "https://l1.example/", "--rpc.port", "9545", "--dry-run",
    });
    try testing.expectEqualStrings("https://l1.example", full.l1.?);
    try testing.expectEqual(@as(?u16, 9545), full.rpc_port);
    const invalid = [_][]const []const u8{
        &.{"--rpc.port"},                    &.{ "--rpc.port", "0" },
        &.{ "--rpc.port", "70000" },         &.{ "--l1", "ethereum-rpc.publicnode.com" },
        &.{ "--download.connections", "0" }, &.{"--bogus"},
        &.{ "--db", "x", "--reimport" },     &.{ "--no-consensus", "--l1", "https://x" },
        &.{ "--download.rate", "0" },        &.{ "--download.rate", "fast" },
        &.{ "--gossip.port", "9322" },       &.{ "--gossip", "--gossip.port", "65535" },
    };
    const gossip = try parse_flags(&.{ "--gossip", "--gossip.port", "9422" });
    try testing.expect(gossip.gossip and !defaults.gossip);
    try testing.expectEqual(@as(?u16, 9422), gossip.gossip_port);
    const capped = try parse_flags(&.{ "--download.rate", "6" });
    try testing.expectEqual(@as(u32, 6), capped.rate_mb_per_s);
    try testing.expectEqual(@as(u32, 0), defaults.rate_mb_per_s);
    for (invalid) |args| try testing.expectError(error.InvalidArguments, parse_flags(args));
    try testing.expectError(error.Help, parse_flags(&.{"--help"}));
}

test "up: log lines, ports, the import's progress" {
    try testing.expectEqualStrings("c", last_lines("a\nb\nc\n", 1));
    try testing.expectEqualStrings("b\nc", last_lines("a\nb\nc", 2));
    try testing.expectEqualStrings("a\nb", last_lines("a\nb\n", 5));
    var progress: ImportProgress = .{ .started_ms = 0 };
    progress.update("sizing: node shape v2, 14200000 accounts, 1270000000 slots, 9 codes\n" ++
        "  7100000 accounts (2000/s), 635000000 slots (90000/s), 1 + 2 records\n");
    try testing.expectEqual(@as(u64, 14_200_000), progress.accounts_total);
    try testing.expectEqual(@as(u64, 635_000_000), progress.slots);
    var eta: [32]u8 = undefined;
    try testing.expectEqualStrings("ETA 2h 5m", format_eta(&eta, 7500));
    try testing.expectEqualStrings("", format_eta(&eta, null));
    try testing.expectEqualStrings(
        "ethereum-rpc.publicnode.com",
        host_of("https://ethereum-rpc.publicnode.com/x"),
    );
}

test "up: node.json" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text =
        \\{"chain": "base-mainnet", "el.log": "~/nf/follow.log", "el.rpc": "http://127.0.0.1:8546",
        \\ "cl.rpc": "http://127.0.0.1:7546", "pids": {"el": 4242, "consensus": 4243}}
    ;
    const node = try NodeFile.parse(arena.allocator(), text, "/home/u");
    try testing.expectEqualStrings("/home/u/nf/follow.log", node.el_log.?);
    try testing.expectEqualStrings("http://127.0.0.1:7546", node.cl_rpc.?);
    try testing.expectEqual(@as(usize, 2), node.pids.len);
    const log_only = try NodeFile.parse(arena.allocator(), "{\"el.log\": \"/l\"}", null);
    try testing.expect(log_only.el_rpc == null and log_only.pids.len == 0);
    const bad = [_][]const u8{
        "[]",
        "{}",
        "{\"el.log\": 3}",
        "{\"el.log\": \"~/x\"}",
        "{\"el.rpc\": \"http://x\", \"pids\": {\"el\": 1}}",
    };
    for (bad) |case| {
        try testing.expectError(error.BadNodeFile, NodeFile.parse(arena.allocator(), case, null));
    }
}

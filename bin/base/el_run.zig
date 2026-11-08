//! `base el-run`: executes blocks N+1, N+2, ... on a disk-mode database
//! (`execution.import.run`) with blocks from execution-layer peers over devp2p, with no RPC.
//! N is the database head; the first block must name the head's hash as its parent, so the
//! peers' chain is bound to the verified state.
//!
//!     base el-run --db <path> (--peers <file> | --enode <enode://...>)
//!                 [--chain base-sepolia|base-mainnet] [--blocks <n>] [--duration <s>]
//!
//! Blocks come from `el_feed.zig`: every peer at once (`el_pool.zig`) while the head is
//! behind, then one peer following the tip. `--peers` is a file of enodes (one per line,
//! re-read every minute, so `el-peers --out` can grow it); `--enode` adds one more.
//!
//! Every block is checked by the runner (transactions root, gas, bloom, receipts root, state
//! root, withdrawals root, resealed hash) and committed only when all match, so the head
//! only ever advances by one executed block. One line per block (number, transactions, gas,
//! execution ms, tip lag), a summary every 10 s with the download and execution rates. Once
//! the follower reaches the peer's head the run is at the tip: lag (time the block was
//! committed minus its scheduled time) is counted from then on. The first refused or
//! mismatching block exits 1 with the head on its parent; nothing is skipped. Commits are
//! made durable every `flush_every` blocks and whenever no block is waiting.
//!
//! With `--engine.addr <ip:port> --engine.jwt <file>` it also serves the Engine API to a
//! verifier `base consensus` (`el_engine.zig`), between blocks and while idle at the tip.
//!
//! With `--gossip` (and any `--p2p.*` flags) it also joins the consensus gossip network
//! (`el_gossip.zig`) and checks every committed block against the sequencer-signed gossip
//! block at its height, when gossip delivers one: equal hashes anchor the devp2p chain to
//! the sequencer, a different hash prints `GOSSIP CONFLICT`.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const el_source = @import("el_source.zig");
const el_feed = @import("el_feed.zig");
const el_gossip = @import("el_gossip.zig");
const import_run_cli = @import("import_run.zig");
const snapshot_import_out = @import("snapshot_import_out.zig");
const unsafe_watch = @import("unsafe_watch.zig");
const el_engine = @import("el_engine.zig");
const el_rpc = @import("el_rpc.zig");

const to_disk = base.execution.import.to_disk;
const import_run = base.execution.import.run;
const ChainConfig = base.common.chains.ChainConfig;
const assert = std.debug.assert;

const IO = base.utilities.io.IO;
const Storage = base.execution.db.storage.IoStorageType(IO);
const Importer = to_disk.ImporterType(Storage);
const Database = Importer.Database;
const Runner = import_run.RunnerType(Storage);
const Executor = base.execution.node.executor.Executor;

/// The monotonic clock the runner times its phases with.
const AwakeClock = struct {
    io: Io,

    fn clock(self: *AwakeClock) Executor.Clock {
        return .{ .context = self, .now_ns = now_ns };
    }

    fn now_ns(context: *anyopaque) u64 {
        const self: *AwakeClock = @ptrCast(@alignCast(context));
        return @intCast(Io.Clock.awake.now(self.io).nanoseconds);
    }
};

const usage =
    \\usage: base el-run --db <path> (--peers <file> | --enode <enode://...>)
    \\                   [--chain base-sepolia|base-mainnet] [--blocks <n>] [--duration <s>]
    \\                   [--engine.addr <ip:port> --engine.jwt <file>
    \\                    [--engine.ring-blocks <n>] [--engine.ring-mb <n>]]
    \\                   [--engine.rollup-out <rollup.json>] [--gossip [--p2p.* ...]]
    \\                   [--rpc] [--rpc.addr <ip:port>] [--rpc.ring-blocks <n>]
    \\                   [--rpc.ring-mb <n>] [--rpc.tx-index <entries>]
    \\
;

const flush_every = 64;
const summary_interval_ms = 10_000;
const peers_interval_ms = 60_000;
const tip_wait_ms = 100;

const Flags = struct {
    db: []const u8 = "",
    enode: ?[]const u8 = null,
    peers: ?[]const u8 = null,
    chain: *const import_run_cli.Chain = &import_run_cli.chains[0],
    config: *const ChainConfig = &base.common.chains.sepolia,
    blocks: ?u64 = null,
    duration_s: ?u64 = null,
    engine: el_engine.Flags = .{},
    /// The read-only JSON-RPC server (`--rpc`, `--rpc.*`).
    rpc: el_rpc.Flags = .{},
    gossip: bool = false,
    /// Every argument, for the `--p2p.*` flags `el_gossip` reads.
    args: []const []const u8 = &.{},
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{ .args = args };
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const name = args[index];
        if (std.mem.eql(u8, name, "--gossip")) {
            flags.gossip = true;
            continue;
        }
        if (std.mem.eql(u8, name, "--rpc")) {
            flags.rpc.enable();
            continue;
        }
        if (std.mem.startsWith(u8, name, "--p2p.")) {
            const has_value = std.mem.indexOfScalar(u8, name, '=') != null or
                base.consensus.p2p.options.is_bool(name["--p2p.".len..]);
            if (!has_value) index += 1;
            continue;
        }
        if (index + 1 == args.len) return error.InvalidArguments;
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, name, "--db")) {
            flags.db = value;
        } else if (std.mem.eql(u8, name, "--enode")) {
            flags.enode = value;
        } else if (std.mem.eql(u8, name, "--peers")) {
            flags.peers = value;
        } else if (std.mem.eql(u8, name, "--chain")) {
            flags.chain = for (&import_run_cli.chains) |*chain| {
                if (std.mem.eql(u8, chain.name, value)) break chain;
            } else return error.InvalidArguments;
            flags.config = if (std.mem.eql(u8, value, "base-mainnet"))
                &base.common.chains.mainnet
            else
                &base.common.chains.sepolia;
        } else if (std.mem.eql(u8, name, "--blocks")) {
            flags.blocks = try std.fmt.parseInt(u64, value, 10);
            if (flags.blocks.? == 0) return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--duration")) {
            flags.duration_s = try std.fmt.parseInt(u64, value, 10);
            if (flags.duration_s.? == 0) return error.InvalidArguments;
        } else if (!try flags.engine.parse(name, value) and !try flags.rpc.parse(name, value)) {
            return error.InvalidArguments;
        }
    }
    if (flags.db.len == 0 or (flags.enode == null and flags.peers == null)) {
        return error.InvalidArguments;
    }
    if (!flags.engine.valid()) return error.InvalidArguments;
    assert(flags.config.chain_id == flags.chain.spec.chain_id);
    return flags;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const gpa = init.gpa;
    const counts_path = try std.fmt.allocPrint(gpa, "{s}.counts", .{flags.db});
    defer gpa.free(counts_path);
    var buffer: [to_disk.Counts.encoded_size]u8 = undefined;
    const bytes = Io.Dir.cwd().readFile(init.io, counts_path, &buffer) catch |err| {
        std.debug.print("cannot read {s}: {t} (written by snapshot-import --out)\n", .{
            counts_path, err,
        });
        return 1;
    };
    const counts = to_disk.Counts.decode(bytes) catch {
        std.debug.print("{s} is not a counts record\n", .{counts_path});
        return 1;
    };
    const sizing = try to_disk.sizing(Storage, counts, to_disk.node_shape(counts));
    var backend = try snapshot_import_out.backend_init();
    defer backend.deinit();
    const Opened = snapshot_import_out.Opened;
    var opened = Opened.init(gpa, &backend, flags.db, sizing.config, false) catch |err| {
        std.debug.print("cannot open {s}: {t}\n", .{ flags.db, err });
        return 1;
    };
    defer opened.deinit(gpa, &backend);
    var ticker: snapshot_import_out.Ticker = .{ .backend = &backend, .storage = opened.storage };
    Importer.open(opened.db, ticker.driver()) catch |err| {
        std.debug.print("cannot open the database in {s}: {t}\n", .{ flags.db, err });
        return 1;
    };
    if (!import_run_cli.usable(opened.db, flags.chain)) return 1;
    return execute(init, &flags, opened.db, ticker.driver());
}

const Run = struct {
    io: Io,
    flags: *const Flags,
    db: *Database,
    runner: *Runner,
    feed: *el_feed.Feed,
    /// The Engine API (`--engine.addr`), served only between blocks.
    engine: ?*el_engine.Service = null,
    /// The read-only JSON-RPC server (`--rpc`), served only between blocks.
    rpc: ?*el_rpc.Service = null,
    /// Sequencer-signed gossip (`--gossip`), checked against every committed block.
    gossip: ?*el_gossip.Gossip = null,
    rollup: base.consensus.protocol.RollupConfig,
    first: u64,
    started_ms: i64,
    last_summary_ms: i64,
    peers_printed_ms: i64 = 0,
    blocks: u64 = 0,
    transactions: u64 = 0,
    gas: u64 = 0,
    execute_ms: i64 = 0,
    unflushed: u32 = 0,
    at_tip: bool = false,
    tip_blocks: u64 = 0,
    lag_sum_ms: u64 = 0,
    lag_max_ms: u64 = 0,

    fn now_ms(run: *const Run) i64 {
        return Io.Clock.awake.now(run.io).toMilliseconds();
    }

    fn done(run: *const Run) bool {
        if (run.flags.blocks) |limit| {
            assert(run.blocks <= limit);
            if (run.blocks == limit) return true;
        }
        const duration_s = run.flags.duration_s orelse return false;
        return run.now_ms() - run.started_ms >= @as(i64, @intCast(duration_s * 1000));
    }

    fn flush(run: *Run) !void {
        if (run.unflushed == 0) return;
        try run.runner.flush();
        run.unflushed = 0;
    }
};

fn execute(
    init: std.process.Init,
    flags: *const Flags,
    db: *Database,
    driver: to_disk.Driver,
) !u8 {
    const gpa = init.gpa;
    var config: import_run.Config = .{ .executor = .{} };
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    config.executor.state_gas_basis = base.execution.node.executor.default_state_gas_basis;
    var awake: AwakeClock = .{ .io = init.io };
    config.clock = awake.clock();
    const runner = try Runner.create(gpa, db, flags.chain.spec, driver, config);
    defer runner.destroy(gpa);
    const head = db.head_info;
    assert(head.present);
    // Before the peers: a bad address fails before any connection is made.
    const node = el_rpc.runner_node(Runner, runner);
    const rpc = el_rpc.Service.start(gpa, &flags.rpc, flags.chain.spec, node) catch |err| {
        std.debug.print("el-run: cannot start the JSON-RPC server: {t}\n", .{err});
        return 2;
    };
    defer if (rpc) |service| service.destroy(gpa);
    // The first block must be the child of the verified database head.
    const feed = el_feed.Feed.create(gpa, init.io, .{
        .chain = flags.config,
        .from = head.number + 1,
        .parent = head.hash,
        .peers_path = flags.peers,
        .enode = flags.enode,
    }) catch |err| {
        std.debug.print("el-run: no usable peers ({t})\n", .{err});
        return 2;
    };
    defer feed.destroy();
    const chain = el_engine.database_chain(Database, db);
    const spec = flags.chain.spec;
    const start = el_engine.Service.start;
    const engine = start(gpa, init.io, &flags.engine, spec, flags.config, chain) catch |err| {
        std.debug.print("el-run: cannot start the engine API: {t}\n", .{err});
        return 2;
    };
    defer if (engine) |service| service.destroy(gpa);
    if (rpc) |service| if (engine) |engine_service| {
        service.api.engine = &engine_service.engine;
    };
    const gossip = if (flags.gossip)
        try el_gossip.Gossip.start(gpa, init.io, flags.config, flags.args)
    else
        null;
    defer if (gossip) |value| value.destroy();
    var run: Run = .{
        .io = init.io,
        .flags = flags,
        .db = db,
        .runner = runner,
        .feed = feed,
        .engine = engine,
        .rpc = rpc,
        .gossip = gossip,
        .rollup = unsafe_watch.rollup_for(flags.config),
        .first = head.number + 1,
        .started_ms = 0,
        .last_summary_ms = 0,
    };
    return run_reported(&run, head.hash);
}

/// Runs the blocks (`run_blocks`) between the start line and the final summary.
fn run_reported(run: *Run, parent: [32]u8) !u8 {
    assert(run.blocks == 0);
    run.started_ms = run.now_ms();
    run.last_summary_ms = run.started_ms;
    std.debug.print("el-run: executing {s} from block {d} (parent {x}), blocks over devp2p\n", .{
        run.flags.chain.name, run.first, parent,
    });
    const status = try run_blocks(run);
    try run.flush();
    summary(run);
    if (status == 0 and run.blocks > 0) {
        const head = run.db.head_info;
        std.debug.print("el-run: ok, {d} consecutive executed blocks {d}..{d}, head {x}\n", .{
            run.blocks, run.first, head.number, head.hash,
        });
    }
    return status;
}

/// Executes blocks until `--blocks`, `--duration`, or the first failure (1).
fn run_blocks(run: *Run) !u8 {
    while (!run.done()) {
        var block: el_source.Block = undefined;
        if (!try run.feed.next(&block)) {
            // Nothing new yet: make what we have durable, then wait for the next block.
            try run.flush();
            if (!run.at_tip and run.feed.at_tip) {
                std.debug.print("el-run: at the tip, block {d}\n", .{run.db.head_info.number});
            }
            run.at_tip = run.feed.at_tip;
            try serve_idle(run, tip_wait_ms);
            continue;
        }
        if (!try run_one(run, &block)) return 1;
        if (run.engine) |service| service.poll();
        if (run.rpc) |service| service.poll();
        run.unflushed += 1;
        if (run.unflushed >= flush_every) try run.flush();
        if (run.now_ms() - run.last_summary_ms >= summary_interval_ms) summary(run);
    }
    return 0;
}

/// Serves the Engine API and the JSON-RPC server for `duration_ms` while no block is
/// waiting: in slices, alternating between their IOs, when both run. A request's accept,
/// read and write each wait out the other server's slice, so slices stay short: a verifier
/// consensus node sends its engine requests one at a time.
fn serve_idle(run: *Run, duration_ms: u64) !void {
    const slice_ms = 2;
    if (run.engine != null and run.rpc != null) {
        var waited_ms: u64 = 0;
        while (waited_ms < duration_ms) : (waited_ms += 2 * slice_ms) {
            try run.rpc.?.wait(slice_ms);
            try run.engine.?.wait(slice_ms);
        }
    } else if (run.engine) |service| {
        try service.wait(duration_ms);
    } else if (run.rpc) |service| {
        try service.wait(duration_ms);
    } else try run.io.sleep(.fromMilliseconds(@intCast(duration_ms)), .awake);
}

/// Executes one block; false (reported) when the runner refuses it or a check fails.
fn run_one(run: *Run, block: *const el_source.Block) !bool {
    const runner_block: import_run.Block = .{
        .number = block.number,
        .hash = block.hash,
        .header_rlp = block.header_rlp,
        .transactions = block.transactions,
    };
    const started = run.now_ms();
    const outcome = run.runner.execute(&runner_block) catch |err| {
        std.debug.print("el-run: block {d} hash {x}: refused: {t}; database head {d} hash {x}\n", .{
            block.number, block.hash, err, run.db.head_info.number, run.db.head_info.hash,
        });
        return false;
    };
    const elapsed = run.now_ms() - started;
    if (!outcome.ok()) {
        report_failure(run, &outcome);
        return false;
    }
    assert(run.db.head_info.number == block.number);
    block_committed(run, block, outcome.receipts);
    run.blocks += 1;
    run.transactions += outcome.transactions;
    run.gas += outcome.gas_used;
    run.execute_ms += elapsed;
    const now = Io.Clock.real.now(run.io);
    const now_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
    const lag_ms = now_ms -| run.rollup.l2_block_timestamp_ms(block.number);
    if (run.feed.at_tip) {
        run.tip_blocks += 1;
        run.lag_sum_ms += lag_ms;
        run.lag_max_ms = @max(run.lag_max_ms, lag_ms);
    }
    std.debug.print("block {d} hash {x} {d} txs {d} gas {d} ms lag_ms {d} checks ok\n", .{
        block.number, block.hash, outcome.transactions, outcome.gas_used, elapsed, lag_ms,
    });
    return true;
}

/// The per-committed-block hook: `block` was executed (`receipts`, valid until the runner's
/// next block), checked, and committed as the database head. Dispatches to the optional
/// consumers (the Engine API's block ring, the JSON-RPC ring, the gossip anchor).
fn block_committed(
    run: *Run,
    block: *const el_source.Block,
    receipts: []const base.common.consensus.Receipt,
) void {
    assert(run.db.head_info.number == block.number);
    assert(std.mem.eql(u8, &run.db.head_info.hash, &block.hash));
    if (run.engine) |service| service.engine.on_block(&.{
        .number = block.number,
        .hash = block.hash,
        .header_rlp = block.header_rlp,
        .transactions = block.transactions,
    });
    if (run.rpc) |service| service.api.store.on_block(&.{
        .number = block.number,
        .hash = block.hash,
        .header_rlp = block.header_rlp,
        .transactions = block.transactions,
    }, receipts);
    if (run.gossip) |gossip| _ = gossip.on_chain(block.number, block.hash);
}

fn report_failure(run: *const Run, outcome: *const import_run.Outcome) void {
    assert(!outcome.ok());
    std.debug.print("MISMATCH block {d} hash {x} ({d} txs)\n", .{
        outcome.number, outcome.hash, outcome.transactions,
    });
    if (outcome.failure) |err| {
        std.debug.print("  execution failed: {t} at transaction {?d}\n", .{
            err, outcome.failed_transaction,
        });
    } else {
        std.debug.print("  first failed check: {t} (passed mask 0b{b:0>8})\n", .{
            outcome.first_failed().?, outcome.passed,
        });
    }
    std.debug.print("  state root: header {x}\n              computed {x}\n", .{
        outcome.expected_state_root, outcome.computed_state_root,
    });
    std.debug.print("  the database head stays at {d} ({x})\n", .{
        run.db.head_info.number, run.db.head_info.hash,
    });
}

fn summary(run: *Run) void {
    const now = run.now_ms();
    run.last_summary_ms = now;
    const elapsed_s: f64 = @as(f64, @floatFromInt(@max(now - run.started_ms, 1))) / 1000;
    const executing_s: f64 = @as(f64, @floatFromInt(@max(run.execute_ms, 1))) / 1000;
    const gas: f64 = @floatFromInt(run.gas);
    const lag_avg_ms = if (run.tip_blocks == 0) 0 else run.lag_sum_ms / run.tip_blocks;
    std.debug.print("summary: {d} blocks ({d:.1}/s), {d} txs, {d:.1} Mgas/s executing, " ++
        "head {d} ({d} behind), {t}, tip blocks {d} lag_ms avg {d} max {d}, " ++
        "{d} downloaded, {d} switches, {d:.0} s\n", .{
        run.blocks,
        @as(f64, @floatFromInt(run.blocks)) / elapsed_s,
        run.transactions,
        gas / 1e6 / executing_s,
        run.db.head_info.number,
        run.feed.pool.tip_estimate() -| run.db.head_info.number,
        run.feed.mode,
        run.tip_blocks,
        lag_avg_ms,
        run.lag_max_ms,
        run.feed.pool.blocks,
        run.feed.switches,
        elapsed_s,
    });
    print_phases(run);
    if (run.engine) |service| service.engine.summary();
    if (run.rpc) |service| service.api.summary();
    if (run.gossip) |value| value.summary();
    if (now - run.peers_printed_ms >= peers_interval_ms) {
        run.peers_printed_ms = now;
        run.feed.pool.print_peers();
    }
}

/// Milliseconds per committed block in each runner phase (`Runner.Stats.time`).
fn print_phases(run: *const Run) void {
    const blocks = run.runner.stats.blocks;
    if (blocks == 0) return;
    const time = &run.runner.stats.time;
    std.debug.print("phases ms/block:", .{});
    inline for (@typeInfo(@TypeOf(time.*)).@"struct".field_names) |name| {
        const ns: f64 = @floatFromInt(@field(time, name));
        const per_block_ms = ns / 1e6 / @as(f64, @floatFromInt(blocks));
        std.debug.print(" {s} {d:.2}", .{ name[0 .. name.len - 3], per_block_ms });
    }
    std.debug.print("\n", .{});
}

test "el-run: flags" {
    const enode_text = "enode://00@127.0.0.1:1";
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{ "--db", "x" }));
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{ "--enode", enode_text }));
    const peers = try parse_flags(&.{ "--db", "x", "--peers", "peers.txt" });
    try std.testing.expectEqualStrings("peers.txt", peers.peers.?);
    try std.testing.expect(peers.enode == null);
    const set = try parse_flags(&.{
        "--db", "x", "--enode", enode_text, "--chain", "base-mainnet", "--duration", "1800",
    });
    try std.testing.expectEqualStrings("base-mainnet", set.chain.name);
    try std.testing.expectEqual(@as(u64, 8453), set.config.chain_id);
    try std.testing.expectEqual(@as(?u64, 1800), set.duration_s);
    const defaults = try parse_flags(&.{ "--enode", enode_text, "--db", "x" });
    try std.testing.expectEqual(@as(u64, 84532), defaults.config.chain_id);
    const rejected = [_][]const []const u8{
        &.{ "--db", "x", "--enode", enode_text, "--blocks", "0" },
        &.{ "--db", "x", "--enode", enode_text, "--chain", "op-mainnet" },
        &.{ "--db", "x", "--enode", enode_text, "--duration" },
    };
    for (rejected) |args| try std.testing.expectError(error.InvalidArguments, parse_flags(args));
    const engine = try parse_flags(&.{
        "--db", "x", "--enode", enode_text, "--engine.addr", "127.0.0.1:8551", "--engine.jwt", "j",
    });
    try std.testing.expectEqualStrings("127.0.0.1:8551", engine.engine.addr.?);
    const half = parse_flags(&.{ "--db", "x", "--enode", enode_text, "--engine.jwt", "j" });
    try std.testing.expectError(error.InvalidArguments, half);
    // `--gossip` takes no value; `--p2p.*` values are skipped, boolean ones take none.
    const gossip = try parse_flags(&.{
        "--gossip", "--p2p.peers.hi", "4", "--p2p.no-discovery", "--db", "x", "--enode", enode_text,
    });
    try std.testing.expect(gossip.gossip);
    try std.testing.expectEqualStrings("x", gossip.db);
    try std.testing.expect(!defaults.gossip);
}

test {
    _ = el_engine;
    _ = el_rpc;
}

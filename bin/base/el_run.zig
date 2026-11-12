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
//! `--prefetch all|tx|none` picks the runner's prefetches (`import.run.Prefetching`): `all`
//! (the default) reads ahead before execution and the commit's trie paths, `tx` only before
//! execution, `none` neither. Results never depend on it; it is for comparing speeds.
//!
//! `--cache-mb <n>` sizes the flat trees' block cache (default: the database shape's, 4 GiB
//! for the node shapes). Memory only, not part of the file: any size opens any database.
//!
//! With `--engine.addr <ip:port> --engine.jwt <file>` it also serves the Engine API to a
//! verifier `base consensus` (`el_engine.zig`), between blocks and while idle at the tip.
//!
//! With `--rpc` it serves JSON-RPC (`el_rpc.zig`). With `--archive <file>` (needs `--rpc`)
//! it also keeps a window of history on disk (`el_archive.zig`, `--archive.size-gb`):
//! blocks, receipts, and state at past blocks for the RPC.
//!
//! With `--gossip` (and any `--p2p.*` flags) it also joins the consensus gossip network
//! (`el_gossip.zig`) and checks every committed block against the sequencer-signed gossip
//! block at its height, when gossip delivers one: equal hashes anchor the devp2p chain to
//! the sequencer, a different hash prints `GOSSIP CONFLICT`. At the tip it also executes the
//! signed gossip block for the next height when exactly one arrived and it links to the head
//! (`el_gossip.Blocks`): gossip arrives within about 100 ms of a block's slot, a single
//! devp2p peer seconds later at times. devp2p is asked once the next block is
//! `gossip_grace_ms` overdue, and at least every `devp2p_keepalive_ms` so the follow
//! connection stays open.

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
const el_archive = @import("el_archive.zig");
const log_relay = @import("log_relay.zig");

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
    \\                   [--archive <file> [--archive.size-gb <n>]]
    \\                   [--rollup.sequencer-http <url>]
    \\                   [--prefetch all|tx|none] [--cache-mb <n>]
    \\
;

const flush_every = 64;
/// Journal entries queued behind the commit in flight: 12.8 s of 200 ms blocks (the shapes'
/// 8 filled within one 1.6 s sync, and the next block waited for it).
const queue_entries: u32 = 64;
/// At the tip, blocks do not wait for durability: each idle wait first ticks the storage toward
/// it for at most `tip_flush_ms` (waiting for it there held blocks for up to 9 s behind a
/// checkpoint on Base mainnet). The storage's room before each block still bounds the
/// committed but not yet durable blocks; past `tip_unflushed_max` of them, el-run waits.
const tip_flush_ms = 10;
const tip_flush_ticks_max = 4096;
const tip_unflushed_max = 1024;
/// `--cache-mb` bounds: one cache set of 64 KiB blocks at least, 1 TiB at most.
const cache_mb_min: u32 = 1;
const cache_mb_max: u32 = 1 << 20;
const summary_interval_ms = 10_000;
const peers_interval_ms = 60_000;
const tip_wait_ms = 100;
/// At the tip, after a fetch found no new block: the shortest wait before asking again, once
/// the next block's slot time has passed (before it, el-run waits for the slot time). A
/// fixed `tip_wait_ms` here delayed each block by about half of it on average.
const tip_poll_ms = 25;
/// At the tip, the servers' time after each block. Following one peer, the feed waits for
/// the next block inside `next` and then returns it, so el-run can go minutes without its
/// idle wait; a single `poll` per block answered about one engine request, which held a
/// verifier's consolidation near 1 block/s on Base mainnet. Blocks there execute in ~25 ms
/// of their 200 ms slot, so 30 ms leaves room to catch up; behind the tip, `poll` only.
const tip_serve_ms = 30;
/// With `--gossip` at the tip: how long after a block's slot time el-run waits for its signed
/// gossip block before asking devp2p for it, and the longest it leaves devp2p unasked.
const gossip_grace_ms = 250;
const devp2p_keepalive_ms = 2_000;

/// At the tip, a block whose lag rose by more than this over the previous block's gets a
/// `slow block` line saying where the time before it went.
const slow_rise_ms = 400;

comptime {
    assert(tip_serve_ms < tip_wait_ms);
    assert(tip_poll_ms < tip_wait_ms);
    assert(tip_wait_ms < slow_rise_ms);
    assert(tip_flush_ms < tip_wait_ms);
    assert(flush_every < tip_unflushed_max);
}

const Flags = struct {
    db: []const u8 = "",
    enode: ?[]const u8 = null,
    peers: ?[]const u8 = null,
    chain: *const import_run_cli.Chain = &import_run_cli.chains[0],
    config: *const ChainConfig = &base.common.chains.sepolia,
    blocks: ?u64 = null,
    duration_s: ?u64 = null,
    prefetching: import_run.Prefetching = .all,
    /// The flat trees' block cache in MiB (null: the shape's).
    cache_mb: ?u32 = null,
    engine: el_engine.Flags = .{},
    /// The read-only JSON-RPC server (`--rpc`, `--rpc.*`).
    rpc: el_rpc.Flags = .{},
    /// History on disk (`--archive`, `--archive.*`); needs `--rpc`.
    archive: el_archive.Flags = .{},
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
        } else if (std.mem.eql(u8, name, "--rollup.sequencer-http")) {
            flags.rpc.sequencer_url = value;
        } else if (std.mem.eql(u8, name, "--blocks")) {
            flags.blocks = try std.fmt.parseInt(u64, value, 10);
            if (flags.blocks.? == 0) return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--cache-mb")) {
            const cache_mb = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (cache_mb < cache_mb_min or cache_mb > cache_mb_max) return error.InvalidArguments;
            flags.cache_mb = cache_mb;
        } else if (std.mem.eql(u8, name, "--prefetch")) {
            flags.prefetching = std.meta.stringToEnum(import_run.Prefetching, value) orelse
                return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--duration")) {
            flags.duration_s = try std.fmt.parseInt(u64, value, 10);
            if (flags.duration_s.? == 0) return error.InvalidArguments;
        } else if (!try flags.engine.parse(name, value) and !try flags.rpc.parse(name, value) and
            !try flags.archive.parse(name, value))
        {
            return error.InvalidArguments;
        }
    }
    if (flags.db.len == 0 or (flags.enode == null and flags.peers == null)) {
        return error.InvalidArguments;
    }
    if (!flags.engine.valid()) return error.InvalidArguments;
    if (flags.archive.path != null and flags.rpc.addr == null) return error.InvalidArguments;
    if (flags.rpc.sequencer_url != null and flags.rpc.addr == null) return error.InvalidArguments;
    assert(flags.config.chain_id == flags.chain.spec.chain_id);
    return flags;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    // A line per block: a busy disk must not hold up the next block (`log_relay.zig`).
    log_relay.start(init.io);
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
    var sizing = try to_disk.sizing(Storage, counts, to_disk.node_shape(counts));
    if (flags.cache_mb) |cache_mb| {
        sizing.config.flat_cache_blocks = cache_blocks_of(cache_mb, &sizing.config);
    }
    // One group commit is in flight at a time, and its sync can take seconds on a busy disk:
    // the queue behind it holds `queue_entries` blocks before the runner waits. Memory only.
    sizing.config.queue_entries_max = @max(sizing.config.queue_entries_max, queue_entries);
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
    /// The archive (`--archive`), appended to after every committed block.
    archive: ?*el_archive.Service = null,
    /// Sequencer-signed gossip (`--gossip`), checked against every committed block.
    gossip: ?*el_gossip.Gossip = null,
    rollup: base.consensus.protocol.RollupConfig,
    first: u64,
    started_ms: i64,
    last_summary_ms: i64,
    /// When `feed.next` was last called (devp2p), for `devp2p_keepalive_ms`.
    devp2p_asked_ms: i64 = 0,
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
    lag_last_ms: u64 = 0,
    /// Where the time between the previous block's commit and this block's execution went.
    gap: Gap = .{},
    /// `gap` summed over the tip blocks since the last summary (the `tip ms/block:` line).
    gap_sum: Gap = .{},
    gap_blocks: u64 = 0,

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

    /// At the tip: ticks the storage for at most `tip_flush_ms` toward durability and toward
    /// the checkpoint the next block's room would wait for (`Runner.idle_tick`), without
    /// waiting for either.
    fn flush_idle(run: *Run) !void {
        assert(run.feed.at_tip);
        const deadline_ms = run.now_ms() + tip_flush_ms;
        for (0..tip_flush_ticks_max) |_| {
            const quiet = try run.runner.idle_tick();
            if (run.db.durable_sequence == run.db.submitted_sequence) run.unflushed = 0;
            if (quiet or run.now_ms() >= deadline_ms) return;
        }
    }
};

fn execute(
    init: std.process.Init,
    flags: *const Flags,
    db: *Database,
    driver: to_disk.Driver,
) !u8 {
    const gpa = init.gpa;
    var awake: AwakeClock = .{ .io = init.io };
    const config = runner_config(flags, &awake);
    const runner = try Runner.create(gpa, db, flags.chain.spec, driver, config);
    defer runner.destroy(gpa);
    const head = db.head_info;
    assert(head.present);
    // Before the peers: a bad address fails before any connection is made.
    const node = el_rpc.runner_node(Runner, runner);
    const rpc = el_rpc.Service.start(gpa, init.io, &flags.rpc, flags.chain.spec, node) catch |err| {
        std.debug.print("el-run: cannot start the JSON-RPC server: {t}\n", .{err});
        return 2;
    };
    defer if (rpc) |service| service.destroy(gpa);
    const archive = start_archive(gpa, flags, db, rpc) catch return 2;
    defer if (archive) |service| service.destroy(gpa);
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
        try el_gossip.Gossip.start(gpa, init.io, flags.config, flags.chain.spec, flags.args)
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
        .archive = archive,
        .gossip = gossip,
        .rollup = unsafe_watch.rollup_for(flags.config),
        .first = head.number + 1,
        .started_ms = 0,
        .last_summary_ms = 0,
    };
    return run_reported(&run, head.hash);
}

fn runner_config(flags: *const Flags, awake: *AwakeClock) import_run.Config {
    var config: import_run.Config = .{ .executor = .{} };
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    config.executor.state_gas_basis = base.execution.node.executor.default_state_gas_basis;
    config.clock = awake.clock();
    config.prefetching = flags.prefetching;
    return config;
}

/// The archive (`--archive`), serving the JSON-RPC server's history; null without one.
fn start_archive(
    gpa: std.mem.Allocator,
    flags: *const Flags,
    db: *Database,
    rpc: ?*el_rpc.Service,
) !?*el_archive.Service {
    const archive = el_archive.Service.start(gpa, &flags.archive, db) catch |err| {
        std.debug.print("el-run: cannot open the archive: {t}\n", .{err});
        return err;
    } orelse return null;
    // `parse_flags`: an archive needs the RPC server.
    rpc.?.api.history = archive.history();
    return archive;
}

/// Runs the blocks (`run_blocks`) between the start line and the final summary.
fn run_reported(run: *Run, parent: [32]u8) !u8 {
    assert(run.blocks == 0);
    run.started_ms = run.now_ms();
    run.last_summary_ms = run.started_ms;
    const config = &run.db.config;
    const cache_mb = @as(u64, config.flat_cache_blocks) * config.engine.checkpoint_block_size >> 20;
    std.debug.print("el-run: executing {s} from block {d} (parent {x}), blocks over devp2p, " ++
        "prefetch {t}, block cache {d} MiB\n", .{
        run.flags.chain.name, run.first, parent, run.flags.prefetching, cache_mb,
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

/// Blocks of the flat trees' cache in `cache_mb` MiB (at least one cache set).
fn cache_blocks_of(cache_mb: u32, config: *const base.execution.db.database.Config) u32 {
    const block_size: u64 = config.engine.checkpoint_block_size;
    assert(block_size > 0 and block_size <= 1 << 20);
    const ways = base.execution.db.storage.table.BlockCache.ways;
    const blocks = @max(ways, (@as(u64, cache_mb) << 20) / block_size);
    assert(blocks <= std.math.maxInt(u32));
    return @intCast(blocks);
}

/// The time between two blocks' execution, by what el-run was doing (milliseconds).
const Gap = struct {
    /// Inside `feed.next`: devp2p requests, including those that found no new block.
    fetch_ms: u64 = 0,
    /// Making committed blocks durable (`Runner.flush`).
    flush_ms: u64 = 0,
    /// The idle wait after a fetch found no new block.
    idle_ms: u64 = 0,
    /// Serving the Engine API and JSON-RPC after the previous block.
    serve_ms: u64 = 0,
    /// The previous block's hooks (`block_committed`) and log line, and summaries.
    log_ms: u64 = 0,
    /// Fetches that found no new block.
    polls: u64 = 0,

    fn add(sum: *Gap, gap: Gap) void {
        inline for (@typeInfo(Gap).@"struct".field_names) |name| {
            @field(sum, name) += @field(gap, name);
        }
    }
};

/// Executes blocks until `--blocks`, `--duration`, or the first failure (1).
fn run_blocks(run: *Run) !u8 {
    while (!run.done()) {
        var block: el_source.Block = undefined;
        const asked_ms = run.now_ms();
        const got = try next_block(run, &block);
        const fetched_ms = run.now_ms();
        run.gap.fetch_ms += @intCast(fetched_ms - asked_ms);
        if (!got) {
            // Nothing new yet: make what we have durable, then wait for the next block.
            run.gap.polls += 1;
            if (run.feed.at_tip) try run.flush_idle() else try run.flush();
            const flushed_ms = run.now_ms();
            run.gap.flush_ms += @intCast(flushed_ms - fetched_ms);
            if (!run.at_tip and run.feed.at_tip) {
                std.debug.print("el-run: at the tip, block {d}\n", .{run.db.head_info.number});
            }
            run.at_tip = run.feed.at_tip;
            try serve_idle(run, poll_wait_ms(run));
            run.gap.idle_ms += @intCast(run.now_ms() - flushed_ms);
            continue;
        }
        if (!try run_one(run, &block)) return 1;
        const served_ms = run.now_ms();
        if (run.feed.at_tip and (run.engine != null or run.rpc != null)) {
            try serve_idle(run, tip_serve_ms);
        } else {
            if (run.engine) |service| service.poll();
            if (run.rpc) |service| service.poll();
        }
        const flushed_ms = run.now_ms();
        run.gap.serve_ms += @intCast(flushed_ms - served_ms);
        run.unflushed += 1;
        const flush_at: u32 = if (run.feed.at_tip) tip_unflushed_max else flush_every;
        if (run.unflushed >= flush_at) try run.flush();
        run.gap.flush_ms += @intCast(run.now_ms() - flushed_ms);
        if (run.now_ms() - run.last_summary_ms >= summary_interval_ms) {
            const summary_ms = run.now_ms();
            summary(run);
            run.gap.log_ms += @intCast(run.now_ms() - summary_ms);
        }
    }
    return 0;
}

/// The next block: at the tip with `--gossip`, the signed gossip block when it links to the
/// head; from devp2p (`feed.next`) otherwise, or once the block is `gossip_grace_ms` overdue,
/// or after `devp2p_keepalive_ms` without asking. False: nothing new yet.
fn next_block(run: *Run, block: *el_source.Block) !bool {
    const gossip = run.gossip orelse return run.feed.next(block);
    if (run.feed.mode != .follow or !run.feed.at_tip) return run.feed.next(block);
    const parent = run.feed.parent orelse return run.feed.next(block);
    if (gossip.take(run.feed.next_number, parent)) |taken| {
        assert(taken.number == run.feed.next_number);
        block.* = taken;
        run.feed.adopt(block);
        return true;
    }
    const now = Io.Clock.real.now(run.io);
    const now_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
    const due_ms = run.rollup.l2_block_timestamp_ms(run.feed.next_number);
    const overdue = now_ms >= due_ms + gossip_grace_ms;
    const asked_ms = run.now_ms();
    if (!overdue and asked_ms - run.devp2p_asked_ms < devp2p_keepalive_ms) return false;
    run.devp2p_asked_ms = asked_ms;
    return run.feed.next(block);
}

/// At the tip, accounts the gap before `number` (executed in `exec_ms`) and prints a
/// `slow block` line when its lag rose by more than `slow_rise_ms` over the previous block's.
fn account_gap(run: *Run, number: u64, exec_ms: i64, lag_ms: u64, exec: *const ExecSplit) void {
    assert(run.feed.at_tip);
    const gap = run.gap;
    run.gap = .{};
    run.gap_sum.add(gap);
    run.gap_blocks += 1;
    const rise_ms = lag_ms -| run.lag_last_ms;
    run.lag_last_ms = lag_ms;
    if (rise_ms <= slow_rise_ms) return;
    std.debug.print("slow block {d}: lag_ms {d} (+{d}), before it: fetch {d} ms ({d} empty), " ++
        "flush {d} ms, idle {d} ms, serve {d} ms, log {d} ms; exec {d} ms\n", .{
        number,       lag_ms,     rise_ms, gap.fetch_ms, gap.polls, gap.flush_ms, gap.idle_ms,
        gap.serve_ms, gap.log_ms, exec_ms,
    });
    print_exec_split(exec);
}

const phase_count = @typeInfo(base.execution.import.room.Phase).@"enum".field_names.len;

/// One block's runner phase times and room wait (`import.run.Stats`), as deltas.
const ExecSplit = struct {
    time: import_run.Time,
    room_phase_ns: [phase_count]u64,

    fn begin(stats: *const import_run.Stats) ExecSplit {
        comptime assert(phase_count == @typeInfo(@TypeOf(stats.room.phase_ns)).array.len);
        return .{ .time = stats.time, .room_phase_ns = stats.room.phase_ns };
    }

    /// The change since `begin`: the runner's times only grow.
    fn end(split: *ExecSplit, stats: *const import_run.Stats) void {
        inline for (@typeInfo(import_run.Time).@"struct".field_names) |name| {
            assert(@field(stats.time, name) >= @field(split.time, name));
            @field(split.time, name) = @field(stats.time, name) - @field(split.time, name);
        }
        for (&split.room_phase_ns, stats.room.phase_ns) |*before, now| {
            assert(now >= before.*);
            before.* = now - before.*;
        }
    }
};

/// A slow block's execution by phase: those of 5 ms or more, and the room wait's storage phases.
fn print_exec_split(exec: *const ExecSplit) void {
    std.debug.print("  exec split:", .{});
    inline for (@typeInfo(import_run.Time).@"struct".field_names) |name| {
        const ms = @field(exec.time, name) / std.time.ns_per_ms;
        if (ms >= 5) std.debug.print(" {s} {d}", .{ name[0 .. name.len - 3], ms });
    }
    std.debug.print("; room by storage phase:", .{});
    const phases = @typeInfo(base.execution.import.room.Phase).@"enum".field_names;
    inline for (phases, 0..) |name, index| {
        const ms = exec.room_phase_ns[index] / std.time.ns_per_ms;
        if (ms >= 5) std.debug.print(" {s} {d}", .{ name, ms });
    }
    std.debug.print(" (ms)\n", .{});
}

/// How long to wait after a fetch found no new block: at the tip, until the next block's slot
/// time, then `tip_poll_ms` between fetches; behind it (the pool), `tip_wait_ms`.
fn poll_wait_ms(run: *const Run) u64 {
    if (!run.feed.at_tip) return tip_wait_ms;
    const now = Io.Clock.real.now(run.io);
    const now_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
    const due_ms = run.rollup.l2_block_timestamp_ms(run.feed.next_number);
    const wait_ms = std.math.clamp(due_ms -| now_ms, tip_poll_ms, tip_wait_ms);
    assert(wait_ms >= tip_poll_ms and wait_ms <= tip_wait_ms);
    return wait_ms;
}

/// Serves the Engine API and the JSON-RPC server for `duration_ms` while no block is
/// waiting: in slices, alternating between their IOs, when both run. A request's accept,
/// read and write each wait out the other server's slice, so slices stay short: a verifier
/// consensus node sends its engine requests one at a time.
fn serve_idle(run: *Run, duration_ms: u64) !void {
    const slice_ms = 2;
    if (run.archive) |archive| archive.tick();
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
    var exec = ExecSplit.begin(&run.runner.stats);
    const outcome = run.runner.execute(&runner_block) catch |err| {
        std.debug.print("el-run: block {d} hash {x}: refused: {t}; database head {d} hash {x}\n", .{
            block.number, block.hash, err, run.db.head_info.number, run.db.head_info.hash,
        });
        return false;
    };
    const elapsed = run.now_ms() - started;
    exec.end(&run.runner.stats);
    if (!outcome.ok()) {
        report_failure(run, &outcome);
        return false;
    }
    assert(run.db.head_info.number == block.number);
    const hooks_ms = run.now_ms();
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
        account_gap(run, block.number, elapsed, lag_ms, &exec);
    } else {
        run.gap = .{};
    }
    std.debug.print("block {d} hash {x} {d} txs {d} gas {d} ms lag_ms {d} checks ok\n", .{
        block.number, block.hash, outcome.transactions, outcome.gas_used, elapsed, lag_ms,
    });
    // After `account_gap`: the next block's gap.
    run.gap.log_ms += @intCast(run.now_ms() - hooks_ms);
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
    const record = if (run.rpc) |service| service.api.on_block(&.{
        .number = block.number,
        .hash = block.hash,
        .header_rlp = block.header_rlp,
        .transactions = block.transactions,
    }, receipts) else null;
    if (run.archive) |archive| {
        // Proof: the runner decoded this header before executing the block.
        const header = base.common.consensus.Header.decode(block.header_rlp) catch unreachable;
        const started = Io.Clock.awake.now(run.io);
        defer {
            const elapsed = started.durationTo(Io.Clock.awake.now(run.io));
            const elapsed_us: u64 = @intCast(@max(elapsed.toMicroseconds(), 0));
            archive.append_us_sum += elapsed_us;
            archive.append_us_max = @max(archive.append_us_max, elapsed_us);
        }
        archive.on_block(
            block.number,
            block.hash,
            header.parent_hash.bytes,
            record orelse &.{},
            block.transactions,
            run.runner.state_db.last_changeset().?, // This block's commit.
        );
    }
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
    print_gap(run);
    print_phases(run);
    if (run.engine) |service| service.engine.summary();
    if (run.rpc) |service| service.api.summary();
    if (run.archive) |service| service.summary();
    if (run.gossip) |value| value.summary();
    if (now - run.peers_printed_ms >= peers_interval_ms) {
        run.peers_printed_ms = now;
        run.feed.pool.print_peers();
    }
}

/// Milliseconds per tip block between two blocks' execution, by what el-run was doing,
/// since the last summary; then starts the next interval.
fn print_gap(run: *Run) void {
    if (run.gap_blocks == 0) return;
    const sum = run.gap_sum;
    const blocks: f64 = @floatFromInt(run.gap_blocks);
    std.debug.print("tip ms/block: fetch {d:.1} flush {d:.1} idle {d:.1} serve {d:.1} " ++
        "log {d:.1}, " ++
        "{d:.2} empty fetches, {d} blocks\n", .{
        @as(f64, @floatFromInt(sum.fetch_ms)) / blocks,
        @as(f64, @floatFromInt(sum.flush_ms)) / blocks,
        @as(f64, @floatFromInt(sum.idle_ms)) / blocks,
        @as(f64, @floatFromInt(sum.serve_ms)) / blocks,
        @as(f64, @floatFromInt(sum.log_ms)) / blocks,
        @as(f64, @floatFromInt(sum.polls)) / blocks,
        run.gap_blocks,
    });
    run.gap_sum = .{};
    run.gap_blocks = 0;
    assert(run.gap_sum.fetch_ms == 0);
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
    print_room(run);
}

/// What the `room` phase waited on (`import/room.zig`'s counters, since the start): ms per
/// committed block by what the storage was doing during the waiting ticks, the waits by the
/// condition that was short, and the checkpoints asked for and started.
fn print_room(run: *const Run) void {
    const stats = &run.runner.stats;
    assert(stats.blocks > 0);
    const room = &stats.room;
    const blocks: f64 = @floatFromInt(stats.blocks);
    std.debug.print("room ms/block:", .{});
    inline for (@typeInfo(base.execution.import.room.Phase).@"enum".field_names) |name| {
        const phase = @field(base.execution.import.room.Phase, name);
        const ns: f64 = @floatFromInt(room.ns(phase));
        std.debug.print(" {s} {d:.2}", .{ name, ns / 1e6 / blocks });
    }
    std.debug.print(", waits {d} (queue {d} journal {d} admission {d} start {d}), " ++
        "checkpoints requested {d} ahead {d} started {d}, busy retries {d}\n", .{
        room.waits,
        room.short_queue,
        room.short_journal,
        room.short_admission,
        room.start_waits,
        room.checkpoints_requested,
        room.checkpoints_ahead,
        room.checkpoints_started,
        stats.busy_retries,
    });
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
    try std.testing.expectEqual(import_run.Prefetching.all, defaults.prefetching);
    const off = try parse_flags(&.{ "--db", "x", "--enode", enode_text, "--prefetch", "none" });
    try std.testing.expectEqual(import_run.Prefetching.none, off.prefetching);
    try std.testing.expectEqual(@as(?u32, null), defaults.cache_mb);
    const cached = try parse_flags(&.{ "--db", "x", "--enode", enode_text, "--cache-mb", "32768" });
    try std.testing.expectEqual(@as(?u32, 32768), cached.cache_mb);
    const rejected = [_][]const []const u8{
        &.{ "--db", "x", "--enode", enode_text, "--blocks", "0" },
        &.{ "--db", "x", "--enode", enode_text, "--chain", "op-mainnet" },
        &.{ "--db", "x", "--enode", enode_text, "--duration" },
        &.{ "--db", "x", "--enode", enode_text, "--prefetch", "paths" },
        &.{ "--db", "x", "--enode", enode_text, "--cache-mb", "0" },
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

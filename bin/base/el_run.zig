//! `base el-run`: executes blocks N+1, N+2, ... on a disk-mode database
//! (`execution.import.run`) with blocks from one execution-layer peer over devp2p
//! (`el_source.zig`), with no RPC. N is the database head; the first block fetched must name
//! the head's hash as its parent, so the peer's chain is bound to the verified state.
//!
//!     base el-run --db <path> --enode <enode://...> [--chain base-sepolia|base-mainnet]
//!                 [--blocks <n>] [--duration <s>]
//!
//! Every block is checked by the runner (transactions root, gas, bloom, receipts root, state
//! root, withdrawals root, resealed hash) and committed only when all match, so the head
//! only ever advances by one executed block. One line per block (number, transactions, gas,
//! execution ms, tip lag), a summary every 10 s. Once the source reaches the peer's head the
//! run is at the tip: lag (time the block was committed minus its scheduled time) is counted
//! from then on. The first refused or mismatching block exits 1 with the head on its parent;
//! nothing is skipped. Commits are made durable every `flush_every` blocks and at the tip.
//!
//! Catch-up over devp2p is bounded by the peer (3 to 9 blocks/s measured); a database far
//! behind the tip is better caught up with `base import-run` first, then handed to this.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const el_source = @import("el_source.zig");
const import_run_cli = @import("import_run.zig");
const snapshot_import_out = @import("snapshot_import_out.zig");
const unsafe_watch = @import("unsafe_watch.zig");

const to_disk = base.execution.import.to_disk;
const import_run = base.execution.import.run;
const enode = base.consensus.p2p.peers.enode;
const curve = base.common.crypto.secp256k1;
const ChainConfig = base.common.chains.ChainConfig;
const assert = std.debug.assert;

const IO = base.utilities.io.IO;
const Storage = base.execution.db.storage.IoStorageType(IO);
const Importer = to_disk.ImporterType(Storage);
const Database = Importer.Database;
const Runner = import_run.RunnerType(Storage);

const usage =
    \\usage: base el-run --db <path> --enode <enode://...> [--chain base-sepolia|base-mainnet]
    \\                   [--blocks <n>] [--duration <s>]
    \\
;

const flush_every = 64;
const summary_interval_ms = 10_000;
const tip_wait_ms = 100;

const Flags = struct {
    db: []const u8 = "",
    enode: []const u8 = "",
    chain: *const import_run_cli.Chain = &import_run_cli.chains[0],
    config: *const ChainConfig = &base.common.chains.sepolia,
    blocks: ?u64 = null,
    duration_s: ?u64 = null,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (index + 1 == args.len) return error.InvalidArguments;
        const name = args[index];
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, name, "--db")) {
            flags.db = value;
        } else if (std.mem.eql(u8, name, "--enode")) {
            flags.enode = value;
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
        } else return error.InvalidArguments;
    }
    if (flags.db.len == 0 or flags.enode.len == 0) return error.InvalidArguments;
    assert(flags.config.chain_id == flags.chain.spec.chain_id);
    return flags;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const node = enode.parse(flags.enode) catch {
        std.debug.print("el-run: invalid enode\n", .{});
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
    const sizing = try to_disk.sizing(Storage, counts, to_disk.shape_node);
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
    const remote_compressed = node.public_key;
    const target: el_source.Target = .{
        .address = switch (node.address) {
            .ip4 => |ip| .{ .ip4 = .{ .bytes = ip, .port = node.tcp_port } },
            .ip6 => |ip| .{ .ip6 = .{ .bytes = ip, .port = node.tcp_port } },
        },
        .remote = curve.decompress_public_key(&remote_compressed) orelse return error.InvalidKey,
        .secret = el_source.random_secret(init.io),
        .chain = flags.config,
    };
    return execute(init, &flags, opened.db, ticker.driver(), target);
}

const Run = struct {
    io: Io,
    flags: *const Flags,
    db: *Database,
    runner: *Runner,
    source: *el_source.Source,
    rollup: base.consensus.protocol.RollupConfig,
    first: u64,
    started_ms: i64,
    last_summary_ms: i64,
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
    target: el_source.Target,
) !u8 {
    const gpa = init.gpa;
    var config: import_run.Config = .{ .executor = .{} };
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    config.executor.state_gas_basis = base.execution.node.executor.default_state_gas_basis;
    const runner = try Runner.create(gpa, db, flags.chain.spec, driver, config);
    defer runner.destroy(gpa);
    const head = db.head_info;
    assert(head.present);
    const source = try gpa.create(el_source.Source);
    defer gpa.destroy(source);
    // The peer's first block must be the child of the verified database head.
    try source.init(gpa, init.io, target, .{ .from = head.number + 1, .parent = head.hash });
    defer source.deinit(gpa);
    var run: Run = .{
        .io = init.io,
        .flags = flags,
        .db = db,
        .runner = runner,
        .source = source,
        .rollup = unsafe_watch.rollup_for(flags.config),
        .first = head.number + 1,
        .started_ms = 0,
        .last_summary_ms = 0,
    };
    run.started_ms = run.now_ms();
    run.last_summary_ms = run.started_ms;
    std.debug.print("el-run: executing {s} from block {d} (parent {x}), blocks over devp2p\n", .{
        flags.chain.name, run.first, head.hash,
    });
    const status = try run_blocks(&run);
    try run.flush();
    summary(&run);
    if (status == 0 and run.blocks > 0) {
        std.debug.print("el-run: ok, {d} consecutive executed blocks {d}..{d}, head {x}\n", .{
            run.blocks, run.first, db.head_info.number, db.head_info.hash,
        });
    }
    return status;
}

/// Executes blocks until `--blocks`, `--duration`, or the first failure (1).
fn run_blocks(run: *Run) !u8 {
    while (!run.done()) {
        var block: el_source.Block = undefined;
        if (!try run.source.next(&block)) {
            // At the peer's head: make what we have durable, then wait for the next block.
            try run.flush();
            if (!run.at_tip) std.debug.print("el-run: at the tip, block {d}\n", .{
                run.db.head_info.number,
            });
            run.at_tip = true;
            try run.io.sleep(.fromMilliseconds(tip_wait_ms), .awake);
            continue;
        }
        if (!try run_one(run, &block)) return 1;
        run.unflushed += 1;
        if (run.unflushed >= flush_every) try run.flush();
        if (run.now_ms() - run.last_summary_ms >= summary_interval_ms) summary(run);
    }
    return 0;
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
    run.blocks += 1;
    run.transactions += outcome.transactions;
    run.gas += outcome.gas_used;
    run.execute_ms += elapsed;
    const now = Io.Clock.real.now(run.io);
    const now_ms: u64 = @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_ms));
    const lag_ms = now_ms -| run.rollup.l2_block_timestamp_ms(block.number);
    if (run.at_tip) {
        run.tip_blocks += 1;
        run.lag_sum_ms += lag_ms;
        run.lag_max_ms = @max(run.lag_max_ms, lag_ms);
    }
    std.debug.print("block {d} hash {x} {d} txs {d} gas {d} ms lag_ms {d} checks ok\n", .{
        block.number, block.hash, outcome.transactions, outcome.gas_used, elapsed, lag_ms,
    });
    return true;
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
        "head {d}, at tip {}, tip blocks {d} lag_ms avg {d} max {d}, reconnects {d}, " ++
        "{d:.0} s\n", .{
        run.blocks,
        @as(f64, @floatFromInt(run.blocks)) / elapsed_s,
        run.transactions,
        gas / 1e6 / executing_s,
        run.db.head_info.number,
        run.at_tip,
        run.tip_blocks,
        lag_avg_ms,
        run.lag_max_ms,
        run.source.reconnects,
        elapsed_s,
    });
}

test "el-run: flags" {
    const enode_text = "enode://00@127.0.0.1:1";
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{ "--db", "x" }));
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{ "--enode", enode_text }));
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
}

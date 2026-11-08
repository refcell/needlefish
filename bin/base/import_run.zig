//! `base import-run`: executes blocks N+1, N+2, ... on a disk-mode database written by
//! `base snapshot-import --out` (`execution.import.run`), checking every header field.
//!
//!     base import-run --db <path> [--chain base-sepolia|base-mainnet] [--rpc <url>]
//!                     [--blocks <n>]
//!
//! The database opens with the sizing of its `<path>.counts` record (`to_disk.sizing`) over
//! io_uring. Blocks come from `--rpc` (`eth_getBlockByNumber(n, true)`, a few per batch, paced
//! and retried with backoff), each bound to its hash by `follow.follower.decode_block`. One
//! line per block (number, transactions, gas, milliseconds), a summary every 10 s. The first
//! block that fails a check prints the failed check and both state roots, and exits 1 with the
//! database head still on its parent. `--blocks` stops after that many blocks; without it the
//! run follows the chain tip.
//!
//! Every batch is made durable before the next is fetched; checkpoints run as the journal and
//! the replay reserve need them. Ctrl-C (or a kill) loses at most the batch in flight: a rerun
//! opens at the journal's head and continues from the block after it.
//!
//! Refused: a database whose format id names another chain's genesis, and one written with
//! `--test-head` (its head hash is the synthetic `to_disk.SyntheticHeaders` hash).

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const HttpTransport = @import("http_transport.zig").HttpTransport;
const snapshot_import_out = @import("snapshot_import_out.zig");

const to_disk = base.execution.import.to_disk;
const import_run = base.execution.import.run;
const follower = base.infra.follow.follower;
const json = std.json;
const assert = std.debug.assert;

const IO = base.utilities.io.IO;
const Storage = base.execution.db.storage.IoStorageType(IO);
const Importer = to_disk.ImporterType(Storage);
const Database = Importer.Database;
const Runner = import_run.RunnerType(Storage);
const Opened = snapshot_import_out.Opened;
const Ticker = snapshot_import_out.Ticker;
const Hash = [32]u8;

const usage =
    \\usage: base import-run --db <path> [--chain base-sepolia|base-mainnet] [--rpc <url>]
    \\                       [--blocks <n>]
    \\  --db      a disk-mode database written by `base snapshot-import --out` (and <path>.counts)
    \\  --rpc     JSON-RPC endpoint serving eth_getBlockByNumber with full transactions
    \\  --blocks  stop after this many blocks (default: follow the chain tip)
    \\
;

pub const Chain = struct {
    name: []const u8,
    spec: *const base.execution.chainspec.ChainSpec,
    genesis_hash: Hash,
    rpc: []const u8,
};

pub const chains = [_]Chain{
    .{
        .name = "base-sepolia",
        .spec = &base.execution.chainspec.ChainSpec.presets.base_sepolia,
        .genesis_hash = base.common.chains.sepolia.genesis_l2_hash.bytes,
        .rpc = "https://sepolia.base.org",
    },
    .{
        .name = "base-mainnet",
        .spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet,
        .genesis_hash = base.common.chains.mainnet.genesis_l2_hash.bytes,
        .rpc = "https://mainnet.base.org",
    },
};

const Flags = struct {
    db: []const u8,
    chain: *const Chain = &chains[0],
    rpc: ?[]const u8 = null,
    blocks: ?u64 = null,
};

fn parse(args: []const []const u8) !Flags {
    var db: ?[]const u8 = null;
    var flags: Flags = .{ .db = undefined };
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (index + 1 == args.len) return error.InvalidArguments;
        const name = args[index];
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, name, "--db")) {
            db = value;
        } else if (std.mem.eql(u8, name, "--chain")) {
            flags.chain = for (&chains) |*chain| {
                if (std.mem.eql(u8, chain.name, value)) break chain;
            } else return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--rpc")) {
            const http = std.mem.startsWith(u8, value, "http://") or
                std.mem.startsWith(u8, value, "https://");
            if (!http) return error.InvalidArguments;
            flags.rpc = value;
        } else if (std.mem.eql(u8, name, "--blocks")) {
            flags.blocks = std.fmt.parseInt(u64, value, 10) catch return error.InvalidArguments;
            if (flags.blocks.? == 0) return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    flags.db = db orelse return error.InvalidArguments;
    assert(flags.db.len > 0);
    return flags;
}

/// Blocks per JSON-RPC batch (each with full transactions: a few MiB at most).
const batch_max = 5;
const retries_max = 10;
const item_interval_ms = 50;
const response_bytes_max = 64 << 20;
const summary_interval_ms = 10_000;
/// Wait before asking again for a block the endpoint has not produced yet.
const tip_wait_ms = 200;

/// One JSON-RPC endpoint: per-item pacing, retries with backoff.
const Fetcher = struct {
    io: Io,
    http: HttpTransport,
    response: []u8,
    /// Awake-clock time (ms) before which the next request waits.
    next_ms: i64 = 0,
    requests: u64 = 0,
    failures: u64 = 0,

    fn pace(self: *Fetcher, items: u32) !void {
        assert(items > 0 and items <= batch_max);
        const now = Io.Clock.awake.now(self.io).toMilliseconds();
        if (self.next_ms > now) try self.io.sleep(.fromMilliseconds(self.next_ms - now), .awake);
        self.next_ms = @max(now, self.next_ms) + @as(i64, items) * item_interval_ms;
    }

    /// Posts a batch of `items` calls; returns the response once every item has a result.
    fn post(self: *Fetcher, arena: std.mem.Allocator, body: []const u8, items: u32) !json.Value {
        var attempt: u32 = 0;
        while (attempt < retries_max) : (attempt += 1) {
            if (attempt > 0) {
                self.failures += 1;
                const wait_ms: i64 = @min(@as(i64, 250) << @intCast(attempt), 30_000);
                try self.io.sleep(.fromMilliseconds(wait_ms), .awake);
            }
            try self.pace(items);
            self.requests += 1;
            const text = self.http.transport().send(body, self.response) catch |err| {
                std.debug.print("  {s}: {t}\n", .{ self.http.url, err });
                continue;
            };
            const value = json.parseFromSliceLeaky(json.Value, arena, text, .{}) catch continue;
            if (!batch_ok(value, items)) {
                if (attempt >= 3) {
                    const shown = text[0..@min(text.len, 200)];
                    std.debug.print("  {s}: {s}\n", .{ self.http.url, shown });
                }
                continue;
            }
            return value;
        }
        return error.EndpointFailed;
    }

    /// The JSON texts of blocks `first`.. (at most `count`), stopping at the first one the
    /// endpoint has not produced yet.
    fn blocks(
        self: *Fetcher,
        arena: std.mem.Allocator,
        first: u64,
        count: u32,
    ) ![]const []const u8 {
        assert(count > 0 and count <= batch_max);
        var body: Io.Writer.Allocating = .init(arena);
        try body.writer.writeAll("[");
        for (0..count) |id| {
            try body.writer.print("{s}{{\"jsonrpc\":\"2.0\",\"id\":{d}," ++
                "\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x{x}\",true]}}", .{
                if (id == 0) "" else ",",
                id,
                first + id,
            });
        }
        try body.writer.writeAll("]");
        const value = try self.post(arena, body.written(), count);
        var results: [batch_max]json.Value = undefined;
        for (value.array.items) |item| {
            const id = item.object.get("id").?.integer;
            results[@intCast(id)] = item.object.get("result").?;
        }
        const texts = try arena.alloc([]const u8, count);
        for (results[0..count], texts, 0..) |result, *text, index| {
            if (result == .null) return texts[0..index];
            text.* = try json.Stringify.valueAlloc(arena, result, .{});
        }
        return texts;
    }
};

/// A batch response of exactly `items` objects, ids 0..items-1 each once, no errors.
fn batch_ok(value: json.Value, items: u32) bool {
    if (value != .array or value.array.items.len != items) return false;
    var seen: u32 = 0;
    for (value.array.items) |item| {
        if (item != .object or item.object.get("error") != null) return false;
        if (item.object.get("result") == null) return false;
        const id = item.object.get("id") orelse return false;
        if (id != .integer or id.integer < 0 or id.integer >= items) return false;
        const bit = @as(u32, 1) << @intCast(id.integer);
        if (seen & bit != 0) return false;
        seen |= bit;
    }
    assert(@popCount(seen) == items);
    return true;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const gpa = init.gpa;
    const counts_path = try std.fmt.allocPrint(gpa, "{s}.counts", .{flags.db});
    defer gpa.free(counts_path);
    var buffer: [to_disk.Counts.encoded_size]u8 = undefined;
    const bytes = Io.Dir.cwd().readFile(init.io, counts_path, &buffer) catch |err| {
        std.debug.print("cannot read {s}: {t} (written by snapshot-import --out)\n", .{
            counts_path,
            err,
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
    var opened = Opened.init(gpa, &backend, flags.db, sizing.config, false) catch |err| {
        std.debug.print("cannot open {s}: {t}\n", .{ flags.db, err });
        return 1;
    };
    defer opened.deinit(gpa, &backend);
    var ticker: Ticker = .{ .backend = &backend, .storage = opened.storage };
    Importer.open(opened.db, ticker.driver()) catch |err| {
        std.debug.print("cannot open the database in {s}: {t}\n", .{ flags.db, err });
        return 1;
    };
    if (!usable(opened.db, flags.chain)) return 1;
    return execute(init, flags, opened.db, ticker.driver());
}

/// The database belongs to the chain and holds a real head.
pub fn usable(db: *Database, chain: *const Chain) bool {
    assert(db.phase == .ready);
    const head = db.head_info;
    if (!head.present) {
        std.debug.print("the database has no head (an unfinished import?)\n", .{});
        return false;
    }
    const format_id = db.engine.superblock.working.format_id;
    const prefix: u64 = @truncate(format_id >> 64);
    if (prefix != std.mem.readInt(u64, chain.genesis_hash[0..8], .big)) {
        std.debug.print("the database is not a {s} database (--chain)\n", .{chain.name});
        return false;
    }
    const synthetic = to_disk.SyntheticHeaders.hash_of(head.number);
    if (std.mem.eql(u8, &synthetic, &head.hash)) {
        std.debug.print("the database was imported with --test-head (synthetic block " ++
            "hashes): it cannot execute real blocks\n", .{});
        return false;
    }
    std.debug.print("database head {d} hash {x} state root {x}, {d} stored blocks\n", .{
        head.number,
        head.hash,
        head.state_root,
        db.chain.block_count(),
    });
    return true;
}

const Session = struct {
    io: Io,
    flags: Flags,
    db: *Database,
    runner: *Runner,
    fetcher: *Fetcher,
    arena: std.heap.ArenaAllocator,
    started_ms: i64,
    last_summary_ms: i64,
    blocks: u64 = 0,
    transactions: u64 = 0,
    gas: u64 = 0,
    execute_ms: i64 = 0,

    fn now_ms(session: *const Session) i64 {
        return Io.Clock.awake.now(session.io).toMilliseconds();
    }

    fn done(session: *const Session) bool {
        const limit = session.flags.blocks orelse return false;
        assert(session.blocks <= limit);
        return session.blocks == limit;
    }
};

fn execute(init: std.process.Init, flags: Flags, db: *Database, driver: to_disk.Driver) !u8 {
    const gpa = init.gpa;
    var config: import_run.Config = .{ .executor = .{} };
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    config.executor.state_gas_basis = base.execution.node.executor.default_state_gas_basis;
    const runner = try Runner.create(gpa, db, flags.chain.spec, driver, config);
    defer runner.destroy(gpa);
    const response = try gpa.alloc(u8, response_bytes_max);
    defer gpa.free(response);
    const url = flags.rpc orelse flags.chain.rpc;
    var fetcher: Fetcher = .{
        .io = init.io,
        .http = .init(gpa, init.io, url),
        .response = response,
    };
    defer fetcher.http.deinit();
    fetcher.http.timeout_ms = 30_000;
    var session: Session = .{
        .io = init.io,
        .flags = flags,
        .db = db,
        .runner = runner,
        .fetcher = &fetcher,
        .arena = .init(gpa),
        .started_ms = 0,
        .last_summary_ms = 0,
    };
    defer session.arena.deinit();
    session.started_ms = session.now_ms();
    session.last_summary_ms = session.started_ms;
    std.debug.print("executing {s} from block {d}; blocks from {s}\n", .{
        flags.chain.name,
        db.head_info.number + 1,
        url,
    });
    const status = try run_blocks(&session);
    try runner.flush();
    summary(&session);
    return status;
}

/// Fetches and executes batches until `--blocks` or the first failure; 1 on a failure.
fn run_blocks(session: *Session) !u8 {
    while (!session.done()) {
        _ = session.arena.reset(.retain_capacity);
        const arena = session.arena.allocator();
        const next = session.db.head_info.number + 1;
        var count: u32 = batch_max;
        if (session.flags.blocks) |limit| count = @intCast(@min(count, limit - session.blocks));
        const texts = try session.fetcher.blocks(arena, next, count);
        if (texts.len == 0) {
            try session.io.sleep(.fromMilliseconds(tip_wait_ms), .awake);
            continue;
        }
        for (texts) |text| {
            if (!try run_one(session, arena, text)) return 1;
        }
        // Durable before the next fetch: an interrupt loses at most one batch.
        try session.runner.flush();
        if (session.now_ms() - session.last_summary_ms >= summary_interval_ms) summary(session);
    }
    assert(session.done());
    return 0;
}

/// Executes one fetched block; false on a failed check, a failed execution, or a block the
/// database refuses (reported).
fn run_one(session: *Session, arena: std.mem.Allocator, text: []const u8) !bool {
    const decoded = try follower.decode_block(arena, text);
    const block: import_run.Block = .{
        .number = decoded.number,
        .hash = decoded.hash,
        .header_rlp = decoded.header_rlp,
        .transactions = decoded.transactions,
    };
    const started = session.now_ms();
    const outcome = session.runner.execute(&block) catch |err| {
        std.debug.print("block {d} hash {x}: refused: {t}; database head {d} hash {x}\n", .{
            block.number,
            block.hash,
            err,
            session.db.head_info.number,
            session.db.head_info.hash,
        });
        return false;
    };
    const elapsed = session.now_ms() - started;
    if (!outcome.ok()) {
        report_failure(session, &outcome, &decoded);
        return false;
    }
    session.blocks += 1;
    session.transactions += outcome.transactions;
    session.gas += outcome.gas_used;
    session.execute_ms += elapsed;
    std.debug.print("block {d} {d} txs {d} gas {d} ms state root ok\n", .{
        outcome.number,
        outcome.transactions,
        outcome.gas_used,
        elapsed,
    });
    return true;
}

fn report_failure(
    session: *const Session,
    outcome: *const import_run.Outcome,
    decoded: *const follower.Block,
) void {
    assert(!outcome.ok());
    const header = base.common.consensus.Header.decode(decoded.header_rlp) catch unreachable;
    std.debug.print("MISMATCH block {d} hash {x} ({d} txs)\n", .{
        outcome.number,
        outcome.hash,
        outcome.transactions,
    });
    if (outcome.failure) |err| {
        std.debug.print("  execution failed: {t} at transaction {?d}\n", .{
            err,
            outcome.failed_transaction,
        });
    } else {
        std.debug.print("  first failed check: {t} (passed mask 0b{b:0>8})\n", .{
            outcome.first_failed().?,
            outcome.passed,
        });
        std.debug.print("  gas used: header {d}, computed {d}\n", .{
            header.gas_used,
            outcome.gas_used,
        });
    }
    std.debug.print("  state root: header {x}\n              computed {x}\n", .{
        outcome.expected_state_root,
        outcome.computed_state_root,
    });
    std.debug.print("  the database head stays at {d} ({x})\n", .{
        session.db.head_info.number,
        session.db.head_info.hash,
    });
}

fn summary(session: *Session) void {
    const now = session.now_ms();
    session.last_summary_ms = now;
    const db = session.db;
    const elapsed_s: f64 = @as(f64, @floatFromInt(@max(now - session.started_ms, 1))) / 1000;
    const executing_s: f64 = @as(f64, @floatFromInt(@max(session.execute_ms, 1))) / 1000;
    const gas: f64 = @floatFromInt(session.gas);
    const stats = &session.runner.stats;
    std.debug.print("summary: {d} blocks ({d:.1}/s), {d} txs, {d:.1} Mgas/s executing, " ++
        "head {d}, durable seq {d}/{d}, {d} checkpoints ({d} for room), {d} busy retries, " ++
        "{d} rpc requests ({d} retried), {d:.0} s\n", .{
        session.blocks,
        @as(f64, @floatFromInt(session.blocks)) / elapsed_s,
        session.transactions,
        gas / 1e6 / executing_s,
        db.head_info.number,
        db.durable_sequence,
        db.submitted_sequence,
        db.checkpoints_completed,
        stats.room.checkpoints_requested,
        stats.busy_retries,
        session.fetcher.requests,
        session.fetcher.failures,
        elapsed_s,
    });
}

test "import-run: flags" {
    try std.testing.expectError(error.InvalidArguments, parse(&.{}));
    const defaults = try parse(&.{ "--db", "x.dat" });
    try std.testing.expectEqualStrings("x.dat", defaults.db);
    try std.testing.expectEqualStrings("base-sepolia", defaults.chain.name);
    try std.testing.expect(defaults.rpc == null and defaults.blocks == null);
    const set = try parse(&.{
        "--chain", "base-mainnet", "--db", "y", "--rpc", "http://127.0.0.1:8545", "--blocks", "3",
    });
    try std.testing.expectEqualStrings("base-mainnet", set.chain.name);
    try std.testing.expectEqual(@as(?u64, 3), set.blocks);
    const rejected = [_][]const []const u8{
        &.{"--db"},
        &.{ "--db", "x", "--chain", "op-mainnet" },
        &.{ "--db", "x", "--rpc", "ftp://x" },
        &.{ "--db", "x", "--blocks", "0" },
        &.{ "--db", "x", "--blocks", "many" },
        &.{ "--db", "x", "--test-head", "1" },
    };
    for (rejected) |args| try std.testing.expectError(error.InvalidArguments, parse(args));
}

test "import-run: batch responses are accepted only whole and without errors" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ok = try json.parseFromSliceLeaky(json.Value, arena,
        \\[{"id":1,"result":null},{"id":0,"result":{}}]
    , .{});
    try std.testing.expect(batch_ok(ok, 2));
    try std.testing.expect(!batch_ok(ok, 3));
    const rejected = [_][]const u8{
        \\[{"id":0,"result":1},{"id":0,"result":1}]
        ,
        \\[{"id":0,"result":1},{"id":1,"error":{"code":429}}]
        ,
        \\[{"id":0,"result":1},{"id":2,"result":1}]
        ,
        \\{"id":0,"result":1}
        ,
    };
    for (rejected) |text| {
        const value = try json.parseFromSliceLeaky(json.Value, arena, text, .{});
        try std.testing.expect(!batch_ok(value, 2));
    }
}

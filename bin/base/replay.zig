//! `base replay`: replay real Base mainnet blocks offline and check that needlefish reproduces
//! every canonical header field (docs/REPLAY.md).
//!
//!     base replay import <raw dir> [--out <archive>]   saved JSON-RPC results -> archive
//!     base replay run [<archive>] [--blocks <n>]       replay offline, report per block
//!     base replay bench <archive> [<warm runs>]        timing lines (docs/BENCHMARKS.md)

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const replay = base.infra.replay;
const tui = @import("replay_tui.zig");
const fetch = @import("replay_fetch.zig");
const bench = @import("replay_bench.zig");

test {
    _ = fetch;
    _ = bench;
}
const Archive = replay.Archive;
const assert = std.debug.assert;

pub const default_archive = "replay.nfrp";
const usage =
    \\usage: base replay fetch [--count <n>] [--from <block>] [--cache <dir>] [--out <archive>]
    \\       base replay import <raw dir> [--out <archive>]
    \\       base replay run [<archive>] [--blocks <n>] [--plain]
    \\       base replay bench <archive> [<warm runs>]
    \\
;
pub const file_bytes_max = 1 << 30;

pub const archive_config: Archive.Config = .{
    .witness = .{
        .state_nodes_max = 1 << 19,
        .state_bytes_max = 256 << 20,
        .codes_max = 1 << 13,
        .code_bytes_max = 96 << 20,
        .keys_max = 1,
        .headers_max = 1024,
        .header_bytes_max = 1 << 20,
    },
    .transactions_max = 1 << 15,
    .transaction_bytes_max = 64 << 20,
    .accounts_max = 1 << 16,
    .slots_max = 1 << 18,
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    if (std.mem.eql(u8, args[0], "import")) return import_main(init, args[1..]);
    if (std.mem.eql(u8, args[0], "run")) return run_main(init, args[1..]);
    if (std.mem.eql(u8, args[0], "fetch")) return fetch.main(init, args[1..]);
    if (std.mem.eql(u8, args[0], "bench")) return bench.main(init, args[1..]);
    std.debug.print("unknown replay command: {s}\n{s}", .{ args[0], usage });
    return 2;
}

fn import_main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len != 1 and args.len != 3) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    var out_path: []const u8 = default_archive;
    if (args.len == 3) {
        if (!std.mem.eql(u8, args[1], "--out")) return error.InvalidArguments;
        out_path = args[2];
    }
    const gpa = init.gpa;
    var dir = try Io.Dir.cwd().openDir(init.io, args[0], .{});
    defer dir.close(init.io);
    var archive = try Archive.init(gpa, archive_config);
    defer archive.deinit(gpa);
    const window = try read_window(init, dir);
    try import_blocks(init, dir, &archive, window);
    try write_archive(init, &archive, window, out_path);
    return 0;
}

/// Encodes `archive` and writes it to `out_path`.
pub fn write_archive(
    init: std.process.Init,
    archive: *const Archive,
    window: Window,
    out_path: []const u8,
) !void {
    const gpa = init.gpa;
    const body = try replay.archive.encode_body(gpa, archive, archive_config.witness);
    defer gpa.free(body);
    var output: Io.Writer.Allocating = .init(gpa);
    defer output.deinit();
    try replay.archive.write_frame(body, &output.writer);
    try Io.Dir.cwd().writeFile(init.io, .{ .sub_path = out_path, .data = output.written() });
    std.debug.print("imported blocks {d}..{d}: {d} txs, {d} trie nodes, {d} codes, " ++
        "{d} opaque, {d} bytes -> {s} ({d} bytes)\n", .{
        window.first,
        window.first + window.count - 1,
        archive.transactions_total(),
        archive.witness.state.count,
        archive.witness.codes.count,
        archive.opaque_len,
        body.len,
        out_path,
        output.written().len,
    });
}

pub const Window = struct { first: u64, count: u32 };

pub fn read_window(init: std.process.Init, dir: Io.Dir) !Window {
    const raw = try dir.readFileAlloc(init.io, "window.json", init.gpa, .limited(4096));
    defer init.gpa.free(raw);
    const Parsed = struct { first: u64, count: u32 };
    const parsed = try std.json.parseFromSlice(Parsed, init.gpa, raw, .{});
    defer parsed.deinit();
    if (parsed.value.count == 0 or parsed.value.count > replay.archive.blocks_max) {
        return error.InvalidArguments;
    }
    return .{ .first = parsed.value.first, .count = parsed.value.count };
}

pub fn import_blocks(init: std.process.Init, dir: Io.Dir, archive: *Archive, window: Window) !void {
    const gpa = init.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const headers = try dir.readFileAlloc(init.io, "headers.json", gpa, .limited(file_bytes_max));
    defer gpa.free(headers);
    try replay.import.add_ancestors(arena_state.allocator(), archive, headers, window.first);
    archive.chain_id = base.execution.chainspec.ChainSpec.presets.base_mainnet.chain_id;
    var seen: replay.import.Seen = .{};
    defer seen.deinit(gpa);
    var pre_state_root = archive.parent_state_root;
    for (0..window.count) |offset| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "{d}", .{window.first + offset});
        var block_dir = try dir.openDir(init.io, name, .{});
        defer block_dir.close(init.io);
        const files: replay.import.BlockFiles = .{
            .block = try read(init, block_dir, arena, "block.json"),
            .receipts = try read(init, block_dir, arena, "receipts.json"),
            .prestate = try read(init, block_dir, arena, "prestate.json"),
            .proofs_pre = try read(init, block_dir, arena, "proofs_pre.json"),
            .proofs_post = try read(init, block_dir, arena, "proofs_post.json"),
            .proofs_extra = try read_optional(init, block_dir, arena, "proofs_extra.json"),
            .codes_extra = try read_optional(init, block_dir, arena, "codes_extra.json"),
        };
        const pre = pre_state_root;
        pre_state_root = replay.import.add_block(gpa, arena, archive, &seen, files, pre) catch |err|
            {
                std.debug.print("block {s}: import failed: {t}\n", .{ name, err });
                return err;
            };
    }
}

fn read(init: std.process.Init, dir: Io.Dir, arena: std.mem.Allocator, name: []const u8) ![]u8 {
    return dir.readFileAlloc(init.io, name, arena, .limited(file_bytes_max));
}

fn read_optional(
    init: std.process.Init,
    dir: Io.Dir,
    arena: std.mem.Allocator,
    name: []const u8,
) !?[]u8 {
    return read(init, dir, arena, name) catch |err| switch (err) {
        error.FileNotFound => null,
        else => err,
    };
}

fn run_main(init: std.process.Init, args: []const []const u8) !u8 {
    var path: []const u8 = default_archive;
    var blocks_limit: ?u32 = null;
    var plain = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--plain")) {
            plain = true;
        } else if (std.mem.eql(u8, args[index], "--blocks")) {
            if (index + 1 == args.len) return error.InvalidArguments;
            blocks_limit = try std.fmt.parseInt(u32, args[index + 1], 10);
            index += 1;
        } else {
            path = args[index];
        }
    }
    const gpa = init.gpa;
    const file = try Io.Dir.cwd().readFileAlloc(init.io, path, gpa, .limited(file_bytes_max));
    defer gpa.free(file);
    var archive = try Archive.init(gpa, archive_config);
    defer archive.deinit(gpa);
    try replay.archive.decode(gpa, file, &archive);
    var buffer: [4096]u8 = undefined;
    const stdout = Io.File.stdout();
    var writer = stdout.writer(init.io, &buffer);
    const color = !plain and try stdout.isTty(init.io);
    const limit = @min(blocks_limit orelse archive.block_count, archive.block_count);
    var view: tui.View = .{
        .out = &writer.interface,
        .style = .{ .color = color },
        .block_count = limit,
    };
    const first = base.execution.db.witness.header_number(archive.block_header(0)) catch
        return error.InvalidArchive;
    try view.header(first, file.len);
    return run_archive(init, &archive, &view);
}

fn run_archive(init: std.process.Init, archive: *const Archive, view: *tui.View) !u8 {
    const gpa = init.gpa;
    const spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet;
    const replayer = try gpa.create(replay.Replayer);
    defer gpa.destroy(replayer);
    try replayer.init(gpa, spec, archive, replayer_config(archive));
    defer replayer.deinit(gpa);
    try view.progress();
    var replayed: u32 = 0;
    while (replayed < view.block_count and !replayer.done()) : (replayed += 1) {
        const start = Io.Clock.awake.now(init.io);
        const outcome = try replayer.replay_next();
        const elapsed = start.durationTo(Io.Clock.awake.now(init.io));
        try view.row(&outcome, @intCast(@max(elapsed.nanoseconds, 0)));
        if (!outcome.ok()) {
            try view.out.flush();
            print_failure(replayer, &outcome);
            print_gaps_json(replayer, &outcome);
            break;
        }
    }
    try view.summary();
    return if (view.totals.passed == view.block_count) 0 else 1;
}

fn print_failure(replayer: *const replay.Replayer, outcome: *const replay.replayer.Outcome) void {
    if (outcome.failure) |failure| {
        std.debug.print("  execution failed: {t} (transaction {?d})\n", .{
            failure,
            outcome.failed_transaction,
        });
    }
    if (outcome.first_failed()) |check| std.debug.print("  first failed check: {t}\n", .{check});
    if (outcome.receipt_diff) |diff| {
        std.debug.print("  receipt {d}: expected {any} computed {any}\n", .{
            diff.index,
            diff.expected,
            diff.computed,
        });
    }
    if (outcome.state_diff) |diff| std.debug.print("  state: {any}\n", .{diff});
    std.debug.print("  state root expected {x} computed {x}\n", .{
        outcome.expected_state_root,
        outcome.computed_state_root,
    });
    const gaps = &replayer.gaps;
    std.debug.print("  gaps: {d} accounts {d} slots {d} nodes {d} codes {d} hashes (+{d})\n", .{
        gaps.accounts_len,
        gaps.slots_len,
        gaps.nodes_len,
        gaps.codes_len,
        gaps.block_hashes_len,
        gaps.dropped,
    });
    for (gaps.nodes[0..@min(gaps.nodes_len, 4)]) |hash| std.debug.print("    node {x}\n", .{hash});
    for (gaps.accounts[0..@min(gaps.accounts_len, 4)]) |address| {
        std.debug.print("    account {x}\n", .{address});
    }
    for (gaps.slots[0..@min(gaps.slots_len, 4)]) |key| {
        std.debug.print("    slot {x} {x}\n", .{ key.address, key.slot });
    }
    assert(!outcome.ok());
}

/// One machine-readable line for gap-filling tools: `GAPS {"block":n,"accounts":[...],
/// "slots":[[address,slot],...],"nodes":[...]}`.
fn print_gaps_json(replayer: *const replay.Replayer, outcome: *const replay.replayer.Outcome) void {
    const gaps = &replayer.gaps;
    std.debug.print("GAPS {{\"block\":{d},\"accounts\":[", .{outcome.number});
    for (gaps.accounts[0..gaps.accounts_len], 0..) |address, index| {
        std.debug.print("{s}\"0x{x}\"", .{ if (index == 0) "" else ",", address });
    }
    std.debug.print("],\"code_owners\":[", .{});
    for (gaps.code_owners[0..gaps.code_owners_len], 0..) |address, index| {
        std.debug.print("{s}\"0x{x}\"", .{ if (index == 0) "" else ",", address });
    }
    std.debug.print("],\"slots\":[", .{});
    for (gaps.slots[0..gaps.slots_len], 0..) |key, index| {
        std.debug.print("{s}[\"0x{x}\",\"0x{x:0>64}\"]", .{
            if (index == 0) "" else ",",
            key.address,
            key.slot,
        });
    }
    std.debug.print("],\"nodes\":[", .{});
    for (gaps.nodes[0..gaps.nodes_len], 0..) |hash, index| {
        std.debug.print("{s}\"0x{x}\"", .{ if (index == 0) "" else ",", hash });
    }
    std.debug.print("]}}\n", .{});
}

/// The keys the replay lacked in the first block that failed, for the fetcher.
pub const GapReport = struct {
    block: u64,
    accounts: []const [20]u8,
    slots: []const replay.replayer.SlotKey,
    nodes: u32,
    codes: u32,
};

/// Replays the whole archive silently in probe mode. Null when every block passes;
/// otherwise the gaps of every block that lacks state. A block that fails without gaps
/// before any block with gaps is a real mismatch (printed); after one, its pre-state is
/// already wrong, so it is skipped.
pub fn check_archive(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *const Archive,
) !?[]const GapReport {
    const spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet;
    const replayer = try gpa.create(replay.Replayer);
    defer gpa.destroy(replayer);
    try replayer.init(gpa, spec, archive, replayer_config(archive));
    defer replayer.deinit(gpa);
    replayer.probe = true;
    var reports: std.ArrayList(GapReport) = .empty;
    while (!replayer.done()) {
        const outcome = try replayer.replay_next();
        if (outcome.ok()) continue;
        const gaps = &replayer.gaps;
        if (gaps.accounts_len + gaps.code_owners_len + gaps.slots_len == 0) {
            if (reports.items.len > 0) continue;
            print_failure(replayer, &outcome);
            return error.Mismatch;
        }
        const accounts = try arena.alloc([20]u8, gaps.accounts_len + gaps.code_owners_len);
        @memcpy(accounts[0..gaps.accounts_len], gaps.accounts[0..gaps.accounts_len]);
        @memcpy(accounts[gaps.accounts_len..], gaps.code_owners[0..gaps.code_owners_len]);
        try reports.append(arena, .{
            .block = outcome.number,
            .accounts = accounts,
            .slots = try arena.dupe(replay.replayer.SlotKey, gaps.slots[0..gaps.slots_len]),
            .nodes = gaps.nodes_len,
            .codes = gaps.codes_len,
        });
    }
    assert(reports.items.len <= archive.block_count);
    return if (reports.items.len == 0) null else reports.items;
}

/// The replayer limits for `archive`, recovering senders on one worker per spare core (at
/// most 7) as `base node` does; results do not depend on the worker count.
pub fn replayer_config(archive: *const Archive) replay.replayer.Config {
    var config = replay.replayer.config_for(archive);
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    config.executor.state_gas_basis = base.execution.node.executor.default_state_gas_basis;
    return config;
}

//! `replay-roots`: a trie-only root check against real blocks, without the EVM.
//!
//!   replay-roots DIR [BLOCK]
//!
//! DIR holds `headers.json` (a list of `{number, stateRoot, ...}` covering each block's
//! parent) and one directory per block number with the raw RPC results: `block.json`
//! (`eth_getBlockByNumber` with full transactions), `receipts.json`
//! (`eth_getBlockReceipts`), and `proofs_pre.json` / `proofs_post.json` (`eth_getProof`
//! for every touched account and slot at the parent and at the block). Without BLOCK every
//! numeric subdirectory is checked, in order. The analysis is `execution.db.replay_roots`.
//! Exit codes: 0 when every root matched, 1 on a mismatch or error, 2 on bad usage.

const std = @import("std");
const base = @import("base");
const Io = std.Io;

const replay = base.execution.db.replay_roots;
const assert = std.debug.assert;

const usage = "usage: replay-roots DIR [BLOCK]\n";
const file_bytes_max = 256 << 20;
const blocks_max = 4096;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3) {
        std.debug.print("{s}", .{usage});
        std.process.exit(2);
    }
    const block: ?u64 = if (args.len == 3)
        std.fmt.parseInt(u64, args[2], 10) catch {
            std.debug.print("{s}", .{usage});
            std.process.exit(2);
        }
    else
        null;
    const failed = run(init, args[1], block) catch |err| {
        std.debug.print("replay-roots: {t}\n", .{err});
        std.process.exit(1);
    };
    if (failed) std.process.exit(1);
}

fn run(init: std.process.Init, path: []const u8, only: ?u64) !bool {
    const gpa = init.gpa;
    var buffer: [16 * 1024]u8 = undefined;
    var stdout = Io.File.stdout().writer(init.io, &buffer);
    const out = &stdout.interface;
    var dir = try Io.Dir.cwd().openDir(init.io, path, .{ .iterate = only == null });
    defer dir.close(init.io);

    var blocks: [blocks_max]u64 = undefined;
    var count: usize = 0;
    if (only) |number| {
        blocks[0] = number;
        count = 1;
    } else {
        count = try list_blocks(init.io, dir, &blocks);
        std.mem.sort(u64, blocks[0..count], {}, std.sort.asc(u64));
    }
    var checker = try replay.Checker.init(gpa);
    defer checker.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const limit: Io.Limit = .limited(file_bytes_max);
    const headers_text = try dir.readFileAlloc(init.io, "headers.json", gpa, limit);
    defer gpa.free(headers_text);

    const context: Context = .{ .io = init.io, .dir = dir, .checker = &checker, .out = out };
    var failed = false;
    for (blocks[0..count]) |number| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        const headers = try std.json.parseFromSliceLeaky(std.json.Value, arena, headers_text, .{});
        const block_failed = check_block(&context, arena, headers, number) catch |err| blk: {
            try out.print("block {d}: error {t}\n", .{ number, err });
            break :blk true;
        };
        failed = failed or block_failed;
        try out.flush();
    }
    return failed;
}

const Context = struct {
    io: Io,
    dir: Io.Dir,
    checker: *replay.Checker,
    out: *Io.Writer,
};

fn list_blocks(io: Io, dir: Io.Dir, blocks: *[blocks_max]u64) !usize {
    var count: usize = 0;
    var iterator = dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const number = std.fmt.parseInt(u64, entry.name, 10) catch continue;
        if (count == blocks.len) return error.TooManyBlocks;
        blocks[count] = number;
        count += 1;
    }
    assert(count <= blocks_max);
    return count;
}

fn read_json(
    io: Io,
    dir: Io.Dir,
    arena: std.mem.Allocator,
    number: u64,
    name: []const u8,
) !std.json.Value {
    var path_buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{d}/{s}", .{ number, name });
    const text = try dir.readFileAlloc(io, path, arena, .limited(file_bytes_max));
    return std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
}

/// `proofs_<side>.json`, plus `proofs_system_<side>.json` when present: the proofs of the
/// keys the block-start system calls write (EIP-4788 beacon root, EIP-2935 block hash),
/// which per-transaction traces never name.
fn read_proofs(
    io: Io,
    dir: Io.Dir,
    arena: std.mem.Allocator,
    number: u64,
    side: []const u8,
) ![]replay.AccountProof {
    var name_buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "proofs_{s}.json", .{side});
    const proofs = try replay.parse_proofs(arena, try read_json(io, dir, arena, number, name));
    const system_name = try std.fmt.bufPrint(&name_buffer, "proofs_system_{s}.json", .{side});
    const system = read_json(io, dir, arena, number, system_name) catch |err| switch (err) {
        error.FileNotFound => return proofs,
        else => return err,
    };
    return replay.merge_proofs(arena, proofs, try replay.parse_proofs(arena, system));
}

fn check_block(
    context: *const Context,
    arena: std.mem.Allocator,
    headers: std.json.Value,
    number: u64,
) !bool {
    assert(number > 0);
    const io = context.io;
    const dir = context.dir;
    const out = context.out;
    const block = try replay.parse_block(try read_json(io, dir, arena, number, "block.json"));
    if (block.number != number) return error.WrongBlock;
    const parent_root = try replay.header_state_root(headers, number - 1) orelse
        return error.MissingParentHeader;
    const input: replay.StateInput = .{
        .parent_number = number - 1,
        .parent_hash = block.parent_hash,
        .parent_root = parent_root,
        .post_root = block.state_root,
        .pre = try read_proofs(io, dir, arena, number, "pre"),
        .post = try read_proofs(io, dir, arena, number, "post"),
    };
    const replays = try context.checker.check(input);
    const verdict = replays.verdict();
    try out.print("block {d}: accounts {d} (changed {d}), slots changed {d}\n", .{
        number, input.post.len, verdict.accounts_changed, verdict.slots_changed,
    });
    for (replays.slice()) |*report| try print_state(out, report);
    var failed = verdict.status != .ok;

    const receipts_json = try read_json(io, dir, arena, number, "receipts.json");
    const receipts = try replay.receipts_root(arena, receipts_json);
    failed = try print_root(out, "receipts", receipts, block.receipts_root) or failed;
    const transactions = try replay.transactions_root(arena, block.transactions);
    failed = try print_root(out, "transactions", transactions, block.transactions_root) or failed;
    return failed;
}

fn print_state(out: *Io.Writer, report: *const replay.StateReport) !void {
    const label = "state";
    const seed = switch (report.seed) {
        .pre => "pre proofs",
        .pre_and_post => "pre+post proofs",
        .derived => "pre+post+derived",
    };
    switch (report.status) {
        .ok => try out.print("  {s}: OK ({s}) root {x}\n", .{ label, seed, &report.root }),
        .incomplete => {
            try out.print("  {s}: INCOMPLETE ({s})", .{ label, seed });
            if (report.missing_node) |hash| try out.print(" missing node {x}", .{&hash});
            try out.writeAll("\n");
        },
        .invalid_proof => {
            const failure = report.failure.?;
            const set = if (report.failure_post) "post" else "pre";
            try out.print("  {s}: INVALID {s} proof for {x}", .{ label, set, &failure.address });
            if (failure.slot) |slot| try out.print(" slot {x}", .{slot});
            try out.writeAll("\n");
        },
        .mismatch => {
            const mismatch = report.mismatch.?;
            try out.print("  {s}: MISMATCH ({s}) {t} {x} expected {x} got {x}", .{
                label, seed, mismatch.kind, &mismatch.address, &mismatch.expected, &mismatch.actual,
            });
            if (mismatch.slot) |slot| try out.print(" first slot {x}", .{slot});
            try out.writeAll("\n");
        },
    }
}

fn print_root(out: *Io.Writer, label: []const u8, actual: [32]u8, expected: [32]u8) !bool {
    if (std.mem.eql(u8, &actual, &expected)) {
        try out.print("  {s}: OK {x}\n", .{ label, &actual });
        return false;
    }
    try out.print("  {s}: MISMATCH expected {x} got {x}\n", .{ label, &expected, &actual });
    return true;
}

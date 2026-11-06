//! `zig build txcheck -- <block-dir>...`
//!
//! Runs each transaction of real Base blocks alone on its `prestateTracer` pre-state and
//! compares status, gas used, and logs with the canonical receipts (see `tx_check.zig`).
//! Block directories hold `block.json`, `prestate.json`, and `receipts.json`; a sibling
//! `headers.json` supplies BLOCKHASH answers. Exits
//! non-zero on any mismatch.

const std = @import("std");
const base = @import("base");
const evm = base.execution.evm;
const tx_check = evm.tx_check;
const chainspec = base.execution.chainspec;
const node = base.execution.node;
const Io = std.Io;

const Context = struct { block: []const u8 = "" };

fn report(context_opaque: *anyopaque, mismatch: tx_check.Mismatch) void {
    const context: *Context = @ptrCast(@alignCast(context_opaque));
    std.debug.print("FAIL block {s} tx {d} {s}: {s} expected={d} actual={d}\n", .{
        context.block,
        mismatch.index,
        mismatch.hash,
        mismatch.reason,
        mismatch.expected,
        mismatch.actual,
    });
}

fn read_json(io: Io, arena: std.mem.Allocator, dir: Io.Dir, name: []const u8) !std.json.Value {
    const bytes = try dir.readFileAlloc(io, name, arena, .limited(512 << 20));
    return std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{});
}

/// The fetcher's `headers.json` beside the block directories, when present.
fn read_headers(io: Io, arena: std.mem.Allocator, dir: Io.Dir) ?std.json.Value {
    return unwrap(read_json(io, arena, dir, "../headers.json") catch return null);
}

fn unwrap(value: std.json.Value) std.json.Value {
    if (value == .object) {
        if (value.object.get("result")) |result| return result;
    }
    return value;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: txcheck <block-dir>...\n", .{});
        return 2;
    }
    const spec = chainspec.ChainSpec.presets.base_mainnet;
    var database = evm.MemoryDatabase.init(gpa);
    defer database.deinit();
    var state = try evm.State.init(gpa, database.interface(), .{});
    defer state.deinit(gpa);
    var machine = try evm.Evm.init(gpa, .{ .chain_id = spec.chain_id }, &state);
    defer machine.deinit(gpa);
    var context = Context{};
    const checker = tx_check.Checker{
        .state = &state,
        .evm = &machine,
        .report = report,
        .report_context = &context,
    };
    var total = tx_check.Summary{};
    for (args[1..]) |path| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var dir = try Io.Dir.cwd().openDir(io, path, .{});
        defer dir.close(io);
        const block = tx_check.Block{
            .block = unwrap(try read_json(io, arena, dir, "block.json")),
            .prestate = unwrap(try read_json(io, arena, dir, "prestate.json")),
            .receipts = unwrap(try read_json(io, arena, dir, "receipts.json")),
        };
        context.block = std.fs.path.basename(path);
        const timestamp = try tx_check.block_timestamp(block.block);
        const chain = tx_check.Chain{
            .fork = node.executor.evm_fork(spec.spec_at(timestamp)),
            .op = node.executor_op.context(&spec, timestamp),
            .chain_id = spec.chain_id,
            .headers = read_headers(io, arena, dir),
        };
        const summary = try tx_check.check_block(&checker, arena, block, chain);
        total.transactions += summary.transactions;
        total.passed += summary.passed;
    }
    std.debug.print("txcheck: passed={d} total={d}\n", .{ total.passed, total.transactions });
    return if (total.passed == total.transactions) 0 else 1;
}

//! `fuzz_coverage` (a `-Ddiff-coverage` build only): per-request edge coverage for a
//! coverage-guided JSON-RPC fuzzer. The result is `{"counters": n, "hits": [[index, count],
//! ...]}`: every kept edge counter (`evm.coverage_edges`) that is nonzero since the previous
//! call or process start, by ascending index, with its raw 8-bit count. The call then zeroes
//! every counter. An index is the counter's position among the kept ones, stable for one
//! binary. Counters are process-global and not atomic: the fuzzer serializes requests.
//!
//! Kept counters lie in functions whose names start with one of the prefixes, by default
//! `default_prefixes`, or the comma-separated list in `BASE_RPC_COVERAGE_PREFIXES`.
//! Without the build flag the method does not exist (-32601) and nothing here is compiled.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const evm = @import("../evm/root.zig");
const Api = @import("eth.zig").Api;

pub const enabled = evm.coverage.enabled;

/// The code that answers JSON-RPC requests: HTTP and JSON-RPC parsing, JSON, every RPC
/// handler and tracer, the block store lookups, RLP and consensus types, the EVM and
/// precompiles. Leaves out p2p, the Engine API, block import, the database, and logging.
pub const default_prefixes = "utilities.http.,utilities.rpc.,utilities.json.,execution.rpc.," ++
    "execution.node.block_store.,common.rlp.,common.consensus.,execution.evm.,common.crypto.";
pub const prefixes_variable = "BASE_RPC_COVERAGE_PREFIXES";

const prefixes_max = 64;

/// Indices into the edge counters, ascending (set once by `init`).
var kept: []const u32 = &.{};

pub const methods = if (enabled) [_]rpc.Method(*Api){
    .{ .name = "fuzz_coverage", .handler = report },
} else [_]rpc.Method(*Api){};

/// Selects the kept counters from this executable's ELF bytes (once, at startup).
pub fn init(allocator: std.mem.Allocator, elf_bytes: []const u8, prefixes_text: []const u8) !u32 {
    comptime assert(enabled);
    assert(kept.len == 0);
    var prefixes: [prefixes_max][]const u8 = undefined;
    var count: u32 = 0;
    var parts = std.mem.tokenizeScalar(u8, prefixes_text, ',');
    while (parts.next()) |part| {
        const prefix = std.mem.trim(u8, part, " ");
        if (prefix.len == 0) continue;
        if (count == prefixes_max) return error.TooManyPrefixes;
        prefixes[count] = prefix;
        count += 1;
    }
    if (count == 0) return error.NoPrefixes;
    const pcs = evm.coverage.edge_pcs();
    assert(pcs.len == evm.coverage.edge_counters().len);
    kept = try evm.coverage_edges.edge_filter(allocator, elf_bytes, pcs, prefixes[0..count]);
    return @intCast(kept.len);
}

pub fn deinit(allocator: std.mem.Allocator) void {
    comptime assert(enabled);
    allocator.free(kept);
    kept = &.{};
}

/// Snapshots the hits into scratch, zeroes every counter, then writes the snapshot: the
/// counters this call's own writing hits land in the next reading, as the same set each time.
fn report(api: *Api, call: *Call) rpc.HandlerError!void {
    comptime assert(enabled);
    try call.params.finish();
    const counters = evm.coverage.edge_counters();
    const pairs_max = api.scratch.len / @sizeOf([2]u32);
    if (kept.len > pairs_max) return call.fail(rpc.code.server_error, "scratch too small");
    const pairs: [*][2]u32 = @ptrCast(@alignCast(api.scratch.ptr));
    var hits: usize = 0;
    for (kept, 0..) |counter, index| {
        const count = counters[counter];
        if (count == 0) continue;
        pairs[hits] = .{ @intCast(index), count };
        hits += 1;
    }
    @memset(counters, 0);
    const w = call.writer;
    try w.begin_object();
    try w.key("counters");
    try w.integer(kept.len);
    try w.key("hits");
    try w.begin_array();
    for (pairs[0..hits]) |pair| {
        try w.begin_array();
        try w.integer(pair[0]);
        try w.integer(pair[1]);
        try w.end_array();
    }
    try w.end_array();
    try w.end_object();
}

const Call = rpc.Call;

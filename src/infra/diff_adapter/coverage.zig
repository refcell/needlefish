//! Coverage for coverage-guided fuzzing (`BASE_DIFF_COVERAGE`, needs a `-Ddiff-coverage`
//! build): each response gets `"coverage": {"nf:<feature>": count, ...}`, which the harness
//! does not compare. Features are needlefish's semantic features (`evm.coverage`) and its
//! edges, `nf:edge:<index>`: the compiler's 8-bit counters (`-ffuzz`) whose code lies in an
//! EVM or crypto function (`edge_filter`), hit counts modulo 256, reset per request. Edge
//! indices are stable for one binary only.
//!
//! `trie` mode reports only edges (`write_trie`), from its own function list
//! (`trie_function_prefixes`): the trie, the state database and the storage engine. Its
//! databases run on the calling thread (no rehash workers, a blocking file backend), so
//! the counters do not depend on threads or on completion timing.

const std = @import("std");
const assert = std.debug.assert;

const evm = @import("../../execution/evm/root.zig");

/// Functions whose edges are reported: the EVM (interpreter, precompiles, native
/// precompiles, transaction processing) and the crypto behind the precompiles. Zig names a
/// function by its file's path in the `base` module.
pub const function_prefixes = [_][]const u8{ "execution.evm.", "common.crypto." };

/// `trie` mode's functions: the tries (`execution.trie`: sparse trie, `StateTrie`, hash
/// builder, proofs), the state database (`execution.db`: changesets, `State`, `DiskState`,
/// flat trees, branch records, the database facade, `SparseState`) and its storage engine
/// (`execution.db.storage`: journal, checkpoints, grid, LSM trees). Not the adapter, JSON,
/// or the request's decoding.
pub const trie_function_prefixes = [_][]const u8{
    "execution.trie.",
    "execution.db.",
    "execution.db.storage.",
};

pub const Coverage = struct {
    /// Indices into the edge counters, ascending.
    edges: []const u32,
    /// `trie` mode's indices (`trie_function_prefixes`), ascending.
    trie_edges: []const u32,
    counters: []u8,

    /// `elf_bytes` is this executable (for its symbol table). Without the instrumentation,
    /// only semantic features are reported.
    pub fn init(allocator: std.mem.Allocator, elf_bytes: []const u8) !Coverage {
        assert(evm.coverage.enabled);
        const counters = evm.coverage.edge_counters();
        const pcs = evm.coverage.edge_pcs();
        assert(counters.len == pcs.len);
        const filter = evm.coverage_edges.edge_filter;
        const edges = try filter(allocator, elf_bytes, pcs, &function_prefixes);
        errdefer allocator.free(edges);
        const trie_edges = try filter(allocator, elf_bytes, pcs, &trie_function_prefixes);
        evm.coverage.active = true;
        return .{ .edges = edges, .trie_edges = trie_edges, .counters = counters };
    }

    pub fn deinit(coverage: *Coverage, allocator: std.mem.Allocator) void {
        allocator.free(coverage.trie_edges);
        allocator.free(coverage.edges);
        evm.coverage.active = false;
        coverage.* = undefined;
    }

    /// Clears every feature before a request.
    pub fn begin(coverage: *const Coverage) void {
        assert(evm.coverage.active);
        evm.coverage.reset();
        @memset(coverage.counters, 0);
    }

    /// `,"coverage":{...}`
    pub fn write(coverage: *const Coverage, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try out.writeAll(",\"coverage\":{");
        var first = try evm.coverage.write_members(out, true);
        for (coverage.edges) |index| {
            const count = coverage.counters[index];
            if (count == 0) continue;
            try evm.coverage.separator(out, &first);
            try out.print("\"nf:edge:{d}\":{d}", .{ index, count });
        }
        try out.writeAll("}");
    }

    /// `,"coverage":{...}` of a `trie` request: its edges only, hit counts modulo 256.
    pub fn write_trie(coverage: *const Coverage, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try out.writeAll(",\"coverage\":{");
        var first = true;
        for (coverage.trie_edges) |index| {
            const count = coverage.counters[index];
            if (count == 0) continue;
            try evm.coverage.separator(out, &first);
            try out.print("\"nf:edge:{d}\":{d}", .{ index, count });
        }
        try out.writeAll("}");
        assert(coverage.trie_edges.len <= coverage.counters.len);
    }
};

//! Trie node preimages fetched from the preimage oracle. Port of the `TrieProvider`
//! implementations in base/base `crates/proof/proof/src/{l1,l2}/chain_provider.rs`
//! (`trie_node_by_hash` asks the oracle for `PreimageKey::Keccak256(hash)`).
//!
//! Fetched preimages are verified against their hash, copied into a fixed arena and
//! indexed by hash, so a node is fetched once and its bytes stay valid until `reset`
//! (`execution/trie/sparse.zig` keeps slices into preimages it decoded). Plug it into a
//! `SparseTrie` through `resolver()`; a failed fetch resolves to null, which the sparse
//! trie reports as `error.WitnessIncomplete`, and the cause stays in `last_error`.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../../execution/trie/root.zig");
const preimage = @import("../preimage/root.zig");
const Hash = trie.Hash;

pub const Error = preimage.oracle.ReadError || error{
    /// The oracle answered with bytes whose keccak256 is not the requested hash.
    PreimageMismatch,
    /// The arena or the index is full.
    ResolverFull,
};

pub const Options = struct {
    bytes_max: u32,
    entries_max: u32,
};

const Entry = struct {
    hash: Hash = undefined,
    offset: u32 = 0,
    len: u32 = 0,
    used: bool = false,
};

pub const OracleResolver = struct {
    reader: preimage.OracleReader,
    arena: []u8,
    arena_used: u32 = 0,
    /// Open addressing, linear probing, capacity a power of two above `2 * entries_max`.
    table: []Entry,
    entries_max: u32,
    count: u32 = 0,
    last_error: ?Error = null,

    pub fn init(
        allocator: std.mem.Allocator,
        reader: preimage.OracleReader,
        options: Options,
    ) !OracleResolver {
        assert(options.bytes_max > 0);
        assert(options.entries_max > 0 and options.entries_max < (1 << 30));
        const capacity = std.math.ceilPowerOfTwoAssert(u32, options.entries_max * 2);
        const arena = try allocator.alloc(u8, options.bytes_max);
        errdefer allocator.free(arena);
        const table = try allocator.alloc(Entry, capacity);
        @memset(table, .{});
        return .{
            .reader = reader,
            .arena = arena,
            .table = table,
            .entries_max = options.entries_max,
        };
    }

    pub fn deinit(self: *OracleResolver, allocator: std.mem.Allocator) void {
        allocator.free(self.arena);
        allocator.free(self.table);
        self.* = undefined;
    }

    /// Forgets every cached preimage. Slices returned earlier become invalid.
    pub fn reset(self: *OracleResolver) void {
        @memset(self.table, .{});
        self.arena_used = 0;
        self.count = 0;
        self.last_error = null;
    }

    fn slot(self: *const OracleResolver, hash: *const Hash) u32 {
        const mask: u32 = @intCast(self.table.len - 1);
        var index: u32 = std.mem.readInt(u32, hash[0..4], .little) & mask;
        var probes: u32 = 0;
        while (probes < self.table.len) : (probes += 1) {
            const entry = &self.table[index];
            if (!entry.used or std.mem.eql(u8, &entry.hash, hash)) return index;
            index = (index + 1) & mask;
        }
        unreachable; // count <= entries_max < table.len, so a free slot always exists.
    }

    /// The preimage of `hash`, from the cache or the oracle.
    pub fn get(self: *OracleResolver, hash: *const Hash) Error![]const u8 {
        const index = self.slot(hash);
        const entry = &self.table[index];
        if (entry.used) return self.arena[entry.offset..][0..entry.len];
        if (self.count == self.entries_max) return error.ResolverFull;
        const free = self.arena[self.arena_used..];
        const bytes = self.reader.get(.keccak256(hash.*), free) catch |err| switch (err) {
            error.BufferTooSmall => return error.ResolverFull,
            else => return err,
        };
        if (!std.mem.eql(u8, &trie.node.keccak256(bytes), hash)) return error.PreimageMismatch;
        entry.* = .{
            .hash = hash.*,
            .offset = self.arena_used,
            .len = @intCast(bytes.len),
            .used = true,
        };
        self.arena_used += @intCast(bytes.len);
        self.count += 1;
        assert(self.arena_used <= self.arena.len);
        assert(self.count <= self.entries_max);
        return bytes;
    }

    fn resolve(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *OracleResolver = @ptrCast(@alignCast(context));
        return self.get(hash) catch |err| {
            self.last_error = err;
            return null;
        };
    }

    pub fn resolver(self: *OracleResolver) trie.sparse.Resolver {
        return .{ .context = self, .resolve = resolve };
    }
};

//! State the stateless executor fetches on demand through the preimage oracle. Port of
//! the `TrieDBProvider` / `TrieProvider` half of base/base
//! `crates/proof/proof/src/l2/chain_provider.rs` and `TrieDB::block_hash` in
//! `crates/proof/executor/src/db/mod.rs`.
//!
//! - trie nodes: `keccak256` preimages (no hint; the payload witness hint prefetches them),
//! - bytecode: hint `l2-code <hash>`, then the `keccak256` preimage,
//! - block hashes: walk parent hashes from the parent header, one `l2-block-header` hint
//!   and header preimage per step, at most `block_hash_history` steps.
//!
//! Plugs into `execution/db/witness.zig` `SparseState` through `fallback()`. Every
//! preimage lands in the `OracleResolver` arena, so returned slices stay valid until it
//! is reset.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const witness = @import("../../execution/db/witness.zig");

const Hash = [32]u8;
const OracleResolver = mpt.OracleResolver;

/// BLOCKHASH reaches back 256 blocks.
pub const block_hash_history: u64 = 256;

pub const Error = mpt.oracle_resolver.Error || error{InvalidHeader};

pub const OracleFallback = struct {
    resolver: *OracleResolver,
    hints: preimage.HintWriter,
    /// The executed block's parent: the newest block BLOCKHASH can see.
    parent_number: u64,
    parent_hash: Hash,
    /// Hashes found by the walk so far, `walked[i]` = hash of `parent_number - i`.
    walked: [block_hash_history]Hash = undefined,
    walked_len: u32 = 0,
    last_error: ?Error = null,

    pub fn init(
        resolver: *OracleResolver,
        hints: preimage.HintWriter,
        parent_number: u64,
        parent_hash: Hash,
    ) OracleFallback {
        var result: OracleFallback = .{
            .resolver = resolver,
            .hints = hints,
            .parent_number = parent_number,
            .parent_hash = parent_hash,
        };
        result.walked[0] = parent_hash;
        result.walked_len = 1;
        return result;
    }

    fn hint(self: *OracleFallback, type_name: []const u8, data: []const u8) Error!void {
        var text_buffer: [128]u8 = undefined;
        assert(type_name.len + 3 + data.len * 2 <= text_buffer.len);
        const text = preimage.Hint.encode(type_name, data, &text_buffer) catch unreachable;
        try self.hints.write(text);
    }

    pub fn code(self: *OracleFallback, hash: *const Hash) Error![]const u8 {
        try self.hint("l2-code", hash);
        return self.resolver.get(hash);
    }

    /// The header with hash `hash`, from the oracle.
    pub fn header(self: *OracleFallback, hash: *const Hash) Error!consensus.Header {
        try self.hint("l2-block-header", hash);
        const bytes = try self.resolver.get(hash);
        return consensus.Header.decode(bytes) catch error.InvalidHeader;
    }

    /// The hash of block `number`, or null when BLOCKHASH cannot see it.
    pub fn block_hash(self: *OracleFallback, number: u64) Error!?Hash {
        if (number > self.parent_number) return null;
        const depth = self.parent_number - number;
        if (depth >= block_hash_history) return null;
        while (self.walked_len <= depth) {
            assert(self.walked_len < block_hash_history);
            const child = try self.header(&self.walked[self.walked_len - 1]);
            if (child.number != self.parent_number - (self.walked_len - 1)) {
                return error.InvalidHeader;
            }
            self.walked[self.walked_len] = child.parent_hash.bytes;
            self.walked_len += 1;
        }
        assert(depth < self.walked_len);
        return self.walked[@intCast(depth)];
    }

    fn from(context: *anyopaque) *OracleFallback {
        return @ptrCast(@alignCast(context));
    }

    fn fallback_node(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self = from(context);
        return self.resolver.get(hash) catch |err| {
            self.last_error = err;
            return null;
        };
    }

    fn fallback_code(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self = from(context);
        return self.code(hash) catch |err| {
            self.last_error = err;
            return null;
        };
    }

    fn fallback_block_hash(context: *anyopaque, number: u64) ?Hash {
        const self = from(context);
        const found = self.block_hash(number) catch |err| {
            self.last_error = err;
            return null;
        };
        // The evm checks the 256-block window before asking; outside it is zero.
        return found orelse @splat(0);
    }

    pub fn fallback(self: *OracleFallback) witness.SparseState.Fallback {
        return .{
            .context = self,
            .node = fallback_node,
            .code = fallback_code,
            .block_hash = fallback_block_hash,
        };
    }
};

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");
const rlp = @import("../../common/rlp/root.zig");

const chain_length = 300;

/// A chain of `chain_length` headers served through the in-process oracle.
const ChainFixture = struct {
    map: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,
    arena: std.heap.ArenaAllocator,
    hashes: [chain_length]Hash = undefined,
    in_process: preimage.InProcess = undefined,
    resolver: OracleResolver = undefined,

    fn init(fixture: *ChainFixture) !void {
        fixture.* = .{ .arena = .init(testing.allocator) };
        var parent: Hash = @splat(0);
        for (&fixture.hashes, 0..) |*hash, number| {
            const header: consensus.Header = .{
                .parent_hash = .{ .bytes = parent },
                .number = number,
            };
            var buffer: [1024]u8 = undefined;
            const arena = fixture.arena.allocator();
            const encoded = try arena.dupe(u8, rlp.encode_to(&buffer, header));
            hash.* = header.hash().bytes;
            const key = preimage.Key.keccak256(hash.*);
            try fixture.map.put(testing.allocator, key.to_bytes(), encoded);
            parent = hash.*;
        }
        const fetcher: preimage.Fetcher = .{ .context = fixture, .get_preimage = get_preimage };
        try fixture.in_process.init(testing.allocator, fetcher, preimage.in_process.ignore_hints, .{
            .channel_bytes = 4096,
        });
        fixture.resolver = try .init(testing.allocator, fixture.in_process.oracle_reader(), .{
            .bytes_max = 1 << 18,
            .entries_max = 1024,
        });
    }

    fn deinit(fixture: *ChainFixture) void {
        fixture.resolver.deinit(testing.allocator);
        fixture.in_process.deinit(testing.allocator);
        fixture.map.deinit(testing.allocator);
        fixture.arena.deinit();
    }

    fn get_preimage(
        context: *anyopaque,
        key: preimage.Key,
    ) preimage.oracle.FetchError![]const u8 {
        const fixture: *ChainFixture = @ptrCast(@alignCast(context));
        return fixture.map.get(key.to_bytes()) orelse error.KeyNotFound;
    }

    fn fallback_at(fixture: *ChainFixture, parent_number: u64) OracleFallback {
        const hints = fixture.in_process.hint_writer();
        const hash = fixture.hashes[@intCast(parent_number)];
        return .init(&fixture.resolver, hints, parent_number, hash);
    }
};

test "oracle_fallback: block hashes walk the parent chain" {
    var fixture: ChainFixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var fallback = fixture.fallback_at(chain_length - 1);
    try testing.expectEqual(@as(?Hash, null), try fallback.block_hash(chain_length));
    const oldest = chain_length - block_hash_history;
    try testing.expectEqual(@as(?Hash, null), try fallback.block_hash(oldest - 1));
    for ([_]u64{ oldest, chain_length - 1, chain_length - 7 }) |number| {
        const found = (try fallback.block_hash(number)).?;
        try testing.expectEqual(fixture.hashes[@intCast(number)], found);
    }
    // Through the `SparseState` hook, outside the window is zero.
    const outside = OracleFallback.fallback_block_hash(&fallback, chain_length);
    try testing.expectEqual(@as(Hash, @splat(0)), outside);
}

test "oracle_fallback: a header with the wrong number is rejected" {
    var fixture: ChainFixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    // Claim block 10's hash is block 12's parent chain head.
    var fallback = fixture.fallback_at(10);
    fallback.parent_number = 12;
    try testing.expectError(error.InvalidHeader, fallback.block_hash(11));
}

fn fuzz_block_hash(fixture: *ChainFixture, smith: *std.testing.Smith) anyerror!void {
    const parent_number = smith.valueRangeAtMost(u64, 0, chain_length - 1);
    var fallback = fixture.fallback_at(parent_number);
    var queries: u32 = 0;
    while (queries < 16 and !smith.eos()) : (queries += 1) {
        const number = smith.valueRangeAtMost(u64, 0, chain_length + 4);
        const found = try fallback.block_hash(number);
        const visible = number <= parent_number and parent_number - number < block_hash_history;
        try testing.expectEqual(visible, found != null);
        if (found) |hash| try testing.expectEqual(fixture.hashes[@intCast(number)], hash);
    }
}

test "oracle_fallback: fuzz block hash queries" {
    var fixture: ChainFixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    try fuzz.run(&fixture, fuzz_block_hash, .{ .iterations = 64 });
}

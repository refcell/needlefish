//! Witness header ancestry tests: `SparseState` serves BLOCKHASH only from a header chain
//! that is strictly decoded, contiguous and ascending, linked by parent hash, and ends at
//! the bound parent holding the pre-state root. Any mutation of a valid chain fails unless
//! what remains is a suffix of it (fewer ancestors, the same bytes).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const witness = @import("witness.zig");
const header_chain = @import("witness_header_chain.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const HeaderChain = header_chain.HeaderChain;
const SparseState = witness.SparseState;
const Hash = witness.Hash;

const parent_number = 6;
const pre_root: Hash = @splat(0xab);

const sparse_config: SparseState.Config = .{
    .nodes_max = 4,
    .node_bytes_max = 64,
    .codes_max = 4,
    .code_bytes_max = 64,
    .headers_max = HeaderChain.count_max,
    .trie_nodes_max = 4,
    .storage_tries_max = 1,
};

/// Binds `sparse` to (`root`, `parent`), adds `headers` in order, and links them.
fn verify(
    sparse: *SparseState,
    headers: []const []const u8,
    root: Hash,
    parent: SparseState.Parent,
) witness.Error!void {
    sparse.reset(root, parent);
    for (headers) |header| try sparse.add_header(header);
    try sparse.verify_headers();
    assert(sparse.headers_verified);
}

fn expect_invalid(
    sparse: *SparseState,
    headers: []const []const u8,
    root: Hash,
    parent: SparseState.Parent,
) !void {
    try testing.expectError(error.InvalidHeaderChain, verify(sparse, headers, root, parent));
    // Nothing is served from a chain that failed.
    for (0..parent_number + 2) |number| try testing.expectEqual(null, sparse.block_hash(number));
}

test "witness header: a valid chain and its suffixes serve exactly their numbers" {
    var sparse = try SparseState.init(testing.allocator, sparse_config);
    defer sparse.deinit(testing.allocator);
    var chain: HeaderChain = .{};
    chain.build(parent_number, pre_root);
    const headers = chain.headers();
    for (0..headers.len + 1) |start| {
        try verify(&sparse, headers[start..], pre_root, chain.parent());
        for (0..parent_number + 2) |number| {
            const covered = number > start and number <= parent_number;
            const expected: ?Hash = if (covered) chain.hash(number) else null;
            try testing.expectEqual(expected, sparse.block_hash(number));
        }
        // A verified chain takes no more headers.
        try testing.expectError(error.InvalidHeaderChain, sparse.add_header(headers[0]));
    }
}

test "witness header: broken chains are rejected" {
    var sparse = try SparseState.init(testing.allocator, sparse_config);
    defer sparse.deinit(testing.allocator);
    var chain: HeaderChain = .{};
    chain.build(parent_number, pre_root);
    const h = chain.headers();
    const parent = chain.parent();

    // Gap, duplicate number, unsorted.
    try expect_invalid(&sparse, &.{ h[0], h[1], h[3], h[4], h[5] }, pre_root, parent);
    try expect_invalid(&sparse, &.{ h[0], h[1], h[1], h[2], h[3], h[4], h[5] }, pre_root, parent);
    try expect_invalid(&sparse, &.{ h[1], h[0], h[2], h[3], h[4], h[5] }, pre_root, parent);
    // Wrong tail: not the parent's hash, not the parent's number, missing the parent.
    var other = parent;
    other.hash[0] ^= 1;
    try expect_invalid(&sparse, h, pre_root, other);
    other = parent;
    other.number += 1;
    try expect_invalid(&sparse, h, pre_root, other);
    try expect_invalid(&sparse, h[0 .. h.len - 1], pre_root, parent);
    // The parent's state root is not the pre-state root.
    var root = pre_root;
    root[31] ^= 1;
    try expect_invalid(&sparse, h, root, parent);

    // Wrong parent link in the middle: header 3 re-encoded with another parent hash.
    var buffer: [header_chain.header_bytes_max]u8 = undefined;
    const forged_parent: Hash = @splat(0x33);
    const ancestor_root: Hash = @splat(3);
    const forged = header_chain.encode(&buffer, &forged_parent, &ancestor_root, 3);
    try testing.expectEqual(@as(u64, 3), try witness.header_number(forged));
    try expect_invalid(&sparse, &.{ h[0], h[1], forged, h[3], h[4], h[5] }, pre_root, parent);
}

test "witness header: link decoding is strict" {
    var buffer: [header_chain.header_bytes_max]u8 = undefined;
    const parent_hash: Hash = @splat(1);
    const state_root: Hash = @splat(2);
    const header = header_chain.encode(&buffer, &parent_hash, &state_root, 300);
    const link = try witness.header_link(header);
    try testing.expectEqual(parent_hash, link.parent_hash);
    try testing.expectEqual(state_root, link.state_root);
    try testing.expectEqual(@as(u64, 300), link.number);
    try testing.expectEqual(parent_hash, try witness.header_parent_hash(header));
    // Trailing byte, truncated, a 9-field list whose hashes are not 32-byte strings.
    var longer: [header_chain.header_bytes_max + 1]u8 = undefined;
    @memcpy(longer[0..header.len], header);
    longer[header.len] = 0;
    try testing.expectError(error.InvalidWitness, witness.header_link(longer[0 .. header.len + 1]));
    try testing.expectError(error.InvalidWitness, witness.header_link(header[0 .. header.len - 1]));
    const short: [10]u8 = .{ 0xc9, 1, 1, 1, 1, 1, 1, 1, 1, 5 };
    try testing.expectEqual(@as(u64, 5), try witness.header_number(&short));
    try testing.expectError(error.InvalidWitness, witness.header_link(&short));
    try testing.expectError(error.InvalidWitness, witness.header_parent_hash(&.{0x80}));
}

/// A mutable copy of a header chain.
const Mutable = struct {
    const item_bytes_max = header_chain.header_bytes_max + 1;

    buffers: [HeaderChain.count_max][item_bytes_max]u8 = undefined,
    lens: [HeaderChain.count_max]u32 = undefined,
    items: [HeaderChain.count_max][]const u8 = undefined,
    count: u32 = 0,

    fn copy(self: *Mutable, headers: []const []const u8) void {
        assert(headers.len <= HeaderChain.count_max);
        for (headers, 0..) |header, index| {
            @memcpy(self.buffers[index][0..header.len], header);
            self.lens[index] = @intCast(header.len);
        }
        self.count = @intCast(headers.len);
    }

    fn slices(self: *Mutable) []const []const u8 {
        for (0..self.count) |index| self.items[index] = self.buffers[index][0..self.lens[index]];
        return self.items[0..self.count];
    }

    /// One mutation chosen by `op`, at positions from `a` and `b`.
    fn mutate(self: *Mutable, op: u8, a: u8, b: u8) void {
        if (self.count == 0) return;
        const index = a % self.count;
        const other = b % self.count;
        const len = self.lens[index];
        switch (op % 6) {
            0 => self.buffers[index][b % len] ^= @as(u8, 1) << @intCast(a % 8),
            1 => self.buffers[index][a % len] = b,
            2 => self.remove(index),
            3 => if (self.count < HeaderChain.count_max) {
                self.buffers[self.count] = self.buffers[index];
                self.lens[self.count] = len;
                self.count += 1;
                self.swap(other, self.count - 1);
            },
            4 => self.swap(index, other),
            else => if (b % 2 == 0 and len > 1) {
                self.lens[index] = len - 1;
            } else if (len < item_bytes_max) {
                self.buffers[index][len] = a;
                self.lens[index] = len + 1;
            },
        }
    }

    fn remove(self: *Mutable, index: u32) void {
        assert(index < self.count);
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) self.swap(cursor, cursor + 1);
        self.count -= 1;
    }

    fn swap(self: *Mutable, a: u32, b: u32) void {
        std.mem.swap([item_bytes_max]u8, &self.buffers[a], &self.buffers[b]);
        std.mem.swap(u32, &self.lens[a], &self.lens[b]);
    }
};

fn is_suffix(candidate: []const []const u8, valid: []const []const u8) bool {
    if (candidate.len > valid.len) return false;
    const tail = valid[valid.len - candidate.len ..];
    for (candidate, tail) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

/// Mutates a valid chain by `script` (three bytes per mutation, at most 4): if the result
/// still verifies, it is a suffix of the valid chain and serves the valid hashes.
fn check_script(sparse: *SparseState, chain: *const HeaderChain, script: []const u8) !void {
    var mutable: Mutable = .{};
    const valid = chain.headers();
    mutable.copy(valid);
    var offset: usize = 0;
    var mutations: u32 = 0;
    while (offset + 3 <= script.len and mutations < 4) : (mutations += 1) {
        mutable.mutate(script[offset], script[offset + 1], script[offset + 2]);
        offset += 3;
    }
    const headers = mutable.slices();
    for (headers) |header| {
        // Whatever decodes as a link agrees with the number decoder.
        const link = witness.header_link(header) catch continue;
        try testing.expectEqual(link.number, try witness.header_number(header));
    }
    verify(sparse, headers, pre_root, chain.parent()) catch |err| {
        try testing.expect(err == error.InvalidHeaderChain or err == error.InvalidWitness);
        return;
    };
    try testing.expect(is_suffix(headers, valid));
    for (1..parent_number + 1) |number| {
        const served = sparse.block_hash(number) orelse continue;
        try testing.expectEqual(chain.hash(number), served);
    }
}

test "witness header: seeded mutations of a valid chain never verify a forgery" {
    var sparse = try SparseState.init(testing.allocator, sparse_config);
    defer sparse.deinit(testing.allocator);
    var chain: HeaderChain = .{};
    chain.build(parent_number, pre_root);
    var prng = Prng.init(0x4ead_c4a1);
    var script: [12]u8 = undefined;
    for (0..1000) |_| {
        prng.fill(&script);
        try check_script(&sparse, &chain, script[0 .. 3 * prng.range(1, 4)]);
    }
}

fn fuzz_header_chain(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var sparse = try SparseState.init(testing.allocator, sparse_config);
    defer sparse.deinit(testing.allocator);
    var chain: HeaderChain = .{};
    chain.build(parent_number, pre_root);
    var script: [12]u8 = undefined;
    const size = smith.slice(&script);
    try check_script(&sparse, &chain, script[0..size]);
}

test "witness header: fuzz chain mutations" {
    try std.testing.fuzz({}, fuzz_header_chain, .{});
}

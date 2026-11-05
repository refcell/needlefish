//! Reads one 32-byte key (a hashed address or storage slot) under a state or storage trie
//! root through a node resolver: the `TrieNode::open` read path of base/base
//! `crates/proof/mpt` used by EIP-2935 history lookups. Bounded: a 64-nibble key crosses
//! at most 64 branches and as many extensions, then a leaf.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../../execution/trie/root.zig");
const node = @import("node.zig");
const Hash = trie.Hash;
const RlpNode = trie.RlpNode;
const Nibbles = trie.Nibbles;
const Resolver = trie.sparse.Resolver;

pub const Error = error{
    /// A node on the path has no preimage.
    WitnessIncomplete,
    /// A node does not decode, or the path is longer than the key.
    InvalidNode,
};

const key_nibbles = 64;
const steps_max = 2 * key_nibbles + 1;

/// The value at `key` under `root`, or null when the key is absent. The value points into
/// resolver-owned memory or into `scratch` (the last embedded node), so it lives until the
/// next call with the same `scratch` or the resolver's reset.
pub fn get(
    resolver: Resolver,
    root: Hash,
    key: *const [32]u8,
    scratch: *RlpNode,
) Error!?[]const u8 {
    if (std.mem.eql(u8, &root, &trie.empty_root)) return null;
    const path = Nibbles.from_bytes(key);
    assert(path.len == key_nibbles);
    var reference = RlpNode.from_hash(root);
    var depth: u32 = 0;
    var steps: u32 = 0;
    while (steps < steps_max) : (steps += 1) {
        scratch.* = reference;
        const bytes = if (scratch.is_hash()) bytes: {
            const hash: Hash = scratch.bytes[1..33].*;
            break :bytes resolver.resolve(resolver.context, &hash) orelse
                return error.WitnessIncomplete;
        } else scratch.slice();
        const decoded = node.decode(bytes) catch return error.InvalidNode;
        if (depth + decoded.path.len > key_nibbles) return error.InvalidNode;
        const rest = path.data[depth..key_nibbles];
        const prefix = decoded.path.data[0..decoded.path.len];
        const matches = std.mem.eql(u8, prefix, rest[0..decoded.path.len]);
        switch (decoded.kind) {
            .leaf => {
                if (!matches or depth + decoded.path.len != key_nibbles) return null;
                return decoded.value;
            },
            .extension => {
                if (!matches) return null;
                depth += decoded.path.len;
                reference = decoded.children[0];
            },
            .branch => {
                if (depth == key_nibbles) return error.InvalidNode;
                reference = decoded.children[path.data[depth]];
                if (reference.len == 0) return null;
                depth += 1;
            },
        }
        assert(depth <= key_nibbles);
    }
    return error.InvalidNode;
}

const testing = std.testing;
const test_oracle = @import("../test_oracle.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const preimage = @import("../preimage/root.zig");

const KeyTrie = trie.TrieType(.{ .key_bytes_max = 32, .value_size_max = 128 });

const MapResolver = struct {
    store: *test_oracle.MapStore,

    fn resolve(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *MapResolver = @ptrCast(@alignCast(context));
        return self.store.map.get(preimage.Key.keccak256(hash.*).to_bytes());
    }
};

test "mpt key reader: present, absent and incomplete keys" {
    var prng = Prng.init(0x2935);
    for ([_]u32{ 1, 2, 3, 17, 200 }) |count| {
        var store: test_oracle.MapStore = .init();
        defer store.deinit();
        var full = try KeyTrie.init(testing.allocator, 4 * count + 16);
        defer full.deinit(testing.allocator);
        try full.track_changes(testing.allocator);
        var keys: [200][32]u8 = undefined;
        var values: [200][40]u8 = undefined;
        for (keys[0..count], values[0..count]) |*key, *value| {
            prng.fill(key);
            prng.fill(value);
            try full.put(key, value);
        }
        const root = full.root_hash();
        try full.visit_nodes(full.root, .all, test_oracle.MapStore.Collect{ .store = &store });
        var map_resolver: MapResolver = .{ .store = &store };
        const resolver: Resolver = .{ .context = &map_resolver, .resolve = MapResolver.resolve };
        var scratch: RlpNode = .{};
        for (keys[0..count], values[0..count]) |*key, *value| {
            const found = (try get(resolver, root, key, &scratch)).?;
            try testing.expectEqualSlices(u8, value, found);
        }
        var absent: [32]u8 = undefined;
        prng.fill(&absent);
        const missing = try get(resolver, root, &absent, &scratch);
        try testing.expectEqual(@as(?[]const u8, null), missing);
        var wrong = root;
        wrong[31] ^= 1;
        try testing.expectError(error.WitnessIncomplete, get(resolver, wrong, &keys[0], &scratch));
    }
    var scratch: RlpNode = .{};
    const none: Resolver = .{ .context = undefined, .resolve = undefined };
    const key: [32]u8 = @splat(1);
    const empty = try get(none, trie.empty_root, &key, &scratch);
    try testing.expectEqual(@as(?[]const u8, null), empty);
}

const RandomResolver = struct {
    bytes: [200]u8,
    len: usize,

    fn resolve(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *RandomResolver = @ptrCast(@alignCast(context));
        if (hash[0] == 0) return null;
        return self.bytes[0..self.len];
    }
};

test "mpt key reader: fuzz malformed nodes never escape the bounds" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var random: RandomResolver = .{ .bytes = undefined, .len = smith.index(200) };
            smith.bytes(random.bytes[0..random.len]);
            const resolver: Resolver = .{ .context = &random, .resolve = RandomResolver.resolve };
            var root: Hash = undefined;
            smith.bytes(&root);
            var key: [32]u8 = undefined;
            smith.bytes(&key);
            var scratch: RlpNode = .{};
            const value = get(resolver, root, &key, &scratch) catch return;
            if (value) |found| try testing.expect(found.len <= random.len);
        }
    }.one, .{ .iterations = 3000 });
}

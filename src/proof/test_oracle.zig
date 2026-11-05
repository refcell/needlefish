//! Test helpers for the proof lane: a preimage store keyed by rendered oracle keys and
//! tries built with `execution/trie` whose nodes are served as keccak preimages.

const std = @import("std");
const testing = std.testing;

const trie = @import("../execution/trie/root.zig");
const preimage = @import("preimage/root.zig");
const Hash = trie.Hash;

/// Preimages keyed by their rendered oracle key.
pub const MapStore = struct {
    map: std.AutoHashMapUnmanaged([32]u8, []const u8) = .empty,
    arena: std.heap.ArenaAllocator,
    /// When set, preimages are served with their first byte flipped.
    tamper: bool = false,
    tamper_buffer: [4096]u8 = undefined,

    pub fn init() MapStore {
        return .{ .arena = .init(testing.allocator) };
    }

    pub fn deinit(store: *MapStore) void {
        store.map.deinit(testing.allocator);
        store.arena.deinit();
    }

    /// Stores `value` under `key`.
    pub fn put(store: *MapStore, key: preimage.Key, value: []const u8) !void {
        const copy = try store.arena.allocator().dupe(u8, value);
        try store.map.put(testing.allocator, key.to_bytes(), copy);
    }

    pub fn put_node(store: *MapStore, encoding: []const u8) !void {
        const copy = try store.arena.allocator().dupe(u8, encoding);
        const key = preimage.Key.keccak256(trie.node.keccak256(copy));
        try store.map.put(testing.allocator, key.to_bytes(), copy);
    }

    pub fn get_preimage(
        context: *anyopaque,
        key: preimage.Key,
    ) preimage.oracle.FetchError![]const u8 {
        const store: *MapStore = @ptrCast(@alignCast(context));
        const value = store.map.get(key.to_bytes()) orelse return error.KeyNotFound;
        if (!store.tamper) return value;
        @memcpy(store.tamper_buffer[0..value.len], value);
        store.tamper_buffer[0] ^= 1;
        return store.tamper_buffer[0..value.len];
    }

    pub fn fetcher(store: *MapStore) preimage.Fetcher {
        return .{ .context = store, .get_preimage = get_preimage };
    }

    /// Visitor for `TrieType.visit_nodes`: stores every hashed node.
    pub const Collect = struct {
        store: *MapStore,
        pub fn visit(collect: Collect, visit_info: trie.trie.Visit) !void {
            if (visit_info.encoding.len < 32 and visit_info.path.len > 0) return;
            try collect.store.put_node(visit_info.encoding);
        }
    };
};

pub const ListTrie = trie.TrieType(.{ .key_bytes_max = 9, .value_size_max = 2048 });

/// Builds the ordered trie of `items` with the full trie, stores its nodes and returns
/// the root, checked against `ordered_trie_root`.
pub fn store_list(store: *MapStore, items: []const []const u8) !Hash {
    var full = try ListTrie.init(testing.allocator, 4 * @as(u32, @intCast(items.len)) + 16);
    defer full.deinit(testing.allocator);
    try full.track_changes(testing.allocator);
    for (items, 0..) |item, index| {
        var key_buffer: [9]u8 = undefined;
        try full.put(trie.ordered.encode_index(index, &key_buffer), item);
    }
    const root = full.root_hash();
    try testing.expectEqual(trie.ordered_trie_root(items), root);
    try full.visit_nodes(full.root, .all, MapStore.Collect{ .store = store });
    return root;
}

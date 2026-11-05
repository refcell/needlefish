//! The host's preimage store. Port of base/base `crates/proof/host/src/kv/{mem,boot,mod}.rs`:
//! values keyed by the rendered 32-byte oracle key, with helpers for keccak preimages,
//! ordered list tries (every hashed node stored by its keccak) and the boot local keys.
//! Bounded by `Limits`; the host is not the guest, so it allocates within those bounds.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const program = @import("../program/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const trie = @import("../../execution/trie/root.zig");

const Hash = [32]u8;
const Allocator = std.mem.Allocator;
const LocalKey = program.boot.LocalKey;

pub const Limits = struct {
    entries_max: u32 = 1 << 20,
    bytes_max: u64 = 1 << 30,
};

pub const Error = Allocator.Error || error{ StoreFull, NodeTooLarge };

/// Largest trie node accepted from a list (a leaf with a large transaction).
pub const node_bytes_max: u32 = 1 << 20;

pub const Store = struct {
    allocator: Allocator,
    limits: Limits,
    map: std.AutoHashMapUnmanaged([32]u8, []u8) = .empty,
    bytes_used: u64 = 0,
    node_buffer: std.ArrayList(u8) = .empty,
    node_error: ?Error = null,

    pub fn init(allocator: Allocator, limits: Limits) Store {
        assert(limits.entries_max > 0 and limits.bytes_max > 0);
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(store: *Store) void {
        var values = store.map.valueIterator();
        while (values.next()) |value| store.allocator.free(value.*);
        store.map.deinit(store.allocator);
        store.node_buffer.deinit(store.allocator);
        store.* = undefined;
    }

    pub fn count(store: *const Store) u32 {
        return store.map.count();
    }

    /// Stores `value` under `key`; an existing value is kept (preimages are immutable).
    pub fn put(store: *Store, key: preimage.Key, value: []const u8) Error!void {
        const raw = key.to_bytes();
        if (store.map.contains(raw)) return;
        if (store.map.count() >= store.limits.entries_max) return error.StoreFull;
        if (store.bytes_used + value.len > store.limits.bytes_max) return error.StoreFull;
        const copy = try store.allocator.dupe(u8, value);
        errdefer store.allocator.free(copy);
        try store.map.put(store.allocator, raw, copy);
        store.bytes_used += value.len;
        assert(store.bytes_used <= store.limits.bytes_max);
    }

    pub fn get(store: *const Store, key: preimage.Key) ?[]const u8 {
        return store.map.get(key.to_bytes());
    }

    /// Stores `bytes` as the keccak preimage of its hash, which is returned.
    pub fn put_keccak(store: *Store, bytes: []const u8) Error!Hash {
        const hash = keccak.keccak256(bytes);
        try store.put(.keccak256(hash), bytes);
        return hash;
    }

    /// Stores every hashed node of the ordered trie of `items` (and the empty trie's
    /// root preimage for an empty list). Returns the root.
    pub fn put_ordered_list(store: *Store, items: []const []const u8) Error!Hash {
        if (items.len == 0) {
            const root = try store.put_keccak(&.{0x80});
            assert(std.mem.eql(u8, &root, &trie.node.empty_root));
            return root;
        }
        store.node_buffer.clearRetainingCapacity();
        store.node_error = null;
        const sink: trie.hash_builder.NodeSink = .{
            .context = store,
            .write = node_write,
            .end = node_end,
        };
        const root = trie.ordered.ordered_trie_root_with_nodes(items, sink);
        if (store.node_error) |err| return err;
        assert(store.get(.keccak256(root)) != null);
        return root;
    }

    fn node_write(context: *anyopaque, bytes: []const u8) void {
        const store: *Store = @ptrCast(@alignCast(context));
        if (store.node_error != null) return;
        if (store.node_buffer.items.len + bytes.len > node_bytes_max) {
            store.node_error = error.NodeTooLarge;
            return;
        }
        store.node_buffer.appendSlice(store.allocator, bytes) catch |err| {
            store.node_error = err;
        };
    }

    fn node_end(context: *anyopaque) void {
        const store: *Store = @ptrCast(@alignCast(context));
        defer store.node_buffer.clearRetainingCapacity();
        if (store.node_error != null) return;
        _ = store.put_keccak(store.node_buffer.items) catch |err| {
            store.node_error = err;
        };
    }

    pub fn fetcher(store: *Store) preimage.Fetcher {
        return .{ .context = store, .get_preimage = get_preimage };
    }

    fn get_preimage(context: *anyopaque, key: preimage.Key) preimage.oracle.FetchError![]const u8 {
        const store: *Store = @ptrCast(@alignCast(context));
        return store.get(key) orelse error.KeyNotFound;
    }

    /// Writes the boot local keys (base/base `kv/boot.rs`); absent optional values are
    /// served empty, as the program's boot loader expects.
    pub fn put_boot(store: *Store, boot: *const BootValues) Error!void {
        try store.put(LocalKey.l1_head.key(), &boot.l1_head);
        try store.put(LocalKey.l2_output_root.key(), &boot.agreed_l2_output_root);
        try store.put(LocalKey.l2_claim.key(), &boot.claimed_l2_output_root);
        try store.put_u64(.l2_claim_block_number, boot.claimed_l2_block_number);
        try store.put_u64(.l2_chain_id, boot.chain_id);
        try store.put(LocalKey.l2_rollup_config.key(), boot.rollup_config_json);
        try store.put(LocalKey.l1_config.key(), boot.l1_config_json);
        const proposer: []const u8 = if (boot.proposer) |*address| address else "";
        try store.put(LocalKey.proposer.key(), proposer);
        try store.put_u64(.intermediate_block_interval, boot.intermediate_block_interval);
        try store.put_optional_u64(.l1_head_number, boot.l1_head_number);
        try store.put_optional_u64(.l2_schedule_block_number, boot.schedule_block_number);
    }

    fn put_u64(store: *Store, local: LocalKey, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        try store.put(local.key(), &bytes);
    }

    fn put_optional_u64(store: *Store, local: LocalKey, value: ?u64) Error!void {
        if (value) |number| return store.put_u64(local, number);
        try store.put(local.key(), "");
    }
};

/// The program's boot inputs, as the host provides them.
pub const BootValues = struct {
    l1_head: Hash,
    agreed_l2_output_root: Hash,
    claimed_l2_output_root: Hash,
    claimed_l2_block_number: u64,
    chain_id: u64,
    rollup_config_json: []const u8,
    /// Custom L1 chains only: a geth chain config JSON object.
    l1_config_json: []const u8 = "",
    proposer: ?[20]u8 = null,
    intermediate_block_interval: u64 = 1,
    l1_head_number: ?u64 = null,
    schedule_block_number: ?u64 = null,
};

const testing = std.testing;

test "store: ordered lists store every node the walker needs" {
    var store: Store = .init(testing.allocator, .{});
    defer store.deinit();
    var values: [40][150]u8 = undefined;
    var items: [40][]const u8 = undefined;
    for (&values, &items, 0..) |*value, *item, index| {
        value.* = @splat(@intCast(index));
        item.* = value[0 .. 1 + index * 3];
    }
    const root = try store.put_ordered_list(&items);
    try testing.expectEqual(trie.ordered_trie_root(&items), root);
    try testing.expectEqual(trie.node.empty_root, try store.put_ordered_list(&.{}));
    // Walk it back through the oracle.
    var harness: preimage.InProcess = undefined;
    try harness.init(testing.allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
        .channel_bytes = 4096,
    });
    defer harness.deinit(testing.allocator);
    const mpt = @import("../mpt/root.zig");
    var resolver: mpt.OracleResolver = try .init(testing.allocator, harness.oracle_reader(), .{
        .bytes_max = 1 << 16,
        .entries_max = 256,
    });
    defer resolver.deinit(testing.allocator);
    var walked: [64][]const u8 = undefined;
    var seen: [64]bool = undefined;
    const scratch = try testing.allocator.create(mpt.list_walker.Scratch);
    defer testing.allocator.destroy(scratch);
    const found = try mpt.list_walker.walk(resolver.resolver(), root, &walked, &seen, scratch);
    try testing.expectEqual(@as(u32, items.len), found);
    for (items, walked[0..found]) |expected, actual| {
        try testing.expectEqualSlices(u8, expected, actual);
    }
}

test "store: values are immutable and bounded" {
    var store: Store = .init(testing.allocator, .{ .entries_max = 2, .bytes_max = 8 });
    defer store.deinit();
    const key: preimage.Key = .local(1);
    try store.put(key, "abc");
    try store.put(key, "zzzz");
    try testing.expectEqualStrings("abc", store.get(key).?);
    try testing.expectError(error.StoreFull, store.put(.local(2), "123456"));
    try store.put(.local(2), "12345");
    try testing.expectError(error.StoreFull, store.put(.local(3), ""));
}

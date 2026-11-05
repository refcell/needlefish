//! Oracle-backed trie tests: tries built by `execution/trie` are served node by node
//! through the in-process preimage oracle, then read (list walker) or updated (sparse
//! trie) and checked against the full trie.

const std = @import("std");
const testing = std.testing;

const trie = @import("../../execution/trie/root.zig");
const preimage = @import("../preimage/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const fuzz = @import("../../testing/fuzz.zig");
const list_walker = @import("list_walker.zig");
const oracle_resolver = @import("oracle_resolver.zig");
const OracleResolver = oracle_resolver.OracleResolver;
const ResolverError = oracle_resolver.Error;
const Hash = trie.Hash;
const test_oracle = @import("../test_oracle.zig");
const MapStore = test_oracle.MapStore;
const store_list = test_oracle.store_list;

const Fixture = struct {
    store: MapStore,
    harness: preimage.InProcess,
    resolver: OracleResolver,

    fn init(fixture: *Fixture) !void {
        fixture.store = .init();
        try fixture.harness.init(
            testing.allocator,
            fixture.store.fetcher(),
            preimage.in_process.ignore_hints,
            .{ .channel_bytes = 8192 },
        );
        fixture.resolver = try .init(testing.allocator, fixture.harness.oracle_reader(), .{
            .bytes_max = 1 << 20,
            .entries_max = 4096,
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.resolver.deinit(testing.allocator);
        fixture.harness.deinit(testing.allocator);
        fixture.store.deinit();
    }
};

fn check_list(seed: u64, count: u32, value_len_max: u32) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var prng = Prng.init(seed);
    var storage: [300][600]u8 = undefined;
    var items: [300][]const u8 = undefined;
    for (items[0..count], storage[0..count]) |*item, *bytes| {
        const len = prng.range(1, value_len_max);
        prng.fill(bytes[0..len]);
        item.* = bytes[0..len];
    }
    const root = try store_list(&fixture.store, items[0..count]);
    var values: [300][]const u8 = undefined;
    var seen: [300]bool = undefined;
    var scratch: list_walker.Scratch = .{};
    const resolver = fixture.resolver.resolver();
    const walked = try list_walker.walk(resolver, root, &values, &seen, &scratch);
    try testing.expectEqual(count, walked);
    for (items[0..count], values[0..count]) |expected, actual| {
        try testing.expectEqualSlices(u8, expected, actual);
    }
}

test "mpt: list walker reads ordered tries of every shape" {
    try check_list(1, 0, 8);
    try check_list(2, 1, 8);
    try check_list(3, 2, 2);
    for ([_]u32{ 3, 16, 17, 127, 128, 129, 200, 300 }) |count| {
        try check_list(count, count, 4);
        try check_list(count + 1000, count, 600);
    }
}

fn fuzz_list(_: void, smith: *std.testing.Smith) anyerror!void {
    const count = smith.valueRangeAtMost(u32, 0, 300);
    const value_len_max = smith.valueRangeAtMost(u32, 1, 600);
    try check_list(smith.value(u64), count, value_len_max);
}

test "mpt: fuzz list walker" {
    try fuzz.run({}, fuzz_list, .{ .iterations = 24 });
}

test "mpt: list walker reports missing and tampered nodes" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var items: [40][]const u8 = undefined;
    for (&items) |*item| item.* = "a value that is long enough to be hashed, not embedded";
    const root = try store_list(&fixture.store, &items);
    var values: [40][]const u8 = undefined;
    var seen: [40]bool = undefined;
    var scratch: list_walker.Scratch = .{};
    const resolver = fixture.resolver.resolver();
    const short = list_walker.walk(resolver, root, values[0..39], &seen, &scratch);
    try testing.expectError(error.ListTooLong, short);
    const unknown = trie.node.keccak256("unknown");
    const missing = list_walker.walk(resolver, unknown, &values, &seen, &scratch);
    try testing.expectError(error.WitnessIncomplete, missing);
    fixture.resolver.reset();
    fixture.store.tamper = true;
    const tampered = list_walker.walk(resolver, root, &values, &seen, &scratch);
    try testing.expectError(error.WitnessIncomplete, tampered);
    const last_error = fixture.resolver.last_error;
    try testing.expectEqual(@as(?ResolverError, error.PreimageMismatch), last_error);
}

const StateTrie = trie.TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });

fn random_key(prng: *Prng) [32]u8 {
    var key: [32]u8 = undefined;
    prng.fill(&key);
    // Shared prefixes force extensions, splits and collapses.
    key[0] = @intCast(prng.below(3) * 0x11);
    if (prng.chance(1, 2)) key[1] = 0;
    return key;
}

/// The sparse trie over the oracle tracks the full trie through random puts and deletes.
fn check_sparse(seed: u64, keys_count: u32, operations: u32) !void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var prng = Prng.init(seed);
    var full = try StateTrie.init(testing.allocator, 4096);
    defer full.deinit(testing.allocator);
    try full.track_changes(testing.allocator);
    var keys: [64][32]u8 = undefined;
    for (keys[0..keys_count]) |*key| {
        key.* = random_key(&prng);
        try full.put(key, &.{ 0x82, 0xab, @intCast(prng.below(256)) });
    }
    const pre_root = full.root_hash();
    try full.visit_nodes(full.root, .all, MapStore.Collect{ .store = &fixture.store });
    var sparse = try trie.SparseTrie.init(testing.allocator, 4096, fixture.resolver.resolver());
    defer sparse.deinit(testing.allocator);
    var root = try sparse.root_from_hash(pre_root);
    try testing.expectEqual(pre_root, sparse.root_hash(root));
    for (0..operations) |_| {
        const known = keys_count > 0 and prng.chance(2, 3);
        const key = if (known) keys[prng.below(keys_count)] else random_key(&prng);
        if (prng.chance(1, 3)) {
            _ = full.delete(&key);
            try sparse.delete(&root, &key);
        } else {
            const value: [2]u8 = .{ 0x81, @intCast(prng.range(0x80, 0xff)) };
            try full.put(&key, &value);
            try sparse.put(&root, &key, &value);
        }
        try testing.expectEqual(full.root_hash(), sparse.root_hash(root));
    }
    try testing.expectEqual(@as(?ResolverError, null), fixture.resolver.last_error);
}

test "mpt: sparse trie over the oracle matches the full trie" {
    try check_sparse(11, 0, 16);
    try check_sparse(12, 1, 16);
    try check_sparse(13, 64, 128);
}

fn fuzz_sparse(_: void, smith: *std.testing.Smith) anyerror!void {
    const keys_count = smith.valueRangeAtMost(u32, 0, 64);
    try check_sparse(smith.value(u64), keys_count, smith.valueRangeAtMost(u32, 1, 96));
}

test "mpt: fuzz sparse trie over the oracle" {
    try fuzz.run({}, fuzz_sparse, .{ .iterations = 24 });
}

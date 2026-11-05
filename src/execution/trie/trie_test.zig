//! Tests for the mutable trie: public ethereum/tests TrieTests vectors, differential checks
//! against the streaming `HashBuilder`, incremental-versus-fresh roots, delete, and proofs.

const std = @import("std");
const testing = std.testing;

const node = @import("node.zig");
const proof_module = @import("proof.zig");
const trie_module = @import("trie.zig");
const HashBuilder = @import("hash_builder.zig").HashBuilder;
const Nibbles = @import("nibbles.zig").Nibbles;
const Prng = @import("../../testing/prng.zig").Prng;

const Trie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 128 });

/// Decodes a vector string: `0x`-prefixed hex, else the raw bytes.
fn decode_vector_bytes(text: []const u8, out: []u8) ![]const u8 {
    if (!std.mem.startsWith(u8, text, "0x")) return text;
    return std.fmt.hexToBytes(out, text[2..]);
}

fn apply_vector_entry(
    trie: *Trie,
    secure: bool,
    key_text: []const u8,
    value: std.json.Value,
) !void {
    var key_buffer: [64]u8 = undefined;
    var value_buffer: [128]u8 = undefined;
    var key = try decode_vector_bytes(key_text, &key_buffer);
    var hashed: node.Hash = undefined;
    if (secure) {
        hashed = node.keccak256(key);
        key = &hashed;
    }
    const value_bytes: []const u8 = switch (value) {
        .null => "",
        .string => |text| try decode_vector_bytes(text, &value_buffer),
        else => return error.BadVector,
    };
    if (value_bytes.len == 0) {
        _ = trie.delete(key);
    } else {
        try trie.put(key, value_bytes);
    }
}

fn run_vector_file(json_text: []const u8, secure: bool) !u32 {
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json_text, .{});
    defer parsed.deinit();
    var trie = try Trie.init(testing.allocator, 1024);
    defer trie.deinit(testing.allocator);
    var cases: u32 = 0;
    var iterator = parsed.value.object.iterator();
    while (iterator.next()) |case| {
        trie.clear();
        const input = case.value_ptr.object.get("in").?;
        switch (input) {
            .object => |object| {
                var entries = object.iterator();
                while (entries.next()) |entry| {
                    try apply_vector_entry(&trie, secure, entry.key_ptr.*, entry.value_ptr.*);
                }
            },
            .array => |array| for (array.items) |pair| {
                const items = pair.array.items;
                try apply_vector_entry(&trie, secure, items[0].string, items[1]);
            },
            else => return error.BadVector,
        }
        var expected: node.Hash = undefined;
        const root_text = case.value_ptr.object.get("root").?.string;
        _ = try std.fmt.hexToBytes(&expected, root_text[2..]);
        try testing.expectEqual(expected, trie.root_hash());
        cases += 1;
    }
    return cases;
}

test "trie: ethereum/tests TrieTests vectors" {
    var cases: u32 = 0;
    cases += try run_vector_file(@embedFile("testdata/trieanyorder.json"), false);
    cases += try run_vector_file(@embedFile("testdata/trieanyorder_secureTrie.json"), true);
    cases += try run_vector_file(@embedFile("testdata/trietest.json"), false);
    cases += try run_vector_file(@embedFile("testdata/trietest_secureTrie.json"), true);
    cases += try run_vector_file(@embedFile("testdata/hex_encoded_securetrie_test.json"), true);
    try testing.expect(cases >= 20);
}

const Entry = struct {
    key: [32]u8,
    value: [40]u8,
    value_len: u8,

    fn less_than(_: void, a: Entry, b: Entry) bool {
        return std.mem.order(u8, &a.key, &b.key) == .lt;
    }
};

fn random_entry(prng: *Prng, key_space: u64) Entry {
    var entry: Entry = .{ .key = @splat(0), .value = undefined, .value_len = 0 };
    // A small key space forces shared prefixes, overwrites, and deep branches.
    if (key_space > 0) {
        std.mem.writeInt(u64, entry.key[0..8], prng.below(key_space), .big);
    } else {
        prng.fill(&entry.key);
    }
    entry.value_len = @intCast(prng.range(1, entry.value.len));
    prng.fill(entry.value[0..entry.value_len]);
    return entry;
}

/// Root of the deduplicated (last write wins) set via the streaming builder.
fn builder_root(entries: []Entry) node.Hash {
    std.mem.sort(Entry, entries, {}, Entry.less_than);
    var builder = HashBuilder.init();
    var index: usize = 0;
    while (index < entries.len) : (index += 1) {
        const last = index + 1 == entries.len;
        if (!last and std.mem.eql(u8, &entries[index].key, &entries[index + 1].key)) continue;
        const path = Nibbles.from_bytes(&entries[index].key);
        builder.add_leaf(path.slice(), entries[index].value[0..entries[index].value_len]);
    }
    return builder.root();
}

test "trie: seeded differential against hash builder, incremental roots, deletes" {
    var prng = Prng.init(0x7e1e);
    var trie = try Trie.init(testing.allocator, 4096);
    defer trie.deinit(testing.allocator);
    var fresh = try Trie.init(testing.allocator, 4096);
    defer fresh.deinit(testing.allocator);
    var entries: [400]Entry = undefined;
    var sorted: [400]Entry = undefined;
    var round: u32 = 0;
    while (round < 30) : (round += 1) {
        trie.clear();
        const count = prng.range(1, entries.len);
        const key_space: u64 = if (prng.chance(1, 2)) 0 else prng.range(1, 600);
        for (entries[0..count]) |*entry| {
            entry.* = random_entry(&prng, key_space);
            try trie.put(&entry.key, entry.value[0..entry.value_len]);
            if (prng.chance(1, 8)) _ = trie.root_hash(); // Interleave cached roots.
        }
        // Stable sort keeps insertion order among equal keys: the last write wins.
        @memcpy(sorted[0..count], entries[0..count]);
        try testing.expectEqual(builder_root(sorted[0..count]), trie.root_hash());
        // Delete a random subset, then compare against a trie built from the survivors.
        var kept: u32 = 0;
        for (entries[0..count]) |*entry| {
            if (prng.chance(1, 2)) {
                _ = trie.delete(&entry.key);
            } else {
                entries[kept] = entry.*;
                kept += 1;
            }
        }
        fresh.clear();
        for (entries[0..kept]) |*entry| {
            if (trie.get(&entry.key) == null) continue; // Deleted by a later duplicate key.
            try fresh.put(&entry.key, trie.get(&entry.key).?);
        }
        try testing.expectEqual(fresh.root_hash(), trie.root_hash());
        try testing.expectEqual(fresh.node_count(), trie.node_count());
    }
}

test "trie: deleting everything returns to the empty root and frees all nodes" {
    var prng = Prng.init(99);
    var trie = try Trie.init(testing.allocator, 2048);
    defer trie.deinit(testing.allocator);
    var entries: [300]Entry = undefined;
    for (&entries) |*entry| {
        entry.* = random_entry(&prng, 500);
        try trie.put(&entry.key, entry.value[0..entry.value_len]);
    }
    _ = trie.root_hash();
    for (&entries) |*entry| _ = trie.delete(&entry.key);
    try testing.expectEqual(node.empty_root, trie.root_hash());
    try testing.expectEqual(@as(u32, 0), trie.node_count());
    try testing.expect(!trie.delete(&entries[0].key));
}

fn check_proof(trie: *Trie, proof: *Trie.Proof, key: []const u8) !void {
    trie.prove(key, proof);
    var nodes: [Trie.depth_max][]const u8 = undefined;
    for (0..proof.count) |index| nodes[index] = proof.node_at(@intCast(index));
    const result = try proof_module.verify(trie.root_hash(), key, nodes[0..proof.count]);
    const expected = trie.get(key);
    if (expected) |value| {
        try testing.expectEqualSlices(u8, value, result.?);
    } else {
        try testing.expectEqual(@as(?[]const u8, null), result);
    }
    if (proof.count > 0) {
        // A proof against any other root must fail.
        var wrong = trie.root_hash();
        wrong[0] ^= 1;
        try testing.expectError(error.HashMismatch, proof_module.verify(wrong, key, nodes[0..1]));
    }
}

test "trie: seeded proofs of inclusion and exclusion verify" {
    var prng = Prng.init(0x9f00f);
    var trie = try Trie.init(testing.allocator, 4096);
    defer trie.deinit(testing.allocator);
    const proof = try testing.allocator.create(Trie.Proof);
    defer testing.allocator.destroy(proof);
    var round: u32 = 0;
    while (round < 10) : (round += 1) {
        trie.clear();
        const count = prng.range(0, 300);
        const key_space: u64 = if (prng.chance(1, 2)) 0 else 400;
        var entry: Entry = undefined;
        for (0..count) |_| {
            entry = random_entry(&prng, key_space);
            try trie.put(&entry.key, entry.value[0..entry.value_len]);
        }
        for (0..50) |_| {
            const probe = random_entry(&prng, key_space);
            try check_proof(&trie, proof, &probe.key);
        }
        if (count > 0) try check_proof(&trie, proof, &entry.key);
    }
}

test "trie: put fails cleanly when the pool is full" {
    var trie = try Trie.init(testing.allocator, 4);
    defer trie.deinit(testing.allocator);
    try trie.put("a", "1");
    try trie.put("b", "2");
    const before = trie.root_hash();
    try testing.expectError(error.TrieFull, trie.put("c", "3"));
    try testing.expectEqual(before, trie.root_hash());
}

const FuzzContext = struct {
    trie: *Trie,
    fresh: *Trie,
};

fn fuzz_operations(context: FuzzContext, smith: *testing.Smith) anyerror!void {
    const trie = context.trie;
    trie.clear();
    var keys: [64][2]u8 = undefined;
    var key_count: u32 = 0;
    while (key_count < keys.len and !smith.eosWeightedSimple(15, 1)) {
        // Two-byte keys with a tiny alphabet maximize structural collisions.
        const key = [2]u8{ smith.value(u8) & 0x31, smith.value(u8) & 0x13 };
        if (smith.value(bool)) {
            const value = [1]u8{smith.value(u8) | 1};
            try trie.put(&key, &value);
            keys[key_count] = key;
            key_count += 1;
        } else {
            _ = trie.delete(&key);
        }
        if (smith.value(bool)) _ = trie.root_hash();
    }
    context.fresh.clear();
    for (keys[0..key_count]) |*key| {
        if (trie.get(key)) |value| try context.fresh.put(key, value);
    }
    try testing.expectEqual(context.fresh.root_hash(), trie.root_hash());
}

test "trie: fuzz put, delete, and incremental root" {
    var trie = try Trie.init(testing.allocator, 512);
    defer trie.deinit(testing.allocator);
    var fresh = try Trie.init(testing.allocator, 512);
    defer fresh.deinit(testing.allocator);
    try testing.fuzz(FuzzContext{ .trie = &trie, .fresh = &fresh }, fuzz_operations, .{});
}

const TrieSerial = trie_module.TrieType(.{
    .key_bytes_max = 32,
    .value_size_max = 128,
    .hash_batched = false,
});

/// Applies one random put or delete to root `which` of both tries.
fn apply_random_operation(
    prng: *Prng,
    batched: *Trie,
    serial: *TrieSerial,
    roots_batched: []Trie.NodeIndex,
    roots_serial: []TrieSerial.NodeIndex,
    key_space: u64,
) !void {
    const which = prng.below(roots_batched.len);
    const entry = random_entry(prng, key_space);
    // Short and long values mix embedded (< 32 byte) and hashed nodes in one level.
    const value_len = if (prng.chance(1, 2)) prng.range(1, 4) else entry.value_len;
    const value = entry.value[0..value_len];
    if (prng.chance(1, 3)) {
        const removed = batched.delete_in(&roots_batched[which], &entry.key);
        try testing.expectEqual(removed, serial.delete_in(&roots_serial[which], &entry.key));
    } else {
        try batched.put_in(&roots_batched[which], &entry.key, value);
        try serial.put_in(&roots_serial[which], &entry.key, value);
    }
}

test "trie: seeded differential of batched against serial hashing, multi-root" {
    var prng = Prng.init(0xba7c4);
    var batched = try Trie.init(testing.allocator, 8192);
    defer batched.deinit(testing.allocator);
    var serial = try TrieSerial.init(testing.allocator, 8192);
    defer serial.deinit(testing.allocator);
    var round: u32 = 0;
    while (round < 40) : (round += 1) {
        batched.clear();
        serial.clear();
        var roots_batched: [5]Trie.NodeIndex = @splat(Trie.none);
        var roots_serial: [5]TrieSerial.NodeIndex = @splat(TrieSerial.none);
        const root_count = prng.range(1, roots_batched.len);
        const key_space: u64 = if (prng.chance(1, 2)) 0 else prng.range(1, 300);
        const operations = prng.range(1, 1200);
        var operation: u32 = 0;
        while (operation < operations) : (operation += 1) {
            try apply_random_operation(
                &prng,
                &batched,
                &serial,
                roots_batched[0..root_count],
                roots_serial[0..root_count],
                key_space,
            );
            if (!prng.chance(1, 64)) continue;
            // Rehash all roots in one batched pass, or one root at a time.
            if (prng.chance(1, 2)) batched.update_caches(roots_batched[0..root_count]);
            for (roots_batched[0..root_count], roots_serial[0..root_count]) |a, b| {
                try testing.expectEqual(serial.root_hash_of(b), batched.root_hash_of(a));
            }
        }
        batched.update_caches(roots_batched[0..root_count]);
        for (roots_batched[0..root_count], roots_serial[0..root_count]) |a, b| {
            try testing.expectEqual(serial.root_hash_of(b), batched.root_hash_of(a));
        }
        try testing.expectEqual(serial.node_count(), batched.node_count());
    }
}

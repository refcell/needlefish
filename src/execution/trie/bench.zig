//! Trie micro benchmarks, listed in `src/testing/bench_main.zig`.
//!
//! Large fixtures (a 100k-entry trie) are built once on first use from the page allocator;
//! that is benchmark scaffolding, not library code. One op of a `block` case applies a batch
//! of updates and computes the new root, the shape of the per-block state-root work.

const std = @import("std");
const assert = std.debug.assert;

const node = @import("node.zig");
const trie_module = @import("trie.zig");
const ordered = @import("ordered.zig");
const state = @import("state_trie.zig");
const HashBuilder = @import("hash_builder.zig").HashBuilder;
const Nibbles = @import("nibbles.zig").Nibbles;
const Prng = @import("../../testing/prng.zig").Prng;

pub const Case = struct {
    name: []const u8,
    iterations: u32,
    run: *const fn (iterations: u32) u64,
};

pub const cases = [_]Case{
    .{ .name = "trie/get 100k", .iterations = 1_000_000, .run = bench_get },
    .{ .name = "trie/block 1k puts+root on 100k", .iterations = 100, .run = bench_block },
    .{ .name = "trie/hash_builder 10k leaves", .iterations = 100, .run = bench_hash_builder },
    .{ .name = "trie/ordered root 200x200B", .iterations = 1_000, .run = bench_ordered },
    .{ .name = "trie/state block 1k accounts", .iterations = 100, .run = bench_state_block },
};

const Trie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 112 });
const fixture_entries = 100_000;

var fixture: ?Trie = null;
var fixture_prng = Prng.init(1);

fn random_key(index: u64) [32]u8 {
    var input: [8]u8 = undefined;
    std.mem.writeInt(u64, &input, index, .little);
    return node.keccak256(&input);
}

fn get_fixture() *Trie {
    if (fixture == null) {
        var trie = Trie.init(std.heap.page_allocator, fixture_entries * 4) catch {
            @panic("bench fixture: out of memory");
        };
        var value: [70]u8 = @splat(0x42);
        for (0..fixture_entries) |index| {
            const key = random_key(index);
            value[0] = @truncate(index);
            trie.put(&key, &value) catch @panic("bench fixture: trie full");
        }
        _ = trie.root_hash();
        fixture = trie;
    }
    return &fixture.?;
}

fn bench_get(iterations: u32) u64 {
    const trie = get_fixture();
    var accumulator: u64 = 0;
    for (0..iterations) |iteration| {
        const key = random_key(iteration % fixture_entries);
        accumulator +%= trie.get(&key).?[0];
    }
    return accumulator;
}

fn bench_block(iterations: u32) u64 {
    const trie = get_fixture();
    var accumulator: u64 = 0;
    var value: [70]u8 = @splat(0x17);
    for (0..iterations) |_| {
        for (0..1000) |_| {
            const key = random_key(fixture_prng.below(fixture_entries));
            value[1] = @truncate(fixture_prng.int(u8));
            trie.put(&key, &value) catch @panic("bench: trie full");
        }
        accumulator +%= trie.root_hash()[0];
    }
    return accumulator;
}

const Leaf = struct {
    key: [32]u8,

    fn less_than(_: void, a: Leaf, b: Leaf) bool {
        return std.mem.order(u8, &a.key, &b.key) == .lt;
    }
};

var sorted_leaves: ?[]Leaf = null;

fn bench_hash_builder(iterations: u32) u64 {
    if (sorted_leaves == null) {
        const leaves = std.heap.page_allocator.alloc(Leaf, 10_000) catch @panic("bench: oom");
        for (leaves, 0..) |*leaf, index| leaf.key = random_key(index);
        std.mem.sort(Leaf, leaves, {}, Leaf.less_than);
        sorted_leaves = leaves;
    }
    const builder = std.heap.page_allocator.create(HashBuilder) catch @panic("bench: oom");
    defer std.heap.page_allocator.destroy(builder);
    const value: [70]u8 = @splat(0x33);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        builder.reset();
        for (sorted_leaves.?) |*leaf| {
            builder.add_leaf(Nibbles.from_bytes(&leaf.key).slice(), &value);
        }
        accumulator +%= builder.root()[0];
    }
    return accumulator;
}

fn bench_ordered(iterations: u32) u64 {
    var storage: [200][200]u8 = undefined;
    var items: [200][]const u8 = undefined;
    for (&storage, 0..) |*item, index| {
        item.* = @splat(@truncate(index));
        items[index] = item;
    }
    var accumulator: u64 = 0;
    for (0..iterations) |iteration| {
        storage[0][0] = @truncate(iteration);
        accumulator +%= ordered.ordered_trie_root(&items)[0];
    }
    return accumulator;
}

var state_fixture: ?state.StateTrie = null;

fn bench_state_block(iterations: u32) u64 {
    if (state_fixture == null) {
        var trie = state.StateTrie.init(std.heap.page_allocator, .{
            .accounts_max = fixture_entries,
            .account_nodes_max = fixture_entries * 3,
            .storage_nodes_max = 1 << 16,
        }) catch @panic("bench: oom");
        for (0..fixture_entries) |index| {
            const account: state.Account = .{ .nonce = index, .balance = index * 1000 };
            trie.set_account(random_key(index), account) catch @panic("bench");
        }
        _ = trie.root() catch @panic("bench");
        state_fixture = trie;
    }
    const trie = &state_fixture.?;
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        for (0..1000) |_| {
            const index = fixture_prng.below(fixture_entries);
            const nonce = fixture_prng.below(1 << 20);
            const account: state.Account = .{ .nonce = nonce, .balance = index };
            trie.set_account(random_key(index), account) catch @panic("bench");
        }
        accumulator +%= (trie.root() catch @panic("bench"))[0];
    }
    return accumulator;
}

test "bench: cases are well formed" {
    for (cases) |case| {
        assert(case.name.len > 0);
        assert(case.iterations > 0);
    }
    assert(cases.len == 5);
}

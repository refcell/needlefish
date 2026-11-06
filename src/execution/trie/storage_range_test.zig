//! Differential tests for `StateTrie.storage_range` (`debug_storageRangeAt` at the head):
//! random storage with deletions against a sorted model, start keys at, between, before, and
//! after leaves, `max` of 0, 1, exact, and larger, short output buffers, and pagination
//! through `next` covering every slot exactly once. Seeded runs plus a coverage fuzz.

const std = @import("std");
const testing = std.testing;

const node = @import("node.zig");
const state = @import("state_trie.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Hash = node.Hash;

const slots_max = 192;
const out_max = 256;

const Slot = struct { key: Hash, value: u256 };

fn slot_less_than(_: void, a: Slot, b: Slot) bool {
    return std.mem.order(u8, &a.key, &b.key) == .lt;
}

/// Live slots of one account, sorted by hashed key.
const Model = struct {
    slots: [slots_max]Slot = undefined,
    count: u32 = 0,

    fn find(self: *const Model, key: *const Hash) ?u32 {
        for (self.slots[0..self.count], 0..) |*slot, index| {
            if (std.mem.eql(u8, &slot.key, key)) return @intCast(index);
        }
        return null;
    }

    fn set(self: *Model, key: Hash, value: u256) void {
        if (self.find(&key)) |index| {
            if (value != 0) {
                self.slots[index].value = value;
                return;
            }
            self.slots[index] = self.slots[self.count - 1];
            self.count -= 1;
        } else if (value != 0) {
            std.debug.assert(self.count < slots_max);
            self.slots[self.count] = .{ .key = key, .value = value };
            self.count += 1;
        }
        std.mem.sort(Slot, self.slots[0..self.count], {}, slot_less_than);
    }

    /// Index of the first slot at or after `start`.
    fn lower_bound(self: *const Model, start: *const Hash) u32 {
        var index: u32 = 0;
        while (index < self.count and
            std.mem.order(u8, &self.slots[index].key, start) == .lt) index += 1;
        return index;
    }
};

const Coverage = struct {
    empty: u32 = 0,
    truncated: u32 = 0,
    complete: u32 = 0,
    pages: u32 = 0,
};

/// A random key, often sharing a prefix (whole bytes or an odd nibble count) with a live
/// key, so the trie gets extensions and deep branches.
fn random_key(prng: *Prng, model: *const Model) Hash {
    var key: Hash = undefined;
    prng.fill(&key);
    if (model.count == 0 or prng.chance(1, 3)) return key;
    const base = model.slots[prng.below(model.count)].key;
    const nibbles = prng.range(1, 63);
    const bytes = nibbles / 2;
    @memcpy(key[0..bytes], base[0..bytes]);
    if (nibbles % 2 == 1) key[bytes] = (base[bytes] & 0xf0) | (key[bytes] & 0x0f);
    return key;
}

/// A start key: at a live key, just after one, just before one, before all, after all, or
/// random.
fn random_start(prng: *Prng, model: *const Model) Hash {
    if (model.count == 0 or prng.chance(1, 6)) {
        var key: Hash = undefined;
        prng.fill(&key);
        return key;
    }
    var key = model.slots[prng.below(model.count)].key;
    var value = std.mem.readInt(u256, &key, .big);
    switch (prng.below(5)) {
        0 => {},
        1 => value +%= 1,
        2 => value -%= 1,
        3 => value = 0,
        else => value = std.math.maxInt(u256),
    }
    std.mem.writeInt(u256, &key, value, .big);
    return key;
}

fn expect_range(
    trie: *const state.StateTrie,
    address: Hash,
    model: *const Model,
    start: *const Hash,
    max: u32,
    out: []state.StorageEntry,
    coverage: *Coverage,
) !void {
    const range = try trie.storage_range(address, start.*, max, out);
    const first = model.lower_bound(start);
    const available = model.count - first;
    const expected: u32 = @min(available, max, @as(u32, @intCast(out.len)));
    try testing.expectEqual(expected, range.count);
    for (out[0..range.count], model.slots[first..][0..range.count]) |entry, slot| {
        try testing.expectEqualSlices(u8, &slot.key, &entry.key_hash);
        try testing.expectEqual(slot.value, entry.value);
    }
    if (first + expected < model.count) {
        try testing.expect(range.next != null);
        try testing.expectEqualSlices(u8, &model.slots[first + expected].key, &range.next.?);
        coverage.truncated += 1;
    } else {
        try testing.expect(range.next == null);
        coverage.complete += 1;
    }
    if (range.count == 0) coverage.empty += 1;
}

/// Pages of `page` slots from the zero key must cover every slot exactly once, in order.
fn expect_pages(
    trie: *const state.StateTrie,
    address: Hash,
    model: *const Model,
    page: u32,
    out: []state.StorageEntry,
    coverage: *Coverage,
) !void {
    std.debug.assert(page > 0);
    var start: Hash = @splat(0);
    var seen: u32 = 0;
    var pages: u32 = 0;
    while (pages <= model.count) : (pages += 1) {
        const range = try trie.storage_range(address, start, page, out);
        for (out[0..range.count]) |entry| {
            try testing.expect(seen < model.count);
            try testing.expectEqualSlices(u8, &model.slots[seen].key, &entry.key_hash);
            try testing.expectEqual(model.slots[seen].value, entry.value);
            seen += 1;
        }
        start = range.next orelse break;
        try testing.expectEqual(page, range.count);
    } else return error.TestUnexpectedResult;
    try testing.expectEqual(model.count, seen);
    coverage.pages += 1;
}

fn check_ranges(
    prng: *Prng,
    trie: *const state.StateTrie,
    address: Hash,
    model: *const Model,
    out: []state.StorageEntry,
    coverage: *Coverage,
) !void {
    for (0..8) |_| {
        const start = random_start(prng, model);
        const exact = model.count - model.lower_bound(&start);
        const maxes = [_]u32{ 0, 1, exact, exact + 1, @intCast(prng.below(out_max + 8)) };
        for (maxes) |max| try expect_range(trie, address, model, &start, max, out, coverage);
        // A buffer shorter than `max` bounds the range too.
        const short = out[0..prng.below(4)];
        try expect_range(trie, address, model, &start, out_max, short, coverage);
    }
    const page: u32 = @intCast(prng.range(1, 9));
    try expect_pages(trie, address, model, page, out, coverage);
}

fn run_seed(seed: u64, steps: u32, coverage: *Coverage) !void {
    var prng = Prng.init(seed);
    var trie = try state.StateTrie.init(testing.allocator, .{
        .accounts_max = 4,
        .account_nodes_max = 64,
        .storage_nodes_max = 8192,
    });
    defer trie.deinit(testing.allocator);
    const address = node.keccak256("storage range account");
    const other = node.keccak256("other account");
    const empty = node.keccak256("empty account");
    try trie.set_account(address, .{ .nonce = 1 });
    try trie.set_account(other, .{ .nonce = 2 });
    try trie.set_account(empty, .{ .nonce = 3 });
    const model = try testing.allocator.create(Model);
    defer testing.allocator.destroy(model);
    model.* = .{};
    const out = try testing.allocator.alloc(state.StorageEntry, out_max);
    defer testing.allocator.free(out);
    for (0..steps) |_| {
        const writes = prng.range(1, 24);
        for (0..writes) |_| {
            const delete = model.count > 0 and prng.chance(1, 3);
            const key = if (delete)
                model.slots[prng.below(model.count)].key
            else
                random_key(&prng, model);
            if (!delete and model.count == slots_max and model.find(&key) == null) continue;
            const value: u256 = if (delete) 0 else prng.int(u256) >> @intCast(prng.below(256));
            model.set(key, value);
            try trie.set_storage(address, key, value);
            try trie.set_storage(other, random_key(&prng, model), prng.int(u64) | 1);
        }
        if (prng.chance(1, 2)) _ = try trie.root();
        try check_ranges(&prng, &trie, address, model, out, coverage);
        // An account without storage gives an empty range; an unknown one is an error.
        const zero: Hash = @splat(0);
        const none = try trie.storage_range(empty, zero, out_max, out);
        try testing.expectEqual(@as(u32, 0), none.count);
        try testing.expect(none.next == null);
        const unknown = node.keccak256("unknown account");
        try testing.expectError(error.UnknownAccount, trie.storage_range(unknown, zero, 1, out));
    }
}

test "storage range: head walk equals a sorted model with deletions and pagination" {
    var coverage: Coverage = .{};
    for (0..4) |seed| try run_seed(0x5a7e + seed, 24, &coverage);
    try testing.expect(coverage.empty > 0);
    try testing.expect(coverage.truncated > 0);
    try testing.expect(coverage.complete > 0);
    try testing.expect(coverage.pages > 0);
}

fn fuzz_storage_range(_: void, smith: *testing.Smith) anyerror!void {
    var coverage: Coverage = .{};
    const steps = smith.valueRangeAtMost(u32, 1, 12);
    try run_seed(smith.value(u64), steps, &coverage);
}

test "storage range: fuzz head walk against a sorted model" {
    try testing.fuzz({}, fuzz_storage_range, .{});
}

//! Branch records against the in-memory trie. `derive_records` walks a `StateTrie`
//! (`visit_nodes`) and rebuilds every branch record from the nodes it reports, checking that
//! each record synthesizes exactly the branch and extension encodings and the reference the
//! trie computed. The import sink tests (`import/state_root.zig`) compare their streamed
//! records with these, over the same random and edge-case states.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const branch_record = @import("branch_record.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const node = trie.node;
const Hash = node.Hash;
const RlpNode = node.RlpNode;
const Nibbles = trie.Nibbles;
const Record = branch_record.Record;
const StateTrie = trie.StateTrie;
const Account = trie.Account;

pub const Slot = struct {
    key: Hash,
    value: u256,

    fn less(_: void, a: Slot, b: Slot) bool {
        return std.mem.order(u8, &a.key, &b.key) == .lt;
    }
};

/// One account of a test state; accounts and slots sorted by key, keys unique.
pub const TestAccount = struct {
    key: Hash,
    account: Account,
    slots: []Slot,

    fn less(_: void, a: TestAccount, b: TestAccount) bool {
        return std.mem.order(u8, &a.key, &b.key) == .lt;
    }
};

/// One record: its tree key (33 bytes account trie, 65 bytes storage) and encoded value.
pub const Derived = struct {
    key: []const u8,
    value: []const u8,

    pub fn less(_: void, a: Derived, b: Derived) bool {
        return std.mem.order(u8, a.key, b.key) == .lt;
    }
};

pub const RecordSets = struct {
    accounts: std.ArrayList(Derived) = .empty,
    storage: std.ArrayList(Derived) = .empty,
};

pub const state_config: trie.state_trie.Config = .{
    .accounts_max = 64,
    .account_nodes_max = 1 << 12,
    .storage_nodes_max = 1 << 14,
};

fn set_nibble(key: *Hash, index: usize, nibble: u8) void {
    assert(index < 64 and nibble < 16);
    const byte = &key[index / 2];
    byte.* = if (index % 2 == 0) (byte.* & 0x0f) | nibble << 4 else (byte.* & 0xf0) | nibble;
}

/// A key sharing a random-length prefix of `base`: none, short, deep (the rest only 0 and
/// 0xF nibbles, so keys collide deep down), or all but the last nibble.
fn shaped_key(prng: *Prng, base: *const Hash) Hash {
    var key = base.*;
    const keep: u64 = switch (prng.below(4)) {
        0 => 0,
        1 => prng.range(1, 6),
        2 => prng.range(40, 62),
        else => 63,
    };
    for (keep..64) |index| {
        const nibble: u8 = if (keep < 40) @intCast(prng.below(16)) else if (prng.chance(1, 2))
            0
        else
            0xf;
        set_nibble(&key, index, nibble);
    }
    return key;
}

fn unique_slots(slots: []Slot) []Slot {
    std.mem.sort(Slot, slots, {}, Slot.less);
    var count: usize = 0;
    for (slots) |slot| {
        if (count > 0 and std.mem.eql(u8, &slots[count - 1].key, &slot.key)) continue;
        slots[count] = slot;
        count += 1;
    }
    return slots[0..count];
}

fn random_slots(arena: std.mem.Allocator, prng: *Prng) ![]Slot {
    const count: usize = if (prng.chance(1, 3)) 0 else if (prng.chance(1, 4)) 1 else @intCast(
        prng.range(2, 30),
    );
    const slots = try arena.alloc(Slot, count);
    var base: Hash = undefined;
    prng.fill(&base);
    for (slots) |*slot| {
        slot.key = shaped_key(prng, &base);
        // Small values make deep leaves (and branches of them) shorter than 32 bytes.
        const wide = @as(u256, prng.int(u64)) << 128 | 1;
        slot.value = if (prng.chance(3, 4)) prng.range(1, 255) else wide;
    }
    return unique_slots(slots);
}

/// A random state of at most `accounts_max` accounts, shaped for shared prefixes.
pub fn random_state(
    arena: std.mem.Allocator,
    prng: *Prng,
    accounts_max: u64,
) ![]TestAccount {
    const accounts = try arena.alloc(TestAccount, prng.range(0, accounts_max));
    var base: Hash = undefined;
    prng.fill(&base);
    if (prng.chance(1, 2)) base[0] = 0xff;
    for (accounts) |*entry| {
        var code_hash = node.empty_code_hash;
        if (prng.chance(1, 2)) prng.fill(&code_hash);
        entry.* = .{
            .key = shaped_key(prng, &base),
            .account = .{
                .nonce = prng.below(1000),
                .balance = prng.int(u64),
                .code_hash = code_hash,
            },
            .slots = try random_slots(arena, prng),
        };
    }
    std.mem.sort(TestAccount, accounts, {}, TestAccount.less);
    var count: usize = 0;
    for (accounts) |entry| {
        if (count > 0 and std.mem.eql(u8, &accounts[count - 1].key, &entry.key)) continue;
        accounts[count] = entry;
        count += 1;
    }
    return accounts[0..count];
}

pub const edge_cases = 4;

/// 0: empty. 1: one account, no storage. 2: one account, one slot. 3: two accounts and two
/// slots each sharing 63 nibbles (63-nibble root extensions, a branch at depth 63, embedded
/// leaves).
pub fn edge_state(arena: std.mem.Allocator, case: u32) ![]TestAccount {
    assert(case < edge_cases);
    const count: usize = switch (case) {
        0 => 0,
        1, 2 => 1,
        else => 2,
    };
    const accounts = try arena.alloc(TestAccount, count);
    for (accounts, 0..) |*entry, index| {
        var key: Hash = @splat(0x5f);
        key[31] = 0x50 + @as(u8, @intCast(index));
        const slots = try arena.alloc(Slot, if (case == 3) 2 else if (case == 2) 1 else 0);
        for (slots, 0..) |*slot, slot_index| {
            slot.key = @splat(0xf0);
            slot.key[31] = 0xf1 + @as(u8, @intCast(slot_index));
            slot.value = 1 + slot_index;
        }
        entry.* = .{ .key = key, .account = .{ .nonce = 1 }, .slots = slots };
    }
    return accounts;
}

pub fn load(state: *StateTrie, accounts: []const TestAccount) !void {
    for (accounts) |entry| {
        try state.set_account(entry.key, entry.account);
        for (entry.slots) |slot| try state.set_storage(entry.key, slot.key, slot.value);
    }
}

const Visited = struct {
    owner: ?Hash,
    path: []const u8,
    encoding: []const u8,
    reference: RlpNode,
    kind: trie.trie.VisitKind,
    mask: u16,
};

const Collector = struct {
    arena: std.mem.Allocator,
    nodes: *std.ArrayList(Visited),

    pub fn visit(self: Collector, info: StateTrie.NodeVisit) !void {
        assert(info.reference.len > 0 and info.reference.len <= 33);
        var reference: RlpNode = .{ .len = @intCast(info.reference.len) };
        @memcpy(reference.bytes[0..info.reference.len], info.reference);
        try self.nodes.append(self.arena, .{
            .owner = info.owner,
            .path = try self.arena.dupe(u8, info.path),
            .encoding = try self.arena.dupe(u8, info.encoding),
            .reference = reference,
            .kind = info.kind,
            .mask = info.branch_mask,
        });
    }
};

const Lookup = std.StringHashMapUnmanaged(u32);

fn node_key(arena: std.mem.Allocator, owner: ?Hash, path: []const u8) ![]u8 {
    const key = try arena.alloc(u8, 33 + path.len);
    key[0] = @intFromBool(owner != null);
    key[1..33].* = owner orelse @splat(0);
    @memcpy(key[33..], path);
    return key;
}

fn same_owner(a: ?Hash, b: ?Hash) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, &a.?, &b.?);
}

/// The full key of the leaf at `path` with encoding `[hp(rest), value]`.
fn leaf_key(path: []const u8, encoding: []const u8) !Hash {
    const list = try trie.rlp.decode_item(encoding);
    var items: [2]trie.rlp.Item = undefined;
    try testing.expectEqual(@as(u32, 2), try trie.rlp.decode_list(list.payload, &items));
    const decoded = try trie.nibbles.hex_prefix_decode(items[0].payload);
    try testing.expect(decoded.leaf);
    var key = Nibbles.from_nibbles(path);
    key.append(decoded.path.slice());
    try testing.expectEqual(@as(u8, 64), key.len);
    var out: Hash = undefined;
    _ = key.pack(&out);
    return out;
}

/// Fills the record's children from the branch's child nodes.
fn fill_children(
    arena: std.mem.Allocator,
    nodes: []const Visited,
    lookup: *const Lookup,
    branch: *const Visited,
    record: *Record,
) !void {
    var child_path: [64]u8 = undefined;
    try testing.expect(branch.path.len < 64);
    @memcpy(child_path[0..branch.path.len], branch.path);
    const path = child_path[0 .. branch.path.len + 1];
    var child: u32 = 0;
    var leaves: u32 = 0;
    for (0..16) |nibble| {
        const bit = @as(u16, 1) << @intCast(nibble);
        if (branch.mask & bit == 0) continue;
        path[branch.path.len] = @intCast(nibble);
        const key = try node_key(arena, branch.owner, path);
        const visited = &nodes[lookup.get(key) orelse return error.TestUnexpectedResult];
        record.children[child] = visited.reference;
        child += 1;
        if (visited.kind == .leaf) {
            record.leaf_keys[leaves] = try leaf_key(path, visited.encoding);
            leaves += 1;
        } else {
            record.tree_mask |= bit;
        }
    }
    try testing.expectEqual(record.child_count(), child);
}

/// The record's synthesized nodes equal the trie's: same bytes, same references, and the
/// top reference hashes the synthesized top encoding.
fn check_synthesis(
    record: *const Record,
    branch: *const Visited,
    extension: ?*const Visited,
) !void {
    var branch_buffer: [branch_record.branch_bytes_max]u8 = undefined;
    const branch_bytes = branch_record.branch_encoding(record, &branch_buffer);
    try testing.expectEqualSlices(u8, branch.encoding, branch_bytes);
    const branch_reference = branch_record.branch_reference(record);
    try testing.expectEqualSlices(u8, branch.reference.slice(), branch_reference.slice());
    var top_bytes = branch_bytes;
    var top = branch;
    var extension_buffer: [branch_record.extension_encoding_bytes_max]u8 = undefined;
    if (extension) |above| {
        top_bytes = branch_record.extension_encoding(record, &branch_reference, &extension_buffer);
        try testing.expectEqualSlices(u8, above.encoding, top_bytes);
        top = above;
    }
    const reference = branch_record.reference(record);
    try testing.expectEqualSlices(u8, top.reference.slice(), reference.slice());
    if (reference.is_hash()) {
        try testing.expectEqualSlices(u8, &node.keccak256(top_bytes), reference.bytes[1..33]);
    } else {
        try testing.expectEqualSlices(u8, top_bytes, reference.slice());
    }
}

fn derive_one(
    arena: std.mem.Allocator,
    nodes: []const Visited,
    lookup: *const Lookup,
    index: usize,
) !Derived {
    const branch = &nodes[index];
    assert(branch.kind == .branch);
    var extension: ?*const Visited = null;
    // In pre-order the node before a branch is its parent or a leaf, so an extension
    // before it is the extension above it.
    if (index > 0 and nodes[index - 1].kind == .extension) {
        extension = &nodes[index - 1];
        try testing.expect(same_owner(extension.?.owner, branch.owner));
    }
    const hang = if (extension) |above| above.path else branch.path;
    try testing.expect(std.mem.startsWith(u8, branch.path, hang));
    var record: Record = .{ .state_mask = branch.mask };
    const nibbles = branch.path[hang.len..];
    record.extension_len = @intCast(nibbles.len);
    @memcpy(record.extension[0..nibbles.len], nibbles);
    try fill_children(arena, nodes, lookup, branch, &record);
    try check_synthesis(&record, branch, extension);
    try branch_record.validate_path(hang, &record);
    var buffer: [branch_record.value_bytes_max]u8 = undefined;
    const value = branch_record.encode(&record, &buffer);
    var decoded: Record = undefined;
    try branch_record.decode(value, &decoded);
    try testing.expectEqualSlices(u8, record.extension_slice(), decoded.extension_slice());
    const key = if (branch.owner) |owner|
        try arena.dupe(u8, &branch_record.storage_key(&owner, hang))
    else
        try arena.dupe(u8, &branch_record.path_key(hang));
    return .{ .key = key, .value = try arena.dupe(u8, value) };
}

/// Every branch record of `state` (hashed: call `root()` first; change tracking on), keys
/// sorted per tree. Checks each record's synthesized nodes against the trie's.
pub fn derive_records(arena: std.mem.Allocator, state: *StateTrie) !RecordSets {
    var nodes: std.ArrayList(Visited) = .empty;
    try state.visit_nodes(.all, Collector{ .arena = arena, .nodes = &nodes });
    var lookup: Lookup = .empty;
    for (nodes.items, 0..) |*visited, index| {
        const key = try node_key(arena, visited.owner, visited.path);
        const entry = try lookup.getOrPut(arena, key);
        try testing.expect(!entry.found_existing);
        entry.value_ptr.* = @intCast(index);
    }
    var sets: RecordSets = .{};
    for (nodes.items, 0..) |*visited, index| {
        if (visited.kind == .leaf and visited.path.len == 0) {
            // A single-leaf trie: its leaf-root record.
            const record = branch_record.leaf_root(&try leaf_key(&.{}, visited.encoding));
            var buffer: [branch_record.value_bytes_max]u8 = undefined;
            const value = try arena.dupe(u8, branch_record.encode(&record, &buffer));
            const key = if (visited.owner) |owner|
                try arena.dupe(u8, &branch_record.storage_key(&owner, &.{}))
            else
                try arena.dupe(u8, &branch_record.path_key(&.{}));
            const list = if (visited.owner == null) &sets.accounts else &sets.storage;
            try list.append(arena, .{ .key = key, .value = value });
            continue;
        }
        if (visited.kind != .branch) continue;
        const derived = try derive_one(arena, nodes.items, &lookup, index);
        const list = if (visited.owner == null) &sets.accounts else &sets.storage;
        try list.append(arena, derived);
    }
    std.mem.sort(Derived, sets.accounts.items, {}, Derived.less);
    std.mem.sort(Derived, sets.storage.items, {}, Derived.less);
    return sets;
}

/// Builds `accounts` into a fresh `StateTrie` and returns its record sets and root.
pub fn reference_records(
    arena: std.mem.Allocator,
    accounts: []const TestAccount,
    root: *Hash,
) !RecordSets {
    var state = try StateTrie.init(testing.allocator, state_config);
    defer state.deinit(testing.allocator);
    try state.track_changes(testing.allocator);
    try load(&state, accounts);
    root.* = try state.root();
    return derive_records(arena, &state);
}

test "branch record: records from the in-memory trie synthesize its nodes" {
    var prng = Prng.init(0xb4a2_7e1e);
    var records_total: u64 = 0;
    var inline_children: u64 = 0;
    var extensions: u64 = 0;
    for (0..40 + edge_cases) |round| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const accounts = if (round < edge_cases)
            try edge_state(arena, @intCast(round))
        else
            try random_state(arena, &prng, 40);
        var root: Hash = undefined;
        const sets = try reference_records(arena, accounts, &root);
        if (round < 3) {
            // Empty, then single-leaf tries: a leaf-root record each.
            const leaf_roots: usize = if (round == 0) 0 else 1;
            try testing.expectEqual(leaf_roots, sets.accounts.items.len);
            try testing.expectEqual(@intFromBool(round == 2), sets.storage.items.len);
        }
        for ([_][]const Derived{ sets.accounts.items, sets.storage.items }) |list| {
            for (list) |derived| {
                var record: Record = undefined;
                try branch_record.decode(derived.value, &record);
                records_total += 1;
                if (record.extension_len > 0) extensions += 1;
                for (record.children[0..record.child_count()]) |*child| {
                    if (!child.is_hash()) inline_children += 1;
                }
            }
        }
        if (round == 3) {
            // One record per trie: a 63-nibble extension over a branch at depth 63.
            try testing.expectEqual(@as(usize, 1), sets.accounts.items.len);
            try testing.expectEqual(@as(usize, 2), sets.storage.items.len);
            var record: Record = undefined;
            try branch_record.decode(sets.accounts.items[0].value, &record);
            try testing.expectEqual(@as(u8, 63), record.extension_len);
            const root_key = branch_record.path_key(&.{});
            try testing.expectEqualSlices(u8, &root_key, sets.accounts.items[0].key);
        }
    }
    // The shapes reach the cases that matter.
    try testing.expect(records_total > 100);
    try testing.expect(extensions > 10);
    try testing.expect(inline_children > 10);
}

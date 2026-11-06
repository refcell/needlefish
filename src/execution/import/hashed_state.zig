//! The state root of a reth database's hashed state (`HashedAccounts` and the DUPSORT
//! `HashedStorages`), streamed: both tables iterate in hashed-key order, and a storage
//! table's duplicates in hashed-slot order, which is exactly the trie order
//! `StateRootBuilder` needs. Each account takes the run of storage entries under its key.
//! A storage entry with no account, or an entry out of order, is `error.Corrupt`.

const std = @import("std");
const assert = std.debug.assert;

const reth = @import("reth.zig");
const state_root = @import("state_root.zig");

const Hash = [32]u8;

pub const Entry = struct { key: []const u8, value: []const u8 };

/// A table in key order; slices are valid until the next call.
pub const EntrySource = struct {
    context: *anyopaque,
    next: *const fn (context: *anyopaque) anyerror!?Entry,
};

pub const Progress = struct {
    context: *anyopaque,
    /// Called every `progress_interval` accounts.
    report: *const fn (context: *anyopaque, stats: *const state_root.Stats) void,
};

pub const progress_interval: u64 = 1 << 20;

pub const Error = error{Corrupt} || reth.Error || state_root.Error;

pub fn compute(
    builder: *state_root.StateRootBuilder,
    accounts: EntrySource,
    storages: EntrySource,
    progress: ?Progress,
) anyerror!Hash {
    var pending = try storages.next(storages.context);
    while (try accounts.next(accounts.context)) |entry| {
        if (entry.key.len != 32) return error.Corrupt;
        const address_hash = entry.key[0..32].*;
        const account = try reth.decode_account(entry.value);
        try builder.begin_account(&address_hash, .{
            .nonce = account.nonce,
            .balance = account.balance,
            .code_hash = account.code_hash,
        });
        const slots_before = builder.stats.slots;
        while (pending) |slot_entry| {
            if (slot_entry.key.len != 32) return error.Corrupt;
            const order = std.mem.order(u8, slot_entry.key, &address_hash);
            if (order == .lt) return error.Corrupt; // Storage under no account.
            if (order == .gt) break;
            const slot = try reth.decode_storage_entry(slot_entry.value);
            // reth deletes zero slots; a stored zero would mean a broken writer.
            if (slot.value == 0) return error.Corrupt;
            try builder.add_slot(&slot.slot, slot.value);
            pending = try storages.next(storages.context);
        }
        assert(builder.stats.slots >= slots_before);
        _ = try builder.end_account();
        if (progress) |p| {
            if (builder.stats.accounts % progress_interval == 0) {
                p.report(p.context, &builder.stats);
            }
        }
    }
    if (pending != null) return error.Corrupt;
    return builder.root();
}

const testing = std.testing;
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const SliceEntries = struct {
    entries: []const Entry,
    index: usize = 0,

    fn source(self: *SliceEntries) EntrySource {
        return .{ .context = self, .next = next };
    }

    fn next(context: *anyopaque) anyerror!?Entry {
        const self: *SliceEntries = @ptrCast(@alignCast(context));
        if (self.index == self.entries.len) return null;
        self.index += 1;
        return self.entries[self.index - 1];
    }
};

fn less_key(_: void, a: Entry, b: Entry) bool {
    const order = std.mem.order(u8, a.key, b.key);
    return order == .lt or (order == .eq and std.mem.order(u8, a.value, b.value) == .lt);
}

fn append_trimmed(out: []u8, value: u256) []u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) start += 1;
    @memcpy(out[0 .. 32 - start], bytes[start..]);
    return out[0 .. 32 - start];
}

// Encodes reth table values for a random state, applies it to `StateTrie` too, and checks
// both roots.
test "hashed state: root of reth-encoded tables equals StateTrie's (seeded)" {
    const allocator = testing.allocator;
    var prng = Prng.init(0x6861_7368);
    for (0..12) |round| {
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var reference = try trie.StateTrie.init(allocator, .{
            .accounts_max = 64,
            .account_nodes_max = 1 << 12,
            .storage_nodes_max = 1 << 14,
        });
        defer reference.deinit(allocator);
        var accounts: std.ArrayList(Entry) = .empty;
        var storages: std.ArrayList(Entry) = .empty;
        const count = prng.range(1, 50);
        for (0..count) |_| {
            var key: Hash = undefined;
            prng.fill(&key);
            const nonce = prng.below(300);
            const balance: u256 = prng.int(u64);
            var value: std.ArrayList(u8) = .empty;
            const nonce_bytes = append_trimmed(try arena.alloc(u8, 32), nonce);
            const balance_bytes = append_trimmed(try arena.alloc(u8, 32), balance);
            const has_code = prng.chance(1, 2);
            const flags: u16 = @intCast(nonce_bytes.len | balance_bytes.len << 4 |
                @as(usize, @intFromBool(has_code)) << 10);
            try value.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToLittle(u16, flags)));
            try value.appendSlice(arena, nonce_bytes);
            try value.appendSlice(arena, balance_bytes);
            var code_hash = trie.node.empty_code_hash;
            if (has_code) {
                prng.fill(&code_hash);
                try value.appendSlice(arena, &code_hash);
            }
            const stored_key = try arena.dupe(u8, &key);
            try accounts.append(arena, .{ .key = stored_key, .value = value.items });
            try reference.set_account(key, .{
                .nonce = nonce,
                .balance = balance,
                .code_hash = code_hash,
            });
            for (0..prng.below(20)) |_| {
                var slot: Hash = undefined;
                prng.fill(&slot);
                const slot_value: u256 = prng.range(1, 1 << 40);
                const bytes = try arena.alloc(u8, 64);
                @memcpy(bytes[0..32], &slot);
                const tail = append_trimmed(bytes[32..], slot_value);
                const stored = bytes[0 .. 32 + tail.len];
                try storages.append(arena, .{ .key = stored_key, .value = stored });
                try reference.set_storage(key, slot, slot_value);
            }
        }
        std.mem.sort(Entry, accounts.items, {}, less_key);
        std.mem.sort(Entry, storages.items, {}, less_key);
        var account_source: SliceEntries = .{ .entries = accounts.items };
        var storage_source: SliceEntries = .{ .entries = storages.items };
        const builder = try allocator.create(state_root.StateRootBuilder);
        defer allocator.destroy(builder);
        builder.* = .{};
        // Odd rounds stream branch records too; the root must not change.
        var sinks: state_root.RecordSinks = .{ .target = state_root.discard_sink };
        if (round % 2 == 1) builder.set_record_sink(&sinks);
        const root = try compute(builder, account_source.source(), storage_source.source(), null);
        try testing.expectEqualSlices(u8, &try reference.root(), &root);
        // Orphaned storage (an entry below the first account) is corrupt.
        if (storages.items.len > 0) {
            var orphan: Hash = @splat(0);
            orphan[31] = 1;
            var with_orphan: std.ArrayList(Entry) = .empty;
            try with_orphan.append(arena, .{ .key = &orphan, .value = storages.items[0].value });
            try with_orphan.appendSlice(arena, storages.items);
            var again: SliceEntries = .{ .entries = accounts.items };
            var orphaned: SliceEntries = .{ .entries = with_orphan.items };
            builder.* = .{};
            const result = compute(builder, again.source(), orphaned.source(), null);
            try testing.expectError(error.Corrupt, result);
        }
    }
}

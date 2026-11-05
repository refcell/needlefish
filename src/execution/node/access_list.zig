//! Access list collection for `eth_createAccessList`: after a simulated transaction, the
//! accounts and storage slots the evm warmed (EIP-2929) are read from its state, minus
//! the addresses every transaction warms anyway (sender, recipient, coinbase from
//! Shanghai, active precompiles, Base native contracts) and contracts the transaction
//! created. Storage slots are kept for every address, as geth's access list tracer does
//! (its `to` keeps its slots). Entries are sorted by address then slot, accounts first.
//!
//! The evm drops warmth gained in reverted call frames, so unlike geth's opcode tracer
//! a reverted frame's accesses are not listed (they would not be charged either).

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const chainspec = @import("../chainspec/root.zig");
const executor_op = @import("executor_op.zig");

const Address = [20]u8;

pub const Entry = struct {
    address: Address,
    /// Null for the account entry itself.
    slot: ?u256,

    fn less(_: void, a: Entry, b: Entry) bool {
        const order = std.mem.order(u8, &a.address, &b.address);
        if (order != .eq) return order == .lt;
        const a_slot = a.slot orelse return b.slot != null;
        const b_slot = b.slot orelse return false;
        return a_slot < b_slot;
    }

    fn eql(a: Entry, b: Entry) bool {
        if (!std.mem.eql(u8, &a.address, &b.address)) return false;
        if (a.slot == null or b.slot == null) return a.slot == null and b.slot == null;
        return a.slot.? == b.slot.?;
    }
};

/// The transaction's pre-warmed context.
pub const Context = struct {
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
    from: Address,
    to: ?Address,
    coinbase: Address,

    /// Whether every transaction in this context warms `address` before it runs.
    pub fn prewarmed(context: *const Context, address: Address) bool {
        if (std.mem.eql(u8, &address, &context.from)) return true;
        if (context.to) |to| if (std.mem.eql(u8, &address, &to)) return true;
        const spec = context.spec;
        if (spec.is_ethereum_fork_active(.shanghai, context.timestamp)) {
            if (std.mem.eql(u8, &address, &context.coinbase)) return true;
        }
        const op_upgrade = if (executor_op.context(spec, context.timestamp)) |op|
            op.upgrade
        else
            null;
        for (evm.native.warm_addresses(op_upgrade)) |native| {
            if (std.mem.eql(u8, &address, &native)) return true;
        }
        const fork = @import("executor.zig").evm_fork(spec.spec_at(context.timestamp));
        return switch (fork) {
            inline else => |f| evm.precompiles.is_precompile(f, op_upgrade, address),
        };
    }
};

pub const Collector = struct {
    entries: []Entry,
    len: u32 = 0,
    /// More warm entries than `entries` holds; the list is incomplete.
    overflow: bool = false,

    pub fn slice(collector: *const Collector) []const Entry {
        return collector.entries[0..collector.len];
    }

    /// Reads the warm set of the state's current transaction.
    pub fn collect(collector: *Collector, state: *const evm.State, context: *const Context) void {
        collector.len = 0;
        collector.overflow = false;
        const tx_id = state.tx_id;
        var accounts = state.accounts.iterator();
        while (accounts.next()) |item| {
            const account = item.value_ptr;
            if (account.warm_tx != tx_id) continue;
            if (account.created_tx == tx_id) continue;
            if (context.prewarmed(account.address)) continue;
            collector.push(.{ .address = account.address, .slot = null });
        }
        var slots = state.slots.iterator();
        while (slots.next()) |item| {
            if (item.value_ptr.warm_tx != tx_id) continue;
            const key = item.key_ptr.*;
            const owner = state.accounts.getPtr(key.address);
            if (owner != null and owner.?.created_tx == tx_id) continue;
            collector.push(.{ .address = key.address, .slot = key.slot });
            // geth lists an address whose slots were read even when it is pre-warmed.
            collector.push(.{ .address = key.address, .slot = null });
        }
        collector.normalize();
    }

    fn push(collector: *Collector, entry: Entry) void {
        if (collector.len == collector.entries.len) {
            collector.overflow = true;
            return;
        }
        collector.entries[collector.len] = entry;
        collector.len += 1;
    }

    /// Sorts and removes duplicates.
    pub fn normalize(collector: *Collector) void {
        const entries = collector.entries[0..collector.len];
        std.sort.pdq(Entry, entries, {}, Entry.less);
        var kept: u32 = 0;
        for (entries) |entry| {
            if (kept > 0 and Entry.eql(entries[kept - 1], entry)) continue;
            entries[kept] = entry;
            kept += 1;
        }
        collector.len = kept;
        assert(kept <= entries.len);
    }

    pub fn eql(collector: *const Collector, other: []const Entry) bool {
        if (collector.len != other.len) return false;
        for (collector.slice(), other) |a, b| if (!Entry.eql(a, b)) return false;
        return true;
    }
};

/// Converts sorted, deduplicated `entries` into evm access list items; `items` and
/// `keys` must hold one per account and slot entry. Returns the items used.
pub fn to_items(
    entries: []const Entry,
    items: []evm.transaction.AccessListItem,
    keys: []evm.primitives.B256,
) error{AccessListFull}![]const evm.transaction.AccessListItem {
    var item_count: usize = 0;
    var key_count: usize = 0;
    for (entries) |entry| {
        if (entry.slot) |slot| {
            assert(item_count > 0); // The account entry sorts first.
            if (key_count == keys.len) return error.AccessListFull;
            keys[key_count] = evm.primitives.u256_to_b256(slot);
            key_count += 1;
            const item = &items[item_count - 1];
            assert(std.mem.eql(u8, &item.address, &entry.address));
            item.storage_keys = keys[key_count - 1 - item.storage_keys.len .. key_count];
        } else {
            if (item_count == items.len) return error.AccessListFull;
            items[item_count] = .{ .address = entry.address, .storage_keys = &.{} };
            item_count += 1;
        }
    }
    return items[0..item_count];
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn entry_of(byte: u8, slot: ?u256) Entry {
    return .{ .address = @splat(byte), .slot = slot };
}

test "access_list: normalize sorts accounts before their slots and dedups" {
    var buffer: [8]Entry = undefined;
    var collector: Collector = .{ .entries = &buffer };
    const input = [_]Entry{
        entry_of(2, 7), entry_of(1, null), entry_of(2, null),
        entry_of(2, 3), entry_of(2, 7),    entry_of(1, null),
    };
    @memcpy(buffer[0..input.len], &input);
    collector.len = input.len;
    collector.normalize();
    const expected = [_]Entry{
        entry_of(1, null), entry_of(2, null),
        entry_of(2, 3),    entry_of(2, 7),
    };
    try testing.expect(collector.eql(&expected));
    var items: [4]evm.transaction.AccessListItem = undefined;
    var keys: [4]evm.primitives.B256 = undefined;
    const list = try to_items(collector.slice(), &items, &keys);
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqual(@as(usize, 0), list[0].storage_keys.len);
    try testing.expectEqual(@as(usize, 2), list[1].storage_keys.len);
    try testing.expectEqual(@as(u256, 7), evm.primitives.b256_to_u256(list[1].storage_keys[1]));
}

fn check_normalize(seed: u64) !void {
    var prng = Prng.init(seed);
    var buffer: [64]Entry = undefined;
    var collector: Collector = .{ .entries = &buffer };
    const count = prng.range(0, 32);
    for (0..count) |_| {
        const byte: u8 = @intCast(prng.below(4));
        collector.push(entry_of(byte, if (prng.chance(1, 2)) prng.below(4) else null));
        collector.push(entry_of(byte, null)); // As `collect`: each slot has its account.
    }
    collector.normalize();
    const entries = collector.slice();
    for (entries[@min(1, entries.len)..], 0..) |entry, index| {
        try testing.expect(Entry.less({}, entries[index], entry));
    }
    var items: [64]evm.transaction.AccessListItem = undefined;
    var keys: [64]evm.primitives.B256 = undefined;
    const list = try to_items(entries, &items, &keys);
    var total: usize = 0;
    for (list) |item| total += 1 + item.storage_keys.len;
    try testing.expectEqual(entries.len, total);
    // Idempotent.
    const before = collector.len;
    collector.normalize();
    try testing.expectEqual(before, collector.len);
}

test "access_list: seeded fuzz of normalization" {
    for (0..128) |seed| try check_normalize(seed + 0xacc);
}

fn fuzz_normalize(_: void, smith: *testing.Smith) anyerror!void {
    try check_normalize(smith.value(u64));
}

test "access_list: fuzz" {
    try testing.fuzz({}, fuzz_normalize, .{});
}

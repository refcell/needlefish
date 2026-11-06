//! Streaming state root over a whole state in hashed-key order (SYNC_PLAN M3): the check an
//! imported snapshot must pass before needlefish trusts it. Accounts come in strictly
//! increasing keccak256(address) order, each followed by its slots in strictly increasing
//! keccak256(slot) order, exactly as reth's `HashedAccounts` / `HashedStorages` tables (or
//! any sorted export) iterate. Memory is constant: one builder for the account trie and one
//! for the open account's storage trie, so a state of billions of entries needs no more RAM
//! than a state of ten.
//!
//! Input is untrusted (a third-party snapshot): out-of-order or duplicate keys and zero
//! slot values are errors, never asserts.
//!
//! Optionally (`set_record_sink`), every branch of the account trie and of each storage
//! trie streams out as a path-keyed branch record (`db/branch_record.zig`), in post-order
//! per trie, so a disk import can bulk load them without sorting.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const node = trie.node;
const state_trie = trie.state_trie;

const Hash = node.Hash;
const HashBuilder = trie.HashBuilder;
const BranchNode = trie.BranchNode;
const BranchSink = trie.hash_builder.BranchSink;
const Nibbles = trie.Nibbles;

pub const Account = state_trie.Account;

pub const Error = error{
    /// A key is not above the previous one (sorted, unique input required).
    OutOfOrder,
    /// A stored slot is zero (a zero slot does not exist in the trie).
    ZeroSlot,
    /// A slot without an open account, or an account call while one is open.
    NoAccount,
};

pub const Stats = struct {
    accounts: u64 = 0,
    slots: u64 = 0,
    /// Accounts with at least one slot.
    storage_accounts: u64 = 0,
};

/// Receives the branch records of the account trie (`owner` null) and of each storage trie
/// (`owner` the account's address hash). Per trie, records arrive in post-order, which is
/// ascending branch-record key order.
pub const RecordSink = struct {
    context: *anyopaque,
    emit: *const fn (
        context: *anyopaque,
        owner: ?*const Hash,
        hang: []const u8,
        branch: *const BranchNode,
    ) void,
};

/// Scratch for the two builders' branch sinks (~70 KiB), owned by the caller.
pub const RecordSinks = struct {
    target: RecordSink,
    account: BranchSink = undefined,
    storage: BranchSink = undefined,
};

pub const StateRootBuilder = struct {
    accounts: HashBuilder = .init(),
    storage: HashBuilder = .init(),
    /// The builders borrow the previous leaf value until the next leaf: two buffers each.
    account_values: [2][state_trie.account_rlp_bytes_max]u8 = undefined,
    account_flip: u1 = 0,
    slot_values: [2][33]u8 = undefined,
    slot_flip: u1 = 0,
    last_account: ?Hash = null,
    last_slot: ?Hash = null,
    /// The account whose slots are being added.
    open: ?Account = null,
    stats: Stats = .{},
    /// Optional branch record output; see `set_record_sink`.
    record_sinks: ?*RecordSinks = null,

    /// Streams every branch record to `sinks.target`. Call before the first account; the
    /// builder must not move afterwards (the sinks point back at it).
    pub fn set_record_sink(self: *StateRootBuilder, sinks: *RecordSinks) void {
        assert(self.last_account == null and self.open == null);
        assert(self.record_sinks == null);
        sinks.account = .{ .context = self, .emit = emit_account };
        sinks.storage = .{ .context = self, .emit = emit_storage };
        self.record_sinks = sinks;
        self.accounts.branch_sink = &sinks.account;
        assert(self.accounts.branch_sink != null);
    }

    fn emit_account(context: *anyopaque, hang: []const u8, branch: *const BranchNode) void {
        const self: *StateRootBuilder = @ptrCast(@alignCast(context));
        const target = self.record_sinks.?.target;
        target.emit(target.context, null, hang, branch);
    }

    fn emit_storage(context: *anyopaque, hang: []const u8, branch: *const BranchNode) void {
        const self: *StateRootBuilder = @ptrCast(@alignCast(context));
        // Storage branches finish while their account is open, before `end_account` ends.
        assert(self.open != null);
        const target = self.record_sinks.?.target;
        target.emit(target.context, &self.last_account.?, hang, branch);
    }

    /// Opens the account at `address_hash`; its slots follow, then `end_account`.
    pub fn begin_account(
        self: *StateRootBuilder,
        address_hash: *const Hash,
        account: Account,
    ) Error!void {
        if (self.open != null) return error.NoAccount;
        if (self.last_account) |last| {
            if (std.mem.order(u8, &last, address_hash) != .lt) return error.OutOfOrder;
        }
        self.last_account = address_hash.*;
        self.last_slot = null;
        self.open = account;
        self.storage.reset();
        if (self.record_sinks) |sinks| self.storage.branch_sink = &sinks.storage;
        assert(self.open != null);
    }

    pub fn add_slot(self: *StateRootBuilder, slot_hash: *const Hash, value: u256) Error!void {
        if (self.open == null) return error.NoAccount;
        if (value == 0) return error.ZeroSlot;
        if (self.last_slot) |last| {
            if (std.mem.order(u8, &last, slot_hash) != .lt) return error.OutOfOrder;
        }
        self.last_slot = slot_hash.*;
        self.slot_flip +%= 1;
        const buffer = &self.slot_values[self.slot_flip];
        const encoded = state_trie.encode_storage_value(value, buffer);
        const path = Nibbles.from_bytes(slot_hash);
        self.storage.add_leaf(path.slice(), encoded);
        self.stats.slots += 1;
        assert(encoded.len > 0 and encoded.len <= 33);
    }

    /// Closes the open account: its storage root, then its leaf in the account trie.
    /// Returns the storage root.
    pub fn end_account(self: *StateRootBuilder) Error!Hash {
        const account = self.open orelse return error.NoAccount;
        const has_storage = self.last_slot != null;
        const storage_root = if (has_storage) self.storage.root() else node.empty_root;
        self.account_flip +%= 1;
        const buffer = &self.account_values[self.account_flip];
        const encoded = state_trie.encode_account(&account, &storage_root, buffer);
        const path = Nibbles.from_bytes(&self.last_account.?);
        self.accounts.add_leaf(path.slice(), encoded);
        self.open = null;
        self.stats.accounts += 1;
        if (has_storage) self.stats.storage_accounts += 1;
        assert(self.open == null);
        return storage_root;
    }

    /// The state root of every account added. The builder is spent.
    pub fn root(self: *StateRootBuilder) Error!Hash {
        if (self.open != null) return error.NoAccount;
        return self.accounts.root();
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const Entry = struct {
    address_hash: Hash,
    account: Account,
    slots: []const SlotEntry,

    fn less(_: void, a: Entry, b: Entry) bool {
        return std.mem.order(u8, &a.address_hash, &b.address_hash) == .lt;
    }
};
const SlotEntry = struct {
    hash: Hash,
    value: u256,

    fn less(_: void, a: SlotEntry, b: SlotEntry) bool {
        return std.mem.order(u8, &a.hash, &b.hash) == .lt;
    }
};

fn tagged_hash(tag: u8, index: u64) Hash {
    var input: [9]u8 = undefined;
    input[0] = tag;
    std.mem.writeInt(u64, input[1..9], index, .big);
    return node.keccak256(&input);
}

// Differential: the streaming root equals `StateTrie`'s incremental node-based root for
// random states (accounts with and without storage, single-slot tries, empty state).
test "import state root: seeded differential against StateTrie" {
    const allocator = testing.allocator;
    var prng = Prng.init(0x5747_e200);
    for (0..24) |round| {
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const count: usize = if (round == 0) 0 else @intCast(prng.range(1, 60));
        const entries = try arena.alloc(Entry, count);
        var reference = try state_trie.StateTrie.init(allocator, .{
            .accounts_max = 64,
            .account_nodes_max = 1 << 12,
            .storage_nodes_max = 1 << 14,
        });
        defer reference.deinit(allocator);
        for (entries, 0..) |*entry, index| {
            const slot_count: usize = if (prng.chance(1, 3)) 0 else @intCast(prng.range(1, 40));
            const slots = try arena.alloc(SlotEntry, slot_count);
            for (slots, 0..) |*slot, slot_index| {
                slot.hash = tagged_hash(1, round * 100_000 + index * 100 + slot_index);
                const wide = @as(u256, prng.int(u64)) << 128 | 1;
                slot.value = if (prng.chance(1, 2)) prng.range(1, 255) else wide;
            }
            std.mem.sort(SlotEntry, slots, {}, SlotEntry.less);
            entry.* = .{
                .address_hash = tagged_hash(0, round * 1000 + index),
                .account = .{
                    .nonce = prng.below(1000),
                    .balance = prng.int(u64),
                    .code_hash = if (prng.chance(1, 2))
                        node.empty_code_hash
                    else
                        tagged_hash(2, index),
                },
                .slots = slots,
            };
            try reference.set_account(entry.address_hash, entry.account);
            for (slots) |slot| try reference.set_storage(entry.address_hash, slot.hash, slot.value);
        }
        std.mem.sort(Entry, entries, {}, Entry.less);
        const builder = try allocator.create(StateRootBuilder);
        defer allocator.destroy(builder);
        builder.* = .{};
        // Odd rounds stream branch records too; the root must not change.
        const sinks = try allocator.create(RecordSinks);
        defer allocator.destroy(sinks);
        sinks.* = .{ .target = discard_sink };
        if (round % 2 == 1) builder.set_record_sink(sinks);
        for (entries) |entry| {
            try builder.begin_account(&entry.address_hash, entry.account);
            for (entry.slots) |slot| try builder.add_slot(&slot.hash, slot.value);
            _ = try builder.end_account();
        }
        const expected = try reference.root();
        try testing.expectEqualSlices(u8, &expected, &try builder.root());
        try testing.expectEqual(@as(u64, count), builder.stats.accounts);
    }
}

test "import state root: untrusted input is rejected" {
    var builder: StateRootBuilder = .{};
    const a = tagged_hash(0, 1);
    const b = tagged_hash(0, 2);
    const low, const high = if (std.mem.order(u8, &a, &b) == .lt) .{ a, b } else .{ b, a };
    try testing.expectError(error.NoAccount, builder.add_slot(&low, 1));
    try testing.expectError(error.NoAccount, builder.end_account());
    try builder.begin_account(&high, .{});
    try testing.expectError(error.NoAccount, builder.begin_account(&high, .{}));
    try testing.expectError(error.ZeroSlot, builder.add_slot(&low, 0));
    try builder.add_slot(&high, 7);
    try testing.expectError(error.OutOfOrder, builder.add_slot(&high, 7));
    try testing.expectError(error.OutOfOrder, builder.add_slot(&low, 7));
    try testing.expectError(error.NoAccount, builder.root());
    _ = try builder.end_account();
    try testing.expectError(error.OutOfOrder, builder.begin_account(&low, .{}));
    try testing.expectError(error.OutOfOrder, builder.begin_account(&high, .{}));
}

test "import state root: empty state is the empty root" {
    var builder: StateRootBuilder = .{};
    try testing.expectEqualSlices(u8, &node.empty_root, &try builder.root());
}

const branch_record = @import("../db/branch_record.zig");

/// A record sink for tests that only need the root.
pub const discard_sink: RecordSink = .{ .context = @constCast(&discard_context), .emit = discard };
var discard_context: u8 = 0;

fn discard(_: *anyopaque, _: ?*const Hash, hang: []const u8, branch: *const BranchNode) void {
    assert(hang.len < 64);
    // A branch, or a single-leaf trie's leaf-root record at the root.
    assert(branch.child_count() >= 2 or (branch.state_mask == 0 and hang.len == 0));
}
const record_test = @import("../db/branch_record_test.zig");

/// Collects emitted records as encoded (key, value) pairs, in emission order.
const RecordCollector = struct {
    arena: std.mem.Allocator,
    sets: record_test.RecordSets = .{},
    failed: bool = false,

    fn sink(self: *RecordCollector) RecordSink {
        return .{ .context = self, .emit = emit };
    }

    fn emit(
        context: *anyopaque,
        owner: ?*const Hash,
        hang: []const u8,
        branch: *const BranchNode,
    ) void {
        const self: *RecordCollector = @ptrCast(@alignCast(context));
        self.add(owner, hang, branch) catch {
            self.failed = true;
        };
    }

    fn add(
        self: *RecordCollector,
        owner: ?*const Hash,
        hang: []const u8,
        branch: *const BranchNode,
    ) !void {
        try branch_record.validate_path(hang, branch);
        var buffer: [branch_record.value_bytes_max]u8 = undefined;
        const value = try self.arena.dupe(u8, branch_record.encode(branch, &buffer));
        const key = if (owner) |hash|
            try self.arena.dupe(u8, &branch_record.storage_key(hash, hang))
        else
            try self.arena.dupe(u8, &branch_record.path_key(hang));
        const list = if (owner == null) &self.sets.accounts else &self.sets.storage;
        try list.append(self.arena, .{ .key = key, .value = value });
    }
};

fn expect_strictly_ascending(list: []const record_test.Derived) !void {
    for (list[0..list.len -| 1], list[@min(1, list.len)..]) |a, b| {
        try testing.expect(std.mem.order(u8, a.key, b.key) == .lt);
    }
}

fn expect_same_records(want: []const record_test.Derived, got: []const record_test.Derived) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |a, b| {
        try testing.expectEqualSlices(u8, a.key, b.key);
        try testing.expectEqualSlices(u8, a.value, b.value);
    }
}

/// Streams `accounts` through a builder with record sinks; checks the root against the
/// in-memory trie's and the record sets against those derived from its nodes.
fn check_records(arena: std.mem.Allocator, accounts: []const record_test.TestAccount) !void {
    var expected_root: Hash = undefined;
    const want = try record_test.reference_records(arena, accounts, &expected_root);
    const builder = try testing.allocator.create(StateRootBuilder);
    defer testing.allocator.destroy(builder);
    builder.* = .{};
    const sinks = try testing.allocator.create(RecordSinks);
    defer testing.allocator.destroy(sinks);
    var collector: RecordCollector = .{ .arena = arena };
    sinks.* = .{ .target = collector.sink() };
    builder.set_record_sink(sinks);
    for (accounts) |entry| {
        try builder.begin_account(&entry.key, entry.account);
        for (entry.slots) |slot| try builder.add_slot(&slot.key, slot.value);
        _ = try builder.end_account();
    }
    try testing.expectEqualSlices(u8, &expected_root, &try builder.root());
    try testing.expect(!collector.failed);
    // Emission order is already key order (storage owners ascend with the accounts).
    try expect_strictly_ascending(collector.sets.accounts.items);
    try expect_strictly_ascending(collector.sets.storage.items);
    try expect_same_records(want.accounts.items, collector.sets.accounts.items);
    try expect_same_records(want.storage.items, collector.sets.storage.items);
}

test "import state root: branch records equal the in-memory trie's (seeded, edge cases)" {
    var prng = Prng.init(0x5747_b4a2);
    for (0..60 + record_test.edge_cases) |round| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const accounts = if (round < record_test.edge_cases)
            try record_test.edge_state(arena, @intCast(round))
        else
            try record_test.random_state(arena, &prng, 48);
        try check_records(arena, accounts);
    }
}

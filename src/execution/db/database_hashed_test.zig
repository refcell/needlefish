//! Hashed changesets in disk mode (`Changeset.hashed`, `overlay.build_hashed_changeset`):
//! the same random blocks go to two disk-mode databases on `SimStorage`, one through the
//! node's address-keyed path (`Overlay`, `execute_and_commit`), the other as writes in
//! hashed key space (a hashed changeset built from trie-key reads, `State.apply` into the
//! trees, `commit_applied`), the way `StateDb.commit_hashed` commits. After every block,
//! native unwind (`set_head`) and reopen (journal replay of the hashed changesets) both
//! have the same state root and read the same account records and slots by trie key.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const disk_test = @import("database_disk_test.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const state_module = @import("state.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const keccak256 = @import("../trie/node.zig").keccak256;

const Hash = database.Hash;
const Node = disk_test.Node;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const State = state_module.State;

const addresses_max = 8;
const slots_max = 4;
const blocks_max = 48;

/// Trie-key reads of a disk-mode state, for `build_hashed_changeset`.
const Reader = struct {
    state: *const State,

    pub const Error = error{};

    pub fn account(reader: Reader, key: *const Hash) Reader.Error!?AccountInfo {
        const record = reader.state.account_hashed(key) orelse return null;
        return record.info;
    }

    pub fn storage(reader: Reader, key: *const Hash, slot: *const Hash) Reader.Error!u256 {
        return reader.state.storage_hashed(key, slot);
    }
};

fn slot_hash(slot: u64) Hash {
    var bytes: Hash = @splat(0);
    std.mem.writeInt(u64, bytes[24..32], slot, .big);
    return keccak256(&bytes);
}

const Pair = struct {
    address: Node,
    hashed: Node,
    changeset: changeset_module.Changeset,
    buffer: []u8,
    /// Block ids of the canonical chain by height.
    heights: [blocks_max + 1]u32 = undefined,
    height: u32 = 0,
    next_id: u32 = 1,
    header: [8]u8 = undefined,

    fn input(pair: *Pair, id: u32, parent: u32, number: u64) database.BlockInput {
        std.mem.writeInt(u64, &pair.header, id, .big);
        return .{
            .hash = disk_test.hash_of(id),
            .parent_hash = if (number == 0) @splat(0) else disk_test.hash_of(parent),
            .number = number,
            .timestamp = number,
            .header = &pair.header,
            .body = "",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
    }

    /// Random ops into the address side's overlay; the touched addresses and slots.
    fn random_ops(pair: *Pair, prng: *Prng, touched: *[addresses_max]u8) !void {
        const overlay = &pair.address.overlay;
        for (0..prng.range(1, 8)) |_| {
            const index = prng.below(addresses_max);
            const address = disk_test.address_of(index);
            const exists = overlay.basic(address) != null;
            const choice = prng.below(8);
            if (choice < 4 and exists) {
                const slot = prng.below(slots_max);
                const value: u256 = if (prng.chance(1, 3)) 0 else prng.range(1, 1 << 30);
                try overlay.set_storage(address, slot, value);
                touched[index] |= @as(u8, 1) << @intCast(slot);
                touched[index] |= 0x80;
            } else if (choice == 7 and exists) {
                // Disk mode refuses to destroy an account with committed storage.
                if (pair.address.db.state.has_storage(address)) continue;
                try overlay.set_account(address, null);
                touched[index] |= 0x80;
            } else {
                const info: AccountInfo = .{ .nonce = prng.range(1, 4), .balance = prng.below(9) };
                try overlay.set_account(address, info);
                touched[index] |= 0x80;
            }
        }
    }

    /// The address side's post-state of what `touched` names, as hashed writes.
    fn writes(
        pair: *Pair,
        touched: *const [addresses_max]u8,
        accounts: []overlay_module.HashedAccountWrite,
        slots: []overlay_module.HashedSlotWrite,
    ) overlay_module.HashedWrites {
        var accounts_len: usize = 0;
        var slots_len: usize = 0;
        const state = &pair.address.db.state;
        for (touched, 0..) |mask, index| {
            if (mask == 0) continue;
            const address = disk_test.address_of(index);
            const key = keccak256(&address);
            accounts[accounts_len] = .{ .key = key, .info = state.basic(address) };
            accounts_len += 1;
            for (0..slots_max) |slot| {
                if (mask & (@as(u8, 1) << @intCast(slot)) == 0) continue;
                const value = state.storage(address, slot);
                slots[slots_len] = .{ .key = key, .slot = slot_hash(slot), .value = value };
                slots_len += 1;
            }
        }
        sort_writes(accounts[0..accounts_len], slots[0..slots_len]);
        return .{ .accounts = accounts[0..accounts_len], .slots = slots[0..slots_len] };
    }

    fn block(pair: *Pair, prng: *Prng) !void {
        var touched: [addresses_max]u8 = @splat(0);
        try pair.random_ops(prng, &touched);
        const id = pair.next_id;
        pair.next_id += 1;
        const parent = pair.heights[pair.height];
        var block_input = pair.input(id, parent, pair.height + 1);
        _ = try pair.address.commit_retry(&block_input);
        var accounts: [addresses_max]overlay_module.HashedAccountWrite = undefined;
        var slots: [addresses_max * slots_max]overlay_module.HashedSlotWrite = undefined;
        const hashed_writes = pair.writes(&touched, &accounts, &slots);
        try pair.commit_hashed(hashed_writes, &block_input);
        pair.height += 1;
        pair.heights[pair.height] = id;
        try pair.expect_same();
    }

    /// `StateDb.commit_hashed` then `commit_applied`, retried while the trees are busy.
    fn commit_hashed(
        pair: *Pair,
        hashed_writes: overlay_module.HashedWrites,
        block_input: *database.BlockInput,
    ) !void {
        const db = &pair.hashed.db;
        var ticks: u32 = 0;
        while (ticks < 100_000) : (ticks += 1) {
            const reader: Reader = .{ .state = &db.state };
            try overlay_module.build_hashed_changeset(reader, hashed_writes, &pair.changeset);
            try testing.expect(pair.changeset.hashed);
            db.state.apply(&pair.changeset) catch |err| switch (err) {
                error.Busy => {
                    pair.hashed.sim.tick();
                    continue;
                },
                else => return err,
            };
            block_input.changeset = pair.changeset.encode(pair.buffer);
            _ = db.commit_applied(block_input) catch |err| switch (err) {
                error.Busy => {
                    try db.state.unwind(&pair.changeset);
                    pair.hashed.sim.tick();
                    continue;
                },
                else => return err,
            };
            return;
        }
        return error.Timeout;
    }

    fn expect_same(pair: *Pair) !void {
        const a = &pair.address.db;
        const b = &pair.hashed.db;
        try testing.expectEqualSlices(u8, &a.head_info.state_root, &b.head_info.state_root);
        for (0..addresses_max) |index| {
            const address = disk_test.address_of(index);
            const key = keccak256(&address);
            const info = a.state.basic(address);
            const record = b.state.account_hashed(&key);
            try testing.expectEqual(info == null, record == null);
            if (info) |want| try testing.expect(want.eql(record.?.info));
            for (0..slots_max) |slot| {
                const want = a.state.storage(address, slot);
                try testing.expectEqual(want, b.state.storage_hashed(&key, &slot_hash(slot)));
            }
        }
    }
};

const AccountWrite = overlay_module.HashedAccountWrite;
const SlotWrite = overlay_module.HashedSlotWrite;

fn account_less_than(_: void, x: AccountWrite, y: AccountWrite) bool {
    return std.mem.order(u8, &x.key, &y.key) == .lt;
}

fn slot_less_than(_: void, x: SlotWrite, y: SlotWrite) bool {
    const order = std.mem.order(u8, &x.key, &y.key);
    if (order != .eq) return order == .lt;
    return std.mem.order(u8, &x.slot, &y.slot) == .lt;
}

fn sort_writes(accounts: []AccountWrite, slots: []SlotWrite) void {
    std.mem.sort(AccountWrite, accounts, {}, account_less_than);
    std.mem.sort(SlotWrite, slots, {}, slot_less_than);
}

/// Ticks until every entry is durable and nothing is in flight (a clean stop: reopening
/// then replays the journal written since the last checkpoint).
fn settle(node: *Node) !void {
    var ticks: u32 = 0;
    while (node.db.durable_sequence < node.db.submitted_sequence or !node.db.idle()) {
        if (ticks >= 100_000) return error.Timeout;
        node.sim.tick();
        ticks += 1;
    }
    assert(node.db.durable_sequence == node.db.submitted_sequence);
}

fn run_seed(seed: u64) !void {
    var prng = Prng.init(0x4a5e_d000 + seed);
    const size = disk_test.config_disk.engine.size_bytes();
    var sim_a = try SimStorage.init(testing.allocator, .{ .size_bytes = size, .seed = seed });
    defer sim_a.deinit(testing.allocator);
    var sim_b = try SimStorage.init(testing.allocator, .{ .size_bytes = size, .seed = seed + 7 });
    defer sim_b.deinit(testing.allocator);
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    const config = disk_test.config_disk.changeset;
    pair.* = .{
        .address = undefined,
        .hashed = undefined,
        .changeset = try changeset_module.Changeset.init(testing.allocator, config),
        .buffer = try testing.allocator.alloc(u8, disk_test.config_disk.engine.entry_body_size_max),
    };
    defer testing.allocator.free(pair.buffer);
    defer pair.changeset.deinit(testing.allocator);
    try pair.address.init(&sim_a, disk_test.config_disk);
    defer pair.address.deinit();
    try pair.hashed.init(&sim_b, disk_test.config_disk);
    defer pair.hashed.deinit();
    try pair.address.format(0x4a5e + seed);
    try pair.hashed.format(0x4a5f + seed);
    var genesis = pair.input(0, 0, 0);
    _ = try pair.address.commit_retry(&genesis);
    _ = try pair.hashed.commit_retry(&genesis);
    pair.heights[0] = 0;
    while (pair.height < blocks_max) {
        try pair.block(&prng);
        if (prng.chance(1, 6) and pair.height > 1) {
            // A native unwind on both: `set_head` unwinds the stored changesets.
            const depth = prng.range(1, @min(pair.height, 3));
            pair.height -= @intCast(depth);
            const hash = disk_test.hash_of(pair.heights[pair.height]);
            try pair.address.set_head_retry(hash);
            try pair.hashed.set_head_retry(hash);
            try pair.expect_same();
        }
        if (prng.chance(1, 10)) {
            // A restart: the journal's hashed changesets replay through the same paths.
            if (prng.chance(1, 2)) try pair.hashed.checkpoint();
            try settle(&pair.hashed);
            try pair.hashed.reopen();
            try pair.expect_same();
        }
    }
}

test "database hashed changesets: disk mode commits, unwinds and replays them like addresses" {
    for (0..4) |seed| {
        run_seed(seed) catch |err| {
            std.debug.print("database hashed changesets: failing seed={d}\n", .{seed});
            return err;
        };
    }
}

// Leaves at depth 64: keys that share 63 nibbles hang under a branch at depth 63 with an
// empty path. A walk that starts fresh (after a reopen here; in a long-lived node whenever
// the memo is not carried) knows such a leaf only by its locator and rebuilds it from the
// flat trees (`DiskState.resolve_leaf`), as it does every other leaf.

const trie = @import("../trie/root.zig");

fn hash_hex(comptime text: *const [64]u8) Hash {
    var out: Hash = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // A constant of 64 hex digits.
    return out;
}

/// Commits `accounts` and `slots` (sorted hashed writes) as block `id` on the head.
fn commit_writes(
    node: *Node,
    changeset: *changeset_module.Changeset,
    buffer: []u8,
    id: u32,
    accounts: []const AccountWrite,
    slots: []const SlotWrite,
) !void {
    var header: [8]u8 = undefined;
    std.mem.writeInt(u64, &header, id, .big);
    var block_input: database.BlockInput = .{
        .hash = disk_test.hash_of(id),
        .parent_hash = node.db.head_info.hash,
        .number = node.db.head_info.number + 1,
        .timestamp = id,
        .header = &header,
        .body = "",
        .receipts = "",
        .transaction_hashes = &.{},
        .changeset = "",
    };
    const db = &node.db;
    const reader: Reader = .{ .state = &db.state };
    const writes: overlay_module.HashedWrites = .{ .accounts = accounts, .slots = slots };
    try overlay_module.build_hashed_changeset(reader, writes, changeset);
    try db.state.apply(changeset);
    block_input.changeset = changeset.encode(buffer);
    _ = try db.commit_applied(&block_input);
    try settle(node);
}

/// A checkpoint, a clean stop, and an open: the next walk starts fresh.
fn restart(node: *Node) !void {
    try node.checkpoint();
    try settle(node);
    try node.reopen();
}

/// The proofs of `key` (and `slot`) verify against the head's root and name `word`.
fn expect_proof(node: *Node, key: *const Hash, slot: *const Hash, word: u256) !void {
    const account_proof = try testing.allocator.create(trie.StateTrie.AccountProof);
    defer testing.allocator.destroy(account_proof);
    const storage_proofs = try testing.allocator.alloc(trie.StateTrie.StorageProof, 1);
    defer testing.allocator.free(storage_proofs);
    var values: [1]u256 = undefined;
    const slots = [1]Hash{slot.*};
    const account = try node.db.proof_hashed(key, &slots, account_proof, storage_proofs, &values);
    try testing.expectEqual(word, values[0]);
    var nodes: [trie.sparse.depth_max][]const u8 = undefined;
    for (0..account_proof.count) |index| nodes[index] = account_proof.node_at(@intCast(index));
    const root = node.db.head_info.state_root;
    const leaf = try trie.verify_proof(root, key, nodes[0..account_proof.count]);
    try testing.expect(leaf != null and account != null);
    const proof = &storage_proofs[0];
    for (0..proof.count) |index| nodes[index] = proof.node_at(@intCast(index));
    const value = try trie.verify_proof(account.?.storage_root, slot, nodes[0..proof.count]);
    try testing.expectEqual(word == 0, value == null);
}

test "database hashed changesets: leaves at depth 64 resolve on a fresh walk" {
    const size = disk_test.config_disk.engine.size_bytes();
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = size, .seed = 64 });
    defer sim.deinit(testing.allocator);
    const node = try testing.allocator.create(Node);
    defer testing.allocator.destroy(node);
    try node.init(&sim, disk_test.config_disk);
    defer node.deinit();
    var changeset = try changeset_module.Changeset.init(
        testing.allocator,
        disk_test.config_disk.changeset,
    );
    defer changeset.deinit(testing.allocator);
    const body_max = disk_test.config_disk.engine.entry_body_size_max;
    const buffer = try testing.allocator.alloc(u8, body_max);
    defer testing.allocator.free(buffer);
    try node.format(0x6464);
    var genesis_header: [8]u8 = @splat(0);
    var genesis: database.BlockInput = .{
        .hash = disk_test.hash_of(0),
        .parent_hash = @splat(0),
        .number = 0,
        .timestamp = 0,
        .header = &genesis_header,
        .body = "",
        .receipts = "",
        .transaction_hashes = &.{},
        .changeset = "",
    };
    _ = try node.commit_retry(&genesis);
    try depth_64_slots(node, &changeset, buffer);
    try depth_64_accounts(node, &changeset, buffer);
}

/// Two slots of one account share 63 nibbles; the account's storage is wiped after a
/// restart (the diff fuzzer's first reproducer). Roots from an independent trie.
fn depth_64_slots(node: *Node, changeset: *changeset_module.Changeset, buffer: []u8) !void {
    const key = hash_hex("e8bd19873fbc3a087e3e7b365421ce329b1b9ff3e75238ff4eda892208adcb21");
    const slot_a = hash_hex("7dce463b4b242275b93f9c283881774d280e3abf2ceec46c50fa7d9831a81354");
    const slot_b = hash_hex("7dce463b4b242275b93f9c283881774d280e3abf2ceec46c50fa7d9831a8135b");
    const info: AccountInfo = .{ .nonce = 1 };
    const word_b = std.math.maxInt(u256);
    try commit_writes(node, changeset, buffer, 1, &.{.{ .key = key, .info = info }}, &.{
        .{ .key = key, .slot = slot_a, .value = 0xe8 },
        .{ .key = key, .slot = slot_b, .value = word_b },
    });
    const root_set = hash_hex("2259d05c5a525272f2eb2a8ad2621e99f04177f0279ba129ea393019fcaed18e");
    try testing.expectEqualSlices(u8, &root_set, &node.db.head_info.state_root);
    try restart(node);
    try expect_proof(node, &key, &slot_b, word_b);
    try restart(node);
    try commit_writes(node, changeset, buffer, 2, &.{.{ .key = key, .info = info }}, &.{
        .{ .key = key, .slot = slot_a, .value = 0 },
        .{ .key = key, .slot = slot_b, .value = 0 },
    });
    const root_wiped = hash_hex("c16f0092ffc700391c95efda61c6a0064352dfb1e565d9f3a2e9dc2de7cd8d07");
    try testing.expectEqualSlices(u8, &root_wiped, &node.db.head_info.state_root);
    // Gone for the next part: an account without storage may be deleted.
    try commit_writes(node, changeset, buffer, 3, &.{.{ .key = key, .info = null }}, &.{});
}

/// Accounts 0xff..f7 and 0xff..ff share 63 nibbles; one gains a slot after a restart (the
/// second reproducer). Roots from an independent trie.
fn depth_64_accounts(node: *Node, changeset: *changeset_module.Changeset, buffer: []u8) !void {
    var key_a: Hash = @splat(0xff);
    key_a[31] = 0xf7;
    const key_b: Hash = @splat(0xff);
    const slot_x = hash_hex("0098746e65b7d65b10d81764d12b462608c9726c3adf22bfbff14f6c8d370a36");
    const slot_y = hash_hex("0001ea76e6c723f45ebe843f7164a3705a1eeea12a006473fe31c738a5f09043");
    const info: AccountInfo = .{ .nonce = 1 };
    try commit_writes(node, changeset, buffer, 4, &.{
        .{ .key = key_a, .info = info },
        .{ .key = key_b, .info = info },
    }, &.{.{ .key = key_b, .slot = slot_x, .value = 0x12 }});
    const root_two = hash_hex("51ce7f71637a095fdf7771c271c99b8e4fd476befd786c445316adc6c798461d");
    try testing.expectEqualSlices(u8, &root_two, &node.db.head_info.state_root);
    try restart(node);
    try expect_proof(node, &key_a, &slot_x, 0);
    try restart(node);
    try commit_writes(node, changeset, buffer, 5, &.{.{ .key = key_b, .info = info }}, &.{
        .{ .key = key_b, .slot = slot_y, .value = 0x7621 },
    });
    const root_grown = hash_hex("26667428c38ef4606f6f8d879fdc841a7194461ed02bff6b195647e7c9ccdf17");
    try testing.expectEqualSlices(u8, &root_grown, &node.db.head_info.state_root);
    try restart(node);
    try expect_proof(node, &key_b, &slot_y, 0x7621);
}

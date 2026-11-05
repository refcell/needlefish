//! The chain's historical proofs window (`Chain.attach_history`): after builds, adoptions
//! and reorgs, every canonical block the window reports holds the state that block had
//! when it was the executed state. Oracle: account snapshots taken from the live state
//! right after each block executed, compared with proofs walked from the window.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const fixture = @import("test_fixture.zig");
const history_module = @import("../db/history.zig");
const types = @import("../engine/types.zig");
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const B256 = primitives.B256;
const Node = fixture.Node;
const AccountProof = @import("../trie/state_trie.zig").StateTrie.AccountProof;
const StorageProof = @import("../trie/state_trie.zig").StateTrie.StorageProof;
const HistoryDatabase = @import("history_database.zig").HistoryDatabase;

const blocks_max = 128;

const Snapshot = struct {
    hash: B256,
    receiver_balance: u256,
    sender_nonce: u64,
};

const Harness = struct {
    node: *Node,
    store: history_module.Store,
    snapshots: [blocks_max]Snapshot = undefined,
    snapshots_len: u32 = 0,
    proof: AccountProof = .{},
    storage_proof: StorageProof = .{},
    buffers: [blocks_max][256]u8 = undefined,
    timestamp: u64 = 0,

    fn create(window: u32) !*Harness {
        const h = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(h);
        h.* = .{ .node = undefined, .store = undefined };
        h.node = try Node.create();
        errdefer h.node.destroy();
        h.store = try history_module.Store.init(testing.allocator, .{
            .window_blocks = window,
            .paths_max = 1 << 12,
            .small_versions_max = 1 << 12,
            .large_versions_max = 1 << 10,
            .prune_per_commit = 256,
        });
        errdefer h.store.deinit(testing.allocator);
        try h.node.db.trie().track_changes(testing.allocator);
        try h.node.chain.attach_history(&h.store);
        try h.snapshot(h.node.chain.head_hash());
        return h;
    }

    fn destroy(h: *Harness) void {
        h.node.destroy();
        h.store.deinit(testing.allocator);
        testing.allocator.destroy(h);
    }

    /// Records the live state as the state of `hash` (the executed block).
    fn snapshot(h: *Harness, hash: [32]u8) !void {
        assert(std.mem.eql(u8, &hash, &h.node.chain.state_hash));
        assert(h.snapshots_len < blocks_max);
        const db = &h.node.db;
        const receiver = db.get_account(fixture.address_of(9).bytes);
        const sender = db.get_account(fixture.address_of(1).bytes).?;
        h.snapshots[h.snapshots_len] = .{
            .hash = .{ .bytes = hash },
            .receiver_balance = if (receiver) |r| r.balance else 0,
            .sender_nonce = sender.nonce,
        };
        h.snapshots_len += 1;
    }

    fn find(h: *const Harness, hash: [32]u8) ?Snapshot {
        for (h.snapshots[0..h.snapshots_len]) |entry| {
            if (std.mem.eql(u8, &entry.hash.bytes, &hash)) return entry;
        }
        return null;
    }

    /// Builds a block on `parent` (with one transfer when `transfer`), adopts it as the
    /// head, and snapshots it.
    fn build_head(h: *Harness, parent: B256, transfer: bool, recipient: u8) !B256 {
        h.timestamp += 12;
        if (transfer) {
            const nonce = h.node.db.get_account(fixture.address_of(1).bytes).?.nonce;
            const value: u256 = h.timestamp;
            try fixture.submit(h.node, 1, nonce, value, &h.buffers[h.snapshots_len]);
        }
        const hash = try fixture.build(h.node, parent, h.timestamp, recipient);
        try h.snapshot(hash.bytes);
        const version = types.forkchoice_version(h.node.spec, h.timestamp);
        const updated =
            try h.node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        try testing.expectEqual(types.Status.valid, updated.payload_status.status);
        return hash;
    }

    /// Every canonical block the window serves proves its snapshot; the executed state
    /// is always served. Returns how many blocks were checked.
    fn check(h: *Harness) !u32 {
        const chain = &h.node.chain;
        const window = h.store.window().?;
        const state_header = chain.header(chain.state_hash).?;
        try testing.expectEqual(state_header.number, window.head);
        var checked: u32 = 0;
        var number = window.oldest;
        while (number <= window.head) : (number += 1) {
            const hash = chain.store.canonical_hash(number) orelse continue;
            const header = chain.header(hash).?;
            if (!chain.history_has(number, header.state_root.bytes)) continue;
            const expected = h.find(hash).?;
            const sender = (try h.store.prove_account(
                number,
                fixture.address_of(1).bytes,
                &h.proof,
            )).?;
            try testing.expectEqual(expected.sender_nonce, sender.nonce);
            const receiver = try h.store.prove_account(
                number,
                fixture.address_of(9).bytes,
                &h.proof,
            );
            const balance = if (receiver) |r| r.balance else 0;
            try testing.expectEqual(expected.receiver_balance, balance);
            try h.check_database(hash, number, expected);
            checked += 1;
        }
        return checked;
    }

    /// The evm-facing reads (`HistoryDatabase`) agree with the snapshot too.
    fn check_database(h: *Harness, hash: [32]u8, number: u64, expected: Snapshot) !void {
        var history: HistoryDatabase = .{
            .chain = &h.node.chain,
            .hash = hash,
            .number = number,
            .account_proof = &h.proof,
            .storage_proof = &h.storage_proof,
        };
        const database = history.database();
        const sender = (try database.basic(fixture.address_of(1).bytes)).?;
        try testing.expectEqual(expected.sender_nonce, sender.nonce);
        try testing.expect(!sender.has_storage);
        const receiver = try database.basic(fixture.address_of(9).bytes);
        try testing.expectEqual(expected.receiver_balance, if (receiver) |r| r.balance else 0);
        try testing.expectEqual(@as(u256, 0), try database.storage(fixture.address_of(9).bytes, 1));
        try testing.expectEqual(@as(usize, 0), (try database.code_by_hash(sender.code_hash)).len);
        try testing.expect(history.failure == null);
    }
};

test "history: canonical blocks prove their balances and the window slides" {
    const h = try Harness.create(4);
    defer h.destroy();
    var head = h.node.chain.head_hash();
    var hashes: [6]B256 = undefined;
    for (&hashes, 0..) |*hash, index| {
        hash.* = try h.build_head(.{ .bytes = head }, true, @intCast(0x40 + index));
        head = hash.bytes;
        try testing.expect(try h.check() >= 1);
    }
    const window = h.store.window().?;
    try testing.expectEqual(@as(u64, 6), window.head);
    try testing.expectEqual(@as(u64, 3), window.oldest);
    try testing.expectEqual(@as(u32, 4), try h.check());
    const first = h.node.chain.header(hashes[0].bytes).?;
    try testing.expect(!h.node.chain.history_has(1, first.state_root.bytes));
    try testing.expectEqual(@as(u64, 0), h.node.chain.history_resets);
}

test "history: a fork from a block in the window unwinds instead of resetting" {
    const h = try Harness.create(8);
    defer h.destroy();
    var hashes: [5]B256 = undefined;
    var head = h.node.chain.head_hash();
    for (&hashes, 0..) |*hash, index| {
        hash.* = try h.build_head(.{ .bytes = head }, true, @intCast(0x40 + index));
        head = hash.bytes;
    }
    // Sibling of block 4 on block 3: no transfer, a different fee recipient.
    const sibling = try h.build_head(hashes[2], false, 0x77);
    const window = h.store.window().?;
    try testing.expectEqual(@as(u64, 4), window.head);
    try testing.expectEqual(@as(u32, 5), try h.check());
    try testing.expectEqual(@as(u64, 0), h.node.chain.history_resets);
    const old = h.node.chain.header(hashes[3].bytes).?;
    try testing.expect(!h.node.chain.history_has(4, old.state_root.bytes));
    const new = h.node.chain.header(sibling.bytes).?;
    try testing.expect(h.node.chain.history_has(4, new.state_root.bytes));
}

fn fuzz_scenario(seed: u64) !void {
    var prng = Prng.init(seed);
    const window: u32 = @intCast(prng.range(2, 8));
    const h = try Harness.create(window);
    defer h.destroy();
    var head = h.node.chain.head_hash();
    const steps = prng.range(4, 24);
    for (0..steps) |step| {
        var parent = head;
        const number = h.node.chain.header(head).?.number;
        if (number > 0 and prng.chance(1, 4)) {
            // Reorg: build on an ancestor up to four blocks back.
            const back = @min(number, prng.range(1, 4));
            parent = h.node.chain.store.canonical_hash(number - back).?;
        }
        const transfer = prng.chance(2, 3);
        head = (try h.build_head(.{ .bytes = parent }, transfer, @intCast(step))).bytes;
        _ = try h.check();
    }
}

test "history: seeded fuzz of builds and reorgs" {
    for (0..8) |seed| try fuzz_scenario(seed + 300);
}

fn fuzz_history(_: void, smith: *testing.Smith) anyerror!void {
    try fuzz_scenario(smith.value(u64));
}

test "history: fuzz" {
    try testing.fuzz({}, fuzz_history, .{});
}

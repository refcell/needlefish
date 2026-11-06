//! `replay_roots`: synthetic block diffs proven from a full `StateTrie` before and after,
//! replayed through the sparse state, must reproduce the post roots, and report the branch
//! collapses no proof can complete.

const std = @import("std");
const testing = std.testing;

const trie = @import("../trie/root.zig");
const replay = @import("replay_roots.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const node = trie.node;
const StateTrie = trie.StateTrie;
const Hash = replay.Hash;
const Address = replay.Address;

const accounts_count = 48;
const slots_per_account = 6;
/// Holds two slots; the block deletes the proven one, so its root branch collapses into
/// the unproven leaf (derivable from the block's exclusion proof).
const collapse_leaf_account = 11;
/// Holds three slots; deleting the proven one collapses the root branch into a branch over
/// the two unproven ones (no proof holds it).
const collapse_branch_account = 12;

fn address_of(index: u32) Address {
    var address: Address = @splat(0);
    std.mem.writeInt(u32, address[16..20], index + 1, .big);
    return address;
}

fn slot_hash(slot: u256) Hash {
    var bytes: Hash = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return node.keccak256(&bytes);
}

/// Three slots: `lone` alone under its first nibble, `pair` two sharing another one.
const Triple = struct { lone: u256, pair: [2]u256 };

fn branch_triple() Triple {
    const lone: u256 = 0;
    const lone_nibble = slot_hash(lone)[0] >> 4;
    var pair: [2]u256 = undefined;
    var found: u32 = 0;
    var first_nibble: u8 = 0;
    var slot: u256 = 1;
    while (found < 2) : (slot += 1) {
        std.debug.assert(slot < 1024);
        const nibble = slot_hash(slot)[0] >> 4;
        if (nibble == lone_nibble) continue;
        if (found == 1 and nibble != first_nibble) continue;
        first_nibble = nibble;
        pair[found] = slot;
        found += 1;
    }
    return .{ .lone = lone, .pair = pair };
}

/// The slots proven for account `index`: the touched ones only for the collapse accounts.
fn proven_slots(arena: std.mem.Allocator, index: u32) ![]const u256 {
    if (index == collapse_leaf_account) return arena.dupe(u256, &.{0});
    if (index == collapse_branch_account) return arena.dupe(u256, &.{branch_triple().lone});
    const slots = try arena.alloc(u256, slots_per_account);
    for (slots, 0..) |*slot, slot_index| slot.* = slot_index;
    return slots;
}

fn copy_nodes(arena: std.mem.Allocator, proof: anytype) ![]const []const u8 {
    const out = try arena.alloc([]const u8, proof.count);
    for (out, 0..) |*bytes, index| bytes.* = try arena.dupe(u8, proof.node_at(@intCast(index)));
    return out;
}

/// `eth_getProof` for accounts `0..count` and their `proven_slots`, from `state`.
fn prove(arena: std.mem.Allocator, state: *StateTrie, count: u32) ![]replay.AccountProof {
    const out = try arena.alloc(replay.AccountProof, count);
    const account_proof = try arena.create(StateTrie.AccountProof);
    const storage_proof = try arena.create(StateTrie.StorageProof);
    for (out, 0..) |*result, index| {
        const address = address_of(@intCast(index));
        const address_hash = node.keccak256(&address);
        try state.prove_account(address_hash, account_proof);
        const account = state.get_account(address_hash) orelse trie.Account{};
        const keys = try proven_slots(arena, @intCast(index));
        const slots = try arena.alloc(replay.SlotProof, keys.len);
        for (slots, keys) |*slot, key| {
            state.prove_storage(address_hash, slot_hash(key), storage_proof);
            slot.* = .{
                .slot = key,
                .value = state.get_storage(address_hash, slot_hash(key)),
                .proof = try copy_nodes(arena, storage_proof),
            };
        }
        result.* = .{
            .address = address,
            .nonce = account.nonce,
            .balance = account.balance,
            .code_hash = account.code_hash,
            .storage_hash = state.storage_root(address_hash),
            .proof = try copy_nodes(arena, account_proof),
            .slots = slots,
        };
    }
    return out;
}

fn seed_state(state: *StateTrie, prng: *Prng, branch_case: bool) !void {
    for (0..accounts_count) |index| {
        const address_hash = node.keccak256(&address_of(@intCast(index)));
        try state.set_account(address_hash, .{ .nonce = index, .balance = prng.int(u64) + 1 });
        if (index == collapse_leaf_account) {
            try state.set_storage(address_hash, slot_hash(0), 3);
            try state.set_storage(address_hash, slot_hash(1), 4);
        } else if (index == collapse_branch_account) {
            if (!branch_case) continue;
            const triple = branch_triple();
            try state.set_storage(address_hash, slot_hash(triple.lone), 5);
            for (triple.pair) |slot| try state.set_storage(address_hash, slot_hash(slot), 6);
        } else for (0..slots_per_account) |slot| {
            try state.set_storage(address_hash, slot_hash(slot), prng.int(u32) + 1);
        }
    }
}

/// A block: balance changes, slot writes and deletes (emptying one storage trie, collapsing
/// another into an unproven leaf), one account deleted and one created.
fn mutate(state: *StateTrie, prng: *Prng) !void {
    for (0..8) |index| {
        const address_hash = node.keccak256(&address_of(@intCast(index)));
        try state.set_account(address_hash, .{ .nonce = index + 1, .balance = prng.int(u64) });
        try state.set_storage(address_hash, slot_hash(index % slots_per_account), 0);
        try state.set_storage(address_hash, slot_hash(1), prng.int(u32) + 1);
    }
    const emptied = node.keccak256(&address_of(9));
    for (0..slots_per_account) |slot| try state.set_storage(emptied, slot_hash(slot), 0);
    try state.set_storage(node.keccak256(&address_of(collapse_leaf_account)), slot_hash(0), 0);
    try state.delete_account(node.keccak256(&address_of(10)));
    const created = node.keccak256(&address_of(accounts_count));
    try state.set_account(created, .{ .nonce = 1, .balance = 5 });
    try state.set_storage(created, slot_hash(2), 7);
}

const Fixture = struct {
    state: StateTrie,
    input: replay.StateInput,

    fn init(arena: std.mem.Allocator, branch_case: bool) !Fixture {
        var state = try StateTrie.init(testing.allocator, .{
            .accounts_max = 256,
            .account_nodes_max = 4096,
            .storage_nodes_max = 16384,
        });
        errdefer state.deinit(testing.allocator);
        var prng = Prng.init(11);
        try seed_state(&state, &prng, branch_case);
        const pre_root = try state.root();
        const pre = try prove(arena, &state, accounts_count + 1);
        try mutate(&state, &prng);
        if (branch_case) {
            const address_hash = node.keccak256(&address_of(collapse_branch_account));
            try state.set_storage(address_hash, slot_hash(branch_triple().lone), 0);
        }
        const post_root = try state.root();
        return .{ .state = state, .input = .{
            .parent_number = 1,
            .parent_hash = @splat(1),
            .parent_root = pre_root,
            .post_root = post_root,
            .pre = pre,
            .post = try prove(arena, &state, accounts_count + 1),
        } };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.state.deinit(testing.allocator);
    }
};

test "replay_roots: synthetic diff from proofs reproduces the post state root" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var fixture = try Fixture.init(arena_state.allocator(), false);
    defer fixture.deinit();
    const input = fixture.input;
    var checker = try replay.Checker.init(testing.allocator);
    defer checker.deinit(testing.allocator);

    // The collapse into the unproven leaf needs it: only the derived seed has it.
    const replays = try checker.check(input);
    try testing.expectEqual(@as(u32, 3), replays.count);
    try testing.expectEqual(replay.Status.incomplete, replays.slice()[0].status);
    try testing.expect(replays.slice()[0].missing_node != null);
    try testing.expectEqual(replay.Status.incomplete, replays.slice()[1].status);
    const report = replays.verdict();
    try testing.expectEqual(replay.Seed.derived, report.seed);
    try testing.expectEqual(replay.Status.ok, report.status);
    try testing.expectEqual(input.post_root, report.root);
    try testing.expect(report.accounts_changed >= 10);
    try testing.expect(report.slots_changed > 0);

    // Post proofs against the parent root do not verify; neither does a tampered value.
    var wrong = input;
    wrong.post_root = input.parent_root;
    const wrong_replays = try checker.check(wrong);
    try testing.expectEqual(replay.Status.invalid_proof, wrong_replays.verdict().status);
    input.post[3].balance += 1;
    const tampered_replays = try checker.check(input);
    const tampered = tampered_replays.verdict();
    try testing.expectEqual(replay.Status.invalid_proof, tampered.status);
    try testing.expect(tampered.failure_post);
    try testing.expectEqualSlices(u8, &address_of(3), &tampered.failure.?.address);
}

test "replay_roots: a collapse into an unproven branch stays incomplete" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var fixture = try Fixture.init(arena_state.allocator(), true);
    defer fixture.deinit();
    var checker = try replay.Checker.init(testing.allocator);
    defer checker.deinit(testing.allocator);
    const replays = try checker.check(fixture.input);
    try testing.expectEqual(@as(u32, 3), replays.count);
    const report = replays.verdict();
    try testing.expectEqual(replay.Status.incomplete, report.status);
    // The missing node is the surviving branch, referenced by the block's new extension.
    const missing = report.missing_node.?;
    var referenced = false;
    for (fixture.input.post) |*account| {
        for (account.slots) |*slot| {
            for (slot.proof) |bytes| {
                referenced = referenced or std.mem.indexOf(u8, bytes, &missing) != null;
            }
        }
    }
    try testing.expect(referenced);
}

test "replay_roots: merge folds extra keys into listed accounts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const empty: []const []const u8 = &.{};
    var base_slots = [_]replay.SlotProof{.{ .slot = 1, .value = 0, .proof = empty }};
    var listed = [_]replay.AccountProof{.{
        .address = address_of(0),
        .nonce = 0,
        .balance = 0,
        .code_hash = node.empty_code_hash,
        .storage_hash = node.empty_root,
        .proof = empty,
        .slots = &base_slots,
    }};
    const extra_slots = [_]replay.SlotProof{
        .{ .slot = 1, .value = 0, .proof = empty },
        .{ .slot = 2, .value = 0, .proof = empty },
    };
    var extra = listed;
    extra[0].slots = &extra_slots;
    var other = listed;
    other[0].address = address_of(1);
    const merged = try replay.merge_proofs(arena, &listed, &(extra ++ other));
    try testing.expectEqual(@as(usize, 2), merged.len);
    try testing.expectEqual(@as(usize, 2), merged[0].slots.len);
    try testing.expectEqual(@as(u256, 2), merged[0].slots[1].slot);
    try testing.expectEqualSlices(u8, &address_of(1), &merged[1].address);
}

test "replay_roots: receipts root of a deposit and a typed receipt" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const zeros: [512]u8 = @splat('0');
    const bloom = "0x" ++ zeros;
    const text =
        \\[{"type":"0x7e","status":"0x1","cumulativeGasUsed":"0xb48a","logs":[],
        \\"depositNonce":"0x3361482","depositReceiptVersion":"0x1","logsBloom":"
    ++ bloom ++
        \\"},{"type":"0x2","status":"0x0","cumulativeGasUsed":"0x1732f","logs":[],"logsBloom":"
    ++ bloom ++
        \\"}]
    ;
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    const root = try replay.receipts_root(arena, value);
    // Expected: the ordered trie of the same receipts built with the consensus encoder.
    const receipt = @import("../../common/consensus/root.zig").receipt;
    var first_buffer: [512]u8 = undefined;
    var second_buffer: [512]u8 = undefined;
    const first: receipt.Receipt = .{
        .tx_type = .deposit,
        .status = true,
        .cumulative_gas_used = 0xb48a,
        .deposit_nonce = 0x3361482,
        .deposit_receipt_version = 1,
    };
    const second: receipt.Receipt = .{
        .tx_type = .eip1559,
        .status = false,
        .cumulative_gas_used = 0x1732f,
    };
    const items = [_][]const u8{
        first.encode_to(&first_buffer),
        second.encode_to(&second_buffer),
    };
    try testing.expectEqual(trie.ordered.ordered_trie_root(&items), root);
}

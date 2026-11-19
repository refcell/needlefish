//! The trie mode's read and history paths on the node, database by database (`trie.zig` drives
//! the same calls per request): blocks of a few hundred writes with preimages and codes, two
//! native unwinds (and the same blocks again) every seven, then
//! - every block read again through a history view of `disk-view-history`'s database
//!   (`DiskState.view_begin` over the archive, `trie_history.zig`), by trie key and by address;
//! - every code read back from the primary's and the view database's code tables (the view
//!   database is `config_disk_small`: its code store flushes, rewrites and reads tables);
//! - `memory-history`'s database restarted (the window rebuilt) and every block proven again at
//!   its number by `proof_at` and `proofs_at`;
//! each against what the primary answered right after that block.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const trie = @import("../../execution/trie/root.zig");
const db = @import("../../execution/db/root.zig");
const trie_node = @import("trie_node.zig");
const trie_model = @import("trie_model.zig");
const trie_request = @import("trie_request.zig");
const Archive = @import("trie_history.zig").Archive;
const Prng = @import("../../testing/prng.zig").Prng;
const build_options = @import("build_options");

const Hash = [32]u8;
const Address = [20]u8;
const Node = trie_node.Node;
const Op = trie_request.Op;
const HashedWrites = db.overlay.HashedWrites;
const keccak256 = trie.node.keccak256;

const keys_count = 256;
const slots_count = 16;
/// Codes in all; each block may set the first two more than the block before, so new codes
/// come with most blocks (and so do code flushes).
const codes_count = 64;
const blocks_count = 30;
const block_writes = 200;
const targets_count = 4;

const Run = struct {
    prng: Prng,
    model: trie_model.Model,
    addresses: [keys_count]Address = undefined,
    keys: [keys_count]Hash = undefined,
    slot_keys: [slots_count]Hash = undefined,
    slots: [slots_count]Hash = undefined,
    codes: [codes_count][]const u8 = undefined,
    ops: [block_writes]Op = undefined,
    codes_used: u32 = 0,
    /// Codes some block set.
    codes_set: [codes_count]bool = @splat(false),

    fn init(arena: std.mem.Allocator, seed: u64) !Run {
        var run: Run = .{ .prng = Prng.init(seed), .model = .{ .arena = arena } };
        for (&run.addresses, &run.keys) |*address, *key| {
            run.prng.fill(address);
            key.* = keccak256(address);
        }
        for (&run.slot_keys, &run.slots) |*slot_key, *slot| {
            run.prng.fill(slot_key);
            slot.* = keccak256(slot_key);
        }
        for (&run.codes, 0..) |*code, index| {
            // Most fit a disk-small code table record; one in four, up to the evm's largest,
            // does not (it stays in the arena and the checkpoint image).
            const long = index % 4 == 3;
            const size: u64 = if (long) trie_request.code_size_max else 3000;
            const bytes = try arena.alloc(u8, run.prng.range(1, size));
            run.prng.fill(bytes);
            code.* = bytes;
        }
        return run;
    }

    /// One block's ops (no empty account; one account write in eight sets a code), applied
    /// to the model; its writes and a copy of its ops.
    fn block(run: *Run, arena: std.mem.Allocator) !struct { HashedWrites, []const Op } {
        var touched: trie_model.Touched = .{};
        var codes: std.ArrayList([]const u8) = .empty;
        run.codes_used = @min(codes_count, run.codes_used + 2);
        for (&run.ops, 0..) |*op, index| {
            const which = run.prng.below(keys_count);
            const key = run.keys[which];
            const exists = run.model.find(&key) != null;
            const choice = run.prng.below(100);
            op.* = .{ .kind = .account, .key = key, .address = run.addresses[which] };
            if (exists and choice < 60) {
                const slot = run.prng.below(slots_count);
                op.kind = .storage;
                op.slot = run.slots[slot];
                op.slot_key = run.slot_keys[slot];
                op.value = if (run.prng.chance(1, 5)) 0 else run.prng.range(1, 1 << 60);
            } else if (exists and choice < 62) {
                op.kind = .wipe;
            } else if (exists and choice < 64) {
                op.kind = .delete;
            } else {
                op.info = .{ .nonce = run.prng.range(1, 1 << 20), .balance = run.prng.int(u64) };
                if (run.prng.chance(1, 8)) {
                    const code_index = run.prng.below(run.codes_used);
                    const code = run.codes[code_index];
                    run.codes_set[code_index] = true;
                    op.info.code_hash = keccak256(code);
                    op.code = code;
                    const listed = for (codes.items) |item| {
                        if (item.ptr == code.ptr) break true;
                    } else false;
                    if (!listed) try codes.append(arena, code);
                }
            }
            try run.model.apply(run.ops[index..][0..1], &touched);
        }
        var writes = try run.model.writes(&touched);
        writes.codes = codes.items;
        return .{ writes, try arena.dupe(Op, &run.ops) };
    }
};

/// A proof as the primary answered it: the account, its node list, and per slot the value and
/// node list.
const Recorded = struct {
    target: usize,
    account: ?trie_node.AccountState,
    nodes: []const []const u8,
    values: [2]u256,
    slot_nodes: [2][]const []const u8,
};

const Proofs = struct {
    account: *trie_node.AccountProof,
    storage: []trie_node.StorageProof,

    fn create() !Proofs {
        const account = try testing.allocator.create(trie_node.AccountProof);
        errdefer testing.allocator.destroy(account);
        return .{
            .account = account,
            .storage = try testing.allocator.alloc(trie_node.StorageProof, 2),
        };
    }

    fn destroy(proofs: *Proofs) void {
        testing.allocator.free(proofs.storage);
        testing.allocator.destroy(proofs.account);
    }
};

fn nodes_copy(arena: std.mem.Allocator, proof: anytype) ![]const []const u8 {
    const nodes = try arena.alloc([]const u8, proof.count);
    for (nodes, 0..) |*item, index| item.* = try arena.dupe(u8, proof.node_at(@intCast(index)));
    return nodes;
}

fn expect_nodes(want: []const []const u8, proof: anytype) !void {
    try testing.expectEqual(want.len, proof.count);
    for (want, 0..) |bytes, index| {
        try testing.expectEqualSlices(u8, bytes, proof.node_at(@intCast(index)));
    }
}

fn target_slots(run: *const Run, target: usize) [2]Hash {
    return .{ run.slots[target % slots_count], run.slots[(target * 7 + 3) % slots_count] };
}

fn target_slot_words(run: *const Run, target: usize) [2]u256 {
    return .{
        std.mem.readInt(u256, &run.slot_keys[target % slots_count], .big),
        std.mem.readInt(u256, &run.slot_keys[(target * 7 + 3) % slots_count], .big),
    };
}

/// The primary's proof of `target` (by trie key).
fn record(arena: std.mem.Allocator, run: *const Run, node: *Node, target: usize) !Recorded {
    var proofs = try Proofs.create();
    defer proofs.destroy();
    const slots = target_slots(run, target);
    var values: [2]u256 = undefined;
    const account = try node.db.proof_hashed(
        &run.keys[target],
        &slots,
        proofs.account,
        proofs.storage,
        &values,
    );
    return .{
        .target = target,
        .account = account,
        .nodes = try nodes_copy(arena, proofs.account),
        .values = values,
        .slot_nodes = .{
            try nodes_copy(arena, &proofs.storage[0]),
            try nodes_copy(arena, &proofs.storage[1]),
        },
    };
}

/// `node` answers `want` (by trie key, then by address); in a view or at the head.
fn expect_disk_answers(run: *const Run, node: *Node, want: *const Recorded) !void {
    var proofs = try Proofs.create();
    defer proofs.destroy();
    const slots = target_slots(run, want.target);
    var values: [2]u256 = undefined;
    const by_key = try node.db.proof_hashed(
        &run.keys[want.target],
        &slots,
        proofs.account,
        proofs.storage,
        &values,
    );
    try expect_answer(want, by_key, &proofs, values);
    const address = run.addresses[want.target];
    const words = target_slot_words(run, want.target);
    const number = node.db.head_info.number;
    const by_address =
        try node.db.proof_at(number, address, &words, proofs.account, proofs.storage, &values);
    try expect_answer(want, by_address, &proofs, values);
    // eth_getBalance and eth_getStorageAt's reads.
    const info = node.db.state.basic(address);
    try testing.expectEqual(want.account == null, info == null);
    if (info) |found| try testing.expectEqual(want.account.?.nonce, found.nonce);
    for (words, want.values) |word, value| {
        try testing.expectEqual(value, node.db.state.storage(address, word));
    }
}

fn expect_answer(
    want: *const Recorded,
    account: ?trie_node.AccountState,
    proofs: *const Proofs,
    values: [2]u256,
) !void {
    try testing.expectEqualDeep(want.account, account);
    try expect_nodes(want.nodes, proofs.account);
    for (want.values, values, want.slot_nodes, proofs.storage) |a, b, nodes, *proof| {
        try testing.expectEqual(a, b);
        try expect_nodes(nodes, proof);
    }
}

/// `memory-history`'s ops by address, as `trie.zig` puts them into the overlay.
fn overlay_commit(node: *Node, ops: []const Op) !void {
    const overlay = &node.overlay;
    for (ops) |*op| {
        const address = op.address.?;
        switch (op.kind) {
            .account => {
                if (op.code) |code| _ = try overlay.insert_code(code);
                try overlay.set_account(address, op.info);
            },
            .storage => {
                const slot = std.mem.readInt(u256, &op.slot_key.?, .big);
                try overlay.set_storage(address, slot, op.value);
            },
            .wipe => if (overlay.basic(address) != null) try overlay.wipe_storage(address),
            .delete => if (overlay.basic(address) != null) try overlay.set_account(address, null),
        }
    }
    try node.commit_overlay();
}

const Nodes = struct {
    primary: *Node,
    view: *Node,
    history: *Node,
    archive: *Archive,

    fn commit(nodes: Nodes, writes: HashedWrites, ops: []const Op, root: Hash) !void {
        try nodes.primary.commit_hashed(writes);
        try nodes.view.commit_hashed(writes);
        try nodes.archive.take(nodes.view);
        try overlay_commit(nodes.history, ops);
        for ([_]*Node{ nodes.primary, nodes.view, nodes.history }) |node| {
            try testing.expectEqualSlices(u8, &root, &node.state_root());
        }
    }

    fn unwind_to(nodes: Nodes, height: u64, root: Hash) !void {
        for ([_]*Node{ nodes.primary, nodes.view, nodes.history }) |node| {
            try testing.expect(try node.unwind_to(height));
            try testing.expectEqualSlices(u8, &root, &node.state_root());
        }
        nodes.archive.truncate(height);
    }
};

test "diff trie: history views, codes, prefetch and the history window on the node" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    var paths: [3][]const u8 = undefined;
    for (&paths, [_][]const u8{ "primary", "view", "history" }) |*path, name| {
        path.* = try std.fmt.allocPrint(arena, "{s}/{s}.db", .{ dir, name });
    }
    const primary = try Node.create(testing.allocator, .disk, paths[0]);
    defer primary.destroy();
    var view: ?*Node = try Node.create(testing.allocator, .disk_small, paths[1]);
    defer if (view) |node| node.destroy();
    try view.?.capture_enable();
    var history: ?*Node = try Node.create(testing.allocator, .memory_history, paths[2]);
    defer if (history) |node| node.destroy();
    var archive = try Archive.init(arena, testing.allocator);
    defer archive.deinit(testing.allocator);
    var run = try Run.init(arena, 0x4157_0000 + build_options.fuzz_seed);
    const nodes: Nodes = .{
        .primary = primary,
        .view = view.?,
        .history = history.?,
        .archive = &archive,
    };
    var roots: [blocks_count + 1]Hash = undefined;
    roots[0] = trie.empty_root;
    var recorded: [blocks_count + 1][targets_count]Recorded = undefined;
    var blocks: [blocks_count]struct { HashedWrites, []const Op } = undefined;
    for (0..blocks_count) |index| {
        blocks[index] = try run.block(arena);
        roots[index + 1] = try run.model.state_root();
        try nodes.commit(blocks[index][0], blocks[index][1], roots[index + 1]);
        if (index % 7 == 6) {
            try nodes.unwind_to(index - 1, roots[index - 1]);
            for (blocks[index - 1 ..][0..2], roots[index..][0..2]) |again, root| {
                try nodes.commit(again[0], again[1], root);
            }
        }
        for (&recorded[index + 1]) |*item| {
            item.* = try record(arena, &run, primary, run.prng.below(keys_count));
        }
    }
    try expect_views(&run, nodes.view, &archive, &roots, &recorded);
    try testing.expect(nodes.view.stats.prefetches >= nodes.view.stats.commits);
    // The view database's tiny code store flushed every checkpoint and rewrote its tables.
    const code_stats = nodes.view.db.code_store.?.stats;
    try testing.expect(code_stats.flushes >= blocks_count / 2);
    try testing.expect(code_stats.rewrites >= 2);
    view = null;
    view = try nodes.view.reopen(null);
    try expect_codes(&run, primary, view.?);
    history = null;
    history = try nodes.history.reopen(null);
    try expect_history(&run, history.?, &roots, &recorded);
}

/// Every block through a view of it equals the primary's answers then; the archive answered
/// some lookups (the rest read the head's trees).
fn expect_views(
    run: *const Run,
    view: *Node,
    archive: *Archive,
    roots: []const Hash,
    recorded: []const [targets_count]Recorded,
) !void {
    const disk = &view.db.disk.?;
    for (1..blocks_count + 1) |height| {
        archive.view_height = height;
        disk.view_begin(roots[height], archive.overlay());
        defer disk.view_end();
        for (&recorded[height]) |*want| try expect_disk_answers(run, view, want);
    }
    try testing.expect(archive.lookups_archived > 0);
    try testing.expect(archive.lookups > archive.lookups_archived);
}

/// Every code set reads back from both databases (eth_getCode).
fn expect_codes(run: *const Run, primary: *Node, view: *Node) !void {
    var codes_read: u32 = 0;
    for (run.codes, run.codes_set) |code, set| {
        if (!set) continue;
        codes_read += 1;
        const hash = keccak256(code);
        for ([_]*Node{ primary, view }) |node| {
            const found = node.db.state.code_by_hash(hash) orelse
                return error.TestUnexpectedResult;
            try testing.expectEqualSlices(u8, code, found);
            node.db.codes_release();
        }
    }
    try testing.expect(codes_read >= codes_count / 2);
    // Read from the tables: the reopened database keeps only where each table code is.
    try testing.expect(view.db.code_store.?.stats.reads > 0);
}

/// The restarted window holds every block (rebuilt by re-applying them); each block proven
/// at its number equals the primary's answers then, by `proof_at` and by `proofs_at`.
fn expect_history(
    run: *const Run,
    history: *Node,
    roots: []const Hash,
    recorded: []const [targets_count]Recorded,
) !void {
    try testing.expect(history.db.history_rebuild_commits >= blocks_count - 1);
    const store = history.db.history_reader().?;
    var proofs = try Proofs.create();
    defer proofs.destroy();
    var set = try db.history.ProofSet.init(testing.allocator, 2);
    defer set.deinit(testing.allocator);
    for (1..blocks_count + 1) |height| {
        try testing.expectEqualSlices(u8, &roots[height], &(try store.state_root_at(height)));
        for (&recorded[height]) |*want| {
            const address = run.addresses[want.target];
            const words = target_slot_words(run, want.target);
            var values: [2]u256 = undefined;
            const single = try history.db.proof_at(
                height,
                address,
                &words,
                proofs.account,
                proofs.storage,
                &values,
            );
            try expect_answer(want, single, &proofs, values);
            const multi = try history.db.proofs_at(height, address, &words, proofs.account, &set);
            try testing.expectEqualDeep(want.account, multi);
            for (0..2) |index| {
                set.fill(@intCast(index), &proofs.storage[index]);
                values[index] = set.value(@intCast(index));
            }
            try expect_answer(want, multi, &proofs, values);
        }
    }
}

/// The codes `node`'s last block listed in its changeset.
fn listed_codes(node: *Node) !u32 {
    var changeset = try db.Changeset.init(testing.allocator, trie_node.changeset_config);
    defer changeset.deinit(testing.allocator);
    try changeset.decode(node.state_db.last_changeset().?);
    return changeset.codes_len;
}

test "diff trie: commit_hashed lists a block's codes as an evm block's commit does" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const path = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/small.db", .{tmp.sub_path});
    var node = try Node.create(testing.allocator, .disk_small, path);
    defer node.destroy();
    const code_a: []const u8 = &.{ 0x60, 0x01 };
    const code_b: []const u8 = &(@as([3000]u8, @splat(0x5b)));
    const keys = [3]Hash{ @splat(0x11), @splat(0x22), @splat(0x33) };
    const with_a: db.AccountInfo = .{ .nonce = 1, .code_hash = keccak256(code_a) };
    // New codes, each once however often the block names it.
    try node.commit_hashed(.{
        .accounts = &.{.{ .key = keys[0], .info = with_a }},
        .slots = &.{},
        .codes = &.{ code_a, code_b },
    });
    try testing.expectEqual(@as(u32, 2), try listed_codes(node));
    // A code in the arena that an account change sets is listed again (`add_set_codes`);
    // one an unchanged account keeps, or no account sets, is not.
    try node.commit_hashed(.{
        .accounts = &.{ .{ .key = keys[0], .info = with_a }, .{ .key = keys[1], .info = with_a } },
        .slots = &.{},
        .codes = &.{ code_a, code_b },
    });
    try testing.expectEqual(@as(u32, 1), try listed_codes(node));
    // After a restart the codes are in their tables only: known, never listed again.
    node = try node.reopen(null);
    try testing.expect(node.db.state.code_in_arena(keccak256(code_a)) == null);
    try node.commit_hashed(.{
        .accounts = &.{.{ .key = keys[2], .info = with_a }},
        .slots = &.{},
        .codes = &.{code_a},
    });
    try testing.expectEqual(@as(u32, 0), try listed_codes(node));
    try testing.expectEqualSlices(u8, code_b, node.db.state.code_by_hash(keccak256(code_b)).?);
    node.db.codes_release();
}

// Power losses that tear an in-flight write (`Node.restart_torn`), on `disk-small`'s config
// as `disk-small-reopen` runs them: the block's own journal entry (the block is lost and
// committed again), a checkpoint block, or a superblock copy; and a crash that drops the
// writes in flight. Native unwinds across them. After every restart the database agrees
// with the primary.

const torn_blocks = 24;

test "diff trie: torn writes: every open rejects them and recovers the durable state" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const primary_path = try std.fmt.allocPrint(arena, "{s}/primary.db", .{dir});
    const small_path = try std.fmt.allocPrint(arena, "{s}/small.db", .{dir});
    const primary = try Node.create(testing.allocator, .disk, primary_path);
    defer primary.destroy();
    var small: ?*Node = try Node.create(testing.allocator, .disk_small, small_path);
    defer if (small) |node| node.destroy();
    var run = try Run.init(arena, 0x7042_0000 + build_options.fuzz_seed);
    var blocks: [torn_blocks]HashedWrites = undefined;
    var roots: [torn_blocks + 1]Hash = undefined;
    roots[0] = trie.empty_root;
    for (0..torn_blocks) |index| {
        blocks[index] = (try run.block(arena))[0];
        roots[index + 1] = try run.model.state_root();
        try primary.commit_hashed(blocks[index]);
        small = try torn_block(small.?, blocks[index], index);
        try testing.expectEqualSlices(u8, &roots[index + 1], &small.?.state_root());
        if (index % 7 == 6) {
            // Two blocks back natively on the restarted database, then the same two again.
            for ([2]*Node{ primary, small.? }) |node| {
                try testing.expect(try node.unwind_to(index - 1));
                try testing.expectEqualSlices(u8, &roots[index - 1], &node.state_root());
            }
            for (blocks[index - 1 ..][0..2], roots[index..][0..2]) |again, root| {
                try primary.commit_hashed(again);
                try small.?.commit_hashed(again);
                try testing.expectEqualSlices(u8, &root, &small.?.state_root());
            }
        }
        for (0..targets_count) |_| {
            const want = try record(arena, &run, primary, run.prng.below(keys_count));
            try expect_disk_answers(&run, small.?, &want);
        }
    }
    try expect_torn(small.?.stats);
}

/// Block `index` on `node` with a restart in turn: its journal entry torn (lost, then
/// committed again), a checkpoint block torn, a superblock copy torn, its writes in flight
/// dropped. Returns the restarted node (`node` is gone).
fn torn_block(node: *Node, writes: HashedWrites, index: usize) !*Node {
    const variant: u32 = @intCast(index / 4);
    switch (index % 4) {
        0 => {
            const restarted = try node.restart_torn(.journal, variant, writes);
            try testing.expectEqual(restarted.height, restarted.db.head_info.number);
            try restarted.commit_hashed(writes);
            return restarted;
        },
        1 => {
            try node.commit_hashed(writes);
            return node.restart_torn(.checkpoint, variant, null);
        },
        2 => {
            try node.commit_hashed(writes);
            return node.restart_torn(.superblock, variant, null);
        },
        3 => {
            try node.commit_hashed(writes);
            return node.reopen(@intCast(index % 8));
        },
        else => unreachable, // A remainder of four.
    }
}

/// Each tear ran as often as planned; every torn journal entry lost its block, and the opens
/// stopped at torn headers and torn bodies; torn superblock copies were repaired.
fn expect_torn(stats: Node.Stats) !void {
    try testing.expectEqual(@as(u64, torn_blocks / 4), stats.torn_journal);
    try testing.expectEqual(@as(u64, torn_blocks / 4), stats.torn_checkpoint);
    try testing.expectEqual(@as(u64, torn_blocks / 4), stats.torn_superblock);
    try testing.expectEqual(stats.torn_journal, stats.blocks_lost);
    try testing.expect(stats.stops_header > 0 and stats.stops_body > 0);
    try testing.expect(stats.superblocks_repaired > 0);
}

// `memory-history-budget`'s database: the history window under a byte budget a third of
// what an unbudgeted window held beyond its state, as `trie.zig` sets it. The window shrinks
// while blocks commit; the restart rebuilds it from an estimate (40 blocks: more than
// `4 * history_sample_blocks`), and every block left in it is proven as it was then.

const budget_blocks = 40;

test "diff trie: memory-history-budget shrinks its window and rebuilds it from an estimate" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const history_path = try std.fmt.allocPrint(arena, "{s}/history.db", .{dir});
    const budget_path = try std.fmt.allocPrint(arena, "{s}/budget.db", .{dir});
    const history = try Node.create(testing.allocator, .memory_history, history_path);
    defer history.destroy();
    var run = try Run.init(arena, 0xb0d6_0000 + build_options.fuzz_seed);
    var ops: [budget_blocks][]const Op = undefined;
    var roots: [budget_blocks + 1]Hash = undefined;
    roots[0] = trie.empty_root;
    for (&ops, roots[1..]) |*block_ops, *root| {
        block_ops.* = (try run.block(arena))[1];
        try overlay_commit(history, block_ops.*);
        root.* = try run.model.state_root();
    }
    const store = history.db.history_reader().?;
    const base = db.history.reset_bytes_estimate(&history.db.state.state_trie);
    const bytes_max = base + base / 2 + (store.bytes_used() - base) / 3;
    var budget: ?*Node = try Node.create_budget(testing.allocator, budget_path, bytes_max);
    defer if (budget) |node| node.destroy();
    for (ops, roots[1..]) |block_ops, root| {
        try overlay_commit(budget.?, block_ops);
        try testing.expectEqualSlices(u8, &root, &budget.?.state_root());
    }
    const shrunk = budget.?.db.history_reader().?;
    try testing.expect(shrunk.window_shrinks > 0);
    try testing.expect(shrunk.window().?.oldest > 0);
    budget = try budget.?.reopen(null);
    try expect_budget_window(&run, budget.?, history, &roots);
}

/// The rebuild tried a start above the oldest block it could rebuild from (genesis), as the
/// estimate picks it, and kept a shrunk window; each block in it is proven as the unbudgeted
/// window proves it.
fn expect_budget_window(run: *const Run, budget: *Node, history: *Node, roots: []const Hash) !void {
    const window = budget.db.history_reader().?.window().?;
    try testing.expectEqual(@as(u64, budget_blocks), window.head);
    try testing.expect(window.oldest > 0);
    try testing.expect(budget.db.history_rebuild_commits < budget_blocks or
        budget.db.history_rebuild_widens > 0);
    var got = try Proofs.create();
    defer got.destroy();
    var want = try Proofs.create();
    defer want.destroy();
    for (window.oldest..window.head + 1) |number| {
        const store = budget.db.history_reader().?;
        try testing.expectEqualSlices(u8, &roots[number], &(try store.state_root_at(number)));
        for (0..targets_count) |target| {
            const address = run.addresses[target * 7];
            const words = target_slot_words(run, target * 7);
            var values: [2]u256 = undefined;
            var values_want: [2]u256 = undefined;
            const account = try budget.db.proof_at(
                number,
                address,
                &words,
                got.account,
                got.storage,
                &values,
            );
            const account_want = try history.db.proof_at(
                number,
                address,
                &words,
                want.account,
                want.storage,
                &values_want,
            );
            try testing.expectEqualDeep(account_want, account);
            try testing.expectEqual(values_want, values);
            try expect_same_proof(want.account, got.account);
            for (want.storage, got.storage) |*a, *b| try expect_same_proof(a, b);
        }
    }
}

fn expect_same_proof(want: anytype, got: anytype) !void {
    try testing.expectEqual(want.count, got.count);
    for (0..want.count) |index| {
        const at: u32 = @intCast(index);
        try testing.expectEqualSlices(u8, want.node_at(at), got.node_at(at));
    }
}

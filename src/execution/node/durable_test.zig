//! Durable node tests over the simulated sector storage: a node commits blocks through the
//! journal, the storage crashes, and a new node reopens the same storage and continues
//! from the recovered head with the same state; reorgs move state through stored
//! changesets; a seeded fuzz mixes builds, reorgs, crashes and reopen.

const std = @import("std");
const testing = std.testing;
const consensus = @import("../../common/consensus/root.zig");
const genesis_module = @import("../../common/genesis/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const db_module = @import("../db/root.zig");
const SimStorage = @import("../db/storage/sim_storage.zig").SimStorage;
const Prng = @import("../../testing/prng.zig").Prng;
const fixture = @import("test_fixture.zig");
const durable_module = @import("durable.zig");
const witness_module = @import("witness.zig");
const StateDb = @import("state_db.zig").StateDb;

const Durable = durable_module.Durable(SimStorage);
const B256 = primitives.B256;
const Node = fixture.Node;
const sector = db_module.storage.storage.sector_size;
const ticks_max = 1_000_000;

const config: db_module.database.Config = .{
    .engine = .{
        .journal_size_bytes = 256 * sector,
        .checkpoint_zone_size_bytes = 256 * sector,
        .entry_body_size_max = 16 * sector,
        .checkpoint_block_size = 4 * sector,
    },
    .state = StateDb.state_config(Node.state_config),
    .chain = .{
        .blocks_max = 32,
        .bytes_max = 512 * 1024,
        .transactions_max = 1024,
        .canonical_max = 128,
        .reorg_depth_max = 16,
    },
    .changeset = .{
        .accounts_max = 256,
        .storage_max = 1024,
        .codes_max = 64,
        .code_bytes_max = 1 << 16,
    },
    .queue_entries_max = 8,
    .checkpoint_staging_bytes = 1 << 20,
};

var genesis_accounts: [fixture.senders]genesis_module.state.Account = undefined;

fn genesis() genesis_module.Genesis {
    for (&genesis_accounts, 0..) |*account, index| {
        account.* = .{ .address = fixture.address_of(@intCast(index + 1)), .balance = fixture.eth };
    }
    return .{ .accounts = &genesis_accounts };
}

const Harness = struct {
    sim: SimStorage,
    durable: *Durable,
    node: ?*Node = null,
    genesis: consensus.Header,
    config: db_module.database.Config,

    fn create(seed: u64) !*Harness {
        return create_with(seed, config);
    }

    fn create_with(seed: u64, database_config: db_module.database.Config) !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.config = database_config;
        const parsed = genesis();
        const root = try parsed.compute_state_root(testing.allocator);
        harness.genesis = fixture.genesis_header(root.bytes);
        harness.sim = try SimStorage.init(testing.allocator, .{
            .size_bytes = config.engine.size_bytes(),
            .seed = seed,
        });
        errdefer harness.sim.deinit(testing.allocator);
        harness.durable = try harness.open_durable();
        harness.node = null;
        try harness.start_node();
        return harness;
    }

    fn destroy(harness: *Harness) void {
        if (harness.node) |node| node.destroy();
        harness.durable.destroy(testing.allocator);
        harness.sim.deinit(testing.allocator);
        testing.allocator.destroy(harness);
    }

    fn open_durable(harness: *Harness) !*Durable {
        const hash = harness.genesis.hash().bytes;
        const durable = try Durable.create(
            testing.allocator,
            &harness.sim,
            harness.config,
            hash,
            7,
        );
        errdefer durable.destroy(testing.allocator);
        durable.start();
        var ticks: u32 = 0;
        while (durable.phase != .ready) : (ticks += 1) {
            if (durable.phase == .failed or ticks == ticks_max) return error.OpenFailed;
            harness.sim.tick();
            durable.poll();
        }
        return durable;
    }

    /// A node on the durable state: bootstraps genesis or restores the retained blocks.
    fn start_node(harness: *Harness) !void {
        const durable = harness.durable;
        const fresh = !durable.has_head();
        if (fresh) {
            const parsed = genesis();
            _ = try durable.bootstrap(testing.allocator, &parsed, &harness.genesis);
        }
        const node = try Node.create_with(fixture.spec, .{
            .state = durable.state(),
            .genesis = harness.genesis,
            .restoring = !fresh,
        });
        errdefer node.destroy();
        var records: [64][]const u8 = undefined;
        if (!fresh) for (durable.retained(&records)) |record| try node.chain.restore(record);
        node.chain.journal = durable.journal();
        harness.node = node;
        try harness.settle();
    }

    /// Ticks until every journaled entry is durable.
    fn settle(harness: *Harness) !void {
        var ticks: u32 = 0;
        while (!harness.durable.database.idle()) : (ticks += 1) {
            if (ticks == ticks_max) return error.Timeout;
            harness.sim.tick();
            harness.durable.poll();
        }
    }

    /// Crashes the storage (pending writes may be lost or torn) and reopens everything.
    fn crash_and_reopen(harness: *Harness) !void {
        harness.node.?.destroy();
        harness.node = null;
        harness.sim.crash();
        harness.durable.destroy(testing.allocator);
        harness.durable = try harness.open_durable();
        try harness.start_node();
    }

    /// Builds a block on `parent` and makes it the head.
    fn build_head(harness: *Harness, parent: B256, timestamp: u64, recipient: u8) !B256 {
        const node = harness.node.?;
        const hash = try fixture.build(node, parent, timestamp, recipient);
        const version = @import("../engine/root.zig").types.forkchoice_version(
            fixture.spec,
            timestamp,
        );
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        try harness.settle();
        return hash;
    }

    fn head(harness: *Harness) B256 {
        return .{ .bytes = harness.node.?.chain.head_hash() };
    }
};

test "durable: blocks survive a crash and the node continues from the recovered head" {
    const h = try Harness.create(1);
    defer h.destroy();
    var buffers: [2][256]u8 = undefined;
    try fixture.submit(h.node.?, 1, 0, 5, &buffers[0]);
    const first = try h.build_head(h.head(), 12, 0xfe);
    try fixture.submit(h.node.?, 1, 1, 7, &buffers[1]);
    const second = try h.build_head(first, 24, 0xfe);
    const root = try h.node.?.db.root();
    try h.crash_and_reopen();
    try testing.expectEqualSlices(u8, &second.bytes, &h.head().bytes);
    try testing.expectEqualSlices(u8, &root, &(try h.node.?.db.root()));
    const target = fixture.address_of(9).bytes;
    try testing.expectEqual(@as(u256, 12), h.node.?.db.get_account(target).?.balance);
    const record = h.node.?.chain.record(first.bytes).?;
    var transactions = record.transactions;
    const tx_hash = primitives.keccak256(try transactions.bytes()).bytes;
    try testing.expect(h.node.?.chain.find_transaction(tx_hash) != null);
    try testing.expectEqualSlices(u8, &first.bytes, &h.node.?.chain.store.canonical_hash(1).?);
    // The restored node keeps building, and that block survives another reopen.
    const third = try h.build_head(second, 36, 0xfe);
    try h.crash_and_reopen();
    try testing.expectEqualSlices(u8, &third.bytes, &h.head().bytes);
}

test "durable: a reorg moves the shared state through stored changesets" {
    const h = try Harness.create(2);
    defer h.destroy();
    const genesis_hash = h.head();
    var buffer: [256]u8 = undefined;
    try fixture.submit(h.node.?, 1, 0, 5, &buffer);
    const a1 = try h.build_head(genesis_hash, 12, 0xfe);
    const a_root = try h.node.?.db.root();
    // A sibling without the transfer (different fee recipient, empty pool now).
    const b1 = try h.build_head(genesis_hash, 12, 0xfd);
    const b_root = try h.node.?.db.root();
    try testing.expect(!std.mem.eql(u8, &a_root, &b_root));
    const target = fixture.address_of(9).bytes;
    try testing.expect(h.node.?.db.get_account(target) == null);
    _ = try h.build_head(a1, 24, 0xfe);
    try testing.expectEqual(@as(u256, 5), h.node.?.db.get_account(target).?.balance);
    try h.crash_and_reopen();
    try testing.expectEqual(@as(u256, 5), h.node.?.db.get_account(target).?.balance);
    _ = b1;
}

const witness_config: db_module.witness_block.Config = .{
    .builder = .{
        .sparse = .{
            .nodes_max = 512,
            .node_bytes_max = 1 << 17,
            .codes_max = 16,
            .code_bytes_max = 1 << 16,
            .headers_max = 16,
            .trie_nodes_max = 2048,
            .storage_tries_max = 32,
        },
        .keys = .{ .accounts_max = 64, .slots_max = 256, .codes_max = 16, .block_numbers_max = 16 },
    },
    .witness = .{
        .state_nodes_max = 512,
        .state_bytes_max = 1 << 17,
        .codes_max = 16,
        .code_bytes_max = 1 << 16,
        .keys_max = 64 + 256,
        .headers_max = 16,
        .header_bytes_max = 1 << 14,
    },
    .overlay = .{ .accounts_max = 256, .slots_max = 1024, .codes_max = 64 },
    .changeset = config.changeset,
    .depth_max = 8,
};

test "durable: execution witness moves the state in memory only and restores the head" {
    const h = try Harness.create(3);
    defer h.destroy();
    var buffers: [3][256]u8 = undefined;
    var hashes: [4]B256 = undefined;
    hashes[0] = h.head();
    for (1..4) |number| {
        try fixture.submit(h.node.?, 1, number - 1, 5, &buffers[number - 1]);
        hashes[number] = try h.build_head(hashes[number - 1], 12 * number, 0xfe);
    }
    // A side block at height 3, then back to the main tip.
    const side = try h.build_head(hashes[2], 36, 0xfd);
    _ = try h.build_head(hashes[3], 48, 0xfe);
    const node = h.node.?;
    var generator = try db_module.witness_block.Generator.init(
        testing.allocator,
        h.durable.state(),
        witness_config,
    );
    defer generator.deinit(testing.allocator);
    const head = h.durable.database.head_info;
    const sequence = h.durable.database.submitted_sequence;
    for (hashes[1..]) |hash| {
        try witness_module.execution_witness(&node.chain, &generator, hash.bytes);
        try testing.expect(generator.witness.state.count > 0);
        try testing.expect(head.eql(h.durable.database.head_info));
        try testing.expectEqual(head.state_root, try node.db.root());
        try testing.expectEqual(sequence, h.durable.database.submitted_sequence);
    }
    const refused = [_]B256{ side, hashes[0] };
    for (refused) |hash| {
        const result = witness_module.execution_witness(&node.chain, &generator, hash.bytes);
        try testing.expectError(error.BlockUnavailable, result);
        try testing.expectEqual(head.state_root, try node.db.root());
    }
    // The node keeps building on the restored head.
    _ = try h.build_head(h.head(), 60, 0xfe);
}

const history_config: db_module.database.Config = blk: {
    var result = config;
    result.history = .{
        .window_blocks = 3,
        .paths_max = 8192,
        .small_versions_max = 8192,
        .large_versions_max = 2048,
        .prune_per_commit = 1024,
    };
    break :blk result;
};

test "durable: execution witness prefers the history window and leaves the state alone" {
    const h = try Harness.create_with(5, history_config);
    defer h.destroy();
    var buffers: [5][256]u8 = undefined;
    var hashes: [7]B256 = undefined;
    var count: usize = 6;
    hashes[0] = h.head();
    for (1..count) |number| {
        try fixture.submit(h.node.?, 1, number - 1, 5, &buffers[number - 1]);
        hashes[number] = try h.build_head(hashes[number - 1], 12 * number, 0xfe);
    }
    const node = h.node.?;
    var generator = try db_module.witness_block.Generator.init(
        testing.allocator,
        h.durable.state(),
        witness_config,
    );
    defer generator.deinit(testing.allocator);
    const Source = db_module.witness_block.Source;
    for (0..2) |round| {
        const database = &h.durable.database;
        const head = database.head_info;
        const sequence = database.submitted_sequence;
        const window = database.history_reader().?.window().?;
        try testing.expectEqual(head.number, window.head);
        for (hashes[1..count], 1..) |hash, number| {
            try witness_module.execution_witness(&node.chain, &generator, hash.bytes);
            const expected: Source = if (number > window.oldest) .history else .unwind;
            try testing.expectEqual(expected, generator.source.?);
            try testing.expect(head.eql(database.head_info));
            try testing.expectEqual(head.state_root, try node.db.root());
            try testing.expectEqual(sequence, database.submitted_sequence);
        }
        // The node keeps building between witness calls; the window moves with it.
        if (round == 0) {
            hashes[count] = try h.build_head(hashes[count - 1], 12 * count, 0xfe);
            count += 1;
        }
    }
}

/// `debug_executePayload` on a durable node: a side block built on a canonical parent is
/// witnessed from the state that holds it, then the head state comes back.
fn check_built_witness(database_config: db_module.database.Config) !void {
    const h = try Harness.create_with(7, database_config);
    defer h.destroy();
    var buffers: [3][256]u8 = undefined;
    var hashes: [4]B256 = undefined;
    hashes[0] = h.head();
    for (1..4) |number| {
        try fixture.submit(h.node.?, 1, number - 1, 5, &buffers[number - 1]);
        hashes[number] = try h.build_head(hashes[number - 1], 12 * number, 0xfe);
    }
    const node = h.node.?;
    var generator = try db_module.witness_block.Generator.init(
        testing.allocator,
        h.durable.state(),
        witness_config,
    );
    defer generator.deinit(testing.allocator);
    const head_root = try node.db.root();
    for ([_]usize{ 2, 3 }) |parent| {
        const attributes = fixture.attributes(12 * parent + 6, 0xfd);
        const built = try node.chain.build_block(hashes[parent].bytes, &attributes);
        try witness_module.built_witness(&node.chain, &generator, built);
        try testing.expect(generator.witness.state.count > 0);
        try testing.expect(generator.witness.headers.count > 0);
        try node.chain.ensure_head_state();
        try testing.expectEqual(hashes[3].bytes, node.chain.head_hash());
        try testing.expectEqual(head_root, try node.db.root());
    }
    // A block the state does not hold is refused.
    const stale = witness_module.built_witness(&node.chain, &generator, hashes[1].bytes);
    try testing.expectError(error.StateUnavailable, stale);
    if (database_config.history != null) {
        const window = node.chain.history_window().?;
        try testing.expectEqual(@as(u64, 3), window.head);
    } else try testing.expect(node.chain.history_window() == null);
    _ = try h.build_head(h.head(), 60, 0xfe);
}

test "durable: built side blocks are witnessed with and without history" {
    try check_built_witness(config);
    try check_built_witness(history_config);
}

fn fuzz_scenario(seed: u64) !void {
    var prng = Prng.init(seed);
    const h = try Harness.create(seed);
    defer h.destroy();
    var tips: [4]B256 = @splat(h.head());
    var timestamp: u64 = 0;
    var buffers: [8][256]u8 = undefined;
    var nonce: u64 = 0;
    const steps = prng.range(4, 12);
    for (0..steps) |step| {
        timestamp += 12;
        const branch = prng.below(tips.len);
        if (prng.chance(1, 2) and nonce < buffers.len) {
            const node = h.node.?;
            const account = node.db.get_account(fixture.address_of(1).bytes).?;
            if (account.nonce == nonce) {
                try fixture.submit(node, 1, nonce, 1, &buffers[nonce]);
                nonce += 1;
            }
        }
        tips[branch] = try h.build_head(tips[branch], timestamp, @intCast(0x80 + step));
        if (prng.chance(1, 4)) {
            const root = try h.node.?.db.root();
            const head = h.head();
            try h.crash_and_reopen();
            try testing.expectEqualSlices(u8, &head.bytes, &h.head().bytes);
            try testing.expectEqualSlices(u8, &root, &(try h.node.?.db.root()));
            nonce = h.node.?.db.get_account(fixture.address_of(1).bytes).?.nonce;
            tips = @splat(head);
        }
    }
}

test "durable: seeded fuzz of builds, reorgs and crashes" {
    for (0..6) |seed| try fuzz_scenario(seed + 100);
}

fn fuzz_durable(_: void, smith: *testing.Smith) anyerror!void {
    try fuzz_scenario(smith.value(u64));
}

test "durable: fuzz" {
    try testing.fuzz({}, fuzz_durable, .{});
}

//! Historical `eth_getProof` on a durable node with a history window: the response at an
//! older canonical block (by number or hash) is byte-identical to the response served at
//! "latest" when that block was the head; blocks that left the window and side blocks get
//! the usual "historical state unavailable" error.

const std = @import("std");
const testing = std.testing;
const consensus = @import("../../common/consensus/root.zig");
const genesis_module = @import("../../common/genesis/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const db_module = @import("../db/root.zig");
const SimStorage = @import("../db/storage/sim_storage.zig").SimStorage;
const fixture = @import("../node/test_fixture.zig");
const durable_module = @import("../node/durable.zig");
const StateDb = @import("../node/state_db.zig").StateDb;
const engine_types = @import("../engine/root.zig").types;
const eth = @import("eth.zig");

const Durable = durable_module.Durable(SimStorage);
const Hash = [32]u8;
const sector = db_module.storage.storage.sector_size;
const ticks_max = 1_000_000;
const window_blocks = 4;
const blocks_total = 6;
const response_bytes_max = 1 << 15;

const config: db_module.database.Config = .{
    .engine = .{
        .journal_size_bytes = 256 * sector,
        .checkpoint_zone_size_bytes = 256 * sector,
        .entry_body_size_max = 16 * sector,
        .checkpoint_block_size = 4 * sector,
    },
    .state = StateDb.state_config(fixture.Node.state_config),
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
    .history = .{
        .window_blocks = window_blocks,
        .paths_max = 4096,
        .small_versions_max = 4096,
        .large_versions_max = 1024,
        .prune_per_commit = 512,
    },
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
    node: *fixture.Node,
    api: eth.Api,
    scratch: [1 << 18]u8 = undefined,
    out: [response_bytes_max]u8 = undefined,
    /// The "latest" response recorded while block `n` was the head.
    responses: [blocks_total + 1][response_bytes_max]u8 = undefined,
    response_lens: [blocks_total + 1]usize = undefined,
    hashes: [blocks_total + 1]Hash = undefined,

    fn create() !*Harness {
        const allocator = testing.allocator;
        const harness = try allocator.create(Harness);
        errdefer allocator.destroy(harness);
        const parsed = genesis();
        const root = try parsed.compute_state_root(allocator);
        const header = fixture.genesis_header(root.bytes);
        harness.sim = try SimStorage.init(allocator, .{
            .size_bytes = config.engine.size_bytes(),
            .seed = 0x9f00f,
        });
        errdefer harness.sim.deinit(allocator);
        const hash = header.hash().bytes;
        harness.durable = try Durable.create(allocator, &harness.sim, config, hash, 7);
        errdefer harness.durable.destroy(allocator);
        try harness.open();
        _ = try harness.durable.bootstrap(allocator, &parsed, &header);
        harness.node = try fixture.Node.create_with(fixture.spec, .{
            .state = harness.durable.state(),
            .genesis = header,
        });
        harness.node.chain.journal = harness.durable.journal();
        harness.api = .{
            .spec = fixture.spec,
            .chain = &harness.node.chain,
            .pool = &harness.node.pool,
            .scratch = &harness.scratch,
        };
        try harness.settle();
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.node.destroy();
        harness.durable.destroy(testing.allocator);
        harness.sim.deinit(testing.allocator);
        testing.allocator.destroy(harness);
    }

    fn open(harness: *Harness) !void {
        const durable = harness.durable;
        durable.start();
        var ticks: u32 = 0;
        while (durable.phase != .ready) : (ticks += 1) {
            if (durable.phase == .failed or ticks == ticks_max) return error.OpenFailed;
            harness.sim.tick();
            durable.poll();
        }
    }

    fn settle(harness: *Harness) !void {
        var ticks: u32 = 0;
        while (!harness.durable.database.idle()) : (ticks += 1) {
            if (ticks == ticks_max) return error.Timeout;
            harness.sim.tick();
            harness.durable.poll();
        }
    }

    /// One transfer, then one block on `parent` made the head.
    fn mine(harness: *Harness, parent: Hash, nonce: u64, timestamp: u64) !Hash {
        const node = harness.node;
        var buffer: [256]u8 = undefined;
        try fixture.submit(node, 1, nonce, 1000 + nonce, &buffer);
        const hash = try fixture.build(node, .{ .bytes = parent }, timestamp, 0xfe);
        const version = engine_types.forkchoice_version(fixture.spec, timestamp);
        _ = try node.engine.forkchoice_updated(version, fixture.forkchoice(hash), null);
        try harness.settle();
        return hash.bytes;
    }

    fn forkchoice(harness: *Harness, hash: Hash, timestamp: u64) !void {
        const version = engine_types.forkchoice_version(fixture.spec, timestamp);
        const state = fixture.forkchoice(.{ .bytes = hash });
        _ = try harness.node.engine.forkchoice_updated(version, state, null);
        try harness.settle();
    }

    /// `eth_getProof` of sender 1 with two slots at `block` (a JSON block parameter).
    fn proof(harness: *Harness, block: []const u8) ![]const u8 {
        var body_buffer: [512]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
            "\"method\":\"eth_getProof\",\"params\":[\"0x{x}\",[\"0x0\",\"0x01\"],{s}]}}", .{
            &fixture.address_of(1).bytes,
            block,
        });
        var out: std.Io.Writer = .fixed(&harness.out);
        _ = eth.Router.handle(&harness.api, body, &out);
        const text = out.buffered();
        try json.validate(text);
        return text;
    }

    fn record(harness: *Harness, number: u64) !void {
        const text = try harness.proof("\"latest\"");
        try testing.expect(std.mem.indexOf(u8, text, "\"accountProof\"") != null);
        @memcpy(harness.responses[number][0..text.len], text);
        harness.response_lens[number] = text.len;
        harness.hashes[number] = harness.node.chain.head_hash();
    }

    fn recorded(harness: *const Harness, number: u64) []const u8 {
        return harness.responses[number][0..harness.response_lens[number]];
    }
};

fn expect_unavailable(text: []const u8) !void {
    try testing.expect(std.mem.indexOf(u8, text, "historical state unavailable") != null);
}

test "eth_getProof: older blocks of the durable history window match their head responses" {
    const h = try Harness.create();
    defer h.destroy();
    try h.record(0);
    var number: u64 = 1;
    while (number <= blocks_total) : (number += 1) {
        _ = try h.mine(h.node.chain.head_hash(), number - 1, number * 12);
        try h.record(number);
        // Every block still in the window answers exactly as it did as the head.
        const oldest = (number + 1) -| window_blocks;
        var older = oldest;
        while (older < number) : (older += 1) {
            var tag_buffer: [32]u8 = undefined;
            const tag = try std.fmt.bufPrint(&tag_buffer, "\"0x{x}\"", .{older});
            try testing.expectEqualStrings(h.recorded(older), try h.proof(tag));
        }
    }
    // By hash too.
    var hash_buffer: [80]u8 = undefined;
    const by_hash = try std.fmt.bufPrint(&hash_buffer, "\"0x{x}\"", .{&h.hashes[blocks_total - 1]});
    try testing.expectEqualStrings(h.recorded(blocks_total - 1), try h.proof(by_hash));
    // Blocks before the window are refused as before.
    try expect_unavailable(try h.proof("\"0x1\""));
    // A side block (no transactions) becomes the head, then the old chain again.
    const side = try fixture.build(h.node, .{ .bytes = h.hashes[blocks_total - 2] }, 49, 0xfd);
    try h.forkchoice(side.bytes, 49);
    try h.forkchoice(h.hashes[blocks_total], blocks_total * 12);
    try testing.expectEqualSlices(u8, &h.hashes[blocks_total], &h.node.chain.head_hash());
    const stale = try std.fmt.bufPrint(&hash_buffer, "\"0x{x}\"", .{&side.bytes});
    try expect_unavailable(try h.proof(stale));
    // After the unwind and re-apply, the window answers as recorded. By hash: the node's
    // number index can keep the side block at its height after the reorg back.
    var older: u64 = blocks_total + 1 - window_blocks;
    while (older < blocks_total) : (older += 1) {
        const tag = try std.fmt.bufPrint(&hash_buffer, "\"0x{x}\"", .{&h.hashes[older]});
        try testing.expectEqualStrings(h.recorded(older), try h.proof(tag));
    }
}

//! Chain tests over the Engine API: one node builds, a second independent node imports
//! the same payloads; both must agree. Covers pool inclusion and pruning, invalid
//! payloads (state untouched), reorgs (rollback + re-execution) and a seeded fuzz.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const engine_module = @import("../engine/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const chain_module = @import("chain.zig");
const Executor = @import("executor.zig").Executor;
const StateDb = @import("state_db.zig").StateDb;

const Chain = chain_module.Chain;
const Engine = engine_module.Engine(Chain);
const B256 = primitives.B256;
const spec = &chainspec.ChainSpec.presets.l1_dev;
const eth: u256 = 1_000_000_000_000_000_000;
const types = engine_module.types;

fn key(n: u8) [32]u8 {
    var k: [32]u8 = @splat(0);
    k[31] = n;
    return k;
}

fn address_of(n: u8) primitives.Address {
    return consensus.signature.address_from_private(key(n)).?;
}

const senders = 3;

/// One node: state, executor, pool, chain and engine, all on the heap (stable pointers).
const Node = struct {
    db: StateDb,
    executor: Executor,
    pool: txpool.Pool,
    chain: Chain,
    engine: Engine,

    fn create() !*Node {
        const node = try testing.allocator.create(Node);
        errdefer testing.allocator.destroy(node);
        node.db = try StateDb.init(testing.allocator, .{
            .trie = .{ .accounts_max = 256, .account_nodes_max = 4096, .storage_nodes_max = 8192 },
            .code_bytes_max = 1 << 16,
            .codes_max = 64,
            .undo_entries_max = 1 << 12,
        });
        for (0..senders) |i| {
            try node.db.put_account(address_of(@intCast(i + 1)).bytes, eth, 0, &.{});
        }
        node.executor = try Executor.init(testing.allocator, spec, &node.db, .{
            .scratch_bytes = 1 << 20,
            .transactions_max = 64,
            .evm = .{ .memory_bytes_max = 1 << 20, .code_arena_bytes = 1 << 20 },
            .limits = .{
                .accounts_max = 256,
                .slots_max = 1024,
                .transient_slots_max = 64,
                .journal_entries_max = 4096,
                .logs_max = 64,
                .log_data_bytes_max = 4096,
                .code_bytes_max = 1 << 16,
            },
        });
        node.pool = try txpool.Pool.init(testing.allocator, .{});
        const genesis = genesis_header(try node.db.root());
        node.chain = try Chain.init(testing.allocator, spec, &node.db, &node.executor, &genesis, .{
            .store = .{ .blocks_max = 256, .bytes_max = 1 << 20 },
            .staging_bytes = 1 << 18,
            .select_max = 64,
            .build_bytes = 1 << 16,
        });
        node.chain.pool = &node.pool;
        node.engine = Engine.init(spec, &node.chain);
        return node;
    }

    fn destroy(node: *Node) void {
        node.chain.deinit(testing.allocator);
        node.pool.deinit(testing.allocator);
        node.executor.deinit(testing.allocator);
        node.db.deinit(testing.allocator);
        testing.allocator.destroy(node);
    }
};

fn genesis_header(state_root: [32]u8) consensus.Header {
    return .{
        .state_root = .{ .bytes = state_root },
        .gas_limit = 30_000_000,
        .base_fee_per_gas = 1_000_000_000,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .zero,
        .requests_hash = consensus.block.empty_requests_hash,
    };
}

fn forkchoice(head: B256) types.ForkchoiceState {
    return .{ .head_block_hash = head, .safe_block_hash = .zero, .finalized_block_hash = .zero };
}

fn attributes(timestamp: u64, recipient: u8) payload.PayloadAttributes {
    return .{
        .timestamp = timestamp,
        .prev_randao = .zero,
        .suggested_fee_recipient = .{ .bytes = @splat(recipient) },
        .withdrawals = &.{},
        .parent_beacon_block_root = .zero,
    };
}

/// Builds a block on `parent` and returns its hash (the builder's head is unchanged).
fn build(node: *Node, parent: B256, timestamp: u64, recipient: u8) !B256 {
    var attrs = attributes(timestamp, recipient);
    const version = types.forkchoice_version(spec, timestamp);
    const updated = try node.engine.forkchoice_updated(version, forkchoice(parent), &attrs);
    try testing.expectEqual(types.Status.valid, updated.payload_status.status);
    const get_version = types.get_payload_version(spec, timestamp);
    const built = try node.engine.get_payload(get_version, updated.payload_id.?);
    return built.block_hash;
}

/// Imports `hash` from `from` into `to` through newPayload.
fn import(from: *Node, to: *Node, hash: B256) !types.PayloadStatus {
    var transactions: [64][]const u8 = undefined;
    var withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
    const p = from.chain.payload_of(hash.bytes, &transactions, &withdrawals).?;
    const stored = from.chain.record(hash.bytes).?;
    var requests: [2][]const u8 = undefined;
    var requests_decoder = stored.requests;
    var count: usize = 0;
    while (!requests_decoder.is_empty()) : (count += 1) {
        requests[count] = try requests_decoder.bytes();
    }
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = stored.header.parent_beacon_block_root,
        .execution_requests = requests[0..count],
    };
    return to.engine.new_payload(types.new_payload_version(spec, p.timestamp), &p, &params);
}

fn submit(node: *Node, from: u8, nonce: u64, value: u256, buffer: []u8) !void {
    const tx: consensus.Eip1559 = .{
        .chain_id = spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 10_000_000_000,
        .gas_limit = 21_000,
        .to = .{ .call = address_of(9) },
        .value = value,
        .input = &.{},
        .access_list = .empty,
    };
    const envelope = try consensus.tx.sign(tx, key(from));
    const raw = envelope.encode_to(buffer);
    const sender = address_of(from);
    const account = node.db.get_account(sender.bytes).?;
    _ = try node.pool.add(.{
        .hash = envelope.hash(),
        .sender = sender,
        .nonce = nonce,
        .tx_type = 2,
        .gas_limit = tx.gas_limit,
        .max_fee_per_gas = tx.max_fee_per_gas,
        .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
        .value = value,
        .raw = raw,
    }, .{ .nonce = account.nonce, .balance = account.balance });
}

test "chain: build, import on a second node, pool inclusion and pruning" {
    const builder = try Node.create();
    defer builder.destroy();
    const follower = try Node.create();
    defer follower.destroy();
    try testing.expectEqualSlices(u8, &builder.chain.genesis_hash, &follower.chain.genesis_hash);
    var buffers: [2][256]u8 = undefined;
    try submit(builder, 1, 0, 5, &buffers[0]);
    try submit(builder, 1, 1, 7, &buffers[1]);
    const genesis: B256 = .{ .bytes = builder.chain.genesis_hash };
    const hash = try build(builder, genesis, 12, 0xfe);
    const record = builder.chain.record(hash.bytes).?;
    var decoder = record.transactions;
    var included: u32 = 0;
    while (!decoder.is_empty()) : (included += 1) _ = try decoder.bytes();
    try testing.expectEqual(@as(u32, 2), included);
    try testing.expectEqual(@as(u64, 42_000), record.header.gas_used);

    const status = try import(builder, follower, hash);
    try testing.expectEqual(types.Status.valid, status.status);
    const v = types.forkchoice_version(spec, 12);
    _ = try builder.engine.forkchoice_updated(v, forkchoice(hash), null);
    _ = try follower.engine.forkchoice_updated(v, forkchoice(hash), null);
    try testing.expectEqualSlices(u8, &(try builder.db.root()), &(try follower.db.root()));
    try testing.expectEqual(@as(u32, 0), builder.pool.count());
    try testing.expectEqual(@as(u256, 12), follower.db.get_account(address_of(9).bytes).?.balance);
    try testing.expectEqualSlices(u8, &hash.bytes, &follower.chain.store.canonical_hash(1).?);
}

test "chain: tampered payload is invalid and leaves state untouched" {
    const builder = try Node.create();
    defer builder.destroy();
    const follower = try Node.create();
    defer follower.destroy();
    const genesis: B256 = .{ .bytes = builder.chain.genesis_hash };
    const hash = try build(builder, genesis, 12, 0xfe);
    var transactions: [64][]const u8 = undefined;
    var withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
    var p = builder.chain.payload_of(hash.bytes, &transactions, &withdrawals).?;
    const before = try follower.db.root();
    // A wrong state root with a matching block hash: only execution can catch it.
    p.state_root = .{ .bytes = @splat(0x11) };
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = .zero,
        .execution_requests = &.{},
    };
    p.block_hash = (try engine_module.block.header_of(spec, &p, &params)).hash();
    const status = try follower.engine.new_payload(.v4, &p, &params);
    try testing.expectEqual(types.Status.invalid, status.status);
    try testing.expectEqualStrings("state root mismatch", status.validation_error.?);
    try testing.expectEqualSlices(u8, &before, &(try follower.db.root()));
    try testing.expectEqual(types.Status.valid, (try import(builder, follower, hash)).status);
}

test "chain: reorg between sibling branches" {
    const node = try Node.create();
    defer node.destroy();
    var buffer: [256]u8 = undefined;
    const genesis: B256 = .{ .bytes = node.chain.genesis_hash };
    try submit(node, 1, 0, 100, &buffer);
    const a1 = try build(node, genesis, 12, 0xaa);
    const a2 = try build(node, a1, 24, 0xaa);
    const b1 = try build(node, genesis, 13, 0xbb);
    const v = types.forkchoice_version(spec, 24);
    _ = try node.engine.forkchoice_updated(v, forkchoice(a2), null);
    const root_a2 = try node.db.root();
    try testing.expectEqual(@as(u256, 100), node.db.get_account(address_of(9).bytes).?.balance);
    _ = try node.engine.forkchoice_updated(v, forkchoice(b1), null);
    try testing.expect(node.db.get_account(address_of(9).bytes) == null);
    try testing.expectEqualSlices(u8, &b1.bytes, &node.chain.store.canonical_hash(1).?);
    _ = try node.engine.forkchoice_updated(v, forkchoice(a2), null);
    try testing.expectEqualSlices(u8, &root_a2, &(try node.db.root()));
}

/// Random builds on random known blocks and random forkchoice moves; a follower imports
/// every block and must agree on every state.
fn random_chain(prng: *Prng) !void {
    const builder = try Node.create();
    defer builder.destroy();
    const follower = try Node.create();
    defer follower.destroy();
    var known: [16]B256 = undefined;
    var timestamps: [16]u64 = undefined;
    known[0] = .{ .bytes = builder.chain.genesis_hash };
    timestamps[0] = 0;
    var known_len: usize = 1;
    var nonces: [senders]u64 = @splat(0);
    var buffers: [16][256]u8 = undefined;
    for (1..16) |step| {
        if (prng.chance(1, 2)) {
            const from = prng.below(senders);
            // Nonces may be stale after reorgs; the pool or builder then skips the tx.
            const value = prng.below(100);
            submit(builder, @intCast(from + 1), nonces[from], value, &buffers[step]) catch {};
            nonces[from] += 1;
        }
        const parent = prng.below(known_len);
        const timestamp = timestamps[parent] + prng.range(1, 12);
        const hash = try build(builder, known[parent], timestamp, @intCast(prng.below(4)));
        try testing.expectEqual(types.Status.valid, (try import(builder, follower, hash)).status);
        known[known_len] = hash;
        timestamps[known_len] = timestamp;
        known_len += 1;
        const head = known[prng.below(known_len)];
        const v = types.forkchoice_version(spec, timestamp);
        _ = try builder.engine.forkchoice_updated(v, forkchoice(head), null);
        _ = try follower.engine.forkchoice_updated(v, forkchoice(head), null);
        try testing.expectEqualSlices(u8, &(try builder.db.root()), &(try follower.db.root()));
        const header = builder.chain.header(head.bytes).?;
        try testing.expectEqualSlices(u8, &header.state_root.bytes, &(try builder.db.root()));
    }
}

test "chain: seeded fuzz builder and follower agree" {
    var prng = Prng.init(0xc4a1);
    for (0..3) |_| try random_chain(&prng);
}

fn fuzz_chain(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try random_chain(&prng);
}

test "chain: fuzz" {
    try testing.fuzz({}, fuzz_chain, .{});
}

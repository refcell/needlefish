//! Shared test fixture: a complete in-memory L1 dev node (state, executor, pool, chain,
//! engine) with funded test accounts, plus helpers to build blocks and submit txs.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const engine_module = @import("../engine/root.zig");
const chain_module = @import("chain.zig");
const Executor = @import("executor.zig").Executor;
const StateDb = @import("state_db.zig").StateDb;

pub const Chain = chain_module.Chain;
pub const Engine = engine_module.Engine(Chain);
const B256 = primitives.B256;
pub const spec = &chainspec.ChainSpec.presets.l1_dev;
pub const eth: u256 = 1_000_000_000_000_000_000;
const types = engine_module.types;

pub fn key(n: u8) [32]u8 {
    var k: [32]u8 = @splat(0);
    k[31] = n;
    return k;
}

pub fn address_of(n: u8) primitives.Address {
    return consensus.signature.address_from_private(key(n)).?;
}

pub const senders = 3;

/// One node: state, executor, pool, chain and engine, all on the heap (stable pointers).
pub const Node = struct {
    spec: *const chainspec.ChainSpec,
    db: StateDb,
    executor: Executor,
    pool: txpool.Pool,
    chain: Chain,
    engine: Engine,

    pub fn create() !*Node {
        return create_for(spec);
    }

    pub fn create_for(chain_spec: *const chainspec.ChainSpec) !*Node {
        const node = try testing.allocator.create(Node);
        errdefer testing.allocator.destroy(node);
        node.spec = chain_spec;
        node.db = try StateDb.init(testing.allocator, .{
            .trie = .{ .accounts_max = 256, .account_nodes_max = 4096, .storage_nodes_max = 8192 },
            .code_bytes_max = 1 << 16,
            .codes_max = 64,
            .undo_bytes_max = 1 << 20,
        });
        for (0..senders) |i| {
            try node.db.put_account(address_of(@intCast(i + 1)).bytes, eth, 0, &.{});
        }
        node.executor = try Executor.init(testing.allocator, chain_spec, &node.db, .{
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
        var genesis = genesis_header(try node.db.root());
        if (chain_spec.mode == .l2) genesis.extra_data = &l2_genesis_extra_data;
        const allocator = testing.allocator;
        node.chain = try Chain.init(allocator, chain_spec, &node.db, &node.executor, &genesis, .{
            .store = .{ .blocks_max = 256, .bytes_max = 1 << 20 },
            .staging_bytes = 1 << 18,
            .select_max = 64,
            .build_bytes = 1 << 16,
        });
        node.chain.pool = &node.pool;
        node.engine = Engine.init(chain_spec, &node.chain);
        return node;
    }

    pub fn destroy(node: *Node) void {
        node.chain.deinit(testing.allocator);
        node.pool.deinit(testing.allocator);
        node.executor.deinit(testing.allocator);
        node.db.deinit(testing.allocator);
        testing.allocator.destroy(node);
    }
};

pub fn genesis_header(state_root: [32]u8) consensus.Header {
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

/// Jovian genesis extra data selecting the chain's default EIP-1559 parameters (as the
/// devnet genesis writes it): version 1, denominator 250, elasticity 6, no minimum.
const l2_genesis_extra_data = [_]u8{ 1, 0, 0, 0, 250, 0, 0, 0, 6 } ++ @as([8]u8, @splat(0));

pub fn forkchoice(head: B256) types.ForkchoiceState {
    return .{ .head_block_hash = head, .safe_block_hash = .zero, .finalized_block_hash = .zero };
}

pub fn attributes(timestamp: u64, recipient: u8) payload.PayloadAttributes {
    return .{
        .timestamp = timestamp,
        .prev_randao = .zero,
        .suggested_fee_recipient = .{ .bytes = @splat(recipient) },
        .withdrawals = &.{},
        .parent_beacon_block_root = .zero,
    };
}

/// L2 attributes: the OP extensions every Holocene/Jovian payload must carry (an
/// all-zero EIP-1559 parameter field selects the chain defaults).
pub fn attributes_l2(timestamp: u64, recipient: u8) payload.PayloadAttributes {
    var result = attributes(timestamp, recipient);
    result.gas_limit = 30_000_000;
    result.eip1559_params = @splat(0);
    result.min_base_fee = 0;
    result.no_tx_pool = false;
    return result;
}

/// Builds a block on `parent` and returns its hash (the builder's head is unchanged).
pub fn build(node: *Node, parent: B256, timestamp: u64, recipient: u8) !B256 {
    var attrs = if (node.spec.mode == .l2)
        attributes_l2(timestamp, recipient)
    else
        attributes(timestamp, recipient);
    const version = types.forkchoice_version(node.spec, timestamp);
    const updated = try node.engine.forkchoice_updated(version, forkchoice(parent), &attrs);
    try testing.expectEqual(types.Status.valid, updated.payload_status.status);
    const get_version = types.get_payload_version(node.spec, timestamp);
    const built = try node.engine.get_payload(get_version, updated.payload_id.?);
    return built.block_hash;
}

pub fn submit(node: *Node, from: u8, nonce: u64, value: u256, buffer: []u8) !void {
    const tx: consensus.Eip1559 = .{
        .chain_id = node.spec.chain_id,
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

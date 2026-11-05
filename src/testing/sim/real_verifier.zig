//! The consensus lane's real node driver (`consensus/service/driver.zig`) running inside
//! the simulator as a verifier. Its providers answer synchronously from model state, with
//! no sockets and no wall clock:
//! - `L1View` serves the model L1 as an L1 RPC would: headers (timestamp `k * 12`),
//!   inbox transactions from `L1Block.batches`, empty receipts, no blobs;
//! - `SimEngine` is a deterministic execution engine: it executes the driver's payload
//!   attributes by deriving the block hash from the parent hash and the attributes'
//!   user transaction exactly as the model sequencer does (`nodes.block_hash`), so a
//!   correctly derived block has the sequencer's hash. Its chain and forkchoice labels
//!   are durable: a crash of the consensus node keeps them, and the restarted driver
//!   rebuilds its heads through startup discovery, as the binary does. A crash with a
//!   disk fault models an EL that did not fsync: the last label update and the newest
//!   blocks above the finalized head are lost (`SimEngine.lose_unflushed`);
//! - `EngineClient` polls the engine with seeded random `NotAvailable` latency.
//!
//! Unsafe gossip: the sequencer's `unsafe_block` messages reach the driver as full
//! execution payloads (`on_unsafe_block`). The payload is the block the sequencer built:
//! the L1 info deposit from the real attributes builder for the sequencer's L1 origin,
//! then the payload transaction. Derived attributes then consolidate against these
//! blocks instead of rebuilding them. When its unsafe head lags the gossip it has seen,
//! the node asks the sequencer for the missing blocks (`sync_request`).
//!
//! The real verifier shares the first model verifier's fate (crashes, partitions): it is
//! that node's consensus client. The model verifier keeps running beside it for the
//! model invariants (and the real batcher's rollup RPC when the real verifier is off).

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../../consensus/protocol/root.zig");
const driver_module = @import("../../consensus/service/driver.zig");
const task = @import("../../consensus/engine/task.zig");
const InsertEnvelope = @import("../../consensus/engine/insert_task.zig").Envelope;
const attributes_module = @import("../../consensus/derive/attributes.zig");
const sync_start = @import("../../consensus/engine/sync_start.zig");
const SafeDB = @import("../../consensus/safedb/root.zig").SafeDB;
const derive = @import("../../consensus/derive/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../prng.zig").Prng;
const codec = @import("codec.zig");
const nodes = @import("nodes.zig");

const B256 = primitives.B256;
const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const L1Header = protocol.l1_info.L1Header;
const SafeBlock = protocol.span_batch.SafeBlock;
const SystemConfig = protocol.SystemConfig;
const L1Transaction = derive.providers.L1Transaction;
const ProviderError = derive.errors.ProviderError;
const ClientError = task.ClientError;
const Driver = driver_module.Driver;

/// Transactions per L2 block: the L1 info deposit and the model's payload transaction.
pub const block_txs_max = 2;
pub const tx_bytes_max = 512;
const safe_db_capacity = 64;
/// Engine polls answered with `NotAvailable`, in percent.
const not_available_percent = 10;
/// Most blocks an engine disk fault loses (above the finalized head).
pub const engine_blocks_lost_max = 16;
/// Scratch for building one gossiped payload's attributes (the L1 info deposit).
const gossip_scratch_bytes = 16 * 1024;
/// Gap re-request interval, as the model verifier's (`nodes.Verifier.sync_timeout_ns`).
const sync_timeout_ns = nodes.Verifier.sync_timeout_ns;

/// What the real verifier sees this step. Pointers are rebound every step because the
/// cluster lives by value.
pub const View = struct {
    l1: *const nodes.L1,
    pool: *const codec.TxPool,
    l1_reachable: bool,
    now_ns: u64,
};

fn low_word(hash: B256) ?u64 {
    for (hash.bytes[0..24]) |byte| {
        if (byte != 0) return null;
    }
    return std.mem.readInt(u64, hash.bytes[24..32], .big);
}

/// The model L1 as a derivation chain provider (`derive/providers.zig`).
const L1View = struct {
    l1: *const nodes.L1,
    pool: *const codec.TxPool,
    reachable: bool,
    transactions: [nodes.l1_batches_max]L1Transaction = undefined,

    fn info(view: *const L1View, number: u64) BlockInfo {
        assert(number <= view.l1.head);
        const block = &view.l1.blocks[number];
        assert(block.number == number);
        return .{
            .hash = codec.word_hash(block.hash),
            .number = number,
            .parent_hash = codec.word_hash(block.parent_hash),
            .timestamp = number * codec.l1_block_time_s,
        };
    }

    /// Canonical blocks only: an orphaned block is unknown, as after a reorg on a node.
    fn number_of_hash(view: *const L1View, hash: B256) ProviderError!u64 {
        if (!view.reachable) return error.NotAvailable;
        const word = low_word(hash) orelse return error.NotFound;
        var number = view.l1.head;
        for (0..view.l1.head + 1) |_| {
            if (view.l1.blocks[number].hash == word) return number;
            if (number == 0) break;
            number -= 1;
        }
        return error.NotFound;
    }

    pub fn l1_block_info_by_number(view: *L1View, number: u64) ProviderError!BlockInfo {
        if (!view.reachable) return error.NotAvailable;
        if (number > view.l1.head) return error.NotFound;
        return view.info(number);
    }

    pub fn l1_block_info_by_hash(view: *L1View, hash: B256) ProviderError!BlockInfo {
        return view.info(try view.number_of_hash(hash));
    }

    pub fn l1_receipts_by_hash(
        view: *L1View,
        hash: B256,
    ) ProviderError![]const protocol.log.Receipt {
        _ = try view.number_of_hash(hash);
        return &.{}; // No deposits and no system config updates in the model.
    }

    pub fn l1_transactions_by_hash(view: *L1View, hash: B256) ProviderError![]const L1Transaction {
        const block = &view.l1.blocks[try view.number_of_hash(hash)];
        assert(block.batch_count <= nodes.l1_batches_max);
        for (block.batches[0..block.batch_count], 0..) |batch, index| {
            view.transactions[index] = .{
                .tx_type = L1Transaction.type_eip1559,
                .to = codec.batch_inbox,
                .from = codec.sender_address(batch.sender),
                .input = view.pool.get(batch.tx_index),
            };
        }
        return view.transactions[0..block.batch_count];
    }

    pub fn l1_header_by_hash(view: *L1View, hash: B256) ProviderError!L1Header {
        const block = view.info(try view.number_of_hash(hash));
        assert(block.hash.eql(hash));
        return .{
            .number = block.number,
            .timestamp = block.timestamp,
            .hash = block.hash,
            .parent_hash = block.parent_hash,
            .base_fee = 7,
            .excess_blob_gas = null,
        };
    }

    pub fn blobs(
        _: *L1View,
        _: BlockInfo,
        _: []const B256,
    ) ProviderError![]const *const derive.blob.Blob {
        return error.BlobsUnavailable; // The model never posts blobs.
    }
};

/// One stored L2 block. Transactions live inline; slices are built on read.
const Block = struct {
    info: L2BlockInfo,
    prev_randao: B256 = .zero,
    fee_recipient: primitives.Address = .zero,
    gas_limit: u64 = codec.gas_limit,
    parent_beacon_block_root: ?B256 = null,
    /// Inserted from gossip (not built by this engine) and not yet consolidated.
    gossiped: bool = false,
    tx_count: u8 = 0,
    tx_lengths: [block_txs_max]u16 = @splat(0),
    tx_bytes: [block_txs_max][tx_bytes_max]u8 = undefined,

    fn transaction(block: *const Block, index: usize) []const u8 {
        assert(index < block.tx_count);
        return block.tx_bytes[index][0..block.tx_lengths[index]];
    }

    fn store_transactions(block: *Block, transactions: []const []const u8) bool {
        if (transactions.len == 0 or transactions.len > block_txs_max) return false;
        for (transactions) |bytes| {
            if (bytes.len == 0 or bytes.len > tx_bytes_max) return false;
        }
        for (transactions, 0..) |bytes, index| {
            @memcpy(block.tx_bytes[index][0..bytes.len], bytes);
            block.tx_lengths[index] = @intCast(bytes.len);
        }
        block.tx_count = @intCast(transactions.len);
        assert(block.tx_count > 0);
        return true;
    }
};

/// The block hash the engine assigns: the model sequencer's hash for the same parent,
/// number, and payload transaction. Anything else (deposit-only blocks, foreign
/// transactions) hashes its transaction bytes instead, so it can never match.
pub fn block_hash(parent: B256, number: u64, transactions: []const []const u8) B256 {
    assert(number > 0);
    const parent_word = low_word(parent) orelse std.hash.Wyhash.hash(1, &parent.bytes);
    const has_user_tx = transactions.len == 2;
    const payload: ?u64 = if (has_user_tx) codec.payload_from_tx(transactions[1]) else null;
    const word = payload orelse foreign: {
        var hasher = std.hash.Wyhash.init(0x666f_7265_6967_6e00);
        for (transactions) |bytes| hasher.update(bytes);
        break :foreign hasher.final();
    };
    return codec.word_hash(nodes.block_hash(parent_word, number, word));
}

/// Deterministic execution engine with a durable canonical chain and labels.
pub const SimEngine = struct {
    blocks: []Block,
    /// Canonical blocks: `blocks[0..count]`.
    count: u64 = 1,
    safe: u64 = 0,
    finalized: u64 = 0,
    /// Labels before the last label update: what survives a disk fault.
    safe_previous: u64 = 0,
    finalized_previous: u64 = 0,
    /// Gossiped blocks that became safe without a rebuild (consolidation).
    consolidated_gossip: u64 = 0,
    /// Disk faults applied (`lose_unflushed`).
    losses: u64 = 0,
    /// Lowest block number (re)written since the checker last looked.
    written_low: u64 = std.math.maxInt(u64),
    pending: Block = undefined,
    pending_id: ?task.PayloadId = null,
    builds: u64 = 0,
    pending_slices: [block_txs_max][]const u8 = undefined,
    read_slices: [block_txs_max][]const u8 = undefined,
    safe_slices: [block_txs_max][]const u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64) !SimEngine {
        assert(block_count_max > 0);
        const blocks = try allocator.alloc(Block, block_count_max + 1);
        const genesis = codec.rollup.genesis;
        blocks[0] = .{ .info = .{
            .block_info = .{ .hash = genesis.l2.hash, .number = 0, .timestamp = genesis.l2_time },
            .l1_origin = genesis.l1,
        } };
        assert(blocks[0].info.block_info.hash.eql(codec.word_hash(nodes.genesis_hash)));
        return .{ .blocks = blocks };
    }

    pub fn deinit(engine: *SimEngine, allocator: std.mem.Allocator) void {
        allocator.free(engine.blocks);
        engine.* = undefined;
    }

    pub fn head(engine: *const SimEngine) u64 {
        assert(engine.count > 0 and engine.count <= engine.blocks.len);
        return engine.count - 1;
    }

    fn find(engine: *const SimEngine, hash: B256) ?u64 {
        var number = engine.head();
        for (0..engine.count) |_| {
            if (engine.blocks[number].info.block_info.hash.eql(hash)) return number;
            if (number == 0) break;
            number -= 1;
        }
        return null;
    }

    fn slices(block: *const Block, out: *[block_txs_max][]const u8) []const []const u8 {
        for (0..block.tx_count) |index| out[index] = block.transaction(index);
        return out[0..block.tx_count];
    }

    // ------------------------------------------------------------ L2 provider

    pub fn l2_block_info_by_label(
        engine: *SimEngine,
        label: sync_start.Label,
    ) ProviderError!L2BlockInfo {
        const number = switch (label) {
            .latest => engine.head(),
            .safe => engine.safe,
            .finalized => engine.finalized,
        };
        assert(number <= engine.head());
        return engine.blocks[number].info;
    }

    pub fn l2_block_info_by_number(engine: *SimEngine, number: u64) ProviderError!L2BlockInfo {
        if (number > engine.head()) return error.NotFound;
        return engine.blocks[number].info;
    }

    pub fn l2_block_info_by_hash(engine: *SimEngine, hash: B256) ProviderError!L2BlockInfo {
        const number = engine.find(hash) orelse return error.NotFound;
        return engine.blocks[number].info;
    }

    /// The model never updates the system config: every block has the genesis one.
    pub fn system_config_by_l2_hash(engine: *SimEngine, hash: B256) ProviderError!SystemConfig {
        _ = engine.find(hash) orelse return error.NotFound;
        return codec.rollup.genesis.system_config.?;
    }

    pub fn l2_block_by_number(engine: *SimEngine, number: u64) ProviderError!SafeBlock {
        if (number > engine.head()) return error.NotFound;
        const block = &engine.blocks[number];
        return .{
            .transactions = slices(block, &engine.safe_slices),
            .l1_origin_number = block.info.l1_origin.number,
        };
    }

    // ------------------------------------------------------------ Engine API

    fn forkchoice_updated(
        engine: *SimEngine,
        state: *const task.EngineForkchoiceState,
        attributes: ?*const task.EngineAttributes,
    ) ClientError!task.ForkchoiceUpdated {
        const head_number = engine.find(state.head_block_hash) orelse
            return .{ .payload_status = .{ .status = .syncing } };
        const safe = engine.find(state.safe_block_hash) orelse return error.InvalidForkchoiceState;
        const finalized = engine.find(state.finalized_block_hash) orelse
            return error.InvalidForkchoiceState;
        if (finalized > safe or safe > head_number) return error.InvalidForkchoiceState;
        if (safe > engine.safe) engine.count_consolidated(engine.safe, safe);
        if (safe != engine.safe or finalized != engine.finalized) {
            engine.safe_previous = engine.safe;
            engine.finalized_previous = engine.finalized;
        }
        engine.count = head_number + 1;
        engine.safe = safe;
        engine.finalized = finalized;
        const head_hash = state.head_block_hash;
        const built = attributes orelse return .{ .payload_status = .valid(head_hash) };
        if (!engine.build(head_number, built)) {
            return .{ .payload_status = .{ .status = .invalid } };
        }
        return .{ .payload_status = .valid(head_hash), .payload_id = engine.pending_id };
    }

    /// Counts gossiped blocks in `(safe_old, safe_new]` that the safe label now covers:
    /// the derived attributes matched them, so they were consolidated, not rebuilt.
    fn count_consolidated(engine: *SimEngine, safe_old: u64, safe_new: u64) void {
        assert(safe_old < safe_new);
        assert(safe_new <= engine.head());
        for (engine.blocks[safe_old + 1 .. safe_new + 1]) |*block| {
            engine.consolidated_gossip += @intFromBool(block.gossiped);
            block.gossiped = false;
        }
    }

    /// Disk fault: the EL crashed without fsyncing its latest writes. The last label
    /// update is lost, and so are up to `blocks_lost` of the newest blocks, never at or
    /// below the durable finalized head. Startup discovery must recover from what is left.
    pub fn lose_unflushed(engine: *SimEngine, blocks_lost: u64) void {
        assert(blocks_lost <= engine_blocks_lost_max);
        assert(engine.finalized_previous <= engine.safe_previous);
        const finalized = engine.finalized_previous;
        const head_new = @max(engine.head() -| blocks_lost, finalized);
        assert(head_new <= engine.head());
        engine.count = head_new + 1;
        engine.finalized = finalized;
        engine.safe = @min(engine.safe_previous, head_new);
        engine.safe_previous = engine.safe;
        engine.finalized_previous = engine.finalized;
        engine.pending_id = null;
        engine.losses += 1;
        assert(engine.finalized <= engine.safe and engine.safe <= engine.head());
    }

    fn build(engine: *SimEngine, parent: u64, attributes: *const task.EngineAttributes) bool {
        assert(parent <= engine.head());
        const number = parent + 1;
        if (number >= engine.blocks.len) return false;
        if (attributes.timestamp != codec.rollup.l2_block_timestamp(number)) return false;
        const pending = &engine.pending;
        pending.* = .{ .info = .{} };
        if (!pending.store_transactions(attributes.transactions orelse &.{})) return false;
        const transactions = slices(pending, &engine.pending_slices);
        const parent_hash = engine.blocks[parent].info.block_info.hash;
        pending.info.block_info = .{
            .hash = block_hash(parent_hash, number, transactions),
            .number = number,
            .parent_hash = parent_hash,
            .timestamp = attributes.timestamp,
        };
        pending.prev_randao = attributes.prev_randao;
        pending.fee_recipient = attributes.suggested_fee_recipient;
        pending.gas_limit = attributes.gas_limit orelse return false;
        pending.parent_beacon_block_root = attributes.parent_beacon_block_root;
        engine.builds += 1;
        var id: task.PayloadId = undefined;
        std.mem.writeInt(u64, &id, engine.builds, .big);
        engine.pending_id = id;
        assert(pending.tx_count > 0);
        return true;
    }

    fn payload_of(block: *const Block, transactions: []const []const u8) task.ExecutionPayload {
        const info = block.info.block_info;
        return .{
            .parent_hash = info.parent_hash,
            .fee_recipient = block.fee_recipient,
            .state_root = .zero,
            .receipts_root = .zero,
            .logs_bloom = .zero,
            .prev_randao = block.prev_randao,
            .block_number = info.number,
            .gas_limit = block.gas_limit,
            .gas_used = 0,
            .timestamp = info.timestamp,
            .extra_data = &.{},
            .base_fee_per_gas = 7,
            .block_hash = info.hash,
            .transactions = transactions,
            .withdrawals = &.{},
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
        };
    }

    fn get_payload(
        engine: *SimEngine,
        payload_id: task.PayloadId,
    ) ClientError!task.PayloadEnvelope {
        const id = engine.pending_id orelse return error.RpcFailed;
        if (!std.mem.eql(u8, &id, &payload_id)) return error.RpcFailed;
        const transactions = slices(&engine.pending, &engine.pending_slices);
        return .{
            .payload = payload_of(&engine.pending, transactions),
            .block_value = 0,
            .parent_beacon_block_root = engine.pending.parent_beacon_block_root,
        };
    }

    fn new_payload(
        engine: *SimEngine,
        payload: *const task.ExecutionPayload,
        params: *const task.NewPayloadParams,
    ) task.PayloadStatus {
        const number = payload.block_number;
        if (number == 0 or number >= engine.blocks.len) return .{ .status = .invalid };
        if (number > engine.count) return .{ .status = .syncing };
        const parent = &engine.blocks[number - 1].info.block_info;
        if (!parent.hash.eql(payload.parent_hash)) return .{ .status = .syncing };
        const expected = block_hash(payload.parent_hash, number, payload.transactions);
        if (!expected.eql(payload.block_hash)) return .{ .status = .invalid };
        if (payload.timestamp != codec.rollup.l2_block_timestamp(number)) {
            return .{ .status = .invalid };
        }
        const info = task.block_info_from_payload(payload, &codec.rollup.genesis) catch
            return .{ .status = .invalid };
        var block: Block = .{
            .info = info,
            .prev_randao = payload.prev_randao,
            .fee_recipient = payload.fee_recipient,
            .gas_limit = payload.gas_limit,
            .parent_beacon_block_root = params.parent_beacon_block_root,
        };
        if (!block.store_transactions(payload.transactions)) return .{ .status = .invalid };
        const built = engine.pending_id != null and
            engine.pending.info.block_info.hash.eql(payload.block_hash);
        block.gossiped = !built;
        engine.blocks[number] = block;
        engine.count = number + 1;
        engine.safe = @min(engine.safe, number - 1);
        engine.finalized = @min(engine.finalized, engine.safe);
        engine.safe_previous = @min(engine.safe_previous, number - 1);
        engine.finalized_previous = @min(engine.finalized_previous, engine.safe_previous);
        engine.written_low = @min(engine.written_low, number);
        assert(engine.blocks[number].info.block_info.hash.eql(payload.block_hash));
        return .valid(payload.block_hash);
    }

    fn l2_block(engine: *SimEngine, number: u64) ?task.L2Block {
        if (number > engine.head()) return null;
        const block = &engine.blocks[number];
        return .{
            .info = block.info,
            .prev_randao = block.prev_randao,
            .gas_limit = block.gas_limit,
            .fee_recipient = block.fee_recipient,
            .parent_beacon_block_root = block.parent_beacon_block_root,
            .withdrawals = &.{},
            // Canyon: empty withdrawals, so the header holds the empty trie root.
            .withdrawals_root = primitives.empty_root_hash,
            .transactions = slices(block, &engine.read_slices),
        };
    }
};

/// The polling engine client (`engine/task.zig`) over the simulated engine.
pub const EngineClient = struct {
    engine: *SimEngine,
    prng: Prng,
    calls: u64 = 0,

    fn poll(client: *EngineClient) ClientError!void {
        client.calls += 1;
        if (client.prng.below(100) < not_available_percent) return error.NotAvailable;
    }

    pub fn forkchoice_updated(
        client: *EngineClient,
        version: task.Version,
        state: *const task.EngineForkchoiceState,
        attributes: ?*const task.EngineAttributes,
    ) ClientError!task.ForkchoiceUpdated {
        assert(version == .v3); // Ecotone is active from genesis.
        try client.poll();
        return client.engine.forkchoice_updated(state, attributes);
    }

    pub fn new_payload(
        client: *EngineClient,
        version: task.Version,
        payload: *const task.ExecutionPayload,
        params: *const task.NewPayloadParams,
    ) ClientError!task.PayloadStatus {
        assert(version == .v3);
        try client.poll();
        return client.engine.new_payload(payload, params);
    }

    pub fn get_payload(
        client: *EngineClient,
        version: task.Version,
        payload_id: task.PayloadId,
    ) ClientError!task.PayloadEnvelope {
        assert(version == .v3);
        try client.poll();
        return client.engine.get_payload(payload_id);
    }

    pub fn l2_block_by_number(client: *EngineClient, number: u64) ClientError!?task.L2Block {
        try client.poll();
        return client.engine.l2_block(number);
    }

    pub fn l2_block_info_by_number(client: *EngineClient, number: u64) ClientError!?L2BlockInfo {
        const block = try client.l2_block_by_number(number) orelse return null;
        assert(block.info.block_info.number == number);
        return block.info;
    }
};

/// The sequencer's view when it built a block: final L1 origins (never reorged, see
/// `nodes.Sequencer.next_origin`) and the genesis system config the model never changes.
const GossipChain = struct {
    l1: *L1View,

    pub fn l1_header_by_hash(chain: GossipChain, hash: B256) ProviderError!L1Header {
        return chain.l1.l1_header_by_hash(hash);
    }

    pub fn l1_receipts_by_hash(
        chain: GossipChain,
        hash: B256,
    ) ProviderError![]const protocol.log.Receipt {
        return chain.l1.l1_receipts_by_hash(hash);
    }

    pub fn system_config_by_l2_hash(_: GossipChain, _: B256) ProviderError!SystemConfig {
        return codec.rollup.genesis.system_config.?;
    }
};

/// The sequencer's block `number` as an L2 block info (its hash, time, and L1 origin).
fn sequencer_block_info(sequencer: *const nodes.Sequencer, number: u64) L2BlockInfo {
    assert(number <= sequencer.head);
    const chain = &sequencer.chain;
    const origin = chain.origins[number];
    const result: L2BlockInfo = .{
        .block_info = .{
            .hash = codec.word_hash(chain.hashes[number]),
            .number = number,
            .parent_hash = if (number == 0) .zero else codec.word_hash(chain.hashes[number - 1]),
            .timestamp = codec.rollup.l2_block_timestamp(number),
        },
        .l1_origin = .{ .number = origin.number, .hash = codec.word_hash(origin.hash) },
        .sequence_number = origin.sequence_number,
    };
    assert(result.block_info.number == number);
    return result;
}

const Providers = struct {
    l1: *L1View,
    blobs: *L1View,
    l2: *SimEngine,
    engine: *EngineClient,
    l1_head: ?BlockInfo,
    l1_finalized: ?BlockInfo,
};

pub const RealVerifier = struct {
    allocator: std.mem.Allocator,
    rollup: protocol.RollupConfig,
    blob_schedule: protocol.l1_info.L1BlobSchedule = .{},
    engine: SimEngine,
    client: EngineClient,
    l1_view: L1View = undefined,
    safe_db: SafeDB,
    driver: Driver,
    restarts: u32 = 0,
    /// Blocks up to here passed the per-block derivation check.
    checked: u64 = 0,
    /// Fixed scratch for the attributes builder of gossiped payloads (reset per payload).
    gossip_scratch: []u8,
    /// Highest gossiped block number seen this incarnation, and the last sync request.
    sequencer_head_known: u64 = 0,
    sync_ns: u64 = 0,
    gossip_received: u64 = 0,
    gossip_kept: u64 = 0,

    /// Heap-allocated: the driver keeps pointers to the rollup config and safe db.
    pub fn create(
        allocator: std.mem.Allocator,
        block_count_max: u64,
        seed: u64,
    ) !*RealVerifier {
        const verifier = try allocator.create(RealVerifier);
        errdefer allocator.destroy(verifier);
        const gossip_scratch = try allocator.alloc(u8, gossip_scratch_bytes);
        errdefer allocator.free(gossip_scratch);
        verifier.* = .{
            .allocator = allocator,
            .rollup = codec.rollup,
            .engine = try SimEngine.init(allocator, block_count_max),
            .client = undefined,
            .safe_db = undefined,
            .driver = undefined,
            .gossip_scratch = gossip_scratch,
        };
        errdefer verifier.engine.deinit(allocator);
        verifier.client = .{ .engine = &verifier.engine, .prng = Prng.init(seed) };
        try verifier.start();
        assert(verifier.driver.phase == .starting);
        return verifier;
    }

    pub fn destroy(verifier: *RealVerifier) void {
        const allocator = verifier.allocator;
        verifier.stop();
        verifier.engine.deinit(allocator);
        allocator.free(verifier.gossip_scratch);
        allocator.destroy(verifier);
    }

    fn start(verifier: *RealVerifier) !void {
        verifier.safe_db = try SafeDB.init(verifier.allocator, safe_db_capacity);
        errdefer verifier.safe_db.deinit(verifier.allocator);
        try verifier.driver.init(
            verifier.allocator,
            &verifier.rollup,
            &verifier.blob_schedule,
            &verifier.safe_db,
            .{},
        );
    }

    fn stop(verifier: *RealVerifier) void {
        verifier.driver.deinit();
        verifier.safe_db.deinit(verifier.allocator);
    }

    /// Crash-restart of the node: all driver state is lost; the engine keeps its chain
    /// and labels, minus its unflushed writes on a disk fault (`blocks_lost` non-null),
    /// and startup discovery rebuilds the heads from them.
    pub fn restart(verifier: *RealVerifier, blocks_lost: ?u64) !void {
        verifier.stop();
        if (blocks_lost) |count| verifier.engine.lose_unflushed(count);
        try verifier.start();
        verifier.restarts += 1;
        verifier.sequencer_head_known = 0;
        verifier.sync_ns = 0;
        assert(verifier.driver.phase == .starting);
    }

    /// The sequencer's gossip for block `number` arrived. Builds the execution payload the
    /// sequencer built (L1 info deposit for its L1 origin, then the payload transaction)
    /// and hands it to the driver as the real node does with gossiped payloads.
    pub fn on_unsafe_block(
        verifier: *RealVerifier,
        sequencer: *const nodes.Sequencer,
        view: View,
        number: u64,
        payload: u64,
        hash: u64,
    ) void {
        assert(number > 0 and number <= sequencer.head);
        verifier.gossip_received += 1;
        verifier.sequencer_head_known = @max(verifier.sequencer_head_known, number);
        if (verifier.driver.phase != .running) return;
        if (number <= verifier.unsafe_number()) return; // Stale: skip the build work.
        var fixed: std.heap.FixedBufferAllocator = .init(verifier.gossip_scratch);
        var builder = attributes_module.AttributesBuilder.init(
            fixed.allocator(),
            &verifier.rollup,
            &verifier.blob_schedule,
        );
        // The sequencer read L1 directly when it built the block.
        var l1: L1View = .{ .l1 = view.l1, .pool = view.pool, .reachable = true };
        const parent = sequencer_block_info(sequencer, number - 1);
        const origin = sequencer_block_info(sequencer, number).l1_origin;
        const chain: GossipChain = .{ .l1 = &l1 };
        const attributes = builder.prepare_payload_attributes(chain, parent, origin) catch
            unreachable; // Proof: origins are final canonical L1 blocks; scratch is ample.
        assert(attributes.transactions.len == 1); // No deposits or upgrades in the model.
        var tx_buffer: [codec.payload_tx_length_max]u8 = undefined;
        const transactions = [2][]const u8{
            attributes.transactions[0],
            codec.payload_tx(payload, &tx_buffer),
        };
        const envelope: InsertEnvelope = .{
            .payload = .{
                .parent_hash = parent.block_info.hash,
                .fee_recipient = attributes.suggested_fee_recipient,
                .state_root = .zero,
                .receipts_root = .zero,
                .logs_bloom = .zero,
                .prev_randao = attributes.prev_randao,
                .block_number = number,
                .gas_limit = attributes.gas_limit,
                .gas_used = 0,
                .timestamp = attributes.timestamp,
                .extra_data = &.{},
                .base_fee_per_gas = 7,
                .block_hash = codec.word_hash(hash),
                .transactions = &transactions,
                .withdrawals = attributes.withdrawals,
                .blob_gas_used = 0,
                .excess_blob_gas = 0,
            },
            .parent_beacon_block_root = attributes.parent_beacon_block_root,
        };
        verifier.gossip_kept += @intFromBool(verifier.driver.insert_unsafe(&envelope));
    }

    /// The first block to request from the sequencer when the unsafe head lags the gossip
    /// seen, at most once per `sync_timeout_ns`; null when nothing is missing.
    pub fn sync_request(verifier: *RealVerifier, now_ns: u64) ?u64 {
        if (verifier.driver.phase != .running) return null;
        const unsafe = verifier.unsafe_number();
        if (verifier.sequencer_head_known <= unsafe) return null;
        if (now_ns < verifier.sync_ns + sync_timeout_ns) return null;
        verifier.sync_ns = now_ns;
        assert(unsafe + 1 <= verifier.sequencer_head_known);
        return unsafe + 1;
    }

    pub fn tick(verifier: *RealVerifier, view: View) void {
        verifier.l1_view = .{ .l1 = view.l1, .pool = view.pool, .reachable = view.l1_reachable };
        const l1 = &verifier.l1_view;
        const final_depth = nodes.l1_reorg_depth_max;
        const providers: Providers = .{
            .l1 = l1,
            .blobs = l1,
            .l2 = &verifier.engine,
            .engine = &verifier.client,
            .l1_head = if (view.l1_reachable) l1.info(view.l1.head) else null,
            .l1_finalized = if (view.l1_reachable and view.l1.head >= final_depth)
                l1.info(view.l1.head - final_depth)
            else
                null,
        };
        verifier.driver.tick(providers, view.now_ns / std.time.ns_per_s);
    }

    /// The driver's safe head, or null during startup discovery (heads not yet known).
    pub fn safe_head(verifier: *const RealVerifier) ?L2BlockInfo {
        if (verifier.driver.phase == .starting) return null;
        return verifier.driver.sync_state().safe_head;
    }

    pub fn safe_number(verifier: *const RealVerifier) u64 {
        const head = verifier.safe_head() orelse return 0;
        return head.block_info.number;
    }

    /// The driver's unsafe head, or null during startup discovery.
    pub fn unsafe_head(verifier: *const RealVerifier) ?L2BlockInfo {
        if (verifier.driver.phase == .starting) return null;
        return verifier.driver.sync_state().unsafe_head;
    }

    pub fn unsafe_number(verifier: *const RealVerifier) u64 {
        const head = verifier.unsafe_head() orelse return 0;
        return head.block_info.number;
    }

    /// Safety: the driver never fails critically; the safe and unsafe heads are sequencer
    /// blocks with safe <= unsafe; and every engine block up to the safe head carries
    /// exactly the sequencer's payload transaction and L1 origin. Returns the violated
    /// invariant, or null.
    pub fn check(verifier: *RealVerifier, sequencer: *const nodes.Sequencer) ?[]const u8 {
        if (verifier.driver.stats.critical_errors != 0) return "real verifier critical error";
        const safe = (verifier.safe_head() orelse return null).block_info;
        if (safe.number > sequencer.head) return "real verifier safe > sequencer";
        const expected = codec.word_hash(sequencer.chain.hashes[safe.number]);
        if (!safe.hash.eql(expected)) return "real verifier safe head diverged";
        const unsafe = verifier.unsafe_head().?.block_info;
        if (unsafe.number < safe.number) return "real verifier safe > unsafe";
        if (unsafe.number > sequencer.head) return "real verifier unsafe > sequencer";
        const unsafe_expected = codec.word_hash(sequencer.chain.hashes[unsafe.number]);
        if (!unsafe.hash.eql(unsafe_expected)) return "real verifier unsafe head diverged";
        const engine = &verifier.engine;
        if (engine.written_low <= verifier.checked) verifier.checked = engine.written_low - 1;
        engine.written_low = std.math.maxInt(u64);
        while (verifier.checked < safe.number) {
            const number = verifier.checked + 1;
            if (check_block(&engine.blocks[number], sequencer, number)) |reason| return reason;
            verifier.checked = number;
        }
        assert(verifier.checked >= safe.number);
        return null;
    }

    fn check_block(
        block: *const Block,
        sequencer: *const nodes.Sequencer,
        number: u64,
    ) ?[]const u8 {
        assert(block.info.block_info.number == number);
        if (block.tx_count < 2) return "real verifier derived a deposit-only block";
        if (block.tx_count > 2) return "real verifier derived extra transactions";
        var buffer: [codec.payload_tx_length_max]u8 = undefined;
        const expected = codec.payload_tx(sequencer.chain.payloads[number], &buffer);
        if (!std.mem.eql(u8, block.transaction(1), expected)) {
            return "real verifier derived a different transaction";
        }
        const origin = sequencer.chain.origins[number];
        const l1_origin = block.info.l1_origin;
        if (l1_origin.number != origin.number or
            !l1_origin.hash.eql(codec.word_hash(origin.hash)) or
            block.info.sequence_number != origin.sequence_number)
        {
            return "real verifier derived a different L1 origin";
        }
        return null;
    }
};

const testing = std.testing;

test "real verifier: engine hash matches the model sequencer's" {
    var buffer: [codec.payload_tx_length_max]u8 = undefined;
    const user = codec.payload_tx(42, &buffer);
    const deposit = [_]u8{ 0x7e, 0x01 };
    const transactions = [_][]const u8{ &deposit, user };
    const parent = codec.word_hash(nodes.genesis_hash);
    const hash = block_hash(parent, 1, &transactions);
    try testing.expect(hash.eql(codec.word_hash(nodes.block_hash(nodes.genesis_hash, 1, 42))));
    const deposit_only = block_hash(parent, 1, transactions[0..1]);
    try testing.expect(!deposit_only.eql(hash));
}

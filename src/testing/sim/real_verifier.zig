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
//!   rebuilds its heads through startup discovery, as the binary does;
//! - `EngineClient` polls the engine with seeded random `NotAvailable` latency.
//!
//! The real verifier shares the first model verifier's fate (crashes, partitions): it is
//! that node's consensus client. The model verifier keeps running beside it for the
//! model invariants and the real batcher's rollup RPC.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../../consensus/protocol/root.zig");
const driver_module = @import("../../consensus/service/driver.zig");
const task = @import("../../consensus/engine/task.zig");
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
        engine.blocks[number] = block;
        engine.count = number + 1;
        engine.safe = @min(engine.safe, number - 1);
        engine.finalized = @min(engine.finalized, engine.safe);
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

    /// Heap-allocated: the driver keeps pointers to the rollup config and safe db.
    pub fn create(
        allocator: std.mem.Allocator,
        block_count_max: u64,
        seed: u64,
    ) !*RealVerifier {
        const verifier = try allocator.create(RealVerifier);
        errdefer allocator.destroy(verifier);
        verifier.* = .{
            .allocator = allocator,
            .rollup = codec.rollup,
            .engine = try SimEngine.init(allocator, block_count_max),
            .client = undefined,
            .safe_db = undefined,
            .driver = undefined,
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

    /// Crash-restart of the consensus node: all driver state is lost; the engine keeps
    /// its chain and labels, and startup discovery rebuilds the heads from them.
    pub fn restart(verifier: *RealVerifier) !void {
        verifier.stop();
        try verifier.start();
        verifier.restarts += 1;
        assert(verifier.driver.phase == .starting);
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

    /// Safety: the driver never fails critically; the safe head is a sequencer block; and
    /// every engine block up to it carries exactly the sequencer's payload transaction and
    /// L1 origin. Returns the violated invariant, or null.
    pub fn check(verifier: *RealVerifier, sequencer: *const nodes.Sequencer) ?[]const u8 {
        if (verifier.driver.stats.critical_errors != 0) return "real verifier critical error";
        const safe = (verifier.safe_head() orelse return null).block_info;
        if (safe.number > sequencer.head) return "real verifier safe > sequencer";
        const expected = codec.word_hash(sequencer.chain.hashes[safe.number]);
        if (!safe.hash.eql(expected)) return "real verifier safe head diverged";
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

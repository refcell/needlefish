//! Fault-proof client end to end over real blocks: the execution node builds L2 blocks
//! from derived attributes (L1 info deposit plus signed user transfers), the batcher's
//! channel manager frames their batches into signed type-2 L1 transactions to the inbox,
//! and the client derives and statelessly executes them through the real host hint
//! handler, which serves every preimage from an in-memory chain source.
//!
//! Scenarios vary the shape: L2 blocks across an L1 epoch change, one span batch instead
//! of singular batches, frames in an EIP-4844 blob instead of calldata, a batch whose
//! last block fails to execute (Holocene: replaced by its deposit-only block), and the
//! intermediate output roots sampled at the boot's interval (key 9).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const preimage = @import("../preimage/root.zig");
const host = @import("../host/root.zig");
const program = @import("../program/root.zig");
const executor = @import("../executor/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const chains = @import("../../common/chains/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const derive = @import("../../consensus/derive/root.zig");
const json = @import("../../utilities/json/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const trie = @import("../../execution/trie/root.zig");
const db_module = @import("../../execution/db/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const node_witness = @import("../../execution/node/witness.zig");
const engine_types = @import("../../execution/engine/root.zig").types;
const engine_json = @import("../../execution/rpc/engine_json.zig");
const payload = @import("../../execution/payload/root.zig");
const channel_manager = @import("../../batcher/channel/manager.zig");
const batcher_source = @import("../../batcher/source/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const channel_out = @import("../../batcher/channel/root.zig");
const batcher_frame = @import("../../batcher/frame/root.zig");
const batcher_blobs = @import("../../batcher/blobs/root.zig");
const client = @import("client.zig");

const Hash = [32]u8;
const B256 = primitives.B256;
const Chain = host.handler.Chain;
const SourceError = host.handler.SourceError;
const ProviderError = derive.errors.ProviderError;
const L1Header = protocol.l1_info.L1Header;
const Receipt = protocol.log.Receipt;
const L2BlockInfo = protocol.L2BlockInfo;
const SystemConfig = protocol.SystemConfig;
const spec = &chainspec.ChainSpec.presets.base_devnet;

/// L2 blocks derived and proven.
const l2_blocks = 3;
/// L1 blocks at most: genesis (epoch 0), an empty epoch-1 block (only when a scenario
/// changes epoch), and the block carrying the batches (the L1 head).
const l1_blocks_max = 3;
const inbox: primitives.Address = .{ .bytes = @splat(0xbb) };

const sparse_config: db_module.witness.SparseState.Config = .{
    .nodes_max = 1024,
    .node_bytes_max = 1 << 18,
    .codes_max = 16,
    .code_bytes_max = 1 << 16,
    .headers_max = 16,
    .trie_nodes_max = 4096,
    .storage_tries_max = 32,
};

const changeset_config: db_module.changeset.Config = .{
    .accounts_max = 256,
    .storage_max = 1024,
    .codes_max = 64,
    .code_bytes_max = 1 << 16,
};

const generator_config: db_module.witness_block.Config = .{
    .builder = .{ .sparse = sparse_config, .keys = .{
        .accounts_max = 64,
        .slots_max = 256,
        .codes_max = 16,
        .block_numbers_max = 16,
    } },
    .witness = .{
        .state_nodes_max = 1024,
        .state_bytes_max = 1 << 18,
        .codes_max = 16,
        .code_bytes_max = 1 << 16,
        .keys_max = 64 + 256,
        .headers_max = 16,
        .header_bytes_max = 1 << 14,
    },
    .overlay = .{ .accounts_max = 256, .slots_max = 1024, .codes_max = 64 },
    .changeset = changeset_config,
    .depth_max = 8,
};

const builder_config: executor.builder.Config = .{
    .sparse = sparse_config,
    .changeset = changeset_config,
    .executor = .{
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
    },
    .resolver = .{ .bytes_max = 1 << 20, .entries_max = 4096 },
};

const List = []const []const u8;

/// The shape of one end-to-end run.
const Scenario = struct {
    /// Blocks `1..=epoch_zero_blocks` take L1 genesis as origin, later blocks L1 block 1.
    epoch_zero_blocks: u32 = l2_blocks,
    batch: enum { singular, span } = .singular,
    data: enum { calldata, blob } = .calldata,
    /// The last block's batch carries a transaction execution rejects, so the node builds
    /// that block from its deposits only (Holocene).
    invalid: enum {
        none,
        /// First in the batch: a fee cap below the base fee, rejected before any state
        /// read, so the deposit-only block's witness suffices.
        fee_cap_first,
        /// Last, after two transfers that read and write state: a nonce gap from the
        /// first transfer's sender. The client executes the transfers before the failure,
        /// so it needs the witness of the attempted payload.
        nonce_gap_last,
    } = .none,
    /// The source serves the attempted payload's witness for a nonce-gap block; false
    /// serves only the node's deposit-only block's (a host keyed by the canonical child).
    attempted_witness: bool = true,
    /// Boot key 9: blocks between two intermediate output roots.
    interval: u64 = 1,

    fn epoch_change(scenario: Scenario) bool {
        assert(scenario.epoch_zero_blocks >= 1);
        assert(scenario.epoch_zero_blocks <= l2_blocks);
        return scenario.epoch_zero_blocks < l2_blocks;
    }
};

/// The host's chain source over in-memory maps; every value is owned by `arena`.
const MapSource = struct {
    arena: std.heap.ArenaAllocator,
    headers: std.AutoHashMapUnmanaged(Hash, []const u8) = .empty,
    l1_bodies: std.AutoHashMapUnmanaged(Hash, List) = .empty,
    l2_bodies: std.AutoHashMapUnmanaged(Hash, List) = .empty,
    receipt_lists: std.AutoHashMapUnmanaged(Hash, List) = .empty,
    preimages: std.AutoHashMapUnmanaged(Hash, []const u8) = .empty,
    /// Witness byte strings of the node-built child, keyed by parent hash.
    witnesses: std.AutoHashMapUnmanaged(Hash, List) = .empty,
    /// Witnesses of attempted payloads that fail to execute (user transactions the node
    /// left out), keyed by parent hash; served for attributes with user transactions.
    attempted: std.AutoHashMapUnmanaged(Hash, List) = .empty,
    attempted_requests: u32 = 0,
    /// Blobs by versioned hash.
    blobs: std.AutoHashMapUnmanaged(Hash, host.handler.Blob) = .empty,
    witness_requests: u32 = 0,
    blob_requests: u32 = 0,

    fn deinit(source: *MapSource) void {
        const allocator = testing.allocator;
        source.headers.deinit(allocator);
        source.l1_bodies.deinit(allocator);
        source.l2_bodies.deinit(allocator);
        source.receipt_lists.deinit(allocator);
        source.preimages.deinit(allocator);
        source.witnesses.deinit(allocator);
        source.attempted.deinit(allocator);
        source.blobs.deinit(allocator);
        source.arena.deinit();
    }

    fn copy_list(source: *MapSource, items: List) !List {
        const arena = source.arena.allocator();
        const copies = try arena.alloc([]const u8, items.len);
        for (copies, items) |*copy, item| copy.* = try arena.dupe(u8, item);
        return copies;
    }

    /// Adds `header` with its body; returns its hash.
    fn add_block(source: *MapSource, chain: Chain, header: consensus.Header, items: List) !Hash {
        var buffer: [2048]u8 = undefined;
        const encoded = try source.arena.allocator().dupe(u8, rlp.encode_to(&buffer, header));
        const hash = header.hash().bytes;
        assert(std.mem.eql(u8, &keccak.keccak256(encoded), &hash));
        try source.headers.put(testing.allocator, hash, encoded);
        const bodies = if (chain == .l1) &source.l1_bodies else &source.l2_bodies;
        try bodies.put(testing.allocator, hash, try source.copy_list(items));
        return hash;
    }

    fn add_preimage(source: *MapSource, bytes: []const u8) !void {
        const hash = keccak.keccak256(bytes);
        if (source.preimages.contains(hash)) return;
        const copy = try source.arena.allocator().dupe(u8, bytes);
        try source.preimages.put(testing.allocator, hash, copy);
    }

    fn get(context: *anyopaque) *MapSource {
        return @ptrCast(@alignCast(context));
    }

    fn raw_header(context: *anyopaque, chain: Chain, hash: Hash) SourceError![]const u8 {
        _ = chain;
        return get(context).headers.get(hash) orelse error.NotFound;
    }

    fn transactions(context: *anyopaque, chain: Chain, hash: Hash) SourceError!List {
        const source = get(context);
        const bodies = if (chain == .l1) &source.l1_bodies else &source.l2_bodies;
        return bodies.get(hash) orelse error.NotFound;
    }

    fn receipts(context: *anyopaque, hash: Hash) SourceError!List {
        return get(context).receipt_lists.get(hash) orelse error.NotFound;
    }

    fn blob(context: *anyopaque, hash: Hash, timestamp: u64) SourceError!host.handler.Blob {
        const source = get(context);
        if (timestamp == 0) return error.SourceFailed; // Blobs are never in L1 genesis.
        source.blob_requests += 1;
        return source.blobs.get(hash) orelse error.NotFound;
    }

    fn preimage_of(context: *anyopaque, hash: Hash) SourceError![]const u8 {
        return get(context).preimages.get(hash) orelse error.NotFound;
    }

    fn payload_witness(context: *anyopaque, parent: Hash, attributes: []const u8) SourceError!List {
        const source = get(context);
        if (attributes.len == 0 or attributes[0] != '{') return error.SourceFailed;
        source.witness_requests += 1;
        if (source.attempted.get(parent)) |items| {
            if (try has_user_transactions(attributes)) {
                source.attempted_requests += 1;
                return items;
            }
        }
        return source.witnesses.get(parent) orelse error.NotFound;
    }

    /// True when the attributes JSON carries a non-deposit transaction.
    fn has_user_transactions(attributes: []const u8) SourceError!bool {
        var bytes: [1 << 14]u8 = undefined;
        var transaction_slots: [64][]const u8 = undefined;
        var withdrawals: [4]payload.Withdrawal = undefined;
        var hashes: [4]B256 = undefined;
        var space: engine_json.Space = .{
            .bytes = &bytes,
            .transactions = &transaction_slots,
            .withdrawals = &withdrawals,
            .hashes = &hashes,
        };
        const parsed = engine_json.parse_attributes(attributes, &space) catch
            return error.SourceFailed;
        const list = parsed.transactions orelse return false;
        for (list) |transaction| {
            if (transaction.len == 0) return error.SourceFailed;
            if (transaction[0] != 0x7e) return true;
        }
        return false;
    }

    const vtable: host.handler.Source.VTable = .{
        .raw_header = raw_header,
        .transactions = transactions,
        .receipts = receipts,
        .blob = blob,
        .preimage = preimage_of,
        .payload_witness = payload_witness,
    };

    fn as_source(source: *MapSource) host.handler.Source {
        return .{ .context = source, .vtable = &vtable };
    }
};

fn l1_header_of(header: *const consensus.Header) L1Header {
    return .{
        .number = header.number,
        .timestamp = header.timestamp,
        .hash = header.hash(),
        .base_fee = header.base_fee_per_gas,
        .excess_blob_gas = header.excess_blob_gas,
        .parent_hash = header.parent_hash,
        .mix_hash = header.mix_hash,
        .blob_gas_used = header.blob_gas_used,
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .requests_hash = header.requests_hash,
    };
}

/// The attributes builder's chain view: the L1 headers and the built L2 system configs.
const ChainView = struct {
    rollup: *const protocol.RollupConfig,
    l1: [l1_blocks_max]L1Header = undefined,
    l1_count: u32 = 0,
    configs: [l2_blocks + 1]struct { hash: B256, config: SystemConfig } = undefined,
    config_count: u32 = 0,

    pub fn l1_header_by_hash(view: *ChainView, hash: B256) ProviderError!L1Header {
        for (view.l1[0..view.l1_count]) |header| if (header.hash.eql(hash)) return header;
        return error.NotFound;
    }

    pub fn l1_receipts_by_hash(view: *ChainView, hash: B256) ProviderError![]const Receipt {
        _ = view;
        _ = hash;
        return &.{};
    }

    pub fn system_config_by_l2_hash(view: *ChainView, hash: B256) ProviderError!SystemConfig {
        if (hash.eql(view.rollup.genesis.l2.hash)) return view.rollup.genesis.system_config.?;
        for (view.configs[0..view.config_count]) |entry| {
            if (entry.hash.eql(hash)) return entry.config;
        }
        return error.NotFound;
    }
};

/// One L2 block the node built: its transactions (all, and the batched non-deposits).
const Built = struct {
    hash: Hash,
    info: L2BlockInfo,
    all: List,
    user: List,
};

var kzg_storage: kzg.blob.Settings.Storage = undefined;
var kzg_workspace: kzg.blob.Workspace = undefined;
/// Big-endian roots of unity in bit-reversal order, for the host's blob keys.
var host_roots_brp: [kzg.field_elements_per_blob][32]u8 = undefined;

const Fixture = struct {
    scenario: Scenario,
    node: *fixture.Node,
    generator: db_module.witness_block.Generator,
    source: MapSource,
    store: host.Store,
    handler: host.Handler,
    rollup: protocol.RollupConfig,
    bpo: [2]protocol.l1_info.L1BlobSchedule.Entry,
    blob_schedule: protocol.l1_info.L1BlobSchedule,
    view: ChainView,
    l1_hashes: [l1_blocks_max]Hash,
    l1_count: u32,
    blocks: [l2_blocks + 1]Built,
    agreed: Hash,
    expected: Hash,
    rollup_json: [8192]u8,
    sampler: program.IntermediateRootSampler,

    fn create(scenario: Scenario) !*Fixture {
        const allocator = testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.scenario = scenario;
        self.node = try fixture.Node.create_for(spec);
        errdefer self.node.destroy();
        self.generator = try .init(allocator, self.node.db.state, generator_config);
        errdefer self.generator.deinit(allocator);
        self.source = .{ .arena = .init(allocator) };
        errdefer self.source.deinit();
        self.store = .init(allocator, .{});
        errdefer self.store.deinit();
        self.handler = .{ .store = &self.store, .source = self.source.as_source() };
        if (scenario.data == .blob) {
            host.handler.fill_roots(&host_roots_brp);
            self.handler.roots_brp = &host_roots_brp;
        }
        try self.add_l1_genesis();
        self.init_rollup();
        self.view = .{ .rollup = &self.rollup };
        self.view.l1[0] = l1_header_of(&l1_genesis_header());
        self.view.l1_count = 1;
        if (scenario.epoch_change()) try self.add_epoch_block();
        self.blob_schedule = client.blob_schedule_of(&chains.l1_devnet, &self.bpo);
        try self.build_l2();
        try self.add_witnesses();
        try self.add_batch_block();
        return self;
    }

    fn destroy(self: *Fixture) void {
        const allocator = testing.allocator;
        self.store.deinit();
        self.source.deinit();
        self.generator.deinit(allocator);
        self.node.destroy();
        allocator.destroy(self);
    }

    fn l1_genesis_header() consensus.Header {
        var header = fixture.genesis_header(@splat(0x11));
        header.transactions_root = .{ .bytes = trie.node.empty_root };
        header.receipts_root = .{ .bytes = trie.node.empty_root };
        header.mix_hash = .{ .bytes = @splat(0x42) };
        return header;
    }

    fn add_l1_genesis(self: *Fixture) !void {
        const header = l1_genesis_header();
        self.l1_hashes[0] = try self.source.add_block(.l1, header, &.{});
        self.l1_count = 1;
        try self.source.receipt_lists.put(testing.allocator, self.l1_hashes[0], &.{});
    }

    /// Adds the empty L1 block 1, the origin of the blocks after `epoch_zero_blocks`; it
    /// is as old as the first of them.
    fn add_epoch_block(self: *Fixture) !void {
        assert(self.l1_count == 1);
        const first = self.scenario.epoch_zero_blocks + 1;
        var header = l1_genesis_header();
        header.parent_hash = .{ .bytes = self.l1_hashes[0] };
        header.number = 1;
        header.timestamp = self.rollup.genesis.l2_time + self.rollup.block_time * first;
        self.l1_hashes[1] = try self.source.add_block(.l1, header, &.{});
        try self.source.receipt_lists.put(testing.allocator, self.l1_hashes[1], &.{});
        self.l1_count = 2;
        self.view.l1[1] = l1_header_of(&header);
        self.view.l1_count = 2;
        assert(self.view.l1[1].hash.eql(.{ .bytes = self.l1_hashes[1] }));
    }

    /// The L1 origin of L2 block `number`.
    fn epoch_of(self: *const Fixture, number: usize) protocol.BlockId {
        assert(number >= 1);
        if (number <= self.scenario.epoch_zero_blocks) return self.rollup.genesis.l1;
        assert(self.l1_count >= 2);
        return .{ .number = 1, .hash = .{ .bytes = self.l1_hashes[1] } };
    }

    fn sequence_number_of(self: *const Fixture, number: usize) u64 {
        const zero = self.scenario.epoch_zero_blocks;
        return if (number <= zero) number else number - zero - 1;
    }

    fn init_rollup(self: *Fixture) void {
        const genesis = self.node.chain.header(self.node.chain.head_hash()).?;
        assert(genesis.number == 0);
        self.rollup = .{
            .l1_chain_id = chains.l1_devnet.chain_id,
            .l2_chain_id = chains.devnet.chain_id,
            .block_time = 2,
            .seq_window_size = 3600,
            .max_sequencer_drift = 600,
            .channel_timeout = 300,
            .batch_inbox_address = inbox,
        };
        self.rollup.genesis = .{
            .l1 = .{ .number = 0, .hash = .{ .bytes = self.l1_hashes[0] } },
            .l2 = .{ .number = 0, .hash = .{ .bytes = self.node.chain.head_hash() } },
            .l2_time = genesis.timestamp,
            .system_config = .{
                .batcher_address = accounts.derive_dev(@backingInt(accounts.Role.batcher)).address,
                .gas_limit = genesis.gas_limit,
            },
        };
        // Align with the execution spec: everything through Azul at genesis.
        const upgrades = [_]protocol.Upgrade{
            .regolith, .canyon,               .delta,   .ecotone, .fjord, .granite,
            .holocene, .pectra_blob_schedule, .isthmus, .jovian,  .azul,
        };
        for (upgrades) |upgrade| self.rollup.upgrades.set(upgrade, 0);
        assert(self.rollup.is_active(.azul, genesis.timestamp));
    }

    /// Signs one transfer from funded fixture account `from`.
    fn transfer(self: *Fixture, from: u8, nonce: u64) ![]const u8 {
        return self.transfer_paying(from, nonce, 10_000_000_000);
    }

    fn transfer_paying(self: *Fixture, from: u8, nonce: u64, max_fee_per_gas: u64) ![]const u8 {
        assert(max_fee_per_gas > 0);
        const tx: consensus.Eip1559 = .{
            .chain_id = spec.chain_id,
            .nonce = nonce,
            .max_priority_fee_per_gas = @min(2, max_fee_per_gas),
            .max_fee_per_gas = max_fee_per_gas,
            .gas_limit = 21_000,
            .to = .{ .call = fixture.address_of(9) },
            .value = 1000 + nonce,
            .input = &.{},
            .access_list = .empty,
        };
        const envelope = try consensus.tx.sign(tx, fixture.key(from));
        var buffer: [256]u8 = undefined;
        return self.source.arena.allocator().dupe(u8, envelope.encode_to(&buffer));
    }

    fn build_l2(self: *Fixture) !void {
        const genesis_hash = self.node.chain.head_hash();
        const genesis = self.node.chain.header(genesis_hash).?;
        self.blocks[0] = .{
            .hash = genesis_hash,
            .info = .{
                .block_info = .{
                    .hash = .{ .bytes = genesis_hash },
                    .timestamp = genesis.timestamp,
                },
                .l1_origin = self.rollup.genesis.l1,
            },
            .all = &.{},
            .user = &.{},
        };
        _ = try self.source.add_block(.l2, genesis, &.{});
        for (1..l2_blocks + 1) |number| try self.build_one(number);
    }

    /// The batched user transactions of block `number`: two transfers, plus (when the
    /// last block is invalid) one execution rejects and derivation accepts: a fee cap
    /// below the base fee first (rejected before reading state, as revm's environment
    /// check does), or a nonce gap after the transfers.
    fn user_transactions(self: *Fixture, number: usize) !List {
        const invalid = if (number == l2_blocks) self.scenario.invalid else .none;
        const arena = self.source.arena.allocator();
        const user = try arena.alloc([]const u8, if (invalid == .none) 2 else 3);
        const first: usize = if (invalid == .fee_cap_first) 1 else 0;
        if (invalid == .fee_cap_first) user[0] = try self.transfer_paying(3, 0, 1);
        user[first] = try self.transfer(1, number - 1);
        user[first + 1] = try self.transfer(2, number - 1);
        // Sender 1's next nonce is `number`; `number + 1` leaves a gap.
        if (invalid == .nonce_gap_last) user[2] = try self.transfer(1, number + 1);
        assert(user.len >= 2);
        return user;
    }

    /// Derives the attributes of block `number`, adds its user transactions and builds
    /// it (from the deposits alone when the batch is invalid to execute).
    fn build_one(self: *Fixture, number: usize) !void {
        const allocator = testing.allocator;
        const parent = self.blocks[number - 1];
        var builder: derive.attributes.AttributesBuilder =
            .init(allocator, &self.rollup, &self.blob_schedule);
        var attributes = try builder.prepare_payload_attributes(
            &self.view,
            parent.info,
            self.epoch_of(number),
        );
        defer attributes.deinit(allocator);
        const arena = self.source.arena.allocator();
        const user = try self.user_transactions(number);
        const executed = if (user.len > 2) 0 else user.len;
        const deposits = attributes.transactions.len;
        const all = try arena.alloc([]const u8, deposits + executed);
        for (all[0..deposits], attributes.transactions) |*copy, item| {
            copy.* = try arena.dupe(u8, item);
        }
        @memcpy(all[deposits..], user[0..executed]);
        var engine_attributes = attributes.engine();
        if (self.scenario.invalid == .nonce_gap_last and number == l2_blocks) {
            try self.add_attempted_witness(parent.hash, engine_attributes, user);
        }
        engine_attributes.transactions = all;
        const hash = try self.execute(parent.hash, &engine_attributes);
        const header = self.node.chain.header(hash).?;
        try testing.expectEqual(@as(u64, number), header.number);
        _ = try self.source.add_block(.l2, header, all);
        const info = try program.l2_chain_provider.decode_l1_info(all);
        try testing.expectEqual(self.sequence_number_of(number), info.sequence_number);
        try testing.expectEqual(self.epoch_of(number).number, info.number);
        try self.record(number, hash, header, info, all, user);
    }

    /// Records built block `number` for the batcher and its system config for the
    /// attributes builder.
    fn record(
        self: *Fixture,
        number: usize,
        hash: Hash,
        header: consensus.Header,
        info: protocol.L1BlockInfo,
        all: List,
        user: List,
    ) !void {
        assert(number >= 1);
        assert(number <= l2_blocks);
        const parent = self.blocks[number - 1];
        self.blocks[number] = .{
            .hash = hash,
            .info = .{
                .block_info = .{
                    .hash = .{ .bytes = hash },
                    .number = number,
                    .parent_hash = .{ .bytes = parent.hash },
                    .timestamp = header.timestamp,
                },
                .l1_origin = info.id(),
                .sequence_number = info.sequence_number,
            },
            .all = all,
            .user = user,
        };
        const config = try protocol.l2_system_config.from_l1_info(&self.rollup, &info, .{
            .number = number,
            .hash = .{ .bytes = hash },
            .timestamp = header.timestamp,
            .gas_limit = header.gas_limit,
            .extra_data = header.extra_data,
        });
        const slot = &self.view.configs[self.view.config_count];
        slot.* = .{ .hash = .{ .bytes = hash }, .config = config };
        self.view.config_count += 1;
    }

    /// Builds the child of `parent` from `attributes` and makes it canonical.
    fn execute(self: *Fixture, parent: Hash, attributes: anytype) !Hash {
        const engine = &self.node.engine;
        const timestamp = attributes.timestamp;
        const version = engine_types.forkchoice_version(spec, timestamp);
        const state = fixture.forkchoice(.{ .bytes = parent });
        const updated = try engine.forkchoice_updated(version, state, attributes);
        try testing.expectEqual(engine_types.Status.valid, updated.payload_status.status);
        const get_version = engine_types.get_payload_version(spec, timestamp);
        const built = try engine.get_payload(get_version, updated.payload_id.?);
        const head = fixture.forkchoice(built.block_hash);
        const canonical = try engine.forkchoice_updated(version, head, null);
        try testing.expectEqual(engine_types.Status.valid, canonical.payload_status.status);
        return built.block_hash.bytes;
    }

    /// The witness of the attempted payload of a nonce-gap block, which fails at its last
    /// transaction: everything executing it reads before the failure. Built on the node
    /// as a side block of the deposits and the valid prefix (the gap transaction's sender
    /// is the first transfer's, so the failure reads nothing more), then the node's state
    /// returns to its head. Witnessing the attempt also covers the deposit-only retry.
    fn add_attempted_witness(
        self: *Fixture,
        parent: Hash,
        attributes: payload.PayloadAttributes,
        user: List,
    ) !void {
        assert(user.len == 3);
        const deposits = attributes.transactions.?;
        assert(deposits.len >= 1);
        const arena = self.source.arena.allocator();
        const prefix = try std.mem.concat(arena, []const u8, &.{ deposits, user[0..2] });
        var attempted = attributes;
        attempted.transactions = prefix;
        const chain = &self.node.chain;
        const hash = try chain.build_block(parent, &attempted);
        if (self.scenario.attempted_witness) {
            try node_witness.built_witness(chain, &self.generator, hash);
            try self.source.attempted.put(testing.allocator, parent, try self.witness_items());
        }
        try chain.ensure_head_state();
        try testing.expectEqual(parent, chain.head_hash());
    }

    /// The generator's last witness as byte strings, each also a keccak preimage.
    fn witness_items(self: *Fixture) !List {
        const arena = self.source.arena.allocator();
        const witness = &self.generator.witness;
        const lists = [_]*const db_module.witness.ByteList{
            &witness.state, &witness.codes, &witness.keys,
        };
        var total: usize = 0;
        for (lists) |list| total += list.count;
        const items = try arena.alloc([]const u8, total);
        var index: usize = 0;
        for (lists) |list| {
            for (0..list.count) |i| {
                items[index] = try arena.dupe(u8, list.get(@intCast(i)));
                try self.source.add_preimage(items[index]);
                index += 1;
            }
        }
        assert(index == total);
        return items;
    }

    /// Records each block's execution witness for the host's payload-witness hint.
    fn add_witnesses(self: *Fixture) !void {
        for (self.blocks[1..]) |block| {
            try node_witness.execution_witness(&self.node.chain, &self.generator, block.hash);
            const parent = block.info.block_info.parent_hash.bytes;
            try self.source.witnesses.put(testing.allocator, parent, try self.witness_items());
        }
    }

    /// Frames the batches of every built block into signed inbox transactions (calldata
    /// or one blob each) and adds the L1 block carrying them, with successful receipts.
    fn add_batch_block(self: *Fixture) !void {
        var payloads: [8][]const u8 = undefined;
        const count = switch (self.scenario.batch) {
            .singular => try self.singular_payloads(&payloads),
            .span => try self.span_payloads(&payloads),
        };
        try testing.expect(count > 0);
        var txs: [8][]const u8 = undefined;
        var receipts: [8][]const u8 = undefined;
        for (payloads[0..count], 0..) |data, nonce| {
            txs[nonce], receipts[nonce] = switch (self.scenario.data) {
                .calldata => try self.inbox_tx(data, nonce),
                .blob => try self.blob_tx(data, nonce),
            };
        }
        try self.add_l1_block(txs[0..count], receipts[0..count]);
    }

    /// The batcher's channel manager: one singular batch per block.
    fn singular_payloads(self: *Fixture, out: *[8][]const u8) !usize {
        const allocator = testing.allocator;
        var manager: channel_manager.Manager = try .init(allocator, .{
            .channel = .{ .frame_size_max = 100_000, .input_bytes_max = 1 << 16 },
            .batch_bytes_max = 1 << 12,
        }, @splat(0x5a));
        defer manager.deinit(allocator);
        for (self.blocks[1..]) |block| {
            const item: batcher_source.L2Block = .{
                .number = block.info.block_info.number,
                .hash = block.info.block_info.hash,
                .parent_hash = block.info.block_info.parent_hash,
                .timestamp = block.info.block_info.timestamp,
                .l1_origin = block.info.l1_origin,
                .sequence_number = block.info.sequence_number,
                .transactions = block.user,
            };
            try manager.add_block(&item, 1);
        }
        manager.close_open();
        var count: usize = 0;
        while (manager.next_tx_data()) |data| : (count += 1) {
            try testing.expect(count < out.len);
            out[count] = try self.source.arena.allocator().dupe(u8, data);
        }
        return count;
    }

    /// One span batch over every block (`rlp_string(0x01 ++ span)`), framed by a
    /// batcher channel.
    fn span_payloads(self: *Fixture, out: *[8][]const u8) !usize {
        const allocator = testing.allocator;
        const arena = self.source.arena.allocator();
        var singles: [l2_blocks]protocol.batch.SingleBatch = undefined;
        for (&singles, self.blocks[1..]) |*single, block| single.* = .{
            .parent_hash = block.info.block_info.parent_hash,
            .epoch_num = block.info.l1_origin.number,
            .epoch_hash = block.info.l1_origin.hash,
            .timestamp = block.info.block_info.timestamp,
            .transactions = block.user,
        };
        const span = try protocol.span_batch.SpanBatch.from_singular_batches(
            arena,
            &singles,
            self.blocks[1].info.sequence_number,
            self.rollup.genesis.l2_time,
            self.rollup.l2_chain_id,
        );
        const encoded = try span.encode_alloc(arena);
        const typed = try std.mem.concat(arena, u8, &.{ &.{0x01}, encoded });
        const item = try arena.alloc(u8, rlp.bytes_length(typed));
        var encoder = rlp.Encoder.init(item);
        encoder.bytes(typed);
        assert(encoder.written().len == item.len);
        var channel: channel_out.ChannelOut = try .init(allocator, .{
            .frame_size_max = 100_000,
            .input_bytes_max = 1 << 16,
        }, @splat(0x5b));
        defer channel.deinit(allocator);
        try channel.add_batch(item);
        channel.close();
        var count: usize = 0;
        while (channel.next_frame()) |frame| : (count += 1) {
            try testing.expect(count < out.len);
            const frames = [_]batcher_frame.Frame{frame};
            const data = try arena.alloc(u8, batcher_frame.tx_data_length(&frames));
            out[count] = batcher_frame.encode_tx_data(&frames, data);
        }
        return count;
    }

    fn inbox_tx(self: *Fixture, data: []const u8, nonce: usize) !struct { []const u8, []const u8 } {
        const arena = self.source.arena.allocator();
        const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
        const envelope = try txdata.sign_eip1559(.{
            .chain_id = self.rollup.l1_chain_id,
            .nonce = nonce,
            .fees = .{ .max_fee_per_gas = 100_000_000_000, .max_priority_fee_per_gas = 1 },
            .gas_limit = 1_000_000,
            .to = inbox,
            .data = data,
        }, batcher.private_key);
        const raw = try arena.alloc(u8, envelope.encoded_length());
        _ = txdata.encode_raw(envelope, raw);
        return .{ raw, try receipt_of(arena, .eip1559, nonce) };
    }

    /// A blob transaction to the inbox carrying `data` in one blob, which the source
    /// serves under its versioned hash with a real KZG commitment.
    fn blob_tx(self: *Fixture, data: []const u8, nonce: usize) !struct { []const u8, []const u8 } {
        const arena = self.source.arena.allocator();
        const blob = try arena.create(batcher_blobs.Blob);
        try batcher_blobs.encode(data, blob);
        var prover = try batcher_blobs.kzg.Prover.init(testing.allocator);
        defer prover.deinit(testing.allocator);
        const commitment = try prover.commitment(blob);
        const hash = batcher_blobs.kzg.versioned_hash(&commitment);
        try self.source.blobs.put(testing.allocator, hash, .{
            .blob = blob,
            .commitment = commitment,
        });
        const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
        const hash_buffer = try arena.alloc(u8, 33);
        const envelope = try txdata.blob.sign(.{
            .chain_id = self.rollup.l1_chain_id,
            .nonce = nonce,
            .fees = .{ .max_fee_per_gas = 100_000_000_000, .max_priority_fee_per_gas = 1 },
            .blob_fee_wei = 1_000_000,
            .to = inbox,
            .versioned_hashes = &.{hash},
        }, hash_buffer, batcher.private_key);
        const raw = try arena.alloc(u8, envelope.encoded_length());
        _ = txdata.encode_raw(envelope, raw);
        assert(raw[0] == 0x03);
        return .{ raw, try receipt_of(arena, .eip4844, nonce) };
    }

    fn receipt_of(
        arena: std.mem.Allocator,
        tx_type: consensus.TxType,
        index: usize,
    ) ![]const u8 {
        const receipt: consensus.Receipt = .{
            .tx_type = tx_type,
            .status = true,
            .cumulative_gas_used = 100_000 * (index + 1),
        };
        var buffer: [1024]u8 = undefined;
        return arena.dupe(u8, receipt.encode_to(&buffer));
    }

    /// Adds the L1 head: the child of the last L1 block, carrying the batcher's `txs`.
    fn add_l1_block(self: *Fixture, txs: List, receipts: List) !void {
        assert(self.l1_count < l1_blocks_max);
        assert(txs.len == receipts.len);
        var header = l1_genesis_header();
        header.parent_hash = .{ .bytes = self.l1_hashes[self.l1_count - 1] };
        header.number = self.l1_count;
        header.timestamp = 12 * @as(u64, self.l1_count);
        header.transactions_root = .{ .bytes = trie.ordered_trie_root(txs) };
        header.receipts_root = .{ .bytes = trie.ordered_trie_root(receipts) };
        self.l1_hashes[self.l1_count] = try self.source.add_block(.l1, header, txs);
        const copies = try self.source.copy_list(receipts);
        try self.source.receipt_lists.put(testing.allocator, self.l1_hashes[self.l1_count], copies);
        self.l1_count += 1;
    }

    /// The output root of node block `hash`: Isthmus headers carry the message passer
    /// storage root as `withdrawals_root`.
    fn output_root_of(self: *Fixture, hash: Hash) !struct { Hash, [128]u8 } {
        const header = self.node.chain.header(hash).?;
        const output: program.sync.OutputRoot = .{
            .state_root = header.state_root.bytes,
            .message_passer_storage_root = header.withdrawals_root.?.bytes,
            .block_hash = hash,
        };
        const encoded = output.encode();
        return .{ keccak.keccak256(&encoded), encoded };
    }

    fn put_boot(self: *Fixture, claim_matches: bool) !void {
        try self.put_boot_claim(l2_blocks, claim_matches);
    }

    /// Boot values claiming the node's output root at `number` (the trace extension
    /// when 0, the agreed block).
    fn put_boot_at(self: *Fixture, number: u64) !void {
        try self.put_boot_claim(number, true);
    }

    fn put_boot_claim(self: *Fixture, number: u64, claim_matches: bool) !void {
        assert(number <= l2_blocks);
        self.agreed, const encoded = try self.output_root_of(self.blocks[0].hash);
        try testing.expectEqual(self.agreed, try self.store.put_keccak(&encoded));
        self.expected, _ = try self.output_root_of(self.blocks[@intCast(number)].hash);
        var out: std.Io.Writer = .fixed(&self.rollup_json);
        var writer = json.Writer.init(&out);
        try protocol.rollup_json.write(&writer, &self.rollup);
        try self.store.put_boot(&.{
            .l1_head = self.l1_hashes[self.l1_count - 1],
            .agreed_l2_output_root = self.agreed,
            .claimed_l2_output_root = if (claim_matches) self.expected else @splat(0xcc),
            .claimed_l2_block_number = number,
            .chain_id = chains.devnet.chain_id,
            .rollup_config_json = out.buffered(),
            .intermediate_block_interval = self.scenario.interval,
        });
    }

    fn run(self: *Fixture) !struct { client.Outcome, bool } {
        var harness: preimage.InProcess = undefined;
        try harness.init(testing.allocator, self.store.fetcher(), self.handler.router(), .{
            .channel_bytes = 1 << 18,
            .hint_bytes = 1 << 14,
        });
        defer harness.deinit(testing.allocator);
        kzg.blob.fill_roots_brp(&kzg_storage.roots_brp);
        const settings: kzg.blob.Settings = .{
            .g1_lagrange = &kzg_storage.g1_lagrange,
            .roots_brp = &kzg_storage.roots_brp,
        };
        const io: client.Client.Io = .{
            .oracle = harness.oracle_reader(),
            .hints = harness.hint_writer(),
        };
        const outcome = client.run(testing.allocator, io, .{
            .builder = builder_config,
            .resolver = .{ .bytes_max = 1 << 20, .entries_max = 4096 },
            .l1 = .{ .items_max = 16, .logs_max = 16, .topics_max = 64, .blob_hashes_max = 16 },
            .l2 = .{ .items_max = 16 },
            .blobs = .{ .blobs_max = 2, .verify = false },
            .kzg_settings = &settings,
            .kzg_workspace = &kzg_workspace,
            .intermediate = &self.sampler,
        }) catch |err| {
            const last = self.handler.last_error;
            std.debug.print("client failed: {t}, host error: {?}\n", .{ err, last });
            return err;
        };
        var scratch: [program.boot.rollup_config_bytes_max]u8 = undefined;
        const boot = try program.BootInfo.load(harness.oracle_reader(), &scratch);
        return .{ outcome, client.claim_holds(&boot, &outcome) };
    }
};

/// Proves the claim of `scenario` and checks the client reached the node's output root
/// for the last block, executing every block from a host-served witness.
fn prove(scenario: Scenario) !*Fixture {
    const self = try Fixture.create(scenario);
    errdefer self.destroy();
    try self.put_boot(true);
    const outcome, const holds = try self.run();
    try testing.expectEqual(@as(u64, l2_blocks), outcome.block_number);
    try testing.expect(!outcome.exhausted);
    try testing.expectEqual(self.expected, outcome.output_root);
    try testing.expect(holds);
    try testing.expect(self.source.witness_requests >= l2_blocks);
    return self;
}

test "e2e: client derives and executes node-built L2 blocks from L1 batches" {
    const self = try prove(.{});
    defer self.destroy();
    try testing.expectEqual(@as(u32, 2), self.l1_count);
    try testing.expectEqual(@as(u32, 0), self.source.blob_requests);
}

test "e2e: a wrong claimed output root fails the claim" {
    const self = try Fixture.create(.{});
    defer self.destroy();
    try self.put_boot(false);
    const outcome, const holds = try self.run();
    try testing.expectEqual(@as(u64, l2_blocks), outcome.block_number);
    try testing.expectEqual(self.expected, outcome.output_root);
    try testing.expect(!holds);
}

test "e2e: blocks across an L1 epoch change, batched in a later L1 block" {
    const self = try prove(.{ .epoch_zero_blocks = 1 });
    defer self.destroy();
    try testing.expectEqual(@as(u32, 3), self.l1_count);
    // Block 1 is in epoch 0; blocks 2 and 3 in epoch 1 with sequence numbers 0 and 1.
    const expected_epochs = [_]u64{ 0, 0, 1, 1 };
    const expected_sequence = [_]u64{ 0, 1, 0, 1 };
    for (self.blocks, expected_epochs, expected_sequence) |block, epoch, sequence| {
        try testing.expectEqual(epoch, block.info.l1_origin.number);
        try testing.expectEqual(sequence, block.info.sequence_number);
    }
}

test "e2e: one span batch carries every block" {
    const self = try prove(.{ .batch = .span });
    defer self.destroy();
    try testing.expectEqual(@as(u32, 2), self.l1_count);
}

test "e2e: a span batch across an L1 epoch change" {
    const self = try prove(.{ .batch = .span, .epoch_zero_blocks = 2 });
    defer self.destroy();
    try testing.expectEqual(@as(u32, 3), self.l1_count);
    try testing.expectEqual(@as(u64, 1), self.blocks[l2_blocks].info.l1_origin.number);
}

test "e2e: batches framed in an EIP-4844 blob through the host" {
    const self = try prove(.{ .data = .blob });
    defer self.destroy();
    try testing.expect(self.source.blob_requests >= 1);
}

test "e2e: Holocene replaces a block that fails to execute with its deposits only" {
    const self = try prove(.{ .invalid = .fee_cap_first });
    defer self.destroy();
    const last = self.blocks[l2_blocks];
    // The batch carried three user transactions; the proven block has only the deposit.
    try testing.expectEqual(@as(usize, 3), last.user.len);
    try testing.expectEqual(@as(usize, 1), last.all.len);
    const node_header = self.node.chain.header(last.hash).?;
    try testing.expectEqual(@as(u64, l2_blocks), node_header.number);
}

test "e2e: a deposit-only retry after valid transfers uses the attempted payload's witness" {
    const self = try prove(.{ .invalid = .nonce_gap_last });
    defer self.destroy();
    const last = self.blocks[l2_blocks];
    // Two transfers, then the nonce gap; the proven block has only the deposit.
    try testing.expectEqual(@as(usize, 3), last.user.len);
    try testing.expectEqual(@as(usize, 1), last.all.len);
    try testing.expectEqual(@as(u32, 1), self.source.attempted_requests);
}

test "e2e: without the attempted payload's witness the retry block cannot be proven" {
    const self = try Fixture.create(.{ .invalid = .nonce_gap_last, .attempted_witness = false });
    defer self.destroy();
    try self.put_boot(true);
    // The transfers read sender state the deposit-only block's witness lacks; a missing
    // preimage fails the proof instead of triggering the deposit-only retry.
    try testing.expectError(error.StateUnavailable, self.run());
    try testing.expectEqual(@as(u32, 0), self.source.attempted_requests);
}

/// The output roots of node blocks `1..=l2_blocks`.
fn node_roots(self: *Fixture) ![l2_blocks]Hash {
    var roots: [l2_blocks]Hash = undefined;
    for (&roots, self.blocks[1..]) |*root, block| root.*, _ = try self.output_root_of(block.hash);
    return roots;
}

test "e2e: intermediate output roots at every block and at an interval of the range" {
    for ([_]u64{ 1, 3 }) |interval| {
        const self = try prove(.{ .interval = interval });
        defer self.destroy();
        const expected = try node_roots(self);
        const roots = try self.sampler.finish();
        try testing.expectEqual(l2_blocks / interval, roots.len);
        for (roots, 1..) |root, index| {
            try testing.expectEqual(expected[index * interval - 1], root);
        }
        // The last sampled root is the claim's.
        try testing.expectEqual(self.expected, roots[roots.len - 1]);
    }
}

test "e2e: an interval that does not divide the range has no intermediate roots" {
    const self = try prove(.{ .interval = 2 });
    defer self.destroy();
    // The claim still holds; only the sampled roots are unavailable (base/base's provers
    // refuse such a range).
    try testing.expectError(error.PartialInterval, self.sampler.finish());
    try testing.expectEqual(@as(u64, l2_blocks), self.sampler.blocks);
    try testing.expectEqual(@as(u32, 1), self.sampler.count);
}

test "e2e: a claim at the agreed block derives nothing and samples no roots" {
    const self = try Fixture.create(.{ .interval = 3 });
    defer self.destroy();
    try self.put_boot_at(0);
    const outcome, const holds = try self.run();
    try testing.expectEqual(@as(u64, 0), outcome.block_number);
    try testing.expect(holds);
    try testing.expectError(error.EmptyRange, self.sampler.finish());
}

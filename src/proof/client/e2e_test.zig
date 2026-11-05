//! Fault-proof client end to end over real blocks: the execution node builds L2 blocks
//! from derived attributes (L1 info deposit plus signed user transfers), the batcher's
//! channel manager frames their batches into signed type-2 L1 transactions to the inbox,
//! and the client derives and statelessly executes them through the real host hint
//! handler, which serves every preimage from an in-memory chain source.

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
const channel_manager = @import("../../batcher/channel/manager.zig");
const batcher_source = @import("../../batcher/source/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
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

/// L2 blocks derived and proven (all in epoch 0).
const l2_blocks = 3;
/// L1 blocks: genesis (the epoch) and the block carrying the batch (the L1 head).
const l1_blocks = 2;
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
    witness_requests: u32 = 0,

    fn deinit(source: *MapSource) void {
        const allocator = testing.allocator;
        source.headers.deinit(allocator);
        source.l1_bodies.deinit(allocator);
        source.l2_bodies.deinit(allocator);
        source.receipt_lists.deinit(allocator);
        source.preimages.deinit(allocator);
        source.witnesses.deinit(allocator);
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
        _ = context;
        _ = hash;
        _ = timestamp;
        return error.NotFound; // The batch is calldata only.
    }

    fn preimage_of(context: *anyopaque, hash: Hash) SourceError![]const u8 {
        return get(context).preimages.get(hash) orelse error.NotFound;
    }

    fn payload_witness(context: *anyopaque, parent: Hash, attributes: []const u8) SourceError!List {
        const source = get(context);
        if (attributes.len == 0 or attributes[0] != '{') return error.SourceFailed;
        source.witness_requests += 1;
        return source.witnesses.get(parent) orelse error.NotFound;
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
    l1: [l1_blocks]L1Header = undefined,
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

const Fixture = struct {
    node: *fixture.Node,
    generator: db_module.witness_block.Generator,
    source: MapSource,
    store: host.Store,
    handler: host.Handler,
    rollup: protocol.RollupConfig,
    bpo: [2]protocol.l1_info.L1BlobSchedule.Entry,
    blob_schedule: protocol.l1_info.L1BlobSchedule,
    view: ChainView,
    l1_hashes: [l1_blocks]Hash,
    blocks: [l2_blocks + 1]Built,
    agreed: Hash,
    expected: Hash,
    rollup_json: [8192]u8,

    fn create() !*Fixture {
        const allocator = testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.node = try fixture.Node.create_for(spec);
        errdefer self.node.destroy();
        self.generator = try .init(allocator, self.node.db.state, generator_config);
        errdefer self.generator.deinit(allocator);
        self.source = .{ .arena = .init(allocator) };
        errdefer self.source.deinit();
        self.store = .init(allocator, .{});
        errdefer self.store.deinit();
        self.handler = .{ .store = &self.store, .source = self.source.as_source() };
        try self.add_l1_genesis();
        self.init_rollup();
        self.view = .{ .rollup = &self.rollup };
        self.view.l1[0] = l1_header_of(&l1_genesis_header());
        self.view.l1_count = 1;
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
        try self.source.receipt_lists.put(testing.allocator, self.l1_hashes[0], &.{});
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
        const tx: consensus.Eip1559 = .{
            .chain_id = spec.chain_id,
            .nonce = nonce,
            .max_priority_fee_per_gas = 2,
            .max_fee_per_gas = 10_000_000_000,
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

    /// Derives the attributes of block `number`, adds two transfers and builds it.
    fn build_one(self: *Fixture, number: usize) !void {
        const allocator = testing.allocator;
        const parent = self.blocks[number - 1];
        var builder: derive.attributes.AttributesBuilder =
            .init(allocator, &self.rollup, &self.blob_schedule);
        var attributes = try builder.prepare_payload_attributes(
            &self.view,
            parent.info,
            self.rollup.genesis.l1,
        );
        defer attributes.deinit(allocator);
        const arena = self.source.arena.allocator();
        const user = try arena.alloc([]const u8, 2);
        user[0] = try self.transfer(1, number - 1);
        user[1] = try self.transfer(2, number - 1);
        const all = try arena.alloc([]const u8, attributes.transactions.len + user.len);
        for (all[0..attributes.transactions.len], attributes.transactions) |*copy, item| {
            copy.* = try arena.dupe(u8, item);
        }
        @memcpy(all[attributes.transactions.len..], user);
        var engine_attributes = attributes.engine();
        engine_attributes.transactions = all;
        const hash = try self.execute(parent.hash, &engine_attributes);
        const header = self.node.chain.header(hash).?;
        try testing.expectEqual(@as(u64, number), header.number);
        _ = try self.source.add_block(.l2, header, all);
        const info = try program.l2_chain_provider.decode_l1_info(all);
        try testing.expectEqual(@as(u64, number), info.sequence_number);
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

    /// Records each block's execution witness for the host's payload-witness hint.
    fn add_witnesses(self: *Fixture) !void {
        const arena = self.source.arena.allocator();
        for (self.blocks[1..]) |block| {
            try node_witness.execution_witness(&self.node.chain, &self.generator, block.hash);
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
            const parent = block.info.block_info.parent_hash.bytes;
            try self.source.witnesses.put(testing.allocator, parent, items);
        }
    }

    /// Frames the batches of every built block into signed inbox transactions and adds
    /// the L1 block carrying them, with successful receipts.
    fn add_batch_block(self: *Fixture) !void {
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
        var txs: [8][]const u8 = undefined;
        var receipts: [8][]const u8 = undefined;
        var count: usize = 0;
        while (manager.next_tx_data()) |data| : (count += 1) {
            try testing.expect(count < txs.len);
            txs[count], receipts[count] = try self.inbox_tx(data, count);
        }
        try testing.expect(count > 0);
        try self.add_l1_block(txs[0..count], receipts[0..count]);
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
        const receipt: consensus.Receipt = .{
            .tx_type = .eip1559,
            .status = true,
            .cumulative_gas_used = 100_000 * (nonce + 1),
        };
        var buffer: [1024]u8 = undefined;
        return .{ raw, try arena.dupe(u8, receipt.encode_to(&buffer)) };
    }

    fn add_l1_block(self: *Fixture, txs: List, receipts: List) !void {
        var header = l1_genesis_header();
        header.parent_hash = .{ .bytes = self.l1_hashes[0] };
        header.number = 1;
        header.timestamp = 12;
        header.transactions_root = .{ .bytes = trie.ordered_trie_root(txs) };
        header.receipts_root = .{ .bytes = trie.ordered_trie_root(receipts) };
        self.l1_hashes[1] = try self.source.add_block(.l1, header, txs);
        const copies = try self.source.copy_list(receipts);
        try self.source.receipt_lists.put(testing.allocator, self.l1_hashes[1], copies);
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
        self.agreed, const encoded = try self.output_root_of(self.blocks[0].hash);
        try testing.expectEqual(self.agreed, try self.store.put_keccak(&encoded));
        self.expected, _ = try self.output_root_of(self.blocks[l2_blocks].hash);
        var out: std.Io.Writer = .fixed(&self.rollup_json);
        var writer = json.Writer.init(&out);
        try protocol.rollup_json.write(&writer, &self.rollup);
        try self.store.put_boot(&.{
            .l1_head = self.l1_hashes[l1_blocks - 1],
            .agreed_l2_output_root = self.agreed,
            .claimed_l2_output_root = if (claim_matches) self.expected else @splat(0xcc),
            .claimed_l2_block_number = l2_blocks,
            .chain_id = chains.devnet.chain_id,
            .rollup_config_json = out.buffered(),
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

test "e2e: client derives and executes node-built L2 blocks from L1 batches" {
    const self = try Fixture.create();
    defer self.destroy();
    try self.put_boot(true);
    const outcome, const holds = try self.run();
    try testing.expectEqual(@as(u64, l2_blocks), outcome.block_number);
    try testing.expect(!outcome.exhausted);
    try testing.expectEqual(self.expected, outcome.output_root);
    try testing.expect(holds);
    // Every block was executed statelessly from a host-served witness.
    try testing.expect(self.source.witness_requests >= l2_blocks);
}

test "e2e: a wrong claimed output root fails the claim" {
    const self = try Fixture.create();
    defer self.destroy();
    try self.put_boot(false);
    const outcome, const holds = try self.run();
    try testing.expectEqual(@as(u64, l2_blocks), outcome.block_number);
    try testing.expectEqual(self.expected, outcome.output_root);
    try testing.expect(!holds);
}

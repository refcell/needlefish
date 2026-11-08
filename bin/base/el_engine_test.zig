//! Tests of el-run's Engine API (`el_engine.zig`) over a fake chain: newPayload and
//! forkchoiceUpdated semantics, block reads by number, hash and tag from the ring, the
//! safe/finalized anchor, and the JWT-authenticated server driven by a real consensus
//! `EngineClient` over the simulated network.

const std = @import("std");
const base = @import("base");
const el_engine = @import("el_engine.zig");
const el_ring = @import("el_ring.zig");
const import_run_cli = @import("import_run.zig");

const testing = std.testing;
const assert = std.debug.assert;
const io = base.utilities.io;
const jwt = base.utilities.jwt;
const http_client = base.utilities.http.client;
const consensus = base.common.consensus;
const primitives = base.common.primitives;
const engine_types = base.execution.engine.types;
const engine_block = base.execution.engine.block;
const sources = base.consensus.sources;
const L1BlockInfo = base.consensus.protocol.L1BlockInfo;

const B256 = primitives.B256;
const Hash = [32]u8;
const Engine = el_engine.Engine;

/// Base Sepolia (Isthmus active at the fixture timestamps: `newPayloadV4`).
const spec = import_run_cli.chains[0].spec;
const secret: jwt.Secret = .{ .bytes = @splat(0x42) };

/// Consecutive L2 blocks `first ..` with an L1 info deposit and a user deposit each.
const Fixture = struct {
    const count = 40;
    const first = 100;
    const timestamp_first = 1_750_000_000;

    headers: [count]consensus.Header = undefined,
    header_rlp: [count][1024]u8 = undefined,
    header_sizes: [count]usize = undefined,
    deposits: [count][2][400]u8 = undefined,
    transactions: [count][2][]const u8 = undefined,
    hashes: [count]Hash = undefined,

    fn init(fixture: *Fixture) void {
        var parent: B256 = .init(@splat(0x99));
        for (0..count) |index| {
            fixture.init_transactions(index);
            const items = &fixture.transactions[index];
            fixture.headers[index] = .{
                .parent_hash = parent,
                .beneficiary = .init(@splat(0xfe)),
                .state_root = .init(@splat(0x51)),
                .transactions_root = .{ .bytes = base.execution.trie.ordered_trie_root(items) },
                .number = first + index,
                .gas_limit = 60_000_000,
                .gas_used = 21_000,
                .timestamp = timestamp_first + 2 * index,
                .extra_data = &.{ 1, 0, 0, 0, 250, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0 },
                .mix_hash = .init(@splat(0x3d)),
                .base_fee_per_gas = 1_000_000,
                .withdrawals_root = .init(@splat(0x77)),
                .blob_gas_used = 0,
                .excess_blob_gas = 0,
                .parent_beacon_block_root = .init(@splat(0xbe)),
                .requests_hash = engine_block.empty_requests_hash,
            };
            const encoded = base.common.rlp.encode_to(
                &fixture.header_rlp[index],
                fixture.headers[index],
            );
            fixture.header_sizes[index] = encoded.len;
            fixture.hashes[index] = fixture.headers[index].hash().bytes;
            parent = .{ .bytes = fixture.hashes[index] };
        }
    }

    fn init_transactions(fixture: *Fixture, index: usize) void {
        const info: L1BlockInfo = .{
            .format = .ecotone,
            .number = 500 + index / 4,
            .time = 1_749_999_000 + 12 * (index / 4),
            .block_hash = .init(@splat(@intCast(0x10 + index / 4))),
            .sequence_number = index % 4,
        };
        var calldata: [base.consensus.protocol.l1_info.calldata_length_max]u8 = undefined;
        const inputs = [2][]const u8{ info.encode_calldata(&calldata), "hello" };
        for (inputs, 0..) |input, which| {
            var source: B256 = .init(@splat(@intCast(which + 1)));
            source.bytes[0] = @intCast(index);
            const envelope: consensus.Envelope = .{ .deposit = .{
                .source_hash = source,
                .from = .init(@splat(0xde)),
                .to = .{ .call = .init(@splat(0x15)) },
                .mint = which,
                .value = 0,
                .gas_limit = 1_000_000,
                .is_system_transaction = false,
                .input = input,
            } };
            const buffer = &fixture.deposits[index][which];
            fixture.transactions[index][which] = envelope.encode_to(buffer);
        }
    }

    fn block(fixture: *const Fixture, index: usize) el_ring.Block {
        return .{
            .number = first + index,
            .hash = fixture.hashes[index],
            .header_rlp = fixture.header_rlp[index][0..fixture.header_sizes[index]],
            .transactions = &fixture.transactions[index],
        };
    }

    /// The V4 payload of block `index` and its side-car params.
    fn payload(fixture: *const Fixture, index: usize) engine_types.ExecutionPayload {
        const header = &fixture.headers[index];
        return .{
            .parent_hash = header.parent_hash,
            .fee_recipient = header.beneficiary,
            .state_root = header.state_root,
            .receipts_root = header.receipts_root,
            .logs_bloom = header.logs_bloom,
            .prev_randao = header.mix_hash,
            .block_number = header.number,
            .gas_limit = header.gas_limit,
            .gas_used = header.gas_used,
            .timestamp = header.timestamp,
            .extra_data = header.extra_data,
            .base_fee_per_gas = header.base_fee_per_gas.?,
            .block_hash = .{ .bytes = fixture.hashes[index] },
            .transactions = &fixture.transactions[index],
            .withdrawals = &.{},
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
            .withdrawals_root = header.withdrawals_root,
        };
    }

    const params: engine_types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = .init(@splat(0xbe)),
        .execution_requests = &.{},
    };
};

/// The database view: the head and a canonical index over `[canonical_from, head]`.
const FakeChain = struct {
    fixture: *const Fixture,
    head_index: usize = 0,
    canonical_from: usize = 0,

    fn chain(fake: *FakeChain) el_engine.Chain {
        return .{
            .context = fake,
            .head_fn = head,
            .canonical_hash_fn = canonical_hash,
            .number_of_fn = number_of,
        };
    }

    fn from(context: *anyopaque) *FakeChain {
        return @ptrCast(@alignCast(context));
    }

    fn head(context: *anyopaque) el_engine.Label {
        const fake = from(context);
        const index = fake.head_index;
        return .{ .number = Fixture.first + index, .hash = fake.fixture.hashes[index] };
    }

    fn canonical_hash(context: *anyopaque, number: u64) ?Hash {
        const fake = from(context);
        if (number < Fixture.first + fake.canonical_from) return null;
        if (number > Fixture.first + fake.head_index) return null;
        return fake.fixture.hashes[@intCast(number - Fixture.first)];
    }

    fn number_of(context: *anyopaque, hash: Hash) ?u64 {
        const fake = from(context);
        for (fake.canonical_from..fake.head_index + 1) |index| {
            if (std.mem.eql(u8, &fake.fixture.hashes[index], &hash)) return Fixture.first + index;
        }
        return null;
    }
};

/// An engine whose ring holds blocks `executed - ring_blocks .. executed - 1` of the fixture,
/// with the database's canonical index over the last `canonical_blocks`.
const Setup = struct {
    fixture: Fixture = .{},
    fake: FakeChain = undefined,
    engine: Engine = undefined,

    fn init(setup: *Setup, executed: usize, ring_blocks: u32, canonical_blocks: usize) !void {
        assert(executed > 0 and executed <= Fixture.count);
        setup.fixture.init();
        setup.fake = .{ .fixture = &setup.fixture };
        try setup.engine.init(testing.allocator, spec, secret, setup.fake.chain(), .{
            .blocks_max = ring_blocks,
            .bytes_max = 1 << 20,
            .transactions_max = 1 << 14,
        });
        for (0..executed) |index| {
            setup.fake.head_index = index;
            setup.engine.on_block(&setup.fixture.block(index));
        }
        setup.fake.canonical_from = executed -| canonical_blocks;
    }

    fn deinit(setup: *Setup) void {
        setup.engine.deinit(testing.allocator);
    }

    fn state(setup: *const Setup, head: ?usize, safe: ?usize, finalized: ?usize) ForkchoiceState {
        return .{
            .head_block_hash = setup.hash(head),
            .safe_block_hash = setup.hash(safe),
            .finalized_block_hash = setup.hash(finalized),
        };
    }

    fn hash(setup: *const Setup, index: ?usize) B256 {
        const found = index orelse return .zero;
        return .{ .bytes = setup.fixture.hashes[found] };
    }

    /// Runs one JSON-RPC request through the router; returns the response text.
    fn call(setup: *Setup, buffer: []u8, body: []const u8) ![]const u8 {
        var out: std.Io.Writer = .fixed(buffer);
        const outcome = el_engine.Router.handle(&setup.engine, body, &out);
        try testing.expectEqual(.response, outcome);
        return out.buffered();
    }
};

const ForkchoiceState = engine_types.ForkchoiceState;

fn contains(text: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, text, needle) != null;
}

test "el engine: newPayload judges payloads against the executed blocks" {
    var setup: Setup = .{};
    try setup.init(30, 16, 10); // Ring: indexes 14..29; canonical index: 20..29.
    defer setup.deinit();
    const engine = &setup.engine;
    const params = Fixture.params;
    // Executed, in the ring: VALID.
    const valid = engine.payload_status(&setup.fixture.payload(15), &params);
    try testing.expectEqual(.valid, valid.status);
    try testing.expect(valid.latest_valid_hash.?.eql(setup.hash(15)));
    // Above the head: SYNCING.
    setup.fake.head_index = 29;
    const ahead = engine.payload_status(&setup.fixture.payload(31), &params);
    try testing.expectEqual(.syncing, ahead.status);
    // Older than the ring and the canonical index: SYNCING, cannot judge.
    const old = engine.payload_status(&setup.fixture.payload(5), &params);
    try testing.expectEqual(.syncing, old.status);
    try testing.expectEqual(@as(u64, 1), engine.stats.payloads_unjudged);
    // A different, well-formed block at an executed height: INVALID and a divergence.
    var other = setup.fixture.payload(20);
    other.gas_used += 1;
    var header = setup.fixture.headers[20];
    header.gas_used += 1;
    other.block_hash = header.hash();
    const diverged = engine.payload_status(&other, &params);
    try testing.expectEqual(.invalid, diverged.status);
    try testing.expect(diverged.latest_valid_hash.?.eql(setup.hash(19)));
    try testing.expectEqual(@as(u64, 1), engine.stats.divergences);
    // A payload that does not hash to its block hash: INVALID, malformed.
    var forged = setup.fixture.payload(21);
    forged.gas_used += 1;
    const malformed = engine.payload_status(&forged, &params);
    try testing.expectEqual(.invalid, malformed.status);
    try testing.expectEqual(@as(u64, 1), engine.stats.payloads_malformed);
    try testing.expectEqual(@as(u64, 1), engine.stats.divergences);
}

test "el engine: newPayload over JSON-RPC, version checks" {
    var setup: Setup = .{};
    try setup.init(30, 64, 64);
    defer setup.deinit();
    var request_buffer: [16 * 1024]u8 = undefined;
    var request: std.Io.Writer = .fixed(&request_buffer);
    var writer = base.utilities.json.Writer.init(&request);
    try request.writeAll("{\"jsonrpc\":\"2.0\",\"id\":1,");
    try request.writeAll("\"method\":\"engine_newPayloadV4\",\"params\":");
    const payload = setup.fixture.payload(12);
    try writer.begin_array();
    try sources.engine_json.write_new_payload_params(&writer, .v4, &payload, &Fixture.params);
    try writer.end_array();
    try request.writeAll("}");
    var buffer: [4096]u8 = undefined;
    const text = try setup.call(&buffer, request.buffered());
    try testing.expect(contains(text, "\"status\":\"VALID\""));
    // The same payload as V3 is the wrong version for an Isthmus block.
    const v3 = try std.mem.replaceOwned(u8, testing.allocator, request.buffered(), "V4", "V3");
    defer testing.allocator.free(v3);
    const refused = try setup.call(&buffer, v3);
    try testing.expect(contains(refused, "\"error\""));
}

test "el engine: forkchoiceUpdated VALID, SYNCING, and invalid states" {
    var setup: Setup = .{};
    try setup.init(30, 16, 10); // Ring: 14..29; canonical index: 20..29.
    defer setup.deinit();
    const engine = &setup.engine;
    const valid = try engine.forkchoice(&setup.state(29, 25, 14));
    try testing.expectEqual(.valid, valid.status);
    try testing.expectEqual(@as(u64, Fixture.first + 25), engine.safe.?.number);
    try testing.expectEqual(@as(u64, Fixture.first + 14), engine.finalized.?.number);
    // Unset safe and finalized are fine.
    const unset = try engine.forkchoice(&setup.state(28, null, null));
    try testing.expectEqual(.valid, unset.status);
    try testing.expect(engine.safe == null and engine.finalized == null);
    // An unknown head or safe block: SYNCING, the labels stay.
    _ = try engine.forkchoice(&setup.state(29, 25, 14));
    var unknown = setup.state(29, 25, 14);
    unknown.head_block_hash = .init(@splat(0x01));
    try testing.expectEqual(.syncing, (try engine.forkchoice(&unknown)).status);
    try testing.expectEqual(.syncing, (try engine.forkchoice(&setup.state(29, 5, null))).status);
    try testing.expectEqual(.syncing, (try engine.forkchoice(&setup.state(35, 25, 14))).status);
    try testing.expectEqual(@as(u64, Fixture.first + 29), engine.head.?.number);
    // Out of order: safe above the head, finalized above safe.
    const above = setup.state(20, 25, null);
    try testing.expectError(error.InvalidForkchoiceState, engine.forkchoice(&above));
    const inverted = setup.state(29, 15, 25);
    try testing.expectError(error.InvalidForkchoiceState, engine.forkchoice(&inverted));
    try testing.expectEqual(@as(u64, Fixture.first + 25), engine.safe.?.number);
    // Attributes on a VALID update: -38003, the state is still applied.
    var buffer: [4096]u8 = undefined;
    const head = std.fmt.bytesToHex(setup.fixture.hashes[27], .lower);
    var request_buffer: [512]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":7," ++
        "\"method\":\"engine_forkchoiceUpdatedV3\",\"params\":[{{\"headBlockHash\":\"0x{s}\"," ++
        "\"safeBlockHash\":\"0x{s}\",\"finalizedBlockHash\":\"0x{s}\"}}," ++
        "{{\"timestamp\":\"0x1\"}}]}}", .{
        head, head, head,
    });
    const text = try setup.call(&buffer, request);
    try testing.expect(contains(text, "-38003"));
    try testing.expectEqual(@as(u64, Fixture.first + 27), engine.safe.?.number);
}

fn get_block(setup: *Setup, buffer: []u8, tag: []const u8, full: bool) ![]const u8 {
    var request_buffer: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":3," ++
        "\"method\":\"eth_getBlockByNumber\",\"params\":[\"{s}\",{s}]}}", .{
        tag, if (full) "true" else "false",
    });
    return setup.call(buffer, request);
}

/// The `result` of a response, decoded as a full L2 block.
fn decode_full(arena: std.mem.Allocator, text: []const u8) !sources.l2_block_full.L2Block {
    const result = (try base.utilities.json.find_path(text, &.{"result"})).?;
    return sources.l2_block_full.decode(arena, result, &.{}, .{});
}

test "el engine: block reads by number, hash and tag" {
    var setup: Setup = .{};
    try setup.init(30, 16, 10); // Ring: 14..29; canonical index: 20..29.
    defer setup.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const buffer = try arena.allocator().alloc(u8, 64 * 1024);
    // A full block decodes back to the executed bytes (hash and transactions root checked).
    const text = try get_block(&setup, buffer, "0x73", true); // Block 115 (index 15).
    const block = try decode_full(arena.allocator(), text);
    try testing.expect(block.info.block_info.hash.eql(setup.hash(15)));
    try testing.expectEqual(@as(u64, 503), block.info.l1_origin.number);
    try testing.expectEqual(@as(u64, 3), block.info.sequence_number);
    try testing.expectEqualSlices(u8, setup.fixture.transactions[15][1], block.transactions[1]);
    // Latest is the head; hashes only without `full`.
    const latest = try get_block(&setup, buffer, "latest", false);
    try testing.expect(contains(latest, &std.fmt.bytesToHex(setup.fixture.hashes[29], .lower)));
    try testing.expect(contains(latest, "\"withdrawals\":[]"));
    // Above the head: null. Executed but evicted: an error, not a block.
    try testing.expect(contains(try get_block(&setup, buffer, "0x82", true), "\"result\":null"));
    const evicted = try get_block(&setup, buffer, "0x6e", true); // Block 110 (index 10).
    try testing.expect(contains(evicted, "\"code\":-32000"));
    try testing.expect(contains(evicted, "not in el-run's engine ring (blocks 114..129)"));
    try testing.expectEqual(@as(u64, 1), setup.engine.stats.ring_misses);
    // By hash: in the ring, known only to the database (error), unknown (null).
    setup.fake.canonical_from = 10;
    var request_buffer: [256]u8 = undefined;
    for ([_]usize{ 16, 13 }, [_][]const u8{ "\"result\":{", "-32000" }) |index, expected| {
        const request = try std.fmt.bufPrint(&request_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":4," ++
            "\"method\":\"eth_getBlockByHash\",\"params\":[\"0x{s}\",true]}}", .{
            std.fmt.bytesToHex(setup.fixture.hashes[index], .lower),
        });
        try testing.expect(contains(try setup.call(buffer, request), expected));
    }
    const unknown = try std.fmt.bufPrint(&request_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":4," ++
        "\"method\":\"eth_getBlockByHash\",\"params\":[\"0x{s}\",true]}}", .{
        std.fmt.bytesToHex(setup.fixture.hashes[3], .lower),
    });
    try testing.expect(contains(try setup.call(buffer, unknown), "\"result\":null"));
}

test "el engine: safe and finalized answer the anchor until a forkchoice update" {
    var setup: Setup = .{};
    try setup.init(30, 16, 10); // Ring: 14..29.
    defer setup.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const buffer = try arena.allocator().alloc(u8, 64 * 1024);
    // Anchor: half the ring below the newest block, pinned while the ring holds it.
    const safe = try decode_full(arena.allocator(), try get_block(&setup, buffer, "safe", true));
    try testing.expect(safe.info.block_info.hash.eql(setup.hash(21)));
    setup.fake.head_index = 30;
    setup.engine.on_block(&setup.fixture.block(30));
    const finalized_text = try get_block(&setup, buffer, "finalized", true);
    const finalized = try decode_full(arena.allocator(), finalized_text);
    try testing.expect(finalized.info.block_info.hash.eql(setup.hash(21)));
    // The forkchoice labels replace it.
    _ = try setup.engine.forkchoice(&setup.state(30, 26, null));
    const labeled = try decode_full(arena.allocator(), try get_block(&setup, buffer, "safe", true));
    try testing.expect(labeled.info.block_info.hash.eql(setup.hash(26)));
    const still = try get_block(&setup, buffer, "finalized", true);
    try testing.expect((try decode_full(arena.allocator(), still)).info.block_info.hash.eql(
        setup.hash(21),
    ));
}

test "el engine: labels whose blocks left the ring fall back to the anchor" {
    var setup: Setup = .{};
    try setup.init(30, 16, 10); // Ring: 14..29.
    defer setup.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const buffer = try arena.allocator().alloc(u8, 64 * 1024);
    _ = try setup.engine.forkchoice(&setup.state(29, 16, 15));
    const labeled = try decode_full(arena.allocator(), try get_block(&setup, buffer, "safe", true));
    try testing.expect(labeled.info.block_info.hash.eql(setup.hash(16)));
    for (30..33) |index| { // Ring: 17..32; finalized (15) left, safe (16) left.
        setup.fake.head_index = index;
        setup.engine.on_block(&setup.fixture.block(index));
    }
    for ([_][]const u8{ "safe", "finalized" }) |tag| {
        const text = try get_block(&setup, buffer, tag, true);
        const block = try decode_full(arena.allocator(), text);
        try testing.expect(block.info.block_info.hash.eql(setup.hash(24))); // 32 - 16 / 2.
    }
    try testing.expect(setup.engine.safe == null and setup.engine.finalized == null);
    try testing.expectEqual(@as(u64, 0), setup.engine.stats.ring_misses);
    // A label still in the ring is kept.
    _ = try setup.engine.forkchoice(&setup.state(32, 20, 18));
    const kept = try decode_full(arena.allocator(), try get_block(&setup, buffer, "safe", true));
    try testing.expect(kept.info.block_info.hash.eql(setup.hash(20)));
}

test "el engine: safe and finalized wait for a deep enough ring" {
    var setup: Setup = .{};
    try setup.init(30, 64, 10); // Ring 64 blocks, 30 held, nothing evicted yet.
    defer setup.deinit();
    var buffer: [64 * 1024]u8 = undefined;
    for ([_][]const u8{ "safe", "finalized" }) |tag| {
        const text = try get_block(&setup, &buffer, tag, true);
        try testing.expect(contains(text, "warming up (30 of 16384 blocks)"));
    }
    try testing.expect(setup.engine.anchor == null);
    // A forkchoice label answers at once.
    _ = try setup.engine.forkchoice(&setup.state(29, 20, null));
    try testing.expect(contains(try get_block(&setup, &buffer, "safe", false), "\"result\":{"));
    try testing.expect(contains(try get_block(&setup, &buffer, "finalized", false), "warming"));
}

test "el engine: empty ring reads fail clearly" {
    var setup: Setup = .{};
    setup.fixture.init();
    setup.fake = .{ .fixture = &setup.fixture, .head_index = 5, .canonical_from = 0 };
    try setup.engine.init(testing.allocator, spec, secret, setup.fake.chain(), .{
        .blocks_max = 4,
        .bytes_max = 64 * 1024,
        .transactions_max = 1 << 14,
    });
    defer setup.deinit();
    var buffer: [4096]u8 = undefined;
    for ([_][]const u8{ "latest", "safe", "finalized", "0x64" }) |tag| {
        const text = try get_block(&setup, &buffer, tag, true);
        try testing.expect(contains(text, "-32000"));
        try testing.expect(contains(text, "ring is empty"));
    }
}

// ---- HTTP: a consensus EngineClient against the server over the simulated network --------

const Server = el_engine.Server(io.SimIo);
const Client = sources.EngineClient(io.SimIo);

const test_server_options: base.utilities.http.server.Options = .{
    .connections_max = 4,
    .recv_buffer_size = 2 * 64 * 1024,
    .send_buffer_size = 64 * 1024,
    .limits = .{ .head_size_max = 4 * 1024, .body_size_max = 64 * 1024 },
};

const client_options: http_client.Options = .{
    .send_buffer_size = 64 * 1024,
    .recv_buffer_size = 4 * 1024 + 256 * 1024,
    .limits = .{ .head_size_max = 4 * 1024, .body_size_max = 256 * 1024 },
};

const Outcome = struct {
    response: ?sources.engine_client.Error!sources.engine_client.Response = null,

    fn on_response(
        outcome: *Outcome,
        client: *Client,
        result: sources.engine_client.Error!sources.engine_client.Response,
    ) void {
        _ = client;
        outcome.response = result;
    }
};

const Network = struct {
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    server: Server,
    address: io.Address,

    fn init(network: *Network, engine: *Engine) !void {
        const allocator = testing.allocator;
        network.world = try io.SimWorld.init(allocator, .{ .seed = 0xe1 });
        errdefer network.world.deinit();
        try io.SimIo.init(&network.server_io, allocator, &network.world, .{
            .host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        errdefer network.server_io.deinit();
        try io.SimIo.init(&network.client_io, allocator, &network.world, .{
            .host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        errdefer network.client_io.deinit();
        try network.server.init(allocator, &network.server_io, engine, test_server_options);
        errdefer network.server.deinit();
        network.address = try network.server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8551));
        engine.now_s = network.client_io.now_realtime_ns() / std.time.ns_per_s;
    }

    fn deinit(network: *Network) void {
        network.server.deinit();
        network.client_io.deinit();
        network.server_io.deinit();
        network.world.deinit();
    }

    fn client(network: *Network, engine_client: *Client, client_secret: jwt.Secret) !void {
        try engine_client.init(
            testing.allocator,
            &network.client_io,
            network.address,
            client_options,
            client_secret,
            .{ .genesis = .{}, .request_size_max = 64 * 1024 },
        );
    }

    fn run(network: *Network, outcome: *Outcome) !sources.engine_client.Response {
        network.world.run_for_ns(std.time.ns_per_s);
        const result = outcome.response orelse return error.NoResponse;
        outcome.response = null;
        return result;
    }
};

test "el engine: a consensus EngineClient drives the server over HTTP" {
    var setup: Setup = .{};
    try setup.init(30, 16, 10);
    defer setup.deinit();
    var network: Network = undefined;
    try network.init(&setup.engine);
    defer network.deinit();
    var client: Client = undefined;
    try network.client(&client, secret);
    defer client.deinit();
    var outcome: Outcome = .{};
    const on_response = Outcome.on_response;

    try client.exchange_capabilities(*Outcome, &outcome, on_response);
    const capabilities = (try network.run(&outcome)).capabilities;
    try testing.expect(sources.engine_json.has_capability(capabilities, "engine_newPayloadV4"));
    const payload = setup.fixture.payload(18);
    try client.new_payload(.v4, &payload, &Fixture.params, *Outcome, &outcome, on_response);
    try testing.expectEqual(.valid, (try network.run(&outcome)).payload_status.status);
    const state = setup.state(29, 18, 16);
    try client.forkchoice_updated(.v3, &state, null, *Outcome, &outcome, on_response);
    const updated = (try network.run(&outcome)).forkchoice_updated;
    try testing.expectEqual(.valid, updated.payload_status.status);
    try client.l2_full_block(.safe, *Outcome, &outcome, on_response);
    const safe = (try network.run(&outcome)).l2_block_full;
    try testing.expect(safe.info.block_info.hash.eql(setup.hash(18)));
    try testing.expectEqual(@as(usize, 2), safe.transactions.len);
    try client.l2_block_info(.{ .number = Fixture.first + 16 }, *Outcome, &outcome, on_response);
    const info = (try network.run(&outcome)).l2_block;
    try testing.expect(info.block_info.hash.eql(setup.hash(16)));
    try testing.expectEqual(@as(u64, 504), info.l1_origin.number);
    try client.l2_block_info(.{ .number = Fixture.first + 2 }, *Outcome, &outcome, on_response);
    try testing.expectError(error.RpcError, network.run(&outcome));
    try testing.expectEqual(@as(i64, -32000), client.last_rpc_error_code);
    try testing.expectEqual(@as(u64, 0), setup.engine.stats.unauthorized);
}

fn expect_failure(network: *Network, outcome: *Outcome) !void {
    if (network.run(outcome)) |_| return error.TestUnexpectedResult else |err| {
        try testing.expect(err != error.NoResponse);
    }
}

test "el engine: requests without the shared secret are refused" {
    var setup: Setup = .{};
    try setup.init(4, 16, 4);
    defer setup.deinit();
    var network: Network = undefined;
    try network.init(&setup.engine);
    defer network.deinit();
    var client: Client = undefined;
    try network.client(&client, .{ .bytes = @splat(0x43) });
    defer client.deinit();
    var outcome: Outcome = .{};
    const state = setup.state(3, null, null);
    try client.forkchoice_updated(.v3, &state, null, *Outcome, &outcome, Outcome.on_response);
    try expect_failure(&network, &outcome);
    try testing.expectEqual(@as(u64, 1), setup.engine.stats.unauthorized);
    try testing.expectEqual(@as(?el_engine.Label, null), setup.engine.head);
    // A stale token (iat outside the window) is refused too.
    setup.engine.now_s += 3600;
    var good: Client = undefined;
    try network.client(&good, secret);
    defer good.deinit();
    try good.forkchoice_updated(.v3, &state, null, *Outcome, &outcome, Outcome.on_response);
    try expect_failure(&network, &outcome);
    try testing.expectEqual(@as(u64, 2), setup.engine.stats.unauthorized);
    setup.engine.now_s -= 3600;
    try good.forkchoice_updated(.v3, &state, null, *Outcome, &outcome, Outcome.on_response);
    const updated = (try network.run(&outcome)).forkchoice_updated;
    try testing.expectEqual(.valid, updated.payload_status.status);
}

test "el engine: the service answers between blocks and while idle (production IO)" {
    var probe = try io.init_for_test(); // Skips where io_uring is unavailable.
    probe.deinit();
    var fixture: Fixture = .{};
    fixture.init();
    var fake: FakeChain = .{ .fixture = &fixture };
    const loopback = io.Address.ip4(.{ 127, 0, 0, 1 }, 0);
    const ring: el_ring.Options = .{ .blocks_max = 8, .bytes_max = 1 << 20 };
    const chain = fake.chain();
    const create = el_engine.Service.create;
    const options = test_server_options;
    const service = try create(testing.allocator, loopback, secret, spec, chain, ring, options);
    defer service.destroy(testing.allocator);
    for (0..6) |index| {
        fake.head_index = index;
        service.engine.on_block(&fixture.block(index));
    }
    const Production = sources.EngineClient(io.IO);
    var client: Production = undefined;
    try client.init(testing.allocator, &service.io, service.address, client_options, secret, .{
        .genesis = .{},
        .request_size_max = 64 * 1024,
    });
    defer client.deinit();
    const Result = struct {
        response: ?sources.engine_client.Error!sources.engine_client.Response = null,

        fn on_response(
            result: *@This(),
            engine_client: *Production,
            response: sources.engine_client.Error!sources.engine_client.Response,
        ) void {
            _ = engine_client;
            result.response = response;
        }
    };
    var result: Result = .{};
    // Between blocks: non-blocking polls only.
    try client.l2_full_block(.latest, *Result, &result, Result.on_response);
    var polls: u32 = 0;
    while (result.response == null and polls < 100_000) : (polls += 1) service.poll();
    const latest = (try result.response.?).l2_block_full;
    try testing.expect(latest.info.block_info.hash.eql(.{ .bytes = fixture.hashes[5] }));
    // Idle at the tip: bounded waits.
    result.response = null;
    const state: ForkchoiceState = .{
        .head_block_hash = .{ .bytes = fixture.hashes[5] },
        .safe_block_hash = .{ .bytes = fixture.hashes[3] },
        .finalized_block_hash = .zero,
    };
    try client.forkchoice_updated(.v3, &state, null, *Result, &result, Result.on_response);
    var waits: u32 = 0;
    while (result.response == null and waits < 200) : (waits += 1) try service.wait(10);
    const updated = (try result.response.?).forkchoice_updated;
    try testing.expectEqual(.valid, updated.payload_status.status);
    try testing.expectEqual(@as(u64, Fixture.first + 3), service.engine.safe.?.number);
}

test "el engine: flags" {
    var flags: el_engine.Flags = .{};
    try testing.expect(!try flags.parse("--db", "x"));
    try testing.expect(try flags.parse("--engine.addr", "127.0.0.1:8551"));
    try testing.expect(!flags.valid());
    try testing.expect(try flags.parse("--engine.jwt", "jwt.hex"));
    try testing.expect(flags.valid());
    try testing.expect(try flags.parse("--engine.ring-blocks", "4096"));
    try testing.expect(try flags.parse("--engine.ring-mb", "256"));
    const options = flags.ring_options();
    try testing.expectEqual(@as(u32, 4096), options.blocks_max);
    try testing.expectEqual(@as(u64, 256 << 20), options.bytes_max);
    try testing.expectError(error.InvalidArguments, flags.parse("--engine.ring-blocks", "1"));
    try testing.expectError(error.InvalidArguments, flags.parse("--engine.ring-mb", "0"));
    try testing.expectError(error.InvalidArguments, flags.parse("--engine.ring-mb", "x"));
}

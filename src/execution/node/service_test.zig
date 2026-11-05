//! End-to-end tests of the node service over SimIo: the `--dev-l1` chain mines one block
//! per slot, serves JSON-RPC, and keeps blob sidecars for the beacon API.

const std = @import("std");
const testing = std.testing;
const io = @import("../../utilities/io/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const log = @import("../../utilities/log/root.zig");
const genesis = @import("../../common/genesis/root.zig");
const devnet = @import("../../batcher/devnet/root.zig");
const service_module = @import("service.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const validate = @import("../txpool/validate.zig");
const eth = @import("../rpc/eth.zig");

const Service = service_module.Service(io.SimIo);
const genesis_time: u64 = 1_700_000_000; // SimIo's default realtime start.
const block_time_s: u64 = 2;

const test_limits: service_module.Limits = .{
    .state = .{
        .trie = .{ .accounts_max = 256, .account_nodes_max = 4096, .storage_nodes_max = 8192 },
        .code_bytes_max = 1 << 16,
        .codes_max = 64,
        .undo_bytes_max = 1 << 20,
    },
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
    .chain = .{
        .store = .{ .blocks_max = 256, .bytes_max = 1 << 20 },
        .staging_bytes = 1 << 18,
        .select_max = 64,
        .build_bytes = 1 << 16,
        .tx_index_max = 1024,
    },
    .beacon = .{ .slots_max = 64, .bytes_max = 1 << 20 },
    .http = .{
        .connections_max = 2,
        .recv_buffer_size = 16 * 1024,
        .send_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 1024, .body_size_max = 8 * 1024 },
    },
    .beacon_http = .{
        .connections_max = 2,
        .recv_buffer_size = 4 * 1024,
        .send_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 1024, .body_size_max = 1024 },
    },
    .rpc_scratch_bytes = 512 * 1024,
};

const Answer = struct {
    text: [128]u8 = undefined,
    size: usize = 0,
    done: bool = false,

    fn on_result(
        answer: *Answer,
        client: *rpc.Client(io.SimIo),
        result: rpc.client.Error!rpc.client.Result,
    ) void {
        _ = client;
        const value = result catch return;
        const ok = switch (value) {
            .ok => |ok| ok,
            .rpc_error => return,
        };
        @memcpy(answer.text[0..ok.len], ok);
        answer.size = ok.len;
        answer.done = true;
    }
};

test "service: dev L1 mines one block per slot and serves eth_blockNumber" {
    const harness = try Harness.create();
    defer harness.destroy();
    const service = &harness.service;
    var client_io: io.SimIo = undefined;
    const client_host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0);
    try io.SimIo.init(&client_io, testing.allocator, &harness.world, .{ .host = client_host });
    defer client_io.deinit();
    const bound = try service.start();
    const world = &harness.world;

    world.run_for_ns(7 * std.time.ns_per_s);
    try testing.expectEqual(@as(u64, 3), service.blocks_mined);
    try testing.expectEqual(@as(u64, 0), service.mine_failures);
    const head = service.chain.header(service.chain.head_hash()).?;
    try testing.expectEqual(genesis_time + 3 * block_time_s, head.timestamp);
    try testing.expect(service.beacon.?.sidecars(3) != null);
    try testing.expect(service.beacon.?.sidecars(4) == null);

    var client = try rpc.Client(io.SimIo).init(testing.allocator, &client_io, bound, .{
        .send_buffer_size = 4096,
        .recv_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 1024, .body_size_max = 8 * 1024 },
    }, 1024);
    defer client.deinit();
    var answer: Answer = .{};
    const no_params = rpc.client.no_params;
    try client.call(*Answer, &answer, Answer.on_result, "eth_blockNumber", {}, no_params);
    world.run_for_ns(std.time.ns_per_s / 2);
    try testing.expect(answer.done);
    try testing.expectEqualStrings("\"0x3\"", answer.text[0..answer.size]);
}

test "service: durable dev L1 restarts from its synced state file" {
    const harness = try Harness.create_with(true);
    defer harness.destroy();
    _ = try harness.service.start();
    harness.world.run_for_ns(7 * std.time.ns_per_s);
    try testing.expectEqual(@as(u64, 3), harness.service.blocks_mined);
    // Let the journal reach the disk, then lose everything that is not synced.
    harness.world.run_for_ns(std.time.ns_per_s / 2);
    const head_hash = harness.service.chain.head_hash();
    const root = try harness.service.db.root();
    try harness.restart();
    try testing.expectEqualSlices(u8, &head_hash, &harness.service.chain.head_hash());
    try testing.expectEqualSlices(u8, &root, &(try harness.service.db.root()));
    try testing.expect(harness.service.chain.store.canonical_hash(1) != null);
    // Mining continues on the restored head (one block per slot from here).
    _ = try harness.service.start();
    harness.world.run_for_ns(4 * std.time.ns_per_s);
    try testing.expect(harness.service.blocks_mined >= 1);
    try testing.expectEqual(@as(u64, 0), harness.service.mine_failures);
    const head = harness.service.chain.header(harness.service.chain.head_hash()).?;
    try testing.expect(head.number > 3);
    try harness.restart();
    try testing.expectEqual(head.number, harness.service.chain.header(
        harness.service.chain.head_hash(),
    ).?.number);
}

const durable_file = "node.db";

const durable_limits: service_module.Limits = limits: {
    var limits = test_limits;
    limits.durable.engine = .{
        .journal_size_bytes = 128 * 4096,
        .checkpoint_zone_size_bytes = 96 * 4096,
        .entry_body_size_max = 16 * 4096,
        .checkpoint_block_size = 4 * 4096,
    };
    limits.durable.chain.blocks_max = 64;
    limits.durable.chain.bytes_max = 256 * 1024;
    limits.durable.checkpoint_staging_bytes = 96 * 4096;
    limits.storage_tick_ns = std.time.ns_per_ms;
    break :limits limits;
};

const Harness = struct {
    world: io.SimWorld,
    node_io: io.SimIo,
    parsed: genesis.Parsed,
    log_buffer: [16 * 1024]u8,
    memory: log.MemorySink,
    logger: log.Logger,
    service: Service,
    durable: bool,
    /// Restarts so far; shifts the ports because a dead process's listeners linger.
    restarts: u16 = 0,
    history_window: u32 = 0,

    fn create() !*Harness {
        return create_with(false);
    }

    fn create_with(durable: bool) !*Harness {
        return create_full(durable, 0);
    }

    fn create_full(durable: bool, history_window: u32) !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.world = try io.SimWorld.init(testing.allocator, .{ .seed = 11 });
        errdefer harness.world.deinit();
        harness.durable = durable;
        harness.restarts = 0;
        harness.history_window = history_window;
        try harness.init_io();
        errdefer harness.node_io.deinit();
        var text: [64 * 1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&text);
        try devnet.genesis.write_l1_genesis(&writer, &.{ .genesis_timestamp = genesis_time });
        harness.parsed = try genesis.parse(testing.allocator, writer.buffered());
        errdefer harness.parsed.deinit();
        harness.memory = .{ .buffer = &harness.log_buffer };
        harness.logger = .{ .sink = harness.memory.sink() };
        try harness.init_service();
        return harness;
    }

    fn init_io(harness: *Harness) !void {
        const host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0);
        try io.SimIo.init(&harness.node_io, testing.allocator, &harness.world, .{
            .host = host,
            .disk = .{ .files_max = 2, .file_size_max = 2 << 20 },
        });
    }

    fn init_service(harness: *Harness) !void {
        const parsed = &harness.parsed.value;
        const node_io = &harness.node_io;
        try harness.service.init(testing.allocator, node_io, &harness.logger, parsed, .{
            .http_address = io.Address.ip4(.{ 10, 0, 0, 1 }, 8545 + harness.restarts),
            .dev_l1 = true,
            .block_time_s = block_time_s,
            .beacon_address = io.Address.ip4(.{ 10, 0, 0, 1 }, 5052 + harness.restarts),
            .verify_blob_proofs = false, // Fake proofs; KZG is covered in release tests.
            .limits = if (harness.durable) durable_limits else test_limits,
            .data_path = if (harness.durable) durable_file else null,
            .proofs_history_window = harness.history_window,
        });
    }

    /// A process crash and restart: only synced bytes of the state file survive.
    fn restart(harness: *Harness) !void {
        const file = durable_file_of(&harness.node_io).?;
        const size: usize = @intCast(file.size_durable);
        const saved = try testing.allocator.dupe(u8, file.durable[0..size]);
        defer testing.allocator.free(saved);
        harness.service.deinit();
        harness.node_io.deinit();
        try harness.init_io();
        const fd = try harness.node_io.open_file(durable_file, .create);
        harness.node_io.close_now(fd);
        const fresh = durable_file_of(&harness.node_io).?;
        @memcpy(fresh.durable[0..size], saved);
        @memcpy(fresh.current[0..size], saved);
        fresh.size_durable = size;
        fresh.size_current = size;
        harness.memory = .{ .buffer = &harness.log_buffer };
        harness.restarts += 1;
        try harness.init_service();
    }

    fn durable_file_of(node_io: *io.SimIo) ?*@TypeOf(node_io.files[0]) {
        for (node_io.files) |*file| {
            if (file.used and std.mem.eql(u8, file.name[0..file.name_len], durable_file)) {
                return file;
            }
        }
        return null;
    }

    fn destroy(harness: *Harness) void {
        harness.service.deinit();
        harness.parsed.deinit();
        harness.node_io.deinit();
        harness.world.deinit();
        testing.allocator.destroy(harness);
    }
};

/// A signed one-blob pooled transaction from dev account 0 (blob bytes = `fill`).
fn blob_transaction(
    buffer: []u8,
    blob: *[validate.bytes_per_blob]u8,
    blob_list: []u8,
    fill: u8,
) ![]const u8 {
    @memset(blob, fill);
    const commitment: [48]u8 = @splat(fill +% 1);
    const proof: [48]u8 = @splat(fill +% 2);
    var hash_buffer: [64]u8 = undefined;
    const versioned = validate.kzg_to_versioned_hash(&commitment);
    const tx: consensus.Eip4844 = .{
        .chain_id = 900,
        .nonce = 0,
        .max_priority_fee_per_gas = 1_000_000_000,
        .max_fee_per_gas = 100_000_000_000,
        .gas_limit = 21_000,
        .to = primitives.Address.zero,
        .value = 0,
        .input = &.{},
        .access_list = .empty,
        .max_fee_per_blob_gas = 1_000_000_000,
        .blob_versioned_hashes = consensus.HashList.build(&hash_buffer, &.{versioned}),
    };
    const envelope = try consensus.tx.sign(tx, devnet.accounts.derive_dev(0).private_key);
    var commitment_buffer: [64]u8 = undefined;
    var proof_buffer: [64]u8 = undefined;
    const pooled: consensus.PooledBlobTx = .{ .signed = envelope.eip4844, .sidecar = .{
        .blobs = consensus.sidecar.BlobList.build(blob_list, &.{blob.*}),
        .commitments = consensus.sidecar.CommitmentList.build(&commitment_buffer, &.{commitment}),
        .proofs = consensus.sidecar.ProofList.build(&proof_buffer, &.{proof}),
    } };
    return pooled.encode_to(buffer);
}

test "service: in-memory proofs history window follows mined blocks" {
    const harness = try Harness.create_full(false, 2);
    defer harness.destroy();
    const service = &harness.service;
    _ = try service.start();
    harness.world.run_for_ns(7 * std.time.ns_per_s);
    try testing.expectEqual(@as(u64, 3), service.blocks_mined);
    try testing.expect(service.chain.serves_history());
    const window = service.history.?.window().?;
    try testing.expectEqual(@as(u64, 3), window.head);
    try testing.expectEqual(@as(u64, 2), window.oldest);
    for ([_]u64{ 2, 3 }) |number| {
        const header = service.chain.header(service.chain.store.canonical_hash(number).?).?;
        try testing.expect(service.chain.history_has(number, header.state_root.bytes));
    }
    try testing.expectEqual(@as(u64, 0), service.chain.history_resets);
}

test "service: durable proofs history lives in the database and survives restart" {
    const harness = try Harness.create_full(true, 2);
    defer harness.destroy();
    const service = &harness.service;
    _ = try service.start();
    harness.world.run_for_ns(7 * std.time.ns_per_s);
    try testing.expect(service.history == null);
    try testing.expect(service.chain.serves_history());
    const window = service.durable.?.database.history.?.window().?;
    try testing.expectEqual(@as(u64, 3), window.head);
    harness.world.run_for_ns(std.time.ns_per_s / 2); // Let the storage tick sync.
    try harness.restart();
    try testing.expect(service.chain.serves_history());
    const head = service.chain.header(service.chain.head_hash()).?;
    const restored = service.durable.?.database.history.?.window().?;
    try testing.expectEqual(head.number, restored.head);
}

test "service: dev L1 keeps blob sidecars of mined blob transactions" {
    const harness = try Harness.create();
    defer harness.destroy();
    const service = &harness.service;
    _ = try service.start();

    const raw_buffer = try testing.allocator.alloc(u8, 140 * 1024);
    defer testing.allocator.free(raw_buffer);
    const blob = try testing.allocator.create([validate.bytes_per_blob]u8);
    defer testing.allocator.destroy(blob);
    const blob_list = try testing.allocator.alloc(u8, validate.bytes_per_blob + 16);
    defer testing.allocator.free(blob_list);
    const raw = try blob_transaction(raw_buffer, blob, blob_list, 0x5a);
    const body = try testing.allocator.alloc(u8, 2 * raw.len + 128);
    defer testing.allocator.free(body);
    const prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\",";
    const request = try std.fmt.bufPrint(body, "{s}\"params\":[\"0x{x}\"]}}", .{ prefix, raw });
    var response: [512]u8 = undefined;
    var out: std.Io.Writer = .fixed(&response);
    _ = eth.Router.handle(&service.api, request, &out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "\"result\"") != null);
    try testing.expectEqual(@as(u32, 1), service.pool.count());

    harness.world.run_for_ns(3 * std.time.ns_per_s);
    try testing.expectEqual(@as(u64, 1), service.blocks_mined);
    try testing.expectEqual(@as(u32, 0), service.pool.count());
    const entries = service.beacon.?.sidecars(1).?;
    try testing.expectEqual(@as(usize, @import("beacon.zig").entry_size), entries.len);
    try testing.expectEqualSlices(u8, blob, entries[0..validate.bytes_per_blob]);
    const head = service.chain.header(service.chain.head_hash()).?;
    try testing.expectEqual(@as(?u64, 131_072), head.blob_gas_used);
}

const Outcome = struct {
    ok: bool = false,
    failed: bool = false,
    text: [256]u8 = undefined,
    size: usize = 0,

    fn on_result(
        outcome: *Outcome,
        client: *rpc.Client(io.SimIo),
        result: rpc.client.Error!rpc.client.Result,
    ) void {
        _ = client;
        const value = result catch {
            outcome.failed = true;
            return;
        };
        switch (value) {
            .ok => |ok| {
                const size = @min(ok.len, outcome.text.len);
                @memcpy(outcome.text[0..size], ok[0..size]);
                outcome.size = size;
                outcome.ok = true;
            },
            .rpc_error => outcome.failed = true,
        }
    }
};

fn write_capabilities(context: void, writer: *json.Writer) json.Writer.WriteError!void {
    _ = context;
    try writer.begin_array();
    try writer.end_array();
}

test "service: L2 engine API requires a valid JWT" {
    const jwt = @import("../../utilities/jwt/root.zig");
    var world = try io.SimWorld.init(testing.allocator, .{ .seed = 5 });
    defer world.deinit();
    var node_io: io.SimIo = undefined;
    try io.SimIo.init(&node_io, testing.allocator, &world, .{
        .host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0),
    });
    defer node_io.deinit();
    var client_io: io.SimIo = undefined;
    try io.SimIo.init(&client_io, testing.allocator, &world, .{
        .host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0),
    });
    defer client_io.deinit();
    var text: [64 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&text);
    try devnet.genesis.write_l2_genesis(&writer, &.{ .genesis_timestamp = genesis_time });
    const parsed = try genesis.parse(testing.allocator, writer.buffered());
    defer parsed.deinit();
    var log_buffer: [4096]u8 = undefined;
    var memory: log.MemorySink = .{ .buffer = &log_buffer };
    var logger: log.Logger = .{ .sink = memory.sink() };
    const secret: jwt.Secret = .{ .bytes = @splat(0x42) };
    var limits = test_limits;
    limits.engine = .{ .bytes = 1 << 16, .transactions_max = 64 };
    limits.authrpc_http = limits.http;
    const service = try testing.allocator.create(Service);
    defer testing.allocator.destroy(service);
    try service.init(testing.allocator, &node_io, &logger, &parsed.value, .{
        .http_address = io.Address.ip4(.{ 10, 0, 0, 1 }, 9545),
        .authrpc_address = io.Address.ip4(.{ 10, 0, 0, 1 }, 9551),
        .jwt_secret = secret,
        .limits = limits,
    });
    defer service.deinit();
    try testing.expectEqual(@import("../chainspec/root.zig").Mode.l2, service.spec.mode);
    _ = try service.start();

    const authrpc = service.authrpc_address().?;
    var client = try rpc.Client(io.SimIo).init(testing.allocator, &client_io, authrpc, .{
        .send_buffer_size = 4096,
        .recv_buffer_size = 16 * 1024,
        .limits = .{ .head_size_max = 1024, .body_size_max = 8 * 1024 },
    }, 1024);
    defer client.deinit();
    var rejected: Outcome = .{};
    const method = "engine_exchangeCapabilities";
    try client.call(*Outcome, &rejected, Outcome.on_result, method, {}, write_capabilities);
    world.run_for_ns(std.time.ns_per_s / 2);
    try testing.expect(rejected.failed);

    var token_buffer: [jwt.token_size_max]u8 = undefined;
    const now_s = node_io.now_realtime_ns() / std.time.ns_per_s;
    client.set_bearer(jwt.create(secret, now_s, &token_buffer));
    var accepted: Outcome = .{};
    try client.call(*Outcome, &accepted, Outcome.on_result, method, {}, write_capabilities);
    world.run_for_ns(std.time.ns_per_s / 2);
    try testing.expect(accepted.ok);
    const capabilities = accepted.text[0..accepted.size];
    try testing.expect(std.mem.indexOf(u8, capabilities, "newPayloadV4") != null);
}

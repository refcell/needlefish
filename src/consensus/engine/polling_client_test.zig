//! Polling client tests over the simulated network: results are handed out once per
//! request key, stale results are discarded, errors map onto `task.ClientError`, the task
//! queue runs insert and consolidate tasks end to end against a fake execution layer, and a
//! seeded fuzz with random latencies, connection resets, refusals, and abandoned requests
//! checks that no result is lost or handed to the wrong call.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const protocol = @import("../protocol/root.zig");
const harness_module = @import("../sources/sim_harness.zig");
const fixtures = @import("../sources/fixtures.zig");
const engine_client = @import("../sources/engine_client.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;
const task = @import("task.zig");
const queue_module = @import("task_queue.zig");
const insert_module = @import("insert_task.zig");
const PollingClient = @import("polling_client.zig").PollingClient;

const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Engine = engine_client.EngineClient(io.SimIo);
const Client = PollingClient(io.SimIo);

const ms = std.time.ns_per_ms;

const Setup = struct {
    fake: FakeRpc = .{},
    harness: Harness = undefined,
    engine: Engine = undefined,
    client: Client = undefined,

    /// `setup` must not move afterwards.
    fn init(setup: *Setup, options: io.sim.Options) !void {
        try setup.harness.init_world(&setup.fake, options);
        errdefer setup.harness.deinit();
        var http_options = harness_module.client_options;
        http_options.request_timeout_ns = 500 * ms;
        const secret: jwt.Secret = .{ .bytes = @splat(0x42) };
        const harness = &setup.harness;
        const options_engine: engine_client.Options = .{
            .genesis = .{},
            .request_size_max = 8 * 1024,
        };
        const allocator = testing.allocator;
        const address = harness.address;
        const client_io = &harness.client_io;
        try setup.engine.init(allocator, client_io, address, http_options, secret, options_engine);
        setup.client = .init(&setup.engine);
    }

    /// Lets any request in flight finish first: the engine client must be idle.
    fn deinit(setup: *Setup) void {
        for (0..64) |_| {
            if (!setup.engine.busy()) break;
            setup.client.tick();
            setup.harness.world.run_for_ns(100 * ms);
        }
        setup.engine.deinit();
        setup.harness.deinit();
    }

    fn run(setup: *Setup) void {
        setup.harness.world.run_for_ns(200 * ms);
    }
};

fn forkchoice_state(head: u8) task.EngineForkchoiceState {
    return .{
        .head_block_hash = .init(@splat(head)),
        .safe_block_hash = .zero,
        .finalized_block_hash = .zero,
    };
}

const forkchoice_valid =
    \\{"payloadStatus":{"status":"VALID","latestValidHash":null,"validationError":null},
++
    \\"payloadId":null}
;

fn forkchoice_result(comptime id: u8) []const u8 {
    return std.fmt.comptimePrint(
        "{{\"payloadStatus\":{{\"status\":\"VALID\",\"latestValidHash\":null}}," ++
            "\"payloadId\":\"0x00000000000000{x:0>2}\"}}",
        .{id},
    );
}

fn head_filter(comptime head: u8) []const u8 {
    return std.fmt.comptimePrint("\"headBlockHash\":\"0x{x:0>2}{x:0>2}", .{ head, head });
}

/// Heads 1-3 answer with payload id = head; head 4 is -38002 and head 5 is -38001.
fn add_forkchoice_entries(fake: *FakeRpc) void {
    inline for (.{ 1, 2, 3 }) |head| fake.add(.{
        .method = "engine_forkchoiceUpdatedV3",
        .params_contain = head_filter(head),
        .result = forkchoice_result(head),
    });
    fake.add(.{
        .method = "engine_forkchoiceUpdatedV3",
        .params_contain = head_filter(4),
        .rpc_error = "{\"code\":-38002,\"message\":\"Invalid forkchoice state\"}",
    });
    fake.add(.{
        .method = "engine_forkchoiceUpdatedV3",
        .params_contain = head_filter(5),
        .rpc_error = "{\"code\":-38001,\"message\":\"Unknown payload\"}",
    });
}

fn expect_payload_id(expected: u64, updated: task.ForkchoiceUpdated) !void {
    try testing.expectEqual(expected, payload_id_value(updated));
}

fn payload_id_value(updated: task.ForkchoiceUpdated) u64 {
    const id = updated.payload_id orelse return 0;
    return std.mem.readInt(u64, &id, .big);
}

test "polling client: one result per key; stale results are discarded" {
    var setup: Setup = .{};
    try setup.init(.{ .seed = 0x91 });
    defer setup.deinit();
    add_forkchoice_entries(&setup.fake);
    const client = &setup.client;
    const one = forkchoice_state(1);
    const two = forkchoice_state(2);

    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &one, null));
    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &one, null));
    setup.run();
    try expect_payload_id(1, try client.forkchoice_updated(.v3, &one, null));
    try testing.expectEqual(@as(u32, 1), setup.fake.requests);

    // The same call again is a new request.
    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &one, null));
    setup.run();
    // A different call discards the stored result and starts its own request.
    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &two, null));
    setup.run();
    try expect_payload_id(2, try client.forkchoice_updated(.v3, &two, null));
    try testing.expectEqual(@as(u32, 3), setup.fake.requests);
    try testing.expectEqual(@as(u64, 1), client.results_discarded);

    // A different call while a request is in flight waits, then replaces the result.
    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &one, null));
    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &two, null));
    setup.run();
    try testing.expectError(error.NotAvailable, client.forkchoice_updated(.v3, &two, null));
    setup.run();
    try expect_payload_id(2, try client.forkchoice_updated(.v3, &two, null));
    try testing.expectEqual(@as(u64, 2), client.results_discarded);
    try testing.expectEqual(@as(u64, 5), client.requests_started);
}

/// Polls `call` until it stops returning `NotAvailable`.
fn wait(
    setup: *Setup,
    comptime call: anytype,
    args: anytype,
) @typeInfo(@TypeOf(call)).@"fn".return_type.? {
    for (0..16) |_| {
        return @call(.auto, call, .{&setup.client} ++ args) catch |err| {
            if (err == error.NotAvailable) {
                setup.run();
                continue;
            }
            return err;
        };
    }
    return error.NotAvailable;
}

test "polling client: error mapping and block lookups" {
    var setup: Setup = .{};
    try setup.init(.{ .seed = 0x92 });
    defer setup.deinit();
    add_forkchoice_entries(&setup.fake);
    var info_buffer: [4096]u8 = undefined;
    var info_hash: [32]u8 = undefined;
    const info_text = try fixtures.l2_block_json(&info_buffer, 9, &info_hash);
    var block: fixtures.L2FullBlock = undefined;
    block.init(12, .init(@splat(11)), 1, &.{});
    var block_buffer: [8 * 1024]u8 = undefined;
    const block_text = try block.json_text(&block_buffer);
    const by_number = "eth_getBlockByNumber";
    setup.fake.add(.{ .method = by_number, .params_contain = "\"0x9\"", .result = info_text });
    setup.fake.add(.{ .method = by_number, .params_contain = "\"0xc\"", .result = block_text });
    // Block 14 answers with block 12: the number check rejects it.
    setup.fake.add(.{ .method = by_number, .params_contain = "\"0xe\"", .result = block_text });
    // Block 15 answers with block 9's info shape: not a valid full block (no root match).
    setup.fake.add(.{ .method = by_number, .params_contain = "\"0xf\"", .result = info_text });

    const four = forkchoice_state(4);
    const five = forkchoice_state(5);
    const Methods = Client;
    const invalid = wait(&setup, Methods.forkchoice_updated, .{ .v3, &four, null });
    try testing.expectError(error.InvalidForkchoiceState, invalid);
    const failed = wait(&setup, Methods.forkchoice_updated, .{ .v3, &five, null });
    try testing.expectError(error.RpcFailed, failed);

    const info = (try wait(&setup, Methods.l2_block_info_by_number, .{9})).?;
    try testing.expect(info.block_info.hash.eql(.init(info_hash)));
    try testing.expectEqual(@as(u64, 509), info.l1_origin.number);
    try testing.expect(try wait(&setup, Methods.l2_block_info_by_number, .{10}) == null);

    const full = (try wait(&setup, Methods.l2_block_by_number, .{12})).?;
    try testing.expect(full.info.block_info.hash.eql(block.hash()));
    try testing.expectEqual(@as(usize, 1), full.transactions.len);
    try testing.expect(try wait(&setup, Methods.l2_block_by_number, .{13}) == null);
    try testing.expectError(error.InvalidBlock, wait(&setup, Methods.l2_block_by_number, .{14}));
    try testing.expectError(error.InvalidBlock, wait(&setup, Methods.l2_block_by_number, .{15}));
    const wrong_info = wait(&setup, Methods.l2_block_info_by_number, .{14});
    try testing.expectError(error.InvalidBlock, wrong_info);
}

const rollup_default: RollupConfig = .{};

fn info_nine() L2BlockInfo {
    return .{
        .block_info = .{ .hash = .init(@splat(9)), .number = 9, .timestamp = 1_700_000_108 },
        .l1_origin = .{ .number = 509, .hash = .init(@splat(0x55)) },
        .sequence_number = 0,
    };
}

/// Block 10 on top of `info_nine`, with its payload and matching derived attributes.
const Fixture = struct {
    block: fixtures.L2FullBlock,
    bytes: [4][512]u8,
    transactions: [4][]u8,
    envelope: insert_module.Envelope,
    attributes: AttributesWithParent,

    fn init(fixture: *Fixture) void {
        const signed = fixtures.signed_transactions();
        fixture.block.init(10, info_nine().block_info.hash, 1, &.{ signed[0], signed[2] });
        const block = &fixture.block;
        assert(block.count == 3);
        for (block.transactions(), 0..) |envelope, index| {
            fixture.transactions[index] = envelope.encode_to(&fixture.bytes[index]);
        }
        const header = &block.header;
        const transactions = fixture.transactions[0..block.count];
        fixture.envelope = .{
            .payload = .{
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
                .block_hash = block.hash(),
                .transactions = transactions,
                .withdrawals = &.{},
                .blob_gas_used = 0,
                .excess_blob_gas = 0,
            },
            .parent_beacon_block_root = header.parent_beacon_block_root,
        };
        fixture.attributes = .{
            .attributes = .{
                .timestamp = header.timestamp,
                .prev_randao = header.mix_hash,
                .suggested_fee_recipient = header.beneficiary,
                .withdrawals = null,
                .parent_beacon_block_root = header.parent_beacon_block_root,
                .transactions = transactions,
                .no_tx_pool = true,
                .gas_limit = header.gas_limit,
                .eip1559_params = null,
                .min_base_fee = null,
            },
            .parent = info_nine(),
            .derived_from = null,
            .is_last_in_span = true,
        };
    }
};

fn add_engine_entries(fake: *FakeRpc, block_text: []const u8) void {
    const payload_valid =
        \\{"status":"VALID","latestValidHash":null,"validationError":null}
    ;
    fake.add(.{ .method = "engine_newPayloadV3", .result = payload_valid });
    fake.add(.{ .method = "engine_forkchoiceUpdatedV3", .result = forkchoice_valid });
    const by_number = "eth_getBlockByNumber";
    fake.add(.{ .method = by_number, .params_contain = "\"0xa\"", .result = block_text });
}

test "polling client: task queue inserts and consolidates over simulated HTTP" {
    var setup: Setup = .{};
    try setup.init(.{ .seed = 0x93 });
    defer setup.deinit();
    var fixture: Fixture = undefined;
    fixture.init();
    var block_buffer: [8 * 1024]u8 = undefined;
    add_engine_entries(&setup.fake, try fixture.block.json_text(&block_buffer));

    const nine = info_nine();
    const initial: task.EngineState = .{
        .sync_state = .{
            .unsafe_head = nine,
            .local_safe_head = nine,
            .safe_head = nine,
            .finalized_head = nine,
        },
        .el_sync_finished = true,
    };
    var queue = try queue_module.EngineTaskQueue.init(testing.allocator, .{
        .rollup = &rollup_default,
    }, initial, .{ .capacity = 4 });
    defer queue.deinit(testing.allocator);
    try queue.enqueue(.{ .insert = .{ .envelope = &fixture.envelope } });
    try queue.enqueue(.{ .consolidate = &fixture.attributes });

    var completions: [2]queue_module.Completion = undefined;
    var completed: u32 = 0;
    for (0..200) |_| {
        const result = queue.step(&setup.client);
        switch (result) {
            .idle => break,
            .pending => setup.harness.world.run_for_ns(5 * ms),
            .completed => |completion| {
                completions[completed] = completion;
                completed += 1;
            },
            .failed => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqual(@as(u32, 2), completed);
    const inserted = completions[0].insert;
    try testing.expect(completions[1] == .consolidate);
    try testing.expect(inserted.block_info.hash.eql(fixture.block.hash()));
    try testing.expectEqual(@as(u64, 510), inserted.l1_origin.number);
    const sync_state = queue.state.sync_state;
    try testing.expect(sync_state.unsafe_head.eql(inserted));
    try testing.expect(sync_state.safe_head.eql(inserted));
    try testing.expect(sync_state.local_safe_head.eql(inserted));
    try testing.expect(sync_state.finalized_head.eql(nine));
    // newPayload, forkchoice (insert), getBlockByNumber, forkchoice (consolidate).
    try testing.expectEqual(@as(u32, 4), setup.fake.requests);
    try testing.expectEqual(@as(u64, 0), setup.client.results_discarded);
}

/// One call of the fuzz: a forkchoice update for a head, or a block lookup by number.
const Call = union(enum) {
    forkchoice: u8,
    block_info: u64,
    block: u64,
};

const Expected = struct {
    info_hash: B256,
    block_hash: B256,
};

fn random_call(prng: *Prng) Call {
    return switch (prng.below(3)) {
        0 => .{ .forkchoice = @intCast(prng.range(1, 6)) },
        1 => .{ .block_info = prng.range(9, 10) },
        2 => .{ .block = prng.range(12, 13) },
        else => unreachable,
    };
}

/// Calls once. Returns null while not available; otherwise a digest of the outcome after
/// checking it against what the fake serves for that call.
fn call_once(client: *Client, call: Call, expected: *const Expected) ?u64 {
    switch (call) {
        .forkchoice => |head| {
            const state = forkchoice_state(head);
            const updated = client.forkchoice_updated(.v3, &state, null) catch |err| {
                if (err == error.NotAvailable) return null;
                const invalid = head == 4 and err == error.InvalidForkchoiceState;
                assert(err == error.RpcFailed or invalid);
                return @intFromError(err);
            };
            assert(head <= 3);
            assert(payload_id_value(updated) == head);
            return @as(u64, 1000) + head;
        },
        .block_info => |number| {
            const info = client.l2_block_info_by_number(number) catch |err| {
                if (err == error.NotAvailable) return null;
                assert(err == error.RpcFailed);
                return @intFromError(err);
            };
            if (number == 10) assert(info == null);
            if (number == 9) assert(info.?.block_info.hash.eql(expected.info_hash));
            return 2000 + number;
        },
        .block => |number| {
            const block = client.l2_block_by_number(number) catch |err| {
                if (err == error.NotAvailable) return null;
                assert(err == error.RpcFailed);
                return @intFromError(err);
            };
            if (number == 13) assert(block == null);
            if (number == 12) assert(block.?.info.block_info.hash.eql(expected.block_hash));
            return 3000 + number;
        },
    }
}

/// Runs random calls with random latencies, resets, refusals, and abandoned requests.
/// Returns a digest of every outcome for the replay check.
fn fuzz_run(seed: u64) !u64 {
    var prng = Prng.init(seed);
    const latency_max_ns = prng.range(200_000, 20 * ms);
    var setup: Setup = .{};
    try setup.init(.{
        .seed = seed,
        .latency_min_ns = 50_000,
        .latency_max_ns = latency_max_ns,
        .reset_ppm = @intCast(prng.below(30_000)),
        .refuse_ppm = @intCast(prng.below(100_000)),
    });
    defer setup.deinit();
    add_forkchoice_entries(&setup.fake);
    var info_buffer: [4096]u8 = undefined;
    var info_hash: [32]u8 = undefined;
    const info_text = try fixtures.l2_block_json(&info_buffer, 9, &info_hash);
    var block: fixtures.L2FullBlock = undefined;
    block.init(12, .init(@splat(11)), 1, &.{});
    var block_buffer: [8 * 1024]u8 = undefined;
    const block_text = try block.json_text(&block_buffer);
    const by_number = "eth_getBlockByNumber";
    setup.fake.add(.{ .method = by_number, .params_contain = "\"0x9\"", .result = info_text });
    setup.fake.add(.{ .method = by_number, .params_contain = "\"0xc\"", .result = block_text });
    const expected: Expected = .{ .info_hash = .init(info_hash), .block_hash = block.hash() };

    var hasher = std.hash.Wyhash.init(seed);
    var finished: u32 = 0;
    for (0..120) |_| {
        const call = random_call(&prng);
        const abandon = prng.chance(1, 5);
        var outcome: ?u64 = null;
        for (0..2_000) |_| {
            setup.client.tick();
            outcome = call_once(&setup.client, call, &expected);
            if (outcome != null or abandon) break;
            setup.harness.world.run_for_ns(prng.range(100_000, 10 * ms));
        }
        // A call that keeps polling always gets an outcome: no result is lost.
        if (!abandon) assert(outcome != null);
        if (outcome) |value| {
            finished += 1;
            hasher.update(std.mem.asBytes(&value));
        }
    }
    try testing.expect(finished > 0);
    try testing.expect(setup.client.requests_started >= finished);
    hasher.update(std.mem.asBytes(&setup.client.results_discarded));
    return hasher.final();
}

test "polling client: seeded fuzz keeps results matched and replays identically" {
    var seed_prng = Prng.init(0x9011);
    for (0..4) |_| {
        const seed = seed_prng.int(u64);
        _ = try fuzz_run(seed);
    }
    try testing.expectEqual(try fuzz_run(0x51), try fuzz_run(0x51));
}

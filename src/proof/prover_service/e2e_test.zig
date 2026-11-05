//! End-to-end over the simulated network: the prover service on one node; the proposer's
//! requester and two workers with fake TEE backends on another. Covers a proof through the
//! proposer's `Prover`, a worker that stops heartbeating (its lease expires and the other
//! worker reclaims the job), the stale worker learning it lost the job, an idempotent
//! re-request, and deletion.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const interfaces = @import("../proposer/interfaces.zig");
const protocol = @import("protocol.zig");
const store_module = @import("store.zig");
const service_module = @import("service.zig");
const client_module = @import("client.zig");
const worker_module = @import("worker.zig");

const Service = service_module.Service;
const Clock = service_module.Clock;
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Client = client_module.Client(io.SimIo);
const Worker = worker_module.Worker(io.SimIo);
const HttpServer = http.Server(io.SimIo, *Service, Service.handle_http);

/// A TEE backend that answers after `polls_needed` polls with a proposal for the claim.
const FakeBackend = struct {
    polls_needed: u32,
    polls: u32 = 0,
    running: bool = false,
    cancelled: u32 = 0,
    request: protocol.PrimitiveProofRequest = undefined,
    roots: [1]protocol.Hash = undefined,
    signature: [65]u8 = @splat(0x5a),

    fn backend(fake: *FakeBackend) worker_module.Backend {
        return .{ .context = fake, .vtable = &.{ .start = start, .poll = poll, .cancel = cancel } };
    }

    fn of(context: *anyopaque) *FakeBackend {
        return @ptrCast(@alignCast(context));
    }

    fn start(context: *anyopaque, job: *const protocol.ProofJob) worker_module.BackendError!void {
        const fake = of(context);
        if (job.request.request != .tee) return error.Unsupported;
        fake.request = job.request.request.tee.proof;
        fake.polls = 0;
        fake.running = true;
    }

    fn poll(context: *anyopaque) worker_module.BackendError!?protocol.ProofResult {
        const fake = of(context);
        assert(fake.running);
        fake.polls += 1;
        if (fake.polls < fake.polls_needed) return null;
        fake.running = false;
        const request = &fake.request;
        fake.roots = .{request.claimed_l2_output_root};
        fake.signature[64] = 1;
        return .{ .tee = .{
            .aggregate_proposal = .{
                .output_root = request.claimed_l2_output_root,
                .signature = &fake.signature,
                .l1_origin_hash = request.l1_head,
                .l1_origin_number = request.l1_head_number,
                .l2_block_number = request.claimed_l2_block_number,
                .prev_output_root = request.agreed_l2_output_root,
                .config_hash = @splat(0xc0),
            },
            .intermediate_roots = &fake.roots,
            .tee_kind = .aws_nitro,
            .tee_signer = @splat(0x11),
        } };
    }

    fn cancel(context: *anyopaque) void {
        const fake = of(context);
        fake.running = false;
        fake.cancelled += 1;
    }
};

const Node = struct {
    rpc: Endpoint.Client,
    endpoint: Endpoint,
    client: Client,
};

const Harness = struct {
    world: io.SimWorld,
    server_io: io.SimIo,
    client_io: io.SimIo,
    store: store_module.Store,
    service: Service,
    server: HttpServer,
    nodes: [3]Node,

    fn create() !*Harness {
        const allocator = testing.allocator;
        const harness = try allocator.create(Harness);
        errdefer allocator.destroy(harness);
        harness.world = try io.SimWorld.init(allocator, .{ .seed = 0x9e57 });
        errdefer harness.world.deinit();
        try io.SimIo.init(&harness.server_io, allocator, &harness.world, .{
            .host = io.Address.ip4(.{ 10, 0, 0, 1 }, 0),
        });
        errdefer harness.server_io.deinit();
        try io.SimIo.init(&harness.client_io, allocator, &harness.world, .{
            .host = io.Address.ip4(.{ 10, 0, 0, 2 }, 0),
        });
        errdefer harness.client_io.deinit();
        const store_config: store_module.Config = .{
            .jobs_max = 8,
            .proof_bytes_max = 4096,
            .seed = 7,
        };
        harness.store = try .init(allocator, store_config);
        errdefer harness.store.deinit(allocator);
        const clock = Clock.of(io.SimIo, &harness.server_io);
        const service_options: service_module.Options = .{ .request_arena_bytes = 64 << 10 };
        harness.service = try .init(allocator, &harness.store, clock, service_options);
        errdefer harness.service.deinit(allocator);
        try harness.server.init(allocator, &harness.server_io, &harness.service, .{
            .connections_max = 4,
            .recv_buffer_size = 32 * 1024,
            .send_buffer_size = 32 * 1024,
            .limits = .{ .head_size_max = 2048, .body_size_max = 16 * 1024 },
        });
        errdefer harness.server.deinit();
        const bound = try harness.server.listen(io.Address.ip4(.{ 10, 0, 0, 1 }, 8545));
        for (&harness.nodes) |*node| try harness.connect(node, bound);
        return harness;
    }

    fn connect(harness: *Harness, node: *Node, address: io.Address) !void {
        const allocator = testing.allocator;
        node.rpc = try .init(allocator, &harness.client_io, address, .{
            .send_buffer_size = 32 * 1024,
            .recv_buffer_size = 64 * 1024,
            .limits = .{ .head_size_max = 2048, .body_size_max = 32 * 1024 },
        }, 16 * 1024);
        node.endpoint = .init(allocator, &node.rpc, .{ .context = harness, .step = step }, 10_000);
        node.client = try .init(allocator, &node.endpoint, .{
            .request_bytes_max = 8 * 1024,
            .response_arena_bytes = 64 * 1024,
        });
    }

    fn destroy(harness: *Harness) void {
        const allocator = testing.allocator;
        for (&harness.nodes) |*node| {
            node.client.deinit(allocator);
            node.endpoint.deinit();
            node.rpc.deinit();
        }
        harness.server.stop();
        var rounds: u32 = 0;
        while (!harness.server.stopped() and rounds < 10_000) : (rounds += 1) {
            harness.world.run_for_ns(std.time.ns_per_ms);
        }
        harness.server.deinit();
        harness.service.deinit(allocator);
        harness.store.deinit(allocator);
        harness.client_io.deinit();
        harness.server_io.deinit();
        harness.world.deinit();
        allocator.destroy(harness);
    }

    fn step(context: *anyopaque) anyerror!void {
        const harness: *Harness = @ptrCast(@alignCast(context));
        harness.world.run_for_ns(std.time.ns_per_ms);
    }

    fn advance(harness: *Harness, duration_ns: u64) void {
        harness.world.run_for_ns(duration_ns);
    }
};

fn worker_config(name: []const u8) worker_module.Config {
    return .{
        .worker_id = .from(name),
        .proof_type = .tee,
        .tee_kinds = &.{.aws_nitro},
        .lock_duration_seconds = 10,
        .poll_interval_ns = std.time.ns_per_s,
        .heartbeat_interval_ns = 2 * std.time.ns_per_s,
    };
}

const proof_request: interfaces.ProofRequest = .{
    .l1_head = .{ .number = 40, .hash = @splat(0x40) },
    .agreed_l2_head_hash = @splat(0x0a),
    .agreed_l2_output_root = @splat(0x0b),
    .agreed_l2_block_number = 100,
    .claimed_l2_output_root = @splat(0x0c),
    .claimed_l2_block_number = 110,
    .intermediate_block_interval = 10,
    .proposer = @splat(0x0d),
};

test "prover service e2e: proof via the proposer prover, lease expiry, idempotent request" {
    const harness = try Harness.create();
    defer harness.destroy();
    var adapter: client_module.ProposerProver(io.SimIo) = .{ .client = &harness.nodes[0].client };
    const prover = adapter.prover();
    const session = proof_request.claimed_l2_output_root;
    try testing.expectError(error.NotFound, prover.poll(session));
    try prover.request(&proof_request);
    try testing.expectEqual(@as(u32, 1), harness.store.count());
    try testing.expect(try prover.poll(session) == .pending);

    const clock = Clock.of(io.SimIo, &harness.client_io);
    var stuck: FakeBackend = .{ .polls_needed = std.math.maxInt(u32) };
    var quick: FakeBackend = .{ .polls_needed = 2 };
    const client_a = &harness.nodes[1].client;
    const client_b = &harness.nodes[2].client;
    var worker_a: Worker = .init(client_a, stuck.backend(), clock, worker_config("a"));
    var worker_b: Worker = .init(client_b, quick.backend(), clock, worker_config("b"));
    worker_a.tick();
    try testing.expectEqual(worker_module.State.proving, worker_a.state);
    // Worker A heartbeats through 20 s, twice its 10 s lease; B finds nothing to claim.
    for (0..20) |_| {
        harness.advance(std.time.ns_per_s);
        worker_a.tick();
        worker_b.tick();
    }
    try testing.expectEqual(worker_module.State.proving, worker_a.state);
    try testing.expect(worker_a.stats.heartbeats >= 8);
    try testing.expectEqual(@as(u64, 0), worker_b.stats.claimed);
    // Worker A stops (crashed): its lease expires and B reclaims and proves the job.
    var ticks: u32 = 0;
    while (worker_b.stats.submitted == 0 and ticks < 40) : (ticks += 1) {
        harness.advance(std.time.ns_per_s);
        worker_b.tick();
    }
    try testing.expectEqual(@as(u64, 1), worker_b.stats.submitted);
    const session_id = protocol.tee_session_id_for_root(session);
    try testing.expectEqual(@as(u32, 2), harness.store.get(session_id.slice()).?.attempt);
    const status = try prover.poll(session);
    const proof = status.succeeded;
    try testing.expectEqual(proof_request.claimed_l2_output_root, proof.output_root);
    try testing.expectEqual(@as(usize, 1), proof.intermediate_roots.len);
    try testing.expectEqual(@as(usize, 130), proof.init_data.len);
    try testing.expectEqual(@as(u8, 0x40), proof.init_data[1]);
    try testing.expectEqual(@as(u8, 28), proof.init_data[129]);
    // Worker A comes back: its heartbeat is rejected and it drops the job.
    worker_a.tick();
    try testing.expectEqual(worker_module.State.idle, worker_a.state);
    try testing.expectEqual(@as(u64, 1), worker_a.stats.lost);
    try testing.expectEqual(@as(u32, 1), stuck.cancelled);
    // An idempotent re-request adds no job and keeps the result.
    try prover.request(&proof_request);
    try testing.expectEqual(@as(u32, 1), harness.store.count());
    try testing.expect(try prover.poll(session) == .succeeded);
    try prover.delete(session);
    try testing.expectError(error.NotFound, prover.poll(session));
    try testing.expectEqual(@as(u32, 0), harness.store.count());
}

test "prover service e2e: worker abandons an unsupported job and lists over the client" {
    const harness = try Harness.create();
    defer harness.destroy();
    const client = &harness.nodes[0].client;
    const request: protocol.ProveBlockRangeRequest = .{ .proof = .{
        .session_id = .from("range-1"),
        .request = .{ .compressed = .{
            .start_block_number = 0,
            .number_of_blocks_to_prove = 4,
            .intermediate_block_interval = 2,
            .zk_vm = .sp1,
        } },
    } };
    const created = try client.prove_block_range(&request);
    try testing.expectEqualStrings("range-1", created.session_id.slice());
    var fake: FakeBackend = .{ .polls_needed = 1 };
    var config = worker_config("zk");
    config.proof_type = .compressed;
    config.zk_vms = &.{.sp1};
    const clock = Clock.of(io.SimIo, &harness.client_io);
    var worker: Worker = .init(&harness.nodes[1].client, fake.backend(), clock, config);
    worker.tick();
    try testing.expectEqual(worker_module.State.abandoning, worker.state);
    worker.tick();
    try testing.expectEqual(@as(u64, 1), worker.stats.abandoned);
    const listed = try client.list_proofs(&.{ .offset = 0, .limit = 10 });
    try testing.expectEqual(@as(u64, 1), listed.total_count);
    try testing.expectEqual(protocol.ProofStatus.queued, listed.proofs[0].status);
    const abandoned = harness.store.get("range-1").?.error_message.slice();
    try testing.expectEqualStrings("worker backend does not support this proof request", abandoned);
    try client.cancel_proof_request(&.{ .session_id = .from("range-1") });
    try testing.expectError(error.Rejected, client.prove_block_range(&request));
    try testing.expectEqual(protocol.code.failed_precondition, client.last_code);
}

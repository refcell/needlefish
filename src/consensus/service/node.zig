//! The consensus node service (base/base `crates/consensus/service`): owns the L1 head
//! watcher, the L2 chain provider over the authenticated engine endpoint, and the
//! `optimism_*` JSON-RPC server, and is driven by `tick` from the binary's event loop.
//!
//! This first stage tracks heads: L1 latest/safe/finalized from the watcher and the engine's
//! labeled L2 heads (latest/safe/finalized) through the L2 provider, served as
//! `optimism_syncStatus` (the batcher's input). Startup forkchoice discovery, derivation
//! and the engine task queue plug into `tick` as they land (see docs/lanes/consensus.md).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const http = @import("../../utilities/http/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const log = @import("../../utilities/log/root.zig");
const protocol = @import("../protocol/root.zig");
const rollup_rpc = @import("../rpc/rollup.zig");
const safedb = @import("../safedb/root.zig");
const l2_provider = @import("../sources/l2_provider.zig");
const l1_watcher = @import("l1_watcher.zig");

const Address = http_client.Address;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SyncStatus = rollup_rpc.SyncStatus;

pub const Options = struct {
    l1: Address,
    l2: Address,
    jwt_secret: jwt.Secret,
    rpc_address: Address,
    sequencer: bool = false,
    version: []const u8 = "needlefish",
    /// How often the engine's labeled L2 heads are re-read.
    head_poll_interval_ns: u64 = std.time.ns_per_s,
    safedb_entries: u32 = 4096,
    http_client: http_client.Options = .{},
    rpc_server: http.server.Options = .{
        .connections_max = 16,
        .recv_buffer_size = 64 * 1024,
        .send_buffer_size = 64 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 48 * 1024 },
    },
};

pub fn Node(comptime IO: type) type {
    return struct {
        const Self = @This();
        const RpcServer = http.Server(IO, *Self, handle_rpc);
        const backend_vtable: rollup_rpc.Backend.VTable = .{
            .sync_status = backend_sync_status,
            .output_at_block = backend_output_at_block,
            .safe_db = backend_safe_db,
        };

        allocator: Allocator,
        io: *IO,
        logger: *log.Logger,
        rollup: *const RollupConfig,
        options: Options,
        watcher: l1_watcher.L1Watcher(IO),
        l2: l2_provider.L2Provider(IO),
        rpc_server: RpcServer,
        backend: rollup_rpc.Backend,
        safe_db: safedb.SafeDB,
        status: SyncStatus = .{},

        /// Builds the node in place; `node` must not move afterwards.
        pub fn init(
            node: *Self,
            allocator: Allocator,
            io: *IO,
            logger: *log.Logger,
            rollup: *const RollupConfig,
            options: Options,
        ) !void {
            assert(rollup.block_time > 0);
            assert(options.head_poll_interval_ns > 0);
            node.* = .{
                .allocator = allocator,
                .io = io,
                .logger = logger,
                .rollup = rollup,
                .options = options,
                .watcher = undefined,
                .l2 = undefined,
                .rpc_server = undefined,
                .backend = .{
                    .context = node,
                    .vtable = &backend_vtable,
                    .version = options.version,
                    .rollup = rollup,
                },
                .safe_db = try safedb.SafeDB.init(allocator, options.safedb_entries),
            };
            errdefer node.safe_db.deinit(allocator);
            try node.watcher.init(allocator, io, options.l1, options.http_client, .{});
            errdefer node.watcher.deinit();
            try node.l2.init(allocator, io, options.l2, options.http_client, rollup, .{
                .jwt_secret = options.jwt_secret,
                .block_by_number_ttl_ns = options.head_poll_interval_ns,
            });
            errdefer node.l2.deinit();
            try node.rpc_server.init(allocator, io, node, options.rpc_server);
        }

        /// Frees everything. The IO must not run afterwards (in-flight operations would
        /// complete into freed memory); the binary tears both down together.
        pub fn deinit(node: *Self) void {
            node.rpc_server.deinit();
            node.l2.deinit();
            node.watcher.deinit();
            node.safe_db.deinit(node.allocator);
            node.* = undefined;
        }

        /// Starts serving RPC; returns the bound address.
        pub fn start(node: *Self) !Address {
            const address = try node.rpc_server.listen(node.options.rpc_address);
            node.logger.log(.info, "consensus", "rpc listening", .{ .port = address.port });
            assert(address.family == node.options.rpc_address.family);
            return address;
        }

        /// One step of the node's state machines; call every few milliseconds.
        pub fn tick(node: *Self) void {
            node.watcher.tick();
            node.l2.tick();
            node.refresh_l2_heads();
            assert(node.status.finalized_l2.block_info.number <=
                node.status.unsafe_l2.block_info.number or
                node.status.unsafe_l2.block_info.hash.is_zero());
        }

        /// Re-reads the engine's labeled heads (the provider refetches after its TTL).
        fn refresh_l2_heads(node: *Self) void {
            const labels = [_]l2_provider.Label{ .latest, .safe, .finalized };
            var heads: [labels.len]?protocol.block.L2BlockInfo = @splat(null);
            for (labels, 0..) |label, index| {
                heads[index] = node.l2.l2_block_info_by_label(label) catch null;
            }
            // Apply only a consistent snapshot so finalized <= safe <= unsafe holds.
            const unsafe_head = heads[0] orelse return;
            const safe_head = heads[1] orelse node.status.safe_l2;
            const finalized_head = heads[2] orelse node.status.finalized_l2;
            const unsafe_number = unsafe_head.block_info.number;
            if (safe_head.block_info.number > unsafe_number) return;
            if (finalized_head.block_info.number > safe_head.block_info.number) return;
            node.status.unsafe_l2 = unsafe_head;
            node.status.safe_l2 = safe_head;
            node.status.local_safe_l2 = safe_head;
            node.status.finalized_l2 = finalized_head;
        }

        pub fn sync_status(node: *const Self) SyncStatus {
            var status = node.status;
            const watcher = &node.watcher;
            if (watcher.head(.latest)) |head| status.head_l1 = head;
            if (watcher.head(.safe)) |head| status.safe_l1 = head;
            if (watcher.head(.finalized)) |head| status.finalized_l1 = head;
            assert(status.unsafe_l2.block_info.number >= status.safe_l2.block_info.number or
                status.unsafe_l2.block_info.hash.is_zero());
            return status;
        }

        fn handle_rpc(
            node: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (request.method != .POST) return response.fail(405);
            const out = response.writer();
            const outcome = rollup_rpc.Router.handle(&node.backend, request.body, out);
            if (outcome == .empty) response.status = 204;
        }

        fn from_context(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn backend_sync_status(context: *anyopaque) SyncStatus {
            return from_context(context).sync_status();
        }

        fn backend_output_at_block(
            context: *anyopaque,
            tag: rollup_rpc.BlockTag,
        ) error{ NotAvailable, NotFound }!rollup_rpc.OutputAtBlock {
            _ = from_context(context);
            _ = tag;
            return error.NotAvailable; // Needs `eth_getProof` of the message passer.
        }

        fn backend_safe_db(context: *anyopaque) ?*const safedb.SafeDB {
            return &from_context(context).safe_db;
        }
    };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const sim = @import("../../utilities/io/root.zig");
const harness_module = @import("../sources/sim_harness.zig");
const fixtures = @import("../sources/fixtures.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const TestNode = Node(sim.SimIo);

test "node: tracks L1 and engine heads and serves optimism_syncStatus" {
    var block_text: [4096]u8 = undefined;
    var hash: [32]u8 = undefined;
    const block = try fixtures.l2_block_json(&block_text, 7, &hash);
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "latest", .result = block });
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "safe", .result = block });
    var harness: Harness = undefined;
    try harness.init(&fake, 0x4e);
    defer harness.deinit();
    var rollup: RollupConfig = .{ .block_time = 2 };
    rollup.upgrades.set(.holocene, 0);
    var log_buffer: [4096]u8 = undefined;
    var memory: log.MemorySink = .{ .buffer = &log_buffer };
    var logger: log.Logger = .{ .sink = memory.sink() };
    const node = try testing.allocator.create(TestNode);
    defer testing.allocator.destroy(node);
    try node.init(testing.allocator, &harness.client_io, &logger, &rollup, .{
        .l1 = harness.address,
        .l2 = harness.address,
        .jwt_secret = .{ .bytes = @splat(7) },
        .rpc_address = sim.Address.ip4(.{ 10, 0, 0, 2 }, 7545),
        .http_client = harness_module.client_options,
    });
    defer node.deinit();
    for (0..40) |_| {
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    const status = node.sync_status();
    try testing.expectEqual(@as(u64, 7), status.unsafe_l2.block_info.number);
    try testing.expectEqualSlices(u8, &hash, &status.safe_l2.block_info.hash.bytes);
    try testing.expectEqual(@as(u64, 507), status.safe_l2.l1_origin.number);
    try testing.expectEqual(@as(u64, 7), status.head_l1.number);
    try testing.expectEqual(@as(u64, 0), status.finalized_l2.block_info.number);
    var buffer: [8192]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    _ = rollup_rpc.Router.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_syncStatus"}
    , &out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "\"unsafe_l2\":{\"hash\"") != null);
    while (node.watcher.busy() or node.l2.busy()) {
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
}

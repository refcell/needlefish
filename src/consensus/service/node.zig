//! The consensus node service (base/base `crates/consensus/service`): owns the L1 head
//! watcher, the L2 chain provider over the authenticated engine endpoint, and the
//! `optimism_*` JSON-RPC server, and is driven by `tick` from the binary's event loop.
//!
//! Each tick drives the providers (L1 JSON-RPC, beacon blobs, L2 over the engine endpoint,
//! the polling engine client) and then the `Driver` (startup forkchoice, derivation,
//! engine tasks, finalization, sequencing). Sync status comes from the driver's heads,
//! the pipeline origin, and the watcher's L1 heads.

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
const driver_module = @import("driver.zig");
const l1_provider = @import("../sources/l1_provider.zig");
const blob_provider = @import("../sources/blob_provider.zig");
const engine_client = @import("../sources/engine_client.zig");
const polling_client = @import("../engine/polling_client.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const derive_errors = @import("../derive/errors.zig");
const blob_module = @import("../derive/blob.zig");

const ProviderError = derive_errors.ProviderError;
const BlockInfo = protocol.block.BlockInfo;
const Hash = protocol.block.Hash;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;

const Address = http_client.Address;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SyncStatus = rollup_rpc.SyncStatus;
const L2BlockInfo = protocol.block.L2BlockInfo;
const SystemConfig = protocol.system_config.SystemConfig;
const SafeBlock = protocol.span_batch.SafeBlock;

pub const Options = struct {
    l1: Address,
    /// Beacon API for blobs; without it blob batches are unavailable.
    l1_beacon: ?Address = null,
    l2: Address,
    jwt_secret: jwt.Secret,
    rpc_address: Address,
    sequencer: bool = false,
    version: []const u8 = "needlefish",
    /// How often the engine's labeled L2 heads are re-read.
    head_poll_interval_ns: u64 = std.time.ns_per_s,
    safedb_entries: u32 = 4096,
    http_client: http_client.Options = .{},
    /// Engine API: an 8 MiB `newPayload` request, up to 16 MiB `getPayload` responses.
    engine_http_client: http_client.Options = .{
        .send_buffer_size = 8 * 1024 * 1024 + 64 * 1024,
        .recv_buffer_size = 16 * 1024 * 1024 + 8 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 16 * 1024 * 1024 },
    },
    /// Blob sidecars: up to 128 blobs of 128 KiB, hex encoded.
    beacon_http_client: http_client.Options = .{
        .recv_buffer_size = 40 * 1024 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 40 * 1024 * 1024 - 8 * 1024 },
    },
    driver: driver_module.Options = .{},
    rpc_server: http.server.Options = .{
        .connections_max = 16,
        .recv_buffer_size = 64 * 1024,
        .send_buffer_size = 64 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 48 * 1024 },
    },
};

/// The L2 safe chain view the driver needs on top of the L2 provider. Full safe blocks
/// (span batches overlapping the safe chain) are not fetched yet, so those checks stay
/// undecided (`NotAvailable`) until the full-block fetch lands in the L2 provider.
pub fn L2View(comptime IO: type) type {
    return struct {
        provider: *l2_provider.L2Provider(IO),

        const Self = @This();

        pub fn l2_block_info_by_number(view: *Self, number: u64) ProviderError!L2BlockInfo {
            return view.provider.l2_block_info_by_number(number);
        }

        pub fn l2_block_info_by_hash(view: *Self, hash: Hash) ProviderError!L2BlockInfo {
            return view.provider.l2_block_info_by_hash(hash);
        }

        pub fn l2_block_info_by_label(
            view: *Self,
            label: l2_provider.Label,
        ) ProviderError!L2BlockInfo {
            return view.provider.l2_block_info_by_label(label);
        }

        pub fn system_config_by_l2_hash(view: *Self, hash: Hash) ProviderError!SystemConfig {
            return view.provider.system_config_by_l2_hash(hash);
        }

        pub fn l2_block_by_number(view: *Self, number: u64) ProviderError!SafeBlock {
            _ = view;
            _ = number;
            return error.NotAvailable;
        }
    };
}

/// Blob access; without a beacon endpoint every blob fetch fails as unavailable.
pub fn BlobView(comptime IO: type) type {
    return struct {
        provider: ?*blob_provider.BlobProvider(IO, blob_provider.KzgVerifier),

        const Self = @This();

        pub fn blobs(
            view: *Self,
            block: BlockInfo,
            hashes: []const Hash,
        ) ProviderError![]const *const blob_module.Blob {
            const provider = view.provider orelse return error.BlobsUnavailable;
            return provider.blobs(block, hashes);
        }
    };
}

pub fn Node(comptime IO: type) type {
    return struct {
        const Self = @This();
        const RpcServer = http.Server(IO, *Self, handle_rpc);
        const Blobs = blob_provider.BlobProvider(IO, blob_provider.KzgVerifier);
        const Engine = engine_client.EngineClient(IO);
        const Polling = polling_client.PollingClient(IO);
        const backend_vtable: rollup_rpc.Backend.VTable = .{
            .sync_status = backend_sync_status,
            .output_at_block = backend_output_at_block,
            .safe_db = backend_safe_db,
        };

        pub const Providers = struct {
            l1: *l1_provider.L1Provider(IO),
            blobs: *BlobView(IO),
            l2: *L2View(IO),
            engine: *Polling,
            l1_head: ?BlockInfo,
            l1_finalized: ?BlockInfo,
        };

        allocator: Allocator,
        io: *IO,
        logger: *log.Logger,
        rollup: *const RollupConfig,
        options: Options,
        watcher: l1_watcher.L1Watcher(IO),
        l1: l1_provider.L1Provider(IO),
        l2: l2_provider.L2Provider(IO),
        l2_view: L2View(IO),
        blobs: ?*Blobs = null,
        blob_view: BlobView(IO),
        kzg_storage: ?*kzg.blob.Settings.Storage = null,
        kzg_settings: kzg.blob.Settings = undefined,
        kzg_workspace: ?*kzg.blob.Workspace = null,
        engine: Engine,
        polling: Polling,
        blob_schedule: L1BlobSchedule = .{},
        driver: driver_module.Driver,
        rpc_server: RpcServer,
        backend: rollup_rpc.Backend,
        safe_db: safedb.SafeDB,
        logged_phase: driver_module.Phase = .starting,
        logged_safe_number: u64 = 0,
        logged_unsafe_number: u64 = 0,

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
                .l1 = undefined,
                .l2 = undefined,
                .l2_view = .{ .provider = &node.l2 },
                .blob_view = .{ .provider = null },
                .engine = undefined,
                .polling = undefined,
                .driver = undefined,
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
            try node.init_sources();
            errdefer node.deinit_sources();
            try node.driver.init(
                allocator,
                rollup,
                &node.blob_schedule,
                &node.safe_db,
                options.driver,
            );
            errdefer node.driver.deinit();
            try node.rpc_server.init(allocator, io, node, options.rpc_server);
        }

        fn init_sources(node: *Self) !void {
            const allocator = node.allocator;
            const options = node.options;
            const io = node.io;
            try node.watcher.init(allocator, io, options.l1, options.http_client, .{});
            errdefer node.watcher.deinit();
            try node.l1.init(allocator, io, options.l1, options.http_client, .{
                .batch_inbox = node.rollup.batch_inbox_address,
            });
            errdefer node.l1.deinit();
            try node.l2.init(allocator, io, options.l2, options.http_client, node.rollup, .{
                .jwt_secret = options.jwt_secret,
                .block_by_number_ttl_ns = options.head_poll_interval_ns,
            });
            errdefer node.l2.deinit();
            try node.engine.init(
                allocator,
                io,
                options.l2,
                options.engine_http_client,
                options.jwt_secret,
                .{ .genesis = node.rollup.genesis },
            );
            errdefer node.engine.deinit();
            node.polling = Polling.init(&node.engine);
            if (options.l1_beacon) |beacon| try node.init_blobs(beacon);
            assert(node.l2_view.provider == &node.l2);
        }

        fn init_blobs(node: *Self, beacon: Address) !void {
            const allocator = node.allocator;
            const storage = try allocator.create(kzg.blob.Settings.Storage);
            errdefer allocator.destroy(storage);
            const workspace = try allocator.create(kzg.blob.Workspace);
            errdefer allocator.destroy(workspace);
            node.kzg_settings = try kzg.blob.Settings.init(storage);
            const blobs = try allocator.create(Blobs);
            errdefer allocator.destroy(blobs);
            const verifier: blob_provider.KzgVerifier = .{
                .settings = &node.kzg_settings,
                .workspace = workspace,
            };
            const http_options = node.options.beacon_http_client;
            try blobs.init(allocator, node.io, beacon, http_options, verifier, .{});
            node.kzg_storage = storage;
            node.kzg_workspace = workspace;
            node.blobs = blobs;
            node.blob_view.provider = blobs;
        }

        fn deinit_sources(node: *Self) void {
            const allocator = node.allocator;
            if (node.blobs) |blobs| {
                blobs.deinit();
                allocator.destroy(blobs);
            }
            if (node.kzg_workspace) |workspace| allocator.destroy(workspace);
            if (node.kzg_storage) |storage| allocator.destroy(storage);
            node.engine.deinit();
            node.l2.deinit();
            node.l1.deinit();
            node.watcher.deinit();
        }

        /// Frees everything. The IO must not run afterwards (in-flight operations would
        /// complete into freed memory); the binary tears both down together.
        pub fn deinit(node: *Self) void {
            node.rpc_server.deinit();
            node.driver.deinit();
            node.deinit_sources();
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

        pub fn providers(node: *Self) Providers {
            return .{
                .l1 = &node.l1,
                .blobs = &node.blob_view,
                .l2 = &node.l2_view,
                .engine = &node.polling,
                .l1_head = node.watcher.head(.latest),
                .l1_finalized = node.watcher.head(.finalized),
            };
        }

        /// Whether any HTTP request is still in flight (drain before `deinit`).
        pub fn busy(node: *const Self) bool {
            const blobs_busy = if (node.blobs) |blobs| blobs.busy() else false;
            return node.watcher.busy() or node.l1.busy() or node.l2.busy() or
                node.engine.busy() or blobs_busy;
        }

        /// One step of the node's state machines; call every few milliseconds.
        pub fn tick(node: *Self) void {
            node.watcher.tick();
            node.l1.tick();
            node.l2.tick();
            node.polling.tick();
            if (node.blobs) |blobs| blobs.tick();
            const now_s = node.io.now_realtime_ns() / std.time.ns_per_s;
            node.driver.tick(node.providers(), now_s);
            node.log_progress();
            assert(node.driver.sync_state().is_ordered());
        }

        fn log_progress(node: *Self) void {
            const state = node.driver.sync_state();
            if (node.driver.phase != node.logged_phase) {
                node.logged_phase = node.driver.phase;
                node.logger.log(.info, "consensus", "driver phase", .{
                    .phase = @tagName(node.driver.phase),
                    .unsafe = state.unsafe_head.block_info.number,
                    .safe = state.safe_head.block_info.number,
                });
            }
            const unsafe_head = state.unsafe_head;
            if (unsafe_head.block_info.number != node.logged_unsafe_number) {
                node.logged_unsafe_number = unsafe_head.block_info.number;
                node.logger.log(.info, "consensus", "unsafe head", .{
                    .number = unsafe_head.block_info.number,
                    .l1_origin = unsafe_head.l1_origin.number,
                    .sealed = node.driver.stats.sealed,
                });
            }
            const safe_number = state.safe_head.block_info.number;
            if (safe_number != node.logged_safe_number) {
                node.logged_safe_number = safe_number;
                node.logger.log(.info, "consensus", "safe head", .{
                    .number = safe_number,
                    .unsafe = state.unsafe_head.block_info.number,
                    .finalized = state.finalized_head.block_info.number,
                });
            }
        }

        pub fn sync_status(node: *const Self) SyncStatus {
            const state = node.driver.sync_state();
            var status: SyncStatus = .{
                .unsafe_l2 = state.unsafe_head,
                .local_safe_l2 = state.local_safe_head,
                .safe_l2 = state.safe_head,
                .finalized_l2 = state.finalized_head,
            };
            if (node.driver.pipeline.origin()) |origin| status.current_l1 = origin;
            const watcher = &node.watcher;
            if (watcher.head(.latest)) |head| status.head_l1 = head;
            if (watcher.head(.safe)) |head| status.safe_l1 = head;
            if (watcher.head(.finalized)) |head| status.finalized_l1 = head;
            status.current_l1_finalized = status.finalized_l1;
            assert(status.unsafe_l2.block_info.number >= status.safe_l2.block_info.number);
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

test "node: runs the driver, tracks L1 heads, and serves optimism_syncStatus" {
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
    try testing.expectEqual(@as(u64, 7), status.head_l1.number);
    try testing.expectEqualSlices(u8, &hash, &status.head_l1.hash.bytes);
    // The fake chain's L1 origin (507) does not exist, so startup discovery keeps retrying.
    try testing.expectEqual(driver_module.Phase.starting, node.driver.phase);
    try testing.expectEqual(@as(u64, 0), status.unsafe_l2.block_info.number);
    var buffer: [8192]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    _ = rollup_rpc.Router.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_syncStatus"}
    , &out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "\"unsafe_l2\":{\"hash\"") != null);
    while (node.busy()) {
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
}

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
const admin_rpc = @import("../rpc/admin.zig");
const safedb = @import("../safedb/root.zig");
const l2_provider = @import("../sources/l2_provider.zig");
const l2_block = @import("../sources/l2_block.zig");
const message_passer_roots = @import("../sources/message_passer_roots.zig");
const l1_watcher = @import("l1_watcher.zig");
const driver_module = @import("driver.zig");
const l1_provider = @import("../sources/l1_provider.zig");
const blob_provider = @import("../sources/blob_provider.zig");
const engine_client = @import("../sources/engine_client.zig");
const polling_client = @import("../engine/polling_client.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const derive_errors = @import("../derive/errors.zig");
const blob_module = @import("../derive/blob.zig");
const p2p_network = @import("../p2p/network.zig");
const p2p_rpc = @import("../p2p/rpc.zig");
/// `optimism_*`, `admin_*`, and (with p2p on) `opp2p_*` from one router.
const RpcRouter = p2p_rpc.Merged(*const rollup_rpc.Backend, &rollup_rpc.node_methods);
const RpcOutcome = @import("../../utilities/rpc/root.zig").Outcome;
const p2p_options = @import("../p2p/options.zig");
const secp256k1 = @import("../p2p/peers/secp256k1.zig");
const enr = @import("../p2p/peers/enr.zig");
const snappy = @import("../p2p/gossip/snappy.zig");
const primitives = @import("../../common/primitives/root.zig");
const gossip_bridge = @import("gossip_bridge.zig");
const engine_json = @import("../sources/engine_json.zig");
const signer_watcher = @import("signer_watcher.zig");
const checkpoint = @import("checkpoint.zig");
const metrics_module = @import("metrics.zig");
const follow = @import("follow.zig");
const conductor_module = @import("conductor.zig");
const ws_rpc_module = @import("ws_rpc.zig");
const upgrade_signal = @import("../../utilities/upgrade_signal/root.zig");
const base_rpc = @import("../rpc/base.zig");

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

/// Unsafe-block gossip (base/base `NetworkActor`): received blocks go to the driver, and a
/// sequencer publishes every block it seals.
pub const P2p = struct {
    options: p2p_options.Options,
    node_secret: secp256k1.SecretKey,
    unsafe_block_signer: primitives.Address,
    /// Signs published blocks; null on verifiers.
    sequencer_key: ?[32]u8 = null,
    /// Seeds connection keys and the service's randomness; from OS entropy in production.
    seed: u64,
};

/// The L1 `ProtocolVersions` upgrade-signal contract (base/base `--upgrade-signal.*`): the
/// node observes its schedule (metrics-only mode) and serves `base_upgradeReadiness`.
pub const UpgradeSignal = struct {
    contract: [20]u8,
    block_tag: upgrade_signal.BlockTag = .finalized,
};

/// Gossiped blocks handed to the driver per tick.
const gossip_blocks_per_tick: u32 = 8;

pub const Options = struct {
    p2p: ?P2p = null,
    upgrade_signal: ?UpgradeSignal = null,
    /// Durable safe/finalized checkpoints (`--checkpoint.path`); none when null.
    checkpoint_path: ?[]const u8 = null,
    l1: Address,
    /// Beacon API for blobs; without it blob batches are unavailable.
    l1_beacon: ?Address = null,
    l2: Address,
    jwt_secret: jwt.Secret,
    rpc_address: Address,
    /// Follow mode (`--source-l2-rpc`): insert blocks from this source node's execution RPC
    /// instead of deriving them.
    follow_source: ?Address = null,
    /// Sequencer conductor (`--conductor.rpc`): commits sealed payloads, gates starting.
    conductor: ?Address = null,
    /// Serve `admin_*` (`--rpc.enable-admin`); base/base leaves them off by default.
    rpc_admin: bool = false,
    /// Serve `dev_*` (`--rpc.dev-enabled`), including the engine queue subscription.
    rpc_dev: bool = false,
    /// WebSocket JSON-RPC with head subscriptions (`--rpc.ws-enabled`); off when null.
    ws_address: ?Address = null,
    /// Prometheus `GET /metrics` (`--metrics.enabled`); not served when null.
    metrics_address: ?Address = null,
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
        // Room for an `admin_postUnsafePayload` envelope of up to 1 MiB.
        .recv_buffer_size = 1024 * 1024 + 16 * 1024,
        .send_buffer_size = 64 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 * 1024 },
    },
    metrics_server: http.server.Options = .{
        .connections_max = 4,
        .recv_buffer_size = 16 * 1024,
        .send_buffer_size = 32 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 4 * 1024 },
    },
};

/// The L2 safe chain view the driver needs, over the L2 provider.
pub fn L2View(comptime IO: type) type {
    return struct {
        provider: *l2_provider.L2Provider(IO),

        const Self = @This();

        pub fn l2_block_info_by_number(view: *Self, number: u64) ProviderError!L2BlockInfo {
            return view.provider.l2_block_info_by_number(number);
        }

        /// The header behind the provider's last `error.Pruned`.
        pub fn pruned_header(view: *Self) ?BlockInfo {
            const pruned = view.provider.last_pruned orelse return null;
            return pruned.header;
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
            return view.provider.l2_block_by_number(number);
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

/// The version-0 output root of `block`. From Isthmus the header's `withdrawalsRoot` is the
/// message passer storage root; earlier blocks need `proof_root` (`eth_getProof`).
pub fn output_of(
    rollup: *const RollupConfig,
    block: *const l2_block.L2Block,
    proof_root: ?Hash,
) error{NotAvailable}!rollup_rpc.OutputAtBlock {
    const timestamp = block.info.block_info.timestamp;
    const storage_root = if (rollup.is_active(.isthmus, timestamp))
        block.withdrawals_root orelse return error.NotAvailable
    else
        proof_root orelse return error.NotAvailable;
    const result: rollup_rpc.OutputAtBlock = .{
        .block_ref = block.info,
        .output = .{
            .state_root = block.state_root,
            .bridge_storage_root = storage_root,
            .block_hash = block.info.block_info.hash,
        },
    };
    assert(result.output.block_hash.eql(block.info.block_info.hash));
    return result;
}

/// `enode://<public key>@<ip>:<tcp>` for the advertised (else listen) address.
pub fn enode_of(output: []u8, p2p: *const P2p) ![]const u8 {
    const public = try secp256k1.public_key(p2p.node_secret);
    const uncompressed = try secp256k1.decompress(public);
    const hex = std.fmt.bytesToHex(uncompressed[1..], .lower);
    const tcp = p2p.options.advertise_tcp orelse p2p.options.listen_tcp;
    const address = p2p.options.advertise_ip orelse p2p.options.listen_ip;
    const ip4 = switch (address) {
        .ip4 => |bytes| bytes,
        .ip6 => return error.Ip6Unsupported,
    };
    const ip = if (std.mem.allEqual(u8, &ip4, 0)) [4]u8{ 127, 0, 0, 1 } else ip4;
    const text = try std.fmt.bufPrint(output, "enode://{s}@{d}.{d}.{d}.{d}:{d}", .{
        &hex, ip[0], ip[1], ip[2], ip[3], tcp,
    });
    assert(text.len > "enode://".len + 128);
    return text;
}

pub fn Node(comptime IO: type) type {
    return struct {
        const Self = @This();
        const RpcServer = http.Server(IO, *Self, handle_rpc);
        const Blobs = blob_provider.BlobProvider(IO, blob_provider.KzgVerifier);
        const Engine = engine_client.EngineClient(IO);
        const Polling = polling_client.PollingClient(IO);
        const admin_vtable: admin_rpc.VTable = .{
            .is_sequencer = admin_is_sequencer,
            .sequencer_active = admin_sequencer_active,
            .start_sequencer = admin_start_sequencer,
            .stop_sequencer = admin_stop_sequencer,
            .recover_mode = admin_recover_mode,
            .set_recover_mode = admin_set_recover_mode,
            .reset_derivation_pipeline = admin_reset_derivation_pipeline,
            .post_unsafe_payload = admin_post_unsafe_payload,
            .task_queue_length = admin_task_queue_length,
            .conductor_enabled = admin_conductor_enabled,
            .override_leader = admin_override_leader,
        };
        const base_vtable: base_rpc.VTable = .{
            .config = base_config,
            .status = base_status,
            .now_s = base_now_s,
        };
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
            /// Durable safe/finalized heads for startup when the engine pruned their bodies.
            checkpoints: ?checkpoint.Checkpoints = null,
        };

        allocator: Allocator,
        io: *IO,
        logger: *log.Logger,
        rollup: *const RollupConfig,
        options: Options,
        watcher: l1_watcher.L1Watcher(IO),
        l1: l1_provider.L1Provider(IO),
        l2: l2_provider.L2Provider(IO),
        /// Message passer storage roots for pre-Isthmus `optimism_outputAtBlock`.
        message_passer: message_passer_roots.MessagePasserRoots(IO),
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
        logged_error: ?anyerror = null,
        status_logged_ns: u64 = 0,
        network: ?*Network = null,
        p2p_random: std.Random.DefaultPrng = .init(0),
        /// Gossip decode scratch and publish encoding storage (p2p only).
        gossip_scratch: []u8 = &.{},
        publish_storage: []u8 = &.{},
        gossip_arena: std.heap.ArenaAllocator,
        gossip: GossipStats = .{},
        /// Reads the unsafe block signer from the L1 SystemConfig (p2p only, when the rollup
        /// config names the contract).
        signer: ?*Signer = null,
        signer_version: u64 = 0,
        /// Observes the L1 upgrade-signal schedule when configured.
        upgrade: ?*Upgrade = null,
        /// Persists the safe and finalized heads when `checkpoint_path` is set.
        checkpoints: ?*Checkpoints = null,
        checkpoints_logged: bool = false,
        metrics: metrics_module.Metrics = .{},
        metrics_server: ?MetricsServer = null,
        follower: ?*Follower = null,
        conductor: ?*Conductor = null,
        ws_rpc: ?*WsRpc = null,
        /// Source labels waiting for the local blocks they are checked against.
        follow_labels: ?follow.Labels = null,

        pub const Checkpoints = checkpoint.CheckpointStore(IO);
        pub const Follower = follow.Follower(IO);
        pub const Conductor = conductor_module.Conductor(IO);
        pub const WsRpc = ws_rpc_module.WsRpc(IO);
        pub const MetricsServer = http.Server(IO, *Metrics, Metrics.handle);
        const Metrics = metrics_module.Metrics;
        pub const Network = p2p_network.Network(IO);
        pub const Signer = signer_watcher.SignerWatcher(IO);
        pub const Upgrade = upgrade_signal.Observer(IO, *Self);
        pub const GossipStats = struct {
            received: u64 = 0,
            undecodable: u64 = 0,
            published: u64 = 0,
            publish_failures: u64 = 0,
        };

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
                .message_passer = undefined,
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
                    .admin = if (options.rpc_admin) &admin_vtable else null,
                    .dev = if (options.rpc_dev) &admin_vtable else null,
                },
                .safe_db = try safedb.SafeDB.init(allocator, options.safedb_entries),
                .gossip_arena = .init(allocator),
            };
            errdefer node.safe_db.deinit(allocator);
            try node.init_sources();
            errdefer node.deinit_sources();
            var driver_options = options.driver;
            driver_options.follow = options.follow_source != null;
            try node.driver.init(
                allocator,
                rollup,
                &node.blob_schedule,
                &node.safe_db,
                driver_options,
            );
            errdefer node.driver.deinit();
            try node.rpc_server.init(allocator, io, node, options.rpc_server);
            errdefer node.rpc_server.deinit();
            try node.init_metrics();
            errdefer node.deinit_metrics();
            if (options.upgrade_signal) |config| try node.init_upgrade(&config);
            errdefer node.deinit_upgrade();
            if (options.checkpoint_path) |path| try node.init_checkpoints(path);
            errdefer node.deinit_checkpoints();
            if (options.follow_source) |source| try node.init_follower(source);
            errdefer node.deinit_follower();
            if (options.conductor) |address| try node.init_conductor(address);
            errdefer node.deinit_conductor();
            if (options.ws_address != null) try node.init_ws_rpc();
            errdefer node.deinit_ws_rpc();
            if (options.p2p) |p2p| try node.init_p2p(&p2p);
        }

        fn init_ws_rpc(node: *Self) !void {
            assert(node.ws_rpc == null);
            const ws_rpc = try node.allocator.create(WsRpc);
            errdefer node.allocator.destroy(ws_rpc);
            try ws_rpc.init(node.allocator, node.io, &node.backend);
            ws_rpc.fallback = .{ .context = node, .serve = ws_serve_rpc };
            ws_rpc.dev_enabled = node.options.rpc_dev;
            node.ws_rpc = ws_rpc;
        }

        fn deinit_ws_rpc(node: *Self) void {
            const ws_rpc = node.ws_rpc orelse return;
            ws_rpc.stop();
            var rounds: u32 = 0;
            while (!ws_rpc.stopped() and rounds < 1000) : (rounds += 1) {
                node.io.run_for_ns(std.time.ns_per_ms) catch break;
            }
            ws_rpc.deinit();
            node.allocator.destroy(ws_rpc);
            node.ws_rpc = null;
        }

        fn init_conductor(node: *Self, address: Address) !void {
            assert(node.conductor == null);
            const conductor = try node.allocator.create(Conductor);
            errdefer node.allocator.destroy(conductor);
            try conductor.init(node.allocator, node.io, address, node.options.engine_http_client);
            node.conductor = conductor;
            node.driver.queue.context.committer = conductor.committer();
            assert(node.driver.queue.context.committer != null);
        }

        fn deinit_conductor(node: *Self) void {
            const conductor = node.conductor orelse return;
            node.driver.queue.context.committer = null;
            var rounds: u32 = 0;
            while (conductor.busy() and rounds < 1000) : (rounds += 1) {
                node.io.run_for_ns(std.time.ns_per_ms) catch break;
                conductor.client.http.tick();
            }
            conductor.deinit();
            node.allocator.destroy(conductor);
            node.conductor = null;
        }

        fn init_follower(node: *Self, source: Address) !void {
            assert(node.follower == null);
            assert(node.driver.options.follow);
            const follower = try node.allocator.create(Follower);
            errdefer node.allocator.destroy(follower);
            // Full blocks: the engine client's buffers fit them.
            try follower.init(node.allocator, node.io, source, node.options.engine_http_client);
            node.follower = follower;
        }

        fn deinit_follower(node: *Self) void {
            const follower = node.follower orelse return;
            var rounds: u32 = 0;
            while (follower.busy() and rounds < 1000) : (rounds += 1) {
                node.io.run_for_ns(std.time.ns_per_ms) catch break;
                follower.client.http.tick();
            }
            follower.deinit();
            node.allocator.destroy(follower);
            node.follower = null;
        }

        /// Follow mode: inserts the next source block once the engine queue is idle (so the
        /// unsafe head is current and no block is inserted twice), then checks labels.
        fn tick_follow(node: *Self) void {
            const follower = node.follower orelse return;
            const unsafe_number = node.driver.sync_state().unsafe_head.block_info.number;
            const idle = node.driver.phase == .running and node.driver.queue.len() == 0;
            follower.tick(unsafe_number, idle);
            if (follower.take()) |envelope| {
                if (envelope.payload.block_number != unsafe_number + 1) {
                    follower.consume(); // The head moved meanwhile; fetch again.
                } else if (idle and node.driver.insert_unsafe(envelope)) {
                    follower.consume();
                }
            }
            if (follower.take_labels()) |labels| node.follow_labels = labels;
            node.tick_follow_labels();
            assert(node.driver.options.follow);
        }

        /// Checks pending source labels against the local blocks at their heights (base/base
        /// `update_safe_and_finalized`): safe within `[safe, unsafe]`, finalized within
        /// `[finalized, new safe]`. A hash mismatch drops the update.
        fn tick_follow_labels(node: *Self) void {
            const labels = node.follow_labels orelse return;
            const state = node.driver.sync_state();
            const latest = state.unsafe_head.block_info.number;
            const safe_floor = state.safe_head.block_info.number;
            const safe = node.follow_local(labels.safe, safe_floor, latest) catch |err| {
                if (err == error.NotAvailable) return; // Asked again next tick.
                return node.drop_follow_labels(labels.safe.?);
            };
            const safe_limit = if (safe) |head| head.block_info.number else safe_floor;
            const floor = state.finalized_head.block_info.number;
            const top = @min(latest, safe_limit);
            const finalized = node.follow_local(labels.finalized, floor, top) catch |err| {
                if (err == error.NotAvailable) return;
                return node.drop_follow_labels(labels.finalized.?);
            };
            node.follow_labels = null;
            if (safe != null or finalized != null) _ = node.driver.promote_labels(safe, finalized);
            assert(node.follow_labels == null);
        }

        fn drop_follow_labels(node: *Self, label: protocol.block.BlockInfo) void {
            assert(node.follow_labels != null);
            node.follow_labels = null;
            node.logger.log(.warn, "consensus", "follow source label does not match", .{
                .number = label.number,
            });
        }

        /// The local block for a source label in range, or null when it is out of range or
        /// missing locally.
        fn follow_local(
            node: *Self,
            source: ?protocol.block.BlockInfo,
            floor: u64,
            ceiling: u64,
        ) error{ NotAvailable, Mismatch }!?L2BlockInfo {
            const label = source orelse return null;
            if (label.number < floor or label.number > ceiling) return null;
            const local = node.l2.l2_block_info_by_number(label.number) catch |err| {
                if (err == error.NotAvailable) return error.NotAvailable;
                return null;
            };
            assert(local.block_info.number == label.number);
            return switch (follow.verify_label(label, local.block_info, floor, ceiling)) {
                .skip => null,
                .promote => local,
                .mismatch => error.Mismatch,
            };
        }

        fn init_metrics(node: *Self) !void {
            assert(node.metrics_server == null);
            try node.metrics.register();
            if (node.options.metrics_address == null) return;
            node.metrics_server = @as(MetricsServer, undefined);
            const server = &node.metrics_server.?;
            errdefer node.metrics_server = null;
            const options = node.options.metrics_server;
            try server.init(node.allocator, node.io, &node.metrics, options);
            assert(node.metrics.registry.count > 0);
        }

        fn deinit_metrics(node: *Self) void {
            if (node.metrics_server) |*server| server.deinit();
            node.metrics_server = null;
        }

        fn record_metrics(node: *Self) void {
            const l1_head = node.watcher.head(.latest) orelse protocol.block.BlockInfo{};
            const sample: metrics_module.Sample = .{
                .sync_state = node.driver.sync_state(),
                .l1_head = l1_head.number,
                .queue_depth = node.driver.queue.len(),
                .stats = node.driver.stats,
                .peers = if (node.network) |network| network.peer_count() else 0,
            };
            node.metrics.record(&sample);
            assert(node.metrics.registry.count > 0);
        }

        fn init_checkpoints(node: *Self, path: []const u8) !void {
            assert(node.checkpoints == null);
            assert(path.len > 0);
            const store = try node.allocator.create(Checkpoints);
            errdefer node.allocator.destroy(store);
            try store.init(node.allocator, node.io, path);
            node.checkpoints = store;
        }

        fn deinit_checkpoints(node: *Self) void {
            const store = node.checkpoints orelse return;
            store.stop();
            var rounds: u32 = 0;
            while (store.busy() and rounds < 1000) : (rounds += 1) {
                node.io.run_for_ns(std.time.ns_per_ms) catch break;
            }
            store.deinit(node.allocator);
            node.allocator.destroy(store);
            node.checkpoints = null;
        }

        /// Records the engine's safe and finalized heads; logs the stored ones once loaded.
        fn tick_checkpoints(node: *Self) void {
            const store = node.checkpoints orelse return;
            const loaded = store.loaded orelse return;
            if (!node.checkpoints_logged) {
                node.checkpoints_logged = true;
                const none: protocol.block.L2BlockInfo = .{};
                node.logger.log(.info, "consensus", "checkpoints loaded", .{
                    .safe = (loaded.safe orelse none).block_info.number,
                    .finalized = (loaded.finalized orelse none).block_info.number,
                    .invalid_images = store.invalid_images,
                });
            }
            const sync = node.driver.sync_state();
            store.update(sync.safe_head, sync.finalized_head);
        }

        fn init_upgrade(node: *Self, config: *const UpgradeSignal) !void {
            assert(node.upgrade == null);
            assert(!std.mem.allEqual(u8, &config.contract, 0));
            const observer = try node.allocator.create(Upgrade);
            errdefer node.allocator.destroy(observer);
            try observer.init(node.allocator, node.io, node.options.l1, config.contract, .{
                .layer = .consensus,
                .reader = .{ .block_tag = config.block_tag },
            }, node, on_upgrade_schedule);
            node.upgrade = observer;
            node.backend.base = &base_vtable;
        }

        fn deinit_upgrade(node: *Self) void {
            const observer = node.upgrade orelse return;
            observer.stop();
            var rounds: u32 = 0;
            while (!observer.stopped() and rounds < 1000) : (rounds += 1) {
                node.io.run_for_ns(std.time.ns_per_ms) catch break;
            }
            observer.deinit();
            node.allocator.destroy(observer);
            node.upgrade = null;
            node.backend.base = null;
        }

        fn on_upgrade_schedule(node: *Self, schedule: *const upgrade_signal.Schedule) void {
            assert(schedule.count > 0);
            var version_text: [64]u8 = undefined;
            const version = std.fmt.bufPrint(&version_text, "{f}", .{schedule.minimum_version});
            node.logger.log(.info, "consensus", "upgrade signal schedule", .{
                .l1_block = schedule.l1_block_number,
                .signals = schedule.signals_count(),
                .minimum_protocol_version = version catch "unprintable",
            });
        }

        fn init_p2p(node: *Self, p2p: *const P2p) !void {
            const allocator = node.allocator;
            node.gossip_scratch = try allocator.alloc(u8, snappy.gossip_size_max);
            errdefer allocator.free(node.gossip_scratch);
            node.publish_storage = try allocator.alloc(u8, snappy.gossip_size_max);
            errdefer allocator.free(node.publish_storage);
            const network = try allocator.create(Network);
            errdefer allocator.destroy(network);
            node.p2p_random = .init(p2p.seed);
            try network.init(
                allocator,
                node.io,
                node.rollup,
                p2p.options,
                p2p.node_secret,
                p2p.unsafe_block_signer,
                node.p2p_random.random(),
                p2p.seed,
            );
            node.network = network;
            errdefer node.network = null;
            const system_config = node.rollup.l1_system_config_address;
            if (!std.mem.allEqual(u8, &system_config.bytes, 0)) {
                const signer = try allocator.create(Signer);
                errdefer allocator.destroy(signer);
                const http_options = node.options.http_client;
                const l1 = node.options.l1;
                try signer.init(allocator, node.io, l1, http_options, system_config, .{});
                node.signer = signer;
            }
            assert(node.gossip_scratch.len >= snappy.gossip_size_max);
        }

        fn deinit_p2p(node: *Self) void {
            if (node.signer) |signer| {
                signer.deinit();
                node.allocator.destroy(signer);
                node.signer = null;
            }
            const network = node.network orelse return;
            network.stop();
            // The bootstore file writes a final image on stop; let it finish (bounded).
            var rounds: u32 = 0;
            while (network.busy() and rounds < 1000) : (rounds += 1) {
                node.io.run_for_ns(std.time.ns_per_ms) catch break;
            }
            network.deinit(node.allocator);
            node.allocator.destroy(network);
            node.allocator.free(node.gossip_scratch);
            node.allocator.free(node.publish_storage);
            node.network = null;
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
            try node.message_passer.init(allocator, io, options.l2, options.http_client, .{
                .jwt_secret = options.jwt_secret,
            });
            errdefer node.message_passer.deinit();
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
            node.message_passer.deinit();
            node.l2.deinit();
            node.l1.deinit();
            node.watcher.deinit();
        }

        /// Frees everything. The IO must not run afterwards (in-flight operations would
        /// complete into freed memory); the binary tears both down together.
        pub fn deinit(node: *Self) void {
            node.deinit_p2p();
            node.deinit_upgrade();
            node.deinit_checkpoints();
            node.deinit_follower();
            node.deinit_conductor();
            node.deinit_ws_rpc();
            node.gossip_arena.deinit();
            node.deinit_metrics();
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
            if (node.ws_rpc) |ws_rpc| {
                const bound = try ws_rpc.listen(node.options.ws_address.?);
                node.logger.log(.info, "consensus", "ws rpc listening", .{ .port = bound.port });
            }
            if (node.metrics_server) |*server| {
                const bound = try server.listen(node.options.metrics_address.?);
                node.logger.log(.info, "consensus", "metrics listening", .{ .port = bound.port });
            }
            if (node.network) |network| try node.start_p2p(network);
            if (node.upgrade) |observer| observer.start();
            if (node.checkpoints) |store| store.start();
            return address;
        }

        fn start_p2p(node: *Self, network: *Network) !void {
            const invalid = try network.start();
            var record_text: [enr.text_length_max]u8 = undefined;
            var enode_text: [256]u8 = undefined;
            const p2p = &node.options.p2p.?;
            node.logger.log(.info, "consensus", "p2p listening", .{
                .tcp = p2p.options.listen_tcp,
                .udp = p2p.options.listen_udp,
                .enode = enode_of(&enode_text, p2p) catch "unavailable",
                .enr = enr.encode_text(&record_text, &network.record),
                .invalid_bootnodes = invalid,
            });
        }

        pub fn providers(node: *Self) Providers {
            return .{
                .l1 = &node.l1,
                .blobs = &node.blob_view,
                .l2 = &node.l2_view,
                .engine = &node.polling,
                .l1_head = node.watcher.head(.latest),
                .l1_finalized = node.watcher.head(.finalized),
                .checkpoints = if (node.checkpoints) |store| store.loaded else null,
            };
        }

        /// Whether any HTTP request is still in flight (drain before `deinit`).
        pub fn busy(node: *const Self) bool {
            const blobs_busy = if (node.blobs) |blobs| blobs.busy() else false;
            const signer_busy = if (node.signer) |signer| signer.busy() else false;
            const follower_busy = if (node.follower) |follower| follower.busy() else false;
            const conductor_busy = if (node.conductor) |conductor| conductor.busy() else false;
            return node.watcher.busy() or node.l1.busy() or node.l2.busy() or
                node.message_passer.busy() or node.engine.busy() or blobs_busy or signer_busy or
                follower_busy or conductor_busy;
        }

        /// One step of the node's state machines; call every few milliseconds.
        pub fn tick(node: *Self) void {
            node.watcher.tick();
            node.l1.tick();
            node.l2.tick();
            node.message_passer.tick();
            node.polling.tick();
            if (node.blobs) |blobs| blobs.tick();
            const now_s = node.io.now_realtime_ns() / std.time.ns_per_s;
            // Startup may need the checkpoints, so the driver waits until they are read.
            const checkpoints_ready = if (node.checkpoints) |store| store.loaded != null else true;
            if (checkpoints_ready) node.driver.tick(node.providers(), now_s);
            if (node.network) |network| {
                node.tick_signer(network);
                node.tick_gossip(network);
            }
            node.tick_checkpoints();
            node.tick_follow();
            if (node.conductor) |conductor| conductor.tick();
            if (node.ws_rpc) |ws_rpc| ws_rpc.publish(.{
                .sync_state = node.driver.sync_state(),
                .queue_size = node.driver.queue.len(),
            });
            node.record_metrics();
            node.log_progress();
            assert(node.driver.sync_state().is_ordered());
        }

        /// Applies a new L1 SystemConfig signer to gossip validation.
        fn tick_signer(node: *Self, network: *Network) void {
            const watcher = node.signer orelse return;
            watcher.tick();
            if (watcher.version == node.signer_version) return;
            node.signer_version = watcher.version;
            const signer = watcher.signer.?; // Proof: the version only moves with a signer.
            network.service.gossip.set_unsafe_block_signer(signer);
            var hex: [42]u8 = undefined;
            node.logger.log(.info, "consensus", "unsafe block signer from L1", .{
                .signer = std.fmt.bufPrint(&hex, "0x{x}", .{&signer.bytes}) catch unreachable,
            });
        }

        /// Hands received blocks to the driver and publishes the block just sealed.
        fn tick_gossip(node: *Self, network: *Network) void {
            for (0..gossip_blocks_per_tick) |_| {
                const envelope = network.pop_block(node.gossip_scratch) orelse break;
                node.gossip.received += 1;
                defer _ = node.gossip_arena.reset(.{ .retain_with_limit = 1 << 20 });
                const allocator = node.gossip_arena.allocator();
                const decoded = gossip_bridge.decode_gossip(allocator, &envelope) catch {
                    node.gossip.undecodable += 1;
                    continue;
                };
                _ = node.driver.insert_unsafe(&decoded);
            }
            const sealed = node.driver.queue.take_sealed() orelse return;
            const key = node.options.p2p.?.sequencer_key orelse return;
            node.publish(network, key, sealed);
        }

        fn publish(
            node: *Self,
            network: *Network,
            key: [32]u8,
            sealed: *const gossip_bridge.Envelope,
        ) void {
            assert(node.publish_storage.len > 0);
            const storage = node.publish_storage;
            const result = if (gossip_bridge.encode_gossip(node.rollup, sealed, storage)) |payload|
                network.publish_block(key, sealed.parent_beacon_block_root, payload)
            else |err|
                err;
            if (result) |_| {
                node.gossip.published += 1;
            } else |err| {
                node.gossip.publish_failures += 1;
                node.logger.log(.warn, "consensus", "block publish failed", .{
                    .number = sealed.payload.block_number,
                    .err = @errorName(err),
                });
            }
        }

        /// Every 10 s while not running: where startup waits.
        fn log_waiting(node: *Self) void {
            if (node.driver.phase == .running) return;
            const now_ns = node.io.now_realtime_ns();
            if (now_ns < node.status_logged_ns + 10 * std.time.ns_per_s) return;
            node.status_logged_ns = now_ns;
            node.logger.log(.info, "consensus", "waiting", .{
                .phase = @tagName(node.driver.phase),
                .finder = @tagName(node.driver.finder.phase),
                .l1_head = if (node.watcher.head(.latest)) |head| head.number else 0,
                .l1_requests = node.l1.stats.requests,
                .l1_failures = node.l1.stats.failures,
                .l1_error = if (node.l1.stats.last_failure) |err| @errorName(err) else "none",
                .l2_requests = node.l2.stats.requests,
                .l2_failures = node.l2.stats.failures,
                .l2_not_found = node.l2.stats.not_found,
            });
        }

        fn log_progress(node: *Self) void {
            node.log_waiting();
            const state = node.driver.sync_state();
            if (node.driver.last_error != node.logged_error) {
                node.logged_error = node.driver.last_error;
                node.logger.log(.warn, "consensus", "driver error", .{
                    .err = @errorName(node.driver.last_error.?),
                    .phase = @tagName(node.driver.phase),
                    .count = node.driver.error_sequence,
                });
            }
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
            const outcome = node.serve_rpc(request.body, response.writer());
            if (outcome == .empty) response.status = 204;
        }

        fn ws_serve_rpc(context: *anyopaque, body: []const u8, out: *std.Io.Writer) RpcOutcome {
            const node = from_context(context);
            assert(node.ws_rpc != null);
            return node.serve_rpc(body, out);
        }

        fn serve_rpc(node: *Self, body: []const u8, out: *std.Io.Writer) RpcOutcome {
            const p2p = if (node.network) |network| network.service else null;
            const context: RpcRouter.Context = .{ .inner = &node.backend, .p2p = p2p };
            return RpcRouter.Router.handle(&context, body, out);
        }

        fn from_context(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn backend_sync_status(context: *anyopaque) SyncStatus {
            return from_context(context).sync_status();
        }

        /// Output roots from the engine's block headers: from Isthmus on the header's
        /// `withdrawalsRoot` is the message passer storage root. Earlier blocks need
        /// `eth_getProof` of the message passer: the first query starts the fetch and is
        /// reported as not available; later queries answer from the cache.
        fn backend_output_at_block(
            context: *anyopaque,
            tag: rollup_rpc.BlockTag,
        ) error{ NotAvailable, NotFound }!rollup_rpc.OutputAtBlock {
            const node = from_context(context);
            const key: l2_provider.Request = switch (tag) {
                .number => |number| .{ .number = number },
                .earliest => .{ .number = node.rollup.genesis.l2.number },
                .latest, .pending => .{ .label = .latest },
                .safe => .{ .label = .safe },
                .finalized => .{ .label = .finalized },
            };
            const block = node.l2.l2_block_ref(key) catch |err| return switch (err) {
                error.NotFound => error.NotFound,
                else => error.NotAvailable,
            };
            const timestamp = block.info.block_info.timestamp;
            const rollup = node.rollup;
            if (rollup.is_active(.isthmus, timestamp)) return output_of(rollup, &block, null);
            const hash = block.info.block_info.hash;
            const root = node.message_passer.storage_root(hash) catch return error.NotAvailable;
            return output_of(node.rollup, &block, root);
        }

        fn admin_is_sequencer(context: *anyopaque) bool {
            return from_context(context).driver.options.sequencer;
        }

        fn admin_sequencer_active(context: *anyopaque) bool {
            return from_context(context).driver.sequencer_active;
        }

        fn admin_start_sequencer(context: *anyopaque, head: Hash) admin_rpc.StartError!void {
            const node = from_context(context);
            if (node.driver.sequencer_active) return; // base/base: already started is ok.
            if (node.conductor) |conductor| {
                // base/base checks `conductor_leader` first; this answers from the last poll.
                if (conductor.leader != true) return error.NotLeader;
            }
            try node.driver.start_sequencer(head);
            node.logger.log(.info, "consensus", "sequencer started", .{});
        }

        fn admin_stop_sequencer(context: *anyopaque) admin_rpc.StopError!Hash {
            const node = from_context(context);
            const head = try node.driver.stop_sequencer();
            node.logger.log(.info, "consensus", "sequencer stopped", .{});
            return head;
        }

        fn admin_recover_mode(context: *anyopaque) bool {
            return from_context(context).driver.options.recovery_mode;
        }

        fn admin_set_recover_mode(context: *anyopaque, mode: bool) void {
            from_context(context).driver.options.recovery_mode = mode;
        }

        fn admin_reset_derivation_pipeline(context: *anyopaque) void {
            const node = from_context(context);
            node.driver.request_reset();
            node.logger.log(.info, "consensus", "derivation pipeline reset requested", .{});
        }

        fn admin_conductor_enabled(context: *anyopaque) bool {
            return from_context(context).conductor != null;
        }

        fn admin_override_leader(context: *anyopaque) admin_rpc.OverrideError!void {
            const node = from_context(context);
            const conductor = node.conductor orelse return error.NoConductor;
            conductor.request_override();
            node.logger.log(.info, "consensus", "conductor leader override requested", .{});
        }

        fn admin_task_queue_length(context: *anyopaque) u64 {
            return from_context(context).driver.queue.len();
        }

        fn admin_post_unsafe_payload(
            context: *anyopaque,
            envelope_json: []const u8,
        ) admin_rpc.PostError!void {
            const node = from_context(context);
            defer _ = node.gossip_arena.reset(.{ .retain_with_limit = 1 << 20 });
            const allocator = node.gossip_arena.allocator();
            const decoded = engine_json.decode_unsafe_envelope(allocator, envelope_json, .{}) catch
                return error.InvalidPayload;
            const envelope: gossip_bridge.Envelope = .{
                .payload = decoded.payload,
                .parent_beacon_block_root = decoded.parent_beacon_block_root,
            };
            if (!node.driver.insert_unsafe(&envelope)) {
                node.logger.log(.warn, "consensus", "posted unsafe payload not queued", .{
                    .number = envelope.payload.block_number,
                });
                return error.NotAccepted;
            }
            node.logger.log(.info, "consensus", "unsafe payload posted", .{
                .number = envelope.payload.block_number,
            });
        }

        fn base_config(context: *anyopaque) base_rpc.Config {
            const node = from_context(context);
            const tag = node.options.upgrade_signal.?.block_tag;
            return .{
                .node_version = base_rpc.advertised_version(node.options.version),
                .mode = .metrics_only, // Schedules are observed, not applied.
                .halt_lead_s = base_rpc.halt_lead_s(tag),
            };
        }

        fn base_status(context: *anyopaque) base_rpc.Status {
            const node = from_context(context);
            const observer = node.upgrade.?; // Proof: `backend.base` is set only with it.
            if (observer.observed) return .{ .schedule = &observer.last };
            if (observer.metrics.empty_schedule_reads_total.get() > 0) return .empty;
            return .unavailable;
        }

        fn base_now_s(context: *anyopaque) u64 {
            return from_context(context).io.now_realtime_ns() / std.time.ns_per_s;
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

const message_passer_proof =
    \\{"address":"0x4200000000000000000000000000000000000016","storageProof":[],
    \\"storageHash":"0x8ed4baae3a927be3dea54996b4d5899f8c01e7594bf50b17dc1e741388ce3d12"}
;

test "node: runs the driver, tracks L1 heads, and serves optimism_syncStatus" {
    var block_text: [4096]u8 = undefined;
    var hash: [32]u8 = undefined;
    const block = try fixtures.l2_block_json(&block_text, 7, &hash);
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "latest", .result = block });
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "safe", .result = block });
    const proof = message_passer_proof;
    fake.add(.{ .method = "eth_getProof", .params_contain = "0x42", .result = proof });
    var harness: Harness = undefined;
    try harness.init_connections(&fake, 0x4e, 6);
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
        .rpc_admin = true,
        .rpc_address = sim.Address.ip4(.{ 10, 0, 0, 2 }, 7545),
        .http_client = harness_module.client_options,
        .checkpoint_path = "checkpoint.bin",
    });
    defer node.deinit();
    node.checkpoints.?.start(); // `start` would also bind the RPC port.
    for (0..40) |_| {
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    const status = node.sync_status();
    // The discovered safe head is checkpointed (written on change, fsynced).
    const store = node.checkpoints.?;
    try testing.expect(std.meta.eql(checkpoint.Checkpoints{}, store.loaded.?));
    try testing.expect(std.mem.indexOf(u8, memory.text(), "checkpoints loaded") != null);
    if (status.safe_l2.block_info.number != 0) {
        try testing.expect(std.meta.eql(status.safe_l2, store.checkpoints.safe.?));
        try testing.expect(store.file.stats.saves >= 1);
    }
    try testing.expectEqual(@as(u64, 7), status.head_l1.number);
    try testing.expectEqualSlices(u8, &hash, &status.head_l1.hash.bytes);
    // The fake chain's L1 origin (507) does not exist, so the node never starts running.
    try testing.expect(node.driver.phase != driver_module.Phase.running);
    // Startup discovery may already have taken the fake's latest block as the unsafe head.
    const unsafe_number = status.unsafe_l2.block_info.number;
    try testing.expect(unsafe_number == 0 or unsafe_number == 7);
    var buffer: [8192]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    _ = rollup_rpc.Router.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":1,"method":"optimism_syncStatus"}
    , &out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "\"unsafe_l2\":{\"hash\"") != null);
    var admin_buffer: [512]u8 = undefined;
    var admin_out: std.Io.Writer = .fixed(&admin_buffer);
    _ = rollup_rpc.NodeRouter.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":2,"method":"admin_stopSequencer"}
    , &admin_out);
    try testing.expect(std.mem.indexOf(u8, admin_out.buffered(), "-32001") != null);
    admin_out = .fixed(&admin_buffer);
    _ = rollup_rpc.NodeRouter.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":3,"method":"admin_sequencerActive"}
    , &admin_out);
    // A verifier has no sequencer admin API (base/base -32001).
    const unavailable = std.mem.indexOf(u8, admin_out.buffered(), "sequencer not available");
    try testing.expect(unavailable != null);
    admin_out = .fixed(&admin_buffer);
    _ = rollup_rpc.NodeRouter.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":4,"method":"admin_postUnsafePayload","params":[{"executionPayload":{}}]}
    , &admin_out);
    try testing.expect(std.mem.indexOf(u8, admin_out.buffered(), "invalid execution") != null);
    // Pre-Isthmus output roots come from eth_getProof of the message passer.
    var output_buffer: [8192]u8 = undefined;
    var answered = false;
    for (0..40) |_| {
        var output_out: std.Io.Writer = .fixed(&output_buffer);
        _ = rollup_rpc.Router.handle(&node.backend,
            \\{"jsonrpc":"2.0","id":5,"method":"optimism_outputAtBlock","params":["latest"]}
        , &output_out);
        const reply = output_out.buffered();
        if (std.mem.indexOf(u8, reply, "\"withdrawalStorageRoot\":\"0x8ed4") != null) {
            answered = true;
            break;
        }
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    try testing.expect(answered);
    try testing.expectEqual(@as(u64, 1), node.message_passer.stats.requests);
    var metrics_buffer: [8192]u8 = undefined;
    var metrics_out: std.Io.Writer = .fixed(&metrics_buffer);
    try node.metrics.registry.write_prometheus(&metrics_out);
    var expected_buffer: [64]u8 = undefined;
    const metered_unsafe = node.driver.sync_state().unsafe_head.block_info.number;
    const expected = try std.fmt.bufPrint(&expected_buffer, "label=\"unsafe\"}} {d}\n", .{
        metered_unsafe,
    });
    try testing.expect(std.mem.indexOf(u8, metrics_out.buffered(), expected) != null);
    while (node.busy()) {
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
}

test "node: follow mode polls the source node and never derives" {
    var block_text: [4096]u8 = undefined;
    var hash: [32]u8 = undefined;
    const block = try fixtures.l2_block_json(&block_text, 7, &hash);
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "latest", .result = block });
    fake.add(.{ .method = "eth_getBlockByNumber", .params_contain = "safe", .result = block });
    var harness: Harness = undefined;
    try harness.init_connections(&fake, 0xf1, 6);
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
        .follow_source = harness.address,
        .jwt_secret = .{ .bytes = @splat(7) },
        .rpc_address = sim.Address.ip4(.{ 10, 0, 0, 2 }, 7545),
        .http_client = harness_module.client_options,
    });
    defer node.deinit();
    try testing.expect(node.driver.options.follow);
    for (0..20) |_| {
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    const follower = node.follower.?;
    try testing.expect(follower.stats.label_reads >= 2);
    // The driver is not running (the fake L1 origin is missing), so no block is fetched.
    try testing.expectEqual(@as(u64, 0), follower.stats.blocks);
    try testing.expectEqual(@as(u64, 0), node.driver.stats.consolidated);
    while (node.busy()) harness.world.run_for_ns(std.time.ns_per_s / 10);
}

test "node: conductor gates the sequencer start and commits seals" {
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "conductor_leader", .result = "false" });
    var harness: Harness = undefined;
    try harness.init_connections(&fake, 0xc1, 6);
    defer harness.deinit();
    var rollup: RollupConfig = .{ .block_time = 2 };
    var log_buffer: [4096]u8 = undefined;
    var memory: log.MemorySink = .{ .buffer = &log_buffer };
    var logger: log.Logger = .{ .sink = memory.sink() };
    const node = try testing.allocator.create(TestNode);
    defer testing.allocator.destroy(node);
    try node.init(testing.allocator, &harness.client_io, &logger, &rollup, .{
        .l1 = harness.address,
        .l2 = harness.address,
        .conductor = harness.address,
        .ws_address = sim.Address.ip4(.{ 10, 0, 0, 2 }, 7546),
        .sequencer = true,
        .driver = .{ .sequencer = true, .sequencer_stopped = true },
        .jwt_secret = .{ .bytes = @splat(7) },
        .rpc_address = sim.Address.ip4(.{ 10, 0, 0, 2 }, 7545),
        .http_client = harness_module.client_options,
    });
    defer node.deinit();
    try testing.expect(node.driver.queue.context.committer != null);
    try testing.expect(node.ws_rpc != null);
    try testing.expect(!node.driver.sequencer_active);
    const head = node.driver.sync_state().unsafe_head.block_info.hash;
    // Leadership unknown before the first poll, then false: starting is refused.
    try testing.expectError(error.NotLeader, TestNode.admin_start_sequencer(node, head));
    for (0..10) |_| {
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    try testing.expect(node.conductor.?.leader == false);
    try testing.expectError(error.NotLeader, TestNode.admin_start_sequencer(node, head));
    try testing.expect(TestNode.admin_conductor_enabled(node));
    try TestNode.admin_override_leader(node);
    fake.add(.{ .method = "conductor_overrideLeader", .result = "null" });
    for (0..10) |_| {
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    try testing.expectEqual(@as(u64, 1), node.conductor.?.stats.overrides);
    while (node.busy()) harness.world.run_for_ns(std.time.ns_per_s / 10);
}

test "node: observes the upgrade signal and serves base_upgradeReadiness" {
    const contract = upgrade_signal.contract;
    var schedule_data: [64 + 32 * 2]u8 = undefined;
    const encoded = contract.encode_schedule(&.{ 1_000, 2_000 }, &schedule_data);
    var schedule_text: [2 + 2 * schedule_data.len + 2]u8 = undefined;
    const schedule_hex = std.fmt.bytesToHex(schedule_data, .lower);
    const schedule_result = try std.fmt.bufPrint(&schedule_text, "\"0x{s}\"", .{
        schedule_hex[0 .. 2 * encoded.len],
    });
    var version_word: [32]u8 = undefined;
    const minimum = upgrade_signal.Version.pack(2, 0, 0, 0);
    std.mem.writeInt(u256, &version_word, minimum.packed_value, .big);
    var version_text: [70]u8 = undefined;
    const version_hex = std.fmt.bytesToHex(version_word, .lower);
    const version_result = try std.fmt.bufPrint(&version_text, "\"0x{s}\"", .{&version_hex});
    const schedule_selector = std.fmt.bytesToHex(contract.get_schedule_selector, .lower);
    const version_selector = std.fmt.bytesToHex(contract.minimum_protocol_version_selector, .lower);
    const hash_hex = "abababababababababababababababab" ++ "abababababababababababababababab";
    var fake: FakeRpc = .{};
    fake.add(.{
        .method = "eth_getBlockByNumber",
        .params_contain = "finalized",
        .result = "{\"number\":\"0x309\",\"hash\":\"0x" ++ hash_hex ++ "\"}",
    });
    const call = "eth_call";
    fake.add(.{ .method = call, .params_contain = &schedule_selector, .result = schedule_result });
    fake.add(.{ .method = call, .params_contain = &version_selector, .result = version_result });
    var harness: Harness = undefined;
    try harness.init_connections(&fake, 0x5b, 4); // The upgrade reader is one more client.
    defer harness.deinit();
    const rollup: RollupConfig = .{ .block_time = 2 };
    var log_buffer: [8192]u8 = undefined;
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
        .version = "1.5.0",
        .upgrade_signal = .{ .contract = @splat(0xc0) },
    });
    defer node.deinit();
    var buffer: [4096]u8 = undefined;
    const request =
        \\{"jsonrpc":"2.0","id":1,"method":"base_upgradeReadiness","params":["1.5.0"]}
    ;
    var out: std.Io.Writer = .fixed(&buffer);
    _ = rollup_rpc.NodeRouter.handle(&node.backend, request, &out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "-32006") != null);
    _ = try node.start();
    for (0..20) |_| {
        node.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 10);
    }
    try testing.expect(std.mem.indexOf(u8, memory.text(), "upgrade signal schedule") != null);
    out = .fixed(&buffer);
    _ = rollup_rpc.NodeRouter.handle(&node.backend, request, &out);
    const text = out.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "\"ready\":true") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"node_protocol_version\":\"1.5.0\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"l1_block_number\":777") != null);
    const required = "\"required_protocol_version\":\"2.0.0\"";
    try testing.expect(std.mem.indexOf(u8, text, required) != null);
    out = .fixed(&buffer);
    _ = rollup_rpc.NodeRouter.handle(&node.backend,
        \\{"jsonrpc":"2.0","id":2,"method":"base_upgradeReadiness"}
    , &out);
    try testing.expect(std.mem.indexOf(u8, out.buffered(), "metrics-only") != null);
    while (node.busy()) harness.world.run_for_ns(std.time.ns_per_s / 10);
}

test "node: output roots from Isthmus headers" {
    var rollup: RollupConfig = .{ .block_time = 2 };
    rollup.upgrades.set(.isthmus, 100);
    var block: l2_block.L2Block = .{
        .info = .{ .block_info = .{ .number = 9, .timestamp = 100, .hash = .init(@splat(9)) } },
        .system_config = .{},
        .state_root = .init(@splat(1)),
        .withdrawals_root = .init(@splat(2)),
    };
    const output = try output_of(&rollup, &block, null);
    try testing.expect(output.output.bridge_storage_root.eql(.init(@splat(2))));
    try testing.expect(output.output.state_root.eql(.init(@splat(1))));
    try testing.expectEqual(@as(u64, 9), output.block_ref.block_info.number);
    block.info.block_info.timestamp = 98;
    try testing.expectError(error.NotAvailable, output_of(&rollup, &block, null));
    // Before Isthmus only the proof root counts, never the header.
    const proof = try output_of(&rollup, &block, .init(@splat(4)));
    try testing.expect(proof.output.bridge_storage_root.eql(.init(@splat(4))));
    block.info.block_info.timestamp = 100;
    block.withdrawals_root = null;
    try testing.expectError(error.NotAvailable, output_of(&rollup, &block, .init(@splat(4))));
}

test "node: output roots seeded fuzz, available iff the fork's storage root is known" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x0a7);
    for (0..256) |_| {
        var rollup: RollupConfig = .{ .block_time = 2 };
        const isthmus_time = prng.below(1000);
        rollup.upgrades.set(.isthmus, isthmus_time);
        const timestamp = prng.below(1000);
        const has_root = prng.chance(1, 2);
        const has_proof = prng.chance(1, 2);
        const proof_root: ?Hash = if (has_proof) .init(@splat(5)) else null;
        const block: l2_block.L2Block = .{
            .info = .{ .block_info = .{ .number = timestamp, .timestamp = timestamp } },
            .system_config = .{},
            .withdrawals_root = if (has_root) .init(@splat(3)) else null,
        };
        const isthmus = timestamp >= isthmus_time;
        const available = if (isthmus) has_root else has_proof;
        if (output_of(&rollup, &block, proof_root)) |output| {
            try testing.expect(available);
            const expected: Hash = .init(@splat(if (isthmus) 3 else 5));
            try testing.expect(output.output.bridge_storage_root.eql(expected));
        } else |_| try testing.expect(!available);
    }
}

test "node: enode text parses back as a bootnode" {
    var secret: secp256k1.SecretKey = @splat(0);
    secret[31] = 3;
    var p2p: P2p = .{
        .options = try p2p_options.parse(&.{"--p2p.listen.tcp=9300"}),
        .node_secret = secret,
        .unsafe_block_signer = .zero,
        .seed = 1,
    };
    var text: [256]u8 = undefined;
    const enode = try enode_of(&text, &p2p);
    try testing.expect(std.mem.endsWith(u8, enode, "@127.0.0.1:9300"));
    const boot = @import("../p2p/peers/boot.zig");
    const parsed = try boot.parse(enode);
    try testing.expect(parsed == .enode);
    p2p.options.advertise_ip = .{ .ip6 = @splat(1) };
    try testing.expectError(error.Ip6Unsupported, enode_of(&text, &p2p));
}

/// A signed block with a valid hash for `rollup`, timestamped `now_s`.
fn gossip_payload(
    rollup: *const RollupConfig,
    now_s: u64,
    storage: []u8,
    beacon_root: primitives.B256,
) !@import("../p2p/gossip/block.zig").ExecutionPayload {
    const ssz = @import("../p2p/gossip/ssz_payload.zig");
    const validity = @import("../p2p/gossip/validity.zig");
    const consensus_types = @import("../../common/consensus/root.zig");
    const deposit: consensus_types.Envelope = .{ .deposit = .{
        .source_hash = .{ .bytes = @splat(1) },
        .from = .zero,
        .to = .create,
        .mint = 0,
        .value = 0,
        .gas_limit = 1_000_000,
        .is_system_transaction = false,
        .input = "needlefish",
    } };
    const transaction = deposit.encode_to(storage[128..]);
    var payload: ssz.ExecutionPayload = .{
        .version = @import("../p2p/gossip/block.zig").version_at(rollup, now_s),
        .block_number = 1,
        .timestamp = now_s,
        .gas_limit = 30_000_000,
        .base_fee_per_gas = 1,
        .transactions = ssz.Transactions.encode(storage[0..128], &.{transaction}),
    };
    payload.block_hash = try validity.block_hash(rollup, &payload, beacon_root);
    return payload;
}

test "node: receives gossiped unsafe blocks from a p2p peer" {
    const common_secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
    var sequencer_key: [32]u8 = @splat(0);
    sequencer_key[31] = 5;
    const signer: primitives.Address = .{ .bytes = try common_secp256k1.address(sequencer_key) };
    // The node starts with an unknown signer and reads it from the L1 SystemConfig.
    var word_text: [80]u8 = undefined;
    const signer_hex = std.fmt.bytesToHex(signer.bytes, .lower);
    const padding = "000000000000000000000000";
    const word = try std.fmt.bufPrint(&word_text, "\"0x{s}{s}\"", .{ padding, &signer_hex });
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "eth_getStorageAt", .params_contain = "0x65a7ed54", .result = word });
    var harness: Harness = undefined;
    try harness.init(&fake, 0x9e);
    defer harness.deinit();
    var rollup: RollupConfig = .{ .block_time = 2, .l2_chain_id = 901 };
    rollup.upgrades.set(.ecotone, 0);
    rollup.l1_system_config_address = .{ .bytes = @splat(0x5c) };
    // The peer: a bare network on its own host that publishes as the sequencer.
    var peer_io: sim.SimIo = undefined;
    try sim.SimIo.init(&peer_io, testing.allocator, &harness.world, .{
        .host = sim.Address.ip4(.{ 10, 0, 0, 9 }, 0),
    });
    defer peer_io.deinit();
    var peer_secret: secp256k1.SecretKey = @splat(0);
    peer_secret[31] = 4;
    var peer_prng = std.Random.DefaultPrng.init(4);
    const peer = try testing.allocator.create(TestNode.Network);
    defer testing.allocator.destroy(peer);
    const peer_options = try p2p_options.parse(&.{
        "--p2p.listen.ip=10.0.0.9",
        "--p2p.no-discovery",
    });
    const peer_random = peer_prng.random();
    const allocator = testing.allocator;
    try peer.init(allocator, &peer_io, &rollup, peer_options, peer_secret, signer, peer_random, 4);
    defer peer.deinit(testing.allocator);
    _ = try peer.start();
    const peer_p2p: P2p = .{
        .options = peer_options,
        .node_secret = peer_secret,
        .unsafe_block_signer = signer,
        .seed = 0,
    };
    var enode_text: [256]u8 = undefined;
    var boot_flag: [300]u8 = undefined;
    const peer_enode = try enode_of(&enode_text, &peer_p2p);
    const bootnode = try std.fmt.bufPrint(&boot_flag, "--p2p.bootnodes={s}", .{peer_enode});

    var log_buffer: [8192]u8 = undefined;
    var memory: log.MemorySink = .{ .buffer = &log_buffer };
    var logger: log.Logger = .{ .sink = memory.sink() };
    var node_secret: secp256k1.SecretKey = @splat(0);
    node_secret[31] = 3;
    const node = try testing.allocator.create(TestNode);
    defer testing.allocator.destroy(node);
    try node.init(testing.allocator, &harness.client_io, &logger, &rollup, .{
        .l1 = harness.address,
        .l2 = harness.address,
        .jwt_secret = .{ .bytes = @splat(7) },
        .rpc_address = sim.Address.ip4(.{ 10, 0, 0, 2 }, 7545),
        .http_client = harness_module.client_options,
        .p2p = .{
            .options = try p2p_options.parse(&.{
                "--p2p.listen.ip=10.0.0.2",
                "--p2p.no-discovery",
                bootnode,
            }),
            .node_secret = node_secret,
            .unsafe_block_signer = .zero,
            .seed = 3,
        },
    });
    defer node.deinit();
    _ = try node.start();
    try testing.expect(std.mem.indexOf(u8, memory.text(), "enode=") != null);
    for (0..300) |_| {
        node.tick();
        peer.transport.execute_commands();
        harness.world.run_for_ns(10 * std.time.ns_per_ms);
    }
    try testing.expectEqual(@as(u32, 1), node.network.?.peer_count());
    try testing.expect(node.signer.?.signer.?.eql(signer));
    try testing.expect(std.mem.indexOf(u8, memory.text(), "unsafe block signer from L1") != null);
    var storage: [512]u8 = undefined;
    const beacon_root: primitives.B256 = .{ .bytes = @splat(0xbb) };
    const now_s = peer_io.now_realtime_ns() / std.time.ns_per_s;
    const payload = try gossip_payload(&rollup, now_s, &storage, beacon_root);
    _ = try peer.publish_block(sequencer_key, beacon_root, payload);
    for (0..100) |_| {
        node.tick();
        peer.transport.execute_commands();
        harness.world.run_for_ns(10 * std.time.ns_per_ms);
    }
    try testing.expectEqual(@as(u64, 1), node.gossip.received);
    var rpc_buffer: [512]u8 = undefined;
    var rpc_out: std.Io.Writer = .fixed(&rpc_buffer);
    _ = node.serve_rpc(
        \\{"jsonrpc":"2.0","id":1,"method":"opp2p_peerCount","params":[]}
    , &rpc_out);
    try testing.expect(std.mem.indexOf(u8, rpc_out.buffered(), "\"connectedGossip\":1") != null);
    try testing.expectEqual(@as(u64, 0), node.gossip.undecodable);
    // Startup has not finished (no L1), so the driver does not take the block yet.
    try testing.expectEqual(@as(u64, 1), node.driver.stats.unsafe_ignored);
    peer.stop();
    while (node.busy()) harness.world.run_for_ns(std.time.ns_per_s / 10);
}

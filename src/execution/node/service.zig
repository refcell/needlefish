//! The execution node service: one heap-pinned struct that owns state, executor, pool,
//! chain, engine and the eth JSON-RPC HTTP server, driven by an injected `IO` (the
//! production backend or `SimIo` for deterministic simulation).
//!
//! `--dev-l1` mode adds a slot miner and the minimal beacon API: one block per slot at
//! `genesis_time + slot * block_time`, built from the pool through the same Engine API
//! path a consensus client uses, then immediately made head, safe and finalized.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const genesis_types = @import("../../common/genesis/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const engine_module = @import("../engine/root.zig");
const eth = @import("../rpc/eth.zig");
const engine_rpc = @import("../rpc/engine.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const http = @import("../../utilities/http/root.zig");
const io_module = @import("../../utilities/io/root.zig");
const log = @import("../../utilities/log/root.zig");
const Executor = @import("executor.zig").Executor;
const executor_module = @import("executor.zig");
const StateDb = @import("state_db.zig").StateDb;
const state_db = @import("state_db.zig");
const chain_module = @import("chain.zig");
const genesis_loader = @import("genesis.zig");
const beacon_module = @import("beacon.zig");
const consensus = @import("../../common/consensus/root.zig");
const kzg_blob = @import("../../common/crypto/kzg/root.zig").blob;

/// Long-lived KZG verification memory (decoded setup, workspace, batch scratch).
const KzgMemory = struct {
    storage: kzg_blob.Settings.Storage,
    settings: kzg_blob.Settings,
    workspace: kzg_blob.Workspace,
    batch: kzg_blob.BatchStorage(consensus.sidecar.blobs_per_tx_max),

    fn create(allocator: std.mem.Allocator) !*KzgMemory {
        const memory = try allocator.create(KzgMemory);
        errdefer allocator.destroy(memory);
        memory.settings = try kzg_blob.Settings.init(&memory.storage);
        memory.batch = .{};
        return memory;
    }

    fn verifier(memory: *KzgMemory) consensus.sidecar.KzgVerifier {
        return .{
            .settings = &memory.settings,
            .workspace = &memory.workspace,
            .batch = &memory.batch,
        };
    }
};

const Chain = chain_module.Chain;
const Engine = engine_module.Engine(Chain);
const types = engine_module.types;
const B256 = primitives.B256;

pub const Options = struct {
    http_address: io_module.Address,
    /// `--dev-l1`: mine one block per slot and serve the beacon API.
    dev_l1: bool = false,
    block_time_s: u64 = 2,
    beacon_address: ?io_module.Address = null,
    /// Engine API (plus eth_*) behind JWT authentication; both or neither.
    authrpc_address: ?io_module.Address = null,
    jwt_secret: ?jwt.Secret = null,
    /// Verify blob transaction KZG proofs on submission (needs ~1.1 MiB and a setup
    /// decode at startup; L1 mode only, since L2 has no blob transactions).
    verify_blob_proofs: bool = true,
    limits: Limits = .{},
};

/// Every bound of the node. Defaults suit a devnet; all memory is allocated at init.
pub const Limits = struct {
    state: state_db.Config = .{
        .trie = .{
            .accounts_max = 1 << 16,
            .account_nodes_max = 1 << 17,
            .storage_nodes_max = 1 << 18,
        },
        .code_bytes_max = 32 << 20,
        .codes_max = 1 << 13,
        .undo_bytes_max = 16 << 20,
    },
    /// Devnet-sized EVM bounds (a transaction exceeding one fails like out-of-gas).
    executor: executor_module.Config = .{
        .scratch_bytes = 16 << 20,
        .transactions_max = 4096,
        .evm = .{ .memory_bytes_max = 16 << 20, .code_arena_bytes = 16 << 20 },
        .limits = .{
            .accounts_max = 1 << 14,
            .slots_max = 1 << 16,
            .transient_slots_max = 1 << 15,
            .journal_entries_max = 1 << 18,
            .logs_max = 1 << 13,
            .log_data_bytes_max = 8 << 20,
            .code_bytes_max = 4 << 20,
        },
    },
    pool: txpool.Config = .{},
    chain: chain_module.Config = .{
        .store = .{ .blocks_max = 1 << 14, .bytes_max = 32 << 20 },
        .staging_bytes = 8 << 20,
    },
    beacon: beacon_module.Config = .{ .slots_max = 256, .bytes_max = 32 << 20 },
    http: http.server.Options = .{
        .connections_max = 4,
        .recv_buffer_size = 4 << 20,
        .send_buffer_size = 1 << 20,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = (4 << 20) - 16 * 1024 },
    },
    beacon_http: http.server.Options = .{
        .connections_max = 2,
        .recv_buffer_size = 16 * 1024,
        .send_buffer_size = 4 << 20,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 },
    },
    rpc_scratch_bytes: u32 = 4 << 20,
    engine: engine_rpc.Limits = .{},
    authrpc_http: http.server.Options = .{
        .connections_max = 4,
        .recv_buffer_size = 4 << 20,
        .send_buffer_size = 4 << 20,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = (4 << 20) - 16 * 1024 },
    },
};

pub fn Service(comptime IO: type) type {
    return struct {
        const Self = @This();
        const HttpServer = http.Server(IO, *Self, handle_rpc);
        const BeaconServer = http.Server(IO, *Self, handle_beacon);
        const AuthServer = http.Server(IO, *Self, handle_authrpc);

        allocator: std.mem.Allocator,
        io: *IO,
        logger: *log.Logger,
        options: Options,
        spec: chainspec.ChainSpec,
        db: StateDb,
        executor: Executor,
        pool: txpool.Pool,
        chain: Chain,
        engine: Engine,
        api: eth.Api,
        http_server: HttpServer,
        engine_api: ?engine_rpc.EngineApi = null,
        kzg: ?*KzgMemory = null,
        auth_server: ?AuthServer = null,
        beacon: ?beacon_module.Beacon = null,
        beacon_server: ?BeaconServer = null,
        miner_completion: IO.Completion = .{},
        blocks_mined: u64 = 0,
        mine_failures: u64 = 0,

        /// Builds the whole node in place (`service` must not move afterwards).
        pub fn init(
            service: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            logger: *log.Logger,
            genesis: *const genesis_types.Genesis,
            options: Options,
        ) !void {
            assert(options.block_time_s > 0);
            assert(!options.dev_l1 or options.beacon_address != null);
            assert((options.authrpc_address == null) == (options.jwt_secret == null));
            service.* = .{
                .allocator = allocator,
                .io = io,
                .logger = logger,
                .options = options,
                .spec = try chainspec.from_genesis(genesis),
                .db = undefined,
                .executor = undefined,
                .pool = undefined,
                .chain = undefined,
                .engine = undefined,
                .api = undefined,
                .http_server = undefined,
            };
            if (options.dev_l1 and service.spec.mode != .l1) return error.DevL1NeedsL1Genesis;
            try service.init_state(genesis);
            errdefer service.deinit_state();
            try service.init_servers(genesis.timestamp);
        }

        fn init_state(service: *Self, genesis: *const genesis_types.Genesis) !void {
            const allocator = service.allocator;
            const limits = &service.options.limits;
            service.db = try StateDb.init(allocator, limits.state);
            errdefer service.db.deinit(allocator);
            const header = try genesis_loader.load(allocator, &service.db, genesis);
            const spec = &service.spec;
            service.executor = try Executor.init(allocator, spec, &service.db, limits.executor);
            errdefer service.executor.deinit(allocator);
            var pool_config = limits.pool;
            pool_config.block_gas_limit = service.spec.gas_limit;
            service.pool = try txpool.Pool.init(allocator, pool_config);
            errdefer service.pool.deinit(allocator);
            service.chain = try Chain.init(
                allocator,
                &service.spec,
                &service.db,
                &service.executor,
                &header,
                limits.chain,
            );
            service.chain.pool = &service.pool;
            service.engine = Engine.init(&service.spec, &service.chain);
            assert(service.chain.head_hash().len == 32);
        }

        fn init_servers(service: *Self, genesis_time: u64) !void {
            const allocator = service.allocator;
            const limits = &service.options.limits;
            service.api = .{
                .spec = &service.spec,
                .chain = &service.chain,
                .pool = &service.pool,
                .scratch = try allocator.alloc(u8, limits.rpc_scratch_bytes),
            };
            errdefer allocator.free(service.api.scratch);
            if (service.options.verify_blob_proofs and service.spec.mode == .l1) {
                service.kzg = try KzgMemory.create(allocator);
                service.api.kzg = service.kzg.?.verifier();
            }
            errdefer if (service.kzg) |memory| allocator.destroy(memory);
            try service.http_server.init(allocator, service.io, service, limits.http);
            errdefer service.http_server.deinit();
            try service.init_authrpc();
            errdefer service.deinit_authrpc();
            if (!service.options.dev_l1) return;
            service.beacon = try beacon_module.Beacon.init(
                allocator,
                genesis_time,
                service.options.block_time_s,
                limits.beacon,
            );
            errdefer service.beacon.?.deinit(allocator);
            service.beacon_server = @as(BeaconServer, undefined);
            try service.beacon_server.?.init(allocator, service.io, service, limits.beacon_http);
        }

        fn init_authrpc(service: *Self) !void {
            if (service.options.authrpc_address == null) return;
            const limits = &service.options.limits;
            service.engine_api = try engine_rpc.EngineApi.init(
                service.allocator,
                &service.engine,
                &service.api,
                limits.engine,
            );
            errdefer service.engine_api.?.deinit(service.allocator);
            service.auth_server = @as(AuthServer, undefined);
            const server = &service.auth_server.?;
            try server.init(service.allocator, service.io, service, limits.authrpc_http);
        }

        fn deinit_authrpc(service: *Self) void {
            if (service.auth_server) |*server| server.deinit();
            if (service.engine_api) |*api| api.deinit(service.allocator);
        }

        pub fn deinit(service: *Self) void {
            if (service.beacon_server) |*server| server.deinit();
            if (service.beacon) |*beacon| beacon.deinit(service.allocator);
            service.deinit_authrpc();
            service.http_server.deinit();
            service.allocator.free(service.api.scratch);
            if (service.kzg) |memory| service.allocator.destroy(memory);
            service.deinit_state();
            service.* = undefined;
        }

        fn deinit_state(service: *Self) void {
            const allocator = service.allocator;
            service.chain.deinit(allocator);
            service.pool.deinit(allocator);
            service.executor.deinit(allocator);
            service.db.deinit(allocator);
        }

        /// Binds the servers and, in dev mode, starts the miner. Returns the RPC address.
        pub fn start(service: *Self) !io_module.Address {
            const bound = try service.http_server.listen(service.options.http_address);
            service.logger.log(.info, "node", "json-rpc listening", .{ .port = bound.port });
            if (service.auth_server) |*server| {
                const auth_bound = try server.listen(service.options.authrpc_address.?);
                service.logger.log(.info, "node", "engine api listening", .{
                    .port = auth_bound.port,
                });
            }
            if (service.beacon_server) |*server| {
                const beacon_bound = try server.listen(service.options.beacon_address.?);
                service.logger.log(.info, "node", "beacon api listening", .{
                    .port = beacon_bound.port,
                });
                service.schedule_mine();
            }
            return bound;
        }

        pub fn beacon_address(service: *const Self) ?io_module.Address {
            const server = service.beacon_server orelse return null;
            return server.address;
        }

        fn handle_rpc(
            service: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (request.method != .POST) return response.fail(405);
            const outcome = eth.Router.handle(&service.api, request.body, response.writer());
            if (outcome == .empty) response.status = 204;
        }

        fn handle_beacon(
            service: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            assert(service.options.dev_l1);
            service.beacon.?.handle(request, response);
        }

        pub fn authrpc_address(service: *const Self) ?io_module.Address {
            const server = service.auth_server orelse return null;
            return server.address;
        }

        fn handle_authrpc(
            service: *Self,
            request: *const http.Request,
            response: *http.ResponseBuilder,
        ) void {
            if (request.method != .POST) return response.fail(405);
            const header = request.headers.get("authorization") orelse return response.fail(401);
            const token = jwt.bearer_token(header) orelse return response.fail(401);
            const now_s = service.io.now_realtime_ns() / std.time.ns_per_s;
            _ = jwt.verify(service.options.jwt_secret.?, token, now_s) catch {
                return response.fail(401);
            };
            const api = &service.engine_api.?;
            const outcome = engine_rpc.Router.handle(api, request.body, response.writer());
            if (outcome == .empty) response.status = 204;
        }

        // ---- Dev L1 miner -------------------------------------------------------------

        fn next_timestamp(service: *const Self) u64 {
            const head = service.chain.header(service.chain.head_hash()).?;
            return head.timestamp + service.options.block_time_s;
        }

        fn schedule_mine(service: *Self) void {
            const due_ns = service.next_timestamp() * std.time.ns_per_s;
            const now_ns = service.io.now_realtime_ns();
            const delay_ns = if (due_ns > now_ns) due_ns - now_ns else 0;
            service.io.timeout(*Self, service, on_mine, &service.miner_completion, delay_ns);
        }

        fn on_mine(
            service: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            assert(completion == &service.miner_completion);
            result catch |err| {
                service.logger.log(.err, "miner", "timer failed", .{ .err = @errorName(err) });
                return; // Canceled at shutdown.
            };
            if (service.next_timestamp() * std.time.ns_per_s <= service.io.now_realtime_ns()) {
                service.mine_once() catch |err| {
                    service.mine_failures += 1;
                    service.beacon.?.discard_pending();
                    service.logger.log(.err, "miner", "block failed", .{ .err = @errorName(err) });
                };
            }
            service.schedule_mine();
        }

        /// Builds the next slot's block from the pool and makes it head/safe/finalized.
        pub fn mine_once(service: *Self) !void {
            assert(service.options.dev_l1);
            const spec = &service.spec;
            const parent = service.chain.head_hash();
            const timestamp = service.next_timestamp();
            var attributes = dev_attributes(spec, parent, timestamp);
            const version = types.forkchoice_version(spec, timestamp);
            const parent_choice = everything_at(.{ .bytes = parent });
            const engine = &service.engine;
            const started = try engine.forkchoice_updated(version, parent_choice, &attributes);
            if (started.payload_status.status != .valid) return error.BuildRejected;
            const built = try service.engine.get_payload(
                types.get_payload_version(spec, timestamp),
                started.payload_id.?,
            );
            try service.capture_blobs(built.block_hash);
            const head_choice = everything_at(built.block_hash);
            const applied = try service.engine.forkchoice_updated(version, head_choice, null);
            if (applied.payload_status.status != .valid) return error.HeadRejected;
            const beacon = &service.beacon.?;
            try beacon.commit_slot(beacon.slot_of(timestamp));
            service.blocks_mined += 1;
            assert(std.mem.eql(u8, &service.chain.head_hash(), &built.block_hash.bytes));
        }

        /// Copies the sidecars of the block's blob transactions out of the pool (before
        /// the forkchoice update prunes them) into the beacon's pending slot.
        fn capture_blobs(service: *Self, block_hash: B256) !void {
            const stored = service.chain.record(block_hash.bytes) orelse return error.MissingBlock;
            var transactions = stored.transactions;
            while (!transactions.is_empty()) {
                const raw = transactions.bytes() catch unreachable; // Stored by the chain.
                if (raw.len == 0 or raw[0] != 0x03) continue;
                const pooled = service.pool.get(primitives.keccak256(raw)) orelse {
                    return error.MissingSidecar;
                };
                try service.beacon.?.capture(pooled.raw);
            }
        }
    };
}

fn everything_at(hash: B256) types.ForkchoiceState {
    return .{ .head_block_hash = hash, .safe_block_hash = hash, .finalized_block_hash = hash };
}

/// Deterministic dev attributes: randao from the parent hash, zero fee recipient, no
/// withdrawals, and a beacon root derived from the timestamp.
fn dev_attributes(
    spec: *const chainspec.ChainSpec,
    parent: [32]u8,
    timestamp: u64,
) payload.PayloadAttributes {
    var stamp: [8]u8 = undefined;
    std.mem.writeInt(u64, &stamp, timestamp, .big);
    var attributes: payload.PayloadAttributes = .{
        .timestamp = timestamp,
        .prev_randao = primitives.keccak256(&parent),
        .suggested_fee_recipient = .zero,
    };
    if (spec.is_ethereum_fork_active(.shanghai, timestamp)) attributes.withdrawals = &.{};
    if (spec.is_ethereum_fork_active(.cancun, timestamp)) {
        attributes.parent_beacon_block_root = primitives.keccak256(&stamp);
    }
    return attributes;
}

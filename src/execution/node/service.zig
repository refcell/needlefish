//! The execution node service: one heap-pinned struct that owns state, executor, pool,
//! chain, engine and the eth JSON-RPC HTTP server, driven by an injected `IO` (the
//! production backend or `SimIo` for deterministic simulation).
//!
//! `--dev-l1` mode adds a slot miner and the minimal beacon API: one block per slot at
//! `genesis_time + slot * block_time`, built from the pool through the same Engine API
//! path a consensus client uses, then immediately made head, safe and finalized.

const std = @import("std");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const genesis_types = @import("../../common/genesis/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const engine_module = @import("../engine/root.zig");
const eth = @import("../rpc/eth.zig");
const filters_module = @import("../rpc/filters.zig");
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
const durable_module = @import("durable.zig");
const db_module = @import("../db/root.zig");
const io_storage = @import("../db/storage/io_storage.zig");
const consensus = @import("../../common/consensus/root.zig");
const kzg_blob = @import("../../common/crypto/kzg/root.zig").blob;
const kzg_cells = @import("../../common/crypto/kzg/root.zig").cells;

/// Long-lived KZG verification memory (decoded setups, workspaces, batch scratch) for
/// v0 blob proofs and v1 (EIP-7594) cell proofs.
const KzgMemory = struct {
    storage: kzg_blob.Settings.Storage,
    settings: kzg_blob.Settings,
    workspace: kzg_blob.Workspace,
    batch: kzg_blob.BatchStorage(consensus.sidecar.blobs_per_tx_max),
    /// Verifier-only cell settings: the FK20 columns in `cell_storage` stay untouched.
    cell_storage: kzg_cells.Settings.Storage,
    cell_settings: kzg_cells.Settings,
    cell_workspace: kzg_cells.Workspace,
    cell_batch: kzg_cells.VerifyStorage(consensus.sidecar.cells_per_ext_blob),
    cells: kzg_cells.Cells,

    fn create(allocator: std.mem.Allocator) !*KzgMemory {
        const memory = try lazy.create(allocator, KzgMemory);
        errdefer lazy.destroy(allocator, memory);
        memory.settings = try kzg_blob.Settings.init(&memory.storage);
        memory.batch = .{};
        memory.cell_settings = try kzg_cells.Settings.init_verifier(&memory.cell_storage);
        memory.cell_batch = .{};
        assert(memory.cell_settings.columns == null);
        return memory;
    }

    fn verifier(memory: *KzgMemory) consensus.sidecar.KzgVerifier {
        return .{
            .settings = &memory.settings,
            .workspace = &memory.workspace,
            .batch = &memory.batch,
            .cells = .{
                .settings = &memory.cell_settings,
                .workspace = &memory.cell_workspace,
                .batch = &memory.cell_batch,
                .cells = &memory.cells,
            },
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
    /// Durable state file (journal + checkpoints); null keeps everything in memory.
    data_path: ?[]const u8 = null,
    /// Distinguishes formats of the same file (low 64 bits of the format id).
    format_nonce: u64 = 0,
    /// `--proofs-history.window`: blocks of historical state served from memory (state
    /// reads and eth_getProof at older blocks); 0 disables the window.
    proofs_history_window: u32 = 0,
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
    /// Trie node versions one block writes to the historical window, at most; sizes the
    /// window (see `db.history.Store` "Sizing") together with the state trie bounds.
    history_versions_per_block: u32 = 1 << 10,
    /// `debug_executionWitness` buffers (null disables it); see `witness_config` for the
    /// derived fields. Every large buffer is reserved at init and committed on first touch
    /// (`lazy_alloc`); only the hash-map indexes are written at init (their metadata in
    /// ReleaseFast, all of them in safe builds, where `Allocator.alloc` fills memory).
    /// - keys: 4096 accounts + 16384 slots. Each witness key is at least 20 bytes, at least
    ///   45 JSON bytes. Below the executor's per-block bounds: heavier blocks fail
    ///   `KeysFull`.
    /// - sparse.nodes_max 16384: candidate proof nodes (a superset of the witness nodes),
    ///   ~5 per touched key below a 64k-account trie, shared near the root. Bytes: 4 MiB
    ///   (256 B average; a full branch is 532 B). trie_nodes_max: 4 sparse nodes per
    ///   candidate (decoded branches materialize unresolved children).
    /// - codes: 512 contracts read; 8 MiB is 512 x 16 KiB average (EIP-170 max is 24 KiB).
    /// - depth_max 1024: `state.undo_blocks_max`, the deepest in-memory unwind.
    witness: ?db_module.witness_block.Config = .{
        .builder = .{
            .sparse = .{
                .nodes_max = 1 << 14,
                .node_bytes_max = 4 << 20,
                .codes_max = 512,
                .code_bytes_max = 8 << 20,
                .headers_max = db_module.witness_block.headers_max,
                .trie_nodes_max = 1 << 16,
                .storage_tries_max = 1024,
            },
            .keys = .{
                .accounts_max = 1 << 12,
                .slots_max = 1 << 14,
                .codes_max = 512,
                .block_numbers_max = db_module.witness_block.headers_max,
            },
        },
        .witness = undefined,
        .overlay = undefined,
        .changeset = undefined,
        .depth_max = 1024,
    },
    /// Bound on a `debug_executionWitness` result's JSON: an HTTP large send buffer (16 MiB)
    /// less the head reserve (1 KiB) and the JSON-RPC envelope (id up to ~1 KiB). A
    /// storage-heavy witness is ~2.6 MB of JSON. Larger witnesses fail with "witness too
    /// large" instead of an overflowing response. Raising it needs a larger
    /// `http.large_send_buffer_size` too.
    witness_response_bytes_max: u32 = (16 << 20) - (2 << 10),
    http: http.server.Options = .{
        // Devnet: each consensus node holds two (watcher + provider), plus the batcher.
        .connections_max = 16,
        .recv_buffer_size = 4 << 20,
        .send_buffer_size = 1 << 20,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = (4 << 20) - 16 * 1024 },
        // Responses sized up front past 1 MiB (witnesses): 32 MiB reserved, committed only
        // as written; two connections can send one at a time.
        .large_send_buffers_max = 2,
        .large_send_buffer_size = 16 << 20,
    },
    beacon_http: http.server.Options = .{
        .connections_max = 8,
        .recv_buffer_size = 16 * 1024,
        .send_buffer_size = 4 << 20,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = 1024 },
    },
    rpc_scratch_bytes: u32 = 4 << 20,
    /// Durable database layout; `state` and `changeset` are derived from `state` above.
    durable: db_module.database.Config = .{
        .engine = .{
            .journal_size_bytes = 64 << 20,
            .checkpoint_zone_size_bytes = 48 << 20,
            .entry_body_size_max = 2 << 20,
        },
        .state = undefined,
        .chain = .{
            .blocks_max = 1024,
            .bytes_max = 16 << 20,
            .transactions_max = 1 << 16,
            .canonical_max = 1 << 16,
            .reorg_depth_max = 64,
        },
        .changeset = undefined,
        .queue_entries_max = 8,
        .checkpoint_staging_bytes = 40 << 20,
    },
    /// Storage callbacks run from a timer at this interval.
    storage_tick_ns: u64 = 2 * std.time.ns_per_ms,
    engine: engine_rpc.Limits = .{},
    authrpc_http: http.server.Options = .{
        .connections_max = 4,
        .recv_buffer_size = 4 << 20,
        .send_buffer_size = 4 << 20,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = (4 << 20) - 16 * 1024 },
    },

    /// The witness generator's config, null when the method is disabled. `overlay` and
    /// `changeset` hold one block's writes (the `state` block limits). The output `witness`
    /// follows the response bound: hex doubles every byte, so no list can usefully hold
    /// more than half of it, and its counts are the builder's.
    pub fn witness_config(limits: *const Limits) ?db_module.witness_block.Config {
        var config = limits.witness orelse return null;
        const response_bytes_max = limits.witness_response_bytes_max;
        assert(response_bytes_max > 0);
        const keys = &config.builder.keys;
        config.response_bytes_max = response_bytes_max;
        config.witness = .{
            .state_nodes_max = config.builder.sparse.nodes_max,
            .state_bytes_max = @min(config.builder.sparse.node_bytes_max, response_bytes_max / 2),
            .codes_max = keys.codes_max,
            .code_bytes_max = @min(config.builder.sparse.code_bytes_max, response_bytes_max / 2),
            .keys_max = keys.accounts_max + keys.slots_max,
            .headers_max = db_module.witness_block.headers_max,
            .header_bytes_max = response_bytes_max / 2,
        };
        config.overlay = .{
            .accounts_max = limits.state.block_accounts_max,
            .slots_max = limits.state.block_slots_max,
            .codes_max = limits.state.block_codes_max,
        };
        config.changeset = .{
            .accounts_max = limits.state.block_accounts_max,
            .storage_max = limits.state.block_slots_max,
            .codes_max = limits.state.block_codes_max,
            .code_bytes_max = limits.state.block_code_bytes_max,
        };
        assert(config.depth_max > 0);
        assert(config.builder.keys.accounts_max > 0);
        return config;
    }
};

/// Sizes the historical window so `commit_block` never runs out (`db.history.Store`
/// "Sizing"): every live trie node once, plus `window` blocks of the per-block bound.
/// Dense branches (large versions) are at most a quarter of either.
pub fn history_config(limits: *const Limits, window: u32) db_module.history.Config {
    assert(window > 0);
    const trie = limits.state.trie;
    const nodes: u64 = @as(u64, trie.account_nodes_max) + trie.storage_nodes_max;
    const per_block: u64 = limits.history_versions_per_block;
    const total = nodes + @as(u64, window) * per_block;
    assert(total <= std.math.maxInt(u32));
    const config: db_module.history.Config = .{
        .window_blocks = window,
        .paths_max = @intCast(total),
        .small_versions_max = @intCast(total),
        .large_versions_max = @intCast(total / 4),
        .prune_per_commit = limits.history_versions_per_block,
    };
    assert(config.paths_max >= nodes);
    return config;
}

pub fn Service(comptime IO: type) type {
    return struct {
        const Self = @This();
        const HttpServer = http.Server(IO, *Self, handle_rpc);
        const BeaconServer = http.Server(IO, *Self, handle_beacon);
        const AuthServer = http.Server(IO, *Self, handle_authrpc);
        const Storage = io_storage.IoStorageType(IO);
        const DurableState = durable_module.Durable(Storage);

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
        filters: ?*filters_module.Filters = null,
        history: ?*db_module.history.Store = null,
        auth_server: ?AuthServer = null,
        beacon: ?beacon_module.Beacon = null,
        beacon_server: ?BeaconServer = null,
        miner_completion: IO.Completion = .{},
        storage: ?*Storage = null,
        storage_fd: ?IO.Fd = null,
        durable: ?*DurableState = null,
        storage_completion: IO.Completion = .{},
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
            if (service.options.data_path) |path| return service.init_durable(genesis, path);
            const allocator = service.allocator;
            service.db = try StateDb.init(allocator, service.options.limits.state);
            errdefer service.db.deinit(allocator);
            const header = try genesis_loader.load(allocator, &service.db, genesis);
            try service.init_execution(&header, false);
        }

        /// Executor, pool, chain and engine over `db`, which holds genesis (or, when
        /// `restoring`, a recovered head).
        fn init_execution(service: *Self, header: *const consensus.Header, restoring: bool) !void {
            const allocator = service.allocator;
            const limits = &service.options.limits;
            const spec = &service.spec;
            service.executor = try Executor.init(allocator, spec, &service.db, limits.executor);
            errdefer service.executor.deinit(allocator);
            var pool_config = limits.pool;
            pool_config.block_gas_limit = service.spec.gas_limit;
            service.pool = try txpool.Pool.init(allocator, pool_config);
            errdefer service.pool.deinit(allocator);
            var chain_config = limits.chain;
            chain_config.restoring = restoring;
            service.chain = try Chain.init(
                allocator,
                &service.spec,
                &service.db,
                &service.executor,
                header,
                chain_config,
            );
            service.chain.pool = &service.pool;
            service.engine = Engine.init(&service.spec, &service.chain);
            assert(service.chain.head_hash().len == 32);
        }

        /// Opens (or formats) the durable state file, then bootstraps genesis into it or
        /// restores the retained chain, and starts the storage tick.
        fn init_durable(
            service: *Self,
            genesis: *const genesis_types.Genesis,
            path: []const u8,
        ) !void {
            const allocator = service.allocator;
            const limits = &service.options.limits;
            var config = limits.durable;
            config.state = StateDb.state_config(limits.state);
            // A durable node's history window lives in the database (fed by its head moves).
            const window = service.options.proofs_history_window;
            if (window > 0) config.history = history_config(limits, window);
            config.changeset = .{
                .accounts_max = limits.state.block_accounts_max,
                .storage_max = limits.state.block_slots_max,
                .codes_max = limits.state.block_codes_max,
                .code_bytes_max = limits.state.block_code_bytes_max,
            };
            const header = try genesis_header(allocator, genesis);
            const fd = try service.io.open_file(path, .create);
            service.storage_fd = fd;
            const storage = try allocator.create(Storage);
            errdefer allocator.destroy(storage);
            storage.* = try Storage.init(allocator, service.io, fd, .{
                .size_bytes = config.engine.size_bytes(),
            });
            service.storage = storage;
            const hash = header.hash().bytes;
            const nonce = service.options.format_nonce;
            const durable = try DurableState.create(allocator, storage, config, hash, nonce);
            service.durable = durable;
            try service.open_durable();
            const fresh = !durable.has_head();
            if (fresh) _ = try durable.bootstrap(allocator, genesis, &header);
            service.db = try StateDb.init_shared(allocator, limits.state, durable.state());
            try service.init_execution(&header, !fresh);
            if (!fresh) try service.restore_chain();
            service.chain.journal = durable.journal();
            service.logger.log(.info, "node", "durable state ready", .{
                .fresh = fresh,
                .head = service.chain.store.ref(service.chain.head_hash()).?.number,
            });
            service.schedule_storage_tick();
        }

        fn genesis_header(
            allocator: std.mem.Allocator,
            genesis: *const genesis_types.Genesis,
        ) !consensus.Header {
            const root = try genesis.compute_state_root(allocator);
            if (genesis.state_root) |expected| {
                if (!std.mem.eql(u8, &expected.bytes, &root.bytes)) return error.StateRootMismatch;
            }
            return genesis.header(allocator, root);
        }

        /// Drives the storage until the database is open (startup only).
        fn open_durable(service: *Self) !void {
            const durable = service.durable.?;
            durable.start();
            var waited_ms: u32 = 0;
            while (durable.phase == .opening or durable.phase == .formatting) : (waited_ms += 1) {
                if (waited_ms == 600_000) return error.DurableOpenTimeout;
                try service.io.run_for_ns(std.time.ns_per_ms);
                service.storage.?.tick();
                durable.poll();
            }
            if (durable.phase != .ready) {
                service.logger.log(.err, "node", "durable state open failed", .{
                    .reason = if (durable.start_error) |e| @errorName(e) else "unknown",
                });
                return error.DurableOpenFailed;
            }
        }

        fn restore_chain(service: *Self) !void {
            const allocator = service.allocator;
            const durable = service.durable.?;
            const blocks_max = durable.database.config.chain.blocks_max;
            const records = try allocator.alloc([]const u8, blocks_max);
            defer allocator.free(records);
            for (durable.retained(records)) |record| try service.chain.restore(record);
        }

        fn schedule_storage_tick(service: *Self) void {
            const delay_ns = service.options.limits.storage_tick_ns;
            const completion = &service.storage_completion;
            service.io.timeout(*Self, service, on_storage_tick, completion, delay_ns);
        }

        fn on_storage_tick(
            service: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            assert(completion == &service.storage_completion);
            result catch |err| {
                const name = @errorName(err);
                service.logger.log(.warn, "node", "storage tick failed", .{ .err = name });
            };
            service.storage.?.process(); // Inside an IO callback: no re-entrant io.tick.
            service.durable.?.poll();
            service.schedule_storage_tick();
        }

        fn init_servers(service: *Self, genesis_time: u64) !void {
            const allocator = service.allocator;
            const limits = &service.options.limits;
            service.api = .{
                .spec = &service.spec,
                .chain = &service.chain,
                .pool = &service.pool,
                .scratch = try lazy.alloc(allocator, u8, limits.rpc_scratch_bytes),
            };
            errdefer lazy.free(allocator, service.api.scratch);
            const filters = try allocator.create(filters_module.Filters);
            filters.* = .{};
            service.filters = filters;
            service.api.filters = filters;
            errdefer allocator.destroy(filters);
            if (service.options.verify_blob_proofs and service.spec.mode == .l1) {
                service.kzg = try KzgMemory.create(allocator);
                service.api.kzg = service.kzg.?.verifier();
            }
            errdefer if (service.kzg) |memory| lazy.destroy(allocator, memory);
            try service.init_witness();
            errdefer service.deinit_witness();
            try service.init_history();
            errdefer service.deinit_history();
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

        /// The execution witness generator, bound to the node's state.
        fn init_witness(service: *Self) !void {
            const config = service.options.limits.witness_config() orelse return;
            const allocator = service.allocator;
            const generator = try allocator.create(db_module.witness_block.Generator);
            errdefer allocator.destroy(generator);
            generator.* = try .init(allocator, service.db.state, config);
            service.api.witness = generator;
            assert(generator.state == service.chain.db.state);
        }

        /// The in-memory historical proofs window, started at the current state (durable
        /// nodes keep theirs in the database instead, see `init_durable`).
        fn init_history(service: *Self) !void {
            const window = service.options.proofs_history_window;
            if (window == 0) return;
            if (service.options.data_path != null) return; // The database keeps it.
            const allocator = service.allocator;
            const store = try allocator.create(db_module.history.Store);
            errdefer allocator.destroy(store);
            store.* = try .init(allocator, history_config(&service.options.limits, window));
            errdefer store.deinit(allocator);
            try service.db.trie().track_changes(allocator);
            service.history = store;
            try service.chain.attach_history(store);
            assert(service.chain.history == store);
        }

        fn deinit_history(service: *Self) void {
            const store = service.history orelse return;
            service.chain.history = null;
            store.deinit(service.allocator);
            service.allocator.destroy(store);
            service.history = null;
        }

        fn deinit_witness(service: *Self) void {
            const generator = service.api.witness orelse return;
            generator.deinit(service.allocator);
            service.allocator.destroy(generator);
            service.api.witness = null;
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
            service.deinit_witness();
            service.deinit_history();
            lazy.free(service.allocator, service.api.scratch);
            if (service.filters) |filters| service.allocator.destroy(filters);
            if (service.kzg) |memory| lazy.destroy(service.allocator, memory);
            service.deinit_state();
            service.* = undefined;
        }

        fn deinit_state(service: *Self) void {
            const allocator = service.allocator;
            service.chain.deinit(allocator);
            service.pool.deinit(allocator);
            service.executor.deinit(allocator);
            service.db.deinit(allocator);
            if (service.durable) |durable| durable.destroy(allocator);
            if (service.storage) |storage| {
                storage.deinit(allocator);
                allocator.destroy(storage);
            }
            if (service.storage_fd) |fd| service.io.close_now(fd);
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

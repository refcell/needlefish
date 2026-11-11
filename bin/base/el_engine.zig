//! The Engine API of `base el-run` (`--engine.addr`, `--engine.jwt`): lets `base consensus`
//! in verifier mode drive the stateful node, so derived safe attributes are consolidated
//! against blocks el-run itself executed, and the safe and finalized heads are tracked here.
//!
//! el-run takes its blocks from devp2p peers and does not execute engine payloads; the API
//! judges them against what it executed:
//! - `engine_newPayloadV1..V4`: the payload must hash to its `blockHash` (else INVALID). At or
//!   below the head, VALID when el-run's block at that number has that hash and INVALID with a
//!   loud `ENGINE DIVERGENCE` report when not; above the head SYNCING. A block older than
//!   both the ring and the database's canonical index answers SYNCING (cannot judge).
//! - `engine_forkchoiceUpdatedV1..V3`: VALID when the head is a block el-run executed and
//!   the safe and finalized blocks (zero: unset) are known ancestors; the labels are then
//!   recorded. SYNCING when any of them is unknown; -38002 when they are out of order. No
//!   payload building: attributes on a VALID update fail with -38003.
//! - `eth_getBlockByNumber` (numbers, `latest`, `pending`, `safe`, `finalized`, `earliest`)
//!   and `eth_getBlockByHash`, with full transaction objects or hashes, from the block ring
//!   (`el_ring.zig`). A block that el-run executed but no longer holds is an RPC error
//!   (-32000, never a wrong or empty block); a block above the head or an unknown hash is
//!   `null`.
//! - Until a forkchoice update names them, `safe` and `finalized` answer an anchor: the ring
//!   block `min(anchor_depth_max, count / 2)` below the newest, pinned at first use. The
//!   consensus node's startup walk then stops there, with enough blocks below it for its
//!   reset walk-back (one channel timeout of L1 origins). Until the ring holds
//!   `2 * anchor_depth_max` blocks (or is full by bytes) they answer a "warming up" error.
//! - `engine_exchangeCapabilities`, `engine_getClientVersionV1`, `eth_chainId`,
//!   `eth_blockNumber`. Everything else (`engine_getPayload*`, `eth_getProof`, state reads)
//!   is method-not-found: the verifier does not need it on Isthmus+ chains.
//!
//! Single-threaded: the HTTP server runs on its own completion IO that el-run drives only
//! between blocks (`poll`) and during the idle wait at the tip (`wait`), so a request never
//! runs while the runner executes or commits a block.

const std = @import("std");
const base = @import("base");
const el_ring = @import("el_ring.zig");

const json = base.utilities.json;
const rpc = base.utilities.rpc;
const http = base.utilities.http;
const jwt = base.utilities.jwt;
const io_module = base.utilities.io;
const engine_types = base.execution.engine.types;
const engine_block = base.execution.engine.block;
const codec = base.execution.rpc.engine_json;
const format = base.execution.rpc.format;
const consensus = base.common.consensus;
const rlp = base.common.rlp;
const ChainSpec = base.execution.chainspec.ChainSpec;
const ChainConfig = base.common.chains.ChainConfig;
const rollup_json = base.consensus.protocol.rollup_json;
const rollup_config_for = base.consensus.derive_check.start.rollup_config_for;
const Io = std.Io;
const assert = std.debug.assert;

const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Version = engine_types.Version;
const PayloadStatus = engine_types.PayloadStatus;
const Hash = [32]u8;

/// Deepest anchor below the newest block (about 27 minutes of 200 ms blocks).
pub const anchor_depth_max = 8192;
/// Largest `newPayload` request body and decoded payload.
pub const payload_bytes_max = 16 << 20;
const transactions_max = 1 << 14;

pub const Flags = struct {
    addr: ?[]const u8 = null,
    jwt: ?[]const u8 = null,
    ring_blocks: u32 = 16_384,
    ring_mib: u32 = 512,
    /// Where to write the chain's rollup.json for `base consensus --rollup-config`.
    rollup_out: ?[]const u8 = null,

    /// Parses one `--engine.*` flag; false when `name` is not an engine flag.
    pub fn parse(flags: *Flags, name: []const u8, value: []const u8) error{InvalidArguments}!bool {
        const eql = std.mem.eql;
        if (eql(u8, name, "--engine.addr")) {
            flags.addr = value;
        } else if (eql(u8, name, "--engine.jwt")) {
            flags.jwt = value;
        } else if (eql(u8, name, "--engine.ring-blocks")) {
            flags.ring_blocks = std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidArguments;
            if (flags.ring_blocks < 2) return error.InvalidArguments;
        } else if (eql(u8, name, "--engine.rollup-out")) {
            flags.rollup_out = value;
        } else if (eql(u8, name, "--engine.ring-mb")) {
            flags.ring_mib = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (flags.ring_mib == 0 or flags.ring_mib > 64 * 1024) return error.InvalidArguments;
        } else return false;
        assert(std.mem.startsWith(u8, name, "--engine."));
        return true;
    }

    /// The address and the secret go together.
    pub fn valid(flags: *const Flags) bool {
        return (flags.addr == null) == (flags.jwt == null);
    }

    pub fn ring_options(flags: *const Flags) el_ring.Options {
        assert(flags.ring_blocks >= 2);
        return .{
            .blocks_max = flags.ring_blocks,
            .bytes_max = @as(u64, flags.ring_mib) << 20,
            .transactions_max = transactions_max,
        };
    }
};

pub const Label = struct { number: u64, hash: Hash };

/// el-run's chain beyond the ring: the database head and its canonical index (headers of the
/// last `blocks_max` blocks, no bodies). Only called between blocks.
pub const Chain = struct {
    context: *anyopaque,
    head_fn: *const fn (context: *anyopaque) Label,
    canonical_hash_fn: *const fn (context: *anyopaque, number: u64) ?Hash,
    number_of_fn: *const fn (context: *anyopaque, hash: Hash) ?u64,

    fn head(chain: Chain) Label {
        return chain.head_fn(chain.context);
    }
};

/// The `Chain` of a `to_disk` database (`head_info`, `chain.canonical_hash`, `chain.meta`).
pub fn database_chain(comptime Database: type, db: *Database) Chain {
    const adapter = struct {
        fn database(context: *anyopaque) *Database {
            return @ptrCast(@alignCast(context));
        }

        fn head(context: *anyopaque) Label {
            const info = database(context).head_info;
            assert(info.present);
            return .{ .number = info.number, .hash = info.hash };
        }

        fn canonical_hash(context: *anyopaque, number: u64) ?Hash {
            return database(context).chain.canonical_hash(number);
        }

        fn number_of(context: *anyopaque, hash: Hash) ?u64 {
            const chain = &database(context).chain;
            const meta = chain.meta(hash) orelse return null;
            const canonical = chain.canonical_hash(meta.number) orelse return null;
            if (!std.mem.eql(u8, &canonical, &hash)) return null;
            return meta.number;
        }
    };
    return .{
        .context = db,
        .head_fn = adapter.head,
        .canonical_hash_fn = adapter.canonical_hash,
        .number_of_fn = adapter.number_of,
    };
}

pub const Stats = struct {
    requests: u64 = 0,
    unauthorized: u64 = 0,
    payloads_valid: u64 = 0,
    payloads_syncing: u64 = 0,
    /// At or below the head but older than the ring and the canonical index.
    payloads_unjudged: u64 = 0,
    /// The payload does not hash to its `blockHash`.
    payloads_malformed: u64 = 0,
    /// The payload's hash differs from el-run's block at that number.
    divergences: u64 = 0,
    forkchoice_valid: u64 = 0,
    forkchoice_syncing: u64 = 0,
    /// Reads of an executed block that left the ring.
    ring_misses: u64 = 0,
};

/// A hash in a forkchoice state: zero (unset), unknown, or an executed block.
const Known = union(enum) { unset, unknown, block: Label };

pub const Engine = struct {
    spec: *const ChainSpec,
    chain_id: u64,
    secret: jwt.Secret,
    chain: Chain,
    ring: el_ring.Ring,
    /// Decoding space of one `newPayload`.
    space: codec.Space,
    /// Transaction slices of one ring read.
    scratch: [][]const u8,
    /// The labels of the last VALID forkchoice update (null: unset).
    head: ?Label = null,
    safe: ?Label = null,
    finalized: ?Label = null,
    /// What `safe` and `finalized` answer while unset.
    anchor: ?Label = null,
    /// Wall clock seconds for JWT `iat` checks, set by the owner before serving.
    now_s: u64 = 0,
    message_buffer: [256]u8 = undefined,
    stats: Stats = .{},

    /// `engine` must not move afterwards (the server keeps a pointer).
    pub fn init(
        engine: *Engine,
        allocator: std.mem.Allocator,
        spec: *const ChainSpec,
        secret: jwt.Secret,
        chain: Chain,
        ring_options: el_ring.Options,
    ) !void {
        assert(ring_options.transactions_max <= transactions_max);
        var ring = try el_ring.Ring.init(allocator, ring_options);
        errdefer ring.deinit(allocator);
        const bytes = try base.utilities.lazy_alloc.alloc(allocator, u8, payload_bytes_max);
        errdefer base.utilities.lazy_alloc.free(allocator, bytes);
        const transactions = try allocator.alloc([]const u8, transactions_max);
        errdefer allocator.free(transactions);
        const withdrawals = try allocator.alloc(engine_types.Withdrawal, 16);
        errdefer allocator.free(withdrawals);
        const hashes = try allocator.alloc(base.common.primitives.B256, 16);
        errdefer allocator.free(hashes);
        const scratch = try allocator.alloc([]const u8, transactions_max);
        engine.* = .{
            .spec = spec,
            .chain_id = spec.chain_id,
            .secret = secret,
            .chain = chain,
            .ring = ring,
            .space = .{
                .bytes = bytes,
                .transactions = transactions,
                .withdrawals = withdrawals,
                .hashes = hashes,
            },
            .scratch = scratch,
        };
        assert(engine.ring.count == 0);
    }

    pub fn deinit(engine: *Engine, allocator: std.mem.Allocator) void {
        allocator.free(engine.scratch);
        allocator.free(engine.space.hashes);
        allocator.free(engine.space.withdrawals);
        allocator.free(engine.space.transactions);
        base.utilities.lazy_alloc.free(allocator, engine.space.bytes);
        engine.ring.deinit(allocator);
        engine.* = undefined;
    }

    /// The per-block hook: `block` was just executed and committed as the database head.
    pub fn on_block(engine: *Engine, block: *const el_ring.Block) void {
        const head = engine.chain.head();
        assert(head.number == block.number);
        assert(std.mem.eql(u8, &head.hash, &block.hash));
        engine.ring.push(block) catch |err| switch (err) {
            error.BlockTooLarge => std.debug.print(
                "el-run engine: block {d} is larger than the whole ring; ring restarted\n",
                .{block.number},
            ),
        };
    }

    /// el-run's hash at `number`: the ring, else the database's canonical index.
    fn hash_at(engine: *const Engine, number: u64) ?Hash {
        return engine.ring.hash_at(number) orelse engine.chain.canonical_hash_fn(
            engine.chain.context,
            number,
        );
    }

    fn known(engine: *const Engine, hash: Hash) Known {
        if (std.mem.allEqual(u8, &hash, 0)) return .unset;
        const number = engine.ring.number_of(hash) orelse
            engine.chain.number_of_fn(engine.chain.context, hash) orelse return .unknown;
        assert(std.mem.eql(u8, &engine.hash_at(number).?, &hash));
        return .{ .block = .{ .number = number, .hash = hash } };
    }

    /// `newPayload` after the version checks: judges the payload against el-run's block.
    pub fn payload_status(
        engine: *Engine,
        payload: *const engine_types.ExecutionPayload,
        params: *const engine_types.NewPayloadParams,
    ) PayloadStatus {
        _ = engine_block.ensure_well_formed(engine.spec, payload, params) catch |err| {
            engine.stats.payloads_malformed += 1;
            return .invalid(null, @errorName(err));
        };
        const number = payload.block_number;
        if (number > engine.chain.head().number) {
            engine.stats.payloads_syncing += 1;
            return .syncing;
        }
        const ours = engine.hash_at(number) orelse {
            engine.stats.payloads_unjudged += 1;
            return .syncing;
        };
        if (std.mem.eql(u8, &ours, &payload.block_hash.bytes)) {
            engine.stats.payloads_valid += 1;
            return .valid(payload.block_hash);
        }
        engine.stats.divergences += 1;
        report(
            "ENGINE DIVERGENCE block {d}: newPayload hash {x}, el-run executed {x}\n",
            .{ number, payload.block_hash.bytes, ours },
        );
        const parent = if (number == 0) null else engine.hash_at(number - 1);
        const parent_ours = parent != null and
            std.mem.eql(u8, &parent.?, &payload.parent_hash.bytes);
        const latest_valid: ?base.common.primitives.B256 =
            if (parent_ours) payload.parent_hash else null;
        return .invalid(latest_valid, "block hash differs from the block el-run executed");
    }

    /// Applies a forkchoice state (no attributes).
    pub fn forkchoice(
        engine: *Engine,
        state: *const engine_types.ForkchoiceState,
    ) error{InvalidForkchoiceState}!PayloadStatus {
        const head = switch (engine.known(state.head_block_hash.bytes)) {
            .block => |label| label,
            .unset, .unknown => return engine.forkchoice_syncing(),
        };
        const safe = engine.known(state.safe_block_hash.bytes);
        const finalized = engine.known(state.finalized_block_hash.bytes);
        if (safe == .unknown or finalized == .unknown) return engine.forkchoice_syncing();
        const safe_number = if (safe == .block) safe.block.number else 0;
        const finalized_number = if (finalized == .block) finalized.block.number else 0;
        if (safe_number > head.number) return error.InvalidForkchoiceState;
        if (finalized_number > safe_number and safe == .block) return error.InvalidForkchoiceState;
        if (finalized_number > head.number) return error.InvalidForkchoiceState;
        engine.head = head;
        engine.safe = if (safe == .block) safe.block else null;
        engine.finalized = if (finalized == .block) finalized.block else null;
        engine.stats.forkchoice_valid += 1;
        assert(engine.head != null);
        return .valid(.{ .bytes = head.hash });
    }

    fn forkchoice_syncing(engine: *Engine) PayloadStatus {
        engine.stats.forkchoice_syncing += 1;
        return .syncing;
    }

    /// A forkchoice label while the ring holds its block. A label whose block left the ring
    /// is dropped, so `safe`/`finalized` answer the anchor again: a consensus node restarted
    /// after its labeled blocks aged out would otherwise read a block el-run cannot serve.
    fn held(engine: *Engine, label: *?Label) ?Label {
        const found = label.* orelse return null;
        const hash = engine.ring.hash_at(found.number);
        if (hash != null and std.mem.eql(u8, &hash.?, &found.hash)) return found;
        label.* = null;
        report("el-run engine: forkchoice label block {d} left the ring; answering the " ++
            "anchor until the next forkchoice update\n", .{found.number});
        assert(label.* == null);
        return null;
    }

    /// What an unset `safe`/`finalized` answers: the pinned anchor while the ring still holds
    /// it, else a new one; null with an empty ring.
    fn anchor_label(engine: *Engine) ?Label {
        if (engine.anchor) |pinned| {
            const hash = engine.ring.hash_at(pinned.number);
            if (hash != null and std.mem.eql(u8, &hash.?, &pinned.hash)) return pinned;
        }
        const newest = engine.ring.newest_number() orelse return null;
        const depth = @min(anchor_depth_max, engine.ring.count / 2);
        const number = newest - depth;
        const pinned: Label = .{ .number = number, .hash = engine.ring.hash_at(number).? };
        engine.anchor = pinned;
        report("el-run engine: no forkchoice yet: safe and finalized answer block {d}" ++
            " ({x}), {d} below the newest\n", .{ number, pinned.hash, depth });
        return pinned;
    }

    pub fn summary(engine: *const Engine) void {
        const ring = &engine.ring;
        std.debug.print("engine: head {?d} safe {?d} finalized {?d} anchor {?d}, " ++
            "ring {d} blocks {?d}..{?d} {d} MiB, requests {d} unauthorized {d}, " ++
            "new payloads valid {d} syncing {d} unjudged {d} malformed {d}, " ++
            "divergences {d}, ring misses {d}\n", .{
            label_number(engine.head),
            label_number(engine.safe),
            label_number(engine.finalized),
            label_number(engine.anchor),
            ring.count,
            ring.oldest_number(),
            ring.newest_number(),
            ring.bytes_used >> 20,
            engine.stats.requests,
            engine.stats.unauthorized,
            engine.stats.payloads_valid,
            engine.stats.payloads_syncing,
            engine.stats.payloads_unjudged,
            engine.stats.payloads_malformed,
            engine.stats.divergences,
            engine.stats.ring_misses,
        });
    }

    /// The HTTP handler: JWT-authenticated JSON-RPC (`Router`).
    pub fn handle_http(
        engine: *Engine,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        engine.stats.requests += 1;
        if (request.method != .POST) return response.fail(405);
        if (!engine.authorized(request)) {
            engine.stats.unauthorized += 1;
            return response.fail(401);
        }
        const outcome = Router.handle(engine, request.body, response.writer());
        if (outcome == .empty) response.status = 204;
    }

    fn authorized(engine: *const Engine, request: *const http.Request) bool {
        const header = request.headers.get("authorization") orelse return false;
        const token = jwt.bearer_token(header) orelse return false;
        _ = jwt.verify(engine.secret, token, engine.now_s) catch return false;
        return true;
    }
};

/// Operator reports; quiet in unit tests, which check the counters instead.
fn report(comptime text: []const u8, arguments: anytype) void {
    if (@import("builtin").is_test) return;
    std.debug.print(text, arguments);
}

fn label_number(label: ?Label) ?u64 {
    return if (label) |found| found.number else null;
}

// ---- JSON-RPC methods ----------------------------------------------------------------

const engine_methods = [_]rpc.Method(*Engine){
    .{ .name = "engine_exchangeCapabilities", .handler = exchange_capabilities },
    .{ .name = "engine_getClientVersionV1", .handler = client_version },
    .{ .name = "engine_forkchoiceUpdatedV1", .handler = forkchoice_updated },
    .{ .name = "engine_forkchoiceUpdatedV2", .handler = forkchoice_updated },
    .{ .name = "engine_forkchoiceUpdatedV3", .handler = forkchoice_updated },
    .{ .name = "engine_newPayloadV1", .handler = new_payload(.v1) },
    .{ .name = "engine_newPayloadV2", .handler = new_payload(.v2) },
    .{ .name = "engine_newPayloadV3", .handler = new_payload(.v3) },
    .{ .name = "engine_newPayloadV4", .handler = new_payload(.v4) },
};

const eth_methods = [_]rpc.Method(*Engine){
    .{ .name = "eth_chainId", .handler = chain_id },
    .{ .name = "eth_blockNumber", .handler = block_number },
    .{ .name = "eth_getBlockByNumber", .handler = get_block_by_number },
    .{ .name = "eth_getBlockByHash", .handler = get_block_by_hash },
};

pub const methods = engine_methods ++ eth_methods;
pub const Router = rpc.Router(*Engine, &methods);

fn fail_engine(call: *Call, err: engine_types.EngineError) HandlerError {
    return call.fail(@backingInt(engine_types.error_code(err)), @errorName(err));
}

fn exchange_capabilities(_: *Engine, call: *Call) HandlerError!void {
    _ = try call.params.raw(); // The consensus client's list; ours does not depend on it.
    try call.params.finish();
    try call.writer.begin_array();
    for (engine_methods) |method| try call.writer.string(method.name);
    try call.writer.end_array();
}

fn client_version(_: *Engine, call: *Call) HandlerError!void {
    _ = try call.params.optional_raw();
    try call.params.finish();
    const w = call.writer;
    const fields = [_][2][]const u8{
        .{ "code", "NF" },
        .{ "name", "needlefish-el-run" },
        .{ "version", base.build_options.version },
        .{ "commit", "0x00000000" },
    };
    try w.begin_array();
    try w.begin_object();
    for (fields) |field| {
        try w.key(field[0]);
        try w.string(field[1]);
    }
    try w.end_object();
    try w.end_array();
}

fn chain_id(engine: *Engine, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(engine.chain_id);
}

fn block_number(engine: *Engine, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(engine.chain.head().number);
}

fn forkchoice_updated(engine: *Engine, call: *Call) HandlerError!void {
    const state = codec.parse_forkchoice(try call.params.raw()) catch return error.InvalidParams;
    const attributes = try call.params.optional_raw();
    try call.params.finish();
    const building = attributes != null and !std.mem.eql(u8, attributes.?, "null");
    const status = engine.forkchoice(&state) catch |err| return fail_engine(call, err);
    if (building and status.status == .valid) {
        const message = "el-run is a verifier engine: payload building is not supported";
        return call.fail(rpc.code.invalid_payload_attributes, message);
    }
    try codec.write_forkchoice_updated(call.writer, .{ .payload_status = status });
}

fn new_payload(comptime version: Version) fn (*Engine, *Call) HandlerError!void {
    return struct {
        fn handle(engine: *Engine, call: *Call) HandlerError!void {
            const space = &engine.space;
            space.reset();
            const raw = try call.params.raw();
            const payload = codec.parse_payload(raw, space) catch return error.InvalidParams;
            var params: engine_types.NewPayloadParams = .{};
            if (@backingInt(version) >= 3) {
                const hashes = try call.params.raw();
                params.versioned_hashes = codec.parse_hashes(hashes, space) catch
                    return error.InvalidParams;
                params.parent_beacon_block_root = .{ .bytes = try call.params.fixed(32) };
            }
            if (@backingInt(version) >= 4) {
                const requests = try call.params.raw();
                params.execution_requests = codec.parse_data_array(requests, space) catch
                    return error.InvalidParams;
            }
            try call.params.finish();
            engine_types.validate_new_payload(engine.spec, version, &payload, &params) catch |err|
                return fail_engine(call, err);
            try codec.write_status(call.writer, engine.payload_status(&payload, &params));
        }
    }.handle;
}

// ---- Block reads --------------------------------------------------------------------

const Tag = union(enum) { number: u64, latest, safe, finalized };

fn parse_tag(raw: []const u8) HandlerError!Tag {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    const text = raw[1 .. raw.len - 1];
    const eql = std.mem.eql;
    if (eql(u8, text, "latest") or eql(u8, text, "pending")) return .latest;
    if (eql(u8, text, "safe")) return .safe;
    if (eql(u8, text, "finalized")) return .finalized;
    if (eql(u8, text, "earliest")) return .{ .number = 0 };
    return .{ .number = json.parse_quantity(u64, text) catch return error.InvalidParams };
}

fn get_block_by_number(engine: *Engine, call: *Call) HandlerError!void {
    const tag = try parse_tag(try call.params.raw());
    const full = try call.params.optional_boolean() orelse false;
    try call.params.finish();
    const label: Label = switch (tag) {
        .number => |number| {
            const block = try read_number(engine, call, number) orelse
                return call.writer.null_value();
            return write_block(call.writer, &block, full);
        },
        .latest => engine.chain.head(),
        .safe => engine.held(&engine.safe) orelse try anchor_or_fail(engine, call),
        .finalized => engine.held(&engine.finalized) orelse try anchor_or_fail(engine, call),
    };
    // Proof: labels are executed blocks, and the head never moves back.
    const block = try read_number(engine, call, label.number) orelse unreachable;
    if (!std.mem.eql(u8, &block.hash, &label.hash)) {
        return call.fail(rpc.code.server_error, "labeled block is no longer el-run's chain");
    }
    try write_block(call.writer, &block, full);
}

fn get_block_by_hash(engine: *Engine, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    const full = try call.params.optional_boolean() orelse false;
    try call.params.finish();
    const number = engine.ring.number_of(hash) orelse {
        const executed = engine.chain.number_of_fn(engine.chain.context, hash) orelse
            return call.writer.null_value();
        return fail_missing(engine, call, executed);
    };
    const block = engine.ring.get(number, engine.scratch).?; // Proof: just found.
    assert(std.mem.eql(u8, &block.hash, &hash));
    try write_block(call.writer, &block, full);
}

/// Block `number` from the ring; null above the head, an RPC error when it left the ring.
fn read_number(engine: *Engine, call: *Call, number: u64) HandlerError!?el_ring.Block {
    if (number > engine.chain.head().number) return null;
    const block = engine.ring.get(number, engine.scratch) orelse
        return fail_missing(engine, call, number);
    assert(block.number == number);
    return block;
}

fn fail_missing(engine: *Engine, call: *Call, number: u64) HandlerError {
    engine.stats.ring_misses += 1;
    const ring = &engine.ring;
    if (ring.count == 0) return fail_empty(call);
    const message = std.fmt.bufPrint(&engine.message_buffer, "block {d} was executed but is " ++
        "not in el-run's engine ring (blocks {d}..{d}); raise --engine.ring-blocks or " ++
        "--engine.ring-mb", .{ number, ring.oldest_number().?, ring.newest_number().? }) catch
        "block was executed but is not in el-run's engine ring";
    return call.fail(rpc.code.server_error, message);
}

/// The anchor, or an error while the ring is too short to hold one deep enough for the
/// consensus node's reset walk-back: until it holds `2 * anchor_depth_max` blocks or has
/// evicted (it is as full as its byte budget allows).
fn anchor_or_fail(engine: *Engine, call: *Call) HandlerError!Label {
    const ring = &engine.ring;
    if (ring.count == 0) return fail_empty(call);
    if (engine.anchor == null and ring.evicted == 0 and ring.count < 2 * anchor_depth_max) {
        const message = std.fmt.bufPrint(&engine.message_buffer, "el-run's engine ring is " ++
            "warming up ({d} of {d} blocks): safe and finalized are unset until it holds " ++
            "enough blocks below the tip", .{ ring.count, 2 * anchor_depth_max }) catch
            "el-run's engine ring is warming up";
        return call.fail(rpc.code.server_error, message);
    }
    const anchor = engine.anchor_label().?; // Proof: the ring is not empty.
    assert(anchor.number <= ring.newest_number().?);
    return anchor;
}

fn fail_empty(call: *Call) HandlerError {
    const message = "el-run's engine ring is empty: no block executed since el-run started";
    return call.fail(rpc.code.server_error, message);
}

/// An upper bound of the block's JSON: hex doubles every byte; fields and quoting add at
/// most 2 KiB per transaction (access lists and signatures are inside the raw bytes).
fn json_size_bound(block: *const el_ring.Block) usize {
    var size: usize = 4096 + 2 * block.header_rlp.len;
    for (block.transactions) |transaction| size += 3 * transaction.len + 2048;
    return size;
}

/// The block's RLP size (`size`): header, transactions, no ommers, and the (empty, on OP)
/// withdrawals list when the header has a withdrawals root.
fn rlp_size(block: *const el_ring.Block, withdrawals: bool) u64 {
    var transactions: usize = 0;
    for (block.transactions) |transaction| {
        assert(transaction.len > 0);
        const legacy = transaction[0] >= 0xc0;
        transactions += if (legacy) transaction.len else rlp.bytes_length(transaction);
    }
    const payload = block.header_rlp.len + rlp.list_length(transactions) + 1 +
        @as(usize, @intFromBool(withdrawals));
    return rlp.list_length(payload);
}

fn write_block(w: *json.Writer, block: *const el_ring.Block, full: bool) HandlerError!void {
    // Proof: the runner decoded and hashed this header before committing the block.
    const header = consensus.Header.decode(block.header_rlp) catch unreachable;
    assert(header.number == block.number);
    assert(std.mem.eql(u8, &header.hash().bytes, &block.hash));
    try w.out.ensureUnusedCapacity(json_size_bound(block));
    const withdrawals = header.withdrawals_root != null;
    const timestamp_ms = if (block.transactions.len < 2) null else format.timestamp_ms_of(
        block.transactions[1],
        header.number,
        header.timestamp,
    );
    try w.begin_object();
    try format.header_fields(w, &header, block.hash, rlp_size(block, withdrawals));
    if (timestamp_ms) |ms| try format.field_quantity(w, "timestampMs", ms);
    try w.key("uncles");
    try w.begin_array();
    try w.end_array();
    try w.key("transactions");
    try w.begin_array();
    for (block.transactions, 0..) |transaction, index| {
        if (!full) {
            try w.data(&base.common.primitives.keccak256(transaction).bytes);
            continue;
        }
        const inclusion: format.Inclusion = .{
            .block_hash = block.hash,
            .block_number = block.number,
            .index = @intCast(index),
            .base_fee = header.base_fee_per_gas,
            .timestamp_ms = timestamp_ms,
        };
        try format.transaction(w, transaction, inclusion, consensus.recover_address);
    }
    try w.end_array();
    if (withdrawals) {
        try w.key("withdrawals");
        try w.begin_array();
        try w.end_array();
    }
    try w.end_object();
}

/// `base rollup-config --chain base-sepolia|base-mainnet --out <rollup.json>`: writes the
/// chain's built-in rollup config (the one `--engine.rollup-out` writes) without a database,
/// so a consensus node's config can be prepared and checked before el-run first starts.
pub fn rollup_config_main(init: std.process.Init, args: []const []const u8) !u8 {
    const usage = "usage: base rollup-config --chain base-sepolia|base-mainnet --out <file>\n";
    var config: ?*const ChainConfig = null;
    var out: ?[]const u8 = null;
    var index: usize = 0;
    while (index + 1 < args.len) : (index += 2) {
        const name = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, name, "--chain")) {
            config = if (std.mem.eql(u8, value, "base-mainnet"))
                &base.common.chains.mainnet
            else if (std.mem.eql(u8, value, "base-sepolia"))
                &base.common.chains.sepolia
            else
                null;
        } else if (std.mem.eql(u8, name, "--out")) {
            out = value;
        } else break;
    }
    if (index != args.len or config == null or out == null) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    assert(config.?.chain_id != 0);
    try write_rollup_config(init.io, out.?, config.?);
    return 0;
}

/// Writes the built-in rollup config of `config` (the one `base derive-check` derives with)
/// as rollup.json, so `base consensus` runs against el-run with the same chain.
pub fn write_rollup_config(std_io: Io, path: []const u8, config: *const ChainConfig) !void {
    var buffer: [16 * 1024]u8 = undefined;
    const text = try rollup_text(&buffer, config);
    try Io.Dir.cwd().writeFile(std_io, .{ .sub_path = path, .data = text });
    std.debug.print("el-run: wrote the {d} rollup config to {s}\n", .{ config.chain_id, path });
}

pub fn rollup_text(buffer: []u8, config: *const ChainConfig) ![]const u8 {
    const rollup = rollup_config_for(config);
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try rollup_json.write(&writer, &rollup);
    const text = out.buffered();
    assert((try rollup_json.parse(text)).l2_chain_id == config.chain_id);
    return text;
}

test "el engine: the rollup config round trips" {
    var buffer: [16 * 1024]u8 = undefined;
    const chains = base.common.chains;
    const configs = [_]*const ChainConfig{ &chains.sepolia, &chains.mainnet };
    for (configs) |config| {
        const parsed = try rollup_json.parse(try rollup_text(&buffer, config));
        try std.testing.expectEqualDeep(rollup_config_for(config), parsed);
    }
}

// ---- Serving ------------------------------------------------------------------------

pub fn Server(comptime IO: type) type {
    return http.Server(IO, *Engine, Engine.handle_http);
}

/// The production server: large `newPayload` bodies and full blocks; buffers commit lazily.
pub const server_options: http.server.Options = .{
    .connections_max = 16,
    .recv_buffer_size = 16 * 1024 + payload_bytes_max,
    .send_buffer_size = 1 << 20,
    .limits = .{ .head_size_max = 16 * 1024, .body_size_max = payload_bytes_max },
    .large_send_buffers_max = 2,
    .large_send_buffer_size = 64 << 20,
};

/// Non-blocking ticks per `poll`: accept, receive, and send each take one.
const poll_ticks = 4;
const timeout_tick_interval_ns = 250 * std.time.ns_per_ms;

/// The production Engine API: the engine, its own completion IO, and the HTTP server.
pub const Service = struct {
    const IO = io_module.IO;

    engine: Engine,
    io: IO,
    server: Server(IO),
    /// The bound listen address.
    address: io_module.Address = undefined,
    last_tick_ns: u64 = 0,

    /// Null when `--engine.addr` is not given. Reads the JWT secret and listens.
    pub fn start(
        allocator: std.mem.Allocator,
        std_io: Io,
        flags: *const Flags,
        spec: *const ChainSpec,
        config: *const ChainConfig,
        chain: Chain,
    ) !?*Service {
        assert(flags.valid());
        assert(config.chain_id == spec.chain_id);
        if (flags.rollup_out) |path| try write_rollup_config(std_io, path, config);
        const addr = flags.addr orelse return null;
        const address = io_module.Address.parse(addr) catch return error.InvalidEngineAddress;
        if (address.port == 0) return error.InvalidEngineAddress;
        var secret_buffer: [256]u8 = undefined;
        const secret_text = try Io.Dir.cwd().readFile(std_io, flags.jwt.?, &secret_buffer);
        const secret = try jwt.Secret.parse_hex(secret_text);
        const ring_options = flags.ring_options();
        const service = try create(
            allocator,
            address,
            secret,
            spec,
            chain,
            ring_options,
            server_options,
        );
        std.debug.print("el-run: engine API on {f} (JWT), ring {d} blocks / {d} MiB\n", .{
            service.address, flags.ring_blocks, flags.ring_mib,
        });
        return service;
    }

    pub fn create(
        allocator: std.mem.Allocator,
        address: io_module.Address,
        secret: jwt.Secret,
        spec: *const ChainSpec,
        chain: Chain,
        ring_options: el_ring.Options,
        options: http.server.Options,
    ) !*Service {
        const service = try allocator.create(Service);
        errdefer allocator.destroy(service);
        try service.engine.init(allocator, spec, secret, chain, ring_options);
        errdefer service.engine.deinit(allocator);
        service.io = if (@import("builtin").os.tag == .linux) try IO.init(.{}) else try IO.init();
        errdefer service.io.deinit();
        try service.server.init(allocator, &service.io, &service.engine, options);
        errdefer service.server.deinit();
        service.address = try service.server.listen(address);
        service.last_tick_ns = 0;
        assert(service.engine.ring.count == 0);
        assert(address.port == 0 or service.address.port == address.port);
        return service;
    }

    pub fn destroy(service: *Service, allocator: std.mem.Allocator) void {
        service.server.deinit();
        service.io.deinit();
        service.engine.deinit(allocator);
        allocator.destroy(service);
    }

    /// Answers what is ready without blocking (between blocks).
    pub fn poll(service: *Service) void {
        service.prepare();
        for (0..poll_ticks) |_| {
            service.io.tick() catch |err| {
                std.debug.print("el-run engine: io tick failed: {t}\n", .{err});
                return;
            };
        }
    }

    /// Serves requests for `duration_ms` (the idle wait at the tip).
    pub fn wait(service: *Service, duration_ms: u64) !void {
        assert(duration_ms > 0);
        service.prepare();
        try service.io.run_for_ns(duration_ms * std.time.ns_per_ms);
    }

    fn prepare(service: *Service) void {
        service.engine.now_s = service.io.now_realtime_ns() / std.time.ns_per_s;
        const now_ns = service.io.now_monotonic_ns();
        if (now_ns -| service.last_tick_ns < timeout_tick_interval_ns) return;
        service.last_tick_ns = now_ns;
        service.server.tick();
    }
};

test {
    _ = @import("el_ring.zig");
    _ = @import("el_engine_test.zig");
}

//! eth_*, net_* and web3_* JSON-RPC methods over the node's chain, state and pool.
//! State queries serve the head state (older blocks: "historical state unavailable",
//! until persistence keeps state history).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const chainspec = @import("../chainspec/root.zig");
const txpool = @import("../txpool/root.zig");
const node = @import("../node/root.zig");
const format = @import("format.zig");
const debug = @import("debug.zig");

const Hash = [32]u8;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Chain = node.Chain;

pub const default_priority_fee: u64 = 1_000_000_000;
pub const estimate_iterations_max = 64;
pub const logs_blocks_max = 10_000;
pub const logs_max = 10_000;
pub const fee_history_blocks_max = 1024;

pub const Api = struct {
    spec: *const chainspec.ChainSpec,
    chain: *Chain,
    pool: ?*txpool.Pool,
    client_version: []const u8 = "needlefish/v0.0.0",
    /// Verifies blob transaction KZG proofs on submission when set.
    kzg: ?consensus.sidecar.KzgVerifier = null,
    /// Decoding space for raw transactions and call data (bounded request size).
    scratch: []u8,
    /// `debug_executionWitness` buffers, bound to the chain's state; null disables it.
    witness: ?*node.witness.Generator = null,
    /// Polling filters (eth_newFilter and friends); null disables them.
    filters: ?*filters_module.Filters = null,
};

pub const methods = core_methods ++ @import("eth_more.zig").methods ++ filters_module.methods ++
    @import("txpool.zig").methods;
const filters_module = @import("filters.zig");
const state_view = @import("state_view.zig");
const eth_proof = @import("eth_proof.zig");

const core_methods = [_]rpc.Method(*Api){
    .{ .name = "web3_clientVersion", .handler = client_version },
    .{ .name = "net_version", .handler = net_version },
    .{ .name = "net_listening", .handler = net_listening },
    .{ .name = "net_peerCount", .handler = net_peer_count },
    .{ .name = "eth_chainId", .handler = chain_id },
    .{ .name = "eth_syncing", .handler = syncing },
    .{ .name = "eth_blockNumber", .handler = block_number },
    .{ .name = "eth_gasPrice", .handler = gas_price },
    .{ .name = "eth_maxPriorityFeePerGas", .handler = max_priority_fee },
    .{ .name = "eth_blobBaseFee", .handler = blob_base_fee },
    .{ .name = "eth_feeHistory", .handler = fee_history },
    .{ .name = "eth_getBalance", .handler = get_balance },
    .{ .name = "eth_getTransactionCount", .handler = get_transaction_count },
    .{ .name = "eth_getCode", .handler = get_code },
    .{ .name = "eth_getStorageAt", .handler = get_storage_at },
    .{ .name = "eth_getBlockByNumber", .handler = get_block_by_number },
    .{ .name = "eth_getBlockByHash", .handler = get_block_by_hash },
    .{ .name = "eth_getTransactionByHash", .handler = get_transaction_by_hash },
    .{ .name = "eth_getTransactionReceipt", .handler = get_transaction_receipt },
    .{ .name = "eth_getBlockReceipts", .handler = get_block_receipts },
    .{ .name = "eth_sendRawTransaction", .handler = send_raw_transaction },
    .{ .name = "eth_call", .handler = eth_call },
    .{ .name = "eth_estimateGas", .handler = estimate_gas },
    .{ .name = "eth_getLogs", .handler = get_logs },
    .{ .name = "eth_getProof", .handler = @import("eth_proof.zig").get_proof },
    .{ .name = "miner_setMaxDASize", .handler = set_max_da_size },
    .{ .name = "debug_getRawHeader", .handler = debug.get_raw_header },
    .{ .name = "debug_getRawBlock", .handler = debug.get_raw_block },
    .{ .name = "debug_getRawReceipts", .handler = debug.get_raw_receipts },
    .{ .name = "debug_getRawTransaction", .handler = debug.get_raw_transaction },
    .{ .name = "debug_executionWitness", .handler = debug.execution_witness },
};

pub const Router = rpc.Router(*Api, &methods);

// ---- Simple values ----------------------------------------------------------------

fn client_version(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.string(api.client_version);
}

fn net_version(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{api.spec.chain_id}) catch unreachable;
    try call.writer.string(text);
}

fn net_listening(_: *Api, call: *Call) HandlerError!void {
    try call.writer.boolean(true);
}

fn net_peer_count(_: *Api, call: *Call) HandlerError!void {
    try call.writer.quantity(@as(u8, 0));
}

fn chain_id(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(api.spec.chain_id);
}

fn syncing(_: *Api, call: *Call) HandlerError!void {
    try call.writer.boolean(false);
}

fn block_number(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(head_header(api).number);
}

/// Base fee of the next block (assuming it lands one second after the head).
fn next_base_fee(api: *Api) u64 {
    const head = head_header(api);
    return api.spec.next_base_fee(.{
        .timestamp = head.timestamp,
        .gas_used = head.gas_used,
        .gas_limit = head.gas_limit,
        .base_fee = head.base_fee_per_gas orelse 0,
        .blob_gas_used = head.blob_gas_used orelse 0,
        .excess_blob_gas = head.excess_blob_gas orelse 0,
        .extra_data = head.extra_data,
    }, head.timestamp + 1) catch head.base_fee_per_gas orelse 0;
}

fn gas_price(api: *Api, call: *Call) HandlerError!void {
    try call.writer.quantity(@as(u128, next_base_fee(api)) + default_priority_fee);
}

fn max_priority_fee(_: *Api, call: *Call) HandlerError!void {
    try call.writer.quantity(default_priority_fee);
}

/// `miner_setMaxDASize(maxTxSize, maxBlockSize)`: the batcher's DA throttle; 0 lifts a
/// limit. Takes effect from the next payload build.
fn set_max_da_size(api: *Api, call: *Call) HandlerError!void {
    const tx_bytes_max = try call.params.quantity(u64);
    const block_bytes_max = try call.params.quantity(u64);
    try call.params.finish();
    api.chain.da_limits = .{ .tx_bytes_max = tx_bytes_max, .block_bytes_max = block_bytes_max };
    assert(api.chain.da_limits.block_bytes_max == block_bytes_max);
    try call.writer.boolean(true);
}

fn blob_base_fee(api: *Api, call: *Call) HandlerError!void {
    const head = head_header(api);
    const params = api.spec.blob_params_at(head.timestamp + 1) orelse {
        return call.fail(rpc.code.server_error, "blobs not supported");
    };
    const excess = params.next_excess_blob_gas(
        head.excess_blob_gas orelse 0,
        head.blob_gas_used orelse 0,
        head.base_fee_per_gas orelse 0,
    );
    try call.writer.quantity(params.base_fee(excess));
}

fn fee_history(api: *Api, call: *Call) HandlerError!void {
    const count = @min(try call.params.quantity(u64), fee_history_blocks_max);
    const newest = try resolve_number(api, call, try call.params.raw());
    const percentiles = try call.params.optional_raw();
    const oldest = (newest + 1) -| count;
    const w = call.writer;
    try w.begin_object();
    try format.field_quantity(w, "oldestBlock", oldest);
    try w.key("baseFeePerGas");
    try w.begin_array();
    var number = oldest;
    while (number <= newest) : (number += 1) {
        try w.quantity(canonical_header(api, number).?.base_fee_per_gas orelse 0);
    }
    try w.quantity(next_base_fee(api));
    try w.end_array();
    try w.key("gasUsedRatio");
    try w.begin_array();
    number = oldest;
    while (number <= newest) : (number += 1) {
        const header = canonical_header(api, number).?;
        const ratio = @as(f64, @floatFromInt(header.gas_used)) /
            @as(f64, @floatFromInt(@max(header.gas_limit, 1)));
        var text: [32]u8 = undefined;
        try w.raw(std.fmt.bufPrint(&text, "{d}", .{ratio}) catch "0");
    }
    try w.end_array();
    if (percentiles != null) try fee_rewards(api, w, oldest, newest, percentiles.?);
    try w.end_object();
}

/// Rewards per block and percentile: the minimum priority fee in each block (a simple,
/// stable approximation of the percentile reward).
fn fee_rewards(
    api: *Api,
    w: *json.Writer,
    oldest: u64,
    newest: u64,
    percentiles: []const u8,
) !void {
    var scanner = json.Scanner.init(percentiles);
    var count: u32 = 0;
    if ((try scanner_next(&scanner)).tag != .array_begin) return error.InvalidParams;
    while ((try scanner_next(&scanner)).tag == .number) count += 1;
    _ = api;
    try w.key("reward");
    try w.begin_array();
    var number = oldest;
    while (number <= newest) : (number += 1) {
        try w.begin_array();
        for (0..count) |_| try w.quantity(@as(u8, 0));
        try w.end_array();
    }
    try w.end_array();
}

fn scanner_next(scanner: *json.Scanner) HandlerError!json.Token {
    return scanner.next() catch error.InvalidParams;
}

// ---- State ------------------------------------------------------------------------

/// Requires the block param to name the head (or a pending/latest tag).
pub fn require_head_state(api: *Api, call: *Call, raw: ?[]const u8) HandlerError!void {
    if (raw) |text| {
        const hash = try resolve_block(api, call, text);
        if (!std.mem.eql(u8, &hash, &api.chain.head_hash())) {
            return call.fail(rpc.code.server_error, "historical state unavailable");
        }
    }
    api.chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
}

fn get_balance(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    const account = try state_view.account(api, call, view, address);
    try call.writer.quantity(if (account) |a| a.balance else 0);
}

fn get_transaction_count(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const tag = try call.params.optional_raw();
    const pending = if (tag) |t| std.mem.eql(u8, t, "\"pending\"") else false;
    const view = try state_view.resolve(api, call, if (pending) null else tag);
    const account = try state_view.account(api, call, view, address);
    var nonce = if (account) |a| a.nonce else 0;
    if (pending) if (api.pool) |pool| {
        nonce = pool.next_nonce(.{ .bytes = address }, nonce);
    };
    try call.writer.quantity(nonce);
}

fn get_code(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    const account = try state_view.account(api, call, view, address) orelse
        return call.writer.data(&.{});
    try call.writer.data(state_view.code(api, account.code_hash));
}

fn get_storage_at(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const slot = try call.params.quantity(u256);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    var value: [32]u8 = undefined;
    std.mem.writeInt(u256, &value, try state_view.storage(api, call, view, address, slot), .big);
    try call.writer.data(&value);
}

// ---- Blocks -----------------------------------------------------------------------

pub fn head_header(api: *Api) consensus.Header {
    return api.chain.header(api.chain.head_hash()).?;
}

fn canonical_header(api: *Api, number: u64) ?consensus.Header {
    const hash = api.chain.store.canonical_hash(number) orelse return null;
    return api.chain.header(hash);
}

/// Resolves a block parameter (tag, number, bare hash, or `{"blockHash": ...}`) to a
/// hash.
pub fn resolve_block(api: *Api, call: *Call, raw: []const u8) HandlerError!Hash {
    if (raw.len == 2 + 2 + 64 and raw[0] == '"') {
        const hash = json.parse_fixed(32, raw[1 .. raw.len - 1]) catch {
            return error.InvalidParams;
        };
        if (api.chain.store.ref(hash) == null) {
            return call.fail(rpc.code.server_error, "block not found");
        }
        return hash;
    }
    if (raw.len > 0 and raw[0] == '{') {
        var scanner = json.Scanner.init(raw);
        if ((try scanner_next(&scanner)).tag != .object_begin) return error.InvalidParams;
        while (true) {
            const token = try scanner_next(&scanner);
            if (token.tag == .object_end) return error.InvalidParams;
            const value = try scanner_next(&scanner);
            if (!std.mem.eql(u8, token.bytes, "blockHash")) continue;
            const hash = json.parse_fixed(32, value.bytes) catch return error.InvalidParams;
            if (api.chain.store.ref(hash) == null) {
                return call.fail(rpc.code.server_error, "block not found");
            }
            return hash;
        }
    }
    const number = try resolve_number(api, call, raw);
    return api.chain.store.canonical_hash(number) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
}

fn resolve_number(api: *Api, call: *Call, raw: []const u8) HandlerError!u64 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    return resolve_number_text(api, call, raw[1 .. raw.len - 1]);
}

/// A block tag or hex number, without quotes.
fn resolve_number_text(api: *Api, call: *Call, text: []const u8) HandlerError!u64 {
    const head = head_header(api).number;
    if (std.mem.eql(u8, text, "latest") or std.mem.eql(u8, text, "pending")) return head;
    if (std.mem.eql(u8, text, "earliest")) return 0;
    if (std.mem.eql(u8, text, "safe") or std.mem.eql(u8, text, "finalized")) {
        const fc = api.chain.forkchoice;
        const safe = std.mem.eql(u8, text, "safe");
        const hash = if (safe) fc.safe_block_hash else fc.finalized_block_hash;
        const stored = api.chain.store.ref(hash.bytes) orelse return 0;
        return stored.number;
    }
    const number = json.parse_quantity(u64, text) catch return error.InvalidParams;
    if (number > head) return call.fail(rpc.code.server_error, "block not found");
    return number;
}

fn write_block(api: *Api, call: *Call, hash: Hash, full: bool) HandlerError!void {
    const bytes = api.chain.store.record(hash) orelse return call.writer.null_value();
    const record = node.chain.Record.decode(bytes) catch unreachable; // Stored by the chain.
    try format.block(call.writer, record, hash, bytes.len, full, api.chain.executor.recoverer);
}

fn get_block_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    const full = try call.params.optional_boolean() orelse false;
    const hash = resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.writer.null_value(),
        else => return err,
    };
    try write_block(api, call, hash, full);
}

fn get_block_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    const full = try call.params.optional_boolean() orelse false;
    try write_block(api, call, hash, full);
}

// ---- Transactions and receipts ----------------------------------------------------

fn get_transaction_by_hash(api: *Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.fixed(32);
    try call.params.finish();
    const recoverer = api.chain.executor.recoverer;
    if (api.chain.find_transaction(tx_hash)) |location| {
        const record = api.chain.record(location.block_hash).?;
        const raw = nth_transaction(record, location.index);
        return format.transaction(call.writer, raw, .{
            .block_hash = location.block_hash,
            .block_number = record.header.number,
            .index = location.index,
            .base_fee = record.header.base_fee_per_gas,
        }, recoverer);
    }
    const pool = api.pool orelse return call.writer.null_value();
    const tx = pool.get(.{ .bytes = tx_hash }) orelse return call.writer.null_value();
    try format.transaction(call.writer, node.chain.canonical_form(tx.raw, api.scratch) catch {
        return call.fail(rpc.code.internal_error, "transaction too large");
    }, null, recoverer);
}

fn nth_transaction(record: node.chain.Record, index: u32) []const u8 {
    var transactions = record.transactions;
    for (0..index) |_| _ = transactions.bytes() catch unreachable;
    return transactions.bytes() catch unreachable;
}

fn get_transaction_receipt(api: *Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.fixed(32);
    try call.params.finish();
    const location = api.chain.find_transaction(tx_hash) orelse return call.writer.null_value();
    try block_receipts(api, call.writer, location.block_hash, location.index);
}

fn get_block_receipts(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    const hash = resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.writer.null_value(),
        else => return err,
    };
    try call.writer.begin_array();
    try block_receipts(api, call.writer, hash, null);
    try call.writer.end_array();
}

/// Writes the receipt at `only` (or every receipt) of the block `hash`.
fn block_receipts(api: *Api, w: *json.Writer, hash: Hash, only: ?u32) HandlerError!void {
    const record = api.chain.record(hash).?;
    var transactions = record.transactions;
    var receipts = record.receipts;
    var index: u32 = 0;
    var previous_gas: u64 = 0;
    var log_index: u64 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable;
        const encoded = receipts.bytes() catch unreachable; // Stored by the chain.
        const value = consensus.Receipt.decode(encoded) catch unreachable;
        defer previous_gas = value.cumulative_gas_used;
        defer log_index += value.logs.count;
        if (only) |wanted| if (wanted != index) continue;
        const context = receipt_context(api, &record.header, hash, raw, index, value, .{
            .previous_gas = previous_gas,
            .log_index = log_index,
        });
        try format.receipt(w, value, context);
    }
}

fn receipt_context(
    api: *Api,
    header: *const consensus.Header,
    hash: Hash,
    raw: []const u8,
    index: u32,
    value: consensus.Receipt,
    position: struct { previous_gas: u64, log_index: u64 },
) format.ReceiptContext {
    const envelope = consensus.Envelope.decode(raw) catch unreachable; // Stored by the chain.
    const recoverer = api.chain.executor.recoverer;
    const sender = envelope.recover_sender(recoverer) orelse primitives.Address.zero;
    const to = envelope.kind().to();
    const base_fee = header.base_fee_per_gas orelse 0;
    const blob_count = envelope.blob_versioned_hashes().count();
    var blob_price: ?u128 = null;
    if (blob_count > 0) if (api.spec.blob_params_at(header.timestamp)) |params| {
        blob_price = params.base_fee(header.excess_blob_gas orelse 0);
    };
    return .{
        .inclusion = .{
            .block_hash = hash,
            .block_number = header.number,
            .index = index,
            .base_fee = base_fee,
        },
        .tx_hash = primitives.keccak256(raw).bytes,
        .from = sender,
        .to = to,
        .contract_address = if (to == null)
            format.contract_address(sender, envelope.nonce().?)
        else
            null,
        .gas_used = value.cumulative_gas_used - position.previous_gas,
        .effective_gas_price = envelope.effective_gas_price(base_fee) orelse 0,
        .first_log_index = position.log_index,
        .blob_gas_used = @as(u64, blob_count) * (1 << 17),
        .blob_gas_price = blob_price,
    };
}

fn send_raw_transaction(api: *Api, call: *Call) HandlerError!void {
    const half = api.scratch.len / 2;
    const raw = try call.params.data(api.scratch[0..half]);
    try call.params.finish();
    const pool = api.pool orelse {
        return call.fail(rpc.code.server_error, "transaction pool disabled");
    };
    const head = head_header(api);
    const validated = txpool.validate.validate(
        raw,
        api.scratch[half..],
        api.spec,
        head.timestamp + 1,
        api.chain.executor.recoverer,
    ) catch |err| return call.fail(rpc.code.server_error, @errorName(err));
    if (validated.sidecar != null) {
        if (api.kzg) |verifier| txpool.validate.verify_blob_proofs(raw, verifier) catch |err| {
            return call.fail(rpc.code.server_error, @errorName(err));
        };
    }
    api.chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const account = api.chain.db.get_account(validated.tx.sender.bytes);
    _ = pool.add(validated.tx, .{
        .nonce = if (account) |a| a.nonce else 0,
        .balance = if (account) |a| a.balance else 0,
    }) catch |err| return call.fail(rpc.code.server_error, @errorName(err));
    if (api.filters) |filters| filters.note_pending(validated.tx.hash.bytes);
    try call.writer.data(&validated.tx.hash.bytes);
}

// ---- Calls ------------------------------------------------------------------------

fn parse_call(space: []u8, raw: []const u8) HandlerError!node.executor.Executor.Call {
    var result: node.executor.Executor.Call = .{};
    var scanner = json.Scanner.init(raw);
    if ((try scanner_next(&scanner)).tag != .object_begin) return error.InvalidParams;
    while (true) {
        const name = try scanner_next(&scanner);
        if (name.tag == .object_end) break;
        const value = try scanner_next(&scanner);
        if (value.tag == .null) continue;
        const text = value.bytes;
        if (std.mem.eql(u8, name.bytes, "from")) {
            result.from = json.parse_fixed(20, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "to")) {
            result.to = json.parse_fixed(20, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "gas")) {
            result.gas = json.parse_quantity(u64, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "value")) {
            result.value = json.parse_quantity(u256, text) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "data") or std.mem.eql(u8, name.bytes, "input")) {
            result.data = json.parse_data(text, space) catch return error.InvalidParams;
        } else {
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
    return result;
}

/// A call request with the state it runs against. The block is resolved before the
/// call object is parsed, so call data of a historical call stays clear of the proof
/// buffers at the scratch tail.
const CallRequest = struct {
    message: node.executor.Executor.Call,
    view: state_view.View,
};

fn parse_call_request(api: *Api, call: *Call) HandlerError!CallRequest {
    const call_raw = try call.params.raw();
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    const space = switch (view) {
        .head => api.scratch,
        .historical => api.scratch[0 .. proof_tail_offset(api) orelse {
            return call.fail(rpc.code.internal_error, "proof scratch too small");
        }],
    };
    return .{ .message = try parse_call(space, call_raw), .view = view };
}

/// Where the proof buffers of a historical call start (aligned, at the scratch tail).
fn proof_tail_offset(api: *Api) ?usize {
    const size = @sizeOf(eth_proof.Scratch);
    if (api.scratch.len < size + @alignOf(eth_proof.Scratch)) return null;
    const base = @intFromPtr(api.scratch.ptr);
    const alignment = @alignOf(eth_proof.Scratch);
    const start = std.mem.alignBackward(usize, base + api.scratch.len - size, alignment);
    assert(start >= base);
    return start - base;
}

fn view_header(api: *Api, view: state_view.View) consensus.Header {
    return switch (view) {
        .head => head_header(api),
        .historical => |block| api.chain.header(block.hash).?, // Resolved, so stored.
    };
}

fn simulate(
    api: *Api,
    call: *Call,
    request: CallRequest,
) HandlerError!node.executor.Executor.Simulated {
    const header = view_header(api, request.view);
    var env = node.chain.env_of(&header);
    env.number += 1;
    env.timestamp += 1;
    env.parent_hash = header.hash().bytes;
    const executor = api.chain.executor;
    const block = switch (request.view) {
        .head => {
            api.chain.ensure_head_state() catch {
                return call.fail(rpc.code.internal_error, "head state unavailable");
            };
            return executor.simulate(&env, request.message) catch |err| {
                return call.fail(rpc.code.internal_error, @errorName(err));
            };
        },
        .historical => |block| block,
    };
    const offset = proof_tail_offset(api).?; // Checked when the request was parsed.
    const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
    var history: node.HistoryDatabase = .{
        .chain = api.chain,
        .hash = block.hash,
        .number = block.number,
        .account_proof = &proofs.account,
        .storage_proof = &proofs.storage,
    };
    return executor.simulate_on(&env, request.message, history.database()) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
}

fn eth_call(api: *Api, call: *Call) HandlerError!void {
    const request = try parse_call_request(api, call);
    switch (try simulate(api, call, request)) {
        .invalid => |reason| return call.fail(rpc.code.server_error, @tagName(reason)),
        .executed => |executed| {
            if (!executed.success) return call.fail(3, "execution reverted");
            try call.writer.data(executed.output);
        },
    }
}

/// Binary search for the smallest gas limit that succeeds, bounded by the block limit.
fn estimate_gas(api: *Api, call: *Call) HandlerError!void {
    var request = try parse_call_request(api, call);
    var high = request.message.gas orelse view_header(api, request.view).gas_limit;
    request.message.gas = high;
    const first = try simulate(api, call, request);
    switch (first) {
        .invalid => |reason| return call.fail(rpc.code.server_error, @tagName(reason)),
        .executed => |e| if (!e.success) return call.fail(3, "execution reverted"),
    }
    var low: u64 = first.executed.gas_used - 1;
    var iterations: u32 = 0;
    while (low + 1 < high and iterations < estimate_iterations_max) : (iterations += 1) {
        const middle = low + (high - low) / 2;
        request.message.gas = middle;
        const ok = switch (try simulate(api, call, request)) {
            .invalid => false,
            .executed => |e| e.success,
        };
        if (ok) high = middle else low = middle;
    }
    try call.writer.quantity(high);
}

// ---- Logs -------------------------------------------------------------------------

pub const Filter = struct {
    from: u64,
    to: u64,
    /// `toBlock` was a concrete number (not omitted or a tag): a polled filter stops there.
    to_given: bool = false,
    block_hash: ?Hash = null,
    addresses: [16][20]u8 = undefined,
    address_count: u32 = 0,
    /// Per position: allowed topics (empty = any).
    topics: [4][8]Hash = undefined,
    topic_counts: [4]u32 = @splat(0),

    pub fn matches(filter: *const Filter, item: consensus.Log) bool {
        if (filter.address_count > 0) {
            const ok = for (filter.addresses[0..filter.address_count]) |a| {
                if (std.mem.eql(u8, &a, &item.address.bytes)) break true;
            } else false;
            if (!ok) return false;
        }
        for (0..4) |position| {
            const count = filter.topic_counts[position];
            if (count == 0) continue;
            if (position >= item.topics.count()) return false;
            const topic = item.topics.get(position).bytes;
            const ok = for (filter.topics[position][0..count]) |t| {
                if (std.mem.eql(u8, &t, &topic)) break true;
            } else false;
            if (!ok) return false;
        }
        return true;
    }
};

fn parse_hashes(scanner: *json.Scanner, first: json.Token, out: [][32]u8) HandlerError!u32 {
    if (first.tag == .null) return 0;
    if (first.tag == .string) {
        out[0] = json.parse_fixed(32, first.bytes) catch return error.InvalidParams;
        return 1;
    }
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (true) {
        const token = try scanner_next(scanner);
        if (token.tag == .array_end) return count;
        if (count == out.len or token.tag != .string) return error.InvalidParams;
        out[count] = json.parse_fixed(32, token.bytes) catch return error.InvalidParams;
        count += 1;
    }
}

pub fn parse_filter(api: *Api, call: *Call, raw: []const u8) HandlerError!Filter {
    const head = head_header(api).number;
    var filter: Filter = .{ .from = head, .to = head };
    var scanner = json.Scanner.init(raw);
    if ((try scanner_next(&scanner)).tag != .object_begin) return error.InvalidParams;
    while (true) {
        const name = try scanner_next(&scanner);
        if (name.tag == .object_end) break;
        const value = try scanner_next(&scanner);
        if (std.mem.eql(u8, name.bytes, "fromBlock") or std.mem.eql(u8, name.bytes, "toBlock")) {
            if (value.tag != .string) return error.InvalidParams;
            const number = try resolve_number_text(api, call, value.bytes);
            if (name.bytes[0] == 'f') filter.from = number else filter.to = number;
            if (name.bytes[0] == 't') filter.to_given = std.mem.startsWith(u8, value.bytes, "0x");
        } else if (std.mem.eql(u8, name.bytes, "blockHash")) {
            filter.block_hash = json.parse_fixed(32, value.bytes) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "address")) {
            filter.address_count = try parse_addresses(&scanner, value, &filter.addresses);
        } else if (std.mem.eql(u8, name.bytes, "topics")) {
            if (value.tag != .array_begin) return error.InvalidParams;
            var position: usize = 0;
            while (true) : (position += 1) {
                const entry = try scanner_next(&scanner);
                if (entry.tag == .array_end) break;
                if (position == 4) return error.InvalidParams;
                const allowed = &filter.topics[position];
                filter.topic_counts[position] = try parse_hashes(&scanner, entry, allowed);
            }
        } else scanner.skip(value) catch return error.InvalidParams;
    }
    return filter;
}

fn parse_addresses(scanner: *json.Scanner, first: json.Token, out: *[16][20]u8) HandlerError!u32 {
    if (first.tag == .string) {
        out[0] = json.parse_fixed(20, first.bytes) catch return error.InvalidParams;
        return 1;
    }
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (true) {
        const token = try scanner_next(scanner);
        if (token.tag == .array_end) return count;
        if (count == out.len or token.tag != .string) return error.InvalidParams;
        out[count] = json.parse_fixed(20, token.bytes) catch return error.InvalidParams;
        count += 1;
    }
}

fn get_logs(api: *Api, call: *Call) HandlerError!void {
    const filter = try parse_filter(api, call, try call.params.raw());
    try call.params.finish();
    if (filter.block_hash == null) {
        if (filter.to < filter.from) {
            return call.fail(rpc.code.invalid_params, "invalid block range");
        }
        if (filter.to - filter.from >= logs_blocks_max) {
            return call.fail(rpc.code.server_error, "block range too large");
        }
    }
    try call.writer.begin_array();
    var written: u32 = 0;
    if (filter.block_hash) |hash| {
        try block_logs(api, call, hash, &filter, &written);
    } else {
        var number = filter.from;
        while (number <= filter.to) : (number += 1) {
            const hash = api.chain.store.canonical_hash(number) orelse continue;
            try block_logs(api, call, hash, &filter, &written);
        }
    }
    try call.writer.end_array();
}

pub fn block_logs(
    api: *Api,
    call: *Call,
    hash: Hash,
    filter: *const Filter,
    written: *u32,
) HandlerError!void {
    const record = api.chain.record(hash) orelse return;
    if (record.header.logs_bloom.eql(.zero)) return; // No logs in the block.
    var transactions = record.transactions;
    var receipts = record.receipts;
    var index: u32 = 0;
    var log_index: u64 = 0;
    while (!transactions.is_empty()) : (index += 1) {
        const raw = transactions.bytes() catch unreachable;
        const encoded = receipts.bytes() catch unreachable; // Stored by the chain.
        const value = consensus.Receipt.decode(encoded) catch unreachable;
        const at: format.Inclusion = .{
            .block_hash = hash,
            .block_number = record.header.number,
            .index = index,
            .base_fee = null,
        };
        const tx_hash = primitives.keccak256(raw).bytes;
        var it = value.logs.iterator();
        while (it.next()) |item| : (log_index += 1) {
            if (!filter.matches(item)) continue;
            if (written.* == logs_max) return call.fail(rpc.code.server_error, "too many logs");
            try format.log(call.writer, item, at, tx_hash, log_index);
            written.* += 1;
        }
    }
}

test {
    _ = @import("eth_test.zig");
    _ = @import("debug_test.zig");
    _ = @import("debug_http_test.zig");
    _ = @import("eth_proof_test.zig");
}

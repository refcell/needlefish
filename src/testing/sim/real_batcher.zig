//! The batcher lane's real `batcher/service` running inside the simulator. Its three
//! JSON-RPC clients (L1, the sequencer's L2 EL, the rollup node) talk to `Backend`,
//! which answers synchronously from model state. Network faults surface as transport
//! failures: a crashed or partitioned peer, or a randomly dropped call.
//!
//! The L1 model enforces account nonces for these transactions, so the real txmgr's
//! nonce tracking, fee-bump resubmission, and the service's safe-head stall reset all
//! run under crashes, partitions, drops, and L1 reorgs. The model batcher keeps running
//! with submissions off, as an L1 observer for the confirmation checks.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../batcher/rpc/root.zig");
const service_module = @import("../../batcher/service/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const l1_info = @import("../../consensus/protocol/l1_info.zig");
const tx_module = @import("../../common/consensus/tx.zig");
const hex = @import("../../common/primitives/hex.zig");
const Prng = @import("../prng.zig").Prng;
const codec = @import("codec.zig");
const nodes = @import("nodes.zig");

pub const l1_chain_id = 900;
pub const step_interval_ns: u64 = 2 * std.time.ns_per_s;
const raw_tx_bytes_max = codec.tx_data_max + 256;

/// What the batcher can see this step. Pointers are rebound every step because the
/// cluster lives by value.
pub const View = struct {
    l1: *nodes.L1,
    sequencer: *const nodes.Sequencer,
    pool: *codec.TxPool,
    prng: *Prng,
    l1_reachable: bool,
    l2_reachable: bool,
    /// The rollup node is the first verifier; null when it is unreachable.
    rollup: ?struct { safe: u64, unsafe: u64 },
    drop_ppm: u32,
};

pub const Stats = struct {
    calls: u64 = 0,
    transport_failures: u64 = 0,
    submitted: u64 = 0,
    step_errors: u64 = 0,
    steps: u64 = 0,
};

const Role = enum { l1, l2, rollup };

const Endpoint = struct {
    backend: *Backend,
    role: Role,
};

const Backend = struct {
    view: ?View = null,
    stats: Stats = .{},
    info_hex: [2 * l1_info.calldata_length_max]u8 = undefined,
    info_hex_length: usize = 0,

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const endpoint: *Endpoint = @ptrCast(@alignCast(context));
        const backend = endpoint.backend;
        const view = backend.view orelse return error.TransportFailed;
        backend.stats.calls += 1;
        const reachable = switch (endpoint.role) {
            .l1 => view.l1_reachable,
            .l2 => view.l2_reachable,
            .rollup => view.rollup != null,
        };
        if (!reachable or view.prng.chance(view.drop_ppm, 1_000_000)) {
            backend.stats.transport_failures += 1;
            return error.TransportFailed;
        }
        const id = between(body, "\"id\":", ",") orelse return error.TransportFailed;
        const method = between(body, "\"method\":\"", "\"") orelse return error.TransportFailed;
        var writer: std.Io.Writer = .fixed(response);
        writer.print("{{\"jsonrpc\":\"2.0\",\"id\":{s},", .{id}) catch
            return error.ResponseTooLarge;
        backend.answer(endpoint.role, view, method, body, &writer) catch
            return error.ResponseTooLarge;
        writer.writeAll("}") catch return error.ResponseTooLarge;
        return writer.end;
    }

    fn answer(
        backend: *Backend,
        role: Role,
        view: View,
        method: []const u8,
        body: []const u8,
        out: *std.Io.Writer,
    ) !void {
        switch (role) {
            .l1 => try backend.answer_l1(view, method, body, out),
            .l2 => try backend.answer_l2(view, method, body, out),
            .rollup => {
                const rollup = view.rollup.?;
                if (!std.mem.eql(u8, method, "optimism_syncStatus")) return rpc_error(out);
                try out.print("\"result\":{{\"safe_l2\":{{\"number\":{d}}}," ++
                    "\"unsafe_l2\":{{\"number\":{d}}}}}", .{ rollup.safe, rollup.unsafe });
            },
        }
    }

    fn answer_l1(
        backend: *Backend,
        view: View,
        method: []const u8,
        body: []const u8,
        out: *std.Io.Writer,
    ) !void {
        const eql = std.mem.eql;
        if (eql(u8, method, "eth_blockNumber")) {
            return out.print("\"result\":\"0x{x}\"", .{view.l1.head});
        }
        if (eql(u8, method, "eth_getBlockByNumber")) {
            return out.print("\"result\":{{\"number\":\"0x{x}\",\"baseFeePerGas\":\"0x7\"}}", .{
                view.l1.head,
            });
        }
        if (eql(u8, method, "eth_maxPriorityFeePerGas")) return out.writeAll("\"result\":\"0x1\"");
        if (eql(u8, method, "eth_getTransactionCount")) {
            const pending = std.mem.indexOf(u8, body, "\"pending\"") != null;
            const nonce = if (pending) view.l1.nonce_pending() else view.l1.nonce_mined();
            return out.print("\"result\":\"0x{x}\"", .{nonce});
        }
        if (eql(u8, method, "eth_sendRawTransaction")) return backend.send_raw(view, body, out);
        return rpc_error_message(out, "method not found");
    }

    fn send_raw(backend: *Backend, view: View, body: []const u8, out: *std.Io.Writer) !void {
        const raw_hex = between(body, "\"params\":[\"0x", "\"") orelse
            return rpc_error_message(out, "invalid params");
        var raw: [raw_tx_bytes_max]u8 = undefined;
        if (raw_hex.len > 2 * raw.len) return rpc_error_message(out, "oversized data");
        const bytes = hex.decode_into(&raw, raw_hex) catch
            return rpc_error_message(out, "invalid hex");
        const envelope = tx_module.Envelope.decode(bytes) catch
            return rpc_error_message(out, "rlp: invalid transaction");
        const tx = switch (envelope) {
            .eip1559 => |signed| signed.tx,
            else => return rpc_error_message(out, "transaction type not supported"),
        };
        if (tx.chain_id != l1_chain_id) return rpc_error_message(out, "invalid chain id");
        const to = switch (tx.to) {
            .call => |address| address,
            .create => return rpc_error_message(out, "unexpected contract creation"),
        };
        if (!to.eql(codec.batch_inbox)) return rpc_error_message(out, "wrong inbox");
        if (tx.input.len == 0 or tx.input.len > codec.tx_data_max) {
            return rpc_error_message(out, "oversized data");
        }
        const tx_index = view.pool.append(tx.input) orelse
            return rpc_error_message(out, "txpool is full");
        switch (view.l1.submit_nonced(tx_index, tx.nonce)) {
            .accepted, .replaced => {},
            .nonce_too_low => return rpc_error_message(out, "nonce too low"),
            .mempool_full => return rpc_error_message(out, "txpool is full"),
        }
        backend.stats.submitted += 1;
        try out.print("\"result\":\"0x{x}\"", .{&envelope.hash().bytes});
    }

    fn answer_l2(
        backend: *Backend,
        view: View,
        method: []const u8,
        body: []const u8,
        out: *std.Io.Writer,
    ) !void {
        const eql = std.mem.eql;
        const head = view.sequencer.head;
        if (eql(u8, method, "eth_blockNumber")) return out.print("\"result\":\"0x{x}\"", .{head});
        if (!eql(u8, method, "eth_getBlockByNumber")) return rpc_error(out);
        const number_hex = between(body, "\"params\":[\"", "\"") orelse
            return rpc_error_message(out, "invalid params");
        const number = hex.decode_quantity(u64, number_hex) catch
            return rpc_error_message(out, "invalid block number");
        if (number == 0 or number > head) return out.writeAll("\"result\":null");
        try backend.write_l2_block(view.sequencer, number, out);
    }

    /// The model block as `eth_getBlockByNumber(n, true)`: the L1 info deposit, then one
    /// EIP-1559 transaction carrying the payload (see `codec.payload_envelope`).
    fn write_l2_block(
        backend: *Backend,
        sequencer: *const nodes.Sequencer,
        number: u64,
        out: *std.Io.Writer,
    ) !void {
        const chain = &sequencer.chain;
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, chain.payloads[number], .big);
        const envelope = codec.payload_envelope(&payload);
        const tx = envelope.eip1559.tx;
        try out.print("\"result\":{{\"number\":\"0x{x}\",\"hash\":\"0x{x}\"," ++
            "\"parentHash\":\"0x{x}\",\"timestamp\":\"0x{x}\",\"transactions\":[", .{
            number,
            &codec.word_hash(chain.hashes[number]).bytes,
            &codec.word_hash(chain.hashes[number - 1]).bytes,
            number * codec.l2_block_time_s,
        });
        try out.print("{{\"type\":\"0x7e\",\"input\":\"0x{s}\"}},", .{
            backend.info_hex[0..backend.info_hex_length],
        });
        try out.print("{{\"type\":\"0x2\",\"chainId\":\"0x{x}\",\"nonce\":\"0x0\"," ++
            "\"gas\":\"0x{x}\",\"value\":\"0x0\",\"to\":\"0x{x}\",\"input\":\"0x{x}\"," ++
            "\"maxPriorityFeePerGas\":\"0x{x}\",\"maxFeePerGas\":\"0x{x}\"," ++
            "\"accessList\":[],\"yParity\":\"0x0\",\"r\":\"0x1\",\"s\":\"0x1\"," ++
            "\"hash\":\"0x{x}\"}}]}}", .{
            tx.chain_id,
            tx.gas_limit,
            &tx.to.call.bytes,
            &payload,
            tx.max_priority_fee_per_gas,
            tx.max_fee_per_gas,
            &envelope.hash().bytes,
        });
    }
};

fn rpc_error(out: *std.Io.Writer) !void {
    return rpc_error_message(out, "method not found");
}

fn rpc_error_message(out: *std.Io.Writer, message: []const u8) !void {
    try out.print("\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}", .{message});
}

fn between(body: []const u8, start: []const u8, end: []const u8) ?[]const u8 {
    const from = (std.mem.indexOf(u8, body, start) orelse return null) + start.len;
    const length = std.mem.indexOf(u8, body[from..], end) orelse return null;
    return body[from..][0..length];
}

/// The batcher account from the public dev mnemonic. Derivation runs PBKDF2, so it is
/// computed once per process (the simulator is single-threaded).
var dev_account: ?accounts.Account = null;

fn batcher_account() accounts.Account {
    if (dev_account == null) dev_account = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    return dev_account.?;
}

fn service_config() service_module.Config {
    const account = batcher_account();
    return .{
        .channels = .{
            // Single-frame channels: the simulated derivation is stateless per L1 tx.
            // An input cap below the frame size keeps even incompressible data in one
            // frame (zlib stored blocks add a few bytes).
            .channel = .{
                .frame_size_max = codec.tx_data_max - 1,
                .target_frames = 1,
                .compression_ratio_percent = 100,
                .input_bytes_max = 1900,
            },
            .max_channel_duration_l1_blocks = 2,
            .batch_bytes_max = 512,
        },
        .txs = .{
            .chain_id = l1_chain_id,
            .private_key = account.private_key,
            .from = account.address,
            .to = codec.batch_inbox,
            .tx_data_bytes_max = codec.tx_data_max,
        },
        .source = .{ .tx_count_max = 4, .tx_bytes_max = 4096, .input_bytes_max = 1024 },
        .blocks_per_step_max = 16,
        .stall_l1_blocks = 10,
    };
}

pub const RealBatcher = struct {
    backend: Backend,
    endpoints: [3]Endpoint,
    clients: [3]rpc.Client,
    service: service_module.Service,
    next_step_ns: u64 = 0,
    restarts: u32 = 0,

    /// Heap-allocated: the transports point back into this struct.
    pub fn create(allocator: std.mem.Allocator) !*RealBatcher {
        const batcher = try allocator.create(RealBatcher);
        errdefer allocator.destroy(batcher);
        batcher.backend = .{};
        const info: l1_info.L1BlockInfo = .{ .format = .jovian };
        var calldata: [l1_info.calldata_length_max]u8 = undefined;
        const encoded = info.encode_calldata(&calldata);
        const written = std.fmt.bufPrint(&batcher.backend.info_hex, "{x}", .{encoded}) catch
            unreachable; // Twice the calldata bound.
        batcher.backend.info_hex_length = written.len;
        const limits: rpc.Limits = .{
            .request_bytes_max = 2 * raw_tx_bytes_max + 256,
            .response_bytes_max = 8 * 1024,
            .parse_bytes_max = 64 * 1024,
        };
        var initialized: u8 = 0;
        errdefer for (batcher.clients[0..initialized]) |*client| client.deinit(allocator);
        for (&batcher.endpoints, &batcher.clients, 0..) |*endpoint, *client, index| {
            endpoint.* = .{ .backend = &batcher.backend, .role = @fromBackingInt(@intCast(index)) };
            const transport: rpc.Transport = .{ .context = endpoint, .send_fn = Backend.send };
            client.* = try rpc.Client.init(allocator, transport, limits);
            initialized += 1;
        }
        batcher.service = try service_module.Service.init(allocator, service_config(), @splat(7));
        batcher.next_step_ns = 0;
        batcher.restarts = 0;
        return batcher;
    }

    pub fn destroy(batcher: *RealBatcher, allocator: std.mem.Allocator) void {
        batcher.service.deinit(allocator);
        for (&batcher.clients) |*client| client.deinit(allocator);
        allocator.destroy(batcher);
    }

    /// Steps the service on its interval. Errors are retried on the next step, as the
    /// binary's driver loop does.
    pub fn tick(batcher: *RealBatcher, now_ns: u64, view: View) void {
        if (now_ns < batcher.next_step_ns) return;
        batcher.next_step_ns = now_ns + step_interval_ns;
        batcher.backend.view = view;
        defer batcher.backend.view = null;
        batcher.backend.stats.steps += 1;
        const clients: service_module.Clients = .{
            .l1 = &batcher.clients[0],
            .l2 = &batcher.clients[1],
            .rollup = &batcher.clients[2],
        };
        _ = batcher.service.step(clients, now_ns / std.time.ns_per_ms) catch {
            batcher.backend.stats.step_errors += 1;
        };
    }

    /// Crash-restart: in-memory service state is lost; a fresh service re-reads nonces
    /// and resubmits from the safe head.
    pub fn restart(batcher: *RealBatcher, allocator: std.mem.Allocator, now_ns: u64) !void {
        batcher.service.deinit(allocator);
        const seed: u8 = @truncate(batcher.restarts +% 8);
        const config = service_config();
        batcher.service = try service_module.Service.init(allocator, config, @splat(seed));
        batcher.restarts += 1;
        batcher.next_step_ns = now_ns;
    }

    pub fn stats(batcher: *const RealBatcher) Stats {
        return batcher.backend.stats;
    }
};

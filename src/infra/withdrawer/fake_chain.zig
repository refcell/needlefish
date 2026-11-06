//! Fake L1 and L2 JSON-RPC chains for withdrawal tests (withdrawer flow, fee-jobs confirm).
//!
//! One `Chain` type plays either side: L2 serves the fixture's receipts, header, and
//! message passer proof (plus `eth_blockNumber`/`eth_getLogs`); L1 serves the portal,
//! factory, registry, and game reads with one respected game that covers the fixture's
//! header and claims its output root. Both accept raw transactions and mine them in nonce
//! order on `mine`; a mined finalization emits `WithdrawalFinalized`.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const registry = @import("../../proof/contracts/anchor_state_registry.zig");
const factory = @import("../../proof/contracts/dispute_game_factory.zig");
const calldata = @import("calldata.zig");

pub const Hash = [32]u8;
pub const Address = [20]u8;

pub const portal: Address = @splat(0x50);
pub const factory_address: Address = @splat(0xfa);
pub const registry_address: Address = @splat(0xa5);
pub const game_proxy: Address = @splat(0x9a);
pub const sends_max = 16;

/// An L2 receipt served by `eth_getTransactionReceipt`.
pub const Receipt = struct { hash: Hash, json: []const u8 };

pub const Fixture = struct {
    receipts: []const Receipt,
    /// The L2 header at `header_number` (the game's block).
    header: []const u8,
    header_number: u64,
    /// The `eth_getProof` answer for the message passer at `header_number`.
    proof: []const u8,
    root_claim: Hash,
    /// The withdrawal a mined finalization reports in `WithdrawalFinalized`.
    withdrawal_hash: Hash,
    /// The L2 `eth_getLogs` answer (a JSON array).
    logs: []const u8 = "[]",
};

pub const Sent = struct { hash: Hash, nonce: u64, selector: [4]u8, block: u64 = 0 };

pub const Chain = struct {
    fixture: *const Fixture,
    is_l2: bool,
    head: u64 = 10,
    time_s: u64 = 1_000,
    account_nonce: u64 = 0,
    sent: [sends_max]Sent = undefined,
    sent_count: u32 = 0,
    proven_at: u64 = 0,
    finalized: bool = false,
    paused: bool = false,
    game_finalized: bool = true,
    finalize_success: bool = true,
    get_logs_calls: u32 = 0,

    pub fn transport(chain: *Chain) rpc.Transport {
        return .{ .context = chain, .send_fn = send };
    }

    pub fn block_hash(number: u64) Hash {
        var hash: Hash = @splat(0xbb);
        std.mem.writeInt(u64, hash[0..8], number, .big);
        return hash;
    }

    /// Mines every pending transaction in one block at `time_s`.
    pub fn mine(chain: *Chain, time_s: u64) void {
        chain.head += 1;
        chain.time_s = time_s;
        for (chain.sent[0..chain.sent_count]) |*sent| {
            if (sent.block != 0 or sent.nonce != chain.account_nonce) continue;
            sent.block = chain.head;
            chain.account_nonce += 1;
            if (std.mem.eql(u8, &sent.selector, &calldata.prove_withdrawal_transaction)) {
                chain.proven_at = time_s;
            }
            if (std.mem.eql(u8, &sent.selector, &calldata.finalize_withdrawal_transaction)) {
                chain.finalized = chain.finalize_success;
            }
        }
    }

    pub fn count(chain: *const Chain, selector: [4]u8) u32 {
        var total: u32 = 0;
        for (chain.sent[0..chain.sent_count]) |sent| {
            if (std.mem.eql(u8, &sent.selector, &selector)) total += 1;
        }
        return total;
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const chain: *Chain = @ptrCast(@alignCast(context));
        var arena_memory: [64 * 1024]u8 = undefined;
        var arena: std.heap.FixedBufferAllocator = .init(&arena_memory);
        const Value = std.json.Value;
        const request = std.json.parseFromSliceLeaky(Value, arena.allocator(), body, .{}) catch
            return error.TransportFailed;
        const id = request.object.get("id").?.integer;
        const method = request.object.get("method").?.string;
        const params = request.object.get("params").?.array.items;
        var writer: std.Io.Writer = .fixed(response);
        writer.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":", .{id}) catch
            return error.ResponseTooLarge;
        chain.answer(method, params, &writer) catch |err| switch (err) {
            error.WriteFailed => return error.ResponseTooLarge,
            else => return error.TransportFailed,
        };
        writer.writeAll("}") catch return error.ResponseTooLarge;
        return writer.buffered().len;
    }

    fn answer(
        chain: *Chain,
        method: []const u8,
        params: []const std.json.Value,
        w: *std.Io.Writer,
    ) !void {
        const eql = std.mem.eql;
        if (eql(u8, method, "eth_getBlockByNumber")) return chain.block(params[0].string, w);
        if (eql(u8, method, "eth_maxPriorityFeePerGas")) return w.writeAll("\"0x1\"");
        if (eql(u8, method, "eth_estimateGas")) return w.writeAll("\"0x30d40\"");
        if (eql(u8, method, "eth_getTransactionCount")) {
            return w.print("\"0x{x}\"", .{chain.account_nonce});
        }
        if (eql(u8, method, "eth_sendRawTransaction")) return chain.accept(params[0].string, w);
        if (eql(u8, method, "eth_getTransactionReceipt")) return chain.receipt(params[0].string, w);
        if (eql(u8, method, "eth_getProof")) return w.writeAll(chain.fixture.proof);
        if (eql(u8, method, "eth_call")) return chain.call(params[0], w);
        if (eql(u8, method, "eth_blockNumber")) return w.print("\"0x{x}\"", .{chain.head});
        if (eql(u8, method, "eth_getLogs")) {
            chain.get_logs_calls += 1;
            return w.writeAll(chain.fixture.logs);
        }
        return error.UnknownMethod;
    }

    fn block(chain: *Chain, tag: []const u8, w: *std.Io.Writer) !void {
        const number = if (std.mem.eql(u8, tag, "latest"))
            chain.head
        else
            try std.fmt.parseInt(u64, tag[2..], 16);
        if (chain.is_l2 and number == chain.fixture.header_number) {
            return w.writeAll(chain.fixture.header);
        }
        // The withdrawal's L2 block is older than every game.
        const timestamp = if (chain.is_l2) 1_500 else chain.time_s;
        try w.print("{{\"number\":\"0x{x}\",\"timestamp\":\"0x{x}\",\"baseFeePerGas\":\"0x7\"," ++
            "\"hash\":\"0x{x}\"}}", .{ number, timestamp, &block_hash(number) });
    }

    fn accept(chain: *Chain, hex: []const u8, w: *std.Io.Writer) !void {
        var raw: [16 * 1024]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&raw, hex[2..]);
        const envelope = try consensus.tx.Envelope.decode(bytes);
        const input = envelope.input();
        assert(chain.sent_count < sends_max);
        chain.sent[chain.sent_count] = .{
            .hash = envelope.hash().bytes,
            .nonce = envelope.nonce().?,
            .selector = input[0..4].*,
        };
        chain.sent_count += 1;
        try w.print("\"0x{x}\"", .{&envelope.hash().bytes});
    }

    fn receipt(chain: *Chain, hex: []const u8, w: *std.Io.Writer) !void {
        var hash: Hash = undefined;
        _ = try std.fmt.hexToBytes(&hash, hex[2..]);
        if (chain.is_l2) for (chain.fixture.receipts) |entry| {
            if (std.mem.eql(u8, &hash, &entry.hash)) return w.writeAll(entry.json);
        };
        for (chain.sent[0..chain.sent_count]) |sent| {
            if (!std.mem.eql(u8, &sent.hash, &hash) or sent.block == 0) continue;
            try w.print("{{\"status\":\"0x1\",\"blockNumber\":\"0x{x}\",\"blockHash\":\"0x{x}\"," ++
                "\"logs\":[", .{ sent.block, &block_hash(sent.block) });
            if (std.mem.eql(u8, &sent.selector, &calldata.finalize_withdrawal_transaction)) {
                try chain.finalized_log(w);
            }
            return w.writeAll("]}");
        }
        try w.writeAll("null");
    }

    fn finalized_log(chain: *Chain, w: *std.Io.Writer) !void {
        try w.print("{{\"address\":\"0x{x}\",\"topics\":[\"0x{x}\",\"0x{x}\"]," ++
            "\"data\":\"0x{x}\"}}", .{
            &portal,
            &calldata.withdrawal_finalized_topic,
            &chain.fixture.withdrawal_hash,
            &word(@intFromBool(chain.finalize_success)),
        });
    }

    fn call(chain: *Chain, request: std.json.Value, w: *std.Io.Writer) !void {
        var to: Address = undefined;
        _ = try std.fmt.hexToBytes(&to, request.object.get("to").?.string[2..]);
        var input_buffer: [256]u8 = undefined;
        const data_hex = request.object.get("data").?.string[2..];
        const input = try std.fmt.hexToBytes(&input_buffer, data_hex);
        const selector = input[0..4].*;
        if (is(selector, calldata.check_withdrawal)) return w.writeAll("\"0x\"");
        var result: [3][32]u8 = undefined;
        const words = try chain.call_words(selector, &result);
        try w.writeAll("\"0x");
        for (result[0..words]) |item| try w.print("{x}", .{&item});
        try w.writeAll("\"");
    }

    fn call_words(chain: *Chain, selector: [4]u8, out: *[3][32]u8) !usize {
        if (is(selector, calldata.dispute_game_factory)) {
            return one(out, address_word(factory_address));
        }
        if (is(selector, calldata.anchor_state_registry)) {
            return one(out, address_word(registry_address));
        }
        if (is(selector, calldata.finalized_withdrawals)) return one(out, flag(chain.finalized));
        if (is(selector, registry.paused)) return one(out, flag(chain.paused));
        if (is(selector, calldata.proven_withdrawals)) {
            out[0] = address_word(if (chain.proven_at == 0) @splat(0) else game_proxy);
            out[1] = word(chain.proven_at);
            return 2;
        }
        return chain.game_words(selector, out);
    }

    fn game_words(chain: *Chain, selector: [4]u8, out: *[3][32]u8) !usize {
        if (is(selector, registry.is_game_blacklisted)) return one(out, word(0));
        if (is(selector, registry.is_game_retired)) return one(out, word(0));
        if (is(selector, registry.is_game_proper)) return one(out, word(1));
        if (is(selector, registry.is_game_respected)) return one(out, word(1));
        if (is(selector, registry.is_game_finalized)) return one(out, flag(chain.game_finalized));
        if (is(selector, calldata.game_status)) return one(out, word(2));
        if (is(selector, calldata.proof_maturity_delay_seconds)) return one(out, word(100));
        if (is(selector, calldata.game_resolved_at)) return one(out, word(500));
        if (is(selector, registry.dispute_game_finality_delay_seconds)) return one(out, word(200));
        if (is(selector, factory.game_count)) return one(out, word(1));
        if (is(selector, factory.game_at_index)) {
            out[0] = word(621);
            out[1] = word(2_000);
            out[2] = address_word(game_proxy);
            return 3;
        }
        if (is(selector, calldata.game_extra_data)) {
            out[0] = word(32);
            out[1] = word(32);
            out[2] = word(chain.fixture.header_number);
            return 3;
        }
        if (is(selector, calldata.game_root_claim)) return one(out, chain.fixture.root_claim);
        return error.UnknownSelector;
    }
};

fn is(selector: [4]u8, expected: [4]u8) bool {
    return std.mem.eql(u8, &selector, &expected);
}

fn flag(value: bool) [32]u8 {
    return word(@intFromBool(value));
}

fn one(out: *[3][32]u8, value: [32]u8) usize {
    out[0] = value;
    return 1;
}

pub fn word(value: u64) [32]u8 {
    var out: [32]u8 = @splat(0);
    std.mem.writeInt(u64, out[24..32], value, .big);
    return out;
}

pub fn address_word(address: Address) [32]u8 {
    var out: [32]u8 = @splat(0);
    out[12..32].* = address;
    return out;
}

test "fake chain: block hashes differ per number" {
    const first = Chain.block_hash(1);
    const second = Chain.block_hash(2);
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expectEqual(@as(u8, 0xbb), first[31]);
}

//! Transaction manager: sends batcher payloads to L1 and keeps them alive until they
//! are included.
//!
//! Every payload gets the next nonce of the batcher account and occupies a slot until
//! the account's mined nonce passes it. A slot whose transaction is not mined within
//! `resubmit_after_ms` is re-signed with bumped fees under the same nonce (op txmgr
//! semantics), so a stuck or dropped transaction never blocks later nonces for long.
//! Slots and buffers are allocated once; the account key is used only for signing.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../rpc/root.zig");
const txdata = @import("../txdata/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: Address,
    to: Address,
    slots_max: u8 = 8,
    tx_data_bytes_max: u32 = 128 * 1024,
    resubmit_after_ms: u64 = 12_000,
    tip_wei_default: u128 = 1_000_000_000,
    /// Replacement fee bump in percent (geth requires 10 for non-blob transactions).
    bump_percent: u8 = 10,
};

pub const Slot = struct {
    state: enum { free, pending } = .free,
    nonce: u64 = 0,
    fees: txdata.Fees = .{ .max_fee_per_gas = 0, .max_priority_fee_per_gas = 0 },
    data: []u8,
    data_length: u32 = 0,
    sent_at_ms: u64 = 0,
    attempts: u32 = 0,
    hash: primitives.B256 = .zero,
};

pub const Error = rpc.Error || rpc.DecodeError || txdata.SignError || error{NoFreeSlot};

pub const TxManager = struct {
    config: Config,
    slots: []Slot,
    next_nonce: ?u64,
    raw_buffer: []u8,
    params_buffer: []u8,

    pub fn init(allocator: std.mem.Allocator, config: Config) !TxManager {
        assert(config.slots_max > 0);
        assert(config.bump_percent >= 10);
        const slots = try allocator.alloc(Slot, config.slots_max);
        errdefer allocator.free(slots);
        var initialized: usize = 0;
        errdefer for (slots[0..initialized]) |slot| allocator.free(slot.data);
        for (slots) |*slot| {
            slot.* = .{ .data = try allocator.alloc(u8, config.tx_data_bytes_max) };
            initialized += 1;
        }
        const raw_buffer = try allocator.alloc(u8, config.tx_data_bytes_max + 512);
        errdefer allocator.free(raw_buffer);
        const params_buffer = try allocator.alloc(u8, 2 * raw_buffer.len + 16);
        return .{
            .config = config,
            .slots = slots,
            .next_nonce = null,
            .raw_buffer = raw_buffer,
            .params_buffer = params_buffer,
        };
    }

    pub fn deinit(manager: *TxManager, allocator: std.mem.Allocator) void {
        for (manager.slots) |slot| allocator.free(slot.data);
        allocator.free(manager.slots);
        allocator.free(manager.raw_buffer);
        allocator.free(manager.params_buffer);
        manager.* = undefined;
    }

    pub fn pending_count(manager: *const TxManager) u32 {
        var count: u32 = 0;
        for (manager.slots) |slot| count += @intFromBool(slot.state == .pending);
        return count;
    }

    pub fn has_capacity(manager: *const TxManager) bool {
        return manager.pending_count() < manager.slots.len;
    }

    /// Queues `tx_data` under the next nonce and sends it.
    pub fn submit(
        manager: *TxManager,
        client: *rpc.Client,
        tx_data: []const u8,
        now_ms: u64,
    ) Error!void {
        assert(tx_data.len > 0 and tx_data.len <= manager.config.tx_data_bytes_max);
        const slot = for (manager.slots) |*slot| {
            if (slot.state == .free) break slot;
        } else return error.NoFreeSlot;
        const nonce = manager.next_nonce orelse try manager.account_nonce(client, "pending");
        @memcpy(slot.data[0..tx_data.len], tx_data);
        slot.* = .{
            .state = .pending,
            .nonce = nonce,
            .fees = try manager.suggested_fees(client),
            .data = slot.data,
            .data_length = @intCast(tx_data.len),
        };
        manager.next_nonce = nonce + 1;
        try manager.send(client, slot, now_ms);
        assert(slot.state == .pending);
    }

    /// Frees slots whose nonce was mined and resubmits stale ones. Returns the number
    /// of transactions confirmed by this poll.
    pub fn poll(manager: *TxManager, client: *rpc.Client, now_ms: u64) Error!u32 {
        if (manager.pending_count() == 0) return 0;
        const mined_nonce = try manager.account_nonce(client, "latest");
        var confirmed: u32 = 0;
        for (manager.slots) |*slot| {
            if (slot.state != .pending) continue;
            if (slot.nonce < mined_nonce) {
                slot.state = .free;
                confirmed += 1;
                continue;
            }
            if (now_ms >= slot.sent_at_ms + manager.config.resubmit_after_ms) {
                const suggested = try manager.suggested_fees(client);
                slot.fees = txdata.bump_fees(slot.fees, suggested, manager.config.bump_percent);
                try manager.send(client, slot, now_ms);
            }
        }
        return confirmed;
    }

    /// Forgets all pending work, e.g. after a reset; nonces are re-read on next submit.
    pub fn reset(manager: *TxManager) void {
        for (manager.slots) |*slot| slot.state = .free;
        manager.next_nonce = null;
    }

    fn send(manager: *TxManager, client: *rpc.Client, slot: *Slot, now_ms: u64) Error!void {
        const data = slot.data[0..slot.data_length];
        const envelope = try txdata.sign_eip1559(.{
            .chain_id = manager.config.chain_id,
            .nonce = slot.nonce,
            .fees = slot.fees,
            .gas_limit = txdata.calldata_gas(data),
            .to = manager.config.to,
            .data = data,
        }, manager.config.private_key);
        const raw = txdata.encode_raw(envelope, manager.raw_buffer);
        const params = std.fmt.bufPrint(manager.params_buffer, "[\"0x{x}\"]", .{raw}) catch
            unreachable; // params_buffer holds twice the largest raw transaction.
        slot.sent_at_ms = now_ms;
        slot.attempts += 1;
        slot.hash = envelope.hash();
        _ = client.call("eth_sendRawTransaction", params) catch |err| switch (err) {
            // Known benign answers: already mined, already pooled, or the previous
            // attempt still wins; `poll` decides what happens next.
            error.RpcError => if (!benign_send_error(client.last_error())) return err,
            else => return err,
        };
    }

    fn account_nonce(manager: *TxManager, client: *rpc.Client, tag: []const u8) Error!u64 {
        var buffer: [96]u8 = undefined;
        const params = std.fmt.bufPrint(&buffer, "[\"0x{x}\",\"{s}\"]", .{
            &manager.config.from.bytes,
            tag,
        }) catch unreachable; // Fixed-size content.
        return rpc.quantity(u64, try client.call("eth_getTransactionCount", params));
    }

    fn suggested_fees(manager: *TxManager, client: *rpc.Client) Error!txdata.Fees {
        const head = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
        const base_fee = try rpc.quantity(u128, try rpc.field(head, "baseFeePerGas"));
        const tip = blk: {
            const value = client.call("eth_maxPriorityFeePerGas", "[]") catch
                break :blk manager.config.tip_wei_default;
            break :blk rpc.quantity(u128, value) catch manager.config.tip_wei_default;
        };
        return txdata.suggest_fees(base_fee, @max(tip, 1));
    }
};

fn benign_send_error(message: []const u8) bool {
    const benign = [_][]const u8{
        "nonce too low",
        "already known",
        "known transaction",
        "replacement transaction underpriced",
    };
    var lower_buffer: [256]u8 = undefined;
    const lower = std.ascii.lowerString(&lower_buffer, message[0..@min(message.len, 256)]);
    for (benign) |needle| {
        if (std.mem.indexOf(u8, lower, needle) != null) return true;
    }
    return false;
}

const testing = std.testing;
const accounts = @import("../devnet/accounts.zig");

/// Scripted L1: tracks the mined nonce and records sent transactions.
const FakeL1 = struct {
    mined_nonce: u64 = 5,
    sends: u32 = 0,
    reject_with: ?[]const u8 = null,

    fn transport(l1: *FakeL1) rpc.Transport {
        return .{ .context = l1, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const l1: *FakeL1 = @ptrCast(@alignCast(context));
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id = body[id_start..][0..std.mem.indexOfScalar(u8, body[id_start..], ',').?];
        var result_buffer: [64]u8 = undefined;
        const result: []const u8 = if (std.mem.indexOf(u8, body, "eth_getTransactionCount")) |_|
            std.fmt.bufPrint(&result_buffer, "\"0x{x}\"", .{l1.mined_nonce}) catch unreachable
        else if (std.mem.indexOf(u8, body, "eth_getBlockByNumber")) |_|
            "{\"baseFeePerGas\":\"0x64\"}"
        else if (std.mem.indexOf(u8, body, "eth_maxPriorityFeePerGas")) |_|
            "\"0x2\""
        else blk: {
            l1.sends += 1;
            if (l1.reject_with) |message| {
                const text = std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                    "\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}}}", .{ id, message }) catch
                    return error.ResponseTooLarge;
                return text.len;
            }
            break :blk "\"0x00\"";
        };
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{ id, result }) catch
            return error.ResponseTooLarge;
        return text.len;
    }
};

test "txmgr: nonces, confirmation, resubmission with bumped fees" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{};
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 8192,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 2,
        .tx_data_bytes_max = 1024,
        .resubmit_after_ms = 1000,
    });
    defer manager.deinit(testing.allocator);

    try manager.submit(&client, "\x00frame-a", 0);
    try manager.submit(&client, "\x00frame-b", 0);
    try testing.expect(!manager.has_capacity());
    try testing.expectError(error.NoFreeSlot, manager.submit(&client, "\x00c", 0));
    try testing.expectEqual(@as(u64, 5), manager.slots[0].nonce);
    try testing.expectEqual(@as(u64, 6), manager.slots[1].nonce);
    try testing.expectEqual(@as(u32, 2), l1.sends);

    // Nothing mined, not stale yet: no resend.
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 500));
    try testing.expectEqual(@as(u32, 2), l1.sends);
    // First mined; second stale: resent with at least 10% higher fees.
    l1.mined_nonce = 6;
    const fee_before = manager.slots[1].fees.max_fee_per_gas;
    try testing.expectEqual(@as(u32, 1), try manager.poll(&client, 1500));
    try testing.expectEqual(@as(u32, 3), l1.sends);
    try testing.expect(manager.slots[1].fees.max_fee_per_gas * 10 >= fee_before * 11);
    try testing.expectEqual(@as(u32, 2), manager.slots[1].attempts);
    // Benign node errors keep the slot; others surface.
    l1.reject_with = "replacement transaction underpriced";
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 3000));
    l1.reject_with = "insufficient funds";
    try testing.expectError(error.RpcError, manager.poll(&client, 4500));
    l1.reject_with = null;
    l1.mined_nonce = 7;
    try testing.expectEqual(@as(u32, 1), try manager.poll(&client, 5000));
    try testing.expectEqual(@as(u32, 0), manager.pending_count());
}

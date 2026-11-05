//! The shared sender's fee bumping against a canned L1 over SimIo: a transaction without
//! a receipt is re-signed at its nonce with raised fees, and the bumped hash's receipt
//! settles it.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const harness_module = @import("../../consensus/sources/sim_harness.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const sender_module = @import("sender.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Sender = sender_module.Sender(Endpoint);

const target: sender_module.Address = @splat(0x7c);
const calldata = "\x12\x34\x56\x78bump";
const gas_estimate: u64 = 0x40000;
const base_fee: u64 = 9;
const nonce: u64 = 11;

fn step(context: *anyopaque) anyerror!void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    harness.world.run_for_ns(std.time.ns_per_ms);
}

/// The raw transaction and hash the sender signs at `fees` (RFC 6979 is deterministic).
fn signed(
    arena: std.mem.Allocator,
    account: accounts.Account,
    fees: txdata.Fees,
) !struct { raw_hex: []const u8, hash: [32]u8 } {
    const envelope = try txdata.sign_eip1559(.{
        .chain_id = 900,
        .nonce = nonce,
        .fees = fees,
        .gas_limit = gas_estimate + gas_estimate / 100 * 20,
        .to = .{ .bytes = target },
        .value = 5,
        .data = calldata,
    }, account.private_key);
    const raw = try arena.alloc(u8, envelope.encoded_length());
    const encoded = txdata.encode_raw(envelope, raw);
    return .{
        .raw_hex = try std.fmt.allocPrint(arena, "{x}", .{encoded}),
        .hash = envelope.hash().bytes,
    };
}

test "submission sender: a stuck transaction is resubmitted at its nonce with bumped fees" {
    const allocator = testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const account = accounts.derive_dev(5);
    const first = try signed(arena, account, txdata.suggest_fees(base_fee, 2));
    // 2 * 1.15 + 1 and 20 * 1.15 + 1 (integer), above today's suggestion.
    const bumped_fees: txdata.Fees = .{ .max_fee_per_gas = 24, .max_priority_fee_per_gas = 3 };
    const second = try signed(arena, account, bumped_fees);
    const fake = try allocator.create(FakeRpc);
    defer allocator.destroy(fake);
    fake.* = .{};
    fake.add(.{ .method = "eth_estimateGas", .result = "\"0x40000\"" });
    fake.add(.{ .method = "eth_getTransactionCount", .result = "\"0xb\"" });
    fake.add(.{ .method = "eth_maxPriorityFeePerGas", .result = "\"0x2\"" });
    var header_buffer: [600]u8 = undefined;
    const header = rlp.encode_to(&header_buffer, consensus.Header{
        .number = 12,
        .base_fee_per_gas = base_fee,
    });
    fake.add(.{
        .method = "debug_getRawHeader",
        .result = try std.fmt.allocPrint(arena, "\"0x{x}\"", .{header}),
    });
    for ([_]@TypeOf(first){ first, second }) |tx| fake.add(.{
        .method = "eth_sendRawTransaction",
        .params_contain = tx.raw_hex,
        .result = try std.fmt.allocPrint(arena, "\"0x{x}\"", .{&tx.hash}),
    });
    const receipt_second = fake.count;
    fake.add(.{
        .method = "eth_getTransactionReceipt",
        .params_contain = try std.fmt.allocPrint(arena, "{x}", .{&second.hash}),
        .result = "null",
    });
    fake.add(.{ .method = "eth_getTransactionReceipt", .result = "null" });
    var harness: Harness = undefined;
    try harness.init(fake, 0x63);
    defer harness.deinit();
    const address = harness.address;
    const options = harness_module.client_options;
    var client: Endpoint.Client = try .init(allocator, &harness.client_io, address, options, 4096);
    defer client.deinit();
    var l1: Endpoint = .init(allocator, &client, .{ .context = &harness, .step = step }, 100_000);
    defer l1.deinit();
    var sender: Sender = try .init(allocator, &l1, .{
        .chain_id = 900,
        .private_key = account.private_key,
        .from = account.address.bytes,
        .calldata_bytes_max = 64,
        .receipt_polls_max = 10,
        .resubmit_polls = 2,
        .bumps_max = 1,
    });
    defer sender.deinit(allocator);
    const sent = sender.send(.{ .to = target, .value = 5, .calldata = calldata });
    const id = sent.pending;
    // Two polls without a receipt, then the bump goes out at the same nonce.
    try testing.expect(sender.status(id) == .pending);
    try testing.expectEqual(@as(u64, 0), sender.bumps);
    try testing.expect(sender.status(id) == .pending);
    try testing.expectEqual(@as(u64, 1), sender.bumps);
    // No further bumps past `bumps_max`.
    for (0..3) |_| try testing.expect(sender.status(id) == .pending);
    try testing.expectEqual(@as(u64, 1), sender.bumps);
    fake.entries[receipt_second].result = "{\"status\":\"0x1\",\"blockNumber\":\"0xd\"}";
    try testing.expect(sender.status(id) == .mined);
    try testing.expect(sender.has_free_slot());
}

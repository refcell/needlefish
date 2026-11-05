//! `base devnet transfer`: sign and send one EIP-1559 value transfer from a dev
//! account. The smoke test uses it for the L2 transaction and the L1 portal deposit.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../rpc/root.zig");
const txdata = @import("../txdata/root.zig");
const accounts = @import("accounts.zig");
const primitives = @import("../../common/primitives/root.zig");

pub const Params = struct {
    chain_id: u64,
    key_index: u32,
    to: primitives.Address,
    value_wei: u256,
    /// Gas limit; null estimates it (falling back to `gas_fallback`).
    gas_limit: ?u64 = null,
};

/// Gas when estimation fails: covers a call to the portal stub with headroom.
pub const gas_fallback: u64 = 100_000;
const tip_default_wei: u128 = 1_000_000_000;

pub const Error = rpc.Error || rpc.DecodeError || txdata.SignError || error{ChainIdMismatch};

/// Sends the transfer and returns its transaction hash.
pub fn transfer(client: *rpc.Client, params: Params) Error!primitives.B256 {
    const sender = accounts.derive_dev(params.key_index);
    var params_buffer: [256]u8 = undefined;
    const chain_id = try rpc.quantity(u64, try client.call("eth_chainId", "[]"));
    if (chain_id != params.chain_id) return error.ChainIdMismatch;

    const nonce_params = std.fmt.bufPrint(&params_buffer, "[\"0x{x}\",\"pending\"]", .{
        &sender.address.bytes,
    }) catch unreachable; // Fixed-size content.
    const nonce = try rpc.quantity(u64, try client.call("eth_getTransactionCount", nonce_params));

    const head = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
    const base_fee = try rpc.quantity(u128, try rpc.field(head, "baseFeePerGas"));
    const gas_limit = params.gas_limit orelse estimate_gas(client, sender.address, params);
    const envelope = try txdata.sign_eip1559(.{
        .chain_id = params.chain_id,
        .nonce = nonce,
        .fees = txdata.suggest_fees(base_fee, tip_default_wei),
        .gas_limit = gas_limit,
        .to = params.to,
        .value = params.value_wei,
    }, sender.private_key);

    var raw_buffer: [512]u8 = undefined;
    const raw = txdata.encode_raw(envelope, &raw_buffer);
    var send_buffer: [1100]u8 = undefined;
    const send_params = std.fmt.bufPrint(&send_buffer, "[\"0x{x}\"]", .{raw}) catch
        unreachable; // A transfer encodes to well under 512 bytes.
    const hash_value = try client.call("eth_sendRawTransaction", send_params);
    const hash = try rpc.fixed(32, hash_value);
    assert(std.mem.eql(u8, &hash, &envelope.hash().bytes));
    return .{ .bytes = hash };
}

fn estimate_gas(client: *rpc.Client, from: primitives.Address, params: Params) u64 {
    var buffer: [256]u8 = undefined;
    const call_params = std.fmt.bufPrint(
        &buffer,
        "[{{\"from\":\"0x{x}\",\"to\":\"0x{x}\",\"value\":\"0x{x}\"}}]",
        .{ &from.bytes, &params.to.bytes, params.value_wei },
    ) catch unreachable; // Fixed-size content.
    const value = client.call("eth_estimateGas", call_params) catch return gas_fallback;
    const estimate = rpc.quantity(u64, value) catch return gas_fallback;
    // 20% headroom; never below the intrinsic cost of a transfer.
    return @max(21_000, estimate + estimate / 5);
}

const testing = std.testing;

test "transfer: builds, signs, and sends with the node's view" {
    // The expected hash is whatever we sign; the canned node echoes it back, so build
    // the same transaction here to compute it.
    const user = accounts.derive_dev(1);
    const to: primitives.Address = .{ .bytes = @splat(0x22) };
    const expected = try txdata.sign_eip1559(.{
        .chain_id = 901,
        .nonce = 3,
        .fees = txdata.suggest_fees(7, tip_default_wei),
        .gas_limit = 25_200,
        .to = to,
        .value = 1000,
    }, user.private_key);
    var hash_text: [70]u8 = undefined;
    const hash_json = try std.fmt.bufPrint(&hash_text, "\"0x{x}\"", .{&expected.hash().bytes});
    var canned: rpc.CannedTransport = .{ .answers = &.{
        .{ .method = "eth_chainId", .result = "\"0x385\"" },
        .{ .method = "eth_getTransactionCount", .result = "\"0x3\"" },
        .{ .method = "eth_getBlockByNumber", .result = "{\"baseFeePerGas\":\"0x7\"}" },
        .{ .method = "eth_estimateGas", .result = "\"0x5208\"" },
        .{ .method = "eth_sendRawTransaction", .result = hash_json },
    } };
    var client = try rpc.Client.init(testing.allocator, canned.transport(), .{
        .request_bytes_max = 4096,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    const params: Params = .{ .chain_id = 901, .key_index = 1, .to = to, .value_wei = 1000 };
    const hash = try transfer(&client, params);
    try testing.expectEqualSlices(u8, &expected.hash().bytes, &hash.bytes);
    try testing.expectError(
        error.ChainIdMismatch,
        transfer(&client, .{ .chain_id = 900, .key_index = 1, .to = to, .value_wei = 1 }),
    );
}

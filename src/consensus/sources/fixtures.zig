//! Test fixtures: signed L1 transactions from the public dev mnemonic account and JSON-RPC
//! block / receipt bodies written by the execution lane's eth formatter, so decoding is
//! checked against an independent encoder.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const json = @import("../../utilities/json/root.zig");
const format = @import("../../execution/rpc/format.zig");
const ordered = @import("../../execution/trie/ordered.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = consensus.Envelope;
const Header = consensus.Header;

/// Account 0 of the public dev mnemonic `test test ... junk`.
pub const dev_key: [32]u8 =
    parse_key("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
pub const dev_address = Address.comptime_hex("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
pub const inbox = Address.comptime_hex("0xff00000000000000000000000000000000008453");

fn parse_key(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

pub const blob_hashes = [_]B256{ .init(@splat(0x01)), .init(@splat(0x02)) };

/// One transaction of each rebuilt type 0-3, signed by the dev account.
pub fn signed_transactions() [4]Envelope {
    const access_buffer = struct {
        var bytes: [128]u8 = undefined;
        var hashes: [66]u8 = undefined;
    };
    const keys = [_]B256{.init(@splat(0xaa))};
    const access = consensus.AccessList.build(&access_buffer.bytes, &.{
        .{ .address = inbox, .storage_keys = &keys },
    });
    const hashes = consensus.HashList.build(&access_buffer.hashes, &blob_hashes);
    const legacy: consensus.Legacy = .{
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 7,
        .gas_limit = 21000,
        .to = .{ .call = inbox },
        .value = 1,
        .input = "legacy",
    };
    const eip2930: consensus.Eip2930 = .{
        .chain_id = 1,
        .nonce = 1,
        .gas_price = 7,
        .gas_limit = 30000,
        .to = .create,
        .value = 0,
        .input = "create",
        .access_list = access,
    };
    const eip1559: consensus.Eip1559 = .{
        .chain_id = 1,
        .nonce = 2,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 9,
        .gas_limit = 50000,
        .to = .{ .call = inbox },
        .value = 0,
        .input = "frame data",
        .access_list = .empty,
    };
    const eip4844: consensus.Eip4844 = .{
        .chain_id = 1,
        .nonce = 3,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 9,
        .gas_limit = 50000,
        .to = inbox,
        .value = 0,
        .input = "",
        .access_list = .empty,
        .max_fee_per_blob_gas = 3,
        .blob_versioned_hashes = hashes,
    };
    return .{
        consensus.tx.sign(legacy, dev_key) catch unreachable,
        consensus.tx.sign(eip2930, dev_key) catch unreachable,
        consensus.tx.sign(eip1559, dev_key) catch unreachable,
        consensus.tx.sign(eip4844, dev_key) catch unreachable,
    };
}

/// Writes one transaction object as `eth_getTransactionByHash` would.
pub fn write_transaction(writer: *json.Writer, envelope: Envelope) !void {
    var buffer: [1024]u8 = undefined;
    const raw = envelope.encode_to(&buffer);
    try format.transaction(writer, raw, null, consensus.recover_address);
}

/// The header of a block holding `transactions` with a matching transactions root.
pub fn header_for(transactions: []const Envelope, number: u64, parent: B256) Header {
    var bytes: [8192]u8 = undefined;
    var items: [16][]const u8 = undefined;
    assert(transactions.len <= items.len);
    var position: usize = 0;
    for (transactions, 0..) |envelope, index| {
        items[index] = envelope.encode_to(bytes[position..]);
        position += items[index].len;
    }
    return .{
        .parent_hash = parent,
        .number = number,
        .gas_limit = 30_000_000,
        .timestamp = 1_700_000_000 + number * 12,
        .extra_data = "needlefish",
        .base_fee_per_gas = 7,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .init(@splat(0xbe)),
        .transactions_root = .{ .bytes = ordered.ordered_trie_root(items[0..transactions.len]) },
    };
}

/// Writes a block object; `full` writes transaction objects, otherwise hashes.
pub fn write_block(
    writer: *json.Writer,
    header: *const Header,
    transactions: []const Envelope,
    full: bool,
) !void {
    try writer.begin_object();
    try format.header_fields(writer, header, header.hash().bytes, 1000);
    try writer.key("transactions");
    try writer.begin_array();
    for (transactions) |envelope| {
        if (full) {
            try write_transaction(writer, envelope);
        } else {
            try writer.data(&envelope.hash().bytes);
        }
    }
    try writer.end_array();
    try writer.key("uncles");
    try writer.begin_array();
    try writer.end_array();
    try writer.end_object();
}

/// Renders `write_block` into `buffer`.
pub fn block_json(
    buffer: []u8,
    header: *const Header,
    transactions: []const Envelope,
    full: bool,
) ![]const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    var writer = json.Writer.init(&out);
    try write_block(&writer, header, transactions, full);
    return out.buffered();
}

/// Receipts for a block (one per transaction), with the root to put in its header.
pub const ReceiptSet = struct {
    receipts: [4]consensus.Receipt,
    log_buffers: [4][256]u8,
    topic_buffers: [4][66]u8,
    count: u32,

    pub fn init(set: *ReceiptSet, count: u32) void {
        assert(count <= 4);
        set.count = count;
        for (0..count) |index| {
            const topics = [_]B256{ .init(@splat(@intCast(index + 1))), .init(@splat(0x0f)) };
            const log: consensus.Log = .{
                .address = inbox,
                .topics = consensus.HashList.build(&set.topic_buffers[index], &topics),
                .data = "log data",
            };
            const logs = consensus.Logs.build(&set.log_buffers[index], &.{log});
            set.receipts[index] = .{
                .tx_type = if (index == 0) .legacy else .eip1559,
                .status = index != 1,
                .cumulative_gas_used = 21000 * (index + 1),
                .logs_bloom = logs.bloom(),
                .logs = logs,
            };
        }
    }

    pub fn root(set: *const ReceiptSet) B256 {
        var bytes: [4][512]u8 = undefined;
        var items: [4][]const u8 = undefined;
        for (set.receipts[0..set.count], 0..) |receipt, index| {
            items[index] = receipt.encode_to(&bytes[index]);
        }
        return .{ .bytes = ordered.ordered_trie_root(items[0..set.count]) };
    }

    pub fn json_text(set: *const ReceiptSet, buffer: []u8, block_hash: B256) ![]const u8 {
        var out: std.Io.Writer = .fixed(buffer);
        var writer = json.Writer.init(&out);
        try writer.begin_array();
        for (set.receipts[0..set.count], 0..) |receipt, index| {
            try format.receipt(&writer, receipt, .{
                .inclusion = .{
                    .block_hash = block_hash.bytes,
                    .block_number = 1,
                    .index = @intCast(index),
                    .base_fee = 7,
                },
                .tx_hash = @splat(@intCast(index)),
                .from = dev_address,
                .to = inbox,
                .contract_address = null,
                .gas_used = 21000,
                .effective_gas_price = 7,
                .first_log_index = index,
                .blob_gas_used = 0,
                .blob_gas_price = null,
            });
        }
        try writer.end_array();
        return out.buffered();
    }
};

/// Wraps a JSON-RPC `result` in a response envelope.
pub fn rpc_response(buffer: []u8, id: u64, result: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"result\":{s}}}", .{
        id, result,
    });
}

//! Builds an `L2BlockInfo` from an L2 `eth_getBlockByNumber(n, true)` result: the header
//! (hash-verified like L1 headers) plus the L1 origin and sequence number decoded from the
//! L1 info deposit, which must be the block's first transaction. The genesis block has no
//! deposit and takes its origin from the rollup genesis.
//! Mirrors base/base `L2BlockInfo::from_block_and_genesis`.

const std = @import("std");
const assert = std.debug.assert;

const object = @import("json_object.zig");
const header_json = @import("header_json.zig");
const protocol = @import("../protocol/root.zig");

const L2BlockInfo = protocol.block.L2BlockInfo;
const ChainGenesis = protocol.rollup_config.ChainGenesis;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;

pub const deposit_tx_type: u8 = 0x7e;

pub const Error = header_json.DecodeError || error{
    /// Block number equals the genesis number but the hash differs.
    GenesisMismatch,
    /// The first transaction is not an L1 info deposit.
    MissingL1InfoDeposit,
    InvalidL1Info,
};

pub fn decode(raw: []const u8, genesis: *const ChainGenesis) Error!L2BlockInfo {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(raw, &extra);
    const block_info = decoded.block_info();
    if (block_info.number == genesis.l2.number) {
        if (!block_info.hash.eql(genesis.l2.hash)) return error.GenesisMismatch;
        return .{ .block_info = block_info, .l1_origin = genesis.l1, .sequence_number = 0 };
    }
    const transactions = (try header_json.transactions_raw(raw)) orelse
        return error.MissingField;
    var iterator = try object.ArrayIterator.init(transactions);
    const first = (try iterator.next()) orelse return error.MissingL1InfoDeposit;
    if (first.value.tag != .object_begin) return error.InvalidJson; // Hashes, not objects.
    var input_buffer: [protocol.l1_info.calldata_length_max]u8 = undefined;
    const input = try deposit_input(first.raw, &input_buffer);
    const info = L1BlockInfo.decode_calldata(input) catch return error.InvalidL1Info;
    assert(info.number == info.id().number);
    return .{
        .block_info = block_info,
        .l1_origin = info.id(),
        .sequence_number = info.sequence_number,
    };
}

/// The `input` of a deposit transaction object, decoded into a bounded buffer.
fn deposit_input(
    raw: []const u8,
    buffer: *[protocol.l1_info.calldata_length_max]u8,
) Error![]const u8 {
    var iterator = try object.ObjectIterator.init(raw);
    var tx_type: ?u8 = null;
    var input: ?[]const u8 = null;
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "type")) {
            tx_type = try object.quantity(u8, field.value);
        } else if (std.mem.eql(u8, field.key, "input")) {
            const size = try object.data_size(field.value);
            if (size > buffer.len) return error.InvalidL1Info;
            try object.data_into(field.value, buffer[0..size]);
            input = buffer[0..size];
        }
    }
    if (tx_type != deposit_tx_type) return error.MissingL1InfoDeposit;
    return input orelse error.MissingField;
}

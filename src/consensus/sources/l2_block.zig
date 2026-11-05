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
const B256 = @import("../../common/primitives/root.zig").B256;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.system_config.SystemConfig;
const l2_system_config = @import("../protocol/l2_system_config.zig");
const ChainGenesis = protocol.rollup_config.ChainGenesis;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;

pub const deposit_tx_type: u8 = 0x7e;

pub const Error = header_json.DecodeError || error{
    /// Block number equals the genesis number but the hash differs.
    GenesisMismatch,
    /// The first transaction is not an L1 info deposit.
    MissingL1InfoDeposit,
    InvalidL1Info,
} || l2_system_config.Error;

/// An L2 block's position in the chain and the system config it was built under.
pub const L2Block = struct {
    info: L2BlockInfo,
    system_config: SystemConfig,
    state_root: B256 = .zero,
    /// From Isthmus on: the L2ToL1MessagePasser storage root (the output root's
    /// `messagePasserStorageRoot`).
    withdrawals_root: ?B256 = null,
};

/// Decodes `L2BlockInfo` plus the block's system config (base/base `to_system_config`).
pub fn decode_with_system_config(raw: []const u8, rollup: *const RollupConfig) Error!L2Block {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(raw, &extra);
    const fields: l2_system_config.BlockFields = .{
        .number = decoded.header.number,
        .hash = decoded.hash,
        .timestamp = decoded.header.timestamp,
        .gas_limit = decoded.header.gas_limit,
        .extra_data = decoded.header.extra_data,
    };
    if (try l2_system_config.genesis_system_config(rollup, fields)) |config| {
        const info = try decode(raw, &rollup.genesis);
        assert(info.sequence_number == 0);
        return .{
            .info = info,
            .system_config = config,
            .state_root = decoded.header.state_root,
            .withdrawals_root = decoded.header.withdrawals_root,
        };
    }
    var input_buffer: [protocol.l1_info.calldata_length_max]u8 = undefined;
    const input = try first_deposit_input(raw, &input_buffer);
    const l1_block = L1BlockInfo.decode_calldata(input) catch return error.InvalidL1Info;
    const config = try l2_system_config.from_l1_info(rollup, &l1_block, fields);
    const info: L2BlockInfo = .{
        .block_info = decoded.block_info(),
        .l1_origin = l1_block.id(),
        .sequence_number = l1_block.sequence_number,
    };
    assert(info.block_info.hash.eql(decoded.hash));
    return .{
        .info = info,
        .system_config = config,
        .state_root = decoded.header.state_root,
        .withdrawals_root = decoded.header.withdrawals_root,
    };
}

fn first_deposit_input(
    raw: []const u8,
    buffer: *[protocol.l1_info.calldata_length_max]u8,
) Error![]const u8 {
    const transactions = (try header_json.transactions_raw(raw)) orelse
        return error.MissingField;
    var iterator = try object.ArrayIterator.init(transactions);
    const first = (try iterator.next()) orelse return error.MissingL1InfoDeposit;
    if (first.value.tag != .object_begin) return error.InvalidJson; // Hashes, not objects.
    const input = try deposit_input(first.raw, buffer);
    assert(input.len <= buffer.len);
    return input;
}

pub fn decode(raw: []const u8, genesis: *const ChainGenesis) Error!L2BlockInfo {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(raw, &extra);
    const block_info = decoded.block_info();
    if (block_info.number == genesis.l2.number) {
        if (!block_info.hash.eql(genesis.l2.hash)) return error.GenesisMismatch;
        return .{ .block_info = block_info, .l1_origin = genesis.l1, .sequence_number = 0 };
    }
    var input_buffer: [protocol.l1_info.calldata_length_max]u8 = undefined;
    const input = try first_deposit_input(raw, &input_buffer);
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

//! Derivation check, comparison half: puts payload attributes derived from L1 next to the
//! canonical L2 block a reference node serves at the same height, and runs exactly the
//! checks a verifier's consolidation runs (`engine/attributes_match.zig`).
//!
//! The cheap path needs only the block header (`eth_getBlockByNumber(n, false)`): when the
//! derived transactions hash to the header's `transactionsRoot`, the derived list *is* the
//! block's list (the root binds every byte), so it stands in for the block's transactions
//! and every other field is compared from the header. When the roots differ the caller
//! fetches the full block and compares transaction by transaction, which pinpoints the
//! index and both encodings. Mirrors base/base `crates/consensus/engine/src/attributes.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const ordered = @import("../../execution/trie/ordered.zig");
const protocol = @import("../protocol/root.zig");
const object = @import("../sources/json_object.zig");
const header_json = @import("../sources/header_json.zig");
const engine_json = @import("../sources/engine_json.zig");
const l2_system_config = @import("../protocol/l2_system_config.zig");
const attributes_match = @import("../engine/attributes_match.zig");
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const B256 = primitives.B256;
const L1BlockInfo = protocol.l1_info.L1BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.system_config.SystemConfig;

pub const L2Block = attributes_match.L2Block;
pub const Mismatch = attributes_match.Mismatch;
pub const FeeParams = attributes_match.FeeParams;

pub const Error = header_json.DecodeError || l2_system_config.Error || error{
    /// The served block is not the child of the attributes' parent.
    NumberMismatch,
    MissingL1InfoDeposit,
    InvalidL1Info,
};

/// Encodings longer than this are shown truncated in reports.
pub const report_bytes_max = 4096;
/// Differing indices listed for a transaction count mismatch.
pub const report_transactions_max = 8;

/// A reference block seen through its header, ready for `attributes_match.check`.
pub const HeaderView = struct {
    /// `transactions` are the derived ones when `transactions_root_match`, else empty.
    block: L2Block,
    transactions_root_match: bool,
};

/// The ordered trie root of EIP-2718 encoded transactions (the header's
/// `transactionsRoot`).
pub fn transactions_root(transactions: []const []const u8) B256 {
    const root: B256 = .{ .bytes = ordered.ordered_trie_root(transactions) };
    assert(transactions.len > 0 or root.eql(primitives.empty_root_hash));
    return root;
}

/// The L1 info deposit of a transaction list (its first transaction).
pub fn l1_info_of(transactions: []const []const u8) Error!L1BlockInfo {
    if (transactions.len == 0) return error.MissingL1InfoDeposit;
    const first = consensus.Envelope.decode(transactions[0]) catch return error.InvalidL1Info;
    if (!first.is_deposit()) return error.MissingL1InfoDeposit;
    const info = L1BlockInfo.decode_calldata(first.input()) catch return error.InvalidL1Info;
    assert(info.id().number == info.number);
    return info;
}

/// Decodes a header-only block object (hash-verified) served for the child of
/// `attributes.parent`. Slices of the result live in `arena`.
pub fn decode_header(
    arena: Allocator,
    raw: []const u8,
    attributes: *const AttributesWithParent,
) Error!HeaderView {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = try header_json.decode(raw, &extra);
    const header = &decoded.header;
    if (header.number != attributes.parent.block_info.number + 1) return error.NumberMismatch;
    const derived: []const []const u8 = attributes.attributes.transactions;
    const root_match = transactions_root(derived).eql(header.transactions_root);
    var info: protocol.block.L2BlockInfo = .{ .block_info = decoded.block_info() };
    if (root_match) {
        const l1_info = try l1_info_of(derived);
        info.l1_origin = l1_info.id();
        info.sequence_number = l1_info.sequence_number;
    }
    const withdrawals = if (try withdrawals_raw(raw)) |list|
        try engine_json.decode_withdrawals(arena, list, .{})
    else
        null;
    const view: HeaderView = .{
        .block = .{
            .info = info,
            .prev_randao = header.mix_hash,
            .gas_limit = header.gas_limit,
            .fee_recipient = header.beneficiary,
            .extra_data = try arena.dupe(u8, header.extra_data),
            .withdrawals_root = header.withdrawals_root,
            .parent_beacon_block_root = header.parent_beacon_block_root,
            .withdrawals = withdrawals,
            .transactions = if (root_match) derived else &.{},
        },
        .transactions_root_match = root_match,
    };
    assert(view.block.info.block_info.hash.eql(decoded.hash));
    return view;
}

/// The raw `withdrawals` array of a block object, if present.
fn withdrawals_raw(raw: []const u8) Error!?[]const u8 {
    var iterator = try object.ObjectIterator.init(raw);
    var fields: u32 = 0;
    while (try iterator.next()) |field| : (fields += 1) {
        assert(fields <= raw.len);
        if (!std.mem.eql(u8, field.key, "withdrawals")) continue;
        if (field.value.tag == .null) return null;
        if (field.value.tag != .array_begin) return error.InvalidJson;
        return field.raw;
    }
    return null;
}

/// Consolidation's verdict: null when `block` is what `attributes` describe.
pub fn check(
    rollup: *const RollupConfig,
    fee_params_canyon: FeeParams,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) ?Mismatch {
    assert(block.transactions.len > 0);
    return attributes_match.check(rollup, fee_params_canyon, attributes, block);
}

/// The system config a block was built under (base/base `to_system_config`), from its L1
/// info deposit and header. `block` must not be the genesis block.
pub fn system_config_of(rollup: *const RollupConfig, block: *const L2Block) Error!SystemConfig {
    const info = try l1_info_of(block.transactions);
    const header = block.info.block_info;
    assert(header.number != rollup.genesis.l2.number);
    return l2_system_config.from_l1_info(rollup, &info, .{
        .number = header.number,
        .hash = header.hash,
        .timestamp = header.timestamp,
        .gas_limit = block.gas_limit,
        .extra_data = block.extra_data,
    });
}

/// Writes a precise mismatch report: the block, the field, and both values; for
/// transactions the index and both encodings.
pub fn write_report(
    writer: *std.Io.Writer,
    mismatch: Mismatch,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) std.Io.Writer.Error!void {
    const header = block.info.block_info;
    try writer.print("MISMATCH l2 block {d} {f}: field {t}\n", .{
        header.number,
        header.hash,
        mismatch,
    });
    switch (mismatch) {
        .parent_hash, .prev_randao => |pair| try write_pair(writer, "{f}", pair),
        .timestamp, .gas_limit, .min_base_fee => |pair| try write_pair(writer, "{d}", pair),
        .transaction_len => |pair| {
            try write_pair(writer, "{d} transactions", pair);
            try write_transactions_diff(writer, attributes, block);
        },
        .transaction_content => |content| {
            try write_transaction(writer, attributes, block, content.index);
        },
        .malformed_attributes_transaction => |index| {
            try write_transaction(writer, attributes, block, index);
        },
        .eip1559_parameters => |params| {
            try writer.print("  derived:   denominator {d} elasticity {d}\n", .{
                params.attributes.denominator,
                params.attributes.elasticity,
            });
            try writer.print("  reference: denominator {d} elasticity {d}\n", .{
                params.block.denominator,
                params.block.elasticity,
            });
        },
        .fee_recipient => |pair| try write_pair(writer, "{f}", pair),
        .parent_beacon_block_root => |pair| {
            try writer.print("  derived:   {?f}\n  reference: {?f}\n", .{ pair[0], pair[1] });
        },
        else => try write_header_context(writer, attributes, block),
    }
}

fn write_pair(writer: *std.Io.Writer, comptime format: []const u8, pair: anytype) !void {
    try writer.print("  derived:   " ++ format ++ "\n", .{pair[0]});
    try writer.print("  reference: " ++ format ++ "\n", .{pair[1]});
}

/// Extra data and withdrawals, for the EIP-1559 and withdrawals mismatches.
fn write_header_context(
    writer: *std.Io.Writer,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) !void {
    const payload = &attributes.attributes;
    try writer.print("  derived:   eip1559_params {?x} min_base_fee {?d} withdrawals {?d}\n", .{
        payload.eip1559_params,
        payload.min_base_fee,
        if (payload.withdrawals) |list| list.len else null,
    });
    try writer.print("  reference: extra_data 0x{x} withdrawals {?d} withdrawals_root {?f}\n", .{
        block.extra_data,
        if (block.withdrawals) |list| list.len else null,
        block.withdrawals_root,
    });
}

fn write_transaction(
    writer: *std.Io.Writer,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
    index: u32,
) !void {
    const derived: []const []const u8 = attributes.attributes.transactions;
    try writer.print("  transaction index {d}\n", .{index});
    try write_encoding(writer, "derived:  ", if (index < derived.len) derived[index] else null);
    const reference = if (index < block.transactions.len) block.transactions[index] else null;
    try write_encoding(writer, "reference:", reference);
}

fn write_encoding(writer: *std.Io.Writer, label: []const u8, encoded: ?[]const u8) !void {
    const bytes = encoded orelse return writer.print("    {s} absent\n", .{label});
    const shown = bytes[0..@min(bytes.len, report_bytes_max)];
    const more = if (shown.len < bytes.len) "..." else "";
    try writer.print("    {s} {d} bytes hash {f} 0x{x}{s}\n", .{
        label,
        bytes.len,
        primitives.keccak256(bytes),
        shown,
        more,
    });
}

/// Every index (up to `report_transactions_max`) where the two lists differ.
fn write_transactions_diff(
    writer: *std.Io.Writer,
    attributes: *const AttributesWithParent,
    block: *const L2Block,
) !void {
    const derived: []const []const u8 = attributes.attributes.transactions;
    const count = @max(derived.len, block.transactions.len);
    var shown: u32 = 0;
    for (0..count) |index| {
        if (shown == report_transactions_max) break;
        const same = index < derived.len and index < block.transactions.len and
            std.mem.eql(u8, derived[index], block.transactions[index]);
        if (same) continue;
        try write_transaction(writer, attributes, block, @intCast(index));
        shown += 1;
    }
    assert(shown <= report_transactions_max);
}

test {
    _ = @import("compare_test.zig");
}

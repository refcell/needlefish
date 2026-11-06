//! OP receipt fields (base/base `ReceiptFieldsBuilder`): the L1 data fee inputs of each
//! transaction, derived from the block's L1 info deposit (transaction 0), so historical
//! receipts need no historical state.
//!
//! Every transaction (deposits too) reports `l1GasPrice`, `l1GasUsed` (L1 data gas plus the
//! pre-Ecotone overhead), `l1Fee` (zero for deposits), and the scalars; the operator fee
//! fields only when one of them is non-zero; Jovian adds `daFootprintGasScalar` and
//! replaces `blobGasUsed` with the transaction's DA footprint. Pre-Ecotone `l1FeeScalar`
//! (a decimal string in base/base) is not reported.

const std = @import("std");
const assert = std.debug.assert;

const consensus = @import("../../common/consensus/root.zig");
const l1_fees = @import("../../common/l1_fees/root.zig");
const l1_info = @import("../../consensus/protocol/l1_info.zig");
const chainspec = @import("../chainspec/root.zig");
const executor_op = @import("../node/executor_op.zig");
const json = @import("../../utilities/json/root.zig");

pub const Fields = struct {
    l1_gas_price: u256,
    l1_gas_used: u256,
    l1_fee: u256,
    l1_base_fee_scalar: u256,
    l1_blob_base_fee: ?u256,
    l1_blob_base_fee_scalar: ?u256,
    operator_fee_scalar: ?u256,
    operator_fee_constant: ?u256,
    da_footprint_gas_scalar: ?u16,
    /// Jovian: the DA footprint, reported as the receipt's `blobGasUsed`.
    da_footprint: ?u64,
};

/// The L1 fee parameters the L1 info deposit `first` (a block's transaction 0) installs,
/// under `rules`; null when `first` is not an L1 info deposit.
pub fn params_of(first: []const u8, rules: l1_fees.Rules) ?l1_fees.L1FeeParams {
    const envelope = consensus.Envelope.decode(first) catch return null;
    if (envelope != .deposit) return null;
    const info = l1_info.L1BlockInfo.decode_calldata(envelope.deposit.input) catch return null;
    var params: l1_fees.L1FeeParams = .{ .l1_base_fee = info.base_fee };
    if (info.format == .bedrock) {
        params.l1_fee_overhead = info.l1_fee_overhead;
        params.l1_base_fee_scalar = info.l1_fee_scalar;
        // The first Ecotone block still carries the Bedrock calldata and prices with it.
        if (rules.at_least(.ecotone)) {
            params.l1_blob_base_fee = 0;
            params.l1_blob_base_fee_scalar = 0;
            params.empty_ecotone_scalars = true;
        }
        return params;
    }
    params.l1_base_fee_scalar = info.base_fee_scalar;
    params.l1_blob_base_fee = info.blob_base_fee;
    params.l1_blob_base_fee_scalar = info.blob_base_fee_scalar;
    if (info.format == .isthmus or info.format == .jovian) {
        params.operator_fee_scalar = info.operator_fee_scalar;
        params.operator_fee_constant = info.operator_fee_constant;
    }
    if (info.format == .jovian) params.da_footprint_gas_scalar = info.da_footprint_gas_scalar;
    assert(params.l1_fee_overhead == null);
    return params;
}

/// The OP fields of transaction `raw` in a block at `timestamp` whose transaction 0 is
/// `first`; null in L1 mode or without an L1 info deposit.
pub fn fields(
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
    first: []const u8,
    raw: []const u8,
) ?Fields {
    assert(raw.len > 0);
    const context = executor_op.context(spec, timestamp) orelse return null;
    const rules = context.rules();
    const params = params_of(first, rules) orelse return null;
    const operator_set = (params.operator_fee_scalar orelse 0) != 0 or
        (params.operator_fee_constant orelse 0) != 0;
    const jovian = rules.at_least(.jovian);
    const data_gas = l1_fees.L1FeeParams.data_gas(raw, rules);
    const result: Fields = .{
        .l1_gas_price = params.l1_base_fee,
        .l1_gas_used = data_gas +| (params.l1_fee_overhead orelse 0),
        .l1_fee = params.tx_l1_cost(raw, rules),
        .l1_base_fee_scalar = params.l1_base_fee_scalar,
        .l1_blob_base_fee = params.l1_blob_base_fee,
        .l1_blob_base_fee_scalar = params.l1_blob_base_fee_scalar,
        .operator_fee_scalar = if (operator_set) params.operator_fee_scalar else null,
        .operator_fee_constant = if (operator_set) params.operator_fee_constant else null,
        .da_footprint_gas_scalar = if (params.da_footprint_gas_scalar) |scalar|
            @intCast(scalar)
        else
            null,
        .da_footprint = if (jovian) params.jovian_da_footprint(raw) else null,
    };
    assert(raw[0] != 0x7e or result.l1_fee == 0);
    return result;
}

/// Writes the fields (not `blobGasUsed`, which the receipt writes) into an open object.
pub fn write(w: *json.Writer, value: Fields) json.Writer.WriteError!void {
    assert(value.l1_blob_base_fee == null or value.l1_blob_base_fee_scalar != null);
    try w.key("l1GasPrice");
    try w.quantity(value.l1_gas_price);
    try w.key("l1GasUsed");
    try w.quantity(value.l1_gas_used);
    try w.key("l1Fee");
    try w.quantity(value.l1_fee);
    try w.key("l1BaseFeeScalar");
    try w.quantity(value.l1_base_fee_scalar);
    const optional = [_]struct { []const u8, ?u256 }{
        .{ "l1BlobBaseFee", value.l1_blob_base_fee },
        .{ "l1BlobBaseFeeScalar", value.l1_blob_base_fee_scalar },
        .{ "operatorFeeScalar", value.operator_fee_scalar },
        .{ "operatorFeeConstant", value.operator_fee_constant },
    };
    for (optional) |entry| if (entry[1]) |quantity| {
        try w.key(entry[0]);
        try w.quantity(quantity);
    };
    if (value.da_footprint_gas_scalar) |scalar| {
        try w.key("daFootprintGasScalar");
        try w.quantity(scalar);
    }
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

fn hex_concat(comptime parts: []const []const u8) [hex_length(parts) / 2]u8 {
    @setEvalBranchQuota(100_000);
    comptime var text: []const u8 = "";
    inline for (parts) |part| text = text ++ part;
    return primitives.hex.decode_array(text.len / 2, text) catch unreachable;
}

fn hex_length(comptime parts: []const []const u8) usize {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    return total;
}

// Base mainnet block 53715983 (Denim): its L1 info deposit (index 0) and an EIP-1559
// transaction (index 5), re-encoded from `eth_getBlockByNumber`.
const mainnet_first = hex_concat(&.{
    "7ef90106a03b76b0f097f7ca3504ac246b4b5b61e7fcc4275b9680e275d40c14073a2e9ef594deaddeaddead",
    "deaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f424080b8b2",
    "3db6be2b000008dd00101c12000000000000000b000000006aed40570000000001921d1e0000000000000000",
    "000000000000000000000000000000000000000002df75c50000000000000000000000000000000000000000",
    "0000000000000000002abf94d6dfa32df1f48230bf75fa629f1b99b882d484e2dca4618f37fdec41cf9d5b98",
    "0000000000000000000000005050f69a9786f081509234f1a7f4684b5e5b76c9000000000000000000000000",
    "0094",
});

const mainnet_eip1559 = hex_concat(&.{
    "02f90315822105831b27af832dc6c08402fbb3d0834c4b40944b5c71082d027d16d2a146465d66f9eec11634",
    "f680b902a4ca350aa60000000000000000000000000000000000000000000000000000000000000040000000",
    "000000000000000000000000000000000000000000000000000003d090000000000000000000000000000000",
    "0000000000000000000000000000000006000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b",
    "54bda029130000000000000000000000009ee2dffba5abccc43fa3443b6b2ca5bcecb0552d00000000000000",
    "000000000000000000000000000000000000000000000002d1000000000000000000000000833589fcd6edb6",
    "e08f4c7c32d4f71b54bda02913000000000000000000000000a69fa38a6b50570f41ba52da5c88f385ad52cf",
    "db00000000000000000000000000000000000000000000000000000000000016a70000000000000000000000",
    "00833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000c65777ca8c61f7a462c335",
    "a04bd96e62c2eec3c40000000000000000000000000000000000000000000000000000000002faf080000000",
    "000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000009c8074",
    "3be6a97dcfd84a2b42fc3cf551a0907d67000000000000000000000000000000000000000000000000000000",
    "00002991d2000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda0291300000000000000",
    "00000000009c2c87c46b08f9f9ee0a0f0c98b221f30ed4d48000000000000000000000000000000000000000",
    "00000000000000000000003adc000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029",
    "13000000000000000000000000a76a5a0fe1dbb5341018bbc86ad81931c04b32390000000000000000000000",
    "0000000000000000000000000000000000000002d1c001a0867aaf61b33bb4e78b439d53edf0542e0d48ad18",
    "814e6c4ecd72d5ace177818ea0047ada9b041025920bb7fb6a3a79592b5a4465682657bdfe0aa0925ad9c35c",
    "1b",
});

const mainnet_timestamp: u64 = 1793933572;
const mainnet_first_hash = "fdd3b7849cb8b8655e2ee9d6145442e3e54df51b7befeae1fb891bd64bc420ab";
const mainnet_eip1559_hash = "34577b1c1f8e5e3fa76d892456f913b30dfbd365625e908c76bef8c73d888f66";

fn expect_hash(raw: []const u8, comptime expected: []const u8) !void {
    const want = try primitives.hex.decode_array(32, expected);
    try testing.expectEqualSlices(u8, &want, &primitives.keccak256(raw).bytes);
}

test "op receipt: Base mainnet block 53715983 fields match the canonical receipts" {
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    try expect_hash(&mainnet_first, mainnet_first_hash);
    try expect_hash(&mainnet_eip1559, mainnet_eip1559_hash);
    // Receipt 0 (the deposit): `eth_getTransactionReceipt` on Base mainnet.
    const deposit = fields(spec, mainnet_timestamp, &mainnet_first, &mainnet_first).?;
    try testing.expectEqual(@as(u256, 0x2df75c5), deposit.l1_gas_price);
    try testing.expectEqual(@as(u256, 0x702), deposit.l1_gas_used);
    try testing.expectEqual(@as(u256, 0), deposit.l1_fee);
    try testing.expectEqual(@as(u256, 0x8dd), deposit.l1_base_fee_scalar);
    try testing.expectEqual(@as(?u256, 0x2abf94), deposit.l1_blob_base_fee);
    try testing.expectEqual(@as(?u256, 0x101c12), deposit.l1_blob_base_fee_scalar);
    try testing.expectEqual(@as(?u16, 0x94), deposit.da_footprint_gas_scalar);
    try testing.expectEqual(@as(?u64, 0x40c0), deposit.da_footprint);
    try testing.expectEqual(@as(?u256, null), deposit.operator_fee_scalar);
    // Receipt 5.
    const user = fields(spec, mainnet_timestamp, &mainnet_first, &mainnet_eip1559).?;
    try testing.expectEqual(@as(u256, 0x120a), user.l1_gas_used);
    try testing.expectEqual(@as(u256, 0x50ffb1a9), user.l1_fee);
    try testing.expectEqual(@as(?u64, 0xa680), user.da_footprint);
    // L1 mode, and a block without an L1 info deposit, have no OP fields.
    const l1 = &chainspec.ChainSpec.presets.l1_dev;
    try testing.expect(fields(l1, mainnet_timestamp, &mainnet_first, &mainnet_eip1559) == null);
    try testing.expect(fields(spec, mainnet_timestamp, &mainnet_eip1559, &mainnet_eip1559) == null);
}

/// Mutated L1 info deposits never crash, and a decoded block's fields are self-consistent.
fn mutate_first(seed: u64) !void {
    var prng = Prng.init(seed);
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    var first = mainnet_first;
    const flips = prng.range(0, 4);
    for (0..flips) |_| first[prng.below(first.len)] ^= @intCast(prng.range(1, 255));
    const timestamp = prng.range(1_686_789_347, mainnet_timestamp + 1000);
    const result = fields(spec, timestamp, &first, &mainnet_eip1559) orelse return;
    try testing.expect(result.l1_gas_used > 0);
    try testing.expect((result.operator_fee_scalar == null) ==
        (result.operator_fee_constant == null));
}

test "op receipt: seeded fuzz of mutated L1 info deposits" {
    for (0..512) |seed| try mutate_first(seed);
}

fn fuzz_first(_: void, smith: *testing.Smith) anyerror!void {
    try mutate_first(smith.value(u64));
}

test "op receipt: fuzz L1 info deposits" {
    try testing.fuzz({}, fuzz_first, .{});
}

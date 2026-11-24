//! The fee fields of an RPC call request and reth's rules for them: alloy-evm 0.39
//! `rpc/fees.rs` `CallFees::ensure_fees` (as `TryIntoTxEnv` applies it, saturating the
//! prices to u128) with the error codes of base/reth 2b20e42
//! `crates/rpc/rpc-eth-types/src/error/mod.rs` `From<EthTxEnvError>`. A call that names a
//! price is checked against the block's base fee and capped at what the caller can afford
//! (`caller_gas_allowance`); one without runs unpriced.

const std = @import("std");
const assert = std.debug.assert;
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const call_error = @import("call_error.zig");

const HandlerError = rpc.HandlerError;

/// The request's fee fields, as given (null: absent or JSON null).
pub const Fees = struct {
    gas_price: ?u256 = null,
    max_fee: ?u256 = null,
    max_priority_fee: ?u256 = null,
    max_fee_per_blob_gas: ?u256 = null,
    /// The length of `blobVersionedHashes` when given.
    blob_hashes: ?u32 = null,
};

/// The prices a call runs with (`CallFees`).
pub const Prices = struct {
    /// Legacy price, or the EIP-1559 effective price; zero for an unpriced call.
    gas_price: u256,
    priority_fee: ?u256,
};

pub const Result = union(enum) {
    prices: Prices,
    failure: call_error.Failure,
};

/// Reads the fee fields of a call object (other fields are left to `eth.parse_call`).
pub fn parse(raw: []const u8) HandlerError!Fees {
    var fees: Fees = .{};
    var scanner = json.Scanner.init(raw);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag != .object_begin) return error.InvalidParams;
    var members: u32 = 0;
    while (members < 1024) : (members += 1) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) return fees;
        const value = scanner.next() catch return error.InvalidParams;
        const field: ?*?u256 = if (std.mem.eql(u8, name.bytes, "gasPrice"))
            &fees.gas_price
        else if (std.mem.eql(u8, name.bytes, "maxFeePerGas"))
            &fees.max_fee
        else if (std.mem.eql(u8, name.bytes, "maxPriorityFeePerGas"))
            &fees.max_priority_fee
        else if (std.mem.eql(u8, name.bytes, "maxFeePerBlobGas"))
            &fees.max_fee_per_blob_gas
        else
            null;
        if (field) |target| {
            if (value.tag != .null) {
                if (value.tag != .string) return error.InvalidParams;
                target.* = json.parse_quantity(u256, value.bytes) catch
                    return error.InvalidParams;
            }
        } else if (std.mem.eql(u8, name.bytes, "blobVersionedHashes") and value.tag != .null) {
            fees.blob_hashes = try count_blob_hashes(&scanner, value);
        } else {
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
    return error.InvalidParams;
}

/// Counts the `B256` hashes (the EVM checks their version).
fn count_blob_hashes(scanner: *json.Scanner, first: json.Token) HandlerError!u32 {
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (count < 4096) : (count += 1) {
        const token = scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) return count;
        if (token.tag != .string) return error.InvalidParams;
        _ = json.parse_hash(token.bytes) catch return error.InvalidParams;
    }
    return error.InvalidParams;
}

/// The tip of a request that names one but no fee cap (nor a gas price). geth's
/// `CallDefaults` (internal/ethapi/transaction_args.go) leaves the missing cap at zero once
/// the block has a base fee, so `preCheck` fails with `ErrTipAboveFeeCap`; Nethermind does
/// the same (`TransactionExtensions.cs:72`). reth instead prices it at base fee plus tip.
pub fn tip_without_cap(fees: Fees) ?u256 {
    if (fees.max_fee != null or fees.gas_price != null) return null;
    const tip = fees.max_priority_fee orelse return null;
    return if (tip == 0) null else tip;
}

/// `CallFees::ensure_fees` against `base_fee` (the block's, after block overrides).
pub fn ensure(fees: Fees, base_fee: u64) Result {
    if (fees.blob_hashes) |count| if (count == 0) return missing_blob_hashes;
    const eip1559 = fees.max_fee != null or fees.max_priority_fee != null;
    if (fees.max_fee_per_blob_gas == null and !eip1559) {
        // Legacy, or no fee field: unpriced.
        const price = saturate(fees.gas_price orelse 0);
        return .{ .prices = .{ .gas_price = price, .priority_fee = null } };
    }
    if (fees.gas_price != null) return .{ .failure = .{
        .code = rpc.code.invalid_params,
        .message = "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified",
    } };
    const price = effective_price(fees.max_fee, fees.max_priority_fee, base_fee);
    if (price == .failure) return price;
    if (fees.max_fee_per_blob_gas != null and (fees.blob_hashes orelse 0) == 0) {
        return missing_blob_hashes;
    }
    var prices = price.prices;
    prices.priority_fee = if (fees.max_priority_fee) |priority| saturate(priority) else null;
    assert(prices.priority_fee == null or prices.priority_fee.? <= std.math.maxInt(u128));
    return .{ .prices = prices };
}

const missing_blob_hashes: Result = .{ .failure = .{
    .code = call_error.code_transaction_rejected,
    .message = "blob transaction missing blob hashes",
} };

/// `get_effective_gas_price`: `min(maxFee, baseFee + tip)`, the fee cap enforced unless
/// both fields are zero.
fn effective_price(max_fee: ?u256, max_priority_fee: ?u256, base_fee: u64) Result {
    const priority = max_priority_fee orelse 0;
    const sum = @addWithOverflow(@as(u256, base_fee), priority);
    const fee_cap = max_fee orelse {
        if (sum[1] != 0) return tip_very_high;
        return .{ .prices = .{ .gas_price = saturate(sum[0]), .priority_fee = null } };
    };
    if (!(fee_cap == 0 and priority == 0) and fee_cap < base_fee) return .{ .failure = .{
        .code = call_error.code_invalid_input,
        .message = "max fee per gas less than block base fee",
    } };
    if (fee_cap < priority) return .{ .failure = .{
        .code = call_error.code_transaction_rejected,
        .message = "max priority fee per gas higher than max fee per gas",
    } };
    if (sum[1] != 0) return tip_very_high;
    return .{ .prices = .{ .gas_price = saturate(@min(fee_cap, sum[0])), .priority_fee = null } };
}

const tip_very_high: Result = .{ .failure = .{
    .code = call_error.code_transaction_rejected,
    .message = "max priority fee per gas higher than 2^256-1",
} };

/// alloy's `saturating_to::<u128>()` of a request price.
fn saturate(value: u256) u256 {
    return @min(value, std.math.maxInt(u128));
}

/// reth `caller_gas_allowance`: the gas `balance - value` buys at `gas_price` (saturated to
/// u64); null when the balance does not cover `value` (insufficient funds).
pub fn allowance(balance: u256, value: u256, gas_price: u256) ?u64 {
    assert(gas_price > 0);
    if (value > balance) return null;
    const affordable = (balance - value) / gas_price;
    return @intCast(@min(affordable, std.math.maxInt(u64)));
}

test "call_fees: ensure_fees rules" {
    const t = std.testing;
    const unpriced = ensure(.{}, 100).prices;
    try t.expectEqual(@as(u256, 0), unpriced.gas_price);
    try t.expectEqual(@as(?u256, null), unpriced.priority_fee);
    const legacy = ensure(.{ .gas_price = 7 }, 100).prices;
    try t.expectEqual(@as(u256, 7), legacy.gas_price);
    const low = ensure(.{ .max_fee = 1 }, 100).failure;
    try t.expectEqual(call_error.code_invalid_input, low.code);
    try t.expectEqualStrings("max fee per gas less than block base fee", low.message);
    // Both zero: treated as missing, no fee cap check.
    try t.expectEqual(@as(u256, 0), ensure(.{ .max_fee = 0, .max_priority_fee = 0 }, 9)
        .prices.gas_price);
    const tip = ensure(.{ .max_priority_fee = 0 }, 100).prices;
    try t.expectEqual(@as(u256, 100), tip.gas_price);
    try t.expectEqual(@as(?u256, 0), tip.priority_fee);
    const both = ensure(.{ .gas_price = 1, .max_fee = 200 }, 100).failure;
    try t.expectEqual(rpc.code.invalid_params, both.code);
    const above = ensure(.{ .max_fee = 200, .max_priority_fee = 300 }, 100).failure;
    try t.expectEqualStrings("max priority fee per gas higher than max fee per gas", above.message);
    const capped = ensure(.{ .max_fee = 150, .max_priority_fee = 80 }, 100).prices;
    try t.expectEqual(@as(u256, 150), capped.gas_price);
    try t.expectEqual(@as(?u256, 80), capped.priority_fee);
    try t.expectEqual(@as(?u64, null), allowance(5, 6, 1));
    try t.expectEqual(@as(?u64, 2), allowance(10, 4, 3));
    try t.expectEqual(@as(?u64, std.math.maxInt(u64)), allowance(1 << 100, 0, 1));
}

test "call_fees: parse reads only the fee fields" {
    const t = std.testing;
    const fees = try parse(
        \\{"to":"0x01","gasPrice":"0x10","maxFeePerGas":null,"blobVersionedHashes":[],"x":{}}
    );
    try t.expectEqual(@as(?u256, 16), fees.gas_price);
    try t.expectEqual(@as(?u256, null), fees.max_fee);
    try t.expectEqual(@as(?u32, 0), fees.blob_hashes);
    try t.expectError(error.InvalidParams, parse("{\"gasPrice\":1}"));
}

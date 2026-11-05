//! L1 transactions the batcher sends: EIP-1559 calldata transactions to the batch
//! inbox, plus the gas and fee-bump rules a transaction manager needs.
//!
//! Signing and RLP live in `common/consensus` (tx types) and `common/rlp`; this module
//! only decides field values. The same helpers sign plain transfers for devnet tools.

const std = @import("std");
pub const blob = @import("blob.zig");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const signature = consensus.signature;
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

pub const Address = primitives.Address;
pub const B256 = primitives.B256;

pub const Fees = struct {
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,

    pub fn valid(fees: Fees) bool {
        return fees.max_priority_fee_per_gas <= fees.max_fee_per_gas;
    }
};

/// Gas for a transaction with `data` calling an account without code, Prague rules:
/// max(21000 + 4 * tokens, EIP-7623 floor 21000 + 10 * tokens), where
/// tokens = zero_bytes + 4 * nonzero_bytes.
pub fn calldata_gas(data: []const u8) u64 {
    var tokens: u64 = 0;
    for (data) |byte| tokens += if (byte == 0) 1 else 4;
    const standard = 21_000 + 4 * tokens;
    const floor = 21_000 + 10 * tokens;
    assert(floor >= standard);
    return floor;
}

/// Fee caps for a fresh transaction: tip plus twice the base fee, so the transaction
/// stays valid through several full blocks of base fee growth (op-batcher's rule).
pub fn suggest_fees(base_fee_wei: u128, tip_wei: u128) Fees {
    const fees: Fees = .{
        .max_fee_per_gas = tip_wei + 2 * base_fee_wei,
        .max_priority_fee_per_gas = tip_wei,
    };
    assert(fees.valid());
    return fees;
}

/// Replacement fees: at least `bump_percent` above `previous` on both caps (geth needs
/// 10% for normal and 100% for blob transactions), and never below `suggested`.
pub fn bump_fees(previous: Fees, suggested: Fees, bump_percent: u8) Fees {
    assert(previous.valid() and suggested.valid());
    assert(bump_percent >= 10);
    const tip_min = bump(previous.max_priority_fee_per_gas, bump_percent);
    const fee_min = bump(previous.max_fee_per_gas, bump_percent);
    const tip = @max(tip_min, suggested.max_priority_fee_per_gas);
    const fees: Fees = .{
        .max_fee_per_gas = @max(@max(fee_min, suggested.max_fee_per_gas), tip),
        .max_priority_fee_per_gas = tip,
    };
    assert(fees.valid());
    assert(fees.max_fee_per_gas > previous.max_fee_per_gas);
    return fees;
}

fn bump(value: u128, percent: u8) u128 {
    // Round up so that 1 wei still increases; +1 guarantees strict growth at zero.
    return value + (value * percent + 99) / 100 + @intFromBool(value == 0);
}

pub const Request = struct {
    chain_id: u64,
    nonce: u64,
    fees: Fees,
    gas_limit: u64,
    /// Null creates a contract with `data` as init code.
    to: ?Address,
    value: u256 = 0,
    data: []const u8 = &.{},
};

pub const SignError = signature.SignError;

/// Builds and signs an EIP-1559 transaction.
pub fn sign_eip1559(request: Request, private_key: [32]u8) SignError!consensus.Envelope {
    assert(request.fees.valid());
    assert(request.gas_limit >= 21_000);
    var envelope: consensus.Envelope = .{
        .eip1559 = .{
            .tx = .{
                .chain_id = request.chain_id,
                .nonce = request.nonce,
                .max_priority_fee_per_gas = request.fees.max_priority_fee_per_gas,
                .max_fee_per_gas = request.fees.max_fee_per_gas,
                .gas_limit = request.gas_limit,
                .to = if (request.to) |to| .{ .call = to } else .create,
                .value = request.value,
                .input = request.data,
                .access_list = .empty,
            },
            .signature = .{ .y_parity = false, .r = 1, .s = 1 }, // Replaced below.
        },
    };
    const hash = envelope.signing_hash().?; // Only deposits have no signing hash.
    envelope.eip1559.signature = try signature.sign(private_key, hash);
    assert(envelope.eip1559.signature.is_low_s());
    return envelope;
}

/// EIP-2718 bytes ready for `eth_sendRawTransaction`.
pub fn encode_raw(envelope: consensus.Envelope, buffer: []u8) []u8 {
    assert(buffer.len >= envelope.encoded_length());
    return envelope.encode_to(buffer);
}

const testing = std.testing;
const accounts = @import("../devnet/accounts.zig");

test "txdata: calldata gas follows the EIP-7623 floor" {
    try testing.expectEqual(@as(u64, 21_000), calldata_gas(&.{}));
    try testing.expectEqual(@as(u64, 21_000 + 10 + 40), calldata_gas(&.{ 0, 1 }));
}

test "txdata: fee bumps are strictly increasing and respect suggestions" {
    const previous: Fees = .{ .max_fee_per_gas = 100, .max_priority_fee_per_gas = 10 };
    const low = bump_fees(previous, .{ .max_fee_per_gas = 1, .max_priority_fee_per_gas = 1 }, 10);
    try testing.expectEqual(@as(u128, 110), low.max_fee_per_gas);
    try testing.expectEqual(@as(u128, 11), low.max_priority_fee_per_gas);
    const high = bump_fees(previous, suggest_fees(1000, 50), 100);
    try testing.expectEqual(@as(u128, 2050), high.max_fee_per_gas);
    try testing.expectEqual(@as(u128, 50), high.max_priority_fee_per_gas);
    const zero = bump_fees(.{ .max_fee_per_gas = 0, .max_priority_fee_per_gas = 0 }, .{
        .max_fee_per_gas = 0,
        .max_priority_fee_per_gas = 0,
    }, 10);
    try testing.expect(zero.max_fee_per_gas > 0);
}

test "txdata: seeded fuzz fee bumps" {
    var prng = Prng.init(0x62756d70);
    for (0..10_000) |_| {
        const tip = prng.below(1 << 40);
        const previous: Fees = .{
            .max_fee_per_gas = tip + prng.below(1 << 40),
            .max_priority_fee_per_gas = tip,
        };
        const suggested = suggest_fees(prng.below(1 << 40), prng.below(1 << 40));
        const percent: u8 = if (prng.chance(1, 2)) 10 else 100;
        const bumped = bump_fees(previous, suggested, percent);
        const fee_floor = previous.max_fee_per_gas * (100 + percent);
        try testing.expect(bumped.max_fee_per_gas * 100 >= fee_floor);
        try testing.expect(bumped.max_priority_fee_per_gas * 100 >=
            previous.max_priority_fee_per_gas * (100 + percent));
        try testing.expect(bumped.max_fee_per_gas >= suggested.max_fee_per_gas);
    }
}

test "txdata: signed calldata tx round trips and recovers the batcher" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    const data = [_]u8{ 0, 1, 2, 3 };
    const envelope = try sign_eip1559(.{
        .chain_id = 900,
        .nonce = 7,
        .fees = suggest_fees(1_000_000_000, 1_000_000),
        .gas_limit = calldata_gas(&data),
        .to = .{ .bytes = @splat(0xff) },
        .data = &data,
    }, batcher.private_key);
    var buffer: [256]u8 = undefined;
    const raw = encode_raw(envelope, &buffer);
    try testing.expectEqual(@as(u8, 2), raw[0]);
    const decoded = try consensus.Envelope.decode(raw);
    try testing.expectEqual(@as(?u64, 7), decoded.nonce());
    const sender = decoded.recover_sender(signature.recover_address).?;
    try testing.expectEqualSlices(u8, &batcher.address.bytes, &sender.bytes);
    try testing.expectEqualSlices(u8, &envelope.hash().bytes, &decoded.hash().bytes);
}

test "txdata: contract creation has no recipient and round trips" {
    const deployer = accounts.derive_dev(@backingInt(accounts.Role.deployer));
    const init_code = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0xf3 }; // RETURN(0, 0)
    const envelope = try sign_eip1559(.{
        .chain_id = 901,
        .nonce = 3,
        .fees = suggest_fees(1_000_000_000, 1_000_000),
        .gas_limit = 100_000,
        .to = null,
        .data = &init_code,
    }, deployer.private_key);
    try testing.expect(envelope.eip1559.tx.to == .create);
    var buffer: [256]u8 = undefined;
    const decoded = try consensus.Envelope.decode(encode_raw(envelope, &buffer));
    try testing.expect(decoded.eip1559.tx.to == .create);
    try testing.expectEqualSlices(u8, &init_code, decoded.eip1559.tx.input);
    const sender = decoded.recover_sender(signature.recover_address).?;
    try testing.expectEqualSlices(u8, &deployer.address.bytes, &sender.bytes);
}

test {
    std.testing.refAllDecls(@This());
}

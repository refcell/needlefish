//! EIP-8130 (0x79) pool admission. base/base keeps these transactions in a separate
//! 2D-nonce pool; here each nonce channel becomes one pool "sender" (a lane), so the
//! pool's per-sender nonce ordering, promotion and pricing apply unchanged:
//!
//! - `nonce_key == 0` (protocol nonce): the lane is the sender itself; its nonce is the
//!   sender's account nonce.
//! - other keys: the lane address is `keccak256("8130-lane" || sender || key)[12..]`; its
//!   nonce is the channel nonce in the nonce manager's storage.
//! - `nonce_key == max` (nonce-free, expiring): one lane per transaction hash, nonce 0.
//!
//! The lane's balance is the payer's (the sender for self-pay). Lane state is read by the
//! caller (`Chain.lane_account`); this module is stateless. Admission checks the
//! static rules, the validity window at the next block time, the gas limit against the
//! worst-case intrinsic gas (`eip8130_gas.Input.worst_case`), and resolves sender and
//! payer. Authorization of keystore senders and payers is left to execution: the block
//! builder skips transactions the evm rejects.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const txpool = @import("root.zig");
const validate_module = @import("validate.zig");

const Address = primitives.Address;
const eip8130 = consensus.tx.eip8130;
const eip8130_gas = consensus.eip8130_gas;
const ValidateError = validate_module.ValidateError;

pub const Lane = struct {
    /// The pool sender the transaction is filed under.
    address: Address,
    sender: Address,
    payer: Address,
    nonce_key: u256,

    pub fn nonce_free(lane: Lane) bool {
        return lane.nonce_key == eip8130.nonce_key_max;
    }
};

/// The lane of `signed` with resolved `sender` and `payer`.
pub fn lane_of(signed: eip8130.Signed, sender: Address, payer: Address, hash: [32]u8) Lane {
    const key = signed.tx.nonce_key;
    var lane: Lane = .{ .address = sender, .sender = sender, .payer = payer, .nonce_key = key };
    if (key == 0) return lane;
    var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
    hasher.update("8130-lane");
    if (key == eip8130.nonce_key_max) {
        hasher.update(&hash);
    } else {
        hasher.update(&sender.bytes);
        var key_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &key_bytes, key, .big);
        hasher.update(&key_bytes);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    lane.address = .{ .bytes = digest[12..32].* };
    assert(!lane.address.eql(sender));
    return lane;
}

/// Resolves the sender, payer and lane of an encoded 0x79 transaction; null when a
/// signature does not recover.
pub fn resolve(
    signed: eip8130.Signed,
    hash: [32]u8,
    recoverer: consensus.Recoverer,
) ?Lane {
    const sender = signed.recover_sender(recoverer) orelse return null;
    const payer = signed.resolved_payer(sender, recoverer) orelse return null;
    return lane_of(signed, sender, payer, hash);
}

pub const Admitted = struct { tx: txpool.Tx, lane: Lane };

/// Stateless admission of `raw` (an EIP-8130 envelope) for a block at `timestamp`.
pub fn admit(
    raw: []const u8,
    signed: eip8130.Signed,
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
    recoverer: consensus.Recoverer,
) ValidateError!Admitted {
    assert(raw.len > 0 and raw[0] == eip8130.tx_type);
    if (!spec.is_upgrade_active(.everest, timestamp)) return error.TxTypeNotSupported;
    signed.validate_static(spec.chain_id) catch |err| switch (err) {
        error.ChainIdMismatch => return error.WrongChainId,
        else => return error.InvalidFeeCap,
    };
    const tx = signed.tx;
    if (tx.gas_limit > spec.gas_limit) return error.GasLimitExceeded;
    signed.validate_timestamp(timestamp *| 1000) catch return error.OutsideValidityWindow;
    const hash = primitives.keccak256(raw);
    const lane = resolve(signed, hash.bytes, recoverer) orelse return error.InvalidSignature;
    // A new channel is the costlier case; unknown here without state.
    const first_use = tx.nonce_key != 0 and tx.nonce_sequence == 0;
    const input = eip8130_gas.Input.worst_case(lane.sender, first_use, tx.sender != null);
    const gas = eip8130_gas.compute(signed, raw, input) catch return error.IntrinsicGasTooLow;
    if (tx.gas_limit < gas.sender_intrinsic()) return error.IntrinsicGasTooLow;
    if (tx.gas_limit < gas.sender_floor()) return error.IntrinsicGasTooLow;
    return .{
        .tx = .{
            .hash = hash,
            .sender = lane.address,
            .nonce = tx.nonce_sequence,
            .tx_type = eip8130.tx_type,
            .gas_limit = tx.gas_limit,
            .max_fee_per_gas = tx.max_fee_per_gas,
            .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
            .max_fee_per_blob_gas = 0,
            .blob_count = 0,
            .value = 0,
            .raw = raw,
        },
        .lane = lane,
    };
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// Every upgrade through Everest active at genesis.
const everest_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    result.upgrades = @splat(0);
    break :blk result;
};

fn private_key(n: u8) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[31] = n;
    return bytes;
}

const Built = struct {
    sender_auth: [65]u8,
    phase_buffer: [256]u8,
    calls_buffer: [512]u8,
    envelope_buffer: [1024]u8,
    signed: eip8130.Signed,
    raw: []const u8,

    fn build(built: *Built, tx_template: eip8130.TxEip8130, signer: u8) !void {
        const target: Address = .{ .bytes = @splat(0x44) };
        const calls = [_]eip8130.Call{.{ .to = target, .value = 0, .data = &.{} }};
        const phase = eip8130.Phase.build(&built.phase_buffer, &calls);
        var tx = tx_template;
        tx.calls = eip8130.Calls.build(&built.calls_buffer, &.{phase});
        built.sender_auth = try eip8130.sign_sender(tx, private_key(signer));
        built.signed = .{ .tx = tx, .sender_auth = &built.sender_auth };
        built.raw = built.signed.encode_to(&built.envelope_buffer);
    }
};

fn template(nonce_key: u256, sequence: u64) eip8130.TxEip8130 {
    return .{
        .chain_id = everest_spec.chain_id,
        .nonce_key = nonce_key,
        .nonce_sequence = sequence,
        .gas_limit = 300_000,
        .max_fee_per_gas = 100,
        .max_priority_fee_per_gas = 3,
    };
}

const recover = consensus.recover_address;

test "eip8130 pool: lanes per nonce channel, self-paid by the sender" {
    var built: Built = undefined;
    const sender = consensus.signature.address_from_private(private_key(1)).?;
    try built.build(template(0, 4), 1);
    const protocol = try admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expect(protocol.lane.address.eql(sender));
    try testing.expect(protocol.lane.payer.eql(sender));
    try testing.expectEqual(@as(u64, 4), protocol.tx.nonce);
    try testing.expectEqual(eip8130.tx_type, protocol.tx.tx_type);
    try built.build(template(7, 0), 1);
    const channel = try admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expect(!channel.lane.address.eql(sender));
    try testing.expect(channel.lane.sender.eql(sender));
    try built.build(template(8, 0), 1);
    const other = try admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expect(!other.lane.address.eql(channel.lane.address));
}

test "eip8130 pool: rejections" {
    var built: Built = undefined;
    try built.build(template(0, 0), 1);
    const base_devnet = &chainspec.ChainSpec.presets.base_devnet;
    const before = admit(built.raw, built.signed, base_devnet, 10, recover);
    try testing.expectError(error.TxTypeNotSupported, before);
    var wrong_chain = template(0, 0);
    wrong_chain.chain_id += 1;
    try built.build(wrong_chain, 1);
    const chain = admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expectError(error.WrongChainId, chain);
    var low_gas = template(0, 0);
    low_gas.gas_limit = 1000;
    try built.build(low_gas, 1);
    const gas = admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expectError(error.IntrinsicGasTooLow, gas);
    var expired = template(0, 0);
    expired.valid_before = 5;
    try built.build(expired, 1);
    const window = admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expectError(error.OutsideValidityWindow, window);
    var tip_above_cap = template(0, 0);
    tip_above_cap.max_priority_fee_per_gas = 200;
    try built.build(tip_above_cap, 1);
    const fee = admit(built.raw, built.signed, &everest_spec, 10, recover);
    try testing.expectError(error.InvalidFeeCap, fee);
}

fn check_admit(seed: u64) !void {
    var prng = Prng.init(seed);
    var built: Built = undefined;
    var tx = template(0, prng.below(8));
    if (prng.chance(1, 2)) tx.nonce_key = prng.range(1, 4);
    if (prng.chance(1, 8)) tx.nonce_key = eip8130.nonce_key_max;
    tx.gas_limit = prng.range(1, 400_000);
    tx.max_fee_per_gas = prng.range(1, 200);
    tx.max_priority_fee_per_gas = prng.range(0, 200);
    if (prng.chance(1, 4)) tx.valid_before = prng.range(1, 40_000);
    const signer: u8 = @intCast(prng.range(1, 4));
    try built.build(tx, signer);
    const timestamp = prng.range(1, 30);
    const admitted = admit(built.raw, built.signed, &everest_spec, timestamp, recover) catch
        return;
    // Admitted transactions satisfy the static rules and file under a stable lane.
    try testing.expect(admitted.tx.max_priority_fee_per_gas <= admitted.tx.max_fee_per_gas);
    try testing.expectEqual(tx.nonce_sequence, admitted.tx.nonce);
    const again = resolve(built.signed, admitted.tx.hash.bytes, recover).?;
    try testing.expect(again.address.eql(admitted.lane.address));
    try testing.expectEqual(tx.nonce_key == 0, admitted.lane.address.eql(admitted.lane.sender));
}

test "eip8130 pool: seeded fuzz of admission" {
    for (0..64) |seed| try check_admit(seed + 0x8130);
}

fn fuzz_admit(_: void, smith: *testing.Smith) anyerror!void {
    try check_admit(smith.value(u64));
}

test "eip8130 pool: fuzz" {
    try testing.fuzz({}, fuzz_admit, .{});
}

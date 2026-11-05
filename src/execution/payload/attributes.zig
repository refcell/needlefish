//! Engine API payload attributes (L1 + OP Stack extensions), payload ID derivation and
//! the fork/version-specific presence checks for withdrawals, the parent beacon block
//! root, EIP-1559 parameters and the minimum base fee.
//!
//! Mirrors base/base `crates/common/rpc-types-engine/src/attributes.rs` and
//! `crates/execution/node/src/engine.rs` (op-geth compatible payload IDs).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const chainspec = @import("../chainspec/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const PayloadId = [8]u8;

/// Engine API message version (`engine_forkchoiceUpdatedV<n>`, `newPayloadV<n>`, ...).
pub const Version = enum(u8) { v1 = 1, v2 = 2, v3 = 3, v4 = 4, v5 = 5 };

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: Address,
    amount_gwei: u64,
};

pub const PayloadAttributes = struct {
    timestamp: u64,
    prev_randao: B256,
    suggested_fee_recipient: Address,
    withdrawals: ?[]const Withdrawal = null,
    parent_beacon_block_root: ?B256 = null,
    // OP Stack extensions.
    transactions: ?[]const []const u8 = null,
    no_tx_pool: ?bool = null,
    gas_limit: ?u64 = null,
    eip1559_params: ?[8]u8 = null,
    min_base_fee: ?u64 = null,

    /// op-geth compatible payload ID: sha256 over the attributes, first byte replaced by
    /// the payload version. Not consensus critical, but must be stable per attributes.
    pub fn payload_id(
        attributes: *const PayloadAttributes,
        parent: B256,
        version: Version,
    ) PayloadId {
        var hasher = Sha256.init(.{});
        attributes.hash_l1_fields(&hasher, parent);
        const no_tx_pool = attributes.no_tx_pool orelse false;
        const txs = attributes.transactions orelse &.{};
        if (no_tx_pool or txs.len > 0) {
            hasher.update(&.{@intFromBool(no_tx_pool)});
            hasher.update(&std.mem.toBytes(std.mem.nativeToBig(u64, txs.len)));
            for (txs) |tx| hasher.update(&primitives.keccak256(tx).bytes);
        }
        if (attributes.gas_limit) |gas_limit| hash_u64(&hasher, gas_limit);
        if (attributes.eip1559_params) |params| hasher.update(&params);
        if (attributes.min_base_fee) |min_base_fee| hash_u64(&hasher, min_base_fee);
        var out: [32]u8 = undefined;
        hasher.final(&out);
        out[0] = @backingInt(version);
        return out[0..8].*;
    }

    /// Plain Ethereum payload ID (alloy `PayloadAttributes::payload_id`), for L1 mode.
    pub fn payload_id_l1(attributes: *const PayloadAttributes, parent: B256) PayloadId {
        var hasher = Sha256.init(.{});
        attributes.hash_l1_fields(&hasher, parent);
        var out: [32]u8 = undefined;
        hasher.final(&out);
        return out[0..8].*;
    }

    fn hash_l1_fields(attributes: *const PayloadAttributes, hasher: *Sha256, parent: B256) void {
        hasher.update(&parent.bytes);
        hash_u64(hasher, attributes.timestamp);
        hasher.update(&attributes.prev_randao.bytes);
        hasher.update(&attributes.suggested_fee_recipient.bytes);
        if (attributes.withdrawals) |withdrawals| hash_withdrawals(hasher, withdrawals);
        if (attributes.parent_beacon_block_root) |root| hasher.update(&root.bytes);
    }

    /// Fork- and version-specific field presence (Engine API spec + OP exec-engine spec).
    pub fn validate(
        attributes: *const PayloadAttributes,
        spec: *const chainspec.ChainSpec,
        version: Version,
    ) ValidationError!void {
        const t = attributes.timestamp;
        try validate_withdrawals(spec, version, t, attributes.withdrawals != null);
        try validate_beacon_root(spec, version, t, attributes.parent_beacon_block_root != null);
        if (spec.mode == .l1) {
            const op_fields = attributes.transactions != null or attributes.no_tx_pool != null or
                attributes.gas_limit != null or attributes.eip1559_params != null or
                attributes.min_base_fee != null;
            if (op_fields) return error.UnsupportedFields;
            return;
        }
        if (attributes.gas_limit == null) return error.MissingGasLimit;
        if (attributes.gas_limit.? == 0) return error.MissingGasLimit;
        const holocene = spec.is_upgrade_active(.holocene, t);
        if (holocene != (attributes.eip1559_params != null)) return error.Eip1559ParamsPresence;
        if (attributes.eip1559_params) |params| {
            const denominator = std.mem.readInt(u32, params[0..4], .big);
            const elasticity = std.mem.readInt(u32, params[4..8], .big);
            if ((denominator == 0) != (elasticity == 0)) return error.InvalidEip1559Params;
        }
        const jovian = spec.is_upgrade_active(.jovian, t);
        if (jovian != (attributes.min_base_fee != null)) return error.MinBaseFeePresence;
    }

    /// Header extra data for an L2 block built from these attributes: empty before
    /// Holocene, the 9-byte Holocene encoding, or the 17-byte Jovian encoding.
    /// Returns the used prefix of `out`.
    pub fn extra_data(
        attributes: *const PayloadAttributes,
        spec: *const chainspec.ChainSpec,
        out: *[chainspec.basefee.jovian_extra_data_size]u8,
    ) []const u8 {
        const t = attributes.timestamp;
        if (!spec.is_upgrade_active(.holocene, t)) return out[0..0];
        const params = attributes.eip1559_params.?;
        const defaults = spec.base_fee_params_at(t);
        if (spec.is_upgrade_active(.jovian, t)) {
            out.* = chainspec.basefee.encode_jovian(params, defaults, attributes.min_base_fee.?);
            return out[0..];
        }
        out[0..9].* = chainspec.basefee.encode_holocene(params, defaults);
        return out[0..9];
    }
};

pub const ValidationError = error{
    WithdrawalsNotSupportedInV1,
    NoWithdrawalsPostShanghai,
    HasWithdrawalsPreShanghai,
    ParentBeaconBlockRootNotSupportedBeforeV3,
    NoParentBeaconBlockRootPostCancun,
    HasParentBeaconBlockRootPreCancun,
    UnsupportedFork,
    UnsupportedFields,
    MissingGasLimit,
    Eip1559ParamsPresence,
    InvalidEip1559Params,
    MinBaseFeePresence,
};

fn validate_withdrawals(
    spec: *const chainspec.ChainSpec,
    version: Version,
    timestamp: u64,
    has_withdrawals: bool,
) ValidationError!void {
    const shanghai = spec.is_ethereum_fork_active(.shanghai, timestamp);
    if (version == .v1) {
        if (has_withdrawals) return error.WithdrawalsNotSupportedInV1;
        if (shanghai) return error.NoWithdrawalsPostShanghai;
        return;
    }
    if (shanghai and !has_withdrawals) return error.NoWithdrawalsPostShanghai;
    if (!shanghai and has_withdrawals) return error.HasWithdrawalsPreShanghai;
}

fn validate_beacon_root(
    spec: *const chainspec.ChainSpec,
    version: Version,
    timestamp: u64,
    has_root: bool,
) ValidationError!void {
    const cancun = spec.is_ethereum_fork_active(.cancun, timestamp);
    switch (version) {
        .v1, .v2 => {
            if (has_root) return error.ParentBeaconBlockRootNotSupportedBeforeV3;
            if (cancun) return error.UnsupportedFork;
        },
        .v3, .v4, .v5 => {
            if (!cancun) return error.UnsupportedFork;
            if (!has_root) return error.NoParentBeaconBlockRootPostCancun;
        },
    }
    assert(!has_root or cancun);
}

fn hash_u64(hasher: *Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    hasher.update(&bytes);
}

/// Streams the RLP list of withdrawals into the hasher without a heap buffer.
fn hash_withdrawals(hasher: *Sha256, withdrawals: []const Withdrawal) void {
    var payload_length: usize = 0;
    for (withdrawals) |w| payload_length += rlp.length(w);
    var header: [9]u8 = undefined;
    var encoder = rlp.Encoder.init(&header);
    encoder.list_header(payload_length);
    hasher.update(encoder.written());
    for (withdrawals) |w| {
        var item: [64]u8 = undefined;
        assert(rlp.length(w) <= item.len);
        hasher.update(rlp.encode_to(&item, w));
    }
}

const testing = std.testing;

const op_geth_deposit_hex =
    "7ef8f8a0dc19cfa777d90980e4875d0a548a881baaa3f83f14d1bc0d3038bc329350e54194deaddead" ++
    "deaddeaddeaddeaddeaddeaddead00019442000000000000000000000000000000000000158080830f42" ++
    "4080b8a4440a5e20000f424000000000000000000000000300000000670d6d8900000000000001250000" ++
    "0000000000000000000000000000000000000000000000000000000000070000000000000000000000000" ++
    "0000000000000000000000000000000000000014bf9181db6e381d4384bbf69c48b0ee0eed23c6ca2614" ++
    "3c6d2544f9d39997a590000000000000000000000007f83d659683caf2767fd3c720981d51f5bc365bc";

fn op_geth_attributes(buffer: []u8, txs: *[1][]const u8) !PayloadAttributes {
    txs[0] = try primitives.hex.decode_into(buffer, op_geth_deposit_hex);
    return .{
        .timestamp = 1728933301,
        .prev_randao = B256.comptime_hex(
            "9158595abbdab2c90635087619aa7042bbebe47642dfab3c9bfb934f6b082765",
        ),
        .suggested_fee_recipient = Address.comptime_hex(
            "4200000000000000000000000000000000000011",
        ),
        .withdrawals = &.{},
        .parent_beacon_block_root = B256.comptime_hex(
            "8fe0193b9bf83cb7e5a08538e494fecc23046aab9a497af3704f4afdae3250ff",
        ),
        .transactions = txs,
        .gas_limit = 30_000_000,
    };
}

const op_geth_parent = B256.comptime_hex(
    "3533bf30edaf9505d0810bf475cbe4e5f4b9889904b9845e83efdeab4e92eb1e",
);

test "attributes: payload id parity with op-geth" {
    var buffer: [512]u8 = undefined;
    var txs: [1][]const u8 = undefined;
    var attributes = try op_geth_attributes(&buffer, &txs);
    const expected = try primitives.hex.decode_array(8, "03d2dae446d2a86a");
    try testing.expectEqual(expected, attributes.payload_id(op_geth_parent, .v3));
    attributes.min_base_fee = 100;
    const expected_jovian = try primitives.hex.decode_array(8, "046c65ffc4d659ec");
    try testing.expectEqual(expected_jovian, attributes.payload_id(op_geth_parent, .v4));
}

test "attributes: payload id commits to forced transactions and withdrawals" {
    const base: PayloadAttributes = .{
        .timestamp = 1,
        .prev_randao = B256.zero,
        .suggested_fee_recipient = Address.zero,
    };
    var with_tx = base;
    with_tx.transactions = &.{"a"};
    var other_tx = base;
    other_tx.transactions = &.{"b"};
    const id = with_tx.payload_id(B256.zero, .v3);
    try testing.expect(!std.mem.eql(u8, &id, &other_tx.payload_id(B256.zero, .v3)));
    var with_w = base;
    with_w.withdrawals = &.{.{
        .index = 1,
        .validator_index = 2,
        .address = Address.zero,
        .amount_gwei = 3,
    }};
    const id_l1 = base.payload_id_l1(B256.zero);
    try testing.expect(!std.mem.eql(u8, &id_l1, &with_w.payload_id_l1(B256.zero)));
}

test "attributes: validation per fork and version" {
    const spec = &chainspec.ChainSpec.presets.base_devnet;
    var buffer: [512]u8 = undefined;
    var txs: [1][]const u8 = undefined;
    var attributes = try op_geth_attributes(&buffer, &txs);
    try testing.expectError(error.Eip1559ParamsPresence, attributes.validate(spec, .v3));
    attributes.eip1559_params = @splat(0);
    try testing.expectError(error.MinBaseFeePresence, attributes.validate(spec, .v3));
    attributes.min_base_fee = 0;
    try attributes.validate(spec, .v3);
    try testing.expectError(
        error.ParentBeaconBlockRootNotSupportedBeforeV3,
        attributes.validate(spec, .v2),
    );
    attributes.eip1559_params = .{ 0, 0, 0, 1, 0, 0, 0, 0 };
    try testing.expectError(error.InvalidEip1559Params, attributes.validate(spec, .v3));
    attributes.eip1559_params = @splat(0);
    attributes.withdrawals = null;
    try testing.expectError(error.NoWithdrawalsPostShanghai, attributes.validate(spec, .v3));
    attributes.withdrawals = &.{};
    attributes.gas_limit = null;
    try testing.expectError(error.MissingGasLimit, attributes.validate(spec, .v3));
    var out: [17]u8 = undefined;
    attributes.min_base_fee = 7;
    const extra = attributes.extra_data(spec, &out);
    try testing.expectEqual(@as(usize, 17), extra.len);
    const decoded = try chainspec.basefee.decode_jovian(extra);
    try testing.expectEqual(@as(u64, 7), decoded.min_base_fee);
    try testing.expectEqual(@as(u32, 250), decoded.denominator);
}

test "attributes: l1 mode rejects op fields" {
    const spec = &chainspec.ChainSpec.presets.l1_dev;
    var attributes: PayloadAttributes = .{
        .timestamp = 12,
        .prev_randao = B256.zero,
        .suggested_fee_recipient = Address.zero,
        .withdrawals = &.{},
        .parent_beacon_block_root = B256.zero,
    };
    try attributes.validate(spec, .v3);
    attributes.gas_limit = 1;
    try testing.expectError(error.UnsupportedFields, attributes.validate(spec, .v3));
}

fn fuzz_attributes(_: void, smith: *testing.Smith) anyerror!void {
    const specs = [_]*const chainspec.ChainSpec{
        &chainspec.ChainSpec.presets.base_mainnet,
        &chainspec.ChainSpec.presets.l1_dev,
    };
    const spec = specs[smith.valueRangeLessThan(u8, 0, specs.len)];
    var attributes: PayloadAttributes = .{
        .timestamp = smith.value(u64),
        .prev_randao = .{ .bytes = smith.value([32]u8) },
        .suggested_fee_recipient = .{ .bytes = smith.value([20]u8) },
        .withdrawals = if (smith.value(bool)) &.{} else null,
        .parent_beacon_block_root = if (smith.value(bool)) B256.zero else null,
        .gas_limit = if (smith.value(bool)) smith.value(u64) else null,
        .eip1559_params = if (smith.value(bool)) smith.value([8]u8) else null,
        .min_base_fee = if (smith.value(bool)) smith.value(u64) else null,
    };
    const version = smith.value(Version);
    if (attributes.validate(spec, version)) {
        var out: [17]u8 = undefined;
        if (spec.mode == .l2) _ = attributes.extra_data(spec, &out);
    } else |_| {}
    _ = attributes.payload_id(B256.zero, version);
    attributes.timestamp +%= 1;
}

test "attributes: fuzz" {
    try testing.fuzz({}, fuzz_attributes, .{});
}

test "attributes: seeded fuzz validate never panics, ids stable" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xa77e);
    for (0..5_000) |_| {
        var bytes: [64]u8 = undefined;
        prng.fill(&bytes);
        var smith: testing.Smith = .{ .in = &bytes };
        try fuzz_attributes({}, &smith);
    }
}

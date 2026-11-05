//! The L1 info deposit: the first transaction of every L2 block, carrying L1 origin data
//! and fee parameters to the `L1Block` predeploy.
//!
//! Calldata formats by fork (selector ++ body):
//!   Bedrock  0x015d8eb9  8 ABI words: number, time, base_fee, hash, seq, batcher, overhead,
//!                        scalar (260 bytes)
//!   Ecotone  0x440a5e20  packed: base_fee_scalar u32, blob_base_fee_scalar u32, seq u64,
//!                        time u64, number u64, base_fee u256, blob_base_fee u256, hash,
//!                        batcher word (164 bytes)
//!   Isthmus  0x098999be  Ecotone ++ operator_fee_scalar u32 ++ operator_fee_constant u64 (176)
//!   Jovian   0x3db6be2b  Isthmus ++ da_footprint_gas_scalar u16 (178)
//! Mirrors base/base `crates/common/consensus/src/info/*`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const rollup_config = @import("rollup_config.zig");
const RollupConfig = rollup_config.RollupConfig;
const SystemConfig = @import("system_config.zig").SystemConfig;
const deposits = @import("deposits.zig");
const BlockId = @import("block.zig").BlockId;

pub const Format = enum {
    bedrock,
    ecotone,
    isthmus,
    jovian,

    pub fn selector(format: Format) [4]u8 {
        return switch (format) {
            .bedrock => .{ 0x01, 0x5d, 0x8e, 0xb9 },
            .ecotone => .{ 0x44, 0x0a, 0x5e, 0x20 },
            .isthmus => .{ 0x09, 0x89, 0x99, 0xbe },
            .jovian => .{ 0x3d, 0xb6, 0xbe, 0x2b },
        };
    }

    pub fn calldata_length(format: Format) u32 {
        return switch (format) {
            .bedrock => 4 + 32 * 8,
            .ecotone => 4 + 32 * 5,
            .isthmus => 4 + 32 * 5 + 4 + 8,
            .jovian => 4 + 32 * 5 + 4 + 8 + 2,
        };
    }
};

pub const calldata_length_max: u32 = 4 + 32 * 8;
pub const da_footprint_gas_scalar_default: u16 = 400;
/// Pre-Regolith gas limit of the system L1 info deposit.
pub const bedrock_l1_info_gas: u64 = 150_000_000;

pub const DecodeError = error{ MissingSelector, InvalidSelector, InvalidLength };

pub const L1BlockInfo = struct {
    format: Format,
    number: u64 = 0,
    time: u64 = 0,
    base_fee: u64 = 0,
    block_hash: B256 = .zero,
    sequence_number: u64 = 0,
    batcher_address: Address = .zero,
    /// Bedrock only.
    l1_fee_overhead: u256 = 0,
    /// Bedrock only.
    l1_fee_scalar: u256 = 0,
    blob_base_fee: u128 = 0,
    blob_base_fee_scalar: u32 = 0,
    base_fee_scalar: u32 = 0,
    operator_fee_scalar: u32 = 0,
    operator_fee_constant: u64 = 0,
    da_footprint_gas_scalar: u16 = 0,

    pub fn id(info: *const L1BlockInfo) BlockId {
        return .{ .number = info.number, .hash = info.block_hash };
    }

    pub fn encode_calldata(info: *const L1BlockInfo, out: *[calldata_length_max]u8) []u8 {
        const length = info.format.calldata_length();
        @memset(out, 0);
        out[0..4].* = info.format.selector();
        switch (info.format) {
            .bedrock => info.encode_bedrock(out[4..length]),
            .ecotone, .isthmus, .jovian => info.encode_ecotone_body(out[4..length]),
        }
        if (info.format == .isthmus or info.format == .jovian) {
            std.mem.writeInt(u32, out[164..168], info.operator_fee_scalar, .big);
            std.mem.writeInt(u64, out[168..176], info.operator_fee_constant, .big);
        }
        if (info.format == .jovian) {
            std.mem.writeInt(u16, out[176..178], info.da_footprint_gas_scalar, .big);
        }
        return out[0..length];
    }

    fn encode_bedrock(info: *const L1BlockInfo, body: []u8) void {
        assert(body.len == 32 * 8);
        std.mem.writeInt(u256, body[0..32], info.number, .big);
        std.mem.writeInt(u256, body[32..64], info.time, .big);
        std.mem.writeInt(u256, body[64..96], info.base_fee, .big);
        body[96..128].* = info.block_hash.bytes;
        std.mem.writeInt(u256, body[128..160], info.sequence_number, .big);
        body[172..192].* = info.batcher_address.bytes;
        std.mem.writeInt(u256, body[192..224], info.l1_fee_overhead, .big);
        std.mem.writeInt(u256, body[224..256], info.l1_fee_scalar, .big);
    }

    fn encode_ecotone_body(info: *const L1BlockInfo, body: []u8) void {
        assert(body.len >= 32 * 5);
        std.mem.writeInt(u32, body[0..4], info.base_fee_scalar, .big);
        std.mem.writeInt(u32, body[4..8], info.blob_base_fee_scalar, .big);
        std.mem.writeInt(u64, body[8..16], info.sequence_number, .big);
        std.mem.writeInt(u64, body[16..24], info.time, .big);
        std.mem.writeInt(u64, body[24..32], info.number, .big);
        std.mem.writeInt(u256, body[32..64], info.base_fee, .big);
        std.mem.writeInt(u256, body[64..96], info.blob_base_fee, .big);
        body[96..128].* = info.block_hash.bytes;
        body[140..160].* = info.batcher_address.bytes;
    }

    /// Decodes calldata. Matches base/base: only the low bytes of each field are read.
    pub fn decode_calldata(calldata: []const u8) DecodeError!L1BlockInfo {
        if (calldata.len < 4) return error.MissingSelector;
        const format: Format = for (std.enums.values(Format)) |format| {
            if (std.mem.eql(u8, calldata[0..4], &format.selector())) break format;
        } else return error.InvalidSelector;
        if (calldata.len != format.calldata_length()) return error.InvalidLength;
        const r = calldata;
        if (format == .bedrock) return .{
            .format = .bedrock,
            .number = std.mem.readInt(u64, r[28..36], .big),
            .time = std.mem.readInt(u64, r[60..68], .big),
            .base_fee = std.mem.readInt(u64, r[92..100], .big),
            .block_hash = .init(r[100..132].*),
            .sequence_number = std.mem.readInt(u64, r[156..164], .big),
            .batcher_address = .init(r[176..196].*),
            .l1_fee_overhead = std.mem.readInt(u256, r[196..228], .big),
            .l1_fee_scalar = std.mem.readInt(u256, r[228..260], .big),
        };
        var info: L1BlockInfo = .{
            .format = format,
            .base_fee_scalar = std.mem.readInt(u32, r[4..8], .big),
            .blob_base_fee_scalar = std.mem.readInt(u32, r[8..12], .big),
            .sequence_number = std.mem.readInt(u64, r[12..20], .big),
            .time = std.mem.readInt(u64, r[20..28], .big),
            .number = std.mem.readInt(u64, r[28..36], .big),
            .base_fee = std.mem.readInt(u64, r[60..68], .big),
            .blob_base_fee = std.mem.readInt(u128, r[84..100], .big),
            .block_hash = .init(r[100..132].*),
            .batcher_address = .init(r[144..164].*),
        };
        if (format == .isthmus or format == .jovian) {
            info.operator_fee_scalar = std.mem.readInt(u32, r[164..168], .big);
            info.operator_fee_constant = std.mem.readInt(u64, r[168..176], .big);
        }
        if (format == .jovian) {
            info.da_footprint_gas_scalar = std.mem.readInt(u16, r[176..178], .big);
        }
        return info;
    }

    /// Builds the L1 info deposit tx; `input` borrows `calldata_buffer`.
    pub fn deposit_tx(
        info: *const L1BlockInfo,
        rollup: *const RollupConfig,
        l2_block_time: u64,
        calldata_buffer: *[calldata_length_max]u8,
    ) deposits.DepositTx {
        const regolith = rollup.is_feature_active(.deposit_gas_accounting, l2_block_time);
        return .{
            .source_hash = deposits.l1_info_source_hash(info.block_hash, info.sequence_number),
            .from = deposits.depositor_account,
            .to = deposits.l1_block_info_address,
            .gas_limit = if (regolith) deposits.regolith_system_tx_gas else bedrock_l1_info_gas,
            .is_system_transaction = !regolith,
            .input = info.encode_calldata(calldata_buffer),
        };
    }
};

/// The L1 header fields the L1 info deposit needs.
pub const L1Header = struct {
    number: u64,
    timestamp: u64,
    hash: B256,
    base_fee: ?u64,
    excess_blob_gas: ?u64,
};

/// L1 blob fee schedule (EIP-4844 / EIP-7691 / BPO forks).
pub const L1BlobSchedule = struct {
    prague_time: ?u64 = null,
    osaka_time: ?u64 = null,
    /// Blob-parameter-only forks, ascending by timestamp.
    bpo: []const Entry = &.{},

    pub const Entry = struct { timestamp: u64, update_fraction: u64 };
    pub const cancun_update_fraction: u64 = 3_338_477;
    pub const prague_update_fraction: u64 = 5_007_716;

    pub fn update_fraction(
        schedule: *const L1BlobSchedule,
        rollup: *const RollupConfig,
        l1_timestamp: u64,
    ) u64 {
        var index = schedule.bpo.len;
        while (index > 0) : (index -= 1) {
            const entry = schedule.bpo[index - 1];
            if (entry.timestamp <= l1_timestamp) return entry.update_fraction;
        }
        if (schedule.osaka_time) |time| if (time <= l1_timestamp) return prague_update_fraction;
        if (schedule.prague_time) |time| if (time <= l1_timestamp) {
            // Base Sepolia kept the Cancun schedule after L1 Pectra until the optional
            // blob schedule correction activated; without that upgrade use Prague at once.
            const correction = rollup.upgrades.get(.pectra_blob_schedule);
            if (correction == null or rollup.is_active(.pectra_blob_schedule, l1_timestamp)) {
                return prague_update_fraction;
            }
        };
        return cancun_update_fraction;
    }
};

/// EIP-4844 `fake_exponential(1, excess_blob_gas, update_fraction)`, saturating at u128.
pub fn blob_base_fee(excess_blob_gas: u64, update_fraction: u64) u128 {
    assert(update_fraction > 0);
    const denominator: u256 = update_fraction;
    const numerator: u256 = excess_blob_gas;
    var output: u256 = 0;
    var accumulator: u256 = denominator;
    var i: u256 = 1;
    // The series terminates once i > numerator / denominator; cap it for huge excess.
    while (accumulator > 0 and i < 4096) : (i += 1) {
        output += accumulator;
        const product = std.math.mul(u256, accumulator, numerator) catch {
            return std.math.maxInt(u128);
        };
        accumulator = product / (denominator * i);
    }
    const result = output / denominator;
    return std.math.cast(u128, result) orelse std.math.maxInt(u128);
}

/// Builds the L1 info for an L2 block (base/base `L1BlockInfoTx::try_new`).
pub fn build(
    rollup: *const RollupConfig,
    blob_schedule: *const L1BlobSchedule,
    system_config: *const SystemConfig,
    sequence_number: u64,
    header: L1Header,
    l2_parent_time: u64,
    l2_time: u64,
) L1BlockInfo {
    const common: L1BlockInfo = .{
        .format = .bedrock,
        .number = header.number,
        .time = header.timestamp,
        .base_fee = header.base_fee orelse 0,
        .block_hash = header.hash,
        .sequence_number = sequence_number,
        .batcher_address = system_config.batcher_address,
    };
    // The first Ecotone block still uses the Bedrock format: the upgrade transactions
    // that change the L1Block contract come after the L1 info transaction.
    if (!rollup.is_feature_active(.blob_aware_l1_fees, l2_time) or
        rollup.is_feature_first_block(.blob_aware_l1_fees, l2_time, l2_parent_time))
    {
        var info = common;
        info.l1_fee_overhead = system_config.overhead;
        info.l1_fee_scalar = system_config.scalar;
        return info;
    }
    var info = common;
    info.format = .ecotone;
    var scalar: [32]u8 = undefined;
    std.mem.writeInt(u256, &scalar, system_config.scalar, .big);
    const blob_scalar = std.mem.readInt(u32, scalar[24..28], .big);
    info.blob_base_fee_scalar = if (scalar[0] == 1) blob_scalar else 0;
    info.base_fee_scalar = std.mem.readInt(u32, scalar[28..32], .big);
    info.blob_base_fee = if (header.excess_blob_gas) |excess|
        blob_base_fee(excess, blob_schedule.update_fraction(rollup, header.timestamp))
    else
        1;
    if (rollup.is_feature_active(.da_footprint, l2_time) and
        !rollup.is_feature_first_block(.da_footprint, l2_time, l2_parent_time))
    {
        info.format = .jovian;
        const da_scalar = system_config.da_footprint_gas_scalar orelse 0;
        info.da_footprint_gas_scalar = if (da_scalar == 0)
            da_footprint_gas_scalar_default
        else
            da_scalar;
    } else if (rollup.is_feature_active(.operator_fee, l2_time) and
        !rollup.is_feature_first_block(.operator_fee, l2_time, l2_parent_time))
    {
        info.format = .isthmus;
    }
    if (info.format != .ecotone) {
        info.operator_fee_scalar = system_config.operator_fee_scalar orelse 0;
        info.operator_fee_constant = system_config.operator_fee_constant orelse 0;
    }
    return info;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn from_hex(comptime text: []const u8) [text.len / 2]u8 {
    return primitives.hex.decode_array(text.len / 2, text) catch unreachable;
}

const raw_bedrock = from_hex("015d8eb9" ++
    "000000000000000000000000000000000000000000000000000000000117c4eb" ++
    "0000000000000000000000000000000000000000000000000000000065280377" ++
    "000000000000000000000000000000000000000000000000000000026d05d953" ++
    "392012032675be9f94aae5ab442de73c5f4fb1bf30fa7dd0d2442239899a40fc" ++
    "0000000000000000000000000000000000000000000000000000000000000004" ++
    "0000000000000000000000006887246668a3b87f54deb3b94ba47a6f63f32985" ++
    "00000000000000000000000000000000000000000000000000000000000000bc" ++
    "00000000000000000000000000000000000000000000000000000000000a6fe0");
const ecotone_body = "00000558000c5fc5000000000000000500000000661c277300000000012bec20" ++
    "000000000000000000000000000000000000000000000000000000026e9f1099" ++
    "0000000000000000000000000000000000000000000000000000000000000001" ++
    "1c4c84c50740386c7dc081efddd644405f04cde73e30a2e381737acce9f5add3" ++
    "0000000000000000000000006887246668a3b87f54deb3b94ba47a6f63f32985";
const raw_ecotone = from_hex("440a5e20" ++ ecotone_body);
const raw_isthmus = from_hex("098999be" ++ ecotone_body ++ "0000abcd000000000000dcba");

const batcher = Address.comptime_hex("0x6887246668a3b87f54deb3b94ba47a6f63f32985");

fn expect_roundtrip(raw: []const u8) !L1BlockInfo {
    const info = try L1BlockInfo.decode_calldata(raw);
    var buffer: [calldata_length_max]u8 = undefined;
    try testing.expectEqualSlices(u8, raw, info.encode_calldata(&buffer));
    return info;
}

test "l1 info: bedrock roundtrip (base/base vector)" {
    const info = try expect_roundtrip(&raw_bedrock);
    try testing.expectEqual(Format.bedrock, info.format);
    try testing.expectEqual(@as(u64, 18334955), info.number);
    try testing.expectEqual(@as(u64, 1697121143), info.time);
    try testing.expectEqual(@as(u64, 10419034451), info.base_fee);
    try testing.expectEqual(@as(u64, 4), info.sequence_number);
    try testing.expect(info.batcher_address.eql(batcher));
    try testing.expectEqual(@as(u256, 0xbc), info.l1_fee_overhead);
    try testing.expectEqual(@as(u256, 0xa6fe0), info.l1_fee_scalar);
}

test "l1 info: ecotone and isthmus roundtrip (base/base vectors)" {
    const ecotone = try expect_roundtrip(&raw_ecotone);
    try testing.expectEqual(Format.ecotone, ecotone.format);
    try testing.expectEqual(@as(u64, 19655712), ecotone.number);
    try testing.expectEqual(@as(u64, 1713121139), ecotone.time);
    try testing.expectEqual(@as(u64, 10445852825), ecotone.base_fee);
    try testing.expectEqual(@as(u64, 5), ecotone.sequence_number);
    try testing.expectEqual(@as(u128, 1), ecotone.blob_base_fee);
    try testing.expectEqual(@as(u32, 810949), ecotone.blob_base_fee_scalar);
    try testing.expectEqual(@as(u32, 1368), ecotone.base_fee_scalar);
    const isthmus = try expect_roundtrip(&raw_isthmus);
    try testing.expectEqual(Format.isthmus, isthmus.format);
    try testing.expectEqual(@as(u32, 0xabcd), isthmus.operator_fee_scalar);
    try testing.expectEqual(@as(u64, 0xdcba), isthmus.operator_fee_constant);
    var jovian = isthmus;
    jovian.format = .jovian;
    jovian.da_footprint_gas_scalar = 77;
    var buffer: [calldata_length_max]u8 = undefined;
    const decoded = try L1BlockInfo.decode_calldata(jovian.encode_calldata(&buffer));
    try testing.expectEqual(jovian, decoded);
}

test "l1 info: decode errors" {
    try testing.expectError(error.MissingSelector, L1BlockInfo.decode_calldata(&.{ 1, 2 }));
    try testing.expectError(error.InvalidSelector, L1BlockInfo.decode_calldata(&.{ 1, 2, 3, 4 }));
    try testing.expectError(error.InvalidLength, L1BlockInfo.decode_calldata(raw_ecotone[0..100]));
}

fn format_at(
    rollup: *const RollupConfig,
    system: *const SystemConfig,
    header: L1Header,
    parent_time: u64,
    time: u64,
) Format {
    const schedule: L1BlobSchedule = .{};
    return build(rollup, &schedule, system, 0, header, parent_time, time).format;
}

test "l1 info: fork selection" {
    var rollup: RollupConfig = .{};
    rollup.upgrades.set(.regolith, 0);
    rollup.upgrades.set(.ecotone, 100);
    rollup.upgrades.set(.isthmus, 200);
    rollup.upgrades.set(.jovian, 300);
    const system: SystemConfig = .{ .scalar = (1 << 248) | (810949 << 32) | 1368, .overhead = 5 };
    const header: L1Header = .{
        .number = 1,
        .timestamp = 50,
        .hash = .init(@splat(9)),
        .base_fee = 7,
        .excess_blob_gas = 0,
    };
    const schedule: L1BlobSchedule = .{};
    try testing.expectEqual(Format.bedrock, format_at(&rollup, &system, header, 98, 99));
    try testing.expectEqual(Format.bedrock, format_at(&rollup, &system, header, 99, 100));
    const ecotone = build(&rollup, &schedule, &system, 0, header, 100, 102);
    try testing.expectEqual(Format.ecotone, ecotone.format);
    try testing.expectEqual(@as(u32, 810949), ecotone.blob_base_fee_scalar);
    try testing.expectEqual(@as(u32, 1368), ecotone.base_fee_scalar);
    try testing.expectEqual(@as(u128, 1), ecotone.blob_base_fee);
    try testing.expectEqual(Format.ecotone, format_at(&rollup, &system, header, 199, 200));
    try testing.expectEqual(Format.isthmus, format_at(&rollup, &system, header, 200, 202));
    try testing.expectEqual(Format.isthmus, format_at(&rollup, &system, header, 299, 300));
    const jovian = build(&rollup, &schedule, &system, 0, header, 300, 302);
    try testing.expectEqual(Format.jovian, jovian.format);
    try testing.expectEqual(@as(u16, 400), jovian.da_footprint_gas_scalar);

    var buffer: [calldata_length_max]u8 = undefined;
    const tx = jovian.deposit_tx(&rollup, 302, &buffer);
    try testing.expectEqual(deposits.regolith_system_tx_gas, tx.gas_limit);
    try testing.expect(!tx.is_system_transaction);
    try testing.expectEqual(@as(usize, 178), tx.input.len);
}

test "l1 info: blob base fee" {
    try testing.expectEqual(@as(u128, 1), blob_base_fee(0, L1BlobSchedule.cancun_update_fraction));
    // fake_exponential(1, 10_000_000, 3_338_477) = 19 (EIP-4844 reference implementation).
    try testing.expectEqual(@as(u128, 19), blob_base_fee(10_000_000, 3_338_477));
    try testing.expectEqual(std.math.maxInt(u128), blob_base_fee(std.math.maxInt(u64), 1));
    var rollup: RollupConfig = .{};
    const schedule: L1BlobSchedule = .{
        .prague_time = 10,
        .bpo = &.{.{ .timestamp = 20, .update_fraction = 8_346_193 }},
    };
    try testing.expectEqual(@as(u64, 3_338_477), schedule.update_fraction(&rollup, 9));
    try testing.expectEqual(@as(u64, 5_007_716), schedule.update_fraction(&rollup, 10));
    try testing.expectEqual(@as(u64, 8_346_193), schedule.update_fraction(&rollup, 20));
    rollup.upgrades.set(.pectra_blob_schedule, 15);
    try testing.expectEqual(@as(u64, 3_338_477), schedule.update_fraction(&rollup, 12));
    try testing.expectEqual(@as(u64, 5_007_716), schedule.update_fraction(&rollup, 15));
}

fn check_decode(input: []const u8) !void {
    const info = L1BlockInfo.decode_calldata(input) catch return;
    var buffer: [calldata_length_max]u8 = undefined;
    const encoded = info.encode_calldata(&buffer);
    try testing.expectEqual(input.len, encoded.len);
    try testing.expectEqual(info, try L1BlockInfo.decode_calldata(encoded));
}

test "l1 info: seeded fuzz decode" {
    var prng = Prng.init(0x4c31494e);
    var input: [calldata_length_max]u8 = undefined;
    for (0..5_000) |_| {
        const format = std.enums.values(Format)[prng.below(4)];
        const length = if (prng.chance(4, 5)) format.calldata_length() else prng.below(input.len);
        prng.fill(input[0..length]);
        if (length >= 4) input[0..4].* = format.selector();
        try check_decode(input[0..length]);
    }
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [calldata_length_max]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(input[0..length]);
}

test "l1 info: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

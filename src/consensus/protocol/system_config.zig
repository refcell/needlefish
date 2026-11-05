//! L1 system configuration and its updates from `ConfigUpdate` logs on L1.
//!
//! Every update log carries `topics = [TOPIC, version, update_type]` and ABI data
//! `pointer (=32) ++ length ++ payload`. Decoding mirrors alloy `abi_decode_validate`:
//! a `uint64`/`uint16`/`address` word must have zero high bytes.
//! Mirrors base/base `crates/common/genesis/src/system/*` and `updates/*`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const rollup_config = @import("rollup_config.zig");

/// keccak256("ConfigUpdate(uint256,uint8,bytes)").
pub const config_update_topic = B256.comptime_hex(
    "1d2b0bda21d56b8bd12d4f94ebacffdfb35f5e226f84b461103bb8beab6353be",
);
pub const config_update_version_0 = B256.zero;

/// Default DA footprint gas scalar applied when an update sets zero.
pub const da_footprint_gas_scalar_default: u16 = 400;

pub const Log = @import("log.zig").Log;
pub const Receipt = @import("log.zig").Receipt;

pub const UpdateKind = enum(u64) {
    batcher = 0,
    gas_config = 1,
    gas_limit = 2,
    unsafe_block_signer = 3,
    eip1559 = 4,
    operator_fee = 5,
    min_base_fee = 6,
    da_footprint_gas_scalar = 7,
};

pub const UpdateError = error{
    InvalidTopicLength,
    InvalidTopic,
    UnsupportedVersion,
    InvalidUpdateType,
    InvalidDataLength,
    InvalidDataPointer,
    InvalidPayloadLength,
    InvalidPayload,
};

pub const SystemConfig = struct {
    batcher_address: Address = .zero,
    overhead: u256 = 0,
    scalar: u256 = 0,
    gas_limit: u64 = 0,
    base_fee_scalar: ?u64 = null,
    blob_base_fee_scalar: ?u64 = null,
    eip1559_denominator: ?u32 = null,
    eip1559_elasticity: ?u32 = null,
    operator_fee_scalar: ?u32 = null,
    operator_fee_constant: ?u64 = null,
    min_base_fee: ?u64 = null,
    da_footprint_gas_scalar: ?u16 = null,

    /// Applies one `ConfigUpdate` log. On error the config is unchanged.
    pub fn apply_log(config: *SystemConfig, log: Log, ecotone_active: bool) UpdateError!UpdateKind {
        if (log.topics.len < 3) return error.InvalidTopicLength;
        if (!log.topics[0].eql(config_update_topic)) return error.InvalidTopic;
        if (!log.topics[1].eql(config_update_version_0)) return error.UnsupportedVersion;
        const type_word = log.topics[2].bytes;
        const kind_raw = std.mem.readInt(u64, type_word[24..32], .big);
        const kind = std.enums.fromInt(UpdateKind, kind_raw) orelse return error.InvalidUpdateType;
        switch (kind) {
            .gas_config => try config.apply_gas_config(log.data, ecotone_active),
            else => {
                const payload = try standard_payload(log.data);
                try config.apply_standard(kind, payload);
            },
        }
        return kind;
    }

    fn apply_standard(
        config: *SystemConfig,
        kind: UpdateKind,
        payload: *const [32]u8,
    ) UpdateError!void {
        switch (kind) {
            .batcher => config.batcher_address = try decode_address(payload),
            .gas_limit => config.gas_limit = try decode_uint(u64, payload),
            .unsafe_block_signer => _ = try decode_address(payload), // Ignored in derivation.
            .eip1559 => {
                const params = try decode_uint(u64, payload);
                config.eip1559_denominator = @truncate(params >> 32);
                config.eip1559_elasticity = @truncate(params);
            },
            .operator_fee => {
                // Raw slices, no high-byte validation (matches base/base).
                config.operator_fee_scalar = std.mem.readInt(u32, payload[20..24], .big);
                config.operator_fee_constant = std.mem.readInt(u64, payload[24..32], .big);
            },
            .min_base_fee => config.min_base_fee = try decode_uint(u64, payload),
            .da_footprint_gas_scalar => {
                const scalar = try decode_uint(u16, payload);
                config.da_footprint_gas_scalar = if (scalar == 0)
                    da_footprint_gas_scalar_default
                else
                    scalar;
            },
            .gas_config => unreachable, // Handled by apply_gas_config.
        }
    }

    fn apply_gas_config(
        config: *SystemConfig,
        data: []const u8,
        ecotone_active: bool,
    ) UpdateError!void {
        if (data.len != 128) return error.InvalidDataLength;
        if (try decode_uint(u64, data[0..32]) != 32) return error.InvalidDataPointer;
        if (try decode_uint(u64, data[32..64]) != 64) return error.InvalidPayloadLength;
        const overhead = std.mem.readInt(u256, data[64..96], .big);
        const scalar_bytes = data[96..128].*;
        if (ecotone_active) {
            // An invalid Ecotone scalar is a recognized no-op update, not an error.
            rollup_config.check_ecotone_l1_system_config_scalar(scalar_bytes) catch return;
            config.overhead = 0;
        } else {
            config.overhead = overhead;
        }
        config.scalar = std.mem.readInt(u256, &scalar_bytes, .big);
    }

    /// Applies every config update log emitted by `system_config_address` in successful
    /// receipts. Invalid logs are skipped (base/base collects them as errors).
    /// Returns the number of applied updates.
    pub fn update_with_receipts(
        config: *SystemConfig,
        receipts: []const Receipt,
        system_config_address: Address,
        ecotone_active: bool,
    ) u32 {
        var applied: u32 = 0;
        for (receipts) |receipt| {
            if (!receipt.success) continue;
            for (receipt.logs) |log| {
                if (!log.address.eql(system_config_address)) continue;
                if (log.topics.len == 0 or !log.topics[0].eql(config_update_topic)) continue;
                _ = config.apply_log(log, ecotone_active) catch continue;
                applied += 1;
            }
        }
        return applied;
    }

    /// Holocene `eip1559Params` for the payload attributes of `next_timestamp`:
    /// null before Holocene, zero on the activation block, otherwise the config values.
    pub fn eip1559_params(
        config: *const SystemConfig,
        rollup: *const rollup_config.RollupConfig,
        parent_timestamp: u64,
        next_timestamp: u64,
    ) ?[8]u8 {
        if (!rollup.is_feature_active(.dynamic_base_fee_parameters, next_timestamp)) return null;
        var result: [8]u8 = @splat(0);
        if (!rollup.is_feature_active(.dynamic_base_fee_parameters, parent_timestamp)) {
            return result;
        }
        std.mem.writeInt(u32, result[0..4], config.eip1559_denominator orelse 0, .big);
        std.mem.writeInt(u32, result[4..8], config.eip1559_elasticity orelse 0, .big);
        return result;
    }
};

/// Validates the standard 96-byte `pointer ++ length ++ word` layout.
fn standard_payload(data: []const u8) UpdateError!*const [32]u8 {
    if (data.len != 96) return error.InvalidDataLength;
    if (try decode_uint(u64, data[0..32]) != 32) return error.InvalidDataPointer;
    if (try decode_uint(u64, data[32..64]) != 32) return error.InvalidPayloadLength;
    return data[64..96];
}

/// Decodes an ABI word as `T`, rejecting nonzero high bytes.
fn decode_uint(comptime T: type, word: *const [32]u8) UpdateError!T {
    comptime assert(@bitSizeOf(T) % 8 == 0 and @bitSizeOf(T) <= 64);
    const size = @bitSizeOf(T) / 8;
    for (word[0 .. 32 - size]) |byte| if (byte != 0) return error.InvalidPayload;
    return std.mem.readInt(T, word[32 - size ..][0..size], .big);
}

fn decode_address(word: *const [32]u8) UpdateError!Address {
    for (word[0..12]) |byte| if (byte != 0) return error.InvalidPayload;
    return .init(word[12..32].*);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn type_topic(kind: u64) B256 {
    var word: [32]u8 = @splat(0);
    std.mem.writeInt(u64, word[24..32], kind, .big);
    return .init(word);
}

fn hex_data(comptime text: []const u8) [text.len / 2]u8 {
    return primitives.hex.decode_array(text.len / 2, text) catch unreachable;
}

const system_address = Address.comptime_hex("0x229047fed2591dbec1eF1118d64F7aF3dB9EB290");

test "system config: batcher update from receipts" {
    const data = hex_data("0000000000000000000000000000000000000000000000000000000000000020" ++
        "0000000000000000000000000000000000000000000000000000000000000020" ++
        "000000000000000000000000000000000000000000000000000000000000beef");
    const topics = [_]B256{ config_update_topic, config_update_version_0, type_topic(0) };
    const logs = [_]Log{.{ .address = system_address, .topics = &topics, .data = &data }};
    var config: SystemConfig = .{};
    const failed = [_]Receipt{.{ .success = false, .logs = &logs }};
    const none = config.update_with_receipts(&failed, system_address, false);
    try testing.expectEqual(@as(u32, 0), none);
    const ok = [_]Receipt{.{ .success = true, .logs = &logs }};
    try testing.expectEqual(@as(u32, 1), config.update_with_receipts(&ok, system_address, false));
    var expected: [20]u8 = @splat(0);
    expected[18] = 0xbe;
    expected[19] = 0xef;
    try testing.expectEqualSlices(u8, &expected, &config.batcher_address.bytes);
    // Other emitters are ignored.
    try testing.expectEqual(@as(u32, 0), config.update_with_receipts(&ok, .zero, false));
}

test "system config: gas config pre and post ecotone" {
    const data = hex_data("0000000000000000000000000000000000000000000000000000000000000020" ++
        "0000000000000000000000000000000000000000000000000000000000000040" ++
        "000000000000000000000000000000000000000000000000000000000000babe" ++
        "000000000000000000000000000000000000000000000000000000000000beef");
    const topics = [_]B256{ config_update_topic, config_update_version_0, type_topic(1) };
    const log: Log = .{ .address = system_address, .topics = &topics, .data = &data };
    var config: SystemConfig = .{};
    try testing.expectEqual(UpdateKind.gas_config, try config.apply_log(log, false));
    try testing.expectEqual(@as(u256, 0xbabe), config.overhead);
    try testing.expectEqual(@as(u256, 0xbeef), config.scalar);
    config = .{ .overhead = 7 };
    _ = try config.apply_log(log, true);
    try testing.expectEqual(@as(u256, 0), config.overhead);
    try testing.expectEqual(@as(u256, 0xbeef), config.scalar);
    // Invalid Ecotone scalar (version 2) is a no-op.
    var bad = data;
    bad[96] = 2;
    config = .{ .overhead = 7, .scalar = 9 };
    _ = try config.apply_log(.{ .address = system_address, .topics = &topics, .data = &bad }, true);
    try testing.expectEqual(@as(u256, 7), config.overhead);
    try testing.expectEqual(@as(u256, 9), config.scalar);
}

test "system config: standard updates and validation" {
    var word: [96]u8 = @splat(0);
    word[31] = 32;
    word[63] = 32;
    var config: SystemConfig = .{};
    var topics = [_]B256{ config_update_topic, config_update_version_0, type_topic(4) };
    std.mem.writeInt(u64, word[88..96], 0x000000ab_000000cd, .big);
    _ = try config.apply_log(.{ .address = .zero, .topics = &topics, .data = &word }, false);
    try testing.expectEqual(@as(?u32, 0xab), config.eip1559_denominator);
    try testing.expectEqual(@as(?u32, 0xcd), config.eip1559_elasticity);

    topics[2] = type_topic(7);
    @memset(word[64..96], 0);
    _ = try config.apply_log(.{ .address = .zero, .topics = &topics, .data = &word }, false);
    try testing.expectEqual(@as(?u16, 400), config.da_footprint_gas_scalar);
    word[80] = 1; // High byte set in a uint16 word.
    const before = config;
    const result = config.apply_log(.{ .address = .zero, .topics = &topics, .data = &word }, false);
    try testing.expectError(error.InvalidPayload, result);
    try testing.expectEqual(before, config);

    topics[2] = type_topic(8);
    const log: Log = .{ .address = .zero, .topics = &topics, .data = &word };
    const invalid = config.apply_log(log, false);
    try testing.expectError(error.InvalidUpdateType, invalid);
    topics[1] = type_topic(1);
    const version = config.apply_log(log, false);
    try testing.expectError(error.UnsupportedVersion, version);
}

test "system config: eip1559 params by fork" {
    var rollup: rollup_config.RollupConfig = .{};
    rollup.upgrades.set(.holocene, 10);
    const config: SystemConfig = .{ .eip1559_denominator = 0xab, .eip1559_elasticity = 0xcd };
    try testing.expect(config.eip1559_params(&rollup, 0, 9) == null);
    try testing.expectEqual(@as([8]u8, @splat(0)), config.eip1559_params(&rollup, 9, 10).?);
    const expected = [8]u8{ 0, 0, 0, 0xab, 0, 0, 0, 0xcd };
    try testing.expectEqual(expected, config.eip1559_params(&rollup, 10, 12).?);
}

test "system config: seeded fuzz apply_log is all-or-nothing" {
    var prng = Prng.init(0x53595343);
    var data: [160]u8 = undefined;
    for (0..5_000) |_| {
        const length: usize = switch (prng.below(4)) {
            0 => 96,
            1 => 128,
            else => prng.below(data.len),
        };
        prng.fill(data[0..length]);
        if (length >= 64 and prng.chance(3, 4)) {
            @memset(data[0..64], 0);
            data[31] = 32;
            data[63] = if (length == 128) 64 else 32;
            if (prng.chance(1, 2) and length >= 96) @memset(data[64..88], 0);
        }
        const kind = type_topic(prng.below(9));
        const topics = [_]B256{ config_update_topic, config_update_version_0, kind };
        var config: SystemConfig = .{ .gas_limit = 1, .overhead = 2 };
        const before = config;
        const log: Log = .{ .address = .zero, .topics = &topics, .data = data[0..length] };
        _ = config.apply_log(log, prng.chance(1, 2)) catch {
            try testing.expectEqual(before, config);
        };
    }
}

fn fuzz_apply_log(_: void, smith: *testing.Smith) anyerror!void {
    var data: [160]u8 = undefined;
    const length = smith.slice(&data);
    const kind = smith.value(u8);
    const topics = [_]B256{ config_update_topic, config_update_version_0, type_topic(kind) };
    var config: SystemConfig = .{};
    const log: Log = .{ .address = .zero, .topics = &topics, .data = data[0..length] };
    _ = config.apply_log(log, smith.value(bool)) catch {};
}

test "system config: fuzz apply_log" {
    try testing.fuzz({}, fuzz_apply_log, .{});
}

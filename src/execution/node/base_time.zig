//! Denim subsecond blocks on the execution side: the deterministic 200 ms timestamp
//! schedule (base/base `crates/common/genesis/src/schedule.rs`) and the `BaseTime`
//! predeploy install run before the first transaction of every Denim block
//! (`crates/common/evm/src/base_time.rs`, `ensure_predeploy`).

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = evm.primitives.Address;

pub const block_interval_ms: u64 = 200;

/// The `BaseTime` proxy predeploy and its implementation.
pub const proxy_address: Address = address("4200000000000000000000000000000000000030");
pub const implementation_address: Address = address("c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30030");
pub const proxy_admin: Address = address("4200000000000000000000000000000000000018");
/// EIP-1967 slots.
pub const implementation_slot: u256 =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
pub const admin_slot: u256 = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
/// The packed millisecond part lives in the low 16 bits of slot 0.
pub const millis_part_slot: u256 = 0;
pub const implementation_code_hash: [32]u8 =
    hex32("9c4c8a497a69d0b8f2ba67be0bee7a1373186055978c3be6ec3068e0ec27f32a");

const implementation_hex = @embedFile("base_time.hex");
/// The BaseTime runtime from base/base (`bytecode/base-time.hex`).
pub const implementation_code: [implementation_hex.len / 2]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var out: [implementation_hex.len / 2]u8 = undefined;
    // Proof: the embedded artifact is even-length hex (checked by the code-hash test).
    _ = std.fmt.hexToBytes(&out, implementation_hex) catch unreachable;
    break :blk out;
};

fn address(comptime text: *const [40]u8) Address {
    return hex_bytes(20, text);
}

fn hex32(comptime text: *const [64]u8) [32]u8 {
    return hex_bytes(32, text);
}

fn hex_bytes(comptime n: usize, comptime text: *const [2 * n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    // Proof: comptime literal of valid hex digits.
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

/// Legacy-to-Denim timestamp schedule of one chain.
pub const Schedule = struct {
    genesis_block_number: u64,
    genesis_timestamp: u64,
    legacy_interval_seconds: u64,
    denim_activation_timestamp: u64,

    /// Block offset from genesis of the first Denim block: the first legacy slot at or
    /// after the configured activation time.
    pub fn activation_offset(schedule: Schedule) u64 {
        assert(schedule.legacy_interval_seconds > 0);
        const since = schedule.denim_activation_timestamp -| schedule.genesis_timestamp;
        return std.math.divCeil(u64, since, schedule.legacy_interval_seconds) catch unreachable;
    }

    pub fn subsecond_at(schedule: Schedule, number: u64) bool {
        return number -| schedule.genesis_block_number >= schedule.activation_offset();
    }

    /// The deterministic timestamp of block `number` in milliseconds.
    pub fn timestamp_ms(schedule: Schedule, number: u64) u64 {
        const offset = number -| schedule.genesis_block_number;
        const interval = schedule.legacy_interval_seconds;
        const activation = schedule.activation_offset();
        if (offset < activation) {
            return (schedule.genesis_timestamp +| offset *| interval) *| 1_000;
        }
        const activation_ms = (schedule.genesis_timestamp +| activation *| interval) *| 1_000;
        return activation_ms +| (offset - activation) *| block_interval_ms;
    }

    pub const Parts = struct { seconds: u64, millis_part: u16 };

    pub fn parts(schedule: Schedule, number: u64) Parts {
        const millis = schedule.timestamp_ms(number);
        const millis_part: u16 = @intCast(millis % 1_000);
        const result: Parts = .{ .seconds = millis / 1_000, .millis_part = millis_part };
        assert(result.millis_part < 1_000);
        return result;
    }
};

pub const TransitionError = evm.state.Error || error{
    BaseTimeMissingProxy,
    BaseTimeCodelessProxy,
    BaseTimeUnexpectedProxyAdmin,
};

/// Installs the BaseTime implementation and links the proxy, once: an existing
/// implementation link is kept (it is the durable migration marker). The proxy must
/// already exist with code and the canonical proxy admin.
pub fn ensure_predeploy(state: *evm.State) TransitionError!void {
    const current = try state.storage_value(proxy_address, implementation_slot);
    if (current != 0) return;
    const proxy = try state.load(proxy_address);
    if (!proxy.in_database) return error.BaseTimeMissingProxy;
    if (!proxy.info.has_code()) return error.BaseTimeCodelessProxy;
    const admin = try state.storage_value(proxy_address, admin_slot);
    if (admin != address_word(proxy_admin)) return error.BaseTimeUnexpectedProxyAdmin;
    state.begin_transaction();
    const implementation = try state.load(implementation_address);
    try state.set_code(implementation, &implementation_code);
    try state.touch(implementation);
    const access = try state.storage_access(proxy, implementation_slot);
    try state.storage_write(proxy, access.slot, address_word(implementation_address));
    try state.touch(proxy);
    assert(state.transaction_logs().len == 0);
    state.finalize_transaction(.cancun);
    assert(try state.storage_value(proxy_address, implementation_slot) != 0);
}

pub fn address_word(value: Address) u256 {
    return std.mem.readInt(u160, &value, .big);
}

/// Minimal proxy runtime for test genesis allocations (any non-empty code passes the
/// install checks): forwards nothing, returns empty.
pub const test_proxy_code = [_]u8{0x00};

const testing = std.testing;

test "base time: implementation code hash matches base/base" {
    const hash = primitives.keccak256(&implementation_code);
    try testing.expectEqualSlices(u8, &implementation_code_hash, &hash.bytes);
    try testing.expect(implementation_hex.len % 2 == 0);
}

test "base time: schedule matches the reference formula" {
    const schedule: Schedule = .{
        .genesis_block_number = 10,
        .genesis_timestamp = 1_000,
        .legacy_interval_seconds = 2,
        .denim_activation_timestamp = 1_005,
    };
    // First legacy slot at or after 1005 is offset 3 (time 1006).
    try testing.expectEqual(@as(u64, 3), schedule.activation_offset());
    try testing.expect(!schedule.subsecond_at(12));
    try testing.expect(schedule.subsecond_at(13));
    try testing.expectEqual(@as(u64, 1_004_000), schedule.timestamp_ms(12));
    try testing.expectEqual(@as(u64, 1_006_000), schedule.timestamp_ms(13));
    try testing.expectEqual(@as(u64, 1_006_200), schedule.timestamp_ms(14));
    const p = schedule.parts(18);
    try testing.expectEqual(@as(u64, 1_007), p.seconds);
    try testing.expectEqual(@as(u16, 0), p.millis_part);
    try testing.expectEqual(@as(u16, 800), schedule.parts(17).millis_part);
    try testing.expectEqual(@as(u64, 1_000_000), schedule.timestamp_ms(0));
}

test "base time: seeded fuzz schedule is monotonic with 200 ms steps after activation" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xba5e);
    for (0..2_000) |_| {
        const schedule: Schedule = .{
            .genesis_block_number = prng.below(1_000),
            .genesis_timestamp = prng.below(1 << 40),
            .legacy_interval_seconds = 1 + prng.below(4),
            .denim_activation_timestamp = prng.below(1 << 41),
        };
        const number = schedule.genesis_block_number + prng.below(1 << 30);
        const now = schedule.timestamp_ms(number + 1);
        const before = schedule.timestamp_ms(number);
        try testing.expect(now > before);
        if (schedule.subsecond_at(number)) {
            try testing.expectEqual(before + block_interval_ms, now);
            try testing.expect(schedule.parts(number).millis_part % block_interval_ms == 0);
        }
    }
}

fn fuzz_schedule(_: void, smith: *testing.Smith) anyerror!void {
    const schedule: Schedule = .{
        .genesis_block_number = smith.value(u32),
        .genesis_timestamp = smith.value(u40),
        .legacy_interval_seconds = 1 + @as(u64, smith.value(u2)),
        .denim_activation_timestamp = smith.value(u41),
    };
    const number = schedule.genesis_block_number + smith.value(u32);
    try testing.expect(schedule.timestamp_ms(number + 1) > schedule.timestamp_ms(number));
}

test "base time: fuzz schedule" {
    try testing.fuzz({}, fuzz_schedule, .{});
}

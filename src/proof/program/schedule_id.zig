//! The locally derived schedule ID (base/base `crates/proof/proof/src/schedule_id.rs`): the
//! onchain `ProtocolVersions.activatedScheduleId(l2Timestamp)` hash chain over the
//! contract-backed upgrades, `link[i + 1] = keccak256(abi.encode(link[i], i, timestamp_i))`,
//! through the highest upgrade active at the pin timestamp (0 for unscheduled entries below
//! it). Pinning also clears every upgrade above that prefix from the config.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../../consensus/protocol/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");

const Hash = [32]u8;
const RollupConfig = protocol.RollupConfig;
const Upgrade = protocol.rollup_config.Upgrade;

/// base/base `BaseUpgrade::CONTRACT_VARIANTS`, in contract registration order.
pub const contract_upgrades = [_]Upgrade{
    .regolith, .canyon, .delta, .ecotone, .fjord,  .granite, .holocene, .pectra_blob_schedule,
    .isthmus,  .jovian, .azul,  .beryl,   .cobalt, .denim,   .everest,
};

comptime {
    assert(contract_upgrades.len == 15);
}

/// Normalizes genesis-active zero timestamps, clears upgrades above the prefix active at
/// `l2_timestamp`, and returns that prefix's schedule ID (zero when nothing is active).
pub fn pin(config: *RollupConfig, l2_timestamp: u64) Hash {
    for (contract_upgrades) |upgrade| {
        if (config.upgrades.get(upgrade) == 0) config.upgrades.set(upgrade, config.genesis.l2_time);
    }
    var pinned_count: usize = 0;
    var index: usize = contract_upgrades.len;
    while (index > 0) {
        index -= 1;
        const activation = config.upgrades.get(contract_upgrades[index]) orelse continue;
        if (activation <= l2_timestamp) {
            pinned_count = index + 1;
            break;
        }
    }
    for (contract_upgrades[pinned_count..]) |upgrade| config.upgrades.set(upgrade, null);
    var schedule_id: Hash = @splat(0);
    for (contract_upgrades[0..pinned_count], 0..) |upgrade, position| {
        const timestamp = config.upgrades.get(upgrade) orelse 0;
        schedule_id = next_link(schedule_id, position, timestamp);
    }
    assert(pinned_count <= contract_upgrades.len);
    assert(pinned_count > 0 or std.mem.allEqual(u8, &schedule_id, 0));
    return schedule_id;
}

/// One link of the hash chain: `keccak256(previous ++ u256(index) ++ u256(timestamp))`.
pub fn next_link(previous: Hash, index: u64, timestamp: u64) Hash {
    var buffer: [96]u8 = @splat(0);
    buffer[0..32].* = previous;
    std.mem.writeInt(u64, buffer[56..64], index, .big);
    std.mem.writeInt(u64, buffer[88..96], timestamp, .big);
    assert(std.mem.allEqual(u8, buffer[32..56], 0));
    return keccak.keccak256(&buffer);
}

const testing = std.testing;
const zero: Hash = @splat(0);

fn config_of(pairs: []const struct { Upgrade, u64 }) RollupConfig {
    var config: RollupConfig = .{};
    for (pairs) |pair| config.upgrades.set(pair[0], pair[1]);
    return config;
}

test "schedule id: matches the contract's golden value" {
    var config = config_of(&.{ .{ .regolith, 10 }, .{ .canyon, 20 }, .{ .azul, 30 } });
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&pin(&config, 30)});
    const golden = "c04583a182a2a57476d1ca57f9e5e7aa24f1eee188221f75fe17634b8a63f00c";
    try testing.expectEqualStrings(golden, &hex);
}

test "schedule id: zero when nothing is active, with an inclusive boundary" {
    var config = config_of(&.{.{ .canyon, 101 }});
    try testing.expectEqual(zero, pin(&config, 99));
    try testing.expectEqual(@as(?u64, null), config.upgrades.get(.canyon));
    var early = config_of(&.{.{ .regolith, 10 }});
    try testing.expectEqual(zero, pin(&early, 9));
    var boundary = config_of(&.{.{ .regolith, 10 }});
    try testing.expectEqual(next_link(zero, 0, 10), pin(&boundary, 10));
}

test "schedule id: commits inactive gaps and clears only above the prefix" {
    var config = config_of(&.{
        .{ .regolith, 10 }, .{ .canyon, 50 }, .{ .delta, 30 }, .{ .azul, 1000 },
    });
    const expected = next_link(next_link(next_link(zero, 0, 10), 1, 50), 2, 30);
    try testing.expectEqual(expected, pin(&config, 30));
    try testing.expectEqual(@as(?u64, 50), config.upgrades.get(.canyon));
    try testing.expectEqual(@as(?u64, null), config.upgrades.get(.azul));
}

test "schedule id: genesis-active zero timestamps take the genesis time" {
    var config = config_of(&.{ .{ .regolith, 0 }, .{ .canyon, 50 } });
    config.genesis.l2_time = 10;
    const schedule_id = pin(&config, 60);
    try testing.expectEqual(@as(?u64, 10), config.upgrades.get(.regolith));
    try testing.expectEqual(next_link(next_link(zero, 0, 10), 1, 50), schedule_id);
}

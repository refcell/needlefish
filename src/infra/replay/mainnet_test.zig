//! Replays ten real Base mainnet blocks (53715983..53715992, 253 transactions) from the
//! committed archive and requires every header field to match: transactions root, gas
//! used, logs bloom, blob gas used, receipts root, state root, withdrawals root, block hash.
//! The archive was built by `base replay import` from public JSON-RPC results
//! (docs/REPLAY.md); it is chain data only.

const std = @import("std");
const testing = std.testing;

const chainspec = @import("../../execution/chainspec/root.zig");
const archive_module = @import("archive.zig");
const replayer_module = @import("replayer.zig");

const fixture = @embedFile("testdata/base-mainnet-53715983-10.nfrp");

pub const fixture_config: archive_module.Archive.Config = .{
    .witness = .{
        .state_nodes_max = 1 << 16,
        .state_bytes_max = 32 << 20,
        .codes_max = 1 << 10,
        .code_bytes_max = 16 << 20,
        .keys_max = 1,
        .headers_max = 16,
        .header_bytes_max = 1 << 16,
    },
    .transactions_max = 1 << 10,
    .transaction_bytes_max = 8 << 20,
    .accounts_max = 1 << 13,
    .slots_max = 1 << 15,
};

test "replay: ten Base mainnet blocks reproduce every header field" {
    const allocator = testing.allocator;
    var archive = try archive_module.Archive.init(allocator, fixture_config);
    defer archive.deinit(allocator);
    try archive_module.decode(allocator, fixture, &archive);
    try testing.expectEqual(@as(u32, 10), archive.block_count);
    try testing.expectEqual(@as(u32, 253), archive.transactions_total());

    const replayer = try allocator.create(replayer_module.Replayer);
    defer allocator.destroy(replayer);
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    try replayer.init(allocator, spec, &archive, replayer_module.config_for(&archive));
    defer replayer.deinit(allocator);
    var number: u64 = 53_715_983;
    while (!replayer.done()) : (number += 1) {
        const outcome = try replayer.replay_next();
        try testing.expectEqual(number, outcome.number);
        if (!outcome.ok()) {
            std.debug.print("block {d}: first failed check {?t}\n", .{
                outcome.number,
                outcome.first_failed(),
            });
        }
        try testing.expect(outcome.ok());
    }
    try testing.expectEqual(@as(u64, 53_715_993), number);
}

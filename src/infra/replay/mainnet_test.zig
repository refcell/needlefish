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
const keccak256 = @import("../../execution/trie/root.zig").node.keccak256;

pub const fixture = @embedFile("testdata/base-mainnet-53715983-10.nfrp");

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

/// Replays the fixture and returns each block's computed state root (all must pass).
fn replay_roots(
    archive: *const archive_module.Archive,
    probe: bool,
    threads: u32,
) ![10][32]u8 {
    const allocator = testing.allocator;
    const replayer = try allocator.create(replayer_module.Replayer);
    defer allocator.destroy(replayer);
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    var config = replayer_module.config_for(archive);
    config.executor.recovery_threads = threads;
    try replayer.init(allocator, spec, archive, config);
    defer replayer.deinit(allocator);
    // Parallel and serial witness hashing build the same store, in the same order.
    const nodes = replayer.sparse.nodes;
    try testing.expect(nodes.count > 0);
    for (nodes.entries[0..nodes.count]) |*entry| {
        const bytes = nodes.arena[entry.offset..][0..entry.len];
        try testing.expectEqualSlices(u8, &keccak256(bytes), &entry.hash);
    }
    replayer.probe = probe;
    var roots: [10][32]u8 = undefined;
    var index: usize = 0;
    while (!replayer.done()) : (index += 1) {
        const outcome = try replayer.replay_next();
        try testing.expect(outcome.ok());
        try testing.expect(replayer.gaps.empty());
        roots[index] = outcome.computed_state_root;
    }
    try testing.expectEqual(@as(usize, 10), index);
    return roots;
}

test "replay: a second replay, in probe mode, computes the same roots" {
    // Deterministic: the replayer reads no clock, randomness or IO, so two fresh replays of
    // one archive agree; probe mode only changes what a missing key reads as, so on a
    // complete witness it must change nothing.
    const allocator = testing.allocator;
    var archive = try archive_module.Archive.init(allocator, fixture_config);
    defer archive.deinit(allocator);
    try archive_module.decode(allocator, fixture, &archive);
    // The second also hashes the witness on 3 threads.
    const first = try replay_roots(&archive, false, 0);
    const second = try replay_roots(&archive, true, 3);
    for (first, second) |a, b| try testing.expectEqualSlices(u8, &a, &b);
    try testing.expect(!std.mem.eql(u8, &first[0], &first[9]));
}

/// Rewrites the archive's state nodes without the one hashing to `hash`.
fn drop_state_node(archive: *archive_module.Archive, hash: *const [32]u8) !void {
    const allocator = testing.allocator;
    const state = &archive.witness.state;
    var kept: std.ArrayList([]const u8) = .empty;
    defer {
        for (kept.items) |node| allocator.free(node);
        kept.deinit(allocator);
    }
    var dropped: u32 = 0;
    for (0..state.count) |index| {
        const node = state.get(@intCast(index));
        if (std.mem.eql(u8, &keccak256(node), hash)) {
            dropped += 1;
            continue;
        }
        try kept.append(allocator, try allocator.dupe(u8, node));
    }
    try testing.expectEqual(@as(u32, 1), dropped);
    state.clear();
    for (kept.items) |node| try state.append(node);
}

fn replay_count(archive: *const archive_module.Archive, probe: bool) !struct {
    replayed: u32,
    first_gaps: u32,
} {
    const allocator = testing.allocator;
    const replayer = try allocator.create(replayer_module.Replayer);
    defer allocator.destroy(replayer);
    const spec = &chainspec.ChainSpec.presets.base_mainnet;
    try replayer.init(allocator, spec, archive, replayer_module.config_for(archive));
    defer replayer.deinit(allocator);
    replayer.probe = probe;
    var replayed: u32 = 0;
    var first_gaps: u32 = 0;
    while (!replayer.done()) : (replayed += 1) {
        const outcome = try replayer.replay_next();
        if (replayed == 0) {
            // The pre-state root node is gone: the first block lacks state either way.
            try testing.expect(!outcome.ok());
            try testing.expectEqual(@as(?anyerror, error.WitnessIncomplete), outcome.failure);
            first_gaps = replayer.gaps.nodes_len;
        }
    }
    return .{ .replayed = replayed, .first_gaps = first_gaps };
}

test "replay: probe mode replays past a block that lacks state; normal mode stops" {
    const allocator = testing.allocator;
    var archive = try archive_module.Archive.init(allocator, fixture_config);
    defer archive.deinit(allocator);
    try archive_module.decode(allocator, fixture, &archive);
    try drop_state_node(&archive, &archive.parent_state_root);
    const normal = try replay_count(&archive, false);
    try testing.expectEqual(@as(u32, 1), normal.replayed);
    const probe = try replay_count(&archive, true);
    try testing.expectEqual(@as(u32, 10), probe.replayed);
    try testing.expect(probe.first_gaps > 0);
    try testing.expect(normal.first_gaps > 0);
}

//! Validator tests, ported from base/base `crates/proof/challenge/src/validator.rs`.

const std = @import("std");
const testing = std.testing;

const validator = @import("validator.zig");
const fake_world = @import("fake_world.zig");
const crypto = @import("../../common/crypto/root.zig");

const Hash = [32]u8;

fn world_fixture() !*fake_world.World {
    const world = try testing.allocator.create(fake_world.World);
    world.init(1);
    return world;
}

test "challenger validator: claimed root at a block" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const view = world.effects().chain;
    const root = world.honest_root(100);
    const valid = try validator.validate_claimed_root_at_block(view, 100, root);
    try testing.expect(valid.is_valid);
    try testing.expectEqual(root, valid.expected_root);
    const invalid = try validator.validate_claimed_root_at_block(view, 100, @splat(0xdd));
    try testing.expect(!invalid.is_valid);
    try testing.expectEqual(root, invalid.expected_root);
    try testing.expectEqual(@as(?u64, null), invalid.invalid_intermediate_index);
    var buffer: [validator.header_bytes_max]u8 = undefined;
    const raw = fake_world.World.header(100, &buffer);
    const with_hash = try validator.compute_output_root_with_hash(view, 100);
    try testing.expectEqual(crypto.keccak256(raw), with_hash.block_hash);
}

test "challenger validator: intermediate roots, final valid with intermediate invalid" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const view = world.effects().chain;
    var roots = [_]Hash{ world.honest_root(95), world.honest_root(100) };
    const params: validator.IntermediateParams = .{
        .starting_block_number = 90,
        .l2_block_number = 100,
        .intermediate_block_interval = 5,
        .claimed_root = roots[1],
        .intermediate_roots = &roots,
    };
    const valid = try validator.validate_intermediate_roots(view, params);
    try testing.expect(valid.is_valid);
    try testing.expectEqual(roots[1], valid.expected_root);
    const honest_95 = roots[0];
    roots[0] = @splat(0xdd);
    const invalid = try validator.validate_intermediate_roots(view, params);
    try testing.expect(!invalid.is_valid);
    try testing.expectEqual(@as(?u64, 0), invalid.invalid_intermediate_index);
    try testing.expectEqual(honest_95, invalid.expected_root);
    roots[0] = honest_95;
    roots[1] = @splat(0xee);
    const last = try validator.validate_intermediate_roots(view, params);
    try testing.expectEqual(@as(?u64, 1), last.invalid_intermediate_index);
}

test "challenger validator: missing block, count mismatch, range and overflow" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    const view = world.effects().chain;
    world.l2_head = 99;
    try testing.expectError(
        error.BlockNotAvailable,
        validator.validate_claimed_root_at_block(view, 100, @splat(0)),
    );
    const zero: Hash = @splat(0);
    for ([_][]const Hash{ &.{zero}, &.{ zero, zero, zero } }) |roots| {
        const mismatch = validator.validate_intermediate_roots(view, .{
            .starting_block_number = 90,
            .l2_block_number = 100,
            .intermediate_block_interval = 5,
            .claimed_root = zero,
            .intermediate_roots = roots,
        });
        try testing.expectError(error.CheckpointCountMismatch, mismatch);
    }
    for ([_][2]u64{ .{ 100, 100 }, .{ 200, 100 } }) |range| {
        const range_result = validator.validate_intermediate_roots(view, .{
            .starting_block_number = range[0],
            .l2_block_number = range[1],
            .intermediate_block_interval = 10,
            .claimed_root = zero,
            .intermediate_roots = &.{},
        });
        try testing.expectError(error.InvalidBlockRange, range_result);
    }
    const max = std.math.maxInt(u64);
    const none = try validator.validate_intermediate_roots(view, .{
        .starting_block_number = max - 1,
        .l2_block_number = max,
        .intermediate_block_interval = max,
        .claimed_root = zero,
        .intermediate_roots = &.{},
    });
    try testing.expect(none.is_valid);
    world.l2_head = max;
    const roots = [_]Hash{ world.honest_root(max - 10), world.honest_root(max) };
    const top = try validator.validate_intermediate_roots(view, .{
        .starting_block_number = max - 20,
        .l2_block_number = max,
        .intermediate_block_interval = 10,
        .claimed_root = zero,
        .intermediate_roots = &roots,
    });
    try testing.expect(top.is_valid);
}

test "challenger validator: read errors propagate" {
    const world = try world_fixture();
    defer testing.allocator.destroy(world);
    world.faults.read_failure = 1000;
    const view = world.effects().chain;
    try testing.expectError(error.ChainUnavailable, validator.compute_output_root(view, 5));
}

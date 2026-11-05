//! `DisputeGameFactory` calls (base/base `crates/proof/contracts/src/dispute_game_factory.rs`):
//! calldata encoders, return decoders, the packed `extraData` of a game, and the game
//! lookup key (`games(gameType, rootClaim, extraData)`) of a proposal.

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("abi.zig");

const Address = abi.Address;
const Hash = [32]u8;

pub const create_with_init_data =
    abi.selector("createWithInitData(uint32,bytes32,bytes,bytes)");
pub const game_at_index = abi.selector("gameAtIndex(uint256)");
pub const game_count = abi.selector("gameCount()");
pub const init_bonds = abi.selector("initBonds(uint32)");
pub const game_impls = abi.selector("gameImpls(uint32)");
pub const games = abi.selector("games(uint32,bytes32,bytes)");
/// The `GameAlreadyExists(bytes32)` error selector.
pub const game_already_exists = abi.selector("GameAlreadyExists(bytes32)");

/// Most intermediate roots one game carries.
pub const intermediate_roots_max = 512;
/// Bytes of the packed `extraData` prefix: L2 block number (32) and parent address (20).
pub const extra_data_prefix_bytes = 52;
pub const extra_data_bytes_max = extra_data_prefix_bytes + 32 * intermediate_roots_max;

/// Packed (not ABI-encoded) `extraData`: `l2BlockNumber(32) ++ parent(20) ++ roots(32*N)`,
/// read by the game at fixed offsets (clone-with-immutable-args).
pub fn encode_extra_data(
    out: []u8,
    l2_block_number: u64,
    parent: Address,
    intermediate_roots: []const Hash,
) error{NoSpaceLeft}![]u8 {
    assert(intermediate_roots.len <= intermediate_roots_max);
    const size = extra_data_prefix_bytes + 32 * intermediate_roots.len;
    if (out.len < size) return error.NoSpaceLeft;
    const result = out[0..size];
    std.mem.writeInt(u256, result[0..32], l2_block_number, .big);
    result[32..52].* = parent;
    for (intermediate_roots, 0..) |root, index| result[52 + 32 * index ..][0..32].* = root;
    assert(result.len % 4 == 0);
    return result;
}

pub const LookupError = error{
    ZeroBlockInterval,
    ZeroIntermediateBlockInterval,
    InvalidInterval,
    BlockOverflow,
    IntermediateRootCount,
};

/// The roots one game needs: one per intermediate checkpoint, the last being the claim.
pub fn lookup_count(block_interval: u64, intermediate_block_interval: u64) LookupError!u32 {
    if (block_interval == 0) return error.ZeroBlockInterval;
    if (intermediate_block_interval == 0) return error.ZeroIntermediateBlockInterval;
    if (block_interval % intermediate_block_interval != 0) return error.InvalidInterval;
    const count = block_interval / intermediate_block_interval;
    if (count > intermediate_roots_max) return error.BlockOverflow;
    assert(count > 0);
    return @intCast(count);
}

/// The checkpoint blocks of a game starting after `starting_block`, into `out`.
pub fn lookup_blocks(
    out: []u64,
    starting_block: u64,
    block_interval: u64,
    intermediate_block_interval: u64,
) LookupError![]u64 {
    const count = try lookup_count(block_interval, intermediate_block_interval);
    assert(out.len >= count);
    for (out[0..count], 1..) |*block, index| {
        const offset = std.math.mul(u64, intermediate_block_interval, index) catch
            return error.BlockOverflow;
        block.* = std.math.add(u64, starting_block, offset) catch return error.BlockOverflow;
    }
    return out[0..count];
}

pub const LookupKey = struct {
    target_block: u64,
    root_claim: Hash,
    /// Borrows the caller's buffer.
    extra_data: []const u8,
};

/// The `games()` key of the game proposing `intermediate_roots` after `starting_block`.
pub fn lookup_key(
    out: []u8,
    starting_block: u64,
    parent: Address,
    block_interval: u64,
    intermediate_block_interval: u64,
    intermediate_roots: []const Hash,
) (LookupError || error{NoSpaceLeft})!LookupKey {
    const count = try lookup_count(block_interval, intermediate_block_interval);
    if (intermediate_roots.len != count) return error.IntermediateRootCount;
    const target = std.math.add(u64, starting_block, block_interval) catch
        return error.BlockOverflow;
    const extra = try encode_extra_data(out, target, parent, intermediate_roots);
    const claim = intermediate_roots[count - 1];
    return .{ .target_block = target, .root_claim = claim, .extra_data = extra };
}

pub fn encode_create(
    out: []u8,
    game_type: u32,
    root_claim: Hash,
    extra_data: []const u8,
    init_data: []const u8,
) abi.EncodeError![]u8 {
    return abi.encode_call(out, create_with_init_data, &.{
        .{ .uint = game_type },
        .{ .word = root_claim },
        .{ .bytes = extra_data },
        .{ .bytes = init_data },
    });
}

pub const CreateCalldata = struct {
    game_type: u32,
    root_claim: Hash,
    /// Borrows the calldata.
    extra_data: []const u8,
};

/// The game-identifying fields of `createWithInitData` calldata.
pub fn decode_create(calldata: []const u8) abi.DecodeError!CreateCalldata {
    const decoder = try abi.Decoder.call(calldata, create_with_init_data);
    _ = try decoder.bytes(3); // initData must be well formed too.
    return .{
        .game_type = try decoder.uint(u32, 0),
        .root_claim = (try decoder.word(1)).*,
        .extra_data = try decoder.bytes(2),
    };
}

pub fn encode_games(
    out: []u8,
    game_type: u32,
    root_claim: Hash,
    extra_data: []const u8,
) abi.EncodeError![]u8 {
    return abi.encode_call(out, games, &.{
        .{ .uint = game_type },
        .{ .word = root_claim },
        .{ .bytes = extra_data },
    });
}

pub const Game = struct { proxy: Address, timestamp: u64 };

/// `games()` returns `(address proxy, uint64 timestamp)`; a zero proxy means none.
pub fn decode_games(data: []const u8) abi.DecodeError!?Game {
    const decoder: abi.Decoder = .{ .data = data };
    const game: Game = .{
        .proxy = try decoder.address(0),
        .timestamp = try decoder.uint(u64, 1),
    };
    if (std.mem.allEqual(u8, &game.proxy, 0)) return null;
    return game;
}

pub const GameAtIndex = struct { game_type: u32, timestamp: u64, proxy: Address };

pub fn decode_game_at_index(data: []const u8) abi.DecodeError!GameAtIndex {
    const decoder: abi.Decoder = .{ .data = data };
    return .{
        .game_type = try decoder.uint(u32, 0),
        .timestamp = try decoder.uint(u64, 1),
        .proxy = try decoder.address(2),
    };
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

test "dispute game factory: extra data layout and lookup key" {
    var buffer: [extra_data_bytes_max]u8 = undefined;
    const roots = [_]Hash{ @splat(1), @splat(2) };
    const parent: Address = @splat(0xaa);
    const extra = try encode_extra_data(&buffer, 100, parent, &roots);
    try testing.expectEqual(@as(usize, 116), extra.len);
    try testing.expectEqual(@as(u8, 100), extra[31]);
    try testing.expectEqualSlices(u8, &parent, extra[32..52]);
    try testing.expectEqualSlices(u8, &roots[1], extra[84..116]);
    const key = try lookup_key(&buffer, 40, parent, 60, 30, &roots);
    try testing.expectEqual(@as(u64, 100), key.target_block);
    try testing.expectEqual(roots[1], key.root_claim);
    const wrong_count = lookup_key(&buffer, 40, parent, 60, 20, &roots);
    try testing.expectError(error.IntermediateRootCount, wrong_count);
    try testing.expectError(error.InvalidInterval, lookup_count(60, 25));
    try testing.expectError(error.ZeroBlockInterval, lookup_count(0, 1));
    try testing.expectError(error.ZeroIntermediateBlockInterval, lookup_count(1, 0));
    var blocks: [4]u64 = undefined;
    const checkpoints = try lookup_blocks(&blocks, 100, 30, 10);
    try testing.expectEqualSlices(u64, &.{ 110, 120, 130 }, checkpoints);
    const overflow = lookup_blocks(&blocks, std.math.maxInt(u64), 2, 1);
    try testing.expectError(error.BlockOverflow, overflow);
}

test "dispute game factory: create calldata round trip and rejection" {
    var buffer: [1024]u8 = undefined;
    const extra: [52]u8 = @splat(0xab);
    const init: [130]u8 = @splat(0xcd);
    const calldata = try encode_create(&buffer, 7, @splat(0x11), &extra, &init);
    try testing.expectEqualSlices(u8, &create_with_init_data, calldata[0..4]);
    const decoded = try decode_create(calldata);
    try testing.expectEqual(@as(u32, 7), decoded.game_type);
    try testing.expectEqual(@as(Hash, @splat(0x11)), decoded.root_claim);
    try testing.expectEqualSlices(u8, &extra, decoded.extra_data);
    try testing.expectError(error.Overrun, decode_create(""));
    try testing.expectError(error.SelectorMismatch, decode_create(&.{ 0x12, 0x34, 0x56, 0x78 }));
    try testing.expectError(error.Overrun, decode_create(&create_with_init_data));
}

test "dispute game factory: return decoding" {
    var data: [96]u8 = @splat(0);
    try testing.expectEqual(@as(?Game, null), try decode_games(data[0..64]));
    data[31] = 0xff;
    data[63] = 9;
    data[95] = 0x42;
    const game = (try decode_games(data[0..64])).?;
    try testing.expectEqual(@as(u64, 9), game.timestamp);
    const at = try decode_game_at_index(&data);
    try testing.expectEqual(@as(u32, 0xff), at.game_type);
    try testing.expectEqual(@as(u8, 0x42), at.proxy[19]);
    data[0] = 1;
    try testing.expectError(error.TypeCheck, decode_game_at_index(&data));
}

fn fuzz_create(_: void, smith: *std.testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    var extra: [200]u8 = undefined;
    var init: [200]u8 = undefined;
    const extra_length = smith.slice(&extra);
    const init_length = smith.slice(&init);
    const game_type = smith.value(u32);
    const root: Hash = @splat(smith.value(u8));
    const extra_data = extra[0..extra_length];
    const calldata = try encode_create(&buffer, game_type, root, extra_data, init[0..init_length]);
    const decoded = try decode_create(calldata);
    try testing.expectEqual(game_type, decoded.game_type);
    try testing.expectEqualSlices(u8, extra[0..extra_length], decoded.extra_data);
    // Any truncation is rejected or decodes to the same fields.
    const cut = smith.valueRangeAtMost(u32, 0, @intCast(calldata.len));
    if (decode_create(calldata[0..cut])) |again| {
        try testing.expectEqualSlices(u8, decoded.extra_data, again.extra_data);
    } else |_| {}
}

test "dispute game factory: fuzz create calldata" {
    try fuzz.run({}, fuzz_create, .{ .iterations = 1024 });
}

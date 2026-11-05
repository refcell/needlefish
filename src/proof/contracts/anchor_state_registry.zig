//! `AnchorStateRegistry` calls (base/base
//! `crates/proof/contracts/src/anchor_state_registry.rs`).

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("abi.zig");

const Address = abi.Address;
const Hash = [32]u8;

pub const get_anchor_root = abi.selector("getAnchorRoot()");
pub const anchor_game = abi.selector("anchorGame()");
pub const is_game_finalized = abi.selector("isGameFinalized(address)");
pub const is_game_blacklisted = abi.selector("isGameBlacklisted(address)");
pub const is_game_retired = abi.selector("isGameRetired(address)");
pub const is_game_proper = abi.selector("isGameProper(address)");
pub const is_game_respected = abi.selector("isGameRespected(address)");
pub const dispute_game_finality_delay_seconds =
    abi.selector("disputeGameFinalityDelaySeconds()");
pub const paused = abi.selector("paused()");
pub const set_anchor_state = abi.selector("setAnchorState(address)");

pub const AnchorRoot = struct { root: Hash, l2_block_number: u64 };

/// Calldata of a view taking one game address (`isGame*`).
pub fn encode_game_query(out: []u8, function: [4]u8, game: Address) abi.EncodeError![]u8 {
    assert(!std.mem.eql(u8, &function, &get_anchor_root));
    return abi.encode_call(out, function, &.{.{ .address = game }});
}

pub fn encode_set_anchor_state(out: []u8, game: Address) abi.EncodeError![]u8 {
    return abi.encode_call(out, set_anchor_state, &.{.{ .address = game }});
}

/// `getAnchorRoot()` returns `(bytes32 root, uint256 l2SequenceNumber)`.
pub fn decode_anchor_root(data: []const u8) abi.DecodeError!AnchorRoot {
    const decoder: abi.Decoder = .{ .data = data };
    const root: AnchorRoot = .{
        .root = (try decoder.word(0)).*,
        .l2_block_number = try decoder.uint(u64, 1),
    };
    assert(data.len >= 64);
    return root;
}

pub const Preflight = struct {
    blacklisted: bool,
    retired: bool,
    respected: bool,
    paused: bool,
    anchor_root: AnchorRoot,

    /// A blacklisted or retired game can never become the anchor.
    pub fn permanently_ineligible(preflight: Preflight) bool {
        return preflight.blacklisted or preflight.retired;
    }
};

const testing = std.testing;

test "anchor state registry: calls and returns" {
    var buffer: [64]u8 = undefined;
    const game: Address = @splat(0x5a);
    const calldata = try encode_set_anchor_state(&buffer, game);
    try testing.expectEqual(@as(usize, 36), calldata.len);
    const decoder = try abi.Decoder.call(calldata, set_anchor_state);
    try testing.expectEqual(game, try decoder.address(0));
    const query = try encode_game_query(&buffer, is_game_retired, game);
    try testing.expectEqualSlices(u8, &is_game_retired, query[0..4]);
    var data: [64]u8 = @splat(0);
    data[0] = 0x77;
    data[63] = 12;
    const root = try decode_anchor_root(&data);
    try testing.expectEqual(@as(u64, 12), root.l2_block_number);
    try testing.expectEqual(@as(u8, 0x77), root.root[0]);
    try testing.expectError(error.Overrun, decode_anchor_root(data[0..40]));
    const preflight: Preflight = .{
        .blacklisted = false,
        .retired = true,
        .respected = true,
        .paused = false,
        .anchor_root = root,
    };
    try testing.expect(preflight.permanently_ineligible());
}

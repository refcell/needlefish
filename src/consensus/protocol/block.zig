//! Block identifiers used throughout derivation.
//! Mirrors base/base `crates/consensus/protocol/src/block.rs` (`BlockInfo`, `L2BlockInfo`).

const std = @import("std");
const assert = std.debug.assert;

pub const Hash = [32]u8;
pub const zero_hash: Hash = @as([32]u8, @splat(0));

/// A block number and hash pair (alloy `BlockNumHash`).
pub const BlockId = struct {
    number: u64 = 0,
    hash: Hash = zero_hash,

    pub fn eql(a: BlockId, b: BlockId) bool {
        return a.number == b.number and std.mem.eql(u8, &a.hash, &b.hash);
    }
};

/// Minimal header information about an L1 or L2 block.
pub const BlockInfo = struct {
    hash: Hash = zero_hash,
    number: u64 = 0,
    parent_hash: Hash = zero_hash,
    timestamp: u64 = 0,

    pub fn id(block: BlockInfo) BlockId {
        return .{ .number = block.number, .hash = block.hash };
    }

    pub fn is_parent_of(parent: BlockInfo, child: BlockInfo) bool {
        if (parent.number == std.math.maxInt(u64)) return false;
        return parent.number + 1 == child.number and
            std.mem.eql(u8, &parent.hash, &child.parent_hash);
    }

    pub fn eql(a: BlockInfo, b: BlockInfo) bool {
        return a.number == b.number and a.timestamp == b.timestamp and
            std.mem.eql(u8, &a.hash, &b.hash) and std.mem.eql(u8, &a.parent_hash, &b.parent_hash);
    }
};

/// An L2 block with its L1 origin and sequence number within the epoch.
pub const L2BlockInfo = struct {
    block_info: BlockInfo = .{},
    l1_origin: BlockId = .{},
    sequence_number: u64 = 0,

    pub fn hash(block: L2BlockInfo) Hash {
        return block.block_info.hash;
    }

    pub fn eql(a: L2BlockInfo, b: L2BlockInfo) bool {
        return a.block_info.eql(b.block_info) and a.l1_origin.eql(b.l1_origin) and
            a.sequence_number == b.sequence_number;
    }
};

test "block: parent relation" {
    const parent: BlockInfo = .{ .hash = @splat(1), .number = 10, .timestamp = 2 };
    var child: BlockInfo = .{ .hash = @splat(2), .number = 11, .parent_hash = parent.hash };
    try std.testing.expect(parent.is_parent_of(child));
    child.number = 12;
    try std.testing.expect(!parent.is_parent_of(child));
    child.number = 11;
    child.parent_hash = zero_hash;
    try std.testing.expect(!parent.is_parent_of(child));
    const last: BlockInfo = .{ .number = std.math.maxInt(u64) };
    try std.testing.expect(!last.is_parent_of(child));
    try std.testing.expect(parent.eql(parent));
    try std.testing.expect(!parent.eql(child));
}

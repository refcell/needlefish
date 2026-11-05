//! L1 confirmation depth for derivation and sequencing (base/base `ConfDepthProvider`,
//! `--l1.verifier-confs`, and `DelayedL1OriginSelectorProvider`, `--sequencer.l1-confs`).
//!
//! Wraps an L1 chain provider so a block closer than `depth` to the L1 head is reported as
//! `error.NotFound`: derivation treats that as temporary and retries once the head moves,
//! and the sequencer's origin selector treats it as "no next origin yet". Lookups by hash
//! are never delayed: they name blocks the caller already selected.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const ProviderError = @import("../derive/errors.zig").ProviderError;

const BlockInfo = protocol.block.BlockInfo;
const Hash = protocol.block.Hash;

/// What to do while the L1 head is unknown.
pub const Unknown = enum {
    /// Derivation (base/base): no head yet means no filtering.
    pass,
    /// Sequencer (base/base): a by-number result cannot be checked, so none is returned.
    hide,
};

pub fn ConfDepth(comptime L1: type) type {
    return struct {
        l1: L1,
        l1_head: ?BlockInfo,
        depth: u64,
        unknown: Unknown,

        const Self = @This();

        /// Whether block `number` is still too close to the L1 head to use.
        pub fn hidden(self: Self, number: u64) bool {
            if (self.depth == 0 or number == 0) return false;
            const head = self.l1_head orelse return self.unknown == .hide;
            const result = number +| self.depth > head.number;
            assert(!result or head.number -| number < self.depth);
            return result;
        }

        pub fn l1_block_info_by_number(self: Self, number: u64) ProviderError!BlockInfo {
            if (self.hidden(number)) return error.NotFound;
            const block = try self.l1.l1_block_info_by_number(number);
            assert(block.number == number);
            return block;
        }

        pub fn l1_block_info_by_hash(
            self: Self,
            hash: Hash,
        ) @TypeOf(self.l1.l1_block_info_by_hash(hash)) {
            return self.l1.l1_block_info_by_hash(hash);
        }

        pub fn l1_header_by_hash(
            self: Self,
            hash: Hash,
        ) @TypeOf(self.l1.l1_header_by_hash(hash)) {
            return self.l1.l1_header_by_hash(hash);
        }

        pub fn l1_receipts_by_hash(
            self: Self,
            hash: Hash,
        ) @TypeOf(self.l1.l1_receipts_by_hash(hash)) {
            return self.l1.l1_receipts_by_hash(hash);
        }

        pub fn l1_transactions_by_hash(
            self: Self,
            hash: Hash,
        ) @TypeOf(self.l1.l1_transactions_by_hash(hash)) {
            return self.l1.l1_transactions_by_hash(hash);
        }
    };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const TestChain = @import("../derive/test_chain.zig").TestChain;
const Prng = @import("../../testing/prng.zig").Prng;

test "conf depth: hides blocks within depth of the head; zero depth passes through" {
    var chain = TestChain.init(8, 0, 12);
    const head = chain.blocks[7];
    var view: ConfDepth(*TestChain) = .{
        .l1 = &chain,
        .l1_head = head,
        .depth = 4,
        .unknown = .pass,
    };
    try testing.expectEqual(@as(u64, 3), (try view.l1_block_info_by_number(3)).number);
    try testing.expectError(error.NotFound, view.l1_block_info_by_number(4)); // 4 + 4 > 7.
    try testing.expectEqual(@as(u64, 0), (try view.l1_block_info_by_number(0)).number);
    // By hash is never delayed.
    try testing.expect((try view.l1_block_info_by_hash(chain.blocks[6].hash)).number == 6);
    view.depth = 0;
    try testing.expectEqual(@as(u64, 7), (try view.l1_block_info_by_number(7)).number);
    view.depth = 4;
    view.l1_head = null;
    try testing.expectEqual(@as(u64, 7), (try view.l1_block_info_by_number(7)).number);
    view.unknown = .hide;
    try testing.expectError(error.NotFound, view.l1_block_info_by_number(1));
}

test "conf depth: seeded, a block is usable iff it is depth blocks below the head" {
    var prng = Prng.init(0xc0f);
    var chain = TestChain.init(8, 0, 12);
    for (0..1024) |_| {
        var head = chain.blocks[0];
        head.number = prng.below(1 << 40);
        const view: ConfDepth(*TestChain) = .{
            .l1 = &chain,
            .l1_head = head,
            .depth = prng.below(16),
            .unknown = if (prng.below(2) == 0) .pass else .hide,
        };
        const number = prng.below(1 << 40);
        const usable = view.depth == 0 or number == 0 or number + view.depth <= head.number;
        try testing.expectEqual(!usable, view.hidden(number));
    }
}

fn fuzz_hidden(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [17]u8 = undefined;
    if (smith.slice(&bytes) < bytes.len) return;
    const input: []const u8 = &bytes;
    var head: BlockInfo = .{};
    head.number = std.mem.readInt(u64, input[0..8], .little);
    var chain = TestChain.init(1, 0, 12);
    const view: ConfDepth(*TestChain) = .{
        .l1 = &chain,
        .l1_head = if (input[16] & 1 == 0) head else null,
        .depth = input[16] >> 1,
        .unknown = .pass,
    };
    const number = std.mem.readInt(u64, input[8..16], .little);
    if (view.hidden(number)) try testing.expect(view.depth > 0 and number > 0);
}

test "conf depth: fuzz" {
    try std.testing.fuzz({}, fuzz_hidden, .{});
}

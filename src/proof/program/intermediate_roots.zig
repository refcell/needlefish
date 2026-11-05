//! Sampling of the intermediate output roots a proof commits. Port of base/base
//! `crates/proof/proof/src/intermediate_roots.rs` (`IntermediateRootSampler`).
//!
//! Fed the output root of every derived block in order, the sampler keeps the root of
//! every `interval`-th block (boot key 9, `intermediate_block_interval`). A complete
//! range spans a non-zero multiple of the interval, so its last sampled root is the
//! range's final root: the one the claim names. base/base's TEE and ZK provers commit
//! these roots in their journals; the fault-proof program only compares the final root.

const std = @import("std");
const assert = std.debug.assert;

const Hash = [32]u8;

/// Roots one sampler keeps at most (a 6000-block range at interval 1 needs 6000).
pub const roots_max: u32 = 8192;

pub const Error = error{
    /// No block was derived, so there is no root to commit.
    EmptyRange,
    /// The derived range does not end on an intermediate checkpoint.
    PartialInterval,
    /// More than `roots_max` roots were sampled.
    TooManyRoots,
};

pub const Sampler = struct {
    interval: u64,
    blocks: u64 = 0,
    count: u32 = 0,
    overflow: bool = false,
    roots: [roots_max]Hash = undefined,

    pub fn init(interval: u64) Sampler {
        assert(interval > 0);
        const sampler: Sampler = .{ .interval = interval };
        assert(sampler.blocks == 0 and sampler.count == 0);
        return sampler;
    }

    /// Records the output root of the next derived block.
    pub fn push(self: *Sampler, output_root: Hash) void {
        assert(self.interval > 0);
        assert(self.count <= roots_max);
        self.blocks += 1;
        if (self.blocks % self.interval != 0) return;
        if (self.count == roots_max) {
            self.overflow = true;
            return;
        }
        self.roots[self.count] = output_root;
        self.count += 1;
    }

    /// The sampled roots, or why the range has none to commit.
    pub fn finish(self: *const Sampler) Error![]const Hash {
        assert(self.interval > 0);
        assert(self.count <= roots_max);
        if (self.blocks == 0) return error.EmptyRange;
        if (self.blocks % self.interval != 0) return error.PartialInterval;
        if (self.overflow) return error.TooManyRoots;
        assert(self.count == self.blocks / self.interval);
        return self.roots[0..self.count];
    }
};

const testing = std.testing;

fn root_of(block: u64) Hash {
    var root: Hash = @splat(0);
    std.mem.writeInt(u64, root[24..32], block, .big);
    return root;
}

// Base/base's cases: pre- and post-Denim games, a challenge segment, a non-dividing
// interval and an empty range.
test "intermediate_roots: samples every interval-th block" {
    const Case = struct { blocks: u64, interval: u64, expected: Error!u64 };
    const cases = [_]Case{
        .{ .blocks = 600, .interval = 30, .expected = 20 },
        .{ .blocks = 6000, .interval = 300, .expected = 20 },
        .{ .blocks = 30, .interval = 30, .expected = 1 },
        .{ .blocks = 6000, .interval = 7, .expected = error.PartialInterval },
        .{ .blocks = 0, .interval = 30, .expected = error.EmptyRange },
    };
    const sampler = try testing.allocator.create(Sampler);
    defer testing.allocator.destroy(sampler);
    for (cases) |case| {
        sampler.* = .init(case.interval);
        for (1..case.blocks + 1) |block| sampler.push(root_of(block));
        const expected = case.expected catch |err| {
            try testing.expectError(err, sampler.finish());
            continue;
        };
        const roots = try sampler.finish();
        try testing.expectEqual(expected, roots.len);
        for (roots, 1..) |root, index| {
            try testing.expectEqual(root_of(index * case.interval), root);
        }
        try testing.expectEqual(root_of(case.blocks), roots[roots.len - 1]);
    }
}

test "intermediate_roots: more roots than the bound fail the range" {
    const sampler = try testing.allocator.create(Sampler);
    defer testing.allocator.destroy(sampler);
    sampler.* = .init(1);
    for (0..roots_max) |block| sampler.push(root_of(block));
    try testing.expectEqual(@as(usize, roots_max), (try sampler.finish()).len);
    sampler.push(root_of(roots_max));
    try testing.expectError(error.TooManyRoots, sampler.finish());
}

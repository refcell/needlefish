//! Startup forkchoice discovery: reads the execution engine's labeled heads, walks the
//! unsafe head back until its L1 origin is canonical, then walks back to a safe head that
//! is labeled safe, finalized, genesis, or a full sequencing window behind.
//! Mirrors base/base `crates/consensus/engine/src/sync/mod.rs` (`find_starting_forkchoice`).
//!
//! The finder is resumable: providers return `error.NotAvailable` while a fetch is in
//! flight, and the walk resumes from where it stopped on the next `step`.
//!
//! The client implements:
//!   fn l2_block_info_by_label(self, label: Label) ProviderError!?L2BlockInfo
//!   fn l2_block_info_by_hash(self, hash: Hash) ProviderError!?L2BlockInfo
//!   fn l1_block_info_by_number(self, number: u64) ProviderError!?BlockInfo
//!   fn l1_head(self) ProviderError!BlockInfo
//!   fn l2_block_info_by_number(self, number: u64) ProviderError!?L2BlockInfo
//!   fn l2_pruned_header(self) ?BlockInfo      header of the last `error.Pruned` answer
//!   fn l2_checkpoint(self, label: CheckpointLabel) ?L2BlockInfo
//! L2 block infos carry the L1 origin decoded from the L1 info deposit (genesis rule
//! applied by the client).
//!
//! Pruned bodies (base/base `current_with_checkpoint_reader`): when the execution client
//! pruned the finalized or safe block's body, a checkpoint whose block matches the header is
//! used instead (a mismatch is an error). Without one, a pruned safe head falls back to the
//! finalized head, and a pruned finalized head to the earliest unpruned block, found by a
//! resumable binary search up to `latest` (`find_earliest_unpruned_block`).

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../protocol/root.zig");
const ProviderError = @import("../derive/errors.zig").ProviderError;

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const BlockId = protocol.block.BlockId;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;

pub const max_reorg_sequencing_windows: u64 = 5;

pub const Label = enum { latest, safe, finalized };
pub const CheckpointLabel = enum { safe, finalized };

pub const L2ForkchoiceState = struct {
    unsafe_head: L2BlockInfo,
    safe_head: L2BlockInfo,
    finalized_head: L2BlockInfo,
};

pub const Error = ProviderError || error{
    BlockNotFound,
    MismatchedFinalizedBlock,
    FinalizedL1OriginNotCanonical,
    TooDeepReorg,
    /// A checkpoint exists for a pruned head but names a different block.
    CheckpointMismatch,
    /// The latest block is pruned too, so no unpruned block exists to start from.
    LatestPruned,
};

/// Binary search state for the earliest unpruned block: every block below `low` is pruned,
/// `best` (number `high`) is not.
const Search = struct { low: u64, high: u64 = 0, best: ?L2BlockInfo = null };

pub const StartFinder = struct {
    rollup: *const RollupConfig,
    phase: enum {
        finalized,
        finalized_search,
        safe,
        unsafe_head,
        unsafe_walk,
        safe_walk,
        done,
    } = .finalized,
    search: Search = .{ .low = 0 },
    state: L2ForkchoiceState = undefined,
    previous_unsafe_origin: u64 = 0,
    l1_head_number: ?u64 = null,
    safe_cursor: L2BlockInfo = .{},
    /// The current unsafe head's origin was found non-canonical; only its parent fetch is
    /// pending. Keeps each retry from repeating completed lookups.
    parent_pending: bool = false,

    pub fn init(rollup: *const RollupConfig) StartFinder {
        return .{ .rollup = rollup };
    }

    fn genesis_head(finder: *const StartFinder) L2BlockInfo {
        const genesis = finder.rollup.genesis;
        return .{
            .block_info = .{
                .hash = genesis.l2.hash,
                .number = genesis.l2.number,
                .timestamp = genesis.l2_time,
            },
            .l1_origin = genesis.l1,
            .sequence_number = 0,
        };
    }

    /// Advances discovery. Returns the forkchoice state when done; `error.NotAvailable`
    /// means call again after the client's fetches complete. Each call performs a bounded
    /// number of lookups (`lookups_per_step_max`).
    pub fn step(finder: *StartFinder, client: anytype) Error!?L2ForkchoiceState {
        for (0..lookups_per_step_max) |_| {
            switch (finder.phase) {
                .finalized => finder.finalized_step(client) catch |err| {
                    if (err != error.Pruned) return err;
                    const header = client.l2_pruned_header() orelse return error.BlockNotFound;
                    if (try checkpoint_for(client, .finalized, header)) |checkpoint| {
                        finder.state.finalized_head = checkpoint;
                        finder.phase = .safe;
                    } else {
                        finder.search = .{ .low = header.number + 1 };
                        finder.phase = .finalized_search;
                    }
                },
                .finalized_search => if (try finder.search_step(client)) |earliest| {
                    finder.state.finalized_head = earliest;
                    finder.phase = .safe;
                },
                .safe => {
                    const block = client.l2_block_info_by_label(.safe) catch |err| blk: {
                        if (err != error.Pruned) return err;
                        const header = client.l2_pruned_header() orelse
                            return error.BlockNotFound;
                        break :blk try checkpoint_for(client, .safe, header);
                    };
                    const ahead = try checkpoint_ahead(client, .safe, block);
                    finder.state.safe_head = ahead orelse block orelse
                        finder.state.finalized_head;
                    finder.phase = .unsafe_head;
                },
                .unsafe_head => {
                    const block = try client.l2_block_info_by_label(.latest);
                    finder.state.unsafe_head = block orelse return error.BlockNotFound;
                    finder.previous_unsafe_origin = finder.state.unsafe_head.l1_origin.number;
                    finder.phase = .unsafe_walk;
                },
                .unsafe_walk => if (try finder.unsafe_walk_step(client)) {
                    finder.safe_cursor = finder.state.unsafe_head;
                    finder.phase = .safe_walk;
                },
                .safe_walk => if (try finder.safe_walk_step(client)) {
                    finder.phase = .done;
                },
                .done => return finder.state,
            }
        }
        return null;
    }

    pub const lookups_per_step_max = 4096;

    fn finalized_step(finder: *StartFinder, client: anytype) Error!void {
        assert(finder.phase == .finalized);
        const block = try client.l2_block_info_by_label(.finalized);
        const ahead = try checkpoint_ahead(client, .finalized, block);
        finder.state.finalized_head = ahead orelse block orelse finder.genesis_head();
        finder.phase = .safe;
    }

    /// The engine's canonical block at the checkpoint for `label` when the checkpoint is
    /// ahead of the engine's `labeled` block. An engine restarted without its safe and
    /// finalized labels (needlefish's keeps only its head, and only its newest blocks) then
    /// resumes from the heads this node derived instead of walking back to blocks the engine
    /// no longer holds; base/base gets the same from reth, which persists the labels.
    fn checkpoint_ahead(
        client: anytype,
        label: CheckpointLabel,
        labeled: ?L2BlockInfo,
    ) Error!?L2BlockInfo {
        const checkpoint = client.l2_checkpoint(label) orelse return null;
        const number = checkpoint.block_info.number;
        if (labeled) |block| {
            if (block.block_info.number >= number) return null;
        }
        const canonical = client.l2_block_info_by_number(number) catch |err| switch (err) {
            error.Pruned => return null,
            else => return err,
        };
        const block = canonical orelse return null;
        if (!block.block_info.hash.eql(checkpoint.block_info.hash)) return null;
        assert(block.block_info.number == number);
        return block;
    }

    /// The checkpoint for `label` when it matches the pruned block's header.
    fn checkpoint_for(
        client: anytype,
        label: CheckpointLabel,
        header: BlockInfo,
    ) Error!?L2BlockInfo {
        const checkpoint = client.l2_checkpoint(label) orelse return null;
        if (!std.meta.eql(checkpoint.block_info, header)) return error.CheckpointMismatch;
        assert(checkpoint.block_info.hash.eql(header.hash));
        return checkpoint;
    }

    /// One binary-search lookup; the earliest unpruned block once the range collapses.
    fn search_step(finder: *StartFinder, client: anytype) Error!?L2BlockInfo {
        const search = &finder.search;
        if (search.best == null) {
            const latest = client.l2_block_info_by_label(.latest) catch |err| return switch (err) {
                error.Pruned => error.LatestPruned,
                else => err,
            };
            const block = latest orelse return error.BlockNotFound;
            if (block.block_info.number < search.low) return error.LatestPruned;
            search.best = block;
            search.high = block.block_info.number;
        }
        if (search.low >= search.high) return search.best.?;
        const middle = search.low + (search.high - search.low) / 2;
        const found = client.l2_block_info_by_number(middle) catch |err| {
            if (err != error.Pruned) return err;
            search.low = middle + 1;
            return null;
        };
        const block = found orelse return error.BlockNotFound;
        assert(block.block_info.number == middle);
        search.best = block;
        search.high = middle;
        return null;
    }

    /// One unsafe-walk iteration; true once the unsafe head's L1 origin is plausible.
    fn unsafe_walk_step(finder: *StartFinder, client: anytype) Error!bool {
        const state = &finder.state;
        const unsafe_number = state.unsafe_head.block_info.number;
        const finalized_number = state.finalized_head.block_info.number;
        if (unsafe_number <= finalized_number and
            !state.unsafe_head.block_info.hash.eql(state.finalized_head.block_info.hash))
        {
            return error.MismatchedFinalizedBlock;
        }
        const origin = state.unsafe_head.l1_origin;
        const depth_max = finder.rollup.seq_window_size *| max_reorg_sequencing_windows;
        if (origin.number +| depth_max < finder.previous_unsafe_origin) return error.TooDeepReorg;

        if (!finder.parent_pending) {
            if (try finder.origin_plausible(client, origin)) return true;
            if (unsafe_number <= finalized_number) return error.FinalizedL1OriginNotCanonical;
            finder.parent_pending = true;
        }
        const parent = try client.l2_block_info_by_hash(state.unsafe_head.block_info.parent_hash);
        state.unsafe_head = parent orelse return error.BlockNotFound;
        finder.parent_pending = false;
        assert(state.unsafe_head.block_info.number + 1 == unsafe_number);
        return false;
    }

    fn origin_plausible(finder: *StartFinder, client: anytype, origin: BlockId) Error!bool {
        const canonical = try client.l1_block_info_by_number(origin.number);
        const plausible = if (canonical) |block| block.hash.eql(origin.hash) else blk: {
            if (finder.l1_head_number == null) {
                finder.l1_head_number = (try client.l1_head()).number;
            }
            // An origin beyond the visible L1 head may simply not be seen yet.
            break :blk origin.number > finder.l1_head_number.?;
        };
        assert(canonical == null or canonical.?.number == origin.number);
        return plausible;
    }

    /// One safe-walk iteration; true once a suitable safe head is found.
    fn safe_walk_step(finder: *StartFinder, client: anytype) Error!bool {
        const state = &finder.state;
        const cursor = finder.safe_cursor;
        const window_floor = state.unsafe_head.l1_origin.number -| finder.rollup.seq_window_size;
        const behind_window = window_floor > cursor.l1_origin.number;
        const labeled_safe = cursor.block_info.hash.eql(state.safe_head.block_info.hash);
        const finalized = cursor.block_info.hash.eql(state.finalized_head.block_info.hash);
        const genesis = cursor.block_info.hash.eql(finder.rollup.genesis.l2.hash);
        if (behind_window or labeled_safe or finalized or genesis) {
            state.safe_head = cursor;
            return true;
        }
        const parent_hash = cursor.block_info.parent_hash;
        if (parent_hash.eql(state.safe_head.block_info.hash)) {
            finder.safe_cursor = state.safe_head;
        } else if (parent_hash.eql(state.finalized_head.block_info.hash)) {
            finder.safe_cursor = state.finalized_head;
        } else {
            const parent = try client.l2_block_info_by_hash(parent_hash);
            finder.safe_cursor = parent orelse return error.BlockNotFound;
        }
        assert(finder.safe_cursor.block_info.number < cursor.block_info.number or
            finder.safe_cursor.block_info.hash.eql(parent_hash));
        return false;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// Linear test chain: L2 block `i` has L1 origin `i / 2`. L1 blocks at or above
/// `l1_reorg_from` have a different (non-canonical) hash in the L2 view.
const TestClient = struct {
    l2: [32]L2BlockInfo,
    l2_count: u32,
    l1_count: u32,
    labels: [3]?u32 = .{ null, null, null }, // latest, safe, finalized indices
    l1_reorg_from: u64 = std.math.maxInt(u64),
    unavailable_every: u32 = 0,
    calls: u32 = 0,
    /// Blocks below this number have pruned bodies.
    pruned_below: u64 = 0,
    last_pruned: ?BlockInfo = null,
    checkpoints: [2]?L2BlockInfo = .{ null, null }, // safe, finalized
    /// Blocks below this number are gone (an engine's retention after a restart).
    retained_from: u64 = 0,

    fn l1_hash(number: u64, canonical: bool) Hash {
        var hash: Hash = .{ .bytes = @splat(if (canonical) 0xaa else 0xbb) };
        std.mem.writeInt(u64, hash.bytes[0..8], number, .big);
        return hash;
    }

    fn init(l2_count: u32, l1_reorg_from: u64) TestClient {
        var client: TestClient = .{ .l2 = undefined, .l2_count = l2_count, .l1_count = 64 };
        client.l1_reorg_from = l1_reorg_from;
        for (0..l2_count) |i| {
            var hash: Hash = .{ .bytes = @splat(0x22) };
            std.mem.writeInt(u64, hash.bytes[0..8], i, .big);
            const origin: u64 = i / 2;
            client.l2[i] = .{
                .block_info = .{
                    .hash = hash,
                    .number = i,
                    .parent_hash = if (i == 0) .zero else client.l2[i - 1].block_info.hash,
                },
                .l1_origin = .{ .number = origin, .hash = l1_hash(origin, origin < l1_reorg_from) },
            };
        }
        return client;
    }

    fn maybe_unavailable(client: *TestClient) ProviderError!void {
        client.calls += 1;
        if (client.unavailable_every != 0 and client.calls % client.unavailable_every == 0) {
            return error.NotAvailable;
        }
    }

    fn answer(client: *TestClient, block: L2BlockInfo) ProviderError!?L2BlockInfo {
        if (block.block_info.number < client.pruned_below) {
            client.last_pruned = block.block_info;
            return error.Pruned;
        }
        return block;
    }

    pub fn l2_block_info_by_label(client: *TestClient, label: Label) ProviderError!?L2BlockInfo {
        try client.maybe_unavailable();
        const index = client.labels[@backingInt(label)] orelse return null;
        return client.answer(client.l2[index]);
    }

    pub fn l2_block_info_by_number(client: *TestClient, number: u64) ProviderError!?L2BlockInfo {
        try client.maybe_unavailable();
        if (number >= client.l2_count or number < client.retained_from) return null;
        return client.answer(client.l2[number]);
    }

    pub fn l2_pruned_header(client: *TestClient) ?BlockInfo {
        return client.last_pruned;
    }

    pub fn l2_checkpoint(client: *TestClient, label: CheckpointLabel) ?L2BlockInfo {
        return client.checkpoints[@backingInt(label)];
    }

    pub fn l2_block_info_by_hash(client: *TestClient, hash: Hash) ProviderError!?L2BlockInfo {
        try client.maybe_unavailable();
        for (client.l2[client.retained_from..client.l2_count]) |block| {
            if (block.block_info.hash.eql(hash)) return block;
        }
        return null;
    }

    pub fn l1_block_info_by_number(client: *TestClient, number: u64) ProviderError!?BlockInfo {
        try client.maybe_unavailable();
        if (number >= client.l1_count) return null;
        return .{ .number = number, .hash = l1_hash(number, true) };
    }

    pub fn l1_head(client: *TestClient) ProviderError!BlockInfo {
        try client.maybe_unavailable();
        return .{ .number = client.l1_count - 1, .hash = l1_hash(client.l1_count - 1, true) };
    }
};

fn run(finder: *StartFinder, client: *TestClient) Error!L2ForkchoiceState {
    for (0..10_000) |_| {
        const result = finder.step(client) catch |err| switch (err) {
            error.NotAvailable => continue,
            else => return err,
        };
        if (result) |state| return state;
    }
    unreachable;
}

test "sync start: walks back a reorged unsafe tail and finds the safe head" {
    var rollup: RollupConfig = .{ .seq_window_size = 4 };
    var client = TestClient.init(30, 10); // L2 blocks 20.. have non-canonical origins.
    rollup.genesis.l2.hash = client.l2[0].block_info.hash;
    client.labels = .{ 29, 12, 4 };
    var finder = StartFinder.init(&rollup);
    const state = try run(&finder, &client);
    try testing.expectEqual(@as(u64, 19), state.unsafe_head.block_info.number);
    try testing.expectEqual(@as(u64, 12), state.safe_head.block_info.number);
    try testing.expectEqual(@as(u64, 4), state.finalized_head.block_info.number);
}

test "sync start: safe head from the sequencing window, genesis defaults, errors" {
    var rollup: RollupConfig = .{ .seq_window_size = 2 };
    var client = TestClient.init(30, std.math.maxInt(u64));
    rollup.genesis.l2.hash = client.l2[0].block_info.hash;
    client.labels = .{ 29, null, null };
    var finder = StartFinder.init(&rollup);
    const state = try run(&finder, &client);
    try testing.expectEqual(@as(u64, 29), state.unsafe_head.block_info.number);
    // Origin of 29 is 14; the window floor is 12, so the first block with origin 11 is safe.
    try testing.expectEqual(@as(u64, 23), state.safe_head.block_info.number);
    try testing.expect(state.finalized_head.block_info.hash.eql(rollup.genesis.l2.hash));

    client.labels = .{ 3, 3, 5 };
    finder = StartFinder.init(&rollup);
    try testing.expectError(error.MismatchedFinalizedBlock, run(&finder, &client));
    client = TestClient.init(30, 0);
    client.labels = .{ 29, 4, 4 };
    finder = StartFinder.init(&rollup);
    try testing.expectError(error.TooDeepReorg, run(&finder, &client));
}

test "sync start: pruned heads recover from checkpoints or the earliest unpruned block" {
    var rollup: RollupConfig = .{ .seq_window_size = 64 };
    var client = TestClient.init(30, std.math.maxInt(u64));
    rollup.genesis.l2.hash = client.l2[0].block_info.hash;
    client.labels = .{ 29, 12, 4 };
    client.pruned_below = 17;
    // No checkpoints: finalized becomes the earliest unpruned block, safe falls back to it.
    var finder = StartFinder.init(&rollup);
    var state = try run(&finder, &client);
    try testing.expectEqual(@as(u64, 17), state.finalized_head.block_info.number);
    try testing.expectEqual(@as(u64, 17), state.safe_head.block_info.number);
    try testing.expectEqual(@as(u64, 29), state.unsafe_head.block_info.number);
    // Matching checkpoints are used as they are.
    client.checkpoints = .{ client.l2[12], client.l2[4] };
    finder = StartFinder.init(&rollup);
    state = try run(&finder, &client);
    try testing.expectEqual(@as(u64, 4), state.finalized_head.block_info.number);
    try testing.expectEqual(@as(u64, 12), state.safe_head.block_info.number);
    // A checkpoint naming another block is an error.
    client.checkpoints = .{ null, client.l2[5] };
    finder = StartFinder.init(&rollup);
    try testing.expectError(error.CheckpointMismatch, run(&finder, &client));
    // Everything pruned: nothing to start from.
    client.checkpoints = .{ null, null };
    client.pruned_below = 30;
    finder = StartFinder.init(&rollup);
    try testing.expectError(error.LatestPruned, run(&finder, &client));
}

test "sync start: an engine that lost its labels resumes from the checkpoints" {
    var rollup: RollupConfig = .{ .seq_window_size = 100 };
    var client = TestClient.init(30, std.math.maxInt(u64));
    rollup.genesis.l2.hash = client.l2[0].block_info.hash;
    // Restarted: safe and finalized read as genesis, and blocks below 20 are gone, so the
    // safe walk (the window reaches genesis) would hit a missing block.
    client.labels = .{ 29, 0, 0 };
    client.retained_from = 20;
    var lost = StartFinder.init(&rollup);
    try testing.expectError(error.BlockNotFound, run(&lost, &client));

    client.checkpoints = .{ client.l2[25], client.l2[22] };
    var finder = StartFinder.init(&rollup);
    const state = try run(&finder, &client);
    try testing.expectEqual(@as(u64, 29), state.unsafe_head.block_info.number);
    try testing.expectEqual(@as(u64, 25), state.safe_head.block_info.number);
    try testing.expectEqual(@as(u64, 22), state.finalized_head.block_info.number);

    // A checkpoint the engine does not hold at its number (another branch) is not used.
    var other = client.l2[25];
    other.block_info.hash = .{ .bytes = @splat(0x77) };
    client.checkpoints = .{ other, client.l2[22] };
    client.retained_from = 0;
    var mismatch = StartFinder.init(&rollup);
    const walked = try run(&mismatch, &client);
    try testing.expectEqual(@as(u64, 22), walked.safe_head.block_info.number);
    // A checkpoint behind the engine's label is not used either.
    client.labels = .{ 29, 27, 24 };
    client.checkpoints = .{ client.l2[25], client.l2[22] };
    var behind = StartFinder.init(&rollup);
    const labeled = try run(&behind, &client);
    try testing.expectEqual(@as(u64, 27), labeled.safe_head.block_info.number);
    try testing.expectEqual(@as(u64, 24), labeled.finalized_head.block_info.number);
}

test "sync start: seeded fuzz, the binary search finds the earliest unpruned block" {
    var prng = Prng.init(0x9a7e);
    for (0..300) |_| {
        var rollup: RollupConfig = .{ .seq_window_size = 64 };
        var client = TestClient.init(32, std.math.maxInt(u64));
        rollup.genesis.l2.hash = client.l2[0].block_info.hash;
        const finalized: u32 = @intCast(prng.below(16));
        client.labels = .{ 31, finalized + @as(u32, @intCast(prng.below(8))), finalized };
        client.pruned_below = prng.below(33);
        if (prng.chance(1, 3)) client.unavailable_every = 2 + @as(u32, @intCast(prng.below(4)));
        var finder = StartFinder.init(&rollup);
        const result = run(&finder, &client);
        if (client.pruned_below == 32) {
            try testing.expectError(error.LatestPruned, result);
            continue;
        }
        const state = try result;
        const expected = @max(finalized, client.pruned_below);
        try testing.expectEqual(expected, state.finalized_head.block_info.number);
        try testing.expect(state.safe_head.block_info.number >= expected);
    }
}

test "sync start: seeded fuzz, unavailability does not change the result" {
    var prng = Prng.init(0x53594e43);
    for (0..300) |_| {
        var rollup: RollupConfig = .{ .seq_window_size = 1 + prng.below(6) };
        var client = TestClient.init(32, prng.below(20));
        rollup.genesis.l2.hash = client.l2[0].block_info.hash;
        const finalized: u32 = @intCast(prng.below(8));
        const safe: u32 = finalized + @as(u32, @intCast(prng.below(8)));
        client.labels = .{ 31, safe, finalized };
        var finder = StartFinder.init(&rollup);
        const expected = run(&finder, &client);
        client.unavailable_every = 2 + @as(u32, @intCast(prng.below(4)));
        finder = StartFinder.init(&rollup);
        const got = run(&finder, &client);
        if (expected) |state| {
            try testing.expectEqualDeep(state, try got);
            try testing.expect(state.finalized_head.block_info.number <=
                state.safe_head.block_info.number);
        } else |err| try testing.expectError(err, got);
    }
}

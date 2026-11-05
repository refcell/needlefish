//! Proof request dispatch (base/base `crates/proof/proposer/src/proof_dispatcher.rs`).
//!
//! From its own cursor the dispatcher requests one proof per proposal target up to the
//! finalized head, each chaining from the previous target's canonical root. Unlike
//! base/base it runs at most `in_flight_max` targets ahead of the collector: dispatched
//! but uncollected targets live in a fixed FIFO ring, which the collector consults to tell
//! "not dispatched yet" from "lost by the prover".

const std = @import("std");
const assert = std.debug.assert;

const interfaces = @import("interfaces.zig");
const target = @import("target.zig");

const Chain = interfaces.Chain;
const Prover = interfaces.Prover;
const Hash = interfaces.Hash;
const Address = interfaces.Address;
const Intervals = interfaces.Intervals;
const SyncStatus = interfaces.SyncStatus;
const BlockRef = interfaces.BlockRef;
const ProofRequest = interfaces.ProofRequest;
const RecoveredState = target.RecoveredState;

/// Upper bound of `Config.in_flight_max`, the ring's static capacity.
pub const in_flight_limit = 64;

pub const Config = struct {
    /// Bound into each proof request as the game's `msg.sender`.
    proposer: Address,
    /// Most dispatched, uncollected targets.
    in_flight_max: u32,
};

/// One dispatched target: the range `start_block -> target_block` and its roots.
pub const Dispatched = struct {
    start_block: u64,
    agreed_root: Hash,
    target_block: u64,
    claimed_root: Hash,
};

const Cursor = struct { block: u64, root: Hash };

pub const Dispatcher = struct {
    config: Config,
    chain: Chain,
    prover: Prover,
    cursor: ?Cursor = null,
    ring: [in_flight_limit]Dispatched = undefined,
    ring_head: u32 = 0,
    ring_count: u32 = 0,
    stats: Stats = .{},

    pub const Stats = struct {
        requests: u64 = 0,
        failures: u64 = 0,
        resets: u64 = 0,
    };

    pub fn init(config: Config, chain: Chain, prover: Prover) Dispatcher {
        assert(config.in_flight_max > 0);
        assert(config.in_flight_max <= in_flight_limit);
        return .{ .config = config, .chain = chain, .prover = prover };
    }

    /// Forgets every dispatched target; the next `rebase` restarts from recovered state.
    pub fn clear(dispatcher: *Dispatcher) void {
        dispatcher.cursor = null;
        dispatcher.ring_head = 0;
        dispatcher.ring_count = 0;
        assert(dispatcher.find(0) == null);
    }

    /// Moves the base to newly recovered state. Dispatched work is kept when the state is
    /// on the dispatched path (the cursor itself, or the start of a ring entry with the
    /// same agreed root); otherwise dispatch restarts from the state.
    pub fn rebase(dispatcher: *Dispatcher, state: RecoveredState) void {
        if (dispatcher.cursor) |cursor| {
            const same_cursor = cursor.block == state.l2_block_number and
                std.mem.eql(u8, &cursor.root, &state.output_root);
            const on_path = if (dispatcher.find(state.l2_block_number)) |entry|
                std.mem.eql(u8, &entry.agreed_root, &state.output_root)
            else
                false;
            if (same_cursor or on_path) {
                dispatcher.pop_before(state.l2_block_number);
                return;
            }
        }
        dispatcher.clear();
        dispatcher.stats.resets += 1;
        dispatcher.cursor = .{ .block = state.l2_block_number, .root = state.output_root };
        assert(dispatcher.ring_count == 0);
    }

    /// The dispatched entry for the range starting at `start_block`.
    pub fn find(dispatcher: *const Dispatcher, start_block: u64) ?Dispatched {
        assert(dispatcher.ring_count <= in_flight_limit);
        var index: u32 = 0;
        while (index < dispatcher.ring_count) : (index += 1) {
            const entry = dispatcher.ring[(dispatcher.ring_head + index) % in_flight_limit];
            if (entry.start_block == start_block) return entry;
        }
        return null;
    }

    /// Drops entries for ranges starting before `block` (collected or superseded).
    pub fn pop_before(dispatcher: *Dispatcher, block: u64) void {
        while (dispatcher.ring_count > 0) {
            const entry = dispatcher.ring[dispatcher.ring_head];
            if (entry.start_block >= block) break;
            dispatcher.ring_head = (dispatcher.ring_head + 1) % in_flight_limit;
            dispatcher.ring_count -= 1;
        }
        assert(dispatcher.ring_count == 0 or
            dispatcher.ring[dispatcher.ring_head].start_block >= block);
    }

    pub fn in_flight(dispatcher: *const Dispatcher) u32 {
        assert(dispatcher.ring_count <= dispatcher.config.in_flight_max);
        return dispatcher.ring_count;
    }

    /// Dispatches targets from the cursor up to `finalized_head` while the ring has room.
    /// Any failure stops the tick at the current cursor; it retries on the next tick.
    pub fn tick(dispatcher: *Dispatcher, finalized_head: u64, sync_status: SyncStatus) void {
        var steps: u32 = 0;
        while (steps < dispatcher.config.in_flight_max) : (steps += 1) {
            if (dispatcher.ring_count >= dispatcher.config.in_flight_max) return;
            const cursor = dispatcher.cursor orelse return;
            // Resolved per target: the cadence changes at the Denim activation block.
            const intervals = dispatcher.chain.intervals_for(cursor.block) catch return;
            const target_block = target.next_block(cursor.block, intervals.block_interval) orelse
                return;
            if (target_block > finalized_head) return;
            const request = dispatcher.build_request(
                cursor,
                target_block,
                intervals,
                sync_status,
            ) catch {
                dispatcher.stats.failures += 1;
                return;
            };
            dispatcher.prover.request(&request) catch {
                dispatcher.stats.failures += 1;
                return;
            };
            dispatcher.stats.requests += 1;
            dispatcher.push(.{
                .start_block = cursor.block,
                .agreed_root = cursor.root,
                .target_block = target_block,
                .claimed_root = request.claimed_l2_output_root,
            });
            dispatcher.cursor = .{ .block = target_block, .root = request.claimed_l2_output_root };
        }
        assert(dispatcher.ring_count <= dispatcher.config.in_flight_max);
    }

    fn push(dispatcher: *Dispatcher, entry: Dispatched) void {
        assert(dispatcher.ring_count < dispatcher.config.in_flight_max);
        assert(entry.target_block > entry.start_block);
        const tail = (dispatcher.ring_head + dispatcher.ring_count) % in_flight_limit;
        dispatcher.ring[tail] = entry;
        dispatcher.ring_count += 1;
    }

    fn build_request(
        dispatcher: *Dispatcher,
        cursor: Cursor,
        target_block: u64,
        intervals: Intervals,
        sync_status: SyncStatus,
    ) error{ Unavailable, BlockNotFound, TargetNotFinalized }!ProofRequest {
        const l1_head = try select_l1_head(target_block, sync_status);
        const claimed = try dispatcher.chain.output_at_block(target_block);
        const agreed = try dispatcher.chain.output_at_block(cursor.block);
        // The agreed root is the cursor's (recovered or previously claimed) root; a
        // diverging canonical root means the cursor is stale.
        if (!std.mem.eql(u8, &agreed.output_root, &cursor.root)) return error.Unavailable;
        return .{
            .l1_head = l1_head,
            .agreed_l2_head_hash = agreed.block.hash,
            .agreed_l2_output_root = cursor.root,
            .agreed_l2_block_number = cursor.block,
            .claimed_l2_output_root = claimed.output_root,
            .claimed_l2_block_number = target_block,
            .intermediate_block_interval = intervals.intermediate_block_interval,
            .proposer = dispatcher.config.proposer,
        };
    }
};

/// The L1 head a proof for `target_block` derives from: the finalized L1 head, valid only
/// for targets at or below the finalized L2 head.
pub fn select_l1_head(
    target_block: u64,
    sync_status: SyncStatus,
) error{TargetNotFinalized}!BlockRef {
    if (target_block > sync_status.finalized_l2.number) return error.TargetNotFinalized;
    assert(target_block <= sync_status.finalized_l2.number);
    return sync_status.finalized_l1;
}

const testing = std.testing;

test "proposer dispatcher: l1 head selection requires a finalized target" {
    const ref: BlockRef = .{ .number = 7, .hash = @splat(7) };
    var status: SyncStatus = .{
        .current_l1 = ref,
        .head_l1 = ref,
        .finalized_l1 = .{ .number = 5, .hash = @splat(5) },
        .safe_l2 = ref,
        .finalized_l2 = .{ .number = 100, .hash = @splat(1) },
        .unsafe_l2 = ref,
    };
    try testing.expectEqual(@as(u64, 5), (try select_l1_head(100, status)).number);
    try testing.expectError(error.TargetNotFinalized, select_l1_head(101, status));
    status.finalized_l2.number = 200;
    try testing.expectEqual(@as(u64, 5), (try select_l1_head(101, status)).number);
}

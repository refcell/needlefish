//! Recovers the proposer's onchain state (base/base
//! `crates/proof/proposer/src/proof_recovery.rs`).
//!
//! A deterministic forward walk from the `AnchorStateRegistry` anchor root: for each next
//! expected proposal block, build the game key from canonical roots and look it up in the
//! factory, following matching games regardless of proposer. The walk stops at the first
//! missing game, a block the rollup node lacks, the finalized head, or `walk_steps_max`
//! (it then resumes from the cache on the next tick). A `{game_count, state}` cache skips
//! the walk while nothing changed.

const std = @import("std");
const assert = std.debug.assert;

const factory = @import("../contracts/dispute_game_factory.zig");
const interfaces = @import("interfaces.zig");
const target = @import("target.zig");

const Chain = interfaces.Chain;
const ChainError = interfaces.ChainError;
const Hash = interfaces.Hash;
const Address = interfaces.Address;
const Intervals = interfaces.Intervals;
const SyncStatus = interfaces.SyncStatus;
const RecoveredState = target.RecoveredState;

pub const roots_max = factory.intermediate_roots_max;
pub const extra_data_bytes_max = factory.extra_data_bytes_max;

pub const Config = struct {
    game_type: u32,
    /// Parent sentinel for the first game after an anchor without a game. Non-zero.
    anchor_state_registry: Address,
    /// Most games one walk follows before yielding to the next tick.
    walk_steps_max: u32 = 256,
};

/// The result of the last successful walk.
pub const Cache = struct {
    game_count: u64,
    state: RecoveredState,
};

pub const Plan = struct {
    state: RecoveredState,
    finalized_head: u64,
    sync_status: SyncStatus,
};

/// Scratch for one game key: checkpoint blocks, their canonical roots, the packed key.
pub const KeyScratch = struct {
    blocks: [roots_max]u64 = undefined,
    roots: [roots_max]Hash = undefined,
    extra_data: [extra_data_bytes_max]u8 = undefined,
};

/// Builds the `games()` key of the canonical game after `state` from the rollup node's
/// roots. `BlockNotFound` means the node has not reached a checkpoint yet.
pub fn canonical_key(
    chain: Chain,
    scratch: *KeyScratch,
    state: RecoveredState,
    intervals: Intervals,
) ChainError!factory.LookupKey {
    const start = state.l2_block_number;
    const blocks = intervals.intermediate_block_numbers(&scratch.blocks, start) catch
        return error.Unavailable;
    assert(blocks.len <= roots_max);
    for (blocks, scratch.roots[0..blocks.len]) |block, *root| {
        root.* = (try chain.output_at_block(block)).output_root;
    }
    const key = factory.lookup_key(
        &scratch.extra_data,
        state.l2_block_number,
        state.parent,
        intervals.block_interval,
        intervals.intermediate_block_interval,
        scratch.roots[0..blocks.len],
    ) catch return error.Unavailable;
    assert(key.target_block == blocks[blocks.len - 1]);
    return key;
}

pub const Recovery = struct {
    config: Config,
    chain: Chain,
    scratch: KeyScratch = .{},
    stats: Stats = .{},

    pub const Stats = struct {
        walks: u64 = 0,
        cache_hits: u64 = 0,
        failures: u64 = 0,
    };

    pub fn init(config: Config, chain: Chain) Recovery {
        assert(!std.mem.allEqual(u8, &config.anchor_state_registry, 0));
        assert(config.walk_steps_max > 0);
        return .{ .config = config, .chain = chain };
    }

    /// Recovers onchain state and reads the finalized head. Null when a step fails; the
    /// caller retries on the next tick.
    pub fn try_recover_and_plan(recovery: *Recovery, cache: *?Cache) ?Plan {
        const sync_status = recovery.chain.sync_status() catch {
            recovery.stats.failures += 1;
            return null;
        };
        const finalized_head = sync_status.finalized_l2.number;
        if (cache.*) |cached| {
            const intervals = recovery.chain.intervals_for(cached.state.l2_block_number) catch {
                recovery.stats.failures += 1;
                return null;
            };
            const block = cached.state.l2_block_number;
            const next = target.next_block(block, intervals.block_interval) orelse return null;
            if (finalized_head < next) {
                recovery.stats.cache_hits += 1;
                return .{
                    .state = cached.state,
                    .finalized_head = finalized_head,
                    .sync_status = sync_status,
                };
            }
        }
        const state = recovery.recover_latest_state(cache, finalized_head) catch {
            recovery.stats.failures += 1;
            return null;
        };
        assert(cache.* != null);
        return .{ .state = state, .finalized_head = finalized_head, .sync_status = sync_status };
    }

    /// The latest state by a forward walk bounded by `finalized_head`, resuming from the
    /// cached tip when the anchor has not passed it and the game count did not decrease.
    pub fn recover_latest_state(
        recovery: *Recovery,
        cache: *?Cache,
        finalized_head: u64,
    ) ChainError!RecoveredState {
        const count = try recovery.chain.game_count();
        const snapshot = try recovery.chain.anchor_snapshot();
        const anchor = snapshot.root;
        var usable: ?Cache = null;
        if (cache.*) |cached| {
            if (anchor.l2_block_number <= cached.state.l2_block_number) usable = cached;
        }
        if (usable) |cached| {
            if (cached.game_count == count) {
                // Trust the cache only when finalized has not advanced far enough to admit
                // the next, possibly already existing, game.
                const block = cached.state.l2_block_number;
                const intervals = try recovery.chain.intervals_for(block);
                const next = target.next_block(block, intervals.block_interval);
                if (next == null or next.? > finalized_head) {
                    recovery.stats.cache_hits += 1;
                    return cached.state;
                }
            }
        }
        var start: RecoveredState = .{
            .parent = if (std.mem.allEqual(u8, &snapshot.game, 0))
                recovery.config.anchor_state_registry
            else
                snapshot.game,
            .output_root = anchor.root,
            .l2_block_number = anchor.l2_block_number,
        };
        if (usable) |cached| {
            if (count >= cached.game_count) start = cached.state;
        }
        const state = try recovery.forward_walk(start, finalized_head);
        assert(state.l2_block_number >= start.l2_block_number);
        cache.* = .{ .game_count = count, .state = state };
        return state;
    }

    fn forward_walk(
        recovery: *Recovery,
        start: RecoveredState,
        finalized_head: u64,
    ) ChainError!RecoveredState {
        recovery.stats.walks += 1;
        var state = start;
        var steps: u32 = 0;
        while (steps < recovery.config.walk_steps_max) : (steps += 1) {
            // Resolved per step so the walk crosses the Denim cadence boundary.
            const intervals = try recovery.chain.intervals_for(state.l2_block_number);
            const block = state.l2_block_number;
            const expected = target.next_block(block, intervals.block_interval) orelse break;
            if (expected > finalized_head) break;
            const chain = recovery.chain;
            const key = canonical_key(chain, &recovery.scratch, state, intervals) catch |err| {
                switch (err) {
                    error.BlockNotFound => break,
                    error.Unavailable => return err,
                }
            };
            const game = try recovery.chain.game_lookup(
                recovery.config.game_type,
                key.root_claim,
                key.extra_data,
            ) orelse break;
            state = .{ .parent = game, .output_root = key.root_claim, .l2_block_number = expected };
        }
        assert(steps <= recovery.config.walk_steps_max);
        return state;
    }
};

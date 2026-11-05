//! Anchor updater (base/base `crates/proof/challenge/src/anchor.rs`): finds the game that
//! extends the current anchor (recomputing its intermediate roots from L2 headers to build
//! the factory lookup key), waits until it resolved `DEFENDER_WINS` and is finalized in its
//! `AnchorStateRegistry`, and then calls `setAnchorState(game)`. The scanner starts after
//! the anchor, so this keeps the scan window short.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const contracts = @import("../contracts/root.zig");
const validator = @import("validator.zig");

const Address = chain.Address;
const Hash = chain.Hash;
const factory = contracts.dispute_game_factory;

pub const Stats = struct {
    updates_sent: u64 = 0,
    updates_mined: u64 = 0,
    skipped: u64 = 0,
    tx_failures: u64 = 0,
    read_errors: u64 = 0,
};

pub const AnchorUpdater = struct {
    game_type: u32,
    anchor_state_registry: Address,
    cached_next_game: ?struct { anchor: chain.AnchorSnapshot, game: Address } = null,
    pending: ?chain.Ticket = null,
    stats: Stats = .{},
    blocks: [factory.intermediate_roots_max]u64 = undefined,
    roots: [factory.intermediate_roots_max]Hash = undefined,
    extra_data: [factory.extra_data_bytes_max]u8 = undefined,

    pub fn init(game_type: u32, anchor_state_registry: Address) AnchorUpdater {
        assert(!chain.is_zero(anchor_state_registry));
        return .{ .game_type = game_type, .anchor_state_registry = anchor_state_registry };
    }

    pub fn poll(updater: *AnchorUpdater, world: chain.World, now_ns: u64) void {
        _ = now_ns;
        if (updater.pending) |ticket| {
            switch (world.submitter.status(ticket)) {
                .pending => return,
                .mined => {
                    updater.stats.updates_mined += 1;
                    updater.cached_next_game = null;
                },
                .failed => updater.stats.tx_failures += 1,
            }
            updater.pending = null;
            return;
        }
        const anchor = world.chain.anchor_snapshot() catch return updater.read_failed();
        const game = updater.cached_game(anchor) orelse game: {
            updater.cached_next_game = null;
            const found = updater.next_game(world.chain, anchor) orelse return;
            updater.cached_next_game = .{ .anchor = anchor, .game = found };
            break :game found;
        };
        const state = world.chain.game_state(game) catch return updater.read_failed();
        switch (state.status) {
            .defender_wins => {},
            .in_progress => return,
            .challenger_wins => {
                updater.cached_next_game = null;
                return;
            },
        }
        updater.try_update(world, game);
        assert(updater.cached_next_game != null);
    }

    fn cached_game(updater: *const AnchorUpdater, anchor: chain.AnchorSnapshot) ?Address {
        const cached = updater.cached_next_game orelse return null;
        return if (cached.anchor.eql(anchor)) cached.game else null;
    }

    fn read_failed(updater: *AnchorUpdater) void {
        updater.stats.read_errors += 1;
    }

    /// The factory game proposing the honest roots that extend `anchor`, if it exists.
    pub fn next_game(updater: *AnchorUpdater, view: chain.ChainView, anchor: chain.AnchorSnapshot) ?Address {
        const start = anchor.anchor_root.l2_block_number;
        const raw_intervals = view.implementation_intervals(updater.game_type, start) catch
            return null;
        const intervals = contracts.aggregate_verifier.check_intervals(raw_intervals) catch
            return null;
        const blocks = factory.lookup_blocks(
            &updater.blocks,
            start,
            intervals.block,
            intervals.intermediate_block,
        ) catch return null;
        for (blocks, updater.roots[0..blocks.len]) |block, *root| {
            // An unavailable block means the next game cannot exist yet.
            root.* = validator.compute_output_root(view, block) catch return null;
        }
        const parent = if (chain.is_zero(anchor.anchor_game))
            updater.anchor_state_registry
        else
            anchor.anchor_game;
        const key = factory.lookup_key(
            &updater.extra_data,
            start,
            parent,
            intervals.block,
            intervals.intermediate_block,
            updater.roots[0..blocks.len],
        ) catch return null;
        assert(key.target_block > start);
        const found = view.factory_game(updater.game_type, key.root_claim, key.extra_data) catch
            return null;
        return found;
    }

    fn try_update(updater: *AnchorUpdater, world: chain.World, game: Address) void {
        const view = world.chain;
        const registry = view.anchor_registry_of(game) catch return updater.read_failed();
        const finalized = view.is_game_finalized(registry, game) catch return updater.read_failed();
        if (!finalized) return;
        const preflight = view.anchor_preflight(registry, game) catch return updater.read_failed();
        if (preflight.permanently_ineligible()) {
            updater.stats.skipped += 1;
            return;
        }
        if (preflight.paused or !preflight.respected) return;
        const info = view.game_info(game) catch return updater.read_failed();
        if (info.l2_block_number <= preflight.anchor_root.l2_block_number) {
            updater.stats.skipped += 1;
            return;
        }
        var buffer: [64]u8 = undefined;
        // 36 bytes: selector and one address.
        const calldata = contracts.anchor_state_registry.encode_set_anchor_state(&buffer, game) catch
            unreachable;
        updater.stats.updates_sent += 1;
        switch (world.submitter.send(.{ .to = registry, .calldata = calldata })) {
            .queued => |ticket| updater.pending = ticket,
            .rejected => updater.stats.tx_failures += 1,
        }
        assert(updater.pending == null or updater.stats.updates_sent > 0);
    }
};

test {
    _ = @import("anchor_test.zig");
}

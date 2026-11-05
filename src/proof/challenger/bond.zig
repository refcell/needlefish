//! Bond manager (base/base `crates/proof/challenge/src/bond.rs`): every discovery interval
//! it scans the most recent `lookback` factory games for bonds owed to a claim address
//! (the bond recipient, or the ZK prover of an unresolved game it may win), then advances
//! each one step: `resolve()` once the game is over, `claimCredit()` to unlock the bond in
//! `DelayedWETH`, and `claimCredit()` again to withdraw once the WETH delay has passed.
//!
//! base/base sends each bond transaction and waits for its receipt. Here the transaction
//! is queued and the game is skipped while it is pending, so a step is never sent twice;
//! the next scan sees the new on-chain state. Finality-time metrics are not ported.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const contracts = @import("../contracts/root.zig");

const Address = chain.Address;
const aggregate_verifier = contracts.aggregate_verifier;

pub const claim_addresses_max = 16;
/// Bond transactions in flight.
pub const pending_max = 64;
/// Largest scan window.
pub const lookback_games_max: u64 = 4096;

pub const Step = enum { resolve, unlock, withdraw };

pub const BondAction = struct {
    game: Address,
    step: Step,
    /// The bond recipient and its WETH contract (withdraw only).
    recipient: Address = chain.zero_address,
    delayed_weth: Address = chain.zero_address,
};

pub const Config = struct {
    claim_addresses: []const Address,
    lookback_games: u64,
    discovery_interval_ns: u64,
};

pub const Stats = struct {
    scans: u64 = 0,
    resolves_sent: u64 = 0,
    unlocks_sent: u64 = 0,
    withdrawals_sent: u64 = 0,
    withdrawals_completed: u64 = 0,
    tx_failures: u64 = 0,
    read_errors: u64 = 0,
};

const Pending = struct { game: Address, step: Step, ticket: chain.Ticket };

pub const BondManager = struct {
    claim_addresses: [claim_addresses_max]Address,
    claim_count: u32,
    lookback_games: u64,
    discovery_interval_ns: u64,
    weth_delay_seconds: ?u64 = null,
    last_scan_ns: ?u64 = null,
    pending: [pending_max]Pending = undefined,
    pending_used: [pending_max]bool = @splat(false),
    stats: Stats = .{},

    pub fn init(config: Config) BondManager {
        assert(config.claim_addresses.len <= claim_addresses_max);
        assert(config.lookback_games > 0 and config.lookback_games <= lookback_games_max);
        assert(config.discovery_interval_ns > 0);
        var manager: BondManager = .{
            .claim_addresses = undefined,
            .claim_count = @intCast(config.claim_addresses.len),
            .lookback_games = config.lookback_games,
            .discovery_interval_ns = config.discovery_interval_ns,
        };
        @memcpy(manager.claim_addresses[0..config.claim_addresses.len], config.claim_addresses);
        return manager;
    }

    pub fn is_claim_address(manager: *const BondManager, address: Address) bool {
        for (manager.claim_addresses[0..manager.claim_count]) |claim| {
            if (std.mem.eql(u8, &claim, &address)) return true;
        }
        return false;
    }

    pub fn pending_count(manager: *const BondManager) u32 {
        var count: u32 = 0;
        for (manager.pending_used) |used| count += @intFromBool(used);
        assert(count <= pending_max);
        return count;
    }

    /// Lands finished bond transactions, then scans when the discovery interval passed.
    pub fn discover(manager: *BondManager, world: chain.World, now_ns: u64) chain.ReadError!void {
        if (manager.claim_count == 0) return;
        manager.poll_pending(world.submitter);
        if (manager.last_scan_ns) |last| {
            if (now_ns -| last < manager.discovery_interval_ns) return;
        }
        manager.stats.scans += 1;
        const game_count = try world.chain.game_count();
        var index = game_count -| manager.lookback_games;
        while (index < game_count) : (index += 1) {
            if (manager.pending_count() == pending_max) break;
            const action = manager.evaluate_game(world.chain, index) orelse continue;
            if (manager.has_pending(action.game)) continue;
            manager.process(world, action, now_ns);
        }
        manager.last_scan_ns = now_ns;
        assert(index <= game_count);
    }

    /// The next bond step of the game at `index`, if one is owed to a claim address.
    pub fn evaluate_game(manager: *BondManager, view: chain.ChainView, index: u64) ?BondAction {
        const game = view.game_at_index(index) catch {
            manager.stats.read_errors += 1;
            return null;
        };
        const state = view.bond_state(game.proxy) catch {
            manager.stats.read_errors += 1;
            return null;
        };
        const zk_claims = !chain.is_zero(state.zk_prover) and
            manager.is_claim_address(state.zk_prover);
        if (!manager.is_claim_address(state.bond_recipient) and !zk_claims) return null;
        if (state.resolved_at == 0) {
            return if (state.game_over) .{ .game = game.proxy, .step = .resolve } else null;
        }
        if (!manager.is_claim_address(state.bond_recipient)) return null;
        if (state.bond_claimed) return null;
        if (!state.bond_unlocked) return .{ .game = game.proxy, .step = .unlock };
        assert(state.resolved_at > 0);
        return .{
            .game = game.proxy,
            .step = .withdraw,
            .recipient = state.bond_recipient,
            .delayed_weth = state.delayed_weth,
        };
    }

    fn process(manager: *BondManager, world: chain.World, action: BondAction, now_ns: u64) void {
        if (action.step == .withdraw) {
            const ready = manager.withdraw_ready(world.chain, action, now_ns) catch {
                manager.stats.read_errors += 1;
                return;
            };
            if (!ready) return;
        }
        var buffer: [4]u8 = undefined;
        const function = if (action.step == .resolve)
            aggregate_verifier.resolve
        else
            aggregate_verifier.claim_credit;
        // Four bytes always fit a selector-only call.
        const calldata = aggregate_verifier.encode_getter(&buffer, function) catch unreachable;
        switch (world.submitter.send(.{ .to = action.game, .calldata = calldata })) {
            .queued => |ticket| manager.add_pending(action.game, action.step, ticket),
            .rejected => manager.stats.tx_failures += 1,
        }
        switch (action.step) {
            .resolve => manager.stats.resolves_sent += 1,
            .unlock => manager.stats.unlocks_sent += 1,
            .withdraw => manager.stats.withdrawals_sent += 1,
        }
    }

    /// Whether the `DelayedWETH` withdrawal delay of an unlocked bond has passed.
    fn withdraw_ready(
        manager: *BondManager,
        view: chain.ChainView,
        action: BondAction,
        now_ns: u64,
    ) chain.ReadError!bool {
        assert(action.step == .withdraw);
        const delay = manager.weth_delay_seconds orelse delay: {
            const delay = try view.weth_delay_seconds(action.delayed_weth);
            manager.weth_delay_seconds = delay;
            break :delay delay;
        };
        const withdrawal = try view.withdrawal(action.delayed_weth, action.game, action.recipient);
        // Unlocked without a withdrawal record: nothing to withdraw yet.
        const ready_at = contracts.delayed_weth.claimable_at(withdrawal, delay) orelse return false;
        return now_ns / std.time.ns_per_s >= ready_at;
    }

    fn poll_pending(manager: *BondManager, submitter: chain.Submitter) void {
        for (&manager.pending, &manager.pending_used) |*pending, *used| {
            if (!used.*) continue;
            switch (submitter.status(pending.ticket)) {
                .pending => continue,
                .mined => if (pending.step == .withdraw) {
                    manager.stats.withdrawals_completed += 1;
                },
                .failed => manager.stats.tx_failures += 1,
            }
            used.* = false;
        }
    }

    fn has_pending(manager: *const BondManager, game: Address) bool {
        for (manager.pending, manager.pending_used) |pending, used| {
            if (used and std.mem.eql(u8, &pending.game, &game)) return true;
        }
        return false;
    }

    fn add_pending(manager: *BondManager, game: Address, step: Step, ticket: chain.Ticket) void {
        assert(!manager.has_pending(game));
        const index = std.mem.indexOfScalar(bool, &manager.pending_used, false).?;
        manager.pending[index] = .{ .game = game, .step = step, .ticket = ticket };
        manager.pending_used[index] = true;
        assert(manager.has_pending(game));
    }
};

test {
    _ = @import("bond_test.zig");
}

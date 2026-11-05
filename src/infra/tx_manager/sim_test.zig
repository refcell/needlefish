//! Deterministic simulation of the transaction manager against a fake L1.
//!
//! The fake L1 keeps one mempool entry per nonce with geth's replacement rule, mines
//! consecutive nonces whose fee cap covers a drifting base fee, and injects faults:
//! failed RPC calls, mempool drops, and reorgs shallower than the confirmation depth
//! that either return transactions to the pool or lose them. Invariants checked:
//! a confirmed send's version is canonical at the reported block and stays there, no two
//! sends confirm the same nonce, and after the faults stop every send drains.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const manager_module = @import("manager.zig");
const fees = @import("fees.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = manager_module.Hash;
const Fees = manager_module.Fees;
const Action = manager_module.Action;
const PublishError = manager_module.PublishError;
const Manager = manager_module.Manager(.{ .sends_max = 8, .hashes_max = 8 });

const nonces_max = 1024;
const gwei = manager_module.gwei;

const FakeL1 = struct {
    prng: *Prng,
    faults: bool = true,
    head: u64 = 0,
    /// Blocks at or below this are never reorged out: the deepest block any send may have
    /// been confirmed at (confirmation depth 3).
    safe_block: u64 = 0,
    /// Next nonce to mine; every lower nonce is mined.
    account_nonce: u64 = 0,
    base_fee_wei: u128 = 10 * gwei,
    pool: [nonces_max]?PoolTx = @splat(null),
    mined: [nonces_max]?Mined = @splat(null),

    const PoolTx = struct { hash: Hash, fees: Fees };
    const Mined = struct { hash: Hash, fees: Fees, block_number: u64 };

    fn fault(l1: *FakeL1, percent: u64) bool {
        return l1.faults and l1.prng.chance(percent, 100);
    }

    fn suggestion(l1: *const FakeL1) manager_module.Suggestion {
        return .{ .tip_wei = 1 * gwei, .base_fee_wei = l1.base_fee_wei };
    }

    fn publish(l1: *FakeL1, version: Action.Publish, hash: Hash) ?PublishError {
        if (l1.fault(5)) return .rpc;
        if (version.nonce < l1.account_nonce) return .nonce_too_low;
        if (version.nonce >= l1.account_nonce + 32) return .nonce_too_high;
        assert(version.nonce < nonces_max);
        if (l1.pool[version.nonce]) |old| {
            if (std.mem.eql(u8, &old.hash, &hash)) return .already_known;
            const tip_ok = version.fees.tip_wei >= fees.threshold(old.fees.tip_wei, false);
            const cap_ok = version.fees.fee_cap_wei >= fees.threshold(old.fees.fee_cap_wei, false);
            if (!tip_ok or !cap_ok) return .replacement_underpriced;
        }
        l1.pool[version.nonce] = .{ .hash = hash, .fees = version.fees };
        return null;
    }

    fn mine(l1: *FakeL1) void {
        l1.head += 1;
        l1.safe_block = @max(l1.safe_block, l1.head -| 2);
        var included: u32 = 0;
        while (included < 4 and l1.account_nonce < nonces_max) : (included += 1) {
            const tx = l1.pool[l1.account_nonce] orelse break;
            if (tx.fees.fee_cap_wei < l1.base_fee_wei) break;
            l1.mined[l1.account_nonce] = .{
                .hash = tx.hash,
                .fees = tx.fees,
                .block_number = l1.head,
            };
            l1.pool[l1.account_nonce] = null;
            l1.account_nonce += 1;
        }
        // Base fee drifts by up to 12.5% per block, as EIP-1559 allows.
        const step: u64 = @intCast(@min(l1.base_fee_wei / 8, 1 << 60));
        if (l1.prng.chance(1, 2)) {
            l1.base_fee_wei +|= l1.prng.below(step + 1);
        } else {
            l1.base_fee_wei -|= l1.prng.below(step + 1);
            l1.base_fee_wei = @max(l1.base_fee_wei, 1 * gwei);
        }
    }

    fn drop_random(l1: *FakeL1) void {
        const nonce = l1.account_nonce + l1.prng.below(16);
        if (nonce < nonces_max) l1.pool[nonce] = null;
    }

    fn reorg(l1: *FakeL1, depth_wanted: u64) void {
        const depth = @min(depth_wanted, l1.head - l1.safe_block);
        const fork_block = l1.head - depth;
        assert(fork_block >= l1.safe_block);
        while (l1.account_nonce > 0) {
            const nonce = l1.account_nonce - 1;
            const tx = l1.mined[nonce].?;
            if (tx.block_number <= fork_block) break;
            l1.mined[nonce] = null;
            l1.account_nonce = nonce;
            // A reorged-out transaction either returns to the pool or is lost.
            l1.pool[nonce] = if (l1.prng.chance(1, 2))
                null
            else
                .{ .hash = tx.hash, .fees = tx.fees };
        }
        l1.head = fork_block;
    }

    fn receipt(l1: *const FakeL1, hash: Hash) manager_module.ReceiptStatus {
        for (l1.mined[0..l1.account_nonce]) |entry| {
            const tx = entry.?;
            if (!std.mem.eql(u8, &tx.hash, &hash)) continue;
            return .{ .mined = .{ .block_number = tx.block_number, .tip_number = l1.head } };
        }
        return .not_found;
    }
};

fn version_hash(version: Action.Publish) Hash {
    var hash: Hash = @splat(0);
    std.mem.writeInt(u64, hash[0..8], version.id, .little);
    std.mem.writeInt(u64, hash[8..16], version.nonce, .little);
    std.mem.writeInt(u128, hash[16..32], version.fees.tip_wei, .little);
    return hash;
}

const Harness = struct {
    manager: Manager,
    l1: FakeL1,
    now_ms: u64 = 0,
    submitted: u64 = 0,
    confirmed: u64 = 0,
    failed: u64 = 0,
    bumps: u64 = 0,
    confirmed_by_nonce: [nonces_max]?Hash = @splat(null),

    fn drive(harness: *Harness) void {
        var budget: u32 = 256;
        while (budget > 0) : (budget -= 1) {
            const suggestion = harness.l1.suggestion();
            const action = harness.manager.next_action(harness.now_ms, suggestion) orelse break;
            switch (action) {
                .fetch_nonce => |fetch| {
                    const value: ?u64 = if (harness.l1.fault(5)) null else harness.l1.account_nonce;
                    harness.manager.on_chain_nonce(fetch.generation, value);
                },
                .publish => |version| {
                    const hash = version_hash(version);
                    const result = harness.l1.publish(version, hash);
                    harness.manager.on_publish(version.id, hash, result, harness.now_ms);
                },
                .query_receipt => |query| {
                    const status: manager_module.ReceiptStatus = if (harness.l1.fault(5))
                        .not_found
                    else
                        harness.l1.receipt(query.hash);
                    harness.manager.on_receipt(query.id, query.hash, status);
                },
            }
        }
        assert(budget > 0);
    }

    fn collect(harness: *Harness) !void {
        while (harness.manager.take_completion()) |completion| {
            harness.bumps += completion.bump_count;
            switch (completion.outcome) {
                .confirmed => |confirmed| {
                    const mined = harness.l1.mined[completion.nonce].?;
                    try testing.expectEqualSlices(u8, &mined.hash, &confirmed.hash);
                    try testing.expectEqual(mined.block_number, confirmed.block_number);
                    try testing.expect(harness.confirmed_by_nonce[completion.nonce] == null);
                    harness.confirmed_by_nonce[completion.nonce] = confirmed.hash;
                    harness.confirmed += 1;
                },
                .failed => harness.failed += 1,
            }
        }
    }

    fn submit(harness: *Harness, is_blob: bool) void {
        if (!harness.manager.has_capacity()) return;
        const suggestion = harness.l1.suggestion();
        _ = harness.manager.submit(harness.now_ms, suggestion, is_blob) catch return;
        harness.submitted += 1;
    }

    fn step(harness: *Harness, prng: *Prng) !void {
        harness.now_ms += 1_000;
        if (prng.chance(1, 2)) harness.submit(false);
        if (prng.chance(1, 2)) harness.l1.mine();
        if (harness.l1.fault(5)) harness.l1.drop_random();
        if (harness.l1.fault(3) and harness.l1.head > 3) harness.l1.reorg(1 + prng.below(2));
        harness.drive();
        try harness.collect();
    }
};

const sim_config: manager_module.Config = .{
    .num_confirmations = 3,
    .resubmission_timeout_ms = 4_000,
    .receipt_query_interval_ms = 2_000,
    .publish_retry_delay_ms = 1_000,
    .tx_not_in_mempool_timeout_ms = 30_000,
};

const Stats = struct { confirmed: u64, failed: u64, bumps: u64 };

fn run(seed: u64, steps: u32) !Stats {
    var prng = Prng.init(seed);
    var harness: Harness = .{
        .manager = try Manager.init(sim_config),
        .l1 = .{ .prng = &prng },
    };
    for (0..steps) |_| try harness.step(&prng);
    // Faults stop: the stream must keep confirming and then drain completely.
    harness.l1.faults = false;
    const confirmed_before = harness.confirmed;
    for (0..60) |_| {
        harness.now_ms += 1_000;
        harness.submit(false);
        harness.l1.mine();
        harness.drive();
        try harness.collect();
    }
    for (0..200) |_| {
        if (harness.manager.pending_count() == 0) break;
        harness.now_ms += 1_000;
        harness.l1.mine();
        harness.drive();
        try harness.collect();
    }
    try testing.expectEqual(@as(u32, 0), harness.manager.pending_count());
    try testing.expect(harness.confirmed >= confirmed_before + 20);
    try testing.expectEqual(harness.submitted, harness.confirmed + harness.failed);
    // Confirmed versions survived every later (shallow) reorg.
    for (harness.confirmed_by_nonce, 0..) |entry, nonce| {
        const hash = entry orelse continue;
        try testing.expectEqualSlices(u8, &hash, &harness.l1.mined[nonce].?.hash);
    }
    return .{ .confirmed = harness.confirmed, .failed = harness.failed, .bumps = harness.bumps };
}

test "tx_manager sim: faulty L1, seeded" {
    var total: Stats = .{ .confirmed = 0, .failed = 0, .bumps = 0 };
    for (0..40) |seed| {
        const stats = try run(seed, 300);
        total.confirmed += stats.confirmed;
        total.failed += stats.failed;
        total.bumps += stats.bumps;
    }
    // The schedule must exercise replacement and abort paths, not only the happy path.
    try testing.expect(total.bumps > 100);
    try testing.expect(total.failed > 10);
    try testing.expect(total.confirmed > 40 * 50);
}

test "tx_manager sim: happy path confirms in order without bumps" {
    var prng = Prng.init(1);
    var harness: Harness = .{
        .manager = try Manager.init(sim_config),
        .l1 = .{ .prng = &prng, .faults = false },
    };
    for (0..30) |_| {
        harness.now_ms += 1_000;
        harness.submit(false);
        harness.l1.mine();
        harness.drive();
        try harness.collect();
    }
    try testing.expect(harness.confirmed >= 20);
    try testing.expectEqual(@as(u64, 0), harness.failed);
}

test "tx_manager sim: fuzz fault schedules" {
    try testing.fuzz({}, fuzz_run, .{});
}

fn fuzz_run(_: void, smith: *testing.Smith) anyerror!void {
    _ = try run(smith.value(u64), 200);
}

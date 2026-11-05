//! Best-transactions view tests: base/base behaviors, then a model-checked seeded fuzz.

const std = @import("std");
const testing = std.testing;
const best_txs = @import("best_txs.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Tx = best_txs.Tx;
const B256 = best_txs.B256;
const Address = best_txs.Address;
const RejectionCache = best_txs.RejectionCache;
const BestTxs = best_txs.BestTxs;

fn make_tx(sender: u8, nonce: u64, id: u16) Tx {
    var hash: B256 = .zero;
    hash.bytes[0] = sender;
    std.mem.writeInt(u16, hash.bytes[1..3], id, .little);
    std.mem.writeInt(u64, hash.bytes[8..16], nonce, .little);
    var address: Address = .zero;
    address.bytes[19] = sender;
    return .{
        .hash = hash,
        .sender = address,
        .nonce = nonce,
        .tx_type = 2,
        .gas_limit = 21_000,
        .max_fee_per_gas = 10,
        .max_priority_fee_per_gas = 1,
        .raw = &.{},
    };
}

const Fixture = struct {
    cache: RejectionCache,
    best: BestTxs,

    fn init(fixture: *Fixture) !void {
        fixture.cache = try RejectionCache.init(testing.allocator, 8, 1000);
        errdefer fixture.cache.deinit(testing.allocator);
        fixture.best = try BestTxs.init(testing.allocator, &fixture.cache, .{
            .committed_max = 64,
            .invalid_senders_max = 4,
        });
    }

    fn deinit(fixture: *Fixture) void {
        fixture.best.deinit(testing.allocator);
        fixture.cache.deinit(testing.allocator);
    }
};

test "best txs: committed transactions are skipped by later snapshot walks" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const best = &fixture.best;
    const txs = [_]Tx{ make_tx(1, 0, 0), make_tx(2, 0, 0), make_tx(1, 1, 0) };
    const snapshot = [_]*const Tx{ &txs[0], &txs[1], &txs[2] };
    best.refresh(&snapshot);
    try testing.expectEqual(&txs[0], best.next(0).?);
    best.mark_current_committed();
    try testing.expectEqual(&txs[1], best.next(0).?);
    // Not committed (e.g. did not fit the block's gas): offered again next time.
    try testing.expectEqual(&txs[2], best.next(0).?);
    best.mark_current_committed();
    try testing.expectEqual(@as(?*const Tx, null), best.next(0));
    // Next walk: the pool still returns everything.
    best.refresh(&snapshot);
    try testing.expectEqual(&txs[1], best.next(0).?);
    try testing.expectEqual(@as(?*const Tx, null), best.next(0));
    try testing.expect(best.is_committed(txs[0].hash));
    // A new block forgets commitments.
    best.reset_block();
    best.refresh(&snapshot);
    try testing.expectEqual(&txs[0], best.next(0).?);
}

test "best txs: mark_invalid skips the sender's later nonces in this snapshot only" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const best = &fixture.best;
    const txs = [_]Tx{ make_tx(1, 3, 0), make_tx(2, 0, 0), make_tx(1, 4, 0), make_tx(1, 5, 0) };
    const snapshot = [_]*const Tx{ &txs[0], &txs[1], &txs[2], &txs[3] };
    best.refresh(&snapshot);
    const first = best.next(0).?;
    best.mark_invalid(first.sender, first.nonce);
    try testing.expectEqual(&txs[1], best.next(0).?);
    try testing.expectEqual(@as(?*const Tx, null), best.next(0));
    best.refresh(&snapshot);
    try testing.expectEqual(&txs[0], best.next(0).?);
    // mark_invalid without a current transaction is a no-op.
    best.mark_current_committed();
    best.mark_invalid(txs[0].sender, txs[0].nonce);
    try testing.expectEqual(&txs[1], best.next(0).?);
}

test "best txs: rejection cache hits skip the sender and expire after the ttl" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const best = &fixture.best;
    const txs = [_]Tx{ make_tx(1, 0, 0), make_tx(1, 1, 0), make_tx(2, 0, 0) };
    const snapshot = [_]*const Tx{ &txs[0], &txs[1], &txs[2] };
    fixture.cache.mark_rejected(&.{txs[0].hash}, 100);
    best.refresh(&snapshot);
    try testing.expectEqual(&txs[2], best.next(500).?);
    try testing.expectEqual(@as(u64, 1), best.rejection_cache_hits);
    best.refresh(&snapshot);
    try testing.expectEqual(&txs[0], best.next(1100).?); // Expired at 100 + 1000.
}

test "rejection cache: capacity evicts the oldest, re-insert refreshes the ttl" {
    var cache = try RejectionCache.init(testing.allocator, 3, 1000);
    defer cache.deinit(testing.allocator);
    const a = make_tx(1, 0, 0).hash;
    const b = make_tx(2, 0, 0).hash;
    const c = make_tx(3, 0, 0).hash;
    const d = make_tx(4, 0, 0).hash;
    cache.mark_rejected(&.{ a, b, c }, 0);
    try testing.expectEqual(@as(u32, 3), cache.entry_count());
    cache.insert(a, 10); // Full: evicts the oldest slot (`a` itself), then re-inserts.
    try testing.expect(cache.is_rejected(b, 10));
    try testing.expect(cache.is_rejected(a, 10));
    cache.insert(d, 20); // Evicts `b`, the oldest.
    try testing.expect(!cache.is_rejected(b, 20));
    try testing.expect(cache.is_rejected(c, 20));
    try testing.expect(cache.is_rejected(d, 20));
    cache.insert(a, 30); // `a` now has a stale slot; the new one owns the entry.
    cache.insert(b, 40); // Evicts `c`.
    cache.insert(c, 50); // Evicts the stale `a` slot, which must keep the live entry.
    try testing.expect(cache.is_rejected(a, 50));
    try testing.expect(cache.is_rejected(a, 1029));
    try testing.expect(!cache.is_rejected(a, 1030));
}

/// Model: walk the snapshot applying the same rules with linear scans.
const Model = struct {
    committed: [256]B256 = undefined,
    committed_count: u32 = 0,
    invalid: [64]struct { sender: Address, nonce: u64 } = undefined,
    invalid_count: u32 = 0,

    fn is_committed(model: *const Model, hash: B256) bool {
        for (model.committed[0..model.committed_count]) |h| if (h.eql(hash)) return true;
        return false;
    }

    fn invalid_nonce(model: *const Model, sender: Address) ?u64 {
        for (model.invalid[0..model.invalid_count]) |entry| {
            if (entry.sender.eql(sender)) return entry.nonce;
        }
        return null;
    }

    fn mark_invalid(model: *Model, sender: Address, nonce: u64) void {
        for (model.invalid[0..model.invalid_count]) |*entry| {
            if (entry.sender.eql(sender)) {
                entry.nonce = @min(entry.nonce, nonce);
                return;
            }
        }
        model.invalid[model.invalid_count] = .{ .sender = sender, .nonce = nonce };
        model.invalid_count += 1;
    }

    fn next(model: *Model, snapshot: []const *const Tx, cursor: *usize, cache: anytype) ?*const Tx {
        while (cursor.* < snapshot.len) {
            const tx = snapshot[cursor.*];
            cursor.* += 1;
            if (model.is_committed(tx.hash)) continue;
            if (model.invalid_nonce(tx.sender)) |nonce| if (tx.nonce >= nonce) continue;
            if (cache.contains(tx.hash)) {
                model.mark_invalid(tx.sender, tx.nonce);
                continue;
            }
            return tx;
        }
        return null;
    }
};

const RejectedSet = struct {
    hashes: [32]B256 = undefined,
    count: u32 = 0,

    fn contains(set: *const RejectedSet, hash: B256) bool {
        for (set.hashes[0..set.count]) |h| if (h.eql(hash)) return true;
        return false;
    }
};

fn run_model(seed: u64) !void {
    var prng = Prng.init(seed);
    var cache = try RejectionCache.init(testing.allocator, 64, std.math.maxInt(u64));
    defer cache.deinit(testing.allocator);
    var best = try BestTxs.init(testing.allocator, &cache, .{
        .committed_max = 256,
        .invalid_senders_max = 64,
    });
    defer best.deinit(testing.allocator);
    var txs: [48]Tx = undefined;
    for (&txs, 0..) |*tx, index| {
        tx.* = make_tx(@intCast(prng.below(6)), prng.below(6), @intCast(index));
    }
    var rejected: RejectedSet = .{};
    for (0..prng.below(6)) |_| {
        const hash = txs[prng.below(txs.len)].hash;
        cache.insert(hash, 0);
        if (!rejected.contains(hash)) {
            rejected.hashes[rejected.count] = hash;
            rejected.count += 1;
        }
    }
    var model: Model = .{};
    var snapshot: [48]*const Tx = undefined;
    for (0..prng.range(1, 6)) |_| {
        const length = prng.below(snapshot.len + 1);
        for (snapshot[0..length]) |*slot| slot.* = &txs[prng.below(txs.len)];
        best.refresh(snapshot[0..length]);
        model.invalid_count = 0;
        var cursor: usize = 0;
        for (0..length + 1) |_| {
            const expected = model.next(snapshot[0..length], &cursor, &rejected);
            const actual = best.next(1);
            try testing.expectEqual(expected, actual);
            const tx = actual orelse break;
            switch (prng.below(3)) {
                0 => {
                    best.mark_current_committed();
                    if (!model.is_committed(tx.hash)) {
                        model.committed[model.committed_count] = tx.hash;
                        model.committed_count += 1;
                    }
                },
                1 => {
                    best.mark_invalid(tx.sender, tx.nonce);
                    model.mark_invalid(tx.sender, tx.nonce);
                },
                else => {}, // Did not fit: left for a later walk.
            }
        }
    }
}

test "best txs: seeded fuzz against a model" {
    var prng = Prng.init(0xbe57_7c5);
    for (0..500) |_| try run_model(prng.int(u64));
}

test "best txs: fuzz" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            try run_model(smith.value(u64));
        }
    }.run, .{});
}

test "rejection cache: seeded fuzz against a model" {
    var prng = Prng.init(0x7e1_ec7);
    for (0..100) |_| {
        const capacity: u32 = @intCast(prng.range(1, 8));
        const ttl_ns = prng.range(1, 50);
        var cache = try RejectionCache.init(testing.allocator, capacity, ttl_ns);
        defer cache.deinit(testing.allocator);
        var now_ns: u64 = 0;
        var last_insert: [16]?u64 = @splat(null);
        for (0..200) |_| {
            now_ns += prng.below(5);
            const key = prng.below(last_insert.len);
            const hash = make_tx(@intCast(key), 0, 0).hash;
            if (prng.chance(1, 2)) {
                cache.insert(hash, now_ns);
                last_insert[key] = now_ns;
                // A hash just inserted is always present.
                try testing.expect(cache.is_rejected(hash, now_ns));
            }
            // Never reports an expired or never-inserted hash.
            if (cache.is_rejected(hash, now_ns)) {
                try testing.expect(now_ns - last_insert[key].? < ttl_ns);
            }
            try testing.expect(cache.entry_count() <= capacity);
        }
    }
}

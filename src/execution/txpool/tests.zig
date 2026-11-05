//! Txpool tests: behavior, a full-structure invariant checker, a seeded model-based fuzz
//! against a simple reference, and a coverage-guided fuzz target.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const txpool = @import("root.zig");
const Pool = txpool.Pool;
const Tx = txpool.Tx;
const Address = txpool.Address;
const B256 = txpool.B256;
const Prng = @import("../../testing/prng.zig").Prng;

const small_classes = [_]txpool.slab.Class{
    .{ .size_bytes = 64, .count = 64 },
    .{ .size_bytes = 256, .count = 8 },
};

fn small_config(capacity: u32) txpool.Config {
    return .{
        .tx_capacity = capacity,
        .account_slots_max = 4,
        .slab = .{ .classes = &small_classes },
    };
}

fn address(n: u8) Address {
    var a = Address.zero;
    a.bytes[19] = n;
    return a;
}

var hash_counter: u64 = 0;

fn make_tx(sender: u8, nonce: u64, fee: u128, tip: u128) Tx {
    hash_counter += 1;
    var hash = B256.zero;
    std.mem.writeInt(u64, hash.bytes[0..8], hash_counter, .big);
    return .{
        .hash = hash,
        .sender = address(sender),
        .nonce = nonce,
        .tx_type = 2,
        .gas_limit = 21_000,
        .max_fee_per_gas = fee,
        .max_priority_fee_per_gas = tip,
        .raw = "raw-tx-bytes",
    };
}

const rich: txpool.Account = .{ .nonce = 0, .balance = std.math.maxInt(u128) };

/// Walks every structure and checks it against the documented invariants.
pub fn verify(pool: *const Pool) !void {
    var pending: u32 = 0;
    var queued: u32 = 0;
    var entries: u32 = 0;
    var it = pool.by_sender.iterator();
    while (it.next()) |kv| {
        const sender = &pool.senders[kv.value_ptr.*];
        try testing.expect(sender.address.eql(kv.key_ptr.*));
        try testing.expect(sender.count > 0);
        try testing.expect(sender.count <= pool.config.account_slots_max);
        var expected = sender.account.nonce;
        var spent: u256 = 0;
        var contiguous = true;
        var previous_nonce: ?u64 = null;
        var cursor = sender.head;
        var steps: u32 = 0;
        while (cursor != std.math.maxInt(u32)) : (steps += 1) {
            const entry = &pool.entries[cursor];
            try testing.expect(pool.entry_live[cursor]);
            try testing.expectEqual(kv.value_ptr.*, entry.sender);
            try testing.expectEqual(cursor, pool.by_hash.get(entry.tx.hash).?);
            if (previous_nonce) |p| try testing.expect(entry.tx.nonce > p);
            try testing.expect(entry.tx.nonce >= sender.account.nonce);
            previous_nonce = entry.tx.nonce;
            spent +|= entry.tx.cost();
            contiguous = contiguous and entry.tx.nonce == expected and
                spent <= sender.account.balance;
            expected = entry.tx.nonce + 1;
            try testing.expectEqual(contiguous, entry.pending);
            if (entry.pending) pending += 1 else queued += 1;
            cursor = entry.next;
        }
        try testing.expectEqual(sender.count, steps);
        entries += steps;
    }
    try testing.expectEqual(pool.pending_count, pending);
    try testing.expectEqual(pool.queued_count, queued);
    try testing.expectEqual(entries, pool.by_hash.count());
    try testing.expectEqual(entries, pool.count());
    try testing.expectEqual(pool.bytes.free_count() + entries, 64 + 8);
}

test "txpool: pending, queued, gap fill" {
    var pool = try Pool.init(testing.allocator, small_config(16));
    defer pool.deinit(testing.allocator);
    try testing.expectEqual(txpool.AddOutcome.pending, try pool.add(make_tx(1, 0, 10, 1), rich));
    try testing.expectEqual(txpool.AddOutcome.queued, try pool.add(make_tx(1, 2, 10, 1), rich));
    try testing.expectEqual(@as(u32, 1), pool.queued_count);
    try testing.expectEqual(@as(u64, 1), pool.next_nonce(address(1), 0));
    try testing.expectEqual(txpool.AddOutcome.pending, try pool.add(make_tx(1, 1, 10, 1), rich));
    try testing.expectEqual(@as(u32, 3), pool.pending_count);
    try testing.expectEqual(@as(u64, 3), pool.next_nonce(address(1), 0));
    try verify(&pool);
}

test "txpool: rejections" {
    var pool = try Pool.init(testing.allocator, small_config(16));
    defer pool.deinit(testing.allocator);
    var deposit = make_tx(1, 0, 10, 1);
    deposit.tx_type = txpool.deposit_tx_type;
    try testing.expectError(error.DepositTx, pool.add(deposit, rich));
    try testing.expectError(error.TipAboveFeeCap, pool.add(make_tx(1, 0, 10, 11), rich));
    const account: txpool.Account = .{ .nonce = 5, .balance = 21_000 * 10 };
    try testing.expectError(error.NonceTooLow, pool.add(make_tx(1, 4, 10, 1), account));
    try testing.expectError(error.InsufficientFunds, pool.add(make_tx(1, 5, 11, 1), account));
    var big = make_tx(1, 5, 10, 1);
    big.gas_limit = 31_000_000;
    try testing.expectError(error.GasLimitExceeded, pool.add(big, account));
    const tx = make_tx(1, 5, 10, 1);
    _ = try pool.add(tx, account);
    try testing.expectError(error.AlreadyKnown, pool.add(tx, account));
    var huge = make_tx(1, 6, 10, 1);
    huge.raw = &@as([257]u8, @splat(0));
    try testing.expectError(error.TooLarge, pool.add(huge, rich));
    for (1..4) |n| _ = try pool.add(make_tx(2, n, 10, 1), rich);
    _ = try pool.add(make_tx(2, 0, 10, 1), rich);
    try testing.expectError(error.AccountFull, pool.add(make_tx(2, 9, 10, 1), rich));
    try verify(&pool);
}

test "txpool: replacement needs a 10% bump on fee cap and tip" {
    var pool = try Pool.init(testing.allocator, small_config(16));
    defer pool.deinit(testing.allocator);
    const original = make_tx(1, 0, 100, 10);
    _ = try pool.add(original, rich);
    try testing.expectError(error.ReplacementUnderpriced, pool.add(make_tx(1, 0, 109, 11), rich));
    try testing.expectError(error.ReplacementUnderpriced, pool.add(make_tx(1, 0, 110, 10), rich));
    const better = make_tx(1, 0, 110, 11);
    try testing.expectEqual(txpool.AddOutcome.replaced_pending, try pool.add(better, rich));
    try testing.expect(pool.get(original.hash) == null);
    try testing.expectEqual(@as(u128, 110), pool.get(better.hash).?.max_fee_per_gas);
    try testing.expectEqual(@as(u32, 1), pool.count());
    try verify(&pool);
}

test "txpool: select orders by tip across senders and nonce within" {
    var pool = try Pool.init(testing.allocator, small_config(16));
    defer pool.deinit(testing.allocator);
    _ = try pool.add(make_tx(1, 0, 100, 1), rich);
    _ = try pool.add(make_tx(1, 1, 100, 50), rich);
    _ = try pool.add(make_tx(2, 0, 100, 5), rich);
    _ = try pool.add(make_tx(3, 0, 8, 8), rich); // Cannot pay base fee 10.
    _ = try pool.add(make_tx(4, 1, 100, 99), rich); // Queued.
    var out: [8]*const Tx = undefined;
    const n = pool.select(10, &out);
    try testing.expectEqual(@as(u32, 3), n);
    try testing.expect(out[0].sender.eql(address(2)));
    try testing.expect(out[1].sender.eql(address(1)) and out[1].nonce == 0);
    try testing.expect(out[2].sender.eql(address(1)) and out[2].nonce == 1);
    try testing.expectEqual(@as(u32, 1), pool.select(10, out[0..1]));
}

test "txpool: update_account drops mined and promotes; balance limits pending" {
    var pool = try Pool.init(testing.allocator, small_config(16));
    defer pool.deinit(testing.allocator);
    const poor: txpool.Account = .{ .nonce = 0, .balance = 21_000 * 10 * 2 };
    for (0..3) |n| _ = try pool.add(make_tx(1, n, 10, 1), poor);
    try testing.expectEqual(@as(u32, 2), pool.pending_count);
    try verify(&pool);
    pool.update_account(address(1), .{ .nonce = 2, .balance = 21_000 * 10 });
    try testing.expectEqual(@as(u32, 1), pool.count());
    try testing.expectEqual(@as(u32, 1), pool.pending_count);
    try verify(&pool);
    pool.update_account(address(1), .{ .nonce = 3, .balance = 0 });
    try testing.expectEqual(@as(u32, 0), pool.count());
    try testing.expect(pool.by_sender.count() == 0);
    try verify(&pool);
}

test "txpool: full pool evicts worst tail or rejects" {
    var pool = try Pool.init(testing.allocator, small_config(3));
    defer pool.deinit(testing.allocator);
    _ = try pool.add(make_tx(1, 0, 50, 1), rich);
    _ = try pool.add(make_tx(2, 0, 60, 1), rich);
    _ = try pool.add(make_tx(3, 5, 99, 1), rich); // Queued: evicted first.
    _ = try pool.add(make_tx(4, 0, 10, 1), rich);
    try testing.expect(pool.by_sender.get(address(3)) == null);
    try testing.expectError(error.PoolFull, pool.add(make_tx(5, 0, 10, 1), rich));
    _ = try pool.add(make_tx(5, 0, 11, 1), rich); // Evicts sender 4 (fee 10).
    try testing.expect(pool.by_sender.get(address(4)) == null);
    try verify(&pool);
}

/// One random operation against the pool; used by both fuzzers.
fn random_step(pool: *Pool, accounts: []txpool.Account, choice: u64, a: u64, b: u64) !void {
    const sender: u8 = @intCast(a % accounts.len);
    switch (choice % 8) {
        0...4 => {
            if (b % 7 == 0) accounts[sender].nonce += 1; // Caller saw a newer state.
            const nonce = accounts[sender].nonce + b % 6;
            const fee: u128 = 1 + (b >> 8) % 200;
            const tx = make_tx(sender, nonce, fee, fee / (1 + (a >> 8) % 4));
            _ = pool.add(tx, accounts[sender]) catch {};
        },
        5 => {
            accounts[sender].nonce += b % 3;
            accounts[sender].balance = if (b % 5 == 0) 21_000 * 300 else std.math.maxInt(u128);
            pool.update_account(address(sender), accounts[sender]);
        },
        6 => {
            var out: [16]*const Tx = undefined;
            const n = pool.select(@intCast(b % 100), &out);
            for (out[0..n]) |tx| try testing.expect(pool.is_pending(tx.hash));
        },
        else => {
            var hash = B256.zero;
            std.mem.writeInt(u64, hash.bytes[0..8], hash_counter -| (b % 8), .big);
            _ = pool.remove(hash);
        },
    }
}

test "txpool: seeded fuzz keeps invariants" {
    var prng = Prng.init(0x7001);
    for (0..20) |_| {
        var pool = try Pool.init(testing.allocator, small_config(@intCast(prng.range(1, 24))));
        defer pool.deinit(testing.allocator);
        var accounts: [6]txpool.Account = @splat(rich);
        for (0..400) |_| {
            try random_step(&pool, &accounts, prng.int(u64), prng.int(u64), prng.int(u64));
            try verify(&pool);
        }
    }
}

fn fuzz_pool(_: void, smith: *testing.Smith) anyerror!void {
    var pool = try Pool.init(testing.allocator, small_config(8));
    defer pool.deinit(testing.allocator);
    var accounts: [4]txpool.Account = @splat(rich);
    var steps: u32 = 0;
    while (steps < 256 and !smith.eosWeightedSimple(15, 1)) : (steps += 1) {
        try random_step(&pool, &accounts, smith.value(u64), smith.value(u64), smith.value(u64));
        try verify(&pool);
    }
}

test "txpool: fuzz" {
    try testing.fuzz({}, fuzz_pool, .{});
}

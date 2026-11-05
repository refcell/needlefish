//! Deterministic sender keys (base/base `load-tests/src/workload/key_stream.rs`).
//!
//! Key `index` of seed `seed` is keccak256(domain || seed || index || attempt) read as a
//! big-endian secp256k1 scalar; a zero or out-of-range scalar (probability below 2^-127)
//! moves to the next attempt. The keys are public by construction: anyone with the seed
//! can recompute them, so they are for devnets and load tests only, and never committed.
//! base/base draws keys from a seeded `StdRng`; this derivation is random-access instead,
//! so a sender's key does not depend on how many keys came before it.

const std = @import("std");
const assert = std.debug.assert;
const Secp256k1 = std.crypto.ecc.Secp256k1;

const primitives = @import("../../common/primitives/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");

pub const Account = accounts.Account;

const domain = "needlefish/load-test/key-stream/v1";
/// Each attempt fails with probability below 2^-127; the bound is never reached.
const attempts_max = 16;

/// Private key `index` of `seed`.
pub fn derive_key(seed: u64, index: u32) [32]u8 {
    var preimage: [domain.len + 8 + 4 + 1]u8 = undefined;
    @memcpy(preimage[0..domain.len], domain);
    std.mem.writeInt(u64, preimage[domain.len..][0..8], seed, .big);
    std.mem.writeInt(u32, preimage[domain.len + 8 ..][0..4], index, .big);
    for (0..attempts_max) |attempt| {
        preimage[preimage.len - 1] = @intCast(attempt);
        const key = primitives.keccak256(&preimage).bytes;
        if (std.mem.allEqual(u8, &key, 0)) continue;
        Secp256k1.scalar.rejectNonCanonical(key, .big) catch continue;
        return key;
    }
    unreachable; // 16 consecutive invalid scalars: probability below 2^-2000.
}

/// Account `index` of `seed`.
pub fn derive(seed: u64, index: u32) Account {
    const key = derive_key(seed, index);
    const account: Account = .{ .private_key = key, .address = accounts.address_of(key) };
    assert(!std.mem.allEqual(u8, &account.private_key, 0));
    assert(!std.mem.allEqual(u8, &account.address.bytes, 0));
    return account;
}

/// Sequential view over the keys of one seed, starting at `offset`.
pub const KeyStream = struct {
    seed: u64,
    next_index: u32,
    generated: u32 = 0,

    pub fn init(seed: u64, offset: u32) KeyStream {
        return .{ .seed = seed, .next_index = offset };
    }

    pub fn next(stream: *KeyStream) Account {
        assert(stream.next_index < std.math.maxInt(u32));
        const account = derive(stream.seed, stream.next_index);
        stream.next_index += 1;
        stream.generated += 1;
        assert(stream.generated <= stream.next_index);
        return account;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "key_stream: deterministic, distinct, and offset-consistent" {
    var first = KeyStream.init(42, 0);
    var second = KeyStream.init(42, 0);
    var accounts_seen: [64]Account = undefined;
    for (&accounts_seen) |*account| {
        account.* = first.next();
        const again = second.next();
        try testing.expectEqualSlices(u8, &account.private_key, &again.private_key);
    }
    for (accounts_seen, 0..) |a, i| for (accounts_seen[i + 1 ..]) |b| {
        try testing.expect(!std.mem.eql(u8, &a.address.bytes, &b.address.bytes));
    };
    var offset = KeyStream.init(42, 10);
    const tenth = offset.next();
    try testing.expectEqualSlices(u8, &accounts_seen[10].address.bytes, &tenth.address.bytes);
    const other_seed = derive(43, 0);
    const first_address = &accounts_seen[0].address.bytes;
    try testing.expect(!std.mem.eql(u8, &other_seed.address.bytes, first_address));
}

test "key_stream: pinned first key" {
    // Pins the derivation so a change is deliberate: it would move every funded sender.
    const account = derive(1, 0);
    const expected = primitives.keccak256(domain ++ [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 } ++
        [_]u8{ 0, 0, 0, 0 } ++ [_]u8{0}).bytes;
    try testing.expectEqualSlices(u8, &expected, &account.private_key);
    try testing.expectEqualSlices(u8, &accounts.address_of(expected).bytes, &account.address.bytes);
}

fn check_keys(seed: u64, index: u32) !void {
    const account = derive(seed, index);
    try Secp256k1.scalar.rejectNonCanonical(account.private_key, .big);
    const again = derive(seed, index);
    try testing.expectEqualSlices(u8, &account.address.bytes, &again.address.bytes);
    if (index > 0) {
        const previous = derive(seed, index - 1);
        try testing.expect(!std.mem.eql(u8, &previous.private_key, &account.private_key));
    }
}

test "key_stream: seeded fuzz" {
    var prng = Prng.init(0x6e75);
    for (0..32) |_| try check_keys(prng.int(u64), @intCast(prng.below(1 << 32)));
}

test "key_stream: fuzz" {
    try testing.fuzz({}, fuzz_keys, .{});
}

fn fuzz_keys(_: void, smith: *testing.Smith) anyerror!void {
    try check_keys(smith.value(u64), smith.value(u32));
}

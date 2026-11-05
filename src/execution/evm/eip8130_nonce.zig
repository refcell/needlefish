//! EIP-8130 2D nonce manager storage as the enshrined transaction path drives it:
//! journaled and unmetered (base/base `crates/common/precompiles/src/nonce/storage.rs`,
//! `crates/execution/eip8130/src/validate.rs`).
//!
//! Layout under ERC-7201 `base.nonce_manager`: field 0 `nonces[account][key]` (u64),
//! field 1 `expiringNonceSeen[replayId]` (u64 expiry, ms), field 2 `expiringNonceRing[u32]`
//! (replay id), field 3 `expiringNonceRingPtr` (u32). The ring bounds the replay set: a
//! slot is reclaimed only once its occupant has expired.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const native = @import("native.zig");
const tx_module = @import("eip8130_tx.zig");
const eip8130 = @import("../../common/consensus/eip8130.zig");
const common_primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const State = state_module.State;

pub const address = native.nonce_manager_address;
pub const root = native.nonce_manager_root;
pub const slot_seen_base: u256 = root + 1;
pub const slot_ring_base: u256 = root + 2;
pub const slot_ring_pointer: u256 = root + 3;

/// Replay-ring capacity: entries live at most `expiry_window_ms`, so the ring holds
/// every live entry at the protocol's peak transaction rate.
pub const replay_buffer_capacity: u32 = 300_000;
/// A nonce-free transaction's `valid_before` must fall in `(now_ms, now_ms + window]`.
pub const expiry_window_ms: u64 = 30_000;

pub const StorageError = error{
    ProtocolNonceNotSupported,
    InvalidNonceKey,
    NonceOverflow,
    InvalidExpiringNonceExpiry,
    ExpiringNonceReplay,
    ExpiringNonceSetFull,
};

pub const Error = state_module.Error || StorageError || tx_module.NonceError;

pub fn seen_slot(replay_id: B256) u256 {
    return native.mapping_slot(replay_id, slot_seen_base);
}

pub fn ring_slot(index: u32) u256 {
    var key: [32]u8 = @splat(0);
    std.mem.writeInt(u32, key[28..32], index, .big);
    return native.mapping_slot(key, slot_ring_base);
}

/// Journaled, unmetered view over the nonce manager's storage.
pub const Store = struct {
    state: *State,

    fn load(store: Store, slot: u256) state_module.Error!u256 {
        // Warming read, like base's gas-free journal provider: later calls in the
        // transaction see the account and slot warm.
        const access = try store.state.access(address);
        const slot_access = try store.state.storage_access(access.account, slot);
        return slot_access.slot.present;
    }

    fn write(store: Store, slot: u256, value: u256) state_module.Error!void {
        const account = (try store.state.access(address)).account;
        const access = try store.state.storage_access(account, slot);
        try store.state.storage_write(account, access.slot, value);
        assert(access.slot.present == value);
    }

    /// `__initialize`: the `0xef` marker code on a code-less nonce manager account.
    fn initialize(store: Store) state_module.Error!void {
        const account = try store.state.load(address);
        if (account.info.has_code()) return;
        try store.state.set_code(account, &native.marker_code);
        assert(account.info.has_code());
    }

    pub fn get_nonce(store: Store, account: Address, nonce_key: u256) Error!u64 {
        if (nonce_key == 0) return error.ProtocolNonceNotSupported;
        const value = try store.load(native.nonce_slot(account, nonce_key));
        return @truncate(value);
    }

    pub fn increment_nonce(store: Store, account: Address, nonce_key: u256) Error!u64 {
        if (nonce_key == 0) return error.InvalidNonceKey;
        const current = try store.get_nonce(account, nonce_key);
        const next = std.math.add(u64, current, 1) catch return error.NonceOverflow;
        try store.initialize();
        try store.write(native.nonce_slot(account, nonce_key), next);
        assert(next > current);
        return next;
    }

    pub fn is_expiring_nonce_seen(store: Store, replay_id: B256, now_ms: u64) Error!bool {
        const expiry: u64 = @truncate(try store.load(seen_slot(replay_id)));
        return expiry != 0 and expiry > now_ms;
    }

    /// Records `replay_id` until `valid_before` in the bounded ring. The four correlated
    /// writes revert together on failure.
    pub fn check_and_mark_expiring_nonce(
        store: Store,
        replay_id: B256,
        valid_before: u64,
        now_ms: u64,
    ) Error!void {
        if (valid_before <= now_ms) return error.InvalidExpiringNonceExpiry;
        if (valid_before > now_ms +| expiry_window_ms) return error.InvalidExpiringNonceExpiry;
        if (try store.is_expiring_nonce_seen(replay_id, now_ms)) return error.ExpiringNonceReplay;
        const checkpoint = store.state.checkpoint();
        store.mark(replay_id, valid_before, now_ms) catch |err| {
            store.state.revert(checkpoint);
            return err;
        };
        assert(try store.is_expiring_nonce_seen(replay_id, now_ms));
    }

    fn mark(store: Store, replay_id: B256, valid_before: u64, now_ms: u64) Error!void {
        assert(valid_before > now_ms);
        try store.initialize();
        const pointer: u32 = @truncate(try store.load(slot_ring_pointer));
        const old_word = try store.load(ring_slot(pointer));
        if (old_word != 0) {
            var old_id: B256 = undefined;
            std.mem.writeInt(u256, &old_id, old_word, .big);
            if (try store.is_expiring_nonce_seen(old_id, now_ms)) {
                return error.ExpiringNonceSetFull;
            }
            try store.write(seen_slot(old_id), 0);
        }
        try store.write(ring_slot(pointer), std.mem.readInt(u256, &replay_id, .big));
        try store.write(seen_slot(replay_id), valid_before);
        const incremented = pointer +% 1;
        const next = if (incremented >= replay_buffer_capacity) 0 else incremented;
        assert(next < replay_buffer_capacity);
        try store.write(slot_ring_pointer, next);
    }
};

/// `NonceValidator::validate`: nonce-free (`nonce_key_max`) checks the replay set,
/// protocol key 0 checks the account nonce, any other key its 2D channel.
pub fn validate(
    store: Store,
    tx: *const eip8130.TxEip8130,
    account: Address,
    protocol_nonce: u64,
    mode: tx_module.NonceMode,
    now_ms: u64,
) Error!tx_module.NonceStatus {
    if (tx.nonce_key == eip8130.nonce_key_max) {
        if (tx.nonce_sequence != 0) return error.NonceFreeSequence;
        const replay = tx.replay_id(common_primitives.Address.init(account)).bytes;
        if (try store.is_expiring_nonce_seen(replay, now_ms)) return error.Replay;
        return .ready;
    }
    const channel = if (tx.nonce_key == 0)
        protocol_nonce
    else
        try store.get_nonce(account, tx.nonce_key);
    return tx_module.validate_sequence(tx.nonce_sequence, channel, mode);
}

const testing = std.testing;
const memory_db = @import("memory_db.zig");
const fuzz = @import("../../testing/fuzz.zig");

const Fixture = struct {
    database: memory_db.MemoryDatabase,
    state: State,

    fn init(fixture: *Fixture) !void {
        fixture.database = memory_db.MemoryDatabase.init(testing.allocator);
        const limits = @import("evm_test.zig").test_limits;
        fixture.state = try .init(testing.allocator, fixture.database.interface(), limits);
        fixture.state.begin_transaction();
    }

    fn deinit(fixture: *Fixture) void {
        fixture.state.deinit(testing.allocator);
        fixture.database.deinit();
    }

    fn store(fixture: *Fixture) Store {
        return .{ .state = &fixture.state };
    }
};

const account_a: Address = @splat(0xaa);

test "eip8130 nonce: 2D keys increment and install the marker" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    try testing.expectError(error.ProtocolNonceNotSupported, store.get_nonce(account_a, 0));
    try testing.expectError(error.InvalidNonceKey, store.increment_nonce(account_a, 0));
    try testing.expectEqual(@as(u64, 0), try store.get_nonce(account_a, 7));
    try testing.expectEqual(@as(u64, 1), try store.increment_nonce(account_a, 7));
    try testing.expectEqual(@as(u64, 2), try store.increment_nonce(account_a, 7));
    try testing.expectEqual(@as(u64, 0), try store.get_nonce(account_a, 8));
    const manager = try fixture.state.load(address);
    try testing.expectEqualSlices(u8, &native.marker_code, try fixture.state.code(manager));
    try store.write(native.nonce_slot(account_a, 9), std.math.maxInt(u64));
    try testing.expectError(error.NonceOverflow, store.increment_nonce(account_a, 9));
}

test "eip8130 nonce: expiring nonces reject replays and bad windows" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    const id: B256 = @splat(0x11);
    const now: u64 = 1_000_000;
    try testing.expectError(
        error.InvalidExpiringNonceExpiry,
        store.check_and_mark_expiring_nonce(id, now, now),
    );
    try testing.expectError(
        error.InvalidExpiringNonceExpiry,
        store.check_and_mark_expiring_nonce(id, now + expiry_window_ms + 1, now),
    );
    try store.check_and_mark_expiring_nonce(id, now + expiry_window_ms, now);
    try testing.expect(try store.is_expiring_nonce_seen(id, now));
    try testing.expectError(
        error.ExpiringNonceReplay,
        store.check_and_mark_expiring_nonce(id, now + 10, now + 5),
    );
    // Expired entries no longer count as seen and may be marked again.
    const later = now + expiry_window_ms;
    try testing.expect(!try store.is_expiring_nonce_seen(id, later));
    try store.check_and_mark_expiring_nonce(id, later + 1, later);
    try testing.expectEqual(@as(u256, 2), try store.load(slot_ring_pointer));
}

test "eip8130 nonce: a full ring reverts every write" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    const now: u64 = 50_000;
    const live: B256 = @splat(0x22);
    try store.check_and_mark_expiring_nonce(live, now + 100, now);
    // Wrap the pointer back onto the live entry.
    try store.write(slot_ring_pointer, 0);
    const fresh: B256 = @splat(0x33);
    try testing.expectError(
        error.ExpiringNonceSetFull,
        store.check_and_mark_expiring_nonce(fresh, now + 100, now),
    );
    try testing.expect(!try store.is_expiring_nonce_seen(fresh, now));
    try testing.expectEqual(@as(u256, 0), try store.load(slot_ring_pointer));
    // Once the occupant expires its slot is reclaimed.
    try store.check_and_mark_expiring_nonce(fresh, now + 300, now + 100);
    try testing.expect(!try store.is_expiring_nonce_seen(live, now));
    try testing.expectEqual(@as(u256, 1), try store.load(slot_ring_pointer));
}

test "eip8130 nonce: validate routes protocol, 2D, and nonce-free keys" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    var tx = eip8130.TxEip8130{ .chain_id = 8453 };
    tx.nonce_sequence = 3;
    try testing.expectEqual(.ready, try validate(store, &tx, account_a, 3, .inclusion, 0));
    try testing.expectError(error.TooLow, validate(store, &tx, account_a, 4, .inclusion, 0));
    try testing.expectError(error.TooHigh, validate(store, &tx, account_a, 2, .inclusion, 0));
    tx.nonce_key = 5;
    try testing.expectError(error.TooHigh, validate(store, &tx, account_a, 3, .inclusion, 0));
    const status = try validate(store, &tx, account_a, 0, .pool, 0);
    try testing.expectEqual(@as(u64, 3), status.buffered);
    tx.nonce_key = eip8130.nonce_key_max;
    try testing.expectError(error.NonceFreeSequence, validate(store, &tx, account_a, 0, .pool, 0));
    tx.nonce_sequence = 0;
    try testing.expectEqual(.ready, try validate(store, &tx, account_a, 0, .inclusion, 10));
    const replay = tx.replay_id(common_primitives.Address.init(account_a)).bytes;
    try store.check_and_mark_expiring_nonce(replay, 20, 10);
    try testing.expectError(error.Replay, validate(store, &tx, account_a, 0, .inclusion, 10));
}

test "eip8130 nonce: fuzz the replay ring and 2D keys" {
    try fuzz.run_bytes({}, fuzz_nonce, .{ .seed = 0x8130_0001, .iterations = 128 });
}

/// Each 4-byte step: an operation, a replay id or key byte, and a clock advance. A
/// small id alphabet forces replays; a rejected mark leaves the ring untouched.
fn fuzz_nonce(_: void, input: []const u8) anyerror!void {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    const store = fixture.store();
    var now: u64 = 1_000;
    var steps = std.mem.window(u8, input, 4, 4);
    while (steps.next()) |step| {
        if (step.len < 4) break;
        now += std.mem.readInt(u16, step[2..4], .little);
        const id: B256 = @splat(step[1] & 0x0f);
        if (step[0] & 1 == 0) {
            const before_pointer = try store.load(slot_ring_pointer);
            const valid_before = now + @as(u64, step[1] >> 4) * 4_000;
            store.check_and_mark_expiring_nonce(id, valid_before, now) catch {
                try testing.expectEqual(before_pointer, try store.load(slot_ring_pointer));
                continue;
            };
            try testing.expect(try store.is_expiring_nonce_seen(id, now));
            try testing.expect(try store.load(slot_ring_pointer) < replay_buffer_capacity);
        } else {
            const key: u256 = step[1] >> 4;
            const before = store.get_nonce(account_a, key) catch {
                try testing.expectEqual(@as(u256, 0), key);
                continue;
            };
            try testing.expectEqual(before + 1, try store.increment_nonce(account_a, key));
        }
    }
}

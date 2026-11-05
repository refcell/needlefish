//! EIP-8130 `AccountConfiguration` system-contract storage, mirroring base/base
//! `crates/execution/eip8130/src/account_config.rs`.
//!
//! Plain sequential slots, no ERC-7201 namespace:
//! slot 0 `mapping(bytes32 actorId => mapping(address account => ActorRecord))`, where an
//! `ActorRecord` is the packed `ActorConfig` word followed by the policy manager (offset 1)
//! and policy commitment (offset 2); slot 1 `mapping(address account => AccountState)`.
//!
//! The enshrined 8130 path reads and writes these slots without gas metering, through the
//! journal, so a reverted transaction rolls them back.
const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const eip8130 = @import("../../common/consensus/eip8130.zig");
const keccak256 = @import("../../common/crypto/root.zig").keccak256;

const Address = primitives.Address;
const B256 = primitives.B256;
const State = state_module.State;
pub const Error = state_module.Error;

pub const address: Address = eip8130.contracts.account_config.bytes;
pub const k1_authenticator: Address = eip8130.k1_authenticator.bytes;
const slot_actors: u256 = 0;
const slot_account_state: u256 = 1;
pub const policy_manager_offset: u256 = 1;
pub const policy_commitment_offset: u256 = 2;

/// Packed actor config: authenticator in bytes 12..32, uint48 expiry in bytes 6..12,
/// uint16 scope in bytes 4..6.
pub const ActorConfig = struct {
    authenticator: Address,
    expiry: u64,
    scope: u16,

    pub const empty: ActorConfig = .{ .authenticator = @splat(0), .expiry = 0, .scope = 0 };

    pub fn from_word(value: u256) ActorConfig {
        const bytes = word(value);
        return .{
            .authenticator = bytes[12..32].*,
            .expiry = std.mem.readInt(u48, bytes[6..12], .big),
            .scope = std.mem.readInt(u16, bytes[4..6], .big),
        };
    }

    pub fn to_word(config: ActorConfig) u256 {
        assert(config.expiry >> 48 == 0);
        var bytes: [32]u8 = @splat(0);
        bytes[12..32].* = config.authenticator;
        std.mem.writeInt(u48, bytes[6..12], @intCast(config.expiry), .big);
        std.mem.writeInt(u16, bytes[4..6], config.scope, .big);
        return std.mem.readInt(u256, &bytes, .big);
    }

    pub fn is_empty(config: ActorConfig) bool {
        return std.mem.allEqual(u8, &config.authenticator, 0);
    }

    pub fn is_expired(config: ActorConfig, now: u64) bool {
        return config.expiry != 0 and now > config.expiry;
    }
};

pub const LockStatus = struct {
    locked: bool,
    has_initiated_unlock: bool,
    unlocks_at: u64,
    unlock_delay: u16,

    pub const unlocked: LockStatus = .{
        .locked = false,
        .has_initiated_unlock = false,
        .unlocks_at = 0,
        .unlock_delay = 0,
    };
};

/// Packed account state (bit offsets from the low end): uint64 multichain sequence at 0,
/// uint32 local sequence at 64, uint32 local epoch at 96, uint8 flags at 128, uint48 lock
/// union at 136, uint48 default-EOA expiry at 184, uint16 default-EOA scope at 232.
pub const AccountState = struct {
    multichain_sequence: u64,
    local_sequence: u32,
    local_epoch: u32,
    flags: u8,
    lock_union: u64,
    default_eoa_expiry: u64,
    default_eoa_scope: u16,

    pub const unlocks_at_max: u64 = (1 << 48) - 1;

    pub fn from_word(value: u256) AccountState {
        return .{
            .multichain_sequence = @truncate(value),
            .local_sequence = @truncate(value >> 64),
            .local_epoch = @truncate(value >> 96),
            .flags = @truncate(value >> 128),
            .lock_union = @as(u48, @truncate(value >> 136)),
            .default_eoa_expiry = @as(u48, @truncate(value >> 184)),
            .default_eoa_scope = @truncate(value >> 232),
        };
    }

    pub fn to_word(account_state: AccountState) u256 {
        assert(account_state.lock_union >> 48 == 0);
        assert(account_state.default_eoa_expiry >> 48 == 0);
        return @as(u256, account_state.multichain_sequence) |
            @as(u256, account_state.local_sequence) << 64 |
            @as(u256, account_state.local_epoch) << 96 |
            @as(u256, account_state.flags) << 128 |
            @as(u256, account_state.lock_union) << 136 |
            @as(u256, account_state.default_eoa_expiry) << 184 |
            @as(u256, account_state.default_eoa_scope) << 232;
    }

    pub fn default_eoa_revoked(account_state: AccountState) bool {
        return account_state.flags & eip8130.flag_default_eoa_revoked != 0;
    }

    /// Hard-locked, or a pending unlock whose timestamp has not elapsed.
    pub fn is_locked(account_state: AccountState, now: u64) bool {
        if (account_state.flags & eip8130.flag_locked == 0) return false;
        if (account_state.flags & eip8130.flag_unlock_initiated == 0) return true;
        return now < account_state.lock_union;
    }

    pub fn unlock_floor(account_state: AccountState, now: u64) u64 {
        if (account_state.flags & eip8130.flag_unlock_initiated != 0) {
            return account_state.lock_union;
        }
        return now +| (account_state.lock_union & 0xffff);
    }

    pub fn lock_status(account_state: AccountState, now: u64) LockStatus {
        if (account_state.flags & eip8130.flag_locked == 0) return LockStatus.unlocked;
        if (account_state.flags & eip8130.flag_unlock_initiated == 0) {
            return .{
                .locked = true,
                .has_initiated_unlock = false,
                .unlocks_at = unlocks_at_max,
                .unlock_delay = @truncate(account_state.lock_union),
            };
        }
        return .{
            .locked = now < account_state.lock_union,
            .has_initiated_unlock = true,
            .unlocks_at = account_state.lock_union,
            .unlock_delay = 0,
        };
    }

    pub fn is_initialized(account_state: AccountState) bool {
        return account_state.local_sequence > 0 or account_state.local_epoch > 0 or
            account_state.multichain_sequence > 0;
    }
};

fn word(value: u256) [32]u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return bytes;
}

fn address_word(account: Address) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[12..32].* = account;
    return bytes;
}

/// Solidity mapping slot: keccak256(key ++ base).
pub fn mapping_slot(key: [32]u8, base: u256) u256 {
    var preimage: [64]u8 = undefined;
    preimage[0..32].* = key;
    preimage[32..64].* = word(base);
    const digest = keccak256(&preimage);
    return std.mem.readInt(u256, &digest, .big);
}

/// The account's own actor id: the address left-padded to 32 bytes.
pub fn self_actor_id(account: Address) B256 {
    return address_word(account);
}

pub fn account_state_slot(account: Address) u256 {
    return mapping_slot(address_word(account), slot_account_state);
}

/// keccak256(account ++ keccak256(actorId ++ 0)): the record's config slot.
pub fn actor_record_base(account: Address, actor_id: B256) u256 {
    return mapping_slot(address_word(account), mapping_slot(actor_id, slot_actors));
}

/// Journaled, unmetered view over the AccountConfiguration storage.
pub const Store = struct {
    state: *State,

    fn load(store: Store, slot: u256) Error!u256 {
        return store.state.storage_value(address, slot);
    }

    fn write(store: Store, slot: u256, value: u256) Error!void {
        const account = try store.state.load(address);
        const access = try store.state.storage_access(account, slot);
        try store.state.storage_write(account, access.slot, value);
        assert(access.slot.present == value);
    }

    /// The raw `_actorConfig[actorId][account]` word, without the inline-self blend.
    pub fn actor_config_slot(store: Store, account: Address, actor_id: B256) Error!ActorConfig {
        return ActorConfig.from_word(try store.load(actor_record_base(account, actor_id)));
    }

    pub fn account_state(store: Store, account: Address) Error!AccountState {
        return AccountState.from_word(try store.load(account_state_slot(account)));
    }

    /// `getActorConfig`: an explicit entry wins; the self actor falls back to the live
    /// inline k1 config unless the default EOA is revoked.
    pub fn resolve_actor_config(store: Store, account: Address, actor_id: B256) Error!ActorConfig {
        const stored = try store.actor_config_slot(account, actor_id);
        if (!stored.is_empty()) return stored;
        if (!std.mem.eql(u8, &actor_id, &self_actor_id(account))) return ActorConfig.empty;
        const current = try store.account_state(account);
        return inline_self(current);
    }

    /// `Keystore._resolveActorConfig`: the inline self resolves against the in-memory
    /// batch `current` state, and expired actors read as empty.
    pub fn resolve_live_actor_config(
        store: Store,
        account: Address,
        actor_id: B256,
        current: AccountState,
        now: u64,
    ) Error!ActorConfig {
        const stored = try store.actor_config_slot(account, actor_id);
        var config = stored;
        if (stored.is_empty()) {
            const is_self = std.mem.eql(u8, &actor_id, &self_actor_id(account));
            config = if (is_self) inline_self(current) else ActorConfig.empty;
        }
        return if (config.is_expired(now)) ActorConfig.empty else config;
    }

    /// `isActor`: any resolved config, expired or not.
    pub fn is_actor(store: Store, account: Address, actor_id: B256) Error!bool {
        return !(try store.resolve_actor_config(account, actor_id)).is_empty();
    }

    pub const Policy = struct { manager: Address, commitment: B256 };

    /// The policy gate of a policy-gated sender; ungated actors resolve to zeros.
    pub fn policy(store: Store, account: Address, actor_id: B256) Error!Policy {
        const scope = (try store.resolve_actor_config(account, actor_id)).scope;
        if (!eip8130.sender_is_policy_gated(scope)) {
            return .{ .manager = @splat(0), .commitment = @splat(0) };
        }
        return .{
            .manager = try store.policy_manager(account, actor_id),
            .commitment = try store.policy_commitment(account, actor_id),
        };
    }

    pub fn policy_manager(store: Store, account: Address, actor_id: B256) Error!Address {
        const base = actor_record_base(account, actor_id);
        const value = word(try store.load(base +% policy_manager_offset));
        return value[12..32].*;
    }

    pub fn policy_commitment(store: Store, account: Address, actor_id: B256) Error!B256 {
        const base = actor_record_base(account, actor_id);
        return word(try store.load(base +% policy_commitment_offset));
    }

    pub fn is_locked(store: Store, account: Address, now: u64) Error!bool {
        return (try store.account_state(account)).is_locked(now);
    }

    pub fn set_actor_config(
        store: Store,
        account: Address,
        actor_id: B256,
        config: ActorConfig,
    ) Error!void {
        try store.write(actor_record_base(account, actor_id), config.to_word());
    }

    pub fn clear_actor_config(store: Store, account: Address, actor_id: B256) Error!void {
        try store.set_actor_config(account, actor_id, ActorConfig.empty);
    }

    pub fn set_account_state(store: Store, account: Address, value: AccountState) Error!void {
        try store.write(account_state_slot(account), value.to_word());
    }

    pub fn set_policy(
        store: Store,
        account: Address,
        actor_id: B256,
        manager: Address,
        commitment: B256,
    ) Error!void {
        const base = actor_record_base(account, actor_id);
        const manager_word = std.mem.readInt(u256, &address_word(manager), .big);
        try store.write(base +% policy_manager_offset, manager_word);
        try store.write(base +% policy_commitment_offset, std.mem.readInt(u256, &commitment, .big));
    }

    pub fn clear_policy(store: Store, account: Address, actor_id: B256) Error!void {
        try store.set_policy(account, actor_id, @splat(0), @splat(0));
    }
};

fn inline_self(current: AccountState) ActorConfig {
    if (current.default_eoa_revoked()) return ActorConfig.empty;
    return .{
        .authenticator = k1_authenticator,
        .scope = current.default_eoa_scope,
        .expiry = current.default_eoa_expiry,
    };
}

const testing = std.testing;
const memory_db = @import("memory_db.zig");

test "eip8130 config: actor config and account state words round trip" {
    var prng = std.Random.DefaultPrng.init(0x8130);
    const random = prng.random();
    for (0..256) |_| {
        var config: ActorConfig = undefined;
        random.bytes(&config.authenticator);
        config.expiry = random.int(u48);
        config.scope = random.int(u16);
        const decoded = ActorConfig.from_word(config.to_word());
        try testing.expectEqualDeep(config, decoded);
        const value = random.int(u256) & ~(@as(u256, 0xff) << 248);
        const account_state = AccountState.from_word(value);
        try testing.expectEqual(value, account_state.to_word());
    }
    try testing.expect(ActorConfig.empty.is_empty());
    try testing.expect(!ActorConfig.empty.is_expired(std.math.maxInt(u64)));
}

test "eip8130 config: lock status follows the flags" {
    var account_state = AccountState.from_word(0);
    try testing.expect(!account_state.is_locked(5));
    try testing.expect(!account_state.is_initialized());
    account_state.flags = eip8130.flag_locked;
    account_state.lock_union = 60;
    try testing.expect(account_state.is_locked(5));
    try testing.expectEqual(@as(u64, 65), account_state.unlock_floor(5));
    try testing.expectEqual(AccountState.unlocks_at_max, account_state.lock_status(5).unlocks_at);
    account_state.flags |= eip8130.flag_unlock_initiated;
    account_state.lock_union = 100;
    try testing.expect(account_state.is_locked(99));
    try testing.expect(!account_state.is_locked(100));
    try testing.expectEqual(@as(u64, 100), account_state.unlock_floor(5));
}

test "eip8130 config: the inline k1 self resolves until revoked" {
    var database = memory_db.MemoryDatabase.init(testing.allocator);
    defer database.deinit();
    const limits = @import("evm_test.zig").test_limits;
    var state = try State.init(testing.allocator, database.interface(), limits);
    defer state.deinit(testing.allocator);
    state.begin_transaction();
    const store = Store{ .state = &state };
    const account: Address = @splat(0x42);
    const self_id = self_actor_id(account);
    const resolved = try store.resolve_actor_config(account, self_id);
    try testing.expectEqualSlices(u8, &k1_authenticator, &resolved.authenticator);
    try testing.expect(try store.is_actor(account, self_id));
    const other: B256 = @splat(7);
    try testing.expect(!try store.is_actor(account, other));

    var current = try store.account_state(account);
    current.flags = eip8130.flag_default_eoa_revoked;
    try store.set_account_state(account, current);
    try testing.expect(!try store.is_actor(account, self_id));

    const config = ActorConfig{
        .authenticator = @splat(9),
        .expiry = 10,
        .scope = eip8130.scope_policy,
    };
    try store.set_actor_config(account, other, config);
    try store.set_policy(account, other, @splat(3), @splat(4));
    const gate = try store.policy(account, other);
    try testing.expectEqualSlices(u8, &@as(Address, @splat(3)), &gate.manager);
    const live = try store.resolve_live_actor_config(account, other, current, 11);
    try testing.expect(live.is_empty());
    try store.clear_policy(account, other);
    try testing.expectEqual(@as(u256, 0), try store.load(actor_record_base(account, other) + 2));
}

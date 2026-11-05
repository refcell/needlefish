//! Model-based fuzz of the EIP-8130 config-change apply step
//! (`execution/evm/eip8130_apply.zig`, base/base `crates/execution/eip8130/src/apply.rs`).
//!
//! Each case runs a stream of config-change batches (authorize, revoke, increment epoch,
//! lock/unlock, malformed payloads, stale or skipped sequences) for one unlocked account
//! against the real `AccountConfiguration` storage in an EVM `State`, and checks, after
//! every batch:
//!   - the outcome (error or revoke discount) equals a reference model's;
//!   - every actor's config and policy slots, the in-memory account state, and the emitted
//!     logs (count, event, account, actor) equal the model, including the partial effects
//!     a batch leaves when a later item fails;
//!   - reverting a failed batch to its checkpoint restores the pre-batch storage;
//!   - a successful batch's account state round-trips through its packed storage word.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const eip8130 = @import("../common/consensus/eip8130.zig");
const apply = @import("../execution/evm/eip8130_apply.zig");
const config = @import("../execution/evm/eip8130_config.zig");
const state_module = @import("../execution/evm/state.zig");
const memory_db = @import("../execution/evm/memory_db.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const Address = [20]u8;
const B256 = [32]u8;
const ActorConfig = config.ActorConfig;
const AccountState = config.AccountState;

const actor_count = 4;
const items_max = eip8130.max_actor_changes_per_config;
const batches_max = 24;
const payload_size_max = 192 + 64;

const limits = state_module.Limits{
    .accounts_max = 64,
    .slots_max = 1024,
    .transient_slots_max = 16,
    .journal_entries_max = 1 << 12,
    .logs_max = 64,
    .log_data_bytes_max = 1 << 13,
    .code_bytes_max = 1 << 10,
};

const authenticators = [4]Address{
    @splat(0),
    config.k1_authenticator,
    @splat(0x33),
    @splat(0x44),
};

const event_authorized = topic(
    "7427678b205ea26cd22254b5ebdc924c4bf6f9bb78e436872e49599e97963559",
);
const event_revoked = topic(
    "eb5bd9b1e97c446e28bffcb6963893ca5ad94dc662962fd732ffc03ca279b3e5",
);

fn topic(comptime text: []const u8) B256 {
    @setEvalBranchQuota(10_000);
    var bytes: B256 = undefined;
    _ = std.fmt.hexToBytes(&bytes, text) catch unreachable; // Comptime-known valid hex.
    return bytes;
}

// ------------------------------------------------------------------ plan

const Malformed = enum { none, truncated, dirty_expiry };

const Item = union(enum) {
    authorize: struct {
        actor: u8,
        authenticator: u8,
        expiry: u64,
        scope: u16,
        policy_length: u8,
        policy_fill: u8,
        malformed: Malformed,
    },
    revoke: struct { actor: u8, short: bool },
    epoch: struct { payload: bool },
    lock,
};

const Plan = struct {
    channel: eip8130.Channel,
    sequence: u64,
    now: u64,
    items: [items_max]Item = undefined,
    count: u32 = 0,
};

fn draw_expiry(prng: *Prng, now: u64) u64 {
    return switch (prng.below(4)) {
        0 => 0,
        1 => now -| prng.below(8),
        2 => now + prng.below(8),
        else => (1 << 48) - 1 - prng.below(2),
    };
}

fn draw_item(prng: *Prng, now: u64) Item {
    const pick = prng.below(16);
    if (pick < 8) {
        const policy_lengths = [4]u8{ 0, 52, 52, 51 };
        const malformed_pick = prng.below(16);
        return .{ .authorize = .{
            .actor = @intCast(prng.below(actor_count)),
            .authenticator = @intCast(prng.below(authenticators.len)),
            .expiry = draw_expiry(prng, now),
            .scope = @intCast(prng.below(1 << 16)),
            .policy_length = policy_lengths[prng.below(policy_lengths.len)],
            .policy_fill = @intCast(prng.below(3)),
            .malformed = if (malformed_pick == 0)
                .truncated
            else if (malformed_pick == 1) .dirty_expiry else .none,
        } };
    }
    if (pick < 13) return .{ .revoke = .{
        .actor = @intCast(prng.below(actor_count)),
        .short = prng.below(16) == 0,
    } };
    if (pick < 15) return .{ .epoch = .{ .payload = prng.below(16) == 0 } };
    return .lock;
}

fn draw_sequence(prng: *Prng, plan: *Plan, account: AccountState) void {
    plan.channel = if (prng.below(4) == 0) .multichain else .local;
    const wrong = prng.below(12) == 0;
    switch (plan.channel) {
        .multichain => {
            plan.sequence = account.multichain_sequence;
            if (wrong) plan.sequence +%= 1 + prng.below(3);
        },
        .local => {
            var epoch: u64 = account.local_epoch;
            var low: u64 = account.local_sequence;
            if (prng.below(4) == 0) low = eip8130.unsequenced;
            if (wrong) {
                if (prng.below(2) == 0) epoch +%= 1 else low = account.local_sequence + 1;
            }
            plan.sequence = (epoch & 0xffff_ffff) << 32 | low;
        },
    }
}

fn draw_plan(prng: *Prng, account: AccountState) Plan {
    const now = 16 + prng.below(64);
    var plan: Plan = .{ .channel = .local, .sequence = 0, .now = now };
    draw_sequence(prng, &plan, account);
    plan.count = @intCast(if (prng.below(32) == 0) 0 else 1 + prng.below(items_max));
    for (plan.items[0..plan.count]) |*item| item.* = draw_item(prng, now);
    assert(plan.count <= items_max);
    return plan;
}

// ------------------------------------------------------------------ encoding

fn actor_id(account: Address, index: u8) B256 {
    assert(index < actor_count);
    return switch (index) {
        0 => config.self_actor_id(account),
        1 => @splat(0),
        2 => @splat(0x22),
        else => @splat(0x5a),
    };
}

fn policy_bytes(buffer: *[64]u8, length: u8, fill: u8) []const u8 {
    assert(length <= buffer.len);
    for (buffer[0..length], 0..) |*byte, index| {
        byte.* = if (fill == 0) 0 else @truncate(index * fill + 1);
    }
    return buffer[0..length];
}

/// abi.encode(actorId, (authenticator, expiry, scope), policyData).
fn encode_item(buffer: *[payload_size_max]u8, account: Address, item: Item) eip8130.SignedChange {
    @memset(buffer, 0);
    switch (item) {
        .authorize => |a| {
            var policy_buffer: [64]u8 = undefined;
            const policy = policy_bytes(&policy_buffer, a.policy_length, a.policy_fill);
            buffer[0..32].* = actor_id(account, a.actor);
            buffer[44..64].* = authenticators[a.authenticator];
            std.mem.writeInt(u256, buffer[64..96], a.expiry, .big);
            if (a.malformed == .dirty_expiry) buffer[64 + 25] = 1;
            std.mem.writeInt(u256, buffer[96..128], a.scope, .big);
            std.mem.writeInt(u256, buffer[128..160], 160, .big);
            std.mem.writeInt(u256, buffer[160..192], policy.len, .big);
            @memcpy(buffer[192..][0..policy.len], policy);
            var length = 192 + std.mem.alignForward(usize, policy.len, 32);
            if (a.malformed == .truncated) length = 191;
            return .{ .change_type = .authorize_actor, .payload = buffer[0..length] };
        },
        .revoke => |r| {
            buffer[0..32].* = actor_id(account, r.actor);
            const length: usize = if (r.short) 31 else 32;
            return .{ .change_type = .revoke_actor, .payload = buffer[0..length] };
        },
        .epoch => |e| {
            const length: usize = if (e.payload) 1 else 0;
            return .{ .change_type = .increment_local_epoch, .payload = buffer[0..length] };
        },
        .lock => return .{ .change_type = .lock, .payload = buffer[0..0] },
    }
}

// ------------------------------------------------------------------ model

const ActorRecord = struct {
    config: ActorConfig = ActorConfig.empty,
    manager: Address = @splat(0),
    commitment: B256 = @splat(0),
};

const Model = struct {
    actors: [actor_count]ActorRecord = @splat(.{}),
    account: AccountState = AccountState.from_word(0),
    /// Per emitted log: the actor index and whether it was an authorize.
    logs: [items_max]struct { actor: u8, authorized: bool } = undefined,
    log_count: u32 = 0,

    fn emit(model: *Model, actor: u8, authorized: bool) void {
        assert(model.log_count < items_max);
        model.logs[model.log_count] = .{ .actor = actor, .authorized = authorized };
        model.log_count += 1;
    }

    fn disable_inline_self(model: *Model) void {
        model.account.flags |= eip8130.flag_default_eoa_revoked;
        model.account.default_eoa_scope = 0;
        model.account.default_eoa_expiry = 0;
    }
};

const Outcome = union(enum) { discount: u32, failure: anyerror };

fn model_sequence(model: *Model, plan: *const Plan) ?anyerror {
    const account = &model.account;
    switch (plan.channel) {
        .local => {
            if (@as(u32, @truncate(plan.sequence >> 32)) != account.local_epoch) {
                return error.StaleEpoch;
            }
            const low: u32 = @truncate(plan.sequence);
            if (low != eip8130.unsequenced) {
                if (low != account.local_sequence) return error.BadSequence;
                account.local_sequence = low + 1;
            } else if (!account.is_initialized()) {
                account.local_sequence = 1;
            }
        },
        .multichain => {
            if (plan.sequence != account.multichain_sequence) return error.BadSequence;
            account.multichain_sequence += 1;
        },
    }
    return null;
}

fn model_authorize(model: *Model, item: anytype, unsequenced: bool, now: u64) ?anyerror {
    if (item.malformed != .none) return error.MalformedAuthorizeData;
    const actor_config: ActorConfig = .{
        .authenticator = authenticators[item.authenticator],
        .expiry = item.expiry,
        .scope = item.scope,
    };
    if (unsequenced and actor_config.is_expired(now)) return null;
    if (item.authenticator == 0) return error.InvalidAuthenticator;
    const self = item.actor == 0;
    if (!self and item.actor == 1) return error.InvalidActorId;
    if (item.policy_length != 0 and item.policy_length != 52) return error.InvalidPolicyData;
    var policy_buffer: [64]u8 = undefined;
    const policy = policy_bytes(&policy_buffer, item.policy_length, item.policy_fill);
    const record = &model.actors[item.actor];
    if (self and item.authenticator == 1) {
        record.config = ActorConfig.empty;
        model.account.default_eoa_scope = item.scope;
        model.account.default_eoa_expiry = item.expiry;
        model.account.flags &= ~eip8130.flag_default_eoa_revoked;
    } else {
        record.config = actor_config;
        if (self) model.disable_inline_self();
    }
    record.manager = @splat(0);
    record.commitment = @splat(0);
    if (policy.len == 52) {
        record.manager = policy[0..20].*;
        record.commitment = policy[20..52].*;
    }
    model.emit(item.actor, true);
    return null;
}

fn model_revoke(model: *Model, item: anytype, discount: *u32) ?anyerror {
    if (item.short) return error.MalformedRevokeData;
    const record = &model.actors[item.actor];
    const self = item.actor == 0;
    if (!record.config.is_empty()) {
        record.* = .{};
        if (self) model.disable_inline_self();
        model.emit(item.actor, false);
        return null;
    }
    if (!self or model.account.default_eoa_revoked()) {
        discount.* += 3;
        return null;
    }
    var empty_slots: u32 = 1;
    if (std.mem.allEqual(u8, &record.manager, 0)) empty_slots += 1;
    if (std.mem.allEqual(u8, &record.commitment, 0)) empty_slots += 1;
    record.* = .{};
    model.disable_inline_self();
    model.emit(item.actor, false);
    discount.* += empty_slots;
    return null;
}

/// Applies `plan` to `model` the way the spec describes, item by item, leaving the
/// effects of the items before a failing one in place.
fn model_apply(model: *Model, plan: *const Plan) Outcome {
    if (plan.count == 0) return .{ .failure = error.EmptyChangeSet };
    if (model_sequence(model, plan)) |failure| return .{ .failure = failure };
    const low: u32 = @truncate(plan.sequence);
    const unsequenced = plan.channel == .local and low == eip8130.unsequenced;
    var discount: u32 = 0;
    for (plan.items[0..plan.count]) |item| {
        const failure: ?anyerror = switch (item) {
            .authorize => |a| model_authorize(model, a, unsequenced, plan.now),
            .revoke => |r| model_revoke(model, r, &discount),
            .epoch => |e| blk: {
                if (e.payload) break :blk error.InvalidChangePayload;
                model.account.local_epoch += 1;
                model.account.local_sequence = 0;
                break :blk null;
            },
            .lock => error.UnknownChangeType,
        };
        if (failure) |value| return .{ .failure = value };
    }
    return .{ .discount = discount };
}

// ------------------------------------------------------------------ checking

const Fixture = struct {
    database: memory_db.MemoryDatabase,
    state: state_module.State,

    fn init(fixture: *Fixture, allocator: std.mem.Allocator) !void {
        fixture.database = memory_db.MemoryDatabase.init(allocator);
        errdefer fixture.database.deinit();
        fixture.state = try .init(allocator, fixture.database.interface(), limits);
    }

    fn deinit(fixture: *Fixture, allocator: std.mem.Allocator) void {
        fixture.state.deinit(allocator);
        fixture.database.deinit();
    }

    fn store(fixture: *Fixture) config.Store {
        return .{ .state = &fixture.state };
    }
};

fn check_storage(store: config.Store, account: Address, model: *const Model) !void {
    for (model.actors, 0..) |record, index| {
        const id = actor_id(account, @intCast(index));
        const stored = try store.actor_config_slot(account, id);
        try expectEqualSlices(u8, &record.config.authenticator, &stored.authenticator);
        try expectEqual(record.config.expiry, stored.expiry);
        try expectEqual(record.config.scope, stored.scope);
        try expectEqualSlices(u8, &record.manager, &try store.policy_manager(account, id));
        try expectEqualSlices(u8, &record.commitment, &try store.policy_commitment(account, id));
    }
}

fn check_logs(state: *const state_module.State, account: Address, model: *const Model) !void {
    const logs = state.transaction_logs();
    try expectEqual(@as(usize, model.log_count), logs.len);
    var account_word: B256 = @splat(0);
    account_word[12..32].* = account;
    for (logs, model.logs[0..model.log_count]) |log, expected| {
        try expectEqualSlices(u8, &config.address, &log.address);
        try expectEqual(@as(u8, 3), log.topic_count);
        const event = if (expected.authorized) event_authorized else event_revoked;
        try expectEqualSlices(u8, &event, &log.topics[0]);
        try expectEqualSlices(u8, &account_word, &log.topics[1]);
        try expectEqualSlices(u8, &actor_id(account, expected.actor), &log.topics[2]);
        try expect(expected.authorized or log.data.len == 0);
    }
}

fn build_change(
    buffers: *[items_max][payload_size_max]u8,
    list_buffer: []u8,
    account: Address,
    plan: *const Plan,
) eip8130.ConfigChange {
    var signed: [items_max]eip8130.SignedChange = undefined;
    for (plan.items[0..plan.count], 0..) |item, index| {
        signed[index] = encode_item(&buffers[index], account, item);
    }
    return .{
        .channel = plan.channel,
        .sequence = plan.sequence,
        .changes = eip8130.SignedChanges.build(list_buffer, signed[0..plan.count]),
        .signature = &.{},
    };
}

fn run_batch(
    fixture: *Fixture,
    account: Address,
    model: *Model,
    current: *AccountState,
    plan: *const Plan,
) !void {
    const store = fixture.store();
    var buffers: [items_max][payload_size_max]u8 = undefined;
    var list_buffer: [items_max * (payload_size_max + 8)]u8 = undefined;
    const change = build_change(&buffers, &list_buffer, account, plan);
    fixture.state.begin_transaction();
    const checkpoint = fixture.state.checkpoint();
    const before_model = model.*;
    const before_current = current.*;
    model.log_count = 0;
    const expected = model_apply(model, plan);
    const actual = apply.apply_config_change(store, account, change, current, plan.now);
    switch (expected) {
        .discount => |discount| try expectEqual(discount, try actual),
        .failure => |failure| try std.testing.expectError(failure, actual),
    }
    try std.testing.expectEqualDeep(model.account, current.*);
    try check_storage(store, account, model);
    try check_logs(&fixture.state, account, model);
    if (expected == .failure) {
        fixture.state.revert(checkpoint);
        model.* = before_model;
        current.* = before_current;
        try check_storage(store, account, model);
    } else {
        try store.set_account_state(account, current.*);
        try std.testing.expectEqualDeep(current.*, try store.account_state(account));
    }
}

fn run_case(allocator: std.mem.Allocator, prng: *Prng) !void {
    var fixture: Fixture = undefined;
    try fixture.init(allocator);
    defer fixture.deinit(allocator);
    var account: Address = undefined;
    prng.fill(&account);
    account[0] |= 1;
    var model: Model = .{};
    var current = try fixture.store().account_state(account);
    try std.testing.expectEqualDeep(model.account, current);
    const batches = 1 + prng.below(batches_max);
    for (0..batches) |_| {
        const plan = draw_plan(prng, model.account);
        try run_batch(&fixture, account, &model, &current, &plan);
    }
}

fn fuzz_apply(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try run_case(std.testing.allocator, &prng);
}

test "fuzz_targets_eip8130_apply: config changes match the model" {
    try fuzz.run({}, fuzz_apply, .{ .iterations = 512 });
}

test "fuzz_targets_eip8130_apply: model covers every outcome" {
    // Deterministic sweep: every error the model predicts, and success, occurs.
    var prng = Prng.init(0x8130);
    var seen: [8]bool = @splat(false);
    for (0..256) |_| {
        const plan = draw_plan(&prng, AccountState.from_word(0));
        var model: Model = .{};
        const outcome = model_apply(&model, &plan);
        const index: usize = switch (outcome) {
            .discount => 0,
            .failure => |failure| outcome_index(failure),
        };
        seen[index] = true;
    }
    for (seen) |hit| try expect(hit);
}

fn outcome_index(failure: anyerror) usize {
    return switch (failure) {
        error.EmptyChangeSet => 1,
        error.BadSequence, error.StaleEpoch => 2,
        error.MalformedAuthorizeData, error.MalformedRevokeData => 3,
        error.InvalidAuthenticator => 4,
        error.InvalidActorId => 5,
        error.InvalidPolicyData => 6,
        else => 7,
    };
}

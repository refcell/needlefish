//! Sans-IO transaction manager (base/base `tx-manager/src/manager.rs` `SimpleTxManager`).
//!
//! A send is one logical transaction: it gets a nonce once and keeps it while new
//! versions with bumped fees replace each other in the mempool, until one version is
//! buried `num_confirmations` deep. The manager never performs I/O. The driver loops:
//!
//!   while (manager.next_action(now_ms, suggestion)) |action| perform it, then report
//!   the result with `on_chain_nonce`, `on_publish`, or `on_receipt`.
//!
//! and collects finished sends with `take_completion`. That split keeps every decision
//! (fees, retries, aborts, nonce reuse) deterministic and lets the simulator drive the
//! manager against a fake L1 that drops, reorders, and reorgs transactions.
//!
//! Differences from base/base, all forced by the event-driven shape: receipts are
//! polled one hash per action round-robin instead of one task per hash; the hash ring is
//! bounded (`hashes_max`), and the oldest version is forgotten only while nothing is
//! mined, which is the only time a bump happens; a "nonce too low" abort before publish
//! also resets the nonce cache so the next send refetches it.

const std = @import("std");
const assert = std.debug.assert;

const fees = @import("fees.zig");
const errors = @import("errors.zig");
const nonce_module = @import("nonce.zig");
const send_state_module = @import("send_state.zig");

pub const PublishError = errors.PublishError;
pub const Hash = send_state_module.Hash;

pub const gwei: u128 = 1_000_000_000;

/// base/base `TxManagerConfig` defaults.
pub const Config = struct {
    num_confirmations: u64 = 10,
    safe_abort_nonce_too_low_count: u64 = 3,
    fee_limit_multiplier: u64 = 5,
    fee_limit_threshold_wei: u128 = 100 * gwei,
    min_tip_cap_wei: u128 = 0,
    min_base_fee_wei: u128 = 0,
    min_blob_fee_wei: u128 = 1 * gwei,
    resubmission_timeout_ms: u64 = 48_000,
    publish_max_retries: u32 = 10,
    publish_retry_delay_ms: u64 = 1_000,
    receipt_query_interval_ms: u64 = 12_000,
    /// Whole-send deadline; 0 disables it.
    tx_send_timeout_ms: u64 = 0,
    /// A send that never reaches a mempool within this window is abandoned; 0 disables.
    tx_not_in_mempool_timeout_ms: u64 = 120_000,

    pub fn validate(config: Config) error{InvalidConfig}!void {
        if (config.num_confirmations == 0) return error.InvalidConfig;
        if (config.safe_abort_nonce_too_low_count == 0) return error.InvalidConfig;
        if (config.fee_limit_multiplier == 0) return error.InvalidConfig;
        if (config.publish_max_retries == 0) return error.InvalidConfig;
        if (config.resubmission_timeout_ms == 0) return error.InvalidConfig;
        if (config.publish_retry_delay_ms == 0) return error.InvalidConfig;
        if (config.receipt_query_interval_ms == 0) return error.InvalidConfig;
    }
};

/// Raw network fee values: `eth_maxPriorityFeePerGas`, the latest block's base fee, and
/// (blob sends only) `eth_blobBaseFee`.
pub const Suggestion = struct {
    tip_wei: u128,
    base_fee_wei: u128,
    blob_base_fee_wei: u128 = 0,
};

/// Fees of one transaction version. `blob_fee_cap_wei` is zero for non-blob sends.
pub const Fees = struct {
    tip_wei: u128,
    fee_cap_wei: u128,
    blob_fee_cap_wei: u128 = 0,
};

/// base/base `GasPriceCaps`: caps with configured minimums applied, plus the raw caps the
/// fee ceiling is measured against.
pub const Caps = struct {
    tip_wei: u128,
    fee_cap_wei: u128,
    raw_fee_cap_wei: u128,
    blob_fee_cap_wei: u128,
    raw_blob_fee_cap_wei: u128,
};

pub fn suggest_caps(config: *const Config, suggestion: Suggestion, is_blob: bool) Caps {
    const tip = @max(suggestion.tip_wei, config.min_tip_cap_wei);
    const base_fee = @max(suggestion.base_fee_wei, config.min_base_fee_wei);
    var caps: Caps = .{
        .tip_wei = tip,
        .fee_cap_wei = fees.gas_fee_cap(base_fee, tip),
        .raw_fee_cap_wei = fees.gas_fee_cap(suggestion.base_fee_wei, suggestion.tip_wei),
        .blob_fee_cap_wei = 0,
        .raw_blob_fee_cap_wei = 0,
    };
    if (is_blob) {
        const blob_base_fee = @max(suggestion.blob_base_fee_wei, config.min_blob_fee_wei);
        caps.blob_fee_cap_wei = fees.blob_fee_cap(blob_base_fee);
        caps.raw_blob_fee_cap_wei = fees.blob_fee_cap(suggestion.blob_base_fee_wei);
    }
    assert(caps.fee_cap_wei >= caps.tip_wei);
    assert(is_blob or caps.blob_fee_cap_wei == 0);
    return caps;
}

pub const FeeError = error{FeeLimitExceeded};

fn check_limits(config: *const Config, candidate: Fees, caps: Caps, is_blob: bool) FeeError!void {
    const multiplier = config.fee_limit_multiplier;
    const limit = config.fee_limit_threshold_wei;
    if (!fees.within_limit(candidate.fee_cap_wei, caps.raw_fee_cap_wei, multiplier, limit)) {
        return error.FeeLimitExceeded;
    }
    if (!is_blob) return;
    const blob_cap = candidate.blob_fee_cap_wei;
    if (!fees.within_limit(blob_cap, caps.raw_blob_fee_cap_wei, multiplier, limit)) {
        return error.FeeLimitExceeded;
    }
}

/// Fees of the first version of a send.
pub fn initial_fees(config: *const Config, suggestion: Suggestion, is_blob: bool) FeeError!Fees {
    const caps = suggest_caps(config, suggestion, is_blob);
    const result: Fees = .{
        .tip_wei = caps.tip_wei,
        .fee_cap_wei = caps.fee_cap_wei,
        .blob_fee_cap_wei = caps.blob_fee_cap_wei,
    };
    try check_limits(config, result, caps, is_blob);
    return result;
}

/// base/base `increase_gas_price`: replacement fees that clear geth's bump thresholds and
/// track the current network suggestion, within the fee ceiling.
pub fn bump_fees(
    config: *const Config,
    old: Fees,
    suggestion: Suggestion,
    is_blob: bool,
) FeeError!Fees {
    assert(is_blob or old.blob_fee_cap_wei == 0);
    const caps = suggest_caps(config, suggestion, is_blob);
    const new_base_fee = fees.base_fee_from_caps(caps.fee_cap_wei, caps.tip_wei);
    const bumped =
        fees.update_fees(old.tip_wei, old.fee_cap_wei, caps.tip_wei, new_base_fee, is_blob);
    var result: Fees = .{ .tip_wei = bumped.tip_wei, .fee_cap_wei = bumped.fee_cap_wei };
    if (is_blob) {
        const blob_threshold = fees.threshold(old.blob_fee_cap_wei, true);
        result.blob_fee_cap_wei = @max(blob_threshold, caps.blob_fee_cap_wei);
    }
    try check_limits(config, result, caps, is_blob);
    assert(result.tip_wei > old.tip_wei or old.tip_wei == std.math.maxInt(u128));
    return result;
}

pub const Action = union(enum) {
    /// Fetch `eth_getTransactionCount(sender, "latest")`, then call `on_chain_nonce`.
    fetch_nonce: struct { generation: u64 },
    /// Sign and send this version, then call `on_publish` with its local hash.
    publish: Publish,
    /// Look up the receipt and canonical status of `hash`, then call `on_receipt`.
    query_receipt: struct { id: u64, hash: Hash },

    pub const Publish = struct {
        id: u64,
        nonce: u64,
        fees: Fees,
        is_blob: bool,
        /// The version this one replaces, null for the first version.
        replaces: ?Hash,
    };
};

pub const ReceiptStatus = union(enum) {
    /// No receipt, or its block is not canonical.
    not_found,
    mined: struct { block_number: u64, tip_number: u64 },
};

pub const Failure = enum {
    nonce_too_low,
    mempool_deadline_expired,
    send_timeout,
    /// The first version was rejected by the node; see `Completion.publish_error`.
    publish_rejected,
};

pub const Outcome = union(enum) {
    confirmed: struct { hash: Hash, block_number: u64 },
    failed: Failure,
};

pub const Completion = struct {
    id: u64,
    nonce: u64,
    outcome: Outcome,
    publish_error: ?PublishError,
    bump_count: u64,
};

pub const Limits = struct {
    /// Concurrent sends (base/base bounds this with its send queue).
    sends_max: u32 = 16,
    /// Published versions remembered per send.
    hashes_max: u32 = 32,
};

pub const SubmitError = error{ PendingFull, NonceUnknown, NonceOverflow } || FeeError;

pub fn Manager(comptime limits: Limits) type {
    comptime assert(limits.sends_max > 0);
    comptime assert(limits.hashes_max >= 2);
    return struct {
        const Self = @This();
        const NonceTracker = nonce_module.Tracker(limits.sends_max);
        const SendState = send_state_module.SendState(limits.hashes_max);

        const Slot = struct {
            state: enum { free, awaiting_publish, publishing, published, done } = .free,
            id: u64 = 0,
            nonce: u64 = 0,
            is_blob: bool = false,
            /// Fees of the latest accepted version (or the initial fees before publish).
            fees: Fees = .{ .tip_wei = 0, .fee_cap_wei = 0 },
            /// Fees of the version currently being published.
            publishing_fees: Fees = .{ .tip_wei = 0, .fee_cap_wei = 0 },
            publishing_bump: bool = false,
            publish_at_ms: u64 = 0,
            bump_at_ms: u64 = 0,
            receipt_at_ms: u64 = 0,
            receipt_cursor: u32 = 0,
            retries_left: u32 = 0,
            deadline_ms: ?u64 = null,
            /// Ring of published versions; `hash_count` saturates at `hashes_max`.
            hashes: [limits.hashes_max]Hash = undefined,
            hash_count: u32 = 0,
            hash_next: u32 = 0,
            send_state: SendState = undefined,
            outcome: Outcome = .{ .failed = .publish_rejected },
            publish_error: ?PublishError = null,
        };

        config: Config,
        nonce: NonceTracker = .{},
        nonce_fetch_in_flight: bool = false,
        slots: [limits.sends_max]Slot = @splat(.{}),
        id_next: u64 = 1,
        scan_start: u32 = 0,

        pub fn init(config: Config) error{InvalidConfig}!Self {
            try config.validate();
            return .{ .config = config };
        }

        pub fn pending_count(manager: *const Self) u32 {
            var count: u32 = 0;
            for (manager.slots) |slot| count += @intFromBool(slot.state != .free);
            assert(count <= limits.sends_max);
            return count;
        }

        pub fn has_capacity(manager: *const Self) bool {
            return manager.pending_count() < limits.sends_max;
        }

        /// Starts a send. Fails with `NonceUnknown` until the driver has answered a
        /// `fetch_nonce` action.
        pub fn submit(
            manager: *Self,
            now_ms: u64,
            suggestion: Suggestion,
            is_blob: bool,
        ) SubmitError!u64 {
            const slot = manager.free_slot() orelse return error.PendingFull;
            const nonce = try manager.nonce.reserve();
            const first_fees = initial_fees(&manager.config, suggestion, is_blob) catch |err| {
                manager.give_back(nonce);
                return err;
            };
            const config = &manager.config;
            const mempool_deadline_ms: ?u64 = if (config.tx_not_in_mempool_timeout_ms == 0)
                null
            else
                now_ms +| config.tx_not_in_mempool_timeout_ms;
            slot.* = .{
                .state = .awaiting_publish,
                .id = manager.id_next,
                .nonce = nonce,
                .is_blob = is_blob,
                .fees = first_fees,
                .publish_at_ms = now_ms,
                .retries_left = config.publish_max_retries,
                .deadline_ms = if (config.tx_send_timeout_ms == 0)
                    null
                else
                    now_ms +| config.tx_send_timeout_ms,
                .send_state = SendState.init(
                    config.safe_abort_nonce_too_low_count,
                    mempool_deadline_ms,
                ),
            };
            manager.id_next += 1;
            assert(slot.id > 0);
            return slot.id;
        }

        /// The next I/O the driver should perform, or null when nothing is due.
        pub fn next_action(manager: *Self, now_ms: u64, suggestion: Suggestion) ?Action {
            if (!manager.nonce.known() and !manager.nonce_fetch_in_flight) {
                manager.nonce_fetch_in_flight = true;
                return .{ .fetch_nonce = .{ .generation = manager.nonce.generation } };
            }
            for (0..limits.sends_max) |offset| {
                const index = (manager.scan_start + offset) % limits.sends_max;
                const slot = &manager.slots[index];
                if (manager.slot_action(slot, now_ms, suggestion)) |action| {
                    manager.scan_start = @intCast((index + 1) % limits.sends_max);
                    return action;
                }
            }
            return null;
        }

        /// Answer to `fetch_nonce`; `chain_nonce` null means the fetch failed.
        pub fn on_chain_nonce(manager: *Self, generation: u64, chain_nonce: ?u64) void {
            assert(manager.nonce_fetch_in_flight);
            manager.nonce_fetch_in_flight = false;
            if (chain_nonce) |value| _ = manager.nonce.set_chain_nonce(generation, value);
        }

        /// Answer to `publish`. `hash` is the locally computed hash of the signed version.
        pub fn on_publish(
            manager: *Self,
            id: u64,
            hash: Hash,
            result: ?PublishError,
            now_ms: u64,
        ) void {
            const slot = manager.find(id) orelse return;
            // A version can confirm while a replacement is still being published.
            if (slot.state == .done) return;
            assert(slot.state == .publishing);
            if (result == null) return manager.publish_accepted(slot, hash, now_ms);
            const publish_error = result.?;
            if (publish_error == .already_known and slot.send_state.has_published) {
                // Resubmission of a version already in the pool: keep the previous version.
                slot.state = .published;
                slot.bump_at_ms = now_ms +| manager.config.resubmission_timeout_ms;
                return;
            }
            if (publish_error == .nonce_too_low) slot.send_state.record_nonce_too_low();
            slot.publish_error = publish_error;
            if (slot.publishing_bump) {
                // A failed bump keeps the previous version and retries after a full interval.
                slot.state = .published;
                slot.bump_at_ms = now_ms +| manager.config.resubmission_timeout_ms;
                return;
            }
            if (publish_error == .nonce_too_high and slot.retries_left > 0) {
                slot.retries_left -= 1;
                slot.state = .awaiting_publish;
                slot.publish_at_ms = now_ms +| manager.config.publish_retry_delay_ms;
                return;
            }
            const failure: Failure = if (publish_error == .nonce_too_low)
                .nonce_too_low
            else
                .publish_rejected;
            manager.fail(slot, failure);
        }

        /// Answer to `query_receipt`.
        pub fn on_receipt(manager: *Self, id: u64, hash: Hash, status: ReceiptStatus) void {
            const slot = manager.find(id) orelse return;
            if (slot.state == .done or !slot_has_hash(slot, hash)) return;
            switch (status) {
                .not_found => slot.send_state.tx_not_mined(hash),
                .mined => |mined| {
                    // The mined set holds only remembered hashes, so it cannot overflow.
                    const recorded = slot.send_state.tx_mined(hash);
                    assert(recorded);
                    const depth_reached = mined.block_number +| manager.config.num_confirmations <=
                        mined.tip_number +| 1;
                    if (!depth_reached) return;
                    slot.state = .done;
                    slot.outcome = .{ .confirmed = .{
                        .hash = hash,
                        .block_number = mined.block_number,
                    } };
                },
            }
        }

        /// Removes and returns one finished send.
        pub fn take_completion(manager: *Self) ?Completion {
            for (&manager.slots) |*slot| {
                if (slot.state != .done) continue;
                const completion: Completion = .{
                    .id = slot.id,
                    .nonce = slot.nonce,
                    .outcome = slot.outcome,
                    .publish_error = slot.publish_error,
                    .bump_count = slot.send_state.bump_count,
                };
                slot.* = .{};
                assert(slot.state == .free);
                return completion;
            }
            return null;
        }

        fn slot_action(manager: *Self, slot: *Slot, now_ms: u64, suggestion: Suggestion) ?Action {
            switch (slot.state) {
                .free, .done => return null,
                .awaiting_publish, .publishing, .published => {},
            }
            if (manager.check_abort(slot, now_ms)) return null;
            switch (slot.state) {
                .awaiting_publish => if (now_ms >= slot.publish_at_ms) {
                    return manager.start_publish(slot, slot.fees, false);
                },
                .published => if (now_ms >= slot.bump_at_ms) {
                    if (manager.start_bump(slot, now_ms, suggestion)) |action| return action;
                },
                .publishing => {},
                .free, .done => unreachable,
            }
            return receipt_action(manager, slot, now_ms);
        }

        /// Fails the send on a critical error or deadline. Returns true when it did.
        fn check_abort(manager: *Self, slot: *Slot, now_ms: u64) bool {
            // An outstanding publish must be answered before the slot can finish.
            if (slot.state == .publishing) return false;
            if (slot.deadline_ms) |deadline_ms| {
                if (now_ms >= deadline_ms) {
                    manager.fail(slot, .send_timeout);
                    return true;
                }
            }
            const critical = slot.send_state.critical_error(now_ms) orelse return false;
            manager.fail(slot, switch (critical) {
                .nonce_too_low => .nonce_too_low,
                .mempool_deadline_expired => .mempool_deadline_expired,
            });
            return true;
        }

        fn start_bump(manager: *Self, slot: *Slot, now_ms: u64, suggestion: Suggestion) ?Action {
            assert(slot.state == .published);
            assert(slot.hash_count > 0);
            const interval_ms = manager.config.resubmission_timeout_ms;
            // A mined version is waiting for depth: a replacement would only race it.
            if (slot.send_state.waiting_for_confirmation()) {
                slot.bump_at_ms = now_ms +| interval_ms;
                return null;
            }
            const bumped = bump_fees(&manager.config, slot.fees, suggestion, slot.is_blob) catch {
                slot.bump_at_ms = now_ms +| interval_ms;
                return null;
            };
            return manager.start_publish(slot, bumped, true);
        }

        fn start_publish(manager: *Self, slot: *Slot, version_fees: Fees, bump: bool) Action {
            _ = manager;
            assert(slot.state != .publishing);
            slot.state = .publishing;
            slot.publishing_fees = version_fees;
            slot.publishing_bump = bump;
            return .{ .publish = .{
                .id = slot.id,
                .nonce = slot.nonce,
                .fees = version_fees,
                .is_blob = slot.is_blob,
                .replaces = if (slot.hash_count == 0) null else latest_hash(slot),
            } };
        }

        fn receipt_action(manager: *Self, slot: *Slot, now_ms: u64) ?Action {
            if (slot.hash_count == 0 or now_ms < slot.receipt_at_ms) return null;
            assert(slot.receipt_cursor < slot.hash_count);
            const hash = slot.hashes[slot.receipt_cursor];
            slot.receipt_cursor += 1;
            if (slot.receipt_cursor == slot.hash_count) {
                slot.receipt_cursor = 0;
                slot.receipt_at_ms = now_ms +| manager.config.receipt_query_interval_ms;
            }
            return .{ .query_receipt = .{ .id = slot.id, .hash = hash } };
        }

        fn publish_accepted(manager: *Self, slot: *Slot, hash: Hash, now_ms: u64) void {
            const first = slot.hash_count == 0;
            if (slot.hash_count == limits.hashes_max) {
                // Forget the oldest version; bumps happen only while nothing is mined.
                const oldest = slot.hashes[slot.hash_next];
                assert(!slot.send_state.waiting_for_confirmation());
                slot.send_state.tx_not_mined(oldest);
            } else {
                slot.hash_count += 1;
            }
            slot.hashes[slot.hash_next] = hash;
            slot.hash_next = (slot.hash_next + 1) % limits.hashes_max;
            if (slot.receipt_cursor >= slot.hash_count) slot.receipt_cursor = 0;
            slot.fees = slot.publishing_fees;
            if (slot.publishing_bump) _ = slot.send_state.record_fee_bump();
            slot.send_state.record_successful_publish();
            slot.state = .published;
            slot.bump_at_ms = now_ms +| manager.config.resubmission_timeout_ms;
            if (first) slot.receipt_at_ms = now_ms +| manager.config.receipt_query_interval_ms;
            assert(std.mem.eql(u8, &latest_hash(slot), &hash));
        }

        fn fail(manager: *Self, slot: *Slot, failure: Failure) void {
            assert(slot.state != .free and slot.state != .done);
            const published = slot.send_state.has_published;
            // base/base `should_return_reserved_nonce`: a too-low nonce is already used.
            if (!published and failure != .nonce_too_low) manager.give_back(slot.nonce);
            // base/base resets on send timeouts; needlefish also resets when the chain
            // already used the nonce, so the next send refetches instead of failing too.
            if (failure == .send_timeout or (!published and failure == .nonce_too_low)) {
                manager.nonce.reset();
            }
            slot.state = .done;
            slot.outcome = .{ .failed = failure };
        }

        fn give_back(manager: *Self, nonce: u64) void {
            // A full return set leaves a gap; a reset makes the next fetch repair it.
            if (!manager.nonce.give_back(nonce)) manager.nonce.reset();
        }

        fn free_slot(manager: *Self) ?*Slot {
            for (&manager.slots) |*slot| if (slot.state == .free) return slot;
            return null;
        }

        fn find(manager: *Self, id: u64) ?*Slot {
            assert(id > 0);
            for (&manager.slots) |*slot| {
                if (slot.state != .free and slot.id == id) return slot;
            }
            return null;
        }

        fn latest_hash(slot: *const Slot) Hash {
            assert(slot.hash_count > 0);
            const index = (slot.hash_next + limits.hashes_max - 1) % limits.hashes_max;
            return slot.hashes[index];
        }

        fn slot_has_hash(slot: *const Slot, hash: Hash) bool {
            for (slot.hashes[0..slot.hash_count]) |known| {
                if (std.mem.eql(u8, &known, &hash)) return true;
            }
            return false;
        }
    };
}

const testing = std.testing;
const TestManager = Manager(.{ .sends_max = 2, .hashes_max = 4 });
const quiet: Suggestion = .{ .tip_wei = 1 * gwei, .base_fee_wei = 10 * gwei };

fn ready_manager(config: Config) !TestManager {
    var manager = try TestManager.init(config);
    const action = manager.next_action(0, quiet).?;
    manager.on_chain_nonce(action.fetch_nonce.generation, 5);
    return manager;
}

fn expect_publish(manager: *TestManager, now_ms: u64, suggestion: Suggestion) !Action.Publish {
    const action = manager.next_action(now_ms, suggestion) orelse return error.TestNoAction;
    return switch (action) {
        .publish => |publish| publish,
        else => error.TestUnexpectedAction,
    };
}

test "manager: config validation" {
    try testing.expectError(error.InvalidConfig, TestManager.init(.{ .num_confirmations = 0 }));
    try testing.expectError(error.InvalidConfig, TestManager.init(.{ .publish_max_retries = 0 }));
    _ = try TestManager.init(.{});
}

test "manager: submit needs the chain nonce and bounded capacity" {
    var manager = try TestManager.init(.{});
    try testing.expectError(error.NonceUnknown, manager.submit(0, quiet, false));
    manager = try ready_manager(.{});
    _ = try manager.submit(0, quiet, false);
    _ = try manager.submit(0, quiet, false);
    try testing.expectError(error.PendingFull, manager.submit(0, quiet, false));
}

test "manager: nonce too high retries, then bump replaces, then confirm" {
    var manager = try ready_manager(.{ .num_confirmations = 2, .resubmission_timeout_ms = 100 });
    const id = try manager.submit(0, quiet, false);
    var publish = try expect_publish(&manager, 0, quiet);
    try testing.expectEqual(@as(u64, 5), publish.nonce);
    try testing.expectEqual(@as(?Hash, null), publish.replaces);
    manager.on_publish(id, @splat(1), .nonce_too_high, 0);
    try testing.expectEqual(@as(?Action, null), manager.next_action(999, quiet));
    publish = try expect_publish(&manager, 1_000, quiet);
    manager.on_publish(id, @splat(1), null, 1_000);
    // Resubmission: higher fees, same nonce, replaces the first version.
    publish = try expect_publish(&manager, 1_100, quiet);
    try testing.expectEqual(@as(u64, 5), publish.nonce);
    try testing.expectEqual(@as(u128, 1_100_000_000), publish.fees.tip_wei);
    try testing.expectEqualSlices(u8, &@as(Hash, @splat(1)), &publish.replaces.?);
    manager.on_publish(id, @splat(2), null, 1_100);
    manager.on_receipt(id, @splat(2), .{ .mined = .{ .block_number = 9, .tip_number = 9 } });
    try testing.expectEqual(@as(?Completion, null), manager.take_completion());
    manager.on_receipt(id, @splat(2), .{ .mined = .{ .block_number = 9, .tip_number = 10 } });
    const completion = manager.take_completion().?;
    try testing.expectEqual(@as(u64, 1), completion.bump_count);
    try testing.expectEqual(@as(u64, 9), completion.outcome.confirmed.block_number);
    try testing.expectEqual(@as(u32, 0), manager.pending_count());
}

test "manager: rejected first version returns its nonce" {
    var manager = try ready_manager(.{});
    const id = try manager.submit(0, quiet, false);
    _ = try expect_publish(&manager, 0, quiet);
    manager.on_publish(id, @splat(1), .insufficient_funds, 0);
    const completion = manager.take_completion().?;
    try testing.expectEqual(Failure.publish_rejected, completion.outcome.failed);
    try testing.expectEqual(@as(?PublishError, .insufficient_funds), completion.publish_error);
    // The next send reuses nonce 5.
    _ = try manager.submit(0, quiet, false);
    try testing.expectEqual(@as(u64, 5), (try expect_publish(&manager, 0, quiet)).nonce);
}

test "manager: nonce too low before publish aborts and refetches" {
    var manager = try ready_manager(.{});
    const id = try manager.submit(0, quiet, false);
    _ = try expect_publish(&manager, 0, quiet);
    manager.on_publish(id, @splat(1), .nonce_too_low, 0);
    try testing.expectEqual(Failure.nonce_too_low, manager.take_completion().?.outcome.failed);
    try testing.expect(manager.next_action(0, quiet).? == .fetch_nonce);
}

test "manager: blob bump doubles the blob fee cap" {
    const config: Config = .{};
    const suggestion: Suggestion = .{
        .tip_wei = 1 * gwei,
        .base_fee_wei = 10 * gwei,
        .blob_base_fee_wei = 3 * gwei,
    };
    const first = try initial_fees(&config, suggestion, true);
    try testing.expectEqual(@as(u128, 6 * gwei), first.blob_fee_cap_wei);
    const bumped = try bump_fees(&config, first, suggestion, true);
    try testing.expectEqual(@as(u128, 12 * gwei), bumped.blob_fee_cap_wei);
    try testing.expectEqual(@as(u128, 2 * gwei), bumped.tip_wei);
}

test "manager: fee ceiling stops runaway bumps" {
    const config: Config = .{ .fee_limit_threshold_wei = 0, .fee_limit_multiplier = 2 };
    var current = try initial_fees(&config, quiet, false);
    var bumps: u32 = 0;
    while (bumps < 100) : (bumps += 1) {
        current = bump_fees(&config, current, quiet, false) catch break;
    }
    // 21 gwei raw cap, 42 gwei ceiling: a handful of +10% bumps fit, then it stops.
    try testing.expect(bumps > 0 and bumps < 10);
    try testing.expect(current.fee_cap_wei <= 42 * gwei);
}

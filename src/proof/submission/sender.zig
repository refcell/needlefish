//! A generic transaction sender over a blocking JSON-RPC `Endpoint` (the transaction half
//! of base/base `crates/proof/submission` over its `TxManager`), shared by the proposer
//! and the challenger.
//!
//! `send` estimates gas (a JSON-RPC error here is returned with its message and revert
//! data), signs an EIP-1559 transaction carrying `value` at the account's pending nonce,
//! and broadcasts it. `status` polls the receipt: a failed receipt is replayed as an
//! `eth_call` at its block to recover the revert data. A transaction without a receipt
//! after `receipt_polls_max` polls is reported dropped. With `resubmit_polls` set, a
//! transaction without a receipt is re-signed at the same nonce with fees raised by
//! `bump_percent` (at least 1 wei) every `resubmit_polls` polls, up to `bumps_max` times,
//! as base/base's `TxManager` does; a receipt for any of its hashes settles it.

const std = @import("std");
const assert = std.debug.assert;

const clients = @import("../rpc/clients.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");

pub const Address = endpoint_module.Address;
pub const TxId = u64;

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: Address,
    /// Added to the gas estimate, in percent.
    gas_buffer_percent: u8 = 20,
    tip_wei_default: u128 = 1_000_000_000,
    receipt_polls_max: u32 = 120,
    slots_max: u8 = 4,
    calldata_bytes_max: u32,
    /// Polls without a receipt before a fee-bumped resubmission; 0 disables bumping.
    resubmit_polls: u32 = 0,
    bumps_max: u8 = 3,
    /// Geth replaces a pending transaction only for at least 10% higher fees.
    bump_percent: u8 = 15,
};

/// Hashes kept per transaction: the first broadcast and every bump.
pub const hashes_max = 8;

pub const Request = struct {
    to: Address,
    value: u256,
    /// Copied by `send`.
    calldata: []const u8,
};

/// Where a JSON-RPC error came from.
pub const Phase = enum { estimate, broadcast, replay };

pub const Failure = union(enum) {
    /// A JSON-RPC error; the strings borrow the endpoint arena until its next call.
    rpc_error: struct { phase: Phase, message: []const u8, data: []const u8 },
    /// Mined with a failed status, and the replay at its block did not revert.
    reverted,
    /// No free slot, transport failure, malformed answer or signing failure.
    unavailable,
    /// No receipt after `receipt_polls_max` polls, or an unknown id.
    dropped,
};

pub const SendResult = union(enum) { pending: TxId, failed: Failure };
pub const Status = union(enum) { pending, mined, failed: Failure };

pub fn Sender(comptime EndpointType: type) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            id: TxId = 0,
            used: bool = false,
            hashes: [hashes_max][32]u8 = undefined,
            hash_count: u8 = 0,
            to: Address = @splat(0),
            value: u256 = 0,
            nonce: u64 = 0,
            gas_limit: u64 = 0,
            fees: txdata.Fees = .{ .max_fee_per_gas = 0, .max_priority_fee_per_gas = 0 },
            polls: u32 = 0,
            polls_since_send: u32 = 0,
            calldata: []u8,
            calldata_length: u32 = 0,
        };

        l1: *EndpointType,
        config: Config,
        slots: []Slot,
        next_id: TxId = 1,
        /// Why the last `unavailable` happened, for logs.
        last_failure: ?anyerror = null,
        /// Fee-bumped resubmissions sent.
        bumps: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, l1: *EndpointType, config: Config) !Self {
            assert(config.slots_max > 0);
            assert(config.gas_buffer_percent <= 100);
            assert(config.calldata_bytes_max >= 4);
            assert(config.bumps_max < hashes_max);
            assert(config.resubmit_polls == 0 or config.bump_percent >= 10);
            const slots = try allocator.alloc(Slot, config.slots_max);
            errdefer allocator.free(slots);
            for (slots, 0..) |*slot, index| {
                errdefer for (slots[0..index]) |done| allocator.free(done.calldata);
                slot.* = .{ .calldata = try allocator.alloc(u8, config.calldata_bytes_max) };
            }
            return .{ .l1 = l1, .config = config, .slots = slots };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.slots) |slot| allocator.free(slot.calldata);
            allocator.free(self.slots);
            self.* = undefined;
        }

        pub fn has_free_slot(self: *const Self) bool {
            for (self.slots) |slot| {
                if (!slot.used) return true;
            }
            assert(self.slots.len > 0);
            return false;
        }

        fn failed_call(self: *Self, err: endpoint_module.Error, phase: Phase) Failure {
            self.last_failure = err;
            const failure = self.l1.last_error orelse return .unavailable;
            assert(err == error.NotFound);
            return .{ .rpc_error = .{
                .phase = phase,
                .message = failure.message,
                .data = failure.data,
            } };
        }

        /// Estimates, signs and broadcasts `request`. Frees the endpoint's previous results.
        pub fn send(self: *Self, request: Request) SendResult {
            assert(request.calldata.len <= self.config.calldata_bytes_max);
            self.l1.reset();
            const slot = for (self.slots) |*slot| {
                if (!slot.used) break slot;
            } else return .{ .failed = .unavailable };
            const transaction = self.call_object(request.to, request.value, request.calldata);
            const estimate = self.l1.call("eth_estimateGas", &.{.{ .transaction = transaction }});
            const estimate_raw = estimate catch |err| {
                return .{ .failed = self.failed_call(err, .estimate) };
            };
            const gas = endpoint_module.parse_quantity(estimate_raw) catch |err| {
                self.last_failure = err;
                return .{ .failed = .unavailable };
            };
            slot.* = .{
                .id = self.next_id,
                .used = true,
                .to = request.to,
                .value = request.value,
                .gas_limit = @max(gas +| gas / 100 * self.config.gas_buffer_percent, 21_000),
                .calldata = slot.calldata,
                .calldata_length = @intCast(request.calldata.len),
            };
            @memcpy(slot.calldata[0..request.calldata.len], request.calldata);
            const hash = self.first_broadcast(slot) catch |err| {
                slot.used = false;
                return .{ .failed = self.failed_call(err, .broadcast) };
            };
            slot.hashes[0] = hash;
            slot.hash_count = 1;
            self.next_id += 1;
            assert(slot.id < self.next_id);
            return .{ .pending = slot.id };
        }

        fn call_object(
            self: *const Self,
            to: Address,
            value: u256,
            calldata: []const u8,
        ) endpoint_module.Transaction {
            return .{ .from = self.config.from, .to = to, .value = value, .data = calldata };
        }

        /// Picks the nonce and fees of a new transaction, then signs and sends it.
        fn first_broadcast(self: *Self, slot: *Slot) endpoint_module.Error![32]u8 {
            const nonce_raw = try self.l1.call("eth_getTransactionCount", &.{
                .{ .address = self.config.from },
                .{ .string = "pending" },
            });
            slot.nonce = try endpoint_module.parse_quantity(nonce_raw);
            slot.fees = txdata.suggest_fees(try self.base_fee(), self.tip());
            assert(slot.fees.valid());
            return self.sign_and_send(slot);
        }

        /// Signs the slot's transaction at its nonce and fees and sends it; returns its hash.
        fn sign_and_send(self: *Self, slot: *const Slot) endpoint_module.Error![32]u8 {
            const config = self.config;
            assert(slot.used);
            const envelope = txdata.sign_eip1559(.{
                .chain_id = config.chain_id,
                .nonce = slot.nonce,
                .fees = slot.fees,
                .gas_limit = slot.gas_limit,
                .to = .{ .bytes = slot.to },
                .value = slot.value,
                .data = slot.calldata[0..slot.calldata_length],
            }, config.private_key) catch return error.CallFailed;
            const raw = self.l1.arena.allocator().alloc(u8, envelope.encoded_length()) catch
                return error.CallFailed;
            const encoded = txdata.encode_raw(envelope, raw);
            const sent = try self.l1.call("eth_sendRawTransaction", &.{.{ .bytes = encoded }});
            const hash = try endpoint_module.parse_hash(sent);
            // The node must answer with the hash of what was signed.
            if (!std.mem.eql(u8, &hash, &envelope.hash().bytes)) return error.CallFailed;
            assert(encoded.len == raw.len);
            return hash;
        }

        /// Re-signs at the same nonce with fees raised by `bump_percent` (at least 1 wei,
        /// and never below today's suggestion).
        fn bump(self: *Self, slot: *Slot) void {
            assert(slot.hash_count > 0 and slot.hash_count < hashes_max);
            const percent: u128 = 100 + @as(u128, self.config.bump_percent);
            const old = slot.fees;
            const current = txdata.suggest_fees(self.base_fee() catch 0, self.tip());
            const raised_tip = old.max_priority_fee_per_gas * percent / 100 + 1;
            const tip_value = @max(raised_tip, current.max_priority_fee_per_gas);
            const raised_cap = old.max_fee_per_gas * percent / 100 + 1;
            const fee_cap = @max(raised_cap, current.max_fee_per_gas, tip_value);
            slot.fees = .{ .max_fee_per_gas = fee_cap, .max_priority_fee_per_gas = tip_value };
            assert(slot.fees.valid());
            slot.polls_since_send = 0;
            // A failed resubmission (often "nonce too low": an earlier hash mined) keeps the
            // known hashes; the next polls find the receipt or bump again.
            const hash = self.sign_and_send(slot) catch return;
            slot.hashes[slot.hash_count] = hash;
            slot.hash_count += 1;
            self.bumps += 1;
        }

        fn base_fee(self: *Self) endpoint_module.Error!u128 {
            const l1: clients.Execution(EndpointType) = .{ .endpoint = self.l1 };
            const header = rlp.decode_exact(consensus.Header, try l1.raw_header(.latest)) catch
                return error.CallFailed;
            const fee = header.base_fee_per_gas orelse return error.CallFailed;
            return fee;
        }

        fn tip(self: *Self) u128 {
            const raw = self.l1.call("eth_maxPriorityFeePerGas", &.{}) catch
                return self.config.tip_wei_default;
            return endpoint_module.parse_quantity(raw) catch self.config.tip_wei_default;
        }

        /// Polls the receipts of `id`'s hashes, newest first, and bumps its fees when due.
        /// Frees the endpoint's previous results.
        pub fn status(self: *Self, id: TxId) Status {
            self.l1.reset();
            const slot = for (self.slots) |*slot| {
                if (slot.used and slot.id == id) break slot;
            } else return .{ .failed = .dropped };
            assert(slot.hash_count > 0);
            var index: usize = slot.hash_count;
            while (index > 0) {
                index -= 1;
                const hash = slot.hashes[index];
                const receipt = self.l1.call("eth_getTransactionReceipt", &.{.{ .hash = hash }});
                const raw = receipt catch |err| switch (err) {
                    error.NotFound => {
                        if (self.l1.last_error != null) return .pending;
                        continue;
                    },
                    error.CallFailed => return .pending,
                };
                const result = self.settle(slot, raw) catch return .pending;
                slot.used = false;
                assert(result != .pending);
                return result;
            }
            slot.polls += 1;
            slot.polls_since_send += 1;
            if (slot.polls >= self.config.receipt_polls_max) {
                slot.used = false;
                return .{ .failed = .dropped };
            }
            const config = self.config;
            const bumps_left = slot.hash_count <= config.bumps_max;
            if (config.resubmit_polls > 0 and slot.polls_since_send >= config.resubmit_polls and
                bumps_left) self.bump(slot);
            return .pending;
        }

        /// A receipt's outcome; a failed one is replayed at its block for the revert data.
        fn settle(self: *Self, slot: *const Slot, raw: []const u8) endpoint_module.Error!Status {
            const status_raw = try endpoint_module.member(raw, &.{"status"});
            if (try endpoint_module.parse_quantity(status_raw) == 1) return .mined;
            const block_raw = try endpoint_module.member(raw, &.{"blockNumber"});
            const block = try endpoint_module.parse_quantity(block_raw);
            const calldata = slot.calldata[0..slot.calldata_length];
            const replay = self.l1.call("eth_call", &.{
                .{ .transaction = self.call_object(slot.to, slot.value, calldata) },
                .{ .number = block },
            });
            _ = replay catch |err| return .{ .failed = self.failed_call(err, .replay) };
            return .{ .failed = .reverted };
        }
    };
}

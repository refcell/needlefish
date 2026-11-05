//! The proposer's `Submitter` over JSON-RPC (base/base `OutputProposer` over its
//! `TxManager`, with `crates/proof/submission` revert classification).
//!
//! `send` reads the game type's init bond (`initBonds`), estimates gas (a revert here is
//! classified at once), signs an EIP-1559 `createWithInitData` transaction carrying the
//! bond at the account's pending nonce, and broadcasts it. `status` polls the receipt: a
//! failed receipt is replayed as an `eth_call` at its block to recover the revert data. A
//! transaction without a receipt after `receipt_polls_max` polls is reported dropped.
//! Fee bumping and resubmission are left to the caller's restart (a new nonce each time).

const std = @import("std");
const assert = std.debug.assert;

const clients = @import("../rpc/clients.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const interfaces = @import("interfaces.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");

const Address = interfaces.Address;
const SubmitFailure = interfaces.SubmitFailure;

/// Aggregate verifier errors the submission path recognizes (base/base `KnownRevert`).
pub const reverts = struct {
    pub const l1_origin_too_old = abi.selector("L1OriginTooOld(uint256,uint256)");
    pub const invalid_parent_game = abi.selector("InvalidParentGame()");
    pub const invalid_signer = abi.selector("InvalidSigner(address)");
};

const Known = struct { name: []const u8, selector: [4]u8, failure: SubmitFailure };

const known = [_]Known{
    .{
        .name = "GameAlreadyExists",
        .selector = factory.game_already_exists,
        .failure = .game_already_exists,
    },
    .{
        .name = "L1OriginTooOld",
        .selector = reverts.l1_origin_too_old,
        .failure = .l1_origin_too_old,
    },
    .{
        .name = "InvalidParentGame",
        .selector = reverts.invalid_parent_game,
        .failure = .invalid_parent_game,
    },
    .{ .name = "InvalidSigner", .selector = reverts.invalid_signer, .failure = .invalid_signer },
};

/// Classifies a JSON-RPC error by its revert data (selector prefix), or by a selector or
/// error name in its message; anything else is a plain revert.
pub fn classify(message: []const u8, data: []const u8) SubmitFailure {
    var hex_buffer: [10]u8 = undefined;
    for (known) |entry| {
        const hex = std.fmt.bufPrint(&hex_buffer, "0x{x}", .{&entry.selector}) catch unreachable;
        if (std.ascii.startsWithIgnoreCase(data, hex)) return entry.failure;
        if (std.ascii.findIgnoreCase(message, hex[2..]) != null) return entry.failure;
        if (names_error(message, entry.name)) return entry.failure;
    }
    assert(hex_buffer.len == 10);
    return .reverted;
}

/// Whether `text` names `name` itself, not a longer identifier starting with it.
fn names_error(text: []const u8, name: []const u8) bool {
    assert(name.len > 0);
    var start: usize = 0;
    while (std.mem.indexOfPos(u8, text, start, name)) |index| {
        const end = index + name.len;
        if (end == text.len) return true;
        const next = text[end];
        if (!std.ascii.isAlphanumeric(next) and next != '_') return true;
        start = index + 1;
    }
    return false;
}

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: Address,
    factory: Address,
    game_type: u32,
    /// Added to the gas estimate, in percent.
    gas_buffer_percent: u8 = 20,
    tip_wei_default: u128 = 1_000_000_000,
    receipt_polls_max: u32 = 120,
    slots_max: u8 = 4,
    calldata_bytes_max: u32 = factory.extra_data_bytes_max + 1024,
};

pub fn TxSubmitter(comptime EndpointType: type) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            id: interfaces.TxId = 0,
            used: bool = false,
            hash: [32]u8 = @splat(0),
            value: u256 = 0,
            polls: u32 = 0,
            calldata: []u8,
            calldata_length: u32 = 0,
        };

        l1: *EndpointType,
        config: Config,
        slots: []Slot,
        next_id: interfaces.TxId = 1,
        /// Why the last `unavailable` happened, for logs.
        last_failure: ?anyerror = null,

        pub fn init(allocator: std.mem.Allocator, l1: *EndpointType, config: Config) !Self {
            assert(config.slots_max > 0);
            assert(config.gas_buffer_percent <= 100);
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

        pub fn submitter(self: *Self) interfaces.Submitter {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: interfaces.Submitter.VTable = .{ .send = send, .status = status };

        fn of(context: *anyopaque) *Self {
            const self: *Self = @ptrCast(@alignCast(context));
            self.l1.reset();
            return self;
        }

        fn failed_call(self: *Self, err: endpoint_module.Error) SubmitFailure {
            self.last_failure = err;
            const failure = self.l1.last_error orelse return .unavailable;
            assert(err == error.NotFound);
            return classify(failure.message, failure.data);
        }

        fn send(context: *anyopaque, calldata: []const u8) interfaces.SendResult {
            const self = of(context);
            if (calldata.len > self.config.calldata_bytes_max) return .{ .failed = .reverted };
            const slot = for (self.slots) |*slot| {
                if (!slot.used) break slot;
            } else return .{ .failed = .unavailable };
            const value = self.init_bond() catch |err| {
                self.last_failure = err;
                return .{ .failed = .unavailable };
            };
            const request = self.transaction(calldata, value);
            const estimate = self.l1.call("eth_estimateGas", &.{.{ .transaction = request }});
            const estimate_raw = estimate catch |err| return .{ .failed = self.failed_call(err) };
            const gas = endpoint_module.parse_quantity(estimate_raw) catch
                return .{ .failed = .unavailable };
            const hash = self.broadcast(calldata, value, gas) catch |err| {
                return .{ .failed = self.failed_call(err) };
            };
            slot.* = .{
                .id = self.next_id,
                .used = true,
                .hash = hash,
                .value = value,
                .calldata = slot.calldata,
                .calldata_length = @intCast(calldata.len),
            };
            @memcpy(slot.calldata[0..calldata.len], calldata);
            self.next_id += 1;
            return .{ .pending = slot.id };
        }

        fn transaction(
            self: *const Self,
            calldata: []const u8,
            value: u256,
        ) endpoint_module.Transaction {
            return .{
                .from = self.config.from,
                .to = self.config.factory,
                .value = value,
                .data = calldata,
            };
        }

        fn init_bond(self: *Self) endpoint_module.Error!u256 {
            var buffer: [4 + 32]u8 = undefined;
            const data = abi.encode_call(&buffer, factory.init_bonds, &.{
                .{ .uint = self.config.game_type },
            }) catch unreachable; // One static word always fits.
            const l1: clients.Execution(EndpointType) = .{ .endpoint = self.l1 };
            const result = try l1.call_contract(self.config.factory, data, .latest);
            return (abi.Decoder{ .data = result }).uint(u256, 0) catch error.CallFailed;
        }

        /// Signs and sends the creation; returns its hash.
        fn broadcast(
            self: *Self,
            calldata: []const u8,
            value: u256,
            gas_estimate: u64,
        ) endpoint_module.Error![32]u8 {
            const config = self.config;
            const nonce_raw = try self.l1.call("eth_getTransactionCount", &.{
                .{ .address = config.from },
                .{ .string = "pending" },
            });
            const nonce = try endpoint_module.parse_quantity(nonce_raw);
            const fees = txdata.suggest_fees(try self.base_fee(), self.tip());
            const buffer_gas = gas_estimate / 100 * config.gas_buffer_percent;
            const envelope = txdata.sign_eip1559(.{
                .chain_id = config.chain_id,
                .nonce = nonce,
                .fees = fees,
                .gas_limit = @max(gas_estimate +| buffer_gas, 21_000),
                .to = .{ .bytes = config.factory },
                .value = value,
                .data = calldata,
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

        fn status(context: *anyopaque, id: interfaces.TxId) interfaces.TxStatus {
            const self = of(context);
            const slot = for (self.slots) |*slot| {
                if (slot.used and slot.id == id) break slot;
            } else return .{ .failed = .dropped };
            const receipt = self.l1.call("eth_getTransactionReceipt", &.{.{ .hash = slot.hash }});
            const raw = receipt catch |err| switch (err) {
                error.NotFound => {
                    if (self.l1.last_error != null) return .pending;
                    slot.polls += 1;
                    if (slot.polls < self.config.receipt_polls_max) return .pending;
                    slot.used = false;
                    return .{ .failed = .dropped };
                },
                error.CallFailed => return .pending,
            };
            const result = self.settle(slot, raw) catch return .pending;
            slot.used = false;
            return result;
        }

        /// A receipt's outcome; a failed one is replayed at its block for the revert data.
        fn settle(self: *Self, slot: *const Slot, raw: []const u8) !interfaces.TxStatus {
            const status_raw = try endpoint_module.member(raw, &.{"status"});
            if (try endpoint_module.parse_quantity(status_raw) == 1) return .mined;
            const block_raw = try endpoint_module.member(raw, &.{"blockNumber"});
            const block = try endpoint_module.parse_quantity(block_raw);
            const calldata = slot.calldata[0..slot.calldata_length];
            const replay = self.l1.call("eth_call", &.{
                .{ .transaction = self.transaction(calldata, slot.value) },
                .{ .number = block },
            });
            _ = replay catch |err| return .{ .failed = self.failed_call(err) };
            return .{ .failed = .reverted };
        }
    };
}

const testing = std.testing;

test "tx submitter: classifies reverts by data, selector text and name" {
    var hex: [10]u8 = undefined;
    const exists = try std.fmt.bufPrint(&hex, "0x{x}", .{&factory.game_already_exists});
    const by_data = classify("execution reverted", exists);
    try testing.expectEqual(SubmitFailure.game_already_exists, by_data);
    try testing.expectEqual(SubmitFailure.invalid_parent_game, classify(
        "execution reverted: InvalidParentGame()",
        "",
    ));
    try testing.expectEqual(SubmitFailure.invalid_signer, classify("InvalidSigner", ""));
    // A longer identifier is a different error.
    try testing.expectEqual(SubmitFailure.reverted, classify("InvalidSignerType()", ""));
    try testing.expectEqual(SubmitFailure.reverted, classify("execution reverted", "0x12345678"));
    var message: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&message, "custom error {x}", .{&reverts.l1_origin_too_old});
    try testing.expectEqual(SubmitFailure.l1_origin_too_old, classify(text, ""));
}

test "tx submitter: fuzz the classifier" {
    const fuzz = @import("../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var message: [96]u8 = undefined;
            var data: [24]u8 = undefined;
            const message_length = smith.slice(&message);
            const data_length = smith.slice(&data);
            const result = classify(message[0..message_length], data[0..data_length]);
            // Without a selector or name in either string, it is a plain revert.
            if (message_length == 0 and data_length < 10) {
                try testing.expectEqual(SubmitFailure.reverted, result);
            }
        }
    }.one, .{ .iterations = 2000 });
}

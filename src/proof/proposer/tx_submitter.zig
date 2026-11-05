//! The proposer's `Submitter` over JSON-RPC (base/base `OutputProposer` over its
//! `TxManager`, with `crates/proof/submission` revert classification).
//!
//! `send` reads the game type's init bond (`initBonds`), then hands a `createWithInitData`
//! transaction carrying the bond to the shared `submission.Sender` (estimation, EIP-1559
//! signing at the pending nonce, broadcast). `status` polls the sender, which replays a
//! failed receipt for its revert data and reports a transaction without a receipt after
//! `receipt_polls_max` polls as dropped. JSON-RPC errors are classified into
//! `SubmitFailure`s through the shared classifier.

const std = @import("std");
const assert = std.debug.assert;

const clients = @import("../rpc/clients.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const aggregate_verifier = @import("../contracts/aggregate_verifier.zig");
const submission = @import("../submission/root.zig");
const interfaces = @import("interfaces.zig");

const Address = interfaces.Address;
const SubmitFailure = interfaces.SubmitFailure;

/// Aggregate verifier errors the submission path recognizes (base/base `KnownRevert`).
pub const reverts = struct {
    pub const l1_origin_too_old = aggregate_verifier.error_l1_origin_too_old;
    pub const invalid_parent_game = aggregate_verifier.error_invalid_parent_game;
    pub const invalid_signer = aggregate_verifier.error_invalid_signer;
};

/// Classifies a JSON-RPC error by its revert data (selector prefix), or by a selector or
/// error name in its message; anything else, including reverts the proposer does not act
/// on (`AlreadyProven`, `InvalidProof`), is a plain revert.
pub fn classify(message: []const u8, data: []const u8) SubmitFailure {
    const known = submission.classify(message, data) orelse return .reverted;
    const failure: SubmitFailure = switch (known) {
        .game_already_exists => .game_already_exists,
        .l1_origin_too_old => .l1_origin_too_old,
        .invalid_parent_game => .invalid_parent_game,
        .invalid_signer => .invalid_signer,
        .proof_already_verified, .invalid_proof => .reverted,
    };
    assert(failure != .unavailable);
    return failure;
}

fn failure_of(failure: submission.sender.Failure) SubmitFailure {
    return switch (failure) {
        .rpc_error => |rpc_error| classify(rpc_error.message, rpc_error.data),
        .reverted => .reverted,
        .unavailable => .unavailable,
        .dropped => .dropped,
    };
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
        const Sender = submission.Sender(EndpointType);

        l1: *EndpointType,
        config: Config,
        sender: Sender,

        pub fn init(allocator: std.mem.Allocator, l1: *EndpointType, config: Config) !Self {
            assert(config.slots_max > 0);
            assert(!std.mem.allEqual(u8, &config.factory, 0));
            const sender = try Sender.init(allocator, l1, .{
                .chain_id = config.chain_id,
                .private_key = config.private_key,
                .from = config.from,
                .gas_buffer_percent = config.gas_buffer_percent,
                .tip_wei_default = config.tip_wei_default,
                .receipt_polls_max = config.receipt_polls_max,
                .slots_max = config.slots_max,
                .calldata_bytes_max = config.calldata_bytes_max,
            });
            return .{ .l1 = l1, .config = config, .sender = sender };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.sender.deinit(allocator);
            self.* = undefined;
        }

        /// Why the last `unavailable` happened, for logs.
        pub fn last_failure(self: *const Self) ?anyerror {
            return self.sender.last_failure;
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

        fn send(context: *anyopaque, calldata: []const u8) interfaces.SendResult {
            const self = of(context);
            if (calldata.len > self.config.calldata_bytes_max) return .{ .failed = .reverted };
            if (!self.sender.has_free_slot()) return .{ .failed = .unavailable };
            const value = self.init_bond() catch |err| {
                self.sender.last_failure = err;
                return .{ .failed = .unavailable };
            };
            const sent = self.sender.send(.{
                .to = self.config.factory,
                .value = value,
                .calldata = calldata,
            });
            return switch (sent) {
                .pending => |id| .{ .pending = id },
                .failed => |failure| .{ .failed = failure_of(failure) },
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

        fn status(context: *anyopaque, id: interfaces.TxId) interfaces.TxStatus {
            const self = of(context);
            return switch (self.sender.status(id)) {
                .pending => .pending,
                .mined => .mined,
                .failed => |failure| .{ .failed = failure_of(failure) },
            };
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

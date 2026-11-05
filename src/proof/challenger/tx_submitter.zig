//! The challenger's `Submitter` over JSON-RPC (base/base `ChallengeSubmitter` over its
//! `TxManager`, with `crates/proof/submission` revert classification).
//!
//! `nullify`/`challenge`, `resolve`/`claimCredit` (bond unlock and withdrawal) and
//! `setAnchorState` calldata goes out through the shared `submission.Sender` without value.
//! A JSON-RPC error carrying a known revert (data selector through
//! `aggregate_verifier.classify_revert`, or a selector or error name in the message) is
//! `known_revert`; an unknown one is `execution_reverted` at
//! estimation, `tx_reverted` from a failed receipt's replay and `other` at broadcast
//! (nonce, fees). A failed receipt whose replay passes is `tx_reverted`; transport
//! failures and dropped transactions are `other`.

const std = @import("std");
const assert = std.debug.assert;

const submission = @import("../submission/root.zig");
const chain = @import("chain.zig");

const Failure = submission.sender.Failure;

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: chain.Address,
    /// Added to the gas estimate, in percent.
    gas_buffer_percent: u8 = 20,
    tip_wei_default: u128 = 1_000_000_000,
    receipt_polls_max: u32 = 120,
    /// Polls without a receipt before a fee-bumped resubmission (0: never).
    resubmit_polls: u32 = 0,
    slots_max: u8 = 8,
    /// Dispute calldata carries the proof bytes (a TEE signature or an SP1 PLONK proof).
    calldata_bytes_max: u32 = 16 * 1024,
};

/// Maps a sender failure onto the challenger's `SubmitError`.
pub fn submit_error(failure: Failure) chain.SubmitError {
    return switch (failure) {
        .rpc_error => |rpc_error| {
            const known = submission.classify(rpc_error.message, rpc_error.data);
            if (known) |revert| return .{ .known_revert = revert };
            return switch (rpc_error.phase) {
                .estimate => .execution_reverted,
                .replay => .tx_reverted,
                .broadcast => .other,
            };
        },
        .reverted => .tx_reverted,
        .unavailable, .dropped => .other,
    };
}

pub fn TxSubmitter(comptime EndpointType: type) type {
    return struct {
        const Self = @This();
        const Sender = submission.Sender(EndpointType);

        config: Config,
        sender: Sender,

        pub fn init(allocator: std.mem.Allocator, l1: *EndpointType, config: Config) !Self {
            assert(config.slots_max > 0);
            assert(!chain.is_zero(config.from));
            const sender = try Sender.init(allocator, l1, .{
                .chain_id = config.chain_id,
                .private_key = config.private_key,
                .from = config.from,
                .gas_buffer_percent = config.gas_buffer_percent,
                .tip_wei_default = config.tip_wei_default,
                .receipt_polls_max = config.receipt_polls_max,
                .resubmit_polls = config.resubmit_polls,
                .slots_max = config.slots_max,
                .calldata_bytes_max = config.calldata_bytes_max,
            });
            return .{ .config = config, .sender = sender };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.sender.deinit(allocator);
            self.* = undefined;
        }

        /// Why the last `other` happened, for logs.
        pub fn last_failure(self: *const Self) ?anyerror {
            return self.sender.last_failure;
        }

        pub fn submitter(self: *Self) chain.Submitter {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: chain.Submitter.VTable = .{ .send = send, .status = status };

        fn of(context: *anyopaque) *Self {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.config.slots_max > 0);
            return self;
        }

        fn send(context: *anyopaque, tx: chain.Tx) chain.SendResult {
            const self = of(context);
            assert(tx.calldata.len >= 4);
            if (tx.calldata.len > self.config.calldata_bytes_max) {
                return .{ .rejected = .other };
            }
            const sent = self.sender.send(.{ .to = tx.to, .value = 0, .calldata = tx.calldata });
            return switch (sent) {
                .pending => |id| .{ .queued = id },
                .failed => |failure| .{ .rejected = submit_error(failure) },
            };
        }

        fn status(context: *anyopaque, ticket: chain.Ticket) chain.TxStatus {
            const self = of(context);
            return switch (self.sender.status(ticket)) {
                .pending => .pending,
                .mined => .mined,
                .failed => |failure| .{ .failed = submit_error(failure) },
            };
        }
    };
}

const testing = std.testing;

test "challenger tx submitter: failures map onto submit errors" {
    const unknown: Failure = .{ .rpc_error = .{
        .phase = .estimate,
        .message = "execution reverted",
        .data = "0x",
    } };
    try testing.expectEqual(chain.SubmitError.execution_reverted, submit_error(unknown));
    var replay = unknown;
    replay.rpc_error.phase = .replay;
    try testing.expectEqual(chain.SubmitError.tx_reverted, submit_error(replay));
    var broadcast = unknown;
    broadcast.rpc_error.phase = .broadcast;
    broadcast.rpc_error.message = "nonce too low";
    try testing.expectEqual(chain.SubmitError.other, submit_error(broadcast));
    var named = unknown;
    named.rpc_error.message = "execution reverted: InvalidProof()";
    const invalid: chain.SubmitError = .{ .known_revert = .invalid_proof };
    try testing.expectEqual(invalid, submit_error(named));
    try testing.expectEqual(chain.SubmitError.tx_reverted, submit_error(.reverted));
    try testing.expectEqual(chain.SubmitError.other, submit_error(.dropped));
    try testing.expectEqual(chain.SubmitError.other, submit_error(.unavailable));
}

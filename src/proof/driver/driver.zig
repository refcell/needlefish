//! The derive-and-execute loop of the fault-proof program. Port of base/base
//! `crates/proof/driver/src/core.rs` (`advance_to_target`).
//!
//! Each round steps the derivation pipeline from the current safe head; prepared
//! attributes are executed by the stateless builder and become the new safe head (with
//! its output root). When L1 runs out (`NotFound` advancing the origin with no provider
//! failure) derivation halts at the current safe head. From Holocene a block that fails
//! to execute is retried with its deposits only after flushing the channel.

const std = @import("std");
const assert = std.debug.assert;

const consensus = @import("../../common/consensus/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const derive = @import("../../consensus/derive/root.zig");
const payload = @import("../../execution/payload/root.zig");
const executor = @import("../executor/root.zig");
const program = @import("../program/root.zig");
const mpt = @import("../mpt/root.zig");

const Hash = [32]u8;
const L2BlockInfo = protocol.L2BlockInfo;
const Pipeline = derive.pipeline.Pipeline;
const AttributesWithParent = derive.attributes_queue.AttributesWithParent;

pub const Error = derive.errors.Error || executor.builder.Error ||
    program.l2_chain_provider.Failure || error{
    /// A provider recorded an oracle or validation failure.
    ProviderFailed,
    /// A deposit-only retry failed too.
    DepositOnlyFailed,
    /// The step bound was reached.
    TooManySteps,
};

/// Pipeline steps one `advance_to_target` may take.
pub const steps_max: u64 = 1 << 32;

pub const Tip = struct {
    info: L2BlockInfo,
    header: consensus.Header,
    output_root: Hash,
};

pub const Driver = struct {
    rollup: *const protocol.RollupConfig,
    pipeline: *Pipeline,
    l1: *program.L1ChainProvider,
    blobs: *program.L1BlobProvider,
    l2: *program.L2ChainProvider,
    builder: *executor.Builder,
    /// The resolver behind the chain providers; emptied between steps when half full.
    resolver: *mpt.OracleResolver,
    tip: Tip,
    /// Set when L1 ran out before the target.
    exhausted: bool = false,

    /// Resets the pipeline to the safe head `tip`.
    pub fn reset(self: *Driver) Error!void {
        const signal: derive.pipeline.Signal = .{ .reset = .{ .l2_safe_head = self.tip.info } };
        try self.pipeline.signal(self.l1, self.l2, signal);
        try self.check_providers();
    }

    fn check_providers(self: *const Driver) Error!void {
        const failed = self.l1.failure != null or self.blobs.failure != null or
            self.l2.failure != null;
        if (failed) return error.ProviderFailed;
    }

    /// Derives and executes blocks until the safe head reaches `target` or L1 runs out.
    pub fn advance_to_target(self: *Driver, target: u64) Error!void {
        var steps: u64 = 0;
        while (self.tip.info.block_info.number < target) : (steps += 1) {
            if (steps >= steps_max) return error.TooManySteps;
            // Stages copy what they keep, so provider data need not outlive a step.
            if (self.resolver.arena_used > self.resolver.arena.len / 2) self.resolver.reset();
            const result = self.pipeline.step(self.l1, self.blobs, self.l2, self.tip.info);
            switch (result) {
                .prepared_attributes => while (self.pipeline.next()) |prepared| {
                    var owned = prepared;
                    defer owned.deinit(self.pipeline.allocator);
                    try self.execute(&owned);
                },
                .advanced_origin => {},
                .origin_advance_err => |err| {
                    try self.check_providers();
                    if (err == error.NotFound) {
                        self.exhausted = true;
                        return;
                    }
                    try self.handle_error(err);
                },
                .step_failed => |err| {
                    try self.check_providers();
                    try self.handle_error(err);
                },
            }
        }
        assert(self.tip.info.block_info.number >= target);
    }

    fn handle_error(self: *Driver, err: derive.errors.Error) Error!void {
        switch (derive.errors.kind(err)) {
            .temporary => {},
            .reset => try self.reset(),
            .critical => return err,
        }
    }

    fn execute(self: *Driver, prepared: *AttributesWithParent) Error!void {
        assert(prepared.parent.eql(self.tip.info));
        var attributes = engine_attributes(&prepared.attributes);
        const parent_hash = self.tip.info.block_info.hash.bytes;
        const parent = &self.tip.header;
        const outcome = self.builder.build_block(parent, parent_hash, &attributes) catch |err| {
            const feature = .deposits_only_on_invalid_payload;
            const retry = self.rollup.is_feature_active(feature, attributes.timestamp);
            if (!retry or !deposit_only_retryable(err)) return err;
            try self.pipeline.signal(self.l1, self.l2, .flush_channel);
            const transactions = prepared.attributes.transactions;
            attributes.transactions = transactions[0..keep_deposits(transactions)];
            const retried = self.builder.build_block(parent, parent_hash, &attributes) catch {
                return error.DepositOnlyFailed;
            };
            return self.advance_tip(&retried, attributes.transactions.?);
        };
        try self.advance_tip(&outcome, attributes.transactions.?);
    }

    fn advance_tip(
        self: *Driver,
        outcome: *const executor.builder.Outcome,
        transactions: []const []const u8,
    ) Error!void {
        const l1_info = try program.l2_chain_provider.decode_l1_info(transactions);
        const header = &outcome.header;
        const block_info: protocol.BlockInfo = .{
            .hash = .{ .bytes = outcome.hash },
            .number = header.number,
            .parent_hash = header.parent_hash,
            .timestamp = header.timestamp,
        };
        const info: L2BlockInfo = .{
            .block_info = block_info,
            .l1_origin = l1_info.id(),
            .sequence_number = l1_info.sequence_number,
        };
        const fields: protocol.l2_system_config.BlockFields = .{
            .number = header.number,
            .hash = block_info.hash,
            .timestamp = header.timestamp,
            .gas_limit = header.gas_limit,
            .extra_data = header.extra_data,
        };
        const l2_system_config = protocol.l2_system_config;
        const system_config = l2_system_config.from_l1_info(self.rollup, &l1_info, fields) catch {
            return error.InvalidSystemConfig;
        };
        const output_root = try self.builder.output_root(header, outcome.hash);
        self.l2.set_head(block_info);
        self.l2.remember(info, system_config);
        self.tip = .{ .info = info, .header = header.*, .output_root = output_root };
        assert(self.tip.info.block_info.number == block_info.number);
    }
};

/// Moves deposits (type 0x7e) to the front, in order, and returns their count.
fn keep_deposits(transactions: [][]u8) usize {
    var count: usize = 0;
    for (transactions, 0..) |transaction, index| {
        if (transaction.len == 0 or transaction[0] != deposit_type) continue;
        std.mem.swap([]u8, &transactions[count], &transactions[index]);
        count += 1;
    }
    assert(count <= transactions.len);
    return count;
}

const deposit_type: u8 = 0x7e;

fn engine_attributes(
    attributes: *const derive.attributes.PayloadAttributes,
) payload.PayloadAttributes {
    return .{
        .timestamp = attributes.timestamp,
        .prev_randao = attributes.prev_randao,
        .suggested_fee_recipient = attributes.suggested_fee_recipient,
        .withdrawals = attributes.withdrawals,
        .parent_beacon_block_root = attributes.parent_beacon_block_root,
        .transactions = attributes.transactions,
        .no_tx_pool = attributes.no_tx_pool,
        .gas_limit = attributes.gas_limit,
        .eip1559_params = attributes.eip1559_params,
        .min_base_fee = attributes.min_base_fee,
    };
}

/// Whether a failed block is replaced by its deposits (Holocene). Only block-validity
/// failures qualify (base/base `ExecutorError::is_deposit_only_retryable`); a missing
/// preimage, a hint failure or an exhausted configured bound would turn a valid block into
/// a wrong deposit-only one, so those fail the proof instead.
pub fn deposit_only_retryable(err: executor.builder.Error) bool {
    return switch (err) {
        error.InvalidTransaction,
        error.BlockGasExceeded,
        error.BlobGasExceeded,
        error.TxTypeNotSupported,
        => true,
        else => false,
    };
}

test "driver: only block-validity failures retry with deposits only" {
    try std.testing.expect(deposit_only_retryable(error.InvalidTransaction));
    try std.testing.expect(deposit_only_retryable(error.BlockGasExceeded));
    try std.testing.expect(deposit_only_retryable(error.TxTypeNotSupported));
    try std.testing.expect(!deposit_only_retryable(error.StateUnavailable));
    try std.testing.expect(!deposit_only_retryable(error.HintFailed));
    try std.testing.expect(!deposit_only_retryable(error.TooManyTransactions));
    try std.testing.expect(!deposit_only_retryable(error.ScratchFull));
    try std.testing.expect(!deposit_only_retryable(error.CodeArenaFull));
    try std.testing.expect(!deposit_only_retryable(error.InvalidAttributes));
}

test "driver: deposit-only filtering keeps deposits in order" {
    var a = [_]u8{ 0x7e, 1 };
    var b = [_]u8{ 0x02, 2 };
    var c = [_]u8{ 0x7e, 3 };
    var empty = [_]u8{};
    var transactions = [_][]u8{ &a, &b, &empty, &c };
    const count = keep_deposits(&transactions);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(u8, 1), transactions[0][1]);
    try std.testing.expectEqual(@as(u8, 3), transactions[1][1]);
}

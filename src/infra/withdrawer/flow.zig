//! The withdrawal operation (base/base `crates/infra/withdrawer/src/operation.rs` `run`):
//! initiate on L2, then per withdrawal of the initiating receipt decide, prove against a
//! dispute game, wait out the delays, and finalize.
//!
//! Step-driven and IO-free: `step(now_ms)` performs the reads and sends that are due through
//! the injected JSON-RPC clients and returns whether it is working, waiting, or done; the
//! binary loops and sleeps. Every broadcast hash is appended to the journal before it leaves
//! (the tx_manager publish hook), so a restarted run first settles the hashes a crashed run
//! left pending instead of sending again. Sends go through the tx_manager driver (fee
//! suggestion, bumping, confirmation depth); receipts are then checked for success and, for
//! finalization, for the portal's `WithdrawalFinalized(success)` event.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const tx_manager = @import("../tx_manager/root.zig");
const calldata = @import("calldata.zig");
const journal_module = @import("journal.zig");
const reader_module = @import("reader.zig");
const status_module = @import("status.zig");
const withdrawal_module = @import("withdrawal.zig");

const Address = withdrawal_module.Address;
const Hash = withdrawal_module.Hash;
const Withdrawal = withdrawal_module.Withdrawal;
pub const Status = status_module.Status;
const Record = journal_module.Record;
const JournalStep = journal_module.Step;

pub const SendDriver = tx_manager.Driver(.{
    .sends_max = 1,
    .hashes_max = journal_module.hashes_max,
});
pub const GameSearch = status_module.GameSearch(.{});

pub const Command = enum { initiate, status, prove, finalize, run };

pub const Initiate = struct {
    target: Address,
    value: u256 = 0,
    gas_limit: u256 = 100_000,
    data: []const u8 = &.{},
};

pub const Config = struct {
    command: Command,
    /// The initiating L2 transaction; null with `initiate` set sends one first.
    l2_transaction: ?Hash = null,
    initiate: ?Initiate = null,
    poll_interval_ms: u64 = 12_000,
    /// How long journaled broadcasts of a crashed run may stay unmined before resending.
    pending_wait_ms: u64 = 180_000,
    /// Consecutive failed RPC rounds tolerated before giving up.
    rpc_failures_max: u32 = 20,
    /// Optional: only withdrawals it accepts are handled (null handles every withdrawal of
    /// the receipt). A receipt with none accepted fails with `NoMatchingWithdrawal`.
    filter: ?WithdrawalFilter = null,
    /// Optional tx_manager metrics fed with this flow's sends and completions.
    tx_metrics: ?*tx_manager.metrics.Metrics = null,
};

/// Selects the withdrawals a flow handles (fee-jobs `confirm`: the FeeDisburser's own).
pub const WithdrawalFilter = struct {
    context: ?*const anyopaque = null,
    accept: *const fn (context: ?*const anyopaque, withdrawal: *const Withdrawal) bool,
};

/// Appends one record durably (the binary writes and syncs the journal file).
pub const JournalSink = struct {
    context: *anyopaque,
    append: *const fn (context: *anyopaque, record: Record) bool,
};

pub const Progress = union(enum) {
    working,
    waiting: struct { until_ms: u64 },
    done,
};

pub const Outcome = struct {
    withdrawal_hash: Hash,
    /// The last decision before any submission.
    status: Status,
    /// The confirmed L1 transaction of this run, if any.
    transaction: ?Hash = null,
};

pub const Error = reader_module.Error || status_module.Error || tx_manager.driver.Error ||
    error{
        JournalFailed,
        SendFailed,
        Reverted,
        TargetCallFailed,
        MissingFinalizationEvent,
        NothingToInitiate,
        NoSpaceLeft,
        NoMatchingWithdrawal,
    };

const Phase = enum {
    initiate,
    initiate_wait,
    load,
    decide,
    search,
    submit,
    pending,
    send_wait,
    next,
    done,
};

/// `submit` prepares a send for this step of the current withdrawal.
const Send = struct { step: JournalStep, subject: Hash, started_ms: u64 = 0 };

pub const Flow = struct {
    config: Config,
    reader: *reader_module.Reader,
    l1_driver: *SendDriver,
    l2_driver: ?*SendDriver,
    sink: JournalSink,
    replay: journal_module.Replay,
    phase: Phase = .initiate,
    wait_until_ms: u64 = 0,
    rpc_failures: u32 = 0,
    withdrawals: [withdrawal_module.withdrawals_max]Withdrawal = undefined,
    withdrawal_count: u32 = 0,
    index: u32 = 0,
    outcomes: [withdrawal_module.withdrawals_max]Outcome = undefined,
    outcome_count: u32 = 0,
    prepared_length: u32 = 0,
    send: Send = .{ .step = .prove, .subject = @splat(0) },
    send_id: u64 = 0,
    /// Calldata of the current send (copied by the driver on `send`).
    calldata_buffer: []u8,
    l2_transaction: ?Hash = null,
    /// Hashes of the receipt's withdrawals the filter rejected (the caller logs them).
    skipped: [withdrawal_module.withdrawals_max]Hash = undefined,
    skipped_count: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        reader: *reader_module.Reader,
        l1_driver: *SendDriver,
        l2_driver: ?*SendDriver,
        sink: JournalSink,
        replay: journal_module.Replay,
    ) !Flow {
        assert(config.poll_interval_ms > 0);
        const buffer = try allocator.alloc(u8, 8 * withdrawal_module.data_bytes_max);
        var flow: Flow = .{
            .config = config,
            .reader = reader,
            .l1_driver = l1_driver,
            .l2_driver = l2_driver,
            .sink = sink,
            .replay = replay,
            .calldata_buffer = buffer,
            .l2_transaction = config.l2_transaction,
        };
        flow.phase = if (flow.l2_transaction != null) .load else .initiate;
        if (flow.phase == .initiate and config.initiate == null) {
            const resumed = replay.step(.initiate).confirmed;
            flow.l2_transaction = if (resumed) |confirmed| confirmed.transaction else null;
            if (flow.l2_transaction == null) {
                allocator.free(buffer);
                return error.NothingToInitiate;
            }
            flow.phase = .load;
        }
        assert(flow.phase == .load or config.initiate != null);
        return flow;
    }

    pub fn deinit(flow: *Flow, allocator: std.mem.Allocator) void {
        allocator.free(flow.calldata_buffer);
        flow.* = undefined;
    }

    /// The withdrawals handled so far with their decisions.
    pub fn results(flow: *const Flow) []const Outcome {
        assert(flow.outcome_count <= flow.withdrawal_count);
        return flow.outcomes[0..flow.outcome_count];
    }

    /// Publish hook for the drivers: journal the hash before it is broadcast.
    pub fn publish_hook(flow: *Flow) tx_manager.driver.PublishHook {
        return .{ .context = flow, .before_publish = before_publish };
    }

    fn before_publish(context: *anyopaque, id: u64, nonce: u64, hash: Hash) bool {
        const flow: *Flow = @ptrCast(@alignCast(context));
        assert(id > 0);
        return flow.record(.{
            .step = flow.send.step,
            .event = .broadcast,
            .subject = flow.send.subject,
            .transaction = hash,
            .nonce = nonce,
        });
    }

    fn record(flow: *Flow, entry: Record) bool {
        if (!flow.sink.append(flow.sink.context, entry)) return false;
        flow.replay.apply(entry);
        assert(flow.replay.records > 0);
        return true;
    }

    pub fn step(flow: *Flow, now_ms: u64) Error!Progress {
        if (flow.phase == .done) return .done;
        if (now_ms < flow.wait_until_ms) return .{ .waiting = .{ .until_ms = flow.wait_until_ms } };
        flow.step_phase(now_ms) catch |err| {
            if (!transient(err)) return err;
            flow.rpc_failures += 1;
            if (flow.rpc_failures > flow.config.rpc_failures_max) return err;
            flow.wait(now_ms);
        };
        if (flow.phase == .done) return .done;
        if (now_ms < flow.wait_until_ms) return .{ .waiting = .{ .until_ms = flow.wait_until_ms } };
        return .working;
    }

    fn transient(err: Error) bool {
        return switch (err) {
            error.TransportFailed, error.ResponseTooLarge, error.RpcError => true,
            error.MalformedResponse, error.MissingReceipt, error.MissingBlock => true,
            else => false,
        };
    }

    fn wait(flow: *Flow, now_ms: u64) void {
        flow.wait_until_ms = now_ms + flow.config.poll_interval_ms;
        assert(flow.wait_until_ms > now_ms);
    }

    fn step_phase(flow: *Flow, now_ms: u64) Error!void {
        switch (flow.phase) {
            .initiate => try flow.start_initiate(now_ms),
            .initiate_wait => try flow.await_initiate(now_ms),
            .load => try flow.load(),
            .decide => try flow.decide(now_ms),
            .search => try flow.search(now_ms),
            .submit => try flow.submit(now_ms),
            .pending => try flow.settle_pending(now_ms),
            .send_wait => try flow.await_send(now_ms),
            .next => flow.advance(),
            .done => unreachable,
        }
        flow.rpc_failures = 0;
    }

    fn current(flow: *Flow) *Withdrawal {
        assert(flow.index < flow.withdrawal_count);
        return &flow.withdrawals[flow.index];
    }

    fn start_initiate(flow: *Flow, now_ms: u64) Error!void {
        const initiate = flow.config.initiate.?;
        const input = try calldata.encode_initiate(
            flow.calldata_buffer,
            initiate.target,
            initiate.gas_limit,
            initiate.data,
        );
        flow.send = .{ .step = .initiate, .subject = withdrawal_module.keccak256(input) };
        const state = flow.replay.step(.initiate);
        const same = std.mem.eql(u8, &state.subject, &flow.send.subject);
        if (same and state.confirmed != null) {
            // A previous run already initiated this exact withdrawal.
            flow.l2_transaction = state.confirmed.?.transaction;
            return flow.after_initiate();
        }
        if (flow.has_pending()) {
            flow.send.started_ms = now_ms;
            flow.phase = .pending;
            return;
        }
        const driver = flow.l2_driver.?;
        flow.send_id = try driver.send(flow.reader.l2, .{
            .to = .{ .bytes = withdrawal_module.message_passer },
            .value = initiate.value,
            .data = input,
        }, now_ms);
        if (flow.config.tx_metrics) |tx_metrics| tx_metrics.on_submit();
        flow.phase = .initiate_wait;
    }

    fn after_initiate(flow: *Flow) void {
        assert(flow.l2_transaction != null);
        flow.phase = if (flow.config.command == .initiate) .done else .load;
    }

    fn await_initiate(flow: *Flow, now_ms: u64) Error!void {
        const driver = flow.l2_driver.?;
        try driver.step(flow.reader.l2, now_ms);
        const completion = driver.take_completion() orelse return flow.wait_short(now_ms);
        if (flow.config.tx_metrics) |tx_metrics| tx_metrics.on_completion(completion, now_ms);
        const hash = try flow.settle_completion(completion, flow.reader.l2, null);
        flow.l2_transaction = hash;
        flow.after_initiate();
    }

    fn wait_short(flow: *Flow, now_ms: u64) void {
        flow.wait_until_ms = now_ms + @max(flow.config.poll_interval_ms / 4, 1);
    }

    fn load(flow: *Flow) Error!void {
        const found = try flow.reader.load_withdrawals(flow.l2_transaction.?, &flow.withdrawals);
        flow.withdrawal_count = @intCast(found.len);
        flow.index = 0;
        assert(flow.withdrawal_count > 0);
        if (flow.config.filter) |filter| try flow.apply_filter(filter);
        flow.phase = .decide;
    }

    /// The withdrawals of the receipt the filter rejected.
    pub fn skipped_withdrawals(flow: *const Flow) []const Hash {
        assert(flow.skipped_count <= withdrawal_module.withdrawals_max);
        return flow.skipped[0..flow.skipped_count];
    }

    /// Keeps the accepted withdrawals in receipt order and records the skipped ones.
    fn apply_filter(flow: *Flow, filter: WithdrawalFilter) Error!void {
        const total = flow.withdrawal_count;
        var kept: u32 = 0;
        flow.skipped_count = 0;
        for (flow.withdrawals[0..total]) |withdrawal| {
            if (filter.accept(filter.context, &withdrawal)) {
                flow.withdrawals[kept] = withdrawal;
                kept += 1;
            } else {
                flow.skipped[flow.skipped_count] = withdrawal.hash();
                flow.skipped_count += 1;
            }
        }
        assert(kept + flow.skipped_count == total);
        flow.withdrawal_count = kept;
        if (kept == 0) return error.NoMatchingWithdrawal;
    }

    fn decide(flow: *Flow, now_ms: u64) Error!void {
        const withdrawal = flow.current();
        var decider: status_module.Decider = .{};
        var reads: u32 = 0;
        while (decider.next()) |read| : (reads += 1) {
            assert(reads < 32);
            try decider.on_answer(try flow.reader.answer(withdrawal, read));
        }
        const status = decider.outcome.?;
        // `run` decides again after each send: keep the transaction already recorded.
        const seen = flow.index < flow.outcome_count;
        flow.outcomes[flow.index] = .{
            .withdrawal_hash = withdrawal.hash(),
            .status = status,
            .transaction = if (seen) flow.outcomes[flow.index].transaction else null,
        };
        flow.outcome_count = @max(flow.outcome_count, flow.index + 1);
        flow.decided(status, now_ms);
    }

    fn decided(flow: *Flow, status: Status, now_ms: u64) void {
        const command = flow.config.command;
        const run = command == .run;
        flow.phase = switch (status) {
            .finalized => .next,
            .paused, .not_ready => if (run) blk: {
                flow.wait(now_ms);
                break :blk .decide;
            } else .next,
            .prove => if (run or command == .prove) .search else .next,
            .finalize => if (run or command == .finalize) .submit else .next,
        };
        const journal_step: JournalStep = if (status == .finalize) .finalize else .prove;
        flow.send = .{ .step = journal_step, .subject = flow.current().hash() };
        // Broadcasts a crashed run left behind are settled before searching for a game.
        if (flow.phase == .search and flow.has_pending()) flow.phase = .submit;
    }

    fn has_pending(flow: *const Flow) bool {
        const state = flow.replay.step(flow.send.step);
        if (!std.mem.eql(u8, &state.subject, &flow.send.subject)) return false;
        return state.pending().len > 0;
    }

    fn search(flow: *Flow, now_ms: u64) Error!void {
        const withdrawal = flow.current();
        var game_search = GameSearch.init(withdrawal.block_number);
        var reads: u64 = 0;
        while (game_search.next()) |read| : (reads += 1) {
            assert(reads < 8 * 100_000);
            try game_search.on_answer(try flow.reader.answer(withdrawal, read));
        }
        switch (game_search.outcome.?) {
            .no_coverage => {
                // Wait for a proposal that covers the withdrawal's block.
                if (flow.config.command != .run) return flow.advance();
                flow.wait(now_ms);
                flow.phase = .decide;
            },
            .found => |candidate| {
                // `answer(.verify)` left the verified proof in the reader.
                const input = try calldata.encode_prove(flow.calldata_buffer, &.{
                    .transaction = &withdrawal.transaction,
                    .game_index = candidate.index,
                    .output = flow.reader.output.?,
                    .proof = flow.reader.proof_nodes.slice(),
                });
                flow.prepared_length = @intCast(input.len);
                flow.send = .{ .step = .prove, .subject = withdrawal.hash() };
                flow.phase = .submit;
            },
        }
    }

    fn submit(flow: *Flow, now_ms: u64) Error!void {
        assert(flow.send.step != .initiate);
        if (flow.has_pending()) {
            flow.send.started_ms = now_ms;
            flow.phase = .pending;
            return;
        }
        if (flow.send.step == .finalize) {
            const input = try calldata.encode_finalize(
                flow.calldata_buffer,
                &flow.current().transaction,
            );
            flow.prepared_length = @intCast(input.len);
        }
        flow.send_id = try flow.l1_driver.send(flow.reader.l1, .{
            .to = .{ .bytes = flow.reader.contracts.portal },
            .data = flow.calldata_buffer[0..flow.prepared_length],
        }, now_ms);
        if (flow.config.tx_metrics) |tx_metrics| tx_metrics.on_submit();
        flow.phase = .send_wait;
    }

    /// Settles broadcasts a crashed run journaled: a mined one counts, otherwise resend
    /// after `pending_wait_ms` (same nonce or a fresh decision, so at most one executes).
    fn settle_pending(flow: *Flow, now_ms: u64) Error!void {
        const state = flow.replay.step(flow.send.step);
        var hashes: [journal_module.hashes_max]Hash = undefined;
        const pending = state.pending();
        @memcpy(hashes[0..pending.len], pending);
        const client = if (flow.send.step == .initiate) flow.reader.l2 else flow.reader.l1;
        for (hashes[0..pending.len]) |hash| {
            const mined = try receipt_status(client, hash) orelse continue;
            const event: journal_module.Event = if (mined.success) .confirmed else .failed;
            if (!flow.record(flow.settle_record(event, hash, mined.block_number))) {
                return error.JournalFailed;
            }
            if (mined.success) flow.note_transaction(hash);
            return flow.after_send();
        }
        if (now_ms -| flow.send.started_ms < flow.config.pending_wait_ms) return flow.wait(now_ms);
        if (!flow.record(flow.settle_record(.failed, @splat(0), 0))) return error.JournalFailed;
        flow.phase = if (flow.send.step == .initiate) .initiate else .decide;
    }

    fn settle_record(
        flow: *const Flow,
        event: journal_module.Event,
        hash: Hash,
        block: u64,
    ) Record {
        return .{
            .step = flow.send.step,
            .event = event,
            .subject = flow.send.subject,
            .transaction = hash,
            .block_number = block,
        };
    }

    fn await_send(flow: *Flow, now_ms: u64) Error!void {
        try flow.l1_driver.step(flow.reader.l1, now_ms);
        const completion = flow.l1_driver.take_completion() orelse return flow.wait_short(now_ms);
        if (flow.config.tx_metrics) |tx_metrics| tx_metrics.on_completion(completion, now_ms);
        const finalize_hash: ?Hash = if (flow.send.step == .finalize) flow.send.subject else null;
        const hash = try flow.settle_completion(completion, flow.reader.l1, finalize_hash);
        flow.note_transaction(hash);
        flow.after_send();
    }

    fn note_transaction(flow: *Flow, hash: Hash) void {
        if (flow.send.step == .initiate) {
            flow.l2_transaction = hash;
            return;
        }
        assert(flow.index < flow.withdrawal_count);
        flow.outcomes[flow.index].transaction = hash;
    }

    fn after_send(flow: *Flow) void {
        if (flow.send.step == .initiate) return flow.after_initiate();
        // A one-shot command stops after its own transaction; `run` decides again.
        flow.phase = if (flow.config.command == .run) .decide else .next;
    }

    /// Journals a send's result and checks its receipt; returns the confirmed hash.
    fn settle_completion(
        flow: *Flow,
        completion: tx_manager.Completion,
        client: *rpc.Client,
        finalize_hash: ?Hash,
    ) Error!Hash {
        const confirmed = switch (completion.outcome) {
            .confirmed => |confirmed| confirmed,
            .failed => {
                if (!flow.record(flow.settle_record(.failed, @splat(0), 0))) {
                    return error.JournalFailed;
                }
                return error.SendFailed;
            },
        };
        const checked = flow.check_receipt(client, confirmed.hash, finalize_hash);
        const event: journal_module.Event = if (checked) |_| .confirmed else |_| .failed;
        if (!flow.record(flow.settle_record(event, confirmed.hash, confirmed.block_number))) {
            return error.JournalFailed;
        }
        try checked;
        return confirmed.hash;
    }

    fn check_receipt(
        flow: *Flow,
        client: *rpc.Client,
        hash: Hash,
        finalize_hash: ?Hash,
    ) Error!void {
        var params: [80]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\"]", .{&hash}) catch unreachable;
        const receipt = try client.call("eth_getTransactionReceipt", text);
        if (receipt == .null) return error.MissingReceipt;
        if (try rpc.quantity(u8, try rpc.field(receipt, "status")) != 1) return error.Reverted;
        const withdrawal_hash = finalize_hash orelse return;
        var logs: [64]withdrawal_module.Log = undefined;
        var topics: [64][4]Hash = undefined;
        const found = try reader_module.receipt_logs(receipt, &logs, &topics, flow.calldata_buffer);
        const portal = flow.reader.contracts.portal;
        for (found) |log| {
            const decoded = try calldata.decode_withdrawal_finalized(log, portal, withdrawal_hash);
            const success = decoded orelse continue;
            if (!success) return error.TargetCallFailed;
            return;
        }
        return error.MissingFinalizationEvent;
    }

    fn advance(flow: *Flow) void {
        assert(flow.index < flow.withdrawal_count);
        flow.index += 1;
        flow.phase = if (flow.index == flow.withdrawal_count) .done else .decide;
        assert(flow.index <= flow.withdrawal_count);
    }
};

pub const Mined = struct { success: bool, block_number: u64 };

/// Receipt status of `hash`, or null when it is not mined.
pub fn receipt_status(client: *rpc.Client, hash: Hash) Error!?Mined {
    var params: [80]u8 = undefined;
    const text = std.fmt.bufPrint(&params, "[\"0x{x}\"]", .{&hash}) catch unreachable;
    const receipt = try client.call("eth_getTransactionReceipt", text);
    if (receipt == .null) return null;
    const number = rpc.field(receipt, "blockNumber") catch return null;
    if (number == .null) return null;
    const mined: Mined = .{
        .success = try rpc.quantity(u8, try rpc.field(receipt, "status")) == 1,
        .block_number = try rpc.quantity(u64, number),
    };
    assert(receipt != .null);
    return mined;
}

comptime {
    assert(@sizeOf(primitives.Address) == 20);
}

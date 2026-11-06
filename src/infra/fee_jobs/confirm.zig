//! `fee-jobs confirm` (base/base `crates/infra/fee-jobs/src/confirm.rs`): finds recent L2
//! `FeesDisbursed` events of the `FeeDisburser` and proves or finalizes the withdrawals their
//! transactions started, through the withdrawer flow (fault proofs only, like base/base).
//!
//! Only the FeeDisburser's own ETH bridge withdrawals count: the message passer sender is the
//! L2CrossDomainMessenger, its `relayMessage` relays from the L2StandardBridge, and the
//! bridge's `finalizeBridgeETH` names the FeeDisburser as `_from` (both calls decoded strictly
//! and canonically, as alloy's `abi_decode_validate`). Other withdrawals in a receipt are
//! skipped (reported as `skipped`); a receipt with none fails.
//!
//! One run handles each withdrawal once, without waiting out delays: pass one proves the
//! withdrawals that need a proof, pass two finalizes the ones that are ready (base/base takes
//! one step per withdrawal and per run too). `dry_run` only decides. A failed receipt or
//! withdrawal is reported and the run continues; the caller fails the job afterwards.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const abi = @import("../../proof/contracts/abi.zig");
const predeploys = @import("../../common/consensus/predeploys.zig");
const withdrawer = @import("../withdrawer/root.zig");

const flow_module = withdrawer.flow;
const withdrawal_module = withdrawer.withdrawal;
const journal_module = withdrawer.journal;
const Withdrawal = withdrawal_module.Withdrawal;
const Status = withdrawer.status.Status;

pub const Address = [20]u8;
pub const Hash = [32]u8;

pub const fees_disbursed_topic = withdrawal_module.keccak256(
    "FeesDisbursed(uint256,uint256,uint256)",
);
pub const relay_message = abi.selector(
    "relayMessage(uint256,address,address,uint256,uint256,bytes)",
);
pub const finalize_bridge_eth = abi.selector("finalizeBridgeETH(address,address,uint256,bytes)");
pub const messenger: Address = predeploys.l2_cross_domain_messenger.bytes;
pub const standard_bridge: Address = predeploys.l2_standard_bridge.bytes;

/// Distinct disbursal transactions one run handles.
pub const disbursals_max = 256;
/// `FeesDisbursed` logs one `eth_getLogs` range may return.
pub const logs_per_query_max = 1024;
/// Log queries one window may need (the default window needs 303).
pub const queries_max = 100_000;

/// True when `withdrawal` is the FeeDisburser's authenticated ETH bridge withdrawal.
pub fn is_fee_withdrawal(withdrawal: *const Withdrawal, fee_disburser: Address) bool {
    const transaction = &withdrawal.transaction;
    if (!std.mem.eql(u8, &transaction.sender, &messenger)) return false;
    const relay = canonical_call(transaction.data, relay_message, 6, 5) orelse return false;
    _ = relay.decoder.address(2) catch return false; // _target
    const relay_sender = relay.decoder.address(1) catch return false;
    if (!std.mem.eql(u8, &relay_sender, &standard_bridge)) return false;
    const bridge = canonical_call(relay.bytes, finalize_bridge_eth, 4, 3) orelse return false;
    _ = bridge.decoder.address(1) catch return false; // _to
    const from = bridge.decoder.address(0) catch return false;
    assert(transaction.data.len >= 4 + 7 * 32);
    return std.mem.eql(u8, &from, &fee_disburser);
}

const Canonical = struct { decoder: abi.Decoder, bytes: []const u8 };

/// Decodes a call whose only dynamic argument is the `bytes` at `bytes_index`, the last
/// head word: the offset must be the head size and the data must end at its padded end.
fn canonical_call(
    data: []const u8,
    function: [4]u8,
    comptime head_words: u32,
    comptime bytes_index: u32,
) ?Canonical {
    comptime assert(bytes_index + 1 == head_words);
    const decoder = abi.Decoder.call(data, function) catch return null;
    const offset = decoder.uint(u32, bytes_index) catch return null;
    if (offset != head_words * abi.word_bytes) return null;
    const bytes = decoder.bytes(bytes_index) catch return null;
    const padded = (bytes.len + abi.word_bytes - 1) / abi.word_bytes * abi.word_bytes;
    if (decoder.data.len != (head_words + 1) * abi.word_bytes + padded) return null;
    assert(bytes.len <= decoder.data.len);
    return .{ .decoder = decoder, .bytes = bytes };
}

/// The L2 block window to scan: `lookback_ms` rounded up to blocks, clamped at genesis,
/// split into inclusive chunks of `blocks_per_query`.
pub const Window = struct {
    lookback_ms: u64,
    block_time_ms: u64,
    blocks_per_query: u64,

    pub fn valid(window: Window) bool {
        return window.lookback_ms > 0 and window.block_time_ms > 0 and
            window.blocks_per_query > 0;
    }

    pub fn blocks(window: Window) u64 {
        assert(window.valid());
        return std.math.divCeil(u64, window.lookback_ms, window.block_time_ms) catch
            unreachable; // block_time_ms > 0.
    }
};

pub const Range = struct { from: u64, to: u64 };

pub const Ranges = struct {
    start: u64,
    current: u64,
    chunk: u64,
    done: bool = false,

    pub fn init(current: u64, window: Window) Ranges {
        assert(window.valid());
        return .{
            .start = current -| window.blocks(),
            .current = current,
            .chunk = window.blocks_per_query,
        };
    }

    /// Queries needed, saturating.
    pub fn count(ranges: *const Ranges) u64 {
        const span = ranges.current - ranges.start;
        return span / ranges.chunk +| 1;
    }

    pub fn next(ranges: *Ranges) ?Range {
        if (ranges.done) return null;
        const end = @min(ranges.start +| (ranges.chunk - 1), ranges.current);
        const range: Range = .{ .from = ranges.start, .to = end };
        if (end == ranges.current) ranges.done = true else ranges.start = end + 1;
        assert(range.from <= range.to);
        return range;
    }
};

pub const ScanError = rpc.Error || rpc.DecodeError ||
    error{ WindowTooLarge, TooManyLogs, TooManyDisbursals, MissingTransactionHash };

const Located = struct { block: u64, index: u64, hash: Hash };

/// Disbursal transaction hashes of `contract`'s `FeesDisbursed` logs in the window, in
/// block and log order, each once.
pub fn scan_disbursals(
    client: *rpc.Client,
    contract: Address,
    window: Window,
    out: *[disbursals_max]Hash,
    events: Events,
) ScanError![]Hash {
    assert(window.valid());
    const current = try rpc.quantity(u64, try client.call("eth_blockNumber", "[]"));
    var ranges = Ranges.init(current, window);
    if (ranges.count() > queries_max) return error.WindowTooLarge;
    var found: u32 = 0;
    var queries: u64 = 0;
    while (ranges.next()) |range| : (queries += 1) {
        assert(queries < queries_max);
        events.emit(events.context, .{ .range = range });
        var located: [logs_per_query_max]Located = undefined;
        const logs = try query_range(client, contract, range, &located);
        std.mem.sort(Located, logs, {}, located_less);
        for (logs) |log| {
            const seen = for (out[0..found]) |hash| {
                if (std.mem.eql(u8, &hash, &log.hash)) break true;
            } else false;
            if (seen) continue;
            if (found == disbursals_max) return error.TooManyDisbursals;
            out[found] = log.hash;
            found += 1;
        }
    }
    return out[0..found];
}

fn located_less(_: void, a: Located, b: Located) bool {
    if (a.block != b.block) return a.block < b.block;
    return a.index < b.index;
}

fn query_range(
    client: *rpc.Client,
    contract: Address,
    range: Range,
    out: *[logs_per_query_max]Located,
) ScanError![]Located {
    var params: [256]u8 = undefined;
    const text = std.fmt.bufPrint(
        &params,
        "[{{\"address\":\"0x{x}\",\"topics\":[\"0x{x}\"],\"fromBlock\":\"0x{x}\"," ++
            "\"toBlock\":\"0x{x}\"}}]",
        .{ &contract, &fees_disbursed_topic, range.from, range.to },
    ) catch unreachable; // Fixed-size content.
    const logs = try client.call("eth_getLogs", text);
    if (logs != .array) return error.MalformedResponse;
    if (logs.array.items.len > out.len) return error.TooManyLogs;
    for (logs.array.items, 0..) |log, index| {
        const hash_value = rpc.field(log, "transactionHash") catch
            return error.MissingTransactionHash;
        if (hash_value == .null) return error.MissingTransactionHash;
        out[index] = .{
            .block = try rpc.quantity(u64, try rpc.field(log, "blockNumber")),
            .index = try rpc.quantity(u64, try rpc.field(log, "logIndex")),
            .hash = try rpc.fixed(32, hash_value),
        };
    }
    return out[0..logs.array.items.len];
}

pub const Outcome = enum {
    /// Proof submitted this run; finalization is for a later run.
    proven,
    finalized,
    already_finalized,
    /// Not ready yet, or waiting for a game that covers it.
    pending,
    /// Dry run decisions.
    would_prove,
    would_finalize,
};

pub const Event = union(enum) {
    range: Range,
    skipped: struct { transaction: Hash, withdrawal: Hash },
    withdrawal: struct {
        transaction: Hash,
        withdrawal: Hash,
        outcome: Outcome,
        status: Status,
        l1_transaction: ?Hash,
    },
    failed: struct { transaction: Hash, err: anyerror },
};

/// Receives progress and outcomes (the binary logs them; tests collect them).
pub const Events = struct {
    context: *anyopaque,
    emit: *const fn (context: *anyopaque, event: Event) void,
};

pub const Config = struct {
    fee_disburser: Address,
    window: Window,
    dry_run: bool = false,
    withdrawal_timeout_ms: u64 = 600_000,
    poll_interval_ms: u64 = 2_000,
};

pub const Report = struct {
    disbursals: u32 = 0,
    withdrawals: u32 = 0,
    skipped: u32 = 0,
    pending: u32 = 0,
    failures: u32 = 0,
};

pub const RunError = ScanError || flow_module.Error ||
    error{ Timeout, SendInFlight, Paused, OutOfMemory };

/// One confirm run over injected JSON-RPC clients (through `reader`) and an L1 send driver.
/// `reader.resolve_contracts()` must have succeeded (it rejects a zero factory or registry).
pub const Job = struct {
    allocator: std.mem.Allocator,
    config: Config,
    reader: *withdrawer.reader.Reader,
    l1_driver: *flow_module.SendDriver,
    events: Events,
    report: Report = .{},

    /// Scans the window and handles every disbursal. Per-receipt and per-withdrawal failures
    /// are counted in `report.failures`; only scan failures, an L1 send left in flight, and
    /// a timed-out withdrawal (its send may still be pending) end the run early.
    pub fn run(job: *Job, clock: anytype) RunError!Report {
        assert(job.config.window.valid());
        assert(job.config.withdrawal_timeout_ms > 0);
        var hashes: [disbursals_max]Hash = undefined;
        const found = try scan_disbursals(
            job.reader.l2,
            job.config.fee_disburser,
            job.config.window,
            &hashes,
            job.events,
        );
        job.report.disbursals = @intCast(found.len);
        for (found) |transaction| {
            job.confirm_transaction(transaction, clock) catch |err| {
                job.report.failures += 1;
                job.events.emit(job.events.context, .{ .failed = .{
                    .transaction = transaction,
                    .err = err,
                } });
                if (err == error.Timeout or err == error.SendInFlight) return err;
            };
        }
        assert(job.report.disbursals == found.len);
        return job.report;
    }

    const Results = struct {
        outcomes: [withdrawal_module.withdrawals_max]flow_module.Outcome = undefined,
        count: u32 = 0,
    };

    fn confirm_transaction(job: *Job, transaction: Hash, clock: anytype) RunError!void {
        var first: Results = .{};
        const first_command: flow_module.Command = if (job.config.dry_run) .status else .prove;
        try job.pass(first_command, transaction, clock, &first, true);
        if (job.config.dry_run) return job.report_outcomes(transaction, &first, null);
        var second: Results = .{};
        try job.pass(.finalize, transaction, clock, &second, false);
        // Both passes load the same receipt through the same filter.
        if (first.count != second.count) return error.MalformedResponse;
        try job.report_outcomes(transaction, &first, &second);
    }

    /// Runs one flow over `transaction` until it is done or the withdrawal timeout passes.
    fn pass(
        job: *Job,
        command: flow_module.Command,
        transaction: Hash,
        clock: anytype,
        results: *Results,
        report_skipped: bool,
    ) RunError!void {
        var flow = try flow_module.Flow.init(job.allocator, .{
            .command = command,
            .l2_transaction = transaction,
            .poll_interval_ms = job.config.poll_interval_ms,
            .filter = .{ .context = &job.config.fee_disburser, .accept = accept_fee_withdrawal },
        }, job.reader, job.l1_driver, null, memory_sink(), .{});
        defer flow.deinit(job.allocator);
        job.l1_driver.config.publish_hook = flow.publish_hook();
        defer job.l1_driver.config.publish_hook = null;
        const result = drive(&flow, clock, job.config.withdrawal_timeout_ms);
        if (report_skipped) for (flow.skipped_withdrawals()) |hash| {
            job.report.skipped += 1;
            job.events.emit(job.events.context, .{ .skipped = .{
                .transaction = transaction,
                .withdrawal = hash,
            } });
        };
        try result;
        if (job.l1_driver.manager.pending_count() > 0) return error.SendInFlight;
        const outcomes = flow.results();
        @memcpy(results.outcomes[0..outcomes.len], outcomes);
        results.count = @intCast(outcomes.len);
    }

    fn report_outcomes(
        job: *Job,
        transaction: Hash,
        first: *const Results,
        second: ?*const Results,
    ) RunError!void {
        var paused = false;
        for (0..first.count) |index| {
            const proved = first.outcomes[index];
            const last = if (second) |results| results.outcomes[index] else proved;
            const outcome = outcome_of(proved, last, second == null) orelse {
                paused = true;
                continue;
            };
            job.report.withdrawals += 1;
            if (outcome == .pending or outcome == .proven) job.report.pending += 1;
            job.events.emit(job.events.context, .{ .withdrawal = .{
                .transaction = transaction,
                .withdrawal = last.withdrawal_hash,
                .outcome = outcome,
                .status = last.status,
                .l1_transaction = proved.transaction orelse last.transaction,
            } });
        }
        if (paused) return error.Paused;
    }
};

/// The run's outcome from the prove pass and the finalize pass; null when paused.
fn outcome_of(proved: flow_module.Outcome, last: flow_module.Outcome, dry_run: bool) ?Outcome {
    assert(std.mem.eql(u8, &proved.withdrawal_hash, &last.withdrawal_hash));
    if (proved.transaction != null) return .proven;
    if (last.transaction != null) return .finalized;
    return switch (last.status) {
        .paused => null,
        .finalized => .already_finalized,
        .not_ready => .pending,
        .prove => if (dry_run) .would_prove else .pending,
        .finalize => if (dry_run) .would_finalize else .pending,
    };
}

fn accept_fee_withdrawal(context: ?*const anyopaque, withdrawal: *const Withdrawal) bool {
    const fee_disburser: *const Address = @ptrCast(@alignCast(context.?));
    return is_fee_withdrawal(withdrawal, fee_disburser.*);
}

/// Steps `flow` until done; fails once `timeout_ms` passes while it still waits.
fn drive(flow: *flow_module.Flow, clock: anytype, timeout_ms: u64) RunError!void {
    const deadline_ms = clock.now_ms() + timeout_ms;
    // Each iteration either works or sleeps at least 1 ms, so the deadline bounds the loop;
    // this cap only guards a stuck clock.
    const steps_max: u64 = 10_000_000;
    for (0..steps_max) |_| {
        const now_ms = clock.now_ms();
        switch (try flow.step(now_ms)) {
            .done => return,
            .working => {},
            .waiting => |waiting| {
                if (now_ms >= deadline_ms) return error.Timeout;
                const sleep_ms = @min(waiting.until_ms -| now_ms, deadline_ms - now_ms, 1_000);
                clock.sleep_ms(@max(sleep_ms, 1));
            },
        }
    }
    return error.Timeout;
}

/// confirm keeps no journal (base/base has none either): each run decides from the chain.
var memory_journal_context: u8 = 0;

fn memory_sink() flow_module.JournalSink {
    return .{ .context = &memory_journal_context, .append = memory_append };
}

fn memory_append(context: *anyopaque, record: journal_module.Record) bool {
    assert(context == @as(*anyopaque, &memory_journal_context));
    assert(record.step != .initiate);
    return true;
}

test {
    _ = @import("confirm_test.zig");
}

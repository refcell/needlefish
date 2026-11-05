//! Load test runner (base/base `load-tests/src/runner/{load_runner,submission}.rs`).
//!
//! Each sender account owns one transaction-manager driver (nonces, fee bumps, receipts).
//! Every `step` asks the pacer how many sends are owed, hands generated payloads to senders
//! round-robin (skipping full ones; owed sends that find every sender full are dropped
//! from the open-loop target rather than queued), drives every sender, and records
//! completions. Latency is measured from submission to confirmation at the configured
//! depth (1 = inclusion).

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const driver_module = @import("../tx_manager/driver.zig");
const manager = @import("../tx_manager/manager.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const pacing = @import("pacing.zig");
const workload = @import("workload.zig");
const metrics = @import("metrics.zig");

pub const senders_max = 16;
pub const sends_per_sender_max = 32;
pub const calldata_bytes_max = 4096;

const Driver = driver_module.Driver(.{ .sends_max = sends_per_sender_max, .hashes_max = 8 });
const Generator = workload.Generator(calldata_bytes_max);
pub const Recorder = metrics.Recorder(64 * 1024);

pub const Config = struct {
    chain_id: u64,
    /// Indices into the public dev mnemonic. Defaults avoid the devnet's role accounts.
    account_indices: []const u32 = &.{ 2, 3, 4, 8, 9 },
    rate_per_s: u32 = 10,
    duration_ms: u64 = 60_000,
    /// After the submission window, wait at most this long for outstanding sends.
    drain_ms: u64 = 60_000,
    in_flight_per_sender: u32 = 16,
    workload: workload.Config,
    manager: manager.Config = .{
        .num_confirmations = 1,
        .resubmission_timeout_ms = 12_000,
        .receipt_query_interval_ms = 1_000,
    },
};

pub const Runner = struct {
    config: Config,
    drivers: [senders_max]Driver = undefined,
    clients: [senders_max]*rpc.Client = undefined,
    sender_count: u32,
    submitted_ms: [senders_max][sends_per_sender_max]Submitted = undefined,
    sender_next: u32 = 0,
    generator: Generator,
    pacer: pacing.Pacer,
    recorder: Recorder = .{},
    start_ms: u64,
    rpc_errors: u64 = 0,

    const Submitted = struct { id: u64 = 0, at_ms: u64 = 0 };

    /// `clients[i]` serves sender `i`; senders may share one client (single-threaded).
    pub fn init(
        runner: *Runner,
        allocator: std.mem.Allocator,
        config: Config,
        clients: []const *rpc.Client,
        now_ms: u64,
    ) !void {
        const count = config.account_indices.len;
        if (count == 0 or count > senders_max) return error.InvalidSenderCount;
        if (clients.len != count) return error.InvalidSenderCount;
        if (config.in_flight_per_sender == 0) return error.InvalidConfig;
        if (config.in_flight_per_sender > sends_per_sender_max) return error.InvalidConfig;
        runner.* = .{
            .config = config,
            .sender_count = @intCast(count),
            .generator = Generator.init(config.workload),
            .pacer = pacing.Pacer.init(config.rate_per_s, now_ms),
            .start_ms = now_ms,
        };
        for (runner.submitted_ms[0..count]) |*row| row.* = @splat(.{});
        var initialized: u32 = 0;
        errdefer for (runner.drivers[0..initialized]) |*driver| driver.deinit(allocator);
        for (config.account_indices, 0..) |account_index, index| {
            if (account_index >= accounts.funded_count) return error.UnfundedAccount;
            const account = accounts.derive_dev(account_index);
            runner.drivers[index] = try Driver.init(allocator, .{
                .chain_id = config.chain_id,
                .private_key = account.private_key,
                .from = account.address,
                .data_bytes_max = calldata_bytes_max,
                .manager = config.manager,
            });
            runner.clients[index] = clients[index];
            initialized += 1;
        }
    }

    pub fn deinit(runner: *Runner, allocator: std.mem.Allocator) void {
        for (runner.drivers[0..runner.sender_count]) |*driver| driver.deinit(allocator);
        runner.* = undefined;
    }

    pub fn submitting(runner: *const Runner, now_ms: u64) bool {
        return now_ms < runner.start_ms + runner.config.duration_ms;
    }

    /// True when the run is over: the window closed and every send finished or the drain
    /// deadline passed.
    pub fn done(runner: *const Runner, now_ms: u64) bool {
        if (runner.submitting(now_ms)) return false;
        const deadline_ms = runner.start_ms + runner.config.duration_ms + runner.config.drain_ms;
        return runner.outstanding() == 0 or now_ms >= deadline_ms;
    }

    pub fn outstanding(runner: *const Runner) u64 {
        const finished = runner.recorder.confirmed + runner.recorder.failed;
        assert(finished <= runner.recorder.submitted);
        return runner.recorder.submitted - finished;
    }

    pub fn step(runner: *Runner, now_ms: u64) void {
        if (runner.submitting(now_ms)) runner.submit_owed(now_ms);
        for (runner.drivers[0..runner.sender_count], 0..) |*driver, index| {
            driver.step(runner.clients[index], now_ms) catch {
                runner.rpc_errors += 1;
            };
            runner.collect(@intCast(index), now_ms);
        }
    }

    fn submit_owed(runner: *Runner, now_ms: u64) void {
        const owed = runner.pacer.due(now_ms);
        var sent: u64 = 0;
        while (sent < owed) : (sent += 1) {
            const index = runner.pick_sender() orelse break;
            const payload = runner.generator.next();
            const driver = &runner.drivers[index];
            const id = driver.send(runner.clients[index], .{
                .to = payload.to,
                .value = payload.value,
                .data = payload.data,
                .gas_limit = payload.gas_limit,
            }, now_ms) catch {
                runner.recorder.record_send_error();
                continue;
            };
            runner.remember(index, id, now_ms);
            runner.recorder.record_submit(now_ms);
        }
        // Owed sends that found no sender are not carried over (open loop).
        runner.pacer.record_sent(owed);
    }

    fn pick_sender(runner: *Runner) ?u32 {
        for (0..runner.sender_count) |_| {
            const index = runner.sender_next;
            runner.sender_next = (runner.sender_next + 1) % runner.sender_count;
            const pending = runner.drivers[index].manager.pending_count();
            if (pending < runner.config.in_flight_per_sender) return index;
        }
        return null;
    }

    fn remember(runner: *Runner, sender: u32, id: u64, now_ms: u64) void {
        for (&runner.submitted_ms[sender]) |*entry| {
            if (entry.id != 0) continue;
            entry.* = .{ .id = id, .at_ms = now_ms };
            return;
        }
        unreachable; // At most `sends_per_sender_max` sends are pending per driver.
    }

    fn collect(runner: *Runner, sender: u32, now_ms: u64) void {
        const driver = &runner.drivers[sender];
        while (driver.take_completion()) |completion| {
            const at_ms = runner.forget(sender, completion.id);
            runner.recorder.record_completion(
                completion.outcome,
                completion.bump_count,
                now_ms - at_ms,
                now_ms,
            );
        }
    }

    fn forget(runner: *Runner, sender: u32, id: u64) u64 {
        for (&runner.submitted_ms[sender]) |*entry| {
            if (entry.id != id) continue;
            const at_ms = entry.at_ms;
            entry.* = .{};
            return at_ms;
        }
        unreachable; // Every completion was remembered at submission.
    }
};

test {
    _ = @import("runner_test.zig");
}

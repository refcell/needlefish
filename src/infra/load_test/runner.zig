//! Load test runner (base/base `load-tests/src/runner/{load_runner,submission}.rs`).
//!
//! Each sender account owns one transaction-manager driver (nonces, fee bumps, receipts).
//! Every `step` asks the pacer how many sends are owed, hands generated payloads to senders
//! round-robin (skipping full ones; owed sends that find every sender full are dropped
//! from the open-loop target rather than queued), drives every sender, and records
//! completions. Latency is measured from submission to confirmation at the configured
//! depth (1 = inclusion).
//!
//! Senders are dev-mnemonic accounts, or `stream_senders` keys from the key stream. With
//! `prep` set, the run starts with a prep phase (`chain_prep.zig`): deploy the workload
//! contracts the mix needs, fund and mint to the senders, then start the submission window.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const driver_module = @import("../tx_manager/driver.zig");
const manager = @import("../tx_manager/manager.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const pacing = @import("pacing.zig");
const workload = @import("workload.zig");
const metrics = @import("metrics.zig");
const chain_prep = @import("chain_prep.zig");
const key_stream = @import("key_stream.zig");

pub const senders_max = 64;
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
    /// Senders from the key stream of `key_seed` (`key_stream.zig`) instead of
    /// `account_indices`; 0 uses `account_indices`.
    stream_senders: u32 = 0,
    key_seed: u64 = 0,
    /// Optional prep phase before the submission window.
    prep: ?Prep = null,
    manager: manager.Config = .{
        .num_confirmations = 1,
        .resubmission_timeout_ms = 12_000,
        .receipt_query_interval_ms = 1_000,
    },
};

pub const Prep = struct {
    /// Dev mnemonic account that deploys and funds (must not be a sender).
    funder_index: u32,
    /// Wei sent to each sender; 0 skips funding.
    fund_wei: u256,
    mint_amount: u256 = 1_000_000_000_000_000_000_000_000,
    in_flight_max: u32 = 16,
    /// The run fails if prep has not finished by then.
    timeout_ms: u64 = 300_000,
};

pub const Runner = struct {
    config: Config,
    drivers: [senders_max]Driver = undefined,
    clients: [senders_max]*rpc.Client = undefined,
    funder_client: ?*rpc.Client = null,
    sender_count: u32,
    submitted_ms: [senders_max][sends_per_sender_max]Submitted = undefined,
    sender_next: u32 = 0,
    generator: Generator,
    pacer: pacing.Pacer,
    recorder: Recorder = .{},
    start_ms: u64,
    rpc_errors: u64 = 0,
    addresses: [senders_max]workload.Address = undefined,
    prep: ?chain_prep.Prep = null,
    prep_deadline_ms: u64 = 0,
    /// False while the prep phase runs.
    loading: bool = true,

    const Submitted = struct { id: u64 = 0, at_ms: u64 = 0 };

    /// `clients[i]` serves sender `i`; with `prep`, `clients[sender_count]` serves the
    /// funder. Senders may share one client (single-threaded).
    pub fn init(
        runner: *Runner,
        allocator: std.mem.Allocator,
        config: Config,
        clients: []const *rpc.Client,
        now_ms: u64,
    ) !void {
        const count = try sender_count_of(config);
        if (clients.len != count + @intFromBool(config.prep != null)) {
            return error.InvalidSenderCount;
        }
        if (config.in_flight_per_sender == 0) return error.InvalidConfig;
        if (config.in_flight_per_sender > sends_per_sender_max) return error.InvalidConfig;
        const needs_contracts = config.workload.mix.needs_contracts();
        if (needs_contracts and config.prep == null and config.workload.contracts == null) {
            return error.ContractsRequired;
        }
        runner.* = .{
            .config = config,
            .sender_count = count,
            .generator = Generator.init(config.workload),
            .pacer = pacing.Pacer.init(config.rate_per_s, now_ms),
            .start_ms = now_ms,
        };
        for (runner.submitted_ms[0..count]) |*row| row.* = @splat(.{});
        try runner.init_drivers(allocator, clients[0..count]);
        errdefer for (runner.drivers[0..count]) |*driver| driver.deinit(allocator);
        if (config.prep) |prep| {
            runner.funder_client = clients[count];
            try runner.init_prep(allocator, prep, needs_contracts, now_ms);
        }
        assert(runner.loading == (config.prep == null));
    }

    fn sender_count_of(config: Config) !u32 {
        const count = if (config.stream_senders > 0)
            config.stream_senders
        else
            config.account_indices.len;
        if (count == 0 or count > senders_max) return error.InvalidSenderCount;
        return @intCast(count);
    }

    fn sender_account(config: Config, index: u32) !accounts.Account {
        if (config.stream_senders > 0) return key_stream.derive(config.key_seed, index);
        const account_index = config.account_indices[index];
        if (account_index >= accounts.funded_count) return error.UnfundedAccount;
        return accounts.derive_dev(account_index);
    }

    fn init_drivers(
        runner: *Runner,
        allocator: std.mem.Allocator,
        clients: []const *rpc.Client,
    ) !void {
        assert(clients.len == runner.sender_count);
        var initialized: u32 = 0;
        errdefer for (runner.drivers[0..initialized]) |*driver| driver.deinit(allocator);
        for (0..runner.sender_count) |index| {
            const account = try sender_account(runner.config, @intCast(index));
            runner.addresses[index] = account.address;
            runner.drivers[index] = try Driver.init(allocator, .{
                .chain_id = runner.config.chain_id,
                .private_key = account.private_key,
                .from = account.address,
                .data_bytes_max = calldata_bytes_max,
                .manager = runner.config.manager,
            });
            runner.clients[index] = clients[index];
            initialized += 1;
        }
        assert(initialized == runner.sender_count);
    }

    fn init_prep(
        runner: *Runner,
        allocator: std.mem.Allocator,
        prep: Prep,
        deploy: bool,
        now_ms: u64,
    ) !void {
        if (prep.funder_index >= accounts.funded_count) return error.UnfundedAccount;
        const funder = accounts.derive_dev(prep.funder_index);
        for (runner.addresses[0..runner.sender_count]) |address| {
            if (std.mem.eql(u8, &address.bytes, &funder.address.bytes)) {
                return error.FunderIsSender;
            }
        }
        runner.prep = @as(chain_prep.Prep, undefined); // Non-null; filled in by init.
        errdefer runner.prep = null;
        try runner.prep.?.init(allocator, .{
            .chain_id = runner.config.chain_id,
            .funder = funder,
            .fund_wei = prep.fund_wei,
            .deploy = deploy,
            .mint_amount = if (runner.config.workload.mix.weight_of(.erc20_transfer) > 0)
                prep.mint_amount
            else
                0,
            .in_flight_max = prep.in_flight_max,
            .manager = runner.config.manager,
        }, runner.addresses[0..runner.sender_count]);
        runner.loading = false;
        runner.prep_deadline_ms = now_ms + prep.timeout_ms;
        assert(runner.prep != null);
    }

    pub fn deinit(runner: *Runner, allocator: std.mem.Allocator) void {
        if (runner.prep) |*prep| prep.deinit(allocator);
        for (runner.drivers[0..runner.sender_count]) |*driver| driver.deinit(allocator);
        runner.* = undefined;
    }

    pub fn submitting(runner: *const Runner, now_ms: u64) bool {
        return runner.loading and now_ms < runner.start_ms + runner.config.duration_ms;
    }

    /// True when the prep phase failed (or timed out); the run is over without load.
    pub fn prep_failed(runner: *const Runner) bool {
        const prep = runner.prep orelse return false;
        return prep.phase == .failed;
    }

    /// True when the run is over: the window closed and every send finished or the drain
    /// deadline passed.
    pub fn done(runner: *const Runner, now_ms: u64) bool {
        if (runner.prep_failed()) return true;
        if (!runner.loading) return false;
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
        if (!runner.loading) return runner.step_prep(now_ms);
        if (runner.submitting(now_ms)) runner.submit_owed(now_ms);
        for (runner.drivers[0..runner.sender_count], 0..) |*driver, index| {
            driver.step(runner.clients[index], now_ms) catch {
                runner.rpc_errors += 1;
            };
            runner.collect(@intCast(index), now_ms);
        }
    }

    fn step_prep(runner: *Runner, now_ms: u64) void {
        assert(!runner.loading);
        const prep = &runner.prep.?;
        prep.step(runner.funder_client.?, now_ms);
        if (prep.phase != .done) {
            if (now_ms >= runner.prep_deadline_ms) prep.phase = .failed;
            return;
        }
        // The submission window starts once every sender is funded.
        if (prep.contracts_deployed()) |deployed| runner.generator.config.contracts = deployed;
        runner.loading = true;
        runner.start_ms = now_ms;
        runner.pacer = pacing.Pacer.init(runner.config.rate_per_s, now_ms);
        assert(runner.submitting(now_ms));
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

    /// Plain-text report: the recorder's summary, payload counts, and prep results.
    pub fn write_report(runner: *Runner, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try runner.recorder.write_report(out);
        try out.print("rpc errors     {d}\n", .{runner.rpc_errors});
        for (runner.generator.generated, 0..) |count, index| {
            if (count == 0) continue;
            const kind: workload.Kind = @fromBackingInt(@intCast(index));
            try out.print("payload        {t}: {d}\n", .{ kind, count });
        }
        const prep = runner.prep orelse return;
        try out.print("prep           {t}: funded {d} minted {d}", .{
            prep.phase, prep.funded, prep.minted,
        });
        try out.print(" send errors {d} rpc errors {d}\n", .{
            prep.send_errors, prep.rpc_errors,
        });
        if (prep.failure) |failure| try out.print("prep failure   {t}\n", .{failure});
        if (prep.contracts_deployed()) |deployed| {
            try out.print("contracts      token 0x{x} storage 0x{x} looper 0x{x}\n", .{
                &deployed.token.bytes, &deployed.storage.bytes, &deployed.looper.bytes,
            });
        }
    }

    /// Machine-readable report: one JSON object on one line.
    pub fn write_json(runner: *Runner, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try out.writeAll("{");
        try metrics.write_json_members(runner.recorder.summary(), &runner.recorder.failures, out);
        try out.print(",\"rpc_errors\":{d},\"senders\":{d},\"payloads\":{{", .{
            runner.rpc_errors, runner.sender_count,
        });
        for (runner.generator.generated, 0..) |count, index| {
            const kind: workload.Kind = @fromBackingInt(@intCast(index));
            try out.print("{s}\"{t}\":{d}", .{ if (index == 0) "" else ",", kind, count });
        }
        try out.writeAll("},\"prep\":");
        if (runner.prep) |prep| try write_prep_json(&prep, out) else try out.writeAll("null");
        try out.writeAll("}\n");
    }

    fn write_prep_json(prep: *const chain_prep.Prep, out: *std.Io.Writer) std.Io.Writer.Error!void {
        try out.print("{{\"phase\":\"{t}\",\"funded\":{d},\"minted\":{d},", .{
            prep.phase, prep.funded, prep.minted,
        });
        try out.print("\"send_errors\":{d},\"rpc_errors\":{d},\"failure\":", .{
            prep.send_errors, prep.rpc_errors,
        });
        if (prep.failure) |failure| {
            try out.print("\"{t}\"", .{failure});
        } else try out.writeAll("null");
        try out.writeAll(",\"contracts\":");
        if (prep.contracts_deployed()) |deployed| {
            try out.print("{{\"token\":\"0x{x}\",\"storage\":\"0x{x}\",\"looper\":\"0x{x}\"}}", .{
                &deployed.token.bytes, &deployed.storage.bytes, &deployed.looper.bytes,
            });
        } else try out.writeAll("null");
        try out.writeAll("}");
    }
};

test {
    _ = @import("runner_test.zig");
}

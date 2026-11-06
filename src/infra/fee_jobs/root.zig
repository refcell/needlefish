//! fee_jobs: one-shot fee collection jobs (base/base `crates/infra/fee-jobs`).
//!
//! Each job checks an on-chain precondition and, when it holds, sends one zero-argument
//! call through the tx_manager driver and waits for the configured confirmation depth:
//!
//! | job        | chain | precondition                                     | call            |
//! | ---------- | ----- | ------------------------------------------------ | --------------- |
//! | `disburse` | L2    | latest timestamp >= lastDisbursementTime + interval | disburseFees() |
//! | `process`  | L1    | contract balance >= 1 ETH                        | processFees()   |
//! | `sweep`    | L2    | contract balance >= 0.01 ETH                     | withdrawETH()   |
//!
//! A false precondition is a successful skip. Read errors, send failures, timeouts, and
//! reverted receipts fail the job. `confirm` (proving and finalizing the `FeeDisburser`'s
//! withdrawals through the withdrawer flow) lives in `confirm.zig`.
//!
//! IO goes through the injected JSON-RPC client and a `clock` (`now_ms()`, `sleep_ms(ms)`),
//! so tests run against a fake chain with a fake clock.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const tx_manager = @import("../tx_manager/root.zig");

pub const confirm = @import("confirm.zig");

pub const Address = tx_manager.driver.Address;
pub const Hash = tx_manager.driver.Hash;

pub const Kind = enum { disburse, process, sweep };

pub const min_process_balance_wei: u256 = 1_000_000_000_000_000_000;
pub const min_sweep_balance_wei: u256 = 10_000_000_000_000_000;

pub const selectors = struct {
    pub const disburse_fees = selector("disburseFees()");
    pub const last_disbursement_time = selector("lastDisbursementTime()");
    pub const fee_disbursement_interval = selector("FEE_DISBURSEMENT_INTERVAL()");
    pub const process_fees = selector("processFees()");
    pub const withdraw_eth = selector("withdrawETH()");
};

fn selector(comptime signature: []const u8) [4]u8 {
    @setEvalBranchQuota(100_000);
    var digest: [32]u8 = undefined;
    comptime std.crypto.hash.sha3.Keccak256.hash(signature, &digest, .{});
    return digest[0..4].*;
}

pub fn calldata(kind: Kind) [4]u8 {
    return switch (kind) {
        .disburse => selectors.disburse_fees,
        .process => selectors.process_fees,
        .sweep => selectors.withdraw_eth,
    };
}

/// What a job's precondition reads.
pub const Reading = union(enum) {
    window: struct { last_s: u256, interval_s: u256, timestamp_s: u64 },
    balance_wei: u256,
};

/// The precondition: true when the job should send. An overflowing next disbursement time
/// is never ready (base/base `checked_add`).
pub fn ready(kind: Kind, reading: Reading) bool {
    switch (kind) {
        .disburse => {
            assert(reading == .window);
            const window = reading.window;
            const next_s, const overflow = @addWithOverflow(window.last_s, window.interval_s);
            return overflow == 0 and window.timestamp_s >= next_s;
        },
        .process, .sweep => {
            assert(reading == .balance_wei);
            const minimum_wei = switch (kind) {
                .process => min_process_balance_wei,
                else => min_sweep_balance_wei,
            };
            return reading.balance_wei >= minimum_wei;
        },
    }
}

pub const ReadError = rpc.Error || rpc.DecodeError;

/// Reads the precondition inputs of `kind` for `contract` at the latest block.
pub fn read(client: *rpc.Client, kind: Kind, contract: Address) ReadError!Reading {
    switch (kind) {
        .disburse => {
            const interval_s = try call_uint(client, contract, selectors.fee_disbursement_interval);
            const last_s = try call_uint(client, contract, selectors.last_disbursement_time);
            const block = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
            if (block == .null) return error.MalformedResponse;
            const timestamp_s = try rpc.quantity(u64, try rpc.field(block, "timestamp"));
            return .{ .window = .{
                .last_s = last_s,
                .interval_s = interval_s,
                .timestamp_s = timestamp_s,
            } };
        },
        .process, .sweep => {
            var buffer: [96]u8 = undefined;
            const params = std.fmt.bufPrint(&buffer, "[\"0x{x}\",\"latest\"]", .{
                &contract.bytes,
            }) catch unreachable; // Fixed-size content.
            const balance = try client.call("eth_getBalance", params);
            return .{ .balance_wei = try rpc.quantity(u256, balance) };
        },
    }
}

fn call_uint(client: *rpc.Client, contract: Address, function: [4]u8) ReadError!u256 {
    var buffer: [160]u8 = undefined;
    const params = std.fmt.bufPrint(
        &buffer,
        "[{{\"to\":\"0x{x}\",\"data\":\"0x{x}\"}},\"latest\"]",
        .{ &contract.bytes, &function },
    ) catch unreachable; // Fixed-size content.
    const result = try client.call("eth_call", params);
    const word = try rpc.fixed(32, result);
    return std.mem.readInt(u256, &word, .big);
}

pub const Outcome = union(enum) {
    skipped: Reading,
    confirmed: struct { hash: Hash, block_number: u64 },
};

pub const RunError = ReadError || tx_manager.driver.Error ||
    error{ Reverted, SendFailed, Timeout };

/// Runs one job to completion: precondition, send, confirmation. `driver` is a
/// `tx_manager.driver.Driver(...)`; `clock` has `now_ms() u64` and `sleep_ms(u64)`.
pub fn run(
    driver: anytype,
    client: *rpc.Client,
    clock: anytype,
    kind: Kind,
    contract: Address,
    step_ms: u64,
) RunError!Outcome {
    assert(step_ms > 0);
    const reading = try read(client, kind, contract);
    if (!ready(kind, reading)) return .{ .skipped = reading };
    const data = calldata(kind);
    const id = try driver.send(client, .{ .to = contract, .data = &data }, clock.now_ms());
    // The manager's send timeout ends every send; this bound only guards a stuck clock.
    const steps_max: u64 = 1_000_000;
    for (0..steps_max) |_| {
        if (driver.take_completion()) |completion| {
            assert(completion.id == id);
            return switch (completion.outcome) {
                .confirmed => |confirmed| if (confirmed.success) .{ .confirmed = .{
                    .hash = confirmed.hash,
                    .block_number = confirmed.block_number,
                } } else error.Reverted,
                .failed => |failure| if (failure == .send_timeout or
                    failure == .mempool_deadline_expired) error.Timeout else error.SendFailed,
            };
        }
        clock.sleep_ms(step_ms);
        driver.step(client, clock.now_ms()) catch |err| switch (err) {
            // A failed refresh is retried on the next step.
            error.TransportFailed, error.RpcError, error.MalformedResponse => {},
            else => return err,
        };
    }
    return error.Timeout;
}

test {
    _ = @import("tests.zig");
    _ = confirm;
}

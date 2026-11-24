//! `eth_estimateGas`: reth's estimate, base/reth 2b20e42
//! `crates/rpc/rpc-eth-api/src/helpers/estimate.rs` (`estimate_gas_with`,
//! `map_out_of_gas_err`, `update_estimated_gas_range`). One run at the highest gas (capped
//! at the caller's allowance when priced), a 21000 shortcut for a plain transfer, a 64/63
//! optimistic guess, then a binary search that stops once the range is within 1.5%. The
//! base fee stays the block's: the estimate, unlike eth_call, never zeroes it.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const call_fees = @import("call_fees.zig");
const call_error = @import("call_error.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Simulated = node.executor.Executor.Simulated;

/// `reth_rpc_server_types::constants::gas_oracle`.
const call_stipend_gas: u64 = 2_300;
const estimate_gas_error_ratio: f64 = 0.015;
/// `reth_chainspec::MIN_TRANSACTION_GAS`.
const min_transaction_gas: u64 = 21_000;

const Estimate = struct {
    api: *Api,
    call: *Call,
    request: *const eth.CallRequest,
    env: node.executor.BlockEnv,
    message: node.executor.Executor.Call,
    /// The hook template of every run (overrides, price).
    template: eth.Prepared,
    /// The hook of the last run.
    last: eth.Prepared = .{},

    fn run(context: *Estimate, gas: u64, cap: eth.Prepared.Cap) HandlerError!Simulated {
        var prepared = context.template;
        prepared.cap = cap;
        var message = context.message;
        message.gas = gas;
        const view = context.request.view;
        const env = &context.env;
        const api = context.api;
        const result = try eth.run_prepared(api, context.call, view, env, message, &prepared);
        context.last = prepared;
        return result;
    }
};

pub fn estimate(api: *Api, call: *Call, request: *const eth.CallRequest) HandlerError!u64 {
    const env = try eth.request_env(api, call, request);
    // The block's limit, the EIP-7825 cap once active, and the RPC gas cap.
    const gas_max = @min(api.chain.executor.default_call_gas(&env), eth.rpc_gas_cap);
    if (call_fees.tip_without_cap(request.fees)) |tip| {
        // geth `DoEstimateGas` fails the first (highest) run, "failed with N gas: ...".
        const gas = @min(request.message.gas orelse gas_max, gas_max);
        return eth.fail_tip_above_cap(api, call, request.message.from, tip, .estimate, gas);
    }
    const prices = try eth.call_prices(call, request.fees, env.base_fee);
    var context: Estimate = .{
        .api = api,
        .call = call,
        .request = request,
        .env = env,
        .message = request.message,
        .template = .{
            .raw = request.state_overrides orelse "",
            .space = request.override_space,
            .gas_price = prices.gas_price,
            .millis_part = eth.forecast_millis_part(api, request),
        },
    };
    context.message.gas_price = prices.gas_price;
    context.message.priority_fee = prices.priority_fee;
    context.message.keep_base_fee = true;
    var highest = @min(request.message.gas orelse gas_max, gas_max);
    // The highest run, capped at the allowance when priced (an insufficient-funds failure
    // fails here). reth runs the transfer shortcut first; runs are independent.
    context.template.check_callee = true;
    const first = try context.run(highest, if (prices.gas_price > 0) .allowance else .none);
    context.template.check_callee = false;
    const allowance = context.last.allowance;
    if (prices.gas_price > 0) highest = @min(highest, allowance.?);
    // Nethermind (as geth) runs the transfer shortcut with the balance checked, so a
    // transfer whose fee (gasPrice or maxFeePerGas) the sender cannot fund fails on to
    // "gas required exceeds allowance".
    const fee_given = request.fees.gas_price != null or request.fees.max_fee != null;
    const affordable = prices.gas_price == 0 or !fee_given or
        (allowance orelse 0) >= min_transaction_gas;
    const message = &context.message;
    if (affordable and message.data.len == 0 and message.to != null and
        !context.last.callee_code)
    {
        switch (try context.run(@min(min_transaction_gas, gas_max), .none)) {
            .invalid => {},
            .executed => |executed| if (executed.success) return executed.gas_used,
        }
    }
    const retry = request.message.gas != null or request.fees.gas_price != null;
    const executed = switch (first) {
        .invalid => |reason| {
            if (call_error.gas_too_high(reason) and retry) {
                return out_of_gas(&context, highest, gas_max);
            }
            if (call_error.gas_too_low(reason)) return exceeds_allowance(api, call, highest);
            return eth.fail_invalid(call, reason);
        },
        .executed => |executed| executed,
    };
    if (executed.exit.status() == .revert and retry) return out_of_gas(&context, highest, gas_max);
    if (!executed.success) {
        return eth.fail_executed(api, call, executed.output, executed.exit, highest);
    }
    assert(executed.gas_limit == highest);
    return search(&context, highest, executed.gas_used, executed.gas_refunded);
}

/// The optimistic guess, then the binary search over (lowest, highest].
fn search(context: *Estimate, highest_in: u64, gas_used_in: u64, refund: u64) HandlerError!u64 {
    var highest = highest_in;
    var gas_used = gas_used_in;
    var lowest = gas_used -| 1;
    const optimistic_wide = (@as(u128, gas_used) + refund + call_stipend_gas) * 64 / 63;
    const optimistic: u64 = @intCast(@min(optimistic_wide, std.math.maxInt(u64)));
    if (optimistic < highest) {
        const executed = switch (try context.run(optimistic, .none)) {
            .invalid => |reason| return eth.fail_invalid(context.call, reason),
            .executed => |executed| executed,
        };
        gas_used = executed.gas_used;
        if (executed.success) highest = optimistic else lowest = optimistic;
    }
    var middle = @min(gas_used *| 3, midpoint(highest, lowest));
    var iterations: u32 = 0;
    while (lowest + 1 < highest and iterations < eth.estimate_iterations_max) : (iterations += 1) {
        const range: f64 = @floatFromInt(highest - lowest);
        if (range / @as(f64, @floatFromInt(highest)) < estimate_gas_error_ratio) break;
        switch (try context.run(middle, .none)) {
            .invalid => |reason| {
                if (call_error.gas_too_high(reason)) {
                    highest = middle;
                } else if (call_error.gas_too_low(reason)) {
                    lowest = middle;
                } else return eth.fail_invalid(context.call, reason);
            },
            .executed => |executed| {
                if (executed.success) highest = middle else lowest = middle;
            },
        }
        middle = midpoint(highest, lowest);
    }
    assert(highest > 0);
    return highest;
}

fn midpoint(highest: u64, lowest: u64) u64 {
    return @intCast((@as(u128, highest) + lowest) / 2);
}

/// `map_out_of_gas_err`: retries at the gas maximum to tell a gas-limited failure (out of
/// gas at the requested `gas_limit`) from a real revert or halt.
fn out_of_gas(context: *Estimate, gas_limit: u64, gas_max: u64) HandlerError!u64 {
    const call = context.call;
    const executed = switch (try context.run(gas_max, .none)) {
        .invalid => |reason| return eth.fail_invalid(call, reason),
        .executed => |executed| executed,
    };
    if (!executed.success) {
        return eth.fail_executed(context.api, call, executed.output, executed.exit, gas_limit);
    }
    const failure = call_error.halt(context.api.scratch, .out_of_gas, gas_limit);
    return call.fail(failure.code, failure.message);
}

/// `RpcInvalidTransactionError::GasRequiredExceedsAllowance` (-32000).
fn exceeds_allowance(api: *Api, call: *Call, gas_limit: u64) HandlerError {
    const message = std.fmt.bufPrint(
        api.scratch,
        "gas required exceeds allowance ({d})",
        .{gas_limit},
    ) catch unreachable; // Proof: the scratch holds far more than this text.
    return call.fail(call_error.code_invalid_input, message);
}

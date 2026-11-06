//! `base_sendRawTransactionValidity(raw, {validity, validity_signature?})` (port of
//! base/base `txpool-rpc` `send_raw_transaction_validity`): runs the same ingress checks in
//! the same order, then hands the transaction and its predicates to `Api.validity_sink`.
//!
//! Checks: no `flashblock_index` predicates once Denim builds 200 ms blocks (no
//! flashblocks), the batch rules (non-empty, at most 64, storage value within its mask,
//! satisfiable flashblock bounds), a finite block-number expiry within 60 s of blocks from
//! the block being built, a decodable signed transaction, and EIP-8130 transactions only
//! from Everest. The signature mode is base/base's default `Off`: a `validity_signature` is
//! accepted but not verified.
//!
//! Predicates must be enforced where the transaction is included, so this node accepts
//! validity transactions only through a sink (pool storage plus builder enforcement, see
//! `txpool.validity.matches`); without one it rejects them after validation rather than
//! pooling them unenforced.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const txpool = @import("../txpool/root.zig");
const eth = @import("eth.zig");

const validity = txpool.validity;
const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "base_sendRawTransactionValidity", .handler = send_raw_transaction_validity },
};

pub const flashblock_index_unsupported = "flashblock_index predicates are not supported " ++
    "after Denim: blocks are built every 200ms without flashblocks";
pub const pre_everest = "EIP-8130 validity transactions are gated behind the Everest hard " ++
    "fork; they are not accepted before Everest is active";
pub const no_sink = "validity transactions are not supported by this node: no pool enforces " ++
    "their predicates";

/// Pre-Denim full-block interval.
pub const legacy_block_interval_ms: u64 = 2000;
pub const subsecond_block_interval_ms: u64 = 200;

/// Receives accepted validity transactions (pool storage and builder enforcement).
pub const Sink = struct {
    context: *anyopaque,
    submit: *const fn (
        context: *anyopaque,
        transaction: *const txpool.Tx,
        predicates: []const validity.Predicate,
    ) anyerror!void,
};

const Options = struct {
    predicates: [validity.predicates_max + 1]validity.Predicate = undefined,
    count: u32 = 0,
};

fn parse_options(raw: []const u8, options: *Options) error{ InvalidParams, TooMany }!void {
    var scanner = json.Scanner.init(raw);
    if ((scanner.next() catch return error.InvalidParams).tag != .object_begin) {
        return error.InvalidParams;
    }
    var found = false;
    var signed = false;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        if (std.mem.eql(u8, name.bytes, "validity") and !found) {
            options.count = try validity.parse_list(&scanner, &options.predicates);
            found = true;
        } else if (std.mem.eql(u8, name.bytes, "validity_signature") and !signed) {
            const value = scanner.next() catch return error.InvalidParams;
            if (value.tag == .null) continue;
            if (value.tag != .string) return error.InvalidParams;
            _ = json.parse_fixed(65, value.bytes) catch return error.InvalidParams;
            signed = true;
        } else return error.InvalidParams;
    }
    if (!found) return error.InvalidParams;
}

/// Whether the block being built is a 200 ms block: Denim at the head or at the next
/// legacy timestamp (the transition block counts).
fn builds_subsecond_blocks(api: *Api, head_timestamp: u64) bool {
    const next_legacy = head_timestamp +| legacy_block_interval_ms / 1000;
    return api.spec.is_upgrade_active(.denim, head_timestamp) or
        api.spec.is_upgrade_active(.denim, next_legacy);
}

fn send_raw_transaction_validity(api: *Api, call: *Call) HandlerError!void {
    const half = api.scratch.len / 2;
    const raw = try call.params.data(api.scratch[0..half]);
    const options_raw = try call.params.raw();
    try call.params.finish();
    var options: Options = .{};
    parse_options(options_raw, &options) catch |err| switch (err) {
        error.TooMany => return call.fail(rpc.code.invalid_params, validity.message(error.TooMany)),
        error.InvalidParams => return error.InvalidParams,
    };
    const predicates = options.predicates[0..options.count];
    const head = eth.head_header(api);
    const subsecond = builds_subsecond_blocks(api, head.timestamp);
    for (predicates) |predicate| {
        if (subsecond and predicate.kind == .flashblock_index) {
            return call.fail(rpc.code.invalid_params, flashblock_index_unsupported);
        }
    }
    validity.validate_batch(predicates) catch |err| {
        return call.fail(rpc.code.invalid_params, validity.message(err));
    };
    const interval_ms = if (subsecond) subsecond_block_interval_ms else legacy_block_interval_ms;
    validity.validate_block_expiry(predicates, head.number + 1, interval_ms) catch |err| {
        return call.fail(rpc.code.invalid_params, validity.message(err));
    };
    const validated = txpool.validate.validate(
        raw,
        api.scratch[half..],
        api.spec,
        head.timestamp + 1,
        api.chain.executor.recoverer,
    ) catch |err| return call.fail(rpc.code.invalid_params, @errorName(err));
    const is_eip8130 = raw.len > 0 and raw[0] == 0x79;
    if (is_eip8130 and !api.spec.is_upgrade_active(.everest, head.timestamp)) {
        return call.fail(rpc.code.invalid_params, pre_everest);
    }
    const sink = api.validity_sink orelse return call.fail(rpc.code.server_error, no_sink);
    sink.submit(sink.context, &validated.tx, predicates) catch |err| {
        return call.fail(rpc.code.server_error, @errorName(err));
    };
    try call.writer.data(&validated.tx.hash.bytes);
}

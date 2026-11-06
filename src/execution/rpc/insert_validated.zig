//! `base_insertValidatedTransaction(tx)` and `base_insertValidatedTransactions([tx...])`
//! (base/base `BuilderApi`): a mempool node that already validated a transaction and
//! recovered its sender forwards `{sender, raw}` and the pool takes it without recovering
//! the signature again. The batch form inserts up to `batch_max` in order and answers one
//! entry each: null where the single call would have succeeded, else its error object; a
//! malformed entry or an oversized batch fails the whole call before anything is inserted.
//!
//! Not ported: wire extensions (any key besides `sender`, `raw` and `metering` is refused,
//! base/base's default) and the metering cache (`metering` is accepted and ignored: the
//! builder owns metering).

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const eth = @import("eth.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Address = primitives.Address;

/// Most transactions one batch call may carry (base/base `MAX_VALIDATED_INSERT_BATCH`).
pub const batch_max: u32 = 1024;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "base_insertValidatedTransaction", .handler = insert_one },
    .{ .name = "base_insertValidatedTransactions", .handler = insert_batch },
};

pub const Item = struct { sender: Address, raw: []u8 };

pub const ParseError = error{ InvalidParams, ExtensionsDisabled };

/// Parses one `{sender, raw, metering?}` object whose `object_begin` was just read; the
/// transaction bytes are decoded into `space`.
pub fn parse_item(scanner: *json.Scanner, space: []u8) ParseError!Item {
    var sender: ?Address = null;
    var raw: ?[]u8 = null;
    var fields: u32 = 0;
    while (fields < 64) : (fields += 1) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = scanner.next() catch return error.InvalidParams;
        if (std.mem.eql(u8, name.bytes, "sender")) {
            const bytes = json.parse_fixed(20, value.bytes) catch return error.InvalidParams;
            sender = .{ .bytes = bytes };
        } else if (std.mem.eql(u8, name.bytes, "raw")) {
            raw = json.parse_data(value.bytes, space) catch return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "metering")) {
            scanner.skip(value) catch return error.InvalidParams;
        } else {
            return error.ExtensionsDisabled;
        }
    } else return error.InvalidParams;
    const item: Item = .{
        .sender = sender orelse return error.InvalidParams,
        .raw = raw orelse return error.InvalidParams,
    };
    if (item.raw.len == 0) return error.InvalidParams;
    return item;
}

fn parse_message(err: ParseError) []const u8 {
    return switch (err) {
        error.InvalidParams => "invalid validated transaction",
        error.ExtensionsDisabled => "transaction extensions are disabled",
    };
}

/// base/base's error for a failed insert: `message` is filled into `buffer`.
const Failure = struct { code: i32, message: []const u8 };

fn insert(api: *Api, item: Item, buffer: []u8) ?Failure {
    const failure = switch (eth.add_raw_checked(api, item.raw, item.sender)) {
        .added => return null,
        .failed => |failure| failure,
    };
    const pool_error = failure.pool_error orelse {
        // Validation (or a disabled pool) refused it before the pool saw it.
        if (failure.code != rpc.code.server_error) return .{
            .code = failure.code,
            .message = failure.message,
        };
        const text = std.fmt.bufPrint(buffer, "invalid transaction: {s}", .{failure.message});
        return .{ .code = rpc.code.invalid_params, .message = text catch failure.message };
    };
    // Forwarders treat a message ending in "already imported" as a duplicate.
    const reason = if (pool_error == error.AlreadyKnown) "already imported" else failure.message;
    const text = std.fmt.bufPrint(buffer, "pool rejected transaction: {s}", .{reason});
    return .{ .code = rpc.code.internal_error, .message = text catch failure.message };
}

fn insert_one(api: *Api, call: *Call) HandlerError!void {
    const text = try call.params.raw();
    try call.params.finish();
    const half = api.scratch.len / 2;
    var scanner = json.Scanner.init(text);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag != .object_begin) return error.InvalidParams;
    const item = parse_item(&scanner, api.scratch[0..half]) catch |err| {
        return call.fail(rpc.code.invalid_params, parse_message(err));
    };
    var buffer: [128]u8 = undefined;
    if (insert(api, item, &buffer)) |failure| return call.fail(failure.code, failure.message);
    try call.writer.null_value();
}

fn insert_batch(api: *Api, call: *Call) HandlerError!void {
    const text = try call.params.raw();
    try call.params.finish();
    const half = api.scratch.len / 2;
    // First pass: the whole batch must parse before anything is inserted.
    var count: u32 = 0;
    var check = json.Scanner.init(text);
    if ((check.next() catch return error.InvalidParams).tag != .array_begin) {
        return error.InvalidParams;
    }
    while (true) : (count += 1) {
        const token = check.next() catch return error.InvalidParams;
        if (token.tag == .array_end) break;
        if (count == batch_max) {
            return call.fail(rpc.code.invalid_params, "batch exceeds 1024 transactions");
        }
        if (token.tag != .object_begin) return error.InvalidParams;
        _ = parse_item(&check, api.scratch[0..half]) catch |err| {
            return call.fail(rpc.code.invalid_params, parse_message(err));
        };
    }
    var scanner = json.Scanner.init(text);
    _ = scanner.next() catch unreachable; // The first pass read the same `[`.
    try call.writer.begin_array();
    for (0..count) |_| {
        _ = scanner.next() catch unreachable; // `{`: parsed above.
        const item = parse_item(&scanner, api.scratch[0..half]) catch unreachable;
        var buffer: [128]u8 = undefined;
        if (insert(api, item, &buffer)) |failure| {
            try write_error(call.writer, failure);
        } else try call.writer.null_value();
    }
    try call.writer.end_array();
}

fn write_error(writer: *json.Writer, failure: Failure) HandlerError!void {
    assert(failure.message.len > 0);
    try writer.begin_object();
    try writer.key("code");
    try writer.integer(failure.code);
    try writer.key("message");
    try writer.string(failure.message);
    try writer.end_object();
}

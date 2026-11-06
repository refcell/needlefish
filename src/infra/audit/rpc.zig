//! The audit-archiver JSON-RPC query surface (base/base `AuditArchiverApi`, namespace
//! `base`), over the in-memory store:
//!
//!   base_getTransactionEventsByHash(tx_hash, limit?)
//!   base_getTransactionEventsByBlockNumber(block_number, limit?)
//!   base_getTransactionEventsByBlockHash(block_hash, limit?)
//!   base_getTransactionEventsByBundle(bundle_key, limit?)
//!   base_getRejectedTransactionEvents({fromBlock?, toBlock?, fromTime?, toTime?, limit?})
//!
//! Results are `TransactionEventRecord`s: the event envelope plus `ingested_at`. A hash that
//! is not 64 hex digits matches nothing (base/base binds SQL NULL). Limits are clamped to
//! 1..2000 (default 500). The retired write methods (`base_persistBatchedBundleEvent`,
//! `base_persistRejectedTransactionBatch`) are not in the table, so they get -32601.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const event_module = @import("event.zig");
const store_module = @import("store.zig");
const time = @import("time.zig");

const Store = store_module.Store;

/// What the handlers see: the store and the wall clock of this request.
pub const Context = struct {
    store: *Store,
    now_ns: u64,
};

pub const methods = [_]rpc.Method(*Context){
    .{ .name = "base_getTransactionEventsByHash", .handler = by_hash },
    .{ .name = "base_getTransactionEventsByBlockNumber", .handler = by_block_number },
    .{ .name = "base_getTransactionEventsByBlockHash", .handler = by_block_hash },
    .{ .name = "base_getTransactionEventsByBundle", .handler = by_bundle },
    .{ .name = "base_getRejectedTransactionEvents", .handler = rejected },
};

pub const Router = rpc.Router(*Context, &methods);

fn by_hash(context: *Context, call: *rpc.Call) rpc.HandlerError!void {
    const hash = try hash_param(call);
    const limit = try limit_param(call);
    try call.params.finish();
    const key: store_module.Key = .{
        .tx_hash = hash orelse return write_records(context, call, &.{}),
    };
    try write_records(context, call, context.store.query(key, limit, context.now_ns));
}

fn by_block_hash(context: *Context, call: *rpc.Call) rpc.HandlerError!void {
    const hash = try hash_param(call);
    const limit = try limit_param(call);
    try call.params.finish();
    const key: store_module.Key = .{
        .block_hash = hash orelse return write_records(context, call, &.{}),
    };
    try write_records(context, call, context.store.query(key, limit, context.now_ns));
}

/// A string param holding a hash; null when the string is not one (it matches nothing).
fn hash_param(call: *rpc.Call) rpc.HandlerError!?[32]u8 {
    var buffer: [128]u8 = undefined;
    const text = string_param(call, &buffer) catch |err| switch (err) {
        error.TooLong => return null,
        else => |other| return other,
    };
    assert(text.len <= buffer.len);
    return event_module.parse_hash(text);
}

fn by_block_number(context: *Context, call: *rpc.Call) rpc.HandlerError!void {
    const raw = try call.params.raw();
    const number = std.fmt.parseInt(u64, raw, 10) catch return error.InvalidParams;
    const limit = try limit_param(call);
    try call.params.finish();
    if (number > std.math.maxInt(i64)) {
        return call.fail(rpc.code.internal_error, "internal server error");
    }
    const key: store_module.Key = .{ .block_number = number };
    try write_records(context, call, context.store.query(key, limit, context.now_ns));
}

fn by_bundle(context: *Context, call: *rpc.Call) rpc.HandlerError!void {
    var buffer: [event_module.bundle_key_size_max + 1]u8 = undefined;
    const text = string_param(call, &buffer) catch |err| switch (err) {
        // Longer than any indexed bundle key: a valid request that matches nothing.
        error.TooLong => {
            _ = try limit_param(call);
            try call.params.finish();
            return write_records(context, call, &.{});
        },
        else => |other| return other,
    };
    const limit = try limit_param(call);
    try call.params.finish();
    const key: store_module.Key = .{ .bundle = text };
    try write_records(context, call, context.store.query(key, limit, context.now_ns));
}

fn rejected(context: *Context, call: *rpc.Call) rpc.HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    const filter = parse_rejected_query(raw) catch return error.InvalidParams;
    try write_records(context, call, context.store.query_rejected(filter, context.now_ns));
}

const StringError = rpc.HandlerError || error{TooLong};

/// The next param as an unescaped string (serde `String`).
fn string_param(call: *rpc.Call, buffer: []u8) StringError![]const u8 {
    const raw = try call.params.raw();
    var scanner = json.Scanner.init(raw);
    const token = scanner.next() catch return error.InvalidParams;
    if (token.tag != .string) return error.InvalidParams;
    const text = json.unescape(token, buffer) catch |err| switch (err) {
        error.NoSpaceLeft => return error.TooLong,
        error.InvalidString => return error.InvalidParams,
    };
    assert(text.len <= raw.len);
    return text;
}

/// The optional trailing `limit: Option<i64>`, clamped.
fn limit_param(call: *rpc.Call) rpc.HandlerError!u32 {
    const raw = try call.params.optional_raw() orelse return store_module.query_limit_default;
    return parse_limit(raw) catch error.InvalidParams;
}

fn parse_limit(raw: []const u8) error{Invalid}!u32 {
    if (std.mem.eql(u8, raw, "null")) return store_module.query_limit_default;
    const value = std.fmt.parseInt(i64, raw, 10) catch return error.Invalid;
    const clamped = std.math.clamp(value, 1, store_module.query_limit_max);
    assert(clamped >= 1);
    return @intCast(clamped);
}

/// base/base `RejectedTransactionEventQuery` (camelCase, every field optional, unknown
/// fields ignored, `fromTime`/`toTime` RFC 3339).
pub fn parse_rejected_query(raw: []const u8) error{Invalid}!store_module.RejectedQuery {
    var query: store_module.RejectedQuery = .{};
    var scanner = json.Scanner.init(raw);
    const first = scanner.next() catch return error.Invalid;
    if (first.tag != .object_begin) return error.Invalid;
    var members: u32 = 0;
    while (members <= raw.len) : (members += 1) {
        const key = scanner.next() catch return error.Invalid;
        if (key.tag == .object_end) return query;
        const value = scanner.next() catch return error.Invalid;
        const field = std.meta.stringToEnum(RejectedField, key.bytes) orelse {
            scanner.skip(value) catch return error.Invalid;
            continue;
        };
        if (key.escaped) return error.Invalid;
        if (value.tag == .null) continue;
        switch (field) {
            .fromBlock => query.from_block = try number_value(value, u64),
            .toBlock => query.to_block = try number_value(value, u64),
            .fromTime => query.from_time_ns = try time_value(value),
            .toTime => query.to_time_ns = try time_value(value),
            .limit => {
                if (value.tag != .number) return error.Invalid;
                query.limit = parse_limit(value.bytes) catch return error.Invalid;
            },
        }
    }
    return error.Invalid;
}

const RejectedField = enum { fromBlock, toBlock, fromTime, toTime, limit };

fn number_value(value: json.Token, comptime T: type) error{Invalid}!T {
    if (value.tag != .number) return error.Invalid;
    const number = std.fmt.parseInt(T, value.bytes, 10) catch return error.Invalid;
    if (number > std.math.maxInt(i64)) return error.Invalid;
    return number;
}

fn time_value(value: json.Token) error{Invalid}!u64 {
    if (value.tag != .string or value.escaped) return error.Invalid;
    const parsed = time.parse(value.bytes) catch return error.Invalid;
    assert(parsed <= std.math.maxInt(u64));
    return parsed;
}

fn write_records(context: *Context, call: *rpc.Call, slots: []const u32) rpc.HandlerError!void {
    assert(slots.len <= store_module.query_limit_max);
    try call.writer.begin_array();
    for (slots) |slot| {
        const record = context.store.get(slot);
        write_record(call.writer, &record) catch return error.WriteFailed;
    }
    try call.writer.end_array();
}

/// A `TransactionEventRecord` (the flattened envelope plus `ingested_at`).
pub fn write_record(
    writer: *json.Writer,
    record: *const store_module.Record,
) json.Writer.WriteError!void {
    const value = &record.event;
    var time_buffer: [time.formatted_size_max]u8 = undefined;
    try writer.begin_object();
    try writer.key("schema_version");
    try writer.string(event_module.schema_version);
    try writer.key("event_id");
    try writer.string(value.event_id);
    try writer.key("event_time");
    try writer.string(time.format(value.event_time_ns, &time_buffer));
    try writer.key("producer");
    try writer.string(value.producer.wire_name());
    try writer.key("event_type");
    try writer.string(value.event_type.wire_name());
    try optional_string(writer, "network", value.network);
    try optional_hash(writer, "tx_hash", value.tx_hash);
    try optional_hash(writer, "block_hash", value.block_hash);
    try writer.key("block_number");
    if (value.block_number) |number| try writer.integer(number) else try writer.null_value();
    try optional_string(writer, "payload_id", value.payload_id);
    try optional_string(writer, "request_id", value.request_id);
    try writer.key("data");
    try writer.raw(value.data);
    try writer.key("ingested_at");
    try writer.string(time.format(record.ingested_at_ns, &time_buffer));
    try writer.end_object();
}

fn optional_string(writer: *json.Writer, name: []const u8, value: ?[]const u8) !void {
    try writer.key(name);
    if (value) |text| try writer.string(text) else try writer.null_value();
}

fn optional_hash(writer: *json.Writer, name: []const u8, value: ?[32]u8) !void {
    try writer.key(name);
    if (value) |hash| try writer.data(&hash) else try writer.null_value();
}

test {
    _ = @import("rpc_test.zig");
}

//! The `transaction-event/v1` envelope (base/base `crates/common/observability-events`):
//! vocabulary, a decoder for one NDJSON line, and the validation rules of audit-archiver's
//! `validate_transaction_event` and `TransactionEvent::validate`.
//!
//! The decoder runs on one line (a JSON object) and never allocates: unescaped strings, the
//! whitespace-free `data` object, and the bundle keys are written into a caller scratch
//! buffer of at least `scratch_size(limits)` bytes; other slices point into the line.
//!
//! Checks, in base/base's order: the line size, the `data` size, the envelope (required
//! fields, types, enum variants, duplicate fields), the schema version, a non-blank
//! `event_id`, forbidden or too deeply nested `data` keys, and `block_number` within the
//! signed 64-bit range. Unknown envelope fields are ignored, as serde does.
//!
//! needlefish drops the `BUILDER_FLASHBLOCK_*` event types (no flashblocks, AGENTS.md rule
//! 10): such events are rejected with their own reason instead of being stored.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const time = @import("time.zig");

pub const schema_version = "transaction-event/v1";
/// base/base `MAX_DATA_VALIDATION_DEPTH`.
pub const data_depth_max = 16;
/// Longest `data.bundle_id` / `data.bundle_hash` string that is indexed.
pub const bundle_key_size_max = 256;
/// Longest accepted `event_id` (base/base has no limit; bounded here so stored records and
/// echoed ingest results stay bounded).
pub const event_id_size_max = 256;
const key_size_max = 64;

pub const Limits = struct {
    /// base/base `DEFAULT_TRANSACTION_EVENT_MAX_EVENT_BYTES`.
    event_bytes_max: u32 = 256 * 1024,
    /// base/base `DEFAULT_TRANSACTION_EVENT_MAX_DATA_BYTES`.
    data_bytes_max: u32 = 128 * 1024,
};

/// Scratch bytes `decode` needs for any line within `limits`.
pub fn scratch_size(limits: Limits) u32 {
    return limits.event_bytes_max + 2 * bundle_key_size_max;
}

/// base/base `TransactionEventRetentionClass`: high-volume success paths (hot), ordinary
/// arrival and forwarding (warm), failures, drops, and inclusion (cold).
pub const RetentionClass = enum(u8) { hot, warm, cold };

pub const Producer = enum(u8) {
    base_reth_node,
    base_builder,
    ingress_rpc,
    base_routing_proxyd,

    pub fn wire_name(producer: Producer) []const u8 {
        return switch (producer) {
            .base_reth_node => "base-reth-node",
            .base_builder => "base-builder",
            .ingress_rpc => "ingress-rpc",
            .base_routing_proxyd => "base-routing/proxyd",
        };
    }
};

/// Event kinds; the wire name is the tag name in upper case.
pub const EventType = enum(u8) {
    proxy_received,
    proxy_rejected,
    proxy_validation_accepted,
    proxy_validation_rejected,
    proxy_routed_to_backend,
    proxy_backend_success,
    proxy_backend_failure,
    proxy_ingress_rpc_attempt,
    proxy_ingress_rpc_success,
    proxy_ingress_rpc_failure,
    ingress_received,
    simulation_started,
    simulation_succeeded,
    simulation_failed,
    ingress_metering_send_attempt,
    ingress_metering_send_success,
    ingress_metering_send_failure,
    ingress_metering_send_dropped,
    txpool_pending,
    txpool_queued,
    txpool_pending_to_queued,
    txpool_queued_to_pending,
    txpool_dropped,
    txpool_replaced,
    txpool_tracking_overflowed,
    txpool_builder_forward_attempt,
    txpool_builder_forward_success,
    txpool_builder_forward_failure,
    txpool_builder_forward_dropped,
    txpool_builder_consumed,
    txpool_validated_insert_accepted,
    txpool_validated_insert_rejected,
    txpool_send_raw_transaction,
    txpool_send_raw_transaction_validity,
    builder_considered,
    builder_accepted,
    builder_rejected,
    builder_deferred,
    builder_expired,
    builder_included,
    builder_payload_finalized,

    const all = std.enums.values(EventType);
    const wire_names: [all.len][]const u8 = names: {
        @setEvalBranchQuota(20_000);
        var names: [all.len][]const u8 = undefined;
        for (all, 0..) |event_type, index| {
            const tag = @tagName(event_type);
            var upper: [tag.len]u8 = undefined;
            _ = std.ascii.upperString(&upper, tag);
            const final = upper;
            names[index] = &final;
        }
        break :names names;
    };

    pub fn wire_name(event_type: EventType) []const u8 {
        return wire_names[@backingInt(event_type)];
    }

    pub fn from_wire(text: []const u8) ?EventType {
        for (all, wire_names) |event_type, name| {
            if (std.mem.eql(u8, name, text)) return event_type;
        }
        return null;
    }

    /// base/base `TransactionEventRetentionClass::for_event_type`.
    pub fn retention_class(event_type: EventType) RetentionClass {
        return switch (event_type) {
            .proxy_received,
            .proxy_validation_accepted,
            .proxy_routed_to_backend,
            .proxy_backend_success,
            .proxy_ingress_rpc_attempt,
            .proxy_ingress_rpc_success,
            .builder_considered,
            .builder_accepted,
            .builder_rejected,
            .builder_deferred,
            .builder_expired,
            => .hot,
            .ingress_received,
            .simulation_started,
            .simulation_succeeded,
            .ingress_metering_send_attempt,
            .ingress_metering_send_success,
            .txpool_pending,
            .txpool_queued,
            .txpool_pending_to_queued,
            .txpool_queued_to_pending,
            .txpool_builder_forward_attempt,
            .txpool_builder_forward_success,
            .txpool_builder_consumed,
            .txpool_validated_insert_accepted,
            .txpool_send_raw_transaction,
            .txpool_send_raw_transaction_validity,
            => .warm,
            .proxy_rejected,
            .proxy_validation_rejected,
            .proxy_backend_failure,
            .proxy_ingress_rpc_failure,
            .simulation_failed,
            .ingress_metering_send_failure,
            .ingress_metering_send_dropped,
            .txpool_dropped,
            .txpool_replaced,
            .txpool_tracking_overflowed,
            .txpool_builder_forward_failure,
            .txpool_builder_forward_dropped,
            .txpool_validated_insert_rejected,
            .builder_included,
            .builder_payload_finalized,
            => .cold,
        };
    }

    /// Served by `getRejectedTransactionEvents` (base/base `REJECTED_EVENT_TYPES_SQL`).
    pub fn rejected(event_type: EventType) bool {
        return switch (event_type) {
            .simulation_failed, .builder_rejected, .builder_expired => true,
            else => false,
        };
    }
};

pub const Event = struct {
    event_id: []const u8,
    event_time_ns: u64,
    producer: Producer,
    event_type: EventType,
    network: ?[]const u8 = null,
    tx_hash: ?[32]u8 = null,
    block_hash: ?[32]u8 = null,
    block_number: ?u64 = null,
    payload_id: ?[]const u8 = null,
    request_id: ?[]const u8 = null,
    /// The `data` object without insignificant whitespace.
    data: []const u8,
    /// Top-level string `data.bundle_id`, if at most `bundle_key_size_max` bytes.
    bundle_id: ?[]const u8 = null,
    /// Top-level string `data.bundle_hash`, if at most `bundle_key_size_max` bytes.
    bundle_hash: ?[]const u8 = null,
};

pub const Field = enum {
    schema_version,
    event_id,
    event_time,
    producer,
    event_type,
    network,
    tx_hash,
    block_hash,
    block_number,
    payload_id,
    request_id,
    data,
};

pub const Reason = enum {
    event_too_large,
    data_too_large,
    /// The line is not one well-formed JSON object (replay of a foreign record).
    invalid_json,
    missing_field,
    duplicate_field,
    invalid_field,
    flashblock_event_type,
    invalid_schema_version,
    missing_event_id,
    event_id_too_long,
    forbidden_data_key,
    data_too_deep,
    block_number_range,
    /// Set by ingest: older than the retention window.
    expired,
    /// Set by ingest: further ahead of the clock than the allowed skew.
    future,
};

pub const Rejection = struct {
    reason: Reason,
    field: Field = .data,
    /// Raw text for the message (schema version, forbidden key), a slice of the line.
    text: []const u8 = "",
    size: u64 = 0,
    limit: u64 = 0,

    /// Longest echoed `text` (a schema version or data key) in a message.
    pub const text_size_max = 128;

    /// Writes the human-readable reason (base/base wording where it has one).
    pub fn write(rejection: Rejection, out: *std.Io.Writer) std.Io.Writer.Error!void {
        var shown = rejection;
        shown.text = truncate_utf8(rejection.text, text_size_max);
        return shown.write_full(out);
    }

    fn write_full(rejection: Rejection, out: *std.Io.Writer) std.Io.Writer.Error!void {
        assert(rejection.text.len <= text_size_max);
        const field = @tagName(rejection.field);
        const envelope = "invalid transaction event envelope: ";
        switch (rejection.reason) {
            .event_too_large => try out.print("event size {d} exceeds maximum {d} bytes", .{
                rejection.size, rejection.limit,
            }),
            .data_too_large => try out.print("data size {d} exceeds maximum {d} bytes", .{
                rejection.size, rejection.limit,
            }),
            .invalid_json => try out.writeAll("invalid transaction event JSON object"),
            .missing_field => try out.print("{s}missing field `{s}`", .{ envelope, field }),
            .duplicate_field => try out.print("{s}duplicate field `{s}`", .{ envelope, field }),
            .invalid_field => try out.print("{s}invalid value for `{s}`", .{ envelope, field }),
            .flashblock_event_type => try out.writeAll("flashblock event types are not supported"),
            .invalid_schema_version => try out.print(
                "invalid transaction event schema_version {s}",
                .{rejection.text},
            ),
            .missing_event_id => try out.writeAll("transaction event event_id is required"),
            .event_id_too_long => try out.print("event_id exceeds maximum {d} bytes", .{
                event_id_size_max,
            }),
            .forbidden_data_key => try out.print(
                "transaction event data contains forbidden key {s}",
                .{rejection.text},
            ),
            .data_too_deep => try out.writeAll(
                "transaction event data exceeds maximum validation depth",
            ),
            .block_number_range => try out.writeAll("block_number exceeds Postgres BIGINT range"),
            .expired => try out.print("event_time is older than the {s} retention window", .{
                rejection.text,
            }),
            .future => try out.print("event_time is more than {d} seconds in the future", .{
                rejection.limit,
            }),
        }
    }
};

pub const Decoded = union(enum) {
    event: Event,
    rejected: Rejection,
};

/// Decodes and validates one NDJSON line. `scratch` must hold `scratch_size(limits)` bytes.
pub fn decode(line: []const u8, limits: Limits, scratch: []u8) Decoded {
    assert(scratch.len >= scratch_size(limits));
    assert(limits.data_bytes_max <= limits.event_bytes_max);
    if (line.len > limits.event_bytes_max) {
        return .{ .rejected = .{
            .reason = .event_too_large,
            .size = line.len,
            .limit = limits.event_bytes_max,
        } };
    }
    var decoder: Decoder = .{ .scanner = json.Scanner.init(line), .scratch = scratch };
    decoder.scan_envelope() catch return .{ .rejected = .{ .reason = .invalid_json } };
    assert(decoder.scratch_used <= scratch.len);
    return decoder.finish(limits);
}

/// The top-level `event_id` string of a line (for results of rejected events), unescaped
/// into `buffer`; null when absent, not a string, or too long.
pub fn find_event_id(line: []const u8, buffer: []u8) ?[]const u8 {
    const raw = json.find_path(line, &.{"event_id"}) catch return null;
    const text = raw orelse return null;
    assert(text.len > 0);
    var scanner = json.Scanner.init(text);
    const token = scanner.next() catch return null;
    if (token.tag != .string) return null;
    return json.unescape(token, buffer) catch null;
}

const Decoder = struct {
    scanner: json.Scanner,
    scratch: []u8,
    scratch_used: usize = 0,
    seen: std.EnumSet(Field) = .empty,
    envelope_error: ?Rejection = null,
    validation_error: ?Rejection = null,
    data_size: usize = 0,
    data_object: bool = false,
    schema_version: []const u8 = "",
    event: Event = .{
        .event_id = "",
        .event_time_ns = 0,
        .producer = .base_builder,
        .event_type = .builder_accepted,
        .data = "",
    },

    const ScanError = json.Error || error{NotObject};

    fn scan_envelope(decoder: *Decoder) ScanError!void {
        const first = try decoder.scanner.next();
        if (first.tag != .object_begin) return error.NotObject;
        var members: u32 = 0;
        while (members <= decoder.scanner.input.len) : (members += 1) {
            const key = try decoder.scanner.next();
            if (key.tag == .object_end) break;
            assert(key.key);
            const value = try decoder.scanner.next();
            const field = match_field(key) orelse {
                try decoder.scanner.skip(value);
                continue;
            };
            if (decoder.seen.contains(field)) {
                decoder.fail_envelope(.duplicate_field, field);
                try decoder.scanner.skip(value);
                continue;
            }
            decoder.seen.insert(field);
            try decoder.scan_field(field, value);
        }
        const end = try decoder.scanner.next();
        if (end.tag != .end) return error.TrailingData;
    }

    fn match_field(key: json.Token) ?Field {
        assert(key.tag == .string);
        var buffer: [key_size_max]u8 = undefined;
        const name = json.unescape(key, &buffer) catch return null;
        assert(name.len <= key.bytes.len);
        return std.meta.stringToEnum(Field, name);
    }

    fn fail_envelope(decoder: *Decoder, reason: Reason, field: Field) void {
        assert(reason == .missing_field or reason == .duplicate_field or
            reason == .invalid_field or reason == .flashblock_event_type);
        if (decoder.envelope_error == null) {
            decoder.envelope_error = .{ .reason = reason, .field = field };
        }
        assert(decoder.envelope_error != null);
    }

    fn scan_field(decoder: *Decoder, field: Field, value: json.Token) ScanError!void {
        assert(decoder.seen.contains(field));
        switch (field) {
            .data => return decoder.scan_data(value),
            .block_number => decoder.event.block_number = decoder.number(value),
            .tx_hash => decoder.event.tx_hash = decoder.hash(value, field),
            .block_hash => decoder.event.block_hash = decoder.hash(value, field),
            else => {},
        }
        switch (value.tag) {
            .object_begin, .array_begin => {
                decoder.fail_envelope(.invalid_field, field);
                try decoder.scanner.skip(value);
                return;
            },
            else => {},
        }
        switch (field) {
            .data, .block_number, .tx_hash, .block_hash => {},
            .network => decoder.event.network = decoder.optional_string(value, field),
            .payload_id => decoder.event.payload_id = decoder.optional_string(value, field),
            .request_id => decoder.event.request_id = decoder.optional_string(value, field),
            .schema_version, .event_id, .event_time, .producer, .event_type => {
                decoder.required_field(field, value);
            },
        }
    }

    fn required_field(decoder: *Decoder, field: Field, value: json.Token) void {
        assert(value.tag != .object_begin and value.tag != .array_begin);
        const text = decoder.string(value, field) orelse return;
        switch (field) {
            .schema_version => decoder.schema_version = text,
            .event_id => decoder.event.event_id = text,
            .event_time => decoder.event.event_time_ns = time.parse(text) catch {
                return decoder.fail_envelope(.invalid_field, field);
            },
            .producer => decoder.event.producer = for (std.enums.values(Producer)) |producer| {
                if (std.mem.eql(u8, producer.wire_name(), text)) break producer;
            } else return decoder.fail_envelope(.invalid_field, field),
            .event_type => decoder.event.event_type = EventType.from_wire(text) orelse {
                const flashblock = std.mem.startsWith(u8, text, "BUILDER_FLASHBLOCK_");
                const reason: Reason = if (flashblock) .flashblock_event_type else .invalid_field;
                return decoder.fail_envelope(reason, field);
            },
            else => unreachable,
        }
    }

    /// A string value, unescaped into scratch when needed; null (and an envelope error) when
    /// the value is not a string.
    fn string(decoder: *Decoder, value: json.Token, field: Field) ?[]const u8 {
        if (value.tag != .string) {
            decoder.fail_envelope(.invalid_field, field);
            return null;
        }
        if (!value.escaped) return value.bytes;
        const free = decoder.scratch[decoder.scratch_used..];
        const text = json.unescape(value, free) catch {
            decoder.fail_envelope(.invalid_field, field);
            return null;
        };
        assert(text.len <= value.bytes.len);
        decoder.scratch_used += text.len;
        return text;
    }

    fn optional_string(decoder: *Decoder, value: json.Token, field: Field) ?[]const u8 {
        if (value.tag == .null) return null;
        return decoder.string(value, field);
    }

    fn hash(decoder: *Decoder, value: json.Token, field: Field) ?[32]u8 {
        assert(field == .tx_hash or field == .block_hash);
        if (value.tag == .null) return null;
        const text = decoder.string(value, field) orelse return null;
        return parse_hash(text) orelse {
            decoder.fail_envelope(.invalid_field, field);
            return null;
        };
    }

    fn number(decoder: *Decoder, value: json.Token) ?u64 {
        if (value.tag == .null) return null;
        if (value.tag == .number) {
            if (std.fmt.parseInt(u64, value.bytes, 10)) |parsed| return parsed else |_| {}
        }
        decoder.fail_envelope(.invalid_field, .block_number);
        return null;
    }

    fn scan_data(decoder: *Decoder, value: json.Token) ScanError!void {
        const input = decoder.scanner.input;
        const start = @intFromPtr(input.ptr);
        const value_offset: usize = switch (value.tag) {
            .object_begin, .array_begin => decoder.scanner.offset() - 1,
            .string => @intFromPtr(value.bytes.ptr) - start - 1,
            .number => @intFromPtr(value.bytes.ptr) - start,
            else => decoder.scanner.offset() - (if (value.tag == .false) @as(u32, 5) else 4),
        };
        try decoder.scanner.skip(value);
        const raw = input[value_offset..decoder.scanner.offset()];
        const free = decoder.scratch[decoder.scratch_used..];
        const compact = compact_json(raw, free);
        decoder.data_size = compact.len;
        if (value.tag != .object_begin) {
            decoder.fail_envelope(.invalid_field, .data);
            return;
        }
        decoder.scratch_used += compact.len;
        decoder.event.data = compact;
        decoder.data_object = true;
        try decoder.inspect_data(compact);
    }

    /// Forbidden keys, nesting depth, and the top-level bundle keys of `data`.
    fn inspect_data(decoder: *Decoder, data: []const u8) json.Error!void {
        var scanner = json.Scanner.init(data);
        const first = try scanner.next();
        assert(first.tag == .object_begin);
        var pending: ?enum { bundle_id, bundle_hash } = null;
        var tokens: u32 = 0;
        while (tokens <= data.len) : (tokens += 1) {
            const token = try scanner.next();
            if (token.tag == .end) break;
            const opens = token.tag == .object_begin or token.tag == .array_begin;
            const depth = if (opens) scanner.depth - 1 else scanner.depth;
            const closes = token.tag == .object_end or token.tag == .array_end;
            if (!closes and !token.key and depth > data_depth_max) {
                decoder.fail_validation(.{ .reason = .data_too_deep });
            }
            if (token.key) {
                decoder.check_key(token);
                pending = null;
                if (scanner.depth == 1 and !token.escaped) {
                    if (std.mem.eql(u8, token.bytes, "bundle_id")) pending = .bundle_id;
                    if (std.mem.eql(u8, token.bytes, "bundle_hash")) pending = .bundle_hash;
                }
                continue;
            }
            const which = pending orelse continue;
            pending = null;
            if (token.tag != .string) continue;
            const slot = switch (which) {
                .bundle_id => &decoder.event.bundle_id,
                .bundle_hash => &decoder.event.bundle_hash,
            };
            if (slot.* == null) slot.* = decoder.bundle_key(token);
        }
        assert(scanner.depth == 0);
    }

    fn check_key(decoder: *Decoder, key: json.Token) void {
        assert(key.key and key.tag == .string);
        var buffer: [key_size_max]u8 = undefined;
        const name = json.unescape(key, &buffer) catch return; // Longer than any forbidden key.
        if (forbidden_key(name)) {
            decoder.fail_validation(.{ .reason = .forbidden_data_key, .text = key.bytes });
        }
    }

    fn bundle_key(decoder: *Decoder, token: json.Token) ?[]const u8 {
        assert(token.tag == .string);
        if (!token.escaped) {
            return if (token.bytes.len <= bundle_key_size_max) token.bytes else null;
        }
        const free = decoder.scratch[decoder.scratch_used..];
        const room = @min(free.len, bundle_key_size_max);
        const text = json.unescape(token, free[0..room]) catch return null;
        decoder.scratch_used += text.len;
        assert(decoder.scratch_used <= decoder.scratch.len);
        return text;
    }

    fn fail_validation(decoder: *Decoder, rejection: Rejection) void {
        assert(rejection.reason == .forbidden_data_key or rejection.reason == .data_too_deep);
        if (decoder.validation_error == null) decoder.validation_error = rejection;
    }

    fn finish(decoder: *Decoder, limits: Limits) Decoded {
        if (decoder.data_size > limits.data_bytes_max) {
            return .{ .rejected = .{
                .reason = .data_too_large,
                .size = decoder.data_size,
                .limit = limits.data_bytes_max,
            } };
        }
        if (decoder.envelope_error) |rejection| return .{ .rejected = rejection };
        const required = [_]Field{
            .schema_version, .event_id, .event_time, .producer, .event_type, .data,
        };
        for (required) |field| {
            if (!decoder.seen.contains(field)) {
                return .{ .rejected = .{ .reason = .missing_field, .field = field } };
            }
        }
        assert(decoder.data_object);
        if (!std.mem.eql(u8, decoder.schema_version, schema_version)) {
            return .{ .rejected = .{
                .reason = .invalid_schema_version,
                .text = decoder.schema_version,
            } };
        }
        if (std.mem.trim(u8, decoder.event.event_id, " \t\r\n").len == 0) {
            return .{ .rejected = .{ .reason = .missing_event_id } };
        }
        if (decoder.event.event_id.len > event_id_size_max) {
            return .{ .rejected = .{ .reason = .event_id_too_long } };
        }
        if (decoder.validation_error) |rejection| return .{ .rejected = rejection };
        if (decoder.event.block_number) |block_number| {
            if (block_number > std.math.maxInt(i64)) {
                return .{ .rejected = .{ .reason = .block_number_range } };
            }
        }
        return .{ .event = decoder.event };
    }
};

/// The longest prefix of `text` of at most `size_max` bytes that ends on a UTF-8 boundary.
pub fn truncate_utf8(text: []const u8, size_max: usize) []const u8 {
    if (text.len <= size_max) return text;
    var cut = size_max;
    while (cut > 0 and text[cut] & 0xc0 == 0x80) cut -= 1;
    assert(cut <= size_max);
    return text[0..cut];
}

/// base/base `is_forbidden_data_key` (ASCII case-insensitive).
pub fn forbidden_key(name: []const u8) bool {
    const forbidden = [_][]const u8{
        "raw_transaction", "raw_tx",            "raw_transaction_bytes", "raw_tx_bytes",
        "calldata",        "request_body",      "body",                  "authorization",
        "api_key",         "api_keys",          "secret",                "secrets",
        "x-forwarded-for", "forwarded_headers", "headers",
    };
    for (forbidden) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, name)) return true;
    }
    return false;
}

/// 32 bytes from 64 hex digits with an optional `0x`/`0X` prefix, any case.
pub fn parse_hash(text: []const u8) ?[32]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    const has_prefix = trimmed.len >= 2 and trimmed[0] == '0' and
        (trimmed[1] == 'x' or trimmed[1] == 'X');
    const digits = if (has_prefix) trimmed[2..] else trimmed;
    if (digits.len != 64) return null;
    var bytes: [32]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&bytes, digits) catch return null;
    assert(decoded.len == 32);
    return bytes;
}

/// Copies a well-formed JSON value without insignificant whitespace into `out`, which must
/// be at least as long as `raw`.
pub fn compact_json(raw: []const u8, out: []u8) []const u8 {
    assert(out.len >= raw.len);
    var written: usize = 0;
    var in_string = false;
    var escaped = false;
    for (raw) |byte| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
        } else switch (byte) {
            ' ', '\t', '\r', '\n' => continue,
            '"' => in_string = true,
            else => {},
        }
        out[written] = byte;
        written += 1;
    }
    assert(written <= raw.len);
    return out[0..written];
}

test {
    _ = @import("event_test.zig");
}

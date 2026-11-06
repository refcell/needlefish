//! The append-only segment file format for durable audit events (pure encode/decode; the
//! binary does the file IO).
//!
//! A segment is a sequence of records, each:
//!
//!   magic "AEV1" | payload length u32 LE | CRC-32 (ISO-HDLC) of the payload u32 LE | payload
//!
//! The payload is: `ingested_at` u64, `event_time` u64, `block_number` u64 (all LE), a
//! presence byte, `tx_hash` and `block_hash` (32 bytes each, zero when absent), then the
//! producer and event-type wire names (u8 length + bytes) and seven texts (u32 LE length +
//! bytes): event id, network, payload id, request id, data, bundle id, bundle hash. Wire
//! names instead of enum indices keep old segments readable when the vocabulary changes.
//!
//! Replay stops at the first record that is incomplete (a torn tail write) or corrupt; the
//! caller truncates the file there before appending.

const std = @import("std");
const assert = std.debug.assert;

const event_module = @import("event.zig");
const store_module = @import("store.zig");

const Event = event_module.Event;
const Record = store_module.Record;

pub const magic = "AEV1";
pub const header_size = 12;
const fixed_payload_size = 3 * 8 + 1 + 2 * 32;
const name_size_max = 64;
const text_count = 7;

/// Largest payload for records whose texts total at most `texts_max` bytes.
pub fn payload_size_max(texts_max: u32) u32 {
    return fixed_payload_size + 2 * (1 + name_size_max) + text_count * 4 + texts_max;
}

/// Largest encoded record for `limits` (see `store.Store.record_size`).
pub fn record_size_max(limits: event_module.Limits) u32 {
    const texts_max = limits.event_bytes_max + store_module.record_overhead_bytes;
    return header_size + payload_size_max(texts_max);
}

const Present = packed struct(u8) {
    network: bool = false,
    tx_hash: bool = false,
    block_hash: bool = false,
    block_number: bool = false,
    payload_id: bool = false,
    request_id: bool = false,
    bundle_id: bool = false,
    bundle_hash: bool = false,
};

/// Encodes `record` into `out` (at least `header_size + payload_size_max(texts)` bytes).
pub fn encode(record: *const Record, out: []u8) []const u8 {
    const value = &record.event;
    assert(value.event_id.len > 0);
    var writer: std.Io.Writer = .fixed(out[header_size..]);
    encode_payload(record, &writer) catch unreachable; // Caller sized `out`.
    const payload = writer.buffered();
    @memcpy(out[0..4], magic);
    std.mem.writeInt(u32, out[4..8], @intCast(payload.len), .little);
    std.mem.writeInt(u32, out[8..12], std.hash.Crc32.hash(payload), .little);
    assert(payload.len >= fixed_payload_size);
    return out[0 .. header_size + payload.len];
}

fn encode_payload(record: *const Record, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const value = &record.event;
    try writer.writeInt(u64, record.ingested_at_ns, .little);
    try writer.writeInt(u64, value.event_time_ns, .little);
    try writer.writeInt(u64, value.block_number orelse 0, .little);
    const present: Present = .{
        .network = value.network != null,
        .tx_hash = value.tx_hash != null,
        .block_hash = value.block_hash != null,
        .block_number = value.block_number != null,
        .payload_id = value.payload_id != null,
        .request_id = value.request_id != null,
        .bundle_id = value.bundle_id != null,
        .bundle_hash = value.bundle_hash != null,
    };
    try writer.writeByte(@bitCast(present));
    try writer.writeAll(&(value.tx_hash orelse @as([32]u8, @splat(0))));
    try writer.writeAll(&(value.block_hash orelse @as([32]u8, @splat(0))));
    for ([_][]const u8{ value.producer.wire_name(), value.event_type.wire_name() }) |name| {
        assert(name.len <= name_size_max);
        try writer.writeByte(@intCast(name.len));
        try writer.writeAll(name);
    }
    const texts = [text_count]?[]const u8{
        value.event_id, value.network,   value.payload_id,  value.request_id,
        value.data,     value.bundle_id, value.bundle_hash,
    };
    for (texts) |maybe_text| {
        const text = maybe_text orelse "";
        try writer.writeInt(u32, @intCast(text.len), .little);
        try writer.writeAll(text);
    }
}

pub const Decoded = union(enum) {
    /// A record and its encoded size. Slices point into the input.
    record: struct { record: Record, size: u32 },
    /// The input ends inside a record (or is empty): read more, or the tail is torn.
    incomplete,
    /// Not a valid record: bad magic, size, checksum, or contents.
    corrupt,
};

/// Decodes the record at the start of `bytes`; `payload_max` bounds the payload size.
pub fn decode(bytes: []const u8, payload_max: u32) Decoded {
    assert(payload_max >= fixed_payload_size);
    if (bytes.len < header_size) {
        const prefix = @min(bytes.len, magic.len);
        if (!std.mem.eql(u8, bytes[0..prefix], magic[0..prefix])) return .corrupt;
        return .incomplete;
    }
    if (!std.mem.eql(u8, bytes[0..4], magic)) return .corrupt;
    const payload_size = std.mem.readInt(u32, bytes[4..8], .little);
    if (payload_size < fixed_payload_size or payload_size > payload_max) return .corrupt;
    if (bytes.len - header_size < payload_size) return .incomplete;
    const payload = bytes[header_size..][0..payload_size];
    const checksum = std.mem.readInt(u32, bytes[8..12], .little);
    if (std.hash.Crc32.hash(payload) != checksum) return .corrupt;
    const record = decode_payload(payload) orelse return .corrupt;
    assert(record.event.event_id.len > 0);
    return .{ .record = .{ .record = record, .size = header_size + payload_size } };
}

const Cursor = struct {
    bytes: []const u8,
    index: usize = 0,

    fn take(cursor: *Cursor, size: usize) ?[]const u8 {
        if (cursor.bytes.len - cursor.index < size) return null;
        defer cursor.index += size;
        return cursor.bytes[cursor.index..][0..size];
    }

    fn int(cursor: *Cursor, comptime T: type) ?T {
        const bytes = cursor.take(@sizeOf(T)) orelse return null;
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }

    fn name(cursor: *Cursor) ?[]const u8 {
        const size = cursor.int(u8) orelse return null;
        return cursor.take(size);
    }

    fn text(cursor: *Cursor) ?[]const u8 {
        const size = cursor.int(u32) orelse return null;
        return cursor.take(size);
    }
};

fn decode_payload(payload: []const u8) ?Record {
    var cursor: Cursor = .{ .bytes = payload };
    const ingested_at_ns = cursor.int(u64).?; // `decode` checked the fixed size.
    const event_time_ns = cursor.int(u64).?;
    const block_number = cursor.int(u64).?;
    const present: Present = @bitCast(cursor.int(u8).?);
    const tx_hash = cursor.take(32).?[0..32].*;
    const block_hash = cursor.take(32).?[0..32].*;
    const producer = producer_of(cursor.name() orelse return null) orelse return null;
    const event_type = event_module.EventType.from_wire(cursor.name() orelse return null) orelse
        return null;
    var texts: [text_count][]const u8 = undefined;
    for (&texts) |*text| text.* = cursor.text() orelse return null;
    if (cursor.index != payload.len) return null;
    if (!canonical(present, texts, tx_hash, block_hash, block_number)) return null;
    const event_id = texts[0];
    if (event_id.len == 0 or event_id.len > event_module.event_id_size_max) return null;
    if (texts[4].len == 0 or texts[4][0] != '{') return null;
    if (present.block_number and block_number > std.math.maxInt(i64)) return null;
    return .{ .ingested_at_ns = ingested_at_ns, .event = .{
        .event_id = event_id,
        .event_time_ns = event_time_ns,
        .producer = producer,
        .event_type = event_type,
        .network = if (present.network) texts[1] else null,
        .tx_hash = if (present.tx_hash) tx_hash else null,
        .block_hash = if (present.block_hash) block_hash else null,
        .block_number = if (present.block_number) block_number else null,
        .payload_id = if (present.payload_id) texts[2] else null,
        .request_id = if (present.request_id) texts[3] else null,
        .data = texts[4],
        .bundle_id = if (present.bundle_id) bounded(texts[5]) orelse return null else null,
        .bundle_hash = if (present.bundle_hash) bounded(texts[6]) orelse return null else null,
    } };
}

/// Absent fields are encoded as zeros or empty texts, so each record has one encoding.
fn canonical(
    present: Present,
    texts: [text_count][]const u8,
    tx_hash: [32]u8,
    block_hash: [32]u8,
    block_number: u64,
) bool {
    const zero: [32]u8 = @splat(0);
    if (!present.tx_hash and !std.mem.eql(u8, &tx_hash, &zero)) return false;
    if (!present.block_hash and !std.mem.eql(u8, &block_hash, &zero)) return false;
    if (!present.block_number and block_number != 0) return false;
    const optional = [_]struct { bool, []const u8 }{
        .{ present.network, texts[1] },     .{ present.payload_id, texts[2] },
        .{ present.request_id, texts[3] },  .{ present.bundle_id, texts[5] },
        .{ present.bundle_hash, texts[6] },
    };
    for (optional) |entry| if (!entry[0] and entry[1].len != 0) return false;
    return true;
}

fn bounded(bundle_key: []const u8) ?[]const u8 {
    return if (bundle_key.len <= event_module.bundle_key_size_max) bundle_key else null;
}

fn producer_of(name: []const u8) ?event_module.Producer {
    for (std.enums.values(event_module.Producer)) |producer| {
        if (std.mem.eql(u8, producer.wire_name(), name)) return producer;
    }
    return null;
}

pub const ReplayStop = enum {
    /// Every byte was consumed or the rest is an incomplete record (read more).
    incomplete,
    /// A corrupt record starts at `consumed`: truncate there.
    corrupt,
};

pub const ReplayResult = struct {
    consumed: u64 = 0,
    stop: ReplayStop = .incomplete,
    inserted: u32 = 0,
    duplicates: u32 = 0,
    oversized: u32 = 0,
    expired: u32 = 0,
};

/// Replays complete records from `bytes` into `store`, skipping event ids it already holds,
/// records too large for its arena, and records expired at `now_ns` (0: none expire). The
/// caller slides its window by `consumed` and calls again with more bytes; at end of file a
/// leftover `incomplete` tail is torn.
pub fn replay(
    store: *store_module.Store,
    bytes: []const u8,
    payload_max: u32,
    now_ns: u64,
) ReplayResult {
    var result: ReplayResult = .{};
    var records: u64 = 0;
    while (records < bytes.len) : (records += 1) {
        const rest = bytes[result.consumed..];
        switch (decode(rest, payload_max)) {
            .incomplete => break,
            .corrupt => {
                result.stop = .corrupt;
                break;
            },
            .record => |decoded| {
                result.consumed += decoded.size;
                const record = &decoded.record;
                if (store_module.Store.record_size(record) > store.arena.len) {
                    result.oversized += 1;
                } else if (store.expired_at(record.event, now_ns)) {
                    result.expired += 1;
                } else if (store.find_event_id(record.event.event_id) != null) {
                    result.duplicates += 1;
                } else {
                    _ = store.insert(record);
                    result.inserted += 1;
                }
            },
        }
    }
    assert(result.consumed <= bytes.len);
    return result;
}

/// Encodes live (unexpired at `now_ns`) store events from logical position `position.*`
/// into `out` while whole records fit, advancing `position`; used to compact a segment.
/// `out` must hold at least one record of the largest stored size.
pub fn encode_live(
    store: *const store_module.Store,
    position: *u32,
    out: []u8,
    now_ns: u64,
) []const u8 {
    var size: usize = 0;
    while (position.* < store.count) : (position.* += 1) {
        const record = store.get(store.slot_at(position.*));
        if (store.expired_at(record.event, now_ns)) continue;
        const texts: u32 = @intCast(store_module.Store.record_size(&record));
        if (out.len - size < header_size + payload_size_max(texts)) break;
        size += encode(&record, out[size..]).len;
    }
    assert(size <= out.len);
    assert(position.* <= store.count);
    return out[0..size];
}

test {
    _ = @import("segment_test.zig");
}

//! Bounded store of discovered node records, persisted between runs to speed up
//! bootstrap (base/base `peers/src/store.rs` `BootStore`). Oldest records are evicted
//! first once `capacity` is reached. The on-disk form is the same JSON array of `enr:`
//! strings base/base writes; library code serializes to and from bytes and never opens
//! files itself.

const std = @import("std");
const assert = std.debug.assert;
const enr = @import("enr.zig");

/// base/base `MAX_PEERS`.
pub const capacity_default = 2048;

pub const Store = struct {
    records: []enr.Record,
    head: u32 = 0,
    count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: u32) !Store {
        assert(capacity > 0);
        return .{ .records = try allocator.alloc(enr.Record, capacity) };
    }

    pub fn deinit(store: *Store, allocator: std.mem.Allocator) void {
        allocator.free(store.records);
        store.* = undefined;
    }

    fn slots(store: *const Store) u32 {
        return @intCast(store.records.len);
    }

    pub fn at(store: *const Store, index: u32) *const enr.Record {
        assert(index < store.count);
        return &store.records[(store.head + index) % store.slots()];
    }

    fn contains(store: *const Store, record: *const enr.Record) bool {
        var index: u32 = 0;
        while (index < store.count) : (index += 1) {
            if (std.mem.eql(u8, store.at(index).raw(), record.raw())) return true;
        }
        return false;
    }

    /// Adds a record unless an identical one is stored; evicts the oldest when full.
    pub fn add(store: *Store, record: *const enr.Record) void {
        if (store.contains(record)) return;
        if (store.count == store.slots()) {
            store.head = (store.head + 1) % store.slots();
            store.count -= 1;
        }
        store.records[(store.head + store.count) % store.slots()] = record.*;
        store.count += 1;
        assert(store.count <= store.slots());
    }

    /// Writes the indices of records valid for `chain_id` into `output`.
    pub fn valid_for_chain(store: *const Store, chain_id: u64, output: []u32) []u32 {
        var found: usize = 0;
        var index: u32 = 0;
        while (index < store.count and found < output.len) : (index += 1) {
            if (enr.validate_chain(store.at(index), chain_id) != .valid) continue;
            output[found] = index;
            found += 1;
        }
        assert(found <= output.len);
        return output[0..found];
    }

    /// Bytes `serialize` needs at most.
    pub fn serialized_length_max(store: *const Store) usize {
        return 2 + store.count * (enr.text_length_max + 3);
    }

    /// `["enr:...","enr:..."]`, oldest first.
    pub fn serialize(store: *const Store, output: []u8) []const u8 {
        assert(output.len >= store.serialized_length_max());
        var writer = std.Io.Writer.fixed(output);
        // The length bound above covers every byte written below.
        writer.writeByte('[') catch unreachable;
        var index: u32 = 0;
        var text: [enr.text_length_max]u8 = undefined;
        while (index < store.count) : (index += 1) {
            if (index > 0) writer.writeByte(',') catch unreachable;
            writer.print("\"{s}\"", .{enr.encode_text(&text, store.at(index))}) catch unreachable;
        }
        writer.writeByte(']') catch unreachable;
        return writer.buffered();
    }

    /// Loads records from `serialize` output. Like base/base, entries that fail to decode
    /// are skipped; structurally invalid JSON yields `error.InvalidFormat` and leaves the
    /// store unchanged up to the failure point.
    pub fn load(store: *Store, bytes: []const u8) error{InvalidFormat}!u32 {
        var position = skip_space(bytes, 0);
        if (position >= bytes.len or bytes[position] != '[') return error.InvalidFormat;
        position = skip_space(bytes, position + 1);
        var loaded: u32 = 0;
        var first = true;
        while (position < bytes.len and bytes[position] != ']') {
            if (!first) {
                if (bytes[position] != ',') return error.InvalidFormat;
                position = skip_space(bytes, position + 1);
            }
            first = false;
            if (position >= bytes.len or bytes[position] != '"') return error.InvalidFormat;
            const end = std.mem.indexOfScalarPos(u8, bytes, position + 1, '"') orelse
                return error.InvalidFormat;
            if (enr.decode_text(bytes[position + 1 .. end])) |record| {
                store.add(&record);
                loaded += 1;
            } else |_| {}
            position = skip_space(bytes, end + 1);
        }
        if (position >= bytes.len) return error.InvalidFormat;
        assert(bytes[position] == ']');
        return loaded;
    }
};

fn skip_space(bytes: []const u8, start: usize) usize {
    var position = start;
    while (position < bytes.len and std.ascii.isWhitespace(bytes[position])) position += 1;
    return position;
}

const boot = @import("boot.zig");
const fuzz = @import("../../../testing/fuzz.zig");

test "store: dedup, eviction, chain filter" {
    var store = try Store.init(std.testing.allocator, 4);
    defer store.deinit(std.testing.allocator);
    var records: [8]enr.Record = undefined;
    for (boot.mainnet, 0..) |text, index| records[index] = try enr.decode_text(text);
    for (boot.sepolia, 0..) |text, index| records[5 + index] = try enr.decode_text(text);
    records[7] = try enr.decode_text(boot.zeronet[0]);
    for (&records) |*record| {
        store.add(record);
        store.add(record);
    }
    try std.testing.expectEqual(@as(u32, 4), store.count);
    try std.testing.expectEqualSlices(u8, records[4].raw(), store.at(0).raw());
    var indices: [8]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 2), store.valid_for_chain(84532, &indices).len);
    try std.testing.expectEqual(@as(usize, 1), store.valid_for_chain(8453, &indices).len);
}

test "store: serialize and load round trip, skipping bad entries" {
    var store = try Store.init(std.testing.allocator, 8);
    defer store.deinit(std.testing.allocator);
    for (boot.mainnet) |text| store.add(&(try enr.decode_text(text)));
    var buffer: [8 * (enr.text_length_max + 3) + 2]u8 = undefined;
    const json = store.serialize(&buffer);
    var loaded = try Store.init(std.testing.allocator, 8);
    defer loaded.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 5), try loaded.load(json));
    try std.testing.expectEqualSlices(u8, store.at(4).raw(), loaded.at(4).raw());
    var empty = try Store.init(std.testing.allocator, 2);
    defer empty.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 0), try empty.load(" [ \"enr:bad\" , \"x\" ] "));
    try std.testing.expectEqual(@as(u32, 0), try empty.load("[]"));
    try std.testing.expectError(error.InvalidFormat, empty.load("[\"enr:abc\""));
    try std.testing.expectError(error.InvalidFormat, empty.load("{}"));
}

fn fuzz_load(_: void, input: []const u8) anyerror!void {
    var store = try Store.init(std.testing.allocator, 4);
    defer store.deinit(std.testing.allocator);
    _ = store.load(input) catch return;
    try std.testing.expect(store.count <= 4);
}

test "store: fuzz load" {
    try fuzz.run_bytes({}, fuzz_load, .{ .input_size_max = 512, .corpus = &.{"[\"enr:\"]"} });
}

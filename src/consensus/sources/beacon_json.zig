//! Decoders for the beacon API responses the blob provider uses:
//! `/eth/v1/beacon/genesis`, `/eth/v1/config/spec`, `/eth/v1/beacon/blobs/{slot}` (what
//! base/base uses), and `/eth/v1/beacon/blob_sidecars/{slot}`.
//! Mirrors base/base `crates/consensus/providers/src/beacon_client.rs`.
//!
//! Beacon API integers are decimal strings; QUANTITY strings are accepted as well, as
//! alloy's `quantity` deserializer does.

const std = @import("std");
const assert = std.debug.assert;

const object = @import("json_object.zig");
const blob_module = @import("../derive/blob.zig");

pub const Blob = blob_module.Blob;
pub const Commitment = [48]u8;
pub const Proof = [48]u8;
pub const Error = object.Error;

/// The `data` member of a beacon API response object.
pub fn data_raw(raw: []const u8) Error![]const u8 {
    var iterator = try object.ObjectIterator.init(raw);
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "data")) return field.raw;
    }
    return error.MissingField;
}

/// A named integer field of the `data` object.
fn data_integer(raw: []const u8, name: []const u8) Error!u64 {
    var iterator = try object.ObjectIterator.init(try data_raw(raw));
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, name)) return object.decimal_or_quantity(field.value);
    }
    return error.MissingField;
}

pub fn decode_genesis_time(raw: []const u8) Error!u64 {
    return data_integer(raw, "genesis_time");
}

pub fn decode_seconds_per_slot(raw: []const u8) Error!u64 {
    const seconds = try data_integer(raw, "SECONDS_PER_SLOT");
    if (seconds == 0) return error.InvalidField;
    return seconds;
}

/// Number of entries of the `data` array, at most `count_max`.
pub fn data_count(raw: []const u8, count_max: u32) Error!u32 {
    return object.array_count(try data_raw(raw), count_max);
}

/// `GetBlobsResponse`: `data` is an array of blob DATA strings. Decodes into `out`, which
/// must hold `data_count` blobs.
pub fn decode_blobs(raw: []const u8, out: []Blob) Error!void {
    var iterator = try object.ArrayIterator.init(try data_raw(raw));
    for (out) |*blob| {
        const element = (try iterator.next()) orelse return error.InvalidJson;
        try object.data_into(element.value, blob);
    }
    if (try iterator.next() != null) return error.TooLarge;
}

pub const Sidecar = struct { commitment: Commitment, proof: Proof };

/// `blob_sidecars`: `data` is an array of objects with `blob`, `kzg_commitment`, and
/// `kzg_proof`. Decodes into `blobs` and `sidecars`, which must hold `data_count` items.
pub fn decode_sidecars(raw: []const u8, blobs: []Blob, sidecars: []Sidecar) Error!void {
    assert(blobs.len == sidecars.len);
    var iterator = try object.ArrayIterator.init(try data_raw(raw));
    for (blobs, sidecars) |*blob, *sidecar| {
        const element = (try iterator.next()) orelse return error.InvalidJson;
        sidecar.* = try decode_sidecar(element.raw, blob);
    }
    if (try iterator.next() != null) return error.TooLarge;
}

fn decode_sidecar(raw: []const u8, blob: *Blob) Error!Sidecar {
    var iterator = try object.ObjectIterator.init(raw);
    var seen: object.Seen(3) = .{};
    var sidecar: Sidecar = undefined;
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "blob")) {
            try seen.see(0);
            try object.data_into(field.value, blob);
        } else if (std.mem.eql(u8, field.key, "kzg_commitment")) {
            try seen.see(1);
            sidecar.commitment = try object.fixed(48, field.value);
        } else if (std.mem.eql(u8, field.key, "kzg_proof")) {
            try seen.see(2);
            sidecar.proof = try object.fixed(48, field.value);
        }
    }
    try seen.require(0b111);
    return sidecar;
}

const testing = std.testing;

test "beacon json: genesis and spec" {
    try testing.expectEqual(@as(u64, 1606824023), try decode_genesis_time(
        \\{"data":{"genesis_time":"1606824023","genesis_fork_version":"0x00000000"}}
    ));
    try testing.expectEqual(@as(u64, 12), try decode_seconds_per_slot(
        \\{"data":{"CONFIG_NAME":"mainnet","SECONDS_PER_SLOT":"12"}}
    ));
    try testing.expectEqual(@as(u64, 2), try decode_seconds_per_slot(
        \\{"data":{"SECONDS_PER_SLOT":"0x2"}}
    ));
    try testing.expectError(error.InvalidField, decode_seconds_per_slot(
        \\{"data":{"SECONDS_PER_SLOT":"0"}}
    ));
    try testing.expectError(error.MissingField, decode_genesis_time("{\"data\":{}}"));
    try testing.expectError(error.MissingField, decode_genesis_time("{}"));
    try testing.expectError(error.InvalidField, decode_genesis_time(
        \\{"data":{"genesis_time":"-1"}}
    ));
}

test "beacon json: blobs and sidecars" {
    const allocator = testing.allocator;
    const hex = try allocator.alloc(u8, 2 + 2 * blob_module.bytes_per_blob);
    defer allocator.free(hex);
    hex[0] = '0';
    hex[1] = 'x';
    @memset(hex[2..], '0');
    hex[2] = '7';
    const blobs_text = try std.fmt.allocPrint(allocator, "{{\"data\":[\"{s}\"]}}", .{hex});
    defer allocator.free(blobs_text);
    try testing.expectEqual(@as(u32, 1), try data_count(blobs_text, 4));
    const blobs = try allocator.alloc(Blob, 1);
    defer allocator.free(blobs);
    try decode_blobs(blobs_text, blobs);
    try testing.expectEqual(@as(u8, 0x70), blobs[0][0]);
    const sidecar_text = try std.fmt.allocPrint(
        allocator,
        "{{\"data\":[{{\"index\":\"0\",\"blob\":\"{s}\",\"kzg_commitment\":\"0x{x}\"," ++
            "\"kzg_proof\":\"0x{x}\"}}]}}",
        .{ hex, &@as([48]u8, @splat(0xc0)), &@as([48]u8, @splat(0xaa)) },
    );
    defer allocator.free(sidecar_text);
    var sidecars: [1]Sidecar = undefined;
    try decode_sidecars(sidecar_text, blobs, &sidecars);
    try testing.expectEqual(@as(u8, 0xc0), sidecars[0].commitment[47]);
    try testing.expectEqual(@as(u8, 0xaa), sidecars[0].proof[0]);
    try testing.expectError(error.InvalidField, decode_blobs("{\"data\":[\"0x00\"]}", blobs));
}

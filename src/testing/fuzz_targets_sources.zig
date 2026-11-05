//! Fuzz targets for the consensus sources' beacon API decoders
//! (`consensus/sources/beacon_json.zig`), which parse responses from an untrusted beacon
//! node: genesis time, seconds per slot, blobs, and blob sidecars.
//!
//! Properties:
//!   - integers: a generated response (decimal or QUANTITY value, unrelated fields and
//!     whitespace around it) decodes to exactly the generated value; decimal text with a
//!     leading zero or past u64 is rejected; zero seconds per slot is rejected;
//!   - blobs and sidecars: generated responses (fields in any order, extra fields)
//!     decode to exactly the generated blobs, commitments, and proofs; `data_count`
//!     agrees; an extra element or a missing sidecar field is an error;
//!   - arbitrary bytes: no decoder crashes, and a successful `data_count` stays in bounds.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const beacon_json = @import("../consensus/sources/beacon_json.zig");

const Blob = beacon_json.Blob;
const Sidecar = beacon_json.Sidecar;
const blob_bytes = @sizeOf(Blob);
const blobs_max = 2;
/// A response with `blobs_max + 1` hex blobs plus framing.
const text_bytes_max = (blobs_max + 1) * (2 * blob_bytes + 512) + 1024;

/// Unrelated fields the decoders must skip, as beacon nodes send them.
const noise_fields = [_][]const u8{
    "\"genesis_fork_version\":\"0x00000000\"",
    "\"CONFIG_NAME\":\"mainnet\"",
    "\"index\":\"3\"",
    "\"nested\":{\"a\":[1,2,{\"b\":null}],\"c\":\"}\"}",
    "\"list\":[\"x\",true,false,-1.5e3]",
};

const Text = struct {
    bytes: []u8,
    length: usize = 0,

    fn append(text: *Text, part: []const u8) void {
        assert(text.length + part.len <= text.bytes.len);
        @memcpy(text.bytes[text.length..][0..part.len], part);
        text.length += part.len;
    }

    fn print(text: *Text, comptime format: []const u8, arguments: anytype) void {
        const written = std.fmt.bufPrint(text.bytes[text.length..], format, arguments) catch
            unreachable; // Proof: text_bytes_max covers every generated response.
        text.length += written.len;
    }

    fn whitespace(text: *Text, prng: *Prng) void {
        const spaces = [_][]const u8{ "", "", " ", "\n", "\t ", "\r\n  " };
        text.append(spaces[@intCast(prng.below(spaces.len))]);
    }

    fn noise(text: *Text, prng: *Prng) void {
        text.append(noise_fields[@intCast(prng.below(noise_fields.len))]);
        text.append(",");
        text.whitespace(prng);
    }

    fn hex(text: *Text, bytes: []const u8) void {
        text.append("\"0x");
        const digits = "0123456789abcdef";
        assert(text.length + 2 * bytes.len + 1 <= text.bytes.len);
        for (bytes) |byte| {
            text.bytes[text.length] = digits[byte >> 4];
            text.bytes[text.length + 1] = digits[byte & 0xf];
            text.length += 2;
        }
        text.append("\"");
    }

    fn slice(text: *const Text) []const u8 {
        return text.bytes[0..text.length];
    }
};

fn value_u64(prng: *Prng) u64 {
    return switch (prng.below(4)) {
        0 => prng.below(16),
        1 => std.math.maxInt(u64),
        2 => prng.below(1 << 32),
        else => prng.int(u64),
    };
}

/// `{"data":{<noise>,"<name>":"<value text>",<noise>}}`.
fn integer_response(text: *Text, prng: *Prng, name: []const u8, value_text: []const u8) void {
    text.length = 0;
    text.append("{");
    text.whitespace(prng);
    if (prng.chance(1, 3)) text.append("\"execution_optimistic\":false,");
    text.append("\"data\":{");
    for (0..prng.below(3)) |_| text.noise(prng);
    text.print("\"{s}\":", .{name});
    text.whitespace(prng);
    text.print("\"{s}\"", .{value_text});
    for (0..prng.below(3)) |_| {
        text.append(",");
        text.append(noise_fields[@intCast(prng.below(noise_fields.len))]);
    }
    text.append("}");
    text.whitespace(prng);
    text.append("}");
}

fn fuzz_integers(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var buffer: [1024]u8 = undefined;
    var text: Text = .{ .bytes = &buffer };
    var value_buffer: [32]u8 = undefined;
    for (0..16) |_| {
        const value = value_u64(&prng);
        const quantity = prng.chance(1, 2);
        const value_text = if (quantity)
            std.fmt.bufPrint(&value_buffer, "0x{x}", .{value}) catch unreachable
        else
            std.fmt.bufPrint(&value_buffer, "{d}", .{value}) catch unreachable;
        const genesis = prng.chance(1, 2);
        const name = if (genesis) "genesis_time" else "SECONDS_PER_SLOT";
        integer_response(&text, &prng, name, value_text);
        const decoded = if (genesis)
            beacon_json.decode_genesis_time(text.slice())
        else
            beacon_json.decode_seconds_per_slot(text.slice());
        if (!genesis and value == 0) {
            try std.testing.expectError(error.InvalidField, decoded);
        } else {
            try std.testing.expectEqual(value, try decoded);
        }
        // Decimal with a leading zero, or one past u64: rejected.
        const invalid_text = if (prng.chance(1, 2))
            std.fmt.bufPrint(&value_buffer, "0{d}", .{value}) catch unreachable
        else
            "18446744073709551616";
        integer_response(&text, &prng, "genesis_time", invalid_text);
        try std.testing.expectError(error.InvalidField, beacon_json.decode_genesis_time(
            text.slice(),
        ));
    }
}

/// Sparse random blobs: mostly zero, like real blobs, with random bytes sprinkled in.
fn fill_blob(prng: *Prng, blob: *Blob) void {
    @memset(blob, 0);
    for (0..prng.below(64)) |_| blob[@intCast(prng.below(blob_bytes))] = prng.int(u8);
}

/// One sidecar object; `skip` omits one required field (0..2) when set.
fn sidecar_object(
    text: *Text,
    prng: *Prng,
    blob: *const Blob,
    sidecar: *const Sidecar,
    skip: ?u8,
) void {
    var order: [3]u8 = .{ 0, 1, 2 };
    var index: usize = order.len;
    while (index > 1) : (index -= 1) {
        std.mem.swap(u8, &order[index - 1], &order[@intCast(prng.below(index))]);
    }
    text.append("{");
    if (prng.chance(1, 2)) text.append("\"index\":\"0\",");
    var first = true;
    for (order) |field| {
        if (skip == field) continue;
        if (!first) text.append(",");
        first = false;
        switch (field) {
            0 => text.append("\"blob\":"),
            1 => text.append("\"kzg_commitment\":"),
            else => text.append("\"kzg_proof\":"),
        }
        text.hex(switch (field) {
            0 => blob,
            1 => &sidecar.commitment,
            else => &sidecar.proof,
        });
    }
    text.append("}");
}

const BlobCase = struct {
    blobs: []Blob,
    decoded: []Blob,
    sidecars: [blobs_max + 1]Sidecar = undefined,
    count: u32 = 0,
};

fn blobs_response(text: *Text, prng: *Prng, case: *BlobCase, sidecars: bool, skip: ?u8) void {
    text.length = 0;
    text.append("{\"data\":[");
    for (case.blobs[0..case.count], case.sidecars[0..case.count], 0..) |*blob, *sidecar, i| {
        if (i > 0) text.append(",");
        text.whitespace(prng);
        if (sidecars) {
            sidecar_object(text, prng, blob, sidecar, if (i + 1 == case.count) skip else null);
        } else {
            text.hex(blob);
        }
    }
    text.append("]");
    if (prng.chance(1, 2)) text.append(",\"execution_optimistic\":false");
    text.append("}");
}

fn fuzz_blobs(case: *BlobCase, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var text: Text = .{ .bytes = &text_storage };
    case.count = @intCast(prng.below(blobs_max + 1));
    for (case.blobs[0..case.count], case.sidecars[0..case.count]) |*blob, *sidecar| {
        fill_blob(&prng, blob);
        prng.fill(&sidecar.commitment);
        prng.fill(&sidecar.proof);
    }
    const sidecars = prng.chance(1, 2);
    blobs_response(&text, &prng, case, sidecars, null);
    try std.testing.expectEqual(case.count, try beacon_json.data_count(text.slice(), 8));
    const out = case.decoded[0..case.count];
    if (sidecars) {
        var decoded_sidecars: [blobs_max + 1]Sidecar = undefined;
        try beacon_json.decode_sidecars(text.slice(), out, decoded_sidecars[0..case.count]);
        for (case.sidecars[0..case.count], decoded_sidecars[0..case.count]) |a, b| {
            try std.testing.expectEqualSlices(u8, &a.commitment, &b.commitment);
            try std.testing.expectEqualSlices(u8, &a.proof, &b.proof);
        }
    } else {
        try beacon_json.decode_blobs(text.slice(), out);
    }
    for (case.blobs[0..case.count], out) |*expected, *actual| {
        try std.testing.expect(std.mem.eql(u8, expected, actual));
    }
    if (case.count == 0) return;
    // One element too many for the output: rejected.
    const fewer = case.decoded[0 .. case.count - 1];
    if (sidecars) {
        var decoded_sidecars: [blobs_max]Sidecar = undefined;
        const fewer_sidecars = decoded_sidecars[0..fewer.len];
        const result = beacon_json.decode_sidecars(text.slice(), fewer, fewer_sidecars);
        try std.testing.expectError(error.TooLarge, result);
        // A sidecar missing a required field: rejected.
        blobs_response(&text, &prng, case, true, @intCast(prng.below(3)));
        var all: [blobs_max + 1]Sidecar = undefined;
        const missing = beacon_json.decode_sidecars(text.slice(), out, all[0..case.count]);
        try std.testing.expect(std.meta.isError(missing));
    } else {
        try std.testing.expectError(error.TooLarge, beacon_json.decode_blobs(text.slice(), fewer));
    }
}

/// Response text for the blob target (too large for the stack).
var text_storage: [text_bytes_max]u8 = undefined;

fn fuzz_arbitrary(case: *BlobCase, smith: *Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const length = smith.slice(&input);
    const raw = input[0..length];
    _ = beacon_json.decode_genesis_time(raw) catch {};
    _ = beacon_json.decode_seconds_per_slot(raw) catch {};
    if (beacon_json.data_count(raw, blobs_max)) |count| {
        try std.testing.expect(count <= blobs_max);
        var sidecars: [blobs_max]Sidecar = undefined;
        beacon_json.decode_blobs(raw, case.decoded[0..count]) catch {};
        beacon_json.decode_sidecars(raw, case.decoded[0..count], sidecars[0..count]) catch {};
    } else |_| {}
}

fn blob_case(allocator: std.mem.Allocator) !BlobCase {
    const blobs = try allocator.alloc(Blob, blobs_max + 1);
    errdefer allocator.free(blobs);
    return .{ .blobs = blobs, .decoded = try allocator.alloc(Blob, blobs_max + 1) };
}

test "fuzz_targets_sources: beacon integers decode exactly, malformed ones fail" {
    try fuzz.run({}, fuzz_integers, .{ .iterations = 256 });
}

test "fuzz_targets_sources: beacon blobs and sidecars decode exactly" {
    var case = try blob_case(std.testing.allocator);
    defer std.testing.allocator.free(case.blobs);
    defer std.testing.allocator.free(case.decoded);
    try fuzz.run(&case, fuzz_blobs, .{ .iterations = 48 });
}

test "fuzz_targets_sources: beacon decoders survive arbitrary bytes" {
    var case = try blob_case(std.testing.allocator);
    defer std.testing.allocator.free(case.blobs);
    defer std.testing.allocator.free(case.decoded);
    try fuzz.run(&case, fuzz_arbitrary, .{ .iterations = 1024 });
}

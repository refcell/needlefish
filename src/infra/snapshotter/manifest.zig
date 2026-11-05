//! Snapshot manifests (base/base `snapshotter` + `reth-cli/snapshot_manifest.rs`, adapted to
//! needlefish's single-file `node.db`).
//!
//! A snapshot is the node database split into fixed-size chunks. Chunks are stored
//! content-addressed (`chunks/<blake3 hex>`), so a chunk unchanged since an earlier snapshot
//! is reused without re-uploading (base/base reuses static-file archives whose hashes match
//! the previous manifest; content addressing gives the same reuse without the comparison).
//! The manifest is a small line-based text file:
//!
//!   needlefish-snapshot 1
//!   chain_id 900
//!   block 123 0x<32-byte hash>
//!   file node.db 25165824
//!   chunk_bytes 8388608
//!   chunk <size> <blake3 hex>      (one line per chunk, in file order)
//!   end
//!
//! Decoding validates every field and that the chunk sizes add up to the file size, so a
//! truncated or edited manifest never restores silently.

const std = @import("std");
const assert = std.debug.assert;
const Blake3 = std.crypto.hash.Blake3;

pub const format_version: u32 = 1;
pub const chunks_max = 64 * 1024;
pub const chunk_bytes_min: u32 = 4096;
pub const chunk_bytes_max: u32 = 256 * 1024 * 1024;
pub const file_name_max = 64;
const line_bytes_max = 160;

pub const Hash = [32]u8;

pub const Chunk = struct {
    size: u32,
    hash: Hash,
};

pub fn chunk_hash(bytes: []const u8) Hash {
    assert(bytes.len > 0);
    var hash: Hash = undefined;
    Blake3.hash(bytes, &hash, .{});
    return hash;
}

/// `chunks/<64 hex>`.
pub fn chunk_path(hash: Hash, out: *[7 + 64]u8) []const u8 {
    const text = std.fmt.bufPrint(out, "chunks/{x}", .{&hash}) catch unreachable; // Fixed size.
    assert(text.len == out.len);
    return text;
}

pub const Header = struct {
    chain_id: u64,
    block_number: u64,
    block_hash: Hash,
    file_name: []const u8,
    file_bytes: u64,
    chunk_bytes: u32,

    pub fn chunk_count(header: Header) u64 {
        assert(header.chunk_bytes > 0);
        return std.math.divCeil(u64, header.file_bytes, header.chunk_bytes) catch unreachable;
    }

    /// Size of chunk `index`: full chunks, then the remainder.
    pub fn chunk_size(header: Header, index: u64) u32 {
        assert(index < header.chunk_count());
        const start = index * header.chunk_bytes;
        return @intCast(@min(header.chunk_bytes, header.file_bytes - start));
    }

    fn valid_name(name: []const u8) bool {
        if (name.len == 0 or name.len > file_name_max) return false;
        for (name) |byte| switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        };
        return !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..");
    }

    pub fn valid(header: Header) bool {
        if (!valid_name(header.file_name)) return false;
        if (header.chunk_bytes < chunk_bytes_min or header.chunk_bytes > chunk_bytes_max) {
            return false;
        }
        if (header.file_bytes == 0) return false;
        return header.chunk_count() <= chunks_max;
    }
};

pub fn write(header: Header, chunks: []const Chunk, out: *std.Io.Writer) std.Io.Writer.Error!void {
    assert(header.valid());
    assert(chunks.len == header.chunk_count());
    try out.print("needlefish-snapshot {d}\nchain_id {d}\n", .{ format_version, header.chain_id });
    try out.print("block {d} 0x{x}\n", .{ header.block_number, &header.block_hash });
    try out.print("file {s} {d}\nchunk_bytes {d}\n", .{
        header.file_name, header.file_bytes, header.chunk_bytes,
    });
    for (chunks, 0..) |chunk, index| {
        assert(chunk.size == header.chunk_size(index));
        try out.print("chunk {d} {x}\n", .{ chunk.size, &chunk.hash });
    }
    try out.writeAll("end\n");
}

pub const DecodeError = error{InvalidManifest};

/// A decoded manifest; `header.file_name` borrows the input text.
pub const Decoded = struct {
    header: Header,
    chunk_count: u32,
};

/// Decodes `text` into `header` and `chunks_out` (at least `chunks_max` entries or the
/// manifest's chunk count).
pub fn decode(text: []const u8, chunks_out: []Chunk) DecodeError!Decoded {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var header: Header = undefined;
    try expect_line(&lines, "needlefish-snapshot", &.{"1"});
    var fields: [2][]const u8 = undefined;
    try fields_of(&lines, "chain_id", fields[0..1]);
    header.chain_id = try number(u64, fields[0]);
    try fields_of(&lines, "block", fields[0..2]);
    header.block_number = try number(u64, fields[0]);
    header.block_hash = try hex32(fields[1], "0x");
    try fields_of(&lines, "file", fields[0..2]);
    header.file_name = fields[0];
    header.file_bytes = try number(u64, fields[1]);
    try fields_of(&lines, "chunk_bytes", fields[0..1]);
    header.chunk_bytes = try number(u32, fields[0]);
    if (!header.valid()) return error.InvalidManifest;
    const count = header.chunk_count();
    if (count > chunks_out.len) return error.InvalidManifest;
    for (chunks_out[0..@intCast(count)], 0..) |*chunk, index| {
        try fields_of(&lines, "chunk", fields[0..2]);
        chunk.size = try number(u32, fields[0]);
        if (chunk.size != header.chunk_size(index)) return error.InvalidManifest;
        chunk.hash = try hex32(fields[1], "");
    }
    try expect_line(&lines, "end", &.{});
    const rest = lines.rest();
    if (rest.len != 0) return error.InvalidManifest;
    return .{ .header = header, .chunk_count = @intCast(count) };
}

fn expect_line(
    lines: *std.mem.SplitIterator(u8, .scalar),
    key: []const u8,
    expected: []const []const u8,
) DecodeError!void {
    var fields: [2][]const u8 = undefined;
    assert(expected.len <= fields.len);
    try fields_of(lines, key, fields[0..expected.len]);
    for (expected, fields[0..expected.len]) |want, got| {
        if (!std.mem.eql(u8, want, got)) return error.InvalidManifest;
    }
}

/// Reads the next line, which must be `key` followed by exactly `out.len` fields.
fn fields_of(
    lines: *std.mem.SplitIterator(u8, .scalar),
    key: []const u8,
    out: [][]const u8,
) DecodeError!void {
    assert(out.len <= 2);
    const line = lines.next() orelse return error.InvalidManifest;
    if (line.len > line_bytes_max) return error.InvalidManifest;
    var parts = std.mem.splitScalar(u8, line, ' ');
    const first = parts.next() orelse return error.InvalidManifest;
    if (!std.mem.eql(u8, first, key)) return error.InvalidManifest;
    for (out) |*field| {
        field.* = parts.next() orelse return error.InvalidManifest;
        if (field.len == 0) return error.InvalidManifest;
    }
    if (parts.next() != null) return error.InvalidManifest;
}

fn number(comptime T: type, text: []const u8) DecodeError!T {
    if (text.len == 0 or text.len > 20) return error.InvalidManifest;
    if (text.len > 1 and text[0] == '0') return error.InvalidManifest; // Canonical only.
    for (text) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidManifest;
    return std.fmt.parseInt(T, text, 10) catch error.InvalidManifest;
}

fn hex32(text: []const u8, prefix: []const u8) DecodeError!Hash {
    if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidManifest;
    const digits = text[prefix.len..];
    if (digits.len != 64) return error.InvalidManifest;
    for (digits) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return error.InvalidManifest, // Lowercase only, as written.
    };
    var hash: Hash = undefined;
    _ = std.fmt.hexToBytes(&hash, digits) catch return error.InvalidManifest;
    return hash;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn sample_header() Header {
    return .{
        .chain_id = 900,
        .block_number = 123,
        .block_hash = @splat(0xab),
        .file_name = "node.db",
        .file_bytes = 10_000,
        .chunk_bytes = 4096,
    };
}

test "manifest: round trip" {
    const header = sample_header();
    const data: [10_000]u8 = @splat(7);
    var chunks: [3]Chunk = undefined;
    for (&chunks, 0..) |*chunk, index| {
        const start = index * header.chunk_bytes;
        const size = header.chunk_size(index);
        chunk.* = .{ .size = size, .hash = chunk_hash(data[start..][0..size]) };
    }
    try testing.expectEqual(@as(u32, 10_000 - 8192), chunks[2].size);
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try write(header, &chunks, &writer);
    var decoded_chunks: [4]Chunk = undefined;
    const decoded = try decode(writer.buffered(), &decoded_chunks);
    try testing.expectEqual(@as(u32, 3), decoded.chunk_count);
    try testing.expectEqualStrings("node.db", decoded.header.file_name);
    try testing.expectEqual(header.block_hash, decoded.header.block_hash);
    try testing.expectEqual(chunks[1].hash, decoded_chunks[1].hash);
    // Equal chunks share one content address.
    try testing.expectEqual(chunks[0].hash, chunks[1].hash);
}

test "manifest: tampering is rejected" {
    var buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    const chunks = [_]Chunk{
        .{ .size = 4096, .hash = @splat(1) },
        .{ .size = 4096, .hash = @splat(2) },
        .{ .size = 1808, .hash = @splat(3) },
    };
    try write(sample_header(), &chunks, &writer);
    const text = writer.buffered();
    var out: [4]Chunk = undefined;
    // Truncated: the `end` line is missing.
    try testing.expectError(error.InvalidManifest, decode(text[0 .. text.len - 4], &out));
    var edited: [1024]u8 = undefined;
    @memcpy(edited[0..text.len], text);
    const at = std.mem.indexOf(u8, text, "file node.db 10000").?;
    edited[at + "file node.db 1000".len] = '1'; // 10001 bytes: chunk sizes no longer add up.
    try testing.expectError(error.InvalidManifest, decode(edited[0..text.len], &out));
    try testing.expectError(error.InvalidManifest, decode("needlefish-snapshot 2\n", &out));
}

test "manifest: file names cannot escape the datadir" {
    var header = sample_header();
    for ([_][]const u8{ "..", "a/b", "", "x y" }) |name| {
        header.file_name = name;
        try testing.expect(!header.valid());
    }
}

fn check_decode(text: []const u8) !void {
    var chunks: [16]Chunk = undefined;
    const decoded = decode(text, &chunks) catch return;
    try testing.expect(decoded.header.valid());
    var total: u64 = 0;
    for (chunks[0..decoded.chunk_count]) |chunk| total += chunk.size;
    try testing.expectEqual(decoded.header.file_bytes, total);
}

test "manifest: seeded fuzz decode (mutated valid manifests)" {
    var prng = Prng.init(0x5a9);
    var base_buffer: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&base_buffer);
    const chunks = [_]Chunk{
        .{ .size = 4096, .hash = @splat(1) },
        .{ .size = 4096, .hash = @splat(2) },
        .{ .size = 1808, .hash = @splat(3) },
    };
    try write(sample_header(), &chunks, &writer);
    const text = writer.buffered();
    var mutated: [1024]u8 = undefined;
    for (0..2_000) |_| {
        @memcpy(mutated[0..text.len], text);
        for (0..prng.below(4) + 1) |_| {
            mutated[@intCast(prng.below(text.len))] = "0123456789 \nabx."[@intCast(prng.below(16))];
        }
        try check_decode(mutated[0..@intCast(prng.below(text.len) + 1)]);
    }
}

test "manifest: fuzz decode" {
    try testing.fuzz({}, fuzz_decode, .{});
}

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [1024]u8 = undefined;
    try check_decode(buffer[0..smith.slice(&buffer)]);
}

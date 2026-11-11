//! The tar layer of `base up`'s snapshot extraction: a `std.Io.Writer` that parses the tar
//! stream pushed into it and writes each member to an `Output`, hashing it with blake3.
//!
//! It is the zstd decoder's destination (`std.compress.zstd.Decompress` in direct mode, which
//! keeps its window in this writer's buffer), so the archive is never staged as a `.tar`.
//! The archive is untrusted: only the members the snapshot manifest lists are written, each
//! once, at its manifest size, and each must hash to the manifest's blake3. Any other member
//! (another name, a link, a device, a second copy) is refused, so a crafted archive cannot
//! write outside the extraction directory. Sizes may be octal or GNU base-256 (Base's
//! `mdbx.dat` is 1.14 TB, past the octal field's 8 GiB).

const std = @import("std");
const Io = std.Io;
const Blake3 = std.crypto.hash.Blake3;
const assert = std.debug.assert;

pub const block_size = 512;
/// Members of one snapshot component (Base's `state` has four).
pub const members_max = 16;

pub const Member = struct {
    path: []const u8,
    size: u64,
    blake3: [32]u8,
};

/// Where member bytes go: `open` starts member `index`, `write` appends at `offset`.
pub const Output = struct {
    context: *anyopaque,
    open: *const fn (context: *anyopaque, index: u32, member: *const Member) anyerror!void,
    write: *const fn (context: *anyopaque, bytes: []const u8, offset: u64) anyerror!void,
    close: *const fn (context: *anyopaque) anyerror!void,
};

pub const Error = error{
    BadHeader,
    UnexpectedMember,
    SizeMismatch,
    HashMismatch,
    Truncated,
    TrailingData,
    OutputFailed,
};

pub const Sink = struct {
    writer: Io.Writer,
    members: []const Member,
    output: Output,
    seen: [members_max]bool = @splat(false),
    state: State = .header,
    header: [block_size]u8 = undefined,
    header_fill: u32 = 0,
    member: u32 = 0,
    remaining: u64 = 0,
    offset: u64 = 0,
    padding: u32 = 0,
    hasher: Blake3 = Blake3.init(.{}),
    /// The first failure; `drain` can only report `WriteFailed`.
    failure: ?Error = null,
    /// The output error behind `OutputFailed` (no space left, ...).
    output_error: ?anyerror = null,
    /// Member bytes written, for progress (read by other threads).
    written: std.atomic.Value(u64) = .init(0),

    const State = enum { header, body, padding, end };

    /// `buffer` must hold the zstd window and one block when this is a zstd destination.
    pub fn init(buffer: []u8, members: []const Member, output: Output) Sink {
        assert(members.len > 0 and members.len <= members_max);
        assert(buffer.len >= block_size);
        return .{
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .members = members,
            .output = output,
        };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const sink: *Sink = @alignCast(@fieldParentPtr("writer", w));
        sink.consume(w.buffered()) catch |err| return sink.fail(err);
        w.end = 0;
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| {
            sink.consume(bytes) catch |err| return sink.fail(err);
            written += bytes.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            sink.consume(pattern) catch |err| return sink.fail(err);
            written += pattern.len;
        }
        return written;
    }

    fn fail(sink: *Sink, err: Error) Io.Writer.Error {
        if (sink.failure == null) sink.failure = err;
        return error.WriteFailed;
    }

    /// Ends the stream: everything buffered is parsed, and the archive must have ended (its
    /// zero block seen) with every member written.
    pub fn finish(sink: *Sink) Error!void {
        sink.writer.flush() catch return sink.failure.?;
        if (sink.failure) |failure| return failure;
        if (sink.state != .end) return error.Truncated;
        for (sink.members, 0..) |_, index| {
            if (!sink.seen[index]) return error.Truncated;
        }
    }

    /// Parses `bytes`, the next bytes of the archive.
    fn consume(sink: *Sink, bytes: []const u8) Error!void {
        if (sink.failure) |failure| return failure;
        var rest = bytes;
        while (rest.len > 0) {
            const used = switch (sink.state) {
                .header => try sink.take_header(rest),
                .body => try sink.take_body(rest),
                .padding => sink.take_padding(rest),
                .end => try take_end(rest),
            };
            assert(used > 0 and used <= rest.len);
            rest = rest[used..];
        }
    }

    fn take_header(sink: *Sink, bytes: []const u8) Error!usize {
        assert(sink.header_fill < block_size);
        const used = @min(bytes.len, block_size - sink.header_fill);
        @memcpy(sink.header[sink.header_fill..][0..used], bytes[0..used]);
        sink.header_fill += @intCast(used);
        if (sink.header_fill == block_size) {
            sink.header_fill = 0;
            try sink.start_member();
        }
        return used;
    }

    fn start_member(sink: *Sink) Error!void {
        assert(sink.state == .header);
        if (std.mem.allEqual(u8, &sink.header, 0)) {
            sink.state = .end;
            return;
        }
        const header = try parse_header(&sink.header);
        if (header.kind == .directory) {
            if (header.size != 0) return error.BadHeader;
            return; // Directories come from the member paths.
        }
        const index = member_index(sink.members, header.name) orelse return error.UnexpectedMember;
        if (sink.seen[index]) return error.UnexpectedMember;
        const member = &sink.members[index];
        if (header.size != member.size) return error.SizeMismatch;
        sink.seen[index] = true;
        sink.member = index;
        sink.remaining = header.size;
        sink.offset = 0;
        sink.padding = @intCast((block_size - header.size % block_size) % block_size);
        sink.hasher = Blake3.init(.{});
        sink.output.open(sink.output.context, index, member) catch |err| {
            return sink.output_failed(err);
        };
        sink.state = .body;
        if (sink.remaining == 0) try sink.end_member();
    }

    fn take_body(sink: *Sink, bytes: []const u8) Error!usize {
        assert(sink.remaining > 0);
        const used: usize = @intCast(@min(bytes.len, sink.remaining));
        const part = bytes[0..used];
        sink.output.write(sink.output.context, part, sink.offset) catch |err| {
            return sink.output_failed(err);
        };
        sink.hasher.update(part);
        sink.offset += used;
        sink.remaining -= used;
        _ = sink.written.fetchAdd(used, .monotonic);
        if (sink.remaining == 0) try sink.end_member();
        return used;
    }

    fn end_member(sink: *Sink) Error!void {
        assert(sink.state == .body and sink.remaining == 0);
        var digest: [32]u8 = undefined;
        sink.hasher.final(&digest);
        sink.output.close(sink.output.context) catch |err| return sink.output_failed(err);
        if (!std.mem.eql(u8, &digest, &sink.members[sink.member].blake3)) {
            return error.HashMismatch;
        }
        sink.state = if (sink.padding == 0) .header else .padding;
    }

    fn take_padding(sink: *Sink, bytes: []const u8) usize {
        assert(sink.padding > 0);
        const used: u32 = @intCast(@min(bytes.len, sink.padding));
        sink.padding -= used;
        if (sink.padding == 0) sink.state = .header;
        return used;
    }

    /// After the end-of-archive block only zeros may follow (the second zero block and the
    /// record padding).
    fn take_end(bytes: []const u8) Error!usize {
        if (!std.mem.allEqual(u8, bytes, 0)) return error.TrailingData;
        return bytes.len;
    }

    fn output_failed(sink: *Sink, err: anyerror) Error {
        sink.output_error = err;
        return error.OutputFailed;
    }
};

fn member_index(members: []const Member, name: []const u8) ?u32 {
    const path = if (std.mem.startsWith(u8, name, "./")) name[2..] else name;
    for (members, 0..) |member, index| {
        if (std.mem.eql(u8, member.path, path)) return @intCast(index);
    }
    return null;
}

pub const Header = struct {
    name: []const u8,
    size: u64,
    kind: enum { file, directory },
};

/// One tar header block: checksum, regular file or directory, octal or base-256 size.
pub fn parse_header(block: *const [block_size]u8) Error!Header {
    const stored = parse_octal(block[148..156]) orelse return error.BadHeader;
    var sum: u64 = 0;
    for (block, 0..) |byte, index| {
        sum += if (index >= 148 and index < 156) ' ' else byte;
    }
    if (sum != stored) return error.BadHeader;
    const kind: @FieldType(Header, "kind") = switch (block[156]) {
        0, '0' => .file,
        '5' => .directory,
        else => return error.UnexpectedMember, // Links, devices, long names, pax.
    };
    const name_end = std.mem.indexOfScalar(u8, block[0..100], 0) orelse 100;
    const name = block[0..name_end];
    if (name.len == 0) return error.BadHeader;
    const size = parse_size(block[124..136]) orelse return error.BadHeader;
    return .{ .name = name, .size = size, .kind = kind };
}

fn parse_size(field: *const [12]u8) ?u64 {
    if (field[0] & 0x80 == 0) return parse_octal(field);
    // GNU base-256: big-endian, the top bit of the first byte is the marker.
    if (field[0] != 0x80 or !std.mem.allEqual(u8, field[1..4], 0)) return null;
    return std.mem.readInt(u64, field[4..12], .big);
}

fn parse_octal(field: []const u8) ?u64 {
    const trimmed = std.mem.trim(u8, field, " \x00");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(u64, trimmed, 8) catch null;
}

// ---- Tests ---------------------------------------------------------------------------

const testing = std.testing;
const Prng = @import("base").testing.Prng;

/// Writes a header for `name` of `size` bytes; base-256 when `size` needs it or `binary`.
fn test_header(block: *[block_size]u8, name: []const u8, size: u64, kind: u8, binary: bool) void {
    @memset(block, 0);
    @memcpy(block[0..name.len], name);
    @memcpy(block[100..107], "0000644");
    if (binary or size >= 1 << 33) {
        block[124] = 0x80;
        std.mem.writeInt(u64, block[128..136], size, .big);
    } else {
        _ = std.fmt.bufPrint(block[124..135], "{o:0>11}", .{size}) catch unreachable;
    }
    block[156] = kind;
    @memcpy(block[257..265], "ustar  \x00");
    @memset(block[148..156], ' ');
    var sum: u64 = 0;
    for (block) |byte| sum += byte;
    _ = std.fmt.bufPrint(block[148..155], "{o:0>6}\x00", .{sum}) catch unreachable;
}

const Memory = struct {
    files: [members_max]std.ArrayList(u8) = @splat(.empty),
    open_index: ?u32 = null,
    fail_after_bytes: ?u64 = null,
    total: u64 = 0,

    fn output(memory: *Memory) Output {
        return .{ .context = memory, .open = open, .write = write, .close = close };
    }

    fn open(context: *anyopaque, index: u32, member: *const Member) anyerror!void {
        const memory: *Memory = @ptrCast(@alignCast(context));
        assert(memory.open_index == null and member.path.len > 0);
        memory.open_index = index;
    }

    fn write(context: *anyopaque, bytes: []const u8, offset: u64) anyerror!void {
        const memory: *Memory = @ptrCast(@alignCast(context));
        const file = &memory.files[memory.open_index.?];
        try testing.expectEqual(@as(u64, file.items.len), offset);
        memory.total += bytes.len;
        if (memory.fail_after_bytes) |limit| if (memory.total > limit) return error.NoSpaceLeft;
        try file.appendSlice(testing.allocator, bytes);
    }

    fn close(context: *anyopaque) anyerror!void {
        const memory: *Memory = @ptrCast(@alignCast(context));
        memory.open_index = null;
    }

    fn deinit(memory: *Memory) void {
        for (&memory.files) |*file| file.deinit(testing.allocator);
    }
};

/// An archive of `contents` (directory entry first), as GNU tar writes one.
fn test_archive(names: []const []const u8, contents: []const []const u8, binary: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    var block: [block_size]u8 = undefined;
    test_header(&block, "db/", 0, '5', false);
    try out.appendSlice(testing.allocator, &block);
    for (names, contents) |name, content| {
        test_header(&block, name, content.len, 0, binary);
        try out.appendSlice(testing.allocator, &block);
        try out.appendSlice(testing.allocator, content);
        const padding = (block_size - content.len % block_size) % block_size;
        try out.appendNTimes(testing.allocator, 0, padding);
    }
    try out.appendNTimes(testing.allocator, 0, 2 * block_size + 3 * block_size);
    return out.toOwnedSlice(testing.allocator);
}

fn test_members(names: []const []const u8, contents: []const []const u8, out: []Member) void {
    for (names, contents, 0..) |name, content, index| {
        out[index] = .{ .path = name, .size = content.len, .blake3 = undefined };
        Blake3.hash(content, &out[index].blake3, .{});
    }
}

/// Pushes `archive` through a sink in pieces of random sizes.
fn push(archive: []const u8, members: []const Member, memory: *Memory, prng: *Prng) Error!void {
    var buffer: [block_size * 3]u8 = undefined;
    var sink = Sink.init(&buffer, members, memory.output());
    var rest = archive;
    while (rest.len > 0) {
        const size = @min(rest.len, prng.range(1, 2000));
        sink.writer.writeAll(rest[0..size]) catch return sink.failure.?;
        rest = rest[size..];
    }
    return sink.finish();
}

test "up tar: members extract exactly, in any piece sizes" {
    var prng = Prng.init(0x7a12);
    const names = [_][]const u8{ "db/database.version", "db/lock", "db/mdbx.dat", "db/mdbx.lck" };
    var mdbx: [5000]u8 = undefined;
    prng.random().bytes(&mdbx);
    const filler: [513]u8 = @splat('x');
    const contents = [_][]const u8{ "2", "", &mdbx, &filler };
    var members: [4]Member = undefined;
    test_members(&names, &contents, &members);
    for ([_]bool{ false, true }) |binary| {
        const archive = try test_archive(&names, &contents, binary);
        defer testing.allocator.free(archive);
        for (0..20) |_| {
            var memory: Memory = .{};
            defer memory.deinit();
            try push(archive, &members, &memory, &prng);
            for (contents, 0..) |content, index| {
                try testing.expectEqualSlices(u8, content, memory.files[index].items);
            }
        }
    }
}

test "up tar: refuses damaged, foreign, and short archives" {
    var prng = Prng.init(0x7a13);
    const names = [_][]const u8{ "db/lock", "db/mdbx.dat" };
    const data: [1200]u8 = @splat('d');
    const contents = [_][]const u8{ "lock", &data };
    var members: [2]Member = undefined;
    test_members(&names, &contents, &members);
    const archive = try test_archive(&names, &contents, false);
    defer testing.allocator.free(archive);
    const Case = struct { mutate: *const fn ([]u8) []u8, expected: Error };
    const cases = [_]Case{
        // A flipped data byte: the blake3 check.
        .{
            .mutate = struct {
                fn f(a: []u8) []u8 {
                    a[4 * block_size + 7] ^= 1; // Inside db/mdbx.dat (block 3 is its header).
                    return a;
                }
            }.f,
            .expected = error.HashMismatch,
        },
        // A flipped header byte: the header checksum.
        .{ .mutate = struct {
            fn f(a: []u8) []u8 {
                a[block_size + 2] ^= 1;
                return a;
            }
        }.f, .expected = error.BadHeader },
        // Cut short: the archive must end.
        .{ .mutate = struct {
            fn f(a: []u8) []u8 {
                return a[0 .. 4 * block_size];
            }
        }.f, .expected = error.Truncated },
        // Junk after the end blocks.
        .{ .mutate = struct {
            fn f(a: []u8) []u8 {
                a[a.len - 1] = 1;
                return a;
            }
        }.f, .expected = error.TrailingData },
    };
    for (cases) |case| {
        const copy = try testing.allocator.dupe(u8, archive);
        defer testing.allocator.free(copy);
        var memory: Memory = .{};
        defer memory.deinit();
        try testing.expectError(case.expected, push(case.mutate(copy), &members, &memory, &prng));
    }
    // A member the manifest does not list, and a listed one at another size.
    var memory: Memory = .{};
    defer memory.deinit();
    const other = [_][]const u8{ "db/lock", "../etc/passwd" };
    const foreign = try test_archive(&other, &contents, false);
    defer testing.allocator.free(foreign);
    try testing.expectError(error.UnexpectedMember, push(foreign, &members, &memory, &prng));
    const resized = try test_archive(&names, &.{ "lock!", contents[1] }, false);
    defer testing.allocator.free(resized);
    try testing.expectError(error.SizeMismatch, push(resized, &members, &memory, &prng));
}

test "up tar: an output failure stops the extraction with its error" {
    var prng = Prng.init(0x7a14);
    const names = [_][]const u8{"db/mdbx.dat"};
    const data: [4000]u8 = @splat('z');
    const contents = [_][]const u8{&data};
    var members: [1]Member = undefined;
    test_members(&names, &contents, &members);
    const archive = try test_archive(&names, &contents, false);
    defer testing.allocator.free(archive);
    var memory: Memory = .{ .fail_after_bytes = 1000 };
    defer memory.deinit();
    var buffer: [block_size * 2]u8 = undefined;
    var sink = Sink.init(&buffer, &members, memory.output());
    _ = &prng;
    const result = if (sink.writer.writeAll(archive)) |_| sink.finish() else |_| sink.failure.?;
    try testing.expectError(error.OutputFailed, result);
    try testing.expectEqual(error.NoSpaceLeft, sink.output_error.?);
}

test "up tar: header sizes, octal and base-256" {
    var block: [block_size]u8 = undefined;
    test_header(&block, "db/mdbx.dat", 1_138_166_333_440, 0, false);
    const big = try parse_header(&block);
    try testing.expectEqual(@as(u64, 1_138_166_333_440), big.size);
    try testing.expectEqualStrings("db/mdbx.dat", big.name);
    test_header(&block, "db/lock", 12, '0', false);
    try testing.expectEqual(@as(u64, 12), (try parse_header(&block)).size);
    test_header(&block, "db/link", 0, '2', false);
    try testing.expectError(error.UnexpectedMember, parse_header(&block));
}

test "up tar: seeded fuzz, random bytes never crash the parser" {
    var prng = Prng.init(0x7a15);
    const members = [_]Member{.{ .path = "db/mdbx.dat", .size = 10, .blake3 = @splat(0) }};
    var bytes: [4 * block_size]u8 = undefined;
    for (0..2000) |_| {
        prng.random().bytes(&bytes);
        // Sometimes a valid header, so the body and end paths run too.
        if (prng.chance(1, 2)) test_header(bytes[0..block_size], "db/mdbx.dat", 10, 0, false);
        if (prng.chance(1, 4)) @memset(bytes[2 * block_size ..], 0);
        var memory: Memory = .{};
        defer memory.deinit();
        const length = prng.range(0, bytes.len);
        _ = push(bytes[0..length], &members, &memory, &prng) catch {};
    }
}

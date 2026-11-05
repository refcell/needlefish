//! Brotli decompressor (RFC 7932), used for Fjord brotli channels.
//!
//! Mirrors the decoding the base/base channel reader gets from the `brotli` crate. The caller
//! strips the channel version byte (0x01) before calling in.
//!
//! The decoder keeps the whole output in one flat buffer, so back-references read straight
//! from it instead of from a ring buffer. The window size still bounds every distance exactly
//! as RFC 7932 section 9.1 requires, so the output matches a ring-buffer decoder byte for byte.
//!
//! All scratch state (prefix code tables, context maps) lives in `Decoder`, about 1.2 MiB.
//! Callers allocate it once and reuse it; decoding itself allocates nothing, except to grow
//! the output buffer in `decompress`.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// The stream violates RFC 7932.
    InvalidData,
    /// The input ended before the stream was complete.
    Truncated,
    /// The output would exceed the caller's limit. The output buffer holds the prefix that fit.
    OutputLimitExceeded,
    OutOfMemory,
};

/// The RFC 7932 appendix A static dictionary. Its CRC-32 (0x5136cb04) and SHA-256 are checked
/// in the tests below.
pub const dictionary_size_bytes = 122_784;
pub const dictionary: *const [dictionary_size_bytes]u8 = @embedFile("brotli_dictionary.bin");

const window_gap_bytes = 16;
const code_length_max = 15;
const fast_bits = 8;
const fast_size = 1 << fast_bits;
const literal_alphabet_size = 256;
const insert_copy_alphabet_size = 704;
const block_count_alphabet_size = 26;
const block_types_max = 256;
const block_type_alphabet_max = block_types_max + 2;
const trees_max = 256;
const run_length_prefix_max = 16;
const context_map_alphabet_max = trees_max + run_length_prefix_max;
const direct_distance_codes_max = 15 << 3;
const distance_alphabet_max = 16 + direct_distance_codes_max + (48 << 3);
const code_length_alphabet_size = 18;
const literal_contexts = 64;
const distance_contexts = 4;
const max_allowed_distance = 0x7FFF_FFFC;
/// Block length used when a category has a single block type (RFC 7932 section 6).
const block_length_unbounded = 1 << 24;
const block_length_max = 16625 + (1 << 24) - 1;
const transformed_word_max_bytes = 64;
const transform_count = 121;
const word_length_min = 4;
const word_length_max = 24;

comptime {
    assert(distance_alphabet_max == 520);
    // A fast-table entry packs `symbol << 4 | length`, so symbols must fit in 12 bits.
    assert(insert_copy_alphabet_size <= 1 << 12);
    assert(distance_alphabet_max <= 1 << 12);
    assert(code_length_max < 16);
}

/// Feature counters for one decode, used by tests to prove which RFC paths a stream exercised.
pub const Stats = struct {
    meta_blocks_compressed: u32 = 0,
    meta_blocks_uncompressed: u32 = 0,
    meta_blocks_metadata: u32 = 0,
    dictionary_references: u64 = 0,
    transformed_references: u64 = 0,
    block_switches: u64 = 0,
    literal_trees_max: u32 = 0,
    distance_trees_max: u32 = 0,
    /// Bit `m` is set when a meta-block with several literal trees used context mode `m`.
    context_modes_used: u4 = 0,
};

/// Scratch state for decoding. Allocate once (it is large), reuse for every stream.
pub const Decoder = struct {
    literal_trees: [trees_max]Tree(literal_alphabet_size),
    insert_copy_trees: [block_types_max]Tree(insert_copy_alphabet_size),
    distance_trees: [trees_max]Tree(distance_alphabet_max),
    block_type_trees: [3]Tree(block_type_alphabet_max),
    block_count_trees: [3]Tree(block_count_alphabet_size),
    context_map_tree: Tree(context_map_alphabet_max),
    code_length_tree: Tree(code_length_alphabet_size),
    lengths: [insert_copy_alphabet_size]u8,
    literal_context_map: [block_types_max * literal_contexts]u8,
    distance_context_map: [block_types_max * distance_contexts]u8,
    context_modes: [block_types_max]u2,
    stats: Stats,

    /// Decodes `input` into `out`. Returns the written prefix of `out`. Returns
    /// `error.OutputLimitExceeded` when the stream produces more than `out.len` bytes; `out`
    /// then holds the first `out.len` output bytes, so callers can truncate.
    pub fn decompress_into(decoder: *Decoder, out: []u8, input: []const u8) Error![]u8 {
        const result = decoder.decompress_partial(out, input);
        try result.status;
        return result.output;
    }

    /// Like `decompress_into`, but also returns the output written before any error, so a
    /// caller can keep the batches decoded before a corrupt or over-long tail.
    pub fn decompress_partial(decoder: *Decoder, out: []u8, input: []const u8) Partial {
        var sink: Sink = .{ .buffer = out, .limit = out.len, .allocator = null };
        const status = decoder.decode(&sink, input);
        assert(sink.len <= out.len);
        return .{ .output = out[0..sink.len], .status = status };
    }

    fn decode(decoder: *Decoder, sink: *Sink, input: []const u8) Error!void {
        decoder.stats = .{};
        var stream: Stream = .{
            .decoder = decoder,
            .reader = .{ .input = input },
            .sink = sink,
            .max_backward_distance = 0,
        };
        const window_bits = try read_window_bits(&stream.reader);
        assert(window_bits >= 10 and window_bits <= 24);
        stream.max_backward_distance = (@as(u32, 1) << @intCast(window_bits)) - window_gap_bytes;
        // Every meta-block header consumes at least two bits, which bounds the loop.
        const meta_blocks_max = input.len * 4 + 1;
        for (0..meta_blocks_max) |_| {
            const last = try decode_meta_block(&stream);
            if (last) break;
        } else return error.InvalidData;
        // The bits after the last meta-block, up to the byte boundary, must be zero.
        try stream.reader.align_to_byte();
    }
};

comptime {
    // Keep the scratch footprint documented above honest.
    assert(@sizeOf(Decoder) <= 1_300_000);
}

/// Output of `Decoder.decompress_partial`.
pub const Partial = struct {
    output: []u8,
    status: Error!void,
};

/// Decompresses `input` into a new allocator-owned buffer. Returns
/// `error.OutputLimitExceeded` when the output would exceed `output_limit_bytes`.
pub fn decompress(
    allocator: std.mem.Allocator,
    input: []const u8,
    output_limit_bytes: u64,
) Error![]u8 {
    const decoder = try allocator.create(Decoder);
    defer allocator.destroy(decoder);
    const limit: usize = @intCast(@min(output_limit_bytes, std.math.maxInt(usize)));
    var sink: Sink = .{ .buffer = &.{}, .limit = limit, .allocator = allocator };
    errdefer allocator.free(sink.buffer);
    try decoder.decode(&sink, input);
    assert(sink.len <= limit);
    const output = try allocator.realloc(sink.buffer, sink.len);
    assert(output.len == sink.len);
    return output;
}

/// Channel-reader semantics (base/base `Brotli::decompress`): output past
/// `output_limit_bytes` is truncated, and a stream that fails after producing output keeps
/// that output. Fails only when the stream produced nothing. Caller owns the result.
pub fn decompress_truncating(
    allocator: std.mem.Allocator,
    input: []const u8,
    output_limit_bytes: u64,
) Error![]u8 {
    const decoder = try allocator.create(Decoder);
    defer allocator.destroy(decoder);
    const limit: usize = @intCast(@min(output_limit_bytes, std.math.maxInt(usize)));
    var sink: Sink = .{ .buffer = &.{}, .limit = limit, .allocator = allocator };
    errdefer allocator.free(sink.buffer);
    decoder.decode(&sink, input) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.OutputLimitExceeded, error.InvalidData, error.Truncated => {
            if (sink.len == 0) return err;
        },
    };
    assert(sink.len <= limit);
    return allocator.realloc(sink.buffer, sink.len);
}

/// Decodes `input` into `out` with caller-owned scratch. See `Decoder.decompress_into`.
pub fn decompress_into(decoder: *Decoder, out: []u8, input: []const u8) Error![]u8 {
    return decoder.decompress_into(out, input);
}

/// Output buffer: a fixed caller buffer, or one grown with an allocator up to `limit`.
const Sink = struct {
    buffer: []u8,
    len: usize = 0,
    limit: usize,
    allocator: ?std.mem.Allocator,

    /// Returns how many of `wanted` bytes fit, growing the buffer toward `limit` if it can.
    fn reserve(sink: *Sink, wanted: usize) Error!usize {
        assert(sink.len <= sink.buffer.len);
        assert(sink.buffer.len <= sink.limit);
        if (wanted <= sink.buffer.len - sink.len) return wanted;
        if (sink.allocator) |allocator| {
            if (sink.buffer.len < sink.limit) {
                const needed = sink.len +| wanted;
                const capacity = @min(sink.limit, @max(needed, sink.buffer.len *| 2, 4096));
                assert(capacity > sink.buffer.len);
                sink.buffer = try allocator.realloc(sink.buffer, capacity);
            }
        }
        return @min(wanted, sink.buffer.len - sink.len);
    }

    fn last_byte(sink: *const Sink, back: usize) u8 {
        assert(back == 1 or back == 2);
        if (sink.len < back) return 0;
        return sink.buffer[sink.len - back];
    }
};

/// Little-endian bit reader. Past the end of input it reads zero bytes and counts them, so
/// `consume` reports truncation only when a decode really used bits that do not exist.
const BitReader = struct {
    input: []const u8,
    index: usize = 0,
    buffer: u64 = 0,
    count: u32 = 0,
    overrun_bytes: u32 = 0,

    fn refill(reader: *BitReader) void {
        assert(reader.count <= 64);
        // Loads at most eight bytes.
        while (reader.count <= 56) {
            var byte: u64 = 0;
            if (reader.index < reader.input.len) {
                byte = reader.input[reader.index];
                reader.index += 1;
            } else {
                reader.overrun_bytes += 1;
            }
            reader.buffer |= byte << @intCast(reader.count);
            reader.count += 8;
        }
        assert(reader.count >= 57);
    }

    fn peek(reader: *BitReader, bit_count: u32) u32 {
        assert(bit_count <= 32);
        if (reader.count < bit_count) reader.refill();
        assert(reader.count >= bit_count);
        const mask = (@as(u64, 1) << @intCast(bit_count)) - 1;
        return @intCast(reader.buffer & mask);
    }

    fn consume(reader: *BitReader, bit_count: u32) Error!void {
        assert(bit_count <= 32);
        assert(bit_count <= reader.count);
        reader.buffer >>= @intCast(bit_count);
        reader.count -= bit_count;
        if (reader.count < reader.overrun_bytes * 8) return error.Truncated;
    }

    fn read(reader: *BitReader, bit_count: u32) Error!u32 {
        const value = reader.peek(bit_count);
        try reader.consume(bit_count);
        return value;
    }

    /// Skips to the next byte boundary. The skipped bits must be zero.
    fn align_to_byte(reader: *BitReader) Error!void {
        const padding = reader.count % 8;
        if (try reader.read(padding) != 0) return error.InvalidData;
        assert(reader.count % 8 == 0);
    }

    /// Reads whole bytes into `dest` (or skips them when `dest` is null). Byte aligned only.
    fn read_bytes(reader: *BitReader, dest: ?[]u8, length: usize) Error!void {
        assert(reader.count % 8 == 0);
        if (dest) |slice| assert(slice.len == length);
        var done: usize = 0;
        while (done < length and reader.count >= 8) : (done += 1) {
            const byte: u8 = @intCast(try reader.read(8));
            if (dest) |slice| slice[done] = byte;
        }
        if (done == length) return;
        // The buffer is empty, so no zero bytes past the end are pending.
        assert(reader.count == 0);
        assert(reader.overrun_bytes == 0);
        const rest = length - done;
        if (reader.input.len - reader.index < rest) return error.Truncated;
        if (dest) |slice| @memcpy(slice[done..], reader.input[reader.index..][0..rest]);
        reader.index += rest;
    }
};

/// A canonical prefix code. `fast` maps the next 8 input bits to `symbol << 4 | length` for
/// codes of at most 8 bits (0 marks a longer code); longer codes walk `counts`.
/// `counts[0] == 1` marks a code with a single symbol, which uses zero bits.
const Table = struct {
    fast: *[fast_size]u16,
    counts: *[code_length_max + 1]u16,
    symbols: []u16,
};

fn Tree(comptime alphabet_max: u16) type {
    return struct {
        fast: [fast_size]u16,
        counts: [code_length_max + 1]u16,
        symbols: [alphabet_max]u16,

        fn table(tree: *@This()) Table {
            return .{ .fast = &tree.fast, .counts = &tree.counts, .symbols = &tree.symbols };
        }
    };
}

/// Builds a canonical code from code lengths. The code must be complete, or have exactly one
/// used symbol (RFC 7932 section 3.4 single-symbol codes).
fn table_build(table: Table, lengths: []const u8) Error!void {
    assert(lengths.len >= 2);
    assert(lengths.len <= table.symbols.len);
    @memset(table.counts, 0);
    var used: u32 = 0;
    var used_symbol: u16 = 0;
    for (lengths, 0..) |length, symbol| {
        assert(length <= code_length_max);
        if (length == 0) continue;
        table.counts[length] += 1;
        used += 1;
        used_symbol = @intCast(symbol);
    }
    if (used == 0) return error.InvalidData;
    if (used == 1) {
        @memset(table.counts, 0);
        table.counts[0] = 1;
        table.symbols[0] = used_symbol;
        return;
    }
    var left: i32 = 1;
    for (1..code_length_max + 1) |length| {
        left = (left << 1) - @as(i32, table.counts[length]);
        if (left < 0) return error.InvalidData;
    }
    if (left != 0) return error.InvalidData;
    var offsets: [code_length_max + 2]u16 = undefined;
    offsets[1] = 0;
    for (1..code_length_max + 1) |length| {
        offsets[length + 1] = offsets[length] + table.counts[length];
    }
    assert(offsets[code_length_max + 1] == used);
    for (lengths, 0..) |length, symbol| {
        if (length == 0) continue;
        table.symbols[offsets[length]] = @intCast(symbol);
        offsets[length] += 1;
    }
    table_fill_fast(table);
}

fn table_fill_fast(table: Table) void {
    assert(table.counts[0] == 0);
    @memset(table.fast, 0);
    var code: u32 = 0;
    var index: u32 = 0;
    for (1..fast_bits + 1) |length| {
        for (0..table.counts[length]) |_| {
            assert(code < (@as(u32, 1) << @intCast(length)));
            const reversed = @bitReverse(@as(u8, @intCast(code << @intCast(8 - length))));
            const entry: u16 = (table.symbols[index] << 4) | @as(u16, @intCast(length));
            var slot: u32 = reversed;
            while (slot < fast_size) : (slot += @as(u32, 1) << @intCast(length)) {
                table.fast[slot] = entry;
            }
            code += 1;
            index += 1;
        }
        code <<= 1;
    }
}

fn table_decode(table: Table, reader: *BitReader) Error!u16 {
    if (table.counts[0] != 0) return table.symbols[0];
    const bits = reader.peek(code_length_max);
    const entry = table.fast[bits & (fast_size - 1)];
    if (entry != 0) {
        try reader.consume(entry & 15);
        return entry >> 4;
    }
    return table_decode_slow(table, reader, bits);
}

/// Walks the canonical code one bit at a time (codes are packed most significant bit first).
fn table_decode_slow(table: Table, reader: *BitReader, bits: u32) Error!u16 {
    var code: i32 = 0;
    var first: i32 = 0;
    var index: i32 = 0;
    for (1..code_length_max + 1) |length| {
        code |= @intCast((bits >> @intCast(length - 1)) & 1);
        const count: i32 = table.counts[length];
        if (code - first < count) {
            try reader.consume(@intCast(length));
            const position: usize = @intCast(index + code - first);
            assert(position < table.symbols.len);
            return table.symbols[position];
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    // Unreachable for complete codes, which `table_build` enforces.
    return error.InvalidData;
}

const code_length_order = [code_length_alphabet_size]u8{
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15,
};
// The fixed code for code length code lengths (RFC 7932 section 3.5), indexed by 4 peeked bits.
const code_length_prefix_length = [16]u8{ 2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4 };
const code_length_prefix_value = [16]u8{ 0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5 };

/// Reads one prefix code (RFC 7932 section 3.2-3.5) over `alphabet_size` symbols.
fn read_prefix_code(
    decoder: *Decoder,
    reader: *BitReader,
    table: Table,
    alphabet_size: u32,
) Error!void {
    assert(alphabet_size >= 2);
    assert(alphabet_size <= table.symbols.len);
    const lengths = decoder.lengths[0..alphabet_size];
    @memset(lengths, 0);
    const kind = try reader.read(2);
    if (kind == 1) {
        try read_simple_lengths(reader, lengths);
    } else {
        try read_complex_lengths(decoder, reader, lengths, kind);
    }
    try table_build(table, lengths);
}

fn read_simple_lengths(reader: *BitReader, lengths: []u8) Error!void {
    assert(lengths.len >= 2);
    const alphabet_size: u32 = @intCast(lengths.len);
    const symbol_bits: u32 = 32 - @clz(alphabet_size - 1);
    const symbol_count = try reader.read(2) + 1;
    var symbols: [4]u16 = undefined;
    for (0..symbol_count) |i| {
        const symbol = try reader.read(symbol_bits);
        if (symbol >= alphabet_size) return error.InvalidData;
        for (symbols[0..i]) |prior| {
            if (prior == symbol) return error.InvalidData;
        }
        symbols[i] = @intCast(symbol);
    }
    const shape: [4]u8 = switch (symbol_count) {
        1 => .{ 1, 0, 0, 0 },
        2 => .{ 1, 1, 0, 0 },
        3 => .{ 1, 2, 2, 0 },
        4 => if (try reader.read(1) == 0) .{ 2, 2, 2, 2 } else .{ 1, 2, 3, 3 },
        else => unreachable, // symbol_count is a 2-bit value plus one.
    };
    for (symbols[0..symbol_count], shape[0..symbol_count]) |symbol, length| {
        assert(length != 0);
        lengths[symbol] = length;
    }
}

fn read_complex_lengths(
    decoder: *Decoder,
    reader: *BitReader,
    lengths: []u8,
    skip: u32,
) Error!void {
    assert(skip == 0 or skip == 2 or skip == 3);
    var code_lengths: [code_length_alphabet_size]u8 = @splat(0);
    var space: i32 = 32;
    var used: u32 = 0;
    for (code_length_order[skip..]) |symbol| {
        const bits = reader.peek(4);
        try reader.consume(code_length_prefix_length[bits]);
        const value = code_length_prefix_value[bits];
        code_lengths[symbol] = value;
        if (value == 0) continue;
        space -= @as(i32, 32) >> @intCast(value);
        used += 1;
        if (space <= 0) break;
    }
    if (used != 1 and space != 0) return error.InvalidData;
    const table = decoder.code_length_tree.table();
    try table_build(table, &code_lengths);
    try read_symbol_lengths(reader, table, lengths);
}

fn read_symbol_lengths(reader: *BitReader, table: Table, lengths: []u8) Error!void {
    assert(lengths.len >= 2);
    var symbol: usize = 0;
    var previous: u8 = 8;
    var repeat: u32 = 0;
    var repeat_length: u8 = 0;
    var space: i32 = 1 << 15;
    // Every iteration fills at least one symbol.
    for (0..lengths.len) |_| {
        if (symbol >= lengths.len or space <= 0) break;
        const code = try table_decode(table, reader);
        assert(code < code_length_alphabet_size);
        if (code < 16) {
            repeat = 0;
            lengths[symbol] = @intCast(code);
            symbol += 1;
            if (code != 0) {
                previous = @intCast(code);
                space -= @as(i32, 1 << 15) >> @intCast(code);
            }
            continue;
        }
        const extra_bits: u32 = if (code == 16) 2 else 3;
        const new_length: u8 = if (code == 16) previous else 0;
        if (repeat_length != new_length) {
            repeat = 0;
            repeat_length = new_length;
        }
        const old_repeat = repeat;
        if (repeat > 0) repeat = (repeat - 2) << @intCast(extra_bits);
        repeat += try reader.read(extra_bits) + 3;
        const delta = repeat - old_repeat;
        if (delta > lengths.len - symbol) return error.InvalidData;
        @memset(lengths[symbol..][0..delta], repeat_length);
        symbol += delta;
        if (repeat_length != 0) {
            space -= @as(i32, @intCast(delta)) << @intCast(15 - repeat_length);
        }
    }
    if (space != 0) return error.InvalidData;
}

fn read_var_len_u8(reader: *BitReader) Error!u32 {
    if (try reader.read(1) == 0) return 0;
    const bit_count = try reader.read(3);
    if (bit_count == 0) return 1;
    const value = (@as(u32, 1) << @intCast(bit_count)) + try reader.read(bit_count);
    assert(value <= 255);
    return value;
}

fn read_window_bits(reader: *BitReader) Error!u32 {
    if (try reader.read(1) == 0) return 16;
    const high = try reader.read(3);
    if (high != 0) return 17 + high;
    const low = try reader.read(3);
    // low == 1 selects the large-window extension, which RFC 7932 streams never use.
    if (low == 1) return error.InvalidData;
    if (low != 0) return 8 + low;
    return 17;
}

/// Decoding state that lives for the whole stream.
const Stream = struct {
    decoder: *Decoder,
    reader: BitReader,
    sink: *Sink,
    max_backward_distance: u32,
    /// Last four distances, most recent first (RFC 7932 section 4).
    distances: [4]u32 = .{ 4, 11, 15, 16 },
};

const MetaBlockKind = enum { empty_last, metadata, uncompressed, compressed };

const MetaBlockHeader = struct {
    last: bool,
    kind: MetaBlockKind,
    length: u32,
};

/// Decodes one meta-block. Returns whether it was the last one.
fn decode_meta_block(stream: *Stream) Error!bool {
    const reader = &stream.reader;
    const stats = &stream.decoder.stats;
    const header = try read_meta_block_header(reader);
    switch (header.kind) {
        .empty_last => assert(header.last),
        .metadata => {
            stats.meta_blocks_metadata += 1;
            try reader.align_to_byte();
            try reader.read_bytes(null, header.length);
        },
        .uncompressed => {
            assert(!header.last);
            stats.meta_blocks_uncompressed += 1;
            try reader.align_to_byte();
            const sink = stream.sink;
            const room = try sink.reserve(header.length);
            try reader.read_bytes(sink.buffer[sink.len..][0..room], room);
            sink.len += room;
            if (room < header.length) return error.OutputLimitExceeded;
        },
        .compressed => {
            assert(header.length > 0);
            stats.meta_blocks_compressed += 1;
            try decode_compressed(stream, header.length);
        },
    }
    return header.last;
}

fn read_meta_block_header(reader: *BitReader) Error!MetaBlockHeader {
    const last = try reader.read(1) == 1;
    if (last and try reader.read(1) == 1) {
        return .{ .last = true, .kind = .empty_last, .length = 0 };
    }
    const nibbles_code = try reader.read(2);
    if (nibbles_code == 3) return read_metadata_header(reader, last);
    const nibbles = nibbles_code + 4;
    var length: u32 = 0;
    for (0..nibbles) |i| {
        const nibble = try reader.read(4);
        if (i + 1 == nibbles and nibbles > 4 and nibble == 0) return error.InvalidData;
        length |= nibble << @intCast(4 * i);
    }
    length += 1;
    assert(length <= 1 << 24);
    const uncompressed = !last and try reader.read(1) == 1;
    const kind: MetaBlockKind = if (uncompressed) .uncompressed else .compressed;
    return .{ .last = last, .kind = kind, .length = length };
}

fn read_metadata_header(reader: *BitReader, last: bool) Error!MetaBlockHeader {
    if (try reader.read(1) != 0) return error.InvalidData;
    const byte_count = try reader.read(2);
    var length: u32 = 0;
    if (byte_count != 0) {
        for (0..byte_count) |i| {
            const byte = try reader.read(8);
            if (i + 1 == byte_count and byte_count > 1 and byte == 0) return error.InvalidData;
            length |= byte << @intCast(8 * i);
        }
        length += 1;
    }
    assert(length <= 1 << 24);
    return .{ .last = last, .kind = .metadata, .length = length };
}

const Category = enum(u2) { literal = 0, insert_copy = 1, distance = 2 };

/// Block-switching state of one category (RFC 7932 section 6).
const BlockState = struct {
    type_count: u32,
    current: u32 = 0,
    /// The second-to-last block type; RFC 7932 starts it at 1.
    previous: u32 = 1,
    remaining: u32,
};

/// Decoding state that lives for one compressed meta-block.
const MetaBlock = struct {
    remaining: u32,
    blocks: [3]BlockState,
    postfix_bits: u32,
    direct_count: u32,
};

fn decode_compressed(stream: *Stream, length: u32) Error!void {
    const decoder = stream.decoder;
    const reader = &stream.reader;
    var meta: MetaBlock = .{
        .remaining = length,
        .blocks = undefined,
        .postfix_bits = 0,
        .direct_count = 0,
    };
    for (&meta.blocks, 0..) |*block, index| {
        block.* = try read_block_header(decoder, reader, @fromBackingInt(@intCast(index)));
    }
    meta.postfix_bits = try reader.read(2);
    meta.direct_count = try reader.read(4) << @intCast(meta.postfix_bits);
    assert(meta.direct_count <= direct_distance_codes_max);
    const literal_types = meta.blocks[@backingInt(Category.literal)].type_count;
    for (decoder.context_modes[0..literal_types]) |*mode| mode.* = @intCast(try reader.read(2));
    const literal_trees = try read_var_len_u8(reader) + 1;
    const literal_map = decoder.literal_context_map[0 .. literal_types * literal_contexts];
    try read_context_map(decoder, reader, literal_map, literal_trees);
    const distance_types = meta.blocks[@backingInt(Category.distance)].type_count;
    const distance_trees = try read_var_len_u8(reader) + 1;
    const distance_map = decoder.distance_context_map[0 .. distance_types * distance_contexts];
    try read_context_map(decoder, reader, distance_map, distance_trees);
    for (decoder.literal_trees[0..literal_trees]) |*tree| {
        try read_prefix_code(decoder, reader, tree.table(), literal_alphabet_size);
    }
    const insert_copy_types = meta.blocks[@backingInt(Category.insert_copy)].type_count;
    for (decoder.insert_copy_trees[0..insert_copy_types]) |*tree| {
        try read_prefix_code(decoder, reader, tree.table(), insert_copy_alphabet_size);
    }
    const postfix_codes = @as(u32, 48) << @intCast(meta.postfix_bits);
    const distance_alphabet = 16 + meta.direct_count + postfix_codes;
    assert(distance_alphabet <= distance_alphabet_max);
    for (decoder.distance_trees[0..distance_trees]) |*tree| {
        try read_prefix_code(decoder, reader, tree.table(), distance_alphabet);
    }
    record_meta_block_stats(decoder, literal_types, literal_trees, distance_trees);
    try decode_commands(stream, &meta);
}

fn record_meta_block_stats(
    decoder: *Decoder,
    literal_types: u32,
    literal_trees: u32,
    distance_trees: u32,
) void {
    assert(literal_trees >= 1 and literal_trees <= trees_max);
    assert(distance_trees >= 1 and distance_trees <= trees_max);
    const stats = &decoder.stats;
    stats.literal_trees_max = @max(stats.literal_trees_max, literal_trees);
    stats.distance_trees_max = @max(stats.distance_trees_max, distance_trees);
    if (literal_trees < 2) return;
    for (decoder.context_modes[0..literal_types]) |mode| {
        stats.context_modes_used |= @as(u4, 1) << mode;
    }
}

fn read_block_header(decoder: *Decoder, reader: *BitReader, category: Category) Error!BlockState {
    const type_count = try read_var_len_u8(reader) + 1;
    assert(type_count >= 1 and type_count <= block_types_max);
    if (type_count < 2) return .{ .type_count = 1, .remaining = block_length_unbounded };
    const index = @backingInt(category);
    const type_table = decoder.block_type_trees[index].table();
    try read_prefix_code(decoder, reader, type_table, type_count + 2);
    const count_table = decoder.block_count_trees[index].table();
    try read_prefix_code(decoder, reader, count_table, block_count_alphabet_size);
    const remaining = try read_block_count(reader, count_table);
    return .{ .type_count = type_count, .remaining = remaining };
}

const block_count_base = [block_count_alphabet_size]u32{
    1,   5,   9,   13,  17,  25,  33,  41,  49,   65,   81,   97,   113,
    145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625,
};
const block_count_extra = [block_count_alphabet_size]u8{
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
};

comptime {
    for (0..block_count_alphabet_size - 1) |i| {
        assert(block_count_base[i + 1] == block_count_base[i] + (1 << block_count_extra[i]));
    }
    assert(block_count_base[25] + (1 << block_count_extra[25]) - 1 == block_length_max);
}

fn read_block_count(reader: *BitReader, table: Table) Error!u32 {
    const symbol = try table_decode(table, reader);
    assert(symbol < block_count_alphabet_size);
    const count = block_count_base[symbol] + try reader.read(block_count_extra[symbol]);
    assert(count >= 1 and count <= block_length_max);
    return count;
}

/// Reads a context map (RFC 7932 section 7.3) whose entries index `tree_count` trees.
fn read_context_map(
    decoder: *Decoder,
    reader: *BitReader,
    map: []u8,
    tree_count: u32,
) Error!void {
    assert(tree_count >= 1 and tree_count <= trees_max);
    assert(map.len > 0);
    if (tree_count == 1) {
        @memset(map, 0);
        return;
    }
    var run_length_prefix_count: u32 = 0;
    if (try reader.read(1) == 1) run_length_prefix_count = try reader.read(4) + 1;
    const table = decoder.context_map_tree.table();
    try read_prefix_code(decoder, reader, table, tree_count + run_length_prefix_count);
    var index: usize = 0;
    // Every iteration fills at least one entry.
    for (0..map.len) |_| {
        if (index >= map.len) break;
        const code = try table_decode(table, reader);
        if (code == 0) {
            map[index] = 0;
            index += 1;
        } else if (code <= run_length_prefix_count) {
            const run = (@as(u32, 1) << @intCast(code)) + try reader.read(code);
            if (run > map.len - index) return error.InvalidData;
            @memset(map[index..][0..run], 0);
            index += run;
        } else {
            map[index] = @intCast(code - run_length_prefix_count);
            index += 1;
        }
    }
    assert(index == map.len);
    if (try reader.read(1) == 1) inverse_move_to_front(map);
    for (map) |entry| assert(entry < tree_count);
}

fn inverse_move_to_front(map: []u8) void {
    var order: [256]u8 = undefined;
    for (&order, 0..) |*entry, i| entry.* = @intCast(i);
    for (map) |*entry| {
        const index = entry.*;
        const value = order[index];
        entry.* = value;
        std.mem.copyBackwards(u8, order[1 .. @as(usize, index) + 1], order[0..index]);
        order[0] = value;
    }
}

/// Upper bound on commands in one meta-block. A command either outputs a byte, consumes an
/// input bit, or (for zero-length dictionary words) only counts down the insert-and-copy block,
/// whose switch consumes input bits again.
fn commands_max(meta: *const MetaBlock, reader: *const BitReader) u64 {
    const input_bits: u64 = @as(u64, reader.input.len) * 8;
    return (meta.remaining + input_bits + 1) *| (block_length_max + 1);
}

fn decode_commands(stream: *Stream, meta: *MetaBlock) Error!void {
    assert(meta.remaining > 0);
    const bound = commands_max(meta, &stream.reader);
    var commands: u64 = 0;
    while (meta.remaining > 0) : (commands += 1) {
        if (commands >= bound) return error.InvalidData;
        try decode_command(stream, meta);
    }
    assert(meta.remaining == 0);
}

// Insert-and-copy length code cells (RFC 7932 section 5), indexed by `symbol >> 6`.
const insert_cell_base = [11]u8{ 0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16 };
const copy_cell_base = [11]u8{ 0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16 };
const insert_length_base = [24]u32{
    0,  1,  2,  3,  4,   5,   6,   8,   10,   14,   18,   26,
    34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594,
};
const insert_length_extra = [24]u8{
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
};
const copy_length_base = [24]u32{
    2,  3,  4,  5,  6,  7,   8,   9,   10,  12,  14,   18,
    22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
};
const copy_length_extra = [24]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
};

comptime {
    for (0..23) |i| {
        assert(insert_length_base[i + 1] == insert_length_base[i] + (1 << insert_length_extra[i]));
        assert(copy_length_base[i + 1] == copy_length_base[i] + (1 << copy_length_extra[i]));
    }
}

fn decode_command(stream: *Stream, meta: *MetaBlock) Error!void {
    const decoder = stream.decoder;
    const reader = &stream.reader;
    const insert_copy_type = try next_block_type(stream, meta, .insert_copy);
    const table = decoder.insert_copy_trees[insert_copy_type].table();
    const symbol = try table_decode(table, reader);
    assert(symbol < insert_copy_alphabet_size);
    const cell = symbol >> 6;
    const insert_code = insert_cell_base[cell] + ((symbol >> 3) & 7);
    const copy_code = copy_cell_base[cell] + (symbol & 7);
    const insert_extra = try reader.read(insert_length_extra[insert_code]);
    const insert_length = insert_length_base[insert_code] + insert_extra;
    const copy_length = copy_length_base[copy_code] + try reader.read(copy_length_extra[copy_code]);
    assert(copy_length >= 2);
    try insert_literals(stream, meta, insert_length);
    if (meta.remaining == 0) return;
    // Symbols below 128 imply distance code 0 (reuse the last distance).
    var distance_code: u32 = 0;
    if (symbol >= 128) distance_code = try read_distance_code(stream, meta, copy_length);
    const distance = try resolve_distance(stream, meta, distance_code);
    try copy_match(stream, meta, distance_code, distance, copy_length);
}

/// Counts down the block of `category`, switching blocks when it runs out. Returns the
/// current block type.
fn next_block_type(stream: *Stream, meta: *MetaBlock, category: Category) Error!u32 {
    const index = @backingInt(category);
    const block = &meta.blocks[index];
    if (block.remaining == 0) {
        // A single-type category gets 2^24 commands; past that the stream is malformed.
        if (block.type_count < 2) return error.InvalidData;
        const decoder = stream.decoder;
        const type_table = decoder.block_type_trees[index].table();
        const code = try table_decode(type_table, &stream.reader);
        var next: u32 = switch (code) {
            0 => block.previous,
            1 => block.current + 1,
            else => code - 2,
        };
        if (next >= block.type_count) next -= block.type_count;
        assert(next < block.type_count);
        block.previous = block.current;
        block.current = next;
        const count_table = decoder.block_count_trees[index].table();
        block.remaining = try read_block_count(&stream.reader, count_table);
        decoder.stats.block_switches += 1;
    }
    assert(block.remaining > 0);
    block.remaining -= 1;
    return block.current;
}

fn insert_literals(stream: *Stream, meta: *MetaBlock, insert_length: u32) Error!void {
    if (insert_length > meta.remaining) return error.InvalidData;
    const decoder = stream.decoder;
    const sink = stream.sink;
    const room = try sink.reserve(insert_length);
    assert(room <= insert_length);
    var p1 = sink.last_byte(1);
    var p2 = sink.last_byte(2);
    for (0..room) |_| {
        const literal_type = try next_block_type(stream, meta, .literal);
        const context = literal_context(decoder.context_modes[literal_type], p1, p2);
        const tree = decoder.literal_context_map[literal_type * literal_contexts + context];
        const literal = try table_decode(decoder.literal_trees[tree].table(), &stream.reader);
        assert(literal < literal_alphabet_size);
        p2 = p1;
        p1 = @intCast(literal);
        sink.buffer[sink.len] = p1;
        sink.len += 1;
    }
    meta.remaining -= @intCast(room);
    if (room < insert_length) return error.OutputLimitExceeded;
}

/// Literal context id (RFC 7932 section 7.1) from the previous two output bytes.
fn literal_context(mode: u2, p1: u8, p2: u8) u32 {
    const context: u32 = switch (mode) {
        0 => p1 & 0x3f,
        1 => p1 >> 2,
        2 => context_lut_utf8_p1[p1] | context_lut_utf8_p2[p2],
        3 => (@as(u32, context_lut_signed[p1]) << 3) | context_lut_signed[p2],
    };
    assert(context < literal_contexts);
    return context;
}

fn read_distance_code(stream: *Stream, meta: *MetaBlock, copy_length: u32) Error!u32 {
    assert(copy_length >= 2);
    const decoder = stream.decoder;
    const distance_type = try next_block_type(stream, meta, .distance);
    const context: u32 = if (copy_length > 4) 3 else copy_length - 2;
    const tree = decoder.distance_context_map[distance_type * distance_contexts + context];
    const code = try table_decode(decoder.distance_trees[tree].table(), &stream.reader);
    assert(code < distance_alphabet_max);
    return code;
}

/// Maps a distance code to a distance (RFC 7932 section 4).
fn resolve_distance(stream: *Stream, meta: *const MetaBlock, code: u32) Error!u64 {
    const distances = stream.distances;
    if (code < 4) return distances[code];
    if (code < 16) {
        const deltas = [6]i64{ -1, 1, -2, 2, -3, 3 };
        const base: i64 = if (code < 10) distances[0] else distances[1];
        const distance = base + deltas[(code - 4) % 6];
        if (distance <= 0) return error.InvalidData;
        return @intCast(distance);
    }
    if (code < 16 + meta.direct_count) return code - 15;
    const postfix_bits: u6 = @intCast(meta.postfix_bits);
    const code_offset: u64 = code - meta.direct_count - 16;
    const extra_bits: u32 = @intCast(1 + (code_offset >> (postfix_bits + 1)));
    assert(extra_bits <= 24);
    const extra = try stream.reader.read(extra_bits);
    const high = code_offset >> postfix_bits;
    const low = code_offset & ((@as(u64, 1) << postfix_bits) - 1);
    const offset = ((2 + (high & 1)) << @intCast(extra_bits)) - 4;
    return ((offset + extra) << postfix_bits) + low + meta.direct_count + 1;
}

fn copy_match(
    stream: *Stream,
    meta: *MetaBlock,
    distance_code: u32,
    distance: u64,
    copy_length: u32,
) Error!void {
    assert(distance > 0);
    const sink = stream.sink;
    const max_distance = @min(sink.len, stream.max_backward_distance);
    if (distance > max_distance) {
        if (distance > max_allowed_distance) return error.InvalidData;
        return copy_dictionary_word(stream, meta, distance - max_distance - 1, copy_length);
    }
    // Distance code 0 reuses the last distance and leaves the history unchanged.
    if (distance_code != 0) {
        const d = stream.distances;
        stream.distances = .{ @intCast(distance), d[0], d[1], d[2] };
    }
    if (copy_length > meta.remaining) return error.InvalidData;
    const room = try sink.reserve(copy_length);
    assert(room <= copy_length);
    const source = sink.len - @as(usize, @intCast(distance));
    if (distance >= room) {
        @memcpy(sink.buffer[sink.len..][0..room], sink.buffer[source..][0..room]);
    } else {
        // Overlapping copy: later bytes repeat earlier output, so copy forward one at a time.
        for (0..room) |i| sink.buffer[sink.len + i] = sink.buffer[source + i];
    }
    sink.len += room;
    meta.remaining -= @intCast(room);
    if (room < copy_length) return error.OutputLimitExceeded;
}

const dictionary_size_bits_by_length = [word_length_max + 1]u8{
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5,
};

const dictionary_offsets_by_length: [word_length_max + 2]u32 = offsets: {
    var offsets: [word_length_max + 2]u32 = @splat(0);
    for (word_length_min..word_length_max + 1) |length| {
        const words: u32 = 1 << dictionary_size_bits_by_length[length];
        offsets[length + 1] = offsets[length] + words * length;
    }
    break :offsets offsets;
};

comptime {
    assert(dictionary_offsets_by_length[word_length_max + 1] == dictionary_size_bytes);
}

fn copy_dictionary_word(stream: *Stream, meta: *MetaBlock, word_id: u64, length: u32) Error!void {
    if (length < word_length_min or length > word_length_max) return error.InvalidData;
    const size_bits: u6 = @intCast(dictionary_size_bits_by_length[length]);
    assert(size_bits >= 5);
    const word_index = word_id & ((@as(u64, 1) << size_bits) - 1);
    const transform_id = word_id >> size_bits;
    if (transform_id >= transform_count) return error.InvalidData;
    const offset = dictionary_offsets_by_length[length] + word_index * length;
    assert(offset + length <= dictionary_size_bytes);
    const word = dictionary[@intCast(offset)..][0..length];
    var buffer: [transformed_word_max_bytes]u8 = undefined;
    const transformed = transform_word(&buffer, word, transforms[@intCast(transform_id)]);
    stream.decoder.stats.dictionary_references += 1;
    if (transform_id != 0) stream.decoder.stats.transformed_references += 1;
    if (transformed.len > meta.remaining) return error.InvalidData;
    const sink = stream.sink;
    const room = try sink.reserve(transformed.len);
    @memcpy(sink.buffer[sink.len..][0..room], transformed[0..room]);
    sink.len += room;
    meta.remaining -= @intCast(room);
    if (room < transformed.len) return error.OutputLimitExceeded;
}

/// Elementary word transforms (RFC 7932 appendix B), numbered as in the RFC check value.
const TransformKind = enum(u8) {
    identity = 0,
    ferment_first = 1,
    ferment_all = 2,
    omit_first_1 = 3,
    omit_first_2 = 4,
    omit_first_3 = 5,
    omit_first_4 = 6,
    omit_first_5 = 7,
    omit_first_6 = 8,
    omit_first_7 = 9,
    omit_first_8 = 10,
    omit_first_9 = 11,
    omit_last_1 = 12,
    omit_last_2 = 13,
    omit_last_3 = 14,
    omit_last_4 = 15,
    omit_last_5 = 16,
    omit_last_6 = 17,
    omit_last_7 = 18,
    omit_last_8 = 19,
    omit_last_9 = 20,
};

const Transform = struct {
    prefix: []const u8,
    kind: TransformKind,
    suffix: []const u8,
};

fn transform_word(
    buffer: *[transformed_word_max_bytes]u8,
    word: []const u8,
    transform: Transform,
) []u8 {
    assert(word.len >= word_length_min and word.len <= word_length_max);
    assert(transform.prefix.len + word.len + transform.suffix.len <= buffer.len);
    var length: usize = 0;
    @memcpy(buffer[0..transform.prefix.len], transform.prefix);
    length += transform.prefix.len;
    const kind = @backingInt(transform.kind);
    var body = word;
    if (kind >= 3 and kind <= 11) body = word[@min(kind - 2, word.len)..];
    if (kind >= 12) body = word[0 .. word.len - @min(kind - 11, word.len)];
    const fermented = buffer[length..][0..body.len];
    @memcpy(fermented, body);
    length += body.len;
    if (transform.kind == .ferment_first and fermented.len > 0) _ = ferment(fermented, 0);
    if (transform.kind == .ferment_all) {
        var position: usize = 0;
        // Every step advances by one to three bytes.
        for (0..fermented.len) |_| {
            if (position >= fermented.len) break;
            position += ferment(fermented, position);
        }
    }
    @memcpy(buffer[length..][0..transform.suffix.len], transform.suffix);
    length += transform.suffix.len;
    assert(length <= buffer.len);
    return buffer[0..length];
}

/// Upper-cases one UTF-8 sequence the way RFC 7932 section 8 defines it. Returns its length.
fn ferment(word: []u8, position: usize) usize {
    assert(position < word.len);
    const byte = word[position];
    if (byte < 192) {
        if (byte >= 'a' and byte <= 'z') word[position] ^= 32;
        return 1;
    }
    if (byte < 224) {
        if (position + 1 < word.len) word[position + 1] ^= 32;
        return 2;
    }
    if (position + 2 < word.len) word[position + 2] ^= 5;
    return 3;
}

// Context lookup tables (RFC 7932 section 7.1: Lut0, Lut1, Lut2).
const context_lut_utf8_p1 = [256]u8{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    8,  12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
};
const context_lut_utf8_p2 = [256]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};
const context_lut_signed = [256]u8{
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
};

// Word transforms (RFC 7932 appendix B).
const transforms = [_]Transform{
    .{ .prefix = "", .kind = .identity, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = " " },
    .{ .prefix = " ", .kind = .identity, .suffix = " " },
    .{ .prefix = "", .kind = .omit_first_1, .suffix = "" },
    .{ .prefix = "", .kind = .ferment_first, .suffix = " " },
    .{ .prefix = "", .kind = .identity, .suffix = " the " },
    .{ .prefix = " ", .kind = .identity, .suffix = "" },
    .{ .prefix = "s ", .kind = .identity, .suffix = " " },
    .{ .prefix = "", .kind = .identity, .suffix = " of " },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = " and " },
    .{ .prefix = "", .kind = .omit_first_2, .suffix = "" },
    .{ .prefix = "", .kind = .omit_last_1, .suffix = "" },
    .{ .prefix = ", ", .kind = .identity, .suffix = " " },
    .{ .prefix = "", .kind = .identity, .suffix = ", " },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = " " },
    .{ .prefix = "", .kind = .identity, .suffix = " in " },
    .{ .prefix = "", .kind = .identity, .suffix = " to " },
    .{ .prefix = "e ", .kind = .identity, .suffix = " " },
    .{ .prefix = "", .kind = .identity, .suffix = "\x22" },
    .{ .prefix = "", .kind = .identity, .suffix = "." },
    .{ .prefix = "", .kind = .identity, .suffix = "\x22>" },
    .{ .prefix = "", .kind = .identity, .suffix = "\x0a" },
    .{ .prefix = "", .kind = .omit_last_3, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = "]" },
    .{ .prefix = "", .kind = .identity, .suffix = " for " },
    .{ .prefix = "", .kind = .omit_first_3, .suffix = "" },
    .{ .prefix = "", .kind = .omit_last_2, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = " a " },
    .{ .prefix = "", .kind = .identity, .suffix = " that " },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = ". " },
    .{ .prefix = ".", .kind = .identity, .suffix = "" },
    .{ .prefix = " ", .kind = .identity, .suffix = ", " },
    .{ .prefix = "", .kind = .omit_first_4, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = " with " },
    .{ .prefix = "", .kind = .identity, .suffix = "'" },
    .{ .prefix = "", .kind = .identity, .suffix = " from " },
    .{ .prefix = "", .kind = .identity, .suffix = " by " },
    .{ .prefix = "", .kind = .omit_first_5, .suffix = "" },
    .{ .prefix = "", .kind = .omit_first_6, .suffix = "" },
    .{ .prefix = " the ", .kind = .identity, .suffix = "" },
    .{ .prefix = "", .kind = .omit_last_4, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = ". The " },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = " on " },
    .{ .prefix = "", .kind = .identity, .suffix = " as " },
    .{ .prefix = "", .kind = .identity, .suffix = " is " },
    .{ .prefix = "", .kind = .omit_last_7, .suffix = "" },
    .{ .prefix = "", .kind = .omit_last_1, .suffix = "ing " },
    .{ .prefix = "", .kind = .identity, .suffix = "\x0a\x09" },
    .{ .prefix = "", .kind = .identity, .suffix = ":" },
    .{ .prefix = " ", .kind = .identity, .suffix = ". " },
    .{ .prefix = "", .kind = .identity, .suffix = "ed " },
    .{ .prefix = "", .kind = .omit_first_9, .suffix = "" },
    .{ .prefix = "", .kind = .omit_first_7, .suffix = "" },
    .{ .prefix = "", .kind = .omit_last_6, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = "(" },
    .{ .prefix = "", .kind = .ferment_first, .suffix = ", " },
    .{ .prefix = "", .kind = .omit_last_8, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = " at " },
    .{ .prefix = "", .kind = .identity, .suffix = "ly " },
    .{ .prefix = " the ", .kind = .identity, .suffix = " of " },
    .{ .prefix = "", .kind = .omit_last_5, .suffix = "" },
    .{ .prefix = "", .kind = .omit_last_9, .suffix = "" },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = ", " },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "\x22" },
    .{ .prefix = ".", .kind = .identity, .suffix = "(" },
    .{ .prefix = "", .kind = .ferment_all, .suffix = " " },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "\x22>" },
    .{ .prefix = "", .kind = .identity, .suffix = "=\x22" },
    .{ .prefix = " ", .kind = .identity, .suffix = "." },
    .{ .prefix = ".com/", .kind = .identity, .suffix = "" },
    .{ .prefix = " the ", .kind = .identity, .suffix = " of the " },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "'" },
    .{ .prefix = "", .kind = .identity, .suffix = ". This " },
    .{ .prefix = "", .kind = .identity, .suffix = "," },
    .{ .prefix = ".", .kind = .identity, .suffix = " " },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "(" },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "." },
    .{ .prefix = "", .kind = .identity, .suffix = " not " },
    .{ .prefix = " ", .kind = .identity, .suffix = "=\x22" },
    .{ .prefix = "", .kind = .identity, .suffix = "er " },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = " " },
    .{ .prefix = "", .kind = .identity, .suffix = "al " },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = "" },
    .{ .prefix = "", .kind = .identity, .suffix = "='" },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "\x22" },
    .{ .prefix = "", .kind = .ferment_first, .suffix = ". " },
    .{ .prefix = " ", .kind = .identity, .suffix = "(" },
    .{ .prefix = "", .kind = .identity, .suffix = "ful " },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = ". " },
    .{ .prefix = "", .kind = .identity, .suffix = "ive " },
    .{ .prefix = "", .kind = .identity, .suffix = "less " },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "'" },
    .{ .prefix = "", .kind = .identity, .suffix = "est " },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = "." },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "\x22>" },
    .{ .prefix = " ", .kind = .identity, .suffix = "='" },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "," },
    .{ .prefix = "", .kind = .identity, .suffix = "ize " },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "." },
    .{ .prefix = "\xc2\xa0", .kind = .identity, .suffix = "" },
    .{ .prefix = " ", .kind = .identity, .suffix = "," },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "=\x22" },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "=\x22" },
    .{ .prefix = "", .kind = .identity, .suffix = "ous " },
    .{ .prefix = "", .kind = .ferment_all, .suffix = ", " },
    .{ .prefix = "", .kind = .ferment_first, .suffix = "='" },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = "," },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = "=\x22" },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = ", " },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "," },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "(" },
    .{ .prefix = "", .kind = .ferment_all, .suffix = ". " },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = "." },
    .{ .prefix = "", .kind = .ferment_all, .suffix = "='" },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = ". " },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = "=\x22" },
    .{ .prefix = " ", .kind = .ferment_all, .suffix = "='" },
    .{ .prefix = " ", .kind = .ferment_first, .suffix = "='" },
};

// Tests.
//
// Vector sources (all public): `*.compressed*` files are from the google/brotli repository,
// `tests/testdata/`; their expected outputs are the matching uncompressed files there, recorded
// here by length and SHA-256. The `*.br` files were generated with the brotli 1.2.0 CLI from
// prefixes of the same public corpus:
//   head -c 3000 alice29.txt > alice_3k.txt
//   brotli -q 11 -w 10 -c alice_3k.txt > alice_3k_q11_w10.br
//   brotli -q 5 -w 18 -c alice_3k.txt > alice_3k_q5_w18.br
//   brotli -q 1 -c alice_3k.txt > alice_3k_q1.br
//   head -c 2000 random_org_10k.bin > random_2k.bin
//   brotli -q 11 -c random_2k.bin > random_2k_q11.br
//   { head -c 2000 alice29.txt; head -c 2000 mapsdatazrh; head -c 2000 cp1251-utf16le;
//     tail -c 2000 alice29.txt; } > mixed.bin
//   brotli -q 11 -c mixed.bin > mixed_q11.br

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const Sha256 = std.crypto.hash.sha2.Sha256;

const Vector = struct {
    file: []const u8,
    size_bytes: usize,
    sha256: []const u8,
};

const vectors = [_]Vector{
    .{
        .file = "mixed_q11.br",
        .size_bytes = 7554,
        .sha256 = "67475a4c62b894810d4659ee1afe2f73f0cc4cc4d7913086553db34b711172c9",
    },
    .{
        .file = "10x10y.compressed",
        .size_bytes = 20,
        .sha256 = "41bd4c895e9fb36d74bc97db5092872a24267e3b0455ff6152b0d262faa00d49",
    },
    .{
        .file = "64x.compressed",
        .size_bytes = 64,
        .sha256 = "be4d3ed1fc5f5cfa00735b28605a975f3293fa235d23abb1d9dea380fba0fb87",
    },
    .{
        .file = "alice_3k_q1.br",
        .size_bytes = 3000,
        .sha256 = "bda958b8379523f138e8c626a2c6e1881e6329e0a5425d0a177a1f9f23c78ad3",
    },
    .{
        .file = "alice_3k_q11_w10.br",
        .size_bytes = 3000,
        .sha256 = "bda958b8379523f138e8c626a2c6e1881e6329e0a5425d0a177a1f9f23c78ad3",
    },
    .{
        .file = "alice_3k_q5_w18.br",
        .size_bytes = 3000,
        .sha256 = "bda958b8379523f138e8c626a2c6e1881e6329e0a5425d0a177a1f9f23c78ad3",
    },
    .{
        .file = "backward65536.compressed",
        .size_bytes = 65792,
        .sha256 = "a6dbac2165542001c574fe1d5ed6ca646203660c228cac57b47a9fec68c20217",
    },
    .{
        .file = "cp1251-utf16le.compressed",
        .size_bytes = 1554,
        .sha256 = "0817dfe4fe7b6e29e63bbb048a785f7cbe67dc3188f96df5b5bc69826ca2a6e6",
    },
    .{
        .file = "cp852-utf8.compressed",
        .size_bytes = 706,
        .sha256 = "37465d3004d504c3d4320de2f821fa42f79a10917421cf1872ace46cfb152c42",
    },
    .{
        .file = "empty.compressed",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.00",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.01",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.02",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.03",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.04",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.05",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.06",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.07",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.08",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.09",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.10",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.11",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.12",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.13",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.14",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.15",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "empty.compressed.16",
        .size_bytes = 0,
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    .{
        .file = "monkey.compressed",
        .size_bytes = 843,
        .sha256 = "937ad127fe0e373e0e267d11905f2bca154f40fe6fd438b6ddcce40de2ddcd99",
    },
    .{
        .file = "quickfox.compressed",
        .size_bytes = 43,
        .sha256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    },
    .{
        .file = "quickfox_repeated.compressed",
        .size_bytes = 176128,
        .sha256 = "254fdc641d1a65d0b1e427e4b0a1e16a96a5242adb98af71833782ba99c3dd82",
    },
    .{
        .file = "random_2k_q11.br",
        .size_bytes = 2000,
        .sha256 = "5b1826f893e70c446fc76216f83f12b1ec8dca01c283374066b70f24b014c684",
    },
    .{
        .file = "ukkonooa.compressed",
        .size_bytes = 119,
        .sha256 = "1fb2529b0c6fbf80a60d2bb4c20efba2fff6cecb0c52d42693d404501064f407",
    },
    .{
        .file = "x.compressed",
        .size_bytes = 1,
        .sha256 = "4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015",
    },
    .{
        .file = "x.compressed.00",
        .size_bytes = 1,
        .sha256 = "4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015",
    },
    .{
        .file = "x.compressed.01",
        .size_bytes = 1,
        .sha256 = "4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015",
    },
    .{
        .file = "x.compressed.02",
        .size_bytes = 1,
        .sha256 = "4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015",
    },
    .{
        .file = "x.compressed.03",
        .size_bytes = 1,
        .sha256 = "4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015",
    },
    .{
        .file = "xyzzy.compressed",
        .size_bytes = 5,
        .sha256 = "7609128715518308672067aab169e24944ead24e3d732aab8a8f0b7013a65564",
    },
    .{
        .file = "zeros.compressed",
        .size_bytes = 262144,
        .sha256 = "8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90",
    },
    .{
        .file = "zerosukkanooa.compressed",
        .size_bytes = 262263,
        .sha256 = "3f54e9caa8aa46d5eafde978d92ab5ebff42bac1396327320430c3b02fdcb77a",
    },
};

const corpus: [vectors.len][]const u8 = corpus: {
    var list: [vectors.len][]const u8 = undefined;
    for (vectors, 0..) |vector, i| list[i] = @embedFile("testdata/brotli/" ++ vector.file);
    break :corpus list;
};

fn vector_compressed(name: []const u8) []const u8 {
    for (vectors, 0..) |vector, i| {
        if (std.mem.eql(u8, vector.file, name)) return corpus[i];
    }
    unreachable; // Tests only ask for vectors in the table.
}

fn expect_sha256(expected_hex: []const u8, data: []const u8) !void {
    var expected: [Sha256.digest_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "brotli: public vectors decode to the expected output" {
    for (vectors, corpus) |vector, compressed| {
        const output = try decompress(testing.allocator, compressed, vector.size_bytes);
        defer testing.allocator.free(output);
        try testing.expectEqual(vector.size_bytes, output.len);
        try expect_sha256(vector.sha256, output);
        if (vector.size_bytes == 0) continue;
        const short = decompress(testing.allocator, compressed, vector.size_bytes - 1);
        try testing.expectError(error.OutputLimitExceeded, short);
    }
}

test "brotli: decompress_into truncates at the buffer and keeps the prefix" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    const monkey = vector_compressed("monkey.compressed");
    const full = try decompress(testing.allocator, monkey, 1 << 20);
    defer testing.allocator.free(full);
    var buffer: [1024]u8 = undefined;
    for ([_]usize{ 0, 1, 7, 100, 500, full.len - 1 }) |limit| {
        const result = decoder.decompress_partial(buffer[0..limit], monkey);
        try testing.expectError(error.OutputLimitExceeded, result.status);
        try testing.expectEqualSlices(u8, full[0..limit], result.output);
    }
    const exact = try decompress_into(decoder, buffer[0..full.len], monkey);
    try testing.expectEqualSlices(u8, full, exact);
}

test "brotli: base/base channel vector and truncation" {
    // From base/base `crates/consensus/protocol/src/brotli.rs` tests.
    var compressed: [14]u8 = undefined;
    _ = try std.fmt.hexToBytes(&compressed, "8b048075ed184249e9bc19675e03");
    var expected: [10]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "75ed184249e9bc19675e");
    const output = try decompress(testing.allocator, &compressed, expected.len);
    defer testing.allocator.free(output);
    try testing.expectEqualSlices(u8, &expected, output);
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    var buffer: [5]u8 = undefined;
    const result = decoder.decompress_partial(&buffer, &compressed);
    try testing.expectError(error.OutputLimitExceeded, result.status);
    try testing.expectEqualSlices(u8, expected[0..5], result.output);
}

test "brotli: empty stream" {
    const output = try decompress(testing.allocator, &.{0x06}, 0);
    defer testing.allocator.free(output);
    try testing.expectEqual(@as(usize, 0), output.len);
    try testing.expectError(error.Truncated, decompress(testing.allocator, &.{}, 16));
}

test "brotli: every strict prefix of a valid stream is truncated" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    var buffer: [4096]u8 = undefined;
    const names = [_][]const u8{ "alice_3k_q11_w10.br", "monkey.compressed", "x.compressed.03" };
    for (names) |name| {
        const compressed = vector_compressed(name);
        for (0..compressed.len) |length| {
            const result = decompress_into(decoder, &buffer, compressed[0..length]);
            try testing.expectError(error.Truncated, result);
        }
    }
}

test "brotli: vectors exercise dictionary, transforms, context modeling, block switching" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    var buffer: [8192]u8 = undefined;
    _ = try decoder.decompress_into(&buffer, vector_compressed("alice_3k_q11_w10.br"));
    const stats = decoder.stats;
    try testing.expect(stats.dictionary_references > 0);
    try testing.expect(stats.transformed_references > 0);
    try testing.expect(stats.literal_trees_max > 1);
    try testing.expect(stats.context_modes_used & 0b0100 != 0); // UTF8.
    _ = try decoder.decompress_into(&buffer, vector_compressed("cp1251-utf16le.compressed"));
    try testing.expect(decoder.stats.context_modes_used & 0b1000 != 0); // Signed.
    _ = try decoder.decompress_into(&buffer, vector_compressed("mixed_q11.br"));
    try testing.expect(decoder.stats.block_switches > 0);
    _ = try decoder.decompress_into(&buffer, vector_compressed("ukkonooa.compressed"));
    try testing.expect(decoder.stats.distance_trees_max > 1);
    _ = try decoder.decompress_into(&buffer, vector_compressed("random_2k_q11.br"));
    try testing.expect(decoder.stats.meta_blocks_uncompressed > 0);
}

/// Little-endian bit writer for hand-built streams.
const BitWriter = struct {
    bytes: [64]u8 = @splat(0),
    bit_count: usize = 0,

    fn write(writer: *BitWriter, value: u32, bit_count: u5) void {
        for (0..bit_count) |i| {
            const bit: u8 = @intCast((value >> @intCast(i)) & 1);
            writer.bytes[writer.bit_count / 8] |= bit << @intCast(writer.bit_count % 8);
            writer.bit_count += 1;
        }
    }

    fn align_to_byte(writer: *BitWriter) void {
        writer.bit_count = std.mem.alignForward(usize, writer.bit_count, 8);
    }

    fn write_bytes(writer: *BitWriter, data: []const u8) void {
        writer.align_to_byte();
        for (data) |byte| writer.write(byte, 8);
    }

    fn slice(writer: *const BitWriter) []const u8 {
        return writer.bytes[0 .. (writer.bit_count + 7) / 8];
    }
};

/// Builds a one meta-block stream: literal context `mode`, two literal trees ('a' and 'b',
/// zero bits each) chosen by the context map, four literals, then a copy of two bytes with
/// NPOSTFIX = 1, NDIRECT = 2 and distance code 18 (distance 3).
fn context_mode_stream(mode: u2) BitWriter {
    var writer: BitWriter = .{};
    writer.write(0, 1); // WBITS = 16.
    writer.write(1, 1); // ISLAST.
    writer.write(0, 1); // ISLASTEMPTY = 0.
    writer.write(0, 2); // MNIBBLES = 4.
    writer.write(5, 16); // MLEN - 1 = 5.
    writer.write(0, 3); // NBLTYPESL, NBLTYPESI, NBLTYPESD = 1.
    writer.write(1, 2); // NPOSTFIX = 1.
    writer.write(1, 4); // NDIRECT = 1 << 1.
    writer.write(mode, 2);
    writer.write(1, 1); // NTREESL = 2.
    writer.write(0, 3);
    writer.write(0, 1); // No run-length codes.
    writer.write(1, 2); // Simple prefix code, two symbols: 0 and 1, one bit each.
    writer.write(1, 2);
    writer.write(0, 1);
    writer.write(1, 1);
    for (0..literal_contexts) |context| {
        writer.write(@intFromBool(context == 24 or context == 33), 1);
    }
    writer.write(0, 1); // No inverse move-to-front.
    writer.write(0, 1); // NTREESD = 1.
    for ("ab") |literal| {
        writer.write(1, 2); // Simple prefix code with one symbol.
        writer.write(0, 2);
        writer.write(literal, 8);
    }
    writer.write(1, 2); // Insert-and-copy: one symbol, 160 = insert 4, copy 2, explicit.
    writer.write(0, 2);
    writer.write(160, 10);
    writer.write(1, 2); // Distance: one symbol over 16 + 2 + 96 codes.
    writer.write(0, 2);
    writer.write(18, 7);
    writer.write(0, 1); // Distance extra bit.
    return writer;
}

test "brotli: all four literal context modes and postfix distances" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    // Contexts 24 and 33 select tree 1 ('b'); RFC 7932 section 7.1 gives these sequences.
    const expected = [4][]const u8{ "ababba", "abbbbb", "aaaaaa", "abaaba" };
    for (expected, 0..) |want, mode| {
        var buffer: [16]u8 = undefined;
        const writer = context_mode_stream(@intCast(mode));
        const output = try decoder.decompress_into(&buffer, writer.slice());
        try testing.expectEqualStrings(want, output);
        try testing.expectEqual(@as(u4, 1) << @intCast(mode), decoder.stats.context_modes_used);
    }
}

test "brotli: metadata and uncompressed meta-blocks" {
    var writer: BitWriter = .{};
    writer.write(0, 1); // WBITS = 16.
    writer.write(0, 1); // ISLAST = 0.
    writer.write(3, 2); // MNIBBLES = 0: metadata.
    writer.write(0, 1); // Reserved.
    writer.write(1, 2); // MSKIPBYTES = 1.
    writer.write(2, 8); // MSKIPLEN - 1 = 2.
    writer.write_bytes("xyz");
    writer.write(0, 1); // ISLAST = 0.
    writer.write(0, 2); // MNIBBLES = 4.
    writer.write(4, 16); // MLEN - 1 = 4.
    writer.write(1, 1); // ISUNCOMPRESSED.
    writer.write_bytes("hello");
    writer.write(1, 1); // ISLAST.
    writer.write(1, 1); // ISLASTEMPTY.
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    var buffer: [16]u8 = undefined;
    const output = try decoder.decompress_into(&buffer, writer.slice());
    try testing.expectEqualSlices(u8, "hello", output);
    try testing.expectEqual(@as(u32, 1), decoder.stats.meta_blocks_metadata);
    try testing.expectEqual(@as(u32, 1), decoder.stats.meta_blocks_uncompressed);
    // A set padding bit after the last meta-block is invalid.
    var padded = writer;
    padded.write(1, 1);
    const invalid = decoder.decompress_into(&buffer, padded.slice());
    try testing.expectError(error.InvalidData, invalid);
}

test "brotli: malformed headers" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    var buffer: [16]u8 = undefined;
    // Large-window WBITS escape (1, 000, 001).
    try testing.expectError(error.InvalidData, decoder.decompress_into(&buffer, &.{ 0x11, 0x00 }));
    // Five MLEN nibbles whose last nibble is zero.
    var writer: BitWriter = .{};
    writer.write(0, 1);
    writer.write(0, 1);
    writer.write(1, 2);
    writer.write(0, 20);
    try testing.expectError(error.InvalidData, decoder.decompress_into(&buffer, writer.slice()));
}

test "brotli: word transforms" {
    var buffer: [transformed_word_max_bytes]u8 = undefined;
    try testing.expectEqualStrings("HELLO", transform_word(&buffer, "hello", transforms[44]));
    const of_the = transform_word(&buffer, "time", transforms[73]);
    try testing.expectEqualStrings(" the time of the ", of_the);
    try testing.expectEqualStrings("", transform_word(&buffer, "time", transforms[54]));
    try testing.expectEqualStrings("Time", transform_word(&buffer, "time", transforms[9]));
    try testing.expectEqualStrings("tim", transform_word(&buffer, "time", transforms[12]));
    // UTF-8: a two-byte sequence flips bit 5 of its second byte.
    const utf8 = transform_word(&buffer, "\xc3\xa0bc", transforms[9]);
    try testing.expectEqualStrings("\xc3\x80bc", utf8);
}

test "brotli: static data matches RFC 7932 check values" {
    try testing.expectEqual(@as(u32, 0x5136cb04), std.hash.Crc32.hash(dictionary));
    try expect_sha256(
        "20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70",
        dictionary,
    );
    try testing.expectEqual(@as(u32, 0x8e91efb7), std.hash.Crc32.hash(&context_lut_utf8_p1));
    try testing.expectEqual(@as(u32, 0xd01a32f4), std.hash.Crc32.hash(&context_lut_utf8_p2));
    try testing.expectEqual(@as(u32, 0x0dd7a0d6), std.hash.Crc32.hash(&context_lut_signed));
    // Appendix B: prefix, 0, kind, suffix, 0 for every transform.
    var crc = std.hash.Crc32.init();
    var total_bytes: usize = 0;
    for (transforms) |transform| {
        crc.update(transform.prefix);
        crc.update(&.{ 0, @backingInt(transform.kind) });
        crc.update(transform.suffix);
        crc.update(&.{0});
        total_bytes += transform.prefix.len + transform.suffix.len + 3;
    }
    try testing.expectEqual(@as(usize, 648), total_bytes);
    try testing.expectEqual(@as(u32, 0x3d965f81), crc.final());
}

fn mutate(prng: *Prng, data: []u8, length_start: usize) usize {
    assert(length_start <= data.len);
    var length = length_start;
    const mutations = prng.range(1, 8);
    for (0..mutations) |_| {
        if (length == 0) break;
        const position = prng.below(length);
        switch (prng.below(4)) {
            0 => data[position] ^= @as(u8, 1) << @intCast(prng.below(8)),
            1 => data[position] = prng.int(u8),
            2 => length = position + 1,
            3 => {
                const span = @min(prng.range(1, 16), length - position, data.len - length);
                const tail = data[position..length];
                std.mem.copyBackwards(u8, data[position + span ..][0..tail.len], tail);
                length += span;
            },
            else => unreachable,
        }
    }
    return length;
}

fn check_decode(decoder: *Decoder, input: []const u8, out: []u8) !void {
    const result = decoder.decompress_partial(out, input);
    try testing.expect(result.output.len <= out.len);
    if (result.status) |_| {} else |err| {
        if (err == error.OutputLimitExceeded) try testing.expectEqual(out.len, result.output.len);
    }
}

test "brotli: seeded mutation fuzz" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    var prng = Prng.init(0xb207_1932);
    var input: [4096 + 256]u8 = undefined;
    var output: [8192]u8 = undefined;
    for (0..3000) |_| {
        const source = corpus[prng.below(corpus.len)];
        const source_length = @min(source.len, 4096);
        @memcpy(input[0..source_length], source[0..source_length]);
        const length = mutate(&prng, &input, source_length);
        const limit = prng.below(output.len + 1);
        try check_decode(decoder, input[0..length], output[0..limit]);
    }
}

fn fuzz_decompress(decoder: *Decoder, smith: *testing.Smith) anyerror!void {
    var input: [4096]u8 = undefined;
    var output: [16384]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(decoder, input[0..length], &output);
}

test "brotli: fuzz decompress" {
    const decoder = try testing.allocator.create(Decoder);
    defer testing.allocator.destroy(decoder);
    try testing.fuzz(decoder, fuzz_decompress, .{ .corpus = &corpus });
}

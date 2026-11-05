//! Brotli encoder (RFC 7932) for channel compression: greedy LZ77 over a hash table,
//! then one compressed meta-block with a single block type per category and one
//! prefix code each for literals, insert-and-copy lengths, and distances.
//!
//! Simplifications, all valid brotli: no static dictionary, no last-distance codes
//! (every copy carries an explicit distance; NPOSTFIX = NDIRECT = 0), no context
//! modeling, and code lengths written with literal lengths plus zero-run code 17
//! (never consecutive repeat codes). Output decodes with any brotli decoder; tests
//! round-trip through the consensus decoder that derivation uses.
//!
//! Memory is allocated once in `init` from the configured input cap.

const std = @import("std");
const assert = std.debug.assert;

pub const window_bits = 22;
const window_size_max = (1 << window_bits) - 16;
const meta_block_length_max = 1 << 24;
const match_length_min = 4;
const match_length_max = 1 << 16;
const hash_bits = 16;

const literal_alphabet = 256;
const command_alphabet = 704;
const distance_alphabet = 64;
const code_length_alphabet = 18;
const code_length_max = 15;
const code_length_code_max = 5;

pub const Error = error{OutputTooSmall};

const Command = struct { insert: u32, copy: u32, distance: u32 };

const Range = struct { base: u32, extra: u5 };

const insert_ranges = [24]Range{
    .{ .base = 0, .extra = 0 },     .{ .base = 1, .extra = 0 },
    .{ .base = 2, .extra = 0 },     .{ .base = 3, .extra = 0 },
    .{ .base = 4, .extra = 0 },     .{ .base = 5, .extra = 0 },
    .{ .base = 6, .extra = 1 },     .{ .base = 8, .extra = 1 },
    .{ .base = 10, .extra = 2 },    .{ .base = 14, .extra = 2 },
    .{ .base = 18, .extra = 3 },    .{ .base = 26, .extra = 3 },
    .{ .base = 34, .extra = 4 },    .{ .base = 50, .extra = 4 },
    .{ .base = 66, .extra = 5 },    .{ .base = 98, .extra = 5 },
    .{ .base = 130, .extra = 6 },   .{ .base = 194, .extra = 7 },
    .{ .base = 322, .extra = 8 },   .{ .base = 578, .extra = 9 },
    .{ .base = 1090, .extra = 10 }, .{ .base = 2114, .extra = 12 },
    .{ .base = 6210, .extra = 14 }, .{ .base = 22594, .extra = 24 },
};

const copy_ranges = [24]Range{
    .{ .base = 2, .extra = 0 },     .{ .base = 3, .extra = 0 },
    .{ .base = 4, .extra = 0 },     .{ .base = 5, .extra = 0 },
    .{ .base = 6, .extra = 0 },     .{ .base = 7, .extra = 0 },
    .{ .base = 8, .extra = 0 },     .{ .base = 9, .extra = 0 },
    .{ .base = 10, .extra = 1 },    .{ .base = 12, .extra = 1 },
    .{ .base = 14, .extra = 2 },    .{ .base = 18, .extra = 2 },
    .{ .base = 22, .extra = 3 },    .{ .base = 30, .extra = 3 },
    .{ .base = 38, .extra = 4 },    .{ .base = 54, .extra = 4 },
    .{ .base = 70, .extra = 5 },    .{ .base = 102, .extra = 5 },
    .{ .base = 134, .extra = 6 },   .{ .base = 198, .extra = 7 },
    .{ .base = 326, .extra = 8 },   .{ .base = 582, .extra = 9 },
    .{ .base = 1094, .extra = 10 }, .{ .base = 2118, .extra = 24 },
};

fn range_code(ranges: *const [24]Range, value: u32) u5 {
    var code: u5 = 23;
    while (ranges[code].base > value) code -= 1;
    assert(value - ranges[code].base < (@as(u64, 1) << ranges[code].extra));
    return code;
}

/// Insert-and-copy symbol for explicit distances (RFC 7932 section 5 cell table).
fn command_symbol(insert_code: u5, copy_code: u5) u16 {
    const cell_base: u16 = switch (insert_code >> 3) {
        0 => switch (copy_code >> 3) {
            0 => 128,
            1 => 192,
            else => 384,
        },
        1 => switch (copy_code >> 3) {
            0 => 256,
            1 => 320,
            else => 512,
        },
        else => switch (copy_code >> 3) {
            0 => 448,
            1 => 576,
            else => 640,
        },
    };
    return cell_base + (@as(u16, insert_code & 7) << 3) + (copy_code & 7);
}

/// Distance code and extra bits for NPOSTFIX = NDIRECT = 0.
const DistanceCode = struct { symbol: u16, extra_bits: u5, extra: u32 };

fn distance_code(distance: u32) DistanceCode {
    assert(distance >= 1);
    const x: u32 = distance + 3;
    const top: u5 = @intCast(31 - @clz(x));
    const extra_bits: u5 = top - 1;
    const prefix: u32 = (x >> extra_bits) & 1;
    const hcode: u32 = 2 * (@as(u32, extra_bits) - 1) + prefix;
    const extra = x - ((2 + prefix) << extra_bits);
    return .{ .symbol = @intCast(16 + hcode), .extra_bits = extra_bits, .extra = extra };
}

const BitWriter = struct {
    out: []u8,
    position_bits: u64 = 0,

    fn write(bits: *BitWriter, value: u64, count: u6) Error!void {
        assert(count == 0 or count == 64 or value >> count == 0);
        var remaining = count;
        var data = value;
        while (remaining > 0) {
            const byte_index = bits.position_bits / 8;
            if (byte_index >= bits.out.len) return error.OutputTooSmall;
            const bit_index: u3 = @intCast(bits.position_bits % 8);
            if (bit_index == 0) bits.out[byte_index] = 0;
            const take: u6 = @min(remaining, 8 - @as(u6, bit_index));
            const mask = (@as(u64, 1) << take) - 1;
            bits.out[byte_index] |= @as(u8, @intCast(data & mask)) << bit_index;
            data >>= take;
            remaining -= take;
            bits.position_bits += take;
        }
    }

    fn byte_length(bits: *const BitWriter) usize {
        return @intCast((bits.position_bits + 7) / 8);
    }
};

/// A canonical prefix code: lengths and LSB-first (bit-reversed) code words.
fn PrefixCode(comptime size: usize) type {
    return struct {
        lengths: [size]u4 = @splat(0),
        codes: [size]u16 = @splat(0),
        used: u32 = 0,
        /// The used symbols when `used <= 4` (simple prefix code), in emission order.
        simple: [4]u16 = @splat(0),

        const Self = @This();

        fn build(code: *Self, histogram: *const [size]u32, limit: u4) void {
            huffman_lengths(size, histogram, limit, &code.lengths);
            code.used = 0;
            for (code.lengths) |length| code.used += @intFromBool(length > 0);
            if (code.used == 0) {
                // An unused alphabet still needs a code: one symbol, zero bits.
                code.used = 1;
                code.simple[0] = 0;
                return;
            }
            if (code.used <= 4) code.assign_simple(histogram);
            canonical_codes(size, &code.lengths, &code.codes);
        }

        /// Simple prefix codes fix the lengths by symbol count (RFC 7932 3.4).
        fn assign_simple(code: *Self, histogram: *const [size]u32) void {
            var count: usize = 0;
            for (code.lengths, 0..) |length, symbol| {
                if (length == 0) continue;
                code.simple[count] = @intCast(symbol);
                count += 1;
            }
            assert(count == code.used);
            // NSYM = 3: the first listed symbol gets length 1; list the most frequent.
            if (count == 3) {
                var best: usize = 0;
                for (1..3) |index| {
                    if (histogram[code.simple[index]] > histogram[code.simple[best]]) best = index;
                }
                std.mem.swap(u16, &code.simple[0], &code.simple[best]);
            }
            const lengths: [4]u4 = switch (count) {
                1 => .{ 0, 0, 0, 0 },
                2 => .{ 1, 1, 0, 0 },
                3 => .{ 1, 2, 2, 0 },
                else => .{ 2, 2, 2, 2 },
            };
            for (code.simple[0..count], lengths[0..count]) |symbol, length| {
                code.lengths[symbol] = length;
            }
        }

        fn write_symbol(code: *const Self, bits: *BitWriter, symbol: usize) Error!void {
            if (code.used == 1) return; // Zero-bit code.
            assert(code.lengths[symbol] > 0);
            try bits.write(code.codes[symbol], code.lengths[symbol]);
        }
    };
}

/// Huffman code lengths limited to `limit`, by halving counts until the tree fits.
fn huffman_lengths(
    comptime size: usize,
    histogram: *const [size]u32,
    limit: u4,
    lengths: *[size]u4,
) void {
    var counts: [size]u32 = histogram.*;
    var attempt: u32 = 0;
    // Each halving flattens the distribution; 32 rounds reach all-equal counts.
    while (attempt < 32) : (attempt += 1) {
        if (huffman_attempt(size, &counts, limit, lengths)) return;
        for (&counts) |*count| {
            if (count.* > 0) count.* = @max(1, count.* >> 1);
        }
    }
    unreachable; // Equal counts give a balanced tree of depth ceil(log2(size)) <= limit.
}

fn huffman_attempt(
    comptime size: usize,
    counts: *const [size]u32,
    limit: u4,
    lengths: *[size]u4,
) bool {
    const Node = struct { weight: u64, parent: u16 };
    var nodes: [2 * size]Node = undefined;
    var leaves: [size]u16 = undefined;
    var leaf_count: usize = 0;
    for (counts, 0..) |count, symbol| {
        lengths[symbol] = 0;
        if (count == 0) continue;
        nodes[leaf_count] = .{ .weight = count, .parent = 0 };
        leaves[leaf_count] = @intCast(symbol);
        leaf_count += 1;
    }
    if (leaf_count == 0) return true;
    if (leaf_count == 1) {
        lengths[leaves[0]] = 1;
        return true;
    }
    // O(n^2) pairing of the two lightest roots: n <= 704, run once per meta-block.
    var is_root: [2 * size]bool = @splat(false);
    for (0..leaf_count) |index| is_root[index] = true;
    var node_count = leaf_count;
    while (node_count < 2 * leaf_count - 1) : (node_count += 1) {
        var first: usize = 2 * size;
        var second: usize = 2 * size;
        for (0..node_count) |index| {
            if (!is_root[index]) continue;
            if (first == 2 * size or nodes[index].weight < nodes[first].weight) {
                second = first;
                first = index;
            } else if (second == 2 * size or nodes[index].weight < nodes[second].weight) {
                second = index;
            }
        }
        is_root[first] = false;
        is_root[second] = false;
        nodes[first].parent = @intCast(node_count);
        nodes[second].parent = @intCast(node_count);
        nodes[node_count] = .{ .weight = nodes[first].weight + nodes[second].weight, .parent = 0 };
        is_root[node_count] = true;
    }
    const root = node_count - 1;
    for (0..leaf_count) |leaf| {
        var depth: u32 = 0;
        var index = leaf;
        while (index != root) : (depth += 1) index = nodes[index].parent;
        if (depth > limit) return false;
        lengths[leaves[leaf]] = @intCast(depth);
    }
    return true;
}

/// Canonical code words (RFC 1951 order), bit-reversed for LSB-first writing.
fn canonical_codes(comptime size: usize, lengths: *const [size]u4, codes: *[size]u16) void {
    var length_counts: [16]u16 = @splat(0);
    for (lengths) |length| length_counts[length] += 1;
    length_counts[0] = 0;
    var next_code: [16]u16 = @splat(0);
    var code: u16 = 0;
    for (1..16) |bits| {
        code = (code + length_counts[bits - 1]) << 1;
        next_code[bits] = code;
    }
    for (lengths, 0..) |length, symbol| {
        if (length == 0) continue;
        const value = next_code[length];
        next_code[length] += 1;
        codes[symbol] = @bitReverse(value) >> @intCast(16 - @as(u5, length));
    }
}

/// Writes `code` for an alphabet of `size` symbols (RFC 7932 section 3.4 / 3.5).
fn write_prefix_code(
    comptime size: usize,
    bits: *BitWriter,
    code: *const PrefixCode(size),
) Error!void {
    const alphabet_bits: u6 = @intCast(std.math.log2_int_ceil(usize, size));
    if (code.used <= 4) {
        try bits.write(1, 2); // HSKIP = 1: simple prefix code.
        try bits.write(code.used - 1, 2); // NSYM - 1.
        for (code.simple[0..code.used]) |symbol| try bits.write(symbol, alphabet_bits);
        if (code.used == 4) try bits.write(0, 1); // Tree select: lengths 2, 2, 2, 2.
        return;
    }
    // Complex code: the symbol lengths, themselves prefix-coded. Lengths are sent up to
    // the last nonzero one; the decoder stops once the Kraft sum is complete.
    var last: usize = size;
    while (code.lengths[last - 1] == 0) last -= 1;
    var histogram: [code_length_alphabet]u32 = @splat(0);
    try code_length_symbols(code.lengths[0..last], &histogram, null, null);
    var length_code: PrefixCode(code_length_alphabet) = .{};
    huffman_lengths(code_length_alphabet, &histogram, code_length_code_max, &length_code.lengths);
    canonical_codes(code_length_alphabet, &length_code.lengths, &length_code.codes);
    length_code.used = 0;
    for (length_code.lengths) |length| length_code.used += @intFromBool(length > 0);
    try write_code_length_code(bits, &length_code.lengths);
    try code_length_symbols(code.lengths[0..last], null, bits, &length_code);
}

const code_length_order = [code_length_alphabet]u8{
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15,
};

/// The fixed code for code-length-code lengths 0..5, as (LSB-first value, bit count).
const code_length_code_words = [6][2]u8{
    .{ 0, 2 }, .{ 7, 4 }, .{ 3, 3 }, .{ 2, 2 }, .{ 1, 2 }, .{ 15, 4 },
};

fn write_code_length_code(bits: *BitWriter, lengths: *const [code_length_alphabet]u4) Error!void {
    try bits.write(0, 2); // HSKIP = 0.
    var used: u32 = 0;
    for (lengths) |length| used += @intFromBool(length > 0);
    var space: u32 = 32;
    for (code_length_order) |symbol| {
        const length = lengths[symbol];
        assert(length <= code_length_code_max);
        const word = code_length_code_words[length];
        try bits.write(word[0], @intCast(word[1]));
        if (length > 0) space -= @as(u32, 32) >> length;
        // The decoder stops once the code completes; a lone used symbol never completes
        // it, so then all 18 lengths are written.
        if (space == 0) break;
    }
    assert(space == 0 or used == 1);
}

/// Walks `lengths` as code-length symbols (0..15 literal, 17 = zero run of 3..10).
/// Counts them into `histogram`, or writes them with `length_code` to `bits`.
fn code_length_symbols(
    lengths: []const u4,
    histogram: ?*[code_length_alphabet]u32,
    bits: ?*BitWriter,
    length_code: ?*const PrefixCode(code_length_alphabet),
) Error!void {
    var index: usize = 0;
    while (index < lengths.len) {
        var run: usize = 0;
        while (index + run < lengths.len and lengths[index + run] == 0 and run < 10) run += 1;
        if (run >= 3) {
            try emit_code_length(histogram, bits, length_code, 17, run - 3, 3);
            index += run;
            // A literal zero after a run keeps runs from chaining (consecutive 17s
            // multiply); emit it when the next symbol is a zero too.
            if (index < lengths.len and lengths[index] == 0) {
                try emit_code_length(histogram, bits, length_code, 0, 0, 0);
                index += 1;
            }
            continue;
        }
        try emit_code_length(histogram, bits, length_code, lengths[index], 0, 0);
        index += 1;
    }
}

fn emit_code_length(
    histogram: ?*[code_length_alphabet]u32,
    bits: ?*BitWriter,
    length_code: ?*const PrefixCode(code_length_alphabet),
    symbol: u5,
    extra: u64,
    extra_bits: u6,
) Error!void {
    if (histogram) |counts| counts[symbol] += 1;
    const writer = bits orelse return;
    try length_code.?.write_symbol(writer, symbol);
    try writer.write(extra, extra_bits);
}

pub const Encoder = struct {
    table: []u32,
    commands: []Command,
    input_bytes_max: u32,

    pub fn init(allocator: std.mem.Allocator, input_bytes_max: u32) !Encoder {
        assert(input_bytes_max <= meta_block_length_max);
        const table = try allocator.alloc(u32, 1 << hash_bits);
        errdefer allocator.free(table);
        const commands = try allocator.alloc(Command, input_bytes_max / match_length_min + 2);
        return .{ .table = table, .commands = commands, .input_bytes_max = input_bytes_max };
    }

    pub fn deinit(encoder: *Encoder, allocator: std.mem.Allocator) void {
        allocator.free(encoder.table);
        allocator.free(encoder.commands);
        encoder.* = undefined;
    }

    /// Compresses `input` into a complete brotli stream in `out`.
    pub fn compress(encoder: *Encoder, input: []const u8, out: []u8) Error![]u8 {
        assert(input.len <= encoder.input_bytes_max);
        var bits: BitWriter = .{ .out = out };
        try bits.write(1 | ((window_bits - 17) << 1), 4); // WBITS = 22.
        if (input.len == 0) {
            try bits.write(0b11, 2); // ISLAST, ISLASTEMPTY.
            return out[0..bits.byte_length()];
        }
        const commands = encoder.find_matches(input);
        try write_meta_block(&bits, input, commands);
        return out[0..bits.byte_length()];
    }

    fn hash(bytes: *const [4]u8) u32 {
        return (std.mem.readInt(u32, bytes, .little) *% 0x1e35a7bd) >> (32 - hash_bits);
    }

    /// Greedy LZ77. Every command has a copy except an optional last one carrying the
    /// trailing literals (its copy is never executed: the meta-block ends first).
    fn find_matches(encoder: *Encoder, input: []const u8) []Command {
        @memset(encoder.table, std.math.maxInt(u32));
        var count: usize = 0;
        var literal_start: usize = 0;
        var position: usize = 0;
        while (position + match_length_min <= input.len) {
            const key = hash(input[position..][0..4]);
            const candidate = encoder.table[key];
            encoder.table[key] = @intCast(position);
            const length = match_length(input, candidate, position);
            if (length < match_length_min) {
                position += 1;
                continue;
            }
            encoder.commands[count] = .{
                .insert = @intCast(position - literal_start),
                .copy = @intCast(length),
                .distance = @intCast(position - candidate),
            };
            count += 1;
            position += length;
            literal_start = position;
        }
        // The decoder stops as soon as MLEN bytes are out, so a trailing command exists
        // only when literals remain.
        if (literal_start < input.len) {
            encoder.commands[count] = .{
                .insert = @intCast(input.len - literal_start),
                .copy = 0,
                .distance = 0,
            };
            count += 1;
        }
        assert(count <= encoder.commands.len);
        return encoder.commands[0..count];
    }

    fn match_length(input: []const u8, candidate: u32, position: usize) usize {
        if (candidate == std.math.maxInt(u32)) return 0;
        if (position - candidate > window_size_max) return 0;
        const limit = @min(input.len - position, match_length_max);
        var length: usize = 0;
        while (length < limit and input[candidate + length] == input[position + length]) {
            length += 1;
        }
        return length;
    }
};

const Codes = struct {
    literal: PrefixCode(literal_alphabet) = .{},
    command: PrefixCode(command_alphabet) = .{},
    distance: PrefixCode(distance_alphabet) = .{},
};

fn write_meta_block(bits: *BitWriter, input: []const u8, commands: []const Command) Error!void {
    try bits.write(1, 1); // ISLAST.
    try bits.write(0, 1); // ISLASTEMPTY = 0.
    const nibbles: u6 = if (input.len <= 1 << 16) 4 else if (input.len <= 1 << 20) 5 else 6;
    try bits.write(nibbles - 4, 2); // MNIBBLES.
    try bits.write(input.len - 1, 4 * nibbles); // MLEN - 1.
    try bits.write(0, 3); // NBLTYPESL, NBLTYPESI, NBLTYPESD = 1.
    try bits.write(0, 2 + 4); // NPOSTFIX = 0, NDIRECT = 0.
    try bits.write(0, 2); // Literal context mode (unused with one tree).
    try bits.write(0, 2); // NTREESL = 1, NTREESD = 1.
    var codes: Codes = .{};
    build_codes(input, commands, &codes);
    try write_prefix_code(literal_alphabet, bits, &codes.literal);
    try write_prefix_code(command_alphabet, bits, &codes.command);
    try write_prefix_code(distance_alphabet, bits, &codes.distance);
    var position: usize = 0;
    for (commands) |command| {
        const symbol = command_parts(command);
        try codes.command.write_symbol(bits, symbol.code);
        try bits.write(symbol.insert_extra, symbol.insert_bits);
        try bits.write(symbol.copy_extra, symbol.copy_bits);
        for (input[position..][0..command.insert]) |byte| {
            try codes.literal.write_symbol(bits, byte);
        }
        position += command.insert;
        if (command.copy == 0) break; // The final literal-only command.
        const distance = distance_code(command.distance);
        try codes.distance.write_symbol(bits, distance.symbol);
        try bits.write(distance.extra, distance.extra_bits);
        position += command.copy;
    }
    assert(position == input.len);
}

const CommandParts = struct {
    code: u16,
    insert_extra: u32,
    insert_bits: u5,
    copy_extra: u32,
    copy_bits: u5,
};

/// Splits a command into its insert-and-copy symbol and extra bits.
fn command_parts(command: Command) CommandParts {
    const insert_code = range_code(&insert_ranges, command.insert);
    const copy_code = if (command.copy == 0) 0 else range_code(&copy_ranges, command.copy);
    // The final command's copy (code 0) is never run: the meta-block ends after its
    // literals, before a distance would be read.
    const code = command_symbol(insert_code, copy_code);
    return .{
        .code = code,
        .insert_extra = command.insert - insert_ranges[insert_code].base,
        .insert_bits = insert_ranges[insert_code].extra,
        .copy_extra = if (command.copy == 0) 0 else command.copy - copy_ranges[copy_code].base,
        .copy_bits = copy_ranges[copy_code].extra,
    };
}

fn build_codes(input: []const u8, commands: []const Command, codes: *Codes) void {
    var literal_counts: [literal_alphabet]u32 = @splat(0);
    var command_counts: [command_alphabet]u32 = @splat(0);
    var distance_counts: [distance_alphabet]u32 = @splat(0);
    var position: usize = 0;
    for (commands) |command| {
        command_counts[command_parts(command).code] += 1;
        for (input[position..][0..command.insert]) |byte| literal_counts[byte] += 1;
        position += command.insert + command.copy;
        if (command.copy > 0) distance_counts[distance_code(command.distance).symbol] += 1;
    }
    codes.literal.build(&literal_counts, code_length_max);
    codes.command.build(&command_counts, code_length_max);
    codes.distance.build(&distance_counts, code_length_max);
}

const testing = std.testing;
const consensus_brotli = @import("../../consensus/protocol/brotli.zig");
const Prng = @import("../../testing/prng.zig").Prng;

fn expect_round_trip(encoder: *Encoder, input: []const u8) !usize {
    const out = try testing.allocator.alloc(u8, input.len * 2 + 1024);
    defer testing.allocator.free(out);
    const compressed = try encoder.compress(input, out);
    const decoded = try consensus_brotli.decompress(testing.allocator, compressed, input.len + 1);
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, input, decoded);
    return compressed.len;
}

test "brotli encoder: round trips through the consensus decoder" {
    var encoder = try Encoder.init(testing.allocator, 1 << 20);
    defer encoder.deinit(testing.allocator);
    _ = try expect_round_trip(&encoder, "");
    _ = try expect_round_trip(&encoder, "a");
    _ = try expect_round_trip(&encoder, "abcd");
    _ = try expect_round_trip(&encoder, "hello hello hello hello, brotli!");
    const zeros = try testing.allocator.alloc(u8, 200_000);
    defer testing.allocator.free(zeros);
    @memset(zeros, 0);
    const zeros_size = try expect_round_trip(&encoder, zeros);
    try testing.expect(zeros_size < 200);
    var prng = Prng.init(0xb207);
    prng.fill(zeros);
    _ = try expect_round_trip(&encoder, zeros);
    // Text-like data compresses well below its size.
    for (zeros, 0..) |*byte, index| {
        const flip: u8 = @intFromBool(index % 977 == 0);
        byte.* = "the quick brown fox "[index % 20] ^ flip;
    }
    const text_size = try expect_round_trip(&encoder, zeros);
    try testing.expect(text_size < zeros.len / 20);
}

test "brotli encoder: seeded fuzz over mixed literal and repeat inputs" {
    var encoder = try Encoder.init(testing.allocator, 1 << 16);
    defer encoder.deinit(testing.allocator);
    var prng = Prng.init(0xf022);
    var input: [1 << 16]u8 = undefined;
    for (0..64) |_| {
        const length = prng.below(input.len + 1);
        var position: usize = 0;
        while (position < length) {
            const run = @min(length - position, prng.range(1, 300));
            if (position > 0 and prng.chance(1, 2)) {
                const distance = prng.range(1, position);
                for (position..position + run) |at| input[at] = input[at - distance];
            } else {
                const alphabet = prng.range(1, 256);
                for (input[position..][0..run]) |*byte| byte.* = @intCast(prng.below(alphabet));
            }
            position += run;
        }
        _ = try expect_round_trip(&encoder, input[0..length]);
    }
}

test "brotli encoder: fuzz" {
    try testing.fuzz({}, fuzz_round_trip, .{});
}

fn fuzz_round_trip(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [4096]u8 = undefined;
    const input = buffer[0..smith.slice(&buffer)];
    var encoder = try Encoder.init(testing.allocator, buffer.len);
    defer encoder.deinit(testing.allocator);
    _ = try expect_round_trip(&encoder, input);
}

//! Zero-allocation JSON for JSON-RPC: a validating pull scanner, a streaming writer, and
//! Ethereum hex encodings (QUANTITY and DATA, per the execution-apis spec).
//!
//! The scanner works on a fully buffered input (an HTTP body or WebSocket message). Tokens
//! are slices into that input, so nothing is copied unless the caller unescapes a string
//! into its own buffer. Nesting depth is bounded by `depth_max`; exceeding it is an error,
//! not a crash. Structure is validated while scanning: a document that scans to `.end`
//! without error is well formed.

const std = @import("std");
const assert = std.debug.assert;

pub const depth_max = 64;

pub const Error = error{
    UnexpectedEnd,
    UnexpectedCharacter,
    InvalidNumber,
    InvalidString,
    InvalidLiteral,
    DepthExceeded,
    TrailingData,
};

pub const TokenTag = enum {
    object_begin,
    object_end,
    array_begin,
    array_end,
    /// The raw contents between the quotes, escapes not decoded.
    string,
    number,
    true,
    false,
    null,
    end,
};

pub const Token = struct {
    tag: TokenTag,
    /// For `string`: the raw bytes between quotes. For `number`: the literal.
    bytes: []const u8 = "",
    /// For `string`: true when `bytes` contains backslash escapes.
    escaped: bool = false,
    /// For `string` inside an object: true when this string is a key.
    key: bool = false,
};

const Container = enum(u1) { object, array };

const State = enum {
    /// Expect a value (document start, after `:` or `,` in an array).
    value,
    /// Just opened an array: a value or `]`.
    array_first,
    /// Just opened an object: a key or `}`.
    object_first,
    /// After `,` in an object: a key.
    object_key,
    /// After a value inside a container: `,` or the closer; at top level, end.
    after_value,
    done,
};

pub const Scanner = struct {
    input: []const u8,
    index: u32 = 0,
    state: State = .value,
    depth: u32 = 0,
    stack: [depth_max]Container = undefined,

    pub fn init(input: []const u8) Scanner {
        assert(input.len <= std.math.maxInt(u32));
        return .{ .input = input };
    }

    /// Returns the next token. After `.end`, keeps returning `.end`.
    pub fn next(scanner: *Scanner) Error!Token {
        scanner.skip_whitespace();
        switch (scanner.state) {
            .done => return .{ .tag = .end },
            .value => return scanner.scan_value(),
            .array_first => {
                if (scanner.peek() == ']') return scanner.close(.array);
                return scanner.scan_value();
            },
            .object_first => {
                if (scanner.peek() == '}') return scanner.close(.object);
                return scanner.scan_key();
            },
            .object_key => return scanner.scan_key(),
            .after_value => return scanner.scan_after_value(),
        }
    }

    /// Byte offset of the scanner, for error reporting.
    pub fn offset(scanner: *const Scanner) u32 {
        return scanner.index;
    }

    /// Skips the value whose first token was just returned (`first`). Containers are
    /// skipped through their closer; scalars need nothing.
    pub fn skip(scanner: *Scanner, first: Token) Error!void {
        const opened: u32 = switch (first.tag) {
            .object_begin, .array_begin => 1,
            .end, .object_end, .array_end => return error.UnexpectedCharacter,
            else => return,
        };
        const target_depth = scanner.depth - opened;
        // Every iteration consumes at least one byte, so input length bounds the loop.
        var iterations: u32 = 0;
        while (iterations <= scanner.input.len) : (iterations += 1) {
            const token = try scanner.next();
            if (token.tag == .end) return error.UnexpectedEnd;
            const closes = token.tag == .object_end or token.tag == .array_end;
            if (closes and scanner.depth == target_depth) return;
        }
        unreachable;
    }

    fn peek(scanner: *const Scanner) ?u8 {
        if (scanner.index >= scanner.input.len) return null;
        return scanner.input[scanner.index];
    }

    fn skip_whitespace(scanner: *Scanner) void {
        while (scanner.index < scanner.input.len) : (scanner.index += 1) {
            switch (scanner.input[scanner.index]) {
                ' ', '\t', '\n', '\r' => {},
                else => return,
            }
        }
    }

    fn scan_after_value(scanner: *Scanner) Error!Token {
        if (scanner.depth == 0) {
            if (scanner.peek() != null) return error.TrailingData;
            scanner.state = .done;
            return .{ .tag = .end };
        }
        const container = scanner.stack[scanner.depth - 1];
        const byte = scanner.peek() orelse return error.UnexpectedEnd;
        if (byte == ',') {
            scanner.index += 1;
            scanner.skip_whitespace();
            switch (container) {
                .array => return scanner.scan_value(),
                .object => return scanner.scan_key(),
            }
        }
        if (container == .array and byte == ']') return scanner.close(.array);
        if (container == .object and byte == '}') return scanner.close(.object);
        return error.UnexpectedCharacter;
    }

    fn close(scanner: *Scanner, container: Container) Error!Token {
        assert(scanner.depth > 0);
        assert(scanner.stack[scanner.depth - 1] == container);
        scanner.index += 1;
        scanner.depth -= 1;
        scanner.state = .after_value;
        return .{ .tag = if (container == .object) .object_end else .array_end };
    }

    fn open(scanner: *Scanner, container: Container) Error!Token {
        if (scanner.depth == depth_max) return error.DepthExceeded;
        scanner.stack[scanner.depth] = container;
        scanner.depth += 1;
        scanner.index += 1;
        scanner.state = if (container == .object) .object_first else .array_first;
        return .{ .tag = if (container == .object) .object_begin else .array_begin };
    }

    fn scan_key(scanner: *Scanner) Error!Token {
        if (scanner.peek() != '"') {
            return if (scanner.peek() == null) error.UnexpectedEnd else error.UnexpectedCharacter;
        }
        var token = try scanner.scan_string();
        token.key = true;
        scanner.skip_whitespace();
        if (scanner.peek() != ':') {
            return if (scanner.peek() == null) error.UnexpectedEnd else error.UnexpectedCharacter;
        }
        scanner.index += 1;
        scanner.state = .value;
        return token;
    }

    fn scan_value(scanner: *Scanner) Error!Token {
        const byte = scanner.peek() orelse return error.UnexpectedEnd;
        const token: Token = switch (byte) {
            '{' => return scanner.open(.object),
            '[' => return scanner.open(.array),
            '"' => try scanner.scan_string(),
            '-', '0'...'9' => try scanner.scan_number(),
            't' => try scanner.scan_literal("true", .true),
            'f' => try scanner.scan_literal("false", .false),
            'n' => try scanner.scan_literal("null", .null),
            else => return error.UnexpectedCharacter,
        };
        scanner.state = .after_value;
        return token;
    }

    fn scan_literal(scanner: *Scanner, comptime text: []const u8, tag: TokenTag) Error!Token {
        const rest = scanner.input[scanner.index..];
        if (rest.len < text.len) {
            if (std.mem.startsWith(u8, text, rest)) return error.UnexpectedEnd;
            return error.InvalidLiteral;
        }
        if (!std.mem.eql(u8, rest[0..text.len], text)) return error.InvalidLiteral;
        scanner.index += text.len;
        return .{ .tag = tag };
    }

    fn scan_string(scanner: *Scanner) Error!Token {
        assert(scanner.input[scanner.index] == '"');
        scanner.index += 1;
        const start = scanner.index;
        var escaped = false;
        while (scanner.index < scanner.input.len) {
            const byte = scanner.input[scanner.index];
            switch (byte) {
                '"' => {
                    const bytes = scanner.input[start..scanner.index];
                    scanner.index += 1;
                    return .{ .tag = .string, .bytes = bytes, .escaped = escaped };
                },
                '\\' => {
                    escaped = true;
                    try scanner.scan_escape();
                },
                0...0x1f => return error.InvalidString,
                0x20...0x21, 0x23...0x5b, 0x5d...0x7f => scanner.index += 1,
                else => try scanner.scan_utf8(),
            }
        }
        return error.UnexpectedEnd;
    }

    fn scan_escape(scanner: *Scanner) Error!void {
        assert(scanner.input[scanner.index] == '\\');
        if (scanner.index + 1 >= scanner.input.len) return error.UnexpectedEnd;
        switch (scanner.input[scanner.index + 1]) {
            '"', '\\', '/', 'b', 'f', 'n', 'r', 't' => scanner.index += 2,
            'u' => {
                if (scanner.index + 6 > scanner.input.len) return error.UnexpectedEnd;
                for (scanner.input[scanner.index + 2 ..][0..4]) |hex| {
                    if (!std.ascii.isHex(hex)) return error.InvalidString;
                }
                scanner.index += 6;
            },
            else => return error.InvalidString,
        }
    }

    fn scan_utf8(scanner: *Scanner) Error!void {
        const length = std.unicode.utf8ByteSequenceLength(scanner.input[scanner.index]) catch
            return error.InvalidString;
        if (scanner.index + length > scanner.input.len) return error.UnexpectedEnd;
        const sequence = scanner.input[scanner.index..][0..length];
        _ = std.unicode.utf8Decode(sequence) catch return error.InvalidString;
        scanner.index += length;
    }

    fn scan_number(scanner: *Scanner) Error!Token {
        const start = scanner.index;
        const input = scanner.input;
        var index: usize = scanner.index;
        if (input[index] == '-') index += 1;
        if (index >= input.len) return error.UnexpectedEnd;
        if (input[index] == '0') {
            index += 1;
        } else if (input[index] >= '1' and input[index] <= '9') {
            index = digits_end(input, index);
        } else return error.InvalidNumber;
        if (index < input.len and input[index] == '.') {
            index += 1;
            const fraction_start = index;
            index = digits_end(input, index);
            if (index == fraction_start) return error.InvalidNumber;
        }
        if (index < input.len and (input[index] == 'e' or input[index] == 'E')) {
            index += 1;
            if (index < input.len and (input[index] == '+' or input[index] == '-')) index += 1;
            const exponent_start = index;
            index = digits_end(input, index);
            if (index == exponent_start) return error.InvalidNumber;
        }
        // A number must be followed by a delimiter, not more number-ish bytes ("01", "1x").
        if (index < input.len) switch (input[index]) {
            ' ', '\t', '\n', '\r', ',', ']', '}' => {},
            else => return error.InvalidNumber,
        };
        scanner.index = @intCast(index);
        return .{ .tag = .number, .bytes = input[start..index] };
    }

    fn digits_end(input: []const u8, start: usize) usize {
        var index = start;
        while (index < input.len and std.ascii.isDigit(input[index])) index += 1;
        return index;
    }
};

/// Decodes a scanned string token into `buffer`. Returns the decoded slice, which is the
/// token bytes themselves when there are no escapes.
pub fn unescape(token: Token, buffer: []u8) error{ NoSpaceLeft, InvalidString }![]const u8 {
    assert(token.tag == .string);
    if (!token.escaped) return token.bytes;
    const raw = token.bytes;
    var read: usize = 0;
    var written: usize = 0;
    while (read < raw.len) {
        if (raw[read] != '\\') {
            if (written == buffer.len) return error.NoSpaceLeft;
            buffer[written] = raw[read];
            written += 1;
            read += 1;
            continue;
        }
        assert(read + 1 < raw.len); // The scanner validated every escape.
        const kind = raw[read + 1];
        if (kind == 'u') {
            const decoded = try decode_unicode_escape(raw, &read);
            var utf8: [4]u8 = undefined;
            const size = std.unicode.utf8Encode(decoded, &utf8) catch return error.InvalidString;
            if (written + size > buffer.len) return error.NoSpaceLeft;
            @memcpy(buffer[written..][0..size], utf8[0..size]);
            written += size;
            continue;
        }
        if (written == buffer.len) return error.NoSpaceLeft;
        buffer[written] = switch (kind) {
            'b' => 0x08,
            'f' => 0x0c,
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            else => kind, // '"', '\\', '/'
        };
        written += 1;
        read += 2;
    }
    return buffer[0..written];
}

fn decode_unicode_escape(raw: []const u8, read: *usize) error{InvalidString}!u21 {
    const high = parse_hex4(raw[read.* + 2 ..][0..4]);
    read.* += 6;
    if (high < 0xd800 or high > 0xdfff) return high;
    if (high >= 0xdc00) return error.InvalidString; // Lone low surrogate.
    // A high surrogate must be followed by `\uDC00`-`\uDFFF`.
    if (read.* + 6 > raw.len or raw[read.*] != '\\' or raw[read.* + 1] != 'u') {
        return error.InvalidString;
    }
    const low = parse_hex4(raw[read.* + 2 ..][0..4]);
    if (low < 0xdc00 or low > 0xdfff) return error.InvalidString;
    read.* += 6;
    return 0x10000 + ((@as(u21, high) - 0xd800) << 10) + (low - 0xdc00);
}

fn parse_hex4(hex: *const [4]u8) u16 {
    var value: u16 = 0;
    for (hex) |digit| {
        // The scanner validated these as hex digits.
        value = value << 4 | (std.fmt.charToDigit(digit, 16) catch unreachable);
    }
    return value;
}

// Ethereum hex encodings.

pub const HexError = error{ InvalidHex, Overflow, LeadingZero, MissingPrefix };

/// Parses a QUANTITY: `0x` followed by at least one hex digit, no leading zeros
/// (except `0x0`). Accepts upper- or lower-case digits.
pub fn parse_quantity(comptime T: type, text: []const u8) HexError!T {
    comptime assert(@typeInfo(T) == .int and @typeInfo(T).int.signedness == .unsigned);
    if (text.len < 3 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) {
        return error.MissingPrefix;
    }
    const digits = text[2..];
    if (digits.len > 1 and digits[0] == '0') return error.LeadingZero;
    const nibbles_max: usize = (@bitSizeOf(T) + 3) / 4;
    if (digits.len > nibbles_max) {
        return error.Overflow;
    }
    var value: T = 0;
    for (digits) |digit| {
        const nibble = std.fmt.charToDigit(digit, 16) catch return error.InvalidHex;
        if (@bitSizeOf(T) >= 4) {
            value = std.math.shlExact(T, value, 4) catch return error.Overflow;
        } else if (value != 0) return error.Overflow;
        value |= @intCast(nibble);
    }
    return value;
}

/// Parses DATA (`0x` + even number of hex digits) into `out`. Returns the decoded slice.
pub fn parse_data(text: []const u8, out: []u8) (HexError || error{NoSpaceLeft})![]u8 {
    if (text.len < 2 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) {
        return error.MissingPrefix;
    }
    const digits = text[2..];
    if (digits.len % 2 != 0) return error.InvalidHex;
    const size = digits.len / 2;
    if (size > out.len) return error.NoSpaceLeft;
    for (out[0..size], 0..) |*byte, index| {
        const high = std.fmt.charToDigit(digits[index * 2], 16) catch return error.InvalidHex;
        const low = std.fmt.charToDigit(digits[index * 2 + 1], 16) catch return error.InvalidHex;
        byte.* = high << 4 | low;
    }
    return out[0..size];
}

/// Parses DATA that must decode to exactly `N` bytes (addresses, hashes).
pub fn parse_fixed(comptime N: usize, text: []const u8) (HexError || error{InvalidLength})![N]u8 {
    var out: [N]u8 = undefined;
    if (text.len != 2 + 2 * N) return error.InvalidLength;
    const decoded = parse_data(text, &out) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable, // Length checked above.
        else => |e| return e,
    };
    assert(decoded.len == N);
    return out;
}

const hex_digits = "0123456789abcdef";

/// Formats a QUANTITY into `buffer` (no quotes). Returns the slice.
pub fn format_quantity(value: anytype, buffer: []u8) []const u8 {
    const T = @TypeOf(value);
    comptime assert(@typeInfo(T) == .int and @typeInfo(T).int.signedness == .unsigned);
    const nibbles_max = (@bitSizeOf(T) + 3) / 4;
    assert(buffer.len >= 2 + nibbles_max);
    buffer[0] = '0';
    buffer[1] = 'x';
    if (value == 0) {
        buffer[2] = '0';
        return buffer[0..3];
    }
    const Wide = @Int(.unsigned, nibbles_max * 4);
    const wide: Wide = value;
    var nibbles: usize = nibbles_max;
    while (nibbles > 1 and (wide >> @intCast((nibbles - 1) * 4)) & 0xf == 0) nibbles -= 1;
    for (0..nibbles) |index| {
        const shift: std.math.Log2Int(Wide) = @intCast((nibbles - 1 - index) * 4);
        buffer[2 + index] = hex_digits[@intCast((wide >> shift) & 0xf)];
    }
    return buffer[0 .. 2 + nibbles];
}

/// A streaming JSON writer that tracks commas. Write errors come from the underlying writer.
pub const Writer = struct {
    out: *std.Io.Writer,
    depth: u32 = 0,
    /// Per depth: whether the container already has an element (needs a comma first).
    has_element: [depth_max + 1]bool = @splat(false),
    /// True right after `key()`: the next value must not be preceded by a comma.
    after_key: bool = false,

    pub const WriteError = std.Io.Writer.Error;

    pub fn init(out: *std.Io.Writer) Writer {
        return .{ .out = out };
    }

    fn separate(writer: *Writer) WriteError!void {
        if (writer.after_key) {
            writer.after_key = false;
            return;
        }
        if (writer.has_element[writer.depth]) try writer.out.writeByte(',');
        writer.has_element[writer.depth] = true;
    }

    pub fn begin_object(writer: *Writer) WriteError!void {
        try writer.begin('{');
    }

    pub fn end_object(writer: *Writer) WriteError!void {
        try writer.end('}');
    }

    pub fn begin_array(writer: *Writer) WriteError!void {
        try writer.begin('[');
    }

    pub fn end_array(writer: *Writer) WriteError!void {
        try writer.end(']');
    }

    fn begin(writer: *Writer, byte: u8) WriteError!void {
        assert(writer.depth < depth_max);
        try writer.separate();
        try writer.out.writeByte(byte);
        writer.depth += 1;
        writer.has_element[writer.depth] = false;
    }

    fn end(writer: *Writer, byte: u8) WriteError!void {
        assert(writer.depth > 0);
        assert(!writer.after_key);
        writer.depth -= 1;
        try writer.out.writeByte(byte);
    }

    pub fn key(writer: *Writer, name: []const u8) WriteError!void {
        assert(writer.depth > 0);
        assert(!writer.after_key);
        try writer.separate();
        try write_string_escaped(writer.out, name);
        try writer.out.writeByte(':');
        writer.after_key = true;
    }

    pub fn string(writer: *Writer, value: []const u8) WriteError!void {
        try writer.separate();
        try write_string_escaped(writer.out, value);
    }

    pub fn boolean(writer: *Writer, value: bool) WriteError!void {
        try writer.separate();
        try writer.out.writeAll(if (value) "true" else "false");
    }

    pub fn null_value(writer: *Writer) WriteError!void {
        try writer.separate();
        try writer.out.writeAll("null");
    }

    /// A plain JSON integer (for JSON-RPC ids and error codes).
    pub fn integer(writer: *Writer, value: anytype) WriteError!void {
        try writer.separate();
        try writer.out.print("{d}", .{value});
    }

    /// Pre-encoded JSON, written verbatim (e.g. a cached response fragment).
    pub fn raw(writer: *Writer, json: []const u8) WriteError!void {
        try writer.separate();
        try writer.out.writeAll(json);
    }

    /// An Ethereum QUANTITY, quoted.
    pub fn quantity(writer: *Writer, value: anytype) WriteError!void {
        var buffer: [2 + 64]u8 = undefined;
        try writer.separate();
        try writer.out.writeByte('"');
        try writer.out.writeAll(format_quantity(value, &buffer));
        try writer.out.writeByte('"');
    }

    /// Ethereum DATA, quoted.
    pub fn data(writer: *Writer, bytes: []const u8) WriteError!void {
        try writer.separate();
        try writer.out.writeAll("\"0x");
        try write_hex(writer.out, bytes);
        try writer.out.writeByte('"');
    }
};

/// Lowercase hex of `bytes`, encoded straight into `out`'s buffer (`hex_encode`), in
/// chunks of whatever room the buffer has: no intermediate copy. A buffer under two bytes
/// (an unbuffered writer) takes one digit at a time.
pub fn write_hex(out: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    if (out.buffer.len < 2) {
        for (bytes) |byte| {
            try out.writeByte(hex_digits[byte >> 4]);
            try out.writeByte(hex_digits[byte & 0xf]);
        }
        return;
    }
    var rest = bytes;
    var chunks: usize = 0;
    while (rest.len > 0) : (chunks += 1) {
        assert(chunks < bytes.len); // Every chunk encodes at least one byte.
        const room = try out.writableSliceGreedy(2);
        const count = @min(rest.len, room.len / 2);
        assert(count > 0);
        hex_encode(room[0 .. 2 * count], rest[0..count]);
        out.advance(2 * count);
        rest = rest[count..];
    }
}

const hex_lanes = 16;
const HexVector = @Vector(hex_lanes, u8);

/// Interleaves the high-nibble digits (first operand) with the low ones (second).
const hex_interleave: [2 * hex_lanes]i32 = blk: {
    var mask: [2 * hex_lanes]i32 = undefined;
    for (0..hex_lanes) |lane| {
        mask[2 * lane] = lane;
        mask[2 * lane + 1] = ~@as(i32, lane);
    }
    break :blk mask;
};

/// Lowercase hex of `source` into `target` (twice as long), 16 bytes per vector step.
pub fn hex_encode(target: []u8, source: []const u8) void {
    assert(target.len == 2 * source.len);
    var index: usize = 0;
    while (index + hex_lanes <= source.len) : (index += hex_lanes) {
        const bytes: HexVector = source[index..][0..hex_lanes].*;
        const high = hex_digits_of(bytes >> @splat(4));
        const low = hex_digits_of(bytes & @as(HexVector, @splat(0xf)));
        const pairs: [2 * hex_lanes]u8 = @shuffle(u8, high, low, hex_interleave);
        target[2 * index ..][0 .. 2 * hex_lanes].* = pairs;
    }
    for (source[index..], index..) |byte, position| {
        target[2 * position] = hex_digits[byte >> 4];
        target[2 * position + 1] = hex_digits[byte & 0xf];
    }
    assert(index <= source.len);
}

/// ASCII digit of each nibble (0..15).
fn hex_digits_of(nibbles: HexVector) HexVector {
    const letters = nibbles > @as(HexVector, @splat(9));
    const letter: HexVector = @splat('a' - 10);
    const digit: HexVector = @splat('0');
    return nibbles + @select(u8, letters, letter, digit);
}

pub fn write_string_escaped(out: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    try out.writeByte('"');
    var start: usize = 0;
    for (value, 0..) |byte, index| {
        const escape: ?[]const u8 = switch (byte) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0...0x08, 0x0b, 0x0c, 0x0e...0x1f => "",
            else => null,
        };
        const sequence = escape orelse continue;
        try out.writeAll(value[start..index]);
        if (sequence.len == 0) {
            try out.print("\\u{x:0>4}", .{byte});
        } else {
            try out.writeAll(sequence);
        }
        start = index + 1;
    }
    try out.writeAll(value[start..]);
    try out.writeByte('"');
}

/// Returns the raw text of the value reached by following object `keys` from the document
/// root (e.g. `&.{ "blockRef", "l1origin", "number" }`), or null if a key is missing or an
/// intermediate value is not an object. The first matching key wins; keys containing escapes
/// never match. Only the path and the returned value are validated, not the whole document.
pub fn find_path(input: []const u8, keys: []const []const u8) Error!?[]const u8 {
    assert(keys.len <= depth_max);
    var scanner = Scanner.init(input);
    for (keys) |wanted| {
        const container = try scanner.next();
        if (container.tag != .object_begin) return null;
        // Each member consumes at least one byte, so input length bounds the loop.
        var members: u32 = 0;
        while (true) : (members += 1) {
            assert(members <= input.len);
            const key = try scanner.next();
            if (key.tag == .object_end) return null;
            assert(key.tag == .string and key.key);
            if (!key.escaped and std.mem.eql(u8, key.bytes, wanted)) break;
            try scanner.skip(try scanner.next());
        }
    }
    scanner.skip_whitespace();
    const start = scanner.index;
    try scanner.skip(try scanner.next());
    assert(scanner.index > start);
    return input[start..scanner.index];
}

/// Scans a whole document, returning an error if it is not well formed.
pub fn validate(input: []const u8) Error!void {
    var scanner = Scanner.init(input);
    var iterations: usize = 0;
    while (iterations <= input.len + 1) : (iterations += 1) {
        const token = try scanner.next();
        if (token.tag == .end) return;
    }
    unreachable; // Each non-end token consumes at least one byte.
}

test {
    _ = @import("tests.zig");
}

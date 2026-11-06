//! Validity predicates carried by `base_sendRawTransactionValidity` transactions (port of
//! base/base `txpool/src/validity.rs`): parsing with bounds, ingress validation, block-expiry
//! bounds, and evaluation against state for the pool and builder.
//!
//! JSON shape: `{"type": "balance"|"nonce"|"storage"|"block_number"|"flashblock_index",
//! "params": {...}}`, with `address`, `slot`, `mask` (storage only, default all ones), `op`
//! (`<`, `<=`, `=`, `!=`, `>`, `>=`) and `value`. Unknown fields are rejected.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");

pub const Address = [20]u8;

/// base/base `DEFAULT_MAX_VALIDITY_PREDICATES`.
pub const predicates_max = 64;
/// base/base `DEFAULT_MAX_VALIDITY_EXPIRY_SECS`.
pub const expiry_seconds_max: u64 = 60;
/// The first flashblock index at which pooled transactions are evaluated.
pub const first_pool_flashblock_index: u256 = 1;

pub const Kind = enum { balance, nonce, storage, block_number, flashblock_index };

pub const Operator = enum {
    less_than,
    less_than_or_equal,
    equal,
    not_equal,
    greater_than,
    greater_than_or_equal,

    pub fn matches(operator: Operator, left: u256, right: u256) bool {
        return switch (operator) {
            .less_than => left < right,
            .less_than_or_equal => left <= right,
            .equal => left == right,
            .not_equal => left != right,
            .greater_than => left > right,
            .greater_than_or_equal => left >= right,
        };
    }

    fn parse(text: []const u8) ?Operator {
        const names = [_][]const u8{ "<", "<=", "=", "!=", ">", ">=" };
        for (names, 0..) |name, index| {
            if (std.mem.eql(u8, text, name)) return @fromBackingInt(@intCast(index));
        }
        return null;
    }

    /// The greatest value satisfying `x op value` (null: unbounded above; `< 0` gives
    /// `.none`, which nothing satisfies).
    fn upper_bound(operator: Operator, value: u256) Bound {
        return switch (operator) {
            .less_than => if (value == 0) .none else .{ .at_most = value - 1 },
            .less_than_or_equal, .equal => .{ .at_most = value },
            .not_equal, .greater_than, .greater_than_or_equal => .unbounded,
        };
    }
};

const Bound = union(enum) { unbounded, none, at_most: u256 };

pub const Predicate = struct {
    kind: Kind,
    operator: Operator,
    value: u256,
    address: Address = @splat(0),
    slot: u256 = 0,
    mask: u256 = std.math.maxInt(u256),
};

pub const Error = error{
    Empty,
    TooMany,
    StorageValueOutsideMask,
    UnsatisfiableFlashblockIndex,
    MissingBlockExpiry,
    ExpiredBlockBound,
    BlockExpiryWindowExceeded,
};

/// base/base's message for each ingress error.
pub fn message(err: Error) []const u8 {
    return switch (err) {
        error.Empty => "validity predicates must not be empty",
        error.TooMany => "too many validity predicates",
        error.StorageValueOutsideMask => "storage predicate has value bits set outside its mask",
        error.UnsatisfiableFlashblockIndex => "flashblock-index predicate can never be " ++
            "satisfied by a pooled transaction",
        error.MissingBlockExpiry => "validity transactions require a block-number predicate " ++
            "with an upper bound",
        error.ExpiredBlockBound => "block-number predicate already expired",
        error.BlockExpiryWindowExceeded => "block-number predicate expires too far in the future",
    };
}

/// Per-predicate checks, then the count (`validate_batch`).
pub fn validate_batch(predicates: []const Predicate) Error!void {
    if (predicates.len == 0) return error.Empty;
    if (predicates.len > predicates_max) return error.TooMany;
    for (predicates) |predicate| {
        if (predicate.kind == .storage and predicate.value & ~predicate.mask != 0) {
            return error.StorageValueOutsideMask;
        }
        if (predicate.kind == .flashblock_index) {
            switch (predicate.operator.upper_bound(predicate.value)) {
                .unbounded => {},
                .none => return error.UnsatisfiableFlashblockIndex,
                .at_most => |most| if (most < first_pool_flashblock_index) {
                    return error.UnsatisfiableFlashblockIndex;
                },
            }
        }
    }
}

/// The tightest block-number upper bound (null: none; `< 0` gives 0 as base/base).
pub fn block_expiry_bound(predicates: []const Predicate) ?u256 {
    var upper: ?u256 = null;
    for (predicates) |predicate| {
        if (predicate.kind != .block_number) continue;
        const candidate: u256 = switch (predicate.operator.upper_bound(predicate.value)) {
            .unbounded => continue,
            .none => 0,
            .at_most => |most| most,
        };
        upper = if (upper) |current| @min(current, candidate) else candidate;
    }
    return upper;
}

/// A finite expiry within `[current_block, current_block + window]` (base/base
/// `validate_block_expiry_bounds`; the window is `expiry_seconds_max` of blocks).
pub fn validate_block_expiry(
    predicates: []const Predicate,
    current_block: u64,
    block_interval_ms: u64,
) Error!void {
    assert(block_interval_ms > 0);
    const bound = block_expiry_bound(predicates) orelse return error.MissingBlockExpiry;
    if (bound < current_block) return error.ExpiredBlockBound;
    const window_blocks = std.math.divCeil(u64, expiry_seconds_max * 1000, block_interval_ms) catch
        unreachable; // The interval is positive.
    const maximum_block = current_block +| window_blocks;
    if (bound > maximum_block) return error.BlockExpiryWindowExceeded;
}

/// State reads for `matches` (the pool or builder supplies its view).
pub const Reader = struct {
    context: *anyopaque,
    balance: *const fn (context: *anyopaque, address: Address) anyerror!u256,
    nonce: *const fn (context: *anyopaque, address: Address) anyerror!u64,
    storage: *const fn (context: *anyopaque, address: Address, slot: u256) anyerror!u256,
};

pub const Context = struct { block_number: u64, flashblock_index: u64 = 0 };

/// Whether the predicate holds on `reader`'s state in the block `context` describes.
pub fn matches(predicate: *const Predicate, reader: Reader, context: Context) !bool {
    const left: u256 = switch (predicate.kind) {
        .balance => try reader.balance(reader.context, predicate.address),
        .nonce => try reader.nonce(reader.context, predicate.address),
        .storage => (try reader.storage(reader.context, predicate.address, predicate.slot)) &
            predicate.mask,
        .block_number => context.block_number,
        .flashblock_index => context.flashblock_index,
    };
    return predicate.operator.matches(left, predicate.value);
}

/// Whether every predicate holds.
pub fn all_match(predicates: []const Predicate, reader: Reader, context: Context) !bool {
    for (predicates) |*predicate| if (!try matches(predicate, reader, context)) return false;
    return true;
}

// ---- JSON -------------------------------------------------------------------------

/// Parses a `validity` array (at most `predicates_max + 1` entries are read, so an
/// oversized batch fails as `TooMany` without unbounded work).
pub fn parse_list(scanner: *json.Scanner, out: []Predicate) error{ InvalidParams, TooMany }!u32 {
    assert(out.len > predicates_max);
    if ((scanner.next() catch return error.InvalidParams).tag != .array_begin) {
        return error.InvalidParams;
    }
    var count: u32 = 0;
    while (true) {
        const token = scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) return count;
        if (token.tag != .object_begin) return error.InvalidParams;
        if (count == predicates_max + 1) return error.TooMany;
        out[count] = try parse_predicate(scanner);
        count += 1;
    }
}

fn parse_predicate(scanner: *json.Scanner) error{InvalidParams}!Predicate {
    var kind: ?Kind = null;
    var parsed: ?Parsed = null;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        if (std.mem.eql(u8, name.bytes, "type")) {
            const value = scanner.next() catch return error.InvalidParams;
            if (value.tag != .string or kind != null) return error.InvalidParams;
            kind = std.meta.stringToEnum(Kind, value.bytes) orelse return error.InvalidParams;
        } else if (std.mem.eql(u8, name.bytes, "params")) {
            const value = scanner.next() catch return error.InvalidParams;
            if (value.tag != .object_begin or parsed != null) return error.InvalidParams;
            parsed = try parse_params(scanner);
        } else return error.InvalidParams;
    }
    const params = parsed orelse return error.InvalidParams;
    var result = params.predicate;
    result.kind = kind orelse return error.InvalidParams;
    try check_fields(&result, params.seen);
    return result;
}

/// Which params fields were present (each kind requires and forbids some).
const Seen = packed struct(u8) {
    address: bool = false,
    slot: bool = false,
    mask: bool = false,
    op: bool = false,
    value: bool = false,
    _: u3 = 0,
};

const Parsed = struct { predicate: Predicate, seen: Seen };

fn parse_params(scanner: *json.Scanner) error{InvalidParams}!Parsed {
    var predicate: Predicate = .{ .kind = .balance, .operator = .equal, .value = 0 };
    var seen: Seen = .{};
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        const value = scanner.next() catch return error.InvalidParams;
        if (std.mem.eql(u8, name.bytes, "address") and !seen.address) {
            if (value.tag != .string) return error.InvalidParams;
            predicate.address = json.parse_fixed(20, value.bytes) catch return error.InvalidParams;
            seen.address = true;
        } else if (std.mem.eql(u8, name.bytes, "slot") and !seen.slot) {
            predicate.slot = try parse_word(value);
            seen.slot = true;
        } else if (std.mem.eql(u8, name.bytes, "mask") and !seen.mask) {
            predicate.mask = try parse_word(value);
            seen.mask = true;
        } else if (std.mem.eql(u8, name.bytes, "op") and !seen.op) {
            if (value.tag != .string) return error.InvalidParams;
            predicate.operator = Operator.parse(value.bytes) orelse return error.InvalidParams;
            seen.op = true;
        } else if (std.mem.eql(u8, name.bytes, "value") and !seen.value) {
            predicate.value = try parse_word(value);
            seen.value = true;
        } else return error.InvalidParams;
    }
    return .{ .predicate = predicate, .seen = seen };
}

fn check_fields(predicate: *const Predicate, seen: Seen) error{InvalidParams}!void {
    if (!seen.op or !seen.value) return error.InvalidParams;
    const wants_address = predicate.kind == .balance or predicate.kind == .nonce or
        predicate.kind == .storage;
    if (seen.address != wants_address) return error.InvalidParams;
    if (predicate.kind == .storage) {
        if (!seen.slot) return error.InvalidParams;
    } else if (seen.slot or seen.mask) return error.InvalidParams;
}

/// A U256 as a `0x` hex string, a decimal string, or a JSON integer.
fn parse_word(token: json.Token) error{InvalidParams}!u256 {
    const text = token.bytes;
    if (token.tag == .number) return std.fmt.parseInt(u256, text, 10) catch error.InvalidParams;
    if (token.tag != .string or text.len == 0) return error.InvalidParams;
    if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) {
        if (text.len == 2 or text.len > 66) return error.InvalidParams;
        return std.fmt.parseInt(u256, text[2..], 16) catch error.InvalidParams;
    }
    return std.fmt.parseInt(u256, text, 10) catch error.InvalidParams;
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn block_bound(operator: Operator, value: u256) Predicate {
    return .{ .kind = .block_number, .operator = operator, .value = value };
}

test "validity: batch rules" {
    try testing.expectError(error.Empty, validate_batch(&.{}));
    var many: [predicates_max + 1]Predicate = @splat(block_bound(.less_than, 5));
    try testing.expectError(error.TooMany, validate_batch(&many));
    try validate_batch(many[0..predicates_max]);
    const outside: Predicate = .{ .kind = .storage, .operator = .equal, .value = 3, .mask = 1 };
    try testing.expectError(error.StorageValueOutsideMask, validate_batch(&.{outside}));
    const flash_lt_1: Predicate = .{
        .kind = .flashblock_index,
        .operator = .less_than,
        .value = 1,
    };
    try testing.expectError(error.UnsatisfiableFlashblockIndex, validate_batch(&.{flash_lt_1}));
    const flash_le_1: Predicate = .{
        .kind = .flashblock_index,
        .operator = .less_than_or_equal,
        .value = 1,
    };
    try validate_batch(&.{flash_le_1});
}

test "validity: block expiry window" {
    // 60 s of 200 ms blocks = 300 blocks from block 100.
    try validate_block_expiry(&.{block_bound(.less_than_or_equal, 400)}, 100, 200);
    try testing.expectError(
        error.BlockExpiryWindowExceeded,
        validate_block_expiry(&.{block_bound(.less_than_or_equal, 401)}, 100, 200),
    );
    try testing.expectError(
        error.ExpiredBlockBound,
        validate_block_expiry(&.{block_bound(.less_than, 100)}, 100, 200),
    );
    try testing.expectError(
        error.MissingBlockExpiry,
        validate_block_expiry(&.{block_bound(.greater_than, 1)}, 100, 200),
    );
    // The tightest bound wins.
    const both = [_]Predicate{ block_bound(.equal, 1000), block_bound(.less_than, 150) };
    try validate_block_expiry(&both, 100, 200);
}

fn parse_text(text: []const u8, out: []Predicate) !u32 {
    var scanner = json.Scanner.init(text);
    return parse_list(&scanner, out);
}

test "validity: JSON predicates" {
    var out: [predicates_max + 1]Predicate = undefined;
    const count = try parse_text(
        \\[{"type":"storage","params":{"address":"0x0000000000000000000000000000000000000055",
        \\"slot":"0x1","op":">=","value":"7"}},{"type":"block_number","params":{"op":"<",
        \\"value":12}}]
    , &out);
    try testing.expectEqual(@as(u32, 2), count);
    try testing.expectEqual(Kind.storage, out[0].kind);
    try testing.expectEqual(@as(u256, std.math.maxInt(u256)), out[0].mask);
    try testing.expectEqual(Operator.greater_than_or_equal, out[0].operator);
    try testing.expectEqual(@as(u256, 12), out[1].value);
    const bad = [_][]const u8{
        "[{\"type\":\"balance\",\"params\":{\"op\":\"=\",\"value\":1}}]", // No address.
        "[{\"type\":\"block_number\",\"params\":{\"op\":\"=\",\"value\":1,\"slot\":1}}]",
        "[{\"type\":\"block_number\",\"params\":{\"op\":\"=~\",\"value\":1}}]",
        "[{\"type\":\"block_number\",\"params\":{\"op\":\"=\",\"value\":1},\"x\":1}]",
        "[{\"type\":\"gas\",\"params\":{\"op\":\"=\",\"value\":1}}]",
        "[{\"type\":\"storage\",\"params\":{\"address\":\"0x00\",\"op\":\"=\",\"value\":1}}]",
    };
    for (bad) |text| try testing.expectError(error.InvalidParams, parse_text(text, &out));
}

const FakeState = struct {
    fn balance(_: *anyopaque, address: Address) anyerror!u256 {
        return address[19];
    }
    fn nonce(_: *anyopaque, _: Address) anyerror!u64 {
        return 4;
    }
    fn storage(_: *anyopaque, _: Address, slot: u256) anyerror!u256 {
        return slot * 3;
    }
};

test "validity: predicates evaluate against state and the block" {
    var unused: u8 = 0;
    const reader: Reader = .{
        .context = &unused,
        .balance = FakeState.balance,
        .nonce = FakeState.nonce,
        .storage = FakeState.storage,
    };
    var rich: Address = @splat(0);
    rich[19] = 9;
    const predicates = [_]Predicate{
        .{ .kind = .balance, .operator = .greater_than, .value = 8, .address = rich },
        .{ .kind = .nonce, .operator = .equal, .value = 4 },
        .{ .kind = .storage, .operator = .equal, .value = 2, .slot = 2, .mask = 0b11 },
        block_bound(.less_than_or_equal, 10),
    };
    try testing.expect(try all_match(&predicates, reader, .{ .block_number = 10 }));
    try testing.expect(!try all_match(&predicates, reader, .{ .block_number = 11 }));
}

test "validity: seeded fuzz of block expiry against brute force" {
    var prng = Prng.init(0x76616c);
    for (0..512) |_| {
        var predicates: [4]Predicate = undefined;
        const count = prng.range(1, predicates.len);
        for (predicates[0..count]) |*predicate| {
            predicate.* = block_bound(@fromBackingInt(@intCast(prng.below(6))), prng.below(600));
        }
        const current = prng.below(400);
        const interval: u64 = if (prng.chance(1, 2)) 200 else 2000;
        // Brute force: the greatest block satisfying every bound predicate.
        var upper: ?u256 = null;
        for (predicates[0..count]) |predicate| {
            const most: u256 = switch (predicate.operator) {
                .less_than => if (predicate.value == 0) 0 else predicate.value - 1,
                .less_than_or_equal, .equal => predicate.value,
                else => continue,
            };
            upper = if (upper) |u| @min(u, most) else most;
        }
        const window = (expiry_seconds_max * 1000 + interval - 1) / interval;
        const result = validate_block_expiry(predicates[0..count], current, interval);
        if (upper) |bound| {
            if (bound < current) {
                try testing.expectError(error.ExpiredBlockBound, result);
            } else if (bound > current + window) {
                try testing.expectError(error.BlockExpiryWindowExceeded, result);
            } else try result;
        } else try testing.expectError(error.MissingBlockExpiry, result);
    }
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var text: [96]u8 = undefined;
    for (&text) |*byte| byte.* = smith.value(u8);
    var out: [predicates_max + 1]Predicate = undefined;
    const count = parse_text(&text, &out) catch return;
    try testing.expect(count <= predicates_max + 1);
    validate_batch(out[0..count]) catch {};
}

test "validity: fuzz predicate parsing" {
    try testing.fuzz({}, fuzz_parse, .{});
}

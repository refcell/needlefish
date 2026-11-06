//! Consensus block tags for roxy (proxyd consensus mode, `rewriter.go`): a request whose block
//! parameter is `latest`, explicitly or by omission, is rewritten to the consensus head's
//! number before it is forwarded, so replicas behind a load balancer never answer with an
//! older view than an earlier response. A numeric block parameter (given or rewritten) is
//! reported as the height an upstream must have reached to serve the request.
//!
//! The method table mirrors proxyd's `RewriteRequest` positions: the block parameter of
//! account-state reads and calls is at index 1 (2 for storage and proofs) and defaults to
//! `latest` when omitted; block-by-number reads take it at index 0. `eth_estimateGas`,
//! `eth_createAccessList` (default `latest`) and `eth_feeHistory` (required `newestBlock`)
//! are added. `safe`, `finalized`, `pending`, `earliest`, and block hashes are never
//! rewritten. No allocation: a plan is one edit per request, applied while copying.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const methods = @import("methods.zig");

/// Longest replacement text: `,"0x` + 16 hex digits + `"`.
pub const replacement_size_max = 21;

pub const Param = struct {
    position: u8,
    /// Omitted (exactly `position` params given) means `latest`.
    defaults_latest: bool,
    /// May be an EIP-1898 object (`{"blockNumber":..}` or `{"blockHash":..}`).
    object_allowed: bool,
};

const Rule = struct { name: []const u8, param: Param };

const state_read: Param = .{ .position = 1, .defaults_latest = true, .object_allowed = true };
const slot_read: Param = .{ .position = 2, .defaults_latest = true, .object_allowed = true };
const by_number: Param = .{ .position = 0, .defaults_latest = false, .object_allowed = false };

const rules = [_]Rule{
    .{ .name = "eth_getBalance", .param = state_read },
    .{ .name = "eth_getCode", .param = state_read },
    .{ .name = "eth_getTransactionCount", .param = state_read },
    .{ .name = "eth_call", .param = state_read },
    .{ .name = "eth_estimateGas", .param = state_read },
    .{ .name = "eth_createAccessList", .param = state_read },
    .{ .name = "eth_getStorageAt", .param = slot_read },
    .{ .name = "eth_getProof", .param = slot_read },
    .{ .name = "eth_getBlockByNumber", .param = by_number },
    .{ .name = "eth_getBlockTransactionCountByNumber", .param = by_number },
    .{ .name = "eth_getTransactionByBlockNumberAndIndex", .param = by_number },
    .{ .name = "eth_getUncleCountByBlockNumber", .param = by_number },
    .{ .name = "eth_getUncleByBlockNumberAndIndex", .param = by_number },
    .{ .name = "eth_getBlockReceipts", .param = .{
        .position = 0,
        .defaults_latest = false,
        .object_allowed = true,
    } },
    .{ .name = "eth_feeHistory", .param = .{
        .position = 1,
        .defaults_latest = false,
        .object_allowed = false,
    } },
};

pub fn param_of(name: []const u8) ?Param {
    for (rules) |rule| {
        if (std.mem.eql(u8, rule.name, name)) return rule.param;
    }
    return null;
}

pub const Edit = enum { none, replace, insert_first, insert_next };

/// What to do with one request. Offsets are absolute in the body.
pub const Plan = struct {
    edit: Edit = .none,
    /// `replace`: the range of the `"latest"` string; inserts: `start == end` at the `]`.
    start: u32 = 0,
    end: u32 = 0,
    /// Lowest head an upstream needs to serve the request (0: any).
    height: u64 = 0,
};

/// Plans the rewrite of one request of `body`. `head` is the consensus head, or null while
/// unknown (then `latest` is left alone).
pub fn plan(body: []const u8, entry: *const methods.Entry, head: ?u64) Plan {
    assert(entry.end <= body.len and entry.start < entry.end);
    const name = entry.name() orelse return .{};
    const param = param_of(name) orelse return .{};
    var scanner = json.Scanner.init(body[0..entry.end]);
    scanner.index = entry.start;
    const first = scanner.next() catch return .{};
    assert(first.tag == .object_begin);
    const params_found = find_params(&scanner) catch return .{};
    if (!params_found) return .{};
    const result = plan_params(&scanner, param, head) catch return .{};
    assert(result.end <= entry.end and result.start <= result.end);
    return result;
}

/// Advances to the value of the only `params` key; false if absent or repeated (a repeat
/// would make the upstream's choice of value ambiguous).
fn find_params(scanner: *json.Scanner) json.Error!bool {
    var found: ?json.Scanner = null;
    var members: u32 = 0;
    while (members <= scanner.input.len) : (members += 1) {
        const key = try scanner.next();
        if (key.tag == .object_end) break;
        assert(key.tag == .string and key.key);
        var buffer: [8]u8 = undefined;
        const decoded = json.unescape(key, &buffer) catch "";
        if (std.ascii.eqlIgnoreCase(decoded, "params")) {
            if (found != null) return false;
            found = scanner.*;
        }
        try scanner.skip(try scanner.next());
    }
    scanner.* = found orelse return false;
    return true;
}

fn plan_params(scanner: *json.Scanner, param: Param, head: ?u64) json.Error!Plan {
    const array = try scanner.next();
    if (array.tag != .array_begin) return .{};
    var index: u32 = 0;
    while (index <= scanner.input.len) : (index += 1) {
        const value = try scanner.next();
        if (value.tag == .array_end) {
            if (index != param.position or !param.defaults_latest) return .{};
            const head_number = head orelse return .{};
            const at = scanner.index - 1;
            assert(scanner.input[at] == ']');
            const edit: Edit = if (index == 0) .insert_first else .insert_next;
            return .{ .edit = edit, .start = at, .end = at, .height = head_number };
        }
        if (index == param.position) return plan_value(scanner, value, param, head);
        try scanner.skip(value);
    }
    unreachable; // Every element consumes at least one byte.
}

fn plan_value(scanner: *json.Scanner, value: json.Token, param: Param, head: ?u64) json.Error!Plan {
    if (value.tag == .string) return plan_tag(scanner.input, value, head);
    if (value.tag != .object_begin or !param.object_allowed) return .{};
    var number: ?json.Token = null;
    var members: u32 = 0;
    while (members <= scanner.input.len) : (members += 1) {
        const key = try scanner.next();
        if (key.tag == .object_end) break;
        var buffer: [16]u8 = undefined;
        const decoded = json.unescape(key, &buffer) catch "";
        const member = try scanner.next();
        if (std.mem.eql(u8, decoded, "blockHash")) return .{};
        if (std.mem.eql(u8, decoded, "blockNumber") and member.tag == .string) number = member;
        try scanner.skip(member);
    }
    return plan_tag(scanner.input, number orelse return .{}, head);
}

fn plan_tag(input: []const u8, token: json.Token, head: ?u64) Plan {
    assert(token.tag == .string);
    var buffer: [32]u8 = undefined;
    const text = json.unescape(token, &buffer) catch return .{};
    if (std.mem.eql(u8, text, "latest")) {
        const head_number = head orelse return .{};
        const start: u32 = @intCast(@intFromPtr(token.bytes.ptr) - @intFromPtr(input.ptr) - 1);
        const end: u32 = start + @as(u32, @intCast(token.bytes.len)) + 2;
        assert(input[start] == '"' and input[end - 1] == '"');
        return .{ .edit = .replace, .start = start, .end = end, .height = head_number };
    }
    const number = json.parse_quantity(u64, text) catch return .{};
    return .{ .height = number };
}

/// Writes the replacement text for `edit` (the quoted head number, with a leading comma when
/// it follows another parameter).
pub fn write_replacement(out: *std.Io.Writer, edit: Edit, head: u64) std.Io.Writer.Error!void {
    assert(edit != .none);
    var buffer: [18]u8 = undefined;
    const quantity = json.format_quantity(head, &buffer);
    assert(quantity.len <= 18);
    if (edit == .insert_next) try out.writeByte(',');
    try out.print("\"{s}\"", .{quantity});
}

/// Copies `body[start..end]`, applying `edit` when it lies inside that range.
pub fn copy(
    out: *std.Io.Writer,
    body: []const u8,
    start: u32,
    end: u32,
    edit: Plan,
    head: u64,
) std.Io.Writer.Error!void {
    assert(start <= end and end <= body.len);
    const inside = edit.edit != .none and edit.start >= start and edit.end <= end;
    if (!inside) return out.writeAll(body[start..end]);
    assert(edit.start <= edit.end);
    try out.writeAll(body[start..edit.start]);
    try write_replacement(out, edit.edit, head);
    try out.writeAll(body[edit.end..end]);
}

const testing = std.testing;

fn plan_single(body: []const u8, head: ?u64) !Plan {
    var entries: [methods.batch_max]methods.Entry = undefined;
    const summary = try methods.extract(body, &entries);
    assert(summary.count == 1);
    return plan(body, &entries[0], head);
}

fn rewritten(body: []const u8, head: u64, buffer: []u8) ![]const u8 {
    const result = try plan_single(body, head);
    var writer: std.Io.Writer = .fixed(buffer);
    try copy(&writer, body, 0, @intCast(body.len), result, head);
    return writer.buffered();
}

test "tags: latest is rewritten, explicit or omitted" {
    var buffer: [256]u8 = undefined;
    const balance = "{\"method\":\"eth_getBalance\",\"params\":[\"0x01\", \"latest\"],\"id\":1}";
    try testing.expectEqualStrings(
        "{\"method\":\"eth_getBalance\",\"params\":[\"0x01\", \"0x64\"],\"id\":1}",
        try rewritten(balance, 100, &buffer),
    );
    const call = "{\"method\":\"eth_call\",\"params\":[{\"to\":\"0x02\"} ],\"id\":2}";
    try testing.expectEqualStrings(
        "{\"method\":\"eth_call\",\"params\":[{\"to\":\"0x02\"} ,\"0xff\"],\"id\":2}",
        try rewritten(call, 255, &buffer),
    );
    const block = "{\"method\":\"eth_getBlockByNumber\",\"params\":[\"latest\",false]}";
    try testing.expectEqualStrings(
        "{\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x0\",false]}",
        try rewritten(block, 0, &buffer),
    );
    const object = "{\"method\":\"eth_getProof\",\"Params\":[\"0x1\",[]," ++
        "{\"blockNumber\":\"latest\"}]}";
    try testing.expectEqualStrings(
        "{\"method\":\"eth_getProof\",\"Params\":[\"0x1\",[],{\"blockNumber\":\"0x7\"}]}",
        try rewritten(object, 7, &buffer),
    );
    try testing.expectEqual(@as(u64, 7), (try plan_single(object, 7)).height);
}

test "tags: what is left alone" {
    const untouched = [_][]const u8{
        "{\"method\":\"eth_chainId\",\"params\":[]}",
        "{\"method\":\"eth_getBalance\",\"params\":[\"0x1\",\"safe\"]}",
        "{\"method\":\"eth_getBalance\",\"params\":[\"0x1\",\"pending\"]}",
        "{\"method\":\"eth_getBalance\",\"params\":[]}",
        "{\"method\":\"eth_getBalance\"}",
        "{\"method\":\"eth_getBlockByNumber\",\"params\":[]}",
        "{\"method\":\"eth_feeHistory\",\"params\":[\"0x4\"]}",
        "{\"method\":\"eth_getCode\",\"params\":[\"0x1\",{\"blockHash\":\"0x2\"}]}",
        "{\"method\":\"eth_getBalance\",\"params\":[\"0x1\",\"latest\"],\"params\":[]}",
        "{\"method\":\"eth_getBlockByNumber\",\"params\":[{\"blockNumber\":\"latest\"}]}",
    };
    for (untouched) |body| try testing.expectEqual(Edit.none, (try plan_single(body, 5)).edit);
    // Unknown head: nothing is rewritten.
    const latest = "{\"method\":\"eth_getBalance\",\"params\":[\"0x1\",\"latest\"]}";
    try testing.expectEqual(Edit.none, (try plan_single(latest, null)).edit);
    // Explicit numbers only report a height.
    const numbered = "{\"method\":\"eth_getBalance\",\"params\":[\"0x1\",\"0x2a\"]}";
    const result = try plan_single(numbered, 5);
    try testing.expectEqual(Edit.none, result.edit);
    try testing.expectEqual(@as(u64, 42), result.height);
}

/// Never crashes; a rewritten body is valid JSON whenever the input was.
fn check_arbitrary(body: []const u8, head: u64) !void {
    var entries: [methods.batch_max]methods.Entry = undefined;
    const summary = methods.extract(body, &entries) catch return;
    var buffer: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var previous: u32 = 0;
    for (entries[0..summary.count]) |*entry| {
        const result = plan(body, entry, head);
        try writer.writeAll(body[previous..entry.start]);
        try copy(&writer, body, entry.start, entry.end, result, head);
        previous = entry.end;
    }
    try writer.writeAll(body[previous..]);
    try json.validate(writer.buffered());
}

test "tags: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0x7a65);
    const pieces = [_][]const u8{
        "{",                "}",                  "[",          "]",        ",",
        ":",                "\"method\"",         "\"params\"", "\"id\"",   "\"latest\"",
        "\"eth_getCode\"",  "\"eth_call\"",       "1",          "\"0x1\"",  "null",
        "\"blockNumber\"",  "\"blockHash\"",      " ",          "\"safe\"", "\"Params\"",
        "\"eth_getProof\"", "\"eth_feeHistory\"",
    };
    var input: [512]u8 = undefined;
    for (0..6000) |_| {
        var writer: std.Io.Writer = .fixed(&input);
        const parts = prng.below(40);
        for (0..parts) |_| writer.writeAll(pieces[prng.below(pieces.len)]) catch break;
        try check_arbitrary(writer.buffered(), prng.below(1 << 20));
    }
}

fn fuzz_plan(context: void, smith: *std.testing.Smith) anyerror!void {
    _ = context;
    var input: [1024]u8 = undefined;
    const size = smith.slice(&input);
    try check_arbitrary(input[0..size], 0x1234);
}

test "tags: fuzz plan" {
    try testing.fuzz({}, fuzz_plan, .{});
}

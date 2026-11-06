//! eth_sendRawTransactionSync (EIP-7966, as base/base serves it through reth): submits a
//! raw transaction like eth_sendRawTransaction, then answers with its receipt once the
//! transaction is canonical, or with error 4 (and the hash as data) after the timeout.
//!
//! The router stays synchronous: the handler adds the transaction and records it in the
//! transport's `Request`; the HTTP service then parks the connection in a `Waiters` slot
//! and resumes it from a timer (`sweep`). A transport without `Request` (null `Api.sync`)
//! does not serve the method; a batch, or a full waiter table, is refused before the
//! transaction is submitted. A positive `timeoutMs` shortens, never extends, the
//! configured wait; zero or none uses it. Timing out does not remove the transaction.

const std = @import("std");
const assert = std.debug.assert;
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const eth = @import("eth.zig");

const Hash = [32]u8;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

/// EIP-7966: the transaction was added but not included within the timeout.
pub const timeout_code: i32 = 4;
/// Longest request id a parked call keeps (longer ids are refused up front).
pub const id_size_max = 64;

pub const methods = [_]rpc.Method(*eth.Api){
    .{ .name = "eth_sendRawTransactionSync", .handler = send_raw_transaction_sync },
};

/// Set by the transport before routing a body; filled by the handler on success.
pub const Request = struct {
    /// The body is a single call (not a batch) with a short enough id.
    single: bool = false,
    /// The transport has a free waiter slot.
    slot_free: bool = false,
    /// The configured (maximal) wait.
    timeout_ms_max: u64,
    /// Out: the submitted transaction and its wait, for the transport to park.
    hash: ?Hash = null,
    timeout_ms: u64 = 0,

    /// Resets the request for the next body.
    pub fn prepare(request: *Request, single: bool, slot_free: bool) void {
        assert(request.timeout_ms_max > 0);
        request.single = single;
        request.slot_free = slot_free;
        request.hash = null;
        request.timeout_ms = 0;
    }
};

fn send_raw_transaction_sync(api: *eth.Api, call: *Call) HandlerError!void {
    const raw = try call.params.data(api.scratch[0 .. api.scratch.len / 2]);
    const timeout_raw = try call.params.optional_raw();
    try call.params.finish();
    const request = api.sync orelse {
        return call.fail(rpc.code.method_not_found, "eth_sendRawTransactionSync unavailable");
    };
    const requested_ms = try parse_timeout(timeout_raw);
    if (!request.single) {
        return call.fail(rpc.code.invalid_request, "eth_sendRawTransactionSync in a batch");
    }
    if (!request.slot_free) {
        return call.fail(rpc.code.server_error, "too many pending synchronous transactions");
    }
    const hash = try eth.add_raw(api, call, raw);
    request.hash = hash;
    request.timeout_ms = effective_timeout_ms(requested_ms, request.timeout_ms_max);
    assert(request.timeout_ms > 0 and request.timeout_ms <= request.timeout_ms_max);
    // Written for transports that cannot park: they answer like eth_sendRawTransaction.
    try call.writer.data(&hash);
}

/// `timeoutMs`: a JSON number (as reth reads it) or a hex quantity; null when absent.
pub fn parse_timeout(raw: ?[]const u8) HandlerError!?u64 {
    const text = raw orelse return null;
    assert(text.len > 0);
    if (std.mem.eql(u8, text, "null")) return null;
    if (text[0] == '"') {
        if (text.len < 2 or text[text.len - 1] != '"') return error.InvalidParams;
        return json.parse_quantity(u64, text[1 .. text.len - 1]) catch error.InvalidParams;
    }
    return std.fmt.parseInt(u64, text, 10) catch error.InvalidParams;
}

pub fn effective_timeout_ms(requested_ms: ?u64, max_ms: u64) u64 {
    assert(max_ms > 0);
    const requested = requested_ms orelse return max_ms;
    if (requested == 0) return max_ms;
    const result = @min(requested, max_ms);
    assert(result > 0);
    return result;
}

/// The request id of a single-call body, if it fits a waiter slot ("null" without one).
pub fn request_id(body: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimStart(u8, body, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '{') return null; // A batch, or not JSON-RPC.
    const id = (json.find_path(body, &.{"id"}) catch return null) orelse return "null";
    if (id.len == 0 or id.len > id_size_max) return null;
    return id;
}

/// Parked eth_sendRawTransactionSync calls: at most `capacity`, each with its transport
/// `Token`, transaction, deadline and request id.
pub fn Waiters(comptime Token: type, comptime capacity: u32) type {
    comptime assert(capacity > 0);
    return struct {
        const Self = @This();

        slots: [capacity]Slot = undefined,
        used: [capacity]bool = @splat(false),
        count: u32 = 0,

        pub const Slot = struct {
            token: Token,
            hash: Hash,
            deadline_ns: u64,
            timeout_ms: u64,
            id: [id_size_max]u8,
            id_size: u8,

            pub fn id_text(slot: *const Slot) []const u8 {
                return slot.id[0..slot.id_size];
            }
        };

        pub const Outcome = enum { included, timed_out };

        pub fn full(waiters: *const Self) bool {
            return waiters.count == capacity;
        }

        pub fn add(
            waiters: *Self,
            token: Token,
            hash: Hash,
            now_ns: u64,
            timeout_ms: u64,
            id: []const u8,
        ) void {
            assert(!waiters.full());
            assert(timeout_ms > 0);
            assert(id.len > 0 and id.len <= id_size_max);
            for (&waiters.used, 0..) |*used, index| {
                if (used.*) continue;
                used.* = true;
                waiters.count += 1;
                const slot = &waiters.slots[index];
                slot.* = .{
                    .token = token,
                    .hash = hash,
                    .deadline_ns = now_ns +| timeout_ms *| std.time.ns_per_ms,
                    .timeout_ms = timeout_ms,
                    .id = undefined,
                    .id_size = @intCast(id.len),
                };
                @memcpy(slot.id[0..id.len], id);
                return;
            }
            unreachable; // Not full, so a slot is free.
        }

        /// Answers every waiter whose transaction is canonical (`included(context, hash)`)
        /// or whose deadline passed, through `finish(context, slot, outcome)`, and frees it.
        /// A waiter whose transport dropped it (`alive` false) is freed silently.
        pub fn sweep(
            waiters: *Self,
            now_ns: u64,
            context: anytype,
            comptime alive: fn (@TypeOf(context), Token) bool,
            comptime included: fn (@TypeOf(context), Hash) bool,
            comptime finish: fn (@TypeOf(context), *const Slot, Outcome) void,
        ) void {
            const count_before = waiters.count;
            for (&waiters.used, &waiters.slots) |*used, *slot| {
                if (!used.*) continue;
                if (!alive(context, slot.token)) {
                    // Dropped by the transport (it timed out or stopped).
                } else if (included(context, slot.hash)) {
                    finish(context, slot, .included);
                } else if (now_ns >= slot.deadline_ns) {
                    finish(context, slot, .timed_out);
                } else continue;
                used.* = false;
                waiters.count -= 1;
            }
            assert(waiters.count <= count_before);
        }
    };
}

/// The deferred answer for an included transaction: the receipt as the result.
pub fn write_included(api: *eth.Api, out: *std.Io.Writer, id: []const u8, hash: Hash) bool {
    const start = out.end;
    var writer = json.Writer.init(out);
    write_receipt_response(api, &writer, out, id, hash) catch {
        out.end = start;
        return false;
    };
    return true;
}

fn write_receipt_response(
    api: *eth.Api,
    writer: *json.Writer,
    out: *std.Io.Writer,
    id: []const u8,
    hash: Hash,
) !void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try out.writeAll(id);
    try out.writeAll(",\"result\":");
    if (!try eth.write_receipt(api, writer, hash)) return error.Unknown;
    try out.writeByte('}');
}

/// The deferred answer after the timeout: error 4 with the hash as data (EIP-7966).
pub fn write_timed_out(
    out: *std.Io.Writer,
    id: []const u8,
    hash: Hash,
    timeout_ms: u64,
) std.Io.Writer.Error!void {
    try out.writeAll("{\"jsonrpc\":\"2.0\",\"id\":");
    try out.writeAll(id);
    try out.print(",\"error\":{{\"code\":{d},\"message\":\"transaction 0x{x} was added to " ++
        "the mempool but wasn't confirmed within {d} ms\",\"data\":\"0x{x}\"}}}}", .{
        timeout_code,
        &hash,
        timeout_ms,
        &hash,
    });
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "send_sync: timeouts parse as numbers or quantities and never extend the maximum" {
    try testing.expectEqual(@as(?u64, null), try parse_timeout(null));
    try testing.expectEqual(@as(?u64, null), try parse_timeout("null"));
    try testing.expectEqual(@as(?u64, 1500), try parse_timeout("1500"));
    try testing.expectEqual(@as(?u64, 255), try parse_timeout("\"0xff\""));
    try testing.expectError(error.InvalidParams, parse_timeout("-1"));
    try testing.expectError(error.InvalidParams, parse_timeout("\"12\""));
    try testing.expectError(error.InvalidParams, parse_timeout("true"));
    try testing.expectEqual(@as(u64, 100), effective_timeout_ms(null, 100));
    try testing.expectEqual(@as(u64, 100), effective_timeout_ms(0, 100));
    try testing.expectEqual(@as(u64, 40), effective_timeout_ms(40, 100));
    try testing.expectEqual(@as(u64, 100), effective_timeout_ms(1 << 63, 100));
}

test "send_sync: request ids of single calls" {
    try testing.expectEqualStrings("7", request_id("{\"jsonrpc\":\"2.0\",\"id\":7}").?);
    try testing.expectEqualStrings("\"a\"", request_id("{\"id\":\"a\",\"method\":\"x\"}").?);
    try testing.expectEqualStrings("null", request_id("{\"method\":\"x\"}").?);
    try testing.expect(request_id("[{\"id\":1}]") == null); // A batch.
    const long = "{\"id\":\"" ++ @as([id_size_max]u8, @splat('a')) ++ "\"}";
    try testing.expect(request_id(long) == null);
    try testing.expect(request_id("{\"id\":") == null);
}

const Fake = struct {
    alive: [8]bool = @splat(true),
    included: [8]bool = @splat(false),
    finished: [8]?FakeWaiters.Outcome = @splat(null),

    fn is_alive(fake: *Fake, token: u32) bool {
        return fake.alive[token];
    }

    fn is_included(fake: *Fake, hash: Hash) bool {
        return fake.included[hash[0]];
    }

    fn finish(fake: *Fake, slot: *const FakeWaiters.Slot, outcome: FakeWaiters.Outcome) void {
        assert(fake.finished[slot.token] == null);
        assert(slot.hash[0] == slot.token);
        fake.finished[slot.token] = outcome;
    }
};
const FakeWaiters = Waiters(u32, 4);

test "send_sync: waiters answer inclusion, time out, and drop dead connections" {
    var waiters: FakeWaiters = .{};
    var fake: Fake = .{};
    for (0..4) |index| {
        const token: u32 = @intCast(index);
        waiters.add(token, @splat(@intCast(index)), 0, 10 * (index + 1), "1");
    }
    try testing.expect(waiters.full());
    fake.included[1] = true;
    fake.alive[2] = false;
    waiters.sweep(15 * std.time.ns_per_ms, &fake, Fake.is_alive, Fake.is_included, Fake.finish);
    try testing.expectEqual(FakeWaiters.Outcome.timed_out, fake.finished[0].?);
    try testing.expectEqual(FakeWaiters.Outcome.included, fake.finished[1].?);
    try testing.expect(fake.finished[2] == null and fake.finished[3] == null);
    try testing.expectEqual(@as(u32, 1), waiters.count);
    // The freed slots are reused; the survivor keeps its deadline.
    waiters.add(5, @splat(5), 15 * std.time.ns_per_ms, 1, "\"x\"");
    waiters.sweep(40 * std.time.ns_per_ms, &fake, Fake.is_alive, Fake.is_included, Fake.finish);
    try testing.expectEqual(FakeWaiters.Outcome.timed_out, fake.finished[3].?);
    try testing.expectEqual(FakeWaiters.Outcome.timed_out, fake.finished[5].?);
    try testing.expectEqual(@as(u32, 0), waiters.count);
}

/// Random adds and sweeps: every waiter is answered exactly once (or dropped), never
/// before its deadline unless included, and the count matches the live slots.
fn waiters_scenario(seed: u64) !void {
    var prng = Prng.init(seed);
    var waiters: FakeWaiters = .{};
    var fake: Fake = .{};
    var now_ns: u64 = 0;
    var added: [8]bool = @splat(false);
    var deadline_ns: [8]u64 = @splat(0);
    for (0..32) |_| {
        now_ns += prng.below(20) * std.time.ns_per_ms;
        const token: u32 = @intCast(prng.below(8));
        if (!added[token] and !waiters.full() and prng.chance(1, 2)) {
            const timeout_ms = 1 + prng.below(50);
            waiters.add(token, @splat(@intCast(token)), now_ns, timeout_ms, "1");
            added[token] = true;
            deadline_ns[token] = now_ns + timeout_ms * std.time.ns_per_ms;
        }
        if (prng.chance(1, 4)) fake.included[prng.below(8)] = true;
        if (prng.chance(1, 8)) fake.alive[prng.below(8)] = false;
        waiters.sweep(now_ns, &fake, Fake.is_alive, Fake.is_included, Fake.finish);
        var live: u32 = 0;
        for (waiters.used) |used| live += @intFromBool(used);
        try testing.expectEqual(live, waiters.count);
        for (fake.finished, 0..) |finished, index| {
            const outcome = finished orelse continue;
            try testing.expect(added[index]);
            if (outcome == .timed_out) try testing.expect(now_ns >= deadline_ns[index]);
        }
    }
}

test "send_sync: seeded fuzz of the waiter table" {
    for (0..256) |seed| try waiters_scenario(seed);
}

fn fuzz_send_sync(_: void, smith: *std.testing.Smith) anyerror!void {
    try waiters_scenario(smith.value(u64));
    var text: [24]u8 = undefined;
    for (&text) |*byte| byte.* = smith.value(u8);
    const length = smith.value(u8) % text.len;
    if (length > 0) _ = parse_timeout(text[0..length]) catch {};
    _ = request_id(text[0..length]);
}

test "send_sync: fuzz waiters, timeouts and request ids" {
    try testing.fuzz({}, fuzz_send_sync, .{});
}

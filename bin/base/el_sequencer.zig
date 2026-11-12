//! Forwarding to the sequencer (`--rollup.sequencer-http <url>`, base/base and op-geth's
//! flag): Base blocks are built by the sequencer alone, so a transaction sent to a follower
//! node only gets included once the sequencer has it. As base/base's `SequencerClient`,
//! el-run's `eth_sendRawTransaction` forwards the raw transaction and answers with the
//! sequencer's answer (its hash, or its error); the transaction also enters el-run's own
//! pool, whatever the pool thinks of it.
//!
//! Each forward is one `eth_sendRawTransaction` POST on a `std.Io` concurrent task with its
//! own HTTPS client (`https_bridge.Worker`: a deadline over every attempt, retries with
//! backoff; a resent transaction is refused by its nonce), so a slow sequencer never holds
//! the thread that executes blocks. At most `slots_max` forwards run at once; another is
//! refused until one ends. The RPC thread parks the HTTP response (`Deferred`) and `poll`
//! resumes it once the task is done. A forward from a batch is not waited for: the batch
//! answers with the local hash, and the sequencer's answer is only counted.

const std = @import("std");
const base = @import("base");
const https_bridge = @import("https_bridge.zig");

const Io = std.Io;
const json = base.utilities.json;
const http = base.utilities.http;
const assert = std.debug.assert;
const Hash = [32]u8;

pub const slots_max = 8;
/// Longest request id a parked call keeps (longer ones are not parked).
pub const id_size_max = 64;
/// The forwarded JSON-RPC body: the raw transaction in hex and a fixed envelope.
const body_size_max = 2 * (1 << 20) + 256;
const response_size_max = 64 * 1024;
const timeout_ms = 10_000;
const retries = 2;

pub const Stats = struct {
    forwarded: u64 = 0,
    /// Answers with a result (the sequencer took the transaction).
    accepted: u64 = 0,
    /// Answers with a JSON-RPC error (the sequencer refused it).
    refused: u64 = 0,
    /// No usable answer: transport failure, timeout, or a non-JSON-RPC response.
    failed: u64 = 0,
    /// Refused here because every slot was busy.
    busy: u64 = 0,
};

const Slot = struct {
    worker: https_bridge.Worker,
    body: []u8,
    body_len: u32 = 0,
    running: bool = false,
    /// Set by the task as its last step; read by `poll` on the RPC thread.
    done: std.atomic.Value(bool) = .init(false),
    future: Io.Future(void) = undefined,
    forwarded: https_bridge.Worker.Forwarded = undefined,
    /// The parked response, when the caller waits for the answer.
    token: ?http.Deferred = null,
    id: [id_size_max]u8 = undefined,
    id_len: u8 = 0,
};

pub const Forwarder = struct {
    io: Io,
    url: []const u8,
    settings: https_bridge.Settings,
    slots: [slots_max]Slot,
    stats: Stats = .{},

    pub fn create(gpa: std.mem.Allocator, io: Io, url: []const u8) !*Forwarder {
        if (!std.mem.startsWith(u8, url, "http://") and !std.mem.startsWith(u8, url, "https://")) {
            return error.InvalidSequencerUrl;
        }
        if (url.len > https_bridge.upstream_size_max) return error.InvalidSequencerUrl;
        const forwarder = try gpa.create(Forwarder);
        errdefer gpa.destroy(forwarder);
        forwarder.* = .{
            .io = io,
            .url = url,
            .settings = .{
                .connections_max = slots_max,
                .request_size_max = body_size_max,
                .response_size_max = response_size_max,
                .timeout_ms = timeout_ms,
                .retries = retries,
                .verbose = false,
            },
            .slots = undefined,
        };
        const route: https_bridge.Route = .{ .port = 0, .upstream = url };
        var initialized: u32 = 0;
        errdefer for (forwarder.slots[0..initialized]) |*slot| slot_deinit(gpa, slot);
        for (&forwarder.slots) |*slot| {
            slot.* = .{ .worker = undefined, .body = try gpa.alloc(u8, body_size_max) };
            errdefer gpa.free(slot.body);
            try slot.worker.init(gpa, io, route, &forwarder.settings);
            initialized += 1;
        }
        assert(initialized == slots_max);
        return forwarder;
    }

    fn slot_deinit(gpa: std.mem.Allocator, slot: *Slot) void {
        slot.worker.deinit();
        gpa.free(slot.body);
    }

    pub fn destroy(forwarder: *Forwarder, gpa: std.mem.Allocator) void {
        for (&forwarder.slots) |*slot| {
            if (slot.running) slot.future.await(forwarder.io);
            slot_deinit(gpa, slot);
        }
        gpa.destroy(forwarder);
    }

    /// A slot with no forward running, or null (the caller refuses the transaction).
    pub fn slot_free(forwarder: *Forwarder) ?u32 {
        for (&forwarder.slots, 0..) |*slot, index| {
            if (!slot.running) return @intCast(index);
        }
        forwarder.stats.busy += 1;
        return null;
    }

    /// Starts forwarding `raw` on slot `index` (from `slot_free`).
    pub fn submit(forwarder: *Forwarder, index: u32, raw: []const u8) void {
        const slot = &forwarder.slots[index];
        assert(!slot.running);
        assert(raw.len > 0 and 2 * raw.len + 128 <= slot.body.len);
        var writer: Io.Writer = .fixed(slot.body);
        writer.print("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\"," ++
            "\"params\":[\"0x{x}\"]}}", .{raw}) catch unreachable; // Sized above.
        slot.body_len = @intCast(writer.buffered().len);
        slot.running = true;
        slot.token = null;
        slot.done.store(false, .release);
        forwarder.stats.forwarded += 1;
        slot.future = forwarder.io.concurrent(run, .{ slot, forwarder.url }) catch {
            // No concurrency available: forward on this thread.
            run(slot, forwarder.url);
            slot.future = .{ .any_future = null, .result = {} };
            return;
        };
    }

    /// Parks the HTTP response of slot `index`'s request until its answer (`id`: the
    /// request id, as JSON).
    pub fn park(forwarder: *Forwarder, index: u32, token: http.Deferred, id: []const u8) void {
        const slot = &forwarder.slots[index];
        assert(slot.running and slot.token == null);
        assert(id.len > 0 and id.len <= id_size_max);
        slot.token = token;
        @memcpy(slot.id[0..id.len], id);
        slot.id_len = @intCast(id.len);
    }

    fn run(slot: *Slot, url: []const u8) void {
        const headers: https_bridge.Headers = blk: {
            var headers: https_bridge.Headers = .{};
            const content_type = "application/json";
            @memcpy(headers.content_type.bytes[0..content_type.len], content_type);
            headers.content_type.len = content_type.len;
            headers.content_type.present = true;
            break :blk headers;
        };
        slot.forwarded = slot.worker.forward(&.{
            .method = .POST,
            .url = url,
            .body = slot.body[0..slot.body_len],
            .headers = &headers,
        });
        slot.done.store(true, .release);
    }

    /// Answers the parked responses whose forward ended; frees their slots.
    pub fn poll(forwarder: *Forwarder, server: anytype) void {
        for (&forwarder.slots) |*slot| {
            if (!slot.running or !slot.done.load(.acquire)) continue;
            slot.future.await(forwarder.io);
            slot.running = false;
            const answer = forwarder.answer_of(slot);
            const token = slot.token orelse continue;
            slot.token = null;
            const context: Resume = .{ .id = slot.id[0..slot.id_len], .answer = answer };
            // False: the client went away (or timed out) meanwhile; nothing to send.
            _ = server.resume_deferred(token, &context, Resume.write);
        }
    }

    /// What the sequencer said: its `result` or `error` JSON, else a local error.
    fn answer_of(forwarder: *Forwarder, slot: *Slot) Answer {
        const reason = switch (slot.forwarded.fetched) {
            .answered => |answered| {
                const body = slot.worker.response_body[0..answered.length];
                if (json.find_path(body, &.{"result"}) catch null) |result| {
                    forwarder.stats.accepted += 1;
                    return .{ .result = result };
                }
                if (json.find_path(body, &.{"error"}) catch null) |err| {
                    forwarder.stats.refused += 1;
                    return .{ .err = err };
                }
                forwarder.stats.failed += 1;
                return .{ .failed = "sequencer answered without a JSON-RPC result" };
            },
            .failed => "sequencer unreachable",
            .timed_out => "sequencer timed out",
            .too_large => "sequencer answer too large",
        };
        forwarder.stats.failed += 1;
        return .{ .failed = reason };
    }

    pub fn summary(forwarder: *const Forwarder) void {
        const stats = &forwarder.stats;
        std.debug.print("sequencer: {d} forwarded, {d} accepted, {d} refused, {d} failed, " ++
            "{d} busy\n", .{
            stats.forwarded, stats.accepted, stats.refused, stats.failed, stats.busy,
        });
    }
};

const Answer = union(enum) { result: []const u8, err: []const u8, failed: []const u8 };

const Resume = struct {
    id: []const u8,
    answer: Answer,

    fn write(context: *const Resume, response: *http.ResponseBuilder) void {
        const out = response.writer();
        response.content_type = "application/json";
        write_answer(out, context.id, context.answer) catch {
            response.fail(500);
        };
    }
};

fn write_answer(out: *Io.Writer, id: []const u8, answer: Answer) Io.Writer.Error!void {
    try out.print("{{\"jsonrpc\":\"2.0\",\"id\":{s},", .{id});
    switch (answer) {
        .result => |result| try out.print("\"result\":{s}}}", .{result}),
        .err => |err| try out.print("\"error\":{s}}}", .{err}),
        .failed => |reason| try out.print(
            "\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}}}",
            .{reason},
        ),
    }
}

test "el sequencer: answers carry the caller's id and the sequencer's result or error" {
    var buffer: [256]u8 = undefined;
    var out: Io.Writer = .fixed(&buffer);
    const sequencer = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xab\"}";
    const result = (try json.find_path(sequencer, &.{"result"})).?;
    try write_answer(&out, "\"call-7\"", .{ .result = result });
    try std.testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"id\":\"call-7\",\"result\":\"0xab\"}",
        out.buffered(),
    );
    out = .fixed(&buffer);
    const refused = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":" ++
        "{\"code\":-32000,\"message\":\"nonce too low\"}}";
    const err = (try json.find_path(refused, &.{"error"})).?;
    try write_answer(&out, "42", .{ .err = err });
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":42,\"error\":" ++
        "{\"code\":-32000,\"message\":\"nonce too low\"}}", out.buffered());
}

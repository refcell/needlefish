//! `--l1-ws-url`: an L1 `newHeads` WebSocket subscription that wakes the batcher's step
//! loop when an L1 block arrives instead of after a full poll interval (base/base's hybrid
//! L1 head source). Optional, so it fails safe: a URL it cannot use, a refused connection
//! or a dropped subscription only logs and leaves polling in charge, and the reader
//! reconnects with a bounded backoff.
//!
//! Binary-only glue on `std.Io` (a concurrent reader task); the frame codec and accept key
//! come from `utilities/ws`. Plain `ws://` only: there is no TLS in the standard library.

const std = @import("std");
const base = @import("base");
const ws = base.utilities.ws;

const Io = std.Io;
const assert = std.debug.assert;

pub const Target = struct {
    host: []const u8,
    port: u16,
    /// Request path including any query; "/" when the URL has none.
    path: []const u8,
};

pub const UrlError = error{ UnsupportedScheme, InvalidUrl };

/// Splits `ws://host[:port][/path]`. The host keeps its brackets off for IPv6 literals.
pub fn parse_url(url: []const u8) UrlError!Target {
    const scheme = "ws://";
    if (std.mem.startsWith(u8, url, "wss://")) return error.UnsupportedScheme;
    if (!std.mem.startsWith(u8, url, scheme)) return error.UnsupportedScheme;
    const rest = url[scheme.len..];
    const authority_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..authority_end];
    const path = if (authority_end == rest.len) "/" else rest[authority_end..];
    if (authority.len == 0) return error.InvalidUrl;
    var host = authority;
    var port: u16 = 80;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        const bracketed = std.mem.indexOfScalar(u8, authority, ']');
        if (bracketed == null or bracketed.? < colon) {
            host = authority[0..colon];
            port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch
                return error.InvalidUrl;
        }
    }
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        host = host[1 .. host.len - 1];
    }
    if (host.len == 0 or port == 0) return error.InvalidUrl;
    assert(path.len > 0 and path[0] == '/');
    return .{ .host = host, .port = port, .path = path };
}

pub fn write_handshake(w: *Io.Writer, target: Target, key: []const u8) Io.Writer.Error!void {
    assert(key.len > 0);
    try w.print("GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n\r\n", .{
        target.path,
        target.host,
        target.port,
        key,
    });
}

pub const HandshakeError = error{ NotSwitchingProtocols, BadAccept };

/// Checks one response header line; `status_seen` tracks the status line. Returns true
/// once the accept header matched.
pub fn check_handshake_line(
    line: []const u8,
    status_seen: *bool,
    key: []const u8,
) HandshakeError!bool {
    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
    if (!status_seen.*) {
        status_seen.* = true;
        if (!std.mem.startsWith(u8, trimmed, "HTTP/1.1 101")) return error.NotSwitchingProtocols;
        return false;
    }
    const name = "sec-websocket-accept:";
    if (trimmed.len < name.len or !std.ascii.eqlIgnoreCase(trimmed[0..name.len], name)) {
        return false;
    }
    const value = std.mem.trim(u8, trimmed[name.len..], " \t");
    const expected = ws.accept_key(key);
    if (!std.mem.eql(u8, value, &expected)) return error.BadAccept;
    return true;
}

/// A notification of the `newHeads` subscription (the only one this client makes).
pub fn is_notification(payload: []const u8) bool {
    return std.mem.indexOf(u8, payload, "\"eth_subscription\"") != null;
}

/// A masked client frame (RFC 6455: clients mask every frame) into `out`.
pub fn encode_client_frame(
    out: []u8,
    opcode: ws.Opcode,
    payload: []const u8,
    mask: [4]u8,
) []const u8 {
    var header: [ws.frame.header_size_max]u8 = undefined;
    const header_size = ws.encode_header(&header, true, opcode, payload.len, mask);
    assert(out.len >= header_size + payload.len);
    @memcpy(out[0..header_size], header[0..header_size]);
    @memcpy(out[header_size..][0..payload.len], payload);
    ws.apply_mask(mask, out[header_size..][0..payload.len], 0);
    return out[0 .. header_size + payload.len];
}

const subscribe_request =
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_subscribe\",\"params\":[\"newHeads\"]}";
const backoff_ms_min = 1000;
const backoff_ms_max = 30_000;
const read_buffer_bytes = 64 * 1024;

pub const L1HeadSubscription = struct {
    io: Io,
    target: Target,
    /// `newHeads` notifications received; the step loop wakes when it changes.
    heads: std.atomic.Value(u64) = .init(0),
    task: ?Io.Future(void) = null,
    /// Tests silence the state-change logs (the test runner fails on stderr output).
    quiet: bool = false,

    /// Starts the reader task; without concurrency (or a usable URL) polling stays alone.
    pub fn start(sub: *L1HeadSubscription) void {
        assert(sub.task == null);
        sub.task = sub.io.concurrent(run, .{sub}) catch {
            std.debug.print("batcher: --l1-ws-url needs a concurrent Io; polling only\n", .{});
            return;
        };
    }

    fn run(sub: *L1HeadSubscription) void {
        var backoff_ms: u64 = backoff_ms_min;
        while (true) {
            const before = sub.heads.load(.monotonic);
            sub.session() catch |err| {
                if (err == error.Canceled) return;
                sub.log("batcher: L1 WS subscription to {s}:{d}: {t}; polling\n", .{
                    sub.target.host,
                    sub.target.port,
                    err,
                });
            };
            // A session that delivered heads resets the backoff.
            if (sub.heads.load(.monotonic) != before) backoff_ms = backoff_ms_min;
            sub.io.sleep(.fromMilliseconds(@intCast(backoff_ms)), .awake) catch return;
            backoff_ms = @min(backoff_ms * 2, backoff_ms_max);
            assert(backoff_ms >= backoff_ms_min and backoff_ms <= backoff_ms_max);
        }
    }

    fn session(sub: *L1HeadSubscription) !void {
        const host = try Io.net.HostName.init(sub.target.host);
        // No connect timeout (the std lacks one for TCP connects); the reader is its own
        // task, so a slow connect only delays early wake-ups, never a batcher step.
        const stream = try host.connect(sub.io, sub.target.port, .{ .mode = .stream });
        defer stream.close(sub.io);
        var write_buffer: [1024]u8 = undefined;
        var read_buffer: [read_buffer_bytes]u8 = undefined;
        var writer = stream.writer(sub.io, &write_buffer);
        var reader = stream.reader(sub.io, &read_buffer);
        try sub.handshake(&writer.interface, &reader.interface);
        var frame: [subscribe_request.len + ws.frame.header_size_max]u8 = undefined;
        const request = encode_client_frame(&frame, .text, subscribe_request, sub.mask());
        try writer.interface.writeAll(request);
        try writer.interface.flush();
        sub.log("batcher: L1 WS newHeads subscription to {s}:{d} active\n", .{
            sub.target.host,
            sub.target.port,
        });
        try sub.read_frames(&writer.interface, &reader.interface);
    }

    fn log(sub: *const L1HeadSubscription, comptime format: []const u8, args: anytype) void {
        if (!sub.quiet) std.debug.print(format, args);
    }

    fn mask(sub: *L1HeadSubscription) [4]u8 {
        var bytes: [4]u8 = undefined;
        sub.io.random(&bytes);
        return bytes;
    }

    fn handshake(sub: *L1HeadSubscription, w: *Io.Writer, r: *Io.Reader) !void {
        var nonce: [16]u8 = undefined;
        sub.io.random(&nonce);
        var key: [24]u8 = undefined;
        const encoded = std.base64.standard.Encoder.encode(&key, &nonce);
        assert(encoded.len == key.len);
        try write_handshake(w, sub.target, &key);
        try w.flush();
        var status_seen = false;
        var accepted = false;
        for (0..64) |_| {
            const line = try r.takeDelimiterInclusive('\n');
            if (std.mem.eql(u8, line, "\r\n")) break;
            if (try check_handshake_line(line, &status_seen, &key)) accepted = true;
        } else return error.HandshakeTooLong;
        if (!accepted) return error.BadAccept;
    }

    /// Until the connection closes: counts notifications and answers pings.
    fn read_frames(sub: *L1HeadSubscription, w: *Io.Writer, r: *Io.Reader) !void {
        const limits: ws.Limits = .{ .payload_size_max = read_buffer_bytes / 2 };
        while (true) {
            const decoded = try ws.decode_frame(r.buffered(), .client, limits);
            const frame = switch (decoded) {
                .incomplete => {
                    try r.fillMore();
                    continue;
                },
                .frame => |frame| frame,
            };
            switch (frame.header.opcode) {
                .text, .continuation => if (is_notification(frame.payload)) {
                    _ = sub.heads.fetchAdd(1, .monotonic);
                },
                .ping => {
                    var pong: [125 + ws.frame.header_size_max]u8 = undefined;
                    try w.writeAll(encode_client_frame(&pong, .pong, frame.payload, sub.mask()));
                    try w.flush();
                },
                .close => return error.ConnectionClosed,
                else => {},
            }
            r.toss(frame.size);
        }
    }
};

/// Waits up to `duration_ms` in `slice_ms` steps through `wait_fn`, returning early once
/// `heads` moves past `seen` (a new L1 block). Returns whether a head woke it.
pub fn wait_for_head(
    heads: *const std.atomic.Value(u64),
    seen: u64,
    duration_ms: u64,
    slice_ms: u64,
    context: anytype,
    comptime wait_fn: fn (@TypeOf(context), u64) anyerror!void,
) !bool {
    assert(slice_ms > 0);
    var waited_ms: u64 = 0;
    while (waited_ms < duration_ms) {
        if (heads.load(.monotonic) != seen) return true;
        const step_ms = @min(slice_ms, duration_ms - waited_ms);
        try wait_fn(context, step_ms);
        waited_ms += step_ms;
    }
    assert(waited_ms == duration_ms);
    return heads.load(.monotonic) != seen;
}

const testing = std.testing;

test "l1 ws: URL parsing keeps host, port and path; refuses wss and garbage" {
    const plain = try parse_url("ws://localhost:8546/");
    try testing.expectEqualStrings("localhost", plain.host);
    try testing.expectEqual(@as(u16, 8546), plain.port);
    try testing.expectEqualStrings("/", plain.path);
    const keyed = try parse_url("ws://10.0.0.1:9000/v1/key?x=1");
    try testing.expectEqualStrings("/v1/key?x=1", keyed.path);
    try testing.expectEqual(@as(u16, 80), (try parse_url("ws://node")).port);
    try testing.expectEqualStrings("::1", (try parse_url("ws://[::1]:8546")).host);
    try testing.expectError(error.UnsupportedScheme, parse_url("wss://node:443"));
    try testing.expectError(error.UnsupportedScheme, parse_url("http://node"));
    try testing.expectError(error.InvalidUrl, parse_url("ws://:80"));
    try testing.expectError(error.InvalidUrl, parse_url("ws://node:0"));
    try testing.expectError(error.InvalidUrl, parse_url("ws://node:http"));
}

test "l1 ws: handshake request and response checks" {
    var buffer: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    try write_handshake(&w, .{ .host = "node", .port = 8546, .path = "/" }, key);
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "GET / HTTP/1.1\r\nHost: node:8546"));
    try testing.expect(std.mem.endsWith(u8, w.buffered(), "\r\n\r\n"));
    var status_seen = false;
    try testing.expect(!try check_handshake_line("HTTP/1.1 101 Switching\r\n", &status_seen, key));
    // RFC 6455 section 1.3 sample.
    const accept = "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n";
    try testing.expect(try check_handshake_line(accept, &status_seen, key));
    try testing.expectError(error.BadAccept, check_handshake_line(
        "sec-websocket-accept: AAAA\r\n",
        &status_seen,
        key,
    ));
    var fresh = false;
    try testing.expectError(error.NotSwitchingProtocols, check_handshake_line(
        "HTTP/1.1 400 Bad Request\r\n",
        &fresh,
        key,
    ));
}

test "l1 ws: masked client frames decode on the server side" {
    var out: [256]u8 = undefined;
    const frame = encode_client_frame(&out, .text, subscribe_request, .{ 1, 2, 3, 4 });
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..frame.len], frame);
    const decoded = try ws.decode_frame(copy[0..frame.len], .server, .{});
    try testing.expectEqualStrings(subscribe_request, decoded.frame.payload);
    try testing.expect(is_notification("{\"method\":\"eth_subscription\",\"params\":{}}"));
    try testing.expect(!is_notification("{\"id\":1,\"result\":\"0x1\"}"));
}

const FakeClock = struct {
    waited_ms: u64 = 0,
    heads: *std.atomic.Value(u64),
    head_at_ms: ?u64,

    fn wait(clock: *FakeClock, duration_ms: u64) anyerror!void {
        clock.waited_ms += duration_ms;
        const at = clock.head_at_ms orelse return;
        if (clock.waited_ms >= at) _ = clock.heads.fetchAdd(1, .monotonic);
    }
};

fn check_wait(poll_ms: u64, slice_ms: u64, head_at_ms: ?u64) !void {
    var heads: std.atomic.Value(u64) = .init(7);
    var clock: FakeClock = .{ .heads = &heads, .head_at_ms = head_at_ms };
    const woke = try wait_for_head(&heads, 7, poll_ms, slice_ms, &clock, FakeClock.wait);
    try testing.expect(clock.waited_ms <= poll_ms);
    if (head_at_ms) |at| {
        if (at <= poll_ms) {
            try testing.expect(woke);
            // Woken within one slice of the head, never a full poll late.
            try testing.expect(clock.waited_ms < at + slice_ms);
            return;
        }
    }
    try testing.expect(!woke);
    try testing.expectEqual(poll_ms, clock.waited_ms);
}

test "l1 ws: a new head cuts the poll wait short" {
    try check_wait(1000, 50, 120);
    try check_wait(1000, 50, null);
    try check_wait(1000, 50, 5000);
    try check_wait(30, 50, 10);
}

test "l1 ws: seeded fuzz of URLs and waits" {
    var prng = base.testing.Prng.init(0x1e5);
    for (0..200) |_| {
        var url: [48]u8 = undefined;
        prng.fill(&url);
        _ = parse_url(&url) catch {};
        const poll_ms = 1 + prng.below(5000);
        const head: ?u64 = if (prng.chance(1, 4)) null else prng.below(6000);
        try check_wait(poll_ms, 1 + prng.below(200), head);
    }
}

/// Test server side: one RFC 6455 handshake, the subscribe frame, then one notification.
fn serve_one_notification(io: Io, server: *Io.net.Server) !void {
    var connection = try server.accept(io);
    defer connection.close(io);
    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [1024]u8 = undefined;
    var reader = connection.reader(io, &read_buffer);
    var writer = connection.writer(io, &write_buffer);
    var key: [24]u8 = undefined;
    var key_seen = false;
    for (0..32) |_| {
        const line = try reader.interface.takeDelimiterInclusive('\n');
        if (std.mem.eql(u8, line, "\r\n")) break;
        const name = "Sec-WebSocket-Key: ";
        if (std.mem.startsWith(u8, line, name)) {
            @memcpy(&key, line[name.len..][0..key.len]);
            key_seen = true;
        }
    }
    try testing.expect(key_seen);
    try writer.interface.print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
        "Connection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&ws.accept_key(&key)});
    try writer.interface.flush();
    while (true) {
        const decoded = try ws.decode_frame(reader.interface.buffered(), .server, .{});
        if (decoded == .frame) {
            try testing.expectEqualStrings(subscribe_request, decoded.frame.payload);
            reader.interface.toss(decoded.frame.size);
            break;
        }
        try reader.interface.fillMore();
    }
    const notification = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_subscription\"," ++
        "\"params\":{\"subscription\":\"0x1\",\"result\":{\"number\":\"0x5\"}}}";
    var header: [ws.frame.header_size_max]u8 = undefined;
    const size = ws.encode_header(&header, true, .text, notification.len, null);
    try writer.interface.writeAll(header[0..size]);
    try writer.interface.writeAll(notification);
    try writer.interface.flush();
}

test "l1 ws: a subscription over loopback counts a newHeads notification" {
    const io = testing.io;
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .reuse_address = true });
    var listening = true;
    defer if (listening) server.deinit(io);
    var sub: L1HeadSubscription = .{
        .io = io,
        .target = .{ .host = "127.0.0.1", .port = server.socket.address.getPort(), .path = "/" },
        .quiet = true,
    };
    sub.start();
    if (sub.task == null) return error.SkipZigTest; // No concurrency in this Io.
    try serve_one_notification(io, &server);
    for (0..200) |_| {
        if (sub.heads.load(.monotonic) == 1) break;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    // Close the listener first: the reader reconnects after the session ends, and a
    // connection queued on a live listener would block its handshake read, which a cancel
    // does not interrupt. Refused connects leave it in its (cancelable) backoff sleep.
    server.deinit(io);
    listening = false;
    sub.task.?.cancel(io);
    try testing.expectEqual(@as(u64, 1), sub.heads.load(.monotonic));
}

fn fuzz_url(_: void, smith: *testing.Smith) anyerror!void {
    var url: [96]u8 = undefined;
    const length = smith.slice(&url);
    const target = parse_url(url[0..length]) catch return;
    try testing.expect(target.host.len > 0 and target.port > 0);
    try testing.expect(target.path[0] == '/');
}

test "l1 ws: fuzz URL parsing" {
    try testing.fuzz({}, fuzz_url, .{});
}

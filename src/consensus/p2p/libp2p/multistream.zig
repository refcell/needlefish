//! multistream-select 1.0 (libp2p `connections/multistream-select` spec). Every message is
//! an unsigned varint length followed by that many bytes, the last of which is `\n`. Both
//! sides first send the header `/multistream/1.0.0`. The dialer then proposes protocols one
//! at a time; the listener echoes a supported protocol or answers `na`.
//!
//! Both roles are pure state machines over byte buffers: `start` writes the opening bytes,
//! `receive` consumes input (any fragmentation) and writes at most one reply frame per
//! call. `receive` stops right after the message that settles the negotiation, so bytes
//! that follow belong to the negotiated protocol and are left unconsumed for the caller.
//!
//! The listener answers `ls` with `na` (listing is optional in the spec and unused by
//! OP Stack peers).

const std = @import("std");
const assert = std.debug.assert;
const varint = @import("../peers/varint.zig");

pub const header = "/multistream/1.0.0";
pub const not_available = "na";
/// Longest message, newline included (the spec's recommended limit).
pub const message_length_max = 1024;
/// Longest protocol name: one byte of every message is the newline.
pub const protocol_length_max = message_length_max - 1;
/// Length prefix bytes for `message_length_max`.
pub const prefix_length_max = 2;
/// Largest single frame (prefix + message).
pub const frame_length_max = prefix_length_max + message_length_max;
/// Most protocols either role is configured with.
pub const protocol_count_max = 16;
/// Most rejected proposals a listener tolerates before giving up on the peer.
pub const proposal_count_max = 32;

comptime {
    assert(varint.encoded_length(message_length_max) == prefix_length_max);
    assert(header.len < protocol_length_max);
}

pub const Error = error{
    /// A length prefix exceeds `message_length_max`.
    MessageTooLong,
    /// Zero length, non-minimal prefix, or missing newline.
    InvalidMessage,
    /// The peer's first message is not the multistream 1.0 header.
    HeaderMismatch,
    /// The dialer ran out of protocols, or the listener saw too many proposals.
    NegotiationFailed,
    /// The listener sent something other than our proposal or `na`.
    UnexpectedMessage,
};

pub const Decoded = struct {
    /// Message bytes without the trailing newline.
    message: []const u8,
    /// Bytes consumed from the input (prefix + message + newline).
    length: u32,
};

/// Decodes one message from the front of `input`. `error.Incomplete` means more bytes are
/// needed; anything else is a protocol violation.
pub fn decode(input: []const u8) (Error || error{Incomplete})!Decoded {
    const prefix = varint.decode(input) catch |err| switch (err) {
        error.Truncated => {
            if (input.len >= prefix_length_max) return error.MessageTooLong;
            return error.Incomplete;
        },
        error.NonMinimal => return error.InvalidMessage,
        error.Overflow => return error.MessageTooLong,
    };
    if (prefix.value > message_length_max) return error.MessageTooLong;
    if (prefix.value == 0) return error.InvalidMessage;
    const total: u32 = prefix.length + @as(u32, @intCast(prefix.value));
    if (input.len < total) return error.Incomplete;
    if (input[total - 1] != '\n') return error.InvalidMessage;
    assert(total <= frame_length_max);
    return .{ .message = input[prefix.length .. total - 1], .length = total };
}

/// Encodes `message` (no newline) as one frame at the front of `output`.
pub fn encode(output: []u8, message: []const u8) []u8 {
    assert(message.len > 0);
    assert(message.len <= protocol_length_max);
    const length: u64 = message.len + 1;
    const prefix = varint.encode(output, length);
    const total = prefix.len + message.len + 1;
    assert(output.len >= total);
    @memcpy(output[prefix.len..][0..message.len], message);
    output[total - 1] = '\n';
    return output[0..total];
}

/// Accumulates one message across fragmented input without allocating.
pub const Inbox = struct {
    buffer: [frame_length_max]u8 = undefined,
    fill: u16 = 0,

    pub const Pushed = struct {
        consumed: usize,
        /// A complete message (no newline), valid until the next `push`.
        message: ?[]const u8,
    };

    /// Consumes bytes until one message completes or `input` runs out.
    pub fn push(inbox: *Inbox, input: []const u8) Error!Pushed {
        assert(inbox.fill <= frame_length_max);
        var consumed: usize = 0;
        // Each pass consumes at least one byte or completes a message.
        while (consumed <= input.len) {
            const filled = inbox.buffer[0..inbox.fill];
            if (decode(filled)) |decoded| {
                assert(decoded.length == inbox.fill);
                inbox.fill = 0;
                return .{ .consumed = consumed, .message = decoded.message };
            } else |err| switch (err) {
                error.Incomplete => {},
                else => |e| return e,
            }
            if (consumed == input.len) break;
            const missing = inbox.needed();
            const take = @min(missing, input.len - consumed);
            assert(take > 0);
            @memcpy(inbox.buffer[inbox.fill..][0..take], input[consumed..][0..take]);
            inbox.fill += @intCast(take);
            consumed += take;
        }
        assert(consumed == input.len);
        return .{ .consumed = consumed, .message = null };
    }

    /// Bytes to read before the buffered prefix can be decoded again.
    fn needed(inbox: *const Inbox) usize {
        assert(inbox.fill < frame_length_max);
        const prefix = varint.decode(inbox.buffer[0..inbox.fill]) catch return 1;
        // `decode` returned Incomplete, so the prefix is valid and the body is short.
        const total = prefix.length + prefix.value;
        assert(total > inbox.fill);
        assert(total <= frame_length_max);
        return @intCast(total - inbox.fill);
    }
};

pub const Outcome = enum { pending, selected };

pub const Step = struct {
    /// Input bytes consumed. Unconsumed bytes after `selected` belong to the protocol.
    consumed: usize,
    /// Bytes to send to the peer (a prefix of the caller's output buffer).
    output: []const u8,
    outcome: Outcome,
};

const State = enum { idle, await_header, await_reply, done, failed };

fn assert_protocols(protocols: []const []const u8) void {
    assert(protocols.len > 0);
    assert(protocols.len <= protocol_count_max);
    for (protocols) |protocol| {
        assert(protocol.len > 0);
        assert(protocol.len <= protocol_length_max);
        assert(std.mem.indexOfScalar(u8, protocol, '\n') == null);
    }
}

/// Proposes protocols in order until the listener accepts one.
pub const Dialer = struct {
    protocols: []const []const u8,
    index: u8 = 0,
    state: State = .idle,
    inbox: Inbox = .{},

    pub fn init(protocols: []const []const u8) Dialer {
        assert_protocols(protocols);
        return .{ .protocols = protocols };
    }

    /// Writes the header and the first proposal. `output` holds two frames.
    pub fn start(dialer: *Dialer, output: []u8) []const u8 {
        assert(dialer.state == .idle);
        assert(output.len >= 2 * frame_length_max);
        const first = encode(output, header);
        const second = encode(output[first.len..], dialer.protocols[0]);
        dialer.state = .await_header;
        return output[0 .. first.len + second.len];
    }

    /// The accepted protocol; only valid after `selected`.
    pub fn selected(dialer: *const Dialer) []const u8 {
        assert(dialer.state == .done);
        assert(dialer.index < dialer.protocols.len);
        return dialer.protocols[dialer.index];
    }

    pub fn receive(dialer: *Dialer, input: []const u8, output: []u8) Error!Step {
        assert(dialer.state == .await_header or dialer.state == .await_reply);
        assert(output.len >= frame_length_max);
        const pushed = dialer.inbox.push(input) catch |err| return dialer.fail(err);
        var step: Step = .{ .consumed = pushed.consumed, .output = &.{}, .outcome = .pending };
        const message = pushed.message orelse return step;
        if (dialer.state == .await_header) {
            if (!std.mem.eql(u8, message, header)) return dialer.fail(error.HeaderMismatch);
            dialer.state = .await_reply;
        } else if (std.mem.eql(u8, message, dialer.protocols[dialer.index])) {
            dialer.state = .done;
            step.outcome = .selected;
        } else if (std.mem.eql(u8, message, not_available)) {
            dialer.index += 1;
            if (dialer.index == dialer.protocols.len) return dialer.fail(error.NegotiationFailed);
            step.output = encode(output, dialer.protocols[dialer.index]);
        } else {
            return dialer.fail(error.UnexpectedMessage);
        }
        assert(dialer.index < dialer.protocols.len);
        return step;
    }

    fn fail(dialer: *Dialer, err: Error) Error {
        assert(dialer.state != .done);
        dialer.state = .failed;
        return err;
    }
};

/// Answers proposals from a fixed list of supported protocols.
pub const Listener = struct {
    protocols: []const []const u8,
    index: u8 = 0,
    proposals: u8 = 0,
    state: State = .idle,
    inbox: Inbox = .{},

    pub fn init(protocols: []const []const u8) Listener {
        assert_protocols(protocols);
        return .{ .protocols = protocols };
    }

    /// Writes the header. `output` holds one frame.
    pub fn start(listener: *Listener, output: []u8) []const u8 {
        assert(listener.state == .idle);
        assert(output.len >= frame_length_max);
        listener.state = .await_header;
        return encode(output, header);
    }

    pub fn selected(listener: *const Listener) []const u8 {
        assert(listener.state == .done);
        assert(listener.index < listener.protocols.len);
        return listener.protocols[listener.index];
    }

    pub fn receive(listener: *Listener, input: []const u8, output: []u8) Error!Step {
        assert(listener.state == .await_header or listener.state == .await_reply);
        assert(output.len >= frame_length_max);
        const pushed = listener.inbox.push(input) catch |err| return listener.fail(err);
        var step: Step = .{ .consumed = pushed.consumed, .output = &.{}, .outcome = .pending };
        const message = pushed.message orelse return step;
        if (listener.state == .await_header) {
            if (!std.mem.eql(u8, message, header)) return listener.fail(error.HeaderMismatch);
            listener.state = .await_reply;
            return step;
        }
        listener.proposals += 1;
        if (listener.proposals > proposal_count_max) {
            return listener.fail(error.NegotiationFailed);
        }
        for (listener.protocols, 0..) |protocol, index| {
            if (std.mem.eql(u8, message, protocol)) {
                listener.index = @intCast(index);
                listener.state = .done;
                step.output = encode(output, protocol);
                step.outcome = .selected;
                return step;
            }
        }
        step.output = encode(output, not_available);
        assert(listener.state == .await_reply);
        return step;
    }

    fn fail(listener: *Listener, err: Error) Error {
        assert(listener.state != .done);
        listener.state = .failed;
        return err;
    }
};

const fuzz = @import("../../../testing/fuzz.zig");
const Prng = @import("../../../testing/prng.zig").Prng;

test "multistream: encode and decode" {
    var buffer: [frame_length_max]u8 = undefined;
    const frame = encode(&buffer, header);
    try std.testing.expectEqual(@as(u8, 19), frame[0]);
    try std.testing.expectEqualSlices(u8, "/multistream/1.0.0\n", frame[1..]);
    const decoded = try decode(frame);
    try std.testing.expectEqualStrings(header, decoded.message);
    try std.testing.expectEqual(@as(u32, 20), decoded.length);
    try std.testing.expectError(error.Incomplete, decode(frame[0..5]));
    try std.testing.expectError(error.Incomplete, decode(&.{}));
    try std.testing.expectError(error.InvalidMessage, decode(&.{ 1, 'x' }));
    try std.testing.expectError(error.InvalidMessage, decode(&.{0}));
    try std.testing.expectError(error.InvalidMessage, decode(&.{ 0x81, 0x00 }));
    try std.testing.expectError(error.MessageTooLong, decode(&.{ 0x81, 0x08 }));
    try std.testing.expectError(error.MessageTooLong, decode(&.{ 0x80, 0x80 }));
}

/// Shuttles bytes between a dialer and a listener in chunks of at most `chunk` bytes.
fn negotiate(dialer: *Dialer, listener: *Listener, chunk: usize) !void {
    var to_listener: [4 * frame_length_max]u8 = undefined;
    var to_dialer: [4 * frame_length_max]u8 = undefined;
    var output: [2 * frame_length_max]u8 = undefined;
    var dialer_bytes: usize = dialer.start(&output).len;
    @memcpy(to_listener[0..dialer_bytes], output[0..dialer_bytes]);
    var listener_bytes: usize = listener.start(&output).len;
    @memcpy(to_dialer[0..listener_bytes], output[0..listener_bytes]);
    var rounds: u32 = 0;
    while (dialer.state != .done or listener.state != .done) : (rounds += 1) {
        if (rounds > 10_000) return error.TestUnexpectedResult;
        if (listener.state != .done and dialer_bytes > 0) {
            const take = @min(chunk, dialer_bytes);
            const step = try listener.receive(to_listener[0..take], &output);
            std.mem.copyForwards(u8, &to_listener, to_listener[step.consumed..dialer_bytes]);
            dialer_bytes -= step.consumed;
            @memcpy(to_dialer[listener_bytes..][0..step.output.len], step.output);
            listener_bytes += step.output.len;
        }
        if (dialer.state != .done and listener_bytes > 0) {
            const take = @min(chunk, listener_bytes);
            const step = try dialer.receive(to_dialer[0..take], &output);
            std.mem.copyForwards(u8, &to_dialer, to_dialer[step.consumed..listener_bytes]);
            listener_bytes -= step.consumed;
            @memcpy(to_listener[dialer_bytes..][0..step.output.len], step.output);
            dialer_bytes += step.output.len;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), dialer_bytes);
    try std.testing.expectEqual(@as(usize, 0), listener_bytes);
}

test "multistream: negotiates the first common protocol" {
    const wanted = [_][]const u8{ "/yamux/2.0.0", "/mplex/6.7.0", "/yamux/1.0.0" };
    const supported = [_][]const u8{ "/yamux/1.0.0", "/mplex/6.7.0" };
    for ([_]usize{ 1, 2, 3, 7, frame_length_max }) |chunk| {
        var dialer = Dialer.init(&wanted);
        var listener = Listener.init(&supported);
        try negotiate(&dialer, &listener, chunk);
        try std.testing.expectEqualStrings("/mplex/6.7.0", dialer.selected());
        try std.testing.expectEqualStrings("/mplex/6.7.0", listener.selected());
    }
}

test "multistream: fails without a common protocol" {
    const wanted = [_][]const u8{ "/a/1", "/b/1" };
    const supported = [_][]const u8{"/c/1"};
    var dialer = Dialer.init(&wanted);
    var listener = Listener.init(&supported);
    try std.testing.expectError(error.NegotiationFailed, negotiate(&dialer, &listener, 5));
    try std.testing.expectEqual(State.failed, dialer.state);
}

test "multistream: leaves protocol bytes after selection unconsumed" {
    const protocols = [_][]const u8{"/noise"};
    var dialer = Dialer.init(&protocols);
    var output: [2 * frame_length_max]u8 = undefined;
    _ = dialer.start(&output);
    var input: [64]u8 = undefined;
    const first = encode(&input, header);
    const second = encode(input[first.len..], "/noise");
    const total = first.len + second.len;
    @memcpy(input[total..][0..3], "abc");
    var step = try dialer.receive(input[0 .. total + 3], &output);
    try std.testing.expectEqual(Outcome.pending, step.outcome);
    try std.testing.expectEqual(first.len, step.consumed);
    step = try dialer.receive(input[first.len .. total + 3], &output);
    try std.testing.expectEqual(Outcome.selected, step.outcome);
    try std.testing.expectEqual(second.len, step.consumed);
}

test "multistream: rejects a bad header and unexpected replies" {
    const protocols = [_][]const u8{"/noise"};
    var output: [2 * frame_length_max]u8 = undefined;
    var input: [64]u8 = undefined;
    var listener = Listener.init(&protocols);
    _ = listener.start(&output);
    const bad = encode(&input, "/multistream/2.0.0");
    try std.testing.expectError(error.HeaderMismatch, listener.receive(bad, &output));

    var dialer = Dialer.init(&protocols);
    _ = dialer.start(&output);
    const first = encode(&input, header);
    const second = encode(input[first.len..], "/tls");
    _ = try dialer.receive(input[0..first.len], &output);
    try std.testing.expectError(error.UnexpectedMessage, dialer.receive(second, &output));
}

test "multistream: listener bounds rejected proposals" {
    const protocols = [_][]const u8{"/noise"};
    var output: [2 * frame_length_max]u8 = undefined;
    var input: [64]u8 = undefined;
    var listener = Listener.init(&protocols);
    _ = listener.start(&output);
    _ = try listener.receive(encode(&input, header), &output);
    for (0..proposal_count_max) |_| {
        const step = try listener.receive(encode(&input, "ls"), &output);
        try std.testing.expectEqualSlices(u8, "\x03na\n", step.output);
    }
    const result = listener.receive(encode(&input, "ls"), &output);
    try std.testing.expectError(error.NegotiationFailed, result);
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    const decoded = decode(input) catch return;
    try std.testing.expect(decoded.length <= input.len);
    try std.testing.expect(decoded.message.len < message_length_max);
    var buffer: [frame_length_max]u8 = undefined;
    if (decoded.message.len > 0) {
        try std.testing.expectEqualSlices(
            u8,
            input[0..decoded.length],
            encode(&buffer, decoded.message),
        );
    }
}

test "multistream: fuzz decode" {
    try fuzz.run_bytes({}, fuzz_decode, .{ .input_size_max = 1100 });
}

fn fuzz_listener(_: void, input: []const u8) anyerror!void {
    const protocols = [_][]const u8{ "/noise", "/yamux/1.0.0" };
    var listener = Listener.init(&protocols);
    var output: [2 * frame_length_max]u8 = undefined;
    _ = listener.start(&output);
    var offset: usize = 0;
    while (offset < input.len and listener.state != .done) {
        const step = listener.receive(input[offset..], &output) catch return;
        try std.testing.expect(step.consumed > 0);
        offset += step.consumed;
    }
}

test "multistream: fuzz listener" {
    var prefixed: [64]u8 = undefined;
    const first = encode(&prefixed, header);
    const corpus = [_][]const u8{first};
    try fuzz.run_bytes({}, fuzz_listener, .{ .input_size_max = 2048, .corpus = &corpus });
}

test "multistream: seeded fragmented negotiation" {
    var prng = Prng.init(0x6d73_7365);
    const supported = [_][]const u8{ "/meshsub/1.1.0", "/ipfs/id/1.0.0", "/ipfs/ping/1.0.0" };
    for (0..64) |_| {
        const pick: usize = @intCast(prng.below(supported.len));
        const wanted = [_][]const u8{ "/unknown/0", supported[pick] };
        var dialer = Dialer.init(&wanted);
        var listener = Listener.init(&supported);
        try negotiate(&dialer, &listener, @intCast(prng.range(1, 40)));
        try std.testing.expectEqualStrings(supported[pick], listener.selected());
    }
}

//! devp2p base protocol and eth/68 messages (devp2p `rlpx.md`, `caps/eth.md`), as frame
//! data: `rlp(message_id) || message_data`. After Hello (p2p version 5) every message's data
//! is snappy-compressed; the id is not. Encoders write into caller buffers; decoders
//! borrow their input.
//!
//! Only what a block-fetching client needs: Hello, Disconnect, Ping/Pong, Status,
//! GetBlockHeaders/BlockHeaders, GetBlockBodies/BlockBodies.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../common/rlp/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const ordered = @import("../trie/ordered.zig");
const Nibbles = @import("../trie/nibbles.zig").Nibbles;

pub const p2p_version = 5;
pub const eth_version = 68;
/// eth message ids start after the 16 base protocol ids.
pub const eth_offset = 0x10;

pub const Id = enum(u8) {
    hello = 0x00,
    disconnect = 0x01,
    ping = 0x02,
    pong = 0x03,
    status = eth_offset + 0x00,
    get_block_headers = eth_offset + 0x03,
    block_headers = eth_offset + 0x04,
    get_block_bodies = eth_offset + 0x05,
    block_bodies = eth_offset + 0x06,
    _,
};

pub const Error = rlp.Error || error{ BufferTooSmall, NoSharedCapability };

/// Splits frame data into its message id and message data.
pub fn split(frame: []const u8) rlp.Error!struct { id: Id, data: []const u8 } {
    var decoder = rlp.Decoder.init(frame);
    const id = try decoder.int(u8);
    return .{ .id = @fromBackingInt(@intCast(id)), .data = decoder.rest() };
}

/// Writes `rlp(id)` at the front of `output`; returns its length (always 1 here).
pub fn write_id(output: []u8, id: Id) usize {
    assert(output.len >= 1);
    const value = @backingInt(id);
    output[0] = if (value == 0) 0x80 else value;
    assert(value < 0x80);
    return 1;
}

pub const Hello = struct {
    version: u64,
    client: []const u8,
    eth_68: bool,
    node_id: [64]u8,
};

/// `[5, client, [["eth", 68]], 0, node_id]`.
pub fn encode_hello(output: []u8, client: []const u8, node_id: *const [64]u8) Error![]u8 {
    const capability = rlp.bytes_length("eth") + rlp.int_length(@as(u8, eth_version));
    const capabilities = rlp.list_length(capability);
    const payload = rlp.int_length(@as(u8, p2p_version)) + rlp.bytes_length(client) +
        rlp.list_length(capabilities) + rlp.int_length(@as(u8, 0)) + rlp.bytes_length(node_id);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.int(@as(u8, p2p_version));
    encoder.bytes(client);
    encoder.list_header(capabilities);
    encoder.list_header(capability);
    encoder.bytes("eth");
    encoder.int(@as(u8, eth_version));
    encoder.int(@as(u8, 0));
    encoder.bytes(node_id);
    assert(encoder.written().len == rlp.list_length(payload));
    return encoder.written();
}

pub fn decode_hello(data: []const u8) Error!Hello {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    var hello: Hello = .{
        .version = try fields.int(u64),
        .client = try fields.bytes(),
        .eth_68 = false,
        .node_id = undefined,
    };
    var capabilities = try fields.list();
    var count: u32 = 0;
    while (!capabilities.is_empty()) : (count += 1) {
        if (count == 64) return error.Overflow;
        var capability = try capabilities.list();
        const name = try capability.bytes();
        const version = try capability.int(u32);
        if (std.mem.eql(u8, name, "eth") and version == eth_version) hello.eth_68 = true;
    }
    _ = try fields.int(u64); // listen port
    hello.node_id = try fields.fixed(64);
    return hello;
}

/// Disconnect reason; peers send `[reason]` or, rarely, a bare integer.
pub fn decode_disconnect(data: []const u8) u8 {
    var decoder = rlp.Decoder.init(data);
    const header = decoder.peek_header() catch return 0xff;
    if (header.list) {
        var fields = decoder.list() catch return 0xff;
        return fields.int(u8) catch 0xff;
    }
    return decoder.int(u8) catch 0xff;
}

pub const ForkId = struct { hash: [4]u8, next: u64 };

pub const Status = struct {
    version: u32,
    network_id: u64,
    total_difficulty: u256,
    head: [32]u8,
    genesis: [32]u8,
    fork_id: ForkId,
};

pub fn encode_status(output: []u8, status: *const Status) Error![]u8 {
    const fork = rlp.bytes_length(&status.fork_id.hash) + rlp.int_length(status.fork_id.next);
    const payload = rlp.int_length(status.version) + rlp.int_length(status.network_id) +
        rlp.int_length(status.total_difficulty) + rlp.bytes_length(&status.head) +
        rlp.bytes_length(&status.genesis) + rlp.list_length(fork);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.int(status.version);
    encoder.int(status.network_id);
    encoder.int(status.total_difficulty);
    encoder.bytes(&status.head);
    encoder.bytes(&status.genesis);
    encoder.list_header(fork);
    encoder.bytes(&status.fork_id.hash);
    encoder.int(status.fork_id.next);
    assert(encoder.written().len == rlp.list_length(payload));
    return encoder.written();
}

pub fn decode_status(data: []const u8) Error!Status {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    var status: Status = .{
        .version = try fields.int(u32),
        .network_id = try fields.int(u64),
        .total_difficulty = try fields.int(u256),
        .head = try fields.fixed(32),
        .genesis = try fields.fixed(32),
        .fork_id = undefined,
    };
    var fork = try fields.list();
    status.fork_id = .{ .hash = try fork.fixed(4), .next = try fork.int(u64) };
    return status;
}

/// Where a header query starts: a block number or a block hash.
pub const Origin = union(enum) { number: u64, hash: [32]u8 };

/// `[request_id, [origin, amount, skip, reverse]]`, ascending from `origin`.
pub fn encode_get_block_headers(
    output: []u8,
    request_id: u64,
    origin: Origin,
    amount: u64,
) Error![]u8 {
    const zero: u8 = 0;
    const origin_length = switch (origin) {
        .number => |number| rlp.int_length(number),
        .hash => |*hash| rlp.bytes_length(hash),
    };
    const query = origin_length + rlp.int_length(amount) + 2 * rlp.int_length(zero);
    const payload = rlp.int_length(request_id) + rlp.list_length(query);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.int(request_id);
    encoder.list_header(query);
    switch (origin) {
        .number => |number| encoder.int(number),
        .hash => |*hash| encoder.bytes(hash),
    }
    encoder.int(amount);
    encoder.int(zero);
    encoder.int(zero);
    return encoder.written();
}

/// `[request_id, [hash, ...]]`.
pub fn encode_get_block_bodies(
    output: []u8,
    request_id: u64,
    hashes: []const [32]u8,
) Error![]u8 {
    const list = hashes.len * rlp.bytes_length(&hashes[0]);
    const payload = rlp.int_length(request_id) + rlp.list_length(list);
    if (output.len < rlp.list_length(payload)) return error.BufferTooSmall;
    var encoder = rlp.Encoder.init(output);
    encoder.list_header(payload);
    encoder.int(request_id);
    encoder.list_header(list);
    for (hashes) |*hash| encoder.bytes(hash);
    return encoder.written();
}

/// A response: its request id and a decoder over its items (raw headers or body lists).
pub const Response = struct { request_id: u64, items: rlp.Decoder };

pub fn decode_response(data: []const u8) Error!Response {
    var outer = rlp.Decoder.init(data);
    var fields = try outer.list();
    const request_id = try fields.int(u64);
    return .{ .request_id = request_id, .items = try fields.list() };
}

/// The EIP-2718 bytes of each transaction in a body's transaction list, written to
/// `output`: legacy transactions are RLP lists (kept whole), typed ones are RLP strings
/// (their payload is `type || rlp`). Returns how many were written.
pub fn body_transactions(
    body: []const u8,
    output: [][]const u8,
) Error!struct { count: usize, ommers_empty: bool } {
    var outer = rlp.Decoder.init(body);
    var fields = try outer.list();
    var transactions = try fields.list();
    var count: usize = 0;
    while (!transactions.is_empty()) : (count += 1) {
        if (count == output.len) return error.BufferTooSmall;
        const header = try transactions.peek_header();
        output[count] = if (header.list) try transactions.raw() else try transactions.bytes();
    }
    const ommers = try fields.list();
    return .{ .count = count, .ommers_empty = ommers.is_empty() };
}

/// Ordered trie root of `transactions` (EIP-2718 bytes): a header's `transactionsRoot`.
pub fn transactions_root(transactions: []const []const u8) [32]u8 {
    var builder = ordered.OrderedHashBuilder.init();
    var step: u64 = 0;
    while (step < transactions.len) : (step += 1) {
        const index = ordered.adjust_index_for_rlp(step, transactions.len);
        var key_buffer: [9]u8 = undefined;
        const key = Nibbles.from_bytes(ordered.encode_index(index, &key_buffer));
        builder.add_leaf(key.slice(), transactions[@intCast(index)]);
    }
    assert(step == transactions.len);
    return builder.root();
}

const testing = std.testing;

test "eth: messages round trip through their decoders" {
    var buffer: [512]u8 = undefined;
    const node_id: [64]u8 = @splat(7);
    const hello = try decode_hello(try encode_hello(&buffer, "needlefish", &node_id));
    try testing.expectEqual(@as(u64, p2p_version), hello.version);
    try testing.expectEqualStrings("needlefish", hello.client);
    try testing.expect(hello.eth_68);
    try testing.expectEqualSlices(u8, &node_id, &hello.node_id);
    const status: Status = .{
        .version = eth_version,
        .network_id = 84532,
        .total_difficulty = 0,
        .head = @splat(1),
        .genesis = @splat(2),
        .fork_id = .{ .hash = .{ 0xc6, 0x75, 0x7f, 0x44 }, .next = 0 },
    };
    try testing.expectEqual(status, try decode_status(try encode_status(&buffer, &status)));
    var frame: [16]u8 = undefined;
    _ = write_id(&frame, .hello);
    try testing.expectEqual(Id.hello, (try split(frame[0..1])).id);
    try testing.expectEqual(@as(u8, 4), decode_disconnect(&.{ 0xc1, 0x04 }));
    try testing.expectEqual(@as(u8, 4), decode_disconnect(&.{0x04}));
}

test "eth: transactions root of the empty list is the empty trie root" {
    const root = transactions_root(&.{});
    const empty = @import("../../common/primitives/root.zig").empty_root_hash;
    try testing.expectEqualSlices(u8, &empty.bytes, &root);
    // A body with one typed and one legacy transaction yields their 2718 bytes.
    const body = [_]u8{ 0xc6, 0xc4, 0x82, 0x02, 0xc0, 0xc0, 0xc0 };
    var items: [4][]const u8 = undefined;
    const result = try body_transactions(&body, &items);
    try testing.expectEqual(@as(usize, 2), result.count);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0xc0 }, items[0]);
    try testing.expectEqualSlices(u8, &.{0xc0}, items[1]);
    try testing.expect(result.ommers_empty);
}

const fuzz = @import("../../testing/fuzz.zig");

/// Every decoder on hostile bytes: errors, never panics, and bounded outputs.
fn fuzz_decoders(_: void, data: []const u8) !void {
    if (split(data)) |message| assert(message.data.len < data.len) else |_| {}
    if (decode_hello(data)) |hello| assert(hello.client.len <= data.len) else |_| {}
    if (decode_status(data)) |status| assert(status.version <= std.math.maxInt(u64)) else |_| {}
    _ = decode_disconnect(data);
    var transactions: [8][]const u8 = undefined;
    if (decode_response(data)) |response| {
        var items = response.items;
        while (!items.is_empty()) {
            const raw = items.raw() catch break;
            const body = body_transactions(raw, &transactions) catch continue;
            assert(body.count <= transactions.len);
            _ = transactions_root(transactions[0..body.count]);
        }
    } else |_| {}
    if (body_transactions(data, &transactions)) |body| {
        assert(body.count <= transactions.len);
    } else |_| {}
}

test "eth: fuzz the message decoders" {
    var hello_buffer: [512]u8 = undefined;
    var status_buffer: [512]u8 = undefined;
    const node_id: [64]u8 = @splat(3);
    const status: Status = .{
        .version = eth_version,
        .network_id = 84532,
        .total_difficulty = 0,
        .head = @splat(1),
        .genesis = @splat(2),
        .fork_id = .{ .hash = .{ 1, 2, 3, 4 }, .next = 0 },
    };
    const corpus: []const []const u8 = &.{
        try encode_hello(&hello_buffer, "needlefish", &node_id),
        try encode_status(&status_buffer, &status),
        // BlockBodies: request id 1, one body holding one legacy transaction.
        &.{ 0xc6, 0x01, 0xc4, 0xc3, 0xc1, 0xc0, 0xc0 },
        &.{ 0xc6, 0xc4, 0x82, 0x02, 0xc0, 0xc0, 0xc0 },
    };
    try fuzz.run_bytes({}, fuzz_decoders, .{ .input_size_max = 512, .corpus = corpus });
}

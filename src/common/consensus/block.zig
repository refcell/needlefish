//! Blocks: withdrawals (EIP-4895), block bodies, full blocks, the ordered-trie roots in
//! the header, and the EIP-7685 requests hash. Mirrors base/base `consensus/src/block.rs`
//! and alloy-consensus `Block`.
//!
//! Bodies are zero copy: transactions, ommers and withdrawals keep their validated RLP
//! list payloads and decode items on iteration.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const tx_module = @import("tx.zig");
const receipt_module = @import("receipt.zig");
const Header = @import("header.zig").Header;
const ordered = @import("../../execution/trie/ordered.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = tx_module.Envelope;
const Receipt = receipt_module.Receipt;

pub const Withdrawal = struct {
    index: u64,
    validator_index: u64,
    address: Address,
    /// In gwei.
    amount: u64,
};

/// A validated RLP list payload whose items decode as `Item` via `decode_item`.
fn ItemList(comptime Item: type, comptime decode_item: anytype) type {
    return struct {
        payload: []const u8 = &.{},
        count: u32 = 0,

        const Self = @This();
        pub const empty: Self = .{};

        pub const Iterator = struct {
            decoder: rlp.Decoder,

            pub fn next(self: *Iterator) ?Item {
                if (self.decoder.is_empty()) return null;
                return decode_item(&self.decoder) catch unreachable; // Validated.
            }
        };

        pub fn iterator(list: Self) Iterator {
            return .{ .decoder = rlp.Decoder.init(list.payload) };
        }

        pub fn from_payload(payload: []const u8) !Self {
            var decoder = rlp.Decoder.init(payload);
            var count: u32 = 0;
            // Every item consumes at least one byte: bounded by payload.len.
            while (!decoder.is_empty()) : (count += 1) _ = try decode_item(&decoder);
            return .{ .payload = payload, .count = count };
        }

        pub fn rlp_length(list: Self) usize {
            return rlp.list_length(list.payload.len);
        }

        pub fn rlp_encode(list: Self, encoder: *rlp.Encoder) void {
            encoder.list_header(list.payload.len);
            encoder.raw(list.payload);
        }

        pub fn decode_list(decoder: *rlp.Decoder) !Self {
            const items = try decoder.list();
            return from_payload(items.input);
        }
    };
}

fn decode_withdrawal(decoder: *rlp.Decoder) rlp.Error!Withdrawal {
    return rlp.decode(Withdrawal, decoder);
}

fn decode_header(decoder: *rlp.Decoder) rlp.Error!Header {
    return rlp.decode(Header, decoder);
}

pub const Withdrawals = ItemList(Withdrawal, decode_withdrawal);
pub const Ommers = ItemList(Header, decode_header);
pub const Transactions = ItemList(Envelope, Envelope.decode_network);

/// Encodes `envelopes` in network form into `buffer` as a transaction list payload.
pub fn build_transactions(buffer: []u8, envelopes: []const Envelope) Transactions {
    var encoder = rlp.Encoder.init(buffer);
    for (envelopes) |envelope| envelope.encode_network(&encoder);
    return .{ .payload = encoder.written(), .count = @intCast(envelopes.len) };
}

pub fn build_withdrawals(buffer: []u8, withdrawals: []const Withdrawal) Withdrawals {
    var encoder = rlp.Encoder.init(buffer);
    for (withdrawals) |withdrawal| rlp.encode(&encoder, withdrawal);
    return .{ .payload = encoder.written(), .count = @intCast(withdrawals.len) };
}

pub const DecodeError = tx_module.DecodeError;

pub const Body = struct {
    transactions: Transactions = .empty,
    ommers: Ommers = .empty,
    /// Present from Shanghai / Canyon.
    withdrawals: ?Withdrawals = null,

    fn payload_length(body: Body) usize {
        var total = body.transactions.rlp_length() + body.ommers.rlp_length();
        if (body.withdrawals) |withdrawals| total += withdrawals.rlp_length();
        return total;
    }

    fn encode_fields(body: Body, encoder: *rlp.Encoder) void {
        body.transactions.rlp_encode(encoder);
        body.ommers.rlp_encode(encoder);
        if (body.withdrawals) |withdrawals| withdrawals.rlp_encode(encoder);
    }

    fn decode_fields(items: *rlp.Decoder) DecodeError!Body {
        var body: Body = .{
            .transactions = try Transactions.decode_list(items),
            .ommers = try Ommers.decode_list(items),
        };
        if (!items.is_empty()) body.withdrawals = try Withdrawals.decode_list(items);
        return body;
    }

    pub fn rlp_length(body: Body) usize {
        return rlp.list_length(body.payload_length());
    }

    pub fn rlp_encode(body: Body, encoder: *rlp.Encoder) void {
        encoder.list_header(body.payload_length());
        body.encode_fields(encoder);
    }

    pub fn decode(encoded: []const u8) DecodeError!Body {
        var decoder = rlp.Decoder.init(encoded);
        var items = try decoder.list();
        try decoder.finish();
        const body = try decode_fields(&items);
        try items.finish();
        return body;
    }
};

pub const Block = struct {
    header: Header,
    body: Body = .{},

    fn payload_length(block: Block) usize {
        return rlp.length(block.header) + block.body.payload_length();
    }

    pub fn rlp_length(block: Block) usize {
        return rlp.list_length(block.payload_length());
    }

    pub fn rlp_encode(block: Block, encoder: *rlp.Encoder) void {
        encoder.list_header(block.payload_length());
        rlp.encode(encoder, block.header);
        block.body.encode_fields(encoder);
    }

    pub fn encode_to(block: Block, buffer: []u8) []u8 {
        var encoder = rlp.Encoder.init(buffer);
        block.rlp_encode(&encoder);
        return encoder.written();
    }

    pub fn decode(encoded: []const u8) DecodeError!Block {
        var decoder = rlp.Decoder.init(encoded);
        var items = try decoder.list();
        try decoder.finish();
        const header = try rlp.decode(Header, &items);
        const body = try Body.decode_fields(&items);
        try items.finish();
        return .{ .header = header, .body = body };
    }

    pub fn hash(block: Block) B256 {
        return block.header.hash();
    }
};

/// Scratch for root computation: encoded items and slices pointing into them.
pub const RootScratch = struct {
    bytes: []u8,
    items: [][]const u8,
};

fn root_of(scratch: RootScratch, count: usize) B256 {
    assert(count <= scratch.items.len);
    return .{ .bytes = ordered.ordered_trie_root(scratch.items[0..count]) };
}

/// Transactions root: ordered trie of EIP-2718 encodings.
pub fn transactions_root(transactions: Transactions, scratch: RootScratch) B256 {
    var position: usize = 0;
    var it = transactions.iterator();
    var index: usize = 0;
    while (it.next()) |envelope| : (index += 1) {
        const encoded = envelope.encode_to(scratch.bytes[position..]);
        scratch.items[index] = encoded;
        position += encoded.len;
    }
    assert(index == transactions.count);
    return root_of(scratch, index);
}

/// Receipts root: ordered trie of EIP-2718 receipt encodings.
pub fn receipts_root(receipts: []const Receipt, scratch: RootScratch) B256 {
    var position: usize = 0;
    for (receipts, 0..) |receipt, index| {
        const encoded = receipt.encode_to(scratch.bytes[position..]);
        scratch.items[index] = encoded;
        position += encoded.len;
    }
    return root_of(scratch, receipts.len);
}

/// Withdrawals root: ordered trie of RLP-encoded withdrawals.
pub fn withdrawals_root(withdrawals: Withdrawals, scratch: RootScratch) B256 {
    var position: usize = 0;
    var it = withdrawals.iterator();
    var index: usize = 0;
    while (it.next()) |withdrawal| : (index += 1) {
        const encoded = rlp.encode_to(scratch.bytes[position..], withdrawal);
        scratch.items[index] = encoded;
        position += encoded.len;
    }
    return root_of(scratch, index);
}

/// EIP-7685: sha256(sha256(r_0) || sha256(r_1) || ...) over requests (type byte followed
/// by data) with empty data skipped.
pub fn requests_hash(requests: []const []const u8) B256 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var outer = Sha256.init(.{});
    for (requests) |request| {
        assert(request.len >= 1);
        if (request.len == 1) continue;
        var digest: [32]u8 = undefined;
        Sha256.hash(request, &digest, .{});
        outer.update(&digest);
    }
    var result: B256 = undefined;
    outer.final(&result.bytes);
    return result;
}

/// Requests hash with no requests: sha256("").
pub const empty_requests_hash = B256.comptime_hex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "block: empty roots" {
    var bytes: [64]u8 = undefined;
    var items: [1][]const u8 = undefined;
    const scratch: RootScratch = .{ .bytes = &bytes, .items = &items };
    try testing.expect(transactions_root(.empty, scratch).eql(primitives.empty_root_hash));
    try testing.expect(withdrawals_root(.empty, scratch).eql(primitives.empty_root_hash));
    try testing.expect(receipts_root(&.{}, scratch).eql(primitives.empty_root_hash));
    try testing.expect(requests_hash(&.{}).eql(empty_requests_hash));
    try testing.expect(requests_hash(&.{ &.{0x00}, &.{0x01} }).eql(empty_requests_hash));
}

test "block: body and block round trip" {
    var prng = Prng.init(0xb10c);
    const key: [32]u8 = @splat(0x22);
    var envelopes: [5]Envelope = undefined;
    for (&envelopes, 0..) |*envelope, index| {
        envelope.* = try tx_module.sign(tx_module.Eip1559{
            .chain_id = 8453,
            .nonce = index,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = prng.int(u32),
            .gas_limit = 21000,
            .to = .{ .call = .zero },
            .value = prng.int(u64),
            .input = &.{},
            .access_list = .empty,
        }, key);
    }
    var tx_buffer: [2048]u8 = undefined;
    const transactions = build_transactions(&tx_buffer, &envelopes);
    var withdrawal_buffer: [256]u8 = undefined;
    const withdrawals = build_withdrawals(&withdrawal_buffer, &.{
        .{ .index = 1, .validator_index = 2, .address = .zero, .amount = 3 },
    });
    const block: Block = .{
        .header = .{ .number = 7, .base_fee_per_gas = 1, .withdrawals_root = .zero },
        .body = .{ .transactions = transactions, .withdrawals = withdrawals },
    };
    var buffer: [4096]u8 = undefined;
    const encoded = block.encode_to(&buffer);
    try testing.expectEqual(block.rlp_length(), encoded.len);
    const decoded = try Block.decode(encoded);
    try testing.expectEqual(@as(u32, 5), decoded.body.transactions.count);
    try testing.expectEqual(@as(u32, 1), decoded.body.withdrawals.?.count);
    try testing.expect(decoded.hash().eql(block.hash()));
    var it = decoded.body.transactions.iterator();
    try testing.expect(it.next().?.hash().eql(envelopes[0].hash()));

    var root_bytes: [2048]u8 = undefined;
    var root_items: [8][]const u8 = undefined;
    const scratch: RootScratch = .{ .bytes = &root_bytes, .items = &root_items };
    const root_a = transactions_root(decoded.body.transactions, scratch);
    const root_b = transactions_root(transactions, scratch);
    try testing.expect(root_a.eql(root_b));
    try testing.expect(!root_a.eql(primitives.empty_root_hash));
}

test "block: ethereum/tests blockchain vectors (Cancun, Prague)" {
    const text = @embedFile("testdata/blocks.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    var root_bytes: [4096]u8 = undefined;
    var root_items: [16][]const u8 = undefined;
    const scratch: RootScratch = .{ .bytes = &root_bytes, .items = &root_items };
    for (parsed.value.array.items) |vector| {
        const object = vector.object;
        var buffer: [4096]u8 = undefined;
        const encoded = try primitives.hex.decode_into(&buffer, object.get("rlp").?.string);
        const block = try Block.decode(encoded);
        const expected_hash = try B256.from_hex(object.get("hash").?.string);
        try testing.expect(block.hash().eql(expected_hash));
        const tx_root = try B256.from_hex(object.get("transactions_root").?.string);
        try testing.expect(transactions_root(block.body.transactions, scratch).eql(tx_root));
        if (object.get("withdrawals_root").? == .string) {
            const expected = try B256.from_hex(object.get("withdrawals_root").?.string);
            try testing.expect(withdrawals_root(block.body.withdrawals.?, scratch).eql(expected));
        }
        const senders = object.get("senders").?.array.items;
        try testing.expectEqual(senders.len, block.body.transactions.count);
        var it = block.body.transactions.iterator();
        for (senders) |sender| {
            const recovered = it.next().?.recover_sender(@import("signature.zig").recover_address);
            try testing.expect(recovered.?.eql(try Address.from_hex(sender.string)));
        }
        var again: [4096]u8 = undefined;
        try testing.expectEqualSlices(u8, encoded, block.encode_to(&again));
    }
}

fn fuzz_block(_: void, smith: *testing.Smith) anyerror!void {
    var input: [2048]u8 = undefined;
    const len = smith.slice(&input);
    const block = Block.decode(input[0..len]) catch return;
    var again: [2048]u8 = undefined;
    try testing.expectEqualSlices(u8, input[0..len], block.encode_to(&again));
}

test "block: fuzz decode is canonical" {
    try testing.fuzz({}, fuzz_block, .{});
}

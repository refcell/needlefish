//! L2 block source: turns `eth_getBlockByNumber(n, true)` JSON into the pieces a batch
//! needs: header fields, the L1 origin (from the L1 info deposit, always the first
//! transaction), and the EIP-2718 bytes of every non-deposit transaction.
//!
//! Like op-batcher, we rebuild each transaction from its JSON fields and re-encode it;
//! the decoder checks the rebuilt hash against the node's so a field mismatch can never
//! produce a silently different batch.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../rpc/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const l1_info = @import("../../consensus/protocol/l1_info.zig");
const rlp = @import("../../common/rlp/root.zig");

const B256 = primitives.B256;
const Address = primitives.Address;
const BlockId = protocol.BlockId;

pub const deposit_tx_type = 0x7e;

pub const L2Block = struct {
    number: u64,
    hash: B256,
    parent_hash: B256,
    timestamp: u64,
    l1_origin: BlockId,
    /// L1 info sequence number (position within the epoch).
    sequence_number: u64,
    /// EIP-2718 bytes of non-deposit transactions; borrow the decoder's storage.
    transactions: []const []const u8,
};

pub const Error = rpc.DecodeError || error{
    UnsupportedTxType,
    MissingL1Info,
    InvalidL1Info,
    InvalidSignature,
    TxHashMismatch,
    BlockTooLarge,
};

pub const Limits = struct {
    tx_count_max: u32 = 8192,
    /// Total encoded transaction bytes per block (Base blocks are far smaller).
    tx_bytes_max: u32 = 16 * 1024 * 1024,
    /// Largest single transaction input.
    input_bytes_max: u32 = 1024 * 1024,
};

/// Reusable block decoder; all memory is allocated once in `init`.
pub const Decoder = struct {
    storage: []u8,
    storage_used: usize,
    spans: [][]const u8,
    input_scratch: []u8,
    access_list_scratch: []u8,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Decoder {
        assert(limits.tx_count_max > 0);
        const storage = try allocator.alloc(u8, limits.tx_bytes_max);
        errdefer allocator.free(storage);
        const spans = try allocator.alloc([]const u8, limits.tx_count_max);
        errdefer allocator.free(spans);
        const input_scratch = try allocator.alloc(u8, limits.input_bytes_max);
        errdefer allocator.free(input_scratch);
        const access_list_scratch = try allocator.alloc(u8, limits.input_bytes_max);
        return .{
            .storage = storage,
            .storage_used = 0,
            .spans = spans,
            .input_scratch = input_scratch,
            .access_list_scratch = access_list_scratch,
        };
    }

    pub fn deinit(decoder: *Decoder, allocator: std.mem.Allocator) void {
        allocator.free(decoder.storage);
        allocator.free(decoder.spans);
        allocator.free(decoder.input_scratch);
        allocator.free(decoder.access_list_scratch);
        decoder.* = undefined;
    }

    /// Decodes one block. The result borrows the decoder until the next `decode`.
    pub fn decode(decoder: *Decoder, block: json.Value) Error!L2Block {
        decoder.storage_used = 0;
        const transactions_value = try rpc.field(block, "transactions");
        if (transactions_value != .array) return error.MalformedResponse;
        const transactions = transactions_value.array.items;
        if (transactions.len == 0) return error.MissingL1Info;
        const info = try decode_l1_info(decoder, transactions[0]);
        var count: usize = 0;
        for (transactions) |tx| {
            const tx_type = try rpc.quantity(u8, try rpc.field(tx, "type"));
            if (tx_type == deposit_tx_type) continue;
            if (count == decoder.spans.len) return error.BlockTooLarge;
            decoder.spans[count] = try decoder.encode_transaction(tx, tx_type);
            count += 1;
        }
        const result: L2Block = .{
            .number = try rpc.quantity(u64, try rpc.field(block, "number")),
            .hash = .{ .bytes = try rpc.fixed(32, try rpc.field(block, "hash")) },
            .parent_hash = .{ .bytes = try rpc.fixed(32, try rpc.field(block, "parentHash")) },
            .timestamp = try rpc.quantity(u64, try rpc.field(block, "timestamp")),
            .l1_origin = info.id(),
            .sequence_number = info.sequence_number,
            .transactions = decoder.spans[0..count],
        };
        assert(result.transactions.len < transactions.len);
        return result;
    }

    fn decode_l1_info(decoder: *Decoder, tx: json.Value) Error!l1_info.L1BlockInfo {
        const tx_type = try rpc.quantity(u8, try rpc.field(tx, "type"));
        if (tx_type != deposit_tx_type) return error.MissingL1Info;
        const input = try rpc.data(try rpc.field(tx, "input"), decoder.input_scratch);
        return l1_info.L1BlockInfo.decode_calldata(input) catch error.InvalidL1Info;
    }

    fn encode_transaction(decoder: *Decoder, tx: json.Value, tx_type: u8) Error![]const u8 {
        const envelope = try decoder.envelope_from_json(tx, tx_type);
        const length = envelope.encoded_length();
        if (decoder.storage_used + length > decoder.storage.len) return error.BlockTooLarge;
        const out = envelope.encode_to(decoder.storage[decoder.storage_used..][0..length]);
        decoder.storage_used += length;
        const expected = try rpc.fixed(32, try rpc.field(tx, "hash"));
        if (!std.mem.eql(u8, &expected, &envelope.hash().bytes)) return error.TxHashMismatch;
        return out;
    }

    fn envelope_from_json(decoder: *Decoder, tx: json.Value, tx_type: u8) Error!consensus.Envelope {
        const input = try rpc.data(try rpc.field(tx, "input"), decoder.input_scratch);
        const nonce = try rpc.quantity(u64, try rpc.field(tx, "nonce"));
        const gas_limit = try rpc.quantity(u64, try rpc.field(tx, "gas"));
        const value = try rpc.quantity(u256, try rpc.field(tx, "value"));
        const to = try tx_kind(tx);
        switch (tx_type) {
            0 => return legacy_from_json(tx, nonce, gas_limit, to, value, input),
            1 => return .{ .eip2930 = .{ .tx = .{
                .chain_id = try rpc.quantity(u64, try rpc.field(tx, "chainId")),
                .nonce = nonce,
                .gas_price = try rpc.quantity(u128, try rpc.field(tx, "gasPrice")),
                .gas_limit = gas_limit,
                .to = to,
                .value = value,
                .input = input,
                .access_list = try decoder.access_list(tx),
            }, .signature = try typed_signature(tx) } },
            2 => return .{ .eip1559 = .{ .tx = .{
                .chain_id = try rpc.quantity(u64, try rpc.field(tx, "chainId")),
                .nonce = nonce,
                .max_priority_fee_per_gas = try rpc.quantity(
                    u128,
                    try rpc.field(tx, "maxPriorityFeePerGas"),
                ),
                .max_fee_per_gas = try rpc.quantity(u128, try rpc.field(tx, "maxFeePerGas")),
                .gas_limit = gas_limit,
                .to = to,
                .value = value,
                .input = input,
                .access_list = try decoder.access_list(tx),
            }, .signature = try typed_signature(tx) } },
            4 => return .{ .eip7702 = .{ .tx = .{
                .chain_id = try rpc.quantity(u64, try rpc.field(tx, "chainId")),
                .nonce = nonce,
                .max_priority_fee_per_gas = try rpc.quantity(
                    u128,
                    try rpc.field(tx, "maxPriorityFeePerGas"),
                ),
                .max_fee_per_gas = try rpc.quantity(u128, try rpc.field(tx, "maxFeePerGas")),
                .gas_limit = gas_limit,
                .to = switch (to) {
                    .call => |address| address,
                    .create => return error.MalformedResponse,
                },
                .value = value,
                .input = input,
                .access_list = try decoder.access_list(tx),
                .authorization_list = try authorization_list(decoder, tx),
            }, .signature = try typed_signature(tx) } },
            else => return error.UnsupportedTxType,
        }
    }

    /// Rebuilds the RLP payload of the JSON `accessList` into scratch memory.
    fn access_list(decoder: *Decoder, tx: json.Value) Error!consensus.AccessList {
        const list = (tx.object.get("accessList")) orelse return .empty;
        if (list != .array) return error.MalformedResponse;
        const half = decoder.access_list_scratch.len / 2;
        var encoder = rlp.Encoder.init(decoder.access_list_scratch[0..half]);
        var addresses: u32 = 0;
        var keys_total: u32 = 0;
        for (list.array.items) |item| {
            const address = try rpc.fixed(20, try rpc.field(item, "address"));
            const keys = try rpc.field(item, "storageKeys");
            if (keys != .array) return error.MalformedResponse;
            const keys_length = keys.array.items.len * 33;
            if (encoder.remaining() < 30 + keys_length) return error.BlockTooLarge;
            encoder.list_header(21 + rlp_list_length(keys_length));
            encoder.bytes(&address);
            encoder.list_header(keys_length);
            for (keys.array.items) |key| encoder.bytes(&(try rpc.fixed(32, key)));
            addresses += 1;
            keys_total += @intCast(keys.array.items.len);
        }
        return .{
            .payload = encoder.written(),
            .address_count = addresses,
            .storage_key_count = keys_total,
        };
    }
};

/// Rebuilds the RLP payload of the JSON `authorizationList` (EIP-7702) into the second
/// half of the scratch memory (the access list uses the first).
fn authorization_list(decoder: *Decoder, tx: json.Value) Error!consensus.AuthorizationList {
    const list = try rpc.field(tx, "authorizationList");
    if (list != .array) return error.MalformedResponse;
    const half = decoder.access_list_scratch.len / 2;
    var encoder = rlp.Encoder.init(decoder.access_list_scratch[half..]);
    for (list.array.items) |item| {
        const chain_id = try rpc.quantity(u256, try rpc.field(item, "chainId"));
        const address = try rpc.fixed(20, try rpc.field(item, "address"));
        const nonce = try rpc.quantity(u64, try rpc.field(item, "nonce"));
        const y_parity = try rpc.quantity(u8, try rpc.field(item, "yParity"));
        const r = try rpc.quantity(u256, try rpc.field(item, "r"));
        const s = try rpc.quantity(u256, try rpc.field(item, "s"));
        const payload = rlp.int_length(chain_id) + 21 + rlp.int_length(nonce) +
            rlp.int_length(y_parity) + rlp.int_length(r) + rlp.int_length(s);
        if (encoder.remaining() < rlp.list_length(payload)) return error.BlockTooLarge;
        encoder.list_header(payload);
        encoder.int(chain_id);
        encoder.bytes(&address);
        encoder.int(nonce);
        encoder.int(y_parity);
        encoder.int(r);
        encoder.int(s);
    }
    const result = consensus.AuthorizationList.from_payload(encoder.written()) catch
        return error.MalformedResponse;
    assert(result.count == list.array.items.len);
    return result;
}

fn rlp_list_length(payload_length: usize) usize {
    return rlp.list_length(payload_length);
}

fn tx_kind(tx: json.Value) Error!consensus.TxKind {
    const to = tx.object.get("to") orelse return .create;
    if (to == .null) return .create;
    return .{ .call = .{ .bytes = try rpc.fixed(20, to) } };
}

fn typed_signature(tx: json.Value) Error!consensus.Signature {
    const parity_value = tx.object.get("yParity") orelse try rpc.field(tx, "v");
    const parity = try rpc.quantity(u8, parity_value);
    if (parity > 1) return error.InvalidSignature;
    return .{
        .y_parity = parity == 1,
        .r = try rpc.quantity(u256, try rpc.field(tx, "r")),
        .s = try rpc.quantity(u256, try rpc.field(tx, "s")),
    };
}

fn legacy_from_json(
    tx: json.Value,
    nonce: u64,
    gas_limit: u64,
    to: consensus.TxKind,
    value: u256,
    input: []const u8,
) Error!consensus.Envelope {
    const v = try rpc.quantity(u256, try rpc.field(tx, "v"));
    const legacy_v = consensus.signature.decode_legacy_v(v) orelse return error.InvalidSignature;
    return .{ .legacy = .{ .tx = .{
        .chain_id = legacy_v.chain_id,
        .nonce = nonce,
        .gas_price = try rpc.quantity(u128, try rpc.field(tx, "gasPrice")),
        .gas_limit = gas_limit,
        .to = to,
        .value = value,
        .input = input,
    }, .signature = .{
        .y_parity = legacy_v.y_parity,
        .r = try rpc.quantity(u256, try rpc.field(tx, "r")),
        .s = try rpc.quantity(u256, try rpc.field(tx, "s")),
    } } };
}

const testing = std.testing;
const txdata = @import("../txdata/root.zig");
const accounts = @import("../devnet/accounts.zig");

/// Writes the JSON object for a signed typed or legacy transaction, as a node would.
fn write_tx_json(w: *std.Io.Writer, envelope: consensus.Envelope) !void {
    const signature = envelope.signature().?;
    switch (envelope) {
        .eip1559 => |signed| {
            const tx = signed.tx;
            try w.print("{{\"type\":\"0x2\",\"chainId\":\"0x{x}\",", .{tx.chain_id});
            try w.print("\"maxPriorityFeePerGas\":\"0x{x}\",", .{tx.max_priority_fee_per_gas});
            try w.print("\"maxFeePerGas\":\"0x{x}\",", .{tx.max_fee_per_gas});
            try w.print("\"to\":\"0x{x}\",\"accessList\":[],", .{&tx.to.call.bytes});
            try w.print("\"yParity\":\"0x{x}\",", .{@intFromBool(signature.y_parity)});
            try write_common(w, tx.nonce, tx.gas_limit, tx.value, tx.input);
        },
        .legacy => |signed| {
            const tx = signed.tx;
            try w.print("{{\"type\":\"0x0\",\"gasPrice\":\"0x{x}\",", .{tx.gas_price});
            try w.print("\"to\":null,\"v\":\"0x{x}\",", .{signature.legacy_v(tx.chain_id)});
            try write_common(w, tx.nonce, tx.gas_limit, tx.value, tx.input);
        },
        else => unreachable,
    }
    try w.print("\"r\":\"0x{x}\",\"s\":\"0x{x}\",", .{ signature.r, signature.s });
    try w.print("\"hash\":\"0x{x}\"}}", .{&envelope.hash().bytes});
}

fn write_common(w: *std.Io.Writer, nonce: u64, gas: u64, value: u256, input: []const u8) !void {
    try w.print("\"nonce\":\"0x{x}\",\"gas\":\"0x{x}\",", .{ nonce, gas });
    try w.print("\"value\":\"0x{x}\",\"input\":\"0x{x}\",", .{ value, input });
}

fn sign_legacy(key: [32]u8) !consensus.Envelope {
    var envelope: consensus.Envelope = .{ .legacy = .{ .tx = .{
        .chain_id = 901,
        .nonce = 0,
        .gas_price = 5,
        .gas_limit = 100_000,
        .to = .create,
        .value = 0,
        .input = &.{ 0x60, 0x00 },
    }, .signature = .{ .y_parity = false, .r = 1, .s = 1 } } };
    envelope.legacy.signature = try consensus.signature.sign(key, envelope.signing_hash().?);
    return envelope;
}

test "source: decodes a block with an L1 info deposit, a 1559 and a legacy tx" {
    const user = accounts.derive_dev(1);
    const transfer = try txdata.sign_eip1559(.{
        .chain_id = 901,
        .nonce = 9,
        .fees = txdata.suggest_fees(100, 2),
        .gas_limit = 21_000,
        .to = .{ .bytes = @splat(0x33) },
        .value = 12345,
        .data = &.{ 0xde, 0xad },
    }, user.private_key);
    const legacy = try sign_legacy(user.private_key);
    const info: l1_info.L1BlockInfo = .{
        .format = .jovian,
        .number = 77,
        .block_hash = .{ .bytes = @splat(0x77) },
        .sequence_number = 3,
    };
    var calldata: [l1_info.calldata_length_max]u8 = undefined;
    const info_input = info.encode_calldata(&calldata);

    const block_hash: [32]u8 = @splat(0xaa);
    const parent_hash: [32]u8 = @splat(0xbb);
    var text: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&text);
    try w.print(
        "{{\"number\":\"0x10\",\"hash\":\"0x{x}\",\"parentHash\":\"0x{x}\"," ++
            "\"timestamp\":\"0x64\"," ++
            "\"transactions\":[{{\"type\":\"0x7e\",\"input\":\"0x{x}\"}},",
        .{ &block_hash, &parent_hash, info_input },
    );
    try write_tx_json(&w, transfer);
    try w.writeAll(",");
    try write_tx_json(&w, legacy);
    try w.writeAll("]}");

    const parsed = try json.parseFromSlice(json.Value, testing.allocator, w.buffered(), .{});
    defer parsed.deinit();
    var decoder = try Decoder.init(testing.allocator, .{
        .tx_count_max = 4,
        .tx_bytes_max = 4096,
        .input_bytes_max = 4096,
    });
    defer decoder.deinit(testing.allocator);
    const block = try decoder.decode(parsed.value);
    try testing.expectEqual(@as(u64, 16), block.number);
    try testing.expectEqual(@as(u64, 100), block.timestamp);
    try testing.expectEqual(@as(u64, 77), block.l1_origin.number);
    try testing.expectEqual(@as(u64, 3), block.sequence_number);
    try testing.expectEqual(@as(usize, 2), block.transactions.len);
    var raw: [512]u8 = undefined;
    try testing.expectEqualSlices(u8, transfer.encode_to(&raw), block.transactions[0]);
    try testing.expectEqualSlices(u8, legacy.encode_to(&raw), block.transactions[1]);

    // Seeded mutation fuzz: corrupted node responses fail cleanly, never crash.
    var prng = @import("../../testing/prng.zig").Prng.init(0x736f7572);
    var mutated: [8192]u8 = undefined;
    const original = w.buffered();
    for (0..300) |_| {
        @memcpy(mutated[0..original.len], original);
        for (0..prng.range(1, 4)) |_| {
            mutated[prng.below(original.len)] = "0123456789abcdefx\"{}[],:"[prng.below(25)];
        }
        const text_mutated = mutated[0..original.len];
        const value = json.parseFromSlice(json.Value, testing.allocator, text_mutated, .{}) catch
            continue;
        defer value.deinit();
        _ = decoder.decode(value.value) catch continue;
    }
}

test "source: rebuilds an EIP-7702 transaction with its authorization list" {
    const user = accounts.derive_dev(1);
    const authorizations = [_]consensus.Authorization{
        .{
            .chain_id = 901,
            .address = .{
                .bytes = @splat(0x44),
            },
            .nonce = 3,
            .y_parity = 1,
            .r = 7,
            .s = 9,
        },
        .{ .chain_id = 0, .address = .{
            .bytes = @splat(0x55),
        }, .nonce = 0, .y_parity = 0, .r = 1, .s = 2 },
    };
    var list_buffer: [512]u8 = undefined;
    var envelope: consensus.Envelope = .{ .eip7702 = .{ .tx = .{
        .chain_id = 901,
        .nonce = 4,
        .max_priority_fee_per_gas = 2,
        .max_fee_per_gas = 300,
        .gas_limit = 80_000,
        .to = .{ .bytes = @splat(0x66) },
        .value = 0,
        .input = &.{0x01},
        .access_list = .empty,
        .authorization_list = consensus.AuthorizationList.build(&list_buffer, &authorizations),
    }, .signature = .{ .y_parity = false, .r = 1, .s = 1 } } };
    envelope.eip7702.signature = try consensus.signature.sign(
        user.private_key,
        envelope.signing_hash().?,
    );
    const tx = envelope.eip7702.tx;
    const signature = envelope.eip7702.signature;
    var text: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&text);
    try w.print("{{\"type\":\"0x4\",\"chainId\":\"0x{x}\",\"maxPriorityFeePerGas\":\"0x2\",", .{
        tx.chain_id,
    });
    try w.print("\"maxFeePerGas\":\"0x{x}\",", .{tx.max_fee_per_gas});
    try w.print("\"to\":\"0x{x}\",", .{&tx.to.bytes});
    try w.writeAll("\"accessList\":[],\"authorizationList\":[");
    for (authorizations, 0..) |item, index| {
        if (index > 0) try w.writeAll(",");
        try w.print("{{\"chainId\":\"0x{x}\",\"address\":\"0x{x}\",\"nonce\":\"0x{x}\",", .{
            item.chain_id,
            &item.address.bytes,
            item.nonce,
        });
        try w.print("\"yParity\":\"0x{x}\",\"r\":\"0x{x}\",\"s\":\"0x{x}\"}}", .{
            item.y_parity,
            item.r,
            item.s,
        });
    }
    try w.print("],\"yParity\":\"0x{x}\",", .{@intFromBool(signature.y_parity)});
    try write_common(&w, tx.nonce, tx.gas_limit, tx.value, tx.input);
    try w.print("\"r\":\"0x{x}\",\"s\":\"0x{x}\",", .{ signature.r, signature.s });
    try w.print("\"hash\":\"0x{x}\"}}", .{&envelope.hash().bytes});

    const parsed = try json.parseFromSlice(json.Value, testing.allocator, w.buffered(), .{});
    defer parsed.deinit();
    var decoder = try Decoder.init(testing.allocator, .{
        .tx_count_max = 2,
        .tx_bytes_max = 2048,
        .input_bytes_max = 2048,
    });
    defer decoder.deinit(testing.allocator);
    const encoded = try decoder.encode_transaction(parsed.value, 4);
    var expected: [1024]u8 = undefined;
    try testing.expectEqualSlices(u8, envelope.encode_to(&expected), encoded);
}

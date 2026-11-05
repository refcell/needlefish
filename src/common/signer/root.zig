//! Remote signer client codecs: `eth_signTransaction` to an external signer sidecar.
//! Mirrors base/base `crates/common/signer`. Transport-agnostic: the caller POSTs the
//! request body and hands back the response body. Responses are trusted only after
//! `verify_signed`: same signing hash as the transaction we asked for, and signed by
//! the expected address.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const consensus = @import("../consensus/root.zig");
const rpc_types = @import("../rpc_types/root.zig");
const json = rpc_types.json;
const hex = primitives.hex;
const Address = primitives.Address;
const Envelope = consensus.tx.Envelope;
const Signature = consensus.signature.Signature;
const Writer = std.Io.Writer;
const Object = json.Object;

/// Writes the JSON-RPC request asking `from` to sign `unsigned` (its signature is
/// ignored). Deposits and 0x79 transactions are not signed this way.
pub fn write_sign_request(
    w: *Writer,
    id: u64,
    unsigned: Envelope,
    from: Address,
) json.Error!void {
    assert(unsigned != .deposit and unsigned != .eip8130);
    try w.print("{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"eth_signTransaction\",", .{id});
    try w.writeAll("\"params\":[");
    var object = try Object.begin(w);
    try object.address("from", from);
    try object.quantity("type", @backingInt(unsigned.tx_type()));
    switch (unsigned) {
        .legacy => |signed| try write_legacy(&object, signed.tx),
        .eip2930 => |signed| try write_common(&object, signed.tx, signed.tx.to),
        .eip1559 => |signed| try write_common(&object, signed.tx, signed.tx.to),
        .eip4844 => |signed| {
            try write_common(&object, signed.tx, .{ .call = signed.tx.to });
            try object.quantity("maxFeePerBlobGas", signed.tx.max_fee_per_blob_gas);
            try object.key("blobVersionedHashes");
            try rpc_types.write_hash_list(w, signed.tx.blob_versioned_hashes);
        },
        .eip7702 => |signed| {
            try write_common(&object, signed.tx, .{ .call = signed.tx.to });
            try write_authorizations(&object, signed.tx.authorization_list);
        },
        .deposit, .eip8130 => unreachable, // Asserted above.
    }
    try object.end();
    try w.writeAll("]}");
}

fn write_to(object: *Object, to: consensus.tx.TxKind) json.Error!void {
    switch (to) {
        .call => |address| try object.address("to", address),
        .create => {},
    }
}

fn write_legacy(object: *Object, tx: consensus.tx.Legacy) json.Error!void {
    try object.optional_quantity("chainId", tx.chain_id);
    try object.quantity("nonce", tx.nonce);
    try object.quantity("gas", tx.gas_limit);
    try object.quantity("gasPrice", tx.gas_price);
    try write_to(object, tx.to);
    try object.quantity("value", tx.value);
    try object.data("input", tx.input);
}

/// Typed transactions: chain id, fees (gas price or the 1559 pair), and access list.
fn write_common(object: *Object, tx: anytype, to: consensus.tx.TxKind) json.Error!void {
    try object.quantity("chainId", tx.chain_id);
    try object.quantity("nonce", tx.nonce);
    try object.quantity("gas", tx.gas_limit);
    if (@hasField(@TypeOf(tx), "gas_price")) {
        try object.quantity("gasPrice", tx.gas_price);
    } else {
        try object.quantity("maxFeePerGas", tx.max_fee_per_gas);
        try object.quantity("maxPriorityFeePerGas", tx.max_priority_fee_per_gas);
    }
    try write_to(object, to);
    try object.quantity("value", tx.value);
    try object.data("input", tx.input);
    try object.key("accessList");
    try object.w.writeByte('[');
    var iterator = tx.access_list.iterator();
    var first = true;
    while (iterator.next()) |item| {
        if (!first) try object.w.writeByte(',');
        first = false;
        var entry = try Object.begin(object.w);
        try entry.address("address", item.address);
        try entry.key("storageKeys");
        try rpc_types.write_hash_list(object.w, item.storage_keys);
        try entry.end();
    }
    try object.w.writeByte(']');
}

fn write_authorizations(
    object: *Object,
    list: consensus.tx_fields.AuthorizationList,
) json.Error!void {
    try object.key("authorizationList");
    try object.w.writeByte('[');
    var iterator = list.iterator();
    var first = true;
    while (iterator.next()) |authorization| {
        if (!first) try object.w.writeByte(',');
        first = false;
        var item = try Object.begin(object.w);
        try item.quantity("chainId", authorization.chain_id);
        try item.address("address", authorization.address);
        try item.quantity("nonce", authorization.nonce);
        try item.quantity("yParity", authorization.y_parity);
        try item.quantity("r", authorization.r);
        try item.quantity("s", authorization.s);
        try item.end();
    }
    try object.w.writeByte(']');
}

pub const ResponseError = error{
    InvalidResponse,
    /// The signer answered with a JSON-RPC error object.
    SignerError,
    OutOfMemory,
};

/// The raw signed transaction from a JSON-RPC response body (allocated from `arena`).
pub fn parse_sign_response(arena: std.mem.Allocator, body: []const u8) ResponseError![]const u8 {
    const Response = struct {
        result: ?[]const u8 = null,
        @"error": ?std.json.Value = null,
    };
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const response = std.json.parseFromSliceLeaky(Response, arena, body, options) catch |err|
        return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidResponse;
    if (response.@"error" != null) return error.SignerError;
    const text = response.result orelse return error.InvalidResponse;
    if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidResponse;
    const length = hex.decoded_length(text) catch return error.InvalidResponse;
    const raw = try arena.alloc(u8, length);
    hex.decode(raw, text) catch return error.InvalidResponse;
    return raw;
}

pub const VerifyError = error{
    Decode,
    /// The signer signed different content than we asked for.
    ContentMismatch,
    /// The signature does not recover to the configured signer address.
    SignerMismatch,
};

/// Decodes the signed transaction and checks it against the request. Returns the
/// verified envelope (borrowing `raw`).
pub fn verify_signed(raw: []const u8, unsigned: Envelope, expected: Address) VerifyError!Envelope {
    assert(unsigned != .deposit and unsigned != .eip8130);
    const signed = Envelope.decode(raw) catch return error.Decode;
    if (signed == .deposit or signed == .eip8130) return error.ContentMismatch;
    const expected_hash = unsigned.signing_hash().?;
    if (!signed.signing_hash().?.eql(expected_hash)) return error.ContentMismatch;
    const recovered = signed.recover_sender(consensus.signature.recover_address) orelse
        return error.SignerMismatch;
    if (!recovered.eql(expected)) return error.SignerMismatch;
    return signed;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const zero_signature: Signature = .{ .y_parity = false, .r = 0, .s = 0 };
const rlp = @import("../rlp/root.zig");

const dev_key = primitives.hex.decode_array(
    32,
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
) catch unreachable; // Constant, valid hex.
const dev_address = Address.comptime_hex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

fn sample_tx() consensus.tx.Eip1559 {
    return .{
        .chain_id = 8453,
        .nonce = 4,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 1_000,
        .gas_limit = 21_000,
        .to = .{ .call = Address.comptime_hex("4200000000000000000000000000000000000006") },
        .value = 7,
        .input = &.{},
        .access_list = .empty,
    };
}

test "signer: request body" {
    const unsigned: Envelope = .{ .eip1559 = .{ .tx = sample_tx(), .signature = zero_signature } };
    var buffer: [2048]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try write_sign_request(&w, 9, unsigned, dev_address);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena, w.buffered(), .{});
    try testing.expectEqualStrings("eth_signTransaction", value.object.get("method").?.string);
    const params = value.object.get("params").?.array.items[0];
    // The body parses back as a TransactionRequest with the same fields.
    const request = try rpc_types.request.parse_transaction_request(arena, params);
    try testing.expectEqual(@as(?u64, 8453), request.chain_id);
    try testing.expectEqual(@as(?u128, 1_000), request.max_fee_per_gas);
    try testing.expect(request.from.?.eql(dev_address));
    try testing.expectEqual(consensus.tx.TxType.eip1559, request.preferred_type());
}

test "signer: response parse and verification" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tx = sample_tx();
    const unsigned: Envelope = .{ .eip1559 = .{ .tx = tx, .signature = zero_signature } };
    const signed = try consensus.tx.sign(tx, dev_key);
    var encoded: [256]u8 = undefined;
    var encoder = rlp.Encoder.init(&encoded);
    signed.encode(&encoder);
    var body: [1024]u8 = undefined;
    var w: Writer = .fixed(&body);
    try w.writeAll("{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":");
    try json.write_data(&w, encoder.written());
    try w.writeByte('}');
    const raw = try parse_sign_response(arena, w.buffered());
    const verified = try verify_signed(raw, unsigned, dev_address);
    try testing.expect(verified.hash().eql(signed.hash()));
    try testing.expectError(error.SignerMismatch, verify_signed(raw, unsigned, .zero));
    var other = tx;
    other.nonce += 1;
    const other_unsigned: Envelope = .{ .eip1559 = .{ .tx = other, .signature = zero_signature } };
    try testing.expectError(error.ContentMismatch, verify_signed(raw, other_unsigned, dev_address));
    try testing.expectError(error.Decode, verify_signed(raw[0..10], unsigned, dev_address));
    const failure = "{\"jsonrpc\":\"2.0\",\"id\":9,\"error\":{\"code\":-32000,\"message\":\"no\"}}";
    try testing.expectError(error.SignerError, parse_sign_response(arena, failure));
    try testing.expectError(error.InvalidResponse, parse_sign_response(arena, "{\"result\":1}"));
}

test "signer: seeded fuzz responses never verify wrongly" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const tx = sample_tx();
    const unsigned: Envelope = .{ .eip1559 = .{ .tx = tx, .signature = zero_signature } };
    const signed = try consensus.tx.sign(tx, dev_key);
    var encoded: [256]u8 = undefined;
    var encoder = rlp.Encoder.init(&encoded);
    signed.encode(&encoder);
    const original = encoder.written();
    var prng = Prng.init(0x5167);
    var mutated: [256]u8 = undefined;
    for (0..64) |_| {
        @memcpy(mutated[0..original.len], original);
        mutated[prng.below(original.len)] ^= @as(u8, 1) << @intCast(prng.below(8));
        const verified = verify_signed(mutated[0..original.len], unsigned, dev_address) catch
            continue;
        // A mutation can only survive if it left the signed content and signer intact.
        try testing.expect(verified.signing_hash().?.eql(unsigned.signing_hash().?));
    }
}

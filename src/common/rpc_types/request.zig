//! JSON-RPC request parameters: `TransactionRequest` (eth_call, eth_estimateGas,
//! eth_sendTransaction) and EIP-1898 block ids. Parses an already-parsed
//! `std.json.Value` (the caller owns JSON tokenizing); decoded byte fields are allocated
//! from a per-request arena. Mirrors alloy's `TransactionRequest` plus the scalar fields
//! of base/base `Eip8130RequestFields`.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const consensus = @import("../consensus/root.zig");
const hex = primitives.hex;
const Address = primitives.Address;
const B256 = primitives.B256;
const Value = std.json.Value;
const fields = consensus.tx_fields;
const Allocator = std.mem.Allocator;

pub const ParseError = error{
    NotAnObject,
    InvalidField,
    /// `input` and `data` were both given with different contents.
    ConflictingInput,
    /// EIP-8130 `accountChanges`/`calls` in a request (not supported yet).
    UnsupportedField,
    OutOfMemory,
};

/// Upper bounds for list fields, so one request cannot claim unbounded work.
pub const access_list_items_max = 4096;
pub const storage_keys_max = 16 * 1024;
pub const blob_hashes_max = consensus.sidecar.blobs_per_tx_max;
pub const authorizations_max = 1024;

pub const TransactionRequest = struct {
    from: ?Address = null,
    /// Null means contract creation.
    to: ?Address = null,
    gas: ?u64 = null,
    gas_price: ?u128 = null,
    max_fee_per_gas: ?u128 = null,
    max_priority_fee_per_gas: ?u128 = null,
    max_fee_per_blob_gas: ?u128 = null,
    value: ?u256 = null,
    input: ?[]const u8 = null,
    nonce: ?u64 = null,
    chain_id: ?u64 = null,
    tx_type: ?u8 = null,
    access_list: ?fields.AccessList = null,
    blob_versioned_hashes: ?fields.HashList = null,
    authorization_list: ?fields.AuthorizationList = null,
    // EIP-8130 scalar fields.
    nonce_key: ?u256 = null,
    valid_after: ?u64 = null,
    valid_before: ?u64 = null,
    metadata: ?[]const u8 = null,
    sender: ?Address = null,
    payer: ?Address = null,
    sender_auth: ?[]const u8 = null,
    payer_auth: ?[]const u8 = null,

    pub fn has_eip8130_fields(request: TransactionRequest) bool {
        return request.nonce_key != null or request.valid_after != null or
            request.valid_before != null or request.metadata != null or
            request.sender != null or request.payer != null or
            request.sender_auth != null or request.payer_auth != null;
    }

    /// The type a node would build from these fields (alloy `preferred_type`, plus 0x79).
    pub fn preferred_type(request: TransactionRequest) consensus.tx.TxType {
        if (request.tx_type) |byte| {
            if (std.enums.fromInt(consensus.tx.TxType, byte)) |known| return known;
        }
        if (request.has_eip8130_fields()) return .eip8130;
        if (request.authorization_list != null) return .eip7702;
        if (request.blob_versioned_hashes != null or request.max_fee_per_blob_gas != null) {
            return .eip4844;
        }
        if (request.gas_price != null) {
            return if (request.access_list != null) .eip2930 else .legacy;
        }
        return .eip1559;
    }
};

pub fn parse_transaction_request(arena: Allocator, value: Value) ParseError!TransactionRequest {
    if (value != .object) return error.NotAnObject;
    const object = value.object;
    if (object.get("accountChanges") != null or object.get("calls") != null) {
        return error.UnsupportedField;
    }
    var request: TransactionRequest = .{
        .from = try optional_address(object, "from"),
        .to = try optional_address(object, "to"),
        .gas = try optional_quantity(u64, object, "gas") orelse
            try optional_quantity(u64, object, "gasLimit"),
        .gas_price = try optional_quantity(u128, object, "gasPrice"),
        .max_fee_per_gas = try optional_quantity(u128, object, "maxFeePerGas"),
        .max_priority_fee_per_gas = try optional_quantity(u128, object, "maxPriorityFeePerGas"),
        .max_fee_per_blob_gas = try optional_quantity(u128, object, "maxFeePerBlobGas"),
        .value = try optional_quantity(u256, object, "value"),
        .nonce = try optional_quantity(u64, object, "nonce"),
        .chain_id = try optional_quantity(u64, object, "chainId"),
        .tx_type = try optional_quantity(u8, object, "type"),
        .nonce_key = try optional_quantity(u256, object, "nonceKey"),
        .valid_after = try optional_quantity(u64, object, "validAfter"),
        .valid_before = try optional_quantity(u64, object, "validBefore"),
        .metadata = try optional_data(arena, object, "metadata"),
        .sender = try optional_address(object, "sender"),
        .payer = try optional_address(object, "payer"),
        .sender_auth = try optional_data(arena, object, "senderAuth"),
        .payer_auth = try optional_data(arena, object, "payerAuth"),
    };
    request.input = try parse_input(arena, object);
    if (object.get("accessList")) |list| request.access_list = try parse_access_list(arena, list);
    if (object.get("blobVersionedHashes")) |list| {
        request.blob_versioned_hashes = try parse_hash_list(arena, list, blob_hashes_max);
    }
    if (object.get("authorizationList")) |list| {
        request.authorization_list = try parse_authorizations(arena, list);
    }
    return request;
}

/// `input` wins; `data` is the legacy alias. Both present must agree.
fn parse_input(arena: Allocator, object: std.json.ObjectMap) ParseError!?[]const u8 {
    const input = try optional_data(arena, object, "input");
    const data = try optional_data(arena, object, "data");
    if (input != null and data != null and !std.mem.eql(u8, input.?, data.?)) {
        return error.ConflictingInput;
    }
    return input orelse data;
}

fn field(object: std.json.ObjectMap, name: []const u8) ?Value {
    const value = object.get(name) orelse return null;
    return if (value == .null) null else value;
}

fn required(object: std.json.ObjectMap, name: []const u8) ParseError!Value {
    return field(object, name) orelse error.InvalidField;
}

fn string_of(value: Value) ParseError![]const u8 {
    return if (value == .string) value.string else error.InvalidField;
}

pub fn quantity(comptime T: type, value: Value) ParseError!T {
    return hex.decode_quantity(T, try string_of(value)) catch error.InvalidField;
}

fn fixed(comptime size: usize, value: Value) ParseError![size]u8 {
    const text = try string_of(value);
    if (text.len != 2 + 2 * size or !std.mem.startsWith(u8, text, "0x")) {
        return error.InvalidField;
    }
    return hex.decode_array(size, text) catch error.InvalidField;
}

fn optional_quantity(
    comptime T: type,
    object: std.json.ObjectMap,
    name: []const u8,
) ParseError!?T {
    const value = field(object, name) orelse return null;
    return try quantity(T, value);
}

fn optional_address(object: std.json.ObjectMap, name: []const u8) ParseError!?Address {
    const value = field(object, name) orelse return null;
    return .{ .bytes = try fixed(20, value) };
}

fn data_of(arena: Allocator, value: Value) ParseError![]const u8 {
    const text = try string_of(value);
    if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidField;
    const length = hex.decoded_length(text) catch return error.InvalidField;
    const output = try arena.alloc(u8, length);
    hex.decode(output, text) catch return error.InvalidField;
    return output;
}

fn optional_data(
    arena: Allocator,
    object: std.json.ObjectMap,
    name: []const u8,
) ParseError!?[]const u8 {
    const value = field(object, name) orelse return null;
    return try data_of(arena, value);
}

fn array_of(value: Value, limit: usize) ParseError![]const Value {
    if (value != .array) return error.InvalidField;
    if (value.array.items.len > limit) return error.InvalidField;
    return value.array.items;
}

fn parse_hashes(arena: Allocator, value: Value, limit: usize) ParseError![]const B256 {
    const items = try array_of(value, limit);
    const hashes = try arena.alloc(B256, items.len);
    for (hashes, items) |*hash, item| hash.* = .{ .bytes = try fixed(32, item) };
    return hashes;
}

fn parse_hash_list(arena: Allocator, value: Value, limit: usize) ParseError!fields.HashList {
    const hashes = try parse_hashes(arena, value, limit);
    const buffer = try arena.alloc(u8, hashes.len * 33);
    return fields.HashList.build(buffer, hashes);
}

fn parse_access_list(arena: Allocator, value: Value) ParseError!fields.AccessList {
    const items = try array_of(value, access_list_items_max);
    const build_items = try arena.alloc(fields.AccessList.BuildItem, items.len);
    var keys_total: usize = 0;
    var length: usize = 0;
    for (build_items, items) |*out, item| {
        if (item != .object) return error.InvalidField;
        const address = field(item.object, "address") orelse return error.InvalidField;
        const keys = field(item.object, "storageKeys") orelse return error.InvalidField;
        out.* = .{
            .address = .{ .bytes = try fixed(20, address) },
            .storage_keys = try parse_hashes(arena, keys, storage_keys_max),
        };
        keys_total += out.storage_keys.len;
        if (keys_total > storage_keys_max) return error.InvalidField;
        // Two list headers (at most 9 bytes each), the address, the keys.
        length += 18 + 21 + out.storage_keys.len * 33;
    }
    return fields.AccessList.build(try arena.alloc(u8, length), build_items);
}

fn parse_authorizations(arena: Allocator, value: Value) ParseError!fields.AuthorizationList {
    const items = try array_of(value, authorizations_max);
    const authorizations = try arena.alloc(fields.Authorization, items.len);
    for (authorizations, items) |*out, item| {
        if (item != .object) return error.InvalidField;
        const object = item.object;
        out.* = .{
            .chain_id = try quantity(u256, try required(object, "chainId")),
            .address = .{ .bytes = try fixed(20, try required(object, "address")) },
            .nonce = try quantity(u64, try required(object, "nonce")),
            .y_parity = try quantity(u8, try required(object, "yParity")),
            .r = try quantity(u256, try required(object, "r")),
            .s = try quantity(u256, try required(object, "s")),
        };
    }
    // List header plus six fields: at most 9 + 33 + 21 + 9 + 2 + 33 + 33 bytes.
    const buffer = try arena.alloc(u8, authorizations.len * 140);
    return fields.AuthorizationList.build(buffer, authorizations);
}

pub const BlockTag = enum { latest, earliest, pending, safe, finalized };

/// EIP-1898 block identifier.
pub const BlockId = union(enum) {
    tag: BlockTag,
    number: u64,
    hash: struct { hash: B256, require_canonical: bool = false },
};

/// A tag, a hex number, a 32-byte hash string, or `{blockNumber}` /
/// `{blockHash, requireCanonical}`. A missing parameter (null) means `latest`.
pub fn parse_block_id(value: Value) ParseError!BlockId {
    switch (value) {
        .null => return .{ .tag = .latest },
        .string => |text| {
            if (std.meta.stringToEnum(BlockTag, text)) |tag| return .{ .tag = tag };
            if (text.len == 66) {
                return .{ .hash = .{ .hash = .{ .bytes = try fixed(32, value) } } };
            }
            return .{ .number = try quantity(u64, value) };
        },
        .object => |object| {
            const number = field(object, "blockNumber");
            const hash = field(object, "blockHash");
            if ((number == null) == (hash == null)) return error.InvalidField;
            if (number) |text| return .{ .number = try quantity(u64, text) };
            const canonical = field(object, "requireCanonical") orelse Value{ .bool = false };
            if (canonical != .bool) return error.InvalidField;
            return .{ .hash = .{
                .hash = .{ .bytes = try fixed(32, hash.?) },
                .require_canonical = canonical.bool,
            } };
        },
        else => return error.InvalidField,
    }
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn parse_text(arena: Allocator, text: []const u8) !TransactionRequest {
    const value = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    return parse_transaction_request(arena, value);
}

test "rpc request: dynamic fee call" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const request = try parse_text(arena_state.allocator(),
        \\{"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        \\"to":"0x4200000000000000000000000000000000000006","gas":"0x5208",
        \\"maxFeePerGas":"0x3b9aca00","value":"0x1","data":"0xd0e30db0",
        \\"accessList":[{"address":"0x4200000000000000000000000000000000000006",
        \\"storageKeys":["0x0000000000000000000000000000000000000000000000000000000000000001"]}]}
    );
    try testing.expectEqual(@as(?u64, 21_000), request.gas);
    try testing.expectEqual(@as(?u128, 1_000_000_000), request.max_fee_per_gas);
    try testing.expectEqualSlices(u8, &.{ 0xd0, 0xe3, 0x0d, 0xb0 }, request.input.?);
    try testing.expectEqual(@as(u32, 1), request.access_list.?.storage_key_count);
    var iterator = request.access_list.?.iterator();
    const item = iterator.next().?;
    try testing.expectEqual(@as(u8, 0x06), item.address.bytes[19]);
    try testing.expectEqual(consensus.tx.TxType.eip1559, request.preferred_type());
}

test "rpc request: types, conflicts, and failures" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqual(
        consensus.tx.TxType.legacy,
        (try parse_text(arena, "{\"gasPrice\":\"0x1\",\"to\":null}")).preferred_type(),
    );
    try testing.expectEqual(
        consensus.tx.TxType.eip8130,
        (try parse_text(arena, "{\"nonceKey\":\"0x5\"}")).preferred_type(),
    );
    try testing.expectError(
        error.ConflictingInput,
        parse_text(arena, "{\"input\":\"0x01\",\"data\":\"0x02\"}"),
    );
    try testing.expectEqual(1, (try parse_text(arena, "{\"input\":\"0x01\",\"data\":\"0x01\"}"))
        .input.?.len);
    try testing.expectError(error.InvalidField, parse_text(arena, "{\"gas\":\"0x01\"}"));
    try testing.expectError(error.InvalidField, parse_text(arena, "{\"to\":\"0x42\"}"));
    try testing.expectError(error.InvalidField, parse_text(arena, "{\"value\":1}"));
    try testing.expectError(error.UnsupportedField, parse_text(arena, "{\"calls\":[]}"));
    try testing.expectError(error.NotAnObject, parse_text(arena, "[]"));
    const authorization = try parse_text(arena,
        \\{"authorizationList":[{"chainId":"0x2105",
        \\"address":"0x4200000000000000000000000000000000000006","nonce":"0x0",
        \\"yParity":"0x1","r":"0x1","s":"0x2"}]}
    );
    var iterator = authorization.authorization_list.?.iterator();
    try testing.expectEqual(@as(u256, 8453), iterator.next().?.chain_id);
    try testing.expectEqual(consensus.tx.TxType.eip7702, authorization.preferred_type());
}

test "rpc request: block ids" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_]struct { text: []const u8, expected: BlockId }{
        .{ .text = "\"latest\"", .expected = .{ .tag = .latest } },
        .{ .text = "\"finalized\"", .expected = .{ .tag = .finalized } },
        .{ .text = "\"0x10\"", .expected = .{ .number = 16 } },
        .{ .text = "null", .expected = .{ .tag = .latest } },
        .{ .text = "{\"blockNumber\":\"0x0\"}", .expected = .{ .number = 0 } },
    };
    for (cases) |case| {
        const value = try std.json.parseFromSliceLeaky(Value, arena, case.text, .{});
        try testing.expectEqualDeep(case.expected, try parse_block_id(value));
    }
    const hash_text =
        \\{"blockHash":"0x0101010101010101010101010101010101010101010101010101010101010101",
        \\"requireCanonical":true}
    ;
    const value = try std.json.parseFromSliceLeaky(Value, arena, hash_text, .{});
    const id = try parse_block_id(value);
    try testing.expect(id.hash.require_canonical);
    try testing.expectEqual(@as(u8, 1), id.hash.hash.bytes[31]);
    const both = try std.json.parseFromSliceLeaky(Value, arena, "{}", .{});
    try testing.expectError(error.InvalidField, parse_block_id(both));
    const bad = try std.json.parseFromSliceLeaky(Value, arena, "\"pending2\"", .{});
    try testing.expectError(error.InvalidField, parse_block_id(bad));
}

test "rpc request: seeded fuzz mutated requests" {
    const base_text =
        \\{"to":"0x4200000000000000000000000000000000000006","gas":"0x5208","input":"0x00",
        \\"accessList":[{"address":"0x4200000000000000000000000000000000000006","storageKeys":[]}],
        \\"blobVersionedHashes":[]}
    ;
    var prng = Prng.init(0x5e9);
    var text: [base_text.len]u8 = undefined;
    for (0..500) |_| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        text = base_text.*;
        text[prng.below(text.len)] = prng.int(u8);
        const arena = arena_state.allocator();
        const value = std.json.parseFromSliceLeaky(Value, arena, &text, .{}) catch continue;
        _ = parse_transaction_request(arena, value) catch {};
        _ = parse_block_id(value) catch {};
    }
}

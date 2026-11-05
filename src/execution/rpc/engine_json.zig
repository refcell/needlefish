//! Engine API JSON codecs: execution payloads, payload attributes, forkchoice state and
//! payload status (execution-apis `engine/*.md` plus the OP Stack extensions).
//!
//! Decoding is bounded: variable-length parts (transactions, extra data, withdrawals,
//! versioned hashes) go into a caller-provided `Space` sized at startup.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const payload = @import("../payload/root.zig");
const engine = @import("../engine/root.zig");

const B256 = primitives.B256;
const Address = primitives.Address;
const types = engine.types;

pub const Error = error{InvalidParams};

/// Decoding space for one request; `reset` before each.
pub const Space = struct {
    bytes: []u8,
    bytes_used: usize = 0,
    transactions: [][]const u8,
    transactions_used: usize = 0,
    withdrawals: []payload.Withdrawal,
    withdrawals_used: usize = 0,
    hashes: []B256,
    hashes_used: usize = 0,

    pub fn reset(space: *Space) void {
        space.bytes_used = 0;
        space.transactions_used = 0;
        space.withdrawals_used = 0;
        space.hashes_used = 0;
    }

    fn data(space: *Space, text: []const u8) Error![]const u8 {
        const out = space.bytes[space.bytes_used..];
        const decoded = json.parse_data(text, out) catch return error.InvalidParams;
        space.bytes_used += decoded.len;
        assert(space.bytes_used <= space.bytes.len);
        return decoded;
    }
};

fn next(scanner: *json.Scanner) Error!json.Token {
    return scanner.next() catch error.InvalidParams;
}

fn string_of(token: json.Token) Error![]const u8 {
    if (token.tag != .string) return error.InvalidParams;
    return token.bytes;
}

fn quantity(comptime T: type, token: json.Token) Error!T {
    return json.parse_quantity(T, try string_of(token)) catch error.InvalidParams;
}

fn fixed(comptime N: usize, token: json.Token) Error![N]u8 {
    return json.parse_fixed(N, try string_of(token)) catch error.InvalidParams;
}

fn hash(token: json.Token) Error!B256 {
    return .{ .bytes = try fixed(32, token) };
}

fn address(token: json.Token) Error!Address {
    return .{ .bytes = try fixed(20, token) };
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Iterates `{ "name": value, ... }`, calling `context.field(name, value, scanner)`.
fn parse_object(raw: []const u8, context: anytype) Error!void {
    var scanner = json.Scanner.init(raw);
    if ((try next(&scanner)).tag != .object_begin) return error.InvalidParams;
    var fields: u32 = 0;
    while (fields < 64) : (fields += 1) {
        const name = try next(&scanner);
        if (name.tag == .object_end) return;
        if (name.tag != .string) return error.InvalidParams;
        const value = try next(&scanner);
        if (value.tag == .null) continue;
        const known = try context.field(name.bytes, value, &scanner);
        if (!known) scanner.skip(value) catch return error.InvalidParams;
    }
    return error.InvalidParams;
}

/// A JSON array of hex data strings, decoded into `space`.
fn parse_data_list(
    space: *Space,
    first: json.Token,
    scanner: *json.Scanner,
) Error![]const []const u8 {
    if (first.tag != .array_begin) return error.InvalidParams;
    const start = space.transactions_used;
    while (true) {
        const token = try next(scanner);
        if (token.tag == .array_end) break;
        if (space.transactions_used == space.transactions.len) return error.InvalidParams;
        space.transactions[space.transactions_used] = try space.data(try string_of(token));
        space.transactions_used += 1;
    }
    return space.transactions[start..space.transactions_used];
}

fn parse_hash_list(space: *Space, first: json.Token, scanner: *json.Scanner) Error![]const B256 {
    if (first.tag != .array_begin) return error.InvalidParams;
    const start = space.hashes_used;
    while (true) {
        const token = try next(scanner);
        if (token.tag == .array_end) break;
        if (space.hashes_used == space.hashes.len) return error.InvalidParams;
        space.hashes[space.hashes_used] = try hash(token);
        space.hashes_used += 1;
    }
    return space.hashes[start..space.hashes_used];
}

const WithdrawalFields = struct {
    out: *payload.Withdrawal,
    seen: u8 = 0,

    fn field(
        context: *WithdrawalFields,
        name: []const u8,
        value: json.Token,
        _: *json.Scanner,
    ) Error!bool {
        if (eql(name, "index")) {
            context.out.index = try quantity(u64, value);
        } else if (eql(name, "validatorIndex")) {
            context.out.validator_index = try quantity(u64, value);
        } else if (eql(name, "address")) {
            context.out.address = try address(value);
        } else if (eql(name, "amount")) {
            context.out.amount_gwei = try quantity(u64, value);
        } else return false;
        context.seen += 1;
        return true;
    }
};

fn parse_withdrawals(
    space: *Space,
    first: json.Token,
    scanner: *json.Scanner,
) Error![]const payload.Withdrawal {
    if (first.tag != .array_begin) return error.InvalidParams;
    const start = space.withdrawals_used;
    while (true) {
        const token = try next(scanner);
        if (token.tag == .array_end) break;
        if (token.tag != .object_begin) return error.InvalidParams;
        if (space.withdrawals_used == space.withdrawals.len) return error.InvalidParams;
        const begin = scanner.offset() - 1;
        scanner.skip(token) catch return error.InvalidParams;
        const out = &space.withdrawals[space.withdrawals_used];
        var fields: WithdrawalFields = .{ .out = out };
        try parse_object(scanner.input[begin..scanner.offset()], &fields);
        if (fields.seen != 4) return error.InvalidParams;
        space.withdrawals_used += 1;
    }
    return space.withdrawals[start..space.withdrawals_used];
}

const PayloadFields = struct {
    space: *Space,
    out: types.ExecutionPayload,
    seen: u32 = 0,

    const required = 14;

    fn field(
        context: *PayloadFields,
        name: []const u8,
        value: json.Token,
        scanner: *json.Scanner,
    ) Error!bool {
        const out = &context.out;
        if (eql(name, "parentHash")) {
            out.parent_hash = try hash(value);
        } else if (eql(name, "feeRecipient")) {
            out.fee_recipient = try address(value);
        } else if (eql(name, "stateRoot")) {
            out.state_root = try hash(value);
        } else if (eql(name, "receiptsRoot")) {
            out.receipts_root = try hash(value);
        } else if (eql(name, "logsBloom")) {
            out.logs_bloom = .{ .bytes = try fixed(256, value) };
        } else if (eql(name, "prevRandao")) {
            out.prev_randao = try hash(value);
        } else if (eql(name, "blockNumber")) {
            out.block_number = try quantity(u64, value);
        } else if (eql(name, "gasLimit")) {
            out.gas_limit = try quantity(u64, value);
        } else if (eql(name, "gasUsed")) {
            out.gas_used = try quantity(u64, value);
        } else if (eql(name, "timestamp")) {
            out.timestamp = try quantity(u64, value);
        } else if (eql(name, "extraData")) {
            out.extra_data = try context.space.data(try string_of(value));
        } else if (eql(name, "baseFeePerGas")) {
            out.base_fee_per_gas = try quantity(u256, value);
        } else if (eql(name, "blockHash")) {
            out.block_hash = try hash(value);
        } else if (eql(name, "transactions")) {
            out.transactions = try parse_data_list(context.space, value, scanner);
        } else return context.optional_field(name, value, scanner);
        context.seen += 1;
        return true;
    }

    fn optional_field(
        context: *PayloadFields,
        name: []const u8,
        value: json.Token,
        scanner: *json.Scanner,
    ) Error!bool {
        const out = &context.out;
        if (eql(name, "withdrawals")) {
            out.withdrawals = try parse_withdrawals(context.space, value, scanner);
        } else if (eql(name, "blobGasUsed")) {
            out.blob_gas_used = try quantity(u64, value);
        } else if (eql(name, "excessBlobGas")) {
            out.excess_blob_gas = try quantity(u64, value);
        } else if (eql(name, "withdrawalsRoot")) {
            out.withdrawals_root = try hash(value);
        } else return false;
        return true;
    }
};

pub fn parse_payload(raw: []const u8, space: *Space) Error!types.ExecutionPayload {
    var fields: PayloadFields = .{ .space = space, .out = undefined };
    fields.out.withdrawals = null;
    fields.out.blob_gas_used = null;
    fields.out.excess_blob_gas = null;
    fields.out.withdrawals_root = null;
    try parse_object(raw, &fields);
    if (fields.seen != PayloadFields.required) return error.InvalidParams;
    return fields.out;
}

const AttributeFields = struct {
    space: *Space,
    out: payload.PayloadAttributes,
    seen: u32 = 0,

    fn field(
        context: *AttributeFields,
        name: []const u8,
        value: json.Token,
        scanner: *json.Scanner,
    ) Error!bool {
        const out = &context.out;
        if (eql(name, "timestamp")) {
            out.timestamp = try quantity(u64, value);
            context.seen += 1;
        } else if (eql(name, "prevRandao")) {
            out.prev_randao = try hash(value);
            context.seen += 1;
        } else if (eql(name, "suggestedFeeRecipient")) {
            out.suggested_fee_recipient = try address(value);
            context.seen += 1;
        } else if (eql(name, "withdrawals")) {
            out.withdrawals = try parse_withdrawals(context.space, value, scanner);
        } else if (eql(name, "parentBeaconBlockRoot")) {
            out.parent_beacon_block_root = try hash(value);
        } else if (eql(name, "transactions")) {
            out.transactions = try parse_data_list(context.space, value, scanner);
        } else if (eql(name, "noTxPool")) {
            out.no_tx_pool = switch (value.tag) {
                .true => true,
                .false => false,
                else => return error.InvalidParams,
            };
        } else if (eql(name, "gasLimit")) {
            out.gas_limit = try quantity(u64, value);
        } else if (eql(name, "eip1559Params")) {
            out.eip1559_params = try fixed(8, value);
        } else if (eql(name, "minBaseFee")) {
            out.min_base_fee = try quantity(u64, value);
        } else return false;
        return true;
    }
};

pub fn parse_attributes(raw: []const u8, space: *Space) Error!payload.PayloadAttributes {
    var fields: AttributeFields = .{
        .space = space,
        .out = .{ .timestamp = 0, .prev_randao = .zero, .suggested_fee_recipient = .zero },
    };
    try parse_object(raw, &fields);
    if (fields.seen != 3) return error.InvalidParams;
    return fields.out;
}

const ForkchoiceFields = struct {
    out: types.ForkchoiceState = undefined,
    seen: u8 = 0,

    fn field(
        context: *ForkchoiceFields,
        name: []const u8,
        value: json.Token,
        _: *json.Scanner,
    ) Error!bool {
        if (eql(name, "headBlockHash")) {
            context.out.head_block_hash = try hash(value);
        } else if (eql(name, "safeBlockHash")) {
            context.out.safe_block_hash = try hash(value);
        } else if (eql(name, "finalizedBlockHash")) {
            context.out.finalized_block_hash = try hash(value);
        } else return false;
        context.seen += 1;
        return true;
    }
};

pub fn parse_forkchoice(raw: []const u8) Error!types.ForkchoiceState {
    var fields: ForkchoiceFields = .{};
    try parse_object(raw, &fields);
    if (fields.seen != 3) return error.InvalidParams;
    return fields.out;
}

pub fn parse_hashes(raw: []const u8, space: *Space) Error![]const B256 {
    var scanner = json.Scanner.init(raw);
    return parse_hash_list(space, try next(&scanner), &scanner);
}

pub fn parse_data_array(raw: []const u8, space: *Space) Error![]const []const u8 {
    var scanner = json.Scanner.init(raw);
    return parse_data_list(space, try next(&scanner), &scanner);
}

// ---- Writers ----------------------------------------------------------------------

const WriteError = json.Writer.WriteError;

pub fn write_status(w: *json.Writer, status: types.PayloadStatus) WriteError!void {
    try w.begin_object();
    try w.key("status");
    try w.string(switch (status.status) {
        .valid => "VALID",
        .invalid => "INVALID",
        .syncing => "SYNCING",
        .accepted => "ACCEPTED",
    });
    try w.key("latestValidHash");
    if (status.latest_valid_hash) |h| try w.data(&h.bytes) else try w.null_value();
    try w.key("validationError");
    if (status.validation_error) |e| try w.string(e) else try w.null_value();
    try w.end_object();
}

pub fn write_forkchoice_updated(w: *json.Writer, updated: types.ForkchoiceUpdated) WriteError!void {
    try w.begin_object();
    try w.key("payloadStatus");
    try write_status(w, updated.payload_status);
    try w.key("payloadId");
    if (updated.payload_id) |id| try w.data(&id) else try w.null_value();
    try w.end_object();
}

pub fn write_payload(w: *json.Writer, p: *const types.ExecutionPayload) WriteError!void {
    try w.begin_object();
    const hashes = .{
        .{ "parentHash", &p.parent_hash.bytes },
        .{ "feeRecipient", &p.fee_recipient.bytes },
        .{ "stateRoot", &p.state_root.bytes },
        .{ "receiptsRoot", &p.receipts_root.bytes },
        .{ "logsBloom", &p.logs_bloom.bytes },
        .{ "prevRandao", &p.prev_randao.bytes },
    };
    inline for (hashes) |entry| {
        try w.key(entry[0]);
        try w.data(entry[1]);
    }
    try write_quantity(w, "blockNumber", p.block_number);
    try write_quantity(w, "gasLimit", p.gas_limit);
    try write_quantity(w, "gasUsed", p.gas_used);
    try write_quantity(w, "timestamp", p.timestamp);
    try w.key("extraData");
    try w.data(p.extra_data);
    try write_quantity(w, "baseFeePerGas", p.base_fee_per_gas);
    try w.key("blockHash");
    try w.data(&p.block_hash.bytes);
    try w.key("transactions");
    try w.begin_array();
    for (p.transactions) |raw| try w.data(raw);
    try w.end_array();
    try write_payload_optionals(w, p);
    try w.end_object();
}

fn write_payload_optionals(w: *json.Writer, p: *const types.ExecutionPayload) WriteError!void {
    if (p.withdrawals) |list| {
        try w.key("withdrawals");
        try w.begin_array();
        for (list) |withdrawal| {
            try w.begin_object();
            try write_quantity(w, "index", withdrawal.index);
            try write_quantity(w, "validatorIndex", withdrawal.validator_index);
            try w.key("address");
            try w.data(&withdrawal.address.bytes);
            try write_quantity(w, "amount", withdrawal.amount_gwei);
            try w.end_object();
        }
        try w.end_array();
    }
    if (p.blob_gas_used) |value| try write_quantity(w, "blobGasUsed", value);
    if (p.excess_blob_gas) |value| try write_quantity(w, "excessBlobGas", value);
    if (p.withdrawals_root) |root| {
        try w.key("withdrawalsRoot");
        try w.data(&root.bytes);
    }
}

pub fn write_quantity(w: *json.Writer, name: []const u8, value: anytype) WriteError!void {
    try w.key(name);
    try w.quantity(value);
}

const testing = std.testing;

fn test_space(
    bytes: []u8,
    txs: [][]const u8,
    withdrawals: []payload.Withdrawal,
    hashes: []B256,
) Space {
    return .{ .bytes = bytes, .transactions = txs, .withdrawals = withdrawals, .hashes = hashes };
}

test "engine json: payload round trip" {
    var bytes: [4096]u8 = undefined;
    var txs: [8][]const u8 = undefined;
    var withdrawals: [4]payload.Withdrawal = undefined;
    var hashes: [4]B256 = undefined;
    var space = test_space(&bytes, &txs, &withdrawals, &hashes);
    const original: types.ExecutionPayload = .{
        .parent_hash = .{ .bytes = @splat(1) },
        .fee_recipient = .{ .bytes = @splat(2) },
        .state_root = .{ .bytes = @splat(3) },
        .receipts_root = .{ .bytes = @splat(4) },
        .logs_bloom = .{ .bytes = @splat(5) },
        .prev_randao = .{ .bytes = @splat(6) },
        .block_number = 7,
        .gas_limit = 30_000_000,
        .gas_used = 21_000,
        .timestamp = 1_700_000_000,
        .extra_data = &.{ 0xaa, 0xbb },
        .base_fee_per_gas = 1_000_000_000,
        .block_hash = .{ .bytes = @splat(8) },
        .transactions = &.{ &.{ 0x02, 0xc0 }, &.{0xc1} },
        .withdrawals = &.{.{
            .index = 1,
            .validator_index = 2,
            .address = .zero,
            .amount_gwei = 3,
        }},
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .withdrawals_root = .{ .bytes = @splat(9) },
    };
    var out: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var w = json.Writer.init(&writer);
    try write_payload(&w, &original);
    const decoded = try parse_payload(writer.buffered(), &space);
    try testing.expectEqual(original.block_number, decoded.block_number);
    try testing.expectEqual(original.base_fee_per_gas, decoded.base_fee_per_gas);
    try testing.expectEqualSlices(u8, original.extra_data, decoded.extra_data);
    try testing.expectEqual(@as(usize, 2), decoded.transactions.len);
    try testing.expectEqualSlices(u8, original.transactions[0], decoded.transactions[0]);
    try testing.expectEqual(@as(u64, 3), decoded.withdrawals.?[0].amount_gwei);
    try testing.expect(decoded.withdrawals_root.?.eql(original.withdrawals_root.?));
    try testing.expect(decoded.logs_bloom.bytes[255] == 5);
    // A missing required field is rejected.
    space.reset();
    const partial = "{\"blockNumber\":\"0x1\"}";
    try testing.expectError(error.InvalidParams, parse_payload(partial, &space));
}

test "engine json: attributes, forkchoice and status" {
    var bytes: [1024]u8 = undefined;
    var txs: [4][]const u8 = undefined;
    var withdrawals: [2]payload.Withdrawal = undefined;
    var hashes: [2]B256 = undefined;
    var space = test_space(&bytes, &txs, &withdrawals, &hashes);
    const zero = "\"0x0000000000000000000000000000000000000000000000000000000000000000\"";
    const attributes_text = "{\"timestamp\":\"0x10\",\"prevRandao\":" ++ zero ++
        ",\"suggestedFeeRecipient\":\"0x1111111111111111111111111111111111111111\"," ++
        "\"withdrawals\":[]," ++
        "\"parentBeaconBlockRoot\":" ++ zero ++ ",\"transactions\":[\"0x7e01\"]," ++
        "\"noTxPool\":true,\"gasLimit\":\"0x1c9c380\",\"eip1559Params\":\"0x0000003200000006\"}";
    const attributes = try parse_attributes(attributes_text, &space);
    try testing.expectEqual(@as(u64, 16), attributes.timestamp);
    try testing.expectEqual(@as(?bool, true), attributes.no_tx_pool);
    try testing.expectEqual(@as(?u64, 30_000_000), attributes.gas_limit);
    try testing.expectEqual(@as(u8, 0x32), attributes.eip1559_params.?[3]);
    try testing.expectEqualSlices(u8, &.{ 0x7e, 0x01 }, attributes.transactions.?[0]);
    const choice_text = "{\"headBlockHash\":" ++ zero ++ ",\"safeBlockHash\":" ++ zero ++
        ",\"finalizedBlockHash\":" ++ zero ++ "}";
    const choice = try parse_forkchoice(choice_text);
    try testing.expect(choice.head_block_hash.is_zero());
    try testing.expectError(error.InvalidParams, parse_forkchoice("{}"));

    var out: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var w = json.Writer.init(&writer);
    try write_forkchoice_updated(&w, .{ .payload_status = .syncing, .payload_id = @splat(1) });
    try testing.expectEqualStrings(
        "{\"payloadStatus\":{\"status\":\"SYNCING\",\"latestValidHash\":null," ++
            "\"validationError\":null},\"payloadId\":\"0x0101010101010101\"}",
        writer.buffered(),
    );
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const len = smith.slice(&input);
    try parse_arbitrary(input[0..len]);
}

fn parse_arbitrary(input: []const u8) !void {
    var bytes: [1024]u8 = undefined;
    var txs: [4][]const u8 = undefined;
    var withdrawals: [2]payload.Withdrawal = undefined;
    var hashes: [2]B256 = undefined;
    var space = test_space(&bytes, &txs, &withdrawals, &hashes);
    json.validate(input) catch return; // The router only hands over valid JSON values.
    _ = parse_payload(input, &space) catch {};
    space.reset();
    _ = parse_attributes(input, &space) catch {};
    _ = parse_forkchoice(input) catch {};
    space.reset();
    _ = parse_hashes(input, &space) catch {};
}

test "engine json: fuzz decoders never crash" {
    try testing.fuzz({}, fuzz_parse, .{});
}

test "engine json: seeded fuzz of mutated payload objects" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xe791);
    const seed_text = "{\"parentHash\":\"0x01\",\"transactions\":[\"0x02\"],\"withdrawals\":" ++
        "[{\"index\":\"0x1\"}],\"timestamp\":\"0x5\",\"headBlockHash\":null}";
    var input: [seed_text.len]u8 = undefined;
    for (0..4000) |_| {
        input = seed_text.*;
        const flips = prng.range(1, 4);
        for (0..flips) |_| input[prng.below(input.len)] = @intCast(prng.range(0x20, 0x7e));
        try parse_arbitrary(&input);
    }
}

//! Differential execution protocol: the response line. Quantities are JSON-RPC quantities,
//! fixed-size data is lower-case hex of its exact width.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const adapter = @import("adapter.zig");
const Coverage = @import("coverage.zig").Coverage;

const Writer = std.Io.Writer;
const Header = consensus.Header;
const hex = primitives.hex;

/// `{"id":...,"ok":false,"error":...}`, with `coverage` when given.
pub fn write_error(
    out: *Writer,
    id: ?[]const u8,
    message: []const u8,
    coverage: ?*const Coverage,
) Writer.Error!void {
    try out.writeAll("{\"id\":");
    try write_string_or_null(out, id);
    try out.writeAll(",\"ok\":false,\"error\":");
    try std.json.Stringify.encodeJsonString(message, .{}, out);
    if (coverage) |features| try features.write(out);
    try out.writeAll("}");
}

pub fn write_outcome(
    out: *Writer,
    id: ?[]const u8,
    outcome: *const adapter.Outcome,
    coverage: ?*const Coverage,
) Writer.Error!void {
    try out.writeAll("{\"id\":");
    try write_string_or_null(out, id);
    try out.print(",\"ok\":true,\"valid\":{},\"invalidReason\":", .{outcome.valid});
    try write_string_or_null(out, outcome.invalid_reason);
    try out.writeAll(",\"rejected\":[");
    for (outcome.rejected, 0..) |entry, index| {
        if (index > 0) try out.writeAll(",");
        try out.print("{{\"index\":{d},\"error\":", .{entry.index});
        try std.json.Stringify.encodeJsonString(entry.reason, .{}, out);
        try out.writeAll("}");
    }
    try out.writeAll("],\"header\":");
    if (outcome.header) |*header| try write_header(out, header) else try out.writeAll("null");
    try out.writeAll(",\"computedBaseFeePerGas\":");
    if (outcome.computed_base_fee) |fee| try quantity(out, fee) else try out.writeAll("null");
    try out.writeAll(",\"receipts\":[");
    for (outcome.receipts, 0..) |*receipt, index| {
        if (index > 0) try out.writeAll(",");
        try write_receipt(out, receipt);
    }
    try out.writeAll("],\"post\":{");
    for (outcome.post, 0..) |*account, index| {
        if (index > 0) try out.writeAll(",");
        try write_account(out, account);
    }
    try out.writeAll("}");
    if (coverage) |features| try features.write(out);
    try out.writeAll("}");
}

pub fn write_string_or_null(out: *Writer, text: ?[]const u8) Writer.Error!void {
    const value = text orelse return out.writeAll("null");
    try std.json.Stringify.encodeJsonString(value, .{}, out);
}

fn write_header(out: *Writer, header: *const Header) Writer.Error!void {
    try field_data(out, "{\"stateRoot\":", &header.state_root.bytes);
    try field_data(out, ",\"receiptsRoot\":", &header.receipts_root.bytes);
    try field_data(out, ",\"transactionsRoot\":", &header.transactions_root.bytes);
    try field_data(out, ",\"logsBloom\":", &header.logs_bloom.bytes);
    try out.writeAll(",\"gasUsed\":");
    try quantity(out, header.gas_used);
    if (header.blob_gas_used) |used| {
        try out.writeAll(",\"blobGasUsed\":");
        try quantity(out, used);
    }
    if (header.withdrawals_root) |root| try field_data(out, ",\"withdrawalsRoot\":", &root.bytes);
    if (header.requests_hash) |hash| try field_data(out, ",\"requestsHash\":", &hash.bytes);
    try field_data(out, ",\"hash\":", &header.hash().bytes);
    try out.writeAll("}");
}

fn write_receipt(out: *Writer, receipt: *const consensus.Receipt) Writer.Error!void {
    try out.writeAll("{\"type\":");
    try quantity(out, @backingInt(receipt.tx_type));
    try out.writeAll(if (receipt.status) ",\"status\":\"0x1\"" else ",\"status\":\"0x0\"");
    try out.writeAll(",\"cumulativeGasUsed\":");
    try quantity(out, receipt.cumulative_gas_used);
    try out.writeAll(",\"logs\":[");
    var logs = receipt.logs.iterator();
    var index: u32 = 0;
    while (logs.next()) |log| : (index += 1) {
        if (index > 0) try out.writeAll(",");
        try field_data(out, "{\"address\":", &log.address.bytes);
        try out.writeAll(",\"topics\":[");
        for (0..log.topics.count()) |topic| {
            if (topic > 0) try out.writeAll(",");
            try data(out, &log.topics.get(topic).bytes);
        }
        try out.writeAll("]");
        try field_data(out, ",\"data\":", log.data);
        try out.writeAll("}");
    }
    assert(index == receipt.logs.count);
    try out.writeAll("]");
    if (receipt.deposit_nonce) |nonce| {
        try out.writeAll(",\"depositNonce\":");
        try quantity(out, nonce);
    }
    if (receipt.deposit_receipt_version) |version| {
        try out.writeAll(",\"depositReceiptVersion\":");
        try quantity(out, version);
    }
    try out.writeAll("}");
}

fn write_account(out: *Writer, account: *const adapter.PostAccount) Writer.Error!void {
    try data(out, &account.address);
    try out.writeAll(":");
    const info = account.info orelse return out.writeAll("null");
    try out.writeAll("{\"nonce\":");
    try quantity(out, info.nonce);
    try out.writeAll(",\"balance\":");
    try quantity(out, info.balance);
    try field_data(out, ",\"codeHash\":", &info.code_hash);
    if (account.wiped) try out.writeAll(",\"wiped\":true");
    try out.writeAll(",\"storage\":{");
    for (account.storage, 0..) |slot, index| {
        if (index > 0) try out.writeAll(",");
        try word(out, slot.slot);
        try out.writeAll(":");
        try word(out, slot.value);
    }
    try out.writeAll("}}");
}

fn field_data(out: *Writer, name: []const u8, bytes: []const u8) Writer.Error!void {
    try out.writeAll(name);
    try data(out, bytes);
}

/// `"0x..."`: lower-case hex of every byte.
pub fn data(out: *Writer, bytes: []const u8) Writer.Error!void {
    try out.writeAll("\"0x");
    var chunk: [128]u8 = undefined;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const take: usize = @min(bytes.len - offset, chunk.len / 2);
        hex.encode(chunk[0 .. take * 2], bytes[offset..][0..take]);
        try out.writeAll(chunk[0 .. take * 2]);
        offset += take;
    }
    assert(offset == bytes.len);
    try out.writeAll("\"");
}

fn word(out: *Writer, value: u256) Writer.Error!void {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    try data(out, &bytes);
}

pub fn quantity(out: *Writer, value: u256) Writer.Error!void {
    var buffer: [66]u8 = undefined;
    try out.writeAll("\"");
    try out.writeAll(hex.encode_quantity(&buffer, value));
    try out.writeAll("\"");
}

const testing = std.testing;

test "diff response: error and outcome lines" {
    var output: Writer.Allocating = .init(testing.allocator);
    defer output.deinit();
    try write_error(&output.writer, "a\"b", "witness incomplete", null);
    try testing.expectEqualStrings(
        \\{"id":"a\"b","ok":false,"error":"witness incomplete"}
    , output.written());
    output.clearRetainingCapacity();
    const slots = [_]adapter.Slot{.{ .slot = 1, .value = 0 }};
    const post = [_]adapter.PostAccount{
        .{ .address = @splat(0xab), .info = .{ .nonce = 0, .balance = 255 }, .storage = &slots },
        .{ .address = @splat(0x01), .info = null, .storage = &.{} },
    };
    const outcome: adapter.Outcome = .{
        .rejected = &.{.{ .index = 3, .reason = "InvalidTransaction" }},
        .computed_base_fee = 16,
        .post = &post,
    };
    try write_outcome(&output.writer, "x", &outcome, null);
    const address_ab = "abababababababababababababababababababab";
    const address_01 = "0101010101010101010101010101010101010101";
    const zero_31 = "00000000000000000000000000000000000000000000000000000000000000";
    const expected = "{\"id\":\"x\",\"ok\":true,\"valid\":true,\"invalidReason\":null," ++
        "\"rejected\":[{\"index\":3,\"error\":\"InvalidTransaction\"}],\"header\":null," ++
        "\"computedBaseFeePerGas\":\"0x10\",\"receipts\":[],\"post\":{\"0x" ++ address_ab ++
        "\":{\"nonce\":\"0x0\",\"balance\":\"0xff\",\"codeHash\":\"0xc5d2460186f7233c927e7db2" ++
        "dcc703c0e500b653ca82273b7bfad8045d85a470\",\"storage\":{\"0x" ++ zero_31 ++ "01\":" ++
        "\"0x" ++ zero_31 ++ "00\"}},\"0x" ++ address_01 ++ "\":null}}";
    try testing.expectEqualStrings(expected, output.written());
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, expected, .{});
    parsed.deinit();
}

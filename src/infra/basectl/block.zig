//! `basectl block`: one L2 block's header summary (base/base `commands/block.rs`), read
//! with `eth_getBlockByNumber` or `eth_getBlockByHash` without full transactions.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Hash = types.Hash;
const Writer = types.Writer;
const DecodeError = types.DecodeError;

/// Which block to read: a tag, a number, or a hash.
pub const Selector = union(enum) {
    tag: Tag,
    number: u64,
    hash: Hash,

    pub const Tag = enum { latest, safe, finalized, pending, earliest };

    /// Parses `latest`/`safe`/`finalized`/`pending`/`earliest`, a decimal or 0x number,
    /// or a 32-byte 0x hash.
    pub fn parse(text: []const u8) error{InvalidBlock}!Selector {
        if (text.len == 0) return error.InvalidBlock;
        if (std.meta.stringToEnum(Tag, text)) |tag| return .{ .tag = tag };
        const has_prefix = std.mem.startsWith(u8, text, "0x");
        if (has_prefix and text.len == 66) {
            var hash: Hash = .{};
            _ = std.fmt.hexToBytes(&hash.bytes, text[2..]) catch return error.InvalidBlock;
            return .{ .hash = hash };
        }
        const digits = if (has_prefix) text[2..] else text;
        const radix: u8 = if (has_prefix) 16 else 10;
        const number = std.fmt.parseInt(u64, digits, radix) catch return error.InvalidBlock;
        return .{ .number = number };
    }

    pub fn format(selector: Selector, writer: *Writer) Writer.Error!void {
        switch (selector) {
            .tag => |tag| try writer.writeAll(@tagName(tag)),
            .number => |number| try writer.print("{d}", .{number}),
            .hash => |hash| try writer.print("{f}", .{hash}),
        }
    }

    /// The JSON-RPC method and params for this selector, params written into `buffer`.
    pub fn request(selector: Selector, buffer: *[96]u8) struct { []const u8, []const u8 } {
        const params = switch (selector) {
            .tag => |tag| std.fmt.bufPrint(buffer, "[\"{t}\",false]", .{tag}),
            .number => |number| std.fmt.bufPrint(buffer, "[\"0x{x}\",false]", .{number}),
            .hash => |hash| std.fmt.bufPrint(buffer, "[\"{f}\",false]", .{hash}),
        } catch unreachable; // Proof: the longest params (a hash) are 76 bytes.
        assert(params.len <= buffer.len);
        const method = if (selector == .hash) "eth_getBlockByHash" else "eth_getBlockByNumber";
        return .{ method, params };
    }
};

pub const Block = struct {
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    timestamp: u64,
    transactions: u32,
    gas_used: u64,
    gas_limit: u64,
    base_fee_per_gas: ?u64 = null,
    size: ?u64 = null,
    blob_gas_used: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    withdrawals: ?u32 = null,
};

pub const Report = struct {
    network: []const u8,
    reference: Selector,
    block: Block,
};

/// Decodes a block; a `null` result (unknown block) is `error.MalformedResponse` here and
/// reported as "not found" by `fetch`.
pub fn decode_block(value: json.Value) DecodeError!Block {
    var block: Block = .{
        .number = try rpc.number(try rpc.field(value, "number")),
        .hash = try types.decode_hash(try rpc.field(value, "hash")),
        .parent_hash = try types.decode_hash(try rpc.field(value, "parentHash")),
        .timestamp = try rpc.number(try rpc.field(value, "timestamp")),
        .transactions = try array_length(try rpc.field(value, "transactions")),
        .gas_used = try rpc.number(try rpc.field(value, "gasUsed")),
        .gas_limit = try rpc.number(try rpc.field(value, "gasLimit")),
    };
    inline for (.{
        .{ "base_fee_per_gas", "baseFeePerGas" },
        .{ "size", "size" },
        .{ "blob_gas_used", "blobGasUsed" },
        .{ "excess_blob_gas", "excessBlobGas" },
    }) |pair| {
        if (try types.optional_field(value, pair[1])) |inner| {
            @field(block, pair[0]) = try rpc.number(inner);
        }
    }
    if (try types.optional_field(value, "withdrawals")) |inner| {
        block.withdrawals = try array_length(inner);
    }
    assert(value == .object);
    return block;
}

fn array_length(value: json.Value) DecodeError!u32 {
    if (value != .array) return error.MalformedResponse;
    return std.math.cast(u32, value.array.items.len) orelse error.MalformedResponse;
}

pub fn fetch(context: *const types.Context, selector: Selector) types.Fetched(Report) {
    assert(context.network.len > 0);
    var buffer: [96]u8 = undefined;
    const method, const params = selector.request(&buffer);
    const client = context.l2.client orelse
        return .{ .failed = .{ .what = "l2 rpc", .failure = .not_configured } };
    const result = client.call(method, params) catch |err| {
        return .{ .failed = .{ .what = "l2 rpc", .failure = types.failure_of(client, err) } };
    };
    if (result == .null) return .{ .failed = .{
        .what = "block not found",
        .failure = .rpc_error,
    } };
    const block = decode_block(result) catch
        return .{ .failed = .{ .what = "l2 rpc", .failure = .malformed } };
    return .{ .ok = .{ .network = context.network, .reference = selector, .block = block } };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    const block = &report.block;
    assert(block.gas_used <= block.gas_limit or block.gas_limit == 0);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "reference", "{f}", .{report.reference});
    try types.row(writer, "number", "{d}", .{block.number});
    try types.row(writer, "hash", "{f}", .{block.hash});
    try types.row(writer, "parent_hash", "{f}", .{block.parent_hash});
    try types.row(writer, "timestamp", "{d} ({f})", .{
        block.timestamp,
        types.UnixTime{ .seconds = block.timestamp },
    });
    try types.row(writer, "transactions", "{d}", .{block.transactions});
    try types.row(writer, "gas_used", "{d}", .{block.gas_used});
    try types.row(writer, "gas_limit", "{d}", .{block.gas_limit});
    if (block.base_fee_per_gas) |fee| {
        try types.row(writer, "base_fee_per_gas", "{f}", .{types.Gwei{ .wei = fee }});
    }
    if (block.size) |size| try types.row(writer, "size", "{d} bytes", .{size});
    if (block.blob_gas_used) |gas| try types.row(writer, "blob_gas_used", "{d}", .{gas});
    if (block.excess_blob_gas) |gas| try types.row(writer, "excess_blob_gas", "{d}", .{gas});
    if (block.withdrawals) |count| try types.row(writer, "withdrawals", "{d}", .{count});
}

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;

pub const sample_block =
    \\{"number":"0x2a","hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
    \\"parentHash":"0x3333333333333333333333333333333333333333333333333333333333333333",
    \\"timestamp":"0x6553f100","transactions":["0x01","0x02"],"gasUsed":"0x5208",
    \\"gasLimit":"0x1c9c380","baseFeePerGas":"0x3b9aca00","size":"0x400","withdrawals":[]}
;

test "basectl block: selector parsing and requests" {
    try testing.expectEqual(Selector.Tag.safe, (try Selector.parse("safe")).tag);
    try testing.expectEqual(@as(u64, 42), (try Selector.parse("42")).number);
    try testing.expectEqual(@as(u64, 42), (try Selector.parse("0x2a")).number);
    try testing.expectError(error.InvalidBlock, Selector.parse("nope"));
    var buffer: [96]u8 = undefined;
    const method, const params = (try Selector.parse("0x2a")).request(&buffer);
    try testing.expectEqualStrings("eth_getBlockByNumber", method);
    try testing.expectEqualStrings("[\"0x2a\",false]", params);
    const hash_text = "0xab" ++ "00000000000000000000000000000000000000000000000000000000000000";
    const by_hash = try Selector.parse(hash_text);
    try testing.expectEqualStrings("eth_getBlockByHash", by_hash.request(&buffer)[0]);
}

test "basectl block: decode, render, not found" {
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "eth_getBlockByNumber", .result = sample_block, .once = true },
        .{ .method = "eth_getBlockByNumber", .result = "null" },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{ .l2 = .{ .client = &client } };
    const report = fetch(&context, .{ .tag = .latest }).ok;
    try testing.expectEqual(@as(u32, 2), report.block.transactions);
    var buffer: [2048]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "number                42\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "base_fee_per_gas      1.000000000 gwei") != null);
    try testing.expect(std.mem.indexOf(u8, out, "withdrawals           0\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "blob_gas_used") == null);
    const missing = fetch(&context, .{ .number = 9 });
    try testing.expectEqualStrings("block not found", missing.failed.what);
}

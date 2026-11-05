//! ethereum/tests `GenesisTests/basic_genesis_tests.json`: genesis JSON to the RLP of the
//! full genesis block (pre-London header, no transactions, no ommers). Cases whose alloc
//! uses the pre-Frontier `wei` key are skipped: alloy's genesis account (base/base) only
//! reads `balance`.

const std = @import("std");
const testing = std.testing;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const genesis_module = @import("root.zig");
const json = @import("json.zig");
const state = @import("state.zig");

fn uses_legacy_wei(case: std.json.Value) bool {
    var accounts = case.object.get("alloc").?.object.iterator();
    while (accounts.next()) |account| {
        if (account.value_ptr.object.get("wei") != null) return true;
    }
    return false;
}

fn check_case(name: []const u8, case: std.json.Value) !void {
    var text: std.Io.Writer.Allocating = .init(testing.allocator);
    defer text.deinit();
    try std.json.Stringify.value(case, .{}, &text.writer);
    const parsed = try json.parse(testing.allocator, text.written());
    defer parsed.deinit();
    const genesis = &parsed.value;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const state_root = try state.state_root(allocator, genesis.accounts);
    const header = try genesis.header(allocator, state_root);
    var buffer: [1024]u8 = undefined;
    var encoder = rlp.Encoder.init(&buffer);
    encoder.list_header(header.rlp_length() + 2);
    header.rlp_encode(&encoder);
    encoder.raw(&.{ 0xc0, 0xc0 }); // No transactions, no ommers.
    var expected: [1024]u8 = undefined;
    const result = case.object.get("result").?.string;
    const expected_bytes = try primitives.hex.decode_into(&expected, result);
    testing.expectEqualSlices(u8, expected_bytes, encoder.written()) catch |err| {
        std.debug.print("genesis vector {s} mismatch\n", .{name});
        return err;
    };
}

test "genesis vectors: ethereum/tests basic_genesis_tests" {
    const text = @embedFile("testdata/basic_genesis_tests.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
    defer parsed.deinit();
    var iterator = parsed.value.object.iterator();
    var checked: u32 = 0;
    var skipped: u32 = 0;
    while (iterator.next()) |entry| {
        if (uses_legacy_wei(entry.value_ptr.*)) {
            skipped += 1;
            continue;
        }
        try check_case(entry.key_ptr.*, entry.value_ptr.*);
        checked += 1;
    }
    try testing.expectEqual(@as(u32, 2), checked);
    try testing.expectEqual(@as(u32, 1), skipped);
    _ = genesis_module;
}

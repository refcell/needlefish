//! JSON shape of an execution witness (`debug_executionWitness` result, alloy
//! `ExecutionWitness`): `{"state":[..],"codes":[..],"keys":[..],"headers":[..]}`, every item
//! a `"0x"`-prefixed lowercase hex string. `rpc/debug.zig` sizes the response with `length`
//! before writing it through `json.Writer`.

const std = @import("std");
const assert = std.debug.assert;
const witness = @import("witness.zig");

const ByteList = witness.ByteList;

/// Member names in output order.
pub const names = [_][]const u8{ "state", "codes", "keys", "headers" };

/// The witness's lists in output order.
pub fn lists(built: *const witness.Witness) [names.len]*const ByteList {
    return .{ &built.state, &built.codes, &built.keys, &built.headers };
}

/// Exact length of the `{state, codes, keys, headers}` object.
pub fn length(built: *const witness.Witness) u64 {
    var total: u64 = 2 + (names.len - 1); // Braces and the commas between members.
    for (names, lists(built)) |name, list| {
        assert(list.count <= list.ends.len);
        total += name.len + 3 + 2; // `"name":` and the brackets.
        if (list.count > 0) {
            total += list.count - 1; // Commas.
            total += 4 * @as(u64, list.count); // `"0x` + `"` per item.
            total += 2 * @as(u64, list.ends[list.count - 1]); // Hex digits.
        }
    }
    assert(total >= 2 + 4 * 5 + 3);
    return total;
}

test "witness json: length counts framing and two hex digits per byte" {
    const allocator = std.testing.allocator;
    var built = try witness.Witness.init(allocator, .{
        .state_nodes_max = 4,
        .state_bytes_max = 64,
        .codes_max = 2,
        .code_bytes_max = 64,
        .keys_max = 2,
        .headers_max = 2,
        .header_bytes_max = 64,
    });
    defer built.deinit(allocator);
    const empty = "{\"state\":[],\"codes\":[],\"keys\":[],\"headers\":[]}";
    try std.testing.expectEqual(@as(u64, empty.len), length(&built));
    try built.state.append(&.{ 0xab, 0xcd });
    try built.state.append(&.{0x01});
    try built.keys.append(&.{});
    // `"0xabcd","0x01"` and `"0x"`.
    try std.testing.expectEqual(@as(u64, empty.len + 15 + 4), length(&built));
}

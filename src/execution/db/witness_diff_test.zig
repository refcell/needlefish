//! Tests for `witness_diff`: set diffs, leaf attribution to accounts and slots, the JSON
//! parser (ours and reth's shapes), and parser fuzzing.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const json = @import("../../utilities/json/root.zig");
const trie = @import("../trie/root.zig");
const witness_diff = @import("witness_diff.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const rlp = trie.rlp;
const node = trie.node;
const Nibbles = trie.nibbles.Nibbles;
const Witness = witness_diff.Witness;
const Hash = witness_diff.Hash;
const Address = witness_diff.Address;

const config: Witness.Config = .{
    .state_nodes_max = 64,
    .state_bytes_max = 16 * 1024,
    .codes_max = 8,
    .code_bytes_max = 4 * 1024,
    .keys_max = 16,
    .headers_max = 4,
    .header_bytes_max = 2 * 1024,
};

const slot_key: Hash = blk: {
    var key: Hash = @splat(0);
    key[31] = 5;
    break :blk key;
};
const code = [_]u8{ 0x60, 0x01, 0x60, 0x00, 0x55, 0x00 };

const Spec = struct {
    slot_value: u8 = 0x2a,
    with_code: bool = true,
    extra_key: bool = false,
};

fn address(last: u8) Address {
    var result: Address = @splat(0);
    result[19] = last;
    return result;
}

fn minimal(value: u64, out: *[8]u8) []const u8 {
    std.mem.writeInt(u64, out, value, .big);
    const skip = @min(@clz(value) / 8, 8);
    return out[skip..];
}

/// rlp([nonce, balance, storage_root, code_hash]).
fn encode_account(
    out: []u8,
    nonce: u64,
    balance: u64,
    storage_root: *const Hash,
    code_hash: *const Hash,
) []u8 {
    var nonce_bytes: [8]u8 = undefined;
    var balance_bytes: [8]u8 = undefined;
    const nonce_slice = minimal(nonce, &nonce_bytes);
    const balance_slice = minimal(balance, &balance_bytes);
    const payload = rlp.string_encoded_length(nonce_slice) +
        rlp.string_encoded_length(balance_slice) + 33 + 33;
    var at: u32 = rlp.write_list_header(out, payload);
    at += rlp.write_string(out[at..], nonce_slice);
    at += rlp.write_string(out[at..], balance_slice);
    at += rlp.write_string(out[at..], storage_root);
    at += rlp.write_string(out[at..], code_hash);
    assert(at == rlp.header_length(payload) + payload);
    return out[0..at];
}

fn encode_leaf(out: []u8, key: *const Hash, skip_nibbles: u32, value: []const u8) []u8 {
    const path = Nibbles.from_bytes(key);
    var sink: node.BufferSink = .{ .buffer = out };
    node.encode_leaf(&sink, path.slice()[skip_nibbles..], value);
    return sink.result();
}

/// Two accounts under a root branch; account 1 has code and one storage slot.
fn build(w: *Witness, spec: Spec) !void {
    w.clear();
    const one = address(1);
    const two = address(2);
    const hash_one = node.keccak256(&one);
    const hash_two = node.keccak256(&two);
    try testing.expect(hash_one[0] >> 4 != hash_two[0] >> 4);

    var storage_buffer: [128]u8 = undefined;
    const storage_value = [_]u8{spec.slot_value};
    const slot_hash = node.keccak256(&slot_key);
    const storage_leaf = encode_leaf(&storage_buffer, &slot_hash, 0, &storage_value);
    const storage_root = node.keccak256(storage_leaf);

    var account_buffers: [2][128]u8 = undefined;
    var leaf_buffers: [2][192]u8 = undefined;
    const code_hash = node.keccak256(&code);
    const value_one = encode_account(&account_buffers[0], 1, 1000, &storage_root, &code_hash);
    const value_two =
        encode_account(&account_buffers[1], 0, 7, &node.empty_root, &node.empty_code_hash);
    const leaf_one = encode_leaf(&leaf_buffers[0], &hash_one, 1, value_one);
    const leaf_two = encode_leaf(&leaf_buffers[1], &hash_two, 1, value_two);

    const first_nibble = [2]u8{ hash_one[0] >> 4, hash_two[0] >> 4 };
    const low: u32 = if (first_nibble[0] < first_nibble[1]) 0 else 1;
    const leaves = [2][]const u8{ leaf_one, leaf_two };
    const refs = [2]node.RlpNode{ .from_rlp(leaves[low]), .from_rlp(leaves[1 - low]) };
    const mask = (@as(u16, 1) << @intCast(first_nibble[0])) |
        (@as(u16, 1) << @intCast(first_nibble[1]));
    var branch_buffer: [600]u8 = undefined;
    var sink: node.BufferSink = .{ .buffer = &branch_buffer };
    node.encode_branch(&sink, mask, &refs, &.{});

    try w.state.append(sink.result());
    try w.state.append(leaf_one);
    try w.state.append(storage_leaf);
    try w.state.append(leaf_two);
    if (spec.with_code) try w.codes.append(&code);
    try w.keys.append(&one);
    try w.keys.append(&two);
    try w.keys.append(&slot_key);
    if (spec.extra_key) try w.keys.append(&address(9));
}

const Fixture = struct {
    a: Witness,
    b: Witness,
    differ: witness_diff.Differ,

    fn init() !Fixture {
        var a = try Witness.init(testing.allocator, config);
        errdefer a.deinit(testing.allocator);
        var b = try Witness.init(testing.allocator, config);
        errdefer b.deinit(testing.allocator);
        const differ = try witness_diff.Differ.init(testing.allocator, .from_witness(config));
        return .{ .a = a, .b = b, .differ = differ };
    }

    fn deinit(self: *Fixture) void {
        self.differ.deinit();
        self.b.deinit(testing.allocator);
        self.a.deinit(testing.allocator);
    }

    fn render(self: *Fixture, report: *const witness_diff.Report, out: []u8) ![]const u8 {
        var writer: std.Io.Writer = .fixed(out);
        try witness_diff.render(&writer, &self.differ, report, &self.a, &self.b);
        return writer.buffered();
    }
};

test "witness diff: identical witnesses have an empty diff" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try build(&fixture.a, .{});
    try build(&fixture.b, .{});
    const report = try fixture.differ.diff(&fixture.a, &fixture.b);
    try testing.expect(report.identical());
    try testing.expectEqual(@as(u32, 4), report.state.common);
    try testing.expectEqual(@as(u32, 3), report.walk[0].leaves);
    try testing.expectEqual(@as(u32, 0), report.walk[0].nodes_missing);
    try testing.expect(report.walk[0].root != null);
    try testing.expectEqual(@as(u32, 2), report.address_preimages);
    try testing.expectEqual(@as(u32, 1), report.slot_preimages);
    var buffer: [8 * 1024]u8 = undefined;
    const text = try fixture.render(&report, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "Witnesses are identical.") != null);
    try testing.expect(std.mem.indexOf(u8, text, "No leaf nodes share") != null);
    try testing.expect(std.mem.indexOf(u8, text, "=== Leaves Only") == null);
}

test "witness diff: a changed storage leaf names the account and slot" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try build(&fixture.a, .{});
    try build(&fixture.b, .{ .slot_value = 0x2b });
    const report = try fixture.differ.diff(&fixture.a, &fixture.b);
    try testing.expect(!report.identical());
    // Storage leaf, account leaf (storage root), and root branch differ.
    try testing.expectEqual(@as(u32, 3), report.state.differences() / 2);
    try testing.expectEqual(@as(usize, 2), report.differing.len);
    const hash_one = node.keccak256(&address(1));
    var storage_pairs: u32 = 0;
    for (report.differing) |pair| {
        const leaf = report.leaves[0][pair.a];
        try testing.expectEqualSlices(u8, &hash_one, &leaf.account);
        if (leaf.kind != .storage) continue;
        storage_pairs += 1;
        try testing.expectEqualSlices(u8, &node.keccak256(&slot_key), &leaf.slot);
        try testing.expectEqual(@as(u256, 0x2a), witness_diff.decode_storage(leaf.value()).?);
    }
    try testing.expectEqual(@as(u32, 1), storage_pairs);
    try testing.expectEqualSlices(u8, &address(1), &fixture.differ.address_of(&hash_one).?);

    var buffer: [8 * 1024]u8 = undefined;
    const text = try fixture.render(&report, &buffer);
    const expected_storage = "  STORAGE account 0x" ++ comptime repeat("00", 19) ++ "01 (hashed 0x";
    try testing.expect(std.mem.indexOf(u8, text, expected_storage) != null);
    const expected_slot = " slot 0x" ++ comptime repeat("00", 31) ++ "05:" ++
        " 0x2a (local) vs 0x2b (remote)\n";
    try testing.expect(std.mem.indexOf(u8, text, expected_slot) != null);
    try testing.expect(std.mem.indexOf(u8, text, "1 account(s) with different state") != null);
    try testing.expect(std.mem.indexOf(u8, text, "    Storage root:") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Witnesses are identical.") == null);
}

test "witness diff: missing code and extra key are reported" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try build(&fixture.a, .{});
    try build(&fixture.b, .{ .with_code = false, .extra_key = true });
    const report = try fixture.differ.diff(&fixture.a, &fixture.b);
    try testing.expectEqual(@as(usize, 1), report.codes.only_a.len);
    try testing.expectEqual(@as(usize, 0), report.codes.only_b.len);
    try testing.expectEqualSlices(u8, &node.keccak256(&code), &report.codes.only_a[0].hash);
    try testing.expectEqual(@as(usize, 1), report.keys.only_b.len);
    try testing.expectEqual(@as(usize, 0), report.differing.len);
    try testing.expectEqual(@as(u64, 2), report.differences());
    var buffer: [8 * 1024]u8 = undefined;
    const text = try fixture.render(&report, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "  code only-local:  0x") != null);
    const key_line = "  key only-remote: 0x0000000000000000000000000000000000000009\n";
    try testing.expect(std.mem.indexOf(u8, text, key_line) != null);
    try testing.expect(std.mem.indexOf(u8, text, "Code diffs:           1\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Key diffs:            1\n") != null);
}

test "witness diff: a leaf only one walk reaches" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try build(&fixture.a, .{});
    try build(&fixture.b, .{});
    // Drop the storage leaf from `b`: its walk misses that node.
    fixture.b.clear();
    var index: u32 = 0;
    while (index < fixture.a.state.count) : (index += 1) {
        if (index != 2) try fixture.b.state.append(fixture.a.state.get(index));
    }
    const report = try fixture.differ.diff(&fixture.a, &fixture.b);
    try testing.expectEqual(@as(usize, 1), report.leaves_only[0].len);
    try testing.expectEqual(@as(u32, 1), report.walk[1].nodes_missing);
    const only = report.leaves[0][report.leaves_only[0][0]];
    try testing.expectEqual(witness_diff.LeafKind.storage, only.kind);
    var buffer: [8 * 1024]u8 = undefined;
    const text = try fixture.render(&report, &buffer);
    try testing.expect(std.mem.indexOf(u8, text, "    LOCAL-ONLY  storage 0x") != null);
}

fn write_json(w: *const Witness, out: []u8, reth: bool) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    var j = json.Writer.init(&writer);
    if (reth) {
        try j.begin_object();
        try j.key("jsonrpc");
        try j.string("2.0");
        try j.key("id");
        try j.integer(1);
        try j.key("result");
    }
    try j.begin_object();
    const lists = [_]struct { []const u8, *const witness_diff.ByteList }{
        .{ "headers", &w.headers }, .{ "keys", &w.keys },
        .{ "codes", &w.codes },     .{ "state", &w.state },
    };
    for (lists) |entry| {
        try j.key(entry[0]);
        if (reth and entry[1] == &w.state) {
            // Older reth: a map keyed by hash.
            try j.begin_object();
            var index: u32 = 0;
            while (index < entry[1].count) : (index += 1) {
                var name: [66]u8 = undefined;
                const hash = node.keccak256(entry[1].get(index));
                try j.key(try std.fmt.bufPrint(&name, "0x{x}", .{&hash}));
                try j.data(entry[1].get(index));
            }
            try j.end_object();
            continue;
        }
        try j.begin_array();
        var index: u32 = 0;
        while (index < entry[1].count) : (index += 1) {
            const item = entry[1].get(index);
            if (reth and entry[1] == &w.keys) {
                var key: [33]u8 = undefined;
                key[0] = 0x80 + @as(u8, @intCast(item.len));
                @memcpy(key[1..][0..item.len], item);
                try j.data(key[0 .. item.len + 1]);
            } else try j.data(item);
        }
        try j.end_array();
    }
    try j.end_object();
    if (reth) try j.end_object();
    return writer.buffered();
}

fn repeat(comptime text: []const u8, comptime count: u32) []const u8 {
    comptime var result: []const u8 = "";
    inline for (0..count) |_| result = result ++ text;
    return result;
}

fn expect_equal_lists(a: *const witness_diff.ByteList, b: *const witness_diff.ByteList) !void {
    try testing.expectEqual(a.count, b.count);
    var index: u32 = 0;
    while (index < a.count) : (index += 1) {
        try testing.expectEqualSlices(u8, a.get(index), b.get(index));
    }
}

test "witness diff: parses our shape and reth's shape" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try build(&fixture.a, .{ .extra_key = true });
    var parser = try witness_diff.Parser.init(testing.allocator, 4096);
    defer parser.deinit(testing.allocator);
    var buffer: [16 * 1024]u8 = undefined;
    for ([_]bool{ false, true }) |reth| {
        const text = try write_json(&fixture.a, &buffer, reth);
        try parser.parse(text, &fixture.b);
        try expect_equal_lists(&fixture.a.state, &fixture.b.state);
        try expect_equal_lists(&fixture.a.codes, &fixture.b.codes);
        try expect_equal_lists(&fixture.a.keys, &fixture.b.keys);
        try expect_equal_lists(&fixture.a.headers, &fixture.b.headers);
        const report = try fixture.differ.diff(&fixture.a, &fixture.b);
        try testing.expect(report.identical());
    }
    try parser.parse("{\"state\":null,\"extra\":[1,{}]}", &fixture.b);
    try testing.expectEqual(@as(u32, 0), fixture.b.state.count);
    const failures = [_]struct { []const u8, witness_diff.ParseError }{
        .{ "[]", error.NotAnObject },
        .{ "{\"state\":[\"0x0\"]}", error.InvalidHex },
        .{ "{\"state\":[1]}", error.InvalidField },
        .{ "{\"codes\":[],\"codes\":[]}", error.DuplicateField },
        .{ "{\"keys\":[\"0x" ++ comptime repeat("11", 34) ++ "\"]}", error.InvalidKey },
        .{ "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000}}", error.RpcError },
        .{ "{\"state\":[}", error.InvalidJson },
    };
    for (failures) |failure| {
        try testing.expectError(failure[1], parser.parse(failure[0], &fixture.b));
    }
    var small = try witness_diff.Parser.init(testing.allocator, 4);
    defer small.deinit(testing.allocator);
    const large = "{\"codes\":[\"0x0000000000\"]}";
    try testing.expectError(error.ItemTooLarge, small.parse(large, &fixture.b));
}

const fuzz_config: Witness.Config = .{
    .state_nodes_max = 16,
    .state_bytes_max = 4096,
    .codes_max = 4,
    .code_bytes_max = 1024,
    .keys_max = 8,
    .headers_max = 2,
    .header_bytes_max = 1024,
};

/// Parses `input`; on success diffs it against `reference` and renders the report.
fn check_input(
    parser: *witness_diff.Parser,
    differ: *witness_diff.Differ,
    reference: *const Witness,
    parsed: *Witness,
    input: []const u8,
) !void {
    parser.parse(input, parsed) catch return;
    try testing.expect(parsed.state.count <= fuzz_config.state_nodes_max);
    const report = differ.diff(reference, parsed) catch return;
    try testing.expect(report.walk[1].nodes_visited <= differ.config.walk_steps_max);
    var buffer: [64 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    witness_diff.render(&writer, differ, &report, reference, parsed) catch |err| switch (err) {
        error.WriteFailed => {},
    };
}

const FuzzContext = struct {
    parser: *witness_diff.Parser,
    differ: *witness_diff.Differ,
    reference: *Witness,
    parsed: *Witness,
};

fn fuzz_parse(context: FuzzContext, smith: *testing.Smith) anyerror!void {
    var input: [2048]u8 = undefined;
    const length = smith.slice(&input);
    const c = context;
    try check_input(c.parser, c.differ, c.reference, c.parsed, input[0..length]);
}

test "witness diff: fuzz parser and diff" {
    var parser = try witness_diff.Parser.init(testing.allocator, 1024);
    defer parser.deinit(testing.allocator);
    var differ = try witness_diff.Differ.init(testing.allocator, .from_witness(fuzz_config));
    defer differ.deinit();
    var reference = try Witness.init(testing.allocator, fuzz_config);
    defer reference.deinit(testing.allocator);
    var parsed = try Witness.init(testing.allocator, fuzz_config);
    defer parsed.deinit(testing.allocator);
    try testing.fuzz(FuzzContext{
        .parser = &parser,
        .differ = &differ,
        .reference = &reference,
        .parsed = &parsed,
    }, fuzz_parse, .{});
}

test "witness diff: seeded fuzz over mutated witness JSON" {
    var parser = try witness_diff.Parser.init(testing.allocator, 1024);
    defer parser.deinit(testing.allocator);
    var differ = try witness_diff.Differ.init(testing.allocator, .from_witness(fuzz_config));
    defer differ.deinit();
    var reference = try Witness.init(testing.allocator, fuzz_config);
    defer reference.deinit(testing.allocator);
    var parsed = try Witness.init(testing.allocator, fuzz_config);
    defer parsed.deinit(testing.allocator);
    try build(&reference, .{ .extra_key = true });
    var prng = Prng.init(0x317e55);
    var original: [8 * 1024]u8 = undefined;
    var mutated: [8 * 1024]u8 = undefined;
    for (0..300) |iteration| {
        const text = try write_json(&reference, &original, iteration % 2 == 0);
        @memcpy(mutated[0..text.len], text);
        const flips = prng.range(1, 8);
        for (0..flips) |_| {
            const at = prng.below(text.len);
            // Mostly hex digits, so the mutation reaches the trie walk.
            const digit = "0123456789abcdef"[prng.below(16)];
            mutated[at] = if (prng.chance(3, 4)) digit else prng.int(u8);
        }
        const length = if (prng.chance(1, 8)) prng.below(text.len + 1) else text.len;
        try check_input(&parser, &differ, &reference, &parsed, mutated[0..length]);
    }
}

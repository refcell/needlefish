//! `trie` mode end to end: request lines through `handle_line`, over real database files in
//! a temporary directory. Known roots come from an independent trie implementation; the
//! seeded fuzz checks the primary (the hashed-key commit path over disk mode) against
//! `hash-builder` and every other variant, block by block, and every proof against the
//! state root.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const diff = @import("root.zig");
const trie = @import("../../execution/trie/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const build_options = @import("build_options");

const Hash = [32]u8;
const Value = std.json.Value;
const keccak256 = trie.node.keccak256;

const empty_root = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
const empty_code = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
/// Roots of `key_a` (0x11 x 32) holding nonce 1, balance 0x10, the empty code hash and the
/// storage below, from an independent trie implementation.
const root_single = "0x11fdff7752c13a5344b74d5ff69bc6768666103ea3b885d670a468d56702e994";
const root_single_storage =
    "0xbd7d0d897f5608b731b5d6ec0abb5b12fc8385c91cef734c88aa0be94bdf2621";
/// The storage root of slot `slot_a` (0x22 x 32) = 0x2a.
const storage_root_a = "0x8bc48a1174aae6e2c4c27c39722129cf64ab409bbf50268841795c65c8d14e99";
/// `key_a` as above and `key_b` (0x11 x 31, 0x12) with nonce 2, balance 0.
const root_two = "0x80a4b7db39596963807d466e45f971c234c39eb6bef2ba69472728461d84f62e";

fn repeat(comptime pair: *const [2]u8, comptime count: usize) *const [2 * count]u8 {
    const pairs: [count][2]u8 = @splat(pair.*);
    const flat: [2 * count]u8 = @bitCast(pairs);
    return &flat;
}

const key_a = "0x" ++ repeat("11", 32);
const key_b = "0x" ++ repeat("11", 31) ++ "12";
const slot_a = "0x" ++ repeat("22", 32);
const word_2a = "0x" ++ repeat("00", 31) ++ "2a";

const account_a = "{\"op\":\"account\",\"key\":\"" ++ key_a ++
    "\",\"nonce\":\"0x1\",\"balance\":\"0x10\",\"codeHash\":\"" ++ empty_code ++ "\"}";
const account_b = "{\"op\":\"account\",\"key\":\"" ++ key_b ++
    "\",\"nonce\":\"0x2\",\"balance\":\"0x0\",\"codeHash\":\"" ++ empty_code ++ "\"}";
const storage_a = "{\"op\":\"storage\",\"key\":\"" ++ key_a ++ "\",\"slot\":\"" ++ slot_a ++
    "\",\"value\":\"" ++ word_2a ++ "\"}";
const wipe_a = "{\"op\":\"wipe\",\"key\":\"" ++ key_a ++ "\"}";
const delete_a = "{\"op\":\"delete\",\"key\":\"" ++ key_a ++ "\"}";
const delete_b = "{\"op\":\"delete\",\"key\":\"" ++ key_b ++ "\"}";
const proof_a = "{\"key\":\"" ++ key_a ++ "\",\"slots\":[\"" ++ slot_a ++ "\"]}";

/// An adapter with file IO and a fresh temporary directory for `trie.dir`.
const Harness = struct {
    adapter: *diff.Adapter,
    tmp: testing.TmpDir,
    dir_buffer: [256]u8 = undefined,
    dir: []const u8 = "",
    arena_state: std.heap.ArenaAllocator,
    output: std.Io.Writer.Allocating,

    fn create() !*Harness {
        const self = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(self);
        self.* = .{
            .adapter = try testing.allocator.create(diff.Adapter),
            .tmp = testing.tmpDir(.{}),
            .arena_state = .init(testing.allocator),
            .output = .init(testing.allocator),
        };
        try self.adapter.init(testing.allocator);
        self.adapter.io = testing.io;
        self.dir = try std.fmt.bufPrint(
            &self.dir_buffer,
            ".zig-cache/tmp/{s}/job",
            .{self.tmp.sub_path},
        );
        return self;
    }

    fn destroy(self: *Harness) void {
        self.output.deinit();
        self.arena_state.deinit();
        self.adapter.deinit();
        testing.allocator.destroy(self.adapter);
        self.tmp.cleanup();
        testing.allocator.destroy(self);
    }

    /// Answers `{"id":"t","mode":"trie","trie":{"dir":...,"blocks":[blocks]}}`; the parsed
    /// response lives until the next call. The directory is gone afterwards.
    fn request(self: *Harness, blocks: []const u8) !Value {
        _ = self.arena_state.reset(.retain_capacity);
        const arena = self.arena_state.allocator();
        const line = try std.fmt.allocPrint(
            arena,
            "{{\"id\":\"t\",\"mode\":\"trie\",\"trie\":{{\"dir\":\"{s}\",\"blocks\":[{s}]}}}}",
            .{ self.dir, blocks },
        );
        self.output.clearRetainingCapacity();
        try diff.handle_line(self.adapter, arena, line, &self.output.writer, null);
        const text = try arena.dupe(u8, self.output.written());
        const gone = std.Io.Dir.cwd().access(testing.io, self.dir, .{});
        try testing.expectError(error.FileNotFound, gone);
        return std.json.parseFromSliceLeaky(Value, arena, text, .{});
    }
};

fn field(value: Value, name: []const u8) Value {
    return value.object.get(name) orelse std.debug.panic("no field {s}", .{name});
}

fn expect_ok(response: Value) !void {
    if (field(response, "ok").bool) return;
    std.debug.print("response error: {s}\n", .{field(response, "error").string});
    return error.TestUnexpectedResult;
}

/// Every block of `blocks` and of every variant has `roots[i]` as its state root.
fn expect_roots(response: Value, roots: []const []const u8) !void {
    try expect_ok(response);
    const blocks = field(response, "blocks").array.items;
    try testing.expectEqual(roots.len, blocks.len);
    for (blocks, roots) |block, root| {
        try expect_no_error("blocks", block);
        try testing.expectEqualStrings(root, field(block, "stateRoot").string);
    }
    var variants = field(response, "variants").object.iterator();
    var count: u32 = 0;
    while (variants.next()) |entry| : (count += 1) {
        const results = entry.value_ptr.array.items;
        try expect_history_answers(entry.key_ptr.*, results);
        for (results, roots) |block, root| {
            try expect_no_error(entry.key_ptr.*, block);
            // A history variant reports a replaced block's number only.
            const reported = block.object.get("stateRoot") orelse continue;
            try testing.expectEqualStrings(root, reported.string);
        }
    }
    try testing.expect(count >= 3);
}

test "diff trie: empty root, a single account, absent-key proofs" {
    const harness = try Harness.create();
    defer harness.destroy();
    const response = try harness.request(
        "{\"number\":\"0x1\",\"ops\":[],\"proofs\":[" ++ proof_a ++ "]}," ++
            "{\"number\":\"0x2\",\"ops\":[" ++ account_a ++ "],\"proofs\":[" ++ proof_a ++
            ",{\"key\":\"" ++ key_b ++ "\",\"slots\":[]}]}",
    );
    try expect_roots(response, &.{ empty_root, root_single });
    const blocks = field(response, "blocks").array.items;
    // The empty trie: no nodes, no account, a zero value.
    const absent = field(blocks[0], "proofs").array.items[0];
    try testing.expectEqual(Value.null, field(absent, "account"));
    try testing.expectEqual(@as(usize, 0), field(absent, "accountProof").array.items.len);
    const empty_slot = field(absent, "storage").array.items[0];
    try testing.expectEqualStrings("0x" ++ repeat("00", 32), field(empty_slot, "value").string);
    try testing.expectEqual(@as(usize, 0), field(empty_slot, "proof").array.items.len);
    // One leaf: its account, a one-node proof, an empty storage proof; key_b is absent and
    // proven by the same leaf.
    const proofs = field(blocks[1], "proofs").array.items;
    const account = field(proofs[0], "account");
    try testing.expectEqualStrings("0x1", field(account, "nonce").string);
    try testing.expectEqualStrings("0x10", field(account, "balance").string);
    try testing.expectEqualStrings(empty_root, field(account, "storageRoot").string);
    try testing.expectEqual(@as(usize, 1), field(proofs[0], "accountProof").array.items.len);
    try testing.expectEqual(Value.null, field(proofs[1], "account"));
    try testing.expectEqual(@as(usize, 1), field(proofs[1], "accountProof").array.items.len);
    const roots = field(blocks[1], "storageRoots").object;
    try testing.expectEqualStrings(empty_root, roots.get(key_a).?.string);
}

test "diff trie: storage write, wipe, rewrite, delete, recreate" {
    const harness = try Harness.create();
    defer harness.destroy();
    const response = try harness.request(
        "{\"number\":\"0x1\",\"ops\":[" ++ account_a ++ "," ++ storage_a ++ "],\"proofs\":[" ++
            proof_a ++ "]}," ++
            "{\"number\":\"0x2\",\"ops\":[" ++ wipe_a ++ "],\"proofs\":[" ++ proof_a ++ "]}," ++
            "{\"number\":\"0x3\",\"ops\":[" ++ storage_a ++ "],\"proofs\":[]}," ++
            "{\"number\":\"0x4\",\"ops\":[" ++ delete_a ++ "],\"proofs\":[" ++ proof_a ++ "]}," ++
            "{\"number\":\"0x5\",\"ops\":[" ++ account_a ++ "],\"proofs\":[" ++ proof_a ++ "]}," ++
            // Storage, then delete and recreate in one block: the storage is gone.
            "{\"number\":\"0x6\",\"ops\":[" ++ storage_a ++ "," ++ delete_a ++ "," ++ account_a ++
            "],\"proofs\":[]}",
    );
    try expect_roots(response, &.{
        root_single_storage, root_single, root_single_storage,
        empty_root,          root_single, root_single,
    });
    const blocks = field(response, "blocks").array.items;
    const first = field(blocks[0], "proofs").array.items[0];
    const slot = field(first, "storage").array.items[0];
    try testing.expectEqualStrings(word_2a, field(slot, "value").string);
    try testing.expectEqual(@as(usize, 1), field(slot, "proof").array.items.len);
    try testing.expectEqualStrings(
        storage_root_a,
        field(blocks[0], "storageRoots").object.get(key_a).?.string,
    );
    // Deleted: no storage root, no account.
    try testing.expectEqual(@as(usize, 0), field(blocks[3], "storageRoots").object.count());
    const deleted = field(blocks[3], "proofs").array.items[0];
    try testing.expectEqual(Value.null, field(deleted, "account"));
}

test "diff trie: unwinds, native and beyond the database's reorg bound" {
    const harness = try Harness.create();
    defer harness.destroy();
    // Block 2 again on block 1 (with the revert); an unwind of an empty block omits its
    // empty revert.
    const response = try harness.request(
        "{\"number\":\"0x1\",\"ops\":[" ++ account_a ++ "],\"proofs\":[]}," ++
            "{\"number\":\"0x2\",\"ops\":[" ++ account_b ++ "],\"proofs\":[]}," ++
            "{\"number\":\"0x2\",\"unwind\":1,\"revert\":[" ++ delete_b ++ "],\"ops\":[" ++
            storage_a ++ "],\"proofs\":[" ++ proof_a ++ "]}," ++
            "{\"number\":\"0x3\",\"ops\":[],\"proofs\":[]}," ++
            "{\"number\":\"0x3\",\"unwind\":1,\"ops\":[" ++ account_b ++ "],\"proofs\":[]}",
    );
    try expect_roots(response, &.{
        root_single,
        root_two,
        root_single_storage,
        root_single_storage,
        root_two_storage,
    });
    // Twelve blocks, then back to block 1: deeper than a head move may unwind, so the
    // primary applies the revert and the ops as one block.
    var blocks: std.Io.Writer.Allocating = .init(testing.allocator);
    defer blocks.deinit();
    const writer = &blocks.writer;
    for (1..13) |number| {
        if (number > 1) try writer.writeAll(",");
        try writer.print(
            "{{\"number\":\"0x{x}\",\"ops\":[{{\"op\":\"account\",\"key\":\"" ++ key_a ++
                "\",\"nonce\":\"0x{x}\",\"balance\":\"0x10\",\"codeHash\":\"" ++ empty_code ++
                "\"}}],\"proofs\":[]}}",
            .{ number, number },
        );
    }
    try writer.writeAll(",{\"number\":\"0x2\",\"unwind\":11,\"revert\":[" ++ account_a ++
        "],\"ops\":[],\"proofs\":[]}");
    const deep = try harness.request(blocks.written());
    try expect_ok(deep);
    const results = field(deep, "blocks").array.items;
    try testing.expectEqualStrings(root_single, field(results[0], "stateRoot").string);
    try testing.expectEqualStrings(root_single, field(results[12], "stateRoot").string);
    try expect_variants_agree(deep);
}

test "diff trie: a preimage that does not hash to its key refuses the request" {
    const harness = try Harness.create();
    defer harness.destroy();
    var address: [20]u8 = @splat(0xab);
    const key = keccak256(&address);
    var slot_key: Hash = @splat(0xcd);
    const slot = keccak256(&slot_key);
    var line: std.Io.Writer.Allocating = .init(testing.allocator);
    defer line.deinit();
    // 0: all hash to their keys; 1: a wrong address; 2: a wrong slotKey; 3: a wrong
    // slotKeys entry; 4: a wrong address with no other preimage in the request.
    for (0..5) |case| {
        if (case == 1 or case == 4) address[0] ^= 1;
        if (case == 2) slot_key[0] ^= 1;
        const proof_slot_key: Hash = if (case == 3) @splat(0xee) else slot_key;
        line.clearRetainingCapacity();
        const w = &line.writer;
        try w.print("{{\"number\":\"0x1\",\"ops\":[{{\"op\":\"account\",\"key\":\"0x{x}\"," ++
            "\"address\":\"0x{x}\",\"nonce\":\"0x1\",\"balance\":\"0x0\",\"codeHash\":\"" ++
            empty_code ++ "\"}}", .{ &key, &address });
        if (case < 4) {
            try w.print(",{{\"op\":\"storage\",\"key\":\"0x{x}\",\"address\":\"0x{x}\"," ++
                "\"slot\":\"0x{x}\",\"slotKey\":\"0x{x}\",\"value\":\"" ++ word_2a ++ "\"}}", .{
                &key, &address, &slot, &slot_key,
            });
        }
        try w.print("],\"proofs\":[{{\"key\":\"0x{x}\",\"slots\":[\"0x{x}\"]", .{ &key, &slot });
        if (case < 4) {
            try w.print(",\"address\":\"0x{x}\",\"slotKeys\":[\"0x{x}\"]", .{
                &address, &proof_slot_key,
            });
        }
        try w.writeAll("}]}");
        if (case == 1 or case == 4) address[0] ^= 1;
        if (case == 2) slot_key[0] ^= 1;
        const response = try harness.request(line.written());
        if (case == 0) {
            try expect_ok(response);
            try testing.expect(field(response, "variants").object.contains("node-address"));
            continue;
        }
        try testing.expect(!field(response, "ok").bool);
        const text = field(response, "error").string;
        try testing.expect(std.mem.indexOf(u8, text, "PreimageMismatch") != null);
    }
}

test "diff trie: codes are stored and read back; a code that does not hash is refused" {
    const harness = try Harness.create();
    defer harness.destroy();
    const code = "0x6001600055";
    const code_hash = keccak256(&.{ 0x60, 0x01, 0x60, 0x00, 0x55 });
    var line: std.Io.Writer.Allocating = .init(testing.allocator);
    defer line.deinit();
    const w = &line.writer;
    const account = "{{\"op\":\"account\",\"key\":\"" ++ key_a ++ "\",\"nonce\":\"0x1\"," ++
        "\"balance\":\"0x0\",\"codeHash\":\"0x{x}\",\"code\":\"{s}\"}}";
    // The code in block 1; block 2 sets it on key_b without it (the database holds it).
    try w.print("{{\"number\":\"0x1\",\"ops\":[" ++ account ++ "],\"proofs\":[{s}]}}," ++
        "{{\"number\":\"0x2\",\"ops\":[{{\"op\":\"account\",\"key\":\"" ++ key_b ++
        "\",\"nonce\":\"0x1\",\"balance\":\"0x0\",\"codeHash\":\"0x{x}\"}}],\"proofs\":[" ++
        "{{\"key\":\"" ++ key_b ++ "\",\"slots\":[]}}]}}", .{
        &code_hash, code, proof_a, &code_hash,
    });
    const response = try harness.request(line.written());
    try expect_variants_agree(response);
    const blocks = field(response, "blocks").array.items;
    for (blocks) |block| {
        const proof = field(block, "proofs").array.items[0];
        try testing.expectEqualStrings(code, field(proof, "code").string);
    }
    // A code that does not hash to its codeHash, and one longer than the evm's limit.
    const wrong: Hash = @splat(0x77);
    line.clearRetainingCapacity();
    try w.print("{{\"number\":\"0x1\",\"ops\":[" ++ account ++ "],\"proofs\":[]}}", .{
        &wrong, code,
    });
    const refused = try harness.request(line.written());
    try testing.expect(!field(refused, "ok").bool);
    try testing.expect(std.mem.indexOf(u8, field(refused, "error").string, "CodeMismatch") != null);
    line.clearRetainingCapacity();
    const long = try testing.allocator.alloc(u8, 24_577);
    defer testing.allocator.free(long);
    @memset(long, 0x5b);
    try w.print("{{\"number\":\"0x1\",\"ops\":[" ++ account ++ "],\"proofs\":[]}}", .{
        &keccak256(long), try std.fmt.allocPrint(harness.arena_state.allocator(), "0x{x}", .{long}),
    });
    const too_long = try harness.request(line.written());
    try testing.expect(!field(too_long, "ok").bool);
}

/// A root of `key_a` with storage and `key_b` (as `root_two`).
fn expect_no_error(name: []const u8, block: Value) !void {
    const text = block.object.get("error") orelse return;
    std.debug.print("{s}: {s}\n", .{ name, text.string });
    return error.TestUnexpectedResult;
}

/// The history variants answer at least the last block (the head is always in the window).
fn expect_history_answers(name: []const u8, results: []const Value) !void {
    const history = std.mem.indexOf(u8, name, "-history") != null;
    if (!history) return;
    const last = results[results.len - 1];
    if (last.object.get("stateRoot") == null) return error.TestUnexpectedResult;
}

const root_two_storage = "0x22277f4e35f680dceefaba949c8fae906faf8f1a43d22064775d865620f7d544";

/// Every variant block reports the primary's state root and storage roots (where it
/// reports them), and every proof verifies against the state root.
fn expect_variants_agree(response: Value) !void {
    try expect_ok(response);
    const blocks = field(response, "blocks").array.items;
    for (blocks) |block| {
        try expect_no_error("blocks", block);
        try expect_proofs_verify(block);
    }
    var variants = field(response, "variants").object.iterator();
    while (variants.next()) |entry| {
        const results = entry.value_ptr.array.items;
        try testing.expectEqual(blocks.len, results.len);
        try expect_history_answers(entry.key_ptr.*, results);
        for (blocks, results) |block, result| {
            try expect_no_error(entry.key_ptr.*, result);
            // A history variant reports a replaced block's number only.
            const reported = result.object.get("stateRoot") orelse continue;
            const want = field(block, "stateRoot").string;
            try testing.expectEqualStrings(want, reported.string);
            try expect_same_storage_roots(block, result);
            if (result.object.get("proofs")) |proofs| {
                try expect_same_proofs(field(block, "proofs"), proofs);
            }
        }
    }
}

fn expect_same_storage_roots(want: Value, got: Value) !void {
    const roots = (got.object.get("storageRoots") orelse return).object;
    const expected = field(want, "storageRoots").object;
    try testing.expectEqual(expected.count(), roots.count());
    var entries = expected.iterator();
    while (entries.next()) |entry| {
        const root = roots.get(entry.key_ptr.*) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(entry.value_ptr.string, root.string);
    }
}

/// Same accounts, values and node lists (after dropping embedded nodes but the first).
fn expect_same_proofs(want: Value, got: Value) !void {
    var buffer_want: [4096]u8 = undefined;
    var buffer_got: [4096]u8 = undefined;
    try testing.expectEqual(want.array.items.len, got.array.items.len);
    for (want.array.items, got.array.items) |a, b| {
        const account_a_json = std.json.fmt(field(a, "account"), .{});
        const account_b_json = std.json.fmt(field(b, "account"), .{});
        const json_a = try std.fmt.bufPrint(&buffer_want, "{f}", .{account_a_json});
        const json_b = try std.fmt.bufPrint(&buffer_got, "{f}", .{account_b_json});
        try testing.expectEqualStrings(json_a, json_b);
        // A variant that stores codes reports the primary's.
        if (b.object.get("code")) |code| {
            try testing.expectEqualStrings(field(a, "code").string, code.string);
        }
        try expect_same_nodes(field(a, "accountProof"), field(b, "accountProof"));
        for (field(a, "storage").array.items, field(b, "storage").array.items) |x, y| {
            try testing.expectEqualStrings(field(x, "value").string, field(y, "value").string);
            try expect_same_nodes(field(x, "proof"), field(y, "proof"));
        }
    }
}

fn expect_same_nodes(want: Value, got: Value) !void {
    var a: usize = 0;
    var b: usize = 0;
    const left = want.array.items;
    const right = got.array.items;
    while (true) {
        while (a < left.len and a > 0 and left[a].string.len < 2 + 64) a += 1;
        while (b < right.len and b > 0 and right[b].string.len < 2 + 64) b += 1;
        if (a == left.len or b == right.len) break;
        try testing.expectEqualStrings(left[a].string, right[b].string);
        a += 1;
        b += 1;
    }
    try testing.expectEqual(left.len - a, right.len - b);
}

fn arena_bytes(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try arena.alloc(u8, (text.len - 2) / 2);
    try primitives.hex.decode(out, text);
    return out;
}

fn nodes_list(arena: std.mem.Allocator, nodes: Value) ![]const []const u8 {
    const out = try arena.alloc([]const u8, nodes.array.items.len);
    for (nodes.array.items, out) |item, *bytes| bytes.* = try arena_bytes(arena, item.string);
    return out;
}

/// Every account proof proves the reported account (or its absence) under the state root,
/// and every storage proof the reported value under the account's storage root.
fn expect_proofs_verify(block: Value) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = (try arena_bytes(arena, field(block, "stateRoot").string))[0..32].*;
    for (field(block, "proofs").array.items) |proof| {
        const key = try arena_bytes(arena, field(proof, "key").string);
        const account_nodes = try nodes_list(arena, field(proof, "accountProof"));
        const leaf = try trie.verify_proof(root, key, account_nodes);
        const account = field(proof, "account");
        try testing.expectEqual(account == .null, leaf == null);
        var storage_root: Hash = trie.empty_root;
        if (account != .null) {
            const text = field(account, "storageRoot").string;
            storage_root = (try arena_bytes(arena, text))[0..32].*;
        }
        for (field(proof, "storage").array.items) |slot| {
            const slot_key = try arena_bytes(arena, field(slot, "slot").string);
            const nodes = try nodes_list(arena, field(slot, "proof"));
            const value = try trie.verify_proof(storage_root, slot_key, nodes);
            const word = try arena_bytes(arena, field(slot, "value").string);
            const zero = std.mem.allEqual(u8, word, 0);
            try testing.expectEqual(zero, value == null);
        }
    }
}

// Seeded fuzz: random blocks over a small key universe (shared key prefixes, so the tries
// branch and extend), random unwinds with a revert that restores the target block's state,
// half the requests with preimages (so `node-address` runs too).

const keys_max = 6;
const slots_max = 5;

const FuzzAccount = struct {
    nonce: u64,
    balance: u64,
    code: u8,
    slots: [slots_max]u64 = @splat(0),
};

const FuzzState = [keys_max]?FuzzAccount;

/// The fuzz's codes by number: none, one byte, longer than a disk-small code table record
/// (it stays in the arena and the checkpoint image), and the evm's largest.
const fuzz_codes = [_]usize{ 0, 1, 5000, 24_576 };
var fuzz_code_bytes: [fuzz_codes.len][24_576]u8 = undefined;

fn fuzz_code(code: u8) []const u8 {
    const bytes = fuzz_code_bytes[code][0..fuzz_codes[code]];
    for (bytes, 0..) |*byte, index| byte.* = @truncate(index * 31 + code);
    return bytes;
}

const Fuzz = struct {
    prng: Prng,
    preimages: bool,
    keys: [keys_max]Hash = undefined,
    addresses: [keys_max][20]u8 = undefined,
    slots: [slots_max]Hash = undefined,
    slot_keys: [slots_max]Hash = undefined,
    /// The state after each block of the canonical chain, by height.
    states: [64]FuzzState = undefined,
    height: u32 = 0,

    fn init(seed: u64) Fuzz {
        var fuzz: Fuzz = .{ .prng = Prng.init(seed), .preimages = seed % 2 == 1 };
        var base: Hash = undefined;
        fuzz.prng.fill(&base);
        for (&fuzz.keys, &fuzz.addresses, 0..) |*key, *address, index| {
            if (fuzz.preimages) {
                fuzz.prng.fill(address);
                key.* = keccak256(address);
            } else {
                // Keys that share long prefixes and differ in one nibble.
                key.* = base;
                key[31 - fuzz.prng.below(3) * 15] ^= @intCast(index * 17 + 1);
            }
        }
        for (&fuzz.slots, &fuzz.slot_keys, 0..) |*slot, *slot_key, index| {
            fuzz.prng.fill(slot_key);
            slot.* = if (fuzz.preimages) keccak256(slot_key) else base;
            if (!fuzz.preimages) slot[30] ^= @intCast(index + 1);
        }
        fuzz.states[0] = @splat(null);
        return fuzz;
    }

    fn code_hash(code: u8) Hash {
        return keccak256(fuzz_code(code));
    }

    fn write_key(fuzz: *const Fuzz, writer: *std.Io.Writer, index: usize) !void {
        try writer.print("\"key\":\"0x{x}\"", .{&fuzz.keys[index]});
        if (fuzz.preimages) try writer.print(",\"address\":\"0x{x}\"", .{&fuzz.addresses[index]});
    }

    fn write_account(fuzz: *const Fuzz, w: *std.Io.Writer, index: usize, a: FuzzAccount) !void {
        try w.writeAll("{\"op\":\"account\",");
        try fuzz.write_key(w, index);
        const code = code_hash(a.code);
        try w.print(",\"nonce\":\"0x{x}\",\"balance\":\"0x{x}\",\"codeHash\":\"0x{x}\"", .{
            a.nonce, a.balance, &code,
        });
        if (a.code != 0) try w.print(",\"code\":\"0x{x}\"", .{fuzz_code(a.code)});
        try w.writeAll("}");
    }

    fn write_storage(
        fuzz: *const Fuzz,
        w: *std.Io.Writer,
        index: usize,
        slot: usize,
        value: u64,
    ) !void {
        try w.writeAll("{\"op\":\"storage\",");
        try fuzz.write_key(w, index);
        try w.print(",\"slot\":\"0x{x}\",\"value\":\"0x{x:0>64}\"", .{ &fuzz.slots[slot], value });
        if (fuzz.preimages) try w.print(",\"slotKey\":\"0x{x}\"", .{&fuzz.slot_keys[slot]});
        try w.writeAll("}");
    }

    fn write_plain(fuzz: *const Fuzz, w: *std.Io.Writer, op: []const u8, index: usize) !void {
        try w.print("{{\"op\":\"{s}\",", .{op});
        try fuzz.write_key(w, index);
        try w.writeAll("}");
    }

    /// One block: maybe an unwind (with its revert), then random ops and proofs.
    fn block(fuzz: *Fuzz, w: *std.Io.Writer) !void {
        var unwind: u32 = 0;
        if (fuzz.height > 0 and fuzz.prng.chance(1, 4)) {
            unwind = @intCast(fuzz.prng.range(1, @min(fuzz.height, 10)));
        }
        const parent = fuzz.height - unwind;
        try w.print("{{\"number\":\"0x{x}\",\"unwind\":{d}", .{ parent + 1, unwind });
        var state = fuzz.states[parent];
        if (unwind > 0) {
            try w.writeAll(",\"revert\":[");
            try fuzz.write_revert(w, &fuzz.states[fuzz.height], &state);
            try w.writeAll("]");
        }
        try w.writeAll(",\"ops\":[");
        const ops = fuzz.prng.range(1, 8);
        for (0..ops) |op_index| {
            if (op_index > 0) try w.writeAll(",");
            try fuzz.random_op(w, &state);
        }
        try w.writeAll("],\"proofs\":[");
        for (0..3) |proof_index| {
            if (proof_index > 0) try w.writeAll(",");
            const index = fuzz.prng.below(keys_max);
            try w.writeAll("{");
            try fuzz.write_key(w, index);
            try w.writeAll(",\"slots\":[");
            const slot_a_index = fuzz.prng.below(slots_max);
            const slot_b_index = fuzz.prng.below(slots_max);
            const slots = .{ &fuzz.slots[slot_a_index], &fuzz.slots[slot_b_index] };
            try w.print("\"0x{x}\",\"0x{x}\"]", slots);
            if (fuzz.preimages) {
                try w.print(",\"slotKeys\":[\"0x{x}\",\"0x{x}\"]", .{
                    &fuzz.slot_keys[slot_a_index], &fuzz.slot_keys[slot_b_index],
                });
            }
            try w.writeAll("}");
        }
        try w.writeAll("]}");
        fuzz.height = parent + 1;
        fuzz.states[fuzz.height] = state;
    }

    /// Writes that turn `tip` into `target`: delete what differs, then recreate it.
    fn write_revert(
        fuzz: *const Fuzz,
        w: *std.Io.Writer,
        tip: *const FuzzState,
        target: *const FuzzState,
    ) !void {
        var first = true;
        for (tip, target, 0..) |a, b, index| {
            if (std.meta.eql(a, b)) continue;
            if (!first) try w.writeAll(",");
            first = false;
            try fuzz.write_plain(w, "delete", index);
            const account = b orelse continue;
            try w.writeAll(",");
            try fuzz.write_account(w, index, account);
            for (account.slots, 0..) |value, slot| {
                if (value == 0) continue;
                try w.writeAll(",");
                try fuzz.write_storage(w, index, slot, value);
            }
        }
    }

    fn random_op(fuzz: *Fuzz, w: *std.Io.Writer, state: *FuzzState) !void {
        const index = fuzz.prng.below(keys_max);
        const choice = fuzz.prng.below(10);
        if (choice < 5 and state[index] != null) {
            const slot = fuzz.prng.below(slots_max);
            const value: u64 = if (fuzz.prng.chance(1, 3)) 0 else fuzz.prng.range(1, 1 << 40);
            state[index].?.slots[slot] = value;
            return fuzz.write_storage(w, index, slot, value);
        }
        if (choice == 8) {
            if (state[index]) |*account| account.slots = @splat(0);
            return fuzz.write_plain(w, "wipe", index);
        }
        if (choice == 9) {
            state[index] = null;
            return fuzz.write_plain(w, "delete", index);
        }
        // Never an empty account: nonce or balance is nonzero.
        var account: FuzzAccount = .{
            .nonce = fuzz.prng.range(1, 3),
            .balance = fuzz.prng.below(1 << 20),
            .code = @intCast(fuzz.prng.below(fuzz_codes.len)),
        };
        if (state[index]) |current| account.slots = current.slots;
        state[index] = account;
        return fuzz.write_account(w, index, account);
    }
};

test "diff trie: seeded fuzz, the primary against hash-builder and every variant" {
    const harness = try Harness.create();
    defer harness.destroy();
    var blocks: std.Io.Writer.Allocating = .init(testing.allocator);
    defer blocks.deinit();
    const rounds = 6 * build_options.fuzz_soak;
    for (0..rounds) |round| {
        var fuzz: Fuzz = .init(0x7e1e_0000 + round + build_options.fuzz_seed);
        blocks.clearRetainingCapacity();
        const count = fuzz.prng.range(4, 16);
        for (0..count) |index| {
            if (index > 0) try blocks.writer.writeAll(",");
            try fuzz.block(&blocks.writer);
        }
        const response = harness.request(blocks.written()) catch |err| {
            std.debug.print("diff trie fuzz: failing round {d}\n", .{round});
            return err;
        };
        expect_variants_agree(response) catch |err| {
            std.debug.print("diff trie fuzz: failing round {d}\n", .{round});
            return err;
        };
        const variants = field(response, "variants").object;
        try testing.expectEqual(fuzz.preimages, variants.contains("node-address"));
        try testing.expectEqual(fuzz.preimages, variants.contains("memory-history"));
        try testing.expectEqual(fuzz.preimages, variants.contains("memory-history-budget"));
        try testing.expect(variants.contains("disk-view-history"));
        try testing.expect(variants.contains("hash-builder"));
        try testing.expect(variants.contains("disk-small"));
        try testing.expect(variants.contains("disk-small-reopen"));
        try testing.expect(variants.contains("disk-deep"));
    }
}

// `disk-small` against the primary and hash-builder, node by node: blocks of a few hundred
// writes, two native unwinds (and the same blocks again) every seven, and the counters of
// the persistence the primary never reaches with them.

const trie_node = @import("trie_node.zig");
const trie_model = @import("trie_model.zig");
const trie_request = @import("trie_request.zig");
const HashedWrites = @import("../../execution/db/root.zig").overlay.HashedWrites;

const small_keys = 384;
const small_slots = 24;
/// Keys of the restart test: enough distinct records that disk-deep's level 1 (about 2k
/// accounts, 1.5k slots) overflows into level 2.
const restart_keys = 4096;
const small_blocks = 30;
const small_writes = 300;

const SmallRun = struct {
    prng: Prng,
    model: trie_model.Model,
    /// The first `keys_used` are written.
    keys: [restart_keys]Hash = undefined,
    keys_used: u32 = small_keys,
    slots: [small_slots]Hash = undefined,
    ops: [small_writes]trie_request.Op = undefined,

    /// One block's ops (no empty account), applied to the model; its writes.
    fn block(run: *SmallRun) !HashedWrites {
        var touched: trie_model.Touched = .{};
        for (&run.ops, 0..) |*op, index| {
            const key = run.keys[run.prng.below(run.keys_used)];
            const exists = run.model.find(&key) != null;
            const choice = run.prng.below(100);
            op.* = .{ .kind = .account, .key = key };
            if (exists and choice < 60) {
                op.kind = .storage;
                op.slot = run.slots[run.prng.below(small_slots)];
                op.value = if (run.prng.chance(1, 5)) 0 else run.prng.range(1, 1 << 60);
            } else if (exists and choice < 62) {
                op.kind = .wipe;
            } else if (exists and choice < 64) {
                op.kind = .delete;
            } else {
                op.info = .{ .nonce = run.prng.range(1, 1 << 20), .balance = run.prng.int(u64) };
            }
            try run.model.apply(run.ops[index..][0..1], &touched);
        }
        return run.model.writes(&touched);
    }
};

fn expect_same_disk_proofs(primary: *trie_node.Node, small: *trie_node.Node, key: Hash) !void {
    const proofs = try testing.allocator.alloc(trie_node.AccountProof, 2);
    defer testing.allocator.free(proofs);
    const storage = try testing.allocator.alloc(trie_node.StorageProof, 2);
    defer testing.allocator.free(storage);
    var values: [2][1]u256 = undefined;
    const slot = [1]Hash{key};
    var accounts: [2]?trie_node.AccountState = undefined;
    for ([2]*trie_node.Node{ primary, small }, 0..) |node, index| {
        accounts[index] = try node.db.proof_hashed(
            &key,
            &slot,
            &proofs[index],
            storage[index..][0..1],
            &values[index],
        );
    }
    try testing.expectEqualDeep(accounts[0], accounts[1]);
    try testing.expectEqual(values[0][0], values[1][0]);
    try testing.expectEqual(proofs[0].count, proofs[1].count);
    for (0..proofs[0].count) |index| {
        const at: u32 = @intCast(index);
        try testing.expectEqualSlices(u8, proofs[0].node_at(at), proofs[1].node_at(at));
    }
    try testing.expectEqual(storage[0].count, storage[1].count);
}

fn small_commit(nodes: [2]*trie_node.Node, writes: HashedWrites, root: Hash) !void {
    for (nodes) |node| {
        try node.commit_hashed(writes);
        try testing.expectEqualSlices(u8, &root, &node.state_root());
    }
}

test "diff trie: disk-small persists every few blocks and agrees with the primary" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    const primary_path = try std.fmt.allocPrint(arena, "{s}/primary.db", .{dir});
    const small_path = try std.fmt.allocPrint(arena, "{s}/small.db", .{dir});
    const primary = try trie_node.Node.create(testing.allocator, .disk, primary_path);
    defer primary.destroy();
    const small = try trie_node.Node.create(testing.allocator, .disk_small, small_path);
    defer small.destroy();
    var run: SmallRun = .{ .prng = Prng.init(0x5a11_0000 + build_options.fuzz_seed), .model = .{
        .arena = arena,
    } };
    for (&run.keys) |*key| run.prng.fill(key);
    for (&run.slots) |*slot| run.prng.fill(slot);
    const nodes = [2]*trie_node.Node{ primary, small };
    var writes: [small_blocks]HashedWrites = undefined;
    var roots: [small_blocks + 1]Hash = undefined;
    roots[0] = trie.empty_root;
    for (0..small_blocks) |index| {
        writes[index] = try run.block();
        roots[index + 1] = try run.model.state_root();
        try small_commit(nodes, writes[index], roots[index + 1]);
        if (index % 7 == 6) {
            // Two blocks back natively, then the same two blocks again.
            for (nodes) |node| {
                try testing.expect(try node.unwind_to(index - 1));
                try testing.expectEqualSlices(u8, &roots[index - 1], &node.state_root());
            }
            try small_commit(nodes, writes[index - 1], roots[index]);
            try small_commit(nodes, writes[index], roots[index + 1]);
        }
        for (0..4) |_| {
            try expect_same_disk_proofs(primary, small, run.keys[run.prng.below(small_keys)]);
        }
    }
    try expect_small_persisted(small);
}

/// disk-small flushed, built tables, compacted, checkpointed and evicted from its caches
/// several times (with these blocks the primary does none of it but evict).
fn expect_small_persisted(small: *trie_node.Node) !void {
    const trees = &small.db.flat.?;
    var flushes: u64 = 0;
    var merges: u64 = 0;
    var tables: u64 = 0;
    inline for (.{ "accounts", "storage", "account_branches", "storage_branches" }) |name| {
        const stats = @field(trees, name).stats;
        try testing.expect(stats.flushes >= 5);
        flushes += stats.flushes;
        merges += stats.merges;
        tables += stats.tables_written;
    }
    try testing.expect(merges >= 5);
    try testing.expect(tables >= flushes + merges);
    try testing.expect(small.db.checkpoints_completed >= 5);
    try testing.expect(small.db.disk.?.record_cache.stats.evictions > 0);
    try testing.expect(trees.cache.stats.evictions > 0);
}

// disk-small-reopen and disk-deep against the primary and hash-builder, node by node: the
// same blocks, a restart after every block (clean, then a crash, alternately) with native
// unwinds across them, and disk-deep's blocks split into blocks of 8 + 8 writes.

test "diff trie: disk-small-reopen restarts and replays, disk-deep merges into level 2" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dir = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    var paths: [3][]const u8 = undefined;
    for (&paths, [_][]const u8{ "primary", "reopen", "deep" }) |*path, name| {
        path.* = try std.fmt.allocPrint(arena, "{s}/{s}.db", .{ dir, name });
    }
    const primary = try trie_node.Node.create(testing.allocator, .disk, paths[0]);
    defer primary.destroy();
    var reopen: ?*trie_node.Node =
        try trie_node.Node.create(testing.allocator, .disk_small, paths[1]);
    defer if (reopen) |node| node.destroy();
    const deep = try trie_node.Node.create(testing.allocator, .disk_deep, paths[2]);
    defer deep.destroy();
    var run: SmallRun = .{
        .prng = Prng.init(0x5e57_0000 + build_options.fuzz_seed),
        .model = .{ .arena = arena },
        .keys_used = restart_keys,
    };
    for (&run.keys) |*key| run.prng.fill(key);
    for (&run.slots) |*slot| run.prng.fill(slot);
    var writes: [small_blocks]HashedWrites = undefined;
    var roots: [small_blocks + 1]Hash = undefined;
    roots[0] = trie.empty_root;
    for (0..small_blocks) |index| {
        writes[index] = try run.block();
        roots[index + 1] = try run.model.state_root();
        try small_commit(.{ primary, reopen.? }, writes[index], roots[index + 1]);
        try deep.commit_split(writes[index]);
        try testing.expectEqualSlices(u8, &roots[index + 1], &deep.state_root());
        const node = reopen.?;
        reopen = null;
        reopen = try node.reopen(if (index % 2 == 1) @intCast(index % 8) else null);
        try testing.expectEqualSlices(u8, &roots[index + 1], &reopen.?.state_root());
        if (index % 7 == 6) {
            // Two blocks back natively on a reopened database, then the same two again.
            for ([2]*trie_node.Node{ primary, reopen.? }) |unwound| {
                try testing.expect(try unwound.unwind_to(index - 1));
                try testing.expectEqualSlices(u8, &roots[index - 1], &unwound.state_root());
            }
            try small_commit(.{ primary, reopen.? }, writes[index - 1], roots[index]);
            try small_commit(.{ primary, reopen.? }, writes[index], roots[index + 1]);
        }
        for (0..4) |_| {
            const key = run.keys[run.prng.below(restart_keys)];
            try expect_same_disk_proofs(primary, reopen.?, key);
            try expect_same_disk_proofs(primary, deep, key);
        }
    }
    try expect_restarted(reopen.?);
    try expect_deep(deep);
}

/// Every block restarted the database, half of them as crashes; every open loaded a
/// checkpoint, and crashes replayed the journal after it.
fn expect_restarted(node: *trie_node.Node) !void {
    const stats = node.stats;
    try testing.expectEqual(@as(u64, small_blocks / 2), stats.reopens_clean);
    try testing.expectEqual(@as(u64, small_blocks / 2), stats.reopens_crash);
    try testing.expectEqual(@as(u64, small_blocks), stats.checkpoint_loads);
    try testing.expect(stats.crashes_mid_checkpoint >= small_blocks / 4);
    try testing.expect(stats.crash_replays >= small_blocks / 4);
    try testing.expect(stats.entries_replayed >= stats.crash_replays);
}

/// disk-deep merged into level 2 of the account and storage trees (tables live there), and
/// its chain evicted on every insert past three blocks.
fn expect_deep(deep: *trie_node.Node) !void {
    const trees = &deep.db.flat.?;
    inline for (.{ "accounts", "storage" }) |name| {
        const tree = &@field(trees, name);
        try testing.expect(tree.stats.merges_into[2] > 0);
        try testing.expect(tree.level_count[2] > 0);
    }
    try testing.expect(deep.stats.commits > 10 * small_blocks);
    try testing.expectEqual(@as(u32, 3), deep.db.chain.block_count());
}

// Keys sharing long prefixes: leaves at depth 62 to 64 under branches at depth 61 to 63,
// read and written by walks that start fresh (disk-small-reopen restarts after every block).
// The two requests are the diff fuzzer's reproducers; roots from an independent trie.

const repro_key = "0xe8bd19873fbc3a087e3e7b365421ce329b1b9ff3e75238ff4eda892208adcb21";
const repro_slot_prefix = "0x7dce463b4b242275b93f9c283881774d280e3abf2ceec46c50fa7d9831a8135";
const repro_one = "{\"number\":\"0x1\",\"ops\":[" ++
    "{\"op\":\"account\",\"key\":\"" ++ repro_key ++
    "\",\"nonce\":\"0x1\",\"balance\":\"0x0\",\"codeHash\":\"" ++ empty_code ++ "\"}," ++
    "{\"op\":\"storage\",\"key\":\"" ++ repro_key ++ "\",\"slot\":\"" ++ repro_slot_prefix ++
    "4\",\"value\":\"0x" ++ repeat("00", 31) ++ "e8\"}," ++
    "{\"op\":\"storage\",\"key\":\"" ++ repro_key ++ "\",\"slot\":\"" ++ repro_slot_prefix ++
    "b\",\"value\":\"0x" ++ repeat("ff", 32) ++ "\"}],\"proofs\":[]}," ++
    "{\"number\":\"0x2\",\"ops\":[{\"op\":\"wipe\",\"key\":\"" ++ repro_key ++
    "\"}],\"proofs\":[]}";

const repro_a = "0x" ++ repeat("ff", 31) ++ "f7";
const repro_b = "0x" ++ repeat("ff", 32);
fn repro_account(comptime key: []const u8) []const u8 {
    return "{\"op\":\"account\",\"key\":\"" ++ key ++
        "\",\"nonce\":\"0x1\",\"balance\":\"0x0\",\"codeHash\":\"" ++ empty_code ++ "\"}";
}
fn repro_storage(
    comptime key: []const u8,
    comptime slot: []const u8,
    comptime word: []const u8,
) []const u8 {
    return "{\"op\":\"storage\",\"key\":\"" ++ key ++ "\",\"slot\":\"0x" ++ slot ++
        "\",\"value\":\"0x" ++ word ++ "\"}";
}
const repro_two = "{\"number\":\"0x1\",\"ops\":[],\"proofs\":[]}," ++
    "{\"number\":\"0x2\",\"ops\":[],\"proofs\":[]}," ++
    "{\"number\":\"0x3\",\"ops\":[" ++ repro_account(repro_a) ++ "," ++ repro_storage(
    repro_a,
    "0090200000064bb05bb32ceece7b385104493cecb993d1632fa3080bbe2cd3bd",
    repeat("00", 32),
) ++ "," ++ repro_account(repro_b) ++ "," ++ repro_storage(
    repro_b,
    "0098746e65b7d65b10d81764d12b462608c9726c3adf22bfbff14f6c8d370a36",
    repeat("00", 31) ++ "12",
) ++ "],\"proofs\":[]}," ++
    "{\"number\":\"0x4\",\"ops\":[" ++ repro_storage(
    repro_b,
    "0001ea76e6c723f45ebe843f7164a3705a1eeea12a006473fe31c738a5f09043",
    repeat("00", 30) ++ "7621",
) ++ "],\"proofs\":[]}," ++
    "{\"number\":\"0x5\",\"ops\":[],\"proofs\":[]}";

test "diff trie: the fuzzer's depth-64 reproducers agree everywhere" {
    const harness = try Harness.create();
    defer harness.destroy();
    try expect_roots(try harness.request(repro_one), &.{
        "0x2259d05c5a525272f2eb2a8ad2621e99f04177f0279ba129ea393019fcaed18e",
        "0xc16f0092ffc700391c95efda61c6a0064352dfb1e565d9f3a2e9dc2de7cd8d07",
    });
    try expect_roots(try harness.request(repro_two), &.{
        empty_root,
        empty_root,
        "0x51ce7f71637a095fdf7771c271c99b8e4fd476befd786c445316adc6c798461d",
        "0x26667428c38ef4606f6f8d879fdc841a7194461ed02bff6b195647e7c9ccdf17",
        "0x26667428c38ef4606f6f8d879fdc841a7194461ed02bff6b195647e7c9ccdf17",
    });
}

/// Writes `key` with its last `64 - shared` nibbles changed from `base`'s from nibble
/// `shared` on (so the two share exactly `shared` nibbles).
fn diverge(base: Hash, shared: u32, salt: u8) Hash {
    var key = base;
    const index = shared / 2;
    const flip: u8 = if (shared % 2 == 0) 0x10 * ((salt % 15) + 1) else (salt % 15) + 1;
    key[index] ^= flip;
    return key;
}

/// Blocks over two accounts and two slots each sharing `shared` nibbles: create with large
/// words (hashed leaves) and a small one (embedded), update, wipe, delete and recreate, an
/// unwind with its revert; every key and slot proven after every block.
fn shared_prefix_blocks(w: *std.Io.Writer, shared: u32) !void {
    const base = keccak256(&.{@as(u8, @intCast(shared))});
    const keys = [2]Hash{ base, diverge(base, shared, 3) };
    const slot_base = keccak256(&.{ @as(u8, @intCast(shared)), 1 });
    const slots = [2]Hash{ slot_base, diverge(slot_base, shared, 7) };
    const big = "0x" ++ repeat("ff", 32);
    const small = "0x" ++ repeat("00", 31) ++ "05";
    const steps = [_]struct { ops: []const u8, unwind: u32 = 0, revert: []const u8 = "" }{
        .{ .ops = "AaAbSaaBSabBSbaBSbbS" },
        .{ .ops = "SaaZSbbB" },
        .{ .ops = "Wa" },
        .{ .ops = "DbAbSbaB" },
        // Back to the second block's state, then other writes.
        .{ .ops = "SabSSbaZ", .unwind = 2, .revert = "SabBSbbB" },
    };
    for (steps, 1..) |step, index| {
        if (index > 1) try w.writeAll(",");
        try w.print("{{\"number\":\"0x{x}\",\"unwind\":{d}", .{ index - step.unwind, step.unwind });
        if (step.unwind > 0) {
            try w.writeAll(",\"revert\":[");
            try shared_ops(w, step.revert, &keys, &slots, big, small);
            try w.writeAll("]");
        }
        try w.writeAll(",\"ops\":[");
        try shared_ops(w, step.ops, &keys, &slots, big, small);
        try w.writeAll("],\"proofs\":[");
        for (keys, 0..) |key, key_index| {
            if (key_index > 0) try w.writeAll(",");
            try w.print("{{\"key\":\"0x{x}\",\"slots\":[\"0x{x}\",\"0x{x}\"]}}", .{
                &key, &slots[0], &slots[1],
            });
        }
        try w.writeAll("]}");
    }
}

/// Ops from a script: `A<k>` account, `S<k><s><word>` storage (`B` big, `S` small, `Z`
/// zero), `W<k>` wipe, `D<k>` delete; `k` and `s` are `a` or `b`.
fn shared_ops(
    w: *std.Io.Writer,
    script: []const u8,
    keys: *const [2]Hash,
    slots: *const [2]Hash,
    big: []const u8,
    small: []const u8,
) !void {
    var index: usize = 0;
    var first = true;
    while (index < script.len) {
        if (!first) try w.writeAll(",");
        first = false;
        const key = &keys[script[index + 1] - 'a'];
        switch (script[index]) {
            'A' => {
                try w.print("{{\"op\":\"account\",\"key\":\"0x{x}\",\"nonce\":\"0x1\"," ++
                    "\"balance\":\"0x7\",\"codeHash\":\"{s}\"}}", .{ key, empty_code });
                index += 2;
            },
            'S' => {
                const slot = &slots[script[index + 2] - 'a'];
                const word = switch (script[index + 3]) {
                    'B' => big,
                    'S' => small,
                    else => "0x" ++ repeat("00", 32),
                };
                try w.print("{{\"op\":\"storage\",\"key\":\"0x{x}\",\"slot\":\"0x{x}\"," ++
                    "\"value\":\"{s}\"}}", .{ key, slot, word });
                index += 4;
            },
            'W', 'D' => {
                const name = if (script[index] == 'W') "wipe" else "delete";
                try w.print("{{\"op\":\"{s}\",\"key\":\"0x{x}\"}}", .{ name, key });
                index += 2;
            },
            else => unreachable, // The scripts above use these letters only.
        }
    }
}

test "diff trie: keys sharing 60 to 63 nibbles agree everywhere, across restarts" {
    const harness = try Harness.create();
    defer harness.destroy();
    var blocks: std.Io.Writer.Allocating = .init(testing.allocator);
    defer blocks.deinit();
    for ([_]u32{ 60, 61, 62, 63 }) |shared| {
        blocks.clearRetainingCapacity();
        try shared_prefix_blocks(&blocks.writer, shared);
        const response = try harness.request(blocks.written());
        expect_variants_agree(response) catch |err| {
            std.debug.print("diff trie: shared prefix of {d} nibbles\n", .{shared});
            return err;
        };
        try testing.expect(field(response, "variants").object.contains("disk-small-reopen"));
    }
}

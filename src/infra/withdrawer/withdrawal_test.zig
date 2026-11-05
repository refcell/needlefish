//! Withdrawal tests over the public base/base Base Sepolia fixture (a real withdrawal, its
//! header, `eth_getProof` response and the dispute game claim) and synthetic tries for the
//! geth and reth inline-node proof shapes.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const withdrawal_module = @import("withdrawal.zig");
const header_json = @import("../../consensus/sources/header_json.zig");
const trie_module = @import("../../execution/trie/trie.zig");
const trie_proof = @import("../../execution/trie/proof.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = withdrawal_module.Hash;
const Address = withdrawal_module.Address;
const Withdrawal = withdrawal_module.Withdrawal;
const Log = withdrawal_module.Log;

const fixture_json = @embedFile("testdata/base_sepolia_withdrawal_proof.json");

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    log: Log,
    receipt_block: u64,
    block: withdrawal_module.BlockCommitment,
    header_number: u64,
    proof: withdrawal_module.AccountProof,
    storage: [1]withdrawal_module.StorageProof,
    root_claim: Hash,

    fn deinit(fixture: *Fixture) void {
        fixture.arena.deinit();
    }
};

fn hex_alloc(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    const text = value.string[2..];
    const out = try allocator.alloc(u8, text.len / 2);
    _ = try std.fmt.hexToBytes(out, text);
    return out;
}

fn hex_fixed(comptime size: usize, value: std.json.Value) ![size]u8 {
    var out: [size]u8 = undefined;
    const text = value.string[2..];
    if (text.len != size * 2) return error.BadFixture;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}

fn quantity(comptime T: type, value: std.json.Value) !T {
    return std.fmt.parseInt(T, value.string[2..], 16);
}

fn node_list(allocator: std.mem.Allocator, value: std.json.Value) ![]const []const u8 {
    const items = value.array.items;
    const nodes = try allocator.alloc([]const u8, items.len);
    for (items, nodes) |item, *node| node.* = try hex_alloc(allocator, item);
    return nodes;
}

fn load(fixture: *Fixture) !void {
    fixture.arena = .init(testing.allocator);
    errdefer fixture.arena.deinit();
    const allocator = fixture.arena.allocator();
    const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, fixture_json, .{});
    const receipt = root.object.get("receipt").?;
    const log = receipt.object.get("logs").?.array.items[0];
    const topic_values = log.object.get("topics").?.array.items;
    const topics = try allocator.alloc(Hash, topic_values.len);
    for (topic_values, topics) |value, *topic| topic.* = try hex_fixed(32, value);
    fixture.log = .{
        .address = try hex_fixed(20, log.object.get("address").?),
        .topics = topics,
        .data = try hex_alloc(allocator, log.object.get("data").?),
    };
    fixture.receipt_block = try quantity(u64, receipt.object.get("blockNumber").?);
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const header_value = root.object.get("header").?;
    const header_text = try std.json.Stringify.valueAlloc(allocator, header_value, .{});
    const header = try header_json.decode(header_text, &extra);
    fixture.block = .{
        .state_root = header.header.state_root.bytes,
        .block_hash = header.hash.bytes,
    };
    fixture.header_number = header.header.number;
    try load_proof(fixture, allocator, root.object.get("proof").?);
    fixture.root_claim = try hex_fixed(32, root.object.get("game").?.object.get("rootClaim").?);
}

fn load_proof(fixture: *Fixture, allocator: std.mem.Allocator, proof: std.json.Value) !void {
    const storage = proof.object.get("storageProof").?.array.items[0];
    fixture.storage[0] = .{
        .key = try hex_fixed(32, storage.object.get("key").?),
        .value = try quantity(u256, storage.object.get("value").?),
        .proof = try node_list(allocator, storage.object.get("proof").?),
    };
    fixture.proof = .{
        .address = try hex_fixed(20, proof.object.get("address").?),
        .nonce = try quantity(u64, proof.object.get("nonce").?),
        .balance = try quantity(u256, proof.object.get("balance").?),
        .storage_hash = try hex_fixed(32, proof.object.get("storageHash").?),
        .code_hash = try hex_fixed(32, proof.object.get("codeHash").?),
        .account_proof = try node_list(allocator, proof.object.get("accountProof").?),
        .storage_proof = &fixture.storage,
    };
}

fn fixture_withdrawal(fixture: *const Fixture) !Withdrawal {
    return (try withdrawal_module.decode_message_passed(fixture.log, fixture.receipt_block)).?;
}

test "withdrawal fixture: hash and slot match the onchain commitments" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    const withdrawal = try fixture_withdrawal(&fixture);
    try testing.expectEqual(@as(u64, 48_112_889), withdrawal.block_number);
    // Version 1 in the top two bytes, sequence 0xb542 below.
    const nonce: u256 = (@as(u256, 1) << 240) | 0xb542;
    try testing.expectEqual(nonce, withdrawal.transaction.nonce);
    try testing.expectEqualSlices(u8, &fixture.storage[0].key, &withdrawal.slot());
    try testing.expectEqual(@as(u256, 0x7812e), withdrawal.transaction.gas_limit);
}

test "withdrawal fixture: proof verifies against the onchain claim" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    const withdrawal = try fixture_withdrawal(&fixture);
    var nodes: withdrawal_module.ProofNodes = .{};
    const output = try withdrawal_module.verify_proof(
        &withdrawal,
        fixture.block,
        &fixture.proof,
        fixture.root_claim,
        &nodes,
    );
    try testing.expectEqualSlices(u8, &fixture.root_claim, &output.root());
    try testing.expectEqual(fixture.storage[0].proof.len, nodes.count);
    for (fixture.storage[0].proof, nodes.slice()) |expected, actual| {
        try testing.expectEqualSlices(u8, expected, actual);
    }
}

fn expect_verify_error(fixture: *const Fixture, expected: anyerror, claim: Hash) !void {
    const withdrawal = try fixture_withdrawal(fixture);
    var nodes: withdrawal_module.ProofNodes = .{};
    try testing.expectError(expected, withdrawal_module.verify_proof(
        &withdrawal,
        fixture.block,
        &fixture.proof,
        claim,
        &nodes,
    ));
}

test "withdrawal fixture: rejects tampered claims, accounts, keys and values" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    try expect_verify_error(&fixture, error.OutputRootMismatch, @splat(0));
    const claim = fixture.root_claim;
    var tampered = fixture.block;
    tampered.block_hash[0] ^= 1;
    fixture.block = tampered;
    try expect_verify_error(&fixture, error.OutputRootMismatch, claim);
    fixture.block.block_hash[0] ^= 1;
    fixture.proof.address = @splat(0);
    try expect_verify_error(&fixture, error.ProofAddressMismatch, claim);
    fixture.proof.address = withdrawal_module.message_passer;
    fixture.storage[0].value = 0;
    try expect_verify_error(&fixture, error.StorageValueMismatch, claim);
    fixture.storage[0].value = 1;
    fixture.storage[0].key = @splat(0);
    try expect_verify_error(&fixture, error.StorageKeyMismatch, claim);
    fixture.storage[0].key = (try fixture_withdrawal(&fixture)).slot();
    fixture.proof.storage_proof = &.{};
    try expect_verify_error(&fixture, error.StorageProofCount, claim);
    const two = [2]withdrawal_module.StorageProof{ fixture.storage[0], fixture.storage[0] };
    fixture.proof.storage_proof = &two;
    try expect_verify_error(&fixture, error.StorageProofCount, claim);
    fixture.proof.storage_proof = &fixture.storage;
    try expect_verify_error(&fixture, error.OutputRootMismatch, @splat(1));
}

test "withdrawal fixture: rejects incomplete and malformed proofs" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    const claim = fixture.root_claim;
    const account = fixture.proof.account_proof;
    fixture.proof.account_proof = account[0 .. account.len - 1];
    try expect_verify_error(&fixture, error.AccountProof, claim);
    fixture.proof.account_proof = account;
    fixture.proof.nonce += 1;
    try expect_verify_error(&fixture, error.AccountProof, claim);
    fixture.proof.nonce -= 1;
    const storage = fixture.storage[0].proof;
    fixture.storage[0].proof = storage[0 .. storage.len - 1];
    try expect_verify_error(&fixture, error.StorageProof, claim);
    // An overlong compact path inserted in the middle (base/base regression).
    var path: [34]u8 = @splat(0);
    path[0] = 0x20;
    var leaf_buffer: [64]u8 = undefined;
    leaf_buffer[0] = 0xc0 + 2 + 34 + 1;
    leaf_buffer[1] = 0x80 + 34;
    @memcpy(leaf_buffer[2..36], &path);
    leaf_buffer[36] = 0x01;
    var malformed: [16][]const u8 = undefined;
    malformed[0] = storage[0];
    malformed[1] = leaf_buffer[0..37];
    @memcpy(malformed[2 .. storage.len + 1], storage[1..]);
    fixture.storage[0].proof = malformed[0 .. storage.len + 1];
    try expect_verify_error(&fixture, error.StorageProof, claim);
}

test "withdrawal fixture: receipt logs keep only message passer events in order" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    var impostor = fixture.log;
    impostor.address = @splat(0x99);
    var other_event = fixture.log;
    const other_topics = [_]Hash{@splat(0x42)};
    other_event.topics = &other_topics;
    var out: [4]Withdrawal = undefined;
    const logs = [_]Log{ impostor, other_event, fixture.log };
    const found = try withdrawal_module.from_logs(&logs, fixture.receipt_block, &out);
    try testing.expectEqual(@as(usize, 1), found.len);
    try testing.expectError(error.NoWithdrawals, withdrawal_module.from_logs(logs[0..2], 1, &out));
    try testing.expectError(error.NoWithdrawals, withdrawal_module.from_logs(&.{}, 1, &out));
    const no_block = withdrawal_module.from_logs(&logs, null, &out);
    try testing.expectError(error.MissingBlockNumber, no_block);
    const max = try withdrawal_module.from_logs(logs[2..], std.math.maxInt(u64), &out);
    try testing.expectEqual(std.math.maxInt(u64), max[0].block_number);
    try testing.expectError(error.TooManyWithdrawals, withdrawal_module.from_logs(
        &.{ fixture.log, fixture.log },
        1,
        out[0..1],
    ));
}

test "withdrawal fixture: a second withdrawal in the same receipt" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    var second = try fixture_withdrawal(&fixture);
    second.transaction.nonce += 1;
    var topics: [4]Hash = undefined;
    @memcpy(&topics, fixture.log.topics);
    std.mem.writeInt(u256, &topics[1], second.transaction.nonce, .big);
    var data: [1024]u8 = undefined;
    @memcpy(data[0..fixture.log.data.len], fixture.log.data);
    data[3 * 32 ..][0..32].* = second.hash();
    const log: Log = .{
        .address = fixture.log.address,
        .topics = &topics,
        .data = data[0..fixture.log.data.len],
    };
    var out: [4]Withdrawal = undefined;
    const found = try withdrawal_module.from_logs(&.{ fixture.log, log }, 5, &out);
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqual(second.transaction.nonce, found[1].transaction.nonce);
}

test "withdrawal fixture: malformed events and wrong commitments are errors" {
    var fixture: Fixture = undefined;
    try load(&fixture);
    defer fixture.deinit();
    var log = fixture.log;
    log.data = "";
    try testing.expectError(error.DecodeEvent, withdrawal_module.decode_message_passed(log, 1));
    var data: [1024]u8 = undefined;
    @memcpy(data[0..fixture.log.data.len], fixture.log.data);
    @memset(data[3 * 32 ..][0..32], 0);
    log.data = data[0..fixture.log.data.len];
    const mismatch = withdrawal_module.decode_message_passed(log, 1);
    try testing.expectError(error.WithdrawalHashMismatch, mismatch);
    log = fixture.log;
    log.topics = fixture.log.topics[0..3];
    try testing.expectError(error.DecodeEvent, withdrawal_module.decode_message_passed(log, 1));
}

const Trie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 33 });

test "withdrawal: geth and reth shaped inline proofs verify identically" {
    var trie = try Trie.init(testing.allocator, 16);
    defer trie.deinit(testing.allocator);
    const key_zero: Hash = @splat(0);
    var key_one: Hash = @splat(0);
    key_one[31] = 1;
    try trie.put(&key_zero, "\x01");
    try trie.put(&key_one, "\x01");
    const root = trie.root_hash();
    var proof: Trie.Proof = .{};
    trie.prove(&key_one, &proof);
    try testing.expectEqual(@as(u32, 1), proof.count);
    const geth = [_][]const u8{proof.node_at(0)};
    var reth: withdrawal_module.ProofNodes = .{};
    try withdrawal_module.expand_inline_nodes(&geth, &key_one, &reth);
    try testing.expectEqual(@as(u32, 3), reth.count);
    for ([_][]const []const u8{ &geth, reth.slice() }) |shape| {
        const stripped = try withdrawal_module.strip_inline_nodes(shape, root, &key_one, "\x01");
        try testing.expectEqual(@as(usize, 1), stripped.len);
        var expanded: withdrawal_module.ProofNodes = .{};
        try withdrawal_module.expand_inline_nodes(stripped, &key_one, &expanded);
        try testing.expectEqual(reth.count, expanded.count);
    }
    var tampered_leaf: [8]u8 = undefined;
    const leaf = reth.nodes[2];
    @memcpy(tampered_leaf[0..leaf.len], leaf);
    tampered_leaf[leaf.len - 1] ^= 1;
    var tampered = reth;
    tampered.nodes[2] = tampered_leaf[0..leaf.len];
    const expected = trie_proof.verify(root, &key_one, tampered.slice());
    try testing.expectError(error.UnusedNodes, expected);
    try testing.expectError(error.UnusedNodes, withdrawal_module.strip_inline_nodes(
        tampered.slice(),
        root,
        &key_one,
        "\x01",
    ));
}

test "withdrawal: seeded tries strip and expand proofs of every shape" {
    var prng = Prng.init(0x77_17);
    var trie = try Trie.init(testing.allocator, 256);
    defer trie.deinit(testing.allocator);
    for (0..32) |_| {
        trie.clear();
        var keys: [16]Hash = undefined;
        const count: usize = @intCast(prng.range(1, keys.len));
        for (keys[0..count]) |*key| {
            key.* = @splat(0);
            // Mostly-shared prefixes make short (inline) subtries likely.
            key[31] = @intCast(prng.below(256));
            if (prng.chance(1, 4)) prng.fill(key);
            try trie.put(key, "\x01");
        }
        const root = trie.root_hash();
        const key = keys[prng.below(count)];
        var proof: Trie.Proof = .{};
        trie.prove(&key, &proof);
        var geth: [64][]const u8 = undefined;
        for (0..proof.count) |index| geth[index] = proof.node_at(@intCast(index));
        var reth: withdrawal_module.ProofNodes = .{};
        try withdrawal_module.expand_inline_nodes(geth[0..proof.count], &key, &reth);
        const stripped = try withdrawal_module.strip_inline_nodes(reth.slice(), root, &key, "\x01");
        try testing.expectEqual(@as(usize, proof.count), stripped.len);
        const value = try trie_proof.verify(root, &key, stripped);
        try testing.expectEqualSlices(u8, "\x01", value.?);
    }
}

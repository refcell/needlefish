//! EIP-2935 history lookups (base/base `crates/proof/proof/src/eip2935.rs`): the hash of an
//! older L2 block read from the history storage contract's ring buffer in `header`'s state,
//! so a by-number lookup leaps back up to 8191 blocks at once instead of walking parents.
//! A target outside the window yields the oldest block the window holds. Any failure
//! (missing nodes, an unserved hint) is returned so the caller falls back to the walk.

const std = @import("std");
const assert = std.debug.assert;

const consensus = @import("../../common/consensus/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const trie = @import("../../execution/trie/root.zig");
const rlp = trie.rlp;
const mpt = @import("../mpt/root.zig");
const preimage = @import("../preimage/root.zig");
const hint = @import("hint.zig");

const Hash = [32]u8;

/// `0x0000F90827F1C53a10cb7A02335B175320002935`.
pub const history_storage_address = [20]u8{
    0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb,
    0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35,
};

/// Blocks the contract serves (`2^13 - 1`); slots are `number % history_serve_window`.
pub const history_serve_window: u64 = (1 << 13) - 1;

pub const Error = mpt.key_reader.Error || hint.SendError || error{
    MissingAccount,
    MissingSlot,
    InvalidAccount,
    InvalidSlot,
};

/// The ring slot holding block `number` as seen from block `head_number`, or the oldest
/// slot when `number` is outside the window.
pub fn slot_for(head_number: u64, number: u64) u64 {
    assert(number <= head_number);
    const inside = head_number - number <= history_serve_window;
    const slot = (if (inside) number else head_number) % history_serve_window;
    assert(slot < history_serve_window);
    return slot;
}

/// The block hash at the ring slot for `number` in `header`'s state.
pub fn lookup(
    resolver: trie.sparse.Resolver,
    hints: preimage.HintWriter,
    header: *const consensus.Header,
    number: u64,
) Error!Hash {
    assert(number < header.number);
    const slot = slot_for(header.number, number);
    var slot_word: [32]u8 = @splat(0);
    std.mem.writeInt(u64, slot_word[24..32], slot, .big);
    var number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &number_bytes, header.number, .big);
    try hint.send(hints, .l2_account_storage_proof, &.{
        &number_bytes, &history_storage_address, &slot_word,
    });
    var scratch: trie.RlpNode = .{};
    const account_key = keccak.keccak256(&history_storage_address);
    const state_root = header.state_root.bytes;
    const account_rlp = try mpt.key_reader.get(resolver, state_root, &account_key, &scratch) orelse
        return error.MissingAccount;
    const storage_root = try storage_root_of(account_rlp);
    const slot_key = keccak.keccak256(&slot_word);
    const value = try mpt.key_reader.get(resolver, storage_root, &slot_key, &scratch) orelse
        return error.MissingSlot;
    // base/base decodes the value as a 32-byte string (`B256::decode`).
    const item = rlp.decode_item(value) catch return error.InvalidSlot;
    if (item.kind != .string or item.encoded_length != value.len) return error.InvalidSlot;
    if (item.payload.len != 32) return error.InvalidSlot;
    return item.payload[0..32].*;
}

/// The storage root (third field) of an RLP account `[nonce, balance, root, code_hash]`.
fn storage_root_of(account_rlp: []const u8) Error!Hash {
    const outer = rlp.decode_item(account_rlp) catch return error.InvalidAccount;
    if (outer.kind != .list or outer.encoded_length != account_rlp.len) {
        return error.InvalidAccount;
    }
    var items: [4]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidAccount;
    if (count != 4) return error.InvalidAccount;
    if (items[2].kind != .string or items[2].payload.len != 32) return error.InvalidAccount;
    assert(items[3].kind == .string or items[3].kind == .list);
    return items[2].payload[0..32].*;
}

const testing = std.testing;

test "eip2935: slots inside and outside the window" {
    try testing.expectEqual(@as(u64, 100), slot_for(200, 100));
    try testing.expectEqual(@as(u64, 0), slot_for(history_serve_window, 0));
    // Out of the window: the oldest block, `head - window`, at the head's slot.
    try testing.expectEqual(@as(u64, 1), slot_for(history_serve_window + 1, 0));
    const head: u64 = 3 * history_serve_window + 17;
    try testing.expectEqual(head % history_serve_window, slot_for(head, 5));
    try testing.expectEqual(@as(u64, 17), slot_for(head, head - 1 - history_serve_window + 1));
}

test "eip2935: the hashed address matches base/base" {
    const expected = "6c9d57be05dd69371c4dd2e871bce6e9f4124236825bb612ee18a45e5675be51";
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&keccak.keccak256(&history_storage_address)});
    try testing.expectEqualStrings(expected, &hex);
}

const test_oracle = @import("../test_oracle.zig");
const KeyTrie = trie.TrieType(.{ .key_bytes_max = 32, .value_size_max = 128 });

/// Stores a trie of `entries` (hashed key, value) and returns its root.
fn store_trie(
    store: *test_oracle.MapStore,
    keys: []const Hash,
    values: []const []const u8,
) !Hash {
    var full = try KeyTrie.init(testing.allocator, 64);
    defer full.deinit(testing.allocator);
    try full.track_changes(testing.allocator);
    for (keys, values) |*key, value| try full.put(key, value);
    const root = full.root_hash();
    try full.visit_nodes(full.root, .all, test_oracle.MapStore.Collect{ .store = store });
    return root;
}

/// `[0, 0, storage_root, keccak256("")]`.
fn test_account(storage_root: Hash) [70]u8 {
    var out: [70]u8 = undefined;
    out[0..4].* = .{ 0xf8, 0x44, 0x80, 0x80 };
    out[4] = 0xa0;
    out[5..37].* = storage_root;
    out[37] = 0xa0;
    out[38..70].* = keccak.keccak256("");
    return out;
}

test "eip2935: lookup reads the ring slot through the state and storage tries" {
    var store: test_oracle.MapStore = .init();
    defer store.deinit();
    const head_number: u64 = 20_000;
    const target: u64 = head_number - 100;
    const block_hash: Hash = @splat(0x7b);
    var slot_word: [32]u8 = @splat(0);
    std.mem.writeInt(u64, slot_word[24..32], slot_for(head_number, target), .big);
    var slot_value: [33]u8 = undefined;
    slot_value[0] = 0xa0;
    slot_value[1..].* = block_hash;
    const other_slot: Hash = @splat(3);
    const storage_root = try store_trie(
        &store,
        &.{ keccak.keccak256(&slot_word), other_slot },
        &.{ &slot_value, "\x05" },
    );
    const account = test_account(storage_root);
    const other_account: Hash = @splat(9);
    const state_root = try store_trie(
        &store,
        &.{ keccak.keccak256(&history_storage_address), other_account },
        &.{ &account, &test_account(@splat(1)) },
    );
    var harness: preimage.InProcess = undefined;
    try harness.init(
        testing.allocator,
        store.fetcher(),
        preimage.in_process.ignore_hints,
        .{ .channel_bytes = 8192 },
    );
    defer harness.deinit(testing.allocator);
    var resolver: mpt.OracleResolver = try .init(testing.allocator, harness.oracle_reader(), .{
        .bytes_max = 1 << 16,
        .entries_max = 256,
    });
    defer resolver.deinit(testing.allocator);
    var header: consensus.Header = .{
        .number = head_number,
        .state_root = .{ .bytes = state_root },
    };
    const hints = harness.hint_writer();
    const nodes = resolver.resolver();
    try testing.expectEqual(block_hash, try lookup(nodes, hints, &header, target));
    // Another slot is absent from the ring.
    try testing.expectError(error.MissingSlot, lookup(nodes, hints, &header, 7));
    // A state without the contract, or with nodes the oracle lacks.
    header.state_root = .{ .bytes = storage_root };
    try testing.expectError(error.MissingAccount, lookup(nodes, hints, &header, target));
    header.state_root = .{ .bytes = @splat(0x44) };
    try testing.expectError(error.WitnessIncomplete, lookup(nodes, hints, &header, target));
}

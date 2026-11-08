//! `base state-check` (`state_check.zig`): decoding the reference node's answers
//! (`eth_getProof`, `eth_getCode`) and comparing them with what a needlefish disk-mode
//! database reads at the same block.
//!
//! Every account is read twice on the needlefish side: through the trie from the state root
//! (`DiskState.verify_leaf`, every node rebuilt and checked against its parent's hash) and from
//! the flat account record (`DiskState.account`). Every slot likewise (`verify_leaf` with the
//! slot, and `DiskState.storage`). Each side is compared field by field with the reference;
//! one differing field is one `Mismatch`. An absent account reads as the empty account on both
//! sides (the reference reports absent accounts with the empty code hash and the empty root,
//! or with zero hashes), so absent-or-empty matches absent-or-empty.

const std = @import("std");
const base = @import("base");

const node = base.execution.trie.node;
const json = std.json;
const assert = std.debug.assert;

pub const Hash = [32]u8;
pub const Address = [20]u8;

/// An account as either side reports it.
pub const Fields = struct {
    nonce: u64,
    balance: u256,
    code_hash: Hash,
    storage_root: Hash,

    pub const empty: Fields = .{
        .nonce = 0,
        .balance = 0,
        .code_hash = node.empty_code_hash,
        .storage_root = node.empty_root,
    };

    pub fn is_empty(fields: *const Fields) bool {
        return fields.nonce == 0 and fields.balance == 0 and
            std.mem.eql(u8, &fields.code_hash, &node.empty_code_hash) and
            std.mem.eql(u8, &fields.storage_root, &node.empty_root);
    }

    pub fn has_code(fields: *const Fields) bool {
        return !std.mem.eql(u8, &fields.code_hash, &node.empty_code_hash);
    }
};

pub const Field = enum { presence, nonce, balance, code_hash, storage_root, slot, code, read };

/// Where the differing value was read: needlefish's trie walk, its flat records, its code
/// tables, or the reference itself (an `eth_getCode` that does not hash to `codeHash`).
pub const Side = enum { trie, flat, code_table, reference };

pub const Mismatch = struct {
    address: Address,
    /// The slot key (not hashed), for slot mismatches.
    slot: ?Hash = null,
    field: Field,
    side: Side,
    /// The reference's value (big-endian), or what the reference implies.
    expected: Hash,
    /// needlefish's value (big-endian).
    actual: Hash,
    /// A read that failed (`field` `.read`).
    failure: ?anyerror = null,
};

/// Mismatches kept for printing; all of them are counted.
pub const mismatches_kept_max = 512;

pub const Report = struct {
    kept: [mismatches_kept_max]Mismatch = undefined,
    kept_count: u32 = 0,
    total: u64 = 0,
    /// Print every mismatch as it is found (all of them, kept or not).
    print: bool = false,

    pub fn add(report: *Report, mismatch: Mismatch) void {
        assert(report.kept_count <= mismatches_kept_max);
        assert(report.kept_count <= report.total);
        if (report.print) print_mismatch(&mismatch);
        report.total += 1;
        if (report.kept_count == mismatches_kept_max) return;
        report.kept[report.kept_count] = mismatch;
        report.kept_count += 1;
    }

    pub fn list(report: *const Report) []const Mismatch {
        assert(report.kept_count <= mismatches_kept_max);
        return report.kept[0..report.kept_count];
    }
};

pub fn word_bytes(value: u256) Hash {
    var bytes: Hash = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return bytes;
}

// Decoding.

pub const DecodeError = error{ MalformedResponse, WrongAddress, MissingKey };

fn hex_digits(text: []const u8) DecodeError![]const u8 {
    if (text.len < 2 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) {
        return error.MalformedResponse;
    }
    return text[2..];
}

/// A JSON-RPC quantity (`0x` and 1..64 hex digits; leading zeros allowed).
pub fn parse_word(text: []const u8) DecodeError!u256 {
    const digits = try hex_digits(text);
    if (digits.len == 0 or digits.len > 64) return error.MalformedResponse;
    const word = std.fmt.parseInt(u256, digits, 16) catch return error.MalformedResponse;
    assert(digits.len == 64 or word >> @intCast(digits.len * 4) == 0);
    return word;
}

pub fn parse_u64(text: []const u8) DecodeError!u64 {
    const word = try parse_word(text);
    if (word > std.math.maxInt(u64)) return error.MalformedResponse;
    return @intCast(word);
}

/// Fixed-size data (`0x` and exactly 2 * `size` hex digits).
pub fn parse_fixed(comptime size: usize, text: []const u8) DecodeError![size]u8 {
    const digits = try hex_digits(text);
    if (digits.len != size * 2) return error.MalformedResponse;
    var out: [size]u8 = undefined;
    const written = std.fmt.hexToBytes(&out, digits) catch return error.MalformedResponse;
    assert(written.len == size);
    return out;
}

/// Variable data (`0x` and an even number of hex digits), into `arena`.
pub fn parse_data(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    const digits = try hex_digits(text);
    if (digits.len % 2 != 0) return error.MalformedResponse;
    const out = try arena.alloc(u8, digits.len / 2);
    const written = std.fmt.hexToBytes(out, digits) catch return error.MalformedResponse;
    assert(written.len == out.len);
    return out;
}

pub fn member_string(value: json.Value, name: []const u8) DecodeError![]const u8 {
    if (value != .object) return error.MalformedResponse;
    const field = value.object.get(name) orelse return error.MalformedResponse;
    if (field != .string) return error.MalformedResponse;
    return field.string;
}

/// One `eth_getProof` result: the account (zero hashes normalized to the empty code hash and
/// the empty root, as some nodes report absent accounts) and the requested slots' words.
pub const Proof = struct {
    fields: Fields,
    words: []u256,
};

/// Decodes an `eth_getProof(address, keys, N)` result; every requested key must be answered
/// (in any order, keys compared as words: nodes echo them trimmed or padded).
pub fn decode_proof(
    arena: std.mem.Allocator,
    value: json.Value,
    address: *const Address,
    keys: []const Hash,
) !Proof {
    const answered = try parse_fixed(20, try member_string(value, "address"));
    if (!std.mem.eql(u8, &answered, address)) return error.WrongAddress;
    var fields: Fields = .{
        .nonce = try parse_u64(try member_string(value, "nonce")),
        .balance = try parse_word(try member_string(value, "balance")),
        .code_hash = try parse_fixed(32, try member_string(value, "codeHash")),
        .storage_root = try parse_fixed(32, try member_string(value, "storageHash")),
    };
    const zero: Hash = @splat(0);
    if (std.mem.eql(u8, &fields.code_hash, &zero)) fields.code_hash = node.empty_code_hash;
    if (std.mem.eql(u8, &fields.storage_root, &zero)) fields.storage_root = node.empty_root;
    const storage = value.object.get("storageProof") orelse return error.MalformedResponse;
    if (storage != .array or storage.array.items.len != keys.len) return error.MalformedResponse;
    const words = try arena.alloc(u256, keys.len);
    for (keys, words) |*key, *word| {
        const wanted = std.mem.readInt(u256, key, .big);
        word.* = for (storage.array.items) |item| {
            const echoed = try parse_word(try member_string(item, "key"));
            if (echoed == wanted) break try parse_word(try member_string(item, "value"));
        } else return error.MissingKey;
    }
    assert(words.len == keys.len);
    return .{ .fields = fields, .words = words };
}

// Comparing.

/// What needlefish holds for one account: through the trie and from the flat record.
pub const LocalAccount = struct { trie: ?Fields, flat: ?Fields };
pub const LocalSlot = struct { trie: u256, flat: u256 };

/// Reads an account both ways from a disk-mode `DiskState` (`db.disk.?`). Writes nothing.
pub fn read_account(disk: anytype, address_hash: *const Hash) !LocalAccount {
    const leaf = try disk.verify_leaf(address_hash, null);
    assert(leaf.word == 0);
    var local: LocalAccount = .{ .trie = null, .flat = null };
    if (leaf.account) |account| local.trie = .{
        .nonce = account.nonce,
        .balance = account.balance,
        .code_hash = account.code_hash,
        .storage_root = account.storage_root,
    };
    if (disk.account(address_hash)) |record| local.flat = .{
        .nonce = record.info.nonce,
        .balance = record.info.balance,
        .code_hash = record.info.code_hash,
        .storage_root = record.storage_root,
    };
    if (disk.fault) return error.ReadFailed;
    return local;
}

/// Reads a slot both ways (`slot_hash` is keccak256 of the slot key). Writes nothing.
pub fn read_slot(disk: anytype, address_hash: *const Hash, slot_hash: *const Hash) !LocalSlot {
    const leaf = try disk.verify_leaf(address_hash, slot_hash);
    const flat = disk.storage(address_hash, slot_hash);
    if (disk.fault) return error.ReadFailed;
    assert(leaf.account != null or leaf.word == 0);
    return .{ .trie = leaf.word, .flat = flat };
}

/// Compares one account; returns the mismatches added. A trie leaf without a flat record (or
/// the reverse) is a `presence` mismatch on the flat side (expected: the trie's presence).
pub fn compare_account(
    report: *Report,
    address: *const Address,
    reference: *const Fields,
    local: *const LocalAccount,
) u32 {
    const before = report.total;
    const trie_present = local.trie != null;
    const flat_present = local.flat != null;
    if (trie_present != flat_present) report.add(.{
        .address = address.*,
        .field = .presence,
        .side = .flat,
        .expected = word_bytes(@intFromBool(trie_present)),
        .actual = word_bytes(@intFromBool(flat_present)),
    });
    compare_fields(report, address, reference, &(local.trie orelse Fields.empty), .trie);
    compare_fields(report, address, reference, &(local.flat orelse Fields.empty), .flat);
    const added: u32 = @intCast(report.total - before);
    assert(added <= 9);
    assert(added > 0 or trie_present == flat_present);
    return added;
}

fn compare_fields(
    report: *Report,
    address: *const Address,
    reference: *const Fields,
    local: *const Fields,
    side: Side,
) void {
    assert(side == .trie or side == .flat);
    const Pair = struct { field: Field, expected: Hash, actual: Hash };
    const pairs = [_]Pair{
        .{
            .field = .nonce,
            .expected = word_bytes(reference.nonce),
            .actual = word_bytes(local.nonce),
        },
        .{
            .field = .balance,
            .expected = word_bytes(reference.balance),
            .actual = word_bytes(local.balance),
        },
        .{ .field = .code_hash, .expected = reference.code_hash, .actual = local.code_hash },
        .{
            .field = .storage_root,
            .expected = reference.storage_root,
            .actual = local.storage_root,
        },
    };
    for (pairs) |pair| {
        if (std.mem.eql(u8, &pair.expected, &pair.actual)) continue;
        report.add(.{
            .address = address.*,
            .field = pair.field,
            .side = side,
            .expected = pair.expected,
            .actual = pair.actual,
        });
    }
}

/// Compares one slot word; returns the mismatches added (0, 1, or 2).
pub fn compare_slot(
    report: *Report,
    address: *const Address,
    key: *const Hash,
    reference: u256,
    local: LocalSlot,
) u32 {
    const before = report.total;
    const sides = [_]struct { side: Side, word: u256 }{
        .{ .side = .trie, .word = local.trie },
        .{ .side = .flat, .word = local.flat },
    };
    for (sides) |entry| {
        if (entry.word == reference) continue;
        report.add(.{
            .address = address.*,
            .slot = key.*,
            .field = .slot,
            .side = entry.side,
            .expected = word_bytes(reference),
            .actual = word_bytes(entry.word),
        });
    }
    const added: u32 = @intCast(report.total - before);
    assert(added <= 2);
    assert((added == 0) == (local.trie == reference and local.flat == reference));
    return added;
}

/// Compares one code: the reference's `eth_getCode` must hash to `code_hash`, and needlefish's
/// code tables must hold the same bytes under it. Returns the mismatches added.
pub fn compare_code(
    report: *Report,
    address: *const Address,
    code_hash: *const Hash,
    reference_code: []const u8,
    local_code: ?[]const u8,
) u32 {
    assert(!std.mem.eql(u8, code_hash, &node.empty_code_hash));
    const before = report.total;
    const reference_hash = node.keccak256(reference_code);
    if (!std.mem.eql(u8, &reference_hash, code_hash)) report.add(.{
        .address = address.*,
        .field = .code,
        .side = .reference,
        .expected = code_hash.*,
        .actual = reference_hash,
    });
    const zero: Hash = @splat(0);
    const local_hash = if (local_code) |code| node.keccak256(code) else zero;
    if (!std.mem.eql(u8, &local_hash, &reference_hash)) report.add(.{
        .address = address.*,
        .field = .code,
        .side = .code_table,
        .expected = reference_hash,
        .actual = local_hash,
    });
    const added: u32 = @intCast(report.total - before);
    assert(added <= 2);
    return added;
}

/// A read that failed on needlefish's side (counted as a mismatch).
pub fn read_failed(
    report: *Report,
    address: *const Address,
    slot: ?*const Hash,
    err: anyerror,
) void {
    const zero: Hash = @splat(0);
    const before = report.total;
    report.add(.{
        .address = address.*,
        .slot = if (slot) |key| key.* else null,
        .field = .read,
        .side = .trie,
        .expected = zero,
        .actual = zero,
        .failure = err,
    });
    assert(report.total == before + 1);
}

pub fn print_mismatch(mismatch: *const Mismatch) void {
    if (mismatch.field == .read) {
        const failure = mismatch.failure.?;
        if (mismatch.slot) |slot| {
            std.debug.print("MISMATCH 0x{x} slot 0x{x}: needlefish read failed: {t}\n", .{
                mismatch.address, slot, failure,
            });
        } else {
            std.debug.print("MISMATCH 0x{x}: needlefish read failed: {t}\n", .{
                mismatch.address, failure,
            });
        }
        return;
    }
    if (mismatch.slot) |slot| {
        std.debug.print("MISMATCH 0x{x} slot 0x{x} ({t}): reference 0x{x} needlefish 0x{x}\n", .{
            mismatch.address, slot, mismatch.side, mismatch.expected, mismatch.actual,
        });
        return;
    }
    std.debug.print("MISMATCH 0x{x} {t} ({t}): reference 0x{x} needlefish 0x{x}\n", .{
        mismatch.address, mismatch.field, mismatch.side, mismatch.expected, mismatch.actual,
    });
}

// Tests.

const testing = std.testing;

/// An `eth_getProof` answer (sepolia.base.org, L1Block at a recent block; proofs dropped):
/// keys echoed as sent, one trimmed and one padded.
const l1_block_proof =
    \\{"address":"0x4200000000000000000000000000000000000015","balance":"0x0",
    \\"codeHash":"0xfa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998",
    \\"nonce":"0x0",
    \\"storageHash":"0xefd1800b3031cdbd77c55195f857d78e4b03a04066a36b1731636a5f79b63d4f",
    \\"accountProof":[],"storageProof":[
    \\{"key":"0x0","value":"0x6af025d00000000000b87784","proof":[]},
    \\{"key":"0x0000000000000000000000000000000000000000000000000000000000000002",
    \\"value":"0x247438e5efadde19d2aa85478a368fd190c8ef5c0e44b27d055940b18c3f325d","proof":[]},
    \\{"key":"0x1","value":"0x16","proof":[]}]}
;

/// An absent account, as the same endpoint reports it.
const absent_proof =
    \\{"address":"0x1234567890123456789012345678901234567891","balance":"0x0",
    \\"codeHash":"0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    \\"nonce":"0x0",
    \\"storageHash":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    \\"accountProof":[],"storageProof":[{"key":"0x0","value":"0x0","proof":[]}]}
;

fn expect_added(expected: u32, actual: u32) !void {
    try testing.expectEqual(expected, actual);
}

fn key_word(value: u256) Hash {
    return word_bytes(value);
}

test "state-check: eth_getProof answers decode, keys matched as words in any order" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const value = try json.parseFromSliceLeaky(json.Value, arena, l1_block_proof, .{});
    const address = try parse_fixed(20, "0x4200000000000000000000000000000000000015");
    const keys = [_]Hash{ key_word(1), key_word(2), key_word(0) };
    const proof = try decode_proof(arena, value, &address, &keys);
    try testing.expectEqual(@as(u64, 0), proof.fields.nonce);
    try testing.expectEqual(@as(u256, 0), proof.fields.balance);
    try testing.expect(proof.fields.has_code() and !proof.fields.is_empty());
    try testing.expectEqual(@as(u8, 0xef), proof.fields.storage_root[0]);
    try testing.expectEqual(@as(u256, 0x16), proof.words[0]);
    try testing.expectEqual(@as(u8, 0x24), word_bytes(proof.words[1])[0]);
    try testing.expectEqual(@as(u256, 0x6af025d00000000000b87784), proof.words[2]);
    // A key the answer lacks, another address, the wrong number of keys.
    const missing = [_]Hash{ key_word(1), key_word(2), key_word(3) };
    try testing.expectError(error.MissingKey, decode_proof(arena, value, &address, &missing));
    const other = try parse_fixed(20, "0x4200000000000000000000000000000000000016");
    try testing.expectError(error.WrongAddress, decode_proof(arena, value, &other, &keys));
    try testing.expectError(error.MalformedResponse, decode_proof(arena, value, &address, &.{}));
    // The absent account is the empty account, and matches needlefish's absence.
    const absent = try json.parseFromSliceLeaky(json.Value, arena, absent_proof, .{});
    const absent_address = try parse_fixed(20, "0x1234567890123456789012345678901234567891");
    const absent_decoded = try decode_proof(arena, absent, &absent_address, &.{key_word(0)});
    try testing.expect(absent_decoded.fields.is_empty());
    try testing.expectEqual(@as(u256, 0), absent_decoded.words[0]);
    var report: Report = .{};
    const local: LocalAccount = .{ .trie = null, .flat = null };
    const reference = &absent_decoded.fields;
    try expect_added(0, compare_account(&report, &absent_address, reference, &local));
}

test "state-check: zero hashes for an absent account normalize to the empty account" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text =
        \\{"address":"0x0000000000000000000000000000000000000001","balance":"0x0","nonce":"0x0",
        \\"codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        \\"storageHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        \\"storageProof":[]}
    ;
    const value = try json.parseFromSliceLeaky(json.Value, arena, text, .{});
    const address = try parse_fixed(20, "0x0000000000000000000000000000000000000001");
    const proof = try decode_proof(arena, value, &address, &.{});
    try testing.expect(proof.fields.is_empty());
    try testing.expectEqual(@as(usize, 0), proof.words.len);
}

test "state-check: hex quantities and data" {
    try testing.expectEqual(@as(u256, 0), try parse_word("0x0"));
    try testing.expectEqual(@as(u256, 0xabc), try parse_word("0x0abc"));
    try testing.expectEqual(@as(u64, 7), try parse_u64("0x7"));
    const max = "0x" ++ "ffffffffffffffffffffffffffffffff" ++ "ffffffffffffffffffffffffffffffff";
    try testing.expectEqual(@as(u256, std.math.maxInt(u256)), try parse_word(max));
    const long = "0x1" ++ "11111111111111111111111111111111" ++ "11111111111111111111111111111111";
    const rejected = [_][]const u8{ "", "0x", "7", "0xg", long, "x0" };
    for (rejected) |text| try testing.expectError(error.MalformedResponse, parse_word(text));
    try testing.expectError(error.MalformedResponse, parse_u64("0x10000000000000000"));
    try testing.expectError(error.MalformedResponse, parse_fixed(20, "0x00"));
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqualSlices(u8, &.{ 0x60, 0x80 }, try parse_data(arena, "0x6080"));
    try testing.expectEqual(@as(usize, 0), (try parse_data(arena, "0x")).len);
    try testing.expectError(error.MalformedResponse, parse_data(arena, "0x608"));
}

fn sample_fields() Fields {
    return .{
        .nonce = 7,
        .balance = 1 << 70,
        .code_hash = node.keccak256("code"),
        .storage_root = node.keccak256("root"),
    };
}

// Mutation check: each field changed on one side alone is exactly one mismatch, named.
test "state-check: one differing account field is one mismatch" {
    const address: Address = @splat(0x11);
    const reference = sample_fields();
    var report: Report = .{};
    const same: LocalAccount = .{ .trie = reference, .flat = reference };
    try expect_added(0, compare_account(&report, &address, &reference, &same));
    const fields = [_]Field{ .nonce, .balance, .code_hash, .storage_root };
    for (fields) |field| {
        for ([_]Side{ .trie, .flat }) |side| {
            var changed = reference;
            switch (field) {
                .nonce => changed.nonce += 1,
                .balance => changed.balance ^= 1,
                .code_hash => changed.code_hash[31] ^= 1,
                .storage_root => changed.storage_root[0] ^= 0x80,
                else => unreachable,
            }
            var local = same;
            if (side == .trie) local.trie = changed else local.flat = changed;
            const before = report.total;
            try expect_added(1, compare_account(&report, &address, &reference, &local));
            const mismatch = report.list()[report.list().len - 1];
            try testing.expectEqual(before + 1, report.total);
            try testing.expectEqual(field, mismatch.field);
            try testing.expectEqual(side, mismatch.side);
            try testing.expect(!std.mem.eql(u8, &mismatch.expected, &mismatch.actual));
        }
    }
    try testing.expectEqual(@as(u64, 8), report.total);
}

test "state-check: presence, absence, slots, and codes" {
    const address: Address = @splat(0x22);
    const reference = sample_fields();
    var report: Report = .{};
    // needlefish lacks a present account: every field differs on both sides.
    const absent: LocalAccount = .{ .trie = null, .flat = null };
    try expect_added(8, compare_account(&report, &address, &reference, &absent));
    // A trie leaf without a flat record: presence, then the flat side's fields.
    const half: LocalAccount = .{ .trie = reference, .flat = null };
    try expect_added(5, compare_account(&report, &address, &reference, &half));
    try testing.expectEqual(Field.presence, report.list()[8].field);
    // An empty account needlefish holds matches an absent one at the reference.
    const empty: LocalAccount = .{ .trie = Fields.empty, .flat = Fields.empty };
    try expect_added(0, compare_account(&report, &address, &Fields.empty, &empty));
    report = .{};
    const key = key_word(3);
    try expect_added(0, compare_slot(&report, &address, &key, 0, .{ .trie = 0, .flat = 0 }));
    try expect_added(0, compare_slot(&report, &address, &key, 9, .{ .trie = 9, .flat = 9 }));
    try expect_added(1, compare_slot(&report, &address, &key, 9, .{ .trie = 9, .flat = 8 }));
    try testing.expectEqual(Side.flat, report.list()[0].side);
    try expect_added(1, compare_slot(&report, &address, &key, 0, .{ .trie = 1, .flat = 0 }));
    try expect_added(2, compare_slot(&report, &address, &key, 5, .{ .trie = 0, .flat = 0 }));
    report = .{};
    const code = "\x60\x80\x60\x40";
    const hash = node.keccak256(code);
    try expect_added(0, compare_code(&report, &address, &hash, code, code));
    try expect_added(1, compare_code(&report, &address, &hash, code, null));
    try expect_added(1, compare_code(&report, &address, &hash, code, "\x60\x80"));
    try expect_added(2, compare_code(&report, &address, &hash, "\x00", code));
    try testing.expectEqual(Side.reference, report.list()[2].side);
}

test "state-check: the report keeps the first mismatches and counts all" {
    var report: Report = .{};
    const address: Address = @splat(0x33);
    for (0..mismatches_kept_max + 10) |_| read_failed(&report, &address, null, error.Corrupt);
    try testing.expectEqual(@as(u64, mismatches_kept_max + 10), report.total);
    try testing.expectEqual(@as(usize, mismatches_kept_max), report.list().len);
}

/// A stand-in for `DiskState`'s reads, with independent trie and flat answers.
const FakeDisk = struct {
    fault: bool = false,
    trie_account: ?Fields,
    flat_account: ?Fields,
    trie_word: u256 = 0,
    flat_word: u256 = 0,
    fail: bool = false,

    const Leaf = struct {
        account: ?struct { nonce: u64, balance: u256, code_hash: Hash, storage_root: Hash },
        word: u256,
    };
    const Record = struct {
        info: struct { nonce: u64, balance: u256, code_hash: Hash },
        storage_root: Hash,
    };

    fn verify_leaf(disk: *FakeDisk, _: *const Hash, slot: ?*const Hash) !Leaf {
        if (disk.fail) return error.Corrupt;
        const fields = disk.trie_account orelse return .{ .account = null, .word = 0 };
        return .{
            .account = .{
                .nonce = fields.nonce,
                .balance = fields.balance,
                .code_hash = fields.code_hash,
                .storage_root = fields.storage_root,
            },
            .word = if (slot != null) disk.trie_word else 0,
        };
    }

    fn account(disk: *FakeDisk, _: *const Hash) ?Record {
        const fields = disk.flat_account orelse return null;
        return .{
            .info = .{
                .nonce = fields.nonce,
                .balance = fields.balance,
                .code_hash = fields.code_hash,
            },
            .storage_root = fields.storage_root,
        };
    }

    fn storage(disk: *FakeDisk, _: *const Hash, _: *const Hash) u256 {
        return disk.flat_word;
    }
};

test "state-check: needlefish reads both ways and each side is compared" {
    const reference = sample_fields();
    const key: Hash = @splat(1);
    var disk: FakeDisk = .{
        .trie_account = reference,
        .flat_account = reference,
        .trie_word = 4,
        .flat_word = 4,
    };
    const local = try read_account(&disk, &key);
    try testing.expectEqual(reference.nonce, local.trie.?.nonce);
    try testing.expectEqual(reference.balance, local.flat.?.balance);
    var report: Report = .{};
    const address: Address = @splat(0x44);
    try expect_added(0, compare_account(&report, &address, &reference, &local));
    const slot = try read_slot(&disk, &key, &key);
    try expect_added(0, compare_slot(&report, &address, &key, 4, slot));
    // The flat record alone differs: caught on the flat side only.
    disk.flat_account.?.balance += 1;
    disk.flat_word = 5;
    const changed = try read_account(&disk, &key);
    try expect_added(1, compare_account(&report, &address, &reference, &changed));
    try testing.expectEqual(Side.flat, report.list()[0].side);
    const changed_slot = try read_slot(&disk, &key, &key);
    try expect_added(1, compare_slot(&report, &address, &key, 4, changed_slot));
    disk.fail = true;
    try testing.expectError(error.Corrupt, read_account(&disk, &key));
    disk.fail = false;
    disk.fault = true;
    try testing.expectError(error.ReadFailed, read_slot(&disk, &key, &key));
}

fn fuzz_decode(_: void, input: []const u8) anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Any server bytes: never crash; a decoded answer has one word per key.
    const value = json.parseFromSliceLeaky(json.Value, arena, input, .{}) catch return;
    const address: Address = @splat(0);
    const keys = [_]Hash{ key_word(0), key_word(1) };
    const proof = decode_proof(arena, value, &address, &keys) catch return;
    try testing.expectEqual(keys.len, proof.words.len);
}

test "state-check: fuzz eth_getProof answers" {
    const corpus = [_][]const u8{
        l1_block_proof, absent_proof,
        \\{"address":"0x0000000000000000000000000000000000000000","balance":"0x1","nonce":"0x2",
        \\"codeHash":"0x00","storageHash":"0x00","storageProof":[{"key":"0x1","value":"0x2"},
        \\{"key":"0x0","value":"0x3"}]}
    };
    try base.testing.fuzz.run_bytes({}, fuzz_decode, .{ .iterations = 512, .corpus = &corpus });
}

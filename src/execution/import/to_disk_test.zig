//! `to_disk` import, end to end on `SimStorage` (no network, no MDBX file): random states
//! encoded with reth's table encodings (`HashedAccounts` Compact accounts, `HashedStorages`
//! storage entries, raw and analyzed `Bytecodes`) stream through `ImporterType.run` with a
//! synthetic header chain; the database is reopened, and its head, block hashes, root, every
//! account and slot (read through the trie from the root, and from the flat trees), every
//! code, and the reservoir samples are checked against the source state.
//!
//! Mutation checks: a dropped account-trie root record (`import_head` refuses), a dropped
//! storage-branch record (the open succeeds, but reads through the trie under it fail), a
//! wrong header root, a broken header chain, a code under the wrong key, a missing code.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const lazy = @import("../../utilities/lazy_alloc/root.zig");

const to_disk = @import("to_disk.zig");
const hashed_state = @import("hashed_state.zig");
const state_root = @import("state_root.zig");
const reth = @import("reth.zig");
const storage = @import("../db/storage/storage.zig");
const SimStorage = @import("../db/storage/sim_storage.zig").SimStorage;
const branch_record = @import("../db/branch_record.zig");
const node = @import("../trie/node.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = node.Hash;
const Entry = hashed_state.Entry;
const Importer = to_disk.ImporterType(SimStorage);
const Database = Importer.Database;
const sector_size = storage.sector_size;

const record_writes_max = 64;
/// Longest code a table holds at `shape_test`'s block size; longer ones ride in the image.
const table_value_max: u64 = 4 * sector_size - 128 - 8 - 4 - 32;
const reorg_depth_max = 4;

pub const shape_test: to_disk.Shape = .{
    .block_size = 4 * sector_size,
    .journal_size_bytes = 256 * sector_size,
    .entry_body_size_max = 8 * sector_size,
    .chain = .{
        .blocks_max = 16,
        .bytes_max = 256 * 1024,
        .transactions_max = 64,
        .canonical_max = 64,
        .reorg_depth_max = reorg_depth_max,
    },
    .changeset = .{
        .accounts_max = 32,
        .storage_max = 160,
        .codes_max = 1,
        .code_bytes_max = 1024,
    },
    .disk_state = .{
        .trie_nodes_max = 1 << 13,
        .storage_tries_max = 64,
        .memo_entries_max = 1 << 13,
        .memo_bytes_max = 2 * 1024 * 1024,
        .record_writes_max = record_writes_max,
        .record_write_bytes_max = record_writes_max * branch_record.value_bytes_max,
        .replay_record_writes_max = record_writes_max * (2 * reorg_depth_max + 1),
    },
    .queue_entries_max = 6,
    .flat_flush_entries_min = 64,
    .flat_branch_flush_entries_min = 16,
    .flat_cache_blocks = 32,
    .code_flush_bytes_min = 1024,
    .codes_headroom = 4,
    .code_bytes_headroom = 4096,
    // Codes out of RAM, as the node: read back from their tables after a reopen.
    .code_pin_bytes = 64 * 1024,
    .code_pins_max = 16,
    .code_cache_blocks = 16,
};

pub const head_number: u64 = 5_000_000;

// The source state, reth-encoded.

pub const Slot = struct { hash: Hash, word: u256 };

pub const Account = struct {
    key: Hash,
    nonce: u64,
    balance: u256,
    code_hash: Hash,
    slots: []Slot,
};

pub const Source = struct {
    accounts: []Account,
    account_entries: []Entry,
    storage_entries: []Entry,
    code_entries: []Entry,
    codes: [][]const u8,
    root: Hash,

    pub fn counts(source: *const Source) to_disk.Counts {
        var code_bytes: u64 = 0;
        for (source.codes) |code| code_bytes += code.len;
        return .{
            .accounts = source.account_entries.len,
            .slots = source.storage_entries.len,
            .codes = source.codes.len,
            .code_bytes = code_bytes,
        };
    }
};

pub const SliceEntries = struct {
    entries: []const Entry,
    index: usize = 0,

    pub fn source(self: *SliceEntries) hashed_state.EntrySource {
        return .{ .context = self, .next = next };
    }

    fn next(context: *anyopaque) anyerror!?Entry {
        const self: *SliceEntries = @ptrCast(@alignCast(context));
        if (self.index == self.entries.len) return null;
        self.index += 1;
        return self.entries[self.index - 1];
    }
};

fn trimmed(out: []u8, value: u256) []u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) start += 1;
    @memcpy(out[0 .. 32 - start], bytes[start..]);
    return out[0 .. 32 - start];
}

/// A `HashedAccounts` value (reth Compact `Account`).
fn encode_account(arena: std.mem.Allocator, account: *const Account) ![]u8 {
    var nonce_bytes: [32]u8 = undefined;
    var balance_bytes: [32]u8 = undefined;
    const nonce = trimmed(&nonce_bytes, account.nonce);
    const balance = trimmed(&balance_bytes, account.balance);
    const has_code = !std.mem.eql(u8, &account.code_hash, &node.empty_code_hash);
    const flags: u16 = @intCast(nonce.len | balance.len << 4 |
        @as(usize, @intFromBool(has_code)) << 10);
    var value: std.ArrayList(u8) = .empty;
    try value.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToLittle(u16, flags)));
    try value.appendSlice(arena, nonce);
    try value.appendSlice(arena, balance);
    if (has_code) try value.appendSlice(arena, &account.code_hash);
    return value.items;
}

/// A `Bytecodes` value: raw, or analyzed legacy (padded with a STOP, then a jump table).
pub fn encode_code(arena: std.mem.Allocator, code: []const u8, analyzed: bool) ![]u8 {
    var value: std.ArrayList(u8) = .empty;
    const stored_len: u32 = @intCast(code.len + @intFromBool(analyzed));
    try value.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u32, stored_len)));
    try value.appendSlice(arena, code);
    if (analyzed) {
        try value.append(arena, 0x00);
        try value.append(arena, reth.variant_analyzed);
        try value.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u64, code.len)));
        try value.append(arena, 0);
    } else {
        try value.append(arena, reth.variant_raw);
    }
    return value.items;
}

/// A random key, sometimes sharing a prefix with `previous` (deep branches, extensions).
fn random_key(prng: *Prng, previous: ?*const Hash) Hash {
    var key: Hash = undefined;
    prng.fill(&key);
    if (previous) |other| {
        if (prng.chance(1, 3)) {
            const shared = prng.range(1, 3);
            @memcpy(key[0..shared], other[0..shared]);
        }
    }
    return key;
}

pub fn less_account(_: void, a: Account, b: Account) bool {
    return std.mem.order(u8, &a.key, &b.key) == .lt;
}

pub fn less_slot(_: void, a: Slot, b: Slot) bool {
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

pub fn less_entry(_: void, a: Entry, b: Entry) bool {
    return std.mem.order(u8, a.key, b.key) == .lt;
}

fn random_slots(arena: std.mem.Allocator, prng: *Prng) ![]Slot {
    const count = if (prng.chance(1, 8)) prng.range(20, 60) else prng.below(6);
    const slots = try arena.alloc(Slot, count);
    var index: usize = 0;
    while (index < slots.len) {
        const previous = if (index > 0) &slots[index - 1].hash else null;
        const hash = random_key(prng, previous);
        var duplicate = false;
        for (slots[0..index]) |slot| duplicate = duplicate or std.mem.eql(u8, &slot.hash, &hash);
        if (duplicate) continue;
        const word: u256 = if (prng.chance(1, 4)) prng.int(u256) else prng.range(1, 1 << 40);
        slots[index] = .{ .hash = hash, .word = @max(word, 1) };
        index += 1;
    }
    std.mem.sort(Slot, slots, {}, less_slot);
    return slots;
}

/// Codes per source, their longest length, and how many of them (after the empty one) are
/// too long for a code table.
const CodeShape = struct { count_min: u64, count_max: u64, length_max: u64, long: u32 = 0 };

fn random_codes(arena: std.mem.Allocator, prng: *Prng, source: *Source) !void {
    return random_codes_shaped(arena, prng, source, .{
        .count_min = 2,
        .count_max = 6,
        .length_max = 300,
    });
}

fn random_codes_shaped(
    arena: std.mem.Allocator,
    prng: *Prng,
    source: *Source,
    shape: CodeShape,
) !void {
    const count = prng.range(shape.count_min, shape.count_max);
    assert(count > shape.long);
    source.codes = try arena.alloc([]const u8, count);
    source.code_entries = try arena.alloc(Entry, count);
    for (source.codes, source.code_entries, 0..) |*code, *entry, index| {
        // The first is the empty code, which reth's Bytecodes holds (Base Sepolia does).
        const length = if (index == 0)
            0
        else if (index <= shape.long)
            prng.range(table_value_max + 1, table_value_max + 200)
        else
            prng.range(1, shape.length_max);
        const bytes = try arena.alloc(u8, length);
        prng.fill(bytes);
        code.* = bytes;
        const hash = try arena.dupe(u8, &node.keccak256(bytes));
        entry.* = .{ .key = hash, .value = try encode_code(arena, bytes, index % 2 == 1) };
    }
    std.mem.sort(Entry, source.code_entries, {}, less_entry);
}

fn random_source(arena: std.mem.Allocator, prng: *Prng, accounts_count: u64) !Source {
    var source: Source = undefined;
    try random_codes(arena, prng, &source);
    return random_accounts(arena, prng, accounts_count, &source);
}

fn random_accounts(
    arena: std.mem.Allocator,
    prng: *Prng,
    accounts_count: u64,
    source_codes: *const Source,
) !Source {
    var source = source_codes.*;
    const accounts = try arena.alloc(Account, accounts_count);
    for (accounts, 0..) |*account, index| {
        const previous = if (index > 0) &accounts[index - 1].key else null;
        account.* = .{
            .key = random_key(prng, previous),
            .nonce = prng.below(1000),
            .balance = if (prng.chance(1, 5)) prng.int(u256) else prng.int(u64),
            .code_hash = node.empty_code_hash,
            .slots = try random_slots(arena, prng),
        };
        if (prng.chance(1, 3)) {
            const code = source.codes[@intCast(prng.below(source.codes.len))];
            account.code_hash = node.keccak256(code);
        }
    }
    std.mem.sort(Account, accounts, {}, less_account);
    // Random keys never repeat in practice; a repeat would make the stream unordered.
    for (accounts[1..], accounts[0 .. accounts.len - 1]) |b, a| {
        assert(std.mem.order(u8, &a.key, &b.key) == .lt);
    }
    try encode_tables(arena, accounts, &source);
    return source;
}

pub fn encode_tables(arena: std.mem.Allocator, accounts: []Account, source: *Source) !void {
    var account_entries: std.ArrayList(Entry) = .empty;
    var storage_entries: std.ArrayList(Entry) = .empty;
    for (accounts) |*account| {
        const key = try arena.dupe(u8, &account.key);
        try account_entries.append(arena, .{
            .key = key,
            .value = try encode_account(arena, account),
        });
        for (account.slots) |slot| {
            const value = try arena.alloc(u8, 64);
            @memcpy(value[0..32], &slot.hash);
            const tail = trimmed(value[32..], slot.word);
            try storage_entries.append(arena, .{ .key = key, .value = value[0 .. 32 + tail.len] });
        }
    }
    source.accounts = accounts;
    source.account_entries = account_entries.items;
    source.storage_entries = storage_entries.items;
    // The root, computed by a plain streaming pass.
    var accounts_source: SliceEntries = .{ .entries = source.account_entries };
    var storages_source: SliceEntries = .{ .entries = source.storage_entries };
    const builder = try arena.create(state_root.StateRootBuilder);
    builder.* = .{};
    source.root = try hashed_state.compute(
        builder,
        accounts_source.source(),
        storages_source.source(),
        null,
        null,
    );
}

// The database under test.

pub const Run = struct {
    sim: *SimStorage,
    db: *Database,
    config: @import("../db/database.zig").Config,

    pub fn init(source: *const Source, seed: u64) !Run {
        return init_shaped(source, seed, shape_test);
    }

    pub fn init_shaped(source: *const Source, seed: u64, shape: to_disk.Shape) !Run {
        const sizing = try to_disk.sizing(SimStorage, source.counts(), shape);
        const sim = try testing.allocator.create(SimStorage);
        errdefer testing.allocator.destroy(sim);
        sim.* = try SimStorage.init(testing.allocator, .{
            .size_bytes = sizing.config.engine.size_bytes(),
            .seed = seed,
        });
        errdefer sim.deinit(testing.allocator);
        const db = try testing.allocator.create(Database);
        errdefer testing.allocator.destroy(db);
        db.* = try Database.init(testing.allocator, sim, sizing.config);
        return .{ .sim = sim, .db = db, .config = sizing.config };
    }

    pub fn deinit(self: *Run) void {
        self.db.deinit(testing.allocator);
        testing.allocator.destroy(self.db);
        self.sim.deinit(testing.allocator);
        testing.allocator.destroy(self.sim);
    }

    pub fn driver(self: *Run) to_disk.Driver {
        return .{ .context = self.sim, .tick = tick };
    }

    fn tick(context: *anyopaque) void {
        const sim: *SimStorage = @ptrCast(@alignCast(context));
        sim.tick();
    }

    pub fn importer(self: *Run) Importer {
        return .{ .allocator = testing.allocator, .db = self.db, .driver = self.driver() };
    }

    pub fn reopen(self: *Run) !void {
        self.db.deinit(testing.allocator);
        self.db.* = try Database.init(testing.allocator, self.sim, self.config);
        try Importer.open(self.db, self.driver());
    }
};

const Sources = struct {
    codes: SliceEntries,
    accounts: SliceEntries,
    storages: SliceEntries,

    fn of(source: *const Source) Sources {
        return .{
            .codes = .{ .entries = source.code_entries },
            .accounts = .{ .entries = source.account_entries },
            .storages = .{ .entries = source.storage_entries },
        };
    }
};

pub fn import_into(
    importer: *Importer,
    source: *const Source,
    chain: *const to_disk.HeaderChain,
) !Hash {
    var sources: Sources = .of(source);
    return importer.run(
        0x1e90_0010,
        sources.codes.source(),
        sources.accounts.source(),
        sources.storages.source(),
        chain,
    );
}

pub fn synthetic_chain(root: Hash, chain: *to_disk.HeaderChain) !void {
    var headers: to_disk.SyntheticHeaders = .{ .head_number = head_number, .state_root = root };
    try to_disk.fetch_chain(headers.source(), head_number, chain);
}

// Checks.

fn check_head(db: *Database, source: *const Source) !void {
    try testing.expect(db.head_info.present);
    try testing.expectEqual(head_number, db.head_info.number);
    const head_hash = to_disk.SyntheticHeaders.hash_of(head_number);
    try testing.expectEqualSlices(u8, &head_hash, &db.head_info.hash);
    try testing.expectEqualSlices(u8, &source.root, &db.head_info.state_root);
    try testing.expectEqual(@as(u32, 0), db.chain.block_count());
    for (0..to_disk.block_hashes_max) |offset| {
        const number = head_number - offset;
        const hash = db.state.block_hash(number) orelse return error.MissingBlockHash;
        try testing.expectEqualSlices(u8, &to_disk.SyntheticHeaders.hash_of(number), &hash);
    }
    try testing.expect(db.state.block_hash(head_number - to_disk.block_hashes_max) == null);
    for (source.codes) |code| {
        const stored = db.state.code_by_hash(node.keccak256(code)) orelse return error.NoCode;
        try testing.expectEqualSlices(u8, code, stored);
    }
}

/// Every account and slot through the trie from the root, and from the flat trees.
fn check_state(db: *Database, source: *const Source, prng: *Prng) !void {
    const disk = &db.disk.?;
    for (source.accounts) |*account| {
        const leaf = try disk.verify_leaf(&account.key, null);
        const read = leaf.account orelse return error.MissingAccount;
        try testing.expectEqual(account.nonce, read.nonce);
        try testing.expectEqual(account.balance, read.balance);
        try testing.expectEqualSlices(u8, &account.code_hash, &read.code_hash);
        const record = disk.account(&account.key) orelse return error.MissingAccount;
        try testing.expectEqualSlices(u8, &read.storage_root, &record.storage_root);
        const empty = std.mem.eql(u8, &read.storage_root, &node.empty_root);
        try testing.expectEqual(account.slots.len == 0, empty);
        for (account.slots) |*slot| {
            const slot_leaf = try disk.verify_leaf(&account.key, &slot.hash);
            try testing.expectEqual(slot.word, slot_leaf.word);
            try testing.expectEqual(slot.word, disk.storage(&account.key, &slot.hash));
        }
    }
    // Absent keys read absent (proofs of absence through the records).
    for (0..8) |_| {
        var key: Hash = undefined;
        prng.fill(&key);
        const leaf = try disk.verify_leaf(&key, null);
        try testing.expect(leaf.account == null);
    }
}

test "to_disk: a random reth state imports, reopens as head N with its root and every leaf" {
    for (0..4) |seed| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var prng = Prng.init(0x7464_0000 + seed);
        const source = try random_source(arena, &prng, 30 + 70 * seed);
        var run = try Run.init(&source, seed);
        defer run.deinit();
        var importer = run.importer();
        var chain: to_disk.HeaderChain = .{};
        try synthetic_chain(source.root, &chain);
        const root = try import_into(&importer, &source, &chain);
        try testing.expectEqualSlices(u8, &source.root, &root);
        const counts = source.counts();
        try testing.expectEqual(counts.accounts, importer.stats.accounts);
        try testing.expectEqual(counts.slots, importer.stats.slots);
        // Every code but the empty one is stored, and a reopen loads exactly those.
        try testing.expectEqual(counts.codes - 1, importer.stats.codes);
        try testing.expect(importer.stats.account_records > 0);
        try testing.expect(importer.stats.blocks_written > 0);
        try run.reopen();
        try testing.expectEqual(importer.stats.codes, run.db.state.code_table.count());
        try check_head(run.db, &source);
        try check_state(run.db, &source, &prng);
        try Importer.verify_samples(run.db, &importer.samples);
        const sampled = importer.samples.account_list().len;
        try testing.expectEqual(@min(counts.accounts, to_disk.samples_max), sampled);
    }
}

fn failed_import(
    source: *const Source,
    mutation: ?to_disk.Mutation,
    seed: u64,
    expected: anyerror,
) !void {
    var run = try Run.init(source, seed);
    defer run.deinit();
    var importer = run.importer();
    importer.mutation = mutation;
    var chain: to_disk.HeaderChain = .{};
    try synthetic_chain(source.root, &chain);
    _ = import_into(&importer, source, &chain) catch |err| {
        try testing.expect(!run.db.head_info.present);
        if (err != expected) return err;
        return;
    };
    return error.TestUnexpectedSuccess;
}

test "to_disk: a dropped account root record is refused by import_head" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var prng = Prng.init(0x7464_0100);
    const source = try random_source(arena_state.allocator(), &prng, 60);
    try failed_import(&source, .drop_account_root, 1, error.StateCorrupt);
}

test "to_disk: a dropped storage record opens but its slots do not resolve" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var prng = Prng.init(0x7464_0200);
    const source = try random_source(arena_state.allocator(), &prng, 80);
    var corrupt_total: u32 = 0;
    for (0..3) |round| {
        var run = try Run.init(&source, 2 + round);
        defer run.deinit();
        var importer = run.importer();
        var chain: to_disk.HeaderChain = .{};
        try synthetic_chain(source.root, &chain);
        // The record count, from a clean import of the same state.
        if (round == 0) {
            _ = try import_into(&importer, &source, &chain);
            try testing.expect(importer.stats.storage_records > 3);
            continue;
        }
        importer.mutation = .{ .drop_storage_record = prng.below(40) };
        _ = try import_into(&importer, &source, &chain);
        try run.reopen();
        var corrupt: u32 = 0;
        const disk = &run.db.disk.?;
        for (source.accounts) |*account| {
            for (account.slots) |*slot| {
                _ = disk.verify_leaf(&account.key, &slot.hash) catch |err| {
                    try testing.expect(err == error.Corrupt);
                    corrupt += 1;
                };
            }
        }
        try testing.expect(corrupt > 0);
        corrupt_total += corrupt;
    }
    try testing.expect(corrupt_total >= 2);
}

test "to_disk: a wrong header root, a broken chain, and bad codes are refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = Prng.init(0x7464_0300);
    var source = try random_source(arena, &prng, 40);
    // Header N names another root: refused before the head is made.
    {
        var run = try Run.init(&source, 5);
        defer run.deinit();
        var importer = run.importer();
        var wrong = source.root;
        wrong[0] ^= 1;
        var chain: to_disk.HeaderChain = .{};
        try synthetic_chain(wrong, &chain);
        try testing.expectError(error.StateRootMismatch, import_into(&importer, &source, &chain));
        try testing.expect(!run.db.head_info.present);
    }
    try check_chain_links();
    // A code under another key.
    const codes = source.code_entries;
    const key = try arena.dupe(u8, codes[0].key);
    key[31] ^= 1;
    const swapped = codes[0].key;
    codes[0].key = key;
    try failed_import(&source, null, 6, error.CodeHashMismatch);
    codes[0].key = swapped;
    // An account whose code is not in `Bytecodes`.
    source.accounts[0].code_hash = node.keccak256("no such code");
    try encode_tables(arena, source.accounts, &source);
    try failed_import(&source, null, 7, error.CodeMissing);
}

/// A source that damages one link: a wrong parent hash, or a wrong number.
const DamagedHeaders = struct {
    inner: to_disk.SyntheticHeaders,
    damaged: u64,
    wrong_number: bool,

    fn source(self: *DamagedHeaders) to_disk.HeaderSource {
        return .{ .context = self, .fetch = fetch };
    }

    fn fetch(context: *anyopaque, number: u64) anyerror!to_disk.HeaderLink {
        const self: *DamagedHeaders = @ptrCast(@alignCast(context));
        var link = try self.inner.source().fetch(&self.inner, number);
        if (number == self.damaged) {
            if (self.wrong_number) link.number += 1 else link.parent_hash[5] ^= 0x40;
        }
        return link;
    }
};

fn check_chain_links() !void {
    var chain: to_disk.HeaderChain = .{};
    for ([_]bool{ false, true }) |wrong_number| {
        var headers: DamagedHeaders = .{
            .inner = .{ .head_number = head_number, .state_root = @splat(1) },
            .damaged = head_number - 7,
            .wrong_number = wrong_number,
        };
        const result = to_disk.fetch_chain(headers.source(), head_number, &chain);
        const expected: anyerror = if (wrong_number) error.WrongBlock else error.BrokenChain;
        try testing.expectError(expected, result);
    }
    // A chain near genesis holds every block down to 0.
    var headers: to_disk.SyntheticHeaders = .{ .head_number = 10, .state_root = @splat(1) };
    try to_disk.fetch_chain(headers.source(), 10, &chain);
    try testing.expectEqual(@as(u32, 11), chain.len);
    try testing.expectEqual(@as(u64, 0), chain.links[10].number);
}

test "to_disk: sizing at Base Sepolia scale" {
    const counts: to_disk.Counts = .{
        .accounts = 300_000_000,
        .slots = 2_000_000_000,
        .codes = 3_000_000,
        .code_bytes = 3 << 30,
    };
    const sizing = try to_disk.sizing(SimStorage, counts, to_disk.shape_node_v2);
    const config = sizing.config;
    try testing.expect(config.engine.grid_block_count > sizing.tree_blocks + sizing.code_blocks);
    // Each tree's layout holds its keys (`layout_of` asserts inside `sizing`).
    try testing.expect(config.flat_slots_max.? >= counts.slots);
    try testing.expect(config.flat_storage_branches_max.? >= counts.slots / 2);
    try testing.expect(config.code_tables_max >= 16);
    try testing.expect(config.checkpoint_staging_bytes > 1 << 20);
    try testing.expect(config.engine.checkpoint_zone_size_bytes >=
        config.checkpoint_staging_bytes);
    try testing.expect(config.disk_state_config() != null);
    // The tree estimate: above the leaves alone (key, value, offset), below three times them
    // (branch records add ~0.4 x 270 B per leaf).
    const tree_bytes = sizing.tree_blocks * config.engine.checkpoint_block_size;
    const leaf_bytes = counts.accounts * (32 + 104 + 4) + counts.slots * (64 + 32 + 4);
    try testing.expect(tree_bytes > leaf_bytes and tree_bytes < 3 * leaf_bytes);
    // Base Sepolia at block 55006660 (measured): 22 GiB of code, past u32 arena offsets.
    var large = counts;
    large.codes = 4_765_573;
    large.code_bytes = 23_171_111_820;
    const sized = try to_disk.sizing(SimStorage, large, to_disk.shape_node_v2);
    try testing.expect(sized.config.state.code_bytes_max >= large.code_bytes);
    try testing.expect(sized.config.state.codes_max >= large.codes);
    try testing.expect(sized.code_blocks * config.engine.checkpoint_block_size >
        4 * large.code_bytes);
    var too_many = counts;
    too_many.codes = std.math.maxInt(u32);
    const refused = to_disk.sizing(SimStorage, too_many, to_disk.shape_node_v2);
    try testing.expectError(error.CodesTooLarge, refused);
}

/// Tracks the live allocations of at least `bytes_min` for the residency guard below.
const LargeAllocations = struct {
    const bytes_min = 1 << 20;
    const count_max = 1024;

    backing: std.mem.Allocator,
    addresses: [count_max]usize = undefined,
    lengths: [count_max]usize = undefined,
    count: u32 = 0,

    fn allocator(self: *LargeAllocations) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *LargeAllocations = @ptrCast(@alignCast(context));
        const memory = self.backing.rawAlloc(len, alignment, ret) orelse return null;
        if (len >= bytes_min) {
            assert(self.count < count_max);
            self.addresses[self.count] = @intFromPtr(memory);
            self.lengths[self.count] = len;
            self.count += 1;
        }
        return memory;
    }

    /// Tracked allocations never change size (the startup buffers do not).
    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        len: usize,
        ret: usize,
    ) bool {
        const self: *LargeAllocations = @ptrCast(@alignCast(context));
        if (memory.len >= bytes_min or len >= bytes_min) return false;
        return self.backing.rawResize(memory, alignment, len, ret);
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        len: usize,
        ret: usize,
    ) ?[*]u8 {
        const self: *LargeAllocations = @ptrCast(@alignCast(context));
        if (memory.len >= bytes_min or len >= bytes_min) return null;
        return self.backing.rawRemap(memory, alignment, len, ret);
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *LargeAllocations = @ptrCast(@alignCast(context));
        if (memory.len >= bytes_min) {
            const index = std.mem.indexOfScalar(
                usize,
                self.addresses[0..self.count],
                @intFromPtr(memory.ptr),
            ).?;
            assert(self.lengths[index] == memory.len);
            self.count -= 1;
            self.addresses[index] = self.addresses[self.count];
            self.lengths[index] = self.lengths[self.count];
        }
        self.backing.rawFree(memory, alignment, ret);
    }

    fn virtual_bytes(self: *const LargeAllocations) u64 {
        var total: u64 = 0;
        for (self.lengths[0..self.count]) |len| total += len;
        return total;
    }

    /// The resident bytes of the tracked allocations (`mincore`, page granularity).
    fn resident_bytes(self: *const LargeAllocations) u64 {
        const page_size = std.heap.pageSize();
        var vector: [4096]u8 = undefined;
        var total: u64 = 0;
        for (self.addresses[0..self.count], self.lengths[0..self.count]) |address, len| {
            // Large allocations come straight from the page allocator: page-aligned.
            assert(address % page_size == 0);
            const end = address + std.mem.alignForward(usize, len, page_size);
            var at = address;
            while (at < end) {
                const pages = @min((end - at) / page_size, vector.len);
                const result = std.os.linux.mincore(@ptrFromInt(at), pages * page_size, &vector);
                assert(std.os.linux.errno(result) == .SUCCESS);
                for (vector[0..pages]) |flags| total += @as(u64, flags & 1) * page_size;
                at += pages * page_size;
            }
        }
        assert(total <= self.virtual_bytes() + self.count * page_size);
        return total;
    }
};

// Regression guard: in Debug and ReleaseSafe, `Allocator.alloc` fills every allocation (0xAA),
// which made every byte of the node's upper-bound buffers resident (the Base Sepolia node held
// ~55 GB). The node shape at 1/100 of Base Sepolia's counts reserves ~12 GiB; a fresh
// database must keep nearly all of it unresident (`lazy.alloc`). What stays resident is the
// hash maps (`std` fills them) and the buffers init writes.
test "to_disk: node sizing reserves its buffers without making them resident" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // 1/1000 of Base Sepolia's counts: the storage this test reserves is the whole file, one
    // mapping, and heuristic overcommit refuses one larger than a small host's RAM. The node's
    // code growth (8 GiB of arena) is reduced for the same reason; laziness does not depend on
    // either size, and the buffers sized from the shape alone (the 4 GiB block cache) stay.
    const counts: to_disk.Counts = .{
        .accounts = 37_612,
        .slots = 3_720_592,
        .codes = 4_766,
        .code_bytes = 23_171_112,
    };
    var shape = to_disk.shape_node_v2;
    shape.code_bytes_growth = 256 << 20;
    shape.codes_growth = 1 << 16;
    const sizing = try to_disk.sizing(SimStorage, counts, shape);
    // `Database.init` only checks the storage's size; nothing reads or writes it.
    // A host that refuses the reservation outright (overcommit) cannot run this check.
    const disk = lazy.alloc(testing.allocator, u8, sizing.config.engine.size_bytes()) catch
        return error.SkipZigTest;
    defer lazy.free(testing.allocator, disk);
    var sim: SimStorage = undefined;
    sim.durable = disk;
    sim.memory = disk;
    var large: LargeAllocations = .{ .backing = testing.allocator };
    const allocator = large.allocator();
    const db = try testing.allocator.create(Database);
    defer testing.allocator.destroy(db);
    db.* = try Database.init(allocator, &sim, sizing.config);
    defer db.deinit(allocator);
    const virtual = large.virtual_bytes();
    const resident = large.resident_bytes();
    try testing.expect(virtual > 8 << 30);
    try testing.expect(resident < 768 << 20);
}

test "to_disk: counts round-trip; damaged encodings are refused (seeded)" {
    var prng = Prng.init(0x7464_0400);
    for (0..2000) |_| {
        const counts: to_disk.Counts = .{
            .accounts = prng.below(to_disk.Counts.count_max + 1),
            .slots = prng.below(to_disk.Counts.count_max + 1),
            .codes = prng.below(to_disk.Counts.count_max + 1),
            .code_bytes = prng.below(to_disk.Counts.count_max + 1),
            .shape = if (prng.chance(1, 2)) .v1 else .v2,
        };
        var bytes = counts.encode();
        try testing.expectEqual(counts, try to_disk.Counts.decode(&bytes));
        bytes[prng.below(bytes.len)] ^= @intCast(prng.range(1, 255));
        if (to_disk.Counts.decode(&bytes)) |decoded| {
            try testing.expect(!std.meta.eql(decoded, counts));
        } else |_| {}
        try testing.expectError(error.InvalidCounts, to_disk.Counts.decode(bytes[0..39]));
    }
}

test "to_disk: fuzz counts decode" {
    try testing.fuzz({}, fuzz_counts, .{});
}

fn fuzz_counts(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [64]u8 = undefined;
    const length = smith.slice(&bytes);
    const counts = to_disk.Counts.decode(bytes[0..length]) catch return;
    try testing.expectEqualSlices(u8, bytes[0..length], &counts.encode());
}

// Code growth (`Shape.codes_growth`): RAM limits past the format's code headroom.

test "to_disk: code growth leaves a Base Sepolia sized file's format unchanged" {
    const counts: to_disk.Counts = .{
        .accounts = 37_612_478,
        .slots = 3_720_591_921,
        .codes = 4_765_573,
        .code_bytes = 23_171_111_820,
    };
    var shape_format = to_disk.shape_node_v1;
    shape_format.codes_growth = 0;
    shape_format.code_bytes_growth = 0;
    const format = (try to_disk.sizing(SimStorage, counts, shape_format)).config;
    const grown = (try to_disk.sizing(SimStorage, counts, to_disk.shape_node_v1)).config;
    // The superblock layout of the Base Sepolia node's file (before code growth existed),
    // checked byte for byte at open (`LayoutMismatch`), and what its checkpoints encode.
    const layout = grown.engine.layout();
    try testing.expectEqual(@as(u64, 2_543_648_768), layout.checkpoint_zone_size_bytes);
    try testing.expectEqual(@as(u64, 64 << 20), layout.journal_size_bytes);
    try testing.expectEqual(@as(u32, 64 * 1024), layout.checkpoint_block_size);
    try testing.expectEqual(@as(u32, 2 << 20), layout.entry_body_size_max);
    try testing.expectEqual(@as(u64, 19_802_124), layout.grid_block_count);
    try testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&format.engine.layout()),
        std.mem.asBytes(&layout),
    );
    // Base Sepolia's counts record ("nfsize01") names v1, which sizes that same layout.
    var record = counts.encode();
    @memcpy(record[0..8], "nfsize01");
    const sidecar = try to_disk.Counts.decode(&record);
    try testing.expectEqual(to_disk.ShapeVersion.v1, sidecar.shape);
    const opened = (try to_disk.sizing(SimStorage, sidecar, to_disk.node_shape(sidecar))).config;
    try testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&opened.engine.layout()),
        std.mem.asBytes(&layout),
    );
    try testing.expectEqual(grown.checkpoint_staging_bytes, opened.checkpoint_staging_bytes);
    try testing.expectEqual(@as(u32, 1408), grown.code_tables_max);
    try testing.expectEqual(format.code_tables_max, grown.code_tables_max);
    try testing.expectEqual(@as(u32, 2_533_551_498), grown.checkpoint_staging_bytes);
    try testing.expectEqual(format.checkpoint_staging_bytes, grown.checkpoint_staging_bytes);
    // The format's code limits, then the state's: the whole growth fits.
    try testing.expectEqual(@as(u32, 4_831_109), format.state.codes_max);
    try testing.expectEqual(@as(u64, 23_238_220_684), format.state.code_bytes_max);
    try testing.expectEqual(format.state.codes_max + (1 << 23), grown.state.codes_max);
    try testing.expectEqual(format.state.code_bytes_max + (8 << 30), grown.state.code_bytes_max);
    const needed = Database.CodeStore.tables_needed(
        grown.engine.checkpoint_block_size,
        grown.state.codes_max,
        grown.state.code_bytes_max,
    );
    try testing.expect(4 * needed <= 3 * grown.code_tables_max);
}

test "to_disk: code growth is halved until every code fits three quarters of the list" {
    var prng = Prng.init(0x7464_0500);
    for (0..200) |_| {
        const codes = prng.range(1, 1 << 20);
        const counts: to_disk.Counts = .{
            .accounts = prng.range(1, 1 << 24),
            .slots = prng.range(1, 1 << 28),
            .codes = codes,
            .code_bytes = codes * prng.range(1, 24_576),
        };
        var shape = to_disk.shape_node_v2;
        shape.codes_growth = @intCast(prng.range(0, 1 << 24));
        shape.code_bytes_growth = prng.range(0, 64 << 30);
        var shape_format = shape;
        shape_format.codes_growth = 0;
        shape_format.code_bytes_growth = 0;
        const format = (try to_disk.sizing(SimStorage, counts, shape_format)).config;
        const grown = (try to_disk.sizing(SimStorage, counts, shape)).config;
        try testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&format.engine.layout()),
            std.mem.asBytes(&grown.engine.layout()),
        );
        try testing.expectEqual(format.code_tables_max, grown.code_tables_max);
        try testing.expectEqual(format.checkpoint_staging_bytes, grown.checkpoint_staging_bytes);
        try testing.expect(grown.state.codes_max >= format.state.codes_max);
        try testing.expect(grown.state.code_bytes_max >= format.state.code_bytes_max);
        try testing.expect(grown.state.codes_max - format.state.codes_max <= shape.codes_growth);
        try testing.expect(grown.state.code_bytes_max - format.state.code_bytes_max <=
            shape.code_bytes_growth);
        const needed = Database.CodeStore.tables_needed(
            grown.engine.checkpoint_block_size,
            grown.state.codes_max,
            grown.state.code_bytes_max,
        );
        try testing.expect(4 * needed <= 3 * grown.code_tables_max);
    }
}

const growth_ticks_max = 1_000_000;

fn growth_settled(db: *const Database) bool {
    return !db.checkpoint_wanted and db.engine.checkpoint_phase == .idle and db.idle();
}

/// Commits one block per code (the shape's changesets hold one), each a fresh code of
/// `length` bytes, onto the head; returns `error.CodeFull` from the state when refused.
fn commit_codes(run: *Run, prng: *Prng, hashes: []Hash, length: u32) !void {
    const db = run.db;
    var overlay = try @import("../db/overlay.zig").Overlay.init(testing.allocator, &db.state, .{
        .accounts_max = 4,
        .slots_max = 4,
        .codes_max = 1,
    });
    defer overlay.deinit(testing.allocator);
    var code: [1024]u8 = undefined;
    for (hashes) |*hash| {
        prng.fill(code[0..length]);
        hash.* = try overlay.insert_code(code[0..length]);
        var block_hash: Hash = undefined;
        prng.fill(&block_hash);
        const input: @import("../db/database.zig").BlockInput = .{
            .hash = block_hash,
            .parent_hash = db.head_info.hash,
            .number = db.head_info.number + 1,
            .timestamp = (db.head_info.number + 1) * 2,
            .header = &block_hash,
            .body = "body",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
        var ticks: u32 = 0;
        while (true) : (ticks += 1) {
            if (ticks >= growth_ticks_max) return error.Timeout;
            _ = db.execute_and_commit(&overlay, &input) catch |err| switch (err) {
                error.Busy => {
                    run.sim.tick();
                    continue;
                },
                else => return err,
            };
            break;
        }
    }
    var ticks: u32 = 0;
    while (!db.idle()) : (ticks += 1) {
        if (ticks >= growth_ticks_max) return error.Timeout;
        run.sim.tick();
    }
}

fn checkpoint_settled(run: *Run) !void {
    run.db.request_checkpoint();
    var ticks: u32 = 0;
    while (!growth_settled(run.db)) : (ticks += 1) {
        if (ticks >= growth_ticks_max) return error.Timeout;
        run.db.checkpoint_flush();
        run.sim.tick();
    }
    if (run.db.checkpoint_error) |err| return err;
}

/// Imports `source` sized with the format's code headroom only (as files were before code
/// growth), then reopens the file with `shape`.
fn growth_run(source: *const Source, shape: to_disk.Shape) !Run {
    var shape_format = shape;
    shape_format.codes_growth = 0;
    shape_format.code_bytes_growth = 0;
    var run = try Run.init_shaped(source, 0x7464_0600, shape_format);
    errdefer run.deinit();
    var importer = run.importer();
    var chain: to_disk.HeaderChain = .{};
    try synthetic_chain(source.root, &chain);
    _ = try import_into(&importer, source, &chain);
    const grown = try to_disk.sizing(SimStorage, source.counts(), shape);
    try testing.expectEqualSlices(
        u8,
        std.mem.asBytes(&run.config.engine.layout()),
        std.mem.asBytes(&grown.config.engine.layout()),
    );
    run.config = grown.config;
    try run.reopen();
    return run;
}

test "to_disk: a file sized before code growth reopens with it and takes more new codes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var prng = Prng.init(0x7464_0700);
    const source = try random_source(arena_state.allocator(), &prng, 40);
    const shape: to_disk.Shape = comptime blk: {
        var shape = shape_test;
        shape.codes_growth = 64;
        shape.code_bytes_growth = 64 * 1024;
        break :blk shape;
    };
    // Three times the format's headroom of codes, and of code bytes.
    const codes_new = 3 * shape.codes_headroom;
    const length = 3 * shape.code_bytes_headroom / codes_new;
    var hashes: [codes_new]Hash = undefined;
    var codes: [codes_new][]const u8 = undefined;
    {
        // Control: the format's limits alone refuse a new code within the headroom.
        var shape_format = shape;
        shape_format.codes_growth = 0;
        shape_format.code_bytes_growth = 0;
        var run = try growth_run(&source, shape_format);
        defer run.deinit();
        try testing.expectError(error.CodeFull, commit_codes(&run, &prng, &hashes, length));
    }
    var run = try growth_run(&source, shape);
    defer run.deinit();
    const half = codes_new / 2;
    try commit_codes(&run, &prng, hashes[0..half], length);
    try checkpoint_settled(&run);
    try commit_codes(&run, &prng, hashes[half..], length);
    const head = run.db.head_info;
    for (&hashes, &codes) |*hash, *code| {
        code.* = try arena_state.allocator().dupe(u8, run.db.state.code_by_hash(hash.*).?);
    }
    run.db.codes_release();
    // The first half from their tables, the rest replayed from the journal.
    try run.reopen();
    try testing.expectEqualSlices(u8, std.mem.asBytes(&head), std.mem.asBytes(&run.db.head_info));
    try testing.expect(run.db.state.codes_in_tables > 0);
    for (&hashes, &codes) |*hash, code| {
        const read = run.db.state.code_by_hash(hash.*) orelse return error.NoCode;
        try testing.expectEqualSlices(u8, code, read);
        try testing.expectEqualSlices(u8, &hash.*, &node.keccak256(read));
    }
    run.db.codes_release();
    try testing.expectEqual(head_number + codes_new, run.db.head_info.number);
    for (source.codes) |code| {
        const stored = run.db.state.code_by_hash(node.keccak256(code)) orelse return error.NoCode;
        try testing.expectEqualSlices(u8, code, stored);
        run.db.codes_release();
    }
}

// Codes out of RAM during the import (`ImporterType.code_batch_bytes`).

/// Imports a source of many codes (two too long for a table) in batches of `batch_bytes`.
fn import_batched(source: *const Source, batch_bytes: u64) !Run {
    var run = try Run.init(source, 0x7464_0800);
    errdefer run.deinit();
    var importer = run.importer();
    importer.code_batch_bytes = batch_bytes;
    var chain: to_disk.HeaderChain = .{};
    try synthetic_chain(source.root, &chain);
    const root = try import_into(&importer, source, &chain);
    try testing.expectEqualSlices(u8, &source.root, &root);
    try testing.expectEqual(source.codes.len - 1, importer.stats.codes);
    const state = &run.db.state;
    // Every code but the long ones (and a last remainder below the flush minimum) left the
    // arena for a table, batch by batch.
    var long_bytes: u64 = 0;
    for (source.codes) |code| {
        if (code.len > table_value_max) long_bytes += code.len;
    }
    try testing.expect(importer.stats.code_evictions >= 3);
    try testing.expect(state.code_arena_len >= long_bytes);
    try testing.expect(state.code_arena_len < long_bytes + shape_test.code_flush_bytes_min);
    try testing.expect(state.codes_in_tables + 2 <= importer.stats.codes);
    try testing.expect(state.codes_in_tables + 2 + 64 >= importer.stats.codes);
    try check_codes(run.db, source);
    return run;
}

/// Every code reads back, byte for byte, one pin at a time.
fn check_codes(db: *Database, source: *const Source) !void {
    for (source.codes[1..]) |code| {
        db.codes_release();
        const stored = db.state.code_by_hash(node.keccak256(code)) orelse return error.NoCode;
        try testing.expectEqualSlices(u8, code, stored);
    }
    db.codes_release();
}

test "to_disk: codes stream through the arena into tables in batches, and reopen" {
    for (0..3) |seed| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var prng = Prng.init(0x7464_0900 + seed);
        var codes: Source = undefined;
        try random_codes_shaped(arena, &prng, &codes, .{
            .count_min = 300,
            .count_max = 500,
            .length_max = 1500,
            .long = 2,
        });
        const source = try random_accounts(arena, &prng, 60, &codes);
        var run = try import_batched(&source, 64 * 1024);
        defer run.deinit();
        try run.reopen();
        try testing.expectEqual(source.codes.len - 1, run.db.state.code_table.count());
        try check_codes(run.db, &source);
        try testing.expectEqualSlices(u8, &source.root, &run.db.head_info.state_root);
        try check_state(run.db, &source, &prng);
    }
}

test "to_disk: a batch the arena cannot drain is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var prng = Prng.init(0x7464_0a00);
    var codes: Source = undefined;
    try random_codes_shaped(arena, &prng, &codes, .{
        .count_min = 40,
        .count_max = 41,
        .length_max = 1000,
        .long = 2,
    });
    const source = try random_accounts(arena, &prng, 20, &codes);
    // Two long codes stay in the arena: more than half of a 16 KiB batch.
    var run = try Run.init(&source, 0x7464_0a01);
    defer run.deinit();
    var importer = run.importer();
    importer.code_batch_bytes = 16 * 1024;
    var chain: to_disk.HeaderChain = .{};
    try synthetic_chain(source.root, &chain);
    try testing.expectError(error.CodesNotEvicted, import_into(&importer, &source, &chain));
}

// The node's shapes (`to_disk.node_shape`).

test "to_disk: new imports take shape v2; its per-block bounds hold a 160M gas block" {
    // Base mainnet's estimate: 2.6x Base Sepolia's counts.
    const counts: to_disk.Counts = .{
        .accounts = 37_612_478 * 26 / 10,
        .slots = 3_720_591_921 * 26 / 10,
        .codes = 4_765_573 * 26 / 10,
        .code_bytes = 23_171_111_820 * 26 / 10,
    };
    try testing.expectEqual(to_disk.ShapeVersion.v2, counts.shape);
    const bytes = counts.encode();
    try testing.expectEqualSlices(u8, "nfsize02", bytes[0..8]);
    const shape = to_disk.node_shape(counts);
    try testing.expectEqual(to_disk.shape_node_v2.entry_body_size_max, shape.entry_body_size_max);
    const config = (try to_disk.sizing(SimStorage, counts, shape)).config;
    const v1 = (try to_disk.sizing(SimStorage, counts, to_disk.shape_node_v1)).config;
    // The trees and the grid are sized by the counts alone.
    try testing.expectEqual(v1.engine.grid_block_count, config.engine.grid_block_count);
    try testing.expect(config.engine.checkpoint_zone_size_bytes >=
        v1.engine.checkpoint_zone_size_bytes);
    // A 160M gas block: at least 4,000 gas per changed slot and 7,600 per changed account,
    // 116 and 165 changeset bytes each: its changeset (slots are the densest) fits an entry.
    const gas: u64 = 160_000_000;
    const changeset_bytes = gas / 4_000 * 116;
    try testing.expect(changeset_bytes + 64 * 1024 < config.engine.entry_body_size_max);
    try testing.expect(v1.engine.entry_body_size_max < changeset_bytes);
    // A scattered 40M gas block: ~10k slots, ~4 branch records each.
    const writes: u64 = 40_000_000 / 4_000 * 4;
    try testing.expect(writes <= config.disk_state.?.record_writes_max);
    try testing.expect(writes > v1.disk_state.?.record_writes_max);
    // The journal holds several of the largest entries; the chain ring a reorg's blocks.
    try testing.expect(config.engine.journal_size_bytes >= 4 * config.engine.entry_body_size_max);
    try testing.expect(config.chain_bytes_capacity() >=
        (config.chain.reorg_depth_max + 1) * config.engine.entry_body_size_max);
    // Both shapes size a database that initializes (every layout assert holds).
    for ([_]to_disk.Shape{ to_disk.shape_node_v1, to_disk.shape_node_v2 }) |node_shape| {
        const small: to_disk.Counts = .{
            .accounts = 1 << 16,
            .slots = 1 << 20,
            .codes = 1 << 10,
            .code_bytes = 1 << 24,
        };
        const sized = (try to_disk.sizing(SimStorage, small, node_shape)).config;
        const disk = try lazy.alloc(testing.allocator, u8, sized.engine.size_bytes());
        defer lazy.free(testing.allocator, disk);
        var sim: SimStorage = undefined;
        sim.durable = disk;
        sim.memory = disk;
        const db = try testing.allocator.create(Database);
        defer testing.allocator.destroy(db);
        db.* = try Database.init(testing.allocator, &sim, sized);
        db.deinit(testing.allocator);
    }
}

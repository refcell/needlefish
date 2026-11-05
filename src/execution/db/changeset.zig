//! Block changeset: every account and storage change of one block, with old and new values.
//!
//! A changeset applies forward (commit a block) or backward (unwind a block on reorg), and it
//! is the unit written to the journal. Storage wipes (self-destruct, account deletion) are
//! spelled out as one entry per cleared slot, so applying a changeset never needs to scan.
//! Entries are kept sorted (accounts by address, slots by address then slot), which makes the
//! encoding canonical: one changeset, one byte string.
//!
//! Encoding (little-endian integers, big-endian u256 words):
//!   magic u32, version u16, account_count u32, storage_count u32, code_count u32,
//!   accounts: address[20], flags u8 (1 = old present, 2 = new present), then each present
//!     side as nonce u64, balance [32], code_hash [32];
//!   storage: address[20], slot[32], old[32], new[32];
//!   codes: length u32, bytes (their hashes are recomputed on decode).

const std = @import("std");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const assert = std.debug.assert;

const keccak256 = @import("../trie/node.zig").keccak256;

pub const Address = [20]u8;
pub const Hash = [32]u8;

pub const AccountInfo = struct {
    nonce: u64 = 0,
    balance: u256 = 0,
    code_hash: Hash = @import("../trie/node.zig").empty_code_hash,

    pub fn eql(a: AccountInfo, b: AccountInfo) bool {
        return a.nonce == b.nonce and a.balance == b.balance and
            std.mem.eql(u8, &a.code_hash, &b.code_hash);
    }
};

/// The address as a big-endian integer: integer order is byte order, in a few word compares
/// (a byte-wise `std.mem.order` made changeset sorting ~2 ms per 4k slots).
fn address_key(address: *const Address) u160 {
    return std.mem.readInt(u160, address, .big);
}

pub const AccountChange = struct {
    address: Address,
    old: ?AccountInfo,
    new: ?AccountInfo,

    fn less_than(a: *const AccountChange, b: *const AccountChange) bool {
        return address_key(&a.address) < address_key(&b.address);
    }
};

pub const StorageChange = struct {
    address: Address,
    slot: u256,
    old: u256,
    new: u256,

    fn less_than(a: *const StorageChange, b: *const StorageChange) bool {
        const a_key = address_key(&a.address);
        const b_key = address_key(&b.address);
        if (a_key != b_key) return a_key < b_key;
        return a.slot < b.slot;
    }
};

pub const Config = struct {
    accounts_max: u32,
    storage_max: u32,
    codes_max: u32,
    code_bytes_max: u32,
};

pub const magic: u32 = 0x5343464e; // "NFCS"
pub const version: u16 = 1;
const header_bytes = 4 + 2 + 4 + 4 + 4;
const account_side_bytes = 8 + 32 + 32;
const storage_entry_bytes = 20 + 32 + 32 + 32;

pub const Error = error{ ChangesetFull, InvalidChangeset };

/// A changeset with fixed capacity, allocated once.
pub const Changeset = struct {
    accounts: []AccountChange,
    accounts_len: u32 = 0,
    storage: []StorageChange,
    storage_len: u32 = 0,
    /// Code introduced by this block, stored back to back.
    code_bytes: []u8,
    code_bytes_len: u32 = 0,
    code_ends: []u32,
    codes_len: u32 = 0,
    /// Sort scratch: one index per entry of the larger of `accounts` and `storage`.
    order: []u64,

    /// Buffers are reserved here and committed on first touch (`lazy_alloc`).
    pub fn init(allocator: std.mem.Allocator, config: Config) !Changeset {
        const accounts = try lazy.alloc(allocator, AccountChange, config.accounts_max);
        errdefer lazy.free(allocator, accounts);
        const storage = try lazy.alloc(allocator, StorageChange, config.storage_max);
        errdefer lazy.free(allocator, storage);
        const code_bytes = try lazy.alloc(allocator, u8, config.code_bytes_max);
        errdefer lazy.free(allocator, code_bytes);
        const code_ends = try lazy.alloc(allocator, u32, config.codes_max);
        errdefer lazy.free(allocator, code_ends);
        const order_len = @max(config.accounts_max, config.storage_max);
        const order = try lazy.alloc(allocator, u64, order_len);
        return .{
            .accounts = accounts,
            .storage = storage,
            .code_bytes = code_bytes,
            .code_ends = code_ends,
            .order = order,
        };
    }

    pub fn deinit(self: *Changeset, allocator: std.mem.Allocator) void {
        lazy.free(allocator, self.order);
        lazy.free(allocator, self.code_ends);
        lazy.free(allocator, self.code_bytes);
        lazy.free(allocator, self.storage);
        lazy.free(allocator, self.accounts);
        self.* = undefined;
    }

    pub fn clear(self: *Changeset) void {
        self.accounts_len = 0;
        self.storage_len = 0;
        self.code_bytes_len = 0;
        self.codes_len = 0;
    }

    pub fn account_changes(self: *const Changeset) []const AccountChange {
        return self.accounts[0..self.accounts_len];
    }

    pub fn storage_changes(self: *const Changeset) []const StorageChange {
        return self.storage[0..self.storage_len];
    }

    pub fn code(self: *const Changeset, index: u32) []const u8 {
        assert(index < self.codes_len);
        const start = if (index == 0) 0 else self.code_ends[index - 1];
        return self.code_bytes[start..self.code_ends[index]];
    }

    pub fn add_account(self: *Changeset, change: AccountChange) Error!void {
        assert(change.old != null or change.new != null);
        if (self.accounts_len == self.accounts.len) return error.ChangesetFull;
        self.accounts[self.accounts_len] = change;
        self.accounts_len += 1;
    }

    pub fn add_storage(self: *Changeset, change: StorageChange) Error!void {
        assert(change.old != change.new);
        if (self.storage_len == self.storage.len) return error.ChangesetFull;
        self.storage[self.storage_len] = change;
        self.storage_len += 1;
    }

    pub fn add_code(self: *Changeset, bytes: []const u8) Error!void {
        if (self.codes_len == self.code_ends.len) return error.ChangesetFull;
        if (self.code_bytes_len + bytes.len > self.code_bytes.len) return error.ChangesetFull;
        @memcpy(self.code_bytes[self.code_bytes_len..][0..bytes.len], bytes);
        self.code_bytes_len += @intCast(bytes.len);
        self.code_ends[self.codes_len] = self.code_bytes_len;
        self.codes_len += 1;
    }

    /// Sorts entries into canonical order. Duplicate keys are a caller bug, so an unstable
    /// sort gives the same order as a stable one.
    pub fn sort(self: *Changeset) void {
        const accounts = self.accounts[0..self.accounts_len];
        sort_entries(AccountChange, accounts, self.order[0..accounts.len]);
        const storage = self.storage[0..self.storage_len];
        sort_entries(StorageChange, storage, self.order[0..storage.len]);
        for (1..@max(1, accounts.len)) |i| {
            assert(AccountChange.less_than(&accounts[i - 1], &accounts[i]));
        }
        for (1..@max(1, storage.len)) |i| {
            assert(StorageChange.less_than(&storage[i - 1], &storage[i]));
        }
    }

    pub fn encoded_length(self: *const Changeset) u64 {
        var length: u64 = header_bytes;
        for (self.account_changes()) |change| {
            length += 21;
            length += account_side_bytes * @as(u64, @intFromBool(change.old != null));
            length += account_side_bytes * @as(u64, @intFromBool(change.new != null));
        }
        length += @as(u64, self.storage_len) * storage_entry_bytes;
        length += @as(u64, self.codes_len) * 4 + self.code_bytes_len;
        return length;
    }

    pub fn encode(self: *const Changeset, out: []u8) []u8 {
        const length = self.encoded_length();
        assert(out.len >= length);
        var writer: Writer = .{ .buffer = out };
        writer.int(u32, magic);
        writer.int(u16, version);
        writer.int(u32, self.accounts_len);
        writer.int(u32, self.storage_len);
        writer.int(u32, self.codes_len);
        for (self.account_changes()) |*change| {
            writer.bytes(&change.address);
            const flags: u8 = @as(u8, @intFromBool(change.old != null)) |
                (@as(u8, @intFromBool(change.new != null)) << 1);
            writer.int(u8, flags);
            if (change.old) |info| writer.account(&info);
            if (change.new) |info| writer.account(&info);
        }
        for (self.storage_changes()) |*change| {
            writer.bytes(&change.address);
            writer.word(change.slot);
            writer.word(change.old);
            writer.word(change.new);
        }
        for (0..self.codes_len) |index| {
            const bytes = self.code(@intCast(index));
            writer.int(u32, @intCast(bytes.len));
            writer.bytes(bytes);
        }
        assert(writer.position == length);
        return out[0..writer.position];
    }

    /// Decodes into `self` (cleared first). Rejects anything `encode` would not produce.
    pub fn decode(self: *Changeset, input: []const u8) Error!void {
        self.clear();
        var reader: Reader = .{ .buffer = input };
        if (try reader.int(u32) != magic) return error.InvalidChangeset;
        if (try reader.int(u16) != version) return error.InvalidChangeset;
        const accounts_count = try reader.int(u32);
        const storage_count = try reader.int(u32);
        const codes_count = try reader.int(u32);
        if (accounts_count > self.accounts.len) return error.InvalidChangeset;
        if (storage_count > self.storage.len) return error.InvalidChangeset;
        if (codes_count > self.code_ends.len) return error.InvalidChangeset;
        for (0..accounts_count) |_| try self.decode_account(&reader);
        for (0..storage_count) |_| {
            const change: StorageChange = .{
                .address = (try reader.bytes(20))[0..20].*,
                .slot = try reader.word(),
                .old = try reader.word(),
                .new = try reader.word(),
            };
            if (change.old == change.new) return error.InvalidChangeset;
            try self.add_storage(change);
        }
        for (0..codes_count) |_| {
            const length = try reader.int(u32);
            const bytes = try reader.bytes(length);
            self.add_code(bytes) catch return error.InvalidChangeset;
        }
        if (reader.position != input.len) return error.InvalidChangeset;
        try self.check_sorted();
    }

    fn decode_account(self: *Changeset, reader: *Reader) Error!void {
        const address = (try reader.bytes(20))[0..20].*;
        const flags = try reader.int(u8);
        if (flags == 0 or flags > 3) return error.InvalidChangeset;
        const old: ?AccountInfo = if (flags & 1 != 0) try reader.account() else null;
        const new: ?AccountInfo = if (flags & 2 != 0) try reader.account() else null;
        try self.add_account(.{ .address = address, .old = old, .new = new });
    }

    fn check_sorted(self: *const Changeset) Error!void {
        const accounts = self.account_changes();
        for (1..@max(1, accounts.len)) |i| {
            if (!AccountChange.less_than(&accounts[i - 1], &accounts[i])) {
                return error.InvalidChangeset;
            }
        }
        const storage = self.storage_changes();
        for (1..@max(1, storage.len)) |i| {
            if (!StorageChange.less_than(&storage[i - 1], &storage[i])) {
                return error.InvalidChangeset;
            }
        }
    }
};

/// Sorts `items` by `T.less_than` through an index array, then permutes `items` in place.
/// Entries are 128+ bytes: sorting them directly copied entries on every compare and swap
/// (~2 ms for 4k slots). Each order word is `address[0..4] << 32 | index`, so most compares
/// are one integer compare (the prefix is the most significant part of the key) and only
/// equal prefixes look at the entries.
fn sort_entries(comptime T: type, items: []T, order: []u64) void {
    assert(order.len == items.len);
    assert(items.len <= std.math.maxInt(u32));
    for (order, items, 0..) |*word, *item, position| {
        const prefix: u64 = std.mem.readInt(u32, item.address[0..4], .big);
        word.* = prefix << 32 | position;
    }
    const Context = struct {
        items: []const T,
        fn less_than(context: @This(), a: u64, b: u64) bool {
            if (a >> 32 != b >> 32) return a >> 32 < b >> 32;
            const a_item = &context.items[@as(u32, @truncate(a))];
            return T.less_than(a_item, &context.items[@as(u32, @truncate(b))]);
        }
    };
    std.sort.pdq(u64, order, Context{ .items = items }, Context.less_than);
    // Follow each cycle of the permutation: position k receives items[order[k]]. A finished
    // position is marked by index(order[k]) == k, so every entry moves at most once.
    var moves: u64 = 0;
    for (0..items.len) |start| {
        if (@as(u32, @truncate(order[start])) == start) continue;
        const saved = items[start];
        var target: usize = start;
        while (true) : (moves += 1) {
            assert(moves <= items.len);
            const source: usize = @as(u32, @truncate(order[target]));
            order[target] = target;
            if (source == start) {
                items[target] = saved;
                break;
            }
            items[target] = items[source];
            target = source;
        }
    }
}

const Writer = struct {
    buffer: []u8,
    position: usize = 0,

    fn bytes(self: *Writer, data: []const u8) void {
        assert(self.position + data.len <= self.buffer.len);
        @memcpy(self.buffer[self.position..][0..data.len], data);
        self.position += data.len;
    }

    fn int(self: *Writer, comptime T: type, value: T) void {
        var scratch: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &scratch, value, .little);
        self.bytes(&scratch);
    }

    fn word(self: *Writer, value: u256) void {
        var scratch: [32]u8 = undefined;
        std.mem.writeInt(u256, &scratch, value, .big);
        self.bytes(&scratch);
    }

    fn account(self: *Writer, info: *const AccountInfo) void {
        self.int(u64, info.nonce);
        self.word(info.balance);
        self.bytes(&info.code_hash);
    }
};

const Reader = struct {
    buffer: []const u8,
    position: usize = 0,

    fn bytes(self: *Reader, length: usize) Error![]const u8 {
        if (length > self.buffer.len - self.position) return error.InvalidChangeset;
        const result = self.buffer[self.position..][0..length];
        self.position += length;
        return result;
    }

    fn int(self: *Reader, comptime T: type) Error!T {
        const data = try self.bytes(@sizeOf(T));
        return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
    }

    fn word(self: *Reader) Error!u256 {
        const data = try self.bytes(32);
        return std.mem.readInt(u256, data[0..32], .big);
    }

    fn account(self: *Reader) Error!AccountInfo {
        return .{
            .nonce = try self.int(u64),
            .balance = try self.word(),
            .code_hash = (try self.bytes(32))[0..32].*,
        };
    }
};

/// Hash of every code blob in the changeset, for checks after decode.
pub fn code_hash(changeset: *const Changeset, index: u32) Hash {
    return keccak256(changeset.code(index));
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const test_config: Config = .{
    .accounts_max = 64,
    .storage_max = 256,
    .codes_max = 8,
    .code_bytes_max = 4096,
};

fn random_info(prng: *Prng) ?AccountInfo {
    if (prng.chance(1, 4)) return null;
    var info: AccountInfo = .{ .nonce = prng.int(u64), .balance = prng.int(u256) };
    prng.fill(&info.code_hash);
    return info;
}

fn random_changeset(prng: *Prng, changeset: *Changeset) !void {
    changeset.clear();
    const accounts = prng.below(test_config.accounts_max);
    for (0..accounts) |index| {
        var address: Address = @splat(0);
        std.mem.writeInt(u32, address[0..4], @intCast(index), .big);
        var old = random_info(prng);
        const new = random_info(prng);
        if (old == null and new == null) old = .{};
        try changeset.add_account(.{ .address = address, .old = old, .new = new });
    }
    const slots = prng.below(test_config.storage_max);
    for (0..slots) |index| {
        var address: Address = @splat(0);
        address[0] = @intCast(prng.below(4));
        const old = prng.int(u256);
        try changeset.add_storage(.{ .address = address, .slot = index, .old = old, .new = ~old });
    }
    var code: [100]u8 = undefined;
    for (0..prng.below(test_config.codes_max)) |_| {
        const length = prng.below(code.len);
        prng.fill(code[0..length]);
        try changeset.add_code(code[0..length]);
    }
    changeset.sort();
}

test "changeset: seeded encode/decode roundtrip is canonical" {
    var prng = Prng.init(0xc5);
    var a = try Changeset.init(testing.allocator, test_config);
    defer a.deinit(testing.allocator);
    var b = try Changeset.init(testing.allocator, test_config);
    defer b.deinit(testing.allocator);
    const buffer = try testing.allocator.alloc(u8, 64 * 1024);
    defer testing.allocator.free(buffer);
    const second = try testing.allocator.alloc(u8, 64 * 1024);
    defer testing.allocator.free(second);
    for (0..200) |_| {
        try random_changeset(&prng, &a);
        const encoded = a.encode(buffer);
        try testing.expectEqual(a.encoded_length(), encoded.len);
        try b.decode(encoded);
        try testing.expectEqualSlices(u8, encoded, b.encode(second));
        // Any truncation is rejected.
        if (encoded.len > header_bytes) {
            const cut = prng.below(encoded.len);
            try testing.expectError(error.InvalidChangeset, b.decode(encoded[0..cut]));
        }
    }
}

fn reference_less_than(_: void, a: StorageChange, b: StorageChange) bool {
    return switch (std.mem.order(u8, &a.address, &b.address)) {
        .lt => true,
        .gt => false,
        .eq => a.slot < b.slot,
    };
}

test "changeset: sort matches a byte-wise stable sort" {
    var prng = Prng.init(0x50e7);
    var changeset = try Changeset.init(testing.allocator, test_config);
    defer changeset.deinit(testing.allocator);
    var expected: [test_config.storage_max]StorageChange = undefined;
    for (0..100) |_| {
        changeset.clear();
        const count = prng.below(test_config.storage_max + 1);
        for (0..count) |index| {
            // Few distinct prefixes and tails, so the prefix compare ties often.
            var address: Address = @splat(0);
            address[prng.below(2) * 3] = @intCast(prng.below(3));
            address[19] = @intCast(prng.below(3));
            const slot = @as(u256, prng.below(4)) << 200 | index;
            try changeset.add_storage(.{ .address = address, .slot = slot, .old = 0, .new = 1 });
        }
        @memcpy(expected[0..count], changeset.storage_changes());
        std.mem.sort(StorageChange, expected[0..count], {}, reference_less_than);
        changeset.sort();
        for (expected[0..count], changeset.storage_changes()) |want, got| {
            try testing.expectEqualSlices(u8, &want.address, &got.address);
            try testing.expectEqual(want.slot, got.slot);
        }
    }
}

fn fuzz_decode(changeset: *Changeset, smith: *testing.Smith) anyerror!void {
    var input: [2048]u8 = undefined;
    const length = smith.slice(&input);
    // Make a valid prefix likely so the fuzzer reaches the body.
    if (length >= 6 and smith.value(bool)) {
        std.mem.writeInt(u32, input[0..4], magic, .little);
        std.mem.writeInt(u16, input[4..6], version, .little);
    }
    changeset.decode(input[0..length]) catch return;
    var output: [4096]u8 = undefined;
    if (changeset.encoded_length() > output.len) return;
    try testing.expectEqualSlices(u8, input[0..length], changeset.encode(&output));
}

test "changeset: fuzz decode" {
    var changeset = try Changeset.init(testing.allocator, test_config);
    defer changeset.deinit(testing.allocator);
    try testing.fuzz(&changeset, fuzz_decode, .{});
}

//! State snapshots: stream a whole `State` out and load it back.
//!
//! The storage engine writes snapshots as checkpoints. A snapshot holds the flat tables
//! only; loading rebuilds the state trie and checks the recomputed root against the root
//! recorded in the snapshot, so a damaged or truncated snapshot never loads silently.
//!
//! Format (little-endian integers, big-endian u256 words):
//!   magic u32, version u16, state_root [32], account_count u32, slot_count u32,
//!   code_count u32, block_hash_count u32,
//!   accounts: address[20], nonce u64, balance[32], code_hash[32];
//!   slots: address[20], slot[32], value[32];
//!   codes: length u32, bytes;
//!   block hashes: number u64, hash[32].
//!
//! Sinks provide `write(bytes) !void`; sources provide `read(buffer) !void` (exact reads).

const std = @import("std");
const assert = std.debug.assert;

const state_module = @import("state.zig");
const State = state_module.State;
const node = @import("../trie/node.zig");

pub const magic: u32 = 0x534e464e; // "NFNS"
pub const version: u16 = 1;

pub const LoadError = error{ InvalidSnapshot, RootMismatch } || state_module.Error;

fn write_int(sink: anytype, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try sink.write(&bytes);
}

fn write_word(sink: anytype, value: u256) !void {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    try sink.write(&bytes);
}

fn read_int(source: anytype, comptime T: type) !T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    try source.read(&bytes);
    return std.mem.readInt(T, &bytes, .little);
}

fn read_word(source: anytype) !u256 {
    var bytes: [32]u8 = undefined;
    try source.read(&bytes);
    return std.mem.readInt(u256, &bytes, .big);
}

fn block_hash_count(state: *const State) u32 {
    var count: u32 = 0;
    for (state.block_hashes) |entry| count += @intFromBool(entry.valid);
    return count;
}

/// Streams `state` into `sink`. Computes the state root first.
pub fn write(state: *State, sink: anytype) !void {
    const root = try state.state_root();
    try write_int(sink, u32, magic);
    try write_int(sink, u16, version);
    try sink.write(&root);
    try write_int(sink, u32, state.account_table.count());
    try write_int(sink, u32, state.storage_table.count());
    try write_int(sink, u32, state.code_table.count());
    try write_int(sink, u32, block_hash_count(state));
    var accounts = state.account_table.iterator();
    while (accounts.next()) |entry| {
        try sink.write(entry.key_ptr);
        try write_int(sink, u64, entry.value_ptr.info.nonce);
        try write_word(sink, entry.value_ptr.info.balance);
        try sink.write(&entry.value_ptr.info.code_hash);
    }
    var slots = state.storage_table.iterator();
    while (slots.next()) |entry| {
        try sink.write(&entry.key_ptr.address);
        try write_word(sink, entry.key_ptr.slot);
        try write_word(sink, entry.value_ptr.*);
    }
    var codes = state.code_table.iterator();
    while (codes.next()) |entry| {
        const code = state.code_by_hash(entry.key_ptr.*).?;
        try write_int(sink, u32, @intCast(code.len));
        try sink.write(code);
    }
    for (state.block_hashes) |entry| {
        if (!entry.valid) continue;
        try write_int(sink, u64, entry.number);
        try sink.write(&entry.hash);
    }
}

const Counts = struct { accounts: u32, slots: u32, codes: u32, block_hashes: u32 };

/// Loads a snapshot into an empty `state`. On error the state must be discarded.
pub fn load(state: *State, source: anytype) !void {
    assert(state.account_table.count() == 0);
    assert(state.code_table.count() == 0);
    if (try read_int(source, u32) != magic) return error.InvalidSnapshot;
    if (try read_int(source, u16) != version) return error.InvalidSnapshot;
    var expected_root: node.Hash = undefined;
    try source.read(&expected_root);
    const counts: Counts = .{
        .accounts = try read_int(source, u32),
        .slots = try read_int(source, u32),
        .codes = try read_int(source, u32),
        .block_hashes = try read_int(source, u32),
    };
    if (counts.accounts > state.config.accounts_max) return error.InvalidSnapshot;
    if (counts.slots > state.config.storage_slots_max) return error.InvalidSnapshot;
    if (counts.codes > state.config.codes_max) return error.InvalidSnapshot;
    if (counts.block_hashes > state_module.block_hashes_max) return error.InvalidSnapshot;
    try load_accounts(state, source, counts.accounts);
    try load_slots(state, source, counts.slots);
    try load_codes(state, source, counts.codes);
    for (0..counts.block_hashes) |_| {
        const number = try read_int(source, u64);
        var hash: node.Hash = undefined;
        try source.read(&hash);
        state.set_block_hash(number, hash);
    }
    const root = try state.state_root();
    if (!std.mem.eql(u8, &root, &expected_root)) return error.RootMismatch;
    // Code bytes are outside the root: every referenced code hash must resolve.
    var accounts = state.account_table.iterator();
    while (accounts.next()) |entry| {
        const code_hash = entry.value_ptr.info.code_hash;
        if (state.code_by_hash(code_hash) == null) return error.InvalidSnapshot;
    }
}

fn load_accounts(state: *State, source: anytype, count: u32) !void {
    for (0..count) |_| {
        var address: state_module.Address = undefined;
        try source.read(&address);
        var info: state_module.AccountInfo = .{
            .nonce = try read_int(source, u64),
            .balance = try read_word(source),
        };
        try source.read(&info.code_hash);
        if (state.account_table.contains(address)) return error.InvalidSnapshot;
        state.account_table.putAssumeCapacityNoClobber(address, .{ .info = info });
        try state.state_trie.set_account(node.keccak256(&address), .{
            .nonce = info.nonce,
            .balance = info.balance,
            .code_hash = info.code_hash,
        });
    }
}

fn load_slots(state: *State, source: anytype, count: u32) !void {
    for (0..count) |_| {
        var key: state_module.SlotKey = undefined;
        try source.read(&key.address);
        key.slot = try read_word(source);
        const value = try read_word(source);
        if (value == 0) return error.InvalidSnapshot;
        const account = state.account_table.getPtr(key.address) orelse {
            return error.InvalidSnapshot;
        };
        if (state.storage_table.contains(key)) return error.InvalidSnapshot;
        state.storage_table.putAssumeCapacityNoClobber(key, value);
        account.storage_slots += 1;
        assert(account.storage_slots <= state.storage_table.count());
        var slot_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_bytes, key.slot, .big);
        const address_hash = node.keccak256(&key.address);
        try state.state_trie.set_storage(address_hash, node.keccak256(&slot_bytes), value);
    }
}

fn load_codes(state: *State, source: anytype, count: u32) !void {
    var buffer: [code_size_max]u8 = undefined;
    for (0..count) |_| {
        const length = try read_int(source, u32);
        if (length == 0 or length > code_size_max) return error.InvalidSnapshot;
        try source.read(buffer[0..length]);
        const result = try state.insert_code(buffer[0..length]);
        if (!result.new) return error.InvalidSnapshot;
    }
}

/// EIP-170 caps deployed code at 24 KiB; leave headroom for chains that raise it.
pub const code_size_max = 64 * 1024;

/// In-memory sink and source, for tests and for callers that buffer whole snapshots.
pub const BufferSink = struct {
    buffer: []u8,
    position: usize = 0,

    pub fn write(self: *BufferSink, bytes: []const u8) error{SnapshotTooLarge}!void {
        if (bytes.len > self.buffer.len - self.position) return error.SnapshotTooLarge;
        @memcpy(self.buffer[self.position..][0..bytes.len], bytes);
        self.position += bytes.len;
    }
};

pub const BufferSource = struct {
    buffer: []const u8,
    position: usize = 0,

    pub fn read(self: *BufferSource, out: []u8) error{InvalidSnapshot}!void {
        if (out.len > self.buffer.len - self.position) return error.InvalidSnapshot;
        @memcpy(out, self.buffer[self.position..][0..out.len]);
        self.position += out.len;
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const Overlay = @import("overlay.zig").Overlay;
const Changeset = @import("changeset.zig").Changeset;

const test_config: state_module.Config = .{
    .accounts_max = 128,
    .storage_slots_max = 1024,
    .codes_max = 16,
    .code_bytes_max = 4096,
    .account_nodes_max = 1024,
    .storage_nodes_max = 8192,
};

fn populate(state: *State, prng: *Prng) !void {
    var overlay = try Overlay.init(testing.allocator, state, .{
        .accounts_max = 128,
        .slots_max = 1024,
        .codes_max = 16,
    });
    defer overlay.deinit(testing.allocator);
    var changeset = try Changeset.init(testing.allocator, .{
        .accounts_max = 128,
        .storage_max = 1024,
        .codes_max = 16,
        .code_bytes_max = 4096,
    });
    defer changeset.deinit(testing.allocator);
    for (0..100) |index| {
        var address: state_module.Address = @splat(0);
        address[0] = @intCast(index);
        var info: state_module.AccountInfo = .{ .nonce = index, .balance = prng.int(u64) };
        if (index % 10 == 0) {
            const code: [12]u8 = @splat(@intCast(index));
            info.code_hash = try overlay.insert_code(&code);
        }
        try overlay.set_account(address, info);
        for (0..prng.below(8)) |slot| try overlay.set_storage(address, slot, prng.int(u256) | 1);
    }
    _ = try overlay.commit(&changeset);
    for (0..40) |number| state.set_block_hash(number, @splat(@intCast(number)));
}

test "snapshot: roundtrip restores root, reads, code, and block hashes" {
    var prng = Prng.init(0x5a5);
    var state = try State.init(testing.allocator, test_config);
    defer state.deinit(testing.allocator);
    try populate(&state, &prng);
    const buffer = try testing.allocator.alloc(u8, 1 << 18);
    defer testing.allocator.free(buffer);
    var sink: BufferSink = .{ .buffer = buffer };
    try write(&state, &sink);
    var loaded = try State.init(testing.allocator, test_config);
    defer loaded.deinit(testing.allocator);
    var source: BufferSource = .{ .buffer = buffer[0..sink.position] };
    try load(&loaded, &source);
    try testing.expectEqual(sink.position, source.position);
    try testing.expectEqual(try state.state_root(), try loaded.state_root());
    var address: state_module.Address = @splat(0);
    address[0] = 50;
    try testing.expect(state.basic(address).?.eql(loaded.basic(address).?));
    try testing.expectEqual(state.storage(address, 0), loaded.storage(address, 0));
    const code_hash = state.basic(address).?.code_hash;
    try testing.expectEqualSlices(u8, state.code_by_hash(code_hash).?, loaded.code_by_hash(
        code_hash,
    ).?);
    try testing.expectEqual(state.block_hash(39), loaded.block_hash(39));
}

test "snapshot: corruption and truncation never load silently" {
    var prng = Prng.init(77);
    var state = try State.init(testing.allocator, test_config);
    defer state.deinit(testing.allocator);
    try populate(&state, &prng);
    const buffer = try testing.allocator.alloc(u8, 1 << 18);
    defer testing.allocator.free(buffer);
    const scratch = try testing.allocator.alloc(u8, 1 << 18);
    defer testing.allocator.free(scratch);
    var sink: BufferSink = .{ .buffer = buffer };
    try write(&state, &sink);
    const length = sink.position;
    // Block hashes are not covered by the state root; the engine's block checksums are.
    const covered = length - block_hash_count(&state) * 40;
    for (0..64) |round| {
        var loaded = try State.init(testing.allocator, test_config);
        defer loaded.deinit(testing.allocator);
        @memcpy(scratch[0..length], buffer[0..length]);
        var end = length;
        if (round % 2 == 0) {
            const position = prng.below(covered);
            scratch[position] ^= @as(u8, 1) << @intCast(prng.below(8));
        } else {
            end = prng.below(length);
        }
        var source: BufferSource = .{ .buffer = scratch[0..end] };
        if (load(&loaded, &source)) |_| return error.TestUnexpectedSuccess else |_| {}
    }
}

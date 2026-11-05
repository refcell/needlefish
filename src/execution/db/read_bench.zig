//! Read-path benchmarks for the evm backend, run by `run` from `src/testing/bench_main.zig`
//! (through `bench.read`).
//!
//! State: the db bench state (`bench.shape_bench`: 100k accounts, 1k contracts x 64 slots)
//! plus one 64-byte code per contract, and an uncommitted `Overlay` holding one measured
//! block (`bench.write_block`: 1k accounts, 4k slots). Every case reads `keys_count` keys
//! drawn from a seeded `Prng` (random, not sequential, so the tables are hit cache-cold),
//! one op per key; a sample times one pass and the report is the median of `samples_count`
//! samples in ns/op, after one untimed warm-up pass.
//!
//! Cases: `State.basic` / `storage` / `code_by_hash` hits and misses; the same reads
//! through `evm_backend.database(&state)` (vtable indirection, plus whatever the backend
//! adds); `Overlay` reads with the key in the overlay vs falling through to `State`; and
//! `StateTrie` reads (prehashed keys and with the keccak256 a caller would pay).
//!
//! Benchmark scaffolding: fixtures and key arrays come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const evm = @import("../evm/root.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const Hash = state_module.Hash;
const SlotKey = state_module.SlotKey;
const Shape = bench.Shape;
const keccak256 = trie.node.keccak256;

pub const samples_count = 15;
pub const keys_count_bench = 1 << 16;
const code_bytes = 64;

/// Random keys of every kind, `keys_count` each.
const Keys = struct {
    accounts_hit: []Address,
    account_hashes_hit: []Hash,
    accounts_miss: []Address,
    slots_hit: []SlotKey,
    slot_address_hashes_hit: []Hash,
    slot_hashes_hit: []Hash,
    slots_miss_existing: []SlotKey,
    slots_miss_absent: []SlotKey,
    codes_hit: []Hash,
    overlay_accounts: []Address,
    overlay_slots: []SlotKey,
    through_accounts: []Address,
    through_slots: []SlotKey,
};

const Fixture = struct {
    shape: Shape,
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    backend: evm.state.Database,
    code_hashes: []Hash,
    keys: Keys,
    keys_count: u32,

    /// `fixture` must not move afterwards (the overlay and backend point at its state).
    fn init(fixture: *Fixture, allocator: std.mem.Allocator, shape: Shape, keys_count: u32) !void {
        shape.check();
        assert(keys_count > 0);
        var config = bench.state_config(shape);
        config.codes_max = shape.contracts;
        config.code_bytes_max = shape.contracts * code_bytes;
        fixture.shape = shape;
        fixture.keys_count = keys_count;
        fixture.state = try State.init(allocator, config);
        fixture.overlay = try Overlay.init(allocator, &fixture.state, bench.overlay_config(shape));
        fixture.changeset = try Changeset.init(allocator, bench.changeset_config(shape));
        fixture.backend = evm_backend.database(&fixture.state);
        fixture.code_hashes = try allocator.alloc(Hash, shape.contracts);
        for (0..shape.fill_blocks()) |fill_index| {
            try bench.write_fill(&fixture.overlay, shape, @intCast(fill_index));
            _ = try fixture.overlay.commit(&fixture.changeset);
        }
        for (fixture.code_hashes, 0..) |*hash, index| {
            var code: [code_bytes]u8 = @splat(0x5b);
            std.mem.writeInt(u64, code[0..8], index, .big);
            const inserted = try fixture.state.insert_code(&code);
            assert(inserted.new);
            hash.* = inserted.hash;
        }
        var prng = Prng.init(7);
        try bench.write_block(&fixture.overlay, shape, &prng);
        assert(fixture.state.account_table.count() == shape.accounts);
        assert(fixture.overlay.accounts.count() == shape.block_accounts);
        try fixture.init_keys(allocator, &prng);
    }

    fn deinit(fixture: *Fixture, allocator: std.mem.Allocator) void {
        inline for (@typeInfo(Keys).@"struct".field_names) |name| {
            allocator.free(@field(fixture.keys, name));
        }
        allocator.free(fixture.code_hashes);
        fixture.changeset.deinit(allocator);
        fixture.overlay.deinit(allocator);
        fixture.state.deinit(allocator);
        fixture.* = undefined;
    }

    fn init_keys(fixture: *Fixture, allocator: std.mem.Allocator, prng: *Prng) !void {
        inline for (@typeInfo(Keys).@"struct".field_names) |name| {
            const Element = @typeInfo(@FieldType(Keys, name)).pointer.child;
            @field(fixture.keys, name) = try allocator.alloc(Element, fixture.keys_count);
        }
        const shape = fixture.shape;
        const keys = &fixture.keys;
        for (0..fixture.keys_count) |index| {
            keys.accounts_hit[index] = bench.address_of(prng.below(shape.accounts));
            keys.account_hashes_hit[index] = keccak256(&keys.accounts_hit[index]);
            keys.accounts_miss[index] = absent_address(shape, prng);
            const slot = prng.below(shape.slots());
            keys.slots_hit[index] = .{
                .address = bench.address_of(slot / shape.slots_per_contract),
                .slot = slot % shape.slots_per_contract,
            };
            keys.slot_address_hashes_hit[index] = keccak256(&keys.slots_hit[index].address);
            keys.slot_hashes_hit[index] = slot_hash(keys.slots_hit[index].slot);
            keys.slots_miss_existing[index] = .{
                .address = bench.address_of(prng.below(shape.contracts)),
                .slot = shape.slots_per_contract + prng.below(1 << 62),
            };
            keys.slots_miss_absent[index] = .{
                .address = absent_address(shape, prng),
                .slot = prng.below(shape.slots_per_contract),
            };
            keys.codes_hit[index] = fixture.code_hashes[prng.below(shape.contracts)];
        }
        try fixture.init_overlay_keys(allocator, prng);
        fixture.check_keys();
    }

    /// Keys present in the overlay, and keys that miss it and fall through to the state.
    fn init_overlay_keys(fixture: *Fixture, allocator: std.mem.Allocator, prng: *Prng) !void {
        const shape = fixture.shape;
        const overlay = &fixture.overlay;
        const present_accounts = try allocator.alloc(Address, overlay.accounts.count());
        defer allocator.free(present_accounts);
        const present_slots = try allocator.alloc(SlotKey, overlay.slots.count());
        defer allocator.free(present_slots);
        var accounts = overlay.accounts.keyIterator();
        for (present_accounts) |*address| address.* = accounts.next().?.*;
        assert(accounts.next() == null);
        var slots = overlay.slots.keyIterator();
        for (present_slots) |*key| key.* = slots.next().?.*;
        assert(slots.next() == null);
        const keys = &fixture.keys;
        for (0..fixture.keys_count) |index| {
            keys.overlay_accounts[index] = present_accounts[prng.below(present_accounts.len)];
            keys.overlay_slots[index] = present_slots[prng.below(present_slots.len)];
            // Rejection sampling: the overlay holds 1% of accounts and 6% of slots.
            var address = bench.address_of(prng.below(shape.accounts));
            while (overlay.accounts.contains(address)) {
                address = bench.address_of(prng.below(shape.accounts));
            }
            keys.through_accounts[index] = address;
            var slot_key = keys.slots_hit[prng.below(fixture.keys_count)];
            while (overlay.slots.contains(slot_key)) {
                slot_key = keys.slots_hit[prng.below(fixture.keys_count)];
            }
            keys.through_slots[index] = slot_key;
        }
    }

    /// Every hit key hits and every miss key misses, in the tables and in the trie.
    fn check_keys(fixture: *const Fixture) void {
        const state = &fixture.state;
        const keys = &fixture.keys;
        for (0..fixture.keys_count) |index| {
            assert(state.basic(keys.accounts_hit[index]) != null);
            assert(state.state_trie.get_account(keys.account_hashes_hit[index]) != null);
            assert(state.basic(keys.accounts_miss[index]) == null);
            const hit = keys.slots_hit[index];
            const value = state.storage(hit.address, hit.slot);
            assert(value != 0);
            assert(value == state.state_trie.get_storage(
                keys.slot_address_hashes_hit[index],
                keys.slot_hashes_hit[index],
            ));
            const existing = keys.slots_miss_existing[index];
            assert(state.basic(existing.address) != null);
            assert(state.storage(existing.address, existing.slot) == 0);
            assert(state.basic(keys.slots_miss_absent[index].address) == null);
            assert(state.code_by_hash(keys.codes_hit[index]).?.len == code_bytes);
            assert(fixture.overlay.accounts.contains(keys.overlay_accounts[index]));
            assert(fixture.overlay.slots.contains(keys.overlay_slots[index]));
            assert(!fixture.overlay.accounts.contains(keys.through_accounts[index]));
            assert(!fixture.overlay.slots.contains(keys.through_slots[index]));
        }
    }
};

/// An address outside the state (indices at and above `shape.accounts`).
fn absent_address(shape: Shape, prng: *Prng) Address {
    return bench.address_of(prng.range(shape.accounts, std.math.maxInt(u32)));
}

fn slot_hash(slot: u256) Hash {
    var key: [32]u8 = undefined;
    std.mem.writeInt(u256, &key, slot, .big);
    return keccak256(&key);
}

// Cases: one op per key of the fixture; the return value keeps the reads alive.

const Case = struct {
    name: []const u8,
    run: *const fn (fixture: *const Fixture) u64,
};

pub const cases = [_]Case{
    .{ .name = "db/read State.basic hit", .run = state_basic_hit },
    .{ .name = "db/read State.basic miss", .run = state_basic_miss },
    .{ .name = "db/read State.storage hit", .run = state_storage_hit },
    .{ .name = "db/read State.storage miss (account exists)", .run = state_storage_miss },
    .{ .name = "db/read State.storage miss (no account)", .run = state_storage_absent },
    .{ .name = "db/read State.code_by_hash hit", .run = state_code_hit },
    .{ .name = "db/read vtable basic hit", .run = vtable_basic_hit },
    .{ .name = "db/read vtable basic miss", .run = vtable_basic_miss },
    .{ .name = "db/read vtable storage hit", .run = vtable_storage_hit },
    .{ .name = "db/read vtable storage miss (account exists)", .run = vtable_storage_miss },
    .{ .name = "db/read vtable storage miss (no account)", .run = vtable_storage_absent },
    .{ .name = "db/read vtable code_by_hash hit", .run = vtable_code_hit },
    .{ .name = "db/read Overlay.basic in overlay", .run = overlay_basic_present },
    .{ .name = "db/read Overlay.basic fall-through", .run = overlay_basic_through },
    .{ .name = "db/read Overlay.storage in overlay", .run = overlay_storage_present },
    .{ .name = "db/read Overlay.storage fall-through", .run = overlay_storage_through },
    .{ .name = "db/read StateTrie.get_account prehashed", .run = trie_account_prehashed },
    .{ .name = "db/read StateTrie.get_account +keccak", .run = trie_account_keccak },
    .{ .name = "db/read account trie walk prehashed", .run = trie_account_walk },
    .{ .name = "db/read StateTrie.get_storage prehashed", .run = trie_storage_prehashed },
    .{ .name = "db/read StateTrie.get_storage +2 keccak", .run = trie_storage_keccak },
};

fn state_basic_hit(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.accounts_hit) |address| {
        accumulator +%= fixture.state.basic(address).?.nonce;
    }
    return accumulator;
}

fn state_basic_miss(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.accounts_miss) |address| {
        accumulator +%= @intFromBool(fixture.state.basic(address) == null);
    }
    return accumulator;
}

fn state_storage(fixture: *const Fixture, keys: []const SlotKey) u64 {
    var accumulator: u64 = 0;
    for (keys) |key| accumulator +%= @truncate(fixture.state.storage(key.address, key.slot));
    return accumulator;
}

fn state_storage_hit(fixture: *const Fixture) u64 {
    return state_storage(fixture, fixture.keys.slots_hit);
}

fn state_storage_miss(fixture: *const Fixture) u64 {
    return state_storage(fixture, fixture.keys.slots_miss_existing);
}

fn state_storage_absent(fixture: *const Fixture) u64 {
    return state_storage(fixture, fixture.keys.slots_miss_absent);
}

fn state_code_hit(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.codes_hit) |hash| {
        accumulator +%= fixture.state.code_by_hash(hash).?[0];
    }
    return accumulator;
}

fn vtable_basic(fixture: *const Fixture, keys: []const Address) u64 {
    var accumulator: u64 = 0;
    for (keys) |address| {
        const info = fixture.backend.basic(address) catch @panic("bench: basic failed");
        if (info) |found| accumulator +%= found.nonce +% @intFromBool(found.has_storage);
    }
    return accumulator;
}

fn vtable_basic_hit(fixture: *const Fixture) u64 {
    return vtable_basic(fixture, fixture.keys.accounts_hit);
}

fn vtable_basic_miss(fixture: *const Fixture) u64 {
    return vtable_basic(fixture, fixture.keys.accounts_miss);
}

fn vtable_storage(fixture: *const Fixture, keys: []const SlotKey) u64 {
    var accumulator: u64 = 0;
    for (keys) |key| {
        const value = fixture.backend.storage(key.address, key.slot) catch {
            @panic("bench: storage failed");
        };
        accumulator +%= @truncate(value);
    }
    return accumulator;
}

fn vtable_storage_hit(fixture: *const Fixture) u64 {
    return vtable_storage(fixture, fixture.keys.slots_hit);
}

fn vtable_storage_miss(fixture: *const Fixture) u64 {
    return vtable_storage(fixture, fixture.keys.slots_miss_existing);
}

fn vtable_storage_absent(fixture: *const Fixture) u64 {
    return vtable_storage(fixture, fixture.keys.slots_miss_absent);
}

fn vtable_code_hit(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.codes_hit) |hash| {
        const code = fixture.backend.code_by_hash(hash) catch @panic("bench: code failed");
        accumulator +%= code[0];
    }
    return accumulator;
}

fn overlay_basic(fixture: *const Fixture, keys: []const Address) u64 {
    var accumulator: u64 = 0;
    for (keys) |address| accumulator +%= fixture.overlay.basic(address).?.nonce;
    return accumulator;
}

fn overlay_basic_present(fixture: *const Fixture) u64 {
    return overlay_basic(fixture, fixture.keys.overlay_accounts);
}

fn overlay_basic_through(fixture: *const Fixture) u64 {
    return overlay_basic(fixture, fixture.keys.through_accounts);
}

fn overlay_storage(fixture: *const Fixture, keys: []const SlotKey) u64 {
    var accumulator: u64 = 0;
    for (keys) |key| accumulator +%= @truncate(fixture.overlay.storage(key.address, key.slot));
    return accumulator;
}

fn overlay_storage_present(fixture: *const Fixture) u64 {
    return overlay_storage(fixture, fixture.keys.overlay_slots);
}

fn overlay_storage_through(fixture: *const Fixture) u64 {
    return overlay_storage(fixture, fixture.keys.through_slots);
}

fn trie_account_prehashed(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.account_hashes_hit) |hash| {
        accumulator +%= fixture.state.state_trie.get_account(hash).?.nonce;
    }
    return accumulator;
}

fn trie_account_keccak(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.accounts_hit) |address| {
        accumulator +%= fixture.state.state_trie.get_account(keccak256(&address)).?.nonce;
    }
    return accumulator;
}

/// The account trie itself (RLP leaf by path), not `StateTrie`'s by-hash entry map.
fn trie_account_walk(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.account_hashes_hit) |hash| {
        accumulator +%= fixture.state.state_trie.accounts.get(&hash).?.len;
    }
    return accumulator;
}

fn trie_storage_prehashed(fixture: *const Fixture) u64 {
    const keys = &fixture.keys;
    var accumulator: u64 = 0;
    for (keys.slot_address_hashes_hit, keys.slot_hashes_hit) |address_hash, hash| {
        accumulator +%= @truncate(fixture.state.state_trie.get_storage(address_hash, hash));
    }
    return accumulator;
}

fn trie_storage_keccak(fixture: *const Fixture) u64 {
    var accumulator: u64 = 0;
    for (fixture.keys.slots_hit) |key| {
        const address_hash = keccak256(&key.address);
        const value = fixture.state.state_trie.get_storage(address_hash, slot_hash(key.slot));
        accumulator +%= @truncate(value);
    }
    return accumulator;
}

// Runner.

/// Median ns/op of `samples_count` timed passes over the case's keys.
fn measure(io: std.Io, fixture: *const Fixture, case: *const Case) f64 {
    std.mem.doNotOptimizeAway(case.run(fixture));
    var samples: [samples_count]u64 = undefined;
    for (&samples) |*sample| {
        const start = bench.now_ns(io);
        std.mem.doNotOptimizeAway(case.run(fixture));
        const end = bench.now_ns(io);
        assert(end >= start);
        sample.* = end - start;
    }
    std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
    assert(samples[0] <= samples[samples_count - 1]);
    const median: f64 = @floatFromInt(samples[samples_count / 2]);
    return median / @as(f64, @floatFromInt(fixture.keys_count));
}

/// Runs the read benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    var any = false;
    for (cases) |case| any = any or bench.matches(case.name, filter);
    if (!any) return;
    const allocator = std.heap.page_allocator;
    run_shape(io, allocator, bench.shape_bench, keys_count_bench, filter, true) catch |err| {
        std.debug.print("db/read: failed: {s}\n", .{@errorName(err)});
    };
}

fn run_shape(
    io: std.Io,
    allocator: std.mem.Allocator,
    shape: Shape,
    keys_count: u32,
    filter: ?[]const u8,
    print: bool,
) !void {
    const fixture = try allocator.create(Fixture);
    defer allocator.destroy(fixture);
    try fixture.init(allocator, shape, keys_count);
    defer fixture.deinit(allocator);
    for (&cases) |*case| {
        if (!bench.matches(case.name, filter)) continue;
        const ns_per_op = measure(io, fixture, case);
        assert(ns_per_op >= 0);
        if (print) {
            std.debug.print("{s:<44} {d:>8.1} ns/op (median)\n", .{ case.name, ns_per_op });
        }
    }
}

test "read bench: every case runs over checked keys (small shape)" {
    try run_shape(std.testing.io, std.testing.allocator, bench.shape_test, 256, null, false);
    for (cases) |case| try std.testing.expect(bench.matches(case.name, "db/read"));
    try std.testing.expect(cases.len == 21);
}

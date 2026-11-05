//! `State.has_storage` (the per-account slot count) against `StateTrie.has_storage` across
//! random genesis writes, overlay blocks (writes, destroys, wipes, discards), unwinds, and
//! snapshot loads. The count answers EIP-7610 create collisions for the evm backend, so a
//! drift from the trie is a consensus bug. Seeded runs go through normal `zig build test`;
//! the fuzz test drives the same sequence from fuzzer choices.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const snapshot = @import("snapshot.zig");
const evm_backend = @import("evm_backend.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;

const addresses_max = 12;
const slots_max = 6;
const blocks_max = 16;
const steps_max = 64;
const writes_per_block_max = 24;

const state_config: state_module.Config = .{
    .accounts_max = 32,
    .storage_slots_max = 2 * addresses_max * slots_max,
    .codes_max = 4,
    .code_bytes_max = 256,
    .account_nodes_max = 256,
    .storage_nodes_max = 4096,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = addresses_max,
    .slots_max = addresses_max * slots_max,
    .codes_max = 4,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = addresses_max,
    .storage_max = addresses_max * slots_max,
    .codes_max = 4,
    .code_bytes_max = 256,
};

const snapshot_bytes_max = 1 << 14;

fn address_of(index: u64) Address {
    assert(index < addresses_max);
    var address: Address = @splat(0x5a);
    address[19] = @intCast(index);
    return address;
}

/// Fuzzer choices as bounded indexes; exhausted input reads as zero.
const SmithSource = struct {
    smith: *testing.Smith,

    fn below(self: *SmithSource, bound: u64) u64 {
        assert(bound > 0);
        const index = self.smith.index(@intCast(bound));
        assert(index < bound);
        return index;
    }
};

/// Every address: the slot count equals a recount of `storage_table`, `has_storage` and the
/// evm backend agree with the trie.
fn expect_consistent(state: *State) !void {
    var counts: [addresses_max]u32 = @splat(0);
    var slots = state.storage_table.iterator();
    while (slots.next()) |entry| {
        try testing.expect(entry.value_ptr.* != 0);
        counts[entry.key_ptr.address[19]] += 1;
    }
    const backend = evm_backend.database(state);
    for (0..addresses_max) |index| {
        const address = address_of(index);
        const expected = state.state_trie.has_storage(trie.node.keccak256(&address));
        try testing.expectEqual(expected, state.has_storage(address));
        if (state.account(address)) |entry| {
            try testing.expectEqual(counts[index], entry.storage_slots);
        } else {
            try testing.expectEqual(@as(u32, 0), counts[index]);
        }
        const info = try backend.vtable.basic(backend.context, address);
        try testing.expectEqual(state.basic(address) != null, info != null);
        if (info) |found| try testing.expectEqual(expected, found.has_storage);
    }
}

fn random_write(source: anytype, overlay: *Overlay) !void {
    const address = address_of(source.below(addresses_max));
    const exists = overlay.basic(address) != null;
    switch (source.below(10)) {
        0...2 => try overlay.set_account(address, .{
            .nonce = source.below(4),
            .balance = source.below(1000) + 1,
        }),
        3 => try overlay.set_account(address, null),
        4 => if (exists) try overlay.wipe_storage(address),
        else => if (exists) {
            const value: u256 = if (source.below(3) == 0) 0 else source.below(1 << 16) + 1;
            try overlay.set_storage(address, source.below(slots_max), value);
        },
    }
}

/// Direct writes (the genesis path), applied the same to both states before any block.
fn genesis(source: anytype, primary: *State, replica: *State) !void {
    for (0..addresses_max) |index| {
        if (source.below(2) == 0) continue;
        const address = address_of(index);
        const info: state_module.AccountInfo = .{ .balance = index + 1 };
        try primary.put_account(address, info);
        try replica.put_account(address, info);
        for (0..source.below(slots_max + 1)) |_| {
            const slot = source.below(slots_max);
            const value: u256 = if (source.below(4) == 0) 0 else source.below(1 << 16) + 1;
            try primary.put_storage(address, slot, value);
            try replica.put_storage(address, slot, value);
        }
        // Re-putting the account keeps its storage and count.
        if (source.below(4) == 0) try primary.put_account(address, info);
        if (source.below(4) == 0) try replica.put_account(address, info);
    }
}

const Harness = struct {
    primary: State,
    replica: State,
    overlay: Overlay,
    changesets: [blocks_max]Changeset,
    height: u32 = 0,
    buffer: []u8,

    fn init(self: *Harness) !void {
        self.primary = try State.init(testing.allocator, state_config);
        errdefer self.primary.deinit(testing.allocator);
        self.replica = try State.init(testing.allocator, state_config);
        errdefer self.replica.deinit(testing.allocator);
        self.overlay = try Overlay.init(testing.allocator, &self.primary, overlay_config);
        errdefer self.overlay.deinit(testing.allocator);
        self.buffer = try testing.allocator.alloc(u8, snapshot_bytes_max);
        errdefer testing.allocator.free(self.buffer);
        var initialized: usize = 0;
        errdefer for (self.changesets[0..initialized]) |*c| c.deinit(testing.allocator);
        for (&self.changesets) |*c| {
            c.* = try Changeset.init(testing.allocator, changeset_config);
            initialized += 1;
        }
        self.height = 0;
    }

    fn deinit(self: *Harness) void {
        for (&self.changesets) |*c| c.deinit(testing.allocator);
        testing.allocator.free(self.buffer);
        self.overlay.deinit(testing.allocator);
        self.replica.deinit(testing.allocator);
        self.primary.deinit(testing.allocator);
    }

    /// One block through the overlay: written then committed, or discarded.
    fn block(self: *Harness, source: anytype) !void {
        assert(self.overlay.accounts.count() == 0);
        for (0..source.below(writes_per_block_max) + 1) |_| try random_write(source, &self.overlay);
        if (self.height == blocks_max or source.below(6) == 0) {
            self.overlay.discard();
            return;
        }
        const changeset = &self.changesets[self.height];
        _ = try self.overlay.commit(changeset);
        try self.replica.apply(changeset);
        self.height += 1;
    }

    fn unwind(self: *Harness) !void {
        if (self.height == 0) return;
        self.height -= 1;
        try self.primary.unwind(&self.changesets[self.height]);
        try self.replica.unwind(&self.changesets[self.height]);
    }

    /// Rebuilds the replica from a snapshot of the primary; later blocks keep applying to it.
    fn reload(self: *Harness) !void {
        var sink: snapshot.BufferSink = .{ .buffer = self.buffer };
        try snapshot.write(&self.primary, &sink);
        self.replica.deinit(testing.allocator);
        self.replica = try State.init(testing.allocator, state_config);
        var source: snapshot.BufferSource = .{ .buffer = self.buffer[0..sink.position] };
        try snapshot.load(&self.replica, &source);
        try testing.expectEqual(sink.position, source.position);
    }

    fn step(self: *Harness, source: anytype) !void {
        switch (source.below(8)) {
            0...4 => try self.block(source),
            5, 6 => try self.unwind(),
            else => try self.reload(),
        }
        try expect_consistent(&self.primary);
        try expect_consistent(&self.replica);
        try testing.expectEqual(try self.primary.state_root(), try self.replica.state_root());
    }
};

fn run(source: anytype, steps: u32) !void {
    assert(steps <= steps_max);
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try genesis(source, &harness.primary, &harness.replica);
    try expect_consistent(&harness.primary);
    try expect_consistent(&harness.replica);
    for (0..steps) |_| try harness.step(source);
    // Unwinding every block returns to genesis, counts included.
    while (harness.height > 0) try harness.unwind();
    try expect_consistent(&harness.primary);
    try expect_consistent(&harness.replica);
}

test "has_storage: slot counts match the trie across blocks, unwinds, and snapshots" {
    for (0..24) |seed| {
        var prng = Prng.init(0x4a5_0000 + seed);
        try run(&prng, steps_max);
    }
}

fn fuzz_sequence(_: void, smith: *testing.Smith) anyerror!void {
    var source: SmithSource = .{ .smith = smith };
    try run(&source, @intCast(source.below(steps_max) + 1));
}

test "has_storage: fuzz slot counts against the trie" {
    try testing.fuzz({}, fuzz_sequence, .{});
}

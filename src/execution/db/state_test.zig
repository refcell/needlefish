//! State provider tests: random blocks through an `Overlay` checked against a plain model,
//! journal-style replay of encoded changesets into a replica, and reorg unwinds.

const std = @import("std");
const testing = std.testing;

const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const Hash = state_module.Hash;

const addresses_max = 24;
const slots_max = 12;

const state_config: state_module.Config = .{
    .accounts_max = 64,
    .storage_slots_max = addresses_max * slots_max,
    .codes_max = 64,
    .code_bytes_max = 64 * 64,
    .account_nodes_max = 512,
    .storage_nodes_max = 4096,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = addresses_max,
    .storage_max = addresses_max * slots_max,
    .codes_max = 64,
    .code_bytes_max = 64 * 64,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = addresses_max,
    .slots_max = addresses_max * slots_max,
    .codes_max = 64,
};

/// The model: what each address holds after the operations applied so far.
const Model = struct {
    infos: [addresses_max]?AccountInfo = @splat(null),
    slots: [addresses_max][slots_max]u256 = @splat(@splat(0)),
};

fn address_of(index: usize) Address {
    var address: Address = @splat(0x11);
    address[19] = @intCast(index);
    return address;
}

fn random_write(prng: *Prng, overlay: *Overlay, model: *Model) !void {
    const index = prng.below(addresses_max);
    const address = address_of(index);
    switch (prng.below(12)) {
        0...3 => {
            var info: AccountInfo = .{ .nonce = prng.below(8), .balance = prng.below(1 << 40) };
            if (prng.chance(1, 4)) {
                // Eight distinct programs, so code repeats and dedup is exercised.
                const kind: u8 = @intCast(prng.below(8));
                const code: [8]u8 = @splat(kind);
                info.code_hash = try overlay.insert_code(code[0 .. kind + 1]);
            }
            try overlay.set_account(address, info);
            model.infos[index] = info;
        },
        4 => {
            try overlay.set_account(address, null);
            model.infos[index] = null;
            model.slots[index] = @splat(0);
        },
        5 => {
            if (model.infos[index] == null) return;
            try overlay.wipe_storage(address);
            model.slots[index] = @splat(0);
        },
        else => {
            if (model.infos[index] == null) return;
            const slot = prng.below(slots_max);
            const shift: u8 = @intCast(prng.below(256));
            const value: u256 = if (prng.chance(1, 3)) 0 else prng.int(u256) >> shift;
            try overlay.set_storage(address, slot, value);
            model.slots[index][slot] = value;
        },
    }
}

fn expect_reads(overlay: *const Overlay, model: *const Model) !void {
    for (0..addresses_max) |index| {
        const address = address_of(index);
        const info = overlay.basic(address);
        try testing.expectEqual(model.infos[index] != null, info != null);
        if (info) |got| try testing.expect(got.eql(model.infos[index].?));
        for (0..slots_max) |slot| {
            try testing.expectEqual(model.slots[index][slot], overlay.storage(address, slot));
        }
    }
}

/// State root of the model built from scratch.
fn model_root(model: *const Model) !Hash {
    var fresh = try trie.StateTrie.init(testing.allocator, .{
        .accounts_max = 64,
        .account_nodes_max = 512,
        .storage_nodes_max = 4096,
    });
    defer fresh.deinit(testing.allocator);
    for (model.infos, 0..) |maybe_info, index| {
        const info = maybe_info orelse continue;
        const address_hash = trie.node.keccak256(&address_of(index));
        const account: trie.Account = .{
            .nonce = info.nonce,
            .balance = info.balance,
            .code_hash = info.code_hash,
        };
        try fresh.set_account(address_hash, account);
        for (model.slots[index], 0..) |value, slot| {
            var slot_bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &slot_bytes, slot, .big);
            try fresh.set_storage(address_hash, trie.node.keccak256(&slot_bytes), value);
        }
    }
    return fresh.root();
}

const blocks_count = 40;

test "state: blocks, replay from encoded changesets, and reorg unwind" {
    var prng = Prng.init(0x5747e);
    var state = try State.init(testing.allocator, state_config);
    defer state.deinit(testing.allocator);
    var replica = try State.init(testing.allocator, state_config);
    defer replica.deinit(testing.allocator);
    var overlay = try Overlay.init(testing.allocator, &state, overlay_config);
    defer overlay.deinit(testing.allocator);
    var decoded = try Changeset.init(testing.allocator, changeset_config);
    defer decoded.deinit(testing.allocator);
    var changesets: [blocks_count]Changeset = undefined;
    for (&changesets) |*c| c.* = try Changeset.init(testing.allocator, changeset_config);
    defer for (&changesets) |*c| c.deinit(testing.allocator);
    const buffer = try testing.allocator.alloc(u8, 1 << 16);
    defer testing.allocator.free(buffer);

    var models: [blocks_count + 1]Model = undefined;
    var roots: [blocks_count + 1]Hash = undefined;
    models[0] = .{};
    roots[0] = try state.state_root();
    try testing.expectEqual(trie.empty_root, roots[0]);
    for (0..blocks_count) |block| {
        var model = models[block];
        if (prng.chance(1, 6)) {
            // A discarded payload leaves no trace.
            for (0..prng.below(20)) |_| try random_write(&prng, &overlay, &model);
            overlay.discard();
            model = models[block];
        }
        for (0..prng.range(1, 40)) |_| try random_write(&prng, &overlay, &model);
        try expect_reads(&overlay, &model);
        const root = try overlay.commit(&changesets[block]);
        try expect_reads(&overlay, &model);
        try testing.expectEqual(try model_root(&model), root);
        // Journal replay: the encoded changeset rebuilds the same state elsewhere.
        try decoded.decode(changesets[block].encode(buffer));
        try replica.apply(&decoded);
        try testing.expectEqual(root, try replica.state_root());
        models[block + 1] = model;
        roots[block + 1] = root;
    }
    // Reorg: unwind a random number of blocks, checking every intermediate root.
    const depth = prng.range(1, blocks_count);
    var height: usize = blocks_count;
    while (height > blocks_count - depth) : (height -= 1) {
        try state.unwind(&changesets[height - 1]);
        try testing.expectEqual(roots[height - 1], try state.state_root());
        try expect_reads(&overlay, &models[height - 1]);
    }
}

test "state: block hashes keep the last 256" {
    var state = try State.init(testing.allocator, state_config);
    defer state.deinit(testing.allocator);
    for (0..300) |number| state.set_block_hash(number, @splat(@truncate(number)));
    try testing.expectEqual(@as(?Hash, null), state.block_hash(10));
    try testing.expectEqual(@as(?Hash, @splat(@truncate(299))), state.block_hash(299));
    try testing.expectEqual(@as(?Hash, @splat(@truncate(44))), state.block_hash(44));
    try testing.expectEqual(@as(?Hash, null), state.block_hash(43));
}

test "state: empty code hash resolves to empty code" {
    var state = try State.init(testing.allocator, state_config);
    defer state.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), state.code_by_hash(trie.node.empty_code_hash).?.len);
    const inserted = try state.insert_code("abc");
    try testing.expect(inserted.new);
    try testing.expect(!(try state.insert_code("abc")).new);
    try testing.expectEqualSlices(u8, "abc", state.code_by_hash(inserted.hash).?);
}

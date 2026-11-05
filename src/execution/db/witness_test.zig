//! Execution witness tests: for random pre-states and blocks (reads, writes, deletes, wipes
//! through an `Overlay`), a `SparseState` loaded only with the witness serves the same reads
//! as the full `State` and reaches the same post-state root; dropping any one witness node
//! makes the stateless replay fail with `WitnessIncomplete`.

const std = @import("std");
const testing = std.testing;

const witness = @import("witness.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const Hash = state_module.Hash;

const addresses_total = 64;
const genesis_accounts = 40;
const slot_ids = 12;
const headers_total = 4;

const state_config: state_module.Config = .{
    .accounts_max = 128,
    .storage_slots_max = 1024,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
    .account_nodes_max = 1024,
    .storage_nodes_max = 8192,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = 128,
    .storage_max = 1024,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 128,
    .slots_max = 1024,
    .codes_max = 64,
};

const keys_config: witness.KeySet.Config = .{
    .accounts_max = 128,
    .slots_max = 1024,
    .codes_max = 64,
    .block_numbers_max = 16,
};

const sparse_config: witness.SparseState.Config = .{
    .nodes_max = 4096,
    .node_bytes_max = 1 << 21,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
    .headers_max = 16,
    .trie_nodes_max = 16384,
    .storage_tries_max = 128,
};

const witness_config: witness.Witness.Config = .{
    .state_nodes_max = 4096,
    .state_bytes_max = 1 << 21,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
    .keys_max = 128 + 1024,
    .headers_max = 16,
    .header_bytes_max = 1024,
};

fn address_of(index: u64) Address {
    var address: Address = @splat(0);
    address[0] = 0xa0;
    address[19] = @intCast(index);
    return address;
}

/// `rlp([1, 1, 1, 1, 1, 1, 1, 1, number])`, a minimal header-shaped list (number < 128).
fn header_of(number: u8) [10]u8 {
    std.debug.assert(number > 0 and number < 0x80);
    return .{ 0xc9, 1, 1, 1, 1, 1, 1, 1, 1, number };
}

fn random_info(prng: *Prng, overlay: *Overlay) !AccountInfo {
    var info: AccountInfo = .{ .nonce = prng.below(4), .balance = prng.below(1 << 40) };
    if (prng.chance(1, 4)) {
        var code: [24]u8 = undefined;
        prng.fill(&code);
        info.code_hash = try overlay.insert_code(code[0..prng.range(1, code.len)]);
    }
    return info;
}

fn genesis(prng: *Prng, state: *State, overlay: *Overlay, changeset: *Changeset) !void {
    for (0..genesis_accounts) |index| {
        const address = address_of(index);
        try overlay.set_account(address, try random_info(prng, overlay));
        for (0..prng.below(7)) |_| {
            try overlay.set_storage(address, prng.below(slot_ids), prng.range(1, 1 << 20));
        }
    }
    _ = try overlay.commit(changeset);
    for (1..headers_total + 1) |number| {
        const header = header_of(@intCast(number));
        state.set_block_hash(number, trie.node.keccak256(&header));
    }
}

fn random_reads(prng: *Prng, state: *State, recorder: *witness.Recorder) !void {
    const database = recorder.database();
    for (0..16) |_| {
        const address = address_of(prng.below(addresses_total));
        switch (prng.below(4)) {
            0 => _ = try database.basic(address),
            1 => _ = try database.storage(address, prng.below(slot_ids)),
            2 => if (state.basic(address)) |info| {
                _ = try database.code_by_hash(info.code_hash);
            },
            else => _ = try database.block_hash(prng.range(1, headers_total)),
        }
    }
}

fn random_writes(prng: *Prng, overlay: *Overlay) !void {
    for (0..16) |_| {
        const address = address_of(prng.below(addresses_total));
        const exists = overlay.basic(address) != null;
        switch (prng.below(10)) {
            0...2 => try overlay.set_account(address, try random_info(prng, overlay)),
            3...6 => if (exists) {
                const value = if (prng.chance(1, 2)) 0 else prng.range(1, 1 << 20);
                try overlay.set_storage(address, prng.below(slot_ids), value);
            },
            7, 8 => if (exists) try overlay.set_account(address, null),
            else => if (exists) try overlay.wipe_storage(address),
        }
    }
}

/// Every recorded read gives the pre-state value through the witness-only evm database.
fn check_reads(state: *State, sparse: *witness.SparseState, keys: *const witness.KeySet) !void {
    const database = sparse.database();
    for (keys.accounts.slice()) |address| {
        const expected = state.basic(address);
        const actual = try database.basic(address);
        try testing.expectEqual(expected == null, actual == null);
        if (expected) |info| {
            try testing.expectEqual(info.nonce, actual.?.nonce);
            try testing.expectEqual(info.balance, actual.?.balance);
            try testing.expectEqual(info.code_hash, actual.?.code_hash);
        }
    }
    for (keys.slots.slice()) |key| {
        const actual = try database.storage(key.address, key.slot);
        try testing.expectEqual(state.storage(key.address, key.slot), actual);
    }
    for (keys.codes.slice()) |hash| {
        const actual = try database.code_by_hash(hash);
        try testing.expectEqualSlices(u8, state.code_by_hash(hash).?, actual);
    }
    for (keys.block_numbers.slice()) |number| {
        try testing.expectEqual(state.block_hash(number).?, try database.block_hash(number));
    }
    try testing.expect(!sparse.incomplete);
}

/// Without any one node the same replay must fail for want of it.
fn check_minimal(
    sparse: *witness.SparseState,
    built: *const witness.Witness,
    keys: *const witness.KeySet,
    changeset: *const Changeset,
    pre_root: Hash,
) !void {
    for (0..built.state.count) |skip| {
        sparse.reset(pre_root);
        for (0..built.state.count) |index| {
            if (index != skip) try sparse.add_node(built.state.get(@intCast(index)));
        }
        try testing.expectError(error.WitnessIncomplete, witness.replay(sparse, keys, changeset));
    }
}

const Fixture = struct {
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    recorder: witness.Recorder,
    builder: witness.Builder,
    built: witness.Witness,
    sparse: witness.SparseState,

    fn init(fixture: *Fixture) !void {
        const allocator = testing.allocator;
        fixture.state = try State.init(allocator, state_config);
        fixture.overlay = try Overlay.init(allocator, &fixture.state, overlay_config);
        fixture.changeset = try Changeset.init(allocator, changeset_config);
        const inner = evm_backend.database(&fixture.state);
        fixture.recorder = try witness.Recorder.init(allocator, inner, keys_config);
        fixture.builder = try witness.Builder.init(allocator, .{
            .sparse = sparse_config,
            .keys = keys_config,
        });
        fixture.built = try witness.Witness.init(allocator, witness_config);
        fixture.sparse = try witness.SparseState.init(allocator, sparse_config);
    }

    fn deinit(fixture: *Fixture) void {
        const allocator = testing.allocator;
        fixture.sparse.deinit(allocator);
        fixture.built.deinit(allocator);
        fixture.builder.deinit(allocator);
        fixture.recorder.deinit(allocator);
        fixture.changeset.deinit(allocator);
        fixture.overlay.deinit(allocator);
        fixture.state.deinit(allocator);
    }
};

fn run_block(prng: *Prng, fixture: *Fixture) !void {
    const state = &fixture.state;
    const keys = &fixture.recorder.keys;
    keys.clear();
    try random_reads(prng, state, &fixture.recorder);
    try random_writes(prng, &fixture.overlay);
    try fixture.overlay.build_changeset(&fixture.changeset);
    var headers_buffer: [headers_total][10]u8 = undefined;
    var headers: [headers_total][]const u8 = undefined;
    for (keys.block_numbers.slice(), 0..) |number, index| {
        headers_buffer[index] = header_of(@intCast(number));
        headers[index] = &headers_buffer[index];
    }
    const header_count = keys.block_numbers.len;
    const pre_root = try state.state_root();
    const built = &fixture.built;
    const sparse_root = try fixture.builder.build(
        state,
        keys,
        &fixture.changeset,
        headers[0..header_count],
        built,
    );
    try testing.expectEqual(keys.codes.len, built.codes.count + empty_codes(keys));
    const sparse = &fixture.sparse;
    sparse.reset(pre_root);
    try sparse.load(built);
    try check_reads(state, sparse, keys);
    try witness.replay(sparse, keys, &fixture.changeset);
    const post_root = try fixture.overlay.commit(&fixture.changeset);
    try testing.expectEqual(post_root, sparse_root);
    try testing.expectEqual(post_root, sparse.state_root());
    try check_minimal(sparse, built, keys, &fixture.changeset, pre_root);
}

fn empty_codes(keys: *const witness.KeySet) u32 {
    var count: u32 = 0;
    for (keys.codes.slice()) |hash| {
        count += @intFromBool(std.mem.eql(u8, &hash, &trie.node.empty_code_hash));
    }
    return count;
}

test "witness: stateless replay matches the full state and every node is needed" {
    var seed: u64 = 0;
    while (seed < 8) : (seed += 1) {
        var prng = Prng.init(0x3317e55 + seed);
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        try genesis(&prng, &fixture.state, &fixture.overlay, &fixture.changeset);
        for (0..4) |_| try run_block(&prng, &fixture);
    }
}

test "witness: missing code and header fail the evm read and flag the witness" {
    var sparse = try witness.SparseState.init(testing.allocator, sparse_config);
    defer sparse.deinit(testing.allocator);
    sparse.reset(trie.node.empty_root);
    const database = sparse.database();
    const empty_code = try database.code_by_hash(trie.node.empty_code_hash);
    try testing.expectEqual(@as(usize, 0), empty_code.len);
    try testing.expectEqual(null, try database.basic(address_of(1)));
    try testing.expectError(error.DatabaseFailure, database.code_by_hash(@splat(7)));
    try testing.expect(sparse.incomplete);
    sparse.incomplete = false;
    try testing.expectError(error.DatabaseFailure, database.block_hash(3));
    try testing.expect(sparse.incomplete);
    const header = header_of(3);
    try sparse.add_header(&header);
    try testing.expectEqual(trie.node.keccak256(&header), try database.block_hash(3));
}

test "witness: header number decoding is strict" {
    try testing.expectEqual(@as(u64, 5), try witness.header_number(&header_of(5)));
    try testing.expectError(error.InvalidWitness, witness.header_number(&.{ 0xc2, 1, 1 }));
    try testing.expectError(error.InvalidWitness, witness.header_number(&.{0x80}));
    var prng = Prng.init(11);
    var buffer: [64]u8 = undefined;
    for (0..2000) |_| {
        prng.fill(&buffer);
        buffer[0] = @intCast(0xc0 + prng.below(64));
        _ = witness.header_number(buffer[0..prng.range(1, buffer.len)]) catch continue;
    }
}

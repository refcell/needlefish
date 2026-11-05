//! Differential test of `witness.Builder` against the reference collection it replaced: one
//! `eth_getProof`-style proof per touched key, the hashed siblings of each deleted key one key
//! at a time (deduplicated by keccak256 in the node store), then the full stateless replay
//! (reads, then the changeset) on a sparse state that keeps only the nodes it decoded.
//!
//! For random pre-states and blocks (reads, writes, deletes, wipes; some blocks without
//! deletions, which skip the sparse apply when the root is not verified), the builder's
//! witness, with and without `verify_root`, encodes (`witness_codec`) to exactly the bytes
//! of the reference witness, from the live state (`StateSource`) and from the history store
//! (`HistorySource`), and the verified roots agree.

const std = @import("std");
const testing = std.testing;

const witness = @import("witness.zig");
const codec = @import("witness_codec.zig");
const history = @import("history.zig");
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
const Hash = state_module.Hash;
const keccak256 = trie.node.keccak256;

const addresses_total = 320;
const genesis_accounts = 240;
const slot_ids = 48;
const seeds_count = 6;
const blocks_per_seed = 6;

const state_config: state_module.Config = .{
    .accounts_max = 512,
    .storage_slots_max = 8192,
    .codes_max = 256,
    .code_bytes_max = 256 * 32,
    .account_nodes_max = 4096,
    .storage_nodes_max = 32768,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = 512,
    .storage_max = 8192,
    .codes_max = 256,
    .code_bytes_max = 256 * 32,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 512,
    .slots_max = 8192,
    .codes_max = 256,
};

const keys_config: witness.KeySet.Config = .{
    .accounts_max = 512,
    .slots_max = 8192,
    .codes_max = 256,
    .block_numbers_max = 16,
};

const sparse_config: witness.SparseState.Config = .{
    .nodes_max = 16384,
    .node_bytes_max = 1 << 23,
    .codes_max = 256,
    .code_bytes_max = 256 * 32,
    .headers_max = 4,
    .trie_nodes_max = 65536,
    .storage_tries_max = 512,
};

const witness_config: witness.Witness.Config = .{
    .state_nodes_max = 16384,
    .state_bytes_max = 1 << 23,
    .codes_max = 256,
    .code_bytes_max = 256 * 32,
    .keys_max = 512 + 8192,
    .headers_max = 4,
    .header_bytes_max = 256,
};

const history_config: history.Config = .{
    .window_blocks = 2,
    .paths_max = 65536,
    .small_versions_max = 65536,
    .large_versions_max = 16384,
    .prune_per_commit = 4096,
};

const encoded_bytes_max = 1 << 24;

fn address_of(index: u64) Address {
    var address: Address = @splat(0);
    address[0] = 0xd1;
    std.mem.writeInt(u16, address[18..20], @intCast(index), .big);
    return address;
}

/// The old builder's collection: per-key proofs and siblings, then the full replay.
const Reference = struct {
    scratch: witness.SparseState,
    touched: witness.KeySet,

    const Collector = struct {
        store: *witness.NodeStore,

        pub fn visit(self: Collector, bytes: []const u8) error{WitnessFull}!void {
            _ = try self.store.add(bytes);
        }
    };

    fn slot_hash(slot: u256) Hash {
        var key: [32]u8 = undefined;
        std.mem.writeInt(u256, &key, slot, .big);
        return keccak256(&key);
    }

    fn collect(self: *Reference, source: anytype, changeset: *const Changeset) !void {
        const collector: Collector = .{ .store = self.scratch.nodes };
        for (self.touched.accounts.slice()) |*address| {
            try source.visit_account_proof(&keccak256(address), collector);
        }
        for (self.touched.slots.slice()) |*key| {
            const address_hash = keccak256(&key.address);
            try source.visit_storage_proof(&address_hash, &slot_hash(key.slot), collector);
        }
        for (changeset.account_changes()) |*change| {
            if (change.new != null) continue;
            try source.visit_account_siblings(&keccak256(&change.address), collector);
        }
        for (changeset.storage_changes()) |*change| {
            if (change.new != 0) continue;
            const address_hash = keccak256(&change.address);
            try source.visit_storage_siblings(&address_hash, &slot_hash(change.slot), collector);
        }
    }

    fn build(
        self: *Reference,
        source: anytype,
        reads: *const witness.KeySet,
        changeset: *const Changeset,
        out: *witness.Witness,
    ) !Hash {
        out.clear();
        self.touched.clear();
        try self.touched.merge(reads);
        for (changeset.account_changes()) |*change| try self.touched.add_account(change.address);
        for (changeset.storage_changes()) |*change| {
            try self.touched.add_slot(change.address, change.slot);
        }
        self.scratch.reset(try source.pre_root(), .{ .number = 0, .hash = @splat(0) });
        try self.collect(source, changeset);
        try witness.replay(&self.scratch, reads, changeset);
        const nodes = self.scratch.nodes;
        for (nodes.entries[0..nodes.count]) |*entry| {
            if (entry.accessed) try out.state.append(nodes.arena[entry.offset..][0..entry.len]);
        }
        for (self.touched.codes.slice()) |hash| {
            if (std.mem.eql(u8, &hash, &trie.node.empty_code_hash)) continue;
            try out.codes.append(source.code_by_hash(hash) orelse return error.UnknownCode);
        }
        for (self.touched.accounts.slice()) |*address| try out.keys.append(address);
        for (self.touched.slots.slice()) |key| {
            var slot: [32]u8 = undefined;
            std.mem.writeInt(u256, &slot, key.slot, .big);
            try out.keys.append(&slot);
        }
        return self.scratch.state_root();
    }
};

const Fixture = struct {
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    recorder: witness.Recorder,
    builder: witness.Builder,
    reference: Reference,
    store: history.Store,
    built: witness.Witness,
    expected: witness.Witness,
    encoder: codec.Encoder,
    built_bytes: []u8,
    expected_bytes: []u8,

    /// In place: the overlay and recorder point into the fixture.
    fn init(fixture: *Fixture) !void {
        const allocator = testing.allocator;
        fixture.state = try State.init(allocator, state_config);
        try fixture.state.state_trie.track_changes(allocator);
        fixture.overlay = try Overlay.init(allocator, &fixture.state, overlay_config);
        fixture.changeset = try Changeset.init(allocator, changeset_config);
        const inner = evm_backend.database(&fixture.state);
        fixture.recorder = try witness.Recorder.init(allocator, inner, keys_config);
        fixture.builder = try witness.Builder.init(allocator, .{
            .sparse = sparse_config,
            .keys = keys_config,
        });
        fixture.reference = .{
            .scratch = try witness.SparseState.init(allocator, sparse_config),
            .touched = try witness.KeySet.init(allocator, keys_config),
        };
        fixture.store = try history.Store.init(allocator, history_config);
        fixture.built = try witness.Witness.init(allocator, witness_config);
        fixture.expected = try witness.Witness.init(allocator, witness_config);
        fixture.encoder = try codec.Encoder.init(allocator, witness_config);
        fixture.built_bytes = try allocator.alloc(u8, encoded_bytes_max);
        fixture.expected_bytes = try allocator.alloc(u8, encoded_bytes_max);
    }

    fn deinit(fixture: *Fixture) void {
        const allocator = testing.allocator;
        allocator.free(fixture.expected_bytes);
        allocator.free(fixture.built_bytes);
        fixture.encoder.deinit(allocator);
        fixture.expected.deinit(allocator);
        fixture.built.deinit(allocator);
        fixture.store.deinit(allocator);
        fixture.reference.touched.deinit(allocator);
        fixture.reference.scratch.deinit(allocator);
        fixture.builder.deinit(allocator);
        fixture.recorder.deinit(allocator);
        fixture.changeset.deinit(allocator);
        fixture.overlay.deinit(allocator);
        fixture.state.deinit(allocator);
    }

    /// The builder's witness from `source` encodes to the reference's bytes, verified or not.
    fn expect_same(fixture: *Fixture, source: anytype) !void {
        const keys = &fixture.recorder.keys;
        const changeset = &fixture.changeset;
        const root = try fixture.reference.build(source, keys, changeset, &fixture.expected);
        const expected_size = try fixture.encoder.encode(&fixture.expected, fixture.expected_bytes);
        const expected = fixture.expected_bytes[0..expected_size];
        for ([_]bool{ true, false }) |verify_root| {
            const built_root = try fixture.builder.build_with(
                source,
                keys,
                changeset,
                &.{},
                &fixture.built,
                .{ .verify_root = verify_root },
            );
            try testing.expectEqual(verify_root, built_root != null);
            if (built_root) |found| try testing.expectEqual(root, found);
            try testing.expectEqual(fixture.expected.state.count, fixture.built.state.count);
            const size = try fixture.encoder.encode(&fixture.built, fixture.built_bytes);
            try testing.expectEqualSlices(u8, expected, fixture.built_bytes[0..size]);
        }
    }
};

fn genesis(prng: *Prng, fixture: *Fixture) !void {
    const overlay = &fixture.overlay;
    for (0..genesis_accounts) |index| {
        const address = address_of(index);
        try overlay.set_account(address, .{ .nonce = 1, .balance = prng.below(1 << 40) });
        for (0..prng.below(24)) |_| {
            try overlay.set_storage(address, prng.below(slot_ids), prng.range(1, 1 << 20));
        }
    }
    _ = try overlay.commit(&fixture.changeset);
}

fn random_reads(prng: *Prng, recorder: *witness.Recorder) !void {
    const database = recorder.database();
    for (0..prng.range(1, 48)) |_| {
        const address = address_of(prng.below(addresses_total));
        if (prng.chance(1, 2)) {
            _ = try database.basic(address);
        } else {
            _ = try database.storage(address, prng.below(slot_ids));
        }
    }
}

/// Random writes; with `deletes` false only puts (no deleted account, slot, or wipe).
fn random_writes(prng: *Prng, overlay: *Overlay, deletes: bool) !void {
    for (0..prng.range(1, 64)) |_| {
        const address = address_of(prng.below(addresses_total));
        const exists = overlay.basic(address) != null;
        const kind = if (deletes) prng.below(10) else prng.below(7);
        switch (kind) {
            0...2 => try overlay.set_account(address, .{ .nonce = prng.below(9) }),
            3...6 => if (exists) {
                const zero = deletes and prng.chance(1, 2);
                const value = if (zero) 0 else prng.range(1, 1 << 20);
                try overlay.set_storage(address, prng.below(slot_ids), value);
            },
            7, 8 => if (exists) try overlay.set_account(address, null),
            else => if (exists) try overlay.wipe_storage(address),
        }
    }
}

fn run_block(prng: *Prng, fixture: *Fixture, number: u64) !void {
    fixture.recorder.keys.clear();
    try fixture.store.reset(&fixture.state.state_trie, number);
    try random_reads(prng, &fixture.recorder);
    try random_writes(prng, &fixture.overlay, prng.chance(2, 3));
    try fixture.overlay.build_changeset(&fixture.changeset);
    try fixture.expect_same(fixture.builder.state_source(&fixture.state));
    const source: witness.HistorySource = .{
        .store = &fixture.store,
        .number = number,
        .codes = &fixture.state,
    };
    try fixture.expect_same(source);
    _ = try fixture.overlay.commit(&fixture.changeset);
}

test "witness differential: sorted multi-key builder equals per-key proofs + replay" {
    var seed: u64 = 0;
    while (seed < seeds_count) : (seed += 1) {
        var prng = Prng.init(0xd1ff + seed);
        const fixture = try testing.allocator.create(Fixture);
        defer testing.allocator.destroy(fixture);
        try fixture.init();
        defer fixture.deinit();
        try genesis(&prng, fixture);
        for (0..blocks_per_seed) |block| try run_block(&prng, fixture, block);
    }
}

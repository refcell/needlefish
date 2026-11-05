//! Client end to end over the in-process oracle: devnet boot inputs, a genesis safe
//! head and an L1 chain without batches, so derivation runs out of L1 data at the safe
//! head and the computed output root is the agreed one.

const std = @import("std");
const testing = std.testing;

const preimage = @import("../preimage/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const chains = @import("../../common/chains/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const json = @import("../../utilities/json/root.zig");
const program = @import("../program/root.zig");
const test_oracle = @import("../test_oracle.zig");
const client = @import("client.zig");

const Hash = [32]u8;
const B256 = primitives.B256;
const LocalKey = program.boot.LocalKey;

const builder_config: @import("../executor/root.zig").builder.Config = .{
    .sparse = .{
        .nodes_max = 256,
        .node_bytes_max = 1 << 16,
        .codes_max = 4,
        .code_bytes_max = 1 << 14,
        .headers_max = 4,
        .trie_nodes_max = 1024,
        .storage_tries_max = 8,
    },
    .changeset = .{
        .accounts_max = 64,
        .storage_max = 256,
        .codes_max = 8,
        .code_bytes_max = 1 << 14,
    },
    .executor = .{
        .scratch_bytes = 1 << 16,
        .transactions_max = 8,
        .evm = .{ .memory_bytes_max = 1 << 16, .code_arena_bytes = 1 << 16 },
        .limits = .{
            .accounts_max = 64,
            .slots_max = 256,
            .transient_slots_max = 16,
            .journal_entries_max = 1024,
            .logs_max = 16,
            .log_data_bytes_max = 1024,
            .code_bytes_max = 1 << 14,
        },
    },
    .resolver = .{ .bytes_max = 1 << 18, .entries_max = 1024 },
};

var kzg_storage: kzg.blob.Settings.Storage = undefined;
var kzg_workspace: kzg.blob.Workspace = undefined;

const Fixture = struct {
    store: test_oracle.MapStore,
    rollup: protocol.RollupConfig,
    l1_hashes: [3]B256 = undefined,
    agreed: Hash = undefined,

    fn put_header(fixture: *Fixture, header: consensus.Header) !B256 {
        var buffer: [1024]u8 = undefined;
        const hash = header.hash();
        try fixture.store.put(.keccak256(hash.bytes), rlp.encode_to(&buffer, header));
        return hash;
    }

    fn put_u64(fixture: *Fixture, local: LocalKey, value: u64) !void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        try fixture.store.put(local.key(), &bytes);
    }

    fn init(fixture: *Fixture, claim_matches: bool) !void {
        fixture.store = .init();
        // The empty trie root's preimage, for empty transaction and receipt tries.
        try fixture.store.put_node(&.{0x80});
        var parent: B256 = .zero;
        for (&fixture.l1_hashes, 0..) |*hash, number| {
            hash.* = try fixture.put_header(.{
                .parent_hash = parent,
                .number = number,
                .timestamp = 12 * number,
            });
            parent = hash.*;
        }
        const l2_genesis = try fixture.put_header(.{ .number = 0, .gas_limit = 30_000_000 });
        fixture.rollup = .{
            .l1_chain_id = chains.l1_devnet.chain_id,
            .l2_chain_id = chains.devnet.chain_id,
            .block_time = 2,
            .seq_window_size = 3600,
            .max_sequencer_drift = 600,
            .channel_timeout = 300,
            .batch_inbox_address = .{ .bytes = @splat(0xbb) },
        };
        fixture.rollup.genesis = .{
            .l1 = .{ .number = 0, .hash = fixture.l1_hashes[0] },
            .l2 = .{ .number = 0, .hash = l2_genesis },
            .system_config = .{
                .batcher_address = .{ .bytes = @splat(0xba) },
                .gas_limit = 30_000_000,
            },
        };
        const output: program.sync.OutputRoot = .{
            .state_root = @splat(1),
            .message_passer_storage_root = @splat(2),
            .block_hash = l2_genesis.bytes,
        };
        const encoded = output.encode();
        fixture.agreed = keccak.keccak256(&encoded);
        try fixture.store.put(.keccak256(fixture.agreed), &encoded);
        const claim: Hash = if (claim_matches) fixture.agreed else @splat(0xcc);
        try fixture.put_boot(claim);
    }

    fn put_boot(fixture: *Fixture, claim: Hash) !void {
        try fixture.store.put(LocalKey.l1_head.key(), &fixture.l1_hashes[2].bytes);
        try fixture.store.put(LocalKey.l2_output_root.key(), &fixture.agreed);
        try fixture.store.put(LocalKey.l2_claim.key(), &claim);
        try fixture.put_u64(.l2_claim_block_number, 1);
        try fixture.put_u64(.l2_chain_id, chains.devnet.chain_id);
        var json_buffer: [8192]u8 = undefined;
        var out: std.Io.Writer = .fixed(&json_buffer);
        var writer = json.Writer.init(&out);
        try protocol.rollup_json.write(&writer, &fixture.rollup);
        try fixture.store.put(LocalKey.l2_rollup_config.key(), out.buffered());
        try fixture.store.put(LocalKey.proposer.key(), "");
        try fixture.put_u64(.intermediate_block_interval, 1);
        try fixture.store.put(LocalKey.l1_head_number.key(), "");
        try fixture.store.put(LocalKey.l2_schedule_block_number.key(), "");
    }

    fn run(fixture: *Fixture) !struct { client.Outcome, bool } {
        var harness: preimage.InProcess = undefined;
        const fetcher = fixture.store.fetcher();
        try harness.init(testing.allocator, fetcher, preimage.in_process.ignore_hints, .{
            .channel_bytes = 1 << 16,
        });
        defer harness.deinit(testing.allocator);
        kzg.blob.fill_roots_brp(&kzg_storage.roots_brp);
        const settings: kzg.blob.Settings = .{
            .g1_lagrange = &kzg_storage.g1_lagrange,
            .roots_brp = &kzg_storage.roots_brp,
        };
        const io: client.Client.Io = .{
            .oracle = harness.oracle_reader(),
            .hints = harness.hint_writer(),
        };
        const outcome = try client.run(testing.allocator, io, .{
            .builder = builder_config,
            .resolver = .{ .bytes_max = 1 << 18, .entries_max = 1024 },
            .l1 = .{ .items_max = 16, .logs_max = 16, .topics_max = 64, .blob_hashes_max = 16 },
            .l2 = .{ .items_max = 16 },
            .blobs = .{ .blobs_max = 2, .verify = false },
            .kzg_settings = &settings,
            .kzg_workspace = &kzg_workspace,
        });
        var scratch: [program.boot.rollup_config_bytes_max]u8 = undefined;
        const boot = try program.BootInfo.load(harness.oracle_reader(), &scratch);
        return .{ outcome, client.claim_holds(&boot, &outcome) };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.store.deinit();
    }
};

test "client: derivation halts at the safe head when L1 has no batches" {
    var fixture: Fixture = undefined;
    try fixture.init(true);
    defer fixture.deinit();
    const outcome, const holds = try fixture.run();
    try testing.expect(outcome.exhausted);
    try testing.expectEqual(@as(u64, 0), outcome.block_number);
    try testing.expectEqual(fixture.agreed, outcome.output_root);
    try testing.expect(holds);
}

test "client: a claim that differs from the computed output root fails" {
    var fixture: Fixture = undefined;
    try fixture.init(false);
    defer fixture.deinit();
    _, const holds = try fixture.run();
    try testing.expect(!holds);
}

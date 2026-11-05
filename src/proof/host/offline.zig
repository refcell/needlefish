//! Offline mode: replay a recorded preimage archive through the fault-proof client
//! (base/base `backend/offline.rs`: stored keys only, hints ignored).

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const client = @import("../client/root.zig");
const program = @import("../program/root.zig");
const archive = @import("archive.zig");
const store_module = @import("store.zig");

pub const Verdict = struct {
    outcome: client.Outcome,
    claimed_output_root: [32]u8,
    holds: bool,
};

pub const Error = archive.DecodeError || client.client.Error || error{ReplayFailed};

/// Runs the client over the preimages of `bytes` (an archive).
pub fn replay(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: client.client.Options,
) Error!Verdict {
    var store: store_module.Store = .init(allocator, .{});
    defer store.deinit();
    try archive.decode(bytes, &store);
    var harness: preimage.InProcess = undefined;
    harness.init(allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
        .channel_bytes = 1 << 20,
    }) catch return error.ReplayFailed;
    defer harness.deinit(allocator);
    const io: client.Client.Io = .{
        .oracle = harness.oracle_reader(),
        .hints = harness.hint_writer(),
    };
    const outcome = try client.run(allocator, io, options);
    var scratch: [program.boot.rollup_config_bytes_max]u8 = undefined;
    const boot = try program.BootInfo.load(harness.oracle_reader(), &scratch);
    const holds = client.claim_holds(&boot, &outcome);
    assert(holds == std.mem.eql(u8, &outcome.output_root, &boot.claimed_l2_output_root));
    const claimed = boot.claimed_l2_output_root;
    return .{ .outcome = outcome, .claimed_output_root = claimed, .holds = holds };
}

const testing = std.testing;
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const chains = @import("../../common/chains/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const json = @import("../../utilities/json/root.zig");

fn put_header(store: *store_module.Store, header: consensus.Header) ![32]u8 {
    var buffer: [1024]u8 = undefined;
    return store.put_keccak(rlp.encode_to(&buffer, header));
}

/// A genesis safe head and an L1 chain without batches (as in `client_test`), recorded
/// into a store. Returns the agreed output root.
fn record(store: *store_module.Store, claim_matches: bool, json_buffer: []u8) ![32]u8 {
    _ = try store.put_ordered_list(&.{});
    var l1: [3][32]u8 = undefined;
    var parent: [32]u8 = @splat(0);
    for (&l1, 0..) |*hash, number| {
        hash.* = try put_header(store, .{
            .parent_hash = .{ .bytes = parent },
            .number = number,
            .timestamp = 12 * number,
        });
        parent = hash.*;
    }
    const l2_genesis = try put_header(store, .{ .number = 0, .gas_limit = 30_000_000 });
    var rollup: protocol.RollupConfig = .{
        .l1_chain_id = chains.l1_devnet.chain_id,
        .l2_chain_id = chains.devnet.chain_id,
        .block_time = 2,
        .seq_window_size = 3600,
        .max_sequencer_drift = 600,
        .channel_timeout = 300,
    };
    rollup.genesis = .{
        .l1 = .{ .number = 0, .hash = .{ .bytes = l1[0] } },
        .l2 = .{ .number = 0, .hash = .{ .bytes = l2_genesis } },
        .system_config = .{ .gas_limit = 30_000_000 },
    };
    const output: program.sync.OutputRoot = .{
        .state_root = @splat(1),
        .message_passer_storage_root = @splat(2),
        .block_hash = l2_genesis,
    };
    const agreed = try store.put_keccak(&output.encode());
    var out: std.Io.Writer = .fixed(json_buffer);
    var writer = json.Writer.init(&out);
    try protocol.rollup_json.write(&writer, &rollup);
    try store.put_boot(&.{
        .l1_head = l1[2],
        .agreed_l2_output_root = agreed,
        .claimed_l2_output_root = if (claim_matches) agreed else @splat(0xcc),
        .claimed_l2_block_number = 1,
        .chain_id = chains.devnet.chain_id,
        .rollup_config_json = out.buffered(),
    });
    return agreed;
}

var kzg_storage: kzg.blob.Settings.Storage = undefined;
var kzg_workspace: kzg.blob.Workspace = undefined;

fn replay_recorded(claim_matches: bool) !Verdict {
    var store: store_module.Store = .init(testing.allocator, .{});
    defer store.deinit();
    var json_buffer: [8192]u8 = undefined;
    _ = try record(&store, claim_matches, &json_buffer);
    const keys = try testing.allocator.alloc([32]u8, store.count());
    defer testing.allocator.free(keys);
    const bytes = try testing.allocator.alloc(u8, @intCast(archive.encoded_bytes(&store)));
    defer testing.allocator.free(bytes);
    var writer: std.Io.Writer = .fixed(bytes);
    try archive.encode(&store, keys, &writer);
    kzg.blob.fill_roots_brp(&kzg_storage.roots_brp);
    const settings: kzg.blob.Settings = .{
        .g1_lagrange = &kzg_storage.g1_lagrange,
        .roots_brp = &kzg_storage.roots_brp,
    };
    return replay(testing.allocator, bytes, .{
        .builder = small_builder_config,
        .resolver = .{ .bytes_max = 1 << 18, .entries_max = 1024 },
        .l1 = .{ .items_max = 16, .logs_max = 16, .topics_max = 64, .blob_hashes_max = 16 },
        .l2 = .{ .items_max = 16 },
        .blobs = .{ .blobs_max = 1, .verify = false },
        .kzg_settings = &settings,
        .kzg_workspace = &kzg_workspace,
    });
}

const small_builder_config: @import("../executor/root.zig").builder.Config = .{
    .sparse = .{
        .nodes_max = 64,
        .node_bytes_max = 1 << 14,
        .codes_max = 4,
        .code_bytes_max = 1 << 12,
        .headers_max = 4,
        .trie_nodes_max = 256,
        .storage_tries_max = 4,
    },
    .changeset = .{
        .accounts_max = 16,
        .storage_max = 64,
        .codes_max = 4,
        .code_bytes_max = 1 << 12,
    },
    .executor = .{
        .scratch_bytes = 1 << 14,
        .transactions_max = 4,
        .evm = .{ .memory_bytes_max = 1 << 14, .code_arena_bytes = 1 << 14 },
        .limits = .{
            .accounts_max = 16,
            .slots_max = 64,
            .transient_slots_max = 8,
            .journal_entries_max = 256,
            .logs_max = 8,
            .log_data_bytes_max = 256,
            .code_bytes_max = 1 << 12,
        },
    },
    .resolver = .{ .bytes_max = 1 << 16, .entries_max = 256 },
};

test "offline: a recorded archive replays to the claim verdict" {
    const holds = try replay_recorded(true);
    try testing.expect(holds.holds);
    try testing.expect(holds.outcome.exhausted);
    const fails = try replay_recorded(false);
    try testing.expect(!fails.holds);
    try testing.expectEqual(holds.outcome.output_root, fails.outcome.output_root);
}

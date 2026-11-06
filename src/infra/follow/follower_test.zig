//! The follower over the committed ten-block Base mainnet fixture (`replay/testdata`), with
//! the witness served only on demand, the way `base follow` fetches it: every node and code
//! the follower asks for (by hash) is looked up in the archive. Every block must verify, and
//! a rebase must recover from data lost with the store.

const std = @import("std");
const testing = std.testing;

const chainspec = @import("../../execution/chainspec/root.zig");
const Header = @import("../../common/consensus/root.zig").Header;
const trie = @import("../../execution/trie/root.zig");
const keccak256 = trie.node.keccak256;
const replay = @import("../replay/root.zig");
const mainnet_test = @import("../replay/mainnet_test.zig");
const follower_module = @import("follower.zig");

const Archive = replay.Archive;
const Follower = follower_module.Follower;
const Hash = [32]u8;

/// Serves archive nodes and codes by hash and remembers what it served, so it can serve it
/// again after a rebase (a real driver refetches).
const Server = struct {
    archive: *const Archive,
    nodes: std.AutoHashMapUnmanaged(Hash, u32) = .empty,
    codes: std.AutoHashMapUnmanaged(Hash, u32) = .empty,
    served_nodes: std.ArrayList(u32) = .empty,
    served_codes: std.ArrayList(u32) = .empty,
    given: std.AutoHashMapUnmanaged(Hash, void) = .empty,

    fn init(allocator: std.mem.Allocator, archive: *const Archive) !Server {
        var server: Server = .{ .archive = archive };
        const state = &archive.witness.state;
        for (0..state.count) |index| {
            try server.nodes.put(allocator, keccak256(state.get(@intCast(index))), @intCast(index));
        }
        const codes = &archive.witness.codes;
        for (0..codes.count) |index| {
            try server.codes.put(allocator, keccak256(codes.get(@intCast(index))), @intCast(index));
        }
        return server;
    }

    fn deinit(server: *Server, allocator: std.mem.Allocator) void {
        server.nodes.deinit(allocator);
        server.codes.deinit(allocator);
        server.served_nodes.deinit(allocator);
        server.served_codes.deinit(allocator);
        server.given.deinit(allocator);
    }

    /// Serves the follower's gaps, each node with every archive node below it (what proofs
    /// of the keys under it would bring); returns how many nodes and codes were served.
    fn serve(server: *Server, allocator: std.mem.Allocator, follower: *Follower) !u32 {
        const gaps = &follower.gaps;
        var served: u32 = 0;
        var stack: std.ArrayList(Hash) = .empty;
        defer stack.deinit(allocator);
        try stack.appendSlice(allocator, gaps.nodes[0..gaps.nodes_len]);
        while (stack.pop()) |hash| {
            const index = server.nodes.get(hash) orelse continue;
            if (server.given.contains(hash)) continue;
            try server.given.put(allocator, hash, {});
            try server.served_nodes.append(allocator, index);
            const bytes = server.archive.witness.state.get(index);
            try follower.add_node(bytes);
            served += 1;
            const decoded = trie.sparse.decode_node(bytes) catch continue;
            for (&decoded.children) |*child| {
                if (child.len == 0 or !child.is_hash()) continue;
                try stack.append(allocator, child.bytes[1..33].*);
            }
        }
        for (gaps.codes[0..gaps.codes_len]) |hash| {
            const index = server.codes.get(hash) orelse continue;
            try server.served_codes.append(allocator, index);
            try follower.add_code(server.archive.witness.codes.get(index));
            served += 1;
        }
        return served;
    }

    fn refill(server: *const Server, follower: *Follower) !void {
        for (server.served_nodes.items) |index| {
            try follower.add_node(server.archive.witness.state.get(index));
        }
        for (server.served_codes.items) |index| {
            try follower.add_code(server.archive.witness.codes.get(index));
        }
    }
};

fn block_of(archive: *const Archive, index: u32, views: [][]const u8) !follower_module.Block {
    const header_rlp = archive.block_header(index);
    const header = try Header.decode(header_rlp);
    const count = archive.transaction_count(index);
    for (views[0..count], 0..) |*view, position| {
        view.* = archive.transaction(index, @intCast(position));
    }
    return .{
        .number = header.number,
        .hash = keccak256(header_rlp),
        .parent_hash = header.parent_hash.bytes,
        .header_rlp = header_rlp,
        .transactions = views[0..count],
    };
}

fn test_config() follower_module.Config {
    var config = follower_module.default_config();
    config.sparse.nodes_max = 1 << 17;
    config.sparse.node_bytes_max = 64 << 20;
    config.sparse.codes_max = 1 << 11;
    config.sparse.code_bytes_max = 32 << 20;
    config.sparse.trie_nodes_max = 1 << 19;
    config.sparse.storage_tries_max = 1 << 14;
    config.executor.transactions_max = 1 << 10;
    return config;
}

fn start(follower: *Follower, archive: *const Archive) void {
    const ancestors = archive.ancestors[0..archive.ancestors_len];
    follower.start(.{
        .number = archive.first_ancestor_number() + archive.ancestors_len - 1,
        .hash = archive.parent_hash(),
        .state_root = archive.parent_state_root,
    }, ancestors);
}

/// Follows one block to a verified outcome the way the driver does.
fn follow_block(
    allocator: std.mem.Allocator,
    follower: *Follower,
    server: *Server,
    block: *const follower_module.Block,
) !follower_module.Outcome {
    var attempts: u32 = 0;
    while (attempts < 1024) : (attempts += 1) {
        const probed = try follower.probe(block);
        switch (probed) {
            .gaps => if (try server.serve(allocator, follower) == 0) {
                const gaps = &follower.gaps;
                std.debug.print("block {d} stuck: {d} nodes {d} slots {d} accounts\n", .{
                    block.number,
                    gaps.nodes_len,
                    gaps.slots_len,
                    gaps.accounts_len,
                });
                return error.NoProgress;
            },
            .full, .failed => return error.ProbeFailed,
            .ready => {
                // The archive's opaque branches stand in for `add_post_nodes`' (no post
                // proofs are stored); the derived siblings are witness nodes, served below.
                for (server.archive.opaque_branches[0..server.archive.opaque_len]) |hash| {
                    try follower.add_opaque(hash);
                }
                const outcome = try follower.verify(block);
                if (outcome.ok()) return outcome;
                if (!follower_module.retryable(&outcome)) return outcome;
                _ = try server.serve(allocator, follower);
                try server.refill(follower);
            },
        }
    }
    return error.NoProgress;
}

test "follow: ten Base mainnet blocks verify with the witness fetched on demand" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, mainnet_test.fixture_config);
    defer archive.deinit(allocator);
    try replay.archive.decode(allocator, mainnet_test.fixture, &archive);
    var server = try Server.init(allocator, &archive);
    defer server.deinit(allocator);

    const follower = try allocator.create(Follower);
    defer allocator.destroy(follower);
    try follower.init(allocator, &chainspec.ChainSpec.presets.base_mainnet, test_config());
    defer follower.deinit(allocator);
    start(follower, &archive);

    const views = try allocator.alloc([]const u8, 1 << 10);
    defer allocator.free(views);
    for (0..archive.block_count) |index| {
        const block = try block_of(&archive, @intCast(index), views);
        const outcome = try follow_block(allocator, follower, &server, &block);
        if (!outcome.ok()) std.debug.print("block {d}: {?t} {?t}\n", .{
            outcome.number,
            outcome.first_failed(),
            outcome.failure,
        });
        try testing.expect(outcome.ok());
        try testing.expectEqualSlices(u8, &block.hash, &follower.head.hash);
        // Midway, drop the trie: the store kept every node the follower computed, so the
        // rest of the chain verifies from the store and the archive (which holds no
        // post-state nodes).
        if (index == 4) follower.rebase();
    }
    try testing.expectEqual(@as(u64, 1), follower.stats.rebases);
    try testing.expectEqual(@as(u64, 10), follower.stats.blocks);
    try testing.expectEqual(@as(u64, 253), follower.stats.transactions);
    // On-demand fetching needed more than one pass for some block, and fewer nodes than the
    // whole witness.
    try testing.expect(follower.stats.probe_passes > archive.block_count);
    try testing.expect(server.served_nodes.items.len <= archive.witness.state.count);

    // The chain moved on: block 0 is no longer the head's child.
    const stale = try block_of(&archive, 0, views);
    try testing.expectError(error.NotChild, follower.probe(&stale));
}

test "follow: a block whose hash disagrees with its header is a mismatch" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, mainnet_test.fixture_config);
    defer archive.deinit(allocator);
    try replay.archive.decode(allocator, mainnet_test.fixture, &archive);
    var server = try Server.init(allocator, &archive);
    defer server.deinit(allocator);
    const follower = try allocator.create(Follower);
    defer allocator.destroy(follower);
    try follower.init(allocator, &chainspec.ChainSpec.presets.base_mainnet, test_config());
    defer follower.deinit(allocator);
    start(follower, &archive);
    const views = try allocator.alloc([]const u8, 1 << 10);
    defer allocator.free(views);
    var block = try block_of(&archive, 0, views);
    block.hash[31] ^= 1;
    const outcome = try follow_block(allocator, follower, &server, &block);
    try testing.expect(!outcome.ok());
    try testing.expectEqual(@as(?replay.replayer.Check, .block_hash), outcome.first_failed());
    try testing.expect(follower.broken);
    // Nothing advanced: the head is still the fixture's parent.
    try testing.expectEqual(@as(u64, 0), follower.stats.blocks);
    try testing.expectEqualSlices(u8, &archive.parent_hash(), &follower.head.hash);
}

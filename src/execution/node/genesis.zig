//! Loads a parsed genesis into the node: chain spec, allocation into `StateDb`, and the
//! genesis header (whose hash must equal what `base devnet init` writes to rollup.json).

const std = @import("std");
const assert = std.debug.assert;
const genesis = @import("../../common/genesis/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../chainspec/root.zig");
const StateDb = @import("state_db.zig").StateDb;

pub const Error = error{StateRootMismatch} || chainspec.from_genesis_module.Error ||
    @import("state_db.zig").Error || genesis.state.Error;

/// Writes every allocated account into `db` (which must be empty) and returns the
/// genesis header. `allocator` is only used for the header's Isthmus storage root.
pub fn load(
    allocator: std.mem.Allocator,
    db: *StateDb,
    parsed: *const genesis.Genesis,
) Error!consensus.Header {
    assert(db.trie().account_count() == 0);
    for (parsed.accounts) |*account| {
        try db.put_account(account.address.bytes, account.balance, account.nonce, account.code);
        for (account.storage) |slot| {
            const key = std.mem.readInt(u256, &slot.key.bytes, .big);
            const value = slot.value;
            if (value != 0) try db.put_storage(account.address.bytes, key, value);
        }
    }
    const root = try db.root();
    if (parsed.state_root) |expected| {
        if (!std.mem.eql(u8, &expected.bytes, &root)) return error.StateRootMismatch;
    }
    const header = try parsed.header(allocator, .{ .bytes = root });
    assert(header.number == parsed.number);
    return header;
}

const testing = std.testing;
const devnet = @import("../../batcher/devnet/root.zig");

fn load_and_hash(text: []const u8) ![32]u8 {
    const parsed = try genesis.parse(testing.allocator, text);
    defer parsed.deinit();
    var db = try StateDb.init(testing.allocator, .{
        .trie = .{
            .accounts_max = 256,
            .account_nodes_max = 1 << 12,
            .storage_nodes_max = 1 << 12,
        },
        .code_bytes_max = 1 << 18,
        .codes_max = 64,
        .undo_bytes_max = 1 << 16,
    });
    defer db.deinit(testing.allocator);
    const header = try load(testing.allocator, &db, &parsed.value);
    const root = try parsed.value.compute_state_root(testing.allocator);
    try testing.expectEqualSlices(u8, &root.bytes, &header.state_root.bytes);
    _ = try chainspec.from_genesis(&parsed.value);
    return header.hash().bytes;
}

test "genesis: devnet L1 and L2 genesis hashes match the devnet rollup anchor" {
    const config: devnet.genesis.Config = .{ .genesis_timestamp = 1_700_000_000 };
    const anchor = try devnet.genesis.compute_anchor(testing.allocator, &config);
    var buffer: [64 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);
    try devnet.genesis.write_l1_genesis(&w, &config);
    try testing.expectEqualSlices(u8, &anchor.l1_hash, &(try load_and_hash(w.buffered())));
    w = .fixed(&buffer);
    try devnet.genesis.write_l2_genesis(&w, &config);
    try testing.expectEqualSlices(u8, &anchor.l2_hash, &(try load_and_hash(w.buffered())));
}

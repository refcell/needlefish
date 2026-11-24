//! Diff adapter end to end: a synthetic genesis as a complete witness, a build-mode block
//! with valid and invalid transactions through `handle_line`, its state root checked
//! against an independently built post-state, validate mode on the block it built, and
//! `ok: false` for a witness that lacks a node.

const std = @import("std");
const testing = std.testing;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const db = @import("../../execution/db/root.zig");
const diff = @import("root.zig");

const hex = primitives.hex;
const Address = [20]u8;
const SparseState = db.witness.SparseState;
const spec = &chainspec.ChainSpec.presets.base_mainnet;

/// Jovian is active and Azul is not: no Osaka gas cap, no BaseTime predeploy.
const timestamp: u64 = 1_770_000_000;
const parent_base_fee: u64 = 1_000;
/// What the parent implies (see the build test), so validate mode accepts the block.
const base_fee: u64 = 1_008;
const coinbase: Address = address_hex("4200000000000000000000000000000000000011");
const base_fee_vault: Address = address_hex("4200000000000000000000000000000000000019");
const recipient: Address = @splat(0x33);
const ether: u256 = 1_000_000_000_000_000_000;

fn address_hex(comptime text: []const u8) Address {
    return comptime hex.decode_array(20, text) catch unreachable;
}

fn key(n: u8) [32]u8 {
    var bytes: [32]u8 = @splat(0);
    bytes[31] = n;
    return bytes;
}

fn address_of(n: u8) Address {
    return consensus.signature.address_from_private(key(n)).?.bytes;
}

const Account = struct { address: Address, info: db.AccountInfo };

/// A trie of `accounts` built from empty: every node the trie hashes is a witness node.
const Genesis = struct {
    sparse: SparseState,
    root: [32]u8,

    fn init(genesis: *Genesis, accounts: []const Account) !void {
        genesis.sparse = try SparseState.init(testing.allocator, .{
            .nodes_max = 1024,
            .node_bytes_max = 1 << 20,
            .codes_max = 16,
            .code_bytes_max = 1 << 16,
            .headers_max = 1,
            .trie_nodes_max = 1 << 14,
            .storage_tries_max = 64,
        });
        genesis.sparse.reset(primitives.empty_root_hash.bytes, .{ .number = 0, .hash = @splat(0) });
        genesis.sparse.keep_new_nodes(true);
        var changeset = try db.Changeset.init(testing.allocator, .{
            .accounts_max = 64,
            .storage_max = 64,
            .codes_max = 1,
            .code_bytes_max = 1,
        });
        defer changeset.deinit(testing.allocator);
        for (accounts) |account| {
            const change: db.changeset.AccountChange = .{
                .address = account.address,
                .old = null,
                .new = account.info,
            };
            try changeset.add_account(change);
        }
        changeset.sort();
        try genesis.sparse.apply(&changeset);
        genesis.root = genesis.sparse.state_root();
    }

    fn deinit(genesis: *Genesis) void {
        genesis.sparse.deinit(testing.allocator);
    }

    /// The witness nodes as a JSON array body (`"0x..","0x.."`), skipping `skip` (an index).
    fn nodes_json(genesis: *const Genesis, out: *std.Io.Writer, skip: ?u32) !void {
        const store = genesis.sparse.nodes;
        var first = true;
        for (store.entries[0..store.count], 0..) |entry, index| {
            if (skip != null and skip.? == index) continue;
            if (!first) try out.writeAll(",");
            first = false;
            try hex_string(out, store.arena[entry.offset..][0..entry.len]);
        }
    }
};

fn hex_string(out: *std.Io.Writer, bytes: []const u8) !void {
    try out.writeAll("\"0x");
    for (bytes) |byte| try out.print("{x:0>2}", .{byte});
    try out.writeAll("\"");
}

fn transfer(buffer: []u8, from: u8, nonce: u64, max_fee: u128) ![]const u8 {
    return send(buffer, from, nonce, max_fee, recipient, 5);
}

fn send(
    buffer: []u8,
    from: u8,
    nonce: u64,
    max_fee: u128,
    to: Address,
    value: u256,
) ![]const u8 {
    const tx: consensus.Eip1559 = .{
        .chain_id = spec.chain_id,
        .nonce = nonce,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = max_fee,
        .gas_limit = 21_000,
        .to = .{ .call = .{ .bytes = to } },
        .value = value,
        .input = &.{},
        .access_list = .empty,
    };
    return (try consensus.tx.sign(tx, key(from))).encode_to(buffer);
}

fn parent_header(state_root: [32]u8, extra: []const u8) consensus.Header {
    return .{
        .state_root = .{ .bytes = state_root },
        .number = 99,
        .gas_limit = 30_000_000,
        .gas_used = 15_000_000,
        .timestamp = timestamp - 2,
        .extra_data = extra,
        .base_fee_per_gas = parent_base_fee,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .zero,
        .requests_hash = consensus.block.empty_requests_hash,
    };
}

const Lines = struct {
    out: std.Io.Writer.Allocating,
    /// Leave out the transactions build mode rejects (the block it built).
    only_valid: bool = false,
    /// Replaces the default transactions.
    transactions: ?[]const []const u8 = null,

    fn request(lines: *Lines, genesis: *const Genesis, mode: []const u8, skip: ?u32) ![]const u8 {
        return lines.request_with(genesis, mode, skip, null);
    }

    /// `results`: the canonical header's result fields, as a build response reports them.
    fn request_with(
        lines: *Lines,
        genesis: *const Genesis,
        mode: []const u8,
        skip: ?u32,
        results: ?std.json.ObjectMap,
    ) ![]const u8 {
        lines.out.clearRetainingCapacity();
        const w = &lines.out.writer;
        const extra = chainspec.basefee.encode_jovian(@splat(0), spec.base_fee_params_canyon, 0);
        const parent = parent_header(genesis.root, &extra);
        var parent_buffer: [1024]u8 = undefined;
        try w.print("{{\"id\":\"t-{s}\",\"chain\":\"base-mainnet\",", .{mode});
        try w.print("\"mode\":\"{s}\",", .{mode});
        try w.writeAll("\"ancestors\":[");
        try hex_string(w, rlp.encode_to(&parent_buffer, parent));
        try w.print("],\"header\":{{\"number\":\"0x64\",\"timestamp\":\"0x{x}\",", .{timestamp});
        try w.writeAll("\"coinbase\":");
        try hex_string(w, &coinbase);
        try w.writeAll(",\"prevRandao\":");
        try hex_string(w, &@as([32]u8, @splat(0x77)));
        try w.print(",\"gasLimit\":\"0x1c9c380\",\"baseFeePerGas\":\"0x{x}\",", .{base_fee});
        try w.writeAll("\"extraData\":");
        try hex_string(w, &extra);
        try w.writeAll(",\"parentBeaconBlockRoot\":");
        try hex_string(w, &@as([32]u8, @splat(0x55)));
        try w.writeAll(",\"excessBlobGas\":\"0x0\"");
        if (results) |fields| {
            var it = fields.iterator();
            while (it.next()) |field| {
                try w.print(",\"{s}\":\"{s}\"", .{ field.key_ptr.*, field.value_ptr.string });
            }
        }
        return lines.finish(genesis, skip);
    }

    fn finish(lines: *Lines, genesis: *const Genesis, skip: ?u32) ![]const u8 {
        const w = &lines.out.writer;
        try w.writeAll("},\"transactions\":[");
        var buffers: [4][256]u8 = undefined;
        const all = [_][]const u8{
            try transfer(&buffers[0], 1, 0, 2_000),
            try transfer(&buffers[1], 1, 0, 2_000), // Nonce too low.
            try transfer(&buffers[2], 2, 0, 10), // Max fee below the base fee.
            try transfer(&buffers[3], 1, 1, 2_000),
        };
        const included = [_][]const u8{ all[0], all[3] };
        const default: []const []const u8 = if (lines.only_valid) &included else &all;
        const transactions = lines.transactions orelse default;
        for (transactions, 0..) |raw, index| {
            if (index > 0) try w.writeAll(",");
            try hex_string(w, raw);
        }
        try w.writeAll("],\"witness\":{\"state\":[");
        try genesis.nodes_json(w, skip);
        try w.writeAll("],\"codes\":[]}}");
        return lines.out.written();
    }
};

const ReceiptFields = struct {
    type: []const u8,
    status: []const u8,
    cumulativeGasUsed: []const u8,
};

const Response = struct {
    id: []const u8,
    ok: bool,
    @"error": ?[]const u8 = null,
    valid: bool = false,
    invalidReason: ?[]const u8 = null,
    rejected: []const struct { index: u32, @"error": []const u8 } = &.{},
    header: ?std.json.Value = null,
    computedBaseFeePerGas: ?[]const u8 = null,
    receipts: []const ReceiptFields = &.{},
    post: ?std.json.Value = null,
};

fn answer(adapter: *diff.Adapter, arena: std.mem.Allocator, line: []const u8) !Response {
    var out: std.Io.Writer.Allocating = .init(arena);
    try diff.handle_line(adapter, arena, line, &out.writer, null);
    return std.json.parseFromSliceLeaky(Response, arena, out.written(), .{
        .ignore_unknown_fields = true,
    });
}

fn expect_account(post: std.json.Value, address: Address, nonce: u64, balance: u256) !void {
    var name: [42]u8 = undefined;
    hex.encode_prefixed(&name, &address);
    const account = post.object.get(&name) orelse return error.TestMissingAccount;
    var buffer: [66]u8 = undefined;
    const expected_nonce = hex.encode_quantity(&buffer, nonce);
    try testing.expectEqualStrings(expected_nonce, account.object.get("nonce").?.string);
    const expected_balance = hex.encode_quantity(&buffer, balance);
    try testing.expectEqualStrings(expected_balance, account.object.get("balance").?.string);
}

test "diff adapter: build mode skips invalid transactions and reports the block" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const accounts = [_]Account{
        .{ .address = address_of(1), .info = .{ .balance = 10 * ether } },
        .{ .address = address_of(2), .info = .{ .balance = ether } },
        .{ .address = coinbase, .info = .{ .balance = 7 } },
        .{ .address = @splat(0x44), .info = .{ .nonce = 3 } },
    };
    var genesis: Genesis = undefined;
    try genesis.init(&accounts);
    defer genesis.deinit();
    const adapter = try testing.allocator.create(diff.Adapter);
    defer testing.allocator.destroy(adapter);
    try adapter.init(testing.allocator);
    defer adapter.deinit();
    var lines: Lines = .{ .out = .init(testing.allocator) };
    defer lines.out.deinit();

    const built = try answer(adapter, arena, try lines.request(&genesis, "build", null));
    try testing.expect(built.ok);
    try testing.expect(built.valid);
    try testing.expectEqual(@as(usize, 2), built.rejected.len);
    try testing.expectEqual(@as(u32, 1), built.rejected[0].index);
    try testing.expectEqual(@as(u32, 2), built.rejected[1].index);
    try testing.expectEqual(@as(usize, 2), built.receipts.len);
    try testing.expectEqualStrings("0x5208", built.receipts[0].cumulativeGasUsed);
    try testing.expectEqualStrings("0xa410", built.receipts[1].cumulativeGasUsed);
    try testing.expectEqualStrings("0x2", built.receipts[1].type);
    // Parent at half its 30M limit with elasticity 6: target 5M, used 15M, denominator 250.
    // 1000 + 1000 * 10M / 5M / 250 = 1008.
    try testing.expectEqualStrings("0x3f0", built.computedBaseFeePerGas.?);
    const post = built.post.?;
    try testing.expectEqual(@as(usize, 4), post.object.count());
    const gas: u256 = 42_000;
    try expect_account(post, address_of(1), 2, 10 * ether - 10 - gas * (base_fee + 1));
    try expect_account(post, recipient, 0, 10);
    try expect_account(post, coinbase, 0, 7 + gas);
    try expect_account(post, base_fee_vault, 0, gas * base_fee);

    // The post-state root, built independently from the expected accounts.
    const expected_accounts = [_]Account{
        .{ .address = address_of(1), .info = .{
            .nonce = 2,
            .balance = 10 * ether - 10 - gas * (base_fee + 1),
        } },
        accounts[1],
        .{ .address = coinbase, .info = .{ .balance = 7 + gas } },
        accounts[3],
        .{ .address = recipient, .info = .{ .balance = 10 } },
        .{ .address = base_fee_vault, .info = .{ .balance = gas * base_fee } },
    };
    var expected: Genesis = undefined;
    try expected.init(&expected_accounts);
    defer expected.deinit();
    const header = built.header.?.object;
    var root_text: [66]u8 = undefined;
    hex.encode_prefixed(&root_text, &expected.root);
    try testing.expectEqualStrings(&root_text, header.get("stateRoot").?.string);
    try testing.expect(header.get("withdrawalsRoot") != null);
    try testing.expectEqualStrings("0x0", header.get("blobGasUsed").?.string);

    // A witness without one of its nodes cannot be executed.
    const missing = try answer(adapter, arena, try lines.request(&genesis, "build", 0));
    try testing.expect(!missing.ok);
    const text = missing.@"error".?;
    const prefix = "WitnessIncomplete: witness lacks trie node 0x";
    try testing.expect(std.mem.startsWith(u8, text, prefix));
    // Requests are independent: the full witness answers the same again.
    const again = try answer(adapter, arena, try lines.request(&genesis, "build", null));
    const again_hash = again.header.?.object.get("hash").?.string;
    try testing.expectEqualStrings(header.get("hash").?.string, again_hash);

    // Validate mode accepts the block build mode built, and rejects it with a wrong result.
    lines.only_valid = true;
    const canonical = try answer(adapter, arena, try lines.request_with(
        &genesis,
        "validate",
        null,
        header,
    ));
    try testing.expect(canonical.ok);
    if (!canonical.valid) std.debug.print("invalid: {?s}\n", .{canonical.invalidReason});
    try testing.expect(canonical.valid);
    try testing.expectEqual(@as(usize, 0), canonical.rejected.len);
    const hash = header.get("hash").?.string;
    try testing.expectEqualStrings(hash, canonical.header.?.object.get("hash").?.string);
    var wrong = try header.clone(arena);
    try wrong.put(arena, "gasUsed", .{ .string = "0xa411" });
    const rejected = try answer(adapter, arena, try lines.request_with(
        &genesis,
        "validate",
        null,
        wrong,
    ));
    try testing.expect(rejected.ok);
    try testing.expect(!rejected.valid);
    try testing.expectEqualStrings(hash, rejected.header.?.object.get("hash").?.string);
    // A rejected transaction makes a canonical block invalid.
    lines.only_valid = false;
    const invalid = try answer(adapter, arena, try lines.request_with(
        &genesis,
        "validate",
        null,
        header,
    ));
    try testing.expect(invalid.ok and !invalid.valid);
    try testing.expectEqual(@as(usize, 0), invalid.rejected.len);
}

test "diff adapter: post marks an account destroyed and recreated in the block as wiped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const empty: Address = @splat(0x66);
    const accounts = [_]Account{
        .{ .address = address_of(1), .info = .{ .balance = 10 * ether } },
        .{ .address = coinbase, .info = .{ .balance = 7 } },
        // Exists but is empty: touching it removes it (EIP-161), a destruction.
        .{ .address = empty, .info = .{} },
    };
    var genesis: Genesis = undefined;
    try genesis.init(&accounts);
    defer genesis.deinit();
    const adapter = try testing.allocator.create(diff.Adapter);
    defer testing.allocator.destroy(adapter);
    try adapter.init(testing.allocator);
    defer adapter.deinit();
    var buffers: [3][256]u8 = undefined;
    const transactions = [_][]const u8{
        try send(&buffers[0], 1, 0, 2_000, empty, 0), // Touches it: removed.
        try send(&buffers[1], 1, 1, 2_000, empty, 9), // Recreates it.
        try send(&buffers[2], 1, 2, 2_000, recipient, 5), // New: not wiped.
    };
    var lines: Lines = .{ .out = .init(testing.allocator), .transactions = &transactions };
    defer lines.out.deinit();
    const built = try answer(adapter, arena, try lines.request(&genesis, "build", null));
    try testing.expect(built.ok and built.valid);
    try testing.expectEqual(@as(usize, 3), built.receipts.len);
    const post = built.post.?;
    try expect_account(post, empty, 0, 9);
    var name: [42]u8 = undefined;
    hex.encode_prefixed(&name, &empty);
    const recreated = post.object.get(&name).?.object;
    try testing.expect(recreated.get("wiped").?.bool);
    try testing.expectEqual(@as(usize, 0), recreated.get("storage").?.object.count());
    // Neither a new account nor a changed one that was never destroyed is wiped.
    hex.encode_prefixed(&name, &recipient);
    try testing.expect(post.object.get(&name).?.object.get("wiped") == null);
    hex.encode_prefixed(&name, &address_of(1));
    try testing.expect(post.object.get(&name).?.object.get("wiped") == null);
}

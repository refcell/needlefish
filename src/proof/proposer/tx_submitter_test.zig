//! The proposer's transaction submitter against a canned L1 over SimIo: a creation is
//! signed with the init bond and mined; reverts are classified at estimation and from a
//! failed receipt's replay; a transaction that never lands is reported dropped.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const harness_module = @import("../../consensus/sources/sim_harness.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const tx_submitter = @import("tx_submitter.zig");
const interfaces = @import("interfaces.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Submitter = tx_submitter.TxSubmitter(Endpoint);

const bond: u256 = 80_000_000_000_000_000;
const gas_estimate: u64 = 0x30000;
const base_fee: u64 = 7;
const tip: u128 = 3;
const nonce: u64 = 5;

/// A JSON-RPC `execution reverted` error carrying `data`.
fn revert_error(arena: std.mem.Allocator, data: []const u8) ![]const u8 {
    const format = "{{\"code\":3,\"message\":\"execution reverted\",\"data\":\"0x{x}\"}}";
    return std.fmt.allocPrint(arena, format, .{data});
}

fn step(context: *anyopaque) anyerror!void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    harness.world.run_for_ns(std.time.ns_per_ms);
}

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    harness: Harness,
    fake: FakeRpc = .{},
    client: Endpoint.Client,
    l1: Endpoint,
    submitter: Submitter,
    account: accounts.Account,
    calldata: []const u8,
    /// Index of the receipt entry, which tests rewrite between polls.
    receipt: u32 = 0,

    fn create() !*Fixture {
        const allocator = testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.* = .{
            .arena = .init(allocator),
            .harness = undefined,
            .client = undefined,
            .l1 = undefined,
            .submitter = undefined,
            .account = accounts.derive_dev(3),
            .calldata = undefined,
        };
        errdefer self.arena.deinit();
        try self.add_answers();
        try self.harness.init(&self.fake, 0x61);
        errdefer self.harness.deinit();
        const options = harness_module.client_options;
        const address = self.harness.address;
        self.client = try .init(allocator, &self.harness.client_io, address, options, 4096);
        errdefer self.client.deinit();
        const pump: endpoint_module.Pump = .{ .context = &self.harness, .step = step };
        self.l1 = .init(allocator, &self.client, pump, 100_000);
        errdefer self.l1.deinit();
        self.submitter = try .init(allocator, &self.l1, .{
            .chain_id = 900,
            .private_key = self.account.private_key,
            .from = self.account.address.bytes,
            .factory = @splat(0xfa),
            .game_type = 621,
            .receipt_polls_max = 3,
        });
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.submitter.deinit(testing.allocator);
        self.l1.deinit();
        self.client.deinit();
        self.harness.deinit();
        self.arena.deinit();
        testing.allocator.destroy(self);
    }

    fn add_answers(self: *Fixture) !void {
        const arena = self.arena.allocator();
        var buffer: [512]u8 = undefined;
        const extra: [factory.extra_data_prefix_bytes]u8 = @splat(1);
        const create_call = try factory.encode_create(&buffer, 621, @splat(4), &extra, "proof");
        self.calldata = try arena.dupe(u8, create_call);
        const create_selector = &factory.create_with_init_data;
        const create_hex = try std.fmt.allocPrint(arena, "\"0x{x}", .{create_selector});
        const bond_hex = try std.fmt.allocPrint(arena, "\"0x{x}", .{&factory.init_bonds});
        var word: [32]u8 = undefined;
        std.mem.writeInt(u256, &word, bond, .big);
        self.fake.add(.{
            .method = "eth_call",
            .params_contain = bond_hex,
            .result = try std.fmt.allocPrint(arena, "\"0x{x}\"", .{&word}),
        });
        // A replayed creation reverts with InvalidParentGame().
        const parent_error = try revert_error(arena, &tx_submitter.reverts.invalid_parent_game);
        self.fake.add(.{
            .method = "eth_call",
            .params_contain = create_hex,
            .rpc_error = parent_error,
        });
        self.fake.add(.{ .method = "eth_estimateGas", .result = "\"0x30000\"" });
        self.fake.add(.{ .method = "eth_getTransactionCount", .result = "\"0x5\"" });
        self.fake.add(.{ .method = "eth_maxPriorityFeePerGas", .result = "\"0x3\"" });
        var header_buffer: [600]u8 = undefined;
        const header = rlp.encode_to(&header_buffer, consensus.Header{
            .number = 9,
            .base_fee_per_gas = base_fee,
        });
        self.fake.add(.{
            .method = "debug_getRawHeader",
            .result = try std.fmt.allocPrint(arena, "\"0x{x}\"", .{header}),
        });
        self.fake.add(.{
            .method = "eth_sendRawTransaction",
            .result = try std.fmt.allocPrint(arena, "\"0x{x}\"", .{&(try self.expected_hash())}),
        });
        self.receipt = self.fake.count;
        self.fake.add(.{ .method = "eth_getTransactionReceipt", .result = "null" });
    }

    /// The hash of the creation the submitter signs (RFC 6979 signatures are
    /// deterministic).
    fn expected_hash(self: *Fixture) ![32]u8 {
        const envelope = try txdata.sign_eip1559(.{
            .chain_id = 900,
            .nonce = nonce,
            .fees = txdata.suggest_fees(base_fee, tip),
            .gas_limit = gas_estimate + gas_estimate / 100 * 20,
            .to = .{ .bytes = @splat(0xfa) },
            .value = bond,
            .data = self.calldata,
        }, self.account.private_key);
        return envelope.hash().bytes;
    }
};

test "tx submitter: a creation carries the bond and is mined" {
    const self = try Fixture.create();
    defer self.destroy();
    const submitter = self.submitter.submitter();
    const sent = submitter.send(self.calldata);
    try testing.expect(sent == .pending);
    // The broadcast was the signed creation from the proposer account with the bond.
    const body = self.fake.body();
    try testing.expect(std.mem.indexOf(u8, body, "eth_sendRawTransaction") != null);
    try testing.expect(submitter.status(sent.pending) == .pending);
    self.fake.entries[self.receipt].result = "{\"status\":\"0x1\",\"blockNumber\":\"0x9\"}";
    try testing.expect(submitter.status(sent.pending) == .mined);
    // A settled transaction is forgotten.
    const dropped: interfaces.TxStatus = .{ .failed = .dropped };
    try testing.expectEqual(dropped, submitter.status(sent.pending));
}

test "tx submitter: a failed receipt is classified from its replay" {
    const self = try Fixture.create();
    defer self.destroy();
    const submitter = self.submitter.submitter();
    const sent = submitter.send(self.calldata);
    self.fake.entries[self.receipt].result = "{\"status\":\"0x0\",\"blockNumber\":\"0x9\"}";
    const failed: interfaces.TxStatus = .{ .failed = .invalid_parent_game };
    try testing.expectEqual(failed, submitter.status(sent.pending));
    // The replay ran at the receipt's block.
    try testing.expect(std.mem.indexOf(u8, self.fake.body(), "\"0x9\"") != null);
}

test "tx submitter: a revert at estimation fails the send" {
    const self = try Fixture.create();
    defer self.destroy();
    const arena = self.arena.allocator();
    for (self.fake.entries[0..self.fake.count]) |*entry| {
        if (!std.mem.eql(u8, entry.method, "eth_estimateGas")) continue;
        var data: [36]u8 = @splat(0x11);
        data[0..4].* = factory.game_already_exists;
        entry.rpc_error = try revert_error(arena, &data);
    }
    const sent = self.submitter.submitter().send(self.calldata);
    const expected: interfaces.SendResult = .{ .failed = .game_already_exists };
    try testing.expectEqual(expected, sent);
}

test "tx submitter: a transaction without a receipt is dropped" {
    const self = try Fixture.create();
    defer self.destroy();
    const submitter = self.submitter.submitter();
    const sent = submitter.send(self.calldata);
    try testing.expect(submitter.status(sent.pending) == .pending);
    try testing.expect(submitter.status(sent.pending) == .pending);
    const dropped: interfaces.TxStatus = .{ .failed = .dropped };
    try testing.expectEqual(dropped, submitter.status(sent.pending));
}

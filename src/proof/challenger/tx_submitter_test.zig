//! The challenger's transaction submitter against a canned L1 over SimIo: a nullification
//! is signed without value and mined; reverts are classified at estimation and from a
//! failed receipt's replay; a transaction that never lands is reported dropped.

const std = @import("std");
const testing = std.testing;

const io = @import("../../utilities/io/root.zig");
const harness_module = @import("../../consensus/sources/sim_harness.zig");
const verifier = @import("../contracts/aggregate_verifier.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const accounts = @import("../../batcher/devnet/accounts.zig");
const chain = @import("chain.zig");
const tx_submitter = @import("tx_submitter.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Submitter = tx_submitter.TxSubmitter(Endpoint);

const game: chain.Address = @splat(0x6a);
const gas_estimate: u64 = 0x40000;
const base_fee: u64 = 9;
const tip: u128 = 2;
const nonce: u64 = 11;

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
    /// Indices of the entries tests rewrite.
    receipt: u32 = 0,
    estimate: u32 = 0,
    replay: u32 = 0,

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
            .account = accounts.derive_dev(4),
            .calldata = undefined,
        };
        errdefer self.arena.deinit();
        try self.add_answers();
        try self.harness.init(&self.fake, 0x62);
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
        const proof: [66]u8 = @splat(0x5e);
        const nullify = try verifier.encode_dispute(&buffer, .nullify, &proof, 3, @splat(0xd3));
        self.calldata = try arena.dupe(u8, nullify);
        // A replayed nullification reverts with InvalidProof().
        self.replay = self.fake.count;
        self.fake.add(.{
            .method = "eth_call",
            .params_contain = try std.fmt.allocPrint(arena, "\"0x{x}", .{&verifier.nullify}),
            .rpc_error = try revert_error(arena, &verifier.error_invalid_proof),
        });
        self.estimate = self.fake.count;
        self.fake.add(.{ .method = "eth_estimateGas", .result = "\"0x40000\"" });
        self.fake.add(.{ .method = "eth_getTransactionCount", .result = "\"0xb\"" });
        self.fake.add(.{ .method = "eth_maxPriorityFeePerGas", .result = "\"0x2\"" });
        var header_buffer: [600]u8 = undefined;
        const header = rlp.encode_to(&header_buffer, consensus.Header{
            .number = 12,
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

    /// The hash of the nullification the submitter signs (RFC 6979 signatures are
    /// deterministic).
    fn expected_hash(self: *Fixture) ![32]u8 {
        const envelope = try txdata.sign_eip1559(.{
            .chain_id = 900,
            .nonce = nonce,
            .fees = txdata.suggest_fees(base_fee, tip),
            .gas_limit = gas_estimate + gas_estimate / 100 * 20,
            .to = .{ .bytes = game },
            .value = 0,
            .data = self.calldata,
        }, self.account.private_key);
        return envelope.hash().bytes;
    }

    fn send(self: *Fixture) chain.SendResult {
        return self.submitter.submitter().send(.{ .to = game, .calldata = self.calldata });
    }
};

test "challenger tx submitter: a nullification is signed and mined" {
    const self = try Fixture.create();
    defer self.destroy();
    const submitter = self.submitter.submitter();
    const sent = self.send();
    try testing.expect(sent == .queued);
    // The broadcast was the signed nullification (the node echoed its hash).
    try testing.expect(std.mem.indexOf(u8, self.fake.body(), "eth_sendRawTransaction") != null);
    try testing.expect(submitter.status(sent.queued) == .pending);
    self.fake.entries[self.receipt].result = "{\"status\":\"0x1\",\"blockNumber\":\"0xc\"}";
    try testing.expect(submitter.status(sent.queued) == .mined);
    // A settled transaction is forgotten.
    const forgotten: chain.TxStatus = .{ .failed = .other };
    try testing.expectEqual(forgotten, submitter.status(sent.queued));
}

test "challenger tx submitter: a known revert at estimation rejects the send" {
    const self = try Fixture.create();
    defer self.destroy();
    var data: [36]u8 = @splat(0x01);
    data[0..4].* = verifier.error_already_proven;
    const arena = self.arena.allocator();
    self.fake.entries[self.estimate].rpc_error = try revert_error(arena, &data);
    const known: chain.SendResult = .{ .rejected = .{ .known_revert = .proof_already_verified } };
    try testing.expectEqual(known, self.send());
    // An unknown revert at estimation is `execution_reverted`.
    self.fake.entries[self.estimate].rpc_error = try revert_error(arena, &.{ 1, 2, 3, 4 });
    const unknown: chain.SendResult = .{ .rejected = .execution_reverted };
    try testing.expectEqual(unknown, self.send());
}

test "challenger tx submitter: a failed receipt is classified from its replay" {
    const self = try Fixture.create();
    defer self.destroy();
    const submitter = self.submitter.submitter();
    const sent = self.send();
    self.fake.entries[self.receipt].result = "{\"status\":\"0x0\",\"blockNumber\":\"0xc\"}";
    const invalid: chain.TxStatus = .{ .failed = .{ .known_revert = .invalid_proof } };
    try testing.expectEqual(invalid, submitter.status(sent.queued));
    // The replay ran at the receipt's block.
    try testing.expect(std.mem.indexOf(u8, self.fake.body(), "\"0xc\"") != null);
    // A failed receipt whose replay passes is a plain on-chain revert.
    self.fake.entries[self.replay].rpc_error = null;
    self.fake.entries[self.replay].result = "\"0x\"";
    const again = self.send();
    const reverted: chain.TxStatus = .{ .failed = .tx_reverted };
    try testing.expectEqual(reverted, submitter.status(again.queued));
}

test "challenger tx submitter: a transaction without a receipt is dropped" {
    const self = try Fixture.create();
    defer self.destroy();
    const submitter = self.submitter.submitter();
    const sent = self.send();
    try testing.expect(submitter.status(sent.queued) == .pending);
    try testing.expect(submitter.status(sent.queued) == .pending);
    const dropped: chain.TxStatus = .{ .failed = .other };
    try testing.expectEqual(dropped, submitter.status(sent.queued));
    try testing.expect(self.submitter.sender.has_free_slot());
}

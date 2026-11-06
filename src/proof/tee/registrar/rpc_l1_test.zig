//! The registrar's RPC L1 against canned JSON-RPC answers over SimIo: registry and
//! `CertManager` reads decoded, warm-validation reverts told apart from transport
//! failures, the `CertManager` resolved through the `NitroValidator`, and sender failures
//! mapped onto transaction outcomes.

const std = @import("std");
const testing = std.testing;

const io = @import("../../../utilities/io/root.zig");
const harness_module = @import("../../../consensus/sources/sim_harness.zig");
const abi = @import("../../contracts/abi.zig");
const registry_abi = @import("../../contracts/tee_prover_registry.zig");
const cert_manager_abi = @import("../../contracts/cert_manager.zig");
const endpoint_module = @import("../../rpc/endpoint.zig");
const accounts = @import("../../../batcher/devnet/accounts.zig");
const signer_manager = @import("signer_manager.zig");
const rpc_l1 = @import("rpc_l1.zig");

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Endpoint = endpoint_module.Endpoint(io.SimIo);
const Chain = rpc_l1.RpcChain(Endpoint);
const Transactor = rpc_l1.RpcTransactor(Endpoint);
const Allocator = std.mem.Allocator;

const registry: [20]u8 = @splat(0x11);
const validator: [20]u8 = @splat(0x33);
const cert_manager: [20]u8 = @splat(0x22);

/// `"0x<abi.encode(values)>"`, allocated in `arena`.
fn returns(arena: Allocator, prefix: []const u8, values: []const abi.Value) ![]const u8 {
    var buffer: [1024]u8 = undefined;
    const encoded = try abi.encode_call(&buffer, @splat(0), values);
    return std.fmt.allocPrint(arena, "\"0x{x}{x}\"", .{ prefix, encoded[4..] });
}

fn add_call(fake: *FakeRpc, arena: Allocator, function: [4]u8, values: []const abi.Value) !void {
    fake.add(.{
        .method = "eth_call",
        .params_contain = try std.fmt.allocPrint(arena, "\"0x{x}", .{&function}),
        .result = try returns(arena, "", values),
    });
}

/// A `CertManagerVerifiedCert memory` return: an offset word, then the struct.
fn add_verified(fake: *FakeRpc, arena: Allocator, function: [4]u8, ca: bool) !void {
    const offset: [32]u8 = @as([31]u8, @splat(0)) ++ [_]u8{32};
    fake.add(.{
        .method = "eth_call",
        .params_contain = try std.fmt.allocPrint(arena, "\"0x{x}", .{&function}),
        .result = try returns(arena, &offset, &.{
            .{ .boolean = ca },        .{ .uint = 1_900_000_000 },                 .{ .uint = 0 },
            .{ .word = @splat(0x44) }, .{ .bytes = &(@as([96]u8, @splat(0x55))) },
        }),
    });
}

fn add_world(fake: *FakeRpc, arena: Allocator) !void {
    try add_call(fake, arena, registry_abi.nitro_validator, &.{.{ .address = validator }});
    try add_call(fake, arena, registry_abi.cert_manager, &.{.{ .address = cert_manager }});
    try add_call(fake, arena, registry_abi.is_registered_signer, &.{.{ .boolean = true }});
    try add_call(fake, arena, registry_abi.get_registered_signers, &.{
        .{ .uint = 32 }, .{ .uint = 2 }, .{ .address = @splat(0xaa) }, .{ .address = @splat(0xbb) },
    });
    try add_call(fake, arena, cert_manager_abi.is_revoked, &.{.{ .boolean = false }});
    try add_verified(fake, arena, cert_manager_abi.load_verified, true);
    try add_call(fake, arena, cert_manager_abi.verify_ca_cert_with_hints, &.{
        .{ .word = @splat(0x07) },
    });
    // The client certificate fails warm validation with a revert.
    fake.add(.{
        .method = "eth_call",
        .params_contain = try std.fmt.allocPrint(
            arena,
            "\"0x{x}",
            .{&cert_manager_abi.verify_client_cert_with_hints},
        ),
        .rpc_error = "{\"code\":3,\"message\":\"execution reverted\",\"data\":\"0x\"}",
    });
    fake.add(.{
        .method = "eth_estimateGas",
        .rpc_error = "{\"code\":3,\"message\":\"execution reverted\",\"data\":\"0x\"}",
    });
}

fn step(context: *anyopaque) anyerror!void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    harness.world.run_for_ns(std.time.ns_per_ms);
}

fn wait_none(context: *anyopaque, ms: u64) void {
    _ = context;
    std.debug.assert(ms > 0);
}

const Fixture = struct {
    harness: Harness,
    fake: FakeRpc = .{},
    client: Endpoint.Client,
    endpoint: Endpoint,

    fn create(arena: Allocator) !*Fixture {
        const allocator = testing.allocator;
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.fake = .{};
        try add_world(&self.fake, arena);
        try self.harness.init(&self.fake, 0x77);
        errdefer self.harness.deinit();
        const options = harness_module.client_options;
        const address = self.harness.address;
        self.client = try .init(allocator, &self.harness.client_io, address, options, 4096);
        const pump: endpoint_module.Pump = .{ .context = &self.harness, .step = step };
        self.endpoint = .init(allocator, &self.client, pump, 100_000);
        return self;
    }

    fn destroy(self: *Fixture) void {
        self.endpoint.deinit();
        self.client.deinit();
        self.harness.deinit();
        testing.allocator.destroy(self);
    }
};

test "registrar rpc l1: registry and CertManager reads" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const self = try Fixture.create(arena_state.allocator());
    defer self.destroy();
    const resolved = try Chain.resolve_cert_manager(&self.endpoint, registry);
    try testing.expectEqual(cert_manager, resolved);
    var adapter: Chain = .init(&self.endpoint, registry, resolved);
    const chain = adapter.chain();
    try testing.expect(try chain.is_registered_signer(@splat(0xaa)));
    var signers: [4][20]u8 = undefined;
    const registered = try chain.registered_signers(&signers);
    try testing.expectEqual(@as(usize, 2), registered.len);
    try testing.expectEqual(@as([20]u8, @splat(0xbb)), registered[1]);
    try testing.expect(!try chain.is_revoked(@splat(1)));
    const verified = try chain.load_verified(@splat(2));
    try testing.expect(verified.ca and verified.has_public_key);
    try testing.expectEqual(@as(u64, 1_900_000_000), verified.not_after);
    try testing.expectEqual(@as([32]u8, @splat(7)), try chain.verify_ca_cert("cert", @splat(3)));
    try testing.expectError(error.ContractReverted, chain.verify_client_cert("leaf", @splat(3)));
}

test "registrar rpc l1: estimation revert is a permanent failure" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const self = try Fixture.create(arena_state.allocator());
    defer self.destroy();
    const account = accounts.derive_dev(0);
    var waiter_context: u8 = 0;
    var transactor: Transactor = try .init(testing.allocator, &self.endpoint, .{
        .chain_id = 900,
        .private_key = account.private_key,
        .from = account.address.bytes,
        .calldata_bytes_max = signer_manager.calldata_size_max,
        .slots_max = 1,
    }, .{ .context = &waiter_context, .wait_ms = wait_none }, 1000);
    defer transactor.deinit(testing.allocator);
    const outcome = transactor.transactor().send(registry, "\x01\x02\x03\x04");
    try testing.expect(!outcome.failed.retryable);
}

test "registrar rpc l1: sender failures map onto outcomes" {
    const estimate: rpc_l1.submission_failure = .{ .rpc_error = .{
        .phase = .estimate,
        .message = "execution reverted",
        .data = "0x",
    } };
    try testing.expect(!rpc_l1.tx_outcome(estimate).failed.retryable);
    var broadcast = estimate;
    broadcast.rpc_error.phase = .broadcast;
    try testing.expect(rpc_l1.tx_outcome(broadcast).failed.retryable);
    var replay = estimate;
    replay.rpc_error.phase = .replay;
    try testing.expect(rpc_l1.tx_outcome(replay) == .reverted);
    try testing.expect(rpc_l1.tx_outcome(.reverted) == .reverted);
    try testing.expect(rpc_l1.tx_outcome(.dropped).failed.retryable);
    try testing.expect(rpc_l1.tx_outcome(.unavailable).failed.retryable);
}

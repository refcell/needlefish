//! The proposer's `Chain` over JSON-RPC (base/base `RollupProvider`,
//! `AnchorStateRegistryClient`, `DisputeGameFactoryClient`, `IntervalResolver`): the
//! rollup node's sync status and output roots, and `eth_call`s of the L1 contracts.
//!
//! The anchor root and anchor game are read at one pinned L1 block, so recovery never
//! pairs an old root with a newer game. Intervals are resolved from the factory's current
//! implementation (`gameImpls`) on every call, so an upgrade is picked up without a
//! restart; verifiers older than 0.3.0 answer through their fixed interval getters.

const std = @import("std");
const assert = std.debug.assert;

const clients = @import("../rpc/clients.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const registry = @import("../contracts/anchor_state_registry.zig");
const interfaces = @import("interfaces.zig");
const intervals_module = @import("intervals.zig");

const Address = interfaces.Address;
const Hash = interfaces.Hash;
const ChainError = interfaces.ChainError;

/// Aggregate verifier getters for interval resolution.
pub const verifier = struct {
    pub const version = abi.selector("version()");
    pub const intervals_for_starting_block = abi.selector("intervalsForStartingBlock(uint256)");
    pub const block_interval = abi.selector("BLOCK_INTERVAL()");
    pub const intermediate_block_interval = abi.selector("INTERMEDIATE_BLOCK_INTERVAL()");
};

pub const Config = struct {
    factory: Address,
    anchor_state_registry: Address,
    game_type: u32,
};

pub fn RpcChain(comptime EndpointType: type) type {
    return struct {
        const Self = @This();

        l1: *EndpointType,
        rollup: *EndpointType,
        config: Config,
        calldata: [factory.extra_data_bytes_max + 256]u8 = undefined,

        pub fn init(l1: *EndpointType, rollup: *EndpointType, config: Config) Self {
            assert(l1 != rollup);
            assert(!std.mem.allEqual(u8, &config.factory, 0));
            return .{ .l1 = l1, .rollup = rollup, .config = config };
        }

        pub fn chain(self: *Self) interfaces.Chain {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: interfaces.Chain.VTable = .{
            .sync_status = sync_status,
            .output_at_block = output_at_block,
            .anchor_snapshot = anchor_snapshot,
            .game_count = game_count,
            .game_lookup = game_lookup,
            .intervals = intervals,
        };

        fn of(context: *anyopaque) *Self {
            const self: *Self = @ptrCast(@alignCast(context));
            self.l1.reset();
            self.rollup.reset();
            return self;
        }

        fn sync_status(context: *anyopaque) ChainError!interfaces.SyncStatus {
            const self = of(context);
            const rollup: clients.Rollup(EndpointType) = .{ .endpoint = self.rollup };
            return rollup.sync_status() catch error.Unavailable;
        }

        fn output_at_block(
            context: *anyopaque,
            block: u64,
        ) ChainError!interfaces.OutputAtBlock {
            const self = of(context);
            const rollup: clients.Rollup(EndpointType) = .{ .endpoint = self.rollup };
            return rollup.output_at_block(block) catch |err| switch (err) {
                error.NotFound => error.BlockNotFound,
                error.CallFailed => error.Unavailable,
            };
        }

        /// One `eth_call` at `block`, with the call's return data.
        fn call(
            self: *Self,
            to: Address,
            data: []const u8,
            block: endpoint_module.Block,
        ) ChainError![]const u8 {
            assert(data.len >= 4);
            const l1: clients.Execution(EndpointType) = .{ .endpoint = self.l1 };
            return l1.call_contract(to, data, block) catch error.Unavailable;
        }

        fn call_static(
            self: *Self,
            to: Address,
            function: [4]u8,
            values: []const abi.Value,
            block: endpoint_module.Block,
        ) ChainError![]const u8 {
            const data = abi.encode_call(&self.calldata, function, values) catch
                return error.Unavailable;
            return self.call(to, data, block);
        }

        fn anchor_snapshot(context: *anyopaque) ChainError!interfaces.AnchorSnapshot {
            const self = of(context);
            const l1: clients.Execution(EndpointType) = .{ .endpoint = self.l1 };
            const pinned: endpoint_module.Block = .{
                .number = l1.block_number() catch return error.Unavailable,
            };
            const to = self.config.anchor_state_registry;
            const root_data = try self.call_static(to, registry.get_anchor_root, &.{}, pinned);
            const root = registry.decode_anchor_root(root_data) catch return error.Unavailable;
            const game_data = try self.call_static(to, registry.anchor_game, &.{}, pinned);
            const decoder: abi.Decoder = .{ .data = game_data };
            const game = decoder.address(0) catch return error.Unavailable;
            return .{ .root = root, .game = game };
        }

        fn game_count(context: *anyopaque) ChainError!u64 {
            const self = of(context);
            const to = self.config.factory;
            const data = try self.call_static(to, factory.game_count, &.{}, .latest);
            const decoder: abi.Decoder = .{ .data = data };
            return decoder.uint(u64, 0) catch error.Unavailable;
        }

        fn game_lookup(
            context: *anyopaque,
            game_type: u32,
            root_claim: Hash,
            extra_data: []const u8,
        ) ChainError!?Address {
            const self = of(context);
            assert(extra_data.len >= factory.extra_data_prefix_bytes);
            const out = &self.calldata;
            const data = factory.encode_games(out, game_type, root_claim, extra_data) catch
                return error.Unavailable;
            const result = try self.call(self.config.factory, data, .latest);
            const game = factory.decode_games(result) catch return error.Unavailable;
            return if (game) |found| found.proxy else null;
        }

        fn intervals(context: *anyopaque, starting_block: u64) ChainError!interfaces.Intervals {
            const self = of(context);
            const impl_data = try self.call_static(self.config.factory, factory.game_impls, &.{
                .{ .uint = self.config.game_type },
            }, .latest);
            const impl = (abi.Decoder{ .data = impl_data }).address(0) catch
                return error.Unavailable;
            // No implementation registered for the game type: nothing can be proposed.
            if (std.mem.allEqual(u8, &impl, 0)) return error.Unavailable;
            const version_data = try self.call_static(impl, verifier.version, &.{}, .latest);
            const version = (abi.Decoder{ .data = version_data }).bytes(0) catch
                return error.Unavailable;
            if (intervals_module.supports_fork_aware_intervals(version)) {
                const data = try self.call_static(impl, verifier.intervals_for_starting_block, &.{
                    .{ .uint = starting_block },
                }, .latest);
                return decode_pair(data);
            }
            const block_data = try self.call_static(impl, verifier.block_interval, &.{}, .latest);
            // Results of earlier calls stay valid until the next `reset`.
            const intermediate_data = try self.call_static(
                impl,
                verifier.intermediate_block_interval,
                &.{},
                .latest,
            );
            return decode_legacy(block_data, intermediate_data);
        }
    };
}

/// `intervalsForStartingBlock` returns `(uint256, uint256)`.
fn decode_pair(data: []const u8) ChainError!interfaces.Intervals {
    if (data.len != 64) return error.Unavailable;
    const decoder: abi.Decoder = .{ .data = data };
    return .{
        .block_interval = decoder.uint(u64, 0) catch return error.Unavailable,
        .intermediate_block_interval = decoder.uint(u64, 1) catch return error.Unavailable,
    };
}

fn decode_legacy(
    block_data: []const u8,
    intermediate_data: []const u8,
) ChainError!interfaces.Intervals {
    assert(block_data.ptr != intermediate_data.ptr);
    const block_decoder: abi.Decoder = .{ .data = block_data };
    const intermediate_decoder: abi.Decoder = .{ .data = intermediate_data };
    return .{
        .block_interval = block_decoder.uint(u64, 0) catch return error.Unavailable,
        .intermediate_block_interval = intermediate_decoder.uint(u64, 0) catch
            return error.Unavailable,
    };
}

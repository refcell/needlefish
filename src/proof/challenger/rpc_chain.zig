//! The challenger's `ChainView` over JSON-RPC (base/base `DisputeGameFactoryClient`,
//! `AggregateVerifierClient`, `AnchorStateRegistryClient`, `DelayedWETHClient`,
//! `L1Provider`/`L2Provider`): `eth_call`s of the L1 contracts, L1 headers by hash and L2
//! raw headers by number.
//!
//! The anchor root and anchor game are read at one pinned L1 block, so the updater never
//! pairs an old root with a newer game. A game's intervals are read through its own proxy
//! (a clone bound to the implementation it was created with); the factory's intervals
//! through its current `gameImpls` entry. Verifiers older than 0.3.0 answer through their
//! fixed interval getters. Every failed read (transport, JSON-RPC error, revert, decode) is
//! `ChainUnavailable`; a missing L2 header is `BlockNotAvailable`.

const std = @import("std");
const assert = std.debug.assert;

const clients = @import("../rpc/clients.zig");
const endpoint_module = @import("../rpc/endpoint.zig");
const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const verifier = @import("../contracts/aggregate_verifier.zig");
const registry = @import("../contracts/anchor_state_registry.zig");
const weth = @import("../contracts/delayed_weth.zig");
const consensus = @import("../../common/consensus/root.zig");
const crypto = @import("../../common/crypto/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const chain = @import("chain.zig");

const Address = chain.Address;
const Hash = chain.Hash;
const ReadError = chain.ReadError;
const HeaderError = chain.HeaderError;
const Block = endpoint_module.Block;

pub const Config = struct {
    factory: Address,
    anchor_state_registry: Address,
};

pub fn RpcChain(comptime EndpointType: type) type {
    return struct {
        const Self = @This();
        const Execution = clients.Execution(EndpointType);

        l1: *EndpointType,
        l2: *EndpointType,
        config: Config,
        calldata: [factory.extra_data_bytes_max + 256]u8 = undefined,

        pub fn init(l1: *EndpointType, l2: *EndpointType, config: Config) Self {
            assert(l1 != l2);
            assert(!chain.is_zero(config.factory));
            assert(!chain.is_zero(config.anchor_state_registry));
            return .{ .l1 = l1, .l2 = l2, .config = config };
        }

        pub fn view(self: *Self) chain.ChainView {
            return .{ .context = self, .vtable = &vtable };
        }

        const vtable: chain.ChainView.VTable = .{
            .game_count = game_count,
            .game_at_index = game_at_index,
            .game_state = game_state,
            .game_info = game_info,
            .intermediate_roots = intermediate_roots,
            .intermediate_root = intermediate_root,
            .anchor_snapshot = anchor_snapshot,
            .implementation_intervals = implementation_intervals,
            .factory_game = factory_game,
            .anchor_registry_of = anchor_registry_of,
            .is_game_finalized = is_game_finalized,
            .anchor_preflight = anchor_preflight,
            .bond_state = bond_state,
            .weth_delay_seconds = weth_delay_seconds,
            .withdrawal = withdrawal,
            .l1_block_number = l1_block_number,
            .l2_header = l2_header,
        };

        fn of(context: *anyopaque) *Self {
            const self: *Self = @ptrCast(@alignCast(context));
            self.l1.reset();
            self.l2.reset();
            return self;
        }

        /// One L1 `eth_call` at `block`; the return data stays valid until the next `reset`.
        fn call(self: *Self, to: Address, data: []const u8, block: Block) ReadError![]const u8 {
            assert(data.len >= 4);
            assert(!chain.is_zero(to));
            const l1: Execution = .{ .endpoint = self.l1 };
            return l1.call_contract(to, data, block) catch error.ChainUnavailable;
        }

        fn call_static(
            self: *Self,
            to: Address,
            function: [4]u8,
            values: []const abi.Value,
            block: Block,
        ) ReadError![]const u8 {
            const data = abi.encode_call(&self.calldata, function, values) catch
                return error.ChainUnavailable;
            return self.call(to, data, block);
        }

        /// A getter without arguments at the latest block.
        fn getter(self: *Self, to: Address, function: [4]u8) ReadError![]const u8 {
            return self.call_static(to, function, &.{}, .latest);
        }

        fn get_address(self: *Self, to: Address, function: [4]u8) ReadError!Address {
            return verifier.decode_address(try self.getter(to, function)) catch
                error.ChainUnavailable;
        }

        fn get_uint(self: *Self, to: Address, function: [4]u8) ReadError!u64 {
            return verifier.decode_uint(u64, try self.getter(to, function)) catch
                error.ChainUnavailable;
        }

        fn get_hash(self: *Self, to: Address, function: [4]u8) ReadError!Hash {
            return verifier.decode_hash(try self.getter(to, function)) catch
                error.ChainUnavailable;
        }

        fn get_boolean(self: *Self, to: Address, function: [4]u8) ReadError!bool {
            return verifier.decode_boolean(try self.getter(to, function)) catch
                error.ChainUnavailable;
        }

        /// A registry view taking one game address.
        fn query_game(self: *Self, to: Address, function: [4]u8, game: Address) ReadError!bool {
            const data = try self.call_static(to, function, &.{.{ .address = game }}, .latest);
            return verifier.decode_boolean(data) catch error.ChainUnavailable;
        }

        fn game_count(context: *anyopaque) ReadError!u64 {
            const self = of(context);
            return self.get_uint(self.config.factory, factory.game_count);
        }

        fn game_at_index(context: *anyopaque, index: u64) ReadError!chain.GameAtIndex {
            const self = of(context);
            const to = self.config.factory;
            const data = try self.call_static(to, factory.game_at_index, &.{
                .{ .uint = index },
            }, .latest);
            return factory.decode_game_at_index(data) catch error.ChainUnavailable;
        }

        fn game_state(context: *anyopaque, game: Address) ReadError!chain.GameState {
            const self = of(context);
            const status_data = try self.getter(game, verifier.status);
            const state: chain.GameState = .{
                .status = verifier.decode_status(status_data) catch return error.ChainUnavailable,
                .tee_prover = try self.get_address(game, verifier.tee_prover),
                .zk_prover = try self.get_address(game, verifier.zk_prover),
                .countered_index = try self.get_uint(game, verifier.countered_index),
            };
            return state;
        }

        fn game_info(context: *anyopaque, game: Address) ReadError!chain.GameInfo {
            const self = of(context);
            const starting_block_number = try self.get_uint(game, verifier.starting_block_number);
            return .{
                .root_claim = try self.get_hash(game, verifier.root_claim),
                .l2_block_number = try self.get_uint(game, verifier.l2_sequence_number),
                .parent = try self.get_address(game, verifier.parent_address),
                .starting_block_number = starting_block_number,
                .l1_head = try self.get_hash(game, verifier.l1_head),
                .intervals = try self.resolve_intervals(game, starting_block_number),
            };
        }

        fn intermediate_roots(context: *anyopaque, game: Address, out: []Hash) ReadError![]Hash {
            const self = of(context);
            const data = try self.getter(game, verifier.intermediate_output_roots);
            const roots = verifier.decode_intermediate_roots(data, out) catch
                return error.ChainUnavailable;
            assert(roots.len <= out.len);
            return roots;
        }

        fn intermediate_root(context: *anyopaque, game: Address, index: u64) ReadError!Hash {
            const self = of(context);
            const data = try self.call_static(game, verifier.intermediate_output_root, &.{
                .{ .uint = index },
            }, .latest);
            return verifier.decode_hash(data) catch error.ChainUnavailable;
        }

        fn anchor_snapshot(context: *anyopaque) ReadError!chain.AnchorSnapshot {
            const self = of(context);
            const l1: Execution = .{ .endpoint = self.l1 };
            const pinned: Block = .{
                .number = l1.block_number() catch return error.ChainUnavailable,
            };
            const to = self.config.anchor_state_registry;
            const root_data = try self.call_static(to, registry.get_anchor_root, &.{}, pinned);
            const root = registry.decode_anchor_root(root_data) catch
                return error.ChainUnavailable;
            const game_data = try self.call_static(to, registry.anchor_game, &.{}, pinned);
            const game = verifier.decode_address(game_data) catch return error.ChainUnavailable;
            return .{ .anchor_game = game, .anchor_root = root };
        }

        fn implementation_intervals(
            context: *anyopaque,
            kind: u32,
            starting_block: u64,
        ) ReadError!chain.Intervals {
            const self = of(context);
            const data = try self.call_static(self.config.factory, factory.game_impls, &.{
                .{ .uint = kind },
            }, .latest);
            const implementation = verifier.decode_address(data) catch
                return error.ChainUnavailable;
            // No implementation registered for the game type.
            if (chain.is_zero(implementation)) return error.ChainUnavailable;
            return self.resolve_intervals(implementation, starting_block);
        }

        /// The interval pair `target` (an implementation or a game proxy) applies to a
        /// range starting at `starting_block`, gated on its `version()`.
        fn resolve_intervals(
            self: *Self,
            target: Address,
            starting_block: u64,
        ) ReadError!chain.Intervals {
            const version_data = try self.getter(target, verifier.version);
            const version = verifier.decode_version(version_data) catch
                return error.ChainUnavailable;
            if (verifier.supports_fork_aware_intervals(version)) {
                const data = try self.call_static(target, verifier.intervals_for_starting_block, &.{
                    .{ .uint = starting_block },
                }, .latest);
                if (data.len != 2 * abi.word_bytes) return error.ChainUnavailable;
                const decoder: abi.Decoder = .{ .data = data };
                return .{
                    .block = decoder.uint(u64, 0) catch return error.ChainUnavailable,
                    .intermediate_block = decoder.uint(u64, 1) catch return error.ChainUnavailable,
                };
            }
            const block = try self.get_uint(target, verifier.block_interval);
            const intermediate = verifier.intermediate_block_interval;
            const intervals: chain.Intervals = .{
                .block = block,
                .intermediate_block = try self.get_uint(target, intermediate),
            };
            return intervals;
        }

        fn factory_game(
            context: *anyopaque,
            kind: u32,
            claim: Hash,
            extra_data: []const u8,
        ) ReadError!?Address {
            const self = of(context);
            assert(extra_data.len <= factory.extra_data_bytes_max);
            const data = factory.encode_games(&self.calldata, kind, claim, extra_data) catch
                return error.ChainUnavailable;
            const result = try self.call(self.config.factory, data, .latest);
            const game = factory.decode_games(result) catch return error.ChainUnavailable;
            return if (game) |found| found.proxy else null;
        }

        fn anchor_registry_of(context: *anyopaque, game: Address) ReadError!Address {
            const self = of(context);
            const address = try self.get_address(game, verifier.anchor_state_registry);
            if (chain.is_zero(address)) return error.ChainUnavailable;
            return address;
        }

        fn is_game_finalized(context: *anyopaque, to: Address, game: Address) ReadError!bool {
            const self = of(context);
            return self.query_game(to, registry.is_game_finalized, game);
        }

        fn anchor_preflight(
            context: *anyopaque,
            to: Address,
            game: Address,
        ) ReadError!chain.Preflight {
            const self = of(context);
            const root_data = try self.getter(to, registry.get_anchor_root);
            const root = registry.decode_anchor_root(root_data) catch
                return error.ChainUnavailable;
            return .{
                .blacklisted = try self.query_game(to, registry.is_game_blacklisted, game),
                .retired = try self.query_game(to, registry.is_game_retired, game),
                .respected = try self.query_game(to, registry.is_game_respected, game),
                .paused = try self.get_boolean(to, registry.paused),
                .anchor_root = root,
            };
        }

        fn bond_state(context: *anyopaque, game: Address) ReadError!chain.BondState {
            const self = of(context);
            return .{
                .bond_recipient = try self.get_address(game, verifier.bond_recipient),
                .zk_prover = try self.get_address(game, verifier.zk_prover),
                .resolved_at = try self.get_uint(game, verifier.resolved_at),
                .game_over = try self.get_boolean(game, verifier.game_over),
                .bond_unlocked = try self.get_boolean(game, verifier.bond_unlocked),
                .bond_claimed = try self.get_boolean(game, verifier.bond_claimed),
                .delayed_weth = try self.get_address(game, verifier.delayed_weth),
            };
        }

        fn weth_delay_seconds(context: *anyopaque, to: Address) ReadError!u64 {
            const self = of(context);
            return weth.decode_delay_seconds(try self.getter(to, weth.delay)) catch
                error.ChainUnavailable;
        }

        fn withdrawal(
            context: *anyopaque,
            to: Address,
            owner: Address,
            guy: Address,
        ) ReadError!chain.Withdrawal {
            const self = of(context);
            const data = weth.encode_withdrawals(&self.calldata, owner, guy) catch
                return error.ChainUnavailable;
            const result = try self.call(to, data, .latest);
            return weth.decode_withdrawal(result) catch error.ChainUnavailable;
        }

        /// The number of the L1 block with `hash`, from its raw header (checked against
        /// the hash, so a lying node cannot hand out another block).
        fn l1_block_number(context: *anyopaque, hash: Hash) ReadError!u64 {
            const self = of(context);
            const l1: Execution = .{ .endpoint = self.l1 };
            const raw = l1.raw_header_by_hash(hash) catch return error.ChainUnavailable;
            const digest = crypto.keccak256(raw);
            if (!std.mem.eql(u8, &digest, &hash)) return error.ChainUnavailable;
            const header = rlp.decode_exact(consensus.Header, raw) catch
                return error.ChainUnavailable;
            return header.number;
        }

        fn l2_header(context: *anyopaque, number: u64, out: []u8) HeaderError![]const u8 {
            const self = of(context);
            const l2: Execution = .{ .endpoint = self.l2 };
            const raw = l2.raw_header(.{ .number = number }) catch |err| switch (err) {
                error.NotFound => return error.BlockNotAvailable,
                error.CallFailed => return error.ChainUnavailable,
            };
            if (raw.len > out.len) return error.ChainUnavailable;
            @memcpy(out[0..raw.len], raw);
            assert(raw.len > 0);
            return out[0..raw.len];
        }
    };
}

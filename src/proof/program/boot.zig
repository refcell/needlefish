//! Boot information of the fault-proof program. Port of base/base
//! `crates/proof/proof/src/boot.rs`.
//!
//! The host provides the program's inputs as local preimages (key type `local`, the
//! identifier in the low 8 bytes): hashes are 32 bytes, integers 8-byte big-endian, the
//! proposer 20 bytes, the rollup config JSON. Optional keys the host does not have are
//! served as empty preimages (the wire has no "not found"; see the lane decisions).
//!
//! Trust: the rollup config comes from the host, so outside the devnet its identity
//! fields (chain ids, genesis, inbox, deposit and system config contracts, block time)
//! must equal the built-in chain config; only upgrade timestamps come from the host.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const chains = @import("../../common/chains/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");

const Hash = [32]u8;
const Address = [20]u8;
const RollupConfig = protocol.RollupConfig;

pub const LocalKey = enum(u64) {
    l1_head = 1,
    l2_output_root = 2,
    l2_claim = 3,
    l2_claim_block_number = 4,
    l2_chain_id = 5,
    l2_rollup_config = 6,
    l1_config = 7,
    proposer = 8,
    intermediate_block_interval = 9,
    l1_head_number = 10,
    l2_schedule_block_number = 11,

    pub fn key(local: LocalKey) preimage.Key {
        return .local(@backingInt(local));
    }
};

/// Largest rollup config JSON accepted.
pub const rollup_config_bytes_max: u32 = 64 * 1024;

pub const Error = preimage.oracle.ReadError || error{
    InvalidBootValue,
    UnknownChainId,
    RollupConfigInvalid,
    RollupConfigMismatch,
    MissingL1ChainConfig,
};

pub const BootInfo = struct {
    l1_head: Hash,
    agreed_l2_output_root: Hash,
    claimed_l2_output_root: Hash,
    claimed_l2_block_number: u64,
    chain_id: u64,
    rollup_config: RollupConfig,
    l1_config: *const chains.L1Config,
    proposer: Address,
    intermediate_block_interval: u64,
    l1_head_number: u64,
    /// The L2 block the claim schedules against; defaults to the claim block.
    schedule_block_number: u64,

    /// Loads every boot value through `oracle`. `scratch` holds the rollup config JSON.
    pub fn load(oracle: preimage.OracleReader, scratch: []u8) Error!BootInfo {
        assert(scratch.len >= 32);
        var info: BootInfo = undefined;
        try oracle.get_exact(LocalKey.l1_head.key(), &info.l1_head);
        try oracle.get_exact(LocalKey.l2_output_root.key(), &info.agreed_l2_output_root);
        try oracle.get_exact(LocalKey.l2_claim.key(), &info.claimed_l2_output_root);
        info.claimed_l2_block_number = try read_u64(oracle, .l2_claim_block_number) orelse
            return error.InvalidBootValue;
        info.chain_id = try read_u64(oracle, .l2_chain_id) orelse return error.InvalidBootValue;
        const chain = chains.by_chain_id(info.chain_id) orelse return error.UnknownChainId;
        const text = try oracle.get(LocalKey.l2_rollup_config.key(), scratch);
        info.rollup_config = protocol.rollup_json.parse(text) catch {
            return error.RollupConfigInvalid;
        };
        try check_rollup_config(&info.rollup_config, chain);
        info.l1_config = chains.l1_by_chain_id(info.rollup_config.l1_chain_id) orelse
            return error.MissingL1ChainConfig;
        info.proposer = @splat(0);
        const proposer = try oracle.get(LocalKey.proposer.key(), scratch);
        if (proposer.len == 20) {
            info.proposer = proposer[0..20].*;
        } else if (proposer.len != 0) return error.InvalidBootValue;
        info.intermediate_block_interval = try read_u64(oracle, .intermediate_block_interval) orelse
            return error.InvalidBootValue;
        if (info.intermediate_block_interval == 0) return error.InvalidBootValue;
        info.l1_head_number = try read_u64(oracle, .l1_head_number) orelse 0;
        const schedule = try read_u64(oracle, .l2_schedule_block_number) orelse 0;
        info.schedule_block_number = if (schedule == 0) info.claimed_l2_block_number else schedule;
        assert(info.rollup_config.l2_chain_id == info.chain_id);
        return info;
    }
};

/// An 8-byte big-endian local value, or null when served empty.
fn read_u64(oracle: preimage.OracleReader, local: LocalKey) Error!?u64 {
    var buffer: [8]u8 = undefined;
    const bytes = try oracle.get(local.key(), &buffer);
    if (bytes.len == 0) return null;
    if (bytes.len != 8) return error.InvalidBootValue;
    return std.mem.readInt(u64, buffer[0..8], .big);
}

fn check_rollup_config(config: *const RollupConfig, chain: *const chains.ChainConfig) Error!void {
    if (config.l2_chain_id != chain.chain_id) return error.RollupConfigMismatch;
    if (chain.chain_id == chains.devnet.chain_id) return;
    const same = config.l1_chain_id == chain.l1_chain_id and
        config.block_time == chain.block_time and
        config.genesis.l1.hash.eql(chain.genesis_l1_hash) and
        config.genesis.l1.number == chain.genesis_l1_number and
        config.genesis.l2.hash.eql(chain.genesis_l2_hash) and
        config.genesis.l2.number == chain.genesis_l2_number and
        config.genesis.l2_time == chain.genesis_l2_time and
        config.batch_inbox_address.eql(chain.batch_inbox_address) and
        config.deposit_contract_address.eql(chain.deposit_contract_address) and
        config.l1_system_config_address.eql(chain.system_config_address);
    if (!same) return error.RollupConfigMismatch;
}

const testing = std.testing;
const json = @import("../../utilities/json/root.zig");

const BootStore = preimage.MemoryStore(16, 16 * 1024);

fn put_u64(store: *BootStore, local: LocalKey, value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    try store.put(local.key(), &bytes);
}

/// Every required key plus a rollup config with `chain_id`, optional keys empty.
fn fill_store(store: *BootStore, config: *const RollupConfig, json_buffer: []u8) !void {
    try store.put(LocalKey.l1_head.key(), &@as(Hash, @splat(1)));
    try store.put(LocalKey.l2_output_root.key(), &@as(Hash, @splat(2)));
    try store.put(LocalKey.l2_claim.key(), &@as(Hash, @splat(3)));
    try put_u64(store, .l2_claim_block_number, 40);
    try put_u64(store, .l2_chain_id, config.l2_chain_id);
    var out: std.Io.Writer = .fixed(json_buffer);
    var writer = json.Writer.init(&out);
    try protocol.rollup_json.write(&writer, config);
    try store.put(LocalKey.l2_rollup_config.key(), out.buffered());
    try store.put(LocalKey.proposer.key(), "");
    try put_u64(store, .intermediate_block_interval, 10);
    try store.put(LocalKey.l1_head_number.key(), "");
    try store.put(LocalKey.l2_schedule_block_number.key(), "");
}

fn devnet_config() RollupConfig {
    return .{ .l1_chain_id = chains.l1_devnet.chain_id, .l2_chain_id = chains.devnet.chain_id };
}

fn load_from(store: *BootStore) Error!BootInfo {
    var harness: preimage.InProcess = undefined;
    harness.init(testing.allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
        .channel_bytes = 1 << 16,
    }) catch unreachable; // Test allocator with ample memory.
    defer harness.deinit(testing.allocator);
    var scratch: [rollup_config_bytes_max]u8 = undefined;
    return BootInfo.load(harness.oracle_reader(), &scratch);
}

test "boot: loads devnet inputs with defaults for optional keys" {
    var store: BootStore = .{};
    var json_buffer: [8192]u8 = undefined;
    const config = devnet_config();
    try fill_store(&store, &config, &json_buffer);
    const info = try load_from(&store);
    try testing.expectEqual(@as(Hash, @splat(1)), info.l1_head);
    try testing.expectEqual(@as(Hash, @splat(3)), info.claimed_l2_output_root);
    try testing.expectEqual(@as(u64, 40), info.claimed_l2_block_number);
    try testing.expectEqual(@as(u64, 40), info.schedule_block_number);
    try testing.expectEqual(@as(u64, 0), info.l1_head_number);
    try testing.expectEqual(@as(Address, @splat(0)), info.proposer);
    try testing.expectEqual(chains.devnet.chain_id, info.rollup_config.l2_chain_id);
}

test "boot: a mainnet config that disagrees with the built-in chain is rejected" {
    var store: BootStore = .{};
    var json_buffer: [8192]u8 = undefined;
    var config = devnet_config();
    config.l2_chain_id = chains.mainnet.chain_id;
    config.l1_chain_id = chains.mainnet.l1_chain_id;
    try fill_store(&store, &config, &json_buffer);
    try testing.expectError(error.RollupConfigMismatch, load_from(&store));
}

test "boot: zero interval and a malformed integer are rejected" {
    var json_buffer: [8192]u8 = undefined;
    const config = devnet_config();
    var zero: BootStore = .{};
    try put_u64(&zero, .intermediate_block_interval, 0);
    try fill_store(&zero, &config, &json_buffer);
    try testing.expectError(error.InvalidBootValue, load_from(&zero));
    var short: BootStore = .{};
    try short.put(LocalKey.l2_claim_block_number.key(), &.{ 1, 2, 3 });
    try fill_store(&short, &config, &json_buffer);
    try testing.expectError(error.InvalidBootValue, load_from(&short));
}

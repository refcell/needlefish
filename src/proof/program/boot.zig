//! Boot information of the fault-proof program. Port of base/base
//! `crates/proof/proof/src/boot.rs`.
//!
//! The host provides the program's inputs as local preimages (key type `local`, the
//! identifier in the low 8 bytes): hashes are 32 bytes, integers 8-byte big-endian, the
//! proposer 20 bytes, the rollup config JSON. Optional keys the host does not have are
//! served as empty preimages (the wire has no "not found"; see the lane decisions).
//!
//! Trust: the rollup config comes from the host, so for a known chain (outside the
//! devnet) its identity fields (chain ids, genesis, inbox, deposit and system config
//! contracts, block time) must equal the built-in chain config; only upgrade timestamps
//! come from the host. An unknown L2 chain id is a custom chain (base/base `BootInfo`):
//! the rollup config is taken from the host as is, and an unknown L1 chain's config comes
//! from the `l1_config` key (a geth chain config JSON object). Whoever picks a custom
//! chain's boot values vouches for them, exactly as for the claim itself.
//!
//! The proposer (key 8), the intermediate block interval (key 9, required, non-zero) and
//! the schedule block (key 11, at or above the claim; 0 or absent means the claim) are
//! commitments of base/base's TEE and ZK proof journals. The fault-proof client samples
//! intermediate roots at the interval (`intermediate_roots.zig`); the schedule ID is pinned
//! at the schedule block's timestamp (`schedule_id.zig`).

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const chains = @import("../../common/chains/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const schedule_id = @import("schedule_id.zig");

const Hash = [32]u8;
const Address = [20]u8;
const RollupConfig = protocol.RollupConfig;
const json = @import("../../utilities/json/root.zig");

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
    L1ConfigInvalid,
    /// The claimed block is below the L2 genesis block.
    ClaimBeforeGenesis,
    /// The schedule block (key 11) is below the claimed block.
    ScheduleBlockBeforeClaim,
    /// Zenith, which the schedule ID does not commit, is active by the claimed block.
    UncommittedZenithUpgrade,
};

/// Largest L1 config JSON accepted.
pub const l1_config_bytes_max: u32 = 16 * 1024;

/// L2 EIP-1559 parameters (rollup config `chain_op_config`); the Base mainnet values
/// when absent.
pub const ChainOpConfig = struct {
    elasticity: u64 = 6,
    denominator: u64 = 50,
    denominator_canyon: u64 = 250,
};

pub const BootInfo = struct {
    l1_head: Hash,
    agreed_l2_output_root: Hash,
    claimed_l2_output_root: Hash,
    claimed_l2_block_number: u64,
    chain_id: u64,
    rollup_config: RollupConfig,
    l1_config: chains.L1Config,
    chain_op: ChainOpConfig,
    /// The L2 chain is not built in: the rollup config is the host's.
    custom: bool,
    proposer: Address,
    intermediate_block_interval: u64,
    l1_head_number: u64,
    /// The L2 block the claim schedules against; defaults to the claim block.
    schedule_block_number: u64,
    /// The schedule ID pinned at the schedule block (`schedule_id.zig`); the rollup config
    /// keeps only the upgrades of that activated prefix.
    schedule_id: [32]u8,

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
        try load_chain(oracle, &info, scratch);
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
        if (info.claimed_l2_block_number < info.rollup_config.genesis.l2.number) {
            return error.ClaimBeforeGenesis;
        }
        if (info.schedule_block_number < info.claimed_l2_block_number) {
            return error.ScheduleBlockBeforeClaim;
        }
        // Zenith is not contract-backed: refused inside the proven range, dropped after it.
        const claim_timestamp =
            info.rollup_config.l2_block_timestamp(info.claimed_l2_block_number);
        if (info.rollup_config.upgrades.get(.zenith)) |zenith| {
            if (zenith <= claim_timestamp) return error.UncommittedZenithUpgrade;
            info.rollup_config.upgrades.set(.zenith, null);
        }
        const schedule_timestamp =
            info.rollup_config.l2_block_timestamp(info.schedule_block_number);
        info.schedule_id = schedule_id.pin(&info.rollup_config, schedule_timestamp);
        assert(info.rollup_config.l2_chain_id == info.chain_id);
        assert(info.intermediate_block_interval > 0);
        return info;
    }
};

/// The rollup config, its chain op config, and the L1 config.
fn load_chain(oracle: preimage.OracleReader, info: *BootInfo, scratch: []u8) Error!void {
    const text = try oracle.get(LocalKey.l2_rollup_config.key(), scratch);
    info.rollup_config = protocol.rollup_json.parse(text) catch {
        return error.RollupConfigInvalid;
    };
    if (info.rollup_config.l2_chain_id != info.chain_id) return error.RollupConfigMismatch;
    info.chain_op = parse_chain_op(text) catch return error.RollupConfigInvalid;
    info.custom = chains.by_chain_id(info.chain_id) == null;
    if (chains.by_chain_id(info.chain_id)) |chain| {
        try check_rollup_config(&info.rollup_config, chain);
    }
    if (chains.l1_by_chain_id(info.rollup_config.l1_chain_id)) |known| {
        info.l1_config = known.*;
        return;
    }
    if (!info.custom) return error.MissingL1ChainConfig;
    var buffer: [l1_config_bytes_max]u8 = undefined;
    const l1_text = try oracle.get(LocalKey.l1_config.key(), &buffer);
    if (l1_text.len == 0) return error.MissingL1ChainConfig;
    info.l1_config = parse_l1_config(l1_text) catch return error.L1ConfigInvalid;
    if (info.l1_config.chain_id != info.rollup_config.l1_chain_id) {
        return error.L1ConfigInvalid;
    }
}

fn find_u64(text: []const u8, path: []const []const u8) !?u64 {
    const raw = try json.find_path(text, path) orelse return null;
    if (std.mem.eql(u8, raw, "null")) return null;
    return try std.fmt.parseInt(u64, raw, 10);
}

/// `chain_op_config` of a rollup config JSON (missing fields keep their defaults).
pub fn parse_chain_op(text: []const u8) !ChainOpConfig {
    var config: ChainOpConfig = .{};
    const fields = .{
        .{ "eip1559Elasticity", &config.elasticity },
        .{ "eip1559Denominator", &config.denominator },
        .{ "eip1559DenominatorCanyon", &config.denominator_canyon },
    };
    inline for (fields) |field| {
        if (try find_u64(text, &.{ "chain_op_config", field[0] })) |value| field[1].* = value;
    }
    if (config.elasticity == 0 or config.denominator == 0) return error.InvalidChainOp;
    if (config.denominator_canyon == 0) return error.InvalidChainOp;
    return config;
}

/// An L1 config from a geth chain config JSON object (`chainId`, `shanghaiTime`, ...).
pub fn parse_l1_config(text: []const u8) !chains.L1Config {
    const chain_id = try find_u64(text, &.{"chainId"}) orelse return error.MissingChainId;
    var config: chains.L1Config = .{
        .chain_id = chain_id,
        .shanghai = try find_u64(text, &.{"shanghaiTime"}),
        .cancun = try find_u64(text, &.{"cancunTime"}),
        .prague = try find_u64(text, &.{"pragueTime"}),
        .osaka = try find_u64(text, &.{"osakaTime"}),
        .bpo1 = try find_u64(text, &.{"bpo1Time"}),
        .bpo2 = try find_u64(text, &.{"bpo2Time"}),
    };
    if (try json.find_path(text, &.{"depositContractAddress"})) |raw| {
        if (raw.len < 2 or raw[0] != '"') return error.InvalidAddress;
        const bytes = try json.parse_fixed(20, raw[1 .. raw.len - 1]);
        config.deposit_contract_address = .{ .bytes = bytes };
    }
    assert(config.chain_id == chain_id);
    return config;
}

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
    // Pinning is idempotent: the loaded config already holds only the activated prefix.
    var pinned = info.rollup_config;
    const timestamp = pinned.l2_block_timestamp(40);
    try testing.expectEqual(info.schedule_id, schedule_id.pin(&pinned, timestamp));
    try testing.expectEqual(@as(u64, 0), info.l1_head_number);
    try testing.expectEqual(@as(Address, @splat(0)), info.proposer);
    try testing.expectEqual(chains.devnet.chain_id, info.rollup_config.l2_chain_id);
}

test "boot: the schedule block may not precede the claim, nor the claim genesis" {
    var json_buffer: [8192]u8 = undefined;
    var config = devnet_config();
    var later: BootStore = .{};
    try put_u64(&later, .l2_schedule_block_number, 41);
    try fill_store(&later, &config, &json_buffer);
    try testing.expectEqual(@as(u64, 41), (try load_from(&later)).schedule_block_number);
    var early: BootStore = .{};
    try put_u64(&early, .l2_schedule_block_number, 39);
    try fill_store(&early, &config, &json_buffer);
    try testing.expectError(error.ScheduleBlockBeforeClaim, load_from(&early));
    var genesis: BootStore = .{};
    config.genesis.l2.number = 41;
    try fill_store(&genesis, &config, &json_buffer);
    try testing.expectError(error.ClaimBeforeGenesis, load_from(&genesis));
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

test "boot: a custom chain takes the host's rollup and L1 configs" {
    var store: BootStore = .{};
    var json_buffer: [8192]u8 = undefined;
    var config = devnet_config();
    config.l2_chain_id = 901;
    config.l1_chain_id = 900;
    try fill_store(&store, &config, &json_buffer);
    var empty: BootStore = store;
    try empty.put(LocalKey.l1_config.key(), "");
    try testing.expectError(error.MissingL1ChainConfig, load_from(&empty));
    var wrong: BootStore = store;
    try wrong.put(LocalKey.l1_config.key(), "{\"chainId\":1,\"cancunTime\":0}");
    try testing.expectError(error.L1ConfigInvalid, load_from(&wrong));
    try store.put(
        LocalKey.l1_config.key(),
        "{\"chainId\":900,\"shanghaiTime\":0,\"cancunTime\":0,\"pragueTime\":null}",
    );
    const info = try load_from(&store);
    try testing.expect(info.custom);
    try testing.expectEqual(@as(u64, 900), info.l1_config.chain_id);
    try testing.expectEqual(@as(?u64, 0), info.l1_config.cancun);
    try testing.expectEqual(@as(?u64, null), info.l1_config.prague);
    try testing.expectEqual(@as(u64, 50), info.chain_op.denominator);
}

test "boot: chain op config and L1 config parsing" {
    const text =
        \\{"chain_op_config":{"eip1559Elasticity":10,"eip1559Denominator":40,
        \\"eip1559DenominatorCanyon":200}}
    ;
    const op = try parse_chain_op(text);
    try testing.expectEqual(@as(u64, 10), op.elasticity);
    try testing.expectEqual(@as(u64, 200), op.denominator_canyon);
    const zero = "{\"chain_op_config\":{\"eip1559Elasticity\":0}}";
    try testing.expectError(error.InvalidChainOp, parse_chain_op(zero));
    const l1 = try parse_l1_config(
        \\{"chainId":5,"depositContractAddress":"0x00000000000000000000000000000000000000aa"}
    );
    try testing.expectEqual(@as(u8, 0xaa), l1.deposit_contract_address.?.bytes[19]);
    try testing.expectError(error.MissingChainId, parse_l1_config("{}"));
}

const fuzz = @import("../../testing/fuzz.zig");

fn fuzz_parse(_: void, smith: *std.testing.Smith) anyerror!void {
    var text: [256]u8 = undefined;
    const length = smith.slice(&text);
    // Arbitrary JSON-ish text parses or fails cleanly.
    if (parse_chain_op(text[0..length])) |op| {
        try testing.expect(op.elasticity > 0 and op.denominator > 0);
    } else |_| {}
    _ = parse_l1_config(text[0..length]) catch {};
}

test "boot: fuzz config parsing" {
    try fuzz.run({}, fuzz_parse, .{ .iterations = 1024 });
}

test "boot: Zenith is refused by the claim and dropped after it" {
    var json_buffer: [8192]u8 = undefined;
    var config = devnet_config();
    config.upgrades.set(.zenith, std.math.maxInt(u32));
    var future: BootStore = .{};
    try fill_store(&future, &config, &json_buffer);
    const info = try load_from(&future);
    try testing.expectEqual(@as(?u64, null), info.rollup_config.upgrades.get(.zenith));
    config.upgrades.set(.zenith, config.genesis.l2_time);
    var active: BootStore = .{};
    try fill_store(&active, &config, &json_buffer);
    try testing.expectError(error.UncommittedZenithUpgrade, load_from(&active));
}

//! Per-chain configuration and its config hash (base/base
//! `crates/proof/primitives/src/per_chain_config.rs`).
//!
//! The config hash identifies a chain in TEE and ZK proof journals: keccak256 of a fixed
//! 212-byte big-endian encoding of the genesis anchor and two L1 contract addresses. It
//! stays stable across network upgrades because no upgrade timestamp is encoded. The
//! overhead field exists but is forced to zero and left out of the encoding.

const std = @import("std");
const assert = std.debug.assert;

const keccak = @import("../../common/crypto/keccak.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const chains = @import("../../common/chains/root.zig");

pub const Hash = [32]u8;
pub const Address = [20]u8;

const version_0: u64 = 0;

/// Total size of the binary-serialized `PerChainConfig`.
pub const marshal_binary_size = 212;

comptime {
    assert(marshal_binary_size == 8 + 32 + 32 + 32 + 8 + 20 + 32 + 8 + 20 + 20);
}

pub const BlockId = struct {
    hash: Hash = @splat(0),
    number: u64 = 0,
};

pub const GenesisSystemConfig = struct {
    batcher_addr: Address = @splat(0),
    /// Forced to zero.
    overhead: Hash = @splat(0),
    scalar: Hash = @splat(0),
    gas_limit: u64 = 30_000_000,
};

pub const Genesis = struct {
    l1: BlockId = .{},
    l2: BlockId = .{},
    l2_time: u64 = 0,
    system_config: GenesisSystemConfig = .{},
};

pub const PerChainConfig = struct {
    chain_id: u256 = 1,
    genesis: Genesis = .{},
    /// Forced to 1 by `force_defaults`; not encoded.
    block_time: u64 = 2,
    deposit_contract_address: Address = @splat(0),
    l1_system_config_address: Address = @splat(0),

    /// Null when the rollup config has no genesis system config.
    pub fn from_rollup_config(config: *const protocol.RollupConfig) ?PerChainConfig {
        const system = config.genesis.system_config orelse return null;
        var scalar: Hash = undefined;
        std.mem.writeInt(u256, &scalar, system.scalar, .big);
        const result: PerChainConfig = .{
            .chain_id = config.l2_chain_id,
            .genesis = .{
                .l1 = .{ .hash = config.genesis.l1.hash.bytes, .number = config.genesis.l1.number },
                .l2 = .{ .hash = config.genesis.l2.hash.bytes, .number = config.genesis.l2.number },
                .l2_time = config.genesis.l2_time,
                .system_config = .{
                    .batcher_addr = system.batcher_address.bytes,
                    .scalar = scalar,
                    .gas_limit = system.gas_limit,
                },
            },
            .block_time = config.block_time,
            .deposit_contract_address = config.deposit_contract_address.bytes,
            .l1_system_config_address = config.l1_system_config_address.bytes,
        };
        assert(result.chain_id == config.l2_chain_id);
        assert(std.mem.allEqual(u8, &result.genesis.system_config.overhead, 0));
        return result;
    }

    /// The config of a built-in chain, as base/base derives it through
    /// `RollupConfig::from(ChainConfig)`: built-in chains always carry a system config.
    pub fn from_chain_config(chain: *const chains.ChainConfig) PerChainConfig {
        assert(chain.chain_id != 0);
        var scalar: Hash = undefined;
        std.mem.writeInt(u256, &scalar, chain.genesis_scalar, .big);
        const result: PerChainConfig = .{
            .chain_id = chain.chain_id,
            .genesis = .{
                .l1 = .{ .hash = chain.genesis_l1_hash.bytes, .number = chain.genesis_l1_number },
                .l2 = .{ .hash = chain.genesis_l2_hash.bytes, .number = chain.genesis_l2_number },
                .l2_time = chain.genesis_l2_time,
                .system_config = .{
                    .batcher_addr = chain.genesis_batcher_address.bytes,
                    .scalar = scalar,
                    .gas_limit = chain.genesis_gas_limit,
                },
            },
            .block_time = chain.block_time,
            .deposit_contract_address = chain.deposit_contract_address.bytes,
            .l1_system_config_address = chain.system_config_address.bytes,
        };
        assert(result.chain_id == chain.chain_id);
        return result;
    }

    /// The canonical 212-byte encoding (all big-endian):
    /// version(8) chain_id(32) l1.hash(32) l2.hash(32) l2_time(8) batcher(20) scalar(32)
    /// gas_limit(8) deposit_contract(20) l1_system_config(20).
    pub fn marshal_binary(config: *const PerChainConfig) [marshal_binary_size]u8 {
        var out: [marshal_binary_size]u8 = undefined;
        var offset: usize = 0;
        put_int(u64, &out, &offset, version_0);
        put_int(u256, &out, &offset, config.chain_id);
        put_bytes(&out, &offset, &config.genesis.l1.hash);
        put_bytes(&out, &offset, &config.genesis.l2.hash);
        put_int(u64, &out, &offset, config.genesis.l2_time);
        put_bytes(&out, &offset, &config.genesis.system_config.batcher_addr);
        put_bytes(&out, &offset, &config.genesis.system_config.scalar);
        put_int(u64, &out, &offset, config.genesis.system_config.gas_limit);
        put_bytes(&out, &offset, &config.deposit_contract_address);
        put_bytes(&out, &offset, &config.l1_system_config_address);
        assert(offset == marshal_binary_size);
        assert(std.mem.allEqual(u8, out[0..8], 0));
        return out;
    }

    /// keccak256 of `marshal_binary`. Call `force_defaults` first for the canonical hash.
    pub fn hash(config: *const PerChainConfig) Hash {
        const encoded = config.marshal_binary();
        const digest = keccak.keccak256(&encoded);
        assert(encoded.len == marshal_binary_size);
        return digest;
    }

    /// Normalizes the fields that do not identify a chain: block time 1, L2 genesis
    /// number 0, overhead zero.
    pub fn force_defaults(config: *PerChainConfig) void {
        config.block_time = 1;
        config.genesis.l2.number = 0;
        config.genesis.system_config.overhead = @splat(0);
        assert(config.block_time == 1);
        assert(config.genesis.l2.number == 0);
    }

    /// A full rollup config with default timings and every upgrade through Azul active at
    /// the L2 genesis time (base/base `to_rollup_config`). base/base also sets the Base
    /// mainnet fee config; `protocol.RollupConfig` keeps no fee config, so it is left out.
    pub fn to_rollup_config(config: *const PerChainConfig) protocol.RollupConfig {
        assert(config.chain_id <= std.math.maxInt(u64));
        const genesis_time = config.genesis.l2_time;
        var result: protocol.RollupConfig = .{
            .l1_chain_id = 1,
            .l2_chain_id = @intCast(config.chain_id),
            .genesis = .{
                .l1 = .{
                    .hash = .{ .bytes = config.genesis.l1.hash },
                    .number = config.genesis.l1.number,
                },
                .l2 = .{
                    .hash = .{ .bytes = config.genesis.l2.hash },
                    .number = config.genesis.l2.number,
                },
                .l2_time = genesis_time,
                .system_config = .{
                    .batcher_address = .{ .bytes = config.genesis.system_config.batcher_addr },
                    .scalar = std.mem.readInt(u256, &config.genesis.system_config.scalar, .big),
                    .gas_limit = config.genesis.system_config.gas_limit,
                },
            },
            .block_time = config.block_time,
            .max_sequencer_drift = 600,
            .seq_window_size = 3600,
            .channel_timeout = 300,
            .granite_channel_timeout = 300,
            .deposit_contract_address = .{ .bytes = config.deposit_contract_address },
            .l1_system_config_address = .{ .bytes = config.l1_system_config_address },
            .blobs_enabled_l1_timestamp = 0,
        };
        const active = [_]protocol.Upgrade{
            .regolith, .canyon,   .delta,   .ecotone, .fjord,
            .granite,  .holocene, .isthmus, .jovian,  .azul,
        };
        for (active) |upgrade| result.upgrades.set(upgrade, genesis_time);
        assert(result.upgrades.get(.pectra_blob_schedule) == null);
        assert(result.upgrades.get(.beryl) == null);
        return result;
    }
};

/// The canonical config hash of a built-in chain (base/base `config_hash_for_chain`).
pub fn config_hash_for_chain(chain_id: u64) ?Hash {
    const chain = chains.by_chain_id(chain_id) orelse return null;
    var config: PerChainConfig = .from_chain_config(chain);
    config.force_defaults();
    assert(config.chain_id == chain_id);
    return config.hash();
}

fn put_int(comptime T: type, out: []u8, offset: *usize, value: T) void {
    const size = @sizeOf(T);
    assert(offset.* + size <= out.len);
    std.mem.writeInt(T, out[offset.*..][0..size], value, .big);
    offset.* += size;
}

fn put_bytes(out: []u8, offset: *usize, bytes: []const u8) void {
    assert(offset.* + bytes.len <= out.len);
    assert(bytes.len > 0);
    @memcpy(out[offset.*..][0..bytes.len], bytes);
    offset.* += bytes.len;
}

const testing = std.testing;

fn address_of(comptime text: []const u8) Address {
    return primitives.Address.comptime_hex(text).bytes;
}

fn hash_of(comptime text: []const u8) Hash {
    return primitives.B256.comptime_hex(text).bytes;
}

fn sample_config() PerChainConfig {
    return .{
        .chain_id = 8453,
        .genesis = .{
            .l1 = .{ .hash = @splat(0x11), .number = 1 },
            .l2 = .{ .hash = @splat(0x22), .number = 0 },
            .l2_time = 1686789600,
            .system_config = .{
                .batcher_addr = address_of("5050f69a9786f081509234f1a7f4684b5e5b76c9"),
                .scalar = @splat(0),
                .gas_limit = 30_000_000,
            },
        },
        .block_time = 1,
        .deposit_contract_address = address_of("49048044d57e1c92a77f79988d21fa8faf74e97e"),
        .l1_system_config_address = address_of("73a79fab69143498ed3712e519a88a918e1f4072"),
    };
}

test "per chain config: marshal binary golden" {
    const expected_hex = "0000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000002105" ++
        "1111111111111111111111111111111111111111111111111111111111111111" ++
        "2222222222222222222222222222222222222222222222222222222222222222" ++
        "00000000648a5de0" ++
        "5050f69a9786f081509234f1a7f4684b5e5b76c9" ++
        "0000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000001c9c380" ++
        "49048044d57e1c92a77f79988d21fa8faf74e97e" ++
        "73a79fab69143498ed3712e519a88a918e1f4072";
    var expected: [marshal_binary_size]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try testing.expectEqualSlices(u8, &expected, &sample_config().marshal_binary());
}

test "per chain config: hash golden" {
    const expected = hash_of("f914a90550e1b3f9d107005221dc01403f63ee8e12884d71699046ddbd7036b2");
    try testing.expectEqual(expected, sample_config().hash());
}

test "per chain config: hash changes with chain id" {
    var other = sample_config();
    other.chain_id = 1;
    try testing.expect(!std.mem.eql(u8, &sample_config().hash(), &other.hash()));
}

test "per chain config: force defaults" {
    var config: PerChainConfig = .{
        .chain_id = 8453,
        .genesis = .{
            .l2 = .{ .number = 100 },
            .system_config = .{ .overhead = @splat(0xff) },
        },
        .block_time = 10,
    };
    config.force_defaults();
    try testing.expectEqual(@as(u64, 1), config.block_time);
    try testing.expectEqual(@as(u64, 0), config.genesis.l2.number);
    try testing.expectEqual(@as(Hash, @splat(0)), config.genesis.system_config.overhead);
}

test "per chain config: to rollup config" {
    const config = sample_config();
    const rollup = config.to_rollup_config();
    try testing.expectEqual(@as(u64, 8453), rollup.l2_chain_id);
    try testing.expectEqual(config.block_time, rollup.block_time);
    try testing.expectEqual(config.deposit_contract_address, rollup.deposit_contract_address.bytes);
    try testing.expectEqual(config.l1_system_config_address, rollup.l1_system_config_address.bytes);
    try testing.expectEqual(config.genesis.l1.hash, rollup.genesis.l1.hash.bytes);
    try testing.expectEqual(config.genesis.l2.hash, rollup.genesis.l2.hash.bytes);
    try testing.expectEqual(@as(u64, 600), rollup.max_sequencer_drift);
    try testing.expectEqual(@as(u64, 3600), rollup.seq_window_size);
    try testing.expectEqual(@as(u64, 300), rollup.channel_timeout);
    const genesis_time = rollup.genesis.l2_time;
    const active = [_]protocol.Upgrade{
        .canyon, .delta, .ecotone, .fjord, .granite, .holocene, .isthmus, .regolith, .azul,
    };
    for (active) |upgrade| try testing.expectEqual(genesis_time, rollup.upgrades.get(upgrade));
    // The rollup config round-trips to the same config hash.
    var back = PerChainConfig.from_rollup_config(&rollup).?;
    back.force_defaults();
    try testing.expectEqual(config.hash(), back.hash());
}

test "per chain config: from rollup config needs a system config" {
    var rollup = sample_config().to_rollup_config();
    rollup.genesis.system_config = null;
    try testing.expect(PerChainConfig.from_rollup_config(&rollup) == null);
}

test "per chain config: config hashes of the built-in chains match base/base" {
    const Case = struct { u64, []const u8 };
    const cases = [_]Case{
        .{ 8453, "1607709d90d40904f790574404e2ad614eac858f6162faa0ec34c6bf5e5f3c57" },
        .{ 84532, "12e9c45f19f9817c6d4385fad29e7a70c355502cf0883e76a9a7e478a85d1360" },
        .{ 84538453, "846b1fd10a5e22fb7572cc4ac794454d301b382c64ab934091e519486e5200be" },
        .{ 763360, "d14ddabfc0ad1dd737d6e5917cf271fd479bd539c9b3d85a602589c679a9983a" },
    };
    for (cases) |case| {
        var expected: Hash = undefined;
        _ = try std.fmt.hexToBytes(&expected, case[1]);
        try testing.expectEqual(expected, config_hash_for_chain(case[0]).?);
    }
    try testing.expect(config_hash_for_chain(999999) == null);
}

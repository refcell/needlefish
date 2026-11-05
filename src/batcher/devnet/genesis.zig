//! Devnet chain configuration and the files `base devnet init` writes:
//! `l1-genesis.json`, `l2-genesis.json` (geth-style genesis) and `rollup.json`
//! (base/base `RollupConfig` serde schema). See docs/DEVNET.md.
//!
//! Writers take every input explicitly (timestamps, genesis hashes), so the output
//! is a pure function of the config and is easy to golden-test.

const std = @import("std");
const assert = std.debug.assert;
const Writer = std.Io.Writer;
const primitives = @import("../../common/primitives/root.zig");
const accounts = @import("accounts.zig");
const portal = @import("portal.zig");
const common_genesis = @import("../../common/genesis/root.zig");

const Address = primitives.Address;

pub const Config = struct {
    l1_chain_id: u64 = 900,
    l2_chain_id: u64 = 901,
    l1_block_time_s: u64 = 2,
    l2_block_time_s: u64 = 1,
    /// Genesis timestamp shared by L1 and L2 (seconds since the Unix epoch).
    genesis_timestamp: u64,
    l1_gas_limit: u64 = 60_000_000,
    l2_gas_limit: u64 = 60_000_000,
    seq_window_size: u64 = 3600,
    channel_timeout: u64 = 300,
    max_sequencer_drift: u64 = 1800,
    /// Balance of each funded dev account, in wei (10,000 ETH).
    funded_balance_wei: u256 = 10_000 * std.math.pow(u256, 10, 18),
    eip1559_elasticity: u32 = 6,
    eip1559_denominator: u32 = 50,
    eip1559_denominator_canyon: u32 = 250,
    l2_min_base_fee_wei: u64 = 0,

    pub fn batch_inbox(config: *const Config) Address {
        var address: Address = .zero;
        address.bytes[0] = 0xff;
        std.mem.writeInt(u64, address.bytes[12..20], config.l2_chain_id, .big);
        return address;
    }
};

/// Fixed L1 contract addresses. The devnet has no deployment step: contracts are
/// placed in the L1 genesis alloc at these addresses.
pub const portal_address: Address = low_address(0xde90);
pub const system_config_address: Address = low_address(0x5cf9);

fn low_address(comptime value: u16) Address {
    var address: Address = .zero;
    std.mem.writeInt(u16, address.bytes[18..20], value, .big);
    return address;
}

fn write_address(w: *Writer, address: Address) Writer.Error!void {
    try w.print("\"0x{x}\"", .{&address.bytes});
}

fn write_hash(w: *Writer, hash: [32]u8) Writer.Error!void {
    try w.print("\"0x{x}\"", .{&hash});
}

fn write_funded_alloc(w: *Writer, config: *const Config) Writer.Error!void {
    for (0..accounts.funded_count) |index| {
        const account = accounts.derive_dev(@intCast(index));
        if (index > 0) try w.writeAll(",\n");
        try w.writeAll("    ");
        try write_address(w, account.address);
        try w.print(": {{ \"balance\": \"0x{x}\" }}", .{config.funded_balance_wei});
    }
}

/// L1 genesis: Ethereum with every fork through Prague active at genesis.
pub fn write_l1_genesis(w: *Writer, config: *const Config) Writer.Error!void {
    try w.writeAll("{\n  \"config\": {\n");
    try w.print("    \"chainId\": {d},\n", .{config.l1_chain_id});
    try write_block_forks(w);
    try w.writeAll(
        \\    "shanghaiTime": 0,
        \\    "cancunTime": 0,
        \\    "pragueTime": 0,
        \\    "blobSchedule": {
        \\      "cancun": { "target": 3, "max": 6, "baseFeeUpdateFraction": 3338477 },
        \\      "prague": { "target": 6, "max": 9, "baseFeeUpdateFraction": 5007716 }
        \\    }
        \\  },
        \\
    );
    try write_header_fields(w, config.genesis_timestamp, config.l1_gas_limit, &.{});
    try w.writeAll("  \"alloc\": {\n");
    try write_funded_alloc(w, config);
    try w.writeAll(",\n    ");
    try write_address(w, portal_address);
    try w.print(": {{ \"balance\": \"0x0\", \"code\": \"0x{x}\" }}\n  }}\n}}\n", .{&portal.code});
}

fn write_block_forks(w: *Writer) Writer.Error!void {
    const forks = [_][]const u8{
        "homesteadBlock",   "eip150Block",         "eip155Block",     "eip158Block",
        "byzantiumBlock",   "constantinopleBlock", "petersburgBlock", "istanbulBlock",
        "muirGlacierBlock", "berlinBlock",         "londonBlock",     "arrowGlacierBlock",
        "grayGlacierBlock", "mergeNetsplitBlock",
    };
    for (forks) |fork| try w.print("    \"{s}\": 0,\n", .{fork});
    try w.writeAll("    \"terminalTotalDifficulty\": 0,\n");
}

fn write_header_fields(
    w: *Writer,
    timestamp: u64,
    gas_limit: u64,
    extra_data: []const u8,
) Writer.Error!void {
    assert(gas_limit > 0);
    assert(extra_data.len <= 32);
    try w.print("  \"timestamp\": \"0x{x}\",\n", .{timestamp});
    try w.print("  \"gasLimit\": \"0x{x}\",\n", .{gas_limit});
    try w.print("  \"extraData\": \"0x{x}\",\n", .{extra_data});
    try w.writeAll(
        \\  "nonce": "0x0",
        \\  "difficulty": "0x0",
        \\  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        \\  "coinbase": "0x0000000000000000000000000000000000000000",
        \\  "baseFeePerGas": "0x3b9aca00",
        \\  "excessBlobGas": "0x0",
        \\  "blobGasUsed": "0x0",
        \\  "number": "0x0",
        \\  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        \\
    );
}

/// OP upgrades activated at L2 genesis, in rollup-config key order.
const l2_upgrade_keys = [_][]const u8{
    "regolith", "canyon", "delta", "ecotone", "fjord", "granite", "holocene",
    "isthmus",  "jovian",
};

/// Jovian extraData: version 1 ++ denominator u32 ++ elasticity u32 ++ min base fee u64.
pub fn l2_extra_data(config: *const Config) [17]u8 {
    var out: [17]u8 = undefined;
    out[0] = 1;
    std.mem.writeInt(u32, out[1..5], config.eip1559_denominator_canyon, .big);
    std.mem.writeInt(u32, out[5..9], config.eip1559_elasticity, .big);
    std.mem.writeInt(u64, out[9..17], config.l2_min_base_fee_wei, .big);
    return out;
}

/// L2 genesis: OP Stack chain config, every upgrade through Jovian at genesis.
pub fn write_l2_genesis(w: *Writer, config: *const Config) Writer.Error!void {
    try w.writeAll("{\n  \"config\": {\n");
    try w.print("    \"chainId\": {d},\n", .{config.l2_chain_id});
    try write_block_forks(w);
    try w.writeAll("    \"bedrockBlock\": 0,\n");
    try w.writeAll("    \"shanghaiTime\": 0,\n    \"cancunTime\": 0,\n    \"pragueTime\": 0,\n");
    for (l2_upgrade_keys) |key| try w.print("    \"{s}Time\": 0,\n", .{key});
    try w.print(
        \\    "optimism": {{
        \\      "eip1559Elasticity": {d},
        \\      "eip1559Denominator": {d},
        \\      "eip1559DenominatorCanyon": {d}
        \\    }}
        \\  }},
        \\
    , .{
        config.eip1559_elasticity,
        config.eip1559_denominator,
        config.eip1559_denominator_canyon,
    });
    const extra = l2_extra_data(config);
    try write_header_fields(w, config.genesis_timestamp, config.l2_gas_limit, &extra);
    try w.writeAll("  \"alloc\": {\n");
    try write_funded_alloc(w, config);
    try w.writeAll("\n  }\n}\n");
}

pub const GenesisAnchor = struct {
    l1_hash: [32]u8,
    l2_hash: [32]u8,
};

/// rollup.json in base/base's `RollupConfig` serde layout.
pub fn write_rollup_config(
    w: *Writer,
    config: *const Config,
    anchor: GenesisAnchor,
) Writer.Error!void {
    try w.writeAll("{\n  \"genesis\": {\n    \"l1\": { \"hash\": ");
    try write_hash(w, anchor.l1_hash);
    try w.writeAll(", \"number\": 0 },\n    \"l2\": { \"hash\": ");
    try write_hash(w, anchor.l2_hash);
    try w.print(", \"number\": 0 }},\n    \"l2_time\": {d},\n", .{config.genesis_timestamp});
    try write_system_config(w, config);
    try w.print(
        \\  "block_time": {d},
        \\  "max_sequencer_drift": {d},
        \\  "seq_window_size": {d},
        \\  "channel_timeout": {d},
        \\  "l1_chain_id": {d},
        \\  "l2_chain_id": {d},
        \\
    , .{
        config.l2_block_time_s, config.max_sequencer_drift, config.seq_window_size,
        config.channel_timeout, config.l1_chain_id,         config.l2_chain_id,
    });
    for (l2_upgrade_keys) |key| try w.print("  \"{s}_time\": 0,\n", .{key});
    try w.writeAll("  \"pectra_blob_schedule_time\": 0,\n");
    try w.writeAll("  \"batch_inbox_address\": ");
    try write_address(w, config.batch_inbox());
    try w.writeAll(",\n  \"deposit_contract_address\": ");
    try write_address(w, portal_address);
    try w.writeAll(",\n  \"l1_system_config_address\": ");
    try write_address(w, system_config_address);
    try w.writeAll(",\n  \"protocol_versions_address\": ");
    try write_address(w, .zero);
    try w.print(
        \\,
        \\  "chain_op_config": {{
        \\    "eip1559Elasticity": {d},
        \\    "eip1559Denominator": {d},
        \\    "eip1559DenominatorCanyon": {d}
        \\  }}
        \\}}
        \\
    , .{
        config.eip1559_elasticity,
        config.eip1559_denominator,
        config.eip1559_denominator_canyon,
    });
}

fn write_system_config(w: *Writer, config: *const Config) Writer.Error!void {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    try w.writeAll("    \"system_config\": {\n      \"batcherAddr\": ");
    try write_address(w, batcher.address);
    try w.writeAll(",\n      \"overhead\": ");
    try write_hash(w, @splat(0));
    // Ecotone scalar: version 1, blob base fee scalar 0, base fee scalar 1368 (mainnet-like).
    var scalar: [32]u8 = @splat(0);
    scalar[0] = 1;
    std.mem.writeInt(u32, scalar[28..32], 1368, .big);
    try w.writeAll(",\n      \"scalar\": ");
    try write_hash(w, scalar);
    try w.print(
        \\,
        \\      "gasLimit": {d},
        \\      "baseFeeScalar": 1368,
        \\      "blobBaseFeeScalar": 0,
        \\      "eip1559Denominator": {d},
        \\      "eip1559Elasticity": {d},
        \\      "operatorFeeScalar": 0,
        \\      "operatorFeeConstant": 0,
        \\      "minBaseFee": {d},
        \\      "daFootprintGasScalar": 0
        \\    }}
        \\  }},
        \\
    , .{
        config.l2_gas_limit,
        config.eip1559_denominator_canyon,
        config.eip1559_elasticity,
        config.l2_min_base_fee_wei,
    });
}

/// Genesis block hashes of the generated L1 and L2 genesis files, computed in process
/// (state trie + genesis header) so rollup.json is correct before any node starts.
pub fn compute_anchor(allocator: std.mem.Allocator, config: *const Config) !GenesisAnchor {
    return .{
        .l1_hash = try genesis_hash(allocator, config, .l1),
        .l2_hash = try genesis_hash(allocator, config, .l2),
    };
}

const Layer = enum { l1, l2 };

fn genesis_hash(allocator: std.mem.Allocator, config: *const Config, layer: Layer) ![32]u8 {
    var allocating: Writer.Allocating = .init(allocator);
    defer allocating.deinit();
    switch (layer) {
        .l1 => try write_l1_genesis(&allocating.writer, config),
        .l2 => try write_l2_genesis(&allocating.writer, config),
    }
    const parsed = try common_genesis.parse(allocator, allocating.written());
    defer parsed.deinit();
    const genesis = &parsed.value;
    assert(genesis.accounts.len >= accounts.funded_count);
    const root = try genesis.compute_state_root(allocator);
    const header = try genesis.header(allocator, root);
    return header.hash().bytes;
}

const testing = std.testing;

test "genesis: in-process anchor is deterministic and distinct per layer" {
    const config: Config = .{ .genesis_timestamp = 1_700_000_000 };
    const first = try compute_anchor(testing.allocator, &config);
    const second = try compute_anchor(testing.allocator, &config);
    try testing.expectEqualSlices(u8, &first.l1_hash, &second.l1_hash);
    try testing.expectEqualSlices(u8, &first.l2_hash, &second.l2_hash);
    try testing.expect(!std.mem.eql(u8, &first.l1_hash, &first.l2_hash));
    const later: Config = .{ .genesis_timestamp = 1_700_000_001 };
    const moved = try compute_anchor(testing.allocator, &later);
    try testing.expect(!std.mem.eql(u8, &first.l1_hash, &moved.l1_hash));
}

fn expect_valid_json(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
}

test "genesis: batch inbox follows the 0xff00..chain id convention" {
    const config: Config = .{ .genesis_timestamp = 0 };
    var expected: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "ff00000000000000000000000000000000000385");
    try testing.expectEqualSlices(u8, &expected, &config.batch_inbox().bytes);
}

test "genesis: L1 and L2 genesis are valid JSON with funded accounts" {
    const config: Config = .{ .genesis_timestamp = 1_700_000_000 };
    var buffer: [16 * 1024]u8 = undefined;
    const cases = .{
        .{ write_l1_genesis, 900, accounts.funded_count + 1 }, // + portal
        .{ write_l2_genesis, 901, accounts.funded_count },
    };
    inline for (cases) |case| {
        var w: Writer = .fixed(&buffer);
        try case[0](&w, &config);
        const parsed = try expect_valid_json(w.buffered());
        defer parsed.deinit();
        const root = parsed.value.object;
        const chain_id = root.get("config").?.object.get("chainId").?.integer;
        try testing.expectEqual(@as(i64, case[1]), chain_id);
        try testing.expectEqual(@as(usize, case[2]), root.get("alloc").?.object.count());
        try testing.expectEqualStrings("0x6553f100", root.get("timestamp").?.string);
    }
}

test "genesis: rollup config is valid JSON with the expected anchors" {
    const config: Config = .{ .genesis_timestamp = 1_700_000_000 };
    var buffer: [8 * 1024]u8 = undefined;
    var w: Writer = .fixed(&buffer);
    try write_rollup_config(&w, &config, .{ .l1_hash = @splat(0x11), .l2_hash = @splat(0x22) });
    const parsed = try expect_valid_json(w.buffered());
    defer parsed.deinit();
    const root = parsed.value.object;
    const genesis = root.get("genesis").?.object;
    try testing.expectEqual(@as(i64, 1_700_000_000), genesis.get("l2_time").?.integer);
    const l2 = genesis.get("l2").?.object.get("hash").?.string;
    try testing.expect(std.mem.startsWith(u8, l2, "0x2222"));
    try testing.expectEqual(@as(i64, 0), root.get("jovian_time").?.integer);
    try testing.expectEqualStrings(
        "0x976ea74026e726554db657fa54763abd0c3a0aa9",
        genesis.get("system_config").?.object.get("batcherAddr").?.string,
    );
}

//! `rollup.json` codec for `RollupConfig` (base/base `crates/common/genesis/src/rollup.rs`
//! serde format): snake_case top-level fields, flattened `<upgrade>_time` activations, Base
//! upgrades nested under `"base"` (`azul`/`v1`, `beryl`/`v2`, `cobalt`/`v3`, `denim`,
//! `everest`, `zenith`/`future`), camelCase genesis `system_config`, `blobs_data`.
//!
//! Reading is lenient: unknown fields (e.g. `chain_op_config`, which this node does not
//! model) are skipped, and integers may be JSON numbers or hex quantity strings.
//! Writing emits only known fields; `parse(write(config)) == config`.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const rollup_config = @import("rollup_config.zig");
const BlockId = @import("block.zig").BlockId;
const SystemConfig = @import("system_config.zig").SystemConfig;

const RollupConfig = rollup_config.RollupConfig;
const Upgrade = rollup_config.Upgrade;

pub const Error = json.Error || error{ InvalidField, InvalidType };

/// Flattened OP upgrade activation fields, in `Upgrade` order.
const op_upgrade_fields = [_]struct { []const u8, Upgrade }{
    .{ "regolith_time", .regolith },
    .{ "canyon_time", .canyon },
    .{ "delta_time", .delta },
    .{ "ecotone_time", .ecotone },
    .{ "fjord_time", .fjord },
    .{ "granite_time", .granite },
    .{ "holocene_time", .holocene },
    .{ "pectra_blob_schedule_time", .pectra_blob_schedule },
    .{ "isthmus_time", .isthmus },
    .{ "jovian_time", .jovian },
};

/// Base upgrade fields under `"base"`: canonical name, alias, upgrade.
const base_upgrade_fields = [_]struct { []const u8, []const u8, Upgrade }{
    .{ "azul", "v1", .azul },
    .{ "beryl", "v2", .beryl },
    .{ "cobalt", "v3", .cobalt },
    .{ "denim", "denim", .denim },
    .{ "everest", "everest", .everest },
    .{ "zenith", "future", .zenith },
};

const u64_fields = [_][]const u8{
    "block_time",              "max_sequencer_drift", "seq_window_size", "channel_timeout",
    "granite_channel_timeout", "l1_chain_id",         "l2_chain_id",
};

const address_fields = [_][]const u8{
    "batch_inbox_address",      "deposit_contract_address",
    "l1_system_config_address", "protocol_versions_address",
};

// ------------------------------------------------------------------------ reading

/// The next key of the object being iterated, or null at its end.
fn next_key(scanner: *json.Scanner) Error!?[]const u8 {
    const token = try scanner.next();
    if (token.tag == .object_end) return null;
    if (token.tag != .string or !token.key) return error.InvalidType;
    if (token.escaped) return error.InvalidField;
    return token.bytes;
}

fn expect_object(scanner: *json.Scanner) Error!void {
    const token = try scanner.next();
    if (token.tag != .object_begin) return error.InvalidType;
}

fn read_u64(scanner: *json.Scanner) Error!u64 {
    return try read_optional_u64(scanner) orelse error.InvalidType;
}

fn read_optional_u64(scanner: *json.Scanner) Error!?u64 {
    const token = try scanner.next();
    return switch (token.tag) {
        .null => null,
        .number => std.fmt.parseInt(u64, token.bytes, 10) catch error.InvalidField,
        .string => json.parse_quantity(u64, token.bytes) catch error.InvalidField,
        else => error.InvalidType,
    };
}

fn read_fixed(comptime N: usize, scanner: *json.Scanner) Error![N]u8 {
    const token = try scanner.next();
    if (token.tag != .string) return error.InvalidType;
    return json.parse_fixed(N, token.bytes) catch error.InvalidField;
}

fn read_word(scanner: *json.Scanner) Error!u256 {
    const token = try scanner.next();
    if (token.tag == .number) return std.fmt.parseInt(u256, token.bytes, 10) catch
        error.InvalidField;
    if (token.tag != .string) return error.InvalidType;
    if (token.bytes.len == 66) {
        const bytes = json.parse_fixed(32, token.bytes) catch return error.InvalidField;
        return std.mem.readInt(u256, &bytes, .big);
    }
    return json.parse_quantity(u256, token.bytes) catch error.InvalidField;
}

fn read_narrow(comptime T: type, scanner: *json.Scanner) Error!?T {
    const value = try read_optional_u64(scanner) orelse return null;
    return std.math.cast(T, value) orelse error.InvalidField;
}

fn read_block_id(scanner: *json.Scanner) Error!BlockId {
    try expect_object(scanner);
    var id: BlockId = .{};
    for (0..scanner.input.len) |_| {
        const key = try next_key(scanner) orelse return id;
        if (std.mem.eql(u8, key, "hash")) {
            id.hash = .{ .bytes = try read_fixed(32, scanner) };
        } else if (std.mem.eql(u8, key, "number")) {
            id.number = try read_u64(scanner);
        } else try scanner.skip(try scanner.next());
    }
    unreachable; // Every iteration consumes input.
}

fn read_system_config(scanner: *json.Scanner) Error!?SystemConfig {
    var probe = scanner.*;
    if ((try probe.next()).tag == .null) {
        scanner.* = probe;
        return null;
    }
    try expect_object(scanner);
    var config: SystemConfig = .{};
    for (0..scanner.input.len) |_| {
        const key = try next_key(scanner) orelse return config;
        try read_system_config_field(scanner, &config, key);
    }
    unreachable; // Every iteration consumes input.
}

fn read_system_config_field(
    scanner: *json.Scanner,
    config: *SystemConfig,
    key: []const u8,
) Error!void {
    const eql = std.mem.eql;
    if (eql(u8, key, "batcherAddr")) {
        config.batcher_address = .{ .bytes = try read_fixed(20, scanner) };
    } else if (eql(u8, key, "overhead")) {
        config.overhead = try read_word(scanner);
    } else if (eql(u8, key, "scalar")) {
        config.scalar = try read_word(scanner);
    } else if (eql(u8, key, "gasLimit")) {
        config.gas_limit = try read_u64(scanner);
    } else if (eql(u8, key, "baseFeeScalar")) {
        config.base_fee_scalar = try read_optional_u64(scanner);
    } else if (eql(u8, key, "blobBaseFeeScalar")) {
        config.blob_base_fee_scalar = try read_optional_u64(scanner);
    } else if (eql(u8, key, "eip1559Denominator")) {
        config.eip1559_denominator = try read_narrow(u32, scanner);
    } else if (eql(u8, key, "eip1559Elasticity")) {
        config.eip1559_elasticity = try read_narrow(u32, scanner);
    } else if (eql(u8, key, "operatorFeeScalar")) {
        config.operator_fee_scalar = try read_narrow(u32, scanner);
    } else if (eql(u8, key, "operatorFeeConstant")) {
        config.operator_fee_constant = try read_optional_u64(scanner);
    } else if (eql(u8, key, "minBaseFee")) {
        config.min_base_fee = try read_optional_u64(scanner);
    } else if (eql(u8, key, "daFootprintGasScalar")) {
        config.da_footprint_gas_scalar = try read_narrow(u16, scanner);
    } else try scanner.skip(try scanner.next());
}

fn read_genesis(scanner: *json.Scanner, config: *RollupConfig) Error!void {
    try expect_object(scanner);
    for (0..scanner.input.len) |_| {
        const key = try next_key(scanner) orelse return;
        if (std.mem.eql(u8, key, "l1")) {
            config.genesis.l1 = try read_block_id(scanner);
        } else if (std.mem.eql(u8, key, "l2")) {
            config.genesis.l2 = try read_block_id(scanner);
        } else if (std.mem.eql(u8, key, "l2_time")) {
            config.genesis.l2_time = try read_u64(scanner);
        } else if (std.mem.eql(u8, key, "system_config")) {
            config.genesis.system_config = try read_system_config(scanner);
        } else try scanner.skip(try scanner.next());
    }
    unreachable; // Every iteration consumes input.
}

fn read_base_upgrades(scanner: *json.Scanner, config: *RollupConfig) Error!void {
    try expect_object(scanner);
    outer: for (0..scanner.input.len) |_| {
        const key = try next_key(scanner) orelse return;
        for (base_upgrade_fields) |field| {
            if (std.mem.eql(u8, key, field[0]) or std.mem.eql(u8, key, field[1])) {
                config.upgrades.set(field[2], try read_optional_u64(scanner));
                continue :outer;
            }
        }
        try scanner.skip(try scanner.next());
    }
    unreachable; // Every iteration consumes input.
}

/// Reads one top-level field; returns false when the key is unknown (not consumed).
fn read_top_field(scanner: *json.Scanner, config: *RollupConfig, key: []const u8) Error!bool {
    inline for (u64_fields) |name| if (std.mem.eql(u8, key, name)) {
        @field(config, name) = try read_u64(scanner);
        return true;
    };
    inline for (address_fields) |name| if (std.mem.eql(u8, key, name)) {
        @field(config, name) = .{ .bytes = try read_fixed(20, scanner) };
        return true;
    };
    for (op_upgrade_fields) |field| if (std.mem.eql(u8, key, field[0])) {
        config.upgrades.set(field[1], try read_optional_u64(scanner));
        return true;
    };
    if (std.mem.eql(u8, key, "genesis")) {
        try read_genesis(scanner, config);
    } else if (std.mem.eql(u8, key, "base")) {
        try read_base_upgrades(scanner, config);
    } else if (std.mem.eql(u8, key, "blobs_data")) {
        config.blobs_enabled_l1_timestamp = try read_optional_u64(scanner);
    } else return false;
    return true;
}

/// Parses a `rollup.json` document. Missing fields keep their `RollupConfig` defaults.
pub fn parse(text: []const u8) Error!RollupConfig {
    try json.validate(text);
    var scanner = json.Scanner.init(text);
    try expect_object(&scanner);
    var config: RollupConfig = .{};
    for (0..text.len) |_| {
        const key = try next_key(&scanner) orelse break;
        if (!try read_top_field(&scanner, &config, key)) try scanner.skip(try scanner.next());
    } else unreachable; // Every iteration consumes input.
    assert((try scanner.next()).tag == .end);
    assert(config.upgrades.get(.bedrock) == null);
    return config;
}

// ------------------------------------------------------------------------ writing

fn write_block_id(writer: *json.Writer, id: BlockId) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("hash");
    try writer.data(&id.hash.bytes);
    try writer.key("number");
    try writer.integer(id.number);
    try writer.end_object();
}

fn write_word(writer: *json.Writer, value: u256) json.Writer.WriteError!void {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    try writer.data(&bytes);
}

fn write_optional(writer: *json.Writer, name: []const u8, value: anytype) !void {
    const present = value orelse return;
    try writer.key(name);
    try writer.integer(present);
}

fn write_system_config(writer: *json.Writer, config: SystemConfig) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("batcherAddr");
    try writer.data(&config.batcher_address.bytes);
    try writer.key("overhead");
    try write_word(writer, config.overhead);
    try writer.key("scalar");
    try write_word(writer, config.scalar);
    try writer.key("gasLimit");
    try writer.integer(config.gas_limit);
    try write_optional(writer, "baseFeeScalar", config.base_fee_scalar);
    try write_optional(writer, "blobBaseFeeScalar", config.blob_base_fee_scalar);
    try write_optional(writer, "eip1559Denominator", config.eip1559_denominator);
    try write_optional(writer, "eip1559Elasticity", config.eip1559_elasticity);
    try write_optional(writer, "operatorFeeScalar", config.operator_fee_scalar);
    try write_optional(writer, "operatorFeeConstant", config.operator_fee_constant);
    try write_optional(writer, "minBaseFee", config.min_base_fee);
    try write_optional(writer, "daFootprintGasScalar", config.da_footprint_gas_scalar);
    try writer.end_object();
}

fn write_genesis(writer: *json.Writer, config: *const RollupConfig) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("l1");
    try write_block_id(writer, config.genesis.l1);
    try writer.key("l2");
    try write_block_id(writer, config.genesis.l2);
    try writer.key("l2_time");
    try writer.integer(config.genesis.l2_time);
    if (config.genesis.system_config) |system_config| {
        try writer.key("system_config");
        try write_system_config(writer, system_config);
    }
    try writer.end_object();
}

fn write_upgrades(writer: *json.Writer, config: *const RollupConfig) json.Writer.WriteError!void {
    for (op_upgrade_fields) |field| {
        try write_optional(writer, field[0], config.upgrades.get(field[1]));
    }
    var any_base = false;
    for (base_upgrade_fields) |field| any_base = any_base or config.upgrades.get(field[2]) != null;
    if (!any_base) return;
    try writer.key("base");
    try writer.begin_object();
    for (base_upgrade_fields) |field| {
        try write_optional(writer, field[0], config.upgrades.get(field[2]));
    }
    try writer.end_object();
}

/// Writes `config` as a `rollup.json` object.
pub fn write(writer: *json.Writer, config: *const RollupConfig) json.Writer.WriteError!void {
    const depth = writer.depth;
    try writer.begin_object();
    try writer.key("genesis");
    try write_genesis(writer, config);
    inline for (u64_fields) |name| {
        try writer.key(name);
        try writer.integer(@field(config, name));
    }
    try write_upgrades(writer, config);
    inline for (address_fields) |name| {
        try writer.key(name);
        try writer.data(&@field(config, name).bytes);
    }
    try write_optional(writer, "blobs_data", config.blobs_enabled_l1_timestamp);
    try writer.end_object();
    assert(writer.depth == depth);
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const reference =
    \\{
    \\  "genesis": {
    \\    "l1": {
    \\      "hash": "0x481724ee99b1f4cb71d826e2ec5a37265f460e9b112315665c977f4050b0af54",
    \\      "number": 10
    \\    },
    \\    "l2": {
    \\      "hash": "0x88aedfbf7dea6bfa2c4ff315784ad1a7f145d8f650969359c003bbed68c87631",
    \\      "number": 0
    \\    },
    \\    "l2_time": 1725557164,
    \\    "system_config": {
    \\      "batcherAddr": "0xc81f87a644b41e49b3221f41251f15c6cb00ce03",
    \\      "overhead": "0x0000000000000000000000000000000000000000000000000000000000000000",
    \\      "scalar": "0x00000000000000000000000000000000000000000000000000000000000f4240",
    \\      "gasLimit": 30000000,
    \\      "baseFeeScalar": 1234,
    \\      "blobBaseFeeScalar": 5678,
    \\      "eip1559Denominator": 10,
    \\      "eip1559Elasticity": 20,
    \\      "operatorFeeScalar": 30,
    \\      "operatorFeeConstant": 40,
    \\      "minBaseFee": 50,
    \\      "daFootprintGasScalar": 10
    \\    }
    \\  },
    \\  "block_time": 2,
    \\  "max_sequencer_drift": 600,
    \\  "seq_window_size": 3600,
    \\  "channel_timeout": 300,
    \\  "l1_chain_id": 3151908,
    \\  "l2_chain_id": 1337,
    \\  "regolith_time": 0,
    \\  "canyon_time": 0,
    \\  "delta_time": 0,
    \\  "ecotone_time": 0,
    \\  "fjord_time": 0,
    \\  "base": { "v1": 100, "cobalt": "0x20" },
    \\  "batch_inbox_address": "0xff00000000000000000000000000000000042069",
    \\  "deposit_contract_address": "0x08073dc48dde578137b8af042bcbc1c2491f1eb2",
    \\  "l1_system_config_address": "0x94ee52a9d8edd72a85dea7fae3ba6d75e4bf1710",
    \\  "protocol_versions_address": "0x0000000000000000000000000000000000000000",
    \\  "chain_op_config": {
    \\    "eip1559Elasticity": 6,
    \\    "eip1559Denominator": 50,
    \\    "eip1559DenominatorCanyon": 250
    \\  }
    \\}
;

fn round_trip(config: *const RollupConfig) !RollupConfig {
    var buffer: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    var writer = json.Writer.init(&out);
    try write(&writer, config);
    return parse(out.buffered());
}

test "rollup json: base/base reference config" {
    const config = try parse(reference);
    try testing.expectEqual(@as(u64, 10), config.genesis.l1.number);
    try testing.expectEqual(@as(u8, 0x48), config.genesis.l1.hash.bytes[0]);
    try testing.expectEqual(@as(u64, 1725557164), config.genesis.l2_time);
    const system_config = config.genesis.system_config.?;
    try testing.expectEqual(@as(u256, 0xf4240), system_config.scalar);
    try testing.expectEqual(@as(u64, 30_000_000), system_config.gas_limit);
    try testing.expectEqual(@as(?u16, 10), system_config.da_footprint_gas_scalar);
    try testing.expectEqual(@as(?u32, 30), system_config.operator_fee_scalar);
    try testing.expectEqual(@as(u64, 3600), config.seq_window_size);
    try testing.expectEqual(@as(u64, 50), config.granite_channel_timeout);
    try testing.expectEqual(@as(u64, 1337), config.l2_chain_id);
    try testing.expectEqual(@as(?u64, 0), config.upgrades.get(.fjord));
    try testing.expectEqual(@as(?u64, null), config.upgrades.get(.granite));
    try testing.expectEqual(@as(?u64, 100), config.upgrades.get(.azul));
    try testing.expectEqual(@as(?u64, 32), config.upgrades.get(.cobalt));
    try testing.expectEqual(@as(u8, 0xff), config.batch_inbox_address.bytes[0]);
    try testing.expectEqualDeep(config, try round_trip(&config));
}

test "rollup json: malformed documents are rejected" {
    try testing.expectError(error.InvalidType, parse("[]"));
    try testing.expectError(error.InvalidField, parse("{\"block_time\":-1}"));
    try testing.expectError(error.InvalidType, parse("{\"block_time\":true}"));
    try testing.expectError(error.InvalidField, parse("{\"batch_inbox_address\":\"0x12\"}"));
    try testing.expectError(error.InvalidField, parse(
        \\{"genesis":{"system_config":{"eip1559Denominator":4294967296}}}
    ));
    try testing.expectError(error.UnexpectedEnd, parse("{\"genesis\":"));
}

test "rollup json: seeded fuzz round trip" {
    var prng = Prng.init(0x524a534e);
    for (0..500) |_| {
        var config: RollupConfig = .{
            .block_time = prng.int(u64),
            .seq_window_size = prng.int(u64),
            .l2_chain_id = prng.int(u64),
            .granite_channel_timeout = prng.int(u64),
        };
        prng.fill(&config.genesis.l2.hash.bytes);
        prng.fill(&config.deposit_contract_address.bytes);
        config.genesis.l1.number = prng.int(u64);
        for (std.enums.values(Upgrade)) |upgrade| {
            if (upgrade == .bedrock or !prng.chance(1, 2)) continue;
            config.upgrades.set(upgrade, prng.int(u64));
        }
        if (prng.chance(1, 2)) config.blobs_enabled_l1_timestamp = prng.int(u64);
        if (prng.chance(1, 2)) config.genesis.system_config = .{
            .scalar = prng.int(u256),
            .overhead = prng.int(u256),
            .eip1559_elasticity = if (prng.chance(1, 2)) prng.int(u32) else null,
            .da_footprint_gas_scalar = if (prng.chance(1, 2)) prng.int(u16) else null,
        };
        try testing.expectEqualDeep(config, try round_trip(&config));
    }
}

test "rollup json: fuzz parse" {
    try testing.fuzz({}, fuzz_parse, .{});
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const length = smith.slice(&input);
    const config = parse(input[0..length]) catch return;
    try testing.expectEqualDeep(config, try round_trip(&config));
}

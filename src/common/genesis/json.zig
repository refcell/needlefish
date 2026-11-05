//! Genesis JSON parsing (geth / alloy-genesis schema). Startup only: everything lives
//! in an arena owned by `Parsed`.
//!
//! Quantities are accepted as JSON integers, decimal strings, or `0x` hex strings with
//! optional leading zeros, as real genesis files mix all three. Alloc keys may omit 0x.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const genesis_module = @import("root.zig");
const state = @import("state.zig");
const Value = std.json.Value;
const Address = primitives.Address;
const B256 = primitives.B256;
const Genesis = genesis_module.Genesis;
const Config = genesis_module.Config;

pub const Error = std.mem.Allocator.Error || std.json.ParseError(std.json.Scanner) || error{
    InvalidGenesis,
    InvalidQuantity,
    InvalidHex,
};

pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    value: Genesis,

    pub fn deinit(parsed: Parsed) void {
        const allocator = parsed.arena.child_allocator;
        parsed.arena.deinit();
        allocator.destroy(parsed.arena);
    }
};

/// Parses a lenient quantity into `T`.
pub fn quantity(comptime T: type, value: Value) Error!T {
    switch (value) {
        .integer => |integer| return std.math.cast(T, integer) orelse error.InvalidQuantity,
        .number_string => |text| {
            return std.fmt.parseInt(T, text, 10) catch error.InvalidQuantity;
        },
        .string => |text| {
            if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
                if (text.len == 2) return 0;
                return std.fmt.parseInt(T, text[2..], 16) catch error.InvalidQuantity;
            }
            return std.fmt.parseInt(T, text, 10) catch error.InvalidQuantity;
        },
        else => return error.InvalidQuantity,
    }
}

fn optional_quantity(comptime T: type, object: std.json.ObjectMap, key: []const u8) Error!?T {
    const value = object.get(key) orelse return null;
    if (value == .null) return null;
    return try quantity(T, value);
}

fn string(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return if (value == .string) value.string else null;
}

fn fixed(comptime T: type, object: std.json.ObjectMap, key: []const u8) Error!?T {
    const text = string(object, key) orelse return null;
    return T.from_hex(text) catch error.InvalidHex;
}

/// Hex bytes into the arena.
fn bytes(allocator: std.mem.Allocator, text: []const u8) Error![]const u8 {
    const size = primitives.hex.decoded_length(text) catch return error.InvalidHex;
    const buffer = try allocator.alloc(u8, size);
    primitives.hex.decode(buffer, text) catch return error.InvalidHex;
    return buffer;
}

fn parse_config(value: ?Value) Error!Config {
    const object = switch (value orelse return .{}) {
        .object => |object| object,
        else => return error.InvalidGenesis,
    };
    var config: Config = .{ .chain_id = (try optional_quantity(u64, object, "chainId")) orelse 0 };
    const keys = .{
        .{ "london_block", "londonBlock" },   .{ "shanghai_time", "shanghaiTime" },
        .{ "cancun_time", "cancunTime" },     .{ "prague_time", "pragueTime" },
        .{ "osaka_time", "osakaTime" },       .{ "bedrock_block", "bedrockBlock" },
        .{ "regolith_time", "regolithTime" }, .{ "canyon_time", "canyonTime" },
        .{ "delta_time", "deltaTime" },       .{ "ecotone_time", "ecotoneTime" },
        .{ "fjord_time", "fjordTime" },       .{ "granite_time", "graniteTime" },
        .{ "holocene_time", "holoceneTime" }, .{ "isthmus_time", "isthmusTime" },
        .{ "jovian_time", "jovianTime" },
    };
    inline for (keys) |key| {
        @field(config, key[0]) = try optional_quantity(u64, object, key[1]);
    }
    if (object.get("optimism")) |optimism| {
        if (optimism != .object) return error.InvalidGenesis;
        const params = optimism.object;
        config.eip1559_elasticity = try optional_quantity(u64, params, "eip1559Elasticity");
        config.eip1559_denominator = try optional_quantity(u64, params, "eip1559Denominator");
        config.eip1559_denominator_canyon =
            try optional_quantity(u64, params, "eip1559DenominatorCanyon");
    }
    if (object.get("base")) |base| config.base_upgrade_times = try parse_base_upgrades(base);
    config.activation_admin_address = try fixed(Address, object, "activationAdminAddress");
    return config;
}

/// `config.base`: base/base denies unknown fields and duplicate (name + alias) entries.
fn parse_base_upgrades(value: Value) Error![genesis_module.base_upgrade_count]?u64 {
    if (value == .null) return @splat(null);
    if (value != .object) return error.InvalidGenesis;
    const object = value.object;
    var times: [genesis_module.base_upgrade_count]?u64 = @splat(null);
    var matched: usize = 0;
    const upgrades = comptime std.enums.values(genesis_module.BaseUpgrade);
    inline for (upgrades) |upgrade| {
        const index = @backingInt(upgrade);
        const name = @tagName(upgrade);
        const named = object.get(name) != null;
        const aliased = if (upgrade.alias()) |alias| object.get(alias) != null else false;
        if (named and aliased) return error.InvalidGenesis;
        if (named) times[index] = try optional_quantity(u64, object, name);
        if (aliased) times[index] = try optional_quantity(u64, object, upgrade.alias().?);
        matched += @intFromBool(named) + @intFromBool(aliased);
    }
    assert(matched <= object.count());
    if (matched != object.count()) return error.InvalidGenesis;
    return times;
}

fn parse_storage(allocator: std.mem.Allocator, value: ?Value) Error![]const state.StorageSlot {
    const object = switch (value orelse return &.{}) {
        .object => |object| object,
        .null => return &.{},
        else => return error.InvalidGenesis,
    };
    const slots = try allocator.alloc(state.StorageSlot, object.count());
    var iterator = object.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        const key = try quantity(u256, .{ .string = entry.key_ptr.* });
        slots[index] = .{
            .key = primitives.bytes.u256_to_b256(key),
            .value = try quantity(u256, entry.value_ptr.*),
        };
    }
    return slots;
}

fn parse_account(allocator: std.mem.Allocator, key: []const u8, value: Value) Error!state.Account {
    if (value != .object) return error.InvalidGenesis;
    const object = value.object;
    const code_text = string(object, "code");
    return .{
        .address = Address.from_hex(key) catch return error.InvalidHex,
        .balance = (try optional_quantity(u256, object, "balance")) orelse 0,
        .nonce = (try optional_quantity(u64, object, "nonce")) orelse 0,
        .code = if (code_text) |text| try bytes(allocator, text) else &.{},
        .storage = try parse_storage(allocator, object.get("storage")),
    };
}

fn parse_accounts(allocator: std.mem.Allocator, value: ?Value) Error![]const state.Account {
    const object = switch (value orelse return &.{}) {
        .object => |object| object,
        else => return error.InvalidGenesis,
    };
    const accounts = try allocator.alloc(state.Account, object.count());
    var iterator = object.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        accounts[index] = try parse_account(allocator, entry.key_ptr.*, entry.value_ptr.*);
    }
    return accounts;
}

fn parse_genesis(allocator: std.mem.Allocator, root: Value) Error!Genesis {
    if (root != .object) return error.InvalidGenesis;
    const object = root.object;
    const extra = string(object, "extraData");
    return .{
        .config = try parse_config(object.get("config")),
        .nonce = (try optional_quantity(u64, object, "nonce")) orelse 0,
        .timestamp = (try optional_quantity(u64, object, "timestamp")) orelse 0,
        .extra_data = if (extra) |text| try bytes(allocator, text) else &.{},
        .gas_limit = (try optional_quantity(u64, object, "gasLimit")) orelse 0,
        .difficulty = (try optional_quantity(u256, object, "difficulty")) orelse 0,
        .mix_hash = (try fixed(B256, object, "mixHash")) orelse .zero,
        .coinbase = (try fixed(Address, object, "coinbase")) orelse .zero,
        .number = (try optional_quantity(u64, object, "number")) orelse 0,
        .gas_used = (try optional_quantity(u64, object, "gasUsed")) orelse 0,
        .parent_hash = (try fixed(B256, object, "parentHash")) orelse .zero,
        .base_fee_per_gas = try optional_quantity(u64, object, "baseFeePerGas"),
        .excess_blob_gas = try optional_quantity(u64, object, "excessBlobGas"),
        .blob_gas_used = try optional_quantity(u64, object, "blobGasUsed"),
        .state_root = try fixed(B256, object, "stateRoot"),
        .accounts = try parse_accounts(allocator, object.get("alloc")),
    };
}

/// Parses genesis JSON. The result owns all memory; call `deinit`.
pub fn parse(gpa: std.mem.Allocator, text: []const u8) Error!Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = .init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const root = try std.json.parseFromSliceLeaky(Value, allocator, text, .{
        .duplicate_field_behavior = .@"error",
    });
    return .{ .arena = arena, .value = try parse_genesis(allocator, root) };
}

const testing = std.testing;

test "genesis json: quantities" {
    try testing.expectEqual(@as(u64, 16), try quantity(u64, .{ .string = "0x10" }));
    try testing.expectEqual(@as(u64, 16), try quantity(u64, .{ .string = "0x0010" }));
    try testing.expectEqual(@as(u64, 0), try quantity(u64, .{ .string = "0x" }));
    try testing.expectEqual(@as(u64, 10), try quantity(u64, .{ .string = "10" }));
    try testing.expectEqual(@as(u64, 7), try quantity(u64, .{ .integer = 7 }));
    try testing.expectError(error.InvalidQuantity, quantity(u64, .{ .integer = -1 }));
    try testing.expectError(error.InvalidQuantity, quantity(u8, .{ .string = "0x100" }));
    try testing.expectError(error.InvalidQuantity, quantity(u8, .{ .bool = true }));
}

test "genesis json: base upgrades (base/base extract_base_chain_genesis_info)" {
    const parsed = try parse(testing.allocator,
        \\{"config":{"chainId":8453,"bedrockBlock":10,"regolithTime":12,"canyonTime":0,
        \\ "ecotoneTime":0,"base":{"v1":14,"v2":16,"denim":"0x20","zenith":1000000},
        \\ "activationAdminAddress":"0x4200000000000000000000000000000000000018"}}
    );
    defer parsed.deinit();
    const config = parsed.value.config;
    try testing.expectEqual(@as(?u64, 14), config.base_upgrade_time(.azul));
    try testing.expectEqual(@as(?u64, 16), config.base_upgrade_time(.beryl));
    try testing.expectEqual(@as(?u64, null), config.base_upgrade_time(.cobalt));
    try testing.expectEqual(@as(?u64, 32), config.base_upgrade_time(.denim));
    try testing.expectEqual(@as(?u64, 1_000_000), config.base_upgrade_time(.zenith));
    try testing.expect(config.is_base_upgrade_active(.azul, 14));
    try testing.expect(!config.is_base_upgrade_active(.azul, 13));
    try testing.expect(!config.is_base_upgrade_active(.everest, std.math.maxInt(u64)));
    try testing.expectEqual(@as(u8, 0x18), config.activation_admin_address.?.bytes[19]);
    const rejected = [_][]const u8{
        "{\"config\":{\"base\":{\"v1\":1,\"azul\":1}}}",
        "{\"config\":{\"base\":{\"unknown\":1}}}",
        "{\"config\":{\"base\":[]}}",
        "{\"config\":{\"activationAdminAddress\":\"0x42\"}}",
    };
    for (rejected) |text| {
        if (parse(testing.allocator, text)) |ok| {
            ok.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "genesis json: base/base dev genesis state root" {
    const parsed = try parse(testing.allocator, @embedFile("testdata/dev.json"));
    defer parsed.deinit();
    const genesis = &parsed.value;
    try testing.expectEqual(@as(usize, 22), genesis.accounts.len);
    try testing.expectEqual(@as(u64, 30_000_000), genesis.gas_limit);
    // The file's `stateRoot` predates its last two accounts and is not authoritative;
    // the pinned root is a regression value. The same code reproduces the Base mainnet,
    // Sepolia and Zeronet genesis hashes from base/base's (9 MB, uncommitted) files.
    try testing.expect(genesis.state_root != null);
    const root = try genesis.compute_state_root(testing.allocator);
    const pinned = "e6c2cc5ee712391fb741a2ddb482822c512bc16bfced8d631ec39cd0ac8dac3f";
    try testing.expect(root.eql(B256.comptime_hex(pinned)));
}

test "genesis json: header fork fields" {
    const text =
        \\{"config":{"chainId":901,"londonBlock":0,"bedrockBlock":0,"regolithTime":0,
        \\ "canyonTime":0,"ecotoneTime":0,"isthmusTime":0,
        \\ "optimism":{"eip1559Elasticity":6,"eip1559Denominator":50}},
        \\ "timestamp":"0x10","gasLimit":"0x1c9c380","extraData":"0x00",
        \\ "alloc":{"4200000000000000000000000000000000000016":{"balance":"0x0",
        \\   "storage":{"0x01":"0x02"}},
        \\  "0x00000000000000000000000000000000000000aa":{"balance":"100","nonce":1}}}
    ;
    const parsed = try parse(testing.allocator, text);
    defer parsed.deinit();
    const genesis = &parsed.value;
    try testing.expect(genesis.config.is_optimism());
    try testing.expectEqual(@as(?u64, 6), genesis.config.eip1559_elasticity);
    const root = try genesis.compute_state_root(testing.allocator);
    const header = try genesis.header(testing.allocator, root);
    try testing.expectEqual(@as(?u64, genesis_module.initial_base_fee), header.base_fee_per_gas);
    try testing.expectEqual(@as(?u64, 0), header.excess_blob_gas);
    try testing.expect(header.requests_hash != null);
    // Isthmus: withdrawals root is the message passer's storage root, not empty.
    try testing.expect(!header.withdrawals_root.?.eql(primitives.empty_root_hash));
    try testing.expectError(error.InvalidHex, parse(testing.allocator, "{\"alloc\":{\"zz\":{}}}"));
}

const Prng = @import("../../testing/prng.zig").Prng;

fn parse_and_root(input: []const u8) !void {
    const parsed = parse(testing.allocator, input) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    defer parsed.deinit();
    _ = parsed.value.compute_state_root(testing.allocator) catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.DuplicateKey => return,
    };
}

test "genesis json: seeded fuzz mutations" {
    const seed_text = @embedFile("testdata/dev.json");
    var buffer: [seed_text.len]u8 = undefined;
    var prng = Prng.init(0x6e5);
    for (0..64) |_| {
        @memcpy(&buffer, seed_text);
        for (0..prng.range(1, 8)) |_| buffer[prng.below(buffer.len)] = prng.int(u8);
        try parse_and_root(buffer[0..prng.range(1, buffer.len)]);
    }
}

test "genesis json: seeded fuzz config mutations" {
    const seed_text =
        \\{"config":{"chainId":8453,"bedrockBlock":0,"optimism":{"eip1559Elasticity":6},
        \\"base":{"v1":14,"beryl":"0x10","everest":20},
        \\"activationAdminAddress":"0x4200000000000000000000000000000000000018"}}
    ;
    var buffer: [seed_text.len]u8 = undefined;
    var prng = Prng.init(0xba5e);
    for (0..512) |_| {
        buffer = seed_text.*;
        for (0..prng.range(1, 3)) |_| buffer[prng.below(buffer.len)] = prng.int(u8);
        try parse_and_root(buffer[0..prng.range(1, buffer.len)]);
    }
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [2048]u8 = undefined;
    try parse_and_root(buffer[0..smith.slice(&buffer)]);
}

test "genesis json: fuzz parse" {
    try testing.fuzz({}, fuzz_parse, .{});
}

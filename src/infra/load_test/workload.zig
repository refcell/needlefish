//! Seeded workload generation (base/base `load-tests/src/workload/{generator,seeded}.rs` and
//! the `transfer`, `calldata`, `erc20`, `storage`, `precompile`, and `looper` payloads).
//!
//! The same seed yields the same sequence of payloads, so a load test run is reproducible
//! and the simulator can replay it. Payloads are drawn from a weighted mix; each carries a
//! gas limit computed locally (intrinsic + calldata cost with the EIP-7623 floor, plus the
//! exact execution cost of the hand-assembled contracts in `contracts.zig`, or a fixed
//! safe bound where the cost depends on input values), so the runner needs no
//! `eth_estimateGas` round trip per transaction. `erc20_transfer`, `storage`, and `looper`
//! target contracts deployed by the prep phase (`chain_prep.zig`).

const std = @import("std");
const assert = std.debug.assert;

const txdata = @import("../../batcher/txdata/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const secp256k1 = @import("../../common/crypto/secp256k1/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const contracts = @import("contracts.zig");
const key_stream = @import("key_stream.zig");

pub const Address = primitives.Address;

pub const Kind = enum(u8) { transfer, calldata, erc20_transfer, storage, precompile, looper };
pub const kind_count = std.enums.values(Kind).len;

/// `transfer(address,uint256)` selector.
pub const erc20_transfer_selector = contracts.selector_transfer;

/// Precompiles exercised by the `precompile` payload, with valid inputs.
pub const Precompile = enum(u8) { ecrecover = 1, sha256 = 2, identity = 4, modexp = 5 };
const precompiles = std.enums.values(Precompile);
/// Fixed bound for modexp with operands up to 32 bytes (at most 4080 gas under EIP-7883).
pub const modexp_gas_bound: u64 = 10_000;

/// Largest payload any kind builds (modexp: 96-byte header + three 32-byte operands).
pub const payload_bytes_min = 192;

/// Addresses of the deployed workload contracts.
pub const Contracts = struct {
    token: Address,
    storage: Address,
    looper: Address,
};

pub const Mix = struct {
    weights: [kind_count]u32 = default_weights,

    const default_weights = blk: {
        var weights: [kind_count]u32 = @splat(0);
        weights[@backingInt(Kind.transfer)] = 100;
        break :blk weights;
    };

    pub const ParseError = error{ InvalidMix, EmptyMix };

    /// Parses `transfer=70,calldata=20,erc20_transfer=10`.
    pub fn parse(text: []const u8) ParseError!Mix {
        var mix: Mix = .{ .weights = @splat(0) };
        var parts = std.mem.splitScalar(u8, text, ',');
        var count: u32 = 0;
        while (parts.next()) |part| : (count += 1) {
            if (count == kind_count * 4) return error.InvalidMix;
            const equals = std.mem.indexOfScalar(u8, part, '=') orelse return error.InvalidMix;
            const kind = std.meta.stringToEnum(Kind, part[0..equals]) orelse
                return error.InvalidMix;
            const weight = std.fmt.parseInt(u32, part[equals + 1 ..], 10) catch
                return error.InvalidMix;
            if (weight > 1_000_000) return error.InvalidMix;
            mix.weights[@backingInt(kind)] = weight;
        }
        if (mix.total() == 0) return error.EmptyMix;
        assert(mix.total() <= kind_count * 1_000_000);
        return mix;
    }

    pub fn total(mix: Mix) u64 {
        var sum: u64 = 0;
        for (mix.weights) |weight| sum += weight;
        return sum;
    }

    pub fn weight_of(mix: Mix, kind: Kind) u32 {
        return mix.weights[@backingInt(kind)];
    }

    /// True when a drawn payload may target a deployed contract.
    pub fn needs_contracts(mix: Mix) bool {
        return mix.weight_of(.erc20_transfer) > 0 or mix.weight_of(.storage) > 0 or
            mix.weight_of(.looper) > 0;
    }
};

pub const Payload = struct {
    kind: Kind,
    to: Address,
    value: u256,
    /// Borrowed from the generator; valid until the next `next`.
    data: []const u8,
    gas_limit: u64,
};

pub const Config = struct {
    seed: u64,
    mix: Mix = .{},
    calldata_bytes_max: u32 = 1024,
    /// Fresh slots written per `storage` transaction.
    storage_slots_per_tx: u32 = 4,
    /// Loop iterations per `looper` transaction (40 gas each).
    looper_iterations: u32 = 10_000,
    /// Required when `mix.needs_contracts()`; set by the prep phase.
    contracts: ?Contracts = null,
};

pub const storage_slots_per_tx_max = 1_000;
pub const looper_iterations_max = 1_000_000;

pub fn Generator(comptime data_bytes_max: u32) type {
    comptime assert(data_bytes_max >= payload_bytes_min);
    return struct {
        const Self = @This();

        config: Config,
        prng: Prng,
        /// Signs the `ecrecover` inputs; derived from the seed, public, holds nothing.
        ecrecover_key: [32]u8,
        buffer: [data_bytes_max]u8 = undefined,
        generated: [kind_count]u64 = @splat(0),

        pub fn init(config: Config) Self {
            assert(config.mix.total() > 0);
            assert(config.calldata_bytes_max <= data_bytes_max);
            assert(config.storage_slots_per_tx <= storage_slots_per_tx_max);
            assert(config.looper_iterations <= looper_iterations_max);
            return .{
                .config = config,
                .prng = Prng.init(config.seed),
                .ecrecover_key = key_stream.derive_key(config.seed, std.math.maxInt(u32)),
            };
        }

        pub fn next(generator: *Self) Payload {
            const kind = generator.draw_kind();
            generator.generated[@backingInt(kind)] += 1;
            const payload: Payload = switch (kind) {
                .transfer => .{
                    .kind = kind,
                    .to = generator.draw_address(),
                    .value = 1,
                    .data = &.{},
                    .gas_limit = 21_000,
                },
                .calldata => generator.calldata(),
                .erc20_transfer => generator.erc20_transfer(),
                .storage => generator.storage(),
                .precompile => generator.precompile(),
                .looper => generator.looper(),
            };
            assert(payload.kind == kind);
            assert(payload.gas_limit >= txdata.calldata_gas(payload.data));
            return payload;
        }

        fn draw_kind(generator: *Self) Kind {
            const weights = generator.config.mix.weights;
            var pick = generator.prng.below(generator.config.mix.total());
            for (weights, 0..) |weight, index| {
                if (pick < weight) return @fromBackingInt(@intCast(index));
                pick -= weight;
            }
            unreachable; // `pick` is below the sum of the weights.
        }

        fn draw_address(generator: *Self) Address {
            var address: Address = undefined;
            generator.prng.fill(&address.bytes);
            return address;
        }

        fn deployed(generator: *const Self) Contracts {
            return generator.config.contracts orelse
                unreachable; // The runner requires contracts when the mix needs them.
        }

        fn calldata(generator: *Self) Payload {
            const length = generator.prng.below(@as(u64, generator.config.calldata_bytes_max) + 1);
            const data = generator.buffer[0..@intCast(length)];
            generator.prng.fill(data);
            return .{
                .kind = .calldata,
                .to = generator.draw_address(),
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data),
            };
        }

        fn erc20_transfer(generator: *Self) Payload {
            const recipient = generator.draw_address();
            const data = generator.buffer[0..68];
            @memcpy(data[0..4], &erc20_transfer_selector);
            @memset(data[4..16], 0);
            @memcpy(data[16..36], &recipient.bytes);
            @memset(data[36..68], 0);
            data[67] = 1; // One base unit.
            return .{
                .kind = .erc20_transfer,
                .to = generator.deployed().token,
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data) + contracts.token_transfer_gas,
            };
        }

        /// Writes a non-zero value to `storage_slots_per_tx` slots starting at a random
        /// 64-bit slot, so every write is a fresh zero-to-non-zero SSTORE (exact gas).
        fn storage(generator: *Self) Payload {
            const slots: u64 = generator.config.storage_slots_per_tx;
            const data = generator.buffer[0..96];
            put_word(data[0..32], generator.prng.int(u64));
            put_word(data[32..64], slots);
            put_word(data[64..96], generator.prng.int(u64) | 1);
            const execution = contracts.storage_gas_base + slots * contracts.storage_gas_per_slot;
            return .{
                .kind = .storage,
                .to = generator.deployed().storage,
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data) + execution,
            };
        }

        fn looper(generator: *Self) Payload {
            const iterations: u64 = generator.config.looper_iterations;
            const data = generator.buffer[0..32];
            put_word(data, iterations);
            const execution = contracts.looper_gas_base +
                iterations * contracts.looper_gas_per_iteration;
            return .{
                .kind = .looper,
                .to = generator.deployed().looper,
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data) + execution,
            };
        }

        fn precompile(generator: *Self) Payload {
            const which = precompiles[@intCast(generator.prng.below(precompiles.len))];
            const data, const execution = switch (which) {
                .ecrecover => generator.ecrecover_input(),
                .sha256 => generator.hash_input(64, 60, 12),
                .identity => generator.hash_input(128, 15, 3),
                .modexp => generator.modexp_input(),
            };
            var to: Address = .{ .bytes = @splat(0) };
            to.bytes[19] = @backingInt(which);
            return .{
                .kind = .precompile,
                .to = to,
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data) + execution,
            };
        }

        const Input = struct { []const u8, u64 };

        /// Random input of `length` bytes for a linear-cost precompile.
        fn hash_input(generator: *Self, length: u32, base: u64, per_word: u64) Input {
            assert(length <= data_bytes_max);
            const data = generator.buffer[0..length];
            generator.prng.fill(data);
            return .{ data, base + per_word * ((length + 31) / 32) };
        }

        /// hash || v || r || s for a signature by `ecrecover_key` over a random hash.
        fn ecrecover_input(generator: *Self) Input {
            const data = generator.buffer[0..128];
            var hash: [32]u8 = undefined;
            generator.prng.fill(&hash);
            const signature = secp256k1.sign(generator.ecrecover_key, hash) catch
                unreachable; // `derive_key` returns valid scalars.
            @memcpy(data[0..32], &hash);
            put_word(data[32..64], 27 + @as(u64, signature.recovery_id & 1));
            @memcpy(data[64..96], &signature.r);
            @memcpy(data[96..128], &signature.s);
            return .{ data, 3_000 };
        }

        /// EIP-198 header with 1..32-byte operands and a non-zero modulus.
        fn modexp_input(generator: *Self) Input {
            const base_length: u32 = @intCast(generator.prng.range(1, 32));
            const exponent_length: u32 = @intCast(generator.prng.range(1, 32));
            const modulus_length: u32 = @intCast(generator.prng.range(1, 32));
            const length = 96 + base_length + exponent_length + modulus_length;
            assert(length <= payload_bytes_min);
            const data = generator.buffer[0..length];
            put_word(data[0..32], base_length);
            put_word(data[32..64], exponent_length);
            put_word(data[64..96], modulus_length);
            generator.prng.fill(data[96..]);
            const modulus = data[96 + base_length + exponent_length ..];
            modulus[0] |= 1; // Non-zero modulus.
            return .{ data, modexp_gas_bound };
        }
    };
}

fn put_word(out: *[32]u8, value: u64) void {
    @memset(out[0..24], 0);
    std.mem.writeInt(u64, out[24..32], value, .big);
    assert(out[0] == 0);
}

const testing = std.testing;

test "workload: mix parsing" {
    const mix = try Mix.parse("transfer=70,calldata=20,erc20_transfer=10");
    try testing.expectEqual(@as(u64, 100), mix.total());
    try testing.expectEqual(@as(u32, 20), mix.weights[@backingInt(Kind.calldata)]);
    try testing.expectError(error.InvalidMix, Mix.parse("swap=1"));
    try testing.expectError(error.InvalidMix, Mix.parse("transfer"));
    try testing.expectError(error.EmptyMix, Mix.parse("transfer=0"));
}

test "workload: same seed, same payloads; mix proportions hold" {
    const config: Config = .{ .seed = 7, .mix = try Mix.parse("transfer=50,calldata=50") };
    var first = Generator(1024).init(config);
    var second = Generator(1024).init(config);
    for (0..1000) |_| {
        const a = first.next();
        const b = second.next();
        try testing.expectEqual(a.kind, b.kind);
        try testing.expectEqualSlices(u8, a.data, b.data);
        try testing.expectEqualSlices(u8, &a.to.bytes, &b.to.bytes);
    }
    const transfers = first.generated[@backingInt(Kind.transfer)];
    try testing.expect(transfers > 400 and transfers < 600);
}

const test_contracts: Contracts = .{
    .token = .{ .bytes = @splat(0x20) },
    .storage = .{ .bytes = @splat(0x30) },
    .looper = .{ .bytes = @splat(0x40) },
};

test "workload: erc20, storage, and looper target the deployed contracts" {
    var generator = Generator(256).init(.{
        .seed = 1,
        .mix = try Mix.parse("erc20_transfer=1,storage=1,looper=1"),
        .calldata_bytes_max = 128,
        .contracts = test_contracts,
    });
    for (0..30) |_| {
        const payload = generator.next();
        switch (payload.kind) {
            .erc20_transfer => {
                try testing.expectEqual(@as(usize, 68), payload.data.len);
                try testing.expectEqualSlices(u8, &erc20_transfer_selector, payload.data[0..4]);
                try testing.expectEqual(@as(u8, 1), payload.data[67]);
                try testing.expectEqual(test_contracts.token, payload.to);
            },
            .storage => {
                try testing.expectEqual(@as(usize, 96), payload.data.len);
                try testing.expectEqual(@as(u8, 4), payload.data[63]);
                try testing.expectEqual(test_contracts.storage, payload.to);
            },
            .looper => try testing.expectEqual(test_contracts.looper, payload.to),
            else => unreachable,
        }
    }
    try testing.expect(Mix.needs_contracts(generator.config.mix));
    try testing.expect(!(try Mix.parse("transfer=1,precompile=1,calldata=1")).needs_contracts());
}

test "workload: precompile payloads hit every precompile" {
    var generator = Generator(256).init(.{
        .seed = 9,
        .mix = try Mix.parse("precompile=1"),
        .calldata_bytes_max = 256,
    });
    var seen: [8]bool = @splat(false);
    for (0..64) |_| {
        const payload = generator.next();
        try testing.expect(std.mem.allEqual(u8, payload.to.bytes[0..19], 0));
        seen[payload.to.bytes[19]] = true;
    }
    for (precompiles) |which| try testing.expect(seen[@backingInt(which)]);
}

fn check_mix(text: []const u8, seed: u64) !void {
    const mix = Mix.parse(text) catch return;
    try testing.expect(mix.total() > 0);
    var generator = Generator(256).init(.{
        .seed = seed,
        .mix = mix,
        .calldata_bytes_max = 256,
        .contracts = test_contracts,
        .storage_slots_per_tx = @intCast(seed % 8),
        .looper_iterations = @intCast(seed % 1000),
    });
    for (0..16) |_| {
        const payload = generator.next();
        try testing.expect(mix.weights[@backingInt(payload.kind)] > 0);
        try testing.expect(payload.data.len <= 256);
    }
}

test "workload: seeded fuzz mix parser" {
    const names = [_][]const u8{
        "transfer", "calldata", "erc20_transfer", "storage", "precompile", "looper", "x", "",
    };
    var prng = Prng.init(0x313);
    var buffer: [128]u8 = undefined;
    for (0..2_000) |_| {
        var writer: std.Io.Writer = .fixed(&buffer);
        const parts = prng.range(1, 6);
        for (0..parts) |index| {
            if (index > 0) writer.writeByte(if (prng.chance(1, 20)) ';' else ',') catch break;
            writer.writeAll(names[@intCast(prng.below(names.len))]) catch break;
            if (!prng.chance(1, 20)) writer.writeByte('=') catch break;
            writer.print("{d}", .{prng.below(2_000_010)}) catch break;
        }
        try check_mix(writer.buffered(), prng.int(u64));
    }
}

test "workload: fuzz mix parser" {
    try testing.fuzz({}, fuzz_mix, .{});
}

fn fuzz_mix(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [128]u8 = undefined;
    const text = buffer[0..smith.slice(&buffer)];
    try check_mix(text, smith.value(u64));
}

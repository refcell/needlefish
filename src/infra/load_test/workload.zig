//! Seeded workload generation (base/base `load-tests/src/workload/{generator,seeded}.rs` and
//! the `transfer`, `calldata`, `erc20` payloads).
//!
//! The same seed yields the same sequence of payloads, so a load test run is reproducible
//! and the simulator can replay it. Payloads are drawn from a weighted mix; each carries a
//! gas limit computed locally (intrinsic + calldata cost with the EIP-7623 floor), so the
//! runner needs no `eth_estimateGas` round trip per transaction.

const std = @import("std");
const assert = std.debug.assert;

const txdata = @import("../../batcher/txdata/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

pub const Address = primitives.Address;

pub const Kind = enum(u8) { transfer, calldata, erc20_transfer };
const kind_count = std.enums.values(Kind).len;

/// `transfer(address,uint256)` selector.
pub const erc20_transfer_selector = [4]u8{ 0xa9, 0x05, 0x9c, 0xbb };
/// Gas headroom for a token transfer on top of its intrinsic cost.
pub const erc20_execution_gas: u64 = 60_000;

pub const Mix = struct {
    weights: [kind_count]u32 = .{ 100, 0, 0 },

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
        return mix;
    }

    pub fn total(mix: Mix) u64 {
        var sum: u64 = 0;
        for (mix.weights) |weight| sum += weight;
        return sum;
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
    /// Target of `erc20_transfer` payloads; without a deployed token the call still lands.
    token: Address = .{ .bytes = @splat(0x20) },
};

pub fn Generator(comptime data_bytes_max: u32) type {
    comptime assert(data_bytes_max >= 68);
    return struct {
        const Self = @This();

        config: Config,
        prng: Prng,
        buffer: [data_bytes_max]u8 = undefined,
        generated: [kind_count]u64 = @splat(0),

        pub fn init(config: Config) Self {
            assert(config.mix.total() > 0);
            assert(config.calldata_bytes_max <= data_bytes_max);
            return .{ .config = config, .prng = Prng.init(config.seed) };
        }

        pub fn next(generator: *Self) Payload {
            const kind = generator.draw_kind();
            generator.generated[@backingInt(kind)] += 1;
            const recipient = generator.draw_address();
            const payload: Payload = switch (kind) {
                .transfer => .{
                    .kind = kind,
                    .to = recipient,
                    .value = 1,
                    .data = &.{},
                    .gas_limit = 21_000,
                },
                .calldata => generator.calldata(recipient),
                .erc20_transfer => generator.erc20_transfer(recipient),
            };
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

        fn calldata(generator: *Self, recipient: Address) Payload {
            const length = generator.prng.below(@as(u64, generator.config.calldata_bytes_max) + 1);
            const data = generator.buffer[0..@intCast(length)];
            generator.prng.fill(data);
            return .{
                .kind = .calldata,
                .to = recipient,
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data),
            };
        }

        fn erc20_transfer(generator: *Self, recipient: Address) Payload {
            const data = generator.buffer[0..68];
            @memcpy(data[0..4], &erc20_transfer_selector);
            @memset(data[4..16], 0);
            @memcpy(data[16..36], &recipient.bytes);
            @memset(data[36..68], 0);
            data[67] = 1; // One base unit.
            return .{
                .kind = .erc20_transfer,
                .to = generator.config.token,
                .value = 0,
                .data = data,
                .gas_limit = txdata.calldata_gas(data) + erc20_execution_gas,
            };
        }
    };
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

test "workload: erc20 calldata layout" {
    var generator = Generator(128).init(.{
        .seed = 1,
        .mix = try Mix.parse("erc20_transfer=1"),
        .calldata_bytes_max = 128,
    });
    const payload = generator.next();
    try testing.expectEqual(@as(usize, 68), payload.data.len);
    try testing.expectEqualSlices(u8, &erc20_transfer_selector, payload.data[0..4]);
    try testing.expectEqual(@as(u8, 1), payload.data[67]);
}

test "workload: fuzz mix parser" {
    try testing.fuzz({}, fuzz_mix, .{});
}

fn fuzz_mix(_: void, smith: *testing.Smith) anyerror!void {
    var buffer: [128]u8 = undefined;
    const text = buffer[0..smith.slice(&buffer)];
    const mix = Mix.parse(text) catch return;
    try testing.expect(mix.total() > 0);
    var generator = Generator(256).init(.{
        .seed = text.len,
        .mix = mix,
        .calldata_bytes_max = 256,
    });
    for (0..16) |_| {
        const payload = generator.next();
        try testing.expect(mix.weights[@backingInt(payload.kind)] > 0);
    }
}

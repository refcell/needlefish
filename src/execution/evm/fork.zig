//! Ethereum hard forks as seen by the EVM, in activation order.
//!
//! The interpreter is instantiated once per fork (`comptime fork: Fork`), so every
//! `fork.at_least(...)` check below folds away at compile time on the hot path.
//! OP Stack upgrades map onto these (Bedrock = merge, Canyon = shanghai,
//! Ecotone = cancun, Isthmus = prague, Jovian/Osaka-era = osaka); see `optimism.zig`.

const std = @import("std");
const assert = std.debug.assert;

pub const Fork = enum(u8) {
    frontier,
    homestead,
    /// EIP-150 gas repricing ("Tangerine Whistle", test name `EIP150`).
    tangerine,
    /// EIP-155/158/160/161/170 ("Spurious Dragon", test name `EIP158`).
    spurious_dragon,
    byzantium,
    constantinople,
    /// Constantinople without EIP-1283 (test name `ConstantinopleFix`).
    petersburg,
    istanbul,
    berlin,
    london,
    /// The Merge (test name `Paris`).
    merge,
    shanghai,
    cancun,
    prague,
    osaka,

    pub const latest: Fork = .osaka;

    pub fn at_least(fork: Fork, other: Fork) bool {
        return @backingInt(fork) >= @backingInt(other);
    }

    pub fn before(fork: Fork, other: Fork) bool {
        return @backingInt(fork) < @backingInt(other);
    }

    /// Parse the fork names used by ethereum/tests and execution-spec-tests fixtures.
    pub fn from_test_name(name: []const u8) ?Fork {
        const names = [_]struct { []const u8, Fork }{
            .{ "Frontier", .frontier },
            .{ "Homestead", .homestead },
            .{ "EIP150", .tangerine },
            .{ "EIP158", .spurious_dragon },
            .{ "Byzantium", .byzantium },
            .{ "Constantinople", .constantinople },
            .{ "ConstantinopleFix", .petersburg },
            .{ "Petersburg", .petersburg },
            .{ "Istanbul", .istanbul },
            .{ "Berlin", .berlin },
            .{ "London", .london },
            .{ "Paris", .merge },
            .{ "Merge", .merge },
            .{ "Shanghai", .shanghai },
            .{ "Cancun", .cancun },
            .{ "Prague", .prague },
            .{ "Osaka", .osaka },
        };
        for (names) |entry| {
            if (std.mem.eql(u8, entry[0], name)) return entry[1];
        }
        return null;
    }
};

comptime {
    assert(@backingInt(Fork.frontier) == 0);
    assert(Fork.latest == .osaka);
    assert(Fork.cancun.at_least(.shanghai));
}

test "fork: ordering and names" {
    try std.testing.expect(Fork.berlin.at_least(.istanbul));
    try std.testing.expect(!Fork.berlin.at_least(.london));
    try std.testing.expect(Fork.frontier.before(.homestead));
    try std.testing.expectEqual(Fork.petersburg, Fork.from_test_name("ConstantinopleFix").?);
    try std.testing.expectEqual(Fork.merge, Fork.from_test_name("Paris").?);
    try std.testing.expect(Fork.from_test_name("Nope") == null);
}

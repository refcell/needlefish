//! Multiplex router tests against fake builders: routing around Denim, shadow builds,
//! health, route memory, event filtering, and a seeded model fuzz.

const std = @import("std");
const testing = std.testing;
const multiplex = @import("root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const PayloadId = multiplex.PayloadId;
const PayloadAttributes = multiplex.PayloadAttributes;
const spec = &chainspec.ChainSpec.presets.base_sepolia;
const denim: u64 = 1_792_605_600;

const FakeBuilder = struct {
    closed: bool = false,
    fail_builds: bool = false,
    builds: u32 = 0,
    last_no_tx_pool: ?bool = null,
    known: [8]PayloadId = undefined,
    known_count: u32 = 0,

    pub fn send_new_payload(
        builder: *FakeBuilder,
        id: PayloadId,
        parent: [32]u8,
        attributes: *const PayloadAttributes,
    ) multiplex.BuilderError!void {
        _ = parent;
        if (builder.closed) return error.ChannelClosed;
        builder.builds += 1;
        builder.last_no_tx_pool = attributes.no_tx_pool;
        if (builder.fail_builds) return error.BuildFailed;
        builder.known[builder.known_count % builder.known.len] = id;
        builder.known_count += 1;
    }

    fn knows(builder: *const FakeBuilder, id: PayloadId) bool {
        const count = @min(builder.known_count, builder.known.len);
        for (builder.known[0..count]) |known| if (std.mem.eql(u8, &known, &id)) return true;
        return false;
    }

    pub fn best_payload(builder: *FakeBuilder, id: PayloadId) ?(multiplex.BuilderError!u32) {
        if (builder.closed) return error.ChannelClosed;
        if (!builder.knows(id)) return null;
        return id[0];
    }

    pub fn payload_timestamp(builder: *FakeBuilder, id: PayloadId) ?(multiplex.BuilderError!u64) {
        if (builder.closed) return error.ChannelClosed;
        if (!builder.knows(id)) return null;
        return id[1];
    }

    pub fn resolve(builder: *FakeBuilder, id: PayloadId) ?(multiplex.BuilderError!u32) {
        return builder.best_payload(id);
    }
};

const Router = multiplex.Router(FakeBuilder, u32);

fn id_of(byte: u8) PayloadId {
    return @splat(byte);
}

fn attributes_at(timestamp: u64) PayloadAttributes {
    return .{ .timestamp = timestamp, .prev_randao = .zero, .suggested_fee_recipient = .zero };
}

test "multiplex: flashblocks selected before Denim, basic from Denim, shadow has no pool" {
    var flashblocks: FakeBuilder = .{};
    var basic: FakeBuilder = .{};
    var router = Router.init(&flashblocks, &basic, spec);
    try router.build_new_payload(id_of(1), @splat(0), &attributes_at(denim - 1));
    try testing.expectEqual(multiplex.Kind.flashblocks, router.selected_for(id_of(1)));
    try testing.expectEqual(@as(?bool, null), flashblocks.last_no_tx_pool);
    try testing.expectEqual(@as(?bool, true), basic.last_no_tx_pool);
    try router.build_new_payload(id_of(2), @splat(0), &attributes_at(denim));
    try testing.expectEqual(multiplex.Kind.basic, router.selected_for(id_of(2)));
    try testing.expectEqual(@as(?bool, true), flashblocks.last_no_tx_pool);
    try testing.expectEqual(@as(?bool, null), basic.last_no_tx_pool);
    try testing.expectEqual(@as(u32, 2), flashblocks.builds);
    try testing.expectEqual(@as(u32, 2), basic.builds);
    // Reads follow the route.
    try testing.expectEqual(@as(u32, 2), (router.best_payload(id_of(2)).?) catch unreachable);
    try testing.expectEqual(@as(u64, 1), (router.payload_timestamp(id_of(1)).?) catch unreachable);
    // Unknown ids read from flashblocks, which does not know them.
    try testing.expectEqual(multiplex.Kind.flashblocks, router.selected_for(id_of(9)));
    try testing.expect(router.resolve(id_of(9)) == null);
}

test "multiplex: a closed builder becomes unavailable and stays so" {
    var flashblocks: FakeBuilder = .{};
    var basic: FakeBuilder = .{};
    var router = Router.init(&flashblocks, &basic, spec);
    try router.build_new_payload(id_of(3), @splat(0), &attributes_at(denim - 10));
    flashblocks.closed = true;
    const read = router.best_payload(id_of(3)).?;
    try testing.expectError(error.BuilderUnavailable, read);
    try testing.expect(!router.is_healthy(.flashblocks));
    flashblocks.closed = false; // Even if it answers "none" again, it is unavailable.
    try testing.expectError(error.BuilderUnavailable, router.best_payload(id_of(4)).?);
    // A shadow failure does not fail the selected build.
    basic.closed = true;
    try router.build_new_payload(id_of(5), @splat(0), &attributes_at(denim - 5));
    try testing.expect(!router.is_healthy(.basic));
    try testing.expectEqual(@as(u64, 1), router.metrics.shadow_failed[1].get());
    // A failed selected build is reported as such.
    flashblocks.fail_builds = true;
    const failed = router.build_new_payload(id_of(6), @splat(0), &attributes_at(denim - 5));
    try testing.expectError(error.BuildFailed, failed);
}

test "multiplex: events are forwarded only from the builder selected at their time" {
    var flashblocks: FakeBuilder = .{};
    var basic: FakeBuilder = .{};
    const router = Router.init(&flashblocks, &basic, spec);
    const early: multiplex.Event = .{ .built = .{ .id = id_of(1), .timestamp = denim - 1 } };
    const late: multiplex.Event = .{ .attributes = .{ .id = id_of(2), .timestamp = denim } };
    try testing.expect(router.forwards_event(.flashblocks, early));
    try testing.expect(!router.forwards_event(.basic, early));
    try testing.expect(router.forwards_event(.basic, late));
    try testing.expect(!router.forwards_event(.flashblocks, late));
}

test "multiplex: seeded fuzz route memory against a model" {
    var prng = Prng.init(0x3a17_91e);
    var flashblocks: FakeBuilder = .{};
    var basic: FakeBuilder = .{};
    var router = Router.init(&flashblocks, &basic, spec);
    // Model: base/base's VecDeque. An existing id updates in place; a new id is appended,
    // popping the front first when 128 are held.
    const capacity = multiplex.payload_routes_max;
    var model_ids: [capacity]u16 = undefined;
    var model_basic: [capacity]bool = undefined;
    var model_count: usize = 0;
    for (0..4000) |_| {
        const key: u16 = @intCast(prng.below(300));
        const basic_route = prng.chance(1, 2);
        router.record_route(id_key(key), if (basic_route) .basic else .flashblocks);
        const existing = std.mem.indexOfScalar(u16, model_ids[0..model_count], key);
        if (existing) |index| {
            model_basic[index] = basic_route;
        } else {
            if (model_count == capacity) {
                std.mem.copyForwards(u16, model_ids[0 .. capacity - 1], model_ids[1..]);
                std.mem.copyForwards(bool, model_basic[0 .. capacity - 1], model_basic[1..]);
                model_count -= 1;
            }
            model_ids[model_count] = key;
            model_basic[model_count] = basic_route;
            model_count += 1;
        }
        const probe: u16 = @intCast(prng.below(300));
        var expected: multiplex.Kind = .flashblocks;
        if (std.mem.indexOfScalar(u16, model_ids[0..model_count], probe)) |index| {
            if (model_basic[index]) expected = .basic;
        }
        try testing.expectEqual(expected, router.selected_for(id_key(probe)));
    }
}

fn id_key(key: u16) PayloadId {
    var id: PayloadId = @splat(0);
    std.mem.writeInt(u16, id[0..2], key, .little);
    return id;
}

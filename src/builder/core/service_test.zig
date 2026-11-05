//! Payload service tests on an in-memory L2 dev node with an injected clock: job lifecycle,
//! cancellation by a new FCU, the 150 ms cutoff inside the 200 ms slot, an early resolve
//! sealing immediately, expiry, failures, and a seeded + `std.testing.fuzz` model check of
//! random FCU / resolve / tick interleavings.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const best_txs = @import("best_txs.zig");
const builder_module = @import("builder.zig");
const builder_test = @import("builder_test.zig");
const timing = @import("timing.zig");
const service_module = @import("service.zig");

const BlockBuilder = builder_module.BlockBuilder;
const StepClock = builder_test.StepClock;
const Service = service_module.Service;
const Payload = service_module.Payload;
const PayloadId = service_module.PayloadId;
const Node = fixture.Node;
const l2 = &chainspec.ChainSpec.presets.base_devnet;
const ns_per_ms = timing.ns_per_ms;
const ns_per_s = timing.ns_per_s;

/// Default timing: 200 ms slots, 150 ms seal offset, 500 ms job leeway. A job started at
/// 1 s cuts off at 1.15 s, ends its slot at 1.2 s and expires at 1.7 s.
const start_ns: u64 = 1 * ns_per_s;
const cutoff_ns: u64 = start_ns + 150 * ns_per_ms;
const expires_ns: u64 = start_ns + 700 * ns_per_ms;

const Harness = struct {
    node: *Node,
    cache: best_txs.RejectionCache,
    builder: BlockBuilder,
    clock: StepClock,
    service: Service,

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try Node.create_for(l2);
        errdefer harness.node.destroy();
        harness.cache = try best_txs.RejectionCache.init(testing.allocator, 64, 1000);
        errdefer harness.cache.deinit(testing.allocator);
        harness.builder = try BlockBuilder.init(testing.allocator, &harness.cache, .{
            .transactions_max = 64,
            .transaction_bytes_max = 1 << 14,
            .select_max = 64,
        });
        errdefer harness.builder.deinit(testing.allocator);
        harness.clock = .{};
        const clock = builder_module.Clock.of(StepClock, &harness.clock);
        harness.service = try Service.init(&harness.builder, &harness.node.chain, clock, .{});
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.builder.deinit(testing.allocator);
        harness.cache.deinit(testing.allocator);
        harness.node.destroy();
        testing.allocator.destroy(harness);
    }

    fn genesis(harness: *const Harness) [32]u8 {
        return harness.node.chain.genesis_hash;
    }

    fn submit_pool(harness: *Harness, buffers: [][256]u8) !void {
        for (buffers, 0..) |*buffer, n| {
            try fixture.submit(harness.node, @intCast(n % 3 + 1), n / 3, 5, buffer);
        }
    }

    /// Moves both time sources to `now_ns` (each clock read inside a build then advances
    /// it by `step_ns`) and ticks the service.
    fn tick(harness: *Harness, now_ns: u64, step_ns: u64) void {
        assert(now_ns >= harness.service.now_ns);
        harness.clock = .{ .now = now_ns, .step_ns = step_ns };
        harness.service.tick(now_ns);
    }
};

fn id_of(byte: u8) PayloadId {
    return @splat(byte);
}

fn expect_resolved(result: ?(service_module.Error!Payload)) !Payload {
    const answer = result orelse return error.TestUnexpectedResult;
    return try answer;
}

test "service: FCU starts a job, tick builds and seals, resolve returns the block" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const attributes = fixture.attributes_l2(2, 0xfe);
    const service = &harness.service;
    harness.tick(start_ns, 0);
    try service.send_new_payload(id_of(1), harness.genesis(), &attributes);
    try testing.expectEqual(@as(?u64, start_ns), service.next_deadline_ns());
    try testing.expectEqual(@as(?u64, 2), service.payload_timestamp(id_of(1)));
    harness.tick(start_ns + ns_per_ms, ns_per_ms);
    try testing.expectEqual(@as(u64, 1), service.metrics.blocks_sealed.get());
    try testing.expectEqual(@as(?u64, expires_ns), service.next_deadline_ns());
    // Later ticks inside the slot do not rebuild.
    harness.tick(cutoff_ns, 0);
    try testing.expectEqual(@as(u64, 1), service.metrics.blocks_sealed.get());
    const best = try expect_resolved(service.resolve(id_of(1)));
    try testing.expectEqual(@as(usize, 6), best.transactions.len);
    try testing.expectEqual(service_module.Stop.pool_exhausted, best.stop);
    try testing.expectEqualSlices(u8, &best.header.hash().bytes, &best.block_hash.bytes);
    try testing.expect(best.block_value > 0);
    // Resolved jobs are gone.
    try testing.expect(service.resolve(id_of(1)) == null);
    try testing.expect(service.payload_timestamp(id_of(1)) == null);
    try testing.expect(service.next_deadline_ns() == null);
    try testing.expectEqual(@as(u64, 1), service.metrics.jobs_resolved.get());
    try testing.expectEqual(@as(u64, 0), service.metrics.blocks_sealed_early.get());
}

test "service: the build stops at the 150 ms cutoff" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const service = &harness.service;
    harness.tick(start_ns, 0);
    try service.send_new_payload(id_of(1), harness.genesis(), &fixture.attributes_l2(2, 1));
    // Each pool transaction takes 50 ms: reads at 0, 50 and 100 ms pass, 150 ms stops.
    harness.tick(start_ns, 50 * ns_per_ms);
    const best = try expect_resolved(service.resolve(id_of(1)));
    try testing.expectEqual(@as(usize, 3), best.transactions.len);
    try testing.expectEqual(service_module.Stop.cutoff, best.stop);
    try testing.expectEqual(@as(u64, 1), service.metrics.builds_cut_off.get());
}

test "service: a new FCU cancels the previous job" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [3][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const service = &harness.service;
    harness.tick(start_ns, 0);
    try service.send_new_payload(id_of(1), harness.genesis(), &fixture.attributes_l2(2, 1));
    harness.tick(start_ns + 10, 0);
    try service.send_new_payload(id_of(2), harness.genesis(), &fixture.attributes_l2(2, 2));
    try testing.expectEqual(@as(u64, 1), service.metrics.jobs_cancelled.get());
    try testing.expect(service.resolve(id_of(1)) == null);
    try testing.expectEqualSlices(u8, &id_of(2), &service.active_id().?);
    harness.tick(start_ns + 20, 0);
    const best = try expect_resolved(service.resolve(id_of(2)));
    try testing.expectEqual(@as(usize, 3), best.transactions.len);
    try testing.expectEqual(@as(u8, 0x02), best.header.beneficiary.bytes[0]);
}

test "service: an early resolve seals immediately without waiting" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [3][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    var deposit_buffer: [256]u8 = undefined;
    const deposits = [_][]const u8{builder_test.deposit(&deposit_buffer, 1)};
    var attributes = fixture.attributes_l2(2, 1);
    attributes.transactions = &deposits;
    const service = &harness.service;
    harness.tick(start_ns, 0);
    try service.send_new_payload(id_of(4), harness.genesis(), &attributes);
    // getPayload before any tick: the cutoff moves to now, so only the deposit is sealed.
    const best = try expect_resolved(service.resolve(id_of(4)));
    try testing.expectEqual(@as(usize, 1), best.transactions.len);
    try testing.expectEqualSlices(u8, deposits[0], best.transactions[0]);
    try testing.expectEqual(service_module.Stop.cutoff, best.stop);
    try testing.expectEqual(@as(u64, 1), service.metrics.blocks_sealed_early.get());
}

test "service: an unresolved job expires after its slot plus leeway" {
    const harness = try Harness.create();
    defer harness.destroy();
    const service = &harness.service;
    harness.tick(start_ns, 0);
    try service.send_new_payload(id_of(3), harness.genesis(), &fixture.attributes_l2(2, 1));
    harness.tick(expires_ns - 1, 0);
    try testing.expectEqualSlices(u8, &id_of(3), &service.active_id().?);
    harness.tick(expires_ns, 0);
    try testing.expect(service.resolve(id_of(3)) == null);
    try testing.expectEqual(@as(u64, 1), service.metrics.jobs_expired.get());
    try testing.expect(service.next_deadline_ns() == null);
}

test "service: failed starts and failed builds" {
    const harness = try Harness.create();
    defer harness.destroy();
    const service = &harness.service;
    harness.tick(start_ns, 0);
    try service.send_new_payload(id_of(1), harness.genesis(), &fixture.attributes_l2(2, 1));
    const unknown: [32]u8 = @splat(0xab);
    const result = service.send_new_payload(id_of(2), unknown, &fixture.attributes_l2(2, 1));
    try testing.expectError(error.BuildFailed, result);
    try testing.expect(service.active_id() == null);
    try testing.expectEqual(@as(u64, 1), service.metrics.job_start_failed.get());
    // An attribute transaction that does not execute fails the build, not the FCU.
    const garbage = [_][]const u8{&.{ 0x7e, 0x01 }};
    var attributes = fixture.attributes_l2(2, 1);
    attributes.transactions = &garbage;
    try service.send_new_payload(id_of(5), harness.genesis(), &attributes);
    harness.tick(start_ns + 1, 0);
    try testing.expectEqual(@as(u64, 1), service.metrics.build_failed.get());
    try testing.expectError(error.BuildFailed, service.resolve(id_of(5)).?);
    try testing.expect(service.active_id() == null);
}

/// The model of one job.
const Model = struct {
    id: PayloadId,
    expires_ns: u64,
    no_tx_pool: bool,
};

/// One random interleaving of FCUs, resolves and ticks against the model. Returns how many
/// resolves returned a block with pool transactions.
fn random_interleaving(prng: *Prng) !u64 {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [9][256]u8 = undefined;
    try harness.submit_pool(buffers[0..prng.below(buffers.len + 1)]);
    const service = &harness.service;
    var model: ?Model = null;
    var now_ns: u64 = start_ns + prng.below(ns_per_s);
    harness.tick(now_ns, 0);
    var with_pool: u64 = 0;
    for (0..48) |_| {
        switch (prng.below(8)) {
            0, 1 => {
                const id = id_of(@intCast(prng.below(4)));
                var attributes = fixture.attributes_l2(now_ns / ns_per_s + 1, 1);
                attributes.no_tx_pool = prng.chance(1, 5);
                try service.send_new_payload(id, harness.genesis(), &attributes);
                const slot = timing.Slot.init(.{}, now_ns);
                model = .{
                    .id = id,
                    .expires_ns = slot.expires_ns,
                    .no_tx_pool = attributes.no_tx_pool.?,
                };
            },
            2, 3 => with_pool += try check_resolve(harness, prng, &model),
            else => {
                now_ns += prng.below(400 * ns_per_ms);
                harness.tick(now_ns, prng.below(60 * ns_per_ms));
                const active = model orelse continue;
                if (now_ns >= active.expires_ns) model = null;
            },
        }
        // At most one active job, and it is the model's.
        const active_id = service.active_id();
        try testing.expectEqual(model != null, active_id != null);
        if (model) |m| try testing.expectEqualSlices(u8, &m.id, &active_id.?);
    }
    return with_pool;
}

fn check_resolve(harness: *Harness, prng: *Prng, model: *?Model) !u64 {
    // Usually ask for the active job; sometimes for an arbitrary (likely unknown) id.
    var id = id_of(@intCast(prng.below(4)));
    if (model.*) |m| {
        if (prng.chance(3, 4)) id = m.id;
    }
    const result = harness.service.resolve(id);
    const expected = if (model.*) |m| std.mem.eql(u8, &m.id, &id) else false;
    try testing.expectEqual(expected, result != null);
    if (!expected) return 0;
    const active = model.*.?;
    model.* = null;
    const best = try (result.?);
    try testing.expectEqualSlices(u8, &id, &best.id);
    try testing.expectEqualSlices(u8, &best.header.hash().bytes, &best.block_hash.bytes);
    if (active.no_tx_pool) {
        try testing.expectEqual(@as(usize, 0), best.transactions.len);
        try testing.expectEqual(service_module.Stop.no_tx_pool, best.stop);
    }
    return @intFromBool(best.transactions.len > 0);
}

test "service: seeded fuzz of FCU, resolve and tick interleavings" {
    var prng = Prng.init(0x5e41ce);
    var with_pool: u64 = 0;
    for (0..24) |_| with_pool += try random_interleaving(&prng);
    // The seeds must reach resolves of blocks with pool transactions.
    try testing.expect(with_pool >= 8);
}

fn fuzz_service(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    _ = try random_interleaving(&prng);
}

test "service: fuzz" {
    try testing.fuzz({}, fuzz_service, .{});
}

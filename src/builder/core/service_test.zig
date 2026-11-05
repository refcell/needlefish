//! Flashblocks payload service tests on an in-memory L2 dev node with a recording sink and an
//! injected clock: job lifecycle, cancellation by a new FCU, resolve before and after every
//! flashblock, payload expiry, no-tx-pool jobs, the multiplex `Builder` interface, and a
//! seeded + `std.testing.fuzz` model check of random FCU / resolve / tick interleavings.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const multiplex = @import("../multiplex/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const best_txs = @import("best_txs.zig");
const generator_module = @import("generator.zig");
const timing = @import("timing.zig");
const service_module = @import("service.zig");

const Generator = generator_module.Generator;
const Flashblock = generator_module.Flashblock;
const Node = fixture.Node;
const B256 = primitives.B256;
const PayloadId = service_module.PayloadId;
const Payload = service_module.Payload;
const l2 = &chainspec.ChainSpec.presets.base_devnet;
const ns_per_ms = timing.ns_per_ms;
const ns_per_s = timing.ns_per_s;

/// What the sink saw of one published flashblock (flashblock slices borrow the generator).
const Entry = struct {
    id: PayloadId,
    index: u64,
    block_hash: B256,
    transactions: u64,
    has_base: bool,
};

const Recorder = struct {
    log: [32]Entry = undefined,
    len: u32 = 0,
    total: u64 = 0,
    last: ?Entry = null,

    pub fn publish(recorder: *Recorder, flashblock: Flashblock) error{}!u32 {
        const entry: Entry = .{
            .id = flashblock.payload_id,
            .index = flashblock.index,
            .block_hash = flashblock.diff.block_hash,
            .transactions = flashblock.diff.transactions.len,
            .has_base = flashblock.base != null,
        };
        if (recorder.len < recorder.log.len) {
            recorder.log[recorder.len] = entry;
            recorder.len += 1;
        }
        recorder.total += 1;
        recorder.last = entry;
        return 1;
    }

    fn entries(recorder: *const Recorder) []const Entry {
        return recorder.log[0..recorder.len];
    }
};

const Service = service_module.Service(Recorder);

/// for_tests timing: 1000 ms blocks, 200 ms interval, 100 ms flashblocks leeway, 500 ms job
/// leeway. A job for timestamp 2 s started at 1 s has 5 flashblocks closing at
/// 1.1, 1.3, 1.5, 1.7 and 1.9 s, and expires at 2.5 s.
const config = timing.Config.for_tests;
const start_ns: u64 = 1 * ns_per_s;
const expires_ns: u64 = 2500 * ns_per_ms;

fn deadline_ns(index: u64) u64 {
    assert(index >= 1 and index <= 5);
    return 1100 * ns_per_ms + (index - 1) * 200 * ns_per_ms;
}

const Harness = struct {
    node: *Node,
    cache: best_txs.RejectionCache,
    generator: Generator,
    recorder: Recorder,
    service: Service,

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.node = try Node.create_for(l2);
        errdefer harness.node.destroy();
        harness.cache = try best_txs.RejectionCache.init(testing.allocator, 64, 1000);
        errdefer harness.cache.deinit(testing.allocator);
        harness.generator = try Generator.init(testing.allocator, &harness.cache, .{
            .flashblocks_max = 8,
            .transactions_max = 64,
            .transaction_bytes_max = 1 << 14,
            .select_max = 64,
        });
        errdefer harness.generator.deinit(testing.allocator);
        harness.recorder = .{};
        harness.service = try Service.init(
            &harness.generator,
            &harness.node.chain,
            &harness.recorder,
            config,
        );
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.generator.deinit(testing.allocator);
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
};

fn id_of(byte: u8) PayloadId {
    return @splat(byte);
}

fn expect_resolved(result: ?(service_module.BuilderError!Payload)) !Payload {
    const answer = result orelse return error.TestUnexpectedResult;
    return try answer;
}

test "service: job lifecycle publishes the deltas and resolves the last sealed block" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    var attributes = fixture.attributes_l2(2, 0xfe);
    // Five flashblocks of 42_000 gas: room for two transfers each.
    attributes.gas_limit = 210_000;
    const service = &harness.service;
    service.tick(start_ns);
    try service.send_new_payload(id_of(1), harness.genesis(), &attributes);
    try testing.expectEqual(@as(u32, 1), harness.recorder.len);
    try testing.expect(harness.recorder.log[0].has_base);
    try testing.expectEqual(@as(?u64, deadline_ns(1)), service.next_deadline_ns());
    service.tick(deadline_ns(1) - 1);
    try testing.expectEqual(@as(u32, 1), harness.recorder.len);
    var index: u64 = 1;
    while (index <= 5) : (index += 1) {
        service.tick(deadline_ns(index));
        try testing.expectEqual(index + 1, harness.recorder.len);
    }
    try testing.expectEqual(@as(?u64, expires_ns), service.next_deadline_ns());
    service.tick(expires_ns - 1);
    try testing.expectEqual(@as(u32, 6), harness.recorder.len);
    try testing.expectEqual(@as(u64, 2), service.payload_timestamp(id_of(1)).? catch 0);
    try testing.expectError(error.BuildFailed, service.best_payload(id_of(1)).?);
    const best = try expect_resolved(service.resolve(id_of(1)));
    var transactions: u64 = 0;
    for (harness.recorder.entries(), 0..) |entry, position| {
        try testing.expectEqual(@as(u64, position), entry.index);
        try testing.expectEqual(position == 0, entry.has_base);
        try testing.expectEqualSlices(u8, &id_of(1), &entry.id);
        transactions += entry.transactions;
    }
    try testing.expectEqual(@as(u64, 6), transactions);
    try testing.expectEqual(transactions, best.transactions.len);
    try testing.expectEqual(@as(u32, 5), best.flashblock_index);
    const last = harness.recorder.last.?;
    try testing.expectEqualSlices(u8, &last.block_hash.bytes, &best.block_hash.bytes);
    try testing.expectEqualSlices(u8, &best.header.hash().bytes, &best.block_hash.bytes);
    try testing.expect(best.block_value > 0);
    // Resolved jobs are gone.
    try testing.expect(service.resolve(id_of(1)) == null);
    try testing.expect(service.payload_timestamp(id_of(1)) == null);
    try testing.expect(service.next_deadline_ns() == null);
    try testing.expectEqual(@as(u64, 1), service.metrics.jobs_resolved.get());
}

test "service: a new FCU cancels the previous job" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [3][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const service = &harness.service;
    const first = fixture.attributes_l2(2, 0x01);
    const second = fixture.attributes_l2(2, 0x02);
    service.tick(start_ns);
    try service.send_new_payload(id_of(1), harness.genesis(), &first);
    service.tick(deadline_ns(2));
    try testing.expectEqual(@as(u32, 3), harness.recorder.len);
    try service.send_new_payload(id_of(2), harness.genesis(), &second);
    try testing.expectEqual(@as(u64, 1), service.metrics.jobs_cancelled.get());
    try testing.expect(service.resolve(id_of(1)) == null);
    try testing.expect(service.payload_timestamp(id_of(1)) == null);
    try testing.expectEqualSlices(u8, &id_of(2), &service.active_id().?);
    const restart = harness.recorder.log[3];
    try testing.expectEqualSlices(u8, &id_of(2), &restart.id);
    try testing.expectEqual(@as(u64, 0), restart.index);
    // The second job's schedule starts at its own FCU time (1.3 s): 3 flashblocks.
    service.tick(expires_ns - 1);
    for (harness.recorder.entries()[4..]) |entry| {
        try testing.expectEqualSlices(u8, &id_of(2), &entry.id);
    }
    const best = try expect_resolved(service.resolve(id_of(2)));
    try testing.expectEqual(@as(u32, 3), best.flashblock_index);
    try testing.expectEqual(@as(usize, 3), best.transactions.len);
    try testing.expectEqual(@as(u8, 0x02), best.header.beneficiary.bytes[0]);
}

test "service: resolve before every flashblock returns the newest sealed block" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [6][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    var attributes = fixture.attributes_l2(2, 0xfe);
    attributes.gas_limit = 210_000;
    const service = &harness.service;
    service.tick(start_ns);
    try service.send_new_payload(id_of(9), harness.genesis(), &attributes);
    const zero_hash = harness.recorder.last.?.block_hash;
    service.tick(deadline_ns(2));
    const best = try expect_resolved(service.resolve(id_of(9)));
    try testing.expectEqual(@as(u32, 2), best.flashblock_index);
    try testing.expectEqual(@as(usize, 4), best.transactions.len);
    try testing.expect(!std.mem.eql(u8, &zero_hash.bytes, &best.block_hash.bytes));
    const last_hash = harness.recorder.last.?.block_hash;
    try testing.expectEqualSlices(u8, &last_hash.bytes, &best.block_hash.bytes);
    // No more flashblocks after resolve.
    service.tick(expires_ns);
    try testing.expectEqual(@as(u32, 3), harness.recorder.len);
    try testing.expectEqual(@as(u64, 0), service.metrics.jobs_expired.get());
}

test "service: an unresolved job expires at its payload deadline" {
    const harness = try Harness.create();
    defer harness.destroy();
    const service = &harness.service;
    service.tick(start_ns);
    try service.send_new_payload(id_of(3), harness.genesis(), &fixture.attributes_l2(2, 1));
    // One late tick bursts every remaining flashblock, then drops the job.
    service.tick(expires_ns);
    try testing.expectEqual(@as(u32, 6), harness.recorder.len);
    try testing.expect(service.resolve(id_of(3)) == null);
    try testing.expectEqual(@as(u64, 1), service.metrics.jobs_expired.get());
    try testing.expect(service.next_deadline_ns() == null);
}

test "service: no-tx-pool and late jobs build only the fallback block" {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [3][256]u8 = undefined;
    try harness.submit_pool(&buffers);
    const service = &harness.service;
    var shadow = fixture.attributes_l2(2, 1);
    shadow.no_tx_pool = true;
    service.tick(start_ns);
    try service.send_new_payload(id_of(4), harness.genesis(), &shadow);
    service.tick(deadline_ns(5));
    try testing.expectEqual(@as(u32, 0), harness.recorder.len);
    const quiet = try expect_resolved(service.resolve(id_of(4)));
    try testing.expectEqual(@as(u32, 0), quiet.flashblock_index);
    try testing.expectEqual(@as(usize, 0), quiet.transactions.len);
    // An FCU 50 ms before the flashblocks leeway cut-off gets zero regular flashblocks.
    service.tick(1950 * ns_per_ms);
    try service.send_new_payload(id_of(5), harness.genesis(), &fixture.attributes_l2(2, 1));
    try testing.expectEqual(@as(u32, 1), harness.recorder.len);
    // The payload deadline counts whole seconds: (2 s - floor(1.95 s)) + 500 ms leeway.
    try testing.expectEqual(@as(?u64, 3450 * ns_per_ms), service.next_deadline_ns());
    const late = try expect_resolved(service.resolve(id_of(5)));
    try testing.expectEqual(@as(u32, 0), late.flashblock_index);
}

test "service: a failed start leaves no job" {
    const harness = try Harness.create();
    defer harness.destroy();
    const service = &harness.service;
    service.tick(start_ns);
    try service.send_new_payload(id_of(1), harness.genesis(), &fixture.attributes_l2(2, 1));
    const unknown: [32]u8 = @splat(0xab);
    const result = service.send_new_payload(id_of(2), unknown, &fixture.attributes_l2(2, 1));
    try testing.expectError(error.BuildFailed, result);
    try testing.expect(service.active_id() == null);
    try testing.expect(service.resolve(id_of(1)) == null);
    try testing.expectEqual(@as(u64, 1), service.metrics.job_start_failed.get());
}

test "service: satisfies the multiplex Builder interface" {
    const flashblocks = try Harness.create();
    defer flashblocks.destroy();
    const basic = try Harness.create();
    defer basic.destroy();
    const Router = multiplex.Router(Service, Payload);
    var router = Router.init(&flashblocks.service, &basic.service, l2);
    flashblocks.service.tick(start_ns);
    basic.service.tick(start_ns);
    const attributes = fixture.attributes_l2(2, 1);
    try router.build_new_payload(id_of(6), flashblocks.genesis(), &attributes);
    const selected: multiplex.Kind = if (router.basic_selected_at(2)) .basic else .flashblocks;
    const shadow = if (selected == .basic) flashblocks else basic;
    // The shadow builder runs without the pool and publishes nothing.
    try testing.expectEqual(@as(u32, 0), shadow.recorder.len);
    try testing.expectEqual(@as(u64, 2), (router.payload_timestamp(id_of(6)).?) catch 0);
    const best = (router.resolve(id_of(6)).?) catch return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 0), best.flashblock_index);
}

/// The model of one job, recomputed from the same timing functions.
const Model = struct {
    id: PayloadId,
    schedule: timing.Schedule,
    count: u64,
    expires_ns: u64,
    no_tx_pool: bool,
    /// Flashblocks published so far (index 0 counts).
    published: u64,
    last_hash: ?B256,
};

fn model_start(
    model: *?Model,
    now_ns: u64,
    id: PayloadId,
    attributes: *const payload.PayloadAttributes,
) void {
    const schedule = timing.Schedule.init(config, attributes.timestamp, now_ns, 0);
    const duration_ns = timing.payload_job_duration_ns(config, attributes.timestamp, now_ns);
    model.* = .{
        .id = id,
        .schedule = schedule,
        .count = @min(schedule.count, 8),
        .expires_ns = now_ns + duration_ns,
        .no_tx_pool = attributes.no_tx_pool.?,
        .published = 0,
        .last_hash = null,
    };
}

/// Checks the sink against the model after an operation and folds in what it published.
fn check_publications(harness: *Harness, model: *Model, total_before: u64) !void {
    const new = harness.recorder.total - total_before;
    if (model.no_tx_pool) {
        try testing.expectEqual(@as(u64, 0), new);
        return;
    }
    const due = harness.service.now_ns;
    const ticks = model.schedule.index_due(due) - 1;
    const expected = 1 + @min(ticks, model.count);
    try testing.expectEqual(expected, model.published + new);
    if (new == 0) return;
    const last = harness.recorder.last.?;
    // At most one active job: every publication belongs to it, indices increase by one.
    try testing.expectEqualSlices(u8, &model.id, &last.id);
    try testing.expectEqual(expected - 1, last.index);
    model.published = expected;
    model.last_hash = last.block_hash;
}

/// Returns how many resolves were checked against a published block hash.
fn random_interleaving(prng: *Prng) !u64 {
    const harness = try Harness.create();
    defer harness.destroy();
    var buffers: [9][256]u8 = undefined;
    try harness.submit_pool(buffers[0..prng.below(buffers.len + 1)]);
    const service = &harness.service;
    var model: ?Model = null;
    var now_ns: u64 = start_ns + prng.below(ns_per_s);
    service.tick(now_ns);
    var checked: u64 = 0;
    var step: u32 = 0;
    while (step < 48) : (step += 1) {
        const total_before = harness.recorder.total;
        switch (prng.below(8)) {
            0, 1 => {
                const id = id_of(@intCast(prng.below(4)));
                var attributes = fixture.attributes_l2(now_ns / ns_per_s + prng.range(1, 2), 1);
                attributes.no_tx_pool = prng.chance(1, 5);
                try service.send_new_payload(id, harness.genesis(), &attributes);
                model_start(&model, now_ns, id, &attributes);
                const active = &model.?;
                try check_publications(harness, active, total_before);
            },
            2 => {
                const id = id_of(@intCast(prng.below(4)));
                const result = service.resolve(id);
                const expected = if (model) |m| std.mem.eql(u8, &m.id, &id) else false;
                try testing.expectEqual(expected, result != null);
                if (!expected) continue;
                const best = try (result.?);
                const active = model.?;
                if (active.last_hash) |hash| {
                    try testing.expectEqualSlices(u8, &hash.bytes, &best.block_hash.bytes);
                    try testing.expectEqual(active.published - 1, best.flashblock_index);
                    checked += 1;
                }
                model = null;
            },
            else => {
                now_ns += prng.below(400 * ns_per_ms);
                service.tick(now_ns);
                const active = &(model orelse {
                    try testing.expectEqual(total_before, harness.recorder.total);
                    continue;
                });
                try check_publications(harness, active, total_before);
                if (now_ns >= active.expires_ns) model = null;
            },
        }
        // At most one active job, and it is the model's.
        const active_id = service.active_id();
        try testing.expectEqual(model != null, active_id != null);
        if (model) |m| try testing.expectEqualSlices(u8, &m.id, &active_id.?);
    }
    return checked;
}

test "service: seeded fuzz of FCU, resolve and tick interleavings" {
    var prng = Prng.init(0x5e41ce);
    var checked: u64 = 0;
    for (0..24) |_| checked += try random_interleaving(&prng);
    // The seeds must reach resolves of published jobs, not only empty or expired ones.
    try testing.expect(checked >= 8);
}

fn fuzz_service(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    _ = try random_interleaving(&prng);
}

test "service: fuzz" {
    try testing.fuzz({}, fuzz_service, .{});
}

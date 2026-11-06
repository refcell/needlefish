//! Resource-metering driver tests: base/base `config.rs` cases (fail open without meter
//! data, enforce versus dry-run, overflow fails open, unthrottled accounting overlays the
//! simulated rows), then a seeded and a `std.testing.fuzz` model check of one build over a
//! random schedule, store contents (missing, expired, disabled, oversized samples) and a
//! random sequence of attribute and pool transactions against an independent cumulative.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const Prng = @import("../../testing/prng.zig").Prng;
const metering = @import("root.zig");
const schedule_module = @import("schedule.zig");
const resource = @import("resource.zig");

const Schedule = schedule_module.Schedule;
const Observation = schedule_module.Observation;
const Decision = schedule_module.Decision;
const Sample = metering.Sample;
const MeteringStore = metering.MeteringStore;
const ResourceMetering = resource.ResourceMetering;
const B256 = metering.B256;

const ttl_ns: u64 = 1000;

fn hash_of(byte: u8) B256 {
    return .{ .bytes = @splat(byte) };
}

const Fixture = struct {
    schedule: Schedule,
    store: MeteringStore,

    fn create(text: ?[]const u8) !*Fixture {
        const fixture = try testing.allocator.create(Fixture);
        errdefer testing.allocator.destroy(fixture);
        fixture.schedule = try Schedule.init(testing.allocator, .{ .rules_max = 8 });
        errdefer fixture.schedule.deinit(testing.allocator);
        if (text) |json| try fixture.schedule.load(json);
        fixture.store = try MeteringStore.init(testing.allocator, true, 16, ttl_ns);
        return fixture;
    }

    fn destroy(fixture: *Fixture) void {
        fixture.store.deinit(testing.allocator);
        fixture.schedule.deinit(testing.allocator);
        testing.allocator.destroy(fixture);
    }

    fn put(fixture: *Fixture, byte: u8, sample: Sample, now_ns: u64) void {
        fixture.store.insert(hash_of(byte), .{
            .total_gas_used = sample.gas_used,
            .total_execution_time_us = 1,
            .sample = sample,
        }, now_ns);
    }
};

/// base/base `cpu_schedule`: gas weight 1, SSTORE count 10_000.
fn cpu_schedule(block: u64, transaction: u64, dry_run: bool) [256]u8 {
    var text: [256]u8 = @splat(' ');
    _ = std.fmt.bufPrint(&text,
        \\{{"version":1,"dimensions":[{{"name":"cpu","blockLimit":{d},
        \\"transactionLimit":{d},"baseGasWeight":1,
        \\"operations":[{{"name":"SSTORE","countCost":10000}}],"dryRun":{}}}]}}
    , .{ block, transaction, dry_run }) catch unreachable; // 256 bytes fit the template.
    return text;
}

fn sstore_sample(gas_used: u64, sstores: u64) Sample {
    var sample = Sample.init(gas_used);
    sample.append("SSTORE", sstores, 0) catch unreachable; // One row fits.
    return sample;
}

test "resource: inactive metering allows everything and accounts nothing" {
    const text = cpu_schedule(30_000, 30_000, false);
    const fixture = try Fixture.create(&text);
    defer fixture.destroy();
    fixture.put(1, sstore_sample(21_000, 9), 0);
    var disabled = ResourceMetering.init(false, &fixture.schedule, &fixture.store);
    try testing.expect(!disabled.is_active());
    disabled.begin_build();
    try testing.expectEqual(Decision.allow, disabled.check_simulated(hash_of(1), 0).decision);
    disabled.account_unthrottled(hash_of(1), 21_000, 0);
    try testing.expectEqual(Decision.allow, disabled.account_executed(21_000, null));
    try testing.expectEqual(@as(u128, 0), disabled.cumulative[0]);
    const empty = try Fixture.create(null);
    defer empty.destroy();
    const inactive = ResourceMetering.init(true, &empty.schedule, &empty.store);
    try testing.expect(!inactive.is_active());
}

test "resource: no meter data fails open; executed usage still counts gas" {
    const text = cpu_schedule(30_000, 30_000, false);
    const fixture = try Fixture.create(&text);
    defer fixture.destroy();
    var driver = ResourceMetering.init(true, &fixture.schedule, &fixture.store);
    driver.begin_build();
    const admission = driver.check_simulated(hash_of(7), 0);
    try testing.expectEqual(Decision.allow, admission.decision);
    try testing.expect(admission.sample == null);
    try testing.expectEqual(Decision.allow, driver.account_executed(21_000, admission.sample));
    try testing.expectEqual(@as(u128, 21_000), driver.cumulative_usage()[0]);
    // No store at all behaves the same.
    var storeless = ResourceMetering.init(true, &fixture.schedule, null);
    storeless.begin_build();
    try testing.expectEqual(Decision.allow, storeless.check_simulated(hash_of(7), 0).decision);
}

test "resource: enforced transaction scope is permanent; block scope is not; dry run counts" {
    const text = cpu_schedule(60_000, 40_000, false);
    const fixture = try Fixture.create(&text);
    defer fixture.destroy();
    fixture.put(1, sstore_sample(21_000, 2), 0); // 41_000 > 40_000: transaction scope.
    fixture.put(2, sstore_sample(21_000, 1), 0); // 31_000 fits.
    var driver = ResourceMetering.init(true, &fixture.schedule, &fixture.store);
    driver.begin_build();
    const too_big = driver.check_simulated(hash_of(1), 1);
    try testing.expect(too_big.should_exclude() and too_big.is_permanent());
    const fits = driver.check_simulated(hash_of(2), 1);
    try testing.expect(!fits.should_exclude());
    try testing.expectEqual(Decision.allow, driver.account_executed(21_000, fits.sample));
    try testing.expectEqual(@as(u128, 31_000), driver.cumulative_usage()[0]);
    // The second copy no longer fits the block: excluded, not permanent.
    const again = driver.check_simulated(hash_of(2), 1);
    try testing.expect(again.should_exclude() and !again.is_permanent());
    try testing.expectEqual(@as(u32, 2), driver.build.throttled);
    try testing.expectEqual(@as(u32, 1), driver.build.permanent);
    // Dry run: nothing excluded, usage still accumulates.
    const dry_text = cpu_schedule(60_000, 40_000, true);
    const dry = try Fixture.create(&dry_text);
    defer dry.destroy();
    dry.put(1, sstore_sample(21_000, 2), 0);
    var observer = ResourceMetering.init(true, &dry.schedule, &dry.store);
    observer.begin_build();
    const admitted = observer.check_simulated(hash_of(1), 1);
    try testing.expect(admitted.decision == .throttle and !admitted.should_exclude());
    try testing.expect(!admitted.is_permanent());
    try testing.expect(observer.account_executed(21_000, admitted.sample) == .throttle);
    try testing.expectEqual(@as(u128, 41_000), observer.cumulative_usage()[0]);
    try testing.expectEqual(@as(u32, 0), observer.build.throttled);
    // A new build starts from zero.
    observer.begin_build();
    try testing.expectEqual(@as(u128, 0), observer.cumulative_usage()[0]);
}

test "resource: unthrottled accounting overlays simulated rows; overflow fails open" {
    const text = cpu_schedule(1_000_000, 1_000_000, false);
    const fixture = try Fixture.create(&text);
    defer fixture.destroy();
    fixture.put(3, sstore_sample(50_000, 3), 0);
    var driver = ResourceMetering.init(true, &fixture.schedule, &fixture.store);
    driver.begin_build();
    driver.account_unthrottled(hash_of(3), 45_000, 0); // Actual gas, simulated SSTORE rows.
    try testing.expectEqual(@as(u128, 45_000 + 30_000), driver.cumulative_usage()[0]);
    driver.account_unthrottled(hash_of(4), 1_000, 0); // No sample: gas only.
    try testing.expectEqual(@as(u128, 76_000), driver.cumulative_usage()[0]);
    // Expired samples are gone.
    driver.account_unthrottled(hash_of(3), 0, ttl_ns);
    try testing.expectEqual(@as(u128, 76_000), driver.cumulative_usage()[0]);
}

test "resource: overflowing usage fails open and adds nothing" {
    const fixture = try Fixture.create(
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":100,"baseGasWeight":1,
        \\"operations":[{"name":"SSTORE","countCost":18446744073709551615}],"dryRun":false}]}
    );
    defer fixture.destroy();
    var huge = Sample.init(0);
    try huge.append("SSTORE", std.math.maxInt(u64), 0);
    try huge.append("SSTORE", std.math.maxInt(u64), 0);
    fixture.put(5, huge, 0);
    var driver = ResourceMetering.init(true, &fixture.schedule, &fixture.store);
    driver.begin_build();
    driver.account_unthrottled(hash_of(6), 7, 0);
    const admission = driver.check_simulated(hash_of(5), 0);
    try testing.expectEqual(Decision.calculation_failed, admission.decision);
    try testing.expect(!admission.should_exclude() and !admission.is_permanent());
    const executed = driver.account_executed(0, admission.sample);
    try testing.expectEqual(Decision.calculation_failed, executed);
    driver.account_unthrottled(hash_of(5), 0, 0);
    try testing.expectEqual(@as(u32, 2), driver.build.calculation_failed);
    try testing.expectEqual(@as(u128, 7), driver.cumulative_usage()[0]);
}

// ---------------------------------------------------------------- model check

const hashes_count = 8;

const Model = struct {
    samples: [hashes_count]?Sample = @splat(null),
    cumulative: [2]u128 = @splat(0),
    calculation_failed: u32 = 0,
    throttled: u32 = 0,
    permanent: u32 = 0,
};

fn random_limit(prng: *Prng) u64 {
    if (prng.chance(1, 16)) return std.math.maxInt(u64);
    return prng.range(1, 400_000);
}

fn random_schedule(prng: *Prng, buffer: []u8) ![]const u8 {
    const cpu_block = random_limit(prng);
    const io_block = random_limit(prng);
    return std.fmt.bufPrint(buffer,
        \\{{"version":1,"dimensions":[
        \\{{"name":"cpu","blockLimit":{d},"transactionLimit":{d},"baseGasWeight":{d},
        \\"operations":[{{"name":"SSTORE","gasUsedWeight":{d},"countCost":{d}}}],"dryRun":{}}},
        \\{{"name":"io","blockLimit":{d},"transactionLimit":{d},
        \\"operations":[{{"name":"keccak256","countCost":{d}}}],"dryRun":{}}}]}}
    , .{
        cpu_block,
        prng.range(1, cpu_block),
        prng.range(1, 3),
        prng.below(3),
        if (prng.chance(1, 16)) std.math.maxInt(u64) else prng.range(1, 20_000),
        prng.chance(1, 3),
        io_block,
        prng.range(1, io_block),
        prng.range(1, 5_000),
        prng.chance(1, 3),
    });
}

fn random_sample(prng: *Prng) Sample {
    var sample = Sample.init(prng.range(21_000, 100_000));
    const names = [_][]const u8{ "SSTORE", "sstore", "KECCAK256", "BALANCE", " SSTORE" };
    const rows = prng.below(4);
    for (0..rows) |_| {
        const name = names[prng.below(names.len)];
        const count = if (prng.chance(1, 32)) std.math.maxInt(u64) else prng.below(8);
        sample.append(name, count, prng.below(50_000)) catch unreachable; // 3 rows fit.
    }
    return sample;
}

/// The independent usage of one transaction: actual gas plus the sample's rows.
fn model_usage(schedule: *const Schedule, gas_used: u64, sample: ?Sample, usage: *[2]u128) bool {
    var rows: [metering.sample.observations_max]Observation = undefined;
    const observations: []const Observation = if (sample) |*found|
        found.observations(&rows)
    else
        &.{};
    schedule.evaluate(gas_used, observations, usage) catch return false;
    return true;
}

fn model_add(model: *Model, usage: *const [2]u128) void {
    const cpu = std.math.add(u128, model.cumulative[0], usage[0]) catch {
        model.calculation_failed += 1;
        return;
    };
    const io = std.math.add(u128, model.cumulative[1], usage[1]) catch {
        model.calculation_failed += 1;
        return;
    };
    model.cumulative = .{ cpu, io };
}

fn model_pool(
    model: *Model,
    driver: *ResourceMetering,
    index: usize,
    gas_used: u64,
    now_ns: u64,
) !void {
    const schedule = driver.schedule;
    const admission = driver.check_simulated(hash_of(@intCast(index)), now_ns);
    var usage: [2]u128 = undefined;
    var expected: Decision = .allow;
    if (model.samples[index]) |found| {
        if (model_usage(schedule, found.gas_used, found, &usage)) {
            expected = switch (schedule.check(&usage, &model.cumulative)) {
                .ok => .allow,
                .limit_exceeded => |limit| .{ .throttle = limit },
                .overflow => .calculation_failed,
            };
        } else expected = .calculation_failed;
    }
    try testing.expectEqual(expected, admission.decision);
    if (admission.should_exclude()) {
        model.throttled += 1;
        if (admission.is_permanent()) model.permanent += 1;
        try testing.expect(!admission.decision.throttle.dry_run);
        return;
    }
    _ = driver.account_executed(gas_used, admission.sample);
    if (!model_usage(schedule, gas_used, model.samples[index], &usage)) {
        model.calculation_failed += 1;
        return;
    }
    if (schedule.check(&usage, &model.cumulative) == .overflow) {
        model.calculation_failed += 1;
        return;
    }
    model_add(model, &usage);
}

fn run_model(prng: *Prng) !void {
    var text_buffer: [768]u8 = undefined;
    const text = try random_schedule(prng, &text_buffer);
    const fixture = try Fixture.create(text);
    defer fixture.destroy();
    fixture.store.set_enabled(prng.chance(7, 8));
    var model: Model = .{};
    const insert_ns = prng.below(ttl_ns);
    for (&model.samples, 0..) |*slot, index| {
        if (prng.chance(1, 4)) continue;
        const sample = random_sample(prng);
        fixture.put(@intCast(index), sample, insert_ns);
        if (fixture.store.is_enabled()) slot.* = sample;
    }
    const enabled = prng.chance(7, 8);
    var driver = ResourceMetering.init(enabled, &fixture.schedule, &fixture.store);
    driver.begin_build();
    // Late builds see every sample expired.
    const now_ns = if (prng.chance(1, 8)) insert_ns + ttl_ns else insert_ns;
    if (now_ns >= insert_ns + ttl_ns) model.samples = @splat(null);
    const steps = prng.range(1, 24);
    for (0..steps) |_| {
        const index = prng.below(hashes_count);
        const gas_used = prng.range(21_000, 120_000);
        if (!enabled) {
            const admission = driver.check_simulated(hash_of(@intCast(index)), now_ns);
            try testing.expectEqual(Decision.allow, admission.decision);
            continue;
        }
        if (prng.chance(1, 4)) {
            driver.account_unthrottled(hash_of(@intCast(index)), gas_used, now_ns);
            var usage: [2]u128 = undefined;
            if (model_usage(driver.schedule, gas_used, model.samples[index], &usage)) {
                model_add(&model, &usage);
            } else model.calculation_failed += 1;
        } else try model_pool(&model, &driver, index, gas_used, now_ns);
        try testing.expectEqualSlices(u128, &model.cumulative, driver.cumulative_usage());
    }
    if (!enabled) try testing.expectEqual(@as(u128, 0), driver.cumulative[0]);
    try testing.expectEqual(model.throttled, driver.build.throttled);
    try testing.expectEqual(model.permanent, driver.build.permanent);
    try testing.expectEqual(model.calculation_failed, driver.build.calculation_failed);
}

test "resource: seeded model check" {
    var prng = Prng.init(0x5e50_02ce);
    for (0..256) |_| try run_model(&prng);
}

fn fuzz_resource(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try run_model(&prng);
}

test "resource: fuzz" {
    try testing.fuzz({}, fuzz_resource, .{});
}

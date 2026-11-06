//! Resource-metering schedule tests: base/base `resource_metering.rs` cases (evaluation,
//! limits, validation, JSON shape), then a seeded and a `std.testing.fuzz` model check:
//! random valid schedules are written as JSON (random field order, omitted optionals,
//! whitespace), loaded, and compared with the model; random observations are evaluated and
//! checked against a reference with wide arithmetic; random corruptions must fail with the
//! expected error, and arbitrary bytes must never crash the loader.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const Prng = @import("../../testing/prng.zig").Prng;
const schedule_module = @import("schedule.zig");

const Schedule = schedule_module.Schedule;
const Observation = schedule_module.Observation;
const Decision = schedule_module.Decision;

fn load(text: []const u8) !*Schedule {
    const schedule = try testing.allocator.create(Schedule);
    errdefer testing.allocator.destroy(schedule);
    schedule.* = try Schedule.init(testing.allocator, .{ .rules_max = 64 });
    errdefer schedule.deinit(testing.allocator);
    try schedule.load(text);
    return schedule;
}

fn destroy(schedule: *Schedule) void {
    schedule.deinit(testing.allocator);
    testing.allocator.destroy(schedule);
}

fn expect_load_error(expected: schedule_module.Error, text: []const u8) !void {
    try testing.expectError(expected, load(text));
}

test "schedule: base gas, operation gas and count; names are case-insensitive" {
    const schedule = try load(
        \\{"version":1,"dimensions":[{"name":"execution","blockLimit":1000,
        \\"transactionLimit":500,"baseGasWeight":2,
        \\"operations":[{"name":"SSTORE","gasUsedWeight":3,"countCost":5}],"dryRun":false}]}
    );
    defer destroy(schedule);
    var usage: [1]u128 = undefined;
    const observations = [_]Observation{.{ .name = "sstore", .count = 4, .gas_used = 10 }};
    try schedule.evaluate(100, &observations, &usage);
    try testing.expectEqual(@as(u128, 250), usage[0]);
    // Unknown names are ignored.
    const unknown = [_]Observation{.{ .name = "BALANCE", .count = 9, .gas_used = 9 }};
    try schedule.evaluate(0, &unknown, &usage);
    try testing.expectEqual(@as(u128, 0), usage[0]);
}

test "schedule: count-only prices and one operation in several dimensions" {
    const schedule = try load(
        \\{"version":1,"dimensions":[
        \\{"name":"cpu","blockLimit":100,"operations":[{"name":"CALL","gasUsedWeight":2}],
        \\"dryRun":false},
        \\{"name":"proof","blockLimit":100,"operations":[{"name":"CALL","countCost":3}],
        \\"dryRun":false},
        \\{"name":"new-account","blockLimit":100,"dryRun":false,
        \\"operations":[{"name":"TX_EFFECT_ETH_TRANSFER_TO_NONEXISTENT_ACCOUNT","countCost":25}]}]}
    );
    defer destroy(schedule);
    var usage: [3]u128 = undefined;
    const observations = [_]Observation{
        .{ .name = "CALL", .count = 4, .gas_used = 10 },
        .{ .name = "TX_EFFECT_ETH_TRANSFER_TO_NONEXISTENT_ACCOUNT", .count = 1, .gas_used = 0 },
    };
    try schedule.evaluate(0, &observations, &usage);
    try testing.expectEqualSlices(u128, &.{ 20, 12, 25 }, &usage);
    // Omitted transactionLimit is the block limit.
    try testing.expectEqual(@as(u64, 100), schedule.dimension_list()[0].transaction_limit);
}

test "schedule: transaction and block limits; enforced outranks dry-run" {
    const schedule = try load(
        \\{"version":1,"dimensions":[
        \\{"name":"observed","blockLimit":10,"baseGasWeight":1,"dryRun":true},
        \\{"name":"cpu","blockLimit":100,"transactionLimit":30,"baseGasWeight":1,"dryRun":false}]}
    );
    defer destroy(schedule);
    var usage: [2]u128 = undefined;
    // 40 > 30: transaction scope on cpu, permanent; the dry-run overrun ranks lower.
    var decision = schedule.decide(40, &.{}, &.{}, &usage);
    try testing.expectEqual(schedule_module.Scope.transaction, decision.throttle.scope);
    try testing.expectEqual(@as(u8, 1), decision.throttle.dimension);
    try testing.expect(decision.should_exclude() and decision.is_permanent());
    // 5 fits a transaction but not a block holding 96: block scope, not permanent.
    decision = schedule.decide(5, &.{}, &.{ 0, 96 }, &usage);
    try testing.expectEqual(schedule_module.Scope.block, decision.throttle.scope);
    try testing.expectEqual(@as(u128, 101), decision.throttle.used);
    try testing.expect(decision.should_exclude() and !decision.is_permanent());
    // Only the dry-run dimension is over: observed, included, usage counts.
    decision = schedule.decide(20, &.{}, &.{}, &usage);
    try testing.expect(decision.throttle.dry_run);
    try testing.expect(!decision.should_exclude() and decision.has_usage());
    decision = schedule.decide(5, &.{}, &.{}, &usage);
    try testing.expectEqual(Decision.allow, decision);
}

test "schedule: enforced transaction scope is not masked by an earlier block scope" {
    const schedule = try load(
        \\{"version":1,"dimensions":[
        \\{"name":"a","blockLimit":100,"baseGasWeight":1,"dryRun":false},
        \\{"name":"b","blockLimit":100,"transactionLimit":10,"baseGasWeight":1,"dryRun":false}]}
    );
    defer destroy(schedule);
    var usage: [2]u128 = undefined;
    const decision = schedule.decide(20, &.{}, &.{ 90, 0 }, &usage);
    try testing.expectEqual(schedule_module.Scope.transaction, decision.throttle.scope);
    try testing.expectEqual(@as(u8, 1), decision.throttle.dimension);
}

test "schedule: overflow fails open; add_usage is atomic" {
    const max = std.math.maxInt(u64);
    var text_buffer: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&text_buffer,
        \\{{"version":1,"dimensions":[{{"name":"overflow","blockLimit":{d},"baseGasWeight":{d},
        \\"operations":[{{"name":"CALL","gasUsedWeight":{d}}}],"dryRun":false}}]}}
    , .{ max, max, max });
    const schedule = try load(text);
    defer destroy(schedule);
    var usage: [1]u128 = undefined;
    const observations = [_]Observation{.{ .name = "CALL", .count = 1, .gas_used = max }};
    try testing.expectError(error.Overflow, schedule.evaluate(max, &observations, &usage));
    const decision = schedule.decide(max, &observations, &.{}, &usage);
    try testing.expectEqual(Decision.calculation_failed, decision);
    try testing.expect(!decision.should_exclude() and !decision.has_usage());
    var cumulative = [2]u128{ 1, std.math.maxInt(u128) };
    try testing.expectError(error.Overflow, schedule_module.add_usage(&cumulative, &.{ 5, 1 }));
    try testing.expectEqualSlices(u128, &.{ 1, std.math.maxInt(u128) }, &cumulative);
    try schedule_module.add_usage(&cumulative, &.{ 5, 0 });
    try testing.expectEqual(@as(u128, 6), cumulative[0]);
}

test "schedule: validation errors" {
    try expect_load_error(error.DuplicateDimension,
        \\{"version":1,"dimensions":[{"name":"CPU","blockLimit":100,"baseGasWeight":1,
        \\"dryRun":false},{"name":"cpu","blockLimit":100,"baseGasWeight":1,"dryRun":false}]}
    );
    try expect_load_error(error.NoopOperation,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":100,
        \\"operations":[{"name":"CALL"}],"dryRun":false}]}
    );
    try expect_load_error(error.NoopDimension,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":100,"dryRun":false}]}
    );
    try expect_load_error(error.NoopDimension,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":100,"transactionLimit":0,
        \\"baseGasWeight":1,"dryRun":false}]}
    );
    try expect_load_error(error.TransactionLimitExceedsBlock,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":10,"transactionLimit":11,
        \\"baseGasWeight":1,"dryRun":false}]}
    );
    try expect_load_error(error.ZeroBlockLimit,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":0,"baseGasWeight":1,
        \\"dryRun":false}]}
    );
    try expect_load_error(error.DuplicateOperation,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":9,"dryRun":false,"operations":
        \\[{"name":"call","countCost":1},{"name":"CALL","countCost":2}]}]}
    );
    try expect_load_error(error.UnsupportedVersion, "{\"version\":2}");
    try expect_load_error(error.EmptyDimensionName,
        \\{"version":1,"dimensions":[{"name":"  ","blockLimit":9,"baseGasWeight":1,
        \\"dryRun":false}]}
    );
    try expect_load_error(error.InvalidName,
        \\{"version":1,"dimensions":[{"name":"c pu","blockLimit":9,"baseGasWeight":1,
        \\"dryRun":false}]}
    );
    // U+00A0 (no-break space) is whitespace to Rust `char::is_whitespace`.
    try expect_load_error(error.InvalidName,
        \\{"version":1,"dimensions":[{"name":"cpu\u00a0","blockLimit":9,"baseGasWeight":1,
        \\"dryRun":false}]}
    );
}

test "schedule: JSON shape" {
    // dryRun is required; unknown and duplicate fields are rejected; integers only.
    try expect_load_error(error.ParseJson,
        \\{"version":1,"dimensions":[{"name":"cpu","blockLimit":9,"baseGasWeight":1}]}
    );
    try expect_load_error(error.ParseJson, "{\"version\":1,\"unknownField\":true}");
    try expect_load_error(error.ParseJson, "{\"version\":1,\"version\":1}");
    try expect_load_error(error.ParseJson, "{\"version\":1.0}");
    try expect_load_error(error.ParseJson, "{\"version\":-1}");
    try expect_load_error(error.ParseJson, "{\"dimensions\":[]}");
    try expect_load_error(error.ParseJson, "{\"version\":1} {}");
    const empty = try load("{\"version\":1,\"dimensions\":[]}");
    defer destroy(empty);
    try testing.expect(empty.is_empty());
    const state = try load(
        \\{"version":1,"dimensions":[{"name":"state_updates","blockLimit":800,"dryRun":false,
        \\"transactionLimit":null,"operations":[{"name":"state_changed_storage_slot",
        \\"countCost":25}]}]}
    );
    defer destroy(state);
    const priced = [_]bool{ false, true, false, false, false };
    try testing.expectEqualSlices(bool, &priced, &state.priced_state);
    try testing.expectEqual(@as(u64, 800), state.dimension_list()[0].transaction_limit);
}

// ---- Model check -------------------------------------------------------------------------

const operation_names = [_][]const u8{
    "SSTORE", "SLOAD", "CALL", "KECCAK256", "STATE_NEW_STORAGE_SLOT", "STATE_TOUCHED_ACCOUNT",
};

const ModelOperation = struct { name: u8, gas_used_weight: u64, count_cost: u64 };

const ModelDimension = struct {
    block_limit: u64,
    transaction_limit: ?u64,
    base_gas_weight: u64,
    dry_run: bool,
    operations: [operation_names.len]ModelOperation = undefined,
    operation_count: u8 = 0,

    fn transaction_limit_value(dimension: *const ModelDimension) u64 {
        return dimension.transaction_limit orelse dimension.block_limit;
    }
};

const Model = struct {
    dimensions: [6]ModelDimension = undefined,
    count: u8 = 0,
};

fn small_or_huge(prng: *Prng) u64 {
    if (prng.chance(1, 16)) return std.math.maxInt(u64) - prng.below(4);
    return prng.below(1_000);
}

fn random_model(prng: *Prng) Model {
    var model: Model = .{};
    model.count = @intCast(prng.below(model.dimensions.len + 1));
    for (model.dimensions[0..model.count]) |*dimension| {
        const block_limit = @max(1, small_or_huge(prng));
        dimension.* = .{
            .block_limit = block_limit,
            .transaction_limit = if (prng.chance(1, 2)) null else 1 + prng.below(block_limit),
            .base_gas_weight = prng.below(4),
            .dry_run = prng.chance(1, 3),
        };
        // Distinct operation names: a random subset in order.
        for (operation_names, 0..) |_, name| {
            if (!prng.chance(1, 3)) continue;
            dimension.operations[dimension.operation_count] = .{
                .name = @intCast(name),
                .gas_used_weight = small_or_huge(prng) * @intFromBool(prng.chance(1, 2)),
                .count_cost = 1 + prng.below(50),
            };
            dimension.operation_count += 1;
        }
        if (dimension.operation_count == 0 and dimension.base_gas_weight == 0) {
            dimension.base_gas_weight = 1;
        }
    }
    return model;
}

/// Writes `model` as a schedule file; the casing of operation names is random.
fn write_model(prng: *Prng, model: *const Model, out: *std.Io.Writer) !void {
    try out.writeAll("{ \"dimensions\" : [");
    for (model.dimensions[0..model.count], 0..) |*dimension, index| {
        if (index > 0) try out.writeAll(",");
        try out.print("{{\"name\":\"dim{d}\",", .{index});
        try out.print("\"blockLimit\":{d},", .{dimension.block_limit});
        if (dimension.transaction_limit) |limit| {
            try out.print("\"transactionLimit\":{d},", .{limit});
        }
        if (dimension.base_gas_weight != 0 or prng.chance(1, 2)) {
            try out.print("\"baseGasWeight\":{d},", .{dimension.base_gas_weight});
        }
        try out.writeAll("\"operations\":[");
        for (dimension.operations[0..dimension.operation_count], 0..) |operation, op_index| {
            if (op_index > 0) try out.writeAll(",");
            var name_buffer: [operation_names[0].len + 32]u8 = undefined;
            const name = operation_names[operation.name];
            for (name, 0..) |byte, i| {
                name_buffer[i] = if (prng.chance(1, 2)) std.ascii.toLower(byte) else byte;
            }
            try out.print("{{\"countCost\":{d},\"name\":\"{s}\"", .{
                operation.count_cost, name_buffer[0..name.len],
            });
            if (operation.gas_used_weight != 0) {
                try out.print(",\"gasUsedWeight\":{d}", .{operation.gas_used_weight});
            }
            try out.writeAll("}");
        }
        try out.print("],\"dryRun\":{}}}", .{dimension.dry_run});
    }
    try out.writeAll("] ,\n\"version\": 1 }");
}

/// Reference usage with wide arithmetic; null on any u128 overflow.
fn model_usage(
    model: *const Model,
    gas_used: u64,
    observations: []const Observation,
    usage: []u128,
) bool {
    for (model.dimensions[0..model.count], 0..) |*dimension, index| {
        var total: u256 = @as(u256, dimension.base_gas_weight) * gas_used;
        for (observations) |observation| {
            for (dimension.operations[0..dimension.operation_count]) |operation| {
                const name = operation_names[operation.name];
                if (!std.ascii.eqlIgnoreCase(name, observation.name)) continue;
                total += @as(u256, operation.gas_used_weight) * observation.gas_used;
                total += @as(u256, operation.count_cost) * observation.count;
            }
        }
        if (total > std.math.maxInt(u128)) return false;
        usage[index] = @intCast(total);
    }
    return true;
}

/// Reference decision: enforced transaction scope, then enforced block, then dry-run.
fn model_decision(model: *const Model, usage: []const u128, cumulative: []const u128) Decision {
    var best: ?schedule_module.LimitExceeded = null;
    var best_rank: u8 = 3;
    for (model.dimensions[0..model.count], 0..) |*dimension, index| {
        const cost = usage[index];
        const transaction_limit = dimension.transaction_limit_value();
        const block_used = @as(u256, cumulative[index]) + cost;
        if (cost <= transaction_limit and block_used > std.math.maxInt(u128)) {
            return .calculation_failed;
        }
        const scope: schedule_module.Scope = if (cost > transaction_limit) .transaction else .block;
        if (scope == .block and block_used <= dimension.block_limit) continue;
        const rank: u8 = if (dimension.dry_run) 2 else if (scope == .transaction) 0 else 1;
        if (rank >= best_rank) continue;
        best_rank = rank;
        best = .{
            .dimension = @intCast(index),
            .scope = scope,
            .used = if (scope == .transaction) cost else @intCast(block_used),
            .transaction_cost = cost,
            .limit = if (scope == .transaction) transaction_limit else dimension.block_limit,
            .dry_run = dimension.dry_run,
        };
    }
    const exceeded = best orelse return .allow;
    return .{ .throttle = exceeded };
}

fn check_model(prng: *Prng, schedule: *Schedule) !void {
    const model = random_model(prng);
    var text_buffer: [16 << 10]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&text_buffer);
    try write_model(prng, &model, &writer);
    try schedule.load(writer.buffered());
    const dimensions = schedule.dimension_list();
    try testing.expectEqual(@as(usize, model.count), dimensions.len);
    for (model.dimensions[0..model.count], dimensions) |*expected, actual| {
        try testing.expectEqual(expected.block_limit, actual.block_limit);
        try testing.expectEqual(expected.transaction_limit_value(), actual.transaction_limit);
        try testing.expectEqual(expected.dry_run, actual.dry_run);
    }
    for (0..8) |_| {
        var observations: [4]Observation = undefined;
        for (&observations) |*observation| observation.* = .{
            .name = operation_names[prng.below(operation_names.len)],
            .count = small_or_huge(prng),
            .gas_used = small_or_huge(prng),
        };
        const used = observations[0..prng.below(observations.len + 1)];
        const gas_used = small_or_huge(prng);
        var cumulative: [6]u128 = undefined;
        for (&cumulative) |*value| {
            const near_max = prng.chance(1, 8);
            const offset: u128 = prng.below(if (near_max) 4 else 2_000);
            value.* = if (near_max) std.math.maxInt(u128) - offset else offset;
        }
        var expected_usage: [6]u128 = undefined;
        var usage: [6]u128 = undefined;
        const expected: Decision = if (model_usage(&model, gas_used, used, &expected_usage))
            model_decision(&model, &expected_usage, &cumulative)
        else
            .calculation_failed;
        const decision = schedule.decide(gas_used, used, &cumulative, &usage);
        try testing.expectEqualDeep(expected, decision);
        if (decision.has_usage()) {
            const count = model.count;
            try testing.expectEqualSlices(u128, expected_usage[0..count], usage[0..count]);
        }
    }
}

/// A valid schedule with one corruption; returns the error the loader must report.
const Expected = struct { failure: schedule_module.Error };

fn corrupt(prng: *Prng, out: *std.Io.Writer) !Expected {
    const kind = prng.below(6);
    const head = "{\"version\":1,\"dimensions\":[{\"name\":\"cpu\",";
    switch (kind) {
        0 => try out.writeAll(head ++ "\"blockLimit\":5,\"baseGasWeight\":1}]}"),
        1 => try out.writeAll(head ++ "\"blockLimit\":5,\"blockLimit\":5,\"dryRun\":true}]}"),
        2 => try out.writeAll(head ++ "\"blockLimit\":\"5\",\"dryRun\":true}]}"),
        3 => {
            try out.writeAll(head);
            try out.print("\"blockLimit\":5,\"transactionLimit\":{d},", .{6 + prng.below(100)});
            try out.writeAll("\"baseGasWeight\":1,\"dryRun\":true}]}");
        },
        4 => try out.print("{{\"version\":{d}}}", .{2 + prng.below(1000)}),
        else => try out.writeAll(head ++ "\"blockLimit\":5,\"dryRun\":false}]}"),
    }
    const expected = [_]schedule_module.Error{
        error.ParseJson,
        error.ParseJson,
        error.ParseJson,
        error.TransactionLimitExceedsBlock,
        error.UnsupportedVersion,
        error.NoopDimension,
    };
    return .{ .failure = expected[kind] };
}

fn check_random(prng: *Prng, schedule: *Schedule) !void {
    try check_model(prng, schedule);
    var text_buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&text_buffer);
    const expected = try corrupt(prng, &writer);
    try testing.expectError(expected.failure, schedule.load(writer.buffered()));
    try testing.expect(schedule.is_empty());
    // Arbitrary bytes (half of them mutations of a valid file) never crash the loader.
    var bytes: [128]u8 = undefined;
    const valid = "{\"version\":1,\"dimensions\":[{\"name\":\"a\",\"blockLimit\":9," ++
        "\"operations\":[{\"name\":\"CALL\",\"countCost\":1}],\"dryRun\":false}]}";
    var length: usize = valid.len;
    if (prng.chance(1, 2)) {
        @memcpy(bytes[0..valid.len], valid);
        for (0..1 + prng.below(3)) |_| bytes[prng.below(valid.len)] = @truncate(prng.below(256));
    } else {
        length = prng.below(bytes.len);
        prng.fill(bytes[0..length]);
    }
    schedule.load(bytes[0..length]) catch return;
    try testing.expect(schedule.dimension_list().len <= schedule_module.dimensions_max);
}

test "schedule: seeded model check" {
    var schedule = try Schedule.init(testing.allocator, .{ .rules_max = 64 });
    defer schedule.deinit(testing.allocator);
    var prng = Prng.init(0x5c4ed);
    for (0..500) |_| try check_random(&prng, &schedule);
}

fn fuzz_schedule(schedule: *Schedule, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try check_random(&prng, schedule);
}

test "schedule: fuzz" {
    var schedule = try Schedule.init(testing.allocator, .{ .rules_max = 64 });
    defer schedule.deinit(testing.allocator);
    try testing.fuzz(&schedule, fuzz_schedule, .{});
}

comptime {
    assert(operation_names.len <= schedule_module.operations_per_dimension_max);
}

//! Tests of `basectl denim` over the fake transport (hash pinning, schedule states, cadence
//! failures), plus a `std.testing.fuzz` target and a seeded fuzz for the JSON field checks
//! and the pure evaluation.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const testing = std.testing;
const types = @import("types.zig");
const denim = @import("denim.zig");
const denim_fetch = @import("denim_fetch.zig");
const FakeTransport = @import("fake.zig").FakeTransport;
const Prng = @import("../../testing/prng.zig").Prng;

const Answer = FakeTransport.Answer;

fn hash_of(number: u64) [32]u8 {
    var hash: [32]u8 = @splat(0xab);
    std.mem.writeInt(u64, hash[24..32], number, .big);
    return hash;
}

fn print(arena: std.mem.Allocator, comptime format: []const u8, args: anytype) []const u8 {
    return std.fmt.allocPrint(arena, format, args) catch @panic("oom");
}

fn hex32(arena: std.mem.Allocator, bytes: [32]u8) []const u8 {
    return print(arena, "0x{x}", .{&bytes});
}

/// A full block whose tx[1] is a BaseTime deposit for `timestamp_ms` (none when legacy).
fn block_json(arena: std.mem.Allocator, number: u64, timestamp_ms: u64) []const u8 {
    var deposit_buffer: [1024]u8 = undefined;
    const part: u16 = @intCast(timestamp_ms % 1_000);
    const second = denim.sample_deposit_json(&deposit_buffer, number, part);
    const format =
        \\{{"number":"0x{x}","hash":"{s}","parentHash":"{s}","timestamp":"0x{x}",
        \\"timestampMs":"0x{x}","transactions":[{{"type":"0x7e","hash":"0x{x}"}},{s}]}}
    ;
    return print(arena, format, .{
        number,
        hex32(arena, hash_of(number)),
        hex32(arena, hash_of(number - 1)),
        timestamp_ms / 1_000,
        timestamp_ms,
        &@as([32]u8, @splat(0x10)),
        second,
    });
}

fn word_json(arena: std.mem.Allocator, word: [32]u8) []const u8 {
    return print(arena, "\"0x{x}\"", .{&word});
}

const tx_hash_hex = "0x" ++ denim.repeat("11", 32);

/// A log, receipt, or transaction pinned to block 100 at index 1.
fn pinned_object(arena: std.mem.Allocator, extra: []const u8) []const u8 {
    const format = "{{\"blockHash\":\"{s}\",\"blockNumber\":\"0x64\"," ++
        "\"transactionIndex\":\"0x1\",\"transactionHash\":\"" ++ tx_hash_hex ++
        "\",\"hash\":\"" ++ tx_hash_hex ++ "\"{s}}}";
    return print(arena, format, .{ hex32(arena, hash_of(100)), extra });
}

fn stamped(arena: std.mem.Allocator, timestamp_ms: u64) []const u8 {
    const field = print(arena, ",\"blockTimestampMs\":\"0x{x}\"", .{timestamp_ms});
    return pinned_object(arena, field);
}

const Scenario = struct {
    activation: u64 = 0,
    /// Millisecond timestamp of block 99 (the cadence parent of block 100 at 50_400).
    parent_ms: u64 = 50_200,
    /// `blockTimestampMs` served by `eth_getTransactionByBlockNumberAndIndex`.
    tx_by_number_ms: u64 = 50_401,
};

const timestamp_ms_word = "\"0x" ++ denim.repeat("0", 60) ++ "c4e0\"";
const proxy_file = @embedFile("../../batcher/devnet/base_time_proxy.hex");
const proxy_result = "\"0x" ++ std.mem.trimEnd(u8, proxy_file, "\n") ++ "\"";

/// The snapshot (block 100) answers: its block, state pinned to its hash, and getters.
fn state_answers(arena: std.mem.Allocator, scenario: Scenario) [12]Answer {
    const pin = print(arena, "{{\"blockHash\":\"{s}\"}}", .{hex32(arena, hash_of(100))});
    const snapshot = block_json(arena, 100, 50_400);
    const code = @import("../../execution/node/base_time.zig").implementation_code;
    var millis_word: [32]u8 = @splat(0);
    millis_word[30] = 0x01;
    millis_word[31] = 0x90;
    const config = "{{\"l2_chain_id\":1,\"base\":{{\"denim\":{d}}}}}";
    const logs = print(arena, "[{s}]", .{stamped(arena, 50_400)});
    const receipt_fields = print(arena, ",\"status\":\"0x1\",\"logs\":{s}", .{logs});
    const receipt = pinned_object(arena, receipt_fields);
    const first_format = "{{\"blockHash\":\"{s}\",\"blockNumber\":\"0x64\",\"logs\":[]}}";
    const first = print(arena, first_format, .{hex32(arena, hash_of(100))});
    const admin = denim.address_word(denim.proxy_admin);
    const linked = denim.address_word(denim.implementation_address);
    return .{
        .{
            .method = "optimism_rollupConfig",
            .result = print(arena, config, .{scenario.activation}),
        },
        .{ .method = "eth_getBlockByNumber", .result = snapshot, .once = true },
        .{ .method = "eth_getBlockByHash", .result = snapshot, .once = true },
        .{ .method = "eth_getCode", .result = proxy_result, .once = true, .body_contains = pin },
        .{
            .method = "eth_getCode",
            .result = print(arena, "\"0x{x}\"", .{&code}),
            .body_contains = pin,
        },
        .{
            .method = "eth_getStorageAt",
            .result = word_json(arena, admin),
            .once = true,
            .body_contains = pin,
        },
        .{
            .method = "eth_getStorageAt",
            .result = word_json(arena, linked),
            .once = true,
            .body_contains = pin,
        },
        .{
            .method = "eth_getStorageAt",
            .result = word_json(arena, millis_word),
            .body_contains = pin,
        },
        .{
            .method = "eth_getBlockReceipts",
            .result = print(arena, "[{s},{s}]", .{ first, receipt }),
        },
        .{
            .method = "eth_call",
            .result = word_json(arena, millis_word),
            .body_contains = "7b2fea99",
        },
        .{
            .method = "eth_call",
            .result = timestamp_ms_word,
            .body_contains = "5745a677",
        },
        .{ .method = "eth_getTransactionReceipt", .result = receipt },
    };
}

/// Cadence parents, wire objects, and log answers.
fn wire_answers(arena: std.mem.Allocator, scenario: Scenario) [12]Answer {
    const snapshot = block_json(arena, 100, 50_400);
    const logs = print(arena, "[{s}]", .{stamped(arena, 50_400)});
    const parent = block_json(arena, 99, scenario.parent_ms);
    const grandparent = block_json(arena, 98, 50_000);
    return .{
        .{
            .method = "eth_getBlockByHash",
            .result = parent,
            .body_contains = hex32(arena, hash_of(99)),
        },
        .{
            .method = "eth_getBlockByHash",
            .result = grandparent,
            .body_contains = hex32(arena, hash_of(98)),
        },
        .{ .method = "eth_getBlockByHash", .result = snapshot },
        .{ .method = "eth_getBlockByNumber", .result = snapshot },
        .{ .method = "eth_getTransactionByHash", .result = stamped(arena, 50_400) },
        .{ .method = "eth_getTransactionByBlockHashAndIndex", .result = stamped(arena, 50_400) },
        .{
            .method = "eth_getTransactionByBlockNumberAndIndex",
            .result = stamped(arena, scenario.tx_by_number_ms),
        },
        .{ .method = "eth_getLogs", .result = logs },
        .{ .method = "eth_newFilter", .result = "\"0x1\"" },
        .{ .method = "eth_getFilterChanges", .result = logs },
        .{ .method = "eth_getFilterLogs", .result = logs },
        .{ .method = "eth_uninstallFilter", .result = "true" },
    };
}

fn active_answers(arena: std.mem.Allocator, scenario: Scenario) []const Answer {
    const answers = arena.alloc(Answer, 24) catch @panic("oom");
    answers[0..12].* = state_answers(arena, scenario);
    answers[12..24].* = wire_answers(arena, scenario);
    return answers;
}

fn run(answers: []const Answer, rollup: bool, options: denim_fetch.Options) Fetched {
    var fake: FakeTransport = .{ .answers = answers };
    var client = fake.client(testing.allocator) catch @panic("oom");
    defer client.deinit(testing.allocator);
    const context: types.Context = .{
        .l2 = .{ .client = &client },
        .rollup = .{ .client = if (rollup) &client else null },
    };
    return denim_fetch.fetch(&context, options);
}

const Fetched = types.Fetched(denim.Report);

fn status(report: *denim.Report, name: []const u8) denim.Status {
    return report.find(name).?.status;
}

test "denim fetch: active snapshot pins state reads and checks every dimension" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const answers = active_answers(arena_state.allocator(), .{});
    var report = run(answers, true, .{ .cadence_blocks = 2 }).ok;
    try testing.expectEqual(denim.Schedule.active, report.schedule);
    try testing.expectEqual(@as(u64, 100), report.block_number);
    try testing.expectEqual(@as(u16, 22), report.checks.count);
    const implementation = report.find("implementation").?.observed.slice();
    try testing.expectEqualStrings("LinkedInitial", implementation);
    for (report.checks.slice()[0..9]) |check| {
        errdefer std.debug.print("{s}: {s}\n", .{ check.name, check.observed.slice() });
        try testing.expectEqual(denim.Status.pass, check.status);
    }
    try testing.expectEqual(denim.Status.pass, status(&report, denim.cadence_check));
    try testing.expectEqualStrings(
        "exact +200ms progression (2 edges checked)",
        report.find(denim.cadence_check).?.observed.slice(),
    );
    // Headers are not served: indeterminate with the reason, not a failure.
    try testing.expectEqual(denim.Status.indeterminate, status(&report, denim.wire_checks[2]));
    const header = report.find(denim.wire_checks[3]).?.observed.slice();
    try testing.expect(std.mem.startsWith(u8, header, "method not served"));
    try testing.expectEqual(denim.Status.pass, status(&report, denim.wire_checks[0]));
    try testing.expectEqual(denim.Status.pass, status(&report, denim.wire_checks[1]));
    try testing.expectEqual(denim.Status.pass, status(&report, denim.wire_checks[4]));
    // The by-number-and-index answer carries a timestamp 1 ms off.
    try testing.expectEqual(denim.Status.fail, status(&report, denim.wire_checks[6]));
    for (denim.log_checks) |name| try testing.expectEqual(denim.Status.pass, status(&report, name));
    var buffer: [8192]u8 = undefined;
    var writer: types.Writer = .fixed(&buffer);
    try denim.render(&report, &writer);
    const text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "schedule              active\n") != null);
}

test "denim fetch: unpinned state reads fail the command" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const answers = active_answers(arena, .{});
    // Serve the snapshot as block 101's hash: the code read pinned to it is not answered.
    var moved = arena.dupe(Answer, answers) catch @panic("oom");
    moved[2].result = block_json(arena, 101, 50_600);
    moved[1].result = moved[2].result;
    const fetched = run(moved, true, .{});
    try testing.expectEqualStrings("eth_getCode(BaseTime proxy)", fetched.failed.what);
    try testing.expectEqual(types.Failure.unavailable, fetched.failed.failure);
}

test "denim fetch: wrong cadence gap fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const answers = active_answers(arena_state.allocator(), .{ .parent_ms = 50_000 });
    var report = run(answers, true, .{ .cadence_blocks = 2 }).ok;
    try testing.expectEqual(denim.Status.fail, status(&report, denim.cadence_check));
    try testing.expect(report.has_failures());
}

test "denim fetch: scheduled and unscheduled snapshots never fail" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // The snapshot carries a wrong tx timestamp: before activation it is not a failure.
    const answers = active_answers(arena_state.allocator(), .{ .activation = 1_000_000 });
    var scheduled = run(answers, true, .{}).ok;
    try testing.expectEqual(denim.Schedule.scheduled, scheduled.schedule);
    try testing.expectEqual(@as(u16, 3 + 1 + 12), scheduled.checks.count);
    try testing.expectEqual(denim.Status.indeterminate, status(&scheduled, denim.cadence_check));
    for (denim.object_checks) |name| {
        try testing.expectEqual(denim.Status.indeterminate, status(&scheduled, name));
    }
    for (denim.log_checks) |name| {
        try testing.expectEqual(denim.Status.indeterminate, status(&scheduled, name));
    }
    try testing.expect(!scheduled.has_failures());
    const unscheduled = run(answers, false, .{}).ok;
    try testing.expectEqual(denim.Schedule.not_scheduled, unscheduled.schedule);
    try testing.expectEqual(@as(?u64, null), unscheduled.activation);
}

test "denim fetch: unreachable endpoints fail the command" {
    var fake: FakeTransport = .{ .answers = &.{}, .transport_down = true };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const both: types.Context = .{ .l2 = .{ .client = &client }, .rollup = .{ .client = &client } };
    const fetched = denim_fetch.fetch(&both, .{});
    try testing.expectEqual(types.Failure.transport, fetched.failed.failure);
    const no_l2: types.Context = .{};
    const unconfigured = denim_fetch.fetch(&no_l2, .{});
    try testing.expectEqual(types.Failure.not_configured, unconfigured.failed.failure);
}

test "denim fetch: activation, words, and code hashes decode" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const parse = struct {
        fn value(allocator: std.mem.Allocator, text: []const u8) json.Value {
            const options: json.ParseOptions = .{};
            return json.parseFromSliceLeaky(json.Value, allocator, text, options) catch
                @panic("bad json");
        }
    }.value;
    const decode = denim_fetch.decode_activation;
    const scheduled = parse(arena, "{\"base\":{\"denim\":\"0x7\"}}");
    try testing.expectEqual(@as(?u64, 7), try decode(scheduled));
    try testing.expectEqual(@as(?u64, null), try decode(parse(arena, "{\"base\":{}}")));
    try testing.expectEqual(@as(?u64, null), try denim_fetch.decode_activation(parse(arena, "{}")));
    var slot_buffer: [66]u8 = undefined;
    const zero: [32]u8 = @splat(0);
    try testing.expectEqualStrings("0x0", denim_fetch.slot_quantity(&slot_buffer, zero));
    const slot = denim_fetch.slot_quantity(&slot_buffer, denim.implementation_slot);
    try testing.expectEqualStrings("0x360894a1", slot[0..10]);
    try testing.expectEqual(@as(usize, 66), slot.len);
    const word = try denim_fetch.decode_word(parse(arena, "\"0x1c8\""));
    try testing.expectEqual(@as(u16, 0x1c8), denim.decode_millis_part(word));
    const long = parse(arena, "\"0x" ++ denim.repeat("0", 65) ++ "\"");
    try testing.expectError(error.MalformedResponse, denim_fetch.decode_word(long));
    const empty = try denim_fetch.hash_code(parse(arena, "\"0x\""));
    const keccak = @import("../../common/crypto/keccak.zig");
    try testing.expectEqualSlices(u8, &keccak.empty_digest, &empty);
    const odd = parse(arena, "\"0x1\"");
    try testing.expectError(error.MalformedResponse, denim_fetch.hash_code(odd));
}

// ------------------------------------------------------------------------- fuzz

/// Runs every JSON-facing check on `text`; never crashes, statuses stay in range.
fn exercise_json(text: []const u8) void {
    var memory: [128 * 1024]u8 = undefined;
    var arena: std.heap.FixedBufferAllocator = .init(&memory);
    const value = json.parseFromSliceLeaky(json.Value, arena.allocator(), text, .{
        .duplicate_field_behavior = .use_last,
    }) catch return;
    var report = denim.evaluate(&denim.sample_observations(null, 1));
    const hash: [32]u8 = @splat(0x42);
    const identity = [_]denim.Identity{
        .{ .field = "hash", .expected = .{ .hash = hash } },
        .{ .field = "number", .expected = .{ .quantity = 1 } },
    };
    const outcome: denim.Outcome = .{ .value = value };
    denim.check_wire_object(&report, "object", outcome, "timestampMs", 10_000, &identity);
    denim.check_wire_logs(&report, "logs", .{ .value = value }, 10_000, hash);
    assert(report.checks.count == 5);
    // A pass requires the exact field value.
    if (report.find("object").?.status == .pass) {
        assert(denim.string_quantity(value, "timestampMs") == 10_000);
    }
    if (report.find("logs").?.status == .pass) {
        assert(value == .array and value.array.items.len > 0);
    }
    _ = denim.metadata_from_json(value, 1) catch {};
    _ = denim_fetch.parse_block(value, 1);
    _ = denim_fetch.decode_activation(value) catch {};
    _ = denim_fetch.decode_word(value) catch {};
    _ = denim_fetch.hash_code(value) catch {};
}

fn fuzz_json_checks(_: void, smith: *testing.Smith) anyerror!void {
    var text: [2048]u8 = undefined;
    const length = smith.slice(&text);
    exercise_json(text[0..length]);
}

test "denim fuzz: json field checks on arbitrary input" {
    try testing.fuzz({}, fuzz_json_checks, .{});
}

const hash_fragment = "\"0x" ++ denim.repeat("42", 32) ++ "\"";

const fragments = [_][]const u8{
    "{",                    "}",             "[",          "]",
    ",",                    ":",             "null",       "true",
    "\"0x2710\"",           "\"0x02710\"",   "\"0x\"",     "\"timestampMs\"",
    "\"hash\"",             "\"blockHash\"", "\"number\"", "\"0x1\"",
    "\"blockTimestampMs\"", "\"type\"",      "\"0x7e\"",   "\"input\"",
    "\"transactions\"",     hash_fragment,   "\"base\"",   "\"denim\"",
    "7",
};

fn generate_json(prng: *Prng, buffer: []u8) []const u8 {
    var writer: types.Writer = .fixed(buffer);
    const count = prng.range(1, 48);
    for (0..count) |_| writer.writeAll(fragments[prng.below(fragments.len)]) catch break;
    return writer.buffered();
}

/// Random observations: canonical by default, each field perturbed with some chance.
fn generate_observations(prng: *Prng) denim.Observations {
    const timestamp = prng.int(u64);
    const activation: ?u64 = if (prng.chance(1, 4)) null else prng.int(u64);
    var input = denim.sample_observations(activation, timestamp);
    if (prng.chance(1, 6)) input.proxy_code_hash[prng.below(32)] ^= 1;
    if (prng.chance(1, 6)) input.admin[prng.below(32)] ^= 1;
    if (prng.chance(1, 6)) input.implementation[prng.below(32)] ^= 1;
    if (prng.chance(1, 6)) input.implementation_code_hash = null;
    if (prng.chance(1, 6)) input.storage_millis_part = @intCast(prng.below(1_000));
    if (prng.chance(1, 6)) input.metadata = .{ .failed = denim.note("x", .{}) };
    if (prng.chance(1, 6)) input.metadata_receipt_valid = prng.chance(1, 2);
    if (prng.chance(1, 6)) input.getter_millis_part = .none;
    if (prng.chance(1, 6)) input.getter_timestamp_ms = .{ .ok = prng.int(u64) };
    if (prng.chance(1, 6)) input.timestamp_ms = null;
    return input;
}

test "denim fuzz: seeded evaluation and json checks" {
    var prng = Prng.init(0xde41);
    var buffer: [2048]u8 = undefined;
    var failures: u32 = 0;
    for (0..3000) |_| {
        exercise_json(generate_json(&prng, &buffer));
        const input = generate_observations(&prng);
        const report = denim.evaluate(&input);
        // Before activation nothing fails; only an active snapshot has the metadata checks.
        if (report.schedule != .active) {
            try testing.expect(!report.has_failures());
            try testing.expectEqual(@as(u16, 3), report.checks.count);
        } else {
            try testing.expectEqual(@as(u16, 9), report.checks.count);
        }
        failures += @intFromBool(report.has_failures());
        var blocks: [8]denim.BlockFacts = undefined;
        for (&blocks, 0..) |*block, index| block.* = .{
            .number = 100 - index,
            .hash = @splat(@intCast(100 - index)),
            .parent_hash = @splat(@intCast(99 - index)),
            .timestamp = prng.range(0, 3),
            .timestamp_ms = if (prng.chance(1, 8)) null else prng.range(0, 3_000),
        };
        const cadence = denim.evaluate_cadence(prng.range(0, 3), &blocks, prng.chance(3, 4));
        try testing.expect(cadence.status != .pass or cadence.edges > 0);
    }
    try testing.expect(failures > 0);
    for (fragments) |fragment| exercise_json(fragment);
}

//! `base_*` JSON-RPC methods of the consensus node (base/base `crates/consensus/rpc/src/
//! base.rs` `BaseApi` and `upgrade-signal` `readiness.rs`): `base_upgradeReadiness`, the
//! public, read-only pre-flight check of whether this node supports the contract-backed
//! upgrades scheduled on L1.
//!
//! The report uses the same predicates as base/base: an upgrade is supported when the L1
//! minimum protocol version is at most the node's; a scheduled signal without a minimum is
//! malformed; it would halt when unsupported, the mode applies the live schedule, and the
//! activation is within the halt lead time. A `target_version` param turns the answer into
//! a pure binary-support check.
//!
//! Difference: base/base reads L1 on each query (5 s cache); the router here is synchronous,
//! so the node answers from its upgrade-signal observer's newest read.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const upgrade_signal = @import("../../utilities/upgrade_signal/root.zig");
const rollup = @import("rollup.zig");
const RollupConfig = @import("../protocol/rollup_config.zig").RollupConfig;

const Backend = rollup.Backend;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Version = upgrade_signal.Version;
const Schedule = upgrade_signal.Schedule;
const upgrade_ids = upgrade_signal.contract.upgrade_ids;

/// base/base `UpgradeSignalDefaults::HALT_LEAD_POLL_INTERVALS`.
pub const halt_lead_poll_intervals = 2;

/// base/base JSON-RPC error code for a failed L1 schedule read.
pub const read_failed_code: i32 = -32006;

pub const Mode = enum {
    metrics_only,
    startup_apply,
    runtime_admin,

    pub fn text(mode: Mode) []const u8 {
        return switch (mode) {
            .metrics_only => "metrics-only",
            .startup_apply => "startup-apply",
            .runtime_admin => "runtime-admin",
        };
    }

    /// Only runtime-admin applies (and halts on) live schedule changes.
    pub fn applies_live(mode: Mode) bool {
        return mode == .runtime_admin;
    }
};

pub const Config = struct {
    node_version: Version,
    mode: Mode = .metrics_only,
    halt_lead_s: u64,

    pub fn supports(config: *const Config, minimum: Version) bool {
        return minimum.order(config.node_version) != .gt;
    }
};

/// The halt lead time for reads at `tag`: two poll intervals.
pub fn halt_lead_s(tag: upgrade_signal.BlockTag) u64 {
    const lead_s = tag.poll_interval_ns() / std.time.ns_per_s * halt_lead_poll_intervals;
    assert(lead_s > 0);
    return lead_s;
}

/// The protocol version this binary advertises: its release version, or the highest
/// version-type-0 version for dev builds (`0.0.0` or unparsable), as in base/base.
pub fn advertised_version(release: []const u8) Version {
    const max = Version.pack(std.math.maxInt(u32), std.math.maxInt(u32), std.math.maxInt(u32), 0);
    const parsed = Version.parse(release) catch return max;
    if (parsed.eql(Version.pack(0, 0, 0, 0))) return max;
    assert(parsed.version_type() == 0);
    return parsed;
}

pub const Reason = union(enum) {
    none,
    target_unsupported: Version,
    mode_not_live,
    empty_schedule,
    /// Index into `upgrade_ids`.
    missing_version: u8,
    unsupported_version: u8,
};

pub const Entry = struct {
    index: u8,
    activation_timestamp: u64,
    supported: bool,
    malformed: bool,
    would_halt: bool,
};

pub const Readiness = struct {
    ready: bool,
    reason: Reason,
    node_version: Version,
    mode: Mode,
    l1_block_number: ?u64,
    minimum: Version,
    entries: [upgrade_ids.len]Entry = undefined,
    count: u8 = 0,
};

/// base/base `UpgradeSignalConfig::evaluate_readiness`. `schedule` is null for an empty read.
pub fn evaluate(
    config: *const Config,
    schedule: ?*const Schedule,
    now_s: u64,
    target: ?Version,
) Readiness {
    const minimum = if (schedule) |s| s.minimum_version else Version.pack(0, 0, 0, 0);
    var readiness: Readiness = .{
        .ready = true,
        .reason = .none,
        .node_version = config.node_version,
        .mode = config.mode,
        .l1_block_number = if (schedule) |s| s.l1_block_number else null,
        .minimum = minimum,
    };
    var first_invalid: ?Reason = null;
    const signals = if (schedule) |s| s.signals_count() else 0;
    for (0..signals) |index| {
        const activation = schedule.?.timestamps[index];
        if (activation == 0) continue; // Cleared: omitted and never invalid.
        const missing = minimum.packed_value == 0;
        const supported = config.supports(minimum);
        const imminent = now_s +| config.halt_lead_s >= activation;
        readiness.entries[readiness.count] = .{
            .index = @intCast(index),
            .activation_timestamp = activation,
            .supported = supported,
            .malformed = missing,
            .would_halt = config.mode.applies_live() and !supported and imminent,
        };
        readiness.count += 1;
        if (first_invalid == null) {
            if (missing) first_invalid = .{ .missing_version = @intCast(index) };
            if (!supported) first_invalid = .{ .unsupported_version = @intCast(index) };
        }
    }
    readiness.reason = if (target) |version|
        (if (config.supports(version)) .none else .{ .target_unsupported = version })
    else if (!config.mode.applies_live())
        .mode_not_live
    else if (schedule == null)
        .empty_schedule
    else
        first_invalid orelse .none;
    readiness.ready = readiness.reason == .none;
    assert(readiness.count <= signals);
    return readiness;
}

fn write_reason(readiness: *const Readiness, writer: *json.Writer) json.Writer.WriteError!void {
    var text: [512]u8 = undefined;
    const node = readiness.node_version;
    const message = switch (readiness.reason) {
        .none => return writer.null_value(),
        .target_unsupported => |target| std.fmt.bufPrint(
            &text,
            "node protocol version {f} does not support target {f}",
            .{ node, target },
        ),
        .mode_not_live => std.fmt.bufPrint(&text, "node's upgrade-signal mode does not apply " ++
            "the live L1 schedule; it will not follow a live change to it (per-upgrade " ++
            "`supported` still reflects binary capability)", .{}),
        .empty_schedule => std.fmt.bufPrint(&text, "no upgrade schedule is published on L1 " ++
            "(an append-only ProtocolVersions contract always carries at least the oldest " ++
            "upgrade, so an empty read means a misconfigured, uninitialized, or unreachable " ++
            "contract); pass a target version to check binary support for an announced " ++
            "upgrade", .{}),
        .missing_version => |index| std.fmt.bufPrint(&text, "upgrade signal for {s} has an " ++
            "activation timestamp but no minimum node protocol version", .{upgrade_ids[index]}),
        .unsupported_version => |index| std.fmt.bufPrint(&text, "upgrade signal for {s} " ++
            "requires node protocol version {f}, but this binary supports {f}", .{
            upgrade_ids[index], readiness.minimum, node,
        }),
    } catch unreachable; // Proof: the longest message is under 400 bytes.
    try writer.string(message);
}

/// The `UpgradeReadiness` JSON object (serde field names, snake_case).
pub fn write(readiness: *const Readiness, writer: *json.Writer) json.Writer.WriteError!void {
    assert(readiness.count <= upgrade_ids.len);
    var version_text: [64]u8 = undefined;
    try writer.begin_object();
    try writer.key("ready");
    try writer.boolean(readiness.ready);
    try writer.key("node_protocol_version");
    try writer.string(format_version(&version_text, readiness.node_version));
    try writer.key("mode");
    try writer.string(readiness.mode.text());
    try writer.key("reason");
    try write_reason(readiness, writer);
    try writer.key("l1_block_number");
    if (readiness.l1_block_number) |number| try writer.integer(number) else try writer.null_value();
    try writer.key("upgrades");
    try writer.begin_array();
    for (readiness.entries[0..readiness.count]) |entry| {
        try writer.begin_object();
        try writer.key("upgrade_id");
        try writer.string(upgrade_ids[entry.index]);
        try writer.key("required_protocol_version");
        try writer.string(format_version(&version_text, readiness.minimum));
        try writer.key("activation_timestamp");
        try writer.integer(entry.activation_timestamp);
        inline for (.{ "supported", "malformed", "would_halt" }) |name| {
            try writer.key(name);
            try writer.boolean(@field(entry, name));
        }
        try writer.end_object();
    }
    try writer.end_array();
    try writer.end_object();
}

fn format_version(buffer: *[64]u8, version: Version) []const u8 {
    // Proof: the longest form is `unknown-version-type-255` or four u32s, under 64 bytes.
    return std.fmt.bufPrint(buffer, "{f}", .{version}) catch unreachable;
}

pub const Status = union(enum) {
    /// No read has completed yet (or every read failed).
    unavailable,
    /// The newest read returned an empty schedule.
    empty,
    schedule: *const Schedule,
};

pub const VTable = struct {
    config: *const fn (context: *anyopaque) Config,
    status: *const fn (context: *anyopaque) Status,
    now_s: *const fn (context: *anyopaque) u64,
};

pub const methods = [_]rpc.Method(*const Backend){
    .{ .name = "base_upgradeReadiness", .handler = upgrade_readiness },
};

/// An optional `"major.minor.patch[-rc.N]"` param.
fn target_param(call: *Call) HandlerError!?Version {
    const raw = try call.params.optional_raw() orelse return null;
    if (std.mem.eql(u8, raw, "null")) return null;
    const quoted = raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"';
    if (!quoted) return call.fail(rpc.code.invalid_params, "target version must be a string");
    return Version.parse(raw[1 .. raw.len - 1]) catch
        call.fail(rpc.code.invalid_params, "invalid target version (want major.minor.patch)");
}

fn upgrade_readiness(backend: *const Backend, call: *Call) HandlerError!void {
    const target = try target_param(call);
    try call.params.finish();
    const vtable = backend.base orelse
        return call.fail(rpc.code.server_error, "upgrade signal not configured");
    const schedule: ?*const Schedule = switch (vtable.status(backend.context)) {
        .unavailable => return call.fail(read_failed_code, "failed to read L1 upgrade schedule"),
        .empty => null,
        .schedule => |schedule| schedule,
    };
    const config = vtable.config(backend.context);
    const readiness = evaluate(&config, schedule, vtable.now_s(backend.context), target);
    try write(&readiness, call.writer);
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn test_config(mode: Mode) Config {
    return .{ .node_version = Version.pack(1, 1, 0, 0), .mode = mode, .halt_lead_s = 1_800 };
}

fn test_schedule(activation: u64, minimum: Version) Schedule {
    var schedule: Schedule = .{ .l1_block_number = 42, .count = 1, .minimum_version = minimum };
    schedule.timestamps[0] = activation;
    return schedule;
}

test "base rpc: supported scheduled upgrade is ready" {
    const config = test_config(.runtime_admin);
    const schedule = test_schedule(1_000, Version.pack(1, 1, 0, 0));
    const readiness = evaluate(&config, &schedule, 0, null);
    try testing.expect(readiness.ready);
    try testing.expectEqual(Reason.none, readiness.reason);
    try testing.expectEqual(@as(?u64, 42), readiness.l1_block_number);
    try testing.expectEqual(@as(u8, 1), readiness.count);
    const entry = readiness.entries[0];
    try testing.expect(entry.supported and !entry.malformed and !entry.would_halt);
}

test "base rpc: unsupported upgrade halts only when imminent" {
    const config = test_config(.runtime_admin);
    const activation = 1_000_000;
    const schedule = test_schedule(activation, Version.pack(1, 1, 1, 0));
    const distant = evaluate(&config, &schedule, 0, null);
    try testing.expect(!distant.ready);
    try testing.expectEqual(Reason{ .unsupported_version = 0 }, distant.reason);
    try testing.expect(!distant.entries[0].supported and !distant.entries[0].would_halt);
    const imminent = evaluate(&config, &schedule, activation - config.halt_lead_s + 1, null);
    try testing.expect(!imminent.ready and imminent.entries[0].would_halt);
}

test "base rpc: cleared, malformed, non-live modes, empty schedules, targets" {
    const live = test_config(.runtime_admin);
    const cleared = test_schedule(0, Version.pack(9, 9, 9, 0));
    const cleared_readiness = evaluate(&live, &cleared, 0, null);
    try testing.expect(cleared_readiness.ready and cleared_readiness.count == 0);
    const malformed = test_schedule(1_000, Version.pack(0, 0, 0, 0));
    const malformed_readiness = evaluate(&live, &malformed, 0, null);
    try testing.expect(!malformed_readiness.ready and malformed_readiness.entries[0].malformed);
    try testing.expect(malformed_readiness.entries[0].supported);
    try testing.expectEqual(Reason.empty_schedule, evaluate(&live, null, 0, null).reason);
    const supported = test_schedule(1_000, Version.pack(1, 1, 0, 0));
    for ([_]Mode{ .metrics_only, .startup_apply }) |mode| {
        const readiness = evaluate(&test_config(mode), &supported, 0, null);
        try testing.expectEqual(Reason.mode_not_live, readiness.reason);
    }
    // A target is a pure binary-support probe, independent of mode and schedule.
    const metrics = test_config(.metrics_only);
    try testing.expect(evaluate(&metrics, null, 0, Version.pack(1, 0, 9, 0)).ready);
    try testing.expect(evaluate(&metrics, null, 0, Version.pack(1, 1, 0, 0)).ready);
    const above = evaluate(&metrics, null, 0, Version.pack(1, 1, 0, 1));
    try testing.expect(above.ready); // 1.1.0-rc.1 sorts below 1.1.0.
    const newer = evaluate(&metrics, null, 0, Version.pack(1, 2, 0, 0));
    try testing.expect(!newer.ready);
}

test "base rpc: advertised version and halt lead" {
    try testing.expectEqual(std.math.maxInt(u32), advertised_version("0.0.0").major());
    try testing.expectEqual(std.math.maxInt(u32), advertised_version("dev").patch());
    try testing.expect(advertised_version("1.2.3").eql(Version.pack(1, 2, 3, 0)));
    try testing.expectEqual(@as(u64, 1_800), halt_lead_s(.finalized));
    try testing.expectEqual(@as(u64, 24), halt_lead_s(.latest));
}

const StubNode = struct {
    status: Status = .unavailable,
    schedule: Schedule = .{},

    fn config(_: *anyopaque) Config {
        return test_config(.metrics_only);
    }
    fn status_of(context: *anyopaque) Status {
        const node: *StubNode = @ptrCast(@alignCast(context));
        return node.status;
    }
    fn now_s(_: *anyopaque) u64 {
        return 500;
    }
    const vtable: VTable = .{ .config = config, .status = status_of, .now_s = now_s };
};

fn stub_backend(node: *StubNode, rollup_config: *const RollupConfig) Backend {
    const Optimism = struct {
        fn sync_status(_: *anyopaque) rollup.SyncStatus {
            return std.mem.zeroes(rollup.SyncStatus);
        }
        const OutputError = error{ NotAvailable, NotFound };
        fn output(_: *anyopaque, _: rollup.BlockTag) OutputError!rollup.OutputAtBlock {
            return error.NotAvailable;
        }
        fn safe_db(_: *anyopaque) ?*const @import("../safedb/root.zig").SafeDB {
            return null;
        }
        const vtable: Backend.VTable = .{
            .sync_status = sync_status,
            .output_at_block = output,
            .safe_db = safe_db,
        };
    };
    return .{
        .context = node,
        .vtable = &Optimism.vtable,
        .version = "test",
        .rollup = rollup_config,
        .base = &StubNode.vtable,
    };
}

fn call_text(backend: *const Backend, body: []const u8, buffer: []u8) []const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    _ = rollup.NodeRouter.handle(backend, body, &out);
    return out.buffered();
}

fn expect_contains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, text });
        return error.TestExpectedEqual;
    }
}

test "base rpc: base_upgradeReadiness over the router" {
    const rollup_config: RollupConfig = .{};
    var node: StubNode = .{};
    const backend = stub_backend(&node, &rollup_config);
    var buffer: [4096]u8 = undefined;
    const prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"base_upgradeReadiness\",\"params\":";
    try expect_contains(call_text(&backend, prefix ++ "[]}", &buffer), "-32006");
    node.status = .empty;
    const empty = call_text(&backend, prefix ++ "[\"1.0.0\"]}", &buffer);
    try expect_contains(empty, "\"ready\":true");
    try expect_contains(empty, "\"l1_block_number\":null");
    node.schedule = test_schedule(1_000, Version.pack(1, 1, 1, 0));
    node.status = .{ .schedule = &node.schedule };
    const scheduled = call_text(&backend, prefix ++ "[null]}", &buffer);
    try expect_contains(scheduled, "\"ready\":false");
    try expect_contains(scheduled, "\"mode\":\"metrics-only\"");
    try expect_contains(scheduled, "\"upgrade_id\":\"");
    try expect_contains(scheduled, "\"required_protocol_version\":\"1.1.1\"");
    try expect_contains(scheduled, "\"supported\":false");
    const newer = call_text(&backend, prefix ++ "[\"1.2.0-rc.3\"]}", &buffer);
    try expect_contains(newer, "does not support target 1.2.0-rc.3");
    try expect_contains(call_text(&backend, prefix ++ "[\"v1\"]}", &buffer), "-32602");
    try expect_contains(call_text(&backend, prefix ++ "[7]}", &buffer), "-32602");
    var disabled = backend;
    disabled.base = null;
    try expect_contains(call_text(&disabled, prefix ++ "[]}", &buffer), "not configured");
}

fn small_version(prng: *Prng) Version {
    const part = struct {
        fn of(random: *Prng) u32 {
            return @intCast(random.below(3));
        }
    }.of;
    return Version.pack(part(prng), part(prng), part(prng), 0);
}

test "base rpc: seeded fuzz evaluate and write" {
    var prng = Prng.init(0xba5e);
    var buffer: [4096]u8 = undefined;
    for (0..1_000) |_| {
        const mode: Mode = @fromBackingInt(@intCast(prng.below(3)));
        const config: Config = .{
            .node_version = small_version(&prng),
            .mode = mode,
            .halt_lead_s = prng.below(100),
        };
        var schedule: Schedule = .{
            .count = @intCast(prng.below(upgrade_ids.len + 2)),
            .minimum_version = small_version(&prng),
        };
        for (schedule.timestamps[0..schedule.count]) |*t| t.* = prng.below(200);
        const target: ?Version = if (prng.chance(1, 3)) small_version(&prng) else null;
        const view: ?*const Schedule = if (prng.chance(1, 5)) null else &schedule;
        const readiness = evaluate(&config, view, prng.below(200), target);
        try testing.expectEqual(readiness.ready, readiness.reason == .none);
        if (target == null and !mode.applies_live()) try testing.expect(!readiness.ready);
        for (readiness.entries[0..readiness.count]) |entry| {
            try testing.expect(entry.activation_timestamp > 0);
            if (entry.would_halt) try testing.expect(!entry.supported and mode.applies_live());
        }
        var out: std.Io.Writer = .fixed(&buffer);
        var writer = json.Writer.init(&out);
        try write(&readiness, &writer);
        try json.validate(out.buffered());
    }
}

fn fuzz_params(_: void, smith: *std.testing.Smith) anyerror!void {
    const rollup_config: RollupConfig = .{};
    var node: StubNode = .{ .status = .empty };
    const backend = stub_backend(&node, &rollup_config);
    var params: [64]u8 = undefined;
    const len = smith.slice(&params);
    var body: [160]u8 = undefined;
    const text = std.fmt.bufPrint(&body, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":" ++
        "\"base_upgradeReadiness\",\"params\":[{s}]}}", .{params[0..len]}) catch return;
    var buffer: [4096]u8 = undefined;
    _ = call_text(&backend, text, &buffer);
}

test "base rpc: fuzz target version params" {
    try testing.fuzz({}, fuzz_params, .{});
}

//! `basectl denim`: Denim activation readiness over one hash-pinned L2 snapshot (base/base
//! `crates/infra/basectl/src/denim.rs`). This file is the pure half: the BaseTime
//! constants, observations -> report evaluation, the 200 ms cadence classification, and
//! the JSON field checks of the timestamp wire fields. `denim_fetch.zig` gathers the
//! observations over JSON-RPC.
//!
//! Statuses mirror base/base: a check that does not hold before activation is
//! `indeterminate`, never `fail`; after activation it fails.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const types = @import("types.zig");
const base_time = @import("../../common/consensus/base_time.zig");
const predeploys = @import("../../common/consensus/predeploys.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const hex = @import("../../common/primitives/hex.zig");

const Writer = types.Writer;

// ------------------------------------------------------------------------- constants

/// The BaseTime proxy predeploy (`0x4200…0030`).
pub const proxy_address: [20]u8 = predeploys.base_time.bytes;
/// The canonical proxy admin predeploy (`0x4200…0018`).
pub const proxy_admin: [20]u8 = predeploys.proxy_admin.bytes;
/// The implementation Denim installs and links (base/base `IMPLEMENTATION_ADDRESS`).
pub const implementation_address: [20]u8 =
    hex_bytes(20, "c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30030");
/// keccak256 of the installed implementation runtime.
pub const implementation_code_hash: [32]u8 =
    hex_bytes(32, "9c4c8a497a69d0b8f2ba67be0bee7a1373186055978c3be6ec3068e0ec27f32a");
/// keccak256 of the reserved proxy runtime.
pub const proxy_code_hash: [32]u8 =
    hex_bytes(32, "fa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998");
/// EIP-1967 implementation slot.
pub const implementation_slot: [32]u8 =
    hex_bytes(32, "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc");
/// EIP-1967 admin slot.
pub const admin_slot: [32]u8 =
    hex_bytes(32, "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103");
/// The millisecond part is packed as a uint16 at byte offset 30 of slot 0.
pub const millis_part_slot: [32]u8 = @splat(0);
pub const millis_part_offset_bytes: u8 = 30;
/// `timestampMillisPart()` and `timestampMs()` getter selectors.
pub const timestamp_millis_part_selector = [4]u8{ 0x7b, 0x2f, 0xea, 0x99 };
pub const timestamp_ms_selector = [4]u8{ 0x57, 0x45, 0xa6, 0x77 };
pub const block_interval_ms: u64 = base_time.block_interval_ms;

comptime {
    assert(millis_part_offset_bytes + 2 == 32);
    assert(block_interval_ms == 200);
}

fn hex_bytes(comptime size: usize, comptime text: *const [2 * size]u8) [size]u8 {
    var out: [size]u8 = undefined;
    // Proof: comptime literal of valid hex digits.
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

/// Decodes the packed millisecond part from the raw slot-0 word.
pub fn decode_millis_part(word: [32]u8) u16 {
    const part = std.mem.readInt(u16, word[millis_part_offset_bytes..][0..2], .big);
    assert(@as(u32, part) <= std.math.maxInt(u16));
    return part;
}

/// The address word of `address`: twelve zero bytes, then the address.
pub fn address_word(address: [20]u8) [32]u8 {
    var word: [32]u8 = @splat(0);
    word[12..].* = address;
    assert(std.mem.allEqual(u8, word[0..12], 0));
    return word;
}

// ------------------------------------------------------------------------- report

pub const Schedule = enum { not_scheduled, scheduled, active };
pub const Status = enum { pass, fail, indeterminate };

/// Expected/observed text, truncated to 128 bytes.
pub const Note = types.Text(128);

/// `format` with `args`, truncated to the note capacity.
pub fn note(comptime format: []const u8, args: anytype) Note {
    var result: Note = .{};
    var writer: Writer = .fixed(&result.bytes);
    writer.print(format, args) catch {};
    result.length = @intCast(writer.buffered().len);
    assert(result.length <= result.bytes.len);
    return result;
}

pub const Check = struct {
    name: []const u8,
    status: Status,
    expected: Note,
    observed: Note,
};

pub const checks_max = 32;

pub const Report = struct {
    network: []const u8,
    schedule: Schedule,
    block_number: u64,
    block_hash: types.Hash,
    timestamp: u64,
    timestamp_ms: ?u64,
    activation: ?u64,
    checks: types.List(Check, checks_max) = .{},

    pub fn add(
        report: *Report,
        name: []const u8,
        status: Status,
        expected: Note,
        observed: Note,
    ) void {
        assert(name.len > 0);
        // Proof: a report holds at most 22 checks (3 proxy, 6 active, 1 cadence, 12 wire).
        assert(report.checks.push(.{
            .name = name,
            .status = status,
            .expected = expected,
            .observed = observed,
        }));
    }

    /// The last check named `name`.
    pub fn find(report: *Report, name: []const u8) ?*Check {
        assert(report.checks.count <= checks_max);
        var index: usize = report.checks.count;
        while (index > 0) {
            index -= 1;
            const check = &report.checks.items[index];
            if (std.mem.eql(u8, check.name, name)) return check;
        }
        return null;
    }

    pub fn count(report: *const Report, status: Status) u32 {
        var total: u32 = 0;
        for (report.checks.slice()) |check| total += @intFromBool(check.status == status);
        assert(total <= report.checks.count);
        return total;
    }

    pub fn has_failures(report: *const Report) bool {
        return report.count(.fail) > 0;
    }
};

/// A value read through an RPC that may have failed (the note says why).
pub fn Observed(comptime T: type) type {
    return union(enum) {
        const Self = @This();
        none,
        ok: T,
        failed: Note,

        pub fn get(observed: Self) ?T {
            return switch (observed) {
                .ok => |value| value,
                else => null,
            };
        }

        fn text(observed: Self, comptime format: []const u8) Note {
            return switch (observed) {
                .none => note("unavailable", .{}),
                .ok => |value| note(format, .{value}),
                .failed => |failed| failed,
            };
        }
    };
}

/// Pure observations at one snapshot (base/base `DenimObservations`).
pub const Observations = struct {
    network: []const u8 = "devnet",
    activation: ?u64,
    block_number: u64,
    block_hash: [32]u8,
    timestamp: u64,
    timestamp_ms: ?u64,
    proxy_code_hash: [32]u8,
    admin: [32]u8,
    implementation: [32]u8,
    /// Code hash at the linked implementation address, when it was read.
    implementation_code_hash: ?[32]u8,
    storage_millis_part: u16,
    /// tx[1] metadata millisecond part, or why it is invalid (`.none` before activation).
    metadata: Observed(u16),
    metadata_receipt_valid: ?bool,
    getter_millis_part: Observed(u16),
    getter_timestamp_ms: Observed(u64),
};

pub const Implementation = enum {
    missing,
    inconsistent,
    dormant,
    linked_initial,
    linked_other,

    pub fn text(implementation: Implementation) []const u8 {
        return switch (implementation) {
            .missing => "Missing",
            .inconsistent => "Inconsistent",
            .dormant => "Dormant",
            .linked_initial => "LinkedInitial",
            .linked_other => "LinkedOther",
        };
    }
};

/// The proxy's implementation state, classified exactly like base/base `evaluate`.
pub fn classify_implementation(input: *const Observations) Implementation {
    const empty = keccak.empty_digest;
    const zero: [32]u8 = @splat(0);
    const canonical_admin = std.mem.eql(u8, &input.admin, &address_word(proxy_admin));
    const initial = std.mem.eql(u8, &input.implementation, &address_word(implementation_address));
    const is_address = std.mem.allEqual(u8, input.implementation[0..12], 0);
    const code = input.implementation_code_hash;
    if (std.mem.eql(u8, &input.proxy_code_hash, &empty)) return .missing;
    if (!std.mem.eql(u8, &input.proxy_code_hash, &proxy_code_hash)) return .inconsistent;
    if (!canonical_admin) return .inconsistent;
    if (std.mem.eql(u8, &input.implementation, &zero)) return .dormant;
    if (!is_address) return .inconsistent;
    if (initial and code != null and std.mem.eql(u8, &code.?, &implementation_code_hash)) {
        return .linked_initial;
    }
    if (initial or code == null or std.mem.eql(u8, &code.?, &empty)) return .inconsistent;
    assert(is_address and canonical_admin);
    return .linked_other;
}

pub fn schedule_at(activation: ?u64, timestamp: u64) Schedule {
    const at = activation orelse return .not_scheduled;
    return if (timestamp < at) .scheduled else .active;
}

/// `timestamp * 1000 + millis_part` with uint64 wrapping, like base/base and Solidity.
pub fn expected_timestamp_ms(timestamp: u64, millis_part: u16) u64 {
    return timestamp *% 1_000 +% millis_part;
}

fn status_of(matches: bool, active: bool) Status {
    if (matches) return .pass;
    return if (active) .fail else .indeterminate;
}

/// Evaluates observations into the proxy and (when active) metadata checks.
pub fn evaluate(input: *const Observations) Report {
    const schedule = schedule_at(input.activation, input.timestamp);
    const active = schedule == .active;
    var report: Report = .{
        .network = input.network,
        .schedule = schedule,
        .block_number = input.block_number,
        .block_hash = .{ .bytes = input.block_hash },
        .timestamp = input.timestamp,
        .timestamp_ms = input.timestamp_ms,
        .activation = input.activation,
    };
    const code_matches = std.mem.eql(u8, &input.proxy_code_hash, &proxy_code_hash);
    report.add("proxy_code_hash", status_of(code_matches, active), note("0x{x}", .{
        &proxy_code_hash,
    }), note("0x{x}", .{&input.proxy_code_hash}));
    const admin_matches = std.mem.eql(u8, &input.admin, &address_word(proxy_admin));
    report.add("proxy_admin", status_of(admin_matches, active), note("0x{x}", .{
        &proxy_admin,
    }), note("0x{x}", .{&input.admin}));
    const implementation = classify_implementation(input);
    const linked = implementation == .linked_initial or implementation == .linked_other;
    report.add(
        "implementation",
        status_of(linked, active),
        note("a linked implementation with deployed code", .{}),
        note("{s}", .{implementation.text()}),
    );
    if (active) add_active_checks(&report, input);
    assert(report.checks.count == if (active) @as(u16, 9) else 3);
    return report;
}

fn add_active_checks(report: *Report, input: *const Observations) void {
    assert(report.schedule == .active);
    const part = input.metadata.get();
    const expected_ms: ?u64 = if (part) |value|
        expected_timestamp_ms(input.timestamp, value)
    else
        null;
    const unavailable = note("metadata unavailable", .{});
    const expected_ms_note = if (expected_ms) |value| note("{d}", .{value}) else unavailable;
    const part_note = if (part) |value| note("{d}", .{value}) else unavailable;
    report.add("metadata", status_of(part != null, true), note(
        "canonical tx[1] BaseTime deposit",
        .{},
    ), input.metadata.text("{d}"));
    const receipt = input.metadata_receipt_valid;
    report.add(
        "metadata_receipt",
        status_of(receipt == true, true),
        note("successful receipt at index 1 in the snapshot block", .{}),
        if (receipt) |valid| note("{}", .{valid}) else note("missing", .{}),
    );
    const header_matches = expected_ms != null and input.timestamp_ms == expected_ms;
    report.add(
        "header_timestamp_ms",
        status_of(header_matches, true),
        expected_ms_note,
        if (input.timestamp_ms) |value| note("{d}", .{value}) else note("missing", .{}),
    );
    const storage_matches = part != null and part.? == input.storage_millis_part;
    report.add("storage_millis_part", status_of(storage_matches, true), part_note, note(
        "{d}",
        .{input.storage_millis_part},
    ));
    // Getters must return a value: an error never compares equal to missing metadata.
    const getter_part = input.getter_millis_part.get();
    const part_matches = part != null and getter_part != null and getter_part.? == part.?;
    report.add(
        "getter_millis_part",
        status_of(part_matches, true),
        part_note,
        input.getter_millis_part.text("{d}"),
    );
    const getter_ms = input.getter_timestamp_ms.get();
    const ms_matches = expected_ms != null and getter_ms != null and getter_ms.? == expected_ms.?;
    report.add(
        "getter_timestamp_ms",
        status_of(ms_matches, true),
        expected_ms_note,
        input.getter_timestamp_ms.text("{d}"),
    );
}

// ------------------------------------------------------------------------- metadata

pub const MetadataError = base_time.MetadataError || error{Malformed};

pub fn metadata_error_text(err: MetadataError) []const u8 {
    return @errorName(err);
}

/// The millisecond part from a block's tx[1] as JSON (`null` when the block has none),
/// validated field by field like `base_time.extract`.
pub fn metadata_from_json(second: ?json.Value, block_number: u64) MetadataError!u16 {
    const tx = second orelse return error.Missing;
    if (tx != .object) return error.Malformed;
    const tx_type = quantity_field(u8, tx, "type") orelse return error.Malformed;
    if (tx_type != 0x7e) return error.NotDeposit;
    var input_buffer: [512]u8 = undefined;
    const input_value = tx.object.get("input") orelse return error.Malformed;
    if (input_value != .string) return error.Malformed;
    const input = hex.decode_into(&input_buffer, input_value.string) catch |err| switch (err) {
        // Far longer than a BaseTime call (36 bytes): report it as a length error.
        error.InvalidLength => return error.InvalidLength,
        else => return error.Malformed,
    };
    const deposit = decode_deposit(tx, input) orelse return error.Malformed;
    const part = try base_time.validate_deposit(deposit, block_number);
    assert(base_time.is_valid_millis_part(part));
    return part;
}

fn decode_deposit(tx: json.Value, input: []const u8) ?base_time_tx.Deposit {
    assert(tx == .object);
    const to_value = tx.object.get("to") orelse return null;
    const to: base_time_tx.TxKind = if (to_value == .null) .create else .{
        .call = .{ .bytes = fixed_field(20, tx, "to") orelse return null },
    };
    const system = tx.object.get("isSystemTx") orelse json.Value{ .bool = false };
    if (system != .bool) return null;
    // op-geth omits `mint` when it is zero.
    const mint: u128 = if (tx.object.get("mint")) |_| quantity_field(u128, tx, "mint") orelse
        return null else 0;
    return .{
        .source_hash = .{ .bytes = fixed_field(32, tx, "sourceHash") orelse return null },
        .from = .{ .bytes = fixed_field(20, tx, "from") orelse return null },
        .to = to,
        .mint = mint,
        .value = quantity_field(u256, tx, "value") orelse return null,
        .gas_limit = quantity_field(u64, tx, "gas") orelse return null,
        .is_system_transaction = system.bool,
        .input = input,
    };
}

const base_time_tx = @import("../../common/consensus/tx.zig");

fn quantity_field(comptime T: type, value: json.Value, name: []const u8) ?T {
    if (value != .object) return null;
    const inner = value.object.get(name) orelse return null;
    if (inner != .string) return null;
    return hex.decode_quantity(T, inner.string) catch null;
}

pub fn fixed_field(comptime size: usize, value: json.Value, name: []const u8) ?[size]u8 {
    if (value != .object) return null;
    const inner = value.object.get(name) orelse return null;
    if (inner != .string) return null;
    return hex.decode_array(size, inner.string) catch null;
}

/// Strict JSON-RPC quantity: `0x`, at least one digit, no leading zero (base/base).
pub fn parse_quantity(text: []const u8) ?u64 {
    if (text.len < 3 or text[0] != '0' or text[1] != 'x') return null;
    const digits = text[2..];
    if (digits.len > 1 and digits[0] == '0') return null;
    const value = std.fmt.parseInt(u64, digits, 16) catch return null;
    assert(digits.len <= 16);
    return value;
}

pub fn string_quantity(value: json.Value, name: []const u8) ?u64 {
    if (value != .object) return null;
    const inner = value.object.get(name) orelse return null;
    if (inner != .string) return null;
    return parse_quantity(inner.string);
}

pub fn string_hash(value: json.Value, name: []const u8) ?[32]u8 {
    return fixed_field(32, value, name);
}

// ------------------------------------------------------------------------- cadence

pub const cadence_check = "cadence_200ms";
pub const cadence_expected = "every canonical parent-child edge is exactly +200ms";

/// One block of the cadence walk, newest first.
pub const BlockFacts = struct {
    number: u64,
    hash: [32]u8,
    parent_hash: [32]u8,
    timestamp: u64,
    /// `timestamp * 1000 + millis_part` from valid tx[1] metadata, else null.
    timestamp_ms: ?u64,
};

/// One parent-child edge (base/base `cadence_status`).
pub fn cadence_status(parent: ?u64, child: ?u64, contiguous: bool) Status {
    const parent_ms = parent orelse return .indeterminate;
    const child_ms = child orelse return .indeterminate;
    if (!contiguous) return .indeterminate;
    const next = std.math.add(u64, parent_ms, block_interval_ms) catch return .fail;
    return if (next == child_ms) .pass else .fail;
}

pub const Cadence = struct {
    status: Status,
    edges: u32,

    pub fn observed(cadence: Cadence) []const u8 {
        return switch (cadence.status) {
            .pass => "exact +200ms progression",
            .fail => "wrong timestamp gap",
            .indeterminate => "activation boundary, missing range, or reorg",
        };
    }
};

/// Classifies the walk `blocks` (snapshot first, each next block the parent of the one
/// before). `walk_complete` is false when the walk stopped on an unavailable block. The
/// legacy-to-Denim boundary edge is not checked, as in base/base.
pub fn evaluate_cadence(activation: ?u64, blocks: []const BlockFacts, walk_complete: bool) Cadence {
    var status: Status = .pass;
    var edges: u32 = 0;
    for (blocks, 0..) |block, index| {
        const active = activation != null and block.timestamp >= activation.?;
        if (active and block.timestamp_ms == null) status = .fail;
        if (active and index > 0) {
            const child = blocks[index - 1];
            const linked = std.mem.eql(u8, &child.parent_hash, &block.hash);
            const contiguous = linked and block.number < std.math.maxInt(u64) and
                child.number == block.number + 1;
            if (!contiguous) {
                if (status != .fail) status = .indeterminate;
                break;
            }
            edges += 1;
            const edge = cadence_status(block.timestamp_ms, child.timestamp_ms, true);
            if (edge != .pass and status != .fail) status = edge;
        }
        // A failure is final.
        if (status == .fail or !active) break;
    }
    if (!walk_complete and status == .pass) status = .indeterminate;
    if (status == .pass and edges == 0) status = .indeterminate;
    assert(edges <= blocks.len);
    assert(status != .pass or edges > 0);
    return .{ .status = status, .edges = edges };
}

// ------------------------------------------------------------------------- wire fields

/// The 12 HTTP wire checks of base/base `WIRE_CHECKS`, in order.
pub const wire_checks = [_][]const u8{
    "rpc_eth_getBlockByHash_timestampMs",
    "rpc_eth_getBlockByNumber_timestampMs",
    "rpc_eth_getHeaderByHash_timestampMs",
    "rpc_eth_getHeaderByNumber_timestampMs",
    "rpc_eth_getTransactionByHash_blockTimestampMs",
    "rpc_eth_getTransactionByBlockHashAndIndex_blockTimestampMs",
    "rpc_eth_getTransactionByBlockNumberAndIndex_blockTimestampMs",
    "rpc_eth_getLogs_blockTimestampMs",
    "rpc_eth_getFilterChanges_blockTimestampMs",
    "rpc_eth_getFilterLogs_blockTimestampMs",
    "rpc_eth_getTransactionReceipt_logs_blockTimestampMs",
    "rpc_eth_getBlockReceipts_logs_blockTimestampMs",
};
pub const object_checks = wire_checks[0..7];
pub const log_checks = wire_checks[7..];

comptime {
    assert(3 + 6 + 1 + wire_checks.len <= checks_max);
}

/// One raw RPC result: a value, a JSON-RPC error (fails), or no answer (indeterminate;
/// includes -32601 "method not served").
pub const Outcome = union(enum) {
    value: json.Value,
    method_error: Note,
    unavailable: Note,
};

/// A field of a wire object that must match the pinned snapshot.
pub const Identity = struct {
    field: []const u8,
    expected: union(enum) { hash: [32]u8, quantity: u64 },

    fn matches(identity: Identity, object: json.Value) bool {
        return switch (identity.expected) {
            .hash => |hash| if (string_hash(object, identity.field)) |actual|
                std.mem.eql(u8, &actual, &hash)
            else
                false,
            .quantity => |quantity| string_quantity(object, identity.field) == quantity,
        };
    }
};

/// A block/header/transaction object must carry `field` == `expected_ms` and the pinned
/// identity (base/base `check_wire_object`).
pub fn check_wire_object(
    report: *Report,
    name: []const u8,
    outcome: Outcome,
    field: []const u8,
    expected_ms: u64,
    identity: []const Identity,
) void {
    assert(field.len > 0);
    switch (outcome) {
        .method_error => |text| report.add(name, .fail, note("{s}", .{field}), text),
        .unavailable => |text| report.add(name, .indeterminate, note("{s}", .{field}), text),
        .value => |value| {
            if (value == .null) {
                const missing = note("known snapshot object missing", .{});
                return report.add(name, .fail, note("{s}", .{field}), missing);
            }
            const timestamp = string_quantity(value, field);
            var identity_matches = true;
            for (identity) |item| identity_matches = identity_matches and item.matches(value);
            const pass = timestamp == expected_ms and identity_matches;
            const expected = note("{s}=0x{x} with pinned identity", .{ field, expected_ms });
            const observed = if (timestamp) |actual|
                (if (identity_matches) note("0x{x}", .{actual}) else note("identity mismatch", .{}))
            else
                note("missing or invalid {s}", .{field});
            report.add(name, if (pass) .pass else .fail, expected, observed);
        },
    }
}

/// Running conformance over logs that must all be pinned to one block.
pub const LogTally = struct {
    count: u32 = 0,
    valid: bool = true,

    pub fn add(tally: *LogTally, logs: []const json.Value, expected_ms: u64, hash: [32]u8) void {
        for (logs) |log| {
            const hash_ok = if (string_hash(log, "blockHash")) |actual|
                std.mem.eql(u8, &actual, &hash)
            else
                false;
            const ms_ok = string_quantity(log, "blockTimestampMs") == expected_ms;
            tally.valid = tally.valid and hash_ok and ms_ok;
            tally.count +|= 1;
        }
        assert(tally.count >= logs.len or tally.count == std.math.maxInt(u32));
    }
};

/// Adds a log check from a tally (at least one log, all conformant).
pub fn finish_logs(report: *Report, name: []const u8, tally: LogTally) void {
    if (tally.count == 0) {
        const expected = note("at least one pinned log", .{});
        return report.add(name, .fail, expected, note("no logs in evidence block", .{}));
    }
    const expected = note("blockTimestampMs with pinned blockHash", .{});
    const observed = if (tally.valid)
        note("conformant", .{})
    else
        note("missing, wrong, or mismatched log field", .{});
    report.add(name, if (tally.valid) .pass else .fail, expected, observed);
}

/// A log array must be non-empty and every log pinned (base/base `check_wire_logs`).
pub fn check_wire_logs(
    report: *Report,
    name: []const u8,
    outcome: Outcome,
    expected_ms: u64,
    hash: [32]u8,
) void {
    const field = note("blockTimestampMs", .{});
    switch (outcome) {
        .method_error => |text| report.add(name, .fail, field, text),
        .unavailable => |text| report.add(name, .indeterminate, field, text),
        .value => |value| {
            if (value != .array) {
                return report.add(name, .fail, note("log array", .{}), note("invalid result", .{}));
            }
            var tally: LogTally = .{};
            tally.add(value.array.items, expected_ms, hash);
            finish_logs(report, name, tally);
        },
    }
}

/// Adds `names` as indeterminate with one reason.
pub fn add_indeterminate(
    report: *Report,
    names: []const []const u8,
    expected: []const u8,
    reason: []const u8,
) void {
    assert(names.len > 0);
    for (names) |name| report.add(name, .indeterminate, note("{s}", .{expected}), note(
        "{s}",
        .{reason},
    ));
}

// ------------------------------------------------------------------------- rendering

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.checks.count <= checks_max);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "schedule", "{t}", .{report.schedule});
    try types.row(writer, "block", "{d} {f}", .{ report.block_number, report.block_hash });
    try types.row(writer, "timestamp", "{d}", .{report.timestamp});
    try types.row(writer, "timestamp_ms", "{f}", .{types.optional_number(report.timestamp_ms)});
    if (report.activation) |activation| {
        try types.row(writer, "denim_activation", "{d}", .{activation});
    } else {
        try types.row(writer, "denim_activation", "not scheduled", .{});
    }
    try types.row(writer, "checks", "{d} pass, {d} fail, {d} indeterminate", .{
        report.count(.pass), report.count(.fail), report.count(.indeterminate),
    });
    try writer.writeByte('\n');
    for (report.checks.slice()) |*check| {
        try writer.print("{s:<13} {s}\n", .{ @tagName(check.status), check.name });
        if (check.status == .pass) continue;
        try writer.print("              expected: {s}\n", .{check.expected.slice()});
        try writer.print("              observed: {s}\n", .{check.observed.slice()});
    }
}

// ------------------------------------------------------------------------- tests

const testing = std.testing;

/// base/base `observations`: a canonical snapshot with millis part 200.
pub fn sample_observations(activation: ?u64, timestamp: u64) Observations {
    const part: u16 = 200;
    const ms = expected_timestamp_ms(timestamp, part);
    return .{
        .activation = activation,
        .block_number = 10,
        .block_hash = @splat(0),
        .timestamp = timestamp,
        .timestamp_ms = ms,
        .proxy_code_hash = proxy_code_hash,
        .admin = address_word(proxy_admin),
        .implementation = address_word(implementation_address),
        .implementation_code_hash = implementation_code_hash,
        .storage_millis_part = part,
        .metadata = .{ .ok = part },
        .metadata_receipt_valid = true,
        .getter_millis_part = .{ .ok = part },
        .getter_timestamp_ms = .{ .ok = ms },
    };
}

fn status_named(report: *Report, name: []const u8) Status {
    return report.find(name).?.status;
}

test "denim: constants match the execution side and the proxy bytecode" {
    const execution_base_time = @import("../../execution/node/base_time.zig");
    const execution = execution_base_time;
    try testing.expectEqualSlices(u8, &execution.implementation_address, &implementation_address);
    try testing.expectEqualSlices(
        u8,
        &execution.implementation_code_hash,
        &implementation_code_hash,
    );
    const implementation_digest = keccak.keccak256(&execution_base_time.implementation_code);
    try testing.expectEqualSlices(u8, &implementation_code_hash, &implementation_digest);
    const implementation_word = std.mem.readInt(u256, &implementation_slot, .big);
    try testing.expectEqual(execution.implementation_slot, implementation_word);
    try testing.expectEqual(execution.admin_slot, std.mem.readInt(u256, &admin_slot, .big));
    const proxy_file = @embedFile("../../batcher/devnet/base_time_proxy.hex");
    const proxy_hex = comptime std.mem.trimEnd(u8, proxy_file, "\n");
    var proxy_code: [proxy_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&proxy_code, proxy_hex);
    try testing.expectEqualSlices(u8, &proxy_code_hash, &keccak.keccak256(&proxy_code));
    try testing.expectEqualSlices(u8, &base_time.selector, &[_]u8{ 0x86, 0xbd, 0xf3, 0x94 });
}

test "denim: millis part decodes only the low uint16 of slot 0" {
    var word: [32]u8 = @splat(0xff);
    word[30] = 0x01;
    word[31] = 0x90;
    try testing.expectEqual(@as(u16, 400), decode_millis_part(word));
}

test "denim: schedule selection and inactive metadata are stable" {
    var unscheduled = evaluate(&sample_observations(null, 10));
    try testing.expectEqual(Schedule.not_scheduled, unscheduled.schedule);
    try testing.expect(!unscheduled.has_failures());
    try testing.expectEqual(@as(u16, 3), unscheduled.checks.count);
    const scheduled = evaluate(&sample_observations(20, 10));
    try testing.expectEqual(Schedule.scheduled, scheduled.schedule);
    // Before activation a broken proxy is indeterminate, never a failure.
    var broken = sample_observations(20, 10);
    broken.proxy_code_hash = @splat(1);
    var broken_report = evaluate(&broken);
    try testing.expectEqual(Status.indeterminate, status_named(&broken_report, "proxy_code_hash"));
    try testing.expect(!broken_report.has_failures());
}

test "denim: active snapshot requires canonical metadata and state" {
    var input = sample_observations(10, 10);
    var clean = evaluate(&input);
    try testing.expectEqual(Schedule.active, clean.schedule);
    try testing.expectEqual(@as(u32, 9), clean.count(.pass));
    input.storage_millis_part = 400;
    var report = evaluate(&input);
    try testing.expectEqual(Status.fail, status_named(&report, "storage_millis_part"));
    input = sample_observations(10, 10);
    input.metadata_receipt_valid = false;
    report = evaluate(&input);
    try testing.expectEqual(Status.fail, status_named(&report, "metadata_receipt"));
    try testing.expectEqualStrings("false", report.find("metadata_receipt").?.observed.slice());
}

test "denim: governance-changed implementation with code is permitted" {
    var input = sample_observations(10, 10);
    input.implementation = address_word(@as([20]u8, @splat(0)));
    input.implementation[31] = 1;
    input.implementation_code_hash = @splat(0);
    input.implementation_code_hash.?[31] = 1;
    var report = evaluate(&input);
    try testing.expectEqual(Status.pass, status_named(&report, "implementation"));
    try testing.expectEqualStrings("LinkedOther", report.find("implementation").?.observed.slice());
}

test "denim: malformed or empty implementation fails" {
    var malformed = sample_observations(10, 10);
    malformed.implementation[0] = 1;
    var empty = sample_observations(10, 10);
    empty.implementation = @splat(0);
    empty.implementation[31] = 1;
    empty.implementation_code_hash = keccak.empty_digest;
    var unavailable = empty;
    unavailable.implementation_code_hash = null;
    var wrong_initial = sample_observations(10, 10);
    wrong_initial.implementation_code_hash = @splat(7);
    for ([_]Observations{ malformed, empty, unavailable, wrong_initial }) |input| {
        var report = evaluate(&input);
        const check = report.find("implementation").?;
        try testing.expectEqual(Status.fail, check.status);
        try testing.expectEqualStrings("Inconsistent", check.observed.slice());
    }
    var dormant = sample_observations(10, 10);
    dormant.implementation = @splat(0);
    try testing.expectEqual(Implementation.dormant, classify_implementation(&dormant));
    var missing = dormant;
    missing.proxy_code_hash = keccak.empty_digest;
    try testing.expectEqual(Implementation.missing, classify_implementation(&missing));
    var bad_admin = sample_observations(10, 10);
    bad_admin.admin[31] ^= 1;
    try testing.expectEqual(Implementation.inconsistent, classify_implementation(&bad_admin));
}

test "denim: unavailable getters fail instead of comparing equal" {
    var input = sample_observations(10, 10);
    input.metadata = .{ .failed = note("missing metadata", .{}) };
    input.getter_millis_part = .{ .failed = note("execution reverted", .{}) };
    input.getter_timestamp_ms = .{ .failed = note("execution reverted", .{}) };
    var report = evaluate(&input);
    try testing.expectEqual(Status.fail, status_named(&report, "getter_millis_part"));
    try testing.expectEqual(Status.fail, status_named(&report, "getter_timestamp_ms"));
    try testing.expectEqualStrings(
        "execution reverted",
        report.find("getter_timestamp_ms").?.observed.slice(),
    );
    try testing.expectEqual(Status.fail, status_named(&report, "metadata"));
}

test "denim: timestamp comparison uses uint64 wrapping semantics" {
    const timestamp = std.math.maxInt(u64) / 1_000 + 1;
    var report = evaluate(&sample_observations(0, timestamp));
    try testing.expectEqual(Status.pass, status_named(&report, "header_timestamp_ms"));
    try testing.expectEqual(Status.pass, status_named(&report, "getter_timestamp_ms"));
    try testing.expectEqual(Status.pass, status_named(&report, "getter_millis_part"));
}

test "denim: report json carries the schedule and failure context" {
    var input = sample_observations(10, 10);
    input.metadata_receipt_valid = false;
    const report = evaluate(&input);
    var buffer: [8192]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try types.render_json(report, &writer);
    const out = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\"schedule\": \"active\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"name\": \"metadata_receipt\",\n" ++
        "      \"status\": \"fail\"") != null);
}

test "denim: cadence classifies boundary, exact gap, and wrong gap" {
    try testing.expectEqual(Status.indeterminate, cadence_status(null, 1_000, true));
    try testing.expectEqual(Status.pass, cadence_status(1_000, 1_200, true));
    try testing.expectEqual(Status.fail, cadence_status(1_000, 1_400, true));
    try testing.expectEqual(Status.indeterminate, cadence_status(1_000, 1_200, false));
    try testing.expectEqual(Status.fail, cadence_status(std.math.maxInt(u64), 199, true));
}

fn chain(blocks: []BlockFacts, newest: u64, timestamp_ms_newest: u64) void {
    for (blocks, 0..) |*block, index| {
        const number = newest - index;
        const ms = timestamp_ms_newest - index * block_interval_ms;
        block.* = .{
            .number = number,
            .hash = @splat(@intCast(number % 256)),
            .parent_hash = @splat(@intCast((number - 1) % 256)),
            .timestamp = ms / 1_000,
            .timestamp_ms = ms,
        };
    }
}

test "denim: cadence walk" {
    var blocks: [5]BlockFacts = undefined;
    chain(&blocks, 100, 50_000);
    const exact = evaluate_cadence(0, &blocks, true);
    try testing.expectEqual(Cadence{ .status = .pass, .edges = 4 }, exact);
    try testing.expectEqual(Status.indeterminate, evaluate_cadence(0, &blocks, false).status);
    try testing.expectEqual(Status.indeterminate, evaluate_cadence(0, blocks[0..1], true).status);
    // Activation at second 50: blocks 98..100 are active, 97 is legacy and its edge to
    // 98 is not checked.
    var boundary_blocks: [5]BlockFacts = undefined;
    chain(&boundary_blocks, 100, 50_400);
    const boundary = evaluate_cadence(50, &boundary_blocks, true);
    try testing.expectEqual(Cadence{ .status = .pass, .edges = 2 }, boundary);
    boundary_blocks[3].timestamp_ms = null;
    try testing.expectEqual(Status.pass, evaluate_cadence(50, &boundary_blocks, true).status);
    try testing.expectEqual(Status.indeterminate, evaluate_cadence(null, &blocks, true).status);
    var gap = blocks;
    gap[2].timestamp_ms.? -= 200;
    try testing.expectEqual(Status.fail, evaluate_cadence(0, &gap, true).status);
    var missing = blocks;
    missing[3].timestamp_ms = null;
    try testing.expectEqual(Status.fail, evaluate_cadence(0, &missing, false).status);
    var reorg = blocks;
    reorg[1].parent_hash = @splat(0xee);
    try testing.expectEqual(Status.indeterminate, evaluate_cadence(0, &reorg, true).status);
}

/// `text` repeated `times` times (the `**` operator is gone in Zig 0.17).
pub fn repeat(comptime text: []const u8, comptime times: usize) [text.len * times]u8 {
    var out: [text.len * times]u8 = undefined;
    for (0..times) |index| @memcpy(out[index * text.len ..][0..text.len], text);
    return out;
}

fn parse(arena: std.mem.Allocator, text: []const u8) !json.Value {
    return json.parseFromSliceLeaky(json.Value, arena, text, .{});
}

test "denim: raw object classifies field and method evidence" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var report = evaluate(&sample_observations(10, 10));
    const hash: [32]u8 = @splat(0x42);
    const identity = [_]Identity{.{ .field = "hash", .expected = .{ .hash = hash } }};
    const hash_hex = "\"0x" ++ repeat("42", 32) ++ "\"";
    check_wire_object(&report, "pass", .{ .value = try parse(arena, "{\"hash\":" ++ hash_hex ++
        ",\"timestampMs\":\"0x2710\"}") }, "timestampMs", 10_000, &identity);
    check_wire_object(&report, "missing", .{ .value = try parse(arena, "{\"hash\":" ++
        hash_hex ++ "}") }, "timestampMs", 10_000, &identity);
    const method: Outcome = .{ .method_error = note("boom", .{}) };
    check_wire_object(&report, "method", method, "timestampMs", 10_000, &identity);
    const served: Outcome = .{ .unavailable = note("method not served", .{}) };
    check_wire_object(&report, "served", served, "timestampMs", 10_000, &identity);
    check_wire_object(&report, "identity", .{ .value = try parse(arena, "{\"hash\":\"0x" ++
        repeat("43", 32) ++ "\",\"timestampMs\":\"0x2710\"}") }, "timestampMs", 10_000, &identity);
    check_wire_object(&report, "null", .{ .value = .null }, "timestampMs", 10_000, &identity);
    check_wire_logs(&report, "empty", .{ .value = try parse(arena, "[]") }, 10_000, hash);
    check_wire_logs(&report, "log", .{ .value = try parse(arena, "[{\"blockHash\":" ++ hash_hex ++
        ",\"blockTimestampMs\":\"0x2710\"}]") }, 10_000, hash);
    check_wire_logs(&report, "zero", .{ .value = try parse(arena, "[{\"blockHash\":" ++ hash_hex ++
        ",\"blockTimestampMs\":\"0x02710\"}]") }, 10_000, hash);
    const expected = [_]Status{
        .pass, .fail, .fail, .indeterminate, .fail, .fail, .fail, .pass, .fail,
    };
    for (expected, report.checks.slice()[9..]) |status, check| {
        try testing.expectEqual(status, check.status);
    }
    try testing.expectEqualStrings("identity mismatch", report.find("identity").?.observed.slice());
}

test "denim: parse quantity is strict" {
    try testing.expectEqual(@as(?u64, 0), parse_quantity("0x0"));
    try testing.expectEqual(@as(?u64, 0x2710), parse_quantity("0x2710"));
    try testing.expectEqual(@as(?u64, null), parse_quantity("0x"));
    try testing.expectEqual(@as(?u64, null), parse_quantity("0x00"));
    try testing.expectEqual(@as(?u64, null), parse_quantity("2710"));
    try testing.expectEqual(@as(?u64, null), parse_quantity("0x1" ++ repeat("0", 16)));
}

pub fn sample_deposit_json(buffer: []u8, block_number: u64, millis_part: u16) []const u8 {
    const calldata = base_time.encode_calldata(millis_part);
    const source = base_time.source_hash(block_number);
    return std.fmt.bufPrint(buffer,
        \\{{"type":"0x7e","hash":"0x{x}","sourceHash":"0x{x}",
        \\"from":"0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001","to":"0x{x}",
        \\"mint":"0x0","value":"0x0","gas":"0xf4240","isSystemTx":false,"input":"0x{x}"}}
    , .{ &@as([32]u8, @splat(0x11)), &source.bytes, &proxy_address, &calldata }) catch
        // Proof: callers pass at least 1 KiB; the object is under 400 bytes.
        unreachable;
}

test "denim: metadata from json validates the deposit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [1024]u8 = undefined;
    const tx = try parse(arena, sample_deposit_json(&buffer, 77, 600));
    try testing.expectEqual(@as(u16, 600), try metadata_from_json(tx, 77));
    try testing.expectError(error.InvalidSourceHash, metadata_from_json(tx, 78));
    try testing.expectError(error.Missing, metadata_from_json(null, 77));
    const legacy = try parse(arena, "{\"type\":\"0x2\"}");
    try testing.expectError(error.NotDeposit, metadata_from_json(legacy, 77));
    const bare = try parse(arena, "{\"type\":\"0x7e\"}");
    try testing.expectError(error.Malformed, metadata_from_json(bare, 77));
    try testing.expectEqualStrings("Malformed", metadata_error_text(error.Malformed));
}

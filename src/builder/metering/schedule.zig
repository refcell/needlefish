//! Resource-metering schedules and their transaction-cost evaluator. Mirrors base/base
//! `crates/execution/payload/src/resource_metering.rs` (`ResourceMeteringSchedule`,
//! `evaluate`, `check`, `decide_sample`, the JSON schedule file and its validation).
//!
//! A schedule reweights named observations of one transaction (actual gas used, opcode and
//! precompile gas/count rows, post-state `STATE_*` effects) into independent resource-unit
//! dimensions, each with a per-transaction and a cumulative per-block budget. Throttling
//! excludes a transaction when an enforced dimension is over budget; a `dryRun` dimension is
//! observed without excluding. Transaction-scope excludes are permanent (no block can hold
//! the transaction); block-scope excludes skip only the current build. Nothing here changes
//! protocol gas, fees or validity.
//!
//! The schedule is parsed once at startup into buffers sized by `Config` (no allocation
//! afterwards). Rules are kept sorted by normalized (trimmed, ASCII-uppercase) operation
//! name, so `evaluate` looks names up by binary search. Usage vectors are caller buffers
//! with one `u128` per dimension; arithmetic is checked and overflow fails open (base/base
//! `CalculationFailed`).

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");

pub const version_current: u32 = 1;
/// base/base `MAX_DIMENSIONS`, `MAX_DIMENSION_NAME_LENGTH`, `MAX_OPERATIONS_PER_DIMENSION`,
/// `MAX_OPERATION_NAME_LENGTH`.
pub const dimensions_max = 128;
pub const dimension_name_length_max = 64;
pub const operations_per_dimension_max = 512;
pub const operation_name_length_max = 128;

/// Post-state effects the builder counts from execution (base/base
/// `ResourceSample::EXECUTED_STATE_OPERATIONS`), in this order.
pub const state_operations = [_][]const u8{
    "STATE_NEW_STORAGE_SLOT",
    "STATE_CHANGED_STORAGE_SLOT",
    "STATE_CLEARED_STORAGE_SLOT",
    "STATE_TOUCHED_ACCOUNT",
    "STATE_CHANGED_ACCOUNT",
};

comptime {
    assert(dimensions_max <= std.math.maxInt(u8) + 1);
    assert(operation_name_length_max <= std.math.maxInt(u8));
    for (state_operations) |name| assert(name.len <= operation_name_length_max);
}

pub const Error = error{
    /// Malformed JSON, a wrong type, a missing required field, an unknown or duplicate field.
    ParseJson,
    UnsupportedVersion,
    TooManyDimensions,
    EmptyDimensionName,
    InvalidName,
    DuplicateDimension,
    NoopDimension,
    NoopOperation,
    ZeroBlockLimit,
    TransactionLimitExceedsBlock,
    /// Over `operations_per_dimension_max` in one dimension, or over `Config.rules_max` in all.
    TooManyOperations,
    DuplicateOperation,
};

pub const Config = struct {
    /// Operation rules across all dimensions (a needlefish bound for static allocation;
    /// base/base bounds only the per-dimension count).
    rules_max: u32 = 4096,
};

pub const Dimension = struct {
    name_buffer: [dimension_name_length_max]u8 = undefined,
    name_length: u8 = 0,
    /// The raw name was longer than the buffer (always an invalid name).
    name_overflow: bool = false,
    block_limit: u64,
    transaction_limit: u64,
    base_gas_weight: u64,
    dry_run: bool,
    /// Operation rules parsed for this dimension (may exceed what was stored).
    operation_count: u32 = 0,

    pub fn name(dimension: *const Dimension) []const u8 {
        assert(dimension.name_length <= dimension.name_buffer.len);
        return dimension.name_buffer[0..dimension.name_length];
    }
};

/// One operation price inside one dimension.
pub const Rule = struct {
    /// The raw name until `compile`, then the normalized name.
    name_buffer: [operation_name_length_max]u8 = undefined,
    name_length: u8 = 0,
    name_overflow: bool = false,
    dimension: u8,
    gas_used_weight: u64,
    count_cost: u64,

    pub fn name(rule: *const Rule) []const u8 {
        assert(rule.name_length <= rule.name_buffer.len);
        return rule.name_buffer[0..rule.name_length];
    }
};

/// One named observation of a transaction (base/base `OpcodeGas`).
pub const Observation = struct {
    name: []const u8,
    count: u64,
    gas_used: u64,
};

pub const Scope = enum { transaction, block };

/// base/base `ResourceThrottlingLimitExceeded`.
pub const LimitExceeded = struct {
    dimension: u8,
    scope: Scope,
    /// Block usage after adding the transaction, or the transaction's usage.
    used: u128,
    transaction_cost: u128,
    limit: u64,
    dry_run: bool,
};

pub const Check = union(enum) {
    ok,
    limit_exceeded: LimitExceeded,
    overflow,
};

/// base/base `ResourceThrottlingDecision`; the usage is in the caller's buffer.
pub const Decision = union(enum) {
    allow,
    throttle: LimitExceeded,
    calculation_failed,

    /// Throttles exclude unless dry-run; calculation failures fail open.
    pub fn should_exclude(decision: Decision) bool {
        return switch (decision) {
            .allow, .calculation_failed => false,
            .throttle => |limit| !limit.dry_run,
        };
    }

    /// An excluded transaction-scope overrun: the pool should evict it.
    pub fn is_permanent(decision: Decision) bool {
        return switch (decision) {
            .allow, .calculation_failed => false,
            .throttle => |limit| !limit.dry_run and limit.scope == .transaction,
        };
    }

    /// Whether the usage counts toward the block when the transaction is included
    /// (dry-run throttles do, so later enforced dimensions see the real remaining budget).
    pub fn has_usage(decision: Decision) bool {
        return decision != .calculation_failed;
    }
};

pub const Schedule = struct {
    version: u32 = version_current,
    dimensions: []Dimension,
    /// Dimensions in the file; may exceed `dimensions.len` (then `TooManyDimensions`).
    dimension_count: u32 = 0,
    rules: []Rule,
    /// Rules in the file; may exceed `rules.len` (then `TooManyOperations`).
    rule_count: u32 = 0,
    /// Whether each of `state_operations` is priced by some rule.
    priced_state: [state_operations.len]bool = @splat(false),

    /// An empty schedule (no dimensions: metering inactive) with room for `config`.
    pub fn init(allocator: std.mem.Allocator, config: Config) !Schedule {
        assert(config.rules_max > 0);
        const dimensions = try allocator.alloc(Dimension, dimensions_max);
        errdefer allocator.free(dimensions);
        const rules = try allocator.alloc(Rule, config.rules_max);
        const schedule: Schedule = .{ .dimensions = dimensions, .rules = rules };
        assert(schedule.is_empty());
        return schedule;
    }

    pub fn deinit(schedule: *Schedule, allocator: std.mem.Allocator) void {
        allocator.free(schedule.rules);
        allocator.free(schedule.dimensions);
        schedule.* = undefined;
    }

    pub fn is_empty(schedule: *const Schedule) bool {
        assert(schedule.dimensions.len == dimensions_max);
        return schedule.dimension_count == 0;
    }

    /// Stored dimensions (all of them once `load` succeeded).
    pub fn dimension_list(schedule: *const Schedule) []const Dimension {
        return schedule.dimensions[0..@min(schedule.dimension_count, schedule.dimensions.len)];
    }

    pub fn rule_list(schedule: *const Schedule) []const Rule {
        return schedule.rules[0..@min(schedule.rule_count, schedule.rules.len)];
    }

    /// Parses, validates and compiles a JSON schedule (base/base `from_json`). On error the
    /// schedule is left empty.
    pub fn load(schedule: *Schedule, text: []const u8) Error!void {
        schedule.reset();
        errdefer schedule.reset();
        var parser: Parser = .{ .scanner = json.Scanner.init(text), .schedule = schedule };
        try parser.top();
        try schedule.validate();
        schedule.compile();
        assert(schedule.dimension_count <= dimensions_max);
    }

    fn reset(schedule: *Schedule) void {
        schedule.version = version_current;
        schedule.dimension_count = 0;
        schedule.rule_count = 0;
        schedule.priced_state = @splat(false);
        assert(schedule.is_empty());
    }

    /// Calculates every dimension's cost for one transaction into `usage`
    /// (base/base `evaluate`). Unknown observation names are ignored.
    pub fn evaluate(
        schedule: *const Schedule,
        gas_used: u64,
        observations: []const Observation,
        usage: []u128,
    ) error{Overflow}!void {
        const dimensions = schedule.dimension_list();
        assert(usage.len >= dimensions.len);
        for (dimensions, 0..) |dimension, index| {
            usage[index] = @as(u128, dimension.base_gas_weight) * gas_used;
        }
        for (observations) |observation| {
            var buffer: [operation_name_length_max]u8 = undefined;
            const name = normalize(observation.name, &buffer) orelse continue;
            const rules = schedule.rule_list();
            var index = schedule.first_rule(name);
            while (index < rules.len) : (index += 1) {
                const rule = &rules[index];
                if (!std.mem.eql(u8, rule.name(), name)) break;
                const gas_cost = @as(u128, rule.gas_used_weight) * observation.gas_used;
                const count_cost = @as(u128, rule.count_cost) * observation.count;
                const cost = try std.math.add(u128, gas_cost, count_cost);
                const slot = &usage[rule.dimension];
                slot.* = try std.math.add(u128, slot.*, cost);
            }
        }
    }

    /// Index of the first rule named `name` (or where it would be).
    fn first_rule(schedule: *const Schedule, name: []const u8) usize {
        const rules = schedule.rule_list();
        var low: usize = 0;
        var high: usize = rules.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (std.mem.order(u8, rules[middle].name(), name) == .lt) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        assert(low <= rules.len);
        return low;
    }

    /// Checks transaction and cumulative block budgets (base/base `check`): enforced
    /// transaction-scope overruns rank first, then enforced block-scope, then the first
    /// dry-run overrun. `cumulative` may be shorter than the dimension list (zeros).
    pub fn check(schedule: *const Schedule, usage: []const u128, cumulative: []const u128) Check {
        var enforced_transaction: ?LimitExceeded = null;
        var enforced_block: ?LimitExceeded = null;
        var dry_run: ?LimitExceeded = null;
        const dimensions = schedule.dimension_list();
        assert(usage.len >= dimensions.len);
        for (dimensions, 0..) |dimension, index| {
            const cost = usage[index];
            var exceeded: LimitExceeded = .{
                .dimension = @intCast(index),
                .scope = .transaction,
                .used = cost,
                .transaction_cost = cost,
                .limit = dimension.transaction_limit,
                .dry_run = dimension.dry_run,
            };
            if (cost <= dimension.transaction_limit) {
                const before: u128 = if (index < cumulative.len) cumulative[index] else 0;
                const used = std.math.add(u128, before, cost) catch return .overflow;
                if (used <= dimension.block_limit) continue;
                exceeded.scope = .block;
                exceeded.used = used;
                exceeded.limit = dimension.block_limit;
            }
            const slot = if (dimension.dry_run)
                &dry_run
            else if (exceeded.scope == .transaction)
                &enforced_transaction
            else
                &enforced_block;
            if (slot.* == null) slot.* = exceeded;
        }
        const first = enforced_transaction orelse enforced_block orelse dry_run orelse return .ok;
        assert(first.used > first.limit);
        return .{ .limit_exceeded = first };
    }

    /// Evaluates and checks one sample (base/base `decide_sample`); `usage` receives the
    /// transaction's usage unless the calculation failed.
    pub fn decide(
        schedule: *const Schedule,
        gas_used: u64,
        observations: []const Observation,
        cumulative: []const u128,
        usage: []u128,
    ) Decision {
        schedule.evaluate(gas_used, observations, usage) catch return .calculation_failed;
        const result = schedule.check(usage, cumulative);
        return switch (result) {
            .ok => .allow,
            .limit_exceeded => |exceeded| .{ .throttle = exceeded },
            .overflow => .calculation_failed,
        };
    }

    /// Validates names, limits and prices (base/base `validate`, same order of checks).
    fn validate(schedule: *const Schedule) Error!void {
        if (schedule.version != version_current) return error.UnsupportedVersion;
        if (schedule.dimension_count > dimensions_max) return error.TooManyDimensions;
        const dimensions = schedule.dimension_list();
        var rule_index: usize = 0;
        for (dimensions, 0..) |*dimension, index| {
            try validate_name(dimension.name(), dimension.name_overflow, dimension_name_length_max);
            for (dimensions[0..index]) |*earlier| {
                if (std.ascii.eqlIgnoreCase(earlier.name(), dimension.name())) {
                    return error.DuplicateDimension;
                }
            }
            if (dimension.block_limit == 0) return error.ZeroBlockLimit;
            if (dimension.transaction_limit == 0) return error.NoopDimension;
            if (dimension.transaction_limit > dimension.block_limit) {
                return error.TransactionLimitExceedsBlock;
            }
            if (dimension.operation_count > operations_per_dimension_max) {
                return error.TooManyOperations;
            }
            if (rule_index + dimension.operation_count > schedule.rules.len) {
                return error.TooManyOperations;
            }
            const rules = schedule.rules[rule_index..][0..dimension.operation_count];
            rule_index += dimension.operation_count;
            try validate_rules(rules);
            if (dimension.base_gas_weight == 0 and rules.len == 0) return error.NoopDimension;
        }
        assert(rule_index == schedule.rule_count);
    }

    fn validate_rules(rules: []const Rule) Error!void {
        for (rules, 0..) |*rule, index| {
            try validate_name(rule.name(), rule.name_overflow, operation_name_length_max);
            if (rule.gas_used_weight == 0 and rule.count_cost == 0) return error.NoopOperation;
            for (rules[0..index]) |*earlier| {
                if (std.ascii.eqlIgnoreCase(earlier.name(), rule.name())) {
                    return error.DuplicateOperation;
                }
            }
        }
        assert(rules.len <= operations_per_dimension_max);
    }

    /// Normalizes rule names and sorts them for lookup; records priced `STATE_*` effects.
    fn compile(schedule: *Schedule) void {
        const rules = schedule.rules[0..schedule.rule_count];
        for (rules) |*rule| {
            // Valid names have no whitespace: normalizing is uppercasing in place.
            const name = rule.name_buffer[0..rule.name_length];
            for (name) |*byte| byte.* = std.ascii.toUpper(byte.*);
        }
        std.mem.sort(Rule, rules, {}, rule_less);
        for (state_operations, 0..) |operation, index| {
            const first = schedule.first_rule(operation);
            schedule.priced_state[index] = first < rules.len and
                std.mem.eql(u8, rules[first].name(), operation);
        }
        assert(schedule.rule_count == rules.len);
    }

    fn rule_less(_: void, left: Rule, right: Rule) bool {
        return switch (std.mem.order(u8, left.name(), right.name())) {
            .lt => true,
            .gt => false,
            .eq => left.dimension < right.dimension,
        };
    }
};

/// Adds `usage` to `cumulative` atomically: on overflow nothing is written
/// (base/base `ResourceMeteringUsage::add_to`).
pub fn add_usage(cumulative: []u128, usage: []const u128) error{Overflow}!void {
    assert(cumulative.len >= usage.len);
    for (usage, 0..) |value, index| _ = try std.math.add(u128, cumulative[index], value);
    for (usage, 0..) |value, index| cumulative[index] += value;
}

/// base/base `validate_name`: no surrounding or inner whitespace, non-empty, bounded.
fn validate_name(name: []const u8, overflow: bool, length_max: usize) Error!void {
    if (trim(name).len == 0 and !overflow) return error.EmptyDimensionName;
    if (overflow or name.len > length_max or has_whitespace(name)) return error.InvalidName;
    assert(name.len > 0);
}

/// Trimmed and ASCII-uppercased `name` in `buffer`, or null when it cannot match a rule.
fn normalize(name: []const u8, buffer: *[operation_name_length_max]u8) ?[]const u8 {
    const trimmed = trim(name);
    if (trimmed.len > buffer.len) return null;
    for (trimmed, 0..) |byte, index| buffer[index] = std.ascii.toUpper(byte);
    return buffer[0..trimmed.len];
}

/// Unicode `White_Space` (Rust `char::is_whitespace`).
fn is_whitespace(code_point: u21) bool {
    return switch (code_point) {
        0x09...0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a => true,
        0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}

/// Length of the UTF-8 sequence at `text[0]` and its code point; invalid bytes decode as a
/// single non-whitespace unit (the JSON scanner already validated strings).
fn decode(text: []const u8) struct { length: usize, code_point: u21 } {
    assert(text.len > 0);
    const length = std.unicode.utf8ByteSequenceLength(text[0]) catch 1;
    if (length > text.len) return .{ .length = 1, .code_point = 0xfffd };
    const code_point = std.unicode.utf8Decode(text[0..length]) catch 0xfffd;
    return .{ .length = length, .code_point = code_point };
}

fn has_whitespace(text: []const u8) bool {
    var index: usize = 0;
    while (index < text.len) {
        const unit = decode(text[index..]);
        if (is_whitespace(unit.code_point)) return true;
        index += unit.length;
    }
    return false;
}

/// Rust `str::trim`: strips Unicode whitespace from both ends.
pub fn trim(text: []const u8) []const u8 {
    var start: usize = 0;
    while (start < text.len) {
        const unit = decode(text[start..]);
        if (!is_whitespace(unit.code_point)) break;
        start += unit.length;
    }
    var end: usize = text.len;
    while (end > start) {
        var begin = end - 1;
        while (begin > start and text[begin] & 0xc0 == 0x80) begin -= 1;
        const unit = decode(text[begin..end]);
        if (!is_whitespace(unit.code_point)) break;
        end = begin;
    }
    assert(start <= end);
    return text[start..end];
}

/// Strict JSON reader for the schedule file (serde `deny_unknown_fields`, no duplicate
/// fields, u64 integers only).
const Parser = struct {
    scanner: json.Scanner,
    schedule: *Schedule,

    fn next(parser: *Parser) Error!json.Token {
        return parser.scanner.next() catch error.ParseJson;
    }

    fn expect(parser: *Parser, tag: json.TokenTag) Error!void {
        const token = try parser.next();
        if (token.tag != tag) return error.ParseJson;
    }

    /// The next object key, or null at the object's end.
    fn key(parser: *Parser, buffer: []u8) Error!?[]const u8 {
        const token = try parser.next();
        if (token.tag == .object_end) return null;
        if (token.tag != .string or !token.key) return error.ParseJson;
        return json.unescape(token, buffer) catch error.ParseJson;
    }

    fn integer(parser: *Parser, comptime T: type) Error!T {
        const token = try parser.next();
        if (token.tag != .number) return error.ParseJson;
        if (token.bytes.len == 0 or !std.ascii.isDigit(token.bytes[0])) return error.ParseJson;
        return std.fmt.parseInt(T, token.bytes, 10) catch error.ParseJson;
    }

    fn boolean(parser: *Parser) Error!bool {
        const token = try parser.next();
        return switch (token.tag) {
            .true => true,
            .false => false,
            else => error.ParseJson,
        };
    }

    /// An optional u64 (`null` is absent, as serde `Option` with `default`).
    fn optional_integer(parser: *Parser) Error!?u64 {
        const token = try parser.next();
        if (token.tag == .null) return null;
        if (token.tag != .number) return error.ParseJson;
        if (token.bytes.len == 0 or !std.ascii.isDigit(token.bytes[0])) return error.ParseJson;
        return std.fmt.parseInt(u64, token.bytes, 10) catch error.ParseJson;
    }

    /// A string into `buffer`; `overflow` when it did not fit (the stored part is cut).
    fn string(parser: *Parser, buffer: []u8, length: *u8, overflow: *bool) Error!void {
        const token = try parser.next();
        if (token.tag != .string) return error.ParseJson;
        var scratch: [512]u8 = undefined;
        const text = json.unescape(token, &scratch) catch |err| switch (err) {
            error.NoSpaceLeft => {
                overflow.* = true;
                length.* = 0;
                return;
            },
            error.InvalidString => return error.ParseJson,
        };
        overflow.* = text.len > buffer.len;
        const stored = text[0..@min(text.len, buffer.len)];
        @memcpy(buffer[0..stored.len], stored);
        length.* = @intCast(stored.len);
    }

    fn top(parser: *Parser) Error!void {
        try parser.expect(.object_begin);
        var seen_version = false;
        var seen_dimensions = false;
        var buffer: [32]u8 = undefined;
        // Each key consumes input bytes; the scanner bounds the loop by the input length.
        while (try parser.key(&buffer)) |name| {
            if (std.mem.eql(u8, name, "version") and !seen_version) {
                parser.schedule.version = try parser.integer(u32);
                seen_version = true;
            } else if (std.mem.eql(u8, name, "dimensions") and !seen_dimensions) {
                try parser.dimension_array();
                seen_dimensions = true;
            } else return error.ParseJson;
        }
        if (!seen_version) return error.ParseJson;
        try parser.expect(.end);
    }

    fn dimension_array(parser: *Parser) Error!void {
        try parser.expect(.array_begin);
        while (true) {
            const token = try parser.next();
            if (token.tag == .array_end) return;
            if (token.tag != .object_begin) return error.ParseJson;
            try parser.dimension_object();
        }
    }

    const DimensionField = enum {
        name,
        block_limit,
        transaction_limit,
        base_gas_weight,
        operations,
        dry_run,

        const keys = [_][]const u8{
            "name", "blockLimit", "transactionLimit", "baseGasWeight", "operations", "dryRun",
        };

        fn of(text: []const u8) ?DimensionField {
            for (keys, 0..) |candidate, index| {
                if (std.mem.eql(u8, candidate, text)) return @fromBackingInt(@intCast(index));
            }
            return null;
        }
    };

    /// One dimension object (its `{` already read); stored while there is room.
    fn dimension_object(parser: *Parser) Error!void {
        const schedule = parser.schedule;
        var scratch: Dimension = .{
            .block_limit = 0,
            .transaction_limit = 0,
            .base_gas_weight = 0,
            .dry_run = false,
        };
        const stored = schedule.dimension_count < schedule.dimensions.len;
        const target = if (stored) &schedule.dimensions[schedule.dimension_count] else &scratch;
        target.* = scratch;
        schedule.dimension_count +|= 1;
        var transaction_limit: ?u64 = null;
        var seen: std.EnumSet(DimensionField) = .empty;
        var buffer: [32]u8 = undefined;
        while (try parser.key(&buffer)) |name| {
            const field = DimensionField.of(name) orelse return error.ParseJson;
            if (seen.contains(field)) return error.ParseJson;
            seen.insert(field);
            switch (field) {
                .name => try parser.string(
                    &target.name_buffer,
                    &target.name_length,
                    &target.name_overflow,
                ),
                .block_limit => target.block_limit = try parser.integer(u64),
                .transaction_limit => transaction_limit = try parser.optional_integer(),
                .base_gas_weight => target.base_gas_weight = try parser.integer(u64),
                .operations => try parser.operation_array(target, stored),
                .dry_run => target.dry_run = try parser.boolean(),
            }
        }
        const required = [_]DimensionField{ .name, .block_limit, .dry_run };
        for (required) |field| if (!seen.contains(field)) return error.ParseJson;
        target.transaction_limit = transaction_limit orelse target.block_limit;
    }

    fn operation_array(parser: *Parser, dimension: *Dimension, stored: bool) Error!void {
        const schedule = parser.schedule;
        const index: u8 = @intCast(@min(schedule.dimension_count - 1, dimensions_max - 1));
        try parser.expect(.array_begin);
        while (true) {
            const token = try parser.next();
            if (token.tag == .array_end) return;
            if (token.tag != .object_begin) return error.ParseJson;
            var scratch: Rule = .{ .dimension = index, .gas_used_weight = 0, .count_cost = 0 };
            const room = stored and schedule.rule_count < schedule.rules.len;
            const rule = if (room) &schedule.rules[schedule.rule_count] else &scratch;
            rule.* = scratch;
            if (stored) schedule.rule_count +|= 1;
            dimension.operation_count +|= 1;
            try parser.operation_object(rule);
        }
    }

    fn operation_object(parser: *Parser, rule: *Rule) Error!void {
        var seen_name = false;
        var seen_gas = false;
        var seen_count = false;
        var buffer: [32]u8 = undefined;
        while (try parser.key(&buffer)) |name| {
            if (std.mem.eql(u8, name, "name") and !seen_name) {
                try parser.string(&rule.name_buffer, &rule.name_length, &rule.name_overflow);
                seen_name = true;
            } else if (std.mem.eql(u8, name, "gasUsedWeight") and !seen_gas) {
                rule.gas_used_weight = try parser.integer(u64);
                seen_gas = true;
            } else if (std.mem.eql(u8, name, "countCost") and !seen_count) {
                rule.count_cost = try parser.integer(u64);
                seen_count = true;
            } else return error.ParseJson;
        }
        if (!seen_name) return error.ParseJson;
    }
};

test {
    _ = @import("schedule_test.zig");
}

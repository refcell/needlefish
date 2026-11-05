//! Zero-allocation command-line flags driven by a spec struct.
//!
//! Each field of the spec is one flag: `http_port: u16 = 8545` becomes `--http-port <u16>`,
//! with environment fallback `<PREFIX>HTTP_PORT` (the binary picks the prefix, e.g.
//! `BASE_NODE_`). Precedence: command line, then environment, then the field default; a
//! field without a default is required. Supported types: `bool`, integers, `[]const u8`,
//! enums, and optionals of those. String values are slices into argv or the environment, so
//! nothing is copied. A spec may declare `pub const help = .{ .field = "text" }`.
//!
//! The environment is injected as a lookup function, so tests and the simulator never read
//! the real process environment.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    UnknownFlag,
    MissingValue,
    InvalidValue,
    MissingRequired,
    DuplicateFlag,
    UnexpectedArgument,
    HelpRequested,
};

/// Looks up an environment variable by name.
pub const Env = struct {
    context: ?*const anyopaque = null,
    get: *const fn (context: ?*const anyopaque, name: []const u8) ?[]const u8 = no_env,

    fn no_env(context: ?*const anyopaque, name: []const u8) ?[]const u8 {
        _ = context;
        _ = name;
        return null;
    }

    /// Wraps a `std.process.Environ.Map` (from `std.process.Init.environ_map`).
    pub fn from_map(map: *const std.process.Environ.Map) Env {
        return .{ .context = map, .get = get_map };
    }

    fn get_map(context: ?*const anyopaque, name: []const u8) ?[]const u8 {
        const map: *const std.process.Environ.Map = @ptrCast(@alignCast(context.?));
        return map.get(name);
    }
};

pub const Diagnostic = struct {
    /// The argument or environment variable that caused the error.
    subject: []const u8 = "",
};

const name_size_max = 64;

fn flag_name(comptime field: []const u8) []const u8 {
    comptime {
        assert(field.len < name_size_max);
        var name: [field.len]u8 = undefined;
        for (field, 0..) |byte, index| name[index] = if (byte == '_') '-' else byte;
        const final = name;
        return &final;
    }
}

fn env_name(comptime prefix: []const u8, comptime field: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(100 * (prefix.len + field.len) + 1000);
        var name: [prefix.len + field.len]u8 = undefined;
        @memcpy(name[0..prefix.len], prefix);
        for (field, 0..) |byte, index| name[prefix.len + index] = std.ascii.toUpper(byte);
        const final = name;
        return &final;
    }
}

/// Parses `args` (without the program name) into a `Spec`.
pub fn parse(
    comptime Spec: type,
    comptime env_prefix: []const u8,
    args: []const []const u8,
    env: Env,
    diagnostic: *Diagnostic,
) Error!Spec {
    const fields = @typeInfo(Spec).@"struct";
    var seen: [fields.field_names.len]bool = @splat(false);
    var result: Spec = undefined;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        diagnostic.subject = arg;
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            return error.HelpRequested;
        }
        if (!std.mem.startsWith(u8, arg, "--") or arg.len == 2) return error.UnexpectedArgument;
        const body = arg[2..];
        const equals = std.mem.findScalar(u8, body, '=');
        const name = body[0 .. equals orelse body.len];
        const inline_value: ?[]const u8 = if (equals) |e| body[e + 1 ..] else null;
        const matched = inline for (fields.field_names, fields.field_types, 0..) |field, T, i| {
            if (std.mem.eql(u8, name, comptime flag_name(field))) {
                if (seen[i]) return error.DuplicateFlag;
                seen[i] = true;
                const value_text = try take_value(T, inline_value, args, &index);
                @field(result, field) = try parse_value(T, value_text);
                break true;
            }
        } else false;
        if (!matched) return error.UnknownFlag;
    }
    try fill_unset(Spec, env_prefix, &result, &seen, env, diagnostic);
    return result;
}

fn take_value(
    comptime T: type,
    inline_value: ?[]const u8,
    args: []const []const u8,
    index: *usize,
) Error![]const u8 {
    if (inline_value) |value| return value;
    // A bare boolean flag means true.
    if (Base(T) == bool) return "true";
    if (index.* + 1 >= args.len) return error.MissingValue;
    index.* += 1;
    return args[index.*];
}

fn fill_unset(
    comptime Spec: type,
    comptime env_prefix: []const u8,
    result: *Spec,
    seen: []const bool,
    env: Env,
    diagnostic: *Diagnostic,
) Error!void {
    const fields = @typeInfo(Spec).@"struct";
    inline for (fields.field_names, fields.field_types, fields.field_attrs, 0..) |
        field,
        T,
        attrs,
        i,
    | {
        if (!seen[i]) {
            const variable = comptime env_name(env_prefix, field);
            if (env.get(env.context, variable)) |text| {
                diagnostic.subject = variable;
                @field(result, field) = try parse_value(T, text);
            } else if (comptime attrs.defaultValue(T)) |default| {
                @field(result, field) = default;
            } else if (@typeInfo(T) == .optional) {
                @field(result, field) = null;
            } else {
                diagnostic.subject = comptime "--" ++ flag_name(field);
                return error.MissingRequired;
            }
        }
    }
}

fn Base(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .optional => |o| o.child,
        else => T,
    };
}

fn parse_value(comptime T: type, text: []const u8) Error!T {
    const B = Base(T);
    if (B == []const u8) return text;
    return switch (@typeInfo(B)) {
        .bool => parse_bool(text),
        .int => parse_int(B, text),
        .@"enum" => std.meta.stringToEnum(B, text) orelse error.InvalidValue,
        else => @compileError("cli: unsupported flag type " ++ @typeName(T)),
    };
}

fn parse_bool(text: []const u8) Error!bool {
    if (std.mem.eql(u8, text, "true") or std.mem.eql(u8, text, "1")) return true;
    if (std.mem.eql(u8, text, "false") or std.mem.eql(u8, text, "0")) return false;
    return error.InvalidValue;
}

/// Decimal, or hex with a `0x` prefix (chain ids, gas limits).
fn parse_int(comptime T: type, text: []const u8) Error!T {
    if (text.len > 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
        return std.fmt.parseInt(T, text[2..], 16) catch error.InvalidValue;
    }
    return std.fmt.parseInt(T, text, 10) catch error.InvalidValue;
}

/// Writes usage text for `Spec`.
pub fn write_help(
    comptime Spec: type,
    comptime env_prefix: []const u8,
    out: *std.Io.Writer,
) std.Io.Writer.Error!void {
    const fields = @typeInfo(Spec).@"struct";
    try out.writeAll("Options:\n");
    inline for (fields.field_names, fields.field_types, fields.field_attrs) |field, T, attrs| {
        const placeholder = comptime type_placeholder(T);
        try out.print("  --{s}{s}\n", .{ comptime flag_name(field), placeholder });
        if (@hasDecl(Spec, "help") and @hasField(@TypeOf(Spec.help), field)) {
            try out.print("      {s}\n", .{@field(Spec.help, field)});
        }
        try out.print("      [env: {s}]", .{comptime env_name(env_prefix, field)});
        if (comptime attrs.defaultValue(T)) |default| {
            try write_default(T, out, default);
        } else if (@typeInfo(T) != .optional) {
            try out.writeAll(" [required]");
        }
        try out.writeByte('\n');
    }
}

fn type_placeholder(comptime T: type) []const u8 {
    const B = Base(T);
    if (B == bool) return "";
    if (B == []const u8) return " <string>";
    return switch (@typeInfo(B)) {
        .int => " <" ++ @typeName(B) ++ ">",
        .@"enum" => |e| blk: {
            var text: []const u8 = " <";
            for (e.field_names, 0..) |name, index| {
                text = text ++ (if (index == 0) "" else "|") ++ name;
            }
            break :blk text ++ ">";
        },
        else => @compileError("cli: unsupported flag type"),
    };
}

fn write_default(comptime T: type, out: *std.Io.Writer, value: T) std.Io.Writer.Error!void {
    const B = Base(T);
    if (@typeInfo(T) == .optional) {
        const inner = value orelse return;
        return write_default(B, out, inner);
    }
    if (B == []const u8) return out.print(" [default: {s}]", .{value});
    switch (@typeInfo(B)) {
        .bool, .int => try out.print(" [default: {any}]", .{value}),
        .@"enum" => try out.print(" [default: {s}]", .{@tagName(value)}),
        else => unreachable,
    }
}

const TestSpec = struct {
    http_port: u16 = 8545,
    chain_id: u64,
    jwt_secret: ?[]const u8,
    log_level: enum { trace, debug, info, warn, err } = .info,
    sequencer: bool = false,
    pub const help = .{ .http_port = "HTTP JSON-RPC port." };
};

const TestEnv = struct {
    fn get(context: ?*const anyopaque, name: []const u8) ?[]const u8 {
        _ = context;
        if (std.mem.eql(u8, name, "NODE_CHAIN_ID")) return "0x2105";
        if (std.mem.eql(u8, name, "NODE_HTTP_PORT")) return "9000";
        return null;
    }
};

test "cli: flags, env fallback, defaults" {
    var diagnostic: Diagnostic = .{};
    const env: Env = .{ .get = TestEnv.get };
    const args = [_][]const u8{ "--http-port=7000", "--sequencer", "--log-level", "debug" };
    const spec = try parse(TestSpec, "NODE_", &args, env, &diagnostic);
    try std.testing.expectEqual(@as(u16, 7000), spec.http_port); // Flag beats env.
    try std.testing.expectEqual(@as(u64, 8453), spec.chain_id); // From env (hex).
    try std.testing.expectEqual(@as(?[]const u8, null), spec.jwt_secret);
    try std.testing.expect(spec.sequencer);
    try std.testing.expectEqual(.debug, spec.log_level);

    const defaults = try parse(TestSpec, "NODE_", &.{"--chain-id=1"}, .{}, &diagnostic);
    try std.testing.expectEqual(@as(u16, 8545), defaults.http_port);
    try std.testing.expect(!defaults.sequencer);
}

test "cli: errors carry the offending argument" {
    var diagnostic: Diagnostic = .{};
    const cases = [_]struct { []const []const u8, Error, []const u8 }{
        .{ &.{"--nope"}, error.UnknownFlag, "--nope" },
        .{ &.{"--chain-id"}, error.MissingValue, "--chain-id" },
        .{ &.{"--chain-id=x"}, error.InvalidValue, "--chain-id=x" },
        .{ &.{}, error.MissingRequired, "--chain-id" },
        .{ &.{ "--chain-id=1", "--chain-id=2" }, error.DuplicateFlag, "--chain-id=2" },
        .{ &.{"positional"}, error.UnexpectedArgument, "positional" },
        .{ &.{ "--chain-id=1", "--sequencer=maybe" }, error.InvalidValue, "--sequencer=maybe" },
        .{ &.{"--help"}, error.HelpRequested, "--help" },
    };
    for (cases) |case| {
        try std.testing.expectError(case[1], parse(TestSpec, "NODE_", case[0], .{}, &diagnostic));
        try std.testing.expectEqualStrings(case[2], diagnostic.subject);
    }
}

test "cli: help text" {
    var buffer: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&buffer);
    try write_help(TestSpec, "NODE_", &out);
    try std.testing.expectEqualStrings(
        \\Options:
        \\  --http-port <u16>
        \\      HTTP JSON-RPC port.
        \\      [env: NODE_HTTP_PORT] [default: 8545]
        \\  --chain-id <u64>
        \\      [env: NODE_CHAIN_ID] [required]
        \\  --jwt-secret <string>
        \\      [env: NODE_JWT_SECRET]
        \\  --log-level <trace|debug|info|warn|err>
        \\      [env: NODE_LOG_LEVEL] [default: info]
        \\  --sequencer
        \\      [env: NODE_SEQUENCER] [default: false]
        \\
    , out.buffered());
}

test "cli: seeded fuzz never crashes" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xc11);
    const pieces = [_][]const u8{
        "--http-port", "--chain-id", "--jwt-secret", "--log-level", "--sequencer", "=", "1",
        "0x",          "ffff",       "65536",        "debug",       "true",        "-", "",
        "--",          "x",
    };
    var storage: [8][32]u8 = undefined;
    var args: [8][]const u8 = undefined;
    for (0..3000) |_| {
        const count = prng.below(args.len + 1);
        for (0..count) |index| {
            var size: usize = 0;
            for (0..prng.range(1, 3)) |_| {
                const piece = pieces[prng.below(pieces.len)];
                if (size + piece.len > storage[index].len) break;
                @memcpy(storage[index][size..][0..piece.len], piece);
                size += piece.len;
            }
            args[index] = storage[index][0..size];
        }
        var diagnostic: Diagnostic = .{};
        _ = parse(TestSpec, "NODE_", args[0..count], .{}, &diagnostic) catch {};
    }
}

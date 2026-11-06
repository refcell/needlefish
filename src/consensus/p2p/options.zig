//! `--p2p.*` command-line options with base/base defaults (`crates/consensus/cli/src/p2p.rs`).
//!
//! `parse` reads `--p2p.name=value` or `--p2p.name value` pairs, ignores arguments that do
//! not start with `--p2p.` (other parsers own them), and rejects unknown `--p2p.` names.
//! Boolean flags accept a bare `--p2p.name` as true. Values borrow from `args`.
//! File paths (`--p2p.priv.path`, `--p2p.bootnodes-file`) are only recorded: the binary
//! reads files, library code takes contents.

const std = @import("std");
const assert = std.debug.assert;
const ip = @import("peers/ip.zig");
const score = @import("peers/score.zig");
const primitives = @import("../../common/primitives/root.zig");

pub const bootnodes_max = 64;

pub const Options = struct {
    no_discovery: bool = false,
    priv_path: ?[]const u8 = null,
    /// Hex secp256k1 secret (`--p2p.priv.raw`).
    priv_raw: ?[]const u8 = null,
    advertise_ip: ?ip.Address = null,
    advertise_tcp: ?u16 = null,
    advertise_udp: ?u16 = null,
    listen_ip: ip.Address = .{ .ip4 = .{ 0, 0, 0, 0 } },
    listen_tcp: u16 = 9222,
    listen_udp: u16 = 9223,
    peers_hi: u32 = 30,
    max_pending_outgoing: u32 = 16,
    gossip_mesh_d: u32 = 8,
    gossip_mesh_lo: u32 = 6,
    gossip_mesh_dhi: u32 = 12,
    gossip_mesh_dlazy: u32 = 6,
    scoring: score.Level = .light,
    topic_scoring: bool = false,
    ban_peers: bool = false,
    ban_threshold: i64 = -100,
    ban_duration_min: u64 = 60,
    discovery_interval_s: u64 = 5,
    redial: u32 = 500,
    redial_period_min: u64 = 60,
    pending_dial_timeout_s: u64 = 30,
    /// Re-dial known unconnected nodes every this many seconds; 0 is off (needlefish only,
    /// for nodes without inbound reachability: `Service.Config.redial_known_interval_ns`).
    redial_known_interval_s: u64 = 0,
    bootnodes: [bootnodes_max][]const u8 = undefined,
    bootnodes_count: u32 = 0,
    bootnodes_file: ?[]const u8 = null,
    /// Bootstore JSON path (`--p2p.bootstore`); the binary reads and writes it.
    bootstore: ?[]const u8 = null,
    no_bootstore: bool = false,
    unsafe_block_signer: ?primitives.Address = null,

    pub fn bootnode_slice(options: *const Options) []const []const u8 {
        assert(options.bootnodes_count <= bootnodes_max);
        return options.bootnodes[0..options.bootnodes_count];
    }
};

pub const Error = error{ UnknownFlag, MissingValue, InvalidValue, TooManyBootnodes };

/// Parses every `--p2p.*` argument in `args` over the defaults.
pub fn parse(args: []const []const u8) Error!Options {
    var options: Options = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (!std.mem.startsWith(u8, arg, "--p2p.")) continue;
        const body = arg["--p2p.".len..];
        const equals = std.mem.indexOfScalar(u8, body, '=');
        const name = if (equals) |at| body[0..at] else body;
        var value: ?[]const u8 = if (equals) |at| body[at + 1 ..] else null;
        if (value == null and !is_bool(name)) {
            if (index + 1 >= args.len) return error.MissingValue;
            index += 1;
            value = args[index];
        }
        try apply(&options, name, value);
    }
    assert(options.bootnodes_count <= bootnodes_max);
    return options;
}

const bool_flags = [_][]const u8{
    "no-discovery", "scoring.topics", "topic-scoring", "ban.peers", "no-bootstore",
};

pub fn is_bool(name: []const u8) bool {
    for (bool_flags) |flag| if (std.mem.eql(u8, flag, name)) return true;
    return false;
}

fn apply(options: *Options, name: []const u8, value: ?[]const u8) Error!void {
    if (is_bool(name)) return apply_bool(options, name, try parse_bool(value));
    const text = value orelse return error.MissingValue;
    if (try apply_number(options, name, text)) return;
    if (eql(name, "priv.path")) {
        options.priv_path = text;
    } else if (eql(name, "priv.raw")) {
        options.priv_raw = text;
    } else if (eql(name, "advertise.ip")) {
        options.advertise_ip = try parse_ip(text);
    } else if (eql(name, "listen.ip")) {
        options.listen_ip = try parse_ip(text);
    } else if (eql(name, "scoring")) {
        options.scoring = std.meta.stringToEnum(score.Level, text) orelse
            return error.InvalidValue;
    } else if (eql(name, "bootnodes")) {
        try add_bootnodes(options, text);
    } else if (eql(name, "bootnodes-file")) {
        options.bootnodes_file = text;
    } else if (eql(name, "bootstore")) {
        options.bootstore = text;
    } else if (eql(name, "unsafe.block.signer")) {
        options.unsafe_block_signer = primitives.Address.from_hex(text) catch
            return error.InvalidValue;
    } else return error.UnknownFlag;
}

fn apply_bool(options: *Options, name: []const u8, value: bool) void {
    if (eql(name, "no-discovery")) options.no_discovery = value;
    if (eql(name, "scoring.topics") or eql(name, "topic-scoring")) options.topic_scoring = value;
    if (eql(name, "ban.peers")) options.ban_peers = value;
    if (eql(name, "no-bootstore")) options.no_bootstore = value;
}

/// Returns true when `name` is a numeric option (and stores it).
fn apply_number(options: *Options, name: []const u8, text: []const u8) Error!bool {
    const Field = struct { name: []const u8, field: []const u8 };
    const fields = [_]Field{
        .{ .name = "advertise.tcp", .field = "advertise_tcp" },
        .{ .name = "advertise.udp", .field = "advertise_udp" },
        .{ .name = "listen.tcp", .field = "listen_tcp" },
        .{ .name = "listen.udp", .field = "listen_udp" },
        .{ .name = "peers.hi", .field = "peers_hi" },
        .{ .name = "max-pending-outgoing", .field = "max_pending_outgoing" },
        .{ .name = "gossip.mesh.d", .field = "gossip_mesh_d" },
        .{ .name = "gossip.mesh.lo", .field = "gossip_mesh_lo" },
        .{ .name = "gossip.mesh.dhi", .field = "gossip_mesh_dhi" },
        .{ .name = "gossip.mesh.dlazy", .field = "gossip_mesh_dlazy" },
        .{ .name = "ban.threshold", .field = "ban_threshold" },
        .{ .name = "ban.duration", .field = "ban_duration_min" },
        .{ .name = "discovery.interval", .field = "discovery_interval_s" },
        .{ .name = "redial", .field = "redial" },
        .{ .name = "redial.period", .field = "redial_period_min" },
        .{ .name = "pending-dial.timeout", .field = "pending_dial_timeout_s" },
        .{ .name = "redial.known-interval", .field = "redial_known_interval_s" },
    };
    inline for (fields) |entry| {
        if (eql(name, entry.name)) {
            const Target = @FieldType(Options, entry.field);
            const Int = switch (@typeInfo(Target)) {
                .optional => |info| info.child,
                else => Target,
            };
            @field(options, entry.field) = std.fmt.parseInt(Int, text, 10) catch
                return error.InvalidValue;
            return true;
        }
    }
    return false;
}

fn parse_bool(value: ?[]const u8) Error!bool {
    const text = value orelse return true;
    if (eql(text, "true")) return true;
    if (eql(text, "false")) return false;
    return error.InvalidValue;
}

fn parse_ip(text: []const u8) Error!ip.Address {
    return ip.parse(text) catch error.InvalidValue;
}

/// Comma-separated ENR or enode strings; repeated flags append.
fn add_bootnodes(options: *Options, text: []const u8) Error!void {
    var parts = std.mem.tokenizeScalar(u8, text, ',');
    while (parts.next()) |part| {
        if (options.bootnodes_count == bootnodes_max) return error.TooManyBootnodes;
        options.bootnodes[options.bootnodes_count] = std.mem.trim(u8, part, " ");
        options.bootnodes_count += 1;
    }
}

/// Adds bootnodes from `--p2p.bootnodes-file` contents: one ENR or enode per line, or a
/// JSON array of strings (base/base accepts both). Blank lines and `#` comments are
/// skipped. Entries borrow from `contents`, which must outlive `options`.
pub fn add_bootnodes_file(options: *Options, contents: []const u8) Error!void {
    const trimmed = std.mem.trim(u8, contents, " \t\r\n");
    const is_json = trimmed.len > 0 and trimmed[0] == '[';
    var lines = std.mem.tokenizeAny(u8, if (is_json) trimmed[1..] else trimmed, "\r\n,]");
    var processed: u32 = 0;
    while (lines.next()) |line| : (processed += 1) {
        assert(processed <= contents.len);
        const entry = std.mem.trim(u8, line, " \t\"");
        if (entry.len == 0 or entry[0] == '#') continue;
        if (options.bootnodes_count == bootnodes_max) return error.TooManyBootnodes;
        options.bootnodes[options.bootnodes_count] = entry;
        options.bootnodes_count += 1;
    }
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// --------------------------------------------------------------------------- tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const fuzz = @import("../../testing/fuzz.zig");

test "options: defaults match base/base" {
    const options = try parse(&.{});
    try testing.expectEqual(@as(u16, 9222), options.listen_tcp);
    try testing.expectEqual(@as(u16, 9223), options.listen_udp);
    try testing.expectEqual(@as(u32, 30), options.peers_hi);
    try testing.expectEqual(@as(u32, 500), options.redial);
    try testing.expect(!options.ban_peers and !options.topic_scoring);
    try testing.expectEqual(score.Level.light, options.scoring);
}

test "options: parses both value forms, bools, lists, and skips other flags" {
    const args = [_][]const u8{
        "--l1",
        "http://l1",
        "--p2p.listen.tcp=30303",
        "--p2p.listen.ip",
        "10.1.2.3",
        "--p2p.ban.peers",
        "--p2p.ban.threshold=-50",
        "--p2p.bootnodes=enr:-a, enode://b",
        "--p2p.bootnodes",
        "enr:-c",
        "--p2p.scoring=off",
        "--p2p.topic-scoring=false",
        "--p2p.unsafe.block.signer=0x" ++
            "1111111111111111111111111111111111111111",
    };
    const options = try parse(&args);
    try testing.expectEqual(@as(u16, 30303), options.listen_tcp);
    try testing.expectEqual(ip.Address{ .ip4 = .{ 10, 1, 2, 3 } }, options.listen_ip);
    try testing.expect(options.ban_peers);
    try testing.expectEqual(@as(i64, -50), options.ban_threshold);
    try testing.expectEqual(@as(usize, 3), options.bootnode_slice().len);
    try testing.expectEqualStrings("enode://b", options.bootnode_slice()[1]);
    try testing.expectEqual(score.Level.off, options.scoring);
    try testing.expectEqual(@as(u8, 0x11), options.unsafe_block_signer.?.bytes[19]);
}

test "options: rejects unknown flags, bad values, and missing values" {
    try testing.expectError(error.UnknownFlag, parse(&.{"--p2p.nope=1"}));
    try testing.expectError(error.InvalidValue, parse(&.{"--p2p.listen.tcp=70000"}));
    try testing.expectError(error.InvalidValue, parse(&.{"--p2p.ban.peers=maybe"}));
    try testing.expectError(error.MissingValue, parse(&.{"--p2p.listen.tcp"}));
    try testing.expectError(error.InvalidValue, parse(&.{"--p2p.scoring=heavy"}));
}

test "options: bootnodes file as lines or a JSON array" {
    var options: Options = .{};
    try add_bootnodes_file(&options, "# base\nenr:-a\n\n  enode://b@1.2.3.4:1  \r\n");
    try add_bootnodes_file(&options, "[\"enr:-c\", \"enr:-d\"]\n");
    const nodes = options.bootnode_slice();
    try testing.expectEqual(@as(usize, 4), nodes.len);
    try testing.expectEqualStrings("enode://b@1.2.3.4:1", nodes[1]);
    try testing.expectEqualStrings("enr:-d", nodes[3]);
}

const FuzzContext = struct {};

fn fuzz_one(_: FuzzContext, input: []const u8) anyerror!void {
    var args: [16][]const u8 = undefined;
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, input, 0);
    while (parts.next()) |part| {
        if (count == args.len) break;
        args[count] = part;
        count += 1;
    }
    var options = parse(args[0..count]) catch return;
    assert(options.bootnodes_count <= bootnodes_max);
    add_bootnodes_file(&options, input) catch return;
    assert(options.bootnodes_count <= bootnodes_max);
}

test "options: fuzz parse" {
    try fuzz.run_bytes(FuzzContext{}, fuzz_one, fuzz.Options{
        .input_size_max = 512,
        .corpus = &.{ "--p2p.listen.tcp=1\x00--p2p.bootnodes\x00a,b", "--p2p.ban.peers" },
    });
}

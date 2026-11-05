//! `base consensus`: the consensus (rollup) node (see docs/DEVNET.md for the devnet process
//! contract). Reads `rollup.json`, follows L1 over JSON-RPC, drives the L2 execution engine
//! over the authenticated Engine API, and serves `optimism_*` JSON-RPC.

const std = @import("std");
const base = @import("base");

const Io = std.Io;
const io = base.utilities.io;
const log = base.utilities.log;
const consensus = base.consensus;
const Node = consensus.service.Node(io.IO);

const usage =
    \\usage: base consensus --rollup-config ROLLUP.json --l1 URL --l2 URL --l2-jwt FILE
    \\         [--l1-beacon URL] [--rpc.addr IP] [--rpc.port P]
    \\         [--sequencer [--sequencer.key-index N]] [--log.level LEVEL]
    \\
;

pub const Flags = struct {
    rollup_config: ?[]const u8 = null,
    l1: ?io.Address = null,
    l1_beacon: ?io.Address = null,
    l2: ?io.Address = null,
    l2_jwt: ?[]const u8 = null,
    rpc_addr: [4]u8 = .{ 127, 0, 0, 1 },
    rpc_port: u16 = 7545,
    sequencer: bool = false,
    sequencer_key_index: u32 = 0,
    log_level: log.Level = .info,
};

/// Parses `http://a.b.c.d:port` (IPv4 literal only; no DNS).
pub fn parse_url(text: []const u8) !io.Address {
    const prefix = "http://";
    if (!std.mem.startsWith(u8, text, prefix)) return error.UnsupportedUrl;
    var rest = text[prefix.len..];
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash| {
        if (slash + 1 != rest.len) return error.UnsupportedUrl; // No paths.
        rest = rest[0..slash];
    }
    const colon = std.mem.lastIndexOfScalar(u8, rest, ':') orelse return error.MissingPort;
    const port = try std.fmt.parseInt(u16, rest[colon + 1 ..], 10);
    return io.Address.ip4(try parse_ip4(rest[0..colon]), port);
}

fn parse_ip4(text: []const u8) ![4]u8 {
    var bytes: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&bytes) |*byte| byte.* = try std.fmt.parseInt(u8, parts.next() orelse "", 10);
    if (parts.next() != null) return error.InvalidAddress;
    return bytes;
}

fn apply_switch(flags: *Flags, arg: []const u8) bool {
    if (std.mem.eql(u8, arg, "--sequencer")) {
        flags.sequencer = true;
        return true;
    }
    return false;
}

fn apply_value(flags: *Flags, arg: []const u8, value: []const u8) !void {
    const eql = std.mem.eql;
    if (eql(u8, arg, "--rollup-config")) {
        flags.rollup_config = value;
    } else if (eql(u8, arg, "--l1")) {
        flags.l1 = try parse_url(value);
    } else if (eql(u8, arg, "--l1-beacon")) {
        flags.l1_beacon = try parse_url(value);
    } else if (eql(u8, arg, "--l2")) {
        flags.l2 = try parse_url(value);
    } else if (eql(u8, arg, "--l2-jwt")) {
        flags.l2_jwt = value;
    } else if (eql(u8, arg, "--rpc.addr")) {
        flags.rpc_addr = try parse_ip4(value);
    } else if (eql(u8, arg, "--rpc.port")) {
        flags.rpc_port = try std.fmt.parseInt(u16, value, 10);
    } else if (eql(u8, arg, "--sequencer.key-index")) {
        flags.sequencer_key_index = try std.fmt.parseInt(u32, value, 10);
    } else if (eql(u8, arg, "--log.level")) {
        flags.log_level = std.meta.stringToEnum(log.Level, value) orelse
            return error.UnknownLogLevel;
    } else return error.UnknownFlag;
}

pub fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) {
        if (apply_switch(&flags, args[index])) {
            index += 1;
            continue;
        }
        if (index + 1 == args.len) return error.MissingValue;
        try apply_value(&flags, args[index], args[index + 1]);
        index += 2;
    }
    if (flags.rollup_config == null) return error.MissingRollupConfig;
    if (flags.l1 == null or flags.l2 == null) return error.MissingEndpoint;
    if (flags.l2_jwt == null) return error.MissingJwt;
    return flags;
}

fn now_ns(context: ?*anyopaque) u64 {
    const os_io: *io.IO = @ptrCast(@alignCast(context.?));
    return os_io.now_realtime_ns();
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch |err| {
        std.debug.print("consensus: {t}\n{s}", .{ err, usage });
        return 2;
    };
    const cwd = Io.Dir.cwd();
    const path = flags.rollup_config.?;
    const text = try cwd.readFileAlloc(init.io, path, init.gpa, .limited(1 << 20));
    defer init.gpa.free(text);
    const rollup = consensus.protocol.rollup_json.parse(text) catch |err| {
        std.debug.print("consensus: invalid rollup config: {t}\n", .{err});
        return 2;
    };
    var secret_buffer: [256]u8 = undefined;
    const secret_text = try cwd.readFile(init.io, flags.l2_jwt.?, &secret_buffer);
    const secret = try base.utilities.jwt.Secret.parse_hex(secret_text);

    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    var logger: log.Logger = .{
        .level = flags.log_level,
        .sink = log.stderr_sink(),
        .time = .{ .context = &os_io, .now_ns = now_ns },
    };
    const node = try init.gpa.create(Node);
    defer init.gpa.destroy(node);
    try node.init(init.gpa, &os_io, &logger, &rollup, .{
        .l1 = flags.l1.?,
        .l1_beacon = flags.l1_beacon,
        .l2 = flags.l2.?,
        .jwt_secret = secret,
        .rpc_address = io.Address.ip4(flags.rpc_addr, flags.rpc_port),
        .sequencer = flags.sequencer,
        .driver = .{ .sequencer = flags.sequencer },
        .version = base.build_options.version,
    });
    defer node.deinit();
    _ = try node.start();
    logger.log(.info, "consensus", "started", .{
        .l2_chain_id = rollup.l2_chain_id,
        .sequencer = flags.sequencer,
    });
    while (true) {
        node.tick();
        try os_io.run_for_ns(10 * std.time.ns_per_ms);
    }
}

test "consensus: flags" {
    const flags = try parse_flags(&.{
        "--rollup-config", "r.json",                "--l1",       "http://127.0.0.1:8545",
        "--l1-beacon",     "http://127.0.0.1:5052", "--l2",       "http://127.0.0.1:9551",
        "--l2-jwt",        "jwt.hex",               "--rpc.port", "7545",
        "--sequencer",     "--sequencer.key-index", "5",
    });
    try std.testing.expect(flags.sequencer);
    try std.testing.expectEqual(@as(u32, 5), flags.sequencer_key_index);
    try std.testing.expectEqual(@as(u16, 9551), flags.l2.?.port);
    try std.testing.expectEqual(@as(u16, 7545), flags.rpc_port);
    try std.testing.expectError(error.MissingRollupConfig, parse_flags(&.{}));
    try std.testing.expectError(error.UnknownFlag, parse_flags(&.{ "--nope", "1" }));
    try std.testing.expectError(error.UnsupportedUrl, parse_url("https://127.0.0.1:1"));
    try std.testing.expectError(error.MissingPort, parse_url("http://127.0.0.1"));
    try std.testing.expectError(error.InvalidAddress, parse_url("http://1.2.3.4.5:1"));
    const address = try parse_url("http://10.0.0.1:8545/");
    try std.testing.expectEqual(@as(u8, 10), address.bytes[0]);
}

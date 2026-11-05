//! `base devnet ...`: generate and inspect local devnet configuration.
//!
//!   base devnet init   --out DIR [--force] [--timestamp SECONDS]
//!   base devnet rollup --out DIR --timestamp SECONDS --l1-hash 0x.. --l2-hash 0x..
//!   base devnet account INDEX
//!   base devnet transfer --rpc URL --chain-id N --key-index N --to 0x.. --value WEI [--gas N]
//!
//! `init` writes genesis files, a placeholder rollup.json, devnet.env and a fresh JWT
//! secret. Once the ELs are up, `rollup` rewrites rollup.json with their real genesis
//! hashes (until genesis hashing lands in-process).

const std = @import("std");
const base = @import("base");
const devnet = base.batcher.devnet;
const Io = std.Io;
const HttpTransport = @import("http_transport.zig").HttpTransport;

pub const usage =
    \\usage: base devnet <init|rollup|account> [flags]
    \\  init    --out DIR [--force] [--timestamp SECONDS]
    \\  rollup  --out DIR --timestamp SECONDS --l1-hash 0x.. --l2-hash 0x..
    \\  account INDEX
    \\  transfer --rpc URL --chain-id N --key-index N --to 0x.. --value WEI [--gas N]
    \\
;

const Flags = struct {
    out: []const u8 = ".devnet",
    force: bool = false,
    timestamp: ?u64 = null,
    l1_hash: ?[32]u8 = null,
    l2_hash: ?[32]u8 = null,
    rpc_url: ?[]const u8 = null,
    chain_id: ?u64 = null,
    key_index: ?u32 = null,
    to: ?[20]u8 = null,
    value: ?u256 = null,
    gas: ?u64 = null,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--force")) {
            flags.force = true;
            continue;
        }
        if (i + 1 >= args.len) return error.MissingFlagValue;
        const value = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, arg, "--out")) {
            flags.out = value;
        } else if (std.mem.eql(u8, arg, "--timestamp")) {
            flags.timestamp = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, arg, "--l1-hash")) {
            flags.l1_hash = try base.common.primitives.hex.decode_array(32, value);
        } else if (std.mem.eql(u8, arg, "--l2-hash")) {
            flags.l2_hash = try base.common.primitives.hex.decode_array(32, value);
        } else {
            try parse_transfer_flag(&flags, arg, value);
        }
    }
    return flags;
}

fn parse_transfer_flag(flags: *Flags, arg: []const u8, value: []const u8) !void {
    if (std.mem.eql(u8, arg, "--rpc")) {
        flags.rpc_url = value;
    } else if (std.mem.eql(u8, arg, "--chain-id")) {
        flags.chain_id = try std.fmt.parseInt(u64, value, 10);
    } else if (std.mem.eql(u8, arg, "--key-index")) {
        flags.key_index = try std.fmt.parseInt(u32, value, 10);
    } else if (std.mem.eql(u8, arg, "--to")) {
        flags.to = try base.common.primitives.hex.decode_array(20, value);
    } else if (std.mem.eql(u8, arg, "--value")) {
        flags.value = try std.fmt.parseInt(u256, value, 10);
    } else if (std.mem.eql(u8, arg, "--gas")) {
        flags.gas = try std.fmt.parseInt(u64, value, 10);
    } else {
        return error.UnknownFlag;
    }
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0) {
        std.debug.print("{s}", .{usage});
        return 2;
    }
    const command = args[0];
    if (std.mem.eql(u8, command, "account")) {
        if (args.len != 2) return usage_error();
        const index = try std.fmt.parseInt(u32, args[1], 10);
        const account = devnet.accounts.derive_dev(index);
        try write_stdout(init.io, "0x{x}\n", .{&account.address.bytes});
        return 0;
    }
    const flags = parse_flags(args[1..]) catch return usage_error();
    if (std.mem.eql(u8, command, "init")) return command_init(init, flags);
    if (std.mem.eql(u8, command, "rollup")) return command_rollup(init, flags);
    if (std.mem.eql(u8, command, "transfer")) return command_transfer(init, flags);
    return usage_error();
}

fn usage_error() u8 {
    std.debug.print("{s}", .{usage});
    return 2;
}

fn write_stdout(io: Io, comptime format: []const u8, args: anytype) !void {
    var buffer: [256]u8 = undefined;
    var writer = Io.File.stdout().writer(io, &buffer);
    try writer.interface.print(format, args);
    try writer.interface.flush();
}

fn command_init(init: std.process.Init, flags: Flags) !u8 {
    const io = init.io;
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, flags.out);
    var out_dir = try cwd.openDir(io, flags.out, .{});
    defer out_dir.close(io);
    if (!flags.force) {
        if (out_dir.access(io, devnet.init.File.l1_genesis.name(), .{})) |_| {
            std.debug.print("devnet: {s} already initialized (use --force)\n", .{flags.out});
            return 0;
        } else |_| {}
    }
    const now_s: u64 = @intCast(Io.Clock.real.now(io).toSeconds());
    const config: devnet.genesis.Config = .{ .genesis_timestamp = flags.timestamp orelse now_s };
    const anchor: devnet.genesis.GenesisAnchor = .{ .l1_hash = @splat(0), .l2_hash = @splat(0) };
    for (std.enums.values(devnet.init.File)) |file| {
        try write_rendered(init, out_dir, file, &config, anchor);
    }
    var secret: [32]u8 = undefined;
    try io.randomSecure(&secret);
    const jwt = devnet.init.jwt_hex(secret);
    try out_dir.writeFile(io, .{ .sub_path = devnet.init.jwt_file_name, .data = &jwt });
    std.debug.print("devnet: wrote {s} (genesis timestamp {d})\n", .{
        flags.out,
        config.genesis_timestamp,
    });
    return 0;
}

fn command_rollup(init: std.process.Init, flags: Flags) !u8 {
    const timestamp = flags.timestamp orelse return usage_error();
    const l1_hash = flags.l1_hash orelse return usage_error();
    const l2_hash = flags.l2_hash orelse return usage_error();
    const io = init.io;
    var out_dir = try Io.Dir.cwd().openDir(io, flags.out, .{});
    defer out_dir.close(io);
    const config: devnet.genesis.Config = .{ .genesis_timestamp = timestamp };
    const anchor: devnet.genesis.GenesisAnchor = .{ .l1_hash = l1_hash, .l2_hash = l2_hash };
    try write_rendered(init, out_dir, .rollup, &config, anchor);
    return 0;
}

fn write_rendered(
    init: std.process.Init,
    dir: Io.Dir,
    file: devnet.init.File,
    config: *const devnet.genesis.Config,
    anchor: devnet.genesis.GenesisAnchor,
) !void {
    var allocating: Io.Writer.Allocating = .init(init.gpa);
    defer allocating.deinit();
    try devnet.init.render(&allocating.writer, file, config, anchor, .{});
    try dir.writeFile(init.io, .{ .sub_path = file.name(), .data = allocating.written() });
}

fn command_transfer(init: std.process.Init, flags: Flags) !u8 {
    const url = flags.rpc_url orelse return usage_error();
    const params: devnet.transfer.Params = .{
        .chain_id = flags.chain_id orelse return usage_error(),
        .key_index = flags.key_index orelse return usage_error(),
        .to = .{ .bytes = flags.to orelse return usage_error() },
        .value_wei = flags.value orelse return usage_error(),
        .gas_limit = flags.gas,
    };
    var http = HttpTransport.init(init.gpa, init.io, url);
    defer http.deinit();
    var client = try base.batcher.rpc.Client.init(init.gpa, http.transport(), .{
        .request_bytes_max = 4096,
        .response_bytes_max = 1024 * 1024,
        .parse_bytes_max = 4 * 1024 * 1024,
    });
    defer client.deinit(init.gpa);
    const hash = devnet.transfer.transfer(&client, params) catch |err| {
        std.debug.print("transfer: {t} {s}\n", .{ err, client.last_error() });
        return 1;
    };
    try write_stdout(init.io, "0x{x}\n", .{&hash.bytes});
    return 0;
}

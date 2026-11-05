//! `base node`: the execution node (see docs/DEVNET.md for the devnet process contract).
//!
//! `--dev-l1` runs a standalone auto-mining L1 chain with a minimal beacon API; without it
//! the node follows the chain in `--chain` and serves eth JSON-RPC (and the Engine API on
//! `--authrpc.port`). With `--datadir` the state and chain persist in `DIR/node.db` (a
//! journal plus checkpoints) and a restart resumes from it; without it state is in memory.
//! `--proofs-history` keeps the last `--proofs-history.window` blocks (default 300: 60 s of
//! 200 ms blocks) of trie nodes in memory, so state reads and eth_getProof work at older
//! blocks; a 1 GiB byte budget shrinks the window under heavy blocks.
//! `--rehash-threads N` sets the storage-trie rehash workers (default: one per spare core,
//! at most 4; 0 hashes on the calling thread).
//! `--builder.enabled` (L2) routes Engine API payload jobs through the `builder/core` payload
//! service: base/base runs its builder as a separate `builder` binary only to add
//! flashblocks; without flashblocks the builder is part of `base node` (docs/lanes/builder.md).
//! `--builder.rejection-cache-max-capacity` and `--builder.rejection-cache-ttl-secs` follow
//! base/base `crates/builder/cli/src/args.rs`.

const std = @import("std");
const base = @import("base");

const Io = std.Io;
const io = base.utilities.io;
const log = base.utilities.log;
const node = base.execution.node;
const Service = node.Service(io.IO);

const usage =
    \\usage: base node --chain GENESIS.json [--datadir DIR] [--http.addr IP] [--http.port P]
    \\         [--dev-l1 [--block-time S] [--beacon.port P]]
    \\         [--authrpc.port P --authrpc.jwtsecret FILE] [--log.level LEVEL]
    \\         [--proofs-history [--proofs-history.window BLOCKS]] [--rehash-threads N]
    \\         [--builder.enabled [--builder.rejection-cache-max-capacity N]
    \\          [--builder.rejection-cache-ttl-secs S]]
    \\
;

pub const Flags = struct {
    chain: ?[]const u8 = null,
    datadir: ?[]const u8 = null,
    http_addr: [4]u8 = .{ 127, 0, 0, 1 },
    http_port: u16 = 8545,
    dev_l1: bool = false,
    block_time_s: u64 = 2,
    beacon_port: u16 = 5052,
    authrpc_port: ?u16 = null,
    jwt_secret_path: ?[]const u8 = null,
    log_level: log.Level = .info,
    proofs_history: bool = false,
    proofs_history_window: u32 = node.service.proofs_history_window_default,
    /// Storage-rehash workers; null picks `state_db.rehash_threads_auto` from the cores.
    rehash_threads: ?u32 = null,
    builder: bool = false,
    builder_rejection_cache_capacity: u32 = 100_000,
    builder_rejection_cache_ttl_s: u64 = 1800,
};

pub fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var i: usize = 0;
    const eql = std.mem.eql;
    while (i < args.len) {
        const arg = args[i];
        if (eql(u8, arg, "--dev-l1")) {
            flags.dev_l1 = true;
            i += 1; // A switch takes no value.
            continue;
        }
        if (eql(u8, arg, "--builder.enabled")) {
            flags.builder = true;
            i += 1;
            continue;
        }
        if (eql(u8, arg, "--proofs-history")) {
            flags.proofs_history = true;
            i += 1;
            continue;
        }
        if (i + 1 == args.len) return error.MissingValue;
        const value = args[i + 1];
        if (eql(u8, arg, "--chain")) {
            flags.chain = value;
        } else if (eql(u8, arg, "--datadir")) {
            flags.datadir = value;
        } else if (eql(u8, arg, "--http.addr")) {
            flags.http_addr = try parse_ip4(value);
        } else if (eql(u8, arg, "--http.port")) {
            flags.http_port = try std.fmt.parseInt(u16, value, 10);
        } else if (eql(u8, arg, "--block-time")) {
            flags.block_time_s = try std.fmt.parseInt(u64, value, 10);
            if (flags.block_time_s == 0) return error.InvalidBlockTime;
        } else if (eql(u8, arg, "--beacon.port")) {
            flags.beacon_port = try std.fmt.parseInt(u16, value, 10);
        } else if (eql(u8, arg, "--authrpc.port")) {
            flags.authrpc_port = try std.fmt.parseInt(u16, value, 10);
        } else if (eql(u8, arg, "--authrpc.jwtsecret")) {
            flags.jwt_secret_path = value;
        } else if (eql(u8, arg, "--proofs-history.window")) {
            flags.proofs_history_window = try std.fmt.parseInt(u32, value, 10);
            if (flags.proofs_history_window == 0) return error.InvalidProofsHistoryWindow;
        } else if (eql(u8, arg, "--rehash-threads")) {
            const threads = try std.fmt.parseInt(u32, value, 10);
            if (threads > rehash_threads_max) return error.TooManyRehashThreads;
            flags.rehash_threads = threads;
        } else if (eql(u8, arg, "--builder.rejection-cache-max-capacity")) {
            flags.builder_rejection_cache_capacity = try std.fmt.parseInt(u32, value, 10);
            if (flags.builder_rejection_cache_capacity == 0) return error.InvalidCacheCapacity;
        } else if (eql(u8, arg, "--builder.rejection-cache-ttl-secs")) {
            flags.builder_rejection_cache_ttl_s = try std.fmt.parseInt(u64, value, 10);
            const ttl_s = flags.builder_rejection_cache_ttl_s;
            if (ttl_s == 0 or ttl_s > ttl_s_max) return error.InvalidCacheTtl;
        } else if (eql(u8, arg, "--log.level")) {
            flags.log_level = std.meta.stringToEnum(log.Level, value) orelse
                return error.UnknownLogLevel;
        } else return error.UnknownFlag;
        i += 2;
    }
    if (flags.chain == null) return error.MissingChain;
    if ((flags.authrpc_port == null) != (flags.jwt_secret_path == null)) {
        return error.AuthrpcNeedsPortAndSecret;
    }
    return flags;
}

/// Keeps the TTL in nanoseconds far inside u64.
const ttl_s_max: u64 = 365 * 24 * 60 * 60;

fn builder_config(flags: Flags) ?node.service.NodeBuilderConfig {
    if (!flags.builder) return null;
    std.debug.assert(flags.builder_rejection_cache_capacity > 0);
    std.debug.assert(flags.builder_rejection_cache_ttl_s <= ttl_s_max);
    return .{
        .rejection_cache_capacity = flags.builder_rejection_cache_capacity,
        .rejection_cache_ttl_ns = flags.builder_rejection_cache_ttl_s * std.time.ns_per_s,
    };
}

fn parse_ip4(text: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&result) |*byte| byte.* = try std.fmt.parseInt(u8, parts.next() orelse "", 10);
    if (parts.next() != null) return error.InvalidAddress;
    return result;
}

fn beacon_address(flags: Flags) io.Address {
    return io.Address.ip4(flags.http_addr, flags.beacon_port);
}

fn authrpc_address(flags: Flags) ?io.Address {
    const port = flags.authrpc_port orelse return null;
    return io.Address.ip4(flags.http_addr, port);
}

const rehash_threads_max = base.execution.trie.state_trie.rehash_threads_max;

/// Default limits, plus one sender-recovery thread per spare core (at most 7) and the
/// storage-rehash workers (`--rehash-threads`, else one per spare core, at most 4).
fn limits(flags: Flags) base.execution.node.service.Limits {
    var result: base.execution.node.service.Limits = .{};
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    result.executor.recovery_threads = @min(cores - 1, 7);
    const auto = node.state_db.rehash_threads_auto(cores);
    result.state.trie.rehash_threads = flags.rehash_threads orelse auto;
    std.debug.assert(result.state.trie.rehash_threads <= rehash_threads_max);
    return result;
}

fn now_ns(context: ?*anyopaque) u64 {
    const os_io: *io.IO = @ptrCast(@alignCast(context.?));
    return os_io.now_realtime_ns();
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch |err| {
        std.debug.print("node: {t}\n{s}", .{ err, usage });
        return 2;
    };
    const cwd = Io.Dir.cwd();
    var data_path_buffer: [4096]u8 = undefined;
    var data_path: ?[]const u8 = null;
    if (flags.datadir) |datadir| {
        try cwd.createDirPath(init.io, datadir);
        data_path = try std.fmt.bufPrint(&data_path_buffer, "{s}/node.db", .{datadir});
    }
    const text = try cwd.readFileAlloc(init.io, flags.chain.?, init.gpa, .limited(256 << 20));
    defer init.gpa.free(text);
    const parsed = try base.common.genesis.parse(init.gpa, text);
    defer parsed.deinit();

    var secret: ?base.utilities.jwt.Secret = null;
    if (flags.jwt_secret_path) |path| {
        var buffer: [256]u8 = undefined;
        const secret_text = try cwd.readFile(init.io, path, &buffer);
        secret = try base.utilities.jwt.Secret.parse_hex(secret_text);
    }
    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    var logger: log.Logger = .{
        .level = flags.log_level,
        .sink = log.stderr_sink(),
        .time = .{ .context = &os_io, .now_ns = now_ns },
    };
    const service = try init.gpa.create(Service);
    defer init.gpa.destroy(service);
    try service.init(init.gpa, &os_io, &logger, &parsed.value, .{
        .http_address = io.Address.ip4(flags.http_addr, flags.http_port),
        .dev_l1 = flags.dev_l1,
        .block_time_s = flags.block_time_s,
        .beacon_address = if (flags.dev_l1) beacon_address(flags) else null,
        .authrpc_address = authrpc_address(flags),
        .jwt_secret = secret,
        .data_path = data_path,
        .proofs_history_window = if (flags.proofs_history) flags.proofs_history_window else 0,
        .builder = builder_config(flags),
        .limits = limits(flags),
    });
    defer service.deinit();
    _ = try service.start();
    logger.log(.info, "node", "started", .{
        .chain_id = service.spec.chain_id,
        .dev_l1 = flags.dev_l1,
    });
    while (true) try os_io.run_for_ns(std.time.ns_per_s);
}

test "node: flags" {
    const flags = try parse_flags(&.{
        "--dev-l1",      "--chain", "g.json",       "--http.port", "8545",
        "--beacon.port", "5052",    "--block-time", "2",           "--datadir",
        ".devnet/l1",
    });
    try std.testing.expect(flags.dev_l1);
    try std.testing.expectEqual(@as(u16, 5052), flags.beacon_port);
    try std.testing.expectError(error.MissingChain, parse_flags(&.{"--dev-l1"}));
    try std.testing.expectError(error.UnknownFlag, parse_flags(&.{ "--nope", "1" }));
    try std.testing.expectError(error.MissingValue, parse_flags(&.{"--chain"}));
    try std.testing.expectError(error.InvalidAddress, parse_ip4("1.2.3.4.5"));
    try std.testing.expectError(
        error.AuthrpcNeedsPortAndSecret,
        parse_flags(&.{ "--chain", "g.json", "--authrpc.port", "9551" }),
    );
}

test "node: proofs history flags" {
    const off = try parse_flags(&.{ "--chain", "g.json" });
    try std.testing.expect(!off.proofs_history);
    const on = try parse_flags(&.{
        "--proofs-history", "--chain", "g.json", "--proofs-history.window", "64",
    });
    try std.testing.expect(on.proofs_history);
    try std.testing.expectEqual(@as(?u32, null), on.rehash_threads);
    try std.testing.expectEqual(@as(u32, 64), on.proofs_history_window);
    try std.testing.expectError(
        error.InvalidProofsHistoryWindow,
        parse_flags(&.{ "--chain", "g.json", "--proofs-history.window", "0" }),
    );
}

test "node: rehash threads flag" {
    const off = try parse_flags(&.{ "--chain", "g.json", "--rehash-threads", "0" });
    try std.testing.expectEqual(@as(?u32, 0), off.rehash_threads);
    try std.testing.expectEqual(@as(u32, 0), limits(off).state.trie.rehash_threads);
    const two = try parse_flags(&.{ "--rehash-threads", "2", "--chain", "g.json" });
    try std.testing.expectEqual(@as(u32, 2), limits(two).state.trie.rehash_threads);
    const auto = limits(try parse_flags(&.{ "--chain", "g.json" }));
    try std.testing.expect(auto.state.trie.rehash_threads <= 4);
    try std.testing.expectError(
        error.TooManyRehashThreads,
        parse_flags(&.{ "--chain", "g.json", "--rehash-threads", "17" }),
    );
}

test "node: builder flags" {
    const off = try parse_flags(&.{ "--chain", "g.json" });
    try std.testing.expect(builder_config(off) == null);
    const on = try parse_flags(&.{
        "--builder.enabled",                      "--chain", "g.json",
        "--builder.rejection-cache-max-capacity", "64",      "--builder.rejection-cache-ttl-secs",
        "30",
    });
    const config = builder_config(on).?;
    try std.testing.expectEqual(@as(u32, 64), config.rejection_cache_capacity);
    try std.testing.expectEqual(30 * std.time.ns_per_s, config.rejection_cache_ttl_ns);
    try std.testing.expectError(error.InvalidCacheTtl, parse_flags(&.{
        "--chain", "g.json", "--builder.rejection-cache-ttl-secs", "0",
    }));
    try std.testing.expectError(error.InvalidCacheCapacity, parse_flags(&.{
        "--chain", "g.json", "--builder.rejection-cache-max-capacity", "0",
    }));
}

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
const p2p = consensus.p2p;
const accounts = base.batcher.devnet.accounts;

const usage =
    \\usage: base consensus --rollup-config ROLLUP.json --l1 URL --l2 URL --l2-jwt FILE
    \\         [--l1-beacon URL] [--rpc.addr IP] [--rpc.port P]
    \\         [--rpc.ws-enabled [--rpc.ws-port P]] [--rpc.enable-admin] [--rpc.dev-enabled]
    \\         [--rpc.disabled] [--rpc.execution-forwarding-endpoint URL]
    \\         [--l1.verifier-confs N] [--sequencer.l1-confs N] [--sequencer.recover]
    \\         [--sequencer [--sequencer.key-index N]] [--log.level LEVEL]
    \\         [--p2p.disabled | --p2p.NAME VALUE ...]
    \\         [--upgrade-signal.contract ADDRESS] [--upgrade-signal.l1-block-tag TAG]
    \\         [--checkpoint.path FILE] [--safedb.path FILE]
    \\         [--metrics.enabled [--metrics.addr IP] [--metrics.port P]]
    \\         [--source-l2-rpc URL]   follow mode: insert blocks from a source node
    \\         [--conductor.rpc URL] [--sequencer.stopped]
    \\
;

pub const Flags = struct {
    rollup_config: ?[]const u8 = null,
    l1: ?io.Address = null,
    l1_beacon: ?io.Address = null,
    l2: ?io.Address = null,
    /// Follow mode (base/base `follow --source-l2-rpc`): no derivation.
    source_l2_rpc: ?io.Address = null,
    /// Execution RPC that serves the HTTP RPC methods this node does not.
    execution_forwarding: ?io.Address = null,
    /// op-conductor (base/base `--conductor.rpc`).
    conductor_rpc: ?io.Address = null,
    sequencer_stopped: bool = false,
    l2_jwt: ?[]const u8 = null,
    rpc_addr: [4]u8 = .{ 127, 0, 0, 1 },
    rpc_port: u16 = 7545,
    /// WebSocket RPC on its own port (base/base serves it on the HTTP port).
    rpc_ws_enabled: bool = false,
    /// No HTTP or WebSocket RPC server at all (base/base `--rpc.disabled`).
    rpc_disabled: bool = false,
    rpc_admin: bool = false,
    /// base/base defaults: derive from the L1 head, pick origins 4 blocks below it.
    verifier_l1_confs: u64 = 0,
    sequencer_l1_confs: u64 = 4,
    sequencer_recover: bool = false,
    rpc_dev: bool = false,
    rpc_ws_port: u16 = 7546,
    /// Prometheus endpoint (base/base defaults: disabled, 0.0.0.0:9090).
    metrics_enabled: bool = false,
    metrics_addr: [4]u8 = .{ 0, 0, 0, 0 },
    metrics_port: u16 = base.consensus.service.metrics.default_port,
    sequencer: bool = false,
    sequencer_key_index: u32 = 0,
    log_level: log.Level = .info,
    /// Unsafe-block gossip, on unless `--p2p.disabled` (base/base default).
    p2p_disabled: bool = false,
    p2p: p2p.options.Options = .{},
    /// The L1 `ProtocolVersions` contract; defaults to the chain's public one.
    upgrade_signal_contract: ?[20]u8 = null,
    upgrade_signal_block_tag: base.utilities.upgrade_signal.BlockTag = .finalized,
    /// Durable safe/finalized checkpoints; base/base defaults to a file under its data dir,
    /// here they are off unless a path is given.
    checkpoint_path: ?[]const u8 = null,
    /// Durable L1 -> safe head entries for `optimism_safeHeadAtL1Block`; in memory only
    /// (lost on restart) unless a path is given.
    safedb_path: ?[]const u8 = null,
};

const p2p_args_max = 2 * p2p.options.bootnodes_max + 64;

/// How many arguments the `--p2p.*` flag at `args[index]` spans.
fn p2p_flag_span(args: []const []const u8, index: usize) !usize {
    const name = args[index]["--p2p.".len..];
    if (std.mem.indexOfScalar(u8, name, '=') != null) return 1;
    if (p2p.options.is_bool(name) or std.mem.eql(u8, name, "disabled")) return 1;
    if (index + 1 == args.len) return error.MissingValue;
    return 2;
}

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

fn parse_address(text: []const u8) ![20]u8 {
    const digits = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    if (digits.len != 40) return error.InvalidAddress;
    var address: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&address, digits) catch return error.InvalidAddress;
    return address;
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
    if (std.mem.eql(u8, arg, "--rpc.enable-admin")) {
        flags.rpc_admin = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--rpc.dev-enabled")) {
        flags.rpc_dev = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--rpc.ws-enabled")) {
        flags.rpc_ws_enabled = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--rpc.disabled")) {
        flags.rpc_disabled = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--sequencer.stopped")) {
        flags.sequencer_stopped = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--sequencer.recover")) {
        flags.sequencer_recover = true;
        return true;
    }
    if (std.mem.eql(u8, arg, "--metrics.enabled")) {
        flags.metrics_enabled = true;
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
    } else if (eql(u8, arg, "--conductor.rpc")) {
        flags.conductor_rpc = try parse_url(value);
    } else if (eql(u8, arg, "--rpc.execution-forwarding-endpoint")) {
        flags.execution_forwarding = try parse_url(value);
    } else if (eql(u8, arg, "--source-l2-rpc")) {
        flags.source_l2_rpc = try parse_url(value);
    } else if (eql(u8, arg, "--l2-jwt")) {
        flags.l2_jwt = value;
    } else if (eql(u8, arg, "--rpc.addr")) {
        flags.rpc_addr = try parse_ip4(value);
    } else if (eql(u8, arg, "--rpc.port")) {
        flags.rpc_port = try std.fmt.parseInt(u16, value, 10);
    } else if (eql(u8, arg, "--l1.verifier-confs")) {
        flags.verifier_l1_confs = try std.fmt.parseInt(u64, value, 10);
    } else if (eql(u8, arg, "--sequencer.l1-confs")) {
        flags.sequencer_l1_confs = try std.fmt.parseInt(u64, value, 10);
    } else if (eql(u8, arg, "--rpc.ws-port")) {
        flags.rpc_ws_port = try std.fmt.parseInt(u16, value, 10);
    } else if (eql(u8, arg, "--metrics.addr")) {
        flags.metrics_addr = try parse_ip4(value);
    } else if (eql(u8, arg, "--metrics.port")) {
        flags.metrics_port = try std.fmt.parseInt(u16, value, 10);
    } else if (eql(u8, arg, "--sequencer.key-index")) {
        flags.sequencer_key_index = try std.fmt.parseInt(u32, value, 10);
    } else if (eql(u8, arg, "--checkpoint.path")) {
        if (value.len == 0) return error.InvalidValue;
        flags.checkpoint_path = value;
    } else if (eql(u8, arg, "--safedb.path")) {
        if (value.len == 0) return error.InvalidValue;
        flags.safedb_path = value;
    } else if (eql(u8, arg, "--upgrade-signal.contract")) {
        flags.upgrade_signal_contract = try parse_address(value);
    } else if (eql(u8, arg, "--upgrade-signal.l1-block-tag")) {
        const BlockTag = base.utilities.upgrade_signal.BlockTag;
        flags.upgrade_signal_block_tag = std.meta.stringToEnum(BlockTag, value) orelse
            return error.UnknownBlockTag;
    } else if (eql(u8, arg, "--log.level")) {
        flags.log_level = std.meta.stringToEnum(log.Level, value) orelse
            return error.UnknownLogLevel;
    } else return error.UnknownFlag;
}

pub fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var p2p_args: [p2p_args_max][]const u8 = undefined;
    var p2p_count: usize = 0;
    var index: usize = 0;
    while (index < args.len) {
        if (std.mem.startsWith(u8, args[index], "--p2p.")) {
            const span = try p2p_flag_span(args, index);
            if (std.mem.eql(u8, args[index], "--p2p.disabled")) {
                flags.p2p_disabled = true;
            } else {
                if (p2p_count + span > p2p_args.len) return error.TooManyP2pFlags;
                @memcpy(p2p_args[p2p_count..][0..span], args[index..][0..span]);
                p2p_count += span;
            }
            index += span;
            continue;
        }
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
    if (flags.source_l2_rpc != null and flags.sequencer) return error.FollowSequencer;
    flags.p2p = try p2p.options.parse(p2p_args[0..p2p_count]);
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
    const p2p_config = try p2p_settings(init, &flags, &rollup, &logger);
    const addresses = server_addresses(&flags);
    const node = try init.gpa.create(Node);
    defer init.gpa.destroy(node);
    try node.init(init.gpa, &os_io, &logger, &rollup, .{
        .l1 = flags.l1.?,
        .l1_beacon = flags.l1_beacon,
        .l2 = flags.l2.?,
        .jwt_secret = secret,
        .rpc_address = addresses.rpc,
        .sequencer = flags.sequencer,
        .driver = .{
            .sequencer = flags.sequencer,
            .sequencer_stopped = flags.sequencer_stopped,
            .recovery_mode = flags.sequencer_recover,
            .verifier_l1_confs = flags.verifier_l1_confs,
            .sequencer_l1_confs = flags.sequencer_l1_confs,
        },
        .conductor = flags.conductor_rpc,
        .version = base.build_options.version,
        .p2p = p2p_config,
        .upgrade_signal = upgrade_settings(&flags, rollup.l2_chain_id),
        .checkpoint_path = flags.checkpoint_path,
        .safedb_path = flags.safedb_path,
        .follow_source = flags.source_l2_rpc,
        .execution_forwarding = flags.execution_forwarding,
        .rpc_admin = flags.rpc_admin,
        .rpc_dev = flags.rpc_dev,
        .ws_address = addresses.ws,
        .metrics_address = addresses.metrics,
    });
    defer node.deinit();
    _ = try node.start();
    logger.log(.info, "consensus", "started", .{
        .l2_chain_id = rollup.l2_chain_id,
        .sequencer = flags.sequencer,
    });
    while (true) {
        node.tick();
        try os_io.run_for_ns(loop_period_ns);
    }
}

/// One node tick per period. Engine and L1 requests advance one step per tick (the polling
/// client starts a request in one tick and takes its result in a later one), so the period
/// bounds a verifier's request rate: at 10 ms, about 20 engine requests per second, under
/// the five L2 blocks per second Base produces at five requests per consolidated block.
const loop_period_ns: u64 = 2 * std.time.ns_per_ms;

const ServerAddresses = struct { rpc: ?io.Address, ws: ?io.Address, metrics: ?io.Address };

/// Listen addresses of the optional servers; null when off (`--rpc.disabled` turns off
/// both RPC servers).
fn server_addresses(flags: *const Flags) ServerAddresses {
    const rpc_on = !flags.rpc_disabled;
    const result: ServerAddresses = .{
        .rpc = if (rpc_on) io.Address.ip4(flags.rpc_addr, flags.rpc_port) else null,
        .ws = if (rpc_on and flags.rpc_ws_enabled)
            io.Address.ip4(flags.rpc_addr, flags.rpc_ws_port)
        else
            null,
        .metrics = if (flags.metrics_enabled)
            io.Address.ip4(flags.metrics_addr, flags.metrics_port)
        else
            null,
    };
    std.debug.assert(result.ws == null or result.rpc != null);
    std.debug.assert((result.metrics != null) == flags.metrics_enabled);
    return result;
}

/// The upgrade-signal contract to observe: the flag, else the chain's public default.
fn upgrade_settings(flags: *const Flags, l2_chain_id: u64) ?consensus.service.node.UpgradeSignal {
    const upgrade_signal = base.utilities.upgrade_signal;
    const contract = flags.upgrade_signal_contract orelse
        upgrade_signal.contract.default_contract(l2_chain_id) orelse return null;
    if (std.mem.allEqual(u8, &contract, 0)) return null;
    return .{ .contract = contract, .block_tag = flags.upgrade_signal_block_tag };
}

/// The gossip setup, or null when disabled or no unsafe block signer can be known.
fn p2p_settings(
    init: std.process.Init,
    flags: *const Flags,
    rollup: *const consensus.protocol.rollup_config.RollupConfig,
    logger: *log.Logger,
) !?consensus.service.node.P2p {
    if (flags.p2p_disabled) return null;
    const sequencer_key: ?[32]u8 = if (flags.sequencer)
        accounts.derive_dev(flags.sequencer_key_index).private_key
    else
        null;
    // base/base order: the L1 SystemConfig (read at runtime by the node), then the built-in
    // chain config, then the flag; a sequencer falls back to its own key.
    const own_signer = if (sequencer_key) |key| accounts.address_of(key) else null;
    const chain_signer = if (base.common.chains.by_chain_id(rollup.l2_chain_id)) |chain|
        chain.unsafe_block_signer
    else
        null;
    const reads_l1 = !std.mem.allEqual(u8, &rollup.l1_system_config_address.bytes, 0);
    const fallback = chain_signer orelse flags.p2p.unsafe_block_signer orelse own_signer;
    const signer = fallback orelse if (reads_l1) base.common.primitives.Address.zero else {
        logger.log(.warn, "consensus", "p2p disabled: no unsafe block signer", .{});
        return null;
    };
    var key_buffer: [256]u8 = undefined;
    const key_file = if (flags.p2p.priv_path) |path|
        try Io.Dir.cwd().readFile(init.io, path, &key_buffer)
    else
        null;
    var seed_bytes: [8]u8 = undefined;
    init.io.random(&seed_bytes);
    const seed = std.mem.readInt(u64, &seed_bytes, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    return .{
        .options = flags.p2p,
        .node_secret = try p2p.network.node_secret(&flags.p2p, key_file, prng.random()),
        .unsafe_block_signer = signer,
        .sequencer_key = sequencer_key,
        .seed = seed,
    };
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
    const required = [_][]const u8{
        "--rollup-config", "r.json", "--l1", "http://127.0.0.1:1", "--l2", "http://127.0.0.1:2",
        "--l2-jwt",        "j",
    };
    const with_p2p = try parse_flags(&(required ++ [_][]const u8{
        "--p2p.listen.tcp", "9300", "--p2p.no-discovery", "--p2p.listen.udp=9301",
    }));
    try std.testing.expect(!with_p2p.p2p_disabled);
    try std.testing.expectEqual(@as(u16, 9300), with_p2p.p2p.listen_tcp);
    try std.testing.expectEqual(@as(u16, 9301), with_p2p.p2p.listen_udp);
    try std.testing.expect(with_p2p.p2p.no_discovery);
    const disabled = try parse_flags(&(required ++ [_][]const u8{"--p2p.disabled"}));
    const upgrade = try parse_flags(&(required ++ [_][]const u8{
        "--upgrade-signal.contract",     "0x7480afc8d99a5c645c247db5a1e4a4f440e6e095",
        "--upgrade-signal.l1-block-tag", "safe",
    }));
    try std.testing.expectEqual(@as(u8, 0x74), upgrade.upgrade_signal_contract.?[0]);
    try std.testing.expectEqual(.safe, upgrade.upgrade_signal_block_tag);
    try std.testing.expect(upgrade.checkpoint_path == null);
    const with_checkpoint = required ++ [_][]const u8{ "--checkpoint.path", "ckpt.bin" };
    const checkpointed = try parse_flags(&with_checkpoint);
    try std.testing.expectEqualStrings("ckpt.bin", checkpointed.checkpoint_path.?);
    const with_safedb = required ++ [_][]const u8{ "--safedb.path", "safe.bin" };
    try std.testing.expectEqualStrings("safe.bin", (try parse_flags(&with_safedb)).safedb_path.?);
    try std.testing.expect(!checkpointed.metrics_enabled);
    const with_metrics = required ++ [_][]const u8{
        "--metrics.enabled", "--metrics.addr", "127.0.0.1", "--metrics.port", "9191",
    };
    const metered = try parse_flags(&with_metrics);
    try std.testing.expect(metered.metrics_enabled);
    try std.testing.expectEqual(@as(u16, 9191), metered.metrics_port);
    try std.testing.expectEqual(@as(u8, 127), metered.metrics_addr[0]);
    const follow_args = required ++ [_][]const u8{ "--source-l2-rpc", "http://10.0.0.9:8545" };
    const following = try parse_flags(&follow_args);
    try std.testing.expectEqual(@as(u16, 8545), following.source_l2_rpc.?.port);
    const follow_sequencer = follow_args ++ [_][]const u8{"--sequencer"};
    try std.testing.expectError(error.FollowSequencer, parse_flags(&follow_sequencer));
    const conducted = try parse_flags(&(required ++ [_][]const u8{
        "--sequencer", "--sequencer.stopped", "--conductor.rpc", "http://10.0.0.8:8547",
    }));
    try std.testing.expect(conducted.sequencer_stopped);
    const ws_args = required ++ [_][]const u8{ "--rpc.ws-enabled", "--rpc.ws-port", "9546" };
    const with_ws = try parse_flags(&ws_args);
    try std.testing.expect(with_ws.rpc_ws_enabled);
    try std.testing.expectEqual(@as(u16, 9546), with_ws.rpc_ws_port);
    try std.testing.expect(!with_ws.rpc_admin and !with_ws.rpc_dev);
    try std.testing.expect(!with_ws.rpc_disabled);
    const no_rpc = try parse_flags(&(ws_args ++ [_][]const u8{"--rpc.disabled"}));
    try std.testing.expect(no_rpc.rpc_disabled and no_rpc.rpc_ws_enabled);
    const forward_args = required ++ [_][]const u8{
        "--rpc.execution-forwarding-endpoint", "http://127.0.0.1:9545",
    };
    const forwarding = try parse_flags(&forward_args);
    try std.testing.expectEqual(@as(u16, 9545), forwarding.execution_forwarding.?.port);
    const no_servers = server_addresses(&no_rpc);
    try std.testing.expect(no_servers.rpc == null and no_servers.ws == null);
    const servers = server_addresses(&with_ws);
    try std.testing.expectEqual(@as(u16, 9546), servers.ws.?.port);
    try std.testing.expectEqual(@as(u16, 7545), servers.rpc.?.port);
    const admin_args = required ++ [_][]const u8{ "--rpc.enable-admin", "--rpc.dev-enabled" };
    const with_admin = try parse_flags(&admin_args);
    try std.testing.expect(with_admin.rpc_admin and with_admin.rpc_dev);
    try std.testing.expectEqual(@as(u64, 4), with_admin.sequencer_l1_confs);
    const conf_args = required ++ [_][]const u8{
        "--l1.verifier-confs", "3", "--sequencer.l1-confs", "0", "--sequencer.recover",
    };
    const with_confs = try parse_flags(&conf_args);
    try std.testing.expectEqual(@as(u64, 3), with_confs.verifier_l1_confs);
    try std.testing.expectEqual(@as(u64, 0), with_confs.sequencer_l1_confs);
    try std.testing.expect(with_confs.sequencer_recover);
    try std.testing.expectEqual(@as(u16, 8547), conducted.conductor_rpc.?.port);
    try std.testing.expect(upgrade_settings(&upgrade, 1).?.block_tag == .safe);
    try std.testing.expect(upgrade_settings(&disabled, 901) == null);
    try std.testing.expect(upgrade_settings(&disabled, 8453) != null);
    const bad_tag = required ++ [_][]const u8{ "--upgrade-signal.l1-block-tag", "pending" };
    try std.testing.expectError(error.UnknownBlockTag, parse_flags(&bad_tag));
    const bad_address = required ++ [_][]const u8{ "--upgrade-signal.contract", "0x12" };
    try std.testing.expectError(error.InvalidAddress, parse_flags(&bad_address));
    try std.testing.expect(disabled.p2p_disabled);
    try std.testing.expectError(
        error.MissingValue,
        parse_flags(&(required ++ [_][]const u8{"--p2p.listen.tcp"})),
    );
    try std.testing.expectError(error.UnknownFlag, parse_flags(&.{ "--nope", "1" }));
    try std.testing.expectError(error.UnsupportedUrl, parse_url("https://127.0.0.1:1"));
    try std.testing.expectError(error.MissingPort, parse_url("http://127.0.0.1"));
    try std.testing.expectError(error.InvalidAddress, parse_url("http://1.2.3.4.5:1"));
    const address = try parse_url("http://10.0.0.1:8545/");
    try std.testing.expectEqual(@as(u8, 10), address.bytes[0]);
}

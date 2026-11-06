//! `base withdrawer <command>`: L2 to L1 withdrawals (base/base `bin/withdrawer`). Commands:
//! `initiate` (send `initiateWithdrawal` on L2), `status` (print the next step), `prove`,
//! `finalize`, and `run` (all steps, waiting out the delays). Every broadcast is journaled to
//! `--journal` before it leaves, so a restarted run resumes without double-sending. See
//! `src/infra/withdrawer`.
//!
//! The signer is a private key (`--private-key` / `BASE_WITHDRAWER_PRIVATE_KEY`, prefer the
//! environment) or, for devnets only, an index into the public dev mnemonic.

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const Io = std.Io;
const cli = base.utilities.cli;
const rpc = base.batcher.rpc;
const accounts = base.batcher.devnet.accounts;
const withdrawer = base.infra.withdrawer;
const flow_module = withdrawer.flow;
const journal_module = withdrawer.journal;

const assert = std.debug.assert;
const env_prefix = "BASE_WITHDRAWER_";
const journal_bytes_max = 64 << 20;
const no_dev_account = std.math.maxInt(u32);

pub const Spec = struct {
    l1_rpc_url: []const u8,
    l2_rpc_url: []const u8 = "",
    portal: []const u8,
    l1_chain_id: u64,
    l2_chain_id: u64 = 0,
    transaction: []const u8 = "",
    private_key: []const u8 = "",
    dev_account: u32 = no_dev_account,
    journal: []const u8 = "withdrawer.journal",
    target: []const u8 = "",
    value_wei: u64 = 0,
    gas_limit: u64 = 100_000,
    data: []const u8 = "",
    poll_interval_s: u32 = 12,
    confirmations: u64 = 1,
    network_timeout_ms: u64 = 10_000,

    pub const help = .{
        .l1_rpc_url = "L1 JSON-RPC endpoint (http://...)",
        .l2_rpc_url = "L2 JSON-RPC endpoint (http://...)",
        .portal = "OptimismPortal2 address on L1",
        .l1_chain_id = "L1 chain id to sign for",
        .l2_chain_id = "L2 chain id to sign initiate transactions for",
        .transaction = "Initiating L2 transaction hash (else the journal's initiate)",
        .private_key = "Signer key, 0x hex; prefer the environment variable",
        .dev_account = "Devnet only: index into the public dev mnemonic instead of a key",
        .journal = "Append-only broadcast journal file (resumes a crashed run)",
        .target = "initiate: L1 target address",
        .value_wei = "initiate: value to withdraw, in wei",
        .gas_limit = "initiate: L1 gas limit of the withdrawal call",
        .data = "initiate: L1 calldata, 0x hex",
        .poll_interval_s = "Seconds between status polls while waiting",
        .confirmations = "Blocks deep before a sent transaction counts",
        .network_timeout_ms = "Per-request RPC timeout",
    };
};

pub const Signer = struct { private_key: [32]u8, address: [20]u8 };

pub const Parsed = struct {
    command: flow_module.Command,
    portal: [20]u8,
    transaction: ?[32]u8,
    signer: Signer,
    initiate: ?flow_module.Initiate,
    data_buffer: [4096]u8 = undefined,
};

pub fn parse_hex(comptime size: usize, text: []const u8) ![size]u8 {
    const digits = if (std.mem.startsWith(u8, text, "0x")) text[2..] else text;
    if (digits.len != size * 2) return error.InvalidHex;
    var out: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, digits) catch return error.InvalidHex;
    return out;
}

fn parse_signer(spec: Spec) !Signer {
    if (spec.private_key.len > 0) {
        if (spec.dev_account != no_dev_account) return error.ConflictingSigner;
        const key = try parse_hex(32, spec.private_key);
        if (std.mem.allEqual(u8, &key, 0)) return error.InvalidKey;
        return .{ .private_key = key, .address = accounts.address_of(key).bytes };
    }
    const index = spec.dev_account;
    if (index == no_dev_account) return error.MissingSigner;
    if (index >= accounts.funded_count) return error.InvalidValue;
    const account = accounts.derive_dev(index);
    return .{ .private_key = account.private_key, .address = account.address.bytes };
}

/// Validates flags for `command`. `parsed.initiate.data` points into `parsed.data_buffer`.
pub fn parse_config(command: flow_module.Command, spec: Spec, parsed: *Parsed) !void {
    if (spec.poll_interval_s == 0 or spec.confirmations == 0) return error.InvalidValue;
    parsed.command = command;
    parsed.portal = try parse_hex(20, spec.portal);
    parsed.transaction = null;
    if (spec.transaction.len > 0) parsed.transaction = try parse_hex(32, spec.transaction);
    parsed.signer = try parse_signer(spec);
    parsed.initiate = null;
    if (spec.target.len > 0) {
        const digits = if (std.mem.startsWith(u8, spec.data, "0x")) spec.data[2..] else spec.data;
        if (digits.len / 2 > parsed.data_buffer.len) return error.DataTooLarge;
        const data = std.fmt.hexToBytes(&parsed.data_buffer, digits) catch return error.InvalidHex;
        parsed.initiate = .{
            .target = try parse_hex(20, spec.target),
            .value = spec.value_wei,
            .gas_limit = spec.gas_limit,
            .data = data,
        };
    }
    if (command == .initiate and parsed.initiate == null) return error.MissingTarget;
    const needs_l2 = command == .initiate or parsed.initiate != null or parsed.transaction != null;
    if (needs_l2 and spec.l2_rpc_url.len == 0) return error.MissingL2Rpc;
    if (parsed.initiate != null and spec.l2_chain_id == 0) return error.MissingL2ChainId;
    assert(parsed.command == command);
}

fn print_help() void {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("usage: base withdrawer <initiate|status|prove|finalize|run> " ++
        "--l1-rpc-url URL --portal ADDRESS --l1-chain-id ID\n{s}", .{writer.buffered()});
}

fn now_ms(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).toMilliseconds());
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0) {
        print_help();
        return 2;
    }
    const command = std.meta.stringToEnum(flow_module.Command, args[0]) orelse {
        if (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) {
            print_help();
            return 0;
        }
        std.debug.print("withdrawer: unknown command {s}\n", .{args[0]});
        print_help();
        return 2;
    };
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args[1..], env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("withdrawer: {t}: {s}\n", .{ err, diagnostic.subject });
        return 2;
    };
    const parsed = try init.gpa.create(Parsed);
    defer init.gpa.destroy(parsed);
    parse_config(command, spec, parsed) catch |err| {
        std.debug.print("withdrawer: invalid flags: {t}\n", .{err});
        return 2;
    };
    return run(init, spec, parsed);
}

const Clients = struct {
    l1_http: HttpTransport,
    l2_http: HttpTransport,
    l1: rpc.Client,
    l2: rpc.Client,

    fn init(clients: *Clients, gpa: std.mem.Allocator, io: Io, spec: Spec) !void {
        const l2_url = if (spec.l2_rpc_url.len > 0) spec.l2_rpc_url else spec.l1_rpc_url;
        clients.l1_http = HttpTransport.init(gpa, io, spec.l1_rpc_url);
        clients.l2_http = HttpTransport.init(gpa, io, l2_url);
        clients.l1_http.timeout_ms = spec.network_timeout_ms;
        clients.l2_http.timeout_ms = spec.network_timeout_ms;
        const limits: rpc.Limits = .{
            .request_bytes_max = 256 * 1024,
            .response_bytes_max = 1024 * 1024,
            .parse_bytes_max = 8 * 1024 * 1024,
        };
        clients.l1 = try rpc.Client.init(gpa, clients.l1_http.transport(), limits);
        errdefer clients.l1.deinit(gpa);
        clients.l2 = try rpc.Client.init(gpa, clients.l2_http.transport(), limits);
    }

    fn deinit(clients: *Clients, gpa: std.mem.Allocator) void {
        clients.l2.deinit(gpa);
        clients.l1.deinit(gpa);
        clients.l2_http.deinit();
        clients.l1_http.deinit();
    }
};

/// The journal file: replayed at start, then appended and synced per record.
const JournalFile = struct {
    io: Io,
    file: Io.File,
    length: u64,

    fn open(
        gpa: std.mem.Allocator,
        io: Io,
        path: []const u8,
        replay: *journal_module.Replay,
    ) !JournalFile {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = false });
        errdefer file.close(io);
        const size = try file.length(io);
        if (size > journal_bytes_max) return error.JournalTooLarge;
        const bytes = try gpa.alloc(u8, @intCast(size));
        defer gpa.free(bytes);
        const read = try file.readPositionalAll(io, bytes, 0);
        if (read != bytes.len) return error.ShortRead;
        replay.* = try journal_module.replay(bytes);
        // Drop a record torn by a crash mid-write before appending after it.
        if (replay.valid_length < size) try file.setLength(io, replay.valid_length);
        assert(replay.valid_length <= size);
        return .{ .io = io, .file = file, .length = replay.valid_length };
    }

    fn sink(journal: *JournalFile) flow_module.JournalSink {
        return .{ .context = journal, .append = append };
    }

    fn append(context: *anyopaque, record: journal_module.Record) bool {
        const journal: *JournalFile = @ptrCast(@alignCast(context));
        var bytes: [journal_module.record_bytes]u8 = undefined;
        journal_module.encode(record, &bytes);
        journal.file.writePositionalAll(journal.io, &bytes, journal.length) catch return false;
        journal.file.sync(journal.io) catch return false;
        journal.length += journal_module.record_bytes;
        return true;
    }
};

fn run(init: std.process.Init, spec: Spec, parsed: *const Parsed) !u8 {
    const gpa = init.gpa;
    var clients: Clients = undefined;
    try clients.init(gpa, init.io, spec);
    defer clients.deinit(gpa);
    var replay: journal_module.Replay = .{};
    var journal = try JournalFile.open(gpa, init.io, spec.journal, &replay);
    defer journal.file.close(init.io);
    var reader = try withdrawer.reader.Reader.init(
        gpa,
        &clients.l1,
        &clients.l2,
        parsed.portal,
        parsed.signer.address,
        .{},
    );
    defer reader.deinit(gpa);
    if (command_needs_l1(parsed.command)) _ = reader.resolve_contracts() catch |err| {
        std.debug.print("withdrawer: reading portal contracts: {t}\n", .{err});
        return 1;
    };
    const drivers = try gpa.create([2]flow_module.SendDriver);
    defer gpa.destroy(drivers);
    const SendDriver = flow_module.SendDriver;
    drivers[0] = try SendDriver.init(gpa, driver_config(spec, parsed, spec.l1_chain_id));
    defer drivers[0].deinit(gpa);
    drivers[1] = try SendDriver.init(gpa, driver_config(spec, parsed, spec.l2_chain_id));
    defer drivers[1].deinit(gpa);
    var flow = flow_module.Flow.init(gpa, .{
        .command = parsed.command,
        .l2_transaction = parsed.transaction,
        .initiate = parsed.initiate,
        .poll_interval_ms = @as(u64, spec.poll_interval_s) * 1000,
    }, &reader, &drivers[0], &drivers[1], journal.sink(), replay) catch |err| {
        std.debug.print("withdrawer: {t} (pass --transaction or --target)\n", .{err});
        return 2;
    };
    defer flow.deinit(gpa);
    drivers[0].config.publish_hook = flow.publish_hook();
    drivers[1].config.publish_hook = flow.publish_hook();
    loop(init.io, &flow) catch |err| {
        std.debug.print("withdrawer: {t}\n", .{err});
        report(&flow);
        return 1;
    };
    report(&flow);
    return 0;
}

fn command_needs_l1(command: flow_module.Command) bool {
    return command != .initiate;
}

fn driver_config(
    spec: Spec,
    parsed: *const Parsed,
    chain_id: u64,
) base.infra.tx_manager.driver.Config {
    return .{
        .chain_id = chain_id,
        .private_key = parsed.signer.private_key,
        .from = .{ .bytes = parsed.signer.address },
        .data_bytes_max = 64 * 1024,
        .manager = .{
            .num_confirmations = spec.confirmations,
            .receipt_query_interval_ms = 2_000,
        },
    };
}

fn loop(io: Io, flow: *flow_module.Flow) !void {
    var reported_ms: u64 = 0;
    while (true) {
        const now = now_ms(io);
        switch (try flow.step(now)) {
            .done => return,
            .working => {},
            .waiting => |waiting| {
                if (now >= reported_ms + 60_000) {
                    reported_ms = now;
                    report(flow);
                }
                const sleep_ms = @min(waiting.until_ms -| now, 5_000);
                try io.sleep(.fromMilliseconds(@intCast(@max(sleep_ms, 100))), .awake);
            },
        }
    }
}

fn report(flow: *const flow_module.Flow) void {
    if (flow.l2_transaction) |hash| std.debug.print("l2 transaction 0x{x}\n", .{&hash});
    for (flow.results()) |outcome| {
        std.debug.print("withdrawal 0x{x}: ", .{&outcome.withdrawal_hash});
        switch (outcome.status) {
            .not_ready => |not_ready| std.debug.print(
                "not ready (ready at {d}, l1 time {d}, waiting for game {})",
                .{ not_ready.ready_at, not_ready.l1_timestamp, not_ready.waiting_for_game },
            ),
            else => |status| std.debug.print("{t}", .{status}),
        }
        if (outcome.transaction) |hash| std.debug.print(", l1 transaction 0x{x}", .{&hash});
        std.debug.print("\n", .{});
    }
}

const testing = std.testing;

test "withdrawer: flags to config" {
    const parsed = try testing.allocator.create(Parsed);
    defer testing.allocator.destroy(parsed);
    const portal = "0x5050505050505050505050505050505050505050";
    try parse_config(.status, .{
        .l1_rpc_url = "http://127.0.0.1:8545",
        .l2_rpc_url = "http://127.0.0.1:9545",
        .portal = portal,
        .l1_chain_id = 900,
        .transaction = "0x" ++ ("abababababababababababababababab" ++
            "abababababababababababababababab"),
        .dev_account = 3,
    }, parsed);
    try testing.expectEqual(@as(u8, 0xab), parsed.transaction.?[31]);
    const dev = accounts.derive_dev(3);
    try testing.expectEqualSlices(u8, &dev.address.bytes, &parsed.signer.address);
    try testing.expectError(error.MissingSigner, parse_config(.status, .{
        .l1_rpc_url = "http://127.0.0.1:8545",
        .portal = portal,
        .l1_chain_id = 900,
    }, parsed));
    try testing.expectError(error.MissingTarget, parse_config(.initiate, .{
        .l1_rpc_url = "http://127.0.0.1:8545",
        .l2_rpc_url = "http://127.0.0.1:9545",
        .portal = portal,
        .l1_chain_id = 900,
        .dev_account = 1,
    }, parsed));
    try parse_config(.initiate, .{
        .l1_rpc_url = "http://127.0.0.1:8545",
        .l2_rpc_url = "http://127.0.0.1:9545",
        .portal = portal,
        .l1_chain_id = 900,
        .l2_chain_id = 901,
        .dev_account = 1,
        .target = "0x7777777777777777777777777777777777777777",
        .data = "0xbeef",
    }, parsed);
    try testing.expectEqualSlices(u8, "\xbe\xef", parsed.initiate.?.data);
}

//! `base state-check`: spot-checks a disk-mode database's state at its head N against a
//! reference node over JSON-RPC (docs/SYNC_PLAN.md M3: "spot-check 10,000 random accounts and
//! storage slots against a reference node").
//!
//!     base state-check --db <path> [--chain base-sepolia|base-mainnet] [--rpc <url>]
//!                      [--samples <n>] [--accounts <n>] [--seed <n>] [--interval-ms <n>]
//!
//! The database opens read-write with the sizing of `<path>.counts` (as `import-run` and
//! `el-run` open it; a file another process holds fails with `FileLocked`) and nothing is
//! written: every read is a trie walk (`DiskState.verify_leaf`), a flat record lookup, or a
//! code table lookup. The reference must agree on block N's hash and state root
//! (`eth_getBlockByNumber`), or the check stops: the reference is on another block.
//!
//! Samples (`state_check_sample.zig`) are chosen from `--seed` and the reference's answers:
//! `--accounts` of `--samples` (default one in 200) are accounts drawn from recent blocks' logs
//! and transactions and the system contracts, the rest are slots of those accounts (own
//! slots, holder-map keys, generic mapping keys, and the EIP-2935/EIP-4788 rings, which keep
//! at least 30% of the samples nonzero slots). Every account is compared with `eth_getProof`
//! at N (nonce, balance, code hash, storage root), through the trie and from the flat record;
//! every slot with its `storageProof` value (zeros included), both ways; every distinct code
//! from the code tables against the code hash, the first few also against `eth_getCode` at N
//! (`state_check_compare.zig`).
//!
//! The reference is rate limited per call, not per key (`state_check_rpc.zig`), so each
//! account costs a call and slots ride along, up to 1024 keys a call. Public endpoints serve
//! `eth_getProof` for the most recent ~10,000 blocks only (sepolia.base.org: about 33
//! minutes), so the check refuses a head the planned calls cannot finish before it leaves the
//! window, re-reads the window every five minutes, and stops at the deadline or at the first
//! answer that says the state is out of range, printing what it checked and why it stopped.
//! Other keyless Base Sepolia endpoints (publicnode, drpc) refuse proofs even ten blocks
//! back, so there is no second endpoint.
//!
//! Exit status: 0 every sample matches, 1 a mismatch (or the reference is on another block),
//! 2 bad arguments, 3 the check could not run or finish (database, window, or endpoint).

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const HttpTransport = @import("http_transport.zig").HttpTransport;
const import_run_cli = @import("import_run.zig");
const snapshot_import_out = @import("snapshot_import_out.zig");
const compare = @import("state_check_compare.zig");
const sample = @import("state_check_sample.zig");
const rpc = @import("state_check_rpc.zig");
const Endpoint = rpc.Endpoint;

const to_disk = base.execution.import.to_disk;
const node = base.execution.trie.node;
const json = std.json;
const assert = std.debug.assert;

const IO = base.utilities.io.IO;
const Storage = base.execution.db.storage.IoStorageType(IO);
const Importer = to_disk.ImporterType(Storage);
const Database = Importer.Database;
const DiskState = Database.DiskState;
const Hash = [32]u8;
const Address = [20]u8;

const usage =
    \\usage: base state-check --db <path> [--chain base-sepolia|base-mainnet] [--rpc <url>]
    \\                        [--samples <n>] [--accounts <n>] [--seed <n>] [--interval-ms <n>]
    \\  --db           a disk-mode database (and <path>.counts); opened, never written
    \\  --rpc          reference JSON-RPC endpoint (eth_getProof, eth_getCode, eth_getLogs)
    \\  --samples      accounts plus slots to check (default 10000)
    \\  --accounts     of the samples, accounts: one eth_getProof call each (default 1 in 200)
    \\  --seed         sample selection seed (default 1)
    \\  --interval-ms  starting spacing of calls; it adapts to rate limits (default 6000)
    \\exit status: 0 all match, 1 mismatch, 2 usage, 3 could not check
    \\
;

const exit_mismatch = 1;
const exit_usage = 2;
const exit_unchecked = 3;

const samples_default = 10_000;
const samples_min = 10;
const samples_max = 100_000;
/// One sample in this many is an account by default: each costs a rate-limited call, while
/// a call carries up to `sample.keys_per_call_max` slots.
const accounts_divisor = 200;
const interval_min_ms = 500;
const interval_max_ms = 60_000;

const Flags = struct {
    db: []const u8,
    chain: *const import_run_cli.Chain = &import_run_cli.chains[0],
    rpc: ?[]const u8 = null,
    samples: u32 = samples_default,
    accounts: u32 = 0,
    seed: u64 = 1,
    interval_ms: u32 = rpc.Pacer.Config.interval_initial_default_ms,
};

fn parse(args: []const []const u8) !Flags {
    var db: ?[]const u8 = null;
    var flags: Flags = .{ .db = undefined };
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (index + 1 == args.len) return error.InvalidArguments;
        const name = args[index];
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, name, "--db")) {
            db = value;
        } else if (std.mem.eql(u8, name, "--chain")) {
            flags.chain = for (&import_run_cli.chains) |*chain| {
                if (std.mem.eql(u8, chain.name, value)) break chain;
            } else return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--rpc")) {
            const http = std.mem.startsWith(u8, value, "http://") or
                std.mem.startsWith(u8, value, "https://");
            if (!http) return error.InvalidArguments;
            flags.rpc = value;
        } else if (std.mem.eql(u8, name, "--samples")) {
            flags.samples = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (flags.samples < samples_min or flags.samples > samples_max) {
                return error.InvalidArguments;
            }
        } else if (std.mem.eql(u8, name, "--accounts")) {
            flags.accounts = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (flags.accounts == 0) return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--seed")) {
            flags.seed = std.fmt.parseInt(u64, value, 10) catch return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--interval-ms")) {
            const interval = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (interval < interval_min_ms or interval > interval_max_ms) {
                return error.InvalidArguments;
            }
            flags.interval_ms = interval;
        } else return error.InvalidArguments;
    }
    flags.db = db orelse return error.InvalidArguments;
    if (flags.db.len == 0) return error.InvalidArguments;
    if (flags.accounts == 0) flags.accounts = @max(flags.samples / accounts_divisor, 1);
    if (flags.accounts > flags.samples / 2) return error.InvalidArguments;
    assert(flags.samples >= samples_min and flags.samples <= samples_max);
    assert(flags.accounts > 0 and flags.accounts < flags.samples);
    return flags;
}

// The reference endpoint (`state_check_rpc.zig`).

const response_bytes_max = 64 << 20;
/// Blocks back from its head for which the public endpoint serves `eth_getProof`.
const proof_window_blocks = 10_000;
const block_time_ms = 200;
/// Blocks of the window kept unused: the check stops this far before N leaves it.
const window_margin_blocks = 150;
/// The window is re-read (`eth_blockNumber`) this often while proofs are fetched.
const window_refresh_ms = 5 * 60_000;
/// Logs are read in chunks of blocks back from N until the pool holds two addresses per
/// sampled account, or `logs_blocks_max` blocks were read. sepolia.base.org refuses
/// `eth_getLogs` ranges over 200 blocks ("eth_getLogs is limited to a 200 range").
const logs_chunk_blocks = 100;
const logs_blocks_max = 2_000;
/// Blocks back from N whose transactions' senders and recipients join the pool.
const transaction_blocks = 1;
/// Codes fetched with `eth_getCode` as a cross-check of the reference itself (every code is
/// checked against the reference's code hash without a call).
const reference_codes_max = 3;
/// Calls per request. sepolia.base.org charges every call of a batch and refuses bursts of
/// more than a few, so a batch is a burst: five-call batches got 8 of 29 calls refused and
/// ~6 calls a minute through, evenly spaced single calls 10 a minute with none refused. A
/// proof's cost also grows with its keys and with N's distance from the tip (1024 keys:
/// ~1 s 600 blocks back, ~15 s 5,900 back; 5 x 1024 keys: no answer in 60 s).
const calls_per_request = 1;
/// The spacing the window guard plans with: twice sepolia.base.org's best sustained rate
/// (one call every 6 s held for 20 calls one hour, and half were refused the next).
const guard_interval_ms = 12_000;
const http_timeout_ms = 90_000;

// The window.

/// Calls the check makes for `accounts` accounts and `slots` slots: the setup (tip, probe,
/// block, transactions, logs), one proof per account, a second-phase proof for up to
/// `sample.second_phase_share` of them, ring proofs, the window re-reads, and codes.
fn calls_estimate(accounts: u64, slots: u64) u64 {
    assert(accounts > 0);
    const setup = 3 + transaction_blocks + logs_blocks_max / logs_chunk_blocks / 2;
    const ring = slots / sample.keys_per_call_max + 2;
    const calls = setup + accounts + accounts / sample.second_phase_share + ring + 4 +
        reference_codes_max;
    assert(calls > accounts);
    return calls;
}

/// Whether `calls` calls at `interval_ms` apart end before block N, `behind` blocks behind
/// the tip now, leaves the window (with `window_margin_blocks` to spare).
fn window_holds(behind: u64, calls: u64, interval_ms: u64) bool {
    const run_blocks = calls * interval_ms / block_time_ms;
    const holds = behind + run_blocks + window_margin_blocks < proof_window_blocks;
    assert(!holds or behind < proof_window_blocks);
    return holds;
}

/// The awake-clock time at which block N, `behind` blocks behind the tip at `now_ms`, comes
/// within `window_margin_blocks` of leaving the window.
fn deadline_of(now_ms: i64, behind: u64) i64 {
    const left = proof_window_blocks -| (behind + window_margin_blocks);
    const deadline = now_ms + @as(i64, @intCast(left * block_time_ms));
    assert(deadline >= now_ms);
    return deadline;
}

// The check.

const SlotCounts = struct { zero: u64 = 0, nonzero: u64 = 0 };

const Check = struct {
    io: Io,
    flags: *const Flags,
    endpoint: *Endpoint,
    db: *Database,
    disk: *DiskState,
    head: u64,
    scratch: std.heap.ArenaAllocator,
    keep: std.heap.ArenaAllocator,
    report: *compare.Report,
    /// The reference's fields of every sampled account.
    accounts: std.AutoArrayHashMapUnmanaged(Address, compare.Fields) = .empty,
    /// Holder-map indices that came back nonzero, per contract.
    learned: std.AutoHashMapUnmanaged(Address, u16) = .empty,
    slots: [sample.kinds.len]SlotCounts = @splat(.{}),
    codes: u64 = 0,
    code_accounts: u64 = 0,
    started_ms: i64,
    behind_start: u64 = 0,
    /// What the check is doing (printed when it stops).
    phase: []const u8 = "opening",
    /// When the window was last re-read.
    window_read_ms: i64 = 0,
    codes_fetched: u64 = 0,

    fn now_ms(check: *const Check) i64 {
        return Io.Clock.awake.now(check.io).toMilliseconds();
    }

    fn elapsed_s(check: *const Check) f64 {
        return @as(f64, @floatFromInt(check.now_ms() - check.started_ms)) / 1000;
    }

    fn nonzero(check: *const Check) u64 {
        var total: u64 = 0;
        for (check.slots) |counts| total += counts.nonzero;
        return total;
    }

    fn zero(check: *const Check) u64 {
        var total: u64 = 0;
        for (check.slots) |counts| total += counts.zero;
        return total;
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return exit_usage;
    };
    const gpa = init.gpa;
    const counts_path = try std.fmt.allocPrint(gpa, "{s}.counts", .{flags.db});
    defer gpa.free(counts_path);
    var buffer: [to_disk.Counts.encoded_size]u8 = undefined;
    const bytes = Io.Dir.cwd().readFile(init.io, counts_path, &buffer) catch |err| {
        std.debug.print("cannot read {s}: {t} (written by snapshot-import --out)\n", .{
            counts_path, err,
        });
        return exit_unchecked;
    };
    const counts = to_disk.Counts.decode(bytes) catch {
        std.debug.print("{s} is not a counts record\n", .{counts_path});
        return exit_unchecked;
    };
    const sizing = try to_disk.sizing(Storage, counts, to_disk.node_shape(counts));
    var backend = try snapshot_import_out.backend_init();
    defer backend.deinit();
    const Opened = snapshot_import_out.Opened;
    var opened = Opened.init(gpa, &backend, flags.db, sizing.config, false) catch |err| {
        if (err == error.FileLocked) {
            std.debug.print("cannot open {s}: FileLocked: another process (a running node?) " ++
                "holds it; stop it, or check a copy\n", .{flags.db});
        } else std.debug.print("cannot open {s}: {t}\n", .{ flags.db, err });
        return exit_unchecked;
    };
    defer opened.deinit(gpa, &backend);
    var ticker: snapshot_import_out.Ticker = .{ .backend = &backend, .storage = opened.storage };
    Importer.open(opened.db, ticker.driver()) catch |err| {
        std.debug.print("cannot open the database in {s}: {t}\n", .{ flags.db, err });
        return exit_unchecked;
    };
    if (!import_run_cli.usable(opened.db, flags.chain)) return exit_unchecked;
    const disk = if (opened.db.disk) |*disk| disk else {
        std.debug.print("{s} is not a disk-mode database\n", .{flags.db});
        return exit_unchecked;
    };
    if (!std.mem.eql(u8, &disk.root(), &opened.db.head_info.state_root)) {
        std.debug.print("the state is not at the head's root\n", .{});
        return exit_unchecked;
    }
    return check_state(init, &flags, opened.db, disk);
}

fn check_state(init: std.process.Init, flags: *const Flags, db: *Database, disk: *DiskState) !u8 {
    const gpa = init.gpa;
    assert(db.head_info.present);
    const response = try gpa.alloc(u8, response_bytes_max);
    defer gpa.free(response);
    const url = flags.rpc orelse flags.chain.rpc;
    var endpoint: Endpoint = .{
        .io = init.io,
        .http = .init(gpa, init.io, url),
        .response = response,
        .pacer = .init(.{
            .interval_initial_ms = flags.interval_ms,
            .interval_min_ms = @min(flags.interval_ms, rpc.Pacer.Config.interval_floor_ms),
            .interval_max_ms = @max(flags.interval_ms, rpc.Pacer.Config.interval_ceiling_ms),
        }),
    };
    defer endpoint.http.deinit();
    endpoint.http.timeout_ms = http_timeout_ms;
    const report = try gpa.create(compare.Report);
    defer gpa.destroy(report);
    report.* = .{ .print = true };
    var check: Check = .{
        .io = init.io,
        .flags = flags,
        .endpoint = &endpoint,
        .db = db,
        .disk = disk,
        .head = db.head_info.number,
        .scratch = .init(gpa),
        .keep = .init(gpa),
        .report = report,
        .started_ms = 0,
    };
    defer check.scratch.deinit();
    defer check.keep.deinit();
    check.started_ms = check.now_ms();
    const status = run(&check) catch |err| return stopped(&check, err);
    assert(status <= exit_unchecked);
    return status;
}

/// Reports why the check stopped early, with what it had checked; the exit status.
fn stopped(check: *Check, err: anyerror) !u8 {
    const url = check.endpoint.http.url;
    std.debug.print("state-check: STOPPED during {s} after {d:.0} s: ", .{
        check.phase,
        check.elapsed_s(),
    });
    switch (err) {
        error.OutOfWindow => std.debug.print("the reference does not serve state at block " ++
            "{d} (outside its eth_getProof window: \"{s}\"); use a fresher database copy\n", .{
            check.head, check.endpoint.problem(),
        }),
        error.WindowClosing => std.debug.print("block {d} is about to leave {s}'s " ++
            "eth_getProof window (deadline reached, last problem: \"{s}\"); use a fresher " ++
            "copy or fewer --samples/--accounts\n", .{ check.head, url, check.endpoint.problem() }),
        error.EndpointFailed => std.debug.print("{s} failed {d} times in a row without a rate " ++
            "limit (last: \"{s}\")\n", .{ url, rpc.failures_max, check.endpoint.problem() }),
        error.MalformedResponse => std.debug.print("{s} sent an answer that does not decode " ++
            "(last problem: \"{s}\")\n", .{ url, check.endpoint.problem() }),
        error.DatabaseFault => std.debug.print("FAILED: the database faulted on a read (a " ++
            "missing or corrupt record)\n", .{}),
        else => {
            std.debug.print("{t}\n", .{err});
            return err;
        },
    }
    summary(check);
    assert(check.report.total <= std.math.maxInt(u64));
    if (err == error.DatabaseFault or check.report.total > 0) return exit_mismatch;
    return exit_unchecked;
}

fn run(check: *Check) !u8 {
    std.debug.print("state-check: {s} block {d}, {d} samples ({d} accounts), seed {d}, " ++
        "reference {s}\n", .{
        check.flags.chain.name, check.head,       check.flags.samples,
        check.flags.accounts,   check.flags.seed, check.endpoint.http.url,
    });
    check.phase = "the window guard";
    if (!try check_window(check)) return exit_unchecked;
    check.phase = "the block check";
    if (!try check_block(check)) return exit_mismatch;
    var prng: std.Random.DefaultPrng = .init(check.flags.seed);
    const arena = check.keep.allocator();
    var pool: sample.Pool = .{};
    check.phase = "collecting addresses";
    try collect_pool(check, &pool, check.flags.accounts);
    const accounts = try sample.select_accounts(arena, prng.random(), &pool, check.flags.accounts);
    const slots_target = check.flags.samples - accounts.len;
    std.debug.print("samples: {d} accounts from {d} addresses ({d} log emitters), " ++
        "{d} slots\n", .{
        accounts.len, pool.addresses.count(), pool.holders.count(), slots_target,
    });
    var planner: sample.Planner = .{ .arena = arena, .random = prng.random() };
    try prove_slots(check, &planner, &pool, accounts, slots_target);
    check.phase = "codes";
    try check_codes(check);
    final_window(check);
    summary(check);
    return verdict(check);
}

/// The three proof phases (`state_check_sample.zig`).
fn prove_slots(
    check: *Check,
    planner: *sample.Planner,
    pool: *const sample.Pool,
    accounts: []const Address,
    slots_target: u64,
) !void {
    assert(accounts.len > 0);
    check.phase = "accounts and probes";
    const first = try sample.plan_accounts(planner, accounts, pool, slots_target / 2);
    try prove(check, first, true);
    progress(check, "accounts and probes");
    const contracts = try contracts_of(check, accounts);
    // Keep room for ring slots (nonzero) when the probes found too few nonzero words.
    const nonzero_min = (@as(u64, check.flags.samples) * 3 + 9) / 10;
    const remaining = slots_target - planner.planned;
    const reserve = @min(remaining, nonzero_min -| check.nonzero());
    const budget = planner.planned + remaining - reserve;
    const calls_max = accounts.len / sample.second_phase_share + 1;
    check.phase = "contract slots";
    const second = try sample.plan_contracts(planner, contracts, accounts, pool, budget, calls_max);
    try prove(check, second, false);
    progress(check, "contract slots");
    var rings: std.ArrayList(Address) = .empty;
    for ([_]Address{ sample.history_contract, sample.beacon_roots_contract }) |ring| {
        const fields = check.accounts.get(ring) orelse continue;
        if (fields.has_code()) try rings.append(check.keep.allocator(), ring);
    }
    check.phase = "ring slots";
    const third = try sample.plan_ring(planner, rings.items, slots_target - planner.planned);
    try prove(check, third, false);
    progress(check, "ring slots");
    assert(planner.planned <= slots_target);
}

fn verdict(check: *const Check) u8 {
    const nonzero_min = (@as(u64, check.flags.samples) * 3 + 9) / 10;
    if (check.nonzero() < nonzero_min) {
        std.debug.print("note: {d} nonzero slots, under 30% of the samples\n", .{check.nonzero()});
    }
    if (check.report.total > 0) {
        std.debug.print("state-check: FAILED: {d} mismatches at block {d} (printed above)\n", .{
            check.report.total, check.head,
        });
        return exit_mismatch;
    }
    std.debug.print("state-check: ok: every sample matches the reference at block {d}\n", .{
        check.head,
    });
    assert(check.report.total == 0);
    return 0;
}

/// The reference's tip, and block N's distance behind it.
fn read_tip(check: *Check) !u64 {
    _ = check.scratch.reset(.retain_capacity);
    const arena = check.scratch.allocator();
    const tip_value = try check.endpoint.call(arena, "eth_blockNumber", "[]");
    if (tip_value != .string) return error.MalformedResponse;
    const tip = try compare.parse_u64(tip_value.string);
    check.window_read_ms = check.now_ms();
    if (tip >= check.head) {
        check.endpoint.deadline_ms = deadline_of(check.window_read_ms, tip - check.head);
    }
    assert(check.window_read_ms > 0 or tip >= 0);
    return tip;
}

/// The window guard: the reference's tip, how far N is behind it, and a probe of
/// `eth_getProof` at N. False (reported) when the planned calls at `guard_interval_ms` would
/// not end before N leaves the window.
fn check_window(check: *Check) !bool {
    const tip = try read_tip(check);
    if (tip < check.head) {
        std.debug.print("window: the reference's tip {d} is behind block {d}; it cannot serve " ++
            "that block yet\n", .{ tip, check.head });
        return false;
    }
    const slots = check.flags.samples - check.flags.accounts;
    const calls = calls_estimate(check.flags.accounts, slots);
    const interval_ms = @max(guard_interval_ms, check.flags.interval_ms);
    const behind = tip - check.head;
    const holds = window_holds(behind, calls, interval_ms);
    std.debug.print("window: reference tip {d}; block {d} is {d} blocks (~{d} s) behind; " ++
        "eth_getProof is served {d} blocks back; ~{d} calls at {d} ms each take ~{d} s, " ++
        "~{d} s are left: {s}\n", .{
        tip,
        check.head,
        behind,
        behind * block_time_ms / 1000,
        proof_window_blocks,
        calls,
        interval_ms,
        calls * interval_ms / 1000,
        (proof_window_blocks -| (behind + window_margin_blocks)) * block_time_ms / 1000,
        if (holds) "ok" else "REFUSED",
    });
    if (!holds) {
        std.debug.print("window: block {d} would leave the reference's window before the " ++
            "check ends; use a fresher database copy or fewer --samples/--accounts\n", .{
            check.head,
        });
        return false;
    }
    // The first eth_getProof at N: an out-of-window answer stops the check here.
    const arena = check.scratch.allocator();
    const params = try std.fmt.allocPrint(arena, "[\"0x{x}\",[],\"0x{x}\"]", .{
        sample.system_contracts[0],
        check.head,
    });
    _ = try check.endpoint.call(arena, "eth_getProof", params);
    std.debug.print("window: eth_getProof at block {d}: served\n", .{check.head});
    check.behind_start = behind;
    assert(check.behind_start < proof_window_blocks);
    return true;
}

/// Re-reads the tip every `window_refresh_ms` (the deadline moves with the chain's real pace).
fn refresh_window(check: *Check) !void {
    if (check.now_ms() - check.window_read_ms < window_refresh_ms) return;
    const tip = try read_tip(check);
    const behind = tip -| check.head;
    std.debug.print("window: block {d} is {d} blocks behind the tip; ~{d} s left " ++
        "(interval {d} ms)\n", .{
        check.head,
        behind,
        @divTrunc(@max(check.endpoint.deadline_ms - check.now_ms(), 0), 1000),
        check.endpoint.pacer.interval_ms,
    });
    if (behind + window_margin_blocks >= proof_window_blocks) return error.WindowClosing;
    assert(check.endpoint.deadline_ms > check.now_ms());
}

/// Where N stands in the window once the check is done (informational).
fn final_window(check: *Check) void {
    const tip = read_tip(check) catch |err| {
        std.debug.print("window: tip unavailable at the end ({t})\n", .{err});
        return;
    };
    assert(check.head > 0 or tip >= 0);
    std.debug.print("window: done; block {d} was {d} blocks behind the tip at the start and " ++
        "{d} at the end (limit {d})\n", .{
        check.head, check.behind_start, tip -| check.head, proof_window_blocks,
    });
}

/// The reference must name the same hash and state root for block N.
fn check_block(check: *Check) !bool {
    _ = check.scratch.reset(.retain_capacity);
    const arena = check.scratch.allocator();
    const params = try std.fmt.allocPrint(arena, "[\"0x{x}\",false]", .{check.head});
    const block = try check.endpoint.call(arena, "eth_getBlockByNumber", params);
    const head = check.db.head_info;
    assert(head.present and head.number == check.head);
    if (block == .null) {
        std.debug.print("MISMATCH the reference has no block {d}\n", .{check.head});
        return false;
    }
    const number = try compare.parse_u64(try compare.member_string(block, "number"));
    const hash = try compare.parse_fixed(32, try compare.member_string(block, "hash"));
    const root = try compare.parse_fixed(32, try compare.member_string(block, "stateRoot"));
    if (number != check.head) return error.MalformedResponse;
    const same_hash = std.mem.eql(u8, &hash, &head.hash);
    const same_root = std.mem.eql(u8, &root, &head.state_root);
    if (!same_hash or !same_root) {
        std.debug.print("MISMATCH block {d}: the reference is on another block; stopping\n" ++
            "  hash:       reference 0x{x} needlefish 0x{x}\n" ++
            "  state root: reference 0x{x} needlefish 0x{x}\n", .{
            check.head, hash, head.hash, root, head.state_root,
        });
        return false;
    }
    std.debug.print("block {d}: the reference agrees on hash 0x{x} and state root 0x{x}\n", .{
        check.head, hash, root,
    });
    return true;
}

/// Candidate addresses: the system contracts, recent transactions, and recent logs.
fn collect_pool(check: *Check, pool: *sample.Pool, accounts_target: u32) !void {
    assert(accounts_target > 0);
    const arena = check.keep.allocator();
    for (sample.system_contracts) |address| try pool.add(arena, address);
    try collect_transactions(check, pool);
    var scanned: u64 = 0;
    while (scanned < logs_blocks_max and scanned <= check.head) : (scanned += logs_chunk_blocks) {
        if (pool.addresses.count() >= 2 * @as(u64, accounts_target)) break;
        const to = check.head - scanned;
        const from = to -| (logs_chunk_blocks - 1);
        try collect_logs(check, pool, from, to);
    }
    std.debug.print("pool: {d} addresses ({d} log emitters) from the logs of blocks {d}..{d} " ++
        "and the transactions of the last {d} blocks\n", .{
        pool.addresses.count(),
        pool.holders.count(),
        check.head -| (@min(scanned, check.head + 1) -| 1),
        check.head,
        transaction_blocks,
    });
    assert(pool.addresses.count() >= @min(sample.system_contracts.len, sample.addresses_max));
}

fn collect_transactions(check: *Check, pool: *sample.Pool) !void {
    var offset: u64 = 0;
    while (offset < transaction_blocks and offset <= check.head) : (offset += calls_per_request) {
        _ = check.scratch.reset(.retain_capacity);
        const arena = check.scratch.allocator();
        var params: [calls_per_request][]const u8 = undefined;
        var count: usize = 0;
        while (count < calls_per_request and offset + count < transaction_blocks and
            offset + count <= check.head) : (count += 1)
        {
            params[count] = try std.fmt.allocPrint(arena, "[\"0x{x}\",true]", .{
                check.head - offset - count,
            });
        }
        assert(count > 0);
        const method = "eth_getBlockByNumber";
        const blocks = try check.endpoint.batch(arena, method, params[0..count]);
        for (blocks) |block| try add_transactions(check, pool, block);
    }
}

fn add_transactions(check: *Check, pool: *sample.Pool, block: json.Value) !void {
    if (block == .null) return;
    if (block != .object) return error.MalformedResponse;
    const transactions = block.object.get("transactions") orelse return error.MalformedResponse;
    if (transactions != .array) return error.MalformedResponse;
    const arena = check.keep.allocator();
    for (transactions.array.items) |transaction| {
        const from = try compare.member_string(transaction, "from");
        try pool.add(arena, try compare.parse_fixed(20, from));
        const to = transaction.object.get("to") orelse continue;
        if (to == .string) try pool.add(arena, try compare.parse_fixed(20, to.string));
    }
}

fn collect_logs(check: *Check, pool: *sample.Pool, from: u64, to: u64) !void {
    assert(from <= to);
    _ = check.scratch.reset(.retain_capacity);
    const arena = check.scratch.allocator();
    const format = "[{{\"fromBlock\":\"0x{x}\",\"toBlock\":\"0x{x}\"}}]";
    const params = try std.fmt.allocPrint(arena, format, .{ from, to });
    const logs = try check.endpoint.call(arena, "eth_getLogs", params);
    if (logs != .array) return error.MalformedResponse;
    for (logs.array.items) |log| {
        const emitter = try compare.parse_fixed(20, try compare.member_string(log, "address"));
        const topics_value = log.object.get("topics") orelse return error.MalformedResponse;
        if (topics_value != .array or topics_value.array.items.len > 4) {
            return error.MalformedResponse;
        }
        var topics: [4]Hash = undefined;
        const count = topics_value.array.items.len;
        for (topics_value.array.items, topics[0..count]) |topic, *out| {
            if (topic != .string) return error.MalformedResponse;
            out.* = try compare.parse_fixed(32, topic.string);
        }
        try pool.add_log(check.keep.allocator(), emitter, topics[0..count]);
    }
}

fn proof_param(arena: std.mem.Allocator, request: *const sample.Request, block: u64) ![]u8 {
    assert(request.keys.len <= sample.keys_per_call_max);
    var text: Io.Writer.Allocating = .init(arena);
    try text.writer.print("[\"0x{x}\",[", .{request.address});
    for (request.keys, 0..) |*key, index| {
        try text.writer.print("{s}\"0x{x}\"", .{ if (index == 0) "" else ",", key.slot });
    }
    try text.writer.print("],\"0x{x}\"]", .{block});
    assert(text.written().len >= 50);
    return text.written();
}

/// Proves `requests` at N, `calls_per_request` at a time, and checks every account and slot
/// they answer.
fn prove(check: *Check, requests: []const sample.Request, first_phase: bool) !void {
    var start: usize = 0;
    while (start < requests.len) {
        try refresh_window(check);
        _ = check.scratch.reset(.retain_capacity);
        const arena = check.scratch.allocator();
        const end = @min(start + calls_per_request, requests.len);
        const chunk = requests[start..end];
        var params: [calls_per_request][]const u8 = undefined;
        for (chunk, params[0..chunk.len]) |*request, *param| {
            param.* = try proof_param(arena, request, check.head);
        }
        const results = try check.endpoint.batch(arena, "eth_getProof", params[0..chunk.len]);
        assert(results.len == chunk.len);
        for (chunk, results) |*request, result| {
            try absorb(check, arena, request, result, first_phase);
        }
        start = end;
    }
    assert(start == requests.len);
}

/// Checks one `eth_getProof` answer: the account (the first time it is seen) and its slots.
fn absorb(
    check: *Check,
    arena: std.mem.Allocator,
    request: *const sample.Request,
    result: json.Value,
    first_phase: bool,
) !void {
    const keep = check.keep.allocator();
    const keys = try arena.alloc(Hash, request.keys.len);
    for (request.keys, keys) |key, *slot| slot.* = key.slot;
    const address = &request.address;
    const proof = compare.decode_proof(arena, result, address, keys) catch |err| {
        std.debug.print("  eth_getProof 0x{x}: {t}\n", .{ request.address, err });
        return error.MalformedResponse;
    };
    assert(proof.words.len == request.keys.len);
    const address_hash = node.keccak256(address);
    if (!check.accounts.contains(address.*)) {
        try check.accounts.put(keep, address.*, proof.fields);
        try check_account(check, address, &address_hash, &proof.fields);
    }
    if (first_phase and request.keys.len > 0) try check.learned.put(keep, address.*, 0);
    for (request.keys, proof.words) |*key, value| {
        try check_slot(check, address, &address_hash, key, value);
        if (!first_phase) continue;
        if (check.learned.getPtr(address.*)) |mask| sample.learn(mask, key, value);
    }
}

fn check_account(
    check: *Check,
    address: *const Address,
    address_hash: *const Hash,
    fields: *const compare.Fields,
) !void {
    const before = check.report.total;
    const local = compare.read_account(check.disk, address_hash) catch |err| {
        compare.read_failed(check.report, address, null, err);
        if (check.disk.fault) return error.DatabaseFault;
        return;
    };
    _ = compare.compare_account(check.report, address, fields, &local);
    if (fields.has_code()) check.code_accounts += 1;
    assert(check.report.total >= before);
}

fn check_slot(
    check: *Check,
    address: *const Address,
    address_hash: *const Hash,
    key: *const sample.Key,
    value: u256,
) !void {
    const counts = &check.slots[@backingInt(key.kind)];
    if (value == 0) counts.zero += 1 else counts.nonzero += 1;
    const slot_hash = node.keccak256(&key.slot);
    const local = compare.read_slot(check.disk, address_hash, &slot_hash) catch |err| {
        compare.read_failed(check.report, address, &key.slot, err);
        if (check.disk.fault) return error.DatabaseFault;
        return;
    };
    _ = compare.compare_slot(check.report, address, &key.slot, value, local);
    assert(counts.zero + counts.nonzero > 0);
}

/// The sampled accounts with code, with what the first phase learned about them.
fn contracts_of(check: *Check, accounts: []const Address) ![]sample.Contract {
    var list: std.ArrayList(sample.Contract) = .empty;
    for (accounts) |address| {
        const fields = check.accounts.get(address) orelse return error.MissingAccount;
        if (!fields.has_code()) continue;
        try list.append(check.keep.allocator(), .{
            .address = address,
            .probed = check.learned.contains(address),
            .learned = check.learned.get(address) orelse 0,
        });
    }
    assert(list.items.len <= accounts.len);
    return list.items;
}

/// Every distinct code of the sampled accounts is read from needlefish's code tables and must
/// hash to the reference's code hash; the first `reference_codes_max` are also fetched with
/// `eth_getCode` at N and compared byte for byte (through their hashes).
fn check_codes(check: *Check) !void {
    const keep = check.keep.allocator();
    var seen: std.AutoHashMapUnmanaged(Hash, void) = .empty;
    var fetched: std.ArrayList(Address) = .empty;
    for (check.accounts.keys(), check.accounts.values()) |address, fields| {
        if (!fields.has_code()) continue;
        if ((try seen.getOrPut(keep, fields.code_hash)).found_existing) continue;
        const local = check.db.state.code_by_hash(fields.code_hash);
        _ = compare.compare_code(check.report, &address, &fields.code_hash, null, local);
        check.codes += 1;
        if (fetched.items.len < reference_codes_max) try fetched.append(keep, address);
    }
    var start: usize = 0;
    while (start < fetched.items.len) : (start += calls_per_request) {
        try refresh_window(check);
        _ = check.scratch.reset(.retain_capacity);
        const arena = check.scratch.allocator();
        const end = @min(start + calls_per_request, fetched.items.len);
        const chunk = fetched.items[start..end];
        var params: [calls_per_request][]const u8 = undefined;
        for (chunk, params[0..chunk.len]) |address, *param| {
            param.* = try std.fmt.allocPrint(arena, "[\"0x{x}\",\"0x{x}\"]", .{
                address, check.head,
            });
        }
        const results = try check.endpoint.batch(arena, "eth_getCode", params[0..chunk.len]);
        for (chunk, results) |address, result| {
            if (result != .string) return error.MalformedResponse;
            const code = try compare.parse_data(arena, result.string);
            const code_hash = check.accounts.get(address).?.code_hash;
            const local = check.db.state.code_by_hash(code_hash);
            _ = compare.compare_code(check.report, &address, &code_hash, code, local);
            check.codes_fetched += 1;
        }
    }
    assert(check.codes_fetched == fetched.items.len);
    assert(check.codes == seen.count());
}

fn progress(check: *const Check, phase: []const u8) void {
    assert(phase.len > 0);
    const endpoint = check.endpoint;
    std.debug.print("  {s}: {d} accounts, {d} nonzero and {d} zero slots, {d} mismatches, " ++
        "{d} calls in {d} requests ({d} rate-limited), interval {d} ms, {d:.0} s\n", .{
        phase,
        check.accounts.count(),
        check.nonzero(),
        check.zero(),
        check.report.total,
        endpoint.calls,
        endpoint.requests,
        endpoint.limited,
        endpoint.pacer.interval_ms,
        check.elapsed_s(),
    });
}

fn summary(check: *const Check) void {
    var present: u64 = 0;
    for (check.accounts.values()) |*fields| present += @intFromBool(!fields.is_empty());
    const accounts: u64 = check.accounts.count();
    const nonzero = check.nonzero();
    const zero = check.zero();
    const samples = accounts + nonzero + zero;
    const share = if (samples == 0) 0 else nonzero * 100 / samples;
    assert(present <= accounts);
    std.debug.print("summary: block {d}: {d} samples = {d} accounts ({d} present, {d} absent " ++
        "or empty) + {d} slots ({d} nonzero, {d}% of the samples; {d} zero); {d} codes " ++
        "checked ({d} also against eth_getCode; {d} accounts with code); {d} mismatches; " ++
        "{d:.0} s\n", .{
        check.head,         samples,           accounts,            present,
        accounts - present, nonzero + zero,    nonzero,             share,
        zero,               check.codes,       check.codes_fetched, check.code_accounts,
        check.report.total, check.elapsed_s(),
    });
    const endpoint = check.endpoint;
    std.debug.print("summary: {s}: {d} calls in {d} requests, {d} rate-limited, {d} failed, " ++
        "{d} s waiting, final interval {d} ms\n", .{
        endpoint.http.url,
        endpoint.calls,
        endpoint.requests,
        endpoint.limited,
        endpoint.failures,
        endpoint.waited_ms / 1000,
        endpoint.pacer.interval_ms,
    });
    std.debug.print("summary: slots by source:", .{});
    for (sample.kinds, check.slots) |kind, counts| {
        std.debug.print(" {t} {d} nonzero {d} zero;", .{ kind, counts.nonzero, counts.zero });
    }
    std.debug.print("\n", .{});
}

test {
    _ = compare;
    _ = sample;
    _ = rpc;
}

test "state-check: flags" {
    try std.testing.expectError(error.InvalidArguments, parse(&.{}));
    const defaults = try parse(&.{ "--db", "x.nf" });
    try std.testing.expectEqualStrings("x.nf", defaults.db);
    try std.testing.expectEqualStrings("base-sepolia", defaults.chain.name);
    try std.testing.expectEqual(@as(u32, 10_000), defaults.samples);
    try std.testing.expectEqual(@as(u64, 1), defaults.seed);
    try std.testing.expectEqual(@as(u32, 50), defaults.accounts);
    try std.testing.expectEqual(@as(u32, 6_000), defaults.interval_ms);
    try std.testing.expect(defaults.rpc == null);
    const set = try parse(&.{
        "--chain",       "base-mainnet", "--db",   "y",  "--rpc",      "http://127.0.0.1:8545",
        "--samples",     "500",          "--seed", "42", "--accounts", "50",
        "--interval-ms", "800",
    });
    try std.testing.expectEqualStrings("base-mainnet", set.chain.name);
    try std.testing.expectEqual(@as(u32, 500), set.samples);
    try std.testing.expectEqual(@as(u64, 42), set.seed);
    try std.testing.expectEqual(@as(u32, 50), set.accounts);
    try std.testing.expectEqual(@as(u32, 800), set.interval_ms);
    const rejected = [_][]const []const u8{
        &.{"--db"},
        &.{ "--db", "" },
        &.{ "--db", "x", "--chain", "op-mainnet" },
        &.{ "--db", "x", "--rpc", "ws://x" },
        &.{ "--db", "x", "--samples", "9" },
        &.{ "--db", "x", "--samples", "100001" },
        &.{ "--db", "x", "--samples", "many" },
        &.{ "--db", "x", "--seed", "-1" },
        &.{ "--db", "x", "--blocks", "1" },
        &.{ "--db", "x", "--accounts", "0" },
        &.{ "--db", "x", "--samples", "100", "--accounts", "51" },
        &.{ "--db", "x", "--interval-ms", "100" },
        &.{ "--db", "x", "--interval-ms", "60001" },
    };
    for (rejected) |args| try std.testing.expectError(error.InvalidArguments, parse(args));
}

test "state-check: the window guard" {
    // 10,000 samples, 50 accounts: ~85 calls, ~17 minutes at the guard's 12 s a call.
    const calls = calls_estimate(50, 9_950);
    try std.testing.expect(calls > 50 and calls < 100);
    try std.testing.expect(window_holds(649, calls, guard_interval_ms));
    try std.testing.expect(window_holds(4_000, calls, guard_interval_ms));
    try std.testing.expect(!window_holds(6_000, calls, guard_interval_ms));
    try std.testing.expect(!window_holds(proof_window_blocks, 1, 0));
    try std.testing.expect(window_holds(proof_window_blocks - window_margin_blocks - 1, 1, 0));
    try std.testing.expect(!window_holds(0, 2_000, guard_interval_ms));
    // The deadline: the blocks left, at 200 ms a block, before the margin.
    const left_ms = (proof_window_blocks - 649 - window_margin_blocks) * block_time_ms;
    try std.testing.expectEqual(@as(i64, 1_000 + left_ms), deadline_of(1_000, 649));
    try std.testing.expectEqual(@as(i64, 7), deadline_of(7, proof_window_blocks));
}

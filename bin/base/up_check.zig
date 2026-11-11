//! Preflight of `base up`: the chain table and the checks that turn a misconfigured host
//! into one clear message with its fix, before anything is downloaded or started.
//!
//! - Chains: `base-mainnet` (the default) and `base-sepolia`, with aliases (`mainnet`,
//!   `8453`, ...). An unknown name is refused with the nearest valid one.
//! - Disk: free bytes of the datadir's file system (Linux `statfs`), against the peak a
//!   snapshot import needs: the archive and its extraction side by side, then the extraction
//!   and the imported database side by side.
//! - Ports: a loopback bind probe. A port the operator did not name moves to the next free
//!   one; a named port in use is an error naming its flag.
//! - Database lock: the database file's exclusive `flock` (the one every writer takes),
//!   tried without waiting, and its holder from `/proc/locks`.
//! - L1: `eth_chainId` of the L1 RPC and the beacon node's genesis time, both checked against
//!   the chain's L1, so a Sepolia endpoint is never used for mainnet.
//! - Peers: the EIP-2124 fork hash the chain's execution peers advertise now, for
//!   `base el-peers --fork-hash`.

const std = @import("std");
const builtin = @import("builtin");
const base = @import("base");
const import_run_cli = @import("import_run.zig");

const Io = std.Io;
const ChainConfig = base.common.chains.ChainConfig;
const eth_config = base.execution.rpc.eth_config;
const assert = std.debug.assert;

pub const Chain = struct {
    name: []const u8,
    aliases: []const []const u8,
    config: *const ChainConfig,
    /// The `import_run` chain (spec, genesis hash, reference RPC) el-run opens it with.
    run: *const import_run_cli.Chain,
    /// `network` of the chain's entry in the snapshot listing.
    snapshot_network: []const u8,
    /// Keyless public endpoints, tried in order when the operator names none.
    l1_rpcs: []const []const u8,
    l1_beacons: []const []const u8,
    /// The L1 beacon chain's genesis time: tells a mainnet beacon from a Sepolia one.
    l1_beacon_genesis_time: u64,
};

pub const chains = [_]Chain{
    .{
        .name = "base-mainnet",
        .aliases = &.{ "mainnet", "base", "8453" },
        .config = &base.common.chains.mainnet,
        .run = &import_run_cli.chains[1],
        .snapshot_network = "mainnet",
        .l1_rpcs = &.{
            "https://ethereum-rpc.publicnode.com",
            "https://eth.drpc.org",
            "https://1rpc.io/eth",
        },
        .l1_beacons = &.{"https://ethereum-beacon-api.publicnode.com"},
        .l1_beacon_genesis_time = 1_606_824_023,
    },
    .{
        .name = "base-sepolia",
        .aliases = &.{ "sepolia", "84532" },
        .config = &base.common.chains.sepolia,
        .run = &import_run_cli.chains[0],
        .snapshot_network = "sepolia",
        .l1_rpcs = &.{
            "https://ethereum-sepolia-rpc.publicnode.com",
            "https://sepolia.drpc.org",
        },
        .l1_beacons = &.{"https://ethereum-sepolia-beacon-api.publicnode.com"},
        .l1_beacon_genesis_time = 1_655_733_600,
    },
};

comptime {
    for (chains) |chain| {
        assert(chain.config.chain_id == chain.run.spec.chain_id);
        assert(chain.l1_rpcs.len > 0 and chain.l1_beacons.len > 0);
    }
}

pub const default_chain = &chains[0];

pub const ChainChoice = union(enum) {
    chain: *const Chain,
    /// Not a chain; the nearest name, when one is close.
    unknown: ?*const Chain,
};

/// The chain `text` names (its name, an alias, or its chain id), case-insensitive.
pub fn resolve_chain(text: []const u8) ChainChoice {
    assert(chains.len > 0);
    for (&chains) |*chain| {
        if (std.ascii.eqlIgnoreCase(text, chain.name)) return .{ .chain = chain };
        for (chain.aliases) |alias| {
            if (std.ascii.eqlIgnoreCase(text, alias)) return .{ .chain = chain };
        }
    }
    var best: ?*const Chain = null;
    var best_distance: u32 = 4; // Farther than three edits is not a typo.
    for (&chains) |*chain| {
        const distance = @min(edit_distance(text, chain.name), alias_distance(text, chain));
        if (distance < best_distance) {
            best = chain;
            best_distance = distance;
        }
    }
    return .{ .unknown = best };
}

fn alias_distance(text: []const u8, chain: *const Chain) u32 {
    var distance: u32 = std.math.maxInt(u32);
    for (chain.aliases) |alias| distance = @min(distance, edit_distance(text, alias));
    return distance;
}

/// Levenshtein distance, case-insensitive; names longer than 32 bytes are far from all.
fn edit_distance(a: []const u8, b: []const u8) u32 {
    const length_max = 32;
    if (a.len > length_max or b.len > length_max) return std.math.maxInt(u32);
    var row: [length_max + 1]u32 = undefined;
    for (0..b.len + 1) |j| row[j] = @intCast(j);
    for (a, 0..) |a_byte, i| {
        var diagonal = row[0];
        row[0] = @intCast(i + 1);
        for (b, 0..) |b_byte, j| {
            const same = std.ascii.toLower(a_byte) == std.ascii.toLower(b_byte);
            const substitute = diagonal + @intFromBool(!same);
            diagonal = row[j + 1];
            row[j + 1] = @min(substitute, @min(row[j], row[j + 1]) + 1);
        }
    }
    assert(row[b.len] <= @max(a.len, b.len));
    return row[b.len];
}

// ---- Disk ----------------------------------------------------------------------------

/// Free bytes for an unprivileged writer on the file system holding `path`, or null where
/// it cannot be read (not Linux).
pub fn free_bytes(path: [:0]const u8) error{StatFailed}!?u64 {
    if (builtin.os.tag != .linux) return null;
    const linux = std.os.linux;
    var buffer: Statfs = undefined;
    const rc = linux.syscall2(.statfs, @intFromPtr(path.ptr), @intFromPtr(&buffer));
    if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
    assert(buffer.block_size > 0);
    return buffer.blocks_available * @as(u64, @intCast(buffer.block_size));
}

/// Linux `struct statfs` on 64-bit targets (fields up to the ones read).
const Statfs = extern struct {
    kind: i64,
    block_size: i64,
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files: u64,
    files_free: u64,
    fsid: [2]i32,
    name_length: i64,
    fragment_size: i64,
    flags: i64,
    spare: [4]i64,
};

comptime {
    assert(@sizeOf(Statfs) == 120);
}

/// The imported database against its MDBX source: Base mainnet 2.02 TB from 1.14 TB, Base
/// Sepolia 744 GB from 438 GB (both measured). 1.8 covers both.
pub fn database_bytes_estimate(mdbx_bytes: u64) u64 {
    assert(mdbx_bytes > 0);
    const estimate = mdbx_bytes / 5 * 9;
    assert(estimate > mdbx_bytes);
    return estimate;
}

/// Room the database grows into while the node catches up and runs (state growth, the
/// journal): 5% of the database, at least 20 GiB.
pub fn growth_bytes(database_bytes: u64) u64 {
    return @max(database_bytes / 20, 20 << 30);
}

/// The snapshot path's peak footprint: the archive and its extraction side by side, then the
/// extraction and the imported database side by side (the archive is deleted in between).
pub fn snapshot_peak_bytes(archive_bytes: u64, mdbx_bytes: u64) u64 {
    assert(archive_bytes > 0 and mdbx_bytes > 0);
    const database = database_bytes_estimate(mdbx_bytes);
    const peak = @max(archive_bytes + mdbx_bytes, mdbx_bytes + database);
    assert(peak >= database);
    return peak + growth_bytes(database);
}

/// `bytes` in decimal units with two decimals ("761.25 GB").
pub fn format_bytes(buffer: []u8, bytes: u64) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB", "PB" };
    var value: f64 = @floatFromInt(bytes);
    var unit: usize = 0;
    while (value >= 1000 and unit + 1 < units.len) : (unit += 1) value /= 1000;
    if (unit == 0) return std.fmt.bufPrint(buffer, "{d} B", .{bytes}) catch "?";
    return std.fmt.bufPrint(buffer, "{d:.2} {s}", .{ value, units[unit] }) catch "?";
}

// ---- Ports ---------------------------------------------------------------------------

/// Whether a TCP listener can bind 127.0.0.1:`port` now.
pub fn port_free(io: Io, port: u16) bool {
    assert(port != 0);
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var server = address.listen(io, .{}) catch return false;
    server.deinit(io);
    return true;
}

pub const PortError = error{ PortInUse, NoFreePort };

/// `wanted` when free; when not and the operator did not name it, the next free port above
/// it that no other port of this node (`taken`) uses.
pub fn pick_port(io: Io, wanted: u16, named: bool, taken: []const u16) PortError!u16 {
    assert(wanted != 0);
    const tries_max = 100;
    var port = wanted;
    for (0..tries_max) |_| {
        if (std.mem.indexOfScalar(u16, taken, port) == null and port_free(io, port)) {
            return port;
        }
        if (named) return error.PortInUse;
        if (port == std.math.maxInt(u16)) break;
        port += 1;
    }
    return error.NoFreePort;
}

// ---- Database lock -------------------------------------------------------------------

/// Whether another process holds the database file's writer lock (`utilities.io` takes an
/// exclusive `flock` on every writable open). Missing file: false.
pub fn database_locked(io: Io, path: []const u8) !bool {
    if (builtin.os.tag != .linux) return false;
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);
    const linux = std.os.linux;
    const rc = linux.flock(file.handle, std.posix.LOCK.EX | std.posix.LOCK.NB);
    return switch (linux.errno(rc)) {
        .SUCCESS => locked: {
            _ = linux.flock(file.handle, std.posix.LOCK.UN);
            break :locked false;
        },
        .AGAIN => true,
        else => error.LockCheckFailed,
    };
}

/// The pid holding a `flock` on the file with inode `inode`, from `/proc/locks` lines such as
/// `1: FLOCK  ADVISORY  WRITE 4242 00:2a:1234 0 EOF`.
pub fn lock_holder(text: []const u8, inode: u64) ?u32 {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        var values: [8][]const u8 = undefined;
        var count: usize = 0;
        while (fields.next()) |field| {
            if (count == values.len) break;
            values[count] = field;
            count += 1;
        }
        // An entry blocked on a lock reads `1: -> FLOCK ...`: one more field.
        if (count < 6 or !std.mem.eql(u8, values[1], "FLOCK")) continue;
        const device_inode = values[5];
        const colon = std.mem.lastIndexOfScalar(u8, device_inode, ':') orelse continue;
        const line_inode = std.fmt.parseInt(u64, device_inode[colon + 1 ..], 10) catch continue;
        if (line_inode != inode) continue;
        return std.fmt.parseInt(u32, values[4], 10) catch null;
    }
    return null;
}

// ---- Peers ---------------------------------------------------------------------------

/// The fork hash a synced execution peer of `chain` advertises at `timestamp_s`. Execution
/// clients fold only execution forks: Delta and the Pectra blob schedule change derivation
/// alone, so they are left out (Base mainnet's peers advertise 169d85a3 on 2026-11-08,
/// which only that set reproduces).
pub fn fork_hash(chain: *const Chain, timestamp_s: u64) [4]u8 {
    const Upgrade = base.execution.chainspec.Upgrade;
    var times: [32]u64 = undefined;
    var count: usize = 0;
    for (chain.run.spec.upgrades, 0..) |entry, index| {
        const upgrade: Upgrade = @fromBackingInt(@intCast(index));
        if (upgrade == .delta or upgrade == .pectra_blob_schedule) continue;
        const time = entry orelse continue;
        if (std.mem.indexOfScalar(u64, times[0..count], time) != null) continue;
        times[count] = time;
        count += 1;
    }
    std.sort.pdq(u64, times[0..count], {}, std.sort.asc(u64));
    const genesis_time = chain.config.genesis_l2_time;
    assert(genesis_time > 0);
    const hash = eth_config.fork_hash(
        chain.run.genesis_hash,
        genesis_time,
        times[0..count],
        timestamp_s,
    );
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, hash, .big);
    return bytes;
}

// ---- HTTP ----------------------------------------------------------------------------

pub const Answer = struct { status: std.http.Status, body: []const u8 };

pub const Request = struct {
    url: []const u8,
    /// A JSON body (POST); null: GET.
    payload: ?[]const u8 = null,
    /// `Authorization: Bearer <token>` (the Engine API's JWT).
    bearer: ?[]const u8 = null,
};

/// One request with a deadline (a fresh client each time: probes are rare). `response` holds
/// the body; a longer one fails with `ResponseTooLarge`.
pub fn fetch(
    gpa: std.mem.Allocator,
    io: Io,
    request: Request,
    response: []u8,
    timeout_ms: u32,
) !Answer {
    assert(timeout_ms > 0);
    assert(response.len > 0);
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const Outcome = union(enum) {
        fetched: anyerror!Answer,
        timed_out: Io.Cancelable!void,
    };
    var buffer: [2]Outcome = undefined;
    var select = Io.Select(Outcome).init(io, &buffer);
    // On every path, cancellation included: the tasks use this frame.
    defer select.cancelDiscard();
    try select.concurrent(.fetched, fetch_once, .{ &client, &request, response });
    const duration: Io.Clock.Duration = .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake };
    try select.concurrent(.timed_out, sleep, .{ io, duration });
    const first = try select.await();
    return switch (first) {
        .fetched => |result| result,
        .timed_out => error.Timeout,
    };
}

fn sleep(io: Io, duration: Io.Clock.Duration) Io.Cancelable!void {
    return duration.sleep(io);
}

fn fetch_once(client: *std.http.Client, request: *const Request, response: []u8) anyerror!Answer {
    var writer: Io.Writer = .fixed(response);
    var authorization_buffer: [512]u8 = undefined;
    const authorization: std.http.Client.Request.Headers.Value = if (request.bearer) |token|
        .{ .override = try std.fmt.bufPrint(&authorization_buffer, "Bearer {s}", .{token}) }
    else
        .default;
    const result = client.fetch(.{
        .location = .{ .url = request.url },
        .method = if (request.payload == null) .GET else .POST,
        .payload = request.payload,
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .authorization = authorization,
        },
        .response_writer = &writer,
    }) catch |err| switch (err) {
        error.WriteFailed => return error.ResponseTooLarge,
        else => return err,
    };
    return .{ .status = result.status, .body = writer.buffered() };
}

// ---- L1 ------------------------------------------------------------------------------

pub const Probe = union(enum) {
    ok,
    /// Answers, but for another chain (its chain id, or its beacon genesis time).
    wrong_chain: u64,
    failed: anyerror,
};

const probe_timeout_ms = 15_000;

/// `eth_chainId` of an L1 JSON-RPC endpoint against `l1_chain_id`.
pub fn probe_l1(gpa: std.mem.Allocator, io: Io, url: []const u8, l1_chain_id: u64) Probe {
    assert(l1_chain_id != 0);
    const request = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]}";
    var response: [4096]u8 = undefined;
    const answer = fetch(
        gpa,
        io,
        .{ .url = url, .payload = request },
        &response,
        probe_timeout_ms,
    ) catch |err| {
        return .{ .failed = err };
    };
    if (answer.status != .ok) return .{ .failed = error.HttpStatus };
    const id = json_quantity(answer.body, "\"result\"") orelse {
        return .{ .failed = error.NoChainId };
    };
    return if (id == l1_chain_id) .ok else .{ .wrong_chain = id };
}

/// The beacon API's `/eth/v1/beacon/genesis` against the L1's genesis time.
pub fn probe_beacon(gpa: std.mem.Allocator, io: Io, url: []const u8, genesis_time: u64) Probe {
    assert(genesis_time != 0);
    var url_buffer: [512]u8 = undefined;
    const genesis_url = std.fmt.bufPrint(&url_buffer, "{s}/eth/v1/beacon/genesis", .{
        std.mem.trimEnd(u8, url, "/"),
    }) catch return .{ .failed = error.UrlTooLong };
    var response: [4096]u8 = undefined;
    const answer = fetch(
        gpa,
        io,
        .{ .url = genesis_url },
        &response,
        probe_timeout_ms,
    ) catch |err| {
        return .{ .failed = err };
    };
    if (answer.status != .ok) return .{ .failed = error.HttpStatus };
    const time = json_quantity(answer.body, "\"genesis_time\"") orelse {
        return .{ .failed = error.NoGenesisTime };
    };
    return if (time == genesis_time) .ok else .{ .wrong_chain = time };
}

pub const L1 = struct { rpc: []const u8, beacon: []const u8 };

pub const L1Choice = union(enum) {
    ok: L1,
    /// A named endpoint serves another chain: a configuration error, never retried.
    wrong_chain,
    /// No candidate answered; consensus waits and the choice is retried.
    unreachable_endpoints,
};

/// What `choose_l1` found wrong with the candidates, as one line.
pub const L1Report = struct {
    buffer: [768]u8 = undefined,
    len: usize = 0,

    fn add(report: *L1Report, comptime format: []const u8, args: anytype) void {
        const separator = if (report.len == 0) "" else "; ";
        const room = report.buffer[report.len..];
        const added = std.fmt.bufPrint(room, "{s}" ++ format, .{separator} ++ args) catch return;
        report.len += added.len;
    }

    pub fn text(report: *const L1Report) []const u8 {
        return report.buffer[0..report.len];
    }
};

/// The first L1 RPC and beacon among the candidates that answer for the chain's L1.
/// `named`: the operator named them (a wrong chain is then fatal, not skipped).
pub fn choose_l1(
    gpa: std.mem.Allocator,
    io: Io,
    chain: *const Chain,
    rpcs: []const []const u8,
    beacons: []const []const u8,
    named: bool,
    report: *L1Report,
) L1Choice {
    assert(rpcs.len > 0 and beacons.len > 0);
    const l1_id = chain.config.l1_chain_id;
    const rpc = for (rpcs) |url| {
        switch (probe_l1(gpa, io, url, l1_id)) {
            .ok => break url,
            .wrong_chain => |id| {
                report.add("L1 RPC {s} serves chain id {d}, not {d}", .{ url, id, l1_id });
                if (named) return .wrong_chain;
            },
            .failed => |err| report.add("L1 RPC {s} does not answer ({t})", .{ url, err }),
        }
    } else return .unreachable_endpoints;
    const genesis = chain.l1_beacon_genesis_time;
    const beacon = for (beacons) |url| {
        switch (probe_beacon(gpa, io, url, genesis)) {
            .ok => break url,
            .wrong_chain => |time| {
                report.add("L1 beacon {s} has genesis time {d}, not {d}", .{ url, time, genesis });
                if (named) return .wrong_chain;
            },
            .failed => |err| report.add("L1 beacon {s} does not answer ({t})", .{ url, err }),
        }
    } else return .unreachable_endpoints;
    return .{ .ok = .{ .rpc = rpc, .beacon = beacon } };
}

// ---- Processes -----------------------------------------------------------------------

/// `/proc/<pid>/cmdline` (NUL-separated arguments), or null (gone, or not Linux).
pub fn process_cmdline(io: Io, pid: std.posix.pid_t, buffer: []u8) ?[]const u8 {
    if (builtin.os.tag != .linux) return null;
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "/proc/{d}/cmdline", .{pid}) catch return null;
    return Io.Dir.cwd().readFile(io, path, buffer) catch null;
}

/// Whether `pid` exists (read from `/proc`: no signal is sent).
pub fn process_running(io: Io, pid: u32) bool {
    if (builtin.os.tag != .linux) return false;
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buffer, "/proc/{d}", .{pid}) catch return false;
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// The number in the string value after `key` (`"0x1"` hex or `"1606824023"` decimal).
pub fn json_quantity(body: []const u8, key: []const u8) ?u64 {
    const at = std.mem.indexOf(u8, body, key) orelse return null;
    const rest = body[at + key.len ..];
    const open = std.mem.indexOfScalar(u8, rest, '"') orelse return null;
    const value_start = rest[open + 1 ..];
    const close = std.mem.indexOfScalar(u8, value_start, '"') orelse return null;
    const value = value_start[0..close];
    if (std.mem.startsWith(u8, value, "0x")) {
        return std.fmt.parseInt(u64, value[2..], 16) catch null;
    }
    return std.fmt.parseInt(u64, value, 10) catch null;
}

// ---- Tests ---------------------------------------------------------------------------

const testing = std.testing;

test "up check: chain names, aliases, ids, and typos" {
    try testing.expectEqual(&chains[0], resolve_chain("base-mainnet").chain);
    try testing.expectEqual(&chains[0], resolve_chain("Mainnet").chain);
    try testing.expectEqual(&chains[0], resolve_chain("8453").chain);
    try testing.expectEqual(&chains[1], resolve_chain("base-sepolia").chain);
    try testing.expectEqual(&chains[1], resolve_chain("84532").chain);
    // Typos name the nearest chain; far-off names name none.
    try testing.expectEqual(&chains[0], resolve_chain("base-mainet").unknown.?);
    try testing.expectEqual(&chains[1], resolve_chain("sepola").unknown.?);
    try testing.expectEqual(&chains[0], resolve_chain("op-mainnet").unknown.?);
    try testing.expectEqual(@as(?*const Chain, null), resolve_chain("arbitrum").unknown);
    try testing.expectEqual(@as(?*const Chain, null), resolve_chain("").unknown);
    try testing.expectEqual(@as(u32, 3), edit_distance("kitten", "sitting"));
    try testing.expectEqual(@as(u32, 0), edit_distance("ABC", "abc"));
}

test "up check: the snapshot peak covers each stage's footprint" {
    // Base mainnet's manifest of 2026-11-11: 761.25 GB archive, 1138.17 GB mdbx.dat.
    const archive: u64 = 761_254_291_350;
    const mdbx: u64 = 1_138_166_333_440;
    const peak = snapshot_peak_bytes(archive, mdbx);
    const database = database_bytes_estimate(mdbx);
    // The import stage (extraction + database) dominates: 1.14 + 2.05 TB plus growth.
    try testing.expect(peak >= mdbx + database);
    try testing.expect(peak >= archive + mdbx);
    try testing.expect(database >= 2_020_000_000_000); // The measured mainnet import.
    try testing.expect(peak < 3_400_000_000_000);
    // A small chain: the 20 GiB growth floor applies.
    try testing.expectEqual(@as(u64, 20 << 30), growth_bytes(1 << 30));
    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("761.25 GB", format_bytes(&buffer, archive));
    try testing.expectEqualStrings("12 B", format_bytes(&buffer, 12));
}

test "up check: a busy port moves unless named" {
    const io = testing.io;
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    const busy = server.socket.address.getPort();
    try testing.expect(!port_free(io, busy));
    try testing.expectError(error.PortInUse, pick_port(io, busy, true, &.{}));
    const moved = try pick_port(io, busy, false, &.{});
    try testing.expect(moved > busy);
    // A port another of this node's servers took is skipped too.
    const skipped = try pick_port(io, moved, false, &.{moved});
    try testing.expect(skipped > moved);
}

test "up check: lock holders from /proc/locks" {
    const text =
        \\1: POSIX  ADVISORY  WRITE 900 00:2a:77 0 EOF
        \\2: FLOCK  ADVISORY  WRITE 4242 103:02:1234567 0 EOF
        \\2: -> FLOCK  ADVISORY  WRITE 4243 103:02:1234567 0 EOF
        \\3: FLOCK  ADVISORY  READ 17 00:2a:99 0 EOF
    ;
    try testing.expectEqual(@as(?u32, 4242), lock_holder(text, 1234567));
    try testing.expectEqual(@as(?u32, 17), lock_holder(text, 99));
    try testing.expectEqual(@as(?u32, null), lock_holder(text, 77)); // POSIX, not FLOCK.
    try testing.expectEqual(@as(?u32, null), lock_holder("", 1));
}

test "up check: a database file held by a writer is locked" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir_length = try tmp.dir.realPath(io, &path_buffer);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/db.nf", .{
        path_buffer[0..dir_length],
    });
    defer testing.allocator.free(path);
    try testing.expect(!try database_locked(io, path)); // Missing.
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    try testing.expect(!try database_locked(io, path));
    const linux = std.os.linux;
    try testing.expectEqual(@as(usize, 0), linux.flock(file.handle, std.posix.LOCK.EX));
    try testing.expect(try database_locked(io, path));
    file.close(io);
    try testing.expect(!try database_locked(io, path));
}

test "up check: fork hashes of Base mainnet" {
    // Confirmed on Base mainnet execution peers on 2026-11-08 (network 8453, mainnet genesis).
    const nov_8_2026: u64 = 1_794_096_040;
    try testing.expectEqualSlices(
        u8,
        &.{ 0x16, 0x9d, 0x85, 0xa3 },
        &fork_hash(&chains[0], nov_8_2026),
    );
    // Before every timestamp fork: the genesis hash alone.
    const at_genesis = fork_hash(&chains[0], chains[0].config.genesis_l2_time);
    const expected = std.hash.Crc32.hash(&chains[0].run.genesis_hash);
    try testing.expectEqual(expected, std.mem.readInt(u32, &at_genesis, .big));
}

test "up check: JSON quantities" {
    try testing.expectEqual(@as(?u64, 1), json_quantity("{\"result\":\"0x1\"}", "\"result\""));
    const genesis = "{\"data\":{\"genesis_time\":\"1606824023\",\"x\":\"0x00\"}}";
    try testing.expectEqual(@as(?u64, 1_606_824_023), json_quantity(genesis, "\"genesis_time\""));
    try testing.expectEqual(@as(?u64, null), json_quantity("{\"error\":{}}", "\"result\""));
    try testing.expectEqual(@as(?u64, null), json_quantity("{\"result\":\"0xzz\"}", "\"result\""));
}

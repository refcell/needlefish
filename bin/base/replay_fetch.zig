//! `base replay fetch`: downloads recent Base mainnet blocks and a stateless witness of the
//! state they touch from public keyless JSON-RPC endpoints, then builds a replay archive.
//!
//! Raw results are cached under `--cache` in the layout `base replay import` reads
//! (docs/REPLAY.md), so a rerun skips every finished file. After the main download the
//! archive is replayed in-process: every key the replay lacks (pre-block system call
//! contracts, precompiles, the message passer, ...) is fetched at the block's parent into
//! `proofs_extra.json` and `codes_extra.json`, and the archive is rebuilt, until the replay
//! has no gaps (bounded rounds).

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const replay_cli = @import("replay.zig");
const HttpTransport = @import("http_transport.zig").HttpTransport;
const replay = base.infra.replay;
const Archive = replay.Archive;
const json = std.json;
const assert = std.debug.assert;

/// Traces and blocks (no batching).
pub const trace_url = "https://base.drpc.org";
/// Archive proofs and headers (batched).
pub const proof_url = "https://base-mainnet.public.blastapi.io";
pub const default_count = 10;
/// Stay this far behind the head so the window is final enough to fetch consistently.
const head_margin = 32;
const batch_max = 16;
const retries_max = 8;
const gap_rounds_max = 64;
const response_bytes_max = 96 << 20;
const ancestors = replay.archive.ancestors_max;

/// EIP-4788 beacon roots and EIP-2935 history contracts (pre-block system calls) and the
/// L2ToL1MessagePasser (Isthmus withdrawals root): read by every block, never traced.
const beacon_roots = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02";
const history = "0x0000f90827f1c53a10cb7a02335b175320002935";
const message_passer = "0x4200000000000000000000000000000000000016";
/// The system caller of the pre-block calls.
const system_address = "0xfffffffffffffffffffffffffffffffffffffffe";
const history_buffer_length = 8191;

const Flags = struct {
    count: u32 = default_count,
    from: ?u64 = null,
    cache: []const u8 = ".cache/replay",
    out: []const u8 = replay_cli.default_archive,
};

fn parse(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index + 1 < args.len) : (index += 2) {
        const value = args[index + 1];
        if (std.mem.eql(u8, args[index], "--count")) {
            flags.count = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, args[index], "--from")) {
            flags.from = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, args[index], "--cache")) {
            flags.cache = value;
        } else if (std.mem.eql(u8, args[index], "--out")) {
            flags.out = value;
        } else return error.InvalidArguments;
    }
    if (index != args.len) return error.InvalidArguments;
    if (flags.count == 0 or flags.count > replay.archive.blocks_max) {
        return error.InvalidArguments;
    }
    return flags;
}

/// One endpoint, with a reusable response buffer and retries with backoff.
const Endpoint = struct {
    http: HttpTransport,
    response: []u8,
    calls: u64 = 0,

    fn post(endpoint: *Endpoint, io: Io, body: []const u8) ![]const u8 {
        var attempt: u32 = 0;
        while (attempt < retries_max) : (attempt += 1) {
            endpoint.calls += 1;
            const text = endpoint.http.transport().send(body, endpoint.response) catch |err| {
                const wait_s: i64 = @min(@as(i64, 1) << @intCast(attempt), 30);
                if (attempt > 0) std.debug.print("  {s}: {t}, retrying in {d}s\n", .{
                    endpoint.http.url,
                    err,
                    wait_s,
                });
                try io.sleep(.fromSeconds(wait_s), .awake);
                continue;
            };
            if (std.mem.indexOf(u8, text, "\"error\"") != null and
                std.mem.indexOf(u8, text, "\"result\"") == null)
            {
                const wait_s: i64 = @min(@as(i64, 1) << @intCast(attempt), 30);
                if (attempt > 0) {
                    std.debug.print("  {s}: rate limited, retrying\n", .{endpoint.http.url});
                }
                try io.sleep(.fromSeconds(wait_s), .awake);
                continue;
            }
            return text;
        }
        return error.EndpointFailed;
    }
};

const Fetcher = struct {
    init: std.process.Init,
    arena: std.heap.ArenaAllocator,
    trace: Endpoint,
    proof: Endpoint,
    dir: Io.Dir,
    flags: Flags,

    fn alloc(f: *Fetcher) std.mem.Allocator {
        return f.arena.allocator();
    }

    /// One call; returns the JSON text of its `result`.
    fn call(f: *Fetcher, endpoint: *Endpoint, method: []const u8, params: []const u8) ![]u8 {
        const body = try std.fmt.allocPrint(f.alloc(), "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
            "\"method\":\"{s}\",\"params\":{s}}}", .{ method, params });
        const text = try endpoint.post(f.init.io, body);
        const value = try json.parseFromSliceLeaky(json.Value, f.alloc(), text, .{});
        if (value != .object) return error.MalformedResponse;
        const result = value.object.get("result") orelse return error.MalformedResponse;
        return json.Stringify.valueAlloc(f.alloc(), result, .{});
    }

    /// A batch of calls with one method; returns each `result`, in request order. A batch
    /// with any failed item is retried whole.
    fn batch(
        f: *Fetcher,
        endpoint: *Endpoint,
        method: []const u8,
        params: []const []const u8,
    ) ![]json.Value {
        assert(params.len > 0 and params.len <= batch_max);
        var body: Io.Writer.Allocating = .init(f.alloc());
        try body.writer.writeAll("[");
        for (params, 0..) |param, id| {
            try body.writer.print("{s}{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\"," ++
                "\"params\":{s}}}", .{ if (id == 0) "" else ",", id, method, param });
        }
        try body.writer.writeAll("]");
        const results = try f.alloc().alloc(json.Value, params.len);
        var attempt: u32 = 0;
        while (attempt < retries_max) : (attempt += 1) {
            const text = try endpoint.post(f.init.io, body.written());
            if (try batch_results(f.alloc(), text, results)) return results;
            if (attempt > 0) {
                std.debug.print("  {s}: rate limited, retrying\n", .{endpoint.http.url});
            }
            try f.init.io.sleep(.fromSeconds(@min(@as(i64, 1) << @intCast(attempt), 30)), .awake);
        }
        return error.EndpointFailed;
    }

    fn exists(f: *Fetcher, path: []const u8) bool {
        f.dir.access(f.init.io, path, .{}) catch return false;
        return true;
    }

    fn save(f: *Fetcher, path: []const u8, data: []const u8) !void {
        const temporary = try std.fmt.allocPrint(f.alloc(), "{s}.tmp", .{path});
        try f.dir.writeFile(f.init.io, .{ .sub_path = temporary, .data = data });
        try f.dir.rename(temporary, f.dir, path, f.init.io);
    }

    fn read(f: *Fetcher, path: []const u8) ![]u8 {
        return f.dir.readFileAlloc(f.init.io, path, f.alloc(), .limited(1 << 30));
    }
};

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse(args) catch {
        std.debug.print("usage: base replay fetch [--count <n>] [--from <block>] " ++
            "[--cache <dir>] [--out <archive>]\n", .{});
        return 2;
    };
    const gpa = init.gpa;
    const response = try gpa.alloc(u8, response_bytes_max);
    defer gpa.free(response);
    const proof_response = try gpa.alloc(u8, response_bytes_max);
    defer gpa.free(proof_response);
    var f: Fetcher = .{
        .init = init,
        .arena = .init(gpa),
        .trace = .{ .http = .init(gpa, init.io, trace_url), .response = response },
        .proof = .{ .http = .init(gpa, init.io, proof_url), .response = proof_response },
        .dir = undefined,
        .flags = flags,
    };
    defer f.arena.deinit();
    defer f.trace.http.deinit();
    defer f.proof.http.deinit();
    f.trace.http.timeout_ms = 120_000;
    f.proof.http.timeout_ms = 120_000;
    const window = try choose_window(&f);
    const sub = try std.fmt.allocPrint(gpa, "{s}/{d}-{d}", .{
        flags.cache,
        window.first,
        window.count,
    });
    defer gpa.free(sub);
    try Io.Dir.cwd().createDirPath(init.io, sub);
    f.dir = try Io.Dir.cwd().openDir(init.io, sub, .{});
    defer f.dir.close(init.io);
    std.debug.print("fetching Base mainnet blocks {d}..{d} into {s}\n", .{
        window.first,
        window.first + window.count - 1,
        sub,
    });
    try fetch_window(&f, window);
    try fill_gaps(&f, window, sub);
    return 0;
}

/// Fills `results` from a batch response; false when any item failed.
fn batch_results(arena: std.mem.Allocator, text: []const u8, results: []json.Value) !bool {
    const value = json.parseFromSliceLeaky(json.Value, arena, text, .{}) catch return false;
    if (value != .array or value.array.items.len != results.len) return false;
    for (value.array.items) |item| {
        if (item != .object) return false;
        const id = item.object.get("id") orelse return false;
        if (id != .integer or id.integer < 0 or id.integer >= results.len) return false;
        const result = item.object.get("result") orelse return false;
        if (result == .null) return false;
        results[@intCast(id.integer)] = result;
    }
    return true;
}

fn choose_window(f: *Fetcher) !replay_cli.Window {
    if (f.flags.from) |first| return .{ .first = first, .count = f.flags.count };
    const head_text = try f.call(&f.trace, "eth_blockNumber", "[]");
    const head = try std.fmt.parseInt(u64, std.mem.trim(u8, head_text, "\"")[2..], 16);
    if (head < head_margin + f.flags.count + ancestors) return error.ChainTooShort;
    return .{ .first = head - head_margin - f.flags.count + 1, .count = f.flags.count };
}

fn fetch_window(f: *Fetcher, window: replay_cli.Window) !void {
    const window_json = try std.fmt.allocPrint(f.alloc(), "{{\"first\":{d},\"count\":{d}}}", .{
        window.first,
        window.count,
    });
    try f.save("window.json", window_json);
    try fetch_headers(f, window);
    for (0..window.count) |offset| {
        _ = f.arena.reset(.retain_capacity);
        try fetch_block(f, window.first + offset);
    }
}

/// `headers.json`: number, hash, parent hash and state root of the 256 ancestors and the
/// window, fetched in batches.
fn fetch_headers(f: *Fetcher, window: replay_cli.Window) !void {
    if (f.exists("headers.json")) return;
    const low = window.first - ancestors;
    const high = window.first + window.count; // Exclusive.
    var out: Io.Writer.Allocating = .init(f.alloc());
    try out.writer.writeAll("[");
    var number = low;
    while (number < high) {
        const count: usize = @intCast(@min(batch_max, high - number));
        const params = try f.alloc().alloc([]const u8, count);
        for (params, 0..) |*param, index| {
            param.* = try std.fmt.allocPrint(f.alloc(), "[\"0x{x}\",false]", .{number + index});
        }
        const results = try f.batch(&f.proof, "eth_getBlockByNumber", params);
        for (results, 0..) |header, index| {
            if (header != .object) return error.MalformedResponse;
            const fields = [_][]const u8{ "number", "hash", "parentHash", "stateRoot" };
            try out.writer.writeAll(if (number == low and index == 0) "{" else ",{");
            inline for (fields, 0..) |name, field_index| {
                const value = header.object.get(name) orelse return error.MalformedResponse;
                if (value != .string) return error.MalformedResponse;
                try out.writer.print("{s}\"{s}\":\"{s}\"", .{
                    if (field_index == 0) "" else ",",
                    name,
                    value.string,
                });
            }
            try out.writer.writeAll("}");
        }
        number += count;
    }
    try out.writer.writeAll("]");
    try f.save("headers.json", out.written());
    std.debug.print("  headers {d}..{d}\n", .{ low, high - 1 });
}

fn fetch_block(f: *Fetcher, number: u64) !void {
    const name = try std.fmt.allocPrint(f.alloc(), "{d}", .{number});
    try f.dir.createDirPath(f.init.io, name);
    const tag = try std.fmt.allocPrint(f.alloc(), "\"0x{x}\"", .{number});
    const steps = [_]struct { file: []const u8, method: []const u8, params: []const u8 }{
        .{ .file = "block.json", .method = "eth_getBlockByNumber", .params = "[{s},true]" },
        .{ .file = "receipts.json", .method = "eth_getBlockReceipts", .params = "[{s}]" },
        .{
            .file = "prestate.json",
            .method = "debug_traceBlockByNumber",
            .params = "[{s},{{\"tracer\":\"prestateTracer\"}}]",
        },
        .{
            .file = "prestate_diff.json",
            .method = "debug_traceBlockByNumber",
            .params = "[{s},{{\"tracer\":\"prestateTracer\"," ++
                "\"tracerConfig\":{{\"diffMode\":true}}}}]",
        },
    };
    inline for (steps) |step| {
        const path = try std.fmt.allocPrint(f.alloc(), "{s}/{s}", .{ name, step.file });
        if (!f.exists(path)) {
            const params = try std.fmt.allocPrint(f.alloc(), step.params, .{tag});
            try f.save(path, try f.call(&f.trace, step.method, params));
        }
    }
    var keys: Keys = .{};
    try touched_keys(f, name, &keys);
    try fetch_proofs(f, name, "proofs_pre.json", &keys, number - 1);
    try fetch_proofs(f, name, "proofs_post.json", &keys, number);
    std.debug.print("  block {d}: {d} accounts touched\n", .{ number, keys.map.count() });
}

/// Accounts (lowercase hex) to the slots (hex) to prove, sorted on use.
const Keys = struct {
    map: std.StringArrayHashMapUnmanaged(std.StringArrayHashMapUnmanaged(void)) = .empty,

    fn add_account(keys: *Keys, arena: std.mem.Allocator, address: []const u8) !void {
        const lower = try std.ascii.allocLowerString(arena, address);
        const entry = try keys.map.getOrPut(arena, lower);
        if (!entry.found_existing) entry.value_ptr.* = .empty;
    }

    fn add_slot(
        keys: *Keys,
        arena: std.mem.Allocator,
        address: []const u8,
        slot: []const u8,
    ) !void {
        try keys.add_account(arena, address);
        const lower = try std.ascii.allocLowerString(arena, address);
        try keys.map.getPtr(lower).?.put(arena, try std.ascii.allocLowerString(arena, slot), {});
    }
};

/// Every account and slot the block's traces show (pre-state and changes).
fn touched_keys(f: *Fetcher, name: []const u8, keys: *Keys) !void {
    const arena = f.alloc();
    const files = [_][]const u8{ "prestate.json", "prestate_diff.json" };
    for (files) |file| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}", .{ name, file });
        const traces = try json.parseFromSliceLeaky(json.Value, arena, try f.read(path), .{});
        if (traces != .array) return error.MalformedResponse;
        for (traces.array.items) |trace| {
            const result = trace.object.get("result") orelse return error.MalformedResponse;
            if (result != .object) return error.MalformedResponse;
            if (result.object.get("pre") != null or result.object.get("post") != null) {
                for ([_][]const u8{ "pre", "post" }) |side| {
                    const accounts = result.object.get(side) orelse continue;
                    try add_accounts(arena, keys, accounts);
                }
            } else try add_accounts(arena, keys, result);
        }
    }
}

fn add_accounts(arena: std.mem.Allocator, keys: *Keys, accounts: json.Value) !void {
    if (accounts != .object) return error.MalformedResponse;
    for (accounts.object.keys(), accounts.object.values()) |address, account| {
        try keys.add_account(arena, address);
        if (account != .object) continue;
        const storage = account.object.get("storage") orelse continue;
        if (storage != .object) return error.MalformedResponse;
        for (storage.object.keys()) |slot| try keys.add_slot(arena, address, slot);
    }
}

/// `eth_getProof` for every key at `at`, batched, sorted by address.
fn fetch_proofs(f: *Fetcher, name: []const u8, file: []const u8, keys: *Keys, at: u64) !void {
    const path = try std.fmt.allocPrint(f.alloc(), "{s}/{s}", .{ name, file });
    if (f.exists(path)) return;
    try f.save(path, try prove(f, keys, at));
}

fn prove(f: *Fetcher, keys: *Keys, at: u64) ![]u8 {
    const arena = f.alloc();
    const Sort = struct {
        keys: []const []const u8,
        pub fn lessThan(context: @This(), a: usize, b: usize) bool {
            return std.mem.order(u8, context.keys[a], context.keys[b]) == .lt;
        }
    };
    keys.map.sort(Sort{ .keys = keys.map.keys() });
    const params = try arena.alloc([]const u8, keys.map.count());
    for (keys.map.keys(), keys.map.values(), params) |address, *slots, *param| {
        slots.sort(Sort{ .keys = slots.keys() });
        var text: Io.Writer.Allocating = .init(arena);
        try text.writer.print("[\"{s}\",[", .{address});
        for (slots.keys(), 0..) |slot, index| {
            try text.writer.print("{s}\"{s}\"", .{ if (index == 0) "" else ",", slot });
        }
        try text.writer.print("],\"0x{x}\"]", .{at});
        param.* = text.written();
    }
    var out: Io.Writer.Allocating = .init(arena);
    try out.writer.writeAll("[");
    var start: usize = 0;
    while (start < params.len) : (start += batch_max) {
        const chunk = params[start..@min(start + batch_max, params.len)];
        const results = try f.batch(&f.proof, "eth_getProof", chunk);
        // Public endpoints meter compute units per second: pace the batches.
        try f.init.io.sleep(.fromMilliseconds(250), .awake);
        for (results, 0..) |result, index| {
            if (start + index > 0) try out.writer.writeAll(",");
            try json.Stringify.value(result, .{}, &out.writer);
        }
    }
    try out.writer.writeAll("]");
    return out.written();
}

/// Replays the archive and fetches what it lacks until it passes. The first round seeds
/// each block with the keys every block reads but no trace shows.
fn fill_gaps(f: *Fetcher, window: replay_cli.Window, sub: []const u8) !void {
    const gpa = f.init.gpa;
    try seed_extra(f, window);
    var round: u32 = 0;
    while (round < gap_rounds_max) : (round += 1) {
        _ = f.arena.reset(.retain_capacity);
        var archive = try Archive.init(gpa, replay_cli.archive_config);
        defer archive.deinit(gpa);
        try replay_cli.import_blocks(f.init, f.dir, &archive, window);
        const report = try replay_cli.check_archive(gpa, f.alloc(), &archive) orelse {
            const out = f.flags.out;
            try replay_cli.write_archive(f.init, &archive, window, out);
            std.debug.print("witness complete after {d} gap rounds ({s})\n", .{ round, sub });
            return;
        };
        std.debug.print("  gap round {d}: block {d} lacks {d} accounts, {d} slots\n", .{
            round + 1,
            report.block,
            report.accounts.len,
            report.slots.len,
        });
        try add_extra(f, report);
    }
    return error.WitnessIncomplete;
}

fn extra_keys_path(f: *Fetcher, number: u64) ![]u8 {
    return std.fmt.allocPrint(f.alloc(), "{d}/extra_keys.json", .{number});
}

/// Loads a block's extra keys (`{address: [slot, ...]}`), or none.
fn load_extra(f: *Fetcher, number: u64, keys: *Keys) !void {
    const path = try extra_keys_path(f, number);
    if (!f.exists(path)) return;
    const value = try json.parseFromSliceLeaky(json.Value, f.alloc(), try f.read(path), .{});
    if (value != .object) return error.MalformedResponse;
    for (value.object.keys(), value.object.values()) |address, slots| {
        try keys.add_account(f.alloc(), address);
        if (slots != .array) return error.MalformedResponse;
        for (slots.array.items) |slot| {
            if (slot != .string) return error.MalformedResponse;
            try keys.add_slot(f.alloc(), address, slot.string);
        }
    }
}

/// Seeds every block with the system-call contracts (and the slots they write: the
/// timestamp ring of EIP-4788, the parent hash ring of EIP-2935) and the message passer;
/// the first block also gets the precompiles, which the executor loads on every
/// transaction.
fn seed_extra(f: *Fetcher, window: replay_cli.Window) !void {
    for (0..window.count) |offset| {
        _ = f.arena.reset(.retain_capacity);
        const number = window.first + offset;
        if (f.exists(try extra_keys_path(f, number))) continue;
        const block_path = try std.fmt.allocPrint(f.alloc(), "{d}/block.json", .{number});
        const block_text = try f.read(block_path);
        const block = try json.parseFromSliceLeaky(json.Value, f.alloc(), block_text, .{});
        const timestamp_value = block.object.get("timestamp") orelse return error.MalformedResponse;
        if (timestamp_value != .string) return error.MalformedResponse;
        const timestamp = try std.fmt.parseInt(u64, timestamp_value.string[2..], 16);
        var keys: Keys = .{};
        const ring = timestamp % history_buffer_length;
        try keys.add_slot(f.alloc(), beacon_roots, try slot_hex(f, ring));
        try keys.add_slot(f.alloc(), beacon_roots, try slot_hex(f, ring + history_buffer_length));
        const parent_slot = (number - 1) % history_buffer_length;
        try keys.add_slot(f.alloc(), history, try slot_hex(f, parent_slot));
        try keys.add_account(f.alloc(), message_passer);
        try keys.add_account(f.alloc(), system_address);
        if (offset == 0) {
            for ([_]u16{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0x100 }) |id| {
                const address = try std.fmt.allocPrint(f.alloc(), "0x{x:0>40}", .{id});
                try keys.add_account(f.alloc(), address);
            }
        }
        try write_extra(f, number, &keys);
    }
}

fn slot_hex(f: *Fetcher, slot: u64) ![]u8 {
    return std.fmt.allocPrint(f.alloc(), "0x{x:0>64}", .{slot});
}

fn add_extra(f: *Fetcher, report: replay_cli.GapReport) !void {
    var keys: Keys = .{};
    try load_extra(f, report.block, &keys);
    const before = key_count(&keys);
    for (report.accounts) |address| {
        try keys.add_account(f.alloc(), try std.fmt.allocPrint(f.alloc(), "0x{x}", .{address}));
    }
    for (report.slots) |key| {
        const address = try std.fmt.allocPrint(f.alloc(), "0x{x}", .{key.address});
        const slot = try std.fmt.allocPrint(f.alloc(), "0x{x:0>64}", .{key.slot});
        try keys.add_slot(f.alloc(), address, slot);
    }
    if (key_count(&keys) == before) return error.WitnessIncomplete; // No progress.
    try write_extra(f, report.block, &keys);
}

fn key_count(keys: *const Keys) usize {
    var count: usize = keys.map.count();
    for (keys.map.values()) |slots| count += slots.count();
    return count;
}

/// Fetches proofs (at the parent) and code for a block's extra keys and stores them with
/// the key list.
fn write_extra(f: *Fetcher, number: u64, keys: *Keys) !void {
    const arena = f.alloc();
    const proofs = try prove(f, keys, number - 1);
    try f.save(try std.fmt.allocPrint(arena, "{d}/proofs_extra.json", .{number}), proofs);
    var codes: Io.Writer.Allocating = .init(arena);
    try codes.writer.writeAll("[");
    var written: u32 = 0;
    for (keys.map.keys()) |address| {
        const params = try std.fmt.allocPrint(arena, "[\"{s}\",\"0x{x}\"]", .{
            address,
            number - 1,
        });
        const code = try f.call(&f.proof, "eth_getCode", params);
        if (std.mem.eql(u8, code, "\"0x\"")) continue;
        try codes.writer.print("{s}{s}", .{ if (written == 0) "" else ",", code });
        written += 1;
    }
    try codes.writer.writeAll("]");
    try f.save(try std.fmt.allocPrint(arena, "{d}/codes_extra.json", .{number}), codes.written());
    var list: Io.Writer.Allocating = .init(arena);
    try list.writer.writeAll("{");
    for (keys.map.keys(), keys.map.values(), 0..) |address, slots, index| {
        try list.writer.print("{s}\"{s}\":[", .{ if (index == 0) "" else ",", address });
        for (slots.keys(), 0..) |slot, slot_index| {
            try list.writer.print("{s}\"{s}\"", .{ if (slot_index == 0) "" else ",", slot });
        }
        try list.writer.writeAll("]");
    }
    try list.writer.writeAll("}");
    try f.save(try extra_keys_path(f, number), list.written());
}

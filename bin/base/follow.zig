//! `base follow`: a validating follower (docs/SYNC_PLAN.md M1). It follows the live tip of
//! Base Sepolia or Base mainnet over public JSON-RPC, re-executes every block with
//! needlefish's executor over a stateless sparse state fetched on demand, and checks every
//! header field (`base.infra.follow`). On a mismatch it prints the first failed check, the
//! first differing receipt and the first differing account or slot, and exits 1.
//!
//!     base follow [--chain base-sepolia|base-mainnet] [--block-rpc <url>]
//!                 [--proof-rpc <url>] [--proof-batch <n>] [--from <block>]
//!                 [--blocks <n>] [--status <path>] [--verbose]
//!
//! Blocks come from `--block-rpc` (headers and transactions are re-encoded and bound to the
//! block hash), proofs and codes from `--proof-rpc` at the parent of the block that lacks
//! them. Nothing fetched is trusted: proof nodes are stored by hash and only used where the
//! verified trie references them. Endpoints are paced per item and retried with backoff.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const HttpTransport = @import("http_transport.zig").HttpTransport;
const follow = base.infra.follow;
const Follower = follow.Follower;
const json = std.json;
const assert = std.debug.assert;

const Hash = [32]u8;
const Address = [20]u8;

const usage =
    \\usage: base follow [--chain base-sepolia|base-mainnet] [--block-rpc <url>]
    \\                   [--proof-rpc <url>] [--proof-batch <n>] [--from <block>]
    \\                   [--blocks <n>] [--status <path>] [--verbose]
    \\
;

const Chain = struct {
    name: []const u8,
    spec: *const base.execution.chainspec.ChainSpec,
    block_url: []const u8,
    proof_url: []const u8,
    proof_batch: u32,
    /// Spacing between items sent to the proof endpoint (its public rate limit).
    proof_item_interval_ms: u32,
};

const chains = [_]Chain{
    .{
        .name = "base-sepolia",
        .spec = &base.execution.chainspec.ChainSpec.presets.base_sepolia,
        .block_url = "https://base-sepolia-rpc.publicnode.com",
        // Serves `eth_getProof` for the most recent 10,000 blocks; batches of 5.
        .proof_url = "https://sepolia.base.org",
        .proof_batch = 5,
        .proof_item_interval_ms = 150,
    },
    .{
        .name = "base-mainnet",
        .spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet,
        .block_url = "https://mainnet.base.org",
        .proof_url = "https://base.drpc.org",
        .proof_batch = 1,
        .proof_item_interval_ms = 100,
    },
};

const Flags = struct {
    chain: *const Chain = &chains[0],
    block_url: ?[]const u8 = null,
    proof_url: ?[]const u8 = null,
    proof_batch: ?u32 = null,
    from: ?u64 = null,
    blocks: ?u64 = null,
    status: ?[]const u8 = null,
    verbose: bool = false,
};

fn parse(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const name = args[index];
        if (std.mem.eql(u8, name, "--verbose")) {
            flags.verbose = true;
            continue;
        }
        if (index + 1 == args.len) return error.InvalidArguments;
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, name, "--chain")) {
            flags.chain = for (&chains) |*chain| {
                if (std.mem.eql(u8, chain.name, value)) break chain;
            } else return error.InvalidArguments;
        } else if (std.mem.eql(u8, name, "--block-rpc")) {
            flags.block_url = try url_value(value);
        } else if (std.mem.eql(u8, name, "--proof-rpc")) {
            flags.proof_url = try url_value(value);
        } else if (std.mem.eql(u8, name, "--proof-batch")) {
            flags.proof_batch = try std.fmt.parseInt(u32, value, 10);
            if (flags.proof_batch.? == 0 or flags.proof_batch.? > batch_max) {
                return error.InvalidArguments;
            }
        } else if (std.mem.eql(u8, name, "--from")) {
            flags.from = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--blocks")) {
            flags.blocks = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--status")) {
            flags.status = value;
        } else return error.InvalidArguments;
    }
    return flags;
}

fn url_value(value: []const u8) ![]const u8 {
    if (!std.mem.startsWith(u8, value, "http://") and !std.mem.startsWith(u8, value, "https://")) {
        return error.InvalidArguments;
    }
    return value;
}

const batch_max = 16;
const retries_max = 10;
const response_bytes_max = 64 << 20;
/// Probe and verify passes per block before the follower gives up on it.
const attempts_max = 2048;
/// Passes in a row that fetch nothing new before the follower rebases, then gives up.
const stuck_max = 3;
const summary_interval_ms = 10_000;

/// One JSON-RPC endpoint: a reusable response buffer, per-item pacing, and retries with
/// backoff on transport errors and rate limits.
const Endpoint = struct {
    http: HttpTransport,
    response: []u8,
    batch_max: u32,
    item_interval_ms: u32,
    /// Awake-clock time (ms) before which the next request waits.
    next_ms: i64 = 0,
    requests: u64 = 0,
    items: u64 = 0,
    limited: u64 = 0,

    fn pace(endpoint: *Endpoint, io: Io, items: u32) !void {
        const now = Io.Clock.awake.now(io).toMilliseconds();
        if (endpoint.next_ms > now) try io.sleep(.fromMilliseconds(endpoint.next_ms - now), .awake);
        const start = @max(now, endpoint.next_ms);
        endpoint.next_ms = start + @as(i64, items) * endpoint.item_interval_ms;
    }

    /// Posts `body` (`items` calls) and returns the response text once it parses as JSON
    /// without a top-level or per-item error.
    fn post(
        endpoint: *Endpoint,
        io: Io,
        arena: std.mem.Allocator,
        body: []const u8,
        items: u32,
    ) !json.Value {
        assert(items > 0);
        var attempt: u32 = 0;
        while (attempt < retries_max) : (attempt += 1) {
            if (attempt > 0) {
                const wait_ms: i64 = @min(@as(i64, 250) << @intCast(@min(attempt, 7)), 15_000);
                try io.sleep(.fromMilliseconds(wait_ms), .awake);
            }
            try endpoint.pace(io, items);
            endpoint.requests += 1;
            endpoint.items += items;
            const text = endpoint.http.transport().send(body, endpoint.response) catch |err| {
                std.debug.print("  {s}: {t}\n", .{ endpoint.http.url, err });
                continue;
            };
            const value = json.parseFromSliceLeaky(json.Value, arena, text, .{}) catch {
                endpoint.limited += 1;
                continue;
            };
            if (!responses_ok(value)) {
                endpoint.limited += 1;
                if (attempt >= 3) {
                    const shown = text[0..@min(text.len, 200)];
                    std.debug.print("  {s}: {s}\n", .{ endpoint.http.url, shown });
                }
                continue;
            }
            return value;
        }
        return error.EndpointFailed;
    }

    /// One call; returns its `result` (possibly JSON null).
    fn call(
        endpoint: *Endpoint,
        io: Io,
        arena: std.mem.Allocator,
        method: []const u8,
        params: []const u8,
    ) !json.Value {
        const body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":0," ++
            "\"method\":\"{s}\",\"params\":{s}}}", .{ method, params });
        const value = try endpoint.post(io, arena, body, 1);
        if (value != .object) return error.MalformedResponse;
        return value.object.get("result") orelse error.MalformedResponse;
    }

    /// Calls of one method, batched by `batch_max`; returns each `result`, in order.
    fn batch(
        endpoint: *Endpoint,
        io: Io,
        arena: std.mem.Allocator,
        method: []const u8,
        params: []const []const u8,
    ) ![]json.Value {
        const results = try arena.alloc(json.Value, params.len);
        var start: usize = 0;
        while (start < params.len) : (start += endpoint.batch_max) {
            const chunk = params[start..@min(start + endpoint.batch_max, params.len)];
            if (chunk.len == 1) {
                results[start] = try endpoint.call(io, arena, method, chunk[0]);
                continue;
            }
            var body: Io.Writer.Allocating = .init(arena);
            try body.writer.writeAll("[");
            for (chunk, 0..) |param, id| {
                try body.writer.print("{s}{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\"," ++
                    "\"params\":{s}}}", .{ if (id == 0) "" else ",", id, method, param });
            }
            try body.writer.writeAll("]");
            const value = try endpoint.post(io, arena, body.written(), @intCast(chunk.len));
            if (value != .array) return error.MalformedResponse;
            if (value.array.items.len != chunk.len) return error.MalformedResponse;
            for (value.array.items) |item| {
                const id = item.object.get("id") orelse return error.MalformedResponse;
                if (id != .integer or id.integer < 0 or id.integer >= chunk.len) {
                    return error.MalformedResponse;
                }
                results[start + @as(usize, @intCast(id.integer))] = item.object.get("result").?;
            }
        }
        return results;
    }
};

/// A response (one object or a batch) with no error and a `result` everywhere.
fn responses_ok(value: json.Value) bool {
    const items: []const json.Value = switch (value) {
        .array => |array| array.items,
        .object => (&value)[0..1],
        else => return false,
    };
    if (items.len == 0) return false;
    for (items) |item| {
        if (item != .object) return false;
        if (item.object.get("error") != null) return false;
        if (item.object.get("result") == null) return false;
    }
    return true;
}

const Driver = struct {
    init: std.process.Init,
    flags: Flags,
    arena: std.heap.ArenaAllocator,
    blocks: Endpoint,
    proofs: Endpoint,
    follower: *Follower,
    status_file: ?[]const u8,
    started_ms: i64,
    last_summary_ms: i64 = 0,
    chain_head: u64 = 0,
    proofs_fetched: u64 = 0,
    codes_fetched: u64 = 0,
    post_fetches: u64 = 0,
    reorgs: u64 = 0,
    gas_window: u64 = 0,
    window_start_ms: i64 = 0,
    last_lag_ms: i64 = 0,

    fn io(driver: *Driver) Io {
        return driver.init.io;
    }

    fn alloc(driver: *Driver) std.mem.Allocator {
        return driver.arena.allocator();
    }

    fn block_call(driver: *Driver, method: []const u8, params: []const u8) !json.Value {
        return driver.blocks.call(driver.io(), driver.alloc(), method, params);
    }

    fn head_number(driver: *Driver) !u64 {
        const result = try driver.block_call("eth_blockNumber", "[]");
        return quantity(result);
    }

    /// The JSON text of block `number` with full transactions, or null if not produced yet.
    fn block_json(driver: *Driver, number: u64) !?[]const u8 {
        const params = try std.fmt.allocPrint(driver.alloc(), "[\"0x{x}\",true]", .{number});
        const result = try driver.block_call("eth_getBlockByNumber", params);
        if (result == .null) return null;
        return try json.Stringify.valueAlloc(driver.alloc(), result, .{});
    }

    /// Hash-links the 256 headers ending at `number` and starts the follower there.
    fn anchor(driver: *Driver, number: u64) !void {
        const count: u64 = @min(follow.follower.block_hash_window, number + 1);
        const low = number + 1 - count;
        const params = try driver.alloc().alloc([]const u8, @intCast(count));
        for (params, 0..) |*param, offset| {
            param.* = try std.fmt.allocPrint(driver.alloc(), "[\"0x{x}\",false]", .{low + offset});
        }
        const method = "eth_getBlockByNumber";
        const results = try driver.blocks.batch(driver.io(), driver.alloc(), method, params);
        const hashes = try driver.alloc().alloc(Hash, @intCast(count));
        var state_root: Hash = undefined;
        for (results, hashes, 0..) |result, *hash, offset| {
            var extra: [base.consensus.sources.header_json.extra_data_size_max]u8 = undefined;
            const text = try json.Stringify.valueAlloc(driver.alloc(), result, .{});
            const decoded = try base.consensus.sources.header_json.decode(text, &extra);
            if (decoded.header.number != low + offset) return error.InconsistentHeaders;
            if (offset > 0 and !decoded.header.parent_hash.eql(.{ .bytes = hashes[offset - 1] })) {
                return error.InconsistentHeaders;
            }
            hash.* = decoded.hash.bytes;
            state_root = decoded.header.state_root.bytes;
        }
        driver.follower.start(.{
            .number = number,
            .hash = hashes[hashes.len - 1],
            .state_root = state_root,
        }, hashes);
        std.debug.print("anchored at block {d} {x} (state root {x})\n", .{
            number,
            hashes[hashes.len - 1],
            state_root,
        });
    }

    /// Fetches proofs (at block `at`) for the accounts and slots of `keys` and adds their
    /// nodes. Returns the number of proofs fetched.
    fn fetch_proofs(driver: *Driver, keys: *const Keys, at: u64, post: bool) !u32 {
        const arena = driver.alloc();
        if (keys.map.count() == 0) return 0;
        const params = try arena.alloc([]const u8, keys.map.count());
        for (keys.map.keys(), keys.map.values(), params) |address, slots, *param| {
            var text: Io.Writer.Allocating = .init(arena);
            try text.writer.print("[\"0x{x}\",[", .{address});
            for (slots.keys(), 0..) |slot, index| {
                try text.writer.print("{s}\"0x{x:0>64}\"", .{ if (index == 0) "" else ",", slot });
            }
            try text.writer.print("],\"0x{x}\"]", .{at});
            param.* = text.written();
        }
        const results = try driver.proofs.batch(driver.io(), arena, "eth_getProof", params);
        var nodes: std.ArrayList([]const u8) = .empty;
        for (results) |result| try follow.proofs.collect_nodes(arena, result, &nodes);
        if (post) {
            try driver.follower.add_post_nodes(nodes.items);
        } else {
            for (nodes.items) |node| try driver.follower.add_node(node);
        }
        driver.proofs_fetched += results.len;
        return @intCast(results.len);
    }

    fn fetch_codes(driver: *Driver, owners: []const Address, at: u64) !u32 {
        const arena = driver.alloc();
        if (owners.len == 0) return 0;
        const params = try arena.alloc([]const u8, owners.len);
        for (owners, params) |owner, *param| {
            param.* = try std.fmt.allocPrint(arena, "[\"0x{x}\",\"0x{x}\"]", .{ owner, at });
        }
        const results = try driver.proofs.batch(driver.io(), arena, "eth_getCode", params);
        for (results) |result| {
            try driver.follower.add_code(try follow.proofs.decode_hex(arena, result));
        }
        driver.codes_fetched += results.len;
        return @intCast(results.len);
    }

    /// Fetches what the last pass lacked, at the block's parent. Returns the items fetched.
    fn fill_gaps(driver: *Driver, parent: u64) !u32 {
        const gaps = &driver.follower.gaps;
        var keys: Keys = .{};
        for (gaps.accounts[0..gaps.accounts_len]) |address| {
            try keys.add_account(driver.alloc(), address);
        }
        for (gaps.slots[0..gaps.slots_len]) |key| {
            try keys.add_slot(driver.alloc(), key.address, key.slot);
        }
        // A code owner's account proof is already known; fetch its code only.
        const fetched = try driver.fetch_proofs(&keys, parent, false);
        return fetched + try driver.fetch_codes(gaps.code_owners[0..gaps.code_owners_len], parent);
    }

    /// The post-state proofs of the keys the clean pass deletes (collapse siblings).
    fn fetch_post_nodes(driver: *Driver, number: u64) !u32 {
        const follower = driver.follower;
        var keys: Keys = .{};
        for (follower.deleted_accounts[0..follower.deleted_accounts_len]) |address| {
            try keys.add_account(driver.alloc(), address);
        }
        for (follower.deleted_slots[0..follower.deleted_slots_len]) |key| {
            try keys.add_slot(driver.alloc(), key.address, key.slot);
        }
        driver.post_fetches += 1;
        return driver.fetch_proofs(&keys, number, true);
    }

    /// Follows one block to a verified outcome (or a mismatch).
    fn follow_block(driver: *Driver, block: *const follow.follower.Block) !follow.follower.Outcome {
        const follower = driver.follower;
        var stuck: u32 = 0;
        var post_fetched = false;
        var attempt: u32 = 0;
        while (attempt < attempts_max) : (attempt += 1) {
            switch (try follower.probe(block)) {
                .gaps => {
                    const gaps = &follower.gaps;
                    if (driver.flags.verbose) std.debug.print("  pass {d}: {d} accounts " ++
                        "{d} slots " ++
                        "{d} codes {d} nodes {d} hashes (+{d})\n", .{
                        attempt,
                        gaps.accounts_len,
                        gaps.slots_len,
                        gaps.code_owners_len,
                        gaps.nodes_len,
                        gaps.block_hashes_len,
                        gaps.dropped,
                    });
                    if (try driver.fill_gaps(block.number - 1) > 0) {
                        stuck = 0;
                        continue;
                    }
                    stuck += 1;
                    if (stuck == stuck_max) return error.Stuck;
                    follower.rebase();
                },
                .full => {
                    std.debug.print("block {d}: {?t}, resetting\n", .{
                        block.number,
                        follower.full_error,
                    });
                    follower.reset();
                },
                .failed => {
                    std.debug.print("block {d}: execution failed over a complete witness: " ++
                        "{?t} (transaction {?d})\n", .{
                        block.number,
                        follower.probe_error,
                        follower.failed_transaction,
                    });
                    return error.Mismatch;
                },
                .ready => {
                    const outcome = try follower.verify(block);
                    if (outcome.ok() or !follow.follower.retryable(&outcome)) return outcome;
                    if (driver.flags.verbose) std.debug.print("block {d}: retry after {?t}\n", .{
                        block.number,
                        outcome.failure,
                    });
                    if (!post_fetched) {
                        post_fetched = true;
                        _ = try driver.fetch_post_nodes(block.number);
                    }
                },
            }
        }
        return error.Stuck;
    }

    fn report_mismatch(driver: *Driver, outcome: *const follow.follower.Outcome) !void {
        std.debug.print("MISMATCH block {d} {x}\n", .{ outcome.number, outcome.hash });
        if (outcome.failure) |failure| std.debug.print("  execution failed: {t} " ++
            "(transaction {?d})\n", .{
            failure,
            outcome.failed_transaction,
        });
        if (outcome.first_failed()) |check| {
            std.debug.print("  first failed check: {t}\n", .{check});
        }
        std.debug.print("  state root expected {x} computed {x}\n", .{
            outcome.expected_state_root,
            outcome.computed_state_root,
        });
        driver.report_receipts(outcome.number) catch |err| {
            std.debug.print("  receipts unavailable: {t}\n", .{err});
        };
        driver.report_state(outcome.number) catch |err| {
            std.debug.print("  state comparison unavailable: {t}\n", .{err});
        };
    }

    fn report_receipts(driver: *Driver, number: u64) !void {
        const params = try std.fmt.allocPrint(driver.alloc(), "[\"0x{x}\"]", .{number});
        const list = try driver.block_call("eth_getBlockReceipts", params);
        if (list != .array) return error.MalformedResponse;
        const mine = driver.follower.last_receipts;
        if (list.array.items.len != mine.len) {
            std.debug.print("  receipts: expected {d} computed {d}\n", .{
                list.array.items.len,
                mine.len,
            });
        }
        const count = @min(mine.len, list.array.items.len);
        for (list.array.items[0..count], mine[0..count], 0..) |entry, receipt, index| {
            const status = try quantity(try member(entry, "status"));
            const gas = try quantity(try member(entry, "cumulativeGasUsed"));
            const logs = try member(entry, "logs");
            if (logs != .array) return error.MalformedResponse;
            if ((status == 1) == receipt.status and gas == receipt.cumulative_gas_used and
                logs.array.items.len == receipt.logs.count) continue;
            std.debug.print("  first differing receipt {d}: expected status {d} gas {d} " ++
                "logs {d}, " ++
                "computed status {} gas {d} logs {d}\n", .{
                index,
                status,
                gas,
                logs.array.items.len,
                receipt.status,
                receipt.cumulative_gas_used,
                receipt.logs.count,
            });
            return;
        }
        std.debug.print("  receipts match\n", .{});
    }

    /// Compares every account and slot the block changed (needlefish's changeset) with the
    /// canonical post-state from `eth_getProof` at the block.
    fn report_state(driver: *Driver, number: u64) !void {
        const changeset = &driver.follower.changeset;
        var keys: Keys = .{};
        for (changeset.account_changes()) |change| {
            try keys.add_account(driver.alloc(), change.address);
        }
        for (changeset.storage_changes()) |change| {
            try keys.add_slot(driver.alloc(), change.address, change.slot);
        }
        if (keys.map.count() == 0) return error.NoChanges;
        const arena = driver.alloc();
        const params = try arena.alloc([]const u8, keys.map.count());
        for (keys.map.keys(), keys.map.values(), params) |address, slots, *param| {
            var text: Io.Writer.Allocating = .init(arena);
            try text.writer.print("[\"0x{x}\",[", .{address});
            for (slots.keys(), 0..) |slot, index| {
                try text.writer.print("{s}\"0x{x:0>64}\"", .{ if (index == 0) "" else ",", slot });
            }
            try text.writer.print("],\"0x{x}\"]", .{number});
            param.* = text.written();
        }
        const results = try driver.proofs.batch(driver.io(), arena, "eth_getProof", params);
        const sparse = &driver.follower.sparse;
        for (results, keys.map.keys()) |result, address| {
            const nonce = try quantity(try member(result, "nonce"));
            const balance = try quantity_u256(try member(result, "balance"));
            const computed = sparse.basic(address) catch null;
            const computed_nonce: u64 = if (computed) |info| info.nonce else 0;
            const computed_balance: u256 = if (computed) |info| info.balance else 0;
            if (nonce != computed_nonce or balance != computed_balance) {
                std.debug.print("  first differing account 0x{x}: expected nonce {d} " ++
                    "balance {d}, computed nonce {d} balance {d}\n", .{
                    address,
                    nonce,
                    balance,
                    computed_nonce,
                    computed_balance,
                });
                return;
            }
            const storage = result.object.get("storageProof") orelse return error.MalformedResponse;
            if (storage != .array) return error.MalformedResponse;
            for (storage.array.items) |entry| {
                const key = try quantity_u256(try member(entry, "key"));
                const value = try quantity_u256(try member(entry, "value"));
                const mine = sparse.storage(address, key) catch continue;
                if (mine == value) continue;
                std.debug.print("  first differing slot 0x{x} 0x{x:0>64}: expected 0x{x} " ++
                    "computed 0x{x}\n", .{
                    address,
                    key,
                    value,
                    mine,
                });
                return;
            }
        }
        std.debug.print("  every changed account and slot matches the canonical post-state\n", .{});
    }

    fn summary(driver: *Driver, force: bool) !void {
        const now = Io.Clock.awake.now(driver.io()).toMilliseconds();
        if (!force and now - driver.last_summary_ms < summary_interval_ms) return;
        const stats = driver.follower.stats;
        const elapsed_ms = @max(now - driver.window_start_ms, 1);
        const gas: f64 = @floatFromInt(driver.gas_window);
        const mgas_s = gas / @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
        const head = driver.follower.head.number;
        const behind = driver.chain_head -| head;
        std.debug.print("follow {s} head {d} verified {d} txs {d} behind {d} blocks " ++
            "({d} ms) {d:.2} Mgas/s passes {d} proofs {d} codes {d} rebases {d} resets {d} " ++
            "reorgs {d} mismatches 0\n", .{
            driver.flags.chain.name,
            head,
            stats.blocks,
            stats.transactions,
            behind,
            driver.last_lag_ms,
            mgas_s,
            stats.probe_passes,
            driver.proofs_fetched,
            driver.codes_fetched,
            stats.rebases,
            stats.resets,
            driver.reorgs,
        });
        try driver.write_status(behind, mgas_s);
        driver.last_summary_ms = now;
        driver.window_start_ms = now;
        driver.gas_window = 0;
    }

    fn write_status(driver: *Driver, behind: u64, mgas_s: f64) !void {
        const path = driver.status_file orelse return;
        const stats = driver.follower.stats;
        const real_s = Io.Clock.real.now(driver.io()).toSeconds();
        const text = try std.fmt.allocPrint(driver.alloc(), "{{\"chain\":\"{s}\"," ++
            "\"updated\":{d}," ++
            "\"started\":{d},\"head\":{d},\"head_hash\":\"0x{x}\",\"verified\":{d}," ++
            "\"transactions\":{d},\"gas\":{d},\"behind_blocks\":{d},\"lag_ms\":{d}," ++
            "\"mgas_per_s\":{d:.3},\"rebases\":{d},\"resets\":{d},\"reorgs\":{d}," ++
            "\"proofs\":{d},\"mismatches\":0}}\n", .{
            driver.flags.chain.name,
            real_s,
            driver.started_ms,
            driver.follower.head.number,
            driver.follower.head.hash,
            stats.blocks,
            stats.transactions,
            stats.gas,
            behind,
            driver.last_lag_ms,
            mgas_s,
            stats.rebases,
            stats.resets,
            driver.reorgs,
            driver.proofs_fetched,
        });
        const temporary = try std.fmt.allocPrint(driver.alloc(), "{s}.tmp", .{path});
        try Io.Dir.cwd().writeFile(driver.io(), .{ .sub_path = temporary, .data = text });
        try Io.Dir.cwd().rename(temporary, Io.Dir.cwd(), path, driver.io());
    }
};

/// Accounts to the slots to prove, in first-seen order.
const Keys = struct {
    map: std.AutoArrayHashMapUnmanaged(Address, std.AutoArrayHashMapUnmanaged(u256, void)) = .empty,

    fn add_account(keys: *Keys, arena: std.mem.Allocator, address: Address) !void {
        const entry = try keys.map.getOrPut(arena, address);
        if (!entry.found_existing) entry.value_ptr.* = .empty;
    }

    fn add_slot(keys: *Keys, arena: std.mem.Allocator, address: Address, slot: u256) !void {
        try keys.add_account(arena, address);
        try keys.map.getPtr(address).?.put(arena, slot, {});
    }
};

fn member(value: json.Value, name: []const u8) !json.Value {
    if (value != .object) return error.MalformedResponse;
    return value.object.get(name) orelse error.MalformedResponse;
}

fn quantity(value: json.Value) !u64 {
    if (value != .string or value.string.len < 3 or !std.mem.startsWith(u8, value.string, "0x")) {
        return error.MalformedResponse;
    }
    return std.fmt.parseInt(u64, value.string[2..], 16);
}

fn quantity_u256(value: json.Value) !u256 {
    if (value != .string or value.string.len < 3 or !std.mem.startsWith(u8, value.string, "0x")) {
        return error.MalformedResponse;
    }
    return std.fmt.parseInt(u256, value.string[2..], 16);
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const gpa = init.gpa;
    const chain = flags.chain;
    const block_response = try gpa.alloc(u8, response_bytes_max);
    defer gpa.free(block_response);
    const proof_response = try gpa.alloc(u8, response_bytes_max);
    defer gpa.free(proof_response);
    const follower = try gpa.create(Follower);
    defer gpa.destroy(follower);
    var config = follow.follower.default_config();
    const cores: u32 = @intCast(@max(std.Thread.getCpuCount() catch 1, 1));
    config.executor.recovery_threads = @min(cores - 1, 7);
    config.executor.state_gas_basis = base.execution.node.executor.default_state_gas_basis;
    try follower.init(gpa, chain.spec, config);
    defer follower.deinit(gpa);
    var driver: Driver = .{
        .init = init,
        .flags = flags,
        .arena = .init(gpa),
        .blocks = .{
            .http = .init(gpa, init.io, flags.block_url orelse chain.block_url),
            .response = block_response,
            .batch_max = 10,
            .item_interval_ms = 40,
        },
        .proofs = .{
            .http = .init(gpa, init.io, flags.proof_url orelse chain.proof_url),
            .response = proof_response,
            .batch_max = flags.proof_batch orelse chain.proof_batch,
            .item_interval_ms = chain.proof_item_interval_ms,
        },
        .follower = follower,
        .status_file = flags.status,
        .started_ms = Io.Clock.real.now(init.io).toSeconds(),
    };
    defer driver.arena.deinit();
    defer driver.blocks.http.deinit();
    defer driver.proofs.http.deinit();
    driver.blocks.http.timeout_ms = 30_000;
    driver.proofs.http.timeout_ms = 30_000;
    return run(&driver);
}

fn run(driver: *Driver) !u8 {
    const io = driver.io();
    driver.chain_head = try driver.head_number();
    const first = driver.flags.from orelse driver.chain_head;
    if (first == 0) return error.InvalidArguments;
    std.debug.print("following {s} from block {d} (chain head {d}); blocks {s}, proofs {s}\n", .{
        driver.flags.chain.name,
        first,
        driver.chain_head,
        driver.blocks.http.url,
        driver.proofs.http.url,
    });
    try driver.anchor(first - 1);
    driver.window_start_ms = Io.Clock.awake.now(io).toMilliseconds();
    var number = first;
    var head_checked_ms: i64 = 0;
    while (driver.flags.blocks == null or number - first < driver.flags.blocks.?) {
        _ = driver.arena.reset(.retain_capacity);
        const now_ms = Io.Clock.awake.now(io).toMilliseconds();
        if (now_ms - head_checked_ms > 2_000) {
            driver.chain_head = driver.head_number() catch driver.chain_head;
            head_checked_ms = now_ms;
        }
        const raw = try driver.block_json(number) orelse {
            try io.sleep(.fromMilliseconds(50), .awake);
            continue;
        };
        const block = try follow.follower.decode_block(driver.alloc(), raw);
        if (!std.mem.eql(u8, &block.parent_hash, &driver.follower.head.hash)) {
            driver.reorgs += 1;
            std.debug.print("block {d}: parent {x} is not the verified head {x}: reorg, " ++
                "re-anchoring at {d}\n", .{
                number,
                block.parent_hash,
                driver.follower.head.hash,
                number - 1,
            });
            try driver.anchor(number - 1);
            continue;
        }
        const started = Io.Clock.awake.now(io).toMilliseconds();
        const outcome = driver.follow_block(&block) catch |err| {
            std.debug.print("block {d}: {t}\n", .{ number, err });
            try driver.summary(true);
            return 1;
        };
        if (!outcome.ok()) {
            try driver.report_mismatch(&outcome);
            try driver.summary(true);
            return 1;
        }
        const finished = Io.Clock.awake.now(io).toMilliseconds();
        const header = try base.common.consensus.Header.decode(block.header_rlp);
        driver.last_lag_ms = Io.Clock.real.now(io).toMilliseconds() -
            @as(i64, @intCast(header.timestamp)) * 1000;
        driver.gas_window += header.gas_used;
        driver.chain_head = @max(driver.chain_head, number);
        if (driver.flags.verbose) std.debug.print("block {d} {d} txs {d} gas ok in {d} ms\n", .{
            number,
            outcome.transactions,
            outcome.gas_used,
            finished - started,
        });
        try driver.summary(false);
        number += 1;
    }
    try driver.summary(true);
    return 0;
}

test "follow: flags" {
    const defaults = try parse(&.{});
    try std.testing.expectEqualStrings("base-sepolia", defaults.chain.name);
    try std.testing.expect(defaults.from == null and !defaults.verbose);
    const set = try parse(&.{
        "--chain", "base-mainnet", "--from", "7", "--verbose", "--blocks", "3",
    });
    try std.testing.expectEqualStrings("base-mainnet", set.chain.name);
    try std.testing.expectEqual(@as(?u64, 7), set.from);
    try std.testing.expectEqual(@as(?u64, 3), set.blocks);
    try std.testing.expect(set.verbose);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--chain", "op-mainnet" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--block-rpc", "ftp://x" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--from"}));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "--proof-batch", "0" }));
}

test "follow: responses are accepted only without errors" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ok = [_][]const u8{
        "{\"id\":0,\"result\":null}",
        "[{\"id\":0,\"result\":1},{\"id\":1,\"result\":\"0x\"}]",
    };
    for (ok) |text| {
        const value = try json.parseFromSliceLeaky(json.Value, arena, text, .{});
        try std.testing.expect(responses_ok(value));
    }
    const rejected = [_][]const u8{
        "{\"id\":0,\"error\":{\"code\":-32011,\"message\":\"request limit reached\"}}",
        "[{\"id\":0,\"result\":1},{\"id\":1,\"error\":{\"code\":429}}]",
        "[{\"id\":0}]",
        "[]",
        "7",
    };
    for (rejected) |text| {
        const value = try json.parseFromSliceLeaky(json.Value, arena, text, .{});
        try std.testing.expect(!responses_ok(value));
    }
}

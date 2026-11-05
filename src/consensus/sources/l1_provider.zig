//! A non-blocking, caching L1 chain provider over JSON-RPC that implements the derivation
//! chain-provider contract (`derive/providers.zig`).
//!
//! Every query is answered from the cache. On a miss the provider enqueues one fetch and
//! returns `error.NotAvailable`; the pipeline retries after IO progresses and the
//! completion has filled the cache. A fetch that finds nothing (`null` result) is
//! reported once as `error.NotFound`. Failed fetches (transport errors, RPC errors,
//! malformed or unverifiable data) are dropped and re-requested on the next query, so a
//! bad response never reaches the pipeline.
//!
//! Bounds: one request in flight, a fixed-size request queue with de-duplication (a full
//! queue drops the new request; the caller's retry re-enqueues it), and fixed-size LRU
//! caches. Block contents live in one arena per cache slot, reset on eviction, so after
//! warm-up the provider allocates only when a block is larger than any seen before.
//!
//! Verification: headers must hash to the block hash; senders of batch-inbox transactions
//! are recovered from signatures; unless `trust_rpc` is set, transactions and receipts
//! must match the header's trie roots.
//!
//! By-number results are kept for `block_by_number_ttl_ns` only: numbers move on reorgs,
//! so base/base never caches them; the short TTL lets the pipeline consume a completed
//! fetch without re-requesting it. Hash-keyed results are immutable and LRU-cached.
//! Mirrors base/base `crates/consensus/providers/src/chain_provider.rs`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../protocol/root.zig");
const errors = @import("../derive/errors.zig");
const providers = @import("../derive/providers.zig");
const header_json = @import("header_json.zig");
const transaction_json = @import("transaction_json.zig");
const receipt_json = @import("receipt_json.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const BlockInfo = protocol.block.BlockInfo;
const L1Header = protocol.l1_info.L1Header;
const Receipt = protocol.log.Receipt;
const L1Transaction = providers.L1Transaction;
const ProviderError = errors.ProviderError;

pub const queue_size_max = 64;
pub const cache_entries_max = 1024;
pub const missing_max = 8;
/// JSON-RPC request bodies are tiny (one hash or number).
const request_size_max = 4096;
const scratch_retain_bytes = 1024 * 1024;

pub const Options = struct {
    /// Entries per cache (headers, transactions, receipts, by-number).
    cache_entries: u32 = 32,
    queue_size: u32 = 16,
    /// Skip transactions and receipts root checks (base/base `trust_rpc`).
    trust_rpc: bool = false,
    /// Recover senders only for transactions to the batch inbox. Null recovers all.
    batch_inbox: ?Address = null,
    block_by_number_ttl_ns: u64 = 2 * std.time.ns_per_s,
    /// Memory a cache slot's arena keeps across reuse.
    retain_bytes_per_entry: usize = 1024 * 1024,
    transaction_limits: transaction_json.Limits = .{},
    receipt_limits: receipt_json.Limits = .{},
};

pub const Kind = enum(u8) { block_by_number, header_by_hash, transactions_by_hash, receipts };

pub const Request = struct {
    kind: Kind,
    number: u64 = 0,
    hash: B256 = .zero,

    pub fn eql(a: Request, b: Request) bool {
        if (a.kind != b.kind) return false;
        if (a.kind == .block_by_number) return a.number == b.number;
        return a.hash.eql(b.hash);
    }
};

pub const Stats = struct {
    requests: u64 = 0,
    failures: u64 = 0,
    /// The most recent failure, for logs.
    last_failure: ?anyerror = null,
    not_found: u64 = 0,
    dropped: u64 = 0,
};

const NumberEntry = struct { used: u64 = 0, info: BlockInfo = .{}, fetched_ns: u64 = 0 };
const HeaderEntry = struct {
    used: u64 = 0,
    info: BlockInfo = .{},
    header: L1Header = undefined,
    receipts_root: B256 = .zero,
};

fn BodyEntry(comptime T: type) type {
    return struct {
        used: u64 = 0,
        hash: B256 = .zero,
        arena: std.heap.ArenaAllocator,
        items: []const T = &.{},
    };
}

/// Least recently used slot, preferring empty ones.
fn victim(comptime Entry: type, entries: []Entry) *Entry {
    assert(entries.len > 0);
    var best = &entries[0];
    for (entries) |*entry| {
        if (entry.used == 0) return entry;
        if (entry.used < best.used) best = entry;
    }
    assert(best.used != 0);
    return best;
}

pub fn L1Provider(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);
        const TransactionsEntry = BodyEntry(L1Transaction);
        const ReceiptsEntry = BodyEntry(Receipt);

        io: *IO,
        allocator: Allocator,
        client: Rpc,
        options: Options,
        queue: [queue_size_max]Request = undefined,
        queue_head: u32 = 0,
        queue_count: u32 = 0,
        in_flight: ?Request = null,
        numbers: []NumberEntry,
        headers: []HeaderEntry,
        transactions: []TransactionsEntry,
        receipts: []ReceiptsEntry,
        missing: [missing_max]Request = undefined,
        missing_count: u32 = 0,
        scratch: std.heap.ArenaAllocator,
        clock: u64 = 0,
        stats: Stats = .{},

        /// `provider` must not move after `init` while requests are in flight.
        pub fn init(
            provider: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
            options: Options,
        ) !void {
            assert(options.cache_entries > 0 and options.cache_entries <= cache_entries_max);
            assert(options.queue_size > 0 and options.queue_size <= queue_size_max);
            assert(http_options.limits.body_size_max > 0);
            var client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            errdefer client.deinit();
            const count = options.cache_entries;
            const numbers = try allocator.alloc(NumberEntry, count);
            errdefer allocator.free(numbers);
            const headers = try allocator.alloc(HeaderEntry, count);
            errdefer allocator.free(headers);
            const transactions = try allocator.alloc(TransactionsEntry, count);
            errdefer allocator.free(transactions);
            const receipts = try allocator.alloc(ReceiptsEntry, count);
            @memset(numbers, .{});
            @memset(headers, .{});
            for (transactions) |*entry| entry.* = .{ .arena = .init(allocator) };
            for (receipts) |*entry| entry.* = .{ .arena = .init(allocator) };
            provider.* = .{
                .io = io,
                .allocator = allocator,
                .client = client,
                .options = options,
                .numbers = numbers,
                .headers = headers,
                .transactions = transactions,
                .receipts = receipts,
                .scratch = .init(allocator),
            };
        }

        pub fn deinit(provider: *Self) void {
            assert(provider.in_flight == null);
            for (provider.transactions) |*entry| entry.arena.deinit();
            for (provider.receipts) |*entry| entry.arena.deinit();
            provider.allocator.free(provider.receipts);
            provider.allocator.free(provider.transactions);
            provider.allocator.free(provider.headers);
            provider.allocator.free(provider.numbers);
            provider.scratch.deinit();
            provider.client.deinit();
            provider.* = undefined;
        }

        /// Drives request timeouts; call periodically.
        pub fn tick(provider: *Self) void {
            provider.client.http.tick();
            provider.pump();
        }

        /// True while a fetch is queued or in flight.
        pub fn busy(provider: *const Self) bool {
            return provider.in_flight != null or provider.queue_count > 0;
        }

        fn touch(provider: *Self) u64 {
            provider.clock += 1;
            assert(provider.clock != 0);
            return provider.clock;
        }

        // Chain-provider contract.

        pub fn l1_block_info_by_number(provider: *Self, number: u64) ProviderError!BlockInfo {
            const now_ns = provider.io.now_monotonic_ns();
            for (provider.numbers) |*entry| {
                if (entry.used == 0 or entry.info.number != number) continue;
                if (now_ns -| entry.fetched_ns >= provider.options.block_by_number_ttl_ns) {
                    entry.used = 0;
                    continue;
                }
                entry.used = provider.touch();
                assert(entry.info.number == number);
                return entry.info;
            }
            return provider.miss(.{ .kind = .block_by_number, .number = number });
        }

        pub fn l1_header_by_hash(provider: *Self, hash: B256) ProviderError!L1Header {
            if (provider.header_entry(hash)) |entry| return entry.header;
            return provider.miss(.{ .kind = .header_by_hash, .hash = hash });
        }

        pub fn l1_block_info_by_hash(provider: *Self, hash: B256) ProviderError!BlockInfo {
            if (provider.header_entry(hash)) |entry| return entry.info;
            return provider.miss(.{ .kind = .header_by_hash, .hash = hash });
        }

        pub fn l1_transactions_by_hash(
            provider: *Self,
            hash: B256,
        ) ProviderError![]const L1Transaction {
            for (provider.transactions) |*entry| {
                if (entry.used == 0 or !entry.hash.eql(hash)) continue;
                entry.used = provider.touch();
                return entry.items;
            }
            return provider.miss(.{ .kind = .transactions_by_hash, .hash = hash });
        }

        pub fn l1_receipts_by_hash(provider: *Self, hash: B256) ProviderError![]const Receipt {
            for (provider.receipts) |*entry| {
                if (entry.used == 0 or !entry.hash.eql(hash)) continue;
                entry.used = provider.touch();
                return entry.items;
            }
            // Receipts are verified against the header root, so fetch the header first.
            if (!provider.options.trust_rpc and provider.header_entry(hash) == null) {
                return provider.miss(.{ .kind = .header_by_hash, .hash = hash });
            }
            return provider.miss(.{ .kind = .receipts, .hash = hash });
        }

        fn header_entry(provider: *Self, hash: B256) ?*HeaderEntry {
            for (provider.headers) |*entry| {
                if (entry.used == 0 or !entry.info.hash.eql(hash)) continue;
                entry.used = provider.touch();
                assert(entry.header.hash.eql(hash));
                return entry;
            }
            return null;
        }

        /// Reports a recorded `null` result once, otherwise enqueues the fetch.
        fn miss(provider: *Self, request: Request) ProviderError {
            for (provider.missing[0..provider.missing_count], 0..) |missing, index| {
                if (!missing.eql(request)) continue;
                provider.missing_count -= 1;
                provider.missing[index] = provider.missing[provider.missing_count];
                return error.NotFound;
            }
            provider.enqueue(request);
            provider.pump();
            return error.NotAvailable;
        }

        fn enqueue(provider: *Self, request: Request) void {
            if (provider.in_flight) |current| {
                if (current.eql(request)) return;
            }
            for (0..provider.queue_count) |offset| {
                const index = (provider.queue_head + offset) % queue_size_max;
                if (provider.queue[index].eql(request)) return;
            }
            if (provider.queue_count == provider.options.queue_size) {
                provider.stats.dropped += 1;
                return;
            }
            const tail = (provider.queue_head + provider.queue_count) % queue_size_max;
            provider.queue[tail] = request;
            provider.queue_count += 1;
            assert(provider.queue_count <= provider.options.queue_size);
        }

        /// Starts the next queued request when none is in flight.
        fn pump(provider: *Self) void {
            var attempts: u32 = 0;
            while (attempts < queue_size_max) : (attempts += 1) {
                if (provider.in_flight != null or provider.queue_count == 0) return;
                if (provider.client.http.busy()) return;
                const request = provider.queue[provider.queue_head];
                provider.queue_head = (provider.queue_head + 1) % queue_size_max;
                provider.queue_count -= 1;
                provider.in_flight = request;
                provider.stats.requests += 1;
                provider.send(request) catch |err| {
                    provider.in_flight = null;
                    provider.stats.failures += 1;
                    provider.stats.last_failure = err;
                    continue;
                };
                return;
            }
        }

        fn send(provider: *Self, request: Request) !void {
            const in_flight = &provider.in_flight.?;
            assert(in_flight.eql(request));
            const method = switch (request.kind) {
                .block_by_number => "eth_getBlockByNumber",
                .header_by_hash, .transactions_by_hash => "eth_getBlockByHash",
                .receipts => "eth_getBlockReceipts",
            };
            const client = &provider.client;
            try client.call(*Self, provider, on_result, method, in_flight, write_params);
        }

        fn write_params(
            request: *const Request,
            writer: *json.Writer,
        ) json.Writer.WriteError!void {
            switch (request.kind) {
                .block_by_number => try writer.quantity(request.number),
                else => try writer.data(&request.hash.bytes),
            }
            switch (request.kind) {
                .block_by_number, .header_by_hash => try writer.boolean(false),
                .transactions_by_hash => try writer.boolean(true),
                .receipts => {},
            }
        }

        fn on_result(
            provider: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &provider.client);
            const request = provider.in_flight.?;
            provider.in_flight = null;
            defer provider.pump();
            defer _ = provider.scratch.reset(.{ .retain_with_limit = scratch_retain_bytes });
            const outcome = result catch |err| {
                provider.stats.failures += 1;
                provider.stats.last_failure = err;
                return;
            };
            const raw = switch (outcome) {
                .ok => |raw| raw,
                .rpc_error => {
                    provider.stats.failures += 1;
                    provider.stats.last_failure = error.RpcError;
                    return;
                },
            };
            if (std.mem.eql(u8, raw, "null")) return provider.record_missing(request);
            provider.complete(request, raw) catch |err| {
                provider.stats.failures += 1;
                provider.stats.last_failure = err;
            };
        }

        fn record_missing(provider: *Self, request: Request) void {
            provider.stats.not_found += 1;
            if (provider.missing_count == missing_max) {
                // Oldest first out: the pipeline asks for recent blocks.
                const missing = &provider.missing;
                std.mem.copyForwards(Request, missing[0 .. missing_max - 1], missing[1..]);
                provider.missing_count -= 1;
            }
            provider.missing[provider.missing_count] = request;
            provider.missing_count += 1;
            assert(provider.missing_count <= missing_max);
        }

        const CompleteError = header_json.DecodeError || transaction_json.Error ||
            error{BlockMismatch};

        fn complete(provider: *Self, request: Request, raw: []const u8) CompleteError!void {
            if (request.kind == .receipts) return provider.complete_receipts(request.hash, raw);
            var extra: [header_json.extra_data_size_max]u8 = undefined;
            const decoded = try header_json.decode(raw, &extra);
            switch (request.kind) {
                .block_by_number => if (decoded.header.number != request.number) {
                    return error.BlockMismatch;
                },
                else => if (!decoded.hash.eql(request.hash)) return error.BlockMismatch,
            }
            if (request.kind == .transactions_by_hash) {
                try provider.complete_transactions(&decoded, raw);
            }
            provider.store_header(&decoded);
            if (request.kind == .block_by_number) {
                const entry = victim(NumberEntry, provider.numbers);
                entry.* = .{
                    .used = provider.touch(),
                    .info = decoded.block_info(),
                    .fetched_ns = provider.io.now_monotonic_ns(),
                };
            }
        }

        fn store_header(provider: *Self, decoded: *const header_json.Decoded) void {
            if (provider.header_entry(decoded.hash) != null) return;
            const entry = victim(HeaderEntry, provider.headers);
            entry.* = .{
                .used = provider.touch(),
                .info = decoded.block_info(),
                .header = decoded.l1_header(),
                .receipts_root = decoded.header.receipts_root,
            };
            assert(entry.header.hash.eql(decoded.hash));
        }

        fn complete_transactions(
            provider: *Self,
            decoded: *const header_json.Decoded,
            raw: []const u8,
        ) CompleteError!void {
            const transactions_raw = (try header_json.transactions_raw(raw)) orelse
                return error.MissingField;
            const entry = victim(TransactionsEntry, provider.transactions);
            entry.used = 0;
            const retain = provider.options.retain_bytes_per_entry;
            _ = entry.arena.reset(.{ .retain_with_limit = retain });
            entry.items = try transaction_json.decode_block(
                entry.arena.allocator(),
                provider.scratch.allocator(),
                transactions_raw,
                decoded.header.transactions_root,
                .{
                    .limits = provider.options.transaction_limits,
                    .recover_to = provider.options.batch_inbox,
                    .verify_root = !provider.options.trust_rpc,
                },
            );
            entry.hash = decoded.hash;
            entry.used = provider.touch();
        }

        fn complete_receipts(provider: *Self, hash: B256, raw: []const u8) CompleteError!void {
            var root: ?B256 = null;
            if (!provider.options.trust_rpc) {
                const header = provider.header_entry(hash) orelse return error.MissingField;
                root = header.receipts_root;
            }
            const entry = victim(ReceiptsEntry, provider.receipts);
            entry.used = 0;
            const retain = provider.options.retain_bytes_per_entry;
            _ = entry.arena.reset(.{ .retain_with_limit = retain });
            entry.items = try receipt_json.decode_block(
                entry.arena.allocator(),
                provider.scratch.allocator(),
                raw,
                root,
                provider.options.receipt_limits,
            );
            entry.hash = hash;
            entry.used = provider.touch();
        }
    };
}

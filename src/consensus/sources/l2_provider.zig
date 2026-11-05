//! A non-blocking, caching L2 chain provider over JSON-RPC: `l2_block_info_by_number`,
//! `l2_block_info_by_hash`, `l2_block_info_by_label` and `system_config_by_l2_hash`: the L2
//! contract of the derivation pipeline (attributes builder, batch validation, reset walk-back).
//! Mirrors base/base `crates/consensus/providers/src/l2_chain_provider.rs`.
//!
//! Same discipline as `l1_provider.zig`: a miss enqueues one fetch
//! (`eth_getBlockByNumber`/`eth_getBlockByHash` with full transactions, for the L1 info
//! deposit) and returns `error.NotAvailable`; a `null` result surfaces once as
//! `error.NotFound`; failed or unverifiable responses are dropped and re-requested on the
//! next query. With `jwt_secret` every request carries a fresh bearer token.
//! Bounds: one request in flight, a fixed de-duplicating queue, fixed LRU caches.
//! Each cached block keeps only its `L2BlockInfo` and `SystemConfig`. Full safe blocks
//! (`l2_block_by_number`, raw transactions for span batch checks) live in a few slots with
//! one arena each, reused in LRU order. By-number results expire after
//! `block_by_number_ttl_ns` because unsafe L2 numbers move on reorgs; hash-keyed results are
//! immutable.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const jwt = @import("../../utilities/jwt/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../protocol/root.zig");
const errors = @import("../derive/errors.zig");
const l2_block = @import("l2_block.zig");
const l2_block_full = @import("l2_block_full.zig");
const SafeBlock = protocol.span_batch.SafeBlock;

const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const SystemConfig = protocol.system_config.SystemConfig;
const RollupConfig = protocol.rollup_config.RollupConfig;
const ProviderError = errors.ProviderError;

pub const queue_size_max = 64;
pub const cache_entries_max = 4096;
pub const missing_max = 8;
const request_size_max = 4096;

pub const Options = struct {
    cache_entries: u32 = 256,
    queue_size: u32 = 16,
    block_by_number_ttl_ns: u64 = 2 * std.time.ns_per_s,
    /// Slots for full safe blocks (`l2_block_by_number`).
    full_blocks: u32 = 8,
    /// Memory a full-block slot's arena keeps across reuse.
    full_block_retain_bytes: usize = 256 * 1024,
    full_block_limits: l2_block_full.Limits = .{},
    /// Authenticates every request with a fresh JWT (the engine endpoint serves `eth_*`).
    jwt_secret: ?jwt.Secret = null,
};

/// Labeled L2 heads (`eth_getBlockByNumber` tags).
pub const Label = enum(u8) { latest, safe, finalized };

pub const Request = union(enum) {
    number: u64,
    hash: B256,
    label: Label,
    /// A full block (raw transactions) by number.
    full: u64,

    pub fn eql(a: Request, b: Request) bool {
        return switch (a) {
            .number => |number| b == .number and b.number == number,
            .full => |number| b == .full and b.full == number,
            .hash => |hash| b == .hash and b.hash.eql(hash),
            .label => |label| b == .label and b.label == label,
        };
    }

    /// Number and label results move on reorgs, so they expire.
    fn expires(request: Request) bool {
        return request != .hash;
    }
};

pub const Stats = struct {
    requests: u64 = 0,
    failures: u64 = 0,
    not_found: u64 = 0,
    dropped: u64 = 0,
};

const BlockEntry = struct { used: u64 = 0, block: l2_block.L2Block = undefined };
/// A full safe block; `transactions` live in `arena`.
const FullEntry = struct {
    used: u64 = 0,
    number: u64 = 0,
    fetched_ns: u64 = 0,
    block: SafeBlock = .{ .transactions = &.{}, .l1_origin_number = null },
    arena: std.heap.ArenaAllocator,
};
/// A number- or label-keyed result pointing at a hash-keyed block.
const KeyEntry = struct {
    used: u64 = 0,
    key: Request = .{ .number = 0 },
    hash: B256 = .zero,
    fetched_ns: u64 = 0,
};

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

pub fn L2Provider(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);

        io: *IO,
        allocator: Allocator,
        client: Rpc,
        rollup: *const RollupConfig,
        options: Options,
        queue: [queue_size_max]Request = undefined,
        queue_head: u32 = 0,
        queue_count: u32 = 0,
        in_flight: ?Request = null,
        blocks: []BlockEntry,
        numbers: []KeyEntry,
        fulls: []FullEntry,
        missing: [missing_max]Request = undefined,
        missing_count: u32 = 0,
        clock: u64 = 0,
        stats: Stats = .{},

        /// `provider` must not move after `init` while requests are in flight.
        pub fn init(
            provider: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
            rollup: *const RollupConfig,
            options: Options,
        ) !void {
            assert(options.cache_entries > 0 and options.cache_entries <= cache_entries_max);
            assert(options.queue_size > 0 and options.queue_size <= queue_size_max);
            var client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            errdefer client.deinit();
            const blocks = try allocator.alloc(BlockEntry, options.cache_entries);
            errdefer allocator.free(blocks);
            const numbers = try allocator.alloc(KeyEntry, options.cache_entries);
            errdefer allocator.free(numbers);
            assert(options.full_blocks > 0);
            const fulls = try allocator.alloc(FullEntry, options.full_blocks);
            @memset(blocks, .{});
            @memset(numbers, .{});
            for (fulls) |*entry| entry.* = .{ .arena = .init(allocator) };
            provider.* = .{
                .io = io,
                .allocator = allocator,
                .client = client,
                .rollup = rollup,
                .options = options,
                .blocks = blocks,
                .numbers = numbers,
                .fulls = fulls,
            };
        }

        pub fn deinit(provider: *Self) void {
            assert(provider.in_flight == null);
            for (provider.fulls) |*entry| entry.arena.deinit();
            provider.allocator.free(provider.fulls);
            provider.allocator.free(provider.numbers);
            provider.allocator.free(provider.blocks);
            provider.client.deinit();
            provider.* = undefined;
        }

        /// Drives request timeouts; call periodically.
        pub fn tick(provider: *Self) void {
            provider.client.http.tick();
            provider.pump();
        }

        pub fn busy(provider: *const Self) bool {
            return provider.in_flight != null or provider.queue_count > 0;
        }

        fn touch(provider: *Self) u64 {
            provider.clock += 1;
            assert(provider.clock != 0);
            return provider.clock;
        }

        // L2 chain-provider contract.

        pub fn l2_block_info_by_number(provider: *Self, number: u64) ProviderError!L2BlockInfo {
            const info = try provider.keyed(.{ .number = number });
            assert(info.block_info.number == number);
            return info;
        }

        /// The labeled head (`latest`, `safe`, `finalized`) as the execution engine sees it.
        pub fn l2_block_info_by_label(provider: *Self, label: Label) ProviderError!L2BlockInfo {
            return provider.keyed(.{ .label = label });
        }

        fn keyed(provider: *Self, key: Request) ProviderError!L2BlockInfo {
            assert(key.expires());
            const now_ns = provider.io.now_monotonic_ns();
            for (provider.numbers) |*entry| {
                if (entry.used == 0 or !entry.key.eql(key)) continue;
                if (now_ns -| entry.fetched_ns >= provider.options.block_by_number_ttl_ns) {
                    entry.used = 0;
                    continue;
                }
                const block = provider.block_entry(entry.hash) orelse {
                    entry.used = 0; // The block was evicted; refetch.
                    continue;
                };
                entry.used = provider.touch();
                return block.block.info;
            }
            return provider.miss(key);
        }

        /// The full block `number` (raw EIP-2718 transactions, deposits first) for span batch
        /// checks against the safe chain. Borrowed until the slot is reused.
        pub fn l2_block_by_number(provider: *Self, number: u64) ProviderError!SafeBlock {
            const now_ns = provider.io.now_monotonic_ns();
            for (provider.fulls) |*entry| {
                if (entry.used == 0 or entry.number != number) continue;
                if (now_ns -| entry.fetched_ns >= provider.options.block_by_number_ttl_ns) {
                    entry.used = 0;
                    continue;
                }
                entry.used = provider.touch();
                const genesis_number = provider.rollup.genesis.l2.number;
                assert(entry.block.transactions.len > 0 or number == genesis_number);
                return entry.block;
            }
            return provider.miss(.{ .full = number });
        }

        pub fn l2_block_info_by_hash(provider: *Self, hash: B256) ProviderError!L2BlockInfo {
            if (provider.block_entry(hash)) |entry| return entry.block.info;
            return provider.miss(.{ .hash = hash });
        }

        pub fn system_config_by_l2_hash(provider: *Self, hash: B256) ProviderError!SystemConfig {
            if (provider.block_entry(hash)) |entry| return entry.block.system_config;
            return provider.miss(.{ .hash = hash });
        }

        /// The slot already holding `key`, else the least recently used one.
        fn key_slot(provider: *Self, key: Request) *KeyEntry {
            for (provider.numbers) |*entry| {
                if (entry.used != 0 and entry.key.eql(key)) return entry;
            }
            const entry = victim(KeyEntry, provider.numbers);
            assert(entry.used == 0 or !entry.key.eql(key));
            return entry;
        }

        fn block_entry(provider: *Self, hash: B256) ?*BlockEntry {
            for (provider.blocks) |*entry| {
                if (entry.used == 0 or !entry.block.info.block_info.hash.eql(hash)) continue;
                entry.used = provider.touch();
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
                const method = if (request == .hash)
                    "eth_getBlockByHash"
                else
                    "eth_getBlockByNumber";
                const in_flight = &provider.in_flight.?;
                const client = &provider.client;
                if (provider.options.jwt_secret) |secret| {
                    var token_buffer: [jwt.token_size_max]u8 = undefined;
                    const now_s = provider.io.now_realtime_ns() / std.time.ns_per_s;
                    client.set_bearer(jwt.create(secret, now_s, &token_buffer));
                }
                client.call(*Self, provider, on_result, method, in_flight, write_params) catch {
                    provider.in_flight = null;
                    provider.stats.failures += 1;
                    continue;
                };
                return;
            }
        }

        fn write_params(request: *const Request, writer: *json.Writer) json.Writer.WriteError!void {
            switch (request.*) {
                .number, .full => |number| try writer.quantity(number),
                .hash => |hash| try writer.data(&hash.bytes),
                .label => |label| try writer.string(@tagName(label)),
            }
            try writer.boolean(true);
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
            const outcome = result catch {
                provider.stats.failures += 1;
                return;
            };
            const raw = switch (outcome) {
                .ok => |raw| raw,
                .rpc_error => {
                    provider.stats.failures += 1;
                    return;
                },
            };
            if (std.mem.eql(u8, raw, "null")) return provider.record_missing(request);
            provider.complete(request, raw) catch {
                provider.stats.failures += 1;
            };
        }

        fn record_missing(provider: *Self, request: Request) void {
            provider.stats.not_found += 1;
            if (provider.missing_count == missing_max) {
                const missing = &provider.missing;
                std.mem.copyForwards(Request, missing[0 .. missing_max - 1], missing[1..]);
                provider.missing_count -= 1;
            }
            provider.missing[provider.missing_count] = request;
            provider.missing_count += 1;
            assert(provider.missing_count <= missing_max);
        }

        fn complete_full(provider: *Self, number: u64, raw: []const u8) !void {
            const entry = victim(FullEntry, provider.fulls);
            entry.used = 0;
            const retain = provider.options.full_block_retain_bytes;
            _ = entry.arena.reset(.{ .retain_with_limit = retain });
            const genesis = &provider.rollup.genesis;
            const limits = provider.options.full_block_limits;
            const block = try l2_block_full.decode(entry.arena.allocator(), raw, genesis, limits);
            if (block.info.block_info.number != number) return error.BlockMismatch;
            const genesis_number = genesis.l2.number;
            entry.* = .{
                .used = provider.touch(),
                .number = number,
                .fetched_ns = provider.io.now_monotonic_ns(),
                .block = .{
                    .transactions = block.transactions,
                    .l1_origin_number = block.info.l1_origin.number,
                },
                .arena = entry.arena,
            };
            assert(number == genesis_number or entry.block.transactions.len > 0);
        }

        fn complete(provider: *Self, request: Request, raw: []const u8) !void {
            if (request == .full) return provider.complete_full(request.full, raw);
            const block = try l2_block.decode_with_system_config(raw, provider.rollup);
            const info = block.info.block_info;
            switch (request) {
                .number => |number| if (info.number != number) return error.BlockMismatch,
                .hash => |hash| if (!info.hash.eql(hash)) return error.BlockMismatch,
                .label => {},
                .full => unreachable, // Handled by `complete_full`.
            }
            if (provider.block_entry(info.hash) == null) {
                const entry = victim(BlockEntry, provider.blocks);
                entry.* = .{ .used = provider.touch(), .block = block };
            }
            if (request.expires()) {
                const entry = provider.key_slot(request);
                entry.* = .{
                    .used = provider.touch(),
                    .key = request,
                    .hash = info.hash,
                    .fetched_ns = provider.io.now_monotonic_ns(),
                };
            }
            assert(provider.block_entry(info.hash) != null);
        }
    };
}

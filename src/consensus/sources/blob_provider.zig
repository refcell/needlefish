//! A non-blocking, caching beacon blob provider implementing the derivation blob-provider
//! contract: `blobs(block, hashes)` answers from the cache or enqueues one fetch and
//! returns `error.NotAvailable`.
//!
//! The provider learns the beacon genesis time (`/eth/v1/beacon/genesis`) and slot length
//! (`/eth/v1/config/spec`, or an override) on first use, maps the L1 block timestamp to
//! its slot, and fetches `/eth/v1/beacon/blobs/{slot}?versioned_hashes=...` (base/base)
//! or `/eth/v1/beacon/blob_sidecars/{slot}`. Returned blobs are matched to the requested
//! versioned hashes by recomputing each blob's KZG commitment (blobs endpoint), or by the
//! sidecar's commitment plus a KZG proof check (sidecars endpoint); the result keeps the
//! request order. A 404 means the slot was missed or orphaned: it surfaces once as
//! `error.BlobsUnavailable`, which resets the pipeline. Other failures (transport, bad
//! JSON, a missing or invalid blob) drop the fetch; the next call retries.
//!
//! Bounds: one request in flight, a fixed queue with de-duplication by block hash, at most
//! `blobs_per_block_max` blobs per block, and an LRU cache of `cache_entries` blocks whose
//! blobs live in per-slot arenas. Mirrors base/base `OnlineBeaconClient` and
//! `OnlineBlobProvider`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const http_client = @import("../../utilities/http/client.zig");
const parser = @import("../../utilities/http/parser.zig");
const primitives = @import("../../common/primitives/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const protocol = @import("../protocol/root.zig");
const errors = @import("../derive/errors.zig");
const beacon_json = @import("beacon_json.zig");

const B256 = primitives.B256;
const BlockInfo = protocol.block.BlockInfo;
const ProviderError = errors.ProviderError;
const Blob = beacon_json.Blob;
const Sidecar = beacon_json.Sidecar;

pub const queue_size_max = 32;
pub const unavailable_max = 8;
/// Upper bound for `Options.blobs_per_block_max`.
pub const blobs_per_block_limit = 1024;

pub const Endpoint = enum { blobs, blob_sidecars };

pub const Options = struct {
    endpoint: Endpoint = .blobs,
    cache_entries: u32 = 8,
    queue_size: u32 = 8,
    blobs_per_block_max: u32 = 128,
    /// Skips `/eth/v1/config/spec` (base/base `l1_slot_duration` override).
    seconds_per_slot: ?u64 = null,
    retain_bytes_per_entry: usize = 8 * bytes_per_blob,
};

const bytes_per_blob = kzg.bytes_per_blob;

/// Verifies blobs with the KZG trusted setup. `settings` and `workspace` are large
/// (about 1 MiB together) and owned by the caller.
pub const KzgVerifier = struct {
    settings: *const kzg.blob.Settings,
    workspace: *kzg.blob.Workspace,

    /// `blob_to_kzg_commitment(blob)`; null for invalid blobs.
    pub fn blob_commitment(verifier: KzgVerifier, blob: *const Blob) ?[kzg.bytes_per_commitment]u8 {
        return kzg.blob.blob_to_kzg_commitment(
            verifier.settings,
            verifier.workspace,
            blob,
        ) catch null;
    }

    /// `kzg_to_versioned_hash(blob_to_kzg_commitment(blob))`; null for invalid blobs.
    pub fn blob_versioned_hash(verifier: KzgVerifier, blob: *const Blob) ?B256 {
        const commitment = kzg.blob.blob_to_kzg_commitment(
            verifier.settings,
            verifier.workspace,
            blob,
        ) catch return null;
        return .init(kzg.versioned_hash(&commitment));
    }

    pub fn sidecar_valid(verifier: KzgVerifier, blob: *const Blob, sidecar: *const Sidecar) bool {
        return kzg.blob.verify_blob_kzg_proof(
            verifier.settings,
            verifier.workspace,
            blob,
            &sidecar.commitment,
            &sidecar.proof,
        ) catch false;
    }
};

pub const Stats = struct {
    requests: u64 = 0,
    failures: u64 = 0,
    unavailable: u64 = 0,
    dropped: u64 = 0,
};

/// Maps an L1 timestamp to its beacon slot; null before genesis. Matches base/base
/// `(timestamp - genesis) / interval`.
pub fn slot_of(timestamp: u64, genesis_time: u64, seconds_per_slot: u64) ?u64 {
    assert(seconds_per_slot > 0);
    if (timestamp < genesis_time) return null;
    const slot = (timestamp - genesis_time) / seconds_per_slot;
    assert(slot <= timestamp);
    return slot;
}

pub fn BlobProvider(comptime IO: type, comptime Verifier: type) type {
    return struct {
        const Self = @This();
        pub const Http = http_client.Client(IO);

        const Fetch = struct {
            block_hash: B256,
            timestamp: u64,
            hashes: []B256,
            count: u32,

            fn requested(fetch: *const Fetch) []const B256 {
                return fetch.hashes[0..fetch.count];
            }
        };

        const Entry = struct {
            used: u64 = 0,
            block_hash: B256 = .zero,
            arena: std.heap.ArenaAllocator,
            hashes: []const B256 = &.{},
            blobs: []const *const Blob = &.{},
        };

        const InFlight = union(enum) { genesis, spec, fetch: u32 };

        io: *IO,
        allocator: Allocator,
        http: Http,
        verifier: Verifier,
        options: Options,
        genesis_time: ?u64 = null,
        seconds_per_slot: ?u64,
        /// Queue slots; `queue_order` holds indexes into `fetches`, FIFO.
        fetches: []Fetch,
        queue_order: [queue_size_max]u32 = undefined,
        queue_count: u32 = 0,
        in_flight: ?InFlight = null,
        /// The fetch in flight (removed from the queue).
        current: Fetch,
        entries: []Entry,
        unavailable: [unavailable_max]B256 = undefined,
        unavailable_count: u32 = 0,
        target: []u8,
        clock: u64 = 0,
        stats: Stats = .{},

        /// `provider` must not move afterwards while requests are in flight.
        pub fn init(
            provider: *Self,
            allocator: Allocator,
            io: *IO,
            address: http_client.Address,
            http_options: http_client.Options,
            verifier: Verifier,
            options: Options,
        ) !void {
            assert(options.queue_size > 0 and options.queue_size <= queue_size_max);
            assert(options.cache_entries > 0 and options.blobs_per_block_max > 0);
            assert(options.blobs_per_block_max <= blobs_per_block_limit);
            var http = try Http.init(allocator, io, address, http_options);
            errdefer http.deinit();
            const hashes_max = options.blobs_per_block_max;
            // The fetch slots and the in-flight copy share one hash buffer.
            const hashes = try allocator.alloc(B256, (options.queue_size + 1) * hashes_max);
            errdefer allocator.free(hashes);
            const fetches = try allocator.alloc(Fetch, options.queue_size);
            errdefer allocator.free(fetches);
            for (fetches, 0..) |*fetch, index| {
                const slice = hashes[index * hashes_max ..][0..hashes_max];
                fetch.* = .{ .block_hash = .zero, .timestamp = 0, .hashes = slice, .count = 0 };
            }
            const current_hashes = hashes[options.queue_size * hashes_max ..][0..hashes_max];
            const entries = try allocator.alloc(Entry, options.cache_entries);
            errdefer allocator.free(entries);
            for (entries) |*entry| entry.* = .{ .arena = .init(allocator) };
            // Target: path, slot, and a comma-separated list of 0x-prefixed hashes.
            const target = try allocator.alloc(u8, 128 + hashes_max * 67);
            provider.* = .{
                .io = io,
                .allocator = allocator,
                .http = http,
                .verifier = verifier,
                .options = options,
                .seconds_per_slot = options.seconds_per_slot,
                .fetches = fetches,
                .current = .{
                    .block_hash = .zero,
                    .timestamp = 0,
                    .hashes = current_hashes,
                    .count = 0,
                },
                .entries = entries,
                .target = target,
            };
        }

        pub fn deinit(provider: *Self) void {
            assert(provider.in_flight == null);
            for (provider.entries) |*entry| entry.arena.deinit();
            const hashes_max = provider.options.blobs_per_block_max;
            const hashes_total = (provider.options.queue_size + 1) * hashes_max;
            provider.allocator.free(provider.fetches[0].hashes.ptr[0..hashes_total]);
            provider.allocator.free(provider.fetches);
            provider.allocator.free(provider.entries);
            provider.allocator.free(provider.target);
            provider.http.deinit();
            provider.* = undefined;
        }

        pub fn tick(provider: *Self) void {
            provider.http.tick();
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

        /// Blob-provider contract. The returned slice stays valid until the entry is evicted
        /// (at least until the next call).
        pub fn blobs(
            provider: *Self,
            block: BlockInfo,
            hashes: []const B256,
        ) ProviderError![]const *const Blob {
            if (hashes.len == 0) return &.{};
            if (hashes.len > provider.options.blobs_per_block_max) return error.OutOfMemory;
            for (provider.entries) |*entry| {
                if (entry.used == 0 or !entry.block_hash.eql(block.hash)) continue;
                if (!hashes_equal(entry.hashes, hashes)) continue;
                entry.used = provider.touch();
                assert(entry.blobs.len == hashes.len);
                return entry.blobs;
            }
            for (provider.unavailable[0..provider.unavailable_count], 0..) |hash, index| {
                if (!hash.eql(block.hash)) continue;
                provider.unavailable_count -= 1;
                provider.unavailable[index] = provider.unavailable[provider.unavailable_count];
                return error.BlobsUnavailable;
            }
            provider.enqueue(block, hashes);
            provider.pump();
            return error.NotAvailable;
        }

        fn hashes_equal(a: []const B256, b: []const B256) bool {
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!x.eql(y)) return false;
            return true;
        }

        fn enqueue(provider: *Self, block: BlockInfo, hashes: []const B256) void {
            assert(hashes.len <= provider.options.blobs_per_block_max);
            if (provider.in_flight) |in_flight| {
                if (in_flight == .fetch and provider.current.block_hash.eql(block.hash)) return;
            }
            for (provider.queue_order[0..provider.queue_count]) |index| {
                if (provider.fetches[index].block_hash.eql(block.hash)) return;
            }
            if (provider.queue_count == provider.options.queue_size) {
                provider.stats.dropped += 1;
                return;
            }
            const free = provider.free_slot();
            const fetch = &provider.fetches[free];
            fetch.block_hash = block.hash;
            fetch.timestamp = block.timestamp;
            fetch.count = @intCast(hashes.len);
            @memcpy(fetch.hashes[0..hashes.len], hashes);
            provider.queue_order[provider.queue_count] = free;
            provider.queue_count += 1;
        }

        fn free_slot(provider: *const Self) u32 {
            assert(provider.queue_count < provider.options.queue_size);
            for (0..provider.options.queue_size) |slot| {
                const used = for (provider.queue_order[0..provider.queue_count]) |index| {
                    if (index == slot) break true;
                } else false;
                if (!used) return @intCast(slot);
            }
            unreachable; // Fewer queued fetches than slots.
        }

        fn pump(provider: *Self) void {
            var attempts: u32 = 0;
            while (attempts < queue_size_max + 2) : (attempts += 1) {
                if (provider.in_flight != null or provider.queue_count == 0) return;
                if (provider.http.busy()) return;
                const next: InFlight = if (provider.genesis_time == null)
                    .genesis
                else if (provider.seconds_per_slot == null)
                    .spec
                else
                    .{ .fetch = provider.dequeue() };
                provider.in_flight = next;
                provider.stats.requests += 1;
                provider.send(next) catch {
                    provider.in_flight = null;
                    provider.stats.failures += 1;
                    continue;
                };
                return;
            }
        }

        fn dequeue(provider: *Self) u32 {
            assert(provider.queue_count > 0);
            const index = provider.queue_order[0];
            const order = provider.queue_order[0..provider.queue_count];
            std.mem.copyForwards(u32, order[0 .. order.len - 1], order[1..]);
            provider.queue_count -= 1;
            const fetch = &provider.fetches[index];
            provider.current.block_hash = fetch.block_hash;
            provider.current.timestamp = fetch.timestamp;
            provider.current.count = fetch.count;
            @memcpy(provider.current.hashes[0..fetch.count], fetch.requested());
            return index;
        }

        fn send(provider: *Self, in_flight: InFlight) !void {
            const target = switch (in_flight) {
                .genesis => "/eth/v1/beacon/genesis",
                .spec => "/eth/v1/config/spec",
                .fetch => try provider.fetch_target(),
            };
            const headers = [_]parser.Header{.{ .name = "Accept", .value = "application/json" }};
            try provider.http.request(*Self, provider, on_http, .GET, target, &headers, "");
        }

        fn fetch_target(provider: *Self) ![]const u8 {
            const fetch = &provider.current;
            const slot = slot_of(
                fetch.timestamp,
                provider.genesis_time.?,
                provider.seconds_per_slot.?,
            ) orelse return error.InvalidSlot;
            var writer: std.Io.Writer = .fixed(provider.target);
            switch (provider.options.endpoint) {
                .blob_sidecars => try writer.print("/eth/v1/beacon/blob_sidecars/{d}", .{slot}),
                .blobs => {
                    try writer.print("/eth/v1/beacon/blobs/{d}?versioned_hashes=", .{slot});
                    for (fetch.requested(), 0..) |hash, index| {
                        if (index > 0) try writer.writeByte(',');
                        try writer.print("0x{x}", .{&hash.bytes});
                    }
                },
            }
            return writer.buffered();
        }

        fn on_http(
            provider: *Self,
            http: *Http,
            result: http_client.Error!*const parser.Response,
        ) void {
            assert(http == &provider.http);
            const in_flight = provider.in_flight.?;
            provider.in_flight = null;
            defer provider.pump();
            const response = result catch {
                provider.stats.failures += 1;
                return;
            };
            provider.complete(in_flight, response) catch {
                provider.stats.failures += 1;
            };
        }

        const CompleteError = beacon_json.Error || error{ HttpStatus, BlobNotFound };

        fn complete(
            provider: *Self,
            in_flight: InFlight,
            response: *const parser.Response,
        ) CompleteError!void {
            if (in_flight == .fetch and response.status == 404) {
                return provider.record_unavailable(provider.current.block_hash);
            }
            if (response.status != 200) return error.HttpStatus;
            switch (in_flight) {
                .genesis => {
                    provider.genesis_time = try beacon_json.decode_genesis_time(response.body);
                },
                .spec => {
                    const body = response.body;
                    provider.seconds_per_slot = try beacon_json.decode_seconds_per_slot(body);
                },
                .fetch => try provider.complete_fetch(response.body),
            }
        }

        fn record_unavailable(provider: *Self, block_hash: B256) void {
            provider.stats.unavailable += 1;
            if (provider.unavailable_count == unavailable_max) {
                const list = &provider.unavailable;
                std.mem.copyForwards(B256, list[0 .. unavailable_max - 1], list[1..]);
                provider.unavailable_count -= 1;
            }
            provider.unavailable[provider.unavailable_count] = block_hash;
            provider.unavailable_count += 1;
            assert(provider.unavailable_count <= unavailable_max);
        }

        fn victim(provider: *Self) *Entry {
            var best = &provider.entries[0];
            for (provider.entries) |*entry| {
                if (entry.used == 0) return entry;
                if (entry.used < best.used) best = entry;
            }
            assert(best.used != 0);
            return best;
        }

        fn complete_fetch(provider: *Self, body: []const u8) CompleteError!void {
            const fetch = &provider.current;
            const count = try beacon_json.data_count(body, provider.options.blobs_per_block_max);
            const entry = provider.victim();
            entry.used = 0;
            const retain = provider.options.retain_bytes_per_entry;
            _ = entry.arena.reset(.{ .retain_with_limit = retain });
            const arena = entry.arena.allocator();
            const decoded = try arena.alloc(Blob, count);
            const matched = try arena.alloc(*const Blob, fetch.count);
            switch (provider.options.endpoint) {
                .blobs => {
                    try beacon_json.decode_blobs(body, decoded);
                    try provider.match_blobs(decoded, matched);
                },
                .blob_sidecars => {
                    const sidecars = try arena.alloc(Sidecar, count);
                    try beacon_json.decode_sidecars(body, decoded, sidecars);
                    try provider.match_sidecars(decoded, sidecars, matched);
                },
            }
            const hashes = try arena.dupe(B256, fetch.requested());
            entry.* = .{
                .used = provider.touch(),
                .block_hash = fetch.block_hash,
                .arena = entry.arena,
                .hashes = hashes,
                .blobs = matched,
            };
        }

        /// Recomputes each returned blob's versioned hash and picks one per requested hash.
        fn match_blobs(
            provider: *Self,
            decoded: []const Blob,
            matched: []*const Blob,
        ) CompleteError!void {
            const requested = provider.current.requested();
            assert(matched.len == requested.len);
            var filled: [blobs_per_block_limit]bool = undefined;
            assert(requested.len <= filled.len);
            @memset(filled[0..requested.len], false);
            for (decoded) |*blob| {
                const hash = provider.verifier.blob_versioned_hash(blob) orelse continue;
                for (requested, matched, filled[0..requested.len]) |want, *slot, *done| {
                    if (done.* or !want.eql(hash)) continue;
                    slot.* = blob;
                    done.* = true;
                }
            }
            for (filled[0..requested.len]) |done| if (!done) return error.BlobNotFound;
        }

        /// Picks sidecars by commitment hash, then checks each picked sidecar's KZG proof.
        fn match_sidecars(
            provider: *Self,
            decoded: []const Blob,
            sidecars: []const Sidecar,
            matched: []*const Blob,
        ) CompleteError!void {
            const requested = provider.current.requested();
            assert(matched.len == requested.len);
            for (requested, matched) |want, *slot| {
                const index = for (sidecars, 0..) |*sidecar, index| {
                    const hash: B256 = .init(kzg.versioned_hash(&sidecar.commitment));
                    if (hash.eql(want)) break index;
                } else return error.BlobNotFound;
                if (!provider.verifier.sidecar_valid(&decoded[index], &sidecars[index])) {
                    return error.BlobNotFound;
                }
                slot.* = &decoded[index];
            }
        }
    };
}

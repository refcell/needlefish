//! `base derive-check` providers for the derivation pipeline, over blocking HTTPS endpoints:
//! - `L1Source`: L1 blocks, transactions, and receipts (chain-provider contract). Headers
//!   must hash to the block hash, transactions and receipts must match the header roots,
//!   and batch-inbox senders are recovered from signatures. Hash-keyed LRU cache.
//! - `BlobSource`: blobs from the beacon API, each matched to its versioned hash by
//!   recomputing its KZG commitment.
//! - `L2Chain`: the safe L2 chain the pipeline builds on. Blocks the check has verified are
//!   inserted by the driver; older blocks (the reset walk-back) come from the reference
//!   node, preloaded in batches. Blocks above the safe head are never served.
//!
//! The pipeline's providers must not block in a node; this one-shot check runs the
//! pipeline on a single thread, so a provider simply waits for its fetch. A fetch that keeps
//! failing surfaces as `error.NotAvailable` and the driver backs off.

const std = @import("std");
const base = @import("base");

const net = @import("derive_check_net.zig");
const sources = base.consensus.sources;
const protocol = base.consensus.protocol;
const derive = base.consensus.derive;
const primitives = base.common.primitives;
const kzg = base.common.crypto.kzg;
const assert = std.debug.assert;

const Address = primitives.Address;
const B256 = primitives.B256;
const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const L1Header = protocol.l1_info.L1Header;
const Receipt = protocol.log.Receipt;
const SystemConfig = protocol.system_config.SystemConfig;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SafeBlock = protocol.span_batch.SafeBlock;
const L1Transaction = derive.providers.L1Transaction;
const ProviderError = derive.errors.ProviderError;
const Blob = derive.blob.Blob;
const Endpoint = net.Endpoint;

/// Decode attempts of one response before the provider reports `NotAvailable`.
const decode_attempts_max = 3;
const scratch_retain_bytes = 16 * 1024 * 1024;

fn print_failure(name: []const u8, what: []const u8, err: anyerror) void {
    std.debug.print("  {s}: {s}: {t}\n", .{ name, what, err });
}

pub const L1Source = struct {
    endpoint: *Endpoint,
    allocator: std.mem.Allocator,
    batch_inbox: Address,
    entries: []Entry,
    scratch: std.heap.ArenaAllocator,
    clock: u64 = 0,
    blocks_fetched: u64 = 0,
    receipts_fetched: u64 = 0,

    pub const entries_max = 256;

    const Entry = struct {
        used: u64 = 0,
        info: BlockInfo = .{},
        header: L1Header = undefined,
        receipts_root: B256 = .zero,
        transactions: []const L1Transaction = &.{},
        receipts: ?[]const Receipt = null,
        arena: std.heap.ArenaAllocator,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: *Endpoint,
        batch_inbox: Address,
        entries: u32,
    ) !L1Source {
        assert(entries > 0 and entries <= entries_max);
        const slots = try allocator.alloc(Entry, entries);
        for (slots) |*entry| entry.* = .{ .arena = .init(allocator) };
        return .{
            .endpoint = endpoint,
            .allocator = allocator,
            .batch_inbox = batch_inbox,
            .entries = slots,
            .scratch = .init(allocator),
        };
    }

    pub fn deinit(source: *L1Source) void {
        for (source.entries) |*entry| entry.arena.deinit();
        source.allocator.free(source.entries);
        source.scratch.deinit();
        source.* = undefined;
    }

    fn touch(source: *L1Source) u64 {
        source.clock += 1;
        assert(source.clock != 0);
        return source.clock;
    }

    pub fn l1_block_info_by_number(source: *L1Source, number: u64) ProviderError!BlockInfo {
        var params: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{number}) catch unreachable;
        const entry = try source.load("eth_getBlockByNumber", text, .{ .number = number });
        assert(entry.info.number == number);
        return entry.info;
    }

    pub fn l1_block_info_by_hash(source: *L1Source, hash: B256) ProviderError!BlockInfo {
        return (try source.entry_for(hash)).info;
    }

    pub fn l1_header_by_hash(source: *L1Source, hash: B256) ProviderError!L1Header {
        return (try source.entry_for(hash)).header;
    }

    pub fn l1_transactions_by_hash(
        source: *L1Source,
        hash: B256,
    ) ProviderError![]const L1Transaction {
        return (try source.entry_for(hash)).transactions;
    }

    pub fn l1_receipts_by_hash(source: *L1Source, hash: B256) ProviderError![]const Receipt {
        const entry = try source.entry_for(hash);
        if (entry.receipts) |receipts| return receipts;
        var params: [80]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\"]", .{&hash.bytes}) catch unreachable;
        for (0..decode_attempts_max) |_| {
            const raw = source.endpoint.call("eth_getBlockReceipts", text) catch |err| {
                print_failure(source.endpoint.name, "receipts", err);
                return error.NotAvailable;
            } orelse return error.NotFound;
            defer _ = source.scratch.reset(.{ .retain_with_limit = scratch_retain_bytes });
            const receipts = sources.receipt_json.decode_block(
                entry.arena.allocator(),
                source.scratch.allocator(),
                raw,
                entry.receipts_root,
                .{},
            ) catch |err| {
                print_failure(source.endpoint.name, "receipts decode", err);
                continue;
            };
            source.receipts_fetched += 1;
            entry.receipts = receipts;
            assert(entry.info.hash.eql(hash));
            return receipts;
        }
        return error.NotAvailable;
    }

    fn entry_for(source: *L1Source, hash: B256) ProviderError!*Entry {
        for (source.entries) |*entry| {
            if (entry.used == 0 or !entry.info.hash.eql(hash)) continue;
            entry.used = source.touch();
            return entry;
        }
        var params: [80]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{&hash.bytes}) catch
            unreachable;
        return source.load("eth_getBlockByHash", text, .{ .hash = hash });
    }

    const Expect = union(enum) { number: u64, hash: B256 };

    /// Fetches a full block, verifies it, and caches it.
    fn load(
        source: *L1Source,
        method: []const u8,
        params: []const u8,
        expect: Expect,
    ) ProviderError!*Entry {
        for (0..decode_attempts_max) |_| {
            const raw = source.endpoint.call(method, params) catch |err| {
                print_failure(source.endpoint.name, method, err);
                return error.NotAvailable;
            } orelse return error.NotFound;
            defer _ = source.scratch.reset(.{ .retain_with_limit = scratch_retain_bytes });
            return source.store(raw, expect) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                print_failure(source.endpoint.name, "block decode", err);
                continue;
            };
        }
        return error.NotAvailable;
    }

    fn store(source: *L1Source, raw: []const u8, expect: Expect) !*Entry {
        var extra: [sources.header_json.extra_data_size_max]u8 = undefined;
        const decoded = try sources.header_json.decode(raw, &extra);
        switch (expect) {
            .number => |number| if (decoded.header.number != number) return error.BlockMismatch,
            .hash => |hash| if (!decoded.hash.eql(hash)) return error.BlockMismatch,
        }
        for (source.entries) |*entry| {
            if (entry.used != 0 and entry.info.hash.eql(decoded.hash)) return entry;
        }
        const transactions_raw = (try sources.header_json.transactions_raw(raw)) orelse
            return error.MissingField;
        const entry = victim(source.entries);
        entry.used = 0;
        _ = entry.arena.reset(.{ .retain_with_limit = 4 * 1024 * 1024 });
        entry.receipts = null;
        entry.transactions = try sources.transaction_json.decode_block(
            entry.arena.allocator(),
            source.scratch.allocator(),
            transactions_raw,
            decoded.header.transactions_root,
            .{ .recover_to = source.batch_inbox, .verify_root = true },
        );
        entry.info = decoded.block_info();
        entry.header = decoded.l1_header();
        entry.receipts_root = decoded.header.receipts_root;
        entry.used = source.touch();
        source.blocks_fetched += 1;
        assert(entry.header.hash.eql(decoded.hash));
        return entry;
    }

    fn victim(entries: []Entry) *Entry {
        var best = &entries[0];
        for (entries) |*entry| {
            if (entry.used == 0) return entry;
            if (entry.used < best.used) best = entry;
        }
        assert(best.used != 0);
        return best;
    }
};

pub const BlobSource = struct {
    endpoint: *Endpoint,
    settings: *const kzg.blob.Settings,
    workspace: *kzg.blob.Workspace,
    genesis_time: u64,
    seconds_per_slot: u64,
    fetched: []Blob,
    pointers: []*const Blob,
    blocks: u64 = 0,
    blobs_fetched: u64 = 0,

    pub const blobs_max = 64;

    /// Learns the beacon genesis time and slot length; `fetched` holds `blobs_max` blobs.
    pub fn init(
        endpoint: *Endpoint,
        settings: *const kzg.blob.Settings,
        workspace: *kzg.blob.Workspace,
        fetched: []Blob,
        pointers: []*const Blob,
    ) !BlobSource {
        assert(fetched.len == blobs_max and pointers.len == blobs_max);
        const genesis = try endpoint.get("/eth/v1/beacon/genesis");
        const genesis_time = try sources.beacon_json.decode_genesis_time(genesis);
        const spec = try endpoint.get("/eth/v1/config/spec");
        const seconds_per_slot = try sources.beacon_json.decode_seconds_per_slot(spec);
        return .{
            .endpoint = endpoint,
            .settings = settings,
            .workspace = workspace,
            .genesis_time = genesis_time,
            .seconds_per_slot = seconds_per_slot,
            .fetched = fetched,
            .pointers = pointers,
        };
    }

    /// The blobs of `block` with `hashes`, in request order.
    pub fn blobs(
        source: *BlobSource,
        block: BlockInfo,
        hashes: []const B256,
    ) ProviderError![]const *const Blob {
        assert(hashes.len > 0);
        if (hashes.len > blobs_max) return error.BlobsUnavailable;
        if (block.timestamp < source.genesis_time) return error.BlobsUnavailable;
        const slot = (block.timestamp - source.genesis_time) / source.seconds_per_slot;
        var path_buffer: [128 + blobs_max * 67]u8 = undefined;
        var path: std.Io.Writer = .fixed(&path_buffer);
        path.print("/eth/v1/beacon/blobs/{d}?versioned_hashes=", .{slot}) catch unreachable;
        for (hashes, 0..) |hash, index| {
            if (index > 0) path.writeByte(',') catch unreachable;
            path.print("0x{x}", .{&hash.bytes}) catch unreachable;
        }
        for (0..decode_attempts_max) |_| {
            const raw = source.endpoint.get(path.buffered()) catch |err| {
                if (err == error.NotFound) return error.BlobsUnavailable; // Missed slot.
                print_failure(source.endpoint.name, "blobs", err);
                return error.NotAvailable;
            };
            if (source.match(raw, hashes)) |matched| {
                source.blocks += 1;
                source.blobs_fetched += hashes.len;
                return matched;
            } else |err| print_failure(source.endpoint.name, "blobs decode", err);
        }
        return error.NotAvailable;
    }

    /// Decodes the response and orders the blobs by the requested versioned hashes.
    fn match(source: *BlobSource, raw: []const u8, hashes: []const B256) ![]const *const Blob {
        const count = try sources.beacon_json.data_count(raw, blobs_max);
        if (count < hashes.len) return error.BlobsMissing;
        try sources.beacon_json.decode_blobs(raw, source.fetched[0..count]);
        var versioned: [blobs_max]B256 = undefined;
        for (source.fetched[0..count], versioned[0..count]) |*blob, *hash| {
            const commitment = try kzg.blob.blob_to_kzg_commitment(
                source.settings,
                source.workspace,
                blob,
            );
            hash.* = .init(kzg.versioned_hash(&commitment));
        }
        for (hashes, source.pointers[0..hashes.len]) |wanted, *pointer| {
            const index = for (versioned[0..count], 0..) |hash, index| {
                if (hash.eql(wanted)) break index;
            } else return error.BlobsMissing;
            pointer.* = &source.fetched[index];
        }
        assert(hashes.len <= count);
        return source.pointers[0..hashes.len];
    }
};

pub const L2Chain = struct {
    endpoint: *Endpoint,
    rollup: *const RollupConfig,
    /// Ring indexed by `number % entries.len`.
    entries: []Entry,
    /// The safe head: nothing above it is served.
    head: u64 = 0,
    /// Memory of the last `l2_block_by_number` result.
    full_arena: std.heap.ArenaAllocator,
    reference_fetches: u64 = 0,

    pub const entries_max = 1 << 16;

    const Entry = struct {
        present: bool = false,
        info: L2BlockInfo = .{},
        config: SystemConfig = .{},
    };

    pub fn init(
        allocator: std.mem.Allocator,
        endpoint: *Endpoint,
        rollup: *const RollupConfig,
        entries: u32,
    ) !L2Chain {
        assert(entries > 0 and entries <= entries_max);
        const slots = try allocator.alloc(Entry, entries);
        @memset(slots, .{});
        return .{
            .endpoint = endpoint,
            .rollup = rollup,
            .entries = slots,
            .full_arena = .init(allocator),
        };
    }

    pub fn deinit(chain: *L2Chain, allocator: std.mem.Allocator) void {
        allocator.free(chain.entries);
        chain.full_arena.deinit();
        chain.* = undefined;
    }

    /// Records a safe block. Blocks more than a ring length below the head are not kept.
    pub fn insert(chain: *L2Chain, info: L2BlockInfo, config: SystemConfig) void {
        const number = info.block_info.number;
        if (number + chain.entries.len <= chain.head) return;
        const slot = &chain.entries[number % chain.entries.len];
        if (slot.present and slot.info.block_info.number > number) return;
        slot.* = .{ .present = true, .info = info, .config = config };
        assert(chain.entries[number % chain.entries.len].info.block_info.number == number);
    }

    /// Moves the safe head; the block must be stored.
    pub fn set_head(chain: *L2Chain, number: u64) void {
        chain.head = number;
        assert(chain.slot_of(number) != null);
    }

    fn slot_of(chain: *L2Chain, number: u64) ?*Entry {
        const slot = &chain.entries[number % chain.entries.len];
        if (!slot.present or slot.info.block_info.number != number) return null;
        return slot;
    }

    fn by_hash(chain: *L2Chain, hash: B256) ProviderError!*const Entry {
        const scanned = @min(chain.entries.len, chain.head + 1);
        for (0..scanned) |offset| {
            const slot = chain.slot_of(chain.head - offset) orelse continue;
            if (slot.info.block_info.hash.eql(hash)) return slot;
        }
        var params: [80]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{&hash.bytes}) catch
            unreachable;
        const block = try chain.fetch("eth_getBlockByHash", text);
        if (!block.info.block_info.hash.eql(hash)) return error.NotAvailable;
        if (block.info.block_info.number > chain.head) return error.NotFound;
        chain.insert(block.info, block.system_config);
        return chain.slot_of(block.info.block_info.number) orelse error.NotFound;
    }

    fn fetch(
        chain: *L2Chain,
        method: []const u8,
        params: []const u8,
    ) ProviderError!sources.l2_block.L2Block {
        for (0..decode_attempts_max) |_| {
            const raw = chain.endpoint.call(method, params) catch |err| {
                print_failure(chain.endpoint.name, method, err);
                return error.NotAvailable;
            } orelse return error.NotFound;
            chain.reference_fetches += 1;
            return sources.l2_block.decode_with_system_config(raw, chain.rollup) catch |err| {
                print_failure(chain.endpoint.name, "l2 block decode", err);
                continue;
            };
        }
        return error.NotAvailable;
    }

    /// Loads canonical blocks `first ..< first + count` from the reference in one batch and
    /// checks that they link to each other and to a stored child. Returns block `first`.
    pub fn preload(chain: *L2Chain, first: u64, count: u32) ProviderError!L2BlockInfo {
        assert(count > 0 and count <= net.batch_max);
        var params_text: [net.batch_max][48]u8 = undefined;
        var params: [net.batch_max][]const u8 = undefined;
        for (params[0..count], params_text[0..count], 0..) |*param, *text, offset| {
            param.* = std.fmt.bufPrint(text, "[\"0x{x}\",true]", .{first + offset}) catch
                unreachable;
        }
        var results: [net.batch_max]?[]const u8 = undefined;
        const method = "eth_getBlockByNumber";
        chain.endpoint.call_batch(method, params[0..count], results[0..count]) catch |err| {
            print_failure(chain.endpoint.name, "preload", err);
            return error.NotAvailable;
        };
        for (results[0..count], 0..) |result, offset| {
            const raw = result orelse return error.NotFound;
            const decoded = sources.l2_block.decode_with_system_config(raw, chain.rollup);
            const block = decoded catch |err| {
                print_failure(chain.endpoint.name, "preload decode", err);
                return error.NotAvailable;
            };
            if (block.info.block_info.number != first + offset) return error.NotAvailable;
            chain.insert(block.info, block.system_config);
        }
        chain.reference_fetches += count;
        for (first + 1..first + count + 1) |number| {
            const child = chain.slot_of(number) orelse continue;
            const parent = chain.slot_of(number - 1) orelse return error.NotAvailable;
            const link = child.info.block_info.parent_hash;
            if (!link.eql(parent.info.block_info.hash)) return error.NotAvailable;
        }
        const lowest = chain.slot_of(first) orelse return error.NotAvailable;
        assert(lowest.info.block_info.number == first);
        return lowest.info;
    }

    pub fn l2_block_info_by_hash(chain: *L2Chain, hash: B256) ProviderError!L2BlockInfo {
        return (try chain.by_hash(hash)).info;
    }

    pub fn system_config_by_l2_hash(chain: *L2Chain, hash: B256) ProviderError!SystemConfig {
        return (try chain.by_hash(hash)).config;
    }

    pub fn l2_block_info_by_number(chain: *L2Chain, number: u64) ProviderError!L2BlockInfo {
        if (number > chain.head) return error.NotFound;
        if (chain.slot_of(number)) |slot| return slot.info;
        var params: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{number}) catch unreachable;
        const block = try chain.fetch("eth_getBlockByNumber", text);
        if (block.info.block_info.number != number) return error.NotAvailable;
        chain.insert(block.info, block.system_config);
        return block.info;
    }

    /// A safe block with its transactions (span batch overlap checks), from the reference:
    /// at or below the safe head it equals the derived block.
    pub fn l2_block_by_number(chain: *L2Chain, number: u64) ProviderError!SafeBlock {
        if (number > chain.head) return error.NotFound;
        var params: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{number}) catch unreachable;
        for (0..decode_attempts_max) |_| {
            const raw = chain.endpoint.call("eth_getBlockByNumber", text) catch |err| {
                print_failure(chain.endpoint.name, "full block", err);
                return error.NotAvailable;
            } orelse return error.NotFound;
            _ = chain.full_arena.reset(.{ .retain_with_limit = 4 * 1024 * 1024 });
            const allocator = chain.full_arena.allocator();
            const genesis = &chain.rollup.genesis;
            const block = sources.l2_block_full.decode(allocator, raw, genesis, .{}) catch |err| {
                print_failure(chain.endpoint.name, "full block decode", err);
                continue;
            };
            if (block.info.block_info.number != number) return error.NotAvailable;
            return .{
                .transactions = block.transactions,
                .l1_origin_number = block.info.l1_origin.number,
            };
        }
        return error.NotAvailable;
    }
};

//! Sequencer-signed gossip as an anchor for blocks from execution peers. Execution-layer
//! headers are not signed, so a chain followed over devp2p proves continuity and (after
//! execution) state, but not that the sequencer produced it. The consensus gossip network
//! carries every unsafe block signed by the chain's unsafe block signer: `Gossip` joins it
//! (discv5 + gossipsub, as `base unsafe-watch` does) on its own thread, and the caller
//! reports each block it accepts on its chain. Every height seen on both sides is compared:
//! equal hashes anchor the block to the sequencer; a different hash is a conflict.
//!
//! The network uses the `low-latency` p2p profile unless `--p2p.profile base` is given
//! (`p2p.options.low_latency`).
//!
//! Gossip delivery is best effort, so a height with no gossip is unanchored, not failed.
//! `Anchor` is the pure bookkeeping: a ring of recent heights, each holding up to
//! `hashes_max` signed hashes and the caller's hash, so gossip may arrive before or after
//! the caller's block.
//!
//! Gossip is also a block source (`Blocks`): each signed block is converted to a header and
//! transactions, and kept only when that header hashes to the signed block hash. At the tip
//! el-run executes the signed block for its next height (`take`) when exactly one arrived and
//! it links to el-run's head; devp2p stays the fallback. Execution then checks the block like
//! any other (state root, receipts, gas, bloom).

const std = @import("std");
const base = @import("base");

const unsafe_watch = @import("unsafe_watch.zig");
const el_source = @import("el_source.zig");
const io = base.utilities.io;
const p2p = base.consensus.p2p;
const chains = base.common.chains;
const block = p2p.gossip.block;
const gossip_bridge = base.consensus.service.gossip_bridge;
const engine_block = base.execution.engine.block;
const engine_types = base.execution.engine.types;
const ChainSpec = base.execution.chainspec.ChainSpec;
const rlp = base.common.rlp;
const snappy = p2p.gossip.snappy;
const Io = std.Io;
const Network = p2p.network.Network(io.IO);
const Address = base.common.primitives.Address;
const assert = std.debug.assert;
const ns_per_ms = std.time.ns_per_ms;

/// Heights remembered: 4096 blocks are 13.6 minutes at 200 ms.
pub const heights_max = 4096;
/// Signed hashes kept per height (a sequencer may publish a replacement block).
const hashes_max = 2;

pub const Outcome = enum { matched, conflict, pending };

/// Signed blocks kept for `take`: the newest `pending_max` heights (3.2 s at 200 ms).
pub const pending_max = 16;
/// A kept block's header and transactions; a larger block is left to devp2p.
const pending_bytes_max = 4 << 20;
const pending_transactions_max = el_source.transactions_max;
/// The slice table and withdrawals `gossip_bridge.decode_gossip` takes for one block.
const decode_scratch_bytes = pending_transactions_max * @sizeOf([]const u8) + (64 << 10);

pub const ConvertError = engine_block.PayloadError || std.mem.Allocator.Error ||
    error{BlockTooLarge};

/// Signed blocks converted for execution, by height. The network thread converts into
/// `stage` (no lock needed: only it touches `stage` and `scratch`) and then `store`s;
/// the caller `take`s. `store` and `take` run under the owner's lock.
pub const Blocks = struct {
    /// A signed block in el-run's form: its header RLP, then its transactions.
    const Pending = struct {
        number: u64 = 0,
        used: bool = false,
        /// Another signed block arrived at this height: left to devp2p.
        replaced: bool = false,
        /// Handed out by `take`.
        taken: bool = false,
        hash: [32]u8 = undefined,
        parent: [32]u8 = undefined,
        header_length: u32 = 0,
        bytes_used: u32 = 0,
        transactions_count: u32 = 0,
        bytes: []u8 = &.{},
        spans: [][2]u32 = &.{},
    };

    slots: [pending_max]Pending = @splat(.{}),
    stage: Pending = .{},
    scratch: []u8 = &.{},
    taken_bytes: []u8 = &.{},
    taken_transactions: [][]const u8 = &.{},
    // Counters.
    taken: u64 = 0,
    rejected: u64 = 0,
    replaced: u64 = 0,
    replaced_after_take: u64 = 0,

    pub fn init(blocks: *Blocks, allocator: std.mem.Allocator, bytes_max: u32) !void {
        blocks.* = .{};
        errdefer blocks.deinit(allocator);
        for (&blocks.slots) |*slot| try alloc_pending(slot, allocator, bytes_max);
        try alloc_pending(&blocks.stage, allocator, bytes_max);
        blocks.scratch = try allocator.alloc(u8, decode_scratch_bytes);
        blocks.taken_bytes = try allocator.alloc(u8, bytes_max);
        blocks.taken_transactions = try allocator.alloc([]const u8, pending_transactions_max);
    }

    fn alloc_pending(pending: *Pending, allocator: std.mem.Allocator, bytes_max: u32) !void {
        pending.bytes = try allocator.alloc(u8, bytes_max);
        pending.spans = try allocator.alloc([2]u32, pending_transactions_max);
    }

    pub fn deinit(blocks: *Blocks, allocator: std.mem.Allocator) void {
        for (&blocks.slots) |*slot| free_pending(slot, allocator);
        free_pending(&blocks.stage, allocator);
        allocator.free(blocks.scratch);
        allocator.free(blocks.taken_bytes);
        allocator.free(blocks.taken_transactions);
        blocks.* = .{};
    }

    fn free_pending(pending: *Pending, allocator: std.mem.Allocator) void {
        allocator.free(pending.bytes);
        allocator.free(pending.spans);
        pending.* = .{};
    }

    /// Converts a signed gossip block into `stage`. Its header (built from the payload
    /// and its beacon root, as `engine_newPayload` does) must hash to the signed block hash.
    pub fn convert(
        blocks: *Blocks,
        spec: *const ChainSpec,
        envelope: *const block.Envelope,
    ) ConvertError!void {
        var fixed = std.heap.FixedBufferAllocator.init(blocks.scratch);
        const decoded = try gossip_bridge.decode_gossip(fixed.allocator(), envelope);
        const payload = &decoded.payload;
        const stage = &blocks.stage;
        if (payload.transactions.len > stage.spans.len) return error.BlockTooLarge;
        const params: engine_types.NewPayloadParams = .{
            .versioned_hashes = if (payload.blob_gas_used != null) &.{} else null,
            .parent_beacon_block_root = decoded.parent_beacon_block_root,
            .execution_requests = if (payload.withdrawals_root != null) &.{} else null,
        };
        const header = try engine_block.ensure_well_formed(spec, payload, &params);
        if (header.rlp_length() > stage.bytes.len) return error.BlockTooLarge;
        var encoder = rlp.Encoder.init(stage.bytes);
        header.rlp_encode(&encoder);
        var used: u32 = @intCast(encoder.position);
        stage.header_length = used;
        for (payload.transactions, stage.spans[0..payload.transactions.len]) |bytes, *span| {
            if (stage.bytes.len - used < bytes.len) return error.BlockTooLarge;
            @memcpy(stage.bytes[used..][0..bytes.len], bytes);
            span.* = .{ used, @intCast(bytes.len) };
            used += @intCast(bytes.len);
        }
        stage.number = payload.block_number;
        stage.hash = payload.block_hash.bytes;
        stage.parent = payload.parent_hash.bytes;
        stage.bytes_used = used;
        stage.transactions_count = @intCast(payload.transactions.len);
        assert(header.hash().eql(payload.block_hash));
    }

    /// Keeps the converted `stage` at its height (a newer height takes an older one's slot).
    /// A second, different block at a kept height marks it replaced: never taken.
    pub fn store(blocks: *Blocks) void {
        const stage = &blocks.stage;
        const slot = &blocks.slots[stage.number % pending_max];
        if (slot.used and slot.number > stage.number) return;
        if (slot.used and slot.number == stage.number) {
            if (std.mem.eql(u8, &slot.hash, &stage.hash)) return; // A duplicate.
            if (!slot.replaced) blocks.replaced += 1;
            if (slot.taken) blocks.replaced_after_take += 1;
            slot.replaced = true;
            return;
        }
        std.mem.swap(Pending, slot, stage);
        slot.used = true;
        slot.replaced = false;
        slot.taken = false;
        stage.used = false;
        assert(slot.bytes.len == stage.bytes.len);
    }

    /// The signed block `number` when exactly one arrived and it links to `parent`: copied
    /// into buffers that stay valid until the next `take`. Null otherwise.
    pub fn take(blocks: *Blocks, number: u64, parent: [32]u8) ?el_source.Block {
        const slot = &blocks.slots[number % pending_max];
        if (!slot.used or slot.number != number or slot.replaced or slot.taken) return null;
        if (!std.mem.eql(u8, &slot.parent, &parent)) return null;
        const count = slot.transactions_count;
        assert(slot.bytes_used <= blocks.taken_bytes.len);
        @memcpy(blocks.taken_bytes[0..slot.bytes_used], slot.bytes[0..slot.bytes_used]);
        for (slot.spans[0..count], blocks.taken_transactions[0..count]) |span, *bytes| {
            bytes.* = blocks.taken_bytes[span[0]..][0..span[1]];
        }
        slot.taken = true;
        blocks.taken += 1;
        return .{
            .number = number,
            .hash = slot.hash,
            .header_rlp = blocks.taken_bytes[0..slot.header_length],
            .transactions = blocks.taken_transactions[0..count],
        };
    }
};

pub const Anchor = struct {
    const Slot = struct {
        number: u64 = 0,
        used: bool = false,
        hashes: [hashes_max][32]u8 = undefined,
        hashes_count: u8 = 0,
        gossip_ms: u64 = 0,
        chain: ?[32]u8 = null,
        chain_ms: u64 = 0,
        matched: bool = false,
    };

    slots: [heights_max]Slot = @splat(.{}),
    gossip_blocks: u64 = 0,
    gossip_head: u64 = 0,
    /// Heights whose chain hash equals a signed hash.
    matched: u64 = 0,
    /// Signed hashes that differ from the chain hash at their height.
    conflicts: u64 = 0,
    last_matched: u64 = 0,
    /// Matched heights where gossip arrived before the chain's block, and by how much.
    gossip_first: u64 = 0,
    gossip_lead_ms_sum: u64 = 0,
    gossip_lead_ms_max: u64 = 0,

    /// The slot for `number`, reset when it held an older height; null when it holds a
    /// newer one (`number` is too old to compare).
    fn slot_for(anchor: *Anchor, number: u64) ?*Slot {
        const slot = &anchor.slots[number % heights_max];
        if (slot.used and slot.number > number) return null;
        if (!slot.used or slot.number < number) slot.* = .{ .number = number, .used = true };
        assert(slot.used and slot.number == number);
        return slot;
    }

    /// A signed gossip block's height and hash, received at `now_ms` (wall clock).
    pub fn on_gossip(anchor: *Anchor, number: u64, hash: [32]u8, now_ms: u64) Outcome {
        anchor.gossip_blocks += 1;
        anchor.gossip_head = @max(anchor.gossip_head, number);
        const slot = anchor.slot_for(number) orelse return .pending;
        for (slot.hashes[0..slot.hashes_count]) |*known| {
            if (std.mem.eql(u8, known, &hash)) return .pending; // A duplicate.
        }
        if (slot.hashes_count == hashes_max) return .pending;
        if (slot.hashes_count == 0) slot.gossip_ms = now_ms;
        slot.hashes[slot.hashes_count] = hash;
        slot.hashes_count += 1;
        const chain = slot.chain orelse return .pending;
        return anchor.compare(slot, chain, hash);
    }

    /// A block the caller accepted on its chain (executed and committed, for el-run).
    pub fn on_chain(anchor: *Anchor, number: u64, hash: [32]u8, now_ms: u64) Outcome {
        const slot = anchor.slot_for(number) orelse return .pending;
        assert(slot.chain == null or std.mem.eql(u8, &slot.chain.?, &hash));
        if (slot.chain != null) return .pending;
        slot.chain = hash;
        slot.chain_ms = now_ms;
        var outcome: Outcome = .pending;
        for (slot.hashes[0..slot.hashes_count]) |signed| {
            const result = anchor.compare(slot, hash, signed);
            if (outcome != .conflict) outcome = result;
        }
        return outcome;
    }

    fn compare(anchor: *Anchor, slot: *Slot, chain: [32]u8, signed: [32]u8) Outcome {
        assert(slot.used and slot.chain != null);
        if (!std.mem.eql(u8, &chain, &signed)) {
            anchor.conflicts += 1;
            return .conflict;
        }
        if (slot.matched) return .pending;
        slot.matched = true;
        anchor.matched += 1;
        anchor.last_matched = @max(anchor.last_matched, slot.number);
        if (slot.gossip_ms <= slot.chain_ms) {
            const lead_ms = slot.chain_ms - slot.gossip_ms;
            anchor.gossip_first += 1;
            anchor.gossip_lead_ms_sum += lead_ms;
            anchor.gossip_lead_ms_max = @max(anchor.gossip_lead_ms_max, lead_ms);
        }
        return .matched;
    }
};

/// The gossip network on its own thread, feeding an `Anchor` under a mutex.
pub const Gossip = struct {
    allocator: std.mem.Allocator,
    io: Io,
    rollup: base.consensus.protocol.RollupConfig,
    options: p2p.options.Options,
    signer: Address,
    /// Null: gossip only anchors; no blocks are kept for `take`.
    spec: ?*const ChainSpec,
    mutex: Io.Mutex = .init,
    anchor: Anchor = .{},
    /// Signed blocks for `take`; `convert` and `stage` belong to the network thread.
    blocks: Blocks = .{},
    convert_failed: u64 = 0,
    // Guarded by `mutex`.
    peers: u32 = 0,
    bad_signer: u64 = 0,
    failed: ?anyerror = null,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    /// Starts the network thread. `args` are the command's arguments: `--p2p.*` flags
    /// (`p2p.options`) configure the network, the rest are ignored.
    pub fn start(
        allocator: std.mem.Allocator,
        std_io: Io,
        chain: *const chains.ChainConfig,
        spec: ?*const ChainSpec,
        args: []const []const u8,
    ) !*Gossip {
        if (spec) |value| assert(value.chain_id == chain.chain_id);
        // A follower only receives: the low-latency preset unless `--p2p.profile base`.
        var options = try p2p.options.parse_profile(args, .low_latency);
        // Without inbound reachability (NAT), keep asking known peers for a slot.
        if (options.redial_known_interval_s == 0) options.redial_known_interval_s = 10;
        const gossip = try allocator.create(Gossip);
        errdefer allocator.destroy(gossip);
        gossip.* = .{
            .allocator = allocator,
            .io = std_io,
            .rollup = unsafe_watch.rollup_for(chain),
            .options = options,
            .signer = options.unsafe_block_signer orelse chain.unsafe_block_signer.?,
            .spec = spec,
        };
        if (spec != null) try gossip.blocks.init(allocator, pending_bytes_max);
        errdefer if (spec != null) gossip.blocks.deinit(allocator);
        gossip.thread = try std.Thread.spawn(.{}, run_thread, .{gossip});
        const signer = &gossip.signer.bytes;
        std.debug.print("el-gossip: chain {s} signer 0x{x}\n", .{ chain.name, signer });
        return gossip;
    }

    pub fn destroy(gossip: *Gossip) void {
        gossip.stopping.store(true, .release);
        if (gossip.thread) |thread| thread.join();
        if (gossip.spec != null) gossip.blocks.deinit(gossip.allocator);
        gossip.allocator.destroy(gossip);
    }

    /// Reports a block the caller accepted on its chain; prints a conflict.
    pub fn on_chain(gossip: *Gossip, number: u64, hash: [32]u8) Outcome {
        const now_ms = wall_ms(gossip.io);
        gossip.mutex.lockUncancelable(gossip.io);
        defer gossip.mutex.unlock(gossip.io);
        const outcome = gossip.anchor.on_chain(number, hash, now_ms);
        if (outcome == .conflict) print_conflict(&gossip.anchor, number);
        return outcome;
    }

    /// The signed block `number` linking to `parent`, if gossip has exactly one (`Blocks`).
    pub fn take(gossip: *Gossip, number: u64, parent: [32]u8) ?el_source.Block {
        gossip.mutex.lockUncancelable(gossip.io);
        defer gossip.mutex.unlock(gossip.io);
        return gossip.blocks.take(number, parent);
    }

    pub fn summary(gossip: *Gossip) void {
        gossip.mutex.lockUncancelable(gossip.io);
        defer gossip.mutex.unlock(gossip.io);
        const anchor = &gossip.anchor;
        const first = @max(anchor.gossip_first, 1);
        const lead_avg = anchor.gossip_lead_ms_sum / first;
        const failed = if (gossip.failed != null) ", network FAILED" else "";
        std.debug.print("gossip: peers {d}, {d} signed blocks (head {d}), {d} anchored " ++
            "(last {d}), {d} conflicts, {d} bad signer, gossip first {d} lead_ms avg {d} " ++
            "max {d}{s}\n", .{
            gossip.peers,              anchor.gossip_blocks, anchor.gossip_head,
            anchor.matched,            anchor.last_matched,  anchor.conflicts,
            gossip.bad_signer,         anchor.gossip_first,  lead_avg,
            anchor.gossip_lead_ms_max, failed,
        });
        const blocks = &gossip.blocks;
        std.debug.print("gossip blocks: {d} executed from gossip, {d} not convertible, " ++
            "{d} replaced heights ({d} after execution)\n", .{
            blocks.taken, gossip.convert_failed, blocks.replaced, blocks.replaced_after_take,
        });
    }

    fn run_thread(gossip: *Gossip) void {
        gossip.run_network() catch |err| {
            std.debug.print("el-gossip: network stopped: {t}\n", .{err});
            gossip.mutex.lockUncancelable(gossip.io);
            defer gossip.mutex.unlock(gossip.io);
            gossip.failed = err;
        };
    }

    /// The network lives entirely on this thread: its event loop, buffers and state.
    fn run_network(gossip: *Gossip) !void {
        const linux = @import("builtin").os.tag == .linux;
        var os_io = if (linux) try io.IO.init(.{}) else try io.IO.init();
        defer os_io.deinit();
        var seed_bytes: [8]u8 = undefined;
        gossip.io.random(&seed_bytes);
        const seed = std.mem.readInt(u64, &seed_bytes, .little);
        var prng = std.Random.DefaultPrng.init(seed);
        const secret = try p2p.network.node_secret(&gossip.options, null, prng.random());
        const allocator = gossip.allocator;
        const network = try allocator.create(Network);
        defer allocator.destroy(network);
        const random = prng.random();
        const rollup = &gossip.rollup;
        const signer = gossip.signer;
        try network.init(allocator, &os_io, rollup, gossip.options, secret, signer, random, seed);
        defer network.deinit(allocator);
        _ = try network.start();
        const scratch = try allocator.alloc(u8, snappy.gossip_size_max);
        defer allocator.free(scratch);
        while (!gossip.stopping.load(.acquire)) {
            try os_io.run_for_ns(5 * ns_per_ms);
            const now_ms = os_io.now_realtime_ns() / ns_per_ms;
            while (network.pop_block(scratch)) |envelope| gossip.on_envelope(&envelope, now_ms);
            gossip.mutex.lockUncancelable(gossip.io);
            gossip.peers = network.peer_count();
            gossip.mutex.unlock(gossip.io);
        }
        network.stop();
        var drain: u32 = 0;
        while (network.busy() and drain < 1000) : (drain += 1) try os_io.run_for_ns(ns_per_ms);
    }

    /// The gossip handler already checked the signer and block hash; the signer is
    /// recovered again here so an anchored block is evidence on its own.
    fn on_envelope(gossip: *Gossip, envelope: *const block.Envelope, now_ms: u64) void {
        const recovered = block.recover_signer(envelope, gossip.rollup.l2_chain_id);
        const signer_ok = if (recovered) |address| address.eql(gossip.signer) else false;
        // Outside the lock: only this thread touches the stage.
        const spec = gossip.spec orelse return gossip.on_signed(envelope, now_ms, signer_ok, {});
        const converted = if (signer_ok) gossip.blocks.convert(spec, envelope) else {};
        gossip.on_signed(envelope, now_ms, signer_ok, converted);
    }

    /// Counts and anchors a received block, and keeps it for `take` when it converted.
    fn on_signed(
        gossip: *Gossip,
        envelope: *const block.Envelope,
        now_ms: u64,
        signer_ok: bool,
        converted: ConvertError!void,
    ) void {
        const payload = &envelope.payload;
        gossip.mutex.lockUncancelable(gossip.io);
        defer gossip.mutex.unlock(gossip.io);
        if (!signer_ok) {
            gossip.bad_signer += 1;
            return;
        }
        if (converted) |_| {
            if (gossip.spec != null) gossip.blocks.store();
        } else |err| {
            gossip.convert_failed += 1;
            if (gossip.convert_failed <= 8) {
                std.debug.print("el-gossip: block {d} not convertible: {t}\n", .{
                    payload.block_number, err,
                });
            }
        }
        const number = payload.block_number;
        const outcome = gossip.anchor.on_gossip(number, payload.block_hash.bytes, now_ms);
        if (outcome == .conflict) print_conflict(&gossip.anchor, number);
    }
};

fn print_conflict(anchor: *const Anchor, number: u64) void {
    const slot = &anchor.slots[number % heights_max];
    assert(slot.used and slot.number == number and slot.chain != null);
    std.debug.print("GOSSIP CONFLICT block {d}: chain {x}, signed", .{ number, slot.chain.? });
    for (slot.hashes[0..slot.hashes_count]) |*hash| std.debug.print(" {x}", .{hash});
    std.debug.print("\n", .{});
}

fn wall_ms(std_io: Io) u64 {
    return @intCast(@divTrunc(Io.Clock.real.now(std_io).nanoseconds, ns_per_ms));
}

fn test_hash(byte: u8) [32]u8 {
    return @splat(byte);
}

test "el-gossip: anchor matches in either order and measures the gossip lead" {
    var anchor: Anchor = .{};
    // Gossip first, 40 ms before the chain's block.
    try std.testing.expectEqual(Outcome.pending, anchor.on_gossip(100, test_hash(1), 1_000));
    try std.testing.expectEqual(Outcome.matched, anchor.on_chain(100, test_hash(1), 1_040));
    // Chain first: no lead recorded.
    try std.testing.expectEqual(Outcome.pending, anchor.on_chain(101, test_hash(2), 2_000));
    try std.testing.expectEqual(Outcome.matched, anchor.on_gossip(101, test_hash(2), 2_300));
    // A duplicate gossip block counts once.
    try std.testing.expectEqual(Outcome.pending, anchor.on_gossip(101, test_hash(2), 2_400));
    try std.testing.expectEqual(@as(u64, 2), anchor.matched);
    try std.testing.expectEqual(@as(u64, 1), anchor.gossip_first);
    try std.testing.expectEqual(@as(u64, 40), anchor.gossip_lead_ms_max);
    try std.testing.expectEqual(@as(u64, 101), anchor.last_matched);
    try std.testing.expectEqual(@as(u64, 0), anchor.conflicts);
}

test "el-gossip: anchor reports conflicts and keeps a replacement block" {
    var anchor: Anchor = .{};
    // The chain's block differs from the signed one: a conflict, either order.
    try std.testing.expectEqual(Outcome.pending, anchor.on_gossip(200, test_hash(7), 0));
    try std.testing.expectEqual(Outcome.conflict, anchor.on_chain(200, test_hash(8), 0));
    try std.testing.expectEqual(Outcome.pending, anchor.on_chain(201, test_hash(8), 0));
    try std.testing.expectEqual(Outcome.conflict, anchor.on_gossip(201, test_hash(7), 0));
    // Two signed blocks at one height, the chain took the second: matched, one conflict.
    _ = anchor.on_gossip(202, test_hash(3), 0);
    _ = anchor.on_gossip(202, test_hash(4), 0);
    try std.testing.expectEqual(Outcome.conflict, anchor.on_chain(202, test_hash(4), 0));
    try std.testing.expectEqual(@as(u64, 1), anchor.matched);
    try std.testing.expectEqual(@as(u64, 3), anchor.conflicts);
}

test "el-gossip: anchor ring keeps the newer height and ignores a too-old one" {
    var anchor: Anchor = .{};
    // Gossip far ahead of a catching-up chain takes the slot; the old height is skipped.
    _ = anchor.on_gossip(5 + heights_max, test_hash(9), 0);
    try std.testing.expectEqual(Outcome.pending, anchor.on_chain(5, test_hash(1), 0));
    try std.testing.expectEqual(Outcome.pending, anchor.on_gossip(5, test_hash(1), 0));
    // The slot then serves its own height normally.
    try std.testing.expectEqual(Outcome.matched, anchor.on_chain(5 + heights_max, test_hash(9), 0));
    // A newer height evicts an older one; no stale match against the evicted entry.
    _ = anchor.on_chain(6, test_hash(2), 0);
    const evicting = anchor.on_gossip(6 + heights_max, test_hash(2), 0);
    try std.testing.expectEqual(Outcome.pending, evicting);
    try std.testing.expectEqual(@as(u64, 1), anchor.matched);
    try std.testing.expectEqual(@as(u64, 0), anchor.conflicts);
    try std.testing.expectEqual(@as(u64, 6 + heights_max), anchor.gossip_head);
}

/// An Isthmus header over `transactions` (the shape of a Base block), and its signed gossip
/// form: the payload's fields, its transactions in SSZ (`storage`), and the beacon root.
const TestBlock = struct {
    header: base.common.consensus.Header,
    envelope: block.Envelope,

    fn init(
        number: u64,
        parent: [32]u8,
        transactions: []const []const u8,
        storage: []u8,
    ) TestBlock {
        const B256 = base.common.primitives.B256;
        const header: base.common.consensus.Header = .{
            .parent_hash = .{ .bytes = parent },
            .beneficiary = .init(@splat(0xfe)),
            .state_root = .init(@splat(0x51)),
            .transactions_root = .{ .bytes = base.execution.trie.ordered_trie_root(transactions) },
            .receipts_root = .init(@splat(0x52)),
            .number = number,
            .gas_limit = 60_000_000,
            .gas_used = 21_000,
            .timestamp = 1_750_000_000 + number,
            .extra_data = &.{ 1, 0, 0, 0, 250, 0, 0, 0, 6 },
            .mix_hash = .init(@splat(0x3d)),
            .base_fee_per_gas = 1_000_000,
            .withdrawals_root = .init(@splat(0x77)),
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
            .parent_beacon_block_root = .init(@splat(0xbe)),
            .requests_hash = engine_block.empty_requests_hash,
        };
        const payload: block.ExecutionPayload = .{
            .version = .v4,
            .parent_hash = header.parent_hash,
            .fee_recipient = header.beneficiary,
            .state_root = header.state_root,
            .receipts_root = header.receipts_root,
            .logs_bloom = header.logs_bloom,
            .prev_randao = header.mix_hash,
            .block_number = number,
            .gas_limit = header.gas_limit,
            .gas_used = header.gas_used,
            .timestamp = header.timestamp,
            .extra_data = header.extra_data,
            .base_fee_per_gas = header.base_fee_per_gas.?,
            .block_hash = header.hash(),
            .transactions = p2p.gossip.ssz_payload.Transactions.encode(storage, transactions),
            .withdrawals_root = header.withdrawals_root.?,
        };
        return .{ .header = header, .envelope = .{
            .version = .v4,
            .signature = @splat(0),
            .y_parity = 0,
            .parent_beacon_block_root = header.parent_beacon_block_root.?,
            .payload = payload,
            .payload_hash = B256.zero,
        } };
    }
};

const test_spec = @import("import_run.zig").chains[0].spec;

test "el-gossip: a signed block converts to the exact header and transactions" {
    var blocks: Blocks = .{};
    try blocks.init(std.testing.allocator, 1 << 16);
    defer blocks.deinit(std.testing.allocator);
    const transactions = [_][]const u8{ "\x7e\x01\x02\x03", "\x02\xaa\xbb", "\x02\xcc" };
    var storage: [256]u8 = undefined;
    var signed = TestBlock.init(500, @splat(0x99), &transactions, &storage);
    try blocks.convert(test_spec, &signed.envelope);
    blocks.store();
    const taken = blocks.take(500, @splat(0x99)).?;
    var expected: [1024]u8 = undefined;
    const header_rlp = rlp.encode_to(&expected, signed.header);
    try std.testing.expectEqualSlices(u8, header_rlp, taken.header_rlp);
    try std.testing.expectEqualSlices(u8, &signed.header.hash().bytes, &taken.hash);
    try std.testing.expectEqual(transactions.len, taken.transactions.len);
    for (transactions, taken.transactions) |want, got| {
        try std.testing.expectEqualSlices(u8, want, got);
    }
    // A payload whose fields do not hash to its block hash is refused; nothing is kept.
    var forged = TestBlock.init(501, taken.hash, &transactions, &storage);
    forged.envelope.payload.state_root = .init(@splat(0x66));
    const refused = blocks.convert(test_spec, &forged.envelope);
    try std.testing.expectError(error.BlockHashMismatch, refused);
    try std.testing.expectEqual(@as(?el_source.Block, null), blocks.take(501, taken.hash));
}

test "el-gossip: blocks are taken once, only when they link, never after a replacement" {
    var blocks: Blocks = .{};
    try blocks.init(std.testing.allocator, 1 << 16);
    defer blocks.deinit(std.testing.allocator);
    var storage: [256]u8 = undefined;
    const one = [_][]const u8{"\x02\x01"};
    const other = [_][]const u8{"\x02\x02"};
    var first = TestBlock.init(700, @splat(0x10), &one, &storage);
    try blocks.convert(test_spec, &first.envelope);
    blocks.store();
    // Wrong parent: not taken (and still there for the right one).
    try std.testing.expect(blocks.take(700, @splat(0x11)) == null);
    const hash_700 = blocks.take(700, @splat(0x10)).?.hash;
    try std.testing.expect(blocks.take(700, @splat(0x10)) == null);
    // A second, different signed block at 700 after execution is counted.
    var second = TestBlock.init(700, @splat(0x10), &other, &storage);
    try blocks.convert(test_spec, &second.envelope);
    blocks.store();
    try std.testing.expectEqual(@as(u64, 1), blocks.replaced_after_take);
    // Two different blocks at 701 before el-run asks: neither is taken.
    var a = TestBlock.init(701, hash_700, &one, &storage);
    try blocks.convert(test_spec, &a.envelope);
    blocks.store();
    // The same block again is a duplicate, not a replacement.
    try blocks.convert(test_spec, &a.envelope);
    blocks.store();
    try std.testing.expectEqual(@as(u64, 1), blocks.replaced);
    var b = TestBlock.init(701, hash_700, &other, &storage);
    try blocks.convert(test_spec, &b.envelope);
    blocks.store();
    try std.testing.expectEqual(@as(u64, 2), blocks.replaced);
    try std.testing.expect(blocks.take(701, hash_700) == null);
    // A newer height takes the slot; the old height is then too old to store.
    var newer = TestBlock.init(701 + pending_max, @splat(0x20), &one, &storage);
    try blocks.convert(test_spec, &newer.envelope);
    blocks.store();
    try blocks.convert(test_spec, &a.envelope);
    blocks.store();
    try std.testing.expect(blocks.take(701, hash_700) == null);
    try std.testing.expect(blocks.take(701 + pending_max, @splat(0x20)) != null);
    try std.testing.expectEqual(@as(u64, 2), blocks.taken);
}

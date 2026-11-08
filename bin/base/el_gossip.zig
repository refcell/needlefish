//! Sequencer-signed gossip as an anchor for blocks from execution peers. Execution-layer
//! headers are not signed, so a chain followed over devp2p proves continuity and (after
//! execution) state, but not that the sequencer produced it. The consensus gossip network
//! carries every unsafe block signed by the chain's unsafe block signer: `Gossip` joins it
//! (discv5 + gossipsub, as `base unsafe-watch` does) on its own thread, and the caller
//! reports each block it accepts on its chain. Every height seen on both sides is compared:
//! equal hashes anchor the block to the sequencer; a different hash is a conflict.
//!
//! Gossip delivery is best effort (behind NAT whole hours can pass without a block), so a
//! height with no gossip is unanchored, not failed. `Anchor` is the pure bookkeeping: a
//! ring of recent heights, each holding up to `hashes_max` signed hashes and the caller's
//! hash, so gossip may arrive before or after the caller's block.

const std = @import("std");
const base = @import("base");

const unsafe_watch = @import("unsafe_watch.zig");
const io = base.utilities.io;
const p2p = base.consensus.p2p;
const chains = base.common.chains;
const block = p2p.gossip.block;
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
    mutex: Io.Mutex = .init,
    anchor: Anchor = .{},
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
        args: []const []const u8,
    ) !*Gossip {
        var options = try p2p.options.parse(args);
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
        };
        gossip.thread = try std.Thread.spawn(.{}, run_thread, .{gossip});
        const signer = &gossip.signer.bytes;
        std.debug.print("el-gossip: chain {s} signer 0x{x}\n", .{ chain.name, signer });
        return gossip;
    }

    pub fn destroy(gossip: *Gossip) void {
        gossip.stopping.store(true, .release);
        if (gossip.thread) |thread| thread.join();
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
        const payload = &envelope.payload;
        const recovered = block.recover_signer(envelope, gossip.rollup.l2_chain_id);
        const signer_ok = if (recovered) |address| address.eql(gossip.signer) else false;
        gossip.mutex.lockUncancelable(gossip.io);
        defer gossip.mutex.unlock(gossip.io);
        if (!signer_ok) {
            gossip.bad_signer += 1;
            return;
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

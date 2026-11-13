//! The block feed `base el-run` executes, from execution peers only (no RPC): multi-peer
//! catch-up (`el_pool.zig`) until the pool stops short of the tip, then one peer
//! (`el_source.zig`, the pool's fastest first) follows the tip. If the follower loses its
//! peer, or falls more than `behind_max_blocks` behind the block schedule, the pool takes
//! over again from the last block handed out. Blocks come out in ascending order, each
//! linked to the one before and the first to `parent`.

const std = @import("std");
const base = @import("base");

const el_source = @import("el_source.zig");
const el_pool = @import("el_pool.zig");
const ChainConfig = base.common.chains.ChainConfig;
const Io = std.Io;
const assert = std.debug.assert;

/// Back to multi-peer catch-up when the follower is this far behind the schedule.
const behind_max_blocks = 4 * el_pool.segment_blocks;
/// Waits of 50 ms for the round-trip probes before choosing the follower.
const probe_waits_max = 40;
/// Re-read the peer file this often, adding new peers (`el-peers --out` appends to it).
const reload_interval_ms = 60_000;

pub const Mode = enum { catch_up, follow };

pub const Options = struct {
    chain: *const ChainConfig,
    from: u64,
    parent: ?[32]u8,
    /// A file of enodes, re-read every minute.
    peers_path: ?[]const u8 = null,
    enode: ?[]const u8 = null,
};

pub const Feed = struct {
    allocator: std.mem.Allocator,
    io: Io,
    chain: *const ChainConfig,
    pool: *el_pool.Pool,
    source: ?*el_source.Source = null,
    mode: Mode = .catch_up,
    peers_path: ?[]const u8,
    reloaded_ms: i64,
    /// The next block number and the hash its parent must have.
    next_number: u64,
    parent: ?[32]u8,
    /// Set by `next` when the follower fell behind; acted on at the next call.
    behind: bool = false,
    /// The follower reported nothing new at least once since following began.
    at_tip: bool = false,
    switches: u32 = 0,

    pub fn create(allocator: std.mem.Allocator, io: Io, options: Options) !*Feed {
        const pool = try el_pool.Pool.create(allocator, io, options.chain, .{
            .from = options.from,
            .parent = options.parent,
        });
        errdefer pool.destroy();
        var peers: u32 = 0;
        if (options.enode) |text| {
            if (try pool.add_peer(text)) peers += 1 else return error.InvalidEnode;
        }
        if (options.peers_path) |path| peers += try pool.load_peers(path);
        if (peers == 0) return error.NoPeers;
        const feed = try allocator.create(Feed);
        feed.* = .{
            .allocator = allocator,
            .io = io,
            .chain = options.chain,
            .pool = pool,
            .peers_path = options.peers_path,
            .reloaded_ms = Io.Clock.awake.now(io).toMilliseconds(),
            .next_number = options.from,
            .parent = options.parent,
        };
        std.debug.print("el-feed: {d} peers, catch-up from {d}, tip estimate {d}\n", .{
            peers, options.from, pool.tip_estimate(),
        });
        return feed;
    }

    pub fn destroy(feed: *Feed) void {
        feed.stop_follow();
        feed.pool.destroy();
        feed.allocator.destroy(feed);
    }

    /// The next block, or false when there is nothing new yet (wait a little and call
    /// again). The block stays valid until the next call.
    pub fn next(feed: *Feed, block: *el_source.Block) !bool {
        if (feed.behind) {
            feed.behind = false;
            std.debug.print("el-feed: follower behind at {d}; multi-peer catch-up\n", .{
                feed.next_number,
            });
            feed.catch_up();
        }
        switch (feed.mode) {
            .catch_up => {
                feed.reload_peers();
                if (try feed.pool.next(block)) {
                    feed.advance(block);
                    return true;
                }
                feed.follow() catch |err| {
                    std.debug.print("el-feed: cannot follow ({s}); retrying catch-up\n", .{
                        @errorName(err),
                    });
                    feed.catch_up();
                };
                return false;
            },
            .follow => {
                const source = feed.source.?;
                const got = source.next(block) catch |err| {
                    std.debug.print("el-feed: follower failed at {d} ({s})\n", .{
                        feed.next_number, @errorName(err),
                    });
                    feed.catch_up();
                    return false;
                };
                if (!got) {
                    feed.at_tip = true;
                    return false;
                }
                feed.advance(block);
                feed.behind = feed.pool.tip_estimate() -| block.number > behind_max_blocks;
                return true;
            },
        }
    }

    /// Block `next_number`, which links to `parent`, came from another source (gossip):
    /// the follower skips it and continues after it.
    pub fn adopt(feed: *Feed, block: *const el_source.Block) void {
        assert(feed.mode == .follow and feed.at_tip);
        assert(block.number == feed.next_number);
        feed.advance(block);
        feed.source.?.skip(block.number, block.hash);
        assert(feed.source.?.next_number == feed.next_number);
    }

    fn advance(feed: *Feed, block: *const el_source.Block) void {
        assert(block.number == feed.next_number);
        feed.next_number += 1;
        feed.parent = block.hash;
    }

    /// Parks the pool, measures every connected peer's round trip, and follows on the
    /// nearest peer's open connection, taken over from its worker: a peer may refuse a
    /// reconnect or a second connection from us.
    fn follow(feed: *Feed) !void {
        assert(feed.mode == .catch_up and feed.source == null);
        feed.pool.park();
        // Workers finish their segment first; a round trip at the tip is tens of ms.
        if (feed.pool.probe() > 0) {
            for (0..probe_waits_max) |_| {
                if (!feed.pool.probing()) break;
                try feed.io.sleep(.fromMilliseconds(50), .awake);
            }
        }
        var targets: [1]el_source.Target = undefined;
        if (feed.pool.targets_by_latency(&targets) == 0) return error.NoFollower;
        const source = try feed.allocator.create(el_source.Source);
        errdefer feed.allocator.destroy(source);
        try source.init_unconnected(feed.allocator, feed.io, targets[0], .{
            .from = feed.next_number,
            .parent = feed.parent,
            .reconnects_max = 4,
        });
        errdefer source.deinit(feed.allocator);
        // Workers finishing a segment are not lent; give them a moment.
        var target: ?el_source.Target = null;
        for (0..20) |_| {
            target = feed.pool.lend_nearest(&source.peer);
            if (target != null) break;
            try feed.io.sleep(.fromMilliseconds(50), .awake);
        }
        // No idle connection to take over: the source connects on its first `next`.
        if (target) |lent| source.target = lent;
        feed.source = source;
        feed.mode = .follow;
        feed.switches += 1;
        std.debug.print("el-feed: following the tip from {d} ({s} connection)\n", .{
            feed.next_number, if (target != null) "a lent" else "a new",
        });
    }

    fn catch_up(feed: *Feed) void {
        feed.stop_follow();
        feed.pool.reset(feed.next_number, feed.parent);
        feed.mode = .catch_up;
        feed.at_tip = false;
    }

    fn stop_follow(feed: *Feed) void {
        const source = feed.source orelse return;
        source.deinit(feed.allocator);
        feed.allocator.destroy(source);
        feed.source = null;
        feed.switches += @intFromBool(feed.mode == .follow);
    }

    fn reload_peers(feed: *Feed) void {
        const path = feed.peers_path orelse return;
        const now = Io.Clock.awake.now(feed.io).toMilliseconds();
        if (now - feed.reloaded_ms < reload_interval_ms) return;
        feed.reloaded_ms = now;
        const added = feed.pool.load_peers(path) catch |err| {
            std.debug.print("el-feed: cannot reload {s}: {t}\n", .{ path, err });
            return;
        };
        if (added > 0) std.debug.print("el-feed: {d} new peers from {s}\n", .{ added, path });
    }
};

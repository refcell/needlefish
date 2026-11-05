//! Model nodes for the cluster simulator.
//!
//! These are deliberately small stand-ins for the real components (L1 node,
//! sequencer, batcher, verifier) that follow the Base data flow: the sequencer
//! gossips unsafe blocks, the batcher posts batches to L1, verifiers derive the safe
//! chain from L1 and follow unsafe gossip. As lanes land real components behind the
//! IO interface, they replace these models one by one; the fault injector and
//! invariant checkers stay.
//!
//! Every node is a state machine: `tick(env)` on each simulator step and
//! `on_message(env, from, message)` on delivery. Nodes never block or allocate after
//! init.

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../prng.zig").Prng;
const network_module = @import("network.zig");
const NodeId = network_module.NodeId;

pub const batch_blocks_max = 8;
pub const l1_batches_max = 4;
pub const sync_blocks_max = 16;
pub const l1_request_burst = 4;
pub const l1_mempool_max = 16;
pub const pipeline_blocks_max = 32;

pub const node_l1: NodeId = 0;
pub const node_sequencer: NodeId = 1;
pub const node_batcher: NodeId = 2;
pub const node_verifier_first: NodeId = 3;

pub const genesis_hash: u64 = 0x6765_6e65_7369_7300;

pub fn block_hash(parent_hash: u64, number: u64, payload: u64) u64 {
    assert(number > 0);
    const words = [3]u64{ parent_hash, number, payload };
    return std.hash.Wyhash.hash(0, std.mem.asBytes(&words));
}

pub const Batch = struct {
    number_first: u64,
    count: u8,
    payloads: [batch_blocks_max]u64,
};

pub const L1Block = struct {
    number: u64,
    batch_count: u8,
    batches: [l1_batches_max]Batch,
};

pub const Message = union(enum) {
    unsafe_block: struct { number: u64, payload: u64, hash: u64 },
    sync_request: struct { number_first: u64 },
    batch_submit: Batch,
    l1_block: L1Block,
    l1_request: struct { number: u64 },
};

pub const Net = network_module.Network(Message);

/// What a node sees of the world during one callback.
pub const Env = struct {
    now_ns: u64,
    prng: *Prng,
    network: *Net,
    verifier_count: u8,

    pub fn send(env: *const Env, from: NodeId, to: NodeId, message: Message) void {
        env.network.send(env.prng, env.now_ns, from, to, message);
    }
};

/// Durable chain of block hashes and payloads, index = block number. Entry 0 is genesis.
pub const Chain = struct {
    hashes: []u64,
    payloads: []u64,

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64) !Chain {
        assert(block_count_max > 0);
        const hashes = try allocator.alloc(u64, block_count_max + 1);
        errdefer allocator.free(hashes);
        const payloads = try allocator.alloc(u64, block_count_max + 1);
        @memset(hashes, 0);
        @memset(payloads, 0);
        hashes[0] = genesis_hash;
        return .{ .hashes = hashes, .payloads = payloads };
    }

    pub fn deinit(chain: *Chain, allocator: std.mem.Allocator) void {
        allocator.free(chain.hashes);
        allocator.free(chain.payloads);
        chain.* = undefined;
    }

    pub fn capacity(chain: *const Chain) u64 {
        return chain.hashes.len - 1;
    }

    /// Append block `number` on top of `number - 1`; returns its hash.
    pub fn put(chain: *Chain, number: u64, payload: u64) u64 {
        assert(number > 0);
        assert(number <= chain.capacity());
        const hash = block_hash(chain.hashes[number - 1], number, payload);
        chain.hashes[number] = hash;
        chain.payloads[number] = payload;
        return hash;
    }
};

pub const Sequencer = struct {
    chain: Chain,
    head: u64 = 0,
    block_time_ns: u64,
    next_block_ns: u64,
    producing: bool = true,

    pub fn tick(sequencer: *Sequencer, env: *const Env) void {
        if (!sequencer.producing) return;
        if (env.now_ns < sequencer.next_block_ns) return;
        if (sequencer.head == sequencer.chain.capacity()) return;
        sequencer.next_block_ns += sequencer.block_time_ns;
        const number = sequencer.head + 1;
        const payload = env.prng.int(u64);
        const hash = sequencer.chain.put(number, payload);
        sequencer.head = number;
        var verifier: u8 = 0;
        while (verifier < env.verifier_count) : (verifier += 1) {
            env.send(node_sequencer, node_verifier_first + verifier, .{ .unsafe_block = .{
                .number = number,
                .payload = payload,
                .hash = hash,
            } });
        }
    }

    pub fn on_message(sequencer: *Sequencer, env: *const Env, from: NodeId, message: Message) void {
        const request = switch (message) {
            .sync_request => |request| request,
            else => return,
        };
        assert(request.number_first > 0);
        var number = request.number_first;
        const number_last = @min(sequencer.head, request.number_first + sync_blocks_max - 1);
        while (number <= number_last) : (number += 1) {
            env.send(node_sequencer, from, .{ .unsafe_block = .{
                .number = number,
                .payload = sequencer.chain.payloads[number],
                .hash = sequencer.chain.hashes[number],
            } });
        }
    }

    /// Crash-restart: the sequencer chain is durable; production resumes on schedule.
    pub fn restart(sequencer: *Sequencer, env: *const Env) void {
        sequencer.next_block_ns = @max(sequencer.next_block_ns, env.now_ns);
    }
};

pub const L1 = struct {
    blocks: []L1Block,
    head: u64 = 0,
    block_time_ns: u64,
    next_block_ns: u64,
    mempool: [l1_mempool_max]Batch = undefined,
    mempool_count: u8 = 0,

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64, block_time_ns: u64) !L1 {
        assert(block_time_ns > 0);
        const blocks = try allocator.alloc(L1Block, block_count_max + 1);
        blocks[0] = .{ .number = 0, .batch_count = 0, .batches = undefined };
        return .{ .blocks = blocks, .block_time_ns = block_time_ns, .next_block_ns = 0 };
    }

    pub fn deinit(l1: *L1, allocator: std.mem.Allocator) void {
        allocator.free(l1.blocks);
        l1.* = undefined;
    }

    pub fn tick(l1: *L1, env: *const Env) void {
        if (env.now_ns < l1.next_block_ns) return;
        if (l1.head + 1 == l1.blocks.len) return;
        l1.next_block_ns += l1.block_time_ns;
        const number = l1.head + 1;
        const block = &l1.blocks[number];
        block.number = number;
        block.batch_count = @min(l1.mempool_count, l1_batches_max);
        @memcpy(block.batches[0..block.batch_count], l1.mempool[0..block.batch_count]);
        std.mem.copyForwards(
            Batch,
            l1.mempool[0 .. l1.mempool_count - block.batch_count],
            l1.mempool[block.batch_count..l1.mempool_count],
        );
        l1.mempool_count -= block.batch_count;
        l1.head = number;
        env.send(node_l1, node_batcher, .{ .l1_block = block.* });
        var verifier: u8 = 0;
        while (verifier < env.verifier_count) : (verifier += 1) {
            env.send(node_l1, node_verifier_first + verifier, .{ .l1_block = block.* });
        }
    }

    pub fn on_message(l1: *L1, env: *const Env, from: NodeId, message: Message) void {
        switch (message) {
            .batch_submit => |batch| {
                assert(batch.count > 0);
                if (l1.mempool_count == l1_mempool_max) return; // Full: batcher retries.
                l1.mempool[l1.mempool_count] = batch;
                l1.mempool_count += 1;
            },
            .l1_request => |request| {
                if (request.number == 0 or request.number > l1.head) return;
                env.send(node_l1, from, .{ .l1_block = l1.blocks[request.number] });
            },
            else => {},
        }
    }
};

/// Follows L1 in order, re-requesting missed blocks. Embedded in batcher and verifier.
pub const L1Follower = struct {
    /// Next L1 block number to process.
    cursor: u64 = 1,
    head_known: u64 = 0,
    request_ns: u64 = 0,

    pub const request_timeout_ns: u64 = 1 * std.time.ns_per_s;

    /// Returns true when `block` is the next block to process.
    pub fn accept(follower: *L1Follower, env: *const Env, self: NodeId, block: L1Block) bool {
        assert(block.number > 0);
        follower.head_known = @max(follower.head_known, block.number);
        if (block.number == follower.cursor) {
            follower.cursor += 1;
            if (follower.cursor <= follower.head_known) follower.request(env, self);
            return true;
        }
        if (block.number > follower.cursor) follower.request(env, self);
        return false;
    }

    pub fn tick(follower: *L1Follower, env: *const Env, self: NodeId) void {
        if (follower.cursor > follower.head_known) return;
        if (env.now_ns < follower.request_ns + request_timeout_ns) return;
        follower.request(env, self);
    }

    fn request(follower: *L1Follower, env: *const Env, self: NodeId) void {
        follower.request_ns = env.now_ns;
        var number = follower.cursor;
        const number_last = @min(follower.head_known, follower.cursor + l1_request_burst - 1);
        while (number <= number_last) : (number += 1) {
            env.send(self, node_l1, .{ .l1_request = .{ .number = number } });
        }
    }
};

/// The block numbers `batch` adds on top of `head`, or null when it does not connect
/// (gap) or is fully known (duplicate). Derivation ignores such batches.
pub fn batch_extension(head: u64, batch: Batch) ?struct { first: u64, last: u64 } {
    assert(batch.count > 0 and batch.count <= batch_blocks_max);
    assert(batch.number_first > 0);
    if (batch.number_first > head + 1) return null;
    const last = batch.number_first + batch.count - 1;
    if (last <= head) return null;
    return .{ .first = head + 1, .last = last };
}

pub const Batcher = struct {
    follower: L1Follower = .{},
    /// Highest L2 block included contiguously on L1.
    confirmed: u64 = 0,
    /// Highest L2 block submitted to L1.
    submitted: u64 = 0,
    progress_ns: u64 = 0,
    next_submit_ns: u64 = 0,

    // Several blocks per batch, at most two batches per L1 block: L1 includes four.
    pub const submit_interval_ns: u64 = 6 * std.time.ns_per_s;
    pub const resubmit_timeout_ns: u64 = 60 * std.time.ns_per_s;

    pub fn tick(batcher: *Batcher, env: *const Env, sequencer: *const Sequencer) void {
        batcher.follower.tick(env, node_batcher);
        if (env.now_ns < batcher.next_submit_ns) return;
        batcher.next_submit_ns = env.now_ns + submit_interval_ns;
        batcher.submitted = @max(batcher.submitted, batcher.confirmed);
        assert(batcher.submitted >= batcher.confirmed);
        if (batcher.submitted == batcher.confirmed) batcher.progress_ns = env.now_ns;
        if (env.now_ns > batcher.progress_ns + resubmit_timeout_ns) {
            // Submissions were lost (dropped, mempool full, or partition): resubmit.
            batcher.submitted = batcher.confirmed;
            batcher.progress_ns = env.now_ns;
        }
        if (batcher.submitted - batcher.confirmed >= pipeline_blocks_max) return;
        if (batcher.submitted >= sequencer.head) return;
        var batch: Batch = .{
            .number_first = batcher.submitted + 1,
            .count = @intCast(@min(batch_blocks_max, sequencer.head - batcher.submitted)),
            .payloads = undefined,
        };
        for (batch.payloads[0..batch.count], 0..) |*payload, offset| {
            payload.* = sequencer.chain.payloads[batch.number_first + offset];
        }
        batcher.submitted += batch.count;
        env.send(node_batcher, node_l1, .{ .batch_submit = batch });
    }

    pub fn on_message(batcher: *Batcher, env: *const Env, from: NodeId, message: Message) void {
        assert(from == node_l1);
        const block = switch (message) {
            .l1_block => |block| block,
            else => return,
        };
        if (!batcher.follower.accept(env, node_batcher, block)) return;
        for (block.batches[0..block.batch_count]) |batch| {
            if (batch_extension(batcher.confirmed, batch)) |extension| {
                batcher.confirmed = extension.last;
                batcher.progress_ns = env.now_ns;
            }
        }
    }

    /// Crash-restart: the batcher keeps no state; it re-reads L1 from genesis.
    pub fn restart(batcher: *Batcher, env: *const Env) void {
        batcher.* = .{ .next_submit_ns = env.now_ns, .progress_ns = env.now_ns };
    }
};

pub const Checkpoint = struct {
    safe_head: u64 = 0,
    l1_cursor: u64 = 1,
};

pub const Verifier = struct {
    id: NodeId,
    chain: Chain,
    safe_head: u64 = 0,
    unsafe_head: u64 = 0,
    follower: L1Follower = .{},
    /// Last two durable checkpoints. A disk fault loses the latest write.
    checkpoint: Checkpoint = .{},
    checkpoint_previous: Checkpoint = .{},
    sequencer_head_known: u64 = 0,
    sync_ns: u64 = 0,
    /// Safety counters; any non-zero value is an invariant violation in an honest run.
    reorgs: u64 = 0,
    equivocations: u64 = 0,

    pub const sync_timeout_ns: u64 = 500 * std.time.ns_per_ms;

    pub fn tick(verifier: *Verifier, env: *const Env) void {
        verifier.follower.tick(env, verifier.id);
        if (verifier.sequencer_head_known <= verifier.unsafe_head) return;
        if (env.now_ns < verifier.sync_ns + sync_timeout_ns) return;
        verifier.sync(env);
    }

    pub fn on_message(verifier: *Verifier, env: *const Env, from: NodeId, message: Message) void {
        switch (message) {
            .unsafe_block => |block| {
                assert(from == node_sequencer);
                verifier.on_unsafe_block(env, block.number, block.payload, block.hash);
            },
            .l1_block => |block| {
                assert(from == node_l1);
                if (!verifier.follower.accept(env, verifier.id, block)) return;
                for (block.batches[0..block.batch_count]) |batch| verifier.derive(batch);
                verifier.checkpoint_previous = verifier.checkpoint;
                verifier.checkpoint = .{
                    .safe_head = verifier.safe_head,
                    .l1_cursor = verifier.follower.cursor,
                };
            },
            else => {},
        }
    }

    fn on_unsafe_block(
        verifier: *Verifier,
        env: *const Env,
        number: u64,
        payload: u64,
        hash: u64,
    ) void {
        assert(number > 0);
        verifier.sequencer_head_known = @max(verifier.sequencer_head_known, number);
        if (number <= verifier.unsafe_head) {
            if (verifier.chain.hashes[number] != hash) verifier.equivocations += 1;
            return;
        }
        if (number > verifier.unsafe_head + 1) {
            if (env.now_ns >= verifier.sync_ns + sync_timeout_ns) verifier.sync(env);
            return;
        }
        if (number > verifier.chain.capacity()) return;
        const parent_hash = verifier.chain.hashes[number - 1];
        if (block_hash(parent_hash, number, payload) != hash) {
            verifier.equivocations += 1;
            return;
        }
        _ = verifier.chain.put(number, payload);
        verifier.unsafe_head = number;
    }

    fn sync(verifier: *Verifier, env: *const Env) void {
        verifier.sync_ns = env.now_ns;
        env.send(verifier.id, node_sequencer, .{ .sync_request = .{
            .number_first = verifier.unsafe_head + 1,
        } });
    }

    fn derive(verifier: *Verifier, batch: Batch) void {
        assert(verifier.safe_head <= verifier.unsafe_head);
        const extension = batch_extension(verifier.safe_head, batch) orelse return;
        var number = extension.first;
        while (number <= extension.last) : (number += 1) {
            if (number > verifier.chain.capacity()) break;
            const payload = batch.payloads[number - batch.number_first];
            if (number <= verifier.unsafe_head) {
                if (verifier.chain.payloads[number] == payload) {
                    verifier.safe_head = number;
                    continue;
                }
                // L1 is the source of truth: drop the conflicting unsafe tail.
                verifier.reorgs += 1;
                verifier.unsafe_head = number - 1;
            }
            _ = verifier.chain.put(number, payload);
            verifier.unsafe_head = number;
            verifier.safe_head = number;
        }
        assert(verifier.safe_head <= verifier.unsafe_head);
    }

    /// Crash-restart from the durable checkpoint; a disk fault loses the latest write.
    pub fn restart(verifier: *Verifier, disk_fault: bool) void {
        const checkpoint = if (disk_fault) verifier.checkpoint_previous else verifier.checkpoint;
        assert(checkpoint.l1_cursor > 0);
        verifier.safe_head = checkpoint.safe_head;
        verifier.unsafe_head = checkpoint.safe_head;
        verifier.follower = .{ .cursor = checkpoint.l1_cursor };
        verifier.checkpoint = checkpoint;
        verifier.checkpoint_previous = checkpoint;
        verifier.sequencer_head_known = 0;
        verifier.sync_ns = 0;
    }
};

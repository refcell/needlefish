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
const codec = @import("codec.zig");
const B256 = @import("../../common/primitives/root.zig").B256;

pub const batch_blocks_max = 8;
pub const l1_batches_max = 8;
pub const sync_blocks_max = 16;
pub const l1_request_burst = 4;
pub const l1_mempool_max = 32;
pub const pipeline_blocks_max = 32;

pub const node_l1: NodeId = 0;
pub const node_sequencer: NodeId = 1;
pub const node_batcher: NodeId = 2;
pub const node_verifier_first: NodeId = 3;

pub const genesis_hash: u64 = codec.l2_genesis_hash;
pub const l1_genesis_hash: u64 = codec.l1_genesis_hash;
/// Deepest L1 reorg the fault injector produces. Followers must handle any depth.
pub const l1_reorg_depth_max = 3;
/// Mempool storage: the admission limit plus room to re-inject every transaction of a
/// maximal reorg, as geth does, so a reorg never silently loses an account nonce.
pub const l1_mempool_capacity = l1_mempool_max + l1_reorg_depth_max * l1_batches_max;

comptime {
    assert(l1_batches_max <= codec.transactions_max);
    assert(batch_blocks_max <= codec.blocks_max);
}

pub fn block_hash(parent_hash: u64, number: u64, payload: u64) u64 {
    assert(number > 0);
    const words = [3]u64{ parent_hash, number, payload };
    return std.hash.Wyhash.hash(0, std.mem.asBytes(&words));
}

/// One batcher transaction on L1: an index into the shared `codec.TxPool`. Nodes learn
/// its blocks only by decoding the bytes with the real protocol codecs.
pub const Batch = struct {
    tx_index: u32,
    /// `codec.sender_batcher`, or `codec.sender_attacker` for forged inbox spam.
    sender: u8 = codec.sender_batcher,
    /// Account nonce for transactions from the real batcher's account. L1 includes them
    /// strictly in nonce order; model and attacker transactions carry none.
    nonce: ?u64 = null,
    /// Mined once, then orphaned by an L1 reorg and re-injected into the mempool.
    reorged: bool = false,
};

/// Which pending transactions a mempool eviction may drop.
pub const EvictPolicy = enum { any, never_reorged };

pub const SubmitResult = enum { accepted, replaced, nonce_too_low, mempool_full };

pub const L1Block = struct {
    number: u64,
    /// Random per block version: a reorged block at the same height gets a new hash.
    hash: u64,
    parent_hash: u64,
    batch_count: u8,
    batches: [l1_batches_max]Batch,
};

pub const Message = union(enum) {
    /// `sync`: an answer to a `sync_request` (catch-up), not gossip of a new block.
    unsafe_block: struct { number: u64, payload: u64, hash: u64, sync: bool = false },
    sync_request: struct { number_first: u64 },
    batch_submit: Batch,
    l1_block: L1Block,
    l1_request: struct { number: u64 },
};

pub const Net = network_module.Network(Message);

/// What a node sees of the world during one callback.
pub const Env = struct {
    /// The node's local clock: global time plus its (possibly skewed) offset.
    now_ns: u64,
    /// Global simulated time; only the network uses it.
    global_ns: u64,
    prng: *Prng,
    network: *Net,
    verifier_count: u8,
    tx_pool: *codec.TxPool,

    pub fn send(env: *const Env, from: NodeId, to: NodeId, message: Message) void {
        env.network.send(env.prng, env.global_ns, from, to, message);
    }
};

/// Durable chain of block hashes, payloads, and L1 origins, index = block number. Entry 0
/// is genesis. Only the sequencer fills `origins`; verifiers never read them.
pub const Chain = struct {
    hashes: []u64,
    payloads: []u64,
    origins: []codec.Origin,
    /// Real execution (`Config.real_execution`, sequencer chain only): the block hashes
    /// and state roots the execution lane's engine computed for the same blocks, filled
    /// by `real_execution.Reference`. Batches then carry real hashes and signed txs.
    real: bool = false,
    real_hashes: []B256,
    real_state_roots: []B256,

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64) !Chain {
        assert(block_count_max > 0);
        const hashes = try allocator.alloc(u64, block_count_max + 1);
        errdefer allocator.free(hashes);
        const payloads = try allocator.alloc(u64, block_count_max + 1);
        errdefer allocator.free(payloads);
        const origins = try allocator.alloc(codec.Origin, block_count_max + 1);
        errdefer allocator.free(origins);
        const real_hashes = try allocator.alloc(B256, block_count_max + 1);
        errdefer allocator.free(real_hashes);
        const real_state_roots = try allocator.alloc(B256, block_count_max + 1);
        @memset(hashes, 0);
        @memset(payloads, 0);
        @memset(origins, codec.genesis_origin);
        @memset(real_hashes, .zero);
        @memset(real_state_roots, .zero);
        hashes[0] = genesis_hash;
        return .{
            .hashes = hashes,
            .payloads = payloads,
            .origins = origins,
            .real_hashes = real_hashes,
            .real_state_roots = real_state_roots,
        };
    }

    pub fn deinit(chain: *Chain, allocator: std.mem.Allocator) void {
        allocator.free(chain.hashes);
        allocator.free(chain.payloads);
        allocator.free(chain.origins);
        allocator.free(chain.real_hashes);
        allocator.free(chain.real_state_roots);
        chain.* = undefined;
    }

    pub fn tx_format(chain: *const Chain) codec.TxFormat {
        return if (chain.real) .signed else .model;
    }

    /// The hash batches and RPC name for block `number`: real or the widened model word.
    pub fn batch_hash(chain: *const Chain, number: u64) B256 {
        assert(number <= chain.capacity());
        if (!chain.real) return codec.word_hash(chain.hashes[number]);
        assert(number == 0 or !chain.real_hashes[number].is_zero());
        return chain.real_hashes[number];
    }

    /// The real hashes of blocks `first .. first + count` for `codec.Encoder.encode`, or
    /// null without real execution.
    pub fn real_slice(chain: *const Chain, first: u64, count: u64) ?[]const B256 {
        if (!chain.real) return null;
        assert(first + count <= chain.real_hashes.len);
        return chain.real_hashes[first..][0..count];
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
    /// Byzantine mode for checker tests: at this height, gossip a conflicting block to
    /// the first verifier. Honest runs leave it null.
    equivocate_at: ?u64 = null,

    /// `l1` is read directly (the model sequencer's L1 client) only to pick L1 origins.
    pub fn tick(sequencer: *Sequencer, env: *const Env, l1: *const L1) void {
        if (!sequencer.producing) return;
        if (env.now_ns < sequencer.next_block_ns) return;
        if (sequencer.head == sequencer.chain.capacity()) return;
        sequencer.next_block_ns += sequencer.block_time_ns;
        const number = sequencer.head + 1;
        const payload = env.prng.int(u64);
        const origins = sequencer.chain.origins;
        origins[number] = next_origin(origins[number - 1], number, l1);
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
        if (sequencer.equivocate_at == number) {
            const forged = payload +% 1;
            const parent_hash = sequencer.chain.hashes[number - 1];
            env.send(node_sequencer, node_verifier_first, .{ .unsafe_block = .{
                .number = number,
                .payload = forged,
                .hash = block_hash(parent_hash, number, forged),
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
                .sync = true,
            } });
        }
    }

    /// The L1 origin of block `number`: the parent's, or the next L1 block once it is final
    /// (deeper than any L1 reorg) and not newer than the block. One epoch step per block,
    /// as the derivation rules require; L2 time never runs behind the origin's time.
    fn next_origin(parent: codec.Origin, number: u64, l1: *const L1) codec.Origin {
        assert(number > 0);
        assert(parent.number <= l1.head);
        const candidate = parent.number + 1;
        const final = candidate + l1_reorg_depth_max <= l1.head;
        const due = candidate * codec.l1_block_time_s <= number * codec.l2_block_time_s;
        if (!final or !due) {
            return .{
                .number = parent.number,
                .hash = parent.hash,
                .sequence_number = parent.sequence_number + 1,
            };
        }
        assert(l1.blocks[candidate].parent_hash == parent.hash);
        return .{ .number = candidate, .hash = l1.blocks[candidate].hash };
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
    mempool: [l1_mempool_capacity]Batch = undefined,
    mempool_count: u8 = 0,
    /// Congestion: each block includes between this many and `l1_batches_max` batcher
    /// transactions, so a channel's frames can spill into later blocks.
    block_txs_min: u8 = l1_batches_max,
    reorgs: u64 = 0,
    /// Mined nonce of the real batcher's account after each block, index = number.
    nonce_after: []u64,

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64, block_time_ns: u64) !L1 {
        assert(block_time_ns > 0);
        const blocks = try allocator.alloc(L1Block, block_count_max + 1);
        errdefer allocator.free(blocks);
        const nonce_after = try allocator.alloc(u64, block_count_max + 1);
        nonce_after[0] = 0;
        blocks[0] = .{
            .number = 0,
            .hash = l1_genesis_hash,
            .parent_hash = 0,
            .batch_count = 0,
            .batches = undefined,
        };
        return .{
            .blocks = blocks,
            .nonce_after = nonce_after,
            .block_time_ns = block_time_ns,
            .next_block_ns = 0,
        };
    }

    pub fn deinit(l1: *L1, allocator: std.mem.Allocator) void {
        allocator.free(l1.blocks);
        allocator.free(l1.nonce_after);
        l1.* = undefined;
    }

    pub fn tick(l1: *L1, env: *const Env) void {
        if (env.now_ns < l1.next_block_ns) return;
        if (l1.head + 1 == l1.blocks.len) return;
        l1.next_block_ns += l1.block_time_ns;
        l1.mine(env);
    }

    /// Mines the next block from the mempool and broadcasts it.
    fn mine(l1: *L1, env: *const Env) void {
        assert(l1.head + 1 < l1.blocks.len);
        const number = l1.head + 1;
        const block = &l1.blocks[number];
        block.number = number;
        block.parent_hash = l1.blocks[l1.head].hash;
        block.hash = env.prng.int(u64) | 1;
        assert(l1.block_txs_min >= 1 and l1.block_txs_min <= l1_batches_max);
        const capacity: u8 = if (l1.block_txs_min == l1_batches_max)
            l1_batches_max
        else
            @intCast(env.prng.range(l1.block_txs_min, l1_batches_max));
        l1.nonce_after[number] = l1.include_mempool(block, l1.nonce_after[l1.head], capacity);
        l1.head = number;
        env.send(node_l1, node_batcher, .{ .l1_block = block.* });
        var verifier: u8 = 0;
        while (verifier < env.verifier_count) : (verifier += 1) {
            env.send(node_l1, node_verifier_first + verifier, .{ .l1_block = block.* });
        }
    }

    /// Moves includable mempool entries into `block`, in order. Nonce-carrying entries go
    /// in only at the next expected nonce; stale ones (already mined) are dropped and
    /// future ones wait. Returns the mined nonce after the block.
    fn include_mempool(l1: *L1, block: *L1Block, nonce_start: u64, capacity: u8) u64 {
        assert(capacity >= 1 and capacity <= l1_batches_max);
        var nonce_next = nonce_start;
        block.batch_count = 0;
        var kept: u8 = 0;
        // Each pass includes at least one entry or stops; nonces can unlock waiting ones.
        for (0..l1_batches_max + 1) |_| {
            kept = 0;
            var included_any = false;
            for (l1.mempool[0..l1.mempool_count]) |batch| {
                const stale = if (batch.nonce) |nonce| nonce < nonce_next else false;
                if (stale) continue;
                const ready = if (batch.nonce) |nonce| nonce == nonce_next else true;
                if (ready and block.batch_count < capacity) {
                    block.batches[block.batch_count] = batch;
                    block.batch_count += 1;
                    if (batch.nonce != null) nonce_next += 1;
                    included_any = true;
                } else {
                    l1.mempool[kept] = batch;
                    kept += 1;
                }
            }
            l1.mempool_count = kept;
            if (!included_any or block.batch_count == capacity) break;
        }
        assert(nonce_next >= nonce_start);
        assert(block.batch_count <= l1_batches_max);
        return nonce_next;
    }

    /// The real batcher account's mined nonce at the head.
    pub fn nonce_mined(l1: *const L1) u64 {
        return l1.nonce_after[l1.head];
    }

    /// Mined nonce plus consecutive pending nonces in the mempool (`pending` tag).
    pub fn nonce_pending(l1: *const L1) u64 {
        var nonce = l1.nonce_mined();
        for (0..l1_mempool_capacity + 1) |_| {
            const found = for (l1.mempool[0..l1.mempool_count]) |batch| {
                if (batch.nonce == nonce) break true;
            } else false;
            if (!found) break;
            nonce += 1;
        }
        return nonce;
    }

    /// `eth_sendRawTransaction` for the real batcher: replace a pending entry with the
    /// same nonce (fee bump), otherwise queue it.
    pub fn submit_nonced(l1: *L1, tx_index: u32, nonce: u64) SubmitResult {
        if (nonce < l1.nonce_mined()) return .nonce_too_low;
        for (l1.mempool[0..l1.mempool_count]) |*batch| {
            if (batch.nonce == nonce) {
                batch.tx_index = tx_index;
                return .replaced;
            }
        }
        if (l1.mempool_count >= l1_mempool_max) return .mempool_full;
        l1.mempool[l1.mempool_count] = .{ .tx_index = tx_index, .nonce = nonce };
        l1.mempool_count += 1;
        return .accepted;
    }

    /// Orphan the top `depth` blocks and immediately mine a replacement branch of the
    /// same height, as a heavier fork would arrive on L1. Orphaned transactions go back
    /// to the mempool, so the new branch re-includes them where nonces allow.
    /// Each orphaned transaction is lost instead of re-injected with `loss_ppm`, as when
    /// the new branch's L1 nodes never saw it.
    pub fn reorg(l1: *L1, env: *const Env, depth: u64, prng: *Prng, loss_ppm: u32) void {
        const height = l1.head;
        l1.orphan(depth, prng, loss_ppm);
        for (0..depth) |_| l1.mine(env);
        assert(l1.head == height);
    }

    /// Drops the top `depth` blocks; their transactions return to the mempool front.
    fn orphan(l1: *L1, depth: u64, prng: *Prng, loss_ppm: u32) void {
        assert(depth > 0 and depth <= l1_reorg_depth_max);
        assert(depth <= l1.head);
        const restored_max = l1_reorg_depth_max * l1_batches_max;
        var merged: [restored_max + l1_mempool_capacity]Batch = undefined;
        var count: usize = 0;
        var number = l1.head + 1 - depth;
        while (number <= l1.head) : (number += 1) {
            const block = &l1.blocks[number];
            for (block.batches[0..block.batch_count]) |batch| {
                // A pending replacement for the same nonce wins over the orphaned one.
                if (batch.nonce != null and l1.has_nonce(batch.nonce.?)) continue;
                if (prng.chance(loss_ppm, 1_000_000)) continue;
                merged[count] = batch;
                merged[count].reorged = true;
                count += 1;
            }
        }
        assert(count <= restored_max);
        @memcpy(merged[count..][0..l1.mempool_count], l1.mempool[0..l1.mempool_count]);
        count += l1.mempool_count;
        // Overflow drops nonce-less (model) transactions from the back: their senders
        // retry. Nonce-carrying ones number at most the txmgr window plus one reorg.
        var index = count;
        while (count > l1_mempool_capacity and index > 0) {
            index -= 1;
            if (merged[index].nonce != null) continue;
            std.mem.copyForwards(Batch, merged[index .. count - 1], merged[index + 1 .. count]);
            count -= 1;
        }
        assert(count <= l1_mempool_capacity);
        l1.mempool_count = @intCast(count);
        @memcpy(l1.mempool[0..count], merged[0..count]);
        l1.head -= depth;
        l1.reorgs += 1;
    }

    /// Mempool eviction: a random pending transaction disappears. Returns whether one did.
    /// With `never_reorged`, a pick that a reorg re-injected survives (same draw count).
    pub fn evict(l1: *L1, prng: *Prng, policy: EvictPolicy) bool {
        if (l1.mempool_count == 0) return false;
        const index: usize = @intCast(prng.below(l1.mempool_count));
        assert(index < l1.mempool_count);
        if (policy == .never_reorged and l1.mempool[index].reorged) return false;
        std.mem.copyForwards(
            Batch,
            l1.mempool[index .. l1.mempool_count - 1],
            l1.mempool[index + 1 .. l1.mempool_count],
        );
        l1.mempool_count -= 1;
        return true;
    }

    fn has_nonce(l1: *const L1, nonce: u64) bool {
        for (l1.mempool[0..l1.mempool_count]) |batch| {
            if (batch.nonce == nonce) return true;
        }
        return false;
    }

    pub fn on_message(l1: *L1, env: *const Env, from: NodeId, message: Message) void {
        switch (message) {
            .batch_submit => |batch| {
                assert(batch.tx_index < env.tx_pool.count);
                if (l1.mempool_count >= l1_mempool_max) return; // Full: batcher retries.
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

/// Follows L1 in order, re-requesting missed blocks and detecting reorgs by hash.
/// Embedded in batcher and verifier; `hashes` is durable across restarts.
pub const L1Follower = struct {
    /// Hash of every processed L1 block, index = number.
    hashes: []u64,
    /// Next L1 block number to process.
    cursor: u64 = 1,
    head_known: u64 = 0,
    request_ns: u64 = 0,
    rewinds: u64 = 0,

    pub const request_timeout_ns: u64 = 1 * std.time.ns_per_s;

    pub const Accepted = struct {
        /// Owner must restore its state to just after L1 block `rewind_to - 1`.
        rewind_to: ?u64 = null,
        /// Owner must process the block (after any rewind).
        process: bool = false,
    };

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64) !L1Follower {
        const hashes = try allocator.alloc(u64, block_count_max + 1);
        @memset(hashes, 0);
        hashes[0] = l1_genesis_hash;
        return .{ .hashes = hashes };
    }

    pub fn deinit(follower: *L1Follower, allocator: std.mem.Allocator) void {
        allocator.free(follower.hashes);
        follower.* = undefined;
    }

    /// Restart from a durable cursor: hashes below it are on disk.
    pub fn reset(follower: *L1Follower, cursor: u64) void {
        assert(cursor > 0);
        follower.* = .{ .hashes = follower.hashes, .cursor = cursor, .rewinds = follower.rewinds };
    }

    pub fn accept(follower: *L1Follower, env: *const Env, self: NodeId, block: L1Block) Accepted {
        assert(block.number > 0);
        if (block.number >= follower.hashes.len) return .{};
        follower.head_known = @max(follower.head_known, block.number);
        var result: Accepted = .{};
        if (block.number < follower.cursor) {
            if (follower.hashes[block.number] == block.hash) return .{};
            // Reorg: this height changed under us. Re-derive from here.
            follower.cursor = block.number;
            result.rewind_to = block.number;
        }
        if (block.number > follower.cursor) {
            follower.request(env, self);
            return result;
        }
        assert(block.number == follower.cursor);
        if (block.parent_hash != follower.hashes[block.number - 1]) {
            // The reorg goes deeper than this block: step back and fetch the parent.
            assert(block.number > 1); // Genesis never reorgs.
            follower.cursor = block.number - 1;
            result.rewind_to = follower.cursor;
            follower.rewinds += 1;
            follower.request(env, self);
            return result;
        }
        if (result.rewind_to != null) follower.rewinds += 1;
        follower.hashes[block.number] = block.hash;
        follower.cursor += 1;
        if (follower.cursor <= follower.head_known) follower.request(env, self);
        result.process = true;
        return result;
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
pub fn batch_extension(head: u64, batch: codec.Blocks) ?struct { first: u64, last: u64 } {
    assert(batch.count > 0 and batch.count <= codec.blocks_max);
    assert(batch.number_first > 0);
    if (batch.number_first > head + 1) return null;
    const last = batch.number_first + batch.count - 1;
    if (last <= head) return null;
    return .{ .first = head + 1, .last = last };
}

pub const batch_buffer_capacity = 128;

/// Batches seen on L1, kept until they can extend the head: the pre-Holocene batch queue
/// keeps a batch that starts beyond the next block (a "future" batch) instead of dropping
/// it, so a channel that lands early (a byzantine replay of honest content, a batcher
/// repost) applies once the gap before it fills, even long after it left the
/// channel-timeout window. The real driver derives this way; without it the model
/// verifiers would lag a batcher that follows the real verifier's safe head.
///
/// Durable with the owner's L1 cursor: entries from L1 blocks at or after a rewound or
/// restored cursor are dropped, since those blocks are read again. When full, the entry
/// ending lowest goes first: it is the most likely to be behind every head already.
pub const BatchBuffer = struct {
    entries: [batch_buffer_capacity]Entry = undefined,
    count: u32 = 0,

    const Entry = struct { l1_number: u64, blocks: codec.Blocks };

    fn same(a: *const codec.Blocks, b: *const codec.Blocks) bool {
        if (a.number_first != b.number_first or a.count != b.count) return false;
        return std.mem.eql(u64, a.payloads[0..a.count], b.payloads[0..b.count]);
    }

    fn last(blocks: *const codec.Blocks) u64 {
        assert(blocks.count > 0);
        return blocks.number_first + blocks.count - 1;
    }

    /// Records `blocks` seen in L1 block `l1_number`; a replayed copy keeps the earliest.
    pub fn put(buffer: *BatchBuffer, l1_number: u64, blocks: *const codec.Blocks) void {
        assert(buffer.count <= batch_buffer_capacity);
        for (buffer.entries[0..buffer.count]) |*entry| {
            if (!same(&entry.blocks, blocks)) continue;
            entry.l1_number = @min(entry.l1_number, l1_number);
            return;
        }
        if (buffer.count == batch_buffer_capacity) {
            var lowest: usize = 0;
            for (buffer.entries[0..buffer.count], 0..) |*entry, index| {
                if (last(&entry.blocks) < last(&buffer.entries[lowest].blocks)) lowest = index;
            }
            buffer.remove(lowest);
        }
        buffer.entries[buffer.count] = .{ .l1_number = l1_number, .blocks = blocks.* };
        buffer.count += 1;
        assert(buffer.count <= batch_buffer_capacity);
    }

    fn remove(buffer: *BatchBuffer, index: usize) void {
        assert(index < buffer.count);
        buffer.count -= 1;
        buffer.entries[index] = buffer.entries[buffer.count];
    }

    /// Drops entries from L1 blocks numbered `l1_number` or higher.
    pub fn drop_from(buffer: *BatchBuffer, l1_number: u64) void {
        var index: usize = 0;
        while (index < buffer.count) {
            if (buffer.entries[index].l1_number >= l1_number) {
                buffer.remove(index);
            } else {
                index += 1;
            }
        }
        for (buffer.entries[0..buffer.count]) |*entry| assert(entry.l1_number < l1_number);
    }

    /// The next entry that extends `head`, if any.
    pub fn next(buffer: *const BatchBuffer, head: u64) ?*const codec.Blocks {
        for (buffer.entries[0..buffer.count]) |*entry| {
            if (batch_extension(head, entry.blocks) != null) return &entry.blocks;
        }
        return null;
    }
};

/// Durable copies of processed L1 blocks, index = number, and derivation over the
/// channel-timeout window ending at a block (see `codec.derive_window`).
pub const L1Store = struct {
    blocks: []L1Block,

    comptime {
        assert(l1_batches_max <= codec.transactions_max);
    }

    pub fn init(allocator: std.mem.Allocator, block_count_max: u64) !L1Store {
        return .{ .blocks = try allocator.alloc(L1Block, block_count_max + 1) };
    }

    pub fn deinit(store: *L1Store, allocator: std.mem.Allocator) void {
        allocator.free(store.blocks);
        store.* = undefined;
    }

    /// Stores `block` and derives the window ending at it.
    pub fn derive(
        store: *L1Store,
        decoder: *codec.Decoder,
        pool: *const codec.TxPool,
        block: *const L1Block,
        sender_check: bool,
    ) codec.Derived {
        assert(block.number > 0 and block.number < store.blocks.len);
        store.blocks[block.number] = block.*;
        const oldest = block.number -| codec.channel_timeout_blocks;
        const first = @max(oldest, 1);
        var window: [codec.window_blocks_max]codec.WindowBlock = undefined;
        const length: usize = @intCast(block.number - first + 1);
        assert(length <= window.len);
        for (window[0..length], first..) |*entry, number| {
            const stored = &store.blocks[number];
            entry.* = .{
                .number = number,
                .hash = stored.hash,
                .parent_hash = stored.parent_hash,
                .count = stored.batch_count,
            };
            for (stored.batches[0..stored.batch_count], 0..) |batch, index| {
                entry.tx_indexes[index] = batch.tx_index;
                entry.senders[index] = batch.sender;
            }
        }
        return codec.derive_window(decoder, pool, window[0..length], sender_check);
    }
};

pub const Batcher = struct {
    follower: L1Follower,
    store: L1Store,
    encoder: codec.Encoder,
    decoder: codec.Decoder,
    /// Confirmed head after each processed L1 block, for rewinds on L1 reorgs.
    confirmed_at: []u64,
    /// Highest L2 block included contiguously on L1.
    confirmed: u64 = 0,
    /// Our batches seen on L1, so early channels count once the gap fills.
    batches: BatchBuffer = .{},
    /// Highest L2 block submitted to L1.
    submitted: u64 = 0,
    progress_ns: u64 = 0,
    next_submit_ns: u64 = 0,
    /// Byzantine mode for checker tests: corrupt the tx data of this submission. Honest
    /// runs leave it null.
    corrupt_tx: ?u32 = null,
    /// False when the real batcher service submits; this model then only observes L1.
    submitting: bool = true,

    // Several blocks per batch, at most two batches per L1 block: L1 includes four.
    pub const submit_interval_ns: u64 = 6 * std.time.ns_per_s;
    pub const resubmit_timeout_ns: u64 = 60 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, l1_block_count_max: u64, frame_size: u32) !Batcher {
        var follower = try L1Follower.init(allocator, l1_block_count_max);
        errdefer follower.deinit(allocator);
        var store = try L1Store.init(allocator, l1_block_count_max);
        errdefer store.deinit(allocator);
        const confirmed_at = try allocator.alloc(u64, l1_block_count_max + 1);
        errdefer allocator.free(confirmed_at);
        @memset(confirmed_at, 0);
        var encoder = try codec.Encoder.init(allocator, 0x6261_7463_6865_7200, frame_size);
        errdefer encoder.deinit(allocator);
        const decoder = try codec.Decoder.init(allocator);
        return .{
            .follower = follower,
            .store = store,
            .encoder = encoder,
            .decoder = decoder,
            .confirmed_at = confirmed_at,
        };
    }

    pub fn deinit(batcher: *Batcher, allocator: std.mem.Allocator) void {
        batcher.follower.deinit(allocator);
        batcher.store.deinit(allocator);
        batcher.encoder.deinit(allocator);
        batcher.decoder.deinit(allocator);
        allocator.free(batcher.confirmed_at);
        batcher.* = undefined;
    }

    pub fn tick(batcher: *Batcher, env: *const Env, sequencer: *const Sequencer) void {
        batcher.follower.tick(env, node_batcher);
        if (!batcher.submitting) return;
        if (env.now_ns < batcher.next_submit_ns) return;
        batcher.next_submit_ns = env.now_ns + submit_interval_ns;
        batcher.submitted = @max(batcher.submitted, batcher.confirmed);
        assert(batcher.submitted >= batcher.confirmed);
        if (batcher.submitted == batcher.confirmed) batcher.progress_ns = env.now_ns;
        if (env.now_ns > batcher.progress_ns + resubmit_timeout_ns) {
            // Submissions were lost (dropped, mempool full, partition, reorg): resubmit.
            batcher.submitted = batcher.confirmed;
            batcher.progress_ns = env.now_ns;
        }
        if (batcher.submitted - batcher.confirmed >= pipeline_blocks_max) return;
        if (batcher.submitted >= sequencer.head) return;
        const count: u8 = @intCast(@min(batch_blocks_max, sequencer.head - batcher.submitted));
        const first = batcher.submitted + 1;
        const frames = batcher.encoder.encode(
            first,
            sequencer.chain.hashes[first - 1 .. first + count],
            sequencer.chain.real_slice(first - 1, count + 1),
            sequencer.chain.payloads[first .. first + count],
            sequencer.chain.origins[first .. first + count],
        );
        batcher.submitted += count;
        for (frames) |data| {
            // A full pool ends submissions; the liveness checker reports the stall.
            const tx_index = env.tx_pool.append(data) orelse return;
            if (batcher.corrupt_tx == tx_index) {
                const stored = env.tx_pool.get_mutable(tx_index);
                stored[stored.len / 2] ^= 0x5a;
            }
            env.send(node_batcher, node_l1, .{ .batch_submit = .{ .tx_index = tx_index } });
        }
    }

    pub fn on_message(batcher: *Batcher, env: *const Env, from: NodeId, message: Message) void {
        assert(from == node_l1);
        const block = switch (message) {
            .l1_block => |block| block,
            else => return,
        };
        const accepted = batcher.follower.accept(env, node_batcher, block);
        if (accepted.rewind_to) |cursor| {
            batcher.confirmed = batcher.confirmed_at[cursor - 1];
            batcher.batches.drop_from(cursor);
            batcher.progress_ns = env.now_ns;
        }
        if (!accepted.process) return;
        // Like op-batcher, track only our own transactions (the derive sender filter).
        const derived = batcher.store.derive(&batcher.decoder, env.tx_pool, &block, true);
        for (derived.blocks[0..derived.count]) |*blocks| batcher.batches.put(block.number, blocks);
        for (0..batch_buffer_capacity) |_| {
            const blocks = batcher.batches.next(batcher.confirmed) orelse break;
            batcher.confirmed = batch_extension(batcher.confirmed, blocks.*).?.last;
            batcher.progress_ns = env.now_ns;
        }
        batcher.confirmed_at[block.number] = batcher.confirmed;
    }

    /// Crash-restart: the batcher keeps no state; it re-reads L1 from genesis.
    pub fn restart(batcher: *Batcher, env: *const Env) void {
        batcher.follower.reset(1);
        batcher.* = .{
            .follower = batcher.follower,
            .store = batcher.store,
            .encoder = batcher.encoder,
            .decoder = batcher.decoder,
            .confirmed_at = batcher.confirmed_at,
            .next_submit_ns = env.now_ns,
            .progress_ns = env.now_ns,
            .corrupt_tx = batcher.corrupt_tx,
            .submitting = batcher.submitting,
        };
    }
};

/// Written atomically after each L1 block. It must name the L1 block it reflects
/// (`l1_hash`): the per-block arrays may already hold a newer version of that height,
/// and restoring `safe_head` without the matching hash leaves the follower believing
/// it derived a block it did not (found by the swarm: seed 56, L1 reorg + disk fault).
pub const Checkpoint = struct {
    safe_head: u64 = 0,
    l1_cursor: u64 = 1,
    l1_hash: u64 = l1_genesis_hash,
};

pub const Verifier = struct {
    id: NodeId,
    chain: Chain,
    safe_head: u64 = 0,
    unsafe_head: u64 = 0,
    follower: L1Follower,
    store: L1Store,
    decoder: codec.Decoder,
    /// Safe head after each processed L1 block (durable), for rewinds on L1 reorgs.
    safe_at: []u64,
    /// Batches seen on L1 (durable with the L1 cursor), applied once they extend.
    batches: BatchBuffer = .{},
    /// Last two durable checkpoints. A disk fault loses the latest write.
    checkpoint: Checkpoint = .{},
    checkpoint_previous: Checkpoint = .{},
    sequencer_head_known: u64 = 0,
    sync_ns: u64 = 0,
    /// Safety counters; any non-zero value is an invariant violation in an honest run.
    reorgs: u64 = 0,
    equivocations: u64 = 0,
    /// L1 transactions that failed to decode; the honest batcher never writes one.
    invalid_batches: u64 = 0,
    /// Derivation accepts inbox transactions only from the system config batcher.
    /// Negative tests disable the check to prove the checkers notice.
    sender_check: bool = true,

    pub const sync_timeout_ns: u64 = 500 * std.time.ns_per_ms;

    pub fn init(
        allocator: std.mem.Allocator,
        id: NodeId,
        block_count_max: u64,
        l1_block_count_max: u64,
    ) !Verifier {
        assert(id >= node_verifier_first);
        var chain = try Chain.init(allocator, block_count_max);
        errdefer chain.deinit(allocator);
        var follower = try L1Follower.init(allocator, l1_block_count_max);
        errdefer follower.deinit(allocator);
        var store = try L1Store.init(allocator, l1_block_count_max);
        errdefer store.deinit(allocator);
        const safe_at = try allocator.alloc(u64, l1_block_count_max + 1);
        errdefer allocator.free(safe_at);
        @memset(safe_at, 0);
        const decoder = try codec.Decoder.init(allocator);
        return .{
            .id = id,
            .chain = chain,
            .follower = follower,
            .store = store,
            .decoder = decoder,
            .safe_at = safe_at,
        };
    }

    pub fn deinit(verifier: *Verifier, allocator: std.mem.Allocator) void {
        verifier.chain.deinit(allocator);
        verifier.follower.deinit(allocator);
        verifier.store.deinit(allocator);
        verifier.decoder.deinit(allocator);
        allocator.free(verifier.safe_at);
        verifier.* = undefined;
    }

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
                const accepted = verifier.follower.accept(env, verifier.id, block);
                if (accepted.rewind_to) |cursor| {
                    // L1 reorg: safe blocks derived from orphaned L1 blocks are no longer
                    // safe. Unsafe blocks stay; re-derivation will confirm or replace them.
                    verifier.safe_head = verifier.safe_at[cursor - 1];
                    verifier.batches.drop_from(cursor);
                    // After a restart the unsafe head may sit below what the per-block
                    // record says was derived. Those blocks are on disk (the chain is
                    // durable), so take them back rather than leave a derivation gap.
                    verifier.unsafe_head = @max(verifier.unsafe_head, verifier.safe_head);
                }
                if (!accepted.process) return;
                verifier.derive_l1_block(env, &block);
                verifier.safe_at[block.number] = verifier.safe_head;
                verifier.checkpoint_previous = verifier.checkpoint;
                verifier.checkpoint = .{
                    .safe_head = verifier.safe_head,
                    .l1_cursor = verifier.follower.cursor,
                    .l1_hash = block.hash,
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

    /// Derives one L1 block through the derive lane's retrieval, frame queue, and
    /// channel bank, replaying the channel-timeout window that ends at it.
    fn derive_l1_block(verifier: *Verifier, env: *const Env, block: *const L1Block) void {
        assert(block.batch_count <= l1_batches_max);
        const derived = verifier.store.derive(
            &verifier.decoder,
            env.tx_pool,
            block,
            verifier.sender_check,
        );
        verifier.invalid_batches += derived.invalid;
        for (derived.blocks[0..derived.count]) |*blocks| {
            verifier.batches.put(block.number, blocks);
        }
        // Each step raises the safe head, so the buffer runs dry within its capacity.
        for (0..batch_buffer_capacity) |_| {
            const blocks = verifier.batches.next(verifier.safe_head) orelse break;
            verifier.derive(blocks.*);
        }
    }

    fn derive(verifier: *Verifier, batch: codec.Blocks) void {
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
        verifier.follower.reset(checkpoint.l1_cursor);
        verifier.batches.drop_from(checkpoint.l1_cursor);
        verifier.follower.hashes[checkpoint.l1_cursor - 1] = checkpoint.l1_hash;
        verifier.safe_at[checkpoint.l1_cursor - 1] = checkpoint.safe_head;
        verifier.checkpoint = checkpoint;
        verifier.checkpoint_previous = checkpoint;
        verifier.sequencer_head_known = 0;
        verifier.sync_ns = 0;
    }
};

test "nodes: L1 includes nonced transactions in order, replaces, and survives reorgs" {
    const allocator = std.testing.allocator;
    var l1 = try L1.init(allocator, 16, std.time.ns_per_s);
    defer l1.deinit(allocator);
    var network = try Net.init(allocator, .{});
    defer network.deinit(allocator);
    var pool = try codec.TxPool.init(allocator, 8);
    defer pool.deinit(allocator);
    var prng = Prng.init(1);
    const env: Env = .{
        .now_ns = 0,
        .global_ns = 0,
        .prng = &prng,
        .network = &network,
        .verifier_count = 0,
        .tx_pool = &pool,
    };
    // Nonce 1 waits for nonce 0; a resubmitted nonce 1 replaces the first.
    try std.testing.expectEqual(SubmitResult.accepted, l1.submit_nonced(10, 1));
    l1.mine(&env);
    try std.testing.expectEqual(@as(u8, 0), l1.blocks[1].batch_count);
    try std.testing.expectEqual(@as(u64, 0), l1.nonce_pending());
    try std.testing.expectEqual(SubmitResult.replaced, l1.submit_nonced(11, 1));
    try std.testing.expectEqual(SubmitResult.accepted, l1.submit_nonced(12, 0));
    try std.testing.expectEqual(@as(u64, 2), l1.nonce_pending());
    l1.mine(&env);
    try std.testing.expectEqual(@as(u8, 2), l1.blocks[2].batch_count);
    try std.testing.expectEqual(@as(u32, 12), l1.blocks[2].batches[0].tx_index);
    try std.testing.expectEqual(@as(u32, 11), l1.blocks[2].batches[1].tx_index);
    try std.testing.expectEqual(@as(u64, 2), l1.nonce_mined());
    try std.testing.expectEqual(SubmitResult.nonce_too_low, l1.submit_nonced(13, 1));
    // A reorg re-mines the orphaned transactions on the replacement branch.
    const orphaned_hash = l1.blocks[2].hash;
    l1.reorg(&env, 1, &prng, 0);
    try std.testing.expectEqual(@as(u64, 2), l1.head);
    try std.testing.expect(l1.blocks[2].hash != orphaned_hash);
    try std.testing.expectEqual(@as(u64, 2), l1.nonce_mined());
    try std.testing.expectEqual(@as(u8, 0), l1.mempool_count);
}

test "nodes: L1 evictions and lossy reorgs drop transactions" {
    const allocator = std.testing.allocator;
    var l1 = try L1.init(allocator, 16, std.time.ns_per_s);
    defer l1.deinit(allocator);
    var network = try Net.init(allocator, .{});
    defer network.deinit(allocator);
    var pool = try codec.TxPool.init(allocator, 8);
    defer pool.deinit(allocator);
    var prng = Prng.init(2);
    const env: Env = .{
        .now_ns = 0,
        .global_ns = 0,
        .prng = &prng,
        .network = &network,
        .verifier_count = 0,
        .tx_pool = &pool,
    };
    try std.testing.expect(!l1.evict(&prng, .any));
    _ = l1.submit_nonced(1, 0);
    _ = l1.submit_nonced(2, 1);
    try std.testing.expect(l1.evict(&prng, .any));
    try std.testing.expectEqual(@as(u8, 1), l1.mempool_count);
    _ = l1.submit_nonced(3, 0);
    _ = l1.submit_nonced(4, 1);
    l1.mine(&env);
    try std.testing.expectEqual(@as(u64, 2), l1.nonce_mined());
    // Every orphaned tx is lost: the replacement block is empty and the nonce rolls back.
    l1.reorg(&env, 1, &prng, 1_000_000);
    try std.testing.expectEqual(@as(u8, 0), l1.blocks[1].batch_count);
    try std.testing.expectEqual(@as(u64, 0), l1.nonce_mined());
    try std.testing.expectEqual(@as(u8, 0), l1.mempool_count);
    // A lossless reorg re-injects mined txs; `never_reorged` evictions spare them.
    _ = l1.submit_nonced(5, 0);
    l1.mine(&env);
    l1.reorg(&env, 1, &prng, 0);
    l1.orphan(1, &prng, 0);
    try std.testing.expectEqual(@as(u8, 1), l1.mempool_count);
    try std.testing.expect(l1.mempool[0].reorged);
    for (0..16) |_| try std.testing.expect(!l1.evict(&prng, .never_reorged));
    try std.testing.expectEqual(@as(u8, 1), l1.mempool_count);
    try std.testing.expect(l1.evict(&prng, .any));
    try std.testing.expectEqual(@as(u8, 0), l1.mempool_count);
}

test "nodes: batch buffer keeps future batches until they extend the head" {
    var buffer: BatchBuffer = .{};
    var early: codec.Blocks = .{ .number_first = 9, .count = 4, .payloads = @splat(7) };
    const gap: codec.Blocks = .{ .number_first = 5, .count = 4, .payloads = @splat(3) };
    buffer.put(10, &early);
    buffer.put(12, &early); // A replay of the window keeps the earliest inclusion.
    try std.testing.expectEqual(@as(u32, 1), buffer.count);
    try std.testing.expect(buffer.next(4) == null); // Starts beyond the next block.
    buffer.put(11, &gap);
    try std.testing.expectEqual(@as(u64, 5), buffer.next(4).?.number_first);
    try std.testing.expectEqual(@as(u64, 9), buffer.next(8).?.number_first);
    try std.testing.expect(buffer.next(12) == null); // Behind the head.
    buffer.drop_from(11); // An L1 rewind to block 11 drops what block 11 brought.
    try std.testing.expectEqual(@as(u32, 1), buffer.count);
    try std.testing.expect(buffer.next(4) == null);
    // Full: the entry ending lowest makes room.
    for (0..batch_buffer_capacity) |index| {
        early.number_first = 100 + index;
        buffer.put(20, &early);
    }
    try std.testing.expectEqual(@as(u32, batch_buffer_capacity), buffer.count);
    try std.testing.expect(buffer.next(8) == null); // Block 9's entry was evicted.
}

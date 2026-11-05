//! In-memory fakes of the proposer's interfaces for unit tests and the deterministic
//! simulation: a rollup node + L1 contracts view (`FakeChain`), a proving service
//! (`FakeProver`) and an L1 transaction submitter (`FakeSubmitter`). Faults come from a
//! caller-owned seeded `Prng`, so every run reproduces from its seed.
//!
//! The fake factory enforces what the real contracts do: game keys are unique
//! (`GameAlreadyExists`), the parent is a live game or the anchor sentinel
//! (`InvalidParentGame`), the target is one interval after the parent, the root count
//! matches, and the `initData` "proof" matches the range (a digest standing in for TEE/ZK
//! verification).

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("../contracts/abi.zig");
const factory = @import("../contracts/dispute_game_factory.zig");
const interfaces = @import("interfaces.zig");
const intervals_module = @import("intervals.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = interfaces.Hash;
const Address = interfaces.Address;
const Chain = interfaces.Chain;
const ChainError = interfaces.ChainError;
const SubmitFailure = interfaces.SubmitFailure;
const Schedule = intervals_module.Schedule;

pub const games_max = 512;
/// Most intermediate roots per game the fakes support.
pub const roots_max = 16;

/// The `initData` a correct proof of `agreed_root -> claim` at `target_block` carries.
pub const CreateError = error{ Reverted, GameAlreadyExists, InvalidParentGame };

pub fn failure_of(err: CreateError) SubmitFailure {
    return switch (err) {
        error.Reverted => .reverted,
        error.GameAlreadyExists => .game_already_exists,
        error.InvalidParentGame => .invalid_parent_game,
    };
}

pub fn proof_digest(agreed_root: Hash, claim: Hash, target_block: u64) Hash {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&agreed_root);
    hasher.update(&claim);
    hasher.update(std.mem.asBytes(&target_block));
    return hasher.finalResult();
}

fn key_digest(game_type: u32, root_claim: Hash, extra_data: []const u8) Hash {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(std.mem.asBytes(&game_type));
    hasher.update(&root_claim);
    hasher.update(extra_data);
    return hasher.finalResult();
}

fn address_of(index: u64) Address {
    var address: Address = @splat(0);
    address[0] = 0x9a;
    std.mem.writeInt(u64, address[12..20], index + 1, .big);
    return address;
}

pub const FakeChain = struct {
    game_type: u32,
    anchor_state_registry: Address,
    schedule: Schedule,
    salt: u64 = 0,
    anchor: interfaces.AnchorRoot,
    anchor_game: Address = @splat(0),
    finalized_head: u64 = 0,
    safe_head: u64 = 0,
    /// The rollup node reports `BlockNotFound` above this block.
    available_head: u64 = std.math.maxInt(u64),
    games: [games_max]Game = undefined,
    game_count: u32 = 0,
    games_created_total: u64 = 0,
    /// Fault injection: each call fails with `Unavailable` with this probability.
    prng: ?*Prng = null,
    fail_permille: u32 = 0,
    games_should_fail: bool = false,
    /// Games of other types or keys counted by `gameCount` but never looked up.
    unrelated_games: u32 = 0,

    pub const Game = struct {
        address: Address,
        digest: Hash,
        parent: Address,
        start_block: u64,
        target_block: u64,
        root_claim: Hash,
        /// Every committed root (claim and intermediates) is canonical.
        canonical: bool,
    };

    pub fn root_at(chain: *const FakeChain, block: u64) Hash {
        var root: Hash = undefined;
        var prng = Prng.init(chain.salt ^ (block *% 0x9e37_79b9_7f4a_7c15));
        prng.fill(&root);
        return root;
    }

    fn block_hash(chain: *const FakeChain, block: u64) Hash {
        var hash = chain.root_at(block);
        hash[0] ^= 0xff;
        return hash;
    }

    fn fault(chain: *FakeChain) ChainError!void {
        const prng = chain.prng orelse return;
        if (chain.fail_permille > 0 and prng.chance(chain.fail_permille, 1000)) {
            return error.Unavailable;
        }
    }

    pub fn find_address(chain: *const FakeChain, address: Address) ?*const Game {
        for (chain.games[0..chain.game_count]) |*game| {
            if (std.mem.eql(u8, &game.address, &address)) return game;
        }
        return null;
    }

    fn find_digest(chain: *const FakeChain, digest: Hash) ?*const Game {
        for (chain.games[0..chain.game_count]) |*game| {
            if (std.mem.eql(u8, &game.digest, &digest)) return game;
        }
        return null;
    }

    /// The (block, root) a game with `parent` starts from; null for an unknown parent.
    fn parent_start(chain: *const FakeChain, parent: Address) ?struct { u64, Hash } {
        if (std.mem.eql(u8, &parent, &chain.anchor_state_registry)) {
            return .{ chain.anchor.l2_block_number, chain.anchor.root };
        }
        const game = chain.find_address(parent) orelse return null;
        return .{ game.target_block, game.root_claim };
    }

    /// Validates `createWithInitData` calldata as the factory and game would and, when
    /// `apply`, creates the game.
    pub fn create(chain: *FakeChain, calldata: []const u8, apply: bool) CreateError!Address {
        const decoder = abi.Decoder.call(calldata, factory.create_with_init_data) catch
            return error.Reverted;
        const game_type = decoder.uint(u32, 0) catch return error.Reverted;
        const root_claim = (decoder.word(1) catch return error.Reverted).*;
        const extra = decoder.bytes(2) catch return error.Reverted;
        const init_data = decoder.bytes(3) catch return error.Reverted;
        if (game_type != chain.game_type) return error.Reverted;
        if (extra.len < factory.extra_data_prefix_bytes) return error.Reverted;
        if ((extra.len - factory.extra_data_prefix_bytes) % 32 != 0) return error.Reverted;
        const digest = key_digest(game_type, root_claim, extra);
        if (chain.find_digest(digest) != null) return error.GameAlreadyExists;
        const target_block = std.math.cast(u64, std.mem.readInt(u256, extra[0..32], .big)) orelse
            return error.Reverted;
        const parent: Address = extra[32..52].*;
        const start_block, const start_root = chain.parent_start(parent) orelse
            return error.InvalidParentGame;
        const intervals = chain.schedule.for_starting_block(start_block);
        if (start_block + intervals.block_interval != target_block) return error.Reverted;
        const root_count = (extra.len - factory.extra_data_prefix_bytes) / 32;
        if (root_count != intervals.root_count()) return error.Reverted;
        const last_root = extra[extra.len - 32 ..][0..32];
        if (!std.mem.eql(u8, last_root, &root_claim)) return error.Reverted;
        const expected = proof_digest(start_root, root_claim, target_block);
        if (!std.mem.eql(u8, init_data, &expected)) return error.Reverted;
        if (!apply) return @splat(0);
        if (chain.game_count == games_max) return error.Reverted;
        const address = address_of(chain.games_created_total);
        chain.games[chain.game_count] = .{
            .address = address,
            .digest = digest,
            .parent = parent,
            .start_block = start_block,
            .target_block = target_block,
            .root_claim = root_claim,
            .canonical = chain.roots_canonical(start_block, intervals, extra),
        };
        chain.game_count += 1;
        chain.games_created_total += 1;
        return address;
    }

    fn roots_canonical(
        chain: *const FakeChain,
        start_block: u64,
        intervals: interfaces.Intervals,
        extra: []const u8,
    ) bool {
        const roots = extra[factory.extra_data_prefix_bytes..];
        var index: u64 = 0;
        while (index < roots.len / 32) : (index += 1) {
            const block = start_block + (index + 1) * intervals.intermediate_block_interval;
            const root = chain.root_at(block);
            if (!std.mem.eql(u8, roots[index * 32 ..][0..32], &root)) return false;
        }
        return true;
    }

    /// Creates the canonical game after `parent` (test fixture helper).
    pub fn add_canonical_game(chain: *FakeChain, parent: Address) Address {
        const start_block, const start_root = chain.parent_start(parent).?;
        const intervals = chain.schedule.for_starting_block(start_block);
        var roots: [roots_max]Hash = undefined;
        const count = intervals.root_count();
        assert(count <= roots_max);
        for (roots[0..count], 1..) |*root, index| {
            root.* = chain.root_at(start_block + index * intervals.intermediate_block_interval);
        }
        var extra_buffer: [factory.extra_data_prefix_bytes + 32 * roots_max]u8 = undefined;
        const key = factory.lookup_key(
            &extra_buffer,
            start_block,
            parent,
            intervals.block_interval,
            intervals.intermediate_block_interval,
            roots[0..count],
        ) catch unreachable;
        var calldata_buffer: [1024]u8 = undefined;
        const proof = proof_digest(start_root, key.root_claim, key.target_block);
        const calldata = factory.encode_create(
            &calldata_buffer,
            chain.game_type,
            key.root_claim,
            key.extra_data,
            &proof,
        ) catch unreachable;
        return chain.create(calldata, true) catch unreachable;
    }

    /// An L1 reorg that removes the newest games, keeping `count`.
    pub fn truncate(chain: *FakeChain, count: u32) void {
        assert(count <= chain.game_count);
        chain.game_count = count;
    }

    pub fn interface(chain: *FakeChain) Chain {
        return .{ .context = chain, .vtable = &chain_vtable };
    }

    const chain_vtable: Chain.VTable = .{
        .sync_status = chain_sync_status,
        .output_at_block = chain_output_at_block,
        .anchor_snapshot = chain_anchor_snapshot,
        .game_count = chain_game_count,
        .game_lookup = chain_game_lookup,
        .intervals = chain_intervals,
    };

    fn from(context: *anyopaque) *FakeChain {
        return @ptrCast(@alignCast(context));
    }

    fn chain_sync_status(context: *anyopaque) ChainError!interfaces.SyncStatus {
        const chain = from(context);
        try chain.fault();
        const finalized: interfaces.BlockRef = .{
            .number = chain.finalized_head,
            .hash = chain.block_hash(chain.finalized_head),
        };
        const safe: interfaces.BlockRef = .{
            .number = chain.safe_head,
            .hash = chain.block_hash(chain.safe_head),
        };
        const l1: interfaces.BlockRef = .{
            .number = chain.finalized_head / 4,
            .hash = @splat(0x11),
        };
        return .{
            .current_l1 = l1,
            .head_l1 = l1,
            .finalized_l1 = l1,
            .safe_l2 = safe,
            .finalized_l2 = finalized,
            .unsafe_l2 = safe,
        };
    }

    fn chain_output_at_block(context: *anyopaque, block: u64) ChainError!interfaces.OutputAtBlock {
        const chain = from(context);
        try chain.fault();
        if (block > chain.available_head) return error.BlockNotFound;
        return .{
            .output_root = chain.root_at(block),
            .block = .{ .number = block, .hash = chain.block_hash(block) },
        };
    }

    fn chain_anchor_snapshot(context: *anyopaque) ChainError!interfaces.AnchorSnapshot {
        const chain = from(context);
        try chain.fault();
        return .{ .root = chain.anchor, .game = chain.anchor_game };
    }

    fn chain_game_count(context: *anyopaque) ChainError!u64 {
        const chain = from(context);
        try chain.fault();
        return chain.game_count + chain.unrelated_games;
    }

    fn chain_game_lookup(
        context: *anyopaque,
        game_type: u32,
        root_claim: Hash,
        extra_data: []const u8,
    ) ChainError!?Address {
        const chain = from(context);
        try chain.fault();
        if (chain.games_should_fail) return error.Unavailable;
        const game = chain.find_digest(key_digest(game_type, root_claim, extra_data)) orelse
            return null;
        return game.address;
    }

    fn chain_intervals(context: *anyopaque, starting_block: u64) ChainError!interfaces.Intervals {
        const chain = from(context);
        try chain.fault();
        return chain.schedule.for_starting_block(starting_block);
    }
};

pub const FakeProver = struct {
    chain: *const FakeChain,
    sessions: [sessions_max]Session = undefined,
    session_count: u32 = 0,
    /// Fault injection for `request` / `poll` / `delete` (Unavailable).
    prng: ?*Prng = null,
    fail_permille: u32 = 0,
    requests_total: u64 = 0,
    requests_new: u64 = 0,
    pending_max: u32 = 0,
    /// Scratch for the proof handed out by the latest `poll`.
    roots: [roots_max]Hash = undefined,
    digest: Hash = undefined,

    pub const sessions_max = 128;

    pub const Session = struct {
        request: interfaces.ProofRequest,
        state: enum { pending, succeeded, failed },
        /// A faulty proof claiming a wrong root.
        wrong_root: bool,
        age: u64,
    };

    pub fn pending_count(prover: *const FakeProver) u32 {
        var count: u32 = 0;
        for (prover.sessions[0..prover.session_count]) |session| {
            count += @intFromBool(session.state == .pending);
        }
        return count;
    }

    fn find(prover: *FakeProver, session: Hash) ?u32 {
        for (prover.sessions[0..prover.session_count], 0..) |*entry, index| {
            if (std.mem.eql(u8, &entry.request.claimed_l2_output_root, &session)) {
                return @intCast(index);
            }
        }
        return null;
    }

    fn remove(prover: *FakeProver, index: u32) void {
        assert(index < prover.session_count);
        prover.session_count -= 1;
        prover.sessions[index] = prover.sessions[prover.session_count];
    }

    /// Completes pending sessions in random order: success, failure, or a wrong root.
    pub fn step(
        prover: *FakeProver,
        prng: *Prng,
        complete_permille: u32,
        fail_permille: u32,
        wrong_permille: u32,
    ) void {
        for (prover.sessions[0..prover.session_count]) |*session| {
            session.age += 1;
            if (session.state != .pending) continue;
            if (!prng.chance(complete_permille, 1000)) continue;
            session.state = .succeeded;
            if (prng.chance(fail_permille, 1000)) session.state = .failed;
            session.wrong_root = prng.chance(wrong_permille, 1000);
        }
        prover.pending_max = @max(prover.pending_max, prover.pending_count());
    }

    fn fault(prover: *FakeProver) interfaces.ProverError!void {
        const prng = prover.prng orelse return;
        if (prover.fail_permille > 0 and prng.chance(prover.fail_permille, 1000)) {
            return error.Unavailable;
        }
    }

    /// Makes room by evicting the oldest finished session (prover storage retention).
    fn evict(prover: *FakeProver) bool {
        var oldest: ?u32 = null;
        for (prover.sessions[0..prover.session_count], 0..) |session, index| {
            if (session.state == .pending) continue;
            if (oldest) |current| {
                if (session.age <= prover.sessions[current].age) continue;
            }
            oldest = @intCast(index);
        }
        prover.remove(oldest orelse return false);
        return true;
    }

    pub fn interface(prover: *FakeProver) interfaces.Prover {
        return .{ .context = prover, .vtable = &prover_vtable };
    }

    const prover_vtable: interfaces.Prover.VTable = .{
        .request = prover_request,
        .poll = prover_poll,
        .delete = prover_delete,
    };

    fn from(context: *anyopaque) *FakeProver {
        return @ptrCast(@alignCast(context));
    }

    fn prover_request(
        context: *anyopaque,
        request: *const interfaces.ProofRequest,
    ) interfaces.ProverError!void {
        const prover = from(context);
        try prover.fault();
        prover.requests_total += 1;
        if (prover.find(request.session()) != null) return;
        if (prover.session_count == sessions_max and !prover.evict()) return error.Unavailable;
        prover.sessions[prover.session_count] = .{
            .request = request.*,
            .state = .pending,
            .wrong_root = false,
            .age = 0,
        };
        prover.session_count += 1;
        prover.requests_new += 1;
    }

    fn prover_poll(
        context: *anyopaque,
        session: Hash,
    ) interfaces.ProverError!interfaces.ProofStatus {
        const prover = from(context);
        try prover.fault();
        const index = prover.find(session) orelse return error.NotFound;
        const entry = &prover.sessions[index];
        switch (entry.state) {
            .pending => return .pending,
            .failed => return .failed,
            .succeeded => {},
        }
        const request = entry.request;
        const span = request.claimed_l2_block_number - request.agreed_l2_block_number;
        const count = span / request.intermediate_block_interval;
        assert(count <= roots_max);
        for (prover.roots[0..count], 1..) |*root, offset| {
            const block = request.agreed_l2_block_number +
                offset * request.intermediate_block_interval;
            root.* = prover.chain.root_at(block);
        }
        var claim = request.claimed_l2_output_root;
        if (entry.wrong_root) claim[0] ^= 0x5a;
        prover.roots[count - 1] = claim;
        // The digest lives in the prover's scratch so the slice stays valid until the next call.
        const agreed_root = request.agreed_l2_output_root;
        prover.digest = proof_digest(agreed_root, claim, request.claimed_l2_block_number);
        return .{ .succeeded = .{
            .output_root = claim,
            .intermediate_roots = prover.roots[0..count],
            .init_data = &prover.digest,
        } };
    }

    fn prover_delete(context: *anyopaque, session: Hash) interfaces.ProverError!void {
        const prover = from(context);
        try prover.fault();
        prover.remove(prover.find(session) orelse return error.NotFound);
    }
};

pub const FakeSubmitter = struct {
    chain: *FakeChain,
    txs: [txs_max]Tx = undefined,
    tx_next: u64 = 1,
    /// Fault injection: `send` fails with `unavailable` with this probability.
    prng: ?*Prng = null,
    fail_permille: u32 = 0,
    sent_total: u64 = 0,

    pub const txs_max = 32;
    pub const calldata_max = 1024;

    pub const Tx = struct {
        id: interfaces.TxId,
        status: interfaces.TxStatus,
        calldata: [calldata_max]u8,
        calldata_len: u32,
    };

    pub fn init(chain: *FakeChain) FakeSubmitter {
        var submitter: FakeSubmitter = .{ .chain = chain };
        for (&submitter.txs) |*tx| tx.id = 0;
        assert(submitter.slot(1) == null);
        return submitter;
    }

    fn slot(submitter: *FakeSubmitter, id: interfaces.TxId) ?*Tx {
        const tx = &submitter.txs[id % txs_max];
        if (tx.id != id) return null;
        return tx;
    }

    /// Mines or drops pending transactions; a mined creation applies to the factory.
    pub fn step(
        submitter: *FakeSubmitter,
        prng: *Prng,
        mine_permille: u32,
        drop_permille: u32,
    ) void {
        const first = submitter.tx_next -| txs_max;
        var id = @max(first, 1);
        while (id < submitter.tx_next) : (id += 1) {
            const tx = submitter.slot(id) orelse continue;
            if (tx.status != .pending) continue;
            if (prng.chance(drop_permille, 1000)) {
                tx.status = .{ .failed = .dropped };
            } else if (prng.chance(mine_permille, 1000)) {
                if (submitter.chain.create(tx.calldata[0..tx.calldata_len], true)) |_| {
                    tx.status = .mined;
                } else |err| {
                    tx.status = .{ .failed = failure_of(err) };
                }
            }
        }
    }

    pub fn interface(submitter: *FakeSubmitter) interfaces.Submitter {
        return .{ .context = submitter, .vtable = &submitter_vtable };
    }

    const submitter_vtable: interfaces.Submitter.VTable = .{
        .send = submitter_send,
        .status = submitter_status,
    };

    fn from(context: *anyopaque) *FakeSubmitter {
        return @ptrCast(@alignCast(context));
    }

    fn submitter_send(context: *anyopaque, calldata: []const u8) interfaces.SendResult {
        const submitter = from(context);
        submitter.sent_total += 1;
        if (submitter.prng) |prng| {
            if (submitter.fail_permille > 0 and prng.chance(submitter.fail_permille, 1000)) {
                return .{ .failed = .unavailable };
            }
        }
        // Gas estimation surfaces reverts before broadcasting, as the tx manager does.
        _ = submitter.chain.create(calldata, false) catch |err| {
            return .{ .failed = failure_of(err) };
        };
        assert(calldata.len <= calldata_max);
        const id = submitter.tx_next;
        submitter.tx_next += 1;
        const tx = &submitter.txs[id % txs_max];
        tx.* = .{
            .id = id,
            .status = .pending,
            .calldata = undefined,
            .calldata_len = @intCast(calldata.len),
        };
        @memcpy(tx.calldata[0..calldata.len], calldata);
        return .{ .pending = id };
    }

    fn submitter_status(context: *anyopaque, id: interfaces.TxId) interfaces.TxStatus {
        const submitter = from(context);
        const tx = submitter.slot(id) orelse return .{ .failed = .dropped };
        return tx.status;
    }
};

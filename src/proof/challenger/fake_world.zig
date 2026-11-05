//! An in-memory challenger world for unit tests and the deterministic simulation: dispute
//! games with an `AggregateVerifier`-like contract (nullify, challenge, resolve, two-step
//! `claimCredit` through a delayed WETH), an anchor state registry, an L2 chain of real RLP
//! headers, a prover service and a transaction submitter. Every fault and latency comes
//! from one seeded `Prng`, so a run reproduces from its seed.
//!
//! The fake contract checks each dispute against the honest chain: a dispute proving a
//! root other than the honest one, or refuting a root that was right, is counted in
//! `stats.bad_disputes` (and reverts). The simulation asserts it stays zero.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const contracts = @import("../contracts/root.zig");
const native = @import("../host/native.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const crypto = @import("../../common/crypto/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Address = chain.Address;
const Hash = chain.Hash;
const aggregate_verifier = contracts.aggregate_verifier;

pub const games_max = 256;
pub const roots_max = 16;
pub const jobs_max = 1024;
pub const txs_max = 256;
const calldata_bytes_max = 2400;
const game_marker: u8 = 0x6a;

pub fn game_address(index: u64) Address {
    var address: Address = @splat(0);
    address[0] = game_marker;
    std.mem.writeInt(u64, address[12..20], index, .big);
    return address;
}

pub const Game = struct {
    proxy: Address,
    game_type: u32,
    created_at_s: u64,
    creator: Address,
    info: chain.GameInfo,
    roots: [roots_max]Hash,
    root_count: u32,
    status: chain.GameStatus = .in_progress,
    tee_prover: Address,
    zk_prover: Address,
    countered_index: u64 = 0,
    expected_resolution_s: u64,
    resolved_at_s: u64 = 0,
    bond_recipient: Address,
    bond_unlocked: bool = false,
    bond_claimed: bool = false,
    withdrawal_timestamp_s: u64 = 0,
    /// Every read of this game fails (scanner error tests).
    fail_reads: bool = false,
    // Simulation bookkeeping.
    honest: bool,
    proof_count: u32,
    attacked: bool = false,
    disputes_ok: u32 = 0,
    withdrawals: u32 = 0,
};

pub const GameSpec = struct {
    starting_block: u64,
    tee: bool = true,
    zk: bool = false,
    /// The intermediate root to falsify; null for an honest game.
    corrupt_index: ?u32 = null,
    parent: Address = @splat(0),
    game_type: u32 = 1,
};

/// Per-mille fault rates and latency ranges.
pub const Faults = struct {
    read_failure: u32 = 0,
    poll_failure: u32 = 0,
    request_failure: u32 = 0,
    proof_failure: u32 = 0,
    send_rejection: u32 = 0,
    tx_drop: u32 = 0,
    proof_latency_s_min: u64 = 0,
    proof_latency_s_max: u64 = 0,
    tx_latency_s_min: u64 = 0,
    tx_latency_s_max: u64 = 0,
};

pub const Stats = struct {
    bad_disputes: u64 = 0,
    disputes_ok: u64 = 0,
    stale_disputes: u64 = 0,
    concurrent_game_txs: u64 = 0,
    claims_reverted: u64 = 0,
    withdrawals: u64 = 0,
    resolves: u64 = 0,
    anchor_updates: u64 = 0,
    txs_sent: u64 = 0,
    txs_dropped: u64 = 0,
    proof_requests: u64 = 0,
};

const Job = struct {
    kind: enum { tee, zk },
    ready_at_s: u64,
    failed: bool,
    output_root: Hash,
};

const PendingTx = struct {
    ticket: chain.Ticket,
    to: Address,
    length: u32,
    mine_at_s: u64,
    status: chain.TxStatus,
    calldata: [calldata_bytes_max]u8,
};

pub const World = struct {
    now_s: u64,
    prng: Prng,
    faults: Faults,
    games: [games_max]Game,
    game_count: u32,
    anchor: chain.AnchorSnapshot,
    anchor_state_registry: Address,
    delayed_weth: Address,
    weth_delay_s: u64,
    finality_delay_s: u64,
    resolution_delay_s: u64,
    intervals: chain.Intervals,
    l2_head: u64,
    fail_anchor: bool,
    jobs: [jobs_max]Job,
    job_count: u32,
    txs: [txs_max]PendingTx,
    tx_count: u64,
    stats: Stats,
    signature: [65]u8,
    zk_body: [12]u8,

    /// Initializes in place: the world is large.
    pub fn init(world: *World, seed: u64) void {
        world.now_s = 0;
        world.prng = .init(seed);
        world.faults = .{};
        world.game_count = 0;
        world.anchor = .{ .anchor_game = @splat(0), .anchor_root = .{ .root = @splat(0), .l2_block_number = 0 } };
        world.anchor_state_registry = @splat(0xa5);
        world.delayed_weth = @splat(0x3e);
        world.weth_delay_s = 60;
        world.finality_delay_s = 10;
        world.resolution_delay_s = 600;
        world.intervals = .{ .block = 4, .intermediate_block = 2 };
        world.l2_head = 1_000_000;
        world.fail_anchor = false;
        world.job_count = 0;
        world.tx_count = 0;
        world.stats = .{};
        world.signature = @splat(0);
        world.zk_body = .{ 0x5a, 0x09, 0x3a, 0x2f, 1, 2, 3, 4, 5, 6, 7, 8 };
        world.anchor.anchor_root.root = world.honest_root(0);
        assert(world.game_count == 0);
    }

    pub fn effects(world: *World) chain.World {
        return .{
            .chain = .{ .context = world, .vtable = &view_vtable },
            .prover = .{ .context = world, .vtable = &prover_vtable },
            .submitter = .{ .context = world, .vtable = &submitter_vtable },
        };
    }

    /// The raw header of L2 block `number`: a deterministic Isthmus-style header.
    pub fn header(number: u64, out: []u8) []const u8 {
        var seed: [9]u8 = undefined;
        std.mem.writeInt(u64, seed[0..8], number, .big);
        seed[8] = 's';
        const state_root = crypto.keccak256(&seed);
        seed[8] = 'w';
        const passer_root = crypto.keccak256(&seed);
        const value: consensus.Header = .{
            .number = number,
            .timestamp = number,
            .state_root = .{ .bytes = state_root },
            .withdrawals_root = .{ .bytes = passer_root },
            .base_fee_per_gas = 1,
        };
        const raw = rlp.encode_to(out, value);
        assert(raw.len > 0);
        return raw;
    }

    pub fn honest_root(world: *const World, number: u64) Hash {
        _ = world;
        var buffer: [1024]u8 = undefined;
        // The fake header always carries a withdrawals root.
        return native.output_root_of(header(number, &buffer)) catch unreachable;
    }

    pub fn add_game(world: *World, spec: GameSpec) *Game {
        assert(world.game_count < games_max);
        assert(spec.tee or spec.zk);
        const count = world.intervals.block / world.intervals.intermediate_block;
        assert(count <= roots_max);
        const index = world.game_count;
        const game = &world.games[index];
        const creator: Address = @splat(0xbb);
        game.* = .{
            .proxy = game_address(index),
            .game_type = spec.game_type,
            .created_at_s = world.now_s,
            .creator = creator,
            .info = .{
                .root_claim = undefined,
                .l2_block_number = spec.starting_block + world.intervals.block,
                .parent = spec.parent,
                .starting_block_number = spec.starting_block,
                .l1_head = @splat(0x11),
                .intervals = world.intervals,
            },
            .roots = undefined,
            .root_count = @intCast(count),
            .tee_prover = if (spec.tee) creator else @splat(0),
            .zk_prover = if (spec.zk) creator else @splat(0),
            .expected_resolution_s = world.now_s + world.resolution_delay_s,
            .bond_recipient = creator,
            .honest = spec.corrupt_index == null,
            .proof_count = @as(u32, @intFromBool(spec.tee)) + @intFromBool(spec.zk),
        };
        for (game.roots[0..count], 0..) |*root, root_index| {
            root.* = world.honest_root(spec.starting_block + world.intervals.intermediate_block * (root_index + 1));
            if (spec.corrupt_index != null and spec.corrupt_index.? == root_index) root[0] ^= 0xff;
        }
        game.info.root_claim = game.roots[count - 1];
        world.game_count += 1;
        return game;
    }

    pub fn find_game(world: *World, address: Address) ?*Game {
        if (address[0] != game_marker) return null;
        const index = std.mem.readInt(u64, address[12..20], .big);
        if (index >= world.game_count) return null;
        const game = &world.games[index];
        assert(std.mem.eql(u8, &game.proxy, &address));
        return game;
    }

    fn fault(world: *World, per_mille: u32) bool {
        if (per_mille == 0) return false;
        return world.prng.chance(per_mille, 1000);
    }

    fn latency(world: *World, min: u64, max: u64) u64 {
        assert(min <= max);
        return world.prng.range(min, max);
    }

    /// Resolves a game whose resolution time has come. False when it cannot resolve.
    pub fn resolve_game(world: *World, game: *Game) bool {
        if (game.status != .in_progress) return false;
        if (world.now_s < game.expected_resolution_s) return false;
        const has_tee = !chain.is_zero(game.tee_prover);
        const has_zk = !chain.is_zero(game.zk_prover);
        if (game.countered_index > 0 and has_zk) {
            game.status = .challenger_wins;
            game.bond_recipient = game.zk_prover;
        } else if (!has_tee and !has_zk) {
            game.status = .challenger_wins;
        } else {
            game.status = .defender_wins;
        }
        game.resolved_at_s = world.now_s;
        world.stats.resolves += 1;
        assert(game.status != .in_progress);
        return true;
    }

    /// Sets the time and mines every transaction that is due, oldest first.
    pub fn advance(world: *World, now_s: u64) void {
        assert(now_s >= world.now_s);
        world.now_s = now_s;
        var ticket = (world.tx_count -| txs_max) + 1;
        while (ticket <= world.tx_count) : (ticket += 1) {
            const tx = &world.txs[ticket % txs_max];
            if (tx.status != .pending or tx.mine_at_s > now_s) continue;
            if (world.fault(world.faults.tx_drop)) {
                world.stats.txs_dropped += 1;
                tx.status = .{ .failed = .other };
                continue;
            }
            tx.status = if (world.execute(tx)) |err| .{ .failed = err } else .mined;
        }
    }

    /// Runs a mined transaction against the fake contracts; the revert reason on failure.
    fn execute(world: *World, tx: *const PendingTx) ?chain.SubmitError {
        const calldata = tx.calldata[0..tx.length];
        if (std.mem.eql(u8, &tx.to, &world.anchor_state_registry)) {
            return world.set_anchor_state(calldata);
        }
        const game = world.find_game(tx.to) orelse return .tx_reverted;
        const head = calldata[0..4];
        if (std.mem.eql(u8, head, &aggregate_verifier.resolve)) {
            return if (world.resolve_game(game)) null else .tx_reverted;
        }
        if (std.mem.eql(u8, head, &aggregate_verifier.claim_credit)) return world.claim_credit(game);
        const call = aggregate_verifier.decode_dispute(calldata) orelse return .tx_reverted;
        return world.dispute(game, call);
    }

    fn dispute(world: *World, game: *Game, call: aggregate_verifier.DisputeCall) ?chain.SubmitError {
        if (game.status != .in_progress) return .tx_reverted;
        if (call.intermediate_root_index >= game.root_count or call.proof_bytes.len == 0) {
            world.stats.bad_disputes += 1;
            return .execution_reverted;
        }
        const index: u32 = @intCast(call.intermediate_root_index);
        const block = game.info.starting_block_number + game.info.intervals.intermediate_block * (index + 1);
        // A sound verifier only accepts proofs of the honest root.
        if (!std.mem.eql(u8, &call.intermediate_root_to_prove, &world.honest_root(block))) {
            world.stats.bad_disputes += 1;
            return .{ .known_revert = .invalid_proof };
        }
        const claimed_matches = std.mem.eql(u8, &game.roots[index], &call.intermediate_root_to_prove);
        const zk_proof = call.proof_bytes[0] == aggregate_verifier.proof_type_zk;
        if (game.countered_index > 0) {
            // Only a ZK nullification of the challenged (and right) root refutes a challenge.
            const refutes = call.kind == .nullify and zk_proof and
                index + 1 == game.countered_index and claimed_matches;
            if (!refutes) {
                world.stats.bad_disputes += 1;
                return .execution_reverted;
            }
        } else if (claimed_matches) {
            world.stats.bad_disputes += 1; // IntermediateRootSameAsProposed.
            return .execution_reverted;
        }
        return world.apply_dispute(game, call.kind, zk_proof, index);
    }

    fn apply_dispute(world: *World, game: *Game, kind: aggregate_verifier.DisputeKind, zk_proof: bool, index: u32) ?chain.SubmitError {
        switch (kind) {
            .nullify => {
                const prover = if (zk_proof) &game.zk_prover else &game.tee_prover;
                if (chain.is_zero(prover.*)) {
                    world.stats.stale_disputes += 1;
                    return .tx_reverted;
                }
                prover.* = @splat(0);
                if (zk_proof) game.countered_index = 0;
            },
            .challenge => {
                if (!zk_proof or chain.is_zero(game.tee_prover) or !chain.is_zero(game.zk_prover)) {
                    world.stats.stale_disputes += 1;
                    return .tx_reverted;
                }
                game.zk_prover = sender;
                game.countered_index = index + 1;
            },
        }
        game.disputes_ok += 1;
        world.stats.disputes_ok += 1;
        game.expected_resolution_s = world.now_s + world.resolution_delay_s;
        return null;
    }

    fn claim_credit(world: *World, game: *Game) ?chain.SubmitError {
        if (game.status == .in_progress) return .tx_reverted;
        if (!game.bond_unlocked) {
            game.bond_unlocked = true;
            game.withdrawal_timestamp_s = world.now_s;
            return null;
        }
        const ready = world.now_s >= game.withdrawal_timestamp_s + world.weth_delay_s;
        if (game.bond_claimed or !ready) {
            world.stats.claims_reverted += 1;
            return .tx_reverted;
        }
        game.bond_claimed = true;
        game.withdrawals += 1;
        world.stats.withdrawals += 1;
        return null;
    }

    fn set_anchor_state(world: *World, calldata: []const u8) ?chain.SubmitError {
        const decoder = contracts.abi.Decoder.call(calldata, contracts.anchor_state_registry.set_anchor_state) catch
            return .tx_reverted;
        const address = decoder.address(0) catch return .tx_reverted;
        const game = world.find_game(address) orelse return .tx_reverted;
        if (!world.finalized(game) or game.status != .defender_wins) return .tx_reverted;
        if (game.info.l2_block_number <= world.anchor.anchor_root.l2_block_number) return .tx_reverted;
        world.anchor = .{ .anchor_game = game.proxy, .anchor_root = .{
            .root = game.info.root_claim,
            .l2_block_number = game.info.l2_block_number,
        } };
        world.stats.anchor_updates += 1;
        return null;
    }

    fn finalized(world: *const World, game: *const Game) bool {
        return game.status != .in_progress and world.now_s >= game.resolved_at_s + world.finality_delay_s;
    }

    /// Transactions sent but not mined yet.
    pub fn txs_in_flight(world: *const World) u32 {
        var count: u32 = 0;
        var ticket = (world.tx_count -| txs_max) + 1;
        while (ticket <= world.tx_count) : (ticket += 1) {
            count += @intFromBool(world.txs[ticket % txs_max].status == .pending);
        }
        return count;
    }
};

/// The challenger's transaction sender in tests.
pub const sender: Address = @splat(0xcc);

fn cast(context: *anyopaque) *World {
    return @ptrCast(@alignCast(context));
}

fn read(world: *World) chain.ReadError!void {
    if (world.fault(world.faults.read_failure)) return error.ChainUnavailable;
}

fn game_or_fail(world: *World, address: Address) chain.ReadError!*Game {
    try read(world);
    const game = world.find_game(address) orelse return error.ChainUnavailable;
    if (game.fail_reads) return error.ChainUnavailable;
    return game;
}

fn view_game_count(context: *anyopaque) chain.ReadError!u64 {
    const world = cast(context);
    try read(world);
    return world.game_count;
}

fn view_game_at_index(context: *anyopaque, index: u64) chain.ReadError!chain.GameAtIndex {
    const world = cast(context);
    try read(world);
    if (index >= world.game_count) return error.ChainUnavailable;
    const game = &world.games[index];
    if (game.fail_reads) return error.ChainUnavailable;
    return .{ .game_type = game.game_type, .timestamp = game.created_at_s, .proxy = game.proxy };
}

fn view_game_state(context: *anyopaque, address: Address) chain.ReadError!chain.GameState {
    const game = try game_or_fail(cast(context), address);
    return .{
        .status = game.status,
        .tee_prover = game.tee_prover,
        .zk_prover = game.zk_prover,
        .countered_index = game.countered_index,
    };
}

fn view_game_info(context: *anyopaque, address: Address) chain.ReadError!chain.GameInfo {
    const game = try game_or_fail(cast(context), address);
    return game.info;
}

fn view_intermediate_roots(context: *anyopaque, address: Address, out: []Hash) chain.ReadError![]Hash {
    const game = try game_or_fail(cast(context), address);
    if (game.root_count > out.len) return error.ChainUnavailable;
    @memcpy(out[0..game.root_count], game.roots[0..game.root_count]);
    return out[0..game.root_count];
}

fn view_intermediate_root(context: *anyopaque, address: Address, index: u64) chain.ReadError!Hash {
    const game = try game_or_fail(cast(context), address);
    if (index >= game.root_count) return error.ChainUnavailable;
    return game.roots[index];
}

fn view_anchor_snapshot(context: *anyopaque) chain.ReadError!chain.AnchorSnapshot {
    const world = cast(context);
    try read(world);
    if (world.fail_anchor) return error.ChainUnavailable;
    return world.anchor;
}

fn view_implementation_intervals(context: *anyopaque, kind: u32, start: u64) chain.ReadError!chain.Intervals {
    _ = kind;
    _ = start;
    const world = cast(context);
    try read(world);
    return world.intervals;
}

fn view_factory_game(context: *anyopaque, kind: u32, claim: Hash, extra_data: []const u8) chain.ReadError!?Address {
    const world = cast(context);
    try read(world);
    var buffer: [contracts.dispute_game_factory.extra_data_bytes_max]u8 = undefined;
    for (world.games[0..world.game_count]) |*game| {
        if (game.game_type != kind or !std.mem.eql(u8, &game.info.root_claim, &claim)) continue;
        const own = contracts.dispute_game_factory.encode_extra_data(
            &buffer,
            game.info.l2_block_number,
            game.info.parent,
            game.roots[0..game.root_count],
        ) catch unreachable;
        if (std.mem.eql(u8, own, extra_data)) return game.proxy;
    }
    return null;
}

fn view_anchor_registry_of(context: *anyopaque, address: Address) chain.ReadError!Address {
    const world = cast(context);
    _ = try game_or_fail(world, address);
    return world.anchor_state_registry;
}

fn view_is_game_finalized(context: *anyopaque, registry: Address, address: Address) chain.ReadError!bool {
    const world = cast(context);
    assert(std.mem.eql(u8, &registry, &world.anchor_state_registry));
    const game = try game_or_fail(world, address);
    return world.finalized(game);
}

fn view_anchor_preflight(context: *anyopaque, registry: Address, address: Address) chain.ReadError!chain.Preflight {
    const world = cast(context);
    assert(std.mem.eql(u8, &registry, &world.anchor_state_registry));
    _ = try game_or_fail(world, address);
    return .{
        .blacklisted = false,
        .retired = false,
        .respected = true,
        .paused = false,
        .anchor_root = world.anchor.anchor_root,
    };
}

fn view_bond_state(context: *anyopaque, address: Address) chain.ReadError!chain.BondState {
    const world = cast(context);
    const game = try game_or_fail(world, address);
    return .{
        .bond_recipient = game.bond_recipient,
        .zk_prover = game.zk_prover,
        .resolved_at = game.resolved_at_s,
        .game_over = world.now_s >= game.expected_resolution_s,
        .bond_unlocked = game.bond_unlocked,
        .bond_claimed = game.bond_claimed,
        .delayed_weth = world.delayed_weth,
    };
}

fn view_weth_delay_seconds(context: *anyopaque, weth: Address) chain.ReadError!u64 {
    const world = cast(context);
    try read(world);
    assert(std.mem.eql(u8, &weth, &world.delayed_weth));
    return world.weth_delay_s;
}

fn view_withdrawal(context: *anyopaque, weth: Address, owner: Address, guy: Address) chain.ReadError!chain.Withdrawal {
    const world = cast(context);
    assert(std.mem.eql(u8, &weth, &world.delayed_weth));
    const game = try game_or_fail(world, owner);
    if (!std.mem.eql(u8, &guy, &game.bond_recipient)) return .{ .amount = 0, .timestamp = 0 };
    return .{ .amount = 1, .timestamp = game.withdrawal_timestamp_s };
}

fn view_l1_block_number(context: *anyopaque, hash: Hash) chain.ReadError!u64 {
    _ = hash;
    try read(cast(context));
    return 1;
}

fn view_l2_header(context: *anyopaque, number: u64, out: []u8) chain.HeaderError![]const u8 {
    const world = cast(context);
    try read(world);
    if (number > world.l2_head) return error.BlockNotAvailable;
    return World.header(number, out);
}

const view_vtable: chain.ChainView.VTable = .{
    .game_count = view_game_count,
    .game_at_index = view_game_at_index,
    .game_state = view_game_state,
    .game_info = view_game_info,
    .intermediate_roots = view_intermediate_roots,
    .intermediate_root = view_intermediate_root,
    .anchor_snapshot = view_anchor_snapshot,
    .implementation_intervals = view_implementation_intervals,
    .factory_game = view_factory_game,
    .anchor_registry_of = view_anchor_registry_of,
    .is_game_finalized = view_is_game_finalized,
    .anchor_preflight = view_anchor_preflight,
    .bond_state = view_bond_state,
    .weth_delay_seconds = view_weth_delay_seconds,
    .withdrawal = view_withdrawal,
    .l1_block_number = view_l1_block_number,
    .l2_header = view_l2_header,
};

fn prover_request(context: *anyopaque, game: Address, index: u64, request: chain.ProofRequest) chain.ProverError!chain.SessionId {
    _ = game;
    _ = index;
    const world = cast(context);
    if (world.fault(world.faults.request_failure)) return error.ProverUnavailable;
    assert(world.job_count < jobs_max);
    const claimed_block = switch (request) {
        .tee => |tee| tee.claimed_l2_block_number,
        .zk => |zk| zk.start_block_number + zk.number_of_blocks_to_prove,
    };
    world.jobs[world.job_count] = .{
        .kind = if (request == .tee) .tee else .zk,
        .ready_at_s = world.now_s + world.latency(world.faults.proof_latency_s_min, world.faults.proof_latency_s_max),
        .failed = world.fault(world.faults.proof_failure),
        .output_root = world.honest_root(claimed_block),
    };
    world.job_count += 1;
    world.stats.proof_requests += 1;
    return world.job_count;
}

fn prover_poll(context: *anyopaque, session: chain.SessionId) chain.ProverError!chain.ProverStatus {
    const world = cast(context);
    if (world.fault(world.faults.poll_failure)) return error.ProverUnavailable;
    assert(session > 0 and session <= world.job_count);
    const job = &world.jobs[session - 1];
    if (world.now_s < job.ready_at_s) return .running;
    if (job.failed) return .failed;
    return .{ .succeeded = switch (job.kind) {
        .tee => .{ .tee = .{ .output_root = job.output_root, .signature = &world.signature } },
        .zk => .{ .zk = &world.zk_body },
    } };
}

const prover_vtable: chain.Prover.VTable = .{ .request = prover_request, .poll = prover_poll };

fn submitter_send(context: *anyopaque, tx: chain.Tx) chain.SendResult {
    const world = cast(context);
    if (world.fault(world.faults.send_rejection)) return .{ .rejected = .other };
    assert(tx.calldata.len <= calldata_bytes_max);
    // Two in-flight transactions to one game would race each other.
    var ticket = (world.tx_count -| txs_max) + 1;
    while (ticket <= world.tx_count) : (ticket += 1) {
        const other = &world.txs[ticket % txs_max];
        if (other.status == .pending and std.mem.eql(u8, &other.to, &tx.to)) {
            world.stats.concurrent_game_txs += 1;
        }
    }
    world.tx_count += 1;
    const slot = &world.txs[world.tx_count % txs_max];
    // The ring must never overwrite a transaction still in flight.
    assert(world.tx_count <= txs_max or slot.status != .pending);
    slot.* = .{
        .ticket = world.tx_count,
        .to = tx.to,
        .length = @intCast(tx.calldata.len),
        .mine_at_s = world.now_s + world.latency(world.faults.tx_latency_s_min, world.faults.tx_latency_s_max),
        .status = .pending,
        .calldata = undefined,
    };
    @memcpy(slot.calldata[0..tx.calldata.len], tx.calldata);
    world.stats.txs_sent += 1;
    return .{ .queued = world.tx_count };
}

fn submitter_status(context: *anyopaque, ticket: chain.Ticket) chain.TxStatus {
    const world = cast(context);
    assert(ticket > 0 and ticket <= world.tx_count);
    assert(ticket + txs_max > world.tx_count);
    const tx = &world.txs[ticket % txs_max];
    assert(tx.ticket == ticket);
    return tx.status;
}

const submitter_vtable: chain.Submitter.VTable = .{ .send = submitter_send, .status = submitter_status };

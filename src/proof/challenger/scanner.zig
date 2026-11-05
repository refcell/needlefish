//! Game scanner (base/base `crates/proof/challenge/src/scanner.rs`): every tick it finds
//! the current anchor game's factory index and evaluates every later game, classifying the
//! actionable ones into a `GameCategory` by their prover state:
//!
//! 1. `invalid_tee_proposal`: TEE proof only. Validate; nullify with TEE or challenge
//!    with ZK.
//! 2. `fraudulent_zk_challenge`: TEE proof challenged by ZK. Validate the original root at
//!    the challenged index; if it was right, nullify the challenge with a ZK proof.
//! 3. `invalid_zk_proposal`: ZK proof only. Validate; nullify with ZK.
//! 4. `invalid_dual_proposal`: both proofs, unchallenged. Nullify TEE first (falling back
//!    to ZK); the next scan sees an `invalid_zk_proposal`.
//!
//! Resolved and fully nullified games (both provers zero) are skipped. A read failure on one
//! game skips that game; the next scan retries the whole post-anchor range.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");

const Address = chain.Address;
const Hash = chain.Hash;

/// Factory indices inspected per anchor lookup batch (base/base `ANCHOR_SEARCH_BATCH_SIZE`).
pub const anchor_search_batch_size: u64 = 1024;

pub const GameCategory = union(enum) {
    invalid_tee_proposal,
    /// The 0-based challenged intermediate root index.
    fraudulent_zk_challenge: u64,
    invalid_zk_proposal,
    invalid_dual_proposal,
};

pub const CandidateGame = struct {
    index: u64,
    proxy: Address,
    game_type: u32,
    root_claim: Hash,
    l2_block_number: u64,
    starting_block_number: u64,
    intermediate_block_interval: u64,
    l1_head: Hash,
    tee_prover: Address,
    category: GameCategory,

    /// The starting block of the checkpoint at intermediate root `index`.
    pub fn checkpoint_start_block(candidate: *const CandidateGame, index: u64) error{Overflow}!u64 {
        assert(candidate.intermediate_block_interval > 0);
        const offset = try std.math.mul(u64, candidate.intermediate_block_interval, index);
        return std.math.add(u64, candidate.starting_block_number, offset);
    }
};

/// Classifies a game by its provers and 1-based countered index; null for states the
/// contract should never reach. Callers filter fully nullified games first.
pub fn classify(tee_prover: Address, zk_prover: Address, countered_index: u64) ?GameCategory {
    const has_tee = !chain.is_zero(tee_prover);
    const has_zk = !chain.is_zero(zk_prover);
    assert(has_tee or has_zk);
    if (has_tee and !has_zk) {
        // A countered index requires `challenge()`, which sets the ZK prover.
        return if (countered_index == 0) .invalid_tee_proposal else null;
    }
    if (has_tee and has_zk) {
        if (countered_index == 0) return .invalid_dual_proposal;
        return .{ .fraudulent_zk_challenge = countered_index - 1 };
    }
    assert(has_zk and !has_tee);
    // ZK-only with a countered index needs a global TEE verifier nullification.
    return if (countered_index == 0) .invalid_zk_proposal else null;
}

pub const FindResult = struct { found: ?u64, had_errors: bool };

pub const ScanResult = struct {
    candidates: []CandidateGame,
    scan_start: u64,
    games_scanned: u64,
    /// More games or candidates than this scan's bounds; the rest wait for the next scan.
    truncated: bool,
    read_errors: u32,
};

pub const Scanner = struct {
    /// Most games evaluated per scan (base/base scans the whole post-anchor range).
    games_per_scan_max: u64,
    /// The cached factory index of the current anchor game.
    anchor_index: ?struct { game: Address, index: u64 } = null,

    pub fn init(games_per_scan_max: u64) Scanner {
        assert(games_per_scan_max > 0);
        return .{ .games_per_scan_max = games_per_scan_max };
    }

    /// Evaluates the games after the anchor into `out`, in index order.
    pub fn scan(scanner: *Scanner, view: chain.ChainView, out: []CandidateGame) chain.ReadError!ScanResult {
        assert(out.len > 0);
        const game_count = try view.game_count();
        var result: ScanResult = .{
            .candidates = out[0..0],
            .scan_start = 0,
            .games_scanned = 0,
            .truncated = false,
            .read_errors = 0,
        };
        if (game_count == 0) return result;
        result.scan_start = scanner.scan_start_index(view, game_count);
        const available = game_count - result.scan_start;
        const scanned = @min(available, scanner.games_per_scan_max);
        result.truncated = scanned < available;
        var length: usize = 0;
        var index = result.scan_start;
        while (index < result.scan_start + scanned) : (index += 1) {
            const evaluated = evaluate_game(view, index) catch {
                result.read_errors += 1;
                continue;
            };
            const candidate = evaluated orelse continue;
            if (length == out.len) {
                result.truncated = true;
                break;
            }
            out[length] = candidate;
            length += 1;
        }
        result.candidates = out[0..length];
        result.games_scanned = index - result.scan_start;
        assert(result.games_scanned <= scanner.games_per_scan_max);
        return result;
    }

    /// One past the anchor game's factory index; 0 when the registry has no anchor game or
    /// it is not in the factory. A failed anchor read keeps the cached index.
    pub fn scan_start_index(scanner: *Scanner, view: chain.ChainView, game_count: u64) u64 {
        assert(game_count > 0);
        const cached = scanner.anchor_index;
        const cached_start: ?u64 = if (cached) |entry|
            (if (entry.index < game_count) @min(entry.index + 1, game_count) else null)
        else
            null;
        const anchor = view.anchor_snapshot() catch return cached_start orelse 0;
        if (chain.is_zero(anchor.anchor_game)) {
            scanner.anchor_index = null;
            return 0;
        }
        if (cached) |entry| {
            if (std.mem.eql(u8, &entry.game, &anchor.anchor_game) and entry.index < game_count) {
                return @min(entry.index + 1, game_count);
            }
        }
        const search_start = if (cached) |entry| @min(entry.index +| 1, game_count) else 0;
        var lookup = find_game_index(view, anchor.anchor_game, search_start, game_count);
        if (lookup.found == null and search_start > 0) {
            const wrapped = find_game_index(view, anchor.anchor_game, 0, search_start);
            lookup.found = wrapped.found;
            lookup.had_errors = lookup.had_errors or wrapped.had_errors;
        }
        if (lookup.found == null and lookup.had_errors) {
            if (cached_start) |start| return start;
        }
        const found = lookup.found orelse {
            scanner.anchor_index = null;
            return 0;
        };
        scanner.anchor_index = .{ .game = anchor.anchor_game, .index = found };
        assert(found < game_count);
        return @min(found + 1, game_count);
    }
};

/// Finds `target` in `[start, end)`, searching backward in batches; returns the match
/// closest to `end` and whether any index failed to read.
pub fn find_game_index(view: chain.ChainView, target: Address, start: u64, end: u64) FindResult {
    var result: FindResult = .{ .found = null, .had_errors = false };
    if (start >= end) return result;
    var search_end = end;
    while (search_end > start) {
        const search_start = @max(search_end -| anchor_search_batch_size, start);
        var index = search_start;
        while (index < search_end) : (index += 1) {
            const game = view.game_at_index(index) catch {
                result.had_errors = true;
                continue;
            };
            if (std.mem.eql(u8, &game.proxy, &target)) result.found = index;
        }
        if (result.found != null) break;
        search_end = search_start;
    }
    assert(result.found == null or result.found.? < end);
    return result;
}

/// Evaluates one factory index: a candidate when actionable, else null.
pub fn evaluate_game(view: chain.ChainView, index: u64) chain.ReadError!?CandidateGame {
    const factory = try view.game_at_index(index);
    const state = try view.game_state(factory.proxy);
    if (state.status != .in_progress) return null;
    if (chain.is_zero(state.tee_prover) and chain.is_zero(state.zk_prover)) return null;
    const category = classify(state.tee_prover, state.zk_prover, state.countered_index) orelse
        return null;
    const info = try view.game_info(factory.proxy);
    if (info.intervals.intermediate_block == 0) return error.ChainUnavailable;
    const candidate: CandidateGame = .{
        .index = index,
        .proxy = factory.proxy,
        .game_type = factory.game_type,
        .root_claim = info.root_claim,
        .l2_block_number = info.l2_block_number,
        .starting_block_number = info.starting_block_number,
        .intermediate_block_interval = info.intervals.intermediate_block,
        .l1_head = info.l1_head,
        .tee_prover = state.tee_prover,
        .category = category,
    };
    assert(candidate.intermediate_block_interval > 0);
    return candidate;
}

test {
    _ = @import("scanner_test.zig");
}

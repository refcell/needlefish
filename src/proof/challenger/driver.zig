//! Challenger driver (base/base `crates/proof/challenge/src/driver.rs`): one `tick(now)`
//! per poll interval runs a step: advance pending dispute attempts, bonds and the anchor,
//! then scan for candidate games, validate them, and start a dispute attempt for every
//! invalid one. All IO goes through the injected `chain.World`, so the same driver runs
//! against fakes in the simulator and against network adapters in the binary.

const std = @import("std");
const assert = std.debug.assert;

const chain = @import("chain.zig");
const config_module = @import("config.zig");
const scanner_module = @import("scanner.zig");
const validator = @import("validator.zig");
const proof_manager_module = @import("proof_manager.zig");
const bond = @import("bond.zig");
const anchor = @import("anchor.zig");
const contracts = @import("../contracts/root.zig");

const Hash = chain.Hash;
const CandidateGame = scanner_module.CandidateGame;
const DisputeIntent = @import("dispute_attempt.zig").DisputeIntent;

/// Candidates processed per step.
pub const candidates_max = 64;

pub const Stats = struct {
    steps: u64 = 0,
    scan_errors: u64 = 0,
    candidate_errors: u64 = 0,
    valid_games: u64 = 0,
    invalid_detected: u64 = 0,
    legitimate_challenges: u64 = 0,
    fraudulent_challenges: u64 = 0,
    games_scanned: u64 = 0,
};

pub const Driver = struct {
    config: config_module.Config,
    world: chain.World,
    scanner: scanner_module.Scanner,
    proof_manager: proof_manager_module.ProofManager,
    bond_manager: bond.BondManager,
    anchor_updater: anchor.AnchorUpdater,
    last_step_ns: ?u64,
    stats: Stats,
    candidates: [candidates_max]CandidateGame,
    roots: [contracts.dispute_game_factory.intermediate_roots_max]Hash,

    /// Initializes in place (the driver holds its buffers). The config must be valid.
    pub fn init(driver: *Driver, config: config_module.Config, world: chain.World) void {
        config.validate() catch unreachable;
        driver.config = config;
        driver.world = world;
        driver.scanner = .init(config.games_per_scan_max);
        driver.proof_manager.init(config.max_proof_duration_ns, config.tee_submit_retry_limit);
        driver.bond_manager = .init(.{
            .claim_addresses = config.bond_claim_addresses,
            .lookback_games = config.bond_lookback_games,
            .discovery_interval_ns = config.bond_discovery_interval_ns,
        });
        driver.anchor_updater = .init(config.game_type, config.anchor_state_registry);
        driver.last_step_ns = null;
        driver.stats = .{};
        assert(driver.proof_manager.pending_count() == 0);
    }

    /// Runs a step when the poll interval has passed since the last one.
    pub fn tick(driver: *Driver, now_ns: u64) void {
        if (driver.last_step_ns) |last| {
            assert(now_ns >= last);
            if (now_ns - last < driver.config.poll_interval_ns) return;
        }
        driver.last_step_ns = now_ns;
        driver.step(now_ns);
        assert(driver.proof_manager.pending_count() <= proof_manager_module.attempts_max);
    }

    pub fn step(driver: *Driver, now_ns: u64) void {
        driver.stats.steps += 1;
        driver.proof_manager.poll(driver.world, now_ns);
        driver.bond_manager.discover(driver.world, now_ns) catch {
            driver.bond_manager.stats.read_errors += 1;
        };
        driver.anchor_updater.poll(driver.world, now_ns);
        const scan = driver.scanner.scan(driver.world.chain, &driver.candidates) catch {
            driver.stats.scan_errors += 1;
            return;
        };
        driver.stats.games_scanned += scan.games_scanned;
        for (scan.candidates) |*candidate| {
            driver.process_candidate(candidate, now_ns) catch {
                driver.stats.candidate_errors += 1;
            };
        }
        assert(scan.candidates.len <= candidates_max);
    }

    fn process_candidate(driver: *Driver, candidate: *const CandidateGame, now_ns: u64) !void {
        if (driver.proof_manager.is_ignored(candidate.proxy)) return;
        if (driver.proof_manager.has_pending_proof(candidate.proxy)) return;
        switch (candidate.category) {
            .invalid_tee_proposal => try driver.process_invalid_proposal(
                candidate,
                .challenge,
                true,
                now_ns,
            ),
            .fraudulent_zk_challenge => |index| try driver.process_fraudulent_zk_challenge(
                candidate,
                index,
                now_ns,
            ),
            .invalid_zk_proposal => try driver.process_invalid_proposal(
                candidate,
                .nullify,
                false,
                now_ns,
            ),
            .invalid_dual_proposal => try driver.process_invalid_proposal(
                candidate,
                .nullify,
                true,
                now_ns,
            ),
        }
    }

    /// Validates every intermediate root; null when the game cannot be judged yet (blocks
    /// not available, transient read errors).
    fn validate_game(
        driver: *Driver,
        candidate: *const CandidateGame,
    ) !?validator.ValidationResult {
        const roots = try driver.world.chain.intermediate_roots(candidate.proxy, &driver.roots);
        const result = validator.validate_intermediate_roots(driver.world.chain, .{
            .starting_block_number = candidate.starting_block_number,
            .l2_block_number = candidate.l2_block_number,
            .intermediate_block_interval = candidate.intermediate_block_interval,
            .claimed_root = candidate.root_claim,
            .intermediate_roots = roots,
        }) catch |err| switch (err) {
            error.CheckpointCountMismatch, error.InvalidBlockRange => return err,
            else => return null,
        };
        assert(result.is_valid == (result.invalid_intermediate_index == null));
        return result;
    }

    fn process_invalid_proposal(
        driver: *Driver,
        candidate: *const CandidateGame,
        intent: DisputeIntent,
        try_tee_first: bool,
        now_ns: u64,
    ) !void {
        assert(candidate.category != .fraudulent_zk_challenge);
        const result = try driver.validate_game(candidate) orelse return;
        if (result.is_valid) {
            driver.stats.valid_games += 1;
            return;
        }
        driver.stats.invalid_detected += 1;
        try driver.proof_manager.initiate_proof(driver.world, driver.config.sender, candidate, .{
            .invalid_index = result.invalid_intermediate_index.?,
            .expected_root = result.expected_root,
        }, intent, try_tee_first, now_ns);
    }

    /// A ZK challenge is fraudulent when the root it challenged was right: then nullify the
    /// challenge with a ZK proof of that root.
    fn process_fraudulent_zk_challenge(
        driver: *Driver,
        candidate: *const CandidateGame,
        challenged_index: u64,
        now_ns: u64,
    ) !void {
        const on_chain_root = try driver.world.chain.intermediate_root(
            candidate.proxy,
            challenged_index,
        );
        const block = try candidate.checkpoint_start_block(challenged_index + 1);
        const validation = validator.validate_claimed_root_at_block(
            driver.world.chain,
            block,
            on_chain_root,
        ) catch return;
        if (!validation.is_valid) {
            driver.stats.legitimate_challenges += 1;
            return;
        }
        driver.stats.fraudulent_challenges += 1;
        assert(std.mem.eql(u8, &validation.expected_root, &on_chain_root));
        try driver.proof_manager.initiate_zk_proof(driver.world, driver.config.sender, candidate, .{
            .invalid_index = challenged_index,
            .expected_root = validation.expected_root,
        }, .nullify, now_ns);
    }
};

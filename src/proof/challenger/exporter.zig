//! The challenger's health, readiness and metrics (base/base `crates/proof/challenge`
//! `metrics.rs` and its health server) over `proof.telemetry`: the driver, bond and anchor
//! counters as `base_challenger_*_total`, ready while steps scan the factory successfully.

const std = @import("std");
const assert = std.debug.assert;

const telemetry = @import("../telemetry/root.zig");
const driver_module = @import("driver.zig");

pub const Stats = struct {
    steps: u64 = 0,
    scan_errors: u64 = 0,
    candidate_errors: u64 = 0,
    games_scanned: u64 = 0,
    valid_games: u64 = 0,
    invalid_detected: u64 = 0,
    legitimate_challenges: u64 = 0,
    fraudulent_challenges: u64 = 0,
    bond_scans: u64 = 0,
    bond_resolves_sent: u64 = 0,
    bond_unlocks_sent: u64 = 0,
    bond_withdrawals_sent: u64 = 0,
    bond_withdrawals_completed: u64 = 0,
    bond_tx_failures: u64 = 0,
    bond_read_errors: u64 = 0,
    anchor_updates_sent: u64 = 0,
    anchor_updates_mined: u64 = 0,
    anchor_skipped: u64 = 0,
    anchor_tx_failures: u64 = 0,
    anchor_read_errors: u64 = 0,

    pub const descriptions = .{
        .steps = "Driver steps.",
        .scan_errors = "Steps whose factory scan failed.",
        .candidate_errors = "Candidate games that failed to evaluate.",
        .games_scanned = "Games scanned.",
        .valid_games = "Games whose output roots checked out.",
        .invalid_detected = "Games with an invalid output root.",
        .legitimate_challenges = "Challenges against invalid games.",
        .fraudulent_challenges = "Challenges against valid games (nullified).",
        .bond_scans = "Bond discovery scans.",
        .bond_resolves_sent = "Game resolutions sent.",
        .bond_unlocks_sent = "Bond unlocks sent.",
        .bond_withdrawals_sent = "Bond withdrawals sent.",
        .bond_withdrawals_completed = "Bond withdrawals mined.",
        .bond_tx_failures = "Bond transactions that failed.",
        .bond_read_errors = "Bond reads that failed.",
        .anchor_updates_sent = "Anchor state updates sent.",
        .anchor_updates_mined = "Anchor state updates mined.",
        .anchor_skipped = "Anchor updates skipped.",
        .anchor_tx_failures = "Anchor update transactions that failed.",
        .anchor_read_errors = "Anchor reads that failed.",
    };
};

pub const Exporter = telemetry.Exporter(Stats, "base_challenger");

/// Copies the driver's counters after a tick; steps whose scan succeeded are progress.
pub fn observe(exporter: *Exporter, driver: *const driver_module.Driver) void {
    const stats = driver.stats;
    const bond = driver.bond_manager.stats;
    const anchor = driver.anchor_updater.stats;
    assert(stats.scan_errors <= stats.steps);
    exporter.observe(.{
        .steps = stats.steps,
        .scan_errors = stats.scan_errors,
        .candidate_errors = stats.candidate_errors,
        .games_scanned = stats.games_scanned,
        .valid_games = stats.valid_games,
        .invalid_detected = stats.invalid_detected,
        .legitimate_challenges = stats.legitimate_challenges,
        .fraudulent_challenges = stats.fraudulent_challenges,
        .bond_scans = bond.scans,
        .bond_resolves_sent = bond.resolves_sent,
        .bond_unlocks_sent = bond.unlocks_sent,
        .bond_withdrawals_sent = bond.withdrawals_sent,
        .bond_withdrawals_completed = bond.withdrawals_completed,
        .bond_tx_failures = bond.tx_failures,
        .bond_read_errors = bond.read_errors,
        .anchor_updates_sent = anchor.updates_sent,
        .anchor_updates_mined = anchor.updates_mined,
        .anchor_skipped = anchor.skipped,
        .anchor_tx_failures = anchor.tx_failures,
        .anchor_read_errors = anchor.read_errors,
    }, stats.steps - stats.scan_errors);
    assert(exporter.counter("steps") == stats.steps);
}

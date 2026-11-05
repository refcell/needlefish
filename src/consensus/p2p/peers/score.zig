//! Gossipsub peer-scoring parameters derived from the L2 block time (base/base
//! `peers/src/score.rs`, itself from the OP Stack "light" scoring profile). Values are
//! plain data consumed by the gossipsub scoring engine; durations are nanoseconds.

const std = @import("std");
const assert = std.debug.assert;

const ns_per_s = std.time.ns_per_s;

pub const Level = enum { off, light };

pub const decay_to_zero: f64 = 0.01;
pub const mesh_weight: f64 = -0.7;
pub const max_in_mesh_score: f64 = 10.0;
pub const decay_epoch: f64 = 5.0;

pub const Thresholds = struct {
    gossip_threshold: f64 = -10.0,
    publish_threshold: f64 = -40.0,
    graylist_threshold: f64 = -40.0,
    accept_px_threshold: f64 = 20.0,
    opportunistic_graft_threshold: f64 = 0.05,
};

pub const thresholds: Thresholds = .{};

pub const TopicParams = struct {
    topic_weight: f64,
    time_in_mesh_weight: f64,
    time_in_mesh_quantum_ns: u64,
    time_in_mesh_cap: f64,
    first_message_deliveries_weight: f64,
    first_message_deliveries_decay: f64,
    first_message_deliveries_cap: f64,
    mesh_message_deliveries_weight: f64,
    mesh_message_deliveries_decay: f64,
    mesh_message_deliveries_cap: f64,
    mesh_message_deliveries_threshold: f64,
    mesh_message_deliveries_window_ns: u64,
    mesh_message_deliveries_activation_ns: u64,
    mesh_failure_penalty_weight: f64,
    mesh_failure_penalty_decay: f64,
    invalid_message_deliveries_weight: f64,
    invalid_message_deliveries_decay: f64,
};

pub const PeerParams = struct {
    topic_score_cap: f64,
    app_specific_weight: f64,
    ip_colocation_factor_weight: f64,
    ip_colocation_factor_threshold: f64,
    behaviour_penalty_weight: f64,
    behaviour_penalty_threshold: f64,
    behaviour_penalty_decay: f64,
    decay_interval_ns: u64,
    decay_to_zero: f64,
    retain_score_ns: u64,
    slow_peer_weight: f64,
    slow_peer_threshold: f64,
    slow_peer_decay: f64,
    /// Applied to every block topic when topic scoring is enabled.
    topic: ?TopicParams,
};

/// Per-decay-interval factor, exactly as base/base computes it: `(1 - decay_to_zero)^(1/n)`
/// with `n = duration / slot`. Note this shrinks a counter to 99% (not 1%) over
/// `duration`; op-node uses `decay_to_zero^(1/n)`. We mirror base/base (AGENTS rule 7).
pub fn score_decay(duration_s: u64, slot_s: u64) f64 {
    assert(slot_s > 0);
    assert(duration_s >= slot_s);
    const times: f64 = @floatFromInt(duration_s / slot_s);
    return std.math.pow(f64, 1.0 - decay_to_zero, 1.0 / times);
}

pub fn in_mesh_cap(slot_s: u64) f64 {
    assert(slot_s > 0);
    return 3600.0 / @as(f64, @floatFromInt(slot_s));
}

pub fn topic_params(block_time_s: u64) TopicParams {
    assert(block_time_s > 0);
    const slot = block_time_s;
    const epoch = slot * 6;
    const invalid_decay_period = 50 * epoch;
    const decay_epoch_s: u64 = @as(u64, @intFromFloat(decay_epoch)) * epoch;
    const slots_per_epoch: f64 = @floatFromInt(epoch / slot);
    const params: TopicParams = .{
        .topic_weight = 0.8,
        .time_in_mesh_weight = max_in_mesh_score / in_mesh_cap(slot),
        .time_in_mesh_quantum_ns = slot * ns_per_s,
        .time_in_mesh_cap = in_mesh_cap(slot),
        .first_message_deliveries_weight = 1.0,
        .first_message_deliveries_decay = score_decay(20 * epoch, slot),
        .first_message_deliveries_cap = 23.0,
        .mesh_message_deliveries_weight = mesh_weight,
        .mesh_message_deliveries_decay = score_decay(decay_epoch_s, slot),
        .mesh_message_deliveries_cap = slots_per_epoch * decay_epoch,
        .mesh_message_deliveries_threshold = slots_per_epoch * decay_epoch / 10.0,
        .mesh_message_deliveries_window_ns = 2 * ns_per_s,
        .mesh_message_deliveries_activation_ns = epoch * 4 * ns_per_s,
        .mesh_failure_penalty_weight = mesh_weight,
        .mesh_failure_penalty_decay = score_decay(decay_epoch_s, slot),
        .invalid_message_deliveries_weight = -140.4475,
        .invalid_message_deliveries_decay = score_decay(invalid_decay_period, slot),
    };
    assert(params.mesh_message_deliveries_threshold < params.mesh_message_deliveries_cap);
    return params;
}

/// Scoring parameters for `level`, or null when scoring is off.
pub fn peer_params(level: Level, topic_scoring: bool, block_time_s: u64) ?PeerParams {
    assert(block_time_s > 0);
    if (level == .off) return null;
    const slot = block_time_s;
    const epoch = slot * 6;
    return .{
        .topic_score_cap = 34.0,
        .app_specific_weight = 1.0,
        .ip_colocation_factor_weight = -35.0,
        .ip_colocation_factor_threshold = 10.0,
        .behaviour_penalty_weight = -16.0,
        .behaviour_penalty_threshold = 6.0,
        .behaviour_penalty_decay = score_decay(epoch * 10, slot),
        .decay_interval_ns = slot * ns_per_s,
        .decay_to_zero = decay_to_zero,
        .retain_score_ns = epoch * 100 * ns_per_s,
        .slow_peer_weight = -0.2,
        .slow_peer_threshold = 0.0,
        .slow_peer_decay = 0.2,
        .topic = if (topic_scoring) topic_params(block_time_s) else null,
    };
}

fn expect_close(expected: f64, actual: f64) !void {
    try std.testing.expectApproxEqRel(expected, actual, 1e-12);
}

test "score: decay matches base/base formula" {
    // 0.99^(1/10): 10 decay intervals reach 1% of the original value.
    try expect_close(std.math.pow(f64, 0.99, 0.1), score_decay(20, 2));
    try expect_close(1800.0, in_mesh_cap(2));
    // base/base semantics: 60 intervals multiply to 1 - decay_to_zero.
    const decay = score_decay(120, 2);
    try expect_close(0.99, std.math.pow(f64, decay, 60));
}

test "score: params for a 2 second block time" {
    const topic = topic_params(2);
    try expect_close(10.0 / 1800.0, topic.time_in_mesh_weight);
    try expect_close(30.0, topic.mesh_message_deliveries_cap);
    try expect_close(3.0, topic.mesh_message_deliveries_threshold);
    const activation_ns = topic.mesh_message_deliveries_activation_ns;
    try std.testing.expectEqual(@as(u64, 48 * ns_per_s), activation_ns);
    try expect_close(score_decay(240, 2), topic.first_message_deliveries_decay);
    try expect_close(score_decay(600, 2), topic.invalid_message_deliveries_decay);

    const light = peer_params(.light, true, 2).?;
    try std.testing.expectEqual(@as(u64, 1200 * ns_per_s), light.retain_score_ns);
    try expect_close(score_decay(120, 2), light.behaviour_penalty_decay);
    try std.testing.expect(light.topic != null);
    try std.testing.expect(peer_params(.light, false, 2).?.topic == null);
    try std.testing.expect(peer_params(.off, true, 2) == null);
}

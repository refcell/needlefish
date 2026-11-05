//! Gossipsub v1.1 peer-score counters and score function (libp2p gossipsub v1.1 spec,
//! "Peer Scoring"), parameterized by `peers/score.zig` (base/base `score.rs`).
//!
//!   score = min(Σ_t topic_weight_t · score_t, topic_score_cap)
//!         + app_specific_weight · app_score
//!         + ip_colocation_factor_weight · max(0, peers_on_ip - threshold)²
//!         + behaviour_penalty_weight · max(0, behaviour_penalty - threshold)²
//!   score_t = w1·min(time_in_mesh/quantum, cap) + w2·min(first_deliveries, cap)
//!           + w3·deficit² (when mesh deliveries are active and below threshold)
//!           + w3b·mesh_failure_penalty + w4·invalid_deliveries²
//!
//! The app-specific score is always 0 (base/base sets no application score).

const std = @import("std");
const assert = std.debug.assert;
const score = @import("../peers/score.zig");

pub const topics_max = 8;

pub const TopicCounters = struct {
    in_mesh: bool = false,
    mesh_joined_ns: u64 = 0,
    first_message_deliveries: f64 = 0,
    mesh_message_deliveries: f64 = 0,
    mesh_message_deliveries_active: bool = false,
    mesh_failure_penalty: f64 = 0,
    invalid_message_deliveries: f64 = 0,
};

pub const Counters = struct {
    topics: [topics_max]TopicCounters = @splat(.{}),
    behaviour_penalty: f64 = 0,

    pub fn graft(counters: *Counters, topic: u8, now_ns: u64) void {
        assert(topic < topics_max);
        const counter = &counters.topics[topic];
        assert(!counter.in_mesh);
        counter.in_mesh = true;
        counter.mesh_joined_ns = now_ns;
        counter.mesh_message_deliveries_active = false;
    }

    /// Leaving the mesh with a delivery deficit becomes a sticky failure penalty.
    pub fn prune(counters: *Counters, params: *const score.TopicParams, topic: u8) void {
        assert(topic < topics_max);
        const counter = &counters.topics[topic];
        assert(counter.in_mesh);
        const threshold = params.mesh_message_deliveries_threshold;
        if (counter.mesh_message_deliveries_active and
            counter.mesh_message_deliveries < threshold)
        {
            const deficit = threshold - counter.mesh_message_deliveries;
            counter.mesh_failure_penalty += deficit * deficit;
        }
        counter.in_mesh = false;
        counter.mesh_message_deliveries_active = false;
    }

    pub fn first_delivery(counters: *Counters, params: *const score.TopicParams, topic: u8) void {
        assert(topic < topics_max);
        const counter = &counters.topics[topic];
        counter.first_message_deliveries = @min(
            counter.first_message_deliveries + 1,
            params.first_message_deliveries_cap,
        );
        if (counter.in_mesh) counters.mesh_delivery(params, topic);
    }

    pub fn mesh_delivery(counters: *Counters, params: *const score.TopicParams, topic: u8) void {
        assert(topic < topics_max);
        const counter = &counters.topics[topic];
        if (!counter.in_mesh) return;
        counter.mesh_message_deliveries = @min(
            counter.mesh_message_deliveries + 1,
            params.mesh_message_deliveries_cap,
        );
    }

    pub fn invalid_delivery(counters: *Counters, topic: u8) void {
        assert(topic < topics_max);
        counters.topics[topic].invalid_message_deliveries += 1;
    }

    /// Applies one decay interval; counters under `decay_to_zero` snap to zero.
    pub fn decay(counters: *Counters, params: *const score.PeerParams, now_ns: u64) void {
        const floor = params.decay_to_zero;
        const penalty_decay = params.behaviour_penalty_decay;
        counters.behaviour_penalty = decayed(counters.behaviour_penalty, penalty_decay, floor);
        const topic_params = params.topic orelse return;
        for (&counters.topics) |*counter| {
            counter.first_message_deliveries = decayed(
                counter.first_message_deliveries,
                topic_params.first_message_deliveries_decay,
                floor,
            );
            counter.mesh_message_deliveries = decayed(
                counter.mesh_message_deliveries,
                topic_params.mesh_message_deliveries_decay,
                floor,
            );
            counter.mesh_failure_penalty = decayed(
                counter.mesh_failure_penalty,
                topic_params.mesh_failure_penalty_decay,
                floor,
            );
            counter.invalid_message_deliveries = decayed(
                counter.invalid_message_deliveries,
                topic_params.invalid_message_deliveries_decay,
                floor,
            );
            if (counter.in_mesh and now_ns -| counter.mesh_joined_ns >=
                topic_params.mesh_message_deliveries_activation_ns)
            {
                counter.mesh_message_deliveries_active = true;
            }
        }
    }

    pub fn compute(
        counters: *const Counters,
        params: *const score.PeerParams,
        peers_on_ip: u32,
        now_ns: u64,
    ) f64 {
        var total: f64 = 0;
        if (params.topic) |topic_params| {
            for (&counters.topics) |*counter| {
                total += topic_params.topic_weight * topic_score(counter, &topic_params, now_ns);
            }
            if (params.topic_score_cap > 0) total = @min(total, params.topic_score_cap);
        }
        const peers: f64 = @floatFromInt(peers_on_ip);
        if (peers > params.ip_colocation_factor_threshold) {
            const surplus = peers - params.ip_colocation_factor_threshold;
            total += params.ip_colocation_factor_weight * surplus * surplus;
        }
        if (counters.behaviour_penalty > params.behaviour_penalty_threshold) {
            const excess = counters.behaviour_penalty - params.behaviour_penalty_threshold;
            total += params.behaviour_penalty_weight * excess * excess;
        }
        assert(!std.math.isNan(total));
        return total;
    }
};

fn decayed(value: f64, factor: f64, floor: f64) f64 {
    assert(factor >= 0 and factor <= 1);
    const next = value * factor;
    return if (next < floor) 0 else next;
}

fn topic_score(counter: *const TopicCounters, params: *const score.TopicParams, now_ns: u64) f64 {
    var result: f64 = 0;
    if (counter.in_mesh) {
        const quantum: f64 = @floatFromInt(params.time_in_mesh_quantum_ns);
        const in_mesh: f64 = @floatFromInt(now_ns -| counter.mesh_joined_ns);
        result += params.time_in_mesh_weight * @min(in_mesh / quantum, params.time_in_mesh_cap);
    }
    result += params.first_message_deliveries_weight * counter.first_message_deliveries;
    const threshold = params.mesh_message_deliveries_threshold;
    if (counter.mesh_message_deliveries_active and counter.mesh_message_deliveries < threshold) {
        const deficit = threshold - counter.mesh_message_deliveries;
        result += params.mesh_message_deliveries_weight * deficit * deficit;
    }
    result += params.mesh_failure_penalty_weight * counter.mesh_failure_penalty;
    const invalid = counter.invalid_message_deliveries;
    result += params.invalid_message_deliveries_weight * invalid * invalid;
    return result;
}

const ns_per_s = std.time.ns_per_s;

test "peer_score: deliveries raise, invalid messages sink the score" {
    const params = score.peer_params(.light, true, 2).?;
    const topic = params.topic.?;
    var counters: Counters = .{};
    try std.testing.expectEqual(@as(f64, 0), counters.compute(&params, 1, 0));
    counters.graft(0, 0);
    counters.first_delivery(&topic, 0);
    const good = counters.compute(&params, 1, 10 * ns_per_s);
    try std.testing.expect(good > 0);
    counters.invalid_delivery(0);
    const sunk = counters.compute(&params, 1, 10 * ns_per_s);
    try std.testing.expect(sunk < -params.topic_score_cap);
    // base/base decay shrinks a counter to 99% over its decay period (300 intervals here).
    for (0..300) |_| counters.decay(&params, 10 * ns_per_s);
    try std.testing.expectApproxEqRel(0.99, counters.topics[0].invalid_message_deliveries, 1e-9);
}

test "peer_score: mesh delivery deficit and failure penalty" {
    const params = score.peer_params(.light, true, 2).?;
    const topic = params.topic.?;
    var counters: Counters = .{};
    counters.graft(1, 0);
    counters.decay(&params, topic.mesh_message_deliveries_activation_ns);
    try std.testing.expect(counters.topics[1].mesh_message_deliveries_active);
    const now = topic.mesh_message_deliveries_activation_ns;
    try std.testing.expect(counters.compute(&params, 1, now) < 0);
    counters.prune(&topic, 1);
    try std.testing.expect(counters.topics[1].mesh_failure_penalty > 0);
    try std.testing.expect(counters.compute(&params, 1, now) < 0);
}

test "peer_score: colocation and behaviour penalties" {
    const params = score.peer_params(.light, false, 2).?;
    var counters: Counters = .{};
    try std.testing.expectEqual(@as(f64, 0), counters.compute(&params, 10, 0));
    try std.testing.expectEqual(@as(f64, -35), counters.compute(&params, 11, 0));
    counters.behaviour_penalty = 8;
    try std.testing.expectEqual(@as(f64, -35 - 64), counters.compute(&params, 11, 0));
}

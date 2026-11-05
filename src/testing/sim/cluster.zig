//! Deterministic cluster simulation: model nodes on a simulated network with fault
//! injection and invariant checks. One seed fixes the swarm config, the fault
//! schedule, and every network decision, so a failing seed is a complete bug report.
//!
//! Phases:
//!   1. faults:  [0, fault_end)          crashes, partitions (group and one-way), drops,
//!                                       disk faults, clock skew, L1 reorgs, inbox
//!                                       spam (forged channels from a non-batcher)
//!   2. heal:    fault_end               restart everything, heal partitions, stop drops
//!   3. drain:   [fault_end, settle_end) sequencer stops at production_end; then
//!               liveness requires every verifier to reach the sequencer head, safe and
//!               unsafe, and the batcher to confirm it on L1.
//!
//! Safety invariants are checked after every step:
//!   - every verifier block at or below its unsafe head matches the sequencer chain
//!   - safe head <= unsafe head <= sequencer head
//!   - safe head never decreases within one incarnation of a verifier
//!   - no reorgs and no equivocations (the model is honest)
//!   - every L1 batcher transaction decodes with the real protocol codecs (codec.zig)
//!   - batcher confirmed <= L1-included <= sequencer head

const std = @import("std");
const assert = std.debug.assert;
const Prng = @import("../prng.zig").Prng;
const network_module = @import("network.zig");
const nodes = @import("nodes.zig");
const codec = @import("codec.zig");
const real_batcher = @import("real_batcher.zig");
const NodeId = network_module.NodeId;

pub const verifier_count_max = network_module.node_count_max - nodes.node_verifier_first;
pub const step_ns: u64 = 10 * std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;

pub const Config = struct {
    verifier_count: u8 = 2,
    network: network_module.Config = .{},
    l2_block_time_ns: u64 = 2 * ns_per_s,
    l1_block_time_ns: u64 = 12 * ns_per_s,
    fault_end_ns: u64 = 600 * ns_per_s,
    production_end_ns: u64 = 660 * ns_per_s,
    settle_end_ns: u64 = 960 * ns_per_s,
    /// Expected faults per simulated minute during the fault phase.
    crashes_per_minute: u32 = 1,
    partitions_per_minute: u32 = 1,
    /// Probability a restart loses the latest durable write, in parts per million.
    disk_fault_ppm: u32 = 100_000,
    downtime_ns_max: u64 = 60 * ns_per_s,
    l1_reorgs_per_minute: u32 = 0,
    /// Each non-L1 node's clock is offset by up to this much, re-drawn on restart.
    clock_skew_ns_max: u64 = 0,
    /// Forged channels an attacker posts to the batch inbox per minute (fault phase).
    spam_per_minute: u32 = 0,
    /// Run the batcher lane's real service (JSON-RPC against model state) instead of
    /// the model batcher's submissions.
    real_batcher: bool = false,

    /// Swarm testing: a random but valid configuration per seed. Different seeds explore
    /// different corners (one verifier vs many, lossy vs clean, flaky vs stable).
    pub fn random(prng: *Prng) Config {
        const latency_ns_min = prng.range(1, 50) * std.time.ns_per_ms;
        const config: Config = .{
            .verifier_count = @intCast(prng.range(1, verifier_count_max)),
            .network = .{
                .latency_ns_min = latency_ns_min,
                .latency_ns_max = latency_ns_min + prng.range(0, 500) * std.time.ns_per_ms,
                .drop_ppm = @intCast(swarm_level(prng, 300_000)),
                .duplicate_ppm = @intCast(swarm_level(prng, 200_000)),
                .capacity = 4096,
            },
            .crashes_per_minute = @intCast(swarm_level(prng, 6)),
            .partitions_per_minute = @intCast(swarm_level(prng, 4)),
            .disk_fault_ppm = @intCast(swarm_level(prng, 500_000)),
            .downtime_ns_max = prng.range(1, 120) * ns_per_s,
            .clock_skew_ns_max = swarm_level(prng, 30) * ns_per_s,
            .l1_reorgs_per_minute = @intCast(swarm_level(prng, 3)),
            .spam_per_minute = @intCast(swarm_level(prng, 6)),
            .real_batcher = prng.chance(1, 2),
        };
        config.validate();
        return config;
    }

    pub fn validate(config: Config) void {
        assert(config.verifier_count >= 1 and config.verifier_count <= verifier_count_max);
        assert(config.l2_block_time_ns >= step_ns);
        assert(config.l1_block_time_ns >= step_ns);
        assert(config.fault_end_ns <= config.production_end_ns);
        assert(config.production_end_ns < config.settle_end_ns);
        assert(config.disk_fault_ppm <= 1_000_000);
        assert(config.downtime_ns_max > 0);
        assert(config.clock_skew_ns_max <= config.settle_end_ns - config.production_end_ns);
    }

    pub fn block_count_max(config: Config) u64 {
        return config.production_end_ns / config.l2_block_time_ns + 1;
    }

    /// Batcher submissions over the whole run: one per submit interval, doubled for the
    /// immediate submission after each batcher restart.
    pub fn tx_count_max(config: Config) u32 {
        const batcher = 2 * (config.settle_end_ns / nodes.Batcher.submit_interval_ns) + 16;
        // Chance-per-step injection can exceed the mean; four times it is ample headroom.
        const spam = 4 * config.spam_per_minute * (config.fault_end_ns / (60 * ns_per_s) + 1);
        // The real txmgr appends every attempt, including fee-bump resubmissions.
        const real = if (config.real_batcher) 8 * (config.settle_end_ns / ns_per_s) else 0;
        return @intCast(batcher + spam + real);
    }

    pub fn l1_block_count_max(config: Config) u64 {
        return config.settle_end_ns / config.l1_block_time_ns + 1;
    }
};

/// Off a quarter of the time, otherwise uniform up to `max`: swarm testing disables
/// whole fault classes on some seeds so the remaining ones get room to bite.
fn swarm_level(prng: *Prng, max: u64) u64 {
    if (prng.chance(1, 4)) return 0;
    return prng.range(0, max);
}

pub const Failure = error{ SafetyViolation, LivenessViolation };

pub const Report = struct {
    steps: u64 = 0,
    crashes: u64 = 0,
    partitions: u64 = 0,
    asymmetric_partitions: u64 = 0,
    spam: u64 = 0,
    disk_faults: u64 = 0,
    l1_reorgs: u64 = 0,
    sequencer_head: u64 = 0,
    l1_head: u64 = 0,
    network: network_module.Stats = .{},
};

pub const Cluster = struct {
    config: Config,
    now_ns: u64 = 0,
    prng_network: Prng,
    prng_nodes: Prng,
    prng_faults: Prng,
    network: nodes.Net,
    l1: nodes.L1,
    sequencer: nodes.Sequencer,
    batcher: nodes.Batcher,
    tx_pool: codec.TxPool,
    attacker: codec.Encoder,
    real: ?*real_batcher.RealBatcher,
    allocator: std.mem.Allocator,
    verifiers: [verifier_count_max]nodes.Verifier,
    /// Per node: time at which a crashed node restarts, or null when up. L1 never crashes.
    restart_ns: [network_module.node_count_max]?u64 = @splat(null),
    /// Per node clock offset from global time. L1 is the reference and stays at zero.
    clock_offset_ns: [network_module.node_count_max]i64 = @splat(0),
    heal_ns: ?u64 = null,
    safe_floor: [verifier_count_max]u64 = @splat(0),
    /// Follower rewinds seen per verifier; an L1 reorg may legitimately lower safe heads.
    rewinds_seen: [verifier_count_max]u64 = @splat(0),
    report: Report = .{},
    /// Print a diagnosis on violation. Negative tests turn it off: the test runner treats
    /// stderr output as a failure.
    log_failures: bool = true,

    pub fn init(allocator: std.mem.Allocator, seed: u64, config: Config) !Cluster {
        config.validate();
        var network = try nodes.Net.init(allocator, config.network);
        errdefer network.deinit(allocator);
        var l1 = try nodes.L1.init(allocator, config.l1_block_count_max(), config.l1_block_time_ns);
        errdefer l1.deinit(allocator);
        var sequencer_chain = try nodes.Chain.init(allocator, config.block_count_max());
        errdefer sequencer_chain.deinit(allocator);
        var batcher = try nodes.Batcher.init(allocator, config.l1_block_count_max());
        errdefer batcher.deinit(allocator);
        var tx_pool = try codec.TxPool.init(allocator, config.tx_count_max());
        errdefer tx_pool.deinit(allocator);
        var attacker = try codec.Encoder.init(allocator, 0x6174_7461_636b_6572);
        errdefer attacker.deinit(allocator);
        const RealBatcher = real_batcher.RealBatcher;
        const real = if (config.real_batcher) try RealBatcher.create(allocator) else null;
        errdefer if (real) |r| r.destroy(allocator);
        batcher.submitting = real == null;
        var verifiers: [verifier_count_max]nodes.Verifier = undefined;
        var initialized: u8 = 0;
        errdefer for (verifiers[0..initialized]) |*v| v.deinit(allocator);
        while (initialized < config.verifier_count) : (initialized += 1) {
            verifiers[initialized] = try nodes.Verifier.init(
                allocator,
                nodes.node_verifier_first + initialized,
                config.block_count_max(),
                config.l1_block_count_max(),
            );
        }
        return .{
            .config = config,
            .prng_network = Prng.init(seed ^ 0x6e65_7477_6f72_6b00),
            .prng_nodes = Prng.init(seed ^ 0x6e6f_6465_7300_0000),
            .prng_faults = Prng.init(seed ^ 0x6661_756c_7473_0000),
            .network = network,
            .l1 = l1,
            .sequencer = .{
                .chain = sequencer_chain,
                .block_time_ns = config.l2_block_time_ns,
                .next_block_ns = config.l2_block_time_ns,
            },
            .batcher = batcher,
            .tx_pool = tx_pool,
            .attacker = attacker,
            .real = real,
            .allocator = allocator,
            .verifiers = verifiers,
        };
    }

    pub fn deinit(cluster: *Cluster, allocator: std.mem.Allocator) void {
        for (cluster.verifiers[0..cluster.config.verifier_count]) |*v| v.deinit(allocator);
        cluster.batcher.deinit(allocator);
        cluster.tx_pool.deinit(allocator);
        cluster.attacker.deinit(allocator);
        if (cluster.real) |real| real.destroy(allocator);
        cluster.sequencer.chain.deinit(allocator);
        cluster.l1.deinit(allocator);
        cluster.network.deinit(allocator);
        cluster.* = undefined;
    }

    fn env(cluster: *Cluster, node: NodeId) nodes.Env {
        const offset_ns = cluster.clock_offset_ns[node];
        const local_ns: i64 = @as(i64, @intCast(cluster.now_ns)) + offset_ns;
        return .{
            .now_ns = @intCast(@max(0, local_ns)),
            .global_ns = cluster.now_ns,
            .prng = &cluster.prng_network,
            .network = &cluster.network,
            .verifier_count = cluster.config.verifier_count,
            .tx_pool = &cluster.tx_pool,
        };
    }

    fn random_clock_offset(cluster: *Cluster) i64 {
        const skew_max: i64 = @intCast(cluster.config.clock_skew_ns_max);
        if (skew_max == 0) return 0;
        const span: u64 = @intCast(2 * skew_max);
        return @as(i64, @intCast(cluster.prng_faults.range(0, span))) - skew_max;
    }

    fn up(cluster: *const Cluster, node: NodeId) bool {
        return cluster.restart_ns[node] == null;
    }

    /// Run all phases. Returns the report, or a Failure after printing a diagnosis.
    pub fn run(cluster: *Cluster) Failure!Report {
        const steps_max = cluster.config.settle_end_ns / step_ns;
        assert(cluster.now_ns == 0);
        var node: NodeId = nodes.node_sequencer;
        while (node < nodes.node_verifier_first + cluster.config.verifier_count) : (node += 1) {
            cluster.clock_offset_ns[node] = cluster.random_clock_offset();
        }
        var step: u64 = 0;
        while (step < steps_max) : (step += 1) {
            cluster.now_ns += step_ns;
            if (cluster.now_ns < cluster.config.fault_end_ns) cluster.inject_faults();
            if (cluster.now_ns >= cluster.config.fault_end_ns) cluster.heal_all();
            if (cluster.now_ns >= cluster.config.production_end_ns) {
                cluster.sequencer.producing = false;
            }
            cluster.restart_due();
            cluster.deliver();
            cluster.tick();
            try cluster.check_safety();
        }
        cluster.report.steps = steps_max;
        try cluster.check_liveness();
        cluster.report.sequencer_head = cluster.sequencer.head;
        cluster.report.l1_head = cluster.l1.head;
        cluster.report.network = cluster.network.stats;
        return cluster.report;
    }

    fn deliver(cluster: *Cluster) void {
        while (cluster.network.pop_due(cluster.now_ns)) |packet| {
            if (!cluster.up(packet.to)) continue;
            const e = cluster.env(packet.to);
            switch (packet.to) {
                nodes.node_l1 => cluster.l1.on_message(&e, packet.from, packet.message),
                nodes.node_sequencer => {
                    cluster.sequencer.on_message(&e, packet.from, packet.message);
                },
                nodes.node_batcher => cluster.batcher.on_message(&e, packet.from, packet.message),
                else => {
                    const index = packet.to - nodes.node_verifier_first;
                    assert(index < cluster.config.verifier_count);
                    cluster.verifiers[index].on_message(&e, packet.from, packet.message);
                },
            }
        }
    }

    fn tick(cluster: *Cluster) void {
        cluster.l1.tick(&cluster.env(nodes.node_l1));
        if (cluster.up(nodes.node_sequencer)) {
            cluster.sequencer.tick(&cluster.env(nodes.node_sequencer));
        }
        if (cluster.up(nodes.node_batcher)) {
            const e = cluster.env(nodes.node_batcher);
            cluster.batcher.tick(&e, &cluster.sequencer);
            if (cluster.real) |real| real.tick(e.now_ns, cluster.real_view());
        }
        for (cluster.verifiers[0..cluster.config.verifier_count]) |*verifier| {
            if (cluster.up(verifier.id)) verifier.tick(&cluster.env(verifier.id));
        }
    }

    fn linked(cluster: *const Cluster, a: NodeId, b: NodeId) bool {
        const network = &cluster.network;
        return cluster.up(a) and cluster.up(b) and
            !network.is_blocked(a, b) and !network.is_blocked(b, a);
    }

    /// What the real batcher's RPC clients can reach: its L1, the sequencer's EL, and
    /// the first verifier as its rollup node.
    fn real_view(cluster: *Cluster) real_batcher.View {
        const batcher = nodes.node_batcher;
        const rollup_node = nodes.node_verifier_first;
        const rollup = &cluster.verifiers[0];
        return .{
            .l1 = &cluster.l1,
            .sequencer = &cluster.sequencer,
            .pool = &cluster.tx_pool,
            .prng = &cluster.prng_faults,
            .l1_reachable = cluster.linked(batcher, nodes.node_l1),
            .l2_reachable = cluster.linked(batcher, nodes.node_sequencer),
            .rollup = if (cluster.linked(batcher, rollup_node))
                .{ .safe = rollup.safe_head, .unsafe = rollup.unsafe_head }
            else
                null,
            .drop_ppm = cluster.network.config.drop_ppm,
        };
    }

    fn inject_faults(cluster: *Cluster) void {
        const steps_per_minute = 60 * ns_per_s / step_ns;
        const prng = &cluster.prng_faults;
        if (prng.chance(cluster.config.crashes_per_minute, steps_per_minute)) {
            // Any node but L1. Crashing an already-down node extends nothing.
            const node: NodeId = @intCast(prng.range(1, 2 + cluster.config.verifier_count));
            if (cluster.up(node)) {
                cluster.restart_ns[node] = cluster.now_ns +
                    prng.range(step_ns, cluster.config.downtime_ns_max);
                cluster.report.crashes += 1;
            }
        }
        if (prng.chance(cluster.config.l1_reorgs_per_minute, steps_per_minute)) {
            const depth_max = @min(nodes.l1_reorg_depth_max, cluster.l1.head);
            if (depth_max > 0) {
                cluster.l1.reorg(&cluster.env(nodes.node_l1), prng.range(1, depth_max));
                cluster.report.l1_reorgs += 1;
            }
        }
        if (prng.chance(cluster.config.spam_per_minute, steps_per_minute)) {
            cluster.inject_spam(prng);
        }
        if (cluster.heal_ns) |heal_ns| {
            if (cluster.now_ns >= heal_ns) {
                cluster.network.heal();
                cluster.heal_ns = null;
            }
        } else if (prng.chance(cluster.config.partitions_per_minute, steps_per_minute)) {
            cluster.inject_partition(prng);
            cluster.heal_ns = cluster.now_ns + prng.range(step_ns, cluster.config.downtime_ns_max);
            cluster.report.partitions += 1;
        }
    }

    /// Half symmetric group splits, half asymmetric: random one-way link cuts, which
    /// model a node that can send but not receive (or the reverse).
    fn inject_partition(cluster: *Cluster, prng: *Prng) void {
        const node_count = nodes.node_verifier_first + cluster.config.verifier_count;
        if (prng.chance(1, 2)) {
            var group: [network_module.node_count_max]u8 = @splat(0);
            for (&group) |*g| g.* = @intFromBool(prng.chance(1, 2));
            cluster.network.partition(group);
            return;
        }
        var from: NodeId = 0;
        while (from < node_count) : (from += 1) {
            var to: NodeId = 0;
            while (to < node_count) : (to += 1) {
                if (from != to and prng.chance(1, 4)) cluster.network.block_link(from, to);
            }
        }
        cluster.report.asymmetric_partitions += 1;
    }

    /// An attacker posts a well-formed channel that rewrites recent blocks with different
    /// payloads. Only the derive lane's sender filter keeps verifiers from adopting it.
    fn inject_spam(cluster: *Cluster, prng: *Prng) void {
        const head = cluster.sequencer.head;
        if (head == 0) return;
        const first = prng.range(1, head);
        const count: usize = @intCast(@min(codec.blocks_max, head - first + 1));
        var payloads: [codec.blocks_max]u64 = undefined;
        for (payloads[0..count], first..) |*payload, number| {
            payload.* = cluster.sequencer.chain.payloads[number] +% 1;
        }
        const hashes = cluster.sequencer.chain.hashes[first - 1 ..][0 .. count + 1];
        const data = cluster.attacker.encode(first, hashes, payloads[0..count]);
        const tx_index = cluster.tx_pool.append(data) orelse return;
        const e = cluster.env(nodes.node_l1);
        cluster.l1.on_message(&e, nodes.node_l1, .{ .batch_submit = .{
            .tx_index = tx_index,
            .sender = codec.sender_attacker,
        } });
        cluster.report.spam += 1;
    }

    fn heal_all(cluster: *Cluster) void {
        cluster.network.heal();
        cluster.heal_ns = null;
        cluster.network.config.drop_ppm = 0;
        cluster.network.config.duplicate_ppm = 0;
        for (&cluster.restart_ns) |*restart_ns| {
            if (restart_ns.*) |*ns| ns.* = @min(ns.*, cluster.now_ns);
        }
    }

    fn restart_due(cluster: *Cluster) void {
        for (&cluster.restart_ns, 0..) |*restart_ns, node_index| {
            const ns = restart_ns.* orelse continue;
            if (cluster.now_ns < ns) continue;
            restart_ns.* = null;
            const node: NodeId = @intCast(node_index);
            assert(node != nodes.node_l1);
            // A restart may come back with a different clock: jumps forward or backward.
            cluster.clock_offset_ns[node] = cluster.random_clock_offset();
            const e = cluster.env(node);
            switch (node) {
                nodes.node_sequencer => cluster.sequencer.restart(&e),
                nodes.node_batcher => {
                    cluster.batcher.restart(&e);
                    if (cluster.real) |real| {
                        // Proof: the service re-allocates what it just freed.
                        real.restart(cluster.allocator, e.now_ns) catch unreachable;
                    }
                },
                else => {
                    const index = node - nodes.node_verifier_first;
                    const disk_fault = cluster.prng_faults.chance(
                        cluster.config.disk_fault_ppm,
                        1_000_000,
                    );
                    cluster.report.disk_faults += @intFromBool(disk_fault);
                    cluster.verifiers[index].restart(disk_fault);
                    cluster.safe_floor[index] = cluster.verifiers[index].safe_head;
                },
            }
        }
    }

    fn check_safety(cluster: *Cluster) Failure!void {
        const sequencer = &cluster.sequencer;
        if (cluster.batcher.confirmed > sequencer.head) {
            return cluster.fail("batcher confirmed beyond sequencer head", 0);
        }
        for (cluster.verifiers[0..cluster.config.verifier_count], 0..) |*v, index| {
            if (v.safe_head > v.unsafe_head) return cluster.fail("safe > unsafe", v.id);
            if (v.unsafe_head > sequencer.head) return cluster.fail("unsafe > sequencer", v.id);
            if (v.follower.rewinds != cluster.rewinds_seen[index]) {
                cluster.rewinds_seen[index] = v.follower.rewinds;
                cluster.safe_floor[index] = v.safe_head;
            }
            if (v.safe_head < cluster.safe_floor[index]) {
                return cluster.fail("safe head decreased", v.id);
            }
            cluster.safe_floor[index] = v.safe_head;
            if (v.reorgs != 0) return cluster.fail("unexpected reorg", v.id);
            if (v.equivocations != 0) return cluster.fail("equivocation", v.id);
            if (v.invalid_batches != 0) return cluster.fail("undecodable batch", v.id);
            // Heads only: earlier blocks were checked when they were heads, and parent
            // hashes chain them, so a head match implies the whole prefix matches.
            if (v.chain.hashes[v.unsafe_head] != sequencer.chain.hashes[v.unsafe_head]) {
                return cluster.fail("unsafe head diverged", v.id);
            }
            if (v.chain.hashes[v.safe_head] != sequencer.chain.hashes[v.safe_head]) {
                return cluster.fail("safe head diverged", v.id);
            }
        }
    }

    fn check_liveness(cluster: *Cluster) Failure!void {
        const head = cluster.sequencer.head;
        if (cluster.batcher.confirmed != head) {
            return cluster.fail("batcher did not confirm sequencer head", nodes.node_batcher);
        }
        for (cluster.verifiers[0..cluster.config.verifier_count]) |*v| {
            if (v.unsafe_head != head) return cluster.fail("verifier unsafe head lags", v.id);
            if (v.safe_head != head) return cluster.fail("verifier safe head lags", v.id);
        }
    }

    fn fail(cluster: *const Cluster, reason: []const u8, node: NodeId) Failure {
        if (cluster.log_failures) cluster.print_failure(reason, node);
        return if (std.mem.indexOf(u8, reason, "lags") != null or
            std.mem.indexOf(u8, reason, "did not") != null)
            error.LivenessViolation
        else
            error.SafetyViolation;
    }

    fn print_failure(cluster: *const Cluster, reason: []const u8, node: NodeId) void {
        std.debug.print(
            "simulator: violation at t={d}ms node={d}: {s} (sequencer={d} confirmed={d})\n",
            .{
                cluster.now_ns / std.time.ns_per_ms, node,                      reason,
                cluster.sequencer.head,              cluster.batcher.confirmed,
            },
        );
        for (cluster.verifiers[0..cluster.config.verifier_count]) |*v| {
            std.debug.print("  verifier {d}: safe={d} unsafe={d} l1_cursor={d}\n", .{
                v.id, v.safe_head, v.unsafe_head, v.follower.cursor,
            });
        }
    }
};

/// Run one seed with its swarm config. Used by the simulator binary and the test suite.
pub fn run_seed(allocator: std.mem.Allocator, seed: u64) !Report {
    var prng = Prng.init(seed);
    const config = Config.random(&prng);
    var cluster = try Cluster.init(allocator, seed, config);
    defer cluster.deinit(allocator);
    return cluster.run();
}

test "cluster: fault-free run reaches liveness" {
    var cluster = try Cluster.init(std.testing.allocator, 1, .{
        .crashes_per_minute = 0,
        .partitions_per_minute = 0,
        .fault_end_ns = 60 * ns_per_s,
        .production_end_ns = 120 * ns_per_s,
        .settle_end_ns = 300 * ns_per_s,
    });
    defer cluster.deinit(std.testing.allocator);
    const report = try cluster.run();
    try std.testing.expectEqual(@as(u64, 59), report.sequencer_head);
}

test "cluster: same seed, same run" {
    const a = try run_seed(std.testing.allocator, 42);
    const b = try run_seed(std.testing.allocator, 42);
    try std.testing.expectEqual(a.network.sent, b.network.sent);
    try std.testing.expectEqual(a.network.delivered, b.network.delivered);
    try std.testing.expectEqual(a.crashes, b.crashes);
    try std.testing.expectEqual(a.sequencer_head, b.sequencer_head);
}

test "cluster: checkers catch an equivocating sequencer" {
    // Negative test: the honest model never trips the checkers, so prove they can trip.
    var detected: u32 = 0;
    var seed: u64 = 0;
    while (seed < 8) : (seed += 1) {
        var cluster = try Cluster.init(std.testing.allocator, seed, .{
            .verifier_count = 1,
            .crashes_per_minute = 0,
            .partitions_per_minute = 0,
            .fault_end_ns = 60 * ns_per_s,
            .production_end_ns = 120 * ns_per_s,
            .settle_end_ns = 300 * ns_per_s,
        });
        defer cluster.deinit(std.testing.allocator);
        cluster.sequencer.equivocate_at = 10;
        cluster.log_failures = false;
        _ = cluster.run() catch |err| {
            try std.testing.expectEqual(error.SafetyViolation, err);
            detected += 1;
            continue;
        };
    }
    // The forged block can lose the race to the honest one; most seeds must still detect.
    try std.testing.expect(detected >= 4);
}

test "cluster: checkers catch a batcher posting corrupt tx data" {
    // The verifiers decode L1 data with the real protocol codecs; a corrupted channel
    // must fail decoding (zlib checksum, frame bounds) and trip the checker.
    var seed: u64 = 0;
    while (seed < 4) : (seed += 1) {
        var cluster = try Cluster.init(std.testing.allocator, seed, .{
            .verifier_count = 2,
            .crashes_per_minute = 0,
            .partitions_per_minute = 0,
            .fault_end_ns = 0,
            .production_end_ns = 120 * ns_per_s,
            .settle_end_ns = 300 * ns_per_s,
        });
        defer cluster.deinit(std.testing.allocator);
        cluster.batcher.corrupt_tx = 2;
        cluster.log_failures = false;
        try std.testing.expectError(error.SafetyViolation, cluster.run());
    }
}

test "cluster: checkers catch a verifier without the batcher sender check" {
    // Inbox spam is harmless only because derivation filters by sender. A verifier that
    // accepts the attacker's channels adopts forged payloads and must trip safety.
    var seed: u64 = 0;
    while (seed < 4) : (seed += 1) {
        var cluster = try Cluster.init(std.testing.allocator, seed, .{
            .verifier_count = 1,
            .crashes_per_minute = 0,
            .partitions_per_minute = 0,
            .spam_per_minute = 6,
            .fault_end_ns = 120 * ns_per_s,
            .production_end_ns = 180 * ns_per_s,
            .settle_end_ns = 400 * ns_per_s,
        });
        defer cluster.deinit(std.testing.allocator);
        cluster.verifiers[0].sender_check = false;
        cluster.log_failures = false;
        try std.testing.expectError(error.SafetyViolation, cluster.run());
    }
}

test "cluster: inbox spam from a non-batcher sender is ignored" {
    var cluster = try Cluster.init(std.testing.allocator, 2, .{
        .verifier_count = 2,
        .crashes_per_minute = 0,
        .partitions_per_minute = 0,
        .spam_per_minute = 6,
        .fault_end_ns = 120 * ns_per_s,
        .production_end_ns = 180 * ns_per_s,
        .settle_end_ns = 400 * ns_per_s,
    });
    defer cluster.deinit(std.testing.allocator);
    const report = try cluster.run();
    try std.testing.expect(report.spam > 0);
}

test "cluster: real batcher service drives the chain to liveness without faults" {
    var cluster = try Cluster.init(std.testing.allocator, 3, .{
        .verifier_count = 2,
        .crashes_per_minute = 0,
        .partitions_per_minute = 0,
        .real_batcher = true,
        .fault_end_ns = 0,
        .production_end_ns = 120 * ns_per_s,
        .settle_end_ns = 400 * ns_per_s,
    });
    defer cluster.deinit(std.testing.allocator);
    const report = try cluster.run();
    const stats = cluster.real.?.stats();
    try std.testing.expect(stats.submitted > 0);
    try std.testing.expectEqual(report.sequencer_head, cluster.batcher.confirmed);
}

fn fuzz_cluster(_: void, smith: *std.testing.Smith) anyerror!void {
    const fault_end_ns = smith.valueRangeAtMost(u64, 0, 120) * ns_per_s;
    const latency_ns_min = smith.valueRangeAtMost(u64, 1, 100) * std.time.ns_per_ms;
    const config: Config = .{
        .verifier_count = smith.valueRangeAtMost(u8, 1, verifier_count_max),
        .network = .{
            .latency_ns_min = latency_ns_min,
            .latency_ns_max = latency_ns_min +
                smith.valueRangeAtMost(u64, 0, 1000) * std.time.ns_per_ms,
            .drop_ppm = smith.valueRangeAtMost(u32, 0, 500_000),
            .duplicate_ppm = smith.valueRangeAtMost(u32, 0, 500_000),
            .capacity = 4096,
        },
        .fault_end_ns = fault_end_ns,
        .production_end_ns = fault_end_ns + 30 * ns_per_s,
        .settle_end_ns = fault_end_ns + 330 * ns_per_s,
        .crashes_per_minute = smith.valueRangeAtMost(u32, 0, 20),
        .partitions_per_minute = smith.valueRangeAtMost(u32, 0, 20),
        .disk_fault_ppm = smith.valueRangeAtMost(u32, 0, 1_000_000),
        .downtime_ns_max = smith.valueRangeAtMost(u64, 1, 120) * ns_per_s,
        .clock_skew_ns_max = smith.valueRangeAtMost(u64, 0, 60) * ns_per_s,
        .l1_reorgs_per_minute = smith.valueRangeAtMost(u32, 0, 10),
        .spam_per_minute = smith.valueRangeAtMost(u32, 0, 20),
    };
    var cluster = try Cluster.init(std.testing.allocator, smith.value(u64), config);
    defer cluster.deinit(std.testing.allocator);
    _ = try cluster.run();
}

test "cluster: fuzz configs (extreme fault rates)" {
    try @import("../fuzz.zig").run({}, fuzz_cluster, .{ .iterations = 12 });
}

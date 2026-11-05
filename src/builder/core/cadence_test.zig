//! Deterministic simulation of the payload service at Base's native 200 ms cadence, driving
//! `Service` directly over injected time on a Denim-at-genesis chain: every slot the
//! sequencer starts one job (L1-info and BaseTime deposits, then pool transactions), the
//! service builds and seals by the 150 ms cutoff (or seals at once on an early resolve),
//! and the sealed block is imported by both the sequencer and a verifier.
//!
//! Invariants checked per slot: exactly one block per slot, at the Denim schedule's
//! timestamp; no resolve runs past the slot end; the verifier replays every sealed block
//! to the same hash; at the end both chains share head and state root. Seeded runs plus a
//! `std.testing.fuzz` target.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const engine = @import("../../execution/engine/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const fixture = @import("../../execution/node/test_fixture.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const best_txs = @import("best_txs.zig");
const builder_module = @import("builder.zig");
const builder_test = @import("builder_test.zig");
const service_module = @import("service.zig");
const timing = @import("timing.zig");

const types = engine.types;
const B256 = primitives.B256;
const Node = fixture.Node;
const Service = service_module.Service;
const StepClock = builder_test.StepClock;
const ns_per_ms = timing.ns_per_ms;

/// Base devnet with every upgrade through Denim (subsecond blocks) active at genesis.
const denim_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    for (0..@backingInt(chainspec.Upgrade.denim) + 1) |index| result.upgrades[index] = 0;
    break :blk result;
};

const slots_max = 12;
const pool_transactions_max = 32;

const Harness = struct {
    sequencer: *Node,
    verifier: *Node,
    cache: best_txs.RejectionCache,
    builder: builder_module.BlockBuilder,
    clock: StepClock,
    service: Service,
    pool_buffers: [pool_transactions_max][256]u8 = undefined,
    pool_count: u32 = 0,
    nonces: [fixture.senders]u64 = @splat(0),
    calldata: [2][consensus.base_time.calldata_length]u8 = undefined,
    encoded: [2][256]u8 = undefined,
    deposits: [2][]const u8 = undefined,

    fn create() !*Harness {
        const harness = try testing.allocator.create(Harness);
        errdefer testing.allocator.destroy(harness);
        harness.* = .{
            .sequencer = undefined,
            .verifier = undefined,
            .cache = undefined,
            .builder = undefined,
            .clock = .{},
            .service = undefined,
        };
        harness.sequencer = try Node.create_for(&denim_spec);
        errdefer harness.sequencer.destroy();
        harness.verifier = try Node.create_for(&denim_spec);
        errdefer harness.verifier.destroy();
        harness.cache = try best_txs.RejectionCache.init(testing.allocator, 64, 1000);
        errdefer harness.cache.deinit(testing.allocator);
        const cache = &harness.cache;
        harness.builder = try builder_module.BlockBuilder.init(testing.allocator, cache, .{
            .transactions_max = 64,
            .transaction_bytes_max = 1 << 14,
            .select_max = 64,
        });
        errdefer harness.builder.deinit(testing.allocator);
        const clock = builder_module.Clock.of(StepClock, &harness.clock);
        const chain = &harness.sequencer.chain;
        harness.service = try Service.init(&harness.builder, chain, clock, .{});
        return harness;
    }

    fn destroy(harness: *Harness) void {
        harness.builder.deinit(testing.allocator);
        harness.cache.deinit(testing.allocator);
        harness.verifier.destroy();
        harness.sequencer.destroy();
        testing.allocator.destroy(harness);
    }

    /// Adds up to `count` pool transactions with consecutive nonces per sender.
    fn submit(harness: *Harness, prng: *Prng, count: u64) !void {
        for (0..count) |_| {
            if (harness.pool_count == pool_transactions_max) return;
            const sender: u8 = @intCast(prng.below(fixture.senders));
            const buffer = &harness.pool_buffers[harness.pool_count];
            const nonce = harness.nonces[sender];
            try fixture.submit(harness.sequencer, sender + 1, nonce, 5, buffer);
            harness.nonces[sender] = nonce + 1;
            harness.pool_count += 1;
        }
        assert(harness.pool_count <= pool_transactions_max);
    }

    /// The sequencer's attributes for block `number`: a stand-in L1-info deposit and the
    /// BaseTime deposit carrying the schedule's millisecond part.
    fn attributes(harness: *Harness, number: u64) payload.PayloadAttributes {
        const parts = harness.sequencer.chain.denim_schedule().?.parts(number);
        harness.calldata[0] = consensus.base_time.encode_calldata(0);
        harness.calldata[1] = consensus.base_time.encode_calldata(parts.millis_part);
        var info = consensus.base_time.deposit(number, &harness.calldata[0]);
        info.source_hash = .{ .bytes = @splat(@truncate(number)) };
        info.to = .{ .call = fixture.address_of(9) };
        const metadata = consensus.base_time.deposit(number, &harness.calldata[1]);
        const info_envelope: consensus.Envelope = .{ .deposit = info };
        const metadata_envelope: consensus.Envelope = .{ .deposit = metadata };
        harness.deposits[0] = info_envelope.encode_to(&harness.encoded[0]);
        harness.deposits[1] = metadata_envelope.encode_to(&harness.encoded[1]);
        var result = fixture.attributes_l2(parts.seconds, 0xfe);
        result.transactions = &harness.deposits;
        assert(result.timestamp == parts.seconds);
        return result;
    }
};

/// Imports a sealed block through `node`'s Engine API (newPayload, then forkchoice).
fn import(node: *Node, sealed: *const service_module.Payload) !void {
    var execution_payload = engine.block.payload_of(
        &sealed.header,
        sealed.block_hash,
        sealed.transactions,
        sealed.withdrawals,
    );
    execution_payload.withdrawals_root = sealed.header.withdrawals_root;
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = sealed.header.parent_beacon_block_root,
        .execution_requests = &.{},
    };
    const timestamp = sealed.header.timestamp;
    const version = types.new_payload_version(node.spec, timestamp);
    const status = try node.engine.new_payload(version, &execution_payload, &params);
    try testing.expectEqual(types.Status.valid, status.status);
    const choice = fixture.forkchoice(sealed.block_hash);
    const choice_version = types.forkchoice_version(node.spec, timestamp);
    const updated = try node.engine.forkchoice_updated(choice_version, choice, null);
    try testing.expectEqual(types.Status.valid, updated.payload_status.status);
}

/// One slot: start the job at the slot start, maybe tick it (build to the cutoff with a
/// random per-transaction cost), resolve no later than the slot end, import on both nodes.
/// Returns the pool transactions included.
fn run_slot(harness: *Harness, prng: *Prng, number: u64) !u64 {
    const schedule = harness.sequencer.chain.denim_schedule().?;
    // The block's slot is the 200 ms before its scheduled timestamp.
    const slot_start_ns = (schedule.timestamp_ms(number) - 200) * ns_per_ms + 1;
    const service = &harness.service;
    service.tick(slot_start_ns);
    const attributes = harness.attributes(number);
    const head = harness.sequencer.chain.head_hash();
    const id: service_module.PayloadId = @splat(@truncate(number));
    try service.send_new_payload(id, head, &attributes);
    const slot = timing.Slot.init(service.config, slot_start_ns);
    if (prng.chance(3, 4)) {
        // The IO timer fires at the deadline (now): the build reads the stepping clock.
        harness.clock = .{ .now = slot_start_ns, .step_ns = prng.below(60 * ns_per_ms) };
        service.tick(slot_start_ns);
    }
    // getPayload arrives anywhere inside the slot and never runs past its end.
    const resolve_ns = slot_start_ns + prng.below(slot.end_ns - slot_start_ns);
    harness.clock = .{ .now = resolve_ns, .step_ns = 0 };
    service.set_now(resolve_ns);
    const sealed = try (service.resolve(id) orelse return error.TestUnexpectedResult);
    try testing.expect(harness.clock.now <= slot.end_ns);
    try testing.expect(service.active_id() == null);
    try testing.expectEqual(number, sealed.header.number);
    try testing.expectEqual(attributes.timestamp, sealed.header.timestamp);
    try testing.expect(sealed.transactions.len >= 2);
    for (0..2) |index| {
        try testing.expectEqualSlices(u8, harness.deposits[index], sealed.transactions[index]);
    }
    try import(harness.sequencer, &sealed);
    try import(harness.verifier, &sealed);
    // One block per slot: both heads moved to exactly this block.
    for ([_]*Node{ harness.sequencer, harness.verifier }) |node| {
        try testing.expectEqualSlices(u8, &sealed.block_hash.bytes, &node.chain.head_hash());
    }
    return sealed.transactions.len - 2;
}

fn random_cadence(prng: *Prng) !u64 {
    const harness = try Harness.create();
    defer harness.destroy();
    var included: u64 = 0;
    const slots = 1 + prng.below(slots_max);
    for (1..slots + 1) |number| {
        try harness.submit(prng, prng.below(4));
        included += try run_slot(harness, prng, number);
    }
    const sequencer_root = try harness.sequencer.db.root();
    try testing.expectEqualSlices(u8, &sequencer_root, &(try harness.verifier.db.root()));
    const head = harness.verifier.chain.header(harness.verifier.chain.head_hash()).?;
    try testing.expectEqual(@as(u64, slots), head.number);
    return included;
}

test "cadence: one block per 200 ms slot, replayed identically by the verifier" {
    var prng = Prng.init(0x200);
    var included: u64 = 0;
    for (0..12) |_| included += try random_cadence(&prng);
    // The seeds must include pool transactions, not only deposit-only blocks.
    try testing.expect(included >= 8);
}

fn fuzz_cadence(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    _ = try random_cadence(&prng);
}

test "cadence: fuzz" {
    try testing.fuzz({}, fuzz_cadence, .{});
}

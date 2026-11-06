//! `SlotAudit` tests: each violation on a hand-built event stream, then a seeded and a
//! `std.testing.fuzz` generator of valid job lifecycles (resolve, cancel, expire, failed
//! build, failed start; replays out of order) that must audit clean, with one injected fault
//! of a random kind that must be reported as exactly that violation.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const service_module = @import("service.zig");
const slot_audit = @import("slot_audit.zig");
const timing = @import("timing.zig");

const SlotAudit = slot_audit.SlotAudit;
const Violation = slot_audit.Violation;
const Event = service_module.Event;
const PayloadId = service_module.PayloadId;
const B256 = primitives.B256;
const ns_per_ms = timing.ns_per_ms;

fn id_of(value: u64) PayloadId {
    return @bitCast(value);
}

fn hash_of(number: u64) B256 {
    return .{ .bytes = @splat(@truncate(number)) };
}

fn slot_at(start_ns: u64) timing.Slot {
    return timing.Slot.init(.{}, start_ns);
}

fn send(audit: *SlotAudit, event: Event) void {
    audit.on_event(&event);
}

/// A clean block: start, seal at the slot cutoff, resolve inside the slot.
fn block(audit: *SlotAudit, id: u64, number: u64, start_ns: u64) void {
    const slot = slot_at(start_ns);
    send(audit, .{ .started = .{ .id = id_of(id), .number = number, .slot = slot } });
    send(audit, .{ .sealed = .{
        .id = id_of(id),
        .number = number,
        .block_hash = hash_of(number),
        .cutoff_ns = slot.cutoff_ns,
        .stop = .pool_exhausted,
    } });
    send(audit, .{ .resolved = .{ .id = id_of(id), .number = number, .now_ns = slot.cutoff_ns } });
}

test "slot audit: clean blocks, skips and replays" {
    var audit = SlotAudit.init(0);
    block(&audit, 1, 1, 0);
    const slot = slot_at(200 * ns_per_ms);
    send(&audit, .{ .started = .{ .id = id_of(2), .number = 2, .slot = slot } });
    send(&audit, .{ .ended = .{ .id = id_of(2), .number = 2, .reason = .cancelled } });
    block(&audit, 3, 2, 400 * ns_per_ms);
    try testing.expectEqual(@as(u32, 2), audit.unreplayed());
    audit.on_replay(2, hash_of(2));
    audit.on_replay(1, hash_of(1));
    try testing.expectEqual(@as(?Violation, null), audit.violation);
    try testing.expectEqual(@as(u32, 0), audit.unreplayed());
    try testing.expectEqual(@as(u64, 1), audit.skips_total());
    try testing.expectEqual(@as(u64, 0), audit.resolves_late);
}

test "slot audit: each violation" {
    var audit = SlotAudit.init(0);
    const slot = slot_at(0);
    send(&audit, .{ .started = .{ .id = id_of(1), .number = 1, .slot = slot } });
    send(&audit, .{ .started = .{ .id = id_of(2), .number = 1, .slot = slot } });
    try testing.expectEqual(@as(?Violation, .overlapping_jobs), audit.violation);

    audit = SlotAudit.init(0);
    send(&audit, .{ .started = .{ .id = id_of(1), .number = 2, .slot = slot } });
    try testing.expectEqual(@as(?Violation, .number_out_of_order), audit.violation);

    audit = SlotAudit.init(0);
    send(&audit, .{ .resolved = .{ .id = id_of(1), .number = 1, .now_ns = 0 } });
    try testing.expectEqual(@as(?Violation, .unknown_job), audit.violation);

    audit = SlotAudit.init(0);
    send(&audit, .{ .started = .{ .id = id_of(1), .number = 1, .slot = slot } });
    send(&audit, .{ .sealed = .{
        .id = id_of(1),
        .number = 1,
        .block_hash = hash_of(1),
        .cutoff_ns = slot.cutoff_ns + 1,
        .stop = .cutoff,
    } });
    try testing.expectEqual(@as(?Violation, .cutoff_outside_slot), audit.violation);

    audit = SlotAudit.init(0);
    send(&audit, .{ .started = .{ .id = id_of(1), .number = 1, .slot = slot } });
    send(&audit, .{ .resolved = .{ .id = id_of(1), .number = 1, .now_ns = 0 } });
    try testing.expectEqual(@as(?Violation, .seal_out_of_order), audit.violation);

    audit = SlotAudit.init(0);
    block(&audit, 1, 1, 0);
    audit.on_replay(1, hash_of(9));
    try testing.expectEqual(@as(?Violation, .replay_mismatch), audit.violation);

    audit = SlotAudit.init(0);
    audit.on_replay(1, hash_of(1));
    try testing.expectEqual(@as(?Violation, .replay_unknown), audit.violation);
}

test "slot audit: replay backlog is bounded; reset drops reorged blocks" {
    var audit = SlotAudit.init(0);
    for (1..slot_audit.replay_backlog_max + 1) |number| {
        block(&audit, number, number, number * 200 * ns_per_ms);
    }
    try testing.expectEqual(@as(?Violation, null), audit.violation);
    audit.reset(10);
    try testing.expectEqual(@as(u32, 10), audit.unreplayed());
    block(&audit, 100, 11, 100 * 200 * ns_per_ms);
    try testing.expectEqual(@as(?Violation, null), audit.violation);
    try testing.expectEqual(@as(u32, 11), audit.unreplayed());
    // A late getPayload is counted, not a violation.
    const late = slot_at(200 * 200 * ns_per_ms);
    send(&audit, .{ .started = .{ .id = id_of(7), .number = 12, .slot = late } });
    send(&audit, .{ .sealed = .{
        .id = id_of(7),
        .number = 12,
        .block_hash = hash_of(12),
        .cutoff_ns = late.cutoff_ns,
        .stop = .cutoff,
    } });
    send(&audit, .{ .resolved = .{ .id = id_of(7), .number = 12, .now_ns = late.end_ns + 1 } });
    try testing.expectEqual(@as(u64, 1), audit.resolves_late);
    try testing.expectEqual(@as(?Violation, null), audit.violation);
}

const Fault = enum { none, overlap, wrong_number, late_cutoff, wrong_replay, double_seal };

/// Valid random lifecycles with at most one injected `fault` (at a random job); every
/// resolved block is replayed, in random order.
const Generator = struct {
    prng: *Prng,
    fault: Fault,
    fault_job: u64,
    audit: SlotAudit = .init(0),
    number: u64 = 1,
    now_ns: u64 = 0,
    pending: [slot_audit.replay_backlog_max]u64 = undefined,
    pending_count: u32 = 0,
    /// The faulty job's block, replayed to a wrong hash under `.wrong_replay`.
    wrong_number: ?u64 = null,

    fn run(prng: *Prng, fault: Fault) SlotAudit {
        const jobs = 1 + prng.below(40);
        var generator: Generator = .{ .prng = prng, .fault = fault, .fault_job = prng.below(jobs) };
        for (0..jobs) |index| generator.job(index);
        while (generator.pending_count > 0) generator.replay_one();
        assert(generator.audit.unreplayed() == 0 or generator.audit.violation != null);
        return generator.audit;
    }

    fn job(generator: *Generator, job_index: u64) void {
        const prng = generator.prng;
        const faulty = job_index == generator.fault_job;
        const fault: Fault = if (faulty) generator.fault else .none;
        const id = id_of(job_index + 1);
        const number = generator.number;
        const slot = slot_at(generator.now_ns);
        generator.now_ns += 200 * ns_per_ms;
        const outcome = if (faulty) 4 else prng.below(10);
        if (outcome == 0) return send(&generator.audit, .{ .start_failed = .{ .id = id } });
        const start_number = if (fault == .wrong_number) number + 1 else number;
        send(&generator.audit, .{ .started = .{ .id = id, .number = start_number, .slot = slot } });
        if (fault == .overlap) {
            send(&generator.audit, .{ .started = .{ .id = id, .number = number, .slot = slot } });
        }
        if (outcome == 1) {
            return send(&generator.audit, .{ .ended = .{
                .id = id,
                .number = number,
                .reason = .cancelled,
            } });
        }
        generator.seal(id, slot, fault);
        if (outcome == 2) {
            const reason: service_module.EndReason = if (prng.chance(1, 2)) .expired else .failed;
            return send(&generator.audit, .{ .ended = .{
                .id = id,
                .number = number,
                .reason = reason,
            } });
        }
        const resolve_ns = slot.start_ns + prng.below(slot.end_ns - slot.start_ns + 1);
        const resolved: Event = .{ .resolved = .{
            .id = id,
            .number = number,
            .now_ns = resolve_ns,
        } };
        send(&generator.audit, resolved);
        if (fault == .wrong_replay) generator.wrong_number = number;
        generator.pending[generator.pending_count] = number;
        generator.pending_count += 1;
        generator.number += 1;
        while (generator.pending_count > 16 or
            (generator.pending_count > 0 and prng.chance(1, 2))) generator.replay_one();
    }

    fn seal(generator: *Generator, id: PayloadId, slot: timing.Slot, fault: Fault) void {
        const offset_ns = generator.prng.below(slot.cutoff_ns - slot.start_ns + 1);
        var cutoff_ns = slot.start_ns + offset_ns;
        if (fault == .late_cutoff) cutoff_ns = slot.cutoff_ns + 1 + offset_ns;
        const sealed: Event = .{ .sealed = .{
            .id = id,
            .number = generator.number,
            .block_hash = hash_of(generator.number),
            .cutoff_ns = cutoff_ns,
            .stop = .cutoff,
        } };
        send(&generator.audit, sealed);
        if (fault == .double_seal) send(&generator.audit, sealed);
        assert(cutoff_ns >= slot.start_ns);
    }

    fn replay_one(generator: *Generator) void {
        assert(generator.pending_count > 0);
        const index = generator.prng.below(generator.pending_count);
        const number = generator.pending[index];
        const wrong = generator.wrong_number != null and generator.wrong_number.? == number;
        generator.audit.on_replay(number, hash_of(if (wrong) number + 1 else number));
        generator.pending_count -= 1;
        generator.pending[index] = generator.pending[generator.pending_count];
    }
};

fn expected_violation(fault: Fault) ?Violation {
    return switch (fault) {
        .none => null,
        .overlap => .overlapping_jobs,
        .wrong_number => .number_out_of_order,
        .late_cutoff => .cutoff_outside_slot,
        .wrong_replay => .replay_mismatch,
        .double_seal => .seal_out_of_order,
    };
}

fn check_random(prng: *Prng) !void {
    const faults = @typeInfo(Fault).@"enum".field_names.len;
    const fault: Fault = @fromBackingInt(@intCast(prng.below(faults)));
    const audit = Generator.run(prng, fault);
    const ended = audit.blocks_resolved + audit.skips_total();
    try testing.expect(ended <= audit.jobs_started);
    try testing.expectEqual(expected_violation(fault), audit.violation);
    if (fault != .none) return;
    try testing.expectEqual(audit.jobs_started, ended);
    try testing.expectEqual(@as(u32, 0), audit.unreplayed());
    try testing.expectEqual(audit.blocks_resolved, audit.blocks_replayed);
    try testing.expectEqual(@as(u64, 0), audit.resolves_late);
}

test "slot audit: seeded random lifecycles with one injected fault" {
    var prng = Prng.init(0x5107);
    for (0..2000) |_| try check_random(&prng);
}

fn fuzz_audit(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try check_random(&prng);
}

test "slot audit: fuzz" {
    try testing.fuzz({}, fuzz_audit, .{});
}

comptime {
    assert(slot_audit.replay_backlog_max >= 16);
}

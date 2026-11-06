//! Builder slot invariants for deterministic simulation: an auditor fed the payload
//! `Service`'s job events (`Service.observer`) and the verifier's replay results. It checks
//! the builder side of the 200 ms cadence:
//!
//! - one block per slot or an explained skip: every started job ends exactly once, either
//!   resolved with a sealed block or ended with a reason (cancelled by a newer FCU, expired
//!   unresolved, build failed); jobs never overlap; resolved block numbers advance by one.
//! - no getPayload waits past the slot end: every seal's cutoff is inside its slot (at or
//!   before the 150 ms cutoff, so an early getPayload seals at its arrival time) and a
//!   getPayload arriving after the slot end is counted (`resolves_late`) for the harness.
//! - sealed blocks replay identically: every resolved block must later be reported by the
//!   verifier with the same hash (`on_replay`); a bounded ring holds unreplayed blocks.
//!
//! Events cannot return errors, so the first violation is recorded and later events are
//! still counted. Slots without any FCU are invisible here; the cluster checks those.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const service_module = @import("service.zig");
const timing = @import("timing.zig");

const B256 = primitives.B256;
const Event = service_module.Event;
const PayloadId = service_module.PayloadId;

pub const replay_backlog_max = 64;

pub const Violation = enum {
    /// A job started while another was active (the service must end it first).
    overlapping_jobs,
    /// An event for a job that is not the active one.
    unknown_job,
    /// A job started at a height other than the one after the last resolved block.
    number_out_of_order,
    /// A seal cutoff outside the job's slot (past the seal offset or before the start).
    cutoff_outside_slot,
    /// A job sealed twice, or resolved without a seal.
    seal_out_of_order,
    /// More than `replay_backlog_max` resolved blocks were never replayed.
    replay_backlog_full,
    /// The verifier reported a block number that was never resolved (or twice).
    replay_unknown,
    /// The verifier replayed a resolved block to a different hash.
    replay_mismatch,
};

const Active = struct {
    id: PayloadId,
    number: u64,
    slot: timing.Slot,
    sealed: ?B256 = null,
};

const Resolved = struct { number: u64, block_hash: B256 };

pub const SlotAudit = struct {
    active: ?Active = null,
    /// The next block number a job may start at.
    number_next: u64,
    violation: ?Violation = null,
    backlog: [replay_backlog_max]Resolved = undefined,
    backlog_count: u32 = 0,
    jobs_started: u64 = 0,
    blocks_resolved: u64 = 0,
    blocks_replayed: u64 = 0,
    resolves_late: u64 = 0,
    starts_failed: u64 = 0,
    skips: std.EnumArray(service_module.EndReason, u64) = .initFill(0),

    /// `head_number`: the chain head the first job builds on.
    pub fn init(head_number: u64) SlotAudit {
        assert(head_number < std.math.maxInt(u64));
        const audit: SlotAudit = .{ .number_next = head_number + 1 };
        assert(audit.number_next > head_number);
        return audit;
    }

    /// A reorg moved the head: later jobs build on `head_number`; unreplayed blocks above
    /// it are dropped (the verifier never sees them).
    pub fn reset(audit: *SlotAudit, head_number: u64) void {
        assert(head_number < std.math.maxInt(u64));
        audit.number_next = head_number + 1;
        var kept: u32 = 0;
        for (audit.backlog[0..audit.backlog_count]) |entry| {
            if (entry.number > head_number) continue;
            audit.backlog[kept] = entry;
            kept += 1;
        }
        audit.backlog_count = kept;
        assert(audit.backlog_count <= replay_backlog_max);
    }

    fn fail(audit: *SlotAudit, violation: Violation) void {
        if (audit.violation == null) audit.violation = violation;
        assert(audit.violation != null);
    }

    pub fn on_event(audit: *SlotAudit, event: *const Event) void {
        switch (event.*) {
            .started => |started| audit.on_started(started.id, started.number, started.slot),
            .start_failed => {
                if (audit.active != null) audit.fail(.overlapping_jobs);
                audit.starts_failed += 1;
            },
            .sealed => |sealed| audit.on_sealed(sealed.id, sealed.block_hash, sealed.cutoff_ns),
            .resolved => |resolved| audit.on_resolved(resolved.id, resolved.now_ns),
            .ended => |ended| {
                _ = audit.take(ended.id) orelse return;
                audit.skips.getPtr(ended.reason).* += 1;
            },
        }
    }

    fn on_started(audit: *SlotAudit, id: PayloadId, number: u64, slot: timing.Slot) void {
        assert(slot.start_ns <= slot.end_ns);
        if (audit.active != null) audit.fail(.overlapping_jobs);
        if (number != audit.number_next) audit.fail(.number_out_of_order);
        audit.active = .{ .id = id, .number = number, .slot = slot };
        audit.jobs_started += 1;
        assert(audit.active != null);
    }

    fn on_sealed(audit: *SlotAudit, id: PayloadId, block_hash: B256, cutoff_ns: u64) void {
        const active = audit.find(id) orelse return;
        if (active.sealed != null) audit.fail(.seal_out_of_order);
        const slot = active.slot;
        if (cutoff_ns < slot.start_ns or cutoff_ns > slot.cutoff_ns) {
            audit.fail(.cutoff_outside_slot);
        }
        active.sealed = block_hash;
        assert(slot.cutoff_ns <= slot.end_ns);
    }

    fn on_resolved(audit: *SlotAudit, id: PayloadId, now_ns: u64) void {
        const active = audit.take(id) orelse return;
        if (now_ns > active.slot.end_ns) audit.resolves_late += 1;
        const block_hash = active.sealed orelse return audit.fail(.seal_out_of_order);
        if (audit.backlog_count == replay_backlog_max) return audit.fail(.replay_backlog_full);
        audit.backlog[audit.backlog_count] = .{ .number = active.number, .block_hash = block_hash };
        audit.backlog_count += 1;
        audit.number_next = active.number + 1;
        audit.blocks_resolved += 1;
        assert(audit.backlog_count <= replay_backlog_max);
    }

    /// The verifier imported block `number` and computed `block_hash` for it.
    pub fn on_replay(audit: *SlotAudit, number: u64, block_hash: B256) void {
        assert(audit.backlog_count <= replay_backlog_max);
        for (audit.backlog[0..audit.backlog_count], 0..) |entry, index| {
            if (entry.number != number) continue;
            if (!std.mem.eql(u8, &entry.block_hash.bytes, &block_hash.bytes)) {
                audit.fail(.replay_mismatch);
            }
            audit.backlog_count -= 1;
            audit.backlog[index] = audit.backlog[audit.backlog_count];
            audit.blocks_replayed += 1;
            return;
        }
        audit.fail(.replay_unknown);
    }

    /// Resolved blocks the verifier has not replayed yet.
    pub fn unreplayed(audit: *const SlotAudit) u32 {
        assert(audit.backlog_count <= replay_backlog_max);
        assert(audit.blocks_replayed <= audit.blocks_resolved);
        return audit.backlog_count;
    }

    /// Explained skips (jobs ended without a block) of every reason.
    pub fn skips_total(audit: *const SlotAudit) u64 {
        var total: u64 = 0;
        for (audit.skips.values) |count| total += count;
        assert(total <= audit.jobs_started);
        return total;
    }

    fn find(audit: *SlotAudit, id: PayloadId) ?*Active {
        if (audit.active) |*active| {
            if (std.mem.eql(u8, &active.id, &id)) return active;
        }
        audit.fail(.unknown_job);
        assert(audit.violation != null);
        return null;
    }

    fn take(audit: *SlotAudit, id: PayloadId) ?Active {
        const active = (audit.find(id) orelse return null).*;
        audit.active = null;
        assert(audit.active == null);
        return active;
    }
};

test {
    _ = @import("slot_audit_test.zig");
}

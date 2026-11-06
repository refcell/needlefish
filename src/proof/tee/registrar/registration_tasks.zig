//! Bookkeeping and completion handling for background registration tasks (base/base
//! `registrar/src/registration_tasks.rs`).
//!
//! base/base owns a tokio `JoinSet` plus a pending map keyed by signer. Here the
//! bookkeeping is a pure state machine over a fixed table: the driver runs each
//! task on its own scheduler and reports outcomes back. Cancellation is a flag the
//! driver forwards to the task; a cancelled task stays pending until it completes.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");

/// In-flight registration tasks; one per signer.
pub const pending_count_max: u32 = 256;

pub const Error = error{ RegistrationTasksFull, StringTooLong };

pub const TaskId = u64;

/// State for one registration task in flight.
pub const PendingRegistration = struct {
    signer: types.Address,
    /// Originating instance, kept to preserve tasks whose source instance is
    /// unresolved and to attribute log lines.
    instance_id: types.InstanceId,
    task_id: TaskId,
    cancelled: bool,
};

pub const Outcome = enum(u8) { succeeded, failed };

/// Counters mirroring base/base's `RegistrarMetrics` proof-task series.
pub const Metrics = struct {
    spawned: u64 = 0,
    cancelled: u64 = 0,
    completed: u64 = 0,
    outcome_succeeded: u64 = 0,
    outcome_cancelled: u64 = 0,
    outcome_failed: u64 = 0,
    outcome_join_error: u64 = 0,
    processing_errors: u64 = 0,
};

/// Driver-owned set of in-flight registration tasks.
pub const RegistrationTaskSet = struct {
    entries: [pending_count_max]PendingRegistration = undefined,
    count: u32 = 0,
    task_id_next: TaskId = 1,
    metrics: Metrics = .{},

    /// Pending signers and their source instances, including cancelled tasks.
    pub fn pending(set: *const RegistrationTaskSet) []const PendingRegistration {
        assert(set.count <= pending_count_max);
        return set.entries[0..set.count];
    }

    /// Whether `signer` has a pending task, including a cancelled one.
    pub fn contains(set: *const RegistrationTaskSet, signer: *const types.Address) bool {
        return set.find(signer) != null;
    }

    pub fn is_cancelled(set: *const RegistrationTaskSet, signer: *const types.Address) bool {
        const index = set.find(signer) orelse return false;
        return set.entries[index].cancelled;
    }

    /// Track a new task and return its id, or null when the signer already has a
    /// pending task (including a cancelled one); the caller then must not start it.
    pub fn spawn(
        set: *RegistrationTaskSet,
        signer: types.Address,
        instance_id: []const u8,
    ) Error!?TaskId {
        if (set.find(&signer) != null) return null;
        if (set.count == pending_count_max) return error.RegistrationTasksFull;
        const task_id = set.task_id_next;
        set.entries[set.count] = .{
            .signer = signer,
            .instance_id = try types.InstanceId.init(instance_id),
            .task_id = task_id,
            .cancelled = false,
        };
        set.count += 1;
        set.task_id_next += 1;
        set.metrics.spawned += 1;
        assert(set.count <= pending_count_max);
        return task_id;
    }

    /// Mark a signer's task cancelled once it is no longer registerable. Returns
    /// true when this call cancelled it, so the driver signals the task.
    pub fn cancel(set: *RegistrationTaskSet, signer: *const types.Address) bool {
        const index = set.find(signer) orelse return false;
        const entry = &set.entries[index];
        if (entry.cancelled) return false;
        entry.cancelled = true;
        set.metrics.cancelled += 1;
        assert(set.is_cancelled(signer));
        return true;
    }

    /// Consume a finished task's result, keyed by signer as in base/base.
    pub fn complete(
        set: *RegistrationTaskSet,
        signer: *const types.Address,
        outcome: Outcome,
    ) void {
        set.metrics.completed += 1;
        const removed = set.remove_at(set.find(signer));
        const was_cancelled = if (removed) |entry| entry.cancelled else false;
        switch (outcome) {
            .succeeded => if (was_cancelled) {
                set.metrics.outcome_cancelled += 1;
            } else {
                set.metrics.outcome_succeeded += 1;
            },
            .failed => {
                set.metrics.outcome_failed += 1;
                set.metrics.processing_errors += 1;
            },
        }
        assert(set.find(signer) == null);
    }

    /// A task that panicked or was aborted: remove it by task id.
    pub fn join_error(set: *RegistrationTaskSet, task_id: TaskId) ?PendingRegistration {
        set.metrics.completed += 1;
        set.metrics.outcome_join_error += 1;
        set.metrics.processing_errors += 1;
        var found: ?u32 = null;
        for (set.pending(), 0..) |*entry, index| {
            if (entry.task_id == task_id) found = @intCast(index);
        }
        const removed = set.remove_at(found);
        assert(removed == null or removed.?.task_id == task_id);
        return removed;
    }

    /// Cancel every pending task cooperatively; the driver then awaits each task and
    /// reports it through `complete` until `pending()` is empty.
    pub fn begin_drain(set: *RegistrationTaskSet) void {
        for (set.entries[0..set.count]) |*entry| {
            if (entry.cancelled) continue;
            entry.cancelled = true;
            set.metrics.cancelled += 1;
        }
        for (set.pending()) |*entry| assert(entry.cancelled);
    }

    fn find(set: *const RegistrationTaskSet, signer: *const types.Address) ?u32 {
        assert(set.count <= pending_count_max);
        for (set.pending(), 0..) |*entry, index| {
            if (std.mem.eql(u8, &entry.signer, signer)) return @intCast(index);
        }
        return null;
    }

    /// Order-preserving removal, so `pending()` keeps spawn order.
    fn remove_at(set: *RegistrationTaskSet, index: ?u32) ?PendingRegistration {
        const position = index orelse return null;
        assert(position < set.count);
        const removed = set.entries[position];
        std.mem.copyForwards(
            PendingRegistration,
            set.entries[position .. set.count - 1],
            set.entries[position + 1 .. set.count],
        );
        set.count -= 1;
        return removed;
    }
};

const testing = std.testing;

test "registrar tasks: duplicate spawn keeps original task pending" {
    var tasks: RegistrationTaskSet = .{};
    const signer: types.Address = @splat(1);
    const first = try tasks.spawn(signer, "a");
    try testing.expect(first != null);
    try testing.expect(try tasks.spawn(signer, "b") == null);
    try testing.expectEqual(@as(usize, 1), tasks.pending().len);
    try testing.expectEqualStrings("a", tasks.pending()[0].instance_id.slice());
    tasks.begin_drain();
    tasks.complete(&signer, .succeeded);
    try testing.expectEqual(@as(usize, 0), tasks.pending().len);
    try testing.expectEqual(@as(u64, 1), tasks.metrics.outcome_cancelled);
}

test "registrar tasks: cancelled task stays pending until drained" {
    var tasks: RegistrationTaskSet = .{};
    const signer: types.Address = @splat(1);
    _ = try tasks.spawn(signer, "instance");
    try testing.expect(tasks.cancel(&signer));
    try testing.expectEqual(@as(usize, 1), tasks.pending().len);
    try testing.expectEqualStrings("instance", tasks.pending()[0].instance_id.slice());
    try testing.expect(tasks.contains(&signer));
    try testing.expect(try tasks.spawn(signer, "other") == null);
    tasks.begin_drain();
    tasks.complete(&signer, .succeeded);
    try testing.expectEqual(@as(usize, 0), tasks.pending().len);
}

test "registrar tasks: repeated cancel counts one cancellation" {
    var tasks: RegistrationTaskSet = .{};
    const signer: types.Address = @splat(1);
    _ = try tasks.spawn(signer, "instance");
    try testing.expect(tasks.cancel(&signer));
    try testing.expect(!tasks.cancel(&signer));
    tasks.begin_drain();
    try testing.expectEqual(@as(u64, 1), tasks.metrics.cancelled);
}

test "registrar tasks: outcomes, join errors, and capacity" {
    var tasks: RegistrationTaskSet = .{};
    const a: types.Address = @splat(1);
    const b: types.Address = @splat(2);
    _ = try tasks.spawn(a, "x");
    const b_id = (try tasks.spawn(b, "y")).?;
    tasks.complete(&a, .failed);
    try testing.expectEqual(@as(u64, 1), tasks.metrics.outcome_failed);
    const removed = tasks.join_error(b_id).?;
    try testing.expectEqualSlices(u8, &b, &removed.signer);
    try testing.expectEqual(@as(usize, 0), tasks.pending().len);
    try testing.expectEqual(@as(u64, 2), tasks.metrics.processing_errors);
    for (0..pending_count_max) |index| {
        var signer: types.Address = @splat(0);
        std.mem.writeInt(u32, signer[0..4], @intCast(index), .big);
        _ = try tasks.spawn(signer, "z");
    }
    try testing.expectError(error.RegistrationTasksFull, tasks.spawn(@splat(0xff), "z"));
}

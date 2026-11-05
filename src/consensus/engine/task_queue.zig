//! Engine task queue: owns the engine state and runs engine tasks one at a time in priority
//! order (build > seal > insert > consolidate > finalize > synchronize), FIFO within a
//! priority. A task that is waiting on the engine client stays active until it finishes,
//! so tasks are atomic over the engine state as in base/base. Temporary, deferred, and
//! critical failures keep the task (restarted from its beginning) for the next step; flush
//! failures drop it; reset failures clear the queue. Every slot owns an arena holding a
//! copy of its payload or attributes, so callers may free theirs after `enqueue`.
//! Mirrors base/base `crates/consensus/engine/src/task_queue/core.rs` (`Engine::drain`,
//! `enqueue`, `clear`) and `tasks/task.rs` (`EngineTask` ordering).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const task = @import("task.zig");
const protocol = @import("../protocol/root.zig");
const derive_attributes = @import("../derive/attributes.zig");
const insert_module = @import("insert_task.zig");
const SynchronizeTask = @import("synchronize_task.zig").SynchronizeTask;
const FinalizeTask = @import("finalize_task.zig").FinalizeTask;
const ConsolidateTask = @import("consolidate_task.zig").ConsolidateTask;
const SealTask = @import("seal_task.zig").SealTask;
const BuildTask = @import("build_task.zig").BuildTask;
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;

const L2BlockInfo = protocol.block.L2BlockInfo;
const EngineState = task.EngineState;
const PayloadId = task.PayloadId;
const InsertTask = insert_module.InsertTask;
const Envelope = insert_module.Envelope;
const Withdrawal = derive_attributes.Withdrawal;

pub const Kind = enum {
    synchronize,
    finalize,
    consolidate,
    insert,
    seal,
    build,

    /// base/base `EngineTask::task_priority` (Seal 4, Insert 3, Consolidate 2, Finalize 1),
    /// with the direct build ahead of everything and synchronize last.
    pub fn priority(kind: Kind) u8 {
        return switch (kind) {
            .build => 5,
            .seal => 4,
            .insert => 3,
            .consolidate => 2,
            .finalize => 1,
            .synchronize => 0,
        };
    }
};

pub const Task = union(Kind) {
    synchronize: SynchronizeTask,
    finalize: FinalizeTask,
    consolidate: ConsolidateTask,
    insert: InsertTask,
    seal: SealTask,
    build: BuildTask,
};

/// What to enqueue. Pointed-to payloads and attributes are copied into the slot.
pub const Request = union(Kind) {
    synchronize: task.SyncStateUpdate,
    finalize: u64,
    consolidate: *const AttributesWithParent,
    insert: struct {
        envelope: *const Envelope,
        safety: insert_module.Safety = .unsafe_payload,
        policy: insert_module.Policy = .extending_only,
        drop_invalid: bool = false,
    },
    seal: struct {
        payload_id: PayloadId,
        attributes: *const AttributesWithParent,
        safety: insert_module.Safety = .unsafe_payload,
    },
    build: *const AttributesWithParent,
};

pub const Completion = union(Kind) {
    synchronize,
    finalize,
    consolidate,
    /// The engine-acknowledged unsafe head.
    insert: L2BlockInfo,
    /// The sealed block.
    seal: L2BlockInfo,
    build: PayloadId,
};

pub const Failure = struct {
    kind: Kind,
    err: task.Error,
    severity: task.Severity,
};

pub const StepResult = union(enum) {
    /// No task queued.
    idle,
    /// The active task waits on the engine client.
    pending,
    completed: Completion,
    failed: Failure,
};

pub const EnqueueError = error{QueueFull} || Allocator.Error;

pub const Options = struct {
    capacity: u32 = 64,
    /// Bytes each slot arena keeps after its task finishes.
    retain_bytes: usize = 64 * 1024,
};

const Slot = struct {
    used: bool = false,
    sequence: u64 = 0,
    arena: std.heap.ArenaAllocator,
    attributes: AttributesWithParent = undefined,
    envelope: Envelope = undefined,
    task: Task = undefined,
};

pub const EngineTaskQueue = struct {
    slots: []Slot,
    context: task.Context,
    state: EngineState,
    options: Options,
    count: u32 = 0,
    next_sequence: u64 = 0,
    /// The slot whose task is in progress (waiting on the client).
    active: ?u32 = null,
    /// The last sealed unsafe payload (for gossip), until the next unsafe seal completes.
    sealed_arena: std.heap.ArenaAllocator,
    sealed: ?Envelope = null,
    /// `sealed` holds a payload `take_sealed` has not returned yet.
    sealed_fresh: bool = false,
    /// Sealed payloads not kept because copying them ran out of memory.
    sealed_dropped: u64 = 0,

    pub fn init(
        allocator: Allocator,
        context: task.Context,
        initial_state: EngineState,
        options: Options,
    ) Allocator.Error!EngineTaskQueue {
        assert(options.capacity > 0);
        assert(initial_state.sync_state.is_ordered());
        const slots = try allocator.alloc(Slot, options.capacity);
        for (slots) |*slot| slot.* = .{ .arena = .init(allocator) };
        return .{
            .slots = slots,
            .context = context,
            .state = initial_state,
            .options = options,
            .sealed_arena = .init(allocator),
        };
    }

    pub fn deinit(queue: *EngineTaskQueue, allocator: Allocator) void {
        assert(queue.slots.len == queue.options.capacity);
        assert(queue.count <= queue.slots.len);
        for (queue.slots) |*slot| slot.arena.deinit();
        queue.sealed_arena.deinit();
        allocator.free(queue.slots);
        queue.* = undefined;
    }

    pub fn len(queue: *const EngineTaskQueue) u32 {
        assert(queue.count <= queue.slots.len);
        return queue.count;
    }

    /// Drops every task (`Engine::clear`). The engine state is kept.
    pub fn clear(queue: *EngineTaskQueue) void {
        assert(queue.count <= queue.slots.len);
        for (queue.slots, 0..) |*slot, index| {
            if (slot.used) queue.release(@intCast(index));
        }
        queue.next_sequence = 0;
        assert(queue.count == 0);
        assert(queue.active == null);
    }

    pub fn enqueue(queue: *EngineTaskQueue, request: Request) EnqueueError!void {
        const index = queue.free_slot() orelse return error.QueueFull;
        const slot = &queue.slots[index];
        assert(!slot.used);
        errdefer _ = slot.arena.reset(.{ .retain_with_limit = queue.options.retain_bytes });
        const allocator = slot.arena.allocator();
        slot.task = switch (request) {
            .synchronize => |update| .{ .synchronize = .{ .update = update } },
            .finalize => |number| .{ .finalize = .{ .block_number = number } },
            .consolidate => |attributes| blk: {
                slot.attributes = try copy_attributes(allocator, attributes);
                break :blk .{ .consolidate = .{ .attributes = &slot.attributes } };
            },
            .build => |attributes| blk: {
                slot.attributes = try copy_attributes(allocator, attributes);
                break :blk .{ .build = BuildTask.init(&slot.attributes) };
            },
            .seal => |seal| blk: {
                slot.attributes = try copy_attributes(allocator, seal.attributes);
                const sealing = SealTask.init(seal.payload_id, &slot.attributes, seal.safety);
                break :blk .{ .seal = sealing };
            },
            .insert => |insert| blk: {
                slot.envelope = try copy_envelope(allocator, insert.envelope);
                break :blk .{ .insert = .{
                    .envelope = &slot.envelope,
                    .safety = insert.safety,
                    .policy = insert.policy,
                    .drop_invalid = insert.drop_invalid,
                } };
            },
        };
        slot.used = true;
        slot.sequence = queue.next_sequence;
        queue.next_sequence += 1;
        queue.count += 1;
        assert(queue.count <= queue.slots.len);
    }

    /// Runs the active task, or the highest-priority one, until it finishes, waits on the
    /// client, or fails.
    pub fn step(queue: *EngineTaskQueue, client: anytype) StepResult {
        if (queue.count == 0) {
            assert(queue.active == null);
            return .idle;
        }
        const index = queue.active orelse queue.select();
        queue.active = index;
        const slot = &queue.slots[index];
        assert(slot.used);
        const kind = std.meta.activeTag(slot.task);
        const completion = run(&slot.task, &queue.context, &queue.state, client) catch |err| {
            assert(queue.state.sync_state.is_ordered());
            if (err == error.NotAvailable) {
                own_seal_envelope(slot);
                return .pending;
            }
            return .{ .failed = queue.fail(index, kind, err) };
        };
        if (kind == .seal) queue.keep_sealed(&slot.task.seal, completion.seal);
        queue.release(index);
        assert(queue.state.sync_state.is_ordered());
        return .{ .completed = completion };
    }

    pub const DrainResult = struct {
        completed: u32,
        last: StepResult,
    };

    /// Steps while tasks complete, at most `steps_max` times (`Engine::drain`). Stops at the
    /// first pending or failed step; callers that need completion outputs use `step`.
    pub fn drain(queue: *EngineTaskQueue, client: anytype, steps_max: u32) DrainResult {
        assert(steps_max > 0);
        var completed: u32 = 0;
        var last: StepResult = .idle;
        for (0..steps_max) |_| {
            last = queue.step(client);
            if (last != .completed) break;
            completed += 1;
        }
        assert(completed <= steps_max);
        return .{ .completed = completed, .last = last };
    }

    fn fail(queue: *EngineTaskQueue, index: u32, kind: Kind, err: task.Error) Failure {
        const failure: Failure = .{ .kind = kind, .err = err, .severity = task.severity(err) };
        switch (failure.severity) {
            .temporary, .deferred, .critical => {
                restart(&queue.slots[index].task);
                queue.active = null;
            },
            .flush => queue.release(index),
            .reset => queue.clear(),
        }
        assert(queue.active == null);
        return failure;
    }

    /// The used slot with the highest priority, then the lowest sequence.
    fn select(queue: *const EngineTaskQueue) u32 {
        assert(queue.count > 0);
        var best: ?u32 = null;
        for (queue.slots, 0..) |*slot, index| {
            if (!slot.used) continue;
            if (best) |current| {
                const other = &queue.slots[current];
                const priority = std.meta.activeTag(slot.task).priority();
                const other_priority = std.meta.activeTag(other.task).priority();
                if (priority < other_priority) continue;
                if (priority == other_priority and slot.sequence > other.sequence) continue;
            }
            best = @intCast(index);
        }
        assert(best != null);
        assert(queue.slots[best.?].used);
        return best.?;
    }

    fn free_slot(queue: *const EngineTaskQueue) ?u32 {
        assert(queue.count <= queue.slots.len);
        if (queue.count == queue.slots.len) return null;
        for (queue.slots, 0..) |*slot, index| {
            if (!slot.used) return @intCast(index);
        }
        unreachable; // Proof: count < slots.len, so a slot is free.
    }

    /// The payload of the last unsafe seal, once; valid until the next unsafe seal completes.
    pub fn take_sealed(queue: *EngineTaskQueue) ?*const Envelope {
        if (!queue.sealed_fresh) return null;
        queue.sealed_fresh = false;
        assert(queue.sealed != null);
        return &queue.sealed.?;
    }

    /// Copies a seal task's fetched payload into its slot once the insert is under way: the
    /// client's result memory is reused by the next response, and the insert may restart.
    fn own_seal_envelope(slot: *Slot) void {
        if (slot.task != .seal) return;
        const seal = &slot.task.seal;
        if (seal.phase != .insert or seal.envelope_owned) return;
        const copy = copy_envelope(slot.arena.allocator(), &seal.envelope) catch {
            // Fetch the payload again rather than insert from borrowed memory.
            seal.restart();
            assert(seal.phase == .get_payload);
            return;
        };
        seal.envelope = copy;
        seal.envelope_owned = true;
        assert(seal.insert.envelope == &seal.envelope);
    }

    /// Keeps an unsafe seal's payload for gossip, unless the insert skipped it as stale.
    fn keep_sealed(queue: *EngineTaskQueue, seal: *const SealTask, head: L2BlockInfo) void {
        if (seal.safety != .unsafe_payload) return;
        assert(seal.phase == .insert);
        if (!head.block_info.hash.eql(seal.envelope.payload.block_hash)) return;
        queue.sealed = null;
        queue.sealed_fresh = false;
        _ = queue.sealed_arena.reset(.{ .retain_with_limit = queue.options.retain_bytes });
        const copy = copy_envelope(queue.sealed_arena.allocator(), &seal.envelope) catch {
            queue.sealed_dropped += 1;
            return;
        };
        queue.sealed = copy;
        queue.sealed_fresh = true;
    }

    fn release(queue: *EngineTaskQueue, index: u32) void {
        const slot = &queue.slots[index];
        assert(slot.used);
        assert(queue.count > 0);
        slot.used = false;
        slot.task = undefined;
        _ = slot.arena.reset(.{ .retain_with_limit = queue.options.retain_bytes });
        queue.count -= 1;
        if (queue.active == index) queue.active = null;
    }
};

fn run(
    current: *Task,
    context: *const task.Context,
    engine_state: *EngineState,
    client: anytype,
) task.Error!Completion {
    assert(engine_state.sync_state.is_ordered());
    defer assert(engine_state.sync_state.is_ordered());
    switch (current.*) {
        .synchronize => |*synchronize| {
            try synchronize.step(context, engine_state, client);
            return .synchronize;
        },
        .finalize => |*finalize| {
            try finalize.step(context, engine_state, client);
            return .finalize;
        },
        .consolidate => |*consolidate| {
            try consolidate.step(context, engine_state, client);
            return .consolidate;
        },
        .insert => |*insert| {
            const head = insert.step(context, engine_state, client) catch |err| {
                // EL-invalid gossiped payloads are consumed so the queue can progress.
                if (err == error.NewPayloadInvalid and insert.drop_invalid) {
                    return .{ .insert = engine_state.sync_state.unsafe_head };
                }
                return err;
            };
            return .{ .insert = head };
        },
        .seal => |*seal| return .{ .seal = try seal.step(context, engine_state, client) },
        .build => |*build| return .{ .build = try build.step(context, engine_state, client) },
    }
}

fn restart(current: *Task) void {
    const kind = std.meta.activeTag(current.*);
    defer assert(std.meta.activeTag(current.*) == kind);
    switch (current.*) {
        .synchronize, .build => {}, // Stateless between calls.
        .finalize => |*finalize| finalize.restart(),
        .consolidate => |*consolidate| consolidate.restart(),
        .insert => |*insert| insert.restart(),
        .seal => |*seal| seal.restart(),
    }
}

fn copy_attributes(
    allocator: Allocator,
    source: *const AttributesWithParent,
) Allocator.Error!AttributesWithParent {
    assert(source.attributes.transactions.len <= std.math.maxInt(u32));
    var result = source.*;
    const transactions = try allocator.alloc([]u8, source.attributes.transactions.len);
    for (transactions, source.attributes.transactions) |*target, transaction| {
        target.* = try allocator.dupe(u8, transaction);
    }
    result.attributes.transactions = transactions;
    if (source.attributes.withdrawals) |withdrawals| {
        result.attributes.withdrawals = try allocator.dupe(Withdrawal, withdrawals);
    }
    assert(result.attributes.transactions.len == source.attributes.transactions.len);
    return result;
}

pub fn copy_envelope(allocator: Allocator, source: *const Envelope) Allocator.Error!Envelope {
    assert(source.payload.transactions.len <= std.math.maxInt(u32));
    var result = source.*;
    const payload = &source.payload;
    const transactions = try allocator.alloc([]const u8, payload.transactions.len);
    for (transactions, payload.transactions) |*target, transaction| {
        target.* = try allocator.dupe(u8, transaction);
    }
    result.payload.transactions = transactions;
    result.payload.extra_data = try allocator.dupe(u8, payload.extra_data);
    if (payload.withdrawals) |withdrawals| {
        result.payload.withdrawals = try allocator.dupe(Withdrawal, withdrawals);
    }
    assert(result.payload.transactions.len == payload.transactions.len);
    return result;
}

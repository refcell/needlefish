//! Room before a block (`run.zig`'s runner, and `db/disk_state_bench.zig`): a disk-mode
//! database takes the next block only if its entry fits the journal queue and the journal
//! (with a largest entry to spare), and its branch writes and a rollback's fit the replay
//! admission (`DiskStateConfig.replay_record_writes_max`: the writes of the two newest
//! checkpoint intervals and the current one). Only a durable checkpoint frees journal and
//! admission room, and none can start while a block is held (`hold_checkpoints`), so
//! `make_room` asks for one and ticks the storage until there is room.
//!
//! Counters (`Stats`) say what room time is made of: the waits, the condition that was short
//! when each began, and the wall time of the waiting ticks by what the storage was doing
//! before the tick (`Phase`).

const std = @import("std");
const assert = std.debug.assert;

const to_disk = @import("to_disk.zig");
const executor_module = @import("../node/executor.zig");

pub const Clock = executor_module.Executor.Clock;

pub const Error = error{ NotReady, CheckpointFailed, Stalled };

/// Ticks one wait for room may take.
pub const ticks_max: u32 = to_disk.busy_ticks_max;

/// What the storage was doing during a waiting tick.
pub const Phase = enum {
    /// A checkpoint is wanted but the journal queue (or a commit) has not drained.
    drain,
    /// Wanted, the queue drained, and none started: the flat trees or the codes prepare.
    prepare,
    /// A checkpoint writes its blocks.
    write,
    /// A checkpoint's blocks are written: its sync and the superblock copies.
    superblock,
    /// No checkpoint wanted or running (the queue, compaction).
    other,
};

const phase_count = @typeInfo(Phase).@"enum".field_names.len;

pub const Stats = struct {
    /// `make_room` calls, those that ticked, and their ticks.
    calls: u64 = 0,
    waits: u64 = 0,
    ticks: u64 = 0,
    /// Waits by the first condition short when they began (none short: a start wait).
    short_queue: u64 = 0,
    short_journal: u64 = 0,
    short_admission: u64 = 0,
    /// Waits for a wanted checkpoint to start (room was not short; none before ahead
    /// checkpoints).
    start_waits: u64 = 0,
    /// Checkpoints asked for (`ahead`: before room was short; none yet), and those seen to
    /// start during a wait.
    checkpoints_requested: u64 = 0,
    checkpoints_ahead: u64 = 0,
    checkpoints_started: u64 = 0,
    /// Wall time of the waiting ticks by `Phase` (under the clock; zero without one).
    phase_ns: [phase_count]u64 = @splat(0),

    pub fn ns(stats: *const Stats, phase: Phase) u64 {
        return stats.phase_ns[@backingInt(phase)];
    }
};

/// `make_room` over a disk-mode `Database` (`database.DatabaseType`).
pub fn RoomType(comptime Database: type) type {
    return struct {
        pub fn journal_used(db: *const Database) u64 {
            const journal = &db.engine.journal;
            assert(journal.head >= journal.tail);
            return journal.head - journal.tail + db.journal_bytes_pending;
        }

        /// The journal fits this block's entry with a largest entry to spare.
        pub fn journal_roomy(db: *const Database) bool {
            const journal = &db.engine.journal;
            const entry_max = Database.Engine.JournalType.entry_size_max(journal.config);
            return journal_used(db) + 2 * entry_max <= journal.config.zone_size_bytes;
        }

        /// The replay admission takes this block's branch writes and a rollback's.
        pub fn admission_roomy(db: *const Database) bool {
            const disk_config = db.config.disk_state.?;
            const span = db.disk_writes_closed + db.disk_writes_pending + db.disk_writes_current;
            return span + 2 * disk_config.record_writes_max <=
                disk_config.replay_record_writes_max;
        }

        pub fn queue_roomy(db: *const Database) bool {
            return db.queue_count + 1 <= db.config.queue_entries_max;
        }

        pub fn roomy(db: *const Database) bool {
            return queue_roomy(db) and journal_roomy(db) and admission_roomy(db);
        }

        /// Ticks until the next block can be journaled and rolled back without a checkpoint
        /// (none can start while a block is held), asking for checkpoints as needed. Like the
        /// durable node, also asks for one once the journal is half full.
        pub fn make_room(
            db: *Database,
            driver: to_disk.Driver,
            clock: ?Clock,
            stats: *Stats,
        ) Error!void {
            stats.calls += 1;
            var ticks: u32 = 0;
            while (true) : (ticks += 1) {
                if (db.phase != .ready) return error.NotReady;
                if (db.checkpoint_error != null) return error.CheckpointFailed;
                const half = journal_used(db) * 2 > db.engine.journal.config.zone_size_bytes;
                const wanted = half or !journal_roomy(db) or !admission_roomy(db);
                const running = db.checkpoint_wanted or db.engine.checkpoint_phase != .idle;
                if (wanted and !running) {
                    db.request_checkpoint();
                    stats.checkpoints_requested += 1;
                }
                if (roomy(db)) break;
                if (ticks >= ticks_max) return error.Stalled;
                if (ticks == 0) wait_begin(db, stats);
                tick(db, driver, clock, stats);
            }
            assert(roomy(db));
            assert(!db.checkpoints_held);
        }

        fn wait_begin(db: *const Database, stats: *Stats) void {
            assert(db.phase == .ready);
            stats.waits += 1;
            if (!queue_roomy(db)) {
                stats.short_queue += 1;
            } else if (!journal_roomy(db)) {
                stats.short_journal += 1;
            } else if (!admission_roomy(db)) {
                stats.short_admission += 1;
            }
            assert(stats.short_queue + stats.short_journal + stats.short_admission <= stats.waits);
        }

        pub fn phase_of(db: *const Database) Phase {
            return switch (db.engine.checkpoint_phase) {
                .writing => .write,
                .superblock => .superblock,
                .idle => if (!db.checkpoint_wanted)
                    .other
                else if (db.queue_count > 0 or db.engine.commit_callback != null)
                    .drain
                else
                    .prepare,
            };
        }

        /// One waiting tick, counted under the phase the storage was in before it.
        fn tick(db: *Database, driver: to_disk.Driver, clock: ?Clock, stats: *Stats) void {
            const phase = phase_of(db);
            const idle_before = db.engine.checkpoint_phase == .idle;
            const start_ns = if (clock) |source| source.read() else 0;
            driver.tick(driver.context);
            const end_ns = if (clock) |source| source.read() else 0;
            stats.ticks += 1;
            stats.phase_ns[@backingInt(phase)] += end_ns -| start_ns;
            const started = idle_before and db.engine.checkpoint_phase != .idle;
            stats.checkpoints_started += @intFromBool(started);
            assert(stats.checkpoints_started <= stats.ticks);
        }
    };
}

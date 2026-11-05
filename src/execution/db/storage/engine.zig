//! The storage engine: superblock + A/B checkpoints + write-ahead journal over one storage.
//!
//! Layout (byte offsets, all sector aligned):
//!   [0, 16 KiB)             four superblock copies
//!   [A, A + checkpoint)     checkpoint zone A
//!   [B, B + checkpoint)     checkpoint zone B
//!   [J, J + journal)        journal ring
//!
//! Protocol:
//! - `commit(body, metadata)` appends a journal entry; the callback fires once it is durable.
//! - `checkpoint(producer)` streams a full snapshot into the zone the newest checkpoint does
//!   not use, syncs it, then writes a new superblock naming it, with `journal_start` at the
//!   first entry the snapshot does not cover. The superblock keeps the checkpoint it replaces
//!   as the fallback (`checkpoint_previous`, `journal_start_previous`). Only once all four
//!   superblock copies are durable does the journal release entries, and only those before
//!   the fallback's start: the journal always holds every entry since the fallback.
//! - `open(consumer)` picks the newest valid superblock (rewriting all copies if they
//!   disagree), streams the checkpoint into the consumer, then replays the journal from
//!   `journal_start` in order. If the newest checkpoint does not verify, the consumer is
//!   told to discard what it got (`on_checkpoint_reset`), the fallback checkpoint streams
//!   instead, and the journal replays from the fallback's start. The fallback succeeds only
//!   if replay reaches the newest checkpoint's coverage; the superblock is then rewritten to
//!   name the fallback as newest (no distinct fallback), so the next checkpoint overwrites
//!   the rotten zone and never the one just loaded.
//!
//! Crash safety: nothing a recoverable superblock depends on is overwritten while any copy of
//! that superblock may still be chosen. The checkpoint zone in use and the journal entries
//! from its `journal_start` stay intact until a newer superblock is durable on every copy,
//! and a superblock is only written after the data it names is synced. So after a crash at
//! any point, recovery yields the newest durable checkpoint plus a hash-chained prefix of the
//! journal that includes every entry whose commit callback fired.
//!
//! Redundancy: one rotten checkpoint zone is survived through the fallback. It is lost (and
//! open fails with `CheckpointCorrupt`) only together with a second fault: rot in the
//! fallback zone or in a retained journal entry, or a crash while a checkpoint write is
//! overwriting the fallback zone (between the zone write starting and the superblock being
//! durable, the fallback zone holds the half-written new checkpoint).
//!
//! Concurrency: one commit and one checkpoint may run at the same time. A checkpoint cannot
//! start while a commit is in flight, so its snapshot covers exactly the entries committed
//! before `checkpoint()` was called; the producer must keep serving that snapshot while later
//! commits proceed.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const checksum_module = @import("checksum.zig");
const superblock_module = @import("superblock.zig");
const journal_module = @import("journal.zig");
const checkpoint_module = @import("checkpoint.zig");

const sector_size = storage.sector_size;
const SuperBlock = superblock_module.SuperBlock;
const JournalStart = superblock_module.JournalStart;
pub const Checkpoint = superblock_module.Checkpoint;
pub const Entry = journal_module.Entry;
pub const StopReason = journal_module.StopReason;
pub const Producer = checkpoint_module.Producer;
pub const metadata_size = superblock_module.commit_metadata_size;
pub const Metadata = [metadata_size]u8;

pub const Config = struct {
    journal_size_bytes: u64,
    checkpoint_zone_size_bytes: u64,
    entry_body_size_max: u32,
    checkpoint_block_size: u32 = 64 * 1024,

    pub fn layout(config: Config) superblock_module.Layout {
        return .{
            .checkpoint_zone_size_bytes = config.checkpoint_zone_size_bytes,
            .journal_size_bytes = config.journal_size_bytes,
            .checkpoint_block_size = config.checkpoint_block_size,
            .entry_body_size_max = config.entry_body_size_max,
        };
    }

    pub fn checkpoint_zone_offset(config: Config, zone: u8) u64 {
        assert(zone <= 1);
        return superblock_module.zone_size_bytes + zone * config.checkpoint_zone_size_bytes;
    }

    pub fn journal_offset(config: Config) u64 {
        return config.checkpoint_zone_offset(1) + config.checkpoint_zone_size_bytes;
    }

    /// The storage size this layout needs.
    pub fn size_bytes(config: Config) u64 {
        return config.journal_offset() + config.journal_size_bytes;
    }
};

pub const Consumer = struct {
    context: *anyopaque,
    /// Receives the checkpoint in order, one verified chunk at a time.
    on_checkpoint: *const fn (context: *anyopaque, chunk: []const u8) void,
    /// Discards every checkpoint chunk received so far: that checkpoint failed to verify and
    /// the fallback checkpoint streams next, from its first byte. Called at most once per
    /// open, always before any entry.
    on_checkpoint_reset: *const fn (context: *anyopaque) void,
    /// Receives each replayed journal entry in order, after the whole checkpoint. The
    /// entry's slices are valid only during the call.
    on_entry: *const fn (context: *anyopaque, entry: Entry) void,
};

pub const OpenResult = struct {
    /// The checkpoint the state was loaded from.
    checkpoint: Checkpoint,
    /// The newest checkpoint did not verify; the state came from the fallback.
    checkpoint_fallback: bool,
    entries_replayed: u64,
    /// Sequence of the last entry the state now reflects (0 if none ever).
    sequence_last: u64,
    /// Why replay stopped. Corruption here usually means the torn, never-acknowledged last
    /// entry of a crash; it can also mean bit rot destroyed acknowledged entries.
    journal_stop: StopReason,
    superblock_repaired: bool,
};

pub const OpenError = error{
    SuperBlockMissing,
    SuperBlockConflict,
    LayoutMismatch,
    CheckpointCorrupt,
};

pub const CheckpointError = error{CheckpointTooLarge};

/// The chain anchor of a freshly formatted journal: unique per format id.
pub fn chain_anchor(format_id: u128) u128 {
    return checksum_module.checksum(std.mem.asBytes(&format_id));
}

pub fn EngineType(comptime Storage: type) type {
    storage.assert_interface(Storage);
    return struct {
        const Self = @This();

        pub const SuperBlockType = superblock_module.SuperBlockType(Storage);
        pub const JournalType = journal_module.JournalType(Storage);
        pub const CheckpointType = checkpoint_module.CheckpointType(Storage);
        pub const Callback = *const fn (*Self) void;
        pub const Phase = enum {
            closed,
            formatting,
            opening_superblock,
            repairing,
            opening_checkpoint,
            opening_journal,
            /// After a fallback: naming the fallback checkpoint as the newest.
            demoting,
            ready,
        };
        pub const CheckpointPhase = enum { idle, writing, superblock };

        storage: *Storage,
        config: Config,
        superblock: SuperBlockType,
        journal: JournalType,
        checkpoint_io: CheckpointType,
        phase: Phase = .closed,
        phase_callback: ?Callback = null,
        consumer: ?Consumer = null,
        open_result: OpenError!OpenResult = error.SuperBlockMissing,
        superblock_repaired: bool = false,
        /// Open is loading the fallback checkpoint because the newest one failed to verify.
        open_fallback: bool = false,
        /// Where open's journal replay started (the loaded checkpoint's journal start).
        open_start: JournalStart = undefined,
        /// Logical journal position of the durable superblock's `journal_start`. Released to
        /// once the next checkpoint's superblock makes it the fallback start.
        journal_start_position: u64 = 0,
        /// Metadata of the newest committed entry (or of the checkpoint, if none since).
        commit_metadata: Metadata = @splat(0),
        commit_metadata_pending: Metadata = @splat(0),
        commit_callback: ?Callback = null,
        checkpoint_phase: CheckpointPhase = .idle,
        checkpoint_callback: ?Callback = null,
        checkpoint_result: CheckpointError!Checkpoint = .{},
        checkpoint_start: JournalStart = undefined,
        checkpoint_tail: u64 = 0,
        checkpoint_metadata: Metadata = @splat(0),

        pub fn init(allocator: std.mem.Allocator, storage_: *Storage, config: Config) !Self {
            assert(config.size_bytes() <= storage_.size_bytes());
            assert(config.checkpoint_zone_size_bytes % config.checkpoint_block_size == 0);
            var superblock = try SuperBlockType.init(allocator, storage_);
            errdefer superblock.deinit(allocator);
            var journal = try JournalType.init(allocator, storage_, .{
                .zone_offset = config.journal_offset(),
                .zone_size_bytes = config.journal_size_bytes,
                .body_size_max = config.entry_body_size_max,
            });
            errdefer journal.deinit(allocator);
            const checkpoint_io = try CheckpointType.init(allocator, storage_, .{
                .zone_offsets = .{
                    config.checkpoint_zone_offset(0),
                    config.checkpoint_zone_offset(1),
                },
                .zone_size_bytes = config.checkpoint_zone_size_bytes,
                .block_size = config.checkpoint_block_size,
            });
            return .{
                .storage = storage_,
                .config = config,
                .superblock = superblock,
                .journal = journal,
                .checkpoint_io = checkpoint_io,
            };
        }

        /// Frees memory. Operations may be in flight only if the storage dropped them (crash).
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.superblock.deinit(allocator);
            self.journal.deinit(allocator);
            self.checkpoint_io.deinit(allocator);
            self.* = undefined;
        }

        /// True when no engine operation is in flight.
        pub fn idle(self: *const Self) bool {
            const phase_idle = self.phase == .closed or self.phase == .ready;
            return phase_idle and self.commit_callback == null and
                self.checkpoint_phase == .idle;
        }

        /// Sequence of the newest durable entry (valid once ready).
        pub fn sequence_last(self: *const Self) u64 {
            assert(self.phase == .ready);
            assert(self.journal.sequence_next > 0);
            return self.journal.sequence_next - 1;
        }

        /// Writes an empty database: no checkpoint, an empty journal. `format_id` must differ
        /// between formats of the same storage. The file is usable only once this completes.
        pub fn format(self: *Self, format_id: u128, callback: Callback) void {
            assert(self.phase == .closed);
            assert(self.phase_callback == null);
            var superblock = superblock_module.zero();
            superblock.format_id = format_id;
            superblock.journal_start = .{
                .previous_checksum = chain_anchor(format_id),
                .offset = 0,
                .sequence = 1,
            };
            superblock.journal_start_previous = superblock.journal_start;
            superblock.layout = self.config.layout();
            self.superblock.working = superblock_module.zero();
            self.phase = .formatting;
            self.phase_callback = callback;
            self.superblock.write_superblock(superblock, on_superblock);
        }

        /// Loads the latest state through `consumer`. On completion `open_result` is set and,
        /// on success, the engine is ready.
        pub fn open(self: *Self, consumer: Consumer, callback: Callback) void {
            assert(self.phase == .closed);
            assert(self.phase_callback == null);
            self.phase = .opening_superblock;
            self.phase_callback = callback;
            self.consumer = consumer;
            self.superblock_repaired = false;
            self.open_fallback = false;
            self.superblock.open(on_superblock);
        }

        /// Appends one entry and returns its sequence; `callback` fires once it is durable.
        /// `error.JournalFull` asks the caller to checkpoint first.
        pub fn commit(
            self: *Self,
            body: []const u8,
            metadata: *const Metadata,
            callback: Callback,
        ) error{ NotReady, Busy, JournalFull }!u64 {
            if (self.phase != .ready) return error.NotReady;
            if (self.commit_callback != null) return error.Busy;
            assert(self.journal.idle());
            assert(body.len <= self.config.entry_body_size_max);
            const sequence = try self.journal.append(body, metadata, on_journal);
            self.commit_metadata_pending = metadata.*;
            self.commit_callback = callback;
            assert(sequence == self.journal.sequence_next);
            return sequence;
        }

        /// Writes a snapshot of the state after every entry committed so far, then frees the
        /// journal. On completion `checkpoint_result` is set.
        pub fn checkpoint(
            self: *Self,
            producer: Producer,
            callback: Callback,
        ) error{ NotReady, Busy }!void {
            if (self.phase != .ready) return error.NotReady;
            if (self.checkpoint_phase != .idle or self.commit_callback != null) return error.Busy;
            assert(self.journal.idle());
            const working = &self.superblock.working;
            // Never the newest checkpoint's zone. The fallback's zone is overwritten: until
            // the new superblock is durable, only the newest checkpoint is recoverable.
            const zone: u8 = if (working.checkpoint.sequence == 0)
                0
            else
                1 - working.checkpoint.zone;
            self.checkpoint_start = self.journal.start_point();
            self.checkpoint_tail = self.journal.head;
            self.checkpoint_metadata = self.commit_metadata;
            self.checkpoint_phase = .writing;
            self.checkpoint_callback = callback;
            self.checkpoint_io.write_start(
                working.format_id,
                zone,
                working.checkpoint.sequence + 1,
                producer,
                on_checkpoint_io,
            );
        }

        fn on_superblock(superblock: *SuperBlockType) void {
            const self: *Self = @alignCast(@fieldParentPtr("superblock", superblock));
            switch (self.phase) {
                .formatting => {
                    self.phase = .closed;
                    self.finish_phase();
                },
                .opening_superblock => self.open_superblock_done(),
                .repairing => {
                    self.superblock_repaired = true;
                    self.open_checkpoint();
                },
                .demoting => self.open_done(),
                .ready => self.checkpoint_superblock_done(),
                .closed, .opening_checkpoint, .opening_journal => unreachable,
            }
        }

        fn open_superblock_done(self: *Self) void {
            assert(self.phase == .opening_superblock);
            const selection = self.superblock.selection;
            switch (selection.status) {
                .missing => return self.open_failed(error.SuperBlockMissing),
                .conflict => return self.open_failed(error.SuperBlockConflict),
                .ok => {},
            }
            const working = &self.superblock.working;
            const layout = self.config.layout();
            if (!std.mem.eql(u8, std.mem.asBytes(&working.layout), std.mem.asBytes(&layout))) {
                return self.open_failed(error.LayoutMismatch);
            }
            self.commit_metadata = working.commit_metadata;
            if (selection.copies_current < superblock_module.copy_count) {
                // A crash interrupted a superblock write. Rewrite every copy before anything
                // else is written, so no stale copy can be chosen later.
                self.phase = .repairing;
                return self.superblock.write_superblock(working.*, on_superblock);
            }
            self.open_checkpoint();
        }

        /// The checkpoint open loads: the newest, or the fallback after the newest failed.
        fn open_target(self: *const Self) Checkpoint {
            const working = &self.superblock.working;
            if (self.open_fallback) {
                assert(working.has_fallback());
                return working.checkpoint_previous;
            }
            return working.checkpoint;
        }

        fn open_checkpoint(self: *Self) void {
            const working = &self.superblock.working;
            const checkpoint_ = self.open_target();
            if (checkpoint_.size_bytes == 0) {
                const empty_ok = checkpoint_.sequence == 0 or
                    checkpoint_.checksum == checksum_module.checksum("");
                if (!empty_ok) return self.open_checkpoint_failed();
                return self.open_journal();
            }
            const blocks = checkpoint_module.block_count(
                checkpoint_.size_bytes,
                self.config.checkpoint_block_size,
            );
            if (blocks > self.checkpoint_io.blocks_max()) {
                return self.open_checkpoint_failed();
            }
            self.phase = .opening_checkpoint;
            self.checkpoint_io.read_start(working.format_id, checkpoint_, .{
                .context = self,
                .consume = forward_checkpoint,
            }, on_checkpoint_io);
        }

        /// The checkpoint being loaded did not verify: fall back once, else fail.
        fn open_checkpoint_failed(self: *Self) void {
            assert(self.phase != .ready and self.phase != .closed);
            const working = &self.superblock.working;
            if (self.open_fallback or !working.has_fallback()) {
                return self.open_failed(error.CheckpointCorrupt);
            }
            self.open_fallback = true;
            self.commit_metadata = working.commit_metadata_previous;
            self.consumer.?.on_checkpoint_reset(self.consumer.?.context);
            self.open_checkpoint();
        }

        fn forward_checkpoint(context: *anyopaque, chunk: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening_checkpoint);
            self.consumer.?.on_checkpoint(self.consumer.?.context, chunk);
        }

        fn on_checkpoint_io(checkpoint_io: *CheckpointType) void {
            const self: *Self = @alignCast(@fieldParentPtr("checkpoint_io", checkpoint_io));
            if (self.phase == .opening_checkpoint) {
                checkpoint_io.result catch return self.open_checkpoint_failed();
                return self.open_journal();
            }
            assert(self.phase == .ready);
            assert(self.checkpoint_phase == .writing);
            checkpoint_io.result catch |err| switch (err) {
                error.CheckpointTooLarge => return self.checkpoint_finish(error.CheckpointTooLarge),
                error.CheckpointCorrupt => unreachable, // Only reads report corruption.
            };
            var superblock = self.superblock.working;
            // The replaced newest checkpoint becomes the fallback.
            superblock.journal_start_previous = superblock.journal_start;
            superblock.checkpoint_previous = superblock.checkpoint;
            superblock.commit_metadata_previous = superblock.commit_metadata;
            superblock.journal_start = self.checkpoint_start;
            superblock.checkpoint = checkpoint_io.checkpoint;
            superblock.commit_metadata = self.checkpoint_metadata;
            self.checkpoint_phase = .superblock;
            self.superblock.write_superblock(superblock, on_superblock);
        }

        fn checkpoint_superblock_done(self: *Self) void {
            assert(self.checkpoint_phase == .superblock);
            // Every copy now names the new checkpoint, with the replaced one as the fallback:
            // entries before the fallback's start are no longer needed.
            assert(self.journal_start_position <= self.checkpoint_tail);
            self.journal.release(self.journal_start_position);
            self.journal_start_position = self.checkpoint_tail;
            self.checkpoint_finish(self.superblock.working.checkpoint);
        }

        fn checkpoint_finish(self: *Self, result: CheckpointError!Checkpoint) void {
            assert(self.checkpoint_phase != .idle);
            const callback = self.checkpoint_callback.?;
            self.checkpoint_result = result;
            self.checkpoint_phase = .idle;
            self.checkpoint_callback = null;
            callback(self);
        }

        fn open_journal(self: *Self) void {
            const working = &self.superblock.working;
            if (self.open_fallback) {
                self.open_start = working.journal_start_previous;
                self.journal.reset(working.format_id, self.open_start);
            } else {
                self.open_start = working.journal_start;
                self.journal.reset_retained(
                    working.format_id,
                    working.journal_start,
                    working.journal_start_previous,
                );
            }
            self.journal_start_position = self.journal.head;
            self.phase = .opening_journal;
            self.journal.recover(.{ .context = self, .on_entry = forward_entry }, on_journal);
        }

        fn forward_entry(context: *anyopaque, entry: Entry) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening_journal);
            self.commit_metadata = entry.metadata.*;
            self.consumer.?.on_entry(self.consumer.?.context, entry);
        }

        fn on_journal(journal: *JournalType) void {
            const self: *Self = @alignCast(@fieldParentPtr("journal", journal));
            if (self.phase == .opening_journal) return self.open_journal_done();
            assert(self.phase == .ready);
            const callback = self.commit_callback.?;
            self.commit_metadata = self.commit_metadata_pending;
            self.commit_callback = null;
            callback(self);
        }

        fn open_journal_done(self: *Self) void {
            assert(self.phase == .opening_journal);
            if (!self.open_fallback) return self.open_done();
            const working = &self.superblock.working;
            // The fallback must reach the state the rotten checkpoint covered: entries up to
            // its start were acknowledged before that checkpoint was taken.
            if (self.journal.sequence_next < working.journal_start.sequence) {
                return self.open_failed(error.CheckpointCorrupt);
            }
            // Name the fallback as the newest checkpoint before anything else is written, so
            // the next checkpoint goes into the rotten zone, not the one just loaded.
            var superblock = working.*;
            superblock.journal_start = superblock.journal_start_previous;
            superblock.checkpoint = superblock.checkpoint_previous;
            superblock.commit_metadata = superblock.commit_metadata_previous;
            assert(!superblock.has_fallback());
            assert(self.journal_start_position == self.journal.tail);
            self.phase = .demoting;
            self.superblock.write_superblock(superblock, on_superblock);
        }

        fn open_done(self: *Self) void {
            assert(self.phase == .opening_journal or self.phase == .demoting);
            const recovered = self.journal.recover_result;
            self.phase = .ready;
            self.consumer = null;
            self.open_result = .{
                .checkpoint = self.superblock.working.checkpoint,
                .checkpoint_fallback = self.open_fallback,
                .entries_replayed = recovered.replayed,
                .sequence_last = self.journal.sequence_next - 1,
                .journal_stop = recovered.stop,
                .superblock_repaired = self.superblock_repaired,
            };
            assert(self.open_start.sequence <= self.journal.sequence_next);
            self.finish_phase();
        }

        fn open_failed(self: *Self, err: OpenError) void {
            assert(self.phase != .ready and self.phase != .closed);
            self.open_result = err;
            self.phase = .closed;
            self.consumer = null;
            self.finish_phase();
        }

        fn finish_phase(self: *Self) void {
            assert(self.phase == .closed or self.phase == .ready);
            const callback = self.phase_callback.?;
            self.phase_callback = null;
            callback(self);
        }
    };
}

/// Test helper: ticks `storage_` until `engine` is idle, at most `ticks_max` times.
pub fn tick_until_idle(storage_: anytype, engine: anytype, ticks_max: u64) error{Timeout}!void {
    var ticks: u64 = 0;
    while (!engine.idle()) : (ticks += 1) {
        if (ticks >= ticks_max) return error.Timeout;
        storage_.tick();
    }
    assert(engine.idle());
}

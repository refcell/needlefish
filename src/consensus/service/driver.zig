//! The node driver: one non-blocking state machine that ties startup forkchoice discovery,
//! the engine task queue, the derivation pipeline, the finalizer, the safe head database,
//! and (in sequencer mode) block building together. Mirrors the roles of base/base's
//! `service/src/actors/{engine,derivation,sequencer}` actors, run in one loop instead of
//! actors over channels: the queue owns the engine state, so ordering is explicit.
//!
//! Every provider is passed per tick and never blocks (`error.NotAvailable` means "in
//! flight, call again"):
//! - `l1`: the derivation L1 chain provider plus `l1_block_info_by_hash`;
//! - `blobs`: the blob provider;
//! - `l2`: the L2 safe chain (`l2_block_info_by_{number,hash,label}`,
//!   `system_config_by_l2_hash`);
//! - `engine`: the polling engine client (`engine/task.zig`);
//! - `l1_head`, `l1_finalized`: the latest and finalized L1 blocks from the watcher.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const task = @import("../engine/task.zig");
const conf_depth = @import("conf_depth.zig");
const derive_errors = @import("../derive/errors.zig");
const pipeline_module = @import("../derive/pipeline.zig");
const attributes_module = @import("../derive/attributes.zig");
const AttributesWithParent = @import("../derive/attributes_queue.zig").AttributesWithParent;
const task_queue = @import("../engine/task_queue.zig");
const sync_start = @import("../engine/sync_start.zig");
const Finalizer = @import("../engine/finalizer.zig").Finalizer;
const SafeDB = @import("../safedb/root.zig").SafeDB;
const OriginSelector = @import("../sequencer/origin.zig").OriginSelector;
const sequencer_build = @import("../sequencer/build.zig");

const BlockId = protocol.block.BlockId;
const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;
const ProviderError = derive_errors.ProviderError;
const Pipeline = pipeline_module.Pipeline;
const EngineTaskQueue = task_queue.EngineTaskQueue;
const SyncState = @import("../engine/state.zig").SyncState;
const SyncStateUpdate = @import("../engine/state.zig").SyncStateUpdate;
const InsertEnvelope = @import("../engine/insert_task.zig").Envelope;
const UnsafeBuffer = @import("unsafe_buffer.zig").UnsafeBuffer;

pub const Options = struct {
    sequencer: bool = false,
    /// Start a sequencer inactive, for `admin_startSequencer` (base/base `--sequencer.stopped`;
    /// a conductor starts its leader this way).
    sequencer_stopped: bool = false,
    /// Build blocks without transaction pool transactions (base/base recovery mode).
    recovery_mode: bool = false,
    queue: task_queue.Options = .{},
    finalizer_capacity: u32 = 1024,
    /// Upper bound on engine queue steps and pipeline steps per tick.
    steps_per_tick_max: u32 = 64,
    /// Gossiped blocks ahead of the unsafe head kept until their parent is inserted.
    unsafe_buffer_capacity: u32 = 64,
    /// While the execution engine syncs, re-send the forkchoice state this often.
    el_sync_probe_interval_s: u64 = 2,
    /// Follow mode (base/base `FollowNode`): no derivation or L1 finalization; unsafe blocks
    /// come from a source node through `insert_unsafe` and safe/finalized labels through
    /// `promote_labels`.
    follow: bool = false,
    /// Derive only from L1 blocks this many below the L1 head (`--l1.verifier-confs`).
    verifier_l1_confs: u64 = 0,
    /// Pick sequencer L1 origins this many below the L1 head (`--sequencer.l1-confs`;
    /// the binary defaults to base/base's 4).
    sequencer_l1_confs: u64 = 0,
};

pub const Phase = enum { starting, resetting, running };

pub const Stats = struct {
    resets: u64 = 0,
    /// Startups whose safe label canonical L1 no longer supported (see `SafeCheck`).
    safe_unwinds: u64 = 0,
    consolidated: u64 = 0,
    sealed: u64 = 0,
    /// Gossiped unsafe payloads queued for insertion / buffered ahead of the head / ignored
    /// (stale, not running, sequencing, buffer full).
    unsafe_queued: u64 = 0,
    unsafe_buffered: u64 = 0,
    unsafe_ignored: u64 = 0,
    finalized: u64 = 0,
    engine_failures: u64 = 0,
    derivation_failures: u64 = 0,
    critical_errors: u64 = 0,
    /// Forced forkchoice updates sent while waiting for EL sync to finish.
    el_sync_probes: u64 = 0,
    /// Follow mode: label updates queued.
    labels_promoted: u64 = 0,
};

/// Adapts the node providers to the startup finder's client (null on `NotFound`).
fn FinderClient(comptime Providers: type) type {
    return struct {
        providers: Providers,
        /// What canonical L1 supports of the safe label (see `SafeCheck`).
        safe_check: SafeCheck = .{ .done = true },

        const Self = @This();

        pub fn l2_block_info_by_label(
            self: Self,
            label: sync_start.Label,
        ) ProviderError!?L2BlockInfo {
            // The L2 provider's label enum lists latest, safe, finalized in the same order.
            const l2 = self.providers.l2;
            const result = l2.l2_block_info_by_label(@fromBackingInt(@intCast(@backingInt(label))));
            const block = try optional(L2BlockInfo, result);
            if (label != .safe) return block;
            assert(self.safe_check.done);
            // No recorded L1 block is canonical: fall back to the finalized head.
            if (self.safe_check.unsupported) return null;
            const cap = self.safe_check.cap orelse return block;
            const labeled = block orelse return null;
            if (labeled.block_info.number <= cap.number) return labeled;
            return self.l2_block_info_by_hash(cap.hash);
        }

        pub fn l2_block_info_by_hash(self: Self, hash: Hash) ProviderError!?L2BlockInfo {
            return optional(L2BlockInfo, self.providers.l2.l2_block_info_by_hash(hash));
        }

        pub fn l2_block_info_by_number(self: Self, number: u64) ProviderError!?L2BlockInfo {
            return optional(L2BlockInfo, self.providers.l2.l2_block_info_by_number(number));
        }

        /// The header behind the last `error.Pruned` (providers without pruning: none).
        pub fn l2_pruned_header(self: Self) ?BlockInfo {
            const L2 = @typeInfo(@TypeOf(self.providers.l2)).pointer.child;
            if (!@hasDecl(L2, "pruned_header")) return null;
            return self.providers.l2.pruned_header();
        }

        /// Durable checkpoints, when the providers carry them (`checkpoints` field).
        pub fn l2_checkpoint(self: Self, label: sync_start.CheckpointLabel) ?L2BlockInfo {
            if (!@hasField(Providers, "checkpoints")) return null;
            const checkpoints = self.providers.checkpoints orelse return null;
            return switch (label) {
                .safe => checkpoints.safe,
                .finalized => checkpoints.finalized,
            };
        }

        pub fn l1_block_info_by_number(self: Self, number: u64) ProviderError!?BlockInfo {
            return optional(BlockInfo, self.providers.l1.l1_block_info_by_number(number));
        }

        pub fn l1_head(self: Self) ProviderError!BlockInfo {
            return self.providers.l1_head orelse error.NotAvailable;
        }
    };
}

/// Before startup discovery the driver checks the safedb against canonical L1: the newest
/// entry whose L1 block is still canonical caps the engine's safe label at that entry's safe
/// head. An L1 reorg can orphan the blocks that carried the batch data of a safe head whose
/// L1 origin stays canonical; base/base discovery keeps such a safe label, and the batcher,
/// which posts from the safe head, would never post those blocks again.
pub const SafeCheck = struct {
    /// Entries left to check, newest first (null: not started).
    remaining: ?u32 = null,
    done: bool = false,
    /// The newest safe head that canonical L1 still supports.
    cap: ?BlockId = null,
    /// Entries exist but none of their L1 blocks is canonical.
    unsupported: bool = false,
    /// Ticks spent waiting for L1 lookups.
    ticks: u32 = 0,
};

/// L1 lookups per tick for the safedb check.
const safe_check_lookups_max = 16;
/// Ticks the safedb check waits for L1 (a provider behind the recorded blocks) before it
/// gives up without a cap.
const safe_check_ticks_max = 3000;

fn optional(comptime T: type, result: ProviderError!T) ProviderError!?T {
    return result catch |err| switch (err) {
        error.NotFound => null,
        else => err,
    };
}

pub const Driver = struct {
    allocator: Allocator,
    rollup: *const RollupConfig,
    options: Options,
    safe_db: *SafeDB,
    phase: Phase = .starting,
    finder: sync_start.StartFinder,
    safe_check: SafeCheck = .{},
    queue: EngineTaskQueue,
    pipeline: Pipeline,
    finalizer: Finalizer,
    selector: OriginSelector,
    builder: attributes_module.AttributesBuilder,
    unsafe_buffer: UnsafeBuffer,
    /// A consolidate task is queued; holds the L1 block its attributes derive from.
    consolidating: ?BlockInfo = null,
    /// Sequencer attributes waiting for their payload id (build) or seal.
    sealing: ?AttributesWithParent = null,
    /// A build or seal task is queued, or a built payload waits for its seal time.
    building: bool = false,
    /// The built payload waiting for `seal_at_ms` (subsecond slots seal 150 ms in).
    seal_payload: ?task.PayloadId = null,
    /// Wall clock (ms) at which the payload being built is sealed (`engine_getPayload`).
    seal_at_ms: u64 = 0,
    /// Wall clock (ms) of the current tick.
    now_ms: u64 = 0,
    /// Runtime sequencer switch (`admin_startSequencer`/`admin_stopSequencer`).
    sequencer_active: bool = false,
    /// Wall clock (seconds) of the last EL sync probe.
    el_sync_probe_s: u64 = 0,
    stats: Stats = .{},
    /// The most recent failure of any kind, for logs; `error_sequence` counts them.
    last_error: ?anyerror = null,
    error_sequence: u64 = 0,

    /// `driver` must not move afterwards (the pipeline and builder keep config pointers).
    pub fn init(
        driver: *Driver,
        allocator: Allocator,
        rollup: *const RollupConfig,
        blob_schedule: *const L1BlobSchedule,
        safe_db: *SafeDB,
        options: Options,
    ) Allocator.Error!void {
        assert(options.steps_per_tick_max > 0);
        assert(rollup.block_time > 0 or rollup.denim_timestamp_schedule() != null);
        const genesis = rollup.genesis;
        const start_origin: BlockInfo = .{ .hash = genesis.l1.hash, .number = genesis.l1.number };
        const context: @import("../engine/task.zig").Context = .{ .rollup = rollup };
        var queue = try EngineTaskQueue.init(allocator, context, .{}, options.queue);
        errdefer queue.deinit(allocator);
        var finalizer = try Finalizer.init(allocator, options.finalizer_capacity);
        errdefer finalizer.deinit(allocator);
        const retain_bytes = options.queue.retain_bytes;
        var unsafe_buffer =
            try UnsafeBuffer.init(allocator, options.unsafe_buffer_capacity, retain_bytes);
        errdefer unsafe_buffer.deinit(allocator);
        driver.* = .{
            .allocator = allocator,
            .rollup = rollup,
            .options = options,
            .safe_db = safe_db,
            .finder = .init(rollup),
            .queue = queue,
            .pipeline = Pipeline.init(allocator, rollup, blob_schedule, start_origin),
            .finalizer = finalizer,
            .selector = .init(rollup),
            .builder = .init(allocator, rollup, blob_schedule),
            .unsafe_buffer = unsafe_buffer,
            .sequencer_active = options.sequencer and !options.sequencer_stopped,
        };
        assert(driver.phase == .starting);
    }

    pub fn deinit(driver: *Driver) void {
        driver.drop_sealing();
        driver.pipeline.deinit();
        driver.finalizer.deinit(driver.allocator);
        driver.unsafe_buffer.deinit(driver.allocator);
        driver.queue.deinit(driver.allocator);
        driver.* = undefined;
    }

    pub fn sync_state(driver: *const Driver) SyncState {
        return driver.queue.state.sync_state;
    }

    /// One step of every state machine; `now_ms` is the wall clock in milliseconds.
    pub fn tick(driver: *Driver, providers: anytype, now_ms: u64) void {
        driver.now_ms = now_ms;
        const now_s = now_ms / std.time.ms_per_s;
        switch (driver.phase) {
            .starting => driver.start(providers),
            .resetting => driver.reset_pipeline(providers),
            .running => {
                driver.step_engine(providers);
                if (driver.phase != .running) return;
                driver.drain_unsafe();
                // Derivation and sequencing wait until the engine has finished its initial
                // sync (base/base `AwaitingELSyncCompletion`).
                if (!driver.queue.state.el_sync_finished) return driver.probe_el_sync(now_s);
                if (driver.options.follow) return;
                driver.derive(providers);
                if (driver.phase != .running) return;
                driver.finalize(providers.l1_finalized);
                if (driver.sequencer_active) driver.sequence(providers, now_ms);
            },
        }
        assert(driver.queue.state.sync_state.is_ordered());
    }

    fn start(driver: *Driver, providers: anytype) void {
        if (!driver.check_safe_db(providers)) return;
        const client: FinderClient(@TypeOf(providers)) = .{
            .providers = providers,
            .safe_check = driver.safe_check,
        };
        const found = driver.finder.step(client) catch |err| {
            if (err == error.NotAvailable) return;
            driver.note(err);
            driver.stats.critical_errors += 1;
            driver.finder = .init(driver.rollup); // Retry from the labeled heads.
            return;
        } orelse return;
        driver.queue.clear();
        // A capped safe head never drops below the finalized head.
        const unwound = found.safe_head.block_info.number < found.finalized_head.block_info.number;
        const safe_head = if (unwound) found.finalized_head else found.safe_head;
        driver.queue.state.sync_state = .{
            .unsafe_head = found.unsafe_head,
            .local_safe_head = safe_head,
            .safe_head = safe_head,
            .finalized_head = found.finalized_head,
        };
        driver.queue.enqueue(.{ .synchronize = .{} }) catch unreachable; // Proof: cleared.
        driver.selector.reset();
        driver.finalizer.clear();
        driver.safe_db.safe_head_reset(safe_head);
        driver.phase = .resetting;
        assert(driver.queue.len() == 1);
    }

    /// Runs the safedb check (`SafeCheck`); true when done. Lookups that fail for other
    /// reasons than data in flight end the check without a cap (base/base behavior).
    fn check_safe_db(driver: *Driver, providers: anytype) bool {
        const check = &driver.safe_check;
        if (check.done) return true;
        const db = driver.safe_db;
        if (check.remaining == null) {
            check.remaining = db.count;
            // By-number lookups are cached briefly; the reorg may have just moved them.
            const L1 = @typeInfo(@TypeOf(providers.l1)).pointer.child;
            if (@hasDecl(L1, "forget_numbers")) providers.l1.forget_numbers();
        }
        check.ticks += 1;
        if (check.ticks > safe_check_ticks_max) {
            check.done = true; // L1 never caught up: keep the labels (base/base).
            return true;
        }
        var lookups: u32 = 0;
        while (check.remaining.? > 0 and lookups < safe_check_lookups_max) : (lookups += 1) {
            const entry = db.entries[check.remaining.? - 1];
            const result = providers.l1.l1_block_info_by_number(entry.l1_block.number);
            // Unknown (not yet seen by the provider) is no evidence of a reorg: wait.
            const canonical = result catch |err| switch (err) {
                error.NotAvailable, error.NotFound => return false,
                else => {
                    driver.note(err);
                    check.done = true;
                    return true;
                },
            };
            if (canonical.hash.eql(entry.l1_block.hash)) {
                check.cap = entry.safe_head;
                check.done = true;
                if (check.remaining.? < db.count) driver.stats.safe_unwinds += 1;
                return true;
            }
            check.remaining.? -= 1;
        }
        if (check.remaining.? > 0) return false;
        check.done = true;
        check.unsupported = db.count > 0;
        if (check.unsupported) driver.stats.safe_unwinds += 1;
        assert(check.cap == null);
        return true;
    }

    /// base/base `probe_el_sync`: a forced forkchoice update of the current state, since the
    /// engine can move from SYNCING to VALID without the forkchoice changing.
    fn probe_el_sync(driver: *Driver, now_s: u64) void {
        assert(!driver.queue.state.el_sync_finished);
        if (driver.queue.len() > 0) return; // The startup synchronize or inserts first.
        const interval_s = driver.options.el_sync_probe_interval_s;
        if (driver.el_sync_probe_s != 0 and now_s < driver.el_sync_probe_s + interval_s) return;
        driver.queue.enqueue(.{ .synchronize = .{} }) catch return; // Empty: forced.
        driver.el_sync_probe_s = @max(now_s, 1);
        driver.stats.el_sync_probes += 1;
        assert(driver.queue.len() == 1);
    }

    fn reset_pipeline(driver: *Driver, providers: anytype) void {
        const safe_head = driver.queue.state.sync_state.safe_head;
        const signal: pipeline_module.Signal = .{ .reset = .{ .l2_safe_head = safe_head } };
        driver.pipeline.signal(driver.derive_l1(providers), providers.l2, signal) catch |err| {
            if (err != error.NotAvailable) driver.note(err);
            if (derive_errors.kind(err) == .critical) driver.stats.critical_errors += 1;
            return; // Temporary (data in flight) or reset: retry next tick.
        };
        driver.phase = .running;
        assert(driver.pipeline.origin() != null);
    }

    /// `admin_startSequencer`: resume sequencing on `unsafe_head`, the current unsafe head.
    /// Starting an active sequencer succeeds without effect (base/base).
    pub fn start_sequencer(driver: *Driver, unsafe_head: Hash) error{
        NotSequencer,
        UnsafeHeadMismatch,
        NotReady,
    }!void {
        if (!driver.options.sequencer) return error.NotSequencer;
        if (driver.sequencer_active) return;
        if (driver.phase != .running) return error.NotReady;
        const head = driver.queue.state.sync_state.unsafe_head.block_info.hash;
        if (!head.eql(unsafe_head)) return error.UnsafeHeadMismatch;
        driver.sequencer_active = true;
        assert(driver.sequencer_active);
    }

    /// `admin_stopSequencer`: stop building; returns the unsafe head to resume from. A seal
    /// already queued still completes; a built payload waiting for its seal time is discarded
    /// (base/base drops `next_payload`). Stopping a stopped sequencer only returns the head.
    pub fn stop_sequencer(driver: *Driver) error{NotSequencer}!Hash {
        if (!driver.options.sequencer) return error.NotSequencer;
        driver.sequencer_active = false;
        if (driver.seal_payload != null) {
            driver.drop_sealing();
            driver.building = false;
        }
        assert(!driver.sequencer_active);
        return driver.queue.state.sync_state.unsafe_head.block_info.hash;
    }

    /// Takes a gossiped unsafe payload (base/base `UnsafePayload` handling): the block right
    /// after the unsafe head is queued for insertion, later blocks wait in the unsafe buffer
    /// until their parent is inserted, older ones are stale. An active sequencer ignores
    /// gossip. Returns whether the payload was kept; both paths copy it.
    pub fn insert_unsafe(driver: *Driver, envelope: *const InsertEnvelope) bool {
        const unsafe_number = driver.queue.state.sync_state.unsafe_head.block_info.number;
        const number = envelope.payload.block_number;
        const wanted = driver.phase == .running and !driver.sequencer_active and
            number > unsafe_number;
        if (wanted and number == unsafe_number + 1 and driver.enqueue_unsafe(envelope)) {
            return true;
        }
        if (wanted and number > unsafe_number + 1) {
            switch (driver.unsafe_buffer.put(envelope)) {
                .stored, .replaced, .evicted_other => {
                    driver.stats.unsafe_buffered += 1;
                    return true;
                },
                .dropped, .out_of_memory => {},
            }
        }
        driver.stats.unsafe_ignored += 1;
        assert(driver.stats.unsafe_ignored > 0);
        return false;
    }

    /// Follow mode: moves the safe and finalized heads to verified source labels. A label at
    /// or behind the current head, or ahead of the unsafe (safe) head, is ignored, so the
    /// heads never unwind. Returns whether an update was queued.
    pub fn promote_labels(driver: *Driver, safe: ?L2BlockInfo, finalized: ?L2BlockInfo) bool {
        assert(driver.options.follow);
        if (driver.phase != .running) return false;
        const state = &driver.queue.state.sync_state;
        var update: SyncStateUpdate = .{};
        var safe_number = state.safe_head.block_info.number;
        if (safe) |head| {
            const number = head.block_info.number;
            if (number > safe_number and number <= state.unsafe_head.block_info.number) {
                update.local_safe_head = head;
                update.safe_head = head;
                safe_number = number;
            }
        }
        if (finalized) |head| {
            const number = head.block_info.number;
            if (number > state.finalized_head.block_info.number and number <= safe_number) {
                update.finalized_head = head;
            }
        }
        if (update.safe_head == null and update.finalized_head == null) return false;
        driver.queue.enqueue(.{ .synchronize = update }) catch |err| {
            driver.note(err);
            return false;
        };
        driver.stats.labels_promoted += 1;
        assert(driver.stats.labels_promoted > 0);
        return true;
    }

    fn enqueue_unsafe(driver: *Driver, envelope: *const InsertEnvelope) bool {
        const request: task_queue.Request = .{ .insert = .{
            .envelope = envelope,
            .drop_invalid = true,
        } };
        driver.queue.enqueue(request) catch |err| {
            driver.note(err);
            return false;
        };
        driver.stats.unsafe_queued += 1;
        assert(driver.queue.len() > 0);
        return true;
    }

    /// Drops buffered blocks the chain already has and queues the next one, if buffered.
    fn drain_unsafe(driver: *Driver) void {
        const buffer = &driver.unsafe_buffer;
        if (buffer.count == 0) return;
        if (driver.sequencer_active) return buffer.clear();
        const unsafe_number = driver.queue.state.sync_state.unsafe_head.block_info.number;
        buffer.prune_through(unsafe_number);
        const index = buffer.find(unsafe_number + 1) orelse return;
        if (driver.enqueue_unsafe(buffer.get(index))) buffer.remove(index);
        assert(buffer.count <= buffer.slots.len);
    }

    /// Starts over from startup discovery (engine reset, base/base `ResetRequest`).
    pub fn request_reset(driver: *Driver) void {
        driver.stats.resets += 1;
        driver.queue.clear();
        driver.drop_sealing();
        driver.building = false;
        driver.consolidating = null;
        driver.finder = .init(driver.rollup);
        driver.safe_check = .{};
        driver.phase = .starting;
        assert(driver.queue.len() == 0);
    }

    fn note(driver: *Driver, err: anyerror) void {
        driver.last_error = err;
        driver.error_sequence += 1;
        assert(driver.last_error != null);
    }

    /// The L1 provider derivation reads, `verifier_l1_confs` below the head.
    fn derive_l1(
        driver: *const Driver,
        providers: anytype,
    ) conf_depth.ConfDepth(@TypeOf(providers.l1)) {
        assert(driver.options.verifier_l1_confs < 1 << 32);
        return .{
            .l1 = providers.l1,
            .l1_head = providers.l1_head,
            .depth = driver.options.verifier_l1_confs,
            .unknown = .pass,
        };
    }

    /// The L1 provider the sequencer picks origins from, `sequencer_l1_confs` below the head.
    fn sequencer_l1(
        driver: *const Driver,
        providers: anytype,
    ) conf_depth.ConfDepth(@TypeOf(providers.l1)) {
        assert(driver.options.sequencer);
        return .{
            .l1 = providers.l1,
            .l1_head = providers.l1_head,
            .depth = driver.options.sequencer_l1_confs,
            .unknown = .hide,
        };
    }

    fn drop_sealing(driver: *Driver) void {
        if (driver.sealing) |*attributes| attributes.deinit(driver.allocator);
        driver.sealing = null;
        driver.seal_payload = null;
        assert(driver.sealing == null);
    }

    /// Queues the seal (`engine_getPayload` + insert) of the waiting payload.
    fn enqueue_seal(driver: *Driver) void {
        const payload_id = driver.seal_payload.?;
        assert(driver.building);
        const request: task_queue.Request = .{ .seal = .{
            .payload_id = payload_id,
            .attributes = &driver.sealing.?,
        } };
        driver.queue.enqueue(request) catch {
            driver.building = false; // Queue full: drop the block, build again.
        };
        driver.drop_sealing(); // The seal task copied the attributes.
    }

    fn step_engine(driver: *Driver, providers: anytype) void {
        for (0..driver.options.steps_per_tick_max) |_| {
            switch (driver.queue.step(providers.engine)) {
                .idle, .pending => return,
                .completed => |completion| driver.on_completed(completion),
                .failed => |failure| {
                    driver.on_failed(providers, failure);
                    return;
                },
            }
            if (driver.phase != .running) return;
        }
    }

    fn on_completed(driver: *Driver, completion: task_queue.Completion) void {
        switch (completion) {
            .consolidate => {
                const derived_from = driver.consolidating.?;
                driver.consolidating = null;
                const safe_head = driver.queue.state.sync_state.local_safe_head;
                driver.safe_db.safe_head_updated(safe_head, derived_from);
                driver.finalizer.enqueue(derived_from.number, safe_head.block_info.number);
                driver.stats.consolidated += 1;
            },
            .build => |payload_id| {
                assert(driver.sealing != null);
                if (!driver.sequencer_active) { // Stopped while building: discard.
                    driver.drop_sealing();
                    driver.building = false;
                    return;
                }
                driver.seal_payload = payload_id;
                if (driver.now_ms >= driver.seal_at_ms) driver.enqueue_seal();
            },
            .seal => {
                driver.building = false;
                driver.stats.sealed += 1;
            },
            .finalize => driver.stats.finalized += 1,
            .insert, .synchronize => {},
        }
    }

    fn on_failed(driver: *Driver, providers: anytype, failure: task_queue.Failure) void {
        driver.stats.engine_failures += 1;
        driver.note(failure.err);
        switch (failure.severity) {
            .temporary, .deferred => {}, // The task stays queued and is retried.
            .critical => driver.stats.critical_errors += 1,
            .reset => driver.request_reset(),
            .flush => {
                // The task was dropped.
                if (failure.kind == .consolidate) driver.consolidating = null;
                if (failure.kind == .build or failure.kind == .seal) {
                    driver.building = false;
                    driver.drop_sealing();
                }
                const l1 = driver.derive_l1(providers);
                driver.pipeline.signal(l1, providers.l2, .flush_channel) catch {};
            },
        }
    }

    fn derive(driver: *Driver, providers: anytype) void {
        if (driver.consolidating != null) return;
        if (driver.pipeline.next()) |prepared| {
            var attributes = prepared;
            defer attributes.deinit(driver.allocator);
            driver.queue.enqueue(.{ .consolidate = &attributes }) catch return;
            driver.consolidating = attributes.derived_from orelse driver.pipeline.origin().?;
            return;
        }
        const cursor = driver.queue.state.sync_state.local_safe_head;
        for (0..driver.options.steps_per_tick_max) |_| {
            const l1 = driver.derive_l1(providers);
            const result = driver.pipeline.step(l1, providers.blobs, providers.l2, cursor);
            const err = switch (result) {
                .prepared_attributes => return,
                .advanced_origin => continue,
                .origin_advance_err, .step_failed => |err| err,
            };
            if (err != error.NotAvailable and err != error.Eof) driver.note(err);
            switch (derive_errors.kind(err)) {
                .temporary => {},
                .reset => {
                    driver.stats.derivation_failures += 1;
                    driver.request_reset();
                },
                .critical => driver.stats.critical_errors += 1,
            }
            return;
        }
    }

    fn finalize(driver: *Driver, l1_finalized: ?BlockInfo) void {
        const block = l1_finalized orelse return;
        const number = driver.finalizer.process_finalized_l1_block(block) orelse return;
        if (number <= driver.queue.state.sync_state.finalized_head.block_info.number) return;
        driver.queue.enqueue(.{ .finalize = number }) catch {};
    }

    fn sequence(driver: *Driver, providers: anytype, now_ms: u64) void {
        if (driver.building) {
            if (driver.seal_payload != null and now_ms >= driver.seal_at_ms) driver.enqueue_seal();
            return;
        }
        const head = driver.queue.state.sync_state.unsafe_head;
        const slot = block_slot(driver.rollup, head.block_info.number + 1);
        if (now_ms < slot.build_at_ms) return;
        const outcome = sequencer_build.build_on(
            &driver.selector,
            &driver.builder,
            driver.sequencer_l1(providers),
            providers.l2,
            head,
            driver.options.recovery_mode,
        ) catch |err| {
            driver.note(err);
            driver.stats.critical_errors += 1;
            return;
        };
        switch (outcome) {
            .ready => |ready| {
                driver.sealing = .{
                    .attributes = ready.attributes,
                    .parent = ready.parent,
                    .derived_from = null,
                    .is_last_in_span = false,
                };
                driver.queue.enqueue(.{ .build = &driver.sealing.? }) catch {
                    driver.drop_sealing();
                    return;
                };
                driver.building = true;
                driver.seal_at_ms = slot.seal_at_ms;
            },
            .deferred, .awaiting_l1_origin => {},
            .reset => driver.request_reset(),
        }
    }
};

/// base/base `DEFAULT_SEAL_OFFSET`: subsecond blocks request the payload 150 ms into the slot.
pub const seal_offset_ms: u64 = 150;

pub const BlockSlot = struct { build_at_ms: u64, seal_at_ms: u64 };

/// When the sequencer starts building block `number` and when it seals it. A subsecond block
/// (base/base `block_seal_target`) builds from its parent's timestamp and seals at
/// `T - (200 ms - 150 ms)`; an earlier block builds at its own timestamp and seals as soon
/// as the engine returns the payload id.
pub fn block_slot(rollup: *const RollupConfig, number: u64) BlockSlot {
    assert(number > 0);
    const target_ms = rollup.l2_block_timestamp_ms(number);
    const interval_ms = protocol.rollup_config.DenimTimestampSchedule.denim_block_interval_ms;
    comptime assert(seal_offset_ms < interval_ms);
    if (!rollup.is_feature_active(.subsecond_blocks, target_ms / std.time.ms_per_s)) {
        return .{ .build_at_ms = target_ms, .seal_at_ms = target_ms };
    }
    const parent_ms = rollup.l2_block_timestamp_ms(number - 1);
    const seal_at_ms = target_ms -| (interval_ms - seal_offset_ms);
    assert(parent_ms <= seal_at_ms);
    return .{ .build_at_ms = parent_ms, .seal_at_ms = seal_at_ms };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn ms(seconds: u64) u64 {
    return seconds * std.time.ms_per_s;
}
const TestChain = @import("../derive/test_chain.zig").TestChain;
const MockEngine = @import("../engine/mock_engine.zig").MockEngine;
const SystemConfig = protocol.system_config.SystemConfig;
const SafeBlock = protocol.span_batch.SafeBlock;

/// The L2 provider view over a `TestChain` plus the engine's labeled heads.
const TestL2 = struct {
    chain: *TestChain,
    heads: [3]?L2BlockInfo = @splat(null),

    pub fn l2_block_info_by_label(l2: *TestL2, label: sync_start.Label) ProviderError!L2BlockInfo {
        return l2.heads[@backingInt(label)] orelse error.NotFound;
    }

    pub fn l2_block_info_by_number(l2: *TestL2, number: u64) ProviderError!L2BlockInfo {
        return l2.chain.l2_block_info_by_number(number);
    }

    pub fn l2_block_info_by_hash(l2: *TestL2, hash: Hash) ProviderError!L2BlockInfo {
        return l2.chain.l2_block_info_by_hash(hash);
    }

    pub fn system_config_by_l2_hash(l2: *TestL2, hash: Hash) ProviderError!SystemConfig {
        return l2.chain.system_config_by_l2_hash(hash);
    }

    pub fn l2_block_by_number(l2: *TestL2, number: u64) ProviderError!SafeBlock {
        return l2.chain.l2_block_by_number(number);
    }
};

const TestProviders = struct {
    l1: *TestChain,
    blobs: *TestChain,
    l2: *TestL2,
    engine: *MockEngine,
    l1_head: ?BlockInfo,
    l1_finalized: ?BlockInfo = null,
};

const Scenario = struct {
    chain: TestChain,
    l2: TestL2 = undefined,
    mock: MockEngine = .{ .latency = 1 },
    rollup: RollupConfig = undefined,
    schedule: L1BlobSchedule = .{},
    safe_db: SafeDB = undefined,
    driver: Driver = undefined,
    deposit: [512]u8 = undefined,
    transactions: [1][]u8 = undefined,

    const genesis_time: u64 = 1000;

    fn init(scenario: *Scenario, options: Options) !void {
        scenario.* = .{ .chain = TestChain.init(8, 0, 12) };
        const chain = &scenario.chain;
        var genesis_hash: Hash = .zero;
        genesis_hash.bytes[0] = 0x42;
        const config: SystemConfig = .{ .gas_limit = 30_000_000 };
        scenario.rollup = .{
            .block_time = 2,
            .max_sequencer_drift = 600,
            .seq_window_size = 4,
            .channel_timeout = 8,
            .genesis = .{
                .l1 = chain.blocks[0].id(),
                .l2 = .{ .number = 0, .hash = genesis_hash },
                .l2_time = genesis_time,
                .system_config = config,
            },
        };
        const genesis: L2BlockInfo = .{
            .block_info = .{ .hash = genesis_hash, .number = 0, .timestamp = genesis_time },
            .l1_origin = chain.blocks[0].id(),
        };
        chain.add_l2_block(genesis);
        chain.add_system_config(genesis_hash, config);
        scenario.l2 = .{ .chain = chain };
        scenario.l2.heads = @splat(genesis);
        scenario.safe_db = try SafeDB.init(testing.allocator, 64);
        errdefer scenario.safe_db.deinit(testing.allocator);
        const rollup = &scenario.rollup;
        const safe_db = &scenario.safe_db;
        try scenario.driver.init(testing.allocator, rollup, &scenario.schedule, safe_db, options);
    }

    fn deinit(scenario: *Scenario) void {
        scenario.driver.deinit();
        scenario.safe_db.deinit(testing.allocator);
    }

    fn providers(scenario: *Scenario) TestProviders {
        return .{
            .l1 = &scenario.chain,
            .blobs = &scenario.chain,
            .l2 = &scenario.l2,
            .engine = &scenario.mock,
            .l1_head = scenario.chain.blocks[scenario.chain.count - 1],
        };
    }

    /// The payload the mock engine returns for the attributes being built.
    fn arm_payload(scenario: *Scenario, attributes: *const AttributesWithParent) void {
        const deposit = attributes.attributes.transactions[0];
        @memcpy(scenario.deposit[0..deposit.len], deposit);
        scenario.transactions[0] = scenario.deposit[0..deposit.len];
        var hash: Hash = .zero;
        hash.bytes[0] = 0x43;
        hash.bytes[1] = @truncate(attributes.parent.block_info.number + 1);
        scenario.mock.payload = .{ .block_value = 0, .payload = .{
            .parent_hash = attributes.parent.block_info.hash,
            .fee_recipient = .zero,
            .state_root = .zero,
            .receipts_root = .zero,
            .logs_bloom = .zero,
            .prev_randao = .zero,
            .block_number = attributes.parent.block_info.number + 1,
            .gas_limit = 30_000_000,
            .gas_used = 0,
            .timestamp = attributes.attributes.timestamp,
            .extra_data = &.{},
            .base_fee_per_gas = 1,
            .block_hash = hash,
            .transactions = &scenario.transactions,
        } };
    }
};

test "driver: starts from genesis, synchronizes, and resets the pipeline" {
    var scenario: Scenario = undefined;
    try scenario.init(.{});
    defer scenario.deinit();
    const driver = &scenario.driver;
    for (0..16) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time));
    try testing.expectEqual(Phase.running, driver.phase);
    try testing.expect(scenario.mock.forkchoice_calls >= 1);
    const safe_hash = driver.sync_state().safe_head.block_info.hash;
    try testing.expect(safe_hash.eql(scenario.rollup.genesis.l2.hash));
    try testing.expect(driver.pipeline.origin() != null);
    try testing.expectEqual(@as(u64, 0), driver.stats.critical_errors);
}

/// Adds L2 blocks 1..6 on epoch 0 and labels latest = safe = 6; the safedb records
/// L2 block 2 as derived from L1 block 2 and block 6 from L1 block 5 (with `orphaned`
/// entries carrying a hash that is not canonical).
fn add_reorg_history(scenario: *Scenario, orphaned: []const bool) !void {
    assert(orphaned.len == 2);
    var parent = scenario.rollup.genesis.l2;
    var last: L2BlockInfo = undefined;
    for (1..7) |number| {
        var hash: Hash = .zero;
        hash.bytes[0] = 0x51;
        hash.bytes[1] = @intCast(number);
        last = .{
            .block_info = .{
                .hash = hash,
                .number = number,
                .parent_hash = parent.hash,
                .timestamp = Scenario.genesis_time + 2 * number,
            },
            .l1_origin = scenario.chain.blocks[0].id(),
        };
        scenario.chain.add_l2_block(last);
        parent = last.block_info.id();
    }
    scenario.l2.heads[@backingInt(sync_start.Label.latest)] = last;
    scenario.l2.heads[@backingInt(sync_start.Label.safe)] = last;
    const recorded = [_]struct { l1: u64, l2: u64 }{ .{ .l1 = 2, .l2 = 2 }, .{ .l1 = 5, .l2 = 6 } };
    for (recorded, orphaned) |entry, gone| {
        var l1_block = scenario.chain.blocks[entry.l1].id();
        if (gone) l1_block.hash.bytes[31] ^= 0xff; // Its data went with an L1 reorg.
        const safe_head = (try scenario.chain.l2_block_info_by_number(entry.l2)).block_info;
        scenario.safe_db.insert(.{ .l1_block = l1_block, .safe_head = safe_head.id() });
    }
}

fn run_startup(scenario: *Scenario) void {
    var rounds: u32 = 0;
    while (scenario.driver.phase == .starting and rounds < 64) : (rounds += 1) {
        scenario.driver.tick(scenario.providers(), ms(Scenario.genesis_time + 20));
    }
    assert(scenario.driver.phase != .starting);
}

test "driver: startup unwinds a safe head whose L1 data a reorg orphaned" {
    const cases = [_]struct { orphaned: [2]bool, safe: u64, unwinds: u64 }{
        .{ .orphaned = .{ false, false }, .safe = 6, .unwinds = 0 },
        .{ .orphaned = .{ false, true }, .safe = 2, .unwinds = 1 },
        .{ .orphaned = .{ true, true }, .safe = 0, .unwinds = 1 }, // Finalized (genesis).
    };
    for (cases) |case| {
        var scenario: Scenario = undefined;
        try scenario.init(.{});
        defer scenario.deinit();
        try add_reorg_history(&scenario, &case.orphaned);
        run_startup(&scenario);
        const state = scenario.driver.sync_state();
        try testing.expectEqual(case.safe, state.safe_head.block_info.number);
        try testing.expectEqual(case.safe, state.local_safe_head.block_info.number);
        try testing.expectEqual(@as(u64, 6), state.unsafe_head.block_info.number);
        try testing.expectEqual(case.unwinds, scenario.driver.stats.safe_unwinds);
        // The safedb no longer claims safe heads above the unwound one.
        for (scenario.safe_db.entries[0..scenario.safe_db.count]) |entry| {
            try testing.expect(entry.safe_head.number <= case.safe);
        }
    }
}

test "driver: the safedb check runs again after a reset" {
    var scenario: Scenario = undefined;
    try scenario.init(.{});
    defer scenario.deinit();
    try add_reorg_history(&scenario, &.{ false, false });
    run_startup(&scenario);
    try testing.expectEqual(@as(u64, 6), scenario.driver.sync_state().safe_head.block_info.number);
    // Derivation records block 6 from L1 block 5 again, and a reorg then orphans it. (The
    // startup reset recorded safe head 6 at its L1 origin 0, as base/base does; the
    // newer canonical entry, L1 block 2, decides first.)
    var orphaned = scenario.chain.blocks[5].id();
    orphaned.hash.bytes[31] ^= 0xff;
    const head = scenario.driver.sync_state().safe_head.block_info.id();
    scenario.safe_db.insert(.{ .l1_block = orphaned, .safe_head = head });
    scenario.driver.request_reset();
    run_startup(&scenario);
    try testing.expectEqual(@as(u64, 2), scenario.driver.sync_state().safe_head.block_info.number);
    try testing.expectEqual(@as(u64, 1), scenario.driver.stats.safe_unwinds);
}

test "driver: derivation waits for EL sync and probes the engine meanwhile" {
    var scenario: Scenario = undefined;
    try scenario.init(.{ .sequencer = true });
    defer scenario.deinit();
    scenario.mock.forkchoice_status = .syncing;
    const driver = &scenario.driver;
    const start_s = Scenario.genesis_time + 2;
    for (0..32) |_| driver.tick(scenario.providers(), ms(start_s));
    try testing.expectEqual(Phase.running, driver.phase);
    try testing.expect(!driver.queue.state.el_sync_finished);
    try testing.expectEqual(@as(u64, 1), driver.stats.el_sync_probes);
    // Neither derivation nor the sequencer touch the engine while it syncs.
    try testing.expect(driver.consolidating == null);
    try testing.expect(!driver.building);
    try testing.expectEqual(@as(u32, 0), scenario.mock.build_calls);
    const calls = scenario.mock.forkchoice_calls;
    driver.tick(scenario.providers(), ms(start_s + 1)); // Inside the probe interval.
    try testing.expectEqual(calls, scenario.mock.forkchoice_calls);
    for (0..4) |_| driver.tick(scenario.providers(), ms(start_s + 2));
    try testing.expectEqual(@as(u64, 2), driver.stats.el_sync_probes);
    try testing.expect(scenario.mock.forkchoice_calls > calls);
    // The engine finishes syncing: the next probe confirms it and the sequencer builds.
    scenario.mock.forkchoice_status = .valid;
    for (0..8) |_| driver.tick(scenario.providers(), ms(start_s + 4));
    try testing.expect(driver.queue.state.el_sync_finished);
    try testing.expectEqual(@as(u64, 3), driver.stats.el_sync_probes);
    try testing.expect(driver.building or scenario.mock.build_calls >= 1);
    try testing.expectEqual(@as(u64, 0), driver.stats.critical_errors);
}

test "driver: verifier derives empty blocks past the sequencing window" {
    var scenario: Scenario = undefined;
    try scenario.init(.{});
    defer scenario.deinit();
    const driver = &scenario.driver;
    for (0..32) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time));
    // No batches: once the window expires the pipeline derives deposit-only blocks, which
    // the engine does not have, so consolidation builds them.
    try testing.expect(driver.consolidating != null);
    try testing.expect(scenario.mock.build_calls >= 1);
    try testing.expectEqual(@as(u64, 0), driver.sync_state().unsafe_head.block_info.number);
}

test "driver: sequencer builds and seals the next block on time" {
    var scenario: Scenario = undefined;
    try scenario.init(.{ .sequencer = true });
    defer scenario.deinit();
    scenario.chain.unavailable_from = 3; // L1 data stops before the window expires.
    const driver = &scenario.driver;
    for (0..8) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time + 1));
    try testing.expectEqual(Phase.running, driver.phase);
    try testing.expectEqual(@as(u32, 0), scenario.mock.build_calls);
    driver.tick(scenario.providers(), ms(Scenario.genesis_time + 2));
    try testing.expect(driver.building);
    scenario.arm_payload(&driver.sealing.?);
    for (0..16) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time + 2));
    try testing.expectEqual(@as(u64, 1), driver.stats.sealed);
    const head = driver.sync_state().unsafe_head;
    try testing.expectEqual(@as(u64, 1), head.block_info.number);
    try testing.expectEqual(@as(u64, 0), head.l1_origin.number);
    try testing.expect(!driver.building);
    try testing.expectEqual(@as(u64, 0), driver.stats.critical_errors);
}

test "driver: block slots build at the parent time and seal 150 ms into subsecond slots" {
    var rollup: RollupConfig = .{ .block_time = 2 };
    rollup.genesis = .{ .l2 = .{ .number = 0 }, .l2_time = 1000 };
    // Before Denim: build at the block's own timestamp and seal right away.
    const legacy = block_slot(&rollup, 3);
    try testing.expectEqual(@as(u64, 1_006_000), legacy.build_at_ms);
    try testing.expectEqual(legacy.build_at_ms, legacy.seal_at_ms);
    rollup.upgrades.set(.denim, 1004); // Block 2 (t = 1004 s) is the first Denim block.
    try testing.expect(rollup.is_feature_active(.subsecond_blocks, 1004));
    const first = block_slot(&rollup, 3); // 1004.2 s, parent at 1004.0 s.
    try testing.expectEqual(@as(u64, 1_004_000), first.build_at_ms);
    try testing.expectEqual(@as(u64, 1_004_150), first.seal_at_ms);
    const later = block_slot(&rollup, 10);
    try testing.expectEqual(later.build_at_ms + seal_offset_ms, later.seal_at_ms);
    try testing.expectEqual(rollup.l2_block_timestamp_ms(10) - 50, later.seal_at_ms);
    // Seeded: every subsecond slot opens at the parent and seals inside its own 200 ms.
    var prng = Prng.init(0x5107);
    for (0..256) |_| {
        const number = 3 + prng.below(1_000_000);
        const slot = block_slot(&rollup, number);
        try testing.expectEqual(rollup.l2_block_timestamp_ms(number - 1), slot.build_at_ms);
        try testing.expect(slot.seal_at_ms < rollup.l2_block_timestamp_ms(number));
    }
}

test "driver: subsecond sequencer holds the payload until 150 ms into the slot" {
    var scenario: Scenario = undefined;
    try scenario.init(.{ .sequencer = true });
    defer scenario.deinit();
    scenario.chain.unavailable_from = 3;
    scenario.rollup.upgrades.set(.denim, Scenario.genesis_time);
    const driver = &scenario.driver;
    const slot_start = ms(Scenario.genesis_time); // Block 1 is due at +200 ms.
    for (0..8) |_| driver.tick(scenario.providers(), slot_start);
    try testing.expect(driver.building);
    // L1 info, then the BaseTimeUpdateTx deposit carrying the 200 ms part.
    const transactions = driver.sealing.?.attributes.transactions;
    try testing.expectEqual(@as(usize, 2), transactions.len);
    const base_time = try attributes_module.encode_base_time(testing.allocator, 1, 200);
    defer testing.allocator.free(base_time);
    try testing.expectEqualSlices(u8, base_time, transactions[1]);
    scenario.arm_payload(&driver.sealing.?);
    for (0..16) |_| driver.tick(scenario.providers(), slot_start + 149);
    try testing.expect(driver.seal_payload != null); // Built, not sealed yet.
    try testing.expectEqual(@as(u64, 0), driver.stats.sealed);
    for (0..16) |_| driver.tick(scenario.providers(), slot_start + 150);
    try testing.expectEqual(@as(u64, 1), driver.stats.sealed);
    try testing.expectEqual(@as(u64, 1), driver.sync_state().unsafe_head.block_info.number);
    // Block 2 builds right away (its parent's slot has passed); stopping discards it.
    const head = driver.sync_state().unsafe_head;
    scenario.chain.add_l2_block(head);
    scenario.chain.add_system_config(head.block_info.hash, scenario.rollup.genesis.system_config.?);
    for (0..8) |_| driver.tick(scenario.providers(), slot_start + 200);
    try testing.expect(driver.building);
    scenario.arm_payload(&driver.sealing.?);
    for (0..8) |_| driver.tick(scenario.providers(), slot_start + 201);
    try testing.expect(driver.seal_payload != null);
    _ = try driver.stop_sequencer();
    try testing.expect(!driver.building and driver.sealing == null);
    for (0..8) |_| driver.tick(scenario.providers(), slot_start + 400);
    try testing.expectEqual(@as(u64, 1), driver.stats.sealed);
    try testing.expectEqual(@as(u64, 0), driver.stats.critical_errors);
}

test "driver: confirmation depths gate derivation and sequencer origins separately" {
    var scenario: Scenario = undefined;
    try scenario.init(.{ .sequencer = true, .verifier_l1_confs = 2, .sequencer_l1_confs = 4 });
    defer scenario.deinit();
    const driver = &scenario.driver;
    const providers = scenario.providers(); // L1 head: block 7.
    try testing.expect(!driver.derive_l1(providers).hidden(5));
    try testing.expect(driver.derive_l1(providers).hidden(6));
    try testing.expect(!driver.sequencer_l1(providers).hidden(3));
    try testing.expect(driver.sequencer_l1(providers).hidden(4));
    const delayed = driver.sequencer_l1(providers);
    try testing.expectError(error.NotFound, delayed.l1_block_info_by_number(4));
    var no_head = providers;
    no_head.l1_head = null;
    try testing.expect(!driver.derive_l1(no_head).hidden(6)); // Derivation: no head, no gate.
    try testing.expect(driver.sequencer_l1(no_head).hidden(1)); // Sequencer: nothing usable.
}

test "driver: a sealed payload inserts into a verifier as its unsafe head" {
    var sequencer: Scenario = undefined;
    try sequencer.init(.{ .sequencer = true });
    defer sequencer.deinit();
    sequencer.chain.unavailable_from = 3;
    const driver = &sequencer.driver;
    for (0..8) |_| driver.tick(sequencer.providers(), ms(Scenario.genesis_time + 1));
    try testing.expect(driver.queue.take_sealed() == null);
    driver.tick(sequencer.providers(), ms(Scenario.genesis_time + 2));
    sequencer.arm_payload(&driver.sealing.?);
    for (0..16) |_| driver.tick(sequencer.providers(), ms(Scenario.genesis_time + 2));
    const sealed = driver.queue.take_sealed().?;
    try testing.expectEqual(@as(u64, 1), sealed.payload.block_number);
    try testing.expect(driver.queue.take_sealed() == null);
    // The sequencer ignores gossip while it sequences.
    try testing.expect(!driver.insert_unsafe(sealed));

    var verifier: Scenario = undefined;
    try verifier.init(.{});
    defer verifier.deinit();
    verifier.chain.unavailable_from = 3;
    try testing.expect(!verifier.driver.insert_unsafe(sealed)); // Not running yet.
    for (0..8) |_| verifier.driver.tick(verifier.providers(), ms(Scenario.genesis_time + 1));
    try testing.expectEqual(Phase.running, verifier.driver.phase);
    var stale = sealed.*;
    stale.payload.block_number = 0;
    try testing.expect(!verifier.driver.insert_unsafe(&stale));
    try testing.expect(verifier.driver.insert_unsafe(sealed));
    for (0..8) |_| verifier.driver.tick(verifier.providers(), ms(Scenario.genesis_time + 2));
    const head = verifier.driver.sync_state().unsafe_head;
    try testing.expect(head.block_info.hash.eql(sealed.payload.block_hash));
    try testing.expectEqual(@as(u64, 1), verifier.driver.stats.unsafe_queued);
    try testing.expectEqual(@as(u64, 2), verifier.driver.stats.unsafe_ignored);
}

/// Seals blocks 1 and 2 on a sequencer and keeps copies of their payloads in `arena`.
fn seal_two(arena: Allocator) ![2]InsertEnvelope {
    var sequencer: Scenario = undefined;
    try sequencer.init(.{ .sequencer = true });
    defer sequencer.deinit();
    sequencer.chain.unavailable_from = 3;
    const driver = &sequencer.driver;
    for (0..8) |_| driver.tick(sequencer.providers(), ms(Scenario.genesis_time + 1));
    var sealed: [2]InsertEnvelope = undefined;
    for (&sealed, 0..) |*envelope, index| {
        const now_s = Scenario.genesis_time + 2 * (index + 1);
        driver.tick(sequencer.providers(), ms(now_s));
        sequencer.arm_payload(&driver.sealing.?);
        for (0..16) |_| driver.tick(sequencer.providers(), ms(now_s));
        envelope.* = try task_queue.copy_envelope(arena, driver.queue.take_sealed().?);
        // The next build reads its parent's block and system config from the chain.
        const head = driver.sync_state().unsafe_head;
        sequencer.chain.add_l2_block(head);
        const config = sequencer.rollup.genesis.system_config.?;
        sequencer.chain.add_system_config(head.block_info.hash, config);
    }
    try testing.expectEqual(@as(u64, 2), sealed[1].payload.block_number);
    try testing.expect(sealed[1].payload.parent_hash.eql(sealed[0].payload.block_hash));
    return sealed;
}

test "driver: follow mode inserts source blocks and promotes labels without deriving" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const sealed = try seal_two(arena.allocator());
    var follower: Scenario = undefined;
    try follower.init(.{ .follow = true });
    defer follower.deinit();
    const driver = &follower.driver;
    for (0..32) |_| driver.tick(follower.providers(), ms(Scenario.genesis_time + 1));
    try testing.expectEqual(Phase.running, driver.phase);
    // Past the sequencing window a verifier would derive and build; a follower does not.
    try testing.expect(driver.consolidating == null);
    try testing.expectEqual(@as(u32, 0), follower.mock.build_calls);
    try testing.expect(driver.insert_unsafe(&sealed[0]));
    for (0..8) |_| driver.tick(follower.providers(), ms(Scenario.genesis_time + 2));
    const first = driver.sync_state().unsafe_head;
    try testing.expectEqual(@as(u64, 1), first.block_info.number);
    try testing.expect(driver.insert_unsafe(&sealed[1]));
    for (0..8) |_| driver.tick(follower.providers(), ms(Scenario.genesis_time + 4));
    const second = driver.sync_state().unsafe_head;
    try testing.expectEqual(@as(u64, 2), second.block_info.number);
    // Finalized ahead of safe is held back until safe catches up.
    try testing.expect(driver.promote_labels(first, second));
    for (0..8) |_| driver.tick(follower.providers(), ms(Scenario.genesis_time + 4));
    try testing.expectEqual(@as(u64, 1), driver.sync_state().safe_head.block_info.number);
    try testing.expectEqual(@as(u64, 0), driver.sync_state().finalized_head.block_info.number);
    try testing.expect(driver.promote_labels(second, first));
    for (0..8) |_| driver.tick(follower.providers(), ms(Scenario.genesis_time + 4));
    const state = driver.sync_state();
    try testing.expect(state.safe_head.block_info.hash.eql(second.block_info.hash));
    try testing.expect(state.local_safe_head.block_info.hash.eql(second.block_info.hash));
    try testing.expect(state.finalized_head.block_info.hash.eql(first.block_info.hash));
    // Stale labels never unwind; labels past the unsafe head are ignored.
    try testing.expect(!driver.promote_labels(first, first));
    var ahead = second;
    ahead.block_info.number = 9;
    try testing.expect(!driver.promote_labels(ahead, null));
    try testing.expectEqual(@as(u64, 2), driver.stats.labels_promoted);
    try testing.expectEqual(@as(u64, 0), driver.stats.critical_errors);
}

test "driver: out-of-order gossip waits in the unsafe buffer for its parent" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const sealed = try seal_two(arena.allocator());
    var verifier: Scenario = undefined;
    try verifier.init(.{});
    defer verifier.deinit();
    verifier.chain.unavailable_from = 3;
    const driver = &verifier.driver;
    for (0..8) |_| driver.tick(verifier.providers(), ms(Scenario.genesis_time + 1));
    try testing.expectEqual(Phase.running, driver.phase);
    try testing.expect(driver.insert_unsafe(&sealed[1]));
    try testing.expectEqual(@as(u64, 1), driver.stats.unsafe_buffered);
    for (0..4) |_| driver.tick(verifier.providers(), ms(Scenario.genesis_time + 4));
    try testing.expectEqual(@as(u64, 0), driver.sync_state().unsafe_head.block_info.number);
    try testing.expect(driver.insert_unsafe(&sealed[0]));
    for (0..16) |_| driver.tick(verifier.providers(), ms(Scenario.genesis_time + 4));
    const head = driver.sync_state().unsafe_head;
    try testing.expect(head.block_info.hash.eql(sealed[1].payload.block_hash));
    try testing.expectEqual(@as(u32, 0), driver.unsafe_buffer.count);
    try testing.expectEqual(@as(u64, 2), driver.stats.unsafe_queued);
    // A late duplicate of block 1 is stale now.
    try testing.expect(!driver.insert_unsafe(&sealed[0]));
}

test "driver: admin sequencer stop and start" {
    var scenario: Scenario = undefined;
    try scenario.init(.{ .sequencer = true });
    defer scenario.deinit();
    scenario.chain.unavailable_from = 3;
    const driver = &scenario.driver;
    for (0..8) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time + 1));
    const head = try driver.stop_sequencer();
    try testing.expect(head.eql(scenario.rollup.genesis.l2.hash));
    try testing.expect((try driver.stop_sequencer()).eql(head)); // Idempotent.
    driver.tick(scenario.providers(), ms(Scenario.genesis_time + 2));
    try testing.expect(!driver.building);
    try testing.expectError(error.UnsafeHeadMismatch, driver.start_sequencer(.zero));
    try driver.start_sequencer(head);
    try driver.start_sequencer(.zero); // Already active: no effect, no head check.
    driver.tick(scenario.providers(), ms(Scenario.genesis_time + 2));
    try testing.expect(driver.building);
    var verifier: Scenario = undefined;
    try verifier.init(.{});
    defer verifier.deinit();
    try testing.expectError(error.NotSequencer, verifier.driver.stop_sequencer());
}

test "driver: engine reset severity restarts discovery" {
    var scenario: Scenario = undefined;
    try scenario.init(.{});
    defer scenario.deinit();
    const driver = &scenario.driver;
    for (0..16) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time));
    driver.request_reset();
    try testing.expectEqual(Phase.starting, driver.phase);
    for (0..16) |_| driver.tick(scenario.providers(), ms(Scenario.genesis_time));
    try testing.expectEqual(Phase.running, driver.phase);
    try testing.expectEqual(@as(u64, 1), driver.stats.resets);
}

/// Drives a sequencer through random engine latency, L1 availability, and clock steps; the
/// tick asserts the head ordering invariant, and no input may raise a critical error.
fn run_fuzz(bytes: []const u8) !void {
    var scenario: Scenario = undefined;
    try scenario.init(.{ .sequencer = true });
    defer scenario.deinit();
    var prng = @import("../../testing/prng.zig").Prng.init(if (bytes.len > 0) bytes[0] else 1);
    scenario.mock.prng = &prng;
    scenario.mock.not_available_percent = 30;
    var now_s: u64 = Scenario.genesis_time;
    for (bytes) |byte| {
        now_s += byte % 3;
        if (byte & 0x80 != 0) scenario.chain.unavailable_from = byte % 8;
        if (byte & 0x40 != 0) scenario.chain.unavailable_from = std.math.maxInt(u64);
        if (scenario.driver.sealing) |*sealing| scenario.arm_payload(sealing);
        scenario.driver.tick(scenario.providers(), ms(now_s));
    }
    try testing.expectEqual(@as(u64, 0), scenario.driver.stats.critical_errors);
    try testing.expect(scenario.driver.sync_state().is_ordered());
}

test "driver: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xd21);
    var bytes: [96]u8 = undefined;
    for (0..24) |_| {
        prng.fill(&bytes);
        try run_fuzz(&bytes);
    }
}

fn fuzz_driver(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [64]u8 = undefined;
    const len = smith.slice(&bytes);
    try run_fuzz(bytes[0..len]);
}

test "driver: fuzz" {
    try testing.fuzz({}, fuzz_driver, .{});
}

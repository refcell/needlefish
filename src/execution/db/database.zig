//! Durable execution database: the storage engine, `State`, and `ChainStore` behind one facade.
//!
//! Every mutating operation is one journal entry, in memory first and durable later:
//! - `insert_block` stores a block (header, body, receipts, transaction hashes, and its encoded
//!   changeset) and journals a `block` entry. State does not change.
//! - `set_head` moves the canonical head: it plans the reorg, unwinds and applies `State` with
//!   the stored changesets, updates the chain index, and journals a `head` entry.
//! - `execute_and_commit` turns an executed `Overlay` into a changeset (`build_changeset`, not
//!   `commit`), inserts the block, moves the head to it, journals one `block_and_head` entry
//!   (one journal write and one sync per block), and discards the overlay. Replay applies that
//!   entry as a block insert followed by a head move, through the same code paths.
//!
//! Operations return at once with their entry sequence. Entries wait in a bounded queue and
//! the engine writes one at a time; `durable_sequence` (and the optional `on_durable`
//! callback) reports how far the journal is durable. A full queue, or a journal without room
//! for the entry, returns `error.Busy`: tick the storage and retry.
//!
//! Checkpoints serialize the state snapshot, every stored block (oldest first, as block
//! entries), and the canonical head into a staging buffer, then stream it to the engine. A
//! checkpoint only starts when the queue is empty and no commit is in flight, so it covers
//! exactly the entries the engine committed before it; later operations proceed while the
//! frozen staging buffer streams out. `open` loads the checkpoint and replays the journal
//! through the same code paths without journaling again, then checks the result against the
//! last entry's metadata (head number, head hash, state root).
//! If the newest checkpoint is rotten, the engine resets the staged bytes, streams the older
//! fallback checkpoint instead, and replays the longer journal kept since it.
//!
//! Historical proofs (optional, `Config.history`): the database owns a `history.Store` and
//! updates it on every live head move: `unwind_to` the fork point, then `commit_block` for
//! each applied block in order (the state trie tracks rehashed nodes for it). History is
//! derived data and never journaled: `open` rebuilds it with `reset` at the recovered head,
//! so proofs for older blocks return as the window refills. A failed history update
//! (`HistoryFull`, a reorg below the window) never fails the operation: history is dropped
//! and rebuilt at the head (`history_drops`). `proof_at` serves `eth_getProof` at any block
//! of the window.
//!
//! Determinism: replay must make the same decisions as the live run. Operations that fail are
//! never journaled, and block retention is decided here (by count, bytes, and transactions,
//! oldest-inserted first) rather than by the chain store's byte ring, whose fragmentation
//! differs between a live store and one rebuilt from a checkpoint. The ring is oversized so
//! it never evicts on its own (see `chain_bytes_capacity`).

const std = @import("std");
const assert = std.debug.assert;

const engine_module = @import("storage/engine.zig");
const journal_module = @import("storage/journal.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const chain_module = @import("chain.zig");
const changeset_module = @import("changeset.zig");
const snapshot_module = @import("snapshot.zig");
const history_module = @import("history.zig");
const trie_module = @import("../trie/root.zig");

const StateTrie = trie_module.StateTrie;
const keccak256 = trie_module.node.keccak256;

pub const Hash = chain_module.Hash;
pub const BlockInput = chain_module.BlockInput;
pub const BlockMeta = chain_module.BlockMeta;
pub const State = state_module.State;
pub const Overlay = overlay_module.Overlay;
pub const ChainStore = chain_module.ChainStore;
pub const Changeset = changeset_module.Changeset;
pub const Metadata = engine_module.Metadata;

// Journal entries.

pub const EntryKind = enum(u8) { block = 1, head = 2, block_and_head = 3 };

/// `block_and_head` has the `block` layout (only the tag differs): insert the block, then
/// move the head to it.
pub const Entry = union(EntryKind) {
    block: BlockInput,
    head: Hash,
    block_and_head: BlockInput,
};

/// Tag, hash, parent hash, number, timestamp, and five u32 lengths.
pub const block_entry_fixed_size: u32 = 1 + 32 + 32 + 8 + 8 + 5 * 4;
pub const head_entry_size: u32 = 1 + 32;

pub const DecodeError = error{InvalidEntry};

pub fn block_entry_size(input: *const BlockInput) u64 {
    return @as(u64, block_entry_fixed_size) + input.header.len + input.body.len +
        input.receipts.len + @as(u64, input.transaction_hashes.len) * 32 + input.changeset.len;
}

const Writer = struct {
    buffer: []u8,
    position: usize = 0,

    fn bytes(writer: *Writer, data: []const u8) void {
        assert(data.len <= writer.buffer.len - writer.position);
        @memcpy(writer.buffer[writer.position..][0..data.len], data);
        writer.position += data.len;
    }

    fn int(writer: *Writer, comptime T: type, value: T) void {
        var scratch: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &scratch, value, .little);
        writer.bytes(&scratch);
    }
};

const Reader = struct {
    buffer: []const u8,
    position: usize = 0,

    fn bytes(reader: *Reader, length: u64) DecodeError![]const u8 {
        if (length > reader.buffer.len - reader.position) return error.InvalidEntry;
        const result = reader.buffer[reader.position..][0..@intCast(length)];
        reader.position += @intCast(length);
        return result;
    }

    fn int(reader: *Reader, comptime T: type) DecodeError!T {
        const data = try reader.bytes(@sizeOf(T));
        return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
    }

    fn hash(reader: *Reader) DecodeError!Hash {
        return (try reader.bytes(32))[0..32].*;
    }
};

/// Encodes a block entry into `out` (at least `block_entry_size` bytes).
pub fn encode_block(input: *const BlockInput, out: []u8) []u8 {
    return encode_block_kind(.block, input, out);
}

/// Encodes a block-and-head entry (the block layout with its own tag).
pub fn encode_block_and_head(input: *const BlockInput, out: []u8) []u8 {
    return encode_block_kind(.block_and_head, input, out);
}

fn encode_block_kind(kind: EntryKind, input: *const BlockInput, out: []u8) []u8 {
    assert(kind == .block or kind == .block_and_head);
    const size = block_entry_size(input);
    assert(out.len >= size);
    assert(input.header.len > 0);
    var writer: Writer = .{ .buffer = out };
    writer.int(u8, @backingInt(kind));
    writer.bytes(&input.hash);
    writer.bytes(&input.parent_hash);
    writer.int(u64, input.number);
    writer.int(u64, input.timestamp);
    writer.int(u32, @intCast(input.header.len));
    writer.int(u32, @intCast(input.body.len));
    writer.int(u32, @intCast(input.receipts.len));
    writer.int(u32, @intCast(input.transaction_hashes.len));
    writer.int(u32, @intCast(input.changeset.len));
    writer.bytes(input.header);
    writer.bytes(input.body);
    writer.bytes(input.receipts);
    for (input.transaction_hashes) |*transaction_hash| writer.bytes(transaction_hash);
    writer.bytes(input.changeset);
    assert(writer.position == size);
    return out[0..writer.position];
}

pub fn encode_head(hash: *const Hash, out: []u8) []u8 {
    assert(out.len >= head_entry_size);
    out[0] = @backingInt(EntryKind.head);
    @memcpy(out[1..33], hash);
    return out[0..head_entry_size];
}

/// Decodes an entry. Slices point into `body`. Rejects anything the encoders would not
/// produce, so every accepted body re-encodes to itself.
pub fn decode_entry(body: []const u8) DecodeError!Entry {
    var reader: Reader = .{ .buffer = body };
    const tag = try reader.int(u8);
    if (tag == @backingInt(EntryKind.head)) {
        const hash = try reader.hash();
        if (reader.position != body.len) return error.InvalidEntry;
        return .{ .head = hash };
    }
    const with_head = tag == @backingInt(EntryKind.block_and_head);
    if (tag != @backingInt(EntryKind.block) and !with_head) return error.InvalidEntry;
    var input: BlockInput = undefined;
    input.hash = try reader.hash();
    input.parent_hash = try reader.hash();
    input.number = try reader.int(u64);
    input.timestamp = try reader.int(u64);
    const header_len = try reader.int(u32);
    const body_len = try reader.int(u32);
    const receipts_len = try reader.int(u32);
    const transactions_len = try reader.int(u32);
    const changeset_len = try reader.int(u32);
    if (header_len == 0) return error.InvalidEntry;
    input.header = try reader.bytes(header_len);
    input.body = try reader.bytes(body_len);
    input.receipts = try reader.bytes(receipts_len);
    const hashes = try reader.bytes(@as(u64, transactions_len) * 32);
    input.transaction_hashes = std.mem.bytesAsSlice(Hash, hashes);
    input.changeset = try reader.bytes(changeset_len);
    if (reader.position != body.len) return error.InvalidEntry;
    assert(block_entry_size(&input) == body.len);
    if (with_head) return .{ .block_and_head = input };
    return .{ .block = input };
}

// Entry metadata: the head and state root after the entry.

pub const HeadInfo = struct {
    present: bool = false,
    number: u64 = 0,
    hash: Hash = @splat(0),
    state_root: Hash = @splat(0),

    pub fn eql(a: HeadInfo, b: HeadInfo) bool {
        return a.present == b.present and a.number == b.number and
            std.mem.eql(u8, &a.hash, &b.hash) and std.mem.eql(u8, &a.state_root, &b.state_root);
    }
};

/// Layout: present u8 at 0, number u64 at 8, head hash at 16, state root at 48, zeros after.
/// A database with no head encodes as all zeros, the engine's metadata after `format`.
pub fn metadata_encode(info: HeadInfo) Metadata {
    var metadata: Metadata = @splat(0);
    if (!info.present) return metadata;
    metadata[0] = 1;
    std.mem.writeInt(u64, metadata[8..16], info.number, .little);
    @memcpy(metadata[16..48], &info.hash);
    @memcpy(metadata[48..80], &info.state_root);
    return metadata;
}

comptime {
    assert(@sizeOf(Metadata) >= 80);
    assert(block_entry_fixed_size == 101);
}

// Checkpoint format.

/// "NFDB" read as a little-endian u32.
pub const checkpoint_magic: u32 = 0x4244_464e;
pub const checkpoint_version: u16 = 1;
/// magic, version, head present, head meta (hash, parent, number, timestamp), state root,
/// snapshot length, block count.
pub const checkpoint_header_size: u32 = 4 + 2 + 1 + 32 + 32 + 8 + 8 + 32 + 4 + 4;

pub const Config = struct {
    engine: engine_module.Config,
    state: state_module.Config,
    /// Retention budget: the newest blocks kept, by count, record bytes, and transactions.
    chain: chain_module.Config,
    changeset: changeset_module.Config,
    /// Entries waiting for the engine.
    queue_entries_max: u32,
    /// Largest serialized checkpoint (snapshot plus retained blocks).
    checkpoint_staging_bytes: u32,
    /// Historical proofs window; null keeps no history (and no trie change tracking).
    history: ?history_module.Config = null,

    /// The chain ring holds the retention budget plus three of the largest records, so it
    /// never has to evict on its own: with live bytes L <= budget - n before inserting n,
    /// a ring of capacity C >= budget + 3 * max(n) always has n contiguous free bytes.
    pub fn chain_bytes_capacity(config: Config) u32 {
        return config.chain.bytes_max + 3 * config.engine.entry_body_size_max;
    }
};

pub const Phase = enum { closed, formatting, opening, ready, failed };

pub const OperationError = error{
    NotReady,
    Busy,
    UnknownParent,
    ParentNotHead,
    BlockTooLarge,
    InvalidChangeset,
    TransactionIndexFull,
} || chain_module.Error || state_module.Error || overlay_module.Error;

pub const OpenError = engine_module.OpenError || error{
    CheckpointInvalid,
    ReplayFailed,
    MetadataMismatch,
};

pub const ProofError = error{
    NotReady,
    /// History is off (not configured, or a rebuild failed) and the block is not the head.
    HistoryUnavailable,
} || history_module.Error;

pub const Commit = struct {
    /// The one entry that inserts the block and moves the head to it.
    sequence: u64,
    state_root: Hash,
};

pub fn DatabaseType(comptime Storage: type) type {
    return struct {
        const Self = @This();

        pub const Engine = engine_module.EngineType(Storage);
        pub const DurableCallback = *const fn (context: ?*anyopaque, sequence: u64) void;

        engine: Engine,
        config: Config,
        state: State,
        chain: ChainStore,
        /// Live reorgs (bounded by `reorg_depth_max`).
        plan: chain_module.ReorgPlan,
        /// Rebuilding the canonical index on load walks every retained block.
        plan_restore: chain_module.ReorgPlan,
        /// Decoded changesets for unwind/apply and validation.
        changeset: Changeset,
        /// The changeset `execute_and_commit` builds, and its encoding.
        changeset_built: Changeset,
        changeset_buffer: []u8,
        queue_bodies: []u8,
        queue_lengths: []u32,
        queue_metadata: []Metadata,
        queue_head: u32 = 0,
        queue_count: u32 = 0,
        staging: []u8,
        staging_len: u32 = 0,
        staging_position: u32 = 0,
        phase: Phase = .closed,
        head_info: HeadInfo = .{},
        /// Sequence of the newest journaled operation (queued, in flight, or durable).
        submitted_sequence: u64 = 0,
        /// Sequence of the newest durable entry.
        durable_sequence: u64 = 0,
        on_durable: ?DurableCallback = null,
        durable_context: ?*anyopaque = null,
        /// Journal bytes of the queued and in-flight entries.
        journal_bytes_pending: u64 = 0,
        in_flight_bytes: u64 = 0,
        checkpoint_wanted: bool = false,
        checkpoints_completed: u64 = 0,
        checkpoint_error: ?anyerror = null,
        retained_bytes: u64 = 0,
        retained_transactions: u64 = 0,
        open_error: ?OpenError = null,
        load_done: bool = false,
        load_error: ?OpenError = null,
        /// Historical proofs (`Config.history`); its window is null until the first head.
        history: ?history_module.Store = null,
        /// Times history was discarded and rebuilt at the head (a failed update).
        history_drops: u64 = 0,
        /// A rebuild at the head failed: history stays off until the next open.
        history_off: bool = false,
        /// The current head move could not update history; rebuild once it ends.
        history_stale: bool = false,

        pub fn init(allocator: std.mem.Allocator, storage: *Storage, config: Config) !Self {
            assert(config.queue_entries_max > 0);
            assert(config.chain.blocks_max > 0 and config.chain.bytes_max > 0);
            assert(config.checkpoint_staging_bytes >= checkpoint_header_size);
            const body_max = config.engine.entry_body_size_max;
            assert(body_max >= block_entry_fixed_size);
            var engine = try Engine.init(allocator, storage, config.engine);
            errdefer engine.deinit(allocator);
            var state = try State.init(allocator, config.state);
            errdefer state.deinit(allocator);
            var chain_config = config.chain;
            chain_config.blocks_max += 1;
            chain_config.bytes_max = config.chain_bytes_capacity();
            var chain = try ChainStore.init(allocator, chain_config);
            errdefer chain.deinit(allocator);
            var plan = try ChainStore.plan_init(allocator, config.chain);
            errdefer ChainStore.plan_deinit(allocator, &plan);
            var restore_config = config.chain;
            restore_config.reorg_depth_max = config.chain.blocks_max + 1;
            var plan_restore = try ChainStore.plan_init(allocator, restore_config);
            errdefer ChainStore.plan_deinit(allocator, &plan_restore);
            var changeset = try Changeset.init(allocator, config.changeset);
            errdefer changeset.deinit(allocator);
            var changeset_built = try Changeset.init(allocator, config.changeset);
            errdefer changeset_built.deinit(allocator);
            var history_store: ?history_module.Store = null;
            if (config.history) |history_config| {
                try state.state_trie.track_changes(allocator);
                history_store = try history_module.Store.init(allocator, history_config);
            }
            errdefer if (history_store) |*store| store.deinit(allocator);
            const buffers = try Buffers.init(allocator, config);
            return .{
                .engine = engine,
                .config = config,
                .state = state,
                .chain = chain,
                .plan = plan,
                .plan_restore = plan_restore,
                .changeset = changeset,
                .changeset_built = changeset_built,
                .changeset_buffer = buffers.changeset_buffer,
                .queue_bodies = buffers.queue_bodies,
                .queue_lengths = buffers.queue_lengths,
                .queue_metadata = buffers.queue_metadata,
                .staging = buffers.staging,
                .history = history_store,
            };
        }

        const Buffers = struct {
            changeset_buffer: []u8,
            queue_bodies: []u8,
            queue_lengths: []u32,
            queue_metadata: []Metadata,
            staging: []u8,

            fn init(allocator: std.mem.Allocator, config: Config) !Buffers {
                const body_max = config.engine.entry_body_size_max;
                const queue_max = config.queue_entries_max;
                const changeset_buffer = try allocator.alloc(u8, body_max);
                errdefer allocator.free(changeset_buffer);
                const queue_bodies = try allocator.alloc(u8, @as(usize, body_max) * queue_max);
                errdefer allocator.free(queue_bodies);
                const queue_lengths = try allocator.alloc(u32, queue_max);
                errdefer allocator.free(queue_lengths);
                const queue_metadata = try allocator.alloc(Metadata, queue_max);
                errdefer allocator.free(queue_metadata);
                const staging = try allocator.alloc(u8, config.checkpoint_staging_bytes);
                return .{
                    .changeset_buffer = changeset_buffer,
                    .queue_bodies = queue_bodies,
                    .queue_lengths = queue_lengths,
                    .queue_metadata = queue_metadata,
                    .staging = staging,
                };
            }
        };

        /// Frees memory. After a simulated crash, engine operations may still be in flight.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.history) |*store| store.deinit(allocator);
            allocator.free(self.staging);
            allocator.free(self.queue_metadata);
            allocator.free(self.queue_lengths);
            allocator.free(self.queue_bodies);
            allocator.free(self.changeset_buffer);
            self.changeset_built.deinit(allocator);
            self.changeset.deinit(allocator);
            ChainStore.plan_deinit(allocator, &self.plan_restore);
            ChainStore.plan_deinit(allocator, &self.plan);
            self.chain.deinit(allocator);
            self.state.deinit(allocator);
            self.engine.deinit(allocator);
            self.* = undefined;
        }

        /// True when nothing is queued and no engine operation is in flight.
        pub fn idle(self: *const Self) bool {
            return self.queue_count == 0 and self.engine.idle();
        }

        /// Writes an empty database. Completes when `phase` returns to `closed`. The caller
        /// then opens it and commits a genesis block with `execute_and_commit`.
        pub fn format(self: *Self, format_id: u128) void {
            assert(self.phase == .closed);
            assert(self.chain.head() == null);
            self.phase = .formatting;
            self.engine.format(format_id, on_format);
        }

        fn on_format(engine: *Engine) void {
            const self: *Self = @alignCast(@fieldParentPtr("engine", engine));
            assert(self.phase == .formatting);
            self.phase = .closed;
        }

        /// Loads the checkpoint and replays the journal. Completes when `phase` is `ready`
        /// (or `closed`/`failed` with `open_error` set). Only for a freshly initialized value.
        pub fn open(self: *Self) void {
            assert(self.phase == .closed);
            assert(self.chain.block_count() == 0);
            assert(self.state.account_table.count() == 0);
            self.phase = .opening;
            self.staging_len = 0;
            self.load_done = false;
            self.load_error = null;
            self.open_error = null;
            self.engine.open(.{
                .context = self,
                .on_checkpoint = consume_checkpoint,
                .on_checkpoint_reset = consume_checkpoint_reset,
                .on_entry = consume_entry,
            }, on_open);
        }

        fn consume_checkpoint(context: *anyopaque, chunk: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening);
            assert(!self.load_done);
            if (chunk.len > self.staging.len - self.staging_len) {
                self.load_error = error.CheckpointInvalid;
                return;
            }
            @memcpy(self.staging[self.staging_len..][0..chunk.len], chunk);
            self.staging_len += @intCast(chunk.len);
        }

        /// The newest checkpoint failed to verify; the engine streams the fallback next.
        fn consume_checkpoint_reset(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening);
            assert(!self.load_done);
            // Staging overflow is the only load error before the first entry.
            self.staging_len = 0;
            self.load_error = null;
        }

        fn consume_entry(context: *anyopaque, entry: engine_module.Entry) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening);
            self.ensure_loaded();
            if (self.load_error != null) return;
            self.replay(entry) catch {
                self.load_error = error.ReplayFailed;
                return;
            };
            if (!std.mem.eql(u8, &metadata_encode(self.head_info), entry.metadata)) {
                self.load_error = error.MetadataMismatch;
            }
        }

        fn replay(self: *Self, entry: engine_module.Entry) !void {
            const decoded = try decode_entry(entry.body);
            switch (decoded) {
                .block => |*input| try self.chain_insert(input),
                .head => |hash| try self.move_head(hash),
                .block_and_head => |*input| {
                    try self.chain_insert(input);
                    try self.move_head(input.hash);
                },
            }
        }

        fn ensure_loaded(self: *Self) void {
            if (self.load_done) return;
            self.load_done = true;
            if (self.load_error != null) return;
            if (self.staging_len == 0) return; // Fresh format: no checkpoint yet.
            self.checkpoint_load() catch {
                self.load_error = error.CheckpointInvalid;
            };
        }

        fn on_open(engine: *Engine) void {
            const self: *Self = @alignCast(@fieldParentPtr("engine", engine));
            assert(self.phase == .opening);
            const result = engine.open_result catch |err| {
                self.open_error = err;
                self.phase = .closed;
                return;
            };
            self.ensure_loaded();
            if (self.load_error == null) {
                const metadata = metadata_encode(self.head_info);
                if (!std.mem.eql(u8, &metadata, &engine.commit_metadata)) {
                    self.load_error = error.MetadataMismatch;
                }
            }
            if (self.load_error) |err| {
                self.open_error = err;
                self.phase = .failed;
                return;
            }
            self.submitted_sequence = result.sequence_last;
            self.durable_sequence = result.sequence_last;
            self.journal_bytes_pending = 0;
            self.phase = .ready;
            assert(self.queue_count == 0);
            if (self.head_info.present) self.history_rebuild();
        }

        // Operations.

        /// Stores a block and journals it. A known block is a no-op that returns the current
        /// sequence. Its parent must be stored unless the chain is empty (genesis).
        pub fn insert_block(self: *Self, input: *const BlockInput) OperationError!u64 {
            const size = block_entry_size(input);
            if (size > self.config.engine.entry_body_size_max) return error.BlockTooLarge;
            try self.check_accepting(1, journal_module.entry_size_bytes(size));
            if (self.chain.meta(input.hash) != null) return self.submitted_sequence;
            try self.insert_check(input);
            try self.chain_insert(input);
            const body = encode_block(input, self.queue_slot());
            return self.queue_push(@intCast(body.len));
        }

        /// The checks `insert_block` makes on a new block before changing anything.
        fn insert_check(self: *Self, input: *const BlockInput) OperationError!void {
            assert(self.chain.meta(input.hash) == null);
            if (self.chain.block_count() > 0) {
                // The parent must stay stored: a block whose parent this very insert evicts
                // could never become canonical.
                const parent = self.fifo_position(input.parent_hash) orelse
                    return error.UnknownParent;
                if (parent < try self.evictions_needed(input)) return error.UnknownParent;
            }
            self.changeset.decode(input.changeset) catch return error.InvalidChangeset;
        }

        /// Moves the canonical head (and State) to a stored block and journals it.
        pub fn set_head(self: *Self, hash: Hash) OperationError!u64 {
            try self.check_accepting(1, journal_module.entry_size_bytes(head_entry_size));
            if (self.head_info.present and std.mem.eql(u8, &self.head_info.hash, &hash)) {
                return self.submitted_sequence;
            }
            try self.move_head(hash);
            assert(std.mem.eql(u8, &self.head_info.hash, &hash));
            const body = encode_head(&hash, self.queue_slot());
            return self.queue_push(@intCast(body.len));
        }

        /// Commits an executed block: builds its changeset from `overlay` (which must sit on
        /// this database's state at the current head), inserts the block with that changeset
        /// (`input.changeset` is ignored), moves the head to it, journals both as one
        /// `block_and_head` entry, and discards the overlay. A block already stored only moves
        /// the head (one `head` entry), like `insert_block` followed by `set_head`.
        pub fn execute_and_commit(
            self: *Self,
            overlay: *Overlay,
            input: *const BlockInput,
        ) OperationError!Commit {
            assert(overlay.base == &self.state);
            if (self.head_info.present) {
                if (!std.mem.eql(u8, &self.head_info.hash, &input.parent_hash)) {
                    return error.ParentNotHead;
                }
            } else if (self.chain.block_count() > 0) return error.ParentNotHead;
            const block = try self.build_block(overlay, input);
            const size = block_entry_size(&block);
            try self.check_accepting(1, journal_module.entry_size_bytes(size));
            const sequence = if (self.chain.meta(block.hash) != null)
                try self.set_head(block.hash)
            else
                try self.insert_and_move_head(&block);
            overlay.discard();
            assert(std.mem.eql(u8, &self.head_info.hash, &block.hash));
            assert(sequence == self.submitted_sequence);
            return .{ .sequence = sequence, .state_root = self.head_info.state_root };
        }

        /// Commits a block the caller executed on this very state and already applied
        /// (`input.changeset` is the changeset it applied on top of the head): inserts the
        /// block and moves the head without touching state, as one `block_and_head` entry.
        /// Replay applies the changeset through the usual path and ends in the same state.
        /// A block already stored only moves the head (re-applying its changeset is
        /// idempotent: changesets carry absolute values).
        pub fn commit_applied(self: *Self, input: *const BlockInput) OperationError!Commit {
            if (!self.head_info.present) return error.ParentNotHead;
            if (!std.mem.eql(u8, &self.head_info.hash, &input.parent_hash)) {
                return error.ParentNotHead;
            }
            const size = block_entry_size(input);
            if (size > self.config.engine.entry_body_size_max) return error.BlockTooLarge;
            try self.check_accepting(1, journal_module.entry_size_bytes(size));
            if (self.chain.meta(input.hash) != null) {
                const sequence = try self.set_head(input.hash);
                return .{ .sequence = sequence, .state_root = self.head_info.state_root };
            }
            try self.insert_check(input);
            try self.chain_insert(input);
            self.chain.plan_reorg(input.hash, &self.plan) catch |err| {
                // Stored in memory: journal it alone so replay stays in step.
                const body = encode_block(input, self.queue_slot());
                _ = self.queue_push(@intCast(body.len));
                return err;
            };
            assert(self.plan.unwind_hashes().len == 0 and self.plan.apply_hashes().len == 1);
            self.chain.set_head(&self.plan);
            self.state.set_block_hash(input.number, input.hash);
            const state_root = self.state.state_root() catch |err| {
                self.phase = .failed;
                return err;
            };
            self.head_info = .{
                .present = true,
                .number = input.number,
                .hash = input.hash,
                .state_root = state_root,
            };
            self.history_commit_head();
            const body = encode_block_and_head(input, self.queue_slot());
            const sequence = self.queue_push(@intCast(body.len));
            return .{ .sequence = sequence, .state_root = state_root };
        }

        /// The block `input` with the changeset built from `overlay` (in `changeset_buffer`).
        fn build_block(
            self: *Self,
            overlay: *Overlay,
            input: *const BlockInput,
        ) OperationError!BlockInput {
            try overlay.build_changeset(&self.changeset_built);
            const changeset_size = self.changeset_built.encoded_length();
            if (changeset_size > self.changeset_buffer.len) return error.BlockTooLarge;
            var block = input.*;
            block.changeset = self.changeset_built.encode(self.changeset_buffer);
            assert(block.changeset.len == changeset_size);
            const size = block_entry_size(&block);
            if (size > self.config.engine.entry_body_size_max) return error.BlockTooLarge;
            return block;
        }

        /// Inserts a new block, moves the head to it, and journals one `block_and_head` entry.
        /// Room was checked by the caller.
        fn insert_and_move_head(self: *Self, block: *const BlockInput) OperationError!u64 {
            assert(self.chain.meta(block.hash) == null);
            try self.insert_check(block);
            try self.chain_insert(block);
            self.move_head(block.hash) catch |err| {
                // The block is stored in memory: journal it alone so replay stays in step.
                // A planning error changed nothing else; a state error failed the database.
                if (self.phase == .ready) {
                    const body = encode_block(block, self.queue_slot());
                    _ = self.queue_push(@intCast(body.len));
                }
                return err;
            };
            assert(std.mem.eql(u8, &self.head_info.hash, &block.hash));
            const body = encode_block_and_head(block, self.queue_slot());
            return self.queue_push(@intCast(body.len));
        }

        /// Asks for a checkpoint; it starts once the queue drains.
        pub fn request_checkpoint(self: *Self) void {
            assert(self.phase == .ready);
            self.checkpoint_wanted = true;
            self.checkpoint_maybe_start();
        }

        fn check_accepting(self: *Self, entries: u32, journal_bytes: u64) OperationError!void {
            if (self.phase != .ready) return error.NotReady;
            assert(self.queue_count <= self.config.queue_entries_max);
            if (self.queue_count + entries > self.config.queue_entries_max) return error.Busy;
            const journal = &self.engine.journal;
            const zone_size = journal.config.zone_size_bytes;
            const used = journal.head - journal.tail + self.journal_bytes_pending;
            assert(journal.head >= journal.tail);
            // One wrap can waste less than one largest entry; pending bytes never exceed a lap.
            const needed = used + journal_bytes + Engine.JournalType.entry_size_max(journal.config);
            if (needed > zone_size) {
                self.checkpoint_wanted = true;
                self.checkpoint_maybe_start();
                return error.Busy;
            }
        }

        fn queue_slot(self: *Self) []u8 {
            assert(self.queue_count < self.config.queue_entries_max);
            const body_max = self.config.engine.entry_body_size_max;
            const index = (self.queue_head + self.queue_count) % self.config.queue_entries_max;
            return self.queue_bodies[@as(usize, index) * body_max ..][0..body_max];
        }

        /// Queues the entry written into `queue_slot()` and starts a commit if none runs.
        fn queue_push(self: *Self, length: u32) u64 {
            assert(length > 0 and length <= self.config.engine.entry_body_size_max);
            const index = (self.queue_head + self.queue_count) % self.config.queue_entries_max;
            self.queue_lengths[index] = length;
            self.queue_metadata[index] = metadata_encode(self.head_info);
            self.queue_count += 1;
            self.submitted_sequence += 1;
            self.journal_bytes_pending += journal_module.entry_size_bytes(length);
            const journal = &self.engine.journal;
            // `used` counts from the fallback checkpoint's start, so it spans the entries of
            // two checkpoints; triggering at half the journal leaves the other half for
            // entries committed while the checkpoint runs, and in steady state each
            // checkpoint covers about a quarter of the journal.
            const used = journal.head - journal.tail + self.journal_bytes_pending;
            if (used * 2 > journal.config.zone_size_bytes) self.checkpoint_wanted = true;
            self.pump();
            return self.submitted_sequence;
        }

        fn pump(self: *Self) void {
            if (self.phase != .ready or self.queue_count == 0) return;
            if (self.engine.commit_callback != null) return;
            const index = self.queue_head;
            const body_max = self.config.engine.entry_body_size_max;
            const length = self.queue_lengths[index];
            const body = self.queue_bodies[@as(usize, index) * body_max ..][0..length];
            const metadata = &self.queue_metadata[index];
            const sequence = self.engine.commit(body, metadata, on_commit) catch |err|
                switch (err) {
                    // Admission keeps room for every queued entry; a checkpoint frees more.
                    error.JournalFull => {
                        self.checkpoint_wanted = true;
                        return;
                    },
                    // Ready and no commit in flight, both checked above.
                    error.NotReady, error.Busy => unreachable,
                };
            assert(sequence == self.durable_sequence + 1);
            // The journal copied the body: the slot is free.
            self.in_flight_bytes = journal_module.entry_size_bytes(length);
            self.queue_head = (self.queue_head + 1) % self.config.queue_entries_max;
            self.queue_count -= 1;
        }

        fn on_commit(engine: *Engine) void {
            const self: *Self = @alignCast(@fieldParentPtr("engine", engine));
            assert(self.phase == .ready);
            self.durable_sequence += 1;
            assert(self.durable_sequence == engine.sequence_last());
            assert(self.durable_sequence <= self.submitted_sequence);
            self.journal_bytes_pending -= self.in_flight_bytes;
            self.in_flight_bytes = 0;
            if (self.on_durable) |callback| callback(self.durable_context, self.durable_sequence);
            self.checkpoint_maybe_start();
            self.pump();
        }

        // State and chain transitions, shared by live operations and replay.

        /// Inserts into the chain store, evicting the oldest blocks to stay in budget.
        fn chain_insert(self: *Self, input: *const BlockInput) OperationError!void {
            if (self.chain.meta(input.hash) != null) return;
            const evictions = try self.evictions_needed(input);
            for (0..evictions) |_| self.evict_oldest();
            const count_before = self.chain.block_count();
            // The size errors were checked by `evictions_needed`, and the ring is oversized so
            // it never needs space it does not have (see `Config.chain_bytes_capacity`).
            self.chain.insert(input) catch unreachable;
            assert(self.chain.block_count() == count_before + 1);
            self.retained_bytes += record_length(input);
            self.retained_transactions += input.transaction_hashes.len;
        }

        /// How many of the oldest blocks inserting `input` evicts.
        fn evictions_needed(self: *const Self, input: *const BlockInput) OperationError!u32 {
            const budget = &self.config.chain;
            const length = record_length(input);
            const transactions = input.transaction_hashes.len;
            if (length > budget.bytes_max) return error.BlockTooLarge;
            if (transactions > budget.transactions_max) return error.TransactionIndexFull;
            var count = self.chain.block_count();
            var bytes = self.retained_bytes;
            var transactions_retained = self.retained_transactions;
            var evictions: u32 = 0;
            while (count == budget.blocks_max or bytes + length > budget.bytes_max or
                transactions_retained + transactions > budget.transactions_max)
            {
                assert(evictions < self.chain.block_count());
                const slot = self.fifo_slot(evictions);
                bytes -= slot_length(slot);
                transactions_retained -= slot.transactions_len;
                count -= 1;
                evictions += 1;
            }
            assert(count < budget.blocks_max);
            return evictions;
        }

        fn fifo_slot(self: *const Self, position: u32) *const @TypeOf(self.chain.slots[0]) {
            assert(position < self.chain.block_count());
            const capacity: u32 = @intCast(self.chain.slots.len);
            return &self.chain.slots[(self.chain.slot_head + position) % capacity];
        }

        /// FIFO position (0 is the oldest) of a stored block.
        fn fifo_position(self: *const Self, hash: Hash) ?u32 {
            const index = self.chain.by_hash.get(hash) orelse return null;
            const capacity: u32 = @intCast(self.chain.slots.len);
            const position = (index + capacity - self.chain.slot_head) % capacity;
            assert(position < self.chain.block_count());
            return position;
        }

        fn evict_oldest(self: *Self) void {
            assert(self.chain.block_count() > 0);
            const slot = self.fifo_slot(0);
            const length = slot_length(slot);
            assert(self.retained_bytes >= length);
            assert(self.retained_transactions >= slot.transactions_len);
            self.retained_bytes -= length;
            self.retained_transactions -= slot.transactions_len;
            self.chain.evict_oldest();
        }

        /// Plans and performs a head move. A planning error changes nothing; a state error
        /// in the middle leaves the database `failed`.
        fn move_head(self: *Self, hash: Hash) OperationError!void {
            try self.chain.plan_reorg(hash, &self.plan);
            self.move_state() catch |err| {
                self.phase = .failed;
                return err;
            };
            self.chain.set_head(&self.plan);
            const head_meta = self.chain.head().?;
            assert(std.mem.eql(u8, &head_meta.hash, &hash));
            const state_root = self.state.state_root() catch |err| {
                self.phase = .failed;
                return err;
            };
            self.head_info = .{
                .present = true,
                .number = head_meta.number,
                .hash = head_meta.hash,
                .state_root = state_root,
            };
            self.history_settle();
        }

        fn move_state(self: *Self) OperationError!void {
            assert(!self.history_stale);
            const store = self.history_tracking();
            // The first head also applies the block the walk stopped at (genesis).
            if (self.chain.head() == null) try self.apply_block(self.plan.ancestor.hash);
            for (self.plan.unwind_hashes()) |hash| {
                const view = self.chain.block(hash).?;
                self.changeset.decode(view.changeset) catch return error.InvalidChangeset;
                try self.state.unwind(&self.changeset);
            }
            if (store) |tracked| if (self.plan.unwind_len > 0) {
                tracked.unwind_to(self.plan.ancestor.number) catch {
                    self.history_stale = true;
                };
            };
            for (self.plan.apply_hashes()) |hash| {
                try self.apply_block(hash);
                const tracked = store orelse continue;
                if (self.history_stale) continue;
                const number = self.chain.meta(hash).?.number;
                tracked.commit_block(&self.state.state_trie, number) catch {
                    self.history_stale = true;
                };
            }
        }

        fn apply_block(self: *Self, hash: Hash) OperationError!void {
            const view = self.chain.block(hash).?;
            self.changeset.decode(view.changeset) catch return error.InvalidChangeset;
            try self.state.apply(&self.changeset);
            self.state.set_block_hash(view.meta.number, hash);
        }

        // History.

        /// History at the head for readers (`witness_block`): null when history is not
        /// configured, off, or not initialized. Valid until the next head move.
        pub fn history_reader(self: *Self) ?*const history_module.Store {
            if (!self.head_info.present) return null;
            const store = self.history_tracking() orelse return null;
            assert(store.window().?.head == self.head_info.number);
            return store;
        }

        /// The store when live head moves update it: ready, configured, on, and initialized.
        fn history_tracking(self: *Self) ?*history_module.Store {
            if (self.phase != .ready or self.history_off) return null;
            const store = if (self.history) |*store| store else return null;
            if (store.window() == null) return null;
            assert(self.state.state_trie.accounts.changed.len > 0);
            return store;
        }

        /// After a head move: history is at the head, or it is rebuilt there.
        fn history_settle(self: *Self) void {
            assert(self.head_info.present);
            const stale = self.history_stale;
            self.history_stale = false;
            if (self.phase != .ready or self.history_off) return;
            const store = if (self.history) |*store| store else return;
            if (store.window()) |window| {
                if (!stale) {
                    assert(window.head == self.head_info.number);
                    return;
                }
                self.history_drops += 1;
            }
            self.history_rebuild();
        }

        /// `commit_applied` moved the head one block without `move_state`.
        fn history_commit_head(self: *Self) void {
            assert(!self.history_stale);
            if (self.history_tracking()) |store| {
                const number = self.head_info.number;
                store.commit_block(&self.state.state_trie, number) catch {
                    self.history_stale = true;
                };
            }
            self.history_settle();
        }

        /// Drops all history and records the head state as the only block of the window.
        /// A failure leaves history off until the next open (never fails the database).
        fn history_rebuild(self: *Self) void {
            assert(self.phase == .ready and self.head_info.present);
            const store = if (self.history) |*store| store else return;
            self.history_off = false;
            store.reset(&self.state.state_trie, self.head_info.number) catch {
                self.history_off = true;
                return;
            };
            assert(store.window().?.head == self.head_info.number);
        }

        /// `eth_getProof` at block `number`: the account proof, one storage proof and value
        /// per slot, and the account (null when absent), from history for any block of its
        /// window. Without history only the head is served (from the live trie).
        pub fn proof_at(
            self: *Self,
            number: u64,
            address: history_module.Address,
            slots: []const u256,
            account_proof: *StateTrie.AccountProof,
            storage_proofs: []StateTrie.StorageProof,
            values: []u256,
        ) ProofError!?history_module.AccountState {
            assert(slots.len == storage_proofs.len and slots.len == values.len);
            if (self.phase != .ready or !self.head_info.present) return error.NotReady;
            if (self.history_tracking()) |store| {
                const proofs = storage_proofs;
                return store.get_proof(number, address, slots, account_proof, proofs, values);
            }
            if (number != self.head_info.number) return error.HistoryUnavailable;
            return self.proof_live(address, slots, account_proof, storage_proofs, values);
        }

        fn proof_live(
            self: *Self,
            address: history_module.Address,
            slots: []const u256,
            account_proof: *StateTrie.AccountProof,
            storage_proofs: []StateTrie.StorageProof,
            values: []u256,
        ) ProofError!?history_module.AccountState {
            const state_trie = &self.state.state_trie;
            const address_hash = keccak256(&address);
            try state_trie.prove_account(address_hash, account_proof);
            for (slots, storage_proofs, values) |slot, *proof, *value| {
                var slot_bytes: [32]u8 = undefined;
                std.mem.writeInt(u256, &slot_bytes, slot, .big);
                state_trie.prove_storage(address_hash, keccak256(&slot_bytes), proof);
                value.* = self.state.storage(address, slot);
            }
            const info = self.state.basic(address) orelse return null;
            return .{
                .nonce = info.nonce,
                .balance = info.balance,
                .storage_root = state_trie.storage_root(address_hash),
                .code_hash = info.code_hash,
            };
        }

        // Checkpoints.

        fn checkpoint_maybe_start(self: *Self) void {
            if (!self.checkpoint_wanted or self.phase != .ready) return;
            if (self.queue_count > 0 or self.engine.commit_callback != null) return;
            if (self.engine.checkpoint_phase != .idle) return;
            self.checkpoint_wanted = false;
            self.staging_len = self.checkpoint_write() catch |err| {
                self.checkpoint_error = err;
                return;
            };
            self.staging_position = 0;
            const producer: engine_module.Producer = .{ .context = self, .produce = produce };
            // Ready, no commit in flight, and no checkpoint running: checked above.
            self.engine.checkpoint(producer, on_checkpoint) catch unreachable;
        }

        fn produce(context: *anyopaque, buffer: []u8) u32 {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.staging_position <= self.staging_len);
            const remaining = self.staging_len - self.staging_position;
            const chunk: u32 = @intCast(@min(remaining, buffer.len));
            @memcpy(buffer[0..chunk], self.staging[self.staging_position..][0..chunk]);
            self.staging_position += chunk;
            return chunk;
        }

        fn on_checkpoint(engine: *Engine) void {
            const self: *Self = @alignCast(@fieldParentPtr("engine", engine));
            assert(self.phase == .ready);
            if (engine.checkpoint_result) |_| {
                self.checkpoints_completed += 1;
            } else |err| self.checkpoint_error = err;
            self.pump();
            self.checkpoint_maybe_start();
        }

        /// Serializes header, state snapshot, and retained blocks into the staging buffer.
        fn checkpoint_write(self: *Self) !u32 {
            assert(self.queue_count == 0);
            var sink: snapshot_module.BufferSink = .{
                .buffer = self.staging[checkpoint_header_size..],
            };
            try snapshot_module.write(&self.state, &sink);
            const snapshot_len: u32 = @intCast(sink.position);
            var position: usize = checkpoint_header_size + snapshot_len;
            const count = self.chain.block_count();
            for (0..count) |index| {
                const input = self.stored_block(@intCast(index));
                const size = block_entry_size(&input);
                if (4 + size > self.staging.len - position) return error.CheckpointTooLarge;
                std.mem.writeInt(u32, self.staging[position..][0..4], @intCast(size), .little);
                _ = encode_block(&input, self.staging[position + 4 ..]);
                position += 4 + size;
            }
            self.checkpoint_write_header(snapshot_len, count);
            assert(position <= self.staging.len);
            return @intCast(position);
        }

        fn checkpoint_write_header(self: *Self, snapshot_len: u32, block_count: u32) void {
            var writer: Writer = .{ .buffer = self.staging[0..checkpoint_header_size] };
            writer.int(u32, checkpoint_magic);
            writer.int(u16, checkpoint_version);
            const head_meta = self.chain.head() orelse BlockMeta{
                .hash = @splat(0),
                .parent_hash = @splat(0),
                .number = 0,
                .timestamp = 0,
            };
            assert(self.chain.head() != null or !self.head_info.present);
            writer.int(u8, @intFromBool(self.head_info.present));
            writer.bytes(&head_meta.hash);
            writer.bytes(&head_meta.parent_hash);
            writer.int(u64, head_meta.number);
            writer.int(u64, head_meta.timestamp);
            writer.bytes(&self.head_info.state_root);
            writer.int(u32, snapshot_len);
            writer.int(u32, block_count);
            assert(writer.position == checkpoint_header_size);
        }

        /// The stored block at FIFO `position` (0 is the oldest), as an insert input.
        fn stored_block(self: *const Self, position: u32) BlockInput {
            const slot = self.fifo_slot(position);
            const view = self.chain.block(slot.meta.hash).?;
            const offset = slot.offset + slot.header_len + slot.body_len + slot.receipts_len;
            const hashes = self.chain.bytes[offset..][0 .. slot.transactions_len * 32];
            return .{
                .hash = slot.meta.hash,
                .parent_hash = slot.meta.parent_hash,
                .number = slot.meta.number,
                .timestamp = slot.meta.timestamp,
                .header = view.header,
                .body = view.body,
                .receipts = view.receipts,
                .transaction_hashes = std.mem.bytesAsSlice(Hash, hashes),
                .changeset = view.changeset,
            };
        }

        /// Loads the staged checkpoint: state snapshot, blocks, then the canonical head.
        fn checkpoint_load(self: *Self) !void {
            const bytes = self.staging[0..self.staging_len];
            var reader: Reader = .{ .buffer = bytes };
            if (try reader.int(u32) != checkpoint_magic) return error.CheckpointInvalid;
            if (try reader.int(u16) != checkpoint_version) return error.CheckpointInvalid;
            const present = try reader.int(u8);
            if (present > 1) return error.CheckpointInvalid;
            const head_meta: BlockMeta = .{
                .hash = try reader.hash(),
                .parent_hash = try reader.hash(),
                .number = try reader.int(u64),
                .timestamp = try reader.int(u64),
            };
            const state_root = try reader.hash();
            const snapshot_len = try reader.int(u32);
            const block_count = try reader.int(u32);
            if (block_count > self.config.chain.blocks_max) return error.CheckpointInvalid;
            var source: snapshot_module.BufferSource = .{
                .buffer = try reader.bytes(snapshot_len),
            };
            try snapshot_module.load(&self.state, &source);
            if (source.position != snapshot_len) return error.CheckpointInvalid;
            for (0..block_count) |_| {
                const size = try reader.int(u32);
                const entry = try decode_entry(try reader.bytes(size));
                if (entry != .block) return error.CheckpointInvalid;
                if (self.chain.meta(entry.block.hash) != null) return error.CheckpointInvalid;
                try self.chain_insert(&entry.block);
            }
            if (reader.position != bytes.len) return error.CheckpointInvalid;
            if (self.chain.block_count() != block_count) return error.CheckpointInvalid;
            if (present == 1) try self.restore_head(head_meta);
            const root = try self.state.state_root();
            if (!std.mem.eql(u8, &root, &state_root)) return error.CheckpointInvalid;
            self.head_info = .{
                .present = present == 1,
                .number = head_meta.number,
                .hash = head_meta.hash,
                .state_root = state_root,
            };
        }

        /// Rebuilds the canonical index without touching state (the snapshot has it).
        fn restore_head(self: *Self, head_meta: BlockMeta) !void {
            assert(self.chain.head() == null);
            if (self.chain.meta(head_meta.hash)) |stored| {
                if (stored.number != head_meta.number) return error.CheckpointInvalid;
                try self.chain.plan_reorg(head_meta.hash, &self.plan_restore);
                assert(self.plan_restore.unwind_len == 0);
                self.chain.set_head(&self.plan_restore);
            } else {
                // The head block itself was evicted; only its metadata survives.
                self.chain.head_meta = head_meta;
            }
            assert(self.chain.head() != null);
        }
    };
}

fn record_length(input: *const BlockInput) u64 {
    return @as(u64, input.header.len) + input.body.len + input.receipts.len +
        @as(u64, input.transaction_hashes.len) * 32 + input.changeset.len;
}

fn slot_length(slot: anytype) u64 {
    return @as(u64, slot.header_len) + slot.body_len + slot.receipts_len +
        @as(u64, slot.transactions_len) * 32 + slot.changeset_len;
}

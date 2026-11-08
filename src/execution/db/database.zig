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
//! the engine writes them in group commits: every entry queued while a commit was in flight
//! goes into the next one write and one sync (`Engine.commit_batch`), so the sync rate does
//! not bound the block rate; `durable_sequence` (and the optional `on_durable` callback)
//! reports how far the journal is durable. A full queue, or a journal without room
//! for the entry, returns `error.Busy`: tick the storage and retry.
//!
//! Checkpoints serialize the state snapshot, every stored block (oldest first, as block
//! entries), and the canonical head into a staging buffer, then stream it to the engine. A
//! checkpoint only starts when the queue is empty and no commit is in flight, so it covers
//! exactly the entries the engine committed before it; later operations proceed while the
//! frozen staging buffer streams out. `open` loads the checkpoint and replays the journal
//! through the same code paths without journaling again, then checks the result against the
//! last entry's metadata (head number, head hash, state root).
//! Incremental checkpoints (`Config.checkpoint_bytes_per_commit`): the staging buffer is
//! still serialized at once (it must be the state at one point), but the engine writes at
//! most that many bytes of it per durable commit (`Engine.checkpoint_paced`, granted again
//! in every commit callback), so no single commit's sync has to flush the whole image. If
//! the journal runs out of room while a paced checkpoint runs, the pacing is lifted
//! (`checkpoint_flush`) so the checkpoint finishes and frees the journal.
//! If the newest checkpoint is rotten, the engine resets the staged bytes, streams the older
//! fallback checkpoint instead, and replays the longer journal kept since it.
//! Code tables (with a grid, `engine.grid_block_count > 0`; `code_store.zig`): before each
//! checkpoint the codes added since the last one are flushed into sorted grid tables (paced
//! on the same per-commit block budget), and the checkpoint (version 2) carries the table
//! list plus only the codes no table holds. `open` uses the engine's open pause: it decodes
//! the table list, scans the tables into `State.code_arena`, loads the image, and resumes the
//! journal. Codes stay resident, so `State.code_by_hash` is unchanged, unless
//! `Config.code_pin_bytes` is set: then the scan keeps only where each code is and a read
//! copies it from its table, valid until `codes_release`. Without a grid the checkpoint is
//! version 1 with every code, as before.
//! Flat trees (`Config.flat_trees`, needs a grid; `flat_trees.zig`): every head move also
//! writes its unwound changesets' old values and applied changesets' new values into an
//! account tree and a storage tree (shadow writes: `State` stays the source of truth), with
//! each account record's storage root read from `State`'s trie right after the move (and a
//! record for every address whose only change was storage). Two branch-record trees are
//! written only by a bulk import (`FlatTrees.bulk_begin`). Their compaction is granted the
//! same per-commit block budget as the code flush; the checkpoint (version 4) carries the
//! four trees after the code table list; open decodes and scans them in the open pause and
//! replay re-applies the puts through the replay reserve. Version 3 (72-byte account
//! records, two trees) is refused.
//! A checkpoint waits until both trees are `checkpoint_ready` (a replay that filled into the
//! reserve while a flush was pending: the flush runs unpaced and installs first), so the next
//! replay always has a full reserve.
//! Disk mode (`Config.disk_state`, needs flat trees, no history): `State` dispatches accounts,
//! slots, the root, and every apply and unwind to a `DiskState` over the four flat trees
//! (`state.zig`), so head moves write the trees through `State` and there is no shadow write.
//! A live head move first reserves the account and storage puts as above plus
//! `record_writes_max` branch puts per block per branch tree; the branch trees hold one
//! largest move above their flush trigger (`branch_operation_entries`), so a refused move
//! always fits once the memtables swap. Replay cannot compact, so the branch trees also keep a
//! replay reserve (`replay_record_writes_max`), and admission keeps the branch writes the
//! journal can replay within it: the writes since the fallback checkpoint's snapshot (counted
//! per checkpoint interval, the last closed one carried in the checkpoint) plus the move's
//! bound must fit, or the operation is `error.Busy` and a checkpoint is wanted. The
//! checkpoint (version 5) is version 4 plus that count, with no account or slot image (the
//! snapshot keeps codes no table holds and block hashes); open restores the root from the
//! head's state root and checks that its root record resolves to it. `import_head` makes a
//! bulk-imported state the head of an empty database.
//!
//! Historical proofs (optional, `Config.history`): the database owns a `history.Store` and
//! updates it on every live head move: `unwind_to` the fork point, then `commit_block` for
//! each applied block in order (the state trie tracks rehashed nodes for it). History is
//! derived data and never journaled: `open` rebuilds the window from the retained canonical
//! blocks (`history_rebuild_window`, `Config.history_rebuild_on_open`): it unwinds State in
//! memory down to the oldest block the window and retention allow, `reset`s history there,
//! and re-applies the blocks with `commit_block`, ending at the recovered head and root.
//! Under a byte budget it first tries from the window the budget is estimated to keep, and
//! re-applies the whole window only when that try's window did not shrink past its start.
//! A failed history update (`HistoryFull`, a reorg below the window) never fails the
//! operation: history is dropped and rebuilt at the head (`history_drops`). `proof_at`
//! serves `eth_getProof` at any block of the window.
//!
//! Determinism: replay must make the same decisions as the live run. Operations that fail are
//! never journaled, and block retention is decided here (by count, bytes, and transactions,
//! oldest-inserted first) rather than by the chain store's byte ring, whose fragmentation
//! differs between a live store and one rebuilt from a checkpoint. The ring is oversized so
//! it never evicts on its own (see `chain_bytes_capacity`).

const std = @import("std");
const assert = std.debug.assert;
const lazy = @import("../../utilities/lazy_alloc/root.zig");

const engine_module = @import("storage/engine.zig");
const journal_module = @import("storage/journal.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const chain_module = @import("chain.zig");
const changeset_module = @import("changeset.zig");
const snapshot_module = @import("snapshot.zig");
const history_module = @import("history.zig");
const code_store_module = @import("code_store.zig");
const flat_trees_module = @import("flat_trees.zig");
const disk_state_module = @import("disk_state.zig");
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
/// Version 1: header, snapshot, blocks (no grid). Version 2 (with a grid): the code table
/// list (`CodeStore.manifest_encode`) follows the header, and the snapshot carries only
/// the codes no table holds.
pub const checkpoint_version: u16 = 1;
pub const checkpoint_version_tables: u16 = 2;
/// Version 4 (flat trees on): version 2 with the flat trees' bytes
/// (`FlatTrees.checkpoint_encode`: account, storage, and both branch trees) right after the
/// code table list. Version 3 (account records without the storage root, two trees) is
/// refused: no migration, the datadir is formatted again.
pub const checkpoint_version_flat: u16 = 4;
pub const checkpoint_version_flat_v3: u16 = 3;
/// Version 5 (disk mode): version 4 with the branch writes of the checkpoint interval it
/// closes (u64, after the flat trees' bytes), and a snapshot without accounts or slots.
pub const checkpoint_version_disk: u16 = 5;

/// Whether a checkpoint of `version` opens with the given config (`flat` trees on, a
/// `grid`, `disk` mode): version 1 (no tables) only without flat trees, version 2 only with
/// a grid and without flat trees, version 4 only with flat trees outside disk mode, version 5
/// only in disk mode; version 3 never.
pub fn checkpoint_version_valid(version: u16, flat: bool, grid: bool, disk: bool) bool {
    assert(!flat or grid);
    assert(!disk or flat);
    return switch (version) {
        checkpoint_version => !flat,
        checkpoint_version_tables => grid and !flat,
        checkpoint_version_flat => flat and !disk,
        checkpoint_version_disk => disk,
        else => false,
    };
}
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
    checkpoint_staging_bytes: u64,
    /// Checkpoint bytes written per durable commit (rounded up to whole checkpoint blocks);
    /// 0 writes a checkpoint as fast as the storage allows. Choose it so a whole checkpoint
    /// (`checkpoint_staging_bytes`) finishes within the commits that fit in half the journal;
    /// otherwise a full journal lifts the pacing and that commit waits for the rest.
    checkpoint_bytes_per_commit: u32 = 0,
    /// Historical proofs window; null keeps no history (and no trie change tracking).
    history: ?history_module.Config = null,
    /// With history on, `open` rebuilds the window from the retained blocks' changesets
    /// (one unwind, apply, state root, and history commit per block, at most one window,
    /// plus one `reset` of the whole state) instead of restarting it at the head.
    history_rebuild_on_open: bool = true,
    /// Code tables on the grid (`code_store.zig`), on when `engine.grid_block_count > 0`:
    /// the most tables the list holds before every code is rewritten into fresh ones.
    code_tables_max: u32 = 16,
    /// New code bytes since the last flush below which a checkpoint skips the flush and
    /// carries those codes in its image (fewer small tables, fewer rewrites).
    code_flush_bytes_min: u32 = 64 * 1024,
    /// Codes out of RAM (`code_store.zig` pinned mode; needs a grid) when non-zero: open
    /// keeps only where each table code is, and `State.code_by_hash` reads it from its
    /// table, pinned until `codes_release`. Bytes and codes pinned at once (size them for
    /// one block's codes), and the code tables' own block cache.
    code_pin_bytes: u64 = 0,
    code_pins_max: u32 = 0,
    code_cache_blocks: u32 = 0,
    /// Shadow-write committed changesets into flat account and storage trees on the grid
    /// (`flat_trees.zig`); needs a grid. Off: nothing changes (checkpoint version 2).
    /// A database opens only with the setting it was written with (no backfill yet).
    flat_trees: bool = false,
    /// Mutable memtable entries at which a flat tree flushes.
    flat_flush_entries_min: u32 = 16 * 1024,
    /// Block cache blocks the flat trees' lookups share.
    flat_cache_blocks: u32 = 64,
    /// Keys one flat-tree prefetch names and its reads in flight (`prefetch.zig`); 0: none.
    flat_prefetch_keys_max: u32 = 0,
    flat_prefetch_reads_max: u32 = 0,
    /// Live keys the flat trees size their levels for (independent of `state`, which sizes
    /// RAM tables); null: `state.accounts_max` / `state.storage_slots_max`.
    flat_accounts_max: ?u64 = null,
    flat_slots_max: ?u64 = null,
    /// Branch records per branch tree at most; null: the account (slot) limit (a trie of n
    /// leaves has fewer than n branches).
    flat_account_branches_max: ?u64 = null,
    flat_storage_branches_max: ?u64 = null,
    /// Mutable memtable entries at which a branch tree flushes (entries ~1.1 KiB each).
    flat_branch_flush_entries_min: u32 = 1024,
    /// Disk mode (needs `flat_trees`, no `history`); null keeps state in RAM.
    disk_state: ?DiskStateConfig = null,

    /// Head-move blocks one live operation moves State by at most: the reorg plan's unwinds
    /// and applies, plus the first head's oldest walked block.
    pub fn move_blocks_max(config: Config) u64 {
        return 2 * @as(u64, config.chain.reorg_depth_max) + 1;
    }

    /// `DiskState`'s config, null outside disk mode.
    pub fn disk_state_config(config: Config) ?disk_state_module.Config {
        const disk = config.disk_state orelse return null;
        assert(config.flat_trees and config.history == null);
        assert(disk.record_writes_max > 0);
        // One largest move always fits the replay reserve once the journal is clear.
        assert(disk.replay_record_writes_max >= disk.record_writes_max * config.move_blocks_max());
        return .{
            .trie_nodes_max = disk.trie_nodes_max,
            .storage_tries_max = disk.storage_tries_max,
            .memo_entries_max = disk.memo_entries_max,
            .memo_bytes_max = disk.memo_bytes_max,
            .record_writes_max = disk.record_writes_max,
            .record_write_bytes_max = disk.record_write_bytes_max,
            .changeset = config.changeset,
            .record_cache_entries = disk.record_cache_entries,
            .read_memo_accounts_max = disk.read_memo_accounts_max,
            .read_memo_slots_max = disk.read_memo_slots_max,
        };
    }

    /// The flat trees' config, null when off.
    pub fn flat_trees_config(config: Config) ?flat_trees_module.Config {
        if (!config.flat_trees) return null;
        assert(config.engine.grid_block_count > 0);
        const accounts_max = config.flat_accounts_max orelse config.state.accounts_max;
        const slots_max = config.flat_slots_max orelse config.state.storage_slots_max;
        return .{
            .block_size = config.engine.checkpoint_block_size,
            .block_count = config.engine.grid_block_count,
            .journal_bytes = config.engine.journal_size_bytes,
            .chain_bytes = config.chain.bytes_max,
            .entry_body_bytes = config.engine.entry_body_size_max,
            .accounts_max = accounts_max,
            .slots_max = slots_max,
            .account_branches_max = config.flat_account_branches_max orelse accounts_max,
            .storage_branches_max = config.flat_storage_branches_max orelse slots_max,
            .flush_entries_min = config.flat_flush_entries_min,
            .branch_flush_entries_min = config.flat_branch_flush_entries_min,
            .branch_operation_entries = if (config.disk_state) |disk|
                @intCast(disk.record_writes_max * config.move_blocks_max())
            else
                0,
            .branch_replay_entries = if (config.disk_state) |disk|
                disk.replay_record_writes_max
            else
                0,
            .cache_blocks = config.flat_cache_blocks,
            .prefetch_keys_max = config.flat_prefetch_keys_max,
            .prefetch_reads_max = config.flat_prefetch_reads_max,
        };
    }

    /// The code store's config, null without a grid.
    pub fn code_store_config(config: Config) ?code_store_module.Config {
        if (config.engine.grid_block_count == 0) return null;
        return .{
            .block_size = config.engine.checkpoint_block_size,
            .block_count = config.engine.grid_block_count,
            .tables_max = config.code_tables_max,
            .codes_max = config.state.codes_max,
            .code_bytes_max = config.state.code_bytes_max,
            .flush_bytes_min = config.code_flush_bytes_min,
            .pin_bytes = config.code_pin_bytes,
            .pins_max = config.code_pins_max,
            .cache_blocks = config.code_cache_blocks,
        };
    }

    /// The chain ring holds the retention budget plus three of the largest records, so it
    /// never has to evict on its own: with live bytes L <= budget - n before inserting n,
    /// a ring of capacity C >= budget + 3 * max(n) always has n contiguous free bytes.
    pub fn chain_bytes_capacity(config: Config) u32 {
        return config.chain.bytes_max + 3 * config.engine.entry_body_size_max;
    }

    /// Checkpoint blocks granted per durable commit (`maxInt` when not paced).
    pub fn checkpoint_blocks_per_commit(config: Config) u64 {
        if (config.checkpoint_bytes_per_commit == 0) return std.math.maxInt(u64);
        const block_size = config.engine.checkpoint_block_size;
        assert(block_size > 0);
        // block_size > 0, asserted above.
        return std.math.divCeil(u64, config.checkpoint_bytes_per_commit, block_size) catch
            unreachable;
    }
};

/// Disk mode (`Config.disk_state`): `DiskState`'s per-block bounds and the branch trees'
/// replay reserve.
pub const DiskStateConfig = struct {
    /// Sparse trie nodes, storage tries, and locator memo entries and bytes per block.
    trie_nodes_max: u32,
    storage_tries_max: u32,
    memo_entries_max: u32,
    memo_bytes_max: u32,
    /// Branch-record writes (puts and tombstones, both trees) and their bytes per block; a
    /// block that makes more is refused (`StateFull`).
    record_writes_max: u32,
    record_write_bytes_max: u32,
    /// Branch-record writes the journal since the fallback checkpoint may replay (each
    /// branch tree's replay reserve); at least one largest move's bound.
    replay_record_writes_max: u32,
    /// Branch records `DiskState` keeps across blocks (`record_cache.zig`, ~1.1 KiB each).
    record_cache_entries: u32 = disk_state_module.record_cache_entries_default,
    /// Account records and slots `DiskState` remembers between a block's reads and its
    /// write-back (`DiskState.Config`).
    read_memo_accounts_max: u32 = 4096,
    read_memo_slots_max: u32 = 16 * 1024,
};

/// Grid blocks for the code tables of `state` (the node default): four times the blocks
/// all codes fill (the live tables; a rewrite's released tables waiting two checkpoints for
/// reuse; and a rewrite's reservation, which assumes half-full data blocks), plus 64 spare.
/// A flush that still finds no room is skipped and its codes stay in the image.
pub fn code_grid_block_count(state: state_module.Config, block_size: u32) u64 {
    const payload = @import("storage/grid.zig").payload_capacity_of(block_size);
    assert(payload > 0);
    const blocks = std.math.divCeil(u64, state.code_bytes_max, payload) catch unreachable;
    return 4 * blocks + 64;
}

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

/// Steps of `open`, reported to `OpenTrace` as each one ends (in this order; history steps
/// only with history on and a head). Library code never reads the clock: the caller does.
pub const OpenStep = enum(u8) {
    /// The engine read the superblock and streamed (and verified) the checkpoint.
    checkpoint_read,
    /// Code tables the checkpoint names read into the code arena (during the engine's open
    /// pause; immediate without tables).
    code_tables,
    /// Snapshot decoded into the flat tables (the incremental path also builds the trie).
    snapshot_tables,
    /// State trie built from the flat tables (bulk path only).
    snapshot_trie,
    /// State root computed and checked against the snapshot.
    snapshot_root,
    /// Retained blocks inserted and the canonical head restored.
    blocks,
    /// Journal read and replayed; the metadata checked.
    replay,
    /// History rebuild: State unwound to the window start (the flat tables only when the
    /// trie is rebuilt next).
    history_unwind,
    /// History rebuild: the state trie rebuilt in bulk from the unwound tables.
    history_trie,
    /// History rebuild: every trie node stored at the window start (path index fill).
    history_reset,
    /// History rebuild: blocks re-applied with `commit_block` up to the head.
    history_apply,
};

pub const OpenTrace = struct {
    context: *anyopaque,
    step: *const fn (context: *anyopaque, step: OpenStep) void,
};

/// How `open` turns the checkpoint's snapshot into a state trie: `bulk` builds each trie
/// from sorted keys (`snapshot.load`); `incremental` inserts key by key (the reference
/// path, `snapshot.load_incremental`). Both produce the same tries and roots.
pub const LoadMode = enum { bulk, incremental };

/// Where `open` starts the history rebuild. `full`: the oldest block the window and
/// retention allow (re-applies every retained block of the window). `estimate`: where the
/// byte budget is estimated to cut the window. `keep`: that many blocks below the head
/// (tests). A try that does not start at the oldest block runs the full rebuild after it
/// unless its window shrank past its start (see `history_rebuild_window`).
pub const HistoryRebuildMode = union(enum) { full, estimate, keep: u64 };

/// Newest blocks `history_rebuild_guess` unwinds to estimate a block's history bytes.
const history_sample_blocks = 8;

/// Sums `history.version_bytes` over visited trie nodes.
const VersionBytes = struct {
    bytes: u64 = 0,

    pub fn visit(counter: *VersionBytes, node: StateTrie.NodeVisit) error{}!void {
        assert(node.encoding.len > 0);
        counter.bytes += history_module.version_bytes(node.encoding.len);
    }
};

pub fn DatabaseType(comptime Storage: type) type {
    return struct {
        const Self = @This();

        pub const Engine = engine_module.EngineType(Storage);
        pub const CodeStore = code_store_module.CodeStoreType(Storage);
        pub const FlatTrees = flat_trees_module.FlatTreesType(Storage);
        pub const DiskState = disk_state_module.DiskStateType(FlatTrees);
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
        /// The bodies of one group commit (`pump`).
        queue_batch: [][]const u8,
        queue_head: u32 = 0,
        queue_count: u32 = 0,
        staging: []u8,
        staging_len: u64 = 0,
        staging_position: u64 = 0,
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
        /// Entries of the group commit in flight.
        in_flight_count: u32 = 0,
        /// Group commits that journaled more than one entry.
        commits_grouped: u64 = 0,
        checkpoint_wanted: bool = false,
        /// Set while the caller's State holds changes not yet journaled (an executed block
        /// awaiting adoption): a checkpoint snapshot then would capture them. Wanted
        /// checkpoints start when released.
        checkpoints_held: bool = false,
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
        /// Reports the end of each `open` step (benchmarks); null reports nothing.
        open_trace: ?OpenTrace = null,
        /// Snapshot load path at `open` (tests compare both).
        load_mode: LoadMode = .bulk,
        /// Where `open` starts the history rebuild (tests and benchmarks compare them).
        history_rebuild_mode: HistoryRebuildMode = .estimate,
        /// Opens whose first rebuild try kept no shrink and ran the full rebuild too.
        history_rebuild_widens: u64 = 0,
        /// Blocks the last open's history rebuild committed to history (every try).
        history_rebuild_commits: u64 = 0,
        /// Codes in grid tables (null without a grid).
        code_store: ?CodeStore = null,
        /// The wanted checkpoint's code flush ran (or had nothing to do).
        code_flushed: bool = false,
        /// Flat account and storage trees (`Config.flat_trees`), null when off.
        flat: ?FlatTrees = null,
        /// Disk mode (`Config.disk_state`): the state over `flat`, bound at `open`.
        disk: ?DiskState = null,
        /// Disk mode admission: branch writes of the checkpoint interval before the newest
        /// completed checkpoint (`closed`), of intervals whose checkpoint has not completed
        /// (`pending`), and since the last checkpoint snapshot (`current`). Their sum bounds
        /// what a replay from the fallback checkpoint writes.
        disk_writes_closed: u64 = 0,
        disk_writes_pending: u64 = 0,
        disk_writes_current: u64 = 0,
        /// Operations refused because the journal's branch writes could outgrow the reserve.
        disk_admission_busy: u64 = 0,
        /// This open streams the fallback checkpoint (the newest did not verify).
        open_fallback: bool = false,

        pub fn init(allocator: std.mem.Allocator, storage: *Storage, config: Config) !Self {
            assert(config.queue_entries_max > 0);
            assert(config.chain.blocks_max > 0 and config.chain.bytes_max > 0);
            // The canonical index covers the whole history window.
            if (config.history) |history_config| {
                assert(history_config.window_blocks <= config.chain.canonical_max);
            }
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
            var code_store: ?CodeStore = null;
            if (config.code_store_config()) |code_config| {
                code_store = try CodeStore.init(allocator, &engine.grid.?, code_config);
            }
            errdefer if (code_store) |*store| store.deinit(allocator);
            var flat: ?FlatTrees = null;
            if (config.flat_trees_config()) |flat_config| {
                flat = try FlatTrees.init(allocator, &engine.grid.?, flat_config);
            }
            errdefer if (flat) |*trees| trees.deinit(allocator);
            var disk = try disk_init(allocator, config, if (flat) |*trees| trees else null);
            errdefer if (disk) |*state_disk| state_disk.deinit(allocator);
            const buffers = try Buffers.init(allocator, config);
            return .{
                .disk = disk,
                .flat = flat,
                .code_store = code_store,
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
                .queue_batch = buffers.queue_batch,
                .staging = buffers.staging,
                .history = history_store,
            };
        }

        /// Disk mode's state over `trees`; its trees pointer is bound again at `open` (the
        /// database moves after init).
        fn disk_init(allocator: std.mem.Allocator, config: Config, trees: ?*FlatTrees) !?DiskState {
            const disk_config = config.disk_state_config() orelse return null;
            const root = trie_module.node.empty_root;
            return try DiskState.init(allocator, trees.?, root, disk_config);
        }

        const Buffers = struct {
            changeset_buffer: []u8,
            queue_bodies: []u8,
            queue_lengths: []u32,
            queue_metadata: []Metadata,
            queue_batch: [][]const u8,
            staging: []u8,

            fn init(allocator: std.mem.Allocator, config: Config) !Buffers {
                const body_max = config.engine.entry_body_size_max;
                const queue_max = config.queue_entries_max;
                const changeset_buffer = try lazy.alloc(allocator, u8, body_max);
                errdefer lazy.free(allocator, changeset_buffer);
                const queue_bytes = @as(usize, body_max) * queue_max;
                const queue_bodies = try lazy.alloc(allocator, u8, queue_bytes);
                errdefer lazy.free(allocator, queue_bodies);
                const queue_lengths = try allocator.alloc(u32, queue_max);
                errdefer allocator.free(queue_lengths);
                const queue_metadata = try allocator.alloc(Metadata, queue_max);
                errdefer allocator.free(queue_metadata);
                const queue_batch = try allocator.alloc([]const u8, queue_max);
                errdefer allocator.free(queue_batch);
                const staging = try lazy.alloc(allocator, u8, config.checkpoint_staging_bytes);
                return .{
                    .changeset_buffer = changeset_buffer,
                    .queue_bodies = queue_bodies,
                    .queue_lengths = queue_lengths,
                    .queue_metadata = queue_metadata,
                    .queue_batch = queue_batch,
                    .staging = staging,
                };
            }
        };

        /// Frees memory. After a simulated crash, engine operations may still be in flight.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.disk) |*disk| disk.deinit(allocator);
            if (self.flat) |*trees| trees.deinit(allocator);
            if (self.code_store) |*store| store.deinit(allocator);
            if (self.history) |*store| store.deinit(allocator);
            lazy.free(allocator, self.staging);
            allocator.free(self.queue_batch);
            allocator.free(self.queue_metadata);
            allocator.free(self.queue_lengths);
            lazy.free(allocator, self.queue_bodies);
            lazy.free(allocator, self.changeset_buffer);
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
            const flushing = if (self.code_store) |*store| store.flushing() else false;
            const flat_idle = if (self.flat) |*trees| trees.idle() else true;
            return self.queue_count == 0 and self.engine.idle() and !flushing and flat_idle;
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
            if (self.disk) |*disk| {
                // Pinned from here on: bind the state to the trees and to this database.
                disk.trees = &self.flat.?;
                self.state.disk = self.disk_backend();
            }
            if (self.code_store) |*store| {
                if (store.pinned()) self.state.code_reader = .{
                    .context = self,
                    .read = code_read,
                };
            }
            self.phase = .opening;
            self.open_fallback = false;
            self.staging_len = 0;
            self.load_done = false;
            self.load_error = null;
            self.open_error = null;
            self.engine.open(.{
                .context = self,
                .on_checkpoint = consume_checkpoint,
                .on_checkpoint_reset = consume_checkpoint_reset,
                .on_entry = consume_entry,
                .on_checkpoint_loaded = consume_checkpoint_loaded,
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
            self.staging_len += chunk.len;
        }

        /// The newest checkpoint failed to verify; the engine streams the fallback next.
        fn consume_checkpoint_reset(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening);
            assert(!self.load_done);
            // Staging overflow is the only load error before the first entry.
            self.staging_len = 0;
            self.load_error = null;
            self.open_fallback = true;
        }

        /// The engine paused after loading the checkpoint: read the code tables it names into
        /// the arena (before the image's own codes), then load the image and resume.
        fn consume_checkpoint_loaded(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.phase == .opening);
            assert(!self.load_done);
            self.trace(.checkpoint_read);
            if (self.flat) |*trees| {
                trees.bind(&self.engine.grid.?, &self.engine.free_set.?);
                trees.reset();
            }
            const store = if (self.code_store) |*store| store else return self.open_loaded();
            if (self.load_error != null or self.staging_len == 0) return self.open_loaded();
            self.checkpoint_manifest(store) catch {
                self.load_error = error.CheckpointInvalid;
                return self.open_loaded();
            };
            store.owner = self;
            const grid = &self.engine.grid.?;
            store.scan_start(grid, &self.engine.free_set.?, &self.state, on_code_scan);
        }

        fn on_code_scan(store: *CodeStore) void {
            const self: *Self = @ptrCast(@alignCast(store.owner.?));
            assert(self.phase == .opening);
            switch (store.scan_outcome) {
                .loaded => {
                    self.trace(.code_tables);
                    const trees = if (self.flat) |*trees| trees else return self.open_loaded();
                    trees.owner = self;
                    trees.open_scan(on_flat_scan);
                },
                .corrupt => self.open_corrupt(),
            }
        }

        fn on_flat_scan(trees: *FlatTrees) void {
            const self: *Self = @ptrCast(@alignCast(trees.owner.?));
            assert(self.phase == .opening);
            switch (trees.scan_outcome) {
                .loaded => self.open_loaded(),
                .corrupt => self.open_corrupt(),
            }
        }

        /// A table block did not verify: drop its codes and trees and let the engine treat
        /// the checkpoint as rotten (the fallback streams next, or open fails).
        fn open_corrupt(self: *Self) void {
            assert(self.phase == .opening);
            self.state.reset_codes();
            self.code_store.?.reset();
            if (self.flat) |*trees| trees.reset();
            self.engine.open_resume(.corrupt);
        }

        /// Loads the staged checkpoint (codes from tables already in) and replays.
        fn open_loaded(self: *Self) void {
            assert(self.phase == .opening);
            self.ensure_loaded();
            self.engine.open_resume(.loaded);
        }

        /// Decodes the staged checkpoint's code table list into the code store.
        fn checkpoint_manifest(self: *Self, store: *CodeStore) !void {
            const bytes = self.staging[0..self.staging_len];
            var reader: Reader = .{ .buffer = bytes };
            if (try reader.int(u32) != checkpoint_magic) return error.CheckpointInvalid;
            const version = try reader.int(u16);
            // Flat trees open only from a checkpoint that carries them (no backfill).
            if (try self.checkpoint_version_expected(version) == checkpoint_version) return;
            if (bytes.len < checkpoint_header_size) return error.CheckpointInvalid;
            const size = try store.manifest_decode(bytes[checkpoint_header_size..]);
            const trees = if (self.flat) |*trees| trees else return;
            _ = try trees.open_decode(bytes[checkpoint_header_size + size ..]);
        }

        /// Checks a checkpoint's version against the config (`checkpoint_version_valid`).
        fn checkpoint_version_expected(self: *const Self, version: u16) !u16 {
            const flat = self.flat != null;
            const grid = self.code_store != null;
            const disk = self.disk != null;
            if (!checkpoint_version_valid(version, flat, grid, disk)) {
                return error.CheckpointInvalid;
            }
            assert(version != checkpoint_version_flat_v3);
            return version;
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
            self.trace(.replay);
            if (self.head_info.present) self.history_rebuild_window();
        }

        fn trace(self: *Self, step: OpenStep) void {
            assert(self.phase == .opening or self.phase == .ready);
            const open_trace = self.open_trace orelse return;
            open_trace.step(open_trace.context, step);
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
            try self.flat_reserve_applied(input);
            try self.chain_insert(input);
            self.chain.plan_reorg(input.hash, &self.plan) catch |err| {
                // Stored in memory: journal it alone so replay stays in step.
                const body = encode_block(input, self.queue_slot());
                _ = self.queue_push(@intCast(body.len));
                return err;
            };
            assert(self.plan.unwind_hashes().len == 0 and self.plan.apply_hashes().len == 1);
            self.chain.set_head(&self.plan);
            self.flat_write(true) catch |err| {
                self.phase = .failed;
                return err;
            };
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

        /// Disk mode, an importer's first head: the trees hold block `head_meta`'s post-state
        /// with root `state_root` (bulk-loaded, `FlatTrees.bulk_begin`..`bulk_end`), and the
        /// caller has inserted the codes (`state.insert_code`) and set the block hashes
        /// (`state.set_block_hash`). Checks that the root resolves in the trees
        /// (`StateCorrupt` otherwise, nothing changed), makes the block the head with no
        /// stored block (`ChainStore.restore_evicted_head`; the next block builds on it),
        /// journals a `head` entry, and wants a checkpoint. Durable once that checkpoint
        /// completes; an open before then fails (`ReplayFailed`: the journal's head names a
        /// block it does not store) and the importer formats again.
        pub fn import_head(
            self: *Self,
            head_meta: BlockMeta,
            state_root: Hash,
        ) OperationError!u64 {
            const disk = &self.disk.?;
            assert(!self.head_info.present and self.chain.block_count() == 0);
            assert(self.chain.head() == null);
            assert(self.flat.?.bulk == null);
            try self.check_accepting(1, journal_module.entry_size_bytes(head_entry_size));
            disk.set_root(state_root);
            disk.check_root() catch {
                disk.set_root(trie_module.node.empty_root);
                return error.StateCorrupt;
            };
            self.chain.restore_evicted_head(head_meta);
            self.head_info = .{
                .present = true,
                .number = head_meta.number,
                .hash = head_meta.hash,
                .state_root = state_root,
            };
            const body = encode_head(&head_meta.hash, self.queue_slot());
            const sequence = self.queue_push(@intCast(body.len));
            self.checkpoint_wanted = true;
            self.checkpoint_maybe_start();
            assert(std.mem.eql(u8, &self.chain.head().?.hash, &head_meta.hash));
            return sequence;
        }

        /// Holds (or releases) checkpoint starts; see `checkpoints_held`.
        pub fn hold_checkpoints(self: *Self, held: bool) void {
            assert(self.checkpoints_held != held);
            self.checkpoints_held = held;
            if (!held and self.phase == .ready) self.checkpoint_maybe_start();
        }

        /// Asks for a checkpoint; it starts once the queue drains.
        pub fn request_checkpoint(self: *Self) void {
            assert(self.phase == .ready);
            self.checkpoint_wanted = true;
            self.checkpoint_maybe_start();
        }

        /// Lifts the pacing of the running checkpoint, if any: it writes its remaining
        /// blocks as fast as the storage allows (before a shutdown, or when the journal is
        /// full). Later checkpoints are paced again.
        pub fn checkpoint_flush(self: *Self) void {
            if (self.phase != .ready) return;
            if (self.code_store) |*store| store.grant(std.math.maxInt(u64));
            self.engine.checkpoint_grant(std.math.maxInt(u64));
            assert(!self.engine.checkpoint_paused());
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
                // A paced checkpoint must finish to free the journal.
                self.checkpoint_flush();
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

        /// Journals the queued entries from the head, as many as one group commit takes
        /// (`Engine.commit_batch`; up to the ring's end), if no commit is in flight.
        fn pump(self: *Self) void {
            if (self.phase != .ready or self.queue_count == 0) return;
            if (self.engine.commit_callback != null) return;
            const first = self.queue_head;
            const queue_max = self.config.queue_entries_max;
            const run = @min(self.queue_count, queue_max - first);
            const body_max = self.config.engine.entry_body_size_max;
            for (self.queue_batch[0..run], first..) |*body, index| {
                const offset = @as(usize, index) * body_max;
                body.* = self.queue_bodies[offset..][0..self.queue_lengths[index]];
            }
            const bodies = self.queue_batch[0..run];
            const metadatas = self.queue_metadata[first..][0..run];
            const count = self.engine.commit_batch(bodies, metadatas, on_commit) catch |err|
                switch (err) {
                    // Admission keeps room for every queued entry; a checkpoint frees more.
                    error.JournalFull => {
                        self.checkpoint_wanted = true;
                        self.checkpoint_flush();
                        return;
                    },
                    // Ready and no commit in flight, both checked above.
                    error.NotReady, error.Busy => unreachable,
                };
            assert(count >= 1 and count <= run);
            // The journal copied the bodies: the slots are free.
            var bytes: u64 = 0;
            for (bodies[0..count]) |body| bytes += journal_module.entry_size_bytes(body.len);
            self.in_flight_bytes = bytes;
            self.in_flight_count = count;
            self.commits_grouped += @intFromBool(count > 1);
            self.queue_head = (first + count) % queue_max;
            self.queue_count -= count;
            assert(self.durable_sequence + self.in_flight_count + self.queue_count ==
                self.submitted_sequence);
        }

        fn on_commit(engine: *Engine) void {
            const self: *Self = @alignCast(@fieldParentPtr("engine", engine));
            assert(self.phase == .ready);
            const count = self.in_flight_count;
            assert(count >= 1 and count == engine.commit_count);
            self.in_flight_count = 0;
            self.journal_bytes_pending -= self.in_flight_bytes;
            self.in_flight_bytes = 0;
            for (0..count) |_| {
                self.durable_sequence += 1;
                if (self.on_durable) |callback| {
                    callback(self.durable_context, self.durable_sequence);
                }
            }
            assert(self.durable_sequence == engine.sequence_last());
            assert(self.durable_sequence <= self.submitted_sequence);
            // A paced checkpoint writes its next chunk after each durable commit (each entry
            // of a group commit grants its share). The code flush before a checkpoint spends
            // the same per-commit block budget.
            const blocks = self.config.checkpoint_blocks_per_commit() *| count;
            assert(blocks > 0);
            if (self.config.checkpoint_bytes_per_commit > 0) {
                if (self.code_store) |*store| store.grant(blocks);
                self.engine.checkpoint_grant(blocks);
            }
            // Flat tree compaction is paced per durable commit on the same budget.
            if (self.flat) |*trees| trees.compact(blocks);
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
            try self.flat_reserve_plan();
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
            if (self.chain.head() == null) {
                try self.apply_block(self.plan.ancestor.hash);
                try self.flat_write(true);
            }
            for (self.plan.unwind_hashes()) |hash| {
                const view = self.chain.block(hash).?;
                self.changeset.decode(view.changeset) catch return error.InvalidChangeset;
                try self.state.unwind(&self.changeset);
                try self.flat_write(false);
            }
            if (store) |tracked| if (self.plan.unwind_len > 0) {
                tracked.unwind_to(&self.state.state_trie, self.plan.ancestor.number) catch {
                    self.history_stale = true;
                };
            };
            for (self.plan.apply_hashes()) |hash| {
                try self.apply_block(hash);
                try self.flat_write(true);
                const tracked = store orelse continue;
                if (self.history_stale) continue;
                const number = self.chain.meta(hash).?.number;
                tracked.commit_block(&self.state.state_trie, number) catch {
                    self.history_stale = true;
                };
            }
        }

        /// Live head moves only: fails with `error.Busy` before any change when the flat
        /// trees lack memtable room for every put the planned move can make (disk mode: also
        /// `record_writes_max` branch puts per moved block, and the replay admission).
        fn flat_reserve_plan(self: *Self) OperationError!void {
            const trees = if (self.flat) |*trees| trees else return;
            if (self.phase != .ready) return; // Replay writes into the replay reserve.
            var puts: flat_trees_module.Puts = .{};
            var blocks: u64 = 0;
            if (self.chain.head() == null) {
                const view = self.chain.block(self.plan.ancestor.hash).?;
                FlatTrees.puts_add(&puts, view.changeset) catch return error.InvalidChangeset;
                blocks += 1;
            }
            for ([2][]const Hash{ self.plan.unwind_hashes(), self.plan.apply_hashes() }) |hashes| {
                for (hashes) |hash| {
                    const view = self.chain.block(hash).?;
                    FlatTrees.puts_add(&puts, view.changeset) catch
                        return error.InvalidChangeset;
                }
                blocks += hashes.len;
            }
            assert(blocks <= self.config.move_blocks_max());
            if (self.config.disk_state) |disk_config| {
                puts.account_branches = blocks * disk_config.record_writes_max;
                puts.storage_branches = blocks * disk_config.record_writes_max;
            }
            try trees.reserve(puts, self.config.checkpoint_blocks_per_commit());
            try self.disk_admit(blocks);
        }

        /// `commit_applied`: reserves the flat trees' room for the block's changeset and
        /// decodes it into `self.changeset` for `flat_write` (State already holds it). Disk
        /// mode: nothing to do, the caller's `State.apply` reserved and wrote the trees.
        fn flat_reserve_applied(self: *Self, input: *const BlockInput) OperationError!void {
            const trees = if (self.flat) |*trees| trees else return;
            if (self.disk != null) return;
            assert(self.phase == .ready);
            var puts: flat_trees_module.Puts = .{};
            FlatTrees.puts_add(&puts, input.changeset) catch return error.InvalidChangeset;
            try trees.reserve(puts, self.config.checkpoint_blocks_per_commit());
            self.changeset.decode(input.changeset) catch return error.InvalidChangeset;
        }

        /// Shadow-writes `self.changeset` (just applied, or unwound when not `forward`) into
        /// the flat trees, storage roots from `State`'s trie (flushed first, so every dirty
        /// storage trie rehashes in one batch). Busy here means a too-small replay reserve,
        /// or a missed reserve.
        fn flat_write(self: *Self, forward: bool) OperationError!void {
            const trees = if (self.flat) |*trees| trees else return;
            // Disk mode: `State` moved by writing the trees; nothing to shadow.
            if (self.disk != null) return;
            const mode: FlatTrees.Mode = if (self.phase == .opening) .replay else .live;
            assert(mode == .replay or self.phase == .ready);
            assert(!self.state.trie_stale);
            try self.state.state_trie.flush();
            const source: FlatSource = .{ .state = &self.state };
            try trees.write(&self.changeset, forward, mode, source);
        }

        /// What `FlatTrees.write` reads from `State` after a move.
        const FlatSource = struct {
            state: *State,

            pub fn basic(
                source: FlatSource,
                address: state_module.Address,
            ) ?state_module.AccountInfo {
                return source.state.basic(address);
            }

            pub fn storage_root(source: FlatSource, address_hash: *const Hash) Hash {
                return source.state.state_trie.storage_root(address_hash.*);
            }
        };

        // Disk mode: `State.disk`, admission.

        fn code_read(
            context: *anyopaque,
            hash: *const Hash,
            code: state_module.CodeRef,
        ) ?[]const u8 {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.state.code_reader != null);
            return self.code_store.?.read_pinned(hash, code);
        }

        /// Writes the codes added since the last flush into tables now and drops them from the
        /// arena (`CodeStore.evict_start`; pinned mode), so an import streams codes through a
        /// bounded arena. Only while nothing else runs: no checkpoint, no commit. `.pending`:
        /// tick until `codes_evicting()` is false.
        pub fn codes_evict_start(self: *Self) code_store_module.Status {
            assert(self.phase == .ready);
            assert(!self.checkpoint_wanted and self.engine.checkpoint_phase == .idle);
            assert(self.idle());
            const store = &self.code_store.?;
            assert(store.pinned() and !store.flushing());
            const grid = &self.engine.grid.?;
            const free_set = &self.engine.free_set.?;
            return store.evict_start(grid, free_set, &self.state, on_code_evict);
        }

        pub fn codes_evicting(self: *const Self) bool {
            const store = if (self.code_store) |*store| store else return false;
            return store.flushing();
        }

        fn on_code_evict(store: *CodeStore) void {
            assert(!store.flushing());
            assert(store.pinned());
        }

        /// Ends the lifetime of every code slice `State.code_by_hash` returned for a code
        /// held in a table only (`Config.code_pin_bytes`); a no-op otherwise. Call it where
        /// no caller holds one (the import runner: before each block).
        pub fn codes_release(self: *Self) void {
            const store = if (self.code_store) |*store| store else return;
            if (!store.pinned()) return;
            assert(self.state.code_reader != null);
            store.release();
        }

        fn disk_backend(self: *Self) state_module.Disk {
            assert(self.disk != null);
            return .{
                .context = self,
                .account = disk_account,
                .storage = disk_storage,
                .root = disk_root,
                .apply = disk_apply,
            };
        }

        fn disk_of(context: *anyopaque) *DiskState {
            const self: *Self = @ptrCast(@alignCast(context));
            return &self.disk.?;
        }

        fn disk_account(context: *anyopaque, address_hash: *const Hash) ?state_module.DiskAccount {
            return disk_of(context).account(address_hash);
        }

        fn disk_storage(
            context: *anyopaque,
            address_hash: *const Hash,
            slot_hash: *const Hash,
        ) u256 {
            return disk_of(context).storage(address_hash, slot_hash);
        }

        fn disk_root(context: *anyopaque) Hash {
            return disk_of(context).root();
        }

        /// One block through `DiskState`: live (admitted, and a refusal for memtable room
        /// grants compaction once more, as `FlatTrees.reserve` does), or replay (into the
        /// replay reserves). Counts the branch writes for admission.
        fn disk_apply(
            context: *anyopaque,
            changeset: *const Changeset,
            forward: bool,
        ) state_module.Error!void {
            const self: *Self = @ptrCast(@alignCast(context));
            const disk = &self.disk.?;
            const live = self.phase != .opening;
            disk.mode = if (live) .live else .replay;
            if (self.phase == .ready) try self.disk_admit(1);
            disk.apply(changeset, forward) catch |err| switch (err) {
                error.Busy => {
                    if (self.phase == .ready) {
                        const trees = &self.flat.?;
                        trees.stats.busy += 1;
                        trees.compact(self.config.checkpoint_blocks_per_commit());
                    }
                    return error.Busy;
                },
                error.Corrupt => return error.StateCorrupt,
                error.Full => return error.StateFull,
                error.Unsupported => return error.Unsupported,
            };
            self.disk_writes_current += disk.record_writes_len;
            assert(disk.record_writes_len <= self.config.disk_state.?.record_writes_max);
        }

        /// Disk mode, live: refuses (`error.Busy`) a move of `blocks` blocks whose branch
        /// writes could take the journal's past the replay reserve, and wants a checkpoint
        /// (its completion retires the writes before the fallback checkpoint).
        fn disk_admit(self: *Self, blocks: u64) error{Busy}!void {
            const disk_config = self.config.disk_state orelse return;
            assert(self.phase == .ready);
            assert(blocks <= self.config.move_blocks_max());
            const span = self.disk_writes_closed + self.disk_writes_pending +
                self.disk_writes_current;
            if (span + blocks * disk_config.record_writes_max <=
                disk_config.replay_record_writes_max) return;
            self.disk_admission_busy += 1;
            self.checkpoint_wanted = true;
            self.checkpoint_maybe_start();
            self.checkpoint_flush();
            return error.Busy;
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

        /// At open: rebuilds the history window from the retained canonical blocks. Unwinds
        /// State in memory (nothing is journaled, the chain index never moves) through the
        /// stored changesets down to a start block, `reset`s history there, then re-applies
        /// each block with `commit_block`, so the state ends at the recovered head (root
        /// asserted). The full rebuild starts at `history_rebuild_start`; under a byte budget
        /// that keeps fewer blocks, most of its commits are pruned again, so it first tries
        /// the start `history_rebuild_guess` picks. That try ends with the full rebuild's
        /// window, versions, and bytes whenever its window shrank past its start (see the
        /// proof below); otherwise the full rebuild runs (`history_rebuild_widens`).
        ///
        /// Why a shrink past the start is exact: let m(n) be the oldest start whose window
        /// to block n fits the budget (`bytes_used` of a pruned window falls as its oldest
        /// block rises). `fit_budget` drains the prune queue before each shrink, so after
        /// commit n the oldest block is max(oldest after n - 1, m(n)), and a rebuild from s
        /// ends at max(s, m(s + 1), ..., m(head)). Every m(n) with n <= s is at most s, so
        /// when that end is above s, a rebuild from any earlier start ends there too. Both
        /// stores then hold the pruned window with an empty prune queue (the rebuild never
        /// overflows `window_blocks`, so only shrinks queue versions, and a shrink ends after
        /// a drain). A failed try (`HistoryFull`) means the full rebuild fails too: it holds
        /// a superset of the try's window at every block. The one difference: the full
        /// rebuild also fails on a block below the try's start whose state alone is above
        /// the budget (or the capacities); it then keeps only the head, the try keeps more.
        ///
        /// Cost: O(window) unwinds, applies, state roots, and history commits, plus one
        /// O(state) `reset`, per try. Any history failure falls back to `reset` at the head;
        /// a failed re-apply fails the database (state no longer at the head).
        fn history_rebuild_window(self: *Self) void {
            assert(self.phase == .ready and self.head_info.present);
            assert(!self.history_stale and !self.history_off);
            const store = if (self.history) |*store| store else return;
            if (!self.config.history_rebuild_on_open) return self.history_rebuild();
            const head = self.head_info.number;
            const lowest = self.history_rebuild_start();
            self.history_rebuild_commits = 0;
            const guess = self.history_rebuild_guess(lowest) orelse return;
            assert(lowest <= guess.start and guess.start <= guess.at and guess.at <= head);
            if (guess.start == lowest) {
                const start = self.history_rebuild_unwind(guess.at, lowest) orelse return;
                _ = self.history_rebuild_apply(store, start);
                return;
            }
            const start = self.history_rebuild_unwind(guess.at, guess.start) orelse return;
            assert(start > lowest);
            const kept = self.history_rebuild_apply(store, start) orelse return;
            if (!kept or store.window().?.oldest > start) return;
            // No block left the try's window early: the budget may keep older blocks.
            self.history_rebuild_widens += 1;
            const full_start = self.history_rebuild_unwind(head, lowest) orelse return;
            _ = self.history_rebuild_apply(store, full_start);
        }

        /// `reset`s history at `start` (State holds that block) and re-applies every block
        /// up to the head. Returns whether history kept a window (false: dropped and reset
        /// at the head), or null when a re-apply failed the database.
        fn history_rebuild_apply(self: *Self, store: *history_module.Store, start: u64) ?bool {
            const head = self.head_info.number;
            assert(start <= head);
            // Every block of the window is canonical by number (the node checks a proof's
            // block against the canonical index), its oldest included.
            assert(self.chain.canonical_hash(start) != null);
            var history_ok = true;
            store.reset(&self.state.state_trie, start) catch {
                history_ok = false;
            };
            self.trace(.history_reset);
            var number = start;
            while (number < head) {
                number += 1;
                const hash = self.chain.canonical_hash(number).?;
                self.apply_block(hash) catch return self.history_rebuild_failed();
                if (!history_ok) continue;
                self.history_rebuild_commits += 1;
                store.commit_block(&self.state.state_trie, number) catch {
                    history_ok = false;
                };
            }
            const root = self.state.state_root() catch return self.history_rebuild_failed();
            assert(std.mem.eql(u8, &root, &self.head_info.state_root));
            self.trace(.history_apply);
            if (history_ok) {
                assert(store.window().?.head == head);
                return true;
            }
            self.history_drops += 1;
            self.history_rebuild();
            return false;
        }

        fn history_rebuild_failed(self: *Self) ?bool {
            assert(self.phase == .ready);
            self.phase = .failed;
            self.open_error = error.ReplayFailed;
            return null;
        }

        const RebuildGuess = struct {
            /// The block to try the rebuild from.
            start: u64,
            /// The block State holds (unwound there while sampling); `start <= at`.
            at: u64,
        };

        /// Picks where to try the rebuild (`history_rebuild_mode`). `estimate` unwinds the
        /// newest `history_sample_blocks` blocks through the trie and sums the version bytes
        /// of the nodes each rehashes (a block's versions, without new paths and tombstones),
        /// estimates the bytes of a `reset` from the node pools, and keeps the blocks the
        /// rest of the budget fits plus a quarter and the sample. Any start is sound (the
        /// try is checked); a good one only saves work. Null when a root failed the database.
        fn history_rebuild_guess(self: *Self, lowest: u64) ?RebuildGuess {
            const head = self.head_info.number;
            assert(lowest <= head);
            const full: RebuildGuess = .{ .start = lowest, .at = head };
            switch (self.history_rebuild_mode) {
                .full => return full,
                .keep => |keep| return .{ .start = @max(lowest, head -| keep), .at = head },
                .estimate => {},
            }
            const bytes_max = self.config.history.?.bytes_max orelse return full;
            if (head - lowest < 4 * history_sample_blocks) return full;
            const trie = &self.state.state_trie;
            _ = self.state.state_root() catch return self.history_guess_failed();
            trie.clear_changes();
            var counter: VersionBytes = .{};
            var at = head;
            while (at > head - history_sample_blocks) : (at -= 1) {
                const view = self.chain.block(self.chain.canonical_hash(at).?).?;
                self.changeset.decode(view.changeset) catch break;
                self.state.unwind(&self.changeset) catch break;
                _ = self.state.state_root() catch return self.history_guess_failed();
                trie.visit_nodes(.count, &counter) catch |err| switch (err) {};
                trie.clear_changes();
            }
            // An unwind that does not fit: try from the block reached (checked like any).
            if (at > head - history_sample_blocks) return .{ .start = at, .at = at };
            const base = history_module.reset_bytes_estimate(trie);
            const per_block = counter.bytes / history_sample_blocks;
            if (per_block == 0 or base >= bytes_max) return .{ .start = lowest, .at = at };
            const fit = (bytes_max - base) / per_block;
            const keep = fit + fit / 4 + history_sample_blocks;
            const start = @max(lowest, head -| keep);
            assert(start <= at);
            return .{ .start = start, .at = at };
        }

        fn history_guess_failed(self: *Self) ?RebuildGuess {
            _ = self.history_rebuild_failed();
            return null;
        }

        /// Unwinds State from block `from` (State holds it) to `target`; returns the block
        /// reached, or null when the trie rebuild failed (the database failed). Unwinding
        /// the tables and rebuilding the trie once costs O(state); unwinding the trie costs a
        /// trie update per entry of every unwound block (more above a few dozen typical
        /// blocks at 100k accounts). The bulk load path does the former when the staging
        /// buffer can hold the build's scratch.
        fn history_rebuild_unwind(self: *Self, from: u64, target: u64) ?u64 {
            const scratch_max = State.build_trie_scratch_bytes_max(self.config.state);
            const rebuild = self.load_mode == .bulk and self.staging.len >= scratch_max;
            const start = self.history_unwind_to(from, target, rebuild);
            self.trace(.history_unwind);
            if (self.state.trie_stale) {
                assert(rebuild);
                self.state.rebuild_trie(self.staging) catch {
                    self.phase = .failed;
                    self.open_error = error.ReplayFailed;
                    return null;
                };
            }
            assert(!self.state.trie_stale);
            self.trace(.history_trie);
            return start;
        }

        /// The oldest block the window can be rebuilt from: `head - window_blocks + 1`, or
        /// the state below the oldest canonical block whose changeset is still retained
        /// (genesis is never unwound).
        fn history_rebuild_start(self: *const Self) u64 {
            const head = self.head_info.number;
            const window_blocks = self.config.history.?.window_blocks;
            assert(window_blocks > 0);
            const lowest = head -| (window_blocks - 1);
            var start = head;
            while (start > lowest and start > 0) : (start -= 1) {
                const hash = self.chain.canonical_hash(start) orelse break;
                if (self.chain.block(hash) == null) break;
            }
            assert(start >= lowest and start <= head);
            return start;
        }

        /// Unwinds State from block `from` down to block `target`; returns the block it
        /// reached (higher than `target` when an unwind does not fit: `State.unwind` fails
        /// before any change, so the state still holds the block above). With `tables_only`
        /// the trie is left stale (`State.unwind_tables`) for `State.rebuild_trie`.
        fn history_unwind_to(self: *Self, from: u64, target: u64, tables_only: bool) u64 {
            assert(target <= from and from <= self.head_info.number);
            var number = from;
            while (number > target) : (number -= 1) {
                const view = self.chain.block(self.chain.canonical_hash(number).?).?;
                self.changeset.decode(view.changeset) catch break;
                if (tables_only) {
                    self.state.unwind_tables(&self.changeset) catch break;
                } else {
                    self.state.unwind(&self.changeset) catch break;
                }
            }
            assert(number >= target);
            return number;
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
            // Disk mode keeps no `StateTrie` and no history (proofs over records: later).
            if (self.disk != null) return error.HistoryUnavailable;
            if (self.history_tracking()) |store| {
                const proofs = storage_proofs;
                return store.get_proof(number, address, slots, account_proof, proofs, values);
            }
            if (number != self.head_info.number) return error.HistoryUnavailable;
            return self.proof_live(address, slots, account_proof, storage_proofs, values);
        }

        /// `proof_at` for many slots in one storage walk (`history.Store.get_proofs`): the
        /// account proof, and in `set` each slot's proof and value (byte for byte
        /// `proof_at`'s), valid until the next head move. History only: without it every
        /// block, the head too, is `HistoryUnavailable` (the head is served by `proof_at`).
        pub fn proofs_at(
            self: *Self,
            number: u64,
            address: history_module.Address,
            slots: []const u256,
            account_proof: *StateTrie.AccountProof,
            set: *history_module.ProofSet,
        ) ProofError!?history_module.AccountState {
            assert(slots.len <= set.capacity());
            if (self.phase != .ready or !self.head_info.present) return error.NotReady;
            if (self.disk != null) return error.HistoryUnavailable;
            const store = self.history_tracking() orelse return error.HistoryUnavailable;
            assert(store.window() != null);
            return store.get_proofs(number, address, slots, account_proof, set);
        }

        /// `debug_storageRangeAt`: the slots of `address_hash`'s storage trie at block
        /// `number` in hashed-key order from `start` (inclusive), at most `min(max, out.len)`
        /// into `out`, plus the next key (null after the last slot). The head is read from
        /// the live trie (no history needed); older blocks from the history window
        /// (`BlockOutOfWindow` outside it, `HistoryUnavailable` without history).
        /// `UnknownAccount` when the account is absent at `number`; an account without
        /// storage gives an empty range. No allocation.
        pub fn storage_range_at(
            self: *Self,
            number: u64,
            address_hash: Hash,
            start: Hash,
            max: u32,
            out: []history_module.StorageEntry,
        ) ProofError!history_module.StorageRange {
            if (self.phase != .ready or !self.head_info.present) return error.NotReady;
            if (self.disk != null) return error.HistoryUnavailable;
            assert(!self.state.trie_stale);
            if (number == self.head_info.number) {
                return self.state.state_trie.storage_range(address_hash, start, max, out);
            }
            const store = self.history_tracking() orelse return error.HistoryUnavailable;
            assert(store.window().?.head == self.head_info.number);
            return store.storage_range(number, &address_hash, &start, max, out);
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
            if (self.checkpoints_held) return;
            if (self.engine.checkpoint_phase != .idle) return;
            if (!self.code_flush_ready()) return;
            if (self.queue_count > 0 or self.engine.commit_callback != null) return;
            if (!self.flat_checkpoint_ready()) return;
            self.checkpoint_wanted = false;
            self.code_flushed = false;
            self.staging_len = self.checkpoint_write() catch |err| {
                self.checkpoint_error = err;
                return;
            };
            self.staging_position = 0;
            const producer: engine_module.Producer = .{ .context = self, .produce = produce };
            const blocks = self.config.checkpoint_blocks_per_commit();
            assert(blocks > 0);
            // Ready, no commit in flight, and no checkpoint running: checked above.
            self.engine.checkpoint_paced(producer, blocks, on_checkpoint) catch unreachable;
        }

        /// True when the flat trees (if any) leave the next replay a full reserve; otherwise
        /// drives their pending flush unpaced and waits (`on_flat_install` retries). The
        /// install may run inside `checkpoint_prepare` and start the checkpoint there.
        fn flat_checkpoint_ready(self: *Self) bool {
            const trees = if (self.flat) |*trees| trees else return true;
            // A bulk import is running: its owner requests the checkpoint after `bulk_end`.
            if (trees.bulk != null) return false;
            if (trees.checkpoint_ready()) return true;
            trees.owner = self;
            trees.checkpoint_prepare(on_flat_install);
            return false;
        }

        fn on_flat_install(trees: *FlatTrees) void {
            const self: *Self = @ptrCast(@alignCast(trees.owner.?));
            assert(self.phase == .ready);
            if (!self.checkpoint_wanted or !trees.checkpoint_ready()) return;
            self.checkpoint_maybe_start();
        }

        /// True once the wanted checkpoint's codes are in tables (or need none); otherwise
        /// starts (or waits for) the flush. The flush runs alongside commits: it reads only
        /// arena bytes, which never change, and completes its grid writes before the
        /// checkpoint starts, so the checkpoint's sync covers them.
        fn code_flush_ready(self: *Self) bool {
            const store = if (self.code_store) |*store| store else return true;
            if (store.flushing()) return false;
            if (self.code_flushed) return true;
            self.code_flushed = true;
            store.owner = self;
            const grid = &self.engine.grid.?;
            const free_set = &self.engine.free_set.?;
            const blocks = self.config.checkpoint_blocks_per_commit();
            const status = store.flush_start(grid, free_set, &self.state, blocks, on_code_flush);
            return status == .done;
        }

        fn on_code_flush(store: *CodeStore) void {
            const self: *Self = @ptrCast(@alignCast(store.owner.?));
            assert(self.code_flushed);
            assert(!store.flushing());
            self.checkpoint_maybe_start();
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
                // The checkpoint before this one is the fallback now: only the interval it
                // closed (and the writes since) can be replayed.
                self.disk_writes_closed = self.disk_writes_pending;
                self.disk_writes_pending = 0;
            } else |err| self.checkpoint_error = err;
            self.pump();
            self.checkpoint_maybe_start();
        }

        /// Serializes header, state snapshot, and retained blocks into the staging buffer.
        fn checkpoint_write(self: *Self) !u64 {
            assert(self.queue_count == 0);
            var position: usize = checkpoint_header_size;
            var filter: snapshot_module.CodeFilter = .{};
            if (self.code_store) |*store| {
                assert(!store.flushing());
                const size = store.manifest_size();
                if (size > self.staging.len - position) return error.CheckpointTooLarge;
                position += store.manifest_encode(self.staging[position..]);
                filter = store.code_filter();
            }
            if (self.flat) |*trees| {
                if (trees.checkpoint_size() > self.staging.len - position) {
                    return error.CheckpointTooLarge;
                }
                position += trees.checkpoint_encode(self.staging[position..]);
            }
            if (self.disk != null) {
                // The snapshot point closes an interval: its writes stay pending until this
                // checkpoint completes (and are what an open from it carries).
                self.disk_writes_pending += self.disk_writes_current;
                self.disk_writes_current = 0;
                if (8 > self.staging.len - position) return error.CheckpointTooLarge;
                const writes = self.disk_writes_pending;
                std.mem.writeInt(u64, self.staging[position..][0..8], writes, .little);
                position += 8;
                assert(self.state.account_table.count() == 0);
                assert(self.state.storage_table.count() == 0);
            }
            var sink: snapshot_module.BufferSink = .{ .buffer = self.staging[position..] };
            try snapshot_module.write_filtered(&self.state, &sink, filter);
            const snapshot_len: u32 = @intCast(sink.position);
            position += snapshot_len;
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
            const version = if (self.disk != null)
                checkpoint_version_disk
            else if (self.flat != null)
                checkpoint_version_flat
            else if (self.code_store != null)
                checkpoint_version_tables
            else
                checkpoint_version;
            writer.int(u16, version);
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
            const version = try self.checkpoint_version_expected(try reader.int(u16));
            const tables = version != checkpoint_version;
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
            if (tables) {
                // Decoded (and its tables scanned) during the open pause.
                assert(reader.position == checkpoint_header_size);
                const count = try reader.int(u32);
                _ = try reader.bytes(@as(u64, count) * CodeStore.info_size);
            }
            if (version == checkpoint_version_flat or version == checkpoint_version_disk) {
                // Every tree, decoded (and scanned) during the open pause.
                for (0..flat_trees_module.tree_count) |_| {
                    _ = try reader.bytes(try reader.int(u32));
                }
            }
            if (version == checkpoint_version_disk) {
                const writes = try reader.int(u64);
                const root = if (present == 1) state_root else trie_module.node.empty_root;
                try self.disk_load(writes, root);
            }
            try self.snapshot_load(try reader.bytes(snapshot_len));
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
            self.trace(.blocks);
            const root = try self.state.state_root();
            if (!std.mem.eql(u8, &root, &state_root)) return error.CheckpointInvalid;
            self.head_info = .{
                .present = present == 1,
                .number = head_meta.number,
                .hash = head_meta.hash,
                .state_root = state_root,
            };
        }

        /// Disk mode: the state is the trees' at `root` (the head's state root), which must
        /// resolve; the admission counts restart from the interval this checkpoint closed (a
        /// fallback open does not know the one before: assume the whole reserve, so the next
        /// operation waits for a checkpoint).
        fn disk_load(self: *Self, writes: u64, root: Hash) !void {
            const disk = &self.disk.?;
            assert(disk.trees == &self.flat.?);
            disk.set_root(root);
            disk.check_root() catch return error.CheckpointInvalid;
            const reserve = self.config.disk_state.?.replay_record_writes_max;
            self.disk_writes_closed = if (self.open_fallback) reserve else writes;
            self.disk_writes_pending = 0;
            self.disk_writes_current = 0;
            assert(std.mem.eql(u8, &disk.root(), &root));
        }

        /// Loads the checkpoint's snapshot (`load_mode`) and checks its root. The snapshot
        /// bytes are scratch for the bulk trie build afterwards (they lie in `staging`, which
        /// the engine no longer reads once the checkpoint is verified).
        fn snapshot_load(self: *Self, bytes: []const u8) !void {
            const offset = @intFromPtr(bytes.ptr) -% @intFromPtr(self.staging.ptr);
            assert(offset + bytes.len <= self.staging_len);
            var source: snapshot_module.BufferSource = .{ .buffer = bytes };
            const scratch = self.staging[offset..][0..bytes.len];
            const expected = switch (self.load_mode) {
                .bulk => try snapshot_module.load_tables(&self.state, &source),
                .incremental => try snapshot_module.load_incremental_tables(&self.state, &source),
            };
            if (source.position != bytes.len) return error.CheckpointInvalid;
            if (self.disk != null) {
                // Disk mode: codes and block hashes only (accounts and slots are the trees').
                const count = self.state.account_table.count() + self.state.storage_table.count();
                if (count > 0) return error.CheckpointInvalid;
            }
            self.trace(.snapshot_tables);
            if (self.load_mode == .bulk and self.disk == null) {
                try snapshot_module.build_trie(&self.state, scratch);
            }
            self.trace(.snapshot_trie);
            try snapshot_module.verify(&self.state, &expected);
            self.trace(.snapshot_root);
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
                self.chain.restore_evicted_head(head_meta);
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

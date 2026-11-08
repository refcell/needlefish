//! Snapshot import into a needlefish disk-mode database (disk-state import plan step 10).
//!
//! One pass over a reth hashed state (`HashedAccounts` + `HashedStorages`, as `EntrySource`s)
//! writes all four flat trees of a fresh disk-mode database (`Database.Config.disk_state`)
//! straight into their last level: `hashed_state.compute` streams the leaves (`LeafSink`:
//! every slot, then every account with its storage root) and `StateRootBuilder`'s record sink
//! streams the branch records, each stream ascending, into the `FlatTrees` bulk loaders. This
//! is the same emission `db/disk_state_test.zig` imports (`branch_record.encode` at
//! `path_key` / `storage_key`), so `DiskState` resolves the root from what is written.
//! `Bytecodes` go into the state's code arena first (each checked against its key), and every
//! account's code hash must name a loaded code.
//!
//! The head: `fetch_chain` walks a `HeaderSource` from block N down 255 parents, requiring
//! each link's hash to be the parent hash of the block above (the source binds every link's
//! fields to its hash, e.g. `header_json`). After the load the computed root must equal header
//! N's `stateRoot`; the 256 hashes become the state's block hashes and `Database.import_head`
//! makes N the head with no stored block (it checks the root resolves in the trees). A
//! checkpoint makes it durable. `verify_samples` reads a reservoir sample of the streamed
//! accounts and slots back through the trie (every node rebuilt from records and checked
//! against its parent's hash) after a reopen.
//!
//! Sizing (`sizing`) derives the whole database config from the snapshot's counts and a
//! `Shape`; the result is part of the on-disk format (tree layouts, grid size), so every open
//! of the file must use the same counts (`Counts.encode` is the importer's sidecar record).
//! Library code: storage ticks go through the caller's `Driver`, no clock or file access here.

const std = @import("std");
const assert = std.debug.assert;

const hashed_state = @import("hashed_state.zig");
const state_root_module = @import("state_root.zig");
const reth = @import("reth.zig");
const database = @import("../db/database.zig");
const flat_trees_module = @import("../db/flat_trees.zig");
const branch_record = @import("../db/branch_record.zig");
const state_module = @import("../db/state.zig");
const chain_module = @import("../db/chain.zig");
const changeset_module = @import("../db/changeset.zig");
const code_store_module = @import("../db/code_store.zig");
const grid_module = @import("../db/storage/grid.zig");
const checkpoint_module = @import("../db/storage/checkpoint.zig");
const node = @import("../trie/node.zig");

const Hash = node.Hash;
const EntrySource = hashed_state.EntrySource;
const BranchNode = @import("../trie/root.zig").BranchNode;

pub const block_hashes_max = state_module.block_hashes_max;

/// The snapshot's counts: everything sizing needs.
pub const Counts = struct {
    accounts: u64,
    slots: u64,
    codes: u64,
    code_bytes: u64,

    /// magic u64, then the four counts, little-endian.
    pub const encoded_size: u32 = 8 + 4 * 8;
    /// "nfsize01" read as a little-endian u64.
    const magic: u64 = 0x3130_657a_6973_666e;
    /// Larger counts are refused (a damaged sidecar, not a chain).
    pub const count_max: u64 = 1 << 40;

    pub fn encode(counts: Counts) [encoded_size]u8 {
        assert(counts.valid());
        var out: [encoded_size]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], magic, .little);
        std.mem.writeInt(u64, out[8..16], counts.accounts, .little);
        std.mem.writeInt(u64, out[16..24], counts.slots, .little);
        std.mem.writeInt(u64, out[24..32], counts.codes, .little);
        std.mem.writeInt(u64, out[32..40], counts.code_bytes, .little);
        return out;
    }

    pub fn decode(bytes: []const u8) error{InvalidCounts}!Counts {
        if (bytes.len != encoded_size) return error.InvalidCounts;
        if (std.mem.readInt(u64, bytes[0..8], .little) != magic) return error.InvalidCounts;
        const counts: Counts = .{
            .accounts = std.mem.readInt(u64, bytes[8..16], .little),
            .slots = std.mem.readInt(u64, bytes[16..24], .little),
            .codes = std.mem.readInt(u64, bytes[24..32], .little),
            .code_bytes = std.mem.readInt(u64, bytes[32..40], .little),
        };
        if (!counts.valid()) return error.InvalidCounts;
        return counts;
    }

    fn valid(counts: Counts) bool {
        return counts.accounts <= count_max and counts.slots <= count_max and
            counts.codes <= count_max and counts.code_bytes <= count_max;
    }
};

/// Everything in the database config that does not come from the counts.
pub const Shape = struct {
    block_size: u32,
    journal_size_bytes: u64,
    entry_body_size_max: u32,
    chain: chain_module.Config,
    changeset: changeset_module.Config,
    disk_state: database.DiskStateConfig,
    queue_entries_max: u32,
    flat_flush_entries_min: u32,
    flat_branch_flush_entries_min: u32,
    flat_cache_blocks: u32,
    code_flush_bytes_min: u32,
    /// Codes and code bytes the state holds beyond the snapshot's (contracts created later).
    codes_headroom: u32,
    code_bytes_headroom: u32,
};

const node_record_writes_max: u32 = 1 << 14;
const node_reorg_depth_max: u32 = 4;

/// The node's shape: the node's durable journal, chain and per-block limits, with a shallow
/// reorg depth (each branch tree's memtable holds `record_writes_max` per movable block).
pub const shape_node: Shape = .{
    .block_size = 64 * 1024,
    .journal_size_bytes = 64 << 20,
    .entry_body_size_max = 2 << 20,
    .chain = .{
        .blocks_max = 1024,
        .bytes_max = 16 << 20,
        .transactions_max = 1 << 16,
        .canonical_max = 1 << 16,
        .reorg_depth_max = node_reorg_depth_max,
    },
    .changeset = .{
        .accounts_max = 1 << 14,
        .storage_max = 1 << 16,
        .codes_max = 1 << 10,
        .code_bytes_max = 4 << 20,
    },
    .disk_state = .{
        .trie_nodes_max = 1 << 20,
        .storage_tries_max = 1 << 14,
        .memo_entries_max = 1 << 20,
        .memo_bytes_max = 256 << 20,
        .record_writes_max = node_record_writes_max,
        .record_write_bytes_max = node_record_writes_max * branch_record.value_bytes_max,
        .replay_record_writes_max = node_record_writes_max * 16,
        // ~300 MiB: the account trie's top four levels and the hot paths stay resolved.
        .record_cache_entries = 1 << 18,
        // A block's reads, remembered until its write-back (~12 MiB).
        .read_memo_accounts_max = 1 << 14,
        .read_memo_slots_max = 1 << 16,
    },
    .queue_entries_max = 8,
    .flat_flush_entries_min = 16 * 1024,
    .flat_branch_flush_entries_min = 4096,
    .flat_cache_blocks = 1024,
    .code_flush_bytes_min = 64 * 1024,
    .codes_headroom = 1 << 16,
    .code_bytes_headroom = 64 << 20,
};

pub const Sizing = struct {
    counts: Counts,
    /// Branch records each branch tree is sized for (an estimate with margin).
    account_branches_max: u64,
    storage_branches_max: u64,
    /// Estimated grid blocks of the four trees after the import, and of the code tables.
    tree_blocks: u64,
    code_blocks: u64,
    config: database.Config,
};

pub const SizingError = error{CodesTooLarge};

/// Average branch-record value bytes assumed for the grid estimate (children refs and leaf
/// keys; the design's ~140-250 B).
const branch_value_bytes_estimate: u64 = 200;

/// Grid blocks a tree of `records` records of `record_bytes` (key + value) takes: full data
/// blocks plus an index block per 64 data blocks (index blocks hold hundreds), rounded up.
fn tree_blocks_for(records: u64, record_bytes: u64, block_size: u32) u64 {
    const room = grid_module.payload_capacity_of(block_size) - 8;
    const per_block = @max(1, room / (record_bytes + 4));
    const data = std.math.divCeil(u64, records, per_block) catch unreachable; // per_block > 0.
    const blocks = data + data / 64 + 1;
    assert(blocks > data);
    return blocks;
}

/// The database config for a snapshot of `counts` (see the file comment).
pub fn sizing(comptime Storage: type, counts: Counts, shape: Shape) SizingError!Sizing {
    assert(counts.valid());
    assert(shape.block_size % 4096 == 0);
    const codes_max = counts.codes + shape.codes_headroom;
    const code_bytes_max = counts.code_bytes + shape.code_bytes_headroom;
    // The code count is u32; code bytes are u64 (a code arena of tens of GiB).
    if (codes_max > std.math.maxInt(u32)) return error.CodesTooLarge;
    // ~0.4 branch records per leaf (the design's measure); the trees are sized for 0.5.
    // Storage tries add at most one root record each (at most one trie per account, per
    // slot); a single-slot trie's root record is a 37-byte leaf root.
    const storage_tries = @min(counts.accounts, counts.slots);
    const account_branches = counts.accounts / 2 + 16;
    const storage_branches = counts.slots / 2 + storage_tries + 16;
    const block_size = shape.block_size;
    const branch_bytes = 2 + branch_value_bytes_estimate;
    const tree_blocks =
        tree_blocks_for(counts.accounts, 32 + 104, block_size) +
        tree_blocks_for(counts.slots, 64 + 32, block_size) +
        tree_blocks_for(counts.accounts * 2 / 5, 33 + branch_bytes, block_size) +
        tree_blocks_for(counts.slots * 2 / 5, 65 + branch_bytes, block_size) +
        tree_blocks_for(storage_tries, 65 + 37, block_size);
    var config = base_config(shape);
    config.state.codes_max = @intCast(codes_max);
    config.state.code_bytes_max = code_bytes_max;
    config.flat_accounts_max = counts.accounts + counts.accounts / 4 + 1024;
    config.flat_slots_max = counts.slots + counts.slots / 4 + 1024;
    config.flat_account_branches_max = account_branches;
    config.flat_storage_branches_max = storage_branches;
    const code_blocks = database.code_grid_block_count(config.state, block_size);
    // Room for one table per loader (twice) beyond the estimate, then half the trees again
    // for compaction outputs that land before their inputs are released.
    config.engine.grid_block_count = 1;
    const spare = 2 * tables_blocks(Storage, config) + 64;
    config.engine.grid_block_count = tree_blocks + tree_blocks / 2 + code_blocks + spare;
    const CodeStore = code_store_module.CodeStoreType(Storage);
    const tables_min = CodeStore.tables_max_min(
        block_size,
        config.state.codes_max,
        config.state.code_bytes_max,
    );
    config.code_tables_max = @max(16, tables_min);
    size_checkpoint(Storage, &config);
    return .{
        .counts = counts,
        .account_branches_max = account_branches,
        .storage_branches_max = storage_branches,
        .tree_blocks = tree_blocks,
        .code_blocks = code_blocks,
        .config = config,
    };
}

/// The config fields that come from `shape` alone.
fn base_config(shape: Shape) database.Config {
    assert(shape.disk_state.record_writes_max > 0);
    const config: database.Config = .{
        .engine = .{
            .journal_size_bytes = shape.journal_size_bytes,
            .checkpoint_zone_size_bytes = shape.block_size,
            .entry_body_size_max = shape.entry_body_size_max,
            .checkpoint_block_size = shape.block_size,
            .grid_block_count = 1,
        },
        // Disk mode keeps only codes and block hashes in RAM.
        .state = .{
            .accounts_max = 4,
            .storage_slots_max = 4,
            .codes_max = 1,
            .code_bytes_max = 1,
            .account_nodes_max = 64,
            .storage_nodes_max = 64,
        },
        .chain = shape.chain,
        .changeset = shape.changeset,
        .queue_entries_max = shape.queue_entries_max,
        .checkpoint_staging_bytes = database.checkpoint_header_size,
        .code_flush_bytes_min = shape.code_flush_bytes_min,
        .flat_trees = true,
        .flat_flush_entries_min = shape.flat_flush_entries_min,
        .flat_cache_blocks = shape.flat_cache_blocks,
        .flat_branch_flush_entries_min = shape.flat_branch_flush_entries_min,
        .disk_state = shape.disk_state,
    };
    assert(config.history == null);
    return config;
}

/// Blocks one table of each of the four trees takes at most.
fn tables_blocks(comptime Storage: type, config: database.Config) u64 {
    const FlatTrees = flat_trees_module.FlatTreesType(Storage);
    const configs = FlatTrees.tree_configs(config.flat_trees_config().?);
    const blocks = @as(u64, FlatTrees.AccountTree.layout_of(configs.accounts).blocks_per_table) +
        FlatTrees.StorageTree.layout_of(configs.storage).blocks_per_table +
        FlatTrees.AccountBranchTree.layout_of(configs.account_branches).blocks_per_table +
        FlatTrees.StorageBranchTree.layout_of(configs.storage_branches).blocks_per_table;
    assert(blocks >= 4 * 2);
    return blocks;
}

/// Staging bytes: header, code table list, the trees' bytes, the branch-write count, a
/// snapshot (block hashes and the codes no table holds yet: below the flush minimum), and
/// the retained blocks. The zone holds that and the free set image twice over.
fn size_checkpoint(comptime Storage: type, config: *database.Config) void {
    const FlatTrees = flat_trees_module.FlatTreesType(Storage);
    const CodeStore = code_store_module.CodeStoreType(Storage);
    const unflushed_bytes = 5 * @as(u64, config.code_flush_bytes_min);
    const snapshot_max: u64 = 64 + block_hashes_max * 40 + unflushed_bytes;
    const blocks_max = @as(u64, config.chain.blocks_max) + 1;
    const chain_max = @as(u64, config.chain_bytes_capacity()) +
        blocks_max * (4 + database.block_entry_fixed_size);
    const staging = database.checkpoint_header_size +
        @as(u64, CodeStore.manifest_size_max(config.code_store_config().?)) +
        FlatTrees.checkpoint_size_max_of(config.flat_trees_config().?) + 8 +
        snapshot_max + chain_max;
    assert(staging < std.math.maxInt(u32));
    config.checkpoint_staging_bytes = @intCast(staging);
    const block_size = config.engine.checkpoint_block_size;
    const free_image = 2 * (std.math.divCeil(u64, config.engine.grid_block_count, 8) catch
        unreachable); // Non-zero divisor.
    const payload = block_size - checkpoint_module.block_header_size;
    const zone_blocks = @max(
        (std.math.divCeil(u64, staging + free_image, payload) catch unreachable) + 2,
        2 * (std.math.divCeil(u64, free_image, block_size) catch unreachable) + 2,
    );
    config.engine.checkpoint_zone_size_bytes = zone_blocks * block_size;
    assert(free_image < config.engine.checkpoint_zone_size_bytes / 2);
}

// The head: block N and its 255 ancestors, linked by parent hash.

/// A header's identity and the fields the import needs, bound to `hash` by its source.
pub const HeaderLink = struct {
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    timestamp: u64,
    state_root: Hash,
};

/// Block headers by number. Each link's fields must be bound to its hash (the source checks
/// the header hashes to it); `fetch_chain` checks the links between them.
pub const HeaderSource = struct {
    context: *anyopaque,
    fetch: *const fn (context: *anyopaque, number: u64) anyerror!HeaderLink,
};

/// Block N first, then its ancestors, as many as the state's block hash ring holds.
pub const HeaderChain = struct {
    links: [block_hashes_max]HeaderLink = undefined,
    len: u32 = 0,

    pub fn head(chain: *const HeaderChain) *const HeaderLink {
        assert(chain.len > 0);
        return &chain.links[0];
    }
};

/// Fetches block `number` and its ancestors (256 blocks, or down to block 0) and checks the
/// chain: numbers descend by one and each block's hash is the parent hash of the one above.
pub fn fetch_chain(source: HeaderSource, number: u64, chain: *HeaderChain) !void {
    const count: u32 = @intCast(@min(block_hashes_max, number + 1));
    chain.len = 0;
    for (0..count) |offset| {
        const link = try source.fetch(source.context, number - offset);
        if (link.number != number - offset) return error.WrongBlock;
        if (offset > 0) {
            const child = &chain.links[offset - 1];
            if (!std.mem.eql(u8, &child.parent_hash, &link.hash)) return error.BrokenChain;
        }
        chain.links[offset] = link;
        chain.len += 1;
    }
    assert(chain.len == count);
    assert(chain.head().number == number);
}

/// A test-only chain (no real headers): block hashes keccak256("needlefish test block" ++
/// number), so a database imported with it opens but must not execute real blocks.
pub const SyntheticHeaders = struct {
    head_number: u64,
    state_root: Hash,

    pub fn source(self: *SyntheticHeaders) HeaderSource {
        return .{ .context = self, .fetch = fetch };
    }

    pub fn hash_of(number: u64) Hash {
        var bytes: [20 + 8]u8 = undefined;
        @memcpy(bytes[0..20], "needlefish test blk ");
        std.mem.writeInt(u64, bytes[20..28], number, .big);
        return node.keccak256(&bytes);
    }

    fn fetch(context: *anyopaque, number: u64) anyerror!HeaderLink {
        const self: *SyntheticHeaders = @ptrCast(@alignCast(context));
        if (number > self.head_number) return error.BlockNotFound;
        return .{
            .number = number,
            .hash = hash_of(number),
            .parent_hash = if (number == 0) @splat(0) else hash_of(number - 1),
            .timestamp = number * 2,
            .state_root = if (number == self.head_number) self.state_root else @splat(0),
        };
    }
};

// The import.

/// Ticks the storage once (and lets IO complete): the caller's event loop.
pub const Driver = struct {
    context: *anyopaque,
    tick: *const fn (context: *anyopaque) void,
};

pub const Stats = struct {
    codes: u64 = 0,
    code_bytes: u64 = 0,
    accounts: u64 = 0,
    slots: u64 = 0,
    account_records: u64 = 0,
    storage_records: u64 = 0,
    /// Grid blocks the bulk loaders wrote (tables of all four trees).
    blocks_written: u64 = 0,
    /// Storage ticks while a loader was busy.
    busy_ticks: u64 = 0,
};

pub const Progress = struct {
    context: *anyopaque,
    report: *const fn (context: *anyopaque, stats: *const Stats) void,
};

/// Reports every this many accounts, and every this many slots.
pub const progress_accounts: u64 = 1 << 20;
pub const progress_slots: u64 = 1 << 22;

/// Test-only damage to the written state (mutation checks): a record is not written.
pub const Mutation = union(enum) {
    drop_account_root,
    drop_storage_record: u64,
};

pub const samples_max = 64;

pub const AccountSample = struct { key: Hash, account: flat_trees_module.Account };
pub const SlotSample = struct { owner: Hash, slot: Hash, word: u256 };

/// A reservoir sample of the streamed accounts and slots (deterministic).
pub const Samples = struct {
    accounts: [samples_max]AccountSample = undefined,
    accounts_seen: u64 = 0,
    slots: [samples_max]SlotSample = undefined,
    slots_seen: u64 = 0,
    prng: std.Random.DefaultPrng = .init(0x6e66_696d_706f_7274),

    /// Where the `seen`th item goes, or null when the reservoir keeps what it has.
    fn place(samples: *Samples, seen: u64) ?usize {
        if (seen < samples_max) return @intCast(seen);
        const index = samples.prng.random().uintLessThan(u64, seen + 1);
        return if (index < samples_max) @intCast(index) else null;
    }

    pub fn account_list(samples: *const Samples) []const AccountSample {
        return samples.accounts[0..@min(samples.accounts_seen, samples_max)];
    }

    pub fn slot_list(samples: *const Samples) []const SlotSample {
        return samples.slots[0..@min(samples.slots_seen, samples_max)];
    }
};

/// Ticks one loader-busy or phase wait may take at most before the import gives up.
pub const busy_ticks_max: u32 = 1 << 24;

pub fn ImporterType(comptime Storage: type) type {
    return struct {
        const Importer = @This();
        pub const Database = database.DatabaseType(Storage);
        pub const FlatTrees = Database.FlatTrees;

        allocator: std.mem.Allocator,
        db: *Database,
        driver: Driver,
        progress: ?Progress = null,
        mutation: ?Mutation = null,
        stats: Stats = .{},
        samples: Samples = .{},
        /// The first failure inside the record sink (it cannot return errors).
        failure: ?anyerror = null,

        fn trees(self: *Importer) *FlatTrees {
            return &self.db.flat.?;
        }

        fn tick(self: *Importer) void {
            self.driver.tick(self.driver.context);
        }

        fn tick_until(self: *Importer, comptime done: fn (*const Database) bool) !void {
            var ticks: u32 = 0;
            while (!done(self.db)) : (ticks += 1) {
                if (ticks >= busy_ticks_max) return error.Timeout;
                self.tick();
            }
            assert(done(self.db));
        }

        fn not_formatting(db: *const Database) bool {
            return db.phase != .formatting;
        }

        fn not_opening(db: *const Database) bool {
            return db.phase != .opening;
        }

        fn settled(db: *const Database) bool {
            return !db.checkpoint_wanted and db.engine.checkpoint_phase == .idle and db.idle();
        }

        /// Writes an empty database and opens it (disk mode, nothing loaded).
        pub fn format(self: *Importer, format_id: u128) !void {
            assert(self.db.phase == .closed);
            assert(self.db.config.disk_state != null);
            self.db.format(format_id);
            try self.tick_until(not_formatting);
            try open(self.db, self.driver);
            assert(!self.db.head_info.present);
        }

        /// Opens a database (`phase` closed) and drives it until ready.
        pub fn open(db: *Database, driver: Driver) !void {
            assert(db.phase == .closed);
            db.open();
            var ticks: u32 = 0;
            while (db.phase == .opening) : (ticks += 1) {
                if (ticks >= busy_ticks_max) return error.Timeout;
                driver.tick(driver.context);
            }
            if (db.open_error) |err| return err;
            if (db.phase != .ready) return error.OpenFailed;
        }

        /// Loads every `Bytecodes` entry into the state's code arena, each checked against its
        /// key (keccak256 of the code).
        pub fn load_codes(self: *Importer, codes: EntrySource) !void {
            const state = &self.db.state;
            const codes_max = state.config.codes_max;
            while (try codes.next(codes.context)) |entry| {
                if (self.stats.codes >= codes_max) return error.CodeFull;
                if (entry.key.len != 32) return error.Corrupt;
                const code = try reth.decode_bytecode(entry.value);
                const hash = node.keccak256(code);
                if (!std.mem.eql(u8, &hash, entry.key)) return error.CodeHashMismatch;
                // reth may keep the empty code; the state never stores zero-length code, so
                // `stats.codes` counts the codes stored (what a reopen loads).
                if (code.len == 0) continue;
                const inserted = try state.insert_code(code);
                assert(std.mem.eql(u8, &inserted.hash, &hash));
                self.stats.codes += 1;
                self.stats.code_bytes += code.len;
            }
            assert(self.stats.codes <= codes_max);
        }

        /// Streams the hashed state into the four trees by bulk load; returns its root.
        pub fn load_state(self: *Importer, accounts: EntrySource, storages: EntrySource) !Hash {
            assert(self.db.phase == .ready and !self.db.head_info.present);
            const Scratch = struct {
                builder: state_root_module.StateRootBuilder,
                sinks: state_root_module.RecordSinks,
            };
            const scratch = try self.allocator.create(Scratch);
            defer self.allocator.destroy(scratch);
            scratch.builder = .{};
            scratch.sinks = .{ .target = .{ .context = self, .emit = on_record } };
            scratch.builder.set_record_sink(&scratch.sinks);
            try self.trees().bulk_begin(self.allocator);
            const leaves: hashed_state.LeafSink = .{
                .context = self,
                .slot = on_slot,
                .account = on_account,
            };
            const root = hashed_state.compute(
                &scratch.builder,
                accounts,
                storages,
                null,
                leaves,
            ) catch |err| return self.failure orelse err;
            if (self.failure) |err| return err;
            assert(self.stats.accounts == scratch.builder.stats.accounts);
            assert(self.stats.slots == scratch.builder.stats.slots);
            try self.bulk_close();
            return root;
        }

        fn on_bulk_finished(_: *FlatTrees) void {}

        fn bulk_close(self: *Importer) !void {
            const trees_ = self.trees();
            trees_.bulk_finish(on_bulk_finished);
            var ticks: u32 = 0;
            while (trees_.bulk.?.pending > 0) : (ticks += 1) {
                if (ticks >= busy_ticks_max) return error.Timeout;
                self.tick();
                trees_.bulk_poll();
            }
            self.stats.blocks_written = blocks_written(trees_);
            try trees_.bulk_end(self.allocator);
            assert(trees_.bulk == null);
        }

        fn blocks_written(trees_: *FlatTrees) u64 {
            const bulk = trees_.bulk.?;
            return bulk.accounts.stats.blocks_written + bulk.storage.stats.blocks_written +
                bulk.account_branches.stats.blocks_written +
                bulk.storage_branches.stats.blocks_written;
        }

        /// Calls a bulk append, ticking the storage while the loader is busy.
        fn append(self: *Importer, comptime function: anytype, args: anytype) !void {
            var ticks: u32 = 0;
            while (ticks < busy_ticks_max) : (ticks += 1) {
                if (@call(.auto, function, args)) |_| {
                    return;
                } else |err| switch (err) {
                    error.Busy => {
                        self.stats.busy_ticks += 1;
                        self.tick();
                        self.trees().bulk_poll();
                    },
                    else => return err,
                }
            }
            return error.Timeout;
        }

        fn on_record(
            context: *anyopaque,
            owner: ?*const Hash,
            hang: []const u8,
            branch: *const BranchNode,
        ) void {
            const self: *Importer = @ptrCast(@alignCast(context));
            if (self.failure != null) return;
            self.append_record(owner, hang, branch) catch |err| {
                self.failure = err;
            };
        }

        fn append_record(
            self: *Importer,
            owner: ?*const Hash,
            hang: []const u8,
            branch: *const BranchNode,
        ) !void {
            var buffer: [branch_record.value_bytes_max]u8 = undefined;
            const value = branch_record.encode(branch, &buffer);
            assert(value.len >= 1 and value.len <= branch_record.value_bytes_max);
            if (owner) |hash| {
                const index = self.stats.storage_records;
                self.stats.storage_records += 1;
                if (self.mutation) |mutation| switch (mutation) {
                    .drop_storage_record => |dropped| if (dropped == index) return,
                    .drop_account_root => {},
                };
                const key = branch_record.storage_key(hash, hang);
                const trees_ = self.trees();
                try self.append(FlatTrees.bulk_append_storage_branch, .{ trees_, &key, value });
            } else {
                self.stats.account_records += 1;
                if (self.mutation) |mutation| switch (mutation) {
                    .drop_account_root => if (hang.len == 0) return,
                    .drop_storage_record => {},
                };
                const key = branch_record.path_key(hang);
                const trees_ = self.trees();
                try self.append(FlatTrees.bulk_append_account_branch, .{ trees_, &key, value });
            }
        }

        fn on_slot(
            context: *anyopaque,
            address_hash: *const Hash,
            slot_hash: *const Hash,
            word: u256,
        ) anyerror!void {
            const self: *Importer = @ptrCast(@alignCast(context));
            if (self.failure) |err| return err;
            assert(word != 0);
            const trees_ = self.trees();
            try self.append(FlatTrees.bulk_append_slot, .{ trees_, address_hash, slot_hash, word });
            if (self.samples.place(self.stats.slots)) |index| {
                self.samples.slots[index] = .{
                    .owner = address_hash.*,
                    .slot = slot_hash.*,
                    .word = word,
                };
            }
            self.stats.slots += 1;
            self.samples.slots_seen = self.stats.slots;
            if (self.stats.slots % progress_slots == 0) self.report();
        }

        fn on_account(
            context: *anyopaque,
            address_hash: *const Hash,
            account: *const state_root_module.Account,
            storage_root: *const Hash,
        ) anyerror!void {
            const self: *Importer = @ptrCast(@alignCast(context));
            if (self.failure) |err| return err;
            // The evm fails a call into an account whose code is missing.
            if (self.db.state.code_by_hash(account.code_hash) == null) return error.CodeMissing;
            const record: flat_trees_module.Account = .{
                .info = .{
                    .nonce = account.nonce,
                    .balance = account.balance,
                    .code_hash = account.code_hash,
                },
                .storage_root = storage_root.*,
            };
            const trees_ = self.trees();
            try self.append(FlatTrees.bulk_append_account, .{ trees_, address_hash, &record });
            if (self.samples.place(self.stats.accounts)) |index| {
                self.samples.accounts[index] = .{ .key = address_hash.*, .account = record };
            }
            self.stats.accounts += 1;
            self.samples.accounts_seen = self.stats.accounts;
            if (self.stats.accounts % progress_accounts == 0) self.report();
        }

        fn report(self: *Importer) void {
            const progress = self.progress orelse return;
            if (self.trees().bulk != null) self.stats.blocks_written = blocks_written(self.trees());
            progress.report(progress.context, &self.stats);
        }

        /// Makes header N the head with `state_root` (which must be its `stateRoot`), its
        /// chain the block hashes, and writes a checkpoint (durable when this returns).
        pub fn commit_head(self: *Importer, chain: *const HeaderChain, state_root: Hash) !void {
            const head = chain.head();
            if (!std.mem.eql(u8, &head.state_root, &state_root)) return error.StateRootMismatch;
            for (chain.links[0..chain.len]) |*link| {
                self.db.state.set_block_hash(link.number, link.hash);
            }
            _ = try self.db.import_head(.{
                .hash = head.hash,
                .parent_hash = head.parent_hash,
                .number = head.number,
                .timestamp = head.timestamp,
            }, state_root);
            var ticks: u32 = 0;
            while (!settled(self.db)) : (ticks += 1) {
                if (ticks >= busy_ticks_max) return error.Timeout;
                self.db.checkpoint_flush();
                self.tick();
            }
            if (self.db.checkpoint_error) |err| return err;
            assert(self.db.head_info.present and self.db.head_info.number == head.number);
        }

        /// The whole import into a closed, unformatted database: format and open, codes,
        /// state, then the head. Returns the state root (header N's).
        pub fn run(
            self: *Importer,
            format_id: u128,
            codes: EntrySource,
            accounts: EntrySource,
            storages: EntrySource,
            chain: *const HeaderChain,
        ) !Hash {
            try self.format(format_id);
            try self.load_codes(codes);
            const root = try self.load_state(accounts, storages);
            self.report();
            try self.commit_head(chain, root);
            assert(std.mem.eql(u8, &self.db.head_info.state_root, &root));
            return root;
        }

        /// Reads every sample back through the trie of an opened database (`DiskState.
        /// verify_leaf`) and the flat trees; any difference is `error.SampleMismatch`, a
        /// record that does not resolve `error.StateCorrupt`.
        pub fn verify_samples(db: *Database, samples: *const Samples) !void {
            const disk = &db.disk.?;
            for (samples.account_list()) |*sample| {
                const leaf = disk.verify_leaf(&sample.key, null) catch return error.StateCorrupt;
                const account = leaf.account orelse return error.SampleMismatch;
                const expected = sample.account;
                if (account.nonce != expected.info.nonce or
                    account.balance != expected.info.balance or
                    !std.mem.eql(u8, &account.code_hash, &expected.info.code_hash) or
                    !std.mem.eql(u8, &account.storage_root, &expected.storage_root))
                {
                    return error.SampleMismatch;
                }
                const record = disk.account(&sample.key) orelse return error.SampleMismatch;
                if (!record.eql(expected)) return error.SampleMismatch;
                // The code came back from the code tables at its arena offset.
                const code = db.state.code_by_hash(account.code_hash) orelse
                    return error.CodeMissing;
                const code_hash = node.keccak256(code);
                if (!std.mem.eql(u8, &code_hash, &account.code_hash)) return error.SampleMismatch;
            }
            for (samples.slot_list()) |*sample| {
                const leaf = disk.verify_leaf(&sample.owner, &sample.slot) catch
                    return error.StateCorrupt;
                if (leaf.word != sample.word) return error.SampleMismatch;
                if (disk.storage(&sample.owner, &sample.slot) != sample.word) {
                    return error.SampleMismatch;
                }
            }
        }
    };
}

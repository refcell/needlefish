//! Durable node state: the trie-db lane's `db.database` (journal + checkpoints over a sector
//! storage) owns the world `State`; the node's `StateDb` executes on it (`init_shared`), and
//! the chain journals through `journal()`:
//! - a stored block is committed right after execution with `commit_applied` (its changeset
//!   is already applied), one `block_and_head` entry per block;
//! - every other state move (reorg, build on another parent) is `set_head`, which unwinds
//!   and applies stored changesets instead of re-executing.
//! The database head is therefore always the block whose post-state the state holds.
//! With `Config.history` set, `Journal.proof` serves `eth_getProof` at blocks of the
//! database's history window (`Database.proof_at`).
//!
//! Lifecycle (storage callbacks only run from the caller's storage tick):
//! `start` opens the storage, formatting it first when it holds no database, and reports
//! `ready`. A fresh database gets the genesis allocation as block 0 (`bootstrap`). On a
//! restart `retained` lists the canonical blocks for `Chain.restore`.
//!
//! The format id carries the genesis hash prefix in its high 64 bits, so a datadir written
//! for another chain is refused instead of silently reused.

const std = @import("std");
const assert = std.debug.assert;
const db_module = @import("../db/root.zig");
const genesis_module = @import("../../common/genesis/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const evm = @import("../evm/root.zig");
const chain_module = @import("chain.zig");
const StateTrie = @import("../trie/state_trie.zig").StateTrie;

const Hash = [32]u8;
const BlockInput = db_module.database.BlockInput;

pub const Phase = enum { idle, formatting, opening, ready, failed };

pub const StartError = error{ WrongChain, OpenFailed };

pub fn Durable(comptime Storage: type) type {
    return struct {
        const Self = @This();
        pub const Database = db_module.database.DatabaseType(Storage);

        database: Database,
        genesis_hash: Hash,
        format_nonce: u64,
        phase: Phase = .idle,
        start_error: ?StartError = null,

        /// Heap-pinned: the state and the storage callbacks hold pointers into it.
        pub fn create(
            allocator: std.mem.Allocator,
            storage: *Storage,
            config: db_module.database.Config,
            genesis_hash: Hash,
            format_nonce: u64,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            self.* = .{
                .database = try Database.init(allocator, storage, config),
                .genesis_hash = genesis_hash,
                .format_nonce = format_nonce,
            };
            return self;
        }

        pub fn destroy(self: *Self, allocator: std.mem.Allocator) void {
            self.database.deinit(allocator);
            allocator.destroy(self);
        }

        pub fn state(self: *Self) *db_module.State {
            return &self.database.state;
        }

        fn format_id(self: *const Self) u128 {
            const prefix = std.mem.readInt(u64, self.genesis_hash[0..8], .big);
            return @as(u128, prefix) << 64 | self.format_nonce;
        }

        /// Opens the database; drive the storage until `phase` leaves `opening`/`formatting`.
        pub fn start(self: *Self) void {
            assert(self.phase == .idle);
            self.phase = .opening;
            self.database.open();
        }

        /// Advances the open/format state machine; call after storage ticks.
        pub fn poll(self: *Self) void {
            switch (self.phase) {
                .opening => self.poll_opening(),
                .formatting => if (self.database.phase == .closed) {
                    self.phase = .opening;
                    self.database.open();
                },
                .ready => self.maintain(),
                .idle, .failed => {},
            }
        }

        fn poll_opening(self: *Self) void {
            switch (self.database.phase) {
                .opening => return,
                .ready => {
                    const working = &self.database.engine.superblock.working;
                    const chain_prefix: u64 = @truncate(working.format_id >> 64);
                    const expected: u64 = @truncate(self.format_id() >> 64);
                    if (chain_prefix != expected) return self.fail(error.WrongChain);
                    self.phase = .ready;
                },
                .closed => {
                    const open_error = self.database.open_error orelse error.SuperBlockConflict;
                    const missing = open_error == error.SuperBlockMissing;
                    if (!missing) return self.fail(error.OpenFailed);
                    self.phase = .formatting;
                    self.database.open_error = null;
                    self.database.format(self.format_id());
                },
                .failed, .formatting => self.fail(error.OpenFailed),
            }
        }

        fn fail(self: *Self, err: StartError) void {
            self.phase = .failed;
            self.start_error = err;
        }

        /// Checkpoints before the journal fills, so commits never meet a full journal.
        fn maintain(self: *Self) void {
            const database = &self.database;
            if (database.phase != .ready or database.checkpoint_wanted) return;
            const ring = &database.engine.journal;
            const used = ring.head - ring.tail + database.journal_bytes_pending;
            if (used * 2 > ring.config.zone_size_bytes) database.request_checkpoint();
        }

        pub fn has_head(self: *const Self) bool {
            assert(self.phase == .ready);
            return self.database.head_info.present;
        }

        /// Commits the genesis allocation as block 0 of a fresh database. Allocates a
        /// temporary overlay sized from the allocation (startup only).
        pub fn bootstrap(
            self: *Self,
            allocator: std.mem.Allocator,
            parsed: *const genesis_module.Genesis,
            header: *const consensus.Header,
        ) !Hash {
            assert(self.phase == .ready and !self.has_head());
            var slots: u32 = 0;
            for (parsed.accounts) |*account| slots += @intCast(account.storage.len);
            const accounts: u32 = @intCast(parsed.accounts.len);
            var overlay = try db_module.Overlay.init(allocator, self.state(), .{
                .accounts_max = @max(accounts, 1),
                .slots_max = @max(slots, 1),
                .codes_max = @max(accounts, 1),
            });
            defer overlay.deinit(allocator);
            for (parsed.accounts) |*account| try write_account(&overlay, account);
            var header_buffer: [1024]u8 = undefined;
            var encoder = rlp.Encoder.init(&header_buffer);
            rlp.encode(&encoder, header.*);
            const hash = header.hash().bytes;
            const input: BlockInput = .{
                .hash = hash,
                .parent_hash = @splat(0),
                .number = header.number,
                .timestamp = header.timestamp,
                .header = encoder.written(),
                .body = &.{},
                .receipts = &.{},
                .transaction_hashes = &.{},
                .changeset = &.{},
            };
            const commit = try self.database.execute_and_commit(&overlay, &input);
            if (!std.mem.eql(u8, &commit.state_root, &header.state_root.bytes)) {
                return error.StateRootMismatch;
            }
            return hash;
        }

        fn write_account(overlay: *db_module.Overlay, account: anytype) !void {
            const address = account.address.bytes;
            const code_hash = if (account.code.len == 0)
                evm.primitives.keccak_empty
            else
                try overlay.insert_code(account.code);
            try overlay.set_account(address, .{
                .nonce = account.nonce,
                .balance = account.balance,
                .code_hash = code_hash,
            });
            for (account.storage) |slot| {
                const key = std.mem.readInt(u256, &slot.key.bytes, .big);
                if (slot.value != 0) try overlay.set_storage(address, key, slot.value);
            }
        }

        /// Canonical block records from the oldest retained to the head (into `out`,
        /// newest last). Genesis (stored without a record) is skipped.
        pub fn retained(self: *const Self, out: [][]const u8) [][]const u8 {
            assert(self.phase == .ready and self.has_head());
            const chain = &self.database.chain;
            var hash = self.database.head_info.hash;
            var count: usize = 0;
            while (count < out.len) {
                const view = chain.block(hash) orelse break;
                if (view.body.len == 0) break; // Genesis.
                out[count] = view.body;
                count += 1;
                hash = view.meta.parent_hash;
            }
            std.mem.reverse([]const u8, out[0..count]);
            return out[0..count];
        }

        pub fn journal(self: *Self) chain_module.Journal {
            return .{
                .context = self,
                .commit_block = commit_block,
                .move_head = move_head,
                .witness = witness,
                .proof = if (self.database.history != null) proof else null,
                .history_window = if (self.database.history != null) history_window else null,
            };
        }

        fn history_window(context: *anyopaque) ?chain_module.HistoryWindow {
            const self = from(context);
            const store = &(self.database.history orelse return null);
            const window = store.window() orelse return null;
            assert(window.oldest <= window.head);
            return .{ .oldest = window.oldest, .head = window.head };
        }

        /// Historical `eth_getProof` from the database's history window. The database's
        /// canonical index decides whether `hash` is the block at `number`.
        fn proof(
            context: *anyopaque,
            hash: Hash,
            number: u64,
            address: [20]u8,
            slots: []const u256,
            account_proof: *StateTrie.AccountProof,
            storage_proofs: []StateTrie.StorageProof,
            values: []u256,
        ) db_module.database.ProofError!?db_module.history.AccountState {
            const self = from(context);
            assert(self.phase == .ready);
            assert(slots.len == storage_proofs.len and slots.len == values.len);
            const database = &self.database;
            const canonical = database.chain.canonical_hash(number) orelse
                return error.HistoryUnavailable;
            if (!std.mem.eql(u8, &canonical, &hash)) return error.HistoryUnavailable;
            return database.proof_at(number, address, slots, account_proof, storage_proofs, values);
        }

        /// From the history window when it holds the block's parent (state untouched), else
        /// the database's state moves to the block's parent in memory (no journal entry) and
        /// back; see `db.witness_block`.
        fn witness(
            context: *anyopaque,
            generator: *db_module.witness_block.Generator,
            hash: Hash,
            execute: db_module.witness_block.Execute,
        ) db_module.witness_block.Error!Hash {
            const self = from(context);
            assert(self.phase == .ready);
            const head = self.database.head_info;
            const root = try generator.database_witness(&self.database, hash, execute);
            assert(head.eql(self.database.head_info));
            return root;
        }

        fn from(context: *anyopaque) *Self {
            return @ptrCast(@alignCast(context));
        }

        fn commit_block(
            context: *anyopaque,
            block: *const chain_module.JournalBlock,
        ) chain_module.JournalError!void {
            const self = from(context);
            const input: BlockInput = .{
                .hash = block.hash,
                .parent_hash = block.parent_hash,
                .number = block.number,
                .timestamp = block.timestamp,
                .header = block.header,
                .body = block.record,
                .receipts = &.{},
                .transaction_hashes = &.{},
                .changeset = block.changeset,
            };
            _ = self.database.commit_applied(&input) catch |err| return map_error(err);
            assert(std.mem.eql(u8, &self.database.head_info.hash, &block.hash));
        }

        fn move_head(context: *anyopaque, hash: Hash) chain_module.JournalError!void {
            const self = from(context);
            _ = self.database.set_head(hash) catch |err| return map_error(err);
            assert(std.mem.eql(u8, &self.database.head_info.hash, &hash));
        }

        fn map_error(err: db_module.database.OperationError) chain_module.JournalError {
            return switch (err) {
                error.Busy => error.JournalBusy,
                else => error.JournalFailed,
            };
        }
    };
}

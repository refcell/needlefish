//! Executes blocks N+1, N+2, ... on a disk-mode database (disk-state import plan step 11):
//! the entry point a catch-up block source (JSON-RPC, devp2p) feeds once `to_disk` has
//! imported head N.
//!
//! `Runner.execute(block)` takes one block bound to its hash (`Block`: the shape of
//! `bin/base/el_source.zig`'s block; `follow.follower.decode_block` gives the same fields).
//! It refuses (an error, nothing touched) a header that does not hash to `block.hash`, or a
//! block that is not the child of the database head. Otherwise it executes the block with the
//! node's executor over the database's state (`StateDb.init_shared`: the changes go through
//! `State.apply` into the flat trees), then checks every header field needlefish recomputes,
//! in `Check` order: transactions root, gas used, logs bloom, blob gas used (Jovian DA
//! footprint), receipts root, state root, the Isthmus withdrawals root (the
//! L2ToL1MessagePasser's storage root, `State.storage_root`), and the hash of the header
//! resealed with all of them. A block that passes is journaled with `commit_applied` (one
//! `block_and_head` entry: header and changeset; transactions and receipts are not stored).
//! A block that fails a check or does not execute leaves the database head and state as they
//! were (`StateDb.rollback` unwinds an applied block) and its `Outcome` names the first
//! failed check, or the execution error.
//!
//! Prefetch: when the flat trees have a prefetcher (`db/prefetch.zig`), each attempt first
//! reads the blocks of the state the block will likely touch into the block cache, many at
//! once, while checkpoints are held: the beneficiary, the fee vaults and L1Block, each
//! transaction's sender (recovered ahead on the executor's recovery pool), recipient,
//! deposit `from`, and access list (accounts and slots). Execution's synchronous reads then
//! hit the cache. The executor's commit (the runner is its backend, over the StateDb) does
//! the same first for the branch records the root update will resolve: the trie paths of
//! the block's dirty accounts and slots, and of the slots' owners. Best effort: results
//! never depend on what was prefetched. `Config.prefetching` turns the commit's prefetch,
//! or both, off.
//!
//! Busy: a block is held (`hold_checkpoints`) from execution to its journal entry, so no
//! checkpoint can start in between. Before each block the runner therefore makes room for
//! the journal entry and for the branch writes of the block and of a rollback (the database's
//! replay admission), ticking the storage and asking for checkpoints until there is. A
//! `Busy` that still happens (memtable room: compaction is granted) unwinds the attempt and
//! retries the block after the storage quiets down, a bounded number of times.
//!
//! Durability: a commit is durable once the storage has written its entry (`flush`, or later
//! ticks); a crash loses only the blocks after the durable prefix, and the database reopens
//! at a block this runner committed. Library code: every storage tick goes through the
//! caller's `to_disk.Driver`.

const std = @import("std");
const assert = std.debug.assert;

const to_disk = @import("to_disk.zig");
const room_module = @import("room.zig");
const database = @import("../db/database.zig");
const state_module = @import("../db/state.zig");
const executor_module = @import("../node/executor.zig");
const state_db_module = @import("../node/state_db.zig");
const node_chain = @import("../node/chain.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const trie = @import("../trie/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const evm = @import("../evm/root.zig");

const Hash = [32]u8;
const Address = [20]u8;
const Header = consensus.Header;
const State = state_module.State;
const StateDb = state_db_module.StateDb;
const Executor = executor_module.Executor;
const keccak256 = trie.node.keccak256;

pub const l2_to_l1_message_passer: Address =
    primitives.hex.decode_array(20, "4200000000000000000000000000000000000016") catch
        unreachable; // A valid 40-digit literal.

/// One block, bound to its hash by its source (`header_rlp` must hash to `hash`; the runner
/// checks it again). `transactions` are EIP-2718 encodings, valid for the call.
pub const Block = struct {
    number: u64,
    hash: Hash,
    header_rlp: []const u8,
    transactions: []const []const u8,
};

/// A header field needlefish recomputes, in check order.
pub const Check = enum(u8) {
    transactions_root,
    gas_used,
    logs_bloom,
    blob_gas_used,
    receipts_root,
    state_root,
    withdrawals_root,
    block_hash,
};

pub const check_count = @typeInfo(Check).@"enum".field_names.len;
const all_checks: u16 = (1 << check_count) - 1;

comptime {
    assert(check_count <= 16);
}

pub const Outcome = struct {
    number: u64,
    hash: Hash,
    transactions: u32,
    /// Gas the execution used (the header's when execution failed).
    gas_used: u64,
    expected_state_root: Hash,
    /// Zero when execution failed.
    computed_state_root: Hash = @splat(0),
    /// Bit `@intFromEnum(check)` set: that field matched.
    passed: u16 = 0,
    /// Execution failed (an invalid block, or a state that could not be read): no checks ran.
    failure: ?anyerror = null,
    /// Index of the transaction execution failed on, if any.
    failed_transaction: ?u32 = null,
    /// The journal sequence of the commit; 0 when the block was not committed.
    sequence: u64 = 0,
    /// The block's receipts when it executed (one per transaction), valid until the runner's
    /// next block or the next use of its executor (`Runner.executor`).
    receipts: []const consensus.Receipt = &.{},

    pub fn ok(outcome: *const Outcome) bool {
        return outcome.failure == null and outcome.passed == all_checks;
    }

    pub fn check(outcome: *const Outcome, which: Check) bool {
        return outcome.passed & (@as(u16, 1) << @as(u4, @intCast(@backingInt(which)))) != 0;
    }

    /// The first check that failed, in check order (null when all passed).
    pub fn first_failed(outcome: *const Outcome) ?Check {
        inline for (@typeInfo(Check).@"enum".field_names) |name| {
            const which = @field(Check, name);
            if (!outcome.check(which)) return which;
        }
        return null;
    }
};

pub const Error = error{
    /// The database is not open and ready, or has no head.
    NotReady,
    /// The header does not decode, or its number is not `block.number`.
    InvalidHeader,
    /// keccak256(header_rlp) is not `block.hash`.
    HashMismatch,
    /// The block is not the child of the database head (number or parent hash).
    NotNextBlock,
    /// The storage did not make room within its bound (ticks or attempts).
    Stalled,
    CheckpointFailed,
} || database.OperationError || state_db_module.Error;

/// Which prefetches the runner makes (see the file comment): `all` both, `tx` only the one
/// before execution (no trie paths before the commit), `none` neither. Results never change.
pub const Prefetching = enum { all, tx, none };

pub const Config = struct {
    executor: executor_module.Config,
    /// Times the phases into `Stats.time` (and the executor's `last_phases`); none: zeros.
    clock: ?Executor.Clock = null,
    prefetching: Prefetching = .all,
};

/// Accounts every Base block touches: the fee vaults and the L1Block predeploy.
const system_accounts = [_]Address{
    evm.op.sequencer_fee_vault,
    evm.op.base_fee_vault,
    evm.op.l1_fee_vault,
    evm.op.operator_fee_vault,
    evm.op.l1_block_address,
};

/// Summed wall time per phase of the committed blocks, under `Config.clock`.
pub const Time = struct {
    /// Pre-block system calls and the state cache reset.
    pre_block_ns: u64 = 0,
    /// Sender recovery (inline, or waiting for the recovery workers).
    recovery_ns: u64 = 0,
    /// The transactions themselves (execution minus pre-block and recovery).
    transactions_ns: u64 = 0,
    post_block_ns: u64 = 0,
    receipts_root_ns: u64 = 0,
    /// Folding the block into the state: on disk, the sparse root and record write-back.
    commit_ns: u64 = 0,
    state_root_ns: u64 = 0,
    /// The header checks after execution.
    check_ns: u64 = 0,
    /// `commit_applied`: the journal entry and the head move.
    journal_ns: u64 = 0,
    /// Waiting for storage room (checkpoints, compaction) before the block.
    room_ns: u64 = 0,
    /// Naming the block's likely keys and reading their blocks ahead (every attempt).
    prefetch_ns: u64 = 0,
};

pub const Stats = struct {
    blocks: u64 = 0,
    /// Attempts that met `Busy` and were retried.
    busy_retries: u64 = 0,
    /// Making room before each attempt (`room.zig`): waits, causes, checkpoints asked for.
    room: room_module.Stats = .{},
    /// Storage ticks spent making room, quieting, or rolling back.
    ticks: u64 = 0,
    time: Time = .{},
};

/// Attempts per block before the runner gives up (`Stalled`).
pub const attempts_max: u32 = 64;
/// Ticks one wait (room, rollback, flush) may take.
pub const ticks_max: u32 = to_disk.busy_ticks_max;
comptime {
    assert(room_module.ticks_max == ticks_max);
}
/// Ticks a wait for quiet storage takes at most before the next attempt.
const quiet_ticks_max: u32 = 1 << 20;

/// Checks every recomputed header field of a block executed over `state` (committed) and
/// the hash of the header resealed with them. Bit `@intFromEnum(check)` set: it matched.
pub fn check_header(
    spec: *const chainspec.ChainSpec,
    state: *State,
    header: *const Header,
    hash: *const Hash,
    transactions: []const []const u8,
    executed: *const executor_module.Executed,
) u16 {
    var sealed = header.*;
    sealed.transactions_root = .{ .bytes = trie.ordered.ordered_trie_root(transactions) };
    sealed.gas_used = executed.gas_used;
    sealed.logs_bloom = executed.logs_bloom;
    if (header.blob_gas_used != null) sealed.blob_gas_used = executed.blob_gas_used;
    sealed.receipts_root = .{ .bytes = executed.receipts_root };
    sealed.state_root = .{ .bytes = executed.state_root };
    if (spec.is_upgrade_active(.isthmus, header.timestamp)) {
        sealed.withdrawals_root = .{ .bytes = state.storage_root(l2_to_l1_message_passer) };
    }
    const results = [check_count]bool{
        sealed.transactions_root.eql(header.transactions_root),
        sealed.gas_used == header.gas_used,
        sealed.logs_bloom.eql(header.logs_bloom),
        std.meta.eql(sealed.blob_gas_used, header.blob_gas_used),
        sealed.receipts_root.eql(header.receipts_root),
        sealed.state_root.eql(header.state_root),
        std.meta.eql(sealed.withdrawals_root, header.withdrawals_root),
        std.mem.eql(u8, &sealed.hash().bytes, hash),
    };
    var passed: u16 = 0;
    for (results, 0..) |matched, bit| {
        if (matched) passed |= @as(u16, 1) << @intCast(bit);
    }
    assert(passed <= all_checks);
    assert(results[check_count - 1] == (passed >> (check_count - 1) == 1));
    return passed;
}

/// The largest encoded changeset of a block under `config` (the undo ring holds one).
fn changeset_bytes_max(config: @import("../db/changeset.zig").Config) u64 {
    const bytes = 18 + @as(u64, config.accounts_max) * (21 + 2 * 72) +
        @as(u64, config.storage_max) * 116 + @as(u64, config.codes_max) * 4 +
        config.code_bytes_max;
    assert(bytes > config.code_bytes_max);
    return bytes;
}

pub fn RunnerType(comptime Storage: type) type {
    return struct {
        const Runner = @This();
        pub const Database = database.DatabaseType(Storage);
        const Room = room_module.RoomType(Database);
        pub const Prefetch = Database.FlatTrees.Prefetch;

        /// Names a block's prefetch keys in place of the runner's own hints (tests): before
        /// execution (`block`), and before the commit (`block` null).
        pub const Hinter = struct {
            context: *anyopaque,
            hint: *const fn (context: *anyopaque, prefetch: *Prefetch, block: ?*const Block) void,
        };

        db: *Database,
        spec: *const chainspec.ChainSpec,
        driver: to_disk.Driver,
        state_db: StateDb,
        executor: Executor,
        stats: Stats = .{},
        clock: ?Executor.Clock = null,
        hinter: ?Hinter = null,
        prefetching: Prefetching = .all,

        /// Executes on `db`, an open disk-mode database with a head (an import's head N or
        /// a block this runner committed). Heap-pinned: the executor points at the StateDb.
        /// Destroy it before the database is closed or reopened.
        pub fn create(
            allocator: std.mem.Allocator,
            db: *Database,
            spec: *const chainspec.ChainSpec,
            driver: to_disk.Driver,
            config: Config,
        ) !*Runner {
            assert(db.disk != null and db.config.history == null);
            assert(db.phase == .ready and db.head_info.present);
            const changeset = db.config.changeset;
            const undo_bytes = changeset_bytes_max(changeset);
            if (undo_bytes > std.math.maxInt(u32)) return error.ChangesetTooLarge;
            const self = try allocator.create(Runner);
            errdefer allocator.destroy(self);
            self.* = .{
                .db = db,
                .spec = spec,
                .driver = driver,
                .state_db = undefined,
                .executor = undefined,
            };
            self.state_db = try StateDb.init_shared(allocator, .{
                .block_accounts_max = changeset.accounts_max,
                .block_slots_max = changeset.storage_max,
                .block_codes_max = changeset.codes_max,
                .block_code_bytes_max = changeset.code_bytes_max,
                .undo_bytes_max = @intCast(undo_bytes),
                .undo_blocks_max = 2,
            }, &db.state);
            errdefer self.state_db.deinit(allocator);
            self.executor =
                try Executor.init_backend(allocator, spec, self.backend(), config.executor);
            self.executor.phase_clock = config.clock;
            self.clock = config.clock;
            self.prefetching = config.prefetching;
            return self;
        }

        pub fn destroy(self: *Runner, allocator: std.mem.Allocator) void {
            assert(!self.db.checkpoints_held);
            self.executor.deinit(allocator);
            self.state_db.deinit(allocator);
            allocator.destroy(self);
        }

        /// Executes, checks, and commits the next block (see the file comment). Errors are
        /// refusals and database failures; a block that executes is described by the
        /// outcome. Either way, unless `ok()`, the head and state are unchanged.
        pub fn execute(self: *Runner, block: *const Block) Error!Outcome {
            const db = self.db;
            if (db.phase != .ready or !db.head_info.present) return error.NotReady;
            const header = Header.decode(block.header_rlp) catch return error.InvalidHeader;
            if (header.number != block.number) return error.InvalidHeader;
            const hash = keccak256(block.header_rlp);
            if (!std.mem.eql(u8, &hash, &block.hash)) return error.HashMismatch;
            const head = db.head_info;
            if (block.number != head.number + 1) return error.NotNextBlock;
            if (!std.mem.eql(u8, &header.parent_hash.bytes, &head.hash)) {
                return error.NotNextBlock;
            }
            for (0..attempts_max) |_| {
                const room_start_ns = self.now_ns();
                try self.make_room();
                self.stats.time.room_ns += self.now_ns() -| room_start_ns;
                var outcome: Outcome = .{
                    .number = block.number,
                    .hash = block.hash,
                    .transactions = @intCast(block.transactions.len),
                    .gas_used = header.gas_used,
                    .expected_state_root = header.state_root.bytes,
                };
                if (try self.attempt(block, &header, &outcome)) {
                    const moved = std.mem.eql(u8, &db.head_info.hash, &block.hash);
                    assert(moved == outcome.ok());
                    assert(moved or db.head_info.eql(head));
                    self.stats.blocks += @intFromBool(moved);
                    return outcome;
                }
                assert(db.head_info.eql(head));
                self.stats.busy_retries += 1;
                self.wait_quiet();
            }
            return error.Stalled;
        }

        /// One try at a block: false when the database was busy (nothing changed: retry).
        fn attempt(
            self: *Runner,
            block: *const Block,
            header: *const Header,
            outcome: *Outcome,
        ) Error!bool {
            const db = self.db;
            assert(!db.checkpoints_held);
            // No code slice of an earlier block or attempt is in use: the executor's state
            // cache starts empty each block.
            db.codes_release();
            // The state holds the block before its entry is queued: no checkpoint between.
            db.hold_checkpoints(true);
            defer db.hold_checkpoints(false);
            // Held: no block a prefetch read names can be rewritten before the read lands.
            self.prefetch(block, header);
            // Base blocks carry an empty withdrawals list from Canyon on.
            const withdrawals: ?[]const payload.Withdrawal =
                if (header.withdrawals_root != null) &.{} else null;
            const env = node_chain.env_of(header);
            const transactions = block.transactions;
            const executor = &self.executor;
            const executed = executor.execute_block(&env, transactions, withdrawals) catch |err| {
                if (err == error.Busy) return false;
                outcome.failure = err;
                outcome.failed_transaction = executor.invalid_index;
                return true;
            };
            outcome.gas_used = executed.gas_used;
            outcome.computed_state_root = executed.state_root;
            outcome.receipts = executed.receipts;
            assert(executed.receipts.len == transactions.len);
            const check_start_ns = self.now_ns();
            outcome.passed = check_header(
                self.spec,
                &db.state,
                header,
                &block.hash,
                transactions,
                &executed,
            );
            const check_ns = self.now_ns() -| check_start_ns;
            if (!outcome.ok()) {
                try self.rollback();
                return true;
            }
            const journal_start_ns = self.now_ns();
            const sequence = try self.commit(block, header);
            outcome.sequence = sequence orelse return false;
            self.add_time(check_ns, self.now_ns() -| journal_start_ns);
            assert(std.mem.eql(u8, &db.head_info.state_root, &executed.state_root));
            return true;
        }

        /// Reads the blocks of the state `block` will likely touch into the block cache, all
        /// at once, ticking until done (bounded; an unfinished prefetch skips the next).
        fn prefetch(self: *Runner, block: *const Block, header: *const Header) void {
            if (self.prefetching == .none) return;
            const prefetch_state = self.db.flat.?.prefetch orelse return;
            if (prefetch_state.running) return;
            const start_ns = self.now_ns();
            prefetch_state.clear();
            if (self.hinter) |hinter| {
                hinter.hint(hinter.context, prefetch_state, block);
            } else {
                self.hint(prefetch_state, block, header);
            }
            self.prefetch_run(prefetch_state);
            self.stats.time.prefetch_ns += self.now_ns() -| start_ns;
        }

        fn prefetch_run(self: *Runner, prefetch_state: *Prefetch) void {
            assert(!prefetch_state.running);
            prefetch_state.start(&self.db.flat.?);
            var ticks: u32 = 0;
            while (prefetch_state.running and ticks < ticks_max) : (ticks += 1) self.tick();
            assert(ticks <= ticks_max);
        }

        /// The executor's backend: the StateDb, whose commit first prefetches.
        fn backend(self: *Runner) executor_module.Backend {
            return .{
                .context = self,
                .database = self.state_db.database(),
                .commit = backend_commit,
                .root = backend_root,
            };
        }

        fn backend_commit(
            context: *anyopaque,
            evm_state: *evm.State,
        ) executor_module.BackendError!void {
            const self: *Runner = @ptrCast(@alignCast(context));
            assert(self.db.checkpoints_held);
            self.prefetch_paths(evm_state);
            return self.state_db.commit(evm_state);
        }

        fn backend_root(context: *anyopaque) executor_module.BackendError!Hash {
            const self: *Runner = @ptrCast(@alignCast(context));
            assert(self.db.checkpoints_held);
            return self.state_db.root();
        }

        /// Reads ahead the branch records the commit's root update resolves: along the trie
        /// paths of the block's dirty accounts and slots, and of the slots' owners.
        fn prefetch_paths(self: *Runner, evm_state: *const evm.State) void {
            if (self.prefetching != .all) return;
            const prefetch_state = self.db.flat.?.prefetch orelse return;
            if (prefetch_state.running) return;
            const start_ns = self.now_ns();
            prefetch_state.clear();
            if (self.hinter) |hinter| {
                hinter.hint(hinter.context, prefetch_state, null);
            } else {
                var accounts = evm_state.accounts.iterator();
                while (accounts.next()) |entry| {
                    if (!entry.value_ptr.dirty) continue;
                    prefetch_state.add_path(null, &keccak256(entry.key_ptr));
                }
                var slots = evm_state.slots.iterator();
                while (slots.next()) |entry| {
                    if (!entry.value_ptr.dirty) continue;
                    const owner = keccak256(&entry.key_ptr.address);
                    var slot_bytes: [32]u8 = undefined;
                    std.mem.writeInt(u256, &slot_bytes, entry.key_ptr.slot, .big);
                    prefetch_state.add_path(&owner, &keccak256(&slot_bytes));
                    const account = evm_state.accounts.getPtr(entry.key_ptr.address);
                    const dirty = account != null and account.?.dirty;
                    if (!dirty) prefetch_state.add_path(null, &owner);
                }
            }
            self.prefetch_run(prefetch_state);
            self.stats.time.prefetch_ns += self.now_ns() -| start_ns;
        }

        /// The runner's hints (see the file comment). Senders come from the executor's
        /// recovery pool, which the block then adopts; without a pool they are not hinted.
        fn hint(
            self: *Runner,
            prefetch_state: *Prefetch,
            block: *const Block,
            header: *const Header,
        ) void {
            hint_account(prefetch_state, &header.beneficiary.bytes);
            for (&system_accounts) |*address| hint_account(prefetch_state, address);
            self.executor.prefetch(block.transactions);
            const senders = self.executor.prefetched_senders();
            if (senders) |list| assert(list.len == block.transactions.len);
            for (block.transactions, 0..) |raw, index| {
                if (senders) |list| {
                    if (list[index]) |sender| hint_account(prefetch_state, &sender.bytes);
                }
                const envelope = consensus.Envelope.decode(raw) catch continue;
                hint_transaction(prefetch_state, &envelope);
            }
        }

        fn hint_transaction(prefetch_state: *Prefetch, envelope: *const consensus.Envelope) void {
            if (envelope.* == .deposit) hint_account(prefetch_state, &envelope.deposit.from.bytes);
            switch (envelope.kind()) {
                .call => |to| hint_account(prefetch_state, &to.bytes),
                .create => {},
            }
            var items = envelope.access_list().iterator();
            while (items.next()) |item| {
                const address_hash = keccak256(&item.address.bytes);
                prefetch_state.add_account(&address_hash);
                for (0..item.storage_keys.count()) |index| {
                    const slot = item.storage_keys.get(index);
                    prefetch_state.add_slot(&address_hash, &keccak256(&slot.bytes));
                }
            }
        }

        fn hint_account(prefetch_state: *Prefetch, address: *const Address) void {
            prefetch_state.add_account(&keccak256(address));
        }

        fn now_ns(self: *const Runner) u64 {
            const clock = self.clock orelse return 0;
            return clock.read();
        }

        /// Adds the committed block's phases (the executor's, then the runner's own).
        fn add_time(self: *Runner, check_ns: u64, journal_ns: u64) void {
            const phases = &self.executor.last_phases;
            const execution_ns = self.executor.last_execution_ns;
            assert(phases.pre_block_ns + phases.recovery_ns <= execution_ns);
            const time = &self.stats.time;
            time.pre_block_ns += phases.pre_block_ns;
            time.recovery_ns += phases.recovery_ns;
            time.transactions_ns += execution_ns - phases.pre_block_ns - phases.recovery_ns;
            time.post_block_ns += phases.post_block_ns;
            time.receipts_root_ns += phases.receipts_root_ns;
            time.commit_ns += phases.commit_ns;
            time.state_root_ns += phases.state_root_ns;
            time.check_ns += check_ns;
            time.journal_ns += journal_ns;
            assert(self.clock != null or time.journal_ns == 0);
        }

        /// Journals the applied block; null when the database was busy (rolled back).
        fn commit(self: *Runner, block: *const Block, header: *const Header) Error!?u64 {
            const db = self.db;
            const input: database.BlockInput = .{
                .hash = block.hash,
                .parent_hash = header.parent_hash.bytes,
                .number = header.number,
                .timestamp = header.timestamp,
                .header = block.header_rlp,
                .body = &.{},
                .receipts = &.{},
                .transaction_hashes = &.{},
                .changeset = self.state_db.last_changeset().?, // This block's commit.
            };
            const committed = db.commit_applied(&input) catch |err| {
                // A failed database cannot unwind; any other refusal changed nothing.
                if (db.phase == .ready) try self.rollback();
                if (err == error.Busy) return null;
                return err;
            };
            assert(committed.sequence == db.submitted_sequence);
            assert(std.mem.eql(u8, &db.head_info.hash, &block.hash));
            return committed.sequence;
        }

        /// Unwinds the block just applied (the head never moved to it).
        fn rollback(self: *Runner) Error!void {
            const depth = self.state_db.undo_depth();
            assert(depth > 0);
            var ticks: u32 = 0;
            while (true) : (ticks += 1) {
                if (ticks >= ticks_max) return error.Stalled;
                self.state_db.rollback() catch |err| switch (err) {
                    error.Busy => {
                        self.tick();
                        continue;
                    },
                    else => return err,
                };
                break;
            }
            assert(self.state_db.undo_depth() == depth - 1);
            const root = try self.db.state.state_root();
            assert(std.mem.eql(u8, &root, &self.db.head_info.state_root));
        }

        fn tick(self: *Runner) void {
            self.stats.ticks += 1;
            self.driver.tick(self.driver.context);
        }

        /// Ticks until the next block has room (`room.zig`), counting the ticks.
        fn make_room(self: *Runner) Error!void {
            const driver: to_disk.Driver = .{ .context = self, .tick = tick_counted };
            Room.make_room(self.db, driver, self.clock, &self.stats.room) catch |err| {
                return switch (err) {
                    error.NotReady => error.NotReady,
                    error.CheckpointFailed => error.CheckpointFailed,
                    error.Stalled => error.Stalled,
                };
            };
            assert(Room.roomy(self.db));
            assert(!self.db.checkpoints_held);
        }

        fn tick_counted(context: *anyopaque) void {
            const self: *Runner = @ptrCast(@alignCast(context));
            self.tick();
        }

        /// No checkpoint wanted or running, nothing queued, no compaction pending.
        fn quiet(db: *Database) bool {
            if (db.checkpoint_wanted or db.engine.checkpoint_phase != .idle) return false;
            if (!db.idle()) return false;
            const trees = &db.flat.?;
            return trees.accounts.compaction_idle() and trees.storage.compaction_idle() and
                trees.account_branches.compaction_idle() and
                trees.storage_branches.compaction_idle();
        }

        /// After a busy attempt: let compactions and checkpoints run (bounded) before the
        /// next one.
        fn wait_quiet(self: *Runner) void {
            assert(!self.db.checkpoints_held);
            var ticks: u32 = 0;
            while (ticks < quiet_ticks_max and !quiet(self.db)) : (ticks += 1) self.tick();
            assert(ticks <= quiet_ticks_max);
        }

        /// Ticks until every committed block is durable (bounded).
        pub fn flush(self: *Runner) Error!void {
            const db = self.db;
            var ticks: u32 = 0;
            while (db.durable_sequence < db.submitted_sequence) : (ticks += 1) {
                if (db.phase != .ready) return error.NotReady;
                if (ticks >= ticks_max) return error.Stalled;
                self.tick();
            }
            assert(db.durable_sequence == db.submitted_sequence);
            assert(!db.checkpoints_held);
        }
    };
}

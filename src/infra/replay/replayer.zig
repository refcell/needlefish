//! Offline replay of real blocks over a stateless witness (`archive.Archive`).
//!
//! One `SparseState` holds the union of every block's pre-state proof nodes and codes. It is
//! bound to the parent of the first block and never reset: block N+1 runs on the post-state
//! needlefish computed for block N, so a wrong root also derails every later block. Each
//! block runs through the node's block executor (`execution/node/executor.zig`, the same code
//! the node imports blocks with) over a `Backend` that commits into the sparse tries.
//!
//! Checked per block against the canonical header (which `archive` hash-links to the
//! parent): transactions root, gas used, logs bloom, blob gas used (Jovian DA footprint),
//! receipts root, state root, the Isthmus withdrawals root (L2ToL1MessagePasser storage
//! root), and the block hash of the canonical header with every execution result sealed in.
//!
//! BLOCKHASH is served from the archive's header chain through the `SparseState` fallback
//! (only numbers below the block being executed). Reads that hit a gap in the witness are
//! recorded (`Gaps`): the address or slot of a failed read, and the hash of a trie node or
//! code the witness lacks. `base replay fetch` uses them to complete an archive.

const std = @import("std");
const assert = std.debug.assert;

const archive_module = @import("archive.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const evm = @import("../../execution/evm/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");
const node_executor = @import("../../execution/node/executor.zig");
const chain_module = @import("../../execution/node/chain.zig");

const Archive = archive_module.Archive;
const SparseState = db.witness.SparseState;
const Executor = node_executor.Executor;
const Header = consensus.Header;
const Hash = [32]u8;
const Address = [20]u8;
const keccak256 = trie.node.keccak256;

pub const l2_to_l1_message_passer: Address =
    primitives.hex.decode_array(20, "4200000000000000000000000000000000000016") catch unreachable;

/// The stand-in for an opaque branch: two all-zero child hashes and fifteen empty items
/// (fourteen children and the value). Its shape is all a collapse reads. It is never hashed:
/// a clean node keeps its real reference.
/// `rlp([0xa0 ++ 32 x 0, 0xa0 ++ 32 x 0, "", ..., ""])`.
pub const opaque_branch: [2 + 2 * 33 + 15]u8 = blk: {
    var bytes: [2 + 2 * 33 + 15]u8 = undefined;
    bytes[0] = 0xf8; // List, one length byte (payload 56..255 bytes).
    bytes[1] = 2 * 33 + 15;
    var offset: usize = 2;
    for (0..2) |_| {
        bytes[offset] = 0xa0;
        @memset(bytes[offset + 1 ..][0..32], 0);
        offset += 33;
    }
    @memset(bytes[offset..], 0x80);
    break :blk bytes;
};

/// The EVM serves BLOCKHASH for the 256 most recent ancestors.
pub const block_hash_window = 256;
/// Gap entries kept per kind; more are counted, not kept.
pub const gaps_max = 256;

pub const Config = struct {
    sparse: SparseState.Config,
    changeset: db.changeset.Config,
    executor: node_executor.Config,
};

/// Trie pool headroom for the nodes each block's changes create. Freed nodes are reused, so
/// a long window needs far less per block than a short one; 65,536 per block for 1,000 blocks
/// would reserve several GiB (more than a small machine can map).
const trie_nodes_per_block: u32 = 65536;
const trie_nodes_per_block_long: u32 = 8192;
const blocks_generous: u32 = 128;

/// Sizes for an archive: every pool fits the whole archive, since nothing is reset.
pub fn config_for(archive: *const Archive) Config {
    const witness = &archive.witness;
    const nodes: u32 = @max(witness.state.count, 1);
    const blocks: u32 = archive.block_count;
    var transactions_max: u32 = 1;
    for (0..blocks) |index| {
        transactions_max = @max(transactions_max, archive.transaction_count(@intCast(index)));
    }
    return .{
        .sparse = .{
            .nodes_max = nodes + 1024,
            .node_bytes_max = byte_list_used(&witness.state) + (1 << 20),
            .codes_max = @max(witness.codes.count, 1) + 1024 * blocks,
            .code_bytes_max = byte_list_used(&witness.codes) + (8 << 20),
            .headers_max = 1,
            .trie_nodes_max = 4 * nodes + trie_nodes_per_block * @min(blocks, blocks_generous) +
                trie_nodes_per_block_long * (blocks -| blocks_generous),
            .storage_tries_max = 4096 + 2048 * blocks,
        },
        .changeset = .{
            .accounts_max = 1 << 14,
            .storage_max = 1 << 16,
            .codes_max = 1 << 10,
            .code_bytes_max = 8 << 20,
        },
        .executor = .{ .transactions_max = transactions_max },
    };
}

fn byte_list_used(list: *const db.witness.ByteList) u32 {
    return if (list.count == 0) 0 else list.ends[list.count - 1];
}

pub const SlotKey = struct { address: Address, slot: u256 };

/// What the witness lacked during the last block. Bounded; overflow is counted.
pub const Gaps = struct {
    accounts: [gaps_max]Address = undefined,
    accounts_len: u32 = 0,
    slots: [gaps_max]SlotKey = undefined,
    slots_len: u32 = 0,
    nodes: [gaps_max]Hash = undefined,
    nodes_len: u32 = 0,
    codes: [gaps_max]Hash = undefined,
    codes_len: u32 = 0,
    block_hashes: [gaps_max]u64 = undefined,
    block_hashes_len: u32 = 0,
    /// Accounts whose code the witness lacks (owner of each `codes` entry, when known).
    code_owners: [gaps_max]Address = undefined,
    code_owners_len: u32 = 0,
    dropped: u32 = 0,

    pub fn clear(gaps: *Gaps) void {
        gaps.* = .{};
    }

    pub fn empty(gaps: *const Gaps) bool {
        return gaps.accounts_len + gaps.slots_len + gaps.nodes_len + gaps.codes_len +
            gaps.block_hashes_len + gaps.dropped == 0;
    }

    fn push(gaps: *Gaps, comptime T: type, list: []T, len: *u32, item: T) void {
        for (list[0..len.*]) |existing| {
            if (std.meta.eql(existing, item)) return;
        }
        if (len.* == list.len) {
            gaps.dropped += 1;
            return;
        }
        list[len.*] = item;
        len.* += 1;
    }

    pub fn account(gaps: *Gaps, address: Address) void {
        gaps.push(Address, &gaps.accounts, &gaps.accounts_len, address);
    }

    pub fn slot(gaps: *Gaps, key: SlotKey) void {
        gaps.push(SlotKey, &gaps.slots, &gaps.slots_len, key);
    }

    pub fn node(gaps: *Gaps, hash: Hash) void {
        gaps.push(Hash, &gaps.nodes, &gaps.nodes_len, hash);
    }

    pub fn code(gaps: *Gaps, hash: Hash) void {
        gaps.push(Hash, &gaps.codes, &gaps.codes_len, hash);
    }

    pub fn block_hash(gaps: *Gaps, number: u64) void {
        gaps.push(u64, &gaps.block_hashes, &gaps.block_hashes_len, number);
    }

    pub fn code_owner(gaps: *Gaps, address: Address) void {
        gaps.push(Address, &gaps.code_owners, &gaps.code_owners_len, address);
    }
};

/// Recent (code hash, address) pairs from account reads, so a missing code can be traced
/// back to an account the fetcher can ask for. A ring: old pairs are overwritten.
/// Most witness hashing threads; the executor caps recovery threads the same way.
const hash_threads_max = 64;
/// Fewer nodes than this hash inline: thread start-up would cost more than it saves.
const hash_parallel_min = 4096;
/// keccak256 needs a few hundred bytes of stack.
const hash_stack_bytes = 64 << 10;

/// One worker's share of witness hashing: nodes `first`, `first + stride`, ...
const HashJob = struct {
    state: *const db.witness.ByteList,
    hashes: []Hash,
    first: u32,

    fn run(job: HashJob, stride: u32) void {
        assert(stride > 0);
        assert(job.hashes.len == job.state.count);
        var index: u32 = job.first;
        while (index < job.state.count) : (index += stride) {
            job.hashes[index] = keccak256(job.state.get(index));
        }
    }
};

pub const CodeOwners = struct {
    const capacity = 1024;
    hashes: [capacity]Hash = undefined,
    addresses: [capacity]Address = undefined,
    len: u32 = 0,
    next: u32 = 0,

    pub fn put(owners: *CodeOwners, hash: Hash, address: Address) void {
        owners.hashes[owners.next] = hash;
        owners.addresses[owners.next] = address;
        owners.next = (owners.next + 1) % capacity;
        owners.len = @min(owners.len + 1, capacity);
    }

    pub fn get(owners: *const CodeOwners, hash: Hash) ?Address {
        for (0..owners.len) |index| {
            if (std.mem.eql(u8, &owners.hashes[index], &hash)) return owners.addresses[index];
        }
        return null;
    }
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

/// The first receipt that differs from the canonical one (diagnostics).
pub const ReceiptDiff = struct {
    index: u32,
    expected: archive_module.Receipt,
    computed: archive_module.Receipt,
};

/// The first account or slot whose post-block value differs from the canonical chain's.
pub const StateDiff = union(enum) {
    account: struct {
        address: Address,
        expected: ?db.AccountInfo,
        computed: ?db.AccountInfo,
    },
    slot: struct {
        address: Address,
        slot: u256,
        expected: u256,
        computed: u256,
    },
};

pub const Outcome = struct {
    number: u64,
    hash: Hash,
    transactions: u32,
    gas_used: u64,
    expected_state_root: Hash,
    computed_state_root: Hash,
    /// Bit `@intFromEnum(check)` set: that field matched.
    passed: u16 = 0,
    /// Set when execution itself failed (no roots were computed).
    failure: ?anyerror = null,
    /// Index of the transaction execution failed on, if any.
    failed_transaction: ?u32 = null,
    receipt_diff: ?ReceiptDiff = null,
    state_diff: ?StateDiff = null,

    pub fn ok(outcome: *const Outcome) bool {
        return outcome.failure == null and outcome.passed == all_checks;
    }

    pub fn check(outcome: *const Outcome, which: Check) bool {
        return outcome.passed & (@as(u16, 1) << @as(u4, @intCast(@backingInt(which)))) != 0;
    }

    /// The first check that failed, in check order.
    pub fn first_failed(outcome: *const Outcome) ?Check {
        inline for (@typeInfo(Check).@"enum".field_names) |name| {
            const which = @field(Check, name);
            if (!outcome.check(which)) return which;
        }
        return null;
    }
};

const all_checks: u16 = (1 << check_count) - 1;

pub const Error = error{
    /// The archive's chain id does not match the chain spec.
    WrongChain,
    InvalidArchive,
} || db.witness.Error;

pub const Replayer = struct {
    spec: *const chainspec.ChainSpec,
    archive: *const Archive,
    sparse: SparseState,
    changeset: db.Changeset,
    executor: Executor,
    gaps: Gaps = .{},
    code_owners: CodeOwners = .{},
    /// keccak256 of every archive header, in archive order.
    header_hashes: []Hash,
    /// Number of the first archive header.
    first_number: u64,
    /// The block being executed (BLOCKHASH serves only numbers below it).
    current_number: u64 = 0,
    /// Index of the next block to replay.
    next_block: u32 = 0,
    /// Why the backend reported `StateUnavailable`.
    backend_error: ?anyerror = null,
    /// Probe mode (witness gap search): a missing account reads as absent and a missing
    /// slot as zero, so one pass records every missing key of a block instead of stopping
    /// at the first, and replay continues past failed blocks. A block with gaps still fails
    /// with `WitnessIncomplete`.
    probe: bool = false,
    /// Scratch: the transactions of the block being replayed and of the next one (two
    /// halves by block parity), so the executor recovers the next block's senders while
    /// this one commits.
    transaction_views: [][]const u8,
    /// The block whose half of `transaction_views` is already filled (prefetched).
    prefilled: ?u32 = null,

    /// The replayer must not move after `init` (the executor's backend points at it).
    pub fn init(
        self: *Replayer,
        allocator: std.mem.Allocator,
        spec: *const chainspec.ChainSpec,
        archive: *const Archive,
        config: Config,
    ) !void {
        if (archive.chain_id != spec.chain_id) return error.WrongChain;
        assert(archive.block_count > 0);
        self.* = undefined;
        self.spec = spec;
        self.archive = archive;
        self.gaps = .{};
        self.code_owners = .{};
        self.current_number = 0;
        self.next_block = 0;
        self.backend_error = null;
        self.probe = false;
        self.sparse = try SparseState.init(allocator, config.sparse);
        errdefer self.sparse.deinit(allocator);
        self.changeset = try db.Changeset.init(allocator, config.changeset);
        errdefer self.changeset.deinit(allocator);
        const hashes = archive.ancestors_len + archive.block_count;
        self.header_hashes = try allocator.alloc(Hash, hashes);
        errdefer allocator.free(self.header_hashes);
        const views = 2 * config.executor.transactions_max;
        self.transaction_views = try allocator.alloc([]const u8, views);
        errdefer allocator.free(self.transaction_views);
        self.executor = try Executor.init_backend(allocator, spec, self.backend(), config.executor);
        errdefer self.executor.deinit(allocator);
        try self.load(allocator, config.executor.recovery_threads);
    }

    pub fn deinit(self: *Replayer, allocator: std.mem.Allocator) void {
        self.executor.deinit(allocator);
        allocator.free(self.transaction_views);
        allocator.free(self.header_hashes);
        self.changeset.deinit(allocator);
        self.sparse.deinit(allocator);
        self.* = undefined;
    }

    /// Adds every witness node, hashing them on `threads` short-lived workers (the
    /// executor's recovery workers are idle during init), then inserting serially in archive
    /// order, so the store is the same as a serial `add_node` loop builds.
    fn load_nodes(
        self: *Replayer,
        allocator: std.mem.Allocator,
        threads: u32,
    ) (Error || error{OutOfMemory})!void {
        const state = &self.archive.witness.state;
        const count = state.count;
        const workers: u32 = @min(threads, hash_threads_max);
        if (workers == 0 or count < hash_parallel_min) {
            for (0..count) |index| try self.sparse.add_node(state.get(@intCast(index)));
            return;
        }
        const hashes = try allocator.alloc(Hash, count);
        defer allocator.free(hashes);
        var handles: [hash_threads_max]std.Thread = undefined;
        var spawned: u32 = 0;
        // Worker 0 is this thread; a failed spawn leaves its share to this thread.
        while (spawned + 1 < workers) : (spawned += 1) {
            const job: HashJob = .{ .state = state, .hashes = hashes, .first = spawned + 1 };
            const spawn_config: std.Thread.SpawnConfig = .{ .stack_size = hash_stack_bytes };
            handles[spawned] = std.Thread.spawn(spawn_config, HashJob.run, .{ job, workers }) catch
                break;
        }
        HashJob.run(.{ .state = state, .hashes = hashes, .first = 0 }, workers);
        for (spawned + 1..workers) |first| {
            HashJob.run(.{ .state = state, .hashes = hashes, .first = @intCast(first) }, workers);
        }
        for (handles[0..spawned]) |handle| handle.join();
        for (0..count) |index| {
            try self.sparse.add_node_hashed(&hashes[index], state.get(@intCast(index)));
        }
        assert(self.sparse.nodes.count <= count);
    }

    /// Binds the sparse state to the first block's parent and loads every node and code.
    fn load(
        self: *Replayer,
        allocator: std.mem.Allocator,
        threads: u32,
    ) (Error || error{OutOfMemory})!void {
        const archive = self.archive;
        const witness = &archive.witness;
        const ancestors = archive.ancestors[0..archive.ancestors_len];
        @memcpy(self.header_hashes[0..ancestors.len], ancestors);
        for (0..archive.block_count) |index| {
            const header = archive.block_header(@intCast(index));
            self.header_hashes[archive.ancestors_len + index] = keccak256(header);
        }
        self.first_number = archive.first_ancestor_number();
        const parent_number = self.first_number + archive.ancestors_len - 1;
        self.sparse.reset(archive.parent_state_root, .{
            .number = parent_number,
            .hash = archive.parent_hash(),
        });
        self.sparse.set_fallback(self.fallback());
        try self.load_nodes(allocator, threads);
        for (0..witness.codes.count) |index| {
            try self.sparse.add_code(witness.codes.get(@intCast(index)));
        }
        try self.sparse.verify_headers();
        self.executor.state.reset(self.database());
        assert(std.mem.eql(u8, &self.sparse.state_root(), &archive.parent_state_root));
    }

    pub fn done(self: *const Replayer) bool {
        return self.next_block == self.archive.block_count;
    }

    /// Replays the next block. A block that fails leaves the replayer unusable for the
    /// blocks after it (their pre-state is wrong), so `done` is then forced, except in probe
    /// mode: the gap search goes on to collect later blocks' missing keys (their outcomes
    /// mean nothing else).
    pub fn replay_next(self: *Replayer) Error!Outcome {
        assert(!self.done());
        const index = self.next_block;
        self.next_block += 1;
        const header_rlp = self.archive.block_header(index);
        const header = Header.decode(header_rlp) catch return error.InvalidArchive;
        self.gaps.clear();
        self.backend_error = null;
        self.current_number = header.number;
        var outcome: Outcome = .{
            .number = header.number,
            .hash = keccak256(header_rlp),
            .transactions = self.archive.transaction_count(index),
            .gas_used = header.gas_used,
            .expected_state_root = header.state_root.bytes,
            .computed_state_root = @splat(0),
        };
        self.execute(index, &header, &outcome);
        if (!outcome.ok() and !self.probe) self.next_block = self.archive.block_count;
        assert(outcome.number == header.number);
        return outcome;
    }

    fn views_of(self: *Replayer, index: u32) [][]const u8 {
        const half = self.transaction_views.len / 2;
        const count = self.archive.transaction_count(index);
        assert(count <= half); // `config_for` sizes `transactions_max` to the archive.
        return self.transaction_views[(index % 2) * half ..][0..count];
    }

    fn fill_views(self: *Replayer, index: u32) [][]const u8 {
        const views = self.views_of(index);
        for (views, 0..) |*view, position| {
            view.* = self.archive.transaction(index, @intCast(position));
        }
        return views;
    }

    fn execute(self: *Replayer, index: u32, header: *const Header, outcome: *Outcome) void {
        if (self.prefilled != index) {
            self.executor.cancel_prefetch(); // Its views may be refilled below.
            _ = self.fill_views(index);
        }
        const transactions = self.views_of(index);
        self.prefilled = null;
        if (index + 1 < self.archive.block_count) {
            self.executor.next_transactions = self.fill_views(index + 1);
            self.prefilled = index + 1;
        }
        // Base blocks carry an empty withdrawals list from Canyon on.
        const withdrawals: ?[]const @import("../../execution/payload/root.zig").Withdrawal =
            if (header.withdrawals_root != null) &.{} else null;
        const env = chain_module.env_of(header);
        const executed = self.executor.execute_block(&env, transactions, withdrawals) catch |err| {
            outcome.failure = if (self.sparse.incomplete or !self.gaps.empty())
                error.WitnessIncomplete
            else
                self.backend_error orelse err;
            outcome.failed_transaction = self.executor.invalid_index;
            self.sparse.incomplete = false;
            return;
        };
        if (self.sparse.incomplete or !self.gaps.empty()) {
            assert(self.probe or !self.gaps.empty() or self.sparse.incomplete);
            outcome.failure = error.WitnessIncomplete;
            self.sparse.incomplete = false;
            return;
        }
        outcome.computed_state_root = executed.state_root;
        self.compare(header, transactions, &executed, outcome);
        if (!outcome.check(.receipts_root) or !outcome.check(.gas_used)) {
            const expected = self.archive.block_receipts(index);
            outcome.receipt_diff = diff_receipts(expected, executed.receipts);
        }
        if (!outcome.check(.state_root)) outcome.state_diff = self.diff_state(index);
    }

    fn compare(
        self: *Replayer,
        header: *const Header,
        transactions: []const []const u8,
        executed: *const node_executor.Executed,
        outcome: *Outcome,
    ) void {
        outcome.passed = check_header(.{
            .spec = self.spec,
            .sparse = &self.sparse,
            .gaps = &self.gaps,
            .header = header,
            .hash = &outcome.hash,
            .transactions = transactions,
            .executed = executed,
        });
    }

    /// The first account or slot (in archive order) whose post-block value differs.
    fn diff_state(self: *Replayer, index: u32) ?StateDiff {
        for (self.archive.block_accounts(index)) |expected| {
            const computed = self.sparse.basic(expected.address) catch continue;
            const same = if (expected.info != null and computed != null)
                expected.info.?.eql(computed.?)
            else
                expected.info == null and computed == null;
            if (same) continue;
            return .{ .account = .{
                .address = expected.address,
                .expected = expected.info,
                .computed = computed,
            } };
        }
        for (self.archive.block_slots(index)) |expected| {
            const computed = self.sparse.storage(expected.address, expected.slot) catch continue;
            if (computed == expected.value) continue;
            return .{ .slot = .{
                .address = expected.address,
                .slot = expected.slot,
                .expected = expected.value,
                .computed = computed,
            } };
        }
        return null;
    }

    fn backend(self: *Replayer) node_executor.Backend {
        return .{
            .context = self,
            .database = self.database(),
            .commit = backend_commit,
            .root = backend_root,
        };
    }

    fn backend_commit(context: *anyopaque, state: *evm.State) node_executor.BackendError!void {
        const self: *Replayer = @ptrCast(@alignCast(context));
        self.commit(state) catch |err| {
            self.backend_error = err;
            return error.StateUnavailable;
        };
    }

    /// Folds the block into the sparse tries, keeps the code it deployed (later blocks may
    /// call it), and empties the evm cache so the next block reads the new state.
    fn commit(self: *Replayer, state: *evm.State) !void {
        try self.sparse.apply_evm(state, &self.changeset);
        var accounts = state.accounts.valueIterator();
        while (accounts.next()) |account| {
            if (!account.dirty or !account.in_database) continue;
            const code = account.info.code orelse continue;
            if (code.len == 0) continue;
            try self.sparse.add_code_hashed(&account.info.code_hash, code);
        }
        state.accounts.clearRetainingCapacity();
        state.slots.clearRetainingCapacity();
        state.code_store_len = 0;
    }

    fn backend_root(context: *anyopaque) node_executor.BackendError!Hash {
        const self: *Replayer = @ptrCast(@alignCast(context));
        return self.sparse.state_root();
    }

    fn fallback(self: *Replayer) SparseState.Fallback {
        return .{
            .context = self,
            .node = fallback_node,
            .code = fallback_code,
            .block_hash = fallback_block_hash,
        };
    }

    fn from(context: *anyopaque) *Replayer {
        return @ptrCast(@alignCast(context));
    }

    /// An opaque branch resolves to a stand-in branch: the trie only checks its kind (a
    /// collapse turns its parent into an extension over it) and keeps its real hash as the
    /// reference, since nothing in the archive reads below it (a real preimage, when any
    /// block's proof has one, is in the node store and wins over the fallback).
    fn fallback_node(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self = from(context);
        if (self.archive.is_opaque(hash)) return &opaque_branch;
        self.gaps.node(hash.*);
        return null;
    }

    fn fallback_code(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self = from(context);
        self.gaps.code(hash.*);
        if (self.code_owners.get(hash.*)) |owner| self.gaps.code_owner(owner);
        return null;
    }

    /// Ancestors of the block being executed, from the hash-linked archive headers.
    fn fallback_block_hash(context: *anyopaque, number: u64) ?Hash {
        const self = from(context);
        const count = self.header_hashes.len;
        if (number < self.first_number or number >= self.current_number or
            number - self.first_number >= count)
        {
            self.gaps.block_hash(number);
            return null;
        }
        return self.header_hashes[@intCast(number - self.first_number)];
    }

    const recording_vtable: evm.state.Database.VTable = .{
        .basic = database_basic,
        .code_by_hash = database_code_by_hash,
        .storage = database_storage,
        .block_hash = database_block_hash,
    };

    fn database(self: *Replayer) evm.state.Database {
        return .{ .context = self, .vtable = &recording_vtable };
    }

    fn inner(self: *Replayer) evm.state.Database {
        return self.sparse.database();
    }

    fn database_basic(
        context: *anyopaque,
        address: evm.Address,
    ) evm.state.Error!?evm.state.AccountInfo {
        const self = from(context);
        const info = self.inner().basic(address) catch |err| {
            self.gaps.account(address);
            if (self.probe) return null;
            return err;
        };
        if (info) |account| {
            if (account.has_code()) self.code_owners.put(account.code_hash, address);
        }
        return info;
    }

    fn database_code_by_hash(context: *anyopaque, hash: evm.B256) evm.state.Error![]const u8 {
        return from(context).inner().code_by_hash(hash);
    }

    fn database_storage(
        context: *anyopaque,
        address: evm.Address,
        slot: u256,
    ) evm.state.Error!u256 {
        const self = from(context);
        return self.inner().storage(address, slot) catch |err| {
            self.gaps.slot(.{ .address = address, .slot = slot });
            if (self.probe) return 0;
            return err;
        };
    }

    fn database_block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
        return from(context).inner().block_hash(number);
    }
};

/// What `check_header` compares: a block's canonical header and hash, and the results of
/// executing it over `sparse` (already committed).
pub const HeaderCheck = struct {
    spec: *const chainspec.ChainSpec,
    sparse: *SparseState,
    /// Records the message passer's account when the witness lacks it.
    gaps: *Gaps,
    header: *const Header,
    hash: *const Hash,
    transactions: []const []const u8,
    executed: *const node_executor.Executed,
};

/// Checks every recomputed header field and the hash of the header resealed with them.
/// Returns the passed checks: bit `@intFromEnum(check)` set means that field matched.
pub fn check_header(input: HeaderCheck) u16 {
    const header = input.header;
    const executed = input.executed;
    var sealed = header.*;
    sealed.transactions_root = .{ .bytes = trie.ordered.ordered_trie_root(input.transactions) };
    sealed.gas_used = executed.gas_used;
    sealed.logs_bloom = executed.logs_bloom;
    if (header.blob_gas_used != null) sealed.blob_gas_used = executed.blob_gas_used;
    sealed.receipts_root = .{ .bytes = executed.receipts_root };
    sealed.state_root = .{ .bytes = executed.state_root };
    if (input.spec.is_upgrade_active(.isthmus, header.timestamp)) {
        if (input.sparse.account_storage_root(l2_to_l1_message_passer)) |root| {
            sealed.withdrawals_root = .{ .bytes = root };
        } else |_| {
            // The witness lacks the message passer's account: ask the fetcher for it.
            input.gaps.account(l2_to_l1_message_passer);
            sealed.withdrawals_root = .{ .bytes = @splat(0) };
        }
    }
    const results = [check_count]bool{
        sealed.transactions_root.eql(header.transactions_root),
        sealed.gas_used == header.gas_used,
        sealed.logs_bloom.eql(header.logs_bloom),
        std.meta.eql(sealed.blob_gas_used, header.blob_gas_used),
        sealed.receipts_root.eql(header.receipts_root),
        sealed.state_root.eql(header.state_root),
        std.meta.eql(sealed.withdrawals_root, header.withdrawals_root),
        std.mem.eql(u8, &sealed.hash().bytes, input.hash),
    };
    var passed: u16 = 0;
    for (results, 0..) |matched, bit| {
        if (matched) passed |= @as(u16, 1) << @intCast(bit);
    }
    assert(passed <= all_checks);
    assert(results[check_count - 1] == (passed >> (check_count - 1) == 1));
    return passed;
}

/// The first receipt whose status, cumulative gas, or log count differs.
pub fn diff_receipts(
    expected: []const archive_module.Receipt,
    computed: []const consensus.Receipt,
) ?ReceiptDiff {
    const count = @min(expected.len, computed.len);
    for (0..count) |index| {
        const mine: archive_module.Receipt = .{
            .status = computed[index].status,
            .cumulative_gas_used = computed[index].cumulative_gas_used,
            .log_count = computed[index].logs.count,
        };
        if (std.meta.eql(mine, expected[index])) continue;
        return .{ .index = @intCast(index), .expected = expected[index], .computed = mine };
    }
    assert(expected.len == computed.len);
    return null;
}

test "replay: strided witness hashing covers every node once (seeded fuzz)" {
    const allocator = std.testing.allocator;
    var list = try db.witness.ByteList.init(allocator, 512, 64 << 10);
    defer list.deinit(allocator);
    var prng = std.Random.DefaultPrng.init(0x7e9a);
    const random = prng.random();
    var hashes: [512]Hash = undefined;
    for (0..64) |_| {
        list.clear();
        const count = random.uintAtMost(u32, 300);
        var bytes: [96]u8 = undefined;
        for (0..count) |_| {
            const len = random.uintAtMost(usize, bytes.len);
            random.bytes(bytes[0..len]);
            try list.append(bytes[0..len]);
        }
        const stride = random.intRangeAtMost(u32, 1, 9);
        @memset(hashes[0..count], @as(Hash, @splat(0)));
        for (0..stride) |first| {
            const job: HashJob = .{
                .state = &list,
                .hashes = hashes[0..count],
                .first = @intCast(first),
            };
            job.run(stride);
        }
        for (0..count) |index| {
            const expected = keccak256(list.get(@intCast(index)));
            try std.testing.expectEqualSlices(u8, &expected, &hashes[index]);
        }
    }
}

//! Validating follower (`base follow`, docs/SYNC_PLAN.md M1): re-executes every block of a
//! live chain over one long-lived stateless `SparseState` and checks every header field
//! (`replay.replayer.check_header`). Pure: the driver (`bin/base/follow.zig`) fetches
//! blocks, proofs and codes and feeds them in.
//!
//! Per block, in order:
//!
//! 1. `probe`: execute without committing. A missing account reads as absent and a missing
//!    slot as zero, and every gap is recorded (`gaps`), so one pass finds most missing keys.
//!    The driver fetches `eth_getProof` for the gap keys (any block's proof works: the node
//!    store is keyed by keccak256, so only nodes the trie references are ever used) and the
//!    codes of the recorded code owners, then probes again until a pass has no gaps.
//! 2. The clean pass also lists the keys the block deletes (`deleted_accounts`,
//!    `deleted_slots`). A deletion can collapse a branch into its sibling, a node no proof of
//!    a touched key holds. The driver fetches the block's own (post-state) proofs of those
//!    keys and passes their nodes to `add_post_nodes`, which derives the siblings (see
//!    `replay.import`): a sibling that is a leaf or extension is rebuilt from the merged
//!    node; a sibling that is a branch is opaque and resolves to `replayer.opaque_branch`.
//! 3. `verify`: execute and commit, then check the header. A verified block becomes the
//!    head; stand-in branches are dropped from the trie so later reads resolve real nodes.
//!
//! Any capacity or witness failure while committing (`WitnessIncomplete`, `SparseFull`,
//! `WitnessFull`) leaves the trie half-updated, so the follower rebases: it resets to the
//! verified head's state root (an empty witness) and the driver retries the block. A block
//! that executes over a complete witness and still differs from its header is a mismatch.

const std = @import("std");
const assert = std.debug.assert;

const replay = @import("../replay/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const header_json = @import("../../consensus/sources/header_json.zig");
const evm = @import("../../execution/evm/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");
const payload = @import("../../execution/payload/root.zig");
const node_executor = @import("../../execution/node/executor.zig");
const chain_module = @import("../../execution/node/chain.zig");

const replayer = replay.replayer;
const SparseState = db.witness.SparseState;
const Executor = node_executor.Executor;
const Header = consensus.Header;
const Gaps = replayer.Gaps;
const Hash = [32]u8;
const Address = [20]u8;
const keccak256 = trie.node.keccak256;

pub const SlotKey = replayer.SlotKey;
pub const Outcome = replayer.Outcome;

/// The EVM serves BLOCKHASH for the 256 most recent ancestors.
pub const block_hash_window = 256;
/// State-trie leaf values are accounts (at most 110 bytes) or slots (at most 33).
const candidate_value_bytes_max = 512;
const candidate_bytes_max = candidate_value_bytes_max + 64;

pub const Config = struct {
    sparse: SparseState.Config,
    changeset: db.changeset.Config,
    executor: node_executor.Config,
    /// Opaque sibling branches per block.
    opaque_max: u32 = 4096,
    /// Deleted keys listed per block; more are counted in `deletions_dropped`.
    deleted_accounts_max: u32 = 1024,
    deleted_slots_max: u32 = 8192,
};

/// Pools for a long run: every pool fills with the state the chain touches, and a full pool
/// rebases (`Follower.rebase`). The large ones are reserved lazily (`utilities.lazy_alloc`).
pub fn default_config() Config {
    return .{
        .sparse = .{
            .nodes_max = 4 << 20,
            .node_bytes_max = 2 << 30,
            .codes_max = 1 << 16,
            .code_bytes_max = 1 << 30,
            .headers_max = 1,
            .trie_nodes_max = 8 << 20,
            .storage_tries_max = 1 << 18,
        },
        .changeset = .{
            .accounts_max = 1 << 16,
            .storage_max = 1 << 18,
            .codes_max = 1 << 12,
            .code_bytes_max = 32 << 20,
        },
        .executor = .{ .transactions_max = 1 << 14 },
    };
}

/// A verified block: the child of the previous head (or the starting point).
pub const Anchor = struct { number: u64, hash: Hash, state_root: Hash };

/// A block bound to its hash: the header re-encodes to the block hash and the transactions
/// to its `transactionsRoot` (`decode_block`).
pub const Block = struct {
    number: u64,
    hash: Hash,
    parent_hash: Hash,
    header_rlp: []const u8,
    transactions: []const []const u8,
};

pub const DecodeError = replay.import.Error;

/// Decodes an `eth_getBlockByNumber(n, true)` result. Allocations come from `arena`.
pub fn decode_block(arena: std.mem.Allocator, raw: []const u8) DecodeError!Block {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = header_json.decode(raw, &extra) catch return error.Inconsistent;
    const header = decoded.header;
    const header_rlp = try arena.alloc(u8, rlp.length(header));
    _ = rlp.encode_to(header_rlp, header);
    if (!std.mem.eql(u8, &keccak256(header_rlp), &decoded.hash.bytes)) return error.Inconsistent;
    const root = header.transactions_root.bytes;
    const transactions = try replay.import.decode_transactions(arena, raw, root);
    assert(header_rlp.len > 0);
    return .{
        .number = header.number,
        .hash = decoded.hash.bytes,
        .parent_hash = header.parent_hash.bytes,
        .header_rlp = header_rlp,
        .transactions = transactions,
    };
}

pub const Probe = enum {
    /// The pass lacked state: fetch `gaps` and probe again.
    gaps,
    /// Every read resolved: fetch the deleted keys' post-state proofs, then `verify`.
    ready,
    /// A pool filled up (`full_error`): rebase and start the block again.
    full,
    /// Execution failed over a complete witness (`probe_error`): the block is invalid to
    /// needlefish, which is a mismatch for a canonical block.
    failed,
};

pub const Stats = struct {
    blocks: u64 = 0,
    transactions: u64 = 0,
    gas: u64 = 0,
    probe_passes: u64 = 0,
    rebases: u64 = 0,
    resets: u64 = 0,
    opaque_branches: u64 = 0,
    derived_siblings: u64 = 0,
};

pub const Error = error{ NotChild, InvalidBlock, OpaqueFull } || db.witness.Error;

pub const Follower = struct {
    spec: *const chainspec.ChainSpec,
    sparse: SparseState,
    changeset: db.Changeset,
    executor: Executor,
    gaps: Gaps = .{},
    code_owners: replayer.CodeOwners = .{},
    head: Anchor,
    started: bool = false,
    /// Hashes of the 256 blocks up to the head, by `number % 256`, and their numbers.
    ring: [block_hash_window]Hash,
    ring_numbers: [block_hash_window]u64,
    /// The block being executed: BLOCKHASH serves only numbers below it.
    current_number: u64 = 0,
    probing: bool = false,
    /// Collapse siblings that are branches with unknown preimages (this block only).
    opaque_hashes: std.AutoHashMapUnmanaged(Hash, void) = .empty,
    opaque_max: u32,
    deleted_accounts: []Address,
    deleted_accounts_len: u32 = 0,
    deleted_slots: []SlotKey,
    deleted_slots_len: u32 = 0,
    deletions_dropped: u32 = 0,
    /// Why the last pass hit a full pool (`Probe.full`) or the commit failed.
    full_error: ?anyerror = null,
    /// Why the last probe failed over a complete witness (`Probe.failed`).
    probe_error: ?anyerror = null,
    /// Transaction the last failed execution stopped at.
    failed_transaction: ?u32 = null,
    /// Set by a mismatch: the state is the block's wrong post-state (for diagnostics) and
    /// nothing more can be verified.
    broken: bool = false,
    /// The receipts of the last block `verify` executed (valid until the next execution).
    last_receipts: []const consensus.Receipt = &.{},
    stats: Stats = .{},

    /// The follower must not move after `init` (the executor's backend points at it).
    pub fn init(
        self: *Follower,
        allocator: std.mem.Allocator,
        spec: *const chainspec.ChainSpec,
        config: Config,
    ) !void {
        assert(config.opaque_max > 0);
        self.* = .{
            .spec = spec,
            .sparse = undefined,
            .changeset = undefined,
            .executor = undefined,
            .head = .{ .number = 0, .hash = @splat(0), .state_root = @splat(0) },
            .ring = undefined,
            .ring_numbers = @splat(std.math.maxInt(u64)),
            .opaque_max = config.opaque_max,
            .deleted_accounts = undefined,
            .deleted_slots = undefined,
        };
        self.sparse = try SparseState.init(allocator, config.sparse);
        errdefer self.sparse.deinit(allocator);
        self.changeset = try db.Changeset.init(allocator, config.changeset);
        errdefer self.changeset.deinit(allocator);
        try self.opaque_hashes.ensureTotalCapacity(allocator, config.opaque_max);
        errdefer self.opaque_hashes.deinit(allocator);
        self.deleted_accounts = try allocator.alloc(Address, config.deleted_accounts_max);
        errdefer allocator.free(self.deleted_accounts);
        self.deleted_slots = try allocator.alloc(SlotKey, config.deleted_slots_max);
        errdefer allocator.free(self.deleted_slots);
        self.executor = try Executor.init_backend(allocator, spec, self.backend(), config.executor);
        assert(!self.started);
    }

    pub fn deinit(self: *Follower, allocator: std.mem.Allocator) void {
        self.executor.deinit(allocator);
        allocator.free(self.deleted_slots);
        allocator.free(self.deleted_accounts);
        self.opaque_hashes.deinit(allocator);
        self.changeset.deinit(allocator);
        self.sparse.deinit(allocator);
        self.* = undefined;
    }

    /// Starts from a trusted block: `ancestors` are the hashes of up to 256 blocks ending at
    /// `anchor` (oldest first, consecutive numbers, the last is `anchor.hash`). The caller
    /// hash-links them; the state is `anchor.state_root`, all unknown.
    pub fn start(self: *Follower, anchor: Anchor, ancestors: []const Hash) void {
        assert(ancestors.len > 0 and ancestors.len <= block_hash_window);
        assert(std.mem.eql(u8, &ancestors[ancestors.len - 1], &anchor.hash));
        assert(anchor.number + 1 >= ancestors.len);
        self.ring_numbers = @splat(std.math.maxInt(u64));
        const first = anchor.number + 1 - ancestors.len;
        for (ancestors, 0..) |hash, offset| self.remember(first + offset, hash);
        self.head = anchor;
        self.started = true;
        self.broken = false;
        self.reset_state();
        assert(std.mem.eql(u8, &self.sparse.state_root(), &anchor.state_root));
    }

    /// Drops the trie (not the node store): the state is the head's state root again, read
    /// back from the store, which holds every node the follower fetched or computed
    /// (`SparseState.keep_new_nodes`). For a commit that failed half way, a full trie pool,
    /// or after a mismatch.
    pub fn rebase(self: *Follower) void {
        assert(self.started);
        self.stats.rebases += 1;
        self.broken = false;
        self.sparse.rebase(self.head.state_root, .{
            .number = self.head.number,
            .hash = self.head.hash,
        });
        self.bind();
    }

    /// Forgets every node and code too: the state is the head's state root, all unknown.
    /// For a full node store.
    pub fn reset(self: *Follower) void {
        assert(self.started);
        self.stats.resets += 1;
        self.broken = false;
        self.reset_state();
    }

    fn reset_state(self: *Follower) void {
        self.sparse.reset(self.head.state_root, .{
            .number = self.head.number,
            .hash = self.head.hash,
        });
        self.bind();
        self.code_owners = .{};
    }

    /// Binds a freshly reset sparse state to the follower.
    fn bind(self: *Follower) void {
        self.sparse.set_fallback(self.fallback());
        self.sparse.keep_new_nodes(true);
        // An empty header chain verifies: BLOCKHASH then comes from the ring (fallback).
        self.sparse.verify_headers() catch unreachable;
        self.executor.state.reset(self.database());
        assert(self.sparse.headers_verified);
        assert(std.mem.eql(u8, &self.sparse.state_root(), &self.head.state_root));
    }

    fn remember(self: *Follower, number: u64, hash: Hash) void {
        const slot: usize = @intCast(number % block_hash_window);
        self.ring[slot] = hash;
        self.ring_numbers[slot] = number;
    }

    /// A trie node from any proof (unreferenced nodes are never read). Embedded nodes (under
    /// 32 bytes) are skipped: their parent holds them.
    pub fn add_node(self: *Follower, bytes: []const u8) error{WitnessFull}!void {
        if (bytes.len < 32) return;
        try self.sparse.add_node(bytes);
    }

    /// A contract code from `eth_getCode` (stored by its keccak256, checked on use).
    pub fn add_code(self: *Follower, code: []const u8) error{WitnessFull}!void {
        if (code.len == 0) return;
        try self.sparse.add_code(code);
    }

    /// The nodes of the block's own (post-state) proofs of its deleted keys: derives the
    /// collapse siblings and records opaque branches (module comment). Unreferenced
    /// candidates are harmless (the store is keyed by hash). Untrusted input: an invalid
    /// node is skipped.
    pub fn add_post_nodes(
        self: *Follower,
        nodes: []const []const u8,
    ) (error{ WitnessFull, OpaqueFull })!void {
        for (nodes) |bytes| {
            if (bytes.len < 32) continue;
            try self.add_node(bytes);
            const decoded = trie.sparse.decode_node(bytes) catch continue;
            if (decoded.kind == .branch) continue;
            const path = decoded.path.slice();
            var offset: usize = 1;
            while (offset <= path.len) : (offset += 1) {
                if (offset == path.len) {
                    if (decoded.kind == .leaf) break;
                    const child = &decoded.children[0];
                    if (!child.is_hash()) break;
                    const hash = child.bytes[1..33].*;
                    if (self.sparse.nodes.get(&hash) == null) try self.add_opaque(hash);
                    break;
                }
                if (decoded.value.len > candidate_value_bytes_max) break;
                var buffer: [candidate_bytes_max]u8 = undefined;
                var sink: trie.node.BufferSink = .{ .buffer = &buffer };
                switch (decoded.kind) {
                    .leaf => trie.node.encode_leaf(&sink, path[offset..], decoded.value),
                    .extension => {
                        trie.node.encode_extension(&sink, path[offset..], &decoded.children[0]);
                    },
                    .branch => unreachable,
                }
                const candidate = sink.result();
                if (candidate.len < 32) continue; // Embedded in its parent, never a hash child.
                const before = self.sparse.nodes.count;
                try self.sparse.add_node(candidate);
                self.stats.derived_siblings += self.sparse.nodes.count - before;
            }
        }
    }

    /// Marks `hash` as a branch whose preimage is unknown (it resolves to a stand-in).
    pub fn add_opaque(self: *Follower, hash: Hash) error{OpaqueFull}!void {
        if (self.opaque_hashes.contains(hash)) return;
        if (self.opaque_hashes.count() == self.opaque_max) return error.OpaqueFull;
        self.opaque_hashes.putAssumeCapacityNoClobber(hash, {});
        self.stats.opaque_branches += 1;
    }

    fn check_child(self: *const Follower, block: *const Block) Error!Header {
        assert(self.started);
        if (block.number != self.head.number + 1) return error.NotChild;
        if (!std.mem.eql(u8, &block.parent_hash, &self.head.hash)) return error.NotChild;
        const header = Header.decode(block.header_rlp) catch return error.InvalidBlock;
        if (header.number != block.number) return error.InvalidBlock;
        return header;
    }

    fn begin_pass(self: *Follower, header: *const Header, probing: bool) void {
        assert(!self.broken);
        self.gaps.clear();
        self.full_error = null;
        self.probe_error = null;
        self.failed_transaction = null;
        self.sparse.incomplete = false;
        self.current_number = header.number;
        self.probing = probing;
        if (probing) self.stats.probe_passes += 1;
    }

    /// One pass over `block` without committing (module comment, step 1). A transaction
    /// that fails is skipped, so the transactions after it still reveal their keys (a
    /// block with a failed transaction verifies only once its witness is complete).
    pub fn probe(self: *Follower, block: *const Block) Error!Probe {
        const header = try self.check_child(block);
        self.begin_pass(&header, true);
        defer self.probing = false;
        const env = chain_module.env_of(&header);
        var building = self.executor.begin_block(&env) catch |err| return self.pass_failure(err);
        defer self.executor.abort_block();
        var failure: ?anyerror = null;
        for (block.transactions, 0..) |raw, index| {
            self.executor.apply(&building, raw) catch |err| {
                if (failure != null) continue;
                failure = err;
                self.failed_transaction = @intCast(index);
            };
        }
        if (self.spec.is_upgrade_active(.isthmus, header.timestamp)) {
            // The withdrawals root is the message passer's storage root (checked later).
            _ = self.sparse.account_storage_root(replayer.l2_to_l1_message_passer) catch |err| {
                if (err != error.WitnessIncomplete) {
                    self.full_error = err;
                    return .full;
                }
                self.gaps.account(replayer.l2_to_l1_message_passer);
            };
        }
        if (failure) |err| return self.pass_failure(err);
        if (self.full_error != null) return .full;
        if (!self.gaps.empty() or self.sparse.incomplete) return .gaps;
        self.collect_deletions();
        return .ready;
    }

    fn pass_failure(self: *Follower, err: anyerror) Probe {
        if (self.full_error != null) return .full;
        if (!self.gaps.empty() or self.sparse.incomplete) return .gaps;
        if (err == error.ScratchFull or err == error.StateFull) {
            self.full_error = err;
            return .full;
        }
        self.probe_error = err;
        return .failed;
    }

    /// The keys a clean pass deletes: dirty slots set to zero and dirty accounts no longer
    /// in the database. A superset is fine (a slot that was already zero adds a proof).
    fn collect_deletions(self: *Follower) void {
        self.deleted_accounts_len = 0;
        self.deleted_slots_len = 0;
        self.deletions_dropped = 0;
        const state = self.executor.state;
        var accounts = state.accounts.valueIterator();
        while (accounts.next()) |account| {
            if (!account.dirty or account.in_database) continue;
            if (self.deleted_accounts_len == self.deleted_accounts.len) {
                self.deletions_dropped += 1;
                continue;
            }
            self.deleted_accounts[self.deleted_accounts_len] = account.address;
            self.deleted_accounts_len += 1;
        }
        var slots = state.slots.iterator();
        while (slots.next()) |entry| {
            const slot = entry.value_ptr;
            if (!slot.dirty or slot.present != 0) continue;
            const account = state.accounts.getPtr(entry.key_ptr.address) orelse continue;
            if (!account.in_database or slot.epoch != account.storage_epoch) continue;
            if (self.deleted_slots_len == self.deleted_slots.len) {
                self.deletions_dropped += 1;
                continue;
            }
            self.deleted_slots[self.deleted_slots_len] = .{
                .address = entry.key_ptr.address,
                .slot = entry.key_ptr.slot,
            };
            self.deleted_slots_len += 1;
        }
        assert(self.deleted_slots_len <= self.deleted_slots.len);
    }

    /// Executes and commits `block`, then checks its header (module comment, step 3). On a
    /// witness or capacity failure (`retryable`) the follower has rebased; probe again.
    pub fn verify(self: *Follower, block: *const Block) Error!Outcome {
        const header = try self.check_child(block);
        self.begin_pass(&header, false);
        var outcome: Outcome = .{
            .number = header.number,
            .hash = block.hash,
            .transactions = @intCast(block.transactions.len),
            .gas_used = header.gas_used,
            .expected_state_root = header.state_root.bytes,
            .computed_state_root = @splat(0),
        };
        const executed = self.execute(block, &header, &outcome) orelse return outcome;
        outcome.computed_state_root = executed.state_root;
        self.last_receipts = executed.receipts;
        outcome.passed = replayer.check_header(.{
            .spec = self.spec,
            .sparse = &self.sparse,
            .gaps = &self.gaps,
            .header = &header,
            .hash = &block.hash,
            .transactions = block.transactions,
            .executed = &executed,
        });
        if (self.sparse.incomplete or !self.gaps.empty()) {
            outcome.failure = error.WitnessIncomplete;
            self.rebase();
            return outcome;
        }
        if (!outcome.ok()) {
            self.broken = true;
            return outcome;
        }
        try self.advance(block, &header);
        self.stats.transactions += block.transactions.len;
        self.stats.gas += header.gas_used;
        // Verified, but the store missed some new nodes, so a rebase could not rebuild the
        // trie: start over from the new head.
        if (self.sparse.nodes.dropped > 0) self.reset();
        return outcome;
    }

    /// Executes and commits `block`; null (with `outcome.failure` set) when it failed.
    fn execute(
        self: *Follower,
        block: *const Block,
        header: *const Header,
        outcome: *Outcome,
    ) ?node_executor.Executed {
        const env = chain_module.env_of(header);
        const transactions = block.transactions;
        return self.executor.execute_block(&env, transactions, withdrawals_of(header)) catch |err| {
            const gap = self.sparse.incomplete or !self.gaps.empty();
            outcome.failure = self.full_error orelse if (gap) error.WitnessIncomplete else err;
            outcome.failed_transaction = self.executor.invalid_index;
            if (retryable(outcome)) self.recover(outcome.failure.?) else self.broken = true;
            assert(outcome.failure != null);
            return null;
        };
    }

    /// After a retryable failure: a full node store resets, anything else rebases.
    fn recover(self: *Follower, failure: anyerror) void {
        if (failure == error.WitnessFull or self.sparse.nodes.dropped > 0) {
            self.reset();
        } else {
            self.rebase();
        }
    }

    /// The verified block becomes the head; stand-ins stop serving.
    fn advance(self: *Follower, block: *const Block, header: *const Header) Error!void {
        if (self.opaque_hashes.count() > 0) {
            _ = try self.sparse.trie.unresolve_source(&replayer.opaque_branch);
            self.opaque_hashes.clearRetainingCapacity();
        }
        self.head = .{
            .number = block.number,
            .hash = block.hash,
            .state_root = header.state_root.bytes,
        };
        self.remember(block.number, block.hash);
        self.stats.blocks += 1;
        assert(std.mem.eql(u8, &self.sparse.state_root(), &self.head.state_root));
    }

    fn backend(self: *Follower) node_executor.Backend {
        return .{
            .context = self,
            .database = self.database(),
            .commit = backend_commit,
            .root = backend_root,
        };
    }

    fn from(context: *anyopaque) *Follower {
        return @ptrCast(@alignCast(context));
    }

    fn backend_commit(context: *anyopaque, state: *evm.State) node_executor.BackendError!void {
        const self = from(context);
        assert(!self.probing);
        self.commit(state) catch |err| {
            self.full_error = err;
            return error.StateUnavailable;
        };
    }

    /// Folds the block into the sparse tries, keeps the code it deployed, and empties the
    /// evm cache so the next block reads the new state.
    fn commit(self: *Follower, state: *evm.State) !void {
        try self.sparse.apply_evm(state, &self.changeset);
        var accounts = state.accounts.valueIterator();
        while (accounts.next()) |account| {
            if (!account.dirty or !account.in_database) continue;
            const code = account.info.code orelse continue;
            if (code.len == 0) continue;
            try self.sparse.add_code(code);
        }
        state.accounts.clearRetainingCapacity();
        state.slots.clearRetainingCapacity();
        state.code_store_len = 0;
    }

    fn backend_root(context: *anyopaque) node_executor.BackendError!Hash {
        return from(context).sparse.state_root();
    }

    fn fallback(self: *Follower) SparseState.Fallback {
        return .{
            .context = self,
            .node = fallback_node,
            .code = fallback_code,
            .block_hash = fallback_block_hash,
        };
    }

    fn fallback_node(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self = from(context);
        if (self.opaque_hashes.contains(hash.*)) return &replayer.opaque_branch;
        self.gaps.node(hash.*);
        return null;
    }

    fn fallback_code(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self = from(context);
        self.gaps.code(hash.*);
        if (self.code_owners.get(hash.*)) |owner| self.gaps.code_owner(owner);
        return null;
    }

    /// The 256 verified ancestors of the block being executed.
    fn fallback_block_hash(context: *anyopaque, number: u64) ?Hash {
        const self = from(context);
        const slot: usize = @intCast(number % block_hash_window);
        if (number >= self.current_number or self.ring_numbers[slot] != number) {
            self.gaps.block_hash(number);
            return null;
        }
        return self.ring[slot];
    }

    const recording_vtable: evm.state.Database.VTable = .{
        .basic = database_basic,
        .code_by_hash = database_code_by_hash,
        .storage = database_storage,
        .block_hash = database_block_hash,
    };

    fn database(self: *Follower) evm.state.Database {
        return .{ .context = self, .vtable = &recording_vtable };
    }

    /// Runs `read` through the witness and tells a gap (the witness lacks a node or code)
    /// from any other failure (a full pool, recorded in `full_error`).
    fn witness_read(self: *Follower, comptime T: type, read: anytype, args: anytype) struct {
        result: evm.state.Error!T,
        gap: bool,
    } {
        const was_incomplete = self.sparse.incomplete;
        self.sparse.incomplete = false;
        const result = @call(.auto, read, .{self.sparse.database()} ++ args);
        const gap = self.sparse.incomplete;
        self.sparse.incomplete = was_incomplete or gap;
        if (result) |_| {} else |_| {
            if (!gap and self.full_error == null) self.full_error = error.StateUnreadable;
        }
        return .{ .result = result, .gap = gap };
    }

    fn database_basic(
        context: *anyopaque,
        address: evm.Address,
    ) evm.state.Error!?evm.state.AccountInfo {
        const self = from(context);
        const read = self.witness_read(?evm.state.AccountInfo, evm.state.Database.basic, .{
            address,
        });
        const info = read.result catch |err| {
            if (!read.gap) return err;
            self.gaps.account(address);
            if (self.probing) return null;
            return err;
        };
        if (info) |account| {
            if (account.has_code()) self.code_owners.put(account.code_hash, address);
        }
        return info;
    }

    /// In a probe a missing code runs as empty code (the call returns at once), so the
    /// rest of the block still reveals its keys.
    fn database_code_by_hash(context: *anyopaque, hash: evm.B256) evm.state.Error![]const u8 {
        const self = from(context);
        const read = self.witness_read([]const u8, evm.state.Database.code_by_hash, .{hash});
        return read.result catch |err| {
            if (read.gap and self.probing) return &.{};
            return err;
        };
    }

    fn database_storage(
        context: *anyopaque,
        address: evm.Address,
        slot: u256,
    ) evm.state.Error!u256 {
        const self = from(context);
        const read = self.witness_read(u256, evm.state.Database.storage, .{ address, slot });
        return read.result catch |err| {
            if (!read.gap) return err;
            self.gaps.slot(.{ .address = address, .slot = slot });
            if (self.probing) return 0;
            return err;
        };
    }

    fn database_block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
        return from(context).sparse.database().block_hash(number);
    }
};

/// Whether a failed `verify` only lacked witness data or capacity (the follower rebased).
pub fn retryable(outcome: *const Outcome) bool {
    const failure = outcome.failure orelse return false;
    return switch (failure) {
        error.WitnessIncomplete,
        error.WitnessFull,
        error.SparseFull,
        error.KeysFull,
        error.ChangesetFull,
        error.StateUnavailable,
        error.ScratchFull,
        error.StateFull,
        error.StateUnreadable,
        => true,
        else => false,
    };
}

/// Base blocks carry an empty withdrawals list from Canyon on.
fn withdrawals_of(header: *const Header) ?[]const payload.Withdrawal {
    return if (header.withdrawals_root != null) &.{} else null;
}

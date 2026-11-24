//! The trie mode's in-memory variants, each another root path of needlefish's:
//! - `sparse`: the stateless verifier's `SparseState` (`db/witness.zig` over
//!   `trie/sparse.zig`). It keeps every node it ever hashed (`keep_new_nodes`), and each
//!   block starts with `rebase` at the parent's root: the trie is revealed from those nodes
//!   (the whole previous state) as it is read, then the block's hashed changeset is built
//!   from its own reads (`build_hashed_changeset`) and applied. Unwinds are native: the
//!   next block rebases at the ancestor's root.
//! - `state-trie`: the in-memory node state's `StateTrie` (hashed keys), driven op by op
//!   (`set_account`, `set_storage`, `wipe_storage`, `delete_account`) with its incremental
//!   root and its proofs (`prove_account`, `prove_storage`: the live eth_getProof path). No
//!   history: an unwind applies the block's revert, then its ops.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");
const trie_request = @import("trie_request.zig");
const trie_node = @import("trie_node.zig");

const Hash = [32]u8;
const SparseState = db.witness.SparseState;
const Changeset = db.Changeset;
const HashedWrites = db.overlay.HashedWrites;
const Op = trie_request.Op;

pub const Sparse = struct {
    sparse: SparseState,
    changeset: Changeset,
    /// The state root after each block of the canonical chain, by height.
    roots: [trie_node.blocks_max + 1]Hash = undefined,

    const config: SparseState.Config = .{
        .nodes_max = 1 << 18,
        .node_bytes_max = 64 << 20,
        .codes_max = 1,
        .code_bytes_max = 1,
        .headers_max = 1,
        .trie_nodes_max = 1 << 17,
        .storage_tries_max = 4096,
    };

    pub const Error = db.witness.Error || db.changeset.Error;

    /// Heap-pinned: the sparse state's resolver points into it.
    pub fn create(allocator: std.mem.Allocator) !*Sparse {
        const self = try allocator.create(Sparse);
        errdefer allocator.destroy(self);
        self.* = .{
            .sparse = try SparseState.init(allocator, config),
            .changeset = undefined,
        };
        errdefer self.sparse.deinit(allocator);
        self.changeset = try Changeset.init(allocator, trie_node.changeset_config);
        self.sparse.reset(trie.empty_root, .{ .number = 0, .hash = @splat(0) });
        self.sparse.keep_new_nodes(true);
        self.roots[0] = trie.empty_root;
        return self;
    }

    pub fn destroy(self: *Sparse, allocator: std.mem.Allocator) void {
        self.changeset.deinit(allocator);
        self.sparse.deinit(allocator);
        allocator.destroy(self);
    }

    /// The block at height `parent + 1` from `writes` (the block's own writes on the state
    /// at height `parent`): its state root.
    pub fn block(self: *Sparse, parent: u64, writes: HashedWrites) Error!Hash {
        assert(parent < self.roots.len - 1);
        self.sparse.rebase(self.roots[@intCast(parent)], .{ .number = parent, .hash = @splat(0) });
        const reader: Reader = .{ .sparse = &self.sparse };
        try db.overlay.build_hashed_changeset(reader, writes, &self.changeset);
        try self.sparse.apply(&self.changeset);
        if (self.sparse.nodes.dropped > 0) return error.WitnessFull;
        const root = self.sparse.state_root();
        self.roots[@intCast(parent + 1)] = root;
        return root;
    }

    /// The storage root in `key`'s account leaf; null when the account is absent.
    pub fn storage_root(self: *Sparse, key: *const Hash) Error!?Hash {
        const leaf = try self.sparse.account_hashed(key) orelse return null;
        return leaf.storage_root;
    }

    const Reader = struct {
        sparse: *SparseState,

        pub const Error = db.witness.Error;

        pub fn account(reader: Reader, key: *const Hash) db.witness.Error!?db.AccountInfo {
            const leaf = try reader.sparse.account_hashed(key) orelse return null;
            return .{ .nonce = leaf.nonce, .balance = leaf.balance, .code_hash = leaf.code_hash };
        }

        pub fn storage(reader: Reader, key: *const Hash, slot: *const Hash) db.witness.Error!u256 {
            return reader.sparse.storage_hashed(key, slot);
        }
    };
};

pub const StateTrieVariant = struct {
    state_trie: trie.StateTrie,

    pub const Error = trie.state_trie.Error;

    pub fn init(allocator: std.mem.Allocator) !StateTrieVariant {
        return .{ .state_trie = try trie.StateTrie.init(allocator, .{
            .accounts_max = 1 << 14,
            .account_nodes_max = 1 << 16,
            .storage_nodes_max = 1 << 18,
        }) };
    }

    pub fn deinit(self: *StateTrieVariant, allocator: std.mem.Allocator) void {
        self.state_trie.deinit(allocator);
        self.* = undefined;
    }

    pub fn apply(self: *StateTrieVariant, ops: []const Op) Error!void {
        const state = &self.state_trie;
        for (ops) |*op| {
            const exists = state.get_account(op.key) != null;
            switch (op.kind) {
                .account => try state.set_account(op.key, .{
                    .nonce = op.info.nonce,
                    .balance = op.info.balance,
                    .code_hash = op.info.code_hash,
                }),
                .storage => try state.set_storage(op.key, op.slot, op.value),
                .wipe => if (exists) try state.wipe_storage(op.key),
                .delete => try state.delete_account(op.key),
            }
        }
    }

    pub fn root(self: *StateTrieVariant) Error!Hash {
        return self.state_trie.root();
    }

    /// The account at `key` with its storage root (after `root`), null when absent.
    pub fn account(self: *StateTrieVariant, key: *const Hash) ?db.history.AccountState {
        const entry = self.state_trie.get_account(key.*) orelse return null;
        return .{
            .nonce = entry.nonce,
            .balance = entry.balance,
            .storage_root = self.state_trie.storage_root(key.*),
            .code_hash = entry.code_hash,
        };
    }
};

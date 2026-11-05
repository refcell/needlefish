//! Execution witness (`debug_executionWitness`) and stateless re-execution.
//!
//! A witness lets a node with no state re-execute a block and check its state root. Same
//! shape as alloy's `ExecutionWitness` (base/base `debug_executionWitness`):
//! - `state`: deduplicated RLP preimages of the pre-state trie nodes the block needs,
//! - `codes`: bytecodes read,
//! - `keys`: preimages of touched keys (20-byte addresses, 32-byte slot keys),
//! - `headers`: RLP headers of ancestors read by BLOCKHASH, oldest first, ending at the
//!   parent. A verifier links them to the parent it trusts (`SparseState.reset`): each is
//!   the child of the previous one and the last is the parent (reth stateless validation).
//!
//! Flow: execute the block over `Recorder` (wraps the evm `Database`, records every account,
//! slot, code hash, and block number read), build the block's `Changeset`, then
//! `Builder.build` from the pre-state `State`. `SparseState` is the stateless side: it serves
//! evm reads from the witness alone and applies a changeset to a sparse trie
//! (`trie/sparse.zig`) to get the post-state root.
//!
//! The builder gathers a superset first (proofs of every touched key, plus the hashed
//! siblings along deleted keys' paths, which a collapsing branch merges into its parent),
//! then replays the block on a `SparseState` over that superset and keeps only the nodes
//! the replay decoded. So the witness is minimal for this replay: dropping any node makes
//! the same replay fail with `WitnessIncomplete`.

const std = @import("std");
const assert = std.debug.assert;

const evm = @import("../evm/root.zig");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const trie = @import("../trie/root.zig");
const state_module = @import("state.zig");
const changeset_module = @import("changeset.zig");
const history = @import("history.zig");
const rlp = trie.rlp;
const node = trie.node;
const sparse = trie.sparse;

const State = state_module.State;
const SlotKey = state_module.SlotKey;
const Changeset = changeset_module.Changeset;
const AccountChange = changeset_module.AccountChange;
const StorageChange = changeset_module.StorageChange;
pub const Address = state_module.Address;
pub const Hash = state_module.Hash;
pub const AccountInfo = state_module.AccountInfo;

pub const Error = error{ WitnessFull, KeysFull, UnknownCode, InvalidHeaderChain } || sparse.Error;

/// A bounded list of byte strings in one arena. The arena and ends are reserved at init and
/// committed on first touch (`lazy_alloc`), so an idle list costs no resident memory.
pub const ByteList = struct {
    bytes: []u8,
    ends: []u32,
    count: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, items_max: u32, bytes_max: u32) !ByteList {
        assert(items_max > 0);
        const bytes = try lazy.alloc(allocator, u8, bytes_max);
        errdefer lazy.free(allocator, bytes);
        const ends = try lazy.alloc(allocator, u32, items_max);
        return .{ .bytes = bytes, .ends = ends };
    }

    pub fn deinit(self: *ByteList, allocator: std.mem.Allocator) void {
        lazy.free(allocator, self.ends);
        lazy.free(allocator, self.bytes);
        self.* = undefined;
    }

    pub fn clear(self: *ByteList) void {
        self.count = 0;
    }

    fn used(self: *const ByteList) u32 {
        return if (self.count == 0) 0 else self.ends[self.count - 1];
    }

    pub fn append(self: *ByteList, item: []const u8) error{WitnessFull}!void {
        const start = self.used();
        if (self.count == self.ends.len) return error.WitnessFull;
        if (item.len > self.bytes.len - start) return error.WitnessFull;
        @memcpy(self.bytes[start..][0..item.len], item);
        self.ends[self.count] = start + @as(u32, @intCast(item.len));
        self.count += 1;
        assert(std.mem.eql(u8, self.get(self.count - 1), item));
    }

    pub fn get(self: *const ByteList, index: u32) []const u8 {
        assert(index < self.count);
        const start = if (index == 0) 0 else self.ends[index - 1];
        return self.bytes[start..self.ends[index]];
    }
};

pub const Witness = struct {
    pub const Config = struct {
        state_nodes_max: u32,
        state_bytes_max: u32,
        codes_max: u32,
        code_bytes_max: u32,
        keys_max: u32,
        headers_max: u32,
        header_bytes_max: u32,
    };

    state: ByteList,
    codes: ByteList,
    keys: ByteList,
    headers: ByteList,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Witness {
        var state = try ByteList.init(allocator, config.state_nodes_max, config.state_bytes_max);
        errdefer state.deinit(allocator);
        var codes = try ByteList.init(allocator, config.codes_max, config.code_bytes_max);
        errdefer codes.deinit(allocator);
        var keys = try ByteList.init(allocator, config.keys_max, config.keys_max * 32);
        errdefer keys.deinit(allocator);
        const headers = try ByteList.init(allocator, config.headers_max, config.header_bytes_max);
        return .{ .state = state, .codes = codes, .keys = keys, .headers = headers };
    }

    pub fn deinit(self: *Witness, allocator: std.mem.Allocator) void {
        self.headers.deinit(allocator);
        self.keys.deinit(allocator);
        self.codes.deinit(allocator);
        self.state.deinit(allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Witness) void {
        self.state.clear();
        self.codes.clear();
        self.keys.clear();
        self.headers.clear();
    }
};

/// A bounded set that remembers insertion order (deterministic witness order).
fn SetList(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        len: u32 = 0,
        index: std.AutoHashMapUnmanaged(T, void) = .empty,

        fn init(allocator: std.mem.Allocator, items_max: u32) !Self {
            assert(items_max > 0);
            const items = try lazy.alloc(allocator, T, items_max);
            errdefer lazy.free(allocator, items);
            var result: Self = .{ .items = items };
            try result.index.ensureTotalCapacity(allocator, items_max);
            return result;
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.index.deinit(allocator);
            lazy.free(allocator, self.items);
            self.* = undefined;
        }

        fn clear(self: *Self) void {
            self.index.clearRetainingCapacity();
            self.len = 0;
        }

        fn add(self: *Self, item: T) error{KeysFull}!void {
            if (self.index.contains(item)) return;
            if (self.len == self.items.len) return error.KeysFull;
            self.index.putAssumeCapacityNoClobber(item, {});
            self.items[self.len] = item;
            self.len += 1;
            assert(self.index.count() == self.len);
        }

        pub fn slice(self: *const Self) []const T {
            return self.items[0..self.len];
        }
    };
}

/// Keys touched by a block: accounts, slots, code hashes, and block numbers.
pub const KeySet = struct {
    pub const Config = struct {
        accounts_max: u32,
        slots_max: u32,
        codes_max: u32,
        block_numbers_max: u32,
    };

    accounts: SetList(Address),
    slots: SetList(SlotKey),
    codes: SetList(Hash),
    block_numbers: SetList(u64),

    pub fn init(allocator: std.mem.Allocator, config: Config) !KeySet {
        var accounts = try SetList(Address).init(allocator, config.accounts_max);
        errdefer accounts.deinit(allocator);
        var slots = try SetList(SlotKey).init(allocator, config.slots_max);
        errdefer slots.deinit(allocator);
        var codes = try SetList(Hash).init(allocator, config.codes_max);
        errdefer codes.deinit(allocator);
        const block_numbers = try SetList(u64).init(allocator, config.block_numbers_max);
        return .{
            .accounts = accounts,
            .slots = slots,
            .codes = codes,
            .block_numbers = block_numbers,
        };
    }

    pub fn deinit(self: *KeySet, allocator: std.mem.Allocator) void {
        self.block_numbers.deinit(allocator);
        self.codes.deinit(allocator);
        self.slots.deinit(allocator);
        self.accounts.deinit(allocator);
        self.* = undefined;
    }

    pub fn clear(self: *KeySet) void {
        self.accounts.clear();
        self.slots.clear();
        self.codes.clear();
        self.block_numbers.clear();
    }

    pub fn add_account(self: *KeySet, address: Address) error{KeysFull}!void {
        try self.accounts.add(address);
    }

    /// A slot read also touches its account (the account leaf holds the storage root).
    pub fn add_slot(self: *KeySet, address: Address, slot: u256) error{KeysFull}!void {
        try self.accounts.add(address);
        try self.slots.add(.{ .address = address, .slot = slot });
    }

    pub fn merge(self: *KeySet, other: *const KeySet) error{KeysFull}!void {
        for (other.accounts.slice()) |address| try self.accounts.add(address);
        for (other.slots.slice()) |key| try self.slots.add(key);
        for (other.codes.slice()) |hash| try self.codes.add(hash);
        for (other.block_numbers.slice()) |number| try self.block_numbers.add(number);
    }
};

/// Wraps an evm `Database` and records every key read through it. A full key set fails the
/// read with `StateFull`.
pub const Recorder = struct {
    inner: evm.state.Database,
    keys: KeySet,

    const vtable: evm.state.Database.VTable = .{
        .basic = basic,
        .code_by_hash = code_by_hash,
        .storage = storage,
        .block_hash = block_hash,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        inner: evm.state.Database,
        config: KeySet.Config,
    ) !Recorder {
        return .{ .inner = inner, .keys = try KeySet.init(allocator, config) };
    }

    pub fn deinit(self: *Recorder, allocator: std.mem.Allocator) void {
        self.keys.deinit(allocator);
        self.* = undefined;
    }

    /// Records into `keys`; `self` must outlive the returned database.
    pub fn database(self: *Recorder) evm.state.Database {
        return .{ .context = self, .vtable = &vtable };
    }

    fn from(context: *anyopaque) *Recorder {
        return @ptrCast(@alignCast(context));
    }

    fn basic(context: *anyopaque, address: evm.Address) evm.state.Error!?evm.state.AccountInfo {
        const self = from(context);
        self.keys.add_account(address) catch return error.StateFull;
        return self.inner.basic(address);
    }

    fn code_by_hash(context: *anyopaque, code_hash: evm.B256) evm.state.Error![]const u8 {
        const self = from(context);
        self.keys.codes.add(code_hash) catch return error.StateFull;
        return self.inner.code_by_hash(code_hash);
    }

    fn storage(context: *anyopaque, address: evm.Address, slot: u256) evm.state.Error!u256 {
        const self = from(context);
        self.keys.add_slot(address, slot) catch return error.StateFull;
        return self.inner.storage(address, slot);
    }

    fn block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
        const self = from(context);
        self.keys.block_numbers.add(number) catch return error.StateFull;
        return self.inner.block_hash(number);
    }
};

/// Preimages by keccak256, deduplicated, in insertion order, with a per-entry "decoded"
/// mark (set when the sparse trie resolved it).
pub const NodeStore = struct {
    const Entry = struct { hash: Hash, offset: u32, len: u32, accessed: bool };

    index: std.AutoHashMapUnmanaged(Hash, u32) = .empty,
    entries: []Entry,
    count: u32 = 0,
    arena: []u8,
    arena_len: u32 = 0,
    /// Asked for preimages the store lacks (see `SparseState.Fallback`).
    fallback: ?sparse.Resolver = null,

    pub fn init(allocator: std.mem.Allocator, items_max: u32, bytes_max: u32) !NodeStore {
        assert(items_max > 0);
        const entries = try lazy.alloc(allocator, Entry, items_max);
        errdefer lazy.free(allocator, entries);
        const arena = try lazy.alloc(allocator, u8, bytes_max);
        errdefer lazy.free(allocator, arena);
        var result: NodeStore = .{ .entries = entries, .arena = arena };
        try result.index.ensureTotalCapacity(allocator, items_max);
        return result;
    }

    pub fn deinit(self: *NodeStore, allocator: std.mem.Allocator) void {
        self.index.deinit(allocator);
        lazy.free(allocator, self.arena);
        lazy.free(allocator, self.entries);
        self.* = undefined;
    }

    pub fn clear(self: *NodeStore) void {
        self.index.clearRetainingCapacity();
        self.count = 0;
        self.arena_len = 0;
    }

    pub fn add(self: *NodeStore, bytes: []const u8) error{WitnessFull}!Hash {
        const hash = node.keccak256(bytes);
        if (self.index.contains(hash)) return hash;
        if (self.count == self.entries.len) return error.WitnessFull;
        if (bytes.len > self.arena.len - self.arena_len) return error.WitnessFull;
        const offset = self.arena_len;
        @memcpy(self.arena[offset..][0..bytes.len], bytes);
        self.arena_len += @intCast(bytes.len);
        self.entries[self.count] = .{
            .hash = hash,
            .offset = offset,
            .len = @intCast(bytes.len),
            .accessed = false,
        };
        self.index.putAssumeCapacityNoClobber(hash, self.count);
        self.count += 1;
        return hash;
    }

    fn bytes_of(self: *const NodeStore, entry: *const Entry) []const u8 {
        return self.arena[entry.offset..][0..entry.len];
    }

    pub fn get(self: *const NodeStore, hash: *const Hash) ?[]const u8 {
        const position = self.index.get(hash.*) orelse return null;
        assert(position < self.count);
        return self.bytes_of(&self.entries[position]);
    }

    fn resolve(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *NodeStore = @ptrCast(@alignCast(context));
        const position = self.index.get(hash.*) orelse {
            const fallback = self.fallback orelse return null;
            return fallback.resolve(fallback.context, hash);
        };
        const entry = &self.entries[position];
        entry.accessed = true;
        assert(std.mem.eql(u8, &entry.hash, hash));
        return self.bytes_of(entry);
    }
};

/// The fields of an RLP header a stateless verifier links ancestors by.
pub const HeaderLink = struct { parent_hash: Hash, state_root: Hash, number: u64 };

const header_items_max = 32;

/// Decodes the header list strictly: one list spanning all of `header`, at least 9 fields.
fn header_items(
    header: []const u8,
    items: *[header_items_max]rlp.Item,
) error{InvalidWitness}!u32 {
    const outer = rlp.decode_item(header) catch return error.InvalidWitness;
    if (outer.kind != .list or outer.encoded_length != header.len) return error.InvalidWitness;
    const count = rlp.decode_list(outer.payload, items) catch return error.InvalidWitness;
    if (count < 9) return error.InvalidWitness;
    assert(count <= header_items_max);
    return count;
}

/// A canonical RLP integer of at most 8 bytes (no leading zero).
fn header_integer(item: rlp.Item) error{InvalidWitness}!u64 {
    if (item.kind != .string or item.payload.len > 8) return error.InvalidWitness;
    if (item.payload.len > 0 and item.payload[0] == 0) return error.InvalidWitness;
    var number: u64 = 0;
    for (item.payload) |byte| number = (number << 8) | byte;
    return number;
}

fn header_hash(item: rlp.Item) error{InvalidWitness}!Hash {
    if (item.kind != .string or item.payload.len != 32) return error.InvalidWitness;
    return item.payload[0..32].*;
}

/// The block number of an RLP header (field 8 of the header list).
pub fn header_number(header: []const u8) error{InvalidWitness}!u64 {
    var items: [header_items_max]rlp.Item = undefined;
    _ = try header_items(header, &items);
    return header_integer(items[8]);
}

/// Parent hash (field 0), state root (field 3), and number (field 8) of an RLP header.
/// Strict: both hashes are 32-byte strings, the number a canonical integer.
pub fn header_link(header: []const u8) error{InvalidWitness}!HeaderLink {
    var items: [header_items_max]rlp.Item = undefined;
    const count = try header_items(header, &items);
    assert(count >= 9);
    return .{
        .parent_hash = try header_hash(items[0]),
        .state_root = try header_hash(items[3]),
        .number = try header_integer(items[8]),
    };
}

/// The parent hash of an RLP header (field 0 of the header list), decoded strictly.
pub fn header_parent_hash(header: []const u8) error{InvalidWitness}!Hash {
    return (try header_link(header)).parent_hash;
}

fn slot_hash_of(slot: u256) Hash {
    var key: [32]u8 = undefined;
    std.mem.writeInt(u256, &key, slot, .big);
    return node.keccak256(&key);
}

fn address_order(a: *const Address, b: *const Address) std.math.Order {
    return std.math.order(std.mem.readInt(u160, a, .big), std.mem.readInt(u160, b, .big));
}

const HeaderEntry = struct { number: u64, hash: Hash };

/// A stateless state provider backed only by a witness, bound to the parent of the block it
/// verifies: BLOCKHASH is served only from a header chain that ends at that parent.
pub const SparseState = struct {
    /// The parent of the block being verified, trusted by the caller.
    pub const Parent = struct { number: u64, hash: Hash };

    pub const Config = struct {
        nodes_max: u32,
        node_bytes_max: u32,
        codes_max: u32,
        code_bytes_max: u32,
        headers_max: u32,
        /// Sparse trie pool shared by the account trie and every storage trie.
        trie_nodes_max: u32,
        /// Storage tries opened (read or written) per block.
        storage_tries_max: u32,
    };

    /// Heap-allocated: the trie's resolver points at it.
    nodes: *NodeStore,
    codes: NodeStore,
    /// Ancestors, oldest first, each the child of the previous one.
    headers: []HeaderEntry,
    headers_len: u32 = 0,
    /// The state root in the last header added (the parent's, once verified).
    headers_tail_state_root: Hash = @splat(0),
    /// Set by `verify_headers`; `block_hash` serves nothing before.
    headers_verified: bool = false,
    /// Null only for the builder's scratch, which never serves BLOCKHASH.
    parent: ?Parent = null,
    pre_state_root: Hash = @splat(0),
    trie: sparse.SparseTrie,
    account_root: sparse.NodeIndex = sparse.none,
    /// Storage trie roots by address hash, opened on first use from the account leaf.
    storage_roots: std.AutoHashMapUnmanaged(Hash, sparse.NodeIndex) = .empty,
    storage_tries_max: u32,
    /// A read through `database()` failed for want of witness data (the evm only sees
    /// `DatabaseFailure`).
    incomplete: bool = false,
    fallback: ?Fallback = null,

    /// Source for trie nodes, codes and block hashes missing from the loaded witness, for
    /// a verifier that fetches them on demand (the fault-proof program's preimage
    /// oracle). Returned slices must stay valid until `reset`. Null means missing.
    pub const Fallback = struct {
        context: *anyopaque,
        node: *const fn (context: *anyopaque, hash: *const Hash) ?[]const u8,
        code: *const fn (context: *anyopaque, hash: *const Hash) ?[]const u8,
        block_hash: *const fn (context: *anyopaque, number: u64) ?Hash,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !SparseState {
        assert(config.storage_tries_max > 0);
        const nodes = try allocator.create(NodeStore);
        errdefer allocator.destroy(nodes);
        nodes.* = try NodeStore.init(allocator, config.nodes_max, config.node_bytes_max);
        errdefer nodes.deinit(allocator);
        var codes = try NodeStore.init(allocator, config.codes_max, config.code_bytes_max);
        errdefer codes.deinit(allocator);
        const headers = try allocator.alloc(HeaderEntry, config.headers_max);
        errdefer allocator.free(headers);
        var sparse_trie = try sparse.SparseTrie.init(allocator, config.trie_nodes_max, .{
            .context = nodes,
            .resolve = NodeStore.resolve,
        });
        errdefer sparse_trie.deinit(allocator);
        var result: SparseState = .{
            .nodes = nodes,
            .codes = codes,
            .headers = headers,
            .trie = sparse_trie,
            .storage_tries_max = config.storage_tries_max,
        };
        try result.storage_roots.ensureTotalCapacity(allocator, config.storage_tries_max);
        return result;
    }

    pub fn deinit(self: *SparseState, allocator: std.mem.Allocator) void {
        self.storage_roots.deinit(allocator);
        self.trie.deinit(allocator);
        allocator.free(self.headers);
        self.codes.deinit(allocator);
        self.nodes.deinit(allocator);
        allocator.destroy(self.nodes);
        self.* = undefined;
    }

    /// Forgets the witness and every update; the state is `pre_state_root`, all unknown, and
    /// headers must end at `parent` (whose state root must be `pre_state_root`).
    pub fn reset(self: *SparseState, pre_state_root: Hash, parent: Parent) void {
        self.clear(pre_state_root);
        self.parent = parent;
        assert(self.parent != null and !self.headers_verified);
    }

    /// As `reset`, unbound: no header chain verifies (the builder's scratch).
    fn clear(self: *SparseState, pre_state_root: Hash) void {
        self.nodes.clear();
        self.codes.clear();
        self.headers_len = 0;
        self.headers_tail_state_root = @splat(0);
        self.headers_verified = false;
        self.parent = null;
        self.pre_state_root = pre_state_root;
        self.trie.clear();
        self.storage_roots.clearRetainingCapacity();
        self.incomplete = false;
        // The pool was just emptied and has at least one node.
        self.account_root = self.trie.root_from_hash(pre_state_root) catch unreachable;
        assert(self.state_root_clean(pre_state_root));
    }

    /// Consults `fallback` whenever the witness lacks a node, code or block hash.
    pub fn set_fallback(self: *SparseState, fallback: ?Fallback) void {
        self.fallback = fallback;
        self.nodes.fallback = null;
        if (fallback) |f| self.nodes.fallback = .{ .context = f.context, .resolve = f.node };
        assert((self.fallback == null) == (self.nodes.fallback == null));
    }

    fn state_root_clean(self: *SparseState, root: Hash) bool {
        return std.mem.eql(u8, &self.trie.root_hash(self.account_root), &root);
    }

    pub fn add_node(self: *SparseState, bytes: []const u8) error{WitnessFull}!void {
        _ = try self.nodes.add(bytes);
    }

    pub fn add_code(self: *SparseState, code: []const u8) error{WitnessFull}!void {
        _ = try self.codes.add(code);
    }

    /// Appends the next ancestor header, oldest first: it must be the child of the previous
    /// one (number + 1, parent hash = keccak256 of the previous header). Nothing is served
    /// until `verify_headers` links the last one to the parent.
    pub fn add_header(self: *SparseState, header: []const u8) Error!void {
        if (self.headers_verified) return error.InvalidHeaderChain;
        const link = try header_link(header);
        if (self.headers_len > 0) {
            const previous = &self.headers[self.headers_len - 1];
            if (previous.number == std.math.maxInt(u64)) return error.InvalidHeaderChain;
            if (link.number != previous.number + 1) return error.InvalidHeaderChain;
            if (!std.mem.eql(u8, &link.parent_hash, &previous.hash)) {
                return error.InvalidHeaderChain;
            }
        }
        if (self.headers_len == self.headers.len) return error.WitnessFull;
        const hash = node.keccak256(header);
        self.headers[self.headers_len] = .{ .number = link.number, .hash = hash };
        self.headers_len += 1;
        self.headers_tail_state_root = link.state_root;
        assert(self.headers[self.headers_len - 1].number == link.number);
    }

    /// Links the header chain to the bound parent: the last header is the parent (number and
    /// hash) and holds the pre-state root. An empty chain verifies and serves no BLOCKHASH.
    pub fn verify_headers(self: *SparseState) error{InvalidHeaderChain}!void {
        if (self.headers_verified) return;
        const parent = self.parent orelse return error.InvalidHeaderChain;
        if (self.headers_len > 0) {
            const tail = &self.headers[self.headers_len - 1];
            if (tail.number != parent.number) return error.InvalidHeaderChain;
            if (!std.mem.eql(u8, &tail.hash, &parent.hash)) return error.InvalidHeaderChain;
            if (!std.mem.eql(u8, &self.headers_tail_state_root, &self.pre_state_root)) {
                return error.InvalidHeaderChain;
            }
            // Contiguous numbers ending at the parent: the first is at least 0.
            assert(self.headers[0].number == parent.number - (self.headers_len - 1));
        }
        self.headers_verified = true;
    }

    /// Loads every part of `witness` and verifies its headers against the bound parent.
    /// `keys` are not needed: reads come with their keys.
    pub fn load(self: *SparseState, witness: *const Witness) Error!void {
        for (0..witness.state.count) |index| try self.add_node(witness.state.get(@intCast(index)));
        for (0..witness.codes.count) |index| try self.add_code(witness.codes.get(@intCast(index)));
        for (0..witness.headers.count) |index| {
            try self.add_header(witness.headers.get(@intCast(index)));
        }
        try self.verify_headers();
        assert(self.headers_len == witness.headers.count);
    }

    fn account_state(self: *SparseState, address_hash: *const Hash) Error!?history.AccountState {
        const value = try self.trie.get(self.account_root, address_hash) orelse return null;
        return history.decode_account(value) catch error.InvalidWitness;
    }

    /// The root slot of the account's storage trie, opened from its leaf on first use.
    fn storage_root_slot(self: *SparseState, address_hash: *const Hash) Error!*sparse.NodeIndex {
        if (self.storage_roots.getPtr(address_hash.*)) |root| return root;
        if (self.storage_roots.count() == self.storage_tries_max) return error.SparseFull;
        const account = try self.account_state(address_hash);
        var root = sparse.none;
        if (account) |info| root = try self.trie.root_from_hash(info.storage_root);
        self.storage_roots.putAssumeCapacityNoClobber(address_hash.*, root);
        return self.storage_roots.getPtr(address_hash.*).?;
    }

    pub fn basic(self: *SparseState, address: Address) Error!?AccountInfo {
        const account = try self.account_state(&node.keccak256(&address)) orelse return null;
        return .{
            .nonce = account.nonce,
            .balance = account.balance,
            .code_hash = account.code_hash,
        };
    }

    pub fn storage(self: *SparseState, address: Address, slot: u256) Error!u256 {
        const root = (try self.storage_root_slot(&node.keccak256(&address))).*;
        const value = try self.trie.get(root, &slot_hash_of(slot)) orelse return 0;
        return history.decode_storage_value(value) catch error.InvalidWitness;
    }

    pub fn code_by_hash(self: *SparseState, hash: Hash) Error![]const u8 {
        if (std.mem.eql(u8, &hash, &node.empty_code_hash)) return &.{};
        if (self.codes.get(&hash)) |code| return code;
        const fallback = self.fallback orelse return error.WitnessIncomplete;
        return fallback.code(fallback.context, &hash) orelse error.WitnessIncomplete;
    }

    /// The hash of ancestor `number` from a verified chain that covers it, else the trusted
    /// fallback (never unverified witness headers).
    pub fn block_hash(self: *const SparseState, number: u64) ?Hash {
        if (self.headers_verified and self.headers_len > 0) {
            const first = self.headers[0].number;
            if (number >= first and number - first < self.headers_len) {
                const entry = &self.headers[@intCast(number - first)];
                assert(entry.number == number);
                return entry.hash;
            }
        }
        // A caller-installed fallback is trusted (it is the node's own chain, not witness data).
        const fallback = self.fallback orelse return null;
        return fallback.block_hash(fallback.context, number);
    }

    /// The storage root in `address`'s account leaf (post-state after `apply`), or the
    /// empty root for a missing account.
    pub fn account_storage_root(self: *SparseState, address: Address) Error!Hash {
        const account = try self.account_state(&node.keccak256(&address)) orelse {
            return node.empty_root;
        };
        return account.storage_root;
    }

    /// The state root after every `apply` so far.
    pub fn state_root(self: *SparseState) Hash {
        return self.trie.root_hash(self.account_root);
    }

    /// Applies a block's changes: storage first (storage roots come from pre-state account
    /// leaves; a destroyed account's storage is dropped whole, not slot by slot), then every
    /// account with a change or new storage, in address order.
    pub fn apply(self: *SparseState, changeset: *const Changeset) Error!void {
        const accounts = changeset.account_changes();
        const changes = changeset.storage_changes();
        var cursor: usize = 0;
        var start: usize = 0;
        while (start < changes.len) {
            const address = &changes[start].address;
            var end = start + 1;
            while (end < changes.len and std.mem.eql(u8, &changes[end].address, address)) end += 1;
            while (cursor < accounts.len and
                address_order(&accounts[cursor].address, address) == .lt) cursor += 1;
            const destroyed = cursor < accounts.len and
                std.mem.eql(u8, &accounts[cursor].address, address) and
                accounts[cursor].new == null;
            if (!destroyed) try self.apply_slots(address, changes[start..end]);
            start = end;
        }
        try self.apply_accounts(accounts, changes);
    }

    fn apply_slots(
        self: *SparseState,
        address: *const Address,
        run: []const StorageChange,
    ) Error!void {
        assert(run.len > 0);
        const root = try self.storage_root_slot(&node.keccak256(address));
        for (run) |*change| {
            assert(std.mem.eql(u8, &change.address, address));
            const slot_hash = slot_hash_of(change.slot);
            if (change.new == 0) {
                try self.trie.delete(root, &slot_hash);
            } else {
                var buffer: [33]u8 = undefined;
                const encoded = trie.state_trie.encode_storage_value(change.new, &buffer);
                try self.trie.put(root, &slot_hash, encoded);
            }
        }
    }

    /// Merges the sorted account changes with the sorted storage addresses.
    fn apply_accounts(
        self: *SparseState,
        accounts: []const AccountChange,
        changes: []const StorageChange,
    ) Error!void {
        var account_index: usize = 0;
        var storage_index: usize = 0;
        var steps: usize = 0;
        while (account_index < accounts.len or storage_index < changes.len) : (steps += 1) {
            assert(steps <= accounts.len + changes.len);
            var address: Address = undefined;
            var change: ?*const AccountChange = null;
            if (storage_index == changes.len or (account_index < accounts.len and address_order(
                &accounts[account_index].address,
                &changes[storage_index].address,
            ) != .gt)) {
                change = &accounts[account_index];
                address = accounts[account_index].address;
                account_index += 1;
            } else {
                address = changes[storage_index].address;
            }
            while (storage_index < changes.len and
                std.mem.eql(u8, &changes[storage_index].address, &address)) storage_index += 1;
            try self.apply_account(&address, change);
        }
    }

    fn apply_account(
        self: *SparseState,
        address: *const Address,
        change: ?*const AccountChange,
    ) Error!void {
        const address_hash = node.keccak256(address);
        if (change) |account_change| {
            if (account_change.new == null) {
                try self.trie.delete(&self.account_root, &address_hash);
                _ = self.storage_roots.remove(address_hash);
                return;
            }
        }
        const current = try self.account_state(&address_hash);
        // Storage changed for an account that neither exists nor is created: bad changeset.
        if (change == null and current == null) return error.InvalidWitness;
        const info: AccountInfo = if (change) |account_change| account_change.new.? else .{
            .nonce = current.?.nonce,
            .balance = current.?.balance,
            .code_hash = current.?.code_hash,
        };
        var storage_root = if (current) |account| account.storage_root else node.empty_root;
        if (self.storage_roots.get(address_hash)) |root| storage_root = self.trie.root_hash(root);
        const account: trie.Account = .{
            .nonce = info.nonce,
            .balance = info.balance,
            .code_hash = info.code_hash,
        };
        var buffer: [trie.state_trie.account_rlp_bytes_max]u8 = undefined;
        const encoded = trie.state_trie.encode_account(&account, &storage_root, &buffer);
        try self.trie.put(&self.account_root, &address_hash, encoded);
    }

    /// Folds the evm's journaled block `State` into `changeset` and applies it: the rules of
    /// `evm_backend.commit_evm` then `Overlay.build_changeset` (old values read from the
    /// witness, no-op changes dropped). A wiped account that survives gets its storage trie
    /// dropped whole (its old slots are not in the witness) and always an account entry, so
    /// its leaf takes the new storage root. Codes are not recorded: only roots are needed.
    pub fn apply_evm(
        self: *SparseState,
        evm_state: *const evm.State,
        changeset: *Changeset,
    ) (Error || changeset_module.Error)!void {
        changeset.clear();
        try self.fold_evm_accounts(evm_state, changeset);
        try self.fold_evm_slots(evm_state, changeset);
        changeset.sort();
        try self.apply(changeset);
        assert(changeset.account_changes().len <= evm_state.accounts.count());
    }

    fn fold_evm_accounts(
        self: *SparseState,
        evm_state: *const evm.State,
        changeset: *Changeset,
    ) (Error || changeset_module.Error)!void {
        var accounts = evm_state.accounts.valueIterator();
        while (accounts.next()) |account| {
            if (!account.dirty) continue;
            const old = try self.basic(account.address);
            const new: ?AccountInfo = if (account.in_database) .{
                .nonce = account.info.nonce,
                .balance = account.info.balance,
                .code_hash = account.info.code_hash,
            } else null;
            const wiped = account.in_database and account.storage_cleared;
            if (wiped) {
                const root = try self.storage_root_slot(&node.keccak256(&account.address));
                root.* = sparse.none;
            }
            const same = if (old != null and new != null)
                old.?.eql(new.?)
            else
                old == null and new == null;
            if (wiped or !same) {
                assert(old != null or new != null);
                const change: AccountChange = .{
                    .address = account.address,
                    .old = old,
                    .new = new,
                };
                try changeset.add_account(change);
            }
        }
    }

    fn fold_evm_slots(
        self: *SparseState,
        evm_state: *const evm.State,
        changeset: *Changeset,
    ) (Error || changeset_module.Error)!void {
        var slots = evm_state.slots.iterator();
        while (slots.next()) |entry| {
            if (!entry.value_ptr.dirty) continue;
            const key = entry.key_ptr;
            const account = evm_state.accounts.getPtr(key.address) orelse continue;
            if (!account.in_database) continue;
            if (entry.value_ptr.epoch != account.storage_epoch) continue;
            const old = try self.storage(key.address, key.slot);
            if (old == entry.value_ptr.present) continue;
            try changeset.add_storage(.{
                .address = key.address,
                .slot = key.slot,
                .old = old,
                .new = entry.value_ptr.present,
            });
        }
    }

    const vtable: evm.state.Database.VTable = .{
        .basic = database_basic,
        .code_by_hash = database_code_by_hash,
        .storage = database_storage,
        .block_hash = database_block_hash,
    };

    /// The evm `Database` over the witness; `self` must outlive it.
    pub fn database(self: *SparseState) evm.state.Database {
        return .{ .context = self, .vtable = &vtable };
    }

    fn from(context: *anyopaque) *SparseState {
        return @ptrCast(@alignCast(context));
    }

    fn database_failure(self: *SparseState, err: Error) evm.state.Error {
        if (err == error.WitnessIncomplete) self.incomplete = true;
        return error.DatabaseFailure;
    }

    fn database_basic(
        context: *anyopaque,
        address: evm.Address,
    ) evm.state.Error!?evm.state.AccountInfo {
        const self = from(context);
        const address_hash = node.keccak256(&address);
        const account = self.account_state(&address_hash) catch |err| {
            return self.database_failure(err);
        } orelse return null;
        return .{
            .balance = account.balance,
            .nonce = account.nonce,
            .code_hash = account.code_hash,
            .has_storage = !std.mem.eql(u8, &account.storage_root, &node.empty_root),
        };
    }

    fn database_code_by_hash(context: *anyopaque, code_hash: evm.B256) evm.state.Error![]const u8 {
        const self = from(context);
        return self.code_by_hash(code_hash) catch |err| self.database_failure(err);
    }

    fn database_storage(
        context: *anyopaque,
        address: evm.Address,
        slot: u256,
    ) evm.state.Error!u256 {
        const self = from(context);
        return self.storage(address, slot) catch |err| self.database_failure(err);
    }

    /// The evm checks the 256-block window first, so a missing header is a witness gap.
    fn database_block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
        const self = from(context);
        return self.block_hash(number) orelse self.database_failure(error.WitnessIncomplete);
    }
};

/// Builds witnesses from a pre-state `State`. Owns its scratch (a sparse state over the
/// candidate nodes, a key set, and proof buffers), allocated once at init.
pub const Builder = struct {
    pub const Config = struct {
        /// Candidate nodes and bytes: proofs of every touched key plus deleted keys' siblings.
        sparse: SparseState.Config,
        keys: KeySet.Config,
    };

    scratch: SparseState,
    touched: KeySet,
    account_proof: *trie.StateTrie.AccountProof,
    storage_proof: *trie.StateTrie.StorageProof,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Builder {
        var scratch = try SparseState.init(allocator, config.sparse);
        errdefer scratch.deinit(allocator);
        var touched = try KeySet.init(allocator, config.keys);
        errdefer touched.deinit(allocator);
        const account_proof = try lazy.create(allocator, trie.StateTrie.AccountProof);
        errdefer lazy.destroy(allocator, account_proof);
        const storage_proof = try lazy.create(allocator, trie.StateTrie.StorageProof);
        return .{
            .scratch = scratch,
            .touched = touched,
            .account_proof = account_proof,
            .storage_proof = storage_proof,
        };
    }

    pub fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        lazy.destroy(allocator, self.storage_proof);
        lazy.destroy(allocator, self.account_proof);
        self.touched.deinit(allocator);
        self.scratch.deinit(allocator);
        self.* = undefined;
    }

    /// Fills `out` with the witness of a block that read `reads` and wrote `changeset` on top
    /// of `state` (the pre-state, before `changeset` is applied). `headers` are the RLP
    /// ancestors for BLOCKHASH. Returns the post-state root computed from the witness alone.
    pub fn build(
        self: *Builder,
        state: *State,
        reads: *const KeySet,
        changeset: *const Changeset,
        headers: []const []const u8,
        out: *Witness,
    ) (Error || state_module.Error)!Hash {
        return self.build_from(self.state_source(state), reads, changeset, headers, out);
    }

    /// The live pre-state `state` as a node source (uses the builder's proof buffers).
    pub fn state_source(self: *Builder, state: *State) StateSource {
        return .{
            .state = state,
            .account_proof = self.account_proof,
            .storage_proof = self.storage_proof,
        };
    }

    /// `build` over any pre-state node source (`StateSource`, `HistorySource`): proofs of
    /// every touched key, hashed siblings along deleted keys, and codes by hash.
    pub fn build_from(
        self: *Builder,
        source: anytype,
        reads: *const KeySet,
        changeset: *const Changeset,
        headers: []const []const u8,
        out: *Witness,
    ) !Hash {
        const pre_root = try source.pre_root();
        out.clear();
        self.touched.clear();
        try self.touched.merge(reads);
        for (changeset.account_changes()) |*change| try self.touched.add_account(change.address);
        for (changeset.storage_changes()) |*change| {
            try self.touched.add_slot(change.address, change.slot);
        }
        self.scratch.clear(pre_root);
        try self.collect_proofs(source);
        try self.collect_siblings(source, changeset);
        try replay(&self.scratch, reads, changeset);
        const post_root = self.scratch.state_root();
        const nodes = self.scratch.nodes;
        for (nodes.entries[0..nodes.count]) |*entry| {
            if (entry.accessed) try out.state.append(nodes.bytes_of(entry));
        }
        for (self.touched.codes.slice()) |hash| {
            if (std.mem.eql(u8, &hash, &node.empty_code_hash)) continue;
            try out.codes.append(source.code_by_hash(hash) orelse return error.UnknownCode);
        }
        for (self.touched.accounts.slice()) |*address| try out.keys.append(address);
        for (self.touched.slots.slice()) |key| {
            var slot: [32]u8 = undefined;
            std.mem.writeInt(u256, &slot, key.slot, .big);
            try out.keys.append(&slot);
        }
        for (headers) |header| try out.headers.append(header);
        assert(out.keys.count == self.touched.accounts.len + self.touched.slots.len);
        return post_root;
    }

    const Collector = struct {
        store: *NodeStore,

        pub fn visit(self: Collector, bytes: []const u8) error{WitnessFull}!void {
            _ = try self.store.add(bytes);
        }
    };

    fn collect_proofs(self: *Builder, source: anytype) !void {
        const collector: Collector = .{ .store = self.scratch.nodes };
        for (self.touched.accounts.slice()) |*address| {
            try source.visit_account_proof(&node.keccak256(address), collector);
        }
        for (self.touched.slots.slice()) |*key| {
            const address_hash = node.keccak256(&key.address);
            try source.visit_storage_proof(&address_hash, &slot_hash_of(key.slot), collector);
        }
    }

    fn collect_siblings(self: *Builder, source: anytype, changeset: *const Changeset) !void {
        const collector: Collector = .{ .store = self.scratch.nodes };
        for (changeset.account_changes()) |*change| {
            if (change.new != null) continue;
            try source.visit_account_siblings(&node.keccak256(&change.address), collector);
        }
        for (changeset.storage_changes()) |*change| {
            if (change.new != 0) continue;
            const address_hash = node.keccak256(&change.address);
            const slot_hash = slot_hash_of(change.slot);
            try source.visit_storage_siblings(&address_hash, &slot_hash, collector);
        }
    }
};

/// Witness nodes from the live trie of a pre-state `State` (`Builder.state_source`).
pub const StateSource = struct {
    state: *State,
    account_proof: *trie.StateTrie.AccountProof,
    storage_proof: *trie.StateTrie.StorageProof,

    pub fn pre_root(self: StateSource) state_module.Error!Hash {
        return self.state.state_root();
    }

    pub fn visit_account_proof(
        self: StateSource,
        address_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.state.state_trie.prove_account(address_hash.*, self.account_proof);
        assert(self.account_proof.count > 0);
        for (0..self.account_proof.count) |index| {
            try visitor.visit(self.account_proof.node_at(@intCast(index)));
        }
    }

    pub fn visit_storage_proof(
        self: StateSource,
        address_hash: *const Hash,
        slot_hash: *const Hash,
        visitor: anytype,
    ) !void {
        const state_trie = &self.state.state_trie;
        state_trie.prove_storage(address_hash.*, slot_hash.*, self.storage_proof);
        for (0..self.storage_proof.count) |index| {
            try visitor.visit(self.storage_proof.node_at(@intCast(index)));
        }
    }

    pub fn visit_account_siblings(
        self: StateSource,
        address_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.state.state_trie.visit_account_siblings(address_hash.*, visitor);
    }

    pub fn visit_storage_siblings(
        self: StateSource,
        address_hash: *const Hash,
        slot_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.state.state_trie.visit_storage_siblings(address_hash.*, slot_hash.*, visitor);
    }

    pub fn code_by_hash(self: StateSource, hash: Hash) ?[]const u8 {
        return self.state.code_by_hash(hash);
    }
};

/// Witness nodes of block `number`'s state from the history store (no live trie is
/// touched). Codes come from `codes` (a `State`'s code store, which never deletes).
pub const HistorySource = struct {
    store: *const history.Store,
    number: u64,
    codes: *const State,

    pub fn pre_root(self: HistorySource) history.Error!Hash {
        return self.store.state_root_at(self.number);
    }

    pub fn visit_account_proof(
        self: HistorySource,
        address_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.store.visit_account_proof(self.number, address_hash, visitor);
    }

    pub fn visit_storage_proof(
        self: HistorySource,
        address_hash: *const Hash,
        slot_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.store.visit_storage_proof(self.number, address_hash, slot_hash, visitor);
    }

    pub fn visit_account_siblings(
        self: HistorySource,
        address_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.store.visit_account_siblings(self.number, address_hash, visitor);
    }

    pub fn visit_storage_siblings(
        self: HistorySource,
        address_hash: *const Hash,
        slot_hash: *const Hash,
        visitor: anytype,
    ) !void {
        try self.store.visit_storage_siblings(self.number, address_hash, slot_hash, visitor);
    }

    pub fn code_by_hash(self: HistorySource, hash: Hash) ?[]const u8 {
        return self.codes.code_by_hash(hash);
    }
};

/// The stateless trie work of a block: every recorded account and slot read, then the
/// changeset. The builder keeps exactly the nodes this decodes, so a verifier running it
/// (or any order of the same reads and changeset) needs every one of them.
pub fn replay(
    sparse_state: *SparseState,
    reads: *const KeySet,
    changeset: *const Changeset,
) Error!void {
    for (reads.accounts.slice()) |address| _ = try sparse_state.basic(address);
    for (reads.slots.slice()) |key| _ = try sparse_state.storage(key.address, key.slot);
    try sparse_state.apply(changeset);
}

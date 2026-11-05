//! Historical proofs store: `eth_getProof` at any block of a retention window, without
//! re-execution. Mirrors base/base `crates/execution/trie` (`BaseProofsStore`): trie node
//! preimages are versioned by (trie, path, block), and a proof at block N walks the trie from
//! the state root of N, taking at each path the newest version written at or before N.
//!
//! Why paths and not hashes: a path has one node per block, so the newest version at or before
//! N is exactly the node of N whenever N's parent node points at that path, and pruning is
//! per path (a version is dropped once a newer one is at or before the window start). The
//! store is fed by `StateTrie.visit_nodes`: every node rehashed in a block is written at its
//! path. Nodes a block removes need no tombstone, since a parent of N never points at them.
//! Every node of a proof is checked against the reference its parent holds.
//!
//! Leaf values are the leaves themselves (accounts and slots decode from leaf nodes), so no
//! separate leaf history is kept. All memory is sized at init from `Config`.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const changeset_module = @import("changeset.zig");
const rlp = trie.rlp;
const nibbles_module = trie.nibbles;
const StateTrie = trie.StateTrie;

pub const Address = changeset_module.Address;
pub const Hash = changeset_module.Hash;

pub const Config = struct {
    /// Proofs work for blocks `[head - window_blocks + 1, head]`.
    window_blocks: u32,
    /// Distinct (trie, path) keys ever stored. Paths are never freed (see `Store`).
    paths_max: u32,
    /// Node versions with encodings of at most `small_bytes` bytes (leaves, extensions,
    /// sparse branches), across the window plus one base version per path.
    small_versions_max: u32,
    /// Node versions with longer encodings (dense branches).
    large_versions_max: u32,
};

pub const Error = error{
    /// The block is not in `[oldest, head]`.
    BlockOutOfWindow,
    /// `commit_block` takes `head + 1` only.
    NotNextBlock,
    /// Not enough paths or versions for the block; the store keeps its previous head.
    HistoryFull,
    /// `reset` has not run (or failed).
    NotInitialized,
    /// A stored node does not decode or does not match its parent's reference.
    HistoryCorrupt,
} || trie.state_trie.Error;

/// Largest encoding kept in a small version: an account leaf (148 bytes) fits.
pub const small_bytes = 160;
pub const large_bytes = @max(StateTrie.account_node_bytes_max, StateTrie.storage_node_bytes_max);
const path_nibbles_max = 64;

comptime {
    assert(2 + 34 + 2 + trie.state_trie.account_rlp_bytes_max <= small_bytes);
    assert(small_bytes < large_bytes);
    assert(large_bytes < std.math.maxInt(u16));
}

/// Owner (32 bytes), storage flag, path length, packed path nibbles.
const Key = [32 + 1 + 1 + path_nibbles_max / 2]u8;

fn make_key(owner: ?Hash, path: []const u8) Key {
    assert(path.len <= path_nibbles_max);
    var key: Key = @splat(0);
    if (owner) |hash| {
        key[0..32].* = hash;
        key[32] = 1;
    }
    key[33] = @intCast(path.len);
    for (path, 0..) |nibble, index| {
        assert(nibble < 16);
        key[34 + index / 2] |= if (index % 2 == 0) nibble << 4 else nibble;
    }
    return key;
}

const none: u32 = std.math.maxInt(u32);
const large_bit: u32 = 1 << 31;

const Version = struct {
    block: u64,
    /// The next older version of the same path, or `none`.
    prev: u32,
    /// The next version written in the same block (unwind and prune), or `none`.
    block_next: u32,
    path: u32,
    len: u16,
};

const Path = struct { key: Key, head: u32 };

const BlockEntry = struct {
    number: u64,
    state_root: Hash,
    /// Versions written in this block; `none` for the oldest block (they are base versions).
    versions: u32,
};

/// The account fields of an account leaf.
pub const AccountState = struct {
    nonce: u64,
    balance: u256,
    storage_root: Hash,
    code_hash: Hash,
};

/// A free list of version slots of one size class.
fn Pool(comptime bytes: u32) type {
    return struct {
        const Self = @This();
        versions: []Version,
        data: [][bytes]u8,
        free: []u32,
        free_len: u32,

        fn init(allocator: std.mem.Allocator, count: u32) !Self {
            const versions = try allocator.alloc(Version, count);
            errdefer allocator.free(versions);
            const data = try allocator.alloc([bytes]u8, count);
            errdefer allocator.free(data);
            const free = try allocator.alloc(u32, count);
            var self: Self = .{ .versions = versions, .data = data, .free = free, .free_len = 0 };
            self.clear();
            return self;
        }

        fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.free);
            allocator.free(self.data);
            allocator.free(self.versions);
            self.* = undefined;
        }

        fn clear(self: *Self) void {
            for (self.free, 0..) |*slot, index| slot.* = @intCast(self.free.len - 1 - index);
            self.free_len = @intCast(self.free.len);
        }

        fn take(self: *Self) u32 {
            assert(self.free_len > 0);
            self.free_len -= 1;
            const index = self.free[self.free_len];
            assert(index < self.versions.len);
            return index;
        }

        fn give(self: *Self, index: u32) void {
            assert(index < self.versions.len);
            assert(self.free_len < self.free.len);
            self.free[self.free_len] = index;
            self.free_len += 1;
        }
    };
}

/// What a block will need, from a `count` walk.
const Needs = struct {
    paths: u32 = 0,
    small: u32 = 0,
    large: u32 = 0,
};

pub const Store = struct {
    config: Config,
    path_index: std.AutoHashMapUnmanaged(Key, u32),
    paths: []Path,
    paths_len: u32,
    small: Pool(small_bytes),
    large: Pool(large_bytes),
    /// Ring of retained blocks, oldest first.
    blocks: []BlockEntry,
    blocks_start: u32,
    blocks_len: u32,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Store {
        assert(config.window_blocks > 0);
        assert(config.small_versions_max < large_bit and config.large_versions_max < large_bit);
        var path_index: std.AutoHashMapUnmanaged(Key, u32) = .empty;
        try path_index.ensureTotalCapacity(allocator, config.paths_max);
        errdefer path_index.deinit(allocator);
        const paths = try allocator.alloc(Path, config.paths_max);
        errdefer allocator.free(paths);
        var small = try Pool(small_bytes).init(allocator, config.small_versions_max);
        errdefer small.deinit(allocator);
        var large = try Pool(large_bytes).init(allocator, config.large_versions_max);
        errdefer large.deinit(allocator);
        const blocks = try allocator.alloc(BlockEntry, config.window_blocks);
        return .{
            .config = config,
            .path_index = path_index,
            .paths = paths,
            .paths_len = 0,
            .small = small,
            .large = large,
            .blocks = blocks,
            .blocks_start = 0,
            .blocks_len = 0,
        };
    }

    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        allocator.free(self.blocks);
        self.large.deinit(allocator);
        self.small.deinit(allocator);
        allocator.free(self.paths);
        self.path_index.deinit(allocator);
        self.* = undefined;
    }

    /// Oldest and newest retained block, or null before `reset`.
    pub fn window(self: *const Store) ?struct { oldest: u64, head: u64 } {
        if (self.blocks_len == 0) return null;
        const oldest = self.block_at(0).number;
        const head = self.block_at(self.blocks_len - 1).number;
        assert(head - oldest + 1 == self.blocks_len);
        return .{ .oldest = oldest, .head = head };
    }

    fn block_at(self: *const Store, offset: u32) *BlockEntry {
        assert(offset < self.blocks_len);
        return &self.blocks[(self.blocks_start + offset) % self.blocks.len];
    }

    fn version(self: *const Store, id: u32) *Version {
        if (id & large_bit != 0) return &self.large.versions[id & ~large_bit];
        return &self.small.versions[id];
    }

    fn encoding(self: *const Store, id: u32) []const u8 {
        const length = self.version(id).len;
        if (id & large_bit != 0) return self.large.data[id & ~large_bit][0..length];
        return self.small.data[id][0..length];
    }

    fn release(self: *Store, id: u32) void {
        if (id & large_bit != 0) self.large.give(id & ~large_bit) else self.small.give(id);
    }

    /// Drops all history and stores every node of `state_trie` as block `number`, the new
    /// oldest block and head. `state_trie` must have change tracking enabled; after this, only
    /// nodes rehashed later are fed by `commit_block`.
    pub fn reset(self: *Store, state_trie: *StateTrie, number: u64) Error!void {
        self.path_index.clearRetainingCapacity();
        self.paths_len = 0;
        self.small.clear();
        self.large.clear();
        self.blocks_start = 0;
        self.blocks_len = 1;
        const root = try state_trie.root();
        self.blocks[0] = .{ .number = number, .state_root = root, .versions = none };
        var writer: Writer = .{ .store = self, .number = number };
        state_trie.visit_nodes(.all, &writer) catch |err| {
            self.blocks_len = 0;
            return err;
        };
        // The snapshot block is the oldest: its versions are base versions.
        self.blocks[0].versions = none;
        assert(self.window().?.head == number);
    }

    /// Records block `number` (`head + 1`) from the nodes `state_trie` rehashed since the
    /// previous `commit_block`, `reset`, or `unwind_to`. Drops the oldest block once the
    /// window is full. On `HistoryFull` nothing of the block is stored.
    pub fn commit_block(self: *Store, state_trie: *StateTrie, number: u64) Error!void {
        const current = self.window() orelse return error.NotInitialized;
        if (number != current.head + 1) return error.NotNextBlock;
        const root = try state_trie.root();
        if (self.blocks_len == self.blocks.len) self.drop_oldest();
        var counter: Counter = .{ .store = self };
        try state_trie.visit_nodes(.count, &counter);
        if (self.paths_len + counter.needs.paths > self.paths.len) return error.HistoryFull;
        if (counter.needs.small > self.small.free_len) return error.HistoryFull;
        if (counter.needs.large > self.large.free_len) return error.HistoryFull;
        assert(self.blocks_len < self.blocks.len);
        self.blocks_len += 1;
        const entry = self.block_at(self.blocks_len - 1);
        entry.* = .{ .number = number, .state_root = root, .versions = none };
        var writer: Writer = .{ .store = self, .number = number };
        try state_trie.visit_nodes(.drain, &writer);
        if (self.blocks_len == 1) self.make_base(entry);
        assert(self.window().?.head == number);
    }

    /// Reorg: forgets every block above `number`, which must be in the window. The state
    /// trie must be moved back to `number` too (`State.unwind`); the nodes that move rehashes
    /// are written again (unchanged encodings are skipped) by the next `commit_block`.
    pub fn unwind_to(self: *Store, number: u64) Error!void {
        const current = self.window() orelse return error.NotInitialized;
        if (number < current.oldest or number > current.head) return error.BlockOutOfWindow;
        while (self.block_at(self.blocks_len - 1).number > number) {
            assert(self.blocks_len > 1);
            const entry = self.block_at(self.blocks_len - 1);
            var id = entry.versions;
            var count: u64 = 0;
            while (id != none) : (count += 1) {
                assert(count < self.small.versions.len + self.large.versions.len);
                const removed = self.version(id);
                const path = &self.paths[removed.path];
                assert(path.head == id);
                assert(removed.block == entry.number);
                path.head = removed.prev;
                const next = removed.block_next;
                self.release(id);
                id = next;
            }
            self.blocks_len -= 1;
        }
        assert(self.window().?.head == number);
    }

    fn drop_oldest(self: *Store) void {
        assert(self.blocks_len > 0);
        self.blocks_start = @intCast((self.blocks_start + 1) % self.blocks.len);
        self.blocks_len -= 1;
        if (self.blocks_len > 0) self.make_base(self.block_at(0));
    }

    /// `entry` became the oldest block: older versions of its paths are no longer reachable.
    fn make_base(self: *Store, entry: *BlockEntry) void {
        var id = entry.versions;
        var count: u64 = 0;
        while (id != none) : (count += 1) {
            assert(count < self.small.versions.len + self.large.versions.len);
            const current = self.version(id);
            assert(current.block == entry.number);
            if (current.prev != none) {
                const older = self.version(current.prev);
                assert(older.block < entry.number);
                // Versions at or below the oldest block never keep an older version.
                assert(older.prev == none);
                self.release(current.prev);
                current.prev = none;
            }
            id = current.block_next;
        }
        entry.versions = none;
    }

    /// The newest version of the path at or before `number`.
    fn lookup(self: *const Store, owner: ?Hash, path: []const u8, number: u64) ?u32 {
        const path_id = self.path_index.get(make_key(owner, path)) orelse return null;
        var id = self.paths[path_id].head;
        var steps: u64 = 0;
        while (id != none) : (steps += 1) {
            assert(steps <= self.blocks.len);
            const current = self.version(id);
            assert(current.path == path_id);
            if (current.block <= number) return id;
            id = current.prev;
        }
        return null;
    }

    /// Whether `visit` needs a new version, and whether its path is new.
    fn needs_version(self: *const Store, key: *const Key, visit_encoding: []const u8) struct {
        version: bool,
        path_id: ?u32,
    } {
        const path_id = self.path_index.get(key.*) orelse
            return .{ .version = true, .path_id = null };
        const head = self.paths[path_id].head;
        if (head == none) return .{ .version = true, .path_id = path_id };
        const same = std.mem.eql(u8, self.encoding(head), visit_encoding);
        return .{ .version = !same, .path_id = path_id };
    }

    const Counter = struct {
        store: *const Store,
        needs: Needs = .{},

        pub fn visit(self: *Counter, visit_info: StateTrie.NodeVisit) error{}!void {
            assert(visit_info.encoding.len <= large_bytes);
            const key = make_key(visit_info.owner, visit_info.path);
            const needed = self.store.needs_version(&key, visit_info.encoding);
            if (!needed.version) return;
            if (needed.path_id == null) self.needs.paths += 1;
            if (visit_info.encoding.len <= small_bytes) self.needs.small += 1;
            if (visit_info.encoding.len > small_bytes) self.needs.large += 1;
        }
    };

    const Writer = struct {
        store: *Store,
        number: u64,

        pub fn visit(self: *Writer, visit_info: StateTrie.NodeVisit) error{HistoryFull}!void {
            try self.store.put_version(self.number, &visit_info);
        }
    };

    fn put_version(
        self: *Store,
        number: u64,
        visit: *const StateTrie.NodeVisit,
    ) error{HistoryFull}!void {
        const length = visit.encoding.len;
        assert(length > 0 and length <= large_bytes);
        const key = make_key(visit.owner, visit.path);
        const needed = self.needs_version(&key, visit.encoding);
        if (!needed.version) return;
        const path_id = needed.path_id orelse blk: {
            if (self.paths_len == self.paths.len) return error.HistoryFull;
            const id = self.paths_len;
            self.paths[id] = .{ .key = key, .head = none };
            self.path_index.putAssumeCapacityNoClobber(key, id);
            self.paths_len += 1;
            break :blk id;
        };
        var id: u32 = undefined;
        if (length <= small_bytes) {
            if (self.small.free_len == 0) return error.HistoryFull;
            id = self.small.take();
            @memcpy(self.small.data[id][0..length], visit.encoding);
        } else {
            if (self.large.free_len == 0) return error.HistoryFull;
            const index = self.large.take();
            @memcpy(self.large.data[index][0..length], visit.encoding);
            id = index | large_bit;
        }
        const path = &self.paths[path_id];
        if (path.head != none) assert(self.version(path.head).block < number);
        const entry = self.block_at(self.blocks_len - 1);
        assert(entry.number == number);
        self.version(id).* = .{
            .block = number,
            .prev = path.head,
            .block_next = entry.versions,
            .path = path_id,
            .len = @intCast(length),
        };
        path.head = id;
        entry.versions = id;
    }

    /// The state root of block `number`.
    pub fn state_root_at(self: *const Store, number: u64) Error!Hash {
        const current = self.window() orelse return error.NotInitialized;
        if (number < current.oldest or number > current.head) return error.BlockOutOfWindow;
        const entry = self.block_at(@intCast(number - current.oldest));
        assert(entry.number == number);
        return entry.state_root;
    }

    /// `eth_getProof(address, slots, number)`: fills the account proof, one storage proof and
    /// value per slot, and returns the account (null when absent at `number`). Proofs have the
    /// format of `StateTrie.prove_account`/`prove_storage` on the state of block `number`.
    pub fn get_proof(
        self: *const Store,
        number: u64,
        address: Address,
        slots: []const u256,
        account_proof: *StateTrie.AccountProof,
        storage_proofs: []StateTrie.StorageProof,
        values: []u256,
    ) Error!?AccountState {
        assert(slots.len == storage_proofs.len and slots.len == values.len);
        const account = try self.prove_account(number, address, account_proof);
        const storage_root = if (account) |found| found.storage_root else trie.empty_root;
        const address_hash = trie.node.keccak256(&address);
        for (slots, storage_proofs, values) |slot, *proof, *value| {
            value.* = try self.prove_storage(number, address_hash, storage_root, slot, proof);
        }
        return account;
    }

    /// The account proof at block `number`; returns the account or null when absent.
    pub fn prove_account(
        self: *const Store,
        number: u64,
        address: Address,
        proof: *StateTrie.AccountProof,
    ) Error!?AccountState {
        const root = try self.state_root_at(number);
        const address_hash = trie.node.keccak256(&address);
        const value = try self.prove_path(null, root, &address_hash, number, proof) orelse
            return null;
        return decode_account(value) catch return error.HistoryCorrupt;
    }

    /// The storage proof of `slot` at block `number` in the storage trie of `address_hash`,
    /// whose root at that block is `storage_root` (from the account); returns the value.
    pub fn prove_storage(
        self: *const Store,
        number: u64,
        address_hash: Hash,
        storage_root: Hash,
        slot: u256,
        proof: *StateTrie.StorageProof,
    ) Error!u256 {
        _ = try self.state_root_at(number);
        var slot_bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &slot_bytes, slot, .big);
        const slot_hash = trie.node.keccak256(&slot_bytes);
        const owner: ?Hash = address_hash;
        const value = try self.prove_path(owner, storage_root, &slot_hash, number, proof) orelse
            return 0;
        return decode_storage_value(value) catch return error.HistoryCorrupt;
    }

    /// Walks the trie of `owner` at block `number` from `root` along `key`, appending every
    /// hashed node (and the root) to `proof`, like `TrieType.prove_in`. Returns the leaf value
    /// (pointing into the store) or null for an exclusion proof.
    fn prove_path(
        self: *const Store,
        owner: ?Hash,
        root: Hash,
        key: *const Hash,
        number: u64,
        proof: anytype,
    ) Error!?[]const u8 {
        proof.count = 0;
        if (std.mem.eql(u8, &root, &trie.empty_root)) return null;
        const path = trie.Nibbles.from_bytes(key);
        const nibbles = path.slice();
        assert(nibbles.len == path_nibbles_max);
        var consumed: u32 = 0;
        var reference: Reference = .{ .hash = root };
        var depth: u32 = 0;
        while (depth <= path_nibbles_max + 1) : (depth += 1) {
            const id = self.lookup(owner, nibbles[0..consumed], number) orelse
                return error.HistoryCorrupt;
            const bytes = self.encoding(id);
            switch (reference) {
                .hash => |hash| if (!std.mem.eql(u8, &trie.node.keccak256(bytes), &hash)) {
                    return error.HistoryCorrupt;
                },
                .embedded => |inline_bytes| if (!std.mem.eql(u8, inline_bytes, bytes)) {
                    return error.HistoryCorrupt;
                },
            }
            if (depth == 0 or bytes.len >= 32) append_node(proof, bytes);
            const step = step_node(bytes, nibbles[consumed..]) catch return error.HistoryCorrupt;
            switch (step) {
                .found => |value| return value,
                .absent => return null,
                .next => |next| {
                    consumed += next.consumed;
                    assert(consumed <= path_nibbles_max);
                    reference = next.reference;
                },
            }
        }
        return error.HistoryCorrupt;
    }
};

fn append_node(proof: anytype, bytes: []const u8) void {
    assert(proof.count < proof.ends.len);
    const start = if (proof.count == 0) 0 else proof.ends[proof.count - 1];
    assert(start + bytes.len <= proof.buffer.len);
    @memcpy(proof.buffer[start..][0..bytes.len], bytes);
    proof.ends[proof.count] = start + @as(u32, @intCast(bytes.len));
    proof.count += 1;
}

const Reference = union(enum) {
    hash: Hash,
    embedded: []const u8,
};

pub const StepError = error{InvalidNode} || rlp.DecodeError;

pub const Step = union(enum) {
    found: []const u8,
    absent,
    next: struct { consumed: u32, reference: Reference },
};

/// Decodes one node and returns where the walk along `rest` goes next.
pub fn step_node(bytes: []const u8, rest: []const u8) StepError!Step {
    const outer = try rlp.decode_item(bytes);
    if (outer.kind != .list or outer.encoded_length != bytes.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string) return error.InvalidNode;
        if (rest.len == 0) {
            if (items[16].payload.len == 0) return .absent;
            return .{ .found = items[16].payload };
        }
        const reference = try child_reference(items[rest[0]]) orelse return .absent;
        return .{ .next = .{ .consumed = 1, .reference = reference } };
    }
    if (count != 2 or items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch {
        return error.InvalidNode;
    };
    const node_path = decoded.path.slice();
    if (decoded.leaf) {
        if (items[1].kind != .string or items[1].payload.len == 0) return error.InvalidNode;
        if (!std.mem.eql(u8, node_path, rest)) return .absent;
        return .{ .found = items[1].payload };
    }
    if (node_path.len == 0) return error.InvalidNode;
    if (!std.mem.startsWith(u8, rest, node_path)) return .absent;
    const reference = try child_reference(items[1]) orelse return error.InvalidNode;
    return .{ .next = .{ .consumed = @intCast(node_path.len), .reference = reference } };
}

fn child_reference(item: rlp.Item) StepError!?Reference {
    switch (item.kind) {
        .string => {
            if (item.payload.len == 0) return null;
            if (item.payload.len != 32) return error.InvalidNode;
            return .{ .hash = item.payload[0..32].* };
        },
        .list => {
            if (item.raw.len >= 32) return error.InvalidNode;
            return .{ .embedded = item.raw };
        },
    }
}

pub const ValueError = error{InvalidValue} || rlp.DecodeError;

fn decode_integer(comptime T: type, item: rlp.Item) ValueError!T {
    if (item.kind != .string) return error.InvalidValue;
    if (item.payload.len > @sizeOf(T)) return error.InvalidValue;
    if (item.payload.len > 0 and item.payload[0] == 0) return error.InvalidValue;
    var result: T = 0;
    for (item.payload) |byte| result = (result << 8) | byte;
    return result;
}

fn decode_hash(item: rlp.Item) ValueError!Hash {
    if (item.kind != .string or item.payload.len != 32) return error.InvalidValue;
    return item.payload[0..32].*;
}

/// Decodes an account leaf value `rlp([nonce, balance, storage_root, code_hash])`.
pub fn decode_account(value: []const u8) ValueError!AccountState {
    const outer = try rlp.decode_item(value);
    if (outer.kind != .list or outer.encoded_length != value.len) return error.InvalidValue;
    var items: [4]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidValue;
    if (count != 4) return error.InvalidValue;
    return .{
        .nonce = try decode_integer(u64, items[0]),
        .balance = try decode_integer(u256, items[1]),
        .storage_root = try decode_hash(items[2]),
        .code_hash = try decode_hash(items[3]),
    };
}

/// Decodes a storage leaf value `rlp(value)`; stored values are never zero.
pub fn decode_storage_value(value: []const u8) ValueError!u256 {
    const item = try rlp.decode_item(value);
    if (item.encoded_length != value.len) return error.InvalidValue;
    const result = try decode_integer(u256, item);
    if (result == 0) return error.InvalidValue;
    return result;
}

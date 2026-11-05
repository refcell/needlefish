//! Witness diff: compare two execution witnesses (`debug_executionWitness` results) and find
//! the trie nodes, codes, keys, accounts, and storage slots where they diverge. Port of
//! base/base `etc/tools/witness-diff`; the `witness-diff` binary does the IO.
//!
//! Use case: two nodes disagree on a block's state root. Each node's witness for that block
//! holds the pre-state trie nodes, codes, and key preimages its execution touched; where the
//! executions (or the pre-states) differ, the witnesses differ.
//!
//! - `Parser` reads a witness JSON document into a bounded `witness.Witness`: either the
//!   `result` object itself or a whole JSON-RPC response. `state`, `codes`, `keys`, and
//!   `headers` may each be an array of hex strings (ours, reth, geth), an object whose values
//!   are hex strings (older reth maps keyed by hash), null, or absent. Keys are normalized:
//!   reth RLP-encodes them (`0x94 ++ address`, `0xa0 ++ slot`); the RLP header is stripped
//!   so our raw 20/32-byte keys and reth's compare equal.
//! - `Differ.diff` compares `state`, `codes`, and `keys` as sets keyed by keccak256 (as the
//!   reference does), then walks each witness's account trie from its pre-state root and
//!   descends into every storage trie it reaches. Each leaf gets its full key: the hashed
//!   address, and for storage the hashed slot, so a diverging leaf is attributed to an
//!   account and slot (the reference matches leaves by their partial path only). Preimages
//!   from both witnesses' keys turn hashed keys back into addresses and slots.
//! - `render` writes the report as stable text with the reference's sections.
//!
//! The pre-state root of a witness is the state root of its last header (the parent) when
//! that node is in the witness, else the only decodable node no other node references.
//! Everything is bounded by `Config`; nothing here allocates after `init`.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const trie = @import("../trie/root.zig");
const witness_module = @import("witness.zig");

const rlp = trie.rlp;
const node = trie.node;
const sparse = trie.sparse;
const Nibbles = trie.nibbles.Nibbles;
const RlpNode = node.RlpNode;
const keccak256 = node.keccak256;

pub const Witness = witness_module.Witness;
pub const ByteList = witness_module.ByteList;
pub const Hash = [32]u8;
pub const Address = [20]u8;

// Parsing.

pub const ParseError = error{
    InvalidJson,
    NotAnObject,
    RpcError,
    DuplicateField,
    InvalidField,
    InvalidHex,
    InvalidKey,
    ItemTooLarge,
    WitnessFull,
};

const fields = [_][]const u8{ "state", "codes", "keys", "headers" };

/// Reads witness JSON into a `Witness`. Holds one scratch buffer for the largest item.
pub const Parser = struct {
    scratch: []u8,

    pub fn init(allocator: std.mem.Allocator, item_bytes_max: u32) !Parser {
        assert(item_bytes_max > 0);
        return .{ .scratch = try lazy.alloc(allocator, u8, item_bytes_max) };
    }

    pub fn deinit(self: *Parser, allocator: std.mem.Allocator) void {
        lazy.free(allocator, self.scratch);
        self.* = undefined;
    }

    /// Parses `input` into `out` (cleared first). On error `out` holds a partial witness.
    pub fn parse(self: *Parser, input: []const u8, out: *Witness) ParseError!void {
        out.clear();
        if (input.len > std.math.maxInt(u32)) return error.InvalidJson;
        json.validate(input) catch return error.InvalidJson;
        const rpc_error = json.find_path(input, &.{"error"}) catch return error.InvalidJson;
        if (rpc_error) |value| {
            if (!std.mem.eql(u8, value, "null")) return error.RpcError;
        }
        const result = json.find_path(input, &.{"result"}) catch return error.InvalidJson;
        const body = result orelse input;
        var scanner = json.Scanner.init(body);
        const first = scanner.next() catch return error.InvalidJson;
        if (first.tag != .object_begin) return error.NotAnObject;
        var seen: [fields.len]bool = @splat(false);
        // Each member consumes at least one byte, so the body length bounds the loop.
        var members: u32 = 0;
        while (members <= body.len) : (members += 1) {
            const key = scanner.next() catch return error.InvalidJson;
            if (key.tag == .object_end) return;
            assert(key.tag == .string and key.key);
            const field = field_index(key) orelse {
                const value = scanner.next() catch return error.InvalidJson;
                scanner.skip(value) catch return error.InvalidJson;
                continue;
            };
            if (seen[field]) return error.DuplicateField;
            seen[field] = true;
            const list = switch (field) {
                0 => &out.state,
                1 => &out.codes,
                2 => &out.keys,
                3 => &out.headers,
                else => unreachable,
            };
            try self.parse_list(&scanner, list, field == 2);
        }
        unreachable; // The scanner ends the object before `members` exceeds the length.
    }

    fn parse_list(
        self: *Parser,
        scanner: *json.Scanner,
        list: *ByteList,
        normalize: bool,
    ) ParseError!void {
        const open = scanner.next() catch return error.InvalidJson;
        const close: json.TokenTag = switch (open.tag) {
            .null => return,
            .array_begin => .array_end,
            .object_begin => .object_end,
            else => return error.InvalidField,
        };
        const count_before = list.count;
        // Every item consumes at least one input byte.
        var items: u32 = 0;
        while (items <= scanner.input.len) : (items += 1) {
            var token = scanner.next() catch return error.InvalidJson;
            if (token.tag == close) {
                assert(list.count >= count_before);
                return;
            }
            if (close == .object_end) {
                assert(token.key); // Map keys are hashes; recomputed, so ignored.
                token = scanner.next() catch return error.InvalidJson;
            }
            if (token.tag != .string) return error.InvalidField;
            const bytes = try self.decode_item(token);
            try list.append(if (normalize) try normalize_key(bytes) else bytes);
        }
        unreachable; // The scanner closes the container first.
    }

    fn decode_item(self: *Parser, token: json.Token) ParseError![]const u8 {
        assert(token.tag == .string);
        if (token.escaped) return error.InvalidHex; // Hex never needs escapes.
        const bytes = json.parse_data(token.bytes, self.scratch) catch |err| switch (err) {
            error.NoSpaceLeft => return error.ItemTooLarge,
            else => return error.InvalidHex,
        };
        assert(bytes.len <= self.scratch.len);
        return bytes;
    }
};

fn field_index(key: json.Token) ?u32 {
    assert(key.tag == .string);
    if (key.escaped) return null;
    for (fields, 0..) |name, index| {
        if (std.mem.eql(u8, key.bytes, name)) return @intCast(index);
    }
    return null;
}

/// Strips reth's RLP header from a key preimage (`0x94 ++ address`, `0xa0 ++ slot`). Other
/// keys up to 32 bytes are kept as they are.
pub fn normalize_key(bytes: []const u8) error{InvalidKey}![]const u8 {
    if (bytes.len == 21 and bytes[0] == 0x80 + 20) return bytes[1..];
    if (bytes.len == 33 and bytes[0] == 0x80 + 32) return bytes[1..];
    if (bytes.len > 32) return error.InvalidKey;
    assert(bytes.len <= 32);
    return bytes;
}

// Leaf values.

pub const Account = struct {
    nonce: u64,
    balance: u256,
    storage_root: Hash,
    code_hash: Hash,
};

/// A canonical big-endian RLP integer of at most `bytes_max` bytes.
fn rlp_integer(item: rlp.Item, comptime T: type) ?T {
    if (item.kind != .string or item.payload.len > @sizeOf(T)) return null;
    if (item.payload.len > 0 and item.payload[0] == 0) return null;
    var value: T = 0;
    for (item.payload) |byte| value = (value << 8) | byte;
    return value;
}

/// Decodes an account-trie leaf value: `rlp([nonce, balance, storage_root, code_hash])`.
pub fn decode_account(value: []const u8) ?Account {
    const outer = rlp.decode_item(value) catch return null;
    if (outer.kind != .list or outer.encoded_length != value.len) return null;
    var items: [4]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return null;
    if (count != 4) return null;
    if (items[2].kind != .string or items[2].payload.len != 32) return null;
    if (items[3].kind != .string or items[3].payload.len != 32) return null;
    return .{
        .nonce = rlp_integer(items[0], u64) orelse return null,
        .balance = rlp_integer(items[1], u256) orelse return null,
        .storage_root = items[2].payload[0..32].*,
        .code_hash = items[3].payload[0..32].*,
    };
}

/// Decodes a storage-trie leaf value: `rlp(value)`, a non-zero canonical integer.
pub fn decode_storage(value: []const u8) ?u256 {
    const item = rlp.decode_item(value) catch return null;
    if (item.encoded_length != value.len) return null;
    const result = rlp_integer(item, u256) orelse return null;
    if (result == 0) return null;
    return result;
}

// Diff.

pub const Config = struct {
    state_nodes_max: u32,
    codes_max: u32,
    keys_max: u32,
    /// Leaves kept per witness by the trie walk.
    leaves_max: u32,
    /// Nodes decoded per witness by the trie walk. A storage trie shared by several
    /// accounts is walked once per account, so this may exceed `state_nodes_max`.
    walk_steps_max: u32,

    pub fn from_witness(config: Witness.Config) Config {
        assert(config.state_nodes_max > 0);
        return .{
            .state_nodes_max = config.state_nodes_max,
            .codes_max = config.codes_max,
            .keys_max = config.keys_max,
            .leaves_max = config.state_nodes_max,
            .walk_steps_max = config.state_nodes_max *| 4,
        };
    }
};

/// One item of a witness list: keccak256 of its bytes and its index in the list.
pub const Entry = struct { hash: Hash, index: u32 };

pub const SetDiff = struct {
    count_a: u32 = 0,
    count_b: u32 = 0,
    /// Distinct items in both.
    common: u32 = 0,
    /// Distinct items only in one witness, ascending by hash.
    only_a: []const Entry = &.{},
    only_b: []const Entry = &.{},

    pub fn differences(self: *const SetDiff) u32 {
        return @intCast(self.only_a.len + self.only_b.len);
    }
};

pub const LeafKind = enum(u8) { account, storage };

pub const Leaf = struct {
    kind: LeafKind,
    /// keccak256(address).
    account: Hash,
    /// keccak256(slot) for storage leaves; zero for account leaves.
    slot: Hash,
    value_length: u8,
    value_bytes: [sparse.value_bytes_max]u8,

    pub fn value(self: *const Leaf) []const u8 {
        assert(self.value_length > 0);
        return self.value_bytes[0..self.value_length];
    }

    fn order(a: *const Leaf, b: *const Leaf) std.math.Order {
        if (a.kind != b.kind) return std.math.order(@backingInt(a.kind), @backingInt(b.kind));
        const by_account = std.mem.order(u8, &a.account, &b.account);
        if (by_account != .eq) return by_account;
        return std.mem.order(u8, &a.slot, &b.slot);
    }

    fn less_than(_: void, a: Leaf, b: Leaf) bool {
        return order(&a, &b) == .lt;
    }
};

pub const WalkStats = struct {
    root: ?Hash = null,
    nodes_visited: u32 = 0,
    /// Hashed references whose preimage is not in the witness (normal at the edges).
    nodes_missing: u32 = 0,
    nodes_invalid: u32 = 0,
    leaves: u32 = 0,
    /// The walk stopped at `leaves_max`, `walk_steps_max`, or the stack bound.
    truncated: bool = false,
};

/// Indices into `Report.leaves[0]` and `Report.leaves[1]`.
pub const LeafPair = struct { a: u32, b: u32 };

pub const Report = struct {
    state: SetDiff = .{},
    codes: SetDiff = .{},
    keys: SetDiff = .{},
    address_preimages: u32 = 0,
    slot_preimages: u32 = 0,
    walk: [2]WalkStats = .{ .{}, .{} },
    /// Leaves of each walk, sorted by (kind, account, slot), without duplicates.
    leaves: [2][]const Leaf = .{ &.{}, &.{} },
    /// Same key, different value.
    differing: []const LeafPair = &.{},
    /// Keys only one walk reached.
    leaves_only: [2][]const u32 = .{ &.{}, &.{} },

    pub fn differences(self: *const Report) u64 {
        return @as(u64, self.state.differences()) + self.codes.differences() +
            self.keys.differences() + self.differing.len + self.leaves_only[0].len +
            self.leaves_only[1].len;
    }

    pub fn identical(self: *const Report) bool {
        return self.differences() == 0;
    }
};

pub const DiffError = error{DiffFull};

/// A key preimage by its keccak256: a 20-byte address or a 32-byte slot.
const Preimage = struct {
    hash: Hash,
    length: u8,
    key: [32]u8,

    fn less_than(_: void, a: Preimage, b: Preimage) bool {
        return std.mem.order(u8, &a.hash, &b.hash) == .lt;
    }
};

const Frame = struct {
    ref: RlpNode,
    path: Nibbles,
    kind: LeafKind,
    account: Hash,

    /// A child in the same trie as `parent`.
    fn child(parent: *const Frame, ref: RlpNode, path: *const Nibbles) Frame {
        assert(ref.len > 0);
        assert(path.len <= sparse.key_nibbles);
        return .{ .ref = ref, .path = path.*, .kind = parent.kind, .account = parent.account };
    }
};

/// The deepest DFS stack: per trie at most 15 pending siblings per level over 65 levels plus
/// one node's 16 children; the account trie's pending frames plus one storage trie's.
pub const stack_frames_max = 2 * (15 * 65 + 16) + 1;

comptime {
    assert(sparse.key_nibbles == 64);
    assert(sparse.value_bytes_max <= std.math.maxInt(u8));
}

fn entry_less_than(_: void, a: Entry, b: Entry) bool {
    return std.mem.order(u8, &a.hash, &b.hash) == .lt;
}

/// Binary search over items sorted by `hash`.
fn find(comptime T: type, items: []const T, hash: *const Hash) ?u32 {
    var low: usize = 0;
    var high: usize = items.len;
    // Halves the range each step.
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, &items[middle].hash, hash)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return @intCast(middle),
        }
    }
    assert(low == high);
    return null;
}

pub const Differ = struct {
    config: Config,
    arena: std.heap.ArenaAllocator,
    state_index: [2][]Entry,
    code_index: [2][]Entry,
    key_index: [2][]Entry,
    state_only: [2][]Entry,
    code_only: [2][]Entry,
    key_only: [2][]Entry,
    referenced: []bool,
    preimages: []Preimage,
    preimages_count: u32 = 0,
    leaves: [2][]Leaf,
    pairs: []LeafPair,
    leaves_only: [2][]u32,
    stack: []Frame,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Differ {
        assert(config.state_nodes_max > 0 and config.leaves_max > 0);
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var result: Differ = undefined;
        result.config = config;
        result.preimages_count = 0;
        for (0..2) |side| {
            result.state_index[side] = try lazy.alloc(a, Entry, config.state_nodes_max);
            result.code_index[side] = try lazy.alloc(a, Entry, config.codes_max);
            result.key_index[side] = try lazy.alloc(a, Entry, config.keys_max);
            result.state_only[side] = try lazy.alloc(a, Entry, config.state_nodes_max);
            result.code_only[side] = try lazy.alloc(a, Entry, config.codes_max);
            result.key_only[side] = try lazy.alloc(a, Entry, config.keys_max);
            result.leaves[side] = try lazy.alloc(a, Leaf, config.leaves_max);
            result.leaves_only[side] = try lazy.alloc(a, u32, config.leaves_max);
        }
        result.referenced = try lazy.alloc(a, bool, config.state_nodes_max);
        result.preimages = try lazy.alloc(a, Preimage, @as(usize, config.keys_max) * 2);
        result.pairs = try lazy.alloc(a, LeafPair, config.leaves_max);
        result.stack = try lazy.alloc(a, Frame, stack_frames_max);
        result.arena = arena;
        return result;
    }

    pub fn deinit(self: *Differ) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Compares witness `a` (local) with `b` (remote). The report borrows this `Differ`'s
    /// buffers and the witnesses, valid until the next `diff`.
    pub fn diff(self: *Differ, a: *const Witness, b: *const Witness) DiffError!Report {
        const witnesses = [2]*const Witness{ a, b };
        var report: Report = .{};
        var state_sorted: [2][]Entry = undefined;
        var code_sorted: [2][]Entry = undefined;
        var key_sorted: [2][]Entry = undefined;
        for (witnesses, 0..) |w, side| {
            state_sorted[side] = try index_list(&w.state, self.state_index[side]);
            code_sorted[side] = try index_list(&w.codes, self.code_index[side]);
            key_sorted[side] = try index_list(&w.keys, self.key_index[side]);
        }
        report.state = merge_sets(state_sorted, self.state_only);
        report.codes = merge_sets(code_sorted, self.code_only);
        report.keys = merge_sets(key_sorted, self.key_only);
        self.index_preimages(witnesses, &report);
        var leaf_counts: [2]u32 = undefined;
        for (witnesses, 0..) |w, side| {
            report.walk[side].root = self.find_root(w, state_sorted[side]);
            leaf_counts[side] = self.walk(w, state_sorted[side], side, &report.walk[side]);
            report.leaves[side] = self.leaves[side][0..leaf_counts[side]];
        }
        self.merge_leaves(&report);
        assert(report.differing.len <= @min(leaf_counts[0], leaf_counts[1]));
        return report;
    }

    /// The address whose keccak256 is `hash`, if a witness carried its preimage.
    pub fn address_of(self: *const Differ, hash: *const Hash) ?Address {
        const index = find(Preimage, self.preimages[0..self.preimages_count], hash) orelse
            return null;
        const preimage = &self.preimages[index];
        if (preimage.length != 20) return null;
        return preimage.key[0..20].*;
    }

    /// The storage slot whose keccak256 is `hash`, if a witness carried its preimage.
    pub fn slot_of(self: *const Differ, hash: *const Hash) ?Hash {
        const index = find(Preimage, self.preimages[0..self.preimages_count], hash) orelse
            return null;
        const preimage = &self.preimages[index];
        if (preimage.length != 32) return null;
        return preimage.key;
    }

    fn index_preimages(self: *Differ, witnesses: [2]*const Witness, report: *Report) void {
        var count: u32 = 0;
        for (witnesses) |w| {
            assert(w.keys.count <= self.config.keys_max);
            var index: u32 = 0;
            while (index < w.keys.count) : (index += 1) {
                const key = w.keys.get(index);
                if (key.len != 20 and key.len != 32) continue;
                var preimage: Preimage = .{
                    .hash = keccak256(key),
                    .length = @intCast(key.len),
                    .key = @splat(0),
                };
                @memcpy(preimage.key[0..key.len], key);
                self.preimages[count] = preimage;
                count += 1;
            }
        }
        const all = self.preimages[0..count];
        std.mem.sortUnstable(Preimage, all, {}, Preimage.less_than);
        var unique: u32 = 0;
        for (all) |preimage| {
            if (unique > 0 and std.mem.eql(u8, &all[unique - 1].hash, &preimage.hash)) continue;
            all[unique] = preimage;
            unique += 1;
            if (preimage.length == 20) report.address_preimages += 1;
            if (preimage.length == 32) report.slot_preimages += 1;
        }
        self.preimages_count = unique;
        assert(report.address_preimages + report.slot_preimages == unique);
    }

    fn lookup(w: *const Witness, sorted: []const Entry, hash: *const Hash) ?[]const u8 {
        const position = find(Entry, sorted, hash) orelse return null;
        const bytes = w.state.get(sorted[position].index);
        assert(std.mem.eql(u8, &keccak256(bytes), hash));
        return bytes;
    }

    /// The parent header's state root if its node is present, else the only decodable node
    /// that no node (child reference or account storage root) points to.
    fn find_root(self: *Differ, w: *const Witness, sorted: []const Entry) ?Hash {
        if (w.headers.count > 0) {
            const last = w.headers.get(w.headers.count - 1);
            if (witness_module.header_link(last)) |link| {
                if (lookup(w, sorted, &link.state_root) != null) return link.state_root;
            } else |_| {}
        }
        const referenced = self.referenced[0..sorted.len];
        @memset(referenced, false);
        for (sorted) |entry| self.mark_references(sorted, w.state.get(entry.index));
        var root: ?Hash = null;
        for (sorted, referenced, 0..) |entry, marked, position| {
            if (marked) continue;
            if (position > 0 and std.mem.eql(u8, &sorted[position - 1].hash, &entry.hash)) {
                continue; // A duplicate of the previous entry.
            }
            _ = sparse.decode_node(w.state.get(entry.index)) catch continue;
            if (root != null) return null; // Ambiguous.
            root = entry.hash;
        }
        return root;
    }

    fn mark_references(self: *Differ, sorted: []const Entry, bytes: []const u8) void {
        const decoded = sparse.decode_node(bytes) catch return;
        const referenced = self.referenced[0..sorted.len];
        if (decoded.kind == .leaf) {
            const account = decode_account(decoded.value) orelse return;
            mark_hash(sorted, referenced, &account.storage_root);
            return;
        }
        // Embedded children are under 32 bytes, too short to hold a hashed reference.
        for (&decoded.children) |*child| {
            if (child.len > 0 and child.is_hash()) {
                mark_hash(sorted, referenced, child.bytes[1..33]);
            }
        }
    }

    fn mark_hash(sorted: []const Entry, referenced: []bool, hash: *const Hash) void {
        assert(sorted.len == referenced.len);
        const position = find(Entry, sorted, hash) orelse return;
        // Duplicates sit next to each other; mark them all.
        var low = position;
        while (low > 0 and std.mem.eql(u8, &sorted[low - 1].hash, hash)) low -= 1;
        var index = low;
        while (index < sorted.len and std.mem.eql(u8, &sorted[index].hash, hash)) : (index += 1) {
            referenced[index] = true;
        }
    }

    /// Depth-first walk of the account trie and every reachable storage trie. Returns the
    /// number of distinct leaves, sorted.
    fn walk(
        self: *Differ,
        w: *const Witness,
        sorted: []const Entry,
        side: usize,
        stats: *WalkStats,
    ) u32 {
        const root = stats.root orelse return 0;
        var depth: u32 = 0;
        self.stack[0] = .{
            .ref = RlpNode.from_hash(root),
            .path = .{},
            .kind = .account,
            .account = @splat(0),
        };
        depth = 1;
        var count: u32 = 0;
        while (depth > 0) {
            if (stats.nodes_visited == self.config.walk_steps_max) {
                stats.truncated = true;
                break;
            }
            depth -= 1;
            const frame = self.stack[depth];
            const bytes = if (frame.ref.is_hash())
                lookup(w, sorted, frame.ref.bytes[1..33]) orelse {
                    stats.nodes_missing += 1;
                    continue;
                }
            else
                frame.ref.slice();
            stats.nodes_visited += 1;
            const decoded = sparse.decode_node(bytes) catch {
                stats.nodes_invalid += 1;
                continue;
            };
            const step = self.visit(&frame, &decoded, &depth, side, &count, stats);
            if (!step) {
                stats.truncated = true;
                break;
            }
        }
        const leaves = self.leaves[side][0..count];
        std.mem.sortUnstable(Leaf, leaves, {}, Leaf.less_than);
        var unique: u32 = 0;
        for (leaves) |leaf| {
            if (unique > 0 and Leaf.order(&leaves[unique - 1], &leaf) == .eq) continue;
            leaves[unique] = leaf;
            unique += 1;
        }
        stats.leaves = unique;
        assert(unique <= count);
        return unique;
    }

    /// Handles one decoded node. Returns false when a bound stops the walk.
    fn visit(
        self: *Differ,
        frame: *const Frame,
        decoded: *const sparse.Decoded,
        depth: *u32,
        side: usize,
        count: *u32,
        stats: *WalkStats,
    ) bool {
        const path_length = frame.path.len + decoded.path.len;
        if (path_length > sparse.key_nibbles) {
            stats.nodes_invalid += 1;
            return true;
        }
        var path = frame.path;
        path.append(decoded.path.slice());
        switch (decoded.kind) {
            .leaf => return self.visit_leaf(frame, &path, decoded.value, depth, side, count, stats),
            .extension => {
                if (path.len == sparse.key_nibbles) {
                    stats.nodes_invalid += 1;
                    return true;
                }
                return self.push(depth, frame.child(decoded.children[0], &path));
            },
            .branch => {
                if (path.len == sparse.key_nibbles) {
                    stats.nodes_invalid += 1;
                    return true;
                }
                var nibble: u8 = 16;
                while (nibble > 0) {
                    nibble -= 1;
                    const child = decoded.children[nibble];
                    if (child.len == 0) continue;
                    var child_path = path;
                    child_path.push(nibble);
                    if (!self.push(depth, frame.child(child, &child_path))) return false;
                }
                return true;
            },
        }
    }

    fn visit_leaf(
        self: *Differ,
        frame: *const Frame,
        path: *const Nibbles,
        value: []const u8,
        depth: *u32,
        side: usize,
        count: *u32,
        stats: *WalkStats,
    ) bool {
        assert(value.len > 0 and value.len <= sparse.value_bytes_max);
        if (path.len != sparse.key_nibbles) {
            stats.nodes_invalid += 1;
            return true;
        }
        if (count.* == self.config.leaves_max) return false;
        var key: Hash = undefined;
        _ = path.pack(&key);
        var leaf: Leaf = .{
            .kind = frame.kind,
            .account = if (frame.kind == .account) key else frame.account,
            .slot = if (frame.kind == .account) @splat(0) else key,
            .value_length = @intCast(value.len),
            .value_bytes = undefined,
        };
        @memcpy(leaf.value_bytes[0..value.len], value);
        self.leaves[side][count.*] = leaf;
        count.* += 1;
        if (frame.kind == .storage) return true;
        const account = decode_account(value) orelse return true;
        if (std.mem.eql(u8, &account.storage_root, &node.empty_root)) return true;
        return self.push(depth, .{
            .ref = RlpNode.from_hash(account.storage_root),
            .path = .{},
            .kind = .storage,
            .account = key,
        });
    }

    fn push(self: *Differ, depth: *u32, frame: Frame) bool {
        assert(depth.* <= self.stack.len);
        if (depth.* == self.stack.len) return false;
        self.stack[depth.*] = frame;
        depth.* += 1;
        return true;
    }

    fn merge_leaves(self: *Differ, report: *Report) void {
        const a = report.leaves[0];
        const b = report.leaves[1];
        var i: u32 = 0;
        var j: u32 = 0;
        var pairs: u32 = 0;
        var only: [2]u32 = .{ 0, 0 };
        // Each step advances i, j, or both.
        while (i < a.len or j < b.len) {
            const order: std.math.Order = if (i == a.len)
                .gt
            else if (j == b.len)
                .lt
            else
                Leaf.order(&a[i], &b[j]);
            switch (order) {
                .lt => {
                    self.leaves_only[0][only[0]] = i;
                    only[0] += 1;
                    i += 1;
                },
                .gt => {
                    self.leaves_only[1][only[1]] = j;
                    only[1] += 1;
                    j += 1;
                },
                .eq => {
                    if (!std.mem.eql(u8, a[i].value(), b[j].value())) {
                        self.pairs[pairs] = .{ .a = i, .b = j };
                        pairs += 1;
                    }
                    i += 1;
                    j += 1;
                },
            }
        }
        assert(pairs <= @min(a.len, b.len));
        report.differing = self.pairs[0..pairs];
        report.leaves_only = .{ self.leaves_only[0][0..only[0]], self.leaves_only[1][0..only[1]] };
    }
};

/// Hashes every item of `list` into `out` and sorts by hash.
fn index_list(list: *const ByteList, out: []Entry) DiffError![]Entry {
    if (list.count > out.len) return error.DiffFull;
    const entries = out[0..list.count];
    for (entries, 0..) |*entry, index| {
        entry.* = .{ .hash = keccak256(list.get(@intCast(index))), .index = @intCast(index) };
    }
    std.mem.sortUnstable(Entry, entries, {}, entry_less_than);
    return entries;
}

/// Index of the next entry with a different hash.
fn skip_equal(entries: []const Entry, index: usize) usize {
    assert(index < entries.len);
    var next = index + 1;
    while (next < entries.len and std.mem.eql(u8, &entries[next].hash, &entries[index].hash)) {
        next += 1;
    }
    return next;
}

/// Merge-joins two hash-sorted lists, counting distinct hashes.
fn merge_sets(sorted: [2][]Entry, only: [2][]Entry) SetDiff {
    const a = sorted[0];
    const b = sorted[1];
    var result: SetDiff = .{ .count_a = @intCast(a.len), .count_b = @intCast(b.len) };
    var i: usize = 0;
    var j: usize = 0;
    var count: [2]u32 = .{ 0, 0 };
    // Each step advances i, j, or both.
    while (i < a.len or j < b.len) {
        const order: std.math.Order = if (i == a.len)
            .gt
        else if (j == b.len)
            .lt
        else
            std.mem.order(u8, &a[i].hash, &b[j].hash);
        switch (order) {
            .lt => {
                only[0][count[0]] = a[i];
                count[0] += 1;
                i = skip_equal(a, i);
            },
            .gt => {
                only[1][count[1]] = b[j];
                count[1] += 1;
                j = skip_equal(b, j);
            },
            .eq => {
                result.common += 1;
                i = skip_equal(a, i);
                j = skip_equal(b, j);
            },
        }
    }
    result.only_a = only[0][0..count[0]];
    result.only_b = only[1][0..count[1]];
    assert(result.common + count[0] <= a.len and result.common + count[1] <= b.len);
    return result;
}

// Rendering.

const Writer = std.Io.Writer;

fn mark(equal: bool) []const u8 {
    return if (equal) " \u{2713}" else " DIFFERS";
}

fn write_account_name(w: *Writer, differ: *const Differ, hash: *const Hash) Writer.Error!void {
    if (differ.address_of(hash)) |address| {
        try w.print("0x{x}", .{&address});
    } else {
        try w.writeAll("(unknown)");
    }
    try w.print(" (hashed 0x{x})", .{hash});
}

fn write_slot_name(w: *Writer, differ: *const Differ, hash: *const Hash) Writer.Error!void {
    if (differ.slot_of(hash)) |slot| {
        try w.print("0x{x}", .{&slot});
    } else {
        try w.print("(unknown, hashed 0x{x})", .{hash});
    }
}

fn write_storage_value(w: *Writer, value: []const u8) Writer.Error!void {
    if (decode_storage(value)) |number| {
        try w.print("0x{x}", .{number});
    } else {
        try w.print("raw 0x{x}", .{value});
    }
}

/// Writes the report as text with the reference's sections. `a` is "local", `b` "remote".
pub fn render(
    w: *Writer,
    differ: *const Differ,
    report: *const Report,
    a: *const Witness,
    b: *const Witness,
) Writer.Error!void {
    assert(report.leaves[0].len <= differ.config.leaves_max);
    try render_overview(w, report, a, b);
    try render_differing(w, differ, report);
    try render_only(w, differ, report);
    try render_summary(w, report);
}

fn render_overview(
    w: *Writer,
    report: *const Report,
    a: *const Witness,
    b: *const Witness,
) Writer.Error!void {
    try w.writeAll("=== Overview ===\n");
    const labels = [2][]const u8{ "local: ", "remote:" };
    for ([2]*const Witness{ a, b }, labels) |witness, label| {
        try w.print("  {s} {d} state nodes, {d} codes, {d} keys, {d} headers\n", .{
            label,                 witness.state.count, witness.codes.count, witness.keys.count,
            witness.headers.count,
        });
    }
    const sets = [_]struct { []const u8, *const SetDiff }{
        .{ "state", &report.state }, .{ "codes", &report.codes }, .{ "keys", &report.keys },
    };
    for (sets) |set| {
        try w.print("  {s}: {d} common, {d} only-local, {d} only-remote\n", .{
            set[0], set[1].common, set[1].only_a.len, set[1].only_b.len,
        });
    }
    try w.print("  address preimages available: {d}\n", .{report.address_preimages});
    try w.print("  slot preimages available: {d}\n", .{report.slot_preimages});
    for (report.codes.only_a) |entry| {
        const length = a.codes.get(entry.index).len;
        try w.print("  code only-local:  0x{x} ({d} bytes)\n", .{ &entry.hash, length });
    }
    for (report.codes.only_b) |entry| {
        const length = b.codes.get(entry.index).len;
        try w.print("  code only-remote: 0x{x} ({d} bytes)\n", .{ &entry.hash, length });
    }
    for (report.keys.only_a) |entry| {
        try w.print("  key only-local:  0x{x}\n", .{a.keys.get(entry.index)});
    }
    for (report.keys.only_b) |entry| {
        try w.print("  key only-remote: 0x{x}\n", .{b.keys.get(entry.index)});
    }
    const sides = [2][]const u8{ "local", "remote" };
    for (report.walk, sides) |stats, side| {
        if (stats.root) |root| {
            try w.print("  {s} pre-state root: 0x{x}\n", .{ side, &root });
        } else {
            try w.print("  {s} pre-state root: (unknown, leaf walk skipped)\n", .{side});
        }
        const truncated = if (stats.truncated) ", truncated" else "";
        try w.print("  {s} walk: {d} nodes, {d} leaves, {d} missing, {d} invalid{s}\n", .{
            side,      stats.nodes_visited, stats.leaves, stats.nodes_missing, stats.nodes_invalid,
            truncated,
        });
    }
}

fn render_account_pair(
    w: *Writer,
    differ: *const Differ,
    leaf: *const Leaf,
    local: *const Account,
    remote: *const Account,
) Writer.Error!void {
    try w.writeAll("  ACCOUNT ");
    try write_account_name(w, differ, &leaf.account);
    try w.writeAll("\n");
    try w.print("    Nonce:            {d} (local) vs {d} (remote){s}\n", .{
        local.nonce, remote.nonce, mark(local.nonce == remote.nonce),
    });
    try w.print("    Balance:          {d} (local) vs {d} (remote){s}\n", .{
        local.balance, remote.balance, mark(local.balance == remote.balance),
    });
    try w.print("    Code hash:        0x{x} (local)\n", .{&local.code_hash});
    try w.print("                      0x{x} (remote){s}\n", .{
        &remote.code_hash, mark(std.mem.eql(u8, &local.code_hash, &remote.code_hash)),
    });
    try w.print("    Storage root:     0x{x} (local)\n", .{&local.storage_root});
    try w.print("                      0x{x} (remote){s}\n\n", .{
        &remote.storage_root, mark(std.mem.eql(u8, &local.storage_root, &remote.storage_root)),
    });
}

fn render_storage_pair(
    w: *Writer,
    differ: *const Differ,
    a: *const Leaf,
    b: *const Leaf,
) Writer.Error!void {
    assert(Leaf.order(a, b) == .eq);
    try w.writeAll(if (a.kind == .storage) "  STORAGE account " else "  ACCOUNT (undecodable) ");
    try write_account_name(w, differ, &a.account);
    if (a.kind == .storage) {
        try w.writeAll(" slot ");
        try write_slot_name(w, differ, &a.slot);
    }
    try w.writeAll(": ");
    try write_storage_value(w, a.value());
    try w.writeAll(" (local) vs ");
    try write_storage_value(w, b.value());
    try w.writeAll(" (remote)\n");
}

fn render_differing(w: *Writer, differ: *const Differ, report: *const Report) Writer.Error!void {
    try w.writeAll("\n=== Differing Leaf Nodes ===\n");
    if (report.differing.len == 0) {
        try w.writeAll("  No leaf nodes share the same path with different values.\n");
        return;
    }
    var accounts: u32 = 0;
    for (report.differing) |pair| {
        const a = &report.leaves[0][pair.a];
        const b = &report.leaves[1][pair.b];
        if (a.kind == .account and decode_account(a.value()) != null and
            decode_account(b.value()) != null) accounts += 1;
    }
    if (accounts == 0) {
        try w.writeAll("  No account leaves differ (all diffs are storage leaves).\n");
    } else {
        try w.print("  {d} account(s) with different state:\n\n", .{accounts});
    }
    for (report.differing) |pair| {
        const a = &report.leaves[0][pair.a];
        const b = &report.leaves[1][pair.b];
        if (a.kind != .account) continue;
        const local = decode_account(a.value()) orelse continue;
        const remote = decode_account(b.value()) orelse continue;
        try render_account_pair(w, differ, a, &local, &remote);
    }
    const storage = report.differing.len - accounts;
    try w.print("  {d} storage leaf(s) also differ (values computed differently).\n", .{storage});
    for (report.differing) |pair| {
        const a = &report.leaves[0][pair.a];
        const b = &report.leaves[1][pair.b];
        if (a.kind == .account and decode_account(a.value()) != null and
            decode_account(b.value()) != null) continue;
        try render_storage_pair(w, differ, a, b);
    }
}

fn render_only_leaf(
    w: *Writer,
    differ: *const Differ,
    leaf: *const Leaf,
    label: []const u8,
) Writer.Error!void {
    if (leaf.kind == .account) {
        if (decode_account(leaf.value())) |account| {
            try w.print("    {s} account ", .{label});
            try write_account_name(w, differ, &leaf.account);
            try w.print(": nonce={d}, balance={d}, storage_root=0x{x}\n", .{
                account.nonce, account.balance, &account.storage_root,
            });
            return;
        }
    }
    try w.print("    {s} {s} ", .{ label, if (leaf.kind == .account) "account" else "storage" });
    try write_account_name(w, differ, &leaf.account);
    if (leaf.kind == .storage) {
        try w.writeAll(" slot ");
        try write_slot_name(w, differ, &leaf.slot);
    }
    try w.writeAll(": ");
    try write_storage_value(w, leaf.value());
    try w.writeAll("\n");
}

fn render_only(w: *Writer, differ: *const Differ, report: *const Report) Writer.Error!void {
    if (report.leaves_only[0].len == 0 and report.leaves_only[1].len == 0) return;
    try w.writeAll("\n=== Leaves Only in One Witness ===\n");
    try w.print("  {d} leaves only in local, {d} leaves only in remote\n", .{
        report.leaves_only[0].len, report.leaves_only[1].len,
    });
    const labels = [2][]const u8{ "LOCAL-ONLY ", "REMOTE-ONLY" };
    for (report.leaves_only, report.leaves, labels) |only, leaves, label| {
        for (only) |index| try render_only_leaf(w, differ, &leaves[index], label);
    }
}

fn render_summary(w: *Writer, report: *const Report) Writer.Error!void {
    try w.writeAll("\n=== SUMMARY ===\n");
    try w.print("State node diffs:     {d}\n", .{report.state.differences()});
    try w.print("Code diffs:           {d}\n", .{report.codes.differences()});
    try w.print("Key diffs:            {d}\n", .{report.keys.differences()});
    try w.print("Differing leaf pairs: {d}\n", .{report.differing.len});
    try w.print("Leaves only-local:    {d}\n", .{report.leaves_only[0].len});
    try w.print("Leaves only-remote:   {d}\n", .{report.leaves_only[1].len});
    if (report.identical()) try w.writeAll("\nWitnesses are identical.\n");
}

test {
    _ = @import("witness_diff_test.zig");
}

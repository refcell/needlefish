//! Builds a replay archive from raw JSON-RPC results saved on disk (`base replay import`).
//!
//! Input, one directory per block plus a header list (the exact JSON-RPC `result`s):
//!
//!     headers.json              [{number, hash, parentHash, stateRoot, ...}] ancestors+window
//!     <n>/block.json            eth_getBlockByNumber(n, true)
//!     <n>/receipts.json         eth_getBlockReceipts(n)
//!     <n>/prestate.json         debug_traceBlockByNumber(n, prestateTracer)
//!     <n>/prestate_diff.json    debug_traceBlockByNumber(n, prestateTracer diffMode)
//!     <n>/proofs_pre.json       [eth_getProof(account, slots, n - 1)] per touched account
//!     <n>/proofs_post.json      [eth_getProof(account, slots, n)] same keys
//!
//! Every byte that reaches the replay is bound to the chain: the header is re-encoded and must
//! hash to the block hash, the transactions must hash to `transactionsRoot`, and every proof
//! must verify against the parent's (or the block's) state root. The canonical results the
//! replay compares against (receipts, post-state of changed accounts and slots) are taken
//! from the receipts and post proofs. This file does no IO: callers pass file contents.

const std = @import("std");
const assert = std.debug.assert;

const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const header_json = @import("../../consensus/sources/header_json.zig");
const transaction_json = @import("../../consensus/sources/transaction_json.zig");
const object = @import("../../consensus/sources/json_object.zig");
const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");
const archive_module = @import("archive.zig");

const Archive = archive_module.Archive;
const Hash = [32]u8;
const Address = [20]u8;
const Value = std.json.Value;
const keccak256 = trie.node.keccak256;
const empty_root = trie.node.empty_root;
const empty_code_hash = trie.node.empty_code_hash;

pub const Error = error{
    OutOfMemory,
    WitnessFull,
    /// Malformed JSON or a field of the wrong shape.
    Malformed,
    /// A response contradicts the block hash, a root, or a proof.
    Inconsistent,
    /// The block holds a transaction type the JSON decoder does not rebuild.
    Unsupported,
};

/// Fills `archive.ancestors` and `parent_state_root` from `headers.json` for a replay whose
/// first block is `first`: the up-to-256 hashes just below it, hash-linked.
pub fn add_ancestors(
    arena: std.mem.Allocator,
    archive: *Archive,
    raw: []const u8,
    first: u64,
) Error!void {
    assert(archive.ancestors_len == 0);
    assert(first > 0);
    const list = try parse(arena, raw);
    if (list != .array) return error.Malformed;
    const lowest = first -| archive_module.ancestors_max;
    var expected_number = lowest;
    var previous_hash: ?Hash = null;
    for (list.array.items) |entry| {
        const number = try quantity(u64, try field(entry, "number"));
        if (number < lowest or number >= first) continue;
        if (number != expected_number) return error.Inconsistent;
        const hash = try fixed(32, try field(entry, "hash"));
        const parent = try fixed(32, try field(entry, "parentHash"));
        if (previous_hash) |previous| {
            if (!std.mem.eql(u8, &previous, &parent)) return error.Inconsistent;
        }
        try archive.add_ancestor(hash);
        previous_hash = hash;
        expected_number += 1;
        if (number == first - 1) {
            archive.parent_state_root = try fixed(32, try field(entry, "stateRoot"));
        }
    }
    if (expected_number != first) return error.Inconsistent;
    assert(archive.ancestors_len == first - lowest);
}

/// The raw JSON of one block's files.
pub const BlockFiles = struct {
    block: []const u8,
    receipts: []const u8,
    prestate: []const u8,
    prestate_diff: []const u8,
    proofs_pre: []const u8,
    proofs_post: []const u8,
    /// Optional `eth_getProof` results at the parent for keys no trace shows (the pre-block
    /// system calls' contracts, collapse siblings): nodes only.
    proofs_extra: ?[]const u8 = null,
    /// Optional codes (a JSON list of hex strings) for those accounts (`eth_getCode`).
    codes_extra: ?[]const u8 = null,
};

/// Deduplicates witness nodes and codes across blocks (the archive witness is a plain list).
pub const Seen = struct {
    hashes: std.AutoHashMapUnmanaged(Hash, void) = .empty,
    /// Hashes some witness node references as a child (what a replay may resolve).
    wanted: std.AutoHashMapUnmanaged(Hash, void) = .empty,
    /// Collapse siblings derived and opaque branches recorded (summary).
    derived: u32 = 0,
    opaque_branches: u32 = 0,

    pub fn deinit(seen: *Seen, allocator: std.mem.Allocator) void {
        seen.hashes.deinit(allocator);
        seen.wanted.deinit(allocator);
    }

    /// Whether `hash` is referenced by a witness node but no node with that hash is known.
    fn missing(seen: *const Seen, hash: *const Hash) bool {
        return seen.wanted.contains(hash.*) and !seen.hashes.contains(hash.*);
    }

    fn want_children(seen: *Seen, allocator: std.mem.Allocator, node: []const u8) Error!void {
        const decoded = trie.sparse.decode_node(node) catch return error.Inconsistent;
        for (&decoded.children) |*child| {
            if (child.len == 0 or !child.is_hash()) continue;
            try seen.wanted.put(allocator, child.bytes[1..33].*, {});
        }
    }

    fn first(seen: *Seen, allocator: std.mem.Allocator, bytes: []const u8) Error!bool {
        const entry = try seen.hashes.getOrPut(allocator, keccak256(bytes));
        return !entry.found_existing;
    }
};

/// Appends one block. `pre_state_root` is the parent's state root (the previous block's
/// header, or `archive.parent_state_root` for the first). Returns the block's state root.
pub fn add_block(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    files: BlockFiles,
    pre_state_root: Hash,
) Error!Hash {
    var extra: [header_json.extra_data_size_max]u8 = undefined;
    const decoded = header_json.decode(files.block, &extra) catch return error.Inconsistent;
    const header = decoded.header;
    const header_rlp = try arena.alloc(u8, rlp.length(header));
    _ = rlp.encode_to(header_rlp, header);
    assert(std.mem.eql(u8, &keccak256(header_rlp), &decoded.hash.bytes));
    try archive.witness.headers.append(header_rlp);
    try archive.begin_block();
    const transactions_root = header.transactions_root.bytes;
    const transactions = try decode_transactions(arena, files.block, transactions_root);
    try add_receipts(arena, archive, transactions, files.receipts);
    try add_codes(allocator, arena, archive, seen, files.prestate);
    try add_proof_nodes(allocator, arena, archive, seen, files.proofs_pre, pre_state_root);
    if (files.codes_extra) |codes| try add_code_list(allocator, arena, archive, seen, codes);
    if (files.proofs_extra) |extra_proofs| {
        try add_proof_nodes(allocator, arena, archive, seen, extra_proofs, pre_state_root);
    }
    const post_root = header.state_root.bytes;
    const posts = try parse(arena, files.proofs_post);
    try check_proofs(arena, posts, post_root);
    try derive_siblings(allocator, arena, archive, seen, posts);
    try add_changes(arena, archive, files.prestate_diff, posts);
    return post_root;
}

fn decode_transactions(
    arena: std.mem.Allocator,
    raw: []const u8,
    root: Hash,
) Error![]const []const u8 {
    const list = (header_json.transactions_raw(raw) catch return error.Malformed) orelse
        return error.Malformed;
    const options: transaction_json.Options = .{ .verify_root = false, .recover_senders = false };
    const count = object.array_count(list, options.limits.transactions_max) catch
        return error.Malformed;
    const items = try arena.alloc([]const u8, count);
    var iterator = object.ArrayIterator.init(list) catch return error.Malformed;
    for (items) |*item| {
        const element = (iterator.next() catch return error.Malformed) orelse unreachable;
        if (element.value.tag != .object_begin) return error.Malformed; // Hashes only.
        const tx = transaction_json.decode(arena, arena, element.raw, options) catch |err| {
            return if (err == error.OutOfMemory) error.OutOfMemory else error.Inconsistent;
        };
        const envelope = tx.envelope orelse return error.Unsupported;
        const bytes = try arena.alloc(u8, envelope.encoded_length());
        item.* = envelope.encode_to(bytes);
    }
    if (!std.mem.eql(u8, &trie.ordered_trie_root(items), &root)) return error.Inconsistent;
    return items;
}

fn add_receipts(
    arena: std.mem.Allocator,
    archive: *Archive,
    transactions: []const []const u8,
    raw: []const u8,
) Error!void {
    const list = try parse(arena, raw);
    if (list != .array or list.array.items.len != transactions.len) return error.Inconsistent;
    for (list.array.items, transactions, 0..) |entry, transaction, index| {
        const position = try quantity(u64, try field(entry, "transactionIndex"));
        if (position != index) return error.Inconsistent;
        const logs = try field(entry, "logs");
        if (logs != .array) return error.Malformed;
        try archive.add_transaction(transaction, .{
            .status = try quantity(u64, try field(entry, "status")) == 1,
            .cumulative_gas_used = try quantity(u64, try field(entry, "cumulativeGasUsed")),
            .log_count = @intCast(logs.array.items.len),
        });
    }
}

/// Every pre-state code the block runs (prestateTracer): bound by the code hashes the
/// verified account proofs commit to, which the replay checks on use.
fn add_codes(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    raw: []const u8,
) Error!void {
    const traces = try parse(arena, raw);
    if (traces != .array) return error.Malformed;
    for (traces.array.items) |trace| {
        const result = try field(trace, "result");
        if (result != .object) return error.Malformed;
        for (result.object.values()) |account| {
            const code_value = (if (account == .object) account.object.get("code") else null) orelse
                continue;
            const code = try data(arena, code_value);
            if (code.len == 0 or !try seen.first(allocator, code)) continue;
            try archive.witness.codes.append(code);
        }
    }
}

fn add_code_list(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    raw: []const u8,
) Error!void {
    const list = try parse(arena, raw);
    if (list != .array) return error.Malformed;
    for (list.array.items) |item| {
        const code = try data(arena, item);
        if (code.len == 0 or !try seen.first(allocator, code)) continue;
        try archive.witness.codes.append(code);
    }
}

/// Adds every node of every account and storage proof, after verifying each proof against
/// `state_root` (and each storage proof against its account's storage root).
fn add_proof_nodes(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    raw: []const u8,
    state_root: Hash,
) Error!void {
    const proofs = try parse(arena, raw);
    try check_proofs(arena, proofs, state_root);
    for (proofs.array.items) |proof| {
        try add_nodes(allocator, arena, archive, seen, try field(proof, "accountProof"));
        const storage = try field(proof, "storageProof");
        for (storage.array.items) |entry| {
            try add_nodes(allocator, arena, archive, seen, try field(entry, "proof"));
        }
    }
}

fn add_nodes(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    nodes: Value,
) Error!void {
    if (nodes != .array) return error.Malformed;
    for (nodes.array.items) |node_value| {
        const node = try data(arena, node_value);
        if (!try seen.first(allocator, node)) continue;
        try seen.want_children(allocator, node);
        try archive.witness.state.append(node);
    }
}

/// Recovers the siblings that deleted keys' branches collapse into, which no pre-state proof
/// contains (a proof only holds the nodes on its own key's path, and a sibling is a child
/// hash). After a collapse the sibling is merged into a node on the deleted key's post-state
/// path: a leaf or extension whose path is the collapsed nibbles followed by the sibling's
/// path. So every suffix of a post-state leaf or extension path is a candidate sibling; a
/// candidate whose hash a witness node references but no proof supplies is the sibling. When
/// the sibling is a branch, the post-state node is an extension pointing at its hash; its
/// preimage is unknowable here, so it is recorded as opaque (`Archive.opaque_branches`).
/// State-trie leaf values are accounts (at most 110 bytes) or slots (at most 33).
const candidate_value_bytes_max = 512;
const candidate_bytes_max = candidate_value_bytes_max + 64;

fn derive_siblings(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    posts: Value,
) Error!void {
    for (posts.array.items) |proof| {
        try derive_from_nodes(allocator, arena, archive, seen, try field(proof, "accountProof"));
        const storage = try field(proof, "storageProof");
        for (storage.array.items) |entry| {
            try derive_from_nodes(allocator, arena, archive, seen, try field(entry, "proof"));
        }
    }
}

fn derive_from_nodes(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    archive: *Archive,
    seen: *Seen,
    nodes: Value,
) Error!void {
    if (nodes != .array) return error.Malformed;
    for (nodes.array.items) |node_value| {
        const node = try data(arena, node_value);
        const decoded = trie.sparse.decode_node(node) catch return error.Inconsistent;
        if (decoded.kind == .branch) continue;
        const path = decoded.path.slice();
        var start: usize = 1;
        while (start <= path.len) : (start += 1) {
            if (start == path.len and decoded.kind == .leaf) break;
            if (start == path.len) {
                const child = &decoded.children[0];
                if (!child.is_hash()) break;
                const hash = child.bytes[1..33].*;
                if (seen.missing(&hash)) {
                    try archive.add_opaque(hash);
                    seen.opaque_branches += 1;
                }
                break;
            }
            if (decoded.value.len > candidate_value_bytes_max) break;
            var buffer: [candidate_bytes_max]u8 = undefined;
            var sink: trie.node.BufferSink = .{ .buffer = &buffer };
            switch (decoded.kind) {
                .leaf => trie.node.encode_leaf(&sink, path[start..], decoded.value),
                .extension => {
                    trie.node.encode_extension(&sink, path[start..], &decoded.children[0]);
                },
                .branch => unreachable,
            }
            const candidate = sink.result();
            if (candidate.len < 32) continue; // Embedded in its parent, never a hash child.
            if (!seen.missing(&keccak256(candidate))) continue;
            const copy = try arena.dupe(u8, candidate);
            assert(try seen.first(allocator, copy));
            try seen.want_children(allocator, copy);
            try archive.witness.state.append(copy);
            seen.derived += 1;
        }
    }
}

/// Verifies every account proof (and its storage proofs) of an `eth_getProof` list.
fn check_proofs(arena: std.mem.Allocator, proofs: Value, state_root: Hash) Error!void {
    if (proofs != .array) return error.Malformed;
    for (proofs.array.items) |proof| {
        const address = try fixed(20, try field(proof, "address"));
        const account = try proven_account(proof);
        const nodes = try node_list(arena, try field(proof, "accountProof"));
        const value = trie.proof.verify(state_root, &keccak256(&address), nodes) catch
            return error.Inconsistent;
        try check_account_leaf(value, account);
        const storage = try field(proof, "storageProof");
        if (storage != .array) return error.Malformed;
        for (storage.array.items) |entry| {
            const key = try fixed(32, try field(entry, "key"));
            const slot_value = try quantity(u256, try field(entry, "value"));
            const slot_nodes = try node_list(arena, try field(entry, "proof"));
            const leaf = trie.proof.verify(account.storage_root, &keccak256(&key), slot_nodes) catch
                return error.Inconsistent;
            try check_slot_leaf(leaf, slot_value);
        }
    }
}

const Proven = struct {
    info: db.AccountInfo,
    storage_root: Hash,
    exists: bool,
};

fn proven_account(proof: Value) Error!Proven {
    const info: db.AccountInfo = .{
        .nonce = try quantity(u64, try field(proof, "nonce")),
        .balance = try quantity(u256, try field(proof, "balance")),
        .code_hash = try fixed(32, try field(proof, "codeHash")),
    };
    const storage_root = try fixed(32, try field(proof, "storageHash"));
    const zero: Hash = @splat(0);
    // Geth reports a missing account with a zero (or empty) code hash and empty storage.
    const missing = info.nonce == 0 and info.balance == 0 and
        (std.mem.eql(u8, &info.code_hash, &zero) or
            std.mem.eql(u8, &info.code_hash, &empty_code_hash)) and
        (std.mem.eql(u8, &storage_root, &empty_root) or std.mem.eql(u8, &storage_root, &zero));
    var normalized = info;
    if (std.mem.eql(u8, &info.code_hash, &zero)) normalized.code_hash = empty_code_hash;
    return .{
        .info = normalized,
        .storage_root = if (missing) empty_root else storage_root,
        .exists = !missing,
    };
}

fn check_account_leaf(leaf: ?[]const u8, account: Proven) Error!void {
    const bytes = leaf orelse {
        if (account.exists) return error.Inconsistent;
        return;
    };
    if (!account.exists) return error.Inconsistent;
    const decoded = db.witness_diff.decode_account(bytes) orelse return error.Inconsistent;
    if (decoded.nonce != account.info.nonce or decoded.balance != account.info.balance) {
        return error.Inconsistent;
    }
    if (!std.mem.eql(u8, &decoded.code_hash, &account.info.code_hash)) return error.Inconsistent;
    if (!std.mem.eql(u8, &decoded.storage_root, &account.storage_root)) return error.Inconsistent;
}

fn check_slot_leaf(leaf: ?[]const u8, value: u256) Error!void {
    const bytes = leaf orelse {
        if (value != 0) return error.Inconsistent;
        return;
    };
    const decoded = db.witness_diff.decode_storage(bytes) orelse return error.Inconsistent;
    if (decoded != value) return error.Inconsistent;
}

/// The canonical post-state of every account and slot the block changed: the keys come from
/// the diff trace, the values from the verified post proofs.
fn add_changes(
    arena: std.mem.Allocator,
    archive: *Archive,
    raw_diff: []const u8,
    posts: Value,
) Error!void {
    var changed: std.AutoArrayHashMapUnmanaged(Address, std.AutoArrayHashMapUnmanaged(u256, void)) =
        .empty;
    const traces = try parse(arena, raw_diff);
    if (traces != .array) return error.Malformed;
    for (traces.array.items) |trace| {
        const result = try field(trace, "result");
        for ([_][]const u8{ "pre", "post" }) |side| {
            if (result != .object) return error.Malformed;
            const accounts = result.object.get(side) orelse continue;
            if (accounts != .object) return error.Malformed;
            for (accounts.object.keys(), accounts.object.values()) |key, account| {
                const address = try hex_fixed(20, key);
                const slots = try changed.getOrPut(arena, address);
                if (!slots.found_existing) slots.value_ptr.* = .empty;
                if (account != .object) return error.Malformed;
                const storage = account.object.get("storage") orelse continue;
                if (storage != .object) return error.Malformed;
                for (storage.object.keys()) |slot_key| {
                    try slots.value_ptr.put(arena, try hex_quantity_key(slot_key), {});
                }
            }
        }
    }
    try emit_changes(archive, &changed, posts);
}

fn emit_changes(
    archive: *Archive,
    changed: *std.AutoArrayHashMapUnmanaged(Address, std.AutoArrayHashMapUnmanaged(u256, void)),
    posts: Value,
) Error!void {
    const Sort = struct {
        keys: []const Address,
        pub fn lessThan(context: @This(), a: usize, b: usize) bool {
            return std.mem.order(u8, &context.keys[a], &context.keys[b]) == .lt;
        }
    };
    changed.sort(Sort{ .keys = changed.keys() });
    for (changed.keys(), changed.values()) |address, *slots| {
        const proof = try find_proof(posts, address);
        const account = try proven_account(proof);
        try archive.add_account(.{
            .address = address,
            .info = if (account.exists) account.info else null,
        });
        const SlotSort = struct {
            keys: []const u256,
            pub fn lessThan(context: @This(), a: usize, b: usize) bool {
                return context.keys[a] < context.keys[b];
            }
        };
        slots.sort(SlotSort{ .keys = slots.keys() });
        for (slots.keys()) |slot| {
            const value = try find_slot(proof, slot);
            try archive.add_slot(.{ .address = address, .slot = slot, .value = value });
        }
    }
}

fn find_proof(posts: Value, address: Address) Error!Value {
    for (posts.array.items) |proof| {
        const candidate = try fixed(20, try field(proof, "address"));
        if (std.mem.eql(u8, &candidate, &address)) return proof;
    }
    return error.Inconsistent; // The post proofs must cover every changed account.
}

fn find_slot(proof: Value, slot: u256) Error!u256 {
    const storage = try field(proof, "storageProof");
    for (storage.array.items) |entry| {
        const key = try fixed(32, try field(entry, "key"));
        if (std.mem.readInt(u256, &key, .big) != slot) continue;
        return quantity(u256, try field(entry, "value"));
    }
    return error.Inconsistent;
}

fn node_list(arena: std.mem.Allocator, nodes: Value) Error![]const []const u8 {
    if (nodes != .array) return error.Malformed;
    const list = try arena.alloc([]const u8, nodes.array.items.len);
    for (list, nodes.array.items) |*node, item| node.* = try data(arena, item);
    return list;
}

fn parse(arena: std.mem.Allocator, raw: []const u8) Error!Value {
    return std.json.parseFromSliceLeaky(Value, arena, raw, .{}) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Malformed,
    };
}

fn field(value: Value, name: []const u8) Error!Value {
    if (value != .object) return error.Malformed;
    return value.object.get(name) orelse error.Malformed;
}

fn quantity(comptime T: type, value: Value) Error!T {
    if (value != .string) return error.Malformed;
    const text = value.string;
    if (text.len < 3 or text[0] != '0' or text[1] != 'x') return error.Malformed;
    return std.fmt.parseInt(T, text[2..], 16) catch error.Malformed;
}

fn fixed(comptime size: usize, value: Value) Error![size]u8 {
    if (value != .string) return error.Malformed;
    return hex_fixed(size, value.string);
}

fn hex_fixed(comptime size: usize, text: []const u8) Error![size]u8 {
    if (text.len != 2 + 2 * size or text[0] != '0' or text[1] != 'x') return error.Malformed;
    var out: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text[2..]) catch return error.Malformed;
    return out;
}

/// A storage key as the tracer prints it (`0x` + 64 hex digits).
fn hex_quantity_key(text: []const u8) Error!u256 {
    const bytes = try hex_fixed(32, text);
    return std.mem.readInt(u256, &bytes, .big);
}

fn data(arena: std.mem.Allocator, value: Value) Error![]u8 {
    if (value != .string) return error.Malformed;
    const text = value.string;
    if (text.len < 2 or text.len % 2 != 0) return error.Malformed;
    if (text[0] != '0' or text[1] != 'x') return error.Malformed;
    const out = try arena.alloc(u8, (text.len - 2) / 2);
    _ = std.fmt.hexToBytes(out, text[2..]) catch return error.Malformed;
    return out;
}

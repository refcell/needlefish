//! Trie-only root check against real blocks, independent of the EVM.
//!
//! A block's state diff is read from `eth_getProof` results at its parent and at the block
//! itself, for every account and slot the block touched. The parent proofs seed a
//! `SparseState` (the stateless verifier's state), the post values become a `Changeset`,
//! and `SparseState.apply` must then reproduce the block's state root and every account's
//! storage root. A parent proof set may lack a node the update needs (the sibling a branch
//! collapses into when a slot or account is deleted): that is `incomplete`, retried with the
//! post proofs' nodes added. Receipts and transactions roots are rebuilt from the RPC JSON
//! with the consensus encoders and the ordered trie.
//!
//! Pure: callers pass file contents; all IO lives in `bin/replay-roots`.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rpc_types = @import("../../common/rpc_types/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const witness = @import("witness.zig");
const history = @import("history.zig");
const changeset_module = @import("changeset.zig");

const node = trie.node;
const request = rpc_types.request;
const Value = std.json.Value;
const Allocator = std.mem.Allocator;
const Changeset = changeset_module.Changeset;
const AccountInfo = changeset_module.AccountInfo;
const SparseState = witness.SparseState;

pub const Address = [20]u8;
pub const Hash = [32]u8;

/// Upper bounds for one block's inputs.
pub const accounts_max = 1 << 14;
pub const slots_max = 1 << 16;
pub const proof_nodes_max = 2 * trie.sparse.key_nibbles + 2;
pub const items_max = 1 << 16;

pub const ParseError = request.ParseError || error{ TooMany, InvalidProofJson };

pub const SlotProof = struct {
    slot: u256,
    value: u256,
    proof: []const []const u8,
};

pub const AccountProof = struct {
    address: Address,
    nonce: u64,
    balance: u256,
    code_hash: Hash,
    storage_hash: Hash,
    proof: []const []const u8,
    slots: []const SlotProof,
    /// Whether the account proof proves a leaf (set by `verify_proofs`).
    exists: bool = false,

    fn info(account: *const AccountProof) ?AccountInfo {
        if (!account.exists) return null;
        return .{
            .nonce = account.nonce,
            .balance = account.balance,
            .code_hash = account.code_hash,
        };
    }
};

/// The roots of a block (`eth_getBlockByNumber` with full transactions).
pub const Block = struct {
    number: u64,
    parent_hash: Hash,
    state_root: Hash,
    receipts_root: Hash,
    transactions_root: Hash,
    transactions: []const Value,
};

fn array_of(value: Value) ParseError![]const Value {
    if (value != .array) return error.InvalidField;
    if (value.array.items.len > items_max) return error.TooMany;
    return value.array.items;
}

fn object_of(value: Value) ParseError!std.json.ObjectMap {
    if (value != .object) return error.NotAnObject;
    return value.object;
}

fn hash_field(object: std.json.ObjectMap, name: []const u8) ParseError!Hash {
    return (try request.hash_of(try request.required(object, name))).bytes;
}

fn quantity_field(comptime T: type, object: std.json.ObjectMap, name: []const u8) ParseError!T {
    return request.quantity(T, try request.required(object, name));
}

fn nodes_of(arena: Allocator, value: Value) ParseError![]const []const u8 {
    const items = try array_of(value);
    if (items.len > proof_nodes_max) return error.TooMany;
    const out = try arena.alloc([]const u8, items.len);
    for (items, out) |item, *bytes| bytes.* = try request.data_of(arena, item);
    return out;
}

fn slots_of(arena: Allocator, value: Value) ParseError![]const SlotProof {
    const items = try array_of(value);
    const out = try arena.alloc(SlotProof, items.len);
    for (items, out) |item, *slot| {
        const object = try object_of(item);
        slot.* = .{
            // A DATA key (32 bytes, leading zeros kept), not a QUANTITY.
            .slot = std.mem.readInt(u256, &try hash_field(object, "key"), .big),
            .value = try quantity_field(u256, object, "value"),
            .proof = try nodes_of(arena, try request.required(object, "proof")),
        };
    }
    return out;
}

/// Parses an `eth_getProof` result list. Slices point into `arena`.
pub fn parse_proofs(arena: Allocator, root: Value) ParseError![]AccountProof {
    const items = try array_of(root);
    if (items.len > accounts_max) return error.TooMany;
    const out = try arena.alloc(AccountProof, items.len);
    var slots: u64 = 0;
    for (items, out) |item, *account| {
        const object = try object_of(item);
        account.* = .{
            .address = (try request.address_of(try request.required(object, "address"))).bytes,
            .nonce = try quantity_field(u64, object, "nonce"),
            .balance = try quantity_field(u256, object, "balance"),
            .code_hash = try hash_field(object, "codeHash"),
            .storage_hash = try hash_field(object, "storageHash"),
            .proof = try nodes_of(arena, try request.required(object, "accountProof")),
            .slots = try slots_of(arena, try request.required(object, "storageProof")),
        };
        slots += account.slots.len;
        if (slots > slots_max) return error.TooMany;
    }
    return out;
}

/// `accounts` with `extra` folded in: an extra account already listed only adds the slots
/// that account lacks, others are appended. The same merge on both sides keeps a parent and
/// a block proof list aligned. Used for keys no transaction trace names: the EIP-4788 and
/// EIP-2935 system calls at the start of every block.
pub fn merge_proofs(
    arena: Allocator,
    accounts: []AccountProof,
    extra: []const AccountProof,
) error{ OutOfMemory, TooMany }![]AccountProof {
    if (accounts.len + extra.len > accounts_max) return error.TooMany;
    var out: std.ArrayList(AccountProof) = .empty;
    try out.appendSlice(arena, accounts);
    for (extra) |*account| {
        const index = for (out.items, 0..) |*listed, index| {
            if (std.mem.eql(u8, &listed.address, &account.address)) break index;
        } else {
            try out.append(arena, account.*);
            continue;
        };
        var slots: std.ArrayList(SlotProof) = .empty;
        try slots.appendSlice(arena, out.items[index].slots);
        for (account.slots) |*slot| {
            const listed = for (out.items[index].slots) |*present| {
                if (present.slot == slot.slot) break true;
            } else false;
            if (!listed) try slots.append(arena, slot.*);
        }
        out.items[index].slots = slots.items;
    }
    assert(out.items.len >= accounts.len);
    return out.items;
}

pub fn parse_block(root: Value) ParseError!Block {
    const object = try object_of(root);
    return .{
        .number = try quantity_field(u64, object, "number"),
        .parent_hash = try hash_field(object, "parentHash"),
        .state_root = try hash_field(object, "stateRoot"),
        .receipts_root = try hash_field(object, "receiptsRoot"),
        .transactions_root = try hash_field(object, "transactionsRoot"),
        .transactions = try array_of(try request.required(object, "transactions")),
    };
}

/// The state root of header `number` in a list of `{number, hash, stateRoot, ...}`.
pub fn header_state_root(root: Value, number: u64) ParseError!?Hash {
    for (try array_of(root)) |item| {
        const object = try object_of(item);
        if (try quantity_field(u64, object, "number") != number) continue;
        return try hash_field(object, "stateRoot");
    }
    return null;
}

pub const ProofFailure = struct { address: Address, slot: ?u256 };

fn slot_key(slot: u256) Hash {
    var bytes: Hash = undefined;
    std.mem.writeInt(u256, &bytes, slot, .big);
    return node.keccak256(&bytes);
}

fn account_holds(root: Hash, account: *AccountProof) bool {
    const key = node.keccak256(&account.address);
    const value = trie.proof.verify(root, &key, account.proof) catch return false;
    account.exists = value != null;
    const bytes = value orelse return account.nonce == 0 and account.balance == 0 and
        std.mem.eql(u8, &account.code_hash, &node.empty_code_hash) and
        std.mem.eql(u8, &account.storage_hash, &node.empty_root);
    const state = history.decode_account(bytes) catch return false;
    return state.nonce == account.nonce and state.balance == account.balance and
        std.mem.eql(u8, &state.code_hash, &account.code_hash) and
        std.mem.eql(u8, &state.storage_root, &account.storage_hash);
}

fn slot_holds(storage_root: Hash, slot: *const SlotProof) bool {
    const key = slot_key(slot.slot);
    const value = trie.proof.verify(storage_root, &key, slot.proof) catch return false;
    const bytes = value orelse return slot.value == 0;
    const decoded = history.decode_storage_value(bytes) catch return false;
    return decoded == slot.value;
}

/// Verifies every account and slot proof against `root`, recording which accounts exist.
/// Returns the first proof that does not hold, or null.
pub fn verify_proofs(root: Hash, accounts: []AccountProof) ?ProofFailure {
    for (accounts) |*account| {
        if (!account_holds(root, account)) return .{ .address = account.address, .slot = null };
        for (account.slots) |*slot| {
            if (!slot_holds(account.storage_hash, slot)) {
                return .{ .address = account.address, .slot = slot.slot };
            }
        }
    }
    return null;
}

/// Which nodes seed a replay: the parent proofs; plus the block's proofs; plus preimages
/// derived from the block's leaf and extension nodes (`seed_derived`).
pub const Seed = enum { pre, pre_and_post, derived };
pub const Status = enum { ok, mismatch, incomplete, invalid_proof };
pub const MismatchKind = enum { account, storage_root, state_root };

pub const Mismatch = struct {
    kind: MismatchKind,
    address: Address = @splat(0),
    /// A proven slot whose post value the sparse state does not hold, if any.
    slot: ?u256 = null,
    expected: Hash = @splat(0),
    actual: Hash = @splat(0),
};

pub const StateReport = struct {
    status: Status,
    seed: Seed = .pre,
    root: Hash = @splat(0),
    accounts_changed: u32 = 0,
    slots_changed: u32 = 0,
    mismatch: ?Mismatch = null,
    /// The first trie node the update needed and no proof provided.
    missing_node: ?Hash = null,
    /// Which proof set failed verification (`invalid_proof`), and where.
    failure: ?ProofFailure = null,
    failure_post: bool = false,
};

/// The parent and block a state check runs between.
pub const StateInput = struct {
    parent_number: u64,
    parent_hash: Hash,
    parent_root: Hash,
    post_root: Hash,
    pre: []AccountProof,
    post: []AccountProof,
};

/// Every replay `Checker.check` ran, in seed order.
pub const Replays = struct {
    reports: [seeds_count]StateReport = undefined,
    count: u32 = 0,

    fn push(replays: *Replays, report: StateReport) void {
        assert(replays.count < seeds_count);
        replays.reports[replays.count] = report;
        replays.count += 1;
    }

    pub fn slice(replays: *const Replays) []const StateReport {
        return replays.reports[0..replays.count];
    }

    pub fn verdict(replays: *const Replays) *const StateReport {
        assert(replays.count > 0);
        return &replays.reports[replays.count - 1];
    }
};

const seeds_count = std.enums.values(Seed).len;

pub const Error = witness.Error || changeset_module.Error ||
    error{ UnalignedProofs, WitnessFull };

pub const Checker = struct {
    state: SparseState,
    changeset: Changeset,
    missing: ?Hash = null,

    pub fn init(allocator: Allocator) !Checker {
        var state = try SparseState.init(allocator, .{
            .nodes_max = 1 << 18,
            .node_bytes_max = 128 << 20,
            .codes_max = 1,
            .code_bytes_max = 1,
            .headers_max = 1,
            .trie_nodes_max = 1 << 20,
            .storage_tries_max = accounts_max,
        });
        errdefer state.deinit(allocator);
        const changeset = try Changeset.init(allocator, .{
            .accounts_max = accounts_max,
            .storage_max = slots_max,
            .codes_max = 1,
            .code_bytes_max = 1,
        });
        return .{ .state = state, .changeset = changeset };
    }

    pub fn deinit(self: *Checker, allocator: Allocator) void {
        self.changeset.deinit(allocator);
        self.state.deinit(allocator);
        self.* = undefined;
    }

    /// Verifies both proof sets, then replays the diff seeded from the parent proofs; if
    /// that is incomplete, again with each larger `Seed` until one is not. The last report
    /// is the verdict.
    pub fn check(self: *Checker, input: StateInput) Error!Replays {
        var replays: Replays = .{};
        if (verify_proofs(input.parent_root, input.pre)) |failure| {
            replays.push(.{ .status = .invalid_proof, .failure = failure });
            return replays;
        }
        if (verify_proofs(input.post_root, input.post)) |failure| {
            replays.push(.{ .status = .invalid_proof, .failure = failure, .failure_post = true });
            return replays;
        }
        try self.build_changeset(input.pre, input.post);
        for (std.enums.values(Seed)) |seed| {
            const report = try self.replay(input, seed);
            replays.push(report);
            if (report.status != .incomplete) break;
        }
        assert(replays.count > 0);
        return replays;
    }

    /// Every post value that differs from the parent's, as a sorted changeset. Both lists
    /// must name the same accounts and slots in the same order (one key set, two blocks).
    fn build_changeset(
        self: *Checker,
        pre: []const AccountProof,
        post: []const AccountProof,
    ) Error!void {
        if (pre.len != post.len) return error.UnalignedProofs;
        self.changeset.clear();
        for (pre, post) |*before, *after| {
            if (!std.mem.eql(u8, &before.address, &after.address)) return error.UnalignedProofs;
            if (before.slots.len != after.slots.len) return error.UnalignedProofs;
            const old = before.info();
            const new = after.info();
            const same = if (old != null and new != null) old.?.eql(new.?) else old == null and
                new == null;
            if (!same) try self.changeset.add_account(.{
                .address = after.address,
                .old = old,
                .new = new,
            });
            for (before.slots, after.slots) |*slot_before, *slot_after| {
                if (slot_before.slot != slot_after.slot) return error.UnalignedProofs;
                if (slot_before.value == slot_after.value) continue;
                try self.changeset.add_storage(.{
                    .address = after.address,
                    .slot = slot_after.slot,
                    .old = slot_before.value,
                    .new = slot_after.value,
                });
            }
        }
        self.changeset.sort();
        assert(self.changeset.account_changes().len <= post.len);
    }

    fn seed_nodes(self: *Checker, accounts: []const AccountProof) error{WitnessFull}!void {
        for (accounts) |*account| {
            for (account.proof) |bytes| try self.state.add_node(bytes);
            for (account.slots) |*slot| {
                for (slot.proof) |bytes| try self.state.add_node(bytes);
            }
        }
    }

    /// A delete that collapses a branch needs the preimage of the surviving sibling, which
    /// no proof of a touched key holds. When the sibling is a leaf or an extension, the
    /// block's proof of the deleted key ends at the node it merged into: the same node with
    /// a longer path. So every suffix of every post leaf and extension path is a candidate
    /// preimage; the store keys them by keccak256, so only an exact match is ever used.
    fn seed_derived(self: *Checker, accounts: []const AccountProof) error{WitnessFull}!void {
        for (accounts) |*account| {
            for (account.proof) |bytes| try self.add_suffixes(bytes);
            for (account.slots) |*slot| {
                for (slot.proof) |bytes| try self.add_suffixes(bytes);
            }
        }
    }

    fn add_suffixes(self: *Checker, bytes: []const u8) error{WitnessFull}!void {
        // Proof nodes verified against the root already.
        const decoded = trie.sparse.decode_node(bytes) catch unreachable;
        if (decoded.kind == .branch) return;
        const path = decoded.path.slice();
        const leaf = decoded.kind == .leaf;
        assert(leaf or path.len > 0);
        // A leaf may lose its whole path; an extension keeps at least one nibble.
        const strip_max = if (leaf) path.len else path.len - 1;
        var buffer: [256]u8 = undefined;
        var strip: usize = 1;
        while (strip <= strip_max) : (strip += 1) {
            var sink: node.BufferSink = .{ .buffer = &buffer };
            if (leaf) {
                node.encode_leaf(&sink, path[strip..], decoded.value);
            } else {
                node.encode_extension(&sink, path[strip..], &decoded.children[0]);
            }
            // Shorter nodes are embedded in their parent, never looked up by hash.
            if (sink.written >= 32) try self.state.add_node(sink.result());
        }
    }

    fn record_missing(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *Checker = @ptrCast(@alignCast(context));
        if (self.missing == null) self.missing = hash.*;
        return null;
    }

    fn no_code(_: *anyopaque, _: *const Hash) ?[]const u8 {
        return null;
    }

    fn no_block_hash(_: *anyopaque, _: u64) ?Hash {
        return null;
    }

    fn replay(self: *Checker, input: StateInput, seed: Seed) Error!StateReport {
        self.state.reset(input.parent_root, .{
            .number = input.parent_number,
            .hash = input.parent_hash,
        });
        try self.seed_nodes(input.pre);
        if (seed != .pre) try self.seed_nodes(input.post);
        if (seed == .derived) try self.seed_derived(input.post);
        self.missing = null;
        self.state.set_fallback(.{
            .context = self,
            .node = record_missing,
            .code = no_code,
            .block_hash = no_block_hash,
        });
        defer self.state.set_fallback(null);
        var report: StateReport = .{
            .status = .ok,
            .seed = seed,
            .accounts_changed = @intCast(self.changeset.account_changes().len),
            .slots_changed = @intCast(self.changeset.storage_changes().len),
        };
        self.state.apply(&self.changeset) catch |err| switch (err) {
            error.WitnessIncomplete => {
                report.status = .incomplete;
                report.missing_node = self.missing;
                return report;
            },
            else => return err,
        };
        report.mismatch = try self.compare(input);
        report.root = self.state.state_root();
        if (report.mismatch == null and !std.mem.eql(u8, &report.root, &input.post_root)) {
            report.mismatch = .{
                .kind = .state_root,
                .expected = input.post_root,
                .actual = report.root,
            };
        }
        if (report.mismatch != null) report.status = .mismatch;
        return report;
    }

    /// The first post account whose leaf or storage root the sparse state disagrees with.
    fn compare(self: *Checker, input: StateInput) Error!?Mismatch {
        for (input.post) |*after| {
            const info = try self.state.basic(after.address);
            const expected = after.info();
            const same = if (info != null and expected != null)
                info.?.eql(expected.?)
            else
                info == null and expected == null;
            if (!same) return .{ .kind = .account, .address = after.address };
            const storage_root = try self.state.account_storage_root(after.address);
            if (std.mem.eql(u8, &storage_root, &after.storage_hash)) continue;
            var mismatch: Mismatch = .{
                .kind = .storage_root,
                .address = after.address,
                .expected = after.storage_hash,
                .actual = storage_root,
            };
            for (after.slots) |*slot| {
                if (try self.state.storage(after.address, slot.slot) == slot.value) continue;
                mismatch.slot = slot.slot;
                break;
            }
            return mismatch;
        }
        return null;
    }
};

pub const RootError = rpc_types.transaction.ParseError || ParseError ||
    error{ UnknownType, BloomMismatch };

fn logs_of(arena: Allocator, value: Value) RootError!consensus.receipt.Logs {
    const items = try array_of(value);
    const logs = try arena.alloc(consensus.receipt.Log, items.len);
    var length: usize = 0;
    for (items, logs) |item, *log| {
        const object = try object_of(item);
        const topics = try array_of(try request.required(object, "topics"));
        const payload = try arena.alloc(u8, topics.len * 33);
        for (topics, 0..) |topic, index| {
            payload[index * 33] = 0xa0;
            payload[index * 33 + 1 ..][0..32].* = (try request.hash_of(topic)).bytes;
        }
        log.* = .{
            .address = try request.address_of(try request.required(object, "address")),
            .topics = .{ .payload = payload },
            .data = try request.data_of(arena, try request.required(object, "data")),
        };
        length += rlp.length(log.*);
    }
    return consensus.receipt.Logs.build(try arena.alloc(u8, length), logs);
}

fn optional_quantity(comptime T: type, object: std.json.ObjectMap, name: []const u8) !?T {
    const value = request.field(object, name) orelse return null;
    return try request.quantity(T, value);
}

/// The EIP-2718 consensus encoding of an `eth_getBlockReceipts` entry. The reported bloom
/// must match the logs.
fn encode_receipt(arena: Allocator, value: Value) RootError![]const u8 {
    const object = try object_of(value);
    const type_byte = try quantity_field(u8, object, "type");
    const tx_type = std.enums.fromInt(consensus.tx.TxType, type_byte) orelse
        return error.UnknownType;
    const bloom_text = try request.string_of(try request.required(object, "logsBloom"));
    const bloom = primitives.hex.decode_array(256, bloom_text) catch return error.InvalidField;
    const deposit = tx_type == .deposit;
    const receipt: consensus.receipt.Receipt = .{
        .tx_type = tx_type,
        .status = try quantity_field(u64, object, "status") == 1,
        .cumulative_gas_used = try quantity_field(u64, object, "cumulativeGasUsed"),
        .logs_bloom = .{ .bytes = bloom },
        .logs = try logs_of(arena, try request.required(object, "logs")),
        .deposit_nonce = if (deposit) try optional_quantity(u64, object, "depositNonce") else null,
        .deposit_receipt_version = if (deposit)
            try optional_quantity(u64, object, "depositReceiptVersion")
        else
            null,
        .committed_phases = if (tx_type == .eip8130)
            try quantity_field(u64, object, "committedPhases")
        else
            null,
    };
    if (!std.mem.eql(u8, &receipt.logs.bloom().bytes, &bloom)) return error.BloomMismatch;
    return receipt.encode_to(try arena.alloc(u8, receipt.encoded_length()));
}

/// The receipts root of an `eth_getBlockReceipts` result, in order.
pub fn receipts_root(arena: Allocator, root: Value) RootError!Hash {
    const items = try array_of(root);
    const encoded = try arena.alloc([]const u8, items.len);
    for (items, encoded) |item, *out| out.* = try encode_receipt(arena, item);
    return trie.ordered.ordered_trie_root(encoded);
}

/// The transactions root of a block's full transaction objects; each rebuilt envelope must
/// hash to its reported `hash`.
pub fn transactions_root(arena: Allocator, transactions: []const Value) RootError!Hash {
    const encoded = try arena.alloc([]const u8, transactions.len);
    for (transactions, encoded) |item, *out| {
        const parsed = try rpc_types.transaction.parse_transaction(arena, item);
        out.* = parsed.envelope.encode_to(try arena.alloc(u8, parsed.envelope.encoded_length()));
    }
    return trie.ordered.ordered_trie_root(encoded);
}

//! Differential protocol `trie` mode (base/base `TRIE_PROTOCOL.md`): applies a request's
//! blocks of hashed-key writes, from the empty state, and reports after every block the
//! state root, the storage roots of the keys the block names, and the requested proofs.
//!
//! `blocks` (the primary) is the node's commit path over its own on-disk database in
//! `trie.dir` (`trie_node.zig`, disk mode): each block's writes, as post-block values in
//! hashed key space (`trie_model.zig`), go through `StateDb.commit_hashed` (a hashed
//! changeset applied into the flat trees by `DiskState`) and `Database.commit_applied`;
//! roots come from the database head and its account records, proofs from
//! `Database.proof_hashed` (eth_getProof's disk walk). Unwinds are native (`set_head`);
//! one the database cannot make (deeper than its reorg bound) applies the revert and the
//! ops as one block.
//!
//! `variants` (`trie_variants.zig`): `sparse`, `state-trie`, `hash-builder` (the model's
//! whole state through `HashBuilder`), `disk-small` (the primary's path over another
//! database at `trie_node.config_disk_small`: memtables flush and checkpoints run every
//! block, tables merge every few; its own native unwinds), `disk-small-reopen` (the same
//! over another database, restarted after every block, cleanly and as a crash in turn, and
//! read after the restart), `disk-deep` (the primary's path over `config_disk_deep`, each
//! block committed as blocks of 8 + 8 writes, so the flat trees merge into level 2; unwinds
//! as revert and ops), `disk-view-history` (the primary's path over another `config_disk_small`
//! database with el-run's archive capture, `trie_history.zig`: after the last block, every
//! canonical block is read again through a history view of it, `DiskState.view_begin`; the
//! other blocks report their number only), and on requests whose every key carries its
//! preimages, `node-address` (the durable node's in-memory state keyed by address: `Overlay`,
//! `execute_and_commit`, `proof_at`) and `memory-history` (the same with `base node
//! --proofs-history`'s window: after the last block the database restarts, which rebuilds the
//! window, and every canonical block in it is proven again by `proof_at` and `proofs_at` at
//! its number; the other blocks report their number only). Each in another database in
//! `trie.dir`. A variant that fails reports the error on that block and every later one.
//!
//! On requests with preimages, every disk-mode database also answers each proof target by
//! address, as el-run's RPC does (`proof_at` at the head, eth_getProof; `State.basic` and
//! `State.storage`, eth_getBalance and eth_getStorageAt); a disagreement with the hashed
//! answer is that block's `error` (its fields still reported). A proof whose account exists
//! reports its code (`code`) when the database holds it (`State.code_by_hash`, read from the
//! code tables), as eth_getCode.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const trie_request = @import("trie_request.zig");
const trie_model = @import("trie_model.zig");
const trie_node = @import("trie_node.zig");
const trie_variants = @import("trie_variants.zig");
const Archive = @import("trie_history.zig").Archive;
const response = @import("response.zig");
const Coverage = @import("coverage.zig").Coverage;

const Hash = [32]u8;
const empty_root = @import("../../execution/trie/root.zig").empty_root;
const Writer = std.Io.Writer;
const Case = trie_request.Case;
const Block = trie_request.Block;
const Op = trie_request.Op;
const Node = trie_node.Node;
const Model = trie_model.Model;
const Touched = trie_model.Touched;
const AccountState = db.history.AccountState;

pub const StorageRoot = struct { key: Hash, root: Hash };
pub const SlotProof = struct { slot: Hash, value: u256, proof: []const []const u8 };
pub const ProofResult = struct {
    key: Hash,
    account: ?AccountState,
    account_proof: []const []const u8,
    storage: []SlotProof,
    /// The account's code, when it exists and the database holds the code.
    code: ?[]const u8 = null,
};

/// One block's result; a variant fills what it computes, or `error_text`.
pub const BlockResult = struct {
    number: u64,
    error_text: ?[]const u8 = null,
    state_root: ?Hash = null,
    storage_roots: ?[]const StorageRoot = null,
    proofs: ?[]const ProofResult = null,
};

pub const Variant = struct { name: []const u8, blocks: []BlockResult };

pub const Outcome = struct { blocks: []const BlockResult, variants: []const Variant };

const variant_names = [_][]const u8{
    "sparse",
    "state-trie",
    "hash-builder",
    "disk-small",
    "disk-small-reopen",
    "disk-deep",
    "disk-view-history",
    "node-address",
    "memory-history",
    "memory-history-budget",
};
const VariantId = enum(u8) {
    sparse,
    state_trie,
    hash_builder,
    disk_small,
    disk_small_reopen,
    disk_deep,
    disk_view_history,
    node_address,
    memory_history,
    memory_history_budget,
};

/// Variants keyed by address: on requests with preimages only.
fn address_keyed(id: VariantId) bool {
    return switch (id) {
        .node_address, .memory_history, .memory_history_budget => true,
        else => false,
    };
}

/// The variants over another disk-mode database in `trie.dir`, each the primary's path.
const DiskSpec = struct { id: VariantId, mode: trie_node.Mode, file: []const u8 };
const disk_specs = [_]DiskSpec{
    .{ .id = .disk_small, .mode = .disk_small, .file = "disk-small.db" },
    .{ .id = .disk_small_reopen, .mode = .disk_small, .file = "disk-small-reopen.db" },
    .{ .id = .disk_deep, .mode = .disk_deep, .file = "disk-deep.db" },
};
const db_files = [_][]const u8{
    "primary.db",
    "node-address.db",
    "disk-view-history.db",
    "memory-history.db",
    "memory-history-budget.db",
} ++ blk: {
    var files: [disk_specs.len][]const u8 = undefined;
    for (disk_specs, &files) |spec, *file| file.* = spec.file;
    break :blk files;
};

const Disk = struct {
    node: ?*Node = null,
    /// Request height -> the database height holding that state.
    heights: [trie_node.blocks_max + 1]u64 = undefined,
};

/// One request's run: the databases, the variants and the model.
const Run = struct {
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    case: *const Case,
    model: Model,
    primary: *Node,
    /// Request height -> the primary's height holding that state (a non-native unwind
    /// appends a block instead of moving back).
    primary_heights: [trie_node.blocks_max + 1]u64 = undefined,
    address_node: ?*Node = null,
    address_heights: [trie_node.blocks_max + 1]u64 = undefined,
    /// `disk-view-history`: its database, archive, and the state root of each of its blocks.
    view: Disk = .{},
    view_roots: [trie_node.blocks_max + 1]Hash = undefined,
    archive: ?Archive = null,
    /// `memory-history` and `memory-history-budget`.
    history: Disk = .{},
    budget: Disk = .{},
    disks: [disk_specs.len]Disk = @splat(.{}),
    sparse: ?*trie_variants.Sparse = null,
    state_trie: ?trie_variants.StateTrieVariant = null,
    /// The first error of each variant (later blocks repeat it).
    failed: [variant_names.len]?[]const u8 = @splat(null),
    variants: [variant_names.len][]BlockResult = undefined,
    height: u64 = 0,
};

/// Runs `case` in `case.dir` (created, and deleted with everything in it before returning).
pub fn run(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    io: std.Io,
    case: *const Case,
) !Outcome {
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, case.dir) catch return error.DirectoryFailed;
    defer remove_dir(io, case.dir);
    const primary_path = try std.fs.path.join(arena, &.{ case.dir, "primary.db" });
    const address_path = try std.fs.path.join(arena, &.{ case.dir, "node-address.db" });
    var state: Run = .{
        .arena = arena,
        .allocator = allocator,
        .case = case,
        .model = .{ .arena = arena },
        .primary = try Node.create(allocator, .disk, primary_path),
    };
    defer state.primary.destroy();
    state.primary_heights[0] = 0;
    state.address_heights[0] = 0;
    for (&state.disks) |*disk| disk.heights[0] = 0;
    state.view.heights[0] = 0;
    state.history.heights[0] = 0;
    state.budget.heights[0] = 0;
    state.view_roots[0] = empty_root;
    for (&state.variants) |*blocks| blocks.* = try arena.alloc(BlockResult, case.blocks.len);
    try start_variants(&state, address_path);
    defer stop_variants(&state);
    const blocks = try arena.alloc(BlockResult, case.blocks.len);
    for (case.blocks, blocks, 0..) |*block, *result, index| {
        result.* = try run_block(&state, block, index);
    }
    finish_views(&state);
    finish_history(&state);
    finish_budget(&state);
    var variants: std.ArrayList(Variant) = .empty;
    for (variant_names, state.variants, 0..) |name, results, index| {
        const id: VariantId = @fromBackingInt(@intCast(index));
        if (address_keyed(id) and !case.preimages) continue;
        try variants.append(arena, .{ .name = name, .blocks = results });
    }
    return .{ .blocks = blocks, .variants = variants.items };
}

fn start_variants(state: *Run, address_path: []const u8) error{OutOfMemory}!void {
    const allocator = state.allocator;
    state.sparse = trie_variants.Sparse.create(allocator) catch |err| blk: {
        state.failed[@backingInt(VariantId.sparse)] = @errorName(err);
        break :blk null;
    };
    state.state_trie = trie_variants.StateTrieVariant.init(allocator) catch |err| blk: {
        state.failed[@backingInt(VariantId.state_trie)] = @errorName(err);
        break :blk null;
    };
    for (disk_specs, &state.disks) |spec, *disk| {
        disk.node = try create_node(state, spec.id, spec.mode, spec.file);
    }
    state.view.node = try create_node(state, .disk_view_history, .disk_small, db_files[2]);
    if (state.view.node) |node| {
        state.archive = try Archive.init(state.arena, allocator);
        try node.capture_enable();
    }
    if (!state.case.preimages) return;
    state.address_node = Node.create(allocator, .memory, address_path) catch |err| blk: {
        state.failed[@backingInt(VariantId.node_address)] = @errorName(err);
        break :blk null;
    };
    state.history.node = try create_node(state, .memory_history, .memory_history, db_files[3]);
}

/// A variant's database in `trie.dir`, or null with the variant failed.
fn create_node(
    state: *Run,
    id: VariantId,
    mode: trie_node.Mode,
    file: []const u8,
) error{OutOfMemory}!?*Node {
    const path = try std.fs.path.join(state.arena, &.{ state.case.dir, file });
    return Node.create(state.allocator, mode, path) catch |err| {
        state.failed[@backingInt(id)] = @errorName(err);
        return null;
    };
}

fn stop_variants(state: *Run) void {
    if (state.budget.node) |node| node.destroy();
    if (state.history.node) |node| node.destroy();
    if (state.archive) |*archive| archive.deinit(state.allocator);
    if (state.view.node) |node| node.destroy();
    if (state.address_node) |node| node.destroy();
    for (&state.disks) |*disk| if (disk.node) |node| node.destroy();
    if (state.state_trie) |*variant| variant.deinit(state.allocator);
    if (state.sparse) |sparse| sparse.destroy(state.allocator);
}

/// Deletes the request's database files and its directory (best effort: the directory
/// was empty or absent before the request).
fn remove_dir(io: std.Io, dir: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    var names_buffer: [db_files.len][std.fs.max_path_bytes]u8 = undefined;
    for (db_files, &names_buffer) |name, *buffer| {
        const path = std.fmt.bufPrint(buffer, "{s}/{s}", .{ dir, name }) catch continue;
        cwd.deleteFile(io, path) catch {};
    }
    cwd.deleteDir(io, dir) catch |err| {
        std.log.warn("diff adapter: trie dir {s} not removed: {t}", .{ dir, err });
    };
}

fn run_block(state: *Run, block: *const Block, index: usize) !BlockResult {
    if (block.unwind > state.height) return error.InvalidField;
    const parent = state.height - block.unwind;
    if (block.number != parent + 1) return error.InvalidField;
    // The model: the revert (the state after the parent), then the ops.
    // The primary's block is the ops alone after a native unwind, else revert and ops.
    var touched_all: Touched = .{};
    var touched_ops: Touched = .{};
    try state.model.apply(block.revert, &touched_all);
    try state.model.apply(block.ops, &touched_ops);
    for (touched_ops.accounts.keys()) |key| try touched_all.accounts.put(state.arena, key, {});
    for (touched_ops.slots.keys()) |ref| try touched_all.slots.put(state.arena, ref, {});
    var writes_native = try state.model.writes(&touched_ops);
    var writes_all = try state.model.writes(&touched_all);
    writes_native.codes = try block_codes(state.arena, &.{block.ops});
    writes_all.codes = try block_codes(state.arena, &.{ block.revert, block.ops });
    const named = try named_keys(state.arena, block);
    var result: BlockResult = .{ .number = block.number };
    // The primary.
    const node = state.primary;
    const native = try node.unwind_to(state.primary_heights[@intCast(parent)]);
    try node.commit_hashed(if (native) writes_native else writes_all);
    state.primary_heights[@intCast(parent + 1)] = node.height;
    result.state_root = node.state_root();
    result.storage_roots = try node_storage_roots(state, node, named);
    result.proofs = try node_proofs(state, node, block);
    result.error_text = try read_check(state, node, block, result.proofs.?);
    state.height = parent + 1;
    run_variants(state, block, index, parent, named, .{
        .native = writes_native,
        .all = writes_all,
    });
    return result;
}

/// The codes the account ops of `lists` carry, each once (an evm block's deployed codes).
fn block_codes(arena: std.mem.Allocator, lists: []const []const Op) ![]const []const u8 {
    var codes: std.ArrayList([]const u8) = .empty;
    for (lists) |ops| {
        for (ops) |*op| {
            const code = op.code orelse continue;
            const listed = for (codes.items) |item| {
                if (std.mem.eql(u8, item, code)) break true;
            } else false;
            if (!listed) try codes.append(arena, code);
        }
    }
    return codes.items;
}

/// Every key an op of the block (its revert too) names, once, ascending.
fn named_keys(arena: std.mem.Allocator, block: *const Block) ![]const Hash {
    var keys: std.AutoArrayHashMapUnmanaged(Hash, void) = .empty;
    for ([2][]const Op{ block.revert, block.ops }) |ops| {
        for (ops) |*op| try keys.put(arena, op.key, {});
    }
    const sorted = keys.keys();
    std.mem.sort(Hash, sorted, {}, hash_less_than);
    return sorted;
}

fn hash_less_than(_: void, a: Hash, b: Hash) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

/// A disk-mode node's storage roots of `named`, from its account records.
fn node_storage_roots(state: *Run, node: *Node, named: []const Hash) ![]const StorageRoot {
    assert(!node.in_memory());
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const record = node.db.state.account_hashed(key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = record.storage_root });
    }
    return roots.items;
}

/// A disk-mode node's proofs of the block's targets (`Database.proof_hashed`).
fn node_proofs(state: *Run, node: *Node, block: *const Block) ![]const ProofResult {
    assert(!node.in_memory());
    const proofs = try state.arena.alloc(ProofResult, block.proofs.len);
    const account_proof = try state.allocator.create(trie_node.AccountProof);
    defer state.allocator.destroy(account_proof);
    const storage_proofs = try state.allocator.alloc(
        trie_node.StorageProof,
        trie_request.proof_slots_max,
    );
    defer state.allocator.free(storage_proofs);
    var values: [trie_request.proof_slots_max]u256 = undefined;
    for (block.proofs, proofs) |*target, *out| {
        const count = target.slots.len;
        const account = try node.db.proof_hashed(
            &target.key,
            target.slots,
            account_proof,
            storage_proofs[0..count],
            values[0..count],
        );
        out.* = try proof_result(state.arena, target, account, account_proof, storage_proofs);
        for (out.storage, values[0..count]) |*slot, value| slot.value = value;
        out.code = try code_of(state.arena, node, account);
    }
    // As el-run's RPC after a request: the codes read from tables are released.
    node.db.codes_release();
    return proofs;
}

/// The code of `account` from the database (eth_getCode), copied; null when it has none.
fn code_of(arena: std.mem.Allocator, node: *Node, account: ?AccountState) !?[]const u8 {
    const found = account orelse return null;
    const code = node.db.state.code_by_hash(found.code_hash) orelse return null;
    return try arena.dupe(u8, code);
}

/// On requests with preimages: every proof target of the block again by address, as
/// el-run's RPC answers it (`proof_at` at the head, eth_getProof; `State.basic` and
/// `State.storage`, eth_getBalance and eth_getStorageAt), against `proofs`. The first
/// disagreement's description, or null.
fn read_check(
    state: *Run,
    node: *Node,
    block: *const Block,
    proofs: []const ProofResult,
) !?[]const u8 {
    if (!state.case.preimages) return null;
    assert(!node.in_memory());
    const by_address = try address_proofs(state, node, block, node.db.head_info.number);
    for (block.proofs, proofs, by_address) |*target, *hashed, *addressed| {
        if (!proofs_equal(hashed, addressed)) return "proof_at disagrees with proof_hashed";
        const address = target.address.?;
        const info = node.db.state.basic(address);
        const account = hashed.account;
        if ((info == null) != (account == null)) return "State.basic disagrees with the proof";
        if (info) |found| {
            const same = found.nonce == account.?.nonce and found.balance == account.?.balance and
                std.mem.eql(u8, &found.code_hash, &account.?.code_hash);
            if (!same) return "State.basic disagrees with the proof";
        }
        for (target.slot_keys.?, hashed.storage) |*slot_key, *slot| {
            const word = node.db.state.storage(address, std.mem.readInt(u256, slot_key, .big));
            if (word != slot.value) return "State.storage disagrees with the proof";
        }
    }
    return null;
}

fn proofs_equal(a: *const ProofResult, b: *const ProofResult) bool {
    if (!std.meta.eql(a.account, b.account)) return false;
    if (!nodes_equal(a.account_proof, b.account_proof)) return false;
    if (a.storage.len != b.storage.len) return false;
    for (a.storage, b.storage) |*x, *y| {
        if (x.value != y.value or !nodes_equal(x.proof, y.proof)) return false;
    }
    const code_a = a.code orelse &.{};
    const code_b = b.code orelse &.{};
    return (a.code == null) == (b.code == null) and std.mem.eql(u8, code_a, code_b);
}

fn nodes_equal(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

/// Copies a proof out of the trie's proof buffers (values are filled by the caller).
fn proof_result(
    arena: std.mem.Allocator,
    target: *const trie_request.Proof,
    account: ?AccountState,
    account_proof: anytype,
    storage_proofs: anytype,
) error{OutOfMemory}!ProofResult {
    const storage = try arena.alloc(SlotProof, target.slots.len);
    for (storage, target.slots, 0..) |*slot, slot_key, index| {
        const proof = try nodes_of(arena, &storage_proofs[index]);
        slot.* = .{ .slot = slot_key, .value = 0, .proof = proof };
    }
    return .{
        .key = target.key,
        .account = account,
        .account_proof = try nodes_of(arena, account_proof),
        .storage = storage,
    };
}

fn nodes_of(arena: std.mem.Allocator, proof: anytype) error{OutOfMemory}![]const []const u8 {
    const nodes = try arena.alloc([]const u8, proof.count);
    for (nodes, 0..) |*item, index| {
        const start = if (index == 0) 0 else proof.ends[index - 1];
        item.* = try arena.dupe(u8, proof.buffer[start..proof.ends[index]]);
    }
    return nodes;
}

fn run_variants(
    state: *Run,
    block: *const Block,
    index: usize,
    parent: u64,
    named: []const Hash,
    writes: BlockWrites,
) void {
    for (&state.variants, 0..) |results, id_index| {
        const id: VariantId = @fromBackingInt(@intCast(id_index));
        results[index] = .{ .number = block.number };
        if (state.failed[id_index]) |text| {
            results[index].error_text = text;
            continue;
        }
        const outcome = switch (id) {
            .sparse => sparse_block(state, parent, named, writes.native),
            .state_trie => state_trie_block(state, block, named),
            .hash_builder => hash_builder_block(state, named),
            .disk_small, .disk_small_reopen, .disk_deep => disk_block(state, id, block, .{
                .index = index,
                .parent = parent,
                .named = named,
                .writes = writes,
            }),
            .disk_view_history => view_block(state, parent, writes),
            .node_address => address_block(state, block, parent, named),
            .memory_history => history_block(state, block, parent),
            .memory_history_budget => budget_block(),
        };
        results[index] = outcome catch |err| {
            const text = @errorName(err);
            state.failed[id_index] = text;
            results[index].error_text = text;
            continue;
        };
        results[index].number = block.number;
    }
}

/// A block's writes after a native unwind (`native`: the ops), and otherwise (`all`: the
/// revert, then the ops).
const BlockWrites = struct { native: db.overlay.HashedWrites, all: db.overlay.HashedWrites };

const DiskBlock = struct {
    index: usize,
    parent: u64,
    named: []const Hash,
    writes: BlockWrites,
};

/// `disk-small`, `disk-small-reopen` and `disk-deep`: the primary's path over another
/// database, with its own unwind decision (it may retain fewer blocks, or none to unwind
/// to). `disk-deep` commits the block as several (`Node.commit_split`); `disk-small-reopen`
/// restarts the database around the block (`restart_plan`) and answers from the restarted
/// database.
fn disk_block(state: *Run, id: VariantId, block: *const Block, at: DiskBlock) anyerror!BlockResult {
    const disk = for (disk_specs, &state.disks) |spec, *disk| {
        if (spec.id == id) break disk;
    } else unreachable; // `run_variants` passes disk variants only.
    var node = disk.node orelse return error.Unavailable;
    const native = try node.unwind_to(disk.heights[@intCast(at.parent)]);
    const writes = if (native) at.writes.native else at.writes.all;
    const plan: Restart = if (id == .disk_small_reopen) restart_plan(at.index) else .none;
    const variant: u32 = @intCast(at.index / 8);
    if (plan == .torn_journal) {
        disk.node = null; // Gone even when the restart fails.
        node = try node.restart_torn(.journal, variant, writes);
        disk.node = node;
    }
    if (node.mode == .disk_deep) try node.commit_split(writes) else try node.commit_hashed(writes);
    disk.heights[@intCast(at.parent + 1)] = node.height;
    if (plan != .none and plan != .torn_journal) {
        disk.node = null; // Gone even when the restart fails.
        node = switch (plan) {
            .clean => try node.reopen(null),
            // A crash lands at a different point of the checkpoint it asks for each time.
            .crash => try node.reopen(@intCast(at.index % 8)),
            .torn_checkpoint => try node.restart_torn(.checkpoint, variant, null),
            .torn_superblock => try node.restart_torn(.superblock, variant, null),
            .none, .torn_journal => unreachable, // Handled above.
        };
        disk.node = node;
    }
    const proofs = try node_proofs(state, node, block);
    return .{
        .number = 0,
        .state_root = node.state_root(),
        .storage_roots = try node_storage_roots(state, node, at.named),
        .proofs = proofs,
        .error_text = try read_check(state, node, block, proofs),
    };
}

/// How `disk-small-reopen` restarts around a block.
const Restart = enum {
    none,
    /// A clean shutdown and open, after the block.
    clean,
    /// A power loss part way into a checkpoint that drops every write in flight, after the
    /// block.
    crash,
    /// A power loss tearing the block's own journal entry: the block is lost and committed
    /// again (`Node.restart_torn`).
    torn_journal,
    /// After the block, a power loss tearing a checkpoint block, or a superblock copy.
    torn_checkpoint,
    torn_superblock,
};

/// Even blocks restart cleanly; odd ones crash, in turn dropping the writes in flight, tearing
/// the block's journal entry, a checkpoint block, and a superblock copy.
fn restart_plan(index: usize) Restart {
    if (index % 2 == 0) return .clean;
    return switch (index / 2 % 4) {
        0 => .crash,
        1 => .torn_journal,
        2 => .torn_checkpoint,
        3 => .torn_superblock,
        else => unreachable, // A remainder of four.
    };
}

/// `disk-view-history` during the blocks: the primary's path (its own native unwinds), each
/// block taken into the archive; it answers after the last block (`finish_views`).
fn view_block(state: *Run, parent: u64, writes: BlockWrites) anyerror!BlockResult {
    const node = state.view.node orelse return error.Unavailable;
    const archive = &state.archive.?;
    const native = try node.unwind_to(state.view.heights[@intCast(parent)]);
    if (native) archive.truncate(node.height);
    try node.commit_hashed(if (native) writes.native else writes.all);
    try archive.take(node);
    state.view.heights[@intCast(parent + 1)] = node.height;
    state.view_roots[@intCast(node.height)] = node.state_root();
    return .{ .number = 0 };
}

/// Whether block `index` is on the chain the request ends with: no later block replaces it
/// (an unwind to below it).
fn canonical(blocks: []const Block, index: usize) bool {
    for (blocks[index + 1 ..]) |*later| {
        if (later.number <= blocks[index].number) return false;
    }
    return true;
}

/// `disk-view-history` after the last block: every canonical block read again through a
/// history view of it (el-run's archive `view_begin`), over the head's trees and the archive.
fn finish_views(state: *Run) void {
    const id = @backingInt(VariantId.disk_view_history);
    if (state.failed[id] != null) return;
    for (state.case.blocks, state.variants[id], 0..) |*block, *result, index| {
        if (!canonical(state.case.blocks, index)) continue;
        result.* = view_answer(state, block) catch |err| .{
            .number = block.number,
            .error_text = @errorName(err),
        };
    }
}

fn view_answer(state: *Run, block: *const Block) !BlockResult {
    const node = state.view.node.?;
    const archive = &state.archive.?;
    const height = state.view.heights[@intCast(block.number)];
    const root = state.view_roots[@intCast(height)];
    archive.view_height = height;
    const disk = &node.db.disk.?;
    disk.view_begin(root, archive.overlay());
    defer disk.view_end();
    const named = try named_keys(state.arena, block);
    const proofs = try node_proofs(state, node, block);
    return .{
        .number = block.number,
        .state_root = root,
        .storage_roots = try node_storage_roots(state, node, named),
        .proofs = proofs,
        .error_text = try read_check(state, node, block, proofs),
    };
}

/// `memory-history` during the blocks: `node-address`'s path with a history window; it
/// answers after the last block (`finish_history`).
fn history_block(state: *Run, block: *const Block, parent: u64) anyerror!BlockResult {
    const node = state.history.node orelse return error.Unavailable;
    const native = try node.unwind_to(state.history.heights[@intCast(parent)]);
    if (!native) try overlay_ops(node, block.revert);
    try overlay_ops(node, block.ops);
    try node.commit_overlay();
    state.history.heights[@intCast(parent + 1)] = node.height;
    return .{ .number = 0 };
}

/// `memory-history` after the last block: the database restarts (a clean shutdown and open,
/// which rebuilds the window: `history_rebuild_window`), then every canonical block still in
/// the window is proven at its number from history (`proof_at`, checked against
/// `proofs_at`), its storage roots read from history (`account_at`). An open checks that
/// every account's code is stored (`snapshot.verify`): when the request set a code hash
/// without its code (a state no node holds) the window is read without the restart.
fn finish_history(state: *Run) void {
    const id = @backingInt(VariantId.memory_history);
    if (!state.case.preimages or state.failed[id] != null) return;
    const results = state.variants[id];
    if (codes_stored(&state.history.node.?.db.state)) {
        const node = state.history.node.?;
        state.history.node = null; // Gone even when the reopen fails.
        state.history.node = node.reopen(null) catch |err| {
            for (results) |*result| result.error_text = @errorName(err);
            return;
        };
    }
    window_answers(state, &state.history, results);
}

/// `memory-history-budget` during the blocks: nothing yet (`finish_budget` runs it).
fn budget_block() anyerror!BlockResult {
    return .{ .number = 0 };
}

/// Every canonical block still in `history`'s window, into `results`.
fn window_answers(state: *Run, history: *Disk, results: []BlockResult) void {
    for (state.case.blocks, results, 0..) |*block, *result, index| {
        if (!canonical(state.case.blocks, index)) continue;
        const answer = history_answer(state, history, block) catch |err| {
            result.error_text = @errorName(err);
            continue;
        };
        if (answer) |found| result.* = found;
    }
}

/// `memory-history-budget` after `memory-history`: the request again, by address, into an
/// in-memory database whose history has a byte budget (`base node --proofs-history` always
/// sets one: `history_config`), each request block committed as up to four blocks
/// (`budget_chunks`). The budget is a third of what `memory-history`'s window held beyond its
/// state (`budget_bytes`), so the window shrinks as blocks commit (`fit_budget`,
/// `prune_step`); then the database restarts, which rebuilds the window under the budget from
/// an estimate (`history_rebuild_guess`; at least `4 * history_sample_blocks` = 32 blocks),
/// and every canonical block still in it is proven as `memory-history` proves them.
fn finish_budget(state: *Run) void {
    const id = @backingInt(VariantId.memory_history_budget);
    if (!state.case.preimages or state.failed[id] != null) return;
    const results = state.variants[id];
    budget_run(state) catch |err| {
        for (results) |*result| result.error_text = @errorName(err);
        return;
    };
    window_answers(state, &state.budget, results);
}

fn budget_run(state: *Run) !void {
    if (state.failed[@backingInt(VariantId.memory_history)] != null) return error.Unavailable;
    const measured = state.history.node orelse return error.Unavailable;
    const store = measured.db.history_reader() orelse return error.HistoryUnavailable;
    const base = db.history.reset_bytes_estimate(&measured.db.state.state_trie);
    const bytes_max = budget_bytes(base, store.bytes_used());
    const file = db_files[4];
    const path = try std.fs.path.join(state.arena, &.{ state.case.dir, file });
    state.budget.node = try Node.create_budget(state.allocator, path, bytes_max);
    const chunks = budget_chunks(state.case.blocks.len);
    var height: u64 = 0;
    for (state.case.blocks) |*block| {
        const node = state.budget.node.?;
        const parent = height - block.unwind;
        const native = try node.unwind_to(state.budget.heights[@intCast(parent)]);
        const ops = if (native) block.ops else try std.mem.concat(state.arena, Op, &.{
            block.revert,
            block.ops,
        });
        for (0..chunks) |chunk| {
            const start = chunk * ops.len / chunks;
            const end = (chunk + 1) * ops.len / chunks;
            try overlay_ops(node, ops[start..end]);
            try node.commit_overlay();
        }
        height = parent + 1;
        state.budget.heights[@intCast(height)] = node.height;
    }
    if (!codes_stored(&state.budget.node.?.db.state)) return;
    const node = state.budget.node.?;
    state.budget.node = null; // Gone even when the reopen fails.
    state.budget.node = try node.reopen(null);
}

/// The history byte budget of `memory-history-budget`: its state's (`reset`, estimated) with
/// half again for the estimate's error, and a third of the versions `memory-history`'s whole
/// window held beyond it.
fn budget_bytes(base: u64, used: u64) u64 {
    const versions = used -| base;
    const bytes = base + base / 2 + versions / 3;
    assert(bytes >= base);
    return @max(bytes, 1);
}

/// Blocks each request block is committed as: up to four, at most 200 in all (the chain
/// retains 256), so a request of nine blocks reaches the rebuild estimate's 32.
fn budget_chunks(blocks: usize) usize {
    assert(blocks <= trie_node.blocks_max);
    const chunks = std.math.clamp(200 / @max(blocks, 1), 1, 4);
    assert(chunks * blocks <= 200 or chunks == 1);
    return chunks;
}

/// Whether every account of the in-memory state has its code stored.
fn codes_stored(memory_state: *const db.State) bool {
    var accounts = memory_state.account_table.iterator();
    while (accounts.next()) |entry| {
        if (!memory_state.code_known(entry.value_ptr.info.code_hash)) return false;
    }
    return true;
}

/// Block `block` from the history window; null when it is no longer in it.
fn history_answer(state: *Run, history: *Disk, block: *const Block) !?BlockResult {
    const node = history.node.?;
    const number = history.heights[@intCast(block.number)];
    const store = node.db.history_reader() orelse {
        // Under a budget below the state itself the node keeps no history (`history_off`)
        // and serves the head alone, from the live trie; without one that is a fault.
        if (node.history_bytes_max == null) return error.HistoryUnavailable;
        if (number != node.db.head_info.number) return null;
        return .{
            .number = block.number,
            .state_root = node.state_root(),
            .proofs = try address_proofs(state, node, block, number),
        };
    };
    const root = store.state_root_at(number) catch |err| switch (err) {
        error.BlockOutOfWindow => return null,
        else => return err,
    };
    const proofs = try address_proofs(state, node, block, number);
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (try named_keys(state.arena, block)) |*key| {
        const account = try store.account_at(number, key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = account.storage_root });
    }
    return .{
        .number = block.number,
        .state_root = root,
        .storage_roots = roots.items,
        .proofs = proofs,
        .error_text = try proofs_at_check(state, node, block, number, proofs),
    };
}

/// Every proof target of the block again in one storage walk (`proofs_at`, eth_getProof's
/// many-slot path), against `proofs`. The first disagreement's description, or null.
fn proofs_at_check(
    state: *Run,
    node: *Node,
    block: *const Block,
    number: u64,
    proofs: []const ProofResult,
) !?[]const u8 {
    const allocator = state.allocator;
    var set = try db.history.ProofSet.init(allocator, trie_request.proof_slots_max);
    defer set.deinit(allocator);
    const account_proof = try allocator.create(trie_node.AccountProof);
    defer allocator.destroy(account_proof);
    const storage_proof = try allocator.create(trie_node.StorageProof);
    defer allocator.destroy(storage_proof);
    var slots: [trie_request.proof_slots_max]u256 = undefined;
    for (block.proofs, proofs) |*target, *single| {
        const count = target.slots.len;
        for (target.slot_keys.?, slots[0..count]) |*key, *slot| {
            slot.* = std.mem.readInt(u256, key, .big);
        }
        const address = target.address.?;
        const words = slots[0..count];
        const account = try node.db.proofs_at(number, address, words, account_proof, &set);
        if (!std.meta.eql(account, single.account)) return "proofs_at disagrees with proof_at";
        const nodes = try nodes_of(state.arena, account_proof);
        if (!nodes_equal(nodes, single.account_proof)) return "proofs_at disagrees with proof_at";
        for (single.storage, 0..) |*slot, index| {
            set.fill(@intCast(index), storage_proof);
            const slot_nodes = try nodes_of(state.arena, storage_proof);
            const value = set.value(@intCast(index));
            if (value != slot.value or !nodes_equal(slot_nodes, slot.proof)) {
                return "proofs_at disagrees with proof_at";
            }
        }
    }
    return null;
}

fn sparse_block(
    state: *Run,
    parent: u64,
    named: []const Hash,
    writes: db.overlay.HashedWrites,
) anyerror!BlockResult {
    const sparse = state.sparse orelse return error.Unavailable;
    var result: BlockResult = .{ .number = 0 };
    result.state_root = try sparse.block(parent, writes);
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const root = try sparse.storage_root(key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = root });
    }
    result.storage_roots = roots.items;
    return result;
}

fn state_trie_block(state: *Run, block: *const Block, named: []const Hash) anyerror!BlockResult {
    const variant = if (state.state_trie) |*variant| variant else return error.Unavailable;
    try variant.apply(block.revert);
    try variant.apply(block.ops);
    var result: BlockResult = .{ .number = 0 };
    result.state_root = try variant.root();
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const account = variant.account(key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = account.storage_root });
    }
    result.storage_roots = roots.items;
    result.proofs = try state_trie_proofs(state, variant, block);
    return result;
}

fn state_trie_proofs(
    state: *Run,
    variant: *trie_variants.StateTrieVariant,
    block: *const Block,
) anyerror![]const ProofResult {
    const proofs = try state.arena.alloc(ProofResult, block.proofs.len);
    const account_proof = try state.allocator.create(trie_node.AccountProof);
    defer state.allocator.destroy(account_proof);
    const storage_proofs = try state.allocator.alloc(
        trie_node.StorageProof,
        trie_request.proof_slots_max,
    );
    defer state.allocator.free(storage_proofs);
    const state_trie = &variant.state_trie;
    for (block.proofs, proofs) |*target, *out| {
        try state_trie.prove_account(target.key, account_proof);
        for (target.slots, storage_proofs[0..target.slots.len]) |slot, *proof| {
            state_trie.prove_storage(target.key, slot, proof);
        }
        const account = variant.account(&target.key);
        out.* = try proof_result(state.arena, target, account, account_proof, storage_proofs);
        for (out.storage) |*slot| slot.value = state_trie.get_storage(target.key, slot.slot);
    }
    return proofs;
}

fn hash_builder_block(state: *Run, named: []const Hash) anyerror!BlockResult {
    var result: BlockResult = .{ .number = 0 };
    result.state_root = try state.model.state_root();
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        if (state.model.find(key) == null) continue;
        try roots.append(state.arena, .{ .key = key.*, .root = try state.model.storage_root(key) });
    }
    result.storage_roots = roots.items;
    return result;
}

/// `node-address`: the block by address through an `Overlay` into the in-memory node
/// state; a native unwind, else the revert and the ops as one block.
fn address_block(
    state: *Run,
    block: *const Block,
    parent: u64,
    named: []const Hash,
) anyerror!BlockResult {
    const node = state.address_node orelse return error.Unavailable;
    const native = try node.unwind_to(state.address_heights[@intCast(parent)]);
    if (!native) try overlay_ops(node, block.revert);
    try overlay_ops(node, block.ops);
    try node.commit_overlay();
    state.address_heights[@intCast(parent + 1)] = node.height;
    var result: BlockResult = .{ .number = 0, .state_root = node.state_root() };
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const address = address_of(block, key).?;
        if (node.db.state.basic(address) == null) continue;
        const root = node.db.state.storage_root(address);
        try roots.append(state.arena, .{ .key = key.*, .root = root });
    }
    result.storage_roots = roots.items;
    result.proofs = try address_proofs(state, node, block, node.db.head_info.number);
    return result;
}

fn overlay_ops(node: *Node, ops: []const Op) anyerror!void {
    const overlay = &node.overlay;
    for (ops) |*op| {
        const address = op.address.?;
        switch (op.kind) {
            .account => {
                // An evm block stores the code it deploys (`Overlay.insert_code`).
                if (op.code) |code| _ = try overlay.insert_code(code);
                try overlay.set_account(address, op.info);
            },
            .storage => {
                const slot = std.mem.readInt(u256, &op.slot_key.?, .big);
                try overlay.set_storage(address, slot, op.value);
            },
            .wipe => if (overlay.basic(address) != null) try overlay.wipe_storage(address),
            .delete => if (overlay.basic(address) != null) try overlay.set_account(address, null),
        }
    }
}

/// The preimage of a key the block names (every op carries one on these requests).
fn address_of(block: *const Block, key: *const Hash) ?[20]u8 {
    for ([2][]const Op{ block.revert, block.ops }) |ops| {
        for (ops) |*op| if (std.mem.eql(u8, &op.key, key)) return op.address;
    }
    return null;
}

/// Proofs of the block's targets by address and slot key at block `number` (`proof_at`).
fn address_proofs(
    state: *Run,
    node: *Node,
    block: *const Block,
    number: u64,
) ![]const ProofResult {
    const proofs = try state.arena.alloc(ProofResult, block.proofs.len);
    const account_proof = try state.allocator.create(trie_node.AccountProof);
    defer state.allocator.destroy(account_proof);
    const storage_proofs = try state.allocator.alloc(
        trie_node.StorageProof,
        trie_request.proof_slots_max,
    );
    defer state.allocator.free(storage_proofs);
    var slots: [trie_request.proof_slots_max]u256 = undefined;
    var values: [trie_request.proof_slots_max]u256 = undefined;
    for (block.proofs, proofs) |*target, *out| {
        const count = target.slots.len;
        for (target.slot_keys.?, slots[0..count]) |*key, *slot| {
            slot.* = std.mem.readInt(u256, key, .big);
        }
        const account = try node.db.proof_at(
            number,
            target.address.?,
            slots[0..count],
            account_proof,
            storage_proofs[0..count],
            values[0..count],
        );
        out.* = try proof_result(state.arena, target, account, account_proof, storage_proofs);
        for (out.storage, values[0..count]) |*slot, value| slot.value = value;
        out.code = try code_of(state.arena, node, account);
    }
    node.db.codes_release();
    return proofs;
}

// The response.

pub fn write(
    out: *Writer,
    id: ?[]const u8,
    outcome: *const Outcome,
    coverage: ?*const Coverage,
) Writer.Error!void {
    try out.writeAll("{\"id\":");
    try response.write_string_or_null(out, id);
    try out.writeAll(",\"ok\":true,\"blocks\":[");
    for (outcome.blocks, 0..) |*result, index| {
        if (index > 0) try out.writeAll(",");
        try write_block(out, result);
    }
    try out.writeAll("],\"variants\":{");
    for (outcome.variants, 0..) |*variant, index| {
        if (index > 0) try out.writeAll(",");
        try std.json.Stringify.encodeJsonString(variant.name, .{}, out);
        try out.writeAll(":[");
        for (variant.blocks, 0..) |*result, block_index| {
            if (block_index > 0) try out.writeAll(",");
            try write_block(out, result);
        }
        try out.writeAll("]");
    }
    try out.writeAll("}");
    if (coverage) |features| try features.write_trie(out);
    try out.writeAll("}");
}

fn write_block(out: *Writer, result: *const BlockResult) Writer.Error!void {
    try out.writeAll("{\"number\":");
    try response.quantity(out, result.number);
    if (result.error_text) |text| {
        try out.writeAll(",\"error\":");
        try std.json.Stringify.encodeJsonString(text, .{}, out);
    }
    if (result.state_root) |root| {
        try out.writeAll(",\"stateRoot\":");
        try response.data(out, &root);
    }
    if (result.storage_roots) |roots| {
        try out.writeAll(",\"storageRoots\":{");
        for (roots, 0..) |*entry, index| {
            if (index > 0) try out.writeAll(",");
            try response.data(out, &entry.key);
            try out.writeAll(":");
            try response.data(out, &entry.root);
        }
        try out.writeAll("}");
    }
    if (result.proofs) |proofs| {
        try out.writeAll(",\"proofs\":[");
        for (proofs, 0..) |*proof, index| {
            if (index > 0) try out.writeAll(",");
            try write_proof(out, proof);
        }
        try out.writeAll("]");
    }
    try out.writeAll("}");
}

fn write_proof(out: *Writer, proof: *const ProofResult) Writer.Error!void {
    try out.writeAll("{\"key\":");
    try response.data(out, &proof.key);
    try out.writeAll(",\"account\":");
    if (proof.account) |account| {
        try out.writeAll("{\"nonce\":");
        try response.quantity(out, account.nonce);
        try out.writeAll(",\"balance\":");
        try response.quantity(out, account.balance);
        try out.writeAll(",\"codeHash\":");
        try response.data(out, &account.code_hash);
        try out.writeAll(",\"storageRoot\":");
        try response.data(out, &account.storage_root);
        try out.writeAll("}");
    } else try out.writeAll("null");
    if (proof.code) |code| {
        try out.writeAll(",\"code\":");
        try response.data(out, code);
    }
    try out.writeAll(",\"accountProof\":");
    try write_nodes(out, proof.account_proof);
    try out.writeAll(",\"storage\":[");
    for (proof.storage, 0..) |*slot, index| {
        if (index > 0) try out.writeAll(",");
        var value: Hash = undefined;
        std.mem.writeInt(u256, &value, slot.value, .big);
        try out.writeAll("{\"slot\":");
        try response.data(out, &slot.slot);
        try out.writeAll(",\"value\":");
        try response.data(out, &value);
        try out.writeAll(",\"proof\":");
        try write_nodes(out, slot.proof);
        try out.writeAll("}");
    }
    try out.writeAll("]}");
}

fn write_nodes(out: *Writer, nodes: []const []const u8) Writer.Error!void {
    try out.writeAll("[");
    for (nodes, 0..) |item, index| {
        if (index > 0) try out.writeAll(",");
        try response.data(out, item);
    }
    try out.writeAll("]");
}

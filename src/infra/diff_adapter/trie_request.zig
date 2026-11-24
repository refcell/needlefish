//! Differential trie protocol (`trie` mode, base/base `TRIE_PROTOCOL.md`): the request's
//! `trie` object and its decoding into a `Case`.
//!
//! Keys and slots are 32-byte trie keys (already hashed). On some requests every op and
//! proof target also carries its preimages (`address`, `slotKey`, `slotKeys`). Every
//! preimage present must hash to its key (else the request is refused, `PreimageMismatch`);
//! only the address-keyed variants use them, and only when every op and target has them
//! (`Case.preimages`). An account op may carry the code it sets (`code`, hashing to its
//! `codeHash`, else `CodeMismatch`; at most the evm's deployed code limit, EIP-170; a request
//! at most `trie_node.request_codes_max` distinct codes of `request_code_bytes_max` bytes).

const std = @import("std");
const assert = std.debug.assert;

const request = @import("request.zig");
const keccak256 = @import("../../execution/trie/root.zig").node.keccak256;
const AccountInfo = @import("../../execution/db/root.zig").AccountInfo;
const trie_node = @import("trie_node.zig");

const Hash = [32]u8;
const Address = [20]u8;
const Error = request.Error;

/// Ops per block (with its revert), proof targets per block, slots per proof target.
pub const ops_max = trie_node.changeset_config.accounts_max;
pub const proofs_max = 256;
pub const proof_slots_max = 64;
/// The evm's deployed code limit (EIP-170): the longest code a block can store.
pub const code_size_max = 24_576;

pub const RawOp = struct {
    op: []const u8 = "",
    key: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
    balance: ?[]const u8 = null,
    codeHash: ?[]const u8 = null,
    slot: ?[]const u8 = null,
    value: ?[]const u8 = null,
    address: ?[]const u8 = null,
    slotKey: ?[]const u8 = null,
    code: ?[]const u8 = null,
};

pub const RawProof = struct {
    key: ?[]const u8 = null,
    slots: []const []const u8 = &.{},
    address: ?[]const u8 = null,
    slotKeys: ?[]const []const u8 = null,
};

pub const RawBlock = struct {
    number: ?[]const u8 = null,
    unwind: u32 = 0,
    revert: ?[]const RawOp = null,
    ops: []const RawOp = &.{},
    proofs: []const RawProof = &.{},
};

pub const RawTrie = struct {
    dir: ?[]const u8 = null,
    blocks: []const RawBlock = &.{},
};

pub const Kind = enum { account, storage, wipe, delete };

pub const Op = struct {
    kind: Kind,
    key: Hash,
    /// `account`.
    info: AccountInfo = .{},
    /// `storage`: the slot's trie key and its word.
    slot: Hash = @splat(0),
    value: u256 = 0,
    /// Preimages, when the request carries them.
    address: ?Address = null,
    slot_key: ?Hash = null,
    /// `account`: the code it sets, when the request carries it (nonempty).
    code: ?[]const u8 = null,
};

pub const Proof = struct {
    key: Hash,
    slots: []const Hash,
    address: ?Address = null,
    slot_keys: ?[]const Hash = null,
};

pub const Block = struct {
    number: u64,
    unwind: u32,
    /// Empty when the request omits it.
    revert: []const Op,
    ops: []const Op,
    proofs: []const Proof,
};

pub const Case = struct {
    dir: []const u8,
    blocks: []const Block,
    /// Every op and proof target carries its preimages (each hashing to its key).
    preimages: bool,
};

pub fn decode(arena: std.mem.Allocator, raw: *const RawTrie) Error!Case {
    const dir = raw.dir orelse return error.MissingField;
    if (dir.len == 0) return error.InvalidField;
    if (raw.blocks.len > trie_node.blocks_max) return error.InvalidField;
    const blocks = try arena.alloc(Block, raw.blocks.len);
    var applied: u64 = 0;
    for (raw.blocks, blocks) |*raw_block, *block| {
        block.* = try decode_block(arena, raw_block);
        // At most the blocks applied so far (the height before this block).
        if (block.unwind > applied) return error.InvalidField;
        applied = applied - block.unwind + 1;
    }
    var case: Case = .{ .dir = dir, .blocks = blocks, .preimages = false };
    try check_codes(arena, &case);
    case.preimages = try check_preimages(&case);
    assert(case.blocks.len == raw.blocks.len);
    return case;
}

fn decode_block(arena: std.mem.Allocator, raw: *const RawBlock) Error!Block {
    const revert = raw.revert orelse &.{};
    if (raw.unwind == 0 and revert.len > 0) return error.InvalidField;
    if (raw.ops.len + revert.len > ops_max) return error.InvalidField;
    if (raw.proofs.len > proofs_max) return error.InvalidField;
    const proofs = try arena.alloc(Proof, raw.proofs.len);
    for (raw.proofs, proofs) |*raw_proof, *proof| proof.* = try decode_proof(arena, raw_proof);
    const block: Block = .{
        .number = try request.quantity(u64, raw.number orelse return error.MissingField),
        .unwind = raw.unwind,
        .revert = try decode_ops(arena, revert),
        .ops = try decode_ops(arena, raw.ops),
        .proofs = proofs,
    };
    assert(block.ops.len == raw.ops.len);
    return block;
}

fn decode_ops(arena: std.mem.Allocator, raws: []const RawOp) Error![]const Op {
    const ops = try arena.alloc(Op, raws.len);
    for (raws, ops) |*raw, *op| op.* = try decode_op(arena, raw);
    return ops;
}

fn decode_op(arena: std.mem.Allocator, raw: *const RawOp) Error!Op {
    const kind = std.meta.stringToEnum(Kind, raw.op) orelse return error.InvalidField;
    var op: Op = .{ .kind = kind, .key = try request.fixed(32, required(raw.key)) };
    if (raw.address) |text| op.address = try request.fixed(20, text);
    switch (kind) {
        .account => op.info = .{
            .nonce = try request.quantity(u64, required(raw.nonce)),
            .balance = try request.quantity(u256, required(raw.balance)),
            .code_hash = try request.fixed(32, required(raw.codeHash)),
        },
        .storage => {
            op.slot = try request.fixed(32, required(raw.slot));
            const value = try request.fixed(32, required(raw.value));
            op.value = std.mem.readInt(u256, &value, .big);
            if (raw.slotKey) |text| op.slot_key = try request.fixed(32, text);
        },
        .wipe, .delete => {},
    }
    if (kind == .account) if (raw.code) |text| {
        const code = try request.bytes(arena, text);
        if (code.len > code_size_max) return error.InvalidField;
        if (!hashes_to(code, &op.info.code_hash)) return error.CodeMismatch;
        // The empty code is no code to store (its hash is the empty code hash).
        if (code.len > 0) op.code = code;
    };
    return op;
}

fn decode_proof(arena: std.mem.Allocator, raw: *const RawProof) Error!Proof {
    if (raw.slots.len > proof_slots_max) return error.InvalidField;
    const slots = try arena.alloc(Hash, raw.slots.len);
    for (raw.slots, slots) |text, *slot| slot.* = try request.fixed(32, text);
    var proof: Proof = .{ .key = try request.fixed(32, required(raw.key)), .slots = slots };
    if (raw.address) |text| proof.address = try request.fixed(20, text);
    if (raw.slotKeys) |texts| {
        if (texts.len != raw.slots.len) return error.InvalidField;
        const keys = try arena.alloc(Hash, texts.len);
        for (texts, keys) |text, *key| key.* = try request.fixed(32, text);
        proof.slot_keys = keys;
    }
    return proof;
}

/// The request's distinct codes fit what every database keeps (`trie_node.request_codes_max`
/// codes, `request_code_bytes_max` bytes); `InvalidField` otherwise.
fn check_codes(arena: std.mem.Allocator, case: *const Case) Error!void {
    var codes: std.AutoArrayHashMapUnmanaged(Hash, void) = .empty;
    var bytes: u64 = 0;
    for (case.blocks) |*block| {
        for ([2][]const Op{ block.revert, block.ops }) |ops| {
            for (ops) |*op| {
                const code = op.code orelse continue;
                const entry = try codes.getOrPut(arena, op.info.code_hash);
                if (!entry.found_existing) bytes += code.len;
            }
        }
    }
    if (codes.count() > trie_node.request_codes_max) return error.InvalidField;
    if (bytes > trie_node.request_code_bytes_max) return error.InvalidField;
}

fn required(field: ?[]const u8) Error![]const u8 {
    return field orelse error.MissingField;
}

/// Whether every op and proof target carries its preimages; `PreimageMismatch` when one
/// present does not hash to its key.
fn check_preimages(case: *const Case) Error!bool {
    var complete = true;
    for (case.blocks) |*block| {
        for ([2][]const Op{ block.revert, block.ops }) |ops| {
            for (ops) |*op| {
                complete = try check(op.address, &op.key) and complete;
                if (op.kind == .storage) complete = try check(op.slot_key, &op.slot) and complete;
            }
        }
        for (block.proofs) |*proof| {
            complete = try check(proof.address, &proof.key) and complete;
            const slot_keys = proof.slot_keys orelse {
                complete = false;
                continue;
            };
            assert(slot_keys.len == proof.slots.len);
            for (slot_keys, proof.slots) |*slot_key, *slot| {
                _ = try check(@as(?Hash, slot_key.*), slot);
            }
        }
    }
    return complete;
}

/// False when the preimage is absent; `PreimageMismatch` when it does not hash to `key`.
fn check(preimage: anytype, key: *const Hash) Error!bool {
    const value = preimage orelse return false;
    if (!hashes_to(&value, key)) return error.PreimageMismatch;
    return true;
}

fn hashes_to(preimage: []const u8, key: *const Hash) bool {
    return std.mem.eql(u8, &keccak256(preimage), key);
}

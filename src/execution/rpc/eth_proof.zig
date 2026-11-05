//! `eth_getProof` (EIP-1186): the account's Merkle proof against the head state root,
//! plus one proof per requested storage slot against the account's storage root. Only
//! the head state is held in memory, so other blocks are refused like every state call,
//! except on a durable node whose database keeps a history window: then any canonical
//! block of that window is served from it (`Journal.proof`, `Database.proof_at`).
//! Proof buffers are carved from the API's bounded scratch, not the stack.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const state_trie = @import("../trie/state_trie.zig");
const trie = @import("../trie/root.zig");
const db_database = @import("../db/database.zig");
const db_history = @import("../db/history.zig");
const eth = @import("eth.zig");

const Hash = [32]u8;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const AccountProof = state_trie.StateTrie.AccountProof;
const StorageProof = state_trie.StateTrie.StorageProof;

/// Upper bound on storage keys per request (each proof is serialised in the response).
pub const storage_keys_max = 256;

const Scratch = struct {
    account: AccountProof,
    storage: StorageProof,
};

pub fn get_proof(api: *eth.Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    var keys: [storage_keys_max]Hash = undefined;
    const keys_count = try parse_keys(try call.params.raw(), &keys);
    const tag = try call.params.optional_raw();
    if (try historical_block(api, call, tag)) |block| {
        try call.params.finish();
        return get_proof_at(api, call, address, keys[0..keys_count], block);
    }
    try eth.require_head_state(api, call, tag);
    try call.params.finish();
    const scratch = scratch_of(api) orelse {
        return call.fail(rpc.code.internal_error, "proof scratch too small");
    };
    const db = api.chain.db;
    const address_hash = primitives.keccak256(&address).bytes;
    db.trie().prove_account(address_hash, &scratch.account) catch {
        return call.fail(rpc.code.internal_error, "state unavailable");
    };
    const account = db.get_account(address) orelse state_trie.Account{};
    const w = call.writer;
    try write_account(w, &address, &scratch.account, .{
        .nonce = account.nonce,
        .balance = account.balance,
        .storage_root = db.trie().storage_root(address_hash),
        .code_hash = account.code_hash,
    });
    try w.begin_array();
    for (keys[0..keys_count]) |slot| {
        db.trie().prove_storage(address_hash, primitives.keccak256(&slot).bytes, &scratch.storage);
        const value = db.get_storage(address, std.mem.readInt(u256, &slot, .big));
        try write_slot(w, &slot, value, &scratch.storage);
    }
    try w.end_array();
    try w.end_object();
}

/// An older block (hash and number) when the journal serves historical proofs
/// (durable node with history); null for the head (or no tag), so the head path (and
/// its "historical state unavailable" error for other blocks) applies.
fn historical_block(api: *eth.Api, call: *Call, tag: ?[]const u8) HandlerError!?Block {
    const text = tag orelse return null;
    const journal = api.chain.journal orelse return null;
    if (journal.proof == null) return null;
    // History follows the database head, which the head state keeps at the chain head.
    api.chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const hash = try eth.resolve_block(api, call, text);
    if (std.mem.eql(u8, &hash, &api.chain.head_hash())) return null;
    const header = api.chain.header(hash) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
    // The journal checks that `hash` is canonical in its own index (side blocks fail).
    return .{ .hash = hash, .number = header.number };
}

const Block = struct { hash: Hash, number: u64 };

/// `eth_getProof` at an older canonical block from the journal's history window.
fn get_proof_at(
    api: *eth.Api,
    call: *Call,
    address: [20]u8,
    keys: []const Hash,
    block: Block,
) HandlerError!void {
    assert(keys.len <= storage_keys_max);
    const journal = api.chain.journal.?;
    const proof = journal.proof.?;
    const scratch = scratch_of(api) orelse {
        return call.fail(rpc.code.internal_error, "proof scratch too small");
    };
    const context = journal.context;
    const hash = block.hash;
    const number = block.number;
    const found = proof(context, hash, number, address, &.{}, &scratch.account, &.{}, &.{});
    const account = found catch |err| return fail_history(call, err);
    const w = call.writer;
    try write_account(w, &address, &scratch.account, account orelse .{
        .nonce = 0,
        .balance = 0,
        .storage_root = trie.empty_root,
        .code_hash = (state_trie.Account{}).code_hash,
    });
    try w.begin_array();
    for (keys) |*slot| {
        const slots = [1]u256{std.mem.readInt(u256, slot, .big)};
        var values: [1]u256 = undefined;
        // One slot per call; the account proof it refills was already written.
        const proofs: *[1]StorageProof = (&scratch.storage)[0..1];
        const account_proof = &scratch.account;
        const result =
            proof(context, hash, number, address, &slots, account_proof, proofs, &values);
        _ = result catch |err| return fail_history(call, err);
        try write_slot(w, slot, values[0], &proofs[0]);
    }
    try w.end_array();
    try w.end_object();
}

fn fail_history(call: *Call, err: db_database.ProofError) HandlerError {
    return switch (err) {
        error.BlockOutOfWindow, error.HistoryUnavailable, error.NotInitialized => {
            return call.fail(rpc.code.server_error, "historical state unavailable");
        },
        else => call.fail(rpc.code.internal_error, "historical state corrupt"),
    };
}

/// The account fields; leaves the `storageProof` key open for the slot array.
fn write_account(
    w: *json.Writer,
    address: *const [20]u8,
    proof: *const AccountProof,
    account: db_history.AccountState,
) json.Writer.WriteError!void {
    try w.begin_object();
    try w.key("address");
    try w.data(address);
    try w.key("accountProof");
    try write_proof(w, proof);
    try w.key("balance");
    try w.quantity(account.balance);
    try w.key("codeHash");
    try w.data(&account.code_hash);
    try w.key("nonce");
    try w.quantity(account.nonce);
    try w.key("storageHash");
    try w.data(&account.storage_root);
    try w.key("storageProof");
}

fn write_slot(
    w: *json.Writer,
    slot: *const Hash,
    value: u256,
    proof: *const StorageProof,
) json.Writer.WriteError!void {
    try w.begin_object();
    try w.key("key");
    try w.data(slot);
    try w.key("value");
    try w.quantity(value);
    try w.key("proof");
    try write_proof(w, proof);
    try w.end_object();
}

fn write_proof(w: *json.Writer, proof: anytype) json.Writer.WriteError!void {
    assert(proof.count <= proof.ends.len);
    try w.begin_array();
    for (0..proof.count) |index| try w.data(proof.node_at(@intCast(index)));
    try w.end_array();
}

/// The proof buffers inside `api.scratch`, aligned; null when the scratch is too small.
fn scratch_of(api: *eth.Api) ?*Scratch {
    const base = @intFromPtr(api.scratch.ptr);
    const offset = std.mem.alignForward(usize, base, @alignOf(Scratch)) - base;
    if (api.scratch.len < offset + @sizeOf(Scratch)) return null;
    const result: *Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
    assert(@intFromPtr(result) % @alignOf(Scratch) == 0);
    return result;
}

/// Storage keys: a JSON array of hex strings of up to 32 bytes (left-padded), as geth.
fn parse_keys(raw: []const u8, out: *[storage_keys_max]Hash) HandlerError!u32 {
    var scanner = json.Scanner.init(raw);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (true) {
        const token = scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) break;
        if (token.tag != .string or token.escaped) return error.InvalidParams;
        if (count == storage_keys_max) return error.InvalidParams;
        out[count] = parse_key(token.bytes) orelse return error.InvalidParams;
        count += 1;
    }
    assert(count <= storage_keys_max);
    return count;
}

fn parse_key(text: []const u8) ?Hash {
    var key: Hash = @splat(0);
    var buffer: [32]u8 = undefined;
    if (json.parse_data(text, &buffer)) |bytes| {
        @memcpy(key[32 - bytes.len ..], bytes);
        return key;
    } else |_| {}
    // Odd-length or minimal hex: read it as a number.
    const value = json.parse_quantity(u256, text) catch return null;
    std.mem.writeInt(u256, &key, value, .big);
    return key;
}

comptime {
    assert(@sizeOf(Scratch) < 1 << 20);
    assert(@alignOf(Scratch) <= 16);
}

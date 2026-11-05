//! `eth_getProof` (EIP-1186): the account's Merkle proof against the head state root,
//! plus one proof per requested storage slot against the account's storage root. Only
//! the head state is held in memory, so other blocks are refused like every state call.
//! Proof buffers are carved from the API's bounded scratch, not the stack.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const state_trie = @import("../trie/state_trie.zig");
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
    try eth.require_head_state(api, call, try call.params.optional_raw());
    try call.params.finish();
    const scratch = scratch_of(api) orelse {
        return call.fail(rpc.code.internal_error, "proof scratch too small");
    };
    const db = api.chain.db;
    const address_hash = primitives.keccak256(&address).bytes;
    db.trie.prove_account(address_hash, &scratch.account) catch {
        return call.fail(rpc.code.internal_error, "state unavailable");
    };
    const account = db.get_account(address) orelse state_trie.Account{};
    const w = call.writer;
    try w.begin_object();
    try w.key("address");
    try w.data(&address);
    try w.key("accountProof");
    try write_proof(w, &scratch.account);
    try w.key("balance");
    try w.quantity(account.balance);
    try w.key("codeHash");
    try w.data(&account.code_hash);
    try w.key("nonce");
    try w.quantity(account.nonce);
    try w.key("storageHash");
    try w.data(&db.trie.storage_root(address_hash));
    try w.key("storageProof");
    try w.begin_array();
    for (keys[0..keys_count]) |slot| {
        db.trie.prove_storage(address_hash, primitives.keccak256(&slot).bytes, &scratch.storage);
        try w.begin_object();
        try w.key("key");
        try w.data(&slot);
        try w.key("value");
        try w.quantity(db.get_storage(address, std.mem.readInt(u256, &slot, .big)));
        try w.key("proof");
        try write_proof(w, &scratch.storage);
        try w.end_object();
    }
    try w.end_array();
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

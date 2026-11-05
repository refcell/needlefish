//! The host's hint handler. Port of base/base `crates/proof/host/src/handler.rs`: each
//! typed hint makes the host fetch data from a chain `Source` and store the preimages
//! the program will read next.
//!
//! - `l1-block-header` / `l2-block-header <hash>`: the RLP header as keccak preimage,
//! - `l1-transactions` / `l2-transactions` / `l1-receipts <hash>`: the ordered trie nodes,
//! - `l1-blob <hash ++ timestamp>`: the commitment (sha256 key) and the 4096 field elements
//!   (blob keys `keccak256(commitment ++ root_i)`),
//! - `l2-code` / `l2-state-node <hash>`: the keccak preimage,
//! - `l2-payload-witness <parent ++ attributes JSON>`: every witness byte string.
//!
//! Hints the program does not send (precompile, proofs, starting output) are rejected.
//! Data the source returns is checked against the requested hash before storing.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const program = @import("../program/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const crypto = @import("../../common/crypto/root.zig");
const store_module = @import("store.zig");

const Hash = [32]u8;
const HintType = program.HintType;
const Store = store_module.Store;

pub const Chain = enum { l1, l2 };

pub const SourceError = error{ NotFound, SourceFailed };

pub const Blob = struct {
    blob: *const [kzg.bytes_per_blob]u8,
    commitment: [kzg.bytes_per_commitment]u8,
};

/// Where the host gets chain data. Returned slices are valid until the next call.
pub const Source = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        raw_header: *const fn (
            context: *anyopaque,
            chain: Chain,
            hash: Hash,
        ) SourceError![]const u8,
        /// Raw EIP-2718 transactions of block `hash`.
        transactions: *const fn (
            context: *anyopaque,
            chain: Chain,
            hash: Hash,
        ) SourceError![]const []const u8,
        /// Raw EIP-2718 receipts of L1 block `hash`.
        receipts: *const fn (context: *anyopaque, hash: Hash) SourceError![]const []const u8,
        blob: *const fn (context: *anyopaque, hash: Hash, timestamp: u64) SourceError!Blob,
        /// L2 bytecode or state trie node by keccak hash.
        preimage: *const fn (context: *anyopaque, hash: Hash) SourceError![]const u8,
        /// The execution witness byte strings (state nodes, codes, keys) of building the
        /// child of `parent_hash` from `attributes_json`.
        payload_witness: *const fn (
            context: *anyopaque,
            parent_hash: Hash,
            attributes_json: []const u8,
        ) SourceError![]const []const u8,
    };
};

pub const Handler = struct {
    store: *Store,
    source: Source,
    /// Roots of unity in bit-reversal order, for blob field-element keys.
    roots_brp: ?*const [kzg.field_elements_per_blob][32]u8 = null,
    data_buffer: [preimage.hint.hint_size_max / 2]u8 = undefined,
    /// The last failure, for diagnostics.
    last_error: ?anyerror = null,
    /// Digests of hints already served: the store is immutable, so serving one again
    /// cannot add anything (the program re-sends hints before reads). A direct-mapped
    /// table: a collision only costs a redundant fetch.
    served: [served_slots]Hash = @splat(@splat(0)),
    /// Hints answered from `served` without touching the source.
    hints_skipped: u64 = 0,

    pub const served_slots = 4096;

    pub fn router(handler: *Handler) preimage.Router {
        return .{ .context = handler, .route_hint = route_hint };
    }

    fn route_hint(context: *anyopaque, text: []const u8) preimage.hint.RouteError!void {
        const handler: *Handler = @ptrCast(@alignCast(context));
        const hint = preimage.Hint.parse(text, &handler.data_buffer) catch
            return error.HintRejected;
        const hint_type = HintType.from_name(hint.type_name) orelse return error.HintRejected;
        const digest = crypto.keccak256(text);
        const slot = &handler.served[std.mem.readInt(u16, digest[0..2], .little) % served_slots];
        if (std.mem.eql(u8, slot, &digest)) {
            handler.hints_skipped += 1;
            return;
        }
        handler.handle(hint_type, hint.data) catch |err| {
            handler.last_error = err;
            return switch (err) {
                error.InvalidHintData, error.UnsupportedHint => error.HintRejected,
                else => error.HintFailed,
            };
        };
        // Only a fully served hint is remembered; a failed one is retried next time.
        slot.* = digest;
    }

    pub const Error = store_module.Error || SourceError || error{
        InvalidHintData,
        UnsupportedHint,
        HashMismatch,
        MissingRoots,
    };

    pub fn handle(handler: *Handler, hint_type: HintType, data: []const u8) Error!void {
        const vtable = handler.source.vtable;
        const context = handler.source.context;
        switch (hint_type) {
            .l1_block_header, .l2_block_header => {
                const chain: Chain = if (hint_type == .l1_block_header) .l1 else .l2;
                const hash = try hash_of(data);
                try handler.put_checked(hash, try vtable.raw_header(context, chain, hash));
            },
            .l1_transactions, .l2_transactions => {
                const chain: Chain = if (hint_type == .l1_transactions) .l1 else .l2;
                const hash = try hash_of(data);
                const items = try vtable.transactions(context, chain, hash);
                _ = try handler.store.put_ordered_list(items);
            },
            .l1_receipts => {
                const items = try vtable.receipts(context, try hash_of(data));
                _ = try handler.store.put_ordered_list(items);
            },
            .l1_blob => try handler.handle_blob(data),
            .l2_code, .l2_state_node => {
                const hash = try hash_of(data);
                try handler.put_checked(hash, try vtable.preimage(context, hash));
            },
            .l2_payload_witness => {
                if (data.len <= 32) return error.InvalidHintData;
                const items = try vtable.payload_witness(context, data[0..32].*, data[32..]);
                for (items) |item| _ = try handler.store.put_keccak(item);
            },
            .l1_precompile,
            .starting_l2_output,
            .l2_account_proof,
            .l2_account_storage_proof,
            => return error.UnsupportedHint,
        }
    }

    fn put_checked(handler: *Handler, hash: Hash, bytes: []const u8) Error!void {
        if (!std.mem.eql(u8, &keccak.keccak256(bytes), &hash)) return error.HashMismatch;
        const stored = try handler.store.put_keccak(bytes);
        assert(std.mem.eql(u8, &stored, &hash));
    }

    fn handle_blob(handler: *Handler, data: []const u8) Error!void {
        if (data.len != 40) return error.InvalidHintData;
        const roots = handler.roots_brp orelse return error.MissingRoots;
        const hash: Hash = data[0..32].*;
        const timestamp = std.mem.readInt(u64, data[32..40], .big);
        const blob = try handler.source.vtable.blob(handler.source.context, hash, timestamp);
        if (!std.mem.eql(u8, &kzg.versioned_hash(&blob.commitment), &hash)) {
            return error.HashMismatch;
        }
        try handler.store.put(.sha256(hash), &blob.commitment);
        var key_input: [kzg.bytes_per_commitment + 32]u8 = undefined;
        key_input[0..kzg.bytes_per_commitment].* = blob.commitment;
        const element_bytes = kzg.bytes_per_field_element;
        for (roots, 0..) |root, index| {
            key_input[kzg.bytes_per_commitment..].* = root;
            const key: preimage.Key = .init(keccak.keccak256(&key_input), .blob);
            try handler.store.put(key, blob.blob[index * element_bytes ..][0..element_bytes]);
        }
    }
};

fn hash_of(data: []const u8) Handler.Error!Hash {
    if (data.len != 32) return error.InvalidHintData;
    return data[0..32].*;
}

/// Fills `out` with the 32-byte big-endian roots of unity in bit-reversal order.
pub fn fill_roots(out: *[kzg.field_elements_per_blob][32]u8) void {
    var roots: [kzg.field_elements_per_blob]@import("../../common/crypto/bls12_381/root.zig").Fr =
        undefined;
    kzg.blob.fill_roots_brp(&roots);
    for (out, roots) |*bytes, root| bytes.* = root.to_bytes_be();
}

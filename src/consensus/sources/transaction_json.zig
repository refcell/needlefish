//! Decodes full transaction objects from an `eth_getBlockByHash(hash, true)` result into the
//! derivation view (`L1Transaction`), rebuilding the signed EIP-2718 envelope so that:
//! - the sender is recovered from the signature instead of trusting the RPC `from`
//!   (a mismatch with the reported `from` rejects the block),
//! - the envelope hashes to the reported transaction `hash`, and
//! - optionally the transactions trie root matches the (hash-verified) header, which binds
//!   every transaction to the block hash.
//! Mirrors base/base `AlloyChainProvider::block_info_and_transactions_by_hash`, which
//! decodes `TxEnvelope`s and recovers senders in the data sources.
//!
//! Types 0-4 and the OP deposit (0x7e: `sourceHash`, `from`, `to`, `mint`, `value`, `gas`,
//! `isSystemTx`, `input`) are rebuilt; a deposit's `from` is bound by its hash instead of a
//! signature. Other types are kept with the RPC `from` (the data sources ignore them) and
//! make root verification impossible, so strict mode rejects them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const object = @import("json_object.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const ordered = @import("../../execution/trie/ordered.zig");
const providers = @import("../derive/providers.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = consensus.Envelope;
const Signature = consensus.Signature;
const AccessList = consensus.AccessList;
const AuthorizationList = consensus.AuthorizationList;
const Authorization = consensus.Authorization;
const HashList = consensus.HashList;
const L1Transaction = providers.L1Transaction;

pub const Error = object.Error || error{
    InvalidSignature,
    SenderMismatch,
    HashMismatch,
    RootMismatch,
    UnsupportedTransaction,
};

pub const Limits = struct {
    transactions_max: u32 = 8192,
    input_size_max: u32 = 8 * 1024 * 1024,
    blob_hashes_max: u32 = 128,
    access_list_items_max: u32 = 16 * 1024,
    storage_keys_max: u32 = 64 * 1024,
    authorizations_max: u32 = 4096,
};

pub const Options = struct {
    limits: Limits = .{},
    /// Recover senders only for transactions to this address (the batch inbox); others
    /// keep the RPC `from`, which the data sources never use. Null recovers every sender.
    recover_to: ?Address = null,
    /// Verify the transactions root against the header (rejects unknown types).
    verify_root: bool = true,
    /// Recover senders at all. Off for L2 blocks, whose hash and root checks already bind
    /// every transaction and whose senders consolidation never reads.
    recover_senders: bool = true,
};

const Key = enum(u5) {
    tx_type,
    nonce,
    gas,
    gas_price,
    max_fee_per_gas,
    max_priority_fee_per_gas,
    max_fee_per_blob_gas,
    to,
    value,
    input,
    chain_id,
    access_list,
    blob_versioned_hashes,
    authorization_list,
    v,
    r,
    s,
    y_parity,
    from,
    hash,
    source_hash,
    mint,
    is_system_tx,
};

const keys = std.StaticStringMap(Key).initComptime(.{
    .{ "type", .tx_type },
    .{ "nonce", .nonce },
    .{ "gas", .gas },
    .{ "gasPrice", .gas_price },
    .{ "maxFeePerGas", .max_fee_per_gas },
    .{ "maxPriorityFeePerGas", .max_priority_fee_per_gas },
    .{ "maxFeePerBlobGas", .max_fee_per_blob_gas },
    .{ "to", .to },
    .{ "value", .value },
    .{ "input", .input },
    .{ "chainId", .chain_id },
    .{ "accessList", .access_list },
    .{ "blobVersionedHashes", .blob_versioned_hashes },
    .{ "authorizationList", .authorization_list },
    .{ "v", .v },
    .{ "r", .r },
    .{ "s", .s },
    .{ "yParity", .y_parity },
    .{ "from", .from },
    .{ "hash", .hash },
    .{ "sourceHash", .source_hash },
    .{ "mint", .mint },
    .{ "isSystemTx", .is_system_tx },
});

const Seen = object.Seen(@typeInfo(Key).@"enum".field_names.len);

fn mask(comptime list: []const Key) u64 {
    var result: u64 = 0;
    inline for (list) |key| result |= @as(u64, 1) << @backingInt(key);
    return result;
}

const mask_common = mask(&.{ .nonce, .gas, .value, .input, .r, .s, .from, .hash });
const mask_legacy = mask_common | mask(&.{ .gas_price, .v });
const mask_eip2930 = mask_common | mask(&.{ .gas_price, .chain_id, .access_list });
const mask_eip1559 = mask_common |
    mask(&.{ .max_fee_per_gas, .max_priority_fee_per_gas, .chain_id, .access_list });
const mask_eip4844 = mask_eip1559 | mask(&.{ .max_fee_per_blob_gas, .blob_versioned_hashes });
const mask_eip7702 = mask_eip1559 | mask(&.{.authorization_list});
/// `to` (absent for creations), `mint`, and `isSystemTx` default like op-alloy's serde.
const mask_deposit = mask(&.{ .source_hash, .from, .gas, .value, .input, .hash });

/// The decoded fields of one transaction object. Lists stay raw until the type is known.
const Fields = struct {
    seen: Seen = .{},
    tx_type: u8 = 0,
    nonce: u64 = 0,
    gas: u64 = 0,
    gas_price: u128 = 0,
    max_fee_per_gas: u128 = 0,
    max_priority_fee_per_gas: u128 = 0,
    max_fee_per_blob_gas: u128 = 0,
    to: ?Address = null,
    value: u256 = 0,
    input: []const u8 = &.{},
    chain_id: u64 = 0,
    access_list: []const u8 = "[]",
    blob_hashes: []const B256 = &.{},
    authorization_list: []const u8 = "[]",
    v: u256 = 0,
    r: u256 = 0,
    s: u256 = 0,
    y_parity: u64 = 0,
    from: Address = .zero,
    hash: B256 = .zero,
    source_hash: B256 = .zero,
    mint: u128 = 0,
    is_system_tx: bool = false,
};

pub const Decoded = struct {
    transaction: L1Transaction,
    /// Null for types this decoder does not rebuild.
    envelope: ?Envelope,
};

/// Decodes one transaction object. Inputs and blob hashes are allocated from `allocator`
/// (they back the returned `L1Transaction`); envelope lists come from `scratch`.
pub fn decode(
    allocator: Allocator,
    scratch: Allocator,
    raw: []const u8,
    options: Options,
) Error!Decoded {
    var fields: Fields = .{};
    var iterator = try object.ObjectIterator.init(raw);
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        const key = keys.get(field.key) orelse continue;
        try fields.seen.see(@backingInt(key));
        try apply(allocator, &fields, key, field, options.limits);
    }
    const envelope = try build_envelope(scratch, &fields, options.limits);
    var transaction: L1Transaction = .{
        .tx_type = fields.tx_type,
        .to = fields.to,
        .from = fields.from,
        .input = fields.input,
        .blob_hashes = fields.blob_hashes,
    };
    if (envelope) |built| {
        if (!built.hash().eql(fields.hash)) return error.HashMismatch;
        const recover_selected = if (options.recover_to) |target|
            fields.to != null and fields.to.?.eql(target)
        else
            true;
        const recover = options.recover_senders and recover_selected and !built.is_deposit();
        if (recover) transaction.from = try recover_sender(built, fields.from);
    } else {
        try fields.seen.require(mask(&.{ .from, .input }));
    }
    assert(transaction.tx_type == fields.tx_type);
    return .{ .transaction = transaction, .envelope = envelope };
}

fn recover_sender(envelope: Envelope, from_claimed: Address) Error!Address {
    assert(!envelope.is_deposit());
    const recovered = envelope.recover_sender(consensus.recover_address) orelse
        return error.InvalidSignature;
    if (!recovered.eql(from_claimed)) return error.SenderMismatch;
    return recovered;
}

fn apply(
    allocator: Allocator,
    fields: *Fields,
    key: Key,
    field: object.Field,
    limits: Limits,
) Error!void {
    const value = field.value;
    switch (key) {
        .tx_type => fields.tx_type = try object.quantity(u8, value),
        .nonce => fields.nonce = try object.quantity(u64, value),
        .gas => fields.gas = try object.quantity(u64, value),
        .gas_price => fields.gas_price = try object.quantity(u128, value),
        .max_fee_per_gas => fields.max_fee_per_gas = try object.quantity(u128, value),
        .max_priority_fee_per_gas => {
            fields.max_priority_fee_per_gas = try object.quantity(u128, value);
        },
        .max_fee_per_blob_gas => fields.max_fee_per_blob_gas = try object.quantity(u128, value),
        .to => fields.to = try object.address_or_null(value),
        .value => fields.value = try object.quantity(u256, value),
        .input => fields.input = try object.data_alloc(allocator, value, limits.input_size_max),
        .chain_id => fields.chain_id = try object.quantity(u64, value),
        .access_list => fields.access_list = try raw_array(field),
        .blob_versioned_hashes => {
            fields.blob_hashes = try decode_hashes(allocator, field.raw, limits.blob_hashes_max);
        },
        .authorization_list => fields.authorization_list = try raw_array(field),
        .v => fields.v = try object.quantity(u256, value),
        .r => fields.r = try object.quantity(u256, value),
        .s => fields.s = try object.quantity(u256, value),
        .y_parity => fields.y_parity = try object.quantity(u64, value),
        .from => fields.from = try object.address(value),
        .hash => fields.hash = try object.hash(value),
        .source_hash => fields.source_hash = try object.hash(value),
        .mint => fields.mint = try object.quantity(u128, value),
        .is_system_tx => fields.is_system_tx = try object.boolean(value),
    }
}

fn raw_array(field: object.Field) Error![]const u8 {
    if (field.value.tag != .array_begin) return error.InvalidJson;
    assert(field.raw[0] == '[');
    return field.raw;
}

/// Decodes a JSON array of 32-byte hashes.
pub fn decode_hashes(allocator: Allocator, raw: []const u8, count_max: u32) Error![]B256 {
    const count = try object.array_count(raw, count_max);
    const hashes = try allocator.alloc(B256, count);
    var iterator = try object.ArrayIterator.init(raw);
    for (hashes) |*hash| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        hash.* = try object.hash(element.value);
    }
    assert(try iterator.next() == null);
    return hashes;
}

fn build_envelope(scratch: Allocator, fields: *const Fields, limits: Limits) Error!?Envelope {
    const seen = fields.seen;
    return switch (fields.tx_type) {
        L1Transaction.type_legacy => {
            try seen.require(mask_legacy);
            return try build_legacy(fields);
        },
        L1Transaction.type_eip2930 => {
            try seen.require(mask_eip2930);
            return .{ .eip2930 = .{
                .tx = .{
                    .chain_id = fields.chain_id,
                    .nonce = fields.nonce,
                    .gas_price = fields.gas_price,
                    .gas_limit = fields.gas,
                    .to = kind(fields.to),
                    .value = fields.value,
                    .input = fields.input,
                    .access_list = try build_access_list(scratch, fields.access_list, limits),
                },
                .signature = try typed_signature(fields),
            } };
        },
        L1Transaction.type_eip1559 => {
            try seen.require(mask_eip1559);
            return try build_eip1559(scratch, fields, limits);
        },
        L1Transaction.type_eip4844 => {
            try seen.require(mask_eip4844);
            return try build_eip4844(scratch, fields, limits);
        },
        4 => {
            try seen.require(mask_eip7702);
            return try build_eip7702(scratch, fields, limits);
        },
        deposit_tx_type => {
            try seen.require(mask_deposit);
            return build_deposit(fields);
        },
        else => null,
    };
}

fn kind(to: ?Address) consensus.TxKind {
    if (to) |address| return .{ .call = address };
    return .create;
}

pub const deposit_tx_type: u8 = 0x7e;

fn build_deposit(fields: *const Fields) Envelope {
    assert(fields.tx_type == deposit_tx_type);
    assert(fields.seen.has(@backingInt(Key.source_hash)));
    return .{ .deposit = .{
        .source_hash = fields.source_hash,
        .from = fields.from,
        .to = kind(fields.to),
        .mint = fields.mint,
        .value = fields.value,
        .gas_limit = fields.gas,
        .is_system_transaction = fields.is_system_tx,
        .input = fields.input,
    } };
}

fn build_legacy(fields: *const Fields) Error!Envelope {
    assert(fields.tx_type == 0);
    const legacy_v = consensus.signature.decode_legacy_v(fields.v) orelse
        return error.InvalidSignature;
    if (legacy_v.chain_id) |chain_id| {
        if (fields.seen.has(@backingInt(Key.chain_id)) and chain_id != fields.chain_id) {
            return error.InvalidField;
        }
    }
    return .{ .legacy = .{
        .tx = .{
            .chain_id = legacy_v.chain_id,
            .nonce = fields.nonce,
            .gas_price = fields.gas_price,
            .gas_limit = fields.gas,
            .to = kind(fields.to),
            .value = fields.value,
            .input = fields.input,
        },
        .signature = .{ .y_parity = legacy_v.y_parity, .r = fields.r, .s = fields.s },
    } };
}

/// The y parity of a typed transaction: `yParity`, or `v` when absent; both must agree.
fn typed_signature(fields: *const Fields) Error!Signature {
    const has_parity = fields.seen.has(@backingInt(Key.y_parity));
    const has_v = fields.seen.has(@backingInt(Key.v));
    if (!has_parity and !has_v) return error.MissingField;
    const parity: u256 = if (has_parity) fields.y_parity else fields.v;
    if (parity > 1) return error.InvalidSignature;
    if (has_parity and has_v and fields.v != parity) return error.InvalidSignature;
    return .{ .y_parity = parity == 1, .r = fields.r, .s = fields.s };
}

fn build_eip1559(scratch: Allocator, fields: *const Fields, limits: Limits) Error!Envelope {
    assert(fields.tx_type == 2);
    return .{ .eip1559 = .{
        .tx = .{
            .chain_id = fields.chain_id,
            .nonce = fields.nonce,
            .max_priority_fee_per_gas = fields.max_priority_fee_per_gas,
            .max_fee_per_gas = fields.max_fee_per_gas,
            .gas_limit = fields.gas,
            .to = kind(fields.to),
            .value = fields.value,
            .input = fields.input,
            .access_list = try build_access_list(scratch, fields.access_list, limits),
        },
        .signature = try typed_signature(fields),
    } };
}

fn build_eip4844(scratch: Allocator, fields: *const Fields, limits: Limits) Error!Envelope {
    assert(fields.tx_type == 3);
    const to = fields.to orelse return error.InvalidField;
    if (fields.blob_hashes.len == 0) return error.InvalidField;
    const hash_buffer = try scratch.alloc(u8, fields.blob_hashes.len * 33);
    return .{ .eip4844 = .{
        .tx = .{
            .chain_id = fields.chain_id,
            .nonce = fields.nonce,
            .max_priority_fee_per_gas = fields.max_priority_fee_per_gas,
            .max_fee_per_gas = fields.max_fee_per_gas,
            .gas_limit = fields.gas,
            .to = to,
            .value = fields.value,
            .input = fields.input,
            .access_list = try build_access_list(scratch, fields.access_list, limits),
            .max_fee_per_blob_gas = fields.max_fee_per_blob_gas,
            .blob_versioned_hashes = HashList.build(hash_buffer, fields.blob_hashes),
        },
        .signature = try typed_signature(fields),
    } };
}

fn build_eip7702(scratch: Allocator, fields: *const Fields, limits: Limits) Error!Envelope {
    assert(fields.tx_type == 4);
    const to = fields.to orelse return error.InvalidField;
    return .{ .eip7702 = .{
        .tx = .{
            .chain_id = fields.chain_id,
            .nonce = fields.nonce,
            .max_priority_fee_per_gas = fields.max_priority_fee_per_gas,
            .max_fee_per_gas = fields.max_fee_per_gas,
            .gas_limit = fields.gas,
            .to = to,
            .value = fields.value,
            .input = fields.input,
            .access_list = try build_access_list(scratch, fields.access_list, limits),
            .authorization_list = try build_authorizations(scratch, fields, limits),
        },
        .signature = try typed_signature(fields),
    } };
}

fn build_access_list(scratch: Allocator, raw: []const u8, limits: Limits) Error!AccessList {
    const count = try object.array_count(raw, limits.access_list_items_max);
    const items = try scratch.alloc(AccessList.BuildItem, count);
    var iterator = try object.ArrayIterator.init(raw);
    var size: usize = 0;
    var keys_total: u32 = 0;
    for (items) |*item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        item.* = try decode_access_item(scratch, element.raw, limits);
        keys_total += @intCast(item.storage_keys.len);
        if (keys_total > limits.storage_keys_max) return error.TooLarge;
        size += rlp.list_length(21 + rlp.list_length(item.storage_keys.len * 33));
    }
    const buffer = try scratch.alloc(u8, size);
    const list = AccessList.build(buffer, items);
    assert(list.payload.len == size);
    return list;
}

fn decode_access_item(
    scratch: Allocator,
    raw: []const u8,
    limits: Limits,
) Error!AccessList.BuildItem {
    var iterator = try object.ObjectIterator.init(raw);
    var item: AccessList.BuildItem = .{ .address = .zero };
    var seen: object.Seen(2) = .{};
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        if (std.mem.eql(u8, field.key, "address")) {
            try seen.see(0);
            item.address = try object.address(field.value);
        } else if (std.mem.eql(u8, field.key, "storageKeys")) {
            try seen.see(1);
            item.storage_keys = try decode_hashes(scratch, field.raw, limits.storage_keys_max);
        }
    }
    try seen.require(0b11);
    return item;
}

fn build_authorizations(
    scratch: Allocator,
    fields: *const Fields,
    limits: Limits,
) Error!AuthorizationList {
    const raw = fields.authorization_list;
    const count = try object.array_count(raw, limits.authorizations_max);
    if (count == 0) return error.InvalidField; // EIP-7702 requires at least one.
    const items = try scratch.alloc(Authorization, count);
    var iterator = try object.ArrayIterator.init(raw);
    var size: usize = 0;
    for (items) |*item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        item.* = try decode_authorization(element.raw);
        size += rlp.length(item.*);
    }
    const list = AuthorizationList.build(try scratch.alloc(u8, size), items);
    assert(list.count == count);
    return list;
}

fn decode_authorization(raw: []const u8) Error!Authorization {
    var iterator = try object.ObjectIterator.init(raw);
    var item: Authorization = .{
        .chain_id = 0,
        .address = .zero,
        .nonce = 0,
        .y_parity = 0,
        .r = 0,
        .s = 0,
    };
    var seen: object.Seen(6) = .{};
    const names = [_][]const u8{ "chainId", "address", "nonce", "yParity", "r", "s" };
    var count: u32 = 0;
    while (try iterator.next()) |field| : (count += 1) {
        assert(count <= raw.len);
        const index = for (names, 0..) |name, index| {
            if (std.mem.eql(u8, field.key, name)) break index;
        } else continue;
        try seen.see(@intCast(index));
        const value = field.value;
        switch (index) {
            0 => item.chain_id = try object.quantity(u256, value),
            1 => item.address = try object.address(value),
            2 => item.nonce = try object.quantity(u64, value),
            3 => item.y_parity = try object.quantity(u8, value),
            4 => item.r = try object.quantity(u256, value),
            5 => item.s = try object.quantity(u256, value),
            else => unreachable,
        }
    }
    try seen.require(0b111111);
    return item;
}

/// Decodes a block's `transactions` array of full objects and, when requested, verifies
/// the transactions root. Returned transactions live in `allocator`.
pub fn decode_block(
    allocator: Allocator,
    scratch: Allocator,
    raw: []const u8,
    transactions_root: B256,
    options: Options,
) Error![]L1Transaction {
    const count = try object.array_count(raw, options.limits.transactions_max);
    const transactions = try allocator.alloc(L1Transaction, count);
    const envelopes = try scratch.alloc(?Envelope, count);
    var iterator = try object.ArrayIterator.init(raw);
    var encoded_size: usize = 0;
    for (transactions, envelopes) |*transaction, *envelope| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        if (element.value.tag != .object_begin) return error.InvalidJson;
        const decoded = try decode(allocator, scratch, element.raw, options);
        transaction.* = decoded.transaction;
        envelope.* = decoded.envelope;
        if (decoded.envelope) |built| encoded_size += built.encoded_length();
    }
    assert(try iterator.next() == null);
    if (options.verify_root) {
        const root = try compute_root(scratch, envelopes, encoded_size);
        if (!root.eql(transactions_root)) return error.RootMismatch;
    }
    return transactions;
}

/// The EIP-2718 encodings of a block's `transactions` array of full objects, verified
/// against `transactions_root` (the raw block body where `debug_getRawBlock` is missing).
/// Senders are not recovered: the root binds every signed field.
pub fn encode_block(
    allocator: Allocator,
    raw: []const u8,
    transactions_root: B256,
    limits: Limits,
) Error![]const []const u8 {
    const count = try object.array_count(raw, limits.transactions_max);
    const encoded = try allocator.alloc([]const u8, count);
    const options: Options = .{ .limits = limits, .recover_senders = false };
    var iterator = try object.ArrayIterator.init(raw);
    for (encoded) |*item| {
        const element = (try iterator.next()) orelse unreachable; // Counted above.
        if (element.value.tag != .object_begin) return error.InvalidJson;
        const decoded = try decode(allocator, allocator, element.raw, options);
        const envelope = decoded.envelope orelse return error.UnsupportedTransaction;
        item.* = envelope.encode_to(try allocator.alloc(u8, envelope.encoded_length()));
    }
    assert(try iterator.next() == null);
    const root: B256 = .{ .bytes = ordered.ordered_trie_root(encoded) };
    if (!root.eql(transactions_root)) return error.RootMismatch;
    return encoded;
}

fn compute_root(scratch: Allocator, envelopes: []const ?Envelope, size: usize) Error!B256 {
    const bytes = try scratch.alloc(u8, size);
    const items = try scratch.alloc([]const u8, envelopes.len);
    var position: usize = 0;
    for (envelopes, items) |envelope, *item| {
        const built = envelope orelse return error.UnsupportedTransaction;
        item.* = built.encode_to(bytes[position..]);
        position += item.len;
    }
    assert(position == size);
    return .{ .bytes = ordered.ordered_trie_root(items) };
}

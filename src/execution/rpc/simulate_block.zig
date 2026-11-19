//! eth_simulateV1's blocks, assembled as base/base assembles them: reth's
//! `execute_transactions` turns every call into a transaction with a zero signature
//! (`BaseTransactionRequest::try_into_sim_tx`), the block executor builds its receipts,
//! `BaseBlockAssembler::assemble_block` builds the header and reth's
//! `build_simulated_block` writes the RPC block. reth finishes the block with a no-op state
//! provider (`compute_state_root_for_eth_simulate` is off), so the state root and, from
//! Isthmus, the withdrawals root (the message passer's storage root) are zero.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const chainspec = @import("../chainspec/root.zig");
const ordered = @import("../trie/ordered.zig");
const engine_block = @import("../engine/block.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const format = @import("format.zig");
const eth = @import("eth.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Bloom = primitives.Bloom;
const Header = consensus.Header;
const Envelope = consensus.Envelope;

pub const calls_max = 256;
const authorizations_max = 4096;

pub const Error = error{ScratchFull};

/// A call resolved into a transaction (reth `resolve_transaction`): missing fields are
/// filled before it runs.
pub const TxRequest = struct {
    tx_type: consensus.TxType,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    /// Legacy and EIP-2930.
    gas_price: u128 = 0,
    /// EIP-1559 and EIP-7702.
    max_fee_per_gas: u128 = 0,
    max_priority_fee_per_gas: u128 = 0,
    to: ?Address,
    value: u256,
    input: []const u8,
    access_list: []const evm.transaction.AccessListItem = &.{},
    authorizations: consensus.AuthorizationList = .empty,
};

/// The transaction type base/base builds for a call (`output_tx_type` over alloy's
/// `preferred_type`): an authorization list makes EIP-7702, blob data EIP-4844 (which Base
/// builds as EIP-1559), an access list with a gas price EIP-2930, a gas price legacy, and
/// anything else EIP-1559.
pub fn tx_type_of(
    authorizations: bool,
    blob_hashes: bool,
    access_list: bool,
    gas_price: bool,
) consensus.TxType {
    if (authorizations) return .eip7702;
    if (blob_hashes) return .eip1559;
    if (access_list and gas_price) return .eip2930;
    if (gas_price) return .legacy;
    return .eip1559;
}

/// What a simulated header takes from outside its block's transactions.
pub const Context = struct {
    spec: *const chainspec.ChainSpec,
    parent_hash: B256,
    env: *const node.executor.BlockEnv,
    difficulty: u256,
    extra_data: []const u8,
    parent_beacon_block_root: ?B256,
};

/// One simulated block's transactions and receipts, encoded into a scratch region.
pub const Block = struct {
    arena: std.heap.FixedBufferAllocator,
    transactions: [calls_max][]const u8 = undefined,
    receipts: [calls_max][]const u8 = undefined,
    senders: [calls_max]Address = undefined,
    count: u32 = 0,
    receipt_count: u32 = 0,
    gas_used: u64 = 0,
    /// Jovian: the DA footprint of the block's transactions (its `blobGasUsed`).
    da_footprint: u64 = 0,
    logs_bloom: Bloom = .zero,

    pub fn init(space: []u8) Block {
        assert(space.len > 0);
        return .{ .arena = std.heap.FixedBufferAllocator.init(space) };
    }

    fn alloc(block: *Block, size: usize) Error![]u8 {
        return block.arena.allocator().alloc(u8, size) catch error.ScratchFull;
    }

    /// Encodes `request` with a zero signature; returns its hash. A legacy transaction is
    /// unsigned as geth builds it (`ToTransaction`): v, r and s zero, no EIP-155 v
    /// (Nethermind: no signature, `LegacyTransactionForRpc` v 0).
    pub fn add_transaction(
        block: *Block,
        request: *const TxRequest,
        sender: Address,
    ) Error!B256 {
        assert(block.count == block.receipt_count);
        assert(block.count < calls_max);
        const envelope = try block.envelope_of(request);
        const raw = if (envelope == .legacy) legacy: {
            const tx = envelope.legacy.tx;
            const length = consensus.tx.unsigned_legacy_length(tx);
            break :legacy consensus.tx.encode_unsigned_legacy(tx, try block.alloc(length));
        } else envelope.encode_to(try block.alloc(envelope.encoded_length()));
        block.transactions[block.count] = raw;
        block.senders[block.count] = sender;
        block.count += 1;
        return primitives.keccak256(raw);
    }

    fn envelope_of(block: *Block, request: *const TxRequest) Error!Envelope {
        const signature: consensus.Signature = .{ .y_parity = false, .r = 0, .s = 0 };
        const kind: consensus.TxKind = if (request.to) |to| .{ .call = to } else .create;
        const access_list = try block.encode_access_list(request.access_list);
        const r = request;
        return switch (request.tx_type) {
            .legacy => .{ .legacy = .{ .signature = signature, .tx = .{
                .chain_id = r.chain_id,
                .nonce = r.nonce,
                .gas_price = r.gas_price,
                .gas_limit = r.gas_limit,
                .to = kind,
                .value = r.value,
                .input = r.input,
            } } },
            .eip2930 => .{ .eip2930 = .{ .signature = signature, .tx = .{
                .chain_id = r.chain_id,
                .nonce = r.nonce,
                .gas_price = r.gas_price,
                .gas_limit = r.gas_limit,
                .to = kind,
                .value = r.value,
                .input = r.input,
                .access_list = access_list,
            } } },
            .eip1559 => .{ .eip1559 = .{ .signature = signature, .tx = .{
                .chain_id = r.chain_id,
                .nonce = r.nonce,
                .max_priority_fee_per_gas = r.max_priority_fee_per_gas,
                .max_fee_per_gas = r.max_fee_per_gas,
                .gas_limit = r.gas_limit,
                .to = kind,
                .value = r.value,
                .input = r.input,
                .access_list = access_list,
            } } },
            .eip7702 => .{ .eip7702 = .{ .signature = signature, .tx = .{
                .chain_id = r.chain_id,
                .nonce = r.nonce,
                .max_priority_fee_per_gas = r.max_priority_fee_per_gas,
                .max_fee_per_gas = r.max_fee_per_gas,
                .gas_limit = r.gas_limit,
                .to = r.to orelse .zero,
                .value = r.value,
                .input = r.input,
                .access_list = access_list,
                .authorization_list = r.authorizations,
            } } },
            else => unreachable, // `tx_type_of` builds no other type.
        };
    }

    fn encode_access_list(
        block: *Block,
        items: []const evm.transaction.AccessListItem,
    ) Error!consensus.AccessList {
        var size: usize = 0;
        for (items) |item| {
            size += rlp.list_length(21 + rlp.list_length(33 * item.storage_keys.len));
        }
        var encoder = rlp.Encoder.init(try block.alloc(size));
        var keys: u32 = 0;
        for (items) |item| {
            const keys_length = 33 * item.storage_keys.len;
            encoder.list_header(21 + rlp.list_length(keys_length));
            encoder.bytes(&item.address);
            encoder.list_header(keys_length);
            for (item.storage_keys) |*key| encoder.bytes(key);
            keys += @intCast(item.storage_keys.len);
        }
        assert(encoder.written().len == size);
        return .{
            .payload = encoder.written(),
            .address_count = @intCast(items.len),
            .storage_key_count = keys,
        };
    }

    /// The receipt of the last transaction added (base/base `BaseRethReceiptBuilder`).
    pub fn add_receipt(
        block: *Block,
        status: bool,
        gas_used: u64,
        logs: []const evm.state.Log,
    ) Error!void {
        assert(block.receipt_count + 1 == block.count);
        const raw = block.transactions[block.receipt_count];
        const tx_type: consensus.TxType = if (raw[0] >= 0xc0)
            .legacy
        else
            @fromBackingInt(@intCast(raw[0]));
        assert(tx_type != .deposit);
        var size: usize = 0;
        for (logs) |*item| size += rlp.list_length(log_payload_length(item));
        var encoder = rlp.Encoder.init(try block.alloc(size));
        var bloom: Bloom = .zero;
        for (logs) |*item| {
            encoder.list_header(log_payload_length(item));
            encoder.bytes(&item.address);
            encoder.list_header(@as(usize, item.topic_count) * 33);
            for (item.topic_slice()) |*topic| encoder.bytes(topic);
            encoder.bytes(item.data);
            bloom.accrue(&item.address);
            for (item.topic_slice()) |*topic| bloom.accrue(topic);
        }
        assert(encoder.written().len == size);
        block.gas_used += gas_used;
        const receipt: consensus.Receipt = .{
            .tx_type = tx_type,
            .status = status,
            .cumulative_gas_used = block.gas_used,
            .logs_bloom = bloom,
            .logs = .{ .payload = encoder.written(), .count = @intCast(logs.len) },
        };
        block.receipts[block.receipt_count] = receipt.encode_to(
            try block.alloc(receipt.encoded_length()),
        );
        block.receipt_count += 1;
        for (0..bloom.bytes.len) |index| block.logs_bloom.bytes[index] |= bloom.bytes[index];
    }

    /// The block's header (base/base `BaseBlockAssembler::assemble_block`).
    pub fn header(block: *const Block, context: Context) Header {
        assert(block.count == block.receipt_count);
        const spec = context.spec;
        const env = context.env;
        const timestamp = env.timestamp;
        var result: Header = .{
            .parent_hash = context.parent_hash,
            .beneficiary = .{ .bytes = env.beneficiary },
            .state_root = .zero,
            .transactions_root = .{ .bytes = ordered.ordered_trie_root(
                block.transactions[0..block.count],
            ) },
            .receipts_root = .{ .bytes = ordered.ordered_trie_root(
                block.receipts[0..block.receipt_count],
            ) },
            .logs_bloom = block.logs_bloom,
            .difficulty = context.difficulty,
            .number = env.number,
            .gas_limit = env.gas_limit,
            .gas_used = block.gas_used,
            .timestamp = timestamp,
            .extra_data = context.extra_data,
            .mix_hash = .{ .bytes = env.prev_randao },
            .nonce = .zero,
            .base_fee_per_gas = env.base_fee,
            .parent_beacon_block_root = context.parent_beacon_block_root,
        };
        const isthmus = spec.is_upgrade_active(.isthmus, timestamp);
        if (isthmus) {
            result.withdrawals_root = .zero;
        } else if (spec.is_upgrade_active(.canyon, timestamp)) {
            result.withdrawals_root = primitives.empty_root_hash;
        }
        if (spec.is_upgrade_active(.jovian, timestamp)) {
            result.excess_blob_gas = 0;
            result.blob_gas_used = block.da_footprint;
        } else if (spec.is_upgrade_active(.ecotone, timestamp)) {
            result.excess_blob_gas = 0;
            result.blob_gas_used = 0;
        }
        if (isthmus) result.requests_hash = engine_block.empty_requests_hash;
        drop_detached_optionals(&result);
        assert(result.optionals_contiguous());
        return result;
    }

    /// The block's RLP length, `rlp([header, transactions, ommers, withdrawals?])`.
    pub fn size_bytes(block: *const Block, sealed: *const Sealed) usize {
        var transactions_payload: usize = 0;
        for (block.transactions[0..block.count]) |raw| {
            transactions_payload += if (raw[0] >= 0xc0) raw.len else rlp.bytes_length(raw);
        }
        var payload = sealed.rlp_length() + rlp.list_length(transactions_payload) +
            rlp.list_length(0);
        if (sealed.header.withdrawals_root != null) payload += rlp.list_length(0);
        return rlp.list_length(payload);
    }

    /// The block object's own fields (the caller writes `calls`): the header, no uncles,
    /// the transactions (hashes, or objects when `full`) and Canyon's empty withdrawals.
    pub fn write(
        block: *const Block,
        w: *json.Writer,
        sealed: *const Sealed,
        hash: B256,
        full: bool,
        chain_id: u64,
    ) json.Writer.WriteError!void {
        assert(block.count == block.receipt_count);
        const sealed_header = &sealed.header;
        const size = block.size_bytes(sealed);
        try format.header_fields_base_fee(
            w,
            sealed_header,
            hash.bytes,
            size,
            sealed.base_fee_override,
        );
        try w.key("uncles");
        try w.begin_array();
        try w.end_array();
        try w.key("transactions");
        try w.begin_array();
        for (block.transactions[0..block.count], 0..) |raw, index| {
            if (!full) {
                try w.data(&primitives.keccak256(raw).bytes);
                continue;
            }
            try format.simulated_transaction(w, raw, block.senders[index], chain_id, .{
                .block_hash = hash.bytes,
                .block_number = sealed_header.number,
                .index = @intCast(index),
                .base_fee = sealed_header.base_fee_per_gas,
                .base_fee_override = sealed.base_fee_override,
                .timestamp = sealed_header.timestamp,
            });
        }
        try w.end_array();
        if (sealed_header.withdrawals_root != null) {
            try w.key("withdrawals");
            try w.begin_array();
            try w.end_array();
        }
    }
};

/// A simulated block's header with its base fee as overridden: geth (big.Int) and
/// Nethermind (UInt256) keep a `baseFeePerGas` override above `Header`'s u64 whole, so the
/// hash, size and `baseFeePerGas` carry `base_fee_override` when it is set.
pub const Sealed = struct {
    header: Header,
    base_fee_override: ?u256,

    const field_names = @typeInfo(Header).@"struct".field_names;

    pub fn rlp_length(sealed: *const Sealed) usize {
        const fee = sealed.base_fee_override orelse return sealed.header.rlp_length();
        return rlp.list_length(wide_payload_length(&sealed.header, fee));
    }

    /// keccak256(rlp(header)), the base fee whole.
    pub fn hash(sealed: *const Sealed) B256 {
        const fee = sealed.base_fee_override orelse return sealed.header.hash();
        assert(fee > std.math.maxInt(u64));
        assert(sealed.header.base_fee_per_gas == std.math.maxInt(u64));
        assert(sealed.header.optionals_contiguous());
        var sink: consensus.hashing.KeccakSink = .{};
        var encoder = sink.encoder();
        const payload = wide_payload_length(&sealed.header, fee);
        encoder.list_header(payload);
        inline for (field_names) |name| {
            const value = @field(sealed.header, name);
            if (comptime std.mem.eql(u8, name, "base_fee_per_gas")) {
                rlp.encode(&encoder, fee);
            } else if (comptime @typeInfo(@TypeOf(value)) == .optional) {
                if (value) |present| rlp.encode(&encoder, present);
            } else {
                rlp.encode(&encoder, value);
            }
        }
        assert(encoder.position == rlp.list_length(payload));
        return sink.final();
    }

    fn wide_payload_length(header: *const Header, fee: u256) usize {
        var total: usize = 0;
        inline for (field_names) |name| {
            const value = @field(header.*, name);
            if (comptime std.mem.eql(u8, name, "base_fee_per_gas")) {
                total += rlp.length(fee);
            } else if (comptime @typeInfo(@TypeOf(value)) == .optional) {
                if (value) |present| total += rlp.length(present);
            } else {
                total += rlp.length(value);
            }
        }
        return total;
    }
};

/// Keeps the header's optional fields a prefix (a pre-Ecotone base block has no beacon
/// root for a later block's fields to follow).
fn drop_detached_optionals(sealed: *Header) void {
    if (sealed.withdrawals_root == null) sealed.blob_gas_used = null;
    if (sealed.blob_gas_used == null) sealed.excess_blob_gas = null;
    if (sealed.excess_blob_gas == null) sealed.parent_beacon_block_root = null;
    if (sealed.parent_beacon_block_root == null) sealed.requests_hash = null;
}

fn log_payload_length(item: *const evm.state.Log) usize {
    return rlp.bytes_length(&item.address) +
        rlp.list_length(@as(usize, item.topic_count) * 33) + rlp.bytes_length(item.data);
}

/// The text of a log's `blockHash` member, which `patch_block_hashes` finds.
pub const block_hash_key = "\"blockHash\":\"0x";

/// Fills the `blockHash` of every log in `text`, the block's `calls` as written before the
/// block was sealed. The key cannot occur inside a JSON string: its quotes would be escaped.
pub fn patch_block_hashes(text: []u8, hash: B256) u32 {
    const hex = std.fmt.bytesToHex(hash.bytes, .lower);
    var patched: u32 = 0;
    var position: usize = 0;
    while (std.mem.indexOfPos(u8, text, position, block_hash_key)) |at| {
        const start = at + block_hash_key.len;
        assert(start + hex.len < text.len and text[start + hex.len] == '"');
        @memcpy(text[start..][0..hex.len], &hex);
        position = start + hex.len;
        patched += 1;
    }
    assert(position <= text.len);
    return patched;
}

/// Encodes a call's `authorizationList` (signatures kept, as the transaction carries them)
/// into `block`'s scratch.
pub fn encode_authorizations(
    block: *Block,
    raw: []const u8,
) (Error || rpc.HandlerError)!consensus.AuthorizationList {
    var probe = json.Scanner.init(raw);
    const open = probe.next() catch return error.InvalidParams;
    if (open.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    var total: usize = 0;
    while (try eth.signed_authorization(&probe)) |authorization| : (count += 1) {
        if (count == authorizations_max) return error.InvalidParams;
        total += rlp.length(authorization);
    }
    var encoder = rlp.Encoder.init(try block.alloc(total));
    var scanner = json.Scanner.init(raw);
    _ = scanner.next() catch unreachable; // Proof: the probe read the same array.
    while (try eth.signed_authorization(&scanner)) |authorization| {
        rlp.encode(&encoder, authorization);
    }
    assert(encoder.written().len == total);
    return .{ .payload = encoder.written(), .count = count };
}

const testing = std.testing;

test "simulate_block: patching fills every log's block hash" {
    const zero = "0x" ++ @as([64]u8, @splat('0'));
    var text = ("[{\"blockHash\":\"" ++ zero ++ "\",\"message\":\"\\\"blockHash\\\":\\\"0x\"}" ++
        ",{\"blockHash\":\"" ++ zero ++ "\"}]").*;
    const hash: B256 = .{ .bytes = @splat(0xaa) };
    try testing.expectEqual(@as(u32, 2), patch_block_hashes(&text, hash));
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, &text, &@as([64]u8, @splat('a'))));
}

test "simulate_block: transaction types follow alloy's preferred type" {
    try testing.expectEqual(consensus.TxType.eip1559, tx_type_of(false, false, false, false));
    try testing.expectEqual(consensus.TxType.eip1559, tx_type_of(false, false, true, false));
    try testing.expectEqual(consensus.TxType.eip2930, tx_type_of(false, false, true, true));
    try testing.expectEqual(consensus.TxType.legacy, tx_type_of(false, false, false, true));
    try testing.expectEqual(consensus.TxType.eip1559, tx_type_of(false, true, false, true));
    try testing.expectEqual(consensus.TxType.eip7702, tx_type_of(true, true, true, true));
}

test "simulate_block: a base fee above u64 is hashed whole" {
    const fee: u256 = 0x9ed5eb1431d6880000;
    const header: Header = .{
        .number = 5,
        .gas_limit = 30_000_000,
        .extra_data = "base",
        .base_fee_per_gas = std.math.maxInt(u64),
    };
    // The header's fields, in order, with the base fee widened.
    const Wide = struct {
        parent_hash: B256,
        ommers_hash: B256,
        beneficiary: Address,
        state_root: B256,
        transactions_root: B256,
        receipts_root: B256,
        logs_bloom: Bloom,
        difficulty: u256,
        number: u64,
        gas_limit: u64,
        gas_used: u64,
        timestamp: u64,
        extra_data: []const u8,
        mix_hash: B256,
        nonce: primitives.B64,
        base_fee_per_gas: u256,
    };
    var wide: Wide = undefined;
    inline for (@typeInfo(Wide).@"struct".field_names) |name| {
        if (comptime !std.mem.eql(u8, name, "base_fee_per_gas")) {
            @field(wide, name) = @field(header, name);
        }
    }
    wide.base_fee_per_gas = fee;
    const sealed: Sealed = .{ .header = header, .base_fee_override = fee };
    try testing.expect(sealed.hash().eql(consensus.hashing.keccak_rlp(wide)));
    try testing.expectEqual(rlp.length(wide), sealed.rlp_length());
    const narrow: Sealed = .{ .header = header, .base_fee_override = null };
    try testing.expect(narrow.hash().eql(header.hash()));
    try testing.expect(!narrow.hash().eql(sealed.hash()));
}

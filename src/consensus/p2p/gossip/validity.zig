//! Unsafe-block gossip validation: a port of base/base
//! `crates/consensus/gossip/src/block_validity.rs`, in the same order:
//!
//!   1. timestamp within [now - 60 s, now + 5 s] (`now_seconds` is injected)
//!   2. signature recovers, and the signer is the unsafe block signer
//!   3. the block hash recomputed from the payload (header RLP with the transactions
//!      root, withdrawals root, beacon root, and the Isthmus empty requests hash) matches;
//!      like alloy `try_into_block` this rejects extra data over 32 bytes, a base fee above
//!      u64, and transactions that do not decode
//!   4. version rules: v3/v4 need zero blob gas used (until Jovian's DA footprint), zero
//!      excess blob gas, and a parent beacon block root; v4 carries a withdrawals root by
//!      construction; v2+ withdrawals must be empty (base/base caps the SSZ list at 0)
//!   5. at most 5 distinct blocks per height, and a block already seen is ignored
//!
//! Every failure is a gossipsub Reject except an already seen block, which is Ignore.
//!
//! Not ported: base/base also checks the Denim sub-second timestamp schedule
//! (`BaseTimeUpdateTx::validate_block_timestamp`), which needs the Base time-update
//! transaction decoder; the consensus lane owns that and must add the check before
//! sub-second blocks activate.
//!
//! Deviations: transactions decode with `common/consensus` `Envelope`, which matches
//! `BaseTxEnvelope` except that it cannot decode EIP-8130 (type 0x79) yet, so those are
//! accepted undecoded, and EIP-4844 (type 0x03) is rejected explicitly. A v1/v2 payload
//! after Isthmus has no contiguous header encoding with a requests hash, so it fails the
//! block hash check without hashing (alloy would hash placeholders; the hash never
//! matches a real sequencer block either way).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../../common/primitives/root.zig");
const consensus_types = @import("../../../common/consensus/root.zig");
const common_block = @import("../../../common/consensus/block.zig");
const ordered = @import("../../../execution/trie/ordered.zig");
const Nibbles = @import("../../../execution/trie/nibbles.zig").Nibbles;
const rollup_config = @import("../../protocol/rollup_config.zig");
const block = @import("block.zig");
const ssz = @import("ssz_payload.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const Header = consensus_types.header.Header;
const RollupConfig = rollup_config.RollupConfig;

/// gossipsub validation result.
pub const Acceptance = enum { accept, reject, ignore };

pub const Error = error{
    /// Older than 60 s or more than 5 s in the future.
    Timestamp,
    /// The signature does not recover to a public key.
    Signature,
    /// Recovered signer is not the unsafe block signer.
    Signer,
    /// Extra data longer than 32 bytes.
    ExtraData,
    /// Base fee does not fit in u64.
    BaseFeeOverflow,
    /// A transaction does not decode as a Base transaction.
    Transaction,
    /// Recomputed block hash differs from the payload's.
    BlockHash,
    /// A v2+ payload carries withdrawals.
    Withdrawals,
    /// v3+ payload with non-zero blob gas used before Jovian.
    BlobGasUsed,
    /// v3+ payload with non-zero excess blob gas.
    ExcessBlobGas,
    /// v3+ payload without a parent beacon block root.
    ParentBeaconRoot,
    /// Five distinct blocks were already accepted at this height.
    TooManyBlocks,
    /// This block was already accepted.
    BlockSeen,
};

pub const timestamp_future_max_seconds: u64 = 5;
pub const timestamp_age_max_seconds: u64 = block.block_age_max_seconds;
/// Heights remembered (base/base `SEEN_HASH_CACHE_SIZE`, op-node's LRU size).
pub const seen_heights_max: u32 = 1000;
/// Distinct blocks accepted per height (base/base `MAX_BLOCKS_TO_KEEP`).
pub const blocks_per_height_max: u32 = 5;

/// Maps a validation result to gossipsub acceptance: only `BlockSeen` is Ignore.
pub fn acceptance(result: Error!void) Acceptance {
    result catch |err| return if (err == error.BlockSeen) .ignore else .reject;
    return .accept;
}

/// The timestamp window check alone.
pub fn check_timestamp(timestamp: u64, now_seconds: u64) Error!void {
    const is_future = timestamp > now_seconds +| timestamp_future_max_seconds;
    const is_past = timestamp < now_seconds -| timestamp_age_max_seconds;
    if (is_future or is_past) return error.Timestamp;
    assert(timestamp <= now_seconds +| timestamp_future_max_seconds);
    assert(timestamp >= now_seconds -| timestamp_age_max_seconds);
}

/// Bounded `height -> {block hash}` table (base/base `seen_hashes`, a BTreeMap pruned
/// from the lowest height once it holds `seen_heights_max` heights).
pub const SeenHashes = struct {
    heights: [seen_heights_max]u64 = undefined,
    counts: [seen_heights_max]u8 = undefined,
    hashes: [seen_heights_max][blocks_per_height_max]B256 = undefined,
    len: u32 = 0,

    fn find(seen: *const SeenHashes, height: u64) ?u32 {
        assert(seen.len <= seen_heights_max);
        var index: u32 = 0;
        while (index < seen.len) : (index += 1) {
            if (seen.heights[index] == height) return index;
        }
        return null;
    }

    /// Fails with `TooManyBlocks` before `BlockSeen`, like base/base.
    pub fn check(seen: *const SeenHashes, height: u64, hash: B256) Error!void {
        const index = seen.find(height) orelse return;
        const count = seen.counts[index];
        assert(count >= 1 and count <= blocks_per_height_max);
        if (count >= blocks_per_height_max) return error.TooManyBlocks;
        for (seen.hashes[index][0..count]) |known| {
            if (known.eql(hash)) return error.BlockSeen;
        }
    }

    /// Records `hash` at `height`; `check` must have passed. Prunes the lowest height
    /// when the table is full (which may be `height` itself, as in base/base).
    pub fn insert(seen: *SeenHashes, height: u64, hash: B256) void {
        if (seen.find(height)) |index| {
            const count = seen.counts[index];
            assert(count < blocks_per_height_max);
            seen.hashes[index][count] = hash;
            seen.counts[index] = count + 1;
        } else {
            assert(seen.len < seen_heights_max);
            seen.heights[seen.len] = height;
            seen.counts[seen.len] = 1;
            seen.hashes[seen.len][0] = hash;
            seen.len += 1;
        }
        if (seen.len >= seen_heights_max) seen.remove_lowest();
        assert(seen.len < seen_heights_max);
    }

    fn remove_lowest(seen: *SeenHashes) void {
        assert(seen.len > 0);
        var lowest: u32 = 0;
        var index: u32 = 1;
        while (index < seen.len) : (index += 1) {
            if (seen.heights[index] < seen.heights[lowest]) lowest = index;
        }
        const last = seen.len - 1;
        seen.heights[lowest] = seen.heights[last];
        seen.counts[lowest] = seen.counts[last];
        seen.hashes[lowest] = seen.hashes[last];
        seen.len = last;
        assert(seen.len < seen_heights_max);
    }
};

/// Ordered trie root of the raw EIP-2718 transactions, streamed from the SSZ view.
/// Every transaction must be non-empty.
pub fn transactions_root(transactions: ssz.Transactions) B256 {
    var builder = ordered.OrderedHashBuilder.init();
    var step: u64 = 0;
    while (step < transactions.count) : (step += 1) {
        const index = ordered.adjust_index_for_rlp(step, transactions.count);
        var key_buffer: [9]u8 = undefined;
        const key = Nibbles.from_bytes(ordered.encode_index(index, &key_buffer));
        const item = transactions.get(@intCast(index));
        assert(item.len > 0);
        builder.add_leaf(key.slice(), item);
    }
    assert(step == transactions.count);
    return .{ .bytes = builder.root() };
}

/// Decodes every transaction as a Base transaction (alloy `try_into_block`).
pub fn check_transactions(transactions: ssz.Transactions) Error!void {
    var index: u32 = 0;
    while (index < transactions.count) : (index += 1) {
        const item = transactions.get(index);
        if (item.len == 0) return error.Transaction;
        if (item[0] == eip8130_type) continue;
        if (item[0] == @backingInt(consensus_types.tx.TxType.eip4844)) {
            return error.Transaction;
        }
        _ = consensus_types.Envelope.decode(item) catch return error.Transaction;
    }
    assert(index == transactions.count);
}

const eip8130_type: u8 = 0x79;

/// Recomputes the block hash of `payload` (alloy `into_block_raw` + `hash_slow`).
pub fn block_hash(
    config: *const RollupConfig,
    payload: *const ssz.ExecutionPayload,
    parent_beacon_block_root: ?B256,
) Error!B256 {
    if (payload.extra_data.len > ssz.extra_data_size_max) return error.ExtraData;
    if (payload.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeOverflow;
    if (payload.withdrawals.count > 0) return error.Withdrawals;
    try check_transactions(payload.transactions);
    var header: Header = .{
        .parent_hash = payload.parent_hash,
        .beneficiary = payload.fee_recipient,
        .state_root = payload.state_root,
        .transactions_root = transactions_root(payload.transactions),
        .receipts_root = payload.receipts_root,
        .logs_bloom = payload.logs_bloom,
        .number = payload.block_number,
        .gas_limit = payload.gas_limit,
        .gas_used = payload.gas_used,
        .timestamp = payload.timestamp,
        .extra_data = payload.extra_data,
        .mix_hash = payload.prev_randao,
        .base_fee_per_gas = @intCast(payload.base_fee_per_gas),
    };
    if (payload.has_withdrawals()) header.withdrawals_root = primitives.empty_root_hash;
    if (payload.version == .v4) header.withdrawals_root = payload.withdrawals_root;
    if (payload.has_blob_gas()) {
        header.blob_gas_used = payload.blob_gas_used;
        header.excess_blob_gas = payload.excess_blob_gas;
    }
    header.parent_beacon_block_root = parent_beacon_block_root;
    if (config.is_feature_active(.empty_requests_hash, payload.timestamp)) {
        header.requests_hash = common_block.empty_requests_hash;
    }
    if (!header.optionals_contiguous()) return error.BlockHash;
    assert(header.base_fee_per_gas != null);
    return header.hash();
}

/// v3/v4 field rules (base/base `validate_version_specific_payload`).
pub fn check_version_fields(
    config: *const RollupConfig,
    envelope: *const block.Envelope,
) Error!void {
    const payload = &envelope.payload;
    assert(payload.version == envelope.version);
    if (!payload.has_blob_gas()) return;
    const da_footprint = config.is_feature_active(.da_footprint, payload.timestamp);
    if (!da_footprint and payload.blob_gas_used != 0) return error.BlobGasUsed;
    if (payload.excess_blob_gas != 0) return error.ExcessBlobGas;
    if (envelope.parent_beacon_block_root == null) return error.ParentBeaconRoot;
    assert(block.has_parent_beacon_root(envelope.version));
}

/// Stateful validator: rollup config, current unsafe block signer, seen-hash table.
/// About 170 KiB; keep it in long-lived memory.
pub const Validator = struct {
    config: *const RollupConfig,
    unsafe_block_signer: Address,
    seen: SeenHashes = .{},

    /// Validates `envelope` at local time `now_seconds` and records it as seen on success.
    pub fn validate(
        validator: *Validator,
        envelope: *const block.Envelope,
        now_seconds: u64,
    ) Error!void {
        const payload = &envelope.payload;
        try check_timestamp(payload.timestamp, now_seconds);
        const chain_id = validator.config.l2_chain_id;
        const signer = block.recover_signer(envelope, chain_id) orelse return error.Signature;
        if (!signer.eql(validator.unsafe_block_signer)) return error.Signer;
        const computed = try block_hash(
            validator.config,
            payload,
            envelope.parent_beacon_block_root,
        );
        if (!computed.eql(payload.block_hash)) return error.BlockHash;
        try check_version_fields(validator.config, envelope);
        try validator.seen.check(payload.block_number, payload.block_hash);
        validator.seen.insert(payload.block_number, payload.block_hash);
        assert(validator.seen.len > 0 or seen_heights_max == 1);
    }
};

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");
const snappy = @import("snappy.zig");
const secp256k1 = @import("../../../common/crypto/secp256k1/root.zig");

const now_test: u64 = 2_000_000;
const chain_id_test: u64 = 8453;

/// Signs payloads with a fixed tiny test key and decodes them back into envelopes.
const TestContext = struct {
    config: RollupConfig,
    secret: [32]u8,
    signer: Address,
    tx_storage: [512]u8 = undefined,
    scratch: [8192]u8 = undefined,
    out: [snappy.max_compressed_length(8192)]u8 = undefined,
    decoded: [8192]u8 = undefined,
    compressor: snappy.Compressor = .{},

    fn init(context: *TestContext, upgrades: []const rollup_config.Upgrade) !void {
        context.* = .{
            .config = .{ .l2_chain_id = chain_id_test },
            .secret = @splat(0),
            .signer = .zero,
        };
        for (upgrades) |upgrade| context.config.upgrades.set(upgrade, 0);
        context.secret[31] = 5;
        context.signer = .{ .bytes = try secp256k1.address(context.secret) };
    }

    /// A payload with one deposit transaction, a correct block hash, at `now_test`.
    fn payload(context: *TestContext, version: ssz.Version, number: u64) ssz.ExecutionPayload {
        const deposit: consensus_types.Envelope = .{ .deposit = .{
            .source_hash = .{ .bytes = @splat(@truncate(number)) },
            .from = .zero,
            .to = .create,
            .mint = 0,
            .value = 0,
            .gas_limit = 1_000_000,
            .is_system_transaction = false,
            .input = "needlefish",
        } };
        const encoded = deposit.encode_to(context.tx_storage[256..]);
        var result: ssz.ExecutionPayload = .{
            .version = version,
            .block_number = number,
            .timestamp = now_test,
            .gas_limit = 30_000_000,
            .base_fee_per_gas = 1,
            .extra_data = "base",
            .transactions = ssz.Transactions.encode(context.tx_storage[0..256], &.{encoded}),
        };
        if (version == .v4) result.withdrawals_root = .{ .bytes = @splat(0x44) };
        return result;
    }

    fn validator(context: *TestContext) Validator {
        assert(context.config.l2_chain_id == chain_id_test);
        return .{ .config = &context.config, .unsafe_block_signer = context.signer };
    }

    fn root_for(version: ssz.Version) ?B256 {
        if (!block.has_parent_beacon_root(version)) return null;
        return .{ .bytes = @splat(0xbb) };
    }

    fn rehash(context: *TestContext, payload_value: *ssz.ExecutionPayload) !void {
        const root = root_for(payload_value.version);
        payload_value.block_hash = try block_hash(&context.config, payload_value, root);
    }

    fn sign(context: *TestContext, payload_value: ssz.ExecutionPayload) !block.Envelope {
        const message = try block.encode_signed(
            chain_id_test,
            context.secret,
            root_for(payload_value.version),
            payload_value,
            &context.scratch,
            &context.compressor,
            &context.out,
        );
        return block.decode(payload_value.version, message, &context.decoded);
    }

    fn valid(context: *TestContext, version: ssz.Version, number: u64) !block.Envelope {
        var value = context.payload(version, number);
        try context.rehash(&value);
        return context.sign(value);
    }
};

test "validity: accepts every version once, then ignores the duplicate" {
    var context: TestContext = undefined;
    for ([_]ssz.Version{ .v1, .v2, .v3, .v4 }) |version| {
        const isthmus: []const rollup_config.Upgrade = &.{ .ecotone, .isthmus };
        const pre_isthmus: []const rollup_config.Upgrade = &.{.ecotone};
        try context.init(if (version == .v4) isthmus else pre_isthmus);
        var validator = context.validator();
        const envelope = try context.valid(version, 10);
        try validator.validate(&envelope, now_test);
        const again = validator.validate(&envelope, now_test);
        try testing.expectError(error.BlockSeen, again);
        try testing.expectEqual(Acceptance.ignore, acceptance(again));
    }
}

test "validity: timestamp window boundaries" {
    try check_timestamp(now_test - 60, now_test);
    try check_timestamp(now_test + 5, now_test);
    try testing.expectError(error.Timestamp, check_timestamp(now_test - 61, now_test));
    try testing.expectError(error.Timestamp, check_timestamp(now_test + 6, now_test));
    try check_timestamp(0, 30); // saturating at the epoch
    try check_timestamp(std.math.maxInt(u64), std.math.maxInt(u64) - 2);
    var context: TestContext = undefined;
    try context.init(&.{.ecotone});
    var validator = context.validator();
    const envelope = try context.valid(.v3, 1);
    try testing.expectError(error.Timestamp, validator.validate(&envelope, now_test + 61));
    try testing.expectError(error.Timestamp, validator.validate(&envelope, now_test - 6));
    try validator.validate(&envelope, now_test + 60);
}

test "validity: signature and signer" {
    var context: TestContext = undefined;
    try context.init(&.{.ecotone});
    var validator: Validator = .{ .config = &context.config, .unsafe_block_signer = .zero };
    var envelope = try context.valid(.v3, 1);
    const wrong = validator.validate(&envelope, now_test);
    try testing.expectError(error.Signer, wrong);
    try testing.expectEqual(Acceptance.reject, acceptance(wrong));
    validator.unsafe_block_signer = context.signer;
    envelope.signature[0..32].* = @splat(0);
    try testing.expectError(error.Signature, validator.validate(&envelope, now_test));
    try testing.expectEqual(@as(u32, 0), validator.seen.len);
}

test "validity: block hash, extra data, base fee, transactions, withdrawals" {
    var context: TestContext = undefined;
    try context.init(&.{.ecotone});
    var validator = context.validator();
    var stale = context.payload(.v2, 3);
    stale.block_hash = .{ .bytes = @splat(1) };
    const envelope = try context.sign(stale);
    try testing.expectError(error.BlockHash, validator.validate(&envelope, now_test));
    var value = context.payload(.v2, 3);
    const long_extra: [33]u8 = @splat(7);
    value.extra_data = &long_extra;
    try testing.expectError(error.ExtraData, block_hash(&context.config, &value, null));
    value = context.payload(.v2, 3);
    value.base_fee_per_gas = @as(u256, std.math.maxInt(u64)) + 1;
    try testing.expectError(error.BaseFeeOverflow, block_hash(&context.config, &value, null));
    value.base_fee_per_gas = std.math.maxInt(u64);
    _ = try block_hash(&context.config, &value, null);
    var withdrawal_bytes: [ssz.withdrawal_size]u8 = @splat(0);
    value.withdrawals = try ssz.Withdrawals.decode(&withdrawal_bytes);
    try testing.expectError(error.Withdrawals, block_hash(&context.config, &value, null));
    var tx_bytes: [64]u8 = undefined;
    const bad_lists = [_][]const []const u8{ &.{""}, &.{"\x02\xc0"}, &.{"\x03\xc0"}, &.{"\xff"} };
    for (bad_lists) |items| {
        value = context.payload(.v2, 3);
        value.transactions = ssz.Transactions.encode(&tx_bytes, items);
        try testing.expectError(error.Transaction, block_hash(&context.config, &value, null));
    }
    value.transactions = ssz.Transactions.encode(&tx_bytes, &.{"\x79\x01"});
    _ = try block_hash(&context.config, &value, null);
}

test "validity: v3/v4 blob gas, excess blob gas, and beacon root rules" {
    var context: TestContext = undefined;
    try context.init(&.{.ecotone});
    var validator = context.validator();
    var value = context.payload(.v3, 4);
    value.blob_gas_used = 1;
    try context.rehash(&value);
    var envelope = try context.sign(value);
    try testing.expectError(error.BlobGasUsed, validator.validate(&envelope, now_test));
    value = context.payload(.v3, 4);
    value.excess_blob_gas = 1;
    try context.rehash(&value);
    envelope = try context.sign(value);
    try testing.expectError(error.ExcessBlobGas, validator.validate(&envelope, now_test));
    envelope.parent_beacon_block_root = null;
    envelope.payload.excess_blob_gas = 0;
    const missing_root = check_version_fields(&context.config, &envelope);
    try testing.expectError(error.ParentBeaconRoot, missing_root);
    // Jovian's DA footprint allows blob gas used.
    try context.init(&.{.jovian});
    validator = context.validator();
    value = context.payload(.v4, 4);
    value.blob_gas_used = 9;
    try context.rehash(&value);
    envelope = try context.sign(value);
    try validator.validate(&envelope, now_test);
    // A v1 payload after Isthmus cannot carry the requests hash contiguously.
    value = context.payload(.v1, 5);
    try testing.expectError(error.BlockHash, block_hash(&context.config, &value, null));
}

test "validity: at most five blocks per height" {
    var context: TestContext = undefined;
    try context.init(&.{.ecotone});
    var validator = context.validator();
    var first: block.Envelope = undefined;
    for (0..blocks_per_height_max) |index| {
        var value = context.payload(.v3, 7);
        value.gas_used = index;
        try context.rehash(&value);
        const envelope = try context.sign(value);
        try validator.validate(&envelope, now_test);
        if (index == 0) first = envelope;
    }
    var value = context.payload(.v3, 7);
    value.gas_used = 99;
    try context.rehash(&value);
    const sixth = try context.sign(value);
    try testing.expectError(error.TooManyBlocks, validator.validate(&sixth, now_test));
    // A full height reports TooManyBlocks even for a seen hash, like base/base.
    try testing.expectError(error.TooManyBlocks, validator.seen.check(7, first.payload.block_hash));
    try validator.validate(&(try context.valid(.v3, 8)), now_test);
}

test "validity: seen table prunes the lowest height when full" {
    const seen = try testing.allocator.create(SeenHashes);
    defer testing.allocator.destroy(seen);
    seen.* = .{};
    var height: u64 = 100;
    while (height < 100 + seen_heights_max) : (height += 1) {
        try seen.check(height, B256.zero);
        seen.insert(height, B256.zero);
    }
    try testing.expectEqual(seen_heights_max - 1, seen.len);
    try seen.check(100, B256.zero); // height 100 was pruned
    try testing.expectError(error.BlockSeen, seen.check(101, B256.zero));
    seen.insert(5, B256.zero); // the new lowest height is pruned at once
    try seen.check(5, B256.zero);
    try testing.expectEqual(seen_heights_max - 1, seen.len);
}

test "validity: streamed transactions root equals the ordered trie root" {
    var prng = Prng.init(0x7478_726f);
    var storage: [64 * 300]u8 = undefined;
    var list_bytes: [64 * 300 + 300 * 4]u8 = undefined;
    var items: [300][]const u8 = undefined;
    for ([_]usize{ 0, 1, 2, 127, 128, 129, 300 }) |count| {
        for (items[0..count], 0..) |*item, index| {
            const slot = storage[index * 64 ..][0..@intCast(prng.range(1, 64))];
            prng.fill(slot);
            item.* = slot;
        }
        const list = ssz.Transactions.encode(&list_bytes, items[0..count]);
        const expected = ordered.ordered_trie_root(items[0..count]);
        try testing.expectEqualSlices(u8, &expected, &transactions_root(list).bytes);
    }
}

fn fuzz_validate(context: *TestContext, smith: *std.testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    const version: ssz.Version = @fromBackingInt(@intCast(1 + prng.below(4)));
    var envelope = try context.valid(version, prng.below(16));
    const raw = std.mem.asBytes(&envelope.payload.gas_used);
    if (prng.chance(1, 2)) raw[@intCast(prng.below(8))] ^= prng.int(u8) | 1;
    if (prng.chance(1, 4)) envelope.signature[@intCast(prng.below(65))] ^= 0x10;
    var validator = context.validator();
    const now = now_test - 70 + prng.below(140);
    const result = validator.validate(&envelope, now);
    if (acceptance(result) == .accept) try testing.expectEqual(@as(u32, 1), validator.seen.len);
}

test "validity: fuzz validation of mutated envelopes" {
    const context = try testing.allocator.create(TestContext);
    defer testing.allocator.destroy(context);
    try context.init(&.{.ecotone});
    try fuzz.run(context, fuzz_validate, .{ .iterations = 64 });
}

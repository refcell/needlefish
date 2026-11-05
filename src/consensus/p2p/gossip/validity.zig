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
//!   5. Denim schedule (`BaseTimeUpdateTx::validate_block_timestamp`): once sub-second
//!      blocks are active, the timestamp seconds match the schedule and transaction 1 is
//!      the BaseTime metadata deposit carrying the scheduled millisecond part
//!   6. at most 5 distinct blocks per height, and a block already seen is ignored
//!
//! Every failure is a gossipsub Reject except an already seen block, which is Ignore.
//!
//! Deviations: transactions decode with `common/consensus` `Envelope`, which matches
//! `BaseTxEnvelope` (EIP-8130 type 0x79 included); EIP-4844 (type 0x03) is rejected
//! explicitly. A v1/v2 payload
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
const base_time = consensus_types.base_time;
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
    /// A sub-second block's timestamp or BaseTime deposit does not match the Denim schedule.
    BaseTimeSchedule,
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

/// Failure reasons, labeled like base/base `block_validation_failed`.
pub const Reason = enum(u8) {
    timestamp_future,
    timestamp_past,
    invalid_hash,
    invalid_signature,
    invalid_signer,
    too_many_blocks,
    block_seen,
    invalid_block,
    invalid_base_time_schedule,
    parent_beacon_root,
    blob_gas_used,
    excess_blob_gas,
    withdrawals_root,
};

/// Maps a validation error to its metric reason; `timestamp` splits future from past.
pub fn reason_of(err: Error, timestamp: u64, now_seconds: u64) Reason {
    const reason: Reason = switch (err) {
        error.Timestamp => if (timestamp > now_seconds +| timestamp_future_max_seconds)
            .timestamp_future
        else
            .timestamp_past,
        error.Signature => .invalid_signature,
        error.Signer => .invalid_signer,
        error.ExtraData, error.BaseFeeOverflow, error.Transaction => .invalid_block,
        error.BlockHash => .invalid_hash,
        error.Withdrawals => .withdrawals_root,
        error.BlobGasUsed => .blob_gas_used,
        error.ExcessBlobGas => .excess_blob_gas,
        error.ParentBeaconRoot => .parent_beacon_root,
        error.BaseTimeSchedule => .invalid_base_time_schedule,
        error.TooManyBlocks => .too_many_blocks,
        error.BlockSeen => .block_seen,
    };
    assert((err == error.Timestamp) ==
        (reason == .timestamp_future or reason == .timestamp_past));
    return reason;
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
        if (item[0] == @backingInt(consensus_types.tx.TxType.eip4844)) {
            return error.Transaction;
        }
        _ = consensus_types.Envelope.decode(item) catch return error.Transaction;
    }
    assert(index == transactions.count);
}

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
    const root = transactions_root(payload.transactions);
    const header = header_from_payload(config, payload, parent_beacon_block_root, root);
    if (!header.optionals_contiguous()) return error.BlockHash;
    return header.hash();
}

/// The block header a payload describes (alloy `try_into_block` header mapping).
pub fn header_from_payload(
    config: *const RollupConfig,
    payload: *const ssz.ExecutionPayload,
    parent_beacon_block_root: ?B256,
    transactions_root_value: B256,
) Header {
    assert(payload.base_fee_per_gas <= std.math.maxInt(u64));
    assert(payload.extra_data.len <= ssz.extra_data_size_max);
    var header: Header = .{
        .parent_hash = payload.parent_hash,
        .beneficiary = payload.fee_recipient,
        .state_root = payload.state_root,
        .transactions_root = transactions_root_value,
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
    assert(header.base_fee_per_gas != null);
    return header;
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

/// The Denim sub-second schedule check (base/base `validate_block_timestamp`). Passes
/// before Denim or on chains without a schedule.
pub fn check_base_time(
    config: *const RollupConfig,
    payload: *const ssz.ExecutionPayload,
) Error!void {
    const schedule = config.denim_timestamp_schedule() orelse return;
    const blocks = payload.block_number -| schedule.genesis_block_number;
    if (blocks < schedule.denim_activation_block_number()) return;
    const expected_ms = schedule.block_timestamp_ms(payload.block_number);
    const expected_millis_part: u16 = @intCast(expected_ms % 1_000);
    const second: ?consensus_types.Envelope = if (payload.transactions.count < 2)
        null
    else
        consensus_types.Envelope.decode(payload.transactions.get(1)) catch
            return error.BaseTimeSchedule;
    base_time.validate_block_timestamp(
        second,
        payload.block_number,
        payload.timestamp,
        expected_ms / 1_000,
        expected_millis_part,
    ) catch return error.BaseTimeSchedule;
    assert(expected_millis_part < 1_000);
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
        try check_base_time(validator.config, payload);
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
    const bad_lists = [_][]const []const u8{
        &.{""}, &.{"\x02\xc0"}, &.{"\x03\xc0"}, &.{"\xff"}, &.{"\x79\x01"},
    };
    for (bad_lists) |items| {
        value = context.payload(.v2, 3);
        value.transactions = ssz.Transactions.encode(&tx_bytes, items);
        try testing.expectError(error.Transaction, block_hash(&context.config, &value, null));
    }
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

/// Payload at `number` with transactions [L1 info stand-in, BaseTime deposit(millis)].
fn base_time_payload(
    storage: *[1024]u8,
    number: u64,
    timestamp: u64,
    millis_part: ?u16,
) ssz.ExecutionPayload {
    const first: consensus_types.Envelope = .{ .deposit = .{
        .source_hash = .{ .bytes = @splat(1) },
        .from = .zero,
        .to = .create,
        .mint = 0,
        .value = 0,
        .gas_limit = 1_000_000,
        .is_system_transaction = false,
        .input = "l1info",
    } };
    var calldata: [base_time.calldata_length]u8 = undefined;
    var items: [2][]const u8 = undefined;
    items[0] = first.encode_to(storage[512..768]);
    var count: usize = 1;
    if (millis_part) |millis| {
        calldata = base_time.encode_calldata(millis);
        const second: consensus_types.Envelope = .{
            .deposit = base_time.deposit(number, &calldata),
        };
        items[1] = second.encode_to(storage[768..]);
        count = 2;
    }
    return .{
        .version = .v3,
        .block_number = number,
        .timestamp = timestamp,
        .transactions = ssz.Transactions.encode(storage[0..512], items[0..count]),
    };
}

fn base_time_config() RollupConfig {
    var config: RollupConfig = .{ .l2_chain_id = chain_id_test, .block_time = 2 };
    config.genesis.l2_time = 1_000;
    config.upgrades.set(.denim, 1_010); // Activation block 5 at 1010 s; then 200 ms blocks.
    return config;
}

test "validity: Denim BaseTime schedule" {
    const config = base_time_config();
    var storage: [1024]u8 = undefined;
    // Block 6 is 200 ms after the activation block: 1010 s + 200 ms.
    try check_base_time(&config, &base_time_payload(&storage, 6, 1_010, 200));
    try check_base_time(&config, &base_time_payload(&storage, 10, 1_011, 0));
    const wrong_millis = base_time_payload(&storage, 6, 1_010, 400);
    try testing.expectError(error.BaseTimeSchedule, check_base_time(&config, &wrong_millis));
    const wrong_seconds = base_time_payload(&storage, 6, 1_011, 200);
    try testing.expectError(error.BaseTimeSchedule, check_base_time(&config, &wrong_seconds));
    const missing = base_time_payload(&storage, 6, 1_010, null);
    try testing.expectError(error.BaseTimeSchedule, check_base_time(&config, &missing));
    // Wrong block number in the deposit source hash.
    var shifted = base_time_payload(&storage, 7, 1_010, 200);
    shifted.block_number = 6;
    try testing.expectError(error.BaseTimeSchedule, check_base_time(&config, &shifted));
    // Before activation, and on chains without Denim, nothing is checked.
    try check_base_time(&config, &base_time_payload(&storage, 4, 9, null));
    const plain: RollupConfig = .{ .l2_chain_id = chain_id_test, .block_time = 2 };
    try check_base_time(&plain, &base_time_payload(&storage, 6, 1, null));
}

test "validity: seeded fuzz of the BaseTime schedule check" {
    const config = base_time_config();
    var storage: [1024]u8 = undefined;
    var prng = Prng.init(0xba5e);
    const random = prng.random();
    for (0..500) |_| {
        const number = random.uintLessThan(u64, 64);
        const timestamp = 990 + random.uintLessThan(u64, 40);
        const millis: ?u16 = if (random.boolean()) 200 * random.uintLessThan(u16, 5) else null;
        const payload = base_time_payload(&storage, number, timestamp, millis);
        const result = check_base_time(&config, &payload);
        const expected_ms = config.l2_block_timestamp_ms(number);
        const matches = timestamp == expected_ms / 1_000 and
            millis != null and millis.? == expected_ms % 1_000;
        if (number < 5 or matches) try result else try testing.expectError(
            error.BaseTimeSchedule,
            result,
        );
    }
}

test "validity: block hash of a real Base mainnet block (30000000)" {
    // Header fields of Base mainnet block 30000000 from the public base/base fixture
    // `crates/execution/flashblocks-node/benches/fixtures/base_mainnet_blocks.json`; its
    // 1006 transactions are represented by the published transactions root.
    var config: RollupConfig = .{ .l2_chain_id = 8453, .block_time = 2 };
    config.upgrades = .base_mainnet;
    var bloom: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &bloom,
        "" ++
            "03a8022a41c49951880a3009e6a080d611623abc894844000784ca90e78ee57827fcd32130894504" ++
            "46028051140e95ad64589a3506286231d773831de0fedf4e8465243a2252a46d9bcbc41e9102ab2d" ++
            "82cf68d0d04d84ab77d2282c87a0ab4039c90837ba4e8c90600d252329500e07e50034466e1fbe82" ++
            "30e7ac54483a2389806c31ed8b0a10dcc1c547042c3f3c12081af57169350afc992b8cc6314c9c22" ++
            "4b801a7788b1d873306019423050c3033ea950c81dff528e154203711a406a87ec28949b25410561" ++
            "0481b93d407391fb4ca109012f26021320b3e4c7422c65d443d71a1121a5a658f85b03ba631315b1" ++
            "91839102439ce172a3464520284d2835",
    );
    const payload: ssz.ExecutionPayload = .{
        .version = .v3,
        .parent_hash = try hex_b256(
            "6831d48969d8d6d6198ddd60bbdb233f0a002f9674d3ca27f1def0d13ee19570",
        ),
        .fee_recipient = .{ .bytes = (try hex_b256(
            "0000000000000000000000004200000000000000000000000000000000000011",
        )).bytes[12..].* },
        .state_root = try hex_b256(
            "013a354fa6aed2264f2009c7b2ac5700f67e55531518cd6bc65a0b8e91298b38",
        ),
        .receipts_root = try hex_b256(
            "5b70c6a3f036dbe5411c731e48a22beb5893151686e980c2144bd23916ce2d7b",
        ),
        .logs_bloom = .{ .bytes = bloom },
        .prev_randao = try hex_b256(
            "c355ef1002b862857745d465014cb7c33a3ed910da3223487f1bf4104f66645e",
        ),
        .block_number = 30000000,
        .gas_limit = 140000000,
        .gas_used = 59041113,
        .timestamp = 1746789347,
        .extra_data = &.{ 0x00, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x02 },
        .base_fee_per_gas = 2388680,
    };
    const beacon_root = try hex_b256(
        "b5aa7923b1b2b397887dc40ebc9234e4bc4c365d00473416b40503d440a14f3b",
    );
    const transactions_root_value = try hex_b256(
        "9e78d4f68f59d302cbf5bfdef5666e4be161942e560cb3519b9fb0b95797d130",
    );
    const header = header_from_payload(&config, &payload, beacon_root, transactions_root_value);
    try testing.expect(header.requests_hash == null); // Before Isthmus.
    const expected = try hex_b256(
        "4153b494cd159df8d742381b13f0523d6f5620151b025cb62fcb2f4e5f898697",
    );
    try testing.expect(header.hash().eql(expected));
}

fn hex_b256(text: []const u8) !B256 {
    var result: B256 = undefined;
    _ = try std.fmt.hexToBytes(&result.bytes, text);
    return result;
}

test "validity: EIP-8130 transactions decode, malformed ones reject" {
    const eip8130 = consensus_types.eip8130;
    const auth: [65]u8 = @splat(0x11);
    const envelope: consensus_types.Envelope = .{ .eip8130 = .{
        .tx = .{ .chain_id = chain_id_test, .nonce_sequence = 1, .gas_limit = 50_000 },
        .sender_auth = &auth,
    } };
    var tx_buffer: [256]u8 = undefined;
    const encoded = envelope.encode_to(&tx_buffer);
    try testing.expectEqual(eip8130.tx_type, encoded[0]);
    var storage: [512]u8 = undefined;
    try check_transactions(ssz.Transactions.encode(&storage, &.{encoded}));
    const truncated = encoded[0 .. encoded.len - 1];
    try testing.expectError(
        error.Transaction,
        check_transactions(ssz.Transactions.encode(&storage, &.{truncated})),
    );
    try testing.expectError(
        error.Transaction,
        check_transactions(ssz.Transactions.encode(&storage, &.{&.{eip8130.tx_type}})),
    );
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

test "validity: reason_of follows base/base labels" {
    const now = 1_000_000;
    try testing.expectEqual(Reason.timestamp_future, reason_of(error.Timestamp, now + 6, now));
    try testing.expectEqual(Reason.timestamp_past, reason_of(error.Timestamp, now - 61, now));
    try testing.expectEqual(Reason.invalid_hash, reason_of(error.BlockHash, now, now));
    try testing.expectEqual(Reason.invalid_block, reason_of(error.Transaction, now, now));
    try testing.expectEqual(Reason.withdrawals_root, reason_of(error.Withdrawals, now, now));
    try testing.expectEqual(Reason.block_seen, reason_of(error.BlockSeen, now, now));
    try testing.expectEqual(
        Reason.invalid_base_time_schedule,
        reason_of(error.BaseTimeSchedule, now, now),
    );
}

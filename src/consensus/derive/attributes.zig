//! The stateful payload attributes builder: turns an L2 parent and an L1 epoch into the
//! payload attributes of the next L2 block.
//!
//! Transaction order: the L1 info deposit, then (from Denim) the `BaseTime` deposit, then
//! user deposits of the epoch's first block, then the network upgrade transactions of every
//! upgrade activating in this block (Ecotone, Fjord, Isthmus, Jovian).
//!
//! Mirrors base/base `crates/consensus/derive/src/attributes/stateful.rs`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../protocol/root.zig");
const engine_attributes = @import("../../execution/payload/attributes.zig");
const errors = @import("errors.zig");
const upgrades = @import("upgrades.zig");

const Address = primitives.Address;
const B256 = primitives.B256;
const BlockId = protocol.BlockId;
const L2BlockInfo = protocol.L2BlockInfo;
const RollupConfig = protocol.RollupConfig;
const SystemConfig = protocol.SystemConfig;
const Feature = protocol.Feature;
const Upgrade = protocol.Upgrade;
const l1_info = protocol.l1_info;
const deposits = protocol.deposits;
const L1Header = l1_info.L1Header;
const L1BlobSchedule = l1_info.L1BlobSchedule;
const Receipt = protocol.log.Receipt;
const Error = errors.Error;

pub const Withdrawal = engine_attributes.Withdrawal;

pub const sequencer_fee_vault = Address.comptime_hex(
    "0x4200000000000000000000000000000000000011",
);
pub const base_time_address = Address.comptime_hex(
    "0x4200000000000000000000000000000000000030",
);
/// `setTimestampMillisPart(uint16)`.
pub const base_time_selector: [4]u8 = .{ 0x86, 0xbd, 0xf3, 0x94 };
pub const base_time_calldata_length: u32 = 4 + 32;
pub const base_time_block_interval_ms: u16 = 200;
/// Denim divides the gas limit and multiplies the EIP-1559 denominator by this factor on its
/// activation block, preserving gas throughput per second at ten times the block rate.
pub const denim_gas_parameter_scaling_factor: u32 = 10;

/// Contract-backed upgrades (base/base `BaseUpgrade::CONTRACT_VARIANTS`): every upgrade
/// with an activation timestamp except the execution-only Bedrock and the unregistered Zenith.
pub const contract_upgrades = [_]Upgrade{
    .regolith, .canyon,   .delta,                .ecotone, .fjord,
    .granite,  .holocene, .pectra_blob_schedule, .isthmus, .jovian,
    .azul,     .beryl,    .cobalt,               .denim,   .everest,
};

const upgrade_forks = [_]struct { Feature, upgrades.Fork }{
    .{ .ecotone_upgrade_transactions, .ecotone },
    .{ .fjord_upgrade_transactions, .fjord },
    .{ .isthmus_upgrade_transactions, .isthmus },
    .{ .jovian_upgrade_transactions, .jovian },
};

comptime {
    assert(contract_upgrades.len == 15);
    assert(upgrade_forks.len == std.enums.values(upgrades.Fork).len);
}

/// OP Stack payload attributes (base/base `BasePayloadAttributes`). The builder always sets
/// the OP extension fields, so `transactions`, `no_tx_pool` and `gas_limit` are not optional.
///
/// Ownership: `transactions` and every element are allocated with the builder's allocator
/// and released by `deinit`. `withdrawals` is a static empty slice (never freed).
pub const PayloadAttributes = struct {
    timestamp: u64,
    prev_randao: B256,
    suggested_fee_recipient: Address,
    /// Empty from Canyon on, null before.
    withdrawals: ?[]const Withdrawal,
    /// From Ecotone on: the L1 origin's parent beacon root, or zero when it has none.
    parent_beacon_block_root: ?B256,
    /// EIP-2718 encoded transactions.
    transactions: [][]u8,
    no_tx_pool: bool,
    gas_limit: u64,
    /// Holocene `eip1559Params`.
    eip1559_params: ?[8]u8,
    /// Jovian minimum base fee.
    min_base_fee: ?u64,

    pub fn deinit(attributes: *PayloadAttributes, allocator: std.mem.Allocator) void {
        free_transactions(allocator, attributes.transactions);
        attributes.transactions = &.{};
        assert(attributes.transactions.len == 0);
    }

    /// Engine API view; borrows `transactions`.
    pub fn engine(attributes: *const PayloadAttributes) engine_attributes.PayloadAttributes {
        assert(attributes.transactions.len > 0);
        assert(attributes.no_tx_pool);
        return .{
            .timestamp = attributes.timestamp,
            .prev_randao = attributes.prev_randao,
            .suggested_fee_recipient = attributes.suggested_fee_recipient,
            .withdrawals = attributes.withdrawals,
            .parent_beacon_block_root = attributes.parent_beacon_block_root,
            .transactions = attributes.transactions,
            .no_tx_pool = attributes.no_tx_pool,
            .gas_limit = attributes.gas_limit,
            .eip1559_params = attributes.eip1559_params,
            .min_base_fee = attributes.min_base_fee,
        };
    }
};

fn free_transactions(allocator: std.mem.Allocator, transactions: []const []u8) void {
    for (transactions) |tx| {
        assert(tx.len > 0);
        allocator.free(tx);
    }
    allocator.free(transactions);
}

fn free_list(allocator: std.mem.Allocator, list: *std.ArrayList([]u8)) void {
    for (list.items) |tx| {
        assert(tx.len > 0);
        allocator.free(tx);
    }
    list.deinit(allocator);
    list.* = .empty;
    assert(list.items.len == 0);
}

/// The L1 origin of the block being built.
const Origin = struct {
    header: L1Header,
    sequence_number: u64,
};

/// Builds payload attributes from L1 data and L2 system configs.
///
/// `chain` provides:
///   fn l1_header_by_hash(self, hash: Hash) ProviderError!L1Header
///   fn l1_receipts_by_hash(self, hash: Hash) ProviderError![]const Receipt
///   fn system_config_by_l2_hash(self, hash: Hash) ProviderError!SystemConfig
pub const AttributesBuilder = struct {
    allocator: std.mem.Allocator,
    rollup: *const RollupConfig,
    blob_schedule: *const L1BlobSchedule,
    /// Locally known system config for an exact L2 parent; avoids a provider round trip.
    parent_system_config: ?ParentSystemConfig = null,

    pub const ParentSystemConfig = struct { parent: L2BlockInfo, config: SystemConfig };

    pub fn init(
        allocator: std.mem.Allocator,
        rollup: *const RollupConfig,
        blob_schedule: *const L1BlobSchedule,
    ) AttributesBuilder {
        return .{ .allocator = allocator, .rollup = rollup, .blob_schedule = blob_schedule };
    }

    pub fn seed_parent_system_config(
        builder: *AttributesBuilder,
        parent: L2BlockInfo,
        config: SystemConfig,
    ) void {
        builder.parent_system_config = .{ .parent = parent, .config = config };
        assert(builder.parent_system_config.?.parent.eql(parent));
    }

    /// Builds the attributes of the child of `l2_parent` with L1 origin `epoch`. The caller
    /// owns the result and releases it with `PayloadAttributes.deinit(builder.allocator)`.
    pub fn prepare_payload_attributes(
        builder: *AttributesBuilder,
        chain: anytype,
        l2_parent: L2BlockInfo,
        epoch: BlockId,
    ) Error!PayloadAttributes {
        const allocator = builder.allocator;
        const rollup = builder.rollup;
        if (l2_parent.block_info.number == std.math.maxInt(u64)) return error.AttributesBuilder;
        const target_number = l2_parent.block_info.number + 1;
        const target_ms = rollup.l2_block_timestamp_ms(target_number);
        const target_time = target_ms / 1_000;
        const target_millis: u16 = @intCast(target_ms % 1_000);
        const parent_time = l2_parent.block_info.timestamp;

        var config = try builder.resolve_system_config(chain, l2_parent, target_number);
        var user_deposits: std.ArrayList([]u8) = .empty;
        defer free_list(allocator, &user_deposits);
        const origin = try builder.resolve_origin(chain, l2_parent, epoch, &config, &user_deposits);
        assert(origin.sequence_number == 0 or user_deposits.items.len == 0);

        // The L1 origin must keep the L2 time at or after the L1 time.
        if (target_time < origin.header.timestamp) return error.BadTimestamp;

        if (rollup.is_feature_first_block(.subsecond_blocks, target_time, parent_time)) {
            config.gas_limit /= denim_gas_parameter_scaling_factor;
            if (config.eip1559_denominator) |denominator| {
                config.eip1559_denominator = denominator *| denim_gas_parameter_scaling_factor;
            }
        }

        const transactions = try builder.assemble_transactions(.{
            .origin = origin,
            .config = &config,
            .parent_time = parent_time,
            .target_time = target_time,
            .target_number = target_number,
            .target_millis = target_millis,
        }, &user_deposits);
        assert(user_deposits.items.len == 0);
        return builder.finish(origin.header, &config, parent_time, target_time, transactions);
    }

    /// Whether a contract-backed upgrade activates within the last two blocks, in which case
    /// a payload-derived config may be incomplete and the full config must be fetched.
    fn requires_system_config_refresh(rollup: *const RollupConfig, target_number: u64) bool {
        const target_time = rollup.l2_block_timestamp(target_number);
        const two_blocks_back_time = rollup.l2_block_timestamp(target_number -| 2);
        assert(two_blocks_back_time <= target_time);
        for (contract_upgrades) |upgrade| {
            const activation = rollup.upgrades.get(upgrade) orelse continue;
            if (two_blocks_back_time < activation and activation <= target_time) return true;
        }
        return false;
    }

    fn resolve_system_config(
        builder: *const AttributesBuilder,
        chain: anytype,
        l2_parent: L2BlockInfo,
        target_number: u64,
    ) Error!SystemConfig {
        assert(target_number == l2_parent.block_info.number + 1);
        if (builder.parent_system_config) |seed| {
            if (seed.parent.eql(l2_parent) and
                !requires_system_config_refresh(builder.rollup, target_number))
            {
                return seed.config;
            }
        }
        return chain.system_config_by_l2_hash(l2_parent.block_info.hash);
    }

    /// Fetches the L1 origin header. On an epoch change also derives the user deposits into
    /// `user_deposits` and applies the epoch's system config updates to `config`.
    fn resolve_origin(
        builder: *const AttributesBuilder,
        chain: anytype,
        l2_parent: L2BlockInfo,
        epoch: BlockId,
        config: *SystemConfig,
        user_deposits: *std.ArrayList([]u8),
    ) Error!Origin {
        assert(user_deposits.items.len == 0);
        const rollup = builder.rollup;
        if (l2_parent.l1_origin.number != epoch.number) {
            const header = try chain.l1_header_by_hash(epoch.hash);
            if (!l2_parent.l1_origin.hash.eql(header.parent_hash)) {
                return error.EpochParentMismatch;
            }
            // Receipts stay valid only until the next provider call: consume them now.
            const receipts: []const Receipt = try chain.l1_receipts_by_hash(epoch.hash);
            try builder.derive_deposits(epoch.hash, receipts, user_deposits);
            const ecotone = rollup.is_feature_active(.blob_aware_l1_fees, header.timestamp);
            // Malformed updates are skipped (base/base logs and continues).
            _ = config.update_with_receipts(receipts, rollup.l1_system_config_address, ecotone);
            return .{ .header = header, .sequence_number = 0 };
        }
        if (!l2_parent.l1_origin.hash.eql(epoch.hash)) return error.L1OriginMismatch;
        const header = try chain.l1_header_by_hash(epoch.hash);
        const sequence_number = std.math.add(u64, l2_parent.sequence_number, 1) catch {
            return error.AttributesBuilder;
        };
        assert(sequence_number > 0);
        return .{ .header = header, .sequence_number = sequence_number };
    }

    /// Encodes every user deposit of the epoch's receipts (base/base `derive_deposits`).
    fn derive_deposits(
        builder: *const AttributesBuilder,
        block_hash: B256,
        receipts: []const Receipt,
        user_deposits: *std.ArrayList([]u8),
    ) Error!void {
        var logs_total: u64 = 0;
        for (receipts) |receipt| logs_total += receipt.logs.len;
        var iterator: deposits.DepositIterator = .{
            .receipts = receipts,
            .deposit_contract = builder.rollup.deposit_contract_address,
            .l1_block_hash = block_hash,
        };
        // Each deposit consumes at least one log, so this bounds the iteration.
        for (0..logs_total + 1) |_| {
            const tx = (iterator.next() catch return error.BadEncoding) orelse break;
            const encoded = try builder.allocator.alloc(u8, tx.encoded_length());
            errdefer builder.allocator.free(encoded);
            _ = tx.encode(encoded);
            try user_deposits.append(builder.allocator, encoded);
        } else unreachable; // Proof: the iterator returns null after the last log.
        assert(user_deposits.items.len <= logs_total);
    }

    const Target = struct {
        origin: Origin,
        config: *const SystemConfig,
        parent_time: u64,
        target_time: u64,
        target_number: u64,
        target_millis: u16,
    };

    /// Returns the owned transaction list; on success `user_deposits` is moved and empty.
    fn assemble_transactions(
        builder: *const AttributesBuilder,
        target: Target,
        user_deposits: *std.ArrayList([]u8),
    ) Error![][]u8 {
        const allocator = builder.allocator;
        const rollup = builder.rollup;
        const base_time_active = rollup.is_feature_active(.subsecond_blocks, target.target_time);
        var list: std.ArrayList([]u8) = .empty;
        errdefer free_list(allocator, &list);
        try list.ensureTotalCapacity(
            allocator,
            1 + @as(usize, @intFromBool(base_time_active)) + user_deposits.items.len +
                upgrades.transactions_max,
        );
        list.appendAssumeCapacity(try builder.encode_l1_info(target));
        if (base_time_active) {
            const number = target.target_number;
            const millis = target.target_millis;
            list.appendAssumeCapacity(try encode_base_time(allocator, number, millis));
        }
        list.appendSliceAssumeCapacity(user_deposits.items);
        user_deposits.clearRetainingCapacity(); // Ownership moved into `list`.
        for (upgrade_forks) |entry| {
            if (!rollup.is_feature_first_block(entry[0], target.target_time, target.parent_time)) {
                continue;
            }
            try upgrades.append_transactions(allocator, &list, entry[1]);
        }
        assert(list.items.len >= 1);
        return list.toOwnedSlice(allocator);
    }

    fn encode_l1_info(builder: *const AttributesBuilder, target: Target) Error![]u8 {
        const info = l1_info.build(
            builder.rollup,
            builder.blob_schedule,
            target.config,
            target.origin.sequence_number,
            target.origin.header,
            target.parent_time,
            target.target_time,
        );
        assert(info.sequence_number == target.origin.sequence_number);
        var calldata: [l1_info.calldata_length_max]u8 = undefined;
        const tx = info.deposit_tx(builder.rollup, target.target_time, &calldata);
        const encoded = try builder.allocator.alloc(u8, tx.encoded_length());
        _ = tx.encode(encoded);
        assert(encoded[0] == deposits.deposit_tx_type);
        return encoded;
    }

    fn finish(
        builder: *const AttributesBuilder,
        header: L1Header,
        config: *const SystemConfig,
        parent_time: u64,
        target_time: u64,
        transactions: [][]u8,
    ) PayloadAttributes {
        assert(transactions.len >= 1);
        const rollup = builder.rollup;
        const withdrawals: ?[]const Withdrawal =
            if (rollup.is_feature_active(.withdrawals, target_time)) &.{} else null;
        const beacon_root: ?B256 = if (rollup.is_feature_active(.beacon_roots, target_time))
            header.parent_beacon_block_root orelse .zero
        else
            null;
        const min_base_fee: ?u64 = if (rollup.is_feature_active(.min_base_fee, target_time))
            config.min_base_fee orelse 0
        else
            null;
        const result: PayloadAttributes = .{
            .timestamp = target_time,
            .prev_randao = header.mix_hash,
            .suggested_fee_recipient = sequencer_fee_vault,
            .withdrawals = withdrawals,
            .parent_beacon_block_root = beacon_root,
            .transactions = transactions,
            .no_tx_pool = true,
            .gas_limit = config.gas_limit,
            .eip1559_params = config.eip1559_params(rollup, parent_time, target_time),
            .min_base_fee = min_base_fee,
        };
        assert(result.timestamp >= header.timestamp);
        return result;
    }
};

/// Encodes the Denim `BaseTime` deposit carrying the block's millisecond component.
pub fn encode_base_time(
    allocator: std.mem.Allocator,
    l2_block_number: u64,
    millis_part: u16,
) Error![]u8 {
    if (millis_part >= 1_000 or millis_part % base_time_block_interval_ms != 0) {
        return error.AttributesBuilder;
    }
    var calldata: [base_time_calldata_length]u8 = @splat(0);
    calldata[0..4].* = base_time_selector;
    std.mem.writeInt(u16, calldata[34..36], millis_part, .big);
    const tx: deposits.DepositTx = .{
        .source_hash = deposits.base_time_source_hash(l2_block_number),
        .from = deposits.depositor_account,
        .to = base_time_address,
        .gas_limit = deposits.regolith_system_tx_gas,
        .is_system_transaction = false,
        .input = &calldata,
    };
    const encoded = try allocator.alloc(u8, tx.encoded_length());
    _ = tx.encode(encoded);
    assert(encoded.len > base_time_calldata_length);
    return encoded;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;
const consensus_types = @import("../../common/consensus/root.zig");
const TestChain = @import("test_chain.zig").TestChain;
const system_config = protocol.system_config;
const Log = protocol.log.Log;

const deposit_contract = Address.comptime_hex("0x1111111111111111111111111111111111111111");
const config_address = Address.comptime_hex("0x1111111111111111111111111111111111111111");

fn padded_word(byte: u8) B256 {
    var word: [32]u8 = @splat(0);
    word[31] = byte;
    return .init(word);
}

/// A valid `TransactionDeposited` log body (base/base `generate_valid_log`).
const deposit_log_data: [192]u8 = data: {
    var data: [192]u8 = @splat(0);
    data[31] = 32;
    data[63] = 128;
    data[95] = 10; // mint
    data[127] = 100; // value
    std.mem.writeInt(u64, data[128..136], 1000, .big); // gas
    data[136] = 1; // is_creation
    break :data data;
};
const from_word = B256.comptime_hex(
    "0000000000000000000000002222222222222222222222222222222222222222",
);
const to_word = B256.comptime_hex(
    "0000000000000000000000003333333333333333333333333333333333333333",
);
const valid_topics = [_]B256{ deposits.transaction_deposited_topic, from_word, to_word, .zero };
const zero_from_topics = [_]B256{ deposits.transaction_deposited_topic, .zero, to_word, .zero };
const bad_topic_topics = [_]B256{ .zero, from_word, to_word, .zero };
const valid_log: Log = .{
    .address = deposit_contract,
    .topics = &valid_topics,
    .data = &deposit_log_data,
};
/// Valid receipt: two decodable deposits and one non-deposit log.
const valid_logs = [_]Log{
    valid_log,
    .{ .address = deposit_contract, .topics = &zero_from_topics, .data = &deposit_log_data },
    .{ .address = deposit_contract, .topics = &bad_topic_topics, .data = &deposit_log_data },
};
const valid_receipt: Receipt = .{ .success = true, .logs = &valid_logs };

fn config_update_data(value: u64) [96]u8 {
    var data: [96]u8 = @splat(0);
    data[31] = 32;
    data[63] = 32;
    std.mem.writeInt(u64, data[88..96], value, .big);
    return data;
}

fn config_update_topics(kind: system_config.UpdateKind) [3]B256 {
    var word: [32]u8 = @splat(0);
    std.mem.writeInt(u64, word[24..32], @backingInt(kind), .big);
    const version = system_config.config_update_version_0;
    return .{ system_config.config_update_topic, version, .init(word) };
}

fn count_deposits(receipts: []const Receipt) Error!usize {
    const rollup: RollupConfig = .{ .deposit_contract_address = deposit_contract };
    const schedule: L1BlobSchedule = .{};
    const builder = AttributesBuilder.init(testing.allocator, &rollup, &schedule);
    var list: std.ArrayList([]u8) = .empty;
    defer free_list(testing.allocator, &list);
    try builder.derive_deposits(.zero, receipts, &list);
    return list.items.len;
}

test "attributes: derive deposits" {
    try testing.expectEqual(@as(usize, 0), try count_deposits(&.{}));
    try testing.expectEqual(@as(usize, 4), try count_deposits(&.{ valid_receipt, valid_receipt }));
    const no_topics = [_]Log{.{ .address = deposit_contract, .topics = &.{}, .data = &.{} }};
    const non_deposit: Receipt = .{ .success = true, .logs = &(no_topics ++ valid_logs[1..].*) };
    const three = [_]Receipt{ valid_receipt, valid_receipt, non_deposit };
    try testing.expectEqual(@as(usize, 5), try count_deposits(&three));
    var other_logs = valid_logs;
    other_logs[0].address = .zero;
    const other: Receipt = .{ .success = true, .logs = &other_logs };
    const with_other = [_]Receipt{ valid_receipt, valid_receipt, other };
    try testing.expectEqual(@as(usize, 5), try count_deposits(&with_other));
    const failed: Receipt = .{ .success = false, .logs = &valid_logs };
    try testing.expectEqual(@as(usize, 2), try count_deposits(&.{ failed, valid_receipt }));
    const short_topics = [_]B256{deposits.transaction_deposited_topic};
    const bad = [_]Log{.{ .address = deposit_contract, .topics = &short_topics, .data = &.{} }};
    const undecodable: Receipt = .{ .success = true, .logs = &bad };
    const result = count_deposits(&.{ valid_receipt, valid_receipt, undecodable });
    try testing.expectError(error.BadEncoding, result);
    try testing.expectEqual(errors.Kind.critical, errors.kind(error.BadEncoding));
}

/// base/base `system_config_test_builder`: block time 10, parent #1 at 100 whose L1 origin
/// (time 100) is also the epoch; the child is built at `target_time`.
const Fixture = struct {
    chain: TestChain,
    rollup: RollupConfig,
    schedule: L1BlobSchedule = .{},
    parent: L2BlockInfo,

    const target_time: u64 = 110;

    fn init(fixture: *Fixture) void {
        fixture.* = .{
            .chain = TestChain.init(3, 7, 10),
            .rollup = .{ .block_time = 10, .genesis = .{ .l2_time = 90 } },
            .parent = undefined,
        };
        fixture.chain.blocks[0].timestamp = 100;
        fixture.chain.blocks[1].timestamp = 100;
        fixture.parent = .{
            .block_info = .{ .hash = padded_word(1), .number = 1, .timestamp = 100 },
            .l1_origin = fixture.chain.blocks[0].id(),
        };
        assert(fixture.rollup.l2_block_timestamp(2) == target_time);
    }

    fn builder(fixture: *Fixture) AttributesBuilder {
        return .init(testing.allocator, &fixture.rollup, &fixture.schedule);
    }

    fn build(
        fixture: *Fixture,
        attributes_builder: *AttributesBuilder,
        epoch: BlockId,
    ) Error!PayloadAttributes {
        return attributes_builder.prepare_payload_attributes(&fixture.chain, fixture.parent, epoch);
    }
};

fn decode_deposit(encoded: []const u8) !consensus_types.tx.Deposit {
    const envelope = try consensus_types.tx.Envelope.decode(encoded);
    try testing.expect(envelope == .deposit);
    return envelope.deposit;
}

test "attributes: uses only the exact parent system config seed" {
    var fixture: Fixture = undefined;
    fixture.init();
    var builder = fixture.builder();
    builder.seed_parent_system_config(fixture.parent, .{ .gas_limit = 123 });
    const epoch = fixture.parent.l1_origin;
    // No config is registered on the chain: success proves the seed was used, twice.
    for (0..2) |_| {
        var payload = try fixture.build(&builder, epoch);
        defer payload.deinit(testing.allocator);
        try testing.expectEqual(@as(u64, 123), payload.gas_limit);
    }
    // An upgrade activating in the target block forces a refresh.
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{ .gas_limit = 456 });
    fixture.rollup.upgrades.set(.fjord, Fixture.target_time);
    var refreshed = try fixture.build(&builder, epoch);
    refreshed.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 456), refreshed.gas_limit);
    // A seed for another parent is ignored and kept.
    fixture.rollup.upgrades.set(.fjord, null);
    var mismatched = fixture.parent;
    mismatched.block_info.hash = padded_word(2);
    builder.seed_parent_system_config(mismatched, .{ .gas_limit = 123 });
    var payload = try fixture.build(&builder, epoch);
    payload.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 456), payload.gas_limit);
    try testing.expect(builder.parent_system_config.?.parent.eql(mismatched));
}

test "attributes: system config for the exact parent hash" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.chain.add_system_config(padded_word(1), .{ .gas_limit = 123 });
    fixture.chain.add_system_config(padded_word(2), .{ .gas_limit = 456 });
    fixture.parent.block_info.hash = padded_word(2);
    var builder = fixture.builder();
    var payload = try fixture.build(&builder, fixture.parent.l1_origin);
    defer payload.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 456), payload.gas_limit);
}

test "attributes: epoch update applies to the parent system config seed" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.rollup.l1_system_config_address = config_address;
    const data = config_update_data(0xbeef);
    const topics = config_update_topics(.gas_limit);
    const logs = [_]Log{.{ .address = config_address, .topics = &topics, .data = &data }};
    fixture.chain.receipts[1] = &.{.{ .success = true, .logs = &logs }};
    var builder = fixture.builder();
    builder.seed_parent_system_config(fixture.parent, .{ .gas_limit = 123 });
    var payload = try fixture.build(&builder, fixture.chain.blocks[1].id());
    defer payload.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0xbeef), payload.gas_limit);
}

test "attributes: block mismatch errors reset" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
    var builder = fixture.builder();
    // New epoch whose L1 parent is not the L2 parent's origin.
    fixture.parent.l1_origin = .{ .hash = padded_word(0xff), .number = 6 };
    const epoch_reset = fixture.build(&builder, fixture.chain.blocks[1].id());
    try testing.expectError(error.EpochParentMismatch, epoch_reset);
    try testing.expectEqual(errors.Kind.reset, errors.kind(error.EpochParentMismatch));
    // Same epoch number, different hash.
    fixture.parent.l1_origin = .{ .hash = .zero, .number = 7 };
    const mismatch = fixture.build(&builder, fixture.chain.blocks[0].id());
    try testing.expectError(error.L1OriginMismatch, mismatch);
    try testing.expectEqual(errors.Kind.reset, errors.kind(error.L1OriginMismatch));
}

test "attributes: broken time invariant resets" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.rollup.genesis.l2_time = 0; // The child lands at 20, before the L1 origin at 100.
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
    var builder = fixture.builder();
    const result = fixture.build(&builder, fixture.parent.l1_origin);
    try testing.expectError(error.BadTimestamp, result);
    try testing.expectEqual(errors.Kind.reset, errors.kind(error.BadTimestamp));
}

fn denim_fixture(fixture: *Fixture, parent_number: u64, parent_time: u64) void {
    fixture.init();
    fixture.rollup.block_time = 2;
    fixture.rollup.genesis.l2_time = 98;
    fixture.rollup.upgrades.set(.denim, 102);
    fixture.parent.block_info.number = parent_number;
    fixture.parent.block_info.timestamp = parent_time;
}

test "attributes: BaseTime update at tx 1 on the Denim activation block" {
    var fixture: Fixture = undefined;
    denim_fixture(&fixture, 1, 100);
    fixture.rollup.upgrades.set(.ecotone, 102);
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
    var builder = fixture.builder();
    var payload = try fixture.build(&builder, fixture.parent.l1_origin);
    defer payload.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 102), payload.timestamp);
    try testing.expectEqual(@as(usize, 8), payload.transactions.len);
    const deposit = try decode_deposit(payload.transactions[1]);
    try testing.expect(deposit.from.eql(deposits.depositor_account));
    try testing.expect(deposit.to.call.eql(base_time_address));
    try testing.expectEqualSlices(u8, &base_time_selector, deposit.input[0..4]);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, deposit.input[34..36], .big));
    try testing.expect(deposit.source_hash.eql(deposits.base_time_source_hash(2)));
}

test "attributes: Denim subsecond block after activation" {
    var fixture: Fixture = undefined;
    denim_fixture(&fixture, 2, 102);
    fixture.rollup.upgrades.set(.ecotone, 102);
    fixture.rollup.upgrades.set(.jovian, 0);
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{
        .gas_limit = 30_000_000,
        .eip1559_denominator = 500,
        .eip1559_elasticity = 6,
        .min_base_fee = 100_000_000,
    });
    var builder = fixture.builder();
    var payload = try fixture.build(&builder, fixture.parent.l1_origin);
    defer payload.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 102_200), fixture.rollup.l2_block_timestamp_ms(3));
    try testing.expectEqual(@as(u64, 102), payload.timestamp);
    try testing.expectEqual(@as(u64, 30_000_000), payload.gas_limit);
    try testing.expectEqual([8]u8{ 0, 0, 1, 244, 0, 0, 0, 6 }, payload.eip1559_params.?);
    try testing.expectEqual(@as(?u64, 100_000_000), payload.min_base_fee);
    try testing.expectEqual(@as(usize, 2), payload.transactions.len);
    const deposit = try decode_deposit(payload.transactions[1]);
    try testing.expectEqual(@as(u16, 200), std.mem.readInt(u16, deposit.input[34..36], .big));
}

test "attributes: Denim gas transition applies after L1 system config updates" {
    var fixture: Fixture = undefined;
    denim_fixture(&fixture, 1, 100);
    fixture.rollup.l1_system_config_address = config_address;
    fixture.rollup.upgrades.set(.ecotone, 0);
    fixture.rollup.upgrades.set(.jovian, 0);
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{
        .gas_limit = 300_000_000,
        .eip1559_denominator = 50,
        .eip1559_elasticity = 6,
        .min_base_fee = 100_000_000,
    });
    const gas_data = config_update_data(400_000_000);
    const eip_data = config_update_data((40 << 32) | 8);
    const fee_data = config_update_data(200_000_000);
    const gas_topics = config_update_topics(.gas_limit);
    const eip_topics = config_update_topics(.eip1559);
    const fee_topics = config_update_topics(.min_base_fee);
    const logs = [_]Log{
        .{ .address = config_address, .topics = &gas_topics, .data = &gas_data },
        .{ .address = config_address, .topics = &eip_topics, .data = &eip_data },
        .{ .address = config_address, .topics = &fee_topics, .data = &fee_data },
    };
    fixture.chain.receipts[1] = &.{.{ .success = true, .logs = &logs }};
    var builder = fixture.builder();
    var payload = try fixture.build(&builder, fixture.chain.blocks[1].id());
    defer payload.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 40_000_000), payload.gas_limit);
    try testing.expectEqual([8]u8{ 0, 0, 1, 144, 0, 0, 0, 8 }, payload.eip1559_params.?);
    try testing.expectEqual(@as(?u64, 200_000_000), payload.min_base_fee);
}

fn expect_upgrade_txs(transactions: []const []u8, forks: []const upgrades.Fork) !void {
    var expected: std.ArrayList([]u8) = .empty;
    defer free_list(testing.allocator, &expected);
    for (forks) |fork| try upgrades.append_transactions(testing.allocator, &expected, fork);
    try testing.expectEqual(expected.items.len, transactions.len);
    for (expected.items, transactions) |want, got| try testing.expectEqualSlices(u8, want, got);
}

test "attributes: prepare payload by fork" {
    const Case = struct { ?Upgrade, u64, bool, bool, []const upgrades.Fork };
    const cases = [_]Case{
        .{ null, 0, false, false, &.{} },
        .{ .canyon, 0, true, false, &.{} },
        .{ .ecotone, Fixture.target_time, true, true, &.{.ecotone} },
        .{ .fjord, Fixture.target_time, true, true, &.{ .ecotone, .fjord } },
        .{ .isthmus, Fixture.target_time, true, true, &.{ .ecotone, .fjord, .isthmus } },
        .{ .jovian, Fixture.target_time, true, true, &.{ .ecotone, .fjord, .isthmus, .jovian } },
    };
    for (cases) |case| {
        var fixture: Fixture = undefined;
        fixture.init();
        if (case[0]) |upgrade| fixture.rollup.upgrades.set(upgrade, case[1]);
        fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
        var builder = fixture.builder();
        var payload = try fixture.build(&builder, fixture.parent.l1_origin);
        defer payload.deinit(testing.allocator);
        const l1_info_deposit = try decode_deposit(payload.transactions[0]);
        try testing.expect(l1_info_deposit.to.call.eql(deposits.l1_block_info_address));
        try expect_upgrade_txs(payload.transactions[1..], case[4]);
        try testing.expectEqual(Fixture.target_time, payload.timestamp);
        try testing.expect(payload.prev_randao.is_zero());
        try testing.expect(payload.suggested_fee_recipient.eql(sequencer_fee_vault));
        try testing.expectEqual(case[2], payload.withdrawals != null);
        try testing.expectEqual(case[3], payload.parent_beacon_block_root != null);
        if (case[3]) try testing.expect(payload.parent_beacon_block_root.?.is_zero());
        try testing.expect(payload.no_tx_pool);
        try testing.expectEqual(@as(u64, 0), payload.gas_limit);
        // Isthmus and Jovian imply Holocene, activating here: zero params on its first block.
        const holocene = case[0] == .isthmus or case[0] == .jovian;
        if (holocene) {
            try testing.expectEqual(@as([8]u8, @splat(0)), payload.eip1559_params.?);
        } else try testing.expect(payload.eip1559_params == null);
        try testing.expectEqual(case[0] == .jovian, payload.min_base_fee != null);
        const engine = payload.engine();
        try testing.expectEqual(payload.transactions.len, engine.transactions.?.len);
    }
}

test "attributes: malformed system config update is not fatal" {
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.rollup.l1_system_config_address = config_address;
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
    const topics = [_]B256{system_config.config_update_topic};
    const logs = [_]Log{.{ .address = config_address, .topics = &topics, .data = &.{} }};
    fixture.chain.receipts[1] = &.{.{ .success = true, .logs = &logs }};
    var builder = fixture.builder();
    var payload = try fixture.build(&builder, fixture.chain.blocks[1].id());
    payload.deinit(testing.allocator);
}

test "attributes: provider errors propagate and allocations are released" {
    var fixture: Fixture = undefined;
    fixture.init();
    var builder = fixture.builder();
    const missing = fixture.build(&builder, fixture.parent.l1_origin);
    try testing.expectError(error.NotFound, missing);
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
    fixture.chain.receipts[1] = &.{ valid_receipt, valid_receipt };
    fixture.rollup.deposit_contract_address = deposit_contract;
    fixture.rollup.upgrades.set(.ecotone, Fixture.target_time);
    // Every allocation failure point unwinds without leaks.
    for (0..64) |fail_index| {
        const options: testing.FailingAllocator.Config = .{ .fail_index = fail_index };
        var failing = testing.FailingAllocator.init(testing.allocator, options);
        builder.allocator = failing.allocator();
        var payload = fixture.build(&builder, fixture.chain.blocks[1].id()) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            continue;
        };
        try testing.expectEqual(@as(usize, 1 + 4 + 6), payload.transactions.len);
        payload.deinit(builder.allocator);
        break;
    } else return error.TestUnexpectedResult;
    fixture.chain.unavailable_from = 0;
    builder.allocator = testing.allocator;
    const unavailable = fixture.build(&builder, fixture.chain.blocks[1].id());
    try testing.expectError(error.NotAvailable, unavailable);
}

test "attributes: encode base time rejects unaligned millis" {
    try testing.expectError(error.AttributesBuilder, encode_base_time(testing.allocator, 1, 100));
    try testing.expectError(error.AttributesBuilder, encode_base_time(testing.allocator, 1, 1000));
    const encoded = try encode_base_time(testing.allocator, 1, 800);
    defer testing.allocator.free(encoded);
    const deposit = try decode_deposit(encoded);
    try testing.expectEqual(deposits.regolith_system_tx_gas, deposit.gas_limit);
    try testing.expect(!deposit.is_system_transaction);
}

const FuzzScenario = enum { same_epoch, next_epoch, wrong_origin_hash, wrong_epoch_parent };

const FuzzCase = struct {
    chain: TestChain,
    rollup: RollupConfig,
    schedule: L1BlobSchedule = .{},
    parent: L2BlockInfo,
    epoch: BlockId,
    scenario: FuzzScenario,
    expected_deposits: usize,

    fn init(case: *FuzzCase, prng: *Prng) void {
        case.chain = TestChain.init(4, 7, 12);
        case.rollup = .{
            .block_time = 2,
            .genesis = .{ .l2_time = prng.range(0, 50) },
            .deposit_contract_address = deposit_contract,
            .l1_system_config_address = config_address,
        };
        const parent_number = prng.range(1, 200);
        const parent_time = case.rollup.l2_block_timestamp(parent_number);
        const target_time = case.rollup.l2_block_timestamp(parent_number + 1);
        const fork_upgrades = [_]Upgrade{ .canyon, .ecotone, .fjord, .isthmus, .jovian, .denim };
        for (fork_upgrades) |upgrade| {
            if (prng.chance(1, 2)) {
                case.rollup.upgrades.set(upgrade, prng.range(0, target_time + 4));
            }
        }
        case.expected_deposits = 0;
        for (&case.chain.blocks, &case.chain.receipts, 0..) |*block, *receipts, index| {
            // L1 time usually trails the L2 child; sometimes it is ahead (BadTimestamp).
            const ahead = prng.chance(1, 8);
            block.timestamp = if (ahead) target_time + 1 else prng.range(0, target_time);
            const receipt_count = prng.below(3);
            receipts.* = ([_]Receipt{ valid_receipt, valid_receipt })[0..receipt_count];
            if (index == 2) case.expected_deposits = 2 * receipt_count;
            if (index >= 3) break;
        }
        case.scenario = prng.random().enumValue(FuzzScenario);
        case.parent = .{
            .block_info = .{
                .hash = padded_word(9),
                .number = parent_number,
                .timestamp = parent_time,
            },
            .l1_origin = case.chain.blocks[1].id(),
            .sequence_number = prng.below(100),
        };
        case.epoch = switch (case.scenario) {
            .same_epoch => case.chain.blocks[1].id(),
            .next_epoch => case.chain.blocks[2].id(),
            .wrong_origin_hash => .{ .number = 8, .hash = padded_word(3) },
            .wrong_epoch_parent => case.chain.blocks[3].id(),
        };
        case.chain.add_system_config(case.parent.block_info.hash, .{ .gas_limit = prng.int(u32) });
    }

    fn expected_error(case: *const FuzzCase) ?Error {
        const header_index: usize = switch (case.scenario) {
            .wrong_origin_hash => return error.L1OriginMismatch,
            .wrong_epoch_parent => return error.EpochParentMismatch,
            .same_epoch => 1,
            .next_epoch => 2,
        };
        const target_time = case.rollup.l2_block_timestamp(case.parent.block_info.number + 1);
        if (target_time < case.chain.blocks[header_index].timestamp) return error.BadTimestamp;
        return null;
    }
};

fn fuzz_expect_success(case: *const FuzzCase, payload: *const PayloadAttributes) !void {
    const rollup = &case.rollup;
    const parent_time = case.parent.block_info.timestamp;
    const epoch_change = case.scenario == .next_epoch;
    const sequence_number = if (epoch_change) 0 else case.parent.sequence_number + 1;
    const l1_info_deposit = try decode_deposit(payload.transactions[0]);
    try testing.expect(l1_info_deposit.to.call.eql(deposits.l1_block_info_address));
    const source = deposits.l1_info_source_hash(case.epoch.hash, sequence_number);
    try testing.expect(l1_info_deposit.source_hash.eql(source));
    var index: usize = 1;
    if (rollup.is_feature_active(.subsecond_blocks, payload.timestamp)) {
        const base_time = try decode_deposit(payload.transactions[1]);
        try testing.expect(base_time.to.call.eql(base_time_address));
        index += 1;
    }
    const user_count: usize = if (epoch_change) case.expected_deposits else 0;
    for (payload.transactions[index..][0..user_count]) |tx| {
        const deposit = try decode_deposit(tx);
        try testing.expectEqual(@as(u128, 10), deposit.mint);
    }
    index += user_count;
    var upgrade_count: usize = 0;
    for (upgrade_forks) |entry| {
        if (!rollup.is_feature_first_block(entry[0], payload.timestamp, parent_time)) continue;
        upgrade_count += upgrades.deposits_for(entry[1]).len;
    }
    try testing.expectEqual(index + upgrade_count, payload.transactions.len);
    for (payload.transactions) |tx| _ = try decode_deposit(tx);
    try testing.expect(payload.no_tx_pool);
    const canyon = rollup.is_feature_active(.withdrawals, payload.timestamp);
    try testing.expectEqual(canyon, payload.withdrawals != null);
}

test "attributes: seeded fuzz over parents and epochs" {
    var prng = Prng.init(0x5eed_a77b);
    var outcomes: [2]u32 = @splat(0);
    for (0..300) |_| {
        var case: FuzzCase = undefined;
        case.init(&prng);
        var builder = AttributesBuilder.init(testing.allocator, &case.rollup, &case.schedule);
        const expected = case.expected_error();
        const result = builder.prepare_payload_attributes(&case.chain, case.parent, case.epoch);
        var payload = result catch |err| {
            const want = expected orelse return err;
            try testing.expectEqual(want, err);
            outcomes[0] += 1;
            continue;
        };
        defer payload.deinit(testing.allocator);
        try testing.expect(expected == null);
        try fuzz_expect_success(&case, &payload);
        outcomes[1] += 1;
    }
    try testing.expect(outcomes[0] > 0 and outcomes[1] > 0);
}

fn fuzz_receipts(_: void, smith: *testing.Smith) anyerror!void {
    var data: [256]u8 = undefined;
    const length = smith.slice(&data);
    var topics = valid_topics;
    if (smith.value(bool)) topics[1] = .init(@splat(smith.value(u8)));
    const logs = [_]Log{
        .{ .address = deposit_contract, .topics = &topics, .data = data[0..length] },
        valid_log,
    };
    var fixture: Fixture = undefined;
    fixture.init();
    fixture.rollup.deposit_contract_address = deposit_contract;
    fixture.chain.add_system_config(fixture.parent.block_info.hash, .{});
    fixture.chain.receipts[1] = &.{.{ .success = true, .logs = &logs }};
    var builder = fixture.builder();
    var payload = fixture.build(&builder, fixture.chain.blocks[1].id()) catch |err| {
        try testing.expectEqual(error.BadEncoding, err);
        return;
    };
    defer payload.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), payload.transactions.len);
}

test "attributes: fuzz deposit receipts" {
    try testing.fuzz({}, fuzz_receipts, .{});
}

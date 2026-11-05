//! Execution payload → block header conversion and well-formedness checks (reth
//! `ensure_well_formed_payload`): extra data size, base fee range, transactions and
//! withdrawals roots, blob versioned hashes, requests hash, and the block hash.
//! Execution (state root, receipts, gas used) is checked later by the executor.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const ordered = @import("../trie/ordered.zig");
const chainspec = @import("../chainspec/root.zig");
const types = @import("types.zig");

const B256 = primitives.B256;
const B64 = primitives.B64;
const Header = consensus.Header;

pub const extra_data_size_max = 32;
pub const withdrawals_per_payload_max = 16;
/// sha256 of nothing: the requests hash of a block without requests (OP Isthmus+).
pub const empty_requests_hash = B256.comptime_hex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
);

pub const PayloadError = error{
    ExtraDataTooLong,
    BaseFeeOverflow,
    EmptyTransaction,
    TooManyWithdrawals,
    InvalidTransaction,
    VersionedHashesMismatch,
    InvalidRequests,
    BlockHashMismatch,
};

/// Builds the header a payload commits to. `params` supplies the beacon root and
/// requests (V3/V4). Assumes `types.validate_new_payload` already passed.
pub fn header_of(
    spec: *const chainspec.ChainSpec,
    p: *const types.ExecutionPayload,
    params: *const types.NewPayloadParams,
) PayloadError!Header {
    if (p.extra_data.len > extra_data_size_max) return error.ExtraDataTooLong;
    if (p.base_fee_per_gas > std.math.maxInt(u64)) return error.BaseFeeOverflow;
    for (p.transactions) |tx| if (tx.len == 0) return error.EmptyTransaction;
    var header: Header = .{
        .parent_hash = p.parent_hash,
        .beneficiary = p.fee_recipient,
        .state_root = p.state_root,
        .transactions_root = .{ .bytes = ordered.ordered_trie_root(p.transactions) },
        .receipts_root = p.receipts_root,
        .logs_bloom = p.logs_bloom,
        .number = p.block_number,
        .gas_limit = p.gas_limit,
        .gas_used = p.gas_used,
        .timestamp = p.timestamp,
        .extra_data = p.extra_data,
        .mix_hash = p.prev_randao,
        .nonce = B64.zero,
        .base_fee_per_gas = @intCast(p.base_fee_per_gas),
        .blob_gas_used = p.blob_gas_used,
        .excess_blob_gas = p.excess_blob_gas,
        .parent_beacon_block_root = params.parent_beacon_block_root,
    };
    if (p.withdrawals) |withdrawals| {
        header.withdrawals_root = p.withdrawals_root orelse try withdrawals_root(withdrawals);
    }
    if (params.execution_requests) |requests| {
        try check_requests(requests);
        header.requests_hash = if (spec.mode == .l2)
            empty_requests_hash
        else
            consensus.block.requests_hash(requests);
    }
    assert(header.optionals_contiguous());
    return header;
}

/// Converts and verifies a payload; returns the header whose hash is `block_hash`.
pub fn ensure_well_formed(
    spec: *const chainspec.ChainSpec,
    p: *const types.ExecutionPayload,
    params: *const types.NewPayloadParams,
) PayloadError!Header {
    const header = try header_of(spec, p, params);
    if (params.versioned_hashes) |hashes| try check_versioned_hashes(p.transactions, hashes);
    if (!header.hash().eql(p.block_hash)) return error.BlockHashMismatch;
    return header;
}

fn withdrawals_root(withdrawals: []const types.Withdrawal) PayloadError!B256 {
    if (withdrawals.len > withdrawals_per_payload_max) return error.TooManyWithdrawals;
    var bytes: [withdrawals_per_payload_max * 64]u8 = undefined;
    var items: [withdrawals_per_payload_max][]const u8 = undefined;
    var position: usize = 0;
    for (withdrawals, 0..) |w, i| {
        assert(rlp.length(w) <= 64);
        items[i] = rlp.encode_to(bytes[position..], w);
        position += items[i].len;
    }
    return .{ .bytes = ordered.ordered_trie_root(items[0..withdrawals.len]) };
}

/// EIP-7685 engine rules: each request is `type || data` with non-empty data, and
/// request types are strictly increasing.
fn check_requests(requests: []const []const u8) PayloadError!void {
    var previous: ?u8 = null;
    for (requests) |request| {
        if (request.len < 2) return error.InvalidRequests;
        if (previous) |p| if (request[0] <= p) return error.InvalidRequests;
        previous = request[0];
    }
}

/// The versioned hashes of all blob transactions, in order, must equal `expected`.
fn check_versioned_hashes(
    transactions: []const []const u8,
    expected: []const B256,
) PayloadError!void {
    var index: usize = 0;
    for (transactions) |raw| {
        if (raw[0] != @backingInt(consensus.TxType.eip4844)) continue;
        const envelope = consensus.Envelope.decode(raw) catch return error.InvalidTransaction;
        const hashes = envelope.blob_versioned_hashes();
        for (0..hashes.count()) |i| {
            if (index >= expected.len) return error.VersionedHashesMismatch;
            if (!hashes.get(i).eql(expected[index])) return error.VersionedHashesMismatch;
            index += 1;
        }
    }
    if (index != expected.len) return error.VersionedHashesMismatch;
}

/// Inverse direction for payload building: the payload fields of a sealed header.
pub fn payload_of(
    header: *const Header,
    block_hash: B256,
    transactions: []const []const u8,
    withdrawals: ?[]const types.Withdrawal,
) types.ExecutionPayload {
    assert(header.base_fee_per_gas != null);
    return .{
        .parent_hash = header.parent_hash,
        .fee_recipient = header.beneficiary,
        .state_root = header.state_root,
        .receipts_root = header.receipts_root,
        .logs_bloom = header.logs_bloom,
        .prev_randao = header.mix_hash,
        .block_number = header.number,
        .gas_limit = header.gas_limit,
        .gas_used = header.gas_used,
        .timestamp = header.timestamp,
        .extra_data = header.extra_data,
        .base_fee_per_gas = header.base_fee_per_gas.?,
        .block_hash = block_hash,
        .transactions = transactions,
        .withdrawals = withdrawals,
        .blob_gas_used = header.blob_gas_used,
        .excess_blob_gas = header.excess_blob_gas,
        .withdrawals_root = null,
    };
}

const testing = std.testing;

fn sample_header() Header {
    return .{
        .parent_hash = B256.comptime_hex(
            "3533bf30edaf9505d0810bf475cbe4e5f4b9889904b9845e83efdeab4e92eb1e",
        ),
        .number = 7,
        .gas_limit = 30_000_000,
        .timestamp = 14,
        .base_fee_per_gas = 7,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = B256.zero,
        .requests_hash = empty_requests_hash,
    };
}

test "block: payload round trip reproduces the block hash (L1 Prague)" {
    const spec = &chainspec.ChainSpec.presets.l1_dev;
    const header = sample_header();
    var p = payload_of(&header, header.hash(), &.{}, &.{});
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = B256.zero,
        .execution_requests = &.{},
    };
    try types.validate_new_payload(spec, .v4, &p, &params);
    const rebuilt = try ensure_well_formed(spec, &p, &params);
    try testing.expect(rebuilt.hash().eql(header.hash()));
    p.gas_used = 1;
    try testing.expectError(error.BlockHashMismatch, ensure_well_formed(spec, &p, &params));
    p.gas_used = 0;
    p.extra_data = &@as([33]u8, @splat(0));
    try testing.expectError(error.ExtraDataTooLong, ensure_well_formed(spec, &p, &params));
}

test "block: OP Isthmus uses payload withdrawals root and empty requests hash" {
    const spec = &chainspec.ChainSpec.presets.base_devnet;
    var header = sample_header();
    header.withdrawals_root = B256.comptime_hex(
        "8ed4baae3a927be3dea54996b4d5899f8c01e7594bf50b17dc1e741388ce3d12",
    );
    var p = payload_of(&header, header.hash(), &.{}, &.{});
    p.withdrawals_root = header.withdrawals_root;
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = B256.zero,
        .execution_requests = &.{},
    };
    try types.validate_new_payload(spec, .v4, &p, &params);
    _ = try ensure_well_formed(spec, &p, &params);
}

test "block: requests and versioned hash checks" {
    try check_requests(&.{ "\x00ab", "\x01cd" });
    try testing.expectError(error.InvalidRequests, check_requests(&.{"\x00"}));
    try testing.expectError(error.InvalidRequests, check_requests(&.{ "\x01ab", "\x00cd" }));
    try check_versioned_hashes(&.{"\x02abc"}, &.{});
    const missing = check_versioned_hashes(&.{}, &.{B256.zero});
    try testing.expectError(error.VersionedHashesMismatch, missing);
    const w: types.Withdrawal = .{
        .index = 1,
        .validator_index = 2,
        .address = .zero,
        .amount_gwei = 3,
    };
    const root = try withdrawals_root(&.{w});
    try testing.expect(!root.eql(primitives.empty_root_hash));
    try testing.expect((try withdrawals_root(&.{})).eql(primitives.empty_root_hash));
}

fn fuzz_payload(_: void, smith: *testing.Smith) anyerror!void {
    const spec = &chainspec.ChainSpec.presets.l1_dev;
    var tx_bytes: [64]u8 = undefined;
    const tx_len = smith.slice(&tx_bytes);
    const txs: []const []const u8 = &.{tx_bytes[0..tx_len]};
    var header = sample_header();
    header.gas_used = smith.value(u64);
    var p = payload_of(&header, .{ .bytes = smith.value([32]u8) }, txs, &.{});
    p.base_fee_per_gas = smith.value(u256);
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = B256.zero,
        .execution_requests = &.{},
    };
    _ = ensure_well_formed(spec, &p, &params) catch {};
}

test "block: fuzz" {
    try testing.fuzz({}, fuzz_payload, .{});
}

test "block: seeded fuzz" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xb10c);
    for (0..500) |_| {
        var bytes: [160]u8 = undefined;
        prng.fill(&bytes);
        var smith: testing.Smith = .{ .in = &bytes };
        try fuzz_payload({}, &smith);
    }
}

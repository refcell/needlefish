//! ABI codecs for the withdrawal contracts (base/base `crates/infra/withdrawer/src/contracts.rs`
//! and `withdrawal.rs`): OptimismPortal2 `proveWithdrawalTransaction` and
//! `finalizeWithdrawalTransaction{,ExternalProof}` calldata, the L2 message passer's
//! `initiateWithdrawal`, and strict decoders for the portal, dispute game and anchor state
//! registry views the status decision reads. Static-argument calls reuse the proof lane's
//! `abi` codec; the nested `WithdrawalTransaction` tuple and `bytes[]` proof are encoded here.

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("../../proof/contracts/abi.zig");
const withdrawal_module = @import("withdrawal.zig");

const Address = withdrawal_module.Address;
const Hash = withdrawal_module.Hash;
const Transaction = withdrawal_module.Transaction;
const OutputRootProof = withdrawal_module.OutputRootProof;

pub const EncodeError = abi.EncodeError;
pub const DecodeError = abi.DecodeError;

const transaction_tuple = "(uint256,address,address,uint256,uint256,bytes)";

pub const prove_withdrawal_transaction = abi.selector("proveWithdrawalTransaction(" ++
    transaction_tuple ++ ",uint256,(bytes32,bytes32,bytes32,bytes32),bytes[])");
pub const finalize_withdrawal_transaction =
    abi.selector("finalizeWithdrawalTransaction(" ++ transaction_tuple ++ ")");
pub const finalize_withdrawal_transaction_external_proof = abi.selector(
    "finalizeWithdrawalTransactionExternalProof(" ++ transaction_tuple ++ ",address)",
);
pub const initiate_withdrawal = abi.selector("initiateWithdrawal(address,uint256,bytes)");
pub const proven_withdrawals = abi.selector("provenWithdrawals(bytes32,address)");
pub const finalized_withdrawals = abi.selector("finalizedWithdrawals(bytes32)");
pub const check_withdrawal = abi.selector("checkWithdrawal(bytes32,address)");
pub const proof_maturity_delay_seconds = abi.selector("proofMaturityDelaySeconds()");
pub const respected_game_type = abi.selector("respectedGameType()");
pub const dispute_game_factory = abi.selector("disputeGameFactory()");
pub const anchor_state_registry = abi.selector("anchorStateRegistry()");
pub const game_status = abi.selector("status()");
pub const game_l2_block_number = abi.selector("l2BlockNumber()");
pub const game_root_claim = abi.selector("rootClaim()");
pub const game_created_at = abi.selector("createdAt()");
pub const game_resolved_at = abi.selector("resolvedAt()");
pub const game_extra_data = abi.selector("extraData()");
/// `WithdrawalFinalized(bytes32 indexed withdrawalHash, bool success)`.
pub const withdrawal_finalized_topic: Hash =
    withdrawal_module.keccak256("WithdrawalFinalized(bytes32,bool)");

/// Most proof nodes encoded into one prove call.
pub const proof_nodes_max = withdrawal_module.proof_nodes_max;

fn padded(length: usize) usize {
    return (length + 31) / 32 * 32;
}

/// Bytes of `abi.encode(transaction)` as a dynamic tuple body.
fn transaction_size(transaction: *const Transaction) usize {
    return 7 * 32 + padded(transaction.data.len);
}

/// Sequential writer over a zeroed output buffer.
const Writer = struct {
    out: []u8,
    position: usize = 0,

    fn word(writer: *Writer) *[32]u8 {
        assert(writer.position + 32 <= writer.out.len);
        const result = writer.out[writer.position..][0..32];
        writer.position += 32;
        return result;
    }

    fn uint(writer: *Writer, value: u256) void {
        std.mem.writeInt(u256, writer.word(), value, .big);
    }

    fn address(writer: *Writer, value: Address) void {
        writer.word()[12..32].* = value;
    }

    fn hash(writer: *Writer, value: Hash) void {
        writer.word().* = value;
    }

    /// Length word, then the bytes zero-padded to a word boundary.
    fn bytes(writer: *Writer, value: []const u8) void {
        writer.uint(value.len);
        assert(writer.position + padded(value.len) <= writer.out.len);
        @memcpy(writer.out[writer.position..][0..value.len], value);
        writer.position += padded(value.len);
    }

    fn transaction(writer: *Writer, value: *const Transaction) void {
        const start = writer.position;
        writer.uint(value.nonce);
        writer.address(value.sender);
        writer.address(value.target);
        writer.uint(value.value);
        writer.uint(value.gas_limit);
        writer.uint(6 * 32);
        writer.bytes(value.data);
        assert(writer.position - start == transaction_size(value));
    }
};

fn begin(out: []u8, size: usize, function: [4]u8) EncodeError!Writer {
    assert(size >= 4 and (size - 4) % 32 == 0);
    if (size > out.len) return error.NoSpaceLeft;
    @memset(out[0..size], 0);
    out[0..4].* = function;
    return .{ .out = out[0..size], .position = 4 };
}

pub const Prove = struct {
    transaction: *const Transaction,
    /// The dispute game's index in the factory (`outputIndex` in the portal ABI).
    game_index: u256,
    output: OutputRootProof,
    proof: []const []const u8,

    pub fn size(prove: *const Prove) usize {
        var total: usize = 4 + 7 * 32 + transaction_size(prove.transaction) + 32;
        for (prove.proof) |node| total += 32 + 32 + padded(node.len);
        return total;
    }
};

/// `proveWithdrawalTransaction(tx, gameIndex, outputRootProof, withdrawalProof)`.
pub fn encode_prove(out: []u8, prove: *const Prove) EncodeError![]u8 {
    assert(prove.proof.len <= proof_nodes_max);
    const size = prove.size();
    var writer = try begin(out, size, prove_withdrawal_transaction);
    const proof_offset = 7 * 32 + transaction_size(prove.transaction);
    writer.uint(7 * 32);
    writer.uint(prove.game_index);
    writer.hash(prove.output.version);
    writer.hash(prove.output.state_root);
    writer.hash(prove.output.message_passer_storage_root);
    writer.hash(prove.output.latest_blockhash);
    writer.uint(proof_offset);
    writer.transaction(prove.transaction);
    assert(writer.position == 4 + proof_offset);
    writer.uint(prove.proof.len);
    var element_offset: usize = prove.proof.len * 32;
    for (prove.proof) |node| {
        writer.uint(element_offset);
        element_offset += 32 + padded(node.len);
    }
    for (prove.proof) |node| writer.bytes(node);
    assert(writer.position == size);
    return out[0..size];
}

/// `finalizeWithdrawalTransaction(tx)`.
pub fn encode_finalize(out: []u8, transaction: *const Transaction) EncodeError![]u8 {
    const size = 4 + 32 + transaction_size(transaction);
    var writer = try begin(out, size, finalize_withdrawal_transaction);
    writer.uint(32);
    writer.transaction(transaction);
    assert(writer.position == size);
    return out[0..size];
}

/// `finalizeWithdrawalTransactionExternalProof(tx, proofSubmitter)`.
pub fn encode_finalize_external_proof(
    out: []u8,
    transaction: *const Transaction,
    proof_submitter: Address,
) EncodeError![]u8 {
    const size = 4 + 64 + transaction_size(transaction);
    var writer = try begin(out, size, finalize_withdrawal_transaction_external_proof);
    writer.uint(64);
    writer.address(proof_submitter);
    writer.transaction(transaction);
    assert(writer.position == size);
    return out[0..size];
}

/// L2 `initiateWithdrawal(target, gasLimit, data)` on the message passer.
pub fn encode_initiate(
    out: []u8,
    target: Address,
    gas_limit: u256,
    data: []const u8,
) EncodeError![]u8 {
    const result = try abi.encode_call(out, initiate_withdrawal, &.{
        .{ .address = target },
        .{ .uint = gas_limit },
        .{ .bytes = data },
    });
    assert(result.len == 4 + 4 * 32 + padded(data.len));
    return result;
}

pub fn encode_proven_withdrawals(out: []u8, hash: Hash, submitter: Address) EncodeError![]u8 {
    return abi.encode_call(out, proven_withdrawals, &.{
        .{ .word = hash },
        .{ .address = submitter },
    });
}

pub fn encode_check_withdrawal(out: []u8, hash: Hash, submitter: Address) EncodeError![]u8 {
    return abi.encode_call(out, check_withdrawal, &.{
        .{ .word = hash },
        .{ .address = submitter },
    });
}

pub fn encode_finalized_withdrawals(out: []u8, hash: Hash) EncodeError![]u8 {
    const result = try abi.encode_call(out, finalized_withdrawals, &.{.{ .word = hash }});
    assert(result.len == 36);
    return result;
}

/// Decodes the `WithdrawalTransaction` tuple whose head offset sits in word `index`.
pub fn decode_transaction(decoder: abi.Decoder, index: usize) DecodeError!Transaction {
    const offset = try decoder.uint(u32, index);
    if (offset % 32 != 0) return error.TypeCheck;
    if (offset > decoder.data.len) return error.Overrun;
    const tuple: abi.Decoder = .{ .data = decoder.data[offset..] };
    const transaction: Transaction = .{
        .nonce = try tuple.uint(u256, 0),
        .sender = try tuple.address(1),
        .target = try tuple.address(2),
        .value = try tuple.uint(u256, 3),
        .gas_limit = try tuple.uint(u256, 4),
        .data = try tuple.bytes(5),
    };
    assert(@intFromPtr(transaction.data.ptr) >= @intFromPtr(decoder.data.ptr));
    return transaction;
}

/// The transaction of `finalizeWithdrawalTransaction` calldata.
pub fn decode_finalize(calldata: []const u8) DecodeError!Transaction {
    const decoder = try abi.Decoder.call(calldata, finalize_withdrawal_transaction);
    assert(decoder.data.len + 4 == calldata.len);
    return decode_transaction(decoder, 0);
}

pub const DecodedProve = struct {
    transaction: Transaction,
    game_index: u256,
    output: OutputRootProof,
    proof_count: u32,
};

/// The static parts of `proveWithdrawalTransaction` calldata and its proof node count.
pub fn decode_prove(calldata: []const u8) DecodeError!DecodedProve {
    const decoder = try abi.Decoder.call(calldata, prove_withdrawal_transaction);
    const proof_offset = try decoder.uint(u32, 6);
    if (proof_offset % 32 != 0) return error.TypeCheck;
    const count = try decoder.uint(u32, proof_offset / 32);
    if (count > proof_nodes_max) return error.TypeCheck;
    const decoded: DecodedProve = .{
        .transaction = try decode_transaction(decoder, 0),
        .game_index = try decoder.uint(u256, 1),
        .output = .{
            .version = (try decoder.word(2)).*,
            .state_root = (try decoder.word(3)).*,
            .message_passer_storage_root = (try decoder.word(4)).*,
            .latest_blockhash = (try decoder.word(5)).*,
        },
        .proof_count = count,
    };
    if (!std.mem.allEqual(u8, &decoded.output.version, 0)) return error.TypeCheck;
    return decoded;
}

/// The `provenWithdrawals(hash, submitter)` record.
pub const ProvenWithdrawal = struct { game: Address, timestamp: u64 };

pub fn decode_proven_withdrawal(data: []const u8) DecodeError!ProvenWithdrawal {
    const decoder: abi.Decoder = .{ .data = data };
    const proven: ProvenWithdrawal = .{
        .game = try decoder.address(0),
        .timestamp = try decoder.uint(u64, 1),
    };
    assert(data.len >= 64);
    return proven;
}

pub fn decode_bool(data: []const u8) DecodeError!bool {
    const decoder: abi.Decoder = .{ .data = data };
    const value = try decoder.boolean(0);
    assert(data.len >= 32);
    return value;
}

pub fn decode_address(data: []const u8) DecodeError!Address {
    const decoder: abi.Decoder = .{ .data = data };
    const value = try decoder.address(0);
    assert(data.len >= 32);
    return value;
}

pub fn decode_hash(data: []const u8) DecodeError!Hash {
    const decoder: abi.Decoder = .{ .data = data };
    const value = (try decoder.word(0)).*;
    assert(data.len >= 32);
    return value;
}

pub fn decode_uint(comptime T: type, data: []const u8) DecodeError!T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    const decoder: abi.Decoder = .{ .data = data };
    const value = try decoder.uint(T, 0);
    assert(data.len >= 32);
    return value;
}

/// Dispute game `status()` (`GameStatus` in the OP contracts).
pub const GameStatus = enum(u8) { in_progress = 0, challenger_wins = 1, defender_wins = 2 };

pub fn decode_game_status(data: []const u8) DecodeError!GameStatus {
    const value = try decode_uint(u8, data);
    const status = std.enums.fromInt(GameStatus, value) orelse return error.TypeCheck;
    assert(value <= 2);
    return status;
}

/// The L2 block a game claims: the first word of its `extraData()` bytes.
pub fn decode_extra_data_block(data: []const u8) DecodeError!?u64 {
    const decoder: abi.Decoder = .{ .data = data };
    const extra = try decoder.bytes(0);
    if (extra.len < 32) return null;
    assert(extra.len >= 32);
    const block = std.mem.readInt(u256, extra[0..32], .big);
    return std.math.cast(u64, block);
}

/// `success` of a `WithdrawalFinalized` log for `withdrawal_hash` emitted by `portal`, or
/// null when the log is something else.
pub fn decode_withdrawal_finalized(
    log: withdrawal_module.Log,
    portal: Address,
    withdrawal_hash: Hash,
) DecodeError!?bool {
    if (!std.mem.eql(u8, &log.address, &portal)) return null;
    if (log.topics.len < 2) return null;
    if (!std.mem.eql(u8, &log.topics[0], &withdrawal_finalized_topic)) return null;
    if (!std.mem.eql(u8, &log.topics[1], &withdrawal_hash)) return null;
    if (log.topics.len != 2) return error.TypeCheck;
    return try decode_bool(log.data);
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");

fn hex_selector(comptime text: []const u8) [4]u8 {
    var out: [4]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "calldata: selectors match the deployed contracts" {
    const cases = .{
        .{ prove_withdrawal_transaction, "4870496f" },
        .{ finalize_withdrawal_transaction, "8c3152e9" },
        .{ finalize_withdrawal_transaction_external_proof, "43ca1c50" },
        .{ initiate_withdrawal, "c2b3e5ac" },
        .{ proven_withdrawals, "bb2c727e" },
        .{ finalized_withdrawals, "a14238e7" },
        .{ check_withdrawal, "71c1566e" },
        .{ proof_maturity_delay_seconds, "bf653a5c" },
        .{ respected_game_type, "3c9f397c" },
        .{ dispute_game_factory, "f2b4e617" },
        .{ anchor_state_registry, "5c0cba33" },
        .{ game_status, "200d2ed2" },
        .{ game_l2_block_number, "8b85902b" },
        .{ game_root_claim, "bcef3b55" },
        .{ game_created_at, "cf09e0d0" },
        .{ game_resolved_at, "19effeb4" },
        .{ game_extra_data, "609d3334" },
    };
    inline for (cases) |case| try testing.expectEqual(hex_selector(case[1]), case[0]);
    try testing.expectEqual(@as(u8, 0xdb), withdrawal_finalized_topic[0]);
    try testing.expectEqual(@as(u8, 0x1b), withdrawal_finalized_topic[31]);
}

const sample_transaction: Transaction = .{
    .nonce = 1,
    .sender = @splat(0x11),
    .target = @splat(0x22),
    .value = 3,
    .gas_limit = 4,
    .data = "\xab\xcd",
};

test "calldata: prove matches a cast-encoded vector" {
    // cast calldata "proveWithdrawalTransaction((uint256,address,address,uint256,uint256,bytes),
    // uint256,(bytes32,bytes32,bytes32,bytes32),bytes[])" "(1,0x11..11,0x22..22,3,4,0xabcd)" 5
    // "(0x00..00,0x01..01,0x02..02,0x03..03)" "[0xc0,0xc20102]" | keccak256
    var buffer: [1024]u8 = undefined;
    const prove: Prove = .{
        .transaction = &sample_transaction,
        .game_index = 5,
        .output = .{
            .state_root = @splat(1),
            .message_passer_storage_root = @splat(2),
            .latest_blockhash = @splat(3),
        },
        .proof = &.{ "\xc0", "\xc2\x01\x02" },
    };
    const encoded = try encode_prove(&buffer, &prove);
    try testing.expectEqual(prove.size(), encoded.len);
    try expect_keccak(prove_vector_keccak, encoded);
    const decoded = try decode_prove(encoded);
    try testing.expectEqual(@as(u256, 5), decoded.game_index);
    try testing.expectEqual(@as(u32, 2), decoded.proof_count);
    try testing.expectEqualSlices(u8, "\xab\xcd", decoded.transaction.data);
    try testing.expectError(error.NoSpaceLeft, encode_prove(buffer[0..100], &prove));
}

const prove_vector_keccak = "4e001ab10eafdd9455048c25f0a1aa6592d233ec51eab7bbe5c309d46e90645d";
/// keccak256 of `cast calldata "finalizeWithdrawalTransaction(...)"
/// "(1,0x11..,0x22..,3,4,0xabcd)"`.
const finalize_vector_keccak = "b33e05e5d908b3c79a4014c980ed0a1784a1fba42dcb7ad771b73292a6628523";
/// `cast abi-encode "f(uint256,address,address,uint256,uint256,bytes)" ... | cast keccak`.
const hash_vector = "bbb9eb66691286db850101bd1d605a64240588781813137b2ca472786db41755";

fn expect_keccak(expected: []const u8, bytes: []const u8) !void {
    const digest = withdrawal_module.keccak256(bytes);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&digest}) catch unreachable;
    try testing.expectEqualStrings(expected, &hex);
}

test "calldata: finalize and initiate round trip" {
    var buffer: [512]u8 = undefined;
    const finalize = try encode_finalize(&buffer, &sample_transaction);
    try testing.expectEqual(@as(usize, 4 + 32 + 7 * 32 + 32), finalize.len);
    try expect_keccak(finalize_vector_keccak, finalize);
    var hash_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hash_hex, "{x}", .{&sample_transaction.hash()}) catch unreachable;
    try testing.expectEqualStrings(hash_vector, &hash_hex);
    const decoded = try decode_finalize(finalize);
    try testing.expectEqual(sample_transaction.nonce, decoded.nonce);
    try testing.expectEqualSlices(u8, &sample_transaction.target, &decoded.target);
    try testing.expectEqualSlices(u8, sample_transaction.data, decoded.data);
    const hash = sample_transaction.hash();
    try testing.expectEqualSlices(u8, &hash, &decoded.hash());
    const external = try encode_finalize_external_proof(&buffer, &sample_transaction, @splat(9));
    const external_selector = finalize_withdrawal_transaction_external_proof;
    const external_decoder = try abi.Decoder.call(external, external_selector);
    try testing.expectEqual(@as(Address, @splat(9)), try external_decoder.address(1));
    const external_transaction = try decode_transaction(external_decoder, 0);
    try testing.expectEqual(sample_transaction.value, external_transaction.value);
    const initiate = try encode_initiate(&buffer, @splat(0x22), 100_000, "hi");
    const initiate_decoder = try abi.Decoder.call(initiate, initiate_withdrawal);
    try testing.expectEqual(@as(u64, 100_000), try initiate_decoder.uint(u64, 1));
    try testing.expectEqualSlices(u8, "hi", try initiate_decoder.bytes(2));
}

test "calldata: view returns decode strictly" {
    var data: [96]u8 = @splat(0);
    data[31] = 2;
    try testing.expectEqual(GameStatus.defender_wins, try decode_game_status(&data));
    data[31] = 3;
    try testing.expectError(error.TypeCheck, decode_game_status(&data));
    try testing.expectError(error.TypeCheck, decode_bool(&data));
    try testing.expectError(error.Overrun, decode_bool(data[0..31]));
    data[31] = 1;
    try testing.expect(try decode_bool(&data));
    data[12] = 0x42;
    data[63] = 77;
    const proven = try decode_proven_withdrawal(&data);
    try testing.expectEqual(@as(u8, 0x42), proven.game[0]);
    try testing.expectEqual(@as(u64, 77), proven.timestamp);
    data[11] = 1;
    try testing.expectError(error.TypeCheck, decode_proven_withdrawal(&data));
    try testing.expectError(error.TypeCheck, decode_address(&data));
}

test "calldata: extra data block and finalization events" {
    var data: [128]u8 = @splat(0);
    data[31] = 32;
    data[63] = 32;
    data[95] = 9;
    try testing.expectEqual(@as(?u64, 9), try decode_extra_data_block(data[0..96]));
    data[64] = 1;
    try testing.expectEqual(@as(?u64, null), try decode_extra_data_block(data[0..96]));
    data[63] = 31;
    try testing.expectError(error.TypeCheck, decode_extra_data_block(data[0..96]));
    const portal: Address = @splat(0x50);
    const hash: Hash = @splat(0x77);
    var success: [32]u8 = @splat(0);
    success[31] = 1;
    const topics = [_]Hash{ withdrawal_finalized_topic, hash };
    const log: withdrawal_module.Log = .{ .address = portal, .topics = &topics, .data = &success };
    try testing.expectEqual(@as(?bool, true), try decode_withdrawal_finalized(log, portal, hash));
    const other_portal = try decode_withdrawal_finalized(log, @splat(0), hash);
    try testing.expectEqual(@as(?bool, null), other_portal);
    const other_hash = try decode_withdrawal_finalized(log, portal, @splat(0));
    try testing.expectEqual(@as(?bool, null), other_hash);
}

fn fuzz_reads(_: void, smith: *std.testing.Smith) anyerror!void {
    var data: [512]u8 = undefined;
    const length = smith.slice(&data);
    const input = data[0..length];
    // Arbitrary return data and calldata decode or fail cleanly.
    _ = decode_proven_withdrawal(input) catch {};
    _ = decode_game_status(input) catch {};
    _ = decode_extra_data_block(input) catch {};
    _ = decode_uint(u64, input) catch {};
    if (decode_finalize(input)) |transaction| {
        try testing.expect(@intFromPtr(transaction.data.ptr) + transaction.data.len <=
            @intFromPtr(input.ptr) + input.len);
    } else |_| {}
    if (decode_prove(input)) |prove| {
        try testing.expect(prove.proof_count <= proof_nodes_max);
    } else |_| {}
}

test "calldata: fuzz decoders" {
    try fuzz.run({}, fuzz_reads, .{ .iterations = 1024 });
}

fn fuzz_round_trip(_: void, smith: *std.testing.Smith) anyerror!void {
    var data: [200]u8 = undefined;
    const transaction: Transaction = .{
        .nonce = smith.value(u256),
        .sender = smith.value([20]u8),
        .target = smith.value([20]u8),
        .value = smith.value(u256),
        .gas_limit = smith.value(u256),
        .data = data[0..smith.slice(&data)],
    };
    var buffer: [1024]u8 = undefined;
    const encoded = try encode_finalize(&buffer, &transaction);
    const decoded = try decode_finalize(encoded);
    try testing.expectEqualSlices(u8, &transaction.hash(), &decoded.hash());
    try testing.expectEqual(transaction.gas_limit, decoded.gas_limit);
}

test "calldata: fuzz finalize round trip" {
    try fuzz.run({}, fuzz_round_trip, .{ .iterations = 512 });
}

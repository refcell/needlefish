//! Primitives-lane micro benchmarks: transaction encode/decode/hash, sender recovery,
//! header hashing, receipt encoding, FastLZ and L1 cost. Listed in
//! `src/testing/bench_main.zig`; run with `just bench consensus`.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const tx_module = @import("tx.zig");
const signature = @import("signature.zig");
const header_module = @import("header.zig");
const receipt_module = @import("receipt.zig");
const flz = @import("../flz/root.zig");
const l1_fees = @import("../l1_fees/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Envelope = tx_module.Envelope;

pub const Case = struct {
    name: []const u8,
    iterations: u32,
    run: *const fn (iterations: u32) u64,
    bytes_per_op: u64 = 0,
};

/// Public `test test ... junk` devnet account #0.
const dev_key = [32]u8{
    0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38, 0xff, 0x94,
    0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b, 0xf4, 0xf2, 0xff, 0x80,
};

const calldata_size = 512;
var calldata: [calldata_size]u8 = undefined;

/// A typical Base EIP-1559 transfer-with-calldata, signed with the dev key.
fn sample_envelope() Envelope {
    for (&calldata, 0..) |*byte, index| byte.* = @truncate(index *% 31 / 7);
    const tx: tx_module.Eip1559 = .{
        .chain_id = 8453,
        .nonce = 42,
        .max_priority_fee_per_gas = 1_000_000,
        .max_fee_per_gas = 2_000_000_000,
        .gas_limit = 120_000,
        .to = .{ .call = Address.comptime_hex("4200000000000000000000000000000000000006") },
        .value = 1_000_000_000_000_000,
        .input = &calldata,
        .access_list = .{},
    };
    // The dev key is valid and R.x >= n has probability ~2^-128.
    return tx_module.sign(tx, dev_key) catch unreachable;
}

const encoded_capacity = calldata_size + 256;

fn bench_tx_encode(iterations: u32) u64 {
    const envelope = sample_envelope();
    var buffer: [encoded_capacity]u8 = undefined;
    var accumulator: u64 = 0;
    for (0..iterations) |_| accumulator +%= envelope.encode_to(&buffer).len;
    return accumulator;
}

fn bench_tx_decode(iterations: u32) u64 {
    var buffer: [encoded_capacity]u8 = undefined;
    const encoded = sample_envelope().encode_to(&buffer);
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const decoded = Envelope.decode(encoded) catch unreachable; // Valid encoding.
        accumulator +%= decoded.gas_limit();
    }
    return accumulator;
}

fn bench_tx_hash(iterations: u32) u64 {
    const envelope = sample_envelope();
    var accumulator: u64 = 0;
    for (0..iterations) |_| accumulator +%= envelope.hash().bytes[0];
    return accumulator;
}

fn bench_tx_signing_hash(iterations: u32) u64 {
    const envelope = sample_envelope();
    var accumulator: u64 = 0;
    for (0..iterations) |_| accumulator +%= envelope.signing_hash().?.bytes[0];
    return accumulator;
}

fn bench_recover_sender(iterations: u32) u64 {
    const envelope = sample_envelope();
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const sender = envelope.recover_sender(signature.recover_address).?;
        accumulator +%= sender.bytes[19];
    }
    return accumulator;
}

fn sample_header() header_module.Header {
    return .{
        .parent_hash = B256.comptime_hex(
            "f712aa9241cc24369b143cf6dce85f0902a9731e70d66818a3a5845b296c73dd",
        ),
        .beneficiary = Address.comptime_hex("4200000000000000000000000000000000000011"),
        .state_root = primitives.empty_root_hash,
        .transactions_root = primitives.empty_root_hash,
        .receipts_root = primitives.empty_root_hash,
        .number = 30_000_000,
        .gas_limit = 150_000_000,
        .gas_used = 40_000_000,
        .timestamp = 1_750_000_000,
        .extra_data = &.{ 0, 0, 0, 0, 0x32, 0, 0, 0, 6 },
        .base_fee_per_gas = 2_000_000,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .zero,
        .requests_hash = primitives.empty_root_hash,
    };
}

fn bench_header_hash(iterations: u32) u64 {
    var header = sample_header();
    var accumulator: u64 = 0;
    for (0..iterations) |index| {
        header.number = index;
        accumulator +%= header.hash().bytes[0];
    }
    return accumulator;
}

fn bench_receipt_encode(iterations: u32) u64 {
    const receipt: receipt_module.Receipt = .{
        .tx_type = .eip1559,
        .status = true,
        .cumulative_gas_used = 21_000_000,
    };
    var buffer: [512]u8 = undefined;
    var accumulator: u64 = 0;
    for (0..iterations) |_| accumulator +%= receipt.encode_to(&buffer).len;
    return accumulator;
}

fn bench_flz_compress_length(iterations: u32) u64 {
    var buffer: [encoded_capacity]u8 = undefined;
    const encoded = sample_envelope().encode_to(&buffer);
    var accumulator: u64 = 0;
    for (0..iterations) |_| accumulator +%= flz.compress_length(encoded);
    return accumulator;
}

fn bench_l1_cost_fjord(iterations: u32) u64 {
    var buffer: [encoded_capacity]u8 = undefined;
    const encoded = sample_envelope().encode_to(&buffer);
    const params: l1_fees.L1FeeParams = .{
        .l1_base_fee = 10_000_000_000,
        .l1_base_fee_scalar = 2269,
        .l1_blob_base_fee = 1,
        .l1_blob_base_fee_scalar = 1_055_762,
    };
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        accumulator +%= @truncate(params.tx_l1_cost(encoded, .fjord));
    }
    return accumulator;
}

fn encoded_size() u64 {
    var buffer: [encoded_capacity]u8 = undefined;
    return sample_envelope().encode_to(&buffer).len;
}

pub const cases = [_]Case{
    .{ .name = "consensus/tx_encode_1559_512b", .iterations = 1_000_000, .run = bench_tx_encode },
    .{ .name = "consensus/tx_decode_1559_512b", .iterations = 1_000_000, .run = bench_tx_decode },
    .{ .name = "consensus/tx_hash_1559_512b", .iterations = 200_000, .run = bench_tx_hash },
    .{
        .name = "consensus/tx_signing_hash_1559_512b",
        .iterations = 200_000,
        .run = bench_tx_signing_hash,
    },
    .{ .name = "consensus/tx_recover_sender", .iterations = 5_000, .run = bench_recover_sender },
    .{ .name = "consensus/header_hash_prague", .iterations = 200_000, .run = bench_header_hash },
    .{
        .name = "consensus/receipt_encode_empty",
        .iterations = 1_000_000,
        .run = bench_receipt_encode,
    },
    .{ .name = "flz/compress_length_tx", .iterations = 100_000, .run = bench_flz_compress_length },
    .{ .name = "l1_fees/tx_l1_cost_fjord", .iterations = 100_000, .run = bench_l1_cost_fjord },
};

test "consensus bench: cases run" {
    for (cases) |case| _ = case.run(2);
    try std.testing.expect(encoded_size() > calldata_size);
}

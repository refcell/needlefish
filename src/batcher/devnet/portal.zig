//! Minimal L1 deposit portal for the devnet, as hand-assembled EVM bytecode.
//!
//! The real OptimismPortal is a large Solidity contract. Derivation only needs its
//! `TransactionDeposited` logs, so the devnet deploys this stand-in at genesis. Any
//! call to it behaves like the portal's `receive()`: it deposits `msg.value` to
//! `msg.sender` on L2 (mint = value = msg.value, gas limit 100000, not a creation,
//! empty data) by emitting
//!
//!   TransactionDeposited(address indexed from, address indexed to,
//!                        uint256 indexed version, bytes opaqueData)
//!
//! with version 0 and opaqueData = mint(32) ++ value(32) ++ gasLimit(8) ++
//! isCreation(1) ++ data. Callers must be EOAs (no address aliasing is applied).

const std = @import("std");
const assert = std.debug.assert;

/// keccak256("TransactionDeposited(address,address,uint256,bytes)").
pub const transaction_deposited_topic = [32]u8{
    0xb3, 0x81, 0x35, 0x68, 0xd9, 0x99, 0x1f, 0xc9, 0x51, 0x96, 0x1f, 0xcb, 0x4c, 0x78,
    0x48, 0x93, 0x57, 0x42, 0x40, 0xa2, 0x89, 0x25, 0x60, 0x4d, 0x09, 0xfc, 0x57, 0x7c,
    0x55, 0xbb, 0x7c, 0x32,
};

/// Gas limit of L2 deposits made through `receive()` (OptimismPortal constant).
pub const receive_deposit_gas_limit: u64 = 100_000;

/// Length of opaqueData for a deposit with empty calldata.
pub const opaque_data_length = 32 + 32 + 8 + 1;

const op = struct {
    const stop = 0x00;
    const mstore = 0x52;
    const caller = 0x33;
    const callvalue = 0x34;
    const push1 = 0x60;
    const push32 = 0x7f;
    const log4 = 0xa4;
};

pub const code: [code_length]u8 = build();
// 5 + 5 + 4 + 4 (data words) + 33 + 3 (gas word) + 5 + 32 + 6 (LOG4).
const code_length = 97;

fn build() [code_length]u8 {
    var out: [code_length]u8 = undefined;
    var n: usize = 0;
    const emit = struct {
        fn bytes(buffer: *[code_length]u8, offset: *usize, values: []const u8) void {
            @memcpy(buffer[offset.*..][0..values.len], values);
            offset.* += values.len;
        }
    }.bytes;
    // Event data (ABI `bytes`): offset word, length word, then padded opaqueData.
    emit(&out, &n, &.{ op.push1, 0x20, op.push1, 0x00, op.mstore });
    emit(&out, &n, &.{ op.push1, opaque_data_length, op.push1, 0x20, op.mstore });
    emit(&out, &n, &.{ op.callvalue, op.push1, 0x40, op.mstore }); // mint
    emit(&out, &n, &.{ op.callvalue, op.push1, 0x60, op.mstore }); // value
    // gasLimit as 8 big-endian bytes at 0x80; isCreation (0) and padding follow as zeros.
    var gas_word: [32]u8 = @splat(0);
    std.mem.writeInt(u64, gas_word[0..8], receive_deposit_gas_limit, .big);
    emit(&out, &n, &.{op.push32});
    emit(&out, &n, &gas_word);
    emit(&out, &n, &.{ op.push1, 0x80, op.mstore });
    // LOG4(offset 0, size 0xa0, topic0, from, to, version): push in reverse.
    emit(&out, &n, &.{ op.push1, 0x00, op.caller, op.caller, op.push32 });
    emit(&out, &n, &transaction_deposited_topic);
    emit(&out, &n, &.{ op.push1, 0xa0, op.push1, 0x00, op.log4, op.stop });
    assert(n == code_length);
    return out;
}

comptime {
    // Padded opaqueData (3 words) + offset word + length word.
    assert(0x40 + 3 * 32 == 0xa0);
    assert(opaque_data_length == 73);
}

const testing = std.testing;
const primitives = @import("../../common/primitives/root.zig");

test "portal: topic is keccak of the event signature" {
    const hash = primitives.keccak256("TransactionDeposited(address,address,uint256,bytes)");
    try testing.expectEqualSlices(u8, &transaction_deposited_topic, &hash.bytes);
}

test "portal: bytecode shape" {
    try testing.expectEqual(@as(u8, op.stop), code[code.len - 1]);
    try testing.expectEqual(@as(u8, op.log4), code[code.len - 2]);
    // Every PUSH32 immediate is skipped when scanning opcodes; no stray invalid opcodes.
    var i: usize = 0;
    var logs: u32 = 0;
    while (i < code.len) : (i += 1) {
        const byte = code[i];
        if (byte >= op.push1 and byte <= op.push32) {
            i += byte - op.push1 + 1;
        } else {
            if (byte == op.log4) logs += 1;
            try testing.expect(byte == op.stop or byte == op.mstore or byte == op.caller or
                byte == op.callvalue or byte == op.log4);
        }
    }
    try testing.expectEqual(@as(u32, 1), logs);
}

test "portal: consensus decodes the log this code emits" {
    // Log emitted by `code` for a 1 ETH call from dev account 1 (captured on a dev node).
    const deposits = @import("../../consensus/protocol/deposits.zig");
    var sender_word: [32]u8 = @splat(0);
    _ = try std.fmt.hexToBytes(sender_word[12..], "70997970c51812dc3a010c7d01b50e0d17dc79c8");
    const topics = [_]primitives.B256{
        .{ .bytes = transaction_deposited_topic },
        .{ .bytes = sender_word },
        .{ .bytes = sender_word },
        .{ .bytes = @splat(0) },
    };
    // Same layout the bytecode writes to memory: offset, length, mint, value, gas, flag.
    var data: [0xa0]u8 = @splat(0);
    data[31] = 0x20;
    data[63] = opaque_data_length;
    const one_ether: u256 = 1_000_000_000_000_000_000;
    std.mem.writeInt(u256, data[0x40..0x60], one_ether, .big);
    std.mem.writeInt(u256, data[0x60..0x80], one_ether, .big);
    std.mem.writeInt(u64, data[0x80..0x88], receive_deposit_gas_limit, .big);
    const tx = try deposits.decode_deposit_log(.{ .bytes = @splat(1) }, 0, .{
        .address = .{ .bytes = @splat(0) },
        .topics = &topics,
        .data = &data,
    });
    try testing.expectEqual(@as(u128, one_ether), tx.mint);
    try testing.expectEqual(one_ether, tx.value);
    try testing.expectEqual(receive_deposit_gas_limit, tx.gas_limit);
    try testing.expectEqualSlices(u8, sender_word[12..], &tx.from.bytes);
    try testing.expectEqualSlices(u8, sender_word[12..], &tx.to.?.bytes);
    try testing.expectEqual(@as(usize, 0), tx.input.len);
}

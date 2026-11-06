//! Differential fuzz of CALL-family plumbing against a two-contract model.
//!
//! Contract A copies its calldata to memory and calls contract B with a random kind
//! (CALL, CALLCODE, DELEGATECALL, STATICCALL), value, output window, and then a random
//! RETURNDATACOPY range. B echoes CALLER, CALLVALUE, ADDRESS, RETURNDATASIZE (0 on entry
//! even though A's warm-up call left return data), and its calldata, and reverts
//! instead of returning when the first calldata byte is 0xff. A returns a fixed window of
//! its memory: the success flag, RETURNDATASIZE, the output window, the input copy, and the
//! RETURNDATACOPY result. The model predicts that window (or a halt when the copy range
//! is out of bounds) from the call-kind rules for caller, value, and address.

const std = @import("std");
const assert = std.debug.assert;
const op = @import("opcode.zig");
const evm_module = @import("evm.zig");
const primitives = @import("primitives.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const evm_test = @import("evm_test.zig");
const Harness = evm_test.Harness;
const Address = primitives.Address;

const caller_contract = primitives.address_from_int(0xa000);
const callee_contract = primitives.address_from_int(0xb000);
const gas_limit: u64 = 1_000_000;
const input_offset = 0x200;
const copy_offset = 0x400;
const window_bytes = 0x600;
const input_bytes_max = 0x100;
const balance: u256 = 1 << 64;

/// B: mem[0..128] = CALLER ‖ CALLVALUE ‖ ADDRESS ‖ RETURNDATASIZE, mem[128..] = calldata;
/// RETURN or REVERT it.
const callee_code = [_]u8{
    op.CALLER,         op.PUSH1,        0,               op.MSTORE,
    op.CALLVALUE,      op.PUSH1,        32,              op.MSTORE,
    op.ADDRESS,        op.PUSH1,        64,              op.MSTORE,
    op.RETURNDATASIZE, op.PUSH1,        96,              op.MSTORE,
    op.CALLDATASIZE,   op.PUSH1,        0,               op.PUSH1,
    header_bytes,      op.CALLDATACOPY, op.PUSH1,        0,
    op.CALLDATALOAD,   op.PUSH1,        248,             op.SHR,
    op.PUSH1,          0xff,            op.EQ,           op.PUSH1,
    revert_pc,         op.JUMPI,        op.CALLDATASIZE, op.PUSH1,
    header_bytes,      op.ADD,          op.PUSH1,        0,
    op.RETURN,         op.JUMPDEST,     op.CALLDATASIZE, op.PUSH1,
    header_bytes,      op.ADD,          op.PUSH1,        0,
    op.REVERT,
};
const revert_pc = 41;
const header_bytes = 128;

comptime {
    assert(callee_code[revert_pc] == op.JUMPDEST);
}

const Kind = enum { call, callcode, delegatecall, staticcall };

const Case = struct {
    kind: Kind,
    value: u256,
    input: []const u8,
    out_offset: u16,
    out_size: u16,
    copy_from: u16,
    copy_size: u16,
};

fn emit_push(code: []u8, length: *usize, value: u256) void {
    code[length.*] = op.PUSH32;
    primitives.word_to_be(code[length.* + 1 ..][0..32], value);
    length.* += 33;
}

fn emit_bytes(code: []u8, length: *usize, bytes: []const u8) void {
    @memcpy(code[length.*..][0..bytes.len], bytes);
    length.* += bytes.len;
}

fn caller_program(buffer: []u8, case: Case) []const u8 {
    var length: usize = 0;
    // CALLDATACOPY(input_offset, 0, CALLDATASIZE).
    emit_bytes(buffer, &length, &.{ op.CALLDATASIZE, op.PUSH1, 0 });
    emit_push(buffer, &length, input_offset);
    emit_bytes(buffer, &length, &.{op.CALLDATACOPY});
    // Warm-up STATICCALL(gas, B, 0, 0, 0, 0): leaves return data that B must not see.
    emit_bytes(buffer, &length, &.{ op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0, op.PUSH1, 0 });
    emit_push(buffer, &length, primitives.address_to_u256(callee_contract));
    emit_bytes(buffer, &length, &.{ op.GAS, op.STATICCALL, op.POP });
    // kind(gas, to, [value], in_offset, in_size, out_offset, out_size): pushed in reverse.
    emit_push(buffer, &length, case.out_size);
    emit_push(buffer, &length, case.out_offset);
    emit_bytes(buffer, &length, &.{op.CALLDATASIZE});
    emit_push(buffer, &length, input_offset);
    if (case.kind == .call or case.kind == .callcode) emit_push(buffer, &length, case.value);
    emit_push(buffer, &length, primitives.address_to_u256(callee_contract));
    emit_bytes(buffer, &length, &.{op.GAS});
    emit_bytes(buffer, &length, &.{switch (case.kind) {
        .call => op.CALL,
        .callcode => op.CALLCODE,
        .delegatecall => op.DELEGATECALL,
        .staticcall => op.STATICCALL,
    }});
    // mem[0] = success, mem[32] = RETURNDATASIZE.
    emit_bytes(buffer, &length, &.{ op.PUSH1, 0, op.MSTORE, op.RETURNDATASIZE, op.PUSH1, 32 });
    emit_bytes(buffer, &length, &.{op.MSTORE});
    // RETURNDATACOPY(copy_offset, copy_from, copy_size).
    emit_push(buffer, &length, case.copy_size);
    emit_push(buffer, &length, case.copy_from);
    emit_push(buffer, &length, copy_offset);
    emit_bytes(buffer, &length, &.{op.RETURNDATACOPY});
    // RETURN(0, window_bytes).
    emit_push(buffer, &length, window_bytes);
    emit_bytes(buffer, &length, &.{ op.PUSH1, 0, op.RETURN });
    assert(length <= buffer.len);
    return buffer[0..length];
}

/// What B sees as (CALLER, CALLVALUE, ADDRESS, RETURNDATASIZE) for each call kind.
fn seen(case: Case) [4]u256 {
    const a = primitives.address_to_u256(caller_contract);
    const b = primitives.address_to_u256(callee_contract);
    const origin = primitives.address_to_u256(evm_test.caller);
    return switch (case.kind) {
        .call => .{ a, case.value, b, 0 },
        .callcode => .{ a, case.value, a, 0 },
        .delegatecall => .{ origin, 0, a, 0 }, // A's own CALLER and CALLVALUE (0).
        .staticcall => .{ a, 0, b, 0 },
    };
}

const Expected = union(enum) { halt, window: [window_bytes]u8 };

fn model(case: Case) Expected {
    var return_data: [header_bytes + input_bytes_max]u8 = undefined;
    const identity = seen(case);
    for (identity, 0..) |word, index| {
        primitives.word_to_be(return_data[index * 32 ..][0..32], word);
    }
    @memcpy(return_data[header_bytes..][0..case.input.len], case.input);
    const return_len = header_bytes + case.input.len;
    const reverted = case.input.len > 0 and case.input[0] == 0xff;
    if (@as(usize, case.copy_from) + case.copy_size > return_len) return .halt;
    var window: [window_bytes]u8 = @splat(0);
    @memcpy(window[input_offset..][0..case.input.len], case.input);
    const out_count = @min(case.out_size, return_len);
    @memcpy(window[case.out_offset..][0..out_count], return_data[0..out_count]);
    primitives.word_to_be(window[0..32], @intFromBool(!reverted));
    primitives.word_to_be(window[32..64], return_len);
    const copied = return_data[case.copy_from..][0..case.copy_size];
    @memcpy(window[copy_offset..][0..case.copy_size], copied);
    return .{ .window = window };
}

fn random_case(prng: *Prng, input_buffer: *[input_bytes_max]u8) Case {
    const input_len: usize = @intCast(prng.below(input_bytes_max + 1));
    for (input_buffer[0..input_len]) |*byte| byte.* = @truncate(prng.int(u64));
    if (input_len > 0 and prng.below(4) == 0) input_buffer[0] = 0xff; // Revert path.
    const return_len: u64 = header_bytes + input_len;
    const out_offset: u16 = @intCast(prng.range(64, input_offset - 0x40));
    const copy_size: u16 = @intCast(prng.below(return_len + 2));
    const copy_from: u16 = @intCast(prng.below(return_len + 2 - copy_size));
    return .{
        .kind = @fromBackingInt(@intCast(prng.below(4))),
        .value = if (prng.below(2) == 0) 0 else prng.below(1000),
        .input = input_buffer[0..input_len],
        .out_offset = out_offset,
        .out_size = @intCast(prng.below(input_offset - @as(u64, out_offset) + 1)),
        .copy_from = copy_from,
        .copy_size = copy_size,
    };
}

fn check(h: *Harness, case: Case) !void {
    var code: [600]u8 = undefined;
    try h.database.put_account(caller_contract, balance, 1, caller_program(&code, case));
    try h.database.put_account(callee_contract, 0, 1, &callee_code);
    h.state.reset(h.database.interface());
    const outcome = try h.call(.osaka, caller_contract, case.input, gas_limit);
    switch (model(case)) {
        .halt => try std.testing.expectEqual(evm_module.Status.halt, outcome.status),
        .window => |window| {
            try std.testing.expectEqual(evm_module.Status.success, outcome.status);
            try std.testing.expectEqualSlices(u8, &window, outcome.output);
        },
    }
}

fn fuzz_calls(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    const take = @min(bytes.len, 8);
    @memcpy(seed[0..take], bytes[0..take]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    var input: [input_bytes_max]u8 = undefined;
    try check(h, random_case(&prng, &input));
}

test "call fuzz: each call kind's caller, value, and address" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    const input = [_]u8{ 1, 2, 3 };
    for ([_]Kind{ .call, .callcode, .delegatecall, .staticcall }) |kind| {
        try check(&h, .{
            .kind = kind,
            .value = 7,
            .input = &input,
            .out_offset = 64,
            .out_size = 128,
            .copy_from = 0,
            .copy_size = 99,
        });
    }
}

test "call fuzz: CALL family against a two-contract model" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_calls, .{ .seed = 0xca11_0001, .iterations = 300 });
}

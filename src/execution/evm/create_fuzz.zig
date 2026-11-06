//! Differential fuzz of CREATE/CREATE2 against a model of address derivation and the
//! creation rules.
//!
//! Factory F (random nonce) copies its calldata, the init code, to memory and runs CREATE or
//! CREATE2 (random salt), then returns the pushed address. The init code returns a random
//! runtime, or one starting with 0xef (EIP-3541), or one over the EIP-170 limit; sometimes
//! the derived address is pre-occupied (EIP-684 collision) or the init code exceeds the
//! EIP-3860 limit (F itself halts). The model predicts the returned word, the created code,
//! and F's nonce afterwards.

const std = @import("std");
const assert = std.debug.assert;
const op = @import("opcode.zig");
const evm_module = @import("evm.zig");
const primitives = @import("primitives.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Harness = @import("evm_test.zig").Harness;
const Address = primitives.Address;

const factory = primitives.address_from_int(0xfac7);
const gas_limit: u64 = 10_000_000;
const runtime_bytes_max = 64;
const code_size_max = 24_576;
const initcode_size_max = 2 * code_size_max;

const Variant = enum { normal, ef_prefix, collision, runtime_too_large, initcode_too_large };

const Case = struct {
    variant: Variant,
    is_create2: bool,
    nonce: u64,
    salt: u256,
    runtime: [runtime_bytes_max]u8,
    runtime_len: u8,
};

/// F: CALLDATACOPY(0, 0, CALLDATASIZE); CREATE[2](0, 0, CALLDATASIZE[, salt]);
/// MSTORE(0, result); RETURN(0, 32).
fn factory_code(buffer: []u8, case: Case) []const u8 {
    var length: usize = 0;
    const head = [_]u8{ op.CALLDATASIZE, op.PUSH1, 0, op.PUSH1, 0, op.CALLDATACOPY };
    @memcpy(buffer[length..][0..head.len], &head);
    length += head.len;
    if (case.is_create2) {
        buffer[length] = op.PUSH32;
        primitives.word_to_be(buffer[length + 1 ..][0..32], case.salt);
        length += 33;
    }
    const create = [_]u8{
        op.CALLDATASIZE,                                op.PUSH1, 0, op.PUSH1,  0,
        if (case.is_create2) op.CREATE2 else op.CREATE, op.PUSH1, 0, op.MSTORE, op.PUSH1,
        32,                                             op.PUSH1, 0, op.RETURN,
    };
    @memcpy(buffer[length..][0..create.len], &create);
    length += create.len;
    assert(length <= buffer.len);
    return buffer[0..length];
}

/// Init code writing the runtime to memory in 32-byte words and returning it; or returning
/// 24577 zero bytes; padded with zeros past the EIP-3860 limit for that variant.
fn init_code(buffer: []u8, case: Case) []const u8 {
    var length: usize = 0;
    if (case.variant == .runtime_too_large) {
        const big = [_]u8{ op.PUSH2, 0x60, 0x01, op.PUSH1, 0, op.RETURN }; // 24577 bytes.
        @memcpy(buffer[0..big.len], &big);
        return buffer[0..big.len];
    }
    var word_index: usize = 0;
    while (word_index * 32 < case.runtime_len) : (word_index += 1) {
        buffer[length] = op.PUSH32;
        @memcpy(buffer[length + 1 ..][0..32], case.runtime[word_index * 32 ..][0..32]);
        buffer[length + 33] = op.PUSH1;
        buffer[length + 34] = @intCast(word_index * 32);
        buffer[length + 35] = op.MSTORE;
        length += 36;
    }
    const tail = [_]u8{ op.PUSH1, case.runtime_len, op.PUSH1, 0, op.RETURN };
    @memcpy(buffer[length..][0..tail.len], &tail);
    length += tail.len;
    if (case.variant == .initcode_too_large) {
        @memset(buffer[length .. initcode_size_max + 1], 0);
        length = initcode_size_max + 1;
    }
    assert(length <= buffer.len);
    return buffer[0..length];
}

fn derived_address(case: Case, init: []const u8) Address {
    if (case.is_create2) return evm_module.create2_address(factory, case.salt, init);
    return evm_module.create_address(factory, case.nonce);
}

fn random_case(prng: *Prng) Case {
    var case = Case{
        .variant = @fromBackingInt(@intCast(prng.below(5))),
        .is_create2 = prng.below(2) == 0,
        .nonce = prng.range(1, 1 << 20),
        .salt = prng.int(u256),
        .runtime = undefined,
        .runtime_len = @intCast(prng.range(1, runtime_bytes_max)),
    };
    for (&case.runtime) |*byte| byte.* = @truncate(prng.int(u64));
    if (case.runtime[0] == 0xef) case.runtime[0] = 0xee;
    if (case.variant == .ef_prefix) case.runtime[0] = 0xef;
    return case;
}

fn check(h: *Harness, case: Case, init_buffer: []u8) !void {
    var code_buffer: [64]u8 = undefined;
    const init = init_code(init_buffer, case);
    const address = derived_address(case, init);
    try h.database.put_account(factory, 0, case.nonce, factory_code(&code_buffer, case));
    if (case.variant == .collision) try h.database.put_account(address, 0, 1, &.{});
    h.state.reset(h.database.interface());
    const outcome = try h.call(.osaka, factory, init, gas_limit);
    if (case.variant == .initcode_too_large) {
        try std.testing.expectEqual(evm_module.Status.halt, outcome.status);
        return;
    }
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    const succeeds = case.variant == .normal;
    const expected: u256 = if (succeeds) primitives.address_to_u256(address) else 0;
    try std.testing.expectEqual(expected, primitives.word_from_be(outcome.output[0..32]));
    const factory_account = try h.state.load(factory);
    try std.testing.expectEqual(case.nonce + 1, factory_account.info.nonce);
    const created = try h.state.load(address);
    const code = try h.state.code(created);
    if (succeeds) {
        try std.testing.expectEqual(@as(u64, 1), created.info.nonce);
        try std.testing.expectEqualSlices(u8, case.runtime[0..case.runtime_len], code);
    } else {
        try std.testing.expectEqual(@as(usize, 0), code.len);
    }
}

fn fuzz_create(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    @memcpy(seed[0..@min(bytes.len, 8)], bytes[0..@min(bytes.len, 8)]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    var init_buffer: [initcode_size_max + 1]u8 = undefined;
    try check(h, random_case(&prng), &init_buffer);
}

test "create fuzz: CREATE/CREATE2 against an address-derivation and rules model" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_create, .{ .seed = 0xc4ea_0001, .iterations = 300 });
}

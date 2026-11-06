//! Differential fuzz of the memory and copy opcodes against a byte-array model.
//!
//! A random sequence of MSTORE, MSTORE8, MLOAD (stored back), MCOPY, CALLDATACOPY,
//! CALLDATALOAD (stored back), and CODECOPY runs as real bytecode, which then returns all
//! of memory (`RETURN(0, MSIZE)`). A plain byte array with the Yellow Paper expansion rule
//! (grow to the next word past any non-empty access) predicts the same bytes and size.
//! Source offsets may be huge (zero padding); memory offsets stay small so gas never runs
//! out.

const std = @import("std");
const assert = std.debug.assert;
const op = @import("opcode.zig");
const evm_module = @import("evm.zig");
const primitives = @import("primitives.zig");
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const Harness = @import("evm_test.zig").Harness;

const contract = primitives.address_from_int(0x3e3e);
const gas_limit: u64 = 10_000_000;
const operations_max = 16;
const memory_span = 1024; // Memory offsets and sizes stay below this.
const model_bytes = 4096; // Covers every reachable end offset (word aligned).
const code_bytes_max = operations_max * (4 * 33 + 2) + 8;

const Kind = enum { mstore, mstore8, mload, mcopy, calldatacopy, calldataload, codecopy };

const Operation = struct {
    kind: Kind,
    /// Destination memory offset (or MLOAD/CALLDATALOAD source for the stored-back word).
    a: u256,
    b: u256,
    c: u256,
};

const Model = struct {
    bytes: [model_bytes]u8 = @splat(0),
    len: u64 = 0,

    fn touch(model: *Model, offset: u256, size: u256) void {
        if (size == 0) return;
        const end: u64 = @intCast(offset + size);
        assert(end <= model_bytes);
        model.len = @max(model.len, (end + 31) / 32 * 32);
    }

    fn copy_padded(
        model: *Model,
        destination: u64,
        source: []const u8,
        offset: u256,
        size: u64,
    ) void {
        for (0..size) |index| {
            const position = offset +| index;
            model.bytes[destination + index] = if (position < source.len)
                source[@intCast(position)]
            else
                0;
        }
    }
};

fn small(prng: *Prng) u256 {
    return prng.below(memory_span);
}

/// Source offsets: in range, just past the end, or absurdly large.
fn source_offset(prng: *Prng) u256 {
    return switch (prng.below(4)) {
        0 => @as(u256, std.math.maxInt(u256)) - prng.below(8),
        1 => @as(u256, 1) << @intCast(prng.range(32, 255)),
        else => prng.below(memory_span + 64),
    };
}

fn random_operation(prng: *Prng) Operation {
    const kind: Kind = @fromBackingInt(@intCast(prng.below(7)));
    return switch (kind) {
        .mstore => .{ .kind = kind, .a = small(prng), .b = prng.int(u256), .c = 0 },
        .mstore8 => .{ .kind = kind, .a = small(prng), .b = prng.int(u256), .c = 0 },
        .mload, .calldataload => .{
            .kind = kind,
            .a = small(prng),
            .b = if (kind == .mload) small(prng) else source_offset(prng),
            .c = 0,
        },
        .mcopy => .{ .kind = kind, .a = small(prng), .b = small(prng), .c = prng.below(300) },
        .calldatacopy, .codecopy => .{
            .kind = kind,
            .a = small(prng),
            .b = source_offset(prng),
            .c = prng.below(300),
        },
    };
}

fn emit_push(code: []u8, length: *usize, value: u256) void {
    code[length.*] = op.PUSH32;
    primitives.word_to_be(code[length.* + 1 ..][0..32], value);
    length.* += 33;
}

fn emit(code: []u8, length: *usize, operation: Operation) void {
    const o = operation;
    switch (o.kind) {
        .mstore, .mstore8 => {
            emit_push(code, length, o.b);
            emit_push(code, length, o.a);
            code[length.*] = if (o.kind == .mstore) op.MSTORE else op.MSTORE8;
            length.* += 1;
        },
        .mload, .calldataload => {
            // MSTORE(a, LOAD(b)).
            emit_push(code, length, o.b);
            code[length.*] = if (o.kind == .mload) op.MLOAD else op.CALLDATALOAD;
            length.* += 1;
            emit_push(code, length, o.a);
            code[length.*] = op.MSTORE;
            length.* += 1;
        },
        .mcopy, .calldatacopy, .codecopy => {
            emit_push(code, length, o.c);
            emit_push(code, length, o.b);
            emit_push(code, length, o.a);
            code[length.*] = switch (o.kind) {
                .mcopy => op.MCOPY,
                .calldatacopy => op.CALLDATACOPY,
                else => op.CODECOPY,
            };
            length.* += 1;
        },
    }
}

fn apply(model: *Model, operation: Operation, input: []const u8, code: []const u8) void {
    const o = operation;
    switch (o.kind) {
        .mstore => {
            model.touch(o.a, 32);
            primitives.word_to_be(model.bytes[@intCast(o.a)..][0..32], o.b);
        },
        .mstore8 => {
            model.touch(o.a, 1);
            model.bytes[@intCast(o.a)] = @truncate(o.b);
        },
        .mload => {
            model.touch(o.b, 32);
            var word: [32]u8 = model.bytes[@intCast(o.b)..][0..32].*;
            model.touch(o.a, 32);
            @memcpy(model.bytes[@intCast(o.a)..][0..32], &word);
        },
        .calldataload => {
            var word: [32]u8 = undefined;
            for (&word, 0..) |*byte, index| {
                const position = o.b +| index;
                byte.* = if (position < input.len) input[@intCast(position)] else 0;
            }
            model.touch(o.a, 32);
            @memcpy(model.bytes[@intCast(o.a)..][0..32], &word);
        },
        .mcopy => {
            if (o.c == 0) return;
            model.touch(@max(o.a, o.b), o.c);
            var scratch: [300]u8 = undefined;
            const size: usize = @intCast(o.c);
            @memcpy(scratch[0..size], model.bytes[@intCast(o.b)..][0..size]);
            @memcpy(model.bytes[@intCast(o.a)..][0..size], scratch[0..size]);
        },
        .calldatacopy, .codecopy => {
            if (o.c == 0) return;
            model.touch(o.a, o.c);
            const source = if (o.kind == .calldatacopy) input else code;
            model.copy_padded(@intCast(o.a), source, o.b, @intCast(o.c));
        },
    }
}

fn run_case(h: *Harness, prng: *Prng) !void {
    var input: [96]u8 = undefined;
    for (&input) |*byte| byte.* = @truncate(prng.int(u64));
    const input_len: usize = @intCast(prng.below(input.len + 1));
    var operations: [operations_max]Operation = undefined;
    const count: usize = @intCast(prng.range(1, operations_max));
    var code: [code_bytes_max]u8 = undefined;
    var length: usize = 0;
    for (operations[0..count]) |*operation| {
        operation.* = random_operation(prng);
        emit(&code, &length, operation.*);
    }
    const tail = [_]u8{ op.MSIZE, op.PUSH1, 0, op.RETURN };
    @memcpy(code[length..][0..tail.len], &tail);
    length += tail.len;
    assert(length <= code.len);

    var model: Model = .{};
    for (operations[0..count]) |operation| {
        apply(&model, operation, input[0..input_len], code[0..length]);
    }

    try h.database.put_account(contract, 0, 1, code[0..length]);
    h.state.reset(h.database.interface());
    const outcome = try h.call(.osaka, contract, input[0..input_len], gas_limit);
    try std.testing.expectEqual(evm_module.Status.success, outcome.status);
    try std.testing.expectEqual(model.len, outcome.output.len);
    try std.testing.expectEqualSlices(u8, model.bytes[0..@intCast(model.len)], outcome.output);
}

fn fuzz_memory(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    const take = @min(bytes.len, 8);
    @memcpy(seed[0..take], bytes[0..take]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    try run_case(h, &prng);
}

test "memory fuzz: copy opcodes against a byte-array model" {
    var h: Harness = undefined;
    try h.init(std.testing.allocator);
    defer h.deinit(std.testing.allocator);
    try fuzz.run_bytes(&h, fuzz_memory, .{ .seed = 0x3e3e_0001, .iterations = 300 });
}

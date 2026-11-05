//! Solidity-compatible dynamic storage for native precompiles: `string`/`bytes` values
//! (base/base `precompile-storage/src/types/bytes_like.rs`).
//!
//! Up to 31 bytes live in the base slot (`data ++ length * 2`); longer values store
//! `length * 2 + 1` in the base slot and 32-byte chunks from `keccak256(base)`. From Cobalt
//! (`dynamic_storage_tail_cleanup`) every write first reads the old metadata and zeroes long
//! chunks the new value no longer covers; Beryl leaves stale tails in place.

const std = @import("std");
const assert = std.debug.assert;
const native = @import("native.zig");
const keccak256 = @import("../../common/crypto/root.zig").keccak256;
const Context = native.Context;
const Error = native.Error;

/// Longest stored string a precompile reads back (token names, symbols, URIs).
pub const bytes_length_max = 4096;

const panic_overflow: u256 = 0x11;

fn data_slot(base_slot: u256) u256 {
    return std.mem.readInt(u256, &keccak256(&native.u256_word(base_slot)), .big);
}

fn is_long(value: u256) bool {
    return value & 1 != 0;
}

fn chunks(length: u64) u64 {
    return (length + 31) / 32;
}

fn panic(context: *Context) error{Revert} {
    return context.revert_word(native.error_panic, native.u256_word(panic_overflow));
}

/// The stored length; a corrupt short length (above 31) is a database failure.
fn stored_length(context: *Context, value: u256) Error!u64 {
    if (is_long(value)) {
        const length = (value - 1) >> 1;
        if (length > std.math.maxInt(u32)) return panic(context);
        return @intCast(length);
    }
    const length = @as(u8, @truncate(value)) / 2;
    if (length > 31) return error.DatabaseFailure;
    return length;
}

/// Read a value into `buffer`; values longer than `buffer` are a state-limit failure.
pub fn load(context: *Context, base_slot: u256, buffer: []u8) Error![]const u8 {
    const value = try context.sload(base_slot);
    const length = try stored_length(context, value);
    if (length > buffer.len) return error.StateFull;
    if (!is_long(value)) {
        const word = native.u256_word(value);
        @memcpy(buffer[0..length], word[0..length]);
        return buffer[0..length];
    }
    const start = data_slot(base_slot);
    var index: u64 = 0;
    while (index < chunks(length)) : (index += 1) {
        const word = native.u256_word(try context.sload(start +% index));
        const offset = index * 32;
        const take = @min(32, length - offset);
        @memcpy(buffer[offset..][0..take], word[0..take]);
    }
    return buffer[0..length];
}

pub fn store(context: *Context, base_slot: u256, bytes: []const u8) Error!void {
    assert(bytes.len <= std.math.maxInt(u32));
    const new_chunks: u64 = if (bytes.len <= 31) 0 else chunks(bytes.len);
    if (context.is_cobalt()) {
        if (context.is_static) return context.revert(&.{});
        try clear_stale_tail(context, base_slot, new_chunks);
    }
    if (bytes.len <= 31) {
        var word: [32]u8 = @splat(0);
        @memcpy(word[0..bytes.len], bytes);
        word[31] = @intCast(bytes.len * 2);
        return context.sstore(base_slot, std.mem.readInt(u256, &word, .big));
    }
    try context.sstore(base_slot, @as(u256, bytes.len) * 2 + 1);
    const start = data_slot(base_slot);
    var index: u64 = 0;
    while (index < new_chunks) : (index += 1) {
        const offset = index * 32;
        const take = @min(32, bytes.len - offset);
        var word: [32]u8 = @splat(0);
        @memcpy(word[0..take], bytes[offset..][0..take]);
        try context.sstore(start +% index, std.mem.readInt(u256, &word, .big));
    }
}

fn clear_stale_tail(context: *Context, base_slot: u256, new_chunks: u64) Error!void {
    const previous = try context.sload(base_slot);
    if (!is_long(previous)) return;
    const old_chunks = chunks(try stored_length(context, previous));
    if (new_chunks >= old_chunks) return;
    const start = data_slot(base_slot);
    var index = new_chunks;
    while (index < old_chunks) : (index += 1) try context.sstore(start +% index, 0);
}

pub fn delete(context: *Context, base_slot: u256) Error!void {
    const value = try context.sload(base_slot);
    if (is_long(value)) {
        const start = data_slot(base_slot);
        const count = chunks(try stored_length(context, value));
        var index: u64 = 0;
        while (index < count) : (index += 1) try context.sstore(start +% index, 0);
    }
    try context.sstore(base_slot, 0);
}

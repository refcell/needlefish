//! Execution environment: block context, transaction context, and EVM configuration.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const op = @import("op.zig");

pub const BlockEnv = struct {
    number: u64 = 0,
    coinbase: Address = primitives.address_zero,
    timestamp: u64 = 0,
    gas_limit: u64 = 30_000_000,
    base_fee: u256 = 0,
    /// Pre-merge DIFFICULTY.
    difficulty: u256 = 0,
    /// Post-merge PREVRANDAO (EIP-4399).
    prevrandao: B256 = primitives.b256_zero,
    /// EIP-4844 blob base fee, derived from the header's excess blob gas.
    blob_base_fee: u256 = 1,
    /// OP Stack / Base rules for this block; null runs plain Ethereum semantics.
    op: ?op.Context = null,
};

/// Per-transaction values visible to the interpreter.
pub const TxContext = struct {
    origin: Address = primitives.address_zero,
    /// Effective gas price paid per unit of gas.
    gas_price: u256 = 0,
    blob_hashes: []const B256 = &.{},
};

pub const Config = struct {
    chain_id: u64 = 1,
    /// Call depth limit (1024 on every Ethereum fork).
    depth_max: u16 = 1024,
    /// Shared memory for all frames. Growth beyond it halts as out-of-gas.
    memory_bytes_max: u32 = 64 << 20,
    /// LIFO arena for code analyses of live frames.
    code_arena_bytes: u32 = 96 << 20,
    /// Analysis cache by code hash: byte buffer and table slots (a power of two).
    code_cache_bytes: u32 = 64 << 20,
    code_cache_entries: u32 = 1 << 14,
    /// EIP-170 runtime code size limit.
    code_size_max: u32 = 24_576,
    /// EIP-3860 init code size limit.
    initcode_size_max: u32 = 2 * 24_576,
    /// Widest pre-Osaka MODEXP modulus the scratch arena supports. Byzantium pricing is the
    /// cheapest (gas >= len^2 / 320), so 576 KiB covers any transaction up to ~1e9 gas.
    modexp_modulus_bytes_max: u32 = 576 << 10,

    pub fn validate(config: Config) void {
        assert(config.depth_max >= 1 and config.depth_max <= 1024);
        assert(config.memory_bytes_max % 32 == 0);
        assert(config.code_size_max <= config.initcode_size_max);
    }
};

/// EIP-4844 fake exponential: factor * e^(numerator / denominator), integer only.
pub fn fake_exponential(factor: u256, numerator: u256, denominator: u256) u256 {
    assert(denominator != 0);
    var i: u256 = 1;
    var output: u256 = 0;
    var accumulator: u256 = factor * denominator;
    // Terms shrink geometrically; 1024 iterations bound every realistic input.
    var iterations: u32 = 0;
    while (accumulator > 0) : (iterations += 1) {
        assert(iterations < 1024);
        output += accumulator;
        accumulator = (accumulator * numerator) / (denominator * i);
        i += 1;
    }
    return output / denominator;
}

/// Blob base fee from excess blob gas; the update fraction changes per fork.
pub fn blob_base_fee(excess_blob_gas: u64, update_fraction: u64) u256 {
    return fake_exponential(1, excess_blob_gas, update_fraction);
}

pub const blob_update_fraction_cancun: u64 = 3_338_477;
pub const blob_update_fraction_prague: u64 = 5_007_716;

test "env: fake exponential" {
    try std.testing.expectEqual(@as(u256, 1), blob_base_fee(0, blob_update_fraction_cancun));
    try std.testing.expectEqual(@as(u256, 1), fake_exponential(1, 0, 1));
    try std.testing.expectEqual(@as(u256, 2), fake_exponential(1, 1, 1));
    try std.testing.expectEqual(@as(u256, 5), fake_exponential(2, 1, 1));
    try std.testing.expectEqual(@as(u256, 3), fake_exponential(1, 2, 2) + 1);
}

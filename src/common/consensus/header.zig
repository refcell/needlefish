//! Block header with the post-London optional fields in fork order.
//! Mirrors alloy-consensus `Header` as used by base/base.
//!
//! Optional fields (base fee, withdrawals root, blob gas, beacon root, requests hash) are
//! appended in order and must be contiguous: a field may be present only if every
//! earlier optional field is. Encoding asserts this; decoding enforces it by reading
//! optionals in order until the list ends.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const hashing = @import("hashing.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const B64 = primitives.B64;
const Bloom = primitives.Bloom;

pub const Header = struct {
    parent_hash: B256 = .zero,
    ommers_hash: B256 = primitives.empty_ommers_hash,
    beneficiary: Address = .zero,
    state_root: B256 = primitives.empty_root_hash,
    transactions_root: B256 = primitives.empty_root_hash,
    receipts_root: B256 = primitives.empty_root_hash,
    logs_bloom: Bloom = .zero,
    difficulty: u256 = 0,
    number: u64 = 0,
    gas_limit: u64 = 0,
    gas_used: u64 = 0,
    timestamp: u64 = 0,
    extra_data: []const u8 = &.{},
    mix_hash: B256 = .zero,
    nonce: B64 = .zero,
    /// London (EIP-1559).
    base_fee_per_gas: ?u64 = null,
    /// Shanghai (EIP-4895) / Canyon.
    withdrawals_root: ?B256 = null,
    /// Cancun (EIP-4844) / Ecotone.
    blob_gas_used: ?u64 = null,
    excess_blob_gas: ?u64 = null,
    /// Cancun (EIP-4788) / Ecotone.
    parent_beacon_block_root: ?B256 = null,
    /// Prague (EIP-7685) / Isthmus.
    requests_hash: ?B256 = null,
    /// Amsterdam (EIP-7928): hash of the block-level access list.
    block_access_list_hash: ?B256 = null,
    /// Amsterdam (EIP-7843): the beacon slot of the block.
    slot_number: ?u64 = null,

    const field_names = @typeInfo(Header).@"struct".field_names;
    const field_types = @typeInfo(Header).@"struct".field_types;

    fn is_optional(comptime index: usize) bool {
        return @typeInfo(field_types[index]) == .optional;
    }

    /// True when present optional fields form a prefix of the optional list.
    pub fn optionals_contiguous(header: Header) bool {
        var missing = false;
        inline for (field_names, 0..) |name, index| {
            if (comptime is_optional(index)) {
                if (@field(header, name) == null) {
                    missing = true;
                } else if (missing) return false;
            }
        }
        return true;
    }

    fn payload_length(header: Header) usize {
        var total: usize = 0;
        inline for (field_names, 0..) |name, index| {
            if (comptime is_optional(index)) {
                if (@field(header, name)) |present| total += rlp.length(present);
            } else {
                total += rlp.length(@field(header, name));
            }
        }
        return total;
    }

    pub fn rlp_length(header: Header) usize {
        return rlp.list_length(header.payload_length());
    }

    pub fn rlp_encode(header: Header, encoder: *rlp.Encoder) void {
        assert(header.optionals_contiguous());
        encoder.list_header(header.payload_length());
        inline for (field_names, 0..) |name, index| {
            if (comptime is_optional(index)) {
                if (@field(header, name)) |present| rlp.encode(encoder, present);
            } else {
                rlp.encode(encoder, @field(header, name));
            }
        }
    }

    pub fn rlp_decode(decoder: *rlp.Decoder) rlp.Error!Header {
        var items = try decoder.list();
        var header: Header = .{};
        inline for (field_names, field_types, 0..) |name, Field, index| {
            if (comptime is_optional(index)) {
                const Child = @typeInfo(Field).optional.child;
                @field(header, name) = if (items.is_empty())
                    null
                else
                    try rlp.decode(Child, &items);
            } else {
                @field(header, name) = try rlp.decode(Field, &items);
            }
        }
        try items.finish();
        assert(header.optionals_contiguous());
        return header;
    }

    /// keccak256(rlp(header)): the block hash.
    pub fn hash(header: Header) B256 {
        return hashing.keccak_rlp(header);
    }

    pub fn decode(encoded: []const u8) rlp.Error!Header {
        return rlp.decode_exact(Header, encoded);
    }
};

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "header: mainnet genesis hash" {
    // Ethereum mainnet genesis header, a public constant.
    var extra: [32]u8 = undefined;
    _ = try primitives.hex.decode(
        &extra,
        "11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
    );
    const header: Header = .{
        .state_root = B256.comptime_hex(
            "d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
        ),
        .difficulty = 17_179_869_184,
        .gas_limit = 5000,
        .extra_data = &extra,
        .nonce = B64.comptime_hex("0000000000000042"),
    };
    try testing.expect(header.hash().eql(B256.comptime_hex(
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
    )));
    var buffer: [600]u8 = undefined;
    const encoded = rlp.encode_to(&buffer, header);
    const decoded = try Header.decode(encoded);
    try testing.expect(decoded.hash().eql(header.hash()));
    try testing.expect(decoded.base_fee_per_gas == null);
}

test "header: seeded fuzz optional fields round trip" {
    var prng = Prng.init(0x4ead);
    var buffer: [700]u8 = undefined;
    for (0..200) |_| {
        var header: Header = .{
            .number = prng.int(u64),
            .gas_limit = prng.int(u64) >> 20,
            .timestamp = prng.int(u64),
            .difficulty = prng.int(u256) >> @intCast(prng.below(256)),
        };
        prng.fill(&header.parent_hash.bytes);
        prng.fill(&header.logs_bloom.bytes);
        const optional_count = prng.below(7);
        if (optional_count > 0) header.base_fee_per_gas = prng.int(u64);
        if (optional_count > 1) header.withdrawals_root = primitives.keccak256("w");
        if (optional_count > 2) header.blob_gas_used = prng.int(u64) >> 40;
        if (optional_count > 3) header.excess_blob_gas = prng.int(u64) >> 40;
        if (optional_count > 4) header.parent_beacon_block_root = .zero;
        if (optional_count > 5) header.requests_hash = primitives.keccak256("r");
        const encoded = rlp.encode_to(&buffer, header);
        try testing.expectEqual(rlp.length(header), encoded.len);
        const decoded = try Header.decode(encoded);
        var again: [700]u8 = undefined;
        try testing.expectEqualSlices(u8, encoded, rlp.encode_to(&again, decoded));
    }
    var gap: Header = .{ .withdrawals_root = .zero };
    try testing.expect(!gap.optionals_contiguous());
    gap.base_fee_per_gas = 7;
    try testing.expect(gap.optionals_contiguous());
}

fn fuzz_header(_: void, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const len = smith.slice(&input);
    const header = Header.decode(input[0..len]) catch return;
    var again: [1024]u8 = undefined;
    try testing.expectEqualSlices(u8, input[0..len], rlp.encode_to(&again, header));
}

test "header: fuzz decode is canonical" {
    try testing.fuzz({}, fuzz_header, .{});
}

//! Primitive types shared by every Base component. Mirrors alloy-primitives as used by
//! base/base `crates/common`: hex, fixed bytes (`Address`, `B256`, `Bloom`), `u256`
//! conversions, keccak, and EIP-55 checksums.

const std = @import("std");

pub const hex = @import("hex.zig");
pub const bytes = @import("bytes.zig");

pub const FixedBytes = bytes.FixedBytes;
pub const Address = bytes.Address;
pub const B256 = bytes.B256;
pub const B64 = bytes.B64;
pub const Bloom = bytes.Bloom;
pub const keccak256 = bytes.keccak256;
pub const keccak_empty = bytes.keccak_empty;
pub const empty_ommers_hash = bytes.empty_ommers_hash;
pub const empty_root_hash = bytes.empty_root_hash;
pub const checksum = bytes.checksum;
pub const parse_address_checked = bytes.parse_address_checked;
pub const u256_to_bytes = bytes.u256_to_bytes;
pub const u256_from_bytes = bytes.u256_from_bytes;
pub const u256_from_be_slice = bytes.u256_from_be_slice;

test {
    std.testing.refAllDecls(@This());
}

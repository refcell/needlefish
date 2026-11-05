//! Test fixture: contiguous chains of minimal header-shaped RLP lists for witness tests.
//!
//! A header here is `rlp([parent_hash, "", "", state_root, "", "", "", "", number])`: the
//! fields `witness.header_link` reads, at their real header positions. Header 1's parent
//! hash is zero; each later header's parent hash is keccak256 of the previous header.

const std = @import("std");
const assert = std.debug.assert;

const witness = @import("witness.zig");
const trie = @import("../trie/root.zig");
const rlp = trie.rlp;

const Hash = witness.Hash;

/// List header (2) + two hashes (2 x 33) + six empty strings (6) + number (at most 9).
pub const header_bytes_max = 2 + 2 * 33 + 6 + 9;

/// Encodes one header into `buffer`; returns the encoded bytes.
pub fn encode(
    buffer: *[header_bytes_max]u8,
    parent_hash: *const Hash,
    state_root: *const Hash,
    number: u64,
) []const u8 {
    return encode_salted(buffer, parent_hash, state_root, number, 0);
}

/// As `encode`, with `salt` (< 0x80, one byte) in field 1 so sibling blocks with the same
/// parent and state root hash differently; salt 0 is the empty string.
pub fn encode_salted(
    buffer: *[header_bytes_max]u8,
    parent_hash: *const Hash,
    state_root: *const Hash,
    number: u64,
    salt: u8,
) []const u8 {
    assert(salt < 0x80);
    var number_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &number_bytes, number, .big);
    const leading = @clz(number) / 8;
    const number_minimal = number_bytes[leading..];
    var payload: [header_bytes_max]u8 = undefined;
    var length: u32 = 0;
    length += rlp.write_string(payload[length..], parent_hash);
    const salt_bytes = [1]u8{salt};
    const salt_field: []const u8 = if (salt == 0) &.{} else &salt_bytes;
    length += rlp.write_string(payload[length..], salt_field);
    length += rlp.write_string(payload[length..], &.{});
    length += rlp.write_string(payload[length..], state_root);
    for (0..4) |_| length += rlp.write_string(payload[length..], &.{});
    length += rlp.write_string(payload[length..], number_minimal);
    const head = rlp.write_list_header(buffer, length);
    @memcpy(buffer[head..][0..length], payload[0..length]);
    const encoded = buffer[0 .. head + length];
    assert(encoded.len <= header_bytes_max);
    return encoded;
}

/// Headers 1..parent, oldest first. Holds slices into itself: build in place, never move.
pub const HeaderChain = struct {
    pub const count_max = 16;

    buffers: [count_max][header_bytes_max]u8 = undefined,
    items: [count_max][]const u8 = undefined,
    count: u32 = 0,

    /// Headers 1..`parent_number`; the parent holds `parent_state_root`, ancestors a root
    /// derived from their number.
    pub fn build(self: *HeaderChain, parent_number: u64, parent_state_root: Hash) void {
        assert(parent_number >= 1 and parent_number <= count_max);
        var parent_hash: Hash = @splat(0);
        var number: u64 = 1;
        while (number <= parent_number) : (number += 1) {
            const index: usize = @intCast(number - 1);
            const root: Hash = if (number == parent_number)
                parent_state_root
            else
                @splat(@intCast(number));
            self.items[index] = encode(&self.buffers[index], &parent_hash, &root, number);
            parent_hash = trie.node.keccak256(self.items[index]);
        }
        self.count = @intCast(parent_number);
        assert((witness.header_number(self.items[self.count - 1]) catch 0) == parent_number);
    }

    /// Every header, oldest first.
    pub fn headers(self: *const HeaderChain) []const []const u8 {
        assert(self.count > 0);
        return self.items[0..self.count];
    }

    pub fn hash(self: *const HeaderChain, number: u64) Hash {
        assert(number >= 1 and number <= self.count);
        return trie.node.keccak256(self.items[@intCast(number - 1)]);
    }

    /// The parent the chain ends at, for `SparseState.reset`.
    pub fn parent(self: *const HeaderChain) witness.SparseState.Parent {
        assert(self.count > 0);
        return .{ .number = self.count, .hash = self.hash(self.count) };
    }
};

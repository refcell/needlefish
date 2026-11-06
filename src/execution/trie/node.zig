//! Merkle Patricia Trie node encoding.
//!
//! Three node kinds exist: leaf `[hp(path, leaf), value]`, extension `[hp(path), child]`, and
//! branch `[child0 .. child15, value]`. A child reference is the child's RLP when it is shorter
//! than 32 bytes, otherwise the RLP string of its keccak256 hash. `RlpNode` holds exactly that
//! reference. Encoders stream into a sink, so a large leaf value is hashed in place, never
//! copied into a scratch buffer.

const std = @import("std");
const assert = std.debug.assert;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const rlp = @import("rlp.zig");
const nibbles = @import("nibbles.zig");

pub const Hash = [32]u8;

/// keccak256(rlp("")): the root of a trie with no entries.
pub const empty_root: Hash = hex_to_hash(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
);

/// keccak256(""): the code hash of an account without code.
pub const empty_code_hash: Hash = hex_to_hash(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
);

pub fn hex_to_hash(comptime hex: *const [64]u8) Hash {
    var result: Hash = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch unreachable; // Comptime literal, checked here.
    return result;
}

pub fn keccak256(bytes: []const u8) Hash {
    var result: Hash = undefined;
    Keccak256.hash(bytes, &result, .{});
    return result;
}

/// A child reference: raw RLP below 32 bytes, else `0xa0 ++ keccak256(rlp)`.
pub const RlpNode = struct {
    len: u8 = 0,
    bytes: [33]u8 = undefined,

    pub fn from_rlp(encoded: []const u8) RlpNode {
        assert(encoded.len > 0);
        if (encoded.len < 32) {
            var result: RlpNode = .{ .len = @intCast(encoded.len) };
            @memcpy(result.bytes[0..encoded.len], encoded);
            return result;
        }
        return from_hash(keccak256(encoded));
    }

    pub fn from_hash(hash: Hash) RlpNode {
        var result: RlpNode = .{ .len = 33 };
        result.bytes[0] = 0xa0;
        result.bytes[1..33].* = hash;
        assert(result.is_hash());
        return result;
    }

    pub fn slice(self: *const RlpNode) []const u8 {
        assert(self.len > 0);
        return self.bytes[0..self.len];
    }

    pub fn is_hash(self: *const RlpNode) bool {
        assert(self.len <= 33);
        assert(self.len != 32);
        return self.len == 33;
    }

    /// The hash that identifies this node as a trie root: the root node is always hashed, even
    /// when its encoding is shorter than 32 bytes.
    pub fn root_hash(self: *const RlpNode) Hash {
        if (self.is_hash()) return self.bytes[1..33].*;
        return keccak256(self.slice());
    }
};

/// Sink that hashes an encoding of 32 bytes or more and buffers anything shorter.
pub const RefSink = struct {
    total: u64,
    written: u64 = 0,
    hasher: Keccak256,
    small: [31]u8 = undefined,

    pub fn init(total: u64) RefSink {
        assert(total > 0);
        return .{ .total = total, .hasher = Keccak256.init(.{}) };
    }

    pub fn write(self: *RefSink, bytes: []const u8) void {
        assert(self.written + bytes.len <= self.total);
        if (self.total < 32) {
            @memcpy(self.small[@intCast(self.written)..][0..bytes.len], bytes);
        } else {
            self.hasher.update(bytes);
        }
        self.written += bytes.len;
    }

    pub fn finish(self: *RefSink) RlpNode {
        assert(self.written == self.total);
        if (self.total < 32) return RlpNode.from_rlp(self.small[0..@intCast(self.total)]);
        var hash: Hash = undefined;
        self.hasher.final(&hash);
        return RlpNode.from_hash(hash);
    }
};

/// Sink that writes the full encoding into a caller buffer, used for proofs and storage.
pub const BufferSink = struct {
    buffer: []u8,
    written: usize = 0,

    pub fn write(self: *BufferSink, bytes: []const u8) void {
        assert(self.written + bytes.len <= self.buffer.len);
        const out = self.buffer[self.written..];
        // Branch encodings are mostly 33-byte child hashes and 1-byte empty slots: copy
        // those inline instead of calling memmove per child.
        switch (bytes.len) {
            1 => out[0] = bytes[0],
            33 => out[0..33].* = bytes[0..33].*,
            else => @memcpy(out[0..bytes.len], bytes),
        }
        self.written += bytes.len;
    }

    pub fn result(self: *const BufferSink) []u8 {
        return self.buffer[0..self.written];
    }
};

fn write_list_header(sink: anytype, payload_length: u64) void {
    var header: [rlp.header_length_max]u8 = undefined;
    const n = rlp.write_list_header(&header, payload_length);
    sink.write(header[0..n]);
}

fn write_string(sink: anytype, bytes: []const u8) void {
    var header: [rlp.header_length_max]u8 = undefined;
    const n = rlp.write_string_header(&header, bytes);
    sink.write(header[0..n]);
    sink.write(bytes);
}

fn encoded_length(payload_length: u64) u64 {
    return rlp.header_length(payload_length) + payload_length;
}

/// Encoded length of the hex-prefix string of a path of `path_length` nibbles.
fn hex_prefix_string_length(path_length: usize) u64 {
    const hp_length = path_length / 2 + 1;
    assert(hp_length <= nibbles.hex_prefix_bytes_max);
    return if (hp_length == 1) 1 else rlp.header_length(hp_length) + hp_length;
}

pub fn leaf_length(path: []const u8, value: []const u8) u64 {
    return encoded_length(hex_prefix_string_length(path.len) + rlp.string_encoded_length(value));
}

pub fn encode_leaf(sink: anytype, path: []const u8, value: []const u8) void {
    var hp: [nibbles.hex_prefix_bytes_max]u8 = undefined;
    encode_leaf_compact(sink, hp[0..nibbles.hex_prefix_encode(path, true, &hp)], value);
}

pub fn leaf_ref(path: []const u8, value: []const u8) RlpNode {
    var hp: [nibbles.hex_prefix_bytes_max]u8 = undefined;
    return leaf_ref_compact(hp[0..nibbles.hex_prefix_encode(path, true, &hp)], value);
}

/// Leaf length from an already hex-prefix encoded path `hp` (flag nibble included).
pub fn leaf_length_compact(hp: []const u8, value: []const u8) u64 {
    assert(hp.len > 0);
    assert(hp[0] >> 4 == 2 or hp[0] >> 4 == 3);
    return encoded_length(rlp.string_encoded_length(hp) + rlp.string_encoded_length(value));
}

pub fn encode_leaf_compact(sink: anytype, hp: []const u8, value: []const u8) void {
    assert(hp.len > 0);
    write_list_header(sink, rlp.string_encoded_length(hp) + rlp.string_encoded_length(value));
    write_string(sink, hp);
    write_string(sink, value);
}

pub fn leaf_ref_compact(hp: []const u8, value: []const u8) RlpNode {
    var sink = RefSink.init(leaf_length_compact(hp, value));
    encode_leaf_compact(&sink, hp, value);
    return sink.finish();
}

pub fn extension_length(path: []const u8, child: *const RlpNode) u64 {
    assert(path.len > 0);
    return encoded_length(hex_prefix_string_length(path.len) + child.len);
}

pub fn encode_extension(sink: anytype, path: []const u8, child: *const RlpNode) void {
    assert(path.len > 0);
    var hp: [nibbles.hex_prefix_bytes_max]u8 = undefined;
    encode_extension_compact(sink, hp[0..nibbles.hex_prefix_encode(path, false, &hp)], child);
}

pub fn extension_ref(path: []const u8, child: *const RlpNode) RlpNode {
    assert(path.len > 0);
    var hp: [nibbles.hex_prefix_bytes_max]u8 = undefined;
    return extension_ref_compact(hp[0..nibbles.hex_prefix_encode(path, false, &hp)], child);
}

/// Extension length from an already hex-prefix encoded, non-empty path `hp`.
pub fn extension_length_compact(hp: []const u8, child: *const RlpNode) u64 {
    assert(hp.len > 0);
    assert(hp[0] >> 4 == 0 or hp[0] >> 4 == 1);
    assert(hp.len > 1 or hp[0] >> 4 == 1); // The path is not empty.
    return encoded_length(rlp.string_encoded_length(hp) + child.len);
}

pub fn encode_extension_compact(sink: anytype, hp: []const u8, child: *const RlpNode) void {
    assert(hp.len > 0);
    write_list_header(sink, rlp.string_encoded_length(hp) + child.len);
    write_string(sink, hp);
    sink.write(child.slice());
}

pub fn extension_ref_compact(hp: []const u8, child: *const RlpNode) RlpNode {
    var sink = RefSink.init(extension_length_compact(hp, child));
    encode_extension_compact(&sink, hp, child);
    return sink.finish();
}

/// `children` holds one reference per set bit of `mask`, in nibble order. An empty `value`
/// encodes as the empty string, which is how a branch without a value is written.
fn branch_payload_length(mask: u16, children: []const RlpNode, value: []const u8) u64 {
    assert(@popCount(mask) == children.len);
    assert(children.len <= 16);
    var payload: u64 = 16 - children.len;
    for (children) |*child| payload += child.len;
    return payload + rlp.string_encoded_length(value);
}

pub fn branch_length(mask: u16, children: []const RlpNode, value: []const u8) u64 {
    return encoded_length(branch_payload_length(mask, children, value));
}

pub fn encode_branch(sink: anytype, mask: u16, children: []const RlpNode, value: []const u8) void {
    write_list_header(sink, branch_payload_length(mask, children, value));
    var next: u32 = 0;
    var nibble: u5 = 0;
    while (nibble < 16) : (nibble += 1) {
        if (mask & (@as(u16, 1) << @intCast(nibble)) != 0) {
            sink.write(children[next].slice());
            next += 1;
        } else {
            sink.write(&.{0x80});
        }
    }
    assert(next == children.len);
    write_string(sink, value);
}

pub fn branch_ref(mask: u16, children: []const RlpNode, value: []const u8) RlpNode {
    assert(mask != 0 or value.len > 0);
    var sink = RefSink.init(branch_length(mask, children, value));
    encode_branch(&sink, mask, children, value);
    return sink.finish();
}

const testing = std.testing;

test "node: empty roots" {
    try testing.expectEqual(empty_root, keccak256(&.{0x80}));
    try testing.expectEqual(empty_code_hash, keccak256(&.{}));
}

test "node: small leaf is embedded, large leaf is hashed" {
    const small = leaf_ref(&.{ 1, 2 }, "ab");
    try testing.expect(!small.is_hash());
    try testing.expectEqualSlices(u8, &.{ 0xc6, 0x82, 0x20, 0x12, 0x82, 'a', 'b' }, small.slice());
    const value: [100]u8 = @splat(7);
    const large = leaf_ref(&.{ 1, 2 }, &value);
    try testing.expect(large.is_hash());
    var buffer: [200]u8 = undefined;
    var sink: BufferSink = .{ .buffer = &buffer };
    encode_leaf(&sink, &.{ 1, 2 }, &value);
    try testing.expectEqual(leaf_length(&.{ 1, 2 }, &value), sink.written);
    try testing.expectEqual(keccak256(sink.result()), large.root_hash());
}

//! Merkle proof verification.
//!
//! Verifies proofs in the `eth_getProof` format: the root node first, then each node on the
//! key's path whose reference is a hash. Nodes shorter than 32 bytes are embedded in their
//! parent and are followed in place. A proof either proves a value (inclusion) or proves that
//! the key is absent (exclusion). The walk is iterative and bounded by the key length.

const std = @import("std");
const assert = std.debug.assert;

const rlp = @import("rlp.zig");
const node = @import("node.zig");
const nibbles_module = @import("nibbles.zig");
const Nibbles = nibbles_module.Nibbles;
const Hash = node.Hash;

pub const VerifyError = error{
    MissingNode,
    HashMismatch,
    InvalidNode,
    UnusedNodes,
    KeyTooLong,
} || rlp.DecodeError;

const Reference = union(enum) {
    hash: Hash,
    embedded: []const u8,
};

fn child_reference(item: rlp.Item) VerifyError!?Reference {
    switch (item.kind) {
        .string => {
            if (item.payload.len == 0) return null;
            if (item.payload.len != 32) return error.InvalidNode;
            return .{ .hash = item.payload[0..32].* };
        },
        .list => {
            if (item.raw.len >= 32) return error.InvalidNode;
            return .{ .embedded = item.raw };
        },
    }
}

/// Returns the value stored under `key`, or null if the proof shows the key is absent. The
/// returned slice points into `proof`.
pub fn verify(root: Hash, key: []const u8, proof: []const []const u8) VerifyError!?[]const u8 {
    if (key.len > nibbles_module.key_bytes_max) return error.KeyTooLong;
    if (proof.len == 0) {
        if (std.mem.eql(u8, &root, &node.empty_root)) return null;
        return error.MissingNode;
    }
    const path = Nibbles.from_bytes(key);
    var rest: []const u8 = path.slice();
    var reference: Reference = .{ .hash = root };
    var used: u32 = 0;
    var steps: u32 = 0;
    while (steps <= nibbles_module.nibbles_max + 1) : (steps += 1) {
        const current: []const u8 = switch (reference) {
            .embedded => |bytes| bytes,
            .hash => |hash| blk: {
                if (used == proof.len) return error.MissingNode;
                const bytes = proof[used];
                used += 1;
                if (!std.mem.eql(u8, &node.keccak256(bytes), &hash)) return error.HashMismatch;
                break :blk bytes;
            },
        };
        const step = try walk(current, &rest);
        switch (step) {
            .found => |value| {
                if (used != proof.len) return error.UnusedNodes;
                return value;
            },
            .absent => {
                if (used != proof.len) return error.UnusedNodes;
                return null;
            },
            .next => |next| reference = next,
        }
    }
    return error.InvalidNode;
}

const Step = union(enum) {
    found: []const u8,
    absent,
    next: Reference,
};

/// Decodes one node and moves `rest` past the nibbles it consumes.
fn walk(current: []const u8, rest: *[]const u8) VerifyError!Step {
    const outer = try rlp.decode_item(current);
    if (outer.kind != .list or outer.encoded_length != current.len) return error.InvalidNode;
    var items: [17]rlp.Item = undefined;
    const count = rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) {
        if (items[16].kind != .string) return error.InvalidNode;
        if (rest.len == 0) {
            if (items[16].payload.len == 0) return .absent;
            return .{ .found = items[16].payload };
        }
        const nibble = rest.*[0];
        rest.* = rest.*[1..];
        const next = try child_reference(items[nibble]) orelse return .absent;
        return .{ .next = next };
    }
    if (count != 2) return error.InvalidNode;
    if (items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch {
        return error.InvalidNode;
    };
    const node_path = decoded.path.slice();
    if (decoded.leaf) {
        if (items[1].kind != .string) return error.InvalidNode;
        if (!std.mem.eql(u8, node_path, rest.*)) return .absent;
        if (items[1].payload.len == 0) return error.InvalidNode;
        return .{ .found = items[1].payload };
    }
    if (node_path.len == 0) return error.InvalidNode;
    if (!std.mem.startsWith(u8, rest.*, node_path)) return .absent;
    rest.* = rest.*[node_path.len..];
    const next = try child_reference(items[1]) orelse return error.InvalidNode;
    return .{ .next = next };
}

test "proof: empty trie proves absence with no nodes" {
    try std.testing.expectEqual(@as(?[]const u8, null), try verify(node.empty_root, "k", &.{}));
    const other = node.keccak256("x");
    try std.testing.expectError(error.MissingNode, verify(other, "k", &.{}));
}

//! The enclave's preimage oracle (base/base `crates/proof/tee/nitro-enclave/src/oracle.rs`):
//! the witness preimages of a prove request, loaded into a host `Store` that the
//! fault-proof client reads in process. Hints are ignored (the witness is complete).
//!
//! Every keccak256 and sha256 preimage is checked against its key before it is accepted.
//! Local and global generic keys depend on context; blob keys are keccak256(commitment
//! ++ z) and precompile keys keccak256(address ++ input), neither derivable from the value
//! alone, so derivation checks them instead. As in base/base's map, a repeated key keeps
//! its last value.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../../preimage/root.zig");
const host_store = @import("../../host/store.zig");
const keccak = @import("../../../common/crypto/keccak.zig");
const sha256 = @import("../../../common/crypto/sha256.zig");
const protocol = @import("protocol.zig");

pub const Error = host_store.Error || error{InvalidPreimage};

/// Rejects a hash-keyed preimage whose value does not hash to its key.
pub fn check_preimage(key: preimage.Key, value: []const u8) error{InvalidPreimage}!void {
    const digest: [32]u8 = switch (key.key_type) {
        .keccak256 => keccak.keccak256(value),
        .sha256 => sha256.sha256(value),
        .local, .global_generic, .blob, .precompile => return,
    };
    const expected: preimage.Key = .init(digest, key.key_type);
    if (!expected.eql(key)) return error.InvalidPreimage;
    assert(key.key_type == .keccak256 or key.key_type == .sha256);
}

/// Loads `preimages` into `store`, checking each value that is kept.
pub fn load(store: *host_store.Store, preimages: []const protocol.Preimage) Error!void {
    const count_before = store.count();
    var index = preimages.len;
    // Last value wins: walk backwards and keep the first value seen per key.
    while (index > 0) {
        index -= 1;
        const entry = &preimages[index];
        if (store.get(entry.key) != null) continue;
        try check_preimage(entry.key, entry.value);
        try store.put(entry.key, entry.value);
    }
    assert(store.count() >= count_before);
    assert(store.count() <= count_before + preimages.len);
}

const testing = std.testing;

test "enclave oracle: local values round trip without a hash check" {
    var store: host_store.Store = .init(testing.allocator, .{});
    defer store.deinit();
    const value: [128]u8 = @splat(0xab);
    const key: preimage.Key = .init(@splat(1), .local);
    try load(&store, &.{.{ .key = key, .value = &value }});
    try testing.expectEqualSlices(u8, &value, store.get(key).?);
}

test "enclave oracle: hash keys are checked" {
    var store: host_store.Store = .init(testing.allocator, .{});
    defer store.deinit();
    const value = "hello world";
    const keccak_key: preimage.Key = .keccak256(keccak.keccak256(value));
    const sha_key: preimage.Key = .sha256(sha256.sha256(value));
    try load(&store, &.{
        .{ .key = keccak_key, .value = value },
        .{ .key = sha_key, .value = value },
    });
    try testing.expectEqual(@as(u32, 2), store.count());
    const wrong_keccak: preimage.Key = .keccak256(@splat(0xaa));
    const wrong_sha: preimage.Key = .sha256(@splat(0xbb));
    for ([_]preimage.Key{ wrong_keccak, wrong_sha }) |key| {
        try testing.expectError(error.InvalidPreimage, check_preimage(key, value));
        try testing.expectError(error.InvalidPreimage, load(&store, &.{.{
            .key = key,
            .value = value,
        }}));
    }
    const generic: preimage.Key = .init(@splat(0xff), .global_generic);
    try check_preimage(generic, &.{ 0xbe, 0xef });
}

test "enclave oracle: a repeated key keeps its last value" {
    var store: host_store.Store = .init(testing.allocator, .{});
    defer store.deinit();
    const key: preimage.Key = .local(3);
    try load(&store, &.{
        .{ .key = key, .value = "first" },
        .{ .key = key, .value = "last" },
    });
    try testing.expectEqualStrings("last", store.get(key).?);
}

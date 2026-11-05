//! The agreed L2 safe head. Port of base/base `crates/proof/proof/src/sync.rs`
//! (`SafeHeadFetcher`): the keccak preimage of the agreed output root is
//! `version (32) ++ state root ++ message passer storage root ++ block hash`, version 0.
//! The pipeline cursor walk-back (`new_oracle_pipeline_cursor`) is the derivation
//! pipeline's own `initial_reset`.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");

const Hash = [32]u8;

pub const output_root_preimage_bytes = 128;

pub const OutputRoot = struct {
    state_root: Hash,
    message_passer_storage_root: Hash,
    block_hash: Hash,

    pub const DecodeError = error{InvalidOutputRootPreimage};

    pub fn decode(bytes: []const u8) DecodeError!OutputRoot {
        if (bytes.len != output_root_preimage_bytes) return error.InvalidOutputRootPreimage;
        const version: Hash = @splat(0);
        if (!std.mem.eql(u8, bytes[0..32], &version)) return error.InvalidOutputRootPreimage;
        return .{
            .state_root = bytes[32..64].*,
            .message_passer_storage_root = bytes[64..96].*,
            .block_hash = bytes[96..128].*,
        };
    }

    pub fn encode(root: *const OutputRoot) [output_root_preimage_bytes]u8 {
        var bytes: [output_root_preimage_bytes]u8 = @splat(0);
        bytes[32..64].* = root.state_root;
        bytes[64..96].* = root.message_passer_storage_root;
        bytes[96..128].* = root.block_hash;
        assert(std.mem.allEqual(u8, bytes[0..32], 0));
        return bytes;
    }
};

pub const Error = preimage.oracle.ReadError || OutputRoot.DecodeError;

/// The agreed safe head's block hash, from the agreed output root's preimage.
pub fn safe_head_hash(oracle: preimage.OracleReader, agreed_output_root: Hash) Error!Hash {
    var buffer: [output_root_preimage_bytes]u8 = undefined;
    const bytes = try oracle.get(.keccak256(agreed_output_root), &buffer);
    // The host is untrusted: the preimage must hash to the agreed output root.
    if (!std.mem.eql(u8, &keccak.keccak256(bytes), &agreed_output_root)) {
        return error.InvalidOutputRootPreimage;
    }
    const root = try OutputRoot.decode(bytes);
    return root.block_hash;
}

const testing = std.testing;
const test_oracle = @import("../test_oracle.zig");

test "sync: the safe head comes from the output root preimage" {
    var store: test_oracle.MapStore = .init();
    defer store.deinit();
    const root: OutputRoot = .{
        .state_root = @splat(1),
        .message_passer_storage_root = @splat(2),
        .block_hash = @splat(3),
    };
    const encoded = root.encode();
    const output_root = keccak.keccak256(&encoded);
    try store.put(.keccak256(output_root), &encoded);
    var harness: preimage.InProcess = undefined;
    try harness.init(testing.allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
        .channel_bytes = 1024,
    });
    defer harness.deinit(testing.allocator);
    const hash = try safe_head_hash(harness.oracle_reader(), output_root);
    try testing.expectEqual(root.block_hash, hash);
    // A preimage that does not hash to the requested root is rejected.
    const forged: Hash = @splat(9);
    try store.put(.keccak256(forged), &encoded);
    const result = safe_head_hash(harness.oracle_reader(), forged);
    try testing.expectError(error.InvalidOutputRootPreimage, result);
    var bad = encoded;
    bad[0] = 1;
    try testing.expectError(error.InvalidOutputRootPreimage, OutputRoot.decode(&bad));
    try testing.expectError(error.InvalidOutputRootPreimage, OutputRoot.decode(encoded[0..96]));
}

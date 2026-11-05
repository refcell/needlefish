//! Oracle-backed L1 blob provider for the derivation pipeline. Port of base/base
//! `crates/proof/proof/src/l1/blob_provider.rs`.
//!
//! Per blob: hint `l1-blob <versioned hash ++ L1 timestamp (8 bytes BE)>`, read the
//! 48-byte commitment under the `sha256` key of the versioned hash, then the 4096 field
//! elements, element `i` under the `blob` key `keccak256(commitment ++ root_i)` where
//! `root_i` is the 32-byte big-endian `i`-th root of unity in bit-reversal order.
//! The commitment must hash to the versioned hash and, with `verify`, the blob must
//! commit to it (one MSM per blob).
//!
//! Oracle failures return `error.NotFound` and set `failure` (see `l1_chain_provider`).

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const derive = @import("../../consensus/derive/root.zig");
const hint = @import("hint.zig");

const B256 = primitives.B256;
const BlockInfo = protocol.BlockInfo;
const Blob = derive.blob.Blob;
const ProviderError = derive.errors.ProviderError;

const field_elements = kzg.field_elements_per_blob;
const element_bytes = kzg.bytes_per_field_element;
comptime {
    assert(field_elements * element_bytes == @sizeOf(Blob));
}

pub const Failure = preimage.oracle.ReadError || hint.SendError || error{
    CommitmentMismatch,
    BlobMismatch,
    TooManyBlobs,
};

pub const Options = struct {
    blobs_max: u32 = 16,
    /// Recompute each blob's commitment (one MSM per blob).
    verify: bool = true,
};

pub const L1BlobProvider = struct {
    oracle: preimage.OracleReader,
    hints: preimage.HintWriter,
    settings: *const kzg.blob.Settings,
    workspace: *kzg.blob.Workspace,
    options: Options,
    blobs_storage: []Blob,
    pointers: []*const Blob,
    failure: ?Failure = null,

    /// `settings` and `workspace` are owned by the caller (about 1 MiB together).
    pub fn init(
        allocator: std.mem.Allocator,
        oracle: preimage.OracleReader,
        hints: preimage.HintWriter,
        settings: *const kzg.blob.Settings,
        workspace: *kzg.blob.Workspace,
        options: Options,
    ) std.mem.Allocator.Error!L1BlobProvider {
        assert(options.blobs_max > 0);
        const blobs_storage = try allocator.alloc(Blob, options.blobs_max);
        errdefer allocator.free(blobs_storage);
        const pointers = try allocator.alloc(*const Blob, options.blobs_max);
        for (pointers, blobs_storage) |*pointer, *blob| pointer.* = blob;
        return .{
            .oracle = oracle,
            .hints = hints,
            .settings = settings,
            .workspace = workspace,
            .options = options,
            .blobs_storage = blobs_storage,
            .pointers = pointers,
        };
    }

    pub fn deinit(self: *L1BlobProvider, allocator: std.mem.Allocator) void {
        allocator.free(self.pointers);
        allocator.free(self.blobs_storage);
        self.* = undefined;
    }

    /// Blob-provider contract. The slice is valid until the next call.
    pub fn blobs(
        self: *L1BlobProvider,
        block: BlockInfo,
        hashes: []const B256,
    ) ProviderError![]const *const Blob {
        if (hashes.len > self.blobs_storage.len) {
            if (self.failure == null) self.failure = error.TooManyBlobs;
            return error.NotFound;
        }
        for (hashes, self.blobs_storage[0..hashes.len]) |hash, *blob| {
            self.fetch_blob(block.timestamp, hash.bytes, blob) catch |err| {
                if (self.failure == null) self.failure = err;
                return error.NotFound;
            };
        }
        return self.pointers[0..hashes.len];
    }

    fn fetch_blob(self: *L1BlobProvider, timestamp: u64, hash: [32]u8, blob: *Blob) Failure!void {
        var timestamp_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &timestamp_bytes, timestamp, .big);
        try hint.send(self.hints, .l1_blob, &.{ &hash, &timestamp_bytes });
        var commitment: [kzg.bytes_per_commitment]u8 = undefined;
        try self.oracle.get_exact(.sha256(hash), &commitment);
        if (!std.mem.eql(u8, &kzg.versioned_hash(&commitment), &hash)) {
            return error.CommitmentMismatch;
        }
        var key_input: [kzg.bytes_per_commitment + 32]u8 = undefined;
        key_input[0..kzg.bytes_per_commitment].* = commitment;
        for (self.settings.roots_brp, 0..) |root, index| {
            key_input[kzg.bytes_per_commitment..].* = root.to_bytes_be();
            const key: preimage.Key = .init(keccak.keccak256(&key_input), .blob);
            const element = blob[index * element_bytes ..][0..element_bytes];
            try self.oracle.get_exact(key, element);
        }
        if (!self.options.verify) return;
        const computed = kzg.blob.blob_to_kzg_commitment(self.settings, self.workspace, blob) catch
            return error.BlobMismatch;
        if (!std.mem.eql(u8, &computed, &commitment)) return error.BlobMismatch;
    }
};

/// The 32-byte big-endian root of unity behind field element `index` of a blob.
pub fn root_bytes(settings: *const kzg.blob.Settings, index: u32) [32]u8 {
    assert(index < field_elements);
    return settings.roots_brp[index].to_bytes_be();
}

const testing = std.testing;
const builtin = @import("builtin");
const test_oracle = @import("../test_oracle.zig");

var test_storage: kzg.blob.Settings.Storage = undefined;
var test_workspace: kzg.blob.Workspace = undefined;
var test_blob: Blob = undefined;

/// Roots only (fast); the Lagrange points are decoded only when `full`.
fn test_settings(full: bool) !kzg.blob.Settings {
    if (full) return kzg.blob.Settings.init(&test_storage);
    kzg.blob.fill_roots_brp(&test_storage.roots_brp);
    return .{ .g1_lagrange = &test_storage.g1_lagrange, .roots_brp = &test_storage.roots_brp };
}

/// Serves `blob` with `commitment`; returns its versioned hash.
fn serve_blob(
    store: *test_oracle.MapStore,
    settings: *const kzg.blob.Settings,
    blob: *const Blob,
    commitment: [kzg.bytes_per_commitment]u8,
) ![32]u8 {
    const hash = kzg.versioned_hash(&commitment);
    try store.put(.sha256(hash), &commitment);
    var key_input: [kzg.bytes_per_commitment + 32]u8 = undefined;
    key_input[0..kzg.bytes_per_commitment].* = commitment;
    for (0..field_elements) |index| {
        key_input[kzg.bytes_per_commitment..].* = root_bytes(settings, @intCast(index));
        const key: preimage.Key = .init(keccak.keccak256(&key_input), .blob);
        try store.put(key, blob[index * element_bytes ..][0..element_bytes]);
    }
    return hash;
}

fn fill_test_blob(seed: u8) void {
    for (0..field_elements) |index| {
        const element = test_blob[index * element_bytes ..][0..element_bytes];
        element.* = @splat(seed +% @as(u8, @truncate(index)));
        element[0] = 0; // Canonical: below the BLS modulus.
    }
}

fn check_round_trip(full: bool) !void {
    const settings = try test_settings(full);
    var store: test_oracle.MapStore = .init();
    defer store.deinit();
    fill_test_blob(3);
    const commitment = if (full)
        try kzg.blob.blob_to_kzg_commitment(&settings, &test_workspace, &test_blob)
    else
        @as([kzg.bytes_per_commitment]u8, @splat(0xa5));
    const hash = try serve_blob(&store, &settings, &test_blob, commitment);
    var harness: preimage.InProcess = undefined;
    try harness.init(testing.allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
        .channel_bytes = 1024,
    });
    defer harness.deinit(testing.allocator);
    var provider: L1BlobProvider = try .init(
        testing.allocator,
        harness.oracle_reader(),
        harness.hint_writer(),
        &settings,
        &test_workspace,
        .{ .blobs_max = 2, .verify = full },
    );
    defer provider.deinit(testing.allocator);
    const block: BlockInfo = .{ .number = 1, .timestamp = 24 };
    const found = try provider.blobs(block, &.{.{ .bytes = hash }});
    try testing.expectEqual(@as(usize, 1), found.len);
    try testing.expectEqualSlices(u8, &test_blob, found[0]);
    // An unknown versioned hash fails and is recorded.
    try testing.expectError(error.NotFound, provider.blobs(block, &.{.{ .bytes = @splat(1) }}));
    try testing.expect(provider.failure != null);
}

test "l1_blob_provider: field elements reassemble the blob" {
    try check_round_trip(false);
}

test "l1_blob_provider: the commitment of a served blob verifies" {
    // An MSM over 4096 points takes seconds unoptimised.
    if (builtin.mode == .debug) return error.SkipZigTest;
    try check_round_trip(true);
}

test "l1_blob_provider: roots match the base/base root of unity" {
    const settings = try test_settings(false);
    // base/base: the order-2^32 root raised to 2^(32 - 12), placed in bit-reversal order.
    const Fr = @TypeOf(settings.roots_brp[0]);
    const order_32_root = Fr.from_int(
        10238227357739495823651030575849232062558860180284477541189508159991286009131,
    );
    const generator = order_32_root.pow(1 << 20);
    try testing.expect(settings.roots_brp[field_elements / 2].eql(generator));
    try testing.expect(settings.roots_brp[0].eql(Fr.one));
}

//! The host's beacon blob adapter against a fake beacon node over SimIo, with a fake KZG
//! (a blob's commitment is its first 48 bytes) so the test stays fast in Debug builds.

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const harness_module = @import("../../consensus/sources/sim_harness.zig");
const beacon_json = @import("../../consensus/sources/beacon_json.zig");
const beacon_blobs = @import("beacon_blobs.zig");

const Blob = [kzg.bytes_per_blob]u8;

const TestVerifier = struct {
    pub fn blob_versioned_hash(verifier: TestVerifier, blob: *const Blob) ?primitives.B256 {
        _ = verifier;
        return .init(kzg.versioned_hash(blob[0..48]));
    }

    pub fn sidecar_valid(
        verifier: TestVerifier,
        blob: *const Blob,
        sidecar: *const beacon_json.Sidecar,
    ) bool {
        _ = verifier;
        return std.mem.eql(u8, blob[0..48], &sidecar.commitment);
    }

    pub fn blob_commitment(verifier: TestVerifier, blob: *const Blob) ?[48]u8 {
        _ = verifier;
        return blob[0..48].*;
    }
};

const FakeBeacon = struct {
    blobs_body: []const u8,
    requests: u32 = 0,

    fn handle(
        fake: *FakeBeacon,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        fake.requests += 1;
        const target = request.target;
        const body = if (std.mem.startsWith(u8, target, "/eth/v1/beacon/genesis"))
            "{\"data\":{\"genesis_time\":\"1000\"}}"
        else if (std.mem.startsWith(u8, target, "/eth/v1/config/spec"))
            "{\"data\":{\"SECONDS_PER_SLOT\":\"12\"}}"
        else if (std.mem.startsWith(u8, target, "/eth/v1/beacon/blobs/5?"))
            fake.blobs_body
        else
            return response.fail(404);
        response.writer().writeAll(body) catch response.fail(500);
    }
};

const Harness = harness_module.Harness(*FakeBeacon, FakeBeacon.handle);
const Adapter = beacon_blobs.BeaconBlobs(io.SimIo, TestVerifier);

fn step(context: *anyopaque) anyerror!void {
    const harness: *Harness = @ptrCast(@alignCast(context));
    harness.world.run_for_ns(std.time.ns_per_ms);
}

test "beacon blobs: fetches a blob by versioned hash and slot" {
    const allocator = testing.allocator;
    var blob: Blob = @splat(0);
    @memset(blob[0..48], 0x5a);
    var body: std.Io.Writer.Allocating = .init(allocator);
    defer body.deinit();
    try body.writer.print("{{\"data\":[\"0x{x}\"]}}", .{&blob});

    var fake: FakeBeacon = .{ .blobs_body = body.written() };
    var harness: Harness = undefined;
    try harness.init(&fake, 0x31);
    defer harness.deinit();
    var provider: Adapter.Provider = undefined;
    const client_options = harness_module.client_options;
    try provider.init(allocator, &harness.client_io, harness.address, client_options, .{}, .{});
    defer provider.deinit();
    var adapter: Adapter = .{
        .provider = &provider,
        .verifier = .{},
        .pump = .{ .context = &harness, .step = step },
        .steps_max = 100_000,
    };
    const fetcher = adapter.fetcher();

    const hash = kzg.versioned_hash(blob[0..48]);
    const fetched = try fetcher.fetch(fetcher.context, hash, 1060);
    try testing.expectEqualSlices(u8, &blob, fetched.blob);
    try testing.expectEqualSlices(u8, blob[0..48], &fetched.commitment);
    // A cached blob is served again without a request.
    const requests = fake.requests;
    _ = try fetcher.fetch(fetcher.context, hash, 1060);
    try testing.expectEqual(requests, fake.requests);
    // Slot 6 is missing (404): the blob does not exist.
    var missing = hash;
    missing[31] ^= 1;
    try testing.expectError(error.NotFound, fetcher.fetch(fetcher.context, missing, 1072));
    // A blob the slot does not contain fails the fetch.
    var other = hash;
    other[31] ^= 2;
    try testing.expectError(error.SourceFailed, fetcher.fetch(fetcher.context, other, 1060));
    try testing.expect(!provider.busy());
    try testing.expectEqual(@as(u64, 4), adapter.fetches);
    assert(fake.requests >= 3);
}

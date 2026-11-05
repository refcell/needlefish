//! Blob provider tests over the simulated network with a canned beacon node: slot math,
//! request-order matching, 404 → BlobsUnavailable, missing or invalid blobs, both
//! endpoints, and (outside Debug) the real KZG commitment path.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const assert = std.debug.assert;

const io = @import("../../utilities/io/root.zig");
const http = @import("../../utilities/http/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const harness_module = @import("sim_harness.zig");
const blob_provider = @import("blob_provider.zig");
const beacon_json = @import("beacon_json.zig");

const B256 = primitives.B256;
const Blob = beacon_json.Blob;
const Sidecar = beacon_json.Sidecar;
const BlockInfo = @import("../protocol/root.zig").BlockInfo;
const Info = BlockInfo;

/// Fake KZG: a blob's commitment is its first 48 bytes; valid proofs start with 0xaa.
const TestVerifier = struct {
    pub fn blob_versioned_hash(verifier: TestVerifier, blob: *const Blob) ?B256 {
        _ = verifier;
        return .init(kzg.versioned_hash(blob[0..48]));
    }

    pub fn sidecar_valid(verifier: TestVerifier, blob: *const Blob, sidecar: *const Sidecar) bool {
        _ = verifier;
        return std.mem.eql(u8, blob[0..48], &sidecar.commitment) and sidecar.proof[0] == 0xaa;
    }
};

const FakeBeacon = struct {
    const Route = struct { prefix: []const u8, status: u16 = 200, body: []const u8 = "" };

    routes: [8]Route = undefined,
    count: u32 = 0,
    requests: u32 = 0,
    last_target: [8192]u8 = undefined,
    last_target_size: usize = 0,

    fn add(fake: *FakeBeacon, route: Route) void {
        assert(fake.count < fake.routes.len);
        fake.routes[fake.count] = route;
        fake.count += 1;
    }

    fn target(fake: *const FakeBeacon) []const u8 {
        return fake.last_target[0..fake.last_target_size];
    }

    fn handle(
        fake: *FakeBeacon,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        fake.requests += 1;
        const size = @min(request.target.len, fake.last_target.len);
        @memcpy(fake.last_target[0..size], request.target[0..size]);
        fake.last_target_size = size;
        for (fake.routes[0..fake.count]) |route| {
            if (!std.mem.startsWith(u8, request.target, route.prefix)) continue;
            if (route.status != 200) return response.fail(route.status);
            response.writer().writeAll(route.body) catch response.fail(500);
            return;
        }
        response.fail(404);
    }
};

const Harness = harness_module.Harness(*FakeBeacon, FakeBeacon.handle);
const Provider = blob_provider.BlobProvider(io.SimIo, TestVerifier);

fn test_blob(marker: u8) Blob {
    var blob: Blob = @splat(0);
    @memset(blob[0..48], marker);
    return blob;
}

fn hash_of(blob: *const Blob) B256 {
    return TestVerifier.blob_versioned_hash(.{}, blob).?;
}

/// `{"data":[...]}` with blobs, or sidecars with proofs starting with `proof_byte`.
fn body_json(allocator: std.mem.Allocator, blobs: []const Blob, sidecars: ?u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("{\"data\":[");
    for (blobs, 0..) |*blob, index| {
        if (index > 0) try writer.writeByte(',');
        if (sidecars) |proof_byte| {
            const proof: [48]u8 = @splat(proof_byte);
            try writer.print("{{\"index\":\"{d}\",\"blob\":\"0x{x}\",", .{ index, blob });
            try writer.print("\"kzg_commitment\":\"0x{x}\",", .{blob[0..48]});
            try writer.print("\"kzg_proof\":\"0x{x}\"}}", .{&proof});
        } else {
            try writer.print("\"0x{x}\"", .{blob});
        }
    }
    try writer.writeAll("]}");
    return out.toOwnedSlice();
}

const genesis_body = "{\"data\":{\"genesis_time\":\"1000\"}}";
const spec_body = "{\"data\":{\"SECONDS_PER_SLOT\":\"12\"}}";

fn setup(
    harness: *Harness,
    provider: *Provider,
    fake: *FakeBeacon,
    options: blob_provider.Options,
) !void {
    fake.add(.{ .prefix = "/eth/v1/beacon/genesis", .body = genesis_body });
    fake.add(.{ .prefix = "/eth/v1/config/spec", .body = spec_body });
    try harness.init(fake, 0x22);
    errdefer harness.deinit();
    try provider.init(
        testing.allocator,
        &harness.client_io,
        harness.address,
        harness_module.client_options,
        .{},
        options,
    );
}

test "blob provider: slot math" {
    try testing.expectEqual(@as(?u64, 5), blob_provider.slot_of(1060, 1000, 12));
    try testing.expectEqual(@as(?u64, 5), blob_provider.slot_of(1071, 1000, 12));
    try testing.expectEqual(@as(?u64, 0), blob_provider.slot_of(1000, 1000, 12));
    try testing.expectEqual(@as(?u64, null), blob_provider.slot_of(999, 1000, 12));
}

test "blob provider: fetches by slot and returns blobs in request order" {
    const allocator = testing.allocator;
    const blobs = [_]Blob{ test_blob(0x11), test_blob(0x22) };
    const body = try body_json(allocator, &blobs, null);
    defer allocator.free(body);
    var fake: FakeBeacon = .{};
    fake.add(.{ .prefix = "/eth/v1/beacon/blobs/5?", .body = body });
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{});
    defer harness.deinit();
    defer provider.deinit();

    const block: primitives.B256 = .init(@splat(7));
    const info: BlockInfo = .{ .hash = block, .number = 9, .timestamp = 1060 };
    const requested = [_]B256{ hash_of(&blobs[1]), hash_of(&blobs[0]) };
    try testing.expectError(error.NotAvailable, provider.blobs(info, &requested));
    try testing.expectError(error.NotAvailable, provider.blobs(info, &requested));
    harness.run();
    const result = try provider.blobs(info, &requested);
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqual(@as(u8, 0x22), result[0][0]);
    try testing.expectEqual(@as(u8, 0x11), result[1][0]);
    try testing.expectEqual(@as(u32, 3), fake.requests);
    var expected_target: [256]u8 = undefined;
    const prefix = "/eth/v1/beacon/blobs/5?versioned_hashes=";
    const expected = try std.fmt.bufPrint(&expected_target, prefix ++ "0x{x},0x{x}", .{
        &requested[0].bytes, &requested[1].bytes,
    });
    try testing.expectEqualStrings(expected, fake.target());
    // A different hash list for the same block is a new fetch.
    try testing.expectError(error.NotAvailable, provider.blobs(info, requested[0..1]));
    harness.run();
    try testing.expectEqual(@as(usize, 1), (try provider.blobs(info, requested[0..1])).len);
    try testing.expectEqual(@as(u64, 0), provider.stats.failures);
}

test "blob provider: 404 surfaces once as BlobsUnavailable, missing blobs retry" {
    const allocator = testing.allocator;
    const blobs = [_]Blob{test_blob(0x11)};
    const body = try body_json(allocator, &blobs, null);
    defer allocator.free(body);
    var fake: FakeBeacon = .{};
    fake.add(.{ .prefix = "/eth/v1/beacon/blobs/6?", .status = 404 });
    fake.add(.{ .prefix = "/eth/v1/beacon/blobs/7?", .body = body });
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{ .seconds_per_slot = 12 });
    defer harness.deinit();
    defer provider.deinit();
    const missed: Info = .{ .hash = .init(@splat(1)), .timestamp = 1072 };
    const wrong: Info = .{ .hash = .init(@splat(2)), .timestamp = 1084 };
    const other = [_]B256{hash_of(&test_blob(0x33))};
    try testing.expectError(error.NotAvailable, provider.blobs(missed, &other));
    try testing.expectError(error.NotAvailable, provider.blobs(wrong, &other));
    harness.run();
    try testing.expectError(error.BlobsUnavailable, provider.blobs(missed, &other));
    try testing.expectError(error.NotAvailable, provider.blobs(wrong, &other));
    try testing.expectEqual(@as(u64, 1), provider.stats.failures);
    // Seconds per slot came from the override: genesis plus two fetches.
    try testing.expectEqual(@as(u32, 3), fake.requests);
    harness.run();
}

test "blob provider: sidecars endpoint checks commitments and proofs" {
    const allocator = testing.allocator;
    const blobs = [_]Blob{ test_blob(0x11), test_blob(0x22) };
    const good = try body_json(allocator, &blobs, 0xaa);
    defer allocator.free(good);
    const bad = try body_json(allocator, &blobs, 0xbb);
    defer allocator.free(bad);
    var fake: FakeBeacon = .{};
    fake.add(.{ .prefix = "/eth/v1/beacon/blob_sidecars/5", .body = good });
    fake.add(.{ .prefix = "/eth/v1/beacon/blob_sidecars/6", .body = bad });
    var harness: Harness = undefined;
    var provider: Provider = undefined;
    try setup(&harness, &provider, &fake, .{ .endpoint = .blob_sidecars });
    defer harness.deinit();
    defer provider.deinit();
    const valid: Info = .{ .hash = .init(@splat(1)), .timestamp = 1060 };
    const invalid: Info = .{ .hash = .init(@splat(2)), .timestamp = 1072 };
    const requested = [_]B256{hash_of(&blobs[1])};
    try testing.expectError(error.NotAvailable, provider.blobs(valid, &requested));
    try testing.expectError(error.NotAvailable, provider.blobs(invalid, &requested));
    harness.run();
    const result = try provider.blobs(valid, &requested);
    try testing.expectEqual(@as(u8, 0x22), result[0][0]);
    try testing.expectError(error.NotAvailable, provider.blobs(invalid, &requested));
    try testing.expectEqual(@as(u64, 1), provider.stats.failures);
    harness.run();
}

// Shared KZG setup (about 1.1 MiB) for the optimised-build test.
var kzg_storage: kzg.blob.Settings.Storage = undefined;
var kzg_workspace: kzg.blob.Workspace = undefined;

test "blob provider: kzg verifier matches the base/base versioned hash vector" {
    // An MSM over 4096 points takes seconds unoptimised.
    if (builtin.mode == .debug) return error.SkipZigTest;
    const settings = try kzg.blob.Settings.init(&kzg_storage);
    const verifier: blob_provider.KzgVerifier = .{
        .settings = &settings,
        .workspace = &kzg_workspace,
    };
    const blob: Blob = @splat(1);
    const expected: B256 = .comptime_hex(
        "0x016c357b8b3a6b3fd82386e7bebf77143d537cdb1c856509661c412602306a04",
    );
    try testing.expect(verifier.blob_versioned_hash(&blob).?.eql(expected));
    const invalid: Blob = @splat(0xff);
    try testing.expect(verifier.blob_versioned_hash(&invalid) == null);
}

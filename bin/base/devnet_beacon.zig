//! Beacon blob source for `base devnet batches --beacon URL`: maps an L1 timestamp to its
//! slot (genesis time and slot length read once) and fetches the listed blobs with
//! `GET /eth/v1/beacon/blobs/{slot}?versioned_hashes=..`, the endpoint the consensus node
//! uses. Binary-only glue over `std.http.Client`; the inspector sees `BlobSource`.

const std = @import("std");
const base = @import("base");
const inspect = base.batcher.devnet.inspect;
const beacon_json = base.consensus.sources.beacon_json;
const blob_provider = base.consensus.sources.blob_provider;
const Blob = base.batcher.blobs.Blob;

const assert = std.debug.assert;

const blobs_per_tx_max = base.batcher.txdata.blob.blobs_per_tx_max;
/// Every blob of a slot as hex text, plus the JSON around it.
const response_bytes_max = 2 * @sizeOf(Blob) * blobs_per_tx_max * 2 + 4096;

pub const BeaconBlobs = struct {
    client: std.http.Client,
    url: []const u8,
    genesis_time: ?u64 = null,
    seconds_per_slot: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, url: []const u8) BeaconBlobs {
        assert(std.mem.startsWith(u8, url, "http://") or std.mem.startsWith(u8, url, "https://"));
        return .{ .client = .{ .allocator = allocator, .io = io }, .url = url };
    }

    pub fn deinit(beacon: *BeaconBlobs) void {
        beacon.client.deinit();
    }

    pub fn source(beacon: *BeaconBlobs) inspect.BlobSource {
        return .{ .context = beacon, .fetch_fn = fetch };
    }

    fn get(beacon: *BeaconBlobs, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
        const url = try std.fmt.allocPrint(arena, "{s}{s}", .{
            std.mem.trimEnd(u8, beacon.url, "/"),
            path,
        });
        var body: std.Io.Writer.Allocating = .init(arena);
        const result = try beacon.client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &body.writer,
        });
        if (result.status != .ok) return error.BeaconStatus;
        if (body.written().len > response_bytes_max) return error.ResponseTooLarge;
        return body.written();
    }

    fn slot_of(beacon: *BeaconBlobs, arena: std.mem.Allocator, timestamp: u64) !u64 {
        if (beacon.genesis_time == null) {
            const genesis = try beacon.get(arena, "/eth/v1/beacon/genesis");
            const spec = try beacon.get(arena, "/eth/v1/config/spec");
            beacon.seconds_per_slot = try beacon_json.decode_seconds_per_slot(spec);
            beacon.genesis_time = try beacon_json.decode_genesis_time(genesis);
        }
        assert(beacon.seconds_per_slot > 0);
        const genesis_time = beacon.genesis_time.?;
        return blob_provider.slot_of(timestamp, genesis_time, beacon.seconds_per_slot) orelse
            error.BeforeGenesis;
    }

    fn fetch(
        context: *anyopaque,
        arena: std.mem.Allocator,
        timestamp: u64,
        hashes: []const [32]u8,
    ) anyerror![]const *const Blob {
        const beacon: *BeaconBlobs = @ptrCast(@alignCast(context));
        assert(hashes.len > 0 and hashes.len <= blobs_per_tx_max);
        const path = try blobs_path(arena, try beacon.slot_of(arena, timestamp), hashes);
        const raw = try beacon.get(arena, path);
        const decoded = try arena.alloc(Blob, hashes.len);
        try beacon_json.decode_blobs(raw, decoded);
        const result = try arena.alloc(*const Blob, hashes.len);
        for (result, decoded) |*pointer, *blob| pointer.* = blob;
        return result;
    }
};

fn blobs_path(arena: std.mem.Allocator, slot: u64, hashes: []const [32]u8) ![]const u8 {
    var path: std.Io.Writer.Allocating = .init(arena);
    try path.writer.print("/eth/v1/beacon/blobs/{d}?versioned_hashes=", .{slot});
    for (hashes, 0..) |hash, index| {
        if (index > 0) try path.writer.writeAll(",");
        try path.writer.print("0x{x}", .{&hash});
    }
    assert(path.written().len > 0);
    return path.written();
}

test "devnet beacon: the blobs path lists every versioned hash" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const path = try blobs_path(arena_state.allocator(), 9, &.{ @splat(0xab), @splat(0x01) });
    const prefix = "/eth/v1/beacon/blobs/9?versioned_hashes=" ++ "0xabab";
    try std.testing.expect(std.mem.startsWith(u8, path, prefix));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, path, ","));
    try std.testing.expect(std.mem.endsWith(u8, path, "0101"));
}

fn check_blobs_path(prng: *base.testing.Prng, arena: std.mem.Allocator) !void {
    var hashes: [blobs_per_tx_max][32]u8 = undefined;
    const count = 1 + prng.below(blobs_per_tx_max);
    for (hashes[0..count]) |*hash| prng.fill(hash);
    const path = try blobs_path(arena, prng.int(u64), hashes[0..count]);
    try std.testing.expectEqual(count - 1, std.mem.count(u8, path, ","));
    try std.testing.expectEqual(count, std.mem.count(u8, path, "0x"));
}

test "devnet beacon: seeded fuzz of blobs paths" {
    var prng = base.testing.Prng.init(0xbea);
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    for (0..64) |_| try check_blobs_path(&prng, arena_state.allocator());
}

fn fuzz_blobs_path(_: void, smith: *std.testing.Smith) anyerror!void {
    var prng = base.testing.Prng.init(smith.value(u64));
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try check_blobs_path(&prng, arena_state.allocator());
}

test "devnet beacon: fuzz blobs paths" {
    try std.testing.fuzz({}, fuzz_blobs_path, .{});
}

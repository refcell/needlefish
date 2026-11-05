//! Minimal beacon node API for the `--dev-l1` chain, enough for rollup derivation to
//! fetch blobs: `/eth/v1/beacon/genesis`, `/eth/v1/config/spec`, `/eth/v1/node/version`
//! and `/eth/v1/beacon/blob_sidecars/{slot}[?indices=i,j]`.
//!
//! Slots map one-to-one onto dev L1 blocks: `slot = (timestamp - genesis_time) /
//! seconds_per_slot`, and the miner produces exactly one block per slot. Sidecars
//! (blob, commitment, proof) are captured from pooled blob transactions when a block is
//! built and kept in a bounded ring keyed by slot. Block header fields and inclusion
//! proofs are zero: nothing on a dev chain verifies them.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../common/rlp/root.zig");
const json = @import("../../utilities/json/root.zig");
const http = @import("../../utilities/http/root.zig");
const block_store = @import("block_store.zig");

pub const bytes_per_blob = 131_072;
pub const commitment_size = 48;
pub const proof_size = 48;
pub const entry_size = bytes_per_blob + commitment_size + proof_size;
pub const blobs_per_block_max = 9;
/// Depth of the beacon block "commitment inclusion proof" (always zero here).
const inclusion_proof_depth = 17;

pub const Config = struct {
    slots_max: u32 = 256,
    bytes_max: u64 = 64 << 20,
};

pub const Error = block_store.Error || error{ InvalidSidecar, TooManyBlobs };

pub const Beacon = struct {
    genesis_time: u64,
    seconds_per_slot: u64,
    store: block_store.BlockStore,
    /// Sidecars of the block being built, appended before `commit_slot`.
    pending: []u8,
    pending_count: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        genesis_time: u64,
        seconds_per_slot: u64,
        config: Config,
    ) !Beacon {
        assert(seconds_per_slot > 0);
        var store = try block_store.BlockStore.init(allocator, .{
            .blocks_max = config.slots_max,
            .bytes_max = config.bytes_max,
        });
        errdefer store.deinit(allocator);
        const pending = try allocator.alloc(u8, entry_size * blobs_per_block_max);
        return .{
            .genesis_time = genesis_time,
            .seconds_per_slot = seconds_per_slot,
            .store = store,
            .pending = pending,
        };
    }

    pub fn deinit(beacon: *Beacon, allocator: std.mem.Allocator) void {
        allocator.free(beacon.pending);
        beacon.store.deinit(allocator);
        beacon.* = undefined;
    }

    pub fn slot_of(beacon: *const Beacon, timestamp: u64) u64 {
        assert(timestamp >= beacon.genesis_time);
        return (timestamp - beacon.genesis_time) / beacon.seconds_per_slot;
    }

    /// Appends the sidecar of a pooled blob transaction
    /// (`0x03 || rlp([body, (version,) blobs, commitments, proofs])`) to the pending slot.
    pub fn capture(beacon: *Beacon, pooled: []const u8) Error!void {
        if (pooled.len == 0 or pooled[0] != 0x03) return error.InvalidSidecar;
        parse_sidecar(beacon, pooled[1..]) catch |err| switch (err) {
            error.TooManyBlobs => return error.TooManyBlobs,
            else => return error.InvalidSidecar,
        };
    }

    fn parse_sidecar(beacon: *Beacon, payload: []const u8) !void {
        var outer = rlp.Decoder.init(payload);
        var items = try outer.list();
        try outer.finish();
        if (!(try items.peek_header()).list) return error.InvalidSidecar; // No sidecar.
        _ = try items.raw();
        if (!(try items.peek_header()).list) {
            if (try items.int(u8) != 0) return error.InvalidSidecar; // Cell proofs.
        }
        var blobs = try items.list();
        var commitments = try items.list();
        var proofs = try items.list();
        try items.finish();
        while (!blobs.is_empty()) {
            if (beacon.pending_count == blobs_per_block_max) return error.TooManyBlobs;
            const blob = try blobs.bytes();
            const commitment = try commitments.bytes();
            const proof = try proofs.bytes();
            if (blob.len != bytes_per_blob) return error.InvalidSidecar;
            if (commitment.len != commitment_size or proof.len != proof_size) {
                return error.InvalidSidecar;
            }
            const entry = beacon.pending[beacon.pending_count * entry_size ..][0..entry_size];
            @memcpy(entry[0..bytes_per_blob], blob);
            @memcpy(entry[bytes_per_blob..][0..commitment_size], commitment);
            @memcpy(entry[bytes_per_blob + commitment_size ..], proof);
            beacon.pending_count += 1;
        }
        if (!commitments.is_empty() or !proofs.is_empty()) return error.InvalidSidecar;
    }

    /// Stores the pending sidecars under `slot` (an empty slot is stored too).
    pub fn commit_slot(beacon: *Beacon, slot: u64) Error!void {
        defer beacon.pending_count = 0;
        const bytes = beacon.pending[0 .. beacon.pending_count * entry_size];
        try beacon.store.put(slot_ref(slot), bytes);
    }

    pub fn discard_pending(beacon: *Beacon) void {
        beacon.pending_count = 0;
    }

    /// The stored sidecar entries of `slot`, or null when unknown.
    pub fn sidecars(beacon: *const Beacon, slot: u64) ?[]const u8 {
        return beacon.store.record(slot_ref(slot).hash);
    }

    /// Answers one beacon API request.
    pub fn handle(
        beacon: *Beacon,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        if (request.method != .GET) return response.fail(405);
        const path, const query = split_target(request.target);
        var w = json.Writer.init(response.writer());
        const result = if (std.mem.eql(u8, path, "/eth/v1/beacon/genesis"))
            beacon.write_genesis(&w)
        else if (std.mem.eql(u8, path, "/eth/v1/config/spec"))
            beacon.write_spec(&w)
        else if (std.mem.eql(u8, path, "/eth/v1/node/version"))
            write_version(&w)
        else if (std.mem.startsWith(u8, path, sidecars_prefix))
            beacon.write_sidecars(&w, path[sidecars_prefix.len..], query, response)
        else
            return response.fail(404);
        result catch |err| switch (err) {
            error.NotFound => return response.fail(404),
            error.BadRequest => return response.fail(400),
            error.WriteFailed => return response.fail(500),
        };
    }

    const sidecars_prefix = "/eth/v1/beacon/blob_sidecars/";
    const HandleError = json.Writer.WriteError || error{ NotFound, BadRequest };

    fn write_genesis(beacon: *Beacon, w: *json.Writer) HandleError!void {
        try w.begin_object();
        try w.key("data");
        try w.begin_object();
        try write_decimal(w, "genesis_time", beacon.genesis_time);
        try w.key("genesis_validators_root");
        try w.data(&@as([32]u8, @splat(0)));
        try w.key("genesis_fork_version");
        try w.data(&@as([4]u8, @splat(0)));
        try w.end_object();
        try w.end_object();
    }

    fn write_spec(beacon: *Beacon, w: *json.Writer) HandleError!void {
        try w.begin_object();
        try w.key("data");
        try w.begin_object();
        try write_decimal(w, "SECONDS_PER_SLOT", beacon.seconds_per_slot);
        try write_decimal(w, "SLOTS_PER_EPOCH", 32);
        try write_decimal(w, "FIELD_ELEMENTS_PER_BLOB", bytes_per_blob / 32);
        try write_decimal(w, "MAX_BLOBS_PER_BLOCK", blobs_per_block_max);
        try w.end_object();
        try w.end_object();
    }

    fn write_sidecars(
        beacon: *Beacon,
        w: *json.Writer,
        slot_text: []const u8,
        query: []const u8,
        response: *http.ResponseBuilder,
    ) HandleError!void {
        _ = response;
        const slot = std.fmt.parseInt(u64, slot_text, 10) catch return error.BadRequest;
        const entries = beacon.sidecars(slot) orelse return error.NotFound;
        assert(entries.len % entry_size == 0);
        const indices = parse_indices(query) catch return error.BadRequest;
        try w.begin_object();
        try w.key("data");
        try w.begin_array();
        for (0..entries.len / entry_size) |index| {
            const bit = @as(u64, 1) << @intCast(index);
            if (indices.mask != 0 and indices.mask & bit == 0) continue;
            try write_sidecar(w, slot, index, entries[index * entry_size ..][0..entry_size]);
        }
        try w.end_array();
        try w.end_object();
    }
};

fn slot_ref(slot: u64) block_store.Ref {
    var hash: [32]u8 = @splat(0);
    std.mem.writeInt(u64, hash[24..32], slot, .big);
    hash[0] = 0xb1; // Never zero, so it cannot collide with an unset entry.
    return .{ .hash = hash, .parent_hash = @splat(0), .number = slot, .timestamp = 0 };
}

fn split_target(target: []const u8) struct { []const u8, []const u8 } {
    const question = std.mem.indexOfScalar(u8, target, '?') orelse return .{ target, "" };
    return .{ target[0..question], target[question + 1 ..] };
}

const Indices = struct { mask: u64 };

/// `indices=0,2` (or empty for all).
fn parse_indices(query: []const u8) !Indices {
    var result: Indices = .{ .mask = 0 };
    var parameters = std.mem.splitScalar(u8, query, '&');
    while (parameters.next()) |parameter| {
        const prefix = "indices=";
        if (!std.mem.startsWith(u8, parameter, prefix)) continue;
        var values = std.mem.splitScalar(u8, parameter[prefix.len..], ',');
        while (values.next()) |value| {
            const index = try std.fmt.parseInt(u6, value, 10);
            result.mask |= @as(u64, 1) << index;
        }
    }
    return result;
}

fn write_decimal(w: *json.Writer, name: []const u8, value: u64) json.Writer.WriteError!void {
    var buffer: [20]u8 = undefined;
    try w.key(name);
    try w.string(std.fmt.bufPrint(&buffer, "{d}", .{value}) catch unreachable);
}

fn write_version(w: *json.Writer) json.Writer.WriteError!void {
    try w.begin_object();
    try w.key("data");
    try w.begin_object();
    try w.key("version");
    try w.string("needlefish/dev-l1");
    try w.end_object();
    try w.end_object();
}

fn write_sidecar(
    w: *json.Writer,
    slot: u64,
    index: usize,
    entry: []const u8,
) json.Writer.WriteError!void {
    assert(entry.len == entry_size);
    const zero: [32]u8 = @splat(0);
    try w.begin_object();
    try write_decimal(w, "index", index);
    try w.key("blob");
    try w.data(entry[0..bytes_per_blob]);
    try w.key("kzg_commitment");
    try w.data(entry[bytes_per_blob..][0..commitment_size]);
    try w.key("kzg_proof");
    try w.data(entry[bytes_per_blob + commitment_size ..]);
    try w.key("signed_block_header");
    try w.begin_object();
    try w.key("message");
    try w.begin_object();
    try write_decimal(w, "slot", slot);
    try write_decimal(w, "proposer_index", 0);
    for ([_][]const u8{ "parent_root", "state_root", "body_root" }) |name| {
        try w.key(name);
        try w.data(&zero);
    }
    try w.end_object();
    try w.key("signature");
    try w.data(&@as([96]u8, @splat(0)));
    try w.end_object();
    try w.key("kzg_commitment_inclusion_proof");
    try w.begin_array();
    for (0..inclusion_proof_depth) |_| try w.data(&zero);
    try w.end_array();
    try w.end_object();
}

const testing = std.testing;

/// A pooled blob tx with `count` blobs whose bytes are `fill + index`.
fn pooled_blob_tx(buffer: []u8, count: u8, fill: u8) ![]const u8 {
    var blobs: [2][bytes_per_blob]u8 = undefined;
    var encoder = rlp.Encoder.init(buffer[1..]);
    const body = [_]u8{0xc0}; // Placeholder body list (not decoded by `capture`).
    var payload_length: usize = body.len;
    payload_length += rlp.list_length(count * rlp.bytes_length(&blobs[0]));
    payload_length += 2 * rlp.list_length(count * rlp.bytes_length(&@as([48]u8, @splat(0))));
    encoder.list_header(payload_length);
    encoder.raw(&body);
    encoder.list_header(count * rlp.bytes_length(&blobs[0]));
    for (0..count) |i| {
        @memset(&blobs[i], fill + @as(u8, @intCast(i)));
        encoder.bytes(&blobs[i]);
    }
    for (0..2) |kind| {
        encoder.list_header(count * rlp.bytes_length(&@as([48]u8, @splat(0))));
        for (0..count) |i| encoder.bytes(&@as([48]u8, @splat(@intCast(kind * 16 + i))));
    }
    buffer[0] = 0x03;
    return buffer[0 .. 1 + encoder.written().len];
}

test "beacon: capture, commit and serve sidecars" {
    var beacon = try Beacon.init(testing.allocator, 1_000, 2, .{
        .slots_max = 4,
        .bytes_max = 1 << 20,
    });
    defer beacon.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 5), beacon.slot_of(1_010));
    const buffer = try testing.allocator.alloc(u8, 2 * entry_size + 1024);
    defer testing.allocator.free(buffer);
    try beacon.capture(try pooled_blob_tx(buffer, 2, 0x10));
    try beacon.commit_slot(5);
    try beacon.commit_slot(6);
    try testing.expectEqual(@as(usize, 2 * entry_size), beacon.sidecars(5).?.len);
    try testing.expectEqual(@as(usize, 0), beacon.sidecars(6).?.len);
    try testing.expect(beacon.sidecars(7) == null);
    try testing.expectEqual(@as(u8, 0x11), beacon.sidecars(5).?[entry_size]);
    try testing.expectError(error.InvalidSidecar, beacon.capture(&.{ 0x02, 0xc0 }));

    const out = try testing.allocator.alloc(u8, 4 * entry_size);
    defer testing.allocator.free(out);
    var response = http.ResponseBuilder.init(out);
    const request: http.Request = .{
        .method = .GET,
        .method_text = "GET",
        .target = "/eth/v1/beacon/blob_sidecars/5?indices=1",
        .version = .http_1_1,
        .headers = .{},
        .body = "",
        .keep_alive = true,
    };
    beacon.handle(&request, &response);
    try testing.expectEqual(@as(u16, 200), response.status);
    const text = response.body.buffered();
    try json.validate(text);
    try testing.expect(std.mem.indexOf(u8, text, "\"index\":\"1\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"index\":\"0\"") == null);
}

test "beacon: genesis, spec and unknown paths" {
    var beacon = try Beacon.init(testing.allocator, 1_000, 2, .{
        .slots_max = 4,
        .bytes_max = 1 << 16,
    });
    defer beacon.deinit(testing.allocator);
    var out: [4096]u8 = undefined;
    const targets = [_]struct { []const u8, u16, []const u8 }{
        .{ "/eth/v1/beacon/genesis", 200, "\"genesis_time\":\"1000\"" },
        .{ "/eth/v1/config/spec", 200, "\"SECONDS_PER_SLOT\":\"2\"" },
        .{ "/eth/v1/beacon/blob_sidecars/9", 404, "" },
        .{ "/eth/v1/beacon/blob_sidecars/x", 400, "" },
        .{ "/nope", 404, "" },
    };
    for (targets) |case| {
        var response = http.ResponseBuilder.init(&out);
        const request: http.Request = .{
            .method = .GET,
            .method_text = "GET",
            .target = case[0],
            .version = .http_1_1,
            .headers = .{},
            .body = "",
            .keep_alive = true,
        };
        beacon.handle(&request, &response);
        try testing.expectEqual(case[1], response.status);
        if (case[2].len > 0) {
            try testing.expect(std.mem.indexOf(u8, response.body.buffered(), case[2]) != null);
        }
    }
}

fn fuzz_capture(_: void, smith: *testing.Smith) anyerror!void {
    var beacon = try Beacon.init(testing.allocator, 0, 1, .{
        .slots_max = 2,
        .bytes_max = 1 << 16,
    });
    defer beacon.deinit(testing.allocator);
    var bytes: [256]u8 = undefined;
    const len = smith.slice(&bytes);
    beacon.capture(bytes[0..len]) catch return;
}

test "beacon: fuzz capture never crashes" {
    try testing.fuzz({}, fuzz_capture, .{});
}

test "beacon: seeded fuzz capture of random bytes" {
    var beacon = try Beacon.init(testing.allocator, 0, 1, .{
        .slots_max = 2,
        .bytes_max = 1 << 16,
    });
    defer beacon.deinit(testing.allocator);
    var prng = @import("../../testing/prng.zig").Prng.init(0xbea);
    var bytes: [256]u8 = undefined;
    for (0..2000) |_| {
        const len = prng.below(bytes.len);
        prng.fill(bytes[0..len]);
        if (len > 0 and prng.chance(1, 2)) bytes[0] = 0x03;
        beacon.capture(bytes[0..len]) catch {};
        beacon.discard_pending();
    }
}

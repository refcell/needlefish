//! Fuzz targets for every basectl decoder: arbitrary server JSON must decode or return
//! `error.MalformedResponse`, never crash, and a decoded value must render. Runs as a
//! `std.testing.fuzz` target and as a seeded deterministic fuzz in `zig build test`.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const testing = std.testing;
const types = @import("types.zig");
const sync_status = @import("sync_status.zig");
const block = @import("block.zig");
const txpool = @import("txpool.zig");
const batcher = @import("batcher.zig");
const p2p = @import("p2p.zig");
const conductor = @import("conductor.zig");
const proofs = @import("proofs.zig");
const upgrade_readiness = @import("upgrade_readiness.zig");
const doctor = @import("doctor.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Writer = types.Writer;

/// Decodes `text` with every decoder and renders what decodes. Returns how many decoded.
fn exercise(text: []const u8) u32 {
    var memory: [256 * 1024]u8 = undefined;
    var arena: std.heap.FixedBufferAllocator = .init(&memory);
    const value = json.parseFromSliceLeaky(json.Value, arena.allocator(), text, .{
        .duplicate_field_behavior = .use_last,
    }) catch return 0;
    var out: [8192]u8 = undefined;
    var writer: Writer = .fixed(&out);
    var decoded: u32 = 0;
    if (sync_status.decode_sync_status(value)) |status| {
        decoded += 1;
        const report: sync_status.Report = .{
            .network = "x",
            .el = .{ .failed = .unavailable },
            .cl = status,
        };
        sync_status.render(&report, &writer) catch {};
    } else |_| {}
    if (block.decode_block(value)) |decoded_block| {
        decoded += 1;
        const report: block.Report = .{
            .network = "x",
            .reference = .{ .number = 1 },
            .block = decoded_block,
        };
        block.render(&report, &writer) catch {};
    } else |_| {}
    if (upgrade_readiness.decode_readiness(value)) |readiness| {
        decoded += 1;
        const report: upgrade_readiness.Report = .{ .network = "x", .readiness = readiness };
        upgrade_readiness.render(&report, &writer) catch {};
    } else |_| {}
    decoded += count_ok(value);
    assert(writer.buffered().len <= out.len);
    return decoded;
}

/// The decoders without a dedicated renderer here.
fn count_ok(value: json.Value) u32 {
    var decoded: u32 = 0;
    decoded += @intFromBool(if (sync_status.decode_el_sync(value)) |_| true else |_| false);
    decoded += @intFromBool(if (txpool.decode_status(value)) |_| true else |_| false);
    decoded += @intFromBool(if (txpool.decode_content(value)) |_| true else |_| false);
    decoded += @intFromBool(if (txpool.decode_content_from(value)) |_| true else |_| false);
    decoded += @intFromBool(if (batcher.decode_status(value)) |_| true else |_| false);
    decoded += @intFromBool(if (p2p.decode_cl_identity(value)) |_| true else |_| false);
    decoded += @intFromBool(if (p2p.decode_peer_stats(value)) |_| true else |_| false);
    decoded += @intFromBool(if (p2p.decode_el_identity(value)) |_| true else |_| false);
    decoded += @intFromBool(if (conductor.decode_membership(value)) |_| true else |_| false);
    decoded += @intFromBool(if (conductor.decode_server(value)) |_| true else |_| false);
    decoded += @intFromBool(if (proofs.decode_count(value)) |_| true else |_| false);
    decoded += @intFromBool(if (proofs.decode_status(value)) |_| true else |_| false);
    decoded += @intFromBool(if (proofs.decode_entry(value)) |_| true else |_| false);
    decoded += @intFromBool(if (proofs.decode_root_claim(value)) |_| true else |_| false);
    decoded += @intFromBool(if (doctor.decode_chain_ids(value)) |_| true else |_| false);
    assert(decoded <= 15);
    return decoded;
}

fn fuzz_decoders(_: void, smith: *testing.Smith) anyerror!void {
    var text: [2048]u8 = undefined;
    const length = smith.slice(&text);
    _ = exercise(text[0..length]);
}

test "basectl fuzz: decoders on arbitrary json" {
    try testing.fuzz({}, fuzz_decoders, .{});
}

const fragments = [_][]const u8{
    "{",           "}",             "[",             "]",                ",",
    ":",           "null",          "true",          "false",            "0",
    "-1",          "1e400",         "\"0x\"",        "\"0x2a\"",         "\"0xzz\"",
    "\"number\"",  "\"hash\"",      "\"timestamp\"", "\"pending\"",      "\"queued\"",
    "\"stopped\"", "\"in_flight\"", "\"upgrades\"",  "\"ready\"",        "\"servers\"",
    "\"peerID\"",  "\"connected\"", "\"version\"",   "\"transactions\"", "18446744073709551616",
};

const seeds = [_][]const u8{
    block.sample_block,
    upgrade_readiness.sample_readiness,
    p2p.sample_self,
    p2p.sample_peer_stats,
    conductor.sample_membership,
    "{\"pending\":{\"0xa\":{\"0\":{}}},\"queued\":{}}",
    "{\"stopped\":true,\"in_flight\":1,\"da_backlog_bytes\":2}",
};

/// Either a token soup or a mutated valid response.
fn generate(prng: *Prng, buffer: []u8) []const u8 {
    assert(buffer.len >= 2048);
    if (prng.chance(1, 2)) {
        var writer: Writer = .fixed(buffer);
        const count = prng.range(1, 64);
        for (0..count) |_| {
            writer.writeAll(fragments[prng.below(fragments.len)]) catch break;
        }
        return writer.buffered();
    }
    const seed = seeds[prng.below(seeds.len)];
    assert(seed.len <= buffer.len);
    @memcpy(buffer[0..seed.len], seed);
    const flips = prng.range(0, 4);
    for (0..flips) |_| buffer[prng.below(seed.len)] = fragments[prng.below(fragments.len)][0];
    const length = if (prng.chance(1, 4)) prng.range(1, seed.len) else seed.len;
    return buffer[0..length];
}

test "basectl fuzz: seeded decoder fuzz" {
    var prng = Prng.init(0xba5ec71);
    var buffer: [2048]u8 = undefined;
    var decoded_total: u64 = 0;
    for (0..3000) |_| decoded_total += exercise(generate(&prng, &buffer));
    // The unmutated seeds decode, so the generator reaches the decoders' success paths.
    for (seeds) |seed| try testing.expect(exercise(seed) > 0);
    try testing.expect(decoded_total > 0);
}

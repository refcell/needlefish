//! Memory of the node's default witness generator (`Limits.witness_config`): bytes reserved
//! per buffer and bytes made resident by `Generator.init`, measured on a bump allocator over
//! a sentinel-filled region (a page counts as resident once any byte in it changed). This is
//! a resident-set proxy that works on every OS and build mode; Debug fills new allocations
//! with 0xAA exactly like ReleaseSafe, so it sees the debug fill `lazy_alloc` skips.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const lazy = @import("../../utilities/lazy_alloc/root.zig");
const db_module = @import("../db/root.zig");
const trie = @import("../trie/root.zig");
const service = @import("service.zig");
const http = @import("../../utilities/http/root.zig");
const io = @import("../../utilities/io/root.zig");

const witness = db_module.witness;
const page_bytes = 4096;
const sentinel: u8 = 0x5c;

/// Bump allocator over a sentinel-filled region.
const Meter = struct {
    region: []u8,
    fixed: std.heap.FixedBufferAllocator,

    fn init(region_bytes: usize) !Meter {
        assert(region_bytes % page_bytes == 0);
        const region = try lazy.alloc(testing.allocator, u8, region_bytes);
        @memset(region, sentinel);
        return .{ .region = region, .fixed = .init(region) };
    }

    fn deinit(meter: *Meter) void {
        lazy.free(testing.allocator, meter.region);
        meter.* = undefined;
    }

    /// Forgets every allocation and restores the sentinel over the used part.
    fn reset(meter: *Meter) void {
        @memset(meter.region[0..meter.fixed.end_index], sentinel);
        meter.fixed.reset();
        assert(meter.fixed.end_index == 0);
    }

    fn reserved_bytes(meter: *const Meter) u64 {
        return meter.fixed.end_index;
    }

    fn resident_bytes(meter: *const Meter) u64 {
        const used = meter.region[0..meter.fixed.end_index];
        var pages: u64 = 0;
        var offset: usize = 0;
        while (offset < used.len) : (offset += page_bytes) {
            const page = used[offset..@min(used.len, offset + page_bytes)];
            for (page) |byte| {
                if (byte != sentinel) {
                    pages += 1;
                    break;
                }
            }
        }
        assert(pages * page_bytes <= used.len + page_bytes);
        return pages * page_bytes;
    }
};

const Usage = struct { reserved_bytes: u64, resident_bytes: u64 };

fn usage(meter: *Meter) Usage {
    const result: Usage = .{
        .reserved_bytes = meter.reserved_bytes(),
        .resident_bytes = meter.resident_bytes(),
    };
    meter.reset();
    return result;
}

const Part = struct { name: []const u8, usage: Usage };

/// Each buffer of the generator, initialised on its own (Builder, Recorder, Witness,
/// Overlay, two Changesets, slices), plus the whole `Generator.init`.
fn measure(meter: *Meter, config: *const db_module.witness_block.Config) ![8]Part {
    const allocator = meter.fixed.allocator();
    const state = try testing.allocator.create(db_module.State);
    defer testing.allocator.destroy(state);
    var parts: [8]Part = undefined;
    _ = try witness.SparseState.init(allocator, config.builder.sparse);
    parts[0] = .{ .name = "builder.sparse", .usage = usage(meter) };
    _ = try witness.KeySet.init(allocator, config.builder.keys);
    parts[1] = .{ .name = "builder.keys (x2: builder, recorder)", .usage = usage(meter) };
    _ = try witness.Witness.init(allocator, config.witness);
    parts[2] = .{ .name = "witness", .usage = usage(meter) };
    _ = try db_module.Overlay.init(allocator, state, config.overlay);
    parts[3] = .{ .name = "overlay", .usage = usage(meter) };
    _ = try db_module.Changeset.init(allocator, config.changeset);
    parts[4] = .{ .name = "changeset (x2: decode, built)", .usage = usage(meter) };
    _ = try allocator.alloc([]const u8, config.depth_max);
    parts[5] = .{ .name = "depth_max changeset slices", .usage = usage(meter) };
    _ = try lazy.create(allocator, trie.StateTrie.AccountProof);
    _ = try lazy.create(allocator, trie.StateTrie.StorageProof);
    parts[6] = .{ .name = "proof buffers", .usage = usage(meter) };
    _ = try db_module.witness_block.Generator.init(allocator, state, config.*);
    parts[7] = .{ .name = "Generator.init total", .usage = usage(meter) };
    return parts;
}

/// Set to print the table (`zig build test -Dtest-filter="witness memory"`).
const report_enabled = false;

fn report(parts: []const Part) void {
    if (!report_enabled) return;
    for (parts) |part| {
        std.debug.print("witness memory {s}: reserved {d} KiB, resident {d} KiB\n", .{
            part.name,
            part.usage.reserved_bytes >> 10,
            part.usage.resident_bytes >> 10,
        });
    }
}

test "witness memory: default generator reserves its bound and stays non-resident" {
    const limits: service.Limits = .{};
    const config = limits.witness_config().?;
    var meter = try Meter.init(128 << 20);
    defer meter.deinit();
    const parts = try measure(&meter, &config);
    report(&parts);
    const total = parts[7].usage;
    try testing.expect(total.reserved_bytes > 0);
    try testing.expect(total.resident_bytes <= total.reserved_bytes + page_bytes);
    // Buffers without a hash-map index are untouched in every build mode.
    // Witness (its small lists take the eager path) and Changeset.
    try testing.expect(parts[2].usage.resident_bytes <= 4 * page_bytes);
    try testing.expect(parts[4].usage.resident_bytes <= 4 * page_bytes);
    try testing.expect(parts[6].usage.resident_bytes == 0); // Proof buffers.
    // Without the debug fill only the hash-map metadata is written.
    if (!std.debug.runtime_safety) try testing.expect(total.resident_bytes <= 1 << 20);
}

test "witness memory: the default response bound fits the HTTP large send buffer" {
    const limits: service.Limits = .{};
    const config = limits.witness_config().?;
    const head_reserve_bytes = 1024;
    try testing.expect(limits.http.large_send_buffers_max > 0);
    const send_bytes = limits.http.large_send_buffer_size;
    try testing.expect(limits.witness_response_bytes_max + head_reserve_bytes < send_bytes);
    // A storage-heavy witness (1.28 MB binary, ~2.6 MB of hex JSON) fits; 1 MiB did not.
    try testing.expect(limits.witness_response_bytes_max > 2_600_000);
    try testing.expect(limits.http.send_buffer_size < 2_600_000);
    try testing.expectEqual(limits.witness_response_bytes_max, config.response_bytes_max);
    try testing.expect(config.witness.state_bytes_max <= config.response_bytes_max / 2);
    try testing.expect(config.witness.keys_max ==
        config.builder.keys.accounts_max + config.builder.keys.slots_max);
}

fn handle_nothing(
    context: *u8,
    request: *const http.Request,
    response: *http.ResponseBuilder,
) void {
    _ = context;
    _ = request;
    _ = response;
}

test "witness memory: the node's HTTP large send buffers are reserved, not resident" {
    const limits: service.Limits = .{};
    const options = limits.http;
    var meter = try Meter.init(128 << 20);
    defer meter.deinit();
    const Server = http.Server(io.SimIo, *u8, handle_nothing);
    var server: Server = undefined;
    var context: u8 = 0;
    // `init` only stores the IO pointer; nothing runs on it.
    var sim_io: io.SimIo = undefined;
    try server.init(meter.fixed.allocator(), &sim_io, &context, options);
    const large_bytes = @as(u64, options.large_send_buffer_size) * options.large_send_buffers_max;
    try testing.expectEqual(large_bytes, server.large_memory.len);
    const idle = usage(&meter);
    try testing.expect(idle.reserved_bytes >= large_bytes);
    // Only the connection table (debug-filled in safe builds) is written at init.
    try testing.expect(idle.resident_bytes <= 16 * page_bytes);
}

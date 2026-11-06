//! `base audit`: transaction-event audit archiver (base/base `audit-archiver`). Accepts
//! Vector `transaction-event/v1` NDJSON batches over HTTP, stores them idempotently in a
//! bounded in-memory store, and serves the `base_getTransactionEvents*` JSON-RPC queries,
//! `/healthz`, `/readyz`, and `/metrics` on the same port. With `--data-dir` every accepted
//! batch is appended to `<data-dir>/events.seg` and fsynced before the response; the file is
//! replayed at startup and compacted when it grows past `--segment-bytes-max`.
//! See `src/infra/audit`.
//!
//! The endpoints are unauthenticated: bind them to a private network (as base/base says).

const std = @import("std");
const base = @import("base");

const Io = std.Io;
const io = base.utilities.io;
const cli = base.utilities.cli;
const audit = base.infra.audit;
const Archiver = audit.Archiver(io.IO);

const env_prefix = "BASE_AUDIT_";
const segment_name = "events.seg";
const compact_name = "events.seg.tmp";
const day_ns: u64 = 86_400 * std.time.ns_per_s;
/// base/base `MAX_TRANSACTION_EVENT_RETENTION_DAYS`.
const retention_days_max = 90;

pub const Spec = struct {
    listen_addr: []const u8 = "0.0.0.0:9100",
    ingest_path: []const u8 = audit.ingest.default_path,
    max_batch_size: u32 = 1000,
    max_event_bytes: u32 = 256 * 1024,
    max_data_bytes: u32 = 128 * 1024,
    max_request_bytes: u32 = 8 * 1024 * 1024,
    hot_retention_days: u32 = 3,
    warm_retention_days: u32 = 7,
    cold_retention_days: u32 = 30,
    events_max: u32 = 1_000_000,
    store_bytes_max: u32 = 1024 * 1024 * 1024,
    data_dir: []const u8 = "",
    segment_bytes_max: u32 = 2047 * 1024 * 1024,

    pub const help = .{
        .listen_addr = "Address to serve ingest, JSON-RPC, health, and metrics on, IPv4:PORT",
        .ingest_path = "HTTP path of the Vector NDJSON batch endpoint",
        .max_batch_size = "Most events per ingest request",
        .max_event_bytes = "Largest serialized event (one NDJSON line) in bytes",
        .max_data_bytes = "Largest event `data` object in bytes",
        .max_request_bytes = "Largest ingest request body in bytes",
        .hot_retention_days = "Days to keep high-volume proxy and builder-decision events",
        .warm_retention_days = "Days to keep ingress, simulation, and txpool events",
        .cold_retention_days = "Days to keep failures, drops, and inclusion events",
        .events_max = "Most stored events; the oldest are evicted beyond this",
        .store_bytes_max = "Byte budget for stored event fields; the oldest are evicted",
        .data_dir = "Directory for the durable segment file (empty: memory only)",
        .segment_bytes_max = "Compact the segment file once it grows past this many bytes",
    };
};

pub const Settings = struct {
    listen: io.Address,
    options: audit.archiver.Options,
};

/// Validates parsed flags into runtime settings (base/base's retention rules).
pub fn settings_of(spec: Spec) !Settings {
    const retention_valid = spec.hot_retention_days > 0 and
        spec.hot_retention_days <= spec.warm_retention_days and
        spec.warm_retention_days <= spec.cold_retention_days and
        spec.cold_retention_days <= retention_days_max;
    if (!retention_valid) return error.InvalidRetention;
    const sizes_valid = spec.max_batch_size > 0 and spec.max_batch_size <= 4000 and
        spec.max_data_bytes > 0 and spec.max_data_bytes <= spec.max_event_bytes and
        spec.max_event_bytes <= spec.max_request_bytes and
        spec.max_request_bytes <= 64 * 1024 * 1024 and spec.events_max > 0 and
        spec.events_max <= 64 * 1024 * 1024;
    if (!sizes_valid) return error.InvalidValue;
    const record_max = spec.max_event_bytes + audit.store.record_overhead_bytes;
    if (spec.store_bytes_max < record_max) return error.StoreTooSmall;
    if (spec.ingest_path.len == 0 or spec.ingest_path[0] != '/') return error.InvalidPath;
    const head_size_max = 16 * 1024;
    return .{ .listen = try parse_listen(spec.listen_addr), .options = .{
        .store = .{
            .events_max = spec.events_max,
            .arena_bytes = spec.store_bytes_max,
            .retention_ns = .init(.{
                .hot = @as(u64, spec.hot_retention_days) * day_ns,
                .warm = @as(u64, spec.warm_retention_days) * day_ns,
                .cold = @as(u64, spec.cold_retention_days) * day_ns,
            }),
        },
        .ingest = .{
            .batch_max = spec.max_batch_size,
            .request_bytes_max = spec.max_request_bytes,
            .event = .{
                .event_bytes_max = spec.max_event_bytes,
                .data_bytes_max = spec.max_data_bytes,
            },
        },
        .ingest_path = spec.ingest_path,
        .server = .{
            .connections_max = 64,
            .recv_buffer_size = head_size_max + spec.max_request_bytes,
            .send_buffer_size = 64 * 1024,
            .limits = .{ .head_size_max = head_size_max, .body_size_max = spec.max_request_bytes },
            .large_send_buffers_max = 4,
            .large_send_buffer_size = 16 * 1024 * 1024,
        },
        .version = base.build_options.version,
    } };
}

fn parse_listen(text: []const u8) !io.Address {
    const address = io.Address.parse(text) catch return error.InvalidAddress;
    if (address.family != .ip4) return error.InvalidAddress;
    return address;
}

/// The segment file: synchronous `std.Io` file calls. The ingest handler answers only
/// after `persist` returns, so the write and fsync must complete before it; this keeps
/// them blocking instead of routing them through the completion-based `utilities.io`.
const Journal = struct {
    io: Io,
    dir: Io.Dir,
    file: Io.File,
    size: u64,
    /// The configured budget, and the size that triggers the next compaction (at least
    /// twice the live data, so live data near the budget does not compact on every tick).
    segment_bytes_max: u64,
    compact_at: u64,
    archiver: *Archiver,
    os_io: *io.IO,
    chunk: []u8,
    failed: bool = false,

    fn persist(context: *anyopaque, bytes: []const u8) bool {
        const journal: *Journal = @ptrCast(@alignCast(context));
        std.debug.assert(bytes.len > 0);
        if (journal.failed) return false;
        journal.file.writePositionalAll(journal.io, bytes, journal.size) catch
            return journal.fail(error.WriteFailed);
        journal.file.sync(journal.io) catch return journal.fail(error.SyncFailed);
        journal.size += bytes.len;
        return true;
    }

    /// A failed write may have left a partial record: truncate back to the last good size.
    fn fail(journal: *Journal, err: anyerror) bool {
        std.debug.print("audit: segment write failed: {t}\n", .{err});
        journal.file.setLength(journal.io, journal.size) catch {
            journal.failed = true; // Unknown tail: refuse further writes.
        };
        return false;
    }

    /// Compacts once the file outgrew its budget. Called from the main loop, never from
    /// `persist`: the batch being persisted is inserted into the store only afterwards.
    fn maintain(journal: *Journal) void {
        if (journal.failed or journal.size <= journal.compact_at) return;
        journal.compact() catch |err| {
            std.debug.print("audit: compaction failed: {t}\n", .{err});
            journal.compact_at +|= journal.compact_at / 2; // Retry later.
        };
    }

    /// Rewrites the segment with only the live store contents, then renames it into place.
    fn compact(journal: *Journal) !void {
        const now_ns = journal.os_io.now_realtime_ns();
        const store = &journal.archiver.store;
        const file = try journal.dir.createFile(journal.io, compact_name, .{ .read = true });
        errdefer file.close(journal.io);
        var size: u64 = 0;
        var position: u32 = 0;
        var chunks: u32 = 0;
        while (position < store.count and chunks <= store.count) : (chunks += 1) {
            const bytes = audit.segment.encode_live(store, &position, journal.chunk, now_ns);
            try file.writePositionalAll(journal.io, bytes, size);
            size += bytes.len;
        }
        try file.sync(journal.io);
        try journal.dir.rename(compact_name, journal.dir, segment_name, journal.io);
        journal.file.close(journal.io);
        journal.file = file;
        journal.size = size;
        journal.compact_at = @max(journal.segment_bytes_max, 2 * size);
        std.debug.print("audit: compacted segment to {d} bytes\n", .{size});
    }
};

/// Opens (or creates) the segment and replays it into the store; truncates a torn or
/// corrupt tail.
fn open_journal(journal: *Journal, data_dir: []const u8, payload_max: u32) !void {
    try Io.Dir.cwd().createDirPath(journal.io, data_dir);
    journal.dir = try Io.Dir.cwd().openDir(journal.io, data_dir, .{});
    journal.file = try journal.dir.createFile(journal.io, segment_name, .{
        .read = true,
        .truncate = false,
    });
    const length = try journal.file.length(journal.io);
    const now_ns = journal.os_io.now_realtime_ns();
    const window = journal.chunk;
    var offset: u64 = 0;
    var filled: usize = 0;
    var inserted: u64 = 0;
    var reads: u64 = 0;
    while (reads <= length) : (reads += 1) {
        const file = journal.file;
        const read = try file.readPositionalAll(journal.io, window[filled..], offset + filled);
        filled += read;
        const store = &journal.archiver.store;
        const result = audit.segment.replay(store, window[0..filled], payload_max, now_ns);
        inserted += result.inserted;
        offset += result.consumed;
        std.mem.copyForwards(u8, window, window[result.consumed..filled]);
        filled -= result.consumed;
        if (result.stop == .corrupt or read == 0) break;
    }
    if (offset < length) {
        std.debug.print("audit: truncating segment at {d} of {d} bytes\n", .{ offset, length });
        try journal.file.setLength(journal.io, offset);
    }
    journal.size = offset;
    std.debug.print("audit: replayed {d} events from {s}/{s}\n", .{
        inserted,
        data_dir,
        segment_name,
    });
}

fn print_help() void {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    std.debug.print("usage: base audit [--listen-addr IP:PORT] [--data-dir DIR]\n{s}", .{
        writer.buffered(),
    });
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args, env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("audit: {t}: {s}\n", .{ err, diagnostic.subject });
        print_help();
        return 2;
    };
    const settings = settings_of(spec) catch |err| {
        std.debug.print("audit: invalid flags: {t}\n", .{err});
        return 2;
    };
    var os_io = if (@import("builtin").os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    defer os_io.deinit();
    const archiver = try init.gpa.create(Archiver);
    defer init.gpa.destroy(archiver);
    try archiver.init(init.gpa, &os_io, settings.options);
    defer archiver.deinit();
    var journal: Journal = undefined;
    if (spec.data_dir.len > 0) {
        const limits = settings.options.ingest.event;
        const chunk_size = @max(4 * 1024 * 1024, 2 * audit.segment.record_size_max(limits));
        journal = .{
            .io = init.io,
            .dir = undefined,
            .file = undefined,
            .size = 0,
            .segment_bytes_max = spec.segment_bytes_max,
            .compact_at = spec.segment_bytes_max,
            .archiver = archiver,
            .os_io = &os_io,
            .chunk = try init.gpa.alloc(u8, chunk_size),
        };
        const payload_max = audit.segment.record_size_max(limits);
        try open_journal(&journal, spec.data_dir, payload_max);
        journal.maintain();
        archiver.journal = .{ .context = &journal, .persist = Journal.persist };
    }
    defer if (spec.data_dir.len > 0) {
        journal.file.close(init.io);
        journal.dir.close(init.io);
        init.gpa.free(journal.chunk);
    };
    const bound = try archiver.listen(settings.listen);
    std.debug.print("audit: serving on port {d}, ingest at {s}, {d} events stored\n", .{
        bound.port,
        spec.ingest_path,
        archiver.store.count,
    });
    while (true) {
        try os_io.run_for_ns(100 * std.time.ns_per_ms);
        archiver.tick();
        if (archiver.journal != null) journal.maintain();
    }
}

const testing = std.testing;

test "audit: flags to settings" {
    const settings = try settings_of(.{ .listen_addr = "127.0.0.1:9100", .events_max = 10 });
    try testing.expectEqual(@as(u16, 9100), settings.listen.port);
    try testing.expectEqual(@as(u32, 1000), settings.options.ingest.batch_max);
    try testing.expectEqual(3 * day_ns, settings.options.store.retention_ns.get(.hot));
    try testing.expectEqual(30 * day_ns, settings.options.store.retention_ns.get(.cold));
    try testing.expectError(error.InvalidRetention, settings_of(.{ .hot_retention_days = 0 }));
    try testing.expectError(error.InvalidRetention, settings_of(.{ .warm_retention_days = 2 }));
    try testing.expectError(error.InvalidRetention, settings_of(.{ .cold_retention_days = 91 }));
    try testing.expectError(error.InvalidValue, settings_of(.{ .max_data_bytes = 300 * 1024 }));
    try testing.expectError(error.StoreTooSmall, settings_of(.{ .store_bytes_max = 1024 }));
    try testing.expectError(error.InvalidPath, settings_of(.{ .ingest_path = "batch" }));
    try testing.expectError(error.InvalidAddress, settings_of(.{ .listen_addr = "localhost" }));
}

test "audit: cli spec parses with env fallback" {
    var diagnostic: cli.Diagnostic = .{};
    const args = [_][]const u8{ "--data-dir", "/tmp/audit", "--hot-retention-days", "1" };
    const Lookup = struct {
        fn get(context: ?*const anyopaque, name: []const u8) ?[]const u8 {
            _ = context;
            if (std.mem.eql(u8, name, "BASE_AUDIT_EVENTS_MAX")) return "42";
            return null;
        }
    };
    const env: cli.Env = .{ .context = null, .get = Lookup.get };
    const spec = try cli.parse(Spec, env_prefix, &args, env, &diagnostic);
    try testing.expectEqualStrings("/tmp/audit", spec.data_dir);
    try testing.expectEqual(@as(u32, 1), spec.hot_retention_days);
    try testing.expectEqual(@as(u32, 42), spec.events_max);
    try testing.expectEqual(@as(u32, 1000), spec.max_batch_size);
}

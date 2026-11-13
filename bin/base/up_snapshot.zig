//! The snapshot stage of `base up`: the latest public Base snapshot's `state` component
//! (a zstd tar of reth's MDBX database), downloaded and extracted in one resumable pass.
//!
//! - `https://chain.base.org/api/snapshots` names each chain's latest manifest; the manifest
//!   names the archive, its size, and every member's size and blake3. Both are saved under
//!   `snapshot/`, so a restarted `base up` resumes the same snapshot, and switches to the
//!   latest only when the saved one is no longer published (its archive answers 404/403/410).
//! - The archive is fetched as fixed-size chunks (`archive/NNNNNN`) by parallel workers that
//!   claim chunks in order. A chunk is written as `NNNNNN.part`, resumed from its length with
//!   an HTTP range request, and renamed once complete, so a complete name is a complete chunk.
//!   A connection that delivers nothing for `stall_ms` is dropped and the chunk resumed.
//! - Extraction trails the download: a reader over the chunks in order (waiting for the next
//!   one) feeds zstd, which writes into `up_tar.Sink`, which writes the members into
//!   `extracted/` and checks each against the manifest's blake3. Chunks are kept until the
//!   extraction is verified, so an interrupted extraction restarts from chunk 0 without a
//!   new download; `extracted.ok` marks a verified extraction and the chunks are deleted.
//! - A zstd decode error deletes the chunks around the failing offset (they are fetched
//!   again); a blake3 mismatch with no decode error cannot be localized and deletes them all.

const std = @import("std");
const up_tar = @import("up_tar.zig");
const up_check = @import("up_check.zig");

const Io = std.Io;
const assert = std.debug.assert;

pub const listing_url = "https://chain.base.org/api/snapshots";
pub const component = "state";
pub const chunk_bytes: u64 = 256 << 20;
/// Archives up to 256 TiB (Base mainnet's is 0.76 TB).
pub const chunks_max: u32 = 1 << 20;
const stall_ms: i64 = 120_000;
const attempts_max: u32 = 1000;
const backoff_ms_max: u64 = 60_000;
const read_buffer_bytes = 1 << 20;
const listing_bytes_max = 1 << 20;
const manifest_bytes_max = 16 << 20;
/// The zstd window the archive may use: Base's use 2 MiB (every level up to 19 stays within
/// 8 MiB). The decoder keeps this much history in the sink's buffer, moving it each time the
/// buffer fills, so the buffer is several windows long.
pub const window_bytes = 16 << 20;
pub const sink_buffer_bytes = 8 * window_bytes;
pub const input_buffer_bytes = read_buffer_bytes;

pub const Snapshot = struct {
    manifest_url: []const u8,
    block: u64,
    /// The archive's path under the manifest's base URL: identifies the snapshot.
    file: []const u8,
    archive_url: []const u8,
    archive_bytes: u64,
    members: [up_tar.members_max]up_tar.Member,
    members_count: u32,

    pub fn member_slice(snapshot: *const Snapshot) []const up_tar.Member {
        return snapshot.members[0..snapshot.members_count];
    }

    pub fn mdbx_bytes(snapshot: *const Snapshot) u64 {
        for (snapshot.member_slice()) |member| {
            if (std.mem.endsWith(u8, member.path, "mdbx.dat")) return member.size;
        }
        unreachable; // `parse_manifest` requires it.
    }

    pub fn chunk_count(snapshot: *const Snapshot) u32 {
        const count = std.math.divCeil(u64, snapshot.archive_bytes, chunk_bytes) catch unreachable;
        assert(count > 0 and count <= chunks_max);
        return @intCast(count);
    }
};

// ---- Listing and manifest ------------------------------------------------------------

/// The manifest URL of the chain's latest snapshot in the listing.
pub fn parse_listing(arena: std.mem.Allocator, text: []const u8, chain_id: u64) ![]const u8 {
    assert(chain_id != 0);
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    if (parsed != .array) return error.BadListing;
    var id_buffer: [24]u8 = undefined;
    const id = std.fmt.bufPrint(&id_buffer, "{d}", .{chain_id}) catch unreachable;
    for (parsed.array.items) |entry| {
        if (entry != .object) continue;
        const entry_id = entry.object.get("chainId") orelse continue;
        if (entry_id != .string or !std.mem.eql(u8, entry_id.string, id)) continue;
        const url = entry.object.get("manifestUrl") orelse return error.BadListing;
        if (url != .string or !is_http(url.string)) {
            return error.BadListing;
        }
        return url.string;
    }
    return error.ChainNotListed;
}

/// The `state` component of a manifest: archive, size, and members with their blake3.
pub fn parse_manifest(arena: std.mem.Allocator, text: []const u8, url: []const u8) !Snapshot {
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
    if (root != .object) return error.BadManifest;
    const base_url = try string_field(root, "base_url");
    const state = try object_field(try object_field(root, "components"), component);
    const file = try string_field(state, "file");
    if (std.mem.indexOf(u8, file, "..") != null) return error.BadManifest;
    var snapshot: Snapshot = .{
        .manifest_url = url,
        .block = try integer_field(root, "block"),
        .file = file,
        .archive_url = try std.fmt.allocPrint(arena, "{s}/{s}", .{
            std.mem.trimEnd(u8, base_url, "/"), file,
        }),
        .archive_bytes = try integer_field(state, "size"),
        .members = undefined,
        .members_count = 0,
    };
    if (!is_http(snapshot.archive_url)) return error.BadManifest;
    if (snapshot.archive_bytes == 0 or snapshot.archive_bytes > chunks_max * chunk_bytes) {
        return error.BadManifest;
    }
    try parse_members(&snapshot, state);
    return snapshot;
}

fn parse_members(snapshot: *Snapshot, state: std.json.Value) !void {
    const outputs = state.object.get("output_files") orelse return error.BadManifest;
    if (outputs != .array) return error.BadManifest;
    if (outputs.array.items.len == 0 or outputs.array.items.len > up_tar.members_max) {
        return error.BadManifest;
    }
    var has_mdbx = false;
    for (outputs.array.items) |output| {
        const path = try string_field(output, "path");
        // Members land under `extracted/`: plain relative paths only.
        if (path.len == 0 or path[0] == '/' or std.mem.indexOf(u8, path, "..") != null) {
            return error.BadManifest;
        }
        var member: up_tar.Member = .{
            .path = path,
            .size = try integer_field(output, "size"),
            .blake3 = undefined,
        };
        const hex = try string_field(output, "blake3");
        if (hex.len != 64) return error.BadManifest;
        _ = std.fmt.hexToBytes(&member.blake3, hex) catch return error.BadManifest;
        has_mdbx = has_mdbx or std.mem.endsWith(u8, path, "mdbx.dat");
        snapshot.members[snapshot.members_count] = member;
        snapshot.members_count += 1;
    }
    if (!has_mdbx) return error.BadManifest;
}

/// Base serves snapshots over HTTPS; plain HTTP is accepted for local mirrors (integrity
/// comes from the manifest's blake3 and the import's state root, not the transport).
fn is_http(url: []const u8) bool {
    return std.mem.startsWith(u8, url, "https://") or std.mem.startsWith(u8, url, "http://");
}

fn object_field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.BadManifest;
    const field = value.object.get(name) orelse return error.BadManifest;
    if (field != .object) return error.BadManifest;
    return field;
}

fn string_field(value: std.json.Value, name: []const u8) ![]const u8 {
    if (value != .object) return error.BadManifest;
    const field = value.object.get(name) orelse return error.BadManifest;
    if (field != .string) return error.BadManifest;
    return field.string;
}

fn integer_field(value: std.json.Value, name: []const u8) !u64 {
    if (value != .object) return error.BadManifest;
    const field = value.object.get(name) orelse return error.BadManifest;
    if (field != .integer or field.integer < 0) return error.BadManifest;
    return @intCast(field.integer);
}

/// The listing's latest snapshot for `chain_id`: the manifest's text and its URL.
pub fn fetch_latest(
    arena: std.mem.Allocator,
    io: Io,
    listing: []const u8,
    chain_id: u64,
) !struct { url: []const u8, text: []const u8 } {
    const listing_buffer = try arena.alloc(u8, listing_bytes_max);
    const answer = try up_check.fetch(arena, io, .{ .url = listing }, listing_buffer, 30_000);
    if (answer.status != .ok) return error.ListingUnavailable;
    const url = try parse_listing(arena, answer.body, chain_id);
    const manifest_buffer = try arena.alloc(u8, manifest_bytes_max);
    const manifest = try up_check.fetch(arena, io, .{ .url = url }, manifest_buffer, 60_000);
    if (manifest.status != .ok) return error.ManifestUnavailable;
    return .{ .url = url, .text = manifest.body };
}

/// Whether the archive is still published: a one-byte range request.
pub fn archive_published(gpa: std.mem.Allocator, io: Io, url: []const u8) !bool {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var request = try client.request(.GET, try std.Uri.parse(url), .{
        .extra_headers = &.{.{ .name = "range", .value = "bytes=0-0" }},
        .headers = .{ .accept_encoding = .omit },
    });
    defer request.deinit();
    try request.sendBodiless();
    var redirect: [8 * 1024]u8 = undefined;
    const response = try request.receiveHead(&redirect);
    return switch (response.head.status) {
        .ok, .partial_content => true,
        .not_found, .forbidden, .gone => false,
        else => error.HttpStatus,
    };
}

// ---- Download ------------------------------------------------------------------------

pub const Failure = enum(u8) { none, gone, changed, no_space, write_failed, gave_up };

pub const Download = struct {
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    url: []const u8,
    archive_bytes: u64,
    chunks: u32,
    stop: *const std.atomic.Value(bool),
    next: std.atomic.Value(u32) = .init(0),
    /// Archive bytes on disk (complete chunks and parts).
    bytes: std.atomic.Value(u64) = .init(0),
    failure: std.atomic.Value(Failure) = .init(.none),
    /// The cap on all workers together (`--download.rate`); 0: none. A node on the same link
    /// fetches its blocks over it, and a saturated link delays them by seconds.
    rate_bytes_per_s: u64 = 0,
    /// Bytes received this run, and when the run started (the cap's budget).
    received: std.atomic.Value(u64) = .init(0),
    started_ms: i64 = 0,

    pub fn chunk_range(download: *const Download, index: u32) struct { start: u64, end: u64 } {
        assert(index < download.chunks);
        const start = @as(u64, index) * chunk_bytes;
        const end = @min(start + chunk_bytes, download.archive_bytes);
        assert(start < end);
        return .{ .start = start, .end = end };
    }

    fn fail(download: *Download, failure: Failure) void {
        assert(failure != .none);
        _ = download.failure.cmpxchgStrong(.none, failure, .acq_rel, .acquire);
    }

    pub fn failed(download: *const Download) Failure {
        return download.failure.load(.acquire);
    }

    fn halted(download: *const Download) bool {
        return download.stop.load(.acquire) or download.failed() != .none;
    }

    /// Counts the bytes already on disk (before the workers start).
    pub fn count_existing(download: *Download) !void {
        var total: u64 = 0;
        for (0..download.chunks) |index| {
            total += try chunk_length(download, @intCast(index));
        }
        download.bytes.store(total, .release);
    }

    fn chunk_length(download: *const Download, index: u32) !u64 {
        var name: ChunkName = .init(index);
        const range = download.chunk_range(index);
        if (stat_size(download.io, download.dir, name.complete())) |size| {
            if (size == range.end - range.start) return size;
        }
        return stat_size(download.io, download.dir, name.part()) orelse 0;
    }

    /// How long a worker waits before reading more, for `received` bytes to stay within the
    /// rate cap since `started_ms`; 0 without a cap.
    pub fn throttle_ms(download: *const Download, now_ms: i64) u64 {
        const rate = download.rate_bytes_per_s;
        if (rate == 0) return 0;
        assert(now_ms >= download.started_ms);
        const due_ms = download.received.load(.monotonic) * 1000 / rate;
        const elapsed_ms: u64 = @intCast(now_ms - download.started_ms);
        return due_ms -| elapsed_ms;
    }

    /// A worker: claims chunks in order until none is left or the download halts.
    pub fn worker(download: *Download) Io.Cancelable!void {
        var state: Worker = .{ .download = download };
        state.client = .{ .allocator = download.gpa, .io = download.io };
        defer state.client.deinit();
        while (!download.halted()) {
            const index = download.next.fetchAdd(1, .monotonic);
            if (index >= download.chunks) return;
            state.fetch_chunk(index) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.SnapshotGone => download.fail(.gone),
                error.SnapshotChanged => download.fail(.changed),
                error.NoSpaceLeft => download.fail(.no_space),
                error.GaveUp => download.fail(.gave_up),
                else => download.fail(.write_failed),
            };
        }
    }
};

const ChunkName = struct {
    buffer: [16]u8 = undefined,
    index: u32,

    fn init(index: u32) ChunkName {
        assert(index < chunks_max);
        return .{ .index = index };
    }

    fn complete(name: *ChunkName) []const u8 {
        return std.fmt.bufPrint(&name.buffer, "{d:0>7}", .{name.index}) catch unreachable;
    }

    fn part(name: *ChunkName) []const u8 {
        return std.fmt.bufPrint(&name.buffer, "{d:0>7}.part", .{name.index}) catch unreachable;
    }
};

fn stat_size(io: Io, dir: Io.Dir, name: []const u8) ?u64 {
    const stat = dir.statFile(io, name, .{}) catch return null;
    return stat.size;
}

const Worker = struct {
    download: *Download,
    client: std.http.Client = undefined,
    /// Awake-clock time of the last byte received (read by the stall watch).
    progress_ms: std.atomic.Value(i64) = .init(0),

    fn now_ms(worker: *const Worker) i64 {
        return Io.Clock.awake.now(worker.download.io).toMilliseconds();
    }

    /// Fetches chunk `index` into its part file, resuming, then renames it complete.
    fn fetch_chunk(worker: *Worker, index: u32) !void {
        const download = worker.download;
        const io = download.io;
        var name: ChunkName = .init(index);
        const range = download.chunk_range(index);
        const length = range.end - range.start;
        if (stat_size(io, download.dir, name.complete()) == length) return;
        const part = try download.dir.createFile(io, name.part(), .{ .truncate = false });
        defer part.close(io);
        var have = try part.length(io);
        if (have > length) {
            // Not ours to keep: start the chunk over.
            _ = download.bytes.fetchSub(have, .monotonic);
            try part.setLength(io, 0);
            have = 0;
        }
        var attempts: u32 = 0;
        while (have < length) : (attempts += 1) {
            if (download.halted()) return;
            if (attempts == attempts_max) return error.GaveUp;
            if (attempts > 0) try worker.back_off(attempts);
            worker.attempt_watched(part, range.start, have, length) catch |err| switch (err) {
                error.SnapshotGone, error.SnapshotChanged, error.NoSpaceLeft => return err,
                error.Canceled => return err,
                else => {}, // Network trouble: resume after a pause.
            };
            have = try part.length(io);
            assert(have <= length);
        }
        var final_name: ChunkName = .init(index);
        try download.dir.rename(name.part(), download.dir, final_name.complete(), io);
    }

    fn back_off(worker: *Worker, attempts: u32) Io.Cancelable!void {
        assert(attempts > 0);
        const shift: u6 = @intCast(@min(attempts, 16));
        const pause_ms = @min(backoff_ms_max, @as(u64, 500) << shift);
        try Io.sleep(worker.download.io, .fromMilliseconds(@intCast(pause_ms)), .awake);
    }

    const Outcome = union(enum) {
        fetched: anyerror!void,
        stalled: Io.Cancelable!void,
    };

    /// One ranged request for the rest of the chunk, dropped when it stalls.
    fn attempt_watched(worker: *Worker, part: Io.File, start: u64, have: u64, length: u64) !void {
        assert(have < length);
        const io = worker.download.io;
        worker.progress_ms.store(worker.now_ms(), .release);
        var buffer: [2]Outcome = undefined;
        var select = Io.Select(Outcome).init(io, &buffer);
        // On every path, cancellation included: the tasks use this frame.
        defer select.cancelDiscard();
        try select.concurrent(.fetched, request_rest, .{ worker, part, start, have, length });
        try select.concurrent(.stalled, watch, .{worker});
        const first = try select.await();
        select.cancelDiscard();
        switch (first) {
            .fetched => |result| return result,
            .stalled => {
                // The cancelled request may have left its connection mid-response.
                worker.client.deinit();
                worker.client = .{ .allocator = worker.download.gpa, .io = io };
                return error.Stalled;
            },
        }
    }

    fn watch(worker: *Worker) Io.Cancelable!void {
        const io = worker.download.io;
        while (true) {
            try Io.sleep(io, .fromSeconds(5), .awake);
            if (worker.now_ms() - worker.progress_ms.load(.acquire) > stall_ms) return;
        }
    }

    fn request_rest(
        worker: *Worker,
        part: Io.File,
        start: u64,
        have: u64,
        length: u64,
    ) anyerror!void {
        const download = worker.download;
        var range_buffer: [64]u8 = undefined;
        const range = try std.fmt.bufPrint(&range_buffer, "bytes={d}-{d}", .{
            start + have, start + length - 1,
        });
        var request = try worker.client.request(.GET, try std.Uri.parse(download.url), .{
            .extra_headers = &.{.{ .name = "range", .value = range }},
            .headers = .{ .accept_encoding = .omit },
        });
        defer request.deinit();
        try request.sendBodiless();
        var redirect: [8 * 1024]u8 = undefined;
        var response = try request.receiveHead(&redirect);
        switch (response.head.status) {
            .partial_content => {},
            .not_found, .forbidden, .gone => return error.SnapshotGone,
            .range_not_satisfiable => return error.SnapshotChanged,
            else => return error.HttpStatus,
        }
        if (response.head.content_length != length - have) return error.SnapshotChanged;
        var transfer: [64 * 1024]u8 = undefined;
        const body = response.reader(&transfer);
        return worker.copy_body(body, part, have, length);
    }

    fn copy_body(worker: *Worker, body: *Io.Reader, part: Io.File, have: u64, length: u64) !void {
        const download = worker.download;
        var buffer: [read_buffer_bytes]u8 = undefined;
        var offset = have;
        while (offset < length) {
            const want: usize = @intCast(@min(buffer.len, length - offset));
            const got = try body.readSliceShort(buffer[0..want]);
            if (got == 0) return error.EndOfStream;
            part.writePositionalAll(download.io, buffer[0..got], offset) catch |err| {
                return if (err == error.NoSpaceLeft) error.NoSpaceLeft else err;
            };
            offset += got;
            _ = download.bytes.fetchAdd(got, .monotonic);
            _ = download.received.fetchAdd(got, .monotonic);
            worker.progress_ms.store(worker.now_ms(), .release);
            // Under a cap, reading later slows the sender (TCP flow control) on the link.
            const wait_ms = download.throttle_ms(worker.now_ms());
            if (wait_ms > 0) {
                try Io.sleep(download.io, .fromMilliseconds(@intCast(wait_ms)), .awake);
                worker.progress_ms.store(worker.now_ms(), .release);
            }
        }
        assert(offset == length);
    }
};

// ---- Extraction ----------------------------------------------------------------------

/// The archive as one stream over its complete chunks, in order, waiting for each.
pub const ChunkReader = struct {
    reader: Io.Reader,
    download: *Download,
    index: u32 = 0,
    offset: u64 = 0,
    file: ?Io.File = null,
    /// Archive bytes handed to the decoder (the failing offset on a decode error).
    consumed: u64 = 0,

    pub fn init(download: *Download, buffer: []u8) ChunkReader {
        assert(buffer.len > 0);
        return .{
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
            .download = download,
        };
    }

    pub fn deinit(chunk_reader: *ChunkReader) void {
        if (chunk_reader.file) |file| file.close(chunk_reader.download.io);
        chunk_reader.file = null;
    }

    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const chunk_reader: *ChunkReader = @alignCast(@fieldParentPtr("reader", r));
        const download = chunk_reader.download;
        if (chunk_reader.index == download.chunks) return error.EndOfStream;
        const file = chunk_reader.file orelse chunk_reader.open_next() catch {
            return error.ReadFailed;
        };
        const range = download.chunk_range(chunk_reader.index);
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const want: usize = @intCast(@min(dest.len, range.end - range.start - chunk_reader.offset));
        const got = file.readPositional(download.io, &.{dest[0..want]}, chunk_reader.offset) catch {
            return error.ReadFailed;
        };
        if (got == 0) return error.ReadFailed; // A complete chunk is never short.
        w.advance(got);
        chunk_reader.offset += got;
        chunk_reader.consumed += got;
        if (chunk_reader.offset == range.end - range.start) {
            file.close(download.io);
            chunk_reader.file = null;
            chunk_reader.index += 1;
            chunk_reader.offset = 0;
        }
        return got;
    }

    /// Opens the current chunk once it is complete; waits while the download runs.
    fn open_next(chunk_reader: *ChunkReader) !Io.File {
        const download = chunk_reader.download;
        assert(chunk_reader.file == null and chunk_reader.offset == 0);
        var name: ChunkName = .init(chunk_reader.index);
        while (true) {
            if (download.halted()) return error.Halted;
            if (download.dir.openFile(download.io, name.complete(), .{})) |file| {
                chunk_reader.file = file;
                return file;
            } else |err| if (err != error.FileNotFound) return err;
            try Io.sleep(download.io, .fromMilliseconds(500), .awake);
        }
    }
};

/// Members written into a directory, created as they start.
///
/// A restarted extraction (a resumed `base up`) decodes the archive from its first chunk
/// again, but does not rewrite what an earlier run already wrote: a member file is kept, and
/// below its length (`kept`) each decoded range is compared with the bytes on disk and written
/// only where they differ. Reads instead of hundreds of GB of writes on a disk the node may
/// share; the member's blake3 is still over the decoded bytes, and the file ends equal to them.
pub const DirectoryOutput = struct {
    io: Io,
    dir: Io.Dir,
    file: ?Io.File = null,
    /// Bytes of the open member on disk from an earlier run that are compared, not written.
    kept: u64 = 0,
    /// Bytes compared equal and so not written (all members, this run).
    skipped: u64 = 0,
    compare_buffer: [compare_bytes]u8 = undefined,

    const compare_bytes = 1 << 20;

    pub fn output(directory: *DirectoryOutput) up_tar.Output {
        return .{ .context = directory, .open = open, .write = write, .close = close };
    }

    fn open(context: *anyopaque, index: u32, member: *const up_tar.Member) anyerror!void {
        const directory: *DirectoryOutput = @ptrCast(@alignCast(context));
        assert(directory.file == null);
        assert(index < up_tar.members_max);
        if (std.fs.path.dirname(member.path)) |parent| {
            try directory.dir.createDirPath(directory.io, parent);
        }
        const file = try directory.dir.createFile(directory.io, member.path, .{
            .read = true,
            .truncate = false,
        });
        errdefer file.close(directory.io);
        const length = try file.length(directory.io);
        // A longer file is not this member's: the tail past its size goes.
        if (length > member.size) try file.setLength(directory.io, member.size);
        directory.file = file;
        directory.kept = @min(length, member.size);
    }

    fn write(context: *anyopaque, bytes: []const u8, offset: u64) anyerror!void {
        const directory: *DirectoryOutput = @ptrCast(@alignCast(context));
        const file = directory.file.?;
        var done: usize = 0;
        while (done < bytes.len and offset + done < directory.kept) {
            const at = offset + done;
            const length: usize = @intCast(@min(
                bytes.len - done,
                directory.kept - at,
                compare_bytes,
            ));
            const disk = directory.compare_buffer[0..length];
            const got = try file.readPositionalAll(directory.io, disk, at);
            if (got != length or !std.mem.eql(u8, disk, bytes[done..][0..length])) {
                // From the first difference on, the earlier run's bytes are not trusted.
                directory.kept = at;
                break;
            }
            directory.skipped += length;
            done += length;
        }
        assert(done <= bytes.len);
        if (done < bytes.len) {
            try file.writePositionalAll(directory.io, bytes[done..], offset + done);
        }
    }

    fn close(context: *anyopaque) anyerror!void {
        const directory: *DirectoryOutput = @ptrCast(@alignCast(context));
        directory.file.?.close(directory.io);
        directory.file = null;
        directory.kept = 0;
    }
};

pub const Extraction = struct {
    sink: up_tar.Sink,
    chunk_reader: ChunkReader,
    directory: DirectoryOutput,
    /// Null while the extraction runs.
    result: ?(anyerror!void) = null,
    done: std.atomic.Value(bool) = .init(false),

    /// Extracts the archive (the extraction task): zstd over the chunks into the tar sink.
    pub fn run(extraction: *Extraction, gpa: std.mem.Allocator) Io.Cancelable!void {
        defer extraction.done.store(true, .release);
        extraction.result = extraction.decode(gpa);
    }

    fn decode(extraction: *Extraction, gpa: std.mem.Allocator) anyerror!void {
        _ = gpa;
        const window = std.compress.zstd.block_size_max + window_bytes;
        comptime assert(sink_buffer_bytes > window);
        assert(extraction.sink.writer.buffer.len >= window);
        assert(extraction.chunk_reader.reader.buffer.len > 0);
        var decompress = std.compress.zstd.Decompress.init(&extraction.chunk_reader.reader, &.{}, .{
            .window_len = window_bytes,
        });
        _ = decompress.reader.streamRemaining(&extraction.sink.writer) catch |err| switch (err) {
            error.WriteFailed => return extraction.sink.failure.?,
            error.ReadFailed => {
                if (extraction.chunk_reader.download.halted()) return error.Halted;
                return decompress.err orelse error.ReadFailed;
            },
        };
        try extraction.sink.finish();
    }
};

// ---- Tests ---------------------------------------------------------------------------

const testing = std.testing;

test "up snapshot: the listing names each chain's manifest" {
    const listing =
        \\[{"chainId":"8453","network":"mainnet","block":55824129,
        \\  "manifestUrl":"https://mainnet-v2-snapshots.base.org/1794355208/manifest.json"},
        \\ {"chainId":"84532","network":"sepolia",
        \\  "manifestUrl":"https://sepolia-v2-snapshots.base.org/1794355922/manifest.json"}]
    ;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const url = try parse_listing(arena.allocator(), listing, 8453);
    try testing.expectEqualStrings(
        "https://mainnet-v2-snapshots.base.org/1794355208/manifest.json",
        url,
    );
    try testing.expectStringEndsWith(
        try parse_listing(arena.allocator(), listing, 84532),
        "922/manifest.json",
    );
    try testing.expectError(error.ChainNotListed, parse_listing(arena.allocator(), listing, 10));
    try testing.expectError(error.BadListing, parse_listing(arena.allocator(), "{}", 8453));
}

/// The `state` component of Base mainnet's manifest of 2026-11-11 (other components cut).
const mainnet_manifest =
    \\{"block": 55824129, "chain_id": 8453, "storage_version": 2,
    \\ "base_url": "https://mainnet-v2-snapshots.base.org",
    \\ "components": {"state": {"file": "1794355208/state.tar.zst", "size": 761254291350,
    \\  "decompressed_size": 1138167361549, "output_files": [
    \\  {"path": "db/database.version", "size": 1,
    \\   "blake3": "813e9b729141e7f385afa0a2d0df3e6c3789e427ffe4aeef566a565bc8f2fe3d"},
    \\  {"path": "db/lock", "size": 12,
    \\   "blake3": "1e408a6bd9c9bf007336ae0a7e41a6b192bb6697a4e15ac401f4371ee79fc220"},
    \\  {"path": "db/mdbx.dat", "size": 1138166333440,
    \\   "blake3": "a07a84889e49faedfbbfc0026df660634f5ee0fa75f64ee767d64affde2301a8"},
    \\  {"path": "db/mdbx.lck", "size": 1028096,
    \\   "blake3": "b7334c38d2599b80ec57f5fa8e36059748d5dc9cb1fe40e28f4f64b6aa45a6b8"}]}}}
;

test "up snapshot: the manifest's state component" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const snapshot = try parse_manifest(arena.allocator(), mainnet_manifest, "https://m/x.json");
    try testing.expectEqual(@as(u64, 55_824_129), snapshot.block);
    try testing.expectEqualStrings(
        "https://mainnet-v2-snapshots.base.org/1794355208/state.tar.zst",
        snapshot.archive_url,
    );
    try testing.expectEqual(@as(u64, 1_138_166_333_440), snapshot.mdbx_bytes());
    try testing.expectEqual(@as(u32, 4), snapshot.members_count);
    try testing.expectEqual(@as(u8, 0xa0), snapshot.members[2].blake3[0]);
    // 761.25 GB in 256 MiB chunks.
    try testing.expectEqual(@as(u32, 2836), snapshot.chunk_count());
    // A path escaping the extraction directory, and a manifest without mdbx.dat.
    const escaping = try std.mem.replaceOwned(
        u8,
        arena.allocator(),
        mainnet_manifest,
        "db/lock",
        "../lock",
    );
    try testing.expectError(error.BadManifest, parse_manifest(arena.allocator(), escaping, "u"));
    const no_mdbx = try std.mem.replaceOwned(
        u8,
        arena.allocator(),
        mainnet_manifest,
        "mdbx.dat",
        "other.dat",
    );
    try testing.expectError(error.BadManifest, parse_manifest(arena.allocator(), no_mdbx, "u"));
}

test "up snapshot: chunk ranges tile the archive" {
    var stop: std.atomic.Value(bool) = .init(false);
    const sizes = [_]u64{ 1, chunk_bytes - 1, chunk_bytes, chunk_bytes + 1, 761_254_291_350 };
    for (sizes) |size| {
        const count: u32 = @intCast(std.math.divCeil(u64, size, chunk_bytes) catch unreachable);
        const download: Download = .{
            .gpa = testing.allocator,
            .io = testing.io,
            .dir = Io.Dir.cwd(),
            .url = "https://x",
            .archive_bytes = size,
            .chunks = count,
            .stop = &stop,
        };
        var expected_start: u64 = 0;
        for (0..count) |index| {
            const range = download.chunk_range(@intCast(index));
            try testing.expectEqual(expected_start, range.start);
            expected_start = range.end;
        }
        try testing.expectEqual(size, expected_start);
    }
}

test "up snapshot: a resumed extraction keeps the bytes it wrote, rewrites from a difference" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var content: [5000]u8 = undefined;
    for (&content, 0..) |*byte, index| byte.* = @truncate(index *% 7 +% 3);
    const member: up_tar.Member = .{
        .path = "db/mdbx.dat",
        .size = content.len,
        .blake3 = @splat(0),
    };
    // An earlier run wrote 3000 bytes, one of them damaged at 1500.
    var earlier = content[0..3000].*;
    earlier[1500] ^= 0xff;
    try tmp.dir.createDirPath(io, "db");
    try tmp.dir.writeFile(io, .{ .sub_path = member.path, .data = &earlier });
    const directory = try testing.allocator.create(DirectoryOutput);
    defer testing.allocator.destroy(directory);
    directory.* = .{ .io = io, .dir = tmp.dir };
    const output = directory.output();
    try output.open(output.context, 0, &member);
    var offset: usize = 0;
    while (offset < content.len) : (offset += 1000) {
        try output.write(output.context, content[offset..][0..1000], offset);
    }
    try output.close(output.context);
    var read_buffer: [6000]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        &content,
        try tmp.dir.readFile(io, member.path, &read_buffer),
    );
    // The first 1000 bytes matched and were not written again; the damaged range was.
    try testing.expectEqual(@as(u64, 1000), directory.skipped);
    // A file longer than the member (not this member's bytes) ends at the member's size.
    var longer: [5500]u8 = undefined;
    @memcpy(longer[0..5000], &content);
    @memset(longer[5000..], 0xaa);
    try tmp.dir.writeFile(io, .{ .sub_path = member.path, .data = &longer });
    directory.skipped = 0;
    try output.open(output.context, 0, &member);
    try output.write(output.context, &content, 0);
    try output.close(output.context);
    try testing.expectEqualSlices(
        u8,
        &content,
        try tmp.dir.readFile(io, member.path, &read_buffer),
    );
    try testing.expectEqual(@as(u64, content.len), directory.skipped);
}

test "up snapshot: the rate cap holds the workers to rate x elapsed" {
    var stop: std.atomic.Value(bool) = .init(false);
    var download: Download = .{
        .gpa = testing.allocator,
        .io = testing.io,
        .dir = undefined,
        .url = "",
        .archive_bytes = 1,
        .chunks = 1,
        .stop = &stop,
        .started_ms = 10_000,
    };
    // No cap: never waits.
    download.received.store(1 << 40, .monotonic);
    try testing.expectEqual(@as(u64, 0), download.throttle_ms(10_000));
    // 4 MB/s: 10 MB received 1 s in are due at 2.5 s, so 1.5 s to wait; none once due.
    download.rate_bytes_per_s = 4_000_000;
    download.received.store(10_000_000, .monotonic);
    try testing.expectEqual(@as(u64, 1_500), download.throttle_ms(11_000));
    try testing.expectEqual(@as(u64, 0), download.throttle_ms(12_500));
    try testing.expectEqual(@as(u64, 0), download.throttle_ms(20_000));
}

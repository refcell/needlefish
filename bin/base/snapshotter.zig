//! `base snapshotter create|restore|verify`: node datadir snapshots (see
//! `src/infra/snapshotter`).
//!
//! `create` checks the node is at tip (`--rpc-url`, optional), runs `--stop-cmd`, splits
//! `DATADIR/node.db` into content-addressed chunks under `STORE/chunks/` (chunks already in
//! the store are reused), writes `STORE/manifests/<block>.txt` and points `STORE/latest` at
//! it, then runs `--start-cmd` (also after a failure, so the node is never left stopped).
//! The node must be stopped while its database is read: a live copy can be torn.
//! `restore` verifies every chunk, writes `DATADIR/node.db` through a temporary file, and
//! renames it into place. `verify` checks a manifest's chunks without writing anything.

const std = @import("std");
const base = @import("base");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const Io = std.Io;
const Dir = Io.Dir;
const cli = base.utilities.cli;
const rpc = base.batcher.rpc;
const snapshotter = base.infra.snapshotter;
const manifest = snapshotter.manifest;

const env_prefix = "BASE_SNAPSHOTTER_";
const db_name = "node.db";
const manifest_bytes_max = 8 * 1024 * 1024;

pub const Spec = struct {
    datadir: []const u8,
    store: []const u8,
    chain_id: u64 = 0,
    rpc_url: []const u8 = "",
    freshness_s: u64 = snapshotter.tip.freshness_default_s,
    chunk_bytes: u32 = 8 * 1024 * 1024,
    stop_cmd: []const u8 = "",
    start_cmd: []const u8 = "",
    manifest: []const u8 = "",
    force: bool = false,

    pub const help = .{
        .datadir = "Node datadir (holds node.db)",
        .store = "Snapshot store directory",
        .chain_id = "Chain id recorded in the manifest (create)",
        .rpc_url = "Node JSON-RPC; create skips unless the node is at tip",
        .freshness_s = "Latest block must be at most this old (seconds)",
        .chunk_bytes = "Chunk size in bytes (create)",
        .stop_cmd = "Shell command run before reading the database (create)",
        .start_cmd = "Shell command run afterwards, also on failure (create)",
        .manifest = "Manifest path in the store (restore/verify; default: latest)",
        .force = "Replace an existing node.db (restore)",
    };
};

fn print_help() void {
    var buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    cli.write_help(Spec, env_prefix, &writer) catch {};
    const usage = "usage: base snapshotter create|restore|verify --datadir DIR --store DIR\n";
    std.debug.print("{s}{s}", .{ usage, writer.buffered() });
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len == 0) {
        print_help();
        return 2;
    }
    var diagnostic: cli.Diagnostic = .{};
    const env = cli.Env.from_map(init.environ_map);
    const spec = cli.parse(Spec, env_prefix, args[1..], env, &diagnostic) catch |err| {
        if (err == error.HelpRequested) {
            print_help();
            return 0;
        }
        std.debug.print("snapshotter: {t}: {s}\n", .{ err, diagnostic.subject });
        return 2;
    };
    const command = args[0];
    const result = if (std.mem.eql(u8, command, "create"))
        create(init, spec)
    else if (std.mem.eql(u8, command, "restore"))
        restore(init, spec, false)
    else if (std.mem.eql(u8, command, "verify"))
        restore(init, spec, true)
    else {
        print_help();
        return 2;
    };
    return result catch |err| {
        std.debug.print("snapshotter {s}: {t}\n", .{ command, err });
        return 1;
    };
}

fn now_s(io: Io) u64 {
    return @intCast(@divFloor(Io.Clock.real.now(io).toMilliseconds(), 1000));
}

const Head = struct { number: u64 = 0, hash: manifest.Hash = @splat(0) };

/// Returns null when the node is not at tip (the run is skipped).
fn check_tip(init: std.process.Init, spec: Spec) !?Head {
    if (spec.rpc_url.len == 0) return .{};
    var http = HttpTransport.init(init.gpa, init.io, spec.rpc_url);
    http.timeout_ms = 10_000;
    defer http.deinit();
    var client = try rpc.Client.init(init.gpa, http.transport(), .{
        .request_bytes_max = 4096,
        .response_bytes_max = 64 * 1024,
        .parse_bytes_max = 256 * 1024,
    });
    defer client.deinit(init.gpa);
    const status = try snapshotter.tip.check(&client, now_s(init.io), spec.freshness_s);
    if (!status.at_tip) return null;
    return .{ .number = status.block_number, .hash = status.block_hash };
}

fn run_hook(init: std.process.Init, command: []const u8) !void {
    if (command.len == 0) return;
    var child = try std.process.spawn(init.io, .{ .argv = &.{ "/bin/sh", "-c", command } });
    const term = try child.wait(init.io);
    if (!term.success()) return error.HookFailed;
}

fn create(init: std.process.Init, spec: Spec) !u8 {
    const head = try check_tip(init, spec) orelse {
        std.debug.print("snapshotter: node is not at tip; skipped, node left running\n", .{});
        return 0;
    };
    try run_hook(init, spec.stop_cmd);
    const result = write_snapshot(init, spec, head);
    run_hook(init, spec.start_cmd) catch |err| {
        std.debug.print("snapshotter: start command failed: {t}\n", .{err});
        _ = result catch {};
        return err;
    };
    return result;
}

fn write_snapshot(init: std.process.Init, spec: Spec, head: Head) !u8 {
    const io = init.io;
    const cwd = Dir.cwd();
    var datadir = try cwd.openDir(io, spec.datadir, .{});
    defer datadir.close(io);
    var db = try datadir.openFile(io, db_name, .{});
    defer db.close(io);
    try cwd.createDirPath(io, spec.store);
    var store = try cwd.openDir(io, spec.store, .{});
    defer store.close(io);
    try store.createDirPath(io, "chunks");
    try store.createDirPath(io, "manifests");
    const header: manifest.Header = .{
        .chain_id = spec.chain_id,
        .block_number = head.number,
        .block_hash = head.hash,
        .file_name = db_name,
        .file_bytes = try db.length(io),
        .chunk_bytes = spec.chunk_bytes,
    };
    if (!header.valid()) return error.InvalidSnapshotParameters;
    const chunks = try init.gpa.alloc(manifest.Chunk, @intCast(header.chunk_count()));
    defer init.gpa.free(chunks);
    const buffer = try init.gpa.alloc(u8, spec.chunk_bytes);
    defer init.gpa.free(buffer);
    var reused: u64 = 0;
    for (chunks, 0..) |*chunk, index| {
        const size = header.chunk_size(index);
        const bytes = buffer[0..size];
        const read = try db.readPositionalAll(io, bytes, index * header.chunk_bytes);
        if (read != size) return error.DatabaseChanged;
        chunk.* = .{ .size = size, .hash = manifest.chunk_hash(bytes) };
        if (try put_chunk(io, store, chunk.hash, bytes)) reused += 1;
    }
    if (try db.length(io) != header.file_bytes) return error.DatabaseChanged;
    try write_manifest(init, store, header, chunks);
    std.debug.print("snapshotter: block {d}: {d} chunks ({d} reused), {d} bytes\n", .{
        head.number, chunks.len, reused, header.file_bytes,
    });
    return 0;
}

/// Writes a chunk unless the store already has it; returns true when reused.
fn put_chunk(io: Io, store: Dir, hash: manifest.Hash, bytes: []const u8) !bool {
    var path_buffer: [71]u8 = undefined;
    const path = manifest.chunk_path(hash, &path_buffer);
    if (store.statFile(io, path, .{})) |stat| {
        if (stat.size == bytes.len) return true;
    } else |err| if (err != error.FileNotFound) return err;
    try write_atomic(io, store, path, bytes);
    return false;
}

fn write_atomic(io: Io, dir: Dir, path: []const u8, bytes: []const u8) !void {
    var temp_buffer: [128]u8 = undefined;
    const temp = try std.fmt.bufPrint(&temp_buffer, "{s}.tmp", .{path});
    var file = try dir.createFile(io, temp, .{});
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.sync(io);
    try dir.rename(temp, dir, path, io);
}

fn write_manifest(
    init: std.process.Init,
    store: Dir,
    header: manifest.Header,
    chunks: []const manifest.Chunk,
) !void {
    var text: std.Io.Writer.Allocating = .init(init.gpa);
    defer text.deinit();
    try manifest.write(header, chunks, &text.writer);
    var name_buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "manifests/{d}.txt", .{header.block_number});
    try write_atomic(init.io, store, name, text.written());
    try write_atomic(init.io, store, "latest", name);
}

fn restore(init: std.process.Init, spec: Spec, verify_only: bool) !u8 {
    const io = init.io;
    const cwd = Dir.cwd();
    var store = try cwd.openDir(io, spec.store, .{});
    defer store.close(io);
    var latest_buffer: [64]u8 = undefined;
    const manifest_path = if (spec.manifest.len > 0) spec.manifest else latest: {
        const file = try store.openFile(io, "latest", .{});
        defer file.close(io);
        const length = try file.readPositionalAll(io, &latest_buffer, 0);
        break :latest std.mem.trim(u8, latest_buffer[0..length], " \n");
    };
    const text = try store.readFileAlloc(io, manifest_path, init.gpa, .limited(manifest_bytes_max));
    defer init.gpa.free(text);
    const chunks = try init.gpa.alloc(manifest.Chunk, manifest.chunks_max);
    defer init.gpa.free(chunks);
    const decoded = try manifest.decode(text, chunks);
    const buffer = try init.gpa.alloc(u8, decoded.header.chunk_bytes);
    defer init.gpa.free(buffer);
    const header = decoded.header;
    if (verify_only) {
        for (chunks[0..decoded.chunk_count]) |chunk| _ = try read_chunk(io, store, chunk, buffer);
        std.debug.print("snapshotter: block {d}: {d} chunks verified\n", .{
            header.block_number, decoded.chunk_count,
        });
        return 0;
    }
    try restore_into(init, spec, store, header, chunks[0..decoded.chunk_count], buffer);
    std.debug.print("snapshotter: restored block {d} ({d} bytes) into {s}\n", .{
        header.block_number, header.file_bytes, spec.datadir,
    });
    return 0;
}

fn restore_into(
    init: std.process.Init,
    spec: Spec,
    store: Dir,
    header: manifest.Header,
    chunks: []const manifest.Chunk,
    buffer: []u8,
) !void {
    const io = init.io;
    const cwd = Dir.cwd();
    try cwd.createDirPath(io, spec.datadir);
    var datadir = try cwd.openDir(io, spec.datadir, .{});
    defer datadir.close(io);
    if (!spec.force) {
        if (datadir.statFile(io, header.file_name, .{})) |_| {
            return error.DatabaseExists;
        } else |err| if (err != error.FileNotFound) return err;
    }
    var temp_buffer: [manifest.file_name_max + 16]u8 = undefined;
    const temp = try std.fmt.bufPrint(&temp_buffer, "{s}.restore", .{header.file_name});
    var file = try datadir.createFile(io, temp, .{});
    defer file.close(io);
    var offset: u64 = 0;
    for (chunks) |chunk| {
        const bytes = try read_chunk(io, store, chunk, buffer);
        try file.writePositionalAll(io, bytes, offset);
        offset += bytes.len;
    }
    std.debug.assert(offset == header.file_bytes);
    try file.sync(io);
    try datadir.rename(temp, datadir, header.file_name, io);
}

/// Reads a chunk from the store and checks its size and hash.
fn read_chunk(io: Io, store: Dir, chunk: manifest.Chunk, buffer: []u8) ![]const u8 {
    var path_buffer: [71]u8 = undefined;
    const path = manifest.chunk_path(chunk.hash, &path_buffer);
    var file = try store.openFile(io, path, .{});
    defer file.close(io);
    if (try file.length(io) != chunk.size) return error.ChunkCorrupt;
    const bytes = buffer[0..chunk.size];
    if (try file.readPositionalAll(io, bytes, 0) != chunk.size) return error.ChunkCorrupt;
    const hash = manifest.chunk_hash(bytes);
    if (!std.mem.eql(u8, &hash, &chunk.hash)) return error.ChunkCorrupt;
    return bytes;
}

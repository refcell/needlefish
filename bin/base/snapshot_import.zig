//! `base snapshot-import`: verifies a reth state database from a public Base snapshot
//! (docs/SYNC_PLAN.md M3). It reads `mdbx.dat` with needlefish's own MDBX reader, takes the
//! snapshot's block from `StageCheckpoints["Finish"]`, streams `HashedAccounts` and
//! `HashedStorages` into a constant-memory state root, and compares that root with the
//! block's header. The header comes from `--rpc` and is bound to its block hash, or the
//! expected root is given with `--state-root`. Exit 0 only when the roots match.
//!
//!     base snapshot-import --db <path/mdbx.dat> [--chain base-sepolia|base-mainnet]
//!                          [--rpc <url>] [--state-root <hex>] [--blake3 <hex>]
//!
//! `--blake3` first checks the file against the snapshot manifest's blake3 of `mdbx.dat`.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const HttpTransport = @import("http_transport.zig").HttpTransport;
const import = base.execution.import;
const mdbx = import.mdbx;
const json = std.json;
const assert = std.debug.assert;

const Hash = [32]u8;

const usage =
    \\usage: base snapshot-import --db <path/mdbx.dat> [--chain base-sepolia|base-mainnet]
    \\                            [--rpc <url>] [--state-root <hex>] [--blake3 <hex>]
    \\
;

const Flags = struct {
    db: ?[]const u8 = null,
    rpc: []const u8 = "https://sepolia.base.org",
    state_root: ?Hash = null,
    blake3: ?Hash = null,
};

fn parse_hash(value: []const u8) !Hash {
    const text = if (std.mem.startsWith(u8, value, "0x")) value[2..] else value;
    if (text.len != 64) return error.InvalidArguments;
    var hash: Hash = undefined;
    _ = try std.fmt.hexToBytes(&hash, text);
    return hash;
}

fn parse(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (index + 1 >= args.len) return error.InvalidArguments;
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, arg, "--db")) {
            flags.db = value;
        } else if (std.mem.eql(u8, arg, "--rpc")) {
            flags.rpc = value;
        } else if (std.mem.eql(u8, arg, "--chain")) {
            if (std.mem.eql(u8, value, "base-sepolia")) {
                flags.rpc = "https://sepolia.base.org";
            } else if (std.mem.eql(u8, value, "base-mainnet")) {
                flags.rpc = "https://mainnet.base.org";
            } else return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--state-root")) {
            flags.state_root = try parse_hash(value);
        } else if (std.mem.eql(u8, arg, "--blake3")) {
            flags.blake3 = try parse_hash(value);
        } else return error.InvalidArguments;
    }
    if (flags.db == null) return error.InvalidArguments;
    return flags;
}

/// `mdbx.Source` over a file, through `std.Io`.
const FileSource = struct {
    io: Io,
    file: Io.File,
    reads: u64 = 0,

    fn source(self: *FileSource) mdbx.Source {
        return .{ .context = self, .read = read };
    }

    fn read(context: *anyopaque, offset: u64, buffer: []u8) error{ReadFailed}!void {
        const self: *FileSource = @ptrCast(@alignCast(context));
        const done = self.file.readPositionalAll(self.io, buffer, offset) catch {
            return error.ReadFailed;
        };
        if (done != buffer.len) return error.ReadFailed;
        self.reads += 1;
    }
};

/// `hashed_state.EntrySource` over an MDBX cursor.
const CursorEntries = struct {
    cursor: mdbx.Cursor,
    /// The longest run of entries under one key (the largest storage trie, for DUPSORT).
    run_key: Hash = @splat(0),
    run_length: u64 = 0,
    run_max: u64 = 0,
    run_max_key: Hash = @splat(0),

    fn source(self: *CursorEntries) import.hashed_state.EntrySource {
        return .{ .context = self, .next = next };
    }

    fn next(context: *anyopaque) anyerror!?import.hashed_state.Entry {
        const self: *CursorEntries = @ptrCast(@alignCast(context));
        const entry = try self.cursor.next() orelse return null;
        if (entry.key.len == 32) {
            if (std.mem.eql(u8, entry.key, &self.run_key)) {
                self.run_length += 1;
            } else {
                self.run_key = entry.key[0..32].*;
                self.run_length = 1;
            }
            if (self.run_length > self.run_max) {
                self.run_max = self.run_length;
                self.run_max_key = self.run_key;
            }
        }
        assert(self.run_length <= self.cursor.entries);
        return .{ .key = entry.key, .value = entry.value };
    }
};

/// The value at `key` in a small table (a linear scan), copied into `out`.
fn lookup(
    gpa: std.mem.Allocator,
    reader: *mdbx.Reader,
    table: []const u8,
    key: []const u8,
    out: []u8,
) !?[]u8 {
    const tree = reader.table(gpa, table) catch |err| switch (err) {
        error.NoTable => return null,
        else => return err,
    };
    var cursor = try mdbx.Cursor.init(gpa, reader, &tree);
    defer cursor.deinit(gpa);
    while (try cursor.next()) |entry| {
        if (!std.mem.eql(u8, entry.key, key)) continue;
        if (entry.value.len > out.len) return error.ValueTooLarge;
        @memcpy(out[0..entry.value.len], entry.value);
        return out[0..entry.value.len];
    }
    return null;
}

const Progress = struct {
    io: Io,
    builder: *const import.StateRootBuilder,
    source: *const FileSource,
    started_ms: i64,

    fn report(context: *anyopaque, stats: *const import.state_root.Stats) void {
        const self: *Progress = @ptrCast(@alignCast(context));
        const elapsed_ms = @max(Io.Clock.awake.now(self.io).toMilliseconds() - self.started_ms, 1);
        const key = self.builder.last_account orelse @as(Hash, @splat(0));
        // The hashed keys are uniform, so the key prefix is the fraction of accounts done.
        const prefix: f64 = @floatFromInt(std.mem.readInt(u16, key[0..2], .big));
        std.debug.print("  {d} accounts, {d} slots, {d} storage accounts, key {x}.. " ++
            "({d:.2}% of key space), {d:.0} accounts/s, {d} reads\n", .{
            stats.accounts,
            stats.slots,
            stats.storage_accounts,
            key[0..4],
            prefix / 655.36,
            @as(f64, @floatFromInt(stats.accounts)) * 1000 / @as(f64, @floatFromInt(elapsed_ms)),
            self.source.reads,
        });
    }
};

/// The state root in the header of block `number`, bound to the block hash.
fn header_state_root(init: std.process.Init, url: []const u8, number: u64) !Hash {
    const gpa = init.gpa;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var http: HttpTransport = .init(gpa, init.io, url);
    defer http.deinit();
    http.timeout_ms = 30_000;
    const response = try arena.alloc(u8, 1 << 20);
    const body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":0," ++
        "\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x{x}\",false]}}", .{number});
    var attempt: u32 = 0;
    while (attempt < 8) : (attempt += 1) {
        if (attempt > 0) {
            const wait_ms = @as(i64, 500) << @intCast(attempt);
            try init.io.sleep(.fromMilliseconds(wait_ms), .awake);
        }
        const text = http.transport().send(body, response) catch continue;
        const value = json.parseFromSliceLeaky(json.Value, arena, text, .{}) catch continue;
        if (value != .object) continue;
        const result = value.object.get("result") orelse continue;
        if (result == .null) return error.BlockNotFound;
        var extra: [base.consensus.sources.header_json.extra_data_size_max]u8 = undefined;
        const header_text = try json.Stringify.valueAlloc(arena, result, .{});
        const decoded = try base.consensus.sources.header_json.decode(header_text, &extra);
        if (decoded.header.number != number) return error.WrongBlock;
        std.debug.print("block {d} hash {x} (header bound to its hash)\n", .{
            number,
            decoded.hash.bytes,
        });
        return decoded.header.state_root.bytes;
    }
    return error.EndpointFailed;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const gpa = init.gpa;
    const io = init.io;
    var file = try Io.Dir.cwd().openFile(io, flags.db.?, .{});
    defer file.close(io);
    var file_source: FileSource = .{ .io = io, .file = file };
    const file_bytes = try file.length(io);
    if (flags.blake3) |expected| {
        const digest = try file_blake3(init, file, file_bytes);
        if (!std.mem.eql(u8, &digest, &expected)) {
            std.debug.print("BLAKE3 MISMATCH: file {x}, manifest {x}\n", .{ digest, expected });
            return 1;
        }
        std.debug.print("blake3 matches the manifest: {x}\n", .{digest});
    }
    var reader = try mdbx.Reader.open(gpa, file_source.source(), file_bytes, .{});
    defer reader.deinit(gpa);
    std.debug.print("{s}: {d} bytes, page {d}, txnid {d}\n", .{
        flags.db.?,
        file_bytes,
        reader.meta.page_size,
        reader.meta.txnid,
    });
    var buffer: [4096]u8 = undefined;
    const settings = try lookup(gpa, &reader, "Metadata", "storage_settings", &buffer);
    std.debug.print("storage settings: {s}\n", .{settings orelse "(none: storage v1)"});
    const finish = try lookup(gpa, &reader, "StageCheckpoints", "Finish", &buffer) orelse {
        std.debug.print("no Finish stage checkpoint\n", .{});
        return 1;
    };
    const number = try import.reth.decode_stage_block(finish);
    std.debug.print("snapshot block (Finish checkpoint): {d}\n", .{number});
    const expected = flags.state_root orelse try header_state_root(init, flags.rpc, number);
    std.debug.print("expected state root {x}\n", .{expected});
    try code_stats(gpa, &reader);
    const root = try compute(init, &reader, &file_source);
    if (!std.mem.eql(u8, &root, &expected)) {
        std.debug.print("STATE ROOT MISMATCH: computed {x}, header {x}\n", .{ root, expected });
        return 1;
    }
    std.debug.print("state root matches block {d}: {x}\n", .{ number, root });
    return 0;
}

/// The blake3 of the whole file, read sequentially.
fn file_blake3(init: std.process.Init, file: Io.File, file_bytes: u64) !Hash {
    const buffer = try init.gpa.alloc(u8, 8 << 20);
    defer init.gpa.free(buffer);
    var hasher = std.crypto.hash.Blake3.init(.{});
    var offset: u64 = 0;
    const report_bytes: u64 = 32 << 30;
    while (offset < file_bytes) {
        const want: usize = @intCast(@min(buffer.len, file_bytes - offset));
        const done = try file.readPositionalAll(init.io, buffer[0..want], offset);
        if (done != want) return error.FileChanged;
        hasher.update(buffer[0..want]);
        offset += want;
        if (offset % report_bytes == 0) {
            std.debug.print("  blake3: {d} of {d} GiB\n", .{ offset >> 30, file_bytes >> 30 });
        }
    }
    assert(offset == file_bytes);
    var digest: Hash = undefined;
    hasher.final(&digest);
    return digest;
}

fn compute(init: std.process.Init, reader: *mdbx.Reader, source: *const FileSource) !Hash {
    const gpa = init.gpa;
    const account_tree = try reader.table(gpa, "HashedAccounts");
    const storage_tree = try reader.table(gpa, "HashedStorages");
    if (account_tree.dupsort() or !storage_tree.dupsort()) return error.UnexpectedTableFlags;
    std.debug.print("HashedAccounts: {d} items, HashedStorages: {d} items\n", .{
        account_tree.items,
        storage_tree.items,
    });
    var accounts: CursorEntries = .{ .cursor = try .init(gpa, reader, &account_tree) };
    defer accounts.cursor.deinit(gpa);
    var storages: CursorEntries = .{ .cursor = try .init(gpa, reader, &storage_tree) };
    defer storages.cursor.deinit(gpa);
    const builder = try gpa.create(import.StateRootBuilder);
    defer gpa.destroy(builder);
    builder.* = .{};
    var progress: Progress = .{
        .io = init.io,
        .builder = builder,
        .source = source,
        .started_ms = Io.Clock.awake.now(init.io).toMilliseconds(),
    };
    const root = try import.hashed_state.compute(
        builder,
        accounts.source(),
        storages.source(),
        .{ .context = &progress, .report = Progress.report },
        null,
    );
    Progress.report(&progress, &builder.stats);
    // Every table item was consumed: the tree counts agree with what was streamed.
    if (accounts.cursor.entries != account_tree.items) return error.ItemCountMismatch;
    if (storages.cursor.entries != storage_tree.items) return error.ItemCountMismatch;
    assert(builder.stats.accounts == account_tree.items);
    std.debug.print("largest storage trie: {d} slots (account hash {x})\n", .{
        storages.run_max,
        storages.run_max_key,
    });
    return root;
}

/// Counts `Bytecodes` and checks every code against its key (keccak256 of the code).
fn code_stats(gpa: std.mem.Allocator, reader: *mdbx.Reader) !void {
    const tree = try reader.table(gpa, "Bytecodes");
    var cursor = try mdbx.Cursor.init(gpa, reader, &tree);
    defer cursor.deinit(gpa);
    var codes: u64 = 0;
    var code_bytes: u64 = 0;
    var code_bytes_max: u64 = 0;
    while (try cursor.next()) |entry| {
        if (entry.key.len != 32) return error.Corrupt;
        const code = try import.reth.decode_bytecode(entry.value);
        const hash = base.execution.trie.node.keccak256(code);
        if (!std.mem.eql(u8, &hash, entry.key)) return error.CodeHashMismatch;
        codes += 1;
        code_bytes += code.len;
        code_bytes_max = @max(code_bytes_max, code.len);
    }
    if (codes != tree.items) return error.ItemCountMismatch;
    std.debug.print("Bytecodes: {d} codes, {d} bytes ({d} MiB), largest {d} bytes, " ++
        "every hash checked\n", .{ codes, code_bytes, code_bytes >> 20, code_bytes_max });
}

//! `base snapshot-import --out <path>`: imports a reth state database into a needlefish
//! disk-mode database file in one pass (`execution.import.to_disk`), then reopens it and checks
//! the head, the root, and a sample of accounts and slots read through the trie.
//!
//! Head N comes from `StageCheckpoints["Finish"]`; headers N-255..N come from `--rpc` (or
//! `--headers <file>`: one `eth_getBlockByNumber` result object per line), each bound to its
//! hash by `header_json`, and must link by parent hash. The state root must equal header N's.
//! `--test-head` (test-only, needs `--state-root`) skips headers: the head and its 255
//! ancestors get synthetic hashes, so the file opens but must not execute real blocks.
//!
//! Sizing comes from the MDBX counts (`to_disk.sizing`); the counts are written next to the
//! database as `<path>.counts` (`to_disk.Counts.encode`), and every open must size from them.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const base = @import("base");

const snapshot_import = @import("snapshot_import.zig");
const HttpTransport = @import("http_transport.zig").HttpTransport;

const import = base.execution.import;
const to_disk = import.to_disk;
const mdbx = import.mdbx;
const header_json = base.consensus.sources.header_json;
const json = std.json;
const assert = std.debug.assert;

const IO = base.utilities.io.IO;
const Storage = base.execution.db.storage.IoStorageType(IO);
const Importer = to_disk.ImporterType(Storage);
const Database = Importer.Database;
const Hash = [32]u8;

pub const Options = struct {
    out: []const u8,
    rpc: []const u8,
    headers: ?[]const u8,
    test_head: bool,
    state_root: ?Hash,
    /// High 64 bits of the format id (the chain's genesis hash prefix, as the node's).
    genesis_hash: Hash,
};

/// How long one storage tick lets IO run (a busy loader or a checkpoint waits in these).
const tick_ns: u64 = 50 * std.time.ns_per_us;
const headers_file_bytes_max = 64 << 20;

pub fn run(init: std.process.Init, options: Options, reader: *mdbx.Reader, number: u64) !u8 {
    const io = init.io;
    if (Io.Dir.cwd().access(io, options.out, .{})) |_| {
        std.debug.print("{s} exists; refusing to overwrite it\n", .{options.out});
        return 1;
    } else |_| {}
    const chain = try init.gpa.create(to_disk.HeaderChain);
    defer init.gpa.destroy(chain);
    try head_chain(init, options, number, chain);
    const expected = chain.head().state_root;
    if (options.state_root) |root| {
        if (!std.mem.eql(u8, &root, &expected)) {
            std.debug.print("--state-root {x} is not header {d}'s {x}\n", .{
                root,
                number,
                expected,
            });
            return 1;
        }
    }
    std.debug.print("expected state root {x}\n", .{expected});
    const counts = try counts_of(init.gpa, reader);
    const sizing = to_disk.sizing(Storage, counts, to_disk.shape_node) catch |err| {
        std.debug.print("cannot size the database: {t} (codes need u64 limits: plan step 9)\n", .{
            err,
        });
        return 1;
    };
    print_sizing(&sizing);
    var backend = try backend_init();
    defer backend.deinit();
    const samples = try init.gpa.create(to_disk.Samples);
    defer init.gpa.destroy(samples);
    const format_id = @as(u128, std.mem.readInt(u64, options.genesis_hash[0..8], .big)) << 64 |
        number;
    write(init, &backend, options.out, reader, &sizing, chain, format_id, samples) catch |err| {
        std.debug.print("IMPORT FAILED: {t}; delete {s} and import again\n", .{ err, options.out });
        return 1;
    };
    const counts_path = try std.fmt.allocPrint(init.gpa, "{s}.counts", .{options.out});
    defer init.gpa.free(counts_path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = counts_path, .data = &counts.encode() });
    std.debug.print("wrote {s} and {s}\n", .{ options.out, counts_path });
    return reopen(init, &backend, options.out, counts_path, chain, samples);
}

fn backend_init() !IO {
    return if (builtin.os.tag == .linux) IO.init(.{}) else IO.init();
}

fn head_chain(
    init: std.process.Init,
    options: Options,
    number: u64,
    chain: *to_disk.HeaderChain,
) !void {
    if (options.test_head) {
        std.debug.print("TEST-ONLY head: synthetic block hashes (do not execute blocks)\n", .{});
        var headers: to_disk.SyntheticHeaders = .{
            .head_number = number,
            .state_root = options.state_root.?,
        };
        return to_disk.fetch_chain(headers.source(), number, chain);
    }
    if (options.headers) |path| {
        var headers = try FileHeaders.load(init, path);
        defer headers.deinit(init.gpa);
        try to_disk.fetch_chain(headers.source(), number, chain);
    } else {
        var headers: RpcHeaders = .init(init, options.rpc);
        defer headers.deinit();
        try to_disk.fetch_chain(headers.source(), number, chain);
    }
    std.debug.print("headers {d}..{d} link by parent hash; block {d} hash {x}\n", .{
        number + 1 - chain.len,
        number,
        number,
        chain.head().hash,
    });
}

fn link_of(decoded: *const header_json.Decoded) to_disk.HeaderLink {
    return .{
        .number = decoded.header.number,
        .hash = decoded.hash.bytes,
        .parent_hash = decoded.header.parent_hash.bytes,
        .timestamp = decoded.header.timestamp,
        .state_root = decoded.header.state_root.bytes,
    };
}

/// Headers over JSON-RPC (`eth_getBlockByNumber`), each decoded and bound to its hash.
const RpcHeaders = struct {
    io: Io,
    http: HttpTransport,
    arena: std.heap.ArenaAllocator,

    fn init(process: std.process.Init, url: []const u8) RpcHeaders {
        var http: HttpTransport = .init(process.gpa, process.io, url);
        http.timeout_ms = 30_000;
        return .{ .io = process.io, .http = http, .arena = .init(process.gpa) };
    }

    fn deinit(self: *RpcHeaders) void {
        self.arena.deinit();
        self.http.deinit();
    }

    fn source(self: *RpcHeaders) to_disk.HeaderSource {
        return .{ .context = self, .fetch = fetch };
    }

    fn fetch(context: *anyopaque, number: u64) anyerror!to_disk.HeaderLink {
        const self: *RpcHeaders = @ptrCast(@alignCast(context));
        _ = self.arena.reset(.retain_capacity);
        const arena = self.arena.allocator();
        const response = try arena.alloc(u8, 1 << 20);
        const body = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":0," ++
            "\"method\":\"eth_getBlockByNumber\",\"params\":[\"0x{x}\",false]}}", .{number});
        var attempt: u32 = 0;
        while (attempt < 8) : (attempt += 1) {
            if (attempt > 0) {
                const wait_ms = @as(i64, 500) << @intCast(attempt);
                try self.io.sleep(.fromMilliseconds(wait_ms), .awake);
            }
            const text = self.http.transport().send(body, response) catch continue;
            const value = json.parseFromSliceLeaky(json.Value, arena, text, .{}) catch continue;
            if (value != .object) continue;
            const result = value.object.get("result") orelse continue;
            if (result == .null) return error.BlockNotFound;
            const header_text = try json.Stringify.valueAlloc(arena, result, .{});
            var extra: [header_json.extra_data_size_max]u8 = undefined;
            const decoded = try header_json.decode(header_text, &extra);
            return link_of(&decoded);
        }
        return error.EndpointFailed;
    }
};

/// Headers from a file: one block object (an `eth_getBlockByNumber` result) per line.
const FileHeaders = struct {
    links: []to_disk.HeaderLink,

    fn load(init: std.process.Init, path: []const u8) !FileHeaders {
        const gpa = init.gpa;
        const limit: Io.Limit = .limited(headers_file_bytes_max);
        const text = try Io.Dir.cwd().readFileAlloc(init.io, path, gpa, limit);
        defer gpa.free(text);
        var links: std.ArrayList(to_disk.HeaderLink) = .empty;
        errdefer links.deinit(gpa);
        var lines = std.mem.tokenizeScalar(u8, text, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \r\t");
            if (trimmed.len == 0) continue;
            var extra: [header_json.extra_data_size_max]u8 = undefined;
            const decoded = try header_json.decode(trimmed, &extra);
            try links.append(gpa, link_of(&decoded));
        }
        return .{ .links = try links.toOwnedSlice(gpa) };
    }

    fn deinit(self: *FileHeaders, gpa: std.mem.Allocator) void {
        gpa.free(self.links);
    }

    fn source(self: *FileHeaders) to_disk.HeaderSource {
        return .{ .context = self, .fetch = fetch };
    }

    fn fetch(context: *anyopaque, number: u64) anyerror!to_disk.HeaderLink {
        const self: *FileHeaders = @ptrCast(@alignCast(context));
        for (self.links) |link| {
            if (link.number == number) return link;
        }
        return error.BlockNotFound;
    }
};

fn counts_of(gpa: std.mem.Allocator, reader: *mdbx.Reader) !to_disk.Counts {
    const codes = try snapshot_import.code_stats(gpa, reader);
    const account_tree = try reader.table(gpa, "HashedAccounts");
    const storage_tree = try reader.table(gpa, "HashedStorages");
    if (account_tree.dupsort() or !storage_tree.dupsort()) return error.UnexpectedTableFlags;
    return .{
        .accounts = account_tree.items,
        .slots = storage_tree.items,
        .codes = codes.count,
        .code_bytes = codes.bytes,
    };
}

fn print_sizing(sizing: *const to_disk.Sizing) void {
    const config = &sizing.config;
    const block_size = config.engine.checkpoint_block_size;
    std.debug.print("sizing: {d} accounts, {d} slots, {d} codes ({d} MiB); branch records " ++
        "sized for {d} account-trie, {d} storage-trie\n", .{
        sizing.counts.accounts,
        sizing.counts.slots,
        sizing.counts.codes,
        sizing.counts.code_bytes >> 20,
        sizing.account_branches_max,
        sizing.storage_branches_max,
    });
    std.debug.print("sizing: trees ~{d} MiB, code tables ~{d} MiB; grid {d} blocks of {d} KiB " ++
        "({d} MiB, sparse); file {d} MiB; checkpoint staging {d} MiB, zone {d} MiB; " ++
        "code arena {d} MiB, {d} code tables max\n", .{
        sizing.tree_blocks * block_size >> 20,
        sizing.code_blocks * block_size >> 20,
        config.engine.grid_block_count,
        block_size >> 10,
        config.engine.grid_block_count * block_size >> 20,
        config.engine.size_bytes() >> 20,
        config.checkpoint_staging_bytes >> 20,
        config.engine.checkpoint_zone_size_bytes >> 20,
        config.state.code_bytes_max >> 20,
        config.code_tables_max,
    });
}

/// Storage ticks: let IO run briefly, then deliver completions.
const Ticker = struct {
    backend: *IO,
    storage: *Storage,

    fn driver(self: *Ticker) to_disk.Driver {
        return .{ .context = self, .tick = tick };
    }

    fn tick(context: *anyopaque) void {
        const self: *Ticker = @ptrCast(@alignCast(context));
        self.backend.run_for_ns(tick_ns) catch |err| {
            std.debug.panic("snapshot-import: io: {t}", .{err});
        };
        self.storage.tick();
    }
};

const Progress = struct {
    io: Io,
    started_ms: i64,
    block_size: u32,

    fn report(context: *anyopaque, stats: *const to_disk.Stats) void {
        const self: *Progress = @ptrCast(@alignCast(context));
        const now_ms = Io.Clock.awake.now(self.io).toMilliseconds();
        const elapsed: f64 = @floatFromInt(@max(now_ms - self.started_ms, 1));
        const accounts: f64 = @floatFromInt(stats.accounts);
        const slots: f64 = @floatFromInt(stats.slots);
        std.debug.print("  {d} accounts ({d:.0}/s), {d} slots ({d:.0}/s), {d} + {d} records, " ++
            "{d} MiB written, {d} busy ticks, {d:.0} s\n", .{
            stats.accounts,
            accounts * 1000 / elapsed,
            stats.slots,
            slots * 1000 / elapsed,
            stats.account_records,
            stats.storage_records,
            stats.blocks_written * self.block_size >> 20,
            stats.busy_ticks,
            elapsed / 1000,
        });
    }
};

/// The open storage file and the database over it (pinned: heap-allocated).
const Opened = struct {
    fd: IO.Fd,
    storage: *Storage,
    db: *Database,

    fn init(
        gpa: std.mem.Allocator,
        backend: *IO,
        path: []const u8,
        config: base.execution.db.database.Config,
    ) !Opened {
        const fd = try backend.open_file(path, .create);
        errdefer backend.close_now(fd);
        const storage = try gpa.create(Storage);
        errdefer gpa.destroy(storage);
        const options: base.execution.db.storage.io_storage.Options = .{
            .size_bytes = config.engine.size_bytes(),
        };
        storage.* = try Storage.init(gpa, backend, fd, options);
        errdefer storage.deinit(gpa);
        const db = try gpa.create(Database);
        errdefer gpa.destroy(db);
        db.* = try Database.init(gpa, storage, config);
        return .{ .fd = fd, .storage = storage, .db = db };
    }

    fn deinit(self: *Opened, gpa: std.mem.Allocator, backend: *IO) void {
        self.db.deinit(gpa);
        gpa.destroy(self.db);
        self.storage.deinit(gpa);
        gpa.destroy(self.storage);
        backend.close_now(self.fd);
    }
};

fn write(
    init: std.process.Init,
    backend: *IO,
    path: []const u8,
    reader: *mdbx.Reader,
    sizing: *const to_disk.Sizing,
    chain: *const to_disk.HeaderChain,
    format_id: u128,
    samples: *to_disk.Samples,
) !void {
    const gpa = init.gpa;
    var opened = try Opened.init(gpa, backend, path, sizing.config);
    defer opened.deinit(gpa, backend);
    var ticker: Ticker = .{ .backend = backend, .storage = opened.storage };
    var progress: Progress = .{
        .io = init.io,
        .started_ms = Io.Clock.awake.now(init.io).toMilliseconds(),
        .block_size = sizing.config.engine.checkpoint_block_size,
    };
    var importer: Importer = .{
        .allocator = gpa,
        .db = opened.db,
        .driver = ticker.driver(),
        .progress = .{ .context = &progress, .report = Progress.report },
    };
    var cursors = try Cursors.init(gpa, reader);
    defer cursors.deinit(gpa);
    const root = try importer.run(
        format_id,
        cursors.codes.source(),
        cursors.accounts.source(),
        cursors.storages.source(),
        chain,
    );
    try cursors.check_consumed();
    samples.* = importer.samples;
    std.debug.print("imported block {d}: root {x} (trees resolve it), {d} codes, " ++
        "{d} account-trie and {d} storage-trie records, {d} MiB of tables, checkpoint written\n", .{
        chain.head().number,
        root,
        importer.stats.codes,
        importer.stats.account_records,
        importer.stats.storage_records,
        importer.stats.blocks_written * sizing.config.engine.checkpoint_block_size >> 20,
    });
}

/// MDBX cursors over the three tables the import reads.
const Cursors = struct {
    codes: snapshot_import.CursorEntries,
    accounts: snapshot_import.CursorEntries,
    storages: snapshot_import.CursorEntries,
    code_items: u64,
    account_items: u64,
    storage_items: u64,

    fn init(gpa: std.mem.Allocator, reader: *mdbx.Reader) !Cursors {
        const code_tree = try reader.table(gpa, "Bytecodes");
        const account_tree = try reader.table(gpa, "HashedAccounts");
        const storage_tree = try reader.table(gpa, "HashedStorages");
        var codes: snapshot_import.CursorEntries = .{
            .cursor = try .init(gpa, reader, &code_tree),
        };
        errdefer codes.cursor.deinit(gpa);
        var accounts: snapshot_import.CursorEntries = .{
            .cursor = try .init(gpa, reader, &account_tree),
        };
        errdefer accounts.cursor.deinit(gpa);
        const storages: snapshot_import.CursorEntries = .{
            .cursor = try .init(gpa, reader, &storage_tree),
        };
        return .{
            .codes = codes,
            .accounts = accounts,
            .storages = storages,
            .code_items = code_tree.items,
            .account_items = account_tree.items,
            .storage_items = storage_tree.items,
        };
    }

    fn deinit(self: *Cursors, gpa: std.mem.Allocator) void {
        self.storages.cursor.deinit(gpa);
        self.accounts.cursor.deinit(gpa);
        self.codes.cursor.deinit(gpa);
    }

    /// Every table item was streamed: the counts agree with the table descriptors.
    fn check_consumed(self: *const Cursors) !void {
        if (self.codes.cursor.entries != self.code_items) return error.ItemCountMismatch;
        if (self.accounts.cursor.entries != self.account_items) return error.ItemCountMismatch;
        if (self.storages.cursor.entries != self.storage_items) return error.ItemCountMismatch;
    }
};

/// Opens the written file again with the sizing from its counts record, and checks the
/// head, its root, the block hashes, and the samples (read through the trie).
/// Hashes every code the reopened state holds (loaded from the code tables at their arena
/// offsets, which pass 4 GiB at snapshot scale) and returns how many there are.
fn check_codes(state: *const base.execution.db.State) error{CodeHashMismatch}!u64 {
    var count: u64 = 0;
    var codes = state.code_table.iterator();
    while (codes.next()) |entry| : (count += 1) {
        const code = state.code_by_hash(entry.key_ptr.*).?;
        assert(code.len == entry.value_ptr.len);
        var hash: Hash = undefined;
        std.crypto.hash.sha3.Keccak256.hash(code, &hash, .{});
        if (!std.mem.eql(u8, &hash, entry.key_ptr)) return error.CodeHashMismatch;
    }
    assert(count == state.code_table.count());
    return count;
}

fn reopen(
    init: std.process.Init,
    backend: *IO,
    path: []const u8,
    counts_path: []const u8,
    chain: *const to_disk.HeaderChain,
    samples: *const to_disk.Samples,
) !u8 {
    const gpa = init.gpa;
    var buffer: [to_disk.Counts.encoded_size]u8 = undefined;
    const bytes = try Io.Dir.cwd().readFile(init.io, counts_path, &buffer);
    const counts = try to_disk.Counts.decode(bytes);
    const sizing = try to_disk.sizing(Storage, counts, to_disk.shape_node);
    var opened = try Opened.init(gpa, backend, path, sizing.config);
    defer opened.deinit(gpa, backend);
    var ticker: Ticker = .{ .backend = backend, .storage = opened.storage };
    try Importer.open(opened.db, ticker.driver());
    const head = opened.db.head_info;
    const expected = chain.head();
    std.debug.print("reopened: head {d} hash {x}, state root {x}, {d} stored blocks\n", .{
        head.number,
        head.hash,
        head.state_root,
        opened.db.chain.block_count(),
    });
    if (!head.present or head.number != expected.number or
        !std.mem.eql(u8, &head.hash, &expected.hash) or
        !std.mem.eql(u8, &head.state_root, &expected.state_root))
    {
        std.debug.print("SELF-CHECK FAILED: the head is not block {d}\n", .{expected.number});
        return 1;
    }
    for (chain.links[0..chain.len]) |*link| {
        const hash = opened.db.state.block_hash(link.number) orelse return error.NoBlockHash;
        if (!std.mem.eql(u8, &hash, &link.hash)) return error.BlockHashMismatch;
    }
    const codes = check_codes(&opened.db.state) catch |err| {
        std.debug.print("SELF-CHECK FAILED: codes: {t}\n", .{err});
        return 1;
    };
    if (codes != counts.codes) {
        std.debug.print("SELF-CHECK FAILED: {d} codes reopened, {d} imported\n", .{
            codes,
            counts.codes,
        });
        return 1;
    }
    std.debug.print("self-check: {d} codes reopened from the code tables, every hash " ++
        "matches\n", .{codes});
    Importer.verify_samples(opened.db, samples) catch |err| {
        std.debug.print("SELF-CHECK FAILED: samples: {t}\n", .{err});
        return 1;
    };
    std.debug.print("self-check: root record resolves, {d} block hashes, {d} accounts and " ++
        "{d} slots read through the trie match\n", .{
        chain.len,
        samples.account_list().len,
        samples.slot_list().len,
    });
    return 0;
}

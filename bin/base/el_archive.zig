//! el-run's archive (`--archive <file>`, `--archive.size-gb <n>`): the node's history on
//! disk (`execution.archive`), a window of the most recent blocks bounded by the file's
//! size, read by the JSON-RPC server (`el_rpc.History`).
//!
//! Per committed block it appends the block's record (header, transactions, receipts: the
//! RPC ring's encoding), its transaction hashes, and the value before the block of every
//! key the block wrote: account records and branch records from the disk state's history
//! capture (`DiskState.capture_enable`), slots from the block's changeset. State at an
//! older block N is then read through a view (`DiskState.view_begin`): the trie from N's
//! state root, each key's value from the first archived block after N that changed it,
//! else the head's. Every RPC state read, proofs and `eth_call` included, goes through it.
//!
//! The archive never stops the node: a block whose capture is unusable (a pre-state
//! record that could not be rebuilt) or that does not fit restarts the window at the next
//! block. At startup the archive is cut back to the database head (`Archive.rebase`); when
//! it ends below it, it restarts (the blocks in between were executed without it).
//!
//! The archive file has its own completion IO: its writes are waited for inside `on_block`
//! (one sequential write per block, synced every `sync_blocks`), its reads are synchronous.

const std = @import("std");
const base = @import("base");
const el_rpc = @import("el_rpc.zig");

const io_module = base.utilities.io;
const archive_module = base.execution.archive;
const db = base.execution.db;
const branch_record = db.branch_record;
const flat_trees = db.flat_trees;
const disk_state = db.disk_state;
const keccak256 = base.execution.trie.node.keccak256;
const assert = std.debug.assert;

const IO = io_module.IO;
const Storage = db.storage.IoStorageType(IO);
const Database = base.execution.import.to_disk.ImporterType(Storage).Database;
pub const Archive = archive_module.ArchiveType(Storage);
const Hash = [32]u8;

/// Base mainnet blocks carry ~650 keys (about 30 accounts, 180 slots, 400 trie records,
/// 20 transactions): a segment fills its entries in about 6,400 blocks (21 minutes).
pub const config: archive_module.Config = .{
    .segment_blocks = 8192,
    .segment_entries_max = 1 << 22,
    .segments_max = 1024,
    // A block of 160M gas: 65,536 record writes of up to 1,077 bytes, plus its record.
    .unit_bytes_max = 160 << 20,
    // ~16 bits per distinct key of a full segment: a false positive about once per 2,000.
    .filter_bytes = 4 << 20,
    .sync_blocks = 64,
};

pub const Flags = struct {
    path: ?[]const u8 = null,
    size_gib: u32 = 512,

    /// Parses one `--archive*` flag; false when `name` is not one.
    pub fn parse(flags: *Flags, name: []const u8, value: []const u8) error{InvalidArguments}!bool {
        if (std.mem.eql(u8, name, "--archive")) {
            flags.path = value;
        } else if (std.mem.eql(u8, name, "--archive.size-gb")) {
            flags.size_gib = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
            if (flags.size_gib < 8 or flags.size_gib > 64 * 1024) return error.InvalidArguments;
        } else return false;
        assert(std.mem.startsWith(u8, name, "--archive"));
        return true;
    }
};

const Kind = archive_module.Kind;

pub const Service = struct {
    io: IO,
    fd: IO.Fd,
    storage: Storage,
    archive: Archive,
    db: *Database,
    /// The decoded changeset of the block being appended (its slots' old values).
    changeset: db.Changeset,
    changes: []archive_module.Change,
    /// Keys and old words the changes borrow (slot keys, record keys, slot words).
    keys: [][65]u8,
    words: [][32]u8,
    hashes: []Hash,
    /// The capture sequence of the last block appended.
    last_sequence: u64 = 0,
    /// The block a view shows (`view_begin`).
    view_number: u64 = 0,
    restarts: u64 = 0,
    /// Time `on_block` held the tip (collect, append, sync), measured by el-run.
    append_us_sum: u64 = 0,
    append_us_max: u64 = 0,

    /// Opens (or creates) the archive file, enables the disk state's capture, and cuts the
    /// archive back to the database head. Null without `--archive`.
    pub fn start(gpa: std.mem.Allocator, flags: *const Flags, database: *Database) !?*Service {
        const path = flags.path orelse return null;
        const disk = &(database.disk orelse return error.ArchiveNeedsDiskState);
        const service = try gpa.create(Service);
        errdefer gpa.destroy(service);
        service.io = if (@import("builtin").os.tag == .linux) try IO.init(.{}) else try IO.init();
        errdefer service.io.deinit();
        service.fd = try service.io.open_file(path, .create);
        errdefer service.io.close_now(service.fd);
        const size_bytes = @as(u64, flags.size_gib) << 30;
        const options: db.storage.io_storage.Options = .{ .size_bytes = size_bytes };
        service.storage = try Storage.init(gpa, &service.io, service.fd, options);
        errdefer service.storage.deinit(gpa);
        service.archive = try Archive.init(gpa, &service.storage, config);
        errdefer service.archive.deinit(gpa);
        try service.buffers_init(gpa, database);
        try service.archive.load();
        const head = database.head_info;
        switch (try service.archive.rebase(head.number, head.hash)) {
            .aligned, .empty => {},
            .behind => try service.archive.reset(),
        }
        try disk.capture_enable(gpa);
        service.last_sequence = 0;
        std.debug.print("el-run: archive {s} ({d} GiB): blocks {?d}..{?d}\n", .{
            path, flags.size_gib, service.archive.oldest(), service.archive.head,
        });
        return service;
    }

    fn buffers_init(service: *Service, gpa: std.mem.Allocator, database: *Database) !void {
        const changeset_config = database.config.changeset;
        const records_max = database.config.disk_state.?.record_writes_max;
        const keys_max = changeset_config.storage_max + records_max;
        const changes_max = changeset_config.accounts_max + keys_max;
        service.db = database;
        service.changeset = try db.Changeset.init(gpa, changeset_config);
        errdefer service.changeset.deinit(gpa);
        const lazy = base.utilities.lazy_alloc;
        service.changes = try lazy.alloc(gpa, archive_module.Change, changes_max);
        service.keys = try lazy.alloc(gpa, [65]u8, keys_max);
        service.words = try lazy.alloc(gpa, [32]u8, changeset_config.storage_max);
        service.hashes = try lazy.alloc(gpa, Hash, 1 << 16);
        service.view_number = 0;
        service.restarts = 0;
    }

    pub fn destroy(service: *Service, gpa: std.mem.Allocator) void {
        service.archive.flush() catch |err| {
            std.debug.print("el-run: archive flush failed: {t}\n", .{err});
        };
        const lazy = base.utilities.lazy_alloc;
        lazy.free(gpa, service.hashes);
        lazy.free(gpa, service.words);
        lazy.free(gpa, service.keys);
        lazy.free(gpa, service.changes);
        service.changeset.deinit(gpa);
        service.archive.deinit(gpa);
        service.storage.deinit(gpa);
        service.io.close_now(service.fd);
        service.io.deinit();
        gpa.destroy(service);
    }

    /// The per-block hook, right after the block committed: appends it with the values
    /// its writes replaced. `changeset` is the block's encoded changeset.
    pub fn on_block(
        service: *Service,
        number: u64,
        hash: Hash,
        parent_hash: Hash,
        record: []const u8,
        transactions: []const []const u8,
        changeset: []const u8,
    ) void {
        assert(service.db.head_info.number == number);
        service.append(number, hash, parent_hash, record, transactions, changeset) catch |err| {
            service.restart(number, err);
        };
    }

    fn restart(service: *Service, number: u64, err: anyerror) void {
        service.restarts += 1;
        std.debug.print("el-run: archive: block {d} not archived ({t}); the window " ++
            "restarts at the next block\n", .{ number, err });
        service.archive.reset() catch |reset_err| {
            std.debug.print("el-run: archive reset failed: {t}\n", .{reset_err});
        };
    }

    fn append(
        service: *Service,
        number: u64,
        hash: Hash,
        parent_hash: Hash,
        record: []const u8,
        transactions: []const []const u8,
        changeset: []const u8,
    ) !void {
        const disk = &service.db.disk.?;
        const capture = disk.capture.?;
        // The capture must describe this block: one forward apply since the last append.
        if (capture.failed) return error.CaptureFailed;
        if (!capture.forward or capture.sequence == service.last_sequence) {
            return error.CaptureStale;
        }
        service.last_sequence = capture.sequence;
        try service.changeset.decode(changeset);
        if (transactions.len > service.hashes.len) return error.BlockTooLarge;
        for (transactions, service.hashes[0..transactions.len]) |raw, *transaction_hash| {
            transaction_hash.* = keccak256(raw);
        }
        const changes = try service.collect(disk);
        try service.archive.append(&.{
            .number = number,
            .hash = hash,
            .parent_hash = parent_hash,
            .record = record,
            .transaction_hashes = service.hashes[0..transactions.len],
            .changes = changes,
        });
    }

    /// The block's writes with their old values: accounts, slots, branch records.
    fn collect(service: *Service, disk: *const Database.DiskState) ![]const archive_module.Change {
        var count: usize = 0;
        var keys: usize = 0;
        for (disk.last_account_writes()) |*write| {
            const old: ?[]const u8 = if (write.old) |*bytes| bytes else null;
            service.changes[count] = .{ .kind = .account, .key = &write.key, .old = old };
            count += 1;
        }
        const slots = service.changeset.storage_changes();
        for (slots, 0..) |*change, index| {
            const key = &service.keys[keys];
            keys += 1;
            key[0..64].* = flat_trees.storage_key(&keccak256(&change.address), change.slot);
            std.mem.writeInt(u256, &service.words[index], change.old, .big);
            const old: ?[]const u8 = if (change.old == 0) null else &service.words[index];
            service.changes[count] = .{ .kind = .slot, .key = key[0..64], .old = old };
            count += 1;
        }
        for (disk.last_record_writes()) |*write| {
            if (count == service.changes.len) return error.BlockTooLarge;
            if (keys == service.keys.len) return error.BlockTooLarge;
            const key = &service.keys[keys];
            keys += 1;
            var kind: Kind = undefined;
            var key_bytes: []const u8 = undefined;
            if (write.owner) |*owner| {
                key.* = branch_record.storage_key(owner, write.hang.slice());
                kind = .storage_branch;
                key_bytes = key[0..branch_record.storage_key_bytes];
            } else {
                key[0..branch_record.path_key_bytes].* = branch_record.path_key(write.hang.slice());
                kind = .account_branch;
                key_bytes = key[0..branch_record.path_key_bytes];
            }
            const old = disk.record_old(write);
            service.changes[count] = .{ .kind = kind, .key = key_bytes, .old = old };
            count += 1;
        }
        assert(count <= service.changes.len);
        return service.changes[0..count];
    }

    /// Idle work at the tip: seals a due segment; drives the archive's IO.
    pub fn tick(service: *Service) void {
        service.archive.tick() catch |err| service.restart(service.db.head_info.number, err);
    }

    pub fn summary(service: *const Service) void {
        const archive = &service.archive;
        const stats = &archive.stats;
        std.debug.print("archive: blocks {?d}..{?d}, {d} MiB, {d} segments, {d} blocks " ++
            "appended ({d} MiB, {d} us avg, {d} us max), {d} seals, {d} evicted segments, " ++
            "{d} restarts, {d} lookups ({d} page reads, {d} unit reads, {d} filter skips)\n", .{
            archive.oldest(),
            archive.head,
            archive.bytes_used() >> 20,
            archive.sealed_count,
            stats.blocks,
            stats.unit_bytes >> 20,
            service.append_us_sum / @max(stats.blocks, 1),
            service.append_us_max,
            stats.seals,
            stats.evictions,
            service.restarts,
            stats.lookups,
            stats.page_reads,
            stats.unit_reads,
            stats.filter_skips,
        });
    }

    // ---- el_rpc.History -------------------------------------------------------------

    pub fn history(service: *Service) el_rpc.History {
        return .{
            .context = service,
            .window_fn = window,
            .block_fn = block,
            .find_block_fn = find_block,
            .find_transaction_fn = find_transaction,
            .view_begin_fn = view_begin,
            .view_end_fn = view_end,
        };
    }

    fn of(context: *anyopaque) *Service {
        return @ptrCast(@alignCast(context));
    }

    fn window(context: *anyopaque) ?el_rpc.Window {
        const archive = &of(context).archive;
        const head = archive.head orelse return null;
        // The archive's head is the database's, or the archive is of no use for state.
        if (head != of(context).db.head_info.number) return null;
        return .{ .oldest = archive.oldest().?, .head = head };
    }

    fn block(context: *anyopaque, number: u64) anyerror!?el_rpc.Archived {
        const unit = try of(context).archive.block_at(number) orelse return null;
        const record = unit.record orelse return null;
        return .{ .hash = unit.hash, .bytes = record };
    }

    fn find_block(context: *anyopaque, hash: Hash) anyerror!?u64 {
        const location = try of(context).archive.find(.block, &hash) orelse return null;
        return location.number;
    }

    fn find_transaction(context: *anyopaque, hash: Hash) anyerror!?el_rpc.Location {
        const location = try of(context).archive.find(.transaction, &hash) orelse return null;
        return .{ .number = location.number, .index = location.aux };
    }

    fn view_begin(context: *anyopaque, number: u64, state_root: Hash) void {
        const service = of(context);
        assert(window(context) != null);
        service.view_number = number;
        service.db.disk.?.view_begin(state_root, .{ .context = service, .lookup = lookup });
    }

    fn view_end(context: *anyopaque) void {
        of(context).db.disk.?.view_end();
    }

    fn lookup(
        context: *anyopaque,
        kind: disk_state.OverlayKind,
        key: []const u8,
    ) disk_state.OverlayValue {
        const service = of(context);
        const archive_kind: Kind = switch (kind) {
            .account => .account,
            .slot => .slot,
            .account_branch => .account_branch,
            .storage_branch => .storage_branch,
        };
        const found = service.archive.value_after(archive_kind, key, service.view_number) catch
            return .failed;
        const value = found orelse return .trees;
        return .{ .value = value.old };
    }
};

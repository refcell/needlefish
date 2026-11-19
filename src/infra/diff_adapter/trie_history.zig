//! The trie mode's archive for `disk-view-history`: what el-run's archive (`bin/base/
//! el_archive.zig`) keeps per block for its history views, in memory. After every block the
//! view database commits, it takes the block's writes with the values they replaced from the
//! disk state's capture (`DiskState.capture_enable`): account records, branch records, and
//! the slots of the block's changeset. A view of an older block (`DiskState.view_begin`)
//! looks every key up here (`lookup`): the value before the first block after the viewed one
//! that changed the key (`Archive.value_after`'s answer), else the trees' own.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const flat_trees = @import("../../execution/db/flat_trees.zig");
const branch_record = @import("../../execution/db/branch_record.zig");
const trie_node = @import("trie_node.zig");

const Hash = [32]u8;
const Node = trie_node.Node;
const OverlayKind = db.disk_state.OverlayKind;
const OverlayValue = db.disk_state.OverlayValue;

pub const Archive = struct {
    /// The request's arena: keys and old values live as long as the request.
    arena: std.mem.Allocator,
    /// Per kind and key (`kind` byte, then the key), the blocks that changed it, ascending,
    /// each with the value before it (null: absent).
    versions: std.StringHashMapUnmanaged(std.ArrayList(Version)) = .empty,
    /// The changeset of the block being taken (its slots and their old words).
    changeset: db.Changeset,
    /// The capture sequence of the last block taken.
    sequence: u64 = 0,
    /// The database block a view shows (`lookup`).
    view_height: u64 = 0,
    lookups: u64 = 0,
    /// Lookups the archive answered (the rest read the trees).
    lookups_archived: u64 = 0,

    const Version = struct { height: u64, old: ?[]const u8 };

    pub fn init(arena: std.mem.Allocator, allocator: std.mem.Allocator) !Archive {
        return .{
            .arena = arena,
            .changeset = try db.Changeset.init(allocator, trie_node.changeset_config),
        };
    }

    pub fn deinit(archive: *Archive, allocator: std.mem.Allocator) void {
        archive.changeset.deinit(allocator);
        archive.* = undefined;
    }

    /// Takes the block `node` just committed (its head), as el-run's `on_block` does.
    pub fn take(archive: *Archive, node: *const Node) !void {
        const disk = &node.db.disk.?;
        const capture = disk.capture.?;
        // The capture must describe this block: one forward apply since the last.
        if (capture.failed) return error.CaptureFailed;
        if (!capture.forward or capture.sequence == archive.sequence) return error.CaptureStale;
        archive.sequence = capture.sequence;
        const height = node.height;
        for (disk.last_account_writes()) |*write| {
            const old: ?[]const u8 = if (write.old) |*bytes| bytes else null;
            try archive.put(.account, &write.key, height, old);
        }
        try archive.changeset.decode(node.state_db.last_changeset().?);
        const changeset = &archive.changeset;
        for (changeset.storage_changes()) |*change| {
            const owner = changeset.account_key(&change.address);
            const slot = changeset.slot_key(change.slot);
            const key = flat_trees.storage_key_hashed(&owner, &slot);
            var old: ?[]const u8 = null;
            if (change.old != 0) {
                const word = try archive.arena.create(Hash);
                std.mem.writeInt(u256, word, change.old, .big);
                old = word;
            }
            try archive.put(.slot, &key, height, old);
        }
        for (disk.last_record_writes()) |*write| {
            var key: [branch_record.storage_key_bytes]u8 = undefined;
            var kind: OverlayKind = undefined;
            var key_bytes: []const u8 = undefined;
            if (write.owner) |*owner| {
                key = branch_record.storage_key(owner, write.hang.slice());
                kind = .storage_branch;
                key_bytes = &key;
            } else {
                const path = branch_record.path_key(write.hang.slice());
                key[0..branch_record.path_key_bytes].* = path;
                kind = .account_branch;
                key_bytes = key[0..branch_record.path_key_bytes];
            }
            try archive.put(kind, key_bytes, height, disk.record_old(write));
        }
    }

    fn put(
        archive: *Archive,
        kind: OverlayKind,
        key: []const u8,
        height: u64,
        old: ?[]const u8,
    ) !void {
        var name_buffer: [1 + branch_record.storage_key_bytes]u8 = undefined;
        const name = map_key(&name_buffer, kind, key);
        const entry = try archive.versions.getOrPut(archive.arena, name);
        if (!entry.found_existing) {
            entry.key_ptr.* = try archive.arena.dupe(u8, name);
            entry.value_ptr.* = .empty;
        }
        const list = entry.value_ptr;
        if (list.items.len > 0) {
            const last = list.items[list.items.len - 1].height;
            assert(last <= height);
            if (last == height) return; // Already taken for this block.
        }
        const copy: ?[]const u8 = if (old) |bytes| try archive.arena.dupe(u8, bytes) else null;
        try list.append(archive.arena, .{ .height = height, .old = copy });
    }

    fn map_key(buffer: []u8, kind: OverlayKind, key: []const u8) []const u8 {
        assert(key.len + 1 <= buffer.len);
        buffer[0] = @backingInt(kind);
        @memcpy(buffer[1..][0..key.len], key);
        return buffer[0 .. 1 + key.len];
    }

    /// The database moved back to `height` (a native unwind): blocks above it are gone, as
    /// el-run's archive cuts back to the database head (`rebase`).
    pub fn truncate(archive: *Archive, height: u64) void {
        var lists = archive.versions.valueIterator();
        while (lists.next()) |list| {
            while (list.items.len > 0 and list.items[list.items.len - 1].height > height) {
                _ = list.pop();
            }
        }
    }

    pub fn overlay(archive: *Archive) db.disk_state.Overlay {
        return .{ .context = archive, .lookup = lookup };
    }

    fn lookup(context: *anyopaque, kind: OverlayKind, key: []const u8) OverlayValue {
        const archive: *Archive = @ptrCast(@alignCast(context));
        archive.lookups += 1;
        var name_buffer: [1 + branch_record.storage_key_bytes]u8 = undefined;
        if (key.len + 1 > name_buffer.len) return .failed;
        const list = archive.versions.get(map_key(&name_buffer, kind, key)) orelse return .trees;
        for (list.items) |version| {
            if (version.height <= archive.view_height) continue;
            archive.lookups_archived += 1;
            return .{ .value = version.old };
        }
        return .trees;
    }
};

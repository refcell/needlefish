//! Read-only reader for MDBX database files (libmdbx 0.13, the format reth stores its state
//! in), for importing a public Base node snapshot (SYNC_PLAN M3). Pure: pages come from an
//! injected `Source` (a file in the binary, a byte slice in tests).
//!
//! Format (all integers little-endian, read unaligned): pages 0..2 are meta pages; the
//! current one is the steady meta (`sign == ~0`, both txnid halves equal) with the highest
//! txnid. Each meta holds the descriptor (`Tree`, 48 bytes) of the main tree, whose leaf
//! nodes name the tables: key = table name, value = the table's `Tree`. A tree page has a
//! 20-byte header and an array of u16 node offsets; a node has an 8-byte header (data size
//! or child page, flags, key size), then the key, then the data. Leaf node flags: big value
//! in large pages (0x01), table record (0x02), duplicates in a sub-page (0x04) or in a nested
//! tree (0x06). Keys and duplicates sort by memcmp, shorter first.
//!
//! The file is untrusted: every page is checked against the tree it is reached from (its own
//! number, a known type, txnid not above its parent's, node bounds), and a failed check is
//! `error.Corrupt`. Only pages reachable from the chosen meta are ever read.

const std = @import("std");
const assert = std.debug.assert;

pub const page_header_bytes = 20;
pub const node_header_bytes = 8;
pub const tree_bytes = 48;
/// MDBX's cursor stack bound; deeper trees are corrupt.
pub const depth_max = 32;
pub const page_size_min = 256;
pub const page_size_max = 65536;
pub const invalid_page: u32 = 0xffff_ffff;

const magic_data: u64 = 0x59659dbdef4c1103;
const magic_legacy_compat: u64 = 0x59659dbdef4c1102;
const magic_legacy_devel: u64 = 0x59659dbdef4c11ff;
const sign_steady: u64 = 0xffff_ffff_ffff_ffff;
const txnid_max: u64 = 0xffff_ffff_0000_0000 - 1;
const meta_count = 3;
const meta_read_bytes = 256;

const page_branch: u16 = 0x01;
const page_leaf: u16 = 0x02;
const page_large: u16 = 0x04;
const page_meta: u16 = 0x08;
const page_legacy_dirty: u16 = 0x10;
const page_dupfix: u16 = 0x20;
const page_sub: u16 = 0x40;

pub const node_big: u8 = 0x01;
pub const node_tree: u8 = 0x02;
pub const node_dup: u8 = 0x04;

pub const flag_dupsort: u16 = 0x04;
const flag_integerkey: u16 = 0x08;

pub const Error = error{ Corrupt, Unsupported, ValueTooLarge, ReadFailed, NoTable };

/// Reads `buffer.len` bytes at `offset`, all or `error.ReadFailed`.
pub const Source = struct {
    context: *anyopaque,
    read: *const fn (context: *anyopaque, offset: u64, buffer: []u8) error{ReadFailed}!void,
};

/// A B-tree descriptor (the meta's trees, a table record, a nested duplicate tree).
pub const Tree = struct {
    flags: u16,
    height: u16,
    root: u32,
    branch_pages: u32,
    leaf_pages: u32,
    large_pages: u32,
    items: u64,
    mod_txnid: u64,

    pub fn parse(bytes: []const u8) Error!Tree {
        if (bytes.len != tree_bytes) return error.Corrupt;
        const tree: Tree = .{
            .flags = int(u16, bytes, 0),
            .height = int(u16, bytes, 2),
            .root = int(u32, bytes, 8),
            .branch_pages = int(u32, bytes, 12),
            .leaf_pages = int(u32, bytes, 16),
            .large_pages = int(u32, bytes, 20),
            .items = int(u64, bytes, 32),
            .mod_txnid = int(u64, bytes, 40),
        };
        if (tree.height > depth_max) return error.Corrupt;
        if ((tree.root == invalid_page) != (tree.height == 0)) return error.Corrupt;
        return tree;
    }

    pub fn empty(tree: *const Tree) bool {
        return tree.root == invalid_page;
    }

    pub fn dupsort(tree: *const Tree) bool {
        return tree.flags & flag_dupsort != 0;
    }
};

fn int(comptime T: type, bytes: []const u8, offset: usize) T {
    assert(offset + @sizeOf(T) <= bytes.len);
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

pub const Meta = struct {
    txnid: u64,
    page_size: u32,
    /// Pages at and above this number are unused.
    pages_used: u32,
    gc: Tree,
    main: Tree,
};

/// Parses and validates meta page `number` (`bytes`: its first 256 bytes). Null when the
/// meta is unusable (torn, weak, or invalid), as MDBX skips it.
pub fn parse_meta(bytes: []const u8, number: u32, file_bytes: u64) ?Meta {
    assert(bytes.len >= meta_read_bytes);
    const magic = int(u64, bytes, 20);
    if (magic != magic_data and magic != magic_legacy_compat and magic != magic_legacy_devel) {
        return null;
    }
    if (int(u32, bytes, 16) != number or int(u16, bytes, 10) != page_meta) return null;
    const txnid = int(u64, bytes, 28);
    if (txnid != int(u64, bytes, 196) or txnid == 0 or txnid > txnid_max) return null;
    if (int(u64, bytes, 188) != sign_steady) return null;
    const page_size = int(u32, bytes, 64);
    if (!std.math.isPowerOfTwo(page_size)) return null;
    if (page_size < page_size_min or page_size > page_size_max) return null;
    const pages_used = int(u32, bytes, 56);
    if (pages_used < meta_count or @as(u64, pages_used) * page_size > file_bytes) return null;
    const gc = Tree.parse(bytes[60..][0..tree_bytes]) catch return null;
    const main = Tree.parse(bytes[108..][0..tree_bytes]) catch return null;
    if (gc.flags != flag_integerkey) return null;
    for ([_]Tree{ gc, main }) |tree| {
        if (tree.mod_txnid > txnid) return null;
        if (tree.empty()) continue;
        if (tree.root < meta_count or tree.root >= pages_used) return null;
    }
    return .{
        .txnid = txnid,
        .page_size = page_size,
        .pages_used = pages_used,
        .gc = gc,
        .main = main,
    };
}

/// A leaf or branch node of a page (slices into the page).
pub const Node = struct {
    /// Leaf: the value size; branch: the child page.
    size_or_page: u32,
    flags: u8,
    key: []const u8,
    /// The inline data: the value, a 4-byte large page number (`node_big`), or a `Tree`.
    data: []const u8,
};

/// Node `index` of a page or sub-page (`bytes`). Bounds are checked against `bytes`.
fn node_at(bytes: []const u8, index: u32, branch: bool) Error!Node {
    const entry = page_header_bytes + 2 * @as(usize, index);
    if (entry + 2 > bytes.len) return error.Corrupt;
    const offset = @as(usize, int(u16, bytes, entry)) + page_header_bytes;
    if (offset % 2 != 0 or offset + node_header_bytes > bytes.len) return error.Corrupt;
    const size_or_page = int(u32, bytes, offset);
    const flags = bytes[offset + 4];
    const key_size = int(u16, bytes, offset + 6);
    const key_start = offset + node_header_bytes;
    if (key_start + key_size > bytes.len) return error.Corrupt;
    if (branch) {
        if (flags != 0) return error.Corrupt;
        const key = bytes[key_start..][0..key_size];
        return .{ .size_or_page = size_or_page, .flags = 0, .key = key, .data = &.{} };
    }
    const data_size: usize = switch (flags) {
        0, node_dup => size_or_page,
        node_big => 4,
        node_tree, node_tree | node_dup => tree_bytes,
        else => return error.Corrupt,
    };
    if (flags & node_tree != 0 and size_or_page != tree_bytes) return error.Corrupt;
    const data_start = key_start + key_size;
    if (data_start + data_size > bytes.len) return error.Corrupt;
    return .{
        .size_or_page = size_or_page,
        .flags = flags,
        .key = bytes[key_start..][0..key_size],
        .data = bytes[data_start..][0..data_size],
    };
}

/// The node count of a page or sub-page header in `bytes`, after the bounds checks.
fn node_count(bytes: []const u8) Error!u32 {
    if (bytes.len < page_header_bytes) return error.Corrupt;
    const lower = int(u16, bytes, 12);
    const upper = int(u16, bytes, 14);
    if (lower % 2 != 0 or lower > upper) return error.Corrupt;
    if (page_header_bytes + @as(usize, upper) > bytes.len) return error.Corrupt;
    return lower / 2;
}

pub const Reader = struct {
    source: Source,
    meta: Meta,
    file_bytes: u64,
    /// Scratch for large values (`node_big`), at most `value_bytes_max`.
    value_buffer: []u8,

    pub const Config = struct { value_bytes_max: u32 = 1 << 20 };

    pub fn open(
        allocator: std.mem.Allocator,
        source: Source,
        file_bytes: u64,
        config: Config,
    ) (Error || error{OutOfMemory})!Reader {
        var buffer: [meta_read_bytes]u8 = undefined;
        if (file_bytes < meta_read_bytes) return error.Corrupt;
        try source.read(source.context, 0, &buffer);
        const guess = int(u32, &buffer, 64);
        if (!std.math.isPowerOfTwo(guess) or guess < page_size_min or guess > page_size_max) {
            return error.Corrupt;
        }
        var best: ?Meta = null;
        for (0..meta_count) |number| {
            const offset = @as(u64, guess) * number;
            if (offset + meta_read_bytes > file_bytes) return error.Corrupt;
            try source.read(source.context, offset, &buffer);
            const meta = parse_meta(&buffer, @intCast(number), file_bytes) orelse continue;
            if (meta.page_size != guess) continue;
            if (best == null or meta.txnid > best.?.txnid) best = meta;
        }
        const meta = best orelse return error.Corrupt;
        const value_buffer = try allocator.alloc(u8, config.value_bytes_max);
        assert(meta.page_size == guess);
        return .{
            .source = source,
            .meta = meta,
            .file_bytes = file_bytes,
            .value_buffer = value_buffer,
        };
    }

    pub fn deinit(self: *Reader, allocator: std.mem.Allocator) void {
        allocator.free(self.value_buffer);
        self.* = undefined;
    }

    /// Reads tree page `number` into `buffer` (one page) and checks its header.
    fn read_page(self: *Reader, number: u32, front_txnid: u64, buffer: []u8) Error!void {
        assert(buffer.len == self.meta.page_size);
        if (number < meta_count or number >= self.meta.pages_used) return error.Corrupt;
        try self.source.read(self.source.context, @as(u64, number) * self.meta.page_size, buffer);
        if (int(u32, buffer, 16) != number) return error.Corrupt;
        if (int(u64, buffer, 0) > front_txnid) return error.Corrupt;
        const flags = int(u16, buffer, 10);
        if (flags != page_branch and flags != page_leaf) {
            return if (flags == page_leaf | page_dupfix) error.Unsupported else error.Corrupt;
        }
        _ = try node_count(buffer);
    }

    /// The value of a `node_big` node, read from its large pages into `value_buffer`.
    fn big_value(self: *Reader, node: *const Node, leaf_txnid: u64) Error![]const u8 {
        assert(node.flags == node_big);
        const size = node.size_or_page;
        if (size > self.value_buffer.len) return error.ValueTooLarge;
        const first = int(u32, node.data, 0);
        const page_size = self.meta.page_size;
        const pages_needed = (page_header_bytes + @as(u64, size) + page_size - 1) / page_size;
        if (first < meta_count or first + pages_needed > self.meta.pages_used) return error.Corrupt;
        var header: [page_header_bytes]u8 = undefined;
        const offset = @as(u64, first) * page_size;
        try self.source.read(self.source.context, offset, &header);
        if (int(u32, &header, 16) != first or int(u16, &header, 10) != page_large) {
            return error.Corrupt;
        }
        if (int(u64, &header, 0) > leaf_txnid or int(u32, &header, 12) < pages_needed) {
            return error.Corrupt;
        }
        const value = self.value_buffer[0..size];
        try self.source.read(self.source.context, offset + page_header_bytes, value);
        return value;
    }

    /// The front txnid of a tree's root page.
    fn root_front(self: *const Reader, tree: *const Tree) u64 {
        return if (tree.mod_txnid == 0) self.meta.txnid else tree.mod_txnid;
    }

    /// The descriptor of table `name` (a leaf of the main tree).
    pub fn table(self: *Reader, allocator: std.mem.Allocator, name: []const u8) !Tree {
        var cursor = try Cursor.init(allocator, self, &self.meta.main);
        defer cursor.deinit(allocator);
        while (try cursor.next_node()) |node| {
            if (!std.mem.eql(u8, node.key, name)) continue;
            if (node.flags != node_tree) return error.Corrupt;
            return Tree.parse(node.data);
        }
        return error.NoTable;
    }
};

/// Walks one B-tree's leaf nodes in key order with an explicit page stack.
const Walker = struct {
    pages: []u8,
    page_size: u32,
    indexes: [depth_max]u32 = undefined,
    counts: [depth_max]u32 = undefined,
    /// Frames on the stack; 0 = exhausted.
    depth: u32 = 0,
    height: u32 = 0,

    fn init(allocator: std.mem.Allocator, page_size: u32) error{OutOfMemory}!Walker {
        const pages = try allocator.alloc(u8, @as(usize, depth_max) * page_size);
        return .{ .pages = pages, .page_size = page_size };
    }

    fn deinit(self: *Walker, allocator: std.mem.Allocator) void {
        allocator.free(self.pages);
        self.* = undefined;
    }

    fn frame(self: *Walker, level: u32) []u8 {
        assert(level < depth_max);
        return self.pages[@as(usize, level) * self.page_size ..][0..self.page_size];
    }

    fn start(self: *Walker, reader: *Reader, tree: *const Tree, front: u64) Error!void {
        self.depth = 0;
        self.height = tree.height;
        if (tree.empty()) return;
        try self.push(reader, tree.root, front);
    }

    /// Loads page `number` as the next frame; its kind must fit its level.
    fn push(self: *Walker, reader: *Reader, number: u32, front: u64) Error!void {
        if (self.depth == self.height) return error.Corrupt;
        const page = self.frame(self.depth);
        try reader.read_page(number, front, page);
        const leaf = int(u16, page, 10) == page_leaf;
        if (leaf != (self.depth + 1 == self.height)) return error.Corrupt;
        self.counts[self.depth] = try node_count(page);
        if (self.counts[self.depth] == 0 and !leaf) return error.Corrupt;
        self.indexes[self.depth] = 0;
        self.depth += 1;
    }

    /// The txnid of the deepest loaded page.
    fn leaf_txnid(self: *Walker) u64 {
        assert(self.depth > 0);
        return int(u64, self.frame(self.depth - 1), 0);
    }

    /// The next leaf node in key order, or null.
    fn next(self: *Walker, reader: *Reader) Error!?Node {
        var steps: u32 = 0;
        while (self.depth > 0) : (steps += 1) {
            if (steps > 2 * depth_max + 2) return error.Corrupt; // Empty leaves only.
            const level = self.depth - 1;
            const page = self.frame(level);
            if (self.indexes[level] == self.counts[level]) {
                self.depth -= 1;
                continue;
            }
            const index = self.indexes[level];
            self.indexes[level] += 1;
            const branch = int(u16, page, 10) == page_branch;
            const node = try node_at(page, index, branch);
            if (!branch) return node;
            if (index == 0 and node.key.len != 0) return error.Corrupt;
            try self.push(reader, node.size_or_page, int(u64, page, 0));
            steps = 0;
        }
        return null;
    }
};

pub const Entry = struct { key: []const u8, value: []const u8 };

/// Every (key, value) of a table in order; a DUPSORT key yields one entry per duplicate.
/// Slices are valid until the next call.
pub const Cursor = struct {
    reader: *Reader,
    outer: Walker,
    inner: Walker,
    mode: enum { none, sub_page, nested } = .none,
    key: []const u8 = &.{},
    sub_page: []const u8 = &.{},
    sub_index: u32 = 0,
    sub_count: u32 = 0,
    /// Entries returned, for a cross-check against `Tree.items`.
    entries: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, reader: *Reader, tree: *const Tree) !Cursor {
        var outer = try Walker.init(allocator, reader.meta.page_size);
        errdefer outer.deinit(allocator);
        var inner = try Walker.init(allocator, reader.meta.page_size);
        errdefer inner.deinit(allocator);
        try outer.start(reader, tree, reader.root_front(tree));
        return .{ .reader = reader, .outer = outer, .inner = inner };
    }

    pub fn deinit(self: *Cursor, allocator: std.mem.Allocator) void {
        self.inner.deinit(allocator);
        self.outer.deinit(allocator);
        self.* = undefined;
    }

    /// The next raw leaf node of the outer tree (no duplicate expansion).
    pub fn next_node(self: *Cursor) Error!?Node {
        assert(self.mode == .none);
        return self.outer.next(self.reader);
    }

    pub fn next(self: *Cursor) Error!?Entry {
        while (true) {
            switch (self.mode) {
                .sub_page => if (self.sub_index < self.sub_count) {
                    const node = try node_at(self.sub_page, self.sub_index, false);
                    self.sub_index += 1;
                    if (node.flags != 0 or node.size_or_page != 0) return error.Corrupt;
                    return self.emit(node.key);
                },
                .nested => if (try self.inner.next(self.reader)) |node| {
                    if (node.flags != 0 or node.size_or_page != 0) return error.Corrupt;
                    return self.emit(node.key);
                },
                .none => {},
            }
            self.mode = .none;
            const node = try self.outer.next(self.reader) orelse return null;
            self.key = node.key;
            switch (node.flags) {
                0 => return self.emit(node.data),
                node_big => {
                    const leaf_txnid = self.outer.leaf_txnid();
                    return self.emit(try self.reader.big_value(&node, leaf_txnid));
                },
                node_dup => try self.open_sub_page(node.data),
                node_tree | node_dup => try self.open_nested(node.data),
                else => return error.Corrupt, // A table record outside the main tree.
            }
        }
    }

    fn emit(self: *Cursor, value: []const u8) Entry {
        self.entries += 1;
        return .{ .key = self.key, .value = value };
    }

    fn open_sub_page(self: *Cursor, data: []const u8) Error!void {
        const count = try node_count(data);
        const flags = int(u16, data, 10) & ~page_legacy_dirty;
        if (flags == page_leaf | page_sub | page_dupfix) return error.Unsupported;
        if (flags != page_leaf | page_sub or count == 0) return error.Corrupt;
        self.sub_page = data;
        self.sub_index = 0;
        self.sub_count = count;
        self.mode = .sub_page;
    }

    fn open_nested(self: *Cursor, data: []const u8) Error!void {
        const tree = try Tree.parse(data);
        const leaf_txnid = self.outer.leaf_txnid();
        if (tree.empty() or tree.mod_txnid > leaf_txnid) return error.Corrupt;
        if (tree.flags != 0) return error.Unsupported;
        const front = if (tree.mod_txnid == 0) leaf_txnid else tree.mod_txnid;
        try self.inner.start(self.reader, &tree, front);
        self.mode = .nested;
    }
};

/// A `Source` over bytes in memory (tests, small files).
pub const SliceSource = struct {
    bytes: []const u8,

    pub fn source(self: *SliceSource) Source {
        return .{ .context = self, .read = read };
    }

    fn read(context: *anyopaque, offset: u64, buffer: []u8) error{ReadFailed}!void {
        const self: *SliceSource = @ptrCast(@alignCast(context));
        if (offset > self.bytes.len) return error.ReadFailed;
        if (buffer.len > self.bytes.len - offset) return error.ReadFailed;
        @memcpy(buffer, self.bytes[@intCast(offset)..][0..buffer.len]);
    }
};

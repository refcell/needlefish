//! Write-ahead journal: a ring of checksummed, hash-chained entries.
//!
//! An entry is one header sector followed by the body padded to whole sectors. The header
//! holds its own checksum, the body checksum, a sequence number that grows by exactly one,
//! and the previous entry's header checksum, so the entries form a hash chain rooted in the
//! superblock's `journal_start`. An entry that does not fit before the zone end goes to the
//! zone start. Entries at or after the tail (`journal_start`) are never overwritten: append
//! returns `error.JournalFull` and the caller checkpoints, which moves the tail.
//!
//! Positions are logical byte offsets that only grow; `position % zone_size` is the physical
//! offset and wrapping jumps to the next multiple of `zone_size`. The ring is full when an
//! entry would end past `tail + zone_size`.
//!
//! Recovery scans from the tail and accepts an entry only if the header checksum, sequence,
//! chain link, and body checksum all match. At the first position that fails it also tries
//! the zone start once (the writer may have wrapped there), then stops. A stop on a zeroed
//! header, a header from an older lap, or a header from another format is a clean end; any
//! other failure is reported as corruption. After a crash the uncommitted, torn last entry
//! usually shows up as corruption: the scan cannot tell a torn write from bit rot, and it
//! must not, since in both cases the only safe result is the valid prefix.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const checksum_module = @import("checksum.zig");
const superblock_module = @import("superblock.zig");

const sector_size = storage.sector_size;
const checksum = checksum_module.checksum;
const JournalStart = superblock_module.JournalStart;

/// "nfjournl" read as a little-endian u64.
pub const magic: u64 = 0x6c6e_7275_6f6a_666e;
pub const metadata_size: u32 = superblock_module.commit_metadata_size;
const header_used_size = 4 * 16 + 8 + 8 + 4 + 4 + 8 + metadata_size;

pub const Header = extern struct {
    /// Checksum of every header byte after this field.
    checksum: u128,
    checksum_body: u128,
    previous_checksum: u128,
    format_id: u128,
    magic: u64,
    sequence: u64,
    body_size: u32,
    reserved_a: u32,
    reserved_b: u64,
    metadata: [metadata_size]u8,
    reserved: [sector_size - header_used_size]u8,

    pub fn compute_checksum(header: *const Header) u128 {
        return checksum(std.mem.asBytes(header)[@sizeOf(u128)..]);
    }
};

comptime {
    assert(@sizeOf(Header) == sector_size);
    assert(@offsetOf(Header, "reserved") == header_used_size);
}

/// What recovery expects at the next position.
pub const Expect = struct {
    format_id: u128,
    sequence: u64,
    previous_checksum: u128,
    body_size_max: u32,
};

pub const Verdict = enum { valid, clean, corrupt };

/// Classifies one header sector. `valid` still requires the body checksum to match.
pub fn classify_header(sector: []const u8, expect: Expect, header: *Header) Verdict {
    assert(sector.len == sector_size);
    assert(expect.sequence > 0);
    @memcpy(std.mem.asBytes(header), sector);
    const intact = header.checksum == header.compute_checksum() and
        header.magic == magic and header.reserved_a == 0 and header.reserved_b == 0 and
        all_zero(&header.reserved);
    if (!intact) return if (all_zero(sector)) .clean else .corrupt;
    // Intact but not the next entry: leftovers of an earlier format or an earlier lap.
    if (header.format_id != expect.format_id) return .clean;
    if (header.sequence < expect.sequence) return .clean;
    if (header.sequence > expect.sequence) return .corrupt;
    if (header.previous_checksum != expect.previous_checksum) return .corrupt;
    if (header.body_size > expect.body_size_max) return .corrupt;
    return .valid;
}

fn all_zero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

pub fn entry_size_bytes(body_size: u64) u64 {
    const size = sector_size + storage.sector_ceil(body_size);
    assert(size % sector_size == 0);
    assert(size >= sector_size);
    return size;
}

pub const Config = struct {
    /// Absolute storage offset of the zone.
    zone_offset: u64,
    zone_size_bytes: u64,
    body_size_max: u32,
};

pub const Entry = struct {
    sequence: u64,
    metadata: *const [metadata_size]u8,
    body: []const u8,
};

pub const Consumer = struct {
    context: *anyopaque,
    on_entry: *const fn (context: *anyopaque, entry: Entry) void,
};

pub const StopReason = enum { clean, header_corrupt, body_corrupt };

pub const RecoverResult = struct {
    replayed: u64,
    stop: StopReason,
};

pub fn JournalType(comptime Storage: type) type {
    storage.assert_interface(Storage);
    return struct {
        const Self = @This();

        pub const Callback = *const fn (*Self) void;
        /// Failed reads are retried so a transient fault does not truncate the journal.
        pub const read_attempts_max: u32 = 4;
        pub const State = enum { idle, append_write, append_sync, recover_header, recover_body };

        storage: *Storage,
        config: Config,
        /// One entry: header sector plus the largest padded body.
        buffer: []align(sector_size) u8,
        format_id: u128 = 0,
        /// Logical position of the oldest live entry (`journal_start`).
        tail: u64 = 0,
        /// Logical position just past the newest durable entry.
        head: u64 = 0,
        sequence_next: u64 = 1,
        previous_checksum: u128 = 0,
        state: State = .idle,
        callback: ?Callback = null,
        read: storage.Read = .{},
        write: storage.Write = .{},
        sync: storage.Sync = .{},
        append_position: u64 = 0,
        append_checksum: u128 = 0,
        recover_position: u64 = 0,
        recover_consumer: ?Consumer = null,
        recover_attempts: u32 = 0,
        /// Set while trying the zone start after a failure at `recover_position`.
        recover_wrap_reason: ?StopReason = null,
        recover_wrapped: bool = false,
        recover_result: RecoverResult = .{ .replayed = 0, .stop = .clean },

        pub fn entry_size_max(config: Config) u64 {
            return entry_size_bytes(config.body_size_max);
        }

        pub fn init(allocator: std.mem.Allocator, storage_: *Storage, config: Config) !Self {
            assert(config.zone_offset % sector_size == 0);
            assert(config.zone_size_bytes % sector_size == 0);
            // Twice the largest entry: after a checkpoint any entry fits, even when wrapping.
            assert(config.zone_size_bytes >= 2 * entry_size_max(config));
            assert(config.zone_offset + config.zone_size_bytes <= storage_.size_bytes());
            const buffer = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                @intCast(entry_size_max(config)),
            );
            @memset(buffer, 0);
            return .{ .storage = storage_, .config = config, .buffer = buffer };
        }

        /// May run with an operation in flight: after a simulated crash the storage has
        /// dropped it and will never call back.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(self.buffer.len > 0);
            allocator.free(self.buffer);
            self.* = undefined;
        }

        /// Positions the journal at `start` (from the superblock), with nothing after it.
        pub fn reset(self: *Self, format_id: u128, start: JournalStart) void {
            assert(self.state == .idle);
            assert(start.offset < self.config.zone_size_bytes);
            assert(start.offset % sector_size == 0);
            assert(start.sequence > 0);
            self.format_id = format_id;
            self.tail = start.offset;
            self.head = start.offset;
            self.sequence_next = start.sequence;
            self.previous_checksum = start.previous_checksum;
        }

        /// The `journal_start` for a checkpoint covering every entry appended so far.
        pub fn start_point(self: *const Self) JournalStart {
            assert(self.head >= self.tail);
            return .{
                .previous_checksum = self.previous_checksum,
                .offset = self.head % self.config.zone_size_bytes,
                .sequence = self.sequence_next,
            };
        }

        /// Frees entries before logical position `tail` (a past `head`), once a superblock
        /// naming it as `journal_start` is durable.
        pub fn release(self: *Self, tail: u64) void {
            assert(tail >= self.tail);
            assert(tail <= self.head);
            self.tail = tail;
        }

        pub fn idle(self: *const Self) bool {
            return self.state == .idle;
        }

        /// Where an entry of `size` bytes would go, or null if the ring is full.
        fn placement(self: *const Self, size: u64) ?u64 {
            const zone_size = self.config.zone_size_bytes;
            assert(size <= zone_size);
            var position = self.head;
            if (position % zone_size + size > zone_size) position = lap_start(position, zone_size);
            assert(position % zone_size + size <= zone_size);
            if (position + size > self.tail + zone_size) return null;
            return position;
        }

        /// Appends one entry. On success the entry's sequence is returned and `callback` fires
        /// once the entry is durable. One append at a time.
        pub fn append(
            self: *Self,
            body: []const u8,
            metadata: *const [metadata_size]u8,
            callback: Callback,
        ) error{JournalFull}!u64 {
            assert(self.state == .idle);
            assert(self.callback == null);
            assert(body.len <= self.config.body_size_max);
            const size = entry_size_bytes(body.len);
            const position = self.placement(size) orelse return error.JournalFull;

            const header: *Header = @ptrCast(self.buffer[0..sector_size]);
            header.* = std.mem.zeroes(Header);
            header.checksum_body = checksum(body);
            header.previous_checksum = self.previous_checksum;
            header.format_id = self.format_id;
            header.magic = magic;
            header.sequence = self.sequence_next;
            header.body_size = @intCast(body.len);
            header.metadata = metadata.*;
            header.checksum = header.compute_checksum();
            @memcpy(self.buffer[sector_size..][0..body.len], body);
            @memset(self.buffer[sector_size + body.len .. @intCast(size)], 0);

            self.append_position = position;
            self.append_checksum = header.checksum;
            self.state = .append_write;
            self.callback = callback;
            self.storage.write_sectors(
                on_append_write,
                &self.write,
                self.buffer[0..@intCast(size)],
                self.config.zone_offset + position % self.config.zone_size_bytes,
            );
            return self.sequence_next;
        }

        fn on_append_write(write: *storage.Write) void {
            const self: *Self = @alignCast(@fieldParentPtr("write", write));
            assert(self.state == .append_write);
            self.state = .append_sync;
            self.storage.sync(on_append_sync, &self.sync);
        }

        fn on_append_sync(sync: *storage.Sync) void {
            const self: *Self = @alignCast(@fieldParentPtr("sync", sync));
            assert(self.state == .append_sync);
            assert(self.append_position >= self.head);
            self.head = self.append_position + self.write.buffer.len;
            self.sequence_next += 1;
            self.previous_checksum = self.append_checksum;
            assert(self.head <= self.tail + self.config.zone_size_bytes);
            self.finish();
        }

        /// Replays every valid entry from the tail through `consumer`, in order. Afterwards
        /// `head`, `sequence_next`, and `previous_checksum` follow the last valid entry and
        /// `recover_result` tells how many entries replayed and why the scan stopped.
        pub fn recover(self: *Self, consumer: Consumer, callback: Callback) void {
            assert(self.state == .idle);
            assert(self.callback == null);
            assert(self.head == self.tail);
            self.state = .recover_header;
            self.callback = callback;
            self.recover_consumer = consumer;
            self.recover_position = self.tail;
            self.recover_wrap_reason = null;
            self.recover_wrapped = false;
            self.recover_result = .{ .replayed = 0, .stop = .clean };
            self.recover_attempts = 0;
            self.recover_read_header();
        }

        fn recover_read_header(self: *Self) void {
            assert(self.state == .recover_header);
            assert(self.recover_attempts < read_attempts_max);
            const zone_size = self.config.zone_size_bytes;
            // A full lap of entries ends exactly at the tail; there is nothing more to read.
            if (self.recover_position + sector_size > self.tail + zone_size) {
                return self.recover_invalid(.clean);
            }
            self.recover_attempts += 1;
            self.storage.read_sectors(
                on_recover_header,
                &self.read,
                self.buffer[0..sector_size],
                self.config.zone_offset + self.recover_position % zone_size,
            );
        }

        fn on_recover_header(read: *storage.Read) void {
            const self: *Self = @alignCast(@fieldParentPtr("read", read));
            assert(self.state == .recover_header);
            var header: Header = undefined;
            const verdict = classify_header(self.buffer[0..sector_size], self.expect(), &header);
            switch (verdict) {
                .clean => return self.recover_invalid(.clean),
                .corrupt => return self.recover_retry_header(),
                .valid => {},
            }
            const zone_size = self.config.zone_size_bytes;
            const size = entry_size_bytes(header.body_size);
            // The writer never places an entry across the zone end or past the tail.
            const placed = self.recover_position % zone_size + size <= zone_size and
                self.recover_position + size <= self.tail + zone_size;
            if (!placed) return self.recover_retry_header();
            if (header.body_size == 0) return self.recover_body_check();
            self.state = .recover_body;
            self.recover_attempts = 0;
            self.recover_read_body();
        }

        fn recover_retry_header(self: *Self) void {
            if (self.recover_attempts < read_attempts_max) return self.recover_read_header();
            self.recover_invalid(.header_corrupt);
        }

        fn recover_read_body(self: *Self) void {
            assert(self.state == .recover_body);
            const header: *const Header = @ptrCast(self.buffer[0..sector_size]);
            assert(header.body_size > 0);
            self.recover_attempts += 1;
            const body_padded = storage.sector_ceil(header.body_size);
            self.storage.read_sectors(
                on_recover_body,
                &self.read,
                self.buffer[sector_size..][0..@intCast(body_padded)],
                self.config.zone_offset + self.recover_position % self.config.zone_size_bytes +
                    sector_size,
            );
        }

        fn on_recover_body(read: *storage.Read) void {
            const self: *Self = @alignCast(@fieldParentPtr("read", read));
            assert(self.state == .recover_body);
            self.recover_body_check();
        }

        /// The header in `buffer` is valid; checks the body and delivers the entry.
        fn recover_body_check(self: *Self) void {
            const header: *const Header = @ptrCast(self.buffer[0..sector_size]);
            const body = self.buffer[sector_size..][0..header.body_size];
            if (checksum(body) != header.checksum_body) {
                if (header.body_size > 0 and self.recover_attempts < read_attempts_max) {
                    return self.recover_read_body();
                }
                self.state = .recover_header;
                return self.recover_invalid(.body_corrupt);
            }
            assert(header.sequence == self.sequence_next);
            self.recover_consumer.?.on_entry(self.recover_consumer.?.context, .{
                .sequence = header.sequence,
                .metadata = &header.metadata,
                .body = body,
            });
            self.head = self.recover_position + entry_size_bytes(header.body_size);
            self.sequence_next += 1;
            self.previous_checksum = header.checksum;
            self.recover_result.replayed += 1;
            if (self.recover_wrap_reason != null) {
                self.recover_wrap_reason = null;
                self.recover_wrapped = true;
            }
            assert(self.recover_result.replayed <= self.config.zone_size_bytes / sector_size);
            self.recover_position = self.head;
            self.recover_attempts = 0;
            self.state = .recover_header;
            self.recover_read_header();
        }

        /// No valid entry at `recover_position`: try the zone start once, else stop.
        fn recover_invalid(self: *Self, reason: StopReason) void {
            assert(self.state == .recover_header);
            const zone_size = self.config.zone_size_bytes;
            const position = self.recover_position;
            const may_wrap = self.recover_wrap_reason == null and !self.recover_wrapped and
                position % zone_size != 0 and
                lap_start(position, zone_size) + sector_size <= self.tail + zone_size;
            if (may_wrap) {
                self.recover_wrap_reason = reason;
                self.recover_position = lap_start(position, zone_size);
                self.recover_attempts = 0;
                return self.recover_read_header();
            }
            // Report the more serious of the failures at the end and at the zone start.
            const first = self.recover_wrap_reason orelse .clean;
            self.recover_result.stop = if (first != .clean) first else reason;
            self.recover_consumer = null;
            self.finish();
        }

        fn expect(self: *const Self) Expect {
            return .{
                .format_id = self.format_id,
                .sequence = self.sequence_next,
                .previous_checksum = self.previous_checksum,
                .body_size_max = self.config.body_size_max,
            };
        }

        fn finish(self: *Self) void {
            assert(self.state != .idle);
            const callback = self.callback.?;
            self.state = .idle;
            self.callback = null;
            callback(self);
        }
    };
}

fn lap_start(position: u64, zone_size: u64) u64 {
    const result = (position / zone_size + 1) * zone_size;
    assert(result > position);
    assert(result - position <= zone_size);
    return result;
}

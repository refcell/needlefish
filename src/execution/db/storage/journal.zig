//! Write-ahead journal: a ring of checksummed, hash-chained entries.
//!
//! An entry is one header sector followed by the body padded to whole sectors. The header
//! holds its own checksum, the body checksum, a sequence number that grows by exactly one,
//! and the previous entry's header checksum, so the entries form a hash chain rooted in the
//! superblock's `journal_start`. An entry that does not fit before the zone end goes to the
//! zone start. Entries at or after the tail are never overwritten: append returns
//! `error.JournalFull` and the caller checkpoints, which moves the tail. The tail is the
//! previous checkpoint's journal start (the fallback), so the live entries span up to two
//! checkpoints; replay starts at the newest checkpoint's journal start.
//!
//! Positions are logical byte offsets that only grow; `position % zone_size` is the physical
//! offset and wrapping jumps to the next multiple of `zone_size`. The ring is full when an
//! entry would end past `tail + zone_size`.
//!
//! Group commit (`append_batch`): several entries, contiguous in one write and covered by one
//! sync, so one sync makes a whole queue durable. They are ordinary entries (each its own
//! header, sequence and chain link), so the format and recovery are those of single appends:
//! a crash before the sync leaves any subset of the batch's sectors written, and the scan
//! stops at the first entry that does not verify, as it does at a torn single entry; no
//! entry of the batch was acknowledged. A batch stays within the buffer (one largest entry
//! and a trailer), before the zone end, and within the live span.
//!
//! Recovery scans from the replay start and accepts an entry only if the header checksum, sequence,
//! chain link, and body checksum all match. At the first position that fails it also tries
//! the zone start once (the writer may have wrapped there), then stops. A stop on a zeroed
//! header, a header from an older lap, or a header from another format is a clean end; any
//! other failure is reported as corruption. After a crash the uncommitted, torn last entry
//! usually shows up as corruption: the scan cannot tell a torn write from bit rot, and it
//! must not, since in both cases the only safe result is the valid prefix.
//!
//! So that a clean end reads as one, each append also zeroes the sector after its entry, in
//! the same write, when that sector is free (before the zone end and outside the live span).
//! Without it, the end of the newest entry can fall inside an older lap's body, whose bytes
//! look like a damaged header, and a clean restart would report corruption. When the trailer
//! is skipped the end is clean anyway: at the zone end the scan reads the zone start (zeroes
//! or a header, since wraps always begin there), and a full ring ends at the tail.

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
        /// Logical position of the oldest live entry (the fallback checkpoint's start).
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
        /// Bytes of the entries being appended (the write may add a zeroed trailer sector),
        /// their count, and the last one's header checksum.
        append_size: u64 = 0,
        append_count: u32 = 0,
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
            // The largest entry plus its zeroed trailer sector.
            const buffer = try allocator.alignedAlloc(
                u8,
                .fromByteUnits(sector_size),
                @intCast(entry_size_max(config) + sector_size),
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
            self.reset_retained(format_id, start, start);
        }

        /// Positions the journal at `start` (replay begins there) while keeping every entry
        /// from the older `retained` start live: nothing at or after `retained` is
        /// overwritten. Both come from the superblock; `retained` names the fallback.
        pub fn reset_retained(
            self: *Self,
            format_id: u128,
            start: JournalStart,
            retained: JournalStart,
        ) void {
            assert(self.state == .idle);
            const zone_size = self.config.zone_size_bytes;
            assert(start.offset < zone_size and retained.offset < zone_size);
            assert(start.offset % sector_size == 0 and retained.offset % sector_size == 0);
            assert(retained.sequence > 0);
            assert(retained.sequence <= start.sequence);
            // Entries from `retained` to `start` span at most one lap, so the physical offsets
            // and the sequences fix the logical distance: an equal offset with entries in
            // between is a full lap.
            var head = start.offset;
            if (start.sequence == retained.sequence) {
                assert(start.offset == retained.offset);
                assert(start.previous_checksum == retained.previous_checksum);
            } else if (start.offset <= retained.offset) {
                head += zone_size;
            }
            self.format_id = format_id;
            self.tail = retained.offset;
            self.head = head;
            self.sequence_next = start.sequence;
            self.previous_checksum = start.previous_checksum;
            assert(self.head >= self.tail);
            assert(self.head - self.tail <= zone_size);
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

        /// Frees entries before logical position `tail` (a past `head`), once every durable
        /// superblock copy names a start at or after it, as current or fallback.
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
            const sequence = self.sequence_next;
            const metadatas: *const [1][metadata_size]u8 = metadata;
            const count = try self.append_batch(&.{body}, metadatas, callback);
            assert(count == 1);
            return sequence;
        }

        /// Appends the first entries of `bodies` (with `metadatas`, one each) that fit one
        /// write (see the file comment), at least one; returns how many. `callback` fires
        /// once they are all durable; their sequences follow `sequence_next`.
        pub fn append_batch(
            self: *Self,
            bodies: []const []const u8,
            metadatas: []const [metadata_size]u8,
            callback: Callback,
        ) error{JournalFull}!u32 {
            assert(self.state == .idle);
            assert(self.callback == null);
            assert(bodies.len > 0 and bodies.len == metadatas.len);
            const zone_size = self.config.zone_size_bytes;
            const position = self.placement(entry_size_bytes(bodies[0].len)) orelse
                return error.JournalFull;
            var size: u64 = 0;
            var count: u32 = 0;
            var previous = self.previous_checksum;
            for (bodies, metadatas) |body, *metadata| {
                assert(body.len <= self.config.body_size_max);
                const entry_size = entry_size_bytes(body.len);
                const end = size + entry_size;
                // The first entry always fits (placement, and the buffer's size).
                const fits = end + sector_size <= self.buffer.len and
                    position % zone_size + end <= zone_size and
                    position + end <= self.tail + zone_size;
                if (!fits) break;
                previous = self.encode_entry(size, count, previous, body, metadata);
                size = end;
                count += 1;
            }
            assert(count >= 1 and count <= bodies.len);
            // Zeroes the trailer sector, when written.
            const write_size = size + if (self.trailer_free(position, size)) sector_size else 0;
            @memset(self.buffer[@intCast(size)..@intCast(write_size)], 0);
            assert(write_size <= self.buffer.len);

            self.append_position = position;
            self.append_size = size;
            self.append_count = count;
            self.append_checksum = previous;
            self.state = .append_write;
            self.callback = callback;
            self.storage.write_sectors(
                on_append_write,
                &self.write,
                self.buffer[0..@intCast(write_size)],
                self.config.zone_offset + position % zone_size,
            );
            return count;
        }

        /// Writes entry `index` of a batch (header, body, zeroed padding) at `offset` in the
        /// buffer, chained to `previous`; returns its header checksum.
        fn encode_entry(
            self: *Self,
            offset: u64,
            index: u32,
            previous: u128,
            body: []const u8,
            metadata: *const [metadata_size]u8,
        ) u128 {
            const size = entry_size_bytes(body.len);
            assert(offset % sector_size == 0);
            assert(offset + size <= self.buffer.len);
            const entry = self.buffer[@intCast(offset)..][0..@intCast(size)];
            const header: *Header = @ptrCast(@alignCast(entry[0..sector_size]));
            header.* = std.mem.zeroes(Header);
            header.checksum_body = checksum(body);
            header.previous_checksum = previous;
            header.format_id = self.format_id;
            header.magic = magic;
            header.sequence = self.sequence_next + index;
            header.body_size = @intCast(body.len);
            header.metadata = metadata.*;
            header.checksum = header.compute_checksum();
            @memcpy(entry[sector_size..][0..body.len], body);
            @memset(entry[sector_size + body.len ..], 0);
            return header.checksum;
        }

        /// Whether the sector after an entry at `position` of `size` bytes may be zeroed: it
        /// lies before the zone end and outside the live span (never over the tail's entries).
        fn trailer_free(self: *const Self, position: u64, size: u64) bool {
            const zone_size = self.config.zone_size_bytes;
            const end = position + size;
            assert(end <= self.tail + zone_size);
            return end % zone_size != 0 and end + sector_size <= self.tail + zone_size and
                position % zone_size + size + sector_size <= zone_size;
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
            assert(self.write.buffer.len >= self.append_size);
            assert(self.append_count >= 1);
            self.head = self.append_position + self.append_size;
            self.sequence_next += self.append_count;
            self.previous_checksum = self.append_checksum;
            assert(self.head <= self.tail + self.config.zone_size_bytes);
            self.finish();
        }

        /// Replays every valid entry from the head (the replay start set by `reset`) through
        /// `consumer`, in order. Afterwards
        /// `head`, `sequence_next`, and `previous_checksum` follow the last valid entry and
        /// `recover_result` tells how many entries replayed and why the scan stopped.
        pub fn recover(self: *Self, consumer: Consumer, callback: Callback) void {
            assert(self.state == .idle);
            assert(self.callback == null);
            assert(self.head >= self.tail);
            assert(self.head - self.tail <= self.config.zone_size_bytes);
            self.state = .recover_header;
            self.callback = callback;
            self.recover_consumer = consumer;
            self.recover_position = self.head;
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

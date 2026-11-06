//! Grid: fixed-size, checksummed blocks inside the engine file, addressed by index.
//!
//! The grid zone follows the journal. Block `address` (1-based, 0 means none) lives at
//! `zone_offset + (address - 1) * block_size`. Every block starts with a 128-byte header:
//! checksum (of the header after the checksum, then the payload), format id, magic,
//! address, kind, and payload size. Only the used sectors are written.
//!
//! Whoever points at a block holds a `Reference` (address + checksum), as TigerBeetle does.
//! A read verifies the header, the address (catches misdirected IO), the format id
//! (leftovers of an older format), the kind, and that the checksum equals the reference's
//! (catches a stale block at a reused address and torn writes). A read that fails is retried
//! a few times (transient faults) and then reported as corrupt.
//!
//! Which blocks are free is the free set's business (`free_set.zig`); the grid only moves
//! bytes. Reads and writes are intrusive (`Read`, `Write` embedded in the caller), so any
//! number may be in flight, bounded by the callers' own static state.

const std = @import("std");
const assert = std.debug.assert;

const storage = @import("storage.zig");
const checksum_module = @import("checksum.zig");

const sector_size = storage.sector_size;

/// "nfgridbk" read as a little-endian u64.
pub const magic: u64 = 0x6b62_6469_7267_666e;

pub const BlockKind = enum(u8) {
    table_data = 1,
    table_index = 2,
    _,
};

pub const BlockHeader = extern struct {
    /// Checksum of the header bytes after this field followed by the payload.
    checksum: u128,
    format_id: u128,
    magic: u64,
    address: u64,
    payload_size: u32,
    kind: u8,
    reserved_a: [3]u8,
    reserved: [64]u8,

    pub fn compute_checksum(header: *const BlockHeader, payload: []const u8) u128 {
        assert(payload.len == header.payload_size);
        var stream = checksum_module.Stream.init();
        stream.update(std.mem.asBytes(header)[@sizeOf(u128)..]);
        stream.update(payload);
        return stream.final();
    }
};

pub const block_header_size: u32 = @sizeOf(BlockHeader);

/// What a parent stores to name a block.
pub const Reference = extern struct {
    checksum: u128 = 0,
    address: u64 = 0,
    reserved: u64 = 0,
};

comptime {
    assert(block_header_size == 128);
    assert(@sizeOf(Reference) == 32);
}

pub const Config = struct {
    /// Absolute storage offset of block 1.
    zone_offset: u64,
    block_size: u32,
    block_count: u64,

    pub fn size_bytes(config: Config) u64 {
        return config.block_count * config.block_size;
    }

    pub fn payload_capacity(config: Config) u32 {
        return payload_capacity_of(config.block_size);
    }
};

pub fn payload_capacity_of(block_size: u32) u32 {
    assert(block_size > block_header_size);
    return block_size - block_header_size;
}

/// Fills the header of `block` (whose payload is already in place) and returns its reference.
pub fn seal(
    block: []u8,
    format_id: u128,
    address: u64,
    kind: BlockKind,
    payload_size: u32,
) Reference {
    assert(address > 0);
    assert(block_header_size + payload_size <= block.len);
    const header: *BlockHeader = @ptrCast(@alignCast(block[0..block_header_size]));
    header.* = std.mem.zeroes(BlockHeader);
    header.format_id = format_id;
    header.magic = magic;
    header.address = address;
    header.payload_size = payload_size;
    header.kind = @backingInt(kind);
    const payload = block[block_header_size..][0..payload_size];
    header.checksum = header.compute_checksum(payload);
    const length: usize = @intCast(storage.sector_ceil(block_header_size + payload_size));
    @memset(block[block_header_size + payload_size .. length], 0);
    return .{ .checksum = header.checksum, .address = address };
}

/// The bytes of a sealed block that go to disk (whole sectors).
pub fn sealed_length(block: []const u8) u32 {
    const header: *const BlockHeader = @ptrCast(@alignCast(block[0..block_header_size]));
    assert(header.magic == magic);
    const length = storage.sector_ceil(block_header_size + header.payload_size);
    assert(length <= block.len);
    return @intCast(length);
}

/// Verifies a block read for `reference`; returns its payload or null.
pub fn verify(
    block: []const u8,
    format_id: u128,
    reference: Reference,
    kind: BlockKind,
) ?[]const u8 {
    assert(reference.address > 0);
    assert(block.len >= block_header_size);
    const header: *const BlockHeader = @ptrCast(@alignCast(block[0..block_header_size]));
    if (header.checksum != reference.checksum) return null;
    if (header.magic != magic or header.format_id != format_id) return null;
    if (header.address != reference.address or header.kind != @backingInt(kind)) return null;
    if (header.payload_size > block.len - block_header_size) return null;
    const payload = block[block_header_size..][0..header.payload_size];
    if (header.compute_checksum(payload) != header.checksum) return null;
    return payload;
}

pub fn GridType(comptime Storage: type) type {
    storage.assert_interface(Storage);
    return struct {
        const Self = @This();

        pub const read_attempts_max: u32 = 4;

        pub const Write = struct {
            storage_write: storage.Write = .{},
            callback: *const fn (*Write) void = undefined,
            grid: *Self = undefined,
            address: u64 = 0,
        };

        pub const Read = struct {
            storage_read: storage.Read = .{},
            callback: *const fn (*Read) void = undefined,
            grid: *Self = undefined,
            buffer: []align(sector_size) u8 = &.{},
            reference: Reference = .{},
            kind: BlockKind = .table_data,
            attempts: u32 = 0,
            /// Set on completion: the verified payload (inside `buffer`), or null if every
            /// attempt failed to verify.
            payload: ?[]const u8 = null,
        };

        storage: *Storage,
        config: Config,
        format_id: u128 = 0,
        stats: Stats = .{},

        pub const Stats = struct {
            reads: u64 = 0,
            writes: u64 = 0,
            read_retries: u64 = 0,
        };

        pub fn init(storage_: *Storage, config: Config) Self {
            assert(config.block_size % sector_size == 0);
            assert(config.block_size > block_header_size);
            assert(config.block_count > 0);
            assert(config.zone_offset % sector_size == 0);
            assert(config.zone_offset + config.size_bytes() <= storage_.size_bytes());
            return .{ .storage = storage_, .config = config };
        }

        pub fn offset_of(self: *const Self, address: u64) u64 {
            assert(address >= 1 and address <= self.config.block_count);
            return self.config.zone_offset + (address - 1) * self.config.block_size;
        }

        /// Writes a sealed block (`seal`) to `address`. `block` stays untouched until the
        /// callback fires.
        pub fn write_block(
            self: *Self,
            callback: *const fn (*Write) void,
            write: *Write,
            block: []const u8,
            address: u64,
        ) void {
            const header: *const BlockHeader = @ptrCast(@alignCast(block[0..block_header_size]));
            assert(header.address == address);
            assert(header.format_id == self.format_id);
            write.* = .{ .callback = callback, .grid = self, .address = address };
            self.stats.writes += 1;
            self.storage.write_sectors(
                on_write,
                &write.storage_write,
                block[0..sealed_length(block)],
                self.offset_of(address),
            );
        }

        fn on_write(storage_write: *storage.Write) void {
            const write: *Write = @alignCast(@fieldParentPtr("storage_write", storage_write));
            assert(write.address > 0);
            write.callback(write);
        }

        /// Reads and verifies the block `reference` names into `buffer` (one block).
        pub fn read_block(
            self: *Self,
            callback: *const fn (*Read) void,
            read: *Read,
            buffer: []align(sector_size) u8,
            reference: Reference,
            kind: BlockKind,
        ) void {
            assert(buffer.len == self.config.block_size);
            assert(reference.address >= 1 and reference.address <= self.config.block_count);
            read.* = .{
                .callback = callback,
                .grid = self,
                .buffer = buffer,
                .reference = reference,
                .kind = kind,
            };
            self.read_submit(read);
        }

        /// Reads and verifies the block `reference` names into `buffer` (one block) at once,
        /// through `read_sectors_sync`, with `read_block`'s checks and retries. Returns the
        /// verified payload (inside `buffer`), or null if every attempt failed.
        pub fn read_sync(
            self: *Self,
            buffer: []align(sector_size) u8,
            reference: Reference,
            kind: BlockKind,
        ) ?[]const u8 {
            assert(buffer.len == self.config.block_size);
            assert(reference.address >= 1 and reference.address <= self.config.block_count);
            const offset = self.offset_of(reference.address);
            var attempt: u32 = 0;
            while (attempt < read_attempts_max) : (attempt += 1) {
                if (attempt > 0) self.stats.read_retries += 1;
                self.stats.reads += 1;
                self.storage.read_sectors_sync(buffer, offset) catch continue;
                if (verify(buffer, self.format_id, reference, kind)) |payload| return payload;
            }
            return null;
        }

        fn read_submit(self: *Self, read: *Read) void {
            assert(read.attempts < read_attempts_max);
            read.attempts += 1;
            self.stats.reads += 1;
            // Whole blocks: the size is unknown until the header verifies.
            self.storage.read_sectors(
                on_read,
                &read.storage_read,
                read.buffer,
                self.offset_of(read.reference.address),
            );
        }

        fn on_read(storage_read: *storage.Read) void {
            const read: *Read = @alignCast(@fieldParentPtr("storage_read", storage_read));
            const self = read.grid;
            read.payload = verify(read.buffer, self.format_id, read.reference, read.kind);
            if (read.payload == null and read.attempts < read_attempts_max) {
                self.stats.read_retries += 1;
                return self.read_submit(read);
            }
            read.callback(read);
        }
    };
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const SimStorage = @import("sim_storage.zig").SimStorage;

const TestIo = struct {
    writes_done: u32 = 0,
    reads_done: u32 = 0,

    fn on_write(write: *GridType(SimStorage).Write) void {
        const harness: *TestIo = @ptrCast(@alignCast(test_context.?));
        _ = write;
        harness.writes_done += 1;
    }

    fn on_read(read: *GridType(SimStorage).Read) void {
        const harness: *TestIo = @ptrCast(@alignCast(test_context.?));
        _ = read;
        harness.reads_done += 1;
    }
};

var test_context: ?*anyopaque = null;

test "grid: write, read back, reject stale, misdirected, and rotten blocks" {
    const block_size: u32 = 8 * sector_size;
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 64 * block_size, .seed = 1 });
    defer sim.deinit(testing.allocator);
    var grid = GridType(SimStorage).init(&sim, .{
        .zone_offset = 4 * block_size,
        .block_size = block_size,
        .block_count = 16,
    });
    grid.format_id = 77;
    var harness: TestIo = .{};
    test_context = &harness;
    defer test_context = null;

    const block = try testing.allocator.alignedAlloc(u8, .fromByteUnits(sector_size), block_size);
    defer testing.allocator.free(block);
    const buffer = try testing.allocator.alignedAlloc(u8, .fromByteUnits(sector_size), block_size);
    defer testing.allocator.free(buffer);
    var prng = Prng.init(3);
    prng.fill(block[block_header_size..][0..5000]);
    const first = seal(block, 77, 3, .table_data, 5000);
    var write: GridType(SimStorage).Write = .{};
    grid.write_block(TestIo.on_write, &write, block, 3);
    while (harness.writes_done == 0) sim.tick();

    var read: GridType(SimStorage).Read = .{};
    grid.read_block(TestIo.on_read, &read, buffer, first, .table_data);
    while (harness.reads_done == 0) sim.tick();
    try testing.expectEqualSlices(u8, block[block_header_size..][0..5000], read.payload.?);

    // A newer block at the same address: the old reference no longer verifies.
    prng.fill(block[block_header_size..][0..100]);
    const second = seal(block, 77, 3, .table_data, 100);
    grid.write_block(TestIo.on_write, &write, block, 3);
    while (harness.writes_done == 1) sim.tick();
    grid.read_block(TestIo.on_read, &read, buffer, first, .table_data);
    while (harness.reads_done == 1) sim.tick();
    try testing.expect(read.payload == null);
    grid.read_block(TestIo.on_read, &read, buffer, second, .table_index);
    while (harness.reads_done == 2) sim.tick();
    try testing.expect(read.payload == null); // Wrong kind.

    // A misdirected reference (right checksum, other address) and bit rot.
    var misdirected = second;
    misdirected.address = 4;
    grid.read_block(TestIo.on_read, &read, buffer, misdirected, .table_data);
    while (harness.reads_done == 3) sim.tick();
    try testing.expect(read.payload == null);
    // Rot inside the used bytes (padding past the payload is not covered, nor read).
    const rotten: usize = @intCast(grid.offset_of(3) + block_header_size + 50);
    sim.durable[rotten] ^= 0x10;
    sim.memory[rotten] ^= 0x10;
    grid.read_block(TestIo.on_read, &read, buffer, second, .table_data);
    while (harness.reads_done == 4) sim.tick();
    try testing.expect(read.payload == null);
    try testing.expectEqual(@as(u32, 4), read.attempts);
}

test "grid: transient read faults are retried" {
    const block_size: u32 = 4 * sector_size;
    var sim = try SimStorage.init(testing.allocator, .{
        .size_bytes = 32 * block_size,
        .seed = 9,
        .read_fault_numerator = 200,
    });
    defer sim.deinit(testing.allocator);
    var grid = GridType(SimStorage).init(&sim, .{
        .zone_offset = 0,
        .block_size = block_size,
        .block_count = 32,
    });
    var harness: TestIo = .{};
    test_context = &harness;
    defer test_context = null;
    const block = try testing.allocator.alignedAlloc(u8, .fromByteUnits(sector_size), block_size);
    defer testing.allocator.free(block);
    var write: GridType(SimStorage).Write = .{};
    var read: GridType(SimStorage).Read = .{};
    var verified: u32 = 0;
    for (1..33) |address| {
        @memset(block[block_header_size..], @intCast(address));
        const reference = seal(block, 0, address, .table_index, block_size - block_header_size);
        grid.write_block(TestIo.on_write, &write, block, address);
        while (harness.writes_done < address) sim.tick();
        grid.read_block(TestIo.on_read, &read, block, reference, .table_index);
        while (harness.reads_done < address) sim.tick();
        if (read.payload) |payload| {
            verified += 1;
            for (payload) |byte| try testing.expectEqual(@as(u8, @intCast(address)), byte);
        }
    }
    // 20% faults per read, 4 attempts: losing all four is rare.
    try testing.expect(verified >= 30);
    try testing.expect(grid.stats.read_retries > 0);
}

test "grid: read_sync verifies like read_block and retries transient faults" {
    const block_size: u32 = 2 * sector_size;
    var sim = try SimStorage.init(testing.allocator, .{ .size_bytes = 16 * block_size, .seed = 4 });
    defer sim.deinit(testing.allocator);
    var grid = GridType(SimStorage).init(&sim, .{
        .zone_offset = 0,
        .block_size = block_size,
        .block_count = 16,
    });
    grid.format_id = 5;
    var harness: TestIo = .{};
    test_context = &harness;
    defer test_context = null;
    const block = try testing.allocator.alignedAlloc(u8, .fromByteUnits(sector_size), block_size);
    defer testing.allocator.free(block);
    const buffer = try testing.allocator.alignedAlloc(u8, .fromByteUnits(sector_size), block_size);
    defer testing.allocator.free(buffer);
    var prng = Prng.init(8);
    prng.fill(block[block_header_size..][0..3000]);
    const reference = seal(block, 5, 2, .table_data, 3000);
    var write: GridType(SimStorage).Write = .{};
    grid.write_block(TestIo.on_write, &write, block, 2);
    while (harness.writes_done == 0) sim.tick();
    const payload = grid.read_sync(buffer, reference, .table_data).?;
    try testing.expectEqualSlices(u8, block[block_header_size..][0..3000], payload);
    // Wrong kind, misdirected, and stale references fail every attempt.
    try testing.expect(grid.read_sync(buffer, reference, .table_index) == null);
    var misdirected = reference;
    misdirected.address = 3;
    try testing.expect(grid.read_sync(buffer, misdirected, .table_data) == null);
    var stale = reference;
    stale.checksum +%= 1;
    try testing.expect(grid.read_sync(buffer, stale, .table_data) == null);
    const attempts_max = GridType(SimStorage).read_attempts_max;
    try testing.expectEqual(@as(u64, 3 * (attempts_max - 1)), grid.stats.read_retries);
    // Transient faults are retried; rot is not.
    sim.options.read_fault_numerator = 500;
    const retries = grid.stats.read_retries;
    var verified: u32 = 0;
    for (0..32) |_| {
        const read = grid.read_sync(buffer, reference, .table_data) orelse continue;
        try testing.expectEqualSlices(u8, block[block_header_size..][0..3000], read);
        verified += 1;
    }
    // Half the reads flip a bit; losing all four attempts is rare (1 in 16).
    try testing.expect(verified >= 24);
    try testing.expect(grid.stats.read_retries > retries);
    sim.options.read_fault_numerator = 0;
    // Rot inside the used bytes (`corrupt_sector` may land in the unused padding).
    const rotten: usize = @intCast(grid.offset_of(2) + block_header_size + 1000);
    sim.durable[rotten] ^= 0x04;
    sim.memory[rotten] ^= 0x04;
    try testing.expect(grid.read_sync(buffer, reference, .table_data) == null);
}

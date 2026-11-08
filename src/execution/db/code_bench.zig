//! Code tables on the grid vs codes in the checkpoint image (filter "db/codes"), on the db
//! bench state (`bench.shape_bench`: 100k accounts, 64k slots) plus 4096 contract codes
//! sized like mainnet bytecode (40% 0.1-2 KiB proxies and small contracts, 40% 2-12 KiB,
//! 20% 12-24 KiB up to the EIP-170 limit; ~28 MiB), within the node's default code limits.
//!
//! Per variant (grid-less, grid): the first checkpoint after the codes are deployed (with a
//! grid it writes every code into tables), a second checkpoint after 16 more codes (an
//! incremental flush), the checkpoint image sizes, and `open` of the result (checkpoint
//! read; with a grid the table scan during the open pause; the image load). Storage is
//! `SimStorage` with no latency, so times are the CPU side (copies, checksums, decode,
//! keccak of every code at insert), not device time.
//!
//! Then, after the reopen, the code reads of `read_blocks` blocks of `reads_per_block`
//! reads each (half from 512 hot codes, half from all of them, as calls into popular
//! contracts and a long tail): grid codes resident in the arena, and pinned (codes out of
//! RAM, phase 1e): read from their tables through the code block cache (256 MiB, as the
//! node's, so every block is cached after its first read) and pinned until each block's
//! release. Cold: the first block after the open (every block read from storage, CPU side
//! only); warm: the mean of the last half.
//!
//! Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const database = @import("database.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const storage_module = @import("storage/storage.zig");
const checkpoint_module = @import("storage/checkpoint.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const Prng = @import("../../testing/prng.zig").Prng;

const Database = database.DatabaseType(SimStorage);
const Overlay = overlay_module.Overlay;
const shape = bench.shape_bench;
const name = "db/codes 100k acct+4096 codes";

const codes_total: u32 = 4096;
const codes_per_block: u32 = 128;
const codes_later: u32 = 16;
const block_size: u32 = 64 * 1024;
const read_blocks: u32 = 64;
const reads_per_block: u32 = 256;
const hot_codes: u32 = 512;

const Variant = enum { plain, grid, pinned };

fn code_length(prng: *Prng) u32 {
    const roll = prng.below(10);
    if (roll < 4) return @intCast(prng.range(100, 2000));
    if (roll < 8) return @intCast(prng.range(2000, 12_000));
    return @intCast(prng.range(12_000, 24_576));
}

fn config_for(variant: Variant) database.Config {
    var state = bench.state_config(shape);
    state.codes_max = 8192;
    state.code_bytes_max = 32 << 20;
    const body_max: u32 = @intCast(storage_module.sector_ceil(9 << 19));
    const staging: u64 = (64 << 20) + 4 * @as(u64, body_max);
    const payload = checkpoint_module.payload_capacity(block_size);
    const zone_blocks = std.math.divCeil(u64, staging, payload) catch unreachable; // > 0.
    var config: database.Config = .{
        .engine = .{
            .journal_size_bytes = 128 << 20,
            .checkpoint_zone_size_bytes = (zone_blocks + 1) * block_size,
            .entry_body_size_max = body_max,
            .checkpoint_block_size = block_size,
        },
        .state = state,
        .chain = .{
            .blocks_max = 4,
            .bytes_max = 4 * body_max,
            .transactions_max = 64,
            .canonical_max = 64,
        },
        .changeset = .{
            .accounts_max = shape.fill_accounts,
            .storage_max = shape.fill_slots(),
            .codes_max = codes_per_block,
            .code_bytes_max = 4 << 20,
        },
        .queue_entries_max = 4,
        .checkpoint_staging_bytes = @intCast(staging),
    };
    if (variant == .plain) return config;
    config.engine.grid_block_count = database.code_grid_block_count(state, block_size);
    if (variant == .pinned) {
        config.code_pin_bytes = @as(u64, reads_per_block) * 24_576;
        config.code_pins_max = reads_per_block;
        config.code_cache_blocks = 4096;
    }
    return config;
}

const Result = struct {
    image_first_bytes: u64 = 0,
    image_next_bytes: u64 = 0,
    checkpoint_first_ns: u64 = 0,
    checkpoint_next_ns: u64 = 0,
    open_ns: u64 = 0,
    open_tables_ns: u64 = 0,
    tables: u32 = 0,
    read_cold_ns: u64 = 0,
    read_warm_ns: u64 = 0,
    read_bytes: u64 = 0,
};

const Run = struct {
    db: Database,
    overlay: Overlay,
    sim: *SimStorage,
    prng: Prng,
    io: std.Io,
    header: [64]u8 = @splat(0x48),
    code: [24_576]u8 = undefined,
    trace_start_ns: u64 = 0,
    trace_read_ns: u64 = 0,
    trace_tables_ns: u64 = 0,

    fn tick_until(self: *Run, comptime done: fn (*const Database) bool) !void {
        var ticks: u64 = 0;
        while (!done(&self.db)) : (ticks += 1) {
            if (ticks > 50_000_000) return error.Timeout;
            self.sim.tick();
        }
    }

    fn idle(db: *const Database) bool {
        return db.idle();
    }

    fn not_opening(db: *const Database) bool {
        return db.phase != .opening;
    }

    fn not_formatting(db: *const Database) bool {
        return db.phase != .formatting;
    }

    fn commit(self: *Run) !void {
        const head = self.db.head_info;
        const number: u64 = if (head.present) head.number + 1 else 0;
        std.mem.writeInt(u64, self.header[0..8], number, .little);
        var hash: database.Hash = @splat(0xcd);
        std.mem.writeInt(u64, hash[0..8], number + 1, .big);
        const input: database.BlockInput = .{
            .hash = hash,
            .parent_hash = if (head.present) head.hash else @splat(0),
            .number = number,
            .timestamp = number * 2,
            .header = &self.header,
            .body = "",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
        _ = try self.db.execute_and_commit(&self.overlay, &input);
        try self.tick_until(idle);
    }

    fn deploy(self: *Run, first: u32, count: u32) !void {
        for (first..first + count) |index| {
            const code = self.code[0..code_length(&self.prng)];
            self.prng.fill(code);
            const address = bench.address_of(index);
            var info = self.overlay.basic(address).?;
            info.code_hash = try self.overlay.insert_code(code);
            try self.overlay.set_account(address, info);
        }
        try self.commit();
    }

    fn checkpoint(self: *Run) !u64 {
        const start = bench.now_ns(self.io);
        self.db.request_checkpoint();
        try self.tick_until(idle);
        if (self.db.checkpoint_error) |err| return err;
        return bench.now_ns(self.io) - start;
    }

    fn on_step(context: *anyopaque, step: database.OpenStep) void {
        const self: *Run = @ptrCast(@alignCast(context));
        const now = bench.now_ns(self.io);
        switch (step) {
            .checkpoint_read => self.trace_read_ns = now,
            .code_tables => self.trace_tables_ns = now,
            else => {},
        }
    }
};

fn run_variant(io: std.Io, variant: Variant) !Result {
    const allocator = std.heap.page_allocator;
    const config = config_for(variant);
    var sim = try SimStorage.init(allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = 11,
        .latency_ticks_max = 1,
    });
    defer sim.deinit(allocator);
    const fixture = try allocator.create(Run);
    defer allocator.destroy(fixture);
    fixture.* = .{
        .db = try Database.init(allocator, &sim, config),
        .overlay = undefined,
        .sim = &sim,
        .prng = Prng.init(7),
        .io = io,
    };
    defer fixture.db.deinit(allocator);
    fixture.overlay = try Overlay.init(allocator, &fixture.db.state, .{
        .accounts_max = shape.fill_accounts,
        .slots_max = shape.fill_slots(),
        .codes_max = codes_per_block,
    });
    defer fixture.overlay.deinit(allocator);
    fixture.db.format(0xc0de5);
    try fixture.tick_until(Run.not_formatting);
    fixture.db.open();
    try fixture.tick_until(Run.not_opening);
    for (0..shape.fill_blocks()) |fill_index| {
        try bench.write_fill(&fixture.overlay, shape, @intCast(fill_index));
        try fixture.commit();
    }
    _ = try fixture.checkpoint();
    var deployed: u32 = 0;
    while (deployed < codes_total) : (deployed += codes_per_block) {
        try fixture.deploy(deployed, codes_per_block);
    }
    var result: Result = .{};
    result.checkpoint_first_ns = try fixture.checkpoint();
    result.image_first_bytes = fixture.db.engine.superblock.working.checkpoint.size_bytes;
    try fixture.deploy(codes_total, codes_later);
    result.checkpoint_next_ns = try fixture.checkpoint();
    result.image_next_bytes = fixture.db.engine.superblock.working.checkpoint.size_bytes;
    try reopen(fixture, allocator, config, &result);
    try read_codes(fixture, allocator, &result);
    return result;
}

/// Times the reads of `read_blocks` blocks of codes, releasing the pins before each block.
fn read_codes(fixture: *Run, allocator: std.mem.Allocator, result: *Result) !void {
    const state = &fixture.db.state;
    const hashes = try allocator.alloc(database.Hash, state.code_table.count());
    defer allocator.free(hashes);
    var keys = state.code_table.keyIterator();
    for (hashes) |*hash| hash.* = keys.next().?.*;
    var prng = Prng.init(99);
    var checksum: u64 = 0;
    var warm_ns: u64 = 0;
    for (0..read_blocks) |block| {
        const start = bench.now_ns(fixture.io);
        fixture.db.codes_release();
        for (0..reads_per_block) |read| {
            const range: u64 = if (read % 2 == 0) hot_codes else hashes.len;
            const code = state.code_by_hash(hashes[prng.below(range)]) orelse
                return error.CodeUnreadable;
            checksum +%= code[code.len / 2];
            if (block == 0) result.read_bytes += code.len;
        }
        const elapsed = bench.now_ns(fixture.io) - start;
        if (block == 0) result.read_cold_ns = elapsed;
        if (block >= read_blocks / 2) warm_ns += elapsed;
    }
    result.read_warm_ns = warm_ns / (read_blocks / 2);
    std.mem.doNotOptimizeAway(checksum);
}

fn reopen(
    fixture: *Run,
    allocator: std.mem.Allocator,
    config: database.Config,
    result: *Result,
) !void {
    const head = fixture.db.head_info;
    fixture.overlay.discard();
    fixture.db.deinit(allocator);
    fixture.db = try Database.init(allocator, fixture.sim, config);
    fixture.overlay.base = &fixture.db.state;
    fixture.db.open_trace = .{ .context = fixture, .step = Run.on_step };
    const start = bench.now_ns(fixture.io);
    fixture.db.open();
    try fixture.tick_until(Run.not_opening);
    result.open_ns = bench.now_ns(fixture.io) - start;
    if (fixture.db.open_error) |err| return err;
    if (!fixture.db.head_info.eql(head)) return error.HeadMismatch;
    if (fixture.db.state.code_table.count() != codes_total + codes_later) return error.CodesMissing;
    if (fixture.db.code_store) |*store| {
        result.tables = store.tables.count;
        result.open_tables_ns = fixture.trace_tables_ns - fixture.trace_read_ns;
    }
}

fn print_reads(label: []const u8, result: *const Result) void {
    std.debug.print(
        "  {s:<9} reads of a block ({d} codes, {d} KiB): cold {d:>7.3} ms, warm {d:>7.3} ms " ++
            "({d:.0} ns/code)\n",
        .{
            label,
            reads_per_block,
            result.read_bytes / 1024,
            @as(f64, @floatFromInt(result.read_cold_ns)) / 1e6,
            @as(f64, @floatFromInt(result.read_warm_ns)) / 1e6,
            @as(f64, @floatFromInt(result.read_warm_ns)) / reads_per_block,
        },
    );
}

fn print_result(label: []const u8, result: *const Result) void {
    const mib = 1024.0 * 1024.0;
    std.debug.print(
        "  {s:<9} image {d:>6.1} MiB then {d:>6.1} MiB, " ++
            "checkpoint {d:>6.1} ms then {d:>6.1} ms, " ++
            "open {d:>6.1} ms (tables {d:.1} ms, {d} tables)\n",
        .{
            label,
            @as(f64, @floatFromInt(result.image_first_bytes)) / mib,
            @as(f64, @floatFromInt(result.image_next_bytes)) / mib,
            @as(f64, @floatFromInt(result.checkpoint_first_ns)) / 1e6,
            @as(f64, @floatFromInt(result.checkpoint_next_ns)) / 1e6,
            @as(f64, @floatFromInt(result.open_ns)) / 1e6,
            @as(f64, @floatFromInt(result.open_tables_ns)) / 1e6,
            result.tables,
        },
    );
}

fn run_case(io: std.Io) !void {
    const plain = try run_variant(io, .plain);
    const grid = try run_variant(io, .grid);
    const pinned = try run_variant(io, .pinned);
    std.debug.print("{s}\n", .{name});
    print_result("grid-less", &plain);
    print_result("grid", &grid);
    print_result("pinned", &pinned);
    print_reads("grid", &grid);
    print_reads("pinned", &pinned);
}

/// Runs the code table benchmark when it matches `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    if (!bench.matches(name, filter)) return;
    run_case(io) catch |err| std.debug.print("{s}: failed: {s}\n", .{ name, @errorName(err) });
}

//! `base derive-check` (docs/SYNC_PLAN.md M5): derives a real Base chain's safe blocks from
//! real L1 data with needlefish's derivation pipeline and compares every payload attributes
//! with the canonical block a reference node serves at that height, exactly as a verifier's
//! consolidation does (`base.consensus.derive_check.compare`, `engine/attributes_match`).
//!
//!     base derive-check [--chain base-sepolia|base-mainnet] [--l1-rpc <url>]
//!                       [--l1-beacon <url>] [--l2-rpc <url>] [--from <l2 block>]
//!                       [--blocks <n>] [--mismatches-max <n>] [--verbose]
//!
//! Start: the L2 block `--from` (default: `--blocks` below the reference's safe head) is
//! taken as the safe head. Its L1 origin and system config come from its L1 info deposit;
//! the reset walks back one channel timeout of L1 origins (`Pipeline.signal(.reset)`), so
//! the blocks of that window are preloaded from the reference. Every following block, up to
//! `--blocks` of them, is derived from L1 and compared. A verified block becomes the next
//! parent (its hash taken from the reference, like the engine's block in consolidation).
//!
//! The reference node is only compared against: it never feeds derivation except as the
//! safe chain below the start. Exit status: 0 all blocks matched, 1 mismatches, 2 the check
//! could not complete.

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const net = @import("derive_check_net.zig");
const check_sources = @import("derive_check_sources.zig");
const derive_check = base.consensus.derive_check;
const compare = derive_check.compare;
const start_rules = derive_check.start;
const derive_errors = base.consensus.derive.errors;
const protocol = base.consensus.protocol;
const sources = base.consensus.sources;
const chains = base.common.chains;
const kzg = base.common.crypto.kzg;
const assert = std.debug.assert;

const Pipeline = base.consensus.derive.pipeline.Pipeline;
const AttributesWithParent = base.consensus.derive.pipeline.AttributesWithParent;
const L2BlockInfo = protocol.block.L2BlockInfo;
const RollupConfig = protocol.rollup_config.RollupConfig;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;
const Endpoint = net.Endpoint;

const usage =
    \\usage: base derive-check [--chain base-sepolia|base-mainnet] [--l1-rpc <url>]
    \\                         [--l1-beacon <url>] [--l2-rpc <url>] [--from <l2 block>]
    \\                         [--blocks <n>] [--mismatches-max <n>] [--verbose]
    \\
;

const ChainDefaults = struct {
    name: []const u8,
    chain: *const chains.ChainConfig,
    l1_url: []const u8,
    beacon_url: []const u8,
    l2_url: []const u8,
};

const defaults = [_]ChainDefaults{
    .{
        .name = "base-sepolia",
        .chain = &chains.sepolia,
        .l1_url = "https://ethereum-sepolia-rpc.publicnode.com",
        .beacon_url = "https://ethereum-sepolia-beacon-api.publicnode.com",
        .l2_url = "https://sepolia.base.org",
    },
    .{
        .name = "base-mainnet",
        .chain = &chains.mainnet,
        .l1_url = "https://ethereum-rpc.publicnode.com",
        .beacon_url = "https://ethereum-beacon-api.publicnode.com",
        .l2_url = "https://mainnet.base.org",
    },
};

const Flags = struct {
    defaults: *const ChainDefaults = &defaults[0],
    l1_url: ?[]const u8 = null,
    beacon_url: ?[]const u8 = null,
    l2_url: ?[]const u8 = null,
    from: ?u64 = null,
    blocks: u64 = 2000,
    mismatches_max: u64 = 5,
    verbose: bool = false,
};

fn parse_flags(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--verbose")) {
            flags.verbose = true;
            continue;
        }
        if (index + 1 >= args.len) return error.InvalidArguments;
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, arg, "--chain")) {
            flags.defaults = for (&defaults) |*entry| {
                if (std.mem.eql(u8, entry.name, value)) break entry;
            } else return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--l1-rpc")) {
            flags.l1_url = value;
        } else if (std.mem.eql(u8, arg, "--l1-beacon")) {
            flags.beacon_url = value;
        } else if (std.mem.eql(u8, arg, "--l2-rpc")) {
            flags.l2_url = value;
        } else if (std.mem.eql(u8, arg, "--from")) {
            flags.from = std.fmt.parseInt(u64, value, 10) catch return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--blocks")) {
            flags.blocks = std.fmt.parseInt(u64, value, 10) catch return error.InvalidArguments;
        } else if (std.mem.eql(u8, arg, "--mismatches-max")) {
            flags.mismatches_max = std.fmt.parseInt(u64, value, 10) catch
                return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    if (flags.blocks == 0 or flags.mismatches_max == 0) return error.InvalidArguments;
    return flags;
}

/// Headers of the next reference blocks, fetched in one batch (`eth_getBlockByNumber(n,
/// false)`): the cheap path compares only the header and the transactions root.
const Prefetch = struct {
    arena: std.heap.ArenaAllocator,
    first: u64 = 0,
    count: u32 = 0,
    raws: [batch]?[]const u8 = undefined,

    const batch = net.batch_max;

    fn get(prefetch: *Prefetch, endpoint: *Endpoint, number: u64, last: u64) ![]const u8 {
        assert(number <= last);
        if (number >= prefetch.first and number < prefetch.first + prefetch.count) {
            return prefetch.raws[number - prefetch.first] orelse error.ReferenceMissingBlock;
        }
        _ = prefetch.arena.reset(.{ .retain_with_limit = 1024 * 1024 });
        const allocator = prefetch.arena.allocator();
        const count: u32 = @intCast(@min(batch, last - number + 1));
        var params: [batch][]const u8 = undefined;
        for (params[0..count], 0..) |*param, offset| {
            param.* = try std.fmt.allocPrint(allocator, "[\"0x{x}\",false]", .{number + offset});
        }
        prefetch.count = 0;
        var results: [batch]?[]const u8 = undefined;
        try endpoint.call_batch("eth_getBlockByNumber", params[0..count], results[0..count]);
        for (results[0..count], prefetch.raws[0..count]) |result, *raw| {
            raw.* = if (result) |text| try allocator.dupe(u8, text) else null;
        }
        prefetch.first = number;
        prefetch.count = count;
        return prefetch.raws[0] orelse error.ReferenceMissingBlock;
    }
};

const steps_max: u64 = 50_000_000;
const failures_in_row_max = 12;
const l1_waits_max = 120;
const idle_steps_max = 100_000;
const reset_attempts_max = 12;
const progress_interval_blocks = 250;
const cadence_interval_blocks = 1000;

const Checker = struct {
    io: Io,
    flags: Flags,
    rollup: *const RollupConfig,
    fee_params: compare.FeeParams,
    l1: *check_sources.L1Source,
    blobs: *check_sources.BlobSource,
    l2: *check_sources.L2Chain,
    l1_endpoint: *Endpoint,
    beacon_endpoint: *Endpoint,
    reference: *Endpoint,
    pipeline: Pipeline,
    headers: Prefetch,
    arena: std.heap.ArenaAllocator,
    range: start_rules.Range = .{ .start = 0, .last = 1 },
    start: L2BlockInfo = .{},
    walk_back: L2BlockInfo = .{},
    cursor: L2BlockInfo = .{},
    first_derived: ?L2BlockInfo = null,
    cadence: derive_check.cadence.Cadence = .{},
    started_ms: i64 = 0,
    l1_first: u64 = 0,
    matched: u64 = 0,
    mismatches: u64 = 0,
    by_root: u64 = 0,
    full_bodies: u64 = 0,
    resets: u64 = 0,
    l1_advanced: u64 = 0,
    failures_in_row: u32 = 0,
    l1_waits: u32 = 0,
    idle_steps: u64 = 0,

    fn derived_count(checker: *const Checker) u64 {
        return checker.cursor.block_info.number -| checker.range.start;
    }

    fn sleep_ms(checker: *Checker, milliseconds: u64) !void {
        try checker.io.sleep(.fromMilliseconds(@intCast(milliseconds)), .awake);
    }

    /// The number of the reference's labeled block (`safe`, `finalized`).
    fn reference_number(checker: *Checker, label: []const u8) !u64 {
        var params: [32]u8 = undefined;
        const text = try std.fmt.bufPrint(&params, "[\"{s}\",false]", .{label});
        const raw = try checker.reference.call("eth_getBlockByNumber", text) orelse
            return error.ReferenceMissingBlock;
        var extra: [sources.header_json.extra_data_size_max]u8 = undefined;
        const decoded = try sources.header_json.decode(raw, &extra);
        return decoded.header.number;
    }

    fn preload_batch(checker: *Checker, first: u64, count: u32) !L2BlockInfo {
        for (0..reset_attempts_max) |attempt| {
            return checker.l2.preload(first, count) catch |err| {
                if (err != error.NotAvailable) return err;
                try checker.sleep_ms(1000 * (attempt + 1));
                continue;
            };
        }
        return error.ReferenceUnavailable;
    }

    /// Loads the start block and the reset walk-back window below it (the blocks
    /// `Pipeline.initial_reset` visits), mirroring its stop rule.
    fn preload(checker: *Checker) !void {
        const rollup = checker.rollup;
        checker.start = try checker.preload_batch(checker.range.start, 1);
        checker.l2.set_head(checker.range.start);
        const safe_time = checker.start.block_info.timestamp;
        const lower_bound = safe_time -| rollup.max_sequencer_drift_at(safe_time);
        const channel_timeout = rollup.channel_timeout_at(lower_bound);
        const origin_number = checker.start.l1_origin.number;
        const genesis = rollup.genesis.l2.number;
        const batches_max = checker.l2.entries.len / net.batch_max;
        var lowest = checker.start;
        for (0..batches_max) |_| {
            if (lowest.block_info.number <= genesis) break;
            if (lowest.l1_origin.number + channel_timeout <= origin_number) break;
            const count: u32 = @intCast(@min(net.batch_max, lowest.block_info.number - genesis));
            lowest = try checker.preload_batch(lowest.block_info.number - count, count);
        } else return error.WalkBackTooLong;
        checker.walk_back = lowest;
        assert(lowest.block_info.number <= checker.start.block_info.number);
        std.debug.print("start: l2 {d} {f} L1 origin {d}; reset walk-back to l2 {d} " ++
            "(L1 origin {d}, channel timeout {d} L1 blocks), {d} blocks preloaded\n", .{
            checker.start.block_info.number,
            checker.start.block_info.hash,
            origin_number,
            lowest.block_info.number,
            lowest.l1_origin.number,
            channel_timeout,
            checker.start.block_info.number - lowest.block_info.number + 1,
        });
    }

    fn reset_pipeline(checker: *Checker) !void {
        for (0..reset_attempts_max) |attempt| {
            const signal: base.consensus.derive.pipeline.Signal = .{
                .reset = .{ .l2_safe_head = checker.cursor },
            };
            checker.pipeline.signal(checker.l1, checker.l2, signal) catch |err| {
                std.debug.print("reset at l2 {d}: {t}, retry\n", .{
                    checker.cursor.block_info.number,
                    err,
                });
                if (derive_errors.kind(err) == .critical) return err;
                try checker.sleep_ms(2000 * (attempt + 1));
                continue;
            };
            assert(checker.pipeline.origin() != null);
            return;
        }
        return error.ResetFailed;
    }

    fn derive_all(checker: *Checker) !void {
        for (0..steps_max) |_| {
            if (checker.cursor.block_info.number >= checker.range.last) return;
            if (checker.mismatches >= checker.flags.mismatches_max) return;
            const result = checker.pipeline.step(
                checker.l1,
                checker.blobs,
                checker.l2,
                checker.cursor,
            );
            switch (result) {
                .prepared_attributes => try checker.consume(),
                .advanced_origin => checker.on_advanced(),
                .origin_advance_err, .step_failed => |err| try checker.on_error(err),
            }
        }
        return error.StepBudgetExhausted;
    }

    fn progressed(checker: *Checker) void {
        checker.failures_in_row = 0;
        checker.l1_waits = 0;
        checker.idle_steps = 0;
    }

    fn on_advanced(checker: *Checker) void {
        checker.progressed();
        checker.l1_advanced += 1;
        if (!checker.flags.verbose) return;
        const origin = checker.pipeline.origin().?;
        std.debug.print("l1 {d} (l2 safe {d})\n", .{
            origin.number,
            checker.cursor.block_info.number,
        });
    }

    fn on_error(checker: *Checker, err: derive_errors.Error) !void {
        const origin = checker.pipeline.origin();
        switch (derive_errors.kind(err)) {
            .critical => {
                std.debug.print("critical derivation error {t} at l2 {d}, L1 {?d}\n", .{
                    err,
                    checker.cursor.block_info.number,
                    if (origin) |block| block.number else null,
                });
                return error.CriticalDerivationError;
            },
            .reset => {
                checker.resets += 1;
                std.debug.print("reset after {t} at l2 {d}, L1 {?d}\n", .{
                    err,
                    checker.cursor.block_info.number,
                    if (origin) |block| block.number else null,
                });
                try checker.reset_pipeline();
            },
            .temporary => try checker.on_temporary(err),
        }
    }

    fn on_temporary(checker: *Checker, err: derive_errors.Error) !void {
        switch (err) {
            error.NotAvailable => {
                checker.failures_in_row += 1;
                if (checker.failures_in_row > failures_in_row_max) return error.ProvidersFailing;
                try checker.sleep_ms(5000 * @as(u64, checker.failures_in_row));
            },
            error.NotFound => {
                // The next L1 block does not exist yet: wait one slot.
                checker.l1_waits += 1;
                if (checker.l1_waits > l1_waits_max) return error.L1Stalled;
                if (checker.l1_waits == 1) std.debug.print("waiting for L1\n", .{});
                try checker.sleep_ms(12_000);
            },
            else => {
                checker.idle_steps += 1;
                if (checker.idle_steps > idle_steps_max) return error.NoProgress;
            },
        }
    }

    /// Compares the prepared attributes with the reference block and moves the safe head.
    fn consume(checker: *Checker) !void {
        checker.progressed();
        // Proof: `step` just prepared attributes and nothing else pops them.
        var prepared = checker.pipeline.next() orelse unreachable;
        defer prepared.deinit(checker.pipeline.allocator);
        assert(prepared.parent.eql(checker.cursor));
        _ = checker.arena.reset(.{ .retain_with_limit = 8 * 1024 * 1024 });
        const number = checker.cursor.block_info.number + 1;
        const raw = try checker.headers.get(checker.reference, number, checker.range.last);
        const view = try compare.decode_header(checker.arena.allocator(), raw, &prepared);
        var block = view.block;
        var mismatch: ?compare.Mismatch = null;
        if (view.transactions_root_match) {
            checker.by_root += 1;
            mismatch = compare.check(checker.rollup, checker.fee_params, &prepared, &block);
        } else {
            block = try checker.full_block(number);
            mismatch = compare.check(checker.rollup, checker.fee_params, &prepared, &block) orelse
                return error.InconsistentReference; // The roots differ, so must the lists.
        }
        if (mismatch) |found| try checker.report(found, &prepared, &block) else {
            checker.matched += 1;
        }
        const config = try compare.system_config_of(checker.rollup, &block);
        checker.l2.insert(block.info, config);
        checker.l2.set_head(number);
        checker.cursor = block.info;
        if (checker.first_derived == null) checker.first_derived = block.info;
        const derived_from = prepared.derived_from orelse return error.MissingOrigin;
        checker.cadence.record(number, derived_from.number);
        try checker.progress(derived_from.number);
    }

    fn full_block(checker: *Checker, number: u64) !compare.L2Block {
        checker.full_bodies += 1;
        var params: [48]u8 = undefined;
        const text = try std.fmt.bufPrint(&params, "[\"0x{x}\",true]", .{number});
        const raw = try checker.reference.call("eth_getBlockByNumber", text) orelse
            return error.ReferenceMissingBlock;
        const allocator = checker.arena.allocator();
        const genesis = &checker.rollup.genesis;
        const block = try sources.l2_block_full.decode(allocator, raw, genesis, .{});
        if (block.info.block_info.number != number) return error.ReferenceMissingBlock;
        return block;
    }

    fn report(
        checker: *Checker,
        mismatch: compare.Mismatch,
        prepared: *const AttributesWithParent,
        block: *const compare.L2Block,
    ) !void {
        checker.mismatches += 1;
        var text: Io.Writer.Allocating = .init(checker.arena.allocator());
        try compare.write_report(&text.writer, mismatch, prepared, block);
        std.debug.print("{s}  derived from L1 {?d}, L1 origin {d}\n", .{
            text.written(),
            if (prepared.derived_from) |origin| origin.number else null,
            block.info.l1_origin.number,
        });
    }

    fn progress(checker: *Checker, derived_from: u64) !void {
        const derived = checker.derived_count();
        assert(derived > 0);
        if (derived % progress_interval_blocks == 0) {
            std.debug.print("derived {d}/{d}: l2 {d} from L1 {d}, {d} matched, " ++
                "{d} mismatched, L1 origin {d}\n", .{
                derived,
                checker.range.count(),
                checker.cursor.block_info.number,
                derived_from,
                checker.matched,
                checker.mismatches,
                checker.cursor.l1_origin.number,
            });
        }
        if (derived % cadence_interval_blocks == 0) try checker.sample_reference(derived_from);
    }

    /// Informational: the derived safe head against the reference's safe and finalized.
    fn sample_reference(checker: *Checker, derived_from: u64) !void {
        const safe = try checker.reference_number("safe");
        const finalized = try checker.reference_number("finalized");
        const head = checker.cursor.block_info.number;
        const head_signed: i64 = @intCast(head);
        std.debug.print("cadence: derived safe l2 {d} (from L1 {d}); reference safe {d} " ++
            "({d} blocks), finalized {d} ({d} blocks); {d} safe-head jumps so far\n", .{
            head,
            derived_from,
            safe,
            @as(i64, @intCast(safe)) - head_signed,
            finalized,
            @as(i64, @intCast(finalized)) - head_signed,
            checker.cadence.jumps_total(),
        });
    }

    fn print_endpoint(endpoint: *const Endpoint) void {
        const stats = endpoint.stats;
        std.debug.print("derive-check: endpoint {s}: {d} requests, {d} MiB, {d} 429s, " ++
            "{d} failures, {d} timeouts, {d} bad responses\n", .{
            endpoint.name,
            stats.requests,
            stats.bytes >> 20,
            stats.limited,
            stats.failures,
            stats.timeouts,
            stats.invalid,
        });
    }

    fn summary(checker: *Checker, outcome: []const u8) void {
        const now_ms = Io.Clock.awake.now(checker.io).toMilliseconds();
        const elapsed_s = @divTrunc(now_ms - checker.started_ms, 1000);
        const first = checker.first_derived orelse checker.start;
        const last_l1 = if (checker.pipeline.origin()) |origin| origin.number else 0;
        const cadence = &checker.cadence;
        const mean = cadence.gap_l1_mean_tenths();
        std.debug.print("derive-check: {s} start l2 {d} (L1 origin {d}), reset walk-back " ++
            "to l2 {d} (L1 origin {d})\n", .{
            checker.flags.defaults.name,
            checker.start.block_info.number,
            checker.start.l1_origin.number,
            checker.walk_back.block_info.number,
            checker.walk_back.l1_origin.number,
        });
        std.debug.print("derive-check: derived l2 {d}..{d} ({d} of {d} blocks, L1 origins " ++
            "{d}..{d}); L1 traversed {d}..{d} ({d} blocks fetched, {d} with blobs, " ++
            "{d} blobs), {d} resets\n", .{
            first.block_info.number,
            checker.cursor.block_info.number,
            checker.derived_count(),
            checker.range.count(),
            first.l1_origin.number,
            checker.cursor.l1_origin.number,
            checker.l1_first,
            last_l1,
            checker.l1.blocks_fetched,
            checker.blobs.blocks,
            checker.blobs.blobs_fetched,
            checker.resets,
        });
        std.debug.print("derive-check: compared {d} blocks: {d} matched, {d} mismatched " ++
            "({d} by transactions root and header, {d} full bodies)\n", .{
            checker.matched + checker.mismatches,
            checker.matched,
            checker.mismatches,
            checker.by_root,
            checker.full_bodies,
        });
        std.debug.print("derive-check: cadence: {d} safe-head jumps, one every {d}.{d} L1 " ++
            "blocks (max {d}), {d} L2 blocks per jump (max {d})\n", .{
            cadence.jumps_total(),
            mean / 10,
            mean % 10,
            cadence.gap_l1_max,
            cadence.blocks_per_jump_mean(),
            cadence.jump_blocks_max_total(),
        });
        print_endpoint(checker.l1_endpoint);
        print_endpoint(checker.beacon_endpoint);
        print_endpoint(checker.reference);
        std.debug.print("derive-check: {d} s, result {s}\n", .{ elapsed_s, outcome });
    }
};

/// Chooses the range, preloads the start, checks the blob window, resets, and derives.
fn run(checker: *Checker) !u8 {
    checker.started_ms = Io.Clock.awake.now(checker.io).toMilliseconds();
    const safe = try checker.reference_number("safe");
    const finalized = try checker.reference_number("finalized");
    std.debug.print("reference: safe {d}, finalized {d}\n", .{ safe, finalized });
    const genesis = checker.rollup.genesis.l2.number;
    const flags = checker.flags;
    checker.range = start_rules.choose_range(safe, genesis, flags.from, flags.blocks) catch |err| {
        std.debug.print("derive-check: no range: {t}\n", .{err});
        return 2;
    };
    try checker.preload();
    const walk_back_l1 = try checker.l1.l1_block_info_by_number(checker.walk_back.l1_origin.number);
    const now_s: u64 = @intCast(Io.Clock.real.now(checker.io).toSeconds());
    if (!start_rules.blobs_retained(walk_back_l1.timestamp, now_s)) {
        std.debug.print("derive-check: L1 {d} is outside the blob window\n", .{
            walk_back_l1.number,
        });
        return 2;
    }
    checker.cursor = checker.start;
    try checker.reset_pipeline();
    checker.l1_first = checker.pipeline.origin().?.number;
    std.debug.print("pipeline reset to L1 {d}; deriving l2 {d}..{d}\n", .{
        checker.l1_first,
        checker.range.start + 1,
        checker.range.last,
    });
    checker.derive_all() catch |err| {
        std.debug.print("derive-check: stopped: {t}\n", .{err});
        checker.summary("INCOMPLETE");
        return 2;
    };
    try checker.sample_reference(checker.pipeline.origin().?.number);
    if (checker.mismatches > 0) {
        checker.summary("FAIL");
        return 1;
    }
    assert(checker.cursor.block_info.number == checker.range.last);
    checker.summary("PASS");
    return 0;
}

/// KZG trusted setup and scratch for blob verification, heap-allocated once (large).
const Kzg = struct {
    storage: kzg.blob.Settings.Storage,
    workspace: kzg.blob.Workspace,
    settings: kzg.blob.Settings,
};

const Endpoints = struct { l1: Endpoint, beacon: Endpoint, l2: Endpoint };

fn init_endpoints(endpoints: *Endpoints, gpa: std.mem.Allocator, io: Io, flags: Flags) !void {
    const chain = flags.defaults;
    const l1_url = flags.l1_url orelse chain.l1_url;
    endpoints.l1 = try Endpoint.init(gpa, io, "l1", l1_url, 64 << 20, 100);
    errdefer endpoints.l1.deinit();
    const beacon_url = flags.beacon_url orelse chain.beacon_url;
    endpoints.beacon = try Endpoint.init(gpa, io, "beacon", beacon_url, 32 << 20, 200);
    errdefer endpoints.beacon.deinit();
    // The public L2 endpoint limits calls to 25 per second, counting each batch element.
    const l2_url = flags.l2_url orelse chain.l2_url;
    endpoints.l2 = try Endpoint.init(gpa, io, "l2", l2_url, 32 << 20, 55);
    endpoints.l1.verbose = flags.verbose;
    endpoints.beacon.verbose = flags.verbose;
    endpoints.l2.verbose = flags.verbose;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse_flags(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const gpa = init.gpa;
    const chain = flags.defaults.chain;
    const rollup = start_rules.rollup_config_for(chain);
    const l1_config = chains.l1_by_chain_id(rollup.l1_chain_id) orelse return error.UnknownL1;
    var bpo: [2]L1BlobSchedule.Entry = undefined;
    const blob_schedule = base.proof.client.client.blob_schedule_of(l1_config, &bpo);

    const endpoints = try gpa.create(Endpoints);
    defer gpa.destroy(endpoints);
    try init_endpoints(endpoints, gpa, init.io, flags);
    defer endpoints.l2.deinit();
    defer endpoints.beacon.deinit();
    defer endpoints.l1.deinit();
    const setup = try gpa.create(Kzg);
    defer gpa.destroy(setup);
    setup.settings = try kzg.blob.Settings.init(&setup.storage);
    const blob_max = check_sources.BlobSource.blobs_max;
    const fetched = try gpa.alloc(base.consensus.derive.blob.Blob, blob_max);
    defer gpa.free(fetched);
    var pointers: [blob_max]*const base.consensus.derive.blob.Blob = undefined;

    var l1 = try check_sources.L1Source.init(gpa, &endpoints.l1, rollup.batch_inbox_address, 128);
    defer l1.deinit();
    var blobs = try check_sources.BlobSource.init(
        &endpoints.beacon,
        &setup.settings,
        &setup.workspace,
        fetched,
        &pointers,
    );
    var l2 = try check_sources.L2Chain.init(gpa, &endpoints.l2, &rollup, 1 << 15);
    defer l2.deinit(gpa);
    var checker: Checker = .{
        .io = init.io,
        .flags = flags,
        .rollup = &rollup,
        .fee_params = start_rules.fee_params_canyon(chain),
        .l1 = &l1,
        .blobs = &blobs,
        .l2 = &l2,
        .l1_endpoint = &endpoints.l1,
        .beacon_endpoint = &endpoints.beacon,
        .reference = &endpoints.l2,
        .pipeline = Pipeline.init(gpa, &rollup, &blob_schedule, .{}),
        .headers = .{ .arena = .init(gpa) },
        .arena = .init(gpa),
    };
    defer checker.pipeline.deinit();
    defer checker.headers.arena.deinit();
    defer checker.arena.deinit();
    return run(&checker);
}

test "derive check: flags" {
    const flags = try parse_flags(&.{ "--from", "10", "--blocks", "20", "--verbose" });
    try std.testing.expectEqual(@as(?u64, 10), flags.from);
    try std.testing.expectEqual(@as(u64, 20), flags.blocks);
    try std.testing.expect(flags.verbose);
    try std.testing.expectEqualStrings("base-sepolia", flags.defaults.name);
    const mainnet = try parse_flags(&.{ "--chain", "base-mainnet" });
    try std.testing.expectEqual(@as(u64, 8453), mainnet.defaults.chain.chain_id);
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{"--blocks"}));
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{ "--blocks", "0" }));
    try std.testing.expectError(error.InvalidArguments, parse_flags(&.{ "--chain", "x" }));
}

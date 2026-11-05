//! The flashblocks state processor. Mirrors base/base `processor.rs` (`StateProcessor`):
//! flashblocks and canonical blocks arrive as events; flashblocks extend the pending blocks
//! after sequence validation, canonical blocks reconcile them (catch up, reorg, depth
//! limit), and flashblocks whose parent is not canonical yet wait in the cache and replay
//! after the canonical block lands.
//!
//! Differences from base/base, all recorded in the lane file:
//! - The canonical chain is what `on_canonical` reported (`canonical_tip`), not a provider
//!   lookup. With no canonical block seen (`null`) every parent counts as known.
//! - Payload id and parent hash continuity are checked (`validation.validate_continuity`):
//!   a payload id change mid-block clears the pending blocks like a gap; a next block
//!   that does not build on the latest hash restarts the pending blocks from it.
//! - Execution goes through the `StateBuilder` interface (`state.zig`).

const std = @import("std");
const assert = std.debug.assert;

const flashblocks = @import("../../common/flashblocks/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const validation = @import("validation.zig");
const pending_module = @import("pending.zig");
const cache_module = @import("cache.zig");
const state = @import("state.zig");

const B256 = primitives.B256;
const Flashblock = flashblocks.Flashblock;
pub const PendingBlocks = pending_module.PendingBlocks;
pub const Cache = cache_module.Cache;

pub const Options = struct {
    /// base/base `max_pending_blocks_depth`.
    max_depth: u64 = 5,
    limits: pending_module.Limits = .{},
    cache: cache_module.Options = .{},
    /// Arena for decoding one cached flashblock on replay.
    decode_arena_bytes: u32 = 8 << 20,
    /// Latest canonical block at startup, if known (base/base reads `best_block_number`).
    canonical_tip: ?u64 = null,
};

/// base/base `Metrics` counters for the processor.
pub const Stats = struct {
    applied: u64 = 0,
    duplicates: u64 = 0,
    superseded: u64 = 0,
    unexpected_order: u64 = 0,
    cached: u64 = 0,
    replayed: u64 = 0,
    processing_errors: u64 = 0,
    missing_first: u64 = 0,
    evicted_blocks: u64 = 0,
    clear_catchup: u64 = 0,
    clear_reorg: u64 = 0,
    drop_stale: u64 = 0,
};

const ProcessError = error{ MissingCanonicalHeader, MissingFirstFlashblock, Rejected };

pub fn Processor(comptime StateBuilder: type) type {
    comptime state.assert_interface(StateBuilder);
    return struct {
        const Self = @This();

        options: Options,
        pending: PendingBlocks,
        cache: Cache,
        state_builder: *StateBuilder,
        canonical_tip: ?u64,
        replay_buffer: []u8,
        decode_buffer: []u8,
        stats: Stats = .{},

        pub fn init(
            allocator: std.mem.Allocator,
            options: Options,
            state_builder: *StateBuilder,
        ) !Self {
            assert(options.decode_arena_bytes > 0);
            var pending = try PendingBlocks.init(allocator, options.limits);
            errdefer pending.deinit(allocator);
            var cache = try Cache.init(allocator, options.cache, options.canonical_tip);
            errdefer cache.deinit(allocator);
            const replay_buffer = try allocator.alloc(u8, options.cache.bytes_max);
            errdefer allocator.free(replay_buffer);
            const decode_buffer = try allocator.alloc(u8, options.decode_arena_bytes);
            return .{
                .options = options,
                .pending = pending,
                .cache = cache,
                .state_builder = state_builder,
                .canonical_tip = options.canonical_tip,
                .replay_buffer = replay_buffer,
                .decode_buffer = decode_buffer,
            };
        }

        pub fn deinit(processor: *Self, allocator: std.mem.Allocator) void {
            allocator.free(processor.decode_buffer);
            allocator.free(processor.replay_buffer);
            processor.cache.deinit(allocator);
            processor.pending.deinit(allocator);
            processor.* = undefined;
        }

        /// base/base `apply_flashblock`.
        pub fn on_flashblock(processor: *Self, flashblock: Flashblock) void {
            const block_number = flashblock.metadata.block_number;
            if (processor.canonical_tip) |tip| {
                if (block_number <= tip) {
                    processor.stats.superseded += 1;
                    return;
                }
            }
            processor.drop_if_stale();
            processor.process_flashblock(&flashblock) catch |err| switch (err) {
                error.MissingCanonicalHeader => {
                    if (processor.cache.insert(flashblock)) {
                        processor.stats.cached += 1;
                    } else {
                        processor.stats.processing_errors += 1;
                    }
                },
                error.MissingFirstFlashblock => {
                    // Expected after a reset; cached only when its predecessor is.
                    processor.stats.missing_first += 1;
                    if (flashblock.index > 0 and
                        processor.cache.has_flashblock(block_number, flashblock.index - 1) and
                        processor.cache.insert(flashblock))
                    {
                        processor.stats.cached += 1;
                    }
                },
                error.Rejected => processor.stats.processing_errors += 1,
            };
        }

        /// base/base `process_canonical_block` plus the cache drain in `start`.
        /// `transaction_hashes` are the canonical block's, in order.
        pub fn on_canonical(
            processor: *Self,
            block_number: u64,
            transaction_hashes: []const B256,
        ) void {
            const tip = if (processor.canonical_tip) |t| @max(t, block_number) else block_number;
            processor.canonical_tip = tip;
            processor.drop_if_stale();
            if (!processor.pending.is_empty()) {
                processor.reconcile(block_number, tip, transaction_hashes);
            }
            processor.cache.update_canonical(block_number);
            processor.replay_cached(block_number +| 1);
            assert(processor.canonical_tip.? >= block_number);
        }

        fn reconcile(processor: *Self, notified: u64, tip: u64, hashes: []const B256) void {
            const tracked: []const B256 = if (processor.pending.get(notified)) |block|
                block.hashes()
            else
                &.{};
            const reorg = validation.detect_reorg(tracked, hashes).is_reorg();
            const strategy = validation.reconcile(
                processor.pending.earliest_block_number(),
                processor.pending.latest_block_number(),
                tip,
                processor.options.max_depth,
                reorg,
            );
            switch (strategy) {
                .no_pending_state => unreachable, // Checked by the caller.
                .catch_up => {
                    processor.stats.clear_catchup += 1;
                    processor.clear();
                },
                .handle_reorg, .depth_limit_exceeded => {
                    if (strategy == .handle_reorg) processor.stats.clear_reorg += 1;
                    processor.pending.drop_through(tip);
                    processor.rebuild();
                },
                .@"continue" => processor.rebuild(),
            }
        }

        /// Re-executes every held block from a fresh state (base/base `build_pending_state`
        /// over the retained flashblocks), then applies the publish-time tip check.
        fn rebuild(processor: *Self) void {
            processor.state_builder.reset();
            const pending = &processor.pending;
            var position: u32 = 0;
            while (position < pending.count) : (position += 1) {
                const block = pending.at(position);
                processor.state_builder.execute(block, 0, block.transaction_count) catch {
                    processor.stats.processing_errors += 1;
                    return processor.clear();
                };
            }
            if (pending.is_empty()) return;
            processor.publish_check();
        }

        fn replay_cached(processor: *Self, block_number: u64) void {
            var bound: u32 = @intCast(processor.cache.entries.len);
            while (bound > 0) : (bound -= 1) {
                const buffer = processor.replay_buffer;
                const json = processor.cache.take_lowest(block_number, buffer) orelse break;
                var fixed: std.heap.FixedBufferAllocator = .init(processor.decode_buffer);
                // The cache holds only what `encode_json` produced from a decoded flashblock.
                const flashblock = flashblocks.decode_json(fixed.allocator(), json) catch {
                    processor.stats.processing_errors += 1;
                    continue;
                };
                processor.stats.replayed += 1;
                processor.on_flashblock(flashblock);
            }
        }

        /// base/base `load_pending_or_drop_stale`.
        fn drop_if_stale(processor: *Self) void {
            const tip = processor.canonical_tip orelse return;
            const latest = processor.pending.latest_block_number() orelse return;
            if (tip -| latest <= processor.options.max_depth) return;
            processor.stats.drop_stale += 1;
            processor.clear();
        }

        /// base/base `extends_canonical_tip` (checked before publishing a snapshot).
        fn publish_check(processor: *Self) void {
            const tip = processor.canonical_tip orelse return;
            const latest = processor.pending.latest_block_number().?;
            const near = tip -| latest <= processor.options.max_depth;
            if (near and latest > tip) return;
            processor.stats.drop_stale += 1;
            processor.clear();
        }

        fn clear(processor: *Self) void {
            processor.pending.clear();
            processor.state_builder.reset();
            assert(processor.pending.is_empty());
        }

        fn process_flashblock(processor: *Self, flashblock: *const Flashblock) ProcessError!void {
            validation.validate_shape(flashblock) catch |err| {
                if (err == error.MissingBase and processor.pending.is_empty()) {
                    return error.MissingFirstFlashblock;
                }
                return error.Rejected;
            };
            const latest = processor.pending.latest() orelse {
                if (flashblock.index != 0) return error.MissingFirstFlashblock;
                return processor.start_fresh(flashblock);
            };
            const result = validation.validate_sequence(
                latest.block_number,
                latest.latest_index(),
                flashblock.metadata.block_number,
                flashblock.index,
                flashblock.metadata.prev_flashblock_id,
            );
            switch (result) {
                .next_in_sequence, .first_of_next_block => {},
                .duplicate => {
                    processor.stats.duplicates += 1;
                    return;
                },
                else => {
                    processor.stats.unexpected_order += 1;
                    return processor.clear();
                },
            }
            validation.validate_continuity(
                result,
                flashblock,
                latest.payload_id,
                latest.header.block_hash,
            ) catch |err| {
                processor.stats.unexpected_order += 1;
                processor.clear();
                if (err == error.PayloadIdMismatch) return;
                // A next block on another parent: the pending blocks were reorged away.
                processor.stats.clear_reorg += 1;
                return processor.start_fresh(flashblock);
            };
            if (result == .next_in_sequence) {
                return processor.extend(flashblock);
            }
            return processor.next_block(flashblock);
        }

        /// The first flashblock with no pending blocks (base/base `build_pending_state`
        /// from a single flashblock): its parent must be canonical.
        fn start_fresh(processor: *Self, flashblock: *const Flashblock) ProcessError!void {
            assert(flashblock.index == 0);
            assert(processor.pending.is_empty());
            const block_number = flashblock.metadata.block_number;
            if (processor.canonical_tip) |tip| {
                if (block_number - 1 > tip) return error.MissingCanonicalHeader;
            }
            processor.state_builder.reset();
            return processor.next_block(flashblock);
        }

        fn next_block(processor: *Self, flashblock: *const Flashblock) ProcessError!void {
            const evicted = processor.pending.begin_block(flashblock) catch return error.Rejected;
            if (evicted) processor.stats.evicted_blocks += 1;
            const block = processor.pending.latest().?;
            assert(block.block_number == flashblock.metadata.block_number);
            return processor.execute_latest(block);
        }

        fn extend(processor: *Self, flashblock: *const Flashblock) ProcessError!void {
            processor.pending.append(flashblock) catch return error.Rejected;
            const block = processor.pending.latest().?;
            assert(block.latest_index() == flashblock.index);
            return processor.execute_latest(block);
        }

        fn execute_latest(processor: *Self, block: *const pending_module.Block) ProcessError!void {
            const range = block.flashblock_transactions(@intCast(block.latest_index()));
            processor.state_builder.execute(block, range[0], range[1]) catch {
                processor.clear();
                return error.Rejected;
            };
            processor.stats.applied += 1;
            processor.publish_check();
        }
    };
}

test {
    _ = @import("processor_test.zig");
}

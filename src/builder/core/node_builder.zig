//! The payload service wired into the execution node's Engine API. `NodeBuilder(IO)` owns
//! the rejection cache, the single-shot block builder and the payload service, and plugs
//! into `Chain.payload_builder`, so the node's `engine_forkchoiceUpdated` (with attributes)
//! and `engine_getPayload` handlers go through the service instead of the synchronous
//! `Chain` build (base/base: the reth `PayloadBuilderService` driving
//! `crates/builder/core` jobs; one-shot path, no flashblocks).
//!
//! - FCU with attributes: the service's time moves to now and a job starts; the handler
//!   returns at once. A zero-delay IO timer then ticks the service, which builds the block
//!   (attribute transactions, then pool transactions until the 150 ms cutoff) and seals.
//! - getPayload: the service resolves the job. A job not built yet seals immediately with
//!   the cutoff moved to now, so getPayload never waits past the slot end. The chain then
//!   imports the sealed block through its regular insert path.
//! - A second IO timer ticks at the sealed job's expiry to drop it unresolved.
//!
//! Time is the IO's monotonic clock, for both the timers and the in-build cutoff reads.
//! All IO goes through `IO` (production backend or `SimIo`). Pinned once `init` ran.

const std = @import("std");
const assert = std.debug.assert;

const payload = @import("../../execution/payload/root.zig");
const engine = @import("../../execution/engine/root.zig");
const chain_module = @import("../../execution/node/chain.zig");
const io_module = @import("../../utilities/io/root.zig");
const best_txs = @import("best_txs.zig");
const builder_module = @import("builder.zig");
const service_module = @import("service.zig");
const timing = @import("timing.zig");

const Chain = chain_module.Chain;
const BlockBuilder = builder_module.BlockBuilder;
pub const Service = service_module.Service;

pub const Config = struct {
    timing: timing.Config = .{},
    builder: builder_module.Config = .{},
    /// base/base `--builder.rejection-cache-max-capacity`.
    rejection_cache_capacity: u32 = best_txs.rejection_cache_capacity_default,
    /// base/base `--builder.rejection-cache-ttl-secs`.
    rejection_cache_ttl_ns: u64 = best_txs.rejection_cache_ttl_ns_default,
};

pub fn NodeBuilder(comptime IO: type) type {
    return struct {
        const Self = @This();

        io: *IO,
        chain: *Chain,
        cache: best_txs.RejectionCache,
        builder: BlockBuilder,
        service: Service,
        build_completion: IO.Completion = .{},
        build_armed: bool = false,
        expiry_completion: IO.Completion = .{},
        expiry_armed: bool = false,
        timer_failures: u64 = 0,

        /// Builds in place and installs itself as `chain.payload_builder`.
        pub fn init(
            node_builder: *Self,
            allocator: std.mem.Allocator,
            io: *IO,
            chain: *Chain,
            config: Config,
        ) !void {
            assert(chain.payload_builder == null);
            try config.timing.validate();
            node_builder.* = .{
                .io = io,
                .chain = chain,
                .cache = undefined,
                .builder = undefined,
                .service = undefined,
            };
            node_builder.cache = try best_txs.RejectionCache.init(
                allocator,
                config.rejection_cache_capacity,
                config.rejection_cache_ttl_ns,
            );
            errdefer node_builder.cache.deinit(allocator);
            node_builder.builder = try BlockBuilder.init(
                allocator,
                &node_builder.cache,
                config.builder,
            );
            errdefer node_builder.builder.deinit(allocator);
            const clock = builder_module.Clock.of(Self, node_builder);
            node_builder.service = try Service.init(
                &node_builder.builder,
                chain,
                clock,
                config.timing,
            );
            node_builder.service.set_now(io.now_monotonic_ns());
            chain.payload_builder = .{
                .context = node_builder,
                .start = start,
                .resolve = resolve,
            };
            assert(chain.payload_builder != null);
        }

        /// Uninstalls from the chain. Pending timers must not fire afterwards (the IO loop
        /// has stopped).
        pub fn deinit(node_builder: *Self, allocator: std.mem.Allocator) void {
            assert(node_builder.chain.payload_builder.?.context == @as(*anyopaque, node_builder));
            node_builder.chain.payload_builder = null;
            node_builder.builder.deinit(allocator);
            node_builder.cache.deinit(allocator);
            node_builder.* = undefined;
        }

        /// The builder `Clock`: the IO's monotonic time.
        pub fn now_ns(node_builder: *Self) u64 {
            const now = node_builder.io.now_monotonic_ns();
            assert(now <= timing.time_ns_max);
            return now;
        }

        fn start(
            context: *anyopaque,
            id: payload.PayloadId,
            parent_hash: [32]u8,
            attributes: *const payload.PayloadAttributes,
        ) engine.EngineError!void {
            const node_builder: *Self = @ptrCast(@alignCast(context));
            const service = &node_builder.service;
            service.set_now(node_builder.now_ns());
            service.send_new_payload(id, parent_hash, attributes) catch {
                return error.InvalidPayloadAttributes;
            };
            assert(service.next_deadline_ns() != null);
            node_builder.arm_build();
        }

        fn resolve(context: *anyopaque, id: payload.PayloadId) chain_module.Resolved {
            const node_builder: *Self = @ptrCast(@alignCast(context));
            const service = &node_builder.service;
            service.set_now(node_builder.now_ns());
            const result = service.resolve(id) orelse return .unknown;
            const best = result catch return .failed;
            assert(std.mem.eql(u8, &best.id, &id));
            return .{ .sealed = .{
                .header = best.header,
                .block_hash = best.block_hash,
                .block_value = best.block_value,
                .transactions = best.transactions,
                .senders = best.senders,
                .withdrawals = best.withdrawals,
            } };
        }

        fn arm_build(node_builder: *Self) void {
            if (node_builder.build_armed) return;
            node_builder.build_armed = true;
            const completion = &node_builder.build_completion;
            node_builder.io.timeout(*Self, node_builder, on_build, completion, 0);
            assert(node_builder.build_armed);
        }

        /// Arms the expiry timer for the active job, unless it is already armed (it then
        /// fires early, ticks, and re-arms for the remaining time).
        fn arm_expiry(node_builder: *Self) void {
            if (node_builder.expiry_armed) return;
            const deadline_ns = node_builder.service.next_deadline_ns() orelse return;
            const now = node_builder.now_ns();
            const delay_ns = deadline_ns -| now;
            node_builder.expiry_armed = true;
            const completion = &node_builder.expiry_completion;
            node_builder.io.timeout(*Self, node_builder, on_expiry, completion, delay_ns);
            assert(node_builder.expiry_armed);
        }

        fn on_build(
            node_builder: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            assert(completion == &node_builder.build_completion);
            assert(node_builder.build_armed);
            node_builder.build_armed = false;
            result catch {
                node_builder.timer_failures += 1;
                return; // Canceled at shutdown; a getPayload still seals on demand.
            };
            node_builder.service.tick(node_builder.now_ns());
            node_builder.arm_expiry();
        }

        fn on_expiry(
            node_builder: *Self,
            completion: *IO.Completion,
            result: io_module.TimeoutError!void,
        ) void {
            assert(completion == &node_builder.expiry_completion);
            assert(node_builder.expiry_armed);
            node_builder.expiry_armed = false;
            result catch {
                node_builder.timer_failures += 1;
                return;
            };
            node_builder.service.tick(node_builder.now_ns());
            node_builder.arm_expiry();
        }
    };
}

test {
    _ = @import("node_builder_test.zig");
}

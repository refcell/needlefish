//! The payload-builder multiplexer. Mirrors base/base `crates/builder/multiplex`
//! (`MultiplexRouter`).
//!
//! Every payload job is sent to two builders: the flashblocks builder and the basic
//! (one-shot) builder. One is *selected*: from the Denim upgrade on
//! (`OneShotPayloadBuilding`) the basic builder, before it the flashblocks builder. The
//! other runs a *shadow* build of the same attributes with `no_tx_pool = true`, so it
//! stays warm (state, caches) without competing for pool transactions. Reads
//! (`best_payload`, `payload_timestamp`, `resolve`) go to the builder that was selected
//! for that payload id; routes are remembered for the last 128 ids, and an unknown id
//! reads from the flashblocks builder. Builder events are forwarded only from the builder
//! that is selected at the event's timestamp.
//!
//! A builder whose channel closed is marked unhealthy for good: its errors become
//! `BuilderUnavailable`, and a "no payload" answer from an unhealthy builder does too.
//!
//! The builders are comptime interfaces (`Builder` below) so DST can drive fakes;
//! everything is synchronous, with no allocation.

const std = @import("std");
const assert = std.debug.assert;

const payload = @import("../../execution/payload/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const metrics = @import("../../utilities/metrics/root.zig");

pub const PayloadId = payload.PayloadId;
pub const PayloadAttributes = payload.PayloadAttributes;

/// base/base `MAX_PAYLOAD_ROUTES`.
pub const payload_routes_max = 128;

pub const Kind = enum { flashblocks, basic };

/// What a builder call can fail with. `channel_closed` is base/base's
/// `PayloadBuilderError::ChannelClosed`: the builder service is gone.
pub const BuilderError = error{ ChannelClosed, BuildFailed };

/// What the router returns: the builder's error, or `BuilderUnavailable` once the routed
/// builder is unhealthy.
pub const RouterError = error{ BuildFailed, BuilderUnavailable };

/// A builder event: new attributes accepted, or a payload built (with its block
/// timestamp).
pub const Event = union(enum) {
    attributes: struct { id: PayloadId, timestamp: u64 },
    built: struct { id: PayloadId, timestamp: u64 },

    pub fn timestamp(event: Event) u64 {
        return switch (event) {
            .attributes => |a| a.timestamp,
            .built => |b| b.timestamp,
        };
    }
};

pub const Metrics = struct {
    builds_dispatched: [2]metrics.Counter = .{ .{}, .{} },
    selected_builds: [2]metrics.Counter = .{ .{}, .{} },
    shadow_ok: [2]metrics.Counter = .{ .{}, .{} },
    shadow_failed: [2]metrics.Counter = .{ .{}, .{} },
    /// 1 while healthy; set to 1 by `Router.init`, 0 once a builder is unavailable.
    healthy: [2]metrics.Gauge = .{ .{}, .{} },
};

/// Routes one payload service between two builders. `Builder` must provide:
/// - `send_new_payload(*Builder, PayloadId, parent: [32]u8, *const PayloadAttributes)
///   BuilderError!void`
/// - `best_payload(*Builder, PayloadId) ?(BuilderError!Payload)`
/// - `payload_timestamp(*Builder, PayloadId) ?(BuilderError!u64)`
/// - `resolve(*Builder, PayloadId) ?(BuilderError!Payload)`
pub fn Router(comptime Builder: type, comptime Payload: type) type {
    return struct {
        const Self = @This();

        builders: [2]*Builder,
        healthy: [2]bool = .{ true, true },
        spec: *const chainspec.ChainSpec,
        routes_ids: [payload_routes_max]PayloadId = undefined,
        routes_basic: [payload_routes_max]bool = undefined,
        routes_head: u32 = 0,
        routes_count: u32 = 0,
        metrics: Metrics = .{},

        pub fn init(
            flashblocks: *Builder,
            basic: *Builder,
            spec: *const chainspec.ChainSpec,
        ) Self {
            assert(flashblocks != basic);
            var router: Self = .{ .builders = .{ flashblocks, basic }, .spec = spec };
            for (&router.metrics.healthy) |*gauge| gauge.set(1);
            return router;
        }

        /// base/base `OneShotPayloadBuilding` (a Denim feature).
        pub fn basic_selected_at(router: *const Self, timestamp: u64) bool {
            return router.spec.is_upgrade_active(.denim, timestamp);
        }

        pub fn is_healthy(router: *const Self, kind: Kind) bool {
            return router.healthy[@backingInt(kind)];
        }

        /// The builder that serves reads for `id` (flashblocks when unknown).
        pub fn selected_for(router: *const Self, id: PayloadId) Kind {
            var index: u32 = 0;
            while (index < router.routes_count) : (index += 1) {
                const slot = (router.routes_head + index) % payload_routes_max;
                if (std.mem.eql(u8, &router.routes_ids[slot], &id)) {
                    return if (router.routes_basic[slot]) .basic else .flashblocks;
                }
            }
            return .flashblocks;
        }

        pub fn record_route(router: *Self, id: PayloadId, selected: Kind) void {
            const basic = selected == .basic;
            var index: u32 = 0;
            while (index < router.routes_count) : (index += 1) {
                const slot = (router.routes_head + index) % payload_routes_max;
                if (std.mem.eql(u8, &router.routes_ids[slot], &id)) {
                    router.routes_basic[slot] = basic;
                    return;
                }
            }
            if (router.routes_count == payload_routes_max) {
                router.routes_head = (router.routes_head + 1) % payload_routes_max;
                router.routes_count -= 1;
            }
            const slot = (router.routes_head + router.routes_count) % payload_routes_max;
            router.routes_ids[slot] = id;
            router.routes_basic[slot] = basic;
            router.routes_count += 1;
            assert(router.routes_count <= payload_routes_max);
        }

        /// base/base `handle_build_new_payload`: dispatches to both builders and returns
        /// the selected builder's result. The shadow's result only feeds metrics.
        pub fn build_new_payload(
            router: *Self,
            id: PayloadId,
            parent: [32]u8,
            attributes: *const PayloadAttributes,
        ) RouterError!void {
            const selected: Kind = if (router.basic_selected_at(attributes.timestamp))
                .basic
            else
                .flashblocks;
            const shadow: Kind = if (selected == .basic) .flashblocks else .basic;
            router.record_route(id, selected);
            var shadow_attributes = attributes.*;
            shadow_attributes.no_tx_pool = true;
            router.metrics.builds_dispatched[0].increment();
            router.metrics.builds_dispatched[1].increment();
            router.metrics.selected_builds[@backingInt(selected)].increment();
            const shadow_builder = router.builders[@backingInt(shadow)];
            const shadow_result = shadow_builder.send_new_payload(id, parent, &shadow_attributes);
            if (router.map_error(shadow, shadow_result)) |_| {
                router.metrics.shadow_ok[@backingInt(shadow)].increment();
            } else |_| {
                router.metrics.shadow_failed[@backingInt(shadow)].increment();
            }
            const builder = router.builders[@backingInt(selected)];
            return router.map_error(selected, builder.send_new_payload(id, parent, attributes));
        }

        pub fn best_payload(router: *Self, id: PayloadId) ?(RouterError!Payload) {
            const kind = router.selected_for(id);
            const builder = router.builders[@backingInt(kind)];
            return router.map_read(Payload, kind, builder.best_payload(id));
        }

        pub fn payload_timestamp(router: *Self, id: PayloadId) ?(RouterError!u64) {
            const kind = router.selected_for(id);
            const builder = router.builders[@backingInt(kind)];
            return router.map_read(u64, kind, builder.payload_timestamp(id));
        }

        pub fn resolve(router: *Self, id: PayloadId) ?(RouterError!Payload) {
            const kind = router.selected_for(id);
            const builder = router.builders[@backingInt(kind)];
            return router.map_read(Payload, kind, builder.resolve(id));
        }

        /// base/base `handle_subscribe` filter: forward `event` from `source` only when
        /// `source` is the builder selected at the event's timestamp.
        pub fn forwards_event(router: *const Self, source: Kind, event: Event) bool {
            const basic = router.basic_selected_at(event.timestamp());
            return basic == (source == .basic);
        }

        /// A builder's event stream ended: it is gone.
        pub fn on_events_closed(router: *Self, source: Kind) void {
            router.mark_unavailable(source);
        }

        fn mark_unavailable(router: *Self, kind: Kind) void {
            router.healthy[@backingInt(kind)] = false;
            router.metrics.healthy[@backingInt(kind)].set(0);
            assert(!router.is_healthy(kind));
        }

        fn map_error(router: *Self, kind: Kind, result: BuilderError!void) RouterError!void {
            result catch |err| switch (err) {
                error.ChannelClosed => {
                    router.mark_unavailable(kind);
                    return error.BuilderUnavailable;
                },
                error.BuildFailed => return error.BuildFailed,
            };
        }

        /// base/base `map_read_result`.
        fn map_read(
            router: *Self,
            comptime T: type,
            kind: Kind,
            result: ?(BuilderError!T),
        ) ?(RouterError!T) {
            const answer = result orelse {
                if (!router.is_healthy(kind)) return error.BuilderUnavailable;
                return null;
            };
            const value = answer catch |err| switch (err) {
                error.ChannelClosed => {
                    router.mark_unavailable(kind);
                    return error.BuilderUnavailable;
                },
                error.BuildFailed => return error.BuildFailed,
            };
            return value;
        }
    };
}

test {
    _ = @import("root_test.zig");
}

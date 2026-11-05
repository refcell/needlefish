//! Sequencer conductor client (base/base `actors/sequencer/conductor.rs`, `--conductor.rpc`):
//! op-conductor decides which sequencer of a high-availability set leads. With a conductor
//! the sequencer commits every sealed payload with `conductor_commitUnsafePayload` before
//! inserting and gossiping it, refuses `admin_startSequencer` unless `conductor_leader`, and
//! forwards `admin_overrideLeader` as `conductor_overrideLeader`.
//!
//! `Conductor(IO)` runs one request at a time. The admin API is synchronous, so leadership
//! is polled every `leader_poll_interval_ns` and answered from the last poll (base/base asks
//! on each start). Commits are keyed by block hash: the seal task calls `commit` until it
//! succeeds; failures are retried after `retry_interval_ns`. An override is queued and sent
//! when the client is idle. JSON-RPC commits only (no SSZ binary endpoint).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const primitives = @import("../../common/primitives/root.zig");
const engine_json = @import("../sources/engine_json.zig");
const task = @import("../engine/task.zig");

const B256 = primitives.B256;
const ExecutionPayload = task.ExecutionPayload;

pub const leader_poll_interval_ns: u64 = std.time.ns_per_s;
pub const retry_interval_ns: u64 = 100 * std.time.ns_per_ms;
/// An 8 MiB payload as JSON hex, like the engine client's `newPayload`.
pub const request_size_max: u32 = 8 * 1024 * 1024 + 64 * 1024;

pub const Stats = struct {
    commits: u64 = 0,
    commit_failures: u64 = 0,
    leader_polls: u64 = 0,
    leader_failures: u64 = 0,
    overrides: u64 = 0,
    override_failures: u64 = 0,
};

const Commit = struct { payload: *const ExecutionPayload, root: ?B256 };
const Request = union(enum) { leader, override, commit: B256 };

pub fn Conductor(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);

        io: *IO,
        client: Rpc,
        in_flight: ?Request = null,
        /// Leadership from the last successful poll; null until then or after a failure.
        leader: ?bool = null,
        leader_polled_ns: ?u64 = null,
        override_pending: bool = false,
        committed: ?B256 = null,
        commit_retry_at_ns: u64 = 0,
        stats: Stats = .{},

        /// `conductor` must not move after `init` while a request is in flight.
        pub fn init(
            conductor: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
        ) !void {
            assert(http_options.send_buffer_size >= request_size_max);
            const client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            conductor.* = .{ .io = io, .client = client };
            assert(conductor.in_flight == null);
        }

        pub fn deinit(conductor: *Self) void {
            assert(conductor.in_flight == null);
            conductor.client.deinit();
            conductor.* = undefined;
        }

        pub fn busy(conductor: *const Self) bool {
            return conductor.in_flight != null;
        }

        /// Sends a queued override, else polls leadership when due.
        pub fn tick(conductor: *Self) void {
            conductor.client.http.tick();
            if (conductor.in_flight != null or conductor.client.http.busy()) return;
            if (conductor.override_pending) {
                conductor.override_pending = false;
                return conductor.start(.override, &no_params, write_no_params);
            }
            const now_ns = conductor.io.now_monotonic_ns();
            if (conductor.leader_polled_ns) |polled_ns| {
                if (now_ns - polled_ns < leader_poll_interval_ns) return;
            }
            conductor.leader_polled_ns = now_ns;
            conductor.start(.leader, &no_params, write_no_params);
        }

        /// `admin_overrideLeader`: queues `conductor_overrideLeader`.
        pub fn request_override(conductor: *Self) void {
            conductor.override_pending = true;
            assert(conductor.override_pending);
        }

        /// The `task.Committer` interface for the engine task queue.
        pub fn committer(conductor: *Self) task.Committer {
            return .{ .context = conductor, .commit = commit_erased };
        }

        fn commit_erased(
            context: *anyopaque,
            payload: *const ExecutionPayload,
            root: ?B256,
        ) error{NotAvailable}!void {
            const conductor: *Self = @ptrCast(@alignCast(context));
            return conductor.commit(payload, root);
        }

        /// Returns once the conductor accepted this payload; `NotAvailable` until then.
        pub fn commit(
            conductor: *Self,
            payload: *const ExecutionPayload,
            root: ?B256,
        ) error{NotAvailable}!void {
            const hash = payload.block_hash;
            if (conductor.committed) |committed| {
                if (committed.eql(hash)) return;
            }
            conductor.client.http.tick();
            if (conductor.in_flight != null or conductor.client.http.busy()) {
                return error.NotAvailable;
            }
            if (conductor.io.now_monotonic_ns() < conductor.commit_retry_at_ns) {
                return error.NotAvailable;
            }
            const params: Commit = .{ .payload = payload, .root = root };
            conductor.start(.{ .commit = hash }, &params, write_commit);
            return error.NotAvailable;
        }

        fn start(
            conductor: *Self,
            request: Request,
            params: anytype,
            comptime write: rpc.client.ParamsWriter(@TypeOf(params)),
        ) void {
            assert(conductor.in_flight == null);
            conductor.in_flight = request;
            const method = switch (request) {
                .leader => "conductor_leader",
                .override => "conductor_overrideLeader",
                .commit => "conductor_commitUnsafePayload",
            };
            conductor.client.call(*Self, conductor, on_result, method, params, write) catch {
                conductor.in_flight = null;
                conductor.record(request, false);
            };
        }

        fn on_result(
            conductor: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &conductor.client);
            const request = conductor.in_flight.?;
            conductor.in_flight = null;
            const outcome = result catch return conductor.record(request, false);
            const raw = switch (outcome) {
                .ok => |raw| raw,
                .rpc_error => return conductor.record(request, false),
            };
            switch (request) {
                .leader => {
                    const is_true = std.mem.eql(u8, raw, "true");
                    if (!is_true and !std.mem.eql(u8, raw, "false")) {
                        return conductor.record(request, false);
                    }
                    conductor.leader = is_true;
                },
                .commit => |hash| conductor.committed = hash,
                .override => {},
            }
            conductor.record(request, true);
        }

        fn record(conductor: *Self, request: Request, ok: bool) void {
            const stats = &conductor.stats;
            switch (request) {
                .leader => if (ok) {
                    stats.leader_polls += 1;
                } else {
                    stats.leader_failures += 1;
                    conductor.leader = null; // Unknown: starting is refused.
                },
                .override => if (ok) {
                    stats.overrides += 1;
                } else {
                    stats.override_failures += 1;
                },
                .commit => if (ok) {
                    stats.commits += 1;
                } else {
                    stats.commit_failures += 1;
                    const now_ns = conductor.io.now_monotonic_ns();
                    conductor.commit_retry_at_ns = now_ns + retry_interval_ns;
                },
            }
        }
    };
}

const no_params: void = {};

fn write_no_params(_: *const void, writer: *json.Writer) json.Writer.WriteError!void {
    _ = writer;
}

/// `[OpExecutionPayloadEnvelope]`: `{"executionPayload", "parentBeaconBlockRoot"}`.
fn write_commit(params: *const Commit, writer: *json.Writer) json.Writer.WriteError!void {
    try writer.begin_object();
    try writer.key("executionPayload");
    try engine_json.write_payload(writer, params.payload);
    if (params.root) |root| {
        try writer.key("parentBeaconBlockRoot");
        try writer.data(&root.bytes);
    }
    try writer.end_object();
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const sim_harness = @import("../sources/sim_harness.zig");
const FakeRpc = sim_harness.FakeRpc;
const SimConductor = Conductor(@import("../../utilities/io/root.zig").SimIo);

const test_http_options: http_client.Options = .{
    .send_buffer_size = request_size_max + 4096,
    .recv_buffer_size = sim_harness.client_options.recv_buffer_size,
    .limits = sim_harness.limits,
};

fn test_payload(hash_byte: u8) ExecutionPayload {
    return .{
        .parent_hash = .zero,
        .fee_recipient = .zero,
        .state_root = .zero,
        .receipts_root = .zero,
        .logs_bloom = .zero,
        .prev_randao = .zero,
        .block_number = 5,
        .gas_limit = 30_000_000,
        .gas_used = 0,
        .timestamp = 10,
        .extra_data = &.{},
        .base_fee_per_gas = 1,
        .block_hash = .{ .bytes = @splat(hash_byte) },
        .transactions = &.{},
    };
}

fn run(harness: anytype, conductor: *SimConductor, rounds: u32) void {
    for (0..rounds) |_| {
        conductor.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 20);
    }
}

test "conductor: polls leadership, commits by block hash, sends overrides" {
    var fake: FakeRpc = .{};
    fake.add(.{ .method = "conductor_leader", .result = "true" });
    fake.add(.{ .method = "conductor_commitUnsafePayload", .result = "null" });
    fake.add(.{ .method = "conductor_overrideLeader", .result = "null" });
    var harness: sim_harness.Harness(*FakeRpc, FakeRpc.handle) = undefined;
    try harness.init(&fake, 0xc0);
    defer harness.deinit();
    var conductor: SimConductor = undefined;
    try conductor.init(testing.allocator, &harness.client_io, harness.address, test_http_options);
    defer conductor.deinit();
    try testing.expect(conductor.leader == null);
    run(&harness, &conductor, 4);
    try testing.expect(conductor.leader.?);
    const payload = test_payload(0xab);
    const root: B256 = .{ .bytes = @splat(0xbe) };
    var attempts: u32 = 0;
    while (attempts < 40) : (attempts += 1) {
        if (conductor.commit(&payload, root)) |_| break else |_| {}
        harness.world.run_for_ns(std.time.ns_per_s / 20);
    }
    try testing.expect(attempts < 40);
    try testing.expect(std.mem.indexOf(u8, fake.body(), "\"executionPayload\"") != null);
    try testing.expect(std.mem.indexOf(u8, fake.body(), "\"parentBeaconBlockRoot\"") != null);
    try conductor.commit(&payload, root); // Already committed.
    try testing.expectEqual(@as(u64, 1), conductor.stats.commits);
    conductor.request_override();
    run(&harness, &conductor, 4);
    try testing.expectEqual(@as(u64, 1), conductor.stats.overrides);
    // A failing commit is retried after the backoff.
    fake.entries[1].rpc_error = "{\"code\":-32000,\"message\":\"not leader\"}";
    const other = test_payload(0xcd);
    attempts = 0;
    while (attempts < 10) : (attempts += 1) {
        try testing.expectError(error.NotAvailable, conductor.commit(&other, null));
        harness.world.run_for_ns(std.time.ns_per_s / 20);
    }
    try testing.expect(conductor.stats.commit_failures >= 2);
    // Leadership lost: the poll reports it.
    fake.entries[0].result = "false";
    run(&harness, &conductor, 30);
    try testing.expect(!conductor.leader.?);
    fake.entries[0].result = "\"bogus\"";
    run(&harness, &conductor, 30);
    try testing.expect(conductor.leader == null);
    while (conductor.busy()) harness.world.run_for_ns(std.time.ns_per_s / 20);
}

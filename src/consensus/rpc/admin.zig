//! `admin_*` JSON-RPC methods of the consensus node (base/base `crates/consensus/rpc/src/
//! jsonrpsee.rs` `AdminApi`): sequencer control, recovery mode, and derivation reset.
//! Served by the same router as `optimism_*`; the node exposes them through
//! `rollup.Backend.admin`. Without it (or on a verifier) the sequencer methods fail.
//!
//! `admin_postUnsafePayload` hands the raw `OpExecutionPayloadEnvelope` JSON to the node,
//! which decodes it and queues it like a gossiped unsafe block.
//!
//! With a conductor (`--conductor.rpc`) `admin_startSequencer` requires leadership and
//! `admin_overrideLeader` is forwarded; without one the override fails like base/base's.
//! `admin_refreshUpgradeSignal` needs the runtime-admin upgrade mode (only metrics-only
//! exists), so it reports the signal as not configured (-32004).
//! `dev_taskQueueLength` reports the engine task queue length.
//! Not implemented: `admin_clearPendingP2pConnections` (needs a p2p dial-abort API).

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const protocol = @import("../protocol/root.zig");
const rollup = @import("rollup.zig");

const Hash = protocol.block.Hash;
const Backend = rollup.Backend;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const StartError = error{
    NotSequencer,
    UnsafeHeadMismatch,
    NotReady,
    /// A conductor is configured and this node is not (known to be) its leader.
    NotLeader,
};
pub const OverrideError = error{NoConductor};

/// base/base `SEQUENCER_UNAVAILABLE_CODE`.
pub const sequencer_unavailable_code: i32 = -32001;
/// base/base `NOT_LEADER_CODE`.
pub const not_leader_code: i32 = -32002;
pub const StopError = error{NotSequencer};
pub const PostError = error{
    /// The envelope is not a valid execution payload envelope.
    InvalidPayload,
    /// Stale, sequencing, not running yet, or no room to queue it.
    NotAccepted,
};

pub const VTable = struct {
    /// Whether the node runs a sequencer; sequencer methods fail with -32001 otherwise.
    is_sequencer: *const fn (context: *anyopaque) bool,
    sequencer_active: *const fn (context: *anyopaque) bool,
    /// Starts sequencing on top of `unsafe_head`, which must be the current unsafe head.
    start_sequencer: *const fn (context: *anyopaque, unsafe_head: Hash) StartError!void,
    /// Stops sequencing; returns the unsafe head hash to resume from.
    stop_sequencer: *const fn (context: *anyopaque) StopError!Hash,
    recover_mode: *const fn (context: *anyopaque) bool,
    set_recover_mode: *const fn (context: *anyopaque, mode: bool) void,
    reset_derivation_pipeline: *const fn (context: *anyopaque) void,
    /// Queues an unsafe payload from its envelope JSON (`admin_postUnsafePayload`).
    post_unsafe_payload: *const fn (context: *anyopaque, envelope_json: []const u8) PostError!void,
    /// Tasks waiting in the engine queue (`dev_taskQueueLength`).
    task_queue_length: *const fn (context: *anyopaque) u64,
    conductor_enabled: *const fn (context: *anyopaque) bool,
    /// Asks the conductor to make this node the leader (`admin_overrideLeader`).
    override_leader: *const fn (context: *anyopaque) OverrideError!void,
};

/// base/base `UPGRADE_SIGNAL_UNAVAILABLE_CODE`.
pub const upgrade_signal_unavailable_code: i32 = -32004;

pub const methods = [_]rpc.Method(*const Backend){
    .{ .name = "admin_sequencerActive", .handler = sequencer_active },
    .{ .name = "admin_startSequencer", .handler = start_sequencer },
    .{ .name = "admin_stopSequencer", .handler = stop_sequencer },
    .{ .name = "admin_conductorEnabled", .handler = conductor_enabled },
    .{ .name = "admin_recoverMode", .handler = recover_mode },
    .{ .name = "admin_setRecoverMode", .handler = set_recover_mode },
    .{ .name = "admin_resetDerivationPipeline", .handler = reset_derivation_pipeline },
    .{ .name = "admin_postUnsafePayload", .handler = post_unsafe_payload },
    .{ .name = "admin_overrideLeader", .handler = override_leader },
    .{ .name = "admin_refreshUpgradeSignal", .handler = refresh_upgrade_signal },
    .{ .name = "dev_taskQueueLength", .handler = task_queue_length },
    .{ .name = "healthz", .handler = healthz },
};

fn admin(backend: *const Backend, call: *Call) HandlerError!*const VTable {
    const vtable = backend.admin orelse
        return call.fail(rpc.code.method_not_found, "method not found");
    return vtable;
}

fn dev(backend: *const Backend, call: *Call) HandlerError!*const VTable {
    const vtable = backend.dev orelse
        return call.fail(rpc.code.method_not_found, "method not found");
    return vtable;
}

/// The admin API of a sequencer; other nodes get base/base's -32001.
fn sequencer(backend: *const Backend, call: *Call) HandlerError!*const VTable {
    const vtable = try admin(backend, call);
    if (!vtable.is_sequencer(backend.context)) {
        return call.fail(sequencer_unavailable_code, "sequencer not available on this node");
    }
    return vtable;
}

fn sequencer_active(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    try call.writer.boolean(vtable.sequencer_active(backend.context));
}

fn start_sequencer(backend: *const Backend, call: *Call) HandlerError!void {
    const head: Hash = .{ .bytes = try call.params.fixed(32) };
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    // base/base `sequencer_admin_error`: details other than leadership are redacted.
    vtable.start_sequencer(backend.context, head) catch |err| return switch (err) {
        error.NotLeader => call.fail(not_leader_code, "Node is not the conductor leader."),
        error.NotSequencer, error.UnsafeHeadMismatch, error.NotReady => {
            return call.fail(rpc.code.internal_error, "Internal error");
        },
    };
    try call.writer.null_value();
}

fn stop_sequencer(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    const head = vtable.stop_sequencer(backend.context) catch
        return call.fail(rpc.code.internal_error, "Internal error");
    try call.writer.data(&head.bytes);
}

fn conductor_enabled(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    try call.writer.boolean(vtable.conductor_enabled(backend.context));
}

fn override_leader(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    // base/base: `LeaderOverrideError("No conductor configured")`, mapped to InternalError.
    vtable.override_leader(backend.context) catch
        return call.fail(rpc.code.internal_error, "Internal error");
    try call.writer.null_value();
}

fn refresh_upgrade_signal(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    assert(backend.version.len > 0);
    const message = "upgrade signal not configured on this node";
    return call.fail(upgrade_signal_unavailable_code, message);
}

fn task_queue_length(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try dev(backend, call);
    try call.writer.integer(vtable.task_queue_length(backend.context));
}

fn recover_mode(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    try call.writer.boolean(vtable.recover_mode(backend.context));
}

fn set_recover_mode(backend: *const Backend, call: *Call) HandlerError!void {
    const mode = try call.params.boolean();
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    vtable.set_recover_mode(backend.context, mode);
    try call.writer.null_value();
}

fn reset_derivation_pipeline(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try sequencer(backend, call);
    vtable.reset_derivation_pipeline(backend.context);
    try call.writer.null_value();
}

fn post_unsafe_payload(backend: *const Backend, call: *Call) HandlerError!void {
    const envelope_json = try call.params.raw();
    try call.params.finish();
    const vtable = try admin(backend, call);
    assert(envelope_json.len > 0);
    // base/base decodes the envelope as a parameter (invalid params) and then hands it to
    // the network without waiting, so a payload that is not queued still succeeds.
    vtable.post_unsafe_payload(backend.context, envelope_json) catch |err| switch (err) {
        error.InvalidPayload => {
            return call.fail(rpc.code.invalid_params, "invalid execution payload envelope");
        },
        error.NotAccepted => {},
    };
    try call.writer.null_value();
}

fn healthz(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    assert(backend.version.len > 0);
    try call.writer.begin_object();
    try call.writer.key("version");
    try call.writer.string(backend.version);
    try call.writer.end_object();
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;

const StubNode = struct {
    active: bool = true,
    recover: bool = false,
    resets: u32 = 0,
    posts: u32 = 0,
    sequencer: bool = true,
    conductor: bool = false,
    leader: bool = true,
    overrides: u32 = 0,
    head: Hash = .{ .bytes = @splat(0xab) },
    config: protocol.rollup_config.RollupConfig = .{ .block_time = 2 },

    const vtable: VTable = .{
        .is_sequencer = sequencer_of,
        .sequencer_active = active_of,
        .start_sequencer = start,
        .stop_sequencer = stop,
        .recover_mode = recover_of,
        .set_recover_mode = set_recover,
        .reset_derivation_pipeline = reset,
        .post_unsafe_payload = post,
        .task_queue_length = queue_length,
        .conductor_enabled = conductor_of,
        .override_leader = override,
    };
    const rollup_vtable: Backend.VTable = .{
        .sync_status = status_of,
        .output_at_block = output_of,
        .safe_db = db_of,
    };

    fn of(context: *anyopaque) *StubNode {
        return @ptrCast(@alignCast(context));
    }
    fn sequencer_of(context: *anyopaque) bool {
        return of(context).sequencer;
    }
    fn active_of(context: *anyopaque) bool {
        return of(context).active;
    }
    fn start(context: *anyopaque, head: Hash) StartError!void {
        const node = of(context);
        if (node.active) return;
        if (node.conductor and !node.leader) return error.NotLeader;
        if (!head.eql(node.head)) return error.UnsafeHeadMismatch;
        node.active = true;
    }
    fn stop(context: *anyopaque) StopError!Hash {
        const node = of(context);
        node.active = false;
        return node.head;
    }
    fn recover_of(context: *anyopaque) bool {
        return of(context).recover;
    }
    fn set_recover(context: *anyopaque, mode: bool) void {
        of(context).recover = mode;
    }
    fn reset(context: *anyopaque) void {
        of(context).resets += 1;
    }
    fn post(context: *anyopaque, envelope_json: []const u8) PostError!void {
        if (envelope_json[0] != '{') return error.InvalidPayload;
        of(context).posts += 1;
    }
    fn conductor_of(context: *anyopaque) bool {
        return of(context).conductor;
    }
    fn override(context: *anyopaque) OverrideError!void {
        const node = of(context);
        if (!node.conductor) return error.NoConductor;
        node.overrides += 1;
    }
    fn queue_length(context: *anyopaque) u64 {
        return of(context).resets + 3;
    }
    fn status_of(_: *anyopaque) rollup.SyncStatus {
        return .{};
    }
    fn output_of(
        _: *anyopaque,
        _: rollup.BlockTag,
    ) error{ NotAvailable, NotFound }!rollup.OutputAtBlock {
        return error.NotAvailable;
    }
    fn db_of(_: *anyopaque) ?*const @import("../safedb/root.zig").SafeDB {
        return null;
    }

    fn backend(node: *StubNode) Backend {
        return .{
            .context = node,
            .vtable = &rollup_vtable,
            .version = "test",
            .rollup = &node.config,
            .admin = &vtable,
            .dev = &vtable,
        };
    }
};

fn call_text(backend: *const Backend, body: []const u8, buffer: []u8) []const u8 {
    var out: std.Io.Writer = .fixed(buffer);
    _ = rollup.NodeRouter.handle(backend, body, &out);
    return out.buffered();
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "admin rpc: sequencer stop/start, recover mode, reset, healthz" {
    var node: StubNode = .{};
    const backend = node.backend();
    var buffer: [1024]u8 = undefined;
    const stopped = call_text(&backend,
        \\{"jsonrpc":"2.0","id":1,"method":"admin_stopSequencer"}
    , &buffer);
    try testing.expect(contains(stopped, "\"result\":\"0xabab"));
    try testing.expect(!node.active);
    const mismatch = call_text(&backend,
        \\{"jsonrpc":"2.0","id":2,"method":"admin_startSequencer","params":["0x0000000000000000000000000000000000000000000000000000000000000000"]}
    , &buffer);
    try testing.expect(contains(mismatch, "-32603")); // Redacted like base/base.
    const started = call_text(&backend,
        \\{"jsonrpc":"2.0","id":3,"method":"admin_startSequencer","params":["0xabababababababababababababababababababababababababababababababab"]}
    , &buffer);
    try testing.expect(contains(started, "\"result\":null"));
    try testing.expect(node.active);
    _ = call_text(&backend,
        \\{"jsonrpc":"2.0","id":4,"method":"admin_setRecoverMode","params":[true]}
    , &buffer);
    try testing.expect(node.recover);
    _ = call_text(&backend,
        \\{"jsonrpc":"2.0","id":5,"method":"admin_resetDerivationPipeline"}
    , &buffer);
    try testing.expectEqual(@as(u32, 1), node.resets);
    const posted = call_text(&backend,
        \\{"jsonrpc":"2.0","id":8,"method":"admin_postUnsafePayload","params":[{"executionPayload":{}}]}
    , &buffer);
    try testing.expect(contains(posted, "\"result\":null"));
    try testing.expectEqual(@as(u32, 1), node.posts);
    const invalid = call_text(&backend,
        \\{"jsonrpc":"2.0","id":9,"method":"admin_postUnsafePayload","params":["0x00"]}
    , &buffer);
    try testing.expect(contains(invalid, "invalid execution payload envelope"));
    const queue = call_text(&backend,
        \\{"jsonrpc":"2.0","id":10,"method":"dev_taskQueueLength"}
    , &buffer);
    try testing.expect(contains(queue, "\"result\":4"));
    const leader = call_text(&backend,
        \\{"jsonrpc":"2.0","id":11,"method":"admin_overrideLeader"}
    , &buffer);
    try testing.expect(contains(leader, "-32603"));
    node.conductor = true;
    const overridden = call_text(&backend,
        \\{"jsonrpc":"2.0","id":13,"method":"admin_overrideLeader"}
    , &buffer);
    try testing.expect(contains(overridden, "\"result\":null"));
    try testing.expectEqual(@as(u32, 1), node.overrides);
    const enabled = call_text(&backend,
        \\{"jsonrpc":"2.0","id":14,"method":"admin_conductorEnabled"}
    , &buffer);
    try testing.expect(contains(enabled, "\"result\":true"));
    node.active = false;
    node.leader = false;
    const refused = call_text(&backend,
        \\{"jsonrpc":"2.0","id":15,"method":"admin_startSequencer","params":["0xabababababababababababababababababababababababababababababababab"]}
    , &buffer);
    try testing.expect(contains(refused, "-32002"));
    try testing.expect(contains(refused, "Node is not the conductor leader."));
    try testing.expect(!node.active);
    const refresh = call_text(&backend,
        \\{"jsonrpc":"2.0","id":12,"method":"admin_refreshUpgradeSignal"}
    , &buffer);
    try testing.expect(contains(refresh, "-32004"));
    try testing.expect(contains(refresh, "upgrade signal not configured on this node"));
    const health = call_text(&backend,
        \\{"jsonrpc":"2.0","id":6,"method":"healthz"}
    , &buffer);
    try testing.expect(contains(health, "\"version\":\"test\""));
    var disabled = backend;
    disabled.admin = null;
    disabled.dev = null;
    const unavailable = call_text(&disabled,
        \\{"jsonrpc":"2.0","id":7,"method":"admin_sequencerActive"}
    , &buffer);
    try testing.expect(contains(unavailable, "-32601"));
    const no_dev = call_text(&disabled,
        \\{"jsonrpc":"2.0","id":18,"method":"dev_taskQueueLength"}
    , &buffer);
    try testing.expect(contains(no_dev, "-32601"));
    const still_healthy = call_text(&disabled,
        \\{"jsonrpc":"2.0","id":19,"method":"healthz"}
    , &buffer);
    try testing.expect(contains(still_healthy, "\"version\":\"test\""));
    node.sequencer = false;
    const verifier = call_text(&backend,
        \\{"jsonrpc":"2.0","id":16,"method":"admin_stopSequencer"}
    , &buffer);
    try testing.expect(contains(verifier, "-32001"));
    try testing.expect(contains(verifier, "sequencer not available on this node"));
    // Posting a payload is not a sequencer method.
    const verifier_post = call_text(&backend,
        \\{"jsonrpc":"2.0","id":17,"method":"admin_postUnsafePayload","params":[{"executionPayload":{}}]}
    , &buffer);
    try testing.expect(contains(verifier_post, "\"result\":null"));
}

fn fuzz_admin(_: void, smith: *std.testing.Smith) anyerror!void {
    var body: [256]u8 = undefined;
    const len = smith.slice(&body);
    var node: StubNode = .{};
    const backend = node.backend();
    var buffer: [1024]u8 = undefined;
    _ = call_text(&backend, body[0..len], &buffer);
}

test "admin rpc: fuzz" {
    try testing.fuzz({}, fuzz_admin, .{});
}

test "admin rpc: seeded fuzz over method names and params" {
    var prng = @import("../../testing/prng.zig").Prng.init(0xad);
    const names = [_][]const u8{
        "admin_startSequencer",    "admin_stopSequencer",   "admin_setRecoverMode",
        "admin_recoverMode",       "admin_sequencerActive", "healthz",
        "admin_postUnsafePayload", "admin_overrideLeader",  "admin_refreshUpgradeSignal",
        "dev_taskQueueLength",
    };
    const params = [_][]const u8{
        "",                ",\"params\":[]",   ",\"params\":[true]",
        ",\"params\":[1]", ",\"params\":[{}]",
    };
    var node: StubNode = .{};
    const backend = node.backend();
    for (0..256) |_| {
        var body_buffer: [256]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
            "\"method\":\"{s}\"{s}}}", .{
            names[prng.below(names.len)],
            params[prng.below(params.len)],
        });
        var buffer: [1024]u8 = undefined;
        const reply = call_text(&backend, body, &buffer);
        try testing.expect(contains(reply, "\"result\"") or contains(reply, "\"error\""));
    }
}

//! `admin_*` JSON-RPC methods of the consensus node (base/base `crates/consensus/rpc/src/
//! jsonrpsee.rs` `AdminApi`): sequencer control, recovery mode, and derivation reset.
//! Served by the same router as `optimism_*`; the node exposes them through
//! `rollup.Backend.admin`. Without it (or on a verifier) the sequencer methods fail.
//!
//! Not implemented yet: `admin_postUnsafePayload` (needs the payload envelope decoder on the
//! request side), `admin_overrideLeader` and conductor methods (no conductor), and
//! `admin_refreshUpgradeSignal`.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const protocol = @import("../protocol/root.zig");
const rollup = @import("rollup.zig");

const Hash = protocol.block.Hash;
const Backend = rollup.Backend;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const StartError = error{ NotSequencer, AlreadyActive, UnsafeHeadMismatch, NotReady };
pub const StopError = error{ NotSequencer, NotActive };

pub const VTable = struct {
    sequencer_active: *const fn (context: *anyopaque) bool,
    /// Starts sequencing on top of `unsafe_head`, which must be the current unsafe head.
    start_sequencer: *const fn (context: *anyopaque, unsafe_head: Hash) StartError!void,
    /// Stops sequencing; returns the unsafe head hash to resume from.
    stop_sequencer: *const fn (context: *anyopaque) StopError!Hash,
    recover_mode: *const fn (context: *anyopaque) bool,
    set_recover_mode: *const fn (context: *anyopaque, mode: bool) void,
    reset_derivation_pipeline: *const fn (context: *anyopaque) void,
};

pub const methods = [_]rpc.Method(*const Backend){
    .{ .name = "admin_sequencerActive", .handler = sequencer_active },
    .{ .name = "admin_startSequencer", .handler = start_sequencer },
    .{ .name = "admin_stopSequencer", .handler = stop_sequencer },
    .{ .name = "admin_conductorEnabled", .handler = conductor_enabled },
    .{ .name = "admin_recoverMode", .handler = recover_mode },
    .{ .name = "admin_setRecoverMode", .handler = set_recover_mode },
    .{ .name = "admin_resetDerivationPipeline", .handler = reset_derivation_pipeline },
    .{ .name = "healthz", .handler = healthz },
};

fn admin(backend: *const Backend, call: *Call) HandlerError!*const VTable {
    const vtable = backend.admin orelse
        return call.fail(rpc.code.server_error, "admin api not available");
    return vtable;
}

fn sequencer_active(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try admin(backend, call);
    try call.writer.boolean(vtable.sequencer_active(backend.context));
}

fn start_sequencer(backend: *const Backend, call: *Call) HandlerError!void {
    const head: Hash = .{ .bytes = try call.params.fixed(32) };
    try call.params.finish();
    const vtable = try admin(backend, call);
    vtable.start_sequencer(backend.context, head) catch |err| {
        const message = switch (err) {
            error.NotSequencer => "node is not a sequencer",
            error.AlreadyActive => "sequencer already running",
            error.UnsafeHeadMismatch => "block hash does not match unsafe head",
            error.NotReady => "sequencer not ready (engine sync in progress)",
        };
        return call.fail(rpc.code.server_error, message);
    };
    try call.writer.null_value();
}

fn stop_sequencer(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try admin(backend, call);
    const head = vtable.stop_sequencer(backend.context) catch |err| {
        const message = switch (err) {
            error.NotSequencer => "node is not a sequencer",
            error.NotActive => "sequencer not running",
        };
        return call.fail(rpc.code.server_error, message);
    };
    try call.writer.data(&head.bytes);
}

fn conductor_enabled(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    _ = backend;
    try call.writer.boolean(false); // No conductor: a single sequencer.
}

fn recover_mode(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try admin(backend, call);
    try call.writer.boolean(vtable.recover_mode(backend.context));
}

fn set_recover_mode(backend: *const Backend, call: *Call) HandlerError!void {
    const mode = try call.params.boolean();
    try call.params.finish();
    const vtable = try admin(backend, call);
    vtable.set_recover_mode(backend.context, mode);
    try call.writer.null_value();
}

fn reset_derivation_pipeline(backend: *const Backend, call: *Call) HandlerError!void {
    try call.params.finish();
    const vtable = try admin(backend, call);
    vtable.reset_derivation_pipeline(backend.context);
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
    head: Hash = .{ .bytes = @splat(0xab) },
    config: protocol.rollup_config.RollupConfig = .{ .block_time = 2 },

    const vtable: VTable = .{
        .sequencer_active = active_of,
        .start_sequencer = start,
        .stop_sequencer = stop,
        .recover_mode = recover_of,
        .set_recover_mode = set_recover,
        .reset_derivation_pipeline = reset,
    };
    const rollup_vtable: Backend.VTable = .{
        .sync_status = status_of,
        .output_at_block = output_of,
        .safe_db = db_of,
    };

    fn of(context: *anyopaque) *StubNode {
        return @ptrCast(@alignCast(context));
    }
    fn active_of(context: *anyopaque) bool {
        return of(context).active;
    }
    fn start(context: *anyopaque, head: Hash) StartError!void {
        const node = of(context);
        if (node.active) return error.AlreadyActive;
        if (!head.eql(node.head)) return error.UnsafeHeadMismatch;
        node.active = true;
    }
    fn stop(context: *anyopaque) StopError!Hash {
        const node = of(context);
        if (!node.active) return error.NotActive;
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
    try testing.expect(contains(mismatch, "does not match unsafe head"));
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
    const health = call_text(&backend,
        \\{"jsonrpc":"2.0","id":6,"method":"healthz"}
    , &buffer);
    try testing.expect(contains(health, "\"version\":\"test\""));
    var disabled = backend;
    disabled.admin = null;
    const unavailable = call_text(&disabled,
        \\{"jsonrpc":"2.0","id":7,"method":"admin_sequencerActive"}
    , &buffer);
    try testing.expect(contains(unavailable, "admin api not available"));
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
        "admin_startSequencer", "admin_stopSequencer",   "admin_setRecoverMode",
        "admin_recoverMode",    "admin_sequencerActive", "healthz",
    };
    const params = [_][]const u8{ "", ",\"params\":[]", ",\"params\":[true]", ",\"params\":[1]" };
    var node: StubNode = .{};
    const backend = node.backend();
    for (0..256) |_| {
        var body_buffer: [256]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buffer, "{{\"jsonrpc\":\"2.0\",\"id\":1," ++
            "\"method\":\"{s}\"{s}}}", .{ names[prng.below(names.len)], params[prng.below(4)] });
        var buffer: [1024]u8 = undefined;
        const reply = call_text(&backend, body, &buffer);
        try testing.expect(contains(reply, "\"result\"") or contains(reply, "\"error\""));
    }
}

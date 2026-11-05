//! EIP-8130 request fields with nested structure: `calls` (phases of calls) and
//! `accountChanges` (`type`-tagged delegation, create and config entries), in the same
//! JSON shape `eip8130.zig` writes. Lists are re-encoded into exact-size RLP payloads.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../consensus/root.zig");
const rlp = @import("../rlp/root.zig");
const request = @import("request.zig");
const aa = consensus.eip8130;
const Value = std.json.Value;
const Allocator = std.mem.Allocator;
const ParseError = request.ParseError;

pub const calls_per_phase_max = 1024;
/// Parsing bounds; `eip8130_structure` applies the protocol limits afterwards.
pub const account_changes_max = 16;
pub const signed_changes_max = 64;

/// Encodes `items` into an arena buffer of exactly the needed size.
fn build(comptime List: type, arena: Allocator, items: anytype) ParseError!List {
    var length: usize = 0;
    for (items) |item| length += rlp.length(item);
    const list = List.build(try arena.alloc(u8, length), items);
    assert(list.payload.len == length);
    return list;
}

pub fn parse_calls(arena: Allocator, value: Value) ParseError!aa.Calls {
    const phases_json = try request.array_of(value, aa.max_call_phases_per_tx);
    const phases = try arena.alloc(aa.Phase, phases_json.len);
    for (phases, phases_json) |*phase, phase_json| {
        const calls_json = try request.array_of(phase_json, calls_per_phase_max);
        const calls = try arena.alloc(aa.Call, calls_json.len);
        for (calls, calls_json) |*call, call_json| {
            if (call_json != .object) return error.InvalidField;
            const object = call_json.object;
            const call_value = request.field(object, "value");
            call.* = .{
                .to = try request.address_of(try request.required(object, "to")),
                .value = if (call_value) |text| try request.quantity(u256, text) else 0,
                .data = try request.data_of(arena, try request.required(object, "data")),
            };
        }
        phase.* = try build(aa.Phase, arena, calls);
    }
    return build(aa.Calls, arena, phases);
}

pub fn parse_account_changes(arena: Allocator, value: Value) ParseError!aa.AccountChanges {
    const changes_json = try request.array_of(value, account_changes_max);
    const changes = try arena.alloc(aa.AccountChange, changes_json.len);
    for (changes, changes_json) |*change, change_json| {
        if (change_json != .object) return error.InvalidField;
        const object = change_json.object;
        const tag = try request.quantity(u8, try request.required(object, "type"));
        change.* = switch (std.enums.fromInt(std.meta.Tag(aa.AccountChange), tag) orelse
            return error.InvalidField) {
            .delegation => .{
                .delegation = try request.address_of(try request.required(object, "target")),
            },
            .create => .{ .create = try parse_create(arena, object) },
            .config => .{ .config = try parse_config(arena, object) },
        };
    }
    return build(aa.AccountChanges, arena, changes);
}

fn parse_create(arena: Allocator, object: std.json.ObjectMap) ParseError!aa.CreateEntry {
    const actors_value = try request.required(object, "initialActors");
    const actors_json = try request.array_of(actors_value, aa.max_actors_per_entry);
    const actors = try arena.alloc(aa.InitialActor, actors_json.len);
    for (actors, actors_json) |*actor, actor_json| {
        if (actor_json != .object) return error.InvalidField;
        const item = actor_json.object;
        actor.* = .{
            .actor_id = try request.hash_of(try request.required(item, "actorId")),
            .authenticator = try request.address_of(try request.required(item, "authenticator")),
            .scope = try request.quantity(u16, try request.required(item, "scope")),
            .policy_data = try request.data_of(arena, try request.required(item, "policyData")),
        };
    }
    return .{
        .user_salt = try request.hash_of(try request.required(object, "userSalt")),
        .code = try request.data_of(arena, try request.required(object, "code")),
        .initial_actors = try build(aa.InitialActors, arena, actors),
    };
}

fn parse_config(arena: Allocator, object: std.json.ObjectMap) ParseError!aa.ConfigChange {
    const channel_byte = try request.quantity(u8, try request.required(object, "channel"));
    const channel = std.enums.fromInt(aa.Channel, channel_byte) orelse return error.InvalidField;
    const signed_json = try request.array_of(
        try request.required(object, "changes"),
        signed_changes_max,
    );
    const signed = try arena.alloc(aa.SignedChange, signed_json.len);
    for (signed, signed_json) |*change, change_json| {
        if (change_json != .object) return error.InvalidField;
        const item = change_json.object;
        const type_byte = try request.quantity(u8, try request.required(item, "changeType"));
        change.* = .{
            .change_type = std.enums.fromInt(aa.ChangeType, type_byte) orelse
                return error.InvalidField,
            .payload = try request.data_of(arena, try request.required(item, "payload")),
        };
    }
    return .{
        .channel = channel,
        .sequence = try request.quantity(u64, try request.required(object, "sequence")),
        .changes = try build(aa.SignedChanges, arena, signed),
        .signature = try request.data_of(arena, try request.required(object, "signature")),
    };
}

const testing = std.testing;
const rpc_eip8130 = @import("eip8130.zig");
const json = @import("json.zig");

test "rpc request eip8130: written JSON parses back" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var phase_buffer: [256]u8 = undefined;
    var calls_buffer: [512]u8 = undefined;
    var actors_buffer: [256]u8 = undefined;
    var changes_buffer: [256]u8 = undefined;
    var list_buffer: [1024]u8 = undefined;
    const address = consensus.eip8130.k1_authenticator;
    const call: aa.Call = .{ .to = address, .value = 9, .data = &.{0xab} };
    const phase = aa.Phase.build(&phase_buffer, &.{ call, call });
    const actor: aa.InitialActor = .{
        .actor_id = .zero,
        .authenticator = address,
        .scope = aa.scope_operator,
        .policy_data = &.{},
    };
    const payload: [32]u8 = @splat(1);
    const signed_change: aa.SignedChange = .{ .change_type = .lock, .payload = &payload };
    const changes = [_]aa.AccountChange{
        .{ .delegation = address },
        .{ .create = .{
            .user_salt = .zero,
            .code = &.{ 0x60, 0x00 },
            .initial_actors = aa.InitialActors.build(&actors_buffer, &.{actor}),
        } },
        .{ .config = .{
            .channel = .multichain,
            .sequence = 3,
            .changes = aa.SignedChanges.build(&changes_buffer, &.{signed_change}),
            .signature = &.{ 0x01, 0x02 },
        } },
    };
    const signed: aa.Signed = .{
        .tx = .{
            .chain_id = 8453,
            .account_changes = aa.AccountChanges.build(&list_buffer, &changes),
            .calls = aa.Calls.build(&calls_buffer, &.{ phase, phase }),
        },
        .sender_auth = &.{},
    };
    var out: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var object = try json.Object.begin(&w);
    try rpc_eip8130.write_fields(&object, signed, null);
    try object.end();
    const value = try std.json.parseFromSliceLeaky(Value, arena, w.buffered(), .{});
    const calls = try parse_calls(arena, value.object.get("calls").?);
    try testing.expectEqualSlices(u8, signed.tx.calls.payload, calls.payload);
    const parsed_changes = try parse_account_changes(arena, value.object.get("accountChanges").?);
    try testing.expectEqualSlices(u8, signed.tx.account_changes.payload, parsed_changes.payload);
    const full = try request.parse_transaction_request(arena, value);
    try testing.expectEqualSlices(u8, calls.payload, full.calls.?.payload);
    try testing.expectEqual(@as(u32, 3), full.account_changes.?.count);
}

test "rpc request eip8130: rejects malformed entries" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_][]const u8{
        "[{\"type\":\"0x9\"}]",
        "[{\"type\":\"0x1\"}]",
        "[{\"type\":\"0x3\",\"channel\":\"0x2\",\"sequence\":\"0x0\",\"changes\":[]," ++
            "\"signature\":\"0x\"}]",
        "{}",
    };
    for (cases) |text| {
        const value = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
        try testing.expectError(error.InvalidField, parse_account_changes(arena, value));
    }
    const bad_call = try std.json.parseFromSliceLeaky(Value, arena, "[[{\"to\":\"0x00\"}]]", .{});
    try testing.expectError(error.InvalidField, parse_calls(arena, bad_call));
}

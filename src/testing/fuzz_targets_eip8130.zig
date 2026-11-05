//! Fuzz target for the EIP-8130 (0x79) JSON request fields
//! (`common/rpc_types/request_eip8130.zig`) against the JSON writer
//! (`common/rpc_types/eip8130.zig`): `eth_sendTransaction`/`eth_call` bodies carry nested
//! call phases and `type`-tagged account changes from untrusted clients.
//!
//! Random nested structures (phases of calls; delegation, create and config changes with
//! actors and signed changes) are written as JSON and parsed back. Properties:
//!   - the parsed lists re-encode to exactly the original RLP payloads;
//!   - `parse_transaction_request` on the whole object agrees with the field parsers;
//!   - removing any one member from an entry makes the parse fail with an error (every
//!     member the writer emits is required, except a call's `value`), never a panic.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const consensus = @import("../common/consensus/root.zig");
const primitives = @import("../common/primitives/root.zig");
const rlp = @import("../common/rlp/root.zig");
const rpc_types = @import("../common/rpc_types/root.zig");
const nested = @import("../common/rpc_types/request_eip8130.zig");
const json = @import("../common/rpc_types/json.zig");

const aa = consensus.eip8130;
const Value = std.json.Value;
const Allocator = std.mem.Allocator;

const phases_max = 3;
const calls_max = 3;
const changes_max = 4;
const entries_max = 3;
const bytes_max = 24;

fn build(comptime List: type, arena: Allocator, items: anytype) !List {
    var length: usize = 0;
    for (items) |item| length += rlp.length(item);
    return List.build(try arena.alloc(u8, length), items);
}

fn random_bytes(prng: *Prng, arena: Allocator) ![]const u8 {
    const bytes = try arena.alloc(u8, @intCast(prng.below(bytes_max + 1)));
    prng.fill(bytes);
    return bytes;
}

fn random_fixed(comptime T: type, prng: *Prng) T {
    var value: T = undefined;
    prng.fill(&value.bytes);
    return value;
}

fn random_calls(prng: *Prng, arena: Allocator) !aa.Calls {
    const phases = try arena.alloc(aa.Phase, @intCast(prng.below(phases_max + 1)));
    for (phases) |*phase| {
        const calls = try arena.alloc(aa.Call, @intCast(prng.below(calls_max + 1)));
        for (calls) |*call| call.* = .{
            .to = random_fixed(primitives.Address, prng),
            .value = if (prng.chance(1, 2)) 0 else prng.int(u64) *% prng.int(u64),
            .data = try random_bytes(prng, arena),
        };
        phase.* = try build(aa.Phase, arena, calls);
    }
    return build(aa.Calls, arena, phases);
}

fn random_create(prng: *Prng, arena: Allocator) !aa.CreateEntry {
    const actors = try arena.alloc(aa.InitialActor, @intCast(prng.below(entries_max + 1)));
    for (actors) |*actor| actor.* = .{
        .actor_id = random_fixed(primitives.B256, prng),
        .authenticator = random_fixed(primitives.Address, prng),
        .scope = @truncate(prng.int(u64)),
        .policy_data = try random_bytes(prng, arena),
    };
    return .{
        .user_salt = random_fixed(primitives.B256, prng),
        .code = try random_bytes(prng, arena),
        .initial_actors = try build(aa.InitialActors, arena, actors),
    };
}

fn random_config(prng: *Prng, arena: Allocator) !aa.ConfigChange {
    const types = std.enums.values(aa.ChangeType);
    const channels = std.enums.values(aa.Channel);
    const signed = try arena.alloc(aa.SignedChange, @intCast(prng.below(entries_max + 1)));
    for (signed) |*change| change.* = .{
        .change_type = types[@intCast(prng.below(types.len))],
        .payload = try random_bytes(prng, arena),
    };
    return .{
        .channel = channels[@intCast(prng.below(channels.len))],
        .sequence = prng.int(u64),
        .changes = try build(aa.SignedChanges, arena, signed),
        .signature = try random_bytes(prng, arena),
    };
}

fn random_changes(prng: *Prng, arena: Allocator) !aa.AccountChanges {
    const changes = try arena.alloc(aa.AccountChange, @intCast(prng.below(changes_max + 1)));
    for (changes) |*change| change.* = switch (prng.below(3)) {
        0 => .{ .delegation = random_fixed(primitives.Address, prng) },
        1 => .{ .create = try random_create(prng, arena) },
        else => .{ .config = try random_config(prng, arena) },
    };
    return build(aa.AccountChanges, arena, changes);
}

/// Every object inside `value` (depth-first, iterative), excluding `value` itself.
fn collect_objects(arena: Allocator, value: Value) ![]*std.json.ObjectMap {
    var objects: std.ArrayList(*std.json.ObjectMap) = .empty;
    var stack: std.ArrayList(*const Value) = .empty;
    try stack.append(arena, &value);
    var visits: u32 = 0;
    while (stack.pop()) |current| : (visits += 1) {
        assert(visits < 1 << 16);
        switch (current.*) {
            .array => |array| for (array.items) |*item| try stack.append(arena, item),
            .object => |*object| {
                if (current != &value) try objects.append(arena, @constCast(object));
                for (object.values()) |*item| try stack.append(arena, item);
            },
            else => {},
        }
    }
    return objects.items;
}

fn parse_field(arena: Allocator, field: []const u8, value: Value) anyerror!void {
    if (std.mem.eql(u8, field, "calls")) {
        _ = try nested.parse_calls(arena, value);
    } else {
        _ = try nested.parse_account_changes(arena, value);
    }
}

fn fuzz_round_trip(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const signed: aa.Signed = .{
        .tx = .{
            .chain_id = 8453,
            .account_changes = try random_changes(&prng, arena),
            .calls = try random_calls(&prng, arena),
        },
        .sender_auth = &.{},
    };
    var out: [16 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var object = try json.Object.begin(&w);
    try rpc_types.eip8130.write_fields(&object, signed, null);
    try object.end();
    const text = w.buffered();

    const value = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    const calls = try nested.parse_calls(arena, value.object.get("calls").?);
    try std.testing.expectEqualSlices(u8, signed.tx.calls.payload, calls.payload);
    try std.testing.expectEqual(signed.tx.calls.count, calls.count);
    const changes_value = value.object.get("accountChanges").?;
    const changes = try nested.parse_account_changes(arena, changes_value);
    try std.testing.expectEqualSlices(u8, signed.tx.account_changes.payload, changes.payload);
    const full = try rpc_types.request.parse_transaction_request(arena, value);
    try std.testing.expectEqualSlices(u8, calls.payload, full.calls.?.payload);
    try std.testing.expectEqualSlices(u8, changes.payload, full.account_changes.?.payload);

    // Drop one member of one nested entry: the parse must fail (a call's `value` is
    // optional and defaults to zero).
    const mutated = try std.json.parseFromSliceLeaky(Value, arena, text, .{});
    const field_names = [_][]const u8{ "calls", "accountChanges" };
    const field = field_names[@intCast(prng.below(field_names.len))];
    const objects = try collect_objects(arena, mutated.object.get(field).?);
    if (objects.len == 0) return;
    const entry = objects[@intCast(prng.below(objects.len))];
    const keys = entry.keys();
    const key = keys[@intCast(prng.below(keys.len))];
    const removed = entry.fetchOrderedRemove(key).?;
    const result = parse_field(arena, field, mutated.object.get(field).?);
    if (std.mem.eql(u8, key, "value")) {
        // Only a zero value round-trips without the member.
        const zero = std.mem.eql(u8, removed.value.string, "0x0");
        if (zero) try result;
        return;
    }
    try std.testing.expectError(error.InvalidField, result);
}

test "fuzz_targets_eip8130: nested request fields round trip and require every member" {
    try fuzz.run({}, fuzz_round_trip, .{ .iterations = 512 });
}

//! Polling filters: eth_newFilter, eth_newBlockFilter, eth_newPendingTransactionFilter,
//! eth_getFilterChanges, eth_getFilterLogs, eth_uninstallFilter.
//!
//! A fixed table of `slots_max` filters. Instead of wall-clock expiry (reth drops a filter
//! after five idle minutes) a full table evicts the least recently polled filter, which
//! keeps the behavior deterministic. Block and log filters report canonical blocks after
//! the last one they reported (starting from the head at creation, as geth and reth do);
//! pending filters report hashes accepted by eth_sendRawTransaction since the last poll,
//! from a bounded ring (older hashes are dropped when a filter falls behind).

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const eth = @import("eth.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;

pub const slots_max = 64;
pub const pending_ring_size = 1024;
/// Most block hashes returned by one poll of a block filter.
pub const block_hashes_max = 1024;

pub const Kind = enum { block, pending, logs };

const Slot = struct {
    id: u64,
    kind: Kind,
    /// Last block number reported (block and log filters).
    last_number: u64,
    /// Pending sequence number reported up to (pending filters).
    pending_seq: u64,
    /// Filter tick of the last creation or poll (eviction order).
    used: u64,
    criteria: eth.Filter,
};

pub const Filters = struct {
    slots: [slots_max]?Slot = @splat(null),
    next_id: u64 = 1,
    tick: u64 = 0,
    pending: [pending_ring_size]Hash = undefined,
    /// Number of hashes ever noted; `pending[seq % size]` holds hash number `seq`.
    pending_seq: u64 = 0,

    pub fn note_pending(filters: *Filters, hash: Hash) void {
        filters.pending[filters.pending_seq % pending_ring_size] = hash;
        filters.pending_seq += 1;
        assert(filters.pending_seq > 0);
    }

    /// Installs a filter, evicting the least recently used one when the table is full.
    pub fn install(filters: *Filters, kind: Kind, head: u64, criteria: eth.Filter) u64 {
        filters.tick += 1;
        var victim: usize = 0;
        for (filters.slots, 0..) |slot, index| {
            const current = slot orelse {
                victim = index;
                break;
            };
            if (current.used < filters.slots[victim].?.used) victim = index;
        }
        const id = filters.next_id;
        filters.next_id += 1;
        filters.slots[victim] = .{
            .id = id,
            .kind = kind,
            .last_number = head,
            .pending_seq = filters.pending_seq,
            .used = filters.tick,
            .criteria = criteria,
        };
        assert(filters.find(id) != null);
        return id;
    }

    pub fn find(filters: *Filters, id: u64) ?*Slot {
        for (&filters.slots) |*slot| {
            if (slot.*) |*current| {
                if (current.id == id) return current;
            }
        }
        return null;
    }

    pub fn uninstall(filters: *Filters, id: u64) bool {
        for (&filters.slots) |*slot| {
            const current = slot.* orelse continue;
            if (current.id != id) continue;
            slot.* = null;
            return true;
        }
        return false;
    }

    fn touch(filters: *Filters, slot: *Slot) void {
        filters.tick += 1;
        slot.used = filters.tick;
    }
};

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_newFilter", .handler = new_filter },
    .{ .name = "eth_newBlockFilter", .handler = new_block_filter },
    .{ .name = "eth_newPendingTransactionFilter", .handler = new_pending_filter },
    .{ .name = "eth_getFilterChanges", .handler = get_filter_changes },
    .{ .name = "eth_getFilterLogs", .handler = get_filter_logs },
    .{ .name = "eth_uninstallFilter", .handler = uninstall_filter },
};

fn table(api: *Api, call: *Call) HandlerError!*Filters {
    return api.filters orelse call.fail(rpc.code.method_not_found, "filters disabled");
}

fn head_number(api: *Api) u64 {
    return eth.head_header(api).number;
}

fn new_filter(api: *Api, call: *Call) HandlerError!void {
    const filters = try table(api, call);
    const criteria = try eth.parse_filter(api, call, try call.params.raw());
    try call.params.finish();
    if (criteria.block_hash != null) {
        return call.fail(rpc.code.invalid_params, "blockHash is not supported in filters");
    }
    try call.writer.quantity(filters.install(.logs, head_number(api), criteria));
}

fn new_block_filter(api: *Api, call: *Call) HandlerError!void {
    const filters = try table(api, call);
    try call.params.finish();
    const head = head_number(api);
    try call.writer.quantity(filters.install(.block, head, .{ .from = head, .to = head }));
}

fn new_pending_filter(api: *Api, call: *Call) HandlerError!void {
    const filters = try table(api, call);
    _ = try call.params.optional_boolean(); // Full transactions are not supported.
    try call.params.finish();
    const head = head_number(api);
    try call.writer.quantity(filters.install(.pending, head, .{ .from = head, .to = head }));
}

fn lookup(api: *Api, call: *Call) HandlerError!*Slot {
    const filters = try table(api, call);
    const id = try call.params.quantity(u64);
    try call.params.finish();
    const slot = filters.find(id) orelse return call.fail(rpc.code.server_error, "filter not found");
    filters.touch(slot);
    return slot;
}

fn get_filter_changes(api: *Api, call: *Call) HandlerError!void {
    const slot = try lookup(api, call);
    try call.writer.begin_array();
    switch (slot.kind) {
        .block => try block_changes(api, call, slot),
        .pending => try pending_changes(api.filters.?, call, slot),
        .logs => try log_changes(api, call, slot),
    }
    try call.writer.end_array();
}

fn block_changes(api: *Api, call: *Call, slot: *Slot) HandlerError!void {
    const head = head_number(api);
    const last = @min(head, slot.last_number +| block_hashes_max);
    var number = slot.last_number + 1;
    while (number <= last) : (number += 1) {
        const hash = api.chain.store.canonical_hash(number) orelse continue;
        try call.writer.data(&hash);
    }
    slot.last_number = @max(slot.last_number, last);
}

fn pending_changes(filters: *Filters, call: *Call, slot: *Slot) HandlerError!void {
    const oldest = filters.pending_seq -| pending_ring_size;
    var seq = @max(slot.pending_seq, oldest);
    while (seq < filters.pending_seq) : (seq += 1) {
        try call.writer.data(&filters.pending[seq % pending_ring_size]);
    }
    slot.pending_seq = filters.pending_seq;
}

fn log_changes(api: *Api, call: *Call, slot: *Slot) HandlerError!void {
    const criteria = &slot.criteria;
    var last = head_number(api);
    if (criteria.to_given) last = @min(last, criteria.to);
    last = @min(last, slot.last_number +| eth.logs_blocks_max);
    const first = @max(slot.last_number + 1, criteria.from);
    try write_range(api, call, criteria, first, last);
    slot.last_number = @max(slot.last_number, last);
}

fn get_filter_logs(api: *Api, call: *Call) HandlerError!void {
    const slot = try lookup(api, call);
    if (slot.kind != .logs) return call.fail(rpc.code.invalid_params, "not a log filter");
    const criteria = &slot.criteria;
    const to = if (criteria.to_given) criteria.to else head_number(api);
    if (to >= criteria.from and to - criteria.from >= eth.logs_blocks_max) {
        return call.fail(rpc.code.server_error, "block range too large");
    }
    try call.writer.begin_array();
    try write_range(api, call, criteria, criteria.from, to);
    try call.writer.end_array();
}

fn write_range(
    api: *Api,
    call: *Call,
    criteria: *const eth.Filter,
    first: u64,
    last: u64,
) HandlerError!void {
    var written: u32 = 0;
    var number = first;
    while (number <= last) : (number += 1) {
        const hash = api.chain.store.canonical_hash(number) orelse continue;
        try eth.block_logs(api, call, hash, criteria, &written);
    }
}

fn uninstall_filter(api: *Api, call: *Call) HandlerError!void {
    const filters = try table(api, call);
    const id = try call.params.quantity(u64);
    try call.params.finish();
    try call.writer.boolean(filters.uninstall(id));
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "filters: install, find, evict the least recently used, uninstall" {
    var filters: Filters = .{};
    var ids: [slots_max]u64 = undefined;
    for (&ids, 0..) |*id, index| id.* = filters.install(.block, index, .{ .from = 0, .to = 0 });
    filters.touch(filters.find(ids[0]).?); // ids[1] is now the least recently used.
    const extra = filters.install(.pending, 0, .{ .from = 0, .to = 0 });
    try testing.expect(filters.find(ids[1]) == null);
    try testing.expect(filters.find(ids[0]) != null);
    try testing.expect(filters.find(extra) != null);
    try testing.expect(filters.uninstall(extra));
    try testing.expect(!filters.uninstall(extra));
}

test "filters: pending ring keeps the newest hashes" {
    var filters: Filters = .{};
    for (0..pending_ring_size + 5) |index| {
        var hash: Hash = @splat(0);
        std.mem.writeInt(u64, hash[0..8], index, .little);
        filters.note_pending(hash);
    }
    try testing.expectEqual(@as(u64, pending_ring_size + 5), filters.pending_seq);
    const newest = filters.pending[(filters.pending_seq - 1) % pending_ring_size];
    const newest_index = std.mem.readInt(u64, newest[0..8], .little);
    try testing.expectEqual(@as(u64, pending_ring_size + 4), newest_index);
}

/// Random install/touch/uninstall sequences keep ids unique and the table bounded.
fn fuzz_table(prng: *Prng) !void {
    var filters: Filters = .{};
    var live: [slots_max * 2]u64 = undefined;
    var live_count: usize = 0;
    for (0..prng.range(1, 400)) |_| {
        if (prng.chance(1, 3) and live_count > 0) {
            const index = prng.below(live_count);
            _ = filters.uninstall(live[index]);
            live[index] = live[live_count - 1];
            live_count -= 1;
        } else {
            const kind: Kind = @fromBackingInt(@intCast(prng.below(3)));
            const id = filters.install(kind, prng.int(u32), .{ .from = 0, .to = 0 });
            if (live_count == live.len) live_count -= 1;
            live[live_count] = id;
            live_count += 1;
        }
        var used: usize = 0;
        for (filters.slots, 0..) |slot, index| {
            const current = slot orelse continue;
            used += 1;
            for (filters.slots[index + 1 ..]) |other| {
                if (other) |o| try testing.expect(o.id != current.id);
            }
        }
        try testing.expect(used <= slots_max);
    }
}

test "filters: seeded fuzz of the table" {
    var prng = Prng.init(0xf117e2);
    for (0..8) |_| try fuzz_table(&prng);
}

fn fuzz_filters(_: void, smith: *testing.Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    try fuzz_table(&prng);
}

test "filters: fuzz" {
    try testing.fuzz({}, fuzz_filters, .{});
}

comptime {
    assert(slots_max > 0 and pending_ring_size > 0);
}

//! In-memory state cost per account, per storage slot, and per trie node, run by
//! `bench.run_commit` (filter "db/footprint"). Input for docs/design/disk-state.md.
//!
//! A `State` is filled with `put_account` / `put_storage` (the genesis path; same tries as a
//! snapshot load), then hashed. Every allocation goes through a counting allocator, so the
//! numbers are the real bytes of the structs and pools, not estimates:
//! - reserved: `State.init` at the bench sizing rule (`bench.state_config`: tables at the
//!   entry count, node pools at 3 nodes per entry + 1024, what a node reserves today);
//! - tight: each hash table rebuilt at exactly its live count (std rounds capacity up to a
//!   power of two at <= 80% load, so this varies up to 2x with the count), plus the live
//!   trie nodes times the bytes of one pool node (hot node + cached ref + rehash order word).
//! Per account = account table + trie entry map + account-trie nodes, over accounts.
//! Per slot = storage table + storage-trie nodes, over slots.
//! The checkpoint image adds 92 bytes per account and 84 per slot (`snapshot.zig`).
//!
//! Benchmark scaffolding: fixtures come from the page allocator.

const std = @import("std");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const state_module = @import("state.zig");

const State = state_module.State;
const AccountInfo = state_module.AccountInfo;

/// Live bytes of every allocation made through it.
const Counter = struct {
    child: std.mem.Allocator,
    live_bytes: u64 = 0,

    fn allocator(self: *Counter) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *Counter = @ptrCast(@alignCast(context));
        const result = self.child.rawAlloc(len, alignment, ret) orelse return null;
        self.live_bytes += len;
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret: usize,
    ) bool {
        const self: *Counter = @ptrCast(@alignCast(context));
        if (!self.child.rawResize(memory, alignment, new_len, ret)) return false;
        assert(self.live_bytes >= memory.len);
        self.live_bytes = self.live_bytes - memory.len + new_len;
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret: usize,
    ) ?[*]u8 {
        const self: *Counter = @ptrCast(@alignCast(context));
        const result = self.child.rawRemap(memory, alignment, new_len, ret) orelse return null;
        assert(self.live_bytes >= memory.len);
        self.live_bytes = self.live_bytes - memory.len + new_len;
        return result;
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *Counter = @ptrCast(@alignCast(context));
        assert(self.live_bytes >= memory.len);
        self.live_bytes -= memory.len;
        self.child.rawFree(memory, alignment, ret);
    }
};

/// The state: `accounts` accounts, the first `contracts` of them with `slots_per_contract`
/// nonzero slots each.
pub const Shape = struct {
    accounts: u32,
    contracts: u32,
    slots_per_contract: u32,

    pub fn slots(shape: Shape) u32 {
        return shape.contracts * shape.slots_per_contract;
    }

    fn config(shape: Shape) state_module.Config {
        assert(shape.contracts <= shape.accounts);
        return .{
            .accounts_max = shape.accounts,
            .storage_slots_max = @max(shape.slots(), 1),
            .codes_max = 1,
            .code_bytes_max = 64,
            .account_nodes_max = 3 * shape.accounts + 1024,
            .storage_nodes_max = 3 * shape.slots() + 1024,
        };
    }
};

pub const Result = struct {
    accounts: u32,
    slots: u32,
    account_nodes: u32,
    storage_nodes: u32,
    /// Bytes of one pool node: hot `Node` + cached `RlpNode` + one rehash order word.
    account_node_bytes: u32,
    storage_node_bytes: u32,
    reserved_bytes: u64,
    account_table_bytes: u64,
    entry_map_bytes: u64,
    storage_table_bytes: u64,

    pub fn account_bytes(result: *const Result) u64 {
        const nodes = @as(u64, result.account_nodes) * result.account_node_bytes;
        return result.account_table_bytes + result.entry_map_bytes + nodes;
    }

    pub fn slot_bytes(result: *const Result) u64 {
        const nodes = @as(u64, result.storage_nodes) * result.storage_node_bytes;
        return result.storage_table_bytes + nodes;
    }
};

pub const Case = struct { name: []const u8, shape: Shape };

pub const cases = [_]Case{
    .{
        .name = "db/footprint 100k acct, 1k x 64 slots",
        .shape = .{ .accounts = 100_000, .contracts = 1_000, .slots_per_contract = 64 },
    },
    .{
        .name = "db/footprint 1m acct, 10k x 64 slots",
        .shape = .{ .accounts = 1_000_000, .contracts = 10_000, .slots_per_contract = 64 },
    },
    .{
        .name = "db/footprint 10k acct, 100 x 10k slots (deep storage)",
        .shape = .{ .accounts = 10_000, .contracts = 100, .slots_per_contract = 10_000 },
    },
};

fn fill(state: *State, shape: Shape) !void {
    for (0..shape.accounts) |index| {
        const info: AccountInfo = .{ .nonce = 1, .balance = index + 1 };
        try state.put_account(bench.address_of(index), info);
    }
    for (0..shape.contracts) |contract| {
        const address = bench.address_of(contract);
        for (0..shape.slots_per_contract) |slot| {
            try state.put_storage(address, slot, slot + 1);
        }
    }
    _ = try state.state_root();
    assert(state.account_table.count() == shape.accounts);
    assert(state.storage_table.count() == shape.slots());
}

/// Bytes std allocates for a table of `Map` with room for exactly `count` entries.
fn table_bytes(comptime Map: type, child: std.mem.Allocator, count: u32) !u64 {
    var counter: Counter = .{ .child = child };
    var map: Map = .empty;
    try map.ensureTotalCapacity(counter.allocator(), count);
    const bytes = counter.live_bytes;
    map.deinit(counter.allocator());
    assert(counter.live_bytes == 0);
    return bytes;
}

pub fn measure(child: std.mem.Allocator, shape: Shape) !Result {
    assert(shape.accounts > 0);
    var counter: Counter = .{ .child = child };
    const allocator = counter.allocator();
    var state = try State.init(allocator, shape.config());
    defer state.deinit(allocator);
    const reserved_bytes = counter.live_bytes;
    try fill(&state, shape);
    // `put_*` and the root allocate nothing: the reservation is the whole footprint.
    assert(counter.live_bytes == reserved_bytes);
    const tries = &state.state_trie;
    const account_pool = @TypeOf(tries.accounts);
    const storage_pool = @TypeOf(tries.storage);
    const cache_bytes = @sizeOf(@TypeOf(tries.accounts.cache[0]));
    const order_bytes = @sizeOf(@TypeOf(tries.accounts.order[0]));
    const result: Result = .{
        .accounts = shape.accounts,
        .slots = shape.slots(),
        .account_nodes = tries.accounts.node_count(),
        .storage_nodes = tries.storage.node_count(),
        .account_node_bytes = @sizeOf(account_pool.Node) + cache_bytes + order_bytes,
        .storage_node_bytes = @sizeOf(storage_pool.Node) + cache_bytes + order_bytes,
        .reserved_bytes = reserved_bytes,
        .account_table_bytes = try table_bytes(@TypeOf(state.account_table), child, shape.accounts),
        .entry_map_bytes = try table_bytes(@TypeOf(tries.entries), child, shape.accounts),
        .storage_table_bytes = try table_bytes(@TypeOf(state.storage_table), child, shape.slots()),
    };
    assert(result.account_nodes >= result.accounts);
    assert(result.storage_nodes >= result.slots);
    return result;
}

fn per(bytes: u64, count: u64) f64 {
    if (count == 0) return 0;
    return @as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(count));
}

fn mib(bytes: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / (1024.0 * 1024.0);
}

fn print(name: []const u8, result: *const Result) void {
    std.debug.print(
        "{s}\n  nodes: account {d} ({d:.3}/acct, {d} B each), storage {d} " ++
            "({d:.3}/slot, {d} B each)\n" ++
            "  tight tables: account {d:.1} B/acct, entry map {d:.1} B/acct, " ++
            "storage {d:.1} B/slot\n" ++
            "  tight total: {d:.1} B/acct, {d:.1} B/slot ({d:.1} MiB); reserved {d:.1} MiB\n",
        .{
            name,
            result.account_nodes,
            per(result.account_nodes, result.accounts),
            result.account_node_bytes,
            result.storage_nodes,
            per(result.storage_nodes, result.slots),
            result.storage_node_bytes,
            per(result.account_table_bytes, result.accounts),
            per(result.entry_map_bytes, result.accounts),
            per(result.storage_table_bytes, result.slots),
            per(result.account_bytes(), result.accounts),
            per(result.slot_bytes(), result.slots),
            mib(result.account_bytes() + result.slot_bytes()),
            mib(result.reserved_bytes),
        },
    );
}

/// Runs the memory benchmarks whose names match `filter`.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    _ = io;
    for (cases) |case| {
        if (!bench.matches(case.name, filter)) continue;
        const result = measure(std.heap.page_allocator, case.shape) catch |err| {
            std.debug.print("{s}: failed: {s}\n", .{ case.name, @errorName(err) });
            continue;
        };
        print(case.name, &result);
    }
}

test "footprint bench: counts and bytes are consistent (small shape)" {
    const shape: Shape = .{ .accounts = 2_000, .contracts = 20, .slots_per_contract = 32 };
    const result = try measure(std.testing.allocator, shape);
    try std.testing.expectEqual(shape.accounts, result.accounts);
    try std.testing.expectEqual(shape.slots(), result.slots);
    // A random-key trie has one leaf per entry plus branches: more nodes than entries,
    // fewer than the 3-per-entry pool bound.
    try std.testing.expect(result.account_nodes > result.accounts);
    try std.testing.expect(result.account_nodes < 3 * result.accounts);
    try std.testing.expect(result.storage_nodes > result.slots);
    // Every table holds at least its keys and values.
    try std.testing.expect(result.account_table_bytes >= @as(u64, shape.accounts) * (20 + 72));
    try std.testing.expect(result.storage_table_bytes >= @as(u64, shape.slots()) * (20 + 32 + 32));
    try std.testing.expect(result.reserved_bytes > result.account_bytes());
}

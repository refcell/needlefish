//! geth's `prestateTracer` (config `diffMode`) over the executor's journaled state.
//!
//! No evm hook is needed: after a transaction executes, the state cache stamps every
//! account and slot it warmed with the transaction id, and each slot keeps its value from
//! the transaction's start (`original`). The pre-transaction account infos come from a
//! snapshot of the cache taken just before the transaction (earlier transactions of the
//! block live only there), else from the session database. `collect` copies everything
//! (code included) into bounded scratch, so writing never reads the live state.
//!
//! An account is reported when the transaction warmed or changed it, or ran as a call
//! frame; a slot when it was warmed or changed, or read by the transaction in a frame's
//! account (system reads such as the L1 fee parameters neither warm nor run as frames).
//! Frames come from the evm call-frame hook (`tracer`), so frames that later revert, whose
//! warm stamps the revert clears, still count. An account reached only by BALANCE or
//! EXTCODE* inside a reverted frame is still missed.
//! Output is sorted by address (and slot). Diff mode reports, as geth, `pre` for changed
//! accounts that existed (with only their changed slots) and `post` with only changed
//! fields, so created accounts appear only in `post` and destroyed ones only in `pre`.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");

const Address = [20]u8;

/// `0x`-prefixed lowercase hex of `bytes` in `target` (2 + 2 * len bytes).
fn hex_into(target: []u8, bytes: []const u8) []const u8 {
    assert(target.len == 2 + 2 * bytes.len);
    target[0..2].* = "0x".*;
    json.hex_encode(target[2..], bytes);
    return target;
}
const Hash = [32]u8;

pub const Info = struct {
    balance: u256 = 0,
    nonce: u64 = 0,
    code_hash: Hash = evm.primitives.keccak_empty,
    code: []const u8 = &.{},
    exists: bool = false,
};

pub const AccountEntry = struct {
    address: Address,
    pre: Info,
    post: Info,
};

pub const SlotEntry = struct {
    address: Address,
    slot: u256,
    pre: u256,
    post: u256,
};

const Snapshot = std.AutoHashMapUnmanaged(Address, evm.state.AccountInfo);

/// Distinct frame addresses remembered per transaction; more mark the result `full`.
pub const frames_max = 512;

pub const Collected = struct {
    accounts: []AccountEntry,
    account_count: u32 = 0,
    slots: []SlotEntry,
    slot_count: u32 = 0,
    bytes: []u8,
    bytes_used: usize = 0,
    snapshot_space: []u8,
    snapshot: Snapshot = .empty,
    /// A bound was hit; the result is incomplete and must not be served.
    full: bool = false,
    /// The database failed while reading a pre-state.
    failed: bool = false,
    /// Addresses that ran as call frames (from and to) in the traced transaction.
    frames: [frames_max]Address = undefined,
    frame_count: u32 = 0,

    /// Carves the collector out of `space`; null when it is too small.
    pub fn init(space: []u8) ?Collected {
        var fixed: std.heap.FixedBufferAllocator = .init(space);
        const allocator = fixed.allocator();
        const accounts = allocator.alloc(AccountEntry, space.len / 8 / @sizeOf(AccountEntry)) catch
            return null;
        const slots = allocator.alloc(SlotEntry, space.len / 8 / @sizeOf(SlotEntry)) catch
            return null;
        const snapshot_space = allocator.alloc(u8, space.len / 2) catch return null;
        const bytes = allocator.alloc(u8, space.len - fixed.end_index) catch return null;
        if (accounts.len == 0 or slots.len == 0) return null;
        return .{
            .accounts = accounts,
            .slots = slots,
            .bytes = bytes,
            .snapshot_space = snapshot_space,
        };
    }

    /// Copies the cached account infos; call just before the traced transaction.
    pub fn take_snapshot(collected: *Collected, state: *const evm.State) void {
        var fixed: std.heap.FixedBufferAllocator = .init(collected.snapshot_space);
        collected.snapshot = .empty;
        collected.frame_count = 0;
        const count = state.accounts.count();
        collected.snapshot.ensureTotalCapacity(fixed.allocator(), count) catch {
            collected.full = true;
            return;
        };
        var accounts = state.accounts.iterator();
        while (accounts.next()) |item| {
            collected.snapshot.putAssumeCapacity(item.key_ptr.*, item.value_ptr.info);
        }
        assert(collected.snapshot.count() == count);
    }

    fn copy(collected: *Collected, data: []const u8) []const u8 {
        if (collected.bytes.len - collected.bytes_used < data.len) {
            collected.full = true;
            return &.{};
        }
        const out = collected.bytes[collected.bytes_used..][0..data.len];
        @memcpy(out, data);
        collected.bytes_used += data.len;
        return out;
    }

    fn info_of(
        collected: *Collected,
        state: *State,
        info: evm.state.AccountInfo,
        exists: bool,
    ) Info {
        const code: []const u8 = if (info.code) |code| code else if (info.has_code())
            state.database.code_by_hash(info.code_hash) catch blk: {
                collected.failed = true;
                break :blk &.{};
            }
        else
            &.{};
        return .{
            .balance = info.balance,
            .nonce = info.nonce,
            .code_hash = info.code_hash,
            .code = collected.copy(code),
            .exists = exists and !info.is_empty(),
        };
    }

    /// Records the accounts and slots of the state's current transaction.
    pub fn collect(collected: *Collected, state: *State) void {
        collected.account_count = 0;
        collected.slot_count = 0;
        collected.bytes_used = 0;
        const tx_id = state.tx_id;
        var accounts = state.accounts.iterator();
        while (accounts.next()) |item| {
            const account = item.value_ptr;
            const pre = collected.pre_of(state, account.address);
            const post_exists = !account.self_destructed;
            const post = collected.info_of(state, account.info, post_exists);
            const framed = collected.is_frame(&account.address);
            if (account.warm_tx != tx_id and !framed and !info_changed(&pre, &post)) continue;
            if (collected.account_count == collected.accounts.len) {
                collected.full = true;
                return;
            }
            collected.accounts[collected.account_count] = .{
                .address = account.address,
                .pre = pre,
                .post = post,
            };
            collected.account_count += 1;
        }
        collected.collect_slots(state);
        sort(collected);
    }

    fn pre_of(collected: *Collected, state: *State, address: Address) Info {
        if (collected.snapshot.get(address)) |info| return collected.info_of(state, info, true);
        const found = state.database.basic(address) catch {
            collected.failed = true;
            return .{};
        };
        return collected.info_of(state, found orelse .{}, found != null);
    }

    fn collect_slots(collected: *Collected, state: *State) void {
        const tx_id = state.tx_id;
        var slots = state.slots.iterator();
        while (slots.next()) |item| {
            const slot = item.value_ptr;
            if (slot.original_tx != tx_id) continue;
            const warm_or_changed = slot.warm_tx == tx_id or slot.present != slot.original;
            if (!warm_or_changed and !collected.is_frame(&item.key_ptr.address)) continue;
            if (collected.slot_count == collected.slots.len) {
                collected.full = true;
                return;
            }
            collected.slots[collected.slot_count] = .{
                .address = item.key_ptr.address,
                .slot = item.key_ptr.slot,
                .pre = slot.original,
                .post = slot.present,
            };
            collected.slot_count += 1;
        }
    }

    fn is_frame(collected: *const Collected, address: *const Address) bool {
        for (collected.frames[0..collected.frame_count]) |*frame| {
            if (std.mem.eql(u8, frame, address)) return true;
        }
        return false;
    }

    fn note_frame(collected: *Collected, address: Address) void {
        if (collected.is_frame(&address)) return;
        if (collected.frame_count == frames_max) {
            collected.full = true;
            return;
        }
        collected.frames[collected.frame_count] = address;
        collected.frame_count += 1;
    }

    /// The evm hook recording frame addresses; attach it for the traced transaction.
    pub fn tracer(collected: *Collected) evm.evm.Tracer {
        return .{ .context = collected, .enter = on_enter, .exit = on_exit, .log = on_log };
    }

    fn on_enter(context: *anyopaque, frame: evm.evm.TraceFrame) void {
        const collected: *Collected = @ptrCast(@alignCast(context));
        collected.note_frame(frame.from);
        collected.note_frame(frame.to);
    }

    fn on_exit(_: *anyopaque, _: evm.evm.Outcome) void {}

    fn on_log(_: *anyopaque, _: Address, _: []const [32]u8, _: []const u8) void {}

    /// The `Executor.Inspect` hook (debug_traceCall).
    pub fn inspect(collected: *Collected) @import("../node/root.zig").executor.Executor.Inspect {
        return .{ .context = collected, .run = run_inspect };
    }

    fn run_inspect(context: *anyopaque, state: *State) void {
        const collected: *Collected = @ptrCast(@alignCast(context));
        collected.collect(state);
    }
};

const State = evm.State;

fn info_changed(pre: *const Info, post: *const Info) bool {
    return pre.exists != post.exists or pre.balance != post.balance or
        pre.nonce != post.nonce or !std.mem.eql(u8, &pre.code_hash, &post.code_hash);
}

fn address_less(_: void, a: AccountEntry, b: AccountEntry) bool {
    return std.mem.order(u8, &a.address, &b.address) == .lt;
}

fn slot_less(_: void, a: SlotEntry, b: SlotEntry) bool {
    return switch (std.mem.order(u8, &a.address, &b.address)) {
        .lt => true,
        .gt => false,
        .eq => a.slot < b.slot,
    };
}

fn sort(collected: *Collected) void {
    std.mem.sort(AccountEntry, collected.accounts[0..collected.account_count], {}, address_less);
    std.mem.sort(SlotEntry, collected.slots[0..collected.slot_count], {}, slot_less);
}

// ---- Output -----------------------------------------------------------------------

const Side = enum { pre, post };

fn write_slots(
    w: *json.Writer,
    slots: []const SlotEntry,
    side: Side,
    changed_only: bool,
) json.Writer.WriteError!void {
    var count: u32 = 0;
    for (slots) |slot| count += @intFromBool(!changed_only or slot.pre != slot.post);
    if (count == 0) return;
    try w.key("storage");
    try w.begin_object();
    for (slots) |slot| {
        if (changed_only and slot.pre == slot.post) continue;
        var key_bytes: Hash = undefined;
        std.mem.writeInt(u256, &key_bytes, slot.slot, .big);
        var key_text: [66]u8 = undefined;
        try w.key(hex_into(&key_text, &key_bytes));
        var value: Hash = undefined;
        std.mem.writeInt(u256, &value, if (side == .pre) slot.pre else slot.post, .big);
        try w.data(&value);
    }
    try w.end_object();
}

/// Writes one account; in diff mode `post` writes only the fields that changed.
fn write_account(
    w: *json.Writer,
    entry: *const AccountEntry,
    slots: []const SlotEntry,
    side: Side,
    diff: bool,
) json.Writer.WriteError!void {
    const info = if (side == .pre) &entry.pre else &entry.post;
    const only_changes = diff and side == .post;
    var address_text: [42]u8 = undefined;
    try w.key(hex_into(&address_text, &entry.address));
    try w.begin_object();
    if (!only_changes or entry.pre.balance != entry.post.balance) {
        try w.key("balance");
        try w.quantity(info.balance);
    }
    if (info.nonce > 0 and (!only_changes or entry.pre.nonce != entry.post.nonce)) {
        try w.key("nonce");
        try w.integer(info.nonce);
    }
    const code_changed = !std.mem.eql(u8, &entry.pre.code_hash, &entry.post.code_hash);
    if (info.code.len > 0 and (!only_changes or code_changed)) {
        try w.key("code");
        try w.data(info.code);
    }
    try write_slots(w, slots, side, diff);
    try w.end_object();
}

fn slots_of(collected: *const Collected, cursor: *u32, address: *const Address) []const SlotEntry {
    const slots = collected.slots[0..collected.slot_count];
    while (cursor.* < slots.len and
        std.mem.order(u8, &slots[cursor.*].address, address) == .lt) cursor.* += 1;
    const start = cursor.*;
    while (cursor.* < slots.len and std.mem.eql(u8, &slots[cursor.*].address, address)) {
        cursor.* += 1;
    }
    return slots[start..cursor.*];
}

fn write_side(w: *json.Writer, collected: *const Collected, side: Side, diff: bool) !void {
    try w.begin_object();
    var cursor: u32 = 0;
    for (collected.accounts[0..collected.account_count]) |*entry| {
        const slots = slots_of(collected, &cursor, &entry.address);
        if (diff) {
            var slot_changed = false;
            for (slots) |slot| slot_changed = slot_changed or slot.pre != slot.post;
            if (!slot_changed and !info_changed(&entry.pre, &entry.post)) continue;
            const exists = if (side == .pre) entry.pre.exists else entry.post.exists;
            if (!exists) continue;
        }
        try write_account(w, entry, slots, side, diff);
    }
    try w.end_object();
}

/// Writes the collected prestate (or `{pre, post}` in diff mode).
pub fn write(w: *json.Writer, collected: *const Collected, diff: bool) json.Writer.WriteError!void {
    assert(!collected.full and !collected.failed);
    if (!diff) return write_side(w, collected, .pre, false);
    try w.begin_object();
    try w.key("pre");
    try write_side(w, collected, .pre, true);
    try w.key("post");
    try write_side(w, collected, .post, true);
    try w.end_object();
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

/// Random collections (sorted, as `collect` leaves them) write valid JSON in both modes.
fn random_collection(seed: u64) !void {
    var prng = Prng.init(seed);
    var accounts: [8]AccountEntry = undefined;
    var slots: [16]SlotEntry = undefined;
    const code = [_]u8{ 0x60, 0x00 };
    var collected: Collected = .{
        .accounts = &accounts,
        .slots = &slots,
        .bytes = &.{},
        .snapshot_space = &.{},
    };
    collected.account_count = @intCast(prng.range(0, accounts.len));
    for (accounts[0..collected.account_count], 0..) |*entry, index| {
        var info: [2]Info = undefined;
        for (&info) |*side| side.* = .{
            .balance = prng.below(4),
            .nonce = prng.below(3),
            .code_hash = if (prng.chance(1, 2)) evm.primitives.keccak_empty else @splat(1),
            .code = if (prng.chance(1, 2)) &code else &.{},
            .exists = prng.chance(3, 4),
        };
        entry.* = .{ .address = @splat(@intCast(index)), .pre = info[0], .post = info[1] };
    }
    collected.slot_count = @intCast(prng.range(0, slots.len));
    for (slots[0..collected.slot_count], 0..) |*slot, index| slot.* = .{
        .address = @splat(@intCast(index / 2)),
        .slot = index,
        .pre = prng.below(3),
        .post = prng.below(3),
    };
    var out: [1 << 15]u8 = undefined;
    for ([_]bool{ false, true }) |diff| {
        var writer: std.Io.Writer = .fixed(&out);
        var w: json.Writer = .init(&writer);
        try write(&w, &collected, diff);
        try json.validate(writer.buffered());
    }
}

test "prestate: seeded fuzz of prestate output" {
    for (0..256) |seed| try random_collection(seed);
}

test "prestate: fuzz prestate output" {
    try testing.fuzz({}, fuzz_collection, .{});
}

fn fuzz_collection(_: void, smith: *testing.Smith) anyerror!void {
    try random_collection(smith.value(u64));
}

test "prestate: diff mode keeps only changes in post" {
    var accounts = [_]AccountEntry{.{
        .address = @splat(5),
        .pre = .{ .balance = 7, .nonce = 1, .exists = true },
        .post = .{ .balance = 7, .nonce = 2, .exists = true },
    }};
    var slots = [_]SlotEntry{
        .{ .address = @splat(5), .slot = 1, .pre = 3, .post = 3 },
        .{ .address = @splat(5), .slot = 2, .pre = 0, .post = 9 },
    };
    const collected: Collected = .{
        .accounts = &accounts,
        .account_count = 1,
        .slots = &slots,
        .slot_count = 2,
        .bytes = &.{},
        .snapshot_space = &.{},
    };
    var out: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var w: json.Writer = .init(&writer);
    try write(&w, &collected, true);
    const text = writer.buffered();
    const post = text[std.mem.indexOf(u8, text, "\"post\"").?..];
    try testing.expect(std.mem.indexOf(u8, post, "balance") == null);
    try testing.expect(std.mem.indexOf(u8, post, "\"nonce\":2") != null);
    // Only the changed slot, in both sides.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, text, "0002\":"));
    try testing.expect(std.mem.indexOf(u8, text, "0001\":") == null);
}

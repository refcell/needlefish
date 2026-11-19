//! revm-inspectors' `prestateTracer` (`geth_prestate_traces`, configs `diffMode`,
//! `disableCode`, `disableStorage`) over the executor's journaled state.
//!
//! No evm hook is needed: the state cache stamps every account a transaction loads
//! (`seen_tx`, kept when a frame reverts) and every slot it reads or writes keeps its value
//! from the transaction's start (`original`, stamped `original_tx`). Those are the accounts
//! and slots of revm's post-transaction state, which reth hands to the tracer. System reads
//! (the L1 fee parameters) leave no stamp, as they bypass revm's journal. The pre-transaction
//! account infos come from a snapshot of the cache taken just before the transaction
//! (earlier transactions of the block, state overrides), else from the session database.
//! `collect` copies everything (code included) into bounded scratch, so writing never reads
//! the live state.
//!
//! Output is sorted by address (and slot). The default mode reports each account that was
//! not empty before the transaction, with every slot read; diff mode follows
//! `geth_prestate_diff_traces`: only changed accounts and changed non-zero slots, `pre`
//! without accounts empty before (Nethermind), `post` without destroyed ones and with only
//! changed fields.
//! As Nethermind's tracer, an account also gets its `codeHash`, every EIP-7702 authority
//! with a valid signature is looked up, its authorization valid or not, and so is the
//! block's beneficiary for every transaction (deposits included). As geth's tracer, an
//! account an instruction first reads but then cannot pay to run is left out
//! (`State.unsee`), and so is a slot first read by an SSTORE that then runs out of gas
//! (`State.unstamp_slot`). A diff's
//! `post` gives an account missing after the transaction a zero `codeHash`.

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

    /// revm-inspectors' `account_was_empty` (the code hash, whatever `disableCode` says).
    fn is_empty(info: *const Info) bool {
        const no_code = std.mem.eql(u8, &info.code_hash, &evm.primitives.keccak_empty);
        return info.balance == 0 and info.nonce == 0 and no_code;
    }
};

/// The `post` code hash of an account missing after the transaction: Nethermind (as geth)
/// reads a zero hash for it, so a diff lists every account the transaction looked up that
/// does not exist afterwards (a precompile it called, say) with `codeHash` zero in `post`.
const missing_code_hash: Hash = @splat(0);

pub const AccountEntry = struct {
    address: Address,
    pre: Info,
    post: Info,
    /// Created by CREATE in the transaction (revm `is_created`).
    created: bool = false,
    /// Destroyed by a SELFDESTRUCT that ran in the transaction, even in a frame that then
    /// reverted (Nethermind's and geth's deleted accounts).
    destroyed: bool = false,
};

pub const SlotEntry = struct {
    address: Address,
    slot: u256,
    pre: u256,
    post: u256,
};

/// The tracer config (alloy `PreStateConfig`).
pub const Config = struct {
    diff: bool = false,
    code: bool = true,
    storage: bool = true,
};

const Snapshot = std.AutoHashMapUnmanaged(Address, evm.state.AccountInfo);

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
    /// The traced call's EIP-7702 authorizations (debug_traceCall), whose recoverable
    /// authorities are listed even when the authorization is invalid.
    authorities: []const evm.transaction.Authorization = &.{},
    /// The traced call's callee (debug_traceCall), null for a creation.
    callee: ?Address = null,
    /// The traced call's sender (debug_traceCall).
    sender: ?Address = null,

    /// Carves the collector out of `space` (left untouched until used); null when it is too
    /// small. An eighth each goes to accounts and slots, a quarter to the snapshot of the
    /// cached accounts, and the rest holds the accounts' code.
    pub fn init(space: []u8) ?Collected {
        const carve = @import("trace.zig").carve;
        var used: usize = 0;
        const account_count = space.len / 8 / @sizeOf(AccountEntry);
        const accounts = carve(AccountEntry, space, &used, account_count) orelse return null;
        const slot_count = space.len / 8 / @sizeOf(SlotEntry);
        const slots = carve(SlotEntry, space, &used, slot_count) orelse return null;
        const snapshot_space = carve(u8, space, &used, space.len / 4) orelse return null;
        if (accounts.len == 0 or slots.len == 0) return null;
        assert(used <= space.len);
        return .{
            .accounts = accounts,
            .slots = slots,
            .bytes = space[used..],
            .snapshot_space = snapshot_space,
        };
    }

    /// Copies the cached account infos; call just before the traced transaction.
    pub fn take_snapshot(collected: *Collected, state: *const evm.State) void {
        var fixed: std.heap.FixedBufferAllocator = .init(collected.snapshot_space);
        collected.snapshot = .empty;
        const count = state.accounts.count();
        collected.snapshot.ensureTotalCapacity(fixed.allocator(), count) catch {
            collected.full = true;
            return;
        };
        // The insertion list, not the table: the table's capacity follows the gas limit
        // (about a million entries), so iterating it per transaction stalls block traces.
        for (state.touched_accounts()) |account| {
            collected.snapshot.putAssumeCapacity(account.address, account.info);
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

    /// The account's fields with its code copied, unless `same` already holds that code.
    fn info_of(
        collected: *Collected,
        state: *State,
        info: evm.state.AccountInfo,
        same: ?*const Info,
    ) Info {
        if (same) |other| if (std.mem.eql(u8, &other.code_hash, &info.code_hash)) return .{
            .balance = info.balance,
            .nonce = info.nonce,
            .code_hash = info.code_hash,
            .code = other.code,
        };
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
        };
    }

    /// Records the accounts and slots of the state's current transaction.
    pub fn collect(collected: *Collected, state: *State) void {
        collected.account_count = 0;
        collected.slot_count = 0;
        collected.bytes_used = 0;
        const tx_id = state.tx_id;
        for (state.touched_accounts()) |account| {
            if (account.seen_tx != tx_id) continue;
            if (collected.account_count == collected.accounts.len) {
                collected.full = true;
                return;
            }
            const pre = collected.pre_of(state, account.address);
            var post = collected.info_of(state, account.info, &pre);
            if (!account.in_database) post.code_hash = missing_code_hash;
            collected.accounts[collected.account_count] = .{
                .address = account.address,
                .pre = pre,
                .post = post,
                .created = account.created_tx == tx_id,
                .destroyed = account.self_destruct_tx == tx_id,
            };
            collected.account_count += 1;
        }
        collected.collect_slots(state);
        sort(collected);
        collected.add_unborn(state);
    }

    /// Lists the addresses of creates that paid their gas but failed before the address
    /// was loaded (`State.note_unborn`): geth's and Nethermind's tracer look the created
    /// address up and count it created, so a diff's post lists it missing.
    fn add_unborn(collected: *Collected, state: *State) void {
        if (state.unborn_overflow) {
            collected.full = true;
            return;
        }
        for (state.unborn[0..state.unborn_count]) |address| collected.add_created(state, address);
    }

    /// Lists the address a creation transaction from `sender` makes, at the sender's nonce
    /// before the transaction, as created.
    pub fn add_created_by(collected: *Collected, state: *State, sender: Address) void {
        const nonce = collected.pre_of(state, sender).nonce;
        collected.add_created(state, evm.evm.create_address(sender, nonce));
    }

    /// debug_traceCall's sender, which Nethermind's tracer looks up with the address a
    /// creation makes (counted created; the `NativePrestateTracer` constructor). An unpriced
    /// call creates a missing sender (`TransactionProcessor.RecoverSenderIfNeeded`), which
    /// is still there when the tracer reads the post-state: never missing, so a sender whose
    /// nonce the call did not bump (a creation that cannot pay its value) is no diff.
    fn add_call_sender(collected: *Collected, state: *State, sender: Address) void {
        if (collected.callee == null) collected.add_created_by(state, sender);
        const entry = collected.add_account(state, sender) orelse return;
        if (std.mem.eql(u8, &entry.post.code_hash, &missing_code_hash)) {
            entry.post.code_hash = evm.primitives.keccak_empty;
        }
    }

    /// Lists `address` as created in the transaction (looked up if it was not loaded).
    pub fn add_created(collected: *Collected, state: *State, address: Address) void {
        const entry = collected.add_account(state, address) orelse return;
        entry.created = true;
    }

    /// Lists the callee and its EIP-7702 delegate as they were before the transaction, as
    /// Nethermind's tracer looks both up before the authorizations apply (the execution
    /// leaves the delegate it runs unseen). Call after `collect`.
    pub fn add_callee(collected: *Collected, state: *State, callee: Address) void {
        const entry = collected.add_account(state, callee) orelse return;
        const delegate = evm.bytecode.delegation_target(entry.pre.code) orelse return;
        _ = collected.add_account(state, delegate);
    }

    /// Lists an account the transaction may not have loaded, as Nethermind's tracer looks
    /// it up: an EIP-7702 authority with a valid signature whose authorization was invalid
    /// (another chain id, a nonce of 2^64 - 1), or the block's beneficiary (a deposit pays
    /// it nothing). Call after `collect`; keeps the address order.
    pub fn add_account(
        collected: *Collected,
        state: *State,
        address: Address,
    ) ?*AccountEntry {
        const accounts = collected.accounts[0..collected.account_count];
        var position: usize = 0;
        while (position < accounts.len) : (position += 1) {
            switch (std.mem.order(u8, &accounts[position].address, &address)) {
                .lt => continue,
                .eq => return &accounts[position],
                .gt => break,
            }
        }
        if (collected.account_count == collected.accounts.len) {
            collected.full = true;
            return null;
        }
        const pre = collected.pre_of(state, address);
        var post = pre;
        if (state.accounts.get(address)) |account| {
            post = collected.info_of(state, account.info, &pre);
            if (!account.in_database) post.code_hash = missing_code_hash;
        } else {
            const found = state.database.basic(address) catch blk: {
                collected.failed = true;
                break :blk null;
            };
            if (found == null) post.code_hash = missing_code_hash;
        }
        const count = collected.account_count;
        std.mem.copyBackwards(
            AccountEntry,
            collected.accounts[position + 1 .. count + 1],
            collected.accounts[position..count],
        );
        collected.accounts[position] = .{ .address = address, .pre = pre, .post = post };
        collected.account_count += 1;
        assert(collected.account_count <= collected.accounts.len);
        return &collected.accounts[position];
    }

    fn pre_of(collected: *Collected, state: *State, address: Address) Info {
        if (collected.snapshot.get(address)) |info| {
            return collected.info_of(state, info, null);
        }
        const found = state.database.basic(address) catch {
            collected.failed = true;
            return .{};
        };
        return collected.info_of(state, found orelse .{}, null);
    }

    /// The slots the transaction read or wrote (stamped `original_tx`).
    fn collect_slots(collected: *Collected, state: *State) void {
        const tx_id = state.tx_id;
        for (state.touched_slots()) |item| {
            const slot = item.slot;
            if (slot.original_tx != tx_id) continue;
            if (collected.slot_count == collected.slots.len) {
                collected.full = true;
                return;
            }
            collected.slots[collected.slot_count] = .{
                .address = item.key.address,
                .slot = item.key.slot,
                .pre = slot.original,
                .post = slot.present,
            };
            collected.slot_count += 1;
        }
    }

    /// The `Executor.Inspect` hooks (debug_traceCall): the snapshot after the overrides,
    /// the collection after the call.
    pub fn inspect(collected: *Collected) @import("../node/root.zig").executor.Executor.Inspect {
        return .{ .context = collected, .begin = begin_inspect, .run = run_inspect };
    }

    fn begin_inspect(context: *anyopaque, state: *const State) void {
        const collected: *Collected = @ptrCast(@alignCast(context));
        collected.take_snapshot(state);
    }

    fn run_inspect(context: *anyopaque, state: *State) void {
        const collected: *Collected = @ptrCast(@alignCast(context));
        collected.collect(state);
        if (collected.callee) |callee| collected.add_callee(state, callee);
        if (collected.sender) |sender| collected.add_call_sender(state, sender);
        for (collected.authorities) |authorization| {
            const authority = authorization.authority orelse continue;
            _ = collected.add_account(state, authority);
        }
    }
};

const State = evm.State;

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

/// Which slots a side lists: every one read (default mode), or the changed ones with a
/// non-zero value on that side (diff mode, alloy `remove_zero_storage_values`).
fn slot_listed(slot: *const SlotEntry, side: Side, diff: bool) bool {
    if (!diff) return true;
    const value = if (side == .pre) slot.pre else slot.post;
    return slot.pre != slot.post and value != 0;
}

fn write_slots(
    w: *json.Writer,
    slots: []const SlotEntry,
    side: Side,
    diff: bool,
) json.Writer.WriteError!void {
    var count: u32 = 0;
    for (slots) |*slot| count += @intFromBool(slot_listed(slot, side, diff));
    if (count == 0) return;
    try w.key("storage");
    try w.begin_object();
    for (slots) |*slot| {
        if (!slot_listed(slot, side, diff)) continue;
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

/// Writes one account. A diff's `post` keeps only the fields that differ from `pre`
/// (alloy `remove_matching_account_info`); a zero nonce and empty code are never written,
/// and `codeHash` follows the code as Nethermind writes it.
fn write_account(
    w: *json.Writer,
    entry: *const AccountEntry,
    slots: []const SlotEntry,
    side: Side,
    config: Config,
) json.Writer.WriteError!void {
    const info = if (side == .pre) &entry.pre else &entry.post;
    const only_changes = config.diff and side == .post;
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
    if (config.code and info.code.len > 0 and (!only_changes or !same_code(entry))) {
        try w.key("code");
        try w.data(info.code);
    }
    if (code_hash_listed(entry, side, config)) {
        try w.key("codeHash");
        try w.data(&info.code_hash);
    }
    if (config.storage) try write_slots(w, slots, side, config.diff);
    try w.end_object();
}

/// Nethermind's `codeHash` (`disableCode` or not): an account with code lists its hash, and
/// a diff's `post` lists the hash whenever it changed (the empty-code hash included).
fn code_hash_listed(entry: *const AccountEntry, side: Side, config: Config) bool {
    if (config.diff and side == .post) return !same_code(entry);
    const info = if (side == .pre) &entry.pre else &entry.post;
    return !std.mem.eql(u8, &info.code_hash, &evm.primitives.keccak_empty) and
        !std.mem.eql(u8, &info.code_hash, &@as(Hash, @splat(0)));
}

fn same_code(entry: *const AccountEntry) bool {
    return std.mem.eql(u8, &entry.pre.code_hash, &entry.post.code_hash);
}

/// Whether a diff keeps the account (alloy `retain_changed`): its pre and post states
/// differ, or it was destroyed (revm-inspectors never puts it in `post`).
fn diff_keeps(entry: *const AccountEntry, slots: []const SlotEntry, config: Config) bool {
    if (entry.destroyed) return true;
    if (config.storage) {
        for (slots) |slot| if (slot.pre != slot.post) return true;
    }
    // A changed code hash is a change even under `disableCode` (Nethermind's `codeHash`).
    if (!same_code(entry)) return true;
    return entry.pre.balance != entry.post.balance or entry.pre.nonce != entry.post.nonce;
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

/// Whether `side` lists the account: the default mode skips accounts empty before the
/// transaction; so does a diff's `pre` (Nethermind), unless the account was not created
/// and has slots to list there; a diff's `post` skips destroyed accounts.
fn side_lists(
    entry: *const AccountEntry,
    slots: []const SlotEntry,
    side: Side,
    config: Config,
) bool {
    if (!config.diff) return !entry.pre.is_empty();
    if (!diff_keeps(entry, slots, config)) return false;
    return switch (side) {
        .pre => !entry.pre.is_empty() or (!entry.created and pre_slots_listed(slots, config)),
        .post => !entry.destroyed,
    };
}

fn pre_slots_listed(slots: []const SlotEntry, config: Config) bool {
    assert(config.diff);
    if (!config.storage) return false;
    for (slots) |*slot| if (slot_listed(slot, .pre, true)) return true;
    return false;
}

fn write_side(w: *json.Writer, collected: *const Collected, side: Side, config: Config) !void {
    assert(config.diff or side == .pre);
    try w.begin_object();
    var cursor: u32 = 0;
    for (collected.accounts[0..collected.account_count]) |*entry| {
        const slots = slots_of(collected, &cursor, &entry.address);
        if (!side_lists(entry, slots, side, config)) continue;
        try write_account(w, entry, slots, side, config);
    }
    try w.end_object();
}

/// Writes the collected prestate (or `{pre, post}` in diff mode).
pub fn write(
    w: *json.Writer,
    collected: *const Collected,
    config: Config,
) json.Writer.WriteError!void {
    assert(!collected.full and !collected.failed);
    if (!config.diff) return write_side(w, collected, .pre, config);
    try w.begin_object();
    try w.key("pre");
    try write_side(w, collected, .pre, config);
    try w.key("post");
    try write_side(w, collected, .post, config);
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
        };
        entry.* = .{
            .address = @splat(@intCast(index)),
            .pre = info[0],
            .post = info[1],
            .created = prng.chance(1, 4),
            .destroyed = prng.chance(1, 4),
        };
    }
    collected.slot_count = @intCast(prng.range(0, slots.len));
    for (slots[0..collected.slot_count], 0..) |*slot, index| slot.* = .{
        .address = @splat(@intCast(index / 2)),
        .slot = index,
        .pre = prng.below(3),
        .post = prng.below(3),
    };
    var out: [1 << 15]u8 = undefined;
    for (0..8) |bits| {
        const config: Config = .{
            .diff = bits & 1 != 0,
            .code = bits & 2 != 0,
            .storage = bits & 4 != 0,
        };
        var writer: std.Io.Writer = .fixed(&out);
        var w: json.Writer = .init(&writer);
        try write(&w, &collected, config);
        const text = writer.buffered();
        try json.validate(text);
        if (!config.code) try testing.expect(std.mem.indexOf(u8, text, "\"code\"") == null);
        if (!config.storage) try testing.expect(std.mem.indexOf(u8, text, "storage") == null);
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

fn word_text(comptime last: []const u8) []const u8 {
    const zeros = "00000000000000000000000000000000000000000000000000000000000000";
    comptime assert(zeros.len == 62);
    return "\"0x" ++ zeros ++ last ++ "\"";
}

fn address_key(comptime byte: []const u8) []const u8 {
    comptime var text: []const u8 = "\"0x";
    inline for (0..20) |_| text = text ++ byte;
    return text ++ "\"";
}

const address_4 = address_key("04");
const address_5 = address_key("05");
const address_6 = address_key("06");
const address_7 = address_key("07");
const address_8 = address_key("08");
const word_0 = word_text("00");
const word_1 = word_text("01");
const word_2 = word_text("02");
const word_3 = word_text("03");
const word_4 = word_text("04");
const word_9 = word_text("09");

fn write_text(collected: *const Collected, config: Config, out: []u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    var w: json.Writer = .init(&writer);
    try write(&w, collected, config);
    return writer.buffered();
}

test "prestate: modes follow revm-inspectors' geth_prestate_traces" {
    var accounts = [_]AccountEntry{
        // Empty before, not created (a sender): only in a diff's post (Nethermind).
        .{ .address = @splat(4), .pre = .{}, .post = .{ .nonce = 1 } },
        .{
            .address = @splat(5),
            .pre = .{ .balance = 7, .nonce = 1 },
            .post = .{ .balance = 7, .nonce = 2 },
        },
        // Created on an empty address: only in a diff's post.
        .{ .address = @splat(6), .pre = .{}, .post = .{ .nonce = 1 }, .created = true },
        // Destroyed: only in a diff's pre.
        .{ .address = @splat(7), .pre = .{ .balance = 5 }, .post = .{}, .destroyed = true },
        // Read only: in the default mode alone.
        .{ .address = @splat(8), .pre = .{ .balance = 3 }, .post = .{ .balance = 3 } },
    };
    var slots = [_]SlotEntry{
        .{ .address = @splat(5), .slot = 1, .pre = 3, .post = 3 },
        .{ .address = @splat(5), .slot = 2, .pre = 0, .post = 9 },
        .{ .address = @splat(5), .slot = 3, .pre = 4, .post = 0 },
    };
    const collected: Collected = .{
        .accounts = &accounts,
        .account_count = accounts.len,
        .slots = &slots,
        .slot_count = slots.len,
        .bytes = &.{},
        .snapshot_space = &.{},
    };
    var out: [2048]u8 = undefined;
    // A diff lists changed slots without their zero values, and post only what changed.
    try testing.expectEqualStrings("{\"pre\":{" ++ address_5 ++
        ":{\"balance\":\"0x7\",\"nonce\":1,\"storage\":{" ++ word_3 ++ ":" ++
        word_4 ++ "}}," ++ address_7 ++ ":{\"balance\":\"0x5\"}}," ++
        "\"post\":{" ++ address_4 ++ ":{\"nonce\":1}," ++
        address_5 ++ ":{\"nonce\":2,\"storage\":{" ++
        word_2 ++ ":" ++ word_9 ++ "}}," ++ address_6 ++
        ":{\"nonce\":1}}}", try write_text(&collected, .{ .diff = true }, &out));
    // The default mode skips accounts empty before the transaction, keeps every slot read.
    const full = "{" ++ address_5 ++ ":{\"balance\":\"0x7\",\"nonce\":1," ++
        "\"storage\":{" ++ word_1 ++ ":" ++ word_3 ++ "," ++
        word_2 ++ ":" ++ word_0 ++ "," ++ word_3 ++ ":" ++
        word_4 ++ "}}," ++ address_7 ++ ":{\"balance\":\"0x5\"}," ++
        address_8 ++ ":{\"balance\":\"0x3\"}}";
    try testing.expectEqualStrings(full, try write_text(&collected, .{}, &out));
    // disableStorage drops the slots; a diff without them keeps only info changes.
    const bare = try write_text(&collected, .{ .storage = false }, &out);
    try testing.expect(std.mem.indexOf(u8, bare, "storage") == null);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, bare, "balance"));
    const bare_diff = try write_text(&collected, .{ .diff = true, .storage = false }, &out);
    try testing.expect(std.mem.indexOf(u8, bare_diff, "storage") == null);
    try testing.expect(std.mem.indexOf(u8, bare_diff, "\"nonce\":2") != null);
}

test "prestate: codeHash follows Nethermind's tracer" {
    const code = [_]u8{0x00};
    const code_hash: Hash = @splat(0xbc);
    var accounts = [_]AccountEntry{
        // Code kept: its hash is listed in the default mode and a diff's pre, never in post.
        .{
            .address = @splat(5),
            .pre = .{ .balance = 1, .code_hash = code_hash, .code = &code },
            .post = .{ .balance = 2, .code_hash = code_hash, .code = &code },
        },
        // Code installed: a diff's post lists the new hash, even under `disableCode`.
        .{
            .address = @splat(6),
            .pre = .{ .balance = 3 },
            .post = .{ .balance = 3, .code_hash = code_hash, .code = &code },
        },
    };
    const collected: Collected = .{
        .accounts = &accounts,
        .account_count = accounts.len,
        .slots = &.{},
        .bytes = &.{},
        .snapshot_space = &.{},
    };
    const hash_text = "\"codeHash\":\"0x" ++ "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc" ++
        "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc\"";
    var out: [2048]u8 = undefined;
    const plain = try write_text(&collected, .{}, &out);
    try testing.expectEqualStrings("{" ++ address_5 ++ ":{\"balance\":\"0x1\",\"code\":\"0x00\"," ++
        hash_text ++ "}," ++ address_6 ++ ":{\"balance\":\"0x3\"}}", plain);
    const diff = try write_text(&collected, .{ .diff = true, .code = false }, &out);
    try testing.expectEqualStrings("{\"pre\":{" ++ address_5 ++ ":{\"balance\":\"0x1\"," ++
        hash_text ++ "}," ++ address_6 ++ ":{\"balance\":\"0x3\"}},\"post\":{" ++ address_5 ++
        ":{\"balance\":\"0x2\"}," ++ address_6 ++ ":{" ++ hash_text ++ "}}}", diff);
}

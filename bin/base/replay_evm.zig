//! `base replay bench <archive> [<warm runs>] --evm-only [--prestate-out <file>]`: the
//! archive's blocks executed against a flat in-memory state, to time the EVM apart from
//! witness reads and trie work (docs/BENCHMARKS.md, phase B3).
//!
//! Setup (untimed): one normal replay records the first value of every account, slot, code
//! and block hash the blocks read, which is the pre-state of the window, into an
//! `evm.MemoryDatabase`; every sender is recovered up front. Each run then executes the
//! blocks through the node's executor over that database, single-threaded, with the senders
//! given: no sender recovery, no witness, no tries. A block's changes are written back into
//! the flat state; the state root is not computed. A block counts when its gas used, logs
//! bloom and receipts root match the canonical header. Lines are `BENCH` lines as in
//! `replay_bench.zig`, `root_ns` and `recover_ns` zero; the EVM time is `exec_ns - pre_ns`.
//!
//! `--prestate-out` writes the recorded pre-state for the base/base harness (`NFPS`, all
//! integers little-endian, values big-endian):
//!
//!     "NFPS" u32:1
//!     u32 n, n x (address[20] nonce:u64 balance[32] code_hash[32] has_storage:u8)
//!     u32 n, n x (address[20] slot[32] value[32])
//!     u32 n, n x (u32 length, code)
//!     u32 n, n x (number:u64 hash[32])

const std = @import("std");
const Io = std.Io;
const base = @import("base");
const cli = @import("replay.zig");

const replay = base.infra.replay;
const evm = base.execution.evm;
const node = base.execution.node;
const consensus = base.common.consensus;
const primitives = base.common.primitives;
const Archive = replay.Archive;
const Executor = node.executor.Executor;
const Clock = Executor.Clock;
const AccountInfo = evm.state.AccountInfo;
const StorageKey = evm.state.StorageKey;
const Address = evm.Address;
const B256 = evm.B256;
const assert = std.debug.assert;

/// The window's pre-state: the first value of every key the replay read.
const Recorder = struct {
    inner: evm.state.Database,
    arena: std.mem.Allocator,
    accounts: std.AutoHashMapUnmanaged(Address, ?AccountInfo) = .empty,
    slots: std.AutoHashMapUnmanaged(StorageKey, u256) = .empty,
    codes: std.AutoHashMapUnmanaged(B256, []const u8) = .empty,
    hashes: std.AutoHashMapUnmanaged(u64, B256) = .empty,
    /// An allocation failed while recording: the recording is incomplete.
    failed: bool = false,

    const vtable: evm.state.Database.VTable = .{
        .basic = basic,
        .code_by_hash = code_by_hash,
        .storage = storage,
        .block_hash = block_hash,
    };

    fn interface(recorder: *Recorder) evm.state.Database {
        return .{ .context = recorder, .vtable = &vtable };
    }

    fn cast(context: *anyopaque) *Recorder {
        return @ptrCast(@alignCast(context));
    }

    fn basic(context: *anyopaque, address: Address) evm.state.Error!?AccountInfo {
        const recorder = cast(context);
        const info = try recorder.inner.basic(address);
        const entry = recorder.accounts.getOrPut(recorder.arena, address) catch
            return recorder.fail(info);
        if (!entry.found_existing) {
            entry.value_ptr.* = info;
            if (info) |account| {
                entry.value_ptr.*.?.code = null;
                if (account.code) |code| recorder.add_code(account.code_hash, code);
            }
        }
        return info;
    }

    fn code_by_hash(context: *anyopaque, code_hash: B256) evm.state.Error![]const u8 {
        const recorder = cast(context);
        const code = try recorder.inner.code_by_hash(code_hash);
        recorder.add_code(code_hash, code);
        return code;
    }

    fn storage(context: *anyopaque, address: Address, slot: u256) evm.state.Error!u256 {
        const recorder = cast(context);
        const value = try recorder.inner.storage(address, slot);
        const key: StorageKey = .{ .address = address, .slot = slot };
        const entry = recorder.slots.getOrPut(recorder.arena, key) catch
            return recorder.fail(value);
        if (!entry.found_existing) entry.value_ptr.* = value;
        return value;
    }

    fn block_hash(context: *anyopaque, number: u64) evm.state.Error!B256 {
        const recorder = cast(context);
        const hash = try recorder.inner.block_hash(number);
        recorder.hashes.put(recorder.arena, number, hash) catch return recorder.fail(hash);
        return hash;
    }

    fn add_code(recorder: *Recorder, code_hash: B256, code: []const u8) void {
        if (code.len == 0 or recorder.codes.contains(code_hash)) return;
        const copy = recorder.arena.dupe(u8, code) catch return recorder.fail({});
        recorder.codes.put(recorder.arena, code_hash, copy) catch return recorder.fail({});
    }

    fn fail(recorder: *Recorder, value: anytype) @TypeOf(value) {
        recorder.failed = true;
        return value;
    }
};

/// Records the pre-state with one normal replay; every block must reproduce its header.
fn record(gpa: std.mem.Allocator, archive: *const Archive, recorder: *Recorder) !void {
    const spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet;
    const replayer = try gpa.create(replay.Replayer);
    defer gpa.destroy(replayer);
    try replayer.init(gpa, spec, archive, cli.replayer_config(archive, 0));
    defer replayer.deinit(gpa);
    recorder.inner = replayer.executor.state.database;
    replayer.executor.state.database = recorder.interface();
    while (!replayer.done()) {
        const outcome = try replayer.replay_next();
        if (!outcome.ok()) return error.Mismatch;
    }
    if (recorder.failed) return error.OutOfMemory;
    assert(recorder.accounts.count() > 0);
}

/// A fresh flat state holding the recorded pre-state.
fn flat_state(gpa: std.mem.Allocator, recorder: *const Recorder) !evm.MemoryDatabase {
    var database = evm.MemoryDatabase.init(gpa);
    errdefer database.deinit();
    var accounts = recorder.accounts.iterator();
    while (accounts.next()) |entry| {
        const info = entry.value_ptr.* orelse continue;
        try database.accounts.put(gpa, entry.key_ptr.*, info);
    }
    var slots = recorder.slots.iterator();
    while (slots.next()) |entry| {
        if (entry.value_ptr.* == 0) continue;
        try database.storage.put(gpa, entry.key_ptr.*, entry.value_ptr.*);
    }
    var codes = recorder.codes.iterator();
    while (codes.next()) |entry| {
        try database.codes.put(gpa, entry.key_ptr.*, try gpa.dupe(u8, entry.value_ptr.*));
    }
    var hashes = recorder.hashes.iterator();
    while (hashes.next()) |entry| try database.put_block_hash(entry.key_ptr.*, entry.value_ptr.*);
    assert(database.accounts.count() <= recorder.accounts.count());
    return database;
}

/// The executor `Backend` over a flat state: commits write values back, no root.
const Flat = struct {
    database: *evm.MemoryDatabase,
    /// An allocation failed in a commit.
    failed: bool = false,

    fn backend(flat: *Flat) node.executor.Backend {
        return .{
            .context = flat,
            .database = flat.database.interface(),
            .commit = commit,
            .root = root,
        };
    }

    fn commit(context: *anyopaque, state: *evm.State) node.executor.BackendError!void {
        const flat: *Flat = @ptrCast(@alignCast(context));
        flat.fold(state) catch {
            flat.failed = true;
            return error.StateUnavailable;
        };
        // The next block reads the new values from the flat state, as the replayer does.
        state.accounts.clearRetainingCapacity();
        state.slots.clearRetainingCapacity();
        state.code_store_len = 0;
    }

    fn fold(flat: *Flat, state: *const evm.State) !void {
        const database = flat.database;
        const gpa = database.allocator;
        var accounts = state.accounts.valueIterator();
        while (accounts.next()) |account| {
            if (!account.dirty) continue;
            if (!account.in_database or account.storage_cleared) {
                wipe_storage(database, account.address);
            }
            if (!account.in_database) {
                _ = database.accounts.remove(account.address);
                continue;
            }
            const code = account.info.code orelse &.{};
            if (code.len > 0 and !database.codes.contains(account.info.code_hash)) {
                try database.codes.put(gpa, account.info.code_hash, try gpa.dupe(u8, code));
            }
            const old = database.accounts.get(account.address);
            const kept = old != null and old.?.has_storage and !account.storage_cleared;
            try database.accounts.put(gpa, account.address, .{
                .balance = account.info.balance,
                .nonce = account.info.nonce,
                .code_hash = account.info.code_hash,
                .has_storage = kept,
            });
        }
        try fold_slots(database, state);
    }

    fn fold_slots(database: *evm.MemoryDatabase, state: *const evm.State) !void {
        var slots = state.slots.iterator();
        while (slots.next()) |entry| {
            if (!entry.value_ptr.dirty) continue;
            const key = entry.key_ptr.*;
            const account = state.accounts.getPtr(key.address) orelse continue;
            if (!account.in_database) continue;
            if (entry.value_ptr.epoch != account.storage_epoch) continue;
            const value = entry.value_ptr.present;
            if (value == 0) {
                _ = database.storage.remove(key);
                continue;
            }
            try database.storage.put(database.allocator, key, value);
            database.accounts.getPtr(key.address).?.has_storage = true;
        }
    }

    /// Drops every slot of `address` (a destroyed or wiped account; rare).
    fn wipe_storage(database: *evm.MemoryDatabase, address: Address) void {
        var slots = database.storage.iterator();
        while (slots.next()) |entry| {
            if (!std.mem.eql(u8, &entry.key_ptr.address, &address)) continue;
            database.storage.removeByPtr(entry.key_ptr);
            slots = database.storage.iterator(); // Removal invalidates the iterator.
        }
    }

    fn root(context: *anyopaque) node.executor.BackendError![32]u8 {
        _ = context;
        return @splat(0);
    }
};

/// Every block's senders, recovered once (deposits: zero, the executor ignores them).
fn recover_senders(
    gpa: std.mem.Allocator,
    archive: *const Archive,
) ![]const []const primitives.Address {
    const recoverer: consensus.Recoverer = consensus.recover_address;
    const blocks = try gpa.alloc([]const primitives.Address, archive.block_count);
    for (blocks, 0..) |*block, index| {
        const count = archive.transaction_count(@intCast(index));
        const raws = try gpa.alloc([]const u8, count);
        defer gpa.free(raws);
        for (raws, 0..) |*raw, position| {
            raw.* = archive.transaction(@intCast(index), @intCast(position));
        }
        const recovered = try gpa.alloc(?primitives.Address, count);
        defer gpa.free(recovered);
        node.senders.recover(raws, recovered, recoverer, null);
        const senders = try gpa.alloc(primitives.Address, count);
        for (raws, recovered, senders) |raw, sender, *out| {
            const envelope = consensus.Envelope.decode(raw) catch return error.InvalidArchive;
            if (sender) |address| {
                out.* = address;
            } else if (envelope == .deposit) {
                out.* = std.mem.zeroes(primitives.Address);
            } else {
                return error.InvalidTransaction;
            }
        }
        block.* = senders;
    }
    return blocks;
}

pub const Options = struct { warm_runs: u32, prestate_out: ?[]const u8 };

pub fn main(
    init: std.process.Init,
    archive: *const Archive,
    options: Options,
    clock: Clock,
    out: *Io.Writer,
) !u8 {
    const gpa = init.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var recorder: Recorder = .{ .inner = undefined, .arena = arena };
    try record(gpa, archive, &recorder);
    if (options.prestate_out) |path| try write_prestate(init, &recorder, path);
    const senders = try recover_senders(arena, archive);
    var run: u32 = 0;
    while (run <= options.warm_runs) : (run += 1) {
        var database = try flat_state(gpa, &recorder);
        defer database.deinit();
        const passed = try evm_run(gpa, archive, &database, senders, clock, run, out);
        try out.flush();
        if (!passed) return 1;
    }
    assert(run == options.warm_runs + 1);
    return 0;
}

/// One pass over the archive's blocks on `database`; false at the first block whose gas
/// used, logs bloom or receipts root differs from its canonical header.
fn evm_run(
    gpa: std.mem.Allocator,
    archive: *const Archive,
    database: *evm.MemoryDatabase,
    senders: []const []const primitives.Address,
    clock: Clock,
    run: u32,
    out: *Io.Writer,
) !bool {
    assert(senders.len == archive.block_count);
    const spec = &base.execution.chainspec.ChainSpec.presets.base_mainnet;
    var flat: Flat = .{ .database = database };
    const config = cli.replayer_config(archive, 0).executor;
    var executor = try Executor.init_backend(gpa, spec, flat.backend(), config);
    defer executor.deinit(gpa);
    executor.phase_clock = clock;
    const transactions = try gpa.alloc([]const u8, executor.transactions_max);
    defer gpa.free(transactions);
    for (0..archive.block_count) |index| {
        const block: u32 = @intCast(index);
        const header = consensus.Header.decode(archive.block_header(block)) catch
            return error.InvalidArchive;
        const count = archive.transaction_count(block);
        for (transactions[0..count], 0..) |*raw, position| {
            raw.* = archive.transaction(block, @intCast(position));
        }
        const env = node.chain.env_of(&header);
        const withdrawals: ?[]const base.execution.payload.Withdrawal =
            if (header.withdrawals_root != null) &.{} else null;
        executor.given_senders = senders[block];
        const start_ns = clock.read();
        const executed = try executor.execute_block(&env, transactions[0..count], withdrawals);
        const total_ns = clock.read() -| start_ns;
        executor.given_senders = null;
        const ok = executed.gas_used == header.gas_used and
            executed.logs_bloom.eql(header.logs_bloom) and
            std.mem.eql(u8, &executed.receipts_root, &header.receipts_root.bytes);
        try print_line(out, run, &header, count, &executor, total_ns, ok);
        if (!ok) return false;
    }
    if (flat.failed) return error.OutOfMemory;
    return true;
}

fn print_line(
    out: *Io.Writer,
    run: u32,
    header: *const consensus.Header,
    transactions: u32,
    executor: *const Executor,
    total_ns: u64,
    ok: bool,
) !void {
    const phases = &executor.last_phases;
    assert(phases.recovery_ns == 0); // Senders are given.
    try out.print("BENCH run={d} block={d} txs={d} gas={d} exec_ns={d} total_ns={d} " ++
        "pre_ns={d} recover_ns={d} post_ns={d} receipts_ns={d} commit_ns={d} " ++
        "root_ns={d} ok={d}\n", .{
        run,
        header.number,
        transactions,
        header.gas_used,
        executor.last_execution_ns,
        total_ns,
        phases.pre_block_ns,
        phases.recovery_ns,
        phases.post_block_ns,
        phases.receipts_root_ns,
        phases.commit_ns,
        phases.state_root_ns,
        @intFromBool(ok),
    });
}

fn write_prestate(init: std.process.Init, recorder: *const Recorder, path: []const u8) !void {
    var output: Io.Writer.Allocating = .init(init.gpa);
    defer output.deinit();
    const writer = &output.writer;
    try writer.writeAll("NFPS");
    try writer.writeInt(u32, 1, .little);
    var present: u32 = 0;
    var accounts = recorder.accounts.valueIterator();
    while (accounts.next()) |info| present += @intFromBool(info.* != null);
    try writer.writeInt(u32, present, .little);
    var entries = recorder.accounts.iterator();
    while (entries.next()) |entry| {
        const info = entry.value_ptr.* orelse continue;
        try writer.writeAll(&entry.key_ptr.*);
        try writer.writeInt(u64, info.nonce, .little);
        try writer.writeInt(u256, info.balance, .big);
        try writer.writeAll(&info.code_hash);
        try writer.writeByte(@intFromBool(info.has_storage));
    }
    try writer.writeInt(u32, recorder.slots.count(), .little);
    var slots = recorder.slots.iterator();
    while (slots.next()) |entry| {
        try writer.writeAll(&entry.key_ptr.address);
        try writer.writeInt(u256, entry.key_ptr.slot, .big);
        try writer.writeInt(u256, entry.value_ptr.*, .big);
    }
    try writer.writeInt(u32, recorder.codes.count(), .little);
    var codes = recorder.codes.valueIterator();
    while (codes.next()) |code| {
        try writer.writeInt(u32, @intCast(code.len), .little);
        try writer.writeAll(code.*);
    }
    try writer.writeInt(u32, recorder.hashes.count(), .little);
    var hashes = recorder.hashes.iterator();
    while (hashes.next()) |entry| {
        try writer.writeInt(u64, entry.key_ptr.*, .little);
        try writer.writeAll(&entry.value_ptr.*);
    }
    try Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = output.written() });
}

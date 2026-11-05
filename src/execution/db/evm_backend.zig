//! EVM backend: `db.State` as the evm `Database`, and the fold of a block's journaled evm
//! `State` into an `Overlay`.
//!
//! The evm keeps its own block-lifetime cache with transaction journaling. At the end of a
//! block `commit_evm` copies its dirty accounts, wipes, slots, and new code into an
//! `Overlay`; `Overlay.commit` then yields the state root and the block's `Changeset` (for
//! the journal and for reorgs). The fold follows the same rules as the evm's own commit
//! contract: an account no longer `in_database` is deleted, `storage_cleared` drops old
//! storage, and slots cached under an older storage epoch are stale.

const std = @import("std");
const assert = std.debug.assert;

const evm = @import("../evm/root.zig");
const trie = @import("../trie/root.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const State = state_module.State;
const Overlay = overlay_module.Overlay;

const vtable: evm.state.Database.VTable = .{
    .basic = basic,
    .code_by_hash = code_by_hash,
    .storage = storage,
    .block_hash = block_hash,
};

/// The evm `Database` over committed state. `state` must outlive the evm `State`.
pub fn database(state: *State) evm.state.Database {
    return .{ .context = state, .vtable = &vtable };
}

fn from(context: *anyopaque) *State {
    return @ptrCast(@alignCast(context));
}

fn basic(context: *anyopaque, address: evm.Address) evm.state.Error!?evm.state.AccountInfo {
    const state = from(context);
    const info = state.basic(address) orelse return null;
    const address_hash = trie.node.keccak256(&address);
    return .{
        .balance = info.balance,
        .nonce = info.nonce,
        .code_hash = info.code_hash,
        .has_storage = state.state_trie.has_storage(address_hash),
    };
}

fn code_by_hash(context: *anyopaque, code_hash: evm.B256) evm.state.Error![]const u8 {
    return from(context).code_by_hash(code_hash) orelse error.DatabaseFailure;
}

fn storage(context: *anyopaque, address: evm.Address, slot: u256) evm.state.Error!u256 {
    return from(context).storage(address, slot);
}

/// Unknown block hashes read as zero, as BLOCKHASH returns for out-of-window numbers.
fn block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
    return from(context).block_hash(number) orelse @splat(0);
}

/// Copies the evm block state's changes into `overlay`. Clears nothing: the caller resets
/// the evm state after `Overlay.commit`.
pub fn commit_evm(evm_state: *const evm.State, overlay: *Overlay) overlay_module.Error!void {
    var accounts = evm_state.accounts.valueIterator();
    while (accounts.next()) |account| {
        if (!account.dirty) continue;
        if (!account.in_database) {
            try overlay.set_account(account.address, null);
            continue;
        }
        if (account.info.has_code()) {
            if (overlay.code_by_hash(account.info.code_hash) == null) {
                const stored = try overlay.insert_code(account.info.code.?);
                assert(std.mem.eql(u8, &stored, &account.info.code_hash));
            }
        }
        try overlay.set_account(account.address, .{
            .nonce = account.info.nonce,
            .balance = account.info.balance,
            .code_hash = account.info.code_hash,
        });
        if (account.storage_cleared) try overlay.wipe_storage(account.address);
    }
    var slots = evm_state.slots.iterator();
    while (slots.next()) |entry| {
        if (!entry.value_ptr.dirty) continue;
        const account = evm_state.accounts.getPtr(entry.key_ptr.address) orelse continue;
        if (!account.in_database) continue;
        if (entry.value_ptr.epoch != account.storage_epoch) continue;
        const key = entry.key_ptr;
        try overlay.set_storage(key.address, key.slot, entry.value_ptr.present);
    }
}

const testing = std.testing;
const Changeset = @import("changeset.zig").Changeset;

test "evm backend: evm writes commit through the overlay and unwind cleanly" {
    var state = try State.init(testing.allocator, .{
        .accounts_max = 64,
        .storage_slots_max = 256,
        .codes_max = 8,
        .code_bytes_max = 1024,
        .account_nodes_max = 512,
        .storage_nodes_max = 2048,
    });
    defer state.deinit(testing.allocator);
    var overlay = try Overlay.init(testing.allocator, &state, .{
        .accounts_max = 64,
        .slots_max = 256,
        .codes_max = 8,
    });
    defer overlay.deinit(testing.allocator);
    var changeset = try Changeset.init(testing.allocator, .{
        .accounts_max = 64,
        .storage_max = 256,
        .codes_max = 8,
        .code_bytes_max = 1024,
    });
    defer changeset.deinit(testing.allocator);
    var evm_state = try evm.State.init(testing.allocator, database(&state), .{
        .accounts_max = 64,
        .slots_max = 256,
        .transient_slots_max = 16,
        .journal_entries_max = 1024,
        .logs_max = 16,
        .log_data_bytes_max = 1024,
        .code_bytes_max = 1024,
    });
    defer evm_state.deinit(testing.allocator);

    const alice: evm.Address = @splat(0xa1);
    const contract: evm.Address = @splat(0xc0);
    const empty_root = try state.state_root();
    evm_state.begin_transaction();
    const account = try evm_state.load(alice);
    try evm_state.touch(account);
    try evm_state.set_balance(account, 1_000_000);
    try evm_state.set_nonce(account, 1);
    const target = try evm_state.load(contract);
    try evm_state.touch(target);
    try evm_state.create_account(target, .cancun);
    try evm_state.set_code(target, &.{ 0x60, 0x00, 0x60, 0x00, 0xf3 });
    const slot = (try evm_state.storage_access(target, 7)).slot;
    try evm_state.storage_write(target, slot, 42);
    evm_state.finalize_transaction(.cancun);

    try commit_evm(&evm_state, &overlay);
    const root = try overlay.commit(&changeset);
    try testing.expect(!std.mem.eql(u8, &root, &empty_root));
    try testing.expectEqual(@as(u256, 1_000_000), state.basic(alice).?.balance);
    try testing.expectEqual(@as(u256, 42), state.storage(contract, 7));
    const code_hash = state.basic(contract).?.code_hash;
    try testing.expectEqual(@as(usize, 5), state.code_by_hash(code_hash).?.len);

    // A fresh evm state reads the committed values back through the database.
    evm_state.reset(database(&state));
    evm_state.begin_transaction();
    const reloaded = try evm_state.load(contract);
    const reloaded_slot = (try evm_state.storage_access(reloaded, 7)).slot;
    try testing.expectEqual(@as(u256, 42), reloaded_slot.present);

    // EIP-7610: an account with storage reports it; one without does not.
    const backend = database(&state);
    try testing.expect((try backend.vtable.basic(backend.context, contract)).?.has_storage);
    try testing.expect(!(try backend.vtable.basic(backend.context, alice)).?.has_storage);

    try state.unwind(&changeset);
    try testing.expectEqual(empty_root, try state.state_root());
}

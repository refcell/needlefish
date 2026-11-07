//! `run` (blocks N+1.. on an imported disk-mode database), end to end on `SimStorage`.
//!
//! Differential: a small L2 state (three funded dev-mnemonic accounts, a contract with
//! storage, and the L2ToL1MessagePasser holding the same contract code, so the Isthmus
//! withdrawals root moves) is the oracle's genesis: an in-memory `StateDb` executes K blocks
//! of real signed transactions with the node's executor (transfers creating accounts, storage
//! writes and deletes, BLOCKHASH reads, a contract creation and a call into it) and seals
//! their headers from the results. The same state goes into a disk-mode database through the
//! importer's bulk path (`to_disk.ImporterType.run`, reth table encodings) as head N. The
//! runner then executes the K blocks: every check must pass, every state root must be the
//! oracle's, and after the last block every account, slot and storage root reads the same.
//! In the middle the storage crashes with blocks not yet durable: the database reopens at a
//! committed block at or after the durable one, and the runner continues from there.
//!
//! Negative cases (on the imported head and on a committed one): a header whose state root
//! (or withdrawals root) is tampered and rehashed fails that check with the computed root
//! reported; a block with an invalid transaction fails execution; a wrong parent, a wrong
//! number, and a header that does not hash to the block hash are refused. Each leaves the
//! head, the state root and the state's reads unchanged, and the correct block passes after.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const run = @import("run.zig");
const to_disk = @import("to_disk.zig");
const to_disk_test = @import("to_disk_test.zig");
const hashed_state = @import("hashed_state.zig");
const SimStorage = @import("../db/storage/sim_storage.zig").SimStorage;
const sector_size = @import("../db/storage/storage.zig").sector_size;
const state_module = @import("../db/state.zig");
const state_db_module = @import("../node/state_db.zig");
const executor_module = @import("../node/executor.zig");
const node_chain = @import("../node/chain.zig");
const chainspec = @import("../chainspec/root.zig");
const evm = @import("../evm/root.zig");
const trie = @import("../trie/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const dev_accounts = @import("../../batcher/devnet/accounts.zig");

const Hash = [32]u8;
const Address = [20]u8;
const Header = consensus.Header;
const State = state_module.State;
const StateDb = state_db_module.StateDb;
const Executor = executor_module.Executor;
const Runner = run.RunnerType(SimStorage);
const keccak256 = trie.node.keccak256;

/// Every upgrade through Azul (Isthmus withdrawals root, Jovian DA footprint) at genesis.
const spec = &chainspec.ChainSpec.presets.base_devnet;
const head_number = to_disk_test.head_number;
const blocks_count = 12;
const senders = 3;
const gwei: u256 = 1_000_000_000;

/// CALLDATALOAD(0) into slot CALLDATALOAD(32), then BLOCKHASH(NUMBER - 1) into slot NUMBER.
const runtime = [_]u8{
    0x60, 0x00, 0x35, 0x60, 0x20, 0x35, 0x55, // SSTORE(word 1, word 0)
    0x60, 0x01, 0x43, 0x03, 0x40, 0x43, 0x55, // SSTORE(NUMBER, BLOCKHASH(NUMBER - 1))
    0x00,
};
/// CODECOPY the runtime after these 12 bytes to memory 0, RETURN it.
const init_code = [_]u8{
    0x60, runtime.len, 0x60, 12, 0x60, 0x00, 0x39, 0x60, runtime.len, 0x60, 0x00, 0xf3,
} ++ runtime;
/// `to_disk_test.shape_test` with a small journal and the smallest replay reserve: blocks
/// meet the runner's room checks, so checkpoints run between them (journal and admission).
const shape_run: to_disk.Shape = blk: {
    var shape = to_disk_test.shape_test;
    shape.journal_size_bytes = 16 * sector_size;
    shape.entry_body_size_max = 4 * sector_size;
    shape.chain.reorg_depth_max = 1;
    shape.disk_state.replay_record_writes_max = shape.disk_state.record_writes_max * 3;
    break :blk shape;
};

const contract: Address = @as([18]u8, @splat(0)) ++ [2]u8{ 0xc0, 0xde };
const beneficiary: Address = @splat(0xbe);

comptime {
    assert(init_code.len == 12 + runtime.len);
}

fn recipient(index: u64) Address {
    var address: Address = @splat(0xaa);
    address[19] = @intCast(index);
    return address;
}

fn word_hash(value: u256) Hash {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    return keccak256(&bytes);
}

const executor_config: executor_module.Config = .{
    .scratch_bytes = 1 << 20,
    .transactions_max = 16,
    .evm = .{ .memory_bytes_max = 1 << 20, .code_arena_bytes = 1 << 20 },
    .limits = .{
        .accounts_max = 256,
        .slots_max = 1024,
        .transient_slots_max = 64,
        .journal_entries_max = 4096,
        .logs_max = 64,
        .log_data_bytes_max = 4096,
        .code_bytes_max = 1 << 16,
    },
};

const GenesisAccount = struct {
    address: Address,
    balance: u256,
    code: []const u8,
    /// (slot, value) pairs, values non-zero.
    slots: []const [2]u256,
};

const Keys = [senders]dev_accounts.Account;

fn genesis_of(keys: *const Keys) [senders + 2]GenesisAccount {
    var genesis: [senders + 2]GenesisAccount = undefined;
    for (keys, genesis[0..senders]) |key, *entry| {
        entry.* = .{
            .address = key.address.bytes,
            .balance = 1000 * gwei * gwei,
            .code = &.{},
            .slots = &.{},
        };
    }
    genesis[senders] = .{
        .address = contract,
        .balance = 0,
        .code = &runtime,
        .slots = &.{ .{ 1, 7 }, .{ 2, 9 } },
    };
    genesis[senders + 1] = .{
        .address = run.l2_to_l1_message_passer,
        .balance = 0,
        .code = &runtime,
        .slots = &.{.{ 0, 1 }},
    };
    return genesis;
}

/// The genesis as the importer reads it (reth table encodings), with its root.
fn source_of(arena: std.mem.Allocator, genesis: []const GenesisAccount) !to_disk_test.Source {
    var source: to_disk_test.Source = undefined;
    const accounts = try arena.alloc(to_disk_test.Account, genesis.len);
    for (genesis, accounts) |*entry, *account| {
        const slots = try arena.alloc(to_disk_test.Slot, entry.slots.len);
        for (entry.slots, slots) |pair, *slot| {
            assert(pair[1] != 0);
            slot.* = .{ .hash = word_hash(pair[0]), .word = pair[1] };
        }
        std.mem.sort(to_disk_test.Slot, slots, {}, to_disk_test.less_slot);
        account.* = .{
            .key = keccak256(&entry.address),
            .nonce = 0,
            .balance = entry.balance,
            .code_hash = if (entry.code.len == 0)
                trie.node.empty_code_hash
            else
                keccak256(entry.code),
            .slots = slots,
        };
    }
    std.mem.sort(to_disk_test.Account, accounts, {}, to_disk_test.less_account);
    const codes = try arena.alloc([]const u8, 1);
    codes[0] = &runtime;
    const entries = try arena.alloc(hashed_state.Entry, 1);
    entries[0] = .{
        .key = try arena.dupe(u8, &keccak256(&runtime)),
        .value = try to_disk_test.encode_code(arena, &runtime, false),
    };
    source.codes = codes;
    source.code_entries = entries;
    try to_disk_test.encode_tables(arena, accounts, &source);
    return source;
}

// The oracle: an in-memory StateDb with the node's executor; it seals the headers.

const Oracle = struct {
    state_db: StateDb,
    executor: Executor,
    keys: *const Keys,
    nonces: [senders]u64 = @splat(0),
    created: Address = undefined,

    fn create(genesis: []const GenesisAccount, keys: *const Keys) !*Oracle {
        const self = try testing.allocator.create(Oracle);
        errdefer testing.allocator.destroy(self);
        self.* = .{ .state_db = undefined, .executor = undefined, .keys = keys };
        self.state_db = try StateDb.init(testing.allocator, .{
            .trie = .{ .accounts_max = 256, .account_nodes_max = 4096, .storage_nodes_max = 8192 },
            .storage_slots_max = 4096,
            .code_bytes_max = 1 << 16,
            .codes_max = 64,
            .block_accounts_max = 256,
            .block_slots_max = 1024,
            .block_codes_max = 64,
            .block_code_bytes_max = 1 << 16,
            .undo_bytes_max = 1 << 20,
        });
        errdefer self.state_db.deinit(testing.allocator);
        for (genesis) |*entry| {
            try self.state_db.put_account(entry.address, entry.balance, 0, entry.code);
            for (entry.slots) |pair| try self.state_db.put_storage(entry.address, pair[0], pair[1]);
        }
        const db = &self.state_db;
        self.executor = try Executor.init(testing.allocator, spec, db, executor_config);
        return self;
    }

    fn destroy(self: *Oracle) void {
        self.executor.deinit(testing.allocator);
        self.state_db.deinit(testing.allocator);
        testing.allocator.destroy(self);
    }

    fn sign(
        self: *Oracle,
        arena: std.mem.Allocator,
        sender: u32,
        to: ?Address,
        value: u256,
        input: []const u8,
        gas_limit: u64,
    ) ![]const u8 {
        const tx: consensus.Eip1559 = .{
            .chain_id = spec.chain_id,
            .nonce = self.nonces[sender],
            .max_priority_fee_per_gas = 2,
            .max_fee_per_gas = 10 * gwei,
            .gas_limit = gas_limit,
            .to = if (to) |address| .{ .call = .{ .bytes = address } } else .create,
            .value = value,
            .input = input,
            .access_list = .empty,
        };
        if (to == null) {
            const created = primitives.create_address(self.keys[sender].address, tx.nonce);
            self.created = created.bytes;
        }
        self.nonces[sender] += 1;
        const envelope = try consensus.tx.sign(tx, self.keys[sender].private_key);
        const buffer = try arena.alloc(u8, 1024);
        return envelope.encode_to(buffer);
    }

    /// (value, key) calldata for the runtime.
    fn calldata(arena: std.mem.Allocator, value: u256, key: u256) ![]const u8 {
        const bytes = try arena.alloc(u8, 64);
        std.mem.writeInt(u256, bytes[0..32], value, .big);
        std.mem.writeInt(u256, bytes[32..64], key, .big);
        return bytes;
    }

    /// Block `index`'s transactions: a transfer creating an account, a storage write (every
    /// fourth one a delete) into the contract, one into the message passer, the contract's
    /// creation (block 2) and a call into the created contract (from block 5).
    fn workload(self: *Oracle, arena: std.mem.Allocator, index: u32) ![]const []const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        const to = recipient(index);
        const transfer = try self.sign(arena, index % 3, to, 1000 + index, &.{}, 21_000);
        try list.append(arena, transfer);
        const value: u256 = if (index % 4 == 3) 0 else index + 1;
        const write = try calldata(arena, value, index % 3 + 1);
        try list.append(arena, try self.sign(arena, (index + 1) % 3, contract, 0, write, 100_000));
        const passer = run.l2_to_l1_message_passer;
        const message = try calldata(arena, index + 5, index % 2);
        try list.append(arena, try self.sign(arena, (index + 2) % 3, passer, 0, message, 100_000));
        if (index == 2) {
            try list.append(arena, try self.sign(arena, 0, null, 0, &init_code, 300_000));
        }
        if (index >= 5) {
            const input = try calldata(arena, index, 1);
            try list.append(arena, try self.sign(arena, 1, self.created, 0, input, 100_000));
        }
        assert(list.items.len <= executor_config.transactions_max);
        return list.items;
    }

    /// Executes block `index` (number N + 1 + index) on `parent` and seals its header.
    fn produce(self: *Oracle, arena: std.mem.Allocator, index: u32, parent: Hash) !run.Block {
        const number = head_number + 1 + index;
        const transactions = try self.workload(arena, index);
        var header: Header = .{
            .parent_hash = .{ .bytes = parent },
            .beneficiary = .{ .bytes = beneficiary },
            .number = number,
            .gas_limit = 30_000_000,
            .timestamp = number * 2,
            .mix_hash = .{ .bytes = word_hash(number) },
            .base_fee_per_gas = 1_000_000_000,
            .withdrawals_root = primitives.empty_root_hash,
            .blob_gas_used = 0,
            .excess_blob_gas = 0,
            .parent_beacon_block_root = .zero,
            .requests_hash = consensus.block.empty_requests_hash,
        };
        const env = node_chain.env_of(&header);
        const executed = try self.executor.execute_block(&env, transactions, &.{});
        for (executed.receipts) |receipt| try testing.expect(receipt.status);
        header.transactions_root = .{ .bytes = trie.ordered_trie_root(transactions) };
        header.receipts_root = .{ .bytes = executed.receipts_root };
        header.state_root = .{ .bytes = executed.state_root };
        header.gas_used = executed.gas_used;
        header.logs_bloom = executed.logs_bloom;
        header.blob_gas_used = executed.blob_gas_used;
        const passer_root = self.state_db.state.storage_root(run.l2_to_l1_message_passer);
        header.withdrawals_root = .{ .bytes = passer_root };
        const header_rlp = try arena.alloc(u8, rlp.length(header));
        _ = rlp.encode_to(header_rlp, header);
        const hash = keccak256(header_rlp);
        self.state_db.set_block_hash(number, hash);
        return .{
            .number = number,
            .hash = hash,
            .header_rlp = header_rlp,
            .transactions = transactions,
        };
    }
};

// The harness: the oracle's blocks, and a disk-mode database imported from the same genesis.

const Harness = struct {
    arena: std.mem.Allocator,
    oracle: *Oracle,
    blocks: [blocks_count]run.Block,
    disk: to_disk_test.Run,
    runner: *Runner,
    /// Every account the blocks touch.
    addresses: [senders + 6 + blocks_count]Address,
    /// The runner's phase clock (`clock_read`).
    clock_ns: u64 = 0,

    fn create(arena: std.mem.Allocator, keys: *const Keys, seed: u64) !*Harness {
        const self = try arena.create(Harness);
        const genesis = genesis_of(keys);
        const source = try arena.create(to_disk_test.Source);
        source.* = try source_of(arena, &genesis);
        self.arena = arena;
        self.clock_ns = 0;
        self.oracle = try Oracle.create(&genesis, keys);
        errdefer self.oracle.destroy();
        try testing.expectEqualSlices(u8, &source.root, &(try self.oracle.state_db.root()));
        // The disk database's head N and its ancestors (synthetic hashes) for BLOCKHASH.
        var chain: to_disk.HeaderChain = .{};
        try to_disk_test.synthetic_chain(source.root, &chain);
        for (chain.links[0..chain.len]) |*link| {
            self.oracle.state_db.set_block_hash(link.number, link.hash);
        }
        var parent = chain.head().hash;
        for (&self.blocks, 0..) |*block, index| {
            block.* = try self.oracle.produce(arena, @intCast(index), parent);
            parent = block.hash;
        }
        self.addresses_fill(keys);
        self.disk = try to_disk_test.Run.init_shaped(source, seed, shape_run);
        errdefer self.disk.deinit();
        var importer = self.disk.importer();
        const root = try to_disk_test.import_into(&importer, source, &chain);
        try testing.expectEqualSlices(u8, &source.root, &root);
        self.runner = try self.runner_create();
        return self;
    }

    fn addresses_fill(self: *Harness, keys: *const Keys) void {
        for (keys, self.addresses[0..senders]) |key, *address| address.* = key.address.bytes;
        const others = [_]Address{
            contract,
            run.l2_to_l1_message_passer,
            self.oracle.created,
            beneficiary,
            evm.op.base_fee_vault,
            evm.op.l1_fee_vault,
        };
        @memcpy(self.addresses[senders..][0..others.len], &others);
        for (self.addresses[senders + others.len ..], 0..) |*address, index| {
            address.* = recipient(index);
        }
    }

    fn runner_create(self: *Harness) !*Runner {
        return Runner.create(testing.allocator, self.disk.db, spec, self.disk.driver(), .{
            .executor = executor_config,
            .clock = .{ .context = &self.clock_ns, .now_ns = clock_read },
        });
    }

    /// A clock that advances 1 us per read: every timed phase reads it at both ends.
    fn clock_read(context: *anyopaque) u64 {
        const clock_ns: *u64 = @ptrCast(@alignCast(context));
        clock_ns.* += std.time.ns_per_us;
        return clock_ns.*;
    }

    fn destroy(self: *Harness) void {
        self.runner.destroy(testing.allocator);
        self.disk.deinit();
        self.oracle.destroy();
    }

    fn state(self: *Harness) *State {
        return &self.disk.db.state;
    }

    /// Executes block `index`; it must pass with the oracle's root.
    fn pass(self: *Harness, index: u32) !run.Outcome {
        const block = &self.blocks[index];
        const outcome = try self.runner.execute(block);
        if (!outcome.ok()) {
            std.debug.print("block {d}: {?t} {?t}\n", .{
                block.number,
                outcome.first_failed(),
                outcome.failure,
            });
        }
        try testing.expect(outcome.ok());
        try testing.expect(outcome.first_failed() == null);
        try testing.expect(outcome.sequence > 0);
        const expected = outcome.expected_state_root;
        try testing.expectEqualSlices(u8, &expected, &outcome.computed_state_root);
        const head = self.disk.db.head_info;
        try testing.expectEqual(block.number, head.number);
        try testing.expectEqualSlices(u8, &block.hash, &head.hash);
        try testing.expectEqualSlices(u8, &outcome.expected_state_root, &head.state_root);
        return outcome;
    }

    /// Every account, slot and storage root the blocks touch reads as the oracle's.
    fn expect_oracle_state(self: *Harness) !void {
        const oracle = self.oracle.state_db.state;
        const disk = self.state();
        try testing.expectEqualSlices(u8, &(try oracle.state_root()), &(try disk.state_root()));
        for (self.addresses) |address| {
            const expected = oracle.basic(address);
            const got = disk.basic(address);
            try testing.expectEqual(expected != null, got != null);
            if (expected) |info| try testing.expect(info.eql(got.?));
            const storage_root = oracle.storage_root(address);
            try testing.expectEqualSlices(u8, &storage_root, &disk.storage_root(address));
            for (0..4) |slot| {
                try testing.expectEqual(oracle.storage(address, slot), disk.storage(address, slot));
            }
            for (self.blocks) |block| {
                const word = oracle.storage(address, block.number);
                try testing.expectEqual(word, disk.storage(address, block.number));
            }
        }
    }
};

/// What a failed or refused block must leave as it was.
const Snapshot = struct {
    head: @import("../db/database.zig").HeadInfo,
    root: Hash,
    accounts: [senders + 2]?state_module.AccountInfo,
    slots: [4]u256,
    passer_root: Hash,
    sequence: u64,

    fn take(harness: *Harness) !Snapshot {
        const disk = harness.state();
        var snapshot: Snapshot = .{
            .head = harness.disk.db.head_info,
            .root = try disk.state_root(),
            .accounts = undefined,
            .slots = undefined,
            .passer_root = disk.storage_root(run.l2_to_l1_message_passer),
            .sequence = harness.disk.db.submitted_sequence,
        };
        for (harness.addresses[0 .. senders + 2], &snapshot.accounts) |address, *info| {
            info.* = disk.basic(address);
        }
        for (&snapshot.slots, 0..) |*word, slot| word.* = disk.storage(contract, slot);
        return snapshot;
    }

    fn expect_same(snapshot: *const Snapshot, harness: *Harness) !void {
        const now = try take(harness);
        try testing.expect(now.head.eql(snapshot.head));
        try testing.expectEqualSlices(u8, &snapshot.head.state_root, &now.root);
        try testing.expectEqualSlices(u8, &snapshot.root, &now.root);
        try testing.expectEqualSlices(u8, &snapshot.passer_root, &now.passer_root);
        try testing.expectEqual(snapshot.sequence, now.sequence);
        try testing.expectEqual(snapshot.slots, now.slots);
        for (snapshot.accounts, now.accounts) |before, after| {
            try testing.expectEqual(before != null, after != null);
            if (before) |info| try testing.expect(info.eql(after.?));
        }
    }
};

fn derive_keys() Keys {
    var keys: Keys = undefined;
    for (&keys, 0..) |*key, index| key.* = dev_accounts.derive_dev(@intCast(index));
    return keys;
}

test "import run: blocks N+1.. on an imported database match the oracle across a crash" {
    const keys = derive_keys();
    var checkpoints: u64 = 0;
    var requested: u64 = 0;
    for (0..3) |seed| {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const harness = try Harness.create(arena_state.allocator(), &keys, seed);
        defer harness.destroy();
        var sequences: [blocks_count]u64 = undefined;
        // Durable through block 4, then blocks 5..7 only queued when the storage crashes.
        for (0..4) |index| sequences[index] = (try harness.pass(@intCast(index))).sequence;
        try harness.runner.flush();
        const crash_after: u32 = 7 + @as(u32, @intCast(seed));
        for (4..crash_after) |index| {
            sequences[index] = (try harness.pass(@intCast(index))).sequence;
        }
        const durable = harness.disk.db.durable_sequence;
        var acknowledged: u64 = head_number;
        for (sequences[0..crash_after], 0..) |sequence, index| {
            if (sequence <= durable) acknowledged = head_number + 1 + index;
        }
        try testing.expect(acknowledged >= head_number + 4);
        checkpoints += harness.disk.db.checkpoints_completed;
        requested += harness.runner.stats.checkpoints_requested;
        harness.runner.destroy(testing.allocator);
        harness.disk.sim.crash();
        try harness.disk.reopen();
        harness.runner = try harness.runner_create();
        // A committed block at or after the durable one, with that block's root.
        const head = harness.disk.db.head_info;
        try testing.expect(head.number >= acknowledged);
        try testing.expect(head.number <= head_number + crash_after);
        const recovered = &harness.blocks[@intCast(head.number - head_number - 1)];
        try testing.expectEqualSlices(u8, &recovered.hash, &head.hash);
        const header = try Header.decode(recovered.header_rlp);
        try testing.expectEqualSlices(u8, &header.state_root.bytes, &head.state_root);
        try testing.expectEqualSlices(u8, &head.state_root, &(try harness.state().state_root()));
        // A block already applied is not the next one.
        try testing.expectError(error.NotNextBlock, harness.runner.execute(recovered));
        for (head.number - head_number..blocks_count) |index| _ = try harness.pass(@intCast(index));
        try harness.runner.flush();
        try harness.expect_oracle_state();
        // Every phase of the committed blocks was timed.
        const time = harness.runner.stats.time;
        try testing.expect(time.transactions_ns > 0 and time.commit_ns > 0);
        try testing.expect(time.state_root_ns > 0 and time.receipts_root_ns > 0);
        try testing.expect(time.check_ns > 0 and time.journal_ns > 0 and time.room_ns > 0);
        checkpoints += harness.disk.db.checkpoints_completed;
        requested += harness.runner.stats.checkpoints_requested;
    }
    // Beyond the imports' own: the runner made room by checkpoints, before and after a crash.
    try testing.expect(requested >= 6);
    try testing.expect(checkpoints >= 3 + requested / 2);
}

/// Block `index` with its header changed by `tamper` and resealed (hash recomputed).
fn tampered(
    arena: std.mem.Allocator,
    block: *const run.Block,
    comptime tamper: fn (*Header) void,
) !run.Block {
    var header = try Header.decode(block.header_rlp);
    tamper(&header);
    const header_rlp = try arena.alloc(u8, rlp.length(header));
    _ = rlp.encode_to(header_rlp, header);
    var result = block.*;
    result.header_rlp = header_rlp;
    result.hash = keccak256(header_rlp);
    return result;
}

fn tamper_state_root(header: *Header) void {
    header.state_root.bytes[3] ^= 0x10;
}

fn tamper_withdrawals_root(header: *Header) void {
    header.withdrawals_root.?.bytes[0] ^= 0x01;
}

fn tamper_parent(header: *Header) void {
    header.parent_hash.bytes[31] ^= 0x80;
}

fn tamper_number(header: *Header) void {
    header.number += 1;
}

/// Every failure and refusal on block `index`, each leaving the database as it was.
fn reject_variants(harness: *Harness, index: u32) !void {
    const arena = harness.arena;
    const block = &harness.blocks[index];
    const before = try Snapshot.take(harness);
    const oracle_root = (try Header.decode(block.header_rlp)).state_root.bytes;
    // A wrong state root: the check fails, the computed root is the oracle's.
    const wrong_root = try tampered(arena, block, tamper_state_root);
    const outcome = try harness.runner.execute(&wrong_root);
    try testing.expect(!outcome.ok() and outcome.failure == null);
    try testing.expectEqual(@as(?run.Check, .state_root), outcome.first_failed());
    try testing.expect(outcome.check(.receipts_root) and outcome.check(.withdrawals_root));
    try testing.expect(!outcome.check(.block_hash));
    try testing.expectEqualSlices(u8, &oracle_root, &outcome.computed_state_root);
    try testing.expect(!std.mem.eql(u8, &oracle_root, &outcome.expected_state_root));
    try testing.expectEqual(@as(u64, 0), outcome.sequence);
    try before.expect_same(harness);
    // A wrong withdrawals root (the message passer's storage root).
    const wrong_withdrawals = try tampered(arena, block, tamper_withdrawals_root);
    const withdrawals = try harness.runner.execute(&wrong_withdrawals);
    try testing.expectEqual(@as(?run.Check, .withdrawals_root), withdrawals.first_failed());
    try testing.expect(withdrawals.check(.state_root));
    try before.expect_same(harness);
    // An invalid transaction (a nonce far ahead): execution fails.
    var invalid = block.*;
    const transactions = try arena.dupe([]const u8, block.transactions);
    const saved = harness.oracle.nonces[0];
    harness.oracle.nonces[0] = 1000;
    transactions[0] = try harness.oracle.sign(arena, 0, recipient(0), 1, &.{}, 21_000);
    harness.oracle.nonces[0] = saved;
    invalid.transactions = transactions;
    const failed = try harness.runner.execute(&invalid);
    try testing.expect(!failed.ok() and failed.failure != null);
    try testing.expectEqual(@as(u16, 0), failed.passed);
    try before.expect_same(harness);
    // Refusals: a wrong parent, a wrong number, a header that is not the block hash.
    const wrong_parent = try tampered(arena, block, tamper_parent);
    try testing.expectError(error.NotNextBlock, harness.runner.execute(&wrong_parent));
    var wrong_number = try tampered(arena, block, tamper_number);
    try testing.expectError(error.InvalidHeader, harness.runner.execute(&wrong_number));
    wrong_number.number += 1;
    try testing.expectError(error.NotNextBlock, harness.runner.execute(&wrong_number));
    var wrong_hash = block.*;
    wrong_hash.hash[7] ^= 1;
    try testing.expectError(error.HashMismatch, harness.runner.execute(&wrong_hash));
    try before.expect_same(harness);
}

test "import run: failed checks and refusals leave head and state; the next block passes" {
    const keys = derive_keys();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const harness = try Harness.create(arena_state.allocator(), &keys, 11);
    defer harness.destroy();
    // On the imported head (no stored block), then on committed heads.
    try reject_variants(harness, 0);
    _ = try harness.pass(0);
    try reject_variants(harness, 1);
    for (1..6) |index| _ = try harness.pass(@intCast(index));
    try reject_variants(harness, 6);
    for (6..blocks_count) |index| _ = try harness.pass(@intCast(index));
    try harness.runner.flush();
    try harness.expect_oracle_state();
    // A clean reopen keeps the last block.
    harness.runner.destroy(testing.allocator);
    try harness.disk.reopen();
    harness.runner = try harness.runner_create();
    const last = &harness.blocks[blocks_count - 1];
    try testing.expectEqualSlices(u8, &last.hash, &harness.disk.db.head_info.hash);
    try harness.expect_oracle_state();
}

//! `witness_block.Generator` over a durable database: blocks run through the real evm and
//! commit with `execute_and_commit`; then each retained block's witness is generated
//! (state unwound in memory to the parent, block re-executed over the recorder, head
//! restored) and checked by stateless re-execution over `SparseState.database()` loaded
//! with only the witness: same post root as stored. The head, its root, and the journal
//! are unchanged by the call; blocks outside the depth bound, unknown blocks, and genesis
//! are refused.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const storage = @import("storage/storage.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const witness = @import("witness.zig");
const witness_block = @import("witness_block.zig");
const evm_test = @import("witness_evm_test.zig");
const evm = @import("../evm/root.zig");
const trie = @import("../trie/root.zig");

const Hash = database.Hash;
const Address = state_module.Address;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Database = database.DatabaseType(SimStorage);
const TxEnv = evm.transaction.TxEnv;
const sector_size = storage.sector_size;

const blocks_total = 6;
const txs_per_block = 4;
const depth_max = 5;
const senders_total = 3;
const contract_storage = 0xc0;
const contract_inspector = 0xc1;
const ticks_max = 200_000;

const changeset_config: changeset_module.Config = .{
    .accounts_max = 64,
    .storage_max = 256,
    .codes_max = 4,
    .code_bytes_max = 1024,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 64,
    .slots_max = 256,
    .codes_max = 4,
};

const config: database.Config = .{
    .engine = .{
        .journal_size_bytes = 96 * sector_size,
        .checkpoint_zone_size_bytes = 48 * sector_size,
        .entry_body_size_max = 2 * sector_size,
        .checkpoint_block_size = 4 * sector_size,
    },
    .state = .{
        .accounts_max = 64,
        .storage_slots_max = 512,
        .codes_max = 8,
        .code_bytes_max = 2048,
        .account_nodes_max = 1024,
        .storage_nodes_max = 4096,
    },
    .chain = .{
        .blocks_max = 16,
        .bytes_max = 32 * 1024,
        .transactions_max = 128,
        .canonical_max = 64,
        .reorg_depth_max = 16,
    },
    .changeset = changeset_config,
    .queue_entries_max = 6,
    .checkpoint_staging_bytes = 128 * 1024,
};

const keys_config: witness.KeySet.Config = .{
    .accounts_max = 64,
    .slots_max = 256,
    .codes_max = 8,
    .block_numbers_max = 16,
};

const sparse_config: witness.SparseState.Config = .{
    .nodes_max = 1024,
    .node_bytes_max = 1 << 18,
    .codes_max = 8,
    .code_bytes_max = 2048,
    .headers_max = 16,
    .trie_nodes_max = 4096,
    .storage_tries_max = 32,
};

const generator_config: witness_block.Config = .{
    .builder = .{ .sparse = sparse_config, .keys = keys_config },
    .witness = .{
        .state_nodes_max = 1024,
        .state_bytes_max = 1 << 18,
        .codes_max = 8,
        .code_bytes_max = 2048,
        .keys_max = 64 + 256,
        .headers_max = 16,
        .header_bytes_max = 1024,
    },
    .overlay = overlay_config,
    .changeset = changeset_config,
    .depth_max = depth_max,
};

fn address_of(index: u8) Address {
    var address: Address = @splat(0);
    address[0] = 0xa0;
    address[19] = index;
    return address;
}

/// `rlp([1, 1, 1, 1, 1, 1, 1, 1, number])`: header-shaped, number at field 8 (< 128).
fn header_of(number: u8) [10]u8 {
    assert(number < 0x80);
    return .{ 0xc9, 1, 1, 1, 1, 1, 1, 1, 1, if (number == 0) 0x80 else number };
}

fn write_word(buffer: []u8, word_index: u32, value: u256) void {
    std.mem.writeInt(u256, buffer[word_index * 32 ..][0..32], value, .big);
}

const Block = struct {
    env: evm.env.BlockEnv,
    txs: [txs_per_block]TxEnv,
    calldata: [txs_per_block][64]u8,
};

const Harness = struct {
    sim: SimStorage,
    db: Database,
    overlay: Overlay,
    generator: witness_block.Generator,
    evm_state: evm.State,
    machine: evm.Evm,
    sparse: witness.SparseState,
    sparse_changeset: Changeset,
    blocks: [blocks_total + 1]Block,
    headers: [blocks_total + 1][10]u8,
    hashes: [blocks_total + 1]Hash,
    roots: [blocks_total + 1]Hash,
    nonces: [senders_total]u64,

    /// In place: the database, overlay, generator, and evm keep pointers into it.
    fn init(self: *Harness) !void {
        const allocator = testing.allocator;
        self.sim = try SimStorage.init(allocator, .{
            .size_bytes = config.engine.size_bytes(),
            .seed = 0x5eed,
        });
        self.db = try Database.init(allocator, &self.sim, config);
        self.overlay = try Overlay.init(allocator, &self.db.state, overlay_config);
        self.generator = try witness_block.Generator.init(
            allocator,
            &self.db.state,
            generator_config,
        );
        const inner = evm_backend.database(&self.db.state);
        self.evm_state = try evm.State.init(allocator, inner, evm_test.evm_limits);
        self.machine = try evm.Evm.init(allocator, evm_test.evm_config, &self.evm_state);
        self.sparse = try witness.SparseState.init(allocator, sparse_config);
        self.sparse_changeset = try Changeset.init(allocator, changeset_config);
        self.nonces = @splat(0);
    }

    fn deinit(self: *Harness) void {
        const allocator = testing.allocator;
        self.sparse_changeset.deinit(allocator);
        self.sparse.deinit(allocator);
        self.machine.deinit(allocator);
        self.evm_state.deinit(allocator);
        self.generator.deinit(allocator);
        self.overlay.deinit(allocator);
        self.db.deinit(allocator);
        self.sim.deinit(allocator);
    }

    fn tick_until_idle(self: *Harness) !void {
        var ticks: u32 = 0;
        while (self.db.phase != .ready or !self.db.idle()) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            self.sim.tick();
        }
    }

    fn start(self: *Harness) !void {
        self.db.format(0xfeed);
        var ticks: u32 = 0;
        while (self.db.phase == .formatting) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Timeout;
            self.sim.tick();
        }
        self.db.open();
        try self.tick_until_idle();
        for (0..senders_total) |index| {
            try self.overlay.set_account(address_of(@intCast(index)), .{ .balance = 1 << 60 });
        }
        try self.contract(contract_storage, &evm_test.code_storage);
        try self.contract(contract_inspector, &evm_test.code_inspector);
        for (0..4) |slot| try self.overlay.set_storage(address_of(contract_storage), slot, 7);
        try self.commit(0, @splat(0));
    }

    fn contract(self: *Harness, index: u8, code: []const u8) !void {
        const code_hash = try self.overlay.insert_code(code);
        try self.overlay.set_account(address_of(index), .{ .nonce = 1, .code_hash = code_hash });
    }

    /// Commits the overlay as block `number` (header-shaped bytes, hash = keccak).
    fn commit(self: *Harness, number: u8, parent_hash: Hash) !void {
        self.headers[number] = header_of(number);
        const hash = trie.node.keccak256(&self.headers[number]);
        const input: database.BlockInput = .{
            .hash = hash,
            .parent_hash = parent_hash,
            .number = number,
            .timestamp = number,
            .header = &self.headers[number],
            .body = "body",
            .receipts = &.{},
            .transaction_hashes = &.{},
            .changeset = &.{},
        };
        const result = try self.db.execute_and_commit(&self.overlay, &input);
        self.hashes[number] = hash;
        self.roots[number] = result.state_root;
        try self.tick_until_idle();
    }

    fn fill_block(self: *Harness, number: u8) void {
        const block = &self.blocks[number];
        block.env = .{ .number = number, .timestamp = number, .coinbase = address_of(0xfe) };
        for (&block.txs, 0..) |*tx, index| {
            const sender: u8 = @intCast((number + index) % senders_total);
            tx.* = .{
                .caller = address_of(sender),
                .gas_limit = 200_000,
                .gas_price = 1,
                .nonce = self.nonces[sender],
            };
            self.nonces[sender] += 1;
            const calldata = &block.calldata[index];
            switch (index) {
                0, 1 => {
                    tx.to = address_of(contract_storage);
                    write_word(calldata, 0, (number + index) % 6);
                    write_word(calldata, 1, if (index == 1 and number % 2 == 0) 0 else number);
                    tx.data = calldata;
                },
                2 => {
                    tx.to = address_of(contract_inspector);
                    write_word(calldata, 0, std.mem.readInt(u160, &address_of(1), .big));
                    write_word(calldata, 1, @max(number, 2) - 2);
                    tx.data = calldata;
                },
                else => {
                    tx.to = address_of(0x40 + number);
                    tx.value = 1000 + @as(u256, number);
                },
            }
        }
    }

    /// Runs block `number`'s transactions over `db`; leaves the changes in `evm_state`.
    fn execute(self: *Harness, number: u8, db: evm.state.Database) !void {
        const block = &self.blocks[number];
        self.evm_state.reset(db);
        self.machine.block = block.env;
        for (&block.txs) |*tx| {
            const result = try evm.transaction.transact(&self.machine, evm_test.fork, tx);
            if (result == .invalid) return error.InvalidTransaction;
            if (result.executed.status != .success) return error.TransactionFailed;
        }
    }

    fn mine(self: *Harness, number: u8) !void {
        self.fill_block(number);
        try self.execute(number, evm_backend.database(&self.db.state));
        try evm_backend.commit_evm(&self.evm_state, &self.overlay);
        try self.commit(number, self.hashes[number - 1]);
    }
};

const Run = struct {
    harness: *Harness,
    number: u8,

    fn execute(
        context: *anyopaque,
        db: evm.state.Database,
    ) witness_block.ExecuteError!*const evm.State {
        const run: *Run = @ptrCast(@alignCast(context));
        run.harness.execute(run.number, db) catch return error.ExecutionFailed;
        return &run.harness.evm_state;
    }
};

fn witness_of(harness: *Harness, number: u8, hash: Hash) witness_block.Error!Hash {
    var run: Run = .{ .harness = harness, .number = number };
    const execute: witness_block.Execute = .{ .context = &run, .run = Run.execute };
    return harness.generator.database_witness(&harness.db, hash, execute);
}

/// Stateless re-execution of block `number` from the generated witness alone.
fn check_stateless(harness: *Harness, number: u8) !void {
    const sparse = &harness.sparse;
    sparse.reset(harness.roots[number - 1]);
    try sparse.load(&harness.generator.witness);
    try harness.execute(number, sparse.database());
    try testing.expect(!sparse.incomplete);
    try sparse.apply_evm(&harness.evm_state, &harness.sparse_changeset);
    try testing.expectEqual(harness.roots[number], sparse.state_root());
}

test "witness block: durable witness re-executes statelessly to the stored root" {
    const harness = try testing.allocator.create(Harness);
    defer testing.allocator.destroy(harness);
    try harness.init();
    defer harness.deinit();
    try harness.start();
    var number: u8 = 1;
    while (number <= blocks_total) : (number += 1) try harness.mine(number);

    const head = harness.db.head_info;
    const sequence = harness.db.submitted_sequence;
    number = blocks_total + 1 - depth_max;
    while (number <= blocks_total) : (number += 1) {
        const root = try witness_of(harness, number, harness.hashes[number]);
        try testing.expectEqual(harness.roots[number], root);
        try testing.expect(harness.generator.witness.state.count > 0);
        try testing.expect(harness.generator.witness.headers.count >= 1);
        try testing.expect(head.eql(harness.db.head_info));
        try testing.expectEqual(head.state_root, try harness.db.state.state_root());
        try testing.expectEqual(sequence, harness.db.submitted_sequence);
        try check_stateless(harness, number);
    }

    // Deeper than `depth_max`, unknown, and genesis blocks are refused; nothing moves.
    const refused = [_]Hash{ harness.hashes[1], @splat(0xee), harness.hashes[0] };
    for (refused) |hash| {
        try testing.expectError(error.BlockUnavailable, witness_of(harness, 1, hash));
        try testing.expect(head.eql(harness.db.head_info));
        try testing.expectEqual(head.state_root, try harness.db.state.state_root());
    }
    try testing.expectEqual(database.Phase.ready, harness.db.phase);
}

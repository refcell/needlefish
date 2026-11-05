//! Witness differential test over the real evm (base/base `witness_differential`).
//!
//! A seeded random pre-state (EOAs plus hand-assembled contracts exercising SLOAD, SSTORE,
//! LOG1, BALANCE, EXTCODEHASH, EXTCODESIZE, BLOCKHASH, CALL, SELFDESTRUCT, and CREATE) and
//! random blocks of calls and value transfers. Each block runs through the evm against
//! `Recorder(evm_backend.database(&state))`, folds into an `Overlay` with
//! `evm_backend.commit_evm`, and yields the changeset, post root, and witness. The same
//! transactions then run against `SparseState.database()` loaded with only the witness, and
//! `SparseState.apply_evm` folds that evm state into the sparse trie. Checks: identical
//! results (validity, status, gas used and refunded, output, created address, logs), the
//! same post-state root, no `incomplete`; and without any one witness node the stateless
//! run either fails flagged incomplete or reaches a different root.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const witness = @import("witness.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const evm = @import("../evm/root.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const op = evm.opcode;
const push16 = op.PUSH1 + 15;
const dup6 = op.DUP1 + 5;
const log1 = op.LOG0 + 1;
const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const Hash = state_module.Hash;
const TxEnv = evm.transaction.TxEnv;

pub const fork: evm.Fork = .cancun;
const senders_total = 8;
const addresses_total = 64;
const random_accounts = 24;
const slot_ids = 8;
const headers_total = 4;
const txs_max = 12;
const calldata_bytes_max = 128;
const sender_balance: u256 = 1 << 60;
const tx_gas_limit: u64 = 300_000;

const contract_storage = 48;
const contract_inspector = 49;
const contract_forwarder = 50;
const contract_destructor = 51;
const contract_factory = 52;
const coinbase_index = 63;

/// `slot = cd[0]; old = SLOAD(slot); SSTORE(slot, cd[32]); LOG1(old, topic = caller);
/// return old`.
pub const code_storage = [_]u8{
    op.PUSH1, 0x20, op.CALLDATALOAD, op.PUSH1,  0,         op.CALLDATALOAD, op.DUP1,   op.SLOAD,
    op.PUSH1, 0,    op.MSTORE,       op.SSTORE, op.CALLER, op.PUSH1,        0x20,      op.PUSH1,
    0,        log1, op.PUSH1,        0x20,      op.PUSH1,  0,               op.RETURN,
};

/// Returns `BALANCE`, `EXTCODEHASH`, `EXTCODESIZE` of address `cd[0]` and `BLOCKHASH(cd[32])`.
pub const code_inspector = [_]u8{
    op.PUSH1, 0,    op.CALLDATALOAD, op.BALANCE,     op.PUSH1,  0,    op.MSTORE,
    op.PUSH1, 0,    op.CALLDATALOAD, op.EXTCODEHASH, op.PUSH1,  0x20, op.MSTORE,
    op.PUSH1, 0,    op.CALLDATALOAD, op.EXTCODESIZE, op.PUSH1,  0x40, op.MSTORE,
    op.PUSH1, 0x20, op.CALLDATALOAD, op.BLOCKHASH,   op.PUSH1,  0x60, op.MSTORE,
    op.PUSH1, 0x80, op.PUSH1,        0,              op.RETURN,
};

/// Counts calls in slot 1, then `CALL(gas, cd[0], value = cd[32], input = cd[64..])` and
/// returns the first output word and the success flag.
const code_forwarder =
    // SSTORE(1, SLOAD(1) + 1)
    [_]u8{ op.PUSH1, 1, op.SLOAD, op.PUSH1, 1, op.ADD, op.PUSH1, 1, op.SSTORE } ++
    // CALLDATACOPY(0, 64, CALLDATASIZE - 64)
    [_]u8{ op.PUSH1, 0x40, op.CALLDATASIZE, op.SUB, op.PUSH1, 0x40, op.PUSH1, 0 } ++
    [_]u8{op.CALLDATACOPY} ++
    // CALL(GAS, cd[0], cd[32], 0, CALLDATASIZE - 64, 0, 32)
    [_]u8{ op.PUSH1, 0x20, op.PUSH1, 0, op.PUSH1, 0x40, op.CALLDATASIZE, op.SUB } ++
    [_]u8{ op.PUSH1, 0, op.PUSH1, 0x20, op.CALLDATALOAD, op.PUSH1, 0, op.CALLDATALOAD } ++
    [_]u8{ op.GAS, op.CALL } ++
    // MSTORE(32, success); RETURN(0, 64)
    [_]u8{ op.PUSH1, 0x20, op.MSTORE, op.PUSH1, 0x40, op.PUSH1, 0, op.RETURN };

/// `SELFDESTRUCT(cd[0])`: a pre-existing contract only sends its balance (EIP-6780).
const code_destructor = [_]u8{ op.PUSH1, 0, op.CALLDATALOAD, op.SELFDESTRUCT };

/// Init code: `SSTORE(0, 42)`, deploy runtime `CALLER SELFDESTRUCT`.
const init_code = [16]u8{
    op.PUSH1, 0x2a, op.PUSH1,  0,        op.SSTORE, op.PUSH2, op.CALLER, op.SELFDESTRUCT,
    op.PUSH1, 0,    op.MSTORE, op.PUSH1, 2,         op.PUSH1, 0x1e,      op.RETURN,
};

/// `child = CREATE(callvalue, init_code)`, kept in slot 2; when `cd[0] != 0` the child is
/// called and self-destructs in its creating transaction (destroyed, EIP-6780).
const code_factory = [_]u8{push16} ++ init_code ++ [_]u8{
    op.PUSH1,  0,        op.MSTORE,    op.PUSH1, 16,        op.PUSH1, 16,       op.CALLVALUE,
    op.CREATE, op.DUP1,  op.PUSH1,     2,        op.SSTORE, op.PUSH1, 0,        op.CALLDATALOAD,
    op.ISZERO, op.PUSH1, factory_skip, op.JUMPI, op.PUSH1,  0,        op.PUSH1, 0,
    op.PUSH1,  0,        op.PUSH1,     0,        op.PUSH1,  0,        dup6,     op.GAS,
    op.CALL,   op.POP,   op.JUMPDEST,  op.STOP,
};
const factory_skip = 51;

comptime {
    assert(code_factory[factory_skip] == op.JUMPDEST);
    assert(code_factory.len == factory_skip + 2);
}

const state_config: state_module.Config = .{
    .accounts_max = 256,
    .storage_slots_max = 1024,
    .codes_max = 32,
    .code_bytes_max = 2048,
    .account_nodes_max = 2048,
    .storage_nodes_max = 4096,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = 256,
    .storage_max = 1024,
    .codes_max = 32,
    .code_bytes_max = 2048,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 256,
    .slots_max = 1024,
    .codes_max = 32,
};

const keys_config: witness.KeySet.Config = .{
    .accounts_max = 256,
    .slots_max = 1024,
    .codes_max = 32,
    .block_numbers_max = 16,
};

const sparse_config: witness.SparseState.Config = .{
    .nodes_max = 2048,
    .node_bytes_max = 1 << 20,
    .codes_max = 32,
    .code_bytes_max = 2048,
    .headers_max = 16,
    .trie_nodes_max = 8192,
    .storage_tries_max = 128,
};

const witness_config: witness.Witness.Config = .{
    .state_nodes_max = 2048,
    .state_bytes_max = 1 << 20,
    .codes_max = 32,
    .code_bytes_max = 2048,
    .keys_max = 256 + 1024,
    .headers_max = 16,
    .header_bytes_max = 1024,
};

/// Both runs use the same evm configuration; the programs nest at most three calls deep.
pub const evm_config: evm.env.Config = .{
    .depth_max = 64,
    .memory_bytes_max = 1 << 16,
    .code_arena_bytes = 1 << 20,
    .modexp_modulus_bytes_max = 4096,
};

pub const evm_limits: evm.state.Limits = .{
    .accounts_max = 256,
    .slots_max = 1024,
    .transient_slots_max = 16,
    .journal_entries_max = 4096,
    .logs_max = 64,
    .log_data_bytes_max = 4096,
    .code_bytes_max = 4096,
};

fn address_of(index: u64) Address {
    assert(index < addresses_total);
    var address: Address = @splat(0);
    address[0] = 0xa0;
    address[19] = @intCast(index);
    return address;
}

/// `rlp([1, 1, 1, 1, 1, 1, 1, 1, number])`, a minimal header-shaped list (number < 128).
fn header_of(number: u8) [10]u8 {
    assert(number > 0 and number < 0x80);
    return .{ 0xc9, 1, 1, 1, 1, 1, 1, 1, 1, number };
}

/// One transaction's observable result, digested so it outlives the evm's buffers.
const Observed = struct {
    invalid: ?evm.transaction.Invalid = null,
    status: evm.evm.Status = .success,
    gas_used: u64 = 0,
    gas_refunded: u64 = 0,
    output_len: u64 = 0,
    output_hash: u64 = 0,
    created: ?Address = null,
    logs_len: u64 = 0,
    logs_hash: u64 = 0,
};

fn observe(result: evm.transaction.Result) Observed {
    const executed = switch (result) {
        .invalid => |invalid| return .{ .invalid = invalid },
        .executed => |executed| executed,
    };
    var logs = std.hash.Wyhash.init(0);
    for (executed.logs) |*log| {
        logs.update(&log.address);
        for (log.topic_slice()) |*topic| logs.update(topic);
        logs.update(std.mem.asBytes(&log.data.len));
        logs.update(log.data);
    }
    return .{
        .status = executed.status,
        .gas_used = executed.gas_used,
        .gas_refunded = executed.gas_refunded,
        .output_len = executed.output.len,
        .output_hash = std.hash.Wyhash.hash(0, executed.output),
        .created = executed.created,
        .logs_len = executed.logs.len,
        .logs_hash = logs.final(),
    };
}

/// A block's transactions; `txs[i].data` points into `calldata[i]`, so a Block never moves.
const Block = struct {
    env: evm.env.BlockEnv,
    txs: [txs_max]TxEnv,
    calldata: [txs_max][calldata_bytes_max]u8,
    count: u32,
};

fn write_word(buffer: []u8, word_index: u32, value: u256) void {
    std.mem.writeInt(u256, buffer[word_index * 32 ..][0..32], value, .big);
}

fn address_word(address: Address) u256 {
    return std.mem.readInt(u160, &address, .big);
}

fn random_address(prng: *Prng) Address {
    return address_of(prng.below(addresses_total));
}

/// A block number for BLOCKHASH: mostly in the header window, sometimes out of it.
fn random_block_number(prng: *Prng) u256 {
    if (prng.chance(1, 5)) return 1000;
    return prng.range(1, headers_total);
}

/// Fills `calldata` for a call to contract `target_index`; returns the length used.
fn contract_calldata(prng: *Prng, target_index: u64, calldata: []u8) u32 {
    assert(calldata.len >= 64);
    switch (target_index) {
        contract_storage => {
            write_word(calldata, 0, prng.below(slot_ids));
            write_word(calldata, 1, if (prng.chance(1, 3)) 0 else prng.range(1, 1 << 20));
            return 64;
        },
        contract_inspector => {
            write_word(calldata, 0, address_word(random_address(prng)));
            write_word(calldata, 1, random_block_number(prng));
            return 64;
        },
        contract_destructor => {
            write_word(calldata, 0, address_word(random_address(prng)));
            return 32;
        },
        contract_factory => {
            write_word(calldata, 0, @intFromBool(prng.chance(1, 2)));
            return 32;
        },
        else => unreachable,
    }
}

fn random_tx(prng: *Prng, tx: *TxEnv, calldata: *[calldata_bytes_max]u8) void {
    const targets = [_]u64{
        contract_storage, contract_inspector, contract_destructor, contract_factory,
    };
    var length: u32 = 0;
    switch (prng.below(6)) {
        0 => {
            tx.to = random_address(prng);
            tx.value = prng.below(1 << 30);
        },
        1 => {
            tx.to = address_of(contract_forwarder);
            const inner = targets[prng.below(targets.len)];
            const target = if (prng.chance(1, 4)) prng.below(addresses_total) else inner;
            write_word(calldata, 0, address_word(address_of(target)));
            write_word(calldata, 1, prng.below(1000));
            const inner_index = if (target == inner) inner else contract_storage;
            length = 64 + contract_calldata(prng, inner_index, calldata[64..]);
        },
        else => {
            const target = targets[prng.below(targets.len)];
            tx.to = address_of(target);
            if (target != contract_storage) tx.value = prng.below(1000);
            length = contract_calldata(prng, target, calldata);
        },
    }
    assert(length <= calldata_bytes_max);
    tx.data = calldata[0..length];
}

fn generate_block(prng: *Prng, state: *State, block: *Block, number: u64) void {
    var nonces: [senders_total]u64 = undefined;
    for (&nonces, 0..) |*nonce, index| nonce.* = state.basic(address_of(index)).?.nonce;
    block.env = .{
        .number = number,
        .timestamp = number * 2,
        .coinbase = address_of(coinbase_index),
    };
    block.count = @intCast(prng.range(4, txs_max));
    for (block.txs[0..block.count], 0..) |*tx, index| {
        const sender = prng.below(senders_total);
        tx.* = .{
            .caller = address_of(sender),
            .gas_limit = tx_gas_limit,
            .gas_price = 1,
            .nonce = nonces[sender],
        };
        nonces[sender] += 1;
        random_tx(prng, tx, &block.calldata[index]);
        // Sometimes too little gas: the call halts out of gas after some of its reads.
        if (prng.chance(1, 6)) tx.gas_limit = prng.range(24_000, 40_000);
    }
}

fn genesis_contract(overlay: *Overlay, index: u64, code: []const u8, balance: u256) !void {
    const code_hash = try overlay.insert_code(code);
    try overlay.set_account(address_of(index), .{
        .nonce = 1,
        .balance = balance,
        .code_hash = code_hash,
    });
}

fn genesis(prng: *Prng, state: *State, overlay: *Overlay, changeset: *Changeset) !void {
    for (0..senders_total) |index| {
        try overlay.set_account(address_of(index), .{ .balance = sender_balance });
    }
    for (senders_total..senders_total + random_accounts) |index| {
        if (prng.chance(1, 3)) continue;
        try overlay.set_account(address_of(index), .{
            .nonce = prng.below(3),
            .balance = prng.below(1 << 40),
        });
    }
    try genesis_contract(overlay, contract_storage, &code_storage, 0);
    try genesis_contract(overlay, contract_inspector, &code_inspector, prng.below(1 << 20));
    try genesis_contract(overlay, contract_forwarder, &code_forwarder, 1 << 30);
    try genesis_contract(overlay, contract_destructor, &code_destructor, prng.below(1 << 20));
    try genesis_contract(overlay, contract_factory, &code_factory, 0);
    for (0..slot_ids) |slot| {
        if (prng.chance(1, 2)) {
            try overlay.set_storage(address_of(contract_storage), slot, prng.range(1, 1 << 20));
        }
    }
    try overlay.set_storage(address_of(contract_forwarder), 1, prng.range(1, 100));
    _ = try overlay.commit(changeset);
    for (1..headers_total + 1) |number| {
        const header = header_of(@intCast(number));
        state.set_block_hash(number, trie.node.keccak256(&header));
    }
}

const Fixture = struct {
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    recorder: witness.Recorder,
    builder: witness.Builder,
    built: witness.Witness,
    sparse: witness.SparseState,
    sparse_changeset: Changeset,
    evm_state: evm.State,
    machine: evm.Evm,
    block: Block,
    expected: [txs_max]Observed,
    observed: [txs_max]Observed,

    /// In place: the overlay, recorder, and evm keep pointers into the fixture.
    fn init(fixture: *Fixture) !void {
        const allocator = testing.allocator;
        fixture.state = try State.init(allocator, state_config);
        fixture.overlay = try Overlay.init(allocator, &fixture.state, overlay_config);
        fixture.changeset = try Changeset.init(allocator, changeset_config);
        const inner = evm_backend.database(&fixture.state);
        fixture.recorder = try witness.Recorder.init(allocator, inner, keys_config);
        fixture.builder = try witness.Builder.init(allocator, .{
            .sparse = sparse_config,
            .keys = keys_config,
        });
        fixture.built = try witness.Witness.init(allocator, witness_config);
        fixture.sparse = try witness.SparseState.init(allocator, sparse_config);
        fixture.sparse_changeset = try Changeset.init(allocator, changeset_config);
        fixture.evm_state = try evm.State.init(allocator, inner, evm_limits);
        fixture.machine = try evm.Evm.init(allocator, evm_config, &fixture.evm_state);
    }

    fn deinit(fixture: *Fixture) void {
        const allocator = testing.allocator;
        fixture.machine.deinit(allocator);
        fixture.evm_state.deinit(allocator);
        fixture.sparse_changeset.deinit(allocator);
        fixture.sparse.deinit(allocator);
        fixture.built.deinit(allocator);
        fixture.builder.deinit(allocator);
        fixture.recorder.deinit(allocator);
        fixture.changeset.deinit(allocator);
        fixture.overlay.deinit(allocator);
        fixture.state.deinit(allocator);
    }

    /// Runs the block's transactions over `database`; a database failure aborts the block.
    fn execute(fixture: *Fixture, database: evm.state.Database, out: []Observed) !void {
        const block = &fixture.block;
        assert(out.len >= block.count);
        fixture.evm_state.reset(database);
        fixture.machine.block = block.env;
        for (block.txs[0..block.count], 0..) |*tx, index| {
            const result = try evm.transaction.transact(&fixture.machine, fork, tx);
            out[index] = observe(result);
        }
    }
};

/// Full-state run: execute over the recorder, build the changeset and witness, commit.
/// Returns the post-state root.
fn run_full(fixture: *Fixture) !Hash {
    const keys = &fixture.recorder.keys;
    keys.clear();
    try fixture.execute(fixture.recorder.database(), &fixture.expected);
    for (fixture.expected[0..fixture.block.count]) |*observed| {
        // Senders are funded and nonces tracked: every transaction is valid.
        try testing.expectEqual(null, observed.invalid);
    }
    try evm_backend.commit_evm(&fixture.evm_state, &fixture.overlay);
    try fixture.overlay.build_changeset(&fixture.changeset);
    var headers_buffer: [headers_total][10]u8 = undefined;
    var headers: [headers_total][]const u8 = undefined;
    for (keys.block_numbers.slice(), 0..) |number, index| {
        headers_buffer[index] = header_of(@intCast(number));
        headers[index] = &headers_buffer[index];
    }
    const witness_root = try fixture.builder.build(
        &fixture.state,
        keys,
        &fixture.changeset,
        headers[0..keys.block_numbers.len],
        &fixture.built,
    );
    const post_root = try fixture.overlay.commit(&fixture.changeset);
    try testing.expectEqual(post_root, witness_root);
    return post_root;
}

/// Loads the witness into the sparse state, skipping state node `skip` (if any).
fn load_witness(fixture: *Fixture, pre_root: Hash, skip: ?u32) !void {
    const sparse = &fixture.sparse;
    const built = &fixture.built;
    sparse.reset(pre_root);
    var index: u32 = 0;
    while (index < built.state.count) : (index += 1) {
        if (skip != index) try sparse.add_node(built.state.get(index));
    }
    index = 0;
    while (index < built.codes.count) : (index += 1) try sparse.add_code(built.codes.get(index));
    index = 0;
    while (index < built.headers.count) : (index += 1) {
        try sparse.add_header(built.headers.get(index));
    }
}

/// Stateless run with the whole witness: same results, same root, nothing missing.
fn run_stateless(fixture: *Fixture, pre_root: Hash, post_root: Hash) !void {
    try load_witness(fixture, pre_root, null);
    const sparse = &fixture.sparse;
    try fixture.execute(sparse.database(), &fixture.observed);
    try testing.expect(!sparse.incomplete);
    for (0..fixture.block.count) |index| {
        try testing.expectEqualDeep(fixture.expected[index], fixture.observed[index]);
    }
    try sparse.apply_evm(&fixture.evm_state, &fixture.sparse_changeset);
    try testing.expect(!sparse.incomplete);
    try testing.expectEqual(post_root, sparse.state_root());
}

/// Without any one node: the run fails flagged incomplete, or the root differs.
fn check_node_removal(fixture: *Fixture, pre_root: Hash, post_root: Hash) !void {
    const sparse = &fixture.sparse;
    var skip: u32 = 0;
    while (skip < fixture.built.state.count) : (skip += 1) {
        try load_witness(fixture, pre_root, skip);
        fixture.execute(sparse.database(), &fixture.observed) catch |err| {
            try testing.expectEqual(error.DatabaseFailure, err);
            try testing.expect(sparse.incomplete);
            continue;
        };
        sparse.apply_evm(&fixture.evm_state, &fixture.sparse_changeset) catch |err| {
            try testing.expectEqual(error.WitnessIncomplete, err);
            continue;
        };
        try testing.expect(!std.mem.eql(u8, &post_root, &sparse.state_root()));
    }
}

test "witness evm: stateless re-execution over the witness matches the full state" {
    var seed: u64 = 0;
    while (seed < 6) : (seed += 1) {
        var prng = Prng.init(0xe7a1_0000 + seed);
        const fixture = try testing.allocator.create(Fixture);
        defer testing.allocator.destroy(fixture);
        try fixture.init();
        defer fixture.deinit();
        try genesis(&prng, &fixture.state, &fixture.overlay, &fixture.changeset);
        var block_index: u64 = 0;
        while (block_index < 3) : (block_index += 1) {
            generate_block(&prng, &fixture.state, &fixture.block, headers_total + 1 + block_index);
            const pre_root = try fixture.state.state_root();
            const post_root = try run_full(fixture);
            try testing.expect(fixture.built.state.count > 0);
            try run_stateless(fixture, pre_root, post_root);
            try check_node_removal(fixture, pre_root, post_root);
        }
    }
}

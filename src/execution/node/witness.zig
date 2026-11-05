//! Execution witness of a stored block for the node (`debug_executionWitness`): the
//! trie-db lane's `db.witness_block.Generator` with the node's executor as the block
//! executor. A durable database with history (`Config.history`) serves blocks whose parent
//! is in its window from history, without touching the state (`Journal.witness` ->
//! `Generator.database_witness` prefers that path). Otherwise the state is unwound in memory
//! to the block's parent and restored afterwards: with a durable database through its
//! stored changesets, else through `StateDb`'s undo ring. Nothing is journaled. The executor
//! must be idle for the call (the node runs RPC handlers between blocks); the history path
//! still resets the executor's evm state, never the world state.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../../common/rlp/root.zig");
const evm = @import("../evm/root.zig");
const payload = @import("../payload/root.zig");
const db_module = @import("../db/root.zig");
const chain_module = @import("chain.zig");

const Hash = [32]u8;
const Chain = chain_module.Chain;
const Record = chain_module.Record;
pub const Generator = db_module.witness_block.Generator;
const witness_block = db_module.witness_block;

pub const Error = witness_block.Error || error{StateUnavailable};

/// Fills `generator.witness` with the witness of canonical block `hash`. The generator is
/// bound to the chain's state. Blocks below the retention or undo depth, side-chain blocks,
/// and genesis are `BlockUnavailable`; the witness root must equal the header's.
pub fn execution_witness(chain: *Chain, generator: *Generator, hash: Hash) Error!void {
    assert(generator.state == chain.db.state);
    chain.ensure_head_state() catch return error.StateUnavailable;
    const stored = chain.record(hash) orelse return error.BlockUnavailable;
    const number = stored.header.number;
    if (number == 0) return error.BlockUnavailable;
    const canonical = chain.store.canonical_hash(number) orelse return error.BlockUnavailable;
    if (!std.mem.eql(u8, &canonical, &hash)) return error.BlockUnavailable;
    try witness_from_state(chain, generator, stored, hash);
}

/// Fills `generator.witness` with the witness of block `hash`, which the state holds:
/// a block just built (`Chain.build_block`, `debug_executePayload`), canonical or not.
/// The unwind starts at that block, so only its own changeset is needed.
pub fn built_witness(chain: *Chain, generator: *Generator, hash: Hash) Error!void {
    assert(generator.state == chain.db.state);
    if (!std.mem.eql(u8, &chain.state_hash, &hash)) return error.StateUnavailable;
    const stored = chain.record(hash) orelse return error.BlockUnavailable;
    if (stored.header.number == 0) return error.BlockUnavailable;
    try witness_from_state(chain, generator, stored, hash);
    assert(std.mem.eql(u8, &chain.state_hash, &hash));
}

/// Witness of stored block `hash` relative to the state's current block.
fn witness_from_state(chain: *Chain, generator: *Generator, stored: Record, hash: Hash) Error!void {
    const number = stored.header.number;
    assert(number > 0);
    var run: Run = .{ .chain = chain, .record = stored };
    const execute: witness_block.Execute = .{ .context = &run, .run = Run.execute };
    defer {
        chain.executor.abort_block();
        chain.executor.state.reset(chain.db.database());
    }
    const root = if (chain.journal) |journal| blk: {
        const hook = journal.witness orelse return error.StateUnavailable;
        break :blk try hook(journal.context, generator, hash, execute);
    } else try memory_witness(chain, generator, number, execute);
    if (!std.mem.eql(u8, &root, &stored.header.state_root.bytes)) {
        return error.WitnessMismatch;
    }
}

/// In-memory state: the undo ring holds the changesets from the head down to the block.
fn memory_witness(
    chain: *Chain,
    generator: *Generator,
    number: u64,
    execute: witness_block.Execute,
) Error!Hash {
    const head = chain.store.ref(chain.state_hash) orelse return error.StateUnavailable;
    assert(head.number >= number and number > 0);
    const depth = head.number - number + 1;
    if (depth > generator.changesets.len) return error.BlockUnavailable;
    const changesets = chain.db.recent_changesets(@intCast(depth), generator.changesets) orelse
        return error.BlockUnavailable;
    const target: witness_block.Target = .{
        .number = number,
        .changesets = changesets,
        .blocks = blocks_of(chain),
    };
    return generator.generate(&target, execute);
}

/// The block executor over the generator's recorded parent database.
const Run = struct {
    chain: *Chain,
    record: Record,

    fn execute(
        context: *anyopaque,
        database: evm.state.Database,
    ) witness_block.ExecuteError!*const evm.State {
        const run: *Run = @ptrCast(@alignCast(context));
        const chain = run.chain;
        var stored = run.record;
        var count: usize = 0;
        while (!stored.transactions.is_empty()) : (count += 1) {
            if (count == chain.transactions_buffer.len) return error.ExecutionFailed;
            chain.transactions_buffer[count] = stored.transactions.bytes() catch unreachable;
        }
        var withdrawals_buffer: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
        const withdrawals = if (stored.withdrawals) |list|
            chain_module.convert_withdrawals(list, &withdrawals_buffer)
        else
            null;
        const env = chain_module.env_of(&stored.header);
        const executor = chain.executor;
        executor.state.reset(database);
        const transactions = chain.transactions_buffer[0..count];
        executor.execute_uncommitted(&env, transactions, withdrawals) catch {
            return error.ExecutionFailed;
        };
        assert(executor.state.database.context == database.context);
        return executor.state;
    }
};

/// The node's canonical chain: hashes and RLP headers from the block store.
fn blocks_of(chain: *const Chain) witness_block.Blocks {
    return .{ .context = chain, .hash = block_hash, .header = block_header };
}

fn chain_of(context: *const anyopaque) *const Chain {
    return @ptrCast(@alignCast(context));
}

fn block_hash(context: *const anyopaque, number: u64) ?Hash {
    return chain_of(context).store.canonical_hash(number);
}

/// The record's first item is the RLP header.
fn block_header(context: *const anyopaque, number: u64) ?[]const u8 {
    const chain = chain_of(context);
    const hash = chain.store.canonical_hash(number) orelse return null;
    const bytes = chain.store.record(hash) orelse return null;
    var outer = rlp.Decoder.init(bytes);
    var items = outer.list() catch unreachable; // Encoded by the chain.
    return items.raw() catch unreachable;
}

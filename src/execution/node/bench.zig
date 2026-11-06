//! Node benchmarks: block execution throughput.
//!
//! Each iteration executes one block of `transfers` signed EIP-1559 transfers from
//! distinct senders to fresh accounts (sender recovery, EVM, state commit, state root,
//! receipts root), then rolls the state back so every iteration sees the same block.
//! `bytes_per_op` is the block's gas, so the harness's MB/s column reads as Mgas/s.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../chainspec/root.zig");
const Case = @import("../../testing/bench.zig").Case;
const StateDb = @import("state_db.zig").StateDb;
const executor_module = @import("executor.zig");
const Executor = executor_module.Executor;
const senders = @import("senders.zig");

const transfers = 500;
const transfer_gas: u64 = 21_000;
const raw_size_max = 128;

const Setup = struct {
    db: StateDb,
    executor: Executor,
    raw_bytes: [transfers][raw_size_max]u8,
    raws: [transfers][]const u8,
    block: executor_module.BlockEnv,
};

var setup_storage: ?*Setup = null;

fn sender_key(index: u32) [32]u8 {
    var key: [32]u8 = @splat(0);
    std.mem.writeInt(u32, key[28..32], index + 1, .big);
    return key;
}

/// Builds the state and the signed block once (outside the timed region).
fn setup() *Setup {
    if (setup_storage) |ready| return ready;
    const allocator = std.heap.page_allocator;
    const spec = &chainspec.ChainSpec.presets.l1_dev;
    const s = allocator.create(Setup) catch @panic("bench: out of memory");
    s.db = StateDb.init(allocator, .{}) catch @panic("bench: state init");
    s.executor = Executor.init(allocator, spec, &s.db, .{}) catch @panic("bench: executor");
    for (0..transfers) |index| {
        const key = sender_key(@intCast(index));
        const sender = consensus.signature.address_from_private(key).?;
        s.db.put_account(sender.bytes, 1 << 80, 0, &.{}) catch @panic("bench: fund");
        var recipient: [20]u8 = @splat(0);
        std.mem.writeInt(u32, recipient[16..20], 0x10_0000 + @as(u32, @intCast(index)), .big);
        const tx: consensus.Eip1559 = .{
            .chain_id = spec.chain_id,
            .nonce = 0,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 1_000,
            .gas_limit = transfer_gas,
            .to = .{ .call = .{ .bytes = recipient } },
            .value = 1,
            .input = &.{},
            .access_list = .empty,
        };
        const envelope = consensus.tx.sign(tx, key) catch @panic("bench: sign");
        s.raws[index] = envelope.encode_to(&s.raw_bytes[index]);
    }
    s.block = .{
        .number = 1,
        .timestamp = 12,
        .beneficiary = @splat(0xfe),
        .gas_limit = 60_000_000,
        .base_fee = 7,
        .prev_randao = @splat(0),
        .parent_hash = @splat(0),
        .parent_beacon_block_root = @splat(0),
        .excess_blob_gas = 0,
    };
    setup_storage = s;
    return s;
}

fn run_execute(iterations: u32) u64 {
    const s = setup();
    var sink: u64 = 0;
    for (0..iterations) |_| {
        const executed = s.executor.execute_block(&s.block, &s.raws, &.{}) catch |err| {
            std.debug.panic("bench: execute_block: {t}", .{err});
        };
        assert(executed.gas_used == transfers * transfer_gas);
        sink +%= executed.state_root[0];
        s.db.rollback() catch @panic("bench: rollback");
    }
    return sink;
}

fn run_execute_parallel(iterations: u32) u64 {
    const s = setup();
    const cpus: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const allocator = std.heap.page_allocator;
    const pool = senders.Pool.create(allocator, @min(cpus -| 1, 7)) catch @panic("bench: pool");
    s.executor.recovery_pool = pool;
    defer {
        s.executor.recovery_pool = null;
        pool.destroy(allocator);
    }
    return run_execute(iterations);
}

fn run_recover(iterations: u32) u64 {
    const s = setup();
    var sink: u64 = 0;
    for (0..iterations) |_| {
        for (s.raws) |raw| {
            const envelope = consensus.Envelope.decode(raw) catch @panic("bench: decode");
            const sender = envelope.recover_sender(consensus.recover_address).?;
            sink +%= sender.bytes[0];
        }
    }
    return sink;
}

pub const cases = [_]Case{
    .{
        .name = "node: execute block, 500 transfers (MB/s = Mgas/s)",
        .iterations = 20,
        .run = run_execute,
        .bytes_per_op = transfers * transfer_gas,
    },
    .{
        .name = "node: execute block, 500 transfers, parallel recovery (Mgas/s)",
        .iterations = 20,
        .run = run_execute_parallel,
        .bytes_per_op = transfers * transfer_gas,
    },
    .{
        .name = "node: recover 500 senders",
        .iterations = 20,
        .run = run_recover,
    },
};

test "bench: cases are well formed" {
    for (cases) |case| {
        assert(case.iterations > 0);
        assert(case.name.len > 0);
    }
}

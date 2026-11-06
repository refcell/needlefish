//! Builder slot latency at Base's native 200 ms cadence (Denim), measured through the
//! payload `Service` and `BlockBuilder`: per slot, `forkchoiceUpdated` with attributes
//! (`send_new_payload`), the build tick (attribute deposits, then best pool transactions
//! until the gas limit, the pool end, or the 150 ms cutoff on the real clock), and
//! `getPayload` (`resolve`). The sequencer then imports its own block through the Engine
//! API (timed separately) and the pool is refilled outside the clock.
//!
//! The pool always holds one transaction per sender: plain transfers (tip 1) plus calls
//! into a storage-heavy contract (tip 2, 16 SSTOREs each), more gas than one 60 M block,
//! so every block is built to the gas limit. Reports p50/p99/max latency, transactions and
//! gas per block.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const txpool = @import("../../execution/txpool/root.zig");
const engine_module = @import("../../execution/engine/root.zig");
const node = @import("../../execution/node/root.zig");
const bench = @import("../../testing/bench.zig");
const best_txs = @import("best_txs.zig");
const builder_module = @import("builder.zig");
const service_module = @import("service.zig");

const Chain = node.chain.Chain;
const StateDb = node.state_db.StateDb;
const Executor = node.executor.Executor;
const base_time = node.base_time;
const Engine = engine_module.Engine(Chain);
const types = engine_module.types;
const B256 = primitives.B256;

pub const name = "builder: 200 ms slot FCU+build+seal+getPayload, full 60M gas";

const transfer_senders = 3000;
const call_senders = 64;
const senders = transfer_senders + call_senders;
const slots_warmup = 4;
const slots_measured = 64;
const slots = slots_warmup + slots_measured;
const gas_limit: u64 = 60_000_000;
const transfer_gas: u64 = 21_000;
const call_gas: u64 = 400_000;
const storage_contract: [20]u8 = @splat(0xc5);

/// Writes `NUMBER` into 16 consecutive slots starting at calldata word 0.
/// `base = calldataload(0); for (c = 16; c != 0;) { c -= 1; sstore(base + c, number) }`
const storage_code = [_]u8{
    0x60, 0x00, 0x35, 0x60, 0x10, // PUSH1 0 CALLDATALOAD PUSH1 16
    0x5b, 0x80, 0x15, 0x60, 0x17, 0x57, // loop: JUMPDEST DUP1 ISZERO PUSH1 end JUMPI
    0x60, 0x01, 0x90, 0x03, // PUSH1 1 SWAP1 SUB
    0x43, 0x82, 0x82, 0x01, 0x55, // NUMBER DUP3 DUP3 ADD SSTORE
    0x60, 0x05, 0x56, // PUSH1 loop JUMP
    0x5b, 0x00, // end: JUMPDEST STOP
};

comptime {
    assert(storage_code[0x05] == 0x5b and storage_code[0x17] == 0x5b);
    assert(senders <= 4096); // One pooled transaction per sender fits the default pool.
    assert(transfer_senders * transfer_gas > gas_limit);
}

const denim_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    for (0..@backingInt(chainspec.Upgrade.denim) + 1) |index| result.upgrades[index] = 0;
    break :blk result;
};

const genesis_extra_data = [_]u8{ 1, 0, 0, 0, 250, 0, 0, 0, 6 } ++ @as([8]u8, @splat(0));

/// The real monotonic clock, as the builder `Clock` and the service's tick time base.
const RealClock = struct {
    io: std.Io,

    pub fn now_ns(clock: *RealClock) u64 {
        const now = std.Io.Clock.awake.now(clock.io).nanoseconds;
        assert(now >= 0);
        return @intCast(now);
    }
};

const Samples = struct {
    latency_ns: [slots_measured]u64 = undefined,
    /// This thread's CPU time over the same span (the build is single-threaded): stable
    /// on a loaded machine, where wall time includes waiting for a core.
    latency_cpu_ns: [slots_measured]u64 = undefined,
    import_ns: [slots_measured]u64 = undefined,
    transactions: [slots_measured]u64 = undefined,
    gas_used: [slots_measured]u64 = undefined,
    cut_off: u32 = 0,
};

const Setup = struct {
    db: StateDb,
    executor: Executor,
    pool: txpool.Pool,
    chain: Chain,
    engine: Engine,
    cache: best_txs.RejectionCache,
    builder: builder_module.BlockBuilder,
    clock: RealClock,
    service: service_module.Service,
    addresses: [senders]primitives.Address,
    raw_buffer: [512]u8,
    calldata: [2][consensus.base_time.calldata_length]u8,
    deposit_bytes: [2][256]u8,
    deposits: [2][]const u8,
    samples: Samples,
};

fn sender_key(index: u32) [32]u8 {
    var key: [32]u8 = @splat(0);
    std.mem.writeInt(u32, key[28..32], index + 1, .big);
    return key;
}

fn init_state(s: *Setup, allocator: std.mem.Allocator) !void {
    s.db = try StateDb.init(allocator, .{});
    for (0..senders) |index| {
        const key = sender_key(@intCast(index));
        s.addresses[index] = consensus.signature.address_from_private(key).?;
        try s.db.put_account(s.addresses[index].bytes, 1 << 80, 0, &.{});
    }
    try s.db.put_account(storage_contract, 0, 0, &storage_code);
    const proxy = base_time.proxy_address;
    try s.db.put_account(proxy, 0, 0, &base_time.test_proxy_code);
    const admin = base_time.address_word(base_time.proxy_admin);
    try s.db.put_storage(proxy, base_time.admin_slot, admin);
    assert(s.db.get_account(storage_contract) != null);
}

fn init_chain(s: *Setup, allocator: std.mem.Allocator) !void {
    // As `base node` configures it: parallel sender recovery.
    const cpus: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    s.executor = try Executor.init(allocator, &denim_spec, &s.db, .{
        .recovery_threads = @min(cpus -| 1, 7),
    });
    s.pool = try txpool.Pool.init(allocator, .{ .block_gas_limit = gas_limit });
    var genesis: consensus.Header = .{
        .state_root = .{ .bytes = try s.db.root() },
        .gas_limit = gas_limit,
        .base_fee_per_gas = 1_000_000_000,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .zero,
        .requests_hash = consensus.block.empty_requests_hash,
    };
    genesis.extra_data = &genesis_extra_data;
    s.chain = try Chain.init(allocator, &denim_spec, &s.db, &s.executor, &genesis, .{});
    s.chain.pool = &s.pool;
    s.engine = Engine.init(&denim_spec, &s.chain);
    assert(s.chain.denim_schedule() != null);
}

fn init_builder(s: *Setup, allocator: std.mem.Allocator, io: std.Io) !void {
    s.cache = try best_txs.RejectionCache.init(allocator, 1024, 10 * std.time.ns_per_s);
    s.builder = try builder_module.BlockBuilder.init(allocator, &s.cache, .{});
    s.clock = .{ .io = io };
    const clock = builder_module.Clock.of(RealClock, &s.clock);
    s.service = try service_module.Service.init(&s.builder, &s.chain, clock, .{});
    s.samples = .{};
    assert(s.builder.state == .idle);
}

/// Signs and pools the next transaction of every sender with nothing pooled (untimed).
fn refill(s: *Setup) !void {
    for (0..senders) |index| {
        const address = s.addresses[index];
        if (s.pool.sender_of(address) != null) continue;
        const account = s.db.get_account(address.bytes).?;
        const is_call = index >= transfer_senders;
        var input: [32]u8 = @splat(0);
        std.mem.writeInt(u32, input[0..4], @intCast(index), .big);
        var recipient: [20]u8 = @splat(0);
        std.mem.writeInt(u32, recipient[16..20], 0x10_0000 + @as(u32, @intCast(index)), .big);
        const tx: consensus.Eip1559 = .{
            .chain_id = denim_spec.chain_id,
            .nonce = account.nonce,
            .max_priority_fee_per_gas = if (is_call) 2 else 1,
            .max_fee_per_gas = 100_000_000_000,
            .gas_limit = if (is_call) call_gas else transfer_gas,
            .to = .{ .call = .{ .bytes = if (is_call) storage_contract else recipient } },
            .value = if (is_call) 0 else 1,
            .input = if (is_call) &input else &.{},
            .access_list = .empty,
        };
        const envelope = try consensus.tx.sign(tx, sender_key(@intCast(index)));
        _ = try s.pool.add(.{
            .hash = envelope.hash(),
            .sender = address,
            .nonce = tx.nonce,
            .tx_type = 2,
            .gas_limit = tx.gas_limit,
            .max_fee_per_gas = tx.max_fee_per_gas,
            .max_priority_fee_per_gas = tx.max_priority_fee_per_gas,
            .value = tx.value,
            .raw = envelope.encode_to(&s.raw_buffer),
        }, .{ .nonce = account.nonce, .balance = account.balance });
    }
    assert(s.pool.count() == senders);
}

/// The sequencer's attributes for block `number`: L1-info stand-in and BaseTime deposits.
fn attributes_for(s: *Setup, number: u64) payload.PayloadAttributes {
    const parts = s.chain.denim_schedule().?.parts(number);
    s.calldata[0] = consensus.base_time.encode_calldata(0);
    s.calldata[1] = consensus.base_time.encode_calldata(parts.millis_part);
    var info = consensus.base_time.deposit(number, &s.calldata[0]);
    info.source_hash = primitives.keccak256(std.mem.asBytes(&number));
    info.to = .{ .call = .{ .bytes = @splat(0x11) } };
    const deposits = [2]consensus.Envelope{
        .{ .deposit = info },
        .{ .deposit = consensus.base_time.deposit(number, &s.calldata[1]) },
    };
    for (deposits, 0..) |envelope, index| {
        s.deposits[index] = envelope.encode_to(&s.deposit_bytes[index]);
    }
    const result: payload.PayloadAttributes = .{
        .timestamp = parts.seconds,
        .prev_randao = .zero,
        .suggested_fee_recipient = .{ .bytes = @splat(0xfe) },
        .withdrawals = &.{},
        .parent_beacon_block_root = .zero,
        .transactions = &s.deposits,
        .no_tx_pool = false,
        .gas_limit = gas_limit,
        .eip1559_params = @splat(0),
        .min_base_fee = 0,
    };
    assert(result.timestamp == parts.seconds);
    return result;
}

/// Imports the sealed block on the sequencer (newPayload, then forkchoiceUpdated).
fn import(s: *Setup, sealed: *const service_module.Payload) !void {
    var execution_payload = engine_module.block.payload_of(
        &sealed.header,
        sealed.block_hash,
        sealed.transactions,
        sealed.withdrawals,
    );
    execution_payload.withdrawals_root = sealed.header.withdrawals_root;
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = sealed.header.parent_beacon_block_root,
        .execution_requests = &.{},
    };
    const timestamp = sealed.header.timestamp;
    const version = types.new_payload_version(&denim_spec, timestamp);
    const status = try s.engine.new_payload(version, &execution_payload, &params);
    if (status.status != .valid) std.debug.panic("bench: import {?s}", .{status.validation_error});
    const choice: types.ForkchoiceState = .{
        .head_block_hash = sealed.block_hash,
        .safe_block_hash = .zero,
        .finalized_block_hash = .zero,
    };
    const choice_version = types.forkchoice_version(&denim_spec, timestamp);
    _ = try s.engine.forkchoice_updated(choice_version, choice, null);
    assert(std.mem.eql(u8, &s.chain.head_hash(), &sealed.block_hash.bytes));
}

fn cpu_ns(io: std.Io) u64 {
    const now = std.Io.Clock.cpu_thread.now(io).nanoseconds;
    assert(now >= 0);
    return @intCast(now);
}

/// One slot: FCU with attributes, build tick, getPayload (timed), then the import (timed
/// separately) and the pool refill (untimed).
fn run_slot(s: *Setup, number: u64) !void {
    try refill(s);
    const attributes = attributes_for(s, number);
    const head = s.chain.head_hash();
    const id: service_module.PayloadId = @bitCast(number);
    const start_cpu_ns = cpu_ns(s.clock.io);
    const start_ns = s.clock.now_ns();
    s.service.tick(start_ns);
    try s.service.send_new_payload(id, head, &attributes);
    s.service.tick(s.clock.now_ns());
    const sealed = try (s.service.resolve(id) orelse return error.UnknownPayload);
    const sealed_ns = s.clock.now_ns();
    const sealed_cpu_ns = cpu_ns(s.clock.io);
    try import(s, &sealed);
    const imported_ns = s.clock.now_ns();
    assert(sealed.header.number == number);
    assert(sealed.header.gas_used <= gas_limit);
    if (number <= slots_warmup) return;
    const index = number - slots_warmup - 1;
    s.samples.latency_ns[index] = sealed_ns - start_ns;
    s.samples.latency_cpu_ns[index] = sealed_cpu_ns -| start_cpu_ns;
    s.samples.import_ns[index] = imported_ns - sealed_ns;
    s.samples.transactions[index] = sealed.transactions.len;
    s.samples.gas_used[index] = sealed.header.gas_used;
    if (sealed.stop == .cutoff) s.samples.cut_off += 1;
}

fn print_percentiles(label: []const u8, unit: []const u8, divisor: f64, samples: []u64) void {
    assert(samples.len > 0);
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    const p50 = samples[samples.len / 2];
    const p99 = samples[(samples.len * 99) / 100];
    const max = samples[samples.len - 1];
    assert(samples[0] <= p50 and p50 <= p99 and p99 <= max);
    std.debug.print("  {s:<24} p50 {d:>10.2} {s}  p99 {d:>10.2} {s}  max {d:>10.2} {s}\n", .{
        label,
        @as(f64, @floatFromInt(p50)) / divisor,
        unit,
        @as(f64, @floatFromInt(p99)) / divisor,
        unit,
        @as(f64, @floatFromInt(max)) / divisor,
        unit,
    });
}

/// Runs the case when `filter` matches its name.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    if (!bench.matches(name, filter)) return;
    const allocator = std.heap.page_allocator;
    const s = allocator.create(Setup) catch @panic("bench: out of memory");
    defer allocator.destroy(s);
    init_state(s, allocator) catch |err| std.debug.panic("bench: state: {t}", .{err});
    init_chain(s, allocator) catch |err| std.debug.panic("bench: chain: {t}", .{err});
    init_builder(s, allocator, io) catch |err| std.debug.panic("bench: builder: {t}", .{err});
    for (1..slots + 1) |number| {
        run_slot(s, number) catch |err| std.debug.panic("bench: slot: {t}", .{err});
    }
    std.debug.print("{s} ({d} slots, {d} cut off)\n", .{ name, slots_measured, s.samples.cut_off });
    print_percentiles("FCU..getPayload", "ms", 1e6, &s.samples.latency_ns);
    print_percentiles("  same, thread cpu", "ms", 1e6, &s.samples.latency_cpu_ns);
    print_percentiles("import (newPayload+FCU)", "ms", 1e6, &s.samples.import_ns);
    print_percentiles("txs/block", "", 1, &s.samples.transactions);
    print_percentiles("gas/block", "Mgas", 1e6, &s.samples.gas_used);
    assert(s.service.active_id() == null);
}

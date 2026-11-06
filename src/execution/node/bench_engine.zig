//! Engine API slot latency at Base's native 200 ms cadence (Denim): one slot is
//! forkchoiceUpdated with attributes (the block is built), getPayload, then the follower's
//! newPayload and forkchoiceUpdated. Every slot carries the L1-info stand-in and BaseTime
//! deposits plus 500 transfers forced through the attributes, so the numbers cover build,
//! seal and import but not pool admission (sender recovery at submit time). Target: well
//! under the 150 ms seal offset.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const txpool = @import("../txpool/root.zig");
const engine_module = @import("../engine/root.zig");
const Case = @import("../../testing/bench.zig").Case;
const StateDb = @import("state_db.zig").StateDb;
const Executor = @import("executor.zig").Executor;
const chain_module = @import("chain.zig");
const base_time = @import("base_time.zig");
const genesis_module = @import("../../common/genesis/root.zig");
const db_module = @import("../db/root.zig");
const SimStorage = @import("../db/storage/sim_storage.zig").SimStorage;
const durable_module = @import("durable.zig");
const service_limits: @import("service.zig").Limits = .{};

const Durable = durable_module.Durable(SimStorage);

const Chain = chain_module.Chain;
const Engine = engine_module.Engine(Chain);
const types = engine_module.types;
const B256 = primitives.B256;

const transfers = 500;
const slots_max = 128;
const raw_size_max = 128;
const transfer_gas: u64 = 21_000;

const denim_spec: chainspec.ChainSpec = blk: {
    var result = chainspec.ChainSpec.presets.base_devnet;
    for (0..@backingInt(chainspec.Upgrade.denim) + 1) |index| result.upgrades[index] = 0;
    break :blk result;
};

const Node = struct {
    db: StateDb,
    executor: Executor,
    pool: txpool.Pool,
    chain: Chain,
    engine: Engine,

    fn init(node: *Node, allocator: std.mem.Allocator) !void {
        node.db = try StateDb.init(allocator, .{});
        for (0..transfers) |index| {
            const sender = consensus.signature.address_from_private(sender_key(@intCast(index))).?;
            try node.db.put_account(sender.bytes, 1 << 80, 0, &.{});
        }
        const proxy = base_time.proxy_address;
        try node.db.put_account(proxy, 0, 0, &base_time.test_proxy_code);
        const admin = base_time.address_word(base_time.proxy_admin);
        try node.db.put_storage(proxy, base_time.admin_slot, admin);
        try node.init_execution(allocator, try node.db.root());
    }

    /// The same node on a durable database over simulated storage (as `--datadir`).
    fn init_durable(node: *Node, allocator: std.mem.Allocator, durable: *Durable) !void {
        node.db = try StateDb.init_shared(allocator, service_limits.state, durable.state());
        try node.init_execution(allocator, try node.db.root());
        node.chain.journal = durable.journal();
    }

    fn init_execution(node: *Node, allocator: std.mem.Allocator, root: [32]u8) !void {
        // As `base node` configures it: parallel sender recovery.
        const cpus: u32 = @intCast(std.Thread.getCpuCount() catch 1);
        node.executor = try Executor.init(allocator, &denim_spec, &node.db, .{
            .recovery_threads = @min(cpus -| 1, 7),
        });
        node.pool = try txpool.Pool.init(allocator, .{});
        var genesis = genesis_header(root);
        const executor = &node.executor;
        node.chain = try Chain.init(allocator, &denim_spec, &node.db, executor, &genesis, .{});
        node.chain.pool = &node.pool;
        node.engine = Engine.init(&denim_spec, &node.chain);
    }
};

fn genesis_header(root: [32]u8) consensus.Header {
    var genesis: consensus.Header = .{
        .state_root = .{ .bytes = root },
        .gas_limit = 60_000_000,
        .base_fee_per_gas = 1_000_000_000,
        .withdrawals_root = primitives.empty_root_hash,
        .blob_gas_used = 0,
        .excess_blob_gas = 0,
        .parent_beacon_block_root = .zero,
        .requests_hash = consensus.block.empty_requests_hash,
    };
    genesis.extra_data = &genesis_extra_data;
    return genesis;
}

const genesis_extra_data = [_]u8{ 1, 0, 0, 0, 250, 0, 0, 0, 6 } ++ @as([8]u8, @splat(0));

const Setup = struct {
    builder: Node,
    follower: Node,
    raw_bytes: [slots_max][transfers + 2][raw_size_max]u8,
    raws: [slots_max][transfers + 2][]const u8,
    calldata: [slots_max][2][consensus.base_time.calldata_length]u8,
    head: B256,
    slot: u32,
};

var setup_storage: ?*Setup = null;
var durable_setup_storage: ?*Setup = null;

/// A durable node's database over simulated (in-memory) storage.
const Side = struct {
    sim: SimStorage,
    durable: *Durable,

    /// Ticks until every journaled entry is durable.
    fn settle(side: *Side) void {
        var ticks: u32 = 0;
        while (!side.durable.database.idle()) : (ticks += 1) {
            if (ticks == 1_000_000) @panic("bench: storage never idle");
            side.sim.tick();
            side.durable.poll();
        }
    }
};

var sides: [2]Side = undefined;
var genesis_accounts: [transfers + 1]genesis_module.state.Account = undefined;
var proxy_storage: [1]genesis_module.state.StorageSlot = undefined;

fn durable_genesis() genesis_module.Genesis {
    for (genesis_accounts[0..transfers], 0..) |*account, index| {
        const key = sender_key(@intCast(index));
        const sender = consensus.signature.address_from_private(key).?;
        account.* = .{ .address = sender, .balance = 1 << 80 };
    }
    const admin = base_time.address_word(base_time.proxy_admin);
    var slot_key: primitives.B256 = undefined;
    std.mem.writeInt(u256, &slot_key.bytes, base_time.admin_slot, .big);
    proxy_storage[0] = .{ .key = slot_key, .value = admin };
    genesis_accounts[transfers] = .{
        .address = .{ .bytes = base_time.proxy_address },
        .code = &base_time.test_proxy_code,
        .storage = &proxy_storage,
    };
    return .{ .accounts = &genesis_accounts };
}

/// The `--datadir` database layout `base node` derives from its default limits.
fn durable_config() db_module.database.Config {
    const limits = &service_limits;
    var config = limits.durable;
    config.state = StateDb.state_config(limits.state);
    config.changeset = .{
        .accounts_max = limits.state.block_accounts_max,
        .storage_max = limits.state.block_slots_max,
        .codes_max = limits.state.block_codes_max,
        .code_bytes_max = limits.state.block_code_bytes_max,
    };
    return config;
}

fn open_side(side: *Side, node: *Node, allocator: std.mem.Allocator) !void {
    const config = durable_config();
    const size_bytes = config.engine.size_bytes();
    side.sim = try SimStorage.init(allocator, .{ .size_bytes = size_bytes, .seed = 1 });
    const parsed = durable_genesis();
    const root = try parsed.compute_state_root(allocator);
    const header = genesis_header(root.bytes);
    side.durable = try Durable.create(allocator, &side.sim, config, header.hash().bytes, 1);
    side.durable.start();
    var ticks: u32 = 0;
    while (side.durable.phase != .ready) : (ticks += 1) {
        if (side.durable.phase == .failed or ticks == 1_000_000) return error.OpenFailed;
        side.sim.tick();
        side.durable.poll();
    }
    _ = try side.durable.bootstrap(allocator, &parsed, &header);
    side.settle();
    try node.init_durable(allocator, side.durable);
    assert(node.chain.genesis_hash[0] == header.hash().bytes[0]);
}

fn durable_setup() *Setup {
    if (durable_setup_storage) |ready| return ready;
    const allocator = std.heap.page_allocator;
    const s = allocator.create(Setup) catch @panic("bench: out of memory");
    open_side(&sides[0], &s.builder, allocator) catch @panic("bench: builder durable");
    open_side(&sides[1], &s.follower, allocator) catch @panic("bench: follower durable");
    const schedule = s.builder.chain.denim_schedule().?;
    for (0..slots_max) |slot| sign_slot(s, @intCast(slot), schedule);
    s.head = .{ .bytes = s.builder.chain.genesis_hash };
    s.slot = 0;
    durable_setup_storage = s;
    return s;
}

/// Durable slots: the in-memory slot plus the journal writes, settled every slot.
fn run_durable_slots(iterations: u32) u64 {
    const s = durable_setup();
    for (0..iterations) |_| {
        run_slot(s) catch |err| std.debug.panic("bench: slot: {t}", .{err});
        for (&sides) |*side| side.settle();
    }
    return s.slot;
}

fn sender_key(index: u32) [32]u8 {
    var key: [32]u8 = @splat(0);
    std.mem.writeInt(u32, key[28..32], index + 1, .big);
    return key;
}

fn setup() *Setup {
    if (setup_storage) |ready| return ready;
    const allocator = std.heap.page_allocator;
    const s = allocator.create(Setup) catch @panic("bench: out of memory");
    s.builder.init(allocator) catch @panic("bench: builder init");
    s.follower.init(allocator) catch @panic("bench: follower init");
    const schedule = s.builder.chain.denim_schedule().?;
    for (0..slots_max) |slot| sign_slot(s, @intCast(slot), schedule);
    s.head = .{ .bytes = s.builder.chain.genesis_hash };
    s.slot = 0;
    setup_storage = s;
    return s;
}

fn sign_slot(s: *Setup, slot: u32, schedule: base_time.Schedule) void {
    const number: u64 = slot + 1;
    s.calldata[slot][0] = consensus.base_time.encode_calldata(0);
    s.calldata[slot][1] = consensus.base_time.encode_calldata(schedule.parts(number).millis_part);
    var info = consensus.base_time.deposit(number, &s.calldata[slot][0]);
    info.source_hash = primitives.keccak256(std.mem.asBytes(&number));
    info.to = .{ .call = .{ .bytes = @splat(0x11) } };
    const deposits = [2]consensus.Envelope{
        .{ .deposit = info },
        .{ .deposit = consensus.base_time.deposit(number, &s.calldata[slot][1]) },
    };
    for (deposits, 0..) |envelope, index| {
        s.raws[slot][index] = envelope.encode_to(&s.raw_bytes[slot][index]);
    }
    for (0..transfers) |index| {
        var recipient: [20]u8 = @splat(0);
        std.mem.writeInt(u32, recipient[16..20], 0x10_0000 + @as(u32, @intCast(index)), .big);
        const tx: consensus.Eip1559 = .{
            .chain_id = denim_spec.chain_id,
            .nonce = slot,
            .max_priority_fee_per_gas = 1,
            .max_fee_per_gas = 100_000_000_000,
            .gas_limit = transfer_gas,
            .to = .{ .call = .{ .bytes = recipient } },
            .value = 1,
            .input = &.{},
            .access_list = .empty,
        };
        const envelope = consensus.tx.sign(tx, sender_key(@intCast(index))) catch
            @panic("bench: sign");
        s.raws[slot][2 + index] = envelope.encode_to(&s.raw_bytes[slot][2 + index]);
    }
}

/// One 200 ms slot: build and seal on the builder, import and adopt on the follower.
fn run_slot(s: *Setup) !void {
    if (s.slot == slots_max) @panic("bench: pre-signed slots exhausted");
    const number: u64 = s.slot + 1;
    const parts = s.builder.chain.denim_schedule().?.parts(number);
    var attrs: payload.PayloadAttributes = .{
        .timestamp = parts.seconds,
        .prev_randao = .zero,
        .suggested_fee_recipient = .{ .bytes = @splat(0xfe) },
        .withdrawals = &.{},
        .parent_beacon_block_root = .zero,
        .transactions = &s.raws[s.slot],
        .no_tx_pool = true,
        .gas_limit = 60_000_000,
        .eip1559_params = @splat(0),
        .min_base_fee = 0,
    };
    const version = types.forkchoice_version(&denim_spec, parts.seconds);
    const state = forkchoice(s.head);
    const updated = try s.builder.engine.forkchoice_updated(version, state, &attrs);
    const get_version = types.get_payload_version(&denim_spec, parts.seconds);
    const built = try s.builder.engine.get_payload(get_version, updated.payload_id.?);
    var transactions: [transfers + 2][]const u8 = undefined;
    var withdrawals: [chain_module.withdrawals_max]payload.Withdrawal = undefined;
    const block = built.block_hash.bytes;
    const p = s.builder.chain.payload_of(block, &transactions, &withdrawals).?;
    assert(p.transactions.len == transfers + 2);
    const params: types.NewPayloadParams = .{
        .versioned_hashes = &.{},
        .parent_beacon_block_root = .zero,
        .execution_requests = &.{},
    };
    const new_version = types.new_payload_version(&denim_spec, p.timestamp);
    const imported = try s.follower.engine.new_payload(new_version, &p, &params);
    if (imported.status != .valid) {
        std.debug.panic("bench: import {?s}", .{imported.validation_error});
    }
    _ = try s.builder.engine.forkchoice_updated(version, forkchoice(built.block_hash), null);
    _ = try s.follower.engine.forkchoice_updated(version, forkchoice(built.block_hash), null);
    s.head = built.block_hash;
    s.slot += 1;
}

fn forkchoice(head: B256) types.ForkchoiceState {
    return .{ .head_block_hash = head, .safe_block_hash = .zero, .finalized_block_hash = .zero };
}

fn run_slots(iterations: u32) u64 {
    const s = setup();
    for (0..iterations) |_| {
        run_slot(s) catch |err| std.debug.panic("bench: slot: {t}", .{err});
    }
    return s.slot;
}

pub const cases = [_]Case{ .{
    .name = "node: 200 ms slot, FCU+getPayload+newPayload+FCU, 500 transfers (Mgas/s)",
    .iterations = 1,
    .run = run_slots,
    .bytes_per_op = transfers * transfer_gas,
}, .{
    .name = "node: 200 ms slot, durable (sim storage), 500 transfers (Mgas/s)",
    .iterations = 1,
    .run = run_durable_slots,
    .bytes_per_op = transfers * transfer_gas,
} };

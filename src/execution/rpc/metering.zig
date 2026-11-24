//! `base_meterBlockByHash` / `base_meterBlockByNumber` (base/base `metering` crate):
//! re-executes a canonical block on its parent's state and reports how long sender
//! recovery and each transaction's execution took, in microseconds.
//!
//! The parent state is read through `HistoryDatabase` (the history window bounds which
//! blocks can be metered) and every change is discarded. Times come from the service's
//! monotonic clock (`Api.clock`); without one they are zero. `stateRootTimeUs` is zero:
//! the root is not recomputed over historical reads. `totalTimeUs` is the sum of the parts.
//!
//! `base_meterBundle({txs})` runs raw transactions on the head state in the next block
//! (base fee at most 5 Mwei, each sender starting at its first transaction's nonce) and
//! reports each one's gas, fees (`gasUsed * maxFeePerGas`, all counted as coinbase diff, as
//! base/base) and time. `opcodeGas` holds what base/base's node meters by default (every
//! precompile, no opcodes, no pseudo-opcodes; see `Meter`). Not ported: metering opcodes
//! named by `--metering.metered-opcodes`, and the BaseTime update before the first
//! transaction.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const node = @import("../node/root.zig");
const evm = @import("../evm/root.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;
const Executor = node.executor.Executor;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "base_meterBlockByHash", .handler = meter_by_hash },
    .{ .name = "base_meterBlockByNumber", .handler = meter_by_number },
    .{ .name = "base_meterBundle", .handler = meter_bundle },
};

/// Transactions per metered bundle.
pub const bundle_transactions_max = 256;
/// base/base caps the simulated base fee at 5 Mwei.
pub const bundle_base_fee_max: u64 = 5_000_000;

fn meter_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.hash();
    try call.params.finish();
    try meter(api, call, hash);
}

fn meter_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    const hash = eth.resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.fail(rpc.code.server_error, "block not found"),
        else => return err,
    };
    try meter(api, call, hash);
}

fn zero_ns(_: *anyopaque) u64 {
    return 0;
}

var zero_context: u8 = 0;
const zero_clock: Executor.Clock = .{ .context = &zero_context, .now_ns = zero_ns };

/// The per-transaction buffers at the head of the scratch (the proofs sit at its tail).
const Buffers = struct { ns: []u64, gas: []u64 };

fn carve(api: *Api, count: usize) ?Buffers {
    const tail = eth.proof_tail_offset(api) orelse return null;
    const bytes = count * 2 * @sizeOf(u64);
    const start = std.mem.alignForward(usize, @intFromPtr(api.scratch.ptr), @alignOf(u64)) -
        @intFromPtr(api.scratch.ptr);
    if (start + bytes > tail) return null;
    const words: [*]u64 = @ptrCast(@alignCast(api.scratch[start..].ptr));
    return .{ .ns = words[0..count], .gas = words[count .. 2 * count] };
}

fn meter(api: *Api, call: *Call, hash: Hash) HandlerError!void {
    const chain = api.chain;
    var stored = chain.record(hash) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
    const header = stored.header;
    if (header.number <= chain.genesis_number) {
        return call.fail(rpc.code.invalid_params, "genesis has no parent");
    }
    var count: usize = 0;
    while (!stored.transactions.is_empty()) : (count += 1) {
        assert(count < chain.transactions_buffer.len); // Stored blocks fit the executor.
        chain.transactions_buffer[count] = stored.transactions.bytes() catch unreachable;
    }
    const transactions = chain.transactions_buffer[0..count];
    const buffers = carve(api, count) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const offset = eth.proof_tail_offset(api).?; // Checked by `carve`.
    const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
    var history: node.HistoryDatabase = .{
        .chain = chain,
        .hash = header.parent_hash.bytes,
        .number = header.number - 1,
        .account_proof = &proofs.account,
        .storage_proof = &proofs.storage,
    };
    const executor = chain.executor;
    const session = executor.session_begin(history.database());
    defer executor.session_end(session);
    const env = node.chain.env_of(&header);
    const clock = api.clock orelse zero_clock;
    const ns = buffers.ns;
    const gas = buffers.gas;
    const metered = executor.meter_block(&env, transactions, clock, ns, gas) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return call.fail(rpc.code.server_error, @errorName(err));
    };
    if (metered.gas_used != header.gas_used) {
        return call.fail(rpc.code.internal_error, "re-execution diverged from the block");
    }
    try write(call.writer, hash, header.number, metered, transactions, buffers);
}

fn write(
    w: *json.Writer,
    hash: Hash,
    number: u64,
    metered: Executor.Metered,
    transactions: []const []const u8,
    buffers: Buffers,
) json.Writer.WriteError!void {
    const recovery_us = metered.signer_recovery_ns / std.time.ns_per_us;
    const execution_us = metered.execution_ns / std.time.ns_per_us;
    try w.begin_object();
    try w.key("blockHash");
    try w.data(&hash);
    try w.key("blockNumber");
    try w.integer(number);
    const totals = [_]struct { []const u8, u64 }{
        .{ "signerRecoveryTimeUs", recovery_us },
        .{ "executionTimeUs", execution_us },
        .{ "stateRootTimeUs", 0 },
        .{ "totalTimeUs", recovery_us + execution_us },
    };
    for (totals) |total| {
        try w.key(total[0]);
        try w.integer(total[1]);
    }
    try w.key("transactions");
    try w.begin_array();
    for (transactions, buffers.ns[0..transactions.len], buffers.gas[0..transactions.len]) |
        raw,
        ns,
        gas,
    | {
        try w.begin_object();
        try w.key("txHash");
        try w.data(&primitives.keccak256(raw).bytes);
        try w.key("gasUsed");
        try w.integer(gas);
        try w.key("executionTimeUs");
        try w.integer(ns / std.time.ns_per_us);
        try w.end_object();
    }
    try w.end_array();
    try w.end_object();
}

/// base/base `PRECOMPILES` (metering `meter.rs`): EIP-7910 names by address.
const precompile_names = [_]struct { u16, []const u8 }{
    .{ 0x01, "ECREC" },               .{ 0x02, "SHA256" },
    .{ 0x03, "RIPEMD160" },           .{ 0x04, "ID" },
    .{ 0x05, "MODEXP" },              .{ 0x06, "BN254_ADD" },
    .{ 0x07, "BN254_MUL" },           .{ 0x08, "BN254_PAIRING" },
    .{ 0x09, "BLAKE2F" },             .{ 0x0a, "KZG_POINT_EVALUATION" },
    .{ 0x0b, "BLS12_G1ADD" },         .{ 0x0c, "BLS12_G1MSM" },
    .{ 0x0d, "BLS12_G2ADD" },         .{ 0x0e, "BLS12_G2MSM" },
    .{ 0x0f, "BLS12_PAIRING_CHECK" }, .{ 0x10, "BLS12_MAP_FP_TO_G1" },
    .{ 0x11, "BLS12_MAP_FP2_TO_G2" }, .{ 0x100, "P256VERIFY" },
};

/// The name base/base meters a call to `address` under: its node meters every precompile
/// (`MeteredOpcodes::with_all_precompiles`), the Beryl ones from Beryl on (`for_spec`).
/// Whether the precompile is active is not checked.
pub fn precompile_name(upgrade: ?evm.op.Upgrade, address: [20]u8) ?[]const u8 {
    if (std.mem.allEqual(u8, address[0..18], 0)) {
        const number = std.mem.readInt(u16, address[18..20], .big);
        for (precompile_names) |entry| if (entry[0] == number) return entry[1];
        return null;
    }
    const active = upgrade orelse return null;
    if (!active.at_least(.beryl)) return null;
    const native = evm.native;
    if (std.mem.eql(u8, &address, &native.b20_factory.address)) return "BERYL_B20_FACTORY";
    if (std.mem.eql(u8, &address, &native.activation.address)) {
        return "BERYL_ACTIVATION_REGISTRY";
    }
    if (std.mem.eql(u8, &address, &native.policy.address)) return "BERYL_POLICY_REGISTRY";
    const variant = native.b20_variant(address) orelse return null;
    return switch (variant) {
        .asset => "BERYL_B20_ASSET",
        .stablecoin => "BERYL_B20_STABLECOIN",
    };
}

/// One `opcodeGas` entry: the calls to one metered precompile in one transaction.
pub const PrecompileGas = struct {
    transaction: u32,
    address: [20]u8,
    name: []const u8,
    count: u64,
    gas_used: u64,

    fn less(_: void, a: PrecompileGas, b: PrecompileGas) bool {
        if (a.transaction != b.transaction) return a.transaction < b.transaction;
        return std.mem.order(u8, &a.address, &b.address) == .lt;
    }
};

/// `opcodeGas` entries of one bundle.
pub const precompile_gas_max = 4096;
/// Fewer entries than this is not a useful buffer: the scratch is misconfigured.
const precompile_gas_min = 64;
/// Frames open at once: the call depth bound and the SELFDESTRUCT pseudo-frame.
const open_max = 1026;

/// base/base `MeteringInspector`'s precompile half (`call_end`): every CALL-family frame
/// whose callee (revm's `bytecode_address`) is metered counts once with the gas it spent
/// (its limit less what it returned: all of it on a halt), the transaction's own top call
/// and calls that fail before running (depth, balance) included. Fed by the evm's frame
/// hooks over the bundle's transactions only; each top frame starts the next transaction.
pub const Meter = struct {
    machine: *const evm.evm.Evm,
    open: []Open,
    open_count: u32 = 0,
    entries: []PrecompileGas,
    len: u32 = 0,
    /// Top frames seen: the current transaction's index plus one.
    transactions: u32 = 0,
    /// More entries than `entries` holds.
    overflow: bool = false,

    const Open = struct { callee: [20]u8, gas: u64, call: bool };

    /// Carves the buffers out of `space`; null when it is too small.
    pub fn init(space: []u8, machine: *const evm.evm.Evm) ?Meter {
        var fixed: std.heap.FixedBufferAllocator = .init(space);
        const allocator = fixed.allocator();
        const open = allocator.alloc(Open, open_max) catch return null;
        // Room for the alignment of the entries.
        const room = (space.len - fixed.end_index) -| @alignOf(PrecompileGas);
        const count = @min(precompile_gas_max, room / @sizeOf(PrecompileGas));
        if (count < precompile_gas_min) return null;
        const entries = allocator.alloc(PrecompileGas, count) catch return null;
        assert(fixed.end_index <= space.len);
        return .{ .machine = machine, .open = open, .entries = entries };
    }

    pub fn tracer(recorder: *Meter) evm.evm.Tracer {
        return .{ .context = recorder, .enter = on_enter, .exit = on_exit, .log = on_log };
    }

    /// The entries by transaction, then address (base/base sorts by address, then name).
    pub fn sorted(recorder: *Meter) []const PrecompileGas {
        const entries = recorder.entries[0..recorder.len];
        std.sort.pdq(PrecompileGas, entries, {}, PrecompileGas.less);
        return entries;
    }

    fn of(context: *anyopaque) *Meter {
        return @ptrCast(@alignCast(context));
    }

    fn on_enter(context: *anyopaque, frame: evm.evm.TraceFrame) void {
        const recorder = of(context);
        assert(recorder.open_count < open_max);
        if (frame.depth == 0) {
            assert(recorder.open_count == 0);
            recorder.transactions += 1;
        }
        const call = switch (frame.kind) {
            .call, .callcode, .delegatecall, .staticcall => true,
            .create, .create2, .selfdestruct => false,
        };
        const opened: Open = .{ .callee = frame.to, .gas = frame.gas, .call = call };
        recorder.open[recorder.open_count] = opened;
        recorder.open_count += 1;
    }

    fn on_exit(context: *anyopaque, outcome: evm.evm.Outcome) void {
        const recorder = of(context);
        assert(recorder.open_count > 0);
        assert(recorder.transactions > 0);
        recorder.open_count -= 1;
        const opened = recorder.open[recorder.open_count];
        if (!opened.call) return;
        const name = precompile_name(recorder.machine.op_upgrade(), opened.callee) orelse return;
        recorder.add(opened.callee, name, opened.gas -| outcome.gas_remaining);
    }

    fn on_log(_: *anyopaque, _: [20]u8, _: []const [32]u8, _: []const u8) void {}

    fn add(recorder: *Meter, address: [20]u8, name: []const u8, gas_used: u64) void {
        const transaction = recorder.transactions - 1;
        var index = recorder.len;
        while (index > 0) {
            index -= 1;
            const entry = &recorder.entries[index];
            if (entry.transaction != transaction) break;
            if (!std.mem.eql(u8, &entry.address, &address)) continue;
            entry.count +|= 1;
            entry.gas_used +|= gas_used;
            return;
        }
        if (recorder.len == recorder.entries.len) {
            recorder.overflow = true;
            return;
        }
        recorder.entries[recorder.len] = .{
            .transaction = transaction,
            .address = address,
            .name = name,
            .count = 1,
            .gas_used = gas_used,
        };
        recorder.len += 1;
    }
};

const Bundle = struct {
    transactions: [bundle_transactions_max][]const u8 = undefined,
    count: u32 = 0,
};

/// Parses `{"txs":[raw, ...]}`; the transactions decode into `space`.
fn parse_bundle(raw: []const u8, space: []u8, bundle: *Bundle) HandlerError!void {
    var scanner = json.Scanner.init(raw);
    if ((scanner.next() catch return error.InvalidParams).tag != .object_begin) {
        return error.InvalidParams;
    }
    var used: usize = 0;
    var found = false;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = scanner.next() catch return error.InvalidParams;
        if (!std.mem.eql(u8, name.bytes, "txs")) return error.InvalidParams;
        if (value.tag != .array_begin) return error.InvalidParams;
        found = true;
        while (true) {
            const item = scanner.next() catch return error.InvalidParams;
            if (item.tag == .array_end) break;
            if (item.tag != .string) return error.InvalidParams;
            if (bundle.count == bundle_transactions_max) return error.InvalidParams;
            const tx = json.parse_data(item.bytes, space[used..]) catch return error.InvalidParams;
            if (tx.len == 0 or tx[0] == 0x7e) return error.InvalidParams;
            used += tx.len;
            bundle.transactions[bundle.count] = tx;
            bundle.count += 1;
        }
    }
    if (!found) return error.InvalidParams;
    assert(used <= space.len);
}

fn meter_bundle(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    var bundle: Bundle = .{};
    const half = api.scratch.len / 2;
    try parse_bundle(raw, api.scratch[0..half], &bundle);
    const transactions = bundle.transactions[0..bundle.count];
    try check_bundle(api, call, transactions);
    var ns: [bundle_transactions_max]u64 = undefined;
    var gas: [bundle_transactions_max]u64 = undefined;
    const chain = api.chain;
    chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const header = eth.head_header(api);
    var env = node.chain.env_of(&header);
    env.number += 1;
    env.timestamp += 1;
    env.parent_hash = header.hash().bytes;
    env.base_fee = @min(env.base_fee, bundle_base_fee_max);
    const executor = chain.executor;
    const session = executor.session_begin(null);
    defer executor.session_end(session);
    const clock = api.clock orelse zero_clock;
    // The transactions are parsed into the first half of the scratch.
    var precompile_meter = Meter.init(api.scratch[half..], executor.machine) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    const tracer = precompile_meter.tracer();
    _ = executor.meter_bundle(&env, transactions, clock, &ns, &gas, &tracer) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    if (precompile_meter.overflow) {
        return call.fail(rpc.code.internal_error, "opcode gas exceeds its buffer");
    }
    assert(precompile_meter.transactions == transactions.len);
    const senders = executor.senders[0..transactions.len];
    const metered: Metered = .{ .ns = &ns, .gas = &gas, .precompiles = precompile_meter.sorted() };
    try write_bundle(call.writer, header.number, transactions, senders, metered);
}

/// base/base `ParsedBundle::try_from`: every transaction decodes exactly as a Base
/// envelope (no blob transactions) and recovers its signer, or the bundle is invalid params.
fn check_bundle(api: *Api, call: *Call, transactions: []const []const u8) HandlerError!void {
    assert(transactions.len <= bundle_transactions_max);
    const recoverer = api.chain.executor.recoverer;
    for (transactions) |raw| {
        const envelope = consensus.Envelope.decode(raw) catch null;
        if (envelope == null or envelope.? == .eip4844) {
            const message = "Failed to parse bundle: Failed to decode transaction";
            return call.fail(rpc.code.invalid_params, message);
        }
        switch (envelope.?) {
            .deposit, .eip8130 => {},
            else => if (envelope.?.recover_sender(recoverer) == null) {
                const message = "Failed to parse bundle: " ++
                    "Failed to convert transaction to recovered";
                return call.fail(rpc.code.invalid_params, message);
            },
        }
    }
}

/// What `base_meterBundle` measured of each transaction.
const Metered = struct {
    ns: []const u64,
    gas: []const u64,
    /// By transaction, then address.
    precompiles: []const PrecompileGas,
};

fn field_u256(w: *json.Writer, name: []const u8, value: u256) json.Writer.WriteError!void {
    try w.key(name);
    try w.quantity(value);
}

fn write_bundle(
    w: *json.Writer,
    state_block: u64,
    transactions: []const []const u8,
    senders: []const ?primitives.Address,
    metered: Metered,
) json.Writer.WriteError!void {
    const ns = metered.ns;
    const gas = metered.gas;
    var hashes: [bundle_transactions_max * 32]u8 = undefined;
    var total_gas: u64 = 0;
    var total_fees: u256 = 0;
    var total_us: u64 = 0;
    for (transactions, 0..) |raw, index| {
        hashes[index * 32 ..][0..32].* = primitives.keccak256(raw).bytes;
        const envelope = consensus.Envelope.decode(raw) catch unreachable; // Executed.
        total_gas += gas[index];
        total_fees += @as(u256, gas[index]) * envelope.max_fee_per_gas();
        total_us += ns[index] / std.time.ns_per_us;
    }
    try w.begin_object();
    try field_u256(w, "bundleGasPrice", if (total_gas > 0) total_fees / total_gas else 0);
    try w.key("bundleHash");
    try w.data(&primitives.keccak256(hashes[0 .. transactions.len * 32]).bytes);
    try field_u256(w, "coinbaseDiff", total_fees);
    try field_u256(w, "ethSentToCoinbase", 0);
    try field_u256(w, "gasFees", total_fees);
    try w.key("results");
    try w.begin_array();
    var precompiles = metered.precompiles;
    for (transactions, senders, 0..) |raw, sender, index| {
        var count: usize = 0;
        while (count < precompiles.len and precompiles[count].transaction == index) count += 1;
        const result: Result = .{
            .sender = sender,
            .time_ns = ns[index],
            .used = gas[index],
            .precompiles = precompiles[0..count],
        };
        try write_result(w, raw, result);
        precompiles = precompiles[count..];
    }
    assert(precompiles.len == 0);
    try w.end_array();
    try w.key("stateBlockNumber");
    try w.integer(state_block);
    try w.key("totalGasUsed");
    try w.integer(total_gas);
    try w.key("totalExecutionTimeUs");
    try w.integer(total_us);
    try w.end_object();
}

const Result = struct {
    sender: ?primitives.Address,
    time_ns: u64,
    used: u64,
    /// The transaction's `opcodeGas`, sorted by address.
    precompiles: []const PrecompileGas,
};

fn write_result(w: *json.Writer, raw: []const u8, result: Result) json.Writer.WriteError!void {
    const sender = result.sender;
    const used = result.used;
    const envelope = consensus.Envelope.decode(raw) catch unreachable; // Executed.
    const price = envelope.max_fee_per_gas();
    const fees = @as(u256, used) * price;
    try w.begin_object();
    try field_u256(w, "coinbaseDiff", fees);
    try field_u256(w, "ethSentToCoinbase", 0);
    try w.key("fromAddress");
    try w.data(&(sender orelse primitives.Address.zero).bytes);
    try field_u256(w, "gasFees", fees);
    try field_u256(w, "gasPrice", price);
    try w.key("gasUsed");
    try w.integer(used);
    try w.key("toAddress");
    if (envelope.kind().to()) |to| try w.data(&to.bytes) else try w.null_value();
    try w.key("txHash");
    try w.data(&primitives.keccak256(raw).bytes);
    try field_u256(w, "value", envelope.value());
    try w.key("executionTimeUs");
    try w.integer(result.time_ns / std.time.ns_per_us);
    // base/base skips an empty `opcodeGas`.
    if (result.precompiles.len > 0) {
        try w.key("opcodeGas");
        try w.begin_array();
        for (result.precompiles) |entry| {
            try w.begin_object();
            try w.key("contractAddress");
            try w.data(&entry.address);
            try w.key("opcode");
            try w.string(entry.name);
            try w.key("count");
            try w.integer(entry.count);
            try w.key("gasUsed");
            try w.integer(entry.gas_used);
            try w.end_object();
        }
        try w.end_array();
    }
    try w.end_object();
}

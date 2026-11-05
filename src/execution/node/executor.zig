//! Block executor: applies a block's transactions through the evm against `StateDb`,
//! with the pre-block system calls (EIP-4788 beacon roots, EIP-2935 block hashes),
//! withdrawals (gwei credits), Prague execution requests (EIP-7002 / EIP-7251 system
//! calls), receipts, logs bloom, blob gas and the post-state root.
//!
//! L1 (Ethereum) semantics only for now: OP deposit transactions and L1 fee charging
//! wait on the evm lane's OP Stack item, so L2 blocks with deposits are rejected.
//! Memory: one scratch arena sized at init and reset per block; no other allocation.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const ordered = @import("../trie/ordered.zig");
const chainspec = @import("../chainspec/root.zig");
const payload = @import("../payload/root.zig");
const StateDb = @import("state_db.zig").StateDb;

const Address = [20]u8;
const Hash = [32]u8;
const Envelope = consensus.Envelope;
const Receipt = consensus.Receipt;
const TxEnv = evm.transaction.TxEnv;

pub const system_address: Address = hex20("fffffffffffffffffffffffffffffffffffffffe");
pub const beacon_roots_address: Address = hex20("000f3df6d732807ef1319fb7b8bb8522d0beac02");
pub const history_storage_address: Address = hex20("0000f90827f1c53a10cb7a02335b175320002935");
pub const withdrawal_request_address: Address = hex20("00000961ef480eb55e80d19ad83579a64c007002");
pub const consolidation_request_address: Address =
    hex20("0000bbddc7ce488642fb579f8b00f3a590007251");
pub const system_call_gas: u64 = 30_000_000;
const gas_per_blob: u64 = 1 << 17;

fn hex20(comptime text: []const u8) Address {
    return comptime primitives.hex.decode_array(20, text) catch unreachable;
}

pub const Config = struct {
    scratch_bytes: u32 = 64 << 20,
    transactions_max: u32 = 1 << 14,
    evm: evm.env.Config = .{},
    limits: evm.state.Limits = .{},
};

/// Block context, from a header or from payload attributes when building.
pub const BlockEnv = struct {
    number: u64,
    timestamp: u64,
    beneficiary: Address,
    gas_limit: u64,
    base_fee: u64,
    prev_randao: Hash,
    parent_hash: Hash,
    parent_beacon_block_root: ?Hash = null,
    excess_blob_gas: ?u64 = null,
};

pub const Error = evm.evm.Error || @import("state_db.zig").Error || error{
    ScratchFull,
    TooManyTransactions,
    InvalidTransaction,
    BlockGasExceeded,
    BlobGasExceeded,
    TxTypeNotSupported,
    SystemCallFailed,
};

pub const Executed = struct {
    receipts: []const Receipt,
    gas_used: u64,
    blob_gas_used: u64,
    logs_bloom: primitives.Bloom,
    receipts_root: Hash,
    state_root: Hash,
    /// Prague+: EIP-7685 requests (`type || data`, empty data omitted).
    requests: []const []const u8,
    /// Index of the failing transaction when `execute_block` returns InvalidTransaction.
    invalid_index: ?u32 = null,
};

pub const Executor = struct {
    spec: *const chainspec.ChainSpec,
    db: *StateDb,
    state: *evm.State,
    machine: *evm.Evm,
    scratch: []u8,
    arena: std.heap.FixedBufferAllocator,
    transactions_max: u32,
    recoverer: consensus.Recoverer,
    /// Index of the last transaction rejected by `execute_block`.
    invalid_index: ?u32 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        spec: *const chainspec.ChainSpec,
        db: *StateDb,
        config: Config,
    ) !Executor {
        assert(config.scratch_bytes > 0);
        const state = try allocator.create(evm.State);
        errdefer allocator.destroy(state);
        state.* = try evm.State.init(allocator, db.database(), config.limits);
        errdefer state.deinit(allocator);
        const machine = try allocator.create(evm.Evm);
        errdefer allocator.destroy(machine);
        var evm_config = config.evm;
        evm_config.chain_id = spec.chain_id;
        machine.* = try evm.Evm.init(allocator, evm_config, state);
        errdefer machine.deinit(allocator);
        const scratch = try allocator.alloc(u8, config.scratch_bytes);
        return .{
            .spec = spec,
            .db = db,
            .state = state,
            .machine = machine,
            .scratch = scratch,
            .arena = std.heap.FixedBufferAllocator.init(scratch),
            .transactions_max = config.transactions_max,
            .recoverer = consensus.recover_address,
        };
    }

    pub fn deinit(executor: *Executor, allocator: std.mem.Allocator) void {
        allocator.free(executor.scratch);
        executor.machine.deinit(allocator);
        allocator.destroy(executor.machine);
        executor.state.deinit(allocator);
        allocator.destroy(executor.state);
        executor.* = undefined;
    }

    /// Executes and commits a block. On error the state cache is discarded and the
    /// database is unchanged. Results borrow the scratch arena until the next call.
    pub fn execute_block(
        executor: *Executor,
        block: *const BlockEnv,
        transactions: []const []const u8,
        withdrawals: ?[]const payload.Withdrawal,
    ) Error!Executed {
        executor.arena.reset();
        executor.invalid_index = null;
        if (transactions.len > executor.transactions_max) return error.TooManyTransactions;
        const fork = evm_fork(executor.spec.spec_at(block.timestamp));
        errdefer executor.discard();
        executor.set_block_env(block);
        try executor.pre_block_calls(fork, block);
        const receipts = try executor.alloc(Receipt, transactions.len);
        var gas_used: u64 = 0;
        var blob_gas_used: u64 = 0;
        var bloom = primitives.Bloom.zero;
        for (transactions, 0..) |raw, index| {
            executor.invalid_index = @intCast(index);
            const result =
                try executor.apply_transaction(fork, block, raw, gas_used, blob_gas_used);
            gas_used += result.gas_used;
            blob_gas_used += result.blob_gas_used;
            receipts[index] = result.receipt;
            receipts[index].cumulative_gas_used = gas_used;
            bloom_or(&bloom, &result.receipt.logs_bloom);
        }
        executor.invalid_index = null;
        if (withdrawals) |list| try executor.apply_withdrawals(fork, list);
        const requests = try executor.post_block_requests(fork);
        try executor.db.commit(executor.state);
        return .{
            .receipts = receipts,
            .gas_used = gas_used,
            .blob_gas_used = blob_gas_used,
            .logs_bloom = bloom,
            .receipts_root = try executor.receipts_root(receipts),
            .state_root = try executor.db.root(),
            .requests = requests,
        };
    }

    /// Drops every uncommitted change (failed block).
    fn discard(executor: *Executor) void {
        executor.state.accounts.clearRetainingCapacity();
        executor.state.slots.clearRetainingCapacity();
        executor.state.code_store_len = 0;
        executor.state.begin_transaction();
    }

    fn set_block_env(executor: *Executor, block: *const BlockEnv) void {
        var blob_base_fee: u256 = 1;
        if (executor.spec.blob_params_at(block.timestamp)) |params| {
            blob_base_fee = params.base_fee(block.excess_blob_gas orelse 0);
        }
        executor.machine.block = .{
            .number = block.number,
            .coinbase = block.beneficiary,
            .timestamp = block.timestamp,
            .gas_limit = block.gas_limit,
            .base_fee = block.base_fee,
            .prevrandao = block.prev_randao,
            .blob_base_fee = blob_base_fee,
        };
    }

    fn alloc(executor: *Executor, comptime T: type, n: usize) Error![]T {
        return executor.arena.allocator().alloc(T, n) catch error.ScratchFull;
    }

    const Applied = struct { receipt: Receipt, gas_used: u64, blob_gas_used: u64 };

    fn apply_transaction(
        executor: *Executor,
        fork: evm.Fork,
        block: *const BlockEnv,
        raw: []const u8,
        gas_used: u64,
        blob_gas_used: u64,
    ) Error!Applied {
        const envelope = Envelope.decode(raw) catch return error.InvalidTransaction;
        if (envelope == .deposit) return error.TxTypeNotSupported;
        const tx = try executor.tx_env(envelope);
        if (gas_used + tx.gas_limit > block.gas_limit) return error.BlockGasExceeded;
        const blob_gas = @as(u64, tx.blob_hashes.len) * gas_per_blob;
        if (blob_gas > 0) {
            const params = executor.spec.blob_params_at(block.timestamp) orelse
                return error.TxTypeNotSupported;
            if (blob_gas_used + blob_gas > params.max_blob_gas()) return error.BlobGasExceeded;
        }
        const result = try evm.transaction.transact(executor.machine, fork, &tx);
        const executed = switch (result) {
            .invalid => return error.InvalidTransaction,
            .executed => |executed| executed,
        };
        const logs = try executor.encode_logs(executed.logs);
        return .{
            .receipt = .{
                .tx_type = envelope.tx_type(),
                .status = executed.status == .success,
                .cumulative_gas_used = 0,
                .logs_bloom = logs.bloom(),
                .logs = logs,
            },
            .gas_used = executed.gas_used,
            .blob_gas_used = blob_gas,
        };
    }

    /// Converts a decoded envelope into the evm's transaction environment.
    fn tx_env(executor: *Executor, envelope: Envelope) Error!TxEnv {
        const sender = envelope.recover_sender(executor.recoverer) orelse
            return error.InvalidTransaction;
        var tx: TxEnv = .{
            .tx_type = @fromBackingInt(@intCast(@backingInt(envelope.tx_type()))),
            .caller = sender.bytes,
            .gas_limit = envelope.gas_limit(),
            .gas_price = envelope.max_fee_per_gas(),
            .to = if (envelope.kind().to()) |to| to.bytes else null,
            .value = envelope.value(),
            .data = envelope.input(),
            .nonce = envelope.nonce().?,
            .chain_id = envelope.chain_id(),
            .access_list = try executor.access_list(envelope.access_list()),
        };
        if (envelope != .legacy and envelope != .eip2930) {
            tx.gas_priority_fee = envelope.max_priority_fee_per_gas();
        }
        switch (envelope) {
            .eip4844 => |signed| {
                tx.max_fee_per_blob_gas = signed.tx.max_fee_per_blob_gas;
                tx.blob_hashes = try executor.hashes(signed.tx.blob_versioned_hashes);
            },
            .eip7702 => |signed| {
                tx.authorization_list = try executor.authorizations(signed.tx.authorization_list);
            },
            else => {},
        }
        return tx;
    }

    fn access_list(
        executor: *Executor,
        list: consensus.AccessList,
    ) Error![]const evm.transaction.AccessListItem {
        const items = try executor.alloc(evm.transaction.AccessListItem, list.address_count);
        var it = list.iterator();
        var index: usize = 0;
        while (it.next()) |item| : (index += 1) {
            items[index] = .{
                .address = item.address.bytes,
                .storage_keys = try executor.hashes(item.storage_keys),
            };
        }
        assert(index == items.len);
        return items;
    }

    fn hashes(executor: *Executor, list: consensus.HashList) Error![]const Hash {
        const out = try executor.alloc(Hash, list.count());
        for (out, 0..) |*hash, index| hash.* = list.get(index).bytes;
        return out;
    }

    fn authorizations(
        executor: *Executor,
        list: consensus.AuthorizationList,
    ) Error![]const evm.transaction.Authorization {
        const out = try executor.alloc(evm.transaction.Authorization, list.count);
        var it = list.iterator();
        var index: usize = 0;
        while (it.next()) |authorization| : (index += 1) {
            const authority = authorization.recover_authority(executor.recoverer);
            out[index] = .{
                .chain_id = authorization.chain_id,
                .address = authorization.address.bytes,
                .nonce = authorization.nonce,
                .authority = if (authority) |a| a.bytes else null,
            };
        }
        assert(index == out.len);
        return out;
    }

    /// RLP-encodes evm logs as a receipt `Logs` payload in the scratch arena.
    fn encode_logs(executor: *Executor, logs: []const evm.state.Log) Error!consensus.Logs {
        var total: usize = 0;
        for (logs) |*log| total += log_length(log);
        const buffer = try executor.alloc(u8, total);
        var encoder = rlp.Encoder.init(buffer);
        for (logs) |*log| {
            encoder.list_header(log_payload_length(log));
            encoder.bytes(&log.address);
            encoder.list_header(@as(usize, log.topic_count) * 33);
            for (log.topic_slice()) |*topic| encoder.bytes(topic);
            encoder.bytes(log.data);
        }
        assert(encoder.written().len == total);
        return .{ .payload = encoder.written(), .count = @intCast(logs.len) };
    }

    fn pre_block_calls(executor: *Executor, fork: evm.Fork, block: *const BlockEnv) Error!void {
        if (fork.at_least(.cancun)) {
            if (block.parent_beacon_block_root) |root| {
                _ = try executor.system_call(fork, beacon_roots_address, &root);
            }
        }
        if (fork.at_least(.prague) and block.number > 0) {
            _ = try executor.system_call(fork, history_storage_address, &block.parent_hash);
        }
    }

    /// Calls a system contract as SYSTEM_ADDRESS with no fee; null when it has no code.
    fn system_call(
        executor: *Executor,
        fork: evm.Fork,
        target: Address,
        input: []const u8,
    ) Error!?[]const u8 {
        const account = try executor.state.load(target);
        if (!account.info.has_code()) return null;
        executor.state.begin_transaction();
        executor.machine.tx = .{ .origin = system_address, .gas_price = 0 };
        const outcome = try executor.machine.execute(fork, .{
            .kind = .call,
            .caller = system_address,
            .target = target,
            .input = input,
            .gas_limit = system_call_gas,
        });
        if (outcome.status != .success) return error.SystemCallFailed;
        finalize(executor.state, fork);
        return outcome.output;
    }

    fn apply_withdrawals(
        executor: *Executor,
        fork: evm.Fork,
        withdrawals: []const payload.Withdrawal,
    ) Error!void {
        executor.state.begin_transaction();
        for (withdrawals) |w| {
            if (w.amount_gwei == 0) continue;
            const account = try executor.state.load(w.address.bytes);
            const amount = @as(u256, w.amount_gwei) * 1_000_000_000;
            try executor.state.set_balance(account, account.info.balance + amount);
            try executor.state.touch(account);
        }
        finalize(executor.state, fork);
    }

    /// EIP-7002 withdrawal and EIP-7251 consolidation requests (Prague+). Deposit
    /// requests (EIP-6110) need a deposit contract, which the dev chain does not have.
    fn post_block_requests(executor: *Executor, fork: evm.Fork) Error![]const []const u8 {
        if (!fork.at_least(.prague)) return &.{};
        const out = try executor.alloc([]const u8, 2);
        var count: usize = 0;
        const sources = [_]struct { u8, Address }{
            .{ 0x01, withdrawal_request_address },
            .{ 0x02, consolidation_request_address },
        };
        for (sources) |source| {
            const data = try executor.system_call(fork, source[1], &.{}) orelse continue;
            if (data.len == 0) continue;
            const request = try executor.alloc(u8, data.len + 1);
            request[0] = source[0];
            @memcpy(request[1..], data);
            out[count] = request;
            count += 1;
        }
        return out[0..count];
    }

    fn receipts_root(executor: *Executor, receipts: []const Receipt) Error!Hash {
        const items = try executor.alloc([]const u8, receipts.len);
        for (receipts, 0..) |receipt, index| {
            const buffer = try executor.alloc(u8, receipt.encoded_length());
            items[index] = receipt.encode_to(buffer);
        }
        return ordered.ordered_trie_root(items);
    }
};

fn log_payload_length(log: *const evm.state.Log) usize {
    return rlp.bytes_length(&log.address) + rlp.list_length(@as(usize, log.topic_count) * 33) +
        rlp.bytes_length(log.data);
}

fn log_length(log: *const evm.state.Log) usize {
    return rlp.list_length(log_payload_length(log));
}

fn finalize(state: *evm.State, fork: evm.Fork) void {
    switch (fork) {
        inline else => |comptime_fork| state.finalize_transaction(comptime_fork),
    }
}

fn bloom_or(into: *primitives.Bloom, from: *const primitives.Bloom) void {
    for (&into.bytes, from.bytes) |*a, b| a.* |= b;
}

pub fn evm_fork(spec: chainspec.Spec) evm.Fork {
    return switch (spec) {
        .paris => .merge,
        .shanghai => .shanghai,
        .cancun => .cancun,
        .prague => .prague,
        .osaka => .osaka,
    };
}

test {
    _ = @import("executor_test.zig");
}

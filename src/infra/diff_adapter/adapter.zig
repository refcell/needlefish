//! Executes one differential-execution `Case` on the node's block execution path over a
//! stateless witness.
//!
//! The pre-state is a `SparseState` loaded from the case's trie nodes and codes and rooted
//! at the parent's state root; BLOCKHASH is served from the hash-linked ancestor headers.
//! Blocks run through the node's `Executor` (`begin_block`, `apply` per transaction,
//! `finish_block`: system calls, OP fee handling, transition-block changes, commit and the
//! post-state root), exactly as `Chain` builds and imports them. Headers are sealed with
//! `chain.seal_header`, the function the node's builder seals with.
//!
//! Build mode skips a transaction that fails validity checks (the builder's rejection set:
//! invalid, over the block's remaining gas or DA budget, unsupported type) and reports it.
//! Validate mode runs the engine and chain checks (`validate_new_payload`,
//! `ensure_well_formed`, number and timestamp linkage, `check_parent`, the Denim schedule,
//! `check_results`); a rejected transaction makes the block invalid.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const chains = @import("../../common/chains/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const db = @import("../../execution/db/root.zig");
const engine = @import("../../execution/engine/root.zig");
const evm = @import("../../execution/evm/root.zig");
const payload = @import("../../execution/payload/root.zig");
const node_executor = @import("../../execution/node/executor.zig");
const chain_module = @import("../../execution/node/chain.zig");
const base_time = @import("../../execution/node/base_time.zig");
const request = @import("request.zig");

const SparseState = db.witness.SparseState;
const Executor = node_executor.Executor;
const Header = consensus.Header;
const Case = request.Case;
const Hash = [32]u8;
const Address = [20]u8;

pub const l2_to_l1_message_passer: Address =
    primitives.hex.decode_array(20, "4200000000000000000000000000000000000016") catch unreachable;

/// A transaction build mode skipped.
pub const Rejected = struct { index: u32, reason: []const u8 };

/// One storage slot whose value changed, with its new value.
pub const Slot = struct { slot: u256, value: u256 };

/// An account whose nonce, balance, code hash or storage changed; `info` null: deleted.
pub const PostAccount = struct {
    address: Address,
    info: ?db.AccountInfo,
    storage: []const Slot,
    /// Existed before the block, was destroyed in it, and exists after it: its storage
    /// starts from empty, and `storage` lists only the slots written since.
    wiped: bool = false,
};

pub const Outcome = struct {
    valid: bool = true,
    invalid_reason: ?[]const u8 = null,
    rejected: []const Rejected = &.{},
    /// The header sealed from the inputs and the execution results; null when the block
    /// as a whole could not be executed (`valid` is then false).
    header: ?Header = null,
    computed_base_fee: ?u64 = null,
    receipts: []const consensus.Receipt = &.{},
    post: []const PostAccount = &.{},
};

/// What the witness lacked in the last run, for the `WitnessIncomplete` error text.
pub const Missing = struct {
    pub const Phase = enum { pre_block, transaction, post_block };
    pub const Item = union(enum) {
        none,
        node: Hash,
        code: Hash,
        block_hash: u64,
    };
    pub const Key = union(enum) {
        none,
        account: Address,
        slot: struct { address: Address, slot: u256 },
    };

    /// The first trie node, code or ancestor the witness lacked.
    item: Item = .none,
    /// The first account or slot read that failed for it (execution), if any.
    key: Key = .none,
    phase: Phase = .pre_block,
    /// The transaction being applied (`phase == .transaction`).
    transaction: u32 = 0,
    /// The post-state commit and root computation failed (not an execution read).
    committing: bool = false,

    /// One line naming what is missing and where it was needed.
    pub fn describe(missing: *const Missing, out: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (missing.item) {
            .none => try out.writeAll("witness incomplete"),
            .node => |hash| try out.print("witness lacks trie node 0x{x}", .{&hash}),
            .code => |hash| try out.print("witness lacks code 0x{x}", .{&hash}),
            .block_hash => |number| try out.print("ancestors lack block {d}", .{number}),
        }
        switch (missing.key) {
            .none => {},
            .account => |address| try out.print(", reading account 0x{x}", .{&address}),
            .slot => |key| try out.print(", reading slot 0x{x:0>64} of 0x{x}", .{
                key.slot,
                &key.address,
            }),
        }
        if (missing.committing) return out.writeAll(", computing the post-state root");
        switch (missing.phase) {
            .pre_block => try out.writeAll(", before the first transaction"),
            .transaction => try out.print(", executing transaction {d}", .{missing.transaction}),
            .post_block => try out.writeAll(", after the last transaction"),
        }
    }
};

/// Adapter-level failures: the response is `ok: false` with this error.
pub const Error = error{
    /// The witness lacks a trie node, code or ancestor the block needs.
    WitnessIncomplete,
    /// The ancestors are not a hash-linked chain ending at the parent.
    InvalidAncestors,
    OutOfMemory,
    Internal,
};

const rejected_errors = [_]anyerror{
    error.InvalidTransaction,
    error.BlockGasExceeded,
    error.BlobGasExceeded,
    error.TxTypeNotSupported,
};

/// Long-lived: the executor and changeset are reused (their caches are reset per case);
/// the sparse state is rebuilt per case, sized to its witness.
pub const Adapter = struct {
    spec: *const chainspec.ChainSpec,
    allocator: std.mem.Allocator,
    executor: Executor,
    changeset: db.Changeset,
    sparse: SparseState,
    sparse_ready: bool = false,
    /// What the witness lacked in the last run.
    missing: Missing = .{},
    schedule: ?base_time.Schedule,
    /// Accounts the last commit recreated after destroying them in the block (storage
    /// cleared, present at the end).
    destroyed: std.AutoHashMapUnmanaged(Address, void) = .empty,
    /// File system access for `trie` mode's databases (its directory); without it trie
    /// requests fail.
    io: ?std.Io = null,

    pub const changeset_config: db.changeset.Config = .{
        .accounts_max = 1 << 16,
        .storage_max = 1 << 18,
        .codes_max = 1 << 12,
        .code_bytes_max = 64 << 20,
    };

    /// The adapter must not move after `init` (the executor's backend points at it).
    pub fn init(self: *Adapter, allocator: std.mem.Allocator) !void {
        const spec = &chainspec.ChainSpec.presets.base_mainnet;
        self.* = .{
            .spec = spec,
            .allocator = allocator,
            .executor = undefined,
            .changeset = try db.Changeset.init(allocator, changeset_config),
            .sparse = undefined,
            .schedule = chain_module.denim_schedule_of(spec, 0, chains.mainnet.genesis_l2_time),
        };
        errdefer self.changeset.deinit(allocator);
        try self.destroyed.ensureTotalCapacity(allocator, changeset_config.accounts_max);
        errdefer self.destroyed.deinit(allocator);
        const backend: node_executor.Backend = .{
            .context = self,
            .database = self.database(),
            .commit = backend_commit,
            .root = backend_root,
        };
        self.executor = try Executor.init_backend(allocator, spec, backend, .{
            .state_gas_basis = node_executor.default_state_gas_basis,
        });
        assert(self.schedule != null);
    }

    pub fn deinit(self: *Adapter) void {
        if (self.sparse_ready) self.sparse.deinit(self.allocator);
        self.executor.deinit(self.allocator);
        self.changeset.deinit(self.allocator);
        self.destroyed.deinit(self.allocator);
        self.* = undefined;
    }

    /// Runs `case`. Results borrow `arena` and the executor's scratch until the next run.
    pub fn run(self: *Adapter, arena: std.mem.Allocator, case: *const Case) Error!Outcome {
        self.missing = .{};
        try self.load(case);
        self.executor.abort_block();
        self.executor.state.reset(self.database());
        var outcome: Outcome = .{ .computed_base_fee = next_base_fee(self.spec, case) };
        self.execute(arena, case, &outcome) catch |err| return self.failure(err);
        if (self.sparse.incomplete) return error.WitnessIncomplete;
        if (case.mode == .validate) {
            // The first failed check in import order (header checks before execution).
            if (self.validate(case, &outcome)) |reason| {
                outcome.valid = false;
                outcome.invalid_reason = reason;
            }
            outcome.rejected = &.{};
        }
        assert(outcome.valid or outcome.invalid_reason != null);
        return outcome;
    }

    /// Classifies an execution error: missing witness data, or an adapter failure.
    fn failure(self: *Adapter, err: anyerror) Error {
        if (self.sparse.incomplete) return error.WitnessIncomplete;
        return switch (err) {
            error.WitnessIncomplete, error.DatabaseFailure => error.WitnessIncomplete,
            error.OutOfMemory => error.OutOfMemory,
            else => blk: {
                std.log.err("diff adapter: execution failed: {t}", .{err});
                break :blk error.Internal;
            },
        };
    }

    /// Rebuilds the sparse state from the case's witness and ancestors.
    fn load(self: *Adapter, case: *const Case) Error!void {
        if (self.sparse_ready) self.sparse.deinit(self.allocator);
        self.sparse_ready = false;
        self.sparse = SparseState.init(self.allocator, sparse_config(case)) catch
            return error.OutOfMemory;
        self.sparse_ready = true;
        self.sparse.reset(case.parent.state_root.bytes, .{
            .number = case.parent.number,
            .hash = case.parent_hash,
        });
        for (case.nodes) |bytes| self.sparse.add_node(bytes) catch return error.Internal;
        for (case.codes) |code| self.sparse.add_code(code) catch return error.Internal;
        var index = case.ancestors.len;
        while (index > 0) {
            index -= 1;
            self.sparse.add_header(case.ancestors[index]) catch return error.InvalidAncestors;
        }
        self.sparse.verify_headers() catch return error.InvalidAncestors;
        self.sparse.set_fallback(.{
            .context = self,
            .node = missing_node,
            .code = missing_code,
            .block_hash = missing_block_hash,
        });
        assert(self.sparse.headers_len == case.ancestors.len);
    }

    fn execute(
        self: *Adapter,
        arena: std.mem.Allocator,
        case: *const Case,
        outcome: *Outcome,
    ) anyerror!void {
        const env = chain_module.env_of(&case.header);
        const executor = &self.executor;
        var building = executor.begin_block(&env) catch |err| {
            if (is_witness_error(self, err)) return err;
            return block_failure(outcome, err);
        };
        var included: std.ArrayList([]const u8) = .empty;
        var rejected: std.ArrayList(Rejected) = .empty;
        self.missing.phase = .transaction;
        for (case.transactions, 0..) |raw, index| {
            self.missing.transaction = @intCast(index);
            executor.apply(&building, raw) catch |err| {
                if (!is_rejection(err)) {
                    executor.abort_block();
                    return err;
                }
                const entry: Rejected = .{ .index = @intCast(index), .reason = @errorName(err) };
                try rejected.append(arena, entry);
                evm.coverage.transaction(tx_type_of(raw), entry.reason);
                continue;
            };
            try included.append(arena, raw);
            const status = building.receipts[building.count - 1].status;
            evm.coverage.transaction(tx_type_of(raw), if (status) "ok" else "failed");
        }
        assert(building.count == included.items.len);
        self.missing.phase = .post_block;
        const withdrawals = withdrawals_of(self.spec, &case.header);
        const executed = executor.finish_block(&building, withdrawals) catch |err| {
            if (is_witness_error(self, err)) return err;
            return block_failure(outcome, err);
        };
        outcome.rejected = rejected.items;
        if (case.mode == .validate and rejected.items.len > 0) {
            outcome.valid = false;
            outcome.invalid_reason = try std.fmt.allocPrint(arena, "transaction {d}: {s}", .{
                rejected.items[0].index,
                rejected.items[0].reason,
            });
        }
        outcome.receipts = try arena.dupe(consensus.Receipt, executed.receipts);
        try self.seal(case, included.items, withdrawals, &executed, outcome);
        outcome.post = try self.post_accounts(arena);
    }

    fn seal(
        self: *Adapter,
        case: *const Case,
        transactions: []const []const u8,
        withdrawals: ?[]const payload.Withdrawal,
        executed: *const node_executor.Executed,
        outcome: *Outcome,
    ) anyerror!void {
        var header = inputs_of(&case.header);
        const root = try self.message_passer_root(&header);
        chain_module.seal_header(self.spec, &header, transactions, withdrawals, executed, root);
        outcome.header = header;
        assert(header.number == case.header.number);
    }

    /// The L2ToL1MessagePasser storage root of the post-state (Isthmus+), else zero.
    fn message_passer_root(self: *Adapter, header: *const Header) anyerror!Hash {
        if (!self.spec.is_upgrade_active(.isthmus, header.timestamp)) return @splat(0);
        return self.sparse.account_storage_root(l2_to_l1_message_passer);
    }

    /// The engine and chain checks of the canonical block: the first failure, else null.
    /// The EIP-2718 type byte (0 for a legacy RLP list, 0xff for empty bytes).
    fn tx_type_of(raw: []const u8) u8 {
        if (raw.len == 0) return 0xff;
        return if (raw[0] < 0x80) raw[0] else 0;
    }

    fn validate(self: *Adapter, case: *const Case, outcome: *const Outcome) ?[]const u8 {
        const spec = self.spec;
        const canonical = &case.header;
        const version = engine.types.new_payload_version(spec, canonical.timestamp);
        const p = payload_of(spec, case);
        const params = params_of(spec, canonical);
        engine.types.validate_new_payload(spec, version, &p, &params) catch |err| {
            return @errorName(err);
        };
        const imported = engine.block.ensure_well_formed(spec, &p, &params) catch |err| {
            return @errorName(err);
        };
        if (imported.number != case.parent.number + 1) return "invalid block number";
        if (!spec.timestamp_follows(case.parent.timestamp, imported.timestamp)) {
            return "timestamp not after parent";
        }
        if (chain_module.check_parent(spec, &case.parent, &imported)) |reason| return reason;
        const transactions = p.transactions;
        const schedule = self.schedule;
        const subsecond = chain_module.check_subsecond_schedule(schedule, &imported, transactions);
        if (subsecond) |reason| return reason;
        if (!outcome.valid) return outcome.invalid_reason;
        const sealed = outcome.header orelse return "block not executed";
        const executed: node_executor.Executed = .{
            .receipts = outcome.receipts,
            .gas_used = sealed.gas_used,
            .blob_gas_used = sealed.blob_gas_used orelse 0,
            .logs_bloom = sealed.logs_bloom,
            .receipts_root = sealed.receipts_root.bytes,
            .state_root = sealed.state_root.bytes,
            .requests = &.{},
        };
        const root = if (sealed.withdrawals_root) |r| r.bytes else @as(Hash, @splat(0));
        return chain_module.check_results(spec, &imported, &executed, root);
    }

    /// Every account and slot the block changed, merged by address from the changeset of
    /// the last commit (sorted by address, then slot).
    fn post_accounts(self: *Adapter, arena: std.mem.Allocator) anyerror![]const PostAccount {
        const accounts = self.changeset.account_changes();
        const slots = self.changeset.storage_changes();
        var out: std.ArrayList(PostAccount) = .empty;
        var account_index: usize = 0;
        var slot_index: usize = 0;
        while (account_index < accounts.len or slot_index < slots.len) {
            const address = next_address(accounts, account_index, slots, slot_index);
            var info: ?db.AccountInfo = null;
            var changed = false;
            var existed = true;
            if (account_index < accounts.len and eql(&accounts[account_index].address, &address)) {
                const change = accounts[account_index];
                info = change.new;
                existed = change.old != null;
                changed = !same_info(change.old, change.new);
                account_index += 1;
            } else {
                info = try self.sparse.basic(address);
            }
            const first = slot_index;
            while (slot_index < slots.len and eql(&slots[slot_index].address, &address)) {
                slot_index += 1;
            }
            const storage = try arena.alloc(Slot, if (info == null) 0 else slot_index - first);
            // base/base: `original_info.is_some() && was_destroyed() && info.is_some()`.
            const wiped = existed and info != null and self.destroyed.contains(address);
            for (storage, slots[first..][0..storage.len]) |*slot, change| {
                slot.* = .{ .slot = change.slot, .value = change.new };
            }
            if (!changed and storage.len == 0 and !wiped) continue;
            try out.append(arena, .{
                .address = address,
                .info = info,
                .storage = storage,
                .wiped = wiped,
            });
        }
        assert(account_index == accounts.len and slot_index == slots.len);
        return out.items;
    }

    const logging_vtable: evm.state.Database.VTable = .{
        .basic = database_basic,
        .code_by_hash = database_code_by_hash,
        .storage = database_storage,
        .block_hash = database_block_hash,
    };

    /// The sparse state's evm `Database`, logging the key of every read the witness cannot
    /// serve.
    fn database(self: *Adapter) evm.state.Database {
        return .{ .context = self, .vtable = &logging_vtable };
    }

    fn inner(context: *anyopaque) evm.state.Database {
        const self: *Adapter = @ptrCast(@alignCast(context));
        return self.sparse.database();
    }

    fn database_basic(
        context: *anyopaque,
        address: evm.Address,
    ) evm.state.Error!?evm.state.AccountInfo {
        return inner(context).basic(address) catch |err| {
            const self: *Adapter = @ptrCast(@alignCast(context));
            if (self.missing.key == .none) self.missing.key = .{ .account = address };
            return err;
        };
    }

    fn database_code_by_hash(context: *anyopaque, hash: evm.B256) evm.state.Error![]const u8 {
        return inner(context).code_by_hash(hash);
    }

    fn database_storage(
        context: *anyopaque,
        address: evm.Address,
        slot: u256,
    ) evm.state.Error!u256 {
        return inner(context).storage(address, slot) catch |err| {
            const self: *Adapter = @ptrCast(@alignCast(context));
            const key: Missing.Key = .{ .slot = .{ .address = address, .slot = slot } };
            if (self.missing.key == .none) self.missing.key = key;
            return err;
        };
    }

    fn database_block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
        return inner(context).block_hash(number);
    }

    // The witness lacks something the block needs: the first such item names the
    // request's `WitnessIncomplete` error.
    fn missing_node(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *Adapter = @ptrCast(@alignCast(context));
        if (self.missing.item == .none) self.missing.item = .{ .node = hash.* };
        return null;
    }

    fn missing_code(context: *anyopaque, hash: *const Hash) ?[]const u8 {
        const self: *Adapter = @ptrCast(@alignCast(context));
        if (self.missing.item == .none) self.missing.item = .{ .code = hash.* };
        return null;
    }

    fn missing_block_hash(context: *anyopaque, number: u64) ?Hash {
        const self: *Adapter = @ptrCast(@alignCast(context));
        if (self.missing.item == .none) self.missing.item = .{ .block_hash = number };
        return null;
    }

    fn backend_commit(
        context: *anyopaque,
        state: *evm.State,
    ) node_executor.BackendError!void {
        const self: *Adapter = @ptrCast(@alignCast(context));
        self.destroyed.clearRetainingCapacity();
        for (state.touched_accounts()) |account| {
            // Storage is cleared only by a destruction (SELFDESTRUCT or EIP-161 removal).
            if (!account.storage_cleared or !account.in_database) continue;
            if (self.destroyed.count() == changeset_config.accounts_max) {
                return error.StateUnavailable;
            }
            self.destroyed.putAssumeCapacity(account.address, {});
        }
        self.sparse.apply_evm(state, &self.changeset) catch |err| {
            if (err == error.WitnessIncomplete) {
                self.sparse.incomplete = true;
                if (self.missing.key == .none) self.missing.committing = true;
            }
            return error.StateUnavailable;
        };
        state.accounts.clearRetainingCapacity();
        state.slots.clearRetainingCapacity();
        state.code_store_len = 0;
    }

    fn backend_root(context: *anyopaque) node_executor.BackendError!Hash {
        const self: *Adapter = @ptrCast(@alignCast(context));
        return self.sparse.state_root();
    }
};

fn is_rejection(err: anyerror) bool {
    for (rejected_errors) |rejection| {
        if (err == rejection) return true;
    }
    return false;
}

fn is_witness_error(adapter: *const Adapter, err: anyerror) bool {
    return adapter.sparse.incomplete or err == error.DatabaseFailure or
        err == error.StateUnavailable or err == error.OutOfMemory or err == error.ScratchFull;
}

/// The block as a whole cannot be executed (a failed system call, a failed transition).
fn block_failure(outcome: *Outcome, err: anyerror) void {
    outcome.valid = false;
    outcome.invalid_reason = @errorName(err);
    assert(outcome.header == null);
}

fn next_address(
    accounts: []const db.changeset.AccountChange,
    account_index: usize,
    slots: []const db.changeset.StorageChange,
    slot_index: usize,
) Address {
    assert(account_index < accounts.len or slot_index < slots.len);
    if (account_index == accounts.len) return slots[slot_index].address;
    if (slot_index == slots.len) return accounts[account_index].address;
    const a = accounts[account_index].address;
    const b = slots[slot_index].address;
    return if (std.mem.order(u8, &a, &b) == .gt) b else a;
}

fn eql(a: *const Address, b: *const Address) bool {
    return std.mem.eql(u8, a, b);
}

fn same_info(old: ?db.AccountInfo, new: ?db.AccountInfo) bool {
    if (old == null or new == null) return old == null and new == null;
    return old.?.eql(new.?);
}

/// The base fee the parent implies for this block; null when the parent's extra data is
/// invalid or the block's timestamp precedes the parent's.
fn next_base_fee(spec: *const chainspec.ChainSpec, case: *const Case) ?u64 {
    const parent = &case.parent;
    if (case.header.timestamp < parent.timestamp) return null;
    return spec.next_base_fee(.{
        .timestamp = parent.timestamp,
        .gas_used = parent.gas_used,
        .gas_limit = parent.gas_limit,
        .base_fee = parent.base_fee_per_gas orelse 0,
        .blob_gas_used = parent.blob_gas_used orelse 0,
        .excess_blob_gas = parent.excess_blob_gas orelse 0,
        .extra_data = parent.extra_data,
    }, case.header.timestamp) catch null;
}

/// Base blocks carry an empty withdrawals list from Canyon on.
fn withdrawals_of(
    spec: *const chainspec.ChainSpec,
    header: *const Header,
) ?[]const payload.Withdrawal {
    if (!spec.is_ethereum_fork_active(.shanghai, header.timestamp)) return null;
    return &.{};
}

/// The header's builder inputs only (the results are filled by `seal_header`), as
/// `Chain.child_header` derives them: blob fields from Ecotone (excess zero on L2).
fn inputs_of(header: *const Header) Header {
    var inputs: Header = .{
        .parent_hash = header.parent_hash,
        .beneficiary = header.beneficiary,
        .number = header.number,
        .gas_limit = header.gas_limit,
        .timestamp = header.timestamp,
        .extra_data = header.extra_data,
        .mix_hash = header.mix_hash,
        .base_fee_per_gas = header.base_fee_per_gas,
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .excess_blob_gas = header.excess_blob_gas,
    };
    if (inputs.parent_beacon_block_root != null and inputs.excess_blob_gas == null) {
        inputs.excess_blob_gas = 0;
    }
    return inputs;
}

/// The engine payload of the canonical block.
fn payload_of(spec: *const chainspec.ChainSpec, case: *const Case) engine.ExecutionPayload {
    const header = &case.header;
    return .{
        .parent_hash = header.parent_hash,
        .fee_recipient = header.beneficiary,
        .state_root = header.state_root,
        .receipts_root = header.receipts_root,
        .logs_bloom = header.logs_bloom,
        .prev_randao = header.mix_hash,
        .block_number = header.number,
        .gas_limit = header.gas_limit,
        .gas_used = header.gas_used,
        .timestamp = header.timestamp,
        .extra_data = header.extra_data,
        .base_fee_per_gas = header.base_fee_per_gas orelse 0,
        .block_hash = .{ .bytes = case.hash.? },
        .transactions = case.transactions,
        .withdrawals = withdrawals_of(spec, header),
        .blob_gas_used = header.blob_gas_used,
        .excess_blob_gas = header.excess_blob_gas,
        .withdrawals_root = if (spec.is_upgrade_active(.isthmus, header.timestamp))
            header.withdrawals_root
        else
            null,
    };
}

fn params_of(spec: *const chainspec.ChainSpec, header: *const Header) engine.NewPayloadParams {
    const v3 = spec.is_ethereum_fork_active(.cancun, header.timestamp);
    const v4 = spec.is_ethereum_fork_active(.prague, header.timestamp);
    return .{
        .versioned_hashes = if (v3) &.{} else null,
        .parent_beacon_block_root = header.parent_beacon_block_root,
        .execution_requests = if (v4) &.{} else null,
    };
}

/// Pools sized to the witness, with the replayer's headroom for one block's new nodes.
fn sparse_config(case: *const Case) SparseState.Config {
    var node_bytes: u64 = 0;
    for (case.nodes) |bytes| node_bytes += bytes.len;
    var code_bytes: u64 = 0;
    for (case.codes) |code| code_bytes += code.len;
    const nodes: u32 = @intCast(case.nodes.len + 1);
    return .{
        .nodes_max = nodes + 1024,
        .node_bytes_max = @intCast(node_bytes + (1 << 20)),
        .codes_max = @intCast(case.codes.len + 1024),
        .code_bytes_max = @intCast(code_bytes + (8 << 20)),
        .headers_max = request.ancestors_max,
        .trie_nodes_max = 4 * nodes + (1 << 18),
        .storage_tries_max = 1 << 14,
    };
}

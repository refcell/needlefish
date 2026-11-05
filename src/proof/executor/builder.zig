//! Stateless L2 block builder. Port of base/base `crates/proof/executor/src/builder`
//! (`StatelessL2Builder::build_block`, `seal_block`, `compute_output_root`).
//!
//! The block runs through the node's block executor (`execution/node/executor.zig`) over
//! a `Backend` that is the trie-db lane's `SparseState`: reads come from trie nodes,
//! codes and headers fetched through the preimage oracle (`OracleFallback`), and the
//! commit applies the block's changes to the sparse tries for the post-state root. The
//! header is assembled with the rules of the node's `Chain.child_header` and `seal`, so
//! a block built here hashes like the node's (checked by `executor_test.zig`).
//!
//! Before executing, the builder sends the `l2-payload-witness` hint (parent hash ++
//! JSON attributes) so an online host can prefetch the block's execution witness.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const OracleFallback = @import("oracle_fallback.zig").OracleFallback;
const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const evm = @import("../../execution/evm/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const payload = @import("../../execution/payload/root.zig");
const ordered = @import("../../execution/trie/ordered.zig");
const db = @import("../../execution/db/root.zig");
const node_executor = @import("../../execution/node/executor.zig");
const chain_module = @import("../../execution/node/chain.zig");
const json = @import("../../utilities/json/root.zig");
const engine_json = @import("../../consensus/sources/engine_json.zig");

const Hash = [32]u8;
const Header = consensus.Header;
const SparseState = db.witness.SparseState;
const Executor = node_executor.Executor;

pub const l2_to_l1_message_passer: [20]u8 =
    primitives.hex.decode_array(20, "4200000000000000000000000000000000000016") catch unreachable;

/// Largest `l2-payload-witness` hint: parent hash plus JSON attributes.
pub const witness_hint_bytes_max: u32 = 1 << 20;

pub const Config = struct {
    sparse: SparseState.Config,
    changeset: db.changeset.Config,
    executor: node_executor.Config,
    resolver: mpt.oracle_resolver.Options,
};

pub const Error = node_executor.Error || error{
    InvalidAttributes,
    /// The oracle or hint channel failed while sending a hint.
    HintFailed,
};

/// A built block: its header (extra data borrows the builder) and hash.
pub const Outcome = struct {
    header: Header,
    hash: Hash,
    executed: node_executor.Executed,
};

pub const Builder = struct {
    spec: *const chainspec.ChainSpec,
    sparse: SparseState,
    changeset: db.Changeset,
    resolver: mpt.OracleResolver,
    hints: preimage.HintWriter,
    fallback: OracleFallback,
    executor: Executor,
    hint_buffer: []u8,
    extra_data: [chainspec.basefee.jovian_extra_data_size]u8 = undefined,
    /// Why the backend reported `StateUnavailable`.
    backend_error: ?anyerror = null,
    /// The block whose post-state the sparse state holds after `build_block`.
    last_built: ?Hash = null,

    /// The builder must not move after `init` (the executor's backend points at it).
    pub fn init(
        self: *Builder,
        allocator: std.mem.Allocator,
        spec: *const chainspec.ChainSpec,
        oracle: preimage.OracleReader,
        hints: preimage.HintWriter,
        config: Config,
    ) !void {
        self.spec = spec;
        self.hints = hints;
        self.backend_error = null;
        self.last_built = null;
        self.sparse = try SparseState.init(allocator, config.sparse);
        errdefer self.sparse.deinit(allocator);
        self.changeset = try db.Changeset.init(allocator, config.changeset);
        errdefer self.changeset.deinit(allocator);
        self.resolver = try mpt.OracleResolver.init(allocator, oracle, config.resolver);
        errdefer self.resolver.deinit(allocator);
        self.hint_buffer = try allocator.alloc(u8, witness_hint_bytes_max);
        errdefer allocator.free(self.hint_buffer);
        self.fallback = OracleFallback.init(&self.resolver, hints, 0, @splat(0));
        const executor_config = config.executor;
        self.executor = try Executor.init_backend(allocator, spec, self.backend(), executor_config);
    }

    pub fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        self.executor.deinit(allocator);
        allocator.free(self.hint_buffer);
        self.resolver.deinit(allocator);
        self.changeset.deinit(allocator);
        self.sparse.deinit(allocator);
        self.* = undefined;
    }

    fn backend(self: *Builder) node_executor.Backend {
        return .{
            .context = self,
            .database = self.sparse.database(),
            .commit = backend_commit,
            .root = backend_root,
        };
    }

    fn backend_commit(context: *anyopaque, state: *evm.State) node_executor.BackendError!void {
        const self: *Builder = @ptrCast(@alignCast(context));
        self.sparse.apply_evm(state, &self.changeset) catch |err| {
            self.backend_error = err;
            return error.StateUnavailable;
        };
    }

    fn backend_root(context: *anyopaque) node_executor.BackendError!Hash {
        const self: *Builder = @ptrCast(@alignCast(context));
        return self.sparse.state_root();
    }

    /// Points the sparse state at `header`'s post-state, fetching through the oracle.
    fn open_state(self: *Builder, header: *const Header, hash: Hash) void {
        self.sparse.reset(header.state_root.bytes);
        self.fallback = OracleFallback.init(&self.resolver, self.hints, header.number, hash);
        self.sparse.set_fallback(self.fallback.fallback());
        self.executor.state.reset(self.sparse.database());
        self.backend_error = null;
        self.last_built = null;
    }

    fn send_witness_hint(
        self: *Builder,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) Error!void {
        var out: std.Io.Writer = .fixed(self.hint_buffer[0 .. self.hint_buffer.len / 2]);
        var writer = json.Writer.init(&out);
        engine_json.write_attributes(&writer, attributes) catch return error.InvalidAttributes;
        const attributes_json = out.buffered();
        var data_buffer: [32]u8 = undefined;
        data_buffer = parent_hash;
        const text_out = self.hint_buffer[self.hint_buffer.len / 2 ..];
        const prefix = "l2-payload-witness 0x";
        const text_len = prefix.len + (32 + attributes_json.len) * 2;
        if (text_len > text_out.len) return error.InvalidAttributes;
        @memcpy(text_out[0..prefix.len], prefix);
        const hex_out = text_out[prefix.len..text_len];
        _ = std.fmt.bufPrint(hex_out, "{x}{x}", .{ &data_buffer, attributes_json }) catch
            unreachable; // Sized exactly above.
        self.hints.write(text_out[0..text_len]) catch return error.HintFailed;
    }

    /// Builds the child of `parent` (hash `parent_hash`) from `attributes`.
    pub fn build_block(
        self: *Builder,
        parent: *const Header,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) Error!Outcome {
        if (attributes.timestamp <= parent.timestamp) return error.InvalidAttributes;
        try self.send_witness_hint(parent_hash, attributes);
        self.open_state(parent, parent_hash);
        var child = try self.child_header(parent, parent_hash, attributes);
        const env = chain_module.env_of(&child);
        const transactions = attributes.transactions orelse &.{};
        const withdrawals = attributes.withdrawals;
        const executed = self.executor.execute_block(&env, transactions, withdrawals) catch |err| {
            // The evm only sees `DatabaseFailure`; report missing oracle data as such.
            if (self.sparse.incomplete) return error.StateUnavailable;
            return err;
        };
        try self.seal(&child, transactions, attributes.withdrawals, &executed);
        const hash = child.hash().bytes;
        self.last_built = hash;
        return .{ .header = child, .hash = hash, .executed = executed };
    }

    /// Header fields known before execution (`Chain.child_header`).
    fn child_header(
        self: *Builder,
        parent: *const Header,
        parent_hash: Hash,
        attributes: *const payload.PayloadAttributes,
    ) Error!Header {
        const spec = self.spec;
        const extra: []const u8 = if (spec.mode == .l2)
            attributes.extra_data(spec, &self.extra_data)
        else
            &.{};
        var child: Header = .{
            .parent_hash = .{ .bytes = parent_hash },
            .beneficiary = attributes.suggested_fee_recipient,
            .number = parent.number + 1,
            .gas_limit = attributes.gas_limit orelse parent.gas_limit,
            .timestamp = attributes.timestamp,
            .extra_data = extra,
            .mix_hash = attributes.prev_randao,
            .base_fee_per_gas = spec.next_base_fee(.{
                .timestamp = parent.timestamp,
                .gas_used = parent.gas_used,
                .gas_limit = parent.gas_limit,
                .base_fee = parent.base_fee_per_gas orelse 0,
                .blob_gas_used = parent.blob_gas_used orelse 0,
                .excess_blob_gas = parent.excess_blob_gas orelse 0,
                .extra_data = parent.extra_data,
            }, attributes.timestamp) catch return error.InvalidAttributes,
            .parent_beacon_block_root = attributes.parent_beacon_block_root,
        };
        if (spec.blob_params_at(attributes.timestamp)) |params| {
            child.excess_blob_gas = params.next_excess_blob_gas(
                parent.excess_blob_gas orelse 0,
                parent.blob_gas_used orelse 0,
                parent.base_fee_per_gas orelse 0,
            );
        } else if (spec.mode == .l2 and attributes.parent_beacon_block_root != null) {
            child.excess_blob_gas = 0;
        }
        assert(child.number == parent.number + 1);
        return child;
    }

    /// Fills the execution results into `child` (`Chain.seal`).
    fn seal(
        self: *Builder,
        child: *Header,
        transactions: []const []const u8,
        withdrawals: ?[]const payload.Withdrawal,
        executed: *const node_executor.Executed,
    ) Error!void {
        child.state_root = .{ .bytes = executed.state_root };
        child.transactions_root = .{ .bytes = ordered.ordered_trie_root(transactions) };
        child.receipts_root = .{ .bytes = executed.receipts_root };
        child.logs_bloom = executed.logs_bloom;
        child.gas_used = executed.gas_used;
        if (child.parent_beacon_block_root != null) child.blob_gas_used = executed.blob_gas_used;
        if (withdrawals) |list| {
            // L2 payloads carry an empty withdrawal list (Canyon+), never withdrawals.
            if (list.len != 0) return error.InvalidAttributes;
            child.withdrawals_root = primitives.empty_root_hash;
        }
        if (self.spec.is_ethereum_fork_active(.prague, child.timestamp)) {
            if (self.spec.mode == .l1) {
                child.requests_hash = consensus.block.requests_hash(executed.requests);
            } else {
                child.requests_hash = consensus.block.empty_requests_hash;
                const passer = l2_to_l1_message_passer;
                const root = self.sparse.account_storage_root(passer) catch |err| {
                    self.backend_error = err;
                    return error.StateUnavailable;
                };
                child.withdrawals_root = .{ .bytes = root };
            }
        }
        assert(child.optionals_contiguous());
    }

    /// The output root of block `header` (hash `hash`): version 0 over its state root,
    /// the L2ToL1MessagePasser storage root, and the block hash. The block just built is
    /// read from the in-memory post-state; any other block's state from the oracle.
    pub fn output_root(self: *Builder, header: *const Header, hash: Hash) Error!Hash {
        const built = if (self.last_built) |last| std.mem.eql(u8, &last, &hash) else false;
        if (!built) self.open_state(header, hash);
        const passer = l2_to_l1_message_passer;
        const storage_root = self.sparse.account_storage_root(passer) catch |err| {
            self.backend_error = err;
            return error.StateUnavailable;
        };
        return output_root_from_parts(header.state_root.bytes, storage_root, hash);
    }
};

/// `keccak256(version (32 zero bytes) ++ state_root ++ message_passer_root ++ block_hash)`.
pub fn output_root_from_parts(state_root: Hash, storage_root: Hash, block_hash: Hash) Hash {
    var preimage_bytes: [128]u8 = @splat(0);
    preimage_bytes[32..64].* = state_root;
    preimage_bytes[64..96].* = storage_root;
    preimage_bytes[96..128].* = block_hash;
    return primitives.keccak256(&preimage_bytes).bytes;
}

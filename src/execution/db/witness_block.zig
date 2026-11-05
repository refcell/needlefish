//! Execution witness of a stored block (`debug_executionWitness`).
//!
//! `Generator` owns every buffer the witness of one block needs (allocated at init), and is
//! bound to one `State`: the durable database's, or the node's in-memory one. To witness
//! canonical block B while the state holds a descendant head H:
//! 1. unwind the stored changesets of H down to B (in memory, nothing is journaled); the
//!    root after unwinding H..B+1 is B's stored post-state root, and one more unwind leaves
//!    the state at B's parent;
//! 2. run the caller's executor over the evm `Database` of that parent state wrapped in
//!    `witness.Recorder` (BLOCKHASH answers from the caller's canonical chain view, so ring
//!    slots the descendants overwrote do not matter); the executor leaves B's changes
//!    uncommitted in its evm `State`;
//! 3. fold that evm state into a changeset (`evm_backend.commit_evm` +
//!    `Overlay.build_changeset`, the node's commit rules, nothing applied) and build the
//!    witness with `witness.Builder` from the parent state, with the RLP headers of the
//!    ancestors from the lowest BLOCKHASH number read up to the parent;
//! 4. require the witness-only post root to equal B's stored root (`WitnessMismatch`);
//! 5. re-apply the unwound changesets (always, also after an error) and check that the
//!    state root is the head's again (`StateCorrupted` otherwise: the state is unusable).
//!
//! The state moves under the caller, so the caller's executor and every other user of the
//! state must be idle for the call (the node is single-threaded: an RPC handler runs
//! between blocks). Cost: one unwind + re-apply per block between B and the head, plus
//! one execution of B; no copy of the state.

const std = @import("std");
const assert = std.debug.assert;

const evm = @import("../evm/root.zig");
const witness = @import("witness.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const chain_module = @import("chain.zig");
const evm_backend = @import("evm_backend.zig");

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const ChainStore = chain_module.ChainStore;
pub const Hash = state_module.Hash;

/// The parent plus the 256 BLOCKHASH ancestors below it.
pub const headers_max: u32 = state_module.block_hashes_max + 1;

pub const Error = witness.Error || state_module.Error || overlay_module.Error || error{
    /// Not canonical, not retained, genesis, or deeper than `Config.depth_max`.
    BlockUnavailable,
    ExecutionFailed,
    HeaderUnavailable,
    InvalidChangeset,
    /// The witness-only post root differs from the block's stored root.
    WitnessMismatch,
    /// Restoring the head failed; the state no longer matches its head.
    StateCorrupted,
};

pub const ExecuteError = error{ExecutionFailed};

/// The caller's block executor: runs the block over `database` and returns its evm block
/// `State` with the block's changes uncommitted (the caller clears it after the call).
pub const Execute = struct {
    context: *anyopaque,
    run: *const fn (
        context: *anyopaque,
        database: evm.state.Database,
    ) ExecuteError!*const evm.State,
};

/// A view of the canonical chain: hashes and RLP headers by number.
pub const Blocks = struct {
    context: *const anyopaque,
    hash: *const fn (context: *const anyopaque, number: u64) ?Hash,
    header: *const fn (context: *const anyopaque, number: u64) ?[]const u8,
};

pub const Target = struct {
    /// The witnessed block's number (> 0).
    number: u64,
    /// Encoded changesets from the state's current block down to the target, newest first;
    /// the last one is the target's own.
    changesets: []const []const u8,
    blocks: Blocks,
};

pub const Config = struct {
    builder: witness.Builder.Config,
    witness: witness.Witness.Config,
    /// One block's writes (as the node's `StateDb` block limits).
    overlay: overlay_module.Config,
    changeset: changeset_module.Config,
    /// Blocks from the state's block down to the witnessed one, inclusive.
    depth_max: u32,
};

pub const Generator = struct {
    state: *State,
    builder: witness.Builder,
    recorder: witness.Recorder,
    /// The last generated witness.
    witness: witness.Witness,
    overlay: Overlay,
    /// Decode scratch for unwinding and re-applying stored changesets.
    changeset: Changeset,
    /// The witnessed block's changeset, folded from the evm state.
    changeset_built: Changeset,
    changesets: [][]const u8,
    headers: [][]const u8,
    blocks: ?Blocks = null,

    pub fn init(allocator: std.mem.Allocator, state: *State, config: Config) !Generator {
        assert(config.depth_max > 0);
        var builder = try witness.Builder.init(allocator, config.builder);
        errdefer builder.deinit(allocator);
        var recorder = try witness.Recorder.init(
            allocator,
            evm_backend.database(state),
            config.builder.keys,
        );
        errdefer recorder.deinit(allocator);
        var out = try witness.Witness.init(allocator, config.witness);
        errdefer out.deinit(allocator);
        var overlay = try Overlay.init(allocator, state, config.overlay);
        errdefer overlay.deinit(allocator);
        var changeset = try Changeset.init(allocator, config.changeset);
        errdefer changeset.deinit(allocator);
        var changeset_built = try Changeset.init(allocator, config.changeset);
        errdefer changeset_built.deinit(allocator);
        const changesets = try allocator.alloc([]const u8, config.depth_max);
        errdefer allocator.free(changesets);
        const headers = try allocator.alloc([]const u8, headers_max);
        return .{
            .state = state,
            .builder = builder,
            .recorder = recorder,
            .witness = out,
            .overlay = overlay,
            .changeset = changeset,
            .changeset_built = changeset_built,
            .changesets = changesets,
            .headers = headers,
        };
    }

    pub fn deinit(self: *Generator, allocator: std.mem.Allocator) void {
        allocator.free(self.headers);
        allocator.free(self.changesets);
        self.changeset_built.deinit(allocator);
        self.changeset.deinit(allocator);
        self.overlay.deinit(allocator);
        self.witness.deinit(allocator);
        self.recorder.deinit(allocator);
        self.builder.deinit(allocator);
        self.* = undefined;
    }

    /// Fills `self.witness` for `target` and returns the block's post-state root. The state
    /// is back at its block afterwards, also on error (except `StateCorrupted`).
    pub fn generate(self: *Generator, target: *const Target, execute: Execute) Error!Hash {
        if (target.number == 0) return error.BlockUnavailable;
        if (target.changesets.len == 0) return error.BlockUnavailable;
        if (target.changesets.len > self.changesets.len) return error.BlockUnavailable;
        const head_root = try self.state.state_root();
        var unwound: u32 = 0;
        const result = self.generate_unwound(target, execute, &unwound);
        self.blocks = null;
        assert(unwound <= target.changesets.len);
        self.reapply(target.changesets[0..unwound]) catch return error.StateCorrupted;
        const restored = self.state.state_root() catch return error.StateCorrupted;
        if (!std.mem.eql(u8, &restored, &head_root)) return error.StateCorrupted;
        return result;
    }

    fn generate_unwound(
        self: *Generator,
        target: *const Target,
        execute: Execute,
        unwound: *u32,
    ) Error!Hash {
        const changesets = target.changesets;
        assert(unwound.* == 0 and changesets.len > 0);
        for (changesets[0 .. changesets.len - 1]) |encoded| {
            try self.unwind_one(encoded);
            unwound.* += 1;
        }
        const expected_root = try self.state.state_root();
        try self.unwind_one(changesets[changesets.len - 1]);
        unwound.* += 1;
        assert(unwound.* == changesets.len);
        return self.run(target, execute, expected_root);
    }

    fn unwind_one(self: *Generator, encoded: []const u8) Error!void {
        self.changeset.decode(encoded) catch return error.InvalidChangeset;
        try self.state.unwind(&self.changeset);
    }

    /// Re-applies `changesets` (newest first, as unwound) oldest first.
    fn reapply(self: *Generator, changesets: []const []const u8) Error!void {
        var index = changesets.len;
        while (index > 0) {
            index -= 1;
            self.changeset.decode(changesets[index]) catch return error.InvalidChangeset;
            try self.state.apply(&self.changeset);
        }
    }

    /// Executes the block over the recorded parent state and builds the witness.
    fn run(self: *Generator, target: *const Target, execute: Execute, expected: Hash) Error!Hash {
        self.blocks = target.blocks;
        self.recorder.keys.clear();
        self.recorder.inner = self.parent_database();
        const evm_state = try execute.run(execute.context, self.recorder.database());
        self.overlay.discard();
        defer self.overlay.discard();
        try evm_backend.commit_evm(evm_state, &self.overlay);
        try self.overlay.build_changeset(&self.changeset_built);
        const headers = try self.collect_headers(target);
        const post_root = try self.builder.build(
            self.state,
            &self.recorder.keys,
            &self.changeset_built,
            headers,
            &self.witness,
        );
        if (!std.mem.eql(u8, &post_root, &expected)) return error.WitnessMismatch;
        assert(self.witness.headers.count == headers.len);
        return post_root;
    }

    /// Ancestor headers from the lowest BLOCKHASH number read up to the parent, oldest
    /// first, so a stateless verifier can link every read hash to the parent.
    fn collect_headers(self: *Generator, target: *const Target) Error![]const []const u8 {
        const parent = target.number - 1;
        var lowest = parent;
        for (self.recorder.keys.block_numbers.slice()) |number| {
            // The evm only asks the database inside the 256-block window.
            if (number >= target.number) return error.HeaderUnavailable;
            lowest = @min(lowest, number);
        }
        const count = parent - lowest + 1;
        if (count > self.headers.len) return error.HeaderUnavailable;
        for (self.headers[0..count], 0..) |*header, offset| {
            const number = lowest + offset;
            header.* = target.blocks.header(target.blocks.context, number) orelse
                return error.HeaderUnavailable;
        }
        assert(count >= 1);
        return self.headers[0..count];
    }

    const parent_vtable: evm.state.Database.VTable = .{
        .basic = parent_basic,
        .code_by_hash = parent_code_by_hash,
        .storage = parent_storage,
        .block_hash = parent_block_hash,
    };

    /// The parent state as an evm `Database`, with BLOCKHASH from the canonical chain.
    fn parent_database(self: *Generator) evm.state.Database {
        return .{ .context = self, .vtable = &parent_vtable };
    }

    fn from(context: *anyopaque) *Generator {
        return @ptrCast(@alignCast(context));
    }

    fn parent_basic(
        context: *anyopaque,
        address: evm.Address,
    ) evm.state.Error!?evm.state.AccountInfo {
        return evm_backend.database(from(context).state).basic(address);
    }

    fn parent_code_by_hash(context: *anyopaque, code_hash: evm.B256) evm.state.Error![]const u8 {
        return evm_backend.database(from(context).state).code_by_hash(code_hash);
    }

    fn parent_storage(context: *anyopaque, address: evm.Address, slot: u256) evm.state.Error!u256 {
        return evm_backend.database(from(context).state).storage(address, slot);
    }

    /// Unknown numbers read as zero, as `evm_backend` answers.
    fn parent_block_hash(context: *anyopaque, number: u64) evm.state.Error!evm.B256 {
        const self = from(context);
        const blocks = self.blocks.?;
        if (blocks.hash(blocks.context, number)) |hash| return hash;
        return self.state.block_hash(number) orelse @splat(0);
    }

    /// The witness of canonical block `hash` in a durable database (`DatabaseType`), whose
    /// state this generator is bound to. Blocks outside retention are `BlockUnavailable`.
    /// A failed restore fails the database.
    pub fn database_witness(
        self: *Generator,
        database: anytype,
        hash: Hash,
        execute: Execute,
    ) Error!Hash {
        assert(self.state == &database.state);
        if (database.phase != .ready or !database.head_info.present) {
            return error.BlockUnavailable;
        }
        const chain = &database.chain;
        const meta = chain.meta(hash) orelse return error.BlockUnavailable;
        const changesets = try self.canonical_changesets(chain, database.head_info.hash, hash);
        const target: Target = .{
            .number = meta.number,
            .changesets = changesets,
            .blocks = chain_blocks(chain),
        };
        return self.generate(&target, execute) catch |err| {
            if (err == error.StateCorrupted) database.phase = .failed;
            return err;
        };
    }

    /// Stored changesets from `head` down to canonical block `hash`, newest first.
    fn canonical_changesets(
        self: *Generator,
        chain: *const ChainStore,
        head: Hash,
        hash: Hash,
    ) Error![]const []const u8 {
        if (!chain.is_canonical(hash)) return error.BlockUnavailable;
        var cursor = head;
        var count: u32 = 0;
        while (count < self.changesets.len) {
            const view = chain.block(cursor) orelse return error.BlockUnavailable;
            self.changesets[count] = view.changeset;
            count += 1;
            if (std.mem.eql(u8, &cursor, &hash)) return self.changesets[0..count];
            cursor = view.meta.parent_hash;
        }
        return error.BlockUnavailable;
    }
};

/// The canonical chain of a `ChainStore` (headers as stored: RLP from the node).
pub fn chain_blocks(chain: *const ChainStore) Blocks {
    return .{ .context = chain, .hash = chain_hash, .header = chain_header };
}

fn chain_of(context: *const anyopaque) *const ChainStore {
    return @ptrCast(@alignCast(context));
}

fn chain_hash(context: *const anyopaque, number: u64) ?Hash {
    return chain_of(context).canonical_hash(number);
}

fn chain_header(context: *const anyopaque, number: u64) ?[]const u8 {
    const chain = chain_of(context);
    const hash = chain.canonical_hash(number) orelse return null;
    const view = chain.block(hash) orelse return null;
    return view.header;
}

//! Oracle-backed L2 chain provider for the derivation pipeline. Port of base/base
//! `crates/proof/proof/src/l2/chain_provider.rs`.
//!
//! - headers: hint `l2-block-header <hash>`, then the keccak preimage,
//! - transactions: hint `l2-transactions <hash>`, then an ordered walk of
//!   `transactions_root` (raw EIP-2718, deposits first),
//! - block info / system config: from the first transaction (the L1 info deposit), with
//!   the rollup genesis rule,
//! - by number: walk parent hashes back from the head. The program moves the head with
//!   `set_head` after every block it builds; it also records those blocks with
//!   `remember`, since the host may not know a block the program derived differently.
//!
//! Oracle failures return `error.NotFound` and set `failure` (see `l1_chain_provider`).

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const derive = @import("../../consensus/derive/root.zig");
const hint = @import("hint.zig");

const B256 = primitives.B256;
const Hash = [32]u8;
const L2BlockInfo = protocol.L2BlockInfo;
const SystemConfig = protocol.SystemConfig;
const SafeBlock = protocol.span_batch.SafeBlock;
const RollupConfig = protocol.RollupConfig;
const ProviderError = derive.errors.ProviderError;
const l2_system_config = protocol.l2_system_config;

pub const Failure = mpt.oracle_resolver.Error || hint.SendError || mpt.list_walker.Error || error{
    InvalidHeader,
    InvalidTransaction,
    MissingL1InfoDeposit,
    InvalidL1Info,
    InvalidSystemConfig,
    TooManyItems,
};

pub const Options = struct {
    /// Transactions per L2 block.
    items_max: u32 = 4096,
};

/// Program-built blocks remembered by `remember`.
pub const remembered_max = 64;

/// Parent-hash steps one by-number lookup may take.
pub const walk_steps_max: u64 = 1 << 22;

const Remembered = struct {
    info: L2BlockInfo,
    system_config: SystemConfig,
};

const Block = struct {
    info: L2BlockInfo,
    system_config: SystemConfig,
    /// Raw transactions; valid until the next body fetch.
    transactions: []const []const u8,
};

pub const L2ChainProvider = struct {
    resolver: *mpt.OracleResolver,
    hints: preimage.HintWriter,
    rollup: *const RollupConfig,
    head: protocol.BlockInfo,
    cursor: protocol.BlockInfo,
    failure: ?Failure = null,
    values: [][]const u8,
    seen: []bool,
    scratch: *mpt.list_walker.Scratch,
    remembered: [remembered_max]Remembered = undefined,
    remembered_count: u32 = 0,
    remembered_next: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        resolver: *mpt.OracleResolver,
        hints: preimage.HintWriter,
        rollup: *const RollupConfig,
        head_hash: Hash,
        options: Options,
    ) (std.mem.Allocator.Error || Failure)!L2ChainProvider {
        assert(options.items_max > 0);
        var self: L2ChainProvider = .{
            .resolver = resolver,
            .hints = hints,
            .rollup = rollup,
            .head = undefined,
            .cursor = undefined,
            .values = try allocator.alloc([]const u8, options.items_max),
            .seen = undefined,
            .scratch = undefined,
        };
        errdefer allocator.free(self.values);
        self.seen = try allocator.alloc(bool, options.items_max);
        errdefer allocator.free(self.seen);
        self.scratch = try allocator.create(mpt.list_walker.Scratch);
        errdefer allocator.destroy(self.scratch);
        const header = try self.fetch_header(head_hash);
        self.head = info_of(&header, head_hash);
        self.cursor = self.head;
        return self;
    }

    pub fn deinit(self: *L2ChainProvider, allocator: std.mem.Allocator) void {
        allocator.destroy(self.scratch);
        allocator.free(self.seen);
        allocator.free(self.values);
        self.* = undefined;
    }

    /// Moves the head to a block the program built on top of the current head.
    pub fn set_head(self: *L2ChainProvider, head: protocol.BlockInfo) void {
        assert(head.number == self.head.number + 1);
        assert(head.parent_hash.eql(self.head.hash));
        self.head = head;
    }

    /// Records a block the program built, so lookups do not depend on the host.
    pub fn remember(self: *L2ChainProvider, info: L2BlockInfo, system_config: SystemConfig) void {
        self.remembered[self.remembered_next] = .{ .info = info, .system_config = system_config };
        self.remembered_next = (self.remembered_next + 1) % remembered_max;
        self.remembered_count = @min(self.remembered_count + 1, remembered_max);
        assert(self.remembered_count <= remembered_max);
    }

    fn find_remembered(self: *const L2ChainProvider, hash: B256) ?*const Remembered {
        for (self.remembered[0..self.remembered_count]) |*entry| {
            if (entry.info.block_info.hash.eql(hash)) return entry;
        }
        return null;
    }

    fn fail(self: *L2ChainProvider, failure: Failure) ProviderError {
        if (self.failure == null) self.failure = failure;
        return error.NotFound;
    }

    fn fetch_header(self: *L2ChainProvider, hash: Hash) Failure!consensus.Header {
        try hint.send(self.hints, .l2_block_header, &.{&hash});
        const encoded = try self.resolver.get(&hash);
        const header = consensus.Header.decode(encoded) catch return error.InvalidHeader;
        if (!std.mem.eql(u8, &header.hash().bytes, &hash)) return error.InvalidHeader;
        return header;
    }

    /// Header, transactions, block info and system config of block `hash`.
    fn fetch_block(self: *L2ChainProvider, hash: Hash) Failure!Block {
        const header = try self.fetch_header(hash);
        try hint.send(self.hints, .l2_transactions, &.{&hash});
        const count = try mpt.list_walker.walk(
            self.resolver.resolver(),
            header.transactions_root.bytes,
            self.values,
            self.seen,
            self.scratch,
        );
        const transactions = self.values[0..count];
        const fields: l2_system_config.BlockFields = .{
            .number = header.number,
            .hash = .{ .bytes = hash },
            .timestamp = header.timestamp,
            .gas_limit = header.gas_limit,
            .extra_data = header.extra_data,
        };
        const block_info = info_of(&header, hash);
        const genesis = l2_system_config.genesis_system_config(self.rollup, fields) catch
            return error.InvalidSystemConfig;
        if (genesis) |system_config| {
            const info: L2BlockInfo = .{
                .block_info = block_info,
                .l1_origin = self.rollup.genesis.l1,
                .sequence_number = 0,
            };
            return .{ .info = info, .system_config = system_config, .transactions = transactions };
        }
        const l1_info = try decode_l1_info(transactions);
        const system_config = l2_system_config.from_l1_info(self.rollup, &l1_info, fields) catch
            return error.InvalidSystemConfig;
        const info: L2BlockInfo = .{
            .block_info = block_info,
            .l1_origin = l1_info.id(),
            .sequence_number = l1_info.sequence_number,
        };
        return .{ .info = info, .system_config = system_config, .transactions = transactions };
    }

    /// The hash of block `number`, walking parent hashes back from the head.
    fn hash_by_number(self: *L2ChainProvider, number: u64) Failure!?B256 {
        if (number > self.head.number) return null;
        var current = if (number <= self.cursor.number) self.cursor else self.head;
        var steps: u64 = 0;
        while (current.number > number) : (steps += 1) {
            if (steps >= walk_steps_max) return error.TooManyItems;
            const parent = current.parent_hash.bytes;
            const header = try self.fetch_header(parent);
            if (header.number + 1 != current.number) return error.InvalidHeader;
            current = info_of(&header, parent);
        }
        assert(current.number == number);
        self.cursor = current;
        return current.hash;
    }

    // Chain-provider contract.

    pub fn l2_block_info_by_hash(self: *L2ChainProvider, hash: B256) ProviderError!L2BlockInfo {
        if (self.find_remembered(hash)) |entry| return entry.info;
        const block = self.fetch_block(hash.bytes) catch |err| return self.fail(err);
        return block.info;
    }

    pub fn system_config_by_l2_hash(self: *L2ChainProvider, hash: B256) ProviderError!SystemConfig {
        if (self.find_remembered(hash)) |entry| return entry.system_config;
        const block = self.fetch_block(hash.bytes) catch |err| return self.fail(err);
        return block.system_config;
    }

    pub fn l2_block_info_by_number(self: *L2ChainProvider, number: u64) ProviderError!L2BlockInfo {
        const hash = self.hash_by_number(number) catch |err| return self.fail(err);
        return self.l2_block_info_by_hash(hash orelse return error.NotFound);
    }

    /// The full block `number` for span batch checks. Valid until the next call.
    pub fn l2_block_by_number(self: *L2ChainProvider, number: u64) ProviderError!SafeBlock {
        const hash = self.hash_by_number(number) catch |err| return self.fail(err);
        const found = hash orelse return error.NotFound;
        const block = self.fetch_block(found.bytes) catch |err| return self.fail(err);
        const origin = block.info.l1_origin.number;
        return .{ .transactions = block.transactions, .l1_origin_number = origin };
    }
};

/// The L1 info of the block's first transaction, which must be a deposit.
fn decode_l1_info(transactions: []const []const u8) Failure!protocol.L1BlockInfo {
    if (transactions.len == 0) return error.MissingL1InfoDeposit;
    const first = consensus.Envelope.decode(transactions[0]) catch return error.InvalidTransaction;
    if (!first.is_deposit()) return error.MissingL1InfoDeposit;
    return protocol.L1BlockInfo.decode_calldata(first.input()) catch error.InvalidL1Info;
}

fn info_of(header: *const consensus.Header, hash: Hash) protocol.BlockInfo {
    return .{
        .hash = .{ .bytes = hash },
        .number = header.number,
        .parent_hash = header.parent_hash,
        .timestamp = header.timestamp,
    };
}

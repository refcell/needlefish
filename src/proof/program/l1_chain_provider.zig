//! Oracle-backed L1 chain provider for the derivation pipeline. Port of base/base
//! `crates/proof/proof/src/l1/chain_provider.rs`.
//!
//! - headers: hint `l1-block-header <hash>`, then the keccak preimage (hash-verified),
//! - transactions / receipts: hint `l1-transactions|l1-receipts <hash>`, then an ordered
//!   trie walk under the header's root,
//! - by number: walk parent hashes back from the boot L1 head.
//!
//! Derivation's `ProviderError` has no "fatal" member, so oracle failures return
//! `error.NotFound` and are recorded in `failure`; the program driver must check it after
//! every pipeline step and abort. Returned slices are valid until the next body call.

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
const BlockInfo = protocol.BlockInfo;
const L1Header = protocol.l1_info.L1Header;
const Receipt = protocol.log.Receipt;
const Log = protocol.log.Log;
const L1Transaction = derive.providers.L1Transaction;
const ProviderError = derive.errors.ProviderError;

pub const Failure = mpt.oracle_resolver.Error || hint.SendError || mpt.list_walker.Error || error{
    InvalidHeader,
    InvalidTransaction,
    InvalidReceipt,
    InvalidSignature,
    TooManyItems,
};

pub const Options = struct {
    /// Items (transactions or receipts) per block.
    items_max: u32 = 2048,
    logs_max: u32 = 8192,
    topics_max: u32 = 4 * 8192,
    blob_hashes_max: u32 = 2048,
    /// Recover senders only of transactions to this address (the batch inbox); others
    /// keep a zero `from`. Null recovers every sender.
    recover_to: ?primitives.Address = null,
};

/// Parent-hash steps one by-number lookup may take.
pub const walk_steps_max: u64 = 1 << 20;

pub const L1ChainProvider = struct {
    resolver: *mpt.OracleResolver,
    hints: preimage.HintWriter,
    options: Options,
    head: BlockInfo,
    /// The last header reached by a by-number walk; walks resume from it when possible.
    cursor: BlockInfo,
    failure: ?Failure = null,

    values: [][]const u8,
    seen: []bool,
    scratch: *mpt.list_walker.Scratch,
    transactions: []L1Transaction,
    receipts: []Receipt,
    logs: []Log,
    topics: []B256,
    blob_hashes: []B256,

    /// `head` is the boot L1 head; its header must be available from the oracle.
    pub fn init(
        allocator: std.mem.Allocator,
        resolver: *mpt.OracleResolver,
        hints: preimage.HintWriter,
        head_hash: Hash,
        options: Options,
    ) (std.mem.Allocator.Error || Failure)!L1ChainProvider {
        assert(options.items_max > 0 and options.logs_max > 0);
        var self: L1ChainProvider = .{
            .resolver = resolver,
            .hints = hints,
            .options = options,
            .head = undefined,
            .cursor = undefined,
            .values = try allocator.alloc([]const u8, options.items_max),
            .seen = undefined,
            .scratch = undefined,
            .transactions = undefined,
            .receipts = undefined,
            .logs = undefined,
            .topics = undefined,
            .blob_hashes = undefined,
        };
        errdefer allocator.free(self.values);
        self.seen = try allocator.alloc(bool, options.items_max);
        errdefer allocator.free(self.seen);
        self.scratch = try allocator.create(mpt.list_walker.Scratch);
        errdefer allocator.destroy(self.scratch);
        self.transactions = try allocator.alloc(L1Transaction, options.items_max);
        errdefer allocator.free(self.transactions);
        self.receipts = try allocator.alloc(Receipt, options.items_max);
        errdefer allocator.free(self.receipts);
        self.logs = try allocator.alloc(Log, options.logs_max);
        errdefer allocator.free(self.logs);
        self.topics = try allocator.alloc(B256, options.topics_max);
        errdefer allocator.free(self.topics);
        self.blob_hashes = try allocator.alloc(B256, options.blob_hashes_max);
        errdefer allocator.free(self.blob_hashes);
        const header = try self.fetch_header(head_hash);
        self.head = info_of(&header, head_hash);
        self.cursor = self.head;
        return self;
    }

    pub fn deinit(self: *L1ChainProvider, allocator: std.mem.Allocator) void {
        allocator.free(self.blob_hashes);
        allocator.free(self.topics);
        allocator.free(self.logs);
        allocator.free(self.receipts);
        allocator.free(self.transactions);
        allocator.destroy(self.scratch);
        allocator.free(self.seen);
        allocator.free(self.values);
        self.* = undefined;
    }

    fn fail(self: *L1ChainProvider, failure: Failure) ProviderError {
        if (self.failure == null) self.failure = failure;
        return error.NotFound;
    }

    fn fetch_header(self: *L1ChainProvider, hash: Hash) Failure!consensus.Header {
        try hint.send(self.hints, .l1_block_header, &.{&hash});
        const encoded = try self.resolver.get(&hash);
        const header = consensus.Header.decode(encoded) catch return error.InvalidHeader;
        // The preimage is hash-verified; a non-canonical encoding would re-hash differently.
        if (!std.mem.eql(u8, &header.hash().bytes, &hash)) return error.InvalidHeader;
        return header;
    }

    // Chain-provider contract.

    pub fn l1_header_by_hash(self: *L1ChainProvider, hash: B256) ProviderError!L1Header {
        const header = self.fetch_header(hash.bytes) catch |err| return self.fail(err);
        return .{
            .number = header.number,
            .timestamp = header.timestamp,
            .hash = hash,
            .base_fee = header.base_fee_per_gas,
            .excess_blob_gas = header.excess_blob_gas,
            .parent_hash = header.parent_hash,
            .mix_hash = header.mix_hash,
            .blob_gas_used = header.blob_gas_used,
            .parent_beacon_block_root = header.parent_beacon_block_root,
            .requests_hash = header.requests_hash,
        };
    }

    pub fn l1_block_info_by_hash(self: *L1ChainProvider, hash: B256) ProviderError!BlockInfo {
        const header = self.fetch_header(hash.bytes) catch |err| return self.fail(err);
        return info_of(&header, hash.bytes);
    }

    pub fn l1_block_info_by_number(self: *L1ChainProvider, number: u64) ProviderError!BlockInfo {
        if (number > self.head.number) return error.NotFound;
        var current = if (number <= self.cursor.number) self.cursor else self.head;
        var steps: u64 = 0;
        while (current.number > number) : (steps += 1) {
            if (steps >= walk_steps_max) return self.fail(error.TooManyItems);
            const parent = current.parent_hash.bytes;
            const header = self.fetch_header(parent) catch |err| return self.fail(err);
            if (header.number + 1 != current.number) return self.fail(error.InvalidHeader);
            current = info_of(&header, parent);
        }
        assert(current.number == number);
        self.cursor = current;
        return current;
    }

    pub fn l1_transactions_by_hash(
        self: *L1ChainProvider,
        hash: B256,
    ) ProviderError![]const L1Transaction {
        const count = self.walk_body(hash.bytes, .l1_transactions) catch |err| {
            return self.fail(err);
        };
        return self.decode_transactions(count) catch |err| return self.fail(err);
    }

    pub fn l1_receipts_by_hash(self: *L1ChainProvider, hash: B256) ProviderError![]const Receipt {
        const count = self.walk_body(hash.bytes, .l1_receipts) catch |err| return self.fail(err);
        return self.decode_receipts(count) catch |err| return self.fail(err);
    }

    /// Hints and walks the transactions or receipts trie of block `hash` into `values`.
    fn walk_body(self: *L1ChainProvider, hash: Hash, kind: hint.HintType) Failure!u32 {
        assert(kind == .l1_transactions or kind == .l1_receipts);
        const header = try self.fetch_header(hash);
        try hint.send(self.hints, kind, &.{&hash});
        const root = if (kind == .l1_transactions)
            header.transactions_root
        else
            header.receipts_root;
        const count = try mpt.list_walker.walk(
            self.resolver.resolver(),
            root.bytes,
            self.values,
            self.seen,
            self.scratch,
        );
        assert(count <= self.values.len);
        return count;
    }

    pub fn decode_transactions(self: *L1ChainProvider, count: u32) Failure![]const L1Transaction {
        var blob_hashes_used: u32 = 0;
        for (self.values[0..count], self.transactions[0..count]) |encoded, *transaction| {
            const envelope = consensus.Envelope.decode(encoded) catch {
                return error.InvalidTransaction;
            };
            const to: ?primitives.Address = switch (envelope.kind()) {
                .create => null,
                .call => |address| address,
            };
            const list = envelope.blob_versioned_hashes();
            const hashes_count: u32 = @intCast(list.count());
            if (blob_hashes_used + hashes_count > self.blob_hashes.len) return error.TooManyItems;
            const hashes = self.blob_hashes[blob_hashes_used..][0..hashes_count];
            for (hashes, 0..) |*item, index| item.* = list.get(index);
            blob_hashes_used += hashes_count;
            transaction.* = .{
                .tx_type = @backingInt(envelope.tx_type()),
                .to = to,
                .from = .zero,
                .input = envelope.input(),
                .blob_hashes = hashes,
            };
            if (self.should_recover(to) and !envelope.is_deposit()) {
                transaction.from = envelope.recover_sender(consensus.recover_address) orelse
                    return error.InvalidSignature;
            }
        }
        return self.transactions[0..count];
    }

    fn should_recover(self: *const L1ChainProvider, to: ?primitives.Address) bool {
        const target = self.options.recover_to orelse return true;
        const address = to orelse return false;
        return address.eql(target);
    }

    pub fn decode_receipts(self: *L1ChainProvider, count: u32) Failure![]const Receipt {
        var logs_used: u32 = 0;
        var topics_used: u32 = 0;
        for (self.values[0..count], self.receipts[0..count]) |encoded, *receipt| {
            const decoded = consensus.Receipt.decode(encoded) catch return error.InvalidReceipt;
            if (logs_used + decoded.logs.count > self.logs.len) return error.TooManyItems;
            const logs = self.logs[logs_used..][0..decoded.logs.count];
            var iterator = decoded.logs.iterator();
            for (logs) |*log| {
                const item = iterator.next().?; // `count` items were validated.
                const topics_count: u32 = @intCast(item.topics.count());
                if (topics_used + topics_count > self.topics.len) return error.TooManyItems;
                const topics = self.topics[topics_used..][0..topics_count];
                for (topics, 0..) |*topic, index| topic.* = item.topics.get(index);
                topics_used += topics_count;
                log.* = .{ .address = item.address, .topics = topics, .data = item.data };
            }
            assert(iterator.next() == null);
            logs_used += decoded.logs.count;
            receipt.* = .{ .success = decoded.status, .logs = logs };
        }
        return self.receipts[0..count];
    }
};

fn info_of(header: *const consensus.Header, hash: Hash) BlockInfo {
    return .{
        .hash = .{ .bytes = hash },
        .number = header.number,
        .parent_hash = header.parent_hash,
        .timestamp = header.timestamp,
    };
}

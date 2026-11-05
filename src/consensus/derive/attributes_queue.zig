//! Attributes queue: turns singular batches from the batch provider into payload
//! attributes for the engine. The batch is kept across a failed attempt (for example a
//! provider fetch still in flight) and retried before a new batch is pulled.
//! Mirrors base/base `crates/consensus/derive/src/stages/attributes_queue.rs` and
//! `crates/consensus/protocol/src/attributes.rs` (`AttributesWithParent`).
//!
//! The upstream stage (`prev`, see `batch_provider.Upstream`) exposes
//! `next_batch(parent: L2BlockInfo) Error!SingleBatch`, `is_last_in_span() bool`, and
//! `origin() ?BlockInfo`. The batch it returns borrows upstream memory until the next call
//! into upstream, so the queue holds at most one batch and never calls upstream while
//! holding it. `chain` is the attributes builder provider (see `AttributesBuilder`);
//! `BuilderChain` assembles one from separate L1 and L2 providers.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const protocol = @import("../protocol/root.zig");
const errors = @import("errors.zig");
const attributes = @import("attributes.zig");

const BlockInfo = protocol.block.BlockInfo;
const L2BlockInfo = protocol.block.L2BlockInfo;
const Hash = protocol.block.Hash;
const RollupConfig = protocol.rollup_config.RollupConfig;
const SystemConfig = protocol.SystemConfig;
const SingleBatch = protocol.batch.SingleBatch;
const L1Header = protocol.l1_info.L1Header;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;
const Receipt = protocol.log.Receipt;
const AttributesBuilder = attributes.AttributesBuilder;
const PayloadAttributes = attributes.PayloadAttributes;
const Error = errors.Error;
const ProviderError = errors.ProviderError;

/// Payload attributes with the L2 parent they build on and the L1 block they were derived
/// from. `attributes` is owned; release it with `deinit` and the pipeline's allocator.
pub const AttributesWithParent = struct {
    attributes: PayloadAttributes,
    parent: L2BlockInfo,
    /// The L1 origin of the pipeline when the batch was turned into attributes.
    derived_from: ?BlockInfo,
    is_last_in_span: bool,

    pub fn deinit(self: *AttributesWithParent, allocator: Allocator) void {
        assert(self.attributes.transactions.len > 0);
        self.attributes.deinit(allocator);
        assert(self.attributes.transactions.len == 0);
    }
};

/// The attributes builder provider made of an L1 chain provider and an L2 chain provider.
pub fn BuilderChain(comptime L1: type, comptime L2: type) type {
    return struct {
        l1: L1,
        l2: L2,

        const Self = @This();

        pub fn l1_header_by_hash(self: Self, hash: Hash) ProviderError!L1Header {
            return self.l1.l1_header_by_hash(hash);
        }

        pub fn l1_receipts_by_hash(self: Self, hash: Hash) ProviderError![]const Receipt {
            return self.l1.l1_receipts_by_hash(hash);
        }

        pub fn system_config_by_l2_hash(self: Self, hash: Hash) ProviderError!SystemConfig {
            return self.l2.system_config_by_l2_hash(hash);
        }
    };
}

pub const AttributesQueue = struct {
    rollup: *const RollupConfig,
    builder: AttributesBuilder,
    /// The batch being turned into attributes; borrows upstream memory.
    batch: ?SingleBatch = null,
    is_last_in_span: bool = false,

    pub fn init(
        allocator: Allocator,
        rollup: *const RollupConfig,
        blob_schedule: *const L1BlobSchedule,
    ) AttributesQueue {
        return .{ .rollup = rollup, .builder = .init(allocator, rollup, blob_schedule) };
    }

    fn load_batch(queue: *AttributesQueue, prev: anytype, parent: L2BlockInfo) Error!SingleBatch {
        if (queue.batch == null) {
            queue.batch = try prev.next_batch(parent);
            queue.is_last_in_span = prev.is_last_in_span();
        }
        assert(queue.batch != null);
        return queue.batch.?;
    }

    /// Returns the attributes of the child of `parent`. The caller owns the result.
    pub fn next_attributes(
        queue: *AttributesQueue,
        prev: anytype,
        chain: anytype,
        parent: L2BlockInfo,
    ) Error!AttributesWithParent {
        const batch = try queue.load_batch(prev, parent);
        var payload = try queue.create_next_attributes(chain, batch, parent);
        errdefer payload.deinit(queue.builder.allocator);
        const origin = prev.origin() orelse return error.MissingOrigin;
        const result: AttributesWithParent = .{
            .attributes = payload,
            .parent = parent,
            .derived_from = origin,
            .is_last_in_span = queue.is_last_in_span,
        };
        queue.batch = null;
        queue.is_last_in_span = false;
        assert(result.attributes.no_tx_pool);
        return result;
    }

    /// Builds the attributes for `batch`: sets `no_tx_pool` and appends the batch's
    /// transactions after the derived deposits.
    pub fn create_next_attributes(
        queue: *AttributesQueue,
        chain: anytype,
        batch: SingleBatch,
        parent: L2BlockInfo,
    ) Error!PayloadAttributes {
        if (!batch.parent_hash.eql(parent.block_info.hash)) return error.BadParentHash;
        const allocator = queue.builder.allocator;
        var payload = try queue.builder.prepare_payload_attributes(chain, parent, batch.epoch());
        errdefer payload.deinit(allocator);
        payload.no_tx_pool = true;
        const deposits_count = payload.transactions.len;
        try append_transactions(allocator, &payload, batch.transactions);
        assert(payload.transactions.len == deposits_count + batch.transactions.len);
        return payload;
    }

    pub fn reset(queue: *AttributesQueue) void {
        queue.batch = null;
        queue.is_last_in_span = false;
        assert(queue.batch == null);
    }

    pub fn activate(queue: *AttributesQueue) void {
        queue.reset();
        assert(!queue.is_last_in_span);
    }

    /// Drops the current batch (base/base keeps `is_last_in_span` here).
    pub fn flush_channel(queue: *AttributesQueue) void {
        queue.batch = null;
        assert(queue.batch == null);
    }
};

/// Appends copies of `transactions` to `payload.transactions`. On failure `payload` is
/// unchanged.
fn append_transactions(
    allocator: Allocator,
    payload: *PayloadAttributes,
    transactions: []const []const u8,
) Error!void {
    if (transactions.len == 0) return;
    const old = payload.transactions;
    const list = try allocator.alloc([]u8, old.len + transactions.len);
    var copied: usize = 0;
    errdefer {
        for (list[old.len..][0..copied]) |tx| allocator.free(tx);
        allocator.free(list);
    }
    for (transactions, list[old.len..]) |tx, *copy| {
        // Batch validity drops empty transactions before they get here.
        if (tx.len == 0) return error.BadEncoding;
        copy.* = try allocator.dupe(u8, tx);
        copied += 1;
    }
    @memcpy(list[0..old.len], old);
    allocator.free(old);
    payload.transactions = list;
    assert(copied == transactions.len);
}

const testing = std.testing;
const TestChain = @import("test_chain.zig").TestChain;

/// Batch provider stub: hands out `batch` once per `remaining`.
const TestBatches = struct {
    batch: SingleBatch,
    remaining: u32 = 1,
    last_in_span: bool = true,
    origin_block: ?BlockInfo = .{ .number = 9 },
    calls: u32 = 0,

    pub fn next_batch(stub: *TestBatches, parent: L2BlockInfo) Error!SingleBatch {
        _ = parent;
        stub.calls += 1;
        if (stub.remaining == 0) return error.Eof;
        stub.remaining -= 1;
        return stub.batch;
    }

    pub fn is_last_in_span(stub: *const TestBatches) bool {
        return stub.last_in_span;
    }

    pub fn origin(stub: *const TestBatches) ?BlockInfo {
        return stub.origin_block;
    }
};

const Fixture = struct {
    chain: TestChain,
    rollup: RollupConfig,
    schedule: L1BlobSchedule = .{},
    parent: L2BlockInfo,

    fn init(fixture: *Fixture) void {
        fixture.* = .{
            .chain = TestChain.init(2, 0, 2),
            .rollup = .{ .block_time = 2, .genesis = .{ .l2_time = 1000 } },
            .parent = undefined,
        };
        fixture.parent = .{
            .block_info = .{ .hash = .init(@splat(1)), .number = 0, .timestamp = 1000 },
            .l1_origin = fixture.chain.blocks[0].id(),
        };
        fixture.chain.add_system_config(fixture.parent.block_info.hash, .{ .gas_limit = 30 });
    }

    fn batch(fixture: *const Fixture, transactions: []const []const u8) SingleBatch {
        return .{
            .parent_hash = fixture.parent.block_info.hash,
            .epoch_num = fixture.chain.blocks[0].number,
            .epoch_hash = fixture.chain.blocks[0].hash,
            .timestamp = 1002,
            .transactions = transactions,
        };
    }
};

test "attributes queue: builds attributes with batch transactions" {
    var fixture: Fixture = undefined;
    fixture.init();
    const txs = [_][]const u8{ &.{ 0x02, 0xaa }, &.{ 0x01, 0xbb, 0xcc } };
    var stub: TestBatches = .{ .batch = fixture.batch(&txs) };
    var queue = AttributesQueue.init(testing.allocator, &fixture.rollup, &fixture.schedule);
    var result = try queue.next_attributes(&stub, &fixture.chain, fixture.parent);
    defer result.deinit(testing.allocator);
    const payload = result.attributes;
    try testing.expectEqual(@as(u64, 1002), payload.timestamp);
    try testing.expect(payload.no_tx_pool);
    try testing.expectEqual(@as(usize, 3), payload.transactions.len);
    try testing.expectEqual(@as(u8, 0x7e), payload.transactions[0][0]);
    try testing.expectEqualSlices(u8, txs[1], payload.transactions[2]);
    try testing.expect(result.parent.eql(fixture.parent));
    try testing.expectEqual(@as(u64, 9), result.derived_from.?.number);
    try testing.expect(result.is_last_in_span);
    try testing.expect(queue.batch == null);
    const eof = queue.next_attributes(&stub, &fixture.chain, fixture.parent);
    try testing.expectError(error.Eof, eof);
}

test "attributes queue: bad parent hash and retained batch" {
    var fixture: Fixture = undefined;
    fixture.init();
    var stub: TestBatches = .{ .batch = fixture.batch(&.{}) };
    stub.batch.parent_hash = .zero;
    var queue = AttributesQueue.init(testing.allocator, &fixture.rollup, &fixture.schedule);
    const parent = fixture.parent;
    const chain = &fixture.chain;
    try testing.expectError(error.BadParentHash, queue.next_attributes(&stub, chain, parent));
    try testing.expect(queue.batch != null);
    queue.flush_channel();
    try testing.expect(queue.batch == null);

    // A temporary provider failure keeps the batch; the retry does not pull upstream.
    stub = .{ .batch = fixture.batch(&.{}) };
    fixture.chain.unavailable_from = 0;
    try testing.expectError(error.NotAvailable, queue.next_attributes(&stub, chain, parent));
    fixture.chain.unavailable_from = std.math.maxInt(u64);
    var result = try queue.next_attributes(&stub, &fixture.chain, parent);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 1), stub.calls);
    try testing.expectEqual(@as(usize, 1), result.attributes.transactions.len);
    stub.origin_block = null;
    stub.remaining = 1;
    try testing.expectError(error.MissingOrigin, queue.next_attributes(&stub, chain, parent));
    queue.reset();
    try testing.expect(queue.batch == null and !queue.is_last_in_span);
}

test "attributes queue: allocation failures release memory" {
    var fixture: Fixture = undefined;
    fixture.init();
    const txs = [_][]const u8{ &.{ 0x02, 0xaa }, &.{ 0x01, 0xbb } };
    var fail_index: usize = 0;
    while (fail_index < 64) : (fail_index += 1) {
        var failing = testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = fail_index,
        });
        var stub: TestBatches = .{ .batch = fixture.batch(&txs) };
        var queue = AttributesQueue.init(failing.allocator(), &fixture.rollup, &fixture.schedule);
        if (queue.next_attributes(&stub, &fixture.chain, fixture.parent)) |result| {
            var owned = result;
            owned.deinit(failing.allocator());
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
        }
    } else return error.TestUnexpectedResult;
}

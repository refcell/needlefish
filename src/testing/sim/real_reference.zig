//! The reference execution node (`Config.real_execution`): an independent instance of the
//! execution lane's engine (`real_execution.ExecEngine`) that executes the sequencer's
//! chain and records each block's real hash and state root in the model chain
//! (`nodes.Chain.real_hashes`, `real_state_roots`). Every other node executing the same
//! block must reach the same hash and state root.
//!
//! - Model sequencer: the reference builds every new model block through the Engine API
//!   (forkchoiceUpdated with attributes, getPayload, then forkchoiceUpdated to it). The
//!   attributes are the real attributes builder's for the block's parent and L1 origin
//!   (the L1 info deposit), plus the block's payload as a signed transaction, with the pool
//!   off: exactly the block the sequencer gossips and the batcher posts.
//! - Real sequencer: its engine already executed each block (`real_sequencer.record` fills
//!   the reference chain); the reference imports every recorded block with newPayload and
//!   must find it valid, a second node agreeing on the same hash and state root.
//!
//! The reference is infrastructure, not a node under test: it never crashes, and it waits
//! for its own storage (`wait`) instead of answering `NotAvailable`.

const std = @import("std");
const assert = std.debug.assert;

const protocol = @import("../../consensus/protocol/root.zig");
const task = @import("../../consensus/engine/task.zig");
const attributes_module = @import("../../consensus/derive/attributes.zig");
const primitives = @import("../../common/primitives/root.zig");
const codec = @import("codec.zig");
const nodes = @import("nodes.zig");
const real_verifier = @import("real_verifier.zig");
const real_execution = @import("real_execution.zig");

const B256 = primitives.B256;
const L2BlockInfo = protocol.block.L2BlockInfo;
const ExecEngine = real_execution.ExecEngine;

const scratch_bytes = 16 * 1024;
const wait_ticks_max = 100_000;

pub const Reference = struct {
    allocator: std.mem.Allocator,
    engine: *ExecEngine,
    rollup: protocol.RollupConfig,
    blob_schedule: protocol.l1_info.L1BlobSchedule = .{},
    scratch: []u8,
    /// Highest block executed.
    head: u64 = 0,
    imported: u64 = 0,

    pub fn create(allocator: std.mem.Allocator, seed: u64) !*Reference {
        const reference = try allocator.create(Reference);
        errdefer allocator.destroy(reference);
        const scratch = try allocator.alloc(u8, scratch_bytes);
        errdefer allocator.free(scratch);
        const engine = try ExecEngine.create(allocator, seed ^ 0x7265_6665, .follower);
        reference.* = .{
            .allocator = allocator,
            .engine = engine,
            .rollup = real_execution.rollup_config(engine.genesis_hash),
            .scratch = scratch,
        };
        assert(reference.engine.head_number() == 0);
        return reference;
    }

    pub fn destroy(reference: *Reference) void {
        const allocator = reference.allocator;
        reference.engine.destroy();
        allocator.free(reference.scratch);
        allocator.destroy(reference);
    }

    /// Prepares the model chain for real execution: genesis gets the real genesis hash.
    pub fn attach(reference: *const Reference, chain: *nodes.Chain) void {
        assert(!chain.real);
        chain.real = true;
        chain.real_hashes[0] = reference.engine.genesis_hash;
        chain.real_state_roots[0] = reference.engine.genesis.state_root;
    }

    /// Ticks the reference's storage until it accepts engine writes.
    fn wait(reference: *Reference) ?[]const u8 {
        for (0..wait_ticks_max) |_| {
            if (reference.engine.accepting()) return null;
            reference.engine.tick();
        }
        return "reference engine storage stalled";
    }

    /// Builds every model sequencer block above the reference head. Returns the violated
    /// invariant, or null.
    pub fn follow(
        reference: *Reference,
        sequencer: *nodes.Sequencer,
        l1: *const nodes.L1,
        pool: *const codec.TxPool,
    ) ?[]const u8 {
        assert(sequencer.chain.real);
        while (reference.head < sequencer.head) {
            if (reference.build(sequencer, l1, pool, reference.head + 1)) |reason| return reason;
            reference.head += 1;
        }
        assert(reference.head == sequencer.head);
        return null;
    }

    fn parent_info(chain: *const nodes.Chain, number: u64) L2BlockInfo {
        const origin = chain.origins[number];
        return .{
            .block_info = .{
                .hash = chain.real_hashes[number],
                .number = number,
                .parent_hash = if (number == 0) .zero else chain.real_hashes[number - 1],
                .timestamp = codec.rollup.l2_block_timestamp(number),
            },
            .l1_origin = .{ .number = origin.number, .hash = codec.word_hash(origin.hash) },
            .sequence_number = origin.sequence_number,
        };
    }

    fn build(
        reference: *Reference,
        sequencer: *nodes.Sequencer,
        l1: *const nodes.L1,
        pool: *const codec.TxPool,
        number: u64,
    ) ?[]const u8 {
        const chain = &sequencer.chain;
        assert(number > 0 and number <= sequencer.head);
        var fixed: std.heap.FixedBufferAllocator = .init(reference.scratch);
        var builder = attributes_module.AttributesBuilder.init(
            fixed.allocator(),
            &reference.rollup,
            &reference.blob_schedule,
        );
        var view: real_verifier.L1View = .{ .l1 = l1, .pool = pool, .reachable = true };
        const parent = parent_info(chain, number - 1);
        const origin = parent_info(chain, number).l1_origin;
        const gossip_chain: real_verifier.GossipChain = .{ .l1 = &view };
        const derived = builder.prepare_payload_attributes(gossip_chain, parent, origin) catch
            unreachable; // Proof: origins are final canonical L1 blocks; scratch is ample.
        assert(derived.transactions.len == 1); // No deposits or upgrades in the model.
        var tx_buffer: [codec.payload_tx_length_max]u8 = undefined;
        const transactions = [2][]const u8{
            derived.transactions[0],
            codec.payload_tx_as(.signed, chain.payloads[number], &tx_buffer),
        };
        const attributes: task.EngineAttributes = .{
            .timestamp = derived.timestamp,
            .prev_randao = derived.prev_randao,
            .suggested_fee_recipient = derived.suggested_fee_recipient,
            .withdrawals = derived.withdrawals,
            .parent_beacon_block_root = derived.parent_beacon_block_root,
            .transactions = &transactions,
            .no_tx_pool = true,
            .gas_limit = derived.gas_limit,
            .eip1559_params = derived.eip1559_params,
            .min_base_fee = derived.min_base_fee,
        };
        return reference.build_with(chain, number, &attributes);
    }

    fn build_with(
        reference: *Reference,
        chain: *nodes.Chain,
        number: u64,
        attributes: *const task.EngineAttributes,
    ) ?[]const u8 {
        const engine = reference.engine;
        var state: task.EngineForkchoiceState = .{
            .head_block_hash = chain.real_hashes[number - 1],
            .safe_block_hash = .zero,
            .finalized_block_hash = .zero,
        };
        if (reference.wait()) |reason| return reason;
        const updated = engine.forkchoice_updated(.v3, &state, attributes) catch
            return "reference engine rejected the sequencer's attributes";
        if (updated.payload_status.status != .valid) {
            return "reference engine rejected the sequencer's attributes";
        }
        const envelope = engine.get_payload(.v3, updated.payload_id.?) catch
            return "reference engine lost its payload";
        const payload = &envelope.payload;
        if (payload.transactions.len != 2) return "reference engine dropped a transaction";
        chain.real_hashes[number] = payload.block_hash;
        chain.real_state_roots[number] = payload.state_root;
        state.head_block_hash = payload.block_hash;
        if (reference.wait()) |reason| return reason;
        const head = engine.forkchoice_updated(.v3, &state, null) catch
            return "reference engine refused its own block";
        assert(head.payload_status.status == .valid);
        assert(engine.head_number() == number);
        return null;
    }

    /// Imports every block the real sequencer recorded above the reference head from its
    /// engine (`source`). Each must be valid here too. Returns the violated invariant.
    pub fn import(
        reference: *Reference,
        chain: *const nodes.Chain,
        head: u64,
        source: *ExecEngine,
    ) ?[]const u8 {
        assert(chain.real);
        while (reference.head < head) {
            const number = reference.head + 1;
            if (reference.import_block(chain, number, source)) |reason| return reason;
            reference.head = number;
            reference.imported += 1;
        }
        return null;
    }

    fn import_block(
        reference: *Reference,
        chain: *const nodes.Chain,
        number: u64,
        source: *ExecEngine,
    ) ?[]const u8 {
        const hash = chain.real_hashes[number];
        var transactions: [real_execution.block_transactions_max][]const u8 = undefined;
        const payload = source.payload_of(hash, &transactions).?;
        const header = source.header(hash).?;
        const params: task.NewPayloadParams = .{
            .versioned_hashes = &.{},
            .parent_beacon_block_root = header.parent_beacon_block_root,
        };
        const engine = reference.engine;
        if (reference.wait()) |reason| return reason;
        const status = engine.new_payload(.v3, &payload, &params) catch
            return "reference engine rejected the sequencer's block";
        if (status.status != .valid) return "reference engine rejected the sequencer's block";
        const state: task.EngineForkchoiceState = .{
            .head_block_hash = hash,
            .safe_block_hash = .zero,
            .finalized_block_hash = .zero,
        };
        if (reference.wait()) |reason| return reason;
        const head = engine.forkchoice_updated(.v3, &state, null) catch
            return "reference engine refused the sequencer's block";
        assert(head.payload_status.status == .valid);
        const imported = engine.header(hash).?;
        if (!imported.state_root.eql(chain.real_state_roots[number])) {
            return "reference engine state root differs from the sequencer's";
        }
        return null;
    }
};
